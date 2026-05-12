// SPDX-License-Identifier: AGPL-3.0-or-later
//! Inner-payload handling: bounded gzip inflate, KDBX4 inner-header
//! TLVs, and the inner random stream (Salsa20 / ChaCha20) that
//! XOR-unmasks `Protected="True"` string values.

use std::io::Read as _;

use cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha512};

use crate::error::KdbxError;
use crate::header::{InnerStreamCipher, KdbxFormat, OuterHeader};
use crate::Secret;

/// The fixed Salsa20 IV KeePass uses for the KDBX3 inner random stream.
const SALSA20_IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

/// Inflate a gzip stream with a hard output ceiling.
///
/// # Errors
/// [`KdbxError::CorruptPayload`] on a malformed gzip stream;
/// [`KdbxError::InflatedTooLarge`] if the output would exceed `limit`.
pub fn gunzip_bounded(data: &[u8], limit: usize) -> Result<Secret, KdbxError> {
    let mut dec = flate2::read::GzDecoder::new(data);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = dec
            .read(&mut chunk)
            .map_err(|e| KdbxError::CorruptPayload(format!("gzip: {e}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > limit {
            return Err(KdbxError::InflatedTooLarge { limit });
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(zeroize::Zeroizing::new(out))
}

/// The inner random stream that masks `Protected` values.
pub struct InnerStream {
    cipher: InnerStreamKeystream,
}

enum InnerStreamKeystream {
    None,
    Salsa20(salsa20::Salsa20),
    ChaCha20(chacha20::ChaCha20),
}

impl InnerStream {
    /// Build the inner stream from the cipher id + key. For Salsa20 the
    /// 32-byte key is the SHA-256 of the header's inner-stream key (KDBX3
    /// uses a possibly-shorter key, hashed to 32). For ChaCha20 (KDBX4)
    /// the key+nonce are SHA-512(inner_key) → first 32 bytes key, next
    /// 12 bytes nonce.
    pub fn new(cipher: InnerStreamCipher, raw_key: &[u8]) -> Result<Self, KdbxError> {
        let ks = match cipher {
            InnerStreamCipher::None => InnerStreamKeystream::None,
            InnerStreamCipher::Salsa20 => {
                let key = sha2::Sha256::digest(raw_key);
                InnerStreamKeystream::Salsa20(salsa20::Salsa20::new(&key, &SALSA20_IV.into()))
            }
            InnerStreamCipher::ChaCha20 => {
                let h = Sha512::digest(raw_key);
                let key: [u8; 32] = h[..32]
                    .try_into()
                    .map_err(|_| KdbxError::CorruptPayload("inner key derive".into()))?;
                let nonce: [u8; 12] = h[32..44]
                    .try_into()
                    .map_err(|_| KdbxError::CorruptPayload("inner nonce derive".into()))?;
                InnerStreamKeystream::ChaCha20(chacha20::ChaCha20::new(&key.into(), &nonce.into()))
            }
        };
        Ok(Self { cipher: ks })
    }

    /// XOR the next `buf.len()` keystream bytes into `buf` (in place).
    /// Must be called over every `Protected="True"` value's decoded
    /// bytes in document order.
    pub fn apply(&mut self, buf: &mut [u8]) {
        match &mut self.cipher {
            InnerStreamKeystream::None => {}
            InnerStreamKeystream::Salsa20(c) => c.apply_keystream(buf),
            InnerStreamKeystream::ChaCha20(c) => c.apply_keystream(buf),
        }
    }
}

/// KDBX4 inner-header TLV field ids.
mod inner_field {
    pub const END: u8 = 0;
    pub const INNER_RANDOM_STREAM_ID: u8 = 1;
    pub const INNER_RANDOM_STREAM_KEY: u8 = 2;
    pub const BINARY: u8 = 3;
}

/// The decrypted+decompressed inner payload, split into the inner-stream
/// config and the XML bytes.
pub struct InnerPayload {
    /// Inner random-stream cipher + key (already resolved).
    pub inner_stream_cipher: InnerStreamCipher,
    /// Raw inner-stream key bytes (zeroizing).
    pub inner_stream_key: Secret,
    /// The `<KeePassFile>` XML bytes.
    pub xml: Secret,
    /// Number of binary attachments declared in the inner header
    /// (KDBX4) — used only for the per-entry "N attachments dropped"
    /// note; we do not retain the bytes.
    pub binary_count: usize,
    /// Total size of the (dropped) binary attachments, in bytes.
    pub binary_total_bytes: usize,
}

/// Parse the decrypted (and gunzip'd, if needed) inner payload.
///
/// For KDBX3 the payload *is* the XML (the inner-stream config came from
/// the outer header). For KDBX4 the payload begins with the inner-header
/// TLVs (inner-stream id+key, binary pool), then the XML.
pub fn parse_inner_payload(
    header: &OuterHeader,
    decrypted: &[u8],
) -> Result<InnerPayload, KdbxError> {
    // Decompress if flagged.
    let plain: Secret = if header.compressed {
        gunzip_bounded(decrypted, crate::KDBX_MAX_INFLATED_BYTES)?
    } else {
        if decrypted.len() > crate::KDBX_MAX_INFLATED_BYTES {
            return Err(KdbxError::InflatedTooLarge {
                limit: crate::KDBX_MAX_INFLATED_BYTES,
            });
        }
        zeroize::Zeroizing::new(decrypted.to_vec())
    };

    match header.format {
        KdbxFormat::V3 => {
            let cipher = header
                .v3_inner_stream_cipher
                .ok_or_else(|| KdbxError::CorruptHeader("missing inner stream id".into()))?;
            let key = header
                .v3_inner_stream_key
                .clone()
                .unwrap_or_else(|| zeroize::Zeroizing::new(Vec::new()));
            Ok(InnerPayload {
                inner_stream_cipher: cipher,
                inner_stream_key: key,
                xml: plain,
                binary_count: 0,
                binary_total_bytes: 0,
            })
        }
        KdbxFormat::V4 => {
            let mut pos = 0usize;
            let mut cipher: Option<InnerStreamCipher> = None;
            let mut key: Option<Secret> = None;
            let mut binary_count = 0usize;
            let mut binary_total = 0usize;
            loop {
                let id = *plain
                    .get(pos)
                    .ok_or_else(|| KdbxError::CorruptPayload("truncated inner header".into()))?;
                pos += 1;
                let len_bytes = plain
                    .get(pos..pos + 4)
                    .ok_or_else(|| KdbxError::CorruptPayload("truncated inner len".into()))?;
                pos += 4;
                let len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;
                if len > crate::KDBX_MAX_INFLATED_BYTES {
                    return Err(KdbxError::CorruptPayload("inner field too large".into()));
                }
                let data = plain
                    .get(
                        pos..pos.checked_add(len).ok_or_else(|| {
                            KdbxError::CorruptPayload("inner len overflow".into())
                        })?,
                    )
                    .ok_or_else(|| KdbxError::CorruptPayload("truncated inner data".into()))?;
                pos += len;
                match id {
                    inner_field::END => break,
                    inner_field::INNER_RANDOM_STREAM_ID => {
                        let v = u32::from_le_bytes(data.try_into().map_err(|_| {
                            KdbxError::CorruptPayload("inner stream id len".into())
                        })?);
                        cipher = Some(match v {
                            0 => InnerStreamCipher::None,
                            2 => InnerStreamCipher::Salsa20,
                            3 => InnerStreamCipher::ChaCha20,
                            _ => {
                                return Err(KdbxError::CorruptPayload(
                                    "unknown inner stream id".into(),
                                ))
                            }
                        });
                    }
                    inner_field::INNER_RANDOM_STREAM_KEY => {
                        key = Some(zeroize::Zeroizing::new(data.to_vec()));
                    }
                    inner_field::BINARY => {
                        // First byte is a flags byte (memory-protect);
                        // the rest is the attachment bytes — dropped.
                        binary_count += 1;
                        binary_total += data.len().saturating_sub(1);
                    }
                    _ => {}
                }
            }
            let cipher = cipher
                .ok_or_else(|| KdbxError::CorruptPayload("missing inner stream id".into()))?;
            let key = key.unwrap_or_else(|| zeroize::Zeroizing::new(Vec::new()));
            let xml = zeroize::Zeroizing::new(plain[pos..].to_vec());
            Ok(InnerPayload {
                inner_stream_cipher: cipher,
                inner_stream_key: key,
                xml,
                binary_count,
                binary_total_bytes: binary_total,
            })
        }
    }
}
