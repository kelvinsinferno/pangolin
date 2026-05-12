// SPDX-License-Identifier: AGPL-3.0-or-later
//! Outer-cipher decryption (AES-256-CBC / ChaCha20), KDBX4 HMAC-SHA256
//! block-MAC verification + header authentication, and the KDBX3
//! stream-start-bytes integrity check.

use cipher::{BlockDecryptMut, KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::KdbxError;
use crate::header::{OuterCipher, OuterHeader};
use crate::kdf;
use crate::Secret;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Decrypt an outer-cipher ciphertext block. For AES-256-CBC the
/// returned bytes still include PKCS#7 padding for KDBX3 (the caller
/// strips it after the stream-start-bytes check); for KDBX4 the
/// padding is stripped here.
fn decrypt_outer(
    cipher: OuterCipher,
    key: &[u8; 32],
    iv: &[u8],
    ct: &[u8],
    strip_pkcs7: bool,
) -> Result<Secret, KdbxError> {
    match cipher {
        OuterCipher::Aes256Cbc => {
            if ct.is_empty() || ct.len() % 16 != 0 {
                return Err(KdbxError::WrongCredentials);
            }
            let iv16: [u8; 16] = iv
                .try_into()
                .map_err(|_| KdbxError::CorruptHeader("AES IV".into()))?;
            let dec = Aes256CbcDec::new(key.into(), &iv16.into());
            let mut buf = ct.to_vec();
            // Decrypt in place; we cannot use `decrypt_padded_vec_mut`
            // because for KDBX3 we want to defer padding-strip until
            // after the start-bytes check.
            let mut dec = dec;
            for chunk in buf.chunks_mut(16) {
                let block = cipher::generic_array::GenericArray::from_mut_slice(chunk);
                dec.decrypt_block_mut(block);
            }
            if strip_pkcs7 {
                let pad = *buf.last().ok_or(KdbxError::WrongCredentials)? as usize;
                if pad == 0 || pad > 16 || pad > buf.len() {
                    return Err(KdbxError::WrongCredentials);
                }
                // Verify all pad bytes (constant-ish; failure → wrong creds).
                let n = buf.len();
                if buf[n - pad..].iter().any(|&b| b as usize != pad) {
                    return Err(KdbxError::WrongCredentials);
                }
                buf.truncate(n - pad);
            }
            Ok(Zeroizing::new(buf))
        }
        OuterCipher::ChaCha20 => {
            let nonce: [u8; 12] = iv
                .try_into()
                .map_err(|_| KdbxError::CorruptHeader("ChaCha20 nonce".into()))?;
            let mut c = chacha20::ChaCha20::new(key.into(), &nonce.into());
            let mut buf = ct.to_vec();
            c.apply_keystream(&mut buf);
            Ok(Zeroizing::new(buf))
        }
    }
}

/// KDBX3: derive the master key, decrypt the post-header ciphertext,
/// verify the stream-start-bytes, and return the plaintext payload
/// (still gzip-compressed if the header says so).
pub fn decrypt_kdbx3_payload(
    header: &OuterHeader,
    composite: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Secret, KdbxError> {
    let transformed = kdf::transform_key(composite, &header.kdf)?;
    let mkey = kdf::master_key(&header.master_seed, &transformed);
    // For KDBX3 we strip PKCS#7 only AFTER the start-bytes check, but
    // start-bytes are the first 32 plaintext bytes so we decrypt without
    // strip, then handle padding.
    let pt = decrypt_outer(
        header.cipher,
        &mkey,
        &header.encryption_iv,
        ciphertext,
        false,
    )?;
    let expected = header
        .v3_stream_start_bytes
        .as_ref()
        .ok_or_else(|| KdbxError::CorruptHeader("missing stream start bytes".into()))?;
    if pt.len() < expected.len() {
        return Err(KdbxError::WrongCredentials);
    }
    if pt[..expected.len()].ct_eq(expected).unwrap_u8() != 1 {
        // Wrong password / keyfile (or corrupt) — no oracle.
        return Err(KdbxError::WrongCredentials);
    }
    // Strip start bytes, then the trailing PKCS#7 padding (AES) — for
    // ChaCha20 there is no padding.
    let mut body: Vec<u8> = pt[expected.len()..].to_vec();
    if header.cipher == OuterCipher::Aes256Cbc {
        let pad = *body.last().ok_or(KdbxError::WrongCredentials)? as usize;
        if pad == 0 || pad > 16 || pad > body.len() {
            return Err(KdbxError::WrongCredentials);
        }
        let n = body.len();
        if body[n - pad..].iter().any(|&b| b as usize != pad) {
            return Err(KdbxError::WrongCredentials);
        }
        body.truncate(n - pad);
    }
    Ok(Zeroizing::new(body))
}

/// KDBX4: verify the header-HMAC, verify + concatenate the HMAC'd
/// blocks, then decrypt — returns the decrypted (still gzip'd if so
/// flagged) inner payload (which carries the inner header + XML).
pub fn decrypt_kdbx4_payload(
    header: &OuterHeader,
    composite: &[u8; 32],
    after_header: &[u8],
) -> Result<Secret, KdbxError> {
    let transformed = kdf::transform_key(composite, &header.kdf)?;
    let mkey = kdf::master_key(&header.master_seed, &transformed);
    let hmac_base = kdf::hmac_base_key(&header.master_seed, &transformed);

    // Layout after the outer header: 32-byte header-SHA256, 32-byte
    // header-HMAC-SHA256, then the HMAC'd block stream.
    if after_header.len() < 64 {
        return Err(KdbxError::CorruptHeader(
            "missing header integrity tags".into(),
        ));
    }
    let header_sha = &after_header[..32];
    let header_hmac = &after_header[32..64];
    let blocks = &after_header[64..];

    // SHA-256 of the raw header must match.
    let got_sha = Sha256::digest(&header.raw_header);
    if got_sha.as_slice().ct_eq(header_sha).unwrap_u8() != 1 {
        return Err(KdbxError::CorruptHeader("header SHA-256 mismatch".into()));
    }
    // Header-HMAC uses block index 0xFFFF_FFFF_FFFF_FFFF.
    let hkey = kdf::block_hmac_key(&hmac_base, u64::MAX);
    let mut mac =
        HmacSha256::new_from_slice(hkey.as_slice()).map_err(|_| KdbxError::WrongCredentials)?;
    mac.update(&header.raw_header);
    if mac.verify_slice(header_hmac).is_err() {
        // Wrong credentials (or tampered header) — no oracle.
        return Err(KdbxError::WrongCredentials);
    }

    // Walk the block stream: each block = 32-byte HMAC || 4-byte LE
    // length || `length` bytes of ciphertext. A zero-length block ends
    // the stream.
    let mut ct: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let mut idx: u64 = 0;
    loop {
        let hmac_tag = blocks
            .get(pos..pos + 32)
            .ok_or_else(|| KdbxError::CorruptPayload("truncated block HMAC".into()))?;
        pos += 32;
        let len_bytes = blocks
            .get(pos..pos + 4)
            .ok_or_else(|| KdbxError::CorruptPayload("truncated block length".into()))?;
        pos += 4;
        let blk_len =
            u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if blk_len > crate::KDBX_MAX_INFLATED_BYTES {
            return Err(KdbxError::CorruptPayload("block length too large".into()));
        }
        let data = blocks
            .get(
                pos..pos
                    .checked_add(blk_len)
                    .ok_or_else(|| KdbxError::CorruptPayload("block length overflow".into()))?,
            )
            .ok_or_else(|| KdbxError::CorruptPayload("truncated block data".into()))?;
        pos += blk_len;
        // Verify HMAC over (idx_le_u64 || blk_len_le_u32 || data) with
        // this block's key.
        let bkey = kdf::block_hmac_key(&hmac_base, idx);
        let mut bm =
            HmacSha256::new_from_slice(bkey.as_slice()).map_err(|_| KdbxError::WrongCredentials)?;
        bm.update(&idx.to_le_bytes());
        bm.update(&(blk_len as u32).to_le_bytes());
        bm.update(data);
        if bm.verify_slice(hmac_tag).is_err() {
            return Err(KdbxError::BlockHmacMismatch);
        }
        if blk_len == 0 {
            break;
        }
        ct.extend_from_slice(data);
        idx = idx
            .checked_add(1)
            .ok_or_else(|| KdbxError::CorruptPayload("too many blocks".into()))?;
        if ct.len() > crate::KDBX_MAX_INFLATED_BYTES {
            return Err(KdbxError::InflatedTooLarge {
                limit: crate::KDBX_MAX_INFLATED_BYTES,
            });
        }
    }

    // Decrypt the concatenated ciphertext; KDBX4 AES-CBC has PKCS#7
    // padding to strip; ChaCha20 has none.
    decrypt_outer(
        header.cipher,
        &mkey,
        &header.encryption_iv,
        &ct,
        header.cipher == OuterCipher::Aes256Cbc,
    )
}
