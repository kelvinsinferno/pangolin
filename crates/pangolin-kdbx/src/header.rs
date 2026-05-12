// SPDX-License-Identifier: AGPL-3.0-or-later
//! KDBX outer-header parsing: magic, version dispatch, the TLV header
//! fields, and the KDBX4 `VariantDict` KDF parameters.

use crate::error::KdbxError;
use crate::Secret;

/// First magic word — `0x9AA2D903` little-endian.
const SIG1: u32 = 0x9AA2_D903;
/// Second magic word — KeePass 2.x file (`0xB54BFB67`).
const SIG2_KP2: u32 = 0xB54B_FB67;
/// Second magic word — KeePass 1.x file (`.kdb`); we reject it.
const SIG2_KP1: u32 = 0xB54B_FB65;
/// Second magic word — pre-release KeePass 2.x (`0xB54BFB66`); reject.
const SIG2_KP2_PRE: u32 = 0xB54B_FB66;

/// AES-256 outer cipher UUID (`31C1F2E6-BF71-4350-BE58-05216AFC5AFF`).
pub const CIPHER_AES256: [u8; 16] = [
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
];
/// ChaCha20 outer cipher UUID (`D6038A2B-8B6F-4CB5-A524-339A31DBB59A`).
pub const CIPHER_CHACHA20: [u8; 16] = [
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
];
/// `TwoFish` outer cipher UUID — recognised so we can emit a clean
/// "unsupported cipher" rather than a corrupt-header error.
pub const CIPHER_TWOFISH: [u8; 16] = [
    0xAD, 0x68, 0xF2, 0x9F, 0x57, 0x6F, 0x4B, 0xB9, 0xA3, 0x6A, 0xD4, 0x7A, 0xF9, 0x65, 0x34, 0x6C,
];

/// AES-KDF UUID (`C9D9F39A-628A-4460-BF74-0D08C18A4FEA`) — KDBX3.1.
pub const KDF_AES: [u8; 16] = [
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
];
/// Argon2d UUID (`EF636DDF-8C29-444B-91F7-A9A403E30A0C`).
pub const KDF_ARGON2D: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
/// Argon2id UUID (`9E298B19-56DB-4773-B23D-FC3EC6F0A1E6`).
pub const KDF_ARGON2ID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

/// Which major KDBX format the file uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdbxFormat {
    /// KDBX 3.1 — AES-KDF, no block-MAC, Salsa20 inner stream.
    V3,
    /// KDBX 4.x — Argon2 KDF, HMAC-SHA256 block-MAC, ChaCha20 inner stream.
    V4,
}

/// Outer header TLV field ids (shared across 3.x and 4.x).
mod field {
    pub const END: u8 = 0;
    pub const CIPHER_ID: u8 = 2;
    pub const COMPRESSION: u8 = 3;
    pub const MASTER_SEED: u8 = 4;
    /// KDBX3 only.
    pub const TRANSFORM_SEED: u8 = 5;
    /// KDBX3 only.
    pub const TRANSFORM_ROUNDS: u8 = 6;
    pub const ENCRYPTION_IV: u8 = 7;
    /// KDBX3 only — inner random stream key.
    pub const INNER_RANDOM_STREAM_KEY: u8 = 8;
    /// KDBX3 only — first bytes of the decrypted payload.
    pub const STREAM_START_BYTES: u8 = 9;
    /// KDBX3 only — inner random stream cipher id.
    pub const INNER_RANDOM_STREAM_ID: u8 = 10;
    /// KDBX4 only — the KDF `VariantDict`.
    pub const KDF_PARAMETERS: u8 = 11;
}

/// KDF parameters as resolved from the header.
#[derive(Debug, Clone)]
pub enum Kdf {
    /// AES-KDF (KDBX3.1): transform the composite key with AES-256-ECB
    /// `rounds` times, then SHA-256.
    Aes {
        /// 32-byte transform seed.
        seed: [u8; 32],
        /// Round count.
        rounds: u64,
    },
    /// Argon2 (KDBX4) — `variant` is `0` for Argon2d, `2` for Argon2id.
    Argon2 {
        /// `argon2` variant ordinal: 0 = d, 2 = id.
        variant: u32,
        /// 16- or 32-byte salt.
        salt: Vec<u8>,
        /// Parallelism (lanes).
        parallelism: u32,
        /// Memory in KiB.
        memory_kib: u32,
        /// Iterations / passes.
        iterations: u64,
        /// Argon2 version word (`0x10` or `0x13`).
        version: u32,
    },
}

/// Outer cipher selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterCipher {
    /// AES-256-CBC with PKCS#7 padding.
    Aes256Cbc,
    /// ChaCha20 (RFC 8439, 96-bit nonce taken from the 12-byte IV).
    ChaCha20,
}

/// Inner random-stream cipher (protects `Protected="True"` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerStreamCipher {
    /// No protection (id 0).
    None,
    /// Salsa20 with the fixed KeePass IV (id 2) — KDBX3.
    Salsa20,
    /// ChaCha20 (id 3) — KDBX4.
    ChaCha20,
}

impl InnerStreamCipher {
    fn from_id(id: u32) -> Result<Self, KdbxError> {
        match id {
            0 => Ok(Self::None),
            // ArcFourVariant (id 1) — obsolete, unsupported.
            1 => Err(KdbxError::CorruptPayload(
                "obsolete inner stream cipher".into(),
            )),
            2 => Ok(Self::Salsa20),
            3 => Ok(Self::ChaCha20),
            other => Err(KdbxError::CorruptPayload(format!(
                "unknown inner stream cipher id {other}"
            ))),
        }
    }
}

/// The fully-parsed outer header.
#[derive(Debug)]
pub struct OuterHeader {
    /// 3.x vs 4.x.
    pub format: KdbxFormat,
    /// The byte length of the magic+version+header region (the bytes
    /// over which the KDBX4 header-HMAC and header-SHA256 are computed).
    pub header_len: usize,
    /// Outer cipher.
    pub cipher: OuterCipher,
    /// `true` if the inner payload is gzip-compressed.
    pub compressed: bool,
    /// 32-byte master seed.
    pub master_seed: [u8; 32],
    /// Outer-cipher IV (16 bytes for AES-CBC, 12 for ChaCha20).
    pub encryption_iv: Vec<u8>,
    /// Resolved KDF.
    pub kdf: Kdf,
    // -- KDBX3-only fields --
    /// KDBX3: inner random stream key.
    pub v3_inner_stream_key: Option<Secret>,
    /// KDBX3: first 32 bytes the decrypted payload must start with.
    pub v3_stream_start_bytes: Option<Vec<u8>>,
    /// KDBX3: inner random stream cipher.
    pub v3_inner_stream_cipher: Option<InnerStreamCipher>,
    /// Raw header bytes (magic..header end inclusive) — needed for the
    /// KDBX4 header-HMAC + header-SHA256 checks and for the KDBX3
    /// composite-of-header path.
    pub raw_header: Vec<u8>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn u8(&mut self) -> Result<u8, KdbxError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| KdbxError::CorruptHeader("truncated".into()))?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16, KdbxError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 2)
            .ok_or_else(|| KdbxError::CorruptHeader("truncated".into()))?;
        self.pos += 2;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, KdbxError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| KdbxError::CorruptHeader("truncated".into()))?;
        self.pos += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], KdbxError> {
        let s = self
            .buf
            .get(
                self.pos
                    ..self
                        .pos
                        .checked_add(n)
                        .ok_or_else(|| KdbxError::CorruptHeader("length overflow".into()))?,
            )
            .ok_or_else(|| KdbxError::CorruptHeader("truncated".into()))?;
        self.pos += n;
        Ok(s)
    }
}

/// Maximum byte length we will accept for any single outer-header TLV
/// field — guards against a lying length field.
const MAX_HEADER_FIELD: usize = 1 << 20; // 1 MiB

/// Parse the outer header from the start of `buf`.
///
/// # Errors
/// [`KdbxError::NotKdbx`] / [`KdbxError::UnsupportedVersion`] /
/// [`KdbxError::CorruptHeader`] / [`KdbxError::UnsupportedCipher`] /
/// [`KdbxError::UnsupportedKdf`] / [`KdbxError::KdfParamsRejected`].
#[allow(clippy::too_many_lines)]
pub fn parse_outer_header(buf: &[u8]) -> Result<OuterHeader, KdbxError> {
    let mut r = Reader::new(buf);
    let sig1 = r.u32()?;
    let sig2 = r.u32()?;
    if sig1 != SIG1 {
        return Err(KdbxError::NotKdbx);
    }
    match sig2 {
        SIG2_KP2 => {}
        SIG2_KP1 => return Err(KdbxError::UnsupportedVersion { major: 1, minor: 0 }),
        SIG2_KP2_PRE => return Err(KdbxError::UnsupportedVersion { major: 2, minor: 0 }),
        _ => return Err(KdbxError::NotKdbx),
    }
    // Version: minor then major (u16 LE each).
    let minor = r.u16()?;
    let major = r.u16()?;
    let format = match major {
        3 => KdbxFormat::V3,
        4 => KdbxFormat::V4,
        m => return Err(KdbxError::UnsupportedVersion { major: m, minor }),
    };

    let mut cipher: Option<OuterCipher> = None;
    let mut compressed: Option<bool> = None;
    let mut master_seed: Option<[u8; 32]> = None;
    let mut transform_seed: Option<[u8; 32]> = None;
    let mut transform_rounds: Option<u64> = None;
    let mut encryption_iv: Option<Vec<u8>> = None;
    let mut v3_inner_stream_key: Option<Secret> = None;
    let mut v3_stream_start_bytes: Option<Vec<u8>> = None;
    let mut v3_inner_stream_cipher: Option<InnerStreamCipher> = None;
    let mut kdf_variant_dict: Option<Vec<u8>> = None;

    loop {
        let id = r.u8()?;
        // Field length: u16 in KDBX3, u32 in KDBX4.
        let len = match format {
            KdbxFormat::V3 => usize::from(r.u16()?),
            KdbxFormat::V4 => {
                let v = r.u32()?;
                usize::try_from(v).map_err(|_| KdbxError::CorruptHeader("len".into()))?
            }
        };
        if len > MAX_HEADER_FIELD {
            return Err(KdbxError::CorruptHeader(format!(
                "header field {id} length {len} too large"
            )));
        }
        let data = r.take(len)?;
        match id {
            field::END => break,
            field::CIPHER_ID => {
                let uuid: [u8; 16] = data
                    .try_into()
                    .map_err(|_| KdbxError::CorruptHeader("cipher uuid not 16 bytes".into()))?;
                cipher = Some(match uuid {
                    CIPHER_AES256 => OuterCipher::Aes256Cbc,
                    CIPHER_CHACHA20 => OuterCipher::ChaCha20,
                    CIPHER_TWOFISH => return Err(KdbxError::UnsupportedCipher("TwoFish".into())),
                    _ => return Err(KdbxError::UnsupportedCipher("unknown cipher UUID".into())),
                });
            }
            field::COMPRESSION => {
                let v = u32::from_le_bytes(
                    data.try_into()
                        .map_err(|_| KdbxError::CorruptHeader("compression flag".into()))?,
                );
                compressed = Some(match v {
                    0 => false,
                    1 => true,
                    _ => return Err(KdbxError::CorruptHeader("unknown compression flag".into())),
                });
            }
            field::MASTER_SEED => {
                master_seed =
                    Some(data.try_into().map_err(|_| {
                        KdbxError::CorruptHeader("master seed not 32 bytes".into())
                    })?);
            }
            field::TRANSFORM_SEED => {
                transform_seed = Some(
                    data.try_into()
                        .map_err(|_| KdbxError::CorruptHeader("transform seed not 32".into()))?,
                );
            }
            field::TRANSFORM_ROUNDS => {
                transform_rounds = Some(u64::from_le_bytes(data.try_into().map_err(|_| {
                    KdbxError::CorruptHeader("transform rounds not 8 bytes".into())
                })?));
            }
            field::ENCRYPTION_IV => encryption_iv = Some(data.to_vec()),
            field::INNER_RANDOM_STREAM_KEY => {
                v3_inner_stream_key = Some(Secret::new(data.to_vec()));
            }
            field::STREAM_START_BYTES => v3_stream_start_bytes = Some(data.to_vec()),
            field::INNER_RANDOM_STREAM_ID => {
                let v =
                    u32::from_le_bytes(data.try_into().map_err(|_| {
                        KdbxError::CorruptHeader("inner stream id not 4 bytes".into())
                    })?);
                v3_inner_stream_cipher = Some(InnerStreamCipher::from_id(v)?);
            }
            field::KDF_PARAMETERS => kdf_variant_dict = Some(data.to_vec()),
            // Unknown header field — ignore (forward-compat).
            _ => {}
        }
    }

    let header_len = r.pos;
    let raw_header = buf
        .get(..header_len)
        .ok_or_else(|| KdbxError::CorruptHeader("short".into()))?
        .to_vec();

    let cipher = cipher.ok_or_else(|| KdbxError::CorruptHeader("missing cipher id".into()))?;
    let compressed =
        compressed.ok_or_else(|| KdbxError::CorruptHeader("missing compression flag".into()))?;
    let master_seed =
        master_seed.ok_or_else(|| KdbxError::CorruptHeader("missing master seed".into()))?;
    let encryption_iv =
        encryption_iv.ok_or_else(|| KdbxError::CorruptHeader("missing encryption IV".into()))?;

    let kdf = match format {
        KdbxFormat::V3 => {
            let seed = transform_seed
                .ok_or_else(|| KdbxError::CorruptHeader("missing transform seed".into()))?;
            let rounds = transform_rounds
                .ok_or_else(|| KdbxError::CorruptHeader("missing transform rounds".into()))?;
            // Sanity-clamp rounds to bound CPU on a hostile file. A real
            // KeePass DB is in the 10k..a-few-million range; cap at 1e8.
            if rounds > 100_000_000 {
                return Err(KdbxError::KdfParamsRejected(format!(
                    "AES-KDF rounds {rounds} too large"
                )));
            }
            Kdf::Aes { seed, rounds }
        }
        KdbxFormat::V4 => {
            let dict = kdf_variant_dict
                .ok_or_else(|| KdbxError::CorruptHeader("missing KDF parameters".into()))?;
            parse_kdf_variant_dict(&dict)?
        }
    };

    // KDBX3 IV must be 16 bytes for AES-CBC; KDBX4 ChaCha20 IV 12.
    match (format, cipher) {
        (_, OuterCipher::Aes256Cbc) if encryption_iv.len() != 16 => {
            return Err(KdbxError::CorruptHeader("AES-CBC IV not 16 bytes".into()));
        }
        (_, OuterCipher::ChaCha20) if encryption_iv.len() != 12 => {
            return Err(KdbxError::CorruptHeader("ChaCha20 IV not 12 bytes".into()));
        }
        _ => {}
    }

    Ok(OuterHeader {
        format,
        header_len,
        cipher,
        compressed,
        master_seed,
        encryption_iv,
        kdf,
        v3_inner_stream_key,
        v3_stream_start_bytes,
        v3_inner_stream_cipher,
        raw_header,
    })
}

/// `VariantDict` value type tags.
mod vd {
    pub const END: u8 = 0x00;
    pub const U32: u8 = 0x04;
    pub const U64: u8 = 0x05;
    pub const BOOL: u8 = 0x08;
    pub const I32: u8 = 0x0C;
    pub const I64: u8 = 0x0D;
    pub const STR: u8 = 0x18;
    pub const BYTES: u8 = 0x42;
}

/// Maximum number of `VariantDict` entries — guards a hostile dict.
const MAX_VARIANT_ENTRIES: usize = 64;
/// Maximum byte length of a single `VariantDict` value.
const MAX_VARIANT_VALUE: usize = 1 << 20;

/// Parse the KDBX4 KDF `VariantDict` and resolve it to a [`Kdf`].
fn parse_kdf_variant_dict(buf: &[u8]) -> Result<Kdf, KdbxError> {
    let mut r = Reader::new(buf);
    // Version word: u16 LE; we accept the documented `0x0001xx`.
    let _ver = r.u16()?;
    let mut uuid: Option<[u8; 16]> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut parallelism: Option<u32> = None;
    let mut memory: Option<u64> = None;
    let mut iterations: Option<u64> = None;
    let mut version: Option<u32> = None;
    let mut rounds: Option<u64> = None;
    let mut count = 0usize;
    loop {
        let tag = r.u8()?;
        if tag == vd::END {
            break;
        }
        count += 1;
        if count > MAX_VARIANT_ENTRIES {
            return Err(KdbxError::CorruptHeader("VariantDict too large".into()));
        }
        let key_len = usize::try_from(r.u32()?)
            .map_err(|_| KdbxError::CorruptHeader("VariantDict key len".into()))?;
        if key_len > 256 {
            return Err(KdbxError::CorruptHeader("VariantDict key too long".into()));
        }
        let key = r.take(key_len)?;
        let val_len = usize::try_from(r.u32()?)
            .map_err(|_| KdbxError::CorruptHeader("VariantDict value len".into()))?;
        if val_len > MAX_VARIANT_VALUE {
            return Err(KdbxError::CorruptHeader(
                "VariantDict value too large".into(),
            ));
        }
        let val = r.take(val_len)?;
        let read_u32 = || -> Result<u32, KdbxError> {
            val.try_into()
                .map(u32::from_le_bytes)
                .map_err(|_| KdbxError::CorruptHeader("VariantDict u32".into()))
        };
        let read_u64 = || -> Result<u64, KdbxError> {
            val.try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| KdbxError::CorruptHeader("VariantDict u64".into()))
        };
        match key {
            b"$UUID" if tag == vd::BYTES => {
                uuid = Some(
                    val.try_into()
                        .map_err(|_| KdbxError::CorruptHeader("KDF UUID not 16 bytes".into()))?,
                );
            }
            b"S" if tag == vd::BYTES => salt = Some(val.to_vec()),
            b"P" if tag == vd::U32 => parallelism = Some(read_u32()?),
            b"M" if tag == vd::U64 => memory = Some(read_u64()?),
            b"I" if tag == vd::U64 => iterations = Some(read_u64()?),
            b"V" if tag == vd::U32 => version = Some(read_u32()?),
            b"R" if tag == vd::U64 => rounds = Some(read_u64()?),
            b"R" if tag == vd::U32 => rounds = Some(u64::from(read_u32()?)),
            // Ignore other / mis-typed keys; the explicit checks below
            // catch missing required ones.
            _ => {
                // Validate the type tag is one we recognise so a
                // garbage tag is a corrupt-header error, not silently
                // skipped past with the wrong length.
                if !matches!(
                    tag,
                    vd::U32 | vd::U64 | vd::BOOL | vd::I32 | vd::I64 | vd::STR | vd::BYTES
                ) {
                    return Err(KdbxError::CorruptHeader(format!(
                        "unknown VariantDict type tag {tag:#x}"
                    )));
                }
            }
        }
    }
    let uuid = uuid.ok_or_else(|| KdbxError::CorruptHeader("KDF $UUID missing".into()))?;
    match uuid {
        KDF_AES => {
            let rounds =
                rounds.ok_or_else(|| KdbxError::CorruptHeader("AES-KDF rounds missing".into()))?;
            let seed_v =
                salt.ok_or_else(|| KdbxError::CorruptHeader("AES-KDF seed missing".into()))?;
            let seed: [u8; 32] = seed_v
                .as_slice()
                .try_into()
                .map_err(|_| KdbxError::CorruptHeader("AES-KDF seed not 32 bytes".into()))?;
            if rounds > 100_000_000 {
                return Err(KdbxError::KdfParamsRejected(format!(
                    "AES-KDF rounds {rounds} too large"
                )));
            }
            Ok(Kdf::Aes { seed, rounds })
        }
        KDF_ARGON2D | KDF_ARGON2ID => {
            let variant = if uuid == KDF_ARGON2D { 0u32 } else { 2u32 };
            let salt =
                salt.ok_or_else(|| KdbxError::CorruptHeader("Argon2 salt missing".into()))?;
            let parallelism =
                parallelism.ok_or_else(|| KdbxError::CorruptHeader("Argon2 P missing".into()))?;
            let memory =
                memory.ok_or_else(|| KdbxError::CorruptHeader("Argon2 M missing".into()))?;
            let iterations =
                iterations.ok_or_else(|| KdbxError::CorruptHeader("Argon2 I missing".into()))?;
            let version = version.unwrap_or(0x13);
            // M is bytes; argon2 crate wants KiB.
            if memory % 1024 != 0 {
                return Err(KdbxError::CorruptHeader("Argon2 M not KiB-aligned".into()));
            }
            let memory_kib_u64 = memory / 1024;
            // Sanity clamps (KeePassXC defaults are ~64 MiB / a few
            // iterations / 2 lanes). Refuse a memory/iteration bomb.
            if memory_kib_u64 == 0 || memory_kib_u64 > 1024 * 1024 {
                return Err(KdbxError::KdfParamsRejected(format!(
                    "Argon2 memory {memory} bytes out of range"
                )));
            }
            if iterations == 0 || iterations > 1000 {
                return Err(KdbxError::KdfParamsRejected(format!(
                    "Argon2 iterations {iterations} out of range"
                )));
            }
            if parallelism == 0 || parallelism > 64 {
                return Err(KdbxError::KdfParamsRejected(format!(
                    "Argon2 parallelism {parallelism} out of range"
                )));
            }
            if salt.len() < 8 || salt.len() > 64 {
                return Err(KdbxError::CorruptHeader(
                    "Argon2 salt length out of range".into(),
                ));
            }
            #[allow(clippy::cast_possible_truncation)]
            let memory_kib = memory_kib_u64 as u32;
            Ok(Kdf::Argon2 {
                variant,
                salt,
                parallelism,
                memory_kib,
                iterations,
                version,
            })
        }
        _ => Err(KdbxError::UnsupportedKdf("unknown KDF UUID".into())),
    }
}
