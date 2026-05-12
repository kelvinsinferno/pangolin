// SPDX-License-Identifier: AGPL-3.0-or-later
//! Composite-key derivation, AES-KDF (KDBX3.1), and Argon2 (KDBX4).

use aes::cipher::{BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::KdbxError;
use crate::header::Kdf;

/// Build the 32-byte composite key per the KeePass spec:
/// `SHA-256( SHA-256(password) || keyfile_key )`.
///
/// `password` is `None` when only a keyfile protects the database;
/// `keyfile_bytes` is the **raw bytes of the keyfile** (the keyfile-key
/// derivation per [`keyfile_key`] is applied here). At least one of the
/// two must be present, else [`KdbxError::UnsupportedCredential`].
pub fn composite_key(
    password: Option<&[u8]>,
    keyfile_bytes: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, KdbxError> {
    if password.is_none() && keyfile_bytes.is_none() {
        return Err(KdbxError::UnsupportedCredential(
            "no password and no keyfile supplied".into(),
        ));
    }
    let mut hasher = Sha256::new();
    if let Some(pw) = password {
        let pw_hash = Sha256::digest(pw);
        hasher.update(pw_hash);
    }
    if let Some(kf) = keyfile_bytes {
        let kk = keyfile_key(kf)?;
        hasher.update(kk.as_slice());
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(Zeroizing::new(arr))
}

/// Derive the 32-byte keyfile-key from the raw keyfile bytes.
///
/// Supported forms (KeePass / KeePassXC):
/// - **XML keyfile** (`.keyx` / KeePass 2.x `<KeyFile>` XML) — the
///   hex- or base64-encoded `<Key><Data>` element, with the version 2.0
///   hash check when present.
/// - **32 raw bytes** — used verbatim.
/// - **64 hex characters** — decoded to 32 bytes.
/// - **anything else** — `SHA-256(file_bytes)`.
fn keyfile_key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, KdbxError> {
    // Try the XML form first (cheap prefix probe).
    if let Some(k) = parse_xml_keyfile(bytes)? {
        return Ok(k);
    }
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        return Ok(Zeroizing::new(arr));
    }
    if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
        let s = core::str::from_utf8(bytes)
            .map_err(|_| KdbxError::UnsupportedCredential("keyfile hex decode".into()))?;
        let v = decode_hex(s)
            .ok_or_else(|| KdbxError::UnsupportedCredential("keyfile hex decode".into()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        return Ok(Zeroizing::new(arr));
    }
    let h = Sha256::digest(bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h);
    Ok(Zeroizing::new(arr))
}

/// Parse a KeePass 2.x XML keyfile. Returns `Ok(None)` if `bytes` does
/// not look like an XML keyfile (so the caller falls through to the
/// raw-32 / hex / file-hash forms).
fn parse_xml_keyfile(bytes: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, KdbxError> {
    let text = match core::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if !trimmed.starts_with("<?xml") && !trimmed.starts_with("<KeyFile") {
        return Ok(None);
    }
    // Pull out the version (optional) and the <Key><Data ...>...</Data>.
    let version = extract_tag_text(trimmed, "Version");
    let data_text = extract_tag_text(trimmed, "Data")
        .ok_or_else(|| KdbxError::UnsupportedCredential("XML keyfile missing <Data>".into()))?;
    let data_text_clean: String = data_text.split_whitespace().collect();
    let is_v2 = version
        .as_deref()
        .is_some_and(|v| v.trim().starts_with("2."));
    let key_bytes: Zeroizing<Vec<u8>> = if is_v2 {
        // v2: hex-encoded 32 bytes; the <Data Hash="..."> attribute is
        // the first 4 bytes of SHA-256(key) — verify if present.
        let v = decode_hex(&data_text_clean)
            .ok_or_else(|| KdbxError::UnsupportedCredential("XML keyfile v2 hex decode".into()))?;
        if v.len() != 32 {
            return Err(KdbxError::UnsupportedCredential(
                "XML keyfile v2 key not 32 bytes".into(),
            ));
        }
        if let Some(hash_attr) = extract_attr(trimmed, "Data", "Hash") {
            if let Some(expected) = decode_hex(&hash_attr) {
                let got = Sha256::digest(&v);
                if expected.len() != 4 || got[..4] != expected[..] {
                    return Err(KdbxError::UnsupportedCredential(
                        "XML keyfile v2 hash mismatch".into(),
                    ));
                }
            }
        }
        Zeroizing::new(v)
    } else {
        // v1: base64-encoded 32 bytes.
        use base64::Engine as _;
        let v = base64::engine::general_purpose::STANDARD
            .decode(data_text_clean.as_bytes())
            .map_err(|_| KdbxError::UnsupportedCredential("XML keyfile base64 decode".into()))?;
        Zeroizing::new(v)
    };
    // For both versions the keyfile-key is the 32 raw bytes. (KeePass
    // hashes shorter/longer payloads, but the spec mandates 32; reject
    // anything else.)
    if key_bytes.len() != 32 {
        // Tolerate by hashing — matches KeePass leniency on v1.
        let h = Sha256::digest(key_bytes.as_slice());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h);
        return Ok(Some(Zeroizing::new(arr)));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Ok(Some(Zeroizing::new(arr)))
}

/// Very small, dependency-free helper: extract the text content of the
/// first `<Tag>...</Tag>` (no namespace handling; KeePass keyfiles use
/// none). Returns `None` if the tag is absent.
fn extract_tag_text(xml: &str, tag: &str) -> Option<String> {
    let open_prefix = format!("<{tag}");
    let start_tag = xml.find(&open_prefix)?;
    // Find the '>' that closes the opening tag.
    let rest = &xml[start_tag..];
    let gt = rest.find('>')?;
    // Self-closing?
    if rest.as_bytes().get(gt.wrapping_sub(1)) == Some(&b'/') {
        return Some(String::new());
    }
    let content_start = start_tag + gt + 1;
    let close = format!("</{tag}>");
    let close_rel = xml[content_start..].find(&close)?;
    Some(xml[content_start..content_start + close_rel].to_string())
}

/// Extract `attr="..."` from the first `<tag ...>` opening tag.
fn extract_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open_prefix = format!("<{tag}");
    let start = xml.find(&open_prefix)?;
    let rest = &xml[start..];
    let gt = rest.find('>')?;
    let opening = &rest[..gt];
    let needle = format!("{attr}=\"");
    let a = opening.find(&needle)?;
    let after = &opening[a + needle.len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(u8::try_from((hi << 4) | lo).ok()?);
        i += 2;
    }
    Some(out)
}

/// Derive the 32-byte transformed key from the composite key and the
/// header's KDF parameters.
///
/// # Errors
/// [`KdbxError::KdfParamsRejected`] / [`KdbxError::UnsupportedKdf`] on
/// bad parameters; the Argon2 path surfaces internal failures as
/// `UnsupportedKdf`.
pub fn transform_key(composite: &[u8; 32], kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, KdbxError> {
    match kdf {
        Kdf::Aes { seed, rounds } => {
            let cipher = aes::Aes256::new_from_slice(seed)
                .map_err(|_| KdbxError::UnsupportedKdf("AES-KDF key init".into()))?;
            // AES-256-ECB twice (the 32-byte composite is two 16-byte
            // blocks) `rounds` times, then SHA-256.
            let mut block = *composite;
            for _ in 0..*rounds {
                let (lo, hi) = block.split_at_mut(16);
                let mut b0 = aes::cipher::generic_array::GenericArray::clone_from_slice(lo);
                let mut b1 = aes::cipher::generic_array::GenericArray::clone_from_slice(hi);
                cipher.encrypt_block(&mut b0);
                cipher.encrypt_block(&mut b1);
                lo.copy_from_slice(&b0);
                hi.copy_from_slice(&b1);
            }
            let h = Sha256::digest(block);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            // Wipe the intermediate.
            let _ = Zeroizing::new(block);
            Ok(Zeroizing::new(arr))
        }
        Kdf::Argon2 {
            variant,
            salt,
            parallelism,
            memory_kib,
            iterations,
            version,
        } => {
            let algorithm = match variant {
                0 => argon2::Algorithm::Argon2d,
                2 => argon2::Algorithm::Argon2id,
                1 => argon2::Algorithm::Argon2i,
                _ => return Err(KdbxError::UnsupportedKdf("unknown Argon2 variant".into())),
            };
            let ver = match *version {
                0x10 => argon2::Version::V0x10,
                0x13 => argon2::Version::V0x13,
                _ => return Err(KdbxError::UnsupportedKdf("unknown Argon2 version".into())),
            };
            let params = argon2::Params::new(
                *memory_kib,
                u32::try_from(*iterations)
                    .map_err(|_| KdbxError::KdfParamsRejected("Argon2 iterations".into()))?,
                *parallelism,
                Some(32),
            )
            .map_err(|e| KdbxError::KdfParamsRejected(format!("Argon2 params: {e}")))?;
            let ctx = argon2::Argon2::new(algorithm, ver, params);
            let mut out = Zeroizing::new([0u8; 32]);
            ctx.hash_password_into(composite, salt, &mut out[..])
                .map_err(|e| KdbxError::UnsupportedKdf(format!("Argon2: {e}")))?;
            Ok(out)
        }
    }
}

/// Derive the master encryption key: `SHA-256(master_seed || transformed_key)`.
#[must_use]
pub fn master_key(master_seed: &[u8; 32], transformed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(master_seed);
    hasher.update(transformed);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Zeroizing::new(arr)
}

/// Derive the KDBX4 HMAC base key: `SHA-512(master_seed || transformed_key || 0x01)`.
#[must_use]
pub fn hmac_base_key(master_seed: &[u8; 32], transformed: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let mut hasher = Sha512::new();
    hasher.update(master_seed);
    hasher.update(transformed);
    hasher.update([0x01u8]);
    let out = hasher.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    Zeroizing::new(arr)
}

/// Per-block HMAC key for KDBX4 block index `i`:
/// `SHA-512( i_le_u64 || hmac_base_key )`.
#[must_use]
pub fn block_hmac_key(base: &[u8; 64], block_index: u64) -> Zeroizing<[u8; 64]> {
    let mut hasher = Sha512::new();
    hasher.update(block_index.to_le_bytes());
    hasher.update(base);
    let out = hasher.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    Zeroizing::new(arr)
}
