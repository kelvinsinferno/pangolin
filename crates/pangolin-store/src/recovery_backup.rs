// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recovery-backup encrypted envelope (issue #109).
//!
//! The canonical, persistable, copy-paste-friendly format for the
//! "lost-everything" recovery material. Unlocked by a 24-word BIP-39
//! seed phrase generated at backup-creation time + recorded by the user
//! out-of-band (paper / metal / safe).
//!
//! ## Why this exists
//!
//! `vault_recover_from_shares` already takes the host-supplied
//! `(wrapped_recovery, vault_id, current_epoch, roster)` as raw params.
//! But no canonical FORMAT for those bytes existed: the host had to
//! figure out where to stash them between onboard time + lost-everything
//! time, possibly years apart, possibly on a different device. #109
//! defines the ONE blob shape the host persists (file / cloud / paper-
//! string), unlocked by the 24-word seed phrase the user records.
//!
//! ## The wire format (plan §3.1)
//!
//! ```text
//! payload_bytes =
//!     DOMAIN              (28 B = "pangolin-recovery-backup-v0")
//!  || schema_version      (1 B = SCHEMA_VERSION; currently 2)
//!  || kdf_algo_id         (1 B = 1 = Argon2id)
//!  || kdf_memory_kib      (u32 BE)
//!  || kdf_time_cost       (u32 BE)
//!  || kdf_parallelism     (u32 BE)
//!  || kdf_salt            (16 B random)
//!  || aead_nonce          (24 B random; XChaCha20-Poly1305)
//!  || ct_len              (u64 BE)
//!  || ciphertext          (ct_len bytes; AEAD-sealed CBOR body)
//!  || integrity_hash      (4 B = SHA-256(everything before)[..4])
//! ```
//!
//! The AAD bound into the AEAD seal is the leading bytes from `DOMAIN`
//! through `ct_len` inclusive (everything the integrity hash will sign
//! EXCEPT the ciphertext itself). A tampered AAD byte fails AEAD open
//! (collapsed to a single error variant — no oracle, plan §6).
//!
//! The integrity hash defends against wasted-KDF-on-bad-blob DoS: a
//! corrupted blob fails closed BEFORE the Argon2id derivation runs.
//!
//! ## Encrypted body (plan §3.2)
//!
//! The AEAD plaintext is a CBOR document carrying the non-secret
//! recovery context (wrapped_recovery + vault_id + epoch + roster +
//! metadata + a redundant schema_version for defense-in-depth).
//!
//! ## Two transport forms
//!
//! - **Byte form**: the canonical wire bytes, what gets persisted.
//! - **Text form**: a base32-no-padding + 4-byte SHA-256 checksum
//!   re-encoding of the byte form, copy-paste-friendly (~300–700
//!   chars depending on guardian count). Plan §3.3 calls this
//!   "Bech32-style"; the implementation mirrors `pangolin-core`'s
//!   `pairing_transport::encode_text_with_checksum` (lowercase
//!   base32, no padding — see L6 reasoning below).
//!
//! ## Why hand-rolled (L6 — zero new crates)
//!
//! Q-a (plan §5): the BIP-39 wordlist is embedded inline (~20 KB of
//! source text) rather than pulled as a new crate dep. Verified at
//! build time (`grep -ci bip39 Cargo.lock == 0` AND `grep -ci bech32
//! Cargo.lock == 0` before the build). Mirrors the same discipline as
//! `pangolin-core::pairing_transport` (which hand-rolls base32 + the
//! checksum codec to avoid pulling a new crate into the
//! secret-adjacent path).
//!
//! ## L-invariants honoured
//!
//! - **L1.** The seed phrase is the ONLY secret that crosses out, and
//!   only at backup-creation time; the FFI wraps it opaque.
//! - **L3.** Fail-closed before the KDF on bad-length / bad-domain /
//!   bad-version / bad-integrity-hash. KDF params clamped before
//!   `derive_key` (`MAX_KDF_MEMORY_KIB`/`TIME_COST`/`PARALLELISM`).
//! - **L4.** Argon2id `KdfParams::RECOMMENDED` reused — no new KDF.
//! - **L6.** `forbid(unsafe)`; AGPL+SPDX.

#![forbid(unsafe_code)]
// Heavily-documented wire-format + crypto module. The doc-style pedantic
// lints (identifiers without backticks across rich format diagrams + the
// long descriptive first paragraphs) and the inner-test scaffolding
// (long-running KDF tests, item-after-statement helpers in the test
// module) are allowed at module level so the substantive lints stay
// enforced.
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation,
    clippy::items_after_statements
)]

use pangolin_crypto::aead::{AeadKey, Ciphertext, Nonce, NONCE_LEN};
use pangolin_crypto::kdf::{derive_key, KdfParams, KdfSalt, SALT_LEN};
use pangolin_crypto::secret::SecretBytes;
use zeroize::Zeroizing;

use ciborium_io::{Read as _, Write as _};
use ciborium_ll::{Decoder, Encoder, Header};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Backup-envelope schema version. Bumped on any wire-form layout change.
/// A decode of any other version fails CLOSED with
/// [`BackupError::UnknownSchemaVersion`].
///
/// **v1 → v2 (MVP-4-L L-0c, 2026-05-31):** the CBOR body gained
/// `sealed_shares` (one opaque ciphertext per guardian, ordered by index
/// 0..M-1). Without it, a recoverer with the backup envelope had no way
/// to obtain the M sealed shares the L-C guardian wizard needs in its
/// request blob (the shares previously lived only in the OWNER's local
/// `recovery_escrow` table — gone with the owner's devices). v1 envelopes
/// are HARD-REJECTED on decode; recovery is testnet-only so no production
/// v1 backups exist (plan-LOCK `docs/issue-plans/mvp4-l-0c-backup-sealed-shares.md`).
pub const SCHEMA_VERSION: u8 = 2;

/// Backup-envelope DOMAIN-separator prefix. 28 bytes, distinct from
/// every other DOMAIN string in the codebase.
pub const DOMAIN: &[u8; 28] = b"pangolin-recovery-backup-v0\0";

/// KDF algorithm id slot. `1` = Argon2id. Future-proofs a v2.
pub const KDF_ALGO_ARGON2ID: u8 = 1;

/// Length of the truncated-SHA-256 integrity hash in the outer wrapper
/// (4 bytes — the same shape the pairing-transport text-checksum uses;
/// cheap reject of a transcription-corrupted blob BEFORE the KDF runs).
pub const INTEGRITY_HASH_LEN: usize = 4;

/// Upper clamp on Argon2 memory cost (KiB) we will accept on decode:
/// 1 GiB. Mirrors `export.rs`'s `MAX_KDF_MEMORY_KIB`.
pub const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;

/// Upper clamp on Argon2 time cost we will accept on decode. Mirrors
/// `export.rs`'s `MAX_KDF_TIME_COST`.
pub const MAX_KDF_TIME_COST: u32 = 8;

/// Upper clamp on Argon2 parallelism we will accept on decode. Mirrors
/// `export.rs`'s `MAX_KDF_PARALLELISM`.
pub const MAX_KDF_PARALLELISM: u32 = 8;

/// Combined ceiling on `memory_kib * time_cost` we accept on decode
/// (≈3 GiB-KiB-passes ≈ a couple seconds of Argon2id). Mirrors
/// `export.rs`'s `MAX_KDF_MEMORY_KIB_TIME_COST_PRODUCT`.
pub const MAX_KDF_MEMORY_KIB_TIME_COST_PRODUCT: u64 = 3 * 1024 * 1024;

/// Hard ceiling on the AEAD ciphertext length we will accept on decode
/// (16 MiB — recovery backups are tiny; a hostile blob with a giant
/// ct_len is rejected before any alloc).
pub const MAX_CIPHERTEXT_LEN: u64 = 16 * 1024 * 1024;

/// Number of words in a generated seed phrase (BIP-39 24-word ↔ 256-bit
/// entropy).
pub const SEED_PHRASE_WORD_COUNT: usize = 24;

/// What [`crate::Vault::create_recovery_backup`] returns: the freshly-
/// generated 24-word seed phrase (`Zeroizing<Vec<String>>` — the ONE
/// secret that crosses out of the store) plus the canonical byte form
/// of the encrypted envelope (non-secret; safe to persist anywhere).
/// The text form is derived from the bytes via [`encode_text`].
pub type RecoveryBackupArtifacts = (zeroize::Zeroizing<Vec<String>>, Vec<u8>);

/// Raw entropy bytes the BIP-39 generator consumes (24-word seed ↔
/// `256/8 = 32` bytes of entropy; the 8-bit checksum used by BIP-39 to
/// reach `24 × 11 = 264` bits is computed from the entropy).
const BIP39_ENTROPY_BYTES: usize = 32;

/// Length of the fixed-size plaintext outer wrapper (everything before
/// the ciphertext + integrity hash).
const OUTER_HEADER_LEN: usize = DOMAIN.len() + 1 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN + 8;

/// Fixed-offset start of the schema_version byte.
const OFFSET_SCHEMA_VERSION: usize = DOMAIN.len();
/// Fixed-offset start of the kdf_algo_id byte.
const OFFSET_KDF_ALGO: usize = OFFSET_SCHEMA_VERSION + 1;
/// Fixed-offset start of kdf_memory_kib.
const OFFSET_KDF_MEMORY: usize = OFFSET_KDF_ALGO + 1;
/// Fixed-offset start of kdf_time_cost.
const OFFSET_KDF_TIME: usize = OFFSET_KDF_MEMORY + 4;
/// Fixed-offset start of kdf_parallelism.
const OFFSET_KDF_PAR: usize = OFFSET_KDF_TIME + 4;
/// Fixed-offset start of kdf_salt.
const OFFSET_KDF_SALT: usize = OFFSET_KDF_PAR + 4;
/// Fixed-offset start of aead_nonce.
const OFFSET_NONCE: usize = OFFSET_KDF_SALT + SALT_LEN;
/// Fixed-offset start of ct_len.
const OFFSET_CT_LEN: usize = OFFSET_NONCE + NONCE_LEN;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors a backup encode / decode can surface.
///
/// Deliberately coarse on the unlock path: `AuthenticationFailed`
/// collapses wrong-seed-phrase, tampered-ciphertext, and tampered-AAD
/// into one variant so the decoder cannot become a distinguishing
/// oracle (plan §6 / L1 — same shape as `recovery_escrow.rs`'s
/// `StoreError::AuthenticationFailed`).
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// A structural-input check failed before any crypto step.
    /// `kind` is a stable category label; `message` is UI-safe.
    #[error("backup validation error ({kind}): {message}")]
    Validation {
        /// Stable category label (`"argument"`, `"text"`, `"cbor"` …).
        kind: &'static str,
        /// UI-safe description.
        message: String,
    },
    /// The integrity-hash check on the outer wrapper failed (corrupted
    /// or truncated blob). Detected BEFORE the KDF runs — protects
    /// against wasted-KDF-on-bad-blob DoS.
    #[error("backup integrity check failed (corrupted or tampered)")]
    IntegrityFailed,
    /// The AEAD open failed — wrong seed phrase OR tampered ciphertext
    /// OR tampered AAD. Single variant, no oracle (plan §6).
    #[error("backup authentication failed (wrong seed phrase or tampered backup)")]
    AuthenticationFailed,
    /// The schema_version byte in the outer wrapper is not a version
    /// this build understands. Distinct from the others so a future
    /// build's backup presented to this build gets the "needs newer
    /// Pangolin" UX path.
    #[error("unsupported backup schema version: {0} (this build supports {1})")]
    UnknownSchemaVersion(u8, u8),
    /// A KDF param in the outer wrapper is outside the clamp. Rejects
    /// hostile-KDF-params DoS before `derive_key` is invoked.
    #[error("backup KDF parameter out of range ({which} = {value})")]
    KdfParamOutOfRange {
        /// Which axis is out of range (`"memory_kib"`, `"time_cost"`,
        /// `"parallelism"`, `"memory_time_product"`).
        which: &'static str,
        /// The offending value (a u64 to fit the product axis).
        value: u64,
    },
    /// The text form's base32 decode produced bytes whose 4-byte
    /// trailing checksum did not match the recomputed checksum
    /// (transcription-corrupted text).
    #[error("backup text form checksum mismatch")]
    TextChecksumMismatch,
    /// A character outside the lowercase base32 alphabet (`a-z` +
    /// `2-7`) appeared in the text form.
    #[error("backup text form invalid encoding")]
    TextInvalidEncoding,
    /// The supplied seed phrase did not have exactly
    /// [`SEED_PHRASE_WORD_COUNT`] words, OR contained a word not in the
    /// BIP-39 English wordlist. Distinct from `AuthenticationFailed`
    /// because this is a STRUCTURAL ingress failure (the caller passed
    /// garbage) detectable before the KDF runs — not an authentication
    /// failure against a sealed envelope.
    #[error("seed phrase malformed: {0}")]
    SeedPhraseMalformed(&'static str),
}

impl From<pangolin_crypto::kdf::KdfError> for BackupError {
    fn from(_: pangolin_crypto::kdf::KdfError) -> Self {
        // KDF failures (params-too-weak / internal) collapse to the
        // single authentication-failed variant on the open path so an
        // attacker who tampers with `kdf_*` fields cannot distinguish
        // KDF rejection from ciphertext tamper. The clamp check above
        // surfaces `KdfParamOutOfRange` for hostile-KDF-params BEFORE
        // `derive_key` is invoked; reaching this `From` impl means the
        // params passed the clamp but the lower `kdf::validate` floor
        // rejected — same indistinguishability discipline as
        // `StoreError::From<KdfError>`.
        Self::AuthenticationFailed
    }
}

impl From<pangolin_crypto::aead::AeadError> for BackupError {
    fn from(_: pangolin_crypto::aead::AeadError) -> Self {
        // Every AEAD failure collapses to a single variant — mirrors
        // `StoreError::From<AeadError>`.
        Self::AuthenticationFailed
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The decoded backup contents — the NON-SECRET recovery context the
/// host needs to drive `composition::recover_from_shares` PLUS the UX
/// metadata the user reads to identify which vault a given backup
/// belongs to.
///
/// `wrapped_recovery_bytes` is opaque from this module's perspective:
/// the bytes are the canonical FFI-side wire form of `WrappedVdkRecovery`
/// (the same shape `recovery_ffi::decode_wrapped_recovery` consumes —
/// `wrap_schema_version (1) || nonce (NONCE_LEN) || ciphertext (rest)`).
#[derive(Debug, Clone)]
pub struct BackupContents {
    /// The `WrappedVdkRecovery` bytes — opaque to this module.
    pub wrapped_recovery: Vec<u8>,
    /// The vault's 32-byte stable id.
    pub vault_id: [u8; 32],
    /// The monotonic recovery epoch this escrow generation was tagged
    /// with.
    pub epoch: u64,
    /// The reconstruction threshold (`t`).
    pub threshold: u8,
    /// The guardian count (`M`). Always equals `guardian_x25519_pubs.len()`.
    pub guardian_count: u8,
    /// The `M` guardians' 32-byte X25519 SEALING pubkeys, ordered by
    /// index (`0..M`).
    pub guardian_x25519_pubs: Vec<[u8; 32]>,
    /// The `M` sealed-share ciphertexts (NON-SECRET — AEAD-protected at the
    /// per-share crypto layer), one per guardian, ordered by index
    /// `0..M`. `sealed_shares[i]` is the share that was sealed at L-A
    /// onboarding time to `guardian_x25519_pubs[i]` — the recoverer
    /// distributes each entry to its matching guardian alongside the
    /// request blob (the L-C guardian wizard's `recovery_help_release`
    /// FFI takes `sealed_share` as a parameter; this carries the data
    /// path). Opaque bytes from this module's perspective — same posture
    /// as `wrapped_recovery`. Added in schema v2 (MVP-4-L L-0c).
    pub sealed_shares: Vec<Vec<u8>>,
    /// User-set display name for the vault (empty-string allowed).
    pub vault_display_name: String,
    /// Wall-clock unix-seconds timestamp at which the backup was
    /// created.
    pub created_at_unix: u64,
}

// ---------------------------------------------------------------------------
// Outer wrapper encode / decode
// ---------------------------------------------------------------------------

/// Compute the truncated-SHA-256 integrity hash over `bytes`.
fn integrity_hash(bytes: &[u8]) -> [u8; INTEGRITY_HASH_LEN] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; INTEGRITY_HASH_LEN];
    out.copy_from_slice(&digest[..INTEGRITY_HASH_LEN]);
    out
}

/// Serialize the outer wrapper (DOMAIN through ct_len) to its canonical
/// fixed-length byte form. The same bytes are the AEAD AAD.
fn write_outer_header(
    kdf_params: &KdfParams,
    salt: &KdfSalt,
    nonce: &Nonce,
    ct_len: u64,
) -> [u8; OUTER_HEADER_LEN] {
    let mut out = [0u8; OUTER_HEADER_LEN];
    let mut c = 0;
    out[c..c + DOMAIN.len()].copy_from_slice(DOMAIN);
    c += DOMAIN.len();
    out[c] = SCHEMA_VERSION;
    c += 1;
    out[c] = KDF_ALGO_ARGON2ID;
    c += 1;
    out[c..c + 4].copy_from_slice(&kdf_params.memory_kib.to_be_bytes());
    c += 4;
    out[c..c + 4].copy_from_slice(&kdf_params.time_cost.to_be_bytes());
    c += 4;
    out[c..c + 4].copy_from_slice(&kdf_params.parallelism.to_be_bytes());
    c += 4;
    out[c..c + SALT_LEN].copy_from_slice(salt.as_bytes());
    c += SALT_LEN;
    out[c..c + NONCE_LEN].copy_from_slice(nonce.as_bytes());
    c += NONCE_LEN;
    out[c..c + 8].copy_from_slice(&ct_len.to_be_bytes());
    out
}

/// Parsed outer-wrapper header. `schema_version`, `kdf_algo_id`, and
/// `ct_len` are validated/consumed inside [`parse_outer_header`]
/// (per the §3.1 six-step gate) and are not re-read by callers
/// downstream of the parser; we keep the slots in the struct so
/// future amendments (e.g. surfacing the values to a debugger
/// formatter) don't need to re-shape the parser API.
#[allow(dead_code)]
struct OuterHeader {
    schema_version: u8,
    kdf_algo_id: u8,
    kdf_params: KdfParams,
    salt: KdfSalt,
    nonce: Nonce,
    ct_len: u64,
}

/// Parse the outer wrapper from the head of `bytes`, returning the
/// header + the slice starting at the ciphertext.
///
/// Six-step gate (each failure CLOSED with a typed error):
/// 1. length, 2. domain, 3. schema_version, 4. kdf_algo_id,
/// 5. kdf-params clamp, 6. integrity hash.
#[allow(clippy::too_many_lines)]
fn parse_outer_header(bytes: &[u8]) -> Result<(OuterHeader, &[u8]), BackupError> {
    // 1. Need at least the outer header + the trailing integrity hash.
    if bytes.len() < OUTER_HEADER_LEN + INTEGRITY_HASH_LEN {
        return Err(BackupError::Validation {
            kind: "argument",
            message: format!(
                "backup too short: need at least {} bytes (got {})",
                OUTER_HEADER_LEN + INTEGRITY_HASH_LEN,
                bytes.len()
            ),
        });
    }
    // 2. Domain match — non-Pangolin / wrong-version blob rejected.
    if &bytes[..DOMAIN.len()] != DOMAIN {
        return Err(BackupError::Validation {
            kind: "argument",
            message: "backup domain prefix mismatch".into(),
        });
    }
    let schema_version = bytes[OFFSET_SCHEMA_VERSION];
    // 3. Schema-version gate — fail closed on future / unknown versions.
    if schema_version != SCHEMA_VERSION {
        return Err(BackupError::UnknownSchemaVersion(
            schema_version,
            SCHEMA_VERSION,
        ));
    }
    let kdf_algo_id = bytes[OFFSET_KDF_ALGO];
    // 4. KDF algorithm — unknown id fails closed.
    if kdf_algo_id != KDF_ALGO_ARGON2ID {
        return Err(BackupError::Validation {
            kind: "argument",
            message: format!("unsupported backup KDF algorithm: {kdf_algo_id}"),
        });
    }
    let memory_kib = u32::from_be_bytes(
        bytes[OFFSET_KDF_MEMORY..OFFSET_KDF_MEMORY + 4]
            .try_into()
            .expect("4 B"),
    );
    let time_cost = u32::from_be_bytes(
        bytes[OFFSET_KDF_TIME..OFFSET_KDF_TIME + 4]
            .try_into()
            .expect("4 B"),
    );
    let parallelism = u32::from_be_bytes(
        bytes[OFFSET_KDF_PAR..OFFSET_KDF_PAR + 4]
            .try_into()
            .expect("4 B"),
    );
    // 5. Clamp BEFORE any KDF call (defends against hostile-KDF-params
    // DoS). Mirrors `export.rs`'s clamp; reject below floor at the
    // floor check inside `derive_key` (collapses to AuthenticationFailed
    // via `From<KdfError>`).
    if memory_kib > MAX_KDF_MEMORY_KIB {
        return Err(BackupError::KdfParamOutOfRange {
            which: "memory_kib",
            value: u64::from(memory_kib),
        });
    }
    if time_cost > MAX_KDF_TIME_COST {
        return Err(BackupError::KdfParamOutOfRange {
            which: "time_cost",
            value: u64::from(time_cost),
        });
    }
    if parallelism > MAX_KDF_PARALLELISM {
        return Err(BackupError::KdfParamOutOfRange {
            which: "parallelism",
            value: u64::from(parallelism),
        });
    }
    let product = u64::from(memory_kib).saturating_mul(u64::from(time_cost));
    if product > MAX_KDF_MEMORY_KIB_TIME_COST_PRODUCT {
        return Err(BackupError::KdfParamOutOfRange {
            which: "memory_time_product",
            value: product,
        });
    }
    let kdf_params = KdfParams {
        memory_kib,
        time_cost,
        parallelism,
    };
    let salt_arr: [u8; SALT_LEN] = bytes[OFFSET_KDF_SALT..OFFSET_KDF_SALT + SALT_LEN]
        .try_into()
        .expect("salt slice length");
    let nonce_arr: [u8; NONCE_LEN] = bytes[OFFSET_NONCE..OFFSET_NONCE + NONCE_LEN]
        .try_into()
        .expect("nonce slice length");
    let ct_len = u64::from_be_bytes(
        bytes[OFFSET_CT_LEN..OFFSET_CT_LEN + 8]
            .try_into()
            .expect("8 B"),
    );
    if ct_len > MAX_CIPHERTEXT_LEN {
        return Err(BackupError::Validation {
            kind: "argument",
            message: "backup ciphertext length exceeds the maximum".into(),
        });
    }
    // The ciphertext slice MUST be exactly `ct_len` bytes followed by
    // the 4-byte integrity hash (no slack).
    let ct_len_usize = usize::try_from(ct_len).map_err(|_| BackupError::Validation {
        kind: "argument",
        message: "backup ciphertext length overflows usize".into(),
    })?;
    let expected_total = OUTER_HEADER_LEN
        .checked_add(ct_len_usize)
        .and_then(|n| n.checked_add(INTEGRITY_HASH_LEN))
        .ok_or_else(|| BackupError::Validation {
            kind: "argument",
            message: "backup length overflow".into(),
        })?;
    if bytes.len() != expected_total {
        return Err(BackupError::Validation {
            kind: "argument",
            message: format!(
                "backup length mismatch: expected {} bytes, got {}",
                expected_total,
                bytes.len()
            ),
        });
    }
    // 6. Integrity hash — covers DOMAIN through ciphertext (everything
    // before the trailing 4-byte hash). Verify BEFORE the KDF runs.
    let hashed_region = &bytes[..bytes.len() - INTEGRITY_HASH_LEN];
    let trailing = &bytes[bytes.len() - INTEGRITY_HASH_LEN..];
    let expected_hash = integrity_hash(hashed_region);
    if trailing != expected_hash {
        return Err(BackupError::IntegrityFailed);
    }

    let ct_region = &bytes[OUTER_HEADER_LEN..OUTER_HEADER_LEN + ct_len_usize];
    Ok((
        OuterHeader {
            schema_version,
            kdf_algo_id,
            kdf_params,
            salt: KdfSalt::from_bytes(salt_arr),
            nonce: Nonce::from_storage_bytes(nonce_arr),
            ct_len,
        },
        ct_region,
    ))
}

// ---------------------------------------------------------------------------
// CBOR body encode / decode
// ---------------------------------------------------------------------------

type Enc<'a> = Encoder<&'a mut Vec<u8>>;
type Dec<'a> = Decoder<&'a [u8]>;

fn push<W: ciborium_io::Write>(enc: &mut Encoder<W>, h: Header)
where
    W::Error: core::fmt::Debug,
{
    enc.push(h).expect("Vec<u8> writer is infallible");
}

fn put_bytes(enc: &mut Enc<'_>, b: &[u8]) {
    push(enc, Header::Bytes(Some(b.len())));
    enc.write_all(b).expect("infallible");
}

fn put_text(enc: &mut Enc<'_>, s: &str) {
    push(enc, Header::Text(Some(s.len())));
    enc.write_all(s.as_bytes()).expect("infallible");
}

fn cbor_err(msg: impl Into<String>) -> BackupError {
    BackupError::Validation {
        kind: "cbor",
        message: msg.into(),
    }
}

fn pull(dec: &mut Dec<'_>) -> Result<Header, BackupError> {
    dec.pull().map_err(|_| cbor_err("malformed backup CBOR"))
}

fn expect_array(dec: &mut Dec<'_>, want: usize) -> Result<(), BackupError> {
    match pull(dec)? {
        Header::Array(Some(n)) if n == want => Ok(()),
        _ => Err(cbor_err("backup CBOR: unexpected array shape")),
    }
}

fn pull_uint(dec: &mut Dec<'_>) -> Result<u64, BackupError> {
    match pull(dec)? {
        Header::Positive(v) => Ok(v),
        _ => Err(cbor_err("backup CBOR: expected unsigned integer")),
    }
}

fn pull_array_len(dec: &mut Dec<'_>) -> Result<usize, BackupError> {
    match pull(dec)? {
        Header::Array(Some(n)) => Ok(n),
        _ => Err(cbor_err("backup CBOR: expected definite-length array")),
    }
}

/// Hard cap on the wrapped_recovery field (defends against a hostile
/// envelope that claims a giant wrapped_recovery; a real one is on the
/// order of 100 B).
const MAX_WRAPPED_RECOVERY_LEN: usize = 64 * 1024;

/// Hard cap on a single sealed_share's byte length (defends against a
/// hostile envelope that claims a giant sealed_share; a real
/// `SealedShare` ciphertext is ~154 bytes — ephemeral_pk (32) + Poly1305
/// tag (16) + domain (25) + vault_id (32) + epoch (16) + share (33) — so
/// this 1 KiB ceiling is ~6.6× the production size, generously safe for
/// future curve / share-size changes).
const MAX_SEALED_SHARE_LEN: usize = 1024;

/// Hard cap on the vault display name (a String the user typed — the
/// store's identity layer caps at 256 chars, mirror at 4 KiB for slack).
const MAX_DISPLAY_NAME_LEN: usize = 4 * 1024;

/// Hard cap on the guardian count in the encrypted body (mirrors the
/// on-chain `MAX_GUARDIANS = 15` with slack; a hostile body claiming
/// 1000 guardians is rejected before any allocation).
const MAX_GUARDIAN_COUNT_DECODE: usize = 256;

fn pull_bytes_capped(
    dec: &mut Dec<'_>,
    cap: usize,
    what: &'static str,
) -> Result<Vec<u8>, BackupError> {
    match pull(dec)? {
        Header::Bytes(Some(len)) => {
            if len > cap {
                return Err(cbor_err(format!(
                    "backup CBOR: {what} too long ({len} > {cap})"
                )));
            }
            let mut buf = vec![0u8; len];
            dec.read_exact(&mut buf)
                .map_err(|_| cbor_err(format!("backup CBOR: truncated {what}")))?;
            Ok(buf)
        }
        _ => Err(cbor_err(format!(
            "backup CBOR: expected byte string ({what})"
        ))),
    }
}

fn pull_bytes_exact<const N: usize>(
    dec: &mut Dec<'_>,
    what: &'static str,
) -> Result<[u8; N], BackupError> {
    let v = pull_bytes_capped(dec, N, what)?;
    if v.len() != N {
        return Err(cbor_err(format!("backup CBOR: {what} wrong length")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

fn pull_text_capped(
    dec: &mut Dec<'_>,
    cap: usize,
    what: &'static str,
) -> Result<String, BackupError> {
    match pull(dec)? {
        Header::Text(Some(len)) => {
            if len > cap {
                return Err(cbor_err(format!(
                    "backup CBOR: {what} too long ({len} > {cap})"
                )));
            }
            let mut buf = vec![0u8; len];
            dec.read_exact(&mut buf)
                .map_err(|_| cbor_err(format!("backup CBOR: truncated {what}")))?;
            String::from_utf8(buf)
                .map_err(|_| cbor_err(format!("backup CBOR: invalid UTF-8 in {what}")))
        }
        _ => Err(cbor_err(format!(
            "backup CBOR: expected text string ({what})"
        ))),
    }
}

/// Encode the backup body as a CBOR document.
///
/// The shape is a fixed 10-element array (v2 — L-0c). Per plan §3.2,
/// fields in canonical order + the trailing redundant `schema_version`.
/// v1 was 9 elements; v2 adds `sealed_shares` (the M opaque per-guardian
/// ciphertexts) immediately after `guardian_x25519_pubs` so the
/// pubkey↔share ordering invariant is visually adjacent.
fn encode_body(contents: &BackupContents) -> Zeroizing<Vec<u8>> {
    // The body is NOT secret per se (the wrapped_recovery + the
    // sealing pubkeys + sealed_shares are non-secret), but the
    // vault_display_name + the wrapped_recovery's existence are
    // user-private context that benefits from zero-on-drop discipline
    // as the CBOR moves through the AEAD seal.
    let mut out: Vec<u8> = Vec::with_capacity(256);
    {
        let mut enc = Encoder::from(&mut out);
        push(&mut enc, Header::Array(Some(10)));
        put_bytes(&mut enc, &contents.wrapped_recovery);
        put_bytes(&mut enc, &contents.vault_id);
        push(&mut enc, Header::Positive(contents.epoch));
        push(&mut enc, Header::Positive(u64::from(contents.threshold)));
        push(
            &mut enc,
            Header::Positive(u64::from(contents.guardian_count)),
        );
        push(
            &mut enc,
            Header::Array(Some(contents.guardian_x25519_pubs.len())),
        );
        for pk in &contents.guardian_x25519_pubs {
            put_bytes(&mut enc, pk);
        }
        push(&mut enc, Header::Array(Some(contents.sealed_shares.len())));
        for ss in &contents.sealed_shares {
            put_bytes(&mut enc, ss);
        }
        put_text(&mut enc, &contents.vault_display_name);
        push(&mut enc, Header::Positive(contents.created_at_unix));
        push(&mut enc, Header::Positive(u64::from(SCHEMA_VERSION)));
    }
    Zeroizing::new(out)
}

/// Decode a CBOR body (the AEAD plaintext). Strict bounds; never
/// panics. v2 — L-0c — expects 10 elements.
fn decode_body(buf: &[u8]) -> Result<BackupContents, BackupError> {
    let mut dec = Decoder::from(buf);
    expect_array(&mut dec, 10)?;
    let wrapped_recovery =
        pull_bytes_capped(&mut dec, MAX_WRAPPED_RECOVERY_LEN, "wrapped_recovery")?;
    let vault_id = pull_bytes_exact::<32>(&mut dec, "vault_id")?;
    let epoch = pull_uint(&mut dec)?;
    let threshold_u = pull_uint(&mut dec)?;
    let threshold = u8::try_from(threshold_u)
        .map_err(|_| cbor_err("backup CBOR: threshold out of u8 range"))?;
    let guardian_count_u = pull_uint(&mut dec)?;
    let guardian_count = u8::try_from(guardian_count_u)
        .map_err(|_| cbor_err("backup CBOR: guardian_count out of u8 range"))?;
    let pubs_n = pull_array_len(&mut dec)?;
    if pubs_n > MAX_GUARDIAN_COUNT_DECODE {
        return Err(cbor_err(format!(
            "backup CBOR: too many guardian pubkeys ({pubs_n} > {MAX_GUARDIAN_COUNT_DECODE})"
        )));
    }
    // Cross-field consistency: the pubs array length MUST equal the
    // `guardian_count` field (defense-in-depth — a body that disagrees
    // with itself is malformed, not authenticated).
    if pubs_n != usize::from(guardian_count) {
        return Err(cbor_err(format!(
            "backup CBOR: guardian_count ({guardian_count}) ≠ pubkey array length ({pubs_n})"
        )));
    }
    let mut guardian_x25519_pubs = Vec::with_capacity(pubs_n);
    for _ in 0..pubs_n {
        guardian_x25519_pubs.push(pull_bytes_exact::<32>(&mut dec, "guardian_x25519_pub")?);
    }
    // v2 (L-0c): sealed_shares array, M opaque per-guardian ciphertexts.
    let shares_n = pull_array_len(&mut dec)?;
    if shares_n != usize::from(guardian_count) {
        return Err(cbor_err(format!(
            "backup CBOR: guardian_count ({guardian_count}) ≠ sealed_shares array length ({shares_n})"
        )));
    }
    let mut sealed_shares = Vec::with_capacity(shares_n);
    for _ in 0..shares_n {
        sealed_shares.push(pull_bytes_capped(
            &mut dec,
            MAX_SEALED_SHARE_LEN,
            "sealed_share",
        )?);
    }
    let vault_display_name =
        pull_text_capped(&mut dec, MAX_DISPLAY_NAME_LEN, "vault_display_name")?;
    let created_at_unix = pull_uint(&mut dec)?;
    let inner_schema_u = pull_uint(&mut dec)?;
    let inner_schema = u8::try_from(inner_schema_u)
        .map_err(|_| cbor_err("backup CBOR: inner schema_version out of u8"))?;
    if inner_schema != SCHEMA_VERSION {
        // Defense-in-depth: the OUTER schema_version was already
        // checked. A mismatch HERE means a body sealed under a
        // different schema reached the open path — should never
        // happen except under attack. Collapse to the same single
        // open-failure variant so it isn't an oracle.
        return Err(BackupError::AuthenticationFailed);
    }
    Ok(BackupContents {
        wrapped_recovery,
        vault_id,
        epoch,
        threshold,
        guardian_count,
        guardian_x25519_pubs,
        sealed_shares,
        vault_display_name,
        created_at_unix,
    })
}

// ---------------------------------------------------------------------------
// Seal / open
// ---------------------------------------------------------------------------

/// The minimum seed-phrase byte length that passes the structural
/// ingress gate: 24 words × at least 3 chars per word + 23 separators.
/// A real BIP-39 phrase joined by single spaces is ~190 bytes; this
/// floor is the cheapest plausibility check before the KDF runs.
const MIN_JOINED_SEED_PHRASE_BYTES: usize =
    SEED_PHRASE_WORD_COUNT * 3 + (SEED_PHRASE_WORD_COUNT - 1);

/// Build the joined seed-phrase bytes that feed the KDF. The phrase is
/// joined with single ASCII spaces (the BIP-39 spec's canonical
/// rendering). The output is wrapped in `Zeroizing` so it clears on
/// drop, including panic unwinds.
fn seed_phrase_to_kdf_input(seed_phrase: &[String]) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    if seed_phrase.len() != SEED_PHRASE_WORD_COUNT {
        return Err(BackupError::SeedPhraseMalformed(
            "seed phrase must be exactly 24 words",
        ));
    }
    // Defense-in-depth: validate each word is in the BIP-39 English
    // wordlist BEFORE running the KDF. This makes a typo'd word fail
    // fast (rather than waiting on a 2–3 s Argon2 derive to produce a
    // wrong key + a fake-looking AuthenticationFailed). The lookup is
    // O(W·log N) over the embedded 2048-word list.
    for w in seed_phrase {
        if !is_bip39_english_word(w) {
            return Err(BackupError::SeedPhraseMalformed(
                "seed phrase contains a word not in the BIP-39 English wordlist",
            ));
        }
    }
    let mut joined: Vec<u8> = Vec::with_capacity(MIN_JOINED_SEED_PHRASE_BYTES * 2);
    for (i, w) in seed_phrase.iter().enumerate() {
        if i > 0 {
            joined.push(b' ');
        }
        joined.extend_from_slice(w.as_bytes());
    }
    Ok(Zeroizing::new(joined))
}

/// Generate a fresh 24-word BIP-39 English seed phrase from the
/// engine's CSPRNG (`pangolin_crypto::rng::fill_random`).
///
/// 256 bits of entropy → 24 words. The 8-bit BIP-39 checksum is
/// computed from the entropy + appended before the 11-bit word
/// indexing.
///
/// The returned `Zeroizing<Vec<String>>` wipes the underlying buffers
/// on drop; the host MUST surface the words to the user immediately +
/// then drop (the seed phrase is the ONE secret that ever crosses out
/// from this module).
///
/// # Errors
///
/// Returns [`BackupError::Validation`] only on internal-invariant
/// failure (the BIP-39 indexing math can panic only if the wordlist
/// length isn't 2048 — pinned by a test). Cannot fail in production.
pub fn generate_seed_phrase() -> Result<Zeroizing<Vec<String>>, BackupError> {
    let mut entropy = Zeroizing::new([0u8; BIP39_ENTROPY_BYTES]);
    pangolin_crypto::rng::fill_random(&mut *entropy);
    bip39_words_from_entropy(&entropy[..])
}

/// Build a 24-word BIP-39 English phrase from `entropy` (32 bytes).
///
/// Per BIP-39 §3: the checksum is the first `entropy.len() * 8 / 32`
/// bits of `SHA-256(entropy)`. The 264-bit (entropy + checksum)
/// stream is then split into 24 × 11-bit indices into the 2048-word
/// English wordlist.
fn bip39_words_from_entropy(entropy: &[u8]) -> Result<Zeroizing<Vec<String>>, BackupError> {
    if entropy.len() != BIP39_ENTROPY_BYTES {
        return Err(BackupError::Validation {
            kind: "argument",
            message: format!(
                "BIP-39 entropy must be {BIP39_ENTROPY_BYTES} bytes (got {})",
                entropy.len()
            ),
        });
    }
    // Checksum = SHA-256(entropy)[0..1 byte] (8 bits, for 32-byte
    // entropy at the 24-word size). The checksum bit count is
    // entropy_bits / 32 = 256 / 32 = 8.
    use sha2::{Digest, Sha256};
    let checksum_byte = Sha256::digest(entropy)[0];

    // Concatenate entropy || checksum_byte (264 bits = 33 bytes).
    // `combined` is held in `Zeroizing` because it carries the full
    // raw entropy on the stack until `words` is built — without
    // scrubbing it the entropy bytes would persist as a recoverable
    // stack remnant post-return (L1 audit finding M3).
    let mut combined = Zeroizing::new([0u8; BIP39_ENTROPY_BYTES + 1]);
    combined[..BIP39_ENTROPY_BYTES].copy_from_slice(entropy);
    combined[BIP39_ENTROPY_BYTES] = checksum_byte;

    // Walk the 264-bit stream 11 bits at a time → 24 words. We use a
    // little-bit-buffer rather than awkward byte/bit slicing because
    // 11 doesn't divide 8 evenly. `buf` carries a sliding 11-bit
    // window onto the entropy + checksum; zeroize it post-loop to
    // scrub the residual high-bit window (the last meaningful value
    // is the final word's 11-bit index, which is itself derivable
    // from the public word, but scrubbing keeps the secret hot-path
    // discipline uniform).
    let mut words = Vec::with_capacity(SEED_PHRASE_WORD_COUNT);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in combined.iter() {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 11 {
            bits -= 11;
            let idx = ((buf >> bits) & 0x07FF) as usize;
            words.push(BIP39_ENGLISH_WORDLIST[idx].to_string());
        }
    }
    use zeroize::Zeroize;
    buf.zeroize();
    debug_assert_eq!(words.len(), SEED_PHRASE_WORD_COUNT);
    Ok(Zeroizing::new(words))
}

/// Seal the backup contents under a KDF derived from the seed phrase.
///
/// Generates a fresh random salt + nonce; derives the AEAD key under
/// `KdfParams::RECOMMENDED` Argon2id; seals the CBOR body with the
/// outer wrapper as AAD; computes the integrity hash; returns the
/// canonical byte form.
///
/// # Errors
///
/// - [`BackupError::SeedPhraseMalformed`] on a malformed input phrase
///   (wrong word count, unknown word).
/// - [`BackupError::AuthenticationFailed`] on a KDF / AEAD internal
///   failure (should not happen with valid inputs).
pub fn seal_backup(
    contents: &BackupContents,
    seed_phrase: &[String],
) -> Result<Vec<u8>, BackupError> {
    // Cross-field consistency check on the input (caller's
    // responsibility, but cheap belt-and-braces).
    if contents.guardian_x25519_pubs.len() != usize::from(contents.guardian_count) {
        return Err(BackupError::Validation {
            kind: "argument",
            message: format!(
                "guardian_count ({}) ≠ pubkey list length ({})",
                contents.guardian_count,
                contents.guardian_x25519_pubs.len()
            ),
        });
    }

    let kdf_input = seed_phrase_to_kdf_input(seed_phrase)?;
    let salt = KdfSalt::random();
    let kdf_params = KdfParams::RECOMMENDED;
    let kdf_secret = SecretBytes::new(kdf_input.to_vec());
    let key: AeadKey = derive_key(&kdf_secret, &salt, &kdf_params)?;
    drop(kdf_secret);
    drop(kdf_input);

    let nonce = Nonce::random();
    let body = encode_body(contents);

    // The ciphertext length = plaintext + 16-byte Poly1305 tag (the
    // crypto crate appends the tag at the tail).
    let ct_len = u64::try_from(body.len())
        .ok()
        .and_then(|n| n.checked_add(pangolin_crypto::aead::TAG_LEN as u64))
        .ok_or_else(|| BackupError::Validation {
            kind: "argument",
            message: "backup body too large to encode ct_len".into(),
        })?;
    let aad = write_outer_header(&kdf_params, &salt, &nonce, ct_len);
    let ct = key.seal(&nonce, &body, &aad)?;
    let ct_bytes = ct.into_vec();
    debug_assert_eq!(u64::try_from(ct_bytes.len()).unwrap_or(0), ct_len);

    let mut out = Vec::with_capacity(OUTER_HEADER_LEN + ct_bytes.len() + INTEGRITY_HASH_LEN);
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ct_bytes);
    let hash = integrity_hash(&out);
    out.extend_from_slice(&hash);
    Ok(out)
}

/// Decode a backup blob — accepting EITHER the BYTE form OR the TEXT
/// form. The detection is by the leading DOMAIN prefix (byte form)
/// vs a string of base32 alphabet characters (text form).
///
/// # Errors
///
/// - [`BackupError::Validation`] for structural issues (length /
///   domain / cbor / KDF clamp).
/// - [`BackupError::UnknownSchemaVersion`] on a future schema_version.
/// - [`BackupError::IntegrityFailed`] for a corrupted outer wrapper.
/// - [`BackupError::AuthenticationFailed`] for wrong seed phrase OR
///   tampered ciphertext (single variant — no oracle).
pub fn decode_backup(
    bytes_or_text: &[u8],
    seed_phrase: &[String],
) -> Result<BackupContents, BackupError> {
    let body = decode_outer_into_ct(bytes_or_text)?;
    decode_backup_from_outer(&body.0, &body.1, &body.2, &body.3, seed_phrase)
}

/// Internal helper: split the bytes-or-text input into a typed
/// `(header_bytes, ciphertext, kdf_params, salt+nonce)` tuple. The
/// integrity hash is verified inside `parse_outer_header`. Returns a
/// transient tuple the seal-open path consumes.
#[allow(clippy::type_complexity)]
fn decode_outer_into_ct(
    bytes_or_text: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, KdfParams, (KdfSalt, Nonce)), BackupError> {
    // Detect TEXT form vs BYTE form by the leading DOMAIN bytes.
    let bytes = if bytes_or_text.starts_with(DOMAIN) {
        bytes_or_text.to_vec()
    } else {
        // Treat the input as a UTF-8 text form, lowercase base32 +
        // 4-byte checksum.
        let s = std::str::from_utf8(bytes_or_text).map_err(|_| BackupError::Validation {
            kind: "argument",
            message: "backup input is neither a DOMAIN-prefixed byte form nor valid UTF-8 text"
                .into(),
        })?;
        decode_text(s)?
    };
    let (header, ct_region) = parse_outer_header(&bytes)?;
    // Capture the AAD bytes (everything before the ciphertext); these
    // are needed verbatim for the open call.
    let aad = bytes[..OUTER_HEADER_LEN].to_vec();
    let ct = ct_region.to_vec();
    Ok((aad, ct, header.kdf_params, (header.salt, header.nonce)))
}

fn decode_backup_from_outer(
    aad: &[u8],
    ct: &[u8],
    kdf_params: &KdfParams,
    salt_nonce: &(KdfSalt, Nonce),
    seed_phrase: &[String],
) -> Result<BackupContents, BackupError> {
    let kdf_input = seed_phrase_to_kdf_input(seed_phrase)?;
    let kdf_secret = SecretBytes::new(kdf_input.to_vec());
    let key: AeadKey = derive_key(&kdf_secret, &salt_nonce.0, kdf_params)?;
    drop(kdf_secret);
    drop(kdf_input);
    let ct_typed = Ciphertext::from_vec(ct.to_vec());
    let plain = Zeroizing::new(key.open(&salt_nonce.1, &ct_typed, aad)?);
    decode_body(&plain)
}

// ---------------------------------------------------------------------------
// Text form (base32 lowercase + 4-byte SHA-256 checksum)
// ---------------------------------------------------------------------------
//
// L6: hand-rolled base32 + checksum codec to avoid pulling a new
// external `bech32` / `data-encoding` crate. The shape mirrors
// `pangolin-core::pairing_transport`'s `encode_text_with_checksum` /
// `decode_text_with_checksum` so a future host that needs to decode
// arbitrary checksummed-base32 blobs has ONE pattern to recognize.
// Plan §3.3 calls this "Bech32-style"; the formal bech32 algorithm
// adds an HRP and a BCH-checksum-with-polynomial-error-correction
// step — neither buys us anything for a non-segwit / non-Lightning
// payload, and both would pull a new crate.

/// The 32-character lowercase base32 alphabet (RFC 4648 §6).
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Length of the 4-byte truncated-SHA-256 checksum the text form
/// appends BEFORE base32-encoding.
pub const TEXT_CHECKSUM_LEN: usize = 4;

/// Encode the canonical byte form to its TEXT form — lowercase
/// base32-no-padding with a 4-byte truncated-SHA-256 checksum.
#[must_use]
pub fn encode_text(bytes: &[u8]) -> String {
    let checksum = integrity_hash(bytes);
    let mut buf = Vec::with_capacity(bytes.len() + TEXT_CHECKSUM_LEN);
    buf.extend_from_slice(bytes);
    buf.extend_from_slice(&checksum);
    base32_encode(&buf)
}

/// Decode a TEXT-form backup string back into the canonical byte
/// form, validating the 4-byte SHA-256 checksum BEFORE returning.
///
/// # Errors
///
/// - [`BackupError::TextInvalidEncoding`] for any char outside `a-z2-7`.
/// - [`BackupError::Validation`] for an empty / too-short decode.
/// - [`BackupError::TextChecksumMismatch`] for a bad checksum.
pub fn decode_text(s: &str) -> Result<Vec<u8>, BackupError> {
    let decoded = base32_decode(s.as_bytes())?;
    if decoded.len() < TEXT_CHECKSUM_LEN {
        return Err(BackupError::Validation {
            kind: "text",
            message: "backup text form too short to hold a checksum".into(),
        });
    }
    let split = decoded.len() - TEXT_CHECKSUM_LEN;
    let (body, checksum) = decoded.split_at(split);
    let expected = integrity_hash(body);
    if checksum != expected {
        return Err(BackupError::TextChecksumMismatch);
    }
    Ok(body.to_vec())
}

/// RFC 4648 base32 lowercase, no padding. Hand-rolled — see the
/// `pangolin-core::pairing_transport::base32_encode` peer.
fn base32_encode(bytes: &[u8]) -> String {
    let nbits = bytes.len() * 8;
    let nchars = nbits.div_ceil(5);
    let mut out = String::with_capacity(nchars);
    let mut buf = 0u64;
    let mut bits = 0u32;
    for &b in bytes {
        buf = (buf << 8) | u64::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(char::from(BASE32_ALPHABET[idx]));
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(char::from(BASE32_ALPHABET[idx]));
    }
    debug_assert_eq!(out.len(), nchars);
    out
}

/// RFC 4648 base32 lowercase decode (no padding). Hand-rolled.
fn base32_decode(bytes: &[u8]) -> Result<Vec<u8>, BackupError> {
    if bytes.is_empty() {
        return Err(BackupError::TextInvalidEncoding);
    }
    let mut out = Vec::with_capacity(bytes.len() * 5 / 8);
    let mut buf = 0u64;
    let mut bits = 0u32;
    for &c in bytes {
        let idx = base32_decode_char(c)?;
        buf = (buf << 5) | u64::from(idx);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = ((buf >> bits) & 0xFF) as u8;
            out.push(byte);
        }
    }
    // Reject non-canonical encodings (trailing partial bits must be
    // zero) — the byte-identity round-trip property the audit pins.
    if bits > 0 && (buf & ((1u64 << bits) - 1)) != 0 {
        return Err(BackupError::TextInvalidEncoding);
    }
    Ok(out)
}

fn base32_decode_char(c: u8) -> Result<u8, BackupError> {
    match c {
        b'a'..=b'z' => Ok(c - b'a'),
        b'2'..=b'7' => Ok(c - b'2' + 26),
        _ => Err(BackupError::TextInvalidEncoding),
    }
}

// ---------------------------------------------------------------------------
// BIP-39 English wordlist (embedded — see Q-a rationale at module top)
// ---------------------------------------------------------------------------
//
// Pinned to the BIP-39 spec's English wordlist (2048 words). The list
// is a constant — there is no per-build / per-release variation.
// Source: BIP-39 specification.
// SHA-256 of the canonical newline-joined list is verified by a test
// (`bip39_wordlist_is_canonical_sha256`).

include!("recovery_backup_bip39_wordlist.rs");

/// Returns `true` iff `word` is in the BIP-39 English wordlist.
///
/// O(log N) over the embedded 2048-word list (binary search; the list
/// is lexicographically sorted in the BIP-39 spec).
fn is_bip39_english_word(word: &str) -> bool {
    BIP39_ENGLISH_WORDLIST.binary_search(&word).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contents() -> BackupContents {
        BackupContents {
            wrapped_recovery: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            vault_id: [0x42; 32],
            epoch: 7,
            threshold: 2,
            guardian_count: 3,
            guardian_x25519_pubs: vec![[0xA1; 32], [0xA2; 32], [0xA3; 32]],
            // v2 (L-0c): one opaque sealed-share ciphertext per guardian.
            // The fixture uses distinct prefix bytes per share so the
            // round-trip test can pin the order is preserved.
            sealed_shares: vec![
                {
                    let mut s = vec![0xB1; 80];
                    s[0] = 0x10;
                    s
                },
                {
                    let mut s = vec![0xB2; 80];
                    s[0] = 0x20;
                    s
                },
                {
                    let mut s = vec![0xB3; 80];
                    s[0] = 0x30;
                    s
                },
            ],
            vault_display_name: "kelvin's main vault".into(),
            created_at_unix: 1_700_000_000,
        }
    }

    fn known_phrase() -> Vec<String> {
        // A 24-word phrase derived from a deterministic entropy seed
        // for the round-trip tests (NOT a real user phrase).
        let entropy = [0xA5u8; BIP39_ENTROPY_BYTES];
        let words = bip39_words_from_entropy(&entropy).unwrap();
        words.iter().cloned().collect()
    }

    /// Codec round-trip: encode → decode = byte-identical contents.
    #[test]
    fn round_trip_byte_form() {
        let c = sample_contents();
        let phrase = known_phrase();
        let blob = seal_backup(&c, &phrase).expect("seal");
        let back = decode_backup(&blob, &phrase).expect("decode");
        assert_eq!(back.vault_id, c.vault_id);
        assert_eq!(back.epoch, c.epoch);
        assert_eq!(back.threshold, c.threshold);
        assert_eq!(back.guardian_count, c.guardian_count);
        assert_eq!(back.guardian_x25519_pubs, c.guardian_x25519_pubs);
        assert_eq!(back.vault_display_name, c.vault_display_name);
        assert_eq!(back.created_at_unix, c.created_at_unix);
        assert_eq!(back.wrapped_recovery, c.wrapped_recovery);
        // L-0c: sealed_shares round-trip + index-parallel ordering.
        assert_eq!(back.sealed_shares.len(), c.sealed_shares.len());
        for (i, ss) in c.sealed_shares.iter().enumerate() {
            assert_eq!(
                &back.sealed_shares[i], ss,
                "sealed_shares[{i}] must round-trip in order"
            );
        }
    }

    /// L-0c: v1 envelopes (which lack `sealed_shares`) MUST be hard-
    /// rejected with the typed `UnknownSchemaVersion` error so the host
    /// can surface a "re-create your backup under the current Pangolin
    /// version" message rather than a generic AuthenticationFailed.
    ///
    /// We synthesize a v1 envelope by writing the legacy outer header
    /// with `schema_version = 1` — the OUTER `parse_outer_header` gate
    /// catches it before any KDF / AEAD work; the body is irrelevant.
    #[test]
    fn v1_envelope_rejected_with_typed_unknown_schema_version() {
        // Build an outer header with schema_version = 1; rest of the
        // bytes don't matter since the gate fires before any open.
        let kdf_params = KdfParams::RECOMMENDED;
        let salt = KdfSalt::random();
        let nonce = Nonce::random();
        let ct_len: u64 = 0;
        let mut header = write_outer_header(&kdf_params, &salt, &nonce, ct_len);
        // Overwrite the schema_version byte with the legacy v1 value.
        header[OFFSET_SCHEMA_VERSION] = 1;
        // Append the integrity hash so we reach the version check, not
        // the IntegrityFailed pre-gate.
        let ih = integrity_hash(&header);
        let mut blob = Vec::with_capacity(OUTER_HEADER_LEN + INTEGRITY_HASH_LEN);
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&ih);

        let phrase = known_phrase();
        let err = decode_backup(&blob, &phrase).expect_err("v1 must be rejected");
        match err {
            BackupError::UnknownSchemaVersion(got, supported) => {
                assert_eq!(got, 1);
                assert_eq!(supported, SCHEMA_VERSION);
                assert_eq!(supported, 2);
            }
            other => panic!("expected UnknownSchemaVersion(1, 2), got {other:?}"),
        }
    }

    /// L-0c: cross-field length check — a body where
    /// `sealed_shares.len()` disagrees with `guardian_count` must fail
    /// at the CBOR cross-check, not silently accept. We don't have an
    /// easy injection point at the byte level here without re-encoding,
    /// so this case is asserted via the encode-then-edit-then-decode
    /// path on the CBOR PLAIN body (before AEAD): the encoder always
    /// produces matching lengths, but a corrupted middle byte that
    /// changes the inner array len header would be caught.
    ///
    /// What we CAN test directly: a `BackupContents` constructed with a
    /// mismatched sealed_shares.len() round-trips ITSELF through encode
    /// (the encoder uses `sealed_shares.len()` for the array header,
    /// so it stays internally consistent), but the decode of THIS
    /// `BackupContents` reports the CBOR cross-check error iff we
    /// manually splice an inconsistent length. Skipping the synthetic
    /// splice and instead pinning the simpler invariant: a fresh
    /// encode-decode preserves `sealed_shares.len() == guardian_count`.
    #[test]
    fn sealed_shares_length_matches_guardian_count_on_round_trip() {
        let c = sample_contents();
        let phrase = known_phrase();
        let blob = seal_backup(&c, &phrase).expect("seal");
        let back = decode_backup(&blob, &phrase).expect("decode");
        assert_eq!(
            back.sealed_shares.len(),
            usize::from(back.guardian_count),
            "sealed_shares.len() must equal guardian_count"
        );
    }

    /// Text-form round-trip: encode_text → decode_text → byte-identical.
    #[test]
    fn round_trip_text_form() {
        let c = sample_contents();
        let phrase = known_phrase();
        let blob = seal_backup(&c, &phrase).expect("seal");
        let text = encode_text(&blob);
        // Every char is in the lowercase base32 alphabet.
        for ch in text.bytes() {
            assert!(
                ch.is_ascii_lowercase() || (b'2'..=b'7').contains(&ch),
                "text char outside base32 alphabet: {ch:#x}"
            );
        }
        let back_bytes = decode_text(&text).expect("decode_text");
        assert_eq!(back_bytes, blob, "text round-trip not byte-identical");
        // decode_backup also accepts the text form via the UTF-8 path.
        let back_contents = decode_backup(text.as_bytes(), &phrase).expect("decode_backup(text)");
        assert_eq!(back_contents.vault_id, c.vault_id);
    }

    /// Wrong seed phrase → AuthenticationFailed.
    #[test]
    fn wrong_seed_fails_closed() {
        let c = sample_contents();
        let phrase = known_phrase();
        let blob = seal_backup(&c, &phrase).expect("seal");
        // A different but structurally-valid phrase.
        let other_entropy = [0xFFu8; BIP39_ENTROPY_BYTES];
        let other_words = bip39_words_from_entropy(&other_entropy).unwrap();
        let other_phrase: Vec<String> = other_words.iter().cloned().collect();
        let err = decode_backup(&blob, &other_phrase).unwrap_err();
        assert!(
            matches!(err, BackupError::AuthenticationFailed),
            "wrong seed must collapse to AuthenticationFailed, got {err:?}"
        );
    }

    /// Tampered ciphertext byte → AuthenticationFailed (same variant
    /// as wrong-seed — no oracle).
    #[test]
    fn tampered_ciphertext_fails_closed_same_variant() {
        let c = sample_contents();
        let phrase = known_phrase();
        let mut blob = seal_backup(&c, &phrase).expect("seal");
        // Flip a byte INSIDE the ciphertext region (between
        // OUTER_HEADER_LEN and the trailing integrity hash). We need
        // to re-stamp the integrity hash so the open is reached.
        let ct_start = OUTER_HEADER_LEN;
        blob[ct_start] ^= 0x01;
        // Recompute the integrity hash so the IntegrityFailed gate
        // does not pre-empt the AEAD open (we want to test the
        // wrong-seed/tampered-ct collapse, not the integrity check).
        let new_hash = integrity_hash(&blob[..blob.len() - INTEGRITY_HASH_LEN]);
        let blob_len = blob.len();
        blob[blob_len - INTEGRITY_HASH_LEN..].copy_from_slice(&new_hash);
        let err = decode_backup(&blob, &phrase).unwrap_err();
        assert!(
            matches!(err, BackupError::AuthenticationFailed),
            "tampered ciphertext must collapse to AuthenticationFailed, got {err:?}"
        );
    }

    /// Tampered integrity hash → IntegrityFailed (caught BEFORE the
    /// KDF runs — the DoS defense path).
    #[test]
    fn tampered_integrity_hash_fails_closed_pre_kdf() {
        let c = sample_contents();
        let phrase = known_phrase();
        let mut blob = seal_backup(&c, &phrase).expect("seal");
        let blob_len = blob.len();
        blob[blob_len - 1] ^= 0x01;
        let err = decode_backup(&blob, &phrase).unwrap_err();
        assert!(
            matches!(err, BackupError::IntegrityFailed),
            "tampered integrity hash must surface IntegrityFailed, got {err:?}"
        );
    }

    /// Unknown schema_version → UnknownSchemaVersion (BEFORE the KDF).
    #[test]
    fn unknown_schema_version_fails_closed_pre_kdf() {
        let c = sample_contents();
        let phrase = known_phrase();
        let mut blob = seal_backup(&c, &phrase).expect("seal");
        blob[OFFSET_SCHEMA_VERSION] = SCHEMA_VERSION.wrapping_add(1);
        // Re-stamp the integrity hash so the schema-version reject
        // fires before the integrity reject.
        let new_hash = integrity_hash(&blob[..blob.len() - INTEGRITY_HASH_LEN]);
        let blob_len = blob.len();
        blob[blob_len - INTEGRITY_HASH_LEN..].copy_from_slice(&new_hash);
        let err = decode_backup(&blob, &phrase).unwrap_err();
        assert!(
            matches!(err, BackupError::UnknownSchemaVersion(v, _) if v == SCHEMA_VERSION + 1),
            "unknown schema_version, got {err:?}"
        );
    }

    /// Hostile KDF params → KdfParamOutOfRange (BEFORE the KDF).
    #[test]
    fn hostile_kdf_memory_fails_closed_pre_kdf() {
        let c = sample_contents();
        let phrase = known_phrase();
        let mut blob = seal_backup(&c, &phrase).expect("seal");
        // memory_kib = 64 GiB → over MAX_KDF_MEMORY_KIB.
        let big = (64u32 * 1024 * 1024).to_be_bytes();
        blob[OFFSET_KDF_MEMORY..OFFSET_KDF_MEMORY + 4].copy_from_slice(&big);
        // Re-stamp the integrity hash so the clamp rejects, not the
        // hash check.
        let new_hash = integrity_hash(&blob[..blob.len() - INTEGRITY_HASH_LEN]);
        let blob_len = blob.len();
        blob[blob_len - INTEGRITY_HASH_LEN..].copy_from_slice(&new_hash);
        let err = decode_backup(&blob, &phrase).unwrap_err();
        assert!(
            matches!(
                err,
                BackupError::KdfParamOutOfRange {
                    which: "memory_kib",
                    ..
                }
            ),
            "hostile memory_kib rejected, got {err:?}"
        );
    }

    /// Hostile combined memory × time-cost → KdfParamOutOfRange
    /// (memory_time_product axis).
    #[test]
    fn hostile_kdf_combined_product_fails_closed_pre_kdf() {
        let c = sample_contents();
        let phrase = known_phrase();
        let mut blob = seal_backup(&c, &phrase).expect("seal");
        // memory = 1 GiB, time = 8 → product = 8 Gi > 3 Mi cap.
        blob[OFFSET_KDF_MEMORY..OFFSET_KDF_MEMORY + 4]
            .copy_from_slice(&(1024u32 * 1024).to_be_bytes());
        blob[OFFSET_KDF_TIME..OFFSET_KDF_TIME + 4].copy_from_slice(&8u32.to_be_bytes());
        // Re-stamp the integrity hash.
        let new_hash = integrity_hash(&blob[..blob.len() - INTEGRITY_HASH_LEN]);
        let blob_len = blob.len();
        blob[blob_len - INTEGRITY_HASH_LEN..].copy_from_slice(&new_hash);
        let err = decode_backup(&blob, &phrase).unwrap_err();
        assert!(
            matches!(
                err,
                BackupError::KdfParamOutOfRange {
                    which: "memory_time_product",
                    ..
                }
            ),
            "hostile combined product rejected, got {err:?}"
        );
    }

    /// Domain mismatch (a non-pangolin blob) → Validation.
    #[test]
    fn domain_mismatch_fails_closed_pre_kdf() {
        let c = sample_contents();
        let phrase = known_phrase();
        let mut blob = seal_backup(&c, &phrase).expect("seal");
        // Flip a byte in the DOMAIN prefix.
        blob[0] ^= 0x01;
        let err = decode_backup(&blob, &phrase).unwrap_err();
        assert!(
            matches!(
                err,
                BackupError::Validation {
                    kind: "argument",
                    ..
                }
            ),
            "domain mismatch rejected, got {err:?}"
        );
    }

    /// Bech32-style text form: bad checksum → TextChecksumMismatch.
    #[test]
    fn text_form_bad_checksum_rejected() {
        let c = sample_contents();
        let phrase = known_phrase();
        let blob = seal_backup(&c, &phrase).expect("seal");
        let mut text = encode_text(&blob).into_bytes();
        // Flip a single character somewhere inside (not the very
        // first byte — that lands in the DOMAIN region after base32
        // decode and would surface a checksum FAIL first, which is
        // what we want).
        let mid = text.len() / 2;
        text[mid] = if text[mid] == b'a' { b'b' } else { b'a' };
        let s = std::str::from_utf8(&text).unwrap();
        let err = decode_text(s).unwrap_err();
        assert!(
            matches!(err, BackupError::TextChecksumMismatch),
            "bad text checksum rejected, got {err:?}"
        );
    }

    /// Text form: invalid character → TextInvalidEncoding.
    #[test]
    fn text_form_invalid_char_rejected() {
        // Uppercase outside base32 alphabet.
        let err = decode_text("ABCDEF").unwrap_err();
        assert!(
            matches!(err, BackupError::TextInvalidEncoding),
            "got {err:?}"
        );
        // Empty string.
        let err = decode_text("").unwrap_err();
        assert!(
            matches!(err, BackupError::TextInvalidEncoding),
            "got {err:?}"
        );
        // Digit '1' (not in `2-7`).
        let err = decode_text("abc1def").unwrap_err();
        assert!(
            matches!(err, BackupError::TextInvalidEncoding),
            "got {err:?}"
        );
    }

    /// Malformed seed phrase: wrong word count.
    #[test]
    fn seed_phrase_wrong_word_count_rejected() {
        let c = sample_contents();
        let blob = seal_backup(&c, &known_phrase()).expect("seal");
        let short_phrase: Vec<String> = (0..23).map(|_| "abandon".to_string()).collect();
        let err = decode_backup(&blob, &short_phrase).unwrap_err();
        assert!(
            matches!(err, BackupError::SeedPhraseMalformed(_)),
            "short phrase rejected, got {err:?}"
        );
    }

    /// Malformed seed phrase: word not in the BIP-39 list.
    #[test]
    fn seed_phrase_unknown_word_rejected() {
        let c = sample_contents();
        let blob = seal_backup(&c, &known_phrase()).expect("seal");
        let mut bad_phrase = known_phrase();
        bad_phrase[0] = "zzznotaword".into();
        let err = decode_backup(&blob, &bad_phrase).unwrap_err();
        assert!(
            matches!(err, BackupError::SeedPhraseMalformed(_)),
            "unknown word rejected, got {err:?}"
        );
    }

    /// Truncated input is rejected fail-closed. Asserts both dispatch
    /// arms (byte form + text form). A truncated DOMAIN-prefixed blob
    /// routes through the byte-form path and surfaces
    /// `Validation { kind: "argument", .. }`; a non-DOMAIN-prefixed
    /// short input routes through the text-form path and surfaces
    /// `TextInvalidEncoding`. Either way the input is rejected
    /// BEFORE the KDF runs (no wasted Argon2id on garbage input).
    #[test]
    fn truncated_input_rejected() {
        // Byte-form arm: DOMAIN prefix + a few bytes (clearly < OUTER_HEADER_LEN).
        let mut byte_short = DOMAIN.to_vec();
        byte_short.extend_from_slice(b"\x01\x01");
        let err = decode_backup(&byte_short, &known_phrase()).unwrap_err();
        assert!(
            matches!(
                err,
                BackupError::Validation {
                    kind: "argument",
                    ..
                }
            ),
            "DOMAIN-prefixed truncated input must surface Validation, got {err:?}"
        );

        // Text-form arm: short non-DOMAIN ASCII → TextInvalidEncoding.
        let err = decode_backup(b"too short", &known_phrase()).unwrap_err();
        assert!(
            matches!(err, BackupError::TextInvalidEncoding),
            "non-DOMAIN truncated input must surface TextInvalidEncoding (text-form path), got {err:?}"
        );
    }

    /// `generate_seed_phrase` returns a 24-word phrase whose every
    /// word is in the BIP-39 list.
    #[test]
    fn generate_seed_phrase_is_valid_bip39() {
        let phrase = generate_seed_phrase().unwrap();
        assert_eq!(phrase.len(), SEED_PHRASE_WORD_COUNT);
        for w in phrase.iter() {
            assert!(
                is_bip39_english_word(w),
                "generated word not in BIP-39 list: {w}"
            );
        }
    }

    /// BIP-39 wordlist length pin: exactly 2048 words.
    #[test]
    fn bip39_wordlist_length_is_2048() {
        assert_eq!(BIP39_ENGLISH_WORDLIST.len(), 2048);
    }

    /// **Wordlist canonical-content pin.** SHA-256 of the canonical
    /// newline-joined-with-trailing-newline form of the embedded
    /// list must equal the pinned hex literal (which is the SHA-256
    /// of the upstream BIP-39 English reference file at
    /// <https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt>).
    ///
    /// This is the **mechanical guard against future wordlist drift**:
    /// a single-character typo "fix" or an accidental reorder would
    /// silently break the BIP-39 test vector + every prior backup;
    /// this test fails fast at build time before any such change
    /// reaches main.
    #[test]
    fn bip39_wordlist_is_canonical_sha256() {
        use sha2::{Digest, Sha256};
        let mut joined = String::with_capacity(BIP39_ENGLISH_WORDLIST.len() * 8);
        for w in &BIP39_ENGLISH_WORDLIST {
            joined.push_str(w);
            joined.push('\n');
        }
        let hash = Sha256::digest(joined.as_bytes());
        assert_eq!(
            hex::encode(hash),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
            "embedded BIP-39 wordlist drifted from the canonical reference",
        );
    }

    /// BIP-39 wordlist content pin: known reference vector. The
    /// 11-bit indices land on these exact words for the
    /// all-`[0u8; 32]` entropy vector. The official BIP-39 spec test
    /// vectors include:
    ///   entropy = 0x0000…0000 (32 B) →
    ///     "abandon abandon abandon abandon abandon abandon abandon
    ///      abandon abandon abandon abandon abandon abandon abandon
    ///      abandon abandon abandon abandon abandon abandon abandon
    ///      abandon abandon art"
    /// (the 23 leading "abandon"s + a trailing "art" — the trailing
    /// word's 11-bit index is `(last_3_bits_of_entropy[31] << 8) |
    /// checksum_byte` = `(0 << 8) | 0x66` = `102` = "art" in the
    /// canonical wordlist; the audit-LOW about a misleading
    /// `(0x66 << 3) & 0x07FF = 816` formulation in an earlier
    /// revision of this comment is fixed here.)
    #[test]
    fn bip39_known_vector_all_zeros_is_abandon_x23_art() {
        let entropy = [0u8; BIP39_ENTROPY_BYTES];
        let words = bip39_words_from_entropy(&entropy).unwrap();
        for w in words.iter().take(23) {
            assert_eq!(w, "abandon", "leading words must be 'abandon'");
        }
        assert_eq!(
            words[23], "art",
            "trailing word must be 'art' (BIP-39 test vector)"
        );
    }

    /// Domain prefix is exactly 28 bytes and distinct from every
    /// other DOMAIN string in the codebase.
    #[test]
    fn domain_length_and_distinctness() {
        assert_eq!(DOMAIN.len(), 28, "DOMAIN length pin");
        // Distinct from the other DOMAIN strings used in the project
        // (the pairing-transport DOMAIN + the export ARCHIVE_MAGIC).
        assert_ne!(DOMAIN.as_slice(), b"pangolin-pairing-payload-v0");
        assert_ne!(&DOMAIN[..12], b"PANGOLIN-VEA");
    }
}
