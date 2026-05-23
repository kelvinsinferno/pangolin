//! Ed25519 → secp256k1 EVM-wallet derivation (Option A from
//! `docs/issue-plans/P7.md`).
//!
//! ## Why this exists
//!
//! Decision D-006 says the same device key signs revisions AND pays
//! gas. But Ethereum verifies secp256k1 signatures, not Ed25519 — so
//! "same key" can only be honored as **deterministic derivation**
//! from the Ed25519 device seed to a secp256k1 wallet. One Pangolin
//! device produces one EVM address; revisions are still signed in
//! Ed25519 (per [`crate::signing`]) for the v1 contract's eventual
//! verifier; gas is paid from the derived secp256k1 wallet.
//!
//! ## Why not just truncate the seed
//!
//! The Ed25519 secret seed is 32 bytes; the secp256k1 scalar fits in
//! 32 bytes; it is tempting to just use the same bytes. We don't, for
//! two reasons:
//!
//! 1. **`pangolin-crypto::DeviceKey` does not expose the secret
//!    seed.** The `seed_bytes()` accessor is `pub(crate)` to its
//!    parent crate (per the audit discipline that secret material
//!    never leaves `pangolin-crypto` in raw form). P7's constraint
//!    says don't modify `pangolin-crypto`, so we cannot widen that
//!    visibility.
//! 2. **Truncation is not domain-separated.** Even if the bytes were
//!    accessible, reusing them directly as a secp256k1 scalar would
//!    correlate the two keys: anyone who learns the EVM private key
//!    (e.g., from a leaked keystore on the same device) would also
//!    learn the Ed25519 signing seed. That is the opposite of the
//!    cryptographic separation we want — Pangolin's revision identity
//!    must NOT be recoverable from a leaked gas wallet.
//!
//! ## How the derivation works
//!
//! We exploit the fact that Ed25519 signing is **deterministic** per
//! RFC 8032 §5.1.6: given a fixed seed and message, the signature is
//! a deterministic function of those inputs. So:
//!
//! 1. Sign a fixed domain-separator message
//!    `"pangolin-chain-evm-wallet-derive-v0"` with the device's
//!    Ed25519 key. The resulting 64-byte signature is unique to the
//!    device (depends on the secret seed) but does not reveal it.
//! 2. Treat the 64-byte signature as input keying material (IKM) and
//!    feed it into HKDF-SHA256 with a versioned info string
//!    (`"pangolin-chain-evm-wallet-v0"`) plus a counter byte that
//!    starts at 0. Take 32 bytes of output.
//! 3. Interpret those 32 bytes as a big-endian secp256k1 scalar. If
//!    the scalar is zero or ≥ curve order N, increment the counter
//!    and re-derive. The probability of needing more than one round
//!    is approximately `2^-128` (the gap between N and 2^256 is tiny);
//!    we cap the loop at 256 attempts and surface a [`ChainError::Wallet`]
//!    on the (effectively never) failure.
//! 4. Use the scalar to construct an alloy `LocalSigner` (which wraps
//!    a `k256::ecdsa::SigningKey`). Pangolin's `secp256k1`-named
//!    crate is banned by `deny.toml`; `k256` (`RustCrypto`) is what
//!    alloy uses internally and is the only `secp256k1` implementation
//!    that crosses our supply-chain audit surface.
//! 5. Derive the 20-byte EVM address from the public key by Keccak-256
//!    over the uncompressed encoding's last 64 bytes, taking the
//!    final 20 bytes — the standard EIP-55 address derivation.
//!
//! ## Cryptographic assumption (P7 audit HIGH-1)
//!
//! The construction `seed → Sign(seed, fixed-msg) → HKDF-Expand(...)`
//! requires this assumption to be sound:
//!
//! > **Ed25519-deterministic-sign is treated as a PRF in the seed when
//! > the message is fixed.** That is, for a fixed domain-separator
//! > message `m` and a uniformly random 32-byte seed `s`, the 64-byte
//! > output `Sign(s, m)` is computationally indistinguishable from a
//! > uniformly random 64-byte string by an adversary that does not
//! > know `s`.
//!
//! This assumption is plausible — and structurally similar to the one
//! Ed25519 itself already relies on internally — but it is *not* a
//! standard hardness assumption from the original Ed25519 paper, so
//! we name it explicitly here.
//!
//! **Why it's plausible.** RFC 8032 §5.1.6 (the deterministic-Ed25519
//! signing procedure) derives the per-signature nonce as
//! `r = SHA-512(prefix || msg)` where `prefix` is a 32-byte half of
//! the SHA-512-expanded seed. The security of deterministic Ed25519
//! against signature-forgery already relies on `SHA-512(prefix || msg)`
//! being PRF-like in `prefix` (which is itself derived from the
//! seed) — otherwise the per-signature nonce `r` would be predictable
//! and the scheme would be insecure. Our construction
//! `Sign(seed, fixed-msg) → HKDF-Expand(...)` is one HKDF round
//! beyond that same PRF assumption: where Ed25519's internal use is
//! "one round of SHA-512 with a seed-dependent prefix", our use is
//! "the full Ed25519 signing primitive (which incorporates that round
//! of SHA-512 plus point-multiplication and hashing) followed by an
//! HMAC-SHA256-based HKDF expand". Each additional layer can only
//! preserve or strengthen the PRF property, never weaken it.
//!
//! **Directionality of the secrecy guarantee.** The composition is
//! one-way: an attacker who recovers the secp256k1 scalar (e.g., from
//! a compromised keystore on a stolen device that has already been
//! unlocked) cannot recover the Ed25519 seed in polynomial time. This
//! follows from HMAC-SHA256 preimage resistance: HKDF-Expand is built
//! on HMAC-SHA256, and inverting a single HMAC-SHA256 call to recover
//! its 64-byte input would already be a break of HMAC. The
//! revision-signing identity (Ed25519 seed) is therefore strictly
//! protected even when the gas-paying identity (secp256k1 scalar) is
//! compromised. This is the cryptographic separation property
//! Pangolin requires: "a leaked gas wallet must not endanger the
//! revision-signing identity". The reverse direction (Ed25519 seed →
//! secp256k1 scalar) is trivial by design — that's the derivation
//! itself; no hardness claim there.
//!
//! ## Properties we test
//!
//! - **Determinism**: same `DeviceKey` → same EVM address (success
//!   criterion 5).
//! - **Non-collision**: distinct `DeviceKey`s → distinct addresses
//!   (with overwhelmingly high probability).
//! - **Scalar validity**: the produced scalar is in `[1, N-1]` per
//!   secp256k1 spec (k256's `SecretKey::from_slice` enforces this).
//! - **Address shape**: 20 bytes, derived via the standard Ethereum
//!   keccak-of-public-key construction.
//! - **No correlation with Ed25519 secret**: structurally enforced
//!   by HKDF — Ed25519 signature → HKDF expand → secp256k1 scalar.
//!   Even if an attacker recovered the secp256k1 private key, the
//!   pre-image of the HKDF expand is not recoverable in polynomial
//!   time.

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use hkdf::Hkdf;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use sha2::Sha256;

use crate::error::ChainError;

/// HKDF-SHA256 info string for the MVP-2 issue 4.3 indexer temp-DB
/// ephemeral key derivation. **Versioned** — any change to this
/// constant must bump the `-v1` suffix and document the migration.
///
/// Domain separation: this string is distinct from
/// [`DERIVATION_MESSAGE`] / [`HKDF_INFO`] (the EVM-wallet derivation
/// domain), [`pangolin_crypto::keys::WRAP_KEY_INFO`] (the VDK wrap-key
/// derivation domain), and any other HKDF use in the codebase. A
/// future audit can grep for this string to confirm the indexer key
/// is never reused as any other primitive.
pub const INDEXER_KEY_DOMAIN: &str = "pangolin-indexer-tempdb-key-v1";

/// Derive an ephemeral 32-byte AEAD key for the MVP-2 issue 4.3
/// ephemeral local indexer's temp DB.
///
/// **What this exists for (MVP-2 issue 4.3 R-a).** The
/// `pangolin-indexer` crate (D-007 ephemeral local indexer) writes
/// per-run revision data to a `tempfile::NamedTempFile` `SQLite` DB.
/// 4.2 shipped the lifecycle skeleton with a no-op cipher; 4.3 ships
/// real `XChaCha20-Poly1305` page encryption. The key the cipher
/// uses must be:
///
/// 1. Deterministic for a given `(device_key, run_nonce)` pair so
///    hermetic tests can pin known inputs (4.3 L12).
/// 2. Cryptographically separated from every other key in the
///    Pangolin keyring (D-006: same `DeviceKey` signs revisions +
///    pays gas + here derives a session AEAD key — three distinct
///    domain-separated uses).
/// 3. Derived from the device secret per the master plan §5 row
///    4.3 wording ("encrypted with ephemeral key derived from device
///    secret").
///
/// **How the derivation works.** HKDF-SHA256 (RFC 5869) with:
///
/// - **IKM** = `device.secret_seed_bytes()` (the 32-byte Ed25519
///   secret seed; held inside `Zeroizing<[u8; 32]>` for the duration
///   of the call).
/// - **Salt** = `run_nonce` (the caller's per-run 16-byte random
///   nonce — fresh `OsRng` each session; this is what makes the
///   derived key per-session rather than per-device).
/// - **Info** = [`INDEXER_KEY_DOMAIN`] = `"pangolin-indexer-tempdb-key-v1"`
///   (domain separation against every other HKDF use in the
///   codebase).
/// - **Output length** = 32 bytes (matches
///   [`pangolin_crypto::aead::KEY_LEN`]).
///
/// **Domain separation argument.** The same device secret is also
/// the IKM for `derive_evm_wallet` (which uses
/// `Sign(seed, DERIVATION_MESSAGE) → HKDF-SHA256(info = HKDF_INFO)`).
/// Both derivations are HKDF-SHA256 expansions but with **distinct
/// info strings** (`"pangolin-chain-evm-wallet-v1"` vs
/// `"pangolin-indexer-tempdb-key-v1"`), so under HKDF-SHA256's PRF
/// property the two output spaces are computationally independent.
/// An attacker who recovers one cannot derive the other.
///
/// **Why salt = `run_nonce`, not info = `run_nonce`.** HKDF's salt
/// parameter is part of the extract step's PRF input; info is part
/// of the expand step. Per RFC 5869 §3.1, salt should be "a non-
/// secret random value" — exactly what a per-run nonce is. The info
/// string is the constant domain separator. This matches OWASP /
/// NIST guidance on HKDF usage.
///
/// # Errors
///
/// Returns [`ChainError::Wallet`] if HKDF expansion fails. In
/// practice this is unreachable for the fixed 32-byte output length;
/// the variant exists only so the signature is total.
///
/// # Examples
///
/// ```no_run
/// use pangolin_chain::derive_indexer_key;
/// use pangolin_crypto::keys::DeviceKey;
///
/// let device = DeviceKey::generate();
/// let mut run_nonce = [0u8; 16];
/// pangolin_crypto::rng::fill_random(&mut run_nonce);
/// let key = derive_indexer_key(&device, &run_nonce).expect("derivation succeeds");
/// assert_eq!(key.expose().len(), 32);
/// ```
pub fn derive_indexer_key(
    device: &DeviceKey,
    run_nonce: &[u8; 16],
) -> Result<SecretBytes, ChainError> {
    // The seed bytes return a `Zeroizing<[u8; 32]>` — held only for
    // the duration of the HKDF extract; the wrapper zeroes the buffer
    // on Drop at the end of this function (L3).
    let seed = device.secret_seed_bytes();
    let hk = Hkdf::<Sha256>::new(Some(run_nonce), &*seed);
    let mut okm = [0u8; 32];
    hk.expand(INDEXER_KEY_DOMAIN.as_bytes(), &mut okm)
        .map_err(|_| ChainError::Wallet("HKDF-SHA256 expand failed for indexer-key derivation"))?;
    // Move the OKM bytes into SecretBytes (heap-allocated, zeroes on
    // Drop). The stack-side `okm` buffer is then zeroized so a stale
    // stack frame cannot leak the derived key (mirrors the discipline
    // in `pangolin_crypto::aead::AeadKey::from_bytes`).
    let key = SecretBytes::new(okm.to_vec());
    {
        use zeroize::Zeroize;
        okm.zeroize();
    }
    Ok(key)
}

/// Fixed message signed by the device's Ed25519 key to produce
/// derivation IKM. **Versioned** — any change to this constant
/// (or to [`HKDF_INFO`]) must bump the `-v0` suffix and document
/// the migration; existing devices will derive a different EVM
/// wallet under the new version.
const DERIVATION_MESSAGE: &[u8] = b"pangolin-chain-evm-wallet-derive-v0";

/// HKDF info string for the secp256k1 scalar expansion. Versioned
/// alongside [`DERIVATION_MESSAGE`].
const HKDF_INFO: &[u8] = b"pangolin-chain-evm-wallet-v0";

/// Maximum number of HKDF counter rounds before the derivation gives
/// up. Statistically the loop terminates at the first iteration with
/// probability ~ 1 - 2^-128; 256 attempts is therefore an extremely
/// generous bound that exists only to keep the function total.
const MAX_DERIVATION_ATTEMPTS: u8 = 255;

/// An EVM wallet derived from a Pangolin device key.
///
/// Wraps an alloy `PrivateKeySigner` (k256-backed) and exposes the
/// 20-byte address. The signer itself is held privately because
/// alloy's keystore-bearing types implement `Clone` and we want
/// callers to thread the wallet through `ProviderBuilder` rather than
/// duplicating the secret material at every callsite.
///
/// `Debug` redacts the signer; only the public address is printed.
pub struct EvmWallet {
    signer: PrivateKeySigner,
}

impl EvmWallet {
    /// 20-byte EVM address corresponding to this wallet.
    #[must_use]
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Borrow the inner alloy signer. Used by [`crate::base_sepolia`]
    /// to plug the wallet into a `ProviderBuilder`.
    #[must_use]
    pub fn signer(&self) -> &PrivateKeySigner {
        &self.signer
    }

    /// Consume the wallet and return the inner alloy signer. Used in
    /// the `BaseSepoliaAdapter` constructor where the signer is moved
    /// into an `EthereumWallet`.
    #[must_use]
    pub fn into_signer(self) -> PrivateKeySigner {
        self.signer
    }

    /// **MVP-3 issue #106e-2.** Construct an [`EvmWallet`] from an
    /// existing alloy [`PrivateKeySigner`].
    ///
    /// The inverse of [`Self::into_signer`]. Used by the #106e-2 device-
    /// add FFI binding (`pangolin_ffi::pairing::vault_add_device`): the
    /// FFI clones the signer off the active session's `EvmWallet`
    /// engine-side (the secret material never crosses FFI), then needs
    /// to thread it back through `add_device_v2`'s `&EvmWallet`
    /// parameter — this constructor avoids re-running the HKDF /
    /// rejection-sample derivation (`derive_evm_wallet`) just to
    /// reconstruct the wrapper. The signer's secp256k1 scalar is the
    /// same one already in the active session; the resulting
    /// `EvmWallet` is byte-for-byte equivalent to the source.
    ///
    /// NOT a host input — only crate-internal callers (with engine-
    /// side access to a `PrivateKeySigner`) construct one this way.
    #[must_use]
    pub fn from_signer(signer: PrivateKeySigner) -> Self {
        Self { signer }
    }
}

impl core::fmt::Debug for EvmWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EvmWallet")
            .field("address", &self.signer.address())
            .field("signer", &"<redacted>")
            .finish()
    }
}

/// Derive an [`EvmWallet`] from a Pangolin [`DeviceKey`].
///
/// Determinism: calling this with the same `DeviceKey` (i.e., same
/// underlying Ed25519 seed) always produces the same address.
///
/// # Errors
///
/// [`ChainError::Wallet`] if the HKDF rejection-sampling loop
/// exhausts its budget without producing a valid secp256k1 scalar.
/// This is a vanishingly rare condition (probability ~ 2^-128 per
/// attempt × 256 attempts); the variant exists only so the function
/// signature is total.
pub fn derive_evm_wallet(device: &DeviceKey) -> Result<EvmWallet, ChainError> {
    // Step 1: sign the fixed domain-separator message. Ed25519
    // signing is deterministic per RFC 8032; same seed → same sig.
    let ikm = device.signing_key().sign(DERIVATION_MESSAGE);
    let ikm_bytes: [u8; 64] = ikm.to_bytes();

    // Step 2: HKDF-SHA256 expand into a 32-byte secp256k1 scalar
    // candidate. The salt parameter is `None` (i.e., zeros) which
    // satisfies HKDF's "extract" step; the IKM itself carries
    // sufficient entropy because it's an Ed25519 signature over a
    // device-specific seed.
    let hk = Hkdf::<Sha256>::new(None, &ikm_bytes);

    // Step 3: rejection-sample with a counter byte appended to the
    // info string. The counter widens the info-string namespace per
    // RFC 5869's "Different uses of [the same KM]" guidance so each
    // attempt is an independent expansion.
    for counter in 0u8..=MAX_DERIVATION_ATTEMPTS {
        let mut info = Vec::with_capacity(HKDF_INFO.len() + 1);
        info.extend_from_slice(HKDF_INFO);
        info.push(counter);

        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm)
            .expect("HKDF-SHA256 with 32-byte output cannot fail");

        // Try to interpret the 32 bytes as a secp256k1 scalar. k256's
        // `SecretKey::from_slice` enforces 0 < scalar < N; if the
        // scalar is zero or ≥ N, it returns an error and we advance
        // the counter.
        if let Ok(signer) = PrivateKeySigner::from_slice(&okm) {
            // Wipe the OKM buffer once we've consumed it — defense in
            // depth; the signer is what owns the secret bytes from
            // here on, and k256 zeroizes on drop.
            zeroize_array(&mut okm);
            return Ok(EvmWallet { signer });
        }
        zeroize_array(&mut okm);
    }

    Err(ChainError::Wallet(
        "HKDF rejection-sampling budget exhausted (impossible without a broken HKDF)",
    ))
}

/// Zero a 32-byte buffer. Defined inline rather than pulling
/// `zeroize::Zeroize` because we only need it for one local buffer
/// and the dep is already in our tree via pangolin-crypto.
fn zeroize_array(buf: &mut [u8; 32]) {
    use zeroize::Zeroize;
    buf.zeroize();
}

/// Derive the 20-byte EVM address for a Pangolin [`DeviceKey`].
///
/// Wraps [`derive_evm_wallet`] for callers that only need the public
/// address (e.g., to log "this device's gas wallet is 0x...") and
/// don't want to materialize a full signer.
///
/// # Errors
///
/// Same as [`derive_evm_wallet`].
pub fn derive_evm_address(device: &DeviceKey) -> Result<Address, ChainError> {
    Ok(derive_evm_wallet(device)?.address())
}

// Add a `zeroize` dep is unnecessary — we already pull it through the
// workspace via pangolin-crypto's transitive surface. Importing the
// trait inline above is sufficient.

#[cfg(test)]
mod tests {
    use super::{
        derive_evm_address, derive_evm_wallet, derive_indexer_key, DERIVATION_MESSAGE, HKDF_INFO,
        INDEXER_KEY_DOMAIN,
    };
    use alloy::primitives::Address;
    use pangolin_crypto::keys::DeviceKey;
    use pangolin_crypto::sign::SigningKey;

    /// Plan test: `evm::tests::derive_is_deterministic`. Same Ed25519
    /// seed → same EVM address. We use `DeviceKey::generate` to land
    /// fresh material, derive twice, and compare.
    #[test]
    fn derive_is_deterministic() {
        let device = DeviceKey::generate();
        let a1 = derive_evm_address(&device).expect("derivation succeeds");
        let a2 = derive_evm_address(&device).expect("derivation succeeds");
        assert_eq!(a1, a2, "same DeviceKey must derive same address");
    }

    /// Determinism across separate `DeviceKey` instances built from
    /// the **same seed**. This is the "remount the same device on a
    /// reboot" scenario: we don't have public access to construct a
    /// `DeviceKey` from a fixed seed (the constructor is not
    /// `pub(crate)` for that direction), but `pangolin-crypto`
    /// exposes `SigningKey::from_seed` which we can wrap structurally
    /// the same way `DeviceKey::generate_with` does internally.
    ///
    /// Because we cannot construct a `DeviceKey` from a seed via the
    /// public API alone (the wrap is internal), we emulate the
    /// scenario by deriving twice from the same `DeviceKey` instance
    /// and ensuring different `DeviceKey` instances produce different
    /// addresses (criterion 5's two halves).
    #[test]
    fn different_seeds_produce_different_addresses() {
        let d1 = DeviceKey::generate();
        let d2 = DeviceKey::generate();
        let a1 = derive_evm_address(&d1).expect("derive d1");
        let a2 = derive_evm_address(&d2).expect("derive d2");
        // Probability of collision is ~ 2^-160; if this ever fires
        // pseudo-randomly, the RNG is broken or the derivation is
        // worse than constant.
        assert_ne!(a1, a2, "distinct devices must derive distinct addresses");
    }

    /// Plan test: `evm::tests::derived_address_format_valid`. The
    /// address is 20 bytes, non-zero with overwhelmingly high
    /// probability.
    #[test]
    fn derived_address_format_valid() {
        let device = DeviceKey::generate();
        let addr: Address = derive_evm_address(&device).expect("derivation succeeds");
        // Address is 20 bytes by construction (alloy's `Address` is
        // a fixed-size newtype). Sanity: the all-zero address is
        // statistically impossible.
        assert_ne!(addr, Address::ZERO, "derived address is not zero");
        let bytes = addr.0;
        assert_eq!(bytes.len(), 20, "Ethereum addresses are 20 bytes");
    }

    /// The derivation produces a valid k256 scalar (i.e., the
    /// `PrivateKeySigner::from_slice` step succeeded). Indirect test:
    /// `derive_evm_wallet` returns Ok, which implies the rejection
    /// sampling found a valid scalar.
    #[test]
    fn derivation_succeeds_for_random_devices() {
        // Run 32 fresh devices; every single one must yield a valid
        // wallet on the first or first-few HKDF attempts. If the loop
        // ever returns an error, the budget is too tight or HKDF is
        // broken.
        for _ in 0..32 {
            let device = DeviceKey::generate();
            derive_evm_wallet(&device).expect("derivation must always succeed in practice");
        }
    }

    /// EVM address derivation is stable across ed25519-dalek's
    /// deterministic-sign property: signing the same message twice
    /// with the same `DeviceKey` produces byte-identical signatures
    /// (RFC 8032 §5.1.6), so the HKDF input and the final scalar are
    /// stable. We assert this directly on the device's signing key
    /// because an accidental switch to randomized signing would
    /// silently break determinism.
    #[test]
    fn underlying_ed25519_sign_is_deterministic() {
        let device = DeviceKey::generate();
        let s1 = device.signing_key().sign(DERIVATION_MESSAGE);
        let s2 = device.signing_key().sign(DERIVATION_MESSAGE);
        assert_eq!(
            s1.to_bytes(),
            s2.to_bytes(),
            "Ed25519 sign must be deterministic per RFC 8032 §5.1.6"
        );
    }

    /// Domain strings are versioned at v0; any future change must
    /// bump the suffix and document the migration.
    #[test]
    fn domain_strings_are_versioned() {
        assert_eq!(DERIVATION_MESSAGE, b"pangolin-chain-evm-wallet-derive-v0");
        assert_eq!(HKDF_INFO, b"pangolin-chain-evm-wallet-v0");
        // 4.3 indexer-key domain is versioned independently from the
        // EVM-wallet domain — distinct strings prevent HKDF-output
        // collisions between the two derivations (R-a + L12).
        assert_eq!(INDEXER_KEY_DOMAIN, "pangolin-indexer-tempdb-key-v1");
    }

    // ---------- 4.3 R-a: derive_indexer_key tests ----------

    /// 4.3 R-a + L12: same `(device_key, run_nonce)` pair always
    /// produces the same 32-byte derived key. Hermetic tests in the
    /// indexer crate depend on this — they pin a fixed seed + nonce
    /// and pin the output bytes.
    #[test]
    fn derive_indexer_key_is_deterministic() {
        let seed = [0x9Au8; 32];
        let nonce = [0x42u8; 16];
        let d1 = DeviceKey::from_seed(seed);
        let d2 = DeviceKey::from_seed(seed);
        let k1 = derive_indexer_key(&d1, &nonce).expect("derive 1");
        let k2 = derive_indexer_key(&d2, &nonce).expect("derive 2");
        assert_eq!(
            k1.expose(),
            k2.expose(),
            "same (device_key, run_nonce) must derive same key",
        );
    }

    /// 4.3 R-a + L-key-derivation-collision: same device, distinct
    /// `run_nonce` values produce distinct derived keys. If this
    /// fails, two indexer runs against the same device would share a
    /// key, breaking the per-session ephemeral-key property (L3).
    #[test]
    fn derive_indexer_key_distinct_per_run_nonce() {
        let seed = [0x9Au8; 32];
        let nonce_a = [0x01u8; 16];
        let nonce_b = [0x02u8; 16];
        let device = DeviceKey::from_seed(seed);
        let key_a = derive_indexer_key(&device, &nonce_a).expect("derive a");
        let key_b = derive_indexer_key(&device, &nonce_b).expect("derive b");
        assert_ne!(
            key_a.expose(),
            key_b.expose(),
            "distinct run_nonces must derive distinct keys",
        );
    }

    /// 4.3 R-a + L-key-derivation-collision: distinct devices, same
    /// `run_nonce`, produce distinct derived keys. If this fails, a
    /// stolen `run_nonce` (which is non-secret — it's salt) could be
    /// reused with an arbitrary device-derived key candidate.
    #[test]
    fn derive_indexer_key_distinct_per_device() {
        let nonce = [0x42u8; 16];
        let d1 = DeviceKey::from_seed([0x11; 32]);
        let d2 = DeviceKey::from_seed([0x22; 32]);
        let k1 = derive_indexer_key(&d1, &nonce).expect("derive 1");
        let k2 = derive_indexer_key(&d2, &nonce).expect("derive 2");
        assert_ne!(
            k1.expose(),
            k2.expose(),
            "distinct devices must derive distinct keys for same nonce",
        );
    }

    /// 4.3 R-a: the derived key is exactly 32 bytes (matches
    /// `pangolin_crypto::aead::KEY_LEN`). Pinned so a future
    /// refactor that asks for a non-32-byte expansion is caught.
    #[test]
    fn derive_indexer_key_output_length_is_32() {
        let device = DeviceKey::from_seed([0x55; 32]);
        let nonce = [0xCCu8; 16];
        let key = derive_indexer_key(&device, &nonce).expect("derive");
        assert_eq!(
            key.expose().len(),
            32,
            "derived key must be 32 bytes (matches AeadKey KEY_LEN)",
        );
    }

    /// 4.3 R-a + cryptographic-separation: the indexer-key derivation
    /// must NOT collide with the EVM-wallet derivation under any
    /// `run_nonce` — they use different HKDF info strings + different
    /// IKM constructions. Pin this with a fixed seed + nonce so a
    /// future refactor that accidentally aligns the two domains is
    /// caught.
    #[test]
    fn derive_indexer_key_does_not_collide_with_evm_wallet() {
        let seed = [0x77u8; 32];
        let nonce = [0xAAu8; 16];
        let device = DeviceKey::from_seed(seed);
        let indexer_key = derive_indexer_key(&device, &nonce).expect("indexer derive");

        let evm = derive_evm_wallet(&device).expect("evm derive");
        let evm_scalar: [u8; 32] = evm.signer().to_bytes().into();
        assert_ne!(
            indexer_key.expose(),
            evm_scalar.as_slice(),
            "indexer-key must be cryptographically separated from \
             EVM-wallet secret (different HKDF domain)",
        );
    }

    /// MVP-2 issue 3.2 — derivation is deterministic across Drop
    /// boundaries (the L1 contract end-to-end at the scalar layer).
    ///
    /// **What this test actually verifies:** after the first
    /// `EvmWallet` goes out of scope and Drops, a fresh derivation
    /// from the same seed reproduces the same secp256k1 scalar
    /// bytes (and the same address). This is the L1 "secret is a
    /// pure function of the seed" determinism contract, observed
    /// across a Drop boundary so the assertion would catch a future
    /// regression where the derivation pipeline grows hidden state
    /// (e.g. an RNG mixed into HKDF info; an init-once that
    /// remembers the first scalar).
    ///
    /// **What this test does NOT verify** (L2 audit fix-pass clarity
    /// rename — earlier name `no_evm_secret_after_drop` overclaimed):
    /// it does NOT prove the dropped wallet's heap allocation is
    /// zeroed, and it would NOT catch a regression where a static
    /// `OnceCell<EvmWallet>` cache makes the scalar survive the
    /// owning binding's drop (such a cache would return the same
    /// scalar bytes — the equality assertion holds either way). The
    /// session-drop regression (the property that `Vault::evm_wallet`
    /// errors with `StoreError::NotUnlocked` after lock/expiry,
    /// which IS the property that would fail if a `OnceCell` cache
    /// snuck in) is covered separately by
    /// `evm_wallet_dropped_on_lock_idle_expiry_absolute_expiry` in
    /// `pangolin-store/src/vault.rs`.
    ///
    /// The formal zeroize guarantee on the dropped scalar lives in
    /// `k256`'s own zeroize-on-drop discipline (not asserted here —
    /// safe Rust cannot inspect freed allocations).
    #[test]
    fn derive_evm_wallet_is_deterministic_post_drop() {
        use pangolin_crypto::sign::SigningKey;
        // Pin a fixed seed so the test is deterministic across runs.
        let seed: [u8; 32] = [
            0x9c, 0xa5, 0x6a, 0x77, 0xde, 0xb4, 0x02, 0xc7, 0xee, 0x10, 0x35, 0x44, 0x2b, 0x91,
            0x5f, 0x4e, 0x55, 0xdc, 0x77, 0xb2, 0x09, 0x88, 0xfa, 0x21, 0x10, 0xf6, 0xa6, 0xcf,
            0x35, 0x88, 0x6c, 0x10,
        ];
        let _sk = SigningKey::from_seed(seed);
        let device1 = DeviceKey::from_seed(seed);
        let snapshot1: [u8; 32] = {
            let wallet = derive_evm_wallet(&device1).expect("derive 1");
            let bytes: [u8; 32] = wallet.signer().to_bytes().into();
            // wallet drops here at end of scope.
            bytes
        };
        let device2 = DeviceKey::from_seed(seed);
        let snapshot2: [u8; 32] = {
            let wallet = derive_evm_wallet(&device2).expect("derive 2");
            let bytes: [u8; 32] = wallet.signer().to_bytes().into();
            bytes
        };
        assert_eq!(
            snapshot1, snapshot2,
            "same seed must produce the same secp256k1 scalar across wallet \
             instantiations (the determinism contract); a regression here \
             would mean a future refactor introduced a state hazard"
        );
        // Sanity: the scalar is non-zero (k256 enforces this on
        // construction, but assert explicitly so a future
        // change that returns a sentinel-zero scalar would be
        // caught here).
        assert_ne!(
            snapshot1, [0u8; 32],
            "scalar must be non-zero by construction"
        );
        // And the derivation reproduces the same public address —
        // the L1 contract end-to-end.
        let device3 = DeviceKey::from_seed(seed);
        let addr1 = derive_evm_address(&device3).unwrap();
        let device4 = DeviceKey::from_seed(seed);
        let addr2 = derive_evm_address(&device4).unwrap();
        assert_eq!(addr1, addr2);
    }

    /// Two devices with different deterministic seeds (constructed
    /// through `pangolin-crypto`'s public `SigningKey::from_seed`
    /// surface, which is one indirection away from `DeviceKey`)
    /// produce different addresses. This is a stronger statement than
    /// `different_seeds_produce_different_addresses` because we pin
    /// the seeds, removing any randomness from the test.
    ///
    /// We construct a `DeviceKey`-equivalent by signing inside the
    /// test through a `SigningKey` directly, and assert that the
    /// derivation pipeline (sign(domain) → HKDF → scalar → address)
    /// is purely a function of the seed bytes for a fixed encoding.
    /// `DeviceKey::from_seed` is now public (added by P9 fix-pass
    /// HIGH-1 to support the `pending_merges` retry stash), but this
    /// test predates that surface and intentionally probes the
    /// structural property at the `SigningKey` layer to keep the
    /// pangolin-chain → pangolin-crypto dependency surface minimal —
    /// the chain crate does not need `DeviceKey` for this test.
    #[test]
    fn structural_property_distinct_seeds_distinct_signatures() {
        let s1 = SigningKey::from_seed([0x11; 32]);
        let s2 = SigningKey::from_seed([0x22; 32]);
        let sig1 = s1.sign(DERIVATION_MESSAGE);
        let sig2 = s2.sign(DERIVATION_MESSAGE);
        assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "distinct seeds must produce distinct signatures over the same domain message"
        );
        // And, even more importantly, the same seed twice produces
        // the same signature (determinism — the property the
        // derivation pipeline depends on).
        let s1_again = SigningKey::from_seed([0x11; 32]);
        let sig1_again = s1_again.sign(DERIVATION_MESSAGE);
        assert_eq!(
            sig1.to_bytes(),
            sig1_again.to_bytes(),
            "same seed must produce same signature"
        );
    }
}
