// SPDX-License-Identifier: AGPL-3.0-or-later
//! Funder signing abstraction (R-f).
//!
//! Per R-f verbatim: the funder holds a single secp256k1 wallet that
//! (a) signs `Redemption` attestations for the `EntitlementRegistry`,
//! and (b) pays gas + signs the `redeem(...)` + ETH-transfer EIP-1559
//! envelopes. The trait below abstracts over the eventual HSM impl
//! (deferred to mainnet); for testnet we ship [`FileKeystoreSigner`].
//!
//! ## Why a trait?
//!
//! The wallet might live in three places over the project lifetime:
//! a Foundry keystore on disk (today); a cloud KMS / HSM (mainnet);
//! a hardware device (post-MVP-2). The trait keeps the call sites in
//! the HTTP handler agnostic to the storage. `Send + Sync` so axum's
//! `State<AppState>` can clone an `Arc<dyn FunderSigner>` into each
//! handler invocation.
//!
//! ## Test impl
//!
//! `MockSigner` (gated `#[cfg(test)]`) lets hermetic tests assert the
//! happy-path flow without an actual keystore on disk. The mock takes
//! a `PrivateKeySigner` constructed from a deterministic seed.

use core::fmt;
use std::fs;
use std::path::Path;

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;

use pangolin_chain::{
    build_signed_redemption_v1, ChainEnv, RedemptionFieldsV1, SignedRedemptionV1,
};

use crate::error::FunderError;

/// Funder signing surface. `async fn` so HSM impls can be RPC-backed
/// without changing call sites.
#[async_trait]
pub trait FunderSigner: Send + Sync + fmt::Debug {
    /// Sign a Redemption attestation against the `EntitlementRegistry`
    /// at `chain_env`. Returns the typed [`SignedRedemptionV1`].
    async fn sign_redemption(
        &self,
        fields: RedemptionFieldsV1,
        chain_env: ChainEnv,
    ) -> Result<SignedRedemptionV1, FunderError>;

    /// The signer's EVM address. Read at startup + logged at INFO
    /// (the address is non-secret per D-006 + L12).
    fn address(&self) -> Address;

    /// Borrow the underlying `PrivateKeySigner`, if this impl is
    /// file-backed.
    ///
    /// **Design note (audit LOW#2, acknowledged-deferred 2026-05-15):**
    /// the `local_signer` accessor is **file-backed-only by design**.
    /// The chain-submit helpers (`submit_redemption_v1`,
    /// `submit_eth_transfer_v1`) take a `&PrivateKeySigner` because
    /// alloy 2.x's `ProviderBuilder::wallet` expects that concrete
    /// type. A future HSM impl returns `None` from this method and
    /// takes a **different code path** — a `SignerSync`-implementing
    /// RPC adapter rather than a literal scalar in process memory.
    /// The handler's `FunderError::Configuration("local_signer
    /// unavailable...")` branch is the surface that triggers when
    /// an HSM signer is wired in but the HSM-RPC adapter path is not
    /// yet shipped (deferred to mainnet per the plan-gate). Per the
    /// audit: this is an acknowledged future-work surface, not a
    /// 3.4 bug.
    fn local_signer(&self) -> Option<&PrivateKeySigner>;
}

/// Foundry-keystore-backed signer. The keystore is decrypted at
/// startup (passphrase via stdin TTY or sealed env var) into an alloy
/// [`PrivateKeySigner`]; from there it stays in memory for the
/// process lifetime.
///
/// `Debug` redacts the inner signer; only the public address prints.
pub struct FileKeystoreSigner {
    inner: PrivateKeySigner,
}

impl fmt::Debug for FileKeystoreSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKeystoreSigner")
            .field("address", &self.inner.address())
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl FileKeystoreSigner {
    /// Load a keystore from `path`, decrypting with `passphrase`.
    ///
    /// The keystore is the Web3 Secret Storage v3 format (Foundry's
    /// default, the same format `pangolin-dev` lives in). Alloy's
    /// `LocalSigner::decrypt_keystore` handles the scrypt + AES-CTR
    /// path.
    pub fn from_keystore(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, FunderError> {
        let signer = PrivateKeySigner::decrypt_keystore(path.as_ref(), passphrase)
            .map_err(|e| FunderError::Keystore(e.to_string()))?;
        Ok(Self { inner: signer })
    }

    /// Construct a signer directly from a private-key scalar (dev
    /// shortcut). Reads a hex-encoded 32-byte key from a file path or
    /// raw env-var value. Used in dev / CI; production paths go
    /// through [`Self::from_keystore`].
    pub fn from_private_key_hex(hex: &str) -> Result<Self, FunderError> {
        let trimmed = hex.trim().trim_start_matches("0x");
        let signer = trimmed
            .parse::<PrivateKeySigner>()
            .map_err(|e| FunderError::Keystore(format!("parse private key: {e}")))?;
        Ok(Self { inner: signer })
    }

    /// Read a passphrase from a file path. Returns the trimmed
    /// content. Used when the funder is launched with
    /// `FUNDER_KEYSTORE_PASSPHRASE_FILE` rather than stdin.
    pub fn read_passphrase_from_file(path: impl AsRef<Path>) -> Result<String, FunderError> {
        let raw = fs::read_to_string(path.as_ref())
            .map_err(|e| FunderError::Keystore(format!("read passphrase: {e}")))?;
        Ok(raw.trim().to_owned())
    }
}

#[async_trait]
impl FunderSigner for FileKeystoreSigner {
    async fn sign_redemption(
        &self,
        fields: RedemptionFieldsV1,
        chain_env: ChainEnv,
    ) -> Result<SignedRedemptionV1, FunderError> {
        // Delegate to pangolin-chain's EIP-712 builder. The
        // signer + fields are passed through; the deployment cross-
        // check + struct-hash + canonical-s discipline all live in
        // the chain crate.
        build_signed_redemption_v1(&self.inner, fields, chain_env).map_err(FunderError::from)
    }

    fn address(&self) -> Address {
        self.inner.address()
    }

    fn local_signer(&self) -> Option<&PrivateKeySigner> {
        Some(&self.inner)
    }
}

/// Test-only mock signer. Constructed from a deterministic seed scalar
/// so hermetic tests produce byte-stable outputs.
#[cfg(any(test, feature = "test-utilities"))]
#[derive(Debug, Clone)]
pub struct MockSigner {
    inner: PrivateKeySigner,
}

#[cfg(any(test, feature = "test-utilities"))]
impl MockSigner {
    /// Construct from a fixed 32-byte hex scalar (no `0x` prefix
    /// allowed too).
    pub fn from_hex(hex: &str) -> Result<Self, FunderError> {
        let trimmed = hex.trim().trim_start_matches("0x");
        let inner = trimmed
            .parse::<PrivateKeySigner>()
            .map_err(|e| FunderError::Keystore(format!("mock signer parse: {e}")))?;
        Ok(Self { inner })
    }

    /// Default deterministic mock signer (scalar 0x42…42). Same
    /// scalar `pangolin-funder-client::tests` use for cross-crate
    /// recognisability.
    #[must_use]
    pub fn default_for_tests() -> Self {
        let hex = "0x4242424242424242424242424242424242424242424242424242424242424242";
        Self {
            inner: hex.parse::<PrivateKeySigner>().expect("static parse"),
        }
    }
}

#[cfg(any(test, feature = "test-utilities"))]
#[async_trait]
impl FunderSigner for MockSigner {
    async fn sign_redemption(
        &self,
        fields: RedemptionFieldsV1,
        chain_env: ChainEnv,
    ) -> Result<SignedRedemptionV1, FunderError> {
        build_signed_redemption_v1(&self.inner, fields, chain_env).map_err(FunderError::from)
    }

    fn address(&self) -> Address {
        self.inner.address()
    }

    fn local_signer(&self) -> Option<&PrivateKeySigner> {
        Some(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    #[tokio::test]
    async fn mock_signer_signs_redemption() {
        let signer = MockSigner::default_for_tests();
        let fields = RedemptionFieldsV1 {
            user_id: [0xAAu8; 32],
            amount: U256::from(50u64),
            nonce: 0,
            schema_version: 1,
            expires_at: 2_000_000_000,
        };
        let signed = signer
            .sign_redemption(fields, ChainEnv::BaseSepolia)
            .await
            .expect("sign");
        assert_eq!(signed.signature.len(), 65);
        // Address must be the same as the inner signer.
        let expected_address = signer.address();
        // We don't expose the inner address publicly, but a fresh
        // MockSigner constructed from the same scalar must yield the
        // same address.
        let other = MockSigner::default_for_tests();
        assert_eq!(other.address(), expected_address);
    }

    #[test]
    fn file_keystore_signer_parses_hex_key() {
        let signer = FileKeystoreSigner::from_private_key_hex(
            "0x4242424242424242424242424242424242424242424242424242424242424242",
        )
        .expect("parse");
        // Sanity: address is deterministic.
        let mock = MockSigner::default_for_tests();
        assert_eq!(signer.address(), mock.address());
    }
}
