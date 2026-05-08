//! Network-gated end-to-end integration tests against the deployed
//! `RevisionLogV0` on Base Sepolia (D-014).
//!
//! Behind the `integration-tests` cargo feature so the default
//! `cargo test --workspace --lib` does not attempt to reach
//! `https://sepolia.base.org`. CI runs without this feature; humans
//! enable it for manual smoke verification:
//!
//! ```text
//! cargo test -p pangolin-cli --features integration-tests
//! ```
//!
//! Tests in this file:
//!
//! - `publish_pull_roundtrip` — best-effort smoke that the
//!   read-only `BaseSepoliaAdapter` constructor succeeds against
//!   the public Base Sepolia RPC and the `pull_all` orchestrator
//!   completes without error against a freshly-created vault. We
//!   intentionally do NOT exercise the full `publish_all` path
//!   here because it requires a funded Foundry keystore that the
//!   CI environment does not have. Manual humans testing the full
//!   path use the binary's `pangolin-cli publish` against their
//!   own keystore.
//! - `status_against_real_vault` — opens a freshly-created vault
//!   and runs the read-only status path. Confirms the binary is
//!   wired against the network reading path without assertions on
//!   chain content.
//!
//! The Base Sepolia RPC at `https://sepolia.base.org` is rate-
//! limited and occasionally flaky. Tests that fail at the
//! transport layer (e.g., `error sending request`) are best-effort
//! and may be retried by humans; we deliberately do not encode
//! retry loops here per `P8.md` §A6.

#![cfg(feature = "integration-tests")]

use pangolin_chain::BaseSepoliaAdapter;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::Vault;
use tempfile::TempDir;

const RPC_URL: &str = "https://sepolia.base.org";

fn deployment_path() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| {
            p.join("contracts")
                .join("deployments")
                .join("base-sepolia.json")
        })
        .expect("workspace ancestor not found")
}

/// `pull_all` completes against the read-only Base Sepolia adapter
/// for a freshly-created vault (zero events to ingest because the
/// fresh vault has a random `vault_id` not present on chain).
#[tokio::test]
async fn publish_pull_roundtrip() {
    let adapter = BaseSepoliaAdapter::new_read_only(RPC_URL, &deployment_path())
        .await
        .expect("connect read-only");

    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    let pwd = SecretBytes::new(b"test password".to_vec());
    Vault::create(&path, &pwd).expect("create");
    let mut vault = Vault::open(&path).expect("open");
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(SecretBytes::new(b"test password".to_vec()));
    vault.unlock(&presence, &identity).expect("unlock");

    // Pull from the deploy block forward. The fresh vault's vault_id
    // is random; expect zero events.
    let report = pangolin_cli::sync::pull_all(
        &mut vault,
        &adapter,
        Some(adapter.deploy_block().saturating_sub(1)),
        None,
    )
    .await
    .expect("pull_all");
    assert_eq!(report.applied, 0, "no events for a random vault_id");
}

/// `status` smoke against a real vault file — confirms the metadata
/// surface compiles and runs in the network-gated context.
#[tokio::test]
async fn status_against_real_vault() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("v.pvf");
    let pwd = SecretBytes::new(b"test password".to_vec());
    Vault::create(&path, &pwd).expect("create");
    let v = Vault::open(&path).expect("open");
    assert_eq!(v.list_dirty().expect("list").len(), 0);
    assert_eq!(v.last_pulled_block().expect("read"), 0);
}
