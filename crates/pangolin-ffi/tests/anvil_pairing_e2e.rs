// SPDX-License-Identifier: AGPL-3.0-or-later
//! #106e-2 LOW-2 restoration — the FFI-layer COUPLED anvil pairing E2E.
//!
//! Drives the FULL pairing handshake THROUGH the `pangolin-ffi` surface
//! against a live `RevisionLogV2` deployment:
//!
//! ```text
//! 1. vault_create + vault_open + vault_unlock A (the manager)
//!    + anvil_setBalance(A's signer) so A pays gas
//! 2. vault_create + vault_open + vault_unlock B (the new device)
//! 3. B = pairing_begin_new_device       (FfiPairingPayload + fresh nonce)
//! 4. A = pairing_local_payload(B.nonce) (mirror payload bound to B's nonce)
//! 5. pairing_derive_sas on both sides   (assert canonical-symmetric, L3)
//! 6. A = vault_add_device(B_payload, config)
//!        — real on-chain addDevice tx + real seal_vdk_to_new_device
//! 7. B = pairing_open_and_join(envelope, A.vault_id, epoch, b_new_pw)
//!        — real open_vdk + install_paired_vdk (atomic re-key + adopt vault_id)
//! 8. B re-unlocks with the NEW master password
//!        — proves the VDK was recovered via the pairing flow end-to-end
//! ```
//!
//! Unlike the hermetic FFI pairing tests in `src/pairing.rs`, this is the
//! ONE place that drives the FFI bindings against a LIVE chain (the
//! real EIP-712-byte-identical `AddDevice` tx + the live receipt). A
//! broken FFI plumbing of the chain side (signer wallet, EIP-712 digest,
//! `read_device_nonce_v2`, seal AAD) turns this RED.
//!
//! Gated on `integration-tests` + `#[ignore]`; run by `scripts/anvil-ci.sh`
//! in dev mode against a fresh local anvil node.

#![cfg(feature = "integration-tests")]
#![allow(
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph,
    clippy::doc_lazy_continuation,
    clippy::missing_panics_doc,
    clippy::similar_names
)]

use std::sync::Arc;

use pangolin_chain::test_env;
use pangolin_ffi::chain_config::FfiChainConfig;
use pangolin_ffi::device::vault_evm_wallet_address;
use pangolin_ffi::pairing::{
    pairing_begin_new_device, pairing_derive_sas, pairing_local_payload, pairing_open_and_join,
    vault_add_device, vault_bootstrap_chain,
};
use pangolin_ffi::session::{
    vault_create, vault_open, vault_unlock, PresenceProof, SecretPassword,
};

/// The PresenceProof FFI Record carries opaque bytes; CLI tier ignores the
/// bytes (`PressYPresenceProof::confirmed()` lands engine-side regardless).
fn presence() -> PresenceProof {
    PresenceProof {
        schema_version: 1,
        bytes: vec![],
    }
}

/// Fund a wallet on the local anvil chain via `cast rpc anvil_setBalance`
/// (the harness guarantees `cast` is on PATH in dev mode). Needed because
/// `vault_create` generates a RANDOM DeviceKey → the vault's secp256k1
/// signer is NOT the harness-funded `[0x42;32]` wallet. Fail-closed: a
/// non-success exit is a hard test failure.
fn anvil_fund(rpc_url: &str, addr_hex: &str) {
    let out = std::process::Command::new("cast")
        .args([
            "rpc",
            "anvil_setBalance",
            addr_hex,
            // 1 ETH = 0xDE0B6B3A7640000 wei.
            "0xDE0B6B3A7640000",
            "--rpc-url",
            rpc_url,
        ])
        .output()
        .expect("invoke cast rpc anvil_setBalance");
    assert!(
        out.status.success(),
        "anvil_setBalance failed for {addr_hex}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Absolute path to `contracts/deployments/dev.json` — the harness generates
/// it at setup and `BaseSepoliaAdapter::new_with_signer` (consumed inside
/// `vault_add_device`) loads it to resolve `RevisionLogV2`'s address.
/// `CARGO_MANIFEST_DIR` points at `crates/pangolin-ffi` at test time;
/// from there `../../contracts/deployments/dev.json` reaches the workspace.
fn deployment_path() -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest)
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .join("contracts")
        .join("deployments")
        .join("dev.json");
    path.to_string_lossy().into_owned()
}

/// **The FFI-layer pairing E2E centerpiece.** Drives the full add-device
/// handshake through the FFI surface against a live anvil deployment +
/// asserts the new device can re-unlock with its newly-chosen master
/// password (the strongest end-to-end proof: the recovered VDK was
/// correctly opened, installed, and rewrapped under the new authority).
#[test]
#[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
#[allow(clippy::too_many_lines, clippy::redundant_clone)]
fn pairing_e2e_through_ffi_against_anvil() {
    if !test_env::is_dev_mode() && !test_env::require_or_fail("FFI pairing E2E needs dev anvil") {
        return;
    }
    let rpc_url = test_env::rpc_url();
    let config = FfiChainConfig {
        schema_version: 1,
        rpc_url: rpc_url.clone(),
        deployment_path: deployment_path(),
        prefer_websocket: false,
    };

    // ---- A: the manager device ----
    let a_dir = tempfile::TempDir::new().expect("tempdir A");
    let a_path = a_dir.path().join("a.pvf").to_string_lossy().into_owned();
    let a_pw = SecretPassword::new(b"a master password".to_vec());

    vault_create(a_path.clone(), Arc::clone(&a_pw)).expect("vault_create A");
    let a_handle = vault_open(a_path.clone()).expect("vault_open A");
    vault_unlock(Arc::clone(&a_handle), Arc::clone(&a_pw), presence()).expect("vault_unlock A");

    // Fund A's freshly-generated signer (`vault_create` generates a random
    // DeviceKey; the harness-funded `[0x42;32]` wallet is unused here).
    let a_signer_hex =
        vault_evm_wallet_address(Arc::clone(&a_handle)).expect("read A signer address");
    anvil_fund(&rpc_url, &a_signer_hex);

    // Bootstrap A on-chain — the V2 contract REQUIRES this before any
    // `addDevice` / publishRevision (RevisionLogV2.sol Q-f: "publish
    // cannot race an unestablished SET"). Without this `vault_add_device`
    // below reverts with `VaultNotBootstrapped`.
    vault_bootstrap_chain(Arc::clone(&a_handle), Arc::clone(&a_pw), config.clone())
        .expect("A vault_bootstrap_chain (genesis SET on-chain)");

    // ---- B: the new device ----
    let b_dir = tempfile::TempDir::new().expect("tempdir B");
    let b_path = b_dir.path().join("b.pvf").to_string_lossy().into_owned();
    let b_initial_pw = SecretPassword::new(b"b initial password".to_vec());

    vault_create(b_path.clone(), Arc::clone(&b_initial_pw)).expect("vault_create B");
    let b_handle = vault_open(b_path.clone()).expect("vault_open B");
    vault_unlock(Arc::clone(&b_handle), Arc::clone(&b_initial_pw), presence())
        .expect("vault_unlock B");

    // ---- Pairing handshake through the FFI ----
    // B builds its pairing payload (fresh freshness nonce).
    let b_payload =
        pairing_begin_new_device(Arc::clone(&b_handle)).expect("B pairing_begin_new_device");
    assert_eq!(
        b_payload.bytes.len(),
        pangolin_core::pairing_transport::PAYLOAD_LEN,
        "B's payload byte-form is the pinned PAYLOAD_LEN"
    );

    // A builds its mirror payload, bound to B's freshness nonce — so the
    // SAS over (A.pub, B.pub, nonce) comes out identical on both screens.
    let a_payload = pairing_local_payload(Arc::clone(&a_handle), b_payload.freshness_nonce.clone())
        .expect("A pairing_local_payload");
    assert_eq!(
        a_payload.freshness_nonce, b_payload.freshness_nonce,
        "the nonce travels into A's mirror payload (so SAS matches)"
    );

    // Both sides derive the SAS; canonical-symmetric (L3) — must match.
    let sas_from_a =
        pairing_derive_sas(a_payload.clone(), b_payload.clone()).expect("A derive_sas");
    let sas_from_b =
        pairing_derive_sas(b_payload.clone(), a_payload.clone()).expect("B derive_sas");
    assert_eq!(
        sas_from_a, sas_from_b,
        "SAS must be canonical-symmetric regardless of role (L3)"
    );
    assert_eq!(sas_from_a.len(), 6, "SAS is a 6-digit decimal code");
    assert!(
        sas_from_a.chars().all(|c| c.is_ascii_digit()),
        "SAS must be pure ASCII digits: {sas_from_a:?}"
    );
    // (In real UX the humans compare the codes here; in the test we trust
    // the cryptographic match + proceed.)

    // A authorizes B on-chain (real `addDevice` tx — broken EIP-712 or
    // stale `deviceNonce` reverts here) + seals the VDK to B's pubkey.
    let envelope = vault_add_device(
        Arc::clone(&a_handle),
        Arc::clone(&a_pw),
        config.clone(),
        b_payload.clone(),
    )
    .expect("A vault_add_device (real on-chain addDevice + seal)");
    assert!(
        !envelope.bytes.is_empty(),
        "the sealed VDK envelope must be non-empty"
    );

    // B opens the seal + installs A's VDK under its new master password +
    // ATOMICALLY adopts A's vault_id (the install_paired_vdk single-tx
    // re-key, regression-tested by the LOW-1 fault-injection test).
    let b_new_pw = SecretPassword::new(b"b post-pair master password".to_vec());
    pairing_open_and_join(
        Arc::clone(&b_handle),
        envelope.bytes.clone(),
        a_payload.vault_id.clone(),
        0,
        Arc::clone(&b_new_pw),
    )
    .expect("B pairing_open_and_join (real open + install)");

    // ---- The load-bearing assertion ----
    // B can re-unlock with the NEW master password → proves the VDK was
    // correctly recovered from A's seal + installed under the new wrap
    // authority + the vault_id adoption landed atomically (otherwise the
    // device_key row would have been mis-sealed and unlock would fail).
    drop(b_handle);
    let b_reopen = vault_open(b_path).expect("re-open B post-pair");
    vault_unlock(Arc::clone(&b_reopen), Arc::clone(&b_new_pw), presence()).expect(
        "B must unlock with the NEW master password — proves the VDK was \
         recovered + the install_paired_vdk re-key landed cleanly",
    );
}
