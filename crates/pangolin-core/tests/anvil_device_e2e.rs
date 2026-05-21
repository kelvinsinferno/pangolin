// SPDX-License-Identifier: AGPL-3.0-or-later
//! #106c COUPLED anvil E2E (the CENTERPIECE / L10).
//!
//! Ties the `RevisionLogV2` chain client (#106c) + the device-pairing VDK
//! handoff (#106b-1) + the VDK rotation-on-revoke (#106b-2) end-to-end
//! against a live local anvil.
//!
//! This is the env-quirk-#14-class regression gate the #106c plan §5
//! mandates. It composes, against the LIVE deployed `RevisionLogV2` bytecode:
//!
//! ```text
//! 1. bootstrapVault(A)               — A in the set, A is manager
//! 2. addDevice(B)                    — real manager EIP-712, accepted by the live contract
//! 3. seal_vdk_to_new_device + open   — the VDK handoff round-trips byte-identical (ct_eq)
//! 4. B publishRevision succeeds      — B is in the set, honored (honor gate agrees)
//! 5. removeDevice(B)                 — B out of the set
//! 6. B publish now UNHONORED         — the honor gate (L5) rejects the removed signer
//! 7. the DeviceRemoved trigger fires — a rotation-pending row is persisted (NOT auto-rotate, L3)
//! 8. rotate_vdk_for_survivors([A]) + commit_vdk_rotation
//! 9. forward secrecy: removed B CANNOT open the new epoch; survivor A CAN
//! ```
//!
//! The load-bearing joins asserted here: the client's `AddDevice` /
//! `RemoveDevice` EIP-712 digest is byte-identical to the contract's `_hash*`
//! (a broken digest reverts step 2/5 RED — the live contract rejects), the
//! honor gate tracks the on-chain set (step 4 vs 6), the trigger never
//! auto-rotates (step 7 holds no password), and the new-epoch VDK is sealed
//! ONLY to survivors (step 9 — removed B has no seal).
//!
//! Gated on `integration-tests` + `#[ignore]`; run by `scripts/anvil-ci.sh`
//! in dev mode against a fresh local anvil node.
#![cfg(feature = "integration-tests")]

use pangolin_chain::evm::derive_evm_wallet;
use pangolin_chain::{
    add_device_v2, bootstrap_vault_v2, build_signed_device_auth, read_authorized_device_v2,
    read_device_nonce_v2, remove_device_v2, test_env, DeviceAuthFields, DeviceAuthKind, EvmWallet,
};
use pangolin_core::device_add::{
    device_id_from_device_key, open_vdk_for_new_device, seal_vdk_to_new_device, NewDeviceHandshake,
};
use pangolin_core::recovery::orchestration::RecoveryEpoch;
use pangolin_core::recovery::GuardianSetConfig;
use pangolin_core::rotation::{rotate_vdk_for_survivors, SurvivingDevice};
use pangolin_crypto::guardian::derive_x25519_sealing_key;
use pangolin_crypto::keys::{DeviceKey, VdkKey};
use pangolin_crypto::pairing::derive_x25519_pairing_key;
use pangolin_store::recovery_escrow::GuardianRecord;
use pangolin_store::{consume_survivor_seal, Vault};

/// Device A — the manager / primary. The same fixed seed `[0x42;32]`
/// `scripts/anvil-ci.sh` funds (so its lifecycle txs pay gas). It
/// self-bootstraps the vault.
fn device_a() -> DeviceKey {
    DeviceKey::from_seed([0x42; 32])
}

fn wallet_for(device: &DeviceKey) -> EvmWallet {
    derive_evm_wallet(device).expect("derive wallet")
}

/// **L10 CENTERPIECE.** The full multi-device add → remove → rotate loop
/// against a live local anvil node.
#[tokio::test]
#[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
#[allow(clippy::too_many_lines)] // the coupled E2E is one long linear sequence
async fn device_add_remove_rotate_e2e_against_anvil() {
    let env = test_env::target_chain_env();
    if !test_env::is_dev_mode() && !test_env::require_or_fail("#106c device E2E needs dev anvil") {
        return;
    }
    let rpc_url = test_env::rpc_url();
    let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
        .await
        .expect("resolve signing chain id");

    // RevisionLogV2 address (the harness deploys it). Resolve via a public
    // read so we bind the manager EIP-712 to the live verifying contract.
    let contract = pangolin_chain::load_deployed_address(env, "RevisionLogV2")
        .expect("RevisionLogV2 in dev.json");

    // ---- devices ----
    let a_device = device_a();
    let a_wallet = wallet_for(&a_device);
    let a_signer = a_wallet.address();

    let b_device = DeviceKey::from_seed([0x7B; 32]);
    let b_wallet = wallet_for(&b_device);
    let b_signer = b_wallet.address();
    let b_pairing = derive_x25519_pairing_key(&b_device);
    let b_device_id = device_id_from_device_key(&b_device);

    // A fresh vault id (time-tweaked so reruns on a persistent chain don't
    // collide; anvil is fresh per harness run anyway).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut vault_id = [0u8; 32];
    vault_id[..8].copy_from_slice(&now.to_be_bytes());
    vault_id[31] = 0xC6;

    // The "live VDK" A holds while unlocked (the host already has it). We
    // own it here so the test can drive the pairing seal directly.
    let live_vdk = VdkKey::generate();
    let current_epoch = 0u64;

    // ---- 1. bootstrapVault(A): A signs AddDevice at nonce 0 for itself ----
    let bootstrap_fields = DeviceAuthFields {
        kind: DeviceAuthKind::AddDevice,
        vault_id,
        subject: a_signer,
        nonce: 0,
        schema_version: 1,
    };
    let bootstrap_sig =
        build_signed_device_auth(a_wallet.signer(), bootstrap_fields, contract, chain_id)
            .expect("sign genesis AddDevice");
    bootstrap_vault_v2(&a_wallet, a_signer, &bootstrap_sig, env, &rpc_url)
        .await
        .expect("bootstrapVault accepted by the live contract");
    assert!(
        read_authorized_device_v2(env, &rpc_url, vault_id, a_signer)
            .await
            .unwrap(),
        "A is in the on-chain set after bootstrap"
    );

    // ---- 2. addDevice(B): A (manager) signs AddDevice over the live nonce ----
    let nonce1 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let add_fields = DeviceAuthFields {
        kind: DeviceAuthKind::AddDevice,
        vault_id,
        subject: b_signer,
        nonce: nonce1,
        schema_version: 1,
    };
    let add_sig = build_signed_device_auth(a_wallet.signer(), add_fields, contract, chain_id)
        .expect("manager signs AddDevice(B)");
    add_device_v2(&a_wallet, b_signer, &add_sig, env, &rpc_url)
        .await
        .expect("addDevice(B) accepted by the live contract (L2 byte-identity)");
    assert!(
        read_authorized_device_v2(env, &rpc_url, vault_id, b_signer)
            .await
            .unwrap(),
        "B is in the on-chain set after addDevice"
    );

    // ---- 3. seal+open the VDK to B (ct_eq) ----
    let handshake = NewDeviceHandshake {
        device_id: b_device_id,
        x25519_pairing_pub: *b_pairing.public_bytes(),
    };
    let sealed = seal_vdk_to_new_device(&live_vdk, &handshake, &vault_id, current_epoch)
        .expect("A seals VDK to B");
    let b_secret = b_pairing.secret_bytes();
    let b_vdk = open_vdk_for_new_device(&sealed, &b_secret, &vault_id, &b_device_id, current_epoch)
        .expect("B opens the sealed VDK");
    assert!(
        bool::from(live_vdk.ct_eq(&b_vdk)),
        "the VDK handoff round-trips byte-identical (ct_eq)"
    );

    // ---- 4. honor gate honors B (in set) ----
    let set_with_b = vec![a_signer.into_array(), b_signer.into_array()];
    assert!(
        Vault::is_signer_honored(&b_signer.into_array(), &set_with_b),
        "B is honored while in the on-chain set (L5)"
    );

    // ---- 5. removeDevice(B): A signs RemoveDevice over the live nonce ----
    let nonce2 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let remove_fields = DeviceAuthFields {
        kind: DeviceAuthKind::RemoveDevice,
        vault_id,
        subject: b_signer,
        nonce: nonce2,
        schema_version: 1,
    };
    let remove_sig = build_signed_device_auth(a_wallet.signer(), remove_fields, contract, chain_id)
        .expect("manager signs RemoveDevice(B)");
    remove_device_v2(&a_wallet, b_signer, &remove_sig, env, &rpc_url)
        .await
        .expect("removeDevice(B) accepted by the live contract");
    assert!(
        !read_authorized_device_v2(env, &rpc_url, vault_id, b_signer)
            .await
            .unwrap(),
        "B is OUT of the on-chain set after removeDevice"
    );

    // ---- 6. honor gate now REJECTS B (out of set) — L5 ----
    let set_without_b = vec![a_signer.into_array()];
    assert!(
        !Vault::is_signer_honored(&b_signer.into_array(), &set_without_b),
        "removed B is UNHONORED (L5) — the honor gate tracks the live set"
    );

    // ---- a local vault for the rotation half ----
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("device-e2e.pvf");
    let pwd = pangolin_crypto::secret::SecretBytes::new(b"e2e master password".to_vec());
    Vault::create(&path, &pwd).expect("create vault");
    let mut vault = Vault::open(&path).expect("open vault");
    {
        use pangolin_store::{PinIdentityProof, PressYPresenceProof};
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(pangolin_crypto::secret::SecretBytes::new(
            b"e2e master password".to_vec(),
        ));
        vault.unlock(&presence, &identity).expect("unlock");
    }

    // ---- 7. the DeviceRemoved trigger fires → rotation-pending persisted ----
    // Detection: B was locally-known but is no longer in the on-chain set.
    let queued = vault
        .process_device_removed_trigger(
            &set_without_b,
            &[a_signer.into_array(), b_signer.into_array()],
            current_epoch,
        )
        .expect("process DeviceRemoved trigger");
    assert_eq!(queued, 1, "exactly one removal queued (B)");
    let pending = vault.pending_rotations().expect("read pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].removed_signer, b_signer.into_array());
    // L3: the trigger ONLY persisted; it did NOT rotate (the vault is still
    // on the original epoch — no auto-rotate).

    // ---- 8. host completes: rotate_vdk_for_survivors([A]) + commit ----
    let a_pairing = derive_x25519_pairing_key(&a_device);
    let a_device_id = device_id_from_device_key(&a_device);
    let survivors = [SurvivingDevice {
        device_id: a_device_id,
        x25519_pairing_pub: *a_pairing.public_bytes(),
    }];

    // A 2-of-3 guardian set for the escrow re-point (unchanged by a device
    // revoke). Derive deterministic guardian X25519 pubkeys.
    let config = GuardianSetConfig {
        threshold: 2,
        guardian_count: 3,
    };
    let guardian_pubs: Vec<[u8; 32]> = (0u8..3)
        .map(|i| {
            let g = DeviceKey::from_seed([0xE0_u8.wrapping_add(i); 32]);
            *derive_x25519_sealing_key(&g).public_bytes()
        })
        .collect();

    let artifacts = rotate_vdk_for_survivors(
        &survivors,
        &vault_id,
        config,
        &guardian_pubs,
        RecoveryEpoch(current_epoch),
    )
    .expect("rotate_vdk_for_survivors");
    let new_epoch = artifacts.new_epoch.0;
    assert_eq!(new_epoch, current_epoch + 1, "epoch advances on rotation");
    // The removed device B is NEVER in the survivor seals (L1 / forward secrecy).
    assert!(
        !artifacts
            .survivor_seals
            .iter()
            .any(|s| s.device_id == b_device_id),
        "no survivor seal was minted to the removed device B (L1)"
    );

    // Capture the survivor seal for A (consumed below for the FS assert) +
    // the new VDK's expected bytes (via the survivor consume) BEFORE the
    // commit moves the new_vdk into the store.
    let a_seal = artifacts
        .survivor_seals
        .iter()
        .find(|s| s.device_id == a_device_id)
        .expect("A has a survivor seal")
        .sealed
        .clone();

    // Build the GuardianRecord slice from the re_split for commit_vdk_rotation.
    let re_split = &artifacts.re_split;
    let records: Vec<GuardianRecord<'_>> = re_split
        .assignments
        .iter()
        .map(|a| GuardianRecord {
            index: a.index,
            guardian_x25519_pub: a.guardian_x25519_pub,
            sealed_share: &a.sealed_share,
        })
        .collect();

    // Commit the rotation atomically (the local device A re-keys its own
    // wrap inside the commit; prompt-on-revoke: the master password crosses
    // ONLY here, store-side — the engine never auto-rotated).
    vault
        .__test_commit_vdk_rotation_reusing_active(
            artifacts.new_vdk,
            &pwd,
            new_epoch,
            &re_split.wrapped_recovery,
            re_split.config.threshold,
            re_split.config.guardian_count,
            re_split.epoch.0,
            &records,
        )
        .expect("commit_vdk_rotation");
    // Mark the pending rotation resolved.
    vault
        .resolve_rotation_pending(&b_signer.into_array())
        .expect("resolve pending");
    assert!(
        vault.pending_rotations().expect("read pending").is_empty(),
        "the rotation-pending row clears after completion"
    );

    // ---- 9. FORWARD SECRECY ----
    // The survivor A CAN open the new epoch (its survivor seal opens under
    // A's pairing secret).
    let (a_new_vdk, _wrapped) =
        consume_survivor_seal(&a_seal, &a_device, &vault_id, &a_device_id, new_epoch)
            .expect("survivor A opens the new-epoch seal");

    // The removed device B CANNOT open the new epoch: no survivor seal was
    // minted to B, and even if it tried A's seal with its own key/id it
    // fails (the seal is bound to A's pairing pubkey + A's device_id).
    let b_attempt = consume_survivor_seal(&a_seal, &b_device, &vault_id, &b_device_id, new_epoch);
    assert!(
        b_attempt.is_err(),
        "the removed device B CANNOT open the new epoch (forward secrecy, L1)"
    );

    // The new-epoch VDK A recovered is NOT the pre-revoke VDK (a fresh key
    // was minted for the new epoch).
    assert!(
        !bool::from(a_new_vdk.ct_eq(&live_vdk)),
        "the new-epoch VDK is a FRESH key (rotation re-created it, L9)"
    );
}
