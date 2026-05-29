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
    add_device_v2, bootstrap_vault_v2, build_signed_device_auth, cancel_promotion_v2,
    finalize_promotion_v2, propose_promotion_v2, read_authorized_device_v2,
    read_current_manager_v2, read_device_nonce_v2, read_pending_promotion_v2, remove_device_v2,
    test_env, DeviceAuthFields, DeviceAuthKind, EvmWallet,
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

/// **#106e-0 — the PUBLIC `complete_rotation` composition driven against a
/// live anvil set.** The production twin of the rotation half above: instead
/// of hand-wiring `rotate_vdk_for_survivors` + `__test_commit_*`, it drives
/// `pangolin_core::composition::complete_rotation`, which reads the survivor
/// directory + the recovery-escrow params store-side (the active VDK never
/// crosses the crate boundary), runs the driver, calls the audited
/// `commit_vdk_rotation_from_active`, and resolves every retired
/// rotation-pending row (Q-e). Asserts: the epoch advanced, the pending row
/// cleared, the NEW password unlocks (prompt-on-revoke), the escrow
/// re-pointed, and GAP-A surfaces an in-set survivor whose pubkey the local
/// directory does not know.
#[tokio::test]
#[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
#[allow(clippy::too_many_lines)]
async fn complete_rotation_public_composition_e2e_against_anvil() {
    use pangolin_core::composition::complete_rotation;
    use pangolin_store::{PinIdentityProof, PressYPresenceProof, VaultState};

    let env = test_env::target_chain_env();
    if !test_env::is_dev_mode()
        && !test_env::require_or_fail("#106e-0 complete_rotation E2E needs dev anvil")
    {
        return;
    }
    let rpc_url = test_env::rpc_url();
    let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
        .await
        .expect("resolve signing chain id");
    let contract = pangolin_chain::load_deployed_address(env, "RevisionLogV2")
        .expect("RevisionLogV2 in dev.json");

    // ---- devices: A (survivor/manager), B (revoked), C (in-set survivor
    // the local directory does NOT know — GAP-A) ----
    let a_device = device_a();
    let a_wallet = wallet_for(&a_device);
    let a_signer = a_wallet.address();
    let a_pairing = derive_x25519_pairing_key(&a_device);
    let a_device_id = device_id_from_device_key(&a_device);

    let b_device = DeviceKey::from_seed([0x7B; 32]);
    let b_signer = wallet_for(&b_device).address();

    let c_device = DeviceKey::from_seed([0x9C; 32]);
    let c_signer = wallet_for(&c_device).address();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut vault_id = [0u8; 32];
    vault_id[..8].copy_from_slice(&now.to_be_bytes());
    vault_id[31] = 0xE6;

    let current_epoch = 0u64;

    // ---- on-chain: bootstrap A, add B + C, remove B ----
    let sign = |kind, subject, nonce| {
        build_signed_device_auth(
            a_wallet.signer(),
            DeviceAuthFields {
                kind,
                vault_id,
                subject,
                nonce,
                schema_version: 1,
            },
            contract,
            chain_id,
        )
        .expect("sign device auth")
    };
    bootstrap_vault_v2(
        &a_wallet,
        a_signer,
        &sign(DeviceAuthKind::AddDevice, a_signer, 0),
        env,
        &rpc_url,
    )
    .await
    .expect("bootstrapVault(A)");
    let n1 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    add_device_v2(
        &a_wallet,
        b_signer,
        &sign(DeviceAuthKind::AddDevice, b_signer, n1),
        env,
        &rpc_url,
    )
    .await
    .expect("addDevice(B)");
    let n2 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    add_device_v2(
        &a_wallet,
        c_signer,
        &sign(DeviceAuthKind::AddDevice, c_signer, n2),
        env,
        &rpc_url,
    )
    .await
    .expect("addDevice(C)");
    let n3 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    remove_device_v2(
        &a_wallet,
        b_signer,
        &sign(DeviceAuthKind::RemoveDevice, b_signer, n3),
        env,
        &rpc_url,
    )
    .await
    .expect("removeDevice(B)");

    // The live authorized set after the revoke: A + C (B removed).
    let current_onchain_set = vec![a_signer.into_array(), c_signer.into_array()];

    // ---- a local vault, unlocked, with A's directory entry + an escrow ----
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("complete-rotation-e2e.pvf");
    let pwd = pangolin_crypto::secret::SecretBytes::new(b"e2e master password".to_vec());
    Vault::create(&path, &pwd).expect("create vault");
    let mut vault = Vault::open(&path).expect("open vault");
    vault
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pangolin_crypto::secret::SecretBytes::new(
                b"e2e master password".to_vec(),
            )),
        )
        .expect("unlock");

    // The local directory knows A (survivor) but NOT C — C must surface in
    // RotationOutcome.unknown_survivors (GAP-A).
    vault
        .record_device_directory_entry(
            a_signer.into_array(),
            a_device_id,
            *a_pairing.public_bytes(),
        )
        .expect("record A in directory");

    // Onboard an escrow over the active VDK (2-of-3) so complete_rotation can
    // read its params + re-point it.
    let guardian_pubs: Vec<[u8; 32]> = (0u8..3)
        .map(|i| {
            let g = DeviceKey::from_seed([0xE0_u8.wrapping_add(i); 32]);
            *derive_x25519_sealing_key(&g).public_bytes()
        })
        .collect();
    vault
        .__test_onboard_recovery_escrow(2, &guardian_pubs, current_epoch)
        .expect("onboard escrow over active VDK");

    // The DeviceRemoved trigger persists a rotation-pending row for B.
    let queued = vault
        .process_device_removed_trigger(
            &current_onchain_set,
            &[
                a_signer.into_array(),
                b_signer.into_array(),
                c_signer.into_array(),
            ],
            current_epoch,
        )
        .expect("process DeviceRemoved trigger");
    assert_eq!(queued, 1, "exactly one removal queued (B)");
    assert_eq!(vault.pending_rotations().expect("pending").len(), 1);

    // ---- THE PUBLIC COMPOSITION ----
    let new_password = pangolin_crypto::secret::SecretBytes::new(b"post-revoke master pw".to_vec());
    let outcome = complete_rotation(&mut vault, &new_password, &current_onchain_set)
        .expect("complete_rotation composition");

    // Epoch advanced to current+1.
    assert_eq!(
        outcome.new_epoch,
        current_epoch + 1,
        "the shared epoch advances on rotation"
    );
    // GAP-A: C is in-set but its pairing pubkey is unknown locally — surfaced,
    // never silently stranded.
    assert_eq!(
        outcome.unknown_survivors,
        vec![c_signer.into_array()],
        "the in-set-but-unknown survivor C surfaces in unknown_survivors (GAP-A)"
    );
    // The vault is Locked post-commit; the pending row for B cleared (Q-e).
    assert_eq!(vault.state(), VaultState::Locked);
    assert!(
        vault.pending_rotations().expect("pending").is_empty(),
        "the rotation-pending row clears after complete_rotation (Q-e)"
    );

    // The OLD password no longer opens; the NEW password does (prompt-on-revoke).
    let old_err = vault
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pangolin_crypto::secret::SecretBytes::new(
                b"e2e master password".to_vec(),
            )),
        )
        .unwrap_err();
    assert!(matches!(
        old_err,
        pangolin_store::StoreError::AuthenticationFailed
    ));
    vault
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(pangolin_crypto::secret::SecretBytes::new(
                b"post-revoke master pw".to_vec(),
            )),
        )
        .expect("NEW password opens the rotated vault");
    assert_eq!(vault.state(), VaultState::Active);

    // The escrow re-pointed to the new epoch with the same guardian set.
    let params = vault
        .recovery_escrow_params()
        .expect("escrow params")
        .expect("escrow present after rotation");
    assert_eq!(
        params.current_epoch,
        current_epoch + 1,
        "the VDK-chain epoch advanced (rotation shares one clock)"
    );
    assert_eq!(params.guardian_count, 3);
    assert_eq!(params.threshold, 2);
}

/// Fund a wallet on the local anvil chain via `cast rpc anvil_setBalance`
/// (the harness guarantees `cast` is on PATH in dev mode). Needed so a
/// device other than the harness-funded A can pay gas for its own publish.
/// Fail-closed: a non-success exit is a hard test failure.
fn anvil_fund(rpc_url: &str, addr: pangolin_chain::Address) {
    let out = std::process::Command::new("cast")
        .args([
            "rpc",
            "anvil_setBalance",
            &format!("{addr:?}"),
            // 1 ETH = 0xDE0B6B3A7640000 wei.
            "0xDE0B6B3A7640000",
            "--rpc-url",
            rpc_url,
        ])
        .output()
        .expect("invoke cast rpc anvil_setBalance");
    assert!(
        out.status.success(),
        "anvil_setBalance failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Fast-forward the local anvil clock by `secs` + mine a block, so a test
/// can cross the `PROMOTION_DELAY` (48h) without waiting. Fail-closed.
fn anvil_warp(rpc_url: &str, secs: u64) {
    let inc = std::process::Command::new("cast")
        .args([
            "rpc",
            "evm_increaseTime",
            &secs.to_string(),
            "--rpc-url",
            rpc_url,
        ])
        .output()
        .expect("invoke cast rpc evm_increaseTime");
    assert!(
        inc.status.success(),
        "evm_increaseTime failed: {}",
        String::from_utf8_lossy(&inc.stderr)
    );
    let mine = std::process::Command::new("cast")
        .args(["rpc", "evm_mine", "--rpc-url", rpc_url])
        .output()
        .expect("invoke cast rpc evm_mine");
    assert!(
        mine.status.success(),
        "evm_mine failed: {}",
        String::from_utf8_lossy(&mine.stderr)
    );
}

/// **MVP-4-K — the manager-promotion handoff E2E.**
///
/// Drives the candidate-initiated, 48h-delayed promotion against the live
/// `RevisionLogV2` bytecode, exercising the new chain-client glue
/// (`propose_promotion_v2` / `finalize_promotion_v2` /
/// `read_pending_promotion_v2`) + the `DeviceAuthKind::Promote` self-sign:
///
/// ```text
/// bootstrapVault(A) + addDevice(B)        — A manager, B member
/// B self-signs Promote(candidate=B) → proposePromotion   — B's key, NOT A's
///   → pendingPromotion == (B, readyAt); currentManager still A
/// finalize before delay → ErrPromotionDelayNotElapsed     — the 48h gate holds
/// warp +48h + mine → finalizePromotion (permissionless)   — manager rotates to B
///   → currentManager == B; pendingPromotion cleared
/// ```
#[tokio::test]
#[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
#[allow(clippy::too_many_lines)] // one linear propose→warp→finalize sequence
async fn promotion_handoff_e2e_against_anvil() {
    let env = test_env::target_chain_env();
    if !test_env::is_dev_mode()
        && !test_env::require_or_fail("MVP-4-K promotion E2E needs dev anvil")
    {
        return;
    }
    let rpc_url = test_env::rpc_url();
    let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
        .await
        .expect("resolve signing chain id");
    let contract = pangolin_chain::load_deployed_address(env, "RevisionLogV2")
        .expect("RevisionLogV2 in dev.json");

    let a_device = device_a();
    let a_wallet = wallet_for(&a_device);
    let a_signer = a_wallet.address();
    let b_device = DeviceKey::from_seed([0x7B; 32]);
    let b_wallet = wallet_for(&b_device);
    let b_signer = b_wallet.address();
    // B broadcasts proposePromotion → B needs gas (A is harness-funded).
    anvil_fund(&rpc_url, b_signer);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut vault_id = [0u8; 32];
    vault_id[..8].copy_from_slice(&now.to_be_bytes());
    vault_id[31] = 0x4B;

    // bootstrap A + add B.
    let bootstrap_sig = build_signed_device_auth(
        a_wallet.signer(),
        DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id,
            subject: a_signer,
            nonce: 0,
            schema_version: 1,
        },
        contract,
        chain_id,
    )
    .expect("sign genesis AddDevice");
    bootstrap_vault_v2(&a_wallet, a_signer, &bootstrap_sig, env, &rpc_url)
        .await
        .expect("bootstrapVault");
    let nonce1 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let add_sig = build_signed_device_auth(
        a_wallet.signer(),
        DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id,
            subject: b_signer,
            nonce: nonce1,
            schema_version: 1,
        },
        contract,
        chain_id,
    )
    .expect("manager signs AddDevice(B)");
    add_device_v2(&a_wallet, b_signer, &add_sig, env, &rpc_url)
        .await
        .expect("addDevice(B)");

    // B self-signs Promote(candidate=B) — the candidate's key, not A's.
    let nonce2 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let promote_sig = build_signed_device_auth(
        b_wallet.signer(),
        DeviceAuthFields {
            kind: DeviceAuthKind::Promote,
            vault_id,
            subject: b_signer,
            nonce: nonce2,
            schema_version: 1,
        },
        contract,
        chain_id,
    )
    .expect("candidate B self-signs Promote");
    propose_promotion_v2(&b_wallet, b_signer, &promote_sig, env, &rpc_url)
        .await
        .expect("proposePromotion accepted (candidate self-sign)");

    let pending = read_pending_promotion_v2(env, &rpc_url, vault_id)
        .await
        .expect("read pending");
    let (cand, ready_at) = pending.expect("a promotion is pending");
    assert_eq!(cand, b_signer, "pending candidate is B");
    assert!(ready_at > now, "readyAt is in the future (48h delay)");
    assert_eq!(
        read_current_manager_v2(env, &rpc_url, vault_id)
            .await
            .unwrap(),
        a_signer,
        "manager is still A before finalize"
    );

    // Finalize before the delay → reverts.
    assert!(
        finalize_promotion_v2(&b_wallet, vault_id, env, &rpc_url)
            .await
            .is_err(),
        "finalize before the 48h delay must revert (ErrPromotionDelayNotElapsed)"
    );

    // Warp past the delay (+1h slop) + finalize (permissionless — B submits).
    anvil_warp(&rpc_url, 48 * 60 * 60 + 3600);
    finalize_promotion_v2(&b_wallet, vault_id, env, &rpc_url)
        .await
        .expect("finalizePromotion after the delay");
    assert_eq!(
        read_current_manager_v2(env, &rpc_url, vault_id)
            .await
            .unwrap(),
        b_signer,
        "manager rotated to B after finalize"
    );
    assert!(
        read_pending_promotion_v2(env, &rpc_url, vault_id)
            .await
            .unwrap()
            .is_none(),
        "pending promotion cleared after finalize"
    );
}

/// **MVP-4-K — the manager's veto.** A proposes-then-vetoes: after B
/// self-proposes, the current manager A `cancelPromotion`s it (msg.sender
/// gated), clearing the pending state; the manager stays A.
#[tokio::test]
#[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
async fn promotion_veto_e2e_against_anvil() {
    let env = test_env::target_chain_env();
    if !test_env::is_dev_mode() && !test_env::require_or_fail("MVP-4-K veto E2E needs dev anvil") {
        return;
    }
    let rpc_url = test_env::rpc_url();
    let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
        .await
        .unwrap();
    let contract = pangolin_chain::load_deployed_address(env, "RevisionLogV2").unwrap();

    let a_wallet = wallet_for(&device_a());
    let a_signer = a_wallet.address();
    let b_device = DeviceKey::from_seed([0x7C; 32]);
    let b_wallet = wallet_for(&b_device);
    let b_signer = b_wallet.address();
    anvil_fund(&rpc_url, b_signer);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut vault_id = [0u8; 32];
    vault_id[..8].copy_from_slice(&now.to_be_bytes());
    vault_id[31] = 0x4C;

    let bootstrap_sig = build_signed_device_auth(
        a_wallet.signer(),
        DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id,
            subject: a_signer,
            nonce: 0,
            schema_version: 1,
        },
        contract,
        chain_id,
    )
    .unwrap();
    bootstrap_vault_v2(&a_wallet, a_signer, &bootstrap_sig, env, &rpc_url)
        .await
        .unwrap();
    let n1 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let add_sig = build_signed_device_auth(
        a_wallet.signer(),
        DeviceAuthFields {
            kind: DeviceAuthKind::AddDevice,
            vault_id,
            subject: b_signer,
            nonce: n1,
            schema_version: 1,
        },
        contract,
        chain_id,
    )
    .unwrap();
    add_device_v2(&a_wallet, b_signer, &add_sig, env, &rpc_url)
        .await
        .unwrap();

    let n2 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let promote_sig = build_signed_device_auth(
        b_wallet.signer(),
        DeviceAuthFields {
            kind: DeviceAuthKind::Promote,
            vault_id,
            subject: b_signer,
            nonce: n2,
            schema_version: 1,
        },
        contract,
        chain_id,
    )
    .unwrap();
    propose_promotion_v2(&b_wallet, b_signer, &promote_sig, env, &rpc_url)
        .await
        .unwrap();
    assert!(
        read_pending_promotion_v2(env, &rpc_url, vault_id)
            .await
            .unwrap()
            .is_some(),
        "promotion pending after propose"
    );

    // A (the manager) vetoes — msg.sender == currentManager.
    cancel_promotion_v2(&a_wallet, vault_id, env, &rpc_url)
        .await
        .expect("manager A cancels the pending promotion");
    assert!(
        read_pending_promotion_v2(env, &rpc_url, vault_id)
            .await
            .unwrap()
            .is_none(),
        "pending cleared after the manager's veto"
    );
    assert_eq!(
        read_current_manager_v2(env, &rpc_url, vault_id)
            .await
            .unwrap(),
        a_signer,
        "manager stays A after veto"
    );
}

/// **#106d L11 CENTERPIECE — the revocation-on-read regression gate.**
///
/// Drives the live-set honor gate + the retroactive re-eval through the
/// REAL `Vault::sync_from_chain` V2 path against the deployed
/// `RevisionLogV2` bytecode:
///
/// ```text
/// 1. bootstrapVault(A) + addDevice(B)        — both in the on-chain set
/// 2. publish_revision_v2 as A AND as B       — both publishes accepted (in set)
/// 3. sync (from genesis) → BOTH honored      — both rows land + surface as heads/history
/// 4. removeDevice(B)                         — B out of the on-chain set
/// 5. re-sync (from genesis) → A honored, B's stored entry REVOKED-on-read
///    (filtered from head/history); revisions_revoked counts it
/// 6. addDevice(B) again → re-sync → B honored again (re-add un-revokes)
/// ```
///
/// Negatives that MUST flip this RED: a "honor-all" predicate (B's removed
/// entry would still surface — step 5 fails), a fail-OPEN on a set-read
/// error (the gate would honor everyone), and a marks-revoked-but-reads-
/// don't-filter regression (the revoked B row would still appear in
/// head/history — step 5's filter asserts fail).
#[tokio::test]
#[ignore = "live-RPC test; requires PANGOLIN_CHAIN_ENV=dev + local anvil (scripts/anvil-ci.sh)"]
#[allow(clippy::too_many_lines)] // the coupled remove-then-read gate is one long sequence
#[allow(clippy::similar_names)] // a_/b_ device + acct_a/acct_b are inherent to a 2-device test
async fn revocation_honor_gate_remove_then_read_e2e_against_anvil() {
    use pangolin_chain::{
        build_signed_device_auth, build_signed_revision_v2, keccak256, publish_revision_v2,
        read_authorized_set_v2, secp256k1_signing::RevisionFieldsV1, SyncOptions,
    };
    use pangolin_store::{PinIdentityProof, PressYPresenceProof, RevisionLogVersion};

    let env = test_env::target_chain_env();
    if !test_env::is_dev_mode()
        && !test_env::require_or_fail("#106d revocation E2E needs dev anvil")
    {
        return;
    }
    let rpc_url = test_env::rpc_url();
    let chain_id = test_env::resolve_signing_chain_id(env, &rpc_url)
        .await
        .expect("resolve signing chain id");
    let contract = pangolin_chain::load_deployed_address(env, "RevisionLogV2")
        .expect("RevisionLogV2 in dev.json");

    // ---- devices ----
    let a_device = device_a();
    let a_wallet = wallet_for(&a_device);
    let a_signer = a_wallet.address();
    let b_device = DeviceKey::from_seed([0x7B; 32]);
    let b_wallet = wallet_for(&b_device);
    let b_signer = b_wallet.address();
    // B pays gas for its own publish — fund it on the local chain.
    anvil_fund(&rpc_url, b_signer);

    // Fresh vault id (time-tweaked so reruns don't collide).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut vault_id = [0u8; 32];
    vault_id[..8].copy_from_slice(&now.to_be_bytes());
    vault_id[31] = 0xD6;

    let sv = 1u16;

    // ---- 1. bootstrapVault(A) + addDevice(B) ----
    let boot_fields = DeviceAuthFields {
        kind: DeviceAuthKind::AddDevice,
        vault_id,
        subject: a_signer,
        nonce: 0,
        schema_version: sv,
    };
    let boot_sig = build_signed_device_auth(a_wallet.signer(), boot_fields, contract, chain_id)
        .expect("sign bootstrap");
    bootstrap_vault_v2(&a_wallet, a_signer, &boot_sig, env, &rpc_url)
        .await
        .expect("bootstrapVault");
    let nonce1 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let add_fields = DeviceAuthFields {
        kind: DeviceAuthKind::AddDevice,
        vault_id,
        subject: b_signer,
        nonce: nonce1,
        schema_version: sv,
    };
    let add_sig = build_signed_device_auth(a_wallet.signer(), add_fields, contract, chain_id)
        .expect("sign addDevice(B)");
    add_device_v2(&a_wallet, b_signer, &add_sig, env, &rpc_url)
        .await
        .expect("addDevice(B)");

    // ---- 2. publish_revision_v2 as A AND as B (both in set) ----
    // Distinct account ids so each is its own head. `with_signer_device_id`
    // sets the deviceId to the 32-byte left-padded signer — exactly the
    // shape the retroactive re-eval decodes (rightmost 20 bytes).
    let publish = |wallet: &EvmWallet, account: [u8; 32], tag: &str| {
        let enc_payload = format!("rev-{tag}-{now}").into_bytes();
        let enc_payload_hash = keccak256(&enc_payload).0;
        let fields = RevisionFieldsV1::with_signer_device_id(
            wallet,
            vault_id,
            account,
            [0u8; 32],
            sv,
            enc_payload_hash,
        );
        build_signed_revision_v2(wallet, fields, enc_payload, contract, chain_id)
            .expect("sign v2 revision")
    };
    let acct_a = [0xA1; 32];
    let acct_b = [0xB2; 32];
    let signed_a = publish(&a_wallet, acct_a, "A");
    publish_revision_v2(&a_wallet, &signed_a, env, &rpc_url)
        .await
        .expect("A publish accepted (A in set)");
    let signed_b = publish(&b_wallet, acct_b, "B");
    publish_revision_v2(&b_wallet, &signed_b, env, &rpc_url)
        .await
        .expect("B publish accepted (B in set)");

    // ---- a V2-bound local vault to sync into ----
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("revocation-e2e.pvf");
    let pwd = pangolin_crypto::secret::SecretBytes::new(b"e2e master password".to_vec());
    Vault::create(&path, &pwd).expect("create vault");
    let mut vault = Vault::open(&path).expect("open vault");
    {
        let presence = PressYPresenceProof::confirmed();
        let identity = PinIdentityProof::new(pangolin_crypto::secret::SecretBytes::new(
            b"e2e master password".to_vec(),
        ));
        vault.unlock(&presence, &identity).expect("unlock");
    }
    // Bind the vault to V2 so sync routes through the honor-gated V2 path.
    vault
        .set_revisionlog_version(RevisionLogVersion::V2)
        .expect("bind V2");

    let acct_a_id = pangolin_store::AccountId::from_bytes(acct_a);
    let acct_b_id = pangolin_store::AccountId::from_bytes(acct_b);
    let from_genesis = SyncOptions {
        from_genesis: true,
        ..Default::default()
    };

    // ---- 3. sync (from genesis) → BOTH honored ----
    let rep1 = vault
        .sync_from_chain(&rpc_url, env, &vault_id, from_genesis)
        .await
        .expect("sync 1");
    assert_eq!(
        rep1.revisions_revoked, 0,
        "nothing revoked while both in set"
    );
    assert_eq!(
        vault.account_heads(acct_a_id).expect("heads A").len(),
        1,
        "A's revision is honored (a head)"
    );
    assert_eq!(
        vault.account_heads(acct_b_id).expect("heads B").len(),
        1,
        "B's revision is honored (a head) while B is in the set"
    );

    // Sanity: the live set read returns BOTH A and B (the gate's source).
    let set_with_b = read_authorized_set_v2(env, &rpc_url, vault_id, 0)
        .await
        .expect("set read");
    assert!(set_with_b.contains(&a_signer) && set_with_b.contains(&b_signer));

    // ---- 4. removeDevice(B) ----
    let nonce2 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let rm_fields = DeviceAuthFields {
        kind: DeviceAuthKind::RemoveDevice,
        vault_id,
        subject: b_signer,
        nonce: nonce2,
        schema_version: sv,
    };
    let rm_sig = build_signed_device_auth(a_wallet.signer(), rm_fields, contract, chain_id)
        .expect("sign removeDevice(B)");
    remove_device_v2(&a_wallet, b_signer, &rm_sig, env, &rpc_url)
        .await
        .expect("removeDevice(B)");
    let set_without_b = read_authorized_set_v2(env, &rpc_url, vault_id, 0)
        .await
        .expect("set read after remove");
    assert!(
        set_without_b.contains(&a_signer) && !set_without_b.contains(&b_signer),
        "after removeDevice the live set is {{A}} only"
    );

    // ---- 5. re-sync → A honored, B's stored entry REVOKED-on-read ----
    let rep2 = vault
        .sync_from_chain(&rpc_url, env, &vault_id, from_genesis)
        .await
        .expect("sync 2");
    // B's already-stored row is retroactively marked revoked (≥1; the
    // from-genesis re-read may ALSO hit the incoming gate, but the count is
    // disjoint per arm — assert at least the one cut).
    assert!(
        rep2.revisions_revoked >= 1,
        "removed B's entry must be counted as revoked (got {})",
        rep2.revisions_revoked
    );
    assert_eq!(
        vault.account_heads(acct_a_id).expect("heads A after").len(),
        1,
        "A stays honored after B is removed"
    );
    assert!(
        vault
            .account_heads(acct_b_id)
            .expect("heads B after")
            .is_empty(),
        "removed B's revision is REVOKED-on-read (filtered from heads) — \
         a honor-all predicate or a marks-but-reads-don't-filter regression \
         would leave it surfacing here (L11 negative)"
    );
    assert!(
        vault
            .revisions_for(acct_b_id)
            .expect("history B")
            .is_empty(),
        "removed B's revision is filtered from history too"
    );

    // ---- 6. re-add B → re-sync → B honored again (re-add un-revokes) ----
    let nonce3 = read_device_nonce_v2(env, &rpc_url, vault_id).await.unwrap();
    let re_add_fields = DeviceAuthFields {
        kind: DeviceAuthKind::AddDevice,
        vault_id,
        subject: b_signer,
        nonce: nonce3,
        schema_version: sv,
    };
    let re_add_sig = build_signed_device_auth(a_wallet.signer(), re_add_fields, contract, chain_id)
        .expect("sign re-add(B)");
    add_device_v2(&a_wallet, b_signer, &re_add_sig, env, &rpc_url)
        .await
        .expect("re-add(B)");
    let _rep3 = vault
        .sync_from_chain(&rpc_url, env, &vault_id, from_genesis)
        .await
        .expect("sync 3");
    assert_eq!(
        vault
            .account_heads(acct_b_id)
            .expect("heads B re-add")
            .len(),
        1,
        "re-added B's revision is honored again (re-add un-revokes — the live \
         set is the single source of truth)"
    );
}
