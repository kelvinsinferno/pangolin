// SPDX-License-Identifier: AGPL-3.0-or-later
//! #106e-0 HERMETIC composition test — the LOST-EVERYTHING recovery path
//! driven through the PUBLIC composition surface end-to-end:
//!
//! ```text
//! onboard_guardian_escrow(V)            — mint a real escrow for a VDK V
//! Vault::guardian_open_sealed_share x t — each guardian opens its sealed share
//! composition::recover_from_shares      — reconstruct V, re-split, atomic commit
//! unlock(new_password)                  — the recovered VDK is LIVE
//! a post-recovery write decrypts under V — proves the recovered VDK works
//! recovery_escrow_params()              — the re-split landed at the bumped epoch
//! ```
//!
//! No anvil / no chain — this is the hermetic regression gate for the
//! `recover_from_shares` + `guardian_open_sealed_share` composition. The
//! rotation half (`complete_rotation`) is exercised by the coupled anvil
//! E2E (`anvil_device_e2e.rs`), which has the live on-chain authorized set
//! a rotation resolves survivors against.

use pangolin_core::composition::{recover_from_shares, GuardianRoster, RecoveryOutcome};
use pangolin_core::recovery::orchestration::RecoveryEpoch;
use pangolin_core::recovery::{onboard_guardian_escrow, GuardianSetConfig};
use pangolin_crypto::escrow::{SealedShare, Share};
use pangolin_crypto::guardian::derive_x25519_sealing_key;
use pangolin_crypto::keys::{DeviceKey, VdkKey, VAULT_ID_LEN};
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{AccountSnapshot, PinIdentityProof, PressYPresenceProof, Vault, VaultState};

const T: u8 = 2;
const M: u8 = 3;

fn snapshot(name: &str) -> AccountSnapshot {
    AccountSnapshot::new(
        SecretBytes::new(name.as_bytes().to_vec()),
        SecretBytes::new(b"alice".to_vec()),
        SecretBytes::new(b"hunter2".to_vec()),
        SecretBytes::new(b"https://example.com".to_vec()),
        SecretBytes::new(b"notes".to_vec()),
        SecretBytes::new(b"".to_vec()),
    )
}

fn unlock(vault: &mut Vault, password: &[u8]) {
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(SecretBytes::new(password.to_vec()));
    vault.unlock(&presence, &identity).expect("unlock");
}

/// Spin up `M` guardian vaults; return their (sealing pubkey, opener Vault)
/// pairs. The guardian opens shares via `Vault::guardian_open_sealed_share`,
/// which derives the sealing secret from the vault's OWN active device key,
/// so the escrow must be sealed to each vault's derived sealing pubkey.
fn guardian_vaults(
    dirs: &[tempfile::TempDir],
) -> (Vec<[u8; 32]>, Vec<Vault>) {
    let mut pubs = Vec::new();
    let mut vaults = Vec::new();
    for (i, dir) in dirs.iter().enumerate() {
        let path = dir.path().join("guardian.pvf");
        let pwd = SecretBytes::new(format!("guardian {i} master pw").into_bytes());
        Vault::create(&path, &pwd).expect("create guardian vault");
        let mut v = Vault::open(&path).expect("open guardian vault");
        unlock(&mut v, format!("guardian {i} master pw").as_bytes());
        // Reconstruct the guardian's DeviceKey from the vault's own seed and
        // derive the SEALING pubkey the escrow seals share i to.
        let seed = v
            .device_key_secret_seed()
            .expect("active session exposes the device-key seed (test-utilities)");
        let device = DeviceKey::from_seed(*seed);
        let sealing_pub = *derive_x25519_sealing_key(&device).public_bytes();
        pubs.push(sealing_pub);
        vaults.push(v);
    }
    (pubs, vaults)
}

#[test]
#[allow(clippy::too_many_lines)] // the full lost-everything round-trip is one linear sequence
fn lost_everything_recovery_round_trips_through_composition() {
    // The guardian set: M guardian vaults, each opening its own sealed share.
    let g_dirs: Vec<tempfile::TempDir> =
        (0..M).map(|_| tempfile::TempDir::new().expect("tempdir")).collect();
    let (guardian_pubs, guardian_vaults) = guardian_vaults(&g_dirs);
    assert_eq!(guardian_pubs.len(), usize::from(M));

    // The "lost" vault's VDK V + its vault_id (these travel in the backup).
    let recovered_vdk = VdkKey::generate();
    let vault_id: [u8; VAULT_ID_LEN] = [0x5C; VAULT_ID_LEN];
    let current_epoch = 0u64;
    let config = GuardianSetConfig {
        threshold: T,
        guardian_count: M,
    };

    // Onboard a REAL escrow over V at the current epoch: a wrapped_recovery +
    // M sealed shares, each sealed to guardian i's sealing pubkey.
    let escrow = onboard_guardian_escrow(
        &recovered_vdk,
        &vault_id,
        config,
        &guardian_pubs,
        RecoveryEpoch(current_epoch),
    )
    .expect("onboard escrow");
    // The host-supplied backup material.
    let wrapped_recovery = escrow.wrapped_recovery;
    let roster = GuardianRoster {
        threshold: T,
        guardian_count: M,
        x25519_pubs: guardian_pubs.clone(),
    };
    let epoch_bytes = RecoveryEpoch(current_epoch).to_escrow_bytes();

    // Each of the first T guardians opens its sealed share through the PUBLIC
    // `Vault::guardian_open_sealed_share` method (the only secret out).
    let sealed_by_index: Vec<&SealedShare> =
        escrow.assignments.iter().map(|a| &a.sealed_share).collect();
    let mut opened_shares: Vec<Share> = Vec::new();
    for i in 0..usize::from(T) {
        let share = guardian_vaults[i]
            .guardian_open_sealed_share(sealed_by_index[i], &vault_id, &epoch_bytes)
            .expect("guardian opens its sealed share via the public method");
        opened_shares.push(share);
    }
    assert_eq!(opened_shares.len(), usize::from(T));

    // A FRESH (lost-everything) device: create + open a brand-new vault with a
    // placeholder password. It holds NO VDK (never recovered). recover_from_shares
    // takes the wrapped_recovery / roster / epoch / vault_id as HOST-SUPPLIED
    // params and pulls NOTHING from the session.
    let fresh_dir = tempfile::TempDir::new().expect("tempdir");
    let fresh_path = fresh_dir.path().join("recovered.pvf");
    Vault::create(&fresh_path, &SecretBytes::new(b"placeholder".to_vec())).expect("create fresh");
    let mut fresh = Vault::open(&fresh_path).expect("open fresh");

    let new_password = SecretBytes::new(b"post-recovery master password".to_vec());
    let outcome: RecoveryOutcome = recover_from_shares(
        &mut fresh,
        &wrapped_recovery,
        opened_shares,
        &roster,
        &new_password,
        current_epoch,
        vault_id,
    )
    .expect("recover_from_shares composition succeeds");

    // The re-split is tagged current_epoch + 1 (forward security).
    assert_eq!(
        outcome.new_epoch,
        current_epoch + 1,
        "the post-recovery re-split bumps the epoch"
    );
    // The commit leaves the vault Locked (the audited commit's posture).
    assert_eq!(
        fresh.state(),
        VaultState::Locked,
        "vault is Locked after the recovery commit"
    );

    // The OLD placeholder password no longer opens; the NEW password does —
    // the recovered VDK was re-wrapped under the new authority.
    let old_err = fresh
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(SecretBytes::new(b"placeholder".to_vec())),
        )
        .unwrap_err();
    assert!(
        matches!(old_err, pangolin_store::StoreError::AuthenticationFailed),
        "the pre-recovery password must stop opening the vault"
    );
    unlock(&mut fresh, b"post-recovery master password");
    assert_eq!(
        fresh.state(),
        VaultState::Active,
        "the NEW password opens the recovered vault"
    );

    // The recovered VDK is LIVE: a post-recovery write seals under it and
    // reads back across a lock/unlock cycle.
    let id = fresh.add_account(snapshot("recovered.example")).expect("add post-recovery");
    fresh.lock();
    unlock(&mut fresh, b"post-recovery master password");
    let read = fresh.get_account(id).expect("post-recovery account decrypts");
    assert!(
        bool::from(read.ct_eq(&snapshot("recovered.example"))),
        "the post-recovery write decrypts under the recovered VDK"
    );

    // The re-split escrow is persisted with the SAME guardian set, read back
    // through the NON-secret accessor (the active VDK opens it store-side; the
    // VDK never leaves the store). NOTE: `current_epoch` here is the VDK-CHAIN
    // epoch (unchanged by a recovery rekey — recovery bumps the recovery-escrow
    // generation epoch, not the VDK chain), so it stays at the genesis 0.
    let params = fresh
        .recovery_escrow_params()
        .expect("read escrow params")
        .expect("escrow present after recovery");
    assert_eq!(
        params.current_epoch, 0,
        "a recovery rekey does NOT advance the VDK-chain epoch (only the escrow generation)"
    );
    assert_eq!(params.guardian_count, M);
    assert_eq!(params.threshold, T);
    assert_eq!(params.guardian_x25519_pubs.len(), usize::from(M));
    // The same guardian sealing pubkeys were re-sealed to (SAME set, R-e).
    let mut got = params.guardian_x25519_pubs;
    let mut want = guardian_pubs;
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want, "the re-split re-seals to the SAME guardian set");
}

#[test]
fn recover_from_shares_rejects_below_threshold() {
    let g_dirs: Vec<tempfile::TempDir> =
        (0..M).map(|_| tempfile::TempDir::new().expect("tempdir")).collect();
    let (guardian_pubs, guardian_vaults) = guardian_vaults(&g_dirs);

    let recovered_vdk = VdkKey::generate();
    let vault_id: [u8; VAULT_ID_LEN] = [0x77; VAULT_ID_LEN];
    let config = GuardianSetConfig {
        threshold: T,
        guardian_count: M,
    };
    let escrow = onboard_guardian_escrow(
        &recovered_vdk,
        &vault_id,
        config,
        &guardian_pubs,
        RecoveryEpoch(0),
    )
    .expect("onboard escrow");
    let epoch_bytes = RecoveryEpoch(0).to_escrow_bytes();

    // Only ONE share (< T) — recovery must fail with InsufficientShares and
    // commit NOTHING.
    let one = guardian_vaults[0]
        .guardian_open_sealed_share(&escrow.assignments[0].sealed_share, &vault_id, &epoch_bytes)
        .expect("open one share");

    let fresh_dir = tempfile::TempDir::new().expect("tempdir");
    let fresh_path = fresh_dir.path().join("recovered.pvf");
    Vault::create(&fresh_path, &SecretBytes::new(b"placeholder".to_vec())).expect("create fresh");
    let mut fresh = Vault::open(&fresh_path).expect("open fresh");

    let roster = GuardianRoster {
        threshold: T,
        guardian_count: M,
        x25519_pubs: guardian_pubs,
    };
    let err = recover_from_shares(
        &mut fresh,
        &escrow.wrapped_recovery,
        vec![one],
        &roster,
        &SecretBytes::new(b"new pw".to_vec()),
        0,
        vault_id,
    )
    .expect_err("recovery with < t shares must fail");
    assert!(
        matches!(
            err,
            pangolin_core::composition::CompositionError::Recovery(
                pangolin_core::recovery::orchestration::RecoveryOrchestrationError::InsufficientShares { .. }
            )
        ),
        "below-threshold recovery surfaces InsufficientShares, got {err:?}"
    );
    // The placeholder password STILL opens — nothing was committed.
    unlock(&mut fresh, b"placeholder");
    assert_eq!(
        fresh.state(),
        VaultState::Active,
        "a failed recovery commits nothing"
    );
}

#[test]
fn guardian_open_rejects_wrong_epoch() {
    // A guardian opening a share with the WRONG epoch context fails closed
    // (the bound vault_id/epoch header mismatches) — the indistinguishability
    // collapse to AuthenticationFailed.
    let g_dirs: Vec<tempfile::TempDir> =
        (0..M).map(|_| tempfile::TempDir::new().expect("tempdir")).collect();
    let (guardian_pubs, guardian_vaults) = guardian_vaults(&g_dirs);

    let vdk = VdkKey::generate();
    let vault_id: [u8; VAULT_ID_LEN] = [0x9A; VAULT_ID_LEN];
    let escrow = onboard_guardian_escrow(
        &vdk,
        &vault_id,
        GuardianSetConfig {
            threshold: T,
            guardian_count: M,
        },
        &guardian_pubs,
        RecoveryEpoch(0),
    )
    .expect("onboard escrow");

    // Correct epoch opens.
    let correct = RecoveryEpoch(0).to_escrow_bytes();
    guardian_vaults[0]
        .guardian_open_sealed_share(&escrow.assignments[0].sealed_share, &vault_id, &correct)
        .expect("correct epoch opens");

    // Wrong epoch fails closed.
    let wrong = RecoveryEpoch(7).to_escrow_bytes();
    let err = guardian_vaults[0]
        .guardian_open_sealed_share(&escrow.assignments[0].sealed_share, &vault_id, &wrong)
        .unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "a wrong-epoch open fails closed, got {err:?}"
    );
}
