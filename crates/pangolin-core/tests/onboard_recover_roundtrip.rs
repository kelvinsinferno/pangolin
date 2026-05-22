// SPDX-License-Identifier: AGPL-3.0-or-later
//! #106e-0b L5 HERMETIC round-trip — prove a vault onboarded via the
//! PRODUCTION `Vault::onboard_guardians` produces a RECONSTRUCTABLE escrow:
//!
//! ```text
//! Vault::onboard_guardians(t, &guardian_pubs) — production escrow set-up
//! recovery_escrow_params()                    — reads back (t, M) + pubs
//! Vault::guardian_open_sealed_share x t        — each guardian opens its share
//! composition::recover_from_shares             — reconstruct VDK, re-split, commit
//! the recovered VDK opens the (recovered) vault — proves reconstructability
//! ```
//!
//! This mirrors `composition_recovery.rs` but SEEDS the escrow with the
//! production onboard instead of the test-only `__test_onboard_recovery_escrow`
//! / the pure `onboard_guardian_escrow` driver — closing the loop that
//! #106e-0b opens: an escrow CREATED by production code is recoverable by the
//! merged recovery composition. No anvil / no chain — hermetic.

use pangolin_core::composition::{recover_from_shares, GuardianRoster, RecoveryOutcome};
use pangolin_crypto::escrow::Share;
use pangolin_crypto::guardian::derive_x25519_sealing_key;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{
    AccountSnapshot, PinIdentityProof, PressYPresenceProof, Vault, VaultState,
};

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
fn guardian_vaults(dirs: &[tempfile::TempDir]) -> (Vec<[u8; 32]>, Vec<Vault>) {
    let mut pubs = Vec::new();
    let mut vaults = Vec::new();
    for (i, dir) in dirs.iter().enumerate() {
        let path = dir.path().join("guardian.pvf");
        let pwd = SecretBytes::new(format!("guardian {i} master pw").into_bytes());
        Vault::create(&path, &pwd).expect("create guardian vault");
        let mut v = Vault::open(&path).expect("open guardian vault");
        unlock(&mut v, format!("guardian {i} master pw").as_bytes());
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
#[allow(clippy::too_many_lines)] // the full production onboard -> recover round-trip is one linear sequence
fn production_onboard_then_recover_round_trips() {
    // The guardian set: M guardian vaults, each opening its own sealed share.
    let g_dirs: Vec<tempfile::TempDir> = (0..M)
        .map(|_| tempfile::TempDir::new().expect("tempdir"))
        .collect();
    let (guardian_pubs, guardian_vaults) = guardian_vaults(&g_dirs);
    assert_eq!(guardian_pubs.len(), usize::from(M));

    // The vault to onboard: create + unlock so it has a real, live VDK.
    let owner_dir = tempfile::TempDir::new().expect("tempdir");
    let owner_path = owner_dir.path().join("owner.pvf");
    Vault::create(&owner_path, &SecretBytes::new(b"owner master password".to_vec()))
        .expect("create owner vault");
    let mut owner = Vault::open(&owner_path).expect("open owner vault");
    unlock(&mut owner, b"owner master password");

    // Seed a pre-onboard account so we can prove the recovered VDK decrypts
    // the SAME data (byte-identical VDK, L3 / L5).
    let pre_id = owner.add_account(snapshot("pre-onboard.example")).expect("add pre-onboard");

    // PRODUCTION onboard — set up social recovery on the owner vault. This is
    // the surface #106e-0b builds: it reads the active VDK store-internal,
    // mints the escrow, and persists it under the active VDK's column-AEAD.
    let outcome = owner
        .onboard_guardians(T, &guardian_pubs)
        .expect("production onboard_guardians succeeds");
    // Q-c: the first onboard writes at GENESIS (0).
    assert_eq!(outcome.epoch, 0, "first onboard writes at genesis epoch");

    // `recovery_escrow_params` reads back the right (t, M) + the SAME guardian
    // sealing pubkeys (the non-secret accessor; the VDK never leaves the store).
    let params = owner
        .recovery_escrow_params()
        .expect("read escrow params")
        .expect("escrow present after production onboard");
    assert_eq!(params.threshold, T);
    assert_eq!(params.guardian_count, M);
    assert_eq!(params.guardian_x25519_pubs.len(), usize::from(M));
    let mut got = params.guardian_x25519_pubs.clone();
    let mut want = guardian_pubs.clone();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want, "params return the SAME guardian set the onboard sealed to");
    let current_epoch = params.current_epoch;

    // The host-supplied backup material: the non-secret wrapped_recovery + the
    // M sealed shares the production onboard wrote to disk (in production this
    // lives in the user's recovery backup + the guardians' custody; here we
    // read it back to drive the lost-everything path).
    let owner_vault_id = owner.vault_id();
    let (wrapped_recovery, sealed_shares) = owner
        .__test_recovery_backup_material()
        .expect("read recovery backup material")
        .expect("escrow backup present after onboard");
    assert_eq!(sealed_shares.len(), usize::from(M));

    // Each of the first T guardians opens its sealed share via the public
    // method — the escrow being opened is the PRODUCTION one.
    let roster = GuardianRoster {
        threshold: T,
        guardian_count: M,
        x25519_pubs: guardian_pubs.clone(),
    };
    let escrow_epoch =
        pangolin_core::recovery::orchestration::RecoveryEpoch(current_epoch).to_escrow_bytes();

    let mut opened_shares: Vec<Share> = Vec::new();
    for i in 0..usize::from(T) {
        let share = guardian_vaults[i]
            .guardian_open_sealed_share(&sealed_shares[i], &owner_vault_id, &escrow_epoch)
            .expect("guardian opens its production-sealed share");
        opened_shares.push(share);
    }
    assert_eq!(opened_shares.len(), usize::from(T));

    // LOST-EVERYTHING: the user lost their session/password but still holds
    // the (encrypted) vault file + the backup material + can reach >= t
    // guardians. Simulate by LOCKING the owner vault (no active session) and
    // recovering it IN PLACE — the recovered VDK re-keys the SAME file, so the
    // pre-onboard account (whose ciphertext lives in this file, sealed under
    // the original VDK) must decrypt afterward iff the recovered VDK is the
    // byte-identical original. (A separate blank vault would have no account
    // ciphertext to decrypt, so this is the only faithful byte-identity proof.)
    owner.lock();
    assert_eq!(owner.state(), VaultState::Locked);

    let new_password = SecretBytes::new(b"post-recovery master password".to_vec());
    let recovery: RecoveryOutcome = recover_from_shares(
        &mut owner,
        &wrapped_recovery,
        opened_shares,
        &roster,
        &new_password,
        current_epoch,
        owner_vault_id,
    )
    .expect("recover_from_shares from a PRODUCTION-onboarded escrow succeeds");

    // The re-split bumped the escrow generation (forward security).
    assert_eq!(
        recovery.new_epoch,
        current_epoch + 1,
        "the post-recovery re-split bumps the escrow epoch"
    );
    assert_eq!(
        owner.state(),
        VaultState::Locked,
        "vault is Locked after the recovery commit"
    );

    // The recovered VDK is LIVE: the NEW password (NOT the original) opens the
    // recovered vault.
    let old_err = owner
        .unlock(
            &PressYPresenceProof::confirmed(),
            &PinIdentityProof::new(SecretBytes::new(b"owner master password".to_vec())),
        )
        .unwrap_err();
    assert!(
        matches!(old_err, pangolin_store::StoreError::AuthenticationFailed),
        "the pre-recovery password must stop opening the vault"
    );
    unlock(&mut owner, b"post-recovery master password");
    assert_eq!(
        owner.state(),
        VaultState::Active,
        "the NEW password opens the recovered vault"
    );

    // The recovered VDK is byte-identical to the original: the pre-onboard
    // account written under the original VDK decrypts under the recovered one
    // (the catastrophic L5 check — production onboard produces a reconstructable
    // escrow whose recovered VDK is the SAME key).
    let read = owner.get_account(pre_id).expect("pre-onboard account decrypts post-recovery");
    assert!(
        bool::from(read.ct_eq(&snapshot("pre-onboard.example"))),
        "the pre-onboard write decrypts under the recovered VDK (byte-identical, L5)"
    );

    // And the recovered vault is fully usable for fresh writes across a cycle.
    let post_id = owner.add_account(snapshot("post-recovery.example")).expect("add post-recovery");
    owner.lock();
    unlock(&mut owner, b"post-recovery master password");
    let post = owner.get_account(post_id).expect("post-recovery account decrypts");
    assert!(
        bool::from(post.ct_eq(&snapshot("post-recovery.example"))),
        "the recovered vault accepts and reads back fresh writes"
    );
}
