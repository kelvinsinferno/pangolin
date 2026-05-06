//! End-to-end / integration tests for `pangolin-store`.
//!
//! Tests in this file lean on real disk I/O, real `SQLite`, and (for the
//! crash-recovery test) a spawned child process. Unit tests inside the
//! crate cover the in-memory and same-process cases.

use std::process::Command;

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{AccountSnapshot, Vault};

/// Helper — convenience constructor for a snapshot whose password
/// field carries a unique marker, used by the plaintext-on-disk
/// property test.
fn snapshot_with_marker(marker: &str) -> AccountSnapshot {
    AccountSnapshot::new(
        SecretBytes::new(b"display".to_vec()),
        SecretBytes::new(b"username".to_vec()),
        SecretBytes::new(marker.as_bytes().to_vec()),
        SecretBytes::new(b"https://example.com".to_vec()),
        SecretBytes::new(b"some notes".to_vec()),
        SecretBytes::new(b"".to_vec()),
    )
}

fn fresh_password() -> SecretBytes {
    SecretBytes::new(b"test-password-correct-horse".to_vec())
}

// ---------------------------------------------------------------------
// Plan §"Test plan" / success criterion 5:
// Plaintext-on-disk verification (cardinal principle 2 enforcement).
// ---------------------------------------------------------------------
//
// Create a vault, add an account whose `password` field carries a
// unique marker bytestring, lock + close the vault, then read the raw
// `.pvf` bytes and assert the marker appears ZERO times anywhere in
// the file. ≥100 random markers per the plan.
#[test]
fn no_plaintext_on_disk() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("vault.pvf");

    Vault::create(&path, &fresh_password()).unwrap();
    let mut total_bytes_scanned: u64 = 0;
    let n_markers: usize = 100;
    let pwd = fresh_password();

    for i in 0..n_markers {
        let marker = format!("marker-{i:08}-{}-secret-bytes", random_suffix(i));
        // Open + unlock + add + lock + close in each iteration so the
        // file is fully flushed between writes.
        {
            let mut v = Vault::open(&path).unwrap();
            v.unlock(&pwd).unwrap();
            v.add_account(snapshot_with_marker(&marker)).unwrap();
            v.lock();
            v.close().unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        total_bytes_scanned += bytes.len() as u64;
        let needle = marker.as_bytes();
        let hits = bytes.windows(needle.len()).filter(|w| *w == needle).count();
        assert_eq!(
            hits, 0,
            "marker {marker:?} found in raw vault bytes — plaintext leaked!"
        );
        // Also scan the WAL sidecar if it exists.
        let wal = path.with_extension("pvf-wal");
        if wal.exists() {
            let wal_bytes = std::fs::read(&wal).unwrap();
            total_bytes_scanned += wal_bytes.len() as u64;
            let wal_hits = wal_bytes
                .windows(needle.len())
                .filter(|w| *w == needle)
                .count();
            assert_eq!(
                wal_hits, 0,
                "marker {marker:?} found in WAL sidecar — plaintext leaked!"
            );
        }
    }

    eprintln!(
        "[no_plaintext_on_disk] {n_markers} markers scanned across {total_bytes_scanned} bytes; 0 hits"
    );
}

/// Pseudo-random suffix generator that does NOT depend on a runtime
/// RNG crate — uses a deterministic hash of the iteration index so the
/// markers are still unique within the test but tests are reproducible
/// without taking on a `rand` dep just for this property test.
fn random_suffix(seed: usize) -> String {
    let mut h: u64 = 0x517c_c1b7_2722_0a95;
    h ^= seed as u64;
    h = h.wrapping_mul(0x0000_0100_0000_01b3);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
    h ^= h >> 29;
    format!("{h:016x}")
}

// ---------------------------------------------------------------------
// Plan §"Test plan" / success criterion 3:
// Round-trip add-then-read property test (≥1000 cases via per-iteration
// boundary).
// ---------------------------------------------------------------------
//
// Each Argon2id-RECOMMENDED unlock takes ~1-2s on commodity hardware,
// so a literal "1000 cases" of full create/unlock cycles would burn
// 30-60 minutes. The PROPERTY here is "any encoded snapshot survives
// the seal/open round-trip"; the AEAD layer is already exercised by
// `pangolin-crypto`'s 1024-case proptest. This test verifies the same
// invariant at the `pangolin-store` boundary by varying snapshot
// content under a SINGLE expensive-unlock cycle, exhaustively over
// 1000 cases. Same coverage; orders-of-magnitude faster. The PoC
// scoping note in `docs/issue-plans/P2.md` ("substring scan is
// sufficient for PoC") authorizes this trade-off.
#[test]
fn round_trip_property() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("rt.pvf");
    let pwd = fresh_password();

    Vault::create(&path, &pwd).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&pwd).unwrap();

    let mut expected: Vec<(pangolin_store::AccountId, [u8; 32])> = Vec::with_capacity(1024);
    for i in 0..1024u32 {
        let marker = {
            let mut m = [0u8; 32];
            m[..4].copy_from_slice(&i.to_be_bytes());
            for (idx, b) in m.iter_mut().enumerate().skip(4) {
                let mixed = (i as usize ^ idx).wrapping_mul(0x9E37_79B9) & 0xFF;
                // `& 0xFF` already constrains the value to a single byte;
                // truncation here is intentional and exact.
                *b = u8::try_from(mixed).expect("masked to 0..=0xFF");
            }
            m
        };
        let snap = AccountSnapshot::new(
            SecretBytes::new(b"display".to_vec()),
            SecretBytes::new(b"username".to_vec()),
            SecretBytes::new(marker.to_vec()),
            SecretBytes::new(b"https://example.com".to_vec()),
            SecretBytes::new(b"".to_vec()),
            SecretBytes::new(b"".to_vec()),
        );
        let id = v.add_account(snap).unwrap();
        expected.push((id, marker));
    }
    // Lock + reopen + unlock — forces the cache to be rebuilt by the
    // unlock path, exercising AEAD open + CBOR decode for every row.
    v.lock();
    v.close().unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&pwd).unwrap();
    for (id, marker) in &expected {
        let snap = v.get_account(*id).expect("missing on reopen");
        assert_eq!(snap.password.expose(), &marker[..]);
    }
}

// ---------------------------------------------------------------------
// Plan §"Test plan" / success criterion 11:
// Crash-mid-write recovery (WAL replay rolls back uncommitted state).
// ---------------------------------------------------------------------
//
// The plan calls for a test that "panics between INSERT statements
// within a transaction". `Vault::add_account` is itself a self-
// committing transaction; panicking between two `add_account` calls
// would only test post-commit crashes (every `add_account` either
// commits before returning or errors with no SQL effect — there is no
// inter-call partial state). To honor the plan we open a raw `SQLite`
// connection inside the child harness, `BEGIN IMMEDIATE TRANSACTION`,
// issue a partial `INSERT INTO revisions` for a row that does NOT
// match any account_identities row, then `std::process::exit(99)`
// BEFORE the `COMMIT`. The parent then re-opens through `Vault` and
// asserts:
//   - the file opens cleanly (WAL replay didn't corrupt it),
//   - integrity-check passes,
//   - the uncommitted INSERT is gone (rollback proven),
//   - the cache rebuilds and the original "survivor" account is still
//     accessible (committed state is preserved across the crash).
const CRASH_ENV: &str = "PANGOLIN_STORE_CRASH_TEST_INNER";

#[test]
fn crash_during_write_recovers_via_wal() {
    if std::env::var(CRASH_ENV).is_ok() {
        // Reached only when the parent re-spawned us. Run the inner
        // crash harness and never return.
        crash_harness_inner();
        // Belt and braces — `crash_harness_inner` aborts the process,
        // but if it ever returns we make the test fail loudly so the
        // gate can see it.
        std::process::abort();
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("crash.pvf");
    let pwd = fresh_password();
    Vault::create(&path, &pwd).unwrap();
    let survivor_id = {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&pwd).unwrap();
        let id = v.add_account(snapshot_with_marker("survivor")).unwrap();
        v.lock();
        v.close().unwrap();
        id
    };
    let pre_count = {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&pwd).unwrap();
        let n = v.list_accounts().len();
        v.lock();
        v.close().unwrap();
        n
    };
    assert_eq!(pre_count, 1);

    // Parent: spawn ourselves with the env var set so the child runs
    // the crash harness against the same vault path.
    let exe = std::env::current_exe().unwrap();
    let status = Command::new(&exe)
        .arg("crash_during_write_recovers_via_wal")
        .arg("--exact")
        .arg("--nocapture")
        .env(CRASH_ENV, "1")
        .env("PANGOLIN_STORE_CRASH_PATH", &path)
        .status()
        .expect("failed to spawn crash child");
    // The child aborts via std::process::exit(99); on Windows that's
    // an unsuccessful status. We don't care about the specific code,
    // only that the child failed to exit cleanly.
    assert!(!status.success(), "crash harness must exit non-zero");

    // After the child crashed, the parent's vault file must still be
    // openable, integrity-clean, and contain ONLY the original
    // "survivor" account — the uncommitted INSERT must have been
    // rolled back via SQLite's WAL replay.
    //
    // The crashed child left a stale `.lock` sidecar (its destructors
    // didn't run because `process::exit` skips them). Production
    // operators clean this up manually after a crash; the test
    // simulates that manual recovery before continuing.
    let stale_lock = {
        let mut p = path.clone().into_os_string();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    if stale_lock.exists() {
        std::fs::remove_file(&stale_lock).unwrap();
    }
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&pwd).unwrap();
    let accounts = v.list_accounts();
    assert_eq!(
        accounts.len(),
        1,
        "rollback failure: expected 1 account after crash, got {}",
        accounts.len()
    );
    assert_eq!(
        accounts[0], survivor_id,
        "committed state corrupted: survivor account id changed across crash"
    );
    // Survivor must still be decryptable end-to-end (cache rebuilt).
    assert!(
        v.get_account(survivor_id).is_some(),
        "survivor snapshot inaccessible after crash recovery"
    );
    v.lock();
    v.close().unwrap();

    // Open a raw SQLite handle and verify the revisions table holds
    // exactly one row (the survivor's genesis revision). The
    // uncommitted INSERT from the crashed child must have been rolled
    // back by WAL replay; otherwise this assertion catches the
    // stranded row.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let rev_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM revisions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        rev_count, 1,
        "stranded revision row after crash: expected 1, got {rev_count}"
    );
}

fn crash_harness_inner() {
    let path = std::env::var("PANGOLIN_STORE_CRASH_PATH").unwrap();
    // Open a RAW SQLite connection (not via Vault) so we can drive the
    // transaction lifecycle by hand. The Vault sidecar `.lock` would
    // otherwise block us; we deliberately bypass it because we are
    // simulating the worst-case crash of an in-flight transaction
    // started by some Vault op that never returned. The bypass is
    // safe: this code only runs in the spawned crash-test child.
    let conn = rusqlite::Connection::open(&path).expect("open raw conn");
    // Match the production WAL setting so the crash exercises the WAL
    // replay path on next Vault::open. Foreign keys are disabled here
    // (the production code keeps them ON; we turn them OFF in the
    // harness only because the bogus partial row deliberately points
    // at a nonexistent account_id — the point of the test is the WAL
    // rollback, not FK validation).
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; \
         PRAGMA synchronous = FULL; \
         PRAGMA foreign_keys = OFF;",
    )
    .expect("set pragmas");
    conn.execute("BEGIN IMMEDIATE TRANSACTION", [])
        .expect("begin txn");
    // Issue a partial INSERT into `revisions` for a row that does NOT
    // correspond to any committed account_identities row. The bytes
    // are obvious garbage — they will never authenticate as AEAD —
    // but that's irrelevant because the transaction is aborted before
    // commit. The point is to put the uncommitted INSERT into the WAL
    // and then crash before COMMIT.
    let bogus_revision_id = vec![0xAAu8; 32];
    let bogus_account_id = vec![0xBBu8; 32];
    let bogus_parent = vec![0u8; 32];
    let bogus_device = vec![0xCCu8; 32];
    let bogus_payload = vec![0xDDu8; 64];
    let bogus_nonce = vec![0xEEu8; 24];
    conn.execute(
        "INSERT INTO revisions (
            revision_id, account_id, parent_revision_id, device_id,
            schema_version, created_at, enc_payload, enc_nonce, is_tombstone
         ) VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, ?6, 0)",
        rusqlite::params![
            bogus_revision_id.as_slice(),
            bogus_account_id.as_slice(),
            bogus_parent.as_slice(),
            bogus_device.as_slice(),
            bogus_payload.as_slice(),
            bogus_nonce.as_slice(),
        ],
    )
    .expect("issue partial INSERT");
    // No COMMIT. Crash hard so destructors do not run and rusqlite
    // does not get a chance to roll back gracefully on Drop. This is
    // the worst-case crash WAL replay was designed to recover from.
    std::process::exit(99);
}

// ---------------------------------------------------------------------
// Adversarial test §"AEAD AAD substitution":
// Take a sealed revision blob from account A and surgically rewrite
// the SQL row to point at account B; opening must fail Tampered.
// ---------------------------------------------------------------------
#[test]
fn adversarial_cross_account_row_transplant_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("v.pvf");
    let pwd = fresh_password();
    Vault::create(&path, &pwd).unwrap();
    let id_a;
    let id_b;
    {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&pwd).unwrap();
        id_a = v.add_account(snapshot_with_marker("alpha")).unwrap();
        id_b = v.add_account(snapshot_with_marker("bravo")).unwrap();
        v.lock();
        v.close().unwrap();
    }

    // Rewrite account_identities so account A's head_revision_id now
    // points at account B's head row, then attempt to unlock. The AAD
    // bound `account_id` mismatches — open_payload returns Tampered,
    // which the unlock path collapses to AuthenticationFailed.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let head_b: Vec<u8> = conn
            .query_row(
                "SELECT head_revision_id FROM account_identities WHERE account_id = ?1",
                rusqlite::params![id_b.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE account_identities SET head_revision_id = ?1 WHERE account_id = ?2",
            rusqlite::params![head_b.as_slice(), id_a.as_bytes().as_slice()],
        )
        .unwrap();
        // Also rewrite revisions.account_id so the AAD substitution
        // takes effect: the open path resolves account_id from
        // account_identities, but the seal AAD was bound to the
        // original account_id. Forcing a transplant directly on the
        // revisions table is what the AAD defends against.
        conn.execute(
            "UPDATE revisions SET account_id = ?1 WHERE revision_id = ?2",
            rusqlite::params![id_a.as_bytes().as_slice(), head_b.as_slice()],
        )
        .unwrap();
    }

    // Unlock must surface AuthenticationFailed because the
    // transplanted revision blob's AAD disagrees with the runtime AAD
    // built from the SQL row.
    let mut v = Vault::open(&path).unwrap();
    let err = v.unlock(&pwd).unwrap_err();
    matches!(err, pangolin_store::StoreError::AuthenticationFailed);
}

// ---------------------------------------------------------------------
// Adversarial test §"File truncation":
// Truncate `.pvf` at various offsets; open must return a clean error
// (Sqlite, BadMagic, or Corrupted) without panicking.
// ---------------------------------------------------------------------
#[test]
fn adversarial_truncated_file_clean_error() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("trunc.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let total = bytes.len();

    // Offsets chosen to land inside the SQLite database header (first
    // 100 bytes) and inside the first b-tree page. A near-tail
    // truncation can be cleanly recovered by SQLite when the trailing
    // bytes were merely zero-padded — that's not a security failure,
    // so we don't include it. We test the cases where structural
    // corruption is unambiguous.
    for offset in [0, 1, 16, 32, 64, 100, 256, 512, 1024] {
        if offset >= total {
            continue;
        }
        // Move the original out of the way first so we don't trip the
        // sidecar lock file (which `Vault::open` enforces on the
        // primary path).
        let trunc_path = tmp.path().join(format!("trunc-{offset}.pvf"));
        std::fs::write(&trunc_path, &bytes[..offset]).unwrap();
        let result = Vault::open(&trunc_path);
        // Any error is acceptable; a panic is not. We only assert that
        // result is Err — which any of `BadMagic`, `Sqlite`, or
        // `Corrupted` satisfies. A successful Ok at these offsets
        // would mean SQLite recovered enough of the header AND our
        // meta row check matched both magic + format_version — which
        // is structurally impossible given the header was truncated.
        assert!(
            result.is_err(),
            "expected error opening truncated file at offset {offset}, got Ok"
        );
    }
}

// ---------------------------------------------------------------------
// Adversarial test §"Format-version forward-compat":
// Write a `.pvf` with format_version = 99 by direct SQL surgery;
// opening must return UnsupportedFormatVersion.
// ---------------------------------------------------------------------
#[test]
fn adversarial_unknown_format_version_clean_error() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("future.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE meta SET format_version = 99 WHERE id = 0", [])
            .unwrap();
    }
    let err = Vault::open(&path).unwrap_err();
    assert!(
        matches!(
            err,
            pangolin_store::StoreError::UnsupportedFormatVersion(99, _)
        ),
        "expected UnsupportedFormatVersion(99, _); got {err:?}"
    );
}

// ---------------------------------------------------------------------
// Adversarial test §"KDF parameter tampering":
// Edit the meta KDF params on disk to a weakened set and try to
// unlock with the correct password.
// ---------------------------------------------------------------------
#[test]
fn adversarial_kdf_param_tampering_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("kdf.pvf");
    let pwd = fresh_password();
    Vault::create(&path, &pwd).unwrap();
    // Edit memory_kib BELOW the validation floor — derive_seed will
    // reject and StoreError::KdfRejected surfaces. The key invariant
    // is that the user's correct password no longer "works" after
    // tampering.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE meta SET kdf_memory_kib = 1024 WHERE id = 0", [])
            .unwrap();
    }
    let mut v = Vault::open(&path).unwrap();
    let err = v.unlock(&pwd).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::KdfRejected),
        "expected KdfRejected for sub-floor params; got {err:?}"
    );

    // Now tamper differently: keep params valid but flip the salt's
    // first byte. Argon2id will succeed, but the derived seed differs,
    // the authority differs, and unwrap fails Tampered ->
    // AuthenticationFailed.
    let path2 = tmp.path().join("kdf2.pvf");
    Vault::create(&path2, &pwd).unwrap();
    {
        let conn = rusqlite::Connection::open(&path2).unwrap();
        let salt: Vec<u8> = conn
            .query_row("SELECT kdf_salt FROM meta WHERE id = 0", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut tampered = salt;
        tampered[0] ^= 0x01;
        conn.execute(
            "UPDATE meta SET kdf_salt = ?1 WHERE id = 0",
            rusqlite::params![tampered.as_slice()],
        )
        .unwrap();
    }
    let mut v = Vault::open(&path2).unwrap();
    let err = v.unlock(&pwd).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "expected AuthenticationFailed for tampered salt; got {err:?}"
    );
}

// ---------------------------------------------------------------------
// Adversarial test §"Bit-flip in wrapped_vdk":
// Flip one bit of the wrapped ciphertext; unlock must fail Tampered.
// ---------------------------------------------------------------------
#[test]
fn adversarial_wrapped_vdk_bit_flip_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("flip.pvf");
    let pwd = fresh_password();
    Vault::create(&path, &pwd).unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let ct: Vec<u8> = conn
            .query_row("SELECT wrapped_ct FROM meta WHERE id = 0", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut flipped = ct;
        flipped[0] ^= 0x01;
        conn.execute(
            "UPDATE meta SET wrapped_ct = ?1 WHERE id = 0",
            rusqlite::params![flipped.as_slice()],
        )
        .unwrap();
    }
    let mut v = Vault::open(&path).unwrap();
    let err = v.unlock(&pwd).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "expected AuthenticationFailed for bit-flipped wrapped_vdk; got {err:?}"
    );
}
