//! End-to-end / integration tests for `pangolin-store`.
//!
//! Tests in this file lean on real disk I/O, real `SQLite`, and (for the
//! crash-recovery test) a spawned child process. Unit tests inside the
//! crate cover the in-memory and same-process cases.

use std::process::Command;

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{
    AccountIdentityDraft, AccountIdentityPatch, AccountSnapshot, PinIdentityProof,
    PressYPresenceProof, StoreError, Vault, ACCOUNT_IDENTITY_SCHEMA_VERSION,
};

/// Build a fresh `PinIdentityProof` from `fresh_password()`. P4
/// session-policy: every unlock requires both a presence proof and an
/// identity proof, so e2e tests construct proofs at each call site.
/// The original P2 single-password signature is gone; this helper
/// keeps the call sites compact.
fn fresh_pin() -> PinIdentityProof {
    PinIdentityProof::new(fresh_password())
}

/// Build a fresh `PressYPresenceProof` ("user pressed y").
/// `PoC` proofs are single-use, so each `unlock` call gets its own.
fn fresh_presence() -> PressYPresenceProof {
    PressYPresenceProof::confirmed()
}

/// Helper — convenience constructor for a snapshot whose password
/// field carries a unique marker, used by the plaintext-on-disk
/// property test (legacy; prefer [`snapshot_with_per_field_markers`]).
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

/// MEDIUM-3 (P2 audit): place a unique marker in EVERY secret-bearing
/// field so the cardinal-principle-2 verifier scans for leaks across
/// `display_name`, `username`, `password`, `url`, `notes`, AND
/// `totp_secret` rather than just `password`. A regression that, e.g.,
/// started persisting `display_name` outside the AEAD-sealed payload
/// would be caught by the same scan.
fn snapshot_with_per_field_markers(seed: &str) -> [String; 6] {
    [
        format!("display-{seed}-secret-bytes"),
        format!("user-{seed}-secret-bytes"),
        format!("pwd-{seed}-secret-bytes"),
        format!("url-{seed}-secret-bytes"),
        format!("notes-{seed}-secret-bytes"),
        format!("totp-{seed}-secret-bytes"),
    ]
}

fn snapshot_from_markers(markers: &[String; 6]) -> AccountSnapshot {
    AccountSnapshot::new(
        SecretBytes::new(markers[0].as_bytes().to_vec()),
        SecretBytes::new(markers[1].as_bytes().to_vec()),
        SecretBytes::new(markers[2].as_bytes().to_vec()),
        SecretBytes::new(markers[3].as_bytes().to_vec()),
        SecretBytes::new(markers[4].as_bytes().to_vec()),
        SecretBytes::new(markers[5].as_bytes().to_vec()),
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
// Create a vault, add an account with a unique marker in EACH of its
// six secret-bearing fields, lock + close the vault, then read the raw
// `.pvf` bytes and assert NO marker appears anywhere in the file.
// ≥100 random markers per the plan; MEDIUM-3 (P2 audit) extends the
// per-iteration coverage from "just password" to all six fields:
// display_name, username, password, url, notes, totp_secret.
#[test]
fn no_plaintext_on_disk() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("vault.pvf");

    Vault::create(&path, &fresh_password()).unwrap();

    // MVP-1 issue 1.5 criterion 5: the device key's secret seed is
    // AEAD-sealed under the VDK in the `device_key` table — it must
    // NOT appear in plaintext in the raw `.pvf`. The first unlock
    // registers the device + writes the sealed seed; grab the seed
    // bytes here (via the test-only accessor) and add them to the
    // marker set scanned in every iteration below. Sub-slices of the
    // 32-byte seed are also scanned (an 8-byte window) so even a
    // partial leak would be caught.
    let device_key_seed: [u8; 32] = {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let seed = *v
            .device_key_secret_seed()
            .expect("device key present after unlock");
        v.lock();
        v.close().unwrap();
        seed
    };

    let mut total_bytes_scanned: u64 = 0;
    let n_iterations: usize = 100;

    let scan_for_device_key = |bytes: &[u8], where_: &str| {
        // Full 32-byte seed.
        let full_hits = bytes
            .windows(device_key_seed.len())
            .filter(|w| *w == device_key_seed.as_slice())
            .count();
        assert_eq!(
            full_hits, 0,
            "device-key seed bytes found in {where_} — plaintext leaked! \
             (issue 1.5 criterion 5 violation)",
        );
        // 8-byte sub-windows of the seed — a partial leak still fails.
        for w8 in device_key_seed.windows(8) {
            let hits = bytes.windows(8).filter(|w| *w == w8).count();
            assert_eq!(
                hits, 0,
                "8-byte slice of the device-key seed found in {where_} — plaintext leaked! \
                 (issue 1.5 criterion 5 violation)",
            );
        }
    };

    for i in 0..n_iterations {
        let seed = format!("{i:08}-{}", random_suffix(i));
        let markers = snapshot_with_per_field_markers(&seed);
        // Open + unlock + add + lock + close in each iteration so the
        // file is fully flushed between writes.
        {
            let mut v = Vault::open(&path).unwrap();
            v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
            v.add_account(snapshot_from_markers(&markers)).unwrap();
            v.lock();
            v.close().unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        total_bytes_scanned += bytes.len() as u64;
        for marker in &markers {
            let needle = marker.as_bytes();
            let hits = bytes.windows(needle.len()).filter(|w| *w == needle).count();
            assert_eq!(
                hits, 0,
                "marker {marker:?} found in raw vault bytes — plaintext leaked! \
                 (cardinal principle 2 violation; iteration {i})",
            );
        }
        scan_for_device_key(&bytes, "raw vault bytes");
        // Also scan the WAL sidecar if it exists.
        let wal = path.with_extension("pvf-wal");
        if wal.exists() {
            let wal_bytes = std::fs::read(&wal).unwrap();
            total_bytes_scanned += wal_bytes.len() as u64;
            for marker in &markers {
                let needle = marker.as_bytes();
                let wal_hits = wal_bytes
                    .windows(needle.len())
                    .filter(|w| *w == needle)
                    .count();
                assert_eq!(
                    wal_hits, 0,
                    "marker {marker:?} found in WAL sidecar — plaintext leaked! \
                     (cardinal principle 2 violation; iteration {i})",
                );
            }
            scan_for_device_key(&wal_bytes, "WAL sidecar");
        }
    }

    let total_markers = n_iterations * 6;
    eprintln!(
        "[no_plaintext_on_disk] {total_markers} markers across 6 secret fields + the device-key \
         seed × {n_iterations} iterations scanned over {total_bytes_scanned} bytes; 0 hits"
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
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();

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
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    for (id, marker) in &expected {
        // P4 H-1 fix: `AccountSnapshot.password` is `pub(crate)`, so
        // external callers (this integration test) must route through
        // the presence-gated `reveal_password` accessor. Each iteration
        // gets its own fresh `PressYPresenceProof` — single-use replay
        // resistance forbids reusing one across calls.
        assert!(
            v.get_account(*id).is_some(),
            "missing on reopen for id {id:?}"
        );
        let presence = PressYPresenceProof::confirmed();
        let pwd = v
            .reveal_password(*id, &presence)
            .expect("reveal_password must succeed on a freshly-unlocked vault");
        assert_eq!(pwd.expose(), &marker[..]);
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
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        let id = v.add_account(snapshot_with_marker("survivor")).unwrap();
        v.lock();
        v.close().unwrap();
        id
    };
    let pre_count = {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
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
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
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
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
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
    let err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "expected AuthenticationFailed for cross-account row transplant; got {err:?}",
    );
}

// ---------------------------------------------------------------------
// MEDIUM-4 (P2 audit): the per-row `revisions.schema_version` column
// is bound into the AAD on decrypt. Tampering with it diverges the
// reconstructed AAD from the seal-time AAD, so `Vault::unlock` (which
// decrypts current heads to populate the cache) returns
// `AuthenticationFailed`. Without this binding the column was inert.
// ---------------------------------------------------------------------
#[test]
fn adversarial_per_row_schema_version_tamper_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("schema.pvf");
    let pwd = fresh_password();

    Vault::create(&path, &pwd).unwrap();
    {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        v.add_account(snapshot_with_marker("schema-tamper"))
            .unwrap();
        v.lock();
        v.close().unwrap();
    }

    // Edit the head revision's schema_version from 0 to 1 directly in
    // the SQLite row. The wrapped/sealed AAD was built with 0; the
    // re-derived AAD on read will be built with 1; AEAD must reject.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let n = conn
            .execute("UPDATE revisions SET schema_version = 1", [])
            .unwrap();
        assert_eq!(n, 1, "expected exactly one revision row to update");
    }

    let mut v = Vault::open(&path).unwrap();
    let err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "expected AuthenticationFailed for tampered per-row schema_version; got {err:?}",
    );
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
    // reject. Per MEDIUM-1 of the P2 audit, this collapses into
    // AuthenticationFailed (not a distinct KdfRejected variant) so a
    // tamper of the KDF params is indistinguishable from a tamper of
    // the salt or wrapped ciphertext from the user's POV. The key
    // invariant is that the user's correct password no longer "works"
    // after tampering.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE meta SET kdf_memory_kib = 1024 WHERE id = 0", [])
            .unwrap();
    }
    let mut v = Vault::open(&path).unwrap();
    let err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "expected AuthenticationFailed for sub-floor KDF params; got {err:?}",
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
    let err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "expected AuthenticationFailed for tampered salt; got {err:?}"
    );
}

// ---------------------------------------------------------------------
// P3 / Plan §"Test plan": fork_detection_round_trip integration test.
// Synthesizes a fork via the crate's __test_ helper, walks the graph,
// confirms multi-head detection survives a lock+reopen+unlock cycle,
// and verifies all_forked_accounts() reports the forked account.
// ---------------------------------------------------------------------
#[test]
fn fork_detection_round_trip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("fork_e2e.pvf");
    let pwd = fresh_password();
    Vault::create(&path, &pwd).unwrap();

    let id;
    let r0;
    let r1;
    let r2;
    let r2_alt;
    {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Genesis (R0) -> R1 -> R2 (linear so far).
        id = v.add_account(snapshot_with_marker("genesis")).unwrap();
        r0 = v.account_heads(id).unwrap()[0];
        r1 = v.update_account(id, snapshot_with_marker("r1")).unwrap();
        r2 = v.update_account(id, snapshot_with_marker("r2")).unwrap();
        assert!(
            !v.is_forked(id).unwrap(),
            "linear edits must not look forked"
        );

        // Synthesize a sibling of R2 by inserting another revision
        // whose parent is R1. Cardinal-principle 4 — the storage
        // layer DETECTS this; resolution is the user's call (P9).
        r2_alt = v
            .__test_synthesize_sibling_revision(id, r1, snapshot_with_marker("r2-alt"))
            .unwrap();

        // Heads: { R2, R2_alt }.
        let heads_set: std::collections::HashSet<_> =
            v.account_heads(id).unwrap().into_iter().collect();
        assert_eq!(heads_set.len(), 2);
        assert!(heads_set.contains(&r2));
        assert!(heads_set.contains(&r2_alt));
        assert!(v.is_forked(id).unwrap());

        // Common ancestor of the two heads is R1 (the fork point).
        let g = v.revision_graph(id).unwrap();
        let lca = g.common_ancestor(&r2, &r2_alt).unwrap();
        assert_eq!(lca, r1, "fork point must be R1");
        // Genesis is detected.
        assert_eq!(g.genesis(), Some(&r0));

        v.lock();
        v.close().unwrap();
    }

    // Lock+reopen+unlock cycle: the fork persists across a full
    // disk round-trip. Cardinal-principle 4 ("never silent merge")
    // is enforced by storage shape, not in-memory state.
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    assert!(
        v.is_forked(id).unwrap(),
        "fork must still be visible after lock+reopen+unlock"
    );
    let heads_set: std::collections::HashSet<_> =
        v.account_heads(id).unwrap().into_iter().collect();
    assert_eq!(heads_set.len(), 2);
    assert!(heads_set.contains(&r2));
    assert!(heads_set.contains(&r2_alt));

    // all_forked_accounts is the "needs attention" set for P9's UI.
    let forked = v.all_forked_accounts().unwrap();
    assert_eq!(forked.len(), 1);
    assert_eq!(forked[0], id);

    // Graph round-trip: same shape, same fork-point.
    let g = v.revision_graph(id).unwrap();
    assert_eq!(g.len(), 4); // R0 + R1 + R2 + R2_alt
    assert!(g.is_forked());
    assert_eq!(g.common_ancestor(&r2, &r2_alt), Some(r1));

    // The canonical head pointer (account_identities.head_revision_id,
    // which add_account/update_account maintain) still points at R2 —
    // the synthesized sibling is a NON-canonical head. The plan §
    // "Schema implications" anchors this: head_revision_id is the
    // "most recently chosen canonical head" rather than "the only
    // head." Read raw via SQL so the assertion is unambiguous.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let canonical_head: Vec<u8> = conn
        .query_row(
            "SELECT head_revision_id FROM account_identities WHERE account_id = ?1",
            rusqlite::params![id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        canonical_head.as_slice(),
        r2.as_bytes(),
        "canonical head pointer should remain at R2 (the production-path head)"
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
    let err = v.unlock(&fresh_presence(), &fresh_pin()).unwrap_err();
    assert!(
        matches!(err, pangolin_store::StoreError::AuthenticationFailed),
        "expected AuthenticationFailed for bit-flipped wrapped_vdk; got {err:?}"
    );
}

// ---------------------------------------------------------------------
// P4 / Plan §"Test plan": full_session_lifecycle integration test.
// Real time, real PIN, real "press-y" — exercises the spec's session
// flow end-to-end without TestClock injection.
// ---------------------------------------------------------------------
#[test]
fn full_session_lifecycle() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("lifecycle.pvf");
    Vault::create(&path, &fresh_password()).unwrap();

    let mut v = Vault::open(&path).unwrap();
    // Locked: session is not active; session_remaining is None.
    assert!(!v.is_session_active());
    assert!(v.session_remaining().is_none());

    // Cardinal-principle 5: Start = 2 proofs.
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    assert!(v.is_session_active());
    // Right after unlock, ~15 minutes remaining.
    let remaining = v.session_remaining().unwrap();
    assert!(remaining > std::time::Duration::from_secs(14 * 60));
    assert!(remaining <= std::time::Duration::from_secs(15 * 60));

    // Active session: routine credential ops succeed (1-proof maintain).
    // Marker is the literal password we'll later round-trip through
    // reveal_password.
    let id = v
        .add_account(snapshot_with_marker("hunter2-real-time"))
        .unwrap();
    assert!(v.get_account(id).is_some());
    let _ = v.list_accounts();

    // High-risk op (reveal_password) requires presence that is fresh
    // *now* — the unlock's presence proof is still within the 60 s
    // window, so this reveal does not re-prompt (Session spec §5.2's
    // "access remains seamless"; §8.6 dedup). A throwaway proof works
    // because the engine dedups rather than verifying it.
    let pwd = v
        .reveal_password(id, &PressYPresenceProof::confirmed())
        .unwrap();
    assert_eq!(pwd.expose(), b"hunter2-real-time");

    // A second reveal moments later — still within the window — also
    // succeeds without a re-prompt (prompt dedup).
    let pwd2 = v
        .reveal_password(id, &PressYPresenceProof::confirmed())
        .unwrap();
    assert_eq!(pwd2.expose(), b"hunter2-real-time");

    // reveal_current_password is the V1-named entry; same head bytes.
    let pwd3 = v
        .reveal_current_password(id, &PressYPresenceProof::confirmed())
        .unwrap();
    assert_eq!(pwd3.expose(), b"hunter2-real-time");

    // Export-payload exercises the same proof discipline.
    let bytes = v
        .export_payload(id, &PressYPresenceProof::confirmed())
        .unwrap();
    assert!(bytes.len() > 50);

    // Lock → session goes inactive.
    v.lock();
    assert!(!v.is_session_active());
    assert!(v.session_remaining().is_none());
    // Cache is gone — list_accounts is empty after lock.
    assert!(v.list_accounts().is_empty());

    // After lock, every credential op surfaces NotUnlocked (P2
    // semantics) until the next 2-proof unlock.
    let err = v
        .add_account(snapshot_with_marker("after-lock"))
        .unwrap_err();
    assert!(matches!(err, StoreError::NotUnlocked));

    // Re-unlock with both proofs → session is active again, the
    // previously-added account is loaded back from disk.
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    assert!(v.get_account(id).is_some());
    v.lock();
    v.close().unwrap();
}

// =====================================================================
// MVP-1 issue 1.3: `:memory:` FTS5-backed account search.
// =====================================================================

/// Build a V1 account draft with the given display name, tags, urls,
/// username and password marker. The password is the literal `pw` arg
/// so the whitelist test can search for it.
fn v1_draft(
    display: &str,
    tags: &[&str],
    urls: &[&str],
    username: &str,
    pw: &str,
) -> AccountIdentityDraft {
    AccountIdentityDraft {
        schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name: display.to_owned(),
        tags: tags.iter().map(|s| (*s).to_owned()).collect(),
        usernames: vec![username.to_owned()],
        urls: urls.iter().map(|s| (*s).to_owned()).collect(),
        notes: format!("notes for {display}"),
        password: SecretBytes::new(pw.as_bytes().to_vec()),
        totp_secret: SecretBytes::new(Vec::new()),
    }
}

fn empty_patch() -> AccountIdentityPatch {
    AccountIdentityPatch {
        schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name: None,
        tags: None,
        usernames: None,
        urls: None,
        notes: None,
        password: None,
        totp_secret: None,
    }
}

/// Convenience: search and return the display names of the hits.
fn search_names(v: &mut Vault, q: &str) -> Vec<String> {
    v.account_search(q)
        .unwrap()
        .into_iter()
        .map(|s| s.display_name)
        .collect()
}

/// Criterion 6: a fresh 1.3-build vault has the `:memory:` FTS5 tables
/// (`account_fts`, `accounts`, `meta_fts` with `fts_schema_version = 1`)
/// once unlocked; `PRAGMA journal_mode` on disk still returns `wal`.
#[test]
fn fresh_vault_has_search_index_on_unlock() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("fresh.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    // The index exists and is queryable (empty vault -> no hits).
    assert!(v.account_search("anything").unwrap().is_empty());
    v.lock();
    v.close().unwrap();
    // On-disk journal mode unchanged.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert!(mode.eq_ignore_ascii_case("wal"));
}

/// Criterion 8: add accounts; find each by display name, by each tag,
/// and by the hostname of each URL (`https://github.com/foo` ⇒ found by
/// `github`); case-insensitive; arbitrary-substring (`ithu` ⇒ github).
#[test]
fn search_by_display_name_tag_hostname() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("axes.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    v.account_add(v1_draft(
        "GitHub Work",
        &["dev", "shared"],
        &["https://github.com/foo"],
        "alice@example.com",
        "pw1",
    ))
    .unwrap();
    v.account_add(v1_draft(
        "Bank Account",
        &["finance"],
        &[
            "https://mybank.example/login",
            "mailto:support@mybank.example",
        ],
        "bob",
        "pw2",
    ))
    .unwrap();

    // Display name.
    assert_eq!(search_names(&mut v, "github work"), vec!["GitHub Work"]);
    // Arbitrary substring (trigram).
    assert_eq!(search_names(&mut v, "ithu"), vec!["GitHub Work"]);
    // Tag.
    assert_eq!(search_names(&mut v, "shared"), vec!["GitHub Work"]);
    assert_eq!(search_names(&mut v, "finance"), vec!["Bank Account"]);
    // Hostname (host_str from the URL).
    assert_eq!(search_names(&mut v, "github"), vec!["GitHub Work"]);
    assert_eq!(search_names(&mut v, "mybank"), vec!["Bank Account"]);
    // Case-insensitive.
    assert_eq!(search_names(&mut v, "GITHUB"), vec!["GitHub Work"]);
    // Empty query returns all live accounts.
    let all = v.account_search("   ").unwrap();
    assert_eq!(all.len(), 2);
    v.lock();
    v.close().unwrap();
}

/// Criterion 8: NFC equivalence — the index sees the NFC (precomposed)
/// form 1.2's validator produces; a precomposed-`é` query matches.
#[test]
fn search_nfc_equivalence() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("nfc.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    // Add with the DECOMPOSED form ("Cafe" + combining acute); the
    // validator normalises to NFC before storing.
    v.account_add(v1_draft("Cafe\u{0301} Connoisseur", &[], &[], "u@x", "pw"))
        .unwrap();
    // Query with the PRECOMPOSED form.
    assert_eq!(
        search_names(&mut v, "caf\u{00e9}"),
        vec!["Café Connoisseur"]
    );
    v.lock();
    v.close().unwrap();
}

/// Criterion 9: updating `display_name` / `tags` / `urls` reflects in
/// search (new values present, old gone); tombstoning removes from search.
#[test]
fn update_and_tombstone_resync_search() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("resync.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    let id = v
        .account_add(v1_draft(
            "Old Name",
            &["oldtag"],
            &["https://oldhost.example"],
            "u@x",
            "pw",
        ))
        .unwrap();
    assert_eq!(search_names(&mut v, "oldtag"), vec!["Old Name"]);

    let mut update_patch = empty_patch();
    update_patch.display_name = Some("New Name".into());
    update_patch.tags = Some(vec!["newtag".into()]);
    update_patch.urls = Some(vec!["https://newhost.example".into()]);
    v.account_update(id, update_patch).unwrap();

    assert!(v.account_search("oldtag").unwrap().is_empty());
    assert!(v.account_search("oldhost").unwrap().is_empty());
    assert!(v.account_search("old name").unwrap().is_empty());
    assert_eq!(search_names(&mut v, "newtag"), vec!["New Name"]);
    assert_eq!(search_names(&mut v, "newhost"), vec!["New Name"]);
    assert_eq!(search_names(&mut v, "new name"), vec!["New Name"]);

    // Tombstone via the V0 delete_account path (the only tombstone path).
    v.delete_account(id).unwrap();
    assert!(v.account_search("newtag").unwrap().is_empty());
    assert!(v.account_search("new name").unwrap().is_empty());
    v.lock();
    v.close().unwrap();
}

/// Criterion 10 (structural whitelist): a known username substring, a
/// known password substring, and a known notes substring all return
/// ZERO hits — the FTS5 schema simply has no columns for those fields.
#[test]
fn search_never_matches_username_password_notes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("whitelist.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    // Distinctive marker tokens that do NOT appear in display/tags/hostnames.
    v.account_add(AccountIdentityDraft {
        schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name: "Visible Display".into(),
        tags: vec!["visibletag".into()],
        usernames: vec!["zzuserzz@example.com".into()],
        urls: vec!["https://visiblehost.example/zzpathsecretzz/login".into()],
        notes: "zznotesecretzz recovery phrase".into(),
        password: SecretBytes::new(b"zzpasswordsecretzz".to_vec()),
        totp_secret: SecretBytes::new(Vec::new()),
    })
    .unwrap();
    // Sanity: the whitelisted fields ARE searchable.
    assert_eq!(
        search_names(&mut v, "visible display"),
        vec!["Visible Display"]
    );
    assert_eq!(search_names(&mut v, "visibletag"), vec!["Visible Display"]);
    assert_eq!(search_names(&mut v, "visiblehost"), vec!["Visible Display"]);
    // The non-whitelisted fields are NOT.
    assert!(
        v.account_search("zzuserzz").unwrap().is_empty(),
        "username leaked into the index"
    );
    assert!(
        v.account_search("zzpasswordsecretzz").unwrap().is_empty(),
        "password leaked into the index"
    );
    assert!(
        v.account_search("zznotesecretzz").unwrap().is_empty(),
        "notes leaked into the index"
    );
    // The full URL (path) is not indexed either — only the host is. The
    // URL above contains the literal substring `zzpathsecretzz`, but only
    // `visiblehost.example` (the host) reaches the FTS5 `hostnames` column.
    assert!(
        v.account_search("zzpathsecretzz").unwrap().is_empty(),
        "URL path leaked into the index"
    );
    v.lock();
    v.close().unwrap();
}

/// Criterion 11 (smoke): a 10k-account vault's `account_search` returns
/// well under 50ms. `#[ignore]`'d so the normal test run isn't
/// CI-flaky on a loaded runner; the `cargo bench` (`benches/search_10k.rs`)
/// is the authoritative measurement. Run with:
/// `cargo test -p pangolin-store --release --features test-utilities -- --ignored search_10k_smoke`
#[test]
#[ignore = "perf smoke; run with --release --features test-utilities -- --ignored"]
fn search_10k_smoke() {
    use std::time::Instant;
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("perf10k.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    for i in 0..10_000u32 {
        v.account_add(v1_draft(
            &format!("Service {i}"),
            &[
                "bench",
                if i.is_multiple_of(7) {
                    "rare"
                } else {
                    "common"
                },
            ],
            &[&format!("https://host{i}.example/path")],
            &format!("user{i}@example.com"),
            "pw",
        ))
        .unwrap();
    }
    let t0 = Instant::now();
    let hits = v.account_search("service").unwrap();
    let dt = t0.elapsed();
    eprintln!(
        "[search_10k_smoke] account_search(\"service\") over 10k = {dt:?}, {} hits (capped)",
        hits.len()
    );
    assert!(
        dt < std::time::Duration::from_millis(40),
        "account_search over 10k accounts took {dt:?}, expected < 40ms (generous headroom under the 50ms exit criterion)"
    );
    // A rarer term.
    let t1 = Instant::now();
    let _ = v.account_search("rare").unwrap();
    eprintln!(
        "[search_10k_smoke] account_search(\"rare\") over 10k = {:?}",
        t1.elapsed()
    );
    v.lock();
    v.close().unwrap();
}

/// Criterion 12 (corruption): an interrupted FTS5 sync (here simulated
/// by dropping the search index mid-session and re-unlocking) leaves
/// the index correct again — it is rebuilt from the intact blob table.
/// The `:memory:` index puts nothing on disk, so an interrupted update
/// can never desync persistently.
#[test]
fn search_index_rebuilds_on_reunlock() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("rebuild.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    v.account_add(v1_draft(
        "Alpha One",
        &["t1"],
        &["https://alpha.example"],
        "u@x",
        "pw",
    ))
    .unwrap();
    v.account_add(v1_draft(
        "Beta Two",
        &["t2"],
        &["https://beta.example"],
        "u@x",
        "pw",
    ))
    .unwrap();
    assert_eq!(search_names(&mut v, "alpha"), vec!["Alpha One"]);

    // Drop the in-RAM index by locking (frees the `:memory:` arena),
    // then re-unlock — the index is rebuilt from the blob table.
    v.lock();
    // While locked, search errors (no `:memory:` index).
    assert!(matches!(
        v.account_search("alpha"),
        Err(StoreError::NotUnlocked)
    ));
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    // Index is correct again.
    let mut names = search_names(&mut v, "");
    names.sort();
    assert_eq!(names, vec!["Alpha One".to_string(), "Beta Two".to_string()]);
    assert_eq!(search_names(&mut v, "beta"), vec!["Beta Two"]);
    v.lock();
    v.close().unwrap();
}

/// V0-format precedent: a vault populated through the legacy V0
/// `add_account` / `update_account` shims still gets a working search
/// index built on unlock (the index is rebuilt from the decrypted
/// blobs regardless of blob version). Also exercises the V0 sync hooks.
#[test]
fn v0_path_builds_and_syncs_search_index() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("v0.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let id;
    {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        id = v
            .add_account(AccountSnapshot::new(
                SecretBytes::new(b"Legacy V0 Service".to_vec()),
                SecretBytes::new(b"alice".to_vec()),
                SecretBytes::new(b"hunter2".to_vec()),
                SecretBytes::new(b"https://legacyhost.example/x".to_vec()),
                SecretBytes::new(b"v0 notes".to_vec()),
                SecretBytes::new(b"".to_vec()),
            ))
            .unwrap();
        // Same-session search works through the V0 sync hook.
        assert_eq!(search_names(&mut v, "legacy v0"), vec!["Legacy V0 Service"]);
        assert_eq!(
            search_names(&mut v, "legacyhost"),
            vec!["Legacy V0 Service"]
        );
        v.lock();
        v.close().unwrap();
    }
    // Reopen: index rebuilt from the V0 blob.
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    assert_eq!(search_names(&mut v, "legacy"), vec!["Legacy V0 Service"]);
    // Update via the V0 shim resyncs.
    v.update_account(
        id,
        AccountSnapshot::new(
            SecretBytes::new(b"Renamed V0".to_vec()),
            SecretBytes::new(b"alice".to_vec()),
            SecretBytes::new(b"hunter3".to_vec()),
            SecretBytes::new(b"https://newv0host.example".to_vec()),
            SecretBytes::new(b"v0 notes".to_vec()),
            SecretBytes::new(b"".to_vec()),
        ),
    )
    .unwrap();
    assert!(v.account_search("legacy").unwrap().is_empty());
    assert_eq!(search_names(&mut v, "renamed"), vec!["Renamed V0"]);
    assert_eq!(search_names(&mut v, "newv0host"), vec!["Renamed V0"]);
    v.lock();
    v.close().unwrap();
}

// =====================================================================
// MVP-1 issue 1.4: session-policy production — config persistence,
// device-lock, reveal-class, search-index lifecycle.
// =====================================================================

use pangolin_store::SessionDuration;

/// Criterion 14: `set_session_idle` persists to `meta.session_idle_secs`
/// and a subsequent `open` + `unlock` uses the new window. Lengthening
/// (15 → 30 min) requires a fresh presence proof; the persisted value
/// survives a close/reopen cycle.
#[test]
fn set_session_idle_persists_and_is_used_on_reopen() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("idle-persist.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        // Default is 15 min for a fresh vault.
        assert_eq!(v.session_idle(), SessionDuration::Min15);
        // Lengthen to 30 min — high-risk, needs presence.
        v.set_session_idle(
            SessionDuration::Min30,
            Some(&PressYPresenceProof::confirmed()),
        )
        .unwrap();
        v.lock();
        v.close().unwrap();
    }
    // Reopen: the 30-min choice persisted.
    let mut v = Vault::open(&path).unwrap();
    assert_eq!(v.session_idle(), SessionDuration::Min30);
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    // The session's deadline reflects ~30 min.
    let r = v.session_remaining().unwrap();
    assert!(
        r > std::time::Duration::from_secs(29 * 60) && r <= std::time::Duration::from_secs(30 * 60),
        "remaining {r:?} not ≈ 30 min"
    );
    // Shorten back to 5 min — no presence needed.
    v.set_session_idle(SessionDuration::Min5, None).unwrap();
    assert_eq!(v.session_idle(), SessionDuration::Min5);
    // Shortening took effect immediately on the live session.
    let r = v.session_remaining().unwrap();
    assert!(
        r <= std::time::Duration::from_secs(5 * 60),
        "remaining {r:?} not ≤ 5 min"
    );
    v.lock();
    v.close().unwrap();
}

/// Criterion 16: `device_locked()` tears down the `:memory:` FTS5
/// search index (same path as a lock / idle expiry); a re-`unlock`
/// rebuilds it. The 1.3 search-index lifecycle is preserved.
#[test]
fn device_locked_tears_down_search_index() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("device-lock-search.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    v.account_add(v1_draft(
        "Gamma",
        &["g"],
        &["https://gamma.example"],
        "u@x",
        "pw",
    ))
    .unwrap();
    assert_eq!(search_names(&mut v, "gamma"), vec!["Gamma"]);
    // Device locks → session expires, the `:memory:` index is freed.
    v.device_locked();
    assert!(matches!(
        v.account_search("gamma"),
        Err(StoreError::SessionExpired)
    ));
    // Re-unlock (2-proof) rebuilds the index.
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    assert_eq!(search_names(&mut v, "gamma"), vec!["Gamma"]);
    v.lock();
    v.close().unwrap();
}

/// Criterion 13: the V1 `reveal_password_history` returns the complete
/// history (bytes + `set_at_ms` + device per entry) end-to-end through
/// a real on-disk vault, and `reveal_current_password` / `reveal_notes`
/// / `reveal_totp_secret` surface the head password / notes / raw seed.
#[test]
fn reveal_class_round_trip_v1() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("reveal-v1.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    let mut draft = v1_draft(
        "GitHub",
        &["work"],
        &["https://github.com"],
        "alice@x",
        "pw-0",
    );
    draft.notes = "recovery phrase: alpha bravo charlie".into();
    draft.totp_secret = SecretBytes::new(b"jbswy3dpehpk3pxp".to_vec());
    let id = v.account_add(draft).unwrap();
    // Rotate twice.
    for new in [b"pw-1".as_slice(), b"pw-2".as_slice()] {
        v.account_update(
            id,
            AccountIdentityPatch {
                schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
                display_name: None,
                tags: None,
                usernames: None,
                urls: None,
                notes: None,
                password: Some(SecretBytes::new(new.to_vec())),
                totp_secret: None,
            },
        )
        .unwrap();
    }
    let history = v.reveal_password_history(id, &fresh_presence()).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].password.expose(), b"pw-2");
    assert_eq!(history[2].password.expose(), b"pw-0");
    assert_eq!(history[0].originating_device.0.len(), 32);
    assert!(history[0].set_at_ms >= history[2].set_at_ms);
    assert_eq!(
        v.reveal_current_password(id, &fresh_presence())
            .unwrap()
            .expose(),
        b"pw-2"
    );
    assert_eq!(
        v.reveal_notes(id, &fresh_presence()).unwrap().expose(),
        b"recovery phrase: alpha bravo charlie"
    );
    assert_eq!(
        v.reveal_totp_secret(id, &fresh_presence())
            .unwrap()
            .expose(),
        b"jbswy3dpehpk3pxp"
    );
    // The metadata-only summary carries the count + flag, no secrets.
    let summary = v.account_get(id).unwrap();
    assert_eq!(summary.password_history_count, 3);
    assert!(summary.has_totp);
    assert!(summary.current_password_changed_at_ms > 0);
    v.lock();
    v.close().unwrap();
}

// =====================================================================
// MVP-1 issue 1.5: device identity + trust list (criteria 6, 9, 12).
// =====================================================================

/// Criterion 6 (e2e): after register-on-unlock, every new V1 revision
/// (`account_add` / `account_update`) stamps `originating_device ==
/// device_current().device_id` — a real (verifying-key-derived)
/// `devices`-row id, not a per-session random — and `account_history`'s
/// `RevisionMeta.device_id` reflects it. The reveal'd
/// password-history's `originating_device` reflects it too.
#[test]
fn revisions_stamp_real_device_id_after_register() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("dev-stamp-e2e.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    let real_id = v.device_current().unwrap().device_id;
    let id = v
        .account_add(v1_draft("GH", &["w"], &["https://gh.example"], "u@x", "p0"))
        .unwrap();
    v.account_update(
        id,
        AccountIdentityPatch {
            schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: None,
            tags: None,
            usernames: None,
            urls: None,
            notes: None,
            password: Some(SecretBytes::new(b"p1".to_vec())),
            totp_secret: None,
        },
    )
    .unwrap();
    let metas = v.account_history(id).unwrap();
    assert!(metas.len() >= 2);
    for m in &metas {
        assert_eq!(
            m.device_id, real_id,
            "post-1.5 revision stamps the real device_id"
        );
    }
    let history = v.reveal_password_history(id, &fresh_presence()).unwrap();
    for e in &history {
        assert_eq!(e.originating_device, real_id);
    }
    v.lock();
    v.close().unwrap();
}

/// Criterion 9: a "PoC-shaped" `.pvf` — one whose `devices` table is
/// the legacy P2 stub (no `capabilities` / `last_sync_at` / `public_key`
/// / `schema_version` columns, no `device_key` table), whose revisions
/// carry a throwaway-random `originating_device` — still opens, unlocks
/// (two-proof), searches, and reveals; its `devices` table is migrated
/// to the new shape; a device entry is registered on the first unlock;
/// the legacy `revisions.device_id` values are left untouched (Q6).
///
/// We synthesise the legacy shape by first writing a normal 1.5 vault,
/// then opening a raw `rusqlite` connection to the same file and
/// surgically reverting it: drop the new `devices` columns (recreate
/// the table P2-style), drop the `device_key` table, drop the device
/// row, and rewrite every revision's `device_id` to a fresh random
/// value (the per-session throwaway an older-build handle would have
/// stamped).
#[test]
#[allow(clippy::too_many_lines)] // one coherent end-to-end migration scenario; splitting hurts readability
fn poc_vault_migrates_and_registers() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("poc-shaped.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let acct_id;
    {
        let mut v = Vault::open(&path).unwrap();
        v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
        acct_id = v
            .account_add(v1_draft(
                "Legacy Svc",
                &["old"],
                &["https://legacyhost.example"],
                "u@x",
                "pw0",
            ))
            .unwrap();
        v.lock();
        v.close().unwrap();
    }

    // Surgically downgrade the file to the P2-era shape.
    let throwaway_device_id: Vec<u8> = {
        let conn = rusqlite::Connection::open(&path).unwrap();
        // 1. Rewrite every revision's device_id to a fresh random 32
        //    bytes (mimics the per-session throwaway a PoC handle minted).
        let throwaway: Vec<u8> = conn
            .query_row("SELECT randomblob(32)", [], |row| row.get(0))
            .unwrap();
        conn.execute(
            "UPDATE revisions SET device_id = ?1",
            rusqlite::params![throwaway.as_slice()],
        )
        .unwrap();
        // 2. Recreate `devices` in the P2 shape (drop the 1.5 columns).
        conn.execute("DROP TABLE devices", []).unwrap();
        conn.execute(
            "CREATE TABLE devices (
                device_id   BLOB PRIMARY KEY,
                label       TEXT    NOT NULL DEFAULT '',
                added_at    INTEGER NOT NULL,
                revoked_at  INTEGER
            )",
            [],
        )
        .unwrap();
        // 3. Drop the `device_key` table.
        conn.execute("DROP TABLE device_key", []).unwrap();
        throwaway
    };

    // Reopen with the current code: the migration adds the new columns
    // back + recreates `device_key`; the first unlock registers a
    // device; the legacy revisions are untouched; search + reveal work.
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    let cur = v.device_current().unwrap();
    assert_eq!(v.device_list().unwrap().len(), 1);
    assert!(cur.is_current);
    assert_eq!(cur.last_sync_at, None);
    // The migrated `devices` table has the new columns (queryable).
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut stmt = conn.prepare("PRAGMA table_info(devices)").unwrap();
        let cols: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for c in [
            "capabilities",
            "last_sync_at",
            "public_key",
            "schema_version",
        ] {
            assert!(cols.iter().any(|x| x == c), "migrated column {c} missing");
        }
    }
    // Legacy revisions still carry the throwaway device_id (accepted
    // as-is — Q6: no backfill).
    let metas = v.account_history(acct_id).unwrap();
    assert!(!metas.is_empty());
    let throwaway_arr: [u8; 32] = throwaway_device_id.as_slice().try_into().unwrap();
    assert_eq!(
        metas[0].device_id.0, throwaway_arr,
        "legacy revisions keep their throwaway originating_device (Q6)"
    );
    // The vault still searches + reveals.
    assert_eq!(search_names(&mut v, "legacy svc"), vec!["Legacy Svc"]);
    assert_eq!(
        v.reveal_current_password(acct_id, &fresh_presence())
            .unwrap()
            .expose(),
        b"pw0"
    );
    // A NEW revision written now stamps the real (registered) device_id.
    v.account_update(
        acct_id,
        AccountIdentityPatch {
            schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: None,
            tags: None,
            usernames: None,
            urls: None,
            notes: None,
            password: Some(SecretBytes::new(b"pw1".to_vec())),
            totp_secret: None,
        },
    )
    .unwrap();
    let metas = v.account_history(acct_id).unwrap();
    assert_eq!(
        metas.last().unwrap().device_id,
        cur.device_id,
        "new revisions stamp the real registered device_id"
    );
    v.lock();
    v.close().unwrap();
}

/// Criterion 12: a 1.5-flavoured add/update + a device-label edit does
/// not perturb the 1.3 `:memory:` FTS5 search-index lifecycle or the
/// 1.4 session state machine — `account_search` still returns the right
/// rows and the session transitions are unchanged (no new expiry /
/// escalation behaviour introduced by 1.5).
#[test]
fn search_index_and_session_machine_untouched_by_device_ops() {
    use pangolin_store::SessionState;
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("dev-smoke.pvf");
    Vault::create(&path, &fresh_password()).unwrap();
    let mut v = Vault::open(&path).unwrap();
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    assert!(matches!(v.session_state(), SessionState::Active { .. }));

    let dev_id = v.device_current().unwrap().device_id;
    let id = v
        .account_add(v1_draft(
            "Delta",
            &["d"],
            &["https://delta.example"],
            "u@x",
            "pw",
        ))
        .unwrap();
    assert_eq!(search_names(&mut v, "delta"), vec!["Delta"]);
    // A device-label edit: still Active afterwards, search still works.
    v.device_set_label(dev_id, "Renamed device").unwrap();
    assert!(matches!(v.session_state(), SessionState::Active { .. }));
    assert_eq!(v.device_current().unwrap().label, "Renamed device");
    assert_eq!(search_names(&mut v, "delta"), vec!["Delta"]);
    // An update resyncs the index as before.
    v.account_update(
        id,
        AccountIdentityPatch {
            schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: Some("Delta Renamed".into()),
            tags: None,
            usernames: None,
            urls: None,
            notes: None,
            password: None,
            totp_secret: None,
        },
    )
    .unwrap();
    assert_eq!(v.account_search("delta renamed").unwrap().len(), 1);
    // lock → search index torn down (1.3 lifecycle preserved).
    v.lock();
    assert!(matches!(v.session_state(), SessionState::Locked));
    assert!(matches!(
        v.account_search("delta"),
        Err(StoreError::NotUnlocked)
    ));
    // re-unlock rebuilds it.
    v.unlock(&fresh_presence(), &fresh_pin()).unwrap();
    assert_eq!(v.account_search("delta renamed").unwrap().len(), 1);
    v.lock();
    v.close().unwrap();
}
