<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #109 — recovery backup format (encrypted, 24-word-seed-unlocked envelope) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-23 (§0a).** The recurring 6.x deferral: until a vault has a STANDARD encoded backup blob, the lost-everything recovery FFI (`vault_recover_from_shares`) is reachable through code but unusable in production (no canonical way for users to keep + restore the recovery material). #109 ships the format + the FFI helpers so the host can persist + restore backups.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-23)

- **Unlock = generated 24-word BIP-39-style seed phrase.** Generated at backup-creation time; the user records on paper / metal / safe; we do NOT store it. Standard, strong by construction (256 bits of entropy), and the convention users already know from crypto wallets. Argon2id-style KDF over the seed phrase derives the AEAD key (per the codebase's existing wrap-authority pattern; same `KdfParams::RECOMMENDED` profile).
- **Envelope always carries METADATA in the encrypted body** — vault display name (if the user has set one for the vault) + creation timestamp. No "include metadata?" toggle: the metadata sits INSIDE the encrypted envelope, only readable by someone who already has the seed phrase (the legitimate user). No privacy leak; cleaner format + better UX (the user with multiple backups can tell them apart after unlocking).
- **Format location = Rust-side canonical helpers.** New module `pangolin-store::recovery_backup` (alongside `recovery_escrow.rs`): encoder + decoder + the wire format. Mirrors `pangolin-core::pairing_transport`'s discipline — fixed-layout where possible, zero-serde, length + version + checksum gated. (Could later live in `pangolin-crypto` if cleaner; `pangolin-store` is the natural home since this is the export/restore path that already lives there per #1.10's `encrypted-export`.)
- **Two transport forms** — byte form (canonical, what gets persisted to disk / sent over a transport) AND a `Bech32`-style copy-pasteable text form with a 4-byte truncated-SHA-256 checksum (mirrors `#106e-2` pairing's text codec). The seed phrase is its OWN thing (24 words shown at backup creation; the user records out-of-band) — not embedded in either transport form.
- **Versioning + checksum**: `SCHEMA_VERSION = 1`; an integrity hash in the OUTER (plaintext) wrapper so corruption / wrong-length-truncation fails CLOSED with a typed error BEFORE the KDF runs (defends against wasted-KDF-on-bad-blob DoS). Unknown `schema_version` rejects fail-closed.
- **Encrypted body schema (after seed-phrase unlock)**: `wrapped_recovery` (the `WrappedVdkRecovery` bytes — the VDK wrapped under the now-dropped RWK; cryptographically useless without ≥t guardian shares) + `vault_id (32 B)` + recovery-generation `epoch (u64)` + `roster` ((`t: u8`, `M: u8`) + `M × x25519_pub (32 B each)` — the guardian sealing pubkeys) + optional `vault_display_name (String)` + `created_at_unix (u64)`.
- **NEW FFI surface (the host-facing helpers)**:
  - `vault_create_backup(handle, master_password) -> Result<FfiBackup, FfiError>` — generates the seed phrase + encrypts the envelope. Returns the seed-phrase (24 words) + backup bytes + backup text form. ACTIVE-gated (needs to read the active escrow's params + the active VDK's column-AEAD for sourcing the recovery material).
  - `vault_decode_backup(backup_bytes_or_text, seed_phrase) -> Result<FfiBackupContents, FfiError>` — decrypt + decode. Pure (no handle). Returns the non-secret fields needed for recovery + the metadata for UX.
  - `vault_recover_from_backup(handle, backup_bytes_or_text, seed_phrase, opened_shares, new_password) -> Result<FfiRecoveryResult, FfiError>` — convenience all-in-one: decode + drive `composition::recover_from_shares` with the host-supplied opened guardian shares + the new master password. Combines decoding with the existing recovery binding so the host doesn't have to.
- **L-invariants**: L1 zero-secret-crosses-FFI (the seed phrase is the ONLY secret that crosses out, exactly once, at `vault_create_backup` — opaque `Arc<FfiSeedPhrase>` Object with `.word_count()` + a single-use `.consume_for_decode() -> Zeroizing<Vec<String>>` consumed by `vault_decode_backup` / `vault_recover_from_backup`; never stored); L2 no new atomic surface; L3 fail-closed on bad checksum / bad schema_version / bad-length blob (typed errors BEFORE the KDF); L4 KDF is the same Argon2id `RECOMMENDED` profile already used for vault wrap (no new crypto / no new deps); L5 session-gated where it touches the active VDK; L6 `forbid(unsafe)`; L7 testnet-only/D-011 (the whole recovery surface stays Base-Sepolia-only); L8 full `cargo test --workspace` gate; L9 §16 ledger.
- **Scope NOT this slice**: any change to `WrappedVdkRecovery` / the escrow structure (use them verbatim); on-chain anything (#109 is purely off-chain); a printable-paper layout / QR rendering / share-via-cloud (the BYTES + the text form are what we ship; the host renders them).

## 0. One-paragraph summary

Today's `vault_recover_from_shares` FFI takes `wrapped_recovery: Vec<u8>` + `current_epoch: u64` + `vault_id: Vec<u8>` + `roster: FfiGuardianRoster` as host-supplied raw params — but no canonical FORMAT for those bytes exists. The host has to figure out where to stash them (and how to encode them) between onboard time + lost-everything recovery time, possibly years apart, possibly on a different device. #109 defines the canonical encrypted-envelope FORMAT + the FFI helpers so the host has ONE blob to persist (file / cloud / paper-string), unlocked by a 24-word seed phrase the user records out-of-band. Metadata (vault display name, creation timestamp) lives inside the encrypted body for post-unlock UX. Mirrors the discipline of `#1.10` encrypted-export (Argon2id KDF + XChaCha20-Poly1305 AEAD + bounded-length-checked envelope) + `#106e-2` pairing's text codec (Bech32-ish + 4-byte SHA-256 checksum).

## 1. Scope

**Built in #109**:
- `crates/pangolin-store/src/recovery_backup.rs` (NEW): `BackupEnvelope` type, the wire format, `seal_backup` + `decode_backup` + the seed-phrase generation (24-word BIP-39 — note: the `bip39` family doesn't need a new crate dep if we already have its primitives; if it does, this is the ONE place we MIGHT add a dep — see §5 Q-a below); `BackupError`; the text-form encoder/decoder. `forbid(unsafe)`; AGPL.
- `crates/pangolin-store::Vault::create_recovery_backup(master_password)` (NEW production method): reads the active VDK's column-AEAD + the escrow params, builds + seals the envelope, returns the seed phrase + envelope bytes + text form. Session-gated (Active).
- `pangolin-ffi::recovery_backup` (NEW): 3 `#[uniffi::export]` bindings (`vault_create_backup`, `vault_decode_backup`, `vault_recover_from_backup`) + the `FfiBackup` / `FfiBackupContents` / `FfiSeedPhrase` records / Objects. Mirrors `#106e-1` patterns (`FfiOpenedShare`-style opaque seed-phrase Object; length-validated byte ingress; exhaustive error mapping).
- Hermetic tests: codec round-trip (encode → decode = byte-identical), wrong-seed-phrase fails-closed, tampered-envelope fails-closed (single error variant, NO oracle), unknown-schema_version fails-closed, the end-to-end `vault_create_backup → vault_recover_from_backup` round-trip on a hermetically-onboarded vault.

**Deferred (NOT this slice)**:
- A printable-paper-backup layout (the BYTES + text form are what we ship; UI/printing is the host).
- Cloud-sync of backups (host responsibility; the bytes are safe to store anywhere given the seed-phrase wrap).
- The on-chain RecoveryV1 lifecycle FFI (that's #108 — independent; can land in either order).
- The 4-spec-design-system UX flows for "set up recovery" / "use recovery" (MVP-4).

## 2. Splittable? — recommend ONE slice

The codec + the production Vault method + the FFI helpers are tightly coupled (the FFI just wraps the Vault method; the Vault method just wraps the codec). One PR, builder → adversarial audit (focused on L1 zero-secret-crosses + L3 fail-closed-on-bad-input + the panic-on-malformed-input hunt + the seed-phrase opaque-Object discipline) → merge.

## 3. The wire format (designed; build details in the §0a-locked §5 absent)

### 3.1 Plaintext outer wrapper
```text
DOMAIN(28 B = "pangolin-recovery-backup-v0")
 ‖ schema_version (1 B = 1)
 ‖ kdf_algo_id (1 B = 1 = Argon2id)
 ‖ Argon2 params (3 × u32 BE = mem_cost, time_cost, parallelism)
 ‖ kdf_salt (16 B random)
 ‖ aead_nonce (24 B random; XChaCha20-Poly1305)
 ‖ ct_len (u64 BE)
 ‖ ciphertext (ct_len bytes; AEAD-sealed CBOR body; AAD = the whole outer wrapper above)
 ‖ integrity_hash (4 B = truncated SHA-256 of everything before this field)
```

### 3.2 Encrypted CBOR body
```cbor
{
  "wrapped_recovery_bytes": bstr,
  "vault_id": bstr (32),
  "epoch": uint,
  "threshold": uint (u8),
  "guardian_count": uint (u8),
  "guardian_x25519_pubs": [bstr (32) × M],
  "vault_display_name": tstr (optional, empty-string-allowed),
  "created_at_unix": uint,
  "schema_version": uint (1, redundant with outer for defense-in-depth)
}
```

### 3.3 Text form
`bech32_lc(outer_wrapper_bytes ‖ truncated_sha256(outer_wrapper_bytes)[..4])` — lowercase Bech32-ish alphabet, no padding. ~300–500 chars depending on `M`.

### 3.4 Seed-phrase derivation
24 BIP-39-English words ↔ 256 bits of entropy. KDF: `Argon2id(seed_phrase_bytes, kdf_salt, kdf_params) → 32 B AEAD key`.

## 4. L-invariants — see §0a

## 5. Open decisions — pre-locked (with one carve-out for the builder)

- **Q-a (BIP-39 wordlist dependency): builder's call.** The 24-word seed-phrase needs the BIP-39 English wordlist. Options the builder can pick from:
  - (i) Use an existing tiny crate (e.g. `bip39` `=2.x`, `=`-pinned, `cargo deny` clean). Adds one dep.
  - (ii) Embed the 2048-word list inline (~20 KB of text in the source). Zero new deps, slightly bulkier source.
  Either is fine; pick the cleaner one based on what's already transitively in the tree. NOT a Kelvin question (deferred to the builder; report which was chosen).
- All other decisions are locked per §0a.

## 6. Places that need care
- **Seed-phrase generation must use `pangolin_crypto::rng::fill_random`** (the CSPRNG chokepoint). Never `OsRng::fill_bytes` directly.
- **The integrity hash is OUTSIDE the encrypted envelope** so a corrupted blob fails CLOSED with a typed `BackupError::IntegrityFailed` BEFORE the KDF runs (saves Argon2id work on garbage input).
- **The decode path collapses wrong-seed + tampered-ciphertext to ONE error** (`BackupError::AuthenticationFailed`) — no oracle.
- **`vault_create_backup` is the ONE place the seed phrase exists in process memory.** Generated, displayed once via the opaque `FfiSeedPhrase` Object, never persisted. The host MUST surface it to the user immediately; the Object's `.consume_for_decode()` is single-use + zeroizes.
- **Argon2 params are the same `KdfParams::RECOMMENDED`** (256 MiB / t=3 / p=1) used for the vault wrap. The decode-side bounds-check (per #1.10 encrypted-export pattern) clamps a hostile envelope's params before `derive_key` (`MAX_KDF_MEMORY_KIB`=1 GiB, `MAX_KDF_TIME_COST`=8, `MAX_KDF_PARALLELISM`=8, combined 3 Mi KiB-passes cap).
- **The text form's checksum mismatch fails BEFORE bech32 decode** (cheap reject; saves work).
