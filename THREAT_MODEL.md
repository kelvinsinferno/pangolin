# Threat Model — Pangolin

> Living document. Initial scaffold from PoC bootstrap; populated to full spec as MVP-1 issue 0.2.
> Source: Whitepaper §4. **Threat-model claims must not be expanded without Kelvin approval (workspace research-agent rules).**

---

## Scope: what Pangolin defends against

- **Device loss or theft** — encrypted-at-rest local store; no plaintext on disk; biometric / PIN required to unlock.
- **Cloud or vendor compromise** — no vendor-hosted vault; server compromise reveals only encrypted blobs.
- **Account takeover via phishing** — domain binding on every credential request (API contract §4.3); origin mismatch blocks autofill.
- **Password reuse cascades** — per-account identity model; rotation history.
- **Service shutdowns or data unavailability** — vault works fully offline; chain log + ephemeral indexer mean no Pangolin-operated service is required for read.

## Out of scope: what Pangolin does NOT claim to protect against

- **Fully compromised operating systems** — OS root attacker can read process memory.
- **Kernel-level malware** — same.
- **Physical coercion** — Pangolin cannot defend against the user being forced to unlock under duress (Phase-2 Secondary Vault concept partially addresses this; not in MVP-1 scope).
- **Cryptographic failures** — if XChaCha20-Poly1305 or Ed25519 is broken, Pangolin breaks. We assume modern primitives are sound.

## Security invariants (to be expanded in MVP-1 issue 0.2)

These are non-negotiable. Every issue that touches a relevant surface must verify it does not violate any of these.

1. **No plaintext writes to disk.** All payloads encrypted client-side before any persistence (local store, log, network).
2. **Relay/funder/indexer cannot forge revisions.** Contract verifies client signature; all encryption client-side.
3. **Indexer cannot decrypt.** Serves encrypted blobs only.
4. **Recovery requires N-of-M + delay.** Enforced in contract; delay window cancelable by current authority.
5. **Session authority never stored on-chain.** Local-only, time-bounded, non-transferable.
6. **Guardians never see VDK.** Recovery rotates *authority* and re-wraps VDK; never re-derives.
7. **Hardware is never required.** Identity proof always satisfies as fallback.
8. **Capture authority is exclusive per context.** One component owns capture per browser/desktop/mobile.

## Threat enumeration (to be expanded)

Per-component threat enumeration lands as part of MVP-1 issue 0.2 and is updated continuously as new attack surfaces are added.

| Surface | Phase | Status |
|---|---|---|
| Local encrypted store | PoC | DOCUMENTED (P2) |
| Session policy engine | MVP-1 | TBD (issue 0.2) |
| Revision Log v0 contract | PoC | DOCUMENTED (P5-1) |
| Revision Log v1 contract | MVP-2 | TBD (issue 2.1 plan) |
| Funder service | MVP-2 | TBD (issue 3.4 plan) |
| Ephemeral local indexer | MVP-2 | TBD (issue 4.2 plan) |
| Recovery contract | MVP-3 | TBD (issue 2.2 recovery plan) |
| Browser extension | MVP-4 | TBD (issue 7.2.x plans) |
| Native messaging boundary | MVP-4 | TBD (issue 7.2.2 plan) |
| iOS / Android autofill extensions | MVP-5 | TBD (issue 8.x plans) |

### Revision Log v0 contract

> Source: `docs/issue-plans/P5-1.md` §"Threat enumeration". v0 is the PoC
> append-only log: zero on-chain validation, no admin keys, no upgrades.
> v1 (MVP-2 issue 2.1) will add signature verification and a "signer
> must be a registered device key for vaultId" check; the v0 differences
> are noted inline below.

1. **Adversary publishes garbage to a vault's log to slow sync.** Defense: clients filter by `vaultId` topic; per-vault `eth_getLogs` is unaffected by other vaults' garbage. Gas cost falls on the adversary. *v0 difference:* v0 has no on-chain authentication, so any address can call `publishRevision` with arbitrary bytes. v1 will require a valid signature; v0 explicitly does not.
2. **Adversary publishes a fake "next revision" forking a user's account.** Defense: client-side conflict detection (master plan MVP-1 issue 1.6) detects multiple heads. User resolves explicitly per Whitepaper §7. *v0 difference:* same client-side detection applies; v0's lack of signature checks does not change the resolution path because the client always treats on-chain data as untrusted.
3. **Adversary tampers with on-chain ciphertext.** Defense: AEAD AAD binds revision metadata (P1-1 design). Tampered ciphertext fails authentication on the client. The contract is *not* the integrity layer; AEAD is. *v0 difference:* none — encrypt-then-MAC on the client fails closed regardless of contract version.
4. **Chain reorg or network partition.** Defense: clients tolerate reorgs by tracking `(blockNumber, logIndex)` per known revision; on reorg, re-pull from the last known stable block. Out of scope for the contract; in scope for `pangolin-chain` (issue P7). *v0 difference:* none — reorg tolerance is a client concern.
5. **Permanent contract corruption (storage attack).** Defense: contract has only one storage slot (`nextSequence`); no functions write to other slots. The `invariant_noStorageMutationBesidesSequence` test asserts this under fuzzed call sequences (10,000 runs × 32-call depth in CI). *v0 difference:* v0 has no mappings, but the invariant additionally probes a sample of hashed (mapping-style) slots so the assertion future-proofs for v1's mapping storage.

### Local encrypted store (`pangolin-store`)

> Source: `docs/issue-plans/P2.md` §"Threat enumeration". The
> `pangolin-store` crate persists vaults as single `.pvf` SQLite files
> with all sensitive payload bytes wrapped in `XChaCha20-Poly1305`
> AEAD ciphertext bound by a deterministic 105-byte AAD. The crate
> consumes only `pangolin-crypto`'s public API; it ships no new
> primitives.

1. **Attacker reads disk image of locked vault.** Defense: every sensitive value lives inside an AEAD-sealed BLOB column. Decrypting any blob requires the `AuthorityKey`-derived wrap key, which requires the user password. The vault file's structural metadata (account count, revision parentage, timestamps) is visible — same as the on-chain log; this is a known design tradeoff (see threat #1 of the Revision Log v0 row above).
2. **Attacker steals a `WrappedVdk` blob.** Defense: AEAD ciphertext is computationally infeasible to break absent the password. The wrap key is derived through `HKDF-SHA512(authority.seed_bytes, info = "pangolin-vdk-wrap-v0", L = 32)`; the authority itself is reconstructed from `Argon2id(password, salt, params)` via `AuthorityKey::from_seed` at every unlock.
3. **Attacker tampers with row contents to cross-account or cross-vault transplant.** Defense: every revision blob's AEAD AAD binds `WRAP_AAD_DOMAIN_REV (8B "pgrev0\0\0") || vault_id (32B) || account_id (32B) || parent_revision_id (32B) || schema_version (1B)` for a fixed 105-byte deterministic encoding. A row whose `account_id` (or `parent_revision_id` or `vault_id` or `schema_version`) has been edited authenticates with a different AAD than the one used at seal time and the open path returns `AeadError::Tampered`, which `pangolin-store` collapses to `StoreError::AuthenticationFailed`. Verified by the `adversarial_cross_account_row_transplant_fails` integration test.
4. **Attacker has memory dump after vault was unlocked.** Defense: every secret-bearing type implements `ZeroizeOnDrop` and routes through `BoxedSecret` (heap-allocated, wiped in place on drop) or `SecretBytes` (Zeroizing-wrapped Vec). `Vault::lock` drops the in-memory `DecryptedCache`, which transitively drops every `AccountSnapshot` and zeroes its `SecretBytes` fields. Best-effort; not a guarantee against attackers with kernel-level access (out of scope per top-level threat model).
5. **Concurrent corruption from two opens.** Defense: `Vault::open` takes a sidecar `.lock` file via `OpenOptions::create_new(true)`; a second open observes the file and returns `StoreError::AlreadyOpen`. Verified by the `vault::tests::double_open_fails` unit test. After a hard crash the lock file remains and operators must remove it manually before reopening — documented operational hazard, not a security failure.
6. **Format-version downgrade attack.** Defense: `Vault::open` reads the `format_version` byte from the meta row before any AEAD work and surfaces `StoreError::UnsupportedFormatVersion` for any version newer than this build understands. Verified by the `adversarial_unknown_format_version_clean_error` integration test (which writes `99` directly to the meta column).
7. **KDF parameter tampering on disk.** Defense: KDF params live in plaintext on the meta row (they MUST be readable before unlock to feed the same Argon2id parameters back into `derive_seed`). Sub-floor params are rejected by `KdfParams::validate` at `pangolin-crypto`'s public boundary; tampering that keeps params in-range but changes their values (e.g., shifting `time_cost`, or flipping a bit in the salt) produces a different derived seed. Both cases collapse into `StoreError::AuthenticationFailed` via the `From<KdfError>` impl in `error.rs`, which means an attacker who tampers with the KDF params cannot distinguish the result from a salt-tamper or ciphertext-tamper or wrong-password attempt — the failure variant is identical across all four cases (this collapsing is the MEDIUM-1 fix from the P2 audit; previously a separate `KdfRejected` variant let the attacker oracle the cause). Verified by the `adversarial_kdf_param_tampering_fails` integration test, which exercises both sub-floor and salt-tamper paths and asserts both surface `AuthenticationFailed`.

#### Verification artifacts

The `tests/e2e.rs::no_plaintext_on_disk` property test is the load-bearing
cardinal-principle-2 verifier for this layer: it creates a vault, writes
≥100 accounts whose password fields carry unique random markers, locks +
closes the vault, and scans the raw bytes of the `.pvf` file (and the WAL
sidecar when present) for each marker — asserting zero matches across
all writes. Runs on every `cargo test` invocation in CI; a marker hit
would indicate a regression in the seal/AAD discipline and would block
the PR.
