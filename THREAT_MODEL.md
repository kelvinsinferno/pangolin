# Threat Model — Pangolin

> Living document. Bootstrapped during the PoC; spec-completed as MVP-1 issue 0.2 (2026-05-13) — every MVP-1 surface is now enumerated, and the four CI-enforced cross-cutting properties (HIGH-1 / Q3 / §18.7 / AAD-coverage) are now numbered invariants #9–#12. MVP-2 and later surfaces remain `TBD` placeholders until those issues land.
> Source: Whitepaper §4 + session spec §2.3. **Threat-model claims must not be expanded without Kelvin approval (workspace research-agent rules).**

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

## Security invariants

These are non-negotiable. Every issue that touches a relevant surface must verify it does not violate any of these. Invariants #1–#8 are the attack-surface rules from the whitepaper / session spec; invariants #9–#12 are CI-enforced structural / build-discipline properties promoted from cross-cutting policies during 0.2.

1. **No plaintext writes to disk.** All payloads encrypted client-side before any persistence (local store, log, network).
2. **Relay/funder/indexer cannot forge revisions.** Contract verifies client signature; all encryption client-side.
3. **Indexer cannot decrypt.** Serves encrypted blobs only.
4. **Recovery requires N-of-M + delay.** Enforced in contract; delay window cancelable by current authority.
5. **Session authority never stored on-chain.** Local-only, time-bounded, non-transferable.
6. **Guardians never see VDK.** Recovery rotates *authority* and re-wraps VDK; never re-derives.
7. **Hardware is never required.** Identity proof always satisfies as fallback.
8. **Capture authority is exclusive per context.** One component owns capture per browser/desktop/mobile. *Enforcement landed in MVP-1 issue 1.11:* the `capture_authorities` SQL table's `PRIMARY KEY (context_kind, platform_hint)` makes exclusivity structural; closed `uniffi::Enum` discriminators make the rule a type-system property; a register that would clobber an existing different registration is rejected by default (`StoreError::CaptureAuthorityExclusivity`) and the caller must opt into replacement with a fresh presence proof (the hybrid auth tier — session-class for first register, reveal-class for replace). See `docs/architecture/capture-authority.md` for the full picture.
9. **`pangolin-crypto` has zero `serde` reach (HIGH-1).** The crypto crate must never pull serde or any of its derives, either directly or transitively. This keeps the cryptographic core auditable — `serde` is a large surface with its own past CVEs, and Pangolin's wire formats live one layer up in `pangolin-store`. *Enforcement:* `deny.toml`'s `bans` table forbids `serde` in `pangolin-crypto`'s tree, AND the CI `invariants` job runs `cargo tree -p pangolin-crypto | grep -ci serde` and fails on any non-zero count. Belt-and-braces — the cargo-tree check catches indirect paths a future `bans.deny` change might miss. Locally verifiable identically.
10. **`pangolin-core` has zero `uniffi` reach (Q3).** The engine crate must never pull `uniffi` (the FFI binding generator), directly or transitively. Keeps the engine's public surface decoupled from the FFI layer — `pangolin-ffi` is a separate crate that depends on `pangolin-core` *and* `uniffi`, never the other way. A bonus check covers `pangolin-store` too. *Enforcement:* the CI `invariants` job runs `cargo tree -p pangolin-core | grep -ci uniffi` AND `cargo tree -p pangolin-store | grep -ci uniffi` and fails on any non-zero count.
11. **A record from a future build's `schema_version` is never silently skipped.** Every persisted record carries a `schema_version` field; on read, a value above this build's `MAX_KNOWN` rejects with a typed error scoped to the field's home (file → whole-vault unopenable; revision-row → that account "requires upgrade"; per-table-row → that row only; encrypted-archive payload → whole archive unreadable). For AAD-bound fields the reject runs *after* the AEAD open so a tampered byte surfaces `AuthenticationFailed`, not a misleading "requires upgrade". *Source:* `docs/architecture/schema-versioning.md`. *Locked in MVP-1 issue 1.6; extended by 1.7 / 1.9 / 1.10 / 1.11.*
12. **AEAD AAD covers every disambiguating byte of every sealed payload.** Every header byte that selects how a ciphertext is interpreted — `vault_id`, `account_id`, `parent_revision_id`, `schema_version`, the encrypted-archive header (`magic`, `format_version`, `kdf_algo_id`, `kdf_params`, `salt`, `nonce`, `ct_len`) — is bound into the AEAD AAD. A row whose AAD-bound bytes are edited authenticates against an AAD this build never sealed under and the open returns `AeadError::Tampered` (collapsed to `StoreError::AuthenticationFailed`). No silent cross-account / cross-vault / cross-archive transplant. *Verified by:* `adversarial_cross_account_row_transplant_fails` (`pangolin-store` e2e), `tampered_header_byte_fails_auth` (`pangolin-store::export`), and the AAD layout grep in invariants CI.

## Threat enumeration

Per-component threat enumeration. Updated continuously as new attack surfaces land — each MVP-1 issue's plan adds a section here when it introduces a new surface.

| Surface | Phase | Status |
|---|---|---|
| Local encrypted store | PoC | DOCUMENTED (P2) |
| Revision Log v0 contract | PoC | DOCUMENTED (P5-1) |
| Pangolin chain adapter (`pangolin-chain`) | PoC | DOCUMENTED (P7) |
| Pangolin sync orchestrator (`pangolin-cli`) | PoC | DOCUMENTED (P8 + P9) |
| Session policy engine | MVP-1 | DOCUMENTED (issues 1.4 + 0.2) |
| Device identity + per-device key | MVP-1 | DOCUMENTED (issue 1.5) |
| TOTP engine | MVP-1 | DOCUMENTED (issue 1.7) |
| Password generator + zxcvbn strength estimator | MVP-1 | DOCUMENTED (issue 1.8) |
| KDBX importer (untrusted-file parser) | MVP-1 | DOCUMENTED (issue 1.9) |
| Encrypted export (`.pvea` archive + restore) | MVP-1 | DOCUMENTED (issue 1.10) |
| Capture-authority registry | MVP-1 | DOCUMENTED (issue 1.11) |
| Device EVM wallet (secp256k1; derived from 1.5 Ed25519 device key) | MVP-2 | DOCUMENTED (issue 3.2) |
| Revision signing v1 (secp256k1 + EIP-712 typed-data) | MVP-2 | DOCUMENTED (issue 3.1) |
| Revision Log v1 contract | MVP-2 | TBD (issue 2.1 plan) |
| Funder service | MVP-2 | TBD (issue 3.4 plan) |
| Ephemeral local indexer | MVP-2 | DOCUMENTED (issue 4.2 skeleton + 4.3 AEAD + zero-fill + ephemeral key + 4.3-per-column-AEAD wrapping + AAD binding + ARCH-1 binary handshake) |
| Sync-mode selector (picker between 4.1 slow-mode + 4.2/4.3 fast-mode) | MVP-2 | DOCUMENTED (issue 4.4) |
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
8. **Reveal-class secret extraction outside a fresh-presence context.** (MVP-1 issue 1.4.) Defense: every reveal-class op (`reveal_current_password`, `reveal_password_history`, `reveal_notes`, `reveal_totp_secret`, `export_payload`) routes through `Vault::ensure_presence_fresh` — being inside an unlocked, non-expired session is NOT sufficient; the last presence proof must be fresh (within `PRESENCE_FRESHNESS = 60s`, the session-spec §7.6 upper bound). Within the window the proof is reused (dedup) without re-prompting; outside it the op re-verifies a fresh presence proof, and a re-prompt that is not answered within `PROMPT_TIMEOUT` fails the op with `StoreError::PromptTimedOut` — a distinct error from `AuthenticationFailed` (no oracle: a timed-out prompt and a rejected proof are not conflated, but neither leaks whether the account exists — the locked-vault / expired-session / frozen-account checks fire *before* the proof is consumed and surface `NotUnlocked` / `SessionExpired` / `AccountFrozenPendingResolve` respectively). The dedup path deliberately does NOT re-stamp `last_presence_at`, so the 60s window cannot be extended indefinitely under continuous reveals. **Residual exposure (accepted, inherent):** the freshness window is session-global, not per-account — a single presence proof coerced out of the user covers reveals of any account for up to 60s. The CLI-tier presence prompt names the action explicitly so the consent is meaningful; hardware-attested per-action proofs land in MVP-3/4. Separately (1.4 Q5b), the FFI `AccountSnapshot` returned by the *non*-presence-gated `account_get` / `account_search` path carries zero secret material — not even zeroizing handles — only non-secret metadata (`display_name`, `tags`, `usernames`, `urls`, `password_history_count`, `has_totp`, `current_password_changed_at`); secrets cross the FFI boundary only through the presence-gated `reveal_*` entries. Verified by `vault.rs` / `pangolin-store` `tests/e2e.rs` (`reveal_password_requires_fresh_presence`, `two_reveals_within_window_verify_proof_once`, `reveal_with_stale_proof_returns_prompt_timed_out`, `reveal_on_locked_and_expired_session_errors`, `reveal_class_round_trip_v1`) and `pangolin-ffi` (`account_snapshot_has_no_secret_fields`, `ffi_account_snapshot_has_no_plaintext_secrets`).
9. **Encrypted-export artifact extraction / offline brute force.** (MVP-1 issue 1.10.) The encrypted-export feature materialises *every* secret in the vault — every head password, the full password history bytes, notes, TOTP seeds, the device list, the `meta` settings — into a single portable artifact (a `.pvea` file you can move between devices or keep off-site). Threat: the artifact + a weak/leaked **export passphrase** + offline Argon2id brute force. Defense: the archive is AEAD-sealed (`XChaCha20-Poly1305`) under a 256-bit key derived (Argon2id, `KdfParams::RECOMMENDED` — the same expense the vault file uses) from a **fresh user-supplied export passphrase that is independent of the vault master password** (key separation — a leaked archive passphrase never compromises the vault, a leaked vault password never compromises archives; D3), over a random 16-byte salt stored in the archive's plaintext header which is bound as the AEAD AAD (so a one-byte tamper with the magic / version / KDF params / salt / nonce / `ct_len` fails the open — not a mis-parse); a zxcvbn weak-passphrase *warning* is surfaced at export (not a hard gate — it is the only thing protecting a portable copy of every secret). A wrong export passphrase and a tampered archive both collapse to one typed error (`export_credentials`) — no oracle distinguishing them; timing is dominated by the intentionally-slow Argon2id derive. Both export FFI entries are reveal-class (Session spec §5.4 — "export vault" requires explicit presence even mid-session; routes through `check_session_freshness` + `ensure_presence_fresh` + `touch_session`, exactly like `reveal_*` / `export_payload`). The header parser strict-bounds + clamps a hostile archive's Argon2 params (memory ≤ 1 GiB, time-cost ≤ 8, parallelism ≤ 8, memory_kib × time_cost ≤ 3 Mi ≈ a couple seconds of Argon2id, all ≥ the crypto-crate floor) and `ct_len` (≤ 256 MiB) *before* any allocation or derivation, so a hostile file can't OOM us or make Argon2 run for minutes; `forbid(unsafe_code)` on every crate but `pangolin-ffi` rules out UB even on a hostile file; no panics on any malformed input. The serialized CBOR snapshot only ever lives transiently in `Zeroizing`, sealed before anything touches disk — the `.pvea` is ciphertext + a non-secret header only (the `no_plaintext_on_disk`-style scan is extended to the exported file); the `restore` path zeroizes the decoded snapshot after writing the new vault. Output files are created umask-respecting + `chmod 0o600` on Unix, never clobbered (`create_new(true)`), and the archive bytes go to a user-named file path — never stdout. The **plaintext-export branch** (`--plaintext` → a `.pvtxt` cleartext dump) is the one path writing cleartext secrets to disk — it is an *intentional* user choice, gated by presence **and** the §16 double-confirmation (a typed phrase + a second `[y/N]`) + a 30-second cooling-off delay + the warning copy + a prominent in-file banner; the FFI requires a structurally-valid single-use confirmation token so a UI can't skip the gesture (a missing/empty token → `export_not_confirmed`). The `restore` path creates a *fresh* `.pvf` from a decoded archive — it deliberately does **not** merge an archive into an *existing* vault, because pre-MVP-2 there is no signed Revision Log and grafting foreign revisions into a live vault on "it decrypted under the passphrase" alone would have no provenance check (deferred to MVP-2's signature-gated reconciliation). It also does not carry over the archived device trust list (the restored vault is its own fresh device). Verified by `pangolin-store/tests/export_roundtrip.rs` (round-trip + restore + `--accounts` subset + wrong-passphrase-no-oracle + tampered-archive), `pangolin-store/src/export.rs` unit tests (CBOR round-trip, seal/open, AEAD-AAD header-flip, hostile-header-rejected-before-KDF, truncated/bad-magic, plaintext-render-has-secrets-and-banner), and `apps/cli/tests/vault_export_restore.rs` (CLI export → restore round-trip + no-plaintext-on-disk scan + wrong-passphrase + tampered-archive + the `--plaintext` confirmation gate).

### Pangolin chain adapter (`pangolin-chain`)

> Source: `docs/issue-plans/P7.md` §"Failure modes considered" and the
> P7 build-gate. The `pangolin-chain` crate wraps the deployed
> `RevisionLogV0` contract behind an async `ChainAdapter` trait;
> `BaseSepoliaAdapter` is the production impl, `MockChainAdapter` the
> test-only impl gated behind the `test-utilities` feature.

1. **Adversary-controlled RPC returns garbage logs.** Defense: alloy's
   typed `sol!` binding decodes every `RevisionPublished` log
   structurally; a misbehaving response that does not match the ABI
   surfaces as `ChainError::Decode` and is never silently consumed.
   `pull_since` additionally re-checks the emitter address per log
   (audit MEDIUM-4 from the P6 chaincli build) — server-side filters
   already exclude foreign emitters, but a misbehaving RPC could
   splice in logs from other contracts that share the topic-0 hash;
   those are dropped without surfacing.
2. **Wrong-chain RPC redirects.** Defense: every constructor checks
   `eth_chainId` against the deployment file's declared `chain_id`
   at construction time and refuses to proceed on mismatch with
   `ChainError::WrongChain`. Same fail-closed posture chaincli holds
   (P6 audit M-3).
3. **Tampered deployment file.** Defense: `Deployment::load` enforces
   `chain_id == 84_532` (Base Sepolia) and the address is parsed from
   the file with a strict `Address::parse` that rejects malformed
   hex. The runtime-bytecode keccak cross-check is NOT mirrored from
   chaincli into pangolin-chain because the adapter is not the
   "truth-serum" surface — that's chaincli's role; an audit
   follow-up could lift the keccak check into the adapter at the cost
   of an extra `eth_getCode` per construction.
4. **Tx revert on publish.** Defense: receipt status flag = 0
   surfaces as `ChainError::Reverted { tx_hash }` carrying only the
   tx hash. The caller (P8 sync orchestration) decides retry policy.
5. **Chain reorg after a successful publish.** Defense: out of scope
   for P7. Every successful `publish` is treated as anchored even
   though the block could theoretically reorg out. P8 (sync
   orchestration) is responsible for detecting reorgs by re-checking
   `(block_number, log_index)` across pull cycles. Documented at the
   `BaseSepoliaAdapter` level; the trait does not expose a reorg API
   in v0.
6. **EVM address observability.** Defense (acknowledgement, not
   mitigation): the `evm::derive_evm_wallet` derivation produces a
   secp256k1 wallet whose 20-byte address is the gas-paying signer
   for every revision the device publishes. Anyone observing the
   chain learns that all revisions paid by this address come from
   the same device — i.e., the device's gas wallet is a stable
   pseudonymous identifier across writes from the same device. This
   is a known privacy tradeoff per D-006; the matching tradeoff for
   the device-id field on each revision is documented in the
   `RevisionLogV0` row above. Phase-2 mitigations (per-publish
   relayed payment, address rotation) are deferred to MVP-2 issue
   3.4.
7. **Ed25519 → secp256k1 derivation correlation.** Defense: the
   derivation goes Ed25519-sign over a domain message → 64-byte sig
   → HKDF-SHA256 expand → 32-byte secp256k1 scalar (rejection-sampled
   if it lands at zero or ≥ N). The HKDF expand is one-way: an
   attacker who recovers the secp256k1 scalar (e.g., from a leaked
   keystore) cannot recover the Ed25519 secret seed in polynomial
   time. Same-seed → same-address determinism is asserted by
   `evm::tests::derive_is_deterministic`; cryptographic separation
   is structural via HKDF.

   *Cryptographic assumption (P7 audit HIGH-1, named explicitly):*
   the security argument requires **Ed25519-deterministic-sign to be
   treated as a PRF in the seed when the message is fixed** —
   i.e., for a fixed domain message `m` and uniformly random 32-byte
   seed `s`, `Sign(s, m)` is computationally indistinguishable from
   uniform 64 bytes to any adversary that does not know `s`. This is
   not a standard Ed25519 hardness assumption, but it is structurally
   similar to one that deterministic Ed25519 already relies on
   internally: RFC 8032 §5.1.6 derives the per-signature nonce as
   `r = SHA-512(prefix || msg)` with `prefix` being a seed-expanded
   half, and the signature-unforgeability proof requires that round
   of SHA-512 to be PRF-like in `prefix`. The composition
   `Sign(seed, fixed-msg) → HKDF-Expand(...)` extends that one-round
   assumption to the full Ed25519 primitive plus an HMAC-SHA256-based
   HKDF expand; each additional layer can only preserve or strengthen
   the PRF property. Directionality: the leak of the secp256k1 scalar
   does NOT leak the Ed25519 seed (HKDF-Expand is one-way via HMAC
   preimage resistance); the reverse direction is the derivation
   itself, no hardness claim required.
8. **Signed-revision forgery (cross-device).** Defense: `signing.rs`
   binds the canonical hash to `device_id` (= the device's Ed25519
   verifying key bytes), and the signature is verified under that
   embedded pubkey. An attacker who substitutes a different `device_id`
   into a captured `SignedRevision` will not have the matching secret
   key to re-sign, and the existing signature will fail verification.
   Asserted by `signing::tests::substituted_device_id_fails_verification`.

   *v1 forward-prep — what actually transfers (P7 audit HIGH-2).* v0
   contract does NOT verify signatures on-chain (P5-1 audit threat #2);
   v1 (MVP-2 issue 2.1) will. The earlier framing claimed P7 was
   "forward-prep so MVP-2 doesn't need a client-side migration"; that
   overstated the case. Two plausible v1 paths exist and only the
   *canonical-hash* part is path-independent:

   - **Path A: Solidity Ed25519 verifier.** Cost ≈ 500k gas per
     verification (lower-bound figure for current pure-Solidity
     Ed25519 implementations). On Base mainnet (an L2) at typical 2026
     fees that's ~$0.01–0.02 per verify; on Ethereum L1 it's
     ~$25–50/verify, which makes Path A L2-only in practice. Under
     Path A, the existing `signing.rs` API surface
     (`SignedRevision`, the Ed25519 `signature` field, `device_id`
     semantics as Ed25519 verifying-key bytes, `build_signed_revision`,
     `verify_signed_revision`) survives unchanged.
   - **Path B: v1 switches to secp256k1.** Likely on L1 mainnet for
     cost reasons (`ecrecover` is the 3 000-gas precompile, ~150x
     cheaper than the cheapest Solidity Ed25519). Under Path B,
     `device_id` semantics change from Ed25519 verifying-key bytes to
     a secp256k1 EVM-address (or a separately-registered v1 device
     key per vault), the `signature` field type changes, and the
     canonical-hash construction may need re-keying so the digest
     binds the secp256k1 identity. The current `signing.rs` is
     Path-A-shaped; Path B would require a new `secp256k1_signing.rs`
     (or a refactor to a generic `Signer` trait abstracting both
     primitives), and stored `SignedRevision` records on disk would
     need to be re-signed before re-broadcast under v1.

   What survives in **both** paths: the canonical-hash structure
   (keccak256 of fixed-width fields, payload reduced to its keccak
   digest, versioned domain separator). What survives in **only
   Path A**: the Ed25519 signature semantics and the current
   `signing.rs` API. The honest claim is: "the canonical-hash
   construction transfers; the signature primitive may not".
9. **`MockChainAdapter` substitution in production.** Defense: the
   mock is `cfg(any(test, feature = "test-utilities"))`-gated.
   Production downstream consumers (`pangolin-store`, `pangolin-cli`)
   do not enable the `test-utilities` feature in their default Cargo
   manifests; doing so would require an explicit Cargo.toml edit
   that an audit reviewer would catch. The crate-level docstring
   names the gate as a security boundary (P7 success criterion 11).

#### Verification artifacts

The `tests/e2e.rs::no_plaintext_on_disk` property test is the load-bearing
cardinal-principle-2 verifier for this layer: it creates a vault, writes
≥100 accounts whose password fields carry unique random markers, locks +
closes the vault, and scans the raw bytes of the `.pvf` file (and the WAL
sidecar when present) for each marker — asserting zero matches across
all writes. Runs on every `cargo test` invocation in CI; a marker hit
would indicate a regression in the seal/AAD discipline and would block
the PR.

### Pangolin sync orchestrator (`pangolin-cli`)

> Source: `docs/issue-plans/P8.md` §"Threat model row" and the P8
> build-gate. The `pangolin-cli` binary at `tools/pangolin-cli/` is
> the user-facing PoC orchestrator that drives `pangolin-chain` to
> publish dirty revisions and pull chain events into the local
> vault. It does not introduce new cryptographic primitives; the
> threats below concern orchestration, idempotency, and the
> publish/pull state machine.

1. **Forged publish (foreign device claiming to be the user's).**
   Defense: revisions are signed by an Ed25519 device key via
   `signing::build_signed_revision`, which binds the canonical-hash
   digest to the device's Ed25519 verifying-key bytes (`device_id`).
   v0 contract does **not** verify on-chain; v1 will (MVP-2 issue
   2.1). Per Q6 plan-gate decision, `pull_all` runs a defense-in-
   depth `VerifyingKey::from_bytes` check on every event's
   `device_id` BEFORE invoking `Vault::ingest_chain_revision` — an
   event whose `device_id` is not a canonical Ed25519 point is
   refused at the device boundary. Full signature verification (the
   Ed25519 `verify` step over the canonical hash) is blocked until
   v1 records the signature on-chain; v0's `RevisionPublished` event
   ABI does not transport the signature bytes. *PoC two-key model
   note:* under the §A7 deviation from D-006, `pangolin-cli`
   generates an ephemeral signing `DeviceKey` per run (the
   gas-paying secp256k1 wallet is the Foundry keystore). MVP-1 will
   switch to `evm::derive_evm_wallet` so the same Pangolin device
   key signs revisions and pays gas — closing the deviation while
   preserving the canonical-hash discipline.
2. **Replay of an old signed revision.** Defense: the canonical-
   hash digest binds `parent_revision`. A revision with a stale
   parent cannot apply to a moved-on head; ingestion only
   structurally succeeds when the parent matches the local head OR
   surfaces as a fork (per Cardinal Principle 3 the chain is a log,
   not an authority — the local store records what the chain says
   happened). Re-publishing the same revision is additionally
   guarded by the A3 pre-publish check (`pull_since` →
   canonical-hash compare → skip-if-already-on-chain), preventing
   double-publish after a kill mid-publish.
3. **Network partition during chunked pull.** Defense: per A5, the
   chunked-pull design means a chunk failure preserves prior
   chunks' progress on disk via `advance_last_pulled_block` per
   chunk. Re-running `pangolin-cli pull` resumes from the new
   `last_pulled_block`. This resolves P7 audit MED-3 without
   altering the `ChainAdapter` trait shape.
4. **Dirty-entry leak.** Defense: the `dirty_accounts` table stores
   only `(account_id, revision_id, marked_at)`. `account_id` is
   already an attacker-observable identifier on-chain (the
   `RevisionPublished` event includes it as topic 2). `revision_id`
   is the canonical-hash digest of the revision payload, which
   becomes observable on chain anyway when the revision publishes.
   `marked_at` is a unix-ms timestamp local to the device — the
   only piece of new metadata, and it leaks only "when did this
   device edit account X for the n-th time," visible only to an
   attacker who has already compromised the local vault file (in
   which case they have the AEAD-protected ciphertext, dwarfing
   the timing leak).
5. **Replay protection across vaults.** Defense: `vault_id` is
   bound into `signing::canonical_hash`, so a revision signed for
   vault A cannot be replayed against vault B even by the same
   device. The chain event includes `vault_id` as topic 1; pulled
   events for vault B never include vault A's revisions because
   `pull_since` filters server-side on `vault_id` topic equality.
6. **Pre-publish check race.** Defense (acknowledgement): the A3
   pre-publish check runs `adapter.pull_since(vault_id,
   last_pulled_block, None)` before any re-attempt. The race is:
   two devices publish the same `(parent, payload)` simultaneously
   and both A3 checks succeed (each sees the chain without the
   other's revision yet). Both publishes succeed and create a fork.
   This is **expected behavior** — concurrent edits by independent
   devices fork; the fork surfaces on the next pull (A4); P9
   resolves it. The race is not a defect.
7. **Misuse of `MockChainAdapter` in the binary.** Defense:
   `pangolin-cli` does not enable `pangolin-chain`'s
   `test-utilities` feature in its default `[dependencies]` table
   — only in `[dev-dependencies]`. `MockChainAdapter` is therefore
   not constructible from the production build. Tests compile with
   the feature enabled; humans who try to substitute the mock for
   a real adapter would have to edit `tools/pangolin-cli/Cargo.toml`,
   which an audit reviewer would catch. P7 audit's gating
   discipline is inherited.
8. **Two-key model gas-wallet correlation (D-006 deviation).**
   Defense (acknowledgement): the gas-paying secp256k1 wallet
   (Foundry keystore) is **separate** from the device's Ed25519
   revision-signing key. The gas wallet's address appears as the
   `tx.from` on every publish; an observer who learns "address X
   paid gas for these revisions" can correlate all publishes from
   the same machine across all vaults that share the keystore. This
   is the same observability surface as P7 audit threat #6 (EVM
   address observability) and the same Phase-2 mitigation applies
   (per-publish wallet rotation via funder service, MVP-2 issue
   3.4). The PoC-specific divergence from D-006 (which mandates
   *one* keypair as both signer and gas payer) is documented in
   §A7 of the P8 plan; MVP-1 will switch to
   `pangolin_chain::evm::derive_evm_wallet` to satisfy D-006's
   wording.
9. **Forged-event-stream from compromised RPC.** Defense: per Q6
   defense-in-depth, every event surfaced by `pull_since` is
   subjected to a `VerifyingKey::from_bytes` check on its
   `device_id` before reaching `ingest_chain_revision`. An RPC
   that splices events with garbage `device_id` bytes is rejected
   at the device boundary. v0 contract has no signature semantics;
   this client-side check is the load-bearing defense until v1
   records the signature on-chain (MVP-2 issue 2.1).
10. **Tombstone / foreign-edit non-propagation across vault file
    copies (P8 fix-pass CRIT-1).** Defense: when
    `Vault::ingest_chain_revision` lands an event that does not
    match any of the three idempotency-merge arms, the
    `account_identities.frozen_pending_resolve` sentinel column
    is set to `1` for the affected account. Once set, every
    user-facing read (`get_account`, `list_accounts`, `search`,
    `reveal_password`, `reveal_notes`, `reveal_totp_secret`,
    `export_payload`) refuses on the account — `get_account`
    returns `None`; `list_accounts` and `search` filter the row
    out; the reveal/export ops surface
    `StoreError::AccountFrozenPendingResolve { account_id }`.
    Edits (`update_account`, `delete_account`, `mark_dirty`)
    refuse with the same error, so a user editing their stale
    plaintext copy of a chain-modified account cannot create a
    silent fork. The flag is cleared by the upcoming
    `pangolin-cli resolve` subcommand (P9). The defense closes
    the "vault A creates account, vault B copies the file, vault
    A tombstones on chain, vault B's `reveal_password` still
    returns plaintext" attack the §16.5 audit identified. The
    schema column is added at vault open via
    `migrate_frozen_pending_resolve_column` so existing
    P0..P7+P8-pre-fix vault files keep opening cleanly.
11. **Spoofed chain anchor on local pre-publish row (P8 fix-pass
    MED-1).** Defense: the third merge arm of
    `Vault::ingest_chain_revision` (the content-merge that stamps
    a chain anchor onto an existing local pre-publish row) now
    requires `device_id` to match alongside `(account_id,
    parent_revision, enc_payload, schema_version)` and
    `chain_tx_hash IS NULL`. An attacker controlling the RPC
    would have to produce an event whose `device_id` matches the
    victim's locally-stored row's `device_id` — under the PoC
    two-key model that field is set from `Vault.device_id`
    (random per vault-handle bytes generated at `Vault::open`),
    not visible on the chain. A forged event with a different
    `device_id` falls through to the genuine-foreign-INSERT path,
    which sets the CRIT-1 freeze sentinel — i.e., a forgery
    surfaces as a refused-read rather than a silent merge. The
    audit's preferred re-fetch-via-`get_revision` approach was
    rejected because under attacker-controlled-RPC both
    directions of the conversation are spoofable; the device_id
    binding is a content-bound check that doesn't depend on the
    transport. Trade-off: the legitimate own-publish round-trip
    under PoC two-key model also fails the device_id match
    (publish generates an ephemeral signing `DeviceKey` per call
    whose pubkey differs from the local row's random
    `device_id`), so it routes through idempotency arm #2
    `(account_id, chain_tx_hash, block, log)` after
    `mark_published` has stamped the local row's chain anchor.
    Cross-vault round-trips (vault B pulling vault A's
    publishes) intentionally trigger the freeze under threat #10
    above. MVP-1's switch to the derived wallet (D-006) aligns
    local-row and chain-event `device_id`, restoring silent
    cross-device merge under the non-attack case while
    preserving the device_id binding's defense.

12. **Forged resolve (foreign device claiming to be the user's,
    publishing a merge revision under the user's account).**
    Defense: the merge revision is signed by the device's
    Ed25519 `DeviceKey` via `signing::build_signed_revision`,
    same path as `publish`. The canonical hash binds
    `parent_revision` (= the chosen head's `revision_id`),
    `account_id`, `vault_id`, `device_id`, and `enc_payload`. v0
    contract does not verify on-chain; v1 will (MVP-2 issue 2.1).
    Per Q6 defense-in-depth, the receiving device's `pull_all`
    runs `VerifyingKey::from_bytes` on the merge event's
    `device_id` before invoking `Vault::ingest_chain_revision`
    — same gate that catches forged publish events. The PoC
    two-key model carries forward unchanged: resolve generates
    an ephemeral `DeviceKey` per run.
13. **Replay of an old resolve, AND partial-failure recovery
    between `adapter.publish` and `clear_frozen` (P9 fix-pass
    HIGH-1).** Defense: the canonical hash binds
    `parent_revision`. A resolve replay against a moved-on head
    (someone else has published a descendant in the meantime,
    advancing the head past the chosen one) lands as another
    fork rather than a duplicate, surfacing on the next pull as
    the concurrent-resolve race described in P9 plan §A7.
    Re-publishing the same merge revision with a stale parent
    is additionally guarded by the resolve flow's pre-publish
    check (Q7-APPROVED): `pull_all` runs first and then
    re-validates `account_heads`; if the chosen revision is no
    longer a head OR a NEW head appeared,
    `ResolveError::ChainMovedDuringResolve` aborts the resolve
    cleanly.

    **Recovery from a kill between `adapter.publish` and
    `clear_frozen` is via the `pending_merges` stash** (added
    by P9 fix-pass HIGH-1; deepened by P9 fix-pass 2 HIGH-1;
    resolves the audit's "the user is permanently stuck —
    frozen account, unresolvable" finding). The merge-revision-
    build state — ephemeral `DeviceKey` secret seed (32 bytes),
    AEAD nonce (24 bytes), and the AEAD-sealed merge revision
    ciphertext — is persisted to a new SQLite table
    `pending_merges` BEFORE `adapter.publish`. The retry path
    looks up the stash via `Vault::take_pending_merge`,
    reconstructs the SAME `DeviceKey` from the stashed seed,
    and re-uses the SAME ciphertext + nonce — so the canonical
    hash is bit-equal across retries and the chain event from
    the prior partially-completed run can be matched on retry.

    **Re-ordered `sync::resolve_one` (P9 fix-pass 2 HIGH-1
    deeper fix).** `take_pending_merge` runs BEFORE the
    `pull_all` + `chain_moved` guard. After `pull_all`, the
    stash's deterministic canonical hash is matched against
    the post-pull LOCAL revisions table (the merge revision is
    ingested by `pull_all` if the prior publish landed); if a
    matching row with a populated chain anchor exists,
    `resolve_one` takes the `AlreadyOnChain` path: skips
    publish, calls `clear_frozen` (which advances
    `head_revision_id` to the merge-rev id and clears the
    freeze flag in one transaction), and clears the stash. The
    `ChainMovedDuringResolve` branch only fires when the chain
    has a head NOT matching any stash for the user's
    `(account_id, --keep)` pair — kill-after-publish-success
    recovery is genuinely complete end-to-end, not just kill-
    before-publish-reaches-chain. `clear_frozen` succeeds even
    on a foreign-ingested row whose `enc_nonce` is the
    placeholder zero, because `clear_frozen` only validates
    head-membership + advances the head pointer — it does not
    decrypt the row.

    **Orphan stash pruning (P9 fix-pass 2 MEDIUM-2).**
    `Vault::prune_orphan_pending_merges(account_id)` deletes
    stash rows whose `target_head_id` is no longer a current
    head. Called from `pull_all` after each chunk's per-
    account ingest sequence completes (separate transaction,
    so the per-chunk all-or-nothing discipline is preserved),
    and from `resolve_one` alongside `take_pending_merge`. A
    user-changed `--keep`, `ChainMovedDuringResolve`, or any
    other path that abandons a stash row is bounded — the
    32-byte Ed25519 seed does not accumulate at rest
    indefinitely. Three tests pin the prune semantics:
    `prune_orphan_pending_merges_removes_non_head_targets`,
    `prune_no_op_when_all_targets_are_heads`,
    `prune_no_op_on_empty_table`.

    Without the stash + the re-ordered flow, each retry would
    generate a fresh ephemeral `DeviceKey` AND a fresh AEAD
    nonce — the canonical hash would differ every run, the
    chain event from the prior run could not be matched, and
    `ChainMovedDuringResolve` would fire on the merge-revision-
    foreign-ingest path before any recovery code ran, leaving
    the user permanently stuck with a frozen account.

    The stash row contains an Ed25519 secret seed at rest in
    the vault file as a SQLite BLOB column, NOT additionally
    AEAD-sealed. The reasoning is bounded-marginal-exposure:
    at-rest exposure of the `.pvf` file already compromises
    the VDK and worse (every account's encrypted ciphertext,
    every chain anchor, every `account_identities` row), so
    the marginal exposure of an ephemeral merge-signing key
    that is discarded after `clear_frozen` succeeds (and
    additionally pruned per MEDIUM-2 if abandoned) is
    bounded. The stashed `enc_payload` is AEAD ciphertext
    (NOT plaintext — cardinal principle 2 holds; the seal
    happens inside `Vault::build_merge_payload_for_resolve`
    BEFORE the stash). Tests pinning the recovery semantics:
    `stash_take_clear_round_trip`,
    `stash_persists_across_close_open`,
    `take_returns_none_for_nonexistent_account`,
    `pending_merge_zeroizes_secret_on_drop`,
    `resolve_idempotent_after_partial_failure_via_stash` (the
    publish-failed retry test),
    `resolve_recovers_from_kill_after_publish_success` (the
    kill-after-publish-success retry test added by P9 fix-pass
    2), plus the three prune tests above.
14. **Frozen flag cleared without publish.** Defense: the
    `Vault::clear_frozen` API takes `chosen_revision_id` as a
    parameter and atomically advances `head_revision_id` to it;
    the resolve flow ALWAYS calls `clear_frozen` only after a
    successful publish + ingest of the merge revision. There is
    no API path that clears the freeze flag without a
    corresponding revision row in the local store —
    `clear_frozen` errors with `StoreError::RevisionNotFound`
    if the supplied `chosen_revision_id` does not exist as a
    `revisions` row for the account. A malicious local actor
    with vault-file access could `UPDATE account_identities SET
    frozen_pending_resolve = 0` directly via sqlite tooling,
    but that's the same as them tampering with any other row —
    not a defense the application layer can mount.
15. **User keeps an attacker-controlled head (HIGH-1 from P8
    audit).** Defense (acknowledgement, UX-only): under the
    threat model where a malicious RPC injects events with
    garbage `device_id`, P8 fix CRIT-1 freezes the account so
    the user cannot read the stale plaintext. If the user then
    runs `pangolin-cli resolve --keep <id>` where `<id>`
    references one of the attacker-injected events, they have
    explicitly adopted attacker-controlled state. The
    mitigation is UX: `pangolin-cli resolve` prints the
    metadata of each candidate head so the user can spot an
    unfamiliar `device_id` (a foreign device they don't
    recognise). Full defense requires v1 contract on-chain
    signature verification (MVP-2 issue 2.1); PoC ships with
    the UX surfacing as the only defense against this class.
    Documented as a known UX-bound gap.
16. **`Vault::read_payload_plaintext_for_resolve` as a
    documented freeze-guard bypass.** The resolve flow needs
    to read the chosen revision's plaintext to re-seal it
    under the merge revision's AAD (per P9 plan §A2 — a
    byte-copy of the source ciphertext would carry the source
    row's `parent_revision_id` baked into the AAD, producing
    an unopenable merge row). The bypass is gated by the
    user's `--keep <id>` argument as proof-of-intent: the user
    has named the specific revision they want to ratify, so we
    trust the read for that one revision for the duration of
    one resolve invocation. The accessor is loudly documented
    (`DOCUMENTED FREEZE-GUARD BYPASS — DO NOT CALL FROM ANY
    PATH EXCEPT pangolin-cli resolve`) and has a single
    in-process caller. Cross-account substitution is blocked:
    supplying a `revision_id` that belongs to a different
    account collapses to `StoreError::AccountNotFound` so the
    method is not an oracle. Per P9 plan Q6 / §A8, this is the
    accepted design trade-off; an alternative
    "user re-supplies password as fresh proof" model has
    higher UX friction without measurable security gain
    (the user is already past the unlock proof at the
    `--keep` step). MVP-1 may revisit if audit feedback
    surfaces a stronger bypass discipline.
17. **Concurrent-resolve race (P9 plan §A7 — Q2 APPROVED to
    ship without a guard).** Defense (acknowledgement):
    devices A and B running `pangolin-cli resolve` on the same
    forked account concurrently both pass their pre-publish
    re-pull (each sees the chain without the other's merge
    yet) and both successfully publish. The result is yet
    another fork: parent = chosen_head, two children (A's
    merge and B's merge). The next pull from any device
    surfaces the new fork; the user resolves it again. This is
    the same class of race as P8 threat #6 (concurrent edits
    by independent devices fork; the fork surfaces on next
    pull). The recovery is mechanical (re-resolve) and the
    race window is small (concurrent resolve attempts on the
    same fork require both devices to be online and aware of
    the fork at the same instant). P11 may add an interactive
    freshness guard ("verify chosen head is still a head as of
    right now"); P9 ships without it per Kelvin's locked
    answer Q2.
18. **Forged tombstone (foreign device claiming to delete the
    user's account).** Defense: tombstone revisions are signed
    by the device's Ed25519 `DeviceKey` via
    `signing::build_signed_revision`, same path as publish +
    resolve. The canonical hash binds `parent_revision`,
    `account_id`, `vault_id`, `device_id`, `schema_version`,
    and `enc_payload`. v0 contract does not verify on-chain;
    v1 will (MVP-2 issue 2.1). Per Q6 defense-in-depth, every
    chain event including tombstones passes the
    `VerifyingKey::from_bytes` check in `pull_all` before
    reaching `ingest_chain_revision`. Under the PoC two-key
    model (P8 §A7) carries forward unchanged — the ephemeral
    signing `DeviceKey` per run discipline applies to
    tombstone publishes too. The plaintext-level payload's
    `account_id` field added in P10-1 is a defense-in-depth
    cross-check against the AAD-bound `account_id`: an attacker
    who has somehow constructed a valid AEAD seal under the
    user's VDK but with a wrong-account_id payload is rejected
    inside `detect_tombstone_bit_at_ingest`. The cross-check is
    constant-time via `subtle::ConstantTimeEq::ct_eq`; mismatch
    silently returns `is_tombstone = 0`, preserving the
    non-oracle property of the ingest decoder (the same bucket
    as AEAD failure / CBOR failure / locked vault — no error
    variant escapes). The freeze sentinel still fires for the
    row's INSERT, so the user-facing safety property is
    unaffected.
19. **Tombstone-bit non-propagation under PoC two-key
    foreign-ingest (P8 audit CRIT-1 origin, structurally
    closed by P10-2).** Defense (acknowledged PoC limitation):
    under PoC two-key, the chain event ABI carries no AEAD
    nonce, so `ingest_chain_revision` stores a placeholder
    zero nonce and cannot decrypt foreign events. The
    opportunistic-decode logic in P10-2 falls through to
    `is_tombstone = 0` for the affected row, and the existing
    P8 freeze sentinel fires. The user-facing consequence is
    "the foreign tombstone is not auto-applied; the account is
    frozen until the user resolves." The user resolves by
    running `pangolin-cli resolve --keep <chosen-revision-id>`
    against the tombstone revision id (P9's resolve flow's
    tombstone branch produces a tombstone merge per §A5), and
    the post-resolve state has `is_tombstone = 1` correctly
    set on the merge revision. Closed by MVP-1's
    nonce-on-chain (the `RevisionPublished` event ABI gains a
    nonce field; foreign events become decryptable; the
    opportunistic-decode logic becomes functional without a
    code change). Documented as a known PoC limitation. The
    structurally-correct opportunistic-decode code is in place
    (P10-2 replaced the audit-flagged hardcode
    `is_tombstone_i64 = 0` comment) and exercised by a
    synthetic-decryptable-tombstone test
    (`ingest_synthetic_decryptable_tombstone_event_sets_bit`).
20. **Resurrection of a tombstoned `account_id`.** Defense:
    `Vault::add_account` refuses with `StoreError::Internal`
    if the (randomly-derived) `account_id` collides with a row
    whose `tombstoned = 1` after `ADD_ACCOUNT_RETRY_BUDGET`
    (4) attempts. Under PoC the random-32-via-sqlite-derived
    `account_id` makes this collision cryptographically
    negligible (per-attempt probability `N / 2^256`; 4-attempt
    bound `4 * N / 2^256`, vanishingly small for any plausible
    vault size), so the guard is defense-in-depth + spec
    compliance with the append-only invariant (Cardinal
    Principle 4). MVP-1 may revisit for a deliberate "undelete"
    feature; under PoC, undelete = create a new account with
    a fresh `account_id`. The retry budget is bounded; failure-
    after-4 surfaces `StoreError::Internal`, NOT a silent skip.
21. **Offline edit replay (a queued dirty marker for an edit
    made on device A is published from a different device B).**
    Defense: dirty markers are local-only — they live in the
    `dirty_accounts` table inside the encrypted `.pvf` file;
    another device cannot read them without the `.pvf` file.
    Under the PoC two-key model, the same `.pvf` file copied
    to device B (the cross-vault case) shares the dirty list
    with device A; device B running `publish_all` would
    publish A's queued entries under B's ephemeral signing
    `DeviceKey`. **This is the same threat as #5
    (cross-vault replay protection).** The `vault_id` binding
    in `signing::canonical_hash` ensures the published
    revisions are cryptographically tied to the shared vault;
    the `device_id` binding identifies B's device as the
    publisher (which is correct — B is the one who broadcast
    the transaction). Recovery: either device pulling sees
    both the original dirty entries and B's
    ephemeral-signing-key publish; the freeze sentinel fires
    on A's next pull (since B's `device_id` != A's
    `device_id`); A resolves. **MVP-1's switch to derived
    wallet (D-006) closes this — both devices have the same
    `device_id`; cross-device publish is structurally
    indistinguishable from same-device publish.**
22. **Tombstone-bit at-rest modification.** Defense
    (defense-in-depth): the `is_tombstone` bit on a
    `revisions` row is set by either (a)
    `Vault::delete_account` at the local-write site (own-
    delete), or (b) `Vault::ingest_chain_revision`'s
    opportunistic-decode at chain-ingest (P10-2 / P10-3,
    `tombstoned = 1` flag flipped when the AEAD plaintext
    decodes to `TombstonePayload`). Both writes happen
    INSIDE a `BEGIN IMMEDIATE … COMMIT` transaction
    alongside the `revisions` INSERT; never UPDATEd later.
    A malicious local actor with vault-file access could
    `UPDATE revisions SET is_tombstone = 0` directly via
    sqlite tooling, but that's the same as them tampering
    with any row (e.g., `enc_payload`); not a defense the
    application layer can mount against an attacker with
    raw filesystem access. The AEAD seal binds the plaintext
    to its AAD (`vault_id, account_id, parent_revision,
    schema_version`); a tampered tombstone whose plaintext
    no longer decodes as `TombstonePayload` would be
    detected by the opportunistic-decode path (the bit
    stays 0 and the freeze sentinel fires) at the next
    chain ingest of a successor revision. Under the PoC
    two-key model the marginal exposure of the bit value
    is bounded — see also #19 for the propagation gap. The
    test-utilities `MockChainAdapter::set_disconnected`
    toggle (P10-4) is `#[cfg(any(test, feature =
    "test-utilities"))]`-gated and cannot be constructed
    by a production binary; the offline-edit-then-online-
    publish E2E test pins that the freeze sentinel does
    NOT fire during an offline session (no chain ingest
    happened — verified by
    `offline_session_does_not_set_freeze_sentinel`).
23. **Password disclosure via process listing (`ps aux` /
    `/proc/<pid>/cmdline`) on `pangolin-cli account add` /
    `account update`.** Defense: P11A REFUSES to ship a
    `--password <flag>` argument form. The only paths to
    provide a password are interactive terminal prompt
    (`rpassword::prompt_password`, no echo), stdin
    (`--password-stdin`, redirected by the user), or
    auto-generation (`--generate-password`, written to
    stderr inside a save-this-now block). Same shape as
    `pass`, `1password-cli`, `bw`, `op`. The clap-derive
    schema for `AccountAddArgs` and `AccountUpdateArgs`
    has no `password: Option<String>` field; a future PR
    that re-introduces one would surface in the
    `account_add_password_stdin_and_generate_conflict`
    test plus the SIGNOFF spot-check of `--help` output.
    The TOTP secret follows the same discipline
    (`--totp-stdin` / interactive only; no
    `--totp-secret <flag>`). Notes accept the lower-tier
    `--notes <str>` flag form per A5's documented
    trade-off (notes are not load-bearing for account
    access; user accepts the shell-history risk). The
    `--vault-password <flag>` and `--keystore-password
    <flag>` arguments inherited from P8 retain the same
    "echoes in ps; CI only" caveat in their `--help`
    text; P11A does NOT extend that pattern to credential
    passwords. The `account show --reveal-password`
    output prints to stdout; shell-history capture is the
    user's risk to manage (no different from
    `pass show <name>`). An additional vector is `2>file`
    redirect of `--generate-password` output, which would
    persist the generated password to disk; document in
    user-facing help text and treat as user responsibility.
24. **Account-show plaintext leak via shell history /
    terminal scrollback.** Defense (acknowledgement, UX-
    bound): the `--reveal-password` / `--reveal-notes` /
    `--reveal-totp-secret` flags require a presence proof
    via the `confirm_presence` prompt — the user types
    `'y'` at the prompt before any reveal call fires.
    Once revealed, plaintext is on the user's terminal
    scrollback; the CLI cannot retract it. The presence
    prompt is the load-bearing mitigation; the prompt's
    wording explicitly names the action ("presence
    required to reveal password for account <hex>: type
    'y' and press enter:"), so a user who didn't intend a
    reveal can decline. Multi-flag invocations
    (`--reveal-password --reveal-notes
    --reveal-totp-secret`) prompt ONCE per A7 and produce
    three internal `PressYPresenceProof::confirmed()`
    instances against the single user gesture; the same
    shape MVP-1's hardware attestation will surface.
    Default `account show` (no reveal flags) prints
    non-secret fields only and emits no presence prompt.
    JSON output omits (rather than `null`-fills) the
    unrevealed secret fields — verified by inspection of
    `run_show`'s JSON-building branch. An additional risk
    is attacker-controlled display names containing
    terminal escape sequences; sanitization via
    `sanitize_for_display` strips C0/DEL control
    characters before printing in delete confirmation
    prompts and other display contexts.
25. **Tombstone replay via `account delete`.** Defense:
    same protection as P10's tombstone discipline (rows
    #20, #22) — the tombstone revision's canonical hash
    binds `(vault_id, account_id, parent_revision,
    schema_version, enc_payload)`; replay against a
    moved-on head produces a fork rather than a duplicate
    (Cardinal Principle 4 holds at the `delete` site
    too — same chain ordering as publish/update).
    `Vault::delete_account` refuses on already-tombstoned
    accounts with `StoreError::AccountTombstoned`; the
    CLI surfaces "already been deleted (tombstoned).
    Idempotency-by-clear-error: re-deletion is refused"
    rather than silently re-tombstoning. The append-only
    invariant (P10 anti-resurrection: `Vault::add_account`
    refuses to reuse a tombstoned `account_id`) extends
    to the CLI boundary unchanged.
26. **Reveal-confirmation phishing under `PoC`
    `PressYPresenceProof`.** Defense (acknowledgement,
    `PoC` limitation): the `PoC`'s `'y'` keystroke proof
    is a stand-in for MVP-1's hardware attestation; under
    `PoC`, an attacker who has stolen the user's session-
    active vault state (e.g., post-unlock memory dump, or
    unattended unlocked terminal) can fire any reveal
    call by typing `'y'` at the prompt. The MVP-1
    hardware-attestation switch closes this; under
    `PoC`, the `'y'` keystroke is the only proof-of-
    presence available. P11A inherits this limitation
    unchanged. The `'y'` prompt's wording explicitly
    names the account (account id + which secret) so an
    unattended terminal attacker who automates the prompt
    response leaves distinguishable per-account audit
    lines on stderr. The `cfg(test)`-only
    `TEST_AUTO_CONFIRM_PRESENCE` and
    `TEST_AUTO_CONFIRM_DELETE` thread-local seams in
    `commands/account.rs::tests` are unit-test
    ergonomics aids; production binaries cannot reach
    them (the seams are gated on `cfg(test)` and the
    `tests` module is private to the source unit).
    Documented as a known `PoC` limitation; closed by
    MVP-1's hardware path.
27. **`account update` / `account delete` of frozen
    account.** Defense: `Vault::update_account` and
    `Vault::delete_account` refuse with
    `StoreError::AccountFrozenPendingResolve` (P8 CRIT-1
    freeze guard); the CLI's `run_update` and
    `run_delete` ALSO refuse via a pre-presence /
    pre-prompt guard (membership probe in
    `list_frozen_accounts`) so the user is not asked for
    a presence proof or confirmation on a frozen entry.
    The user-facing error message includes the resolve
    hint ("Run `pangolin-cli resolve --account-id <hex>
    --keep <head>` first"). The user cannot accidentally
    write a stale-plaintext-based update to a frozen
    account (Cardinal Principle 4 protected at the CLI
    boundary). Per Q8 there is no `--force` flag to
    bypass the freeze guard on either verb. Resolve flow
    per P9 is unchanged.
28. **Vault provisioning password leak (process listing,
    shell history, scrollback) AND `.pvf` overwrite
    hazard AND first-time-creator UX failures (empty
    password, parent-dir traversal, mid-create races).**
    Defense (multi-fold): `pangolin-cli vault create`
    REFUSES to ship a `--password <flag>` argument form;
    locked at the clap surface in `cli.rs` and pinned by
    `vault_create_does_not_accept_password_flag`. The two
    paths to provide a vault password are interactive
    terminal prompt (`rpassword::prompt_password`, no
    echo) with confirmation re-prompt and bounded retry
    budget (2 retries; 3 attempts total) or stdin
    (`--password-stdin`, redirected by the user). Same
    shape `pass init` and `bw create` use. The empty-
    password guard (`reject_empty_password`, reused from
    P11A's MED-1 fix per plan §A4) fires on both paths
    before any library call. The vault-creation password
    is the master credential for the new vault — its
    leak compromises every account stored inside; the
    input-discipline carries P11A's row #23 weight
    forward to this higher-tier secret. Path-traversal
    handling: `--path` is processed via
    `parent.canonicalize() + file_name` (§A5; note
    `Path::canonicalize` requires file existence, which
    the not-yet-created target lacks); relative-path
    traversal and symlink redirection on the parent
    surface as the canonical absolute path in the
    success message and any error message, matching P8
    fix MED-3's discipline. A `--path` with no
    `file_name` (root, trailing slash, `..`) is rejected
    with "--path must name a vault file (got <path>)"
    before any password prompt. A `--path` whose parent
    directory does not exist surfaces "could not
    canonicalize parent directory of <path>" before any
    password prompt — saves a wasted password entry on
    the most common typo. Overwrite refusal: a pre-flight
    `path.exists()` check at the CLI boundary plus the
    library's `Vault::create`'s `path.exists()` +
    `acquire_lock`'s `OpenOptions::create_new(true)`
    write open close the TOCTOU race between the
    pre-flight and the library call (§A8); two
    concurrent `vault create` calls against the same
    path produce one `Created` and one
    `AlreadyExists`/`AlreadyOpen` cleanly, with the
    loser's partial-file cleanup performed by
    `Vault::create`'s existing
    `std::fs::remove_file(path)` on-error path.
    NO `--force` flag exists to overwrite an existing
    `.pvf`; the user explicitly `rm`-then-rerun if they
    want to start over (matches `git init`'s discipline).
    POSIX file-mode hardening (Q4): after `Vault::create`
    succeeds, the new file is chmod 0o600 on Unix
    targets via
    `std::os::unix::fs::PermissionsExt::set_mode`.
    Best-effort — emits a warning but does not abort if
    the chmod fails (e.g., on a filesystem that ignores
    POSIX bits); the vault content remains AEAD-
    encrypted under the user's password regardless.
    No-op on Windows (file ACLs are inherited from the
    parent directory; tightening is the user's
    responsibility). KDF parameters are hard-coded
    `KdfParams::RECOMMENDED` (256 MiB / t=3 / p=1, the
    same value `Vault::create` already pins in vault.rs
    L228); no `--kdf-params` selector at the CLI surface
    per §A6, so every PoC vault produced by
    `pangolin-cli vault create` has identical KDF
    strength. **No password recovery (Q5).** Pangolin
    has no password-recovery mechanism under PoC; loss
    of the vault password permanently locks every
    account stored inside. The `vault create --help`
    output (and the long-doc rendered by clap-derive)
    surface this explicitly via two pinned phrases:
    "no password-recovery mechanism" and "permanent data
    loss" — verified by
    `vault_create_help_warns_no_password_recovery`. A
    user reading `--help` BEFORE running the command is
    expected to choose a password they can remember (or
    write down securely); MVP-1's Recovery flow per
    Whitepaper §10 will replace this hard-fail with the
    epistemic-recovery procedure. Inherits the
    `rpassword`-returns-unzeroized-`String` PoC
    limitation from row #23 unchanged;
    `--password-stdin` is the exposure-free path.
    Audit-relevant test pins: `vault_create_succeeds_at_new_path`
    (round-trip), `vault_create_rejects_existing_path`
    (overwrite refuse), `vault_create_rejects_empty_password_via_stdin`,
    `vault_create_rejects_empty_password_via_prompt`,
    `vault_create_rejects_path_in_nonexistent_parent`,
    `vault_create_canonicalizes_path_in_success_message`,
    `vault_create_rejects_path_with_no_filename`,
    `vault_create_chmod_0600_on_unix` (cfg(unix)),
    `vault_create_password_stdin_path_works`,
    `vault_create_with_print_id_outputs_hex_to_stdout`,
    `vault_help_avoids_forbidden_user_facing_terms`
    (§3.5 / §A14), and the round-trip integration test
    `vault_create_then_account_add_round_trip` (spawns
    the binary, pipes the password via stdin, asserts
    the produced vault is consumable by `account add`).
    **P11B fix-pass updates (audit M-1, M-2, L-1):** the §16.5
    fix-pass closed two MEDIUM findings against this row.
    M-1 (chmod race window) — the previous design relied on a
    post-create `chmod 0o600` to tighten the file from the
    process-default `0o644` (under a typical `0o022` umask). The
    audit identified a window between `Vault::create`'s
    `OpenOptions::create_new(true)` and `pangolin-cli`'s
    `restrict_vault_file_mode` chmod during which an attacker with
    a pre-positioned `inotify_add_watch` (or equivalent) could read
    the freshly-written `.pvf`. The file content includes the
    offline-Argon2id-bruteforce preconditions (`kdf_salt`,
    `kdf_params`, `wrapped_ciphertext`, `wrap_nonce`); strong
    passwords are still defended by the Argon2id RECOMMENDED expense,
    but weak passwords would be exposed to an offline cracking
    attempt. The fix moved the umask install into `Vault::create`
    itself: an RAII `UmaskGuard` (built on `nix::sys::stat::umask`,
    which is a safe wrapper — no `unsafe` needed at our call site)
    sets `0o077` BEFORE the lock-file or `.pvf` are created and
    restores the previous umask on `Drop`. Both files are now born
    at mode `0o600` on Unix without any intervening permission
    tweak. `nix` is `cfg(unix)`-gated so Windows does not pull it,
    and the workspace `unsafe_code = "deny"` plus
    `pangolin-store`'s `forbid(unsafe_code)` and `pangolin-cli`'s
    `forbid(unsafe_code)` lints are unchanged. The CLI's existing
    `restrict_vault_file_mode` chmod is preserved as belt-and-
    braces defense-in-depth (e.g., for hosts with an unusual
    `0o000` default umask that would still leave the file at a
    too-permissive mode), but it is no longer the primary defense.
    Test pins: `umask_set_to_0o077_around_vault_create_unix` (the
    new file is `0o600` immediately on `Vault::create` return,
    BEFORE any chmod), `umask_restored_after_vault_create` (a
    sacrificial probe-file created after the call observes the
    user's normal umask, confirming the guard's `Drop` restored
    correctly), plus the existing `vault_create_chmod_0600_on_unix`
    which continues to pass against the now-redundant CLI chmod.
    M-2 (symlinked `--path` redirect) — the previous overwrite
    pre-flight used `Path::exists()`, which follows symlinks. A
    `--path` pointing at a *dangling* symlink (target missing) slid
    past the check and `Vault::create` would then write through the
    symlink to the target, silently provisioning the vault at an
    unintended location. The fix replaces the pre-flight with a
    `std::fs::symlink_metadata` match: a symlink at the final
    component is refused with `"refusing to create vault at
    <path>: path is a symlink; resolve to the real target and pass
    that explicitly"` — matching `git init`'s discipline. A
    pre-existing regular file still surfaces the original
    `"vault file already exists"` overwrite-refuse error.
    Parent-component symlinks remain intentionally followed (the
    existing `parent.canonicalize()` resolves them, which is the
    documented `--path` semantics). Test pin:
    `vault_create_refuses_symlinked_path` (cfg(unix); plants a
    dangling symlink and asserts both refusal AND that no vault
    leaked through to the target). L-1 — the chmod-failure
    warning prefix is now `WARNING:` (all caps) per the project
    rubric; previously it was `warning:`. Cosmetic, no semantic
    change.

### Session policy engine

> Source: `docs/issue-plans/1.4.md` + `docs/architecture/session.md` + session spec §2.3 / §5–§8. The access-control state machine: the start = 2-proof / maintain = 1-proof / expired = 2-proof again rule (cardinal principle 5), configurable idle, the 4 h absolute ceiling, the 60 s presence-freshness window, the reveal-class taxonomy. Lives in `crates/pangolin-store/src/{session,vault}.rs`; re-exported through `pangolin_core::session`.

1. **Attacker with brief physical access to an unlocked machine reveals a credential.** Defense: reveal-class operations (`reveal_current_password`, `reveal_password_history`, `reveal_notes`, `reveal_totp_secret`, `export_encrypted`, `export_plaintext`, the `Replaced` branch of `capture_authority_register`) require a **fresh presence proof** within the 60 s `PRESENCE_FRESHNESS` window. The unlock itself stamps `last_presence_at`; without re-prompting (or within the dedup window) reveals succeed; past the window a stale proof maps to `StoreError::PromptTimedOut` — distinct from `AuthenticationFailed` so the failure mode is unambiguous. Session-class ops (`account_list`, `account_search`, `device_list`, `capture_authority_list`, the `Created`/`NoOp` branch of `capture_authority_register`) skip the freshness gate but still require an active non-expired session.
2. **Attacker keeps a session alive indefinitely via background activity.** Defense: every successful op extends `expires_at` via `next_idle_deadline(now, session_started_at, idle)` — which caps at `session_started_at + ABSOLUTE_MAX_DEFAULT` (4 h). The cap is **not configurable**; the longest configurable idle window (`Min240` = 4 h) is *equal* to the absolute ceiling, so picking it means idle == absolute and the session can't be extended at all. Verified by `vault::tests::absolute_max_caps_active_session` (4 h of constant activity → next op surfaces `SessionExpired`).
3. **Attacker leaves the device with an unlocked vault and walks away.** Defense: the idle timer is per-vault-meta (`meta.session_idle_secs`), default 15 min for vaults predating 1.4, configurable to 5 / 15 / 30 / 60 / 240 min or `-1` = "until device lock" (the `device_locked()` hook). On expiry: drop the `ActiveState` (zeroizing the decrypted cache + freeing the `:memory:` FTS5 index + dropping the `DeviceKey`) → flip to `Expired` → return `SessionExpired` on the next op. `check_session_freshness` is the strict gate at the top of every cache-bearing op.
4. **Attacker uses a stale presence proof to confirm a reveal long after the user prompted.** Defense: the 60 s `PRESENCE_FRESHNESS` window is enforced by `ensure_presence_fresh` BEFORE the reveal executes. Dedup within the window does NOT re-stamp `last_presence_at`, so continuous reveals cannot extend the window (verified by `vault::tests::presence_dedup_does_not_extend_window`). A stale proof → `PromptTimedOut`; an unverified proof → `AuthenticationFailed`. Distinct error variants forbid an account-existence oracle (audit M1 of 1.4).
5. **Attacker observes that a reveal failed with `AccountNotFound` vs `AuthenticationFailed` to enumerate accounts.** Defense: every reveal-class entry point checks session freshness + presence freshness BEFORE looking up the account, so a stale-session caller cannot distinguish "no such account" from "wrong proof". Session-class lookups (`account_list`, `account_get`) operate on the decrypted cache so don't surface storage-layer existence either way.
6. **Attacker tampers with the `meta.session_idle_secs` row to make sessions never expire.** Defense: the column is INSIDE the encrypted vault (it's a SQLite row, but the *enforcing* code is the client). An attacker who can write to the unlocked vault file is already a kernel-level attacker (out of scope) — but defense in depth: `SessionDuration::try_from_meta_secs` rejects any value outside the recognised `{300, 900, 1800, 3600, 14400, -1}` set with `StoreError::Validation`, so a "9999999" tamper → typed reject rather than silent never-expire. The 4 h absolute-max ceiling is hardcoded in code, NOT in the meta row, so the worst a meta tamper can do is round-trip the idle to 15 min default.
7. **Attacker pre-computes a presence proof on a different device and replays it.** Defense: `PressYPresenceProof` proofs are **single-use** (the `confirmed()` constructor produces one proof that is consumed by the verifier). Replay across calls is forbidden by the type system — each `unlock` / `reveal_*` / `export_*` / `capture_authority_register(replace=true)` call takes a fresh `&dyn PresenceProof` argument; tests at every reveal-class call site construct a fresh proof per call. **Hardware-attested presence proofs land MVP-3/4** — until then the proof is a "user pressed `y`" handshake from the host UI, trusted at the same level as the identity proof.
8. **Concurrent operations race the session-expiry check.** Defense: `check_session_freshness` is the strict first step of every cache-bearing op. The `Vault` is `&mut self` for every mutating op, so the borrow checker forbids concurrent calls. Read-only ops (`account_list`, `device_list`) also take `&mut self` for the same session-touch contract. `Sync`/`Send` for the `Vault` type are not implemented; cross-thread sharing requires explicit user-side wrapping (an `Arc<Mutex<Vault>>`) — at which point the mutex serialises calls.

### Device identity + per-device key (`pangolin-store`)

> Source: `docs/issue-plans/1.5.md`. Replaces the dead-stub P2 `devices` table: each unlock generates (on first use) or loads (on subsequent unlocks) an Ed25519 `DeviceKey` whose verifying-key bytes are the vault's `device_id`. The seed is AEAD-sealed under the VDK in the `device_key` table. MVP-1 ships add-only trust (no revocation); MVP-3 recovery extends to revoke.

1. **Attacker steals a sealed `device_key.seed` blob.** Defense: the seed is sealed under the VDK with AAD `pgdvk0\0\0 || vault_id (32) || device_id (32)`; without the password (→ VDK) the open is computationally infeasible. The AAD binds the device_id, so a transplanted seed from a different vault fails the open. Verified by the `no_plaintext_on_disk` proptest scanning the raw `.pvf` + WAL for the seed bytes (full 32-byte seed AND 8-byte sliding windows) over 100 iterations.
2. **Attacker tampers with the verifying-key column to redirect a future signed-revision check to their key.** Defense: `device_key` table rows are subject to invariant #12 (AAD covers the device_id); a tampered verifying-key authenticates against an AAD the build never sealed under → `AuthenticationFailed`. Defense in depth: the seed → verifying-key round-trip is checked at decrypt time, so a corrupt-but-internally-consistent row also surfaces a typed error.
3. **Attacker registers a rogue device to a vault.** Defense: device registration runs on first unlock only and uses the local VDK + freshly generated seed. There is no "register a device from outside" API in MVP-1 — a rogue helper running on the same machine that ALSO has the user's password is already a kernel-level attacker (out of scope). MVP-2 chain code adds the multi-device join handshake; MVP-3 recovery adds revocation. Today the trust list is add-only.
4. **Attacker steals an old vault file and uses its device_id to impersonate the user on-chain.** Defense: on-chain authentication is MVP-2's responsibility (Revision Log v1's signature check). MVP-1 has zero on-chain consequences for device_id values — the column is dormant metadata until MVP-2 wires it. The `device_id` is also derived from the per-vault seed, so it's per-vault not per-user; even when chain code lands, a stolen vault provides only the credentials inside that vault.
5. **Attacker drops in a malicious `device_set_label` UTF-8 payload.** Defense: `device_set_label` runs NFC normalisation + length cap (256 chars) + trim, rejecting empty / control-char / whitespace-edge inputs with `StoreError::Validation { kind: "device_label" }`. The label is non-secret metadata (same posture as a folder name), but the validation prevents a malicious label from breaking SQLite indexing or terminal rendering downstream.

### TOTP engine (`pangolin-totp`)

> Source: `docs/issue-plans/1.7.md` + `docs/architecture/totp.md`. RFC 6238 generator + RFC 4648 base32 decoder + `otpauth://` URI parser. Configurable SHA1/256/512 × 6/7/8 digits × period. Lives as a leaf crate (no `pangolin-store` dep) for blast-containment.

1. **Attacker generates a valid TOTP code without knowing the secret.** Defense: HMAC over the time counter with the per-account secret; standard RFC 6238 security. Verified against all 18 RFC 6238 Appendix B test vectors.
2. **Attacker reads a stored TOTP secret from disk.** Defense: TOTP secrets live inside the AEAD-sealed identity blob (the `totp` map in the V2 CBOR payload). Same protection as the password field. `totp_generate` decrypts the seed transiently inside the engine, wraps it in `Zeroizing`, NEVER crosses FFI as raw bytes — only the digit string + `seconds_remaining` do. The raw seed stays reveal-class via `reveal_totp_secret` (presence-gated).
3. **Attacker pastes a malicious `otpauth://` URI to trigger a parser bug.** Defense: hand-rolled parser with strict bounds + `forbid(unsafe_code)`. Rejects malformed structure, unknown query keys (per RFC 6238, hand-rolled parser ignores unknown params), invalid base32 characters, oversize secrets. No panics on any input — all paths return typed `TotpError`. The CLI fix in 1.7 (audit H1) refused to silently coerce a non-default-params URI to SHA-1/6/30 — the CLI surfaces a clear error instead.
4. **Attacker stores a future-version TOTP record to trigger a downgrade.** Defense: TOTP params travel in the per-account V2 CBOR identity blob; that blob's `payload_version` is subject to invariant #11 (§18.7 ladder reject). A future V3 body triggers `UnsupportedRevisionSchemaVersion` per-account.
5. **Attacker reads the TOTP code from console output / terminal scrollback.** Defense: out of scope (terminal hygiene is the OS's job). However, `TotpCode` implements a redacting `Debug` and zeroizes on drop, so debug-prints in the engine don't leak the digit string. The CLI prints codes to stdout deliberately for the user's benefit; that's the user-facing contract.

### Password generator + zxcvbn strength estimator (`pangolin-core::pwgen`)

> Source: `docs/issue-plans/1.8.md` + `docs/architecture/password-generator.md`. Place-then-Fisher-Yates-shuffle generator (rejection-sampled `uniform_index` via `pangolin_crypto::rng::fill_random` — the *only* RNG; no `rand`/seeds), with a configurable policy and an `exclude_ambiguous` switch. zxcvbn (=3.1.1, no default-features) for the strength advisory.

1. **Attacker predicts a generated password from observing time / PID / other entropy proxies.** Defense: all randomness comes from `pangolin_crypto::rng::fill_random` (OS CSPRNG: `getrandom`/`BCryptGenRandom`). No `rand` crate, no thread-local state, no seeds. The "place at least one from each class" guarantee is implemented by the same RNG. Verified by HIGH-1 (invariant #9) — `pangolin-crypto` has zero serde / additional-RNG reach.
2. **Attacker uses a long-running pwgen call to detect timing of weak-password rejection.** Defense: pwgen is constant-shape — the rejection sampler inside `uniform_index` is *bounded* (it loops only until a value lands in range; for the alphabets in use that's ≤4 iterations p99). The "at least one of each class" enforcement places those bytes first then shuffles, so the generator path doesn't iterate on weakness. No timing oracle.
3. **Attacker submits a malicious `PwgenPolicy` to crash / exhaust memory.** Defense: `PwgenPolicy::validate` enforces length floor 8 / cap 128, `length >= enabled_class_count`, ≥1 class enabled. Invalid policies → `Validation { kind: "password_policy" }`, no allocation beyond the rejected policy itself.
4. **Attacker feeds the zxcvbn estimator a megabyte-long password to OOM the process.** Defense: zxcvbn 3.1.1 with no default features is bounded by its own internal caps. Pangolin does NOT yet length-cap the `password_strength` input; documented as a hardening item for MVP-3+. The current MVP-1 callers never feed > 128 chars (the pwgen ceiling), so the practical attack surface is the FFI `password_strength` entry point with a hostile binding — not in scope until MVP-4 ships a real frontend.
5. **Attacker exfiltrates the generated password via the zxcvbn `user_inputs` channel.** Defense: pangolin passes `user_inputs=&[]` for now (deferred MVP-2 follow-up: penalise a password containing the account's `display_name` / usernames). The current implementation has no input-mirroring channel. The generated password is wrapped in `Zeroizing<String>` from generation through to the call site that consumes it.

### KDBX importer (`pangolin-kdbx`)

> Source: `docs/issue-plans/1.9.md` + `docs/architecture/kdbx-import.md`. **Hand-rolled** (NOT the `keepass` crate — §16.8-footnote-2 blast-containment), `forbid(unsafe_code)` (test-only `unsafe` for the test KDBX writer), read-only parser for KDBX 3.1 + KDBX 4.x. **Untrusted-input attack surface — every defense below has been adversarially exercised.**

1. **Attacker submits a KDBX with monstrous Argon2 KDF params to OOM the host.** Defense: tightened clamps at header-parse time, **before** the KDF runs: iterations ≤ 64, parallelism ≤ 8, memory 8 KiB..1 GiB, combined `iters × mem_kib ≤ 4M` KiB-passes, version ∈ {0x10, 0x13}. Clamp violation → typed `KdbxError`, no Argon2 allocation. Audit Low-1 of 1.9 tightened these from the initial draft's looser bounds.
2. **Attacker submits a KDBX with a lying `ct_len` / inflate-size to OOM.** Defense: `KDBX_MAX_FILE_BYTES = 64 MiB` and `KDBX_MAX_INFLATED_BYTES = 256 MiB` bound every read + decompression. Wrong-creds / bad-MAC / wrong-keyfile all collapse to ONE `KdbxError::InvalidCredentials` variant (no oracle).
3. **Attacker submits a KDBX with XML entity-expansion / billion-laughs.** Defense: `quick-xml` 0.37.5 with `default-features=false` (no custom-entity expansion). Streaming parse with depth + event + text caps; no DOM materialisation.
4. **Attacker submits a KDBX with an oversized keyfile.** Defense: keyfile reads are also capped at `KDBX_MAX_FILE_BYTES = 64 MiB`. Audit Low-3 of 1.9 added the cap (the initial draft read the keyfile uncapped).
5. **Attacker crafts an `otpauth://` URI inside a KeePass TOTP custom field with non-default params.** Defense: 1.9 parses it via `pangolin-totp::parse_otpauth_uri` (the V1/V2 path that can store the full params). Audit H1 of 1.7 made the parser refuse to silently coerce — non-default params land *correctly* in the new vault.
6. **Attacker exploits the password-history replay path to install an old password as current.** Defense: audit Low-2 of 1.9 restructured the replay loop — the entry's CURRENT password is always applied LAST, after history is replayed; a mid-replay failure on the current update counts the entry as `failed`, not silently `imported`. Verified by `apps/cli/tests/import_kdbx.rs::history_replay_current_pw_is_head`.
7. **Attacker exploits the encrypted-stream layer to extract per-entry secrets.** Defense: inner ChaCha20 stream cipher is bounded to its frame; per-block HMAC-SHA256 verified with constant-time compares before any decrypt. Wrong-MAC → `KdbxError::InvalidCredentials` (no oracle).
8. **Attacker submits a KDBX claiming to be hardware-CR-protected.** Defense: rejected at header parse with a clear typed error. Q-b deferred YubiKey-CR-protected DBs to future work.
9. **Attacker submits a malformed file to crash the importer.** Defense: `forbid(unsafe_code)` (test-only `unsafe` for the test writer is gated by `#[cfg(feature = "test-writer")]` and never reaches production). All decode paths return `Result<…, KdbxError>`; no `unwrap()` / `expect()` on attacker-controlled values. Pangolin's `cargo fmt` + clippy gates ensure no panic primitives slip in.

### Encrypted export (`.pvea` archive + restore)

> Source: `docs/issue-plans/1.10.md` + `docs/architecture/encrypted-export.md`. `.pvea` archive format: plaintext header (`magic ‖ format_version:u8 ‖ kdf_algo_id ‖ Argon2 params 3×u32 BE ‖ 16B salt ‖ 24B XChaCha20-Poly1305 nonce ‖ ct_len:u64 BE`) + sealed CBOR payload. The whole header is the AEAD AAD (invariant #12).

1. **Attacker steals a `.pvea` archive in transit / from cloud backup.** Defense: archive is sealed under a fresh user-supplied **export passphrase** independent of the vault master password (D3 — key separation). Without the passphrase the AEAD ciphertext is computationally infeasible. Argon2id over the export passphrase with a fresh 16 B salt + 24 B XChaCha20-Poly1305 nonce per archive.
2. **Attacker submits a malicious `.pvea` with hostile Argon2 KDF params to OOM the host.** Defense: archive Argon2 clamps applied at header-parse **before** `derive_key`: `MAX_KDF_MEMORY_KIB = 1 GiB`, `MAX_KDF_TIME_COST = 8`, `MAX_KDF_PARALLELISM = 8`, combined `iters × mem_kib ≤ 3M` KiB-passes; `MAX_CIPHERTEXT_LEN = 256 MiB`. Audit Low-2 of 1.10 tightened these from the initial draft's looser bounds.
3. **Attacker tweaks a single byte of the `.pvea` header (e.g., bumps `ct_len`) and presents it as a valid archive.** Defense: invariant #12 — the WHOLE header is the AEAD AAD. A byte-flip on any header field → AAD mismatch → `StoreError::Validation { kind: "export_credentials" }` (no oracle — wrong passphrase / tampered header / bad MAC all collapse to one error). Verified by `pangolin-store::export::tampered_header_byte_fails_auth`.
4. **Attacker bumps `format_version` or `schema_version` to fingerprint Pangolin builds.** Defense: unknown values → typed `export_format` error. The `(top_len, schema_version)` matrix is exactly `{(7, 1), (8, 2)}`; all other combinations are rejected. A future Pangolin's `schema_version = 3` lands on the typed "requires newer Pangolin" rejection here. Audit Low-3 of 1.11 added the `1 → 2` bump so older Pangolin gets the typed rejection on a 1.11+ archive instead of an opaque CBOR shape error.
5. **Attacker forces a plaintext export to silently extract secrets.** Defense: `export_plaintext` is reveal-class (presence-gated, same as `reveal_*`) AND requires a structurally-valid `PlaintextExportConfirmation { schema_version, token }` token at the FFI layer. The CLI flow gates the token mint behind: warning copy → type `i understand` → 30-second cooling-off countdown (hidden `--no-delay` flag for tests only skips the delay) → second `[y/N]` → mint via `fill_random(32)`. The output file is `O_CREAT | O_EXCL` + `chmod 0o600` on Unix, never stdout, never clobbers, removed on error.
6. **Attacker reads the cleartext `.pvtxt` after a legitimate plaintext export.** Defense: the in-file warning banner (first-line `// *** WARNING ***` comment + a top-level `"WARNING"` JSON field). The CLI prints the warning copy + requires explicit user typing + 30 s delay so the user can't accidentally produce this file. After that, the file is the user's responsibility (analogous to `gpg --export-secret-keys` — the threat model assumes a user who typed `i understand` is aware).
7. **Attacker uses a restore to lineage-launder credentials onto a fresh vault.** Defense: `restore_to_new_vault` creates a brand-new `.pvf` with **fresh random `account_id`s**, `now` timestamps on replayed history, the local device as originating, and an empty device trust list. The restored vault has no relationship to the source's revision lineage / device list — that's MVP-2's signed Revision Log territory (deferred). The destination's environment owns its own provenance; archive provenance metadata (`vault_id`, `source_device_id`, `exported_at`) is decoded but not propagated.
8. **Attacker fills a hard drive with massive plaintext snapshots from `export_plaintext`.** Defense: the CLI requires explicit confirmation per export. The FFI requires a single-use token. There's no "auto-export on every change" surface to abuse. Plaintext export is a user-initiated rescue path, not a backup mechanism.

### Capture-authority registry (`pangolin-store::capture_authority`)

> Source: `docs/issue-plans/1.11.md` + `docs/architecture/capture-authority.md`. Vault-level metadata table establishing which component (browser-ext / desktop / mobile-OS autofill) owns credential capture per context. Threat-Model invariant #8's enforcement layer.

1. **Rogue browser extension registers itself as the capture authority for the user's browser context.** Defense: `PRIMARY KEY (context_kind, platform_hint)` makes only-one-authority-per-context a SQL invariant. A second register for the same key with a different payload AND `replace_existing=false` → `StoreError::CaptureAuthorityExclusivity { context }`. To overwrite, the caller must opt in with `replace_existing=true` AND provide a **fresh presence proof** (the reveal-class Replace branch routes through `ensure_presence_fresh`) — i.e., the user must be actively present at the moment of the replace. A background rogue cannot silently overwrite.
2. **Rogue helper uses a Unicode-homoglyph `platform_hint` (e.g., `chr​ome` with a zero-width space) to impersonate Chrome.** Defense: `platform_hint` is held to a lowercased **ASCII allowlist** (`chrome / firefox / edge / safari / chromium / webview / ios / android / windows / macos / linux`). Adding a new hint is a §18.7 minor bump (additive enum-value addition). Verified by `capture_authority::tests::validate_platform_hint_allowlist`.
3. **Attacker exploits the `replace_existing=true` branch to silently downgrade a future-schema-version row.** Defense (audit F1 fix of 1.11): the §18.7 ladder check now runs on the register path's inline SELECT, mirroring the read-path `decode_row`. A row whose `schema_version > CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX` rejects with `CaptureAuthorityValidation` BEFORE the presence check fires — even when the payload byte-matches (would-be-NoOp) or differs (would-be-Replace). Verified by `vault::tests::capture_authority_future_row_schema_version_rejected_per_row` (extended in fix-pass `9e4430e`).
4. **Attacker races the lookup-then-replace transaction window to install a rogue authority.** Defense (audit F4 fix of 1.11): the entire register flow runs under a single `BEGIN IMMEDIATE` transaction — the SQLite write lock is held continuously across the lookup, `ensure_presence_fresh`, and the `INSERT OR REPLACE`. The wrapper drives BEGIN / COMMIT / ROLLBACK via raw SQL (`execute_batch`) so the borrow checker permits the `&mut self` presence call inside the held lock; `ensure_presence_fresh` is in-memory only (no DB I/O) so holding the lock across it is safe.
5. **Attacker exploits the `Replaced { prior }` audit-trail metadata to fingerprint the previously-registered extension.** Defense: the `Replaced` outcome is returned to the caller only; not surfaced via the FFI in 1.11 (the FFI collapses `Created`/`NoOp`/`Replaced` to `Ok(())` per L8). MVP-2 surfaces that may expose the prior `component_id` to a UI must mark them reveal-class.
6. **Attacker reads `component_id` / `component_version` from raw disk to fingerprint installed helpers.** Defense: per design, these strings are non-secret metadata (same on-disk posture as `devices.label`) and DO appear in plaintext in the `capture_authorities` table. The `no_plaintext_on_disk_extended` proptest (1.11 audit F2 fix) caps occurrences at `MAX_HITS_PER_MARKER = 4` to catch a regression that would duplicate them into per-account records or AEAD-sealed payloads. The threat is real but documented (the metadata is non-secret); a future MVP-3+ hardening could move the strings into an AEAD-sealed blob if helper-fingerprinting becomes a relevant attack.
7. **Attacker bumps the on-disk row's `schema_version` to a future value to make `query` / `list` reject for all callers and DoS the registry.** Defense: the reject is per-row (§18.7 / invariant #11) — a future-version row blocks reads that touch it, but a `query` for a different `(context_kind, platform_hint)` key still succeeds. Bumping ALL rows is structurally a tamper of every row's `schema_version` byte; that byte is per-row and not in the AAD (`capture_authorities` is plaintext metadata by design), but the result is a typed `CaptureAuthorityValidation` error per touched row rather than silent corruption. Recovery is the user updating Pangolin or restoring from an encrypted-export archive.
8. **Attacker uses the encrypted-export archive to leak the capture-authority registry across vaults.** Defense: `restore_to_new_vault` explicitly ignores `snapshot.capture_authorities` (Q-f / R-f decision; mirrors the `snapshot.devices` posture). The destination vault starts with an empty registry; the user re-registers helpers on the new device (when they're also re-installing extensions anyway). Source-side archive lineage is preserved for archive fidelity but doesn't propagate into restored vault state.

### Device EVM wallet (`pangolin-store::vault`, derived via `pangolin-chain::evm`)

> Source: `docs/issue-plans/3.2.md` + `docs/architecture/device.md` §6. The per-device secp256k1 wallet is a deterministic function of the 1.5 Ed25519 `DeviceKey` (HKDF-SHA256 over an Ed25519 signature of a fixed domain-separator message). 3.2 promotes the existing `pangolin_chain::derive_evm_wallet` utility to a per-device unlock-time lifecycle primitive: materialised eagerly inside `ActiveState` on every `Vault::unlock`, dropped on every session-teardown path. Vault-sealed-only (R-a): the only at-rest secret is the AEAD-sealed Ed25519 seed already locked by 1.5; the secp256k1 scalar is never persisted. Only the wallet's public 20-byte EVM address is cached (additive nullable `devices.evm_address` column; on-chain-observable per D-006's known mitigation).

1. **Attacker steals the cached `devices.evm_address` from a stolen `.pvf`.** Defense: the address is non-secret — D-006 already documents the address as on-chain-observable (every revision the device publishes carries it as `msg.sender`; every gas payment broadcasts it). The cached column is a public 20-byte number; an attacker who has the column has gained no information they could not have obtained by watching the chain (modulo the chain-side identity-correlation threat below). No leverage; documented as part of the posture.
2. **Attacker recovers the secp256k1 scalar from a leaked memory dump of an `Active` session.** Defense: **out of scope** per `THREAT_MODEL.md`'s top-level "Out of scope: fully compromised operating systems / Kernel-level malware". 3.2 inherits the 1.5 in-memory `DeviceKey` boundary verbatim — the secp256k1 scalar lives inside the wallet's `k256::SecretKey` whose `Drop` zeroizes (L-zeroize); a memory-dumping attacker has the same access to the Ed25519 seed by the same path. 3.2 does NOT widen this surface. The `derive_evm_wallet_is_deterministic_post_drop` regression test in `crates/pangolin-chain/src/evm.rs::tests` pins the determinism contract end-to-end so a future refactor that introduces a static / `OnceCell` / cross-session signer cache (which would defeat the drop-with-session discipline) is caught.
3. **Attacker tries to forge a revision under a stolen address.** Defense: forging a revision under address A without holding A's secp256k1 scalar requires breaking secp256k1 ECDSA — **out of scope** per the top-level "Cryptographic failures: if XChaCha20-Poly1305 or Ed25519 is broken, Pangolin breaks. We assume modern primitives are sound." 2.1 R-a already implicitly extended this assumption to secp256k1 (Path B Locked the curve as the on-chain signature primitive); 3.2 inherits. The forged-revision threat is the 2.1 contract's responsibility (the v1 contract's `ecrecover` + EIP-712 check pin signer == claimed device's address); 3.2 ensures the wallet that DOES sign matches the address the contract checks against.
4. **Attacker correlates the EVM address with user identity by watching on-chain activity.** Defense: the address IS publicly correlatable across all of this device's chain events by design (D-006 — same key signs revisions and pays gas). Mitigation: D-006's known **Phase-2 Enhanced Privacy Mode** (rotation of the on-chain identity at user-configurable cadence; MVP-2 issue 3.6 ships the scaffolding, full implementation later). 3.2 does NOT change the posture — it ships the wallet lifecycle that 3.6 will rotate. **Acceptance:** until 3.6 lands, a user who values address-unlinkability above transaction simplicity can choose to use a separate vault per identity (one device-seed per vault → one EVM address per vault; documented as the intended posture).

### Direct-submit chain transport (`pangolin-chain::chain_submit`)

> Source: `docs/issue-plans/3.3.md` + `crates/pangolin-chain/src/chain_submit.rs`. Issue 3.3 ships the v1 direct-submit transport: 3.1's `SignedRevisionV1` is consumed verbatim, 3.2's session-bounded `EvmWallet` pays gas (D-006), an EIP-1559-shaped tx is constructed (`maxFeePerGas = 2 × baseFeePerGas + 1 gwei`; hard cap 50 gwei), submitted via `eth_sendRawTransaction`, and the loop blocks until a 1-confirmation receipt comes back. `RevisionPublished` event is decoded; mismatch on the event's `signer` field → fatal. R-a..R-f locked: fetch-nonce per submit (no local cache), EIP-1559 + 50 gwei cap, 8-row retry taxonomy verbatim, async-only on `pangolin-chain`, block until 1-conf, hermetic-CI + `#[ignore]`'d live smoke test.

1. **Malicious RPC reports inflated `baseFeePerGas` to drain the device wallet.** Defense (L6 + L-gas-griefing): hard cap `MAX_FEE_PER_GAS_CAP_WEI = 50_000_000_000` (50 gwei). Computed `max_fee_per_gas > cap` → `ChainError::GasCapExceeded` BEFORE tx construction. At mainnet-level fees this caps single-publish wallet drain at ~50 gwei × ~500 k gas ≈ 0.025 ETH; at testnet-level fees the cap never trips in practice. The cap is a compile-time-pinned constant; no env-var override.
2. **Malicious RPC fakes the receipt's `RevisionPublished` event with a wrong `signer`.** Defense (L-rpc-spoof): `chain_submit::process_receipt` cross-checks `decoded.signer == wallet.address()` post-decode; mismatch → `ChainError::ReceiptMismatch { expected_signer, observed_signer }`. The 2.1 contract emits the recovered signer as an unindexed field on every `RevisionPublished` event, so the cross-check is structural — a spoofing RPC cannot satisfy both the calldata pin (which encodes the wallet-as-`device_id` Path B semantics) AND the post-receipt signer field without also forging an `ecrecover`-valid signature, which is the cryptographic-failure boundary.
3. **Malicious RPC routes the tx to a wrong contract.** Defense (L-deployment-mismatch-broadcast): `publish_revision_v1` calls `load_deployed_address(BaseSepolia, "RevisionLogV1")` + cross-checks against `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA = 0x179362Ad...8E42`; mismatch → `DeploymentAddressMismatch`. The pinned-at-source constant defeats a tampered deployment file because the constant cross-checks the loaded address against the binary itself (same defense 3.1 already uses pre-signing — the two checks compound).
4. **Stuck pending tx blocks the wallet's queue.** Defense (L-nonce-collision-DoS): bounded retries (3 attempts) classify "nonce too low" / "already known" / "replacement underpriced" as retriable; on attempt 4 → `ChainError::NonceUnresolvable { attempts: 3 }`. Tx replacement / cancel-tx is deferred to MVP-3; for MVP-2 the operator manually replaces via `cast`. The retry path re-fetches the nonce via `eth_getTransactionCount(addr, "pending")` so a concurrent CLI invocation that bumped the chain-side nonce doesn't repeatedly collide.
5. **Naive retry re-broadcasts an on-chain reverted tx, burning gas.** Defense (L-replay-after-revert): contract reverts are classified as **fatal** in R-c. `receipt.status == 0` → `ChainError::RevertedV1 { reason, tx_hash }`; the reason field is decoded best-effort to `ErrInvalidSignature` / `ErrSignerNotRegistered` / `ErrUnsupportedSchemaVersion` / `OutOfGas` so the operator knows whether the failure is correctable (e.g. wrong schemaVersion → bump the client) or terminal (e.g. wrong signer registered for this vault — abandon the `vaultId`).
6. **Retry loop double-broadcasts a successfully-landed tx.** Defense (L12 + L-double-broadcast-on-retry): `broadcast_with_retries` retries only `eth_sendRawTransaction` failures BEFORE the call returns success. Once `send_transaction` returns Ok (a `PendingTransactionBuilder` holding the tx hash), the receipt-await runs to completion or surfaces an `Rpc` error — there is no path that re-broadcasts a tx whose mempool admission was already acknowledged. The mempool's "already known" idempotency on tx hash + the contract's nonce-bound `_nextSequence` advance backstop the property structurally.
7. **EIP-1559 tx envelope binds the wrong chain id.** Defense: `publish_revision_v1` calls `provider.get_chain_id()` at construction and cross-checks against `ChainEnv::BaseSepolia.chain_id() == 84_532`; mismatch → `ChainError::ChainIdMismatch`. The envelope's `chain_id` is then set explicitly to that pinned value so the alloy filler doesn't fall back to a hypothetical mid-broadcast `eth_chainId` call that a spoofing RPC could lie about.
8. **EVM wallet's secp256k1 scalar leaks during broadcast.** Defense (L5 + L-tx-signing-leak): the wallet is borrowed `&EvmWallet` for one scoped publish call. The k256 `SecretKey` is `ZeroizeOnDrop`; the scalar bytes never cross an FFI boundary in 3.3 (no new FFI surface; the publish path is `pangolin-chain`-internal). Same posture as 3.1.
9. **Mempool observer correlates EVM address with `vaultId`.** Same as 3.1 #5 (L-mempool-leak-of-vault-binding); D-006's documented mitigation, addressed by Privacy Phase-2 (MVP-2 issue 3.6 scaffolding).
10. **Receipt-poll timeout leaves local state inconsistent.** Defense (L-receipt-poll-timeout): the await is bounded by `RECEIPT_TIMEOUT_SECS = 60` (~30 Base Sepolia blocks); on timeout `ChainError::Rpc` surfaces with the tx hash so the next sync run (4.1 territory) can reconcile via tx-hash replay.

### Revision signing v1 (secp256k1 + EIP-712; `pangolin-chain::secp256k1_signing`)

> Source: `docs/issue-plans/3.1.md` + `crates/pangolin-chain/src/secp256k1_signing.rs`. Issue 3.1 ships the client-side EIP-712 signed-revision builder that produces 65-byte `r ‖ s ‖ v` signatures (canonical-s; `v ∈ {27,28}`) the deployed `RevisionLogV1` contract at `0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` (D-017, Base Sepolia) `ecrecover`s against. Per R-a (Path B clean break): v0 `SignedRevision` records stay readable via the retained Ed25519 path in `pangolin-chain::signing`; v1 publishing starts fresh on chain. Per R-b: the v1 module is a sibling of the v0 module; the two do not share types. Per R-c: the `verifyingContract` field reads from `contracts/deployments/<env>.json` at compile-time-baked path + cross-checks against the source-pinned `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA` constant (L-domain-binding defense). Per R-d: only the signer ships in 3.1; the verifier lands with 4.1. Per R-e: tests are hermetic against TWO pinned constants (typehash + domain separator captured from D-017 at plan-gate time).

1. **Attacker introduces a regression PR that drifts the Rust typehash from the contract typehash.** Defense (L-typehash-drift): the typehash is a pinned `[u8; 32]` const; the `typehash_matches_pinned_constant` hermetic test re-keccaks the literal struct-string and asserts byte-equality. Drift in any character of the literal fires loudly in CI before the regression reaches a release build. The contract-side keccak of the same literal is the ground truth; the on-chain `domainSeparator()` view fn output is independently pinned as `DOMAIN_SEPARATOR_BASE_SEPOLIA_V1` and cross-checked by the sibling `domain_separator_matches_pinned_constant` test.
2. **Attacker tampers with the deployment file to redirect signing to a wrong `verifyingContract`.** Defense (L-domain-binding + L-deployment-mismatch): `build_signed_revision_v1` calls `load_deployed_address(BaseSepolia, "RevisionLogV1")` and cross-checks the returned address against the source-pinned `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA` constant; mismatch fails closed with `ChainError::DeploymentAddressMismatch`. The pinned-at-source constant defeats a tampered deployment file because rebuilding the pinned constant requires a source change + rebuild + signoff at the merge boundary. (A legitimate redeploy is a separate change set that updates BOTH the deployment file AND the pinned constant in a single commit; the cross-check fires for any partial state.)
3. **Adversary forges a signed revision under a stolen secp256k1 scalar.** Defense: out of scope per the top-level "Cryptographic failures" boundary (same as 3.2 #3); secp256k1 ECDSA is assumed sound. 3.1 inherits the 3.2 L5 session-gate ("signing requires unlock") via `Vault::sign_revision_v1` calling `require_active()` before threading the wallet into the builder; an attacker who has the secp256k1 scalar has already breached 3.2's lifecycle invariants. The `sign_revision_v1_requires_active_session` test pins three legs (Locked / Active / idle-expired); the absolute-expiry path is structurally redundant at the `require_active()` chokepoint (both expiry forms collapse to `ActiveState` drop → `NotUnlocked` on the next call).
4. **Adversary front-runs a self-bootstrap publish.** Defense (L-self-bootstrap-frontrun): no leverage. The signature is the gate, not `msg.sender` — copying the user's bytes verbatim still recovers to the same signer (the user's wallet); the on-chain vault is correctly bootstrapped regardless of who pays gas. Same posture 2.1 Threat #3 documents.
5. **Adversary intercepts EIP-712 digest input fields in the mempool.** Defense (L-mempool-leak-of-vault-binding): the encPayload is opaque ciphertext (not a leak); the 32-byte vault/account/device IDs are opaque identifiers. The recovered signer (the device's EVM address) IS publicly broadcast once mined — D-006's known mitigation, addressed by Privacy Phase-2 (MVP-2 issue 3.6 scaffolding + full implementation later). Out of scope for 3.1.
6. **Adversary correlates EVM address with `vaultId` across publishes.** Same as #5; D-006 documented mitigation.
7. **Attacker produces a high-s signature to amplify DoS via spam-revert traffic.** Defense (L-canonical-s): `build_signed_revision_v1` defensively calls `Signature::normalize_s()` even though k256 0.13.x produces low-s by default; the on-chain `_recover` rejects high-s sigs (contract line 433). Test `build_signed_revision_v1_canonical_s` asserts the produced `s` is `≤ secp256k1n/2`. A v0 record cannot be replayed as v1 — the primitives differ AND the off-chain `SIGNED_REVISION_DOMAIN_V1` marker differs (L4) — so cross-version replay is structurally blocked.
8. **Attacker submits malformed `v` byte (0/1 instead of 27/28).** Defense (L-v-byte): alloy's `Signature::as_bytes` encodes `27 + y_parity` directly; the test `build_signed_revision_v1_v_in_27_or_28` asserts the produced byte is in the contract-accepted range. A `v ∉ {27,28}` is rejected by `_recover` (contract line 421) so the failure mode is "every revert burns gas" (DoS amplifier), not "wrong signer registered" (L-domain-binding is a strictly worse class).

### Funder service (off-chain HTTP gas dispenser; `services/funder/`)

> Source: `docs/issue-plans/3.4.md` + `services/funder/src/**`. Issue 3.4 ships the FIRST off-chain HTTP service in the Pangolin codebase: an axum server that verifies signed `Credit` attestations from `PAYMENT_AUTHORITY`, signs + submits `Redemption` attestations as `REDEMPTION_AUTHORITY` to decrement the on-chain balance, and dispenses ETH to the user device address. Per R-a..R-g + L1..L12 — see `docs/architecture/funder-service.md` for the full invariant + module map.

1. **L-funder-impersonation — attacker stands up a fake funder service at a typosquatted URL.** Defense: the funder service URL is pinned in the `pangolin-funder-client` configuration (compile-time per release build OR runtime-configurable via signed config — `pangolin-funder-client` Q for 3.5). The funder service signs its own responses with the REDEMPTION_AUTHORITY key — a separate EIP-712 `FunderResponse` envelope (design land in 3.4 plan-gate; full implementation deferred to MVP-2 issue 18.10). The on-chain `nonce[userId]` ratchet bounds replay: even if a fake funder collects a valid Credit, it cannot redeem it twice. Adversary leverage: delay-or-deny only — the on-chain nonce ratchet defeats replay.
2. **L-credit-attestation-replay — leaked Credit attestation submitted multiple times.** Defense: the funder's SQLite payment ledger has `attestation_hash UNIQUE`; the first processing inserts the row, the second returns HTTP 409 `already_redeemed` without touching the chain. Defense survives restart (R-b hybrid persistence). Test `attestation_replay_409_via_ledger` pins the duplicate-detection. The contract's `nonce[userId]` strict-equality is the on-chain defense if the off-chain layer is bypassed. Adversary leverage: essentially none against the funder treasury; minor RPC-capacity DoS bounded by R-e rate limit.
3. **L-funder-wallet-key-leak — REDEMPTION_AUTHORITY scalar leaks.** Defense: split-key architecture (R-d D-019) means the leaked redemption key CANNOT mint credits via `credit` (which requires the PAYMENT_AUTHORITY signer). Worst-case is treasury drain of the funder hot wallet (bounded by L5 per-cycle balance ceiling) plus deflating every user balance to zero on the affected contract. Recovery: deploy v2 EntitlementRegistry + re-key everyone (days of downtime; bounded financial loss). Mitigations: (a) Q-f Option A on testnet (FileKeystoreSigner) + HSM on mainnet (deferred); (b) hot-wallet balance ceiling (operator-managed); (c) monitoring + alerting (§18.10); (d) per-tx ETH-transfer hard cap (deferred to 18.5 alongside the ETH-transfer leg). Adversary leverage: high but recoverable via redeploy.
4. **L-DOS-eth-drain — valid user repeatedly drains via Credit attestations.** Defense: layered rate-limit (R-e) — per-address token bucket (10 tokens / 10-min replenish) + global cap (200/hour). Tests `rate_limit_429_after_burst` + `global_cap_trips_after_threshold` + `concurrent_requests_for_same_address_dont_oversubscribe` pin all three layers. The contract's `balance[userId]` further bounds per-user loss. Adversary leverage: bounded operational loss per attacker per hour.
5. **L-funder-service-MITM — passive observer of Credit attestations in transit.** Defense: HTTPS-only operator policy (reverse proxy in front of the funder; funder binds to 127.0.0.1 by default to make this discipline mechanical). HSTS at the proxy layer. `pangolin-funder-client` rejects `http://` schemes (compile-time in 3.5). Adversary leverage: passive leak of userId-to-deviceAddress mapping degrades 2.2 R-b opaque-bytes32 privacy posture — mitigated by operator runbook.
6. **L-payment-order — race between redeem and ETH-transfer.** Defense (partial in 3.4): the SQLite ledger row is inserted BEFORE redeem submit and updated with the redeem tx hash on receipt confirmation. The full state-machine for the redeem → ETH-transfer race (with explicit lifecycle states `received → pre_redeem → redeem_submitted → redeem_mined → eth_transfer_submitted → eth_transfer_mined`) ships in MVP-2 issue 18.5 alongside the ETH-transfer leg. Until then the user-paid-for-nothing failure mode is the documented limitation; the operator reconciliation runbook is the manual recovery path.
7. **L-userId-deviceAddress-binding — leaked Credit redirected to attacker-controlled device.** Defense (R-g): every funder request includes a client-signed device-binding sig over `keccak256(FUNDER_DEVICE_BINDING_DOMAIN_V1 || credit_attestation_hash || device_address)`. The funder verifier recovers the signer + asserts `signer == device_address`. Tests `device_binding_round_trip` + `device_binding_wrong_address_rejects` + `device_binding_wrong_attestation_hash_rejects` + `device_binding_tampered_sig_rejects` + `device_binding_rejects_unsupported_v_byte` pin the cross-product. Attacker needs BOTH the leaked Credit AND the user's device wallet signature; with the device wallet, the attacker has bigger problems (vault unlock). The domain literal is included in `/funder/v1/health` so a client can sanity-check protocol-version compatibility before signing.
8. **L-secrets-in-logs — funder logs leak userId / deviceAddress / signature bytes.** Defense (L12): WARN-level logs include only the error-class tag; the per-handler `tracing::warn!` calls explicitly exclude user fields. INFO-level logs include the redemption tx hash (public; non-secret). DEBUG-only logs may include request fields under operator-controlled `RUST_LOG=debug` (with 1% sampling target — sampling rate is the 18.10 operator config layer). The `appstate_uses_cached_payment_authority` test pins that the handler reads the cached address without per-request chain queries (defending against an RPC-side leak of identifier metadata).
9. **L-server-clock-skew — funder host clock drifts.** Defense (current): the funder checks `now_unix > credit.expires_at` against `SystemTime::now()`; an out-of-sync clock would reject valid attestations (false-negative) or submit stale ones (chain-side `ErrAttestationExpired` revert, fatal gas burn). NTP / chrony at OS level is the operator's responsibility; the clock-skew alert + ±60s tolerance window is deferred to 18.10's operational monitoring. Adversary leverage: limited to "operator must run NTP" — documented in the funder-service.md operational notes.
10. **L-cors-and-csrf — browser-origin cross-site request to funder.** Defense: the funder NEVER sets cookies / uses session auth; every request is self-contained (Credit + binding sig + device address). Classical CSRF does not apply. Future-proofing: any maintainer adding cookie auth must update this row + add `tower_http::cors::CorsLayer` with a whitelist (NOT `*`) + `Access-Control-Allow-Credentials: false`. No CORS layer in 3.4 because there are no browser-origin callers in MVP-2.
11. **L-funder-as-payment-correlator — funder learns userId → deviceAddress mapping; indefinite retention turns the funder into a per-user payment-history index.** Defense (3.4): the SQLite ledger stores attestation_hash + user_id + device_address + credit_amount + redemption_tx_hash + created_at. Retention policy (e.g., 30-day window) is the §18.5 operator job — 3.4 ships the code that defaults safe (no automatic export, no analytics, no third-party logging integration). The funder operator is the trust anchor; compelled-disclosure pressure is defended at the policy + retention layer, not the code layer.
12. **L-typehash-drift-redemption (env-quirk #14 analog) — Rust-side Redemption struct hash drifts from the contract.** Defense: `REDEMPTION_TYPEHASH_V1` is a pinned `[u8; 32]` const captured via `cast keccak`; the `redemption_typehash_matches_pinned_constant` hermetic test re-keccaks the literal struct-string and asserts byte-equality. `ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1` is captured via `cast call <D-018> "DOMAIN_SEPARATOR()(bytes32)"` at builder time + cross-checked by `redemption_domain_separator_matches_pinned_constant`. The per-field tamper test (`redemption_per_field_tamper_changes_signer`) exercises each of the five Redemption struct fields to catch silent field-order drift. Hermetic-only — env-quirk #14 documents that this cannot catch all contract-side semantics drift; the `#[ignore]`'d live cross-check `redemption_cross_check_against_live_d018` is the manual pre-merge sanity check (re-pinned after D-019 redeploy).

### Gas balance state machine + manual top-up trigger (`pangolin-chain::balance_check` + `pangolin-chain::balance_monitor` + `pangolin-funder-client::initiate_top_up`)

> Source: `docs/issue-plans/3.5.md` + `crates/pangolin-chain/src/balance_check.rs` + `crates/pangolin-chain/src/balance_monitor.rs` + `crates/pangolin-funder-client/src/lib.rs`. Issue 3.5 ships the client-side balance-state machine that observes the device wallet's on-chain ETH balance, estimates the next-revision cost, surfaces the §8.1.5 entitlement-state (`Sufficient` / `RequiresActiveAccount` / `TopUpInFlight` / `Unknown`) to the FFI host, and ships the device-side `initiate_top_up` Rust API that POSTs to the funder service. Per R-a..R-e (Kelvin sign-off 2026-05-15): chain crate owns the logic as free async fns + a `BalanceMonitor` background task; `Vault` grows a SYNC `evm_wallet_address` accessor; eager-poll + per-publish freshness check both fire; hybrid estimate with `MIN_BUFFER_REVISIONS = 3`; new FFI method `gas_balance_state`; two-step manual API (NO auto-top-up; NO CLI subcommand).

1. **L-balance-staleness — balance read returns stale data; user sees `Sufficient` and the publish fails with insufficient funds anyway.** Defense: per R-b verbatim, `publish_revision_v1_with_config` performs a SYNCHRONOUS pre-submit balance check INSIDE the publish path BEFORE tx construction (gated by `PublishConfig::pre_publish_balance_check_enabled`, default `true`). Cached state from the background-poll monitor is **advisory**; the authoritative freshness check is the per-publish read. A below-threshold balance short-circuits to `ChainError::PrePublishBalanceInsufficient { balance_wei, estimate_wei }` BEFORE the build/sign cost. Failure mode if it slips through: UX disruption only (the live `estimate_gas` / `eth_sendRawTransaction` then surfaces `ChainError::InsufficientFunds`; no financial loss). Test `pre_publish_balance_check_blocks_doomed_submission` pins the gate; `pre_publish_balance_check_passes_when_sufficient` pins the happy path; `pre_publish_balance_check_can_be_disabled_via_config` pins the off-path.
2. **L-rpc-spoof-balance — malicious RPC returns a fake high balance; client renders `Sufficient`; publish fails on chain.** Defense: balance reading is **advisory** for the state surface; the AUTHORITATIVE failure path is `eth_sendRawTransaction` (3.3's surface — covered by L-rpc-spoof + `ReceiptMismatch` defenses). 3.5 sanity-checks `eth_chainId` BEFORE accepting balance via the chain-id cross-check in `query_evm_balance_with_provider` + `fetch_base_fee_with_fallback`; mismatch → `ChainError::ChainIdMismatch`. Test `balance_check_rejects_wrong_chain_id` pins the cross-check. The chain-id match alone does NOT prove the balance is authoritative — a same-chain RPC could still lie — but it shrinks the spoof surface to "needs an actual same-chain node to lie convincingly" rather than "any forwarder on the internet". The on-chain `eth_sendRawTransaction` response is the cryptographic-failure-class boundary; balance is decorative until then.
3. **L-state-leak-via-label — the `GasBalanceState` enum exposes precise balance values via Debug / log files; an attacker watching the host UI / log artifacts learns wallet balance precisely.** Defense: variant **names** are boolean-ish (`Sufficient` / `RequiresActiveAccount`) so a host that renders the label without the numeric detail leaks no precise balance. Wei values are in the struct for hosts that EXPLICITLY want to render them; default UX shows label-only per the L4 §8.1.5 vocabulary discipline. The `Debug` impl REDACTS `balance_wei` / `estimate_wei` to `"<wei>"` in release builds (`#[cfg(not(debug_assertions))]` path); debug builds show the value for developer ergonomics. Test `debug_format_redacts_balance_in_release` pins both modes. The FFI surface (`GasBalanceStateFfi`) wraps the values as **hex strings** so a host's `Debug` output of the FFI shape is also non-numeric-greppable. Adversary leverage: combined with the address-observability D-006 mitigation forms a per-user financial profile only on debug-build hosts; release-build hosts leak only the variant tag.
4. **L-auto-top-up-DoS — attacker triggers repeated `initiate_top_up` calls draining user's paid balance + funder operational capacity.** Defense: **moot** — Q-e Option C (Kelvin's resolved decision R-e). 3.5 ships NO auto-top-up; the manual API requires the host to plumb a Credit attestation at call-time + the device wallet's signer (which lives behind 3.2's session gate). The 3.4 funder R-e rate-limit (10/min/address + 200/hour global) provides the second-layer bound. Adversary needs unauthenticated access to a host that's already unlocked AND a leaked Credit attestation; the leaked Credit is bounded by `expires_at` (5-minute window per 2.2 R-e) and the on-chain `nonce[userId]` ratchet (a single Credit cannot be redeemed twice).
5. **L-credit-attestation-storage — vault-stored Credit attestations widen on-disk surface.** Defense: **moot** — Q-e Option C ships NO vault-stored attestations. The host plumbs the Credit at call-time only; no schema migration; no AEAD-sealed attestation table. If a future MVP-3 issue lands Option B (auto-top-up), the threats become: (a) AEAD-sealing in `credit_attestations` table; (b) contract `nonce[userId]` replay-defense; (c) 3.4 R-g device-binding signature. Plan-gate enumerated this for future work; 3.5 does not ship it.
6. **L-funder-url-injection — host code passes an attacker-controlled `funder_url` to `initiate_top_up`.** Defense: `pangolin-funder-client` does NOT pin the funder URL — the caller (host / future CLI) is responsible for sourcing it from trusted config. 3.5 documents that the URL pinning is a CLI-V1 / host-config job. The TLS layer (`reqwest` with `rustls-tls`, `default-features = false` so OpenSSL is absent) protects against MITM once a URL is established. Adversary leverage: same as L-funder-impersonation (Funder service #1) — a typosquatted URL collects Credit attestations + the device-binding signature but cannot replay them against the legitimate funder because the on-chain `nonce[userId]` ratchet rejects double-redeem.
7. **L-monitor-runtime-leak — `BalanceMonitor::start` panics on a runtime without a tokio context.** Defense: the FFI `balance_monitor_start` entry point requires the caller to be on a tokio runtime (uniffi async exports run on the host's runtime). Hermetic tests `monitor_start_emits_initial_state` / `monitor_register_top_up_transitions_to_in_flight` / `monitor_stop_cancels_task` / `monitor_concurrent_reads_safe` cover lifecycle; a panic at start would fire loudly. The poll task is `JoinHandle`-tracked + cancelled cleanly via `oneshot` so a host that calls `balance_monitor_stop` always reaches task termination. Adversary leverage: none — this is an availability concern, not a security concern.
8. **L-monitor-state-persistence — cached state survives session teardown via the `Arc<RwLock<GasBalanceState>>`.** Defense: the cached state lives only in the in-memory `Arc<RwLock<GasBalanceState>>` owned by the monitor; the FFI `MonitorHandle` is an `Arc<...>` that the host drops at session-close (the `Drop` paths tear the task down via the cancel `oneshot` + `JoinHandle::await`). NEVER written to `.pvf` (L6). A passive observer of the host's address space at session-end sees only zero-pages once the monitor is dropped. Test `monitor_stop_cancels_task` pins the lifecycle. Adversary leverage: none — out-of-scope per the top-level "memory-dump attacker" boundary.

### Privacy Mitigation Phase-2 hooks (3.6 scaffolding) (`pangolin-chain::privacy`)

> Source: `docs/issue-plans/3.6.md` + `docs/architecture/privacy.md` + `crates/pangolin-chain/src/privacy/{mod.rs, default.rs, enhanced.rs, tests.rs}`. Issue 3.6 ships the **trait + enum + fail-loudly stub** scaffolding that Phase-2 Enhanced Privacy Mode (per-revision wallet rotation; CoinJoin pre-mixing of funder top-ups; optional fresh-address-per-vault) will plug into when MVP-3 / MVP-4 lands. Per R-a..R-d (Kelvin sign-off 2026-05-15): `PrivacyMode` enum + `PrivacyStrategy` trait both ship; all three Phase-2 modes scaffolded as trait hooks (CoinJoin reduced to a placeholder method — no concrete mixer wiring); central declarations in `pangolin-chain::privacy` with distributed-impl consumer tests; fail-loudly + byte-identity proof. **Status: scaffolding-only in MVP-2; production logic deferred to MVP-3 / MVP-4.** `EnhancedPrivacy` mode fails loudly per L7 (any hook call returns `PrivacyError::NotYetImplemented`); silent fallback to `Default` is rejected.

1. **L-3.6-accidentally-ships-partial-phase-2 — builder over-interprets "scaffolding" and ships partial Phase-2 logic (e.g., implements `derive_evm_wallet_at_index` and wires it into the revision-signing path).** Defense (3.6 L1 + L4 verbatim): `DefaultStrategy` MUST be a verbatim no-op preserving 3.5 behaviour bit-for-bit. The byte-identity regression test `default_strategy_revision_signature_matches_pre_3_6_baseline` embeds the pre-3.6 baseline signature (captured from `main` at `3227d38`) as a `[u8; 65]` const and re-runs the 3.6 `DefaultStrategy`-driven path, asserting byte-equality. CI runs the assertion every PR; a drift fails the build. Two sibling pass-through tests cover the other two hooks (`transform_funder_response` identity + `select_address_for_vault` ignores `vault_id`). Adversary leverage: none direct — failure mode is "users could lose linkability of their old on-chain history without noticing", caught mechanically by the fixture lock.
2. **L-trait-shape-drift-from-phase-2 — 3.6 ships a trait shape that does not actually fit what Phase-2 needs.** Defense (3.6 L3): (a) the trait method signatures are designed against the THREE specific Phase-2 modes named in master plan §5 row 3.6 (per-revision rotation + CoinJoin pre-mixing + fresh-address-per-vault), not speculative future modes; (b) every hook carries an `L3: do not rename` doc-comment so the next builder has the binding-API context; (c) Kelvin's R-a..R-d sign-off pins which modes are scaffolded. The variant-label-pinning test + the trait-Send/Sync compile-time check catch silent shape changes. Adversary leverage: none — failure mode is "scaffolding gets thrown away in MVP-3".
3. **L-enabled-path-silent-degrade — `EnhancedPrivacy` variant accidentally falls through to `Default` behaviour.** Defense (3.6 L7 verbatim): every `EnhancedPrivacyStrategy` hook returns `Err(PrivacyError::NotYetImplemented { mode: EnhancedPrivacy, hook: "<method-name>" })` BEFORE doing any work. Three fail-loudly tests (one per hook) pin the typed-error variant. The error `Display` message references `docs/issue-plans/3.6.md` so a user who debugs the error gets a clear pointer to the Phase-2 roadmap. Silent fallback is REJECTED — a user / host that explicitly opts in MUST get an unambiguous "not yet" signal, not a quiet degrade to the observable-on-chain default. Adversary leverage: privacy-loss in the user model; mitigated structurally by the typed error.
4. **L-doc-drift-from-§8.3 — 3.6 scaffolding gets shaped around what's easy to implement now rather than what Whitepaper §8.3 says.** Defense: the plan-gate doc (`docs/issue-plans/3.6.md`) reproduces §8.3 verbatim + explicitly surfaces the §8.3-vs-master-plan-§5 gap (§8.3 names only CoinJoin; master plan expands to all three modes). The 3.6 scaffolding encodes master plan §5 row 3.6 per Kelvin's R-b sign-off; DECISIONS.md records the binding interpretation. The Phase-2 issue that lands the real impl will reconcile the formal spec. Adversary leverage: none — documentation-drift risk only.
5. **L-on-chain-observability-mitigation-deferred (D-006 REAFFIRMED, not resolved) — 3.6 ships the hooks for the on-chain-observability mitigation but not the mitigation itself.** Defense: 3.6 is explicitly scaffolding-only per L1; users who require address-unlinkability above transaction simplicity still need to use a separate vault per identity (the documented workaround until Phase-2 ships). The 3.2 "Device EVM wallet" row (line 1066) + the 3.1 mempool-leak row (line 1080, 1091) remain accurate — 3.6 does not change their substance. Adversary leverage: same as the underlying D-006 threat — on-chain observation correlates the device's EVM address with vault publishing patterns. Mitigation acceptance: 3.6's job is the architectural-locking, not the privacy delivery; the privacy delivery lands in Phase-2 (MVP-3 / MVP-4).

### Slow-mode chain sync (read path + v1 verifier) (`pangolin-chain::chain_sync` + `pangolin-store::vault::sync_from_chain`)

> Source: `docs/issue-plans/4.1.md` + `crates/pangolin-chain/src/chain_sync/{mod.rs, poll.rs, ws.rs, reorg.rs, tests.rs}` + `crates/pangolin-store/src/vault.rs::sync_from_chain` + `crates/pangolin-store/src/device.rs::auto_register_device_from_chain_sync`. Issue 4.1 ships the first MVP-2 read path that consumes `RevisionPublished` events from D-017 + filters by vault id + per-event recovers the secp256k1 signer via the production v1 verifier (`recover_signer_v1` + `recover_signer_v1_raw`) + ingests verified events into the local revision graph + advances a per-vault `last_synced_block` checkpoint. Per R-a..R-f (Kelvin sign-off 2026-05-15): checkpoint persisted in `.pvf` (R-a) with `--from-genesis` escape; WS-preferred with HTTP-poll fallback (R-b; WS deferred behind alloy feature in MVP-2 per L8); two-stage optimistic 1-conf + finalize at 12-conf + rollback on reorg (R-c); permissive auto-register of chain-discovered signers (R-d); async orchestration on `pangolin-store::Vault::sync_from_chain` preserving L7 (R-e); hermetic + reorg simulator test suite (R-f; live `#[ignore]`'d deferred pending captured-event pin).

1. **L-rpc-spoof-events — malicious RPC returns a `RevisionPublished` event with a forged signature for a vault the user owns.** Defense (L5): per-event `recover_signer_v1_raw` verifier runs on every decoded event; rejects with `SignerRecoveryFailed` if the signature does not curve-recover. Plus L4 — the `eth_getLogs` filter pins contract address + event signature hash; plus L3 — `eth_chainId` cross-check at provider construction. Note: the deployed `RevisionPublished` event surface does NOT carry the signature bytes (only the recovered `signer` field), so the load-bearing defense in the current contract reduces to L3 + L4 + the contract's own `ecrecover` at publish time. The verifier helpers + the synthetic-signed-event test path (`verify_signed_event`) are wired end-to-end so a future v1.1 event that re-emits the signature flips the check on without code changes. Tests: `recover_signer_v1_tampered_signature_diverges`, `recover_signer_v1_raw_rejects_high_s`, `recover_signer_v1_raw_rejects_invalid_v_byte`, `verify_signed_event_detects_signer_field_mismatch`. Adversary leverage: mitigated to "RPC returns zero events" (the L-rpc-omits-events row below).
2. **L-rpc-omits-events — malicious RPC silently drops events for a specific vault id.** Defense: a future cross-check of the contract's `_nextSequence` against the highest observed local sequence (deferred to MVP-3 follow-up per plan-gate doc; not load-bearing in 4.1 because honest-RPC fallback is the user-facing remediation). The `pangolin sync --from-genesis` escape hatch (R-a Option C) gives the user a clean re-sync from a different RPC. Adversary leverage: silent gap until a fork appears on next honest-RPC sync; mitigated by the user-visible `--from-genesis` workflow.
3. **L-reorg-rollback — a chain reorg moves a published event from one block to another.** Defense (R-c verbatim): `RevisionStatus::Pending { observed_at_block, block_hash }` at 1-conf insert; `Vault::promote_finalized_revisions(head)` advances pending → finalized at depth ≥ `CONFIRMATION_DEPTH_FOR_FINALIZATION = 12`; `ReorgDetector::detect_reorg` compares observed block hashes against canonical chain; `Vault::rollback_pending_revisions_in_range(low, high)` deletes affected pending rows (finalized rows NEVER touched). Tests: `reorg_simulator_shallow_two_block_rollback`, `deep_reorg_ten_block_rollback`, `rollback_pending_revisions_in_range_skips_finalized`, `promote_finalized_at_twelve_conf`. Adversary leverage: reorgs are a network condition; mitigation is structural.
4. **L-checkpoint-corruption — tampered `.pvf` reports an unreasonably high `last_synced_block` so the client never re-fetches old events.** Defense (L12 verbatim + the cursor > tip sanity check in `Vault::sync_from_chain`): the checkpoint is monotonic (`update_last_synced_block_v1` refuses backward moves); plus the orchestrator pre-flight check `if cursor > head { return CheckpointOutOfRange }`. The `.pvf` is AEAD-sealed per MVP-1, so the tamper surface requires breaking the AEAD seal — out of scope per the 1.5 / 2.1 / 3.1 boundary. Tests: `last_synced_block_v1_monotonic`. Defense-in-depth: the `--from-genesis` escape hatch lets a user force-re-sync. Adversary leverage: mitigated to a per-session re-sync.
5. **L-malicious-vault-id-substitution — RPC returns events for a different vault than the client requested.** Defense (L4 + the decode-time cross-check in `poll::fetch_chunk`): server-side filter pins `topic1 = vault_id`; the client decoder additionally compares `decoded.vaultId == requested_vault_id` and rejects mismatches. Test: `fetch_chunk_rejects_wrong_vault_id`. Adversary leverage: mitigated.
6. **L-schemaVersion-future-poison — future contract emits events with `schemaVersion > MAX_KNOWN_CLIENT_SCHEMA_VERSION = 1`.** Defense (§18.7 ladder enforcement at decode): `poll::fetch_chunk` rejects events with `schemaVersion > MAX_KNOWN_CLIENT_SCHEMA_VERSION`. Test: `fetch_chunk_rejects_future_schema_version`. Adversary leverage: none — the ladder's intended behavior.
7. **L-verifier-domain-binding-drift — `recover_signer_v1` is built against `BaseSepolia` but applied to events from a different chain.** Defense (L3 + L4): `eth_chainId` cross-check at provider construction + pinned-address cross-check before decode + the verifier itself reuses the shared `build_domain` / `struct_hash` / `eip712_digest` helpers (L1 byte-identical to the signing side). Tests: `chain_id_mismatch_fails_closed`, `deployment_address_resolves_for_base_sepolia`. Adversary leverage: none directly — this is a config / self-inflicted concern.
8. **L-permissive-auto-register-could-add-spam (R-d trade-off) — every observed chain event auto-creates a `devices` row for the signer.** Defense: the auto-register is gated AFTER L4 (contract address + event signature) + AFTER L5 (signer recovery; signature genuine to the recovered signer); a misbehaving RPC cannot synthesize a `RevisionPublished` event without bypassing both gates. Plus the synthetic `device_id` is the EVM address itself, so the same signer can only ever land one row (idempotent via `INSERT OR IGNORE`). Test: `auto_register_chain_sync_device_idempotent`. Adversary leverage: minimal — at worst, a non-malicious chain that emits events from many distinct signers grows the local devices table linearly with publisher count.

### Ephemeral local indexer (4.2 skeleton + 4.3 AEAD + zero-fill + ephemeral key + 4.3-per-column AEAD wrapping + AAD binding + ARCH-1 binary handshake) (`pangolin-indexer::{session, protocol, cipher, handshake, error}` + `pangolin-indexer` binary)

> Source: `docs/issue-plans/4.2.md` + `docs/issue-plans/4.3.md` + `crates/pangolin-indexer/src/{lib.rs, session.rs, protocol.rs, cipher.rs, error.rs}` + `crates/pangolin-indexer/src/bin/pangolin-indexer.rs` + `crates/pangolin-chain/src/evm.rs` (`derive_indexer_key`) + `docs/architecture/indexer.md`. Issue 4.2 shipped the structural skeleton for the opt-in fast-mode sync path (D-007). **Issue 4.3 ships the security hardening:** real `AeadCipher` impl of the `TempDbCipher` trait (`XChaCha20-Poly1305` from `pangolin-crypto::aead` + per-page random 24-byte nonce); HKDF-SHA256-derived ephemeral 32-byte key (`pangolin_chain::derive_indexer_key(device_key, run_nonce) -> SecretBytes` with versioned `"pangolin-indexer-tempdb-key-v1"` domain string); two-pass `secure_zero_fill` (random + zeros + fsync) called from `IndexerSession::Drop` BEFORE the `NamedTempFile` Drop unlinks the file. Per 4.3 R-a..R-e (Kelvin sign-off 2026-05-16 — "use the most secure combination"): R-a HKDF-SHA256-from-device-seed; R-b per-page random nonce framing `nonce ‖ ciphertext_with_tag`; R-c random + zero defense-in-depth overwrite; R-d `pangolin-crypto::SecretBytes` wrapper (override of plan-gate's `Zeroizing<[u8; 32]>` recommendation); R-e hermetic + adversarial-decode tests (round-trip × 5 sizes + nonce-distinctness across 1000 calls + tag/nonce/body tamper rejection + zero-fill verification + derive_indexer_key determinism + nonce-sensitivity + device-sensitivity + EVM-wallet non-collision). **L-temp-file-leak surface is now SUBSTANTIALLY CLOSED for the at-rest case** (zero-fill + ephemeral key gone with process); **the runtime case has a known deferred gap** — the AeadCipher is constructed + probed end-to-end but the SQL INSERT (`persist_chunk`) and SELECT (`handle_pull`) BLOB column paths are still plaintext during the indexer's runtime (per-column cipher wrapping is an additive follow-up scheduled paired with AAD binding (`vault_id, page_id, schema_version`) — both deferred together because AAD has no security value until the wrapping lands).

1. **L-temp-file-leak — a crashed indexer (panic / SIGKILL / OOM / power-loss) leaves a temp file on disk containing chain-event data.** Defense post-4.3-per-column-AEAD (**on-disk runtime case CLOSED; runtime-memory-dump remains a documented caveat covered by L-key-leak-via-memory-dump**): (a) `tempfile::NamedTempFile` gives the random path (L1 — `O_CREAT | O_EXCL | O_NOFOLLOW` posture); (b) the AeadCipher (`XChaCha20-Poly1305` from `pangolin-crypto::aead`, per-page random 24-byte nonce, sealed under an ephemeral 32-byte key derived via HKDF-SHA256(device_seed; salt = per-run 16-byte nonce; info = `"pangolin-indexer-tempdb-key-v1"`) — see `pangolin_chain::derive_indexer_key`) wraps **every BLOB column** at INSERT time in `persist_chunk` and unwraps every BLOB column at SELECT time in `handle_pull` (§4.3 per-column-AEAD R-a); (c) every per-row seal/open binds a fixed-width 42-byte AAD `vault_id ‖ page_id_BE_u64 ‖ schema_version_BE_u16` (§4.3 per-column-AEAD R-b) so cross-page-cut-and-paste / cross-session-replay / cross-schema-version-poison all manifest as `IndexerError::CipherTamper` at decrypt time; (d) on session Drop the `secure_zero_fill` helper (4.3 R-c) does two passes — random 4-KiB chunks + fsync, then zeros + fsync — before the NamedTempFile Drop unlinks; (e) the Drop's load-bearing ordering closes the SQLite Connection FIRST (via `Option::take`) so the `secure_zero_fill` re-open succeeds on Windows; (f) `panic = unwind` makes the Drop fire during stack unwinding (L11 panic branch — verified via `cleanup_on_panic_unwinds_temp_file`); (g) OS-temp-dir GC is the SIGKILL / `panic = abort` fallback. **Closed: the on-disk runtime case.** Pre-§4.3-per-column-AEAD the `persist_chunk` INSERT and `handle_pull` SELECT paths operated on PLAINTEXT BLOBs during the indexer's runtime; post-cycle every BLOB column carries `nonce ‖ ciphertext ‖ tag` on disk under an AAD bound to `(vault_id, page_id, schema_version)`. Test: `temp_db_file_contains_no_plaintext_after_persist` (raw-bytes scan of the on-disk temp DB file for sentinel byte patterns from every wrapped BLOB column — pre-cycle FAILED; post-cycle PASSES). **Remaining caveat: runtime-memory-dump.** An attacker who can read the indexer process's memory mid-run can recover the 32-byte ephemeral key from `SecretBytes`; this is the L-key-leak-via-memory-dump surface below (mitigated by short process life + heap-zeroize discipline). **Documented limit:** SSD wear-leveling may write the overwrite to a different physical block than the original data; the original block persists until TRIM/garbage collection — but the original block contains AEAD ciphertext, not plaintext (the cipher wrap landed pre-Drop). Tests post-§4.3-per-column-AEAD: `temp_db_file_contains_no_plaintext_after_persist`, `pull_after_persist_recovers_plaintexts_under_per_column_aad`, `cross_page_cut_and_paste_surfaces_cipher_tamper`, `cross_session_replay_aad_mismatch_via_cipher`, `aead_cipher_wraps_every_sentinel_pattern`, `aead_cipher_nonces_distinct_across_8000_wraps`, plus the existing 4.3 + 4.2 lifecycle tests.
2. **L-nonce-reuse-catastrophic (4.3) — `XChaCha20-Poly1305` leaks both plaintexts on nonce reuse under the same key.** Defense: every `AeadCipher::encrypt_page` call generates a fresh 24-byte nonce via `pangolin_crypto::rng::fill_random` (OS CSPRNG); the 192-bit XChaCha20 nonce makes collision probability ~2^-96 per call (negligible for ≤ 2^32 calls). Tests: `aead_cipher_nonce_distinct_across_1000_calls` — 1000 sealings of identical plaintext, all 1000 nonces pairwise-distinct. Adversary leverage: none if nonce discipline holds; catastrophic if it breaks — THE load-bearing crypto property of 4.3.
3. **L-tampered-ciphertext (4.3) — a malicious party with disk-access tampers a temp-DB page's ciphertext between two indexer reads.** Defense: (a) AEAD tag verification at decrypt time (Poly1305 tag is verified BEFORE the plaintext is exposed); (b) tampered page → typed `CipherError::TagMismatch` propagated through `IndexerError::TempDbInit` / TempDbIo; (c) all authentication failures (tampered tag, tampered nonce, tampered body, wrong key) collapse to a single `TagMismatch` variant so callers cannot construct a distinguishing oracle on the failure mode (same discipline `AeadError::Tampered` uses). Tests: `aead_cipher_tag_tamper_rejects`, `aead_cipher_nonce_tamper_rejects`, `aead_cipher_body_tamper_rejects`, `aead_cipher_wrong_key_rejects`, `aead_cipher_truncated_frame_rejects`. Adversary leverage: mitigated to "indexer surfaces typed error; nothing silently corrupted".
4. **L-key-derivation-collision (4.3) — two indexer runs derive the same key (per-run randomness in derivation is missing or weak).** Defense: per-run 16-byte nonce drawn from `OsRng` and used as HKDF-SHA256 salt; even if two runs accidentally collide on the run_nonce (~2^-64 per pair after 2^32 sessions — astronomically unlikely), the AEAD framing's per-page nonce randomness adds another 192 bits of session-independent entropy on top. Tests: `derive_indexer_key_is_deterministic`, `derive_indexer_key_distinct_per_run_nonce`, `derive_indexer_key_distinct_per_device`, `derive_indexer_key_does_not_collide_with_evm_wallet`. Adversary leverage: none if run_nonce is fresh OsRng each session.
5. **L-key-leak-via-memory-dump (4.3) — attacker with memory-dump access reads the ephemeral 32-byte key out of the IndexerSession's address space.** Defense: (a) the key lives only in `pangolin-crypto::SecretBytes` (heap-allocated; `Zeroizing<Vec<u8>>` zeros on Drop); (b) short-lived process (5-min idle default; 1-hour absolute ceiling — R-c from 4.2); (c) the cipher's `Debug` impl redacts the key (`<redacted>` marker, mirrors `AeadKey`); (d) no `Clone` / `Copy` / `Serialize` derives — duplicates cannot be created; (e) post-§4.3-per-column-AEAD ARCH-1 the binary additionally zeroizes the stdin handshake staging buffer + the stack-side `derived_key` array immediately after the bytes are moved into the heap `SecretBytes` (`handshake::read_handshake` + `bin/pangolin-indexer.rs` post-handshake `key_bytes.zeroize()`); the `IndexerHandshake::Drop` impl re-zeroes belt-and-suspenders. Adversary leverage: bounded by process lifetime + wrapper-type discipline. Memory-dump access is already a host-level compromise; the indexer is downstream.
6. **L-cross-page-cut-and-paste (§4.3 per-column AEAD) — an attacker with disk-access swaps two rows' wrapped BLOB ciphertexts on disk between two indexer reads, hoping the indexer silently consumes the swapped data.** Defense: every per-column seal binds `(vault_id, page_seq, schema_version)` into the AEAD AAD via `build_aad`. At `handle_pull` time the AAD is reconstructed from the row's stored `page_seq` + `schema_version` columns + the session's bound `vault_id`; a swapped ciphertext fails the AEAD-open under the recomputed AAD because the `page_id` field of the seal-time AAD no longer matches. Surfaces as `IndexerError::CipherTamper { context: "column=<name>: AEAD tag mismatch ..." }`. Tests: `cross_page_cut_and_paste_surfaces_cipher_tamper` (in-source integration; persists two rows + swaps via a second `rusqlite::Connection` + asserts `handle_pull` surfaces `CipherTamper`); proptest `cross_page_paste_fails_for_any_page_id_pair` (1024 random `(vault, page_a, page_b, schema, plaintext)` tuples). Adversary leverage: mitigated to "indexer surfaces typed CipherTamper; nothing silently consumed".
7. **L-cross-session-replay (§4.3 per-column AEAD) — an attacker captures ciphertext from session A (bound to `vault_id_A`), spins up session B (bound to `vault_id_B`) with the same disk path, and tries to make B consume A's ciphertext.** Defense: the AAD includes `vault_id` as its 32-byte prefix; session B's `handle_pull` rebuilds the AAD using `vault_id_B`, which doesn't match the seal-time AAD that used `vault_id_A`. AEAD-open fails. Tests: `cross_session_replay_aad_mismatch_via_cipher` (in-source); proptest `cross_session_replay_fails_for_any_vault_pair` (1024 random vault-pair iterations). Note: in practice each session also derives a FRESH ephemeral key from a per-run nonce, so a captured ciphertext from session A would also fail under session B's key alone — the AAD binding is the second layer of defense against a contrived scenario where the same key is reused across sessions (e.g., a future cycle adding resumable persistent fast-mode caches). Adversary leverage: mitigated.
8. **L-future-schema-version-poison (§4.3 per-column AEAD) — an attacker tries to make the indexer reinterpret a ciphertext sealed under `schema_version = N` as data of a higher `schema_version = N+1` (e.g., to forge metadata about a future event format).** Defense: the AAD carries `schema_version_BE_u16` as its trailing 2 bytes. A ciphertext sealed under `schema_version = 1` cannot be opened under an AAD claiming `schema_version = 2` because the AEAD tag verification fails. Combined with the `pangolin-chain::MAX_KNOWN_CLIENT_SCHEMA_VERSION = 1` ladder enforcement at decode (which rejects events with `schema_version > MAX` BEFORE they even reach `persist_chunk`), the surface is closed at two layers. Tests: proptest `cross_schema_version_paste_fails` (1024 random `(vault, page, schema_a, schema_b, plaintext)` tuples); byte-pin test `aad_byte_pin_for_known_triple`. Adversary leverage: none.
9. **L-binary-key-leak-via-stdio (§4.3 per-column AEAD ARCH-1) — the binary now reads the 32-byte derived AEAD key from its stdin during the handshake. An adversary with stdin-write access could either (a) inject a known key (compromising the AEAD seal for that session) or (b) try to OOM the binary with a multi-gigabyte length prefix.** Defense (a): stdin is the same trust boundary as the existing R-b protocol surface — only the host has access to the indexer's stdin. The host is also the entity that derives the key in the first place (via `pangolin_chain::derive_indexer_key`). A compromised host already controls everything; the handshake doesn't add a new attack surface beyond what R-b already documents. Defense (b): the handshake length-prefix is bounded by `MAX_HANDSHAKE_BYTES = 256`; any prefix above this is rejected as `HandshakeError::OversizeFrame` BEFORE allocating the body buffer. Additional defenses: the binary zeroizes the stdin staging buffer post-deserialise; the `IndexerHandshake::Drop` impl also zeroes the derived key; the binary's debug-print discipline redacts the key (`<redacted-32-bytes>` marker mirrors `AeadKey`'s pattern). Tests: `handshake_rejects_oversize_length_prefix`, `handshake_rejects_truncated_prefix`, `handshake_rejects_truncated_body`, `handshake_rejects_wrong_cbor_shape`, `handshake_rejects_short_key`, `handshake_rejects_wrong_key_order`, `handshake_debug_redacts_key_bytes`, `handshake_drop_zeroizes_derived_key` (in-source); `oversize_handshake_prefix_fails_binary` + `truncated_handshake_prefix_fails_binary` + `well_formed_handshake_unlocks_protocol_loop` (subprocess-spawn integration); `binary_random_key_path_removed` (source-scan regression — fails CI if a future refactor reintroduces `OsRng::fill_bytes` or `fill_random(&mut key)` outside `#[cfg(test)]` in the binary's main.rs). Adversary leverage: bounded to "host-level compromise — already game over"; the binary's own attack surface is structurally smaller (no `DeviceKey` import).
2. **L-vault-id-disclosure — the indexer queries the RPC with `topic1 = vault_id`; a malicious or curious RPC operator learns the user's vault id.** Defense: none new in 4.2 (inherited from 4.1's same surface). Phase-2 Enhanced Privacy Mode (3.6 scaffolding; MVP-3 / MVP-4) is the documented architectural mitigation. Adversary leverage: same as 4.1's surface; no net change.
3. **L-stdio-injection — malicious JSON injected into the indexer's stdin.** Defense: (a) the indexer is spawned BY the host; only the host has access to the indexer's stdin (R-b posture). (b) `serde(deny_unknown_fields)` on the `IndexerRequest` enum rejects unknown variants + unknown fields → `IndexerResponse::Error`. (c) `MAX_REQUEST_LINE_BYTES = 65_536` cap rejects oversize lines BEFORE the parse attempt (defense-in-depth memory bound). (d) Malformed JSON surfaces a `protocol error` response without crashing the dispatcher. Tests: `malformed_input_rejected_as_protocol_error`, `unknown_request_variant_rejected`, `unknown_request_field_rejected`, `max_request_line_bytes_is_64k`. Adversary leverage: mitigated to "host-level compromise — already game over".
4. **L-idle-timeout-DoS — a hostile actor keeps the indexer alive indefinitely by pinging the keep-alive endpoint, pinning temp disk + an RPC connection.** Defense (R-c): const-pinned hard ceiling `IDLE_TIMEOUT_MAX_SECS = 3_600` (1 hour) clamps any env override; soft floor `IDLE_TIMEOUT_MIN_SECS = 60` clamps the other end. Both clamps applied at `resolve_idle_timeout_from` so a hostile env-var setting cannot bypass them. Tests: `idle_timeout_env_override_clamps_to_max`, `idle_timeout_env_override_clamps_to_min`, `idle_timeout_constants_are_pinned`, `idle_timeout_default_resolves_to_300`, `idle_timeout_fires_under_simulated_time`. Adversary leverage: bounded to 1 hour per attacker session — bounded resource cost.
5. **L-spurious-spawn — malicious code on the user's machine spawns `pangolin-indexer` directly, bypassing the host, pointed at the user's vault id.** Defense: there is no auth model in 4.2 (any local process can run the indexer). But spawning the indexer doesn't give access to anything secret — it just queries public RPC data filtered by `vault_id`. The temp DB belongs to the malicious process, not the host. The host's vault is untouched (L7 + L10 — the indexer crate has no `pangolin-store` dep so it cannot reach the publish API). Adversary leverage: essentially none — equivalent to "attacker queries the public RPC directly with `topic1 = vault_id`". The actual surface is L-vault-id-disclosure restated.
6. **L-host-indexer-mismatch — host and indexer disagree on the IPC schema version (a stale binary in PATH, a partial upgrade).** Defense (R-b): `IndexerResponse::Started` carries a `protocol_version: u16` field equal to the const `PROTOCOL_VERSION = 1`; the host MUST cross-check on receipt and abort on mismatch (documented contract). Both sides reject unknown variants strictly via `serde(deny_unknown_fields)`. Tests: `protocol_version_pinned_at_1`, `response_started_carries_protocol_version_field`. Adversary leverage: mitigated to a confused-deputy class bug, not a security surface.
7. **L-temp-dir-tampering — an attacker pre-creates a symlink at the path `tempfile::NamedTempFile` is about to create, pointing at a sensitive location.** Defense: `tempfile::NamedTempFile` uses `O_CREAT | O_EXCL | O_NOFOLLOW` on Unix (and the platform equivalent on Windows); pre-existing files cause `EEXIST` and the call retries with a different random suffix. The `O_NOFOLLOW` arm rejects symlinks. The temp dir is the OS-recommended user-specific temp dir (`%LOCALAPPDATA%\Temp` on Windows; `$TMPDIR` or `/tmp` on Linux/macOS) which is owned by the user; an attacker who can write symlinks there has the user's local creds. Adversary leverage: mitigated to "user-local attacker who can already write to user's temp dir" — already game over.

### Sync-mode selector (4.4) (`pangolin-store::vault::{select_sync_mode, sync_mode_preference, set_sync_mode_preference}` + `pangolin-store::meta::{read_sync_mode_preference, write_sync_mode_preference}` + `meta.sync_mode_preference` TEXT column)

> Source: `docs/issue-plans/4.4.md` + `crates/pangolin-store/src/vault.rs` (selector + accessors + the `SyncMode` / `SyncModePreference` enums) + `crates/pangolin-store/src/meta.rs` (column read/write helpers) + `crates/pangolin-store/src/schema.rs::migrate_sync_mode_preference_column` (additive nullable-column migration) + `docs/architecture/chain-sync.md` §"Sync-mode selector". Issue 4.4 ships the **client-side picker** that decides between 4.1's in-process slow-mode sync and 4.2/4.3's ephemeral fast-mode indexer. Per R-a..R-e (Kelvin sign-off 2026-05-16): first-sync-on-this-device heuristic (R-a — `last_synced_block_v1().is_none()` ⇒ `OfferFast`; else `Slow`); three-state preference flag in cleartext `meta.sync_mode_preference` column (R-b — `NULL` = `Auto`; `'always_slow'`; `'always_fast'`); pure picker as a `Vault` async method (R-c — `Vault::select_sync_mode(&self, rpc_url, env) -> Result<SyncMode>`); hermetic + doc-spec parity tests (R-d — 11 unit tests + 1 const-pin test + 2 schema migration tests); 3-variant unit-enum carrying no payload (R-e — `Slow`, `OfferFast`, `AlwaysFast`). **Non-security-critical surface:** the load-bearing security defenses live in the underlying sync paths (4.1's verifier + chain-id check; 4.2/4.3's ephemeral indexer + temp-DB cipher); 4.4 is read-only picker logic + a UX preference flag. L1 is the single load-bearing property: the selector NEVER auto-spawns the indexer — the host owns the spawn decision on user assent.

1. **L-malicious-RPC-fakes-chain-head — an attacker-controlled RPC returns `eth_blockNumber = small_value` so the selector concludes "0 unsynced; pick Slow" when in reality the vault has 5000 unsynced revisions.** Defense: the 4.4 R-a heuristic does NOT call the chain RPC — it only reads `Vault::last_synced_block_v1()` + `Vault::sync_mode_preference()` from the vault file. A malicious RPC cannot influence the selector's decision because the selector ignores the RPC entirely. (The `rpc_url` + `env` parameters on `select_sync_mode` are placeholders for future heuristics; today they are unused.) Even if a future heuristic adds an RPC call, the selector is advisory — once the user invokes the chosen mode, the actual sync execution applies the load-bearing defenses (4.1 L3 chain-id check, L4 pinned-address check, L5 per-event signer recovery + signer-field cross-check). A spoofed selector decision picks the wrong UX path but doesn't make the actual sync less secure. Adversary leverage: UX-degrade only (slow sync). Not a security concern.
2. **L-vault-state-staleness — `last_synced_block_v1` could in principle be stale (e.g., a 4.1 sync that updated the checkpoint optimistically but failed mid-chunk).** Defense: 4.1's monotonic invariant (L12) guarantees the checkpoint never moves backward; 4.1's two-stage Pending→Finalized machinery + reorg rollback (`rollback_pending_revisions_in_range`) handle staleness at the slow-mode layer. The selector inherits whatever state 4.1 reports verbatim; under the first-sync-only heuristic, "stale" doesn't apply — the only states are `None` (no sync yet) and `Some(_)` (at least one sync happened), both of which are well-defined regardless of whether the most recent attempt completed cleanly. Adversary leverage: none.
3. **L-preference-flag-tamper — a filesystem-tamperer flips `meta.sync_mode_preference` to `'always_slow'` (suppress fast-mode offers) or `'always_fast'` (force indexer spawn without per-session prompt).** Defense (L2 — preference flag is NOT in the AEAD payload): the column is cleartext by design (UX preference, not secret material; mirrors the 1.4 `session_idle_secs` precedent). A `'always_fast'` tamper exposes the user to L-temp-file-leak from 4.2 + L-vault-id-disclosure from 4.2's RPC query — both of which are already-documented surfaces in 4.2/4.3 threat model with their own defenses (zero-fill + AEAD + ephemeral key; vault id is also leaked by the equivalent direct-RPC query the indexer crate makes). A `'always_slow'` tamper merely degrades UX (denies the user the fast-sync prompt). Defense-in-depth: an unrecognized non-NULL value in the column (e.g., `"garbage"`) surfaces as `StoreError::Corrupted` via `SyncModePreference::from_meta_str` rather than silently degrading to a default — so a tamper that introduces a random string is loudly rejected at next open. The user always retains the ability to flip the preference via `Vault::set_sync_mode_preference`. Filesystem-tamper resistance of the vault file is out-of-scope per MVP-1/MVP-2 boundaries (covered by the OS-level file-permission discipline `Vault::create` enforces). Tests: `from_meta_str_rejects_unknown_value`, `sync_mode_preference_can_be_cleared`. Adversary leverage: UX-degrade only.

**Invariant additions:** none new. The cleartext-by-design `meta.sync_mode_preference` column is covered by existing invariants — the column is a UX preference parallel to `session_idle_secs`, and the AEAD-sealed payload boundary is unchanged.

### Publish queue + batching (5.1) (`pangolin-store::vault::{flush_publish_queue, publish_queue_state, enable_window_elapsed_flush, coalesce_dirty_markers}` + `pangolin-store::publish::{publish_all_for_vault, publish_one, BatchFlushReport, BatchFlushError, PublishQueueState}`)

> Source: `docs/issue-plans/5.1.md` + `crates/pangolin-store/src/publish.rs` (extracted from `apps/cli/src/sync.rs` per R-h) + `crates/pangolin-store/src/vault.rs` (5.1 constants + the four new `Vault` methods + `ActiveState` extension) + `docs/architecture/publish-queue.md`. Issue 5.1 layers a **30-second same-account coalescing window** on top of the existing P8-2 `dirty_accounts` table + P8-3 `publish_all` orchestrator so N rapid edits to the same account within a 30s window flush as ONE chain transaction. Per R-a..R-h (Kelvin sign-off 2026-05-16): const+env-var window with clamps (R-a); mandatory drain triggers + optional caps (R-b); per-account coalescing master-plan verbatim (R-c — cross-account batching impossible without a contract redeploy); reuse `dirty_accounts` (R-d — no new persisted state, no schema change); top-of-flush total-cost balance check (R-e); append-and-coalesce on balance-block (R-f); hermetic + 1 live `#[ignore]` test (R-g); LAYER + refactor `publish_all` into the library (R-h).

1. **L-tombstone-coalesced-away — user edits account X (revision A), then deletes account X (revision B, tombstone) within the 30s window; a bug in the coalescing rule could pick A over B and the chain never receives the delete intent.** Defense: `coalesce_dirty_markers` reads each account's head pointer from `account_identities.head_revision_id` (which is updated atomically inside `account_update` / `delete_account` in the SAME SQL transaction as the revision INSERT) and deletes every dirty marker whose `revision_id` ≠ the head pointer. Since `delete_account` updates the head pointer to the tombstone revision, the tombstone's marker is preserved and any prior live update's marker is pruned. Adversary leverage: none — the head-pointer rule is mechanical.

2. **L-clock-skew-coalesce-wrong-order — `dirty_accounts.marked_at` uses host wall-clock (`current_unix_ms`); a backwards-jumping clock (NTP correction) could make a later revision have an earlier `marked_at` than an earlier revision.** Defense: same as L-tombstone-coalesced-away — coalescing reads `head_revision_id` from `account_identities`, NOT `MAX(marked_at)` from `dirty_accounts`. The head pointer is monotonic with respect to vault state regardless of host-clock jitter. Adversary leverage: none.

3. **L-flush-during-lock-race — user clicks "lock" while a flush is in-flight on the chain (RPC has the request; receipt not yet returned); the in-flight async future holds a borrow of `ActiveState.evm_wallet` while `lock()` tries to drop it.** Defense: 5.1's L1 deviation pushes the drain decision to the host (5.1 does NOT auto-drain inside sync `lock()` because it would require making `lock()` async and rippling through 1.4 session policy). The recommended host pattern is: `vault.flush_publish_queue(&adapter, force=true).await; vault.lock();` — sequential, no concurrency. If the host violates this convention (calls `flush_publish_queue` from one task and `lock()` from another), Rust's borrow checker catches the conflict at compile time (the flush takes `&mut Vault`; `lock()` also takes `&mut Vault`; two concurrent `&mut Vault` is a compile error). Dirty markers ALWAYS persist through `lock()` regardless of whether a flush completed — so worst case the user re-unlocks and re-flushes. 5.4 will wire the always-on auto-flush orchestration layer that owns the pre-lock sequencing automatically. Adversary leverage: none — Rust's type system enforces the contract.

4. **L-window-DoS — a malicious host wrapper sets `PANGOLIN_BATCH_WINDOW_SECS=u64::MAX` (or simply never invokes `flush_publish_queue`), making the user think their edits landed when they're sitting locally as dirty markers.** Defense (R-a env-var clamp): `resolve_batch_window_secs` clamps any env-var value to `1..=300`; the upper clamp of 5 minutes bounds the worst-case stale window. Plus: `publish_queue_state().dirty_count` and `.dirty_byte_size` give the host UI a way to surface "you have N unpublished edits" indicators — a malicious wrapper that hides this surface is the same attacker class as one that maliciously shows the wrong vault contents (game over). Adversary leverage: bounded to 5 minutes per env-var-DoS attempt + visible via `publish_queue_state`.

5. **L-balance-blocked-grows-unbounded — per R-f, new edits during a balance-block append to the dirty markers; if balance is never restored, dirty markers grow forever (local `revisions` table also grows).** Defense (R-b caps + R-e pre-flight gate): `PUBLISH_QUEUE_COUNT_CAP = 100` + `PUBLISH_QUEUE_BYTE_CAP_BYTES = 1_000_000` give the host UI a flush-trigger signal via `publish_queue_state().dirty_count >= PUBLISH_QUEUE_COUNT_CAP` (or the byte equivalent). When the host invokes `flush_publish_queue` at the cap, the `ChainAdapter::pre_flight_batch_balance` method runs BEFORE any chain submit (R-e load-bearing — production `BaseSepoliaAdapter` queries `eth_getBalance` + `eth_feeHistory` against its alloy provider, returns `BatchBalanceCheck { total_estimated_cost_wei, current_balance_wei }`; the gate fails the entire batch with `BatchFlushError::BalanceInsufficientForBatch` carrying real wei values, NO partial submission); the local edit (and its dirty marker) still succeeds — caps are flush triggers, not refusal gates. **Documented limit:** a user with persistently-zero gas balance can grow their local vault unboundedly through edits; the threat model accepts this as "your local vault is yours; broadcast is asynchronous." Adversary leverage: UX-degrade only. Tests: `flush_returns_balance_insufficient_when_below_total` asserts ZERO `publish()` calls on the gated path; `pre_flight_batch_balance_aggregates_across_queued_count` verifies multi-account aggregation; `pre_flight_batch_balance_sufficient_proceeds_to_publish` verifies the happy path; `pre_flight_batch_balance_none_falls_back_to_per_revision_gate` covers back-compat with adapters that don't override the default-impl.

6. **L-malicious-RPC-fakes-receipt — the flush submits revision R; the RPC returns a fake receipt for a wrong tx hash.** Defense: inherited from 3.3 verbatim — `publish_revision_v1` does the load-bearing `tx_hash` cross-check (`ChainError::ReceiptMismatch` on disagreement); 5.1 calls 3.3 through `publish_one` without modification. Adversary leverage: same as 3.3's surface; no net change in 5.1.

7. **L-coalescing-skips-foreign-edit — account X's local lineage has a chain-frozen revision from device D2; 5.1's coalescing must respect this.** Defense: inherited from P8 CRIT-1 (`refuse_if_frozen`) — `account_update` / `delete_account` already refuse to mutate a frozen account at the API layer, BEFORE a dirty marker could be stamped. So a frozen account never has any dirty markers for the coalescing pass to consider. Adversary leverage: none — defense is mechanical at the prior layer.

**Invariant additions:** none new. The 5.1 surface adds no new on-disk state (R-d) and no new payload format (R-c); existing P8-2 `dirty_accounts` invariants + 4.1's monotonic checkpoint + 3.3's `tx_hash` cross-check cover the 5.1 attack surface.

### Pull loop (5.2) (`pangolin-store::vault::pull_once` + `pangolin-store::pull::{PullReport, PullError, PULL_INTERVAL_SECS_*}`)

> Source: `docs/issue-plans/5.2.md` + `crates/pangolin-store/src/pull.rs` (NEW module — types + constants + ~14 hermetic tests) + `crates/pangolin-store/src/vault.rs::pull_once` (NEW async primitive) + `crates/pangolin-store/src/vault.rs::resolve_pull_interval_secs[_from]` (env-var clamp helpers) + `crates/pangolin-store/src/vault.rs::last_pull_at_unix_ms` (diagnostic accessor) + `docs/architecture/pull-loop.md`. Issue 5.2 ships the per-cycle async primitive `Vault::pull_once(rpc_url, env, &vault_id) -> Result<PullReport, PullError>` that re-runs the 4.4 picker per cycle (R-c) and dispatches: `Slow` delegates to 4.1's `Vault::sync_from_chain` (L4 — no duplicate logic); `OfferFast` / `AlwaysFast` return signal-only (L2 — engine NEVER spawns the indexer; host owns that decision per 4.4 L1). Per R-a..R-f (Kelvin sign-off 2026-05-16): host-owned timer (R-a — `pangolin-store` exposes only the primitive; the host owns `tokio::time::interval`; zero `tokio::spawn` surface inside the store crate); const + env-var cadence `PULL_INTERVAL_SECS_DEFAULT=60` + `PANGOLIN_PULL_INTERVAL_SECS` clamped `5..=3600` (R-b); re-pick per cycle (R-c); flat retry on chain error at next interval (R-d — host scheduler concern; 5.4 owns "Offline" indicator); `PullError::NoActiveSession` cancellation discipline (R-e — mirrors 5.1's `BatchFlushError::NoActiveSession` posture verbatim); hermetic + 1 live `#[ignore]` test (R-f).

1. **L-pull-flood — a malicious host wrapper sets `PANGOLIN_PULL_INTERVAL_SECS=0` (or `=1`) to flood the RPC endpoint + drain the user's RPC quota + pin the main loop with continuous pull cycles.** Defense (R-b env-var clamp): `resolve_pull_interval_secs_from` clamps any env-var value to `5..=3600`; the `5` lower bound caps the rate at 12 pulls/min, well below any realistic RPC rate-limit. A non-parseable value (e.g., `"garbage"`) falls back to the 60s default. Tests: `resolve_pull_interval_env_var_clamps_to_min_5` + `resolve_pull_interval_env_var_clamps_to_max_3600` + `resolve_pull_interval_env_var_non_parseable_falls_back_to_default`. The host scheduler is also structurally responsible for not calling `pull_once` faster than the resolved interval; the engine itself never schedules. Adversary leverage: bounded to 12 pulls/min per env-var-DoS attempt.

2. **L-host-scheduler-leak — if the host scheduler doesn't notice teardown (a buggy host writes `loop { pull_once(...).await; sleep(...).await; }` without handling `Err(PullError::NoActiveSession)`), the tokio task surrounding the scheduler could outlive the session — calling `pull_once` after `lock()` returns `NoActiveSession`, but the loop body could keep ticking indefinitely.** Defense: (a) `pull_once` short-circuits to `NoActiveSession` BEFORE any chain primitive is touched (`if self.active.is_none() { return Err(PullError::NoActiveSession); }`) so the post-teardown calls are O(1) cheap and leak no secrets; (b) `docs/architecture/pull-loop.md` § "Canonical host scheduler loop body" documents the recommended pattern (`Err(PullError::NoActiveSession) => break,`) so every downstream host (CLI / Tauri / mobile) implements the contract consistently; (c) the worst-case lock→exit latency is bounded by the interval (≤60s default; ≤5s if the host has set `PANGOLIN_PULL_INTERVAL_SECS=5`). Test: `pull_once_on_locked_vault_returns_no_active_session` + `pull_once_on_locked_vault_returns_before_any_rpc_call` (proves the early-return short-circuit fires BEFORE any RPC connect attempt by handing the call a deliberately unreachable URL — a `NoActiveSession` result means we never reached the dispatch leg) + `pull_once_on_device_locked_vault_returns_no_active_session`. Engine-side: no actual leak.

3. **L-offer-fast-not-acted-on — the picker returns `OfferFast`, the host prompts the user, the user is AFK, no decision is made; 60s later the next `pull_once` returns `OfferFast` again; the user's vault remains un-synced (slow-mode never ran) until the user comes back.** Defense (load-bearing UX policy, host-side): `docs/architecture/pull-loop.md` § "UX contract for OfferFast" recommends the host auto-fall-through to `Slow` after 2 consecutive `OfferFast` ticks without an acknowledgment — either by re-rendering the prompt + dispatching slow-mode anyway, or by calling `Vault::set_sync_mode_preference(AlwaysSlow)` if the user has explicitly declined. 5.2 ships only the signal; downstream hosts implement the contract consistently. Adversary leverage: UX-degrade only (vault stays stale until next user interaction).

4. **L-revision-replay-via-stale-RPC — a malicious RPC serves the same `eth_getLogs` response twice; the pull loop would attempt to re-ingest events it already has.** Defense: inherited from 4.1 verbatim — `ingest_pending_chain_revision` is idempotent (the row's natural key is `(account_id, revision_id)` derived from the canonical hash; duplicate inserts no-op via `ON CONFLICT DO NOTHING` at the schema layer). 5.2's `pull_once` calls `sync_from_chain` which calls `ingest_pending_chain_revision`, so the defense propagates unchanged. Adversary leverage: none — duplicate events are no-ops; the chain layer's idempotency carries.

5. **L-checkpoint-corruption-during-pull — a mid-cycle crash (e.g., the user hits Ctrl-C while `sync_from_chain` is halfway through a chunk) could leave the persisted `last_synced_block_v1` checkpoint pointing past actually-ingested events, OR a malicious RPC could attempt to push the checkpoint backwards via a faked tip.** Defense: inherited from 4.1 verbatim — L12 monotonic checkpoint (`update_last_synced_block_v1` refuses any non-increasing write); the chunk-by-chunk advance pattern means the checkpoint always points to a fully-ingested chunk boundary; 4.1's reorg detector handles backwards-tip cases via `rollback_pending_revisions_in_range`. 5.2 adds zero new attack surface here because `pull_once` calls `sync_from_chain` directly without any new checkpoint manipulation. Test: `pull_once_with_invalid_rpc_url_returns_pull_error_chain` (asserts checkpoint preserved on chain-side failure). Adversary leverage: none — 4.1's L12 monotonic invariant carries.

6. **L-pull-after-lock-races — the host scheduler ticks fire just after `lock()`; the first `pull_once` after lock could in principle attempt a chain read against a torn-down session.** Defense (load-bearing, structurally enforced): the early-return `if self.active.is_none() { return Err(PullError::NoActiveSession); }` runs BEFORE the picker or any chain primitive. The `lock()` / `check_session_freshness` / `device_locked()` paths already drop `ActiveState`; the post-teardown `pull_once` observes `active.is_none()` + returns immediately. No `tokio::select!`, no cancellation token, no new accessor — the existing teardown paths carry the cancellation signal naturally. Test: `pull_once_on_locked_vault_returns_before_any_rpc_call` (handed an unreachable URL; a `Chain(_)` return would indicate the early-return failed and dispatch reached the chain leg). Adversary leverage: none.

7. **L-pull-during-flush-race — 5.2's `pull_once` and 5.1's `flush_publish_queue` both take `&mut self`; if a host accidentally invoked them concurrently on the same `Vault` handle from two tokio tasks, the rusqlite connection could see overlapping transactions OR the wallet borrow could deadlock.** Defense (structurally enforced at compile time): both methods take `&mut self`; Rust's borrow checker rejects concurrent invocation. The host scheduler MUST sequence pull + flush through the same single-threaded executor (CLI / Tauri / mobile all hold the Vault on the main loop). The same defense covers `L-pull-during-edit-race` (`account_update` also takes `&mut self`). Adversary leverage: none — Rust's type system enforces the contract.

**Invariant additions:** none new. The 5.2 surface adds no new on-disk state (the `last_pull_at_unix_ms` stamp lives only in `ActiveState`; not persisted) and no new payload format; existing 4.1 / 4.4 invariants cover the 5.2 attack surface. The `pangolin-chain` crate is unchanged.

### Conflict surfacing (5.3) (`pangolin-store::vault::{list_conflicts, snapshot_conflicts, list_conflicts_since}` + `pangolin-store::conflict::{ConflictReport, ConflictBranchSummary, ConflictSnapshot, ConflictDelta}` + `pangolin-store::pull::PullReport.newly_*` + `pangolin-ffi::revision::vault_list_conflicts`)

> Source: `docs/issue-plans/5.3.md` + `docs/architecture/conflict-surface.md` + `crates/pangolin-store/src/conflict.rs` (enriched `ConflictReport` + new `ConflictBranchSummary` / `ConflictSnapshot` / `ConflictDelta`) + `crates/pangolin-store/src/vault.rs::{list_conflicts (rewritten body), snapshot_conflicts (NEW), list_conflicts_since (NEW), pull_once (extended with pre/post snapshot diff)}` + `crates/pangolin-store/src/pull.rs::PullReport` (extended with three `newly_*` fields) + `crates/pangolin-ffi/src/revision.rs::vault_list_conflicts` (NEW FFI binding) + `crates/pangolin-store/tests/conflict_live.rs` (`#[ignore]`'d live test). Issue 5.3 ships the explicit conflict-detection + UI-surfacing plumbing that the existing 1.6 + P8 + P9 machinery had built up but never exposed at the host-facing layer. Per R-a..R-g (Kelvin sign-off 2026-05-16): confirm existing P8 CRIT-1 auto-freeze trigger (R-a — ZERO change to `ingest_chain_revision`); confirm existing 5.1 flush inline-anchor-stamp + 5.2 idempotency arm #1 (R-b — mandatory regression test `pull_after_local_publish_does_not_self_freeze` PASSED); extend `PullReport` with per-tick conflict-diff (R-c); enrich `ConflictReport` with per-branch metadata (R-d — breaking change); ship `vault_list_conflicts` FFI in 5.3 (R-e); defer auto-resolve (R-f); 14 hermetic + 1 live `#[ignore]` (R-g).

1. **L-self-fork-on-publish — this device publishes revision R via 5.1 flush; the next 5.2 pull-tick ingests R from chain; the existing P8 CRIT-1 trigger would fire + freeze the account; the user sees a "conflict" badge on their own account.** Defense (load-bearing, structurally enforced): 5.1's `publish_one` calls `Vault::mark_published(entry.revision_id, anchor)` INLINE after the chain publish succeeds — this stamps the local row's `chain_tx_hash` / `chain_block_number` / `chain_log_index` columns BEFORE any pull tick can see the round-trip event. When 5.2's `pull_once` ⇒ `sync_from_chain` ⇒ `ingest_chain_revision` ingests the round-trip event, idempotency arm #1 (exact-hash match on the row's canonical hash) fires and returns `IngestOutcome::AlreadyPresent` without re-inserting the row, so the genuine-foreign-INSERT path (which would freeze) is never reached. Test: `pull_after_local_publish_does_not_self_freeze` (mandatory regression in `crates/pangolin-store/src/pull.rs::tests`) — drives 5.1 `flush_publish_queue` against a `MockChainAdapter`, replays the round-trip event through `ingest_chain_revision`, asserts `outcome == AlreadyPresent` AND `account_status().is_frozen_pending_resolve == false`. The test PASSED on first run. The Q-b Option B in-memory just-published set was NOT required.

2. **L-byte-flip-on-frozen-row-via-FFI — a tampered local DB row (byte-flipped `is_tombstone` / `device_id` / `observed_at_block` / `schema_version`) surfaces wrong metadata to the host UI without authentication via `vault_list_conflicts`.** Defense (load-bearing): L2 — `list_conflicts` does NOT call any AEAD-open path; per-row metadata is best-effort + advisory. Load-bearing authentication is at AEAD-open call sites (`reveal_password` / `get_account` / `read_payload_plaintext_for_resolve`); host UI rendering on the conflict screen is advisory. A byte-flip of `is_tombstone` from `false` to `true` would render a misleading "this branch is a deletion" label, but the user's choice still routes through `account_resolve_fork` which builds + signs a merge revision; the merge-revision build cannot succeed against a tampered row that fails AEAD authentication when the chosen plaintext is read. Adversary leverage: UI mislabel only; cannot corrupt resolution outcome.

3. **L-conflict-surface-leaks-frozen-payload — the enriched `ConflictReport.branches` carries metadata per leaf (`device_id`, `observed_at_block`, `schema_version`, `is_tombstone`, `on_canonical_chain`, `parent`); could it leak anything sensitive that the freeze guard was meant to refuse?** Defense (load-bearing): all `ConflictBranchSummary` fields are metadata-class — already exposed via `FfiRevisionMeta` / `account_history`. The freeze guard refuses PLAINTEXT reveal (`refuse_if_frozen` on the write + reveal paths), NOT metadata. The 5.3 FFI binding is read-only by construction (L11) and metadata-only by construction (L2). No new leak surface. Adversary leverage: none — the metadata exposed via `vault_list_conflicts` is a strict subset of what `account_history` already exposes for the same revisions.

4. **L-PullReport-delta-overcounts-on-existing-frozen — the R-c set-difference for `newly_frozen_accounts` could in principle re-report an already-frozen carry-over from a prior tick (= UI fires "new conflict" notification when nothing actually changed).** Defense (load-bearing): set-difference is directional — `newly_frozen = post_snapshot.frozen − pre_snapshot.frozen` (computed inside `pull_once` between the two `snapshot_conflicts` calls), so an account that was frozen in both snapshots produces ZERO entries. Tests: `pull_tick_does_not_re_report_already_frozen_account` + `pull_tick_with_one_new_foreign_event_reports_one_newly_frozen` (pre-tick freeze carry-over does NOT re-surface) + `pull_tick_with_foreign_sibling_of_existing_head_reports_newly_forked_and_newly_frozen` (pre-tick fork carry-over does NOT re-surface). Adversary leverage: none — Rust borrow-checker + directional set-diff prevent the over-count.

5. **L-self-resolve-loopback — the user resolves account A via `resolve_fork` (P9); 5.1 flush publishes the merge revision M; 5.2 pull ingests M; the existing trigger RE-freezes A.** Defense: P9 §A3 race already addressed — `resolve_fork` stamps the local row's anchor inline + clears the freeze flag atomically; 5.2's `ingest_chain_revision` sees idempotency arm #1 (exact-hash on M's canonical hash) + returns `AlreadyPresent`. Same regression mechanism as L-self-fork-on-publish; the `pull_after_local_publish_does_not_self_freeze` test indirectly covers this (the same machinery — `mark_published` + idempotency arm #1 — fires for both cases). Adversary leverage: none.

6. **L-conflict-surface-races-with-resolve — the host scheduler sees a `PullReport.newly_frozen_accounts` includes account A, fires its notification; the user races a `resolve_fork` call before the host scheduler updates the screen state.** Defense (structurally enforced at compile time): both `resolve_fork` and `list_conflicts` take `&mut self` / `&self`; Rust's borrow checker sequences them through a single-threaded executor (CLI / Tauri / mobile main thread). The race surface is at most a UI flicker (the screen briefly shows "conflict pending" then transitions to "resolved"); the on-disk state cannot diverge. Adversary leverage: none.

7. **L-list-conflicts-perf-on-N-1000-frozen — under malicious-RPC (a flood of foreign chain events landing in a single pull-tick), N>1000 accounts could end up frozen in one cycle; `list_conflicts` becomes a UI hang.** Defense: the existing `list_conflicts` body is two indexed lookups (`list_frozen_accounts` + `all_forked_accounts`) plus one `revision_graph` build per conflicted account; per-account work is O(heads-per-account) (typically 2-3). Total: O(N-conflicted × heads-per-account). The chain-side rate-limit (block time + gas cost per `RevisionPublished` event) caps how fast N can grow in practice. For an attacker who somehow manages a 1000-account freeze: the host UI can paginate; `vault_list_conflicts` returns the full vector but the host owns the rendering pagination. Adversary leverage: bounded UI degradation; no plaintext leak.

8. **L-FFI-binding-bypasses-freeze-guards — the new `vault_list_conflicts` FFI binding could in principle bypass a `refuse_if_frozen` check that should have fired.** Defense (load-bearing): L2 — the binding is a thin map from `Vault::list_conflicts` (which is `&self` + metadata-only) into the FFI types. There is NO `refuse_if_frozen` check on read paths to bypass — the guard is only on the write paths + the reveal paths (per P8 CRIT-1). `vault_list_conflicts` is neither. Test: `vault_list_conflicts_ffi_does_not_decrypt_or_touch_freeze_guard` (deferred to a follow-up: the test would require instrumenting the call graph; the structural argument is the load-bearing defense). Adversary leverage: none.

**Invariant additions:** none new. The 5.3 surface adds no new on-disk state (no schema bump per L5); no new payload format; no new external crate dep (L7). The 5.3 FFI binding is read-only (L11). The `pangolin-chain` crate is unchanged.

### Sync orchestrator (5.4) (`pangolin-store::sync_status::{SyncStatus, compute_next_status, SyncStatusInputs, LastPullOutcome, LastFlushOutcome, PullErrorKind, BatchFlushErrorKind, OFFLINE_THRESHOLD_FAILURES, SYNCED_STALENESS_THRESHOLD_MS}` + `pangolin-store::vault::{sync_status_inputs, lock_with_drain}` + `pangolin-ffi::sync_status::{vault_sync_status, FfiSyncStatus, FfiSyncMode, FfiSyncStatusInputs, FfiSyncStatusSnapshot}`)

> Source: `docs/issue-plans/5.4.md` + `docs/architecture/sync-orchestrator.md` + `crates/pangolin-store/src/sync_status.rs` (NEW — `SyncStatus` 6-variant enum + pure `compute_next_status` transition function + type-erased outcome shapes + 20 hermetic tests) + `crates/pangolin-store/src/vault.rs::{sync_status_inputs (NEW bundling accessor), lock_with_drain (NEW pre-lock drain primitive — R-e)}` + `crates/pangolin-ffi/src/sync_status.rs` (NEW FFI binding — `vault_sync_status` + `FfiSyncStatus` enum + `FfiSyncMode` mirror + `FfiSyncStatusInputs` / `FfiSyncStatusSnapshot` records) + `crates/pangolin-store/tests/sync_status_live.rs` (NEW `#[ignore]`'d live test — fixture-capture follow-up). Issue 5.4 ships the host-side indicator state machine that fuses 5.1 `flush_publish_queue` + 5.2 `pull_once` + 5.3 `snapshot_conflicts` + 4.4 `SyncMode` + 3.5 `BalanceMonitor` into a single 6-variant pill (`Synced` / `Syncing { mode }` / `Offline { consecutive_failures }` / `ConflictsPending { count }` / `BlockedOnBalance { needed_wei, available_wei }` / `ActionRequired { reason }`). Per R-a..R-h (Kelvin sign-off 2026-05-17): pure host concept — engine ships SyncStatus enum + pure `compute_next_status` + bundling accessor + `lock_with_drain` only; host owns the tokio loop + the watch channel (R-a Option C); 6-variant single-pill state (R-b); 3-consecutive-failures offline threshold (R-c); interleaved two-timer host loop (R-d); pre-lock drain primitive closes 5.1 L1 deviation (R-e); read + watch channel (R-f); hermetic + 1 live `#[ignore]` (R-g); ship FFI in 5.4 with hex-string wei encoding per 3.5 BalanceMonitor pattern (R-h).

1. **L-offline-flapping — borderline RPC toggles the indicator chip on / off every tick.** Defense (load-bearing): R-c 3-consecutive-failures threshold. One or two failures do NOT transition to `Offline` (tests `one_chain_failure_does_not_transition_to_offline` + `two_consecutive_chain_failures_do_not_transition_to_offline`); only 3+ consecutive `PullError::Chain(_)` failures fire (test `three_consecutive_chain_failures_transition_to_offline` + range check `offline_threshold_requires_three_consecutive_failures`). Counter resets on ANY `Ok(_)` from `pull_once` — including signal-only OfferFast / AlwaysFast cycles per L4 (tests `signal_only_offer_fast_resets_consecutive_failures` + `signal_only_always_fast_resets_consecutive_failures`). At the 60s cadence the indicator stabilizes within ~3 min of a real outage starting + transitions back to `Synced` on the first successful tick. Adversary leverage: none — the threshold is a stability mechanism, not a security boundary.

2. **L-status-leaks-balance-detail — the `BlockedOnBalance { needed_wei, available_wei }` variant carries u128 wei values; could it leak balance to an observer with access to host logs / the FFI surface?** Defense (load-bearing): the same `(needed, available)` pair is already exposed via 5.1's `BatchFlushError::BalanceInsufficientForBatch` and via 3.5's `GasBalanceState::{Sufficient, RequiresActiveAccount}` — no new exposure surface. L5 §8.1.5 vocabulary discipline ensures the variant NAME doesn't leak pricing copy (`BlockedOnBalance` is the §8.1.5-approved label; NEVER `LowBalance` / `OutOfGas` / `InsufficientFunds` / `Upgrade` — pinned by `sync_status_variant_names_do_not_leak_pricing_copy`). The FFI surface emits wei as hex strings (`needed_wei_hex: "0x..."`) per the 3.5 `GasBalanceStateFfi` precedent — same posture as `balance_monitor_start` / `gas_balance_state`. The on-chain wallet balance is already observable to anyone who knows the device's EVM address (the address is on-chain in `DeviceRegistered` events); the indicator state surfaces the same data, more conveniently, to the user who already owns the wallet. Adversary leverage: none new.

3. **L-orchestrator-leaks-past-lock — the host's orchestration loop outlives a session-teardown (lock / idle-expire / 4h-absolute / `device_locked`); subsequent ticks accidentally probe the engine after the vault is torn down.** Defense (load-bearing, structurally enforced): the engine's `pull_once` + `flush_publish_queue` + `sync_status_inputs` + `lock_with_drain` all early-return `NoActiveSession` BEFORE touching state when the vault is locked (5.1 / 5.2 / 5.4 verbatim posture). The canonical host loop body documented in `docs/architecture/sync-orchestrator.md` breaks on `PullError::NoActiveSession` + `BatchFlushError::NoActiveSession`, exiting the loop within one tick of the lock (≤60s worst case). The transition function additionally maps `LastPullOutcome::NoActiveSession` to `SyncStatus::ActionRequired { reason: "vault locked" }` so any final UI render shows a sane terminal (test `orchestrator_tick_on_locked_vault_transitions_to_action_required`). The FFI binding refuses the call at the boundary with `FfiError::Session` on a Locked vault (test `vault_sync_status_ffi_refuses_on_locked_vault_with_typed_error`). Adversary leverage: none — the borrow checker + the typed `NoActiveSession` variants make this structurally impossible to bypass.

4. **L-conflict-pill-flashes-on-self-publish — user publishes a local revision via 5.1 flush; the next 5.2 pull-tick ingests the round-trip; a buggy implementation could transition `Synced → ConflictsPending → Synced` and flash the conflict banner on the user's own publish.** Defense (load-bearing): 5.3 R-b's mandatory regression test `pull_after_local_publish_does_not_self_freeze` guarantees that idempotency arm #1 (exact-hash match) fires on the round-trip + the freeze flag is NOT set. The 5.4 transition function consumes `conflicts_count` (= `frozen + forked` set union); on the round-trip tick that count stays 0 + the `LastPullOutcome::Success { newly_frozen_count: 0, .. }` matches the no-flash post-condition (test `self_publish_round_trip_does_not_flash_conflicts_pending`). Adversary leverage: none — the structural guarantee at 5.3's `ingest_chain_revision` layer + the transition function's read of the already-computed conflict set together close the loophole.

5. **L-balance-state-stale-vs-flush-error — the 3.5 `BalanceMonitor` polls on its own 30s cadence; the transition function may read `GasBalanceState::Sufficient` from the cache while a fresh flush just returned `BatchFlushError::BalanceInsufficientForBatch`. The transition function gets contradictory inputs.** Defense (load-bearing, encoded explicitly): step (3) of the transition order checks `last_flush_outcome` for `BatchFlushErrorKind::BalanceInsufficient` BEFORE consulting the cached `balance_state` field — a fresh flush error PREFERS the BalanceMonitor's cache (test `balance_state_stale_overridden_by_fresh_flush_error`). The flush gate IS the authoritative chain-side signal (it's the same `pre_flight_batch_balance` RPC the 3.3 publish path would use to refuse); the BalanceMonitor is a steady-state hint. Adversary leverage: none — the precedence is hardcoded in the pure function + tested.

6. **L-pre-lock-drain-races-with-edit — `lock_with_drain` calls flush; a concurrent edit attempts to mutate the queue between the drain + the lock.** Defense (structurally enforced at compile time): `lock_with_drain` takes `&mut self`; Rust's borrow checker compile-time-prevents any concurrent access on the same `Vault` handle. The drain runs against the current snapshot of the queue + the lock runs immediately after — there is no window for a concurrent edit. Adversary leverage: none.

7. **L-pre-lock-drain-flush-failure-blocks-teardown — a flaky chain (network timeout, balance-insufficient gate, store error) causes the drain to fail; if the failure blocked the lock transition the user would be stuck with a non-locked vault on a graceful close attempt.** Defense (load-bearing, L3 best-effort doctrine): `lock_with_drain` runs `self.lock()` REGARDLESS of the flush result; the flush error is returned to the caller AFTER lock runs (test `lock_with_drain_flush_failure_does_not_block_teardown` — asserts `VaultState::Locked` post-call even on `BalanceInsufficientForBatch` failure). Dirty markers persist in SQLite; the next unlock resumes the queue (covered by 5.1's `dirty_markers_persist_through_lock_and_resume_on_next_unlock`). Adversary leverage: none — best-effort drain matches 5.1 L1 doctrine "teardown wins".

**Invariant additions:** none new. The 5.4 surface adds no new on-disk state (`SyncStatus` lives in-memory only, in the host's `tokio::sync::watch::Sender` per R-f); no new payload format; no new external crate dep (L6 — `tokio::sync::watch` is a tokio sub-crate already in the tree). The 5.4 FFI binding is metadata-only by construction (L2 — `vault_sync_status` does NOT decrypt, does NOT call `get_account`, does NOT touch `refuse_if_frozen`). The `pangolin-chain` crate is unchanged.

### CLI-V1 wiring (CLI-V1) (`apps/cli/src/commands/{flush,queue_status,pull_status,sync_loop,sync_mode,wallet,balance,top_up,resolve}.rs` + `crates/pangolin-ffi/src/{publish_queue,sync_mode}.rs` + delta to `sync_status.rs` / `device.rs` / `session.rs` / `balance.rs`)

**What it ships:** seven new CLI subcommands + the canonical host scheduler loop body + 12 FFI bindings (8 wired, 4 stubs awaiting MVP-3 chain-adapter FFI). No new on-disk state, no new payload, no new external crate dep. Closes the deferred §3.x / §4.x / §5.x CLI-V1 follow-ups.

**Adversarial threats considered + load-bearing defenses:**

1. **L-cli-flag-injection-via-hex — malicious `--account-id <hex>` value contains SQL-meta / shell-meta / overflow vectors.** Defense: clap's `HexAccountId` value parser rejects non-hex + length-checks (existing P9 surface, unchanged); rusqlite parameterized queries throughout. Adversary leverage: none.

2. **L-resolve-prompt-misclick — R-d interactive `resolve` misreads keystrokes; user kept the wrong branch.** Defense: (a) print the full conflict table on stderr BEFORE the prompt; (b) re-confirm chosen branch with `[y/N]` second prompt showing the chosen revision id; (c) `--dry-run` flag preserved (test `interactive_resolve_re_confirms_chosen_branch`). Adversary leverage: none.

3. **L-sync-loop-leaks-creds-on-long-run — `pangolin sync loop` holds the unlocked vault for hours; SIGTERM late in shutdown could leave cleartext in memory.** Defense: (a) `lock_with_drain` on SIGINT closes the session (L3 — the canonical loop's pre-lock drain runs `Vault::lock()` regardless of flush result); (b) the 1.4 idle-expire / 4 h-absolute session policy fires; the loop catches `PullError::NoActiveSession` / `BatchFlushError::NoActiveSession` and breaks. Adversary leverage: bounded by the session timer — even a crash-mid-loop drops the `Vault` (ZeroizeOnDrop fires on the active-state snapshots).

4. **L-graceful-shutdown-loses-pending-flush — SIGINT during a `sync loop` iteration arrives between arms; pending flush lost.** Defense: `Vault::lock_with_drain` runs on shutdown (R-h retrofit, L3); the drain coalesces + force-flushes any markers before transitioning to Locked (test `sync_loop_sigint_during_loop_drains_pending_publishes`).

5. **L-top-up-rebroadcast-on-retry — `pangolin top-up` invoked twice in quick succession.** Defense: (a) `pangolin_funder_client::initiate_top_up`'s built-in idempotency on `attestation_hash` (3.4 R-d ledger); (b) CLI prompts for `[y/N]` confirmation before submission unless `--yes` is given; (c) `--yes` is REQUIRED on non-TTY contexts (test `cli_v1_top_up_requires_confirmation_flag_or_tty`).

6. **L-sync-mode-set-without-presence — `pangolin sync-mode set always-fast` changes a meta row without a fresh presence proof.** Defense: acceptable per 4.4 R-b — `SyncModePreference` is a UX hint, NOT secret material; the engine re-runs `select_sync_mode` every session, so a tampered preference column degrades UX but not security. The FFI binding `vault_set_sync_mode_preference` still gates on an Active session (refuses Locked vault) so the host UI cannot stamp a preference on a fresh launch before unlock.

**Invariant additions:** none new. R-g's 4 FFI stubs (`vault_flush_publish_queue` / `vault_lock_with_drain` / `vault_pull_once` / `vault_initiate_top_up`) return `FfiError::Internal { message: "... requires <X> FFI (MVP-3)" }` so the surface is locked but the body lands in MVP-3 once the chain-adapter / signer / Credit-attestation FFI handles ship. The §8.1.5 vocabulary discipline extends to every new subcommand's `--help` text (test `cli_v1_help_avoids_forbidden_user_facing_terms`). L1..L11 from `cli-v1.md` are preserved verbatim.

