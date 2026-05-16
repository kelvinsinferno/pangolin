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

### Ephemeral local indexer (4.2 skeleton; 4.3 hardening) (`pangolin-indexer::{session, protocol, cipher, error}` + `pangolin-indexer` binary)

> Source: `docs/issue-plans/4.2.md` + `crates/pangolin-indexer/src/{lib.rs, session.rs, protocol.rs, cipher.rs, error.rs}` + `crates/pangolin-indexer/src/bin/pangolin-indexer.rs` + `docs/architecture/indexer.md`. Issue 4.2 ships the structural skeleton for the opt-in fast-mode sync path (D-007): a single crate exposing both a library (`IndexerSession` for the mobile in-process flow) and a thin binary (desktop subprocess flow). The lifecycle drives a `tempfile::NamedTempFile`-backed SQLite temp DB that buffers verified events between the chain primitive (`pangolin_chain::fetch_and_verify_chunk` — same one 4.1 uses, L4 byte-identical output) and the host's `Pull`-driven drain. Per R-a..R-f (Kelvin sign-off 2026-05-16): single crate (R-a); stdio JSON protocol with `serde(deny_unknown_fields)` strict parse (R-b); const default idle timeout + env override clamp `[60, 3_600]` (R-c); `TempDbCipher` trait + `NoOpCipher` passthrough stub (R-d — 4.3 ships the real `AeadCipher`); lib + bin with `default = ["bin"]` Cargo feature shape (R-e); hermetic + cleanup-on-crash + `#[ignore]`'d live parity test suite (R-f). **4.2 ships the skeleton; 4.3 closes the temp-file-leak surface with ephemeral encryption + zero-fill before unlink.**

1. **L-temp-file-leak — a crashed indexer (panic / SIGKILL / OOM / power-loss) leaves a temp file on disk containing chain-event data.** Defense in 4.2: `tempfile::NamedTempFile` gives the random path (L1 — `O_CREAT | O_EXCL | O_NOFOLLOW` posture); the Drop impl unlinks on normal exit (L11 normal-exit branch); `panic = unwind` (workspace `[profile.release]` default) makes the Drop fire during stack unwinding (L11 panic branch — verified via `cleanup_on_panic_unwinds_temp_file`); the struct field-declaration order (conn before temp_db) closes the SQLite handle before the tempfile unlink so Windows `MoveFileEx`-style unlink succeeds; OS-temp-dir GC is the SIGKILL / `panic = abort` fallback. **Deferred to 4.3:** ephemeral per-run encryption key + `AeadCipher` impl (so a recovered temp file is ciphertext) + explicit zero-fill before unlink (so unlinked disk blocks are zeroed). Adversary leverage in 4.2 alone: a recovered temp file leaks `encPayload` ciphertext (already protected by the vault's MVP-1 AEAD) + `vault_id` + per-event metadata. Worth surfacing explicitly that 4.2 does NOT close this surface — 4.3 does. Tests: `cleanup_on_panic_unwinds_temp_file`, `cleanup_on_drop_in_cancelled_task`, `cleanup_when_multiple_sessions_dropped`, `cleanup_survives_idle_timeout_path`, `session_lifecycle_normal_exit_deletes_temp_db`.
2. **L-vault-id-disclosure — the indexer queries the RPC with `topic1 = vault_id`; a malicious or curious RPC operator learns the user's vault id.** Defense: none new in 4.2 (inherited from 4.1's same surface). Phase-2 Enhanced Privacy Mode (3.6 scaffolding; MVP-3 / MVP-4) is the documented architectural mitigation. Adversary leverage: same as 4.1's surface; no net change.
3. **L-stdio-injection — malicious JSON injected into the indexer's stdin.** Defense: (a) the indexer is spawned BY the host; only the host has access to the indexer's stdin (R-b posture). (b) `serde(deny_unknown_fields)` on the `IndexerRequest` enum rejects unknown variants + unknown fields → `IndexerResponse::Error`. (c) `MAX_REQUEST_LINE_BYTES = 65_536` cap rejects oversize lines BEFORE the parse attempt (defense-in-depth memory bound). (d) Malformed JSON surfaces a `protocol error` response without crashing the dispatcher. Tests: `malformed_input_rejected_as_protocol_error`, `unknown_request_variant_rejected`, `unknown_request_field_rejected`, `max_request_line_bytes_is_64k`. Adversary leverage: mitigated to "host-level compromise — already game over".
4. **L-idle-timeout-DoS — a hostile actor keeps the indexer alive indefinitely by pinging the keep-alive endpoint, pinning temp disk + an RPC connection.** Defense (R-c): const-pinned hard ceiling `IDLE_TIMEOUT_MAX_SECS = 3_600` (1 hour) clamps any env override; soft floor `IDLE_TIMEOUT_MIN_SECS = 60` clamps the other end. Both clamps applied at `resolve_idle_timeout_from` so a hostile env-var setting cannot bypass them. Tests: `idle_timeout_env_override_clamps_to_max`, `idle_timeout_env_override_clamps_to_min`, `idle_timeout_constants_are_pinned`, `idle_timeout_default_resolves_to_300`, `idle_timeout_fires_under_simulated_time`. Adversary leverage: bounded to 1 hour per attacker session — bounded resource cost.
5. **L-spurious-spawn — malicious code on the user's machine spawns `pangolin-indexer` directly, bypassing the host, pointed at the user's vault id.** Defense: there is no auth model in 4.2 (any local process can run the indexer). But spawning the indexer doesn't give access to anything secret — it just queries public RPC data filtered by `vault_id`. The temp DB belongs to the malicious process, not the host. The host's vault is untouched (L7 + L10 — the indexer crate has no `pangolin-store` dep so it cannot reach the publish API). Adversary leverage: essentially none — equivalent to "attacker queries the public RPC directly with `topic1 = vault_id`". The actual surface is L-vault-id-disclosure restated.
6. **L-host-indexer-mismatch — host and indexer disagree on the IPC schema version (a stale binary in PATH, a partial upgrade).** Defense (R-b): `IndexerResponse::Started` carries a `protocol_version: u16` field equal to the const `PROTOCOL_VERSION = 1`; the host MUST cross-check on receipt and abort on mismatch (documented contract). Both sides reject unknown variants strictly via `serde(deny_unknown_fields)`. Tests: `protocol_version_pinned_at_1`, `response_started_carries_protocol_version_field`. Adversary leverage: mitigated to a confused-deputy class bug, not a security surface.
7. **L-temp-dir-tampering — an attacker pre-creates a symlink at the path `tempfile::NamedTempFile` is about to create, pointing at a sensitive location.** Defense: `tempfile::NamedTempFile` uses `O_CREAT | O_EXCL | O_NOFOLLOW` on Unix (and the platform equivalent on Windows); pre-existing files cause `EEXIST` and the call retries with a different random suffix. The `O_NOFOLLOW` arm rejects symlinks. The temp dir is the OS-recommended user-specific temp dir (`%LOCALAPPDATA%\Temp` on Windows; `$TMPDIR` or `/tmp` on Linux/macOS) which is owned by the user; an attacker who can write symlinks there has the user's local creds. Adversary leverage: mitigated to "user-local attacker who can already write to user's temp dir" — already game over.

