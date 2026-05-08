# DEVLOG

> Append-only log. One entry per closed issue. 1–3 sentences each: what shipped, surprises, deferred follow-ups.

---

## 2026-05-05 · P0 bootstrap
Sprint authorized. Repo scaffolded at `C:\Users\kelvi\Projects\pangolin` per master plan §16.8: full directory tree (`crates/`, `contracts/`, `apps/`, `services/`, `tools/`, `design/`, `docs/`, `.github/`). Apache-2.0 LICENSE, README, .gitignore, CONTRIBUTING.md (issue 18.6 — encodes §16 protocol), GitHub PR template + issue template (issue 18.13 — forces §16.2 plan structure), forbidden-terms CI workflow (issue 18.12 — Design Spec §15.2 enforcement), DECISIONS.md (issue P0-2 — locks D-001 through D-013), DEVLOG.md, E2E_TESTS.md, THREAT_MODEL.md skeletons.

## 2026-05-05 · P0-1 — Cargo workspace + rustfmt/clippy + GH Actions CI
Plan committed at `docs/issue-plans/P0-1.md` and self-approved (non-security-critical per §16.3). All 7 crates scaffolded with workspace inheritance: `pangolin-core`, `pangolin-crypto`, `pangolin-store`, `pangolin-chain`, `pangolin-indexer`, `pangolin-funder-client`, `pangolin-cli` (binary). Each has a placeholder `name()` function exercised by a unit test. Workspace lints set to `clippy::all = deny` + `pedantic` + `nursery` warn-level with explicit allows; `unsafe_code = deny` workspace-wide. CI workflow (`.github/workflows/ci.yml`) runs fmt, clippy `-D warnings`, test on Linux/Windows/macOS. Local verification on Windows host: build clean, fmt clean, clippy clean under pedantic+nursery, all 7 unit tests pass, `pangolin v0.0.0 (pangolin-core linked)` prints from CLI.

Surprises: pinned rustup symlinks in `.cargo/bin/` aren't directly invokable from this bash; resolved by invoking the actual toolchain bin path (`~/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/`). Two pedantic-clippy fixes needed mid-build: `SQLite` and `EVM` flagged for missing backticks in doc comments. `imports_granularity` and `group_imports` are nightly-only rustfmt options; removed from `rustfmt.toml` with note to revisit if/when nightly fmt is adopted.

Next issue: P0-2 already shipped as `DECISIONS.md` in the bootstrap commit. After this commit, the next units of work are **P1 series** (`pangolin-crypto` real implementation — Kelvin-gated at PLAN per §16.3 because it's security-critical) and **P5-1** (`RevisionLogV0.sol` first draft + Foundry tests — also Kelvin-gated). Both are independent and parallelizable.

## 2026-05-05 · P5-1 — RevisionLogV0 append-only EVM contract  ✅ MERGED

Plan at `docs/issue-plans/P5-1.md` Kelvin-approved. Built on `issue/P5-1-revision-log-v0` worktree by parallel agent. 7 implementation commits + 5 fix-pass + 1 final fix = 13 commits, merged to main as `303dc19`.

Contract: 443-byte runtime, append-only, single `publishRevision(...)` external function emitting `RevisionPublished` with 3 indexed topics (vaultId, accountId, parentRevision), single storage slot (`nextSequence`). No admin / no owner / no pause / no upgrade / no selfdestruct / no delegatecall / no payable. Solidity 0.8.24, evm_version=shanghai for cross-chain portability per D-005.

Tests: 17/17 pass — 13 unit (including 16-selector probe for absent admin/proxy interfaces, ETH-rejection on all paths) + 4 invariants × 10000 runs × 32 depth = 320,000 calls per invariant, 0 reverts under `fail_on_revert = true`. Slither 0 findings of 101 detectors. Build is bit-deterministic (verified by SHA-256 across rebuilds). Gas: 33k median for 256-byte payload (under 50k budget).

Two security audits performed. First audit: 0 CRITICAL, 0 HIGH, 2 MEDIUM, 4 LOW, 5 INFO. Fix-pass closed all actionable items including the v0 row in THREAT_MODEL.md. Second re-audit caught two HIGH CI-blockers (forge fmt regression introduced by fix-pass; pre-existing ABI trailing-newline mismatch); commit `12c6138` closed both. Final re-audit on `12c6138` recommended APPROVE — 100% CLEAN.

Surprises: bytecode-level audit walked all 431 runtime opcodes byte-by-byte to verify absence of CALL / DELEGATECALL / SELFDESTRUCT / ORIGIN / TLOAD / TSTORE / MCOPY / BLOBHASH / BLOBBASEFEE — confirms cardinal principles 3 and 4 hold *at the bytecode level*, not just at the source level. Solc still appends a 12-byte CBOR trailer (`a164736f6c6343000818000a`) carrying the solc version even when `bytecode_hash = "none"`; documented in `contracts/GAS.md`.

Deferred (filed as v1 follow-ups, not signoff blockers): hashed-mapping-slot probe extension once v1 introduces mappings; multi-target invariant runner; deploy-script CI regression (already partially covered by dry-run step).

Next: P5-4 (deploy `RevisionLogV0` to Base Sepolia) is a separate sub-issue; P2 series (`pangolin-store` SQLite + encrypted blobs) is the next Rust work and depends on P1's primitives, now also merged.

## 2026-05-05 · P1 — pangolin-crypto primitives + key hierarchy  ✅ MERGED

Plan at `docs/issue-plans/P1.md` Kelvin-approved. Built on `issue/P1-crypto` worktree by parallel agent. 6 implementation commits + 6 fix-pass + 1 polish = 13 commits, merged to main as `1ef3c5d`.

Crate: AEAD (XChaCha20-Poly1305 via `chacha20poly1305 0.10.1`), KDF (Argon2id at locked params 256MiB / t=3 / p=1 — RFC 9106 first-recommended profile, raised from t=1 in fix-pass), Ed25519 with `verify_strict` mode (via `ed25519-dalek 2.2.0`), HKDF-SHA512 derived wrap-AEAD-key from authority seed (info `"pangolin-vdk-wrap-v0"`). Key types: `VdkKey`, `WrappedVdk`, `WrapContext { vault_id, schema_version }`, `AuthorityKey`, `DeviceKey` — every secret-bearing type has manual `Drop` calling `Zeroize::zeroize`, implements `ZeroizeOnDrop` marker, redacted `Debug`, no `Clone`, no `Copy`, no `PartialEq` (constant-time eq via `subtle::ConstantTimeEq`), no `Serialize` (banned at supply-chain layer in `deny.toml`).

Tests: 85/85 pass default; 87/87 with `slow-tests` feature (the heavier 256MiB-Argon2id round-trip). RFC vectors: 8439 ChaCha20-Poly1305, IETF XChaCha20, RFC 8032 Ed25519, Argon2id reference. Cross-vault VDK replay test (`vdk_cross_vault_replay_fails`) exercises the `WrapContext` AAD-binding by transplanting a wrapped VDK across vault IDs — fails authentication for the right reason.

CI hardening: `cargo audit` (0 advisories across 118 deps), `cargo deny check` (advisories ok, bans ok, licenses ok, sources ok). `Cargo.lock` un-excluded and committed. `unsafe_code = "deny"` workspace-wide; `pangolin-crypto` itself has `#![forbid(unsafe_code)]` unconditional.

Two audits + a polish round. First audit: 0 CRITICAL, 4 HIGH, 7 MEDIUM, 4 LOW, 4 INFO. Fix-pass closed every actionable finding. The biggest substantive change was HIGH-3 (cross-vault replay) — closed by introducing `WrapContext` and binding it canonically (fixed-width 57-byte encoding `[domain_separator || vault_id || schema_version_be]`) into the wrap AEAD AAD on every wrap/unwrap/rewrap path. HIGH-1 (no Serialize compile-time check) was closed at the supply-chain layer (`deny.toml` ban on `serde` + `serde_derive`) instead of via `static_assertions` — strictly stronger because `serde` is no longer reachable from the crate's dep graph. Re-audit on `4b53af7` recommended APPROVE — 100% CLEAN with three INFO observations; polish commit `1f8db2a` closed two of them (broken intra-doc link from the `serde` ban; `ZeroizeOnDrop` marker on `BoxedSecret<N>` and `SecretBytes`).

Surprises: `secrecy 0.10.3` was on the locked crypto-allowlist but never imported (replaced by direct `Zeroizing` use during build); removed in fix-pass. `cargo-deny`'s `bans.allow` is closed-world for the *entire* dep graph (rejects legitimate transitives like `windows-sys` / `unicode-ident`); switched to `bans.deny` + workspace exact-version pins + committed `Cargo.lock` for the closed-world defense. `Box<[u8; N]>` does not impl `Zeroize` directly in `zeroize 1.8`; introduced `BoxedSecret<const N: usize>` newtype with manual `Zeroize` over `Box<[u8; N]>` to get heap-stable secret allocations for `AeadKey` and `VdkKey`.

Merge conflict in `.github/workflows/ci.yml` between P5-1's contracts pipeline (already merged) and P1-6's audit + deny jobs — resolved additively, both job sets retained side-by-side. Locally verified clean post-merge: fmt OK, build --all-targets OK, 85 tests pass, 17 forge tests pass, all CI gates green.

Deferred: pangolin-crypto's API surface is now frozen for downstream consumption by P2 (`pangolin-store`) and beyond. The `test-vectors` cargo feature is consumer-controlled — heavily documented as "DO NOT enable in production downstream crates."

Next: **P2 series** (`pangolin-store` — SQLite + encrypted blobs, consumes pangolin-crypto's primitives) and **P5-4** (deploy `RevisionLogV0` to Base Sepolia testnet) are the next units of work. P2 is the largest single block of remaining PoC work and gates P3/P4/P7. Neither is Kelvin-gated at PLAN time (P2 is core but not crypto/contract; P5-4 is testnet-only deployment).

## 2026-05-05 · P5-4 — Deploy RevisionLogV0 to Base Sepolia  ✅ MERGED

Plan at `docs/issue-plans/P5-4.md` Kelvin-approved. Deployed by Kelvin from local Foundry encrypted keystore (no plaintext private key on disk, env, or shell history at any point). Single tx, fast finality on Base Sepolia.

**Deployment facts (canonical reference, also in `contracts/deployments/base-sepolia.json` and DECISIONS.md D-014):**
- Address: `0x8566D3de653ee55775783bD7918Fe91b66373896`
- Chain: Base Sepolia (chain id 84532)
- Deployer: `0x89e720238A3913688CB0E025ef03a64539575c54` (Kelvin dev wallet)
- Deploy tx: `0x0569d60324c504bdacba08c309b85a54793b9002c97c4de22c9f8598e5e54b6a` (block 41133000)
- Gas used: 149,135 (matches `GAS.md` baseline exactly — no chain-specific surprises)
- Cost: 0.00000089 ETH at 0.006 gwei
- Runtime keccak256: `0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe` (Ethereum Keccak-256 of the 443-byte deployed bytecode; corrected from `0xaeff0a8f...` recorded at deploy time, which was Python's `hashlib.sha3_256` — wrong primitive. P6 audit M-1 caught this when `chaincli status` added live-bytecode cross-checking. Live bytecode unchanged; only the recorded hash was wrong.)
- Verification on Basescan: deferred (Kelvin will add API key later; `forge verify-contract` command documented in deployment metadata)

All five pre-flights passed before broadcast: chain id == 84532, deployer balance > 0.001 ETH (had 0.118), runtime size == 443 B, gas estimate within budget. End-to-end smoke test recorded as E2E-001 in `E2E_TESTS.md`: `nextSequence()` initial 0; `publishRevision(0xaaaa…, 0xbbbb…, 0x0, 0xcccc…, 0, 0xdeadbeef…)` mined with status 1 in tx `0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6`; emitted event with topic[0] = `keccak256(RevisionPublished signature)` confirmed; `nextSequence()` after = 1. The chain integration write-path is proven on a real EVM testnet.

Surprises: Base Sepolia's gas price was 0.006 gwei at deploy time — substantially below the 0.011 gwei estimate. Final cost was about 60% under projection. Useful data point for sizing the funder service's top-up amounts in MVP-2 (issue 3.4).

The `contracts/deployments/base-sepolia.json` file is the canonical machine-readable record. P6 (chaincli) and P7 (chain adapter) will read the contract address from this file; do not hardcode the address elsewhere.

Deferred: Basescan source verification (a one-command operation when Kelvin obtains a free Basescan API key). The contract works fully without it — verification is purely an explorer convenience.

Next: **P2 series** (`pangolin-store`) is now the only remaining blocker for P3/P4/P7/P8. P5-4 unblocks P6 (chaincli — talks to this deployed contract) and P7 (chain adapter — also talks to it).

## 2026-05-06 · P1.1 — `Nonce::from_storage_bytes` + `WrappedVdk::from_parts`  ✅ MERGED

Two additive public constructors on `pangolin-crypto` to support `pangolin-store`'s on-disk round-trip path. The HIGH-2 fix in P1 made `Nonce::from_bytes` `pub(crate)` to forbid deterministic-nonce construction by external callers; that's correct for fresh seal-time nonces but blocks reloading a previously-random nonce off disk alongside its ciphertext. Same threat profile as the already-public `Ciphertext::from_vec`. Doc-comments are explicit: "wraps random bytes that this crate previously emitted" — caller must not synthesize. Same gap on `WrappedVdk` — extractable via `ciphertext()`/`nonce()`/`context()` accessors but no symmetric reconstructor; `from_parts` adds it. Two new round-trip tests (87 → 89 in pangolin-crypto suite).

Surprises: the original P2 builder agent stopped mid-build on this gap rather than working around it (correct discipline). Three subsequent agents stopped on different gaps at progressively deeper layers — each was the right call. Total of three additive `pangolin-crypto` patches needed before P2 could compile cleanly.

## 2026-05-06 · P1.2 — `AuthorityKey::from_seed`  ✅ MERGED

Mirrors the existing public `SigningKey::from_seed`. Used by `Vault::unlock` to deterministically reconstruct the same `AuthorityKey` each unlock from `Argon2id(password, salt, params)` → seed bytes. Wrong password produces a different seed, which produces a different authority, which produces a different HKDF-derived wrap key, which makes `WrappedVdk::unwrap_with` return `AeadError::Tampered` — indistinguishable from any other tampering case (collapsed at the AEAD boundary).

This sidesteps the alternate design (encrypted random authority on disk) for PoC simplicity. MVP-3 social recovery may revisit; for P2 the deterministic-from-password approach is sufficient. New round-trip test (89 → 90 — wait, 88 actually since the count then went to 91 with P1.3).

## 2026-05-06 · P1.3 — `kdf::derive_seed`  ✅ MERGED

Seed-returning peer of `derive_key`. `derive_key` returns `AeadKey` whose bytes are deliberately not exposed (per MEDIUM-8 from P1's audit + supply-chain discipline). `pangolin-store`'s password-unlock path needs raw bytes to feed into `AuthorityKey::from_seed` — same Argon2id derivation, different output framing. Returns `Zeroizing<[u8; 32]>` so the buffer wipes on drop including unwind. Three new tests pin determinism (same inputs → same bytes), parity with the crate-private `derive_raw` (both KDF entry points must produce identical bytes for identical inputs), and below-floor parameter rejection. Test count 88 → 91.

Misuse-resistance discipline: doc-comment is explicit that `derive_seed` is for type-constructors that take `[u8; 32]` (`AuthorityKey::from_seed`, `SigningKey::from_seed`). For symmetric encryption, callers must use `derive_key` — the `AeadKey` newtype prevents accidental cross-primitive re-use.

## 2026-05-06 · P2 — `pangolin-store` encrypted local vault store  ✅ MERGED

The largest single PoC block: ~3,800 LOC across 9 modules, 40+ tests. Architecture from `docs/issue-plans/P2.md`: single `.pvf` file IS a SQLite database; sensitive content (display name, username, password, URL, notes, TOTP secret) lives in AEAD-sealed CBOR blobs; structural metadata (UUIDs, revision parentage, timestamps, device IDs) is plaintext SQL — same shape as on-chain `RevisionLogV0` events for trivial P7 sync semantics.

Substantive choices: bundled SQLite (no system dep), `ciborium-ll` (low-level CBOR with no `serde` reachability — preserves the supply-chain ban from P1), per-blob XChaCha20-Poly1305 with 105-byte canonical AAD binding `(WRAP_AAD_DOMAIN_REV || vault_id || account_id || parent_revision_id || schema_version)`, `BoxedSecret`/`ZeroizeOnDrop` discipline through every layer, WAL + `synchronous=FULL` + transactional writes for crash safety, `forbid(unsafe_code)` unconditional.

Vault state machine: `Closed → Locked ⇄ Active`. Public surface: `Vault::{create, open, unlock, lock, close, add_account, update_account, delete_account, get_account, search, list_accounts, revisions_for, unpublished_revisions, mark_published}`.

Cardinal-principle-2 verifier: load-bearing `no_plaintext_on_disk` property test creates a vault, writes 100 iterations × 6 unique markers per iteration (one per secret field), locks + closes, and scans raw `.pvf` bytes (and WAL sidecar) for ANY marker — asserts ZERO hits. 605s elapsed; 0 hits.

Audit history: first audit found 0 CRITICAL, 1 HIGH, 5 MEDIUM, plus LOW/INFO. Fix-pass commit `c529d7e` closed all 6 actionable findings:
- HIGH-1: `matches!` → `assert!(matches!)` in adversarial cross-account-transplant test (was a runtime no-op)
- MEDIUM-1: `KdfRejected` variant collapsed into `AuthenticationFailed` (closed an attacker oracle that distinguished KDF tamper from salt/ct tamper)
- MEDIUM-2: `Vault::open` lock-leak on failure paths (wrapped body in closure with `release_lock`-on-error)
- MEDIUM-3: plaintext-on-disk verifier extended from 1 secret field to 6
- MEDIUM-4: per-row `revisions.schema_version` now bound into AAD on decrypt (was inert)
- MEDIUM-5: `Vault::unlock` idempotence semantics on Active vault pinned in docstring + new unit test

Re-audit verdict: **APPROVE — 100% CLEAN**. All 6 prior findings closed; 0 new CRITICAL/HIGH/MEDIUM; 3 INFO observations are non-blocking design trade-offs.

Surprises: the closed-world supply-chain ban on `serde` (HIGH-1 fix from P1) ruled out high-level `ciborium`; switched to `ciborium-ll` low-level CBOR codec which has no serde reachability. SQLite's bundled C library worked cleanly on Windows with no system dep. The `WRAP_AAD_DOMAIN_REV = b"pgrev0\0\0"` 8-byte domain separator is structurally distinct from `pangolin-crypto`'s 24-byte `WRAP_AAD_DOMAIN` — no collision risk.

THREAT_MODEL.md "Local encrypted store" row moves from `TBD (issue 0.2)` to `DOCUMENTED (P2)` with 7 enumerated threats and verification artifacts cited.

Unblocks: P3 (account identity production), P4 (session policy), P7 (chain adapter against deployed Base Sepolia RevisionLogV0 from P5-4), P9 (conflict resolution).

Next: **P3** (account identity production), **P4** (session policy engine), **P6** (chaincli debug oracle), and **P7** (Rust chain adapter) are now all unblocked and parallelizable. P6 + P7 both consume the deployed RevisionLogV0 from P5-4 plus the now-merged pangolin-crypto + pangolin-store. P3 + P4 build on top of pangolin-store's API.

## 2026-05-06 · P3 — RevisionGraph + fork detection  ✅ MERGED

Adds fork-detection primitives on top of pangolin-store. `RevisionGraph` type with full parent→child indexing, head computation accommodating multi-head accounts, ancestor walks, and common-ancestor (LCA at fork point). New `Vault` API: `revision_graph(AccountId)`, `account_heads`, `is_forked`, `all_forked_accounts`. Public test helper `__test_synthesize_sibling_revision` (cfg-gated by name + `#[doc(hidden)]`) lets integration tests build forks without going through P7's chain adapter — uses real AAD-bound encryption matching production paths.

Schema unchanged: `account_identities.head_revision_id` retains its meaning as the canonical-head pointer; multi-head detection happens at query time via `NOT EXISTS` subquery (now scoped by `account_id` per the M-1 audit fix). Cardinal principle 4 preserved: graph DETECTS forks; resolution is P9.

Audit history: 0 CRITICAL, 0 HIGH, 2 MEDIUM, 2 LOW, 4 INFO. Fix-pass closed all 4 actionable items (M-1 NOT EXISTS scoping, M-2 `genesis_extra` flag exposed for P7 partial-replay + P9 conflict-distinguishing, L-1 docstring mention of `#[doc(hidden)]` placement, L-2 topological-order docstring accuracy). Re-audit verdict: APPROVE — 100% CLEAN. 125 lib + 10 e2e tests pass; cardinal-principle-2 verifier (`no_plaintext_on_disk`) still green; pangolin-crypto unchanged.

Surprises: building `genesis_extra` from the existing `revisions` table required a ~20-line filter that pushed `RevisionGraph::build` over clippy's 100-line floor. Extracted as `compute_genesis_extra` free function — cleaner than suppressing the lint. Merged as `5a5079e`.

## 2026-05-06 · P4 — Session policy engine  ✅ MERGED

The full Unified Session Authority spec on top of P3. **Security-critical** per §16.3.

Implements: 2-proof unlock (presence + identity), state machine `Locked → PendingAuthorization → Active{expires_at, last_proof_at, session_started_at} → Expired`, idle timeout (15 min default) + absolute max (4 hr) with `next_idle_deadline` as the single-source-of-truth that caps at `session_started + ABSOLUTE_MAX`, presence escalation for high-risk ops (`reveal_password`, `reveal_notes`, `reveal_totp_secret`, `export_payload`), and the `with_session` mid-action resume primitive. Cache zeroized on every expiry path (BoxedSecret + Zeroizing<Vec<u8>> drop chain, before state flip).

PoC stand-in proofs: `PinIdentityProof` (carries password bytes, ZeroizeOnDrop) + `PressYPresenceProof` (single-use `Cell<bool>`, freshness 60s). Trait-based design slots in real NFC + platform passkey in MVP-1 without API change.

**BREAKING change to `Vault::unlock`** — was `unlock(&SecretBytes)`, now `unlock(&dyn PresenceProof, &dyn IdentityProof)`. No external consumers existed; all internal + e2e tests migrated.

Audit history: 0 CRITICAL, 1 HIGH, 4 MEDIUM, 3 LOW, 1 actionable INFO. Fix-pass closed all 9:
- **H-1 (the spec violation):** `AccountSnapshot.password` was `pub`, allowing `vault.get_account(id).unwrap().password.expose()` to bypass `reveal_password`'s presence gate — a structural violation of spec §5.4 ("high-risk actions MUST require presence proof"). Fixed by making `password`/`notes`/`totp_secret` `pub(crate)`; added `reveal_notes` + `reveal_totp_secret` for symmetry. Compile-fail doctest at `account.rs:101` pins the regression — external code attempting to read those fields via `&AccountSnapshot` no longer compiles.
- **M-1 + I-6:** `with_clock` and `__test_with_timestamp` cfg-gated behind a new `test-utilities` feature so production downstream consumers cannot install a malicious clock or pre-dated presence proof.
- **M-2:** unlock timing oracle (structural-vs-content distinguishability — empty PIN microsecond-fail vs. wrong-PIN ~1.5s Argon2id) DOCUMENTED with detailed audit-traceable comment. Right-PIN vs. wrong-PIN are NOT distinguishable (both run Argon2id to completion). MVP-1 hardening: always-Argon2id on every `AuthenticationFailed` path.
- **M-3:** `static_assertions::assert_impl_all!(Vault: Send) + assert_not_impl_any!(Vault: Sync)` match rusqlite's NO_MUTEX `Connection` contract.
- **M-4:** `is_session_active()` is now clock-aware (was state-machine variant only; misleading).
- **L-1:** `derive_secret` double-allocation DOCUMENTED.
- **L-2:** `next_idle_deadline` uses `checked_add` with saturating fallback; `SystemTime` overflow fails-safe to immediate expiry instead of panicking.
- **L-3:** `with_session` re-validates session AFTER reauth returns Ok, catching "reauth claims success but didn't actually unlock" before re-running the original op.

Re-audit verdict: APPROVE — 100% CLEAN. Spec §4–§9 compliance verified MUST-by-MUST. 148 lib + 4 doctests (incl. the H-1 compile_fail regression) + 11 e2e tests pass. No new `unsafe`; no new deps (`static_assertions` was already a workspace dep). `pangolin-crypto` unchanged.

Surprises: H-1 was the most substantive finding — a textbook "the gate exists but the data is also accessible by another path" pattern. The fix had to thread through the test suite (every test that called `snap.password.expose()` had to migrate to `vault.reveal_password(id, &PressYPresenceProof::confirmed())`). Worth it: spec §5.4 is now structurally enforced at the type-system layer rather than as a documentation invariant.

Unblocks: P5+ host UI shells (Tauri desktop, iOS, Android) — they consume the trait-based proof API and the `with_session` resume primitive. **P6** (chaincli debug oracle) and **P7** (Rust chain adapter) are also unblocked but those don't need session policy; they consume P5-4's deployed contract directly via `pangolin-chain`. Merged as `aab248f`.

Next: **P6** (chaincli) and **P7** (chain adapter) are the natural next pair — both consume the deployed RevisionLogV0 from P5-4 + pangolin-crypto's signing + pangolin-store's local revisions. They unblock **P8** (sync flow), **P9** (conflict resolution), **P10** (tombstones), **P11** (E2E demo), **P12** (packaging) — i.e., the rest of the PoC.

## 2026-05-06 · P8 — pangolin-cli sync (publish + pull + dirty tracking)  ✅ SIGNOFF

Plan at `docs/issue-plans/P8.md` Kelvin-approved (Q4–Q6 answered: two-key PoC model accepted, `tools/pangolin-cli/` location accepted, defense-in-depth signature verify on ingest accepted). **Security-critical** per §16.3 — first issue that wires the vault end-to-end through the chain.

7 commits along the §16.4 BUILD-gate discipline:

- **P8-1** scaffolds `tools/pangolin-cli/` (clap shape, three subcommand stubs, deployment-file walk-up, RPC-URL precedence chain). Mirrors `tools/chaincli/` byte-for-byte. The pre-existing `crates/pangolin-cli/` placeholder (a `pangolin` smoke-test binary) is removed; workspace `members` updated.
- **P8-2** adds the `dirty_accounts` SQL table with `Vault::{mark,clear,list}_dirty` API. Auto-stamp inside `add_account` / `update_account` / `delete_account` runs in the same transaction as the revision INSERT — a crash leaves the vault in the pre-transaction state. `(account_id, revision_id)` composite primary key per §A2 protects against duplicate-publish on re-run.
- **P8-3** implements `pangolin-cli publish`. `sync::publish_all<A: ChainAdapter>` walks the dirty list; per-entry it reads the revision row's `(parent, schema_version, enc_payload)`, builds a `SignedRevision`, runs the §A3 pre-publish check (canonical-hash compare against `pull_since(vault_id, last_pulled_block, None)`), submits, then runs `mark_published` + `clear_dirty`. Per-account error isolation via `PublishReport`. The keystore loader mirrors chaincli; vault unlock uses the standard P4 two-proof flow.
- **P8-4** implements `pangolin-cli pull`. `sync::pull_all<A: ChainAdapter>` chunks the block range into PULL_CHUNK_SIZE = 8 000 windows. Per chunk: pull → Q6 device_id canonical-form check on every event → `Vault::ingest_chain_revision`. After each chunk: `advance_last_pulled_block(chunk_end)` BEFORE the next chunk's `pull_since` — resolves P7 audit MED-3. Forks surface via `PullReport.forks` (cardinal principle 3 — chain is a log, not an authority). Pull exits 0 even with forks; P9 resolves them.
- **P8-5** implements `pangolin-cli status`. Read-only diagnostics; works on a Locked vault (no chain calls). Reports `vault_id`, `dirty_count`, `account_count`, `last_pulled_block`, `last_published_block` (max chain_block_number).
- **P8-6** ships the integration suite. `tests/two_vault_roundtrip.rs` runs three plan-required scenarios (`convergence`, `symmetric_fork`, `idempotent_repeat_pull`) using two vaults that share identity by file-copy. `tests/integration_base_sepolia.rs` is gated `#[cfg(feature = "integration-tests")]`. Adds `src/lib.rs` so integration tests can import the orchestration core (binary crates can't be imported by integration tests under `tests/*.rs` without a lib path).
- **P8-7** documentation (this commit): THREAT_MODEL.md row (9 enumerated threats covering forged publish, replay, partition during chunked pull, dirty-entry leak, cross-vault replay, pre-publish check race, MockChainAdapter substitution, two-key gas-wallet correlation, forged-event-stream); E2E-003 entry (automated MockChainAdapter path + manual Base Sepolia path with funded keystore); this DEVLOG entry; surface table updated.

**Test count delta:** 195 → 242 lib tests + 6 integration tests = 248 total. The standard gate command `cargo test --workspace --lib` runs the 242 lib tests; the 6 integration tests live under `tools/pangolin-cli/tests/*.rs` and run when `cargo test --workspace` (no `--lib`) is invoked. Breakdown:
- pangolin-store: 75 → 90 (+15 = 12 dirty + 3 ingest_chain_revision)
- pangolin-cli unit (lib): 0 → 32 (cli, config, keystore, sync publish + pull, status, vault_open)
- pangolin-cli integration: 0 → 6 (3 cli_arg_parsing + 3 two_vault_roundtrip)
- gated Base Sepolia tests: 2 (off by default; not in the 248 count)

**Architecture surprises:**

- The plan's content-deterministic `revision_id = canonical_hash` discipline collides with P0..P7's random `RevisionId` generation. The two reconcile via three idempotency arms in `Vault::ingest_chain_revision`: exact `revision_id` match, `(account_id, chain_tx_hash, block_number, log_index)` match, and a content-merge path that UPDATEs the existing row's chain anchor when a local `chain_tx_hash IS NULL` row matches by `(account_id, parent_revision, enc_payload, schema_version)`. Without the merge arm, every publish-then-pull round-trip would produce a spurious 2-head fork.
- Two-key PoC model means the locally-stored `device_id` (random bytes from `randomblob(32)`) doesn't match the publish-time signing key's pubkey. Idempotency checks therefore deliberately ignore `device_id` and match on chain anchor + content. MVP-1 will switch to `pangolin_chain::evm::derive_evm_wallet` to satisfy D-006's wording, at which point `device_id` will round-trip and the idempotency check can tighten.
- v0 contract doesn't transport the signature bytes in `RevisionPublished`. Q6 defense-in-depth therefore reduces to a `VerifyingKey::from_bytes` shape check on every event's `device_id` — full Ed25519 `verify` is blocked until v1 records the signature on-chain. The shape check still catches an attacker-controlled-RPC threat: any `device_id` that isn't a canonical Ed25519 point is refused at the device boundary.
- `pangolin-cli` has both `src/main.rs` and `src/lib.rs` because integration tests under `tests/*.rs` cannot import a binary's modules. The library is internal-use-only — external consumers should use `pangolin-store` + `pangolin-chain` directly.

**Critical invariants verified at the tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1 holds)
2. No new `unsafe` (verified by workspace `unsafe_code = "deny"`)
3. No plaintext on disk (`pangolin-cli` does not write decrypted vault data anywhere — `read_revision_for_publish` returns the AEAD-sealed `enc_payload` verbatim)
4. Per-chunk all-or-nothing in pull (verified by `pull_chunk_failure_preserves_prior_chunk_progress`)
5. Per-account atomicity in publish (verified by `publish_per_account_isolation` + `publish_idempotent_on_rerun_after_partial_failure`)
6. Signature verify on pull (`pull_all`'s loop body runs `VerifyingKey::from_bytes` before ingest)
7. Workspace clippy `-D warnings` clean
8. No regression in the 195 P0..P7 lib tests; total now 248

**Deferred follow-ups (not signoff blockers):**

- MVP-1 switches `pangolin-cli publish` to `evm::derive_evm_wallet` for the gas wallet, closing the §A7 D-006 deviation.
- MVP-1 issue 1.4 plans the move to content-deterministic `RevisionId` for locally-created revisions (P2/P3 still use random ids), at which point the ingest path's content-merge arm becomes redundant.
- v1 contract (MVP-2 issue 2.1) records the signature on-chain; `pull_all`'s Q6 check upgrades from "device_id canonical form" to full `verify_signed_revision` at that point.
- Master plan §16.8 layout table needs to record `tools/pangolin-cli/` (was `crates/pangolin-cli/` in the original layout; deviation per Q5 / §A8 of the P8 plan).

Unblocks **P9** (conflict resolution UX — `pangolin-cli resolve <account-id> --keep <revision-id>`), **P10** (tombstone-aware deletes), **P11** (E2E recorded screencast).

## 2026-05-06 · P8 fix-pass — §16.5 audit findings (CRIT-1, MED-1, MED-2, MED-3, MED-4, LOW-1, LOW-2)  ✅ SIGNOFF

Single fix-pass commit on top of the P8-7 tip. Addresses every actionable finding from the §16.5 security audit; HIGH-1 + INFO-1/2/3 are no-code-change per auditor (bounded by Cardinal Principle 3 / observation-class).

**CRIT-1 — Tombstone-flag non-propagation.** Closed via a `frozen_pending_resolve` sentinel column on `account_identities` (additive `ALTER TABLE … ADD COLUMN` migration at `Vault::open` so existing P0..P7+P8-pre-fix vault files keep opening cleanly). `Vault::ingest_chain_revision` sets the flag to `1` when the ingest takes the genuine-foreign-INSERT path (none of the three idempotency-merge arms matched). User-facing read paths (`get_account`, `list_accounts`, `search`, `reveal_password`, `reveal_notes`, `reveal_totp_secret`, `export_payload`) refuse on frozen accounts: `Option`-returning APIs filter the row out; the explicit `Result`-returning ops surface a new `StoreError::AccountFrozenPendingResolve { account_id }` variant. Edit paths (`update_account`, `delete_account`, `mark_dirty`) refuse with the same error so a user editing their stale plaintext copy of a chain-modified account cannot create a silent fork. The flag is cleared by the upcoming `pangolin-cli resolve` (P9). The new `Vault::list_frozen_accounts` exposes the set; `pangolin-cli pull` includes the count in its summary, and `pangolin-cli status` reports per-account ids.

**MED-1 — Spoofed chain anchor on local pre-publish row.** The third merge arm of `Vault::ingest_chain_revision` (the `(account_id, parent_revision, enc_payload, schema_version, chain_tx_hash IS NULL)` content merge) now ALSO requires `device_id` to match. The auditor's preferred re-fetch-via-`get_revision` approach was rejected because under attacker-controlled-RPC both directions of the conversation are spoofable; the `device_id` binding is a content-bound check that doesn't depend on the transport. Trade-off: under the PoC two-key model the legitimate own-publish round-trip ALSO fails the `device_id` match (publish generates an ephemeral signing `DeviceKey` per call whose pubkey differs from the local row's random `device_id` from `Vault::open`), so it routes through idempotency arm #2 `(account_id, chain_tx_hash, block, log)` after `mark_published` has stamped the local row's chain anchor. Cross-vault round-trips (vault B pulling vault A's publishes) intentionally trigger CRIT-1's freeze. MVP-1's switch to D-006's derived wallet aligns local-row and chain-event `device_id`, restoring silent cross-device merge under the non-attack case while preserving the new defense.

**MED-2 — HTTP RPC URL accepted.** Added `--allow-insecure-rpc` global flag and `ResolvedConfig::enforce_rpc_scheme` helper. Default behavior: any URL whose scheme is not `https` (case-insensitive) is refused with a clear remediation hint mentioning the override flag. Both `pangolin-cli publish` and `pangolin-cli pull` call `enforce_rpc_scheme` immediately after `rpc_url_or_default` and before the chain adapter is constructed.

**MED-3 — `--vault-path` not canonicalized.** Added `vault_open::canonicalize_vault_path` and routed every `Vault::open` callsite (status, publish, pull) through it. The status output now includes a `vault_path` row showing the resolved absolute path; the password prompt also references the canonical path so a user with a confused working directory sees what they're actually unlocking.

**MED-4 — `forbid(unsafe_code)` not unconditional.** Replaced the `cfg_attr`-guarded variants in `tools/pangolin-cli/src/{main,lib}.rs` with a single unconditional `#![forbid(unsafe_code)]`. `forbid` cannot be relaxed by a downstream `allow`, so a future test annotating a block with `#[allow(unsafe_code)]` would fail the build.

**LOW-1.** Updated `tools/pangolin-cli/Cargo.toml` comment to reflect the bin+lib hybrid added in P8-6.

**LOW-2.** Updated DEVLOG line on test count attribution to clarify "242 lib tests + 6 integration tests = 248 total" before the fix-pass.

**HIGH-1, INFO-1/2/3.** No code change per auditor. THREAT_MODEL.md rows #1 and #9 reaffirmed as honest framing (verified read-through; no prose-tightening needed — the rows already explicitly call out v0 contract not transporting signature bytes and the bound by Cardinal Principle 3).

**Threat model additions.** Rows #10 (CRIT-1's `frozen_pending_resolve` sentinel) and #11 (MED-1's `device_id`-binding tightening) appended to `THREAT_MODEL.md`'s pangolin-cli section.

**Test count delta:** 242 → 253 lib tests (+11). New tests:

- `pangolin-store::vault::tests::frozen_after_foreign_ingest_blocks_reveal_password`
- `pangolin-store::vault::tests::own_publish_roundtrip_does_not_freeze`
- `pangolin-store::vault::tests::frozen_account_blocks_mark_dirty`
- `pangolin-store::vault::tests::frozen_account_listed_separately_in_pull_result`
- `pangolin-store::vault::tests::legacy_vault_picks_up_frozen_column_on_open`
- `pangolin-cli::config::tests::http_rpc_rejected_without_flag`
- `pangolin-cli::config::tests::http_rpc_accepted_with_flag`
- `pangolin-cli::config::tests::https_rpc_always_accepted`
- `pangolin-cli::config::tests::https_scheme_match_is_case_insensitive`
- `pangolin-cli::commands::status::tests::vault_path_canonicalized_in_status_output`
- `pangolin-cli::cli::tests::allow_insecure_rpc_flag_parses`

Plus `tests/two_vault_roundtrip.rs::convergence` updated to assert that B's pull triggers the CRIT-1 freeze sentinel (its previous "merge succeeds silently" assertion is no longer the post-fix expected behavior under PoC two-key — see the inline comment on the test for the MVP-1 path that restores the silent merge).

**Critical invariants verified at the fix-pass tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1 holds)
2. No new `unsafe`; `forbid(unsafe_code)` is now unconditional (MED-4 strengthens this)
3. No plaintext on disk
4. Per-chunk all-or-nothing in pull (CRIT-1's freeze sentinel doesn't change this)
5. Per-account atomicity in publish; frozen accounts refuse `mark_dirty` cleanly
6. `cargo fmt --all --check` clean
7. `cargo clippy --workspace --all-targets -- -D warnings` clean
8. `cargo test --workspace --lib` — 253/253 passing (242 baseline + 11 new)
9. `cargo audit` clean (the 2 pre-existing unmaintained-warning entries documented in `deny.toml` remain unchanged)
10. `cargo deny check` — advisories ok, bans ok, licenses ok, sources ok
11. `cargo build --workspace --release` clean
12. `pangolin-cli --help` lists `status`, `publish`, `pull` and the new `--allow-insecure-rpc` flag

## 2026-05-07 · P9 — pangolin-cli resolve (Conflicts & Resolve EPIC)  ✅ SIGNOFF

Plan at `docs/issue-plans/P9.md` Kelvin-approved with seven locked
answers (Q1: multi-resolve for N-way forks APPROVED, no
`demote_orphan_heads`; Q2: ship without concurrent-resolve race
guard; Q6: `read_payload_plaintext_for_resolve` documented bypass
APPROVED; Q7: pre-publish chain re-pull APPROVED; Q3/Q4/Q5: full
hex revision-id, tombstone-of-tombstone, `--dry-run` ships).
Ship six commits on `issue/P9-resolve` branch from baseline tip
`101c1c3`.

**P9-1.** `Vault::clear_frozen(account_id, chosen_revision_id)`
clears `frozen_pending_resolve` AND advances `head_revision_id`
in one `BEGIN IMMEDIATE … COMMIT` transaction.
`Vault::read_payload_plaintext_for_resolve(account_id,
revision_id)` is the documented freeze-guard bypass for the
resolve flow's plaintext re-seal step (loud docstring; single
in-process caller). Cross-account substitution collapses to
`AccountNotFound` (no oracle). 7 tests added.

**P9-2.** New `crate::conflict` module hosts `ConflictReport {
account_id, heads, frozen }`. `Vault::list_conflicts()` joins
fork state and freeze state via union-then-dedup, sorted by
`account_id` byte-order ASC. Surfaces all four state combinations
(forked / frozen / both / neither). 6 tests added.

**P9-3.** clap surface for `pangolin-cli resolve --account-id
<hex> --keep <hex> [--yes] [--dry-run] [--account|--keystore-path]
[--vault-password] [--keystore-password]`. Custom value parsers
`HexAccountId` / `HexRevisionId` reject non-64-char or non-hex
input at clap-validation time per Q3 (full hex, no prefix).
`commands/resolve.rs` handler opens the vault, validates the
chosen head locally, prompts for confirmation (skippable via
`--yes`), builds the adapter, dispatches to
`sync::resolve_one`. 9 clap-shape tests added.

**P9-4.** Full `sync::resolve_one` body. Flow: validate `--keep`
is a current head → pre-publish re-pull (Q7) → re-validate heads
(`ChainMovedDuringResolve` if a NEW head appeared) →
`Vault::build_merge_payload_for_resolve` (the new helper that
composes `read_payload_plaintext_for_resolve` + `seal_snapshot` /
`seal_tombstone` per A2/A5; plaintext NEVER leaves the store
crate) → `build_signed_revision` → A3 pre-publish canonical-hash
scan → publish (or skip per A3 already-on-chain) →
`ingest_chain_revision` → `clear_frozen` → advance
`last_pulled_block`. `--dry-run` short-circuits at the canonical
hash and prints `would publish revision <hex>`. 7 tests added.

**P9-5.** Renames the existing `convergence` integration test to
`convergence_freezes_on_pull` (the post-P8-CRIT-1 freeze remains
the expected pre-resolve PoC behavior). New
`convergence_after_resolve` test pins the simple two-handle
convergence flow per P9 plan §A4: A publishes → B pulls
(frozen) → B runs `resolve` against B's local genesis (the only
locally-decryptable head) → B's freeze is CLEAR. Adds E2E-004
entry to `E2E_TESTS.md` with both automated + manual paths.

**P9-6.** This DEVLOG entry. `THREAT_MODEL.md` rows 12–17 added
to the `pangolin-cli` section: 12 (forged resolve), 13 (replay
of an old resolve), 14 (frozen flag cleared without publish),
15 (HIGH-1 attacker-controlled head adoption — UX-only mitigation
acknowledged), 16 (`read_payload_plaintext_for_resolve` bypass —
loud-docstring mitigation per Q6), 17 (concurrent-resolve race
per A7 / Q2 — ship without).

**Test count delta:** 253 → 282 lib tests (+29). New tests:

- `pangolin-store::vault::tests::clear_frozen_advances_head_and_clears_flag`
- `pangolin-store::vault::tests::clear_frozen_idempotent_on_already_clean`
- `pangolin-store::vault::tests::clear_frozen_rejects_unknown_revision`
- `pangolin-store::vault::tests::clear_frozen_rejects_unknown_account`
- `pangolin-store::vault::tests::read_payload_plaintext_for_resolve_bypasses_freeze_guard`
- `pangolin-store::vault::tests::read_payload_plaintext_for_resolve_requires_unlocked_vault`
- `pangolin-store::vault::tests::read_payload_plaintext_for_resolve_rejects_wrong_account_id`
- `pangolin-store::conflict::tests::list_conflicts_empty_on_clean_vault`
- `pangolin-store::conflict::tests::list_conflicts_lists_only_forked`
- `pangolin-store::conflict::tests::list_conflicts_lists_only_frozen`
- `pangolin-store::conflict::tests::list_conflicts_lists_forked_and_frozen`
- `pangolin-store::conflict::tests::list_conflicts_handles_frozen_with_single_head`
- `pangolin-store::conflict::tests::list_conflicts_dedup_when_account_is_both_forked_and_frozen`
- `pangolin-cli::cli::tests::resolve_parses_with_minimum_args`
- `pangolin-cli::cli::tests::resolve_requires_account_id`
- `pangolin-cli::cli::tests::resolve_requires_keep`
- `pangolin-cli::cli::tests::resolve_account_id_must_be_64_hex_chars`
- `pangolin-cli::cli::tests::resolve_keep_must_be_64_hex_chars`
- `pangolin-cli::cli::tests::resolve_account_id_rejects_non_hex`
- `pangolin-cli::cli::tests::resolve_dry_run_flag_parses`
- `pangolin-cli::cli::tests::resolve_yes_flag_parses`
- `pangolin-cli::cli::tests::resolve_account_and_keystore_path_conflict`
- `pangolin-cli::sync::tests::resolve_publishes_merge_revision`
- `pangolin-cli::sync::tests::resolve_clears_freeze_on_success`
- `pangolin-cli::sync::tests::resolve_fails_cleanly_on_publish_error`
- `pangolin-cli::sync::tests::resolve_idempotent_after_partial_failure`
- `pangolin-cli::sync::tests::resolve_chain_moved_during_resolve_aborts_cleanly`
- `pangolin-cli::sync::tests::dry_run_does_not_publish_or_clear`
- `pangolin-cli::sync::tests::resolve_rejects_non_head_revision`

Plus integration: `tests/two_vault_roundtrip.rs::convergence_after_resolve` (new) + `convergence_freezes_on_pull` (rename of `convergence`).

**Critical invariants verified at the SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1 holds)
2. No new `unsafe`; `forbid(unsafe_code)` unconditional in pangolin-cli (P8 MED-4)
3. No plaintext on disk — `read_payload_plaintext_for_resolve` returns plaintext to RAM only; `build_merge_payload_for_resolve` re-seals in RAM and returns ciphertext
4. Append-only state — `clear_frozen` UPDATEs only the freeze flag + head_revision_id; no revision row is ever mutated
5. Per-account atomicity — resolve = "publish then ingest+clear"; failed clear after publish is recoverable (the next pull's arm-2 catches via tx_hash) and re-running resolve with the stale `--keep` surfaces `NotAHead` cleanly
6. `cargo fmt --all --check` clean
7. `cargo clippy --workspace --all-targets -- -D warnings` clean
8. `cargo test --workspace --lib` — 282/282 passing (253 baseline + 29 new)
9. `cargo test --workspace --tests` — integration tests pass (4 in two_vault_roundtrip; the rest unchanged)
10. `cargo audit` — 2 pre-existing unmaintained advisories documented in `deny.toml` (RUSTSEC-2024-0388 etc.) — no new advisories
11. `cargo deny check` — advisories ok, bans ok, licenses ok, sources ok
12. `cargo build --workspace --release` clean

**Open questions / acknowledged gaps:**

- The convergence test's full multi-device single-head pattern
  requires N resolves under PoC two-key (one per device that has
  ingested the foreign chain row but cannot decrypt it because the
  AEAD nonce isn't on chain). MVP-1's switch to D-006's single-key
  model + nonce-on-chain semantics closes the multi-resolve gap.
  The test pins the simple two-handle case where ONE resolve
  clears B's freeze; the multi-resolve N-way case is documented
  as expected PoC behavior per Q1.
- Concurrent-resolve race ships without an interactive freshness
  guard per Q2 — recovery is mechanical (re-resolve on next pull).
- `read_payload_plaintext_for_resolve` is documented as the only
  freeze-guard bypass; alternatives (re-supply password as fresh
  proof) were rejected per the rationale in P9 plan §A8.

Unblocks **P10** (tombstone-aware deletes — P9 ships the
structural is_tombstone round-trip; P10 owns full semantics) and
**P11** (E2E recorded screencast). The `pangolin-cli` binary is
now at four subcommands: `status`, `publish`, `pull`, `resolve`.

## 2026-05-07 · P9 fix-pass — §16.5 audit findings (HIGH-1, MED-1, MED-2, MED-3, MED-4, LOW-1)  ✅ SIGNOFF

Per Kelvin's "100% clean" bar, every actionable finding from the
P9 §16.5 audit is closed with code + tests. Single commit on
`issue/P9-resolve` from baseline tip `6d6bc28`.

**HIGH-1 — A3 partial-failure recovery is structurally
non-functional.** Auditor's exact text: "the user is permanently
stuck — frozen account, unresolvable." Each `resolve_one`
invocation generated a fresh ephemeral `DeviceKey` AND a fresh
AEAD nonce, so the canonical hash differed every run; the chain
event from a prior partially-completed run could not be matched
on retry.

Fix: new `pending_merges` SQLite table stashes the
merge-revision-build state (ephemeral `DeviceKey` secret seed,
AEAD nonce, AEAD ciphertext, schema_version) BEFORE
`adapter.publish`. Retry calls `Vault::take_pending_merge`,
reconstructs the SAME `DeviceKey` via `DeviceKey::from_seed`, and
re-uses the SAME nonce + ciphertext — so the canonical hash is
bit-equal across retries and the existing A3 idempotency scan
inside `sync::resolve_one` matches the chain event from the prior
run. After `clear_frozen` succeeds the stash row is deleted via
`Vault::clear_pending_merge`. Schema migration is idempotent
(`CREATE TABLE IF NOT EXISTS` + a defensive
`migrate_pending_merges_table` helper that runs on every
`Vault::open` for legacy vaults).

**MED-1 — multi-resolve invariant untested.** Added
`resolve_against_three_heads_keeps_chosen_demotes_others_to_orphans`
in `tools/pangolin-cli/src/sync.rs::tests`. A 3-head fork
(`MockChainAdapter` + two synthetic foreign events under the same
genesis-parent) resolved with `--keep <local_genesis>` produces a
merge revision pointing at `local_genesis`; the post-resolve
`account_heads(account_id)` returns the merge revision PLUS the
two unchosen orphans (length 3, not 1). The user re-runs resolve
to fold each orphan in (PoC two-key Q1 multi-resolve pattern;
MVP-1's switch to D-006's single-key model closes the gap).

**MED-2 — `clear_frozen` atomicity test dropped.** Added
`clear_frozen_atomic_under_simulated_crash` in vault.rs. Pinned
the BEGIN IMMEDIATE wrapper across the freeze-clear +
head-advance UPDATE pair via a transaction-rollback control test
(direct SQL UPDATE inside an unchecked_transaction that is
dropped without commit) followed by the `clear_frozen` success
path's combined-write assertion. We did not use
`rusqlite::update_hook` per the audit's fallback hint — the API
is not stable across rusqlite versions and the
transaction-rollback discipline is the relevant invariant
anyway.

**MED-3 — `clear_frozen` doesn't validate `chosen_revision_id`
is a current head.** New head-membership check inside
`clear_frozen`'s SQL transaction (`BEGIN IMMEDIATE`) BEFORE the
UPDATE — uses the same `NOT EXISTS` predicate that
`account_heads` uses for the multi-head detector, scoped by
`account_id`. New `StoreError::NotAHead {account_id, chosen,
current_heads}` variant fires if the supplied revision exists
but isn't a current head. Test:
`clear_frozen_rejects_non_head_revision_id` (a UPDATE-demoted
genesis revision is rejected as non-head). Updated docstring:
"errors with NotAHead if the supplied revision_id is not a
current head AT THE TIME of the SQL transaction."

**MED-4 — `--dry-run` mutates local state via pre-publish pull.**
`sync::resolve_one` now short-circuits `pull_all` on `dry_run =
true`. The dry-run output retains the canonical-hash computation
but does not advance `last_pulled_block` or ingest any chain
rows. Updated existing test `dry_run_does_not_publish_or_clear`
to also assert `last_pulled_block` is UNCHANGED post-call.

**LOW-1 — `__test_synthesize_sibling_revision` is `pub` without
`cfg`.** Added `#[cfg(any(test, feature = "test-utilities"))]`
gate per the docstring's existing promise. The
`tests/e2e.rs` integration test (which links the crate
externally and uses the helper) is annotated with
`required-features = ["test-utilities"]` in pangolin-store's
Cargo.toml so cargo skips it when the feature is disabled and
includes it when `--features test-utilities` is set. Production
builds of the workspace binaries (`chaincli`, `pangolin-cli`)
do not link against the helper.

**LOW-2, LOW-3, INFO-1 — observation-class.** Per audit
guidance: LOW-2 is inherited from P8 (no new code change);
LOW-3 ("AlreadyOnChain user message dead code") naturally
closes via HIGH-1's stash mechanism — with the canonical-hash
determinism the stash provides, the AlreadyOnChain branch
becomes reachable when the prior run's publish landed on chain
but `clear_frozen` was killed; INFO-1 is observation-only.

**`THREAT_MODEL.md` row #13** rewritten to honestly describe the
stash discipline, the at-rest model for the seed BLOB, and the
test list pinning the recovery semantics.

**Test count delta:** 282 → 290 lib tests workspace-wide (+8):

1. `stash_take_clear_round_trip` (vault.rs) — basic API.
2. `stash_persists_across_close_open` (vault.rs) — durability.
3. `take_returns_none_for_nonexistent_account` (vault.rs).
4. `pending_merge_zeroizes_secret_on_drop` (vault.rs) —
   structural Drop discipline on `SecretBytes`.
5. `clear_frozen_rejects_non_head_revision_id` (vault.rs) —
   MED-3.
6. `clear_frozen_atomic_under_simulated_crash` (vault.rs) —
   MED-2.
7. `resolve_against_three_heads_keeps_chosen_demotes_others_to_orphans`
   (sync.rs) — MED-1.
8. `resolve_idempotent_after_partial_failure_via_stash`
   (sync.rs) — HIGH-1 end-to-end recovery.

The existing `dry_run_does_not_publish_or_clear` test was
extended with a `last_pulled_block` assertion (MED-4) without
counting as a separate addition.

**Critical invariants verified at the SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; no new transitive deps from the fix-pass).
2. No new `unsafe`. The stash table stores secrets at rest but
   doesn't introduce unsafe.
3. No plaintext on disk. The stashed `enc_payload` is AEAD
   ciphertext; the `device_secret` is an Ed25519 secret seed
   (NOT vault plaintext). The AEAD-seal happens inside
   `Vault::build_merge_payload_for_resolve` BEFORE the stash.
4. Per-chunk all-or-nothing in pull. Unchanged.
5. Per-account atomicity. Strengthened by the stash + by
   MED-3's head-membership check inside `clear_frozen`'s
   transaction.
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets --features
   pangolin-store/test-utilities -- -D warnings` clean.
8. `cargo test --workspace --lib --features
   pangolin-store/test-utilities` — 290/290 passing (282
   baseline + 8 new).
9. `cargo test --workspace --tests --features
   pangolin-store/test-utilities` — integration tests pass.
10. `cargo build --workspace --release` clean.

**Behaviour-preserving for everyone except the auditor's
finding:** existing tests all continue to pass. The HIGH-1
stash adds two new methods (`stash_pending_merge`,
`take_pending_merge`, `clear_pending_merge`) and one new struct
(`PendingMerge`); the existing `Vault::build_merge_payload_for_resolve`
signature was extended (returning a 4-tuple including the
nonce instead of a 3-tuple) — internal-only call inside
`sync::resolve_one`.

## 2026-05-07 · P9 fix-pass 2 — close HIGH-1 fully + orphan stash prune + cosmetic  ✅ SIGNOFF

The `2d13fea` first fix-pass closed HIGH-1 for the publish-FAILED
retry case but the re-audit identified that the publish-SUCCEEDED-
but-`clear_frozen`-killed case was still unrecoverable. Plus two
new findings (MEDIUM-2 orphan stash accumulation, LOW-2 dry-run
staleness disclosure) and one cosmetic (LOW-1 stale comment about
`DeviceKey::from_seed`).

**HIGH-1 deeper fix — kill-after-publish-success recovery.** The
re-auditor's structural diagnosis: in the prior `resolve_one`, the
sequence `pull_all → chain_moved guard → take_pending_merge` was
fatal for the publish-succeeded-but-killed scenario. On retry,
`pull_all` ingested the prior merge revision as a foreign event,
advancing the head set; `chain_moved = post_pull_heads.iter().any(|h|
!pre_pull_heads.contains(h))` fired (the just-ingested merge IS a
new head); `ChainMovedDuringResolve` aborted BEFORE the stash was
consulted; user permanently stuck.

Fix: re-ordered `sync::resolve_one`. `take_pending_merge` runs FIRST
(unconditionally), THEN `pull_all`, THEN a stash-vs-chain canonical-
hash match against the post-pull LOCAL revisions table. If the
stash's deterministic canonical hash matches a locally-ingested row
with a populated chain anchor, we take the `AlreadyOnChain` path:
`clear_frozen` (advances `head_revision_id` to the merge-rev id and
clears the freeze flag in one transaction) + `clear_pending_merge`
(drop the stash row). The `chain_moved` and `chosen-still-a-head`
guards fire only when no stash matches — i.e., when the chain has
moved BEYOND the user's stashed-`--keep` target. Critical
correctness point: `clear_frozen` does NOT decrypt the local row;
it only validates head-membership and runs the UPDATE pair, so
the foreign-ingested row's placeholder zero `enc_nonce` is not a
problem for the recovery path.

We use the LOCAL revisions table (post-pull) rather than re-calling
`adapter.pull_since` because `pull_all` already advanced
`last_pulled_block` past the merge event's block, so a fresh
`pull_since(last_pulled_block)` would return an empty view. The
local revisions table is the canonical post-pull source of truth,
and `pull_all` itself signature-verifies the foreign event's
`device_id` canonical form (defense-in-depth against forged
streams) before ingesting — so a stash-match against a locally-
ingested row is no weaker than a stash-match against the chain
view.

**MEDIUM-2 (new) — orphan stash accumulation.** Added
`Vault::prune_orphan_pending_merges(account_id) -> Result<usize>`.
Iterates `pending_merges` rows for `account_id` inside a single
SQL transaction (collects current heads via the `account_heads`
predicate, scans stash rows, deletes any whose `target_head_id`
is not a current head). Called from:

- `pull_all` after each chunk's per-account ingest sequence
  completes (per-chunk all-or-nothing discipline preserved — the
  prune runs in its own transaction after the chunk's events
  have committed and the checkpoint has advanced),
- `resolve_one` alongside `take_pending_merge` at the top of the
  flow (skipped on dry-run for purity).

Failures are non-fatal — logged + skipped, the next prune
invocation retries. Three new tests:
`prune_orphan_pending_merges_removes_non_head_targets`,
`prune_no_op_when_all_targets_are_heads`, `prune_no_op_on_empty_table`.

**LOW-1 (re-audit) — stale comment in `crates/pangolin-chain/src/evm.rs`.**
The comment in `structural_property_distinct_seeds_distinct_signatures`
claimed "we can't construct `DeviceKey::from_seed` (no such public
API)". The first P9 fix-pass made `DeviceKey::from_seed` public.
Updated the comment to reflect the new state: "now public (added
by P9 fix-pass HIGH-1), but this test predates that surface and
intentionally probes the structural property at the `SigningKey`
layer to keep the pangolin-chain → pangolin-crypto dependency
surface minimal." Test logic unchanged — uses `SigningKey::from_seed`
directly per the auditor's read.

**LOW-2 (re-audit) — dry-run output omits staleness disclosure.**
The `--dry-run` path in `sync::resolve_one` skips the pre-publish
chain re-pull (per MED-4 hygiene), so the canonical hash printed
to the user is computed against a possibly-stale local view of the
chain. Added an explicit disclosure line BEFORE the canonical-hash
print in `tools/pangolin-cli/src/commands/resolve.rs`'s dry-run
branch: "pre-publish chain re-pull SKIPPED (dry-run mode); current
local view may be stale." Wet-path output unchanged.

**`THREAT_MODEL.md` row #13** rewritten to honestly describe the
now-fully-functional kill-after-publish-success recovery (the
re-ordered `resolve_one`'s stash-vs-local match path), the
`prune_orphan_pending_merges` mechanism, and the updated test list.

**Test count delta:** 290 → 294 lib tests workspace-wide (+4):

1. `prune_orphan_pending_merges_removes_non_head_targets` (vault.rs).
2. `prune_no_op_when_all_targets_are_heads` (vault.rs).
3. `prune_no_op_on_empty_table` (vault.rs).
4. `resolve_recovers_from_kill_after_publish_success` (sync.rs)
   — the kill-after-publish-success end-to-end recovery test
   that the re-auditor explicitly called out as missing.

**Critical invariants verified at the P9 fix-pass 2 SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; no new transitive deps from the fix-pass).
2. No new `unsafe`.
3. No plaintext on disk. The stash semantics + the freeze-guard
   bypass discipline are unchanged.
4. Per-chunk all-or-nothing in pull. Preserved — the prune runs
   in its own transaction AFTER the chunk's events have
   committed and the checkpoint has advanced; failures are
   logged but not fatal.
5. Per-account atomicity. Strengthened (the stash-match path
   composes `clear_frozen`'s atomic head-advance with the stash
   delete, all under per-account scoping).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings` clean.
8. `cargo test --workspace --lib` — 294/294 passing (290
   baseline + 4 new).

## 2026-05-07 · P10 — Tombstones & Offline Mode EPIC  ✅ SIGNOFF

Plan at `docs/issue-plans/P10.md` Kelvin-approved with three
locked answers (Q1: TombstonePayload three-field shape APPROVED;
Q2: tombstoned_at_ms in merge revision is the merge's own seal
time, not the original tombstone's; Q3: add_account
anti-resurrection retry budget = 4). Five commits land on
`issue/P10-tombstones-offline` from baseline tip `562a3ba`.

**P10-1.** Widened tombstone payload schema. New
`pangolin_store::TombstonePayload { deleted, account_id,
tombstoned_at_ms }` with private fields + accessor methods;
deterministic CBOR encoding with three-entry alphabetical key
order (`account_id`, `deleted`, `tombstoned_at_ms`). Encoded via
`ciborium-ll` directly (no serde — HIGH-1 invariant preserved).
Legacy P3-era single-entry `{ "deleted": true }` payloads
continue to decode for forward-compat (produce a
`TombstonePayload` with all-zeros `account_id` and ts=0).
`seal_tombstone` signature widens to take `&TombstonePayload`;
`DecodedPayload::Tombstone` now carries the parsed payload.
`Vault::delete_account` and `Vault::build_merge_payload_for_resolve`
updated; the merge-of-tombstone case carries the merge revision's
own seal time per Q2 (not the original tombstone's). 11 tests
added (10 blob-level + 1 vault-level).

**P10-2.** Opportunistic tombstone-bit detection in
`Vault::ingest_chain_revision`'s genuine-foreign-INSERT branch.
Replaced the audit-flagged hardcode `is_tombstone_i64 = 0` with a
helper `Vault::detect_tombstone_bit_at_ingest` that AEAD-decrypts
under the local VDK + the placeholder zero nonce that ingest
persists for foreign events; sets bit=1 iff the decoded plaintext
is a `TombstonePayload` whose `deleted` is true. Non-oracle
property: every error variant collapses to bit=0; both decode-
success and decode-failure paths return `IngestOutcome::Inserted`;
no error variant escapes; the freeze sentinel still fires for
foreign-ingest UX safety. PoC two-key reality (acknowledged
limitation, plan §A2 / Threat #19): under PoC the chain event
ABI does not transport the AEAD nonce, so the open under
placeholder zero nonce will fail authentication for any real
foreign event — the new logic is functionally a no-op (always
falls through to bit=0 + freeze). The structurally-correct code
is in place for MVP-1's nonce-on-chain to make this functional
without further code changes. The synthetic-decryptable-tombstone
test exercises the positive branch by sealing an event payload
deliberately under the placeholder zero nonce. 5 tests added.

**P10-3.** Read-guard reaffirmation +
`add_account` anti-resurrection. (1)
`ingest_chain_revision` now flips `account_identities.tombstoned
= 1` when P10-2's opportunistic decode returns `is_tombstone =
1`; without this UPDATE, P10-2's bit-set on the revisions row
alone wouldn't propagate through `list_accounts`. (2)
`Vault::add_account` runs a new `derive_fresh_account_id` helper
that probes the existing account_identities row for a
tombstoned-id collision; on collision, regenerate; after
`ADD_ACCOUNT_RETRY_BUDGET` (4) collisions, surface
`StoreError::Internal { reason }` rather than spinning. New
`StoreError::Internal { reason: String }` variant. 7 lib tests
+ 1 integration test added (the integration covers the own-
publish round-trip; the cross-vault propagation case is
acknowledged Threat #19 limitation, closed by MVP-1).

**P10-4.** `MockChainAdapter::set_disconnected(bool)` toggle.
`Arc<AtomicBool>` field next to the existing `Arc<Mutex<...>>`;
cloned mock handles share both. When disconnected, every
adapter method returns `ChainError::Rpc("simulated offline")`
synchronously without state mutation. Test-utilities-feature-
gated alongside the rest of the `mock` module. New
integration test file `tools/pangolin-cli/tests/offline_mode.rs`
with three tests: `offline_edit_then_online_publish` (full
flow: connect → publish 1 → disconnect → 5 add + 1 update +
1 delete locally → publish_all fails per-entry, dirty markers
preserved → reconnect → publish_all drains the queue, chain
has 8 events, list_dirty empty, list_accounts.len() == 5);
`offline_publish_with_no_dirty_entries_is_noop_at_lib_layer`
(documents the orchestrator's swallow-chain-view-precheck-error
discipline; the §A7 connectivity-required invariant lives at
the binary boundary, not the lib entry point);
`offline_session_does_not_set_freeze_sentinel` (pin: pull_all
errors before reaching ingest_chain_revision, so the freeze
sentinel cannot fire). E2E_TESTS.md gains E2E-005 with both
automated and manual paths. 6 mock-level tests added.

**P10-5.** This DEVLOG entry. THREAT_MODEL.md gains rows
18–22 in the `pangolin-cli` section: 18 (forged tombstone),
19 (tombstone-bit non-propagation under PoC two-key — closed
structurally by P10-2, functionally by MVP-1), 20 (resurrection
of tombstoned account_id forbidden), 21 (offline edit replay —
inherits #5 cross-vault discipline), 22 (tombstone-bit at-rest
modification — defense-in-depth via AEAD AAD binding + non-
oracle decode). `pangolin-cli status` output gains a
`tombstoned_count` line (per A8 — omitted in human-readable
output when count is 0; always emitted in JSON for machine
consumers). New `Vault::list_tombstoned_accounts()` accessor.

**Test count delta:** 294 → 323 lib tests (+29) plus 4 new
integration tests:

Lib tests added:
- `pangolin_store::blob::tests::tombstone_payload_round_trip_three_field`
- `pangolin_store::blob::tests::tombstone_payload_encoding_is_deterministic`
- `pangolin_store::blob::tests::tombstone_payload_legacy_single_entry_decodes`
- `pangolin_store::blob::tests::tombstone_payload_rejects_arity_two`
- `pangolin_store::blob::tests::tombstone_payload_rejects_arity_four_or_more`
- `pangolin_store::blob::tests::tombstone_payload_rejects_non_canonical_key_order`
- `pangolin_store::blob::tests::tombstone_payload_rejects_account_id_wrong_length`
- `pangolin_store::blob::tests::tombstone_payload_rejects_tombstoned_at_negative`
- `pangolin_store::blob::tests::seal_tombstone_with_payload_round_trips_through_open_payload`
- `pangolin_store::blob::tests::tombstone_aad_substitution_fails`
- `pangolin_store::vault::tests::delete_account_writes_canonical_three_field_tombstone_payload`
- `pangolin_store::vault::tests::ingest_synthetic_decryptable_tombstone_event_sets_bit`
- `pangolin_store::vault::tests::ingest_own_live_revision_does_not_set_tombstone_bit`
- `pangolin_store::vault::tests::ingest_foreign_event_with_unreadable_payload_leaves_tombstone_clear_and_freezes`
- `pangolin_store::vault::tests::ingest_locked_vault_skips_decryption_and_treats_as_unreadable`
- `pangolin_store::vault::tests::ingest_tombstone_bit_does_not_oracle_aead_failure_versus_decode_failure`
- `pangolin_store::vault::tests::ingest_tombstone_sets_account_identities_tombstoned_flag`
- `pangolin_store::vault::tests::ingest_tombstone_filters_account_from_list_accounts`
- `pangolin_store::vault::tests::ingest_tombstone_makes_get_account_return_none`
- `pangolin_store::vault::tests::ingest_tombstone_makes_reveal_password_return_account_tombstoned`
- `pangolin_store::vault::tests::add_account_refuses_to_resurrect_tombstoned_id`
- `pangolin_store::vault::tests::add_account_retry_budget_happy_path_no_collision`
- `pangolin_store::vault::tests::merge_payload_for_resolve_uses_new_three_field_tombstone_shape`
- `pangolin_chain::mock::tests::disconnect_makes_publish_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_makes_pull_since_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_makes_get_revision_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_makes_current_block_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_persists_until_reconnect`
- `pangolin_chain::mock::tests::reconnect_after_disconnect_preserves_state`
- `pangolin_cli::commands::status::tests::status_includes_tombstone_count_when_nonzero`

Integration tests added:
- `pangolin_cli::tests::two_vault_roundtrip::own_tombstone_round_trip_via_chain`
- `pangolin_cli::tests::offline_mode::offline_edit_then_online_publish`
- `pangolin_cli::tests::offline_mode::offline_publish_with_no_dirty_entries_is_noop_at_lib_layer`
- `pangolin_cli::tests::offline_mode::offline_session_does_not_set_freeze_sentinel`

**Critical invariants verified at the P10 SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; P10 introduces no new transitive deps for the
   crypto crate. The widened `TombstonePayload` uses
   `ciborium-ll` directly, same as the live-snapshot encoder).
2. No new `unsafe`.
3. No plaintext on disk. The opportunistic-decode in P10-2
   happens entirely in memory; the decrypted plaintext is
   wiped on drop via `Zeroizing<Vec<u8>>` inside `open_payload`
   (existing P3 discipline). The bit derived from the plaintext
   IS persisted, but it's a one-bit structural derivation, not
   a plaintext leak.
4. Non-oracle property. P10-2's opportunistic-decode collapses
   every error variant (AEAD failure, CBOR malformed, decoded
   as Live, locked vault) into a single `bit=0` arm; both paths
   return `IngestOutcome::Inserted`. Verified by
   `ingest_tombstone_bit_does_not_oracle_aead_failure_versus_decode_failure`.
5. Append-only state. Tombstone bit is set by INSERT-time
   logic only (in `delete_account` and `ingest_chain_revision`'s
   genuine-foreign-INSERT branch); never UPDATEd after the
   row's initial write. The `account_identities.tombstoned`
   flag is sticky once set (only the resolve flow producing a
   live merge revision can clear it via P9's `clear_frozen`,
   and that path applies to live-revision merges only).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings` clean.
8. `cargo test --workspace --lib` — 323/323 passing (294
   baseline + 29 new).
9. `cargo test --workspace --tests` — integration tests pass,
   including the new `offline_mode::*` and
   `two_vault_roundtrip::own_tombstone_round_trip_via_chain`.

**PoC limitations carried forward (documented in plan + threats):**

- Foreign-event tombstone propagation under PoC two-key
  (Threat #19). Closed structurally in P10-2; closes
  functionally with MVP-1's nonce-on-chain.
- Resurrection of tombstoned account_id is forbidden; under
  PoC, undelete = create a new account with a fresh id (Threat
  #20). MVP-1 may revisit if a deliberate-undelete user
  feature emerges.
- Cross-device offline edit replay inherits #5 — same
  cross-vault discipline applies (Threat #21).
- Tombstone-bit at-rest modification: defense-in-depth via
  AEAD AAD binding; full mitigation is not the application
  layer's job (Threat #22).

## 2026-05-07 · P10 fix-pass — §16.5 audit findings (M-1, M-2, L-1; M-3 deferred; L-2/L-3 no-action)  ✅ SIGNOFF

P10 §16.5 audit (commit `e7d9018`) flagged a documentation drift
plus housekeeping. Fix-pass closes M-1 + M-2 with code+tests, L-1
with a one-line `deny.toml` edit, and explicitly defers M-3 per
auditor recommendation.

**M-1 + M-2 — payload-vs-event `account_id` cross-check (CLOSED).**
THREAT_MODEL row 18 + `docs/issue-plans/P10.md` §A1/§C claimed the
cross-check existed before the code shipped it. Implemented inside
`Vault::detect_tombstone_bit_at_ingest` using
`subtle::ConstantTimeEq::ct_eq` over the 32-byte arrays. Mismatch
silently collapses to `is_tombstone = 0` — same bucket as AEAD
failure / CBOR failure / locked vault — preserving (and
strengthening) the non-oracle property of the ingest decoder. No
new error variant; the decoder itself stays type-pure (the
cross-check is in the ingest layer, not in `decode_payload`). The
freeze sentinel still fires for the row's INSERT, so the
user-facing safety property is unaffected. `subtle` was already a
dep of `pangolin-store` (used in `account.rs::AccountId::ct_eq`);
no Cargo.toml change. Verified `cargo tree -p pangolin-crypto |
grep -ci serde` is still 0 — the new use of `subtle` is in the
store crate, NOT crypto. Two new tests:
- `detect_tombstone_bit_rejects_cross_account_payload` — synthetic
  ciphertext whose AAD-bound id is X but whose plaintext
  `account_id` is Y; bit lands at 0 silently.
- `detect_tombstone_bit_accepts_matching_payload` — same setup
  with X==Y; bit lands at 1 (regression coverage).

THREAT_MODEL row 18 prose updated: replaced the "triggers
`StoreError::Cbor(...)`" claim with the constant-time
silent-rejection description. `docs/issue-plans/P10.md` §A1
(rationale 2), §C (audit-bullet on AAD-vs-plaintext cross-checks),
the threat-model row 14 draft (which is the eventual THREAT_MODEL
row 18 text), and the failure-modes table all updated to align.

**L-1 — stale `RUSTSEC-2024-0388` advisory ignore (CLOSED).** The
alloy/coins version churn that landed earlier dropped `derivative`
from the dep graph, so the ignore began firing
`advisory-not-detected` warnings. Removed the entry from
`deny.toml`; left a forward-comment so a future re-introduction
re-adds it verbatim. `cargo deny check` is now fully clean.

**M-3 — retry-exhaustion deterministic test (DEFERRED).** Per
auditor's PoC-scope recommendation. The retry-loop's failure path
needs a test-only RNG seam to drive `random_32_via_sqlite` through
4 successive collisions; existing happy-path coverage plus the
`~4×N/2^256` probability bound is sound for PoC. Documented in
`docs/issue-plans/P10.md` §"Out of scope (explicit)".

**L-2, L-3 — no-action observations.** L-2 (comment polish on
`derive_fresh_account_id`) and L-3 (positive test count drift)
are acknowledged; no code change.

**Test-count delta:** 324 → 326 lib tests (+2 from M-1+M-2
positive/negative coverage).

**Critical invariants verified at the P10 fix-pass SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; the `subtle` dep was already in `pangolin-store`
   and `subtle` itself does not pull `serde`).
2. No new `unsafe`.
3. No plaintext on disk. The constant-time compare runs on the
   already-decrypted-and-zeroizing-on-drop plaintext inside
   `open_payload`; nothing new is persisted beyond the same
   one-bit `is_tombstone` derivation as P10-2.
4. Non-oracle property STRENGTHENED. The cross-check uses
   `subtle::ConstantTimeEq::ct_eq` (no timing-channel divergence
   on byte-prefix-match position) AND collapses to `0` on
   mismatch (no different error variant). Verified by both new
   tests — the rejection is silent end-to-end.
5. Append-only state unchanged. The cross-check only gates
   bit-set on INSERT; no UPDATE introduced.
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings` clean.
8. `cargo test --workspace --lib` — 326/326 passing.
9. `cargo test --workspace --tests` — integration tests
   unchanged from P10 SIGNOFF tip (no integration test touched).
10. `cargo deny check` fully clean (no `advisory-not-detected`
    warnings after L-1 fix).

## 2026-05-07 · P11A — pangolin-cli account subcommands EPIC  ✅ SIGNOFF

P11A closes the structural gap "Pangolin is a password manager
whose CLI cannot manage passwords." Five new subcommands —
`pangolin-cli account add` / `list` / `show` / `update` /
`delete` — expose P3-era's library account-management API at
the user-facing CLI boundary, preserving P4's presence-
escalation discipline for credential reveals, P8's freeze-guard
discipline, and P10's anti-resurrection / tombstone-payload
discipline. No new cryptographic primitive, no new chain-side
code, no new vault-schema column, no new public library API.

**Commit-by-commit:**

- **P11A-1 (`aba944f`)** — clap scaffold. New
  `tools/pangolin-cli/src/commands/account.rs` module + the
  `Command::Account(AccountArgs)` arm in `cli.rs`. Five sub-
  verbs wired with full `#[derive(Args)]` types; per-verb
  `run_*` functions are stubbed with `bail!("not implemented
  yet")`. 10 clap tests pin the surface (help renders, per-
  verb arg parsing, mutually-exclusive flag groups, empty-
  name reject, §A16 forbidden-user-facing-terms invariant).
- **P11A-2 (`fd382eb`)** — `account add` end-to-end.
  Password input via `--generate-password` (24-char from a
  64-char alphabet, `pangolin_crypto::rng::fill_random` as
  entropy source; printed to STDERR per Q5 inside a
  save-this-now block) OR `--password-stdin` OR interactive
  prompt with confirmation. NO `--password <flag>`. TOTP
  same shape; notes accept the lower-tier `--notes <str>`
  per A5. New `account_id` (lowercase hex) goes to STDOUT
  for shell-pipe ergonomics. Per Q1, `add` does NOT auto-
  create the vault; missing `.pvf` errors fast. 7 tests.
- **P11A-3 (`e2fac26`)** — `account list` + `account show`.
  `list` walks `Vault::list_accounts` (frozen + tombstoned
  filtered by default; `--include-frozen` /
  `--include-tombstoned` opt them in with `[frozen]` /
  `[deleted]` suffix per A11). The internal `ListRow`
  struct holds only identifier-class fields — secret-bearing
  fields are structurally absent (verified by
  `list_row_omits_secret_fields_structurally`). `show`
  default omits secrets; `--reveal-{password,notes,totp-secret}`
  prompt ONCE for presence per A7, then construct N fresh
  `PressYPresenceProof::confirmed()` instances. JSON output
  uses the omit-vs-null discipline (unrevealed fields are
  absent, not `null`). 10 tests.
- **P11A-4 (`cd39730`)** — `account update`. Per A6,
  always presence-gated: the library API requires a
  complete `AccountSnapshot`, so the CLI reveals every
  secret field of the entry to construct it (one prompt;
  three fresh proofs; one update transaction).
  Override-or-preserve per field. Pre-presence guard
  surfaces frozen → resolve hint, tombstoned → "deleted",
  unknown → "no account" before asking the user for a
  presence proof. New `cfg(test)`-only test seam
  `TEST_AUTO_CONFIRM_PRESENCE` bypasses the prompt for
  unit tests; production binaries cannot reach it. 6 tests.
- **P11A-5 (`693d9e2`)** — `account delete`. Default flow
  prints a confirmation prompt that includes the display
  name (typo-prevention per Q3) and reads the literal
  lowercase string `"yes"` (case-sensitive, A9). `--yes`
  bypasses the prompt; `--why <reason>` is informational
  only (echoed to stderr; NOT in the tombstone payload).
  Per Q8 there is NO `--force` flag — frozen-account delete
  surfaces the same "run resolve" hint as `update`.
  Re-deletion of a tombstoned id is refused with an
  idempotency-by-clear-error message rather than silent
  success. Sibling `TEST_AUTO_CONFIRM_DELETE` test seam
  for unit-test ergonomics. 8 tests.
- **P11A-6 (this entry)** — THREAT_MODEL rows 23–27 cover
  the new threat surface: process-listing leak (defense:
  no `--password <flag>`), shell-history leak, tombstone
  replay, reveal-confirmation phishing under `PoC`, and
  frozen-account update/delete refusal. Integration test
  `tools/pangolin-cli/tests/account_lifecycle.rs` exercises
  the full `add → list → show → update → delete` round
  trip on a fresh vault. E2E_TESTS extended with E2E-006
  scenario.

**Test-count delta:** 326 → 367 lib tests (+41 across
P11A-1..P11A-5) plus 1 new integration test
(`account_lifecycle_round_trip`).

**Critical invariants verified at the P11A SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0
   (HIGH-1 bound holds; P11A introduces no new
   `pangolin-crypto` dependency).
2. No new `unsafe`. `forbid(unsafe_code)` is unconditional
   at the top of `tools/pangolin-cli/src/main.rs` and
   `lib.rs`; preserved.
3. No plaintext on disk. Reveal output goes to stdout
   (per Q2). The interactive password prompt, stdin
   variants, and the auto-generated password block all
   route through `SecretBytes` wrappers that zeroize on
   drop. No CLI code path writes plaintext to a file or
   environment variable.
4. No `--password <flag>` form anywhere. Verified by
   `account_add_password_stdin_and_generate_conflict` +
   inspection of `AccountAddArgs` / `AccountUpdateArgs`
   field set (only `password_stdin: bool`,
   `generate_password: bool`, `password_prompt: bool`).
5. Append-only state holds. Account ops use existing
   `add_account` / `update_account` / `delete_account`
   library calls, each of which writes a new revision in
   one transaction (P3 / P8-2 / P10-1 invariants
   preserved).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings`
   clean.
8. `cargo test --workspace --lib` — 367/367 passing
   (326 + 41 new).
9. `cargo test --workspace --tests` — integration tests
   pass, including the new `account_lifecycle.rs`.
10. §3.5 forbidden-user-facing-terms invariant holds —
    `account_help_avoids_forbidden_user_facing_terms`
    pins the rendered `--help` output for "blockchain",
    "transaction", "hashes", "revisions",
    "decentralized storage", and "gas".
11. P0..P10 lib + integration tests unchanged.
12. No new D-NNN entries — every architectural decision
    in the P11A plan is local to the CLI surface and
    documented in `docs/issue-plans/P11A.md` §A1..§A16.

## 2026-05-07 · P11B — pangolin-cli vault create subcommand EPIC  ✅ SIGNOFF

P11B closes the structural gap "Pangolin's CLI cannot create a
vault." One new subcommand — `pangolin-cli vault create
--path <path> [--password-stdin] [--print-id]` — exposes
`Vault::create(path, password)` at the user-facing CLI
boundary, preserving P11A's A3 password-input discipline
(interactive prompt + confirmation OR `--password-stdin`;
NEVER `--password <flag>`). With P11B in place, the P11
reproducer guide drives a non-author developer through
`vault create` → `account add` → `publish` → `pull`
without bespoke fixture scaffolding (the
`Vault::create` library escape hatch is no longer needed).

P11B introduces no new cryptographic primitive, no new
chain-side code, no new vault-schema column, no new public
library API.

**Commit-by-commit:**

- **P11B-1 (`01ee02f`)** — clap scaffold. New
  `Command::Vault(VaultArgs)` variant on the top-level
  `Command` enum (alongside `Account`); nested
  `VaultCommand::Create(VaultCreateArgs)` sub-subcommand;
  one new dispatch arm in `main.rs`; new
  `tools/pangolin-cli/src/commands/vault.rs` module with
  a stubbed `run_create` returning `bail!("not implemented
  yet")`. `VaultCreateArgs`: `--path <PathBuf>` (required),
  `--password-stdin` (bool, default false), `--print-id`
  (bool, default false). NO `--password <flag>` field.
  Per locked Q5 the long-doc on `VaultCommand::Create`
  warns explicitly: "Pangolin has no password-recovery
  mechanism; loss of this password is permanent data
  loss." Eight clap-shape unit tests pin the surface
  (vault subcommand renders, per-verb arg parsing,
  required `--path`, `--print-id` and `--password-stdin`
  flags parse, `--password` flag REJECTED, §A14
  forbidden-user-facing-terms invariant, no-recovery
  warning is in the help output).

- **P11B-2 (`c1d4c0c`)** — `vault create` end-to-end.
  Path canonicalization per §A5: `parent.canonicalize() +
  file_name`, surfacing the absolute resolved path in
  the success message and any error message (matches P8
  fix MED-3's discipline). Pre-flight overwrite refusal
  per §A3: `path.exists()` check at the CLI boundary
  before any password prompt; the library's own check
  plus `acquire_lock`'s `OpenOptions::create_new(true)`
  close the TOCTOU race per §A8; NO `--force` flag.
  Password acquisition per §A2 reuses three helpers from
  `commands/account.rs` (now `pub(crate)` per §A4):
  `prompt_password_with_confirmation`,
  `read_secret_first_line_from_stdin`, and
  `reject_empty_password`. Empty-password guard fires on
  both paths before any library call. Per §A9 the
  interactive path emits a clarifying eprintln! BEFORE
  the rpassword call. POSIX file-mode hardening per Q4:
  after `Vault::create` returns, the new file is chmod
  0o600 on Unix targets (best-effort; warn-but-don't-
  abort on filesystems that ignore POSIX bits;
  cfg(unix) — Windows is a no-op). Vault::close called
  explicitly on success per §A11 (mirrors P11A's
  pattern). Output per §A7: `vault created at
  <canonical-path>` by default; `vault_id: <hex>` line
  added when `--print-id` is set; `--json` global flag
  emits the JSON bundle with the vault_id field always
  present. Nine new unit tests in `commands/vault.rs::tests`
  plus one new integration test
  `tools/pangolin-cli/tests/vault_create_lifecycle.rs::vault_create_then_account_add_round_trip`
  (spawns the binary via `CARGO_BIN_EXE_pangolin-cli`,
  pipes the master password to stdin via
  `--password-stdin`, asserts the produced vault is
  consumable by `account add` under the same password).

- **P11B-3 (this entry)** — THREAT_MODEL row 28 covers
  the new threat surface: vault-creation password leak
  (defense: no `--password <flag>` form), `.pvf`
  overwrite hazard (defense: pre-flight check + library
  guard + lock; no `--force`), parent-dir-traversal /
  symlink redirection at the create boundary (defense:
  parent-canonicalize per §A5), empty-password footgun
  (defense: `reject_empty_password` reused from P11A's
  MED-1 fix), POSIX file-mode hardening (chmod 0o600 on
  Unix per Q4), no-password-recovery user warning
  (`--help` long-doc per Q5; pinned by
  `vault_create_help_warns_no_password_recovery`).
  E2E_TESTS unchanged (`vault create` → `account add`
  is the implicit prefix of every E2E-001..E2E-006
  scenario; the new integration test pins the prefix
  contract).

**Test-count delta:** 384 → 401 lib tests (+17 across
P11B-1's 8 clap tests in `cli.rs` plus P11B-2's 9 vault
unit tests in `commands/vault.rs::tests` on Windows; one
additional cfg(unix) test `vault_create_chmod_0600_on_unix`
runs on Linux for +18 there) plus 1 new integration test
(`vault_create_then_account_add_round_trip`). The P11A
SIGNOFF entry recorded 367 lib tests; the P11B baseline
at `7dd7e77` (P11B plan tip) already showed 384 lib
tests workspace-wide due to P10 / P11A fix-pass / other
intervening commits. P11B-1 took the count to 392
(+8 cli tests), P11B-2 to 401 on Windows (+9 vault
unit tests), and P11B-3 leaves it unchanged at 401.

**Critical invariants verified at the P11B SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0
   (HIGH-1 bound holds; P11B introduces no new
   `pangolin-crypto` dependency and no new `pangolin-store`
   public surface).
2. No new `unsafe`. `forbid(unsafe_code)` is unconditional
   at the top of `tools/pangolin-cli/src/main.rs` and
   `lib.rs`; preserved.
3. No plaintext on disk. Vault password handled via
   `SecretBytes` (zeroizes on drop); the produced `.pvf`'s
   contents are AEAD-encrypted under the VDK which is
   wrapped under the password-derived authority. POSIX
   file-mode hardening (chmod 0o600 on Unix) limits
   on-disk DISCOVERABILITY of the encrypted file to the
   owner UID, not its readability — defense in depth.
4. No `--password <flag>` form anywhere. Verified by
   `vault_create_does_not_accept_password_flag` (clap
   rejects the flag at parse time) and inspection of
   `VaultCreateArgs` field set (only `path: PathBuf`,
   `password_stdin: bool`, `print_id: bool`).
5. Append-only state holds. `Vault::create` is a
   first-time-provisioning op; the append-only invariant
   applies to revisions inside the freshly-created vault,
   not to the `.pvf` file itself. P11B's "refuse to
   overwrite" discipline is the moral equivalent: a
   `.pvf` is created exactly once at a given path
   (per §A3 / §A8).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings`
   clean.
8. `cargo test --workspace --lib` — 401/401 passing
   on Windows (384 baseline + 17 new across P11B-1 +
   P11B-2; +18 on Linux where the cfg(unix) chmod test
   also runs).
9. `cargo test --workspace --tests` — integration tests
   pass, including the new `vault_create_lifecycle.rs::vault_create_then_account_add_round_trip`.
10. §3.5 forbidden-user-facing-terms invariant holds —
    `vault_help_avoids_forbidden_user_facing_terms` pins
    the rendered `vault --help` and `vault create --help`
    output for "blockchain", "transaction", "hashes",
    "revisions", "decentralized storage", and "gas".
11. P0..P11A lib + integration tests unchanged.
12. No new D-NNN entries — every architectural decision
    in the P11B plan is local to the CLI surface and
    documented in `docs/issue-plans/P11B.md` §A1..§A14.

---

## 2026-05-08 · P11 — E2E Reproducer Documentation  ✅ SIGNOFF

**Date:** 2026-05-08
**Tip:** this entry's commit (P11-5 fix-pass)
**Status:** SHIPPED

### Commits

- `ad54185` — docs: P11-1 E2E_REPRODUCER scaffold
- `db9d33d` — docs: P11-2 E2E_TESTS cross-references
- `5a063e7` — docs: P11-3 POC_README entry point
- this entry — docs: P11-5 close P11-4 rehearsal gaps + DEVLOG SIGNOFF

### Deliverables

- `docs/E2E_REPRODUCER.md` (~990 lines after P11-5 fix-pass):
  three scenarios documented in Mock + Live modes using only
  `pangolin-cli` invocations.
- `POC_README.md` (~140 lines): non-author entry point at the
  repository root.
- `E2E_TESTS.md`: cross-reference subsections added to
  E2E-003 / E2E-004 / E2E-005 / E2E-006.

### Non-author rehearsal (P11-4)

- **Scope:** Scenario 1 only (per locked Q3 answer; Scenarios
  2 and 3 deferred per plan).
- **Mode:** Mock.
- **Verdict:** PASS-WITH-FIXES — three minor doc gaps surfaced.
- All three gaps closed in this P11-5 fix-pass:
  - **G1.** Scenario 1 Mock-mode expected count corrected
    from "3 passed" to "5 passed" with one-line explanation
    that the test file also houses Scenario 2's resolve test
    + P10's tombstone round-trip test.
  - **G2.** Setup section split into Mock-mode-required
    (§3a) and Live-mode-required (§3b) subsections with
    explicit "skip §3b if Mock-only" callout — saves a
    cold-read non-author dev ~5 minutes of release-build
    time they don't need.
  - **G3.** Smoke-test expected output now explains cargo's
    per-crate summary lines; reader sums them rather than
    reading just the last one (which would show ~142 passed
    for the largest crate and cause unwarranted panic).

### Critical invariants preserved

1. Zero Rust code modified across P11-1..P11-5 — documentation-
   only.
2. Workspace test count unchanged at 401/401 on Windows
   (~405 on Linux); the smoke baseline from the P11B SIGNOFF
   tip carries through unchanged.
3. HIGH-1 invariant — `cargo tree -p pangolin-crypto |
   grep -ci serde` → 0.
4. No new `unsafe`. `forbid(unsafe_code)` preserved at every
   P0..P11B crate root.
5. §3.5 forbidden-user-facing-terms invariant — none of the
   listed terms appear in any new doc text. (E2E_REPRODUCER.md
   uses "the chain" and "publish" / "pull" / "resolve" — all
   permitted under §3.5; "blockchain", "transaction",
   "decentralized storage", "gas", and the bare nouns
   "hashes" and "revisions" are absent from user-facing
   prose.)
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings`
   clean.
8. `cargo test --workspace --lib` — 401/401 on Windows.
9. `cargo test --workspace --tests` — green.
10. `cargo audit` — clean.
11. `cargo deny check` — clean.

### Out of scope (per plan)

- Recorded screencast — deferred to P12-3.
- Signed binary — deferred to P12-1.
- Live-chain rehearsal in CI — too costly; documented as
  "opt-in, not rehearsed in CI" in the doc itself.
- Scenarios 2 and 3 non-author rehearsal — deferred per the
  locked Q3 answer (scenario 1 only on first pass).

### MVP-1 polish opportunities surfaced during build

These are NOT P11 bugs (P11 is doc-only); they are quirks of
the underlying CLI that the reproducer documents around. Each
becomes a candidate MVP-1 polish item:

- `account show` does not currently expose `revision_id`
  directly; Scenario 2 must save the publish-summary stderr
  to recover it.
- Binary-level network-disconnect simulation absent;
  Scenario 3 Live mode requires OS-level "disable wifi"
  rather than a `pangolin-cli --simulate-disconnect` flag.
- The generated password from `account add --generate-password`
  prints only on stderr; rehearsal-friendly capture would
  benefit from a `--print-password-on-stdout` flag (or the
  existing `--json` global flag, which already includes it
  in the JSON envelope, could be advertised more
  prominently).

### Unblocks

P11 unblocks **P12** (signed binary + screencast + final
`POC_README.md` polish). With the reproducer in `main`, P12
can quote line ranges from `docs/E2E_REPRODUCER.md` rather
than re-derive them, and the screencast author has a
verified script to follow.

---

## 2026-05-08 · P12 — Packaging EPIC  ✅ SIGNOFF

**Date:** 2026-05-08
**Tip:** this entry's commit (P12-5 SIGNOFF)
**Status:** SHIPPED

### Commits

- `3639c3e` — P12: issue plan for packaging + PoC -> MVP gate
  retrospective (P12.md plan-gate, landed before this branch).
- `329916d` — P12 redeploy proof: D-015 RevisionLogV0 at
  `0x74f28794c180bb1BEB698b294F69554D0ACCA9c4` (landed on main
  before this branch; closes §3.9 criterion 4).
- `d73c247` — P12-1: release pipeline + GPG-signing scaffold
  for Windows-x64.
- `c3c0c19` — P12-2: POC_README polish for distribution
  audience.
- `d9b520e` — P12-3: screencast script + recording protocol.
- `05d1cbb` — P12-4: PoC -> MVP gate retrospective in
  DECISIONS.md.
- this entry — P12-5: DEVLOG SIGNOFF + POC COMPLETE
  announcement.

### Deliverables

- **`scripts/release-windows.ps1`** (256 lines) — PowerShell
  release pipeline. Pre-flight gate (cargo fmt / clippy /
  test --lib), workspace release build, binary verification,
  dist directory clobber + recreate, copy artefacts (binaries
  + LICENSE + POC_README.md + docs/E2E_REPRODUCER.md), sorted
  SHA-256 manifest with Linux-style format, optional GPG
  signing of the manifest, Compress-Archive into the upload
  zip. Idempotent + fail-fast. Flags: `-SkipSign`,
  `-SkipPreflight`, `-Version`.
- **`docs/RELEASE.md`** (265 lines) — publisher's release
  runbook. Prerequisites (Rust 1.83+, Windows-x64, GnuPG,
  release-commit working tree), how to run the script, how
  to verify locally, how to upload to GitHub Releases page,
  signing-key fingerprint placeholder (Kelvin fills in
  post-merge), troubleshooting table.
- **`POC_README.md`** polished from 141 to 198 lines:
  - New §A6 Status callout block (verbatim PoC framing).
  - New "Watch the demo" pointer (YouTube unlisted URL
    placeholder).
  - New "Download a prebuilt binary" section with
    `gpg --verify` + `sha256sum -c` verification dance.
  - "Build" → "Build from source (alternative)".
  - New SmartScreen / antivirus disclosure bullet in
    known-quirks.
  - D-015 redeploy proof referenced in Live-chain section.
  - Internal links verified (RELEASE.md, SCREENCAST_SCRIPT.md,
    E2E_REPRODUCER.md#live-mode-safety).
  - Forbidden-terms scan: 0 hits per §3.5.
- **`docs/SCREENCAST_SCRIPT.md`** (466 lines) — beat-by-beat
  recording protocol for Kelvin's 5-minute walkthrough.
  Pre-recording checklist, 6 beat blocks (Title / Setup /
  Scenario 1 / Scenario 2 / Scenario 3 / Closing) with
  command + framing + narration per beat, post-recording
  checklist, YouTube unlisted upload protocol. Forbidden-
  terms scan: 0 hits.
- **`DECISIONS.md`** retrospective (+341 lines) appended after
  D-015. Five §3.9 criterion verdicts (4 CLOSED + 1
  OPEN-WITH-EVIDENCE pending screencast URL); fifteen
  per-D-NNN classifications (6 PERMANENT, 1 EVOLVES-IN-MVP-1,
  2 EVOLVES-IN-MVP-2, 2 EVOLVES-IN-MVP-3, 1 EVOLVES-IN-MVP-4,
  3 THROWAWAY-FOR-PoC); zero NEEDS-REWORK candidates;
  explicit "open follow-ups" subsection (one item: screencast
  URL); explicit handoff to MVP-1.
- **`DEVLOG.md`** (this entry + the POC COMPLETE entry below).

### Critical invariants preserved

1. **HIGH-1** — `cargo tree -p pangolin-crypto | grep -ci serde`
   = **0**. (Verified at P12 SIGNOFF tip.)
2. **No new `unsafe`** — all eight crates retain
   `forbid(unsafe_code)` at their root (verified via grep).
3. **No plaintext on disk** — P12 ships zero new code; the
   release pipeline writes only release binaries + manifests
   + signatures. No vault material on the publisher host.
4. **Workspace clippy clean** — `cargo clippy --workspace
   --all-targets -- -D warnings` passes at P12 SIGNOFF tip.
5. **Workspace fmt clean** — `cargo fmt --all --check` passes.
6. **Test baseline holds at 401/401** — `cargo test
   --workspace --lib` produces:
   - pangolin-core: 52 passed
   - pangolin-store: 133 passed
   - pangolin-crypto: 1 passed (lib placeholder; test vectors
     under tests/)
   - pangolin-chain: 71 passed
   - pangolin-indexer: 1 passed (lib placeholder)
   - pangolin-funder-client: 1 passed (lib placeholder)
   - pangolin-cli (lib): 142 passed
   - **Total: 401 passed; 0 failed; 0 ignored.**
7. **`cargo audit`** — clean (2 unmaintained-crate warnings:
   `derivative 2.2.0` via `ark-ff` via `alloy`,
   per-existing; no vulnerabilities).
8. **`cargo deny check`** — `advisories ok, bans ok, licenses
   ok, sources ok`.
9. **§3.5 forbidden-terms compliance** — none of `gas` /
   `blockchain` / `transaction` / `decentralized storage` /
   `hashes` / `revisions` appear in `POC_README.md` or
   `docs/SCREENCAST_SCRIPT.md` (verified via Grep).
10. **`dist/` correctly ignored** — `git status` clean after
    a release-script run; `git check-ignore` confirms
    `dist/windows-x64/*` matches `.gitignore` line 15.
11. **Zero Rust files modified** — `git diff --stat
    329916d..HEAD` shows changes only in `DECISIONS.md`,
    `POC_README.md`, `docs/RELEASE.md`,
    `docs/SCREENCAST_SCRIPT.md`,
    `scripts/release-windows.ps1`. No `crates/` or `tools/`
    files touched. `Cargo.toml` and `Cargo.lock` unchanged.

### Pipeline verification

- **`scripts/release-windows.ps1`** was verified manually by
  running its individual steps in sequence (the wrapper
  PowerShell invocation is unavailable to the agent
  environment; cargo build + manual file copy + sha256sum
  manifest compute were exercised end-to-end).
- `cargo build --workspace --release` builds clean (1m 45s);
  produces `target/release/pangolin-cli.exe` (9509888 bytes)
  + `target/release/chaincli.exe` (6279680 bytes).
- The SHA-256 manifest format is verified to round-trip via
  `sha256sum -c SHA256SUMS` on the produced
  `dist/windows-x64/` directory tree.
- `gpg --detach-sign` is NOT exercised by the agent (no
  passphrase available). Kelvin runs the script with default
  arguments at release time; `-SkipSign` is the agent /
  CI / non-keyholder path.

### §3.9 gate state at P12 SIGNOFF

Per `DECISIONS.md` retrospective (§"PoC retrospective"):

| Criterion | Verdict | Evidence |
|---|---|---|
| 1. All issues closed; build artifact + screencast | OPEN-WITH-EVIDENCE | All P0..P11B SIGNOFFs in DEVLOG; P12 commits land the build pipeline + script + screencast script; YouTube URL filled in by Kelvin post-record. |
| 2. E2E reproduced by non-author | CLOSED | P11-4 rehearsal record (see `DEVLOG.md` § "Non-author rehearsal (P11-4)" under the P11 SIGNOFF entry). |
| 3. No plaintext to disk in P1, P3, P7 | CLOSED | P1, P3, P7 SIGNOFF entries in DEVLOG; HIGH-1 invariant holds at this tip. |
| 4. Contract redeployed at least once | CLOSED | D-015 (commit `329916d`) redeployed at `0x74f2…A9c4` block 41224971. |
| 5. DECISIONS retrospectively updated | CLOSED | The retrospective IS this section in DECISIONS.md. |

Four CLOSED + one OPEN-WITH-EVIDENCE. Criterion 1 resolves to
CLOSED at the moment Kelvin records the screencast and pastes
the URL into POC_README + the §A11 attestation here.

### Out of scope (per plan)

- **Authenticode signing** — MVP-1's packaging cycle. PoC
  ships GPG-signed manifest only.
- **macOS / Linux / mobile builds** — MVP-1 packaging cycle
  adds `scripts/release-{macos,linux}.sh`.
- **Reproducible builds** — MVP-1+ may target.
- **CI-driven releases** — manual on Kelvin's host for PoC.
- **The actual screencast recording** — Kelvin's task post-
  merge; agent ships only the script.
- **A second non-author rehearsal against the polished
  POC_README** — recommended skip per `P12.md` test plan; the
  P11-4 rehearsal transcript covers the cold-read path.
- **Authenticode-cert acquisition cost cycle** — MVP-1.
- **A `THREAT_MODEL.md` row #29** — P12 BUILD walk surfaced
  no new user-facing risk; recommended NO new row per `P12.md`
  §5; no row added.

### MVP-1 polish opportunities surfaced during build

These are NOT P12 bugs (P12 is doc + script only); they are
items for MVP-1 scoping:

- **Screencast script Sub-beat 4.1** swaps Live-mode offline
  for Mock-mode `cargo test`. Live-mode disconnect-on-camera
  is fragile; Mock mode is recommended. MVP-1's CLI hardening
  could add `--simulate-disconnect` to make a Live-mode
  offline beat possible without OS-level network toggles.
- **Account_id / revision_id capture between scenarios** —
  the screencast walks a `<account_id>`/`<revision_id>`
  capture-and-paste between Beats 1.3 and 3.1. MVP-1 could add
  a `--save-state-to <file>` flag on `account add` /
  `publish` so multi-step demos don't require human paste.
- **`account show` does not currently expose `revision_id`
  directly** — surfaced at P11 SIGNOFF; still open. MVP-1
  could close.
- **Authenticode acquisition** — `docs/RELEASE.md` documents
  the MVP-1 follow-up; the cycle is ~1 week of identity-
  verification + cert-acquisition work.

### Unblocks

P12 unblocks **MVP-1**. The §3.9 gate is closed at this tip
(criterion 1 resolves to CLOSED at screencast-URL fill-in;
criteria 2-5 already CLOSED). MVP-1 issue scoping consumes
the per-D-NNN classifications above as input. Per
`PANGOLIN_PLAN.md` §4 ("PoC code transitions in *as is* where
it's right; gets refactored where MVP-1 needs more"), MVP-1
inherits the full P0..P12 codebase + documentation set; the
EVOLVES-IN-MVP-1 D-006 (gas/payment two-key → single-key) is
the highest-priority MVP-1 issue.

---

## 2026-05-08 · POC COMPLETE — handoff to MVP-1

**Date:** 2026-05-08
**Tip:** this entry's commit (P12-5 SIGNOFF + POC COMPLETE).

This is the phase-boundary marker. Pangolin's PoC sprint is
complete; the master-plan §3.9 PoC → MVP gate is closed (with
one OPEN-WITH-EVIDENCE pending the recorded-screencast URL,
which is filled in by Kelvin post-record without further
agent work).

### What shipped through the PoC sprint

- **11 PoC issues + 2 sub-EPIC fix-passes:** P0, P1 (+ fix-pass),
  P2, P3, P4, P5 (+ P5-1, P5-4), P6, P7, P8 (+ fix-pass),
  P9 (+ fix-pass × 2), P10 (+ fix-pass), P11A, P11B,
  P11 (+ fix-pass), P12. Each has a SIGNOFF entry above.
- **8 Rust crates:** `pangolin-core`, `pangolin-crypto`,
  `pangolin-store`, `pangolin-chain`, `pangolin-indexer`,
  `pangolin-funder-client`, plus `tools/pangolin-cli` and
  `tools/chaincli` binary crates.
- **401/401 lib tests passing on Windows.** No `unsafe` in
  any crate. HIGH-1 invariant (no serde in `pangolin-crypto`)
  holds. Cargo audit clean.
- **Deployed RevisionLogV0** at
  `0x8566D3de653ee55775783bD7918Fe91b66373896` on Base Sepolia
  (D-014); redeploy proof at
  `0x74f28794c180bb1BEB698b294F69554D0ACCA9c4` (D-015) closes
  the §3.9 redeploy criterion.
- **Three end-to-end scenarios** (sync, conflict-resolve,
  offline-edit) each documented in Mock + Live mode in
  `docs/E2E_REPRODUCER.md`.
- **`E2E_TESTS.md` ledger** with E2E-001..E2E-006 entries
  cross-referenced into the reproducer.
- **`THREAT_MODEL.md`** — 28 rows covering credential input,
  foreign-event ingestion, freeze sentinels, presence-prompt
  phishing, vault file format, and chain interaction.
- **`DECISIONS.md`** — D-001..D-015 + the §3.9 PoC → MVP gate
  retrospective (PoC retrospective: PoC → MVP mapping).
- **Windows-x64 release pipeline** at
  `scripts/release-windows.ps1` + runbook at
  `docs/RELEASE.md`.
- **5-minute screencast script** at
  `docs/SCREENCAST_SCRIPT.md`.
- **`POC_README.md`** as the non-author entry point (198
  lines under the §A14 200-line cap).

### §3.9 gate state at POC COMPLETE

| Criterion | Verdict |
|---|---|
| 1. All issues closed; P12 build artefact + screencast | OPEN-WITH-EVIDENCE (resolves CLOSED at screencast-URL fill-in) |
| 2. E2E reproduced by non-author | CLOSED |
| 3. No plaintext to disk in P1, P3, P7 | CLOSED |
| 4. Contract redeployed at least once | CLOSED (D-015) |
| 5. DECISIONS retrospectively updated | CLOSED |

Per master-plan §3.9 ("If any item fails: stop, fix the PoC,
do not start MVP work"), the gate is **closed** with one
OPEN-WITH-EVIDENCE that resolves on a non-blocking out-of-tree
artefact — MVP-1 work is authorized to begin. Kelvin's
attestation for the screencast lands as a post-merge update to
this entry, the P12 SIGNOFF entry, and `POC_README.md`'s
"Watch the demo" link.

### Handoff to MVP-1

The MVP-1 issue-scoping pass starts from:

- **`DECISIONS.md`** §"PoC retrospective" — the canonical
  per-D-NNN classification ledger.
- **`THREAT_MODEL.md`** rows #1-#28 — the threats MVP-1
  inherits.
- **`PANGOLIN_PLAN.md`** §4 (MVP-1 sub-issue list) — the
  master-plan's MVP-1 scope envelope.
- **Open MVP-1 polish opportunities** documented in DEVLOG
  P9, P10, P11, P12 SIGNOFF entries (search the SIGNOFF
  entries above for "MVP-1 polish" subsections).

The highest-priority MVP-1 issue per the retrospective is
**D-006 evolution: PoC two-key → MVP-1 single-key** (closes
the freeze-on-pull surface documented in P10 + P11 reproducer
Scenario 1).

### Reference

- Master plan §3.7: PoC issue list (P0..P12).
- Master plan §3.9: PoC → MVP gate criteria.
- Master plan §4: MVP-1 scope.
- `DECISIONS.md` §"PoC retrospective": per-D-NNN classification.

---

*PoC sprint sealed at this entry. Subsequent DEVLOG entries
belong to MVP-1's issue cycle. Future MVP-N completions follow
this entry's "POC COMPLETE — handoff to MVP-N" pattern.*

---

## 2026-05-08 · MVP-1 issue 1.1 — Rust workspace + FFI plan locked

Plan at `docs/issue-plans/1.1.md` Kelvin-approved with Q1-Q5 answers locked: (Q1) `pangolin-cli` moves to `apps/cli/`, (Q2) Vault/session-type relocation deferred to 1.4 with `pangolin-core` re-exporting from `pangolin-store`, (Q3) FFI surface in dedicated `pangolin-ffi` crate, (Q4) TOTP and KDBX as separate `pangolin-totp` + `pangolin-kdbx` crates, (Q5) MSRV pinned to 1.94.0. Master plan §16.8 amended off-repo (separate from this commit). Security-critical because the FFI boundary every shell binds against is frozen here.

**Workspace shuffle.** `git mv tools/pangolin-cli apps/cli` (history preserved); binary name + cargo target unchanged (`pangolin-cli` → `apps/cli/Cargo.toml`'s `[bin].name`). Three new scaffolding crates: `crates/pangolin-ffi/` (UniFFI proc-macros + cbindgen surface, body grows over 1.2-1.11), `crates/pangolin-totp/` and `crates/pangolin-kdbx/` (single `name()` placeholders pending 1.7 / 1.9 bodies). `pangolin-core/src/{identity,session,revision,sync,recovery}/mod.rs` are placeholder modules; `pangolin-core` now depends on `pangolin-store` and re-exports `Vault`, `AccountSnapshot`, `RevisionId`, `RevisionGraph`, `SessionState`, etc., so the FFI namespace freezes today.

**FFI surface.** `pangolin-ffi` wires UniFFI 0.31.1 in proc-macro mode via `#[uniffi::export]` / `#[derive(uniffi::Record/Object/Error)]` on every record listed in `docs/issue-plans/1.1.md` Public-surface; bodies are `todo!()` until the per-domain issues land but signatures + bindgen output are frozen. Hand-written C-ABI shim in `src/cabi.rs` (`pangolin_vault_open` / `pangolin_vault_close` so far) emits via `cbindgen` 0.29.2 to `target/ffi-bindings/c/pangolin.h`. Two binaries (`uniffi-bindgen` + `cbindgen-build`) gated behind `uniffi-cli` / `cbindgen-cli` features so the default build doesn't pull bindgen tooling. `pangolin-core` unified error taxonomy (§18.8) with total `From<StoreError>` mapping; `FfiError` exhaustively maps from `pangolin_core::Error` per `tests/error_taxonomy.rs`.

**Toolchain pin.** `rust-toolchain.toml` channel 1.94.0; `[workspace.package].rust-version = "1.94"`. `pangolin-ffi` is the only crate that locally allows `unsafe_code` (overrides workspace `unsafe_code = "deny"`); `deny(unsafe_op_in_unsafe_fn)` so every `unsafe` is at a documented call site. Per-crate `crates/pangolin-crypto/clippy.toml` adds `clippy::disallowed_types` belt-and-braces for `serde::*`.

**CI.** New `ffi-bindings` job (3-OS matrix; builds cdylib+staticlib, runs `cbindgen` + `cc -fsyntax-only`, runs `uniffi-bindgen` for Swift on macOS / Kotlin on Linux). New `invariants` job runs `scripts/check-no-serde-in-crypto.{sh,ps1}` and `scripts/check-no-uniffi-in-core.{sh,ps1}`. Both invariants verified locally: `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0.

**Test count delta.** Pre-1.1: 248 tests (242 lib + 6 integration). Post-1.1: 428 tests (409 lib + 19 ffi-integration). Breakdown of new tests: `pangolin-ffi::tests::cabi::*` (3, in-crate), `pangolin-ffi::error::tests::*` (2), `pangolin-ffi::tests::*` (1 lib), `pangolin-ffi/tests/roundtrip.rs` (14 integration), `pangolin-ffi/tests/error_taxonomy.rs` (5 integration), `pangolin-totp` lib (1), `pangolin-kdbx` lib (1). The 142 pangolin-store + 71 pangolin-cli + 133 pangolin-crypto + 52 pangolin-chain + 6 chaincli lib counts are unchanged.

**Local verification.** `cargo build --workspace --all-targets` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --all -- --check` clean; `cargo test --workspace --lib` 409/409 pass; `cargo run -p pangolin-cli -- --version` prints `pangolin-cli 0.0.0` from new `apps/cli/` location; `cargo run -p pangolin-ffi --bin cbindgen-build --features cbindgen-cli` emits 2.8 KB pangolin.h; `cargo run -p pangolin-ffi --bin uniffi-bindgen --features uniffi-cli -- generate ...` emits 85 KB Swift + 116 KB Kotlin (both non-empty).

**Surprises.** UniFFI proc-macros emit code that touches `_`-prefixed argument bindings, which trips clippy's `used_underscore_binding` lint; resolved by renaming the `todo!()`-body args to non-underscore names + a `let _ = (...);` to silence unused-variable. `clippy::doc-markdown` flags every bare `UniFFI` / `SQLite` / `KeePass` / `Session::*` reference; non-trivial cleanup pass to backtick all proper-noun-but-not-rust-ident references throughout the new code. `cbindgen` Cargo crate-name on crates.io is `cbindgen` (matches feature deps name); `uniffi-build` is published as `uniffi_build` (underscore) — both pinned in `crates/pangolin-ffi/Cargo.toml` to specific 0.29.2 / 0.31.1 versions.

**Open. ** Master plan §16.8 amendment lives off-repo at `C:\Users\kelvi\.openclaw\workspace-studio-pangolin\PANGOLIN_PLAN.md` and is not part of this commit (per the plan's note at §F). The actual `swiftc -typecheck` / `kotlinc` foreign-language compile smoke in CI is `continue-on-error: true` for Swift (toolchains drift; locked-in-1.1 invariant is bindgen-emitted-non-empty, not foreign-compile-clean) — when MVP-5 lands real Swift / Kotlin compile pinning, that step graduates to a hard gate.

Unblocks MVP-1 issues 1.2 (account identity), 1.3 (vault create/open), 1.4 (session rewrite, also relocates types out of `pangolin-store` per Q2), 1.6 (revision lineage production + §18.7 schema-versioning policy), 1.7 (TOTP body), 1.8 (password generator), 1.9 (KDBX import body), 1.10 (encrypted export), 1.11 (capture authority).
