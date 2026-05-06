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
