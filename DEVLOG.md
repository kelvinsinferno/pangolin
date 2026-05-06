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
- Runtime keccak256: `0xaeff0a8fc34b478cb4c93b6f5bfd293cc12dd5f0a65a997c7c022b23f3e4e2d0` (matches the audited 443-byte artifact bytewise)
- Verification on Basescan: deferred (Kelvin will add API key later; `forge verify-contract` command documented in deployment metadata)

All five pre-flights passed before broadcast: chain id == 84532, deployer balance > 0.001 ETH (had 0.118), runtime size == 443 B, gas estimate within budget. End-to-end smoke test recorded as E2E-001 in `E2E_TESTS.md`: `nextSequence()` initial 0; `publishRevision(0xaaaa…, 0xbbbb…, 0x0, 0xcccc…, 0, 0xdeadbeef…)` mined with status 1 in tx `0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6`; emitted event with topic[0] = `keccak256(RevisionPublished signature)` confirmed; `nextSequence()` after = 1. The chain integration write-path is proven on a real EVM testnet.

Surprises: Base Sepolia's gas price was 0.006 gwei at deploy time — substantially below the 0.011 gwei estimate. Final cost was about 60% under projection. Useful data point for sizing the funder service's top-up amounts in MVP-2 (issue 3.4).

The `contracts/deployments/base-sepolia.json` file is the canonical machine-readable record. P6 (chaincli) and P7 (chain adapter) will read the contract address from this file; do not hardcode the address elsewhere.

Deferred: Basescan source verification (a one-command operation when Kelvin obtains a free Basescan API key). The contract works fully without it — verification is purely an explorer convenience.

Next: **P2 series** (`pangolin-store`) is now the only remaining blocker for P3/P4/P7/P8. P5-4 unblocks P6 (chaincli — talks to this deployed contract) and P7 (chain adapter — also talks to it).
