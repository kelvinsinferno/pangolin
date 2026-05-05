# DEVLOG

> Append-only log. One entry per closed issue. 1–3 sentences each: what shipped, surprises, deferred follow-ups.

---

## 2026-05-05 · P0 bootstrap
Sprint authorized. Repo scaffolded at `C:\Users\kelvi\Projects\pangolin` per master plan §16.8: full directory tree (`crates/`, `contracts/`, `apps/`, `services/`, `tools/`, `design/`, `docs/`, `.github/`). Apache-2.0 LICENSE, README, .gitignore, CONTRIBUTING.md (issue 18.6 — encodes §16 protocol), GitHub PR template + issue template (issue 18.13 — forces §16.2 plan structure), forbidden-terms CI workflow (issue 18.12 — Design Spec §15.2 enforcement), DECISIONS.md (issue P0-2 — locks D-001 through D-013), DEVLOG.md, E2E_TESTS.md, THREAT_MODEL.md skeletons.

## 2026-05-05 · P0-1 — Cargo workspace + rustfmt/clippy + GH Actions CI
Plan committed at `docs/issue-plans/P0-1.md` and self-approved (non-security-critical per §16.3). All 7 crates scaffolded with workspace inheritance: `pangolin-core`, `pangolin-crypto`, `pangolin-store`, `pangolin-chain`, `pangolin-indexer`, `pangolin-funder-client`, `pangolin-cli` (binary). Each has a placeholder `name()` function exercised by a unit test. Workspace lints set to `clippy::all = deny` + `pedantic` + `nursery` warn-level with explicit allows; `unsafe_code = deny` workspace-wide. CI workflow (`.github/workflows/ci.yml`) runs fmt, clippy `-D warnings`, test on Linux/Windows/macOS. Local verification on Windows host: build clean, fmt clean, clippy clean under pedantic+nursery, all 7 unit tests pass, `pangolin v0.0.0 (pangolin-core linked)` prints from CLI.

Surprises: pinned rustup symlinks in `.cargo/bin/` aren't directly invokable from this bash; resolved by invoking the actual toolchain bin path (`~/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/`). Two pedantic-clippy fixes needed mid-build: `SQLite` and `EVM` flagged for missing backticks in doc comments. `imports_granularity` and `group_imports` are nightly-only rustfmt options; removed from `rustfmt.toml` with note to revisit if/when nightly fmt is adopted.

Next issue: P0-2 already shipped as `DECISIONS.md` in the bootstrap commit. After this commit, the next units of work are **P1 series** (`pangolin-crypto` real implementation — Kelvin-gated at PLAN per §16.3 because it's security-critical) and **P5-1** (`RevisionLogV0.sol` first draft + Foundry tests — also Kelvin-gated). Both are independent and parallelizable.
