# Pangolin

> A local-first, hardware-assisted password manager with blockchain-backed durability and social recovery.

**Status: Pre-development → P0 (sprint authorized 2026-05-05).**

This repository implements Pangolin per the canonical specifications:

- **Whitepaper** — local-first usage, layered authority, append-only revisions, blockchain as durability log only
- **Unified Session Authority, Hardware & Interaction Specification** — session invariant (start = 2 proofs, maintain = 1), proof types, hardware classes, timing rules
- **Browser Extension & Mobile Autofill Integration Specification** — ambient operation, capture-authority rule, 16 JSON-RPC message types between extension and core
- **Unified UI/UX Design System Specification** — future-natural, ambient-first, warm-armor palette, pangolin-scale motion

The master execution plan is in `../../.openclaw/workspace-studio-pangolin/PANGOLIN_PLAN.md`.

## Repository layout

See `docs/architecture/repo-layout.md` for the canonical layout. Top-level:

```
crates/        Rust workspace — pangolin-core, pangolin-crypto, pangolin-store,
               pangolin-chain, pangolin-indexer, pangolin-funder-client, pangolin-cli
contracts/     Solidity (Foundry) — RevisionLog, EntitlementRegistry, Recovery
apps/          Client shells — desktop (Tauri), extension, ios, android (later phases)
services/      Off-chain — funder (one-way ETH dispenser; never signs or submits)
tools/         chaincli debug oracle
design/        Design tokens, components, brand assets
docs/          issue-plans, architecture, specs (links to canonical docs)
```

## How development works

Every issue follows the §16 Per-Issue Development Protocol from the master plan:

1. **PLAN** — write `docs/issue-plans/<issue-id>.md` before any code
2. **APPROVE** — peer or Kelvin reviews the plan (Kelvin required for security-critical)
3. **BUILD** — code on the issue branch, with spec references in comments
4. **TEST** — every success criterion has a test; CI green; never weaken tests to make them pass
5. **SIGNOFF** — DEVLOG entry; close issue; move to next

See `CONTRIBUTING.md` for the full protocol.

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later) for the
core code shipped in this repository — vault engine, sync logic, recovery
logic, credential management, local storage, session policy, and TOTP
handling. See `LICENSE` for the full license text and `LICENSE-RATIONALE.md`
for the per-layer license map (AGPL core, Apache-2.0 future SDKs and
integrations, CC BY-SA documentation, trademark-protected branding) and
the rationale per the Pangolin Licensing & Intellectual Property
Specification.
