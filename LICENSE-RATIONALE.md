# License Rationale

> Per-layer license map for the Pangolin codebase.
>
> Source: `Pangolin Licensing & Intellectual Property Specification`
> (foundational IP strategy authored 2026-05). Per-decision lock recorded
> in `DECISIONS.md` D-016 (supersedes D-002).

---

## TL;DR

| Layer | License | What it covers |
|---|---|---|
| **Core applications** | AGPL-3.0-or-later | Vault engine, sync, recovery, credential management, local storage, session policy, TOTP, capture authority — everything currently in this repo |
| **SDKs / APIs / integrations** | Apache-2.0 | Future MVP-1+ surfaces: FFI/UniFFI bindings, hardware integration helpers, agent SDKs, browser-extension APIs, protocol wrappers |
| **Documentation** | CC BY-SA | Whitepapers, specs, architecture documents, diagrams, educational materials |
| **Branding** | Trademark | "Pangolin", "Pangolin Vault", "Pangolin Commit Mode", "Pangolin Sync", logos |

---

## Why AGPLv3 for the core

Pangolin is security software. The trust users place in a password manager
is structurally different from the trust they place in a productivity tool —
a compromised vault is a catastrophic loss. The licensing model exists to
preserve that trust against three specific threats:

1. **Hosted extractive forks.** A third party hosts a modified version,
   monetizes the ecosystem, and refuses to publish their changes. AGPLv3's
   network-use clause requires hosted forks to publish their modifications,
   keeping the ecosystem transparent.
2. **Unsafe closed security forks.** A third party modifies security-
   critical behavior, distributes opaque binaries, and weakens cryptographic
   assumptions. AGPLv3 ensures any redistributed modification is itself
   inspectable; Apache-2.0 (the original D-002 choice) would not.
3. **Ecosystem fragmentation.** Overly restrictive licensing at the
   integration boundary would discourage browser extensions, hardware
   vendors, and agent tooling. The Apache-2.0 layer (future MVP-1+) keeps
   that boundary permissive.

AGPLv3 makes inspection a license obligation rather than a request. For
security-critical code, that's the operational form of "trust through
transparency."

---

## Why Apache-2.0 for the integration boundary

When MVP-1+ ships SDKs, UniFFI bindings, hardware integration helpers, and
client libraries, those will live under Apache-2.0. Permissive licensing
at the ecosystem boundary is intentional:

- **Hardware integrations** need to embed the API/SDK without copyleft
  contagion into the integrator's own product.
- **Browser extensions and native messaging hosts** need to ship in
  contexts where AGPL would be a non-starter for participating browsers.
- **Agent tooling** (e.g., LLM-based password assistants) needs to call
  Pangolin APIs without the agent's own code being forced into AGPL.

The boundary is enforced **per-crate** via `Cargo.toml` `license` fields.
A future SDK crate will declare `license = "Apache-2.0"`; the core engine
crates declare `license = "AGPL-3.0-or-later"`. `cargo deny check` enforces
the workspace allow-list.

---

## How the boundary is decided

A crate is **core** (AGPLv3) if it:

- defines or implements security-critical behavior (encryption, KDF,
  signing, presence proofs, session policy, vault file format);
- handles secrets directly (passwords, vault data keys, tombstones);
- governs recovery (guardian thresholds, social recovery client logic);
- participates in the trust model (capture authority, ambient escalation,
  freeze sentinel, conflict resolution).

A crate is **integration** (Apache-2.0) if it:

- exposes a stable API surface intended for third-party consumption;
- provides bindings into another language ecosystem (Swift, Kotlin, JS);
- wraps a hardware protocol;
- enables ecosystem interoperability without itself making security
  decisions;
- is meant to be embedded into integrators' products.

When a contribution touches multiple layers (e.g., a helper used by both
core and a future SDK), discuss placement with maintainers before opening
the PR. Default placement is core/AGPL unless there's an explicit
integration-boundary justification.

---

## Why CC BY-SA for documentation

Documentation should remain shareable, remixable, and attributable. CC
BY-SA enables third parties to translate, adapt, and republish Pangolin's
specifications and educational materials while preserving attribution and
ensuring derivative works stay under the same terms.

The repository's `docs/` directory and the master plan / whitepaper /
specifications in `Desktop/Kelvinsinferno studio/Pangolin/` fall under this
layer. (Internal issue plans in `docs/issue-plans/` are working documents
that ship under the repository's AGPL umbrella; they are not public-facing
specifications.)

---

## Why trademark protection for branding

Security software is uniquely vulnerable to scam and malware impersonation.
The "Pangolin" name and logos must not be used to imply official affiliation
or endorsement by an unauthorized fork. Forks may freely use the source code
under AGPL terms — but cannot publish a binary as "Pangolin" or "Pangolin
Vault" without authorization.

This is enforced separately from the source-code license, by trademark law.
See the IP spec §5 for the protected mark list and the §5.3 branding
restrictions.

---

## What this repository contains today

Every crate in this workspace is currently **core**:

- `crates/pangolin-crypto` — AEAD primitives, KDF, signing
- `crates/pangolin-store` — vault file format, session policy, freeze sentinel
- `crates/pangolin-chain` — sync logic, signature builder, chain adapter
- `crates/pangolin-core` — shared types
- `crates/pangolin-funder-client` — funder service client (currently a placeholder; promotion to Apache-2.0 is possible if it stabilizes as a true integration boundary in MVP-2)
- `crates/pangolin-indexer` — indexer placeholder (same caveat)
- `tools/pangolin-cli` — user CLI (driver of all core ops)
- `tools/chaincli` — debug oracle (driver of chain ops)
- `contracts/src/RevisionLogV0.sol` — append-only revision log

All ship under **AGPL-3.0-or-later** per `LICENSE` and the per-crate
`Cargo.toml` `license` fields.

When MVP-1 lands the FFI/UniFFI bindings (master plan issue 1.1) and the
Apache-2.0 layer becomes real, this file will be updated to record the
boundary in the workspace.

---

## Verifying the license declaration

```bash
# Workspace-wide license is AGPL-3.0-or-later
grep '^license' Cargo.toml
# license = "AGPL-3.0-or-later"

# cargo-deny enforces the allow-list (includes AGPL for first-party
# crates plus the existing permissive set for transitive deps)
cargo deny check licenses

# The LICENSE file is the canonical FSF AGPLv3 text
head -2 LICENSE
#                     GNU AFFERO GENERAL PUBLIC LICENSE
#                        Version 3, 19 November 2007
```

If you encounter a mismatch (e.g., a crate declaring Apache-2.0 in its
own `Cargo.toml` but containing core code), open an issue.

---

## See also

- `LICENSE` — full AGPLv3 text
- `DECISIONS.md` D-016 — relicense decision record
- `DECISIONS.md` D-002 — superseded historical record
- `Pangolin Licensing & Intellectual Property Specification` — the spec
  this rationale derives from
- `CONTRIBUTING.md` — contributor license terms
