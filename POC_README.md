# Pangolin (PoC)

A local-first password manager with hardware-assisted authority
and append-only durability. The PoC ships a Rust core
(`pangolin-store`, `pangolin-crypto`, `pangolin-chain`), a thin
command-line shell (`pangolin-cli`), and a debug oracle
(`chaincli`) for inspecting the deployed contract on Base
Sepolia. This document is the entry point for a non-author
developer evaluating the build; the deeper guides live under
`docs/`.

> **Status:** PoC. Not production-ready. The deployed contract
> lives on Base Sepolia testnet only; do not reuse any keystore
> or password from this guide for real-value operations.

## Build

Requires stable Rust 1.83+ ([rustup](https://rustup.rs/)).

```bash
cargo build --workspace --release
```

First build downloads ~300 MB of dependencies and takes ~5
minutes on a modern dev machine. The release binaries land in
`target/release/`; the relevant ones are `pangolin-cli` and
`chaincli`.

## Quick smoke test

```bash
cargo test --workspace --lib
```

Expected: ~395 tests pass on Linux/macOS, ~401 on Windows
(`cfg(unix)`-gated tests are skipped on Windows). Total runtime
~30 seconds. A passing run gives you confidence the build is
healthy before walking through the live scenarios below.

## Try it: three end-to-end scenarios

The scenarios live in `docs/E2E_REPRODUCER.md`. Each takes
~5–10 minutes once the build is done. Each ships in two
execution modes: an unattended **Mock mode** (a `cargo test`
invocation that uses a built-in mock chain adapter; no funded
keystore needed) and an opt-in **Live mode** (the
`pangolin-cli` walkthrough against the deployed contract on
Base Sepolia).

- **Scenario 1 — Two-vault sync round trip.** Create an
  account on vault A, publish it, copy the vault file to
  device B, pull on B, observe the freeze sentinel that PoC
  two-key produces. → `docs/E2E_REPRODUCER.md` § Scenario 1.

- **Scenario 2 — Conflict + resolve convergence.** Continues
  from Scenario 1's freeze. Run `pangolin-cli resolve` on B to
  ratify A's entry as canonical; pull on A and exercise the
  multi-resolve pattern under PoC two-key. →
  `docs/E2E_REPRODUCER.md` § Scenario 2.

- **Scenario 3 — Offline edit then online publish.** Disconnect
  the network, edit the vault locally (Cardinal Principle 1:
  edits MUST succeed without connectivity), reconnect, drain
  the queue. → `docs/E2E_REPRODUCER.md` § Scenario 3.

## Live-chain mode (Base Sepolia testnet)

The PoC's deployed RevisionLogV0 contract:

```
contract address : 0x8566D3de653ee55775783bD7918Fe91b66373896
chain id         : 84532
RPC default      : https://sepolia.base.org
explorer         : https://sepolia.basescan.org
```

To run a Live-mode scenario you need:

1. [Foundry](https://book.getfoundry.sh/getting-started/installation)
   installed (`cast` binary).
2. A **fresh Base Sepolia keystore** funded from any public
   faucet. Create one via `cast wallet new`, fund it from
   either the
   [Coinbase faucet](https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet)
   or the
   [Alchemy faucet](https://www.alchemy.com/faucets/base-sepolia),
   verify the balance with `cast balance <address> --rpc-url
   https://sepolia.base.org`, and import it as a named keystore
   via `cast wallet import <name> --interactive`.

> **TESTNET ONLY.** The keystore you use for the rehearsal must
> NEVER hold mainnet ETH or be reused for any real-value
> operation. Generate it fresh, fund it from a faucet, and
> discard it after the rehearsal. Any future MVP-2 mainnet
> deployment will live at a different address.

The reproducer's [Live-mode safety
callout](docs/E2E_REPRODUCER.md#live-mode-safety) walks through
the keystore-creation flow step by step.

## PoC limitations to set expectations

The PoC ships a deliberately minimal security model. Every
known quirk is closed by a clearly-named MVP-N work item.

- **Two-vault sync triggers a freeze on the receiving side**
  pending an explicit `pangolin-cli resolve` ratification.
  Closes under MVP-1's single-key model. The reproducer's
  Scenario 1 walks through it; the threat model documents the
  full reasoning.
- **Multi-resolve on N-device convergence:** when both devices
  publish before either pulls, both must run `resolve` to
  reach single-head convergence. Also closes under MVP-1.
- **Presence prompt is the only proof-of-presence:** commands
  that reveal secrets (`pangolin-cli account show
  --reveal-password`) prompt for `'y'`; under PoC this is the
  entire proof-of-presence surface. MVP-2 introduces
  hardware-backed presence proofs.
- **No password recovery:** if you forget the vault's master
  password, the vault is unrecoverable. By design under PoC; a
  future MVP introduces social recovery.

## Where to find more

- `docs/E2E_REPRODUCER.md` — the authoritative scenario guide
  (long-form; both Mock and Live mode for each scenario).
- `DECISIONS.md` — the architectural decisions log (D-001
  through D-014 as of P11; D-014 records the deployed-contract
  address verbatim).
- `THREAT_MODEL.md` — the row-by-row threat catalogue (28 rows
  as of P11B; covers credential input, foreign-event ingestion,
  freeze sentinels, presence-prompt phishing surface).
- `E2E_TESTS.md` — the author-facing test ledger; entries
  E2E-001..E2E-006 each have a `### Reproducibility`
  cross-reference back into `docs/E2E_REPRODUCER.md`.
- `CONTRIBUTING.md` — the §16 per-issue development protocol.
- `docs/issue-plans/` — per-issue plans and audits.

## License

Apache-2.0. See `LICENSE`.
