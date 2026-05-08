# Pangolin (PoC)

A local-first password manager with hardware-assisted authority
and append-only durability. The PoC ships a Rust core
(`pangolin-store`, `pangolin-crypto`, `pangolin-chain`), a thin
command-line shell (`pangolin-cli`), and a debug oracle
(`chaincli`) for inspecting the deployed contract on Base
Sepolia testnet. This document is the entry point for a
non-author developer evaluating the build; the deeper guides
live under `docs/`.

> **Status:** Proof-of-concept release for technical evaluation.
> **Not production-ready.** Do not use this binary with real
> credentials. The vault file format may change in subsequent
> milestones without an automatic migration path; treat any
> vault you create with this release as throwaway. The deployed
> contract on Base Sepolia is testnet-only; no mainnet deployment
> exists at this tip. Issues, questions, and reproduction
> reports are welcome via the repository's issue tracker.

A 5-minute walkthrough of all three end-to-end scenarios is
posted as an unlisted YouTube video:
[Pangolin PoC demo (5 min)](https://www.youtube.com/watch?v=_TBD_FILL_IN_AT_RELEASE_TIME_).
The URL is filled in at SIGNOFF time per
[`docs/SCREENCAST_SCRIPT.md`](docs/SCREENCAST_SCRIPT.md).

## Download a prebuilt binary

The recommended path. Pre-built Windows-x64 binaries are
attached to the
[GitHub Releases page](https://github.com/kelvinsinferno/pangolin/releases)
under the tag `v0.0.0-poc`. Each release attaches:

- `pangolin-poc-v0.0.0-poc-windows-x64.zip` — the artefact bundle.
- `SHA256SUMS` — per-artefact integrity manifest.
- `SHA256SUMS.asc` — detached GPG signature over the manifest.

### Verifying a downloaded release

The PoC release ships a GPG-signed manifest in lieu of an
Authenticode-signed binary (deferred to MVP-1; see "Known
quirks" below).

```bash
# 1. Fetch the signing public key (one-time).
#    Fingerprint published in docs/RELEASE.md.
gpg --keyserver hkps://keys.openpgp.org --recv-keys <fingerprint>

# 2. Confirm the manifest signature + each artefact hash.
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS    # or Get-FileHash on PowerShell
```

If both succeed, the download is intact. Unzip and put
`pangolin-cli.exe` and `chaincli.exe` on your `PATH`.

## Build from source (alternative)

Skip this section if you downloaded the prebuilt binary.
Requires stable Rust 1.83+ ([rustup](https://rustup.rs/)).

```bash
cargo build --workspace --release
```

First build downloads ~300 MB of dependencies and takes ~5
minutes on a modern dev machine. The release binaries land in
`target/release/`. Publishers run `scripts/release-windows.ps1`
to produce the same artefact bundle the GitHub Releases page
hosts; see [`docs/RELEASE.md`](docs/RELEASE.md).

## Quick smoke test

```bash
cargo test --workspace --lib
```

Expected: ~395 tests pass on Linux/macOS, ~401 on Windows
(`cfg(unix)`-gated tests skip on Windows). Total runtime
~30 seconds. A passing run gives you confidence the build is
healthy before walking through the live scenarios below.

## Try it: three end-to-end scenarios

The scenarios live in `docs/E2E_REPRODUCER.md`. Each takes
~5–10 minutes once the build is done and ships in two execution
modes: an unattended **Mock mode** (a `cargo test` invocation
using a built-in mock chain adapter; no funded keystore needed)
and an opt-in **Live mode** (the `pangolin-cli` walkthrough
against the deployed contract on Base Sepolia).

- **Scenario 1 — Two-vault sync round trip.** Create an
  account on vault A, publish, copy the vault to device B,
  pull on B, observe the freeze sentinel that PoC two-key
  produces. → `docs/E2E_REPRODUCER.md` § Scenario 1.
- **Scenario 2 — Conflict + resolve convergence.** Continues
  from Scenario 1's freeze. Run `pangolin-cli resolve` on B to
  ratify A's entry; pull on A and exercise the multi-resolve
  pattern. → `docs/E2E_REPRODUCER.md` § Scenario 2.
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

A second deployment of the same bytecode at
`0x74f28794c180bb1BEB698b294F69554D0ACCA9c4` exists as
operational evidence the deploy script remains runnable on
demand (closes the §3.9 PoC-gate redeploy criterion; recorded
as D-015). The PoC CLI continues to point at the canonical
address above; the redeploy is not wired into any code path.

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
> operation. Generate it fresh, fund it from a faucet, discard
> it after. Any future MVP-2 mainnet deployment will live at a
> different address.

The reproducer's [Live-mode safety
callout](docs/E2E_REPRODUCER.md#live-mode-safety) walks through
the keystore-creation flow step by step.

## Known quirks (set expectations)

The PoC ships a deliberately minimal security model. Every
known quirk is closed by a clearly-named MVP-N work item.

- **Two-vault sync triggers a freeze on the receiving side**
  pending an explicit `pangolin-cli resolve` ratification.
  Closes under MVP-1's single-key model. The reproducer's
  Scenario 1 walks through it.
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
- **Unsigned Windows binary may trigger SmartScreen.** The
  PoC release ships a GPG-signed manifest but no Authenticode
  certificate; MVP-1's packaging cycle adds Authenticode.
  Windows SmartScreen may show an "unrecognized publisher"
  warning on first run; click "More info" → "Run anyway" if
  you trust the GPG-verified hash. Some antivirus heuristics
  may also flag unsigned Rust binaries; whitelist the binary
  path or temporarily suppress the heuristic during the
  rehearsal.

## Where to find more

- `docs/E2E_REPRODUCER.md` — the authoritative scenario guide
  (long-form; both Mock and Live mode for each scenario).
- [`docs/RELEASE.md`](docs/RELEASE.md) — publisher's release
  runbook (prerequisites, signing-key fingerprint, upload steps).
- [`docs/SCREENCAST_SCRIPT.md`](docs/SCREENCAST_SCRIPT.md) —
  the beat-by-beat script the demo video follows.
- `DECISIONS.md` — the architectural decisions log (D-001
  through D-015 as of P12; D-014 records the deployed-contract
  address, D-015 records the redeploy proof, plus the §3.9
  PoC → MVP gate retrospective at the bottom of the file).
- `THREAT_MODEL.md` — the row-by-row threat catalogue (28 rows
  as of P11B).
- `E2E_TESTS.md` — the author-facing test ledger; entries
  E2E-001..E2E-006 cross-reference `docs/E2E_REPRODUCER.md`.
- `CONTRIBUTING.md` — the §16 per-issue development protocol.
- `docs/issue-plans/` — per-issue plans and audits.

## License

AGPL-3.0-or-later for the core code (vault engine, sync, credential
management, local storage). See `LICENSE` and `LICENSE-RATIONALE.md` for
the per-layer license map.
