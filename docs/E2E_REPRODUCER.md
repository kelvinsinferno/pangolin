# Pangolin E2E Reproducer

> **Audience:** a non-author developer evaluating Pangolin from a
> fresh clone. This guide walks you through three end-to-end
> scenarios using only the `pangolin-cli` binary; no test code or
> internal documents need to be read. Each scenario takes ~5–10
> minutes once the build is done.
>
> **Verified against:** `main` at commit `474de64` (issue
> `P11`). If your clone is at a later commit, output formats may
> have shifted; the underlying behavior is stable but a literal
> string may differ.

This document is the authoritative reproducer for the three master-
plan E2E scenarios. The matching automated tests live under
`tools/pangolin-cli/tests/`; the reproducer's "Mock mode" pointers
at `cargo test` invocations are the safety net for "did the build
actually work?" The "Live mode" steps walk you through the
production CLI against the deployed contract on Base Sepolia.

---

## Contents

- [Prerequisites](#prerequisites)
- [Setup (shared)](#setup-shared)
- [PoC limitations to set expectations](#poc-limitations-to-set-expectations)
- [Scenario 1 — Two-vault sync round trip](#scenario-1--two-vault-sync-round-trip)
- [Scenario 2 — Conflict + resolve convergence](#scenario-2--conflict--resolve-convergence)
- [Scenario 3 — Offline edit then online publish](#scenario-3--offline-edit-then-online-publish)
- [Cleanup](#cleanup)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

You need:

1. **Rust toolchain — stable 1.83 or later.** Install via
   [rustup](https://rustup.rs/) and run `rustup default stable`.
   Verify with `rustc --version` (should print `1.83.0` or later).
2. **A POSIX or PowerShell shell.** Linux, macOS, and Windows
   PowerShell are supported. On Windows, use PowerShell 5.1+ or
   PowerShell 7+ (cmd.exe and git-bash are not separately
   documented; pick PowerShell or follow the Linux/macOS
   commands under WSL).
3. **A working internet connection** for the initial `cargo build`
   (downloads dependencies on first run; ~300 MB) and for any
   Live-mode walkthrough (Base Sepolia RPC + faucet).

For Live mode (optional, opt-in per scenario), you additionally
need:

4. **Foundry** ([install instructions](https://book.getfoundry.sh/getting-started/installation)),
   in particular the `cast` binary.
5. **A Base Sepolia keystore** with non-zero ETH. See the
   ["Live-mode safety" callout](#live-mode-safety) below for the
   funding workflow.

### Live-mode safety

> **TESTNET ONLY.** The keystore you use for this walkthrough must
> NEVER hold mainnet ETH or be reused for any real-value
> operation. Generate a fresh keystore (`cast wallet new`),
> fund it from a Base Sepolia faucet, and discard it after the
> rehearsal. Pangolin's PoC contract lives on testnet only;
> any future MVP-2 mainnet deployment will live at a different
> address.

Funding workflow (run once, before the first Live-mode scenario):

```bash
# 1. Create a fresh keystore. You'll be prompted for a password.
cast wallet new --unsafe-password 'ephemeral-keystore-password'

# 2. The output contains an Address: 0x... line. Copy that address.

# 3. Visit any Base Sepolia faucet and fund the address. Two known
#    options:
#      - https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet
#      - https://www.alchemy.com/faucets/base-sepolia
#    A small drip (0.001 ETH or so) is more than enough for the
#    full reproducer.

# 4. Verify the balance landed BEFORE running any Live-mode step:
cast balance 0x<your-keystore-address> --rpc-url https://sepolia.base.org
# Expected: a non-zero hex value (e.g., 0x38d7ea4c68000 for
# 0.001 ETH).
```

Once funded, import the keystore under a memorable name so the
rest of the reproducer can reference it:

```bash
cast wallet import poc-rehearsal --interactive
# Paste the private key from step 1's output, then enter a
# password to encrypt it on disk. The keystore is stored at
# ~/.foundry/keystores/poc-rehearsal (Linux/macOS) or
# %USERPROFILE%\.foundry\keystores\poc-rehearsal (Windows).
```

Throughout the rest of this document the keystore name
`poc-rehearsal` is used as the example value; substitute your own
keystore name.

---

## Setup (shared)

These steps are run once at the start of the rehearsal; the three
scenarios then share the resulting build artifact and scratch
directory.

### 1. Clone the repository

```bash
git clone https://github.com/<owner>/pangolin.git
cd pangolin
```

(Replace `<owner>` with the actual GitHub owner; this reproducer
assumes you already have a local clone at the repository root.)

### 2. Build the workspace

```bash
cargo build --workspace --release
```

Expected: ~5 minutes on a modern dev machine for the first build
(downloads ~300 MB of dependencies). Subsequent builds are much
faster. The output binaries land in `target/release/`. The two
binaries the reproducer uses are:

- `target/release/pangolin-cli` — the production CLI
- `target/release/chaincli` — the debug oracle (used in the
  contract-address verification step below)

You can put `target/release/` on your `$PATH` for convenience, or
invoke the binaries with their full path. Throughout this
document, plain `pangolin-cli ...` and `chaincli ...` invocations
assume `target/release/` is on `$PATH`; if you prefer the full
path, substitute `./target/release/pangolin-cli ...` everywhere.

### 3. Smoke test (Mock mode workspace tests)

Before running any scenario, confirm the build is healthy:

```bash
cargo test --workspace --lib
```

Expected: ~395 tests pass on Linux/macOS, ~401 on Windows
(`cfg(unix)`-gated tests are skipped on Windows). If the count is
substantially lower, see [Troubleshooting](#troubleshooting) item
5.

### 4. Verify the deployed contract address (optional but recommended)

The PoC's deployed RevisionLogV0 contract is recorded at
`contracts/deployments/base-sepolia.json`. To cross-check it
matches the address embedded in `POC_README.md` and this
document:

```bash
chaincli status
```

Expected output includes:

```
contract_address   : 0x8566d3de653ee55775783bd7918fe91b66373896
chain_id           : 84532  (expected: 84532)  OK
```

If the address differs from
`0x8566D3de653ee55775783bD7918Fe91b66373896` (case-insensitive),
your clone is on a different fork; the rest of this reproducer's
Live-mode steps will not match the documented contract.

### 5. Create a scratch directory

The scenarios use project-local files under `./tmp/`:

```bash
# Linux / macOS:
mkdir -p tmp

# Windows PowerShell:
mkdir tmp -ErrorAction SilentlyContinue
```

This directory holds the example vault files produced by the
scenarios. It is git-ignored (or you can add it to your local
ignore list). The [Cleanup](#cleanup) section at the end of this
document removes the directory.

### Test password (used by every scenario)

Throughout this reproducer, the example vault password is:

```
pangolin-poc-test-vault-do-not-reuse
```

This value is **a TEST password**. Its content telegraphs intent
("do-not-reuse"); use it for the rehearsal vaults only and
**never** as the master password for a real Pangolin vault, a
real password manager, or any other credential. Generate a fresh,
high-entropy password for any production vault.

---

## PoC limitations to set expectations

Before running the scenarios, note these PoC quirks. They are
expected behavior under the current security model; each is
closed by a clearly-named MVP-N work item and is documented in
the threat model and decisions log.

- **Two-vault sync triggers a "freeze" on the receiving side.**
  When vault A publishes an entry and vault B pulls it, the
  ingested entry is FROZEN on B pending a manual `resolve`. This
  is expected: under the PoC two-key model, vault B does not yet
  share signing authority with vault A, so the cross-device
  ingest is treated as a foreign edit that must be ratified
  before B's view converges. Scenario 1 walks you through the
  freeze + resolve cycle. Scenario 2 exercises the full multi-
  device convergence path. The PoC's quirk closes under MVP-1's
  single-key model.

- **Multi-resolve on N-device convergence.** When two devices
  both publish before either pulls, full single-head
  convergence requires BOTH devices to run `pangolin-cli
  resolve` on their own freeze flags after pulling. Scenario 2
  documents this "two-resolve walk." Closes under MVP-1's
  single-key model.

- **Presence prompt is the only proof-of-presence under PoC.**
  Commands like `pangolin-cli account show --reveal-password`
  prompt for a single `'y'` keystroke before printing a secret.
  Under PoC this prompt is the entire proof-of-presence surface;
  MVP-2 introduces hardware-backed presence proofs.

- **No password recovery.** If you forget the vault's master
  password, the vault is unrecoverable; every account inside is
  permanently inaccessible. This is by design — the PoC has no
  recovery mechanism. MVP-N introduces social recovery.

- **Live mode requires a funded testnet keystore and is NOT
  rehearsed in CI.** Each scenario's Live mode is opt-in; the
  Mock mode (run via `cargo test`) is the unattended safety
  net.

---

## Scenario 1 — Two-vault sync round trip

> **Master-plan ID:** P11-1. **E2E ledger ID:** E2E-003.
> **Underlying automated test:**
> `tools/pangolin-cli/tests/two_vault_roundtrip.rs::convergence_freezes_on_pull`
> (and two sibling tests).

**Narrative.** A user creates an entry on vault A, publishes it
to the chain, then pulls it back on vault B. Under the PoC two-
key model, B's pull observes the ingested entry as a foreign edit
and freezes it pending an explicit ratification (resolve).

### Mock mode — automated end-to-end test

This is the unattended path; no funded keystore needed.

```bash
cargo test -p pangolin-cli --test two_vault_roundtrip
```

Expected: three sub-tests pass —
`convergence_freezes_on_pull`, `symmetric_fork`, and
`idempotent_repeat_pull`. Output ends with:

```
test result: ok. 3 passed; 0 failed; ... finished in <N>s
```

If any of the three fails, the build is broken; see
[Troubleshooting](#troubleshooting) item 5.

### Live mode — Base Sepolia walkthrough

> **TESTNET ONLY.** Re-read the [Live-mode safety
> callout](#live-mode-safety) above before running these steps.
> The keystore you use here MUST be a fresh testnet-only
> keystore funded from a Base Sepolia faucet.

#### Step 1. Create vault A

```bash
# Linux / macOS:
echo 'pangolin-poc-test-vault-do-not-reuse' | \
  pangolin-cli vault create \
    --path ./tmp/pangolin-poc-vault-A.pvf \
    --password-stdin
```

```powershell
# Windows PowerShell:
'pangolin-poc-test-vault-do-not-reuse' | `
  pangolin-cli vault create `
    --path .\tmp\pangolin-poc-vault-A.pvf `
    --password-stdin
```

Expected stdout:

```
vault created at <absolute-path-to-tmp/pangolin-poc-vault-A.pvf>
```

The `<absolute-path>` placeholder will reflect your actual
working directory; the literal string `vault created at ` is
stable.

#### Step 2. Add an account on vault A

```bash
pangolin-cli account add \
  --vault-path ./tmp/pangolin-poc-vault-A.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --name 'github-work' \
  --username 'octocat@example.com' \
  --url 'https://github.com' \
  --generate-password \
  --no-totp
```

Expected output:

- On stderr, a "save this now" block surrounding the generated
  password:

  ```
  =========================================================
  GENERATED PASSWORD (save this now; will not be shown again):
  <24-character generated password>
  =========================================================
  ```

  Copy the generated password if you want to use it later.
  Pangolin will not display it again.

- On stdout, the new account's identifier as 64-char lowercase
  hex (this is non-deterministic — yours will differ):

  ```
  <account_id-64-hex-chars>
  ```

- On stderr, a confirmation line:

  ```
  created account <account_id-64-hex-chars> with name 'github-work'
  ```

Save the `<account_id>` value — Scenario 2 uses it for the
`account show` and `resolve` invocations.

#### Step 3. Inspect vault A

```bash
pangolin-cli status --vault-path ./tmp/pangolin-poc-vault-A.pvf
```

Expected output (line order is stable; values reflect your
state):

```
vault_path            <absolute-path>
vault_id              0x<vault_id-64-hex-chars>
dirty_count           1
account_count         1
frozen_count          0
last_pulled_block     0
last_published_block  0
```

`dirty_count: 1` means there is one queued entry waiting to be
pushed to the chain.

#### Step 4. Publish vault A's entry to Base Sepolia

```bash
pangolin-cli publish \
  --vault-path ./tmp/pangolin-poc-vault-A.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --account poc-rehearsal
```

You will be prompted for the keystore password (the one you set
during `cast wallet new` / `cast wallet import`). The publish
flow signs the entry locally with the keystore key, submits it
to Base Sepolia, and clears the dirty marker on success.

Expected stderr:

```
publish summary: 1 published, 0 failed (out of 1 dirty entries)
  ok   <revision_id-64-hex> block=<N> log=<M> seq=<K>
```

The `<N>`, `<M>`, `<K>` placeholders are non-deterministic
(actual chain state).

#### Step 5. Re-check vault A's status

```bash
pangolin-cli status --vault-path ./tmp/pangolin-poc-vault-A.pvf
```

Expected:

```
dirty_count           0
last_published_block  <block-number-from-step-4>
```

#### Step 6. Create vault B as a copy of vault A's file

In a real two-device deployment, you would copy the `.pvf` file
between devices via any out-of-band channel. For the rehearsal,
copy locally:

```bash
# Linux / macOS:
cp ./tmp/pangolin-poc-vault-A.pvf ./tmp/pangolin-poc-vault-B.pvf
```

```powershell
# Windows PowerShell:
Copy-Item .\tmp\pangolin-poc-vault-A.pvf .\tmp\pangolin-poc-vault-B.pvf
```

Vault B now opens under the same master password as vault A
(the PoC two-key model derives a shared decryption key from the
password). Each vault carries a distinct `device_id` once
opened; the next step exercises that distinction.

#### Step 7. Pull on vault B

```bash
pangolin-cli pull \
  --vault-path ./tmp/pangolin-poc-vault-B.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse'
```

Expected stderr:

```
pull summary: 1 new events ingested; last_pulled_block = <N>; 0 forked account(s); 1 frozen account(s)
  frozen: account <account_id-64-hex> is frozen pending resolve
```

This is the expected PoC freeze surface. Vault B has ingested
A's entry but cannot use it until you ratify it via
`pangolin-cli resolve`; that flow is exercised in Scenario 2.

#### Step 8. Confirm vault B sees the frozen account

```bash
pangolin-cli account list \
  --vault-path ./tmp/pangolin-poc-vault-B.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --include-frozen
```

Expected stdout:

```
<account_id-64-hex>  github-work [frozen]
```

(Without `--include-frozen`, the default `account list` output
hides frozen entries; the empty result `(no entries)` would
otherwise be confusing.)

#### Cleanup for Scenario 1

The vault files survive across scenarios; the
[Cleanup](#cleanup) section at the bottom of this document
removes them all. If you want to reset just Scenario 1's state
before moving on:

```bash
# Linux / macOS:
rm ./tmp/pangolin-poc-vault-A.pvf ./tmp/pangolin-poc-vault-B.pvf
```

```powershell
# Windows PowerShell:
Remove-Item .\tmp\pangolin-poc-vault-A.pvf, .\tmp\pangolin-poc-vault-B.pvf
```

---

## Scenario 2 — Conflict + resolve convergence

> **Master-plan ID:** P11-2. **E2E ledger ID:** E2E-004.
> **Underlying automated test:**
> `tools/pangolin-cli/tests/two_vault_roundtrip.rs::convergence_after_resolve`.

**Narrative.** Continues from Scenario 1's freeze. The user runs
`pangolin-cli resolve` on vault B to ratify A's entry as the
canonical head. The resolve flow re-seals the entry under merge
authority, publishes a "merge revision" pointing at the chosen
head, and clears the freeze flag. After resolve completes on B,
A's view of the chain is updated by re-pulling — under the PoC
two-key model A also sees the merge as a foreign event and must
run its own resolve, which is the documented multi-resolve
pattern.

### Mock mode — automated end-to-end test

```bash
cargo test -p pangolin-cli --test two_vault_roundtrip convergence_after_resolve
```

Expected:

```
test result: ok. 1 passed; 0 failed; ... finished in <N>s
```

(The `convergence_after_resolve` test runs the full publish →
freeze → resolve → re-converge sequence end-to-end against
`MockChainAdapter`.)

### Live mode — Base Sepolia walkthrough

This scenario assumes Scenario 1's Live mode completed
successfully and that vaults A and B both exist under
`./tmp/`. If you cleaned up Scenario 1, re-run its Live-mode
steps 1–7 first.

#### Step 1. Identify the values you need

You need three pieces of information:

1. **`<account_id>`** — the 64-char hex id of the
   `github-work` account. Captured in Scenario 1, Step 2's
   stdout. If you didn't save it, run:

   ```bash
   pangolin-cli account list \
     --vault-path ./tmp/pangolin-poc-vault-B.pvf \
     --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
     --include-frozen
   ```

   The first 64-char hex string on the line is the account id.

2. **`<keep-revision-id>`** — the 64-char hex id of the
   revision you want to ratify as canonical. For this
   walkthrough you'll keep vault A's published revision (the
   only entry that exists). The `account show` command does
   not currently expose the revision id; the easiest source is
   the Step 4 publish-summary output from Scenario 1
   (`<revision_id-64-hex>`). If you didn't save it, the
   automated test path is the simpler walkthrough — see Mock
   mode above.

3. **`poc-rehearsal`** — your funded Base Sepolia keystore
   from the prerequisites.

#### Step 2. Dry-run the resolve

The `--dry-run` flag prints the planned action without
publishing or clearing the freeze flag. Always run it before
the live invocation; it confirms your `--account-id` and
`--keep` values parse cleanly.

```bash
pangolin-cli resolve \
  --vault-path ./tmp/pangolin-poc-vault-B.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --account-id <account_id> \
  --keep <keep-revision-id> \
  --account poc-rehearsal \
  --dry-run
```

Expected stderr:

```
dry run: pre-publish chain re-pull SKIPPED (dry-run mode); current local view may be stale
dry run: would publish merge revision <merge-revision-id-64-hex>
```

No keystore-password prompt fires under `--dry-run` — the
operation does not touch the chain.

#### Step 3. Run the live resolve

```bash
pangolin-cli resolve \
  --vault-path ./tmp/pangolin-poc-vault-B.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --account-id <account_id> \
  --keep <keep-revision-id> \
  --account poc-rehearsal \
  --yes
```

You will be prompted for the keystore password. (The `--yes`
flag skips the additional "type yes to confirm" prompt; the
keystore-password prompt is independent.)

Expected stderr:

```
resolve summary: published merge revision <merge-revision-id-64-hex> at block <N> log <M> seq <K>
```

#### Step 4. Confirm vault B's freeze cleared

```bash
pangolin-cli pull \
  --vault-path ./tmp/pangolin-poc-vault-B.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse'
```

Expected:

```
pull summary: 1 new events ingested; last_pulled_block = <N>; 0 forked account(s); 0 frozen account(s)
```

The `0 frozen account(s)` confirms vault B's view has converged
with the chain.

#### Step 5. Pull on vault A and observe the multi-resolve pattern

Vault A has not yet seen B's merge revision. Pull it:

```bash
pangolin-cli pull \
  --vault-path ./tmp/pangolin-poc-vault-A.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse'
```

Expected:

```
pull summary: 1 new events ingested; last_pulled_block = <N>; 0 forked account(s); 1 frozen account(s)
  frozen: account <account_id> is frozen pending resolve
```

This is the documented multi-resolve pattern under PoC two-key.
Vault A also needs to ratify B's merge (treating it as a
foreign edit) before A's view fully converges. Repeat Step 3
against vault A:

```bash
pangolin-cli resolve \
  --vault-path ./tmp/pangolin-poc-vault-A.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --account-id <account_id> \
  --keep <merge-revision-id-from-step-3> \
  --account poc-rehearsal \
  --yes
```

After both A and B run resolve, re-pulling on either vault
shows `0 frozen account(s)` and the chain's head row is the
common merge revision. Full multi-device single-head
convergence under MVP-1's single-key model removes this two-
resolve walk.

---

## Scenario 3 — Offline edit then online publish

> **Master-plan ID:** P11-3. **E2E ledger ID:** E2E-005.
> **Underlying automated test:**
> `tools/pangolin-cli/tests/offline_mode.rs::offline_edit_then_online_publish`.

**Narrative.** A user edits the vault while the network is
unreachable. Edits succeed locally and queue as dirty entries.
When connectivity returns, a single `publish` call drains the
queue.

### Mock mode — automated end-to-end test

The Mock-mode path uses `MockChainAdapter::set_disconnected(true)`
to simulate the network outage; no real network manipulation
needed.

```bash
cargo test -p pangolin-cli --test offline_mode
```

Expected:

```
test result: ok. 3 passed; 0 failed; ... finished in <N>s
```

The three sub-tests are
`offline_edit_then_online_publish`,
`offline_publish_with_no_dirty_entries_is_noop_at_lib_layer`, and
`offline_session_does_not_set_freeze_sentinel`.

### Live mode — Base Sepolia walkthrough with a real network outage

This scenario is the most environmentally sensitive — it
requires you to actually disconnect from the internet and
reconnect. Plan a 5-minute window where you can drop and restore
your network connection without disrupting other work.

#### Step 1. Set up a fresh vault while online

```bash
echo 'pangolin-poc-test-vault-do-not-reuse' | \
  pangolin-cli vault create \
    --path ./tmp/pangolin-poc-vault-offline.pvf \
    --password-stdin
```

```bash
pangolin-cli account add \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --name 'initial-online-account' \
  --generate-password \
  --no-totp
```

```bash
pangolin-cli publish \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --account poc-rehearsal
```

Expected `publish summary: 1 published, 0 failed (out of 1 dirty entries)`.

#### Step 2. Disconnect from the network

Disable your wifi / unplug the ethernet cable / disable the
network adapter. The exact mechanism is OS-specific; the goal
is that any HTTPS request to `https://sepolia.base.org` fails
at the transport layer.

Quick verification (this should fail on a disconnected host):

```bash
curl -sS --max-time 5 https://sepolia.base.org -o /dev/null
echo "curl exit: $?"
```

Expected: a non-zero curl exit code (e.g., `6` for "Could not
resolve host", `7` for "Failed to connect").

#### Step 3. Edit the vault offline

Add a few entries — these all succeed locally without any
network access. Cardinal Principle 1 of Pangolin: edits MUST
succeed without connectivity.

```bash
pangolin-cli account add \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --name 'offline-entry-1' \
  --generate-password \
  --no-totp
```

```bash
pangolin-cli account add \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --name 'offline-entry-2' \
  --generate-password \
  --no-totp
```

Each `account add` succeeds and prints the new account id and
generated password as in Scenario 1 Step 2.

Confirm the dirty queue with `status` (still works offline —
`status` makes no chain calls):

```bash
pangolin-cli status \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse'
```

Expected:

```
dirty_count           2
account_count         3
```

#### Step 4. Attempt publish while disconnected

```bash
pangolin-cli publish \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --account poc-rehearsal
```

Expected: a non-zero exit code accompanied by an error message
referencing the RPC failure (e.g., a `ChainError::Rpc(...)`
wrapped in a context line). The exact message wording may
shift between releases; the load-bearing behavior is:

- The exit code is non-zero.
- No partial chain state is created.
- The dirty entries remain queued (next `status` still shows
  `dirty_count: 2`).

The keystore-password prompt may or may not fire before the
adapter detects the disconnect; either way, no entry lands on
chain.

#### Step 5. Reconnect

Re-enable your network. Verify connectivity:

```bash
curl -sS --max-time 5 https://sepolia.base.org -o /dev/null
echo "curl exit: $?"
```

Expected: `0`.

#### Step 6. Publish again

```bash
pangolin-cli publish \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' \
  --account poc-rehearsal
```

Expected:

```
publish summary: 2 published, 0 failed (out of 2 dirty entries)
  ok   <revision_id-1> block=<N> log=<M> seq=<K>
  ok   <revision_id-2> block=<N+0> log=<M+1> seq=<K+1>
```

(Both entries land in the same block or in close-by blocks
depending on chain timing.)

#### Step 7. Confirm the queue drained

```bash
pangolin-cli status \
  --vault-path ./tmp/pangolin-poc-vault-offline.pvf \
  --vault-password 'pangolin-poc-test-vault-do-not-reuse'
```

Expected:

```
dirty_count           0
account_count         3
```

The offline session's edits are now durably on the chain; a
non-author developer reproducing this scenario has confirmed
that Pangolin's offline-first contract holds end-to-end.

---

## Cleanup

After the rehearsal:

```bash
# Linux / macOS:
rm -rf ./tmp/

# Windows PowerShell:
Remove-Item -Recurse -Force .\tmp
```

If you generated a Live-mode keystore, also remove it:

```bash
# Linux / macOS:
rm ~/.foundry/keystores/poc-rehearsal

# Windows PowerShell:
Remove-Item $env:USERPROFILE\.foundry\keystores\poc-rehearsal
```

(Or, if you intend to run the rehearsal again later, leave the
keystore in place; just confirm it still has Base Sepolia ETH
via `cast balance ...`.)

The Base Sepolia chain itself retains the rehearsal's published
entries in perpetuity. They are tagged under your keystore's
address; a future rehearsal will see them via
`chaincli list --vault-id <hex>`. This is expected — the
RevisionLogV0 contract is append-only by design.

---

## Troubleshooting

The five most likely issues and their fixes:

1. **`cargo build` fails with "stable Rust 1.83+ required."**
   Install via [rustup](https://rustup.rs/) and run
   `rustup default stable`. Verify with `rustc --version`.

2. **`pangolin-cli account add` exits with "could not
   canonicalize vault path."** The vault file does not exist
   yet; you skipped the
   `pangolin-cli vault create --path <...> --password-stdin`
   step. Run it from the [Setup](#setup-shared) section, then
   retry.

3. **`pangolin-cli pull` exits with a `ChainError::Rpc(...)`
   message in Live mode.** Either the RPC URL is wrong or the
   network is unreachable. Verify connectivity:

   ```bash
   curl -sS https://sepolia.base.org \
     -X POST -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
   ```

   Expected: a JSON-RPC envelope with `"result":"0x14a34"` (=
   84532). If the curl command itself fails, the network is
   the issue; if curl succeeds but `pangolin-cli pull` still
   fails, the RPC URL flag may be wrong (default is
   `https://sepolia.base.org`; override via `--rpc-url <...>`
   or `BASE_SEPOLIA_RPC_URL`).

4. **`pangolin-cli publish` reports "publish summary: 0
   published, 1 failed" with an "insufficient funds" error.**
   The keystore address has no Base Sepolia ETH. Re-fund from
   a faucet (see [Live-mode safety](#live-mode-safety)) and
   wait for the drip to land (`cast balance` should report
   non-zero). Then retry.

5. **`cargo test --workspace --lib` prints fewer than ~395
   passing tests on Linux/macOS (or fewer than ~401 on
   Windows).** The build is on a stale tree or a feature flag
   is misconfigured. Run:

   ```bash
   git status
   git log -1 --oneline
   ```

   `git status` should show no modifications; `git log -1`
   should show `474de64` or a later main-branch commit. If
   not, you're on a feature branch with in-progress work; this
   reproducer is verified against `474de64`.

If your issue is not on this list, the docs may have a gap.
Capture the failing command, the exact error, and your shell /
OS version, and file an issue against the repository.
