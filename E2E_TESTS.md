# E2E Test Scenarios

> Reproducible, step-by-step E2E scenarios for sync, conflict, recovery, and autofill paths.
> Per master plan §3.5 / §3.8: every issue that touches sync/conflict/recovery/autofill must add an entry here.
> A non-author developer must be able to reproduce each scenario from these instructions alone.

---

## Index

- **E2E-001 — RevisionLogV0 deployed-contract smoke test (Base Sepolia)** — issue P5-4
- **E2E-002 — chaincli debug oracle smoke test** — issue P6
- **E2E-003 — pangolin-cli two-vault sync round-trip** — issue P8
- **E2E-004 — pangolin-cli resolve convergence after fork+freeze** — issue P9
- **E2E-005 — pangolin-cli offline-edit-then-online-publish** — issue P10
- **E2E-006 — pangolin-cli account add → list → show → update → delete round trip** — issue P11A

---

## E2E-001: RevisionLogV0 deployed-contract smoke test (Base Sepolia)

**Issue:** P5-4
**Phase:** PoC
**Date added:** 2026-05-05
**Last verified:** 2026-05-05 by Claude Code on contract `0x8566D3de653ee55775783bD7918Fe91b66373896`

### Setup
1. Foundry installed and on PATH (`cast`, `forge`).
2. Read access to Base Sepolia RPC (default: `https://sepolia.base.org`; no key required, rate-limited).
3. For the write test (step 4): a Foundry keystore with the deployer wallet imported (e.g., `pangolin-dev`), or any other Base-Sepolia-funded wallet via `--private-key` or `--account`.

### Steps

1. **Read initial state** (no auth required):
   ```bash
   cast call 0x8566D3de653ee55775783bD7918Fe91b66373896 "nextSequence()" \
       --rpc-url https://sepolia.base.org
   ```
   **Expected:** `0x0000000000000000000000000000000000000000000000000000000000000000` (state at deploy is 0; this stays 0 until any caller publishes a revision).

   **Note:** if a previous smoke test already wrote, this number will be larger than 0. The smoke-test point is just to confirm the contract responds; the state value is whatever the chain currently reports.

2. **Verify event signature hash** (offline):
   ```bash
   cast keccak "RevisionPublished(bytes32,bytes32,bytes32,bytes32,uint8,uint256,bytes)"
   ```
   **Expected:** `0x6562412104cd03f86bf4f5184aa68e9d47cdb237b31b1de9d2fe1904eddcae8f`. This is the value that all `RevisionPublished` events on this contract use as `topics[0]`.

3. **Snapshot the contract balance** (it must remain 0 — the contract is non-payable):
   ```bash
   cast balance 0x8566D3de653ee55775783bD7918Fe91b66373896 --rpc-url https://sepolia.base.org
   ```
   **Expected:** `0` (always; the contract has no `payable` function, no `receive`, no `fallback`).

4. **Publish a test revision** (write — needs a funded wallet):
   ```bash
   cast send 0x8566D3de653ee55775783bD7918Fe91b66373896 \
       "publishRevision(bytes32,bytes32,bytes32,bytes32,uint8,bytes)" \
       0xaaaa000000000000000000000000000000000000000000000000000000000000 \
       0xbbbb000000000000000000000000000000000000000000000000000000000000 \
       0x0000000000000000000000000000000000000000000000000000000000000000 \
       0xcccc000000000000000000000000000000000000000000000000000000000000 \
       0 \
       0xdeadbeefdeadbeefdeadbeefdeadbeef \
       --rpc-url https://sepolia.base.org \
       --account pangolin-dev
   ```
   **Expected:**
   - Tx mines successfully (`status 1 (success)`)
   - Gas used ~30k–50k (depends on payload size; this 16-byte payload is on the low end)
   - Exactly one event log emitted at the contract address
   - Event log topic[0] = `0x6562412104cd03f86bf4f5184aa68e9d47cdb237b31b1de9d2fe1904eddcae8f`
   - Event log topic[1] = `0xaaaa…` (vaultId)
   - Event log topic[2] = `0xbbbb…` (accountId)
   - Event log topic[3] = `0x0000…` (parentRevision = genesis for first revision)
   - Event data carries `deviceId, schemaVersion, sequence, encPayload`

5. **Re-read state**:
   ```bash
   cast call 0x8566D3de653ee55775783bD7918Fe91b66373896 "nextSequence()" \
       --rpc-url https://sepolia.base.org
   ```
   **Expected:** previous value + 1. (i.e., if step 1 returned `0`, step 5 returns `1`. If step 1 returned `5`, step 5 returns `6`. The increment is the durable behavior under test.)

### Expected outcome (overall)

- Contract responds to read calls
- Write call mines successfully
- Event topics are correctly indexed (filterable via `eth_getLogs`)
- State increments deterministically by exactly 1 per `publishRevision` call
- Contract balance remains 0 throughout (rejects any ETH sent with the call)

### Failure modes covered

- **Wrong chain:** all `--rpc-url` strings explicitly use Base Sepolia. Running against any other chain would either fail (no contract at that address) or hit a different deployment. The chain id is implicit but verifiable: `cast chain-id --rpc-url https://sepolia.base.org` must return `84532`.
- **Stale state:** test #5 expects `prev + 1` (relative comparison, not absolute), so it correctly handles the case where prior smoke tests already advanced the counter.
- **Lost wallet:** any Base-Sepolia-funded wallet works for step 4. Replace `--account pangolin-dev` with `--private-key 0x...` or `--account <other-name>`.
- **Contract self-destruct:** impossible — contract has no `selfdestruct` opcode (verified at bytecode level in P5-1 audit).

---

## E2E-002: chaincli debug oracle smoke test

**Issue:** P6
**Phase:** PoC
**Date added:** 2026-05-06
**Last verified:** 2026-05-06 by Claude Code on contract `0x8566D3de653ee55775783bD7918Fe91b66373896`

### Setup

1. Toolchain: stable Rust 1.83+ (workspace pin).
2. Read access to Base Sepolia RPC (`https://sepolia.base.org`; no key required, rate-limited). The `BASE_SEPOLIA_RPC_URL` env var or the `--rpc-url` flag override the default.
3. For step 4 (write path): a Foundry keystore at `~/.foundry/keystores/<name>` (Linux/macOS) or `%USERPROFILE%\.foundry\keystores\<name>` (Windows) containing a Base-Sepolia-funded wallet — same setup as P5-4.
4. Build the binary once: `cargo build --release -p chaincli`.

### Steps

1. **Status sanity check** (zero-config; reads only):
   ```bash
   chaincli status
   ```
   **Expected:**
   ```
   deployment_file    : .../contracts/deployments/base-sepolia.json
   contract_address   : 0x8566d3de653ee55775783bd7918fe91b66373896
   deployer           : 0x89e720238a3913688cb0e025ef03a64539575c54
   deploy_block       : 41133000
   runtime_size_bytes : 443
   rpc                : https://sepolia.base.org
   abi_cross_check    : OK
   chain_id           : 84532  (expected: 84532)  OK
   bytecode_keccak    : 0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe  (expected: 0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe)  OK
   nextSequence       : <current value, ≥1 once any write has landed>
   ```
   The `abi_cross_check` line confirms the on-disk JSON ABI matches the binding chaincli compiled against (selectors + event topic-0). The `bytecode_keccak` line additionally hashes the live runtime bytecode at the recorded address (`eth_getCode`) and compares it to `bytecode.deployed_runtime_keccak256` from the deployment file — defense-in-depth against a tampered deployment file pointing at a foreign contract that happens to expose the same selectors.

2. **List the seed revision** (read-only):
   ```bash
   chaincli list \
       --vault-id 0xaaaa000000000000000000000000000000000000000000000000000000000000 \
       --from-block 41133000 \
       --to-block 41134000
   ```
   **Expected:** at least one JSON-Lines record containing
   `"tx":"0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6"` and
   `"payload_hex":"0xdeadbeefdeadbeefdeadbeefdeadbeef"` —
   the smoke-test revision recorded in `contracts/deployments/base-sepolia.json`.

3. **Dump that revision in detail**:
   ```bash
   chaincli dump --tx 0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6
   ```
   **Expected:**
   ```
   RevisionPublished event in block 41133109 of 0x8566D3de653ee55775783bD7918Fe91b66373896:
     vaultId           : 0xaaaa000000000000000000000000000000000000000000000000000000000000
     accountId         : 0xbbbb000000000000000000000000000000000000000000000000000000000000
     parentRevision    : 0x0000000000000000000000000000000000000000000000000000000000000000
     deviceId          : 0xcccc000000000000000000000000000000000000000000000000000000000000
     schemaVersion     : 0
     sequence          : 0
     encPayload (hex)  : deadbeefdeadbeefdeadbeefdeadbeef
     encPayload (b64)  : 3q2+796tvu/erb7v3q2+7w==
     payload_keccak256 : 0xc8c4a3521e03ff73772713f1dbcd8280039230d30a0d19221234001547c9180e
     log_index         : 155
     tx                : 0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6
   ```

4. **Publish a fresh revision** (write path; needs a funded wallet):
   ```bash
   chaincli publish \
       --vault-id 0xdddd000000000000000000000000000000000000000000000000000000000000 \
       --account-id 0xeeee000000000000000000000000000000000000000000000000000000000000 \
       --parent-revision 0x0000000000000000000000000000000000000000000000000000000000000000 \
       --device-id 0xffff000000000000000000000000000000000000000000000000000000000000 \
       --schema-version 0 \
       --payload-hex 0xcafebabe \
       --account pangolin-dev
   ```
   chaincli prompts:
   ```
   Enter password for keystore .../pangolin-dev:
   ```
   (The password is read from the terminal without echo. If chaincli is invoked with stdin redirected from a pipe, `rpassword` falls back to plain stdin — same as `cast`.)

   **Expected on success:**
   ```
   submitted: 0x<txhash>... — waiting for receipt...
   tx_hash      : 0x<txhash>
   block        : <block-number>
   from         : 0x<wallet-address>
   contract     : 0x8566D3de653ee55775783bD7918Fe91b66373896
   sequence     : <prev nextSequence value>
   vault_id     : 0xdddd...
   ...
   ```

5. **Re-run status to confirm state mutation**:
   ```bash
   chaincli status
   ```
   **Expected:** `nextSequence` is exactly one higher than it was after step 1.

### Expected outcome (overall)

- `status` works against the public Base Sepolia RPC with zero configuration.
- `list` filters events by `vaultId` and returns the seed revision.
- `dump` resolves a tx-hash to the underlying event and prints all 6 documented fields plus the dual-encoded payload (hex + base64).
- `publish` signs locally via Foundry keystore (no plaintext PK on disk/env/argv), broadcasts, waits for the receipt, and prints the assigned `sequence`.
- A subsequent `status` shows `nextSequence` incremented by exactly the number of `publish` calls in this run.

### Failure modes covered

- **Wrong chain:** `status` cross-checks `eth_chainId` against the deployment file's `chain.chain_id`; mismatch → non-zero exit with explicit message. `publish` re-checks before broadcasting.
- **Deployment-file tampering:** `abi_cross_check` compares function selectors and event topic-0 between the compiled `sol!` binding and the JSON ABI on disk; mismatch → non-zero exit with explicit message before any RPC call.
- **Wrong contract address:** `dump` rejects logs whose emitter address doesn't match the deployment file's `contract_address`.
- **Wrong keystore password:** alloy's eth-keystore returns a decryption error; chaincli surfaces it verbatim and exits non-zero. No retry loop in chaincli itself.
- **Adversary-controlled `encPayload`:** never decoded structurally. Printed as raw hex + base64. No CBOR decode path.
- **Public RPC range cap:** `eth_getLogs` is capped at 10_000 blocks per call; `chaincli list` chunks at 9_000 blocks/call automatically. Users do not need `--from-block`/`--to-block` unless they want to narrow.

### Automated equivalent

Steps 1–3 are mirrored as Cargo integration tests in
`tools/chaincli/tests/integration.rs`, gated behind the
`integration-tests` feature so the default `cargo test` does not hit
the network:

```bash
cargo test -p chaincli --features integration-tests --test integration
```

Step 4 (the write path) is NOT automated — it requires a funded
wallet and a real keystore-password prompt, both of which are
out-of-scope for an unattended test runner. Manual verification only.

---

## E2E-003: pangolin-cli two-vault sync round-trip

**Issue:** P8
**Phase:** PoC
**Date added:** 2026-05-06
**Last verified:** 2026-05-06 by automated tests
(`tools/pangolin-cli/tests/two_vault_roundtrip.rs`)

### Setup

1. Workspace toolchain ready: `cargo build -p pangolin-cli` succeeds.
2. Two empty directories on disk for the two vault files (or two
   different machines for the genuine two-device case — copy the
   `.pvf` between them via any out-of-band channel after step 1
   below).
3. For the chain-backed manual scenario: a Foundry keystore funded
   with Base Sepolia ETH (deployer wallet `pangolin-dev` or any
   keystore the user controls). The unattended `MockChainAdapter`
   path needs no funds.

### Steps (automated path — `MockChainAdapter`)

1. **Run the integration test:**
   ```bash
   cargo test -p pangolin-cli --test two_vault_roundtrip
   ```
   This runs three sub-scenarios in one process:
   - `convergence` — vault A publishes; vault B pulls; both end
     with a single chain-anchored head row on the shared account.
   - `symmetric_fork` — A and B make concurrent children of the
     same parent and both publish; both pull and both observe the
     same 2-head fork; `PullReport.forks` is non-empty on both
     sides.
   - `idempotent_repeat_pull` — `pull_all` twice in a row produces
     `applied = 0` on the second run and a stable
     `last_pulled_block`.

   **Expected:** `test result: ok. 3 passed; 0 failed`.

### Steps (manual path — Base Sepolia + funded keystore)

The automated path uses `MockChainAdapter` so it costs no gas and
needs no network. The manual path is for humans verifying the
production chain integration.

1. **Create vault A** (in `~/pangolin-test/A/`):
   ```bash
   # In a Rust shell or a small test harness — Vault::create is
   # exposed by `pangolin-store`. Pick any password; the same
   # password must be used for vault B because vault B is a copy.
   ```

2. **Add an account** (programmatically via `Vault::add_account`).
   Confirm `pangolin-cli status --vault-path ~/pangolin-test/A/v.pvf`
   reports `dirty_count: 1` and `account_count: 1`.

3. **Publish from A:**
   ```bash
   pangolin-cli publish \
       --vault-path ~/pangolin-test/A/v.pvf \
       --account pangolin-dev
   ```
   At the prompt, enter the vault password (then the keystore
   password). **Expected:** `publish summary: 1 published, 0 failed`.

4. **Confirm via chaincli:**
   ```bash
   chaincli list --vault-id <hex> --rpc-url https://sepolia.base.org
   ```
   The just-published revision should appear at the head of the
   chain log.

5. **Copy vault A's file to vault B's path** (`~/pangolin-test/B/`):
   ```bash
   cp ~/pangolin-test/A/v.pvf ~/pangolin-test/B/v.pvf
   ```
   (Or copy across machines via any channel — the file is fully
   self-contained.)

6. **Pull on vault B:**
   ```bash
   pangolin-cli pull \
       --vault-path ~/pangolin-test/B/v.pvf \
       --rpc-url https://sepolia.base.org
   ```
   **Expected:** `pull summary: 1 new events ingested; …; 0 forked
   account(s)`. Idempotent: re-running the same command immediately
   returns `applied = 0`.

7. **Verify convergence via status:**
   ```bash
   pangolin-cli status --vault-path ~/pangolin-test/B/v.pvf
   ```
   Both vaults should report the same `last_published_block` and
   `dirty_count: 0`.

8. **Concurrent-edit fork scenario** (optional):
   - Update the account on A (e.g., `Vault::update_account(...)`),
     publish.
   - Update the same account on B, publish.
   - Pull on both.
   - **Expected:** both A and B's `pangolin-cli status` shows a
     2-head fork via the per-account head listing. `PullReport.forks`
     is non-empty on both. P9 (`pangolin-cli resolve …`, future
     issue) handles the resolution.

### Expected outcome

- The `MockChainAdapter` path runs in under 60 seconds and exits 0.
- The Base Sepolia path completes in roughly 30 seconds per network
  round-trip (chain-id check + 9 000-block-windowed pull). Forks
  are reported but not auto-resolved.

### Failure modes covered

- **Process killed mid-publish.** A re-run of `pangolin-cli publish`
  triggers the A3 pre-publish check; the canonical-hash matches an
  on-chain event and the local commit (`mark_published` +
  `clear_dirty`) runs without a duplicate `publish` call. Verified
  by the unit test
  `sync::tests::publish_idempotent_on_rerun_after_partial_failure`.
- **RPC flake mid-pull.** Per-chunk checkpoint advancement preserves
  prior chunks' progress; re-running `pull` resumes from the new
  `last_pulled_block`. Verified by
  `sync::tests::pull_chunk_failure_preserves_prior_chunk_progress`.
- **Forged-event-stream from compromised RPC.** Every event passes
  a `VerifyingKey::from_bytes` check on its `device_id` before
  being persisted; non-canonical bytes are rejected. Verified
  structurally in `sync::pull_all`'s loop body and asserted by the
  defense-in-depth check in `signing::verify_signed_revision`.

---

## E2E-004: pangolin-cli resolve convergence after fork+freeze

**Issue:** P9
**Phase:** PoC
**Date added:** 2026-05-07
**Last verified:** 2026-05-07 by automated tests
(`tools/pangolin-cli/tests/two_vault_roundtrip.rs::convergence_after_resolve`)

### Setup

1. Workspace toolchain ready: `cargo build -p pangolin-cli`
   succeeds.
2. Two empty directories for the two vault files (or two devices
   sharing the cloned `.pvf` over any out-of-band channel).
3. For the chain-backed manual scenario: a Foundry keystore funded
   with Base Sepolia ETH. The unattended `MockChainAdapter` path
   needs no funds.

### Steps (automated path — `MockChainAdapter`)

1. **Run the integration test:**
   ```bash
   cargo test -p pangolin-cli --test two_vault_roundtrip \
       convergence_after_resolve
   ```

   Sub-scenario:
   - A creates an account, copies the vault file to B
     (`clone_vault_file`), publishes via `MockChainAdapter`.
   - B opens the cloned file and pulls. Under the PoC two-key
     model the foreign device_id triggers the CRIT-1 freeze
     sentinel: `Vault::list_frozen_accounts()` lists the account.
   - B runs `pangolin_cli::sync::resolve_one(...)` with `--keep`
     pointing at B's local genesis row (the one with a
     plaintext-recoverable nonce, NOT the foreign-ingested row
     with the placeholder zero nonce). Resolve succeeds end-to-end:
     plaintext re-seal under merge AAD, build SignedRevision,
     publish, ingest, clear_frozen.
   - Final assertions: B's freeze flag is CLEAR
     (`list_frozen_accounts` does not contain the account); the
     chain now has at least 2 events (A's original publish + B's
     merge); A's pull post-B-resolve sees both rows.

   **Expected:** `test result: ok. 4 passed; 0 failed`.

### Steps (manual path — Base Sepolia + funded keystore)

The automated path uses `MockChainAdapter` so it costs no gas.
The manual path is for humans verifying the production chain
integration.

1. **Run E2E-003 steps 1–6.** Vault A creates an account, copies
   to B, publishes; B pulls and observes the freeze.

2. **Run resolve on B:**
   ```bash
   pangolin-cli resolve \
       --vault-path ~/pangolin-test/B/v.pvf \
       --account-id <hex-32-bytes-of-the-frozen-account> \
       --keep <hex-32-bytes-of-Bs-local-genesis-revision-id> \
       --account pangolin-dev \
       --yes
   ```
   At the prompt, enter the vault password (then the keystore
   password). **Expected:** `resolve summary: published merge
   revision <hex> at block <n> log <m> seq <k>`.

3. **Confirm the freeze cleared** by re-running pull on B:
   ```bash
   pangolin-cli pull --vault-path ~/pangolin-test/B/v.pvf
   ```
   The pull summary's `frozen account(s)` count is now 0.

4. **Pull on A** to bring A's view current with B's merge:
   ```bash
   pangolin-cli pull --vault-path ~/pangolin-test/A/v.pvf
   ```
   Under PoC two-key A's pull will surface the merge revision
   as a freeze on A — the multi-resolve pattern (P9 plan §A4)
   handles this by A running its own resolve next. Full
   single-head convergence across N devices requires MVP-1's
   single-key model (D-006).

5. **Dry-run example:**
   ```bash
   pangolin-cli resolve \
       --vault-path ~/pangolin-test/A/v.pvf \
       --account-id <hex> --keep <hex> \
       --account pangolin-dev \
       --dry-run
   ```
   **Expected:** prints `dry run: would publish merge revision
   <hex>` without making any chain calls or clearing the freeze
   flag.

### Expected outcome

- The `MockChainAdapter` path runs in under 60 seconds and exits 0.
- The Base Sepolia path completes in roughly 30 seconds per round-
  trip (publish + ingest + clear_frozen). Multi-resolve for full
  convergence across N devices is documented as expected PoC
  behavior.

### Failure modes covered

- **Chain moves between user invocation and pre-publish re-pull.**
  Q7's pre-publish re-pull detects new heads and surfaces
  `ResolveError::ChainMovedDuringResolve` so the user re-runs
  against the freshest heads. Verified by
  `sync::tests::resolve_chain_moved_during_resolve_aborts_cleanly`.
- **Process killed mid-resolve.** Re-running with the same
  `--keep` returns `NotAHead` (the merge superseded the chosen
  revision) — no chain side effects, no local-store corruption.
  Verified by `sync::tests::resolve_idempotent_after_partial_failure`.
- **Publish RPC error.** Freeze flag remains set; the user
  retries. Verified by
  `sync::tests::resolve_fails_cleanly_on_publish_error`.
- **`--dry-run`.** No chain side effects; freeze flag unchanged.
  Verified by `sync::tests::dry_run_does_not_publish_or_clear`.

---

## E2E-005: pangolin-cli offline-edit-then-online-publish

**Issue:** P10
**Phase:** PoC
**Date added:** 2026-05-07
**Last verified:** 2026-05-07 by automated tests
(`tools/pangolin-cli/tests/offline_mode.rs::offline_edit_then_online_publish`)

### Setup

1. Workspace toolchain ready: `cargo build -p pangolin-cli`
   succeeds.
2. One empty directory for the vault file.
3. For the chain-backed manual scenario: a Foundry keystore funded
   with Base Sepolia ETH. The unattended `MockChainAdapter` path
   needs no funds (the disconnect toggle is mock-only — production
   chain disconnect is observable via real `ChainError::Rpc`).

### Steps (automated path — `MockChainAdapter`)

1. **Run the integration test:**
   ```bash
   cargo test -p pangolin-cli --test offline_mode \
       offline_edit_then_online_publish
   ```

   Sub-scenario:
   - Connect; create + publish initial account. Chain has 1 event.
   - `set_disconnected(true)`. Add 5 accounts, update one, delete
     one (writes a P10-1 widened tombstone payload). All edits
     succeed locally; `Vault::list_dirty()` returns the queued
     entries.
   - `publish_all` while disconnected: every per-entry attempt
     errors with `ChainError::Rpc`; dirty markers PRESERVED;
     `list_frozen_accounts()` empty (no chain ingest happened, so
     the freeze sentinel cannot fire).
   - `set_disconnected(false)` (reconnect). `publish_all` succeeds
     for every queued entry; chain now has at least 8 events
     (1 initial + 5 add + 1 update + 1 delete).
   - Final: `list_dirty()` empty; `list_accounts().len() == 5`
     (genesis + 5 added - 1 tombstoned).

   **Expected:** `test result: ok. 3 passed; 0 failed`.

### Steps (manual path — Base Sepolia + funded keystore + real network outage)

The automated path uses `MockChainAdapter` so it costs no gas. The
manual path is for humans verifying the production chain
integration.

1. **Connected: publish initial state.**
   ```bash
   pangolin-cli publish \
       --vault-path ~/pangolin-test/v.pvf \
       --account pangolin-dev
   ```
   Add an account first via the host application (or directly via
   `pangolin-store`'s `add_account` API; the CLI does not currently
   expose an `add` subcommand — that's MVP-1 polish).

2. **Disconnect from the network.** Either kill the local network
   interface, switch to a network without internet, or stop the
   local RPC. Real-world reproduction.

3. **Edit the vault offline.** Add / update / delete accounts via
   the host app. Each edit succeeds locally (Cardinal Principle 1
   — edits MUST succeed without network).

4. **Attempt publish while disconnected:**
   ```bash
   pangolin-cli publish \
       --vault-path ~/pangolin-test/v.pvf \
       --account pangolin-dev
   ```
   **Expected:** the CLI surfaces `ChainError::Rpc(...)` from the
   `BaseSepoliaAdapter::with_signer` `eth_chainId` precheck and
   exits non-zero. No partial chain state. Dirty markers
   preserved.

5. **Reconnect.** Restore the network.

6. **Re-run publish.**
   ```bash
   pangolin-cli publish \
       --vault-path ~/pangolin-test/v.pvf \
       --account pangolin-dev
   ```
   **Expected:** every queued entry lands. The publish summary
   reports the per-account success count. Dirty list is now empty.

7. **Verify with status:**
   ```bash
   pangolin-cli status \
       --vault-path ~/pangolin-test/v.pvf
   ```
   `dirty_count` is 0; `account_count` reflects the offline-session
   net change.

### Expected outcome

- The `MockChainAdapter` path runs in under 60 seconds and exits 0.
- The Base Sepolia path completes per offline-session edits + one
  reconnect-publish round-trip; ~30-60 seconds for the publish
  flush depending on the offline edit count.

### Failure modes covered

- **Publish-while-disconnected.** `ChainError::Rpc` is the surface;
  dirty markers persist; user retries on reconnect. Verified by
  `offline_mode::offline_edit_then_online_publish`.
- **Empty dirty list while disconnected (lib-layer no-op).** The
  `sync::publish_all` library entry point is idempotent on an
  empty dirty list — the chain-view precheck failure is non-fatal
  (the loop body sees `chain_view = None` and proceeds). The user-
  facing `pangolin-cli publish` subcommand DOES require
  connectivity for the underlying adapter constructor to succeed,
  so the binary boundary preserves the §A7 invariant. Verified by
  `offline_mode::offline_publish_with_no_dirty_entries_is_noop_at_lib_layer`.
- **No freeze sentinel during offline session.** The freeze
  sentinel is set inside `Vault::ingest_chain_revision`'s
  genuine-foreign-INSERT branch; that function is only invoked by
  `sync::pull_all`, which fails before reaching it on a
  disconnected adapter. Verified by
  `offline_mode::offline_session_does_not_set_freeze_sentinel`.
- **Offline edits cannot be replayed by another device.** The
  dirty markers live inside the encrypted `.pvf` file; another
  device with the same `.pvf` (cross-vault under PoC two-key) sees
  the same markers, but its `device_id` differs from the original
  device's, so any publish from the second device produces an
  event whose `canonical_hash` differs and lands as a co-fork
  rather than a silent duplicate. THREAT_MODEL row #20 documents
  this thoroughly.

---

## E2E-006: pangolin-cli account add → list → show → update → delete round trip

**Issue:** P11A
**Phase:** PoC
**Date added:** 2026-05-07
**Last verified:** 2026-05-07 by Claude Code via the
`account_lifecycle.rs` integration test on a fresh tempdir
vault (MockChainAdapter not required — account ops are
local-vault-only).

### Setup
1. A scratch directory for the vault file (`.pvf`).
2. The `pangolin-cli` binary built from
   `tools/pangolin-cli/`. The integration test under
   `tools/pangolin-cli/tests/account_lifecycle.rs` drives
   the flow without invoking the binary directly — it
   imports the public library entry points
   (`pangolin_cli::commands::account::*`,
   `pangolin_cli::cli::*`) per the same pattern as
   `two_vault_roundtrip.rs` and `offline_mode.rs`.

### Steps (automated path — `account_lifecycle.rs`)

1. **Create** a fresh `.pvf` vault via `Vault::create`
   under a scratch tempdir.
2. **Add** an account via `commands::account::run_add`
   with `--generate-password` + `--no-totp` + a
   non-empty `--name`. Capture the `account_id` returned
   (the test re-opens the vault to read it).
3. **List** via `commands::account::run_list` with no
   include flags. Assert the just-added entry appears.
4. **Show (no reveal)** via `commands::account::run_show`
   without any `--reveal-*` flag. Assert the call
   succeeds (the test seam ensures no presence prompt is
   needed since no reveal is requested).
5. **Show (reveal-password)** at the library layer:
   verify `Vault::reveal_password(id, &fresh_proof)`
   returns the expected bytes. (The CLI-level reveal
   path requires interactive `'y'` input and is covered
   by the unit-test seam in `account.rs::tests`.)
6. **Update** via `commands::account::run_update` with
   the `WithAutoConfirm` test seam enabled, modifying
   `--name` only. Assert the new display name is in
   place AND the password / notes / TOTP carry through
   unchanged.
7. **Delete** via `commands::account::run_delete` with
   `--yes`. Assert the row is now in
   `Vault::list_tombstoned_accounts()` and absent from
   `Vault::list_accounts()`.
8. **Delete-replay refused.** Re-run `run_delete` against
   the same id; assert it fails with the "already been
   deleted (tombstoned)" message.
9. **Show on tombstoned id surfaces the deleted-message**
   not "not found". Assert the error message includes
   "deleted" or "tombstoned".

### Expected outcome
- Each step succeeds at the library layer.
- The dirty list contains exactly the expected revision
  count for the account at the end of step 7 (the
  collapsed-by-account_id semantics of
  `INSERT OR IGNORE INTO dirty_accounts` may keep the
  count at 1; the structural assertion is "the account
  is in the dirty set after every mutating call").
- No plaintext leaks via stdout when no `--reveal-*`
  flag is set — verified by inspection of `run_show`'s
  default branch (only identifier-class fields are
  printed).
- The test runs end-to-end in under 10 seconds on the
  CI host.

### Failure modes covered
- **Auto-resurrection refused.** Step 8 covers Cardinal
  Principle 4: a re-delete on a tombstoned row is
  refused with a clear error rather than silently
  succeeding (which would mask user error).
- **Frozen-account write refusal.** Not exercised by
  this happy-path scenario directly (would require
  ingesting a foreign chain event mid-flow); covered
  by the underlying library tests
  (`update_refuses_frozen_account`,
  `delete_refuses_frozen_account`) and by the
  pre-presence guard in `run_update` / pre-prompt
  guard in `run_delete`.
- **Frozen + tombstoned filtering by default in `list`.**
  Implicitly covered: step 3 lists only the active
  entries; after step 7's tombstone, step 9's `show`
  surfaces the deleted-message rather than re-finding
  the entry.
- **Identifier surface secret-omission.** Verified
  structurally by the `ListRow` struct having no
  password / notes / `totp_secret` fields
  (`list_row_omits_secret_fields_structurally`); E2E-006
  inherits this invariant from the unit tests.

### Automated equivalent
`tools/pangolin-cli/tests/account_lifecycle.rs`

---

## Template

```
## <ID>: <scenario name>

**Issue:** <issue id>
**Phase:** <PoC | MVP-2 | MVP-3 | etc.>
**Date added:** YYYY-MM-DD
**Last verified:** YYYY-MM-DD by <executor>

### Setup
1. ...

### Steps
1. ...

### Expected outcome
- ...

### Failure modes covered
- ...
```
