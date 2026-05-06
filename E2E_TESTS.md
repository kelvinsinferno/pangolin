# E2E Test Scenarios

> Reproducible, step-by-step E2E scenarios for sync, conflict, recovery, and autofill paths.
> Per master plan §3.5 / §3.8: every issue that touches sync/conflict/recovery/autofill must add an entry here.
> A non-author developer must be able to reproduce each scenario from these instructions alone.

---

## Index

- **E2E-001 — RevisionLogV0 deployed-contract smoke test (Base Sepolia)** — issue P5-4
- **E2E-002 — chaincli debug oracle smoke test** — issue P6

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
