# E2E Test Scenarios

> Reproducible, step-by-step E2E scenarios for sync, conflict, recovery, and autofill paths.
> Per master plan §3.5 / §3.8: every issue that touches sync/conflict/recovery/autofill must add an entry here.
> A non-author developer must be able to reproduce each scenario from these instructions alone.

---

## Index

- **E2E-001 — RevisionLogV0 deployed-contract smoke test (Base Sepolia)** — issue P5-4

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
