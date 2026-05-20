# anvil-fork CI harness (issue #101)

> **Scope:** Issue #101 — an additive CI job + a `scripts/anvil-ci.sh`
> wrapper that boots a local `anvil` node, deploys our REAL contract
> bytecode to it, generates `contracts/deployments/dev.json`, funds the
> deterministic test wallet, and runs a curated subset of the
> `#[ignore]`'d live tests against it on every PR.
>
> Companion docs: `chain-submit.md` (the broadcast layer), `signing.md`
> (the EIP-712 v1 signing path), `pull-loop.md` (the pull cycle).

## Why this exists (env-quirk #14)

The hermetic test suite cannot catch contract-side semantics bugs in the
Rust↔contract calldata seam: `MockTransport` fabricates receipts without
re-running the contract's hash/signature logic. The MVP-2 issue 3.3
builder shipped a load-bearing bug — submitting the 32-byte
`enc_payload_hash` as the `encPayload` calldata argument instead of the
raw preimage — that **passed the full hermetic suite** and was caught
only by adversarial audit. The contract's `_hashRevision` recomputes
`keccak256(encPayload)` from the calldata bytes, so passing the hash
means it computes `keccak256(hash) ≠ hash` → `_recover` returns the wrong
signer → `ErrInvalidSignature` revert on every live publish.

MVP-3 (Social Recovery) adds a NEW on-chain contract whose Rust client
builds calldata for its calls + decodes its events — the same bug class.
#101 boots a local node running the actual deployed bytecode and runs
the curated live tests against it, so that bug class turns CI **RED
automatically** before the Recovery contract iterates.

## What it runs

`scripts/anvil-ci.sh all` (the CI entry) does, in order:

1. **start anvil** — `anvil --silent` (chain-id 31337, port 8545), then
   POLL `cast block-number` for readiness (bounded max-attempts,
   fail-closed; never a fixed sleep — L5). A `trap` tears anvil down on
   any exit.
2. **deploy** RevisionLogV1 + EntitlementRegistry via the existing forge
   scripts (`--broadcast --private-key <anvil acct[0] public test key>`;
   EntitlementRegistry's authorities are dummy addrs — no real money
   flows on a local chain).
3. **parse** the fresh addresses + deploy-blocks from the structured
   broadcast artefact `contracts/broadcast/<Script>.s.sol/31337/run-latest.json`
   via `jq` (the human `forge script` log has no `Contract Address:`
   line on the anvil path — parse `.transactions[].contractAddress` +
   `.receipts[].blockNumber`, NOT the log).
4. **generate** `contracts/deployments/dev.json` in the shape
   `pangolin_chain::deployments::load_deployed_address` walks
   (`.contracts.<Name>.address`) plus a `deploy_block` for RevisionLogV1.
   Runtime-generated, never committed (R-e; `.gitignore`d).
5. **fund** the test wallet — the in-scope tests sign with
   `fixed_wallet()` (seed `[0x42;32]`). The harness resolves its EVM
   address via the `print_fixed_wallet_address` helper test, then
   `cast rpc anvil_setBalance <addr> 0xDE0B6B3A7640000` (1 ETH) so its
   publish tx (gas payer == signer per D-006) succeeds.
6. **run** the 3 in-scope tests in dev mode (`PANGOLIN_CHAIN_ENV=dev`,
   `BASE_SEPOLIA_RPC_URL=http://127.0.0.1:8545`).
7. **teardown** anvil (the trap also fires on any earlier failure).

## In-scope tests (first cut — R-a)

The direct env-quirk #14 surface (calldata build + event decode against
real bytecode):

| Test | Crate / file | What it proves against anvil |
|---|---|---|
| `publish_v1_live_d017_smoke` | `pangolin-chain` lib (`chain_submit.rs`, `integration-tests` feature) | The real contract `_recover` accepts the EIP-712 signature — the exact 3.3 surface. |
| `live_pull_once_against_d017_advances_checkpoint` | `pangolin-store` (`tests/pull_live.rs`) | The slow-mode pull cycle reads the real node + advances the monotonic checkpoint. |
| `live_balance_query_against_d017_wallet` | `pangolin-chain` (`tests/integration.rs`) | The `eth_getBalance` roundtrip + non-zero assertion against the funded wallet. |

Deferred (R-a Option B / follow-ups): indexer/conflict/sync tests
(need self-generated seed events); funder top-up tests (need the
funder service in CI); Recovery v1's own anvil tests (land with the
contract); time-warp testing for finalize-after-delay; multi-OS anvil.

## The test seam (`crates/pangolin-chain/src/test_env.rs`, R-b)

Rather than fork the tests into anvil-only duplicates, the existing
`#[ignore]` tests read a thin seam:

- `target_chain_env()` — `PANGOLIN_CHAIN_ENV=dev` → `ChainEnv::Dev`;
  unset / anything else → `ChainEnv::BaseSepolia` (default keeps the
  pre-#101 human-run posture).
- `rpc_url()` — `BASE_SEPOLIA_RPC_URL`, defaulting to the local anvil
  endpoint in dev mode and the public Base Sepolia endpoint otherwise.
- `resolve_signing_chain_id(env, rpc_url)` — the chain id to bind into
  the EIP-712 domain + the tx envelope (see "scoped signing change").
- `require_or_fail(reason)` — the **L6** gate: clean-skip in
  base-sepolia mode (`return false`), HARD `panic!` in dev mode.

The seam is gated to test / test-utilities / integration-tests builds;
it is never compiled into a production binary (L1).

### L6 — skip becomes a hard error in dev mode (load-bearing)

The pre-#101 live tests `return` early ("SKIP") when their env vars are
unset, so default CI never reaches the network. That posture is
**retained for base-sepolia mode**. But in **dev mode** a missing
`dev.json` / RPC / env var is a HARD failure — the 3.3 bug "passed"
precisely because its live test skipped. `require_or_fail` panics in dev
mode; the balance test `assert!`s on its required env var.

## The scoped signing change (#101 amendment)

The publish test could not pass against anvil because the signing path
hardcoded chain-id `84_532` (the EIP-1559 envelope) and `unwrap_or(0)`
(the EIP-712 domain), while anvil is `31337` and the deployed contract
bakes `block.chainid` into its `_DOMAIN_SEPARATOR`. The fix threads an
explicit `chain_id: u64`:

- `secp256k1_signing::build_domain(verifying_contract, chain_id)` — was
  `env.chain_id().unwrap_or(0)`, now takes the id.
- `build_signed_revision_v1(..., chain_id)`,
  `recover_signer_v1[_raw](..., chain_id)`,
  `Vault::sign_revision_v1(..., chain_id)` — thread it through.
- `chain_submit.rs`: a new `resolve_envelope_chain_id(provider, env)`
  replaces the hardcoded `signed_revision_chain_id()` for all three
  EIP-1559 broadcast paths (publish / redemption / eth-transfer).

**Caller resolves the id:**

- `env.chain_id()` is `Some` (BaseSepolia → `84_532`): use the **pinned**
  value, UNCHANGED. `resolve_envelope_chain_id` reads `eth_chainId` ONLY
  to cross-check it (the pre-existing L-rpc-spoof guard) and returns the
  pinned id — a lying RPC is rejected, it can never steer the envelope.
- `env.chain_id()` is `None` (Dev / local anvil): read the live
  `eth_chainId` from the connected (trusted, local) node.

**Invariants held:** `Dev.chain_id()` STAYS `None` (the enum +
`chain_env_chain_ids_are_pinned` test are untouched — L2). BaseSepolia
signing is byte-identical: the hermetic pins
(`DOMAIN_SEPARATOR_BASE_SEPOLIA_V1`, `REVISION_TYPEHASH_V1`, the 3.6
baseline-signature pin) pass `84_532` explicitly, producing bytes
identical to the pre-#101 form. Production NEVER sources its signing
chain id from an untrusted RPC — only the Dev/local-anvil path does.

## L1..L9 invariants

- **L1** Production-code change LIMITED to the scoped signing chain-id
  threading; everything else is test/CI-only.
- **L2** BaseSepolia pins stay byte-identical green; `Dev.chain_id()`
  enum + test untouched.
- **L3** Existing CI jobs untouched; `anvil-integration` is additive.
- **L4** Foundry pinned at `v1.0.0` (same as the contracts jobs).
- **L5** Deterministic: poll-for-ready, `trap`-teardown, fail-closed on
  deploy/parse failure.
- **L6** Skip → hard error in dev mode.
- **L7** No new `=`-pinned external Rust dep (anvil/forge/cast are
  binaries).
- **L8** `forbid(unsafe_code)` + AGPL SPDX on the new script + seam.
- **L9** The regression-proof: a deliberately-broken publish calldata
  (the 3.3 hash-instead-of-preimage shape) MUST turn the publish test
  RED against anvil. Verified at build time (contract recovered a
  different signer → `ReceiptMismatch`), then reverted.

## Running it locally

```bash
# Requires anvil/forge/cast on PATH (foundry-toolchain@v1 / v1.0.0) + jq.
bash scripts/anvil-ci.sh all
```

Or run a single in-scope test against your own anvil:

```bash
PANGOLIN_CHAIN_ENV=dev BASE_SEPOLIA_RPC_URL=http://127.0.0.1:8545 \
  cargo test -p pangolin-chain --features integration-tests \
  publish_v1_live_d017_smoke -- --ignored --nocapture
```
