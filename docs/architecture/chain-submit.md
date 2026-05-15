# Direct-submit transport (v1)

> **Scope:** MVP-2 issue 3.3 — Rust-side broadcast layer that turns a
> 3.1 `SignedRevisionV1` + a 3.2 session-bounded `EvmWallet` into a
> live `publishRevision` call against D-017 on Base Sepolia. Returns a
> `ChainAnchorV1` carrying the tx hash + block + sequence + signer.
>
> Companion docs: `signing.md` (Ed25519 v0 + secp256k1 v1 signing) and
> `chain-revision-log-v1.md` (the contract spec).

## Caller flow (sync → async boundary)

```text
                ┌─────────────────────────────────────────┐
                │       caller (CLI / GUI / FFI host)     │
                │                                         │
                │  let vault: Vault   = unlock(...)       │
                │                                         │
                │  // both calls are sync; Vault is sync  │
                │  let signed: SignedRevisionV1           │
                │      = vault.sign_revision_v1(...)      │
                │  let wallet: &EvmWallet                 │
                │      = vault.evm_wallet()?              │
                │                                         │
                │  // hop to async + broadcast            │
                │  let anchor: ChainAnchorV1              │
                │      = publish_revision_v1(             │
                │            wallet,                      │
                │            &signed,                     │
                │            ChainEnv::BaseSepolia,       │
                │            rpc_url,                     │
                │        ).await?                         │
                │                                         │
                │  store.mark_published(anchor, ...)?     │
                └─────────────────────────────────────────┘
```

- The signing leg is **sync** (3.1 R-d preserved — `Vault::sign_revision_v1`
  doesn't go async).
- The broadcast leg is **async-only on `pangolin-chain`** (3.3 R-d) — no
  `Vault::publish_revision_v1` wrapper exists; the caller hops to async
  itself.
- The wallet reference (`&EvmWallet`) is obtained via `Vault::evm_wallet()`,
  which calls `require_active()` and refuses on locked / expired sessions
  (3.2 L5 enforced).

## Resolved decisions (R-a..R-f)

| # | Decision | Implementation site |
|---|---|---|
| R-a | Fetch nonce via `eth_getTransactionCount(addr, "pending")` immediately before tx construction; no local cache. Nonce-collision retry re-fetches once. | `chain_submit::broadcast_with_retries`, in-loop `provider.get_transaction_count(addr).pending()` |
| R-b | EIP-1559: `maxFeePerGas = 2 × baseFeePerGas + maxPriorityFeePerGas`; `maxPriorityFeePerGas = 1 gwei`. Hard cap 50 gwei → fail with `GasCapExceeded`. | `chain_submit::{MAX_FEE_PER_GAS_CAP_WEI, PRIORITY_FEE_DEFAULT_WEI}` |
| R-c | Retry taxonomy verbatim — see table below. | `broadcast_with_retries` + classifier helpers (`is_nonce_collision`, `is_transient_rpc_error`, `is_insufficient_funds`, `decode_revert_reason_from_msg`) |
| R-d | Async-only `pub async fn publish_revision_v1(...)` on `pangolin-chain`; `Vault` stays sync. | `chain_submit::publish_revision_v1` |
| R-e | Await receipt via `PendingTransactionBuilder::get_receipt`; verify `status == 1`; decode `RevisionPublished`; populate `ChainAnchorV1`. Receipt-decode mismatch → `ReceiptMismatch`. | `chain_submit::process_receipt` |
| R-f | Hermetic CI via alloy `MockTransport` + `Asserter`; calldata-pinned test; one `#[ignore]`'d live test against D-017. | `chain_submit::tests::*` |

## Retry taxonomy (R-c)

| Failure class | Disposition | Bound |
|---|---|---|
| **Nonce collision** ("nonce too low", "already known", "replacement underpriced") | Retry: refresh nonce + resubmit | 3 attempts total; then `ChainError::NonceUnresolvable { attempts }` |
| **RPC transient** ("timeout", "connection reset", 502/503/504, "service unavailable") | Retry with exponential backoff | 250 ms / 1 s / 4 s schedule; then `ChainError::RpcTransient { message, attempts }` |
| **Insufficient funds** ("insufficient funds for gas * price") | Fatal — no retry | `ChainError::InsufficientFunds` |
| **Contract revert** (receipt.status == 0) | Fatal — no retry | `ChainError::RevertedV1 { reason, tx_hash }` with reason decoded (when possible) as `ErrInvalidSignature` / `ErrSignerNotRegistered` / `ErrUnsupportedSchemaVersion` / `OutOfGas` / `"unknown revert"` |
| **Pre-broadcast revert** (eth_estimateGas reverts) | Fatal — no retry; reason decoded | Same as above; `tx_hash = B256::ZERO` since the tx never broadcast |
| **Chain id mismatch** | Fatal at construction | `ChainError::ChainIdMismatch { expected, observed }` |
| **Deployment address mismatch** | Fatal at construction | `ChainError::DeploymentAddressMismatch { env, expected, actual }` |
| **Gas-cap exceeded** | Fatal pre-broadcast | `ChainError::GasCapExceeded { observed_gwei, cap_gwei }` |
| **Receipt mismatch** (event's `signer` != wallet's address) | Fatal post-broadcast | `ChainError::ReceiptMismatch { expected_signer, observed_signer }` |

## L1..L12 invariants

1. **Sig pass-through:** the 65-byte `r ‖ s ‖ v` bytes from 3.1 are written into the tx calldata verbatim. No `v` normalisation, no offset shift, no re-signing.
2. **Same key signs + pays gas (D-006):** the wallet handed to `publish_revision_v1` is the same wallet 3.1 used to sign. After the publish lands, the contract recovers `signer == wallet.address()`; the receipt cross-check `decoded.signer == wallet_address` enforces this client-side too.
3. **Calldata byte-pinned:** `tests::publish_v1_calldata_byte_pin` asserts the encoded `publishRevision(...)` bytes match a `cast calldata`-derived reference. Selector `0x91f6be2f` is independently pinned by `tests::publish_v1_selector_matches`.
4. **Address via `load_deployed_address` + pinned cross-check:** the public entry calls `load_deployed_address(env, "RevisionLogV1")` and cross-checks against `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA` for `BaseSepolia`. Mismatch → `DeploymentAddressMismatch`.
5. **Active-session-only:** the only way to obtain an `&EvmWallet` is via `Vault::evm_wallet()`. The publish fn takes the reference by argument (no static / `OnceCell` cache).
6. **Gas-price hard cap 50 gwei:** computed `max_fee_per_gas > MAX_FEE_PER_GAS_CAP_WEI` → `GasCapExceeded` before any tx is constructed.
7. **Dep direction preserved:** `pangolin-chain` does NOT depend on `pangolin-store`. The new `chain_submit` module imports only from `crate::{deployments, error, evm, secp256k1_signing}` + alloy + tokio.
8. **No new external crate:** alloy / k256 / tokio were already in tree; no Cargo.toml additions.
9. **`forbid(unsafe_code)`** preserved.
10. **AGPL-3.0-or-later SPDX header** on the new `chain_submit.rs`.
11. **Hermetic-CI dominant:** 19 unit tests run on every CI invocation. The `publish_v1_live_d017_smoke` test is `#[ignore]`'d behind `--features integration-tests` + `BASE_SEPOLIA_RPC_URL` env.
12. **Replay protection on retry:** the broadcast leg (`broadcast_with_retries`) retries only `eth_sendRawTransaction` failures BEFORE `send_transaction` returns success. Once a `PendingTransactionBuilder` is returned (tx hash captured), no further re-broadcast happens — the receipt-await path runs to completion or surfaces an `Rpc` error. The on-chain `_nextSequence` advance is idempotent-bound by the tx's nonce, so a hypothetical RPC double-submit is rejected by the mempool's "already known" path (which is itself classified as nonce-collision-retriable, with a 3-attempt ceiling).

## Adversarial threat surface (L-section)

| Threat | Defense |
|---|---|
| **L-gas-griefing** — malicious RPC reports huge `baseFeePerGas` to drain the wallet | L6 hard cap; observed > cap → `GasCapExceeded` |
| **L-rpc-spoof** — malicious RPC fakes the receipt / fakes the event fields | (a) chain-id cross-check at construction; (b) emitter-address filter on log lookup (MED-4 defense from v0); (c) post-receipt cross-check that `event.signer == wallet.address()` → `ReceiptMismatch` |
| **L-nonce-collision-DoS** — stuck pending tx blocks the wallet | Bounded retries (3); `NonceUnresolvable` after exhaustion. Tx replacement / cancel-tx deferred to MVP-3 |
| **L-replay-after-revert** — naive retry of a reverted tx burns gas | Contract reverts classified as **fatal** in R-c; no retry |
| **L-tx-signing-leak** — secp256k1 scalar leaks during broadcast | Same posture as 3.1: k256's `SecretKey` is `ZeroizeOnDrop`; the broadcast fn borrows `&EvmWallet` for one scoped call — the secret never crosses an FFI boundary in 3.3 |
| **L-double-broadcast-on-retry** — retry re-broadcasts an already-landed tx | L12 verbatim — broadcast retries only fire BEFORE `send_transaction` succeeds. The mempool's idempotency on tx hash + the contract's nonce-bound `_nextSequence` advance backstop the property |
| **L-deployment-mismatch-broadcast** — tampered deployment file redirects tx to wrong contract | Same defense 3.1 uses: pinned `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA` cross-check. Plus the v0 adapter's runtime-keccak check (P7 MED-2) carries forward via the existing `BaseSepoliaAdapter` (we re-use the same deployment loader, not a sibling implementation) |
| **L-receipt-poll-timeout** — RPC withholds receipts past `RECEIPT_TIMEOUT_SECS` (60 s default) | `pending_tx.with_timeout(...)`-bounded; surface as `ChainError::Rpc`. The 4.1 chain-sync reconciliation will resolve via tx-hash replay if a "pending" status remains |

## Hermetic test surface

`crates/pangolin-chain/src/chain_submit.rs::tests` — 19 tests, no network:

- `publish_v1_calldata_byte_pin` — alloy's `sol!`-encoded calldata byte-equals `cast calldata` reference.
- `publish_v1_selector_matches` — `0x91f6be2f` pin.
- `publish_v1_happy_path_broadcast_leg` — `broadcast_with_retries` returns a `PendingTransactionBuilder` with the asserter's tx hash.
- `publish_v1_process_receipt_happy_path` — `process_receipt` populates a `ChainAnchorV1` from a synthetic status==1 receipt.
- `publish_v1_chain_id_mismatch_errors` — RPC reports chain id 1, expected 84_532 → `ChainIdMismatch`.
- `publish_v1_deployment_address_mismatch_errors` — wrong-address cross-check → `DeploymentAddressMismatch`.
- `publish_v1_gas_cap_exceeded_errors` — 100 gwei base fee → cap fires; no broadcast attempted.
- `publish_v1_insufficient_funds_errors` — send_tx returns "insufficient funds" → fatal.
- `publish_v1_reverted_decodes_reason` — status==0 receipt → `RevertedV1`.
- `publish_v1_estimate_revert_decodes_signer_not_registered` — `eth_estimateGas` reverts with `ErrSignerNotRegistered` → fatal pre-broadcast with decoded reason.
- `publish_v1_receipt_mismatch_errors` — receipt's `signer` disagrees with wallet → `ReceiptMismatch`.
- `publish_v1_log_from_wrong_address_treated_as_missing` — MED-4 defensive filter drops foreign logs.
- `publish_v1_nonce_collision_retries_then_succeeds` — attempt 1 nonce-too-low, attempt 2 succeeds.
- `publish_v1_nonce_unresolvable_after_max_retries` — 3 nonce-too-low → fatal.
- `publish_v1_rpc_transient_retries` — connection-reset on attempt 1, attempt 2 succeeds.
- Classifier units: `is_nonce_collision` / `is_transient_rpc_error` / `is_insufficient_funds` / `decode_revert_reason_from_msg`.

Live smoke test: `publish_v1_live_d017_smoke` is `#[ignore]`'d behind `#[cfg(feature = "integration-tests")]`. Run with:

```text
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org \
  cargo test -p pangolin-chain --features integration-tests \
  publish_v1_live_d017_smoke -- --ignored --nocapture
```

The wallet derived from the test's pinned seed must hold a small amount of Sepolia ETH for the first publish to clear; thereafter the contract's R-b self-bootstrap path lets subsequent revisions land without pre-registration.

## Out of scope (3.3)

- **Tx replacement / cancel-tx for stuck nonces** — MVP-3.
- **Block confirmations > 1** — 1-conf is sufficient for testnet; reorg-safe `n`-conf is a future hardening.
- **Multi-chain support** — one chain per build (master plan §0 cardinal principle 4).
- **Hardware-wallet tx signing** — MVP-3/4.
- **`apps/cli` integration of the v1 broadcast** — deferred to the standing CLI-V1 batch (same posture as 3.1 / 3.2).
- **`Vault::publish_revision_v1`** — R-d explicitly excludes this; the v1 broadcast lives on `pangolin-chain`, not on `Vault`.
