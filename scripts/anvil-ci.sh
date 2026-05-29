#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Pangolin anvil-fork CI harness (issue #101).
#
# Boots a local `anvil` node, deploys our REAL contract bytecode
# (RevisionLogV1 + EntitlementRegistry + RecoveryV1) to it via the
# existing forge scripts, generates contracts/deployments/dev.json from
# the structured broadcast artefact, funds the deterministic test
# wallet, and runs the in-scope `#[ignore]` live tests against the local
# node in dev mode (PANGOLIN_CHAIN_ENV=dev) — including the issue #103
# RecoveryV1 Rust↔contract lifecycle test (deploy → setGuardianSet →
# initiate → approve×threshold → evm_increaseTime(72h) → finalize).
#
# WHY (env-quirk #14): hermetic mocks fabricate receipts without running
# the contract's hash/signature logic, so the 3.3 keccak(encPayload)-vs-
# preimage calldata bug passed the full suite and was caught only by
# adversarial audit. This harness runs the deployed bytecode, so that
# bug class turns CI RED automatically — the prerequisite for the
# highest-risk MVP-3 Recovery contract.
#
# Determinism (L5): anvil readiness is POLLED (never a fixed sleep);
# teardown is a `trap` that always fires; deploy / parse failures are
# fail-closed.
#
# Usage:
#   scripts/anvil-ci.sh setup       # start anvil + deploy + dev.json + fund
#   scripts/anvil-ci.sh run         # run the 3 in-scope tests (dev mode)
#   scripts/anvil-ci.sh teardown    # stop anvil (idempotent)
#   scripts/anvil-ci.sh all         # setup + run + teardown (the CI entry)
#
# Requires anvil / forge / cast on PATH (foundry-toolchain@v1, pinned to
# the same version as the contracts jobs — env-quirk #4) plus jq + cargo.

set -euo pipefail

# --- locate repo root so paths work regardless of CWD ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# --- constants -------------------------------------------------------
ANVIL_HOST="127.0.0.1"
ANVIL_PORT="8545"
ANVIL_CHAIN_ID="31337"
RPC_URL="http://${ANVIL_HOST}:${ANVIL_PORT}"
# anvil's standard, well-known acct[0] private key (PUBLIC test key — it
# is published in anvil's docs; never used for anything but local dev).
# This account is pre-funded with 10000 ETH on a fresh anvil chain, so it
# pays gas for the deploys.
ANVIL_ACCT0_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_ACCT0_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# Dummy authority addresses for the EntitlementRegistry constructor —
# mirrors the deploy-pipeline dry-run convention. No real money flows on
# a local anvil chain.
PAYMENT_AUTHORITY="0x0000000000000000000000000000000000000001"
REDEMPTION_AUTHORITY="0x0000000000000000000000000000000000000002"

DEPLOYMENTS_DIR="$REPO_ROOT/contracts/deployments"
DEV_JSON="$DEPLOYMENTS_DIR/dev.json"
BROADCAST_DIR="$REPO_ROOT/contracts/broadcast"
LOG_DIR="$(mktemp -d)"
ANVIL_LOG="$LOG_DIR/anvil.log"
ANVIL_PID=""

# --- teardown (L5: always fires via trap) ----------------------------
teardown() {
  if [[ -n "${ANVIL_PID}" ]] && kill -0 "${ANVIL_PID}" 2>/dev/null; then
    echo "==> tearing down anvil (pid ${ANVIL_PID})"
    kill "${ANVIL_PID}" 2>/dev/null || true
    wait "${ANVIL_PID}" 2>/dev/null || true
  fi
  ANVIL_PID=""
  # Remove the runtime-generated dev.json (R-e: never a persistent
  # fixture). Leaving it on disk would make a subsequent local hermetic
  # run of the chain suite see a non-empty Dev deployment file (the
  # `wrong_chain_id_produces_different_signer` test assumes Dev has none)
  # — in CI the jobs are isolated, but locally this keeps the workspace
  # hermetic after the harness exits.
  rm -f "${DEV_JSON}" 2>/dev/null || true
}

# --- start anvil + poll for readiness (L5: never a fixed sleep) ------
start_anvil() {
  echo "==> starting anvil (chain-id ${ANVIL_CHAIN_ID}, port ${ANVIL_PORT})"
  anvil --silent \
    --host "${ANVIL_HOST}" \
    --port "${ANVIL_PORT}" \
    --chain-id "${ANVIL_CHAIN_ID}" \
    >"${ANVIL_LOG}" 2>&1 &
  ANVIL_PID="$!"
  trap teardown EXIT INT TERM

  # Poll cast block-number until the node answers. Bounded max-attempts,
  # fail-closed — NO fixed sleep that races slow CI runners.
  local max_attempts=60
  local attempt=0
  while (( attempt < max_attempts )); do
    if ! kill -0 "${ANVIL_PID}" 2>/dev/null; then
      echo "ERROR: anvil exited during startup; log follows:" >&2
      cat "${ANVIL_LOG}" >&2 || true
      exit 1
    fi
    if cast block-number --rpc-url "${RPC_URL}" >/dev/null 2>&1; then
      echo "==> anvil ready after $((attempt + 1)) poll attempt(s)"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.25
  done
  echo "ERROR: anvil did not become ready within ${max_attempts} attempts" >&2
  cat "${ANVIL_LOG}" >&2 || true
  exit 1
}

# --- deploy one contract via its forge script ------------------------
# Args: <script_name> (e.g. DeployRevisionLogV1)
# The forge script broadcasts to anvil; the structured artefact lands at
# contracts/broadcast/<script>.s.sol/<chain-id>/run-latest.json.
deploy_one() {
  local script_name="$1"
  echo "==> deploying via ${script_name}.s.sol"
  ( cd "$REPO_ROOT/contracts" && \
    PAYMENT_AUTHORITY="$PAYMENT_AUTHORITY" \
    REDEMPTION_AUTHORITY="$REDEMPTION_AUTHORITY" \
    RECOVERY_V1_ADDRESS="${RECOVERY_V1_ADDRESS:-}" \
    forge script "script/${script_name}.s.sol" \
      --sig "run()" --tc "$script_name" \
      --rpc-url "$RPC_URL" \
      --broadcast \
      --private-key "$ANVIL_ACCT0_PK" \
      >"$LOG_DIR/${script_name}.log" 2>&1 ) || {
        echo "ERROR: forge script failed for ${script_name}; log follows:" >&2
        cat "$LOG_DIR/${script_name}.log" >&2 || true
        exit 1
      }
}

# --- parse address + deploy block from the broadcast artefact --------
# env-quirk finding: forge script's human log has NO "Contract Address:"
# line on the anvil broadcast path — parse the structured artefact, NOT
# the log.
# Args: <script_name> <contract_name>
# Echoes: "<address> <deploy_block>"
parse_deploy() {
  local script_name="$1"
  local contract_name="$2"
  local artefact="$BROADCAST_DIR/${script_name}.s.sol/${ANVIL_CHAIN_ID}/run-latest.json"
  if [[ ! -f "$artefact" ]]; then
    echo "ERROR: broadcast artefact missing: $artefact" >&2
    exit 1
  fi
  local addr block
  # The CREATE tx for our contract: match on contractName, take its
  # contractAddress.
  addr="$(jq -r --arg cn "$contract_name" '
    [.transactions[]?
      | select(.contractName == $cn and .contractAddress != null)
      | .contractAddress] | first // empty' "$artefact")"
  # Deploy block from the matching receipt (by txhash → blockNumber).
  local txhash
  txhash="$(jq -r --arg cn "$contract_name" '
    [.transactions[]?
      | select(.contractName == $cn and .contractAddress != null)
      | .hash] | first // empty' "$artefact")"
  block="$(jq -r --arg th "$txhash" '
    [.receipts[]?
      | select(.transactionHash == $th)
      | .blockNumber] | first // empty' "$artefact")"
  # Receipt blockNumber is hex (0x...) → decimal.
  if [[ "$block" =~ ^0x[0-9a-fA-F]+$ ]]; then
    block="$((block))"
  fi
  if [[ -z "$addr" || -z "$block" ]]; then
    echo "ERROR: failed to parse ${contract_name} address/block from $artefact" >&2
    exit 1
  fi
  echo "$addr $block"
}

# --- generate contracts/deployments/dev.json -------------------------
# Shape walked by pangolin_chain::deployments::load_deployed_address:
#   .contracts.<Name>.address
# Plus a deploy_block for RevisionLogV1 (d017_deploy_block(Dev) reads it;
# 0 means scan-from-genesis, but we record the real value for parity).
generate_dev_json() {
  local rev_addr="$1" rev_block="$2" ent_addr="$3" ent_block="$4" rec_addr="$5" rec_block="$6"
  local rv2_addr="$7" rv2_block="$8"
  echo "==> generating $DEV_JSON"
  cat >"$DEV_JSON" <<EOF
{
  "\$schema": "runtime-generated by scripts/anvil-ci.sh (issue #101); DO NOT COMMIT (gitignored)",
  "chain": {
    "name": "anvil-dev",
    "chain_id": ${ANVIL_CHAIN_ID},
    "rpc_default": "${RPC_URL}"
  },
  "contracts": {
    "RevisionLogV1": {
      "address": "${rev_addr}",
      "deployer": "${ANVIL_ACCT0_ADDR}",
      "deploy_block": ${rev_block}
    },
    "EntitlementRegistry": {
      "address": "${ent_addr}",
      "deployer": "${ANVIL_ACCT0_ADDR}",
      "deploy_block": ${ent_block}
    },
    "RecoveryV1": {
      "address": "${rec_addr}",
      "deployer": "${ANVIL_ACCT0_ADDR}",
      "deploy_block": ${rec_block}
    },
    "RevisionLogV2": {
      "address": "${rv2_addr}",
      "deployer": "${ANVIL_ACCT0_ADDR}",
      "deploy_block": ${rv2_block}
    }
  }
}
EOF
  # Validate it's well-formed JSON before the tests rely on it.
  jq empty "$DEV_JSON" || {
    echo "ERROR: generated dev.json is not valid JSON" >&2
    exit 1
  }
}

# --- fund the deterministic test wallet ------------------------------
# The in-scope tests sign with fixed_wallet() (seed [0x42;32]); resolve
# its EVM address via the harness helper test and fund it so its publish
# tx (gas payer == signer per D-006) succeeds.
fund_test_wallet() {
  echo "==> resolving fixed_wallet() address"
  local out addr
  out="$(cargo test -p pangolin-chain --features integration-tests \
    print_fixed_wallet_address -- --ignored --nocapture 2>/dev/null \
    | grep -oE 'PANGOLIN_FIXED_WALLET_ADDRESS=0x[0-9a-fA-F]{40}' | head -n1 || true)"
  addr="${out#PANGOLIN_FIXED_WALLET_ADDRESS=}"
  # Strip any stray whitespace (env-quirk #13 posture).
  addr="$(echo "$addr" | tr -d '[:space:]')"
  if [[ ! "$addr" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "ERROR: could not resolve fixed_wallet() address (got '${addr}')" >&2
    exit 1
  fi
  echo "==> funding test wallet ${addr} with 1 ETH"
  # 0xDE0B6B3A7640000 = 1e18 wei = 1 ETH.
  cast rpc anvil_setBalance "$addr" 0xDE0B6B3A7640000 --rpc-url "$RPC_URL" >/dev/null
  # Export for the balance test (which reads BASE_SEPOLIA_DEV_WALLET).
  export PANGOLIN_FIXED_WALLET_ADDRESS="$addr"
}

# --- setup: anvil + deploy + dev.json + fund -------------------------
do_setup() {
  start_anvil
  deploy_one "DeployRevisionLogV1"
  deploy_one "DeployEntitlementRegistry"
  deploy_one "DeployRecoveryV1"
  local rev ent rec rv2
  rev="$(parse_deploy "DeployRevisionLogV1" "RevisionLogV1")"
  ent="$(parse_deploy "DeployEntitlementRegistry" "EntitlementRegistry")"
  rec="$(parse_deploy "DeployRecoveryV1" "RecoveryV1")"
  # #106a: deploy RevisionLogV2 bound to the just-deployed RecoveryV1
  # address (its sole constructor arg, Q-h cross-bind). Export it so the
  # deploy script's `vm.envOr("RECOVERY_V1_ADDRESS", ...)` picks the
  # canonical RecoveryV1 rather than deploying a fresh throwaway one.
  RECOVERY_V1_ADDRESS="$(echo "$rec" | awk '{print $1}')"
  export RECOVERY_V1_ADDRESS
  deploy_one "DeployRevisionLogV2"
  rv2="$(parse_deploy "DeployRevisionLogV2" "RevisionLogV2")"
  generate_dev_json ${rev} ${ent} ${rec} ${rv2}
  fund_test_wallet
  echo "==> setup complete"
}

# --- run: the 3 in-scope tests in dev mode ---------------------------
# L6: dev mode turns skip-clean into HARD error inside the tests.
do_run() {
  echo "==> running in-scope live tests against anvil (PANGOLIN_CHAIN_ENV=dev)"
  # publish_v1_live_d017_smoke (pangolin-chain lib, integration-tests
  # feature) + live_balance_query_against_d017_wallet (pangolin-chain
  # integration test).
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
  BASE_SEPOLIA_DEV_WALLET="${PANGOLIN_FIXED_WALLET_ADDRESS:-}" \
    cargo test -p pangolin-chain --features integration-tests \
      publish_v1_live_d017_smoke \
      -- --ignored --nocapture

  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
  BASE_SEPOLIA_DEV_WALLET="${PANGOLIN_FIXED_WALLET_ADDRESS:-}" \
    cargo test -p pangolin-chain --features integration-tests \
      --test integration \
      live_balance_query_against_d017_wallet \
      -- --ignored --nocapture

  # live_pull_once_against_d017_advances_checkpoint (pangolin-store). On
  # a fresh anvil chain the test vault has no events, so the pull cycle
  # advances the checkpoint without recovering any signer — the
  # checkpoint-monotonicity property still exercises the chain_sync read
  # path against the real node. PANGOLIN_PULL_LIVE_VAULT_ID is a fresh
  # 64-hex vault id (the publish test used a time-tweaked one; here we
  # use a fixed harness value — its absence of events is expected).
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
  PANGOLIN_PULL_LIVE_VAULT_ID="00000000000000000000000000000000000000000000000000000000000000aa" \
    cargo test -p pangolin-store --features test-utilities \
      --test pull_live \
      live_pull_once_against_d017_advances_checkpoint \
      -- --ignored --nocapture

  # issue #103 RecoveryV1 lifecycle (the centerpiece — L10). The
  # recovering wallet is the same [0x42;32] seed fund_test_wallet
  # funded; it self-bootstraps as authority + pays gas for all five
  # lifecycle txs. Guardians sign off-chain (no funding needed). cast
  # must be on PATH (the test invokes evm_increaseTime / evm_mine for
  # the 72h time-warp).
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
    cargo test -p pangolin-chain --features integration-tests --lib \
      recovery_lifecycle_against_anvil \
      -- --ignored --nocapture

  # issue #104b COUPLED recovery-escrow E2E (the centerpiece — L10). Ties
  # the OFF-CHAIN threshold-escrow reconstruction to the ON-CHAIN
  # lifecycle: real split_rwk -> real merkle root over the SAME guardians
  # whose X25519 shares were sealed -> setGuardianSet -> initiate ->
  # approve×t -> evm_increaseTime(72h) -> finalize -> open_sealed_share×t
  # -> reconstruct_rwk -> unwrap_vdk_under_rwk -> ct_eq original VDK ->
  # new-password re-wrap -> forward-security re-split. The recovering
  # wallet is the same [0x42;32] seed fund_test_wallet funded; guardians
  # sign off-chain (no funding). cast must be on PATH (the test invokes
  # evm_increaseTime / evm_mine for the 72h time-warp). The negatives
  # (<t shares, wrong guardian↔share mapping, finalize-before-delay) MUST
  # fail-red — they are assertions inside the test, so a regression turns
  # this command RED automatically.
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
    cargo test -p pangolin-chain --features integration-tests --lib \
      recovery_escrow_coupled_e2e_against_anvil \
      -- --ignored --nocapture

  # issue #106c COUPLED multi-device E2E (the centerpiece — L10). Ties the
  # RevisionLogV2 chain client (#106c add/remove EIP-712, accepted by the
  # LIVE contract) + the pairing VDK handoff (#106b-1 seal/open ct_eq) + the
  # VDK rotation-on-revoke (#106b-2 rotate + commit_vdk_rotation):
  # bootstrapVault(A) -> addDevice(B) -> seal+open VDK (ct_eq) -> B in set
  # honored -> removeDevice(B) -> B unhonored + the DeviceRemoved trigger
  # fires (rotation-pending persisted, NOT auto-rotated, L3) -> rotate ->
  # commit -> forward secrecy (removed B can't open the new epoch; survivor
  # A can). The negatives (broken AddDevice EIP-712 digest -> the live
  # contract reverts; honor gate honoring a removed signer; a survivor seal
  # to the removed device) are assertions inside the test, so a regression
  # turns this command RED automatically. Manager A == the same [0x42;32]
  # seed fund_test_wallet funded (it self-bootstraps + pays gas for the
  # add/remove txs). RevisionLogV2 is already deployed by do_setup.
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
    cargo test -p pangolin-core --features integration-tests \
      --test anvil_device_e2e \
      device_add_remove_rotate_e2e_against_anvil \
      -- --ignored --nocapture

  # issue #106c2 COUPLED V2 revision data-plane E2E (the centerpiece — L11).
  # The everyday "publish a revision to RevisionLogV2 -> read + verify it"
  # path against the LIVE contract: bootstrapVault(publisher) ->
  # publish_revision_v2 (publisher in the set, real v2 EIP-712 sig accepted
  # by the live publishRevision set-gate) -> fetch_and_verify_chunk_v2 reads
  # the RevisionPublished event back + verifies the digest/signer round-trip.
  # The negatives (a V1-domain sig won't verify against v2; a tampered
  # payload-hash recovers a different signer; a foreign claimed-signer fails
  # the cross-check; a non-member publisher reverts ErrSignerNotAuthorized)
  # are assertions inside the test, so a regression turns this command RED
  # automatically. The publisher is the same [0x42;32] seed fund_test_wallet
  # funded (it self-bootstraps + pays gas). RevisionLogV2 is already deployed
  # by do_setup.
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
    cargo test -p pangolin-chain --features integration-tests --lib \
      publish_revision_v2_e2e_against_anvil \
      -- --ignored --nocapture

  # issue #106d COUPLED revocation-on-read regression gate (the centerpiece
  # — L11). Drives the live-set honor gate + the retroactive re-eval through
  # the REAL Vault::sync_from_chain V2 path against the LIVE RevisionLogV2:
  # bootstrapVault(A) -> addDevice(B) -> publish_revision_v2 as A AND B ->
  # sync -> BOTH honored (surface as heads/history) -> removeDevice(B) ->
  # re-sync -> A still honored, B's retroactively-stored entry REVOKED-on-read
  # (filtered from head + history; revisions_revoked counts it) -> re-add(B)
  # -> re-sync -> B honored again (re-add un-revokes). The negatives (a
  # honor-all predicate would leave B's removed entry surfacing; a fail-OPEN
  # on a set-read error would honor everyone; a marks-but-reads-don't-filter
  # regression would leave the revoked B row in head/history) are assertions
  # inside the test, so a regression turns this command RED automatically.
  # Manager A == the same [0x42;32] seed fund_test_wallet funded; B is funded
  # by the test via anvil_setBalance so it can pay gas for its own publish.
  # RevisionLogV2 is already deployed by do_setup.
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
    cargo test -p pangolin-core --features integration-tests \
      --test anvil_device_e2e \
      revocation_honor_gate_remove_then_read_e2e_against_anvil \
      -- --ignored --nocapture

  # MVP-4-K manager-promotion handoff E2E. Candidate-initiated, 48h-delayed
  # promotion against the LIVE RevisionLogV2: bootstrapVault(A) ->
  # addDevice(B) -> B self-signs Promote(candidate=B) -> proposePromotion
  # (B's key, NOT A's — the contract's recovered==candidate check) ->
  # pendingPromotion==(B,readyAt); manager still A -> finalize-before-delay
  # reverts -> warp +48h + mine -> finalizePromotion (permissionless) ->
  # currentManager==B; pending cleared. Negatives are in-test assertions, so
  # a regression turns this RED. B is funded by the test (anvil_setBalance)
  # to pay gas for its own propose/finalize. Run as its OWN invocation (it
  # warps the global anvil clock; a parallel runner would bleed that warp).
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
    cargo test -p pangolin-core --features integration-tests \
      --test anvil_device_e2e \
      promotion_handoff_e2e_against_anvil \
      -- --ignored --nocapture

  # MVP-4-K manager-veto E2E: B self-proposes, then manager A cancelPromotion's
  # it (msg.sender-gated) -> pending cleared; manager stays A.
  PANGOLIN_CHAIN_ENV=dev \
  BASE_SEPOLIA_RPC_URL="$RPC_URL" \
    cargo test -p pangolin-core --features integration-tests \
      --test anvil_device_e2e \
      promotion_veto_e2e_against_anvil \
      -- --ignored --nocapture

  echo "==> all in-scope tests passed against anvil"
}

# --- dispatch --------------------------------------------------------
case "${1:-}" in
  setup)
    do_setup
    # In bare `setup` mode the caller is responsible for teardown; keep
    # anvil up by detaching the trap-on-exit (the EXIT trap would kill it
    # the moment this subcommand returns). For `all` the trap stays.
    trap - EXIT INT TERM
    echo "==> anvil left running at ${RPC_URL} (pid ${ANVIL_PID}); run 'teardown' to stop"
    ;;
  run)
    do_run
    ;;
  teardown)
    # Best-effort: find + kill any anvil on our port.
    if command -v pkill >/dev/null 2>&1; then
      pkill -f "anvil .*--port ${ANVIL_PORT}" 2>/dev/null || true
    fi
    echo "==> teardown requested (port ${ANVIL_PORT})"
    ;;
  all)
    do_setup
    do_run
    teardown
    echo "==> harness run complete (setup + run + teardown)"
    ;;
  *)
    echo "Usage: $0 {setup|run|teardown|all}" >&2
    exit 2
    ;;
esac
