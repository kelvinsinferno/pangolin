#!/usr/bin/env bash
# Pangolin contract deploy pipeline (MVP-2 issue 2.3).
#
# One-command bootstrap for the three Pangolin contracts across the three
# supported environments (dev / sepolia / mainnet). Implements the locked
# decisions in docs/issue-plans/2.3.md (L1..L8 + R-a..R-d). See
# docs/RELEASE-CONTRACTS.md for the operational runbook.
#
# Per L1 the .s.sol deploy scripts under contracts/script/ are NOT touched
# by this wrapper; we only set the per-network flags + capture results.
# Per L3 the deployer key is referenced through a Foundry keystore alias
# (--account <alias>) and never as a raw --private-key.
# Per L4 Basescan verification is part of the deploy command (auto-verify
# when BASESCAN_API_KEY is non-empty; falls back to no-verify with a
# warning otherwise).
# Per L5 the four guardrails are mandatory: chain-id match, deployer
# balance, keystore prompt, parsed output recording.
# Per L6 mainnet requires PANGOLIN_MAINNET_AUDITED=1 to proceed (D-011
# external-audit soft gate).
# Per R-c this wrapper SHIPS the pipeline; the actual on-chain execution
# is a Kelvin-driven step after the code merges. CI exercises only the
# --dry-run path.
#
# Usage:
#   scripts/deploy-contracts.sh --env <dev|sepolia|mainnet> \
#                                --contract <v0|v1|entitlement|all> \
#                                [--unattended] [--dry-run]
#
# Examples:
#   # CI dry-run (no RPC contact, no balance check, no keystore prompt):
#   scripts/deploy-contracts.sh --env dev --contract all --dry-run --unattended
#
#   # Real Sepolia deploy of v1 (prompts for the pangolin-dev passphrase):
#   scripts/deploy-contracts.sh --env sepolia --contract v1

set -euo pipefail

# --- locate repo root so paths work regardless of CWD ----------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# --- flag parsing ----------------------------------------------------
ENV=""
CONTRACT=""
UNATTENDED=0
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) ENV="${2:-}"; shift 2 ;;
    --contract) CONTRACT="${2:-}"; shift 2 ;;
    --unattended) UNATTENDED=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '1,40p' "$0"
      exit 0
      ;;
    *) echo "ERROR: unknown flag: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$ENV" ]] || { echo "ERROR: --env is required (one of dev, sepolia, mainnet)" >&2; exit 1; }
[[ -n "$CONTRACT" ]] || { echo "ERROR: --contract is required (one of v0, v1, entitlement, all)" >&2; exit 1; }

# --- env validation + mainnet gate (L6) ------------------------------
case "$ENV" in
  dev|sepolia) ;;
  mainnet)
    if [[ "${PANGOLIN_MAINNET_AUDITED:-0}" != "1" ]]; then
      echo "ERROR: --env mainnet requires PANGOLIN_MAINNET_AUDITED=1" >&2
      echo "       D-011 (external audit) gate. Set this only after the audit firm's" >&2
      echo "       report has been reviewed by Kelvin and the findings are addressed." >&2
      exit 1
    fi
    ;;
  *) echo "ERROR: --env must be one of {dev, sepolia, mainnet}; got '$ENV'" >&2; exit 1 ;;
esac

# --- contract validation --------------------------------------------
case "$CONTRACT" in
  v0|v1|entitlement|all) ;;
  *) echo "ERROR: --contract must be one of {v0, v1, entitlement, all}; got '$CONTRACT'" >&2; exit 1 ;;
esac

# --- combo-guard: refuse policy-forbidden (--env, --contract) pairs -
# These guards fire BEFORE the env file is sourced and BEFORE any RPC
# is contacted (chain-id check, balance check). Audit fix-pass: putting
# them later would mean a policy-forbidden invocation hangs on a slow
# public RPC before reaching the guard.

# F3 (audit Med): --contract v0 --env sepolia would destructively
# overwrite the canonical D-014 RevisionLogV0 entry in
# contracts/deployments/base-sepolia.json under the same JSON key.
# The D-015 redeploy-proof pattern used a separate key precisely
# to avoid this. Refuse non-dry-run; dry-run never writes JSON so
# is allowed for syntax-check use.
if [[ "$CONTRACT" == "v0" && "$ENV" == "sepolia" && "$DRY_RUN" == "0" ]]; then
  echo "ERROR: --contract v0 --env sepolia would destructively overwrite the canonical" >&2
  echo "       D-014 RevisionLogV0 entry in contracts/deployments/base-sepolia.json." >&2
  echo "" >&2
  echo "       v0 is the PoC append-only-immutable contract; it stays at D-014" >&2
  echo "       (0x8566D3...3896) and D-015 (0x74f287...A9c4). It does NOT need redeploying" >&2
  echo "       as part of MVP-2." >&2
  echo "" >&2
  echo "       If you genuinely need a fresh v0 redeploy proof (D-015-style), invoke" >&2
  echo "       forge script directly, then hand-edit a unique key (e.g." >&2
  echo "       'RevisionLogV0_redeploy_<date>') into base-sepolia.json. The wrapper" >&2
  echo "       intentionally refuses to touch the D-014 key." >&2
  exit 1
fi

# F5 (audit Low): mainnet --contract all is policy-forbidden by the
# runbook (one contract at a time on mainnet so each on-chain step
# gets explicit human inspection). Doc-only would be bypassable by
# a tired operator; script-level guard makes the policy load-bearing.
if [[ "$CONTRACT" == "all" && "$ENV" == "mainnet" ]]; then
  echo "ERROR: mainnet --contract all is policy-forbidden per docs/RELEASE-CONTRACTS.md." >&2
  echo "       Deploy one contract at a time on mainnet so each irreversible on-chain" >&2
  echo "       step gets explicit human inspection between." >&2
  echo "" >&2
  echo "       Re-run as:" >&2
  echo "         $0 --env mainnet --contract v1" >&2
  echo "         # ... verify D-NNN record + inspect Basescan ..." >&2
  echo "         $0 --env mainnet --contract entitlement" >&2
  exit 1
fi

# --- env file source ------------------------------------------------
ENV_FILE="$REPO_ROOT/contracts/deploy/.env.$ENV"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: missing env file: $ENV_FILE" >&2
  if [[ "$ENV" == "mainnet" ]]; then
    echo "       Copy contracts/deploy/.env.mainnet.template to .env.mainnet" >&2
    echo "       and fill in the required values before deploying." >&2
  fi
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

# --- required-vars check --------------------------------------------
require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "ERROR: required env var '$name' is unset or empty (sourced from $ENV_FILE)" >&2
    exit 1
  fi
}

require_var RPC_URL
require_var EXPECTED_CHAIN_ID
require_var DEPLOYER_ACCOUNT

# EntitlementRegistry constructor needs both authority addresses.
case "$CONTRACT" in
  entitlement|all)
    require_var PAYMENT_AUTHORITY
    require_var REDEMPTION_AUTHORITY
    ;;
esac

# --- unattended-on-real-deploy guard --------------------------------
# Real deploys need an interactive terminal so forge can prompt for the
# keystore passphrase. --unattended is only safe on --dry-run + --env dev.
# Check this BEFORE the balance check because `cast wallet address` may
# prompt for the passphrase in newer foundry releases, which would hang
# under --unattended.
if [[ "$UNATTENDED" == "1" && "$DRY_RUN" == "0" && "$ENV" != "dev" ]]; then
  echo "ERROR: --unattended requires --dry-run (or --env dev)." >&2
  echo "       A real deploy needs an interactive terminal so forge can prompt" >&2
  echo "       for the keystore passphrase." >&2
  exit 1
fi

# --- chain-id sanity check (skipped on --dry-run) -------------------
# Rationale: --dry-run is meant to be runnable in CI (where the dev env's
# 127.0.0.1:8545 has no anvil listening) and as a script-syntax smoke
# test. Real deploys (no --dry-run) MUST verify the RPC matches the
# expected chain id before broadcasting.
if [[ "$DRY_RUN" == "0" ]]; then
  echo "==> verifying chain id at $RPC_URL"
  ACTUAL_CHAIN_ID="$(cast chain-id --rpc-url "$RPC_URL")"
  if [[ "$ACTUAL_CHAIN_ID" != "$EXPECTED_CHAIN_ID" ]]; then
    echo "ERROR: chain id mismatch — expected $EXPECTED_CHAIN_ID, got $ACTUAL_CHAIN_ID at $RPC_URL" >&2
    exit 1
  fi
  echo "    chain id $ACTUAL_CHAIN_ID matches expected"
fi

# --- deployer balance check (skipped on --dry-run or --env dev) -----
if [[ "$DRY_RUN" == "0" && "$ENV" != "dev" ]]; then
  echo "==> checking deployer balance for account '$DEPLOYER_ACCOUNT'"
  # `cast wallet address --account <alias>` reads only the address from
  # the keystore JSON; in recent foundry releases it may prompt for the
  # passphrase even for an address-only read. That prompt is interactive
  # so we expect a TTY at this step (guaranteed by the --unattended guard
  # above).
  DEPLOYER_ADDR="$(cast wallet address --account "$DEPLOYER_ACCOUNT")"
  BAL_WEI="$(cast balance "$DEPLOYER_ADDR" --rpc-url "$RPC_URL")"
  MIN_WEI="${MIN_DEPLOYER_BALANCE_WEI:-10000000000000000}"
  # Compare as decimal strings of arbitrary length; bash arithmetic
  # would overflow for large wei values. `cast` already prints decimal.
  if ! awk -v a="$BAL_WEI" -v b="$MIN_WEI" 'BEGIN { exit !(a + 0 >= b + 0) }'; then
    echo "ERROR: deployer $DEPLOYER_ADDR balance $BAL_WEI wei < required $MIN_WEI wei" >&2
    echo "       Top up via the Base Sepolia faucet or send ETH to this address." >&2
    exit 1
  fi
  echo "    deployer $DEPLOYER_ADDR has $BAL_WEI wei (>= $MIN_WEI minimum)"
fi

# --- assemble forge flags -------------------------------------------
# On --dry-run we deliberately DROP --rpc-url so forge runs against its
# in-memory EVM (matches the existing CI dry-run steps for v0/v1/registry).
# This makes the dev-environment dry-run runnable in CI without an anvil
# listening at 127.0.0.1:8545, and makes the sepolia dry-run runnable
# locally without RPC connectivity. The mismatch with EXPECTED_CHAIN_ID
# is fine because we skipped the chain-id check above for the same reason.
FORGE_FLAGS=()
if [[ "$DRY_RUN" == "0" ]]; then
  FORGE_FLAGS+=(--rpc-url "$RPC_URL" --broadcast --account "$DEPLOYER_ACCOUNT")
  if [[ -n "${BASESCAN_API_KEY:-}" ]]; then
    require_var VERIFIER_URL
    FORGE_FLAGS+=(--verify --etherscan-api-key "$BASESCAN_API_KEY" --verifier-url "$VERIFIER_URL")
    echo "==> Basescan auto-verify ENABLED (verifier-url=$VERIFIER_URL)"
  else
    echo "==> Basescan auto-verify DISABLED (BASESCAN_API_KEY empty); fallback: forge verify-contract"
  fi
fi

# --- deploy one contract --------------------------------------------
# Globals consumed: ENV, RPC_URL, FORGE_FLAGS, DRY_RUN, DEPLOYMENTS_FILE,
# PAYMENT_AUTHORITY, REDEMPTION_AUTHORITY.
deploy_one() {
  local script_name="$1"    # e.g. DeployRevisionLogV1
  local contract_name="$2"  # e.g. RevisionLogV1 (key in deployments JSON)

  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local log_dir="${TMPDIR:-/tmp}"
  local log_file
  log_file="$log_dir/pangolin-deploy-${contract_name}-${ENV}-${ts}.log"

  echo
  echo "==> deploying $contract_name to $ENV via contracts/script/${script_name}.s.sol"
  echo "    log: $log_file"

  # EntitlementRegistry's deploy script reads two env vars via vm.envAddress.
  # Export them unconditionally before invoking forge; the other scripts
  # ignore them.
  export PAYMENT_AUTHORITY REDEMPTION_AUTHORITY

  # Forge looks for foundry.toml + lib/ + remappings.txt relative to its
  # CWD; we cd into contracts/ for the invocation so the build sees the
  # vendored forge-std + the project's compiler settings. The script
  # path is given relative to contracts/ to match what forge expects.
  # PIPESTATUS captures forge's exit code even though `tee` succeeds.
  set +e
  (
    cd "$REPO_ROOT/contracts" && \
    forge script "script/${script_name}.s.sol" \
      --sig "run()" --tc "$script_name" \
      ${FORGE_FLAGS[@]+"${FORGE_FLAGS[@]}"}
  ) 2>&1 | tee "$log_file"
  local forge_rc=${PIPESTATUS[0]}
  set -e
  if [[ "$forge_rc" -ne 0 ]]; then
    echo "ERROR: forge script failed for $contract_name (exit $forge_rc); see $log_file" >&2
    return 1
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    # Dry-run prints "Return ==" with the deployed-address from the
    # simulation. We do NOT record this — dry-run is for syntax + simulation
    # only; nothing landed on chain.
    echo "    dry-run complete for $contract_name (no on-chain state changed; no record written)"
    return 0
  fi

  # --- parse deploy address, tx hash, gas used from the log ---------
  # forge --broadcast prints:
  #   ##### base-sepolia
  #   ✅  [Success] Hash: 0x...
  #   Contract Address: 0x...
  #   Block: 12345
  #   Paid: 0.000... ETH (... gas * ... gwei)
  # Order matches forge 1.0.x. Grep for the first occurrence of each.
  local addr tx_hash block gas_used
  addr="$(grep -oE 'Contract Address: 0x[0-9a-fA-F]{40}' "$log_file" | head -n1 | awk '{print $3}' || true)"
  tx_hash="$(grep -oE 'Hash: 0x[0-9a-fA-F]{64}' "$log_file" | head -n1 | awk '{print $2}' || true)"
  block="$(grep -oE 'Block: [0-9]+' "$log_file" | head -n1 | awk '{print $2}' || true)"
  # gas_used parsing handles BOTH forge output formats:
  #   - dry-run / simulation: "Gas used: 422850"
  #   - broadcast: "Paid: 0.0000... ETH (149135 gas * 0.006 gwei)"
  # We try the dry-run pattern first, then fall back to the broadcast
  # pattern, then to the canonical broadcast artefact at
  # contracts/broadcast/<script>.s.sol/<chain-id>/run-latest.json
  # (only exists after a real --broadcast invocation). Empty value
  # at the end means the JSON entry will record gas_used: 0 — the
  # deploy still succeeded; only the metadata field is unknown.
  gas_used="$(grep -oE 'Gas used: [0-9]+' "$log_file" | head -n1 | awk '{print $3}' || true)"
  if [[ -z "$gas_used" ]]; then
    # Broadcast format: "(149135 gas * 0.006 gwei)" — pull the integer
    # immediately before " gas *".
    gas_used="$(grep -oE '\([0-9]+ gas \*' "$log_file" | head -n1 | grep -oE '[0-9]+' || true)"
  fi
  if [[ -z "$gas_used" && "$DRY_RUN" == "0" ]]; then
    # Canonical fallback: the structured broadcast artefact JSON.
    # Path: contracts/broadcast/<script_name>.s.sol/<chain-id>/run-latest.json
    # (script_name is the function parameter, e.g. "DeployRevisionLogV1")
    local broadcast_artefact
    broadcast_artefact="$REPO_ROOT/contracts/broadcast/${script_name}.s.sol/${EXPECTED_CHAIN_ID}/run-latest.json"
    if [[ -f "$broadcast_artefact" ]]; then
      gas_used="$(jq -r --arg addr "$addr" '
        [.transactions[]?
          | select(.contractAddress != null and (.contractAddress | ascii_downcase) == ($addr | ascii_downcase))
          | .transaction.gas // empty
        ] | first // empty' "$broadcast_artefact" 2>/dev/null || true)"
      # gas in the artefact is hex (0x...); decode to decimal if so.
      if [[ "$gas_used" =~ ^0x[0-9a-fA-F]+$ ]]; then
        gas_used="$((gas_used))"
      fi
    fi
  fi

  if [[ -z "$addr" || -z "$tx_hash" ]]; then
    echo "ERROR: failed to parse deploy address/tx from $log_file" >&2
    echo "       forge output format may have changed; inspect the log manually." >&2
    return 1
  fi

  echo
  echo "==> deployed $contract_name at $addr (tx $tx_hash${block:+, block $block}${gas_used:+, gas used $gas_used})"

  # --- post-deploy smoke tests --------------------------------------
  echo "==> running smoke tests"
  case "$contract_name" in
    RevisionLogV1)
      local max_ver dom_sep
      max_ver="$(cast call "$addr" "MAX_KNOWN_SCHEMA_VERSION()(uint16)" --rpc-url "$RPC_URL")"
      dom_sep="$(cast call "$addr" "domainSeparator()(bytes32)" --rpc-url "$RPC_URL")"
      echo "    MAX_KNOWN_SCHEMA_VERSION = $max_ver (expected: 1)"
      echo "    DOMAIN_SEPARATOR = $dom_sep"
      if [[ "$max_ver" != "1" ]]; then
        echo "ERROR: smoke test failed: MAX_KNOWN_SCHEMA_VERSION expected 1, got $max_ver" >&2
        return 1
      fi
      if [[ "$dom_sep" == "0x0000000000000000000000000000000000000000000000000000000000000000" ]]; then
        echo "ERROR: smoke test failed: DOMAIN_SEPARATOR is zero" >&2
        return 1
      fi
      ;;
    EntitlementRegistry)
      local max_ver pay red
      max_ver="$(cast call "$addr" "MAX_KNOWN_SCHEMA_VERSION()(uint16)" --rpc-url "$RPC_URL")"
      pay="$(cast call "$addr" "PAYMENT_AUTHORITY()(address)" --rpc-url "$RPC_URL")"
      red="$(cast call "$addr" "REDEMPTION_AUTHORITY()(address)" --rpc-url "$RPC_URL")"
      echo "    MAX_KNOWN_SCHEMA_VERSION = $max_ver (expected: 1)"
      echo "    PAYMENT_AUTHORITY = $pay (expected: $PAYMENT_AUTHORITY)"
      echo "    REDEMPTION_AUTHORITY = $red (expected: $REDEMPTION_AUTHORITY)"
      if [[ "$max_ver" != "1" ]]; then
        echo "ERROR: smoke test failed: MAX_KNOWN_SCHEMA_VERSION expected 1, got $max_ver" >&2
        return 1
      fi
      # Address comparison is case-insensitive (cast may return checksummed).
      if [[ "${pay,,}" != "${PAYMENT_AUTHORITY,,}" ]]; then
        echo "ERROR: smoke test failed: PAYMENT_AUTHORITY mismatch" >&2
        return 1
      fi
      if [[ "${red,,}" != "${REDEMPTION_AUTHORITY,,}" ]]; then
        echo "ERROR: smoke test failed: REDEMPTION_AUTHORITY mismatch" >&2
        return 1
      fi
      ;;
    RevisionLogV0)
      local next_seq
      next_seq="$(cast call "$addr" "nextSequence()(uint256)" --rpc-url "$RPC_URL")"
      echo "    nextSequence = $next_seq (expected: 0)"
      if [[ "$next_seq" != "0" ]]; then
        echo "ERROR: smoke test failed: nextSequence expected 0, got $next_seq" >&2
        return 1
      fi
      ;;
  esac

  # --- compute runtime keccak via `cast keccak $(cast code <addr>)` --
  # Per the D-014 correction note in contracts/deployments/base-sepolia.json,
  # the runtime hash MUST be Ethereum Keccak-256 (NOT NIST SHA3-256).
  # `cast keccak` is the Keccak-256 primitive; passing the runtime bytecode
  # (hex with 0x prefix) reproduces what `extcodehash` reports on-chain.
  local runtime_keccak
  runtime_keccak="$(cast keccak "$(cast code "$addr" --rpc-url "$RPC_URL")")"
  echo "    runtime keccak256 = $runtime_keccak"

  # --- atomic JSON injection via jq --------------------------------
  local deployments_file="$REPO_ROOT/contracts/deployments/$([ "$ENV" = "sepolia" ] && echo "base-sepolia" || echo "$ENV").json"
  # Mainnet writes to base-mainnet.json by convention; dev does not record
  # (no canonical address; anvil restarts re-issue the same nonce-0 addr).
  if [[ "$ENV" == "dev" ]]; then
    echo "    skipping deployments JSON write for dev (anvil ephemeral)"
    return 0
  fi
  if [[ "$ENV" == "mainnet" ]]; then
    deployments_file="$REPO_ROOT/contracts/deployments/base-mainnet.json"
    if [[ ! -f "$deployments_file" ]]; then
      # Bootstrap a minimal file mirroring base-sepolia.json's chain block.
      cat >"$deployments_file" <<EOF
{
  "\$schema": "./README.md (no formal schema yet; field set is canonical until v1)",
  "chain": {
    "name": "base-mainnet",
    "chain_id": 8453,
    "explorer": "https://basescan.org",
    "rpc_default": ""
  },
  "contracts": {}
}
EOF
    fi
  fi

  if [[ ! -f "$deployments_file" ]]; then
    echo "ERROR: deployments file missing: $deployments_file" >&2
    return 1
  fi

  # Build the per-contract JSON blob. The shape mirrors what
  # contracts/deployments/base-sepolia.json already records for V0; D-014
  # + D-015 are the precedent. The `smoke_test` field captures the on-chain
  # state we just verified.
  local deployed_at
  deployed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local deployer_addr
  deployer_addr="${DEPLOYER_ADDR:-$(cast wallet address --account "$DEPLOYER_ACCOUNT" 2>/dev/null || echo "unknown")}"
  local explorer_base
  case "$ENV" in
    sepolia) explorer_base="https://sepolia.basescan.org" ;;
    mainnet) explorer_base="https://basescan.org" ;;
  esac

  local entry_json
  case "$contract_name" in
    RevisionLogV1)
      entry_json="$(jq -n \
        --arg addr "$addr" \
        --arg deployer "$deployer_addr" \
        --arg tx "$tx_hash" \
        --argjson block "${block:-0}" \
        --argjson gas_used "${gas_used:-0}" \
        --arg deployed_at "$deployed_at" \
        --arg runtime_keccak "$runtime_keccak" \
        --arg explorer_base "$explorer_base" \
        --arg max_ver "$max_ver" \
        --arg dom_sep "$dom_sep" \
        '{
          address: $addr,
          deployer: $deployer,
          deploy_tx: $tx,
          deploy_block: $block,
          deployed_at: $deployed_at,
          gas_used: $gas_used,
          compiler: {
            name: "solc",
            version: "0.8.24",
            evm_version: "shanghai",
            optimizer: true,
            optimizer_runs: 200,
            bytecode_hash: "none"
          },
          bytecode: {
            deployed_runtime_keccak256: $runtime_keccak
          },
          abi: "../abi/RevisionLogV1.json",
          source: "../src/RevisionLogV1.sol",
          smoke_tests: {
            MAX_KNOWN_SCHEMA_VERSION: $max_ver,
            DOMAIN_SEPARATOR: $dom_sep
          },
          explorer_links: {
            contract: ($explorer_base + "/address/" + $addr),
            deploy_tx: ($explorer_base + "/tx/" + $tx)
          }
        }')"
      ;;
    EntitlementRegistry)
      entry_json="$(jq -n \
        --arg addr "$addr" \
        --arg deployer "$deployer_addr" \
        --arg tx "$tx_hash" \
        --argjson block "${block:-0}" \
        --argjson gas_used "${gas_used:-0}" \
        --arg deployed_at "$deployed_at" \
        --arg runtime_keccak "$runtime_keccak" \
        --arg explorer_base "$explorer_base" \
        --arg max_ver "$max_ver" \
        --arg pay "$PAYMENT_AUTHORITY" \
        --arg red "$REDEMPTION_AUTHORITY" \
        --arg pay_actual "$pay" \
        --arg red_actual "$red" \
        '{
          address: $addr,
          deployer: $deployer,
          deploy_tx: $tx,
          deploy_block: $block,
          deployed_at: $deployed_at,
          gas_used: $gas_used,
          compiler: {
            name: "solc",
            version: "0.8.24",
            evm_version: "shanghai",
            optimizer: true,
            optimizer_runs: 200,
            bytecode_hash: "none"
          },
          bytecode: {
            deployed_runtime_keccak256: $runtime_keccak
          },
          constructor_args: {
            payment_authority: $pay,
            redemption_authority: $red
          },
          abi: "../abi/EntitlementRegistry.json",
          source: "../src/EntitlementRegistry.sol",
          smoke_tests: {
            MAX_KNOWN_SCHEMA_VERSION: $max_ver,
            PAYMENT_AUTHORITY: $pay_actual,
            REDEMPTION_AUTHORITY: $red_actual
          },
          explorer_links: {
            contract: ($explorer_base + "/address/" + $addr),
            deploy_tx: ($explorer_base + "/tx/" + $tx)
          },
          note: "Per 2.3 L8: testnet deploy uses pangolin-dev wallet for BOTH authorities (collapses split-trust per R-a of 2.2). Production deployment with real split authority keys ships with MVP-2 issue 3.4 (funder service); this contract is for smoke-testing only."
        }')"
      ;;
    RevisionLogV0)
      entry_json="$(jq -n \
        --arg addr "$addr" \
        --arg deployer "$deployer_addr" \
        --arg tx "$tx_hash" \
        --argjson block "${block:-0}" \
        --argjson gas_used "${gas_used:-0}" \
        --arg deployed_at "$deployed_at" \
        --arg runtime_keccak "$runtime_keccak" \
        --arg explorer_base "$explorer_base" \
        '{
          address: $addr,
          deployer: $deployer,
          deploy_tx: $tx,
          deploy_block: $block,
          deployed_at: $deployed_at,
          gas_used: $gas_used,
          bytecode: {
            deployed_runtime_keccak256: $runtime_keccak
          },
          abi: "../abi/RevisionLogV0.json",
          source: "../src/RevisionLogV0.sol",
          explorer_links: {
            contract: ($explorer_base + "/address/" + $addr),
            deploy_tx: ($explorer_base + "/tx/" + $tx)
          }
        }')"
      ;;
  esac

  # Atomic write: jq to .tmp, mv into place.
  local tmp_file="${deployments_file}.tmp"
  jq --argjson entry "$entry_json" --arg name "$contract_name" \
    '.contracts[$name] = $entry' \
    "$deployments_file" >"$tmp_file"
  mv "$tmp_file" "$deployments_file"
  echo "    recorded $contract_name in $deployments_file"
}

# --- dispatch on --contract ----------------------------------------
# (Combo-guards for v0+sepolia and all+mainnet fire early, before
# env-file source — see the "combo-guard" block near the top.)
case "$CONTRACT" in
  v0) deploy_one "DeployRevisionLogV0" "RevisionLogV0" ;;
  v1) deploy_one "DeployRevisionLogV1" "RevisionLogV1" ;;
  entitlement) deploy_one "DeployEntitlementRegistry" "EntitlementRegistry" ;;
  all)
    # Per L1: 'all' deploys V1 then EntitlementRegistry in that order;
    # v0 is already deployed at D-014 and stays there.
    # F5: mainnet+all is refused above; only dev + sepolia reach this branch.
    deploy_one "DeployRevisionLogV1" "RevisionLogV1"
    deploy_one "DeployEntitlementRegistry" "EntitlementRegistry"
    ;;
esac

echo
echo "==> done"
