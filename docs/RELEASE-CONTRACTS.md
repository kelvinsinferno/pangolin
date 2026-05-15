# Pangolin Contract Deploy Runbook

> Operational runbook for the Pangolin contract deploy pipeline shipped
> by MVP-2 issue 2.3. Mirrors the structure of `docs/issue-plans/P5-4.md`
> (the v0 deploy precedent that landed D-014 + D-015) extended to cover
> three contracts (`RevisionLogV0`, `RevisionLogV1`, `EntitlementRegistry`)
> across three environments (`dev`, `sepolia`, `mainnet`).
>
> The single entry point is `scripts/deploy-contracts.sh`. The runbook
> below walks the pre-deploy checklist, per-environment invocations,
> post-deploy verification, failure-mode coverage, and the
> abort/rollback plan. **No mainnet deploy without D-011 (external audit)
> cleared + Kelvin authorization.**

## Overview

The deploy pipeline lands one or more of three contracts on one of three
networks:

| Contract | Source | Constructor args | Notes |
|---|---|---|---|
| `RevisionLogV0` | `contracts/src/RevisionLogV0.sol` | none | Already deployed at D-014 + D-015. The wrapper still supports `--contract v0` for completeness (e.g., another redeploy proof), but day-to-day flows do NOT re-run v0. |
| `RevisionLogV1` | `contracts/src/RevisionLogV1.sol` | none | The MVP-2 production log. Replaces v0 with signature verification (see 2.1 plan). |
| `EntitlementRegistry` | `contracts/src/EntitlementRegistry.sol` | `payment_authority`, `redemption_authority` (addresses) | The MVP-2 funder-service contract. On testnet both authorities are the pangolin-dev wallet (L8); on mainnet they MUST be distinct production keys (L8 collapse applies to testnet only). |

| Environment | RPC | Chain id | Keystore alias |
|---|---|---|---|
| `dev` | `http://127.0.0.1:8545` (local anvil) | 31337 | `anvil-default` (no passphrase) |
| `sepolia` | `https://sepolia.base.org` (default; override via `BASE_SEPOLIA_RPC_URL`) | 84532 | `pangolin-dev` (Kelvin's encrypted Foundry keystore) |
| `mainnet` | provided at deploy time via `BASE_MAINNET_RPC_URL` | 8453 | `pangolin-mainnet` (created just-in-time; hardware-wallet preferred) |

The wrapper enforces:

1. The `--env` argument matches one of the three values above.
2. Mainnet additionally requires `PANGOLIN_MAINNET_AUDITED=1` (L6 soft gate).
3. The env file at `contracts/deploy/.env.<env>` is present + sourced.
4. Required env vars (`RPC_URL`, `EXPECTED_CHAIN_ID`, `DEPLOYER_ACCOUNT`,
   and for the entitlement registry `PAYMENT_AUTHORITY` +
   `REDEMPTION_AUTHORITY`) are non-empty.
5. `cast chain-id --rpc-url $RPC_URL` matches `EXPECTED_CHAIN_ID`
   (skipped on `--dry-run`).
6. Deployer balance ≥ `MIN_DEPLOYER_BALANCE_WEI` (skipped on `--dry-run`
   or `--env dev`).
7. Real deploys (no `--dry-run`) on non-dev envs need an interactive
   terminal so `forge` can prompt for the keystore passphrase;
   `--unattended` aborts in that case.

## Pre-deploy checklist

Before invoking `scripts/deploy-contracts.sh`:

- [ ] `pangolin-dev` Foundry keystore present at
      `C:\Users\kelvi\.foundry\keystores\pangolin-dev` (Windows) or
      `~/.foundry/keystores/pangolin-dev` (POSIX). Verify with:
      ```bash
      cast wallet address --account pangolin-dev
      ```
      Must print `0x89e720238A3913688CB0E025ef03a64539575c54`.
- [ ] Base Sepolia balance ≥ 0.01 ETH at that address:
      ```bash
      cast balance 0x89e720238A3913688CB0E025ef03a64539575c54 \
        --rpc-url https://sepolia.base.org --ether
      ```
      Top up via the Coinbase Base Sepolia faucet if short.
- [ ] Foundry pinned at v1.0.0:
      ```bash
      forge --version
      cast --version
      ```
      Both must report `1.0.0-stable`. Bump in lockstep with CI per
      `pangolin_environment_quirks.md` #4.
- [ ] Source committed at the intended HEAD. The deploy is recorded
      against `git rev-parse HEAD`; if uncommitted changes exist the
      record cannot be reconstructed.
- [ ] `BASESCAN_API_KEY` exported in the deploy shell, if Basescan
      auto-verify is desired. Get a free key at
      https://basescan.org/myapikey. Without it the deploy proceeds
      with `--verify` disabled and the runbook's manual verification
      command (below) must be run separately.
- [ ] `BASE_SEPOLIA_RPC_URL` exported in the deploy shell, if using a
      private (Alchemy / Infura) RPC. The default public endpoint at
      `https://sepolia.base.org` is sometimes flaky under load.

## Dev environment (local anvil)

Useful for integration-testing the wrapper itself or sanity-checking a
contract change against a clean chain. Start anvil in a separate
terminal first:

```bash
anvil
```

### One-time anvil keystore setup

`.env.dev` references `DEPLOYER_ACCOUNT="anvil-default"` and the wrapper
passes `--account anvil-default` to forge (per L3 — never `--private-key`
on the command line). This requires a Foundry keystore alias named
`anvil-default`. Anvil's account 0 has a well-known private key; import
it once:

```bash
cast wallet import anvil-default --interactive
# When prompted for the private key, paste:
#   0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
# (the deterministic anvil-account-0 key; SAFE to commit/share —
#  it's the same one in every anvil instance worldwide)
# Set any passphrase you like; the `--unattended` flag below skips
# the passphrase prompt at deploy time.
```

This is a one-time setup; the alias survives across machine reboots.
Verify with `cast wallet list` — you should see `anvil-default (Local)`.

### Run the dev deploy

```bash
scripts/deploy-contracts.sh --env dev --contract all --unattended
```

The wrapper does NOT write `contracts/deployments/dev.json` because anvil
restarts re-issue the same nonce-0 address — recording would be
misleading.

To smoke-test the wrapper without an anvil running (e.g., as part of
a script-syntax check), use `--dry-run`:

```bash
scripts/deploy-contracts.sh --env dev --contract all --dry-run --unattended
```

Dry-run skips the chain-id check (since no RPC is contacted), the
balance check, and the keystore prompt. It still invokes `forge script`
which compiles the contracts + simulates the constructor in an
in-memory EVM. This is what CI runs in the `contracts-build` job.

## Sepolia (staging)

The documented production-testnet flow. **Deploy one contract at a
time** so the smoke-test + JSON-update for each lands cleanly:

```bash
# 1. Make sure BASESCAN_API_KEY is exported (or accept no-verify):
export BASESCAN_API_KEY="<your-basescan-key>"

# 2. Deploy RevisionLogV1:
scripts/deploy-contracts.sh --env sepolia --contract v1

# 3. Deploy EntitlementRegistry:
scripts/deploy-contracts.sh --env sepolia --contract entitlement
```

Each invocation:

1. Verifies chain id == 84532 against the RPC.
2. Reads the deployer address from the keystore alias (no passphrase
   needed for the address read).
3. Checks the deployer balance is ≥ 0.01 ETH (per
   `MIN_DEPLOYER_BALANCE_WEI` in `.env.sepolia`).
4. Prompts for the `pangolin-dev` keystore passphrase via forge's
   own prompt.
5. Broadcasts the deploy tx via `forge script ... --broadcast`.
6. Auto-verifies on Basescan if `BASESCAN_API_KEY` is non-empty.
7. Reads the deployed runtime bytecode via `cast code` + computes
   the Keccak-256 hash via `cast keccak`.
8. Runs a view-function smoke test (V1: `MAX_KNOWN_SCHEMA_VERSION` +
   `DOMAIN_SEPARATOR`; EntitlementRegistry: `MAX_KNOWN_SCHEMA_VERSION`
   + `PAYMENT_AUTHORITY` + `REDEMPTION_AUTHORITY`).
9. Atomically appends a record to
   `contracts/deployments/base-sepolia.json` under the contract name
   key (mirrors the existing `RevisionLogV0` shape).

The wrapper supports `--contract all` (V1 then EntitlementRegistry in
that order), but the documented testnet flow runs them sequentially so
each gets independent inspection.

### Recording the deploys

After a successful Sepolia deploy:

- **`contracts/deployments/base-sepolia.json` is updated automatically**
  by the wrapper. The shape mirrors the existing `RevisionLogV0`
  entry — address, deployer, deploy_tx, deploy_block, gas_used,
  deployed_at, compiler block, bytecode block (with
  `deployed_runtime_keccak256`), abi + source paths, `smoke_tests`
  block recording the view-function values, and `explorer_links` to
  Basescan.
- **`DECISIONS.md` D-017 + D-018 entries are written manually** because
  they carry prose rationale + a "Why:" section that the wrapper
  cannot author. Templates at the end of this runbook.

### Schema for the deployments record (informational)

The wrapper's `jq` invocation produces entries with the following
keys (the precedent is `RevisionLogV0` in
`contracts/deployments/base-sepolia.json`):

```json
{
  "address": "0x...",
  "deployer": "0x89e720238A3913688CB0E025ef03a64539575c54",
  "deploy_tx": "0x...",
  "deploy_block": 12345678,
  "deployed_at": "2026-MM-DDTHH:MM:SSZ",
  "gas_used": 422850,
  "compiler": {
    "name": "solc",
    "version": "0.8.24",
    "evm_version": "shanghai",
    "optimizer": true,
    "optimizer_runs": 200,
    "bytecode_hash": "none"
  },
  "bytecode": {
    "deployed_runtime_keccak256": "0x..."
  },
  "abi": "../abi/<Contract>.json",
  "source": "../src/<Contract>.sol",
  "smoke_tests": { /* contract-specific */ },
  "explorer_links": {
    "contract": "https://sepolia.basescan.org/address/0x...",
    "deploy_tx": "https://sepolia.basescan.org/tx/0x..."
  }
}
```

The EntitlementRegistry record additionally carries `constructor_args`
+ a `note` field documenting the L8 split-trust-collapsed-on-testnet
caveat.

## Mainnet (production)

**Gated on D-011 external audit clear + Kelvin authorization.** The
wrapper enforces the `PANGOLIN_MAINNET_AUDITED=1` env-var soft gate.
Mainnet contracts go live in production — every step deserves
hyper-care. **Deploy one contract at a time; NEVER use `--contract all`
on mainnet.**

### Mainnet pre-deploy checklist

- [ ] D-011 external audit report reviewed by Kelvin; all findings
      addressed; CHANGELOG / DEVLOG entries recording the post-audit
      changes landed.
- [ ] A separate `pangolin-mainnet` keystore alias exists, ideally
      backed by a hardware wallet:
      ```bash
      # Option A: import an existing Ledger as a Foundry alias
      cast wallet import pangolin-mainnet --ledger
      # Option B: generate a fresh keystore (less secure than Ledger)
      cast wallet new --keystore-dir ~/.foundry/keystores
      mv ~/.foundry/keystores/<generated-name> ~/.foundry/keystores/pangolin-mainnet
      ```
- [ ] Authority keys provisioned: the production `PAYMENT_AUTHORITY`
      (controlled by Kelvin's billing service) and the production
      `REDEMPTION_AUTHORITY` (controlled by the funder-service host)
      are distinct addresses. Get the address strings from those
      services + paste into `contracts/deploy/.env.mainnet` (created
      by copying the template).
- [ ] Sufficient deployer balance (≥ 0.1 ETH on mainnet to cover the
      higher gas baseline).
- [ ] Rehearsal complete on Sepolia: the entire flow above ran cleanly,
      D-017 + D-018 records exist, smoke tests passed.
- [ ] Mainnet RPC URL exported as `BASE_MAINNET_RPC_URL` (private
      Alchemy / Infura endpoint; never use a public mainnet RPC for
      production deploys).

### Mainnet deploy commands

```bash
# 1. Copy the template + fill in values:
cp contracts/deploy/.env.mainnet.template contracts/deploy/.env.mainnet
# (edit .env.mainnet to set PAYMENT_AUTHORITY + REDEMPTION_AUTHORITY)

# 2. Export the secrets:
export BASE_MAINNET_RPC_URL="https://base-mainnet.<your-rpc>.com/..."
export BASESCAN_API_KEY="<your-basescan-key>"
export PANGOLIN_MAINNET_AUDITED=1   # D-011 gate

# 3. Deploy v1 (one tx; verify before moving on):
scripts/deploy-contracts.sh --env mainnet --contract v1

# 4. Verify v1 on Basescan + run an extended smoke test before deploying
#    the registry. Compare runtime keccak256 against the Sepolia
#    deployment's hash — they must match (same compiler + source).

# 5. Deploy EntitlementRegistry:
scripts/deploy-contracts.sh --env mainnet --contract entitlement

# 6. Verify on Basescan. Announce the addresses publicly + update
#    consumer services (funder backend, billing) to point at them.
```

Post-deploy on mainnet:

- Write a D-NNN entry for each contract recording the address + tx +
  block + runtime hash + the audit-clear evidence.
- Update `contracts/deployments/base-mainnet.json` (the wrapper
  bootstraps the file if it doesn't exist).
- Announce on the channels consumers monitor (project README, status
  page, Discord/Telegram per channel policy).

## Post-deploy verification

The wrapper runs the smoke tests inline + records the results in the
JSON. For manual / independent verification:

### RevisionLogV1

```bash
# MAX_KNOWN_SCHEMA_VERSION (uint16)
cast call <V1_ADDRESS> "MAX_KNOWN_SCHEMA_VERSION()(uint16)" \
  --rpc-url https://sepolia.base.org
# Expected: 1

# DOMAIN_SEPARATOR (bytes32) — must be non-zero
cast call <V1_ADDRESS> "DOMAIN_SEPARATOR()(bytes32)" \
  --rpc-url https://sepolia.base.org
# Expected: 0x<non-zero 32-byte value>

# Runtime keccak256 — must match the recorded value in base-sepolia.json
cast keccak "$(cast code <V1_ADDRESS> --rpc-url https://sepolia.base.org)"
```

### EntitlementRegistry

```bash
cast call <REGISTRY_ADDRESS> "MAX_KNOWN_SCHEMA_VERSION()(uint16)" \
  --rpc-url https://sepolia.base.org
# Expected: 1

cast call <REGISTRY_ADDRESS> "PAYMENT_AUTHORITY()(address)" \
  --rpc-url https://sepolia.base.org
# Expected (testnet): 0x89e720238A3913688CB0E025ef03a64539575c54

cast call <REGISTRY_ADDRESS> "REDEMPTION_AUTHORITY()(address)" \
  --rpc-url https://sepolia.base.org
# Expected (testnet): 0x89e720238A3913688CB0E025ef03a64539575c54
```

### Basescan source-verified status

Open the explorer link from the JSON record + click the "Contract"
tab. A successfully auto-verified contract shows the "Contract Source
Code Verified (Exact Match)" banner + a "Read Contract" / "Write
Contract" interface. If the banner is missing or shows "unverified",
the auto-verify step failed; rerun verification manually:

```bash
forge verify-contract \
  --chain-id 84532 \
  --etherscan-api-key "$BASESCAN_API_KEY" \
  --verifier-url https://api-sepolia.basescan.org/api \
  <ADDRESS> \
  contracts/src/<Contract>.sol:<Contract>
```

For `EntitlementRegistry` add `--constructor-args $(cast abi-encode
"constructor(address,address)" <payment> <redemption>)`.

## Failure modes

| Failure mode | Mitigation |
|---|---|
| Wrong chain (deploys to mainnet by mistake when meaning to deploy to sepolia). | Wrapper's chain-id sanity check (`cast chain-id --rpc-url $RPC_URL` vs `EXPECTED_CHAIN_ID`) aborts BEFORE broadcasting. STOP rule explicit. |
| Wallet drained / insufficient funds. | Wrapper's deployer-balance check (`cast balance` vs `MIN_DEPLOYER_BALANCE_WEI`) aborts before broadcasting. |
| Bytecode drift between local build and audited artefact. | CI's `contracts-abi-drift` job catches ABI drift on every PR; the deploy compiles the same source the build job tests. Mainnet checklist includes manual byte-comparison against Sepolia. |
| Network failure mid-deploy. | `forge script --broadcast` waits for the tx to mine before returning. If the connection drops, the tx may still mine on chain — recovery: query Basescan for the tx by sender + nonce, capture the address from the contract-creation receipt, manually append the record to `base-sepolia.json`. |
| Replay of broadcast (re-running the same script after a failed broadcast). | Foundry's broadcast cache prevents accidental re-broadcast; a second run with the same nonce fails with `nonce too low` and the user moves on. |
| Smoke test fails post-deploy. | Wrapper aborts at the smoke-test step (non-zero exit) BEFORE writing the JSON record. STOP, diagnose, do NOT proceed to record the deployment as canonical. Most likely cause: a contract-source change broke the view function's signature. Re-audit + redeploy. |
| Basescan verification fails (compiler version mismatch, network issue). | Non-fatal — the wrapper still records the deploy + the runbook's manual `forge verify-contract` command is documented above. Re-attempt later. |
| Keystore passphrase forgotten. | One-way: re-import the key from the original source. For mainnet, this would be the hardware-wallet recovery seed. Operational, not a security failure. |
| Accidental mainnet deploy. | Wrapper aborts unless `PANGOLIN_MAINNET_AUDITED=1` (L6 gate). A development machine running the script defensively can never accidentally spend real ETH. |
| Compromised deployer key. | Keystore-encrypted at rest (scrypt + AES) with passphrase. Mainnet keystore is on hardware-wallet, so the private key is never exposed to the deploy host. |
| `base-sepolia.json` race / corruption. | Wrapper's JSON update uses `jq` to write to `.tmp` then `mv` atomically. Two concurrent deploys would conflict at the `mv` step but the underlying tx hashes are unique so no on-chain corruption occurs; the JSON conflict resolves by re-running the wrapper with the second contract after the first commits. |

## Abort / rollback

**Contracts are immutable.** There is no on-chain rollback. If a
deployed contract is found to be broken:

1. **Note the broken contract in `DECISIONS.md`** with a new D-NNN
   entry marked DEFUNCT, referencing the new D-NNN that supersedes
   it. The original record stays in `contracts/deployments/...json`
   as historical evidence.
2. **Deploy a v2** with the fix at a fresh address (mirrors D-015's
   redeploy-proof pattern for V0).
3. **Update consumers** (funder backend, billing service, `pangolin-chain`
   adapter, frontend) to point at the new address.
4. **Leave the old contract** on-chain as immutable historical record.
   Do NOT attempt admin-key recovery (Pangolin contracts have no admin
   keys by design per master plan §2).

If a pre-flight step in the wrapper fails (chain-id mismatch, balance
shortfall, env-file missing, smoke-test fail): STOP, diagnose, fix
the root cause, re-run. No on-chain state changed — nothing to roll
back.

## Operational notes

### Gas-price strategy

Base Sepolia gas prices are typically < 1 gwei. If a congestion event
pushes prices higher, override via forge's `--gas-price` flag:

```bash
# (Add to FORGE_FLAGS in the wrapper, or invoke forge directly per
#  the runbook's manual fallback.)
forge script ... --gas-price 5000000000   # 5 gwei
```

For mainnet, the deploy script can prefix `--with-gas-price` via env
override; the default behavior (no explicit gas price) lets Foundry
read the gas-price oracle.

### RPC reliability

The public `https://sepolia.base.org` endpoint is sometimes flaky under
load. Set `BASE_SEPOLIA_RPC_URL` to a private RPC for production
testnet deploys:

```bash
export BASE_SEPOLIA_RPC_URL="https://base-sepolia.g.alchemy.com/v2/<api-key>"
```

The wrapper picks it up via the env-var substitution in `.env.sepolia`.

### Wrapper development

When changing `scripts/deploy-contracts.sh` itself, use `--dry-run` to
exercise the flow without touching chain state:

```bash
scripts/deploy-contracts.sh --env dev --contract all --dry-run --unattended
scripts/deploy-contracts.sh --env sepolia --contract v1 --dry-run --unattended
```

(Sepolia dry-run needs the env file but skips chain-id check + balance
check + keystore prompt — it only verifies the script parses flags +
sources env vars + invokes forge correctly.)

The CI `contracts-build` job runs the dev dry-run on every PR. Any
script regression that breaks dry-run breaks CI.

## Appendix A: D-017 + D-018 template

After a successful Sepolia deploy of V1 + EntitlementRegistry, paste
the following into `DECISIONS.md` (after D-016), substituting the
placeholders with the values from the wrapper's output + the
`contracts/deployments/base-sepolia.json` record:

```markdown
## D-017 · MVP-2 RevisionLogV1 deployed address (Base Sepolia)
**Date locked:** 2026-MM-DD
**Decision:** `RevisionLogV1` deployed at `0x<addr>` on Base Sepolia
(chain id `84532`). Deploy tx `0x<tx>` in block `<block>`. Deployer:
`0x89e720238A3913688CB0E025ef03a64539575c54` (pangolin-dev wallet, same
as D-014 + D-015 per R-a of 2.3). Runtime keccak256 (Ethereum
Keccak-256): `0x<keccak>`. Smoke-tested post-deploy:
`MAX_KNOWN_SCHEMA_VERSION()` returns `1`; `DOMAIN_SEPARATOR()` returns
a non-zero 32-byte value. Basescan auto-verified at deploy time
(verifier-url `https://api-sepolia.basescan.org/api`).
**Why:** Per master plan §4 row 2.3 + L7 of `docs/issue-plans/2.3.md`.
V1 supersedes V0 (D-014) as the MVP-2 production log; both contracts
remain on chain (D-014 is immutable) but consumers (pangolin-chain
adapter, the upcoming MVP-2 integration issue) point at the V1
address. Pangolin-dev wallet reused per R-a so deployer attribution
stays coherent across V0 → V1.
**Spec ref:** Master plan §4 row 2.3; `docs/issue-plans/2.3.md` L7;
full metadata in `contracts/deployments/base-sepolia.json` under the
`RevisionLogV1` key.

## D-018 · MVP-2 EntitlementRegistry deployed address (Base Sepolia)
**Date locked:** 2026-MM-DD
**Decision:** `EntitlementRegistry` deployed at `0x<addr>` on Base
Sepolia (chain id `84532`). Deploy tx `0x<tx>` in block `<block>`.
Deployer: `0x89e720238A3913688CB0E025ef03a64539575c54` (pangolin-dev
wallet, per R-a of 2.3). Runtime keccak256 (Ethereum Keccak-256):
`0x<keccak>`. Constructor args: `PAYMENT_AUTHORITY = REDEMPTION_AUTHORITY
= 0x89e720238A3913688CB0E025ef03a64539575c54` (pangolin-dev wallet for
BOTH per R-b + L8 of 2.3 — collapses 2.2's split-trust on testnet only;
production split keys ship with MVP-2 issue 3.4). Smoke-tested
post-deploy: `MAX_KNOWN_SCHEMA_VERSION()` returns `1`;
`PAYMENT_AUTHORITY()` + `REDEMPTION_AUTHORITY()` both return the
pangolin-dev wallet address. Basescan auto-verified at deploy time.
**Why:** Per master plan §4 row 2.3 + L7 + L8 of
`docs/issue-plans/2.3.md`. This is the testnet smoke-test instance; a
fresh EntitlementRegistry with real split authority keys deploys with
MVP-2 issue 3.4 (funder service). This contract is NOT wired to any
production payment flow.
**Spec ref:** Master plan §4 row 2.3; `docs/issue-plans/2.3.md` L7 + L8;
full metadata in `contracts/deployments/base-sepolia.json` under the
`EntitlementRegistry` key.
```

## D-019 split-key EntitlementRegistry redeploy (MVP-2 issue 3.4 follow-up)

> **Status:** Template only — code merged in 3.4; the actual deploy +
> address is the operational follow-up Kelvin runs after merge.

### Why a redeploy

D-018 deployed with `PAYMENT_AUTHORITY = REDEMPTION_AUTHORITY =
pangolin-dev` (collapsed authorities). The 2.2 split-trust property is
load-bearing for the funder threat model (L-funder-wallet-key-leak —
the redemption authority compromise must not also let the attacker
inflate balances via `credit`). 3.4 ships the funder code; the
operational follow-up deploys a fresh `EntitlementRegistry` instance
with two distinct authority addresses.

### Steps

1. **Create the funder keystore** (one-time):

   ```bash
   cast wallet new --keystore-dir ~/.foundry/keystores --name pangolin-funder-dev
   # Note the passphrase + the printed address.
   ```

2. **Fund the funder wallet** via the Base Sepolia faucet
   (https://www.coinbase.com/faucets/base-ethereum-goerli-faucet). At
   minimum ~0.05 ETH for steady-state operation; the cold-wallet refill
   discipline is the 18.5 runbook's job.

3. **Update `contracts/deploy/.env.sepolia`** with the new authority
   variables (the file already has the placeholder block from 3.4).

4. **Deploy** via the existing wrapper, overriding the constructor args
   (`scripts/deploy-contracts.sh --env sepolia --contract entitlement`).

5. **Update `contracts/deployments/base-sepolia.json`** — replace or
   shadow the D-018 `EntitlementRegistry` entry with the D-019 address +
   deploy metadata. The funder reads from this file via
   `load_deployed_address`.

6. **Re-pin the EIP-712 constants** in
   `crates/pangolin-chain/src/secp256k1_signing.rs`:
   - `EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA` → new D-019
     address.
   - `ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1` → re-captured via
     `cast call <D-019 addr> "DOMAIN_SEPARATOR()(bytes32)"`.
   The `redemption_domain_separator_matches_pinned_constant` hermetic
   test will fail loudly if the constants drift from the on-chain
   value.

7. **Smoke-test** the new contract via `cast call` for `PAYMENT_AUTHORITY()`
   and `REDEMPTION_AUTHORITY()` views.

8. **Record D-019** in `DECISIONS.md` (template below) + add to
   `DEVLOG.md` as the post-deploy follow-up entry.

### D-019 entry template

Copy this into `DECISIONS.md` after deploy:

```
## D-019 · EntitlementRegistry redeploy on Base Sepolia with split authorities

**Date locked:** 2026-MM-DD

**Decision:** `EntitlementRegistry` redeployed at `0x<addr>` on Base
Sepolia (chain id `84532`). Deploy tx `0x<tx>` in block `<block>`.
Deployer: `0x89e720238A3913688CB0E025ef03a64539575c54` (pangolin-dev
wallet). Runtime keccak256: `0x<keccak>`. Constructor args:
`PAYMENT_AUTHORITY = 0x89e720238A3913688CB0E025ef03a64539575c54`
(pangolin-dev, testnet smoke-billing); `REDEMPTION_AUTHORITY =
0x<funder-addr>` (pangolin-funder-dev wallet, real split-key per 3.4
R-d). Smoke-tested post-deploy: `PAYMENT_AUTHORITY()` +
`REDEMPTION_AUTHORITY()` views match constructor args;
`DOMAIN_SEPARATOR()` matches the freshly-pinned
`ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1` constant.

**Why:** Per master plan §4 row 3.4 + R-d of `docs/issue-plans/3.4.md`.
D-018 collapsed authorities for the smoke-test pass; D-019 ships real
split keys so the funder service's `REDEMPTION_AUTHORITY` cannot also
mint credits via `credit`. D-018 stays untouched as historical record.

**Spec ref:** Master plan §4 row 3.4; `docs/issue-plans/3.4.md` R-d;
`docs/architecture/funder-service.md`; full metadata in
`contracts/deployments/base-sepolia.json` under the `EntitlementRegistry`
key (replaces / shadows D-018 entry).
```
