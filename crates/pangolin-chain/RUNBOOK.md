<!--
SPDX-License-Identifier: AGPL-3.0-or-later

Issue #98 (2026-05-18): operator-facing runbook for the two
live-chain checks previously embedded as empty `#[test]` bodies in
`src/secp256k1_signing.rs`. The L-empty-test-body class hazard
(test functions whose bodies are `{}` or `{ // ... }`-only register
"passing" without checking anything) is replaced here with explicit
operator guidance.

The hermetic CI tests
`domain_separator_matches_pinned_constant` (D-017) +
`redemption_domain_separator_matches_pinned_constant` (D-019)
remain the load-bearing PR-time defense. The cast calls below are
the symmetric live-chain cross-checks an operator runs as part of
pre-merge / pre-release verification, NOT a one-shot CI gate.
-->

# pangolin-chain — operator runbook

This runbook lives next to the source because it documents
operator-facing actions that are too small / too low-frequency to
warrant an `#[ignore]`'d test scaffold, but too security-sensitive
to leave to "remembered tribal knowledge."

Run each section before merging a cycle that touches the
corresponding constant; if mismatch, **file a bug** and DO NOT
merge until the constant and the live chain agree.

## 1. RevisionLogV1 (D-017) domain separator cross-check

**Pinned constant.** `DOMAIN_SEPARATOR_BASE_SEPOLIA_V1` in
[`src/secp256k1_signing.rs`](src/secp256k1_signing.rs) at line ~116.

**Operator command.**

```bash
cast call 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42 \
  "domainSeparator()(bytes32)" \
  --rpc-url https://sepolia.base.org
```

**Expected output (verbatim).**

```
0x9d1538887c3954f21ebe2602655bba85334719e130e5ba4a5c729bde968f0c62
```

**If mismatch.** The deployed contract's domain separator no longer
matches the pinned constant. Either (a) the contract was redeployed
at the same address (impossible for a normal EVM deploy, but worth
checking) or (b) the cast tool returned an unexpected encoding.
**File a bug** referencing this runbook section + the actual cast
output. Do NOT update the constant blindly — investigate first.

## 2. EntitlementRegistry (D-019) domain separator cross-check

**Pinned constant.** `ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1`
in [`src/secp256k1_signing.rs`](src/secp256k1_signing.rs) at line
~1051.

**Operator command.**

```bash
cast call 0xdDa04e427e95e50Cfd22703A76CAE2E1Da4F5fCD \
  "DOMAIN_SEPARATOR()(bytes32)" \
  --rpc-url https://sepolia.base.org
```

**Expected output (verbatim).**

```
0xb33d25188e5fc32cf5021ce63f28ee4ffb13d1d9a4ca720c46272f4c87c42fd0
```

**If mismatch.** Same disposition as section 1. Common cause: a
redeploy without updating the pinned constant or the JSON record.
The hermetic `redemption_domain_separator_matches_pinned_constant`
test would have caught a JSON drift at PR time; a true live drift
means the contract address changed.

## 3. D-019 REDEMPTION_AUTHORITY cross-check

**Constant location.** `constructor_args.redemption_authority` field
of the `EntitlementRegistry` record in
[`../../contracts/deployments/base-sepolia.json`](../../contracts/deployments/base-sepolia.json).

**Operator command.**

```bash
cast call 0xdDa04e427e95e50Cfd22703A76CAE2E1Da4F5fCD \
  "REDEMPTION_AUTHORITY()(address)" \
  --rpc-url https://sepolia.base.org
```

**Expected output (verbatim).**

```
0xaeE7E9bf859d938CB087D1e567221cffba9455AC
```

**If mismatch.** A different address means the contract isn't
D-019 (the constructor immutables can't change). Confirm contract
address via the deployment record + file a bug if the addresses
match but the authority diverges.

## 4. D-017 deploy block cross-check (issue #98 regression guard)

The Rust constant `pangolin_chain::d017_deploy_block(BaseSepolia)`
+ the JSON record's `RevisionLogV1.deploy_block` BOTH rotted in
the pre-#98 codebase. The hermetic
`deployment_json_pins_match_rust_constants` test pins them together
at PR time; this runbook section is the chain-level cross-check.

**Operator commands.**

```bash
# Should return the deployed runtime bytecode (NON-empty):
cast code 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42 \
  --block 41507120 \
  --rpc-url https://sepolia.base.org

# Should return 0x (empty, pre-deploy):
cast code 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42 \
  --block 41507119 \
  --rpc-url https://sepolia.base.org
```

**If mismatch.** Either the contract was redeployed (the constant
needs re-derivation via binary search) or the RPC is serving stale
data. The hermetic test on the JSON⇔Rust agreement is the first
line of defense; this cast call confirms the JSON itself matches
chain truth.

## 5. Fixture provenance audit

When a new D-XXX deploy lands (per issue #98 R-c Option ζ), fixtures
under `crates/*/tests/fixtures/**/*.meta.toml` must be recaptured.
Audit:

```bash
# List every fixture + its claimed cast command:
grep -rn "cast_command" crates/*/tests/fixtures/ 2>/dev/null
```

For each `.meta.toml`, the audit shape is:

- `cast_command` starts with literal `cast ` (no in-tree adapter)
- `capture_utc` is within the freshness window for the deploy
- `live_block_at_capture` is at or after the contract's deploy_block
- `sha256_of_fixture` matches the sibling fixture file's actual hash
