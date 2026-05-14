# Revision signing (Ed25519 v0 retained read-back + secp256k1 EIP-712 v1)

> Implements master plan §3.7 client-side signing + MVP-2 issue 3.1
> (R-a..R-e signed off by Kelvin 2026-05-14). Frozen plan:
> `docs/issue-plans/3.1.md`. Plan-gate doc enumerates L1..L11 invariants
> + the L-* adversarial risk register; this doc is the architectural
> overview pointing into the source.

## Two coexisting paths

Pangolin's revision-signing surface ships in two **non-interchangeable**
shapes that live side-by-side per R-b:

| Path | Primitive | Sig size | Domain prefix (off-chain) | Module |
|---|---|---|---|---|
| **v0** (legacy) | Ed25519 over a `keccak`-domain-prefixed canonical hash | 64 bytes | `pangolin-chain-signed-revision-v0` | `pangolin-chain::signing` |
| **v1** (3.1+) | secp256k1 over an EIP-712 typed-data digest | 65 bytes (`r ‖ s ‖ v`) | `pangolin-chain-signed-revision-v1` | `pangolin-chain::secp256k1_signing` |

**Why both ship.** Per R-a (clean break) v0 `SignedRevision` records in
legacy PoC `.pvf` files stay readable client-side via the retained
Ed25519 verification path but are **never re-broadcast** under v1; v1
publishes start a fresh per-vault sequence on chain. Per R-b the v0
signing module stays unchanged so the 22 existing v0 callsites in
`apps/cli/src/sync.rs` continue to work for legacy ingest / read-back.

The two paths do not share types. `SignedRevision` (v0) and
`SignedRevisionV1` (3.1) are distinct structs; a caller cannot
accidentally publish a v0 record under v1's API or vice versa. The
type-system boundary is the clean-break enforcement.

## v1 EIP-712 envelope (L2 + L3 verbatim)

The deployed `RevisionLogV1` contract at
`0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` (D-017, Base Sepolia,
chain_id 84_532) `ecrecover`s every revision against this envelope:

```
domain = EIP712Domain(
    name              = "Pangolin RevisionLog",
    version           = "1",
    chainId           = 84_532,
    verifyingContract = 0x179362Ad7fb7dA664312aEFDdaa53431eb748E42,
)
typehash = keccak256(
    "Revision(bytes32 vaultId,bytes32 accountId,bytes32 parentRevision,bytes32 deviceId,uint16 schemaVersion,bytes32 encPayloadHash)"
)
structHash = keccak256(abi.encode(
    typehash,
    vaultId,        // bytes32
    accountId,      // bytes32
    parentRevision, // bytes32
    deviceId,       // bytes32 (Path B: left-padded EVM address)
    schemaVersion,  // uint16 (encoded left-padded to bytes32)
    encPayloadHash, // bytes32 (= keccak256(encPayload))
))
digest = keccak256(0x1901 || domainSeparator || structHash)
```

The `digest` is what the wallet's secp256k1 key signs. Per R-e two
constants are pinned in Rust source:

- `REVISION_TYPEHASH_V1 = 0x240c1b72b1e92476cf861a8c19ed0f617734c55e97342ad6f99ed18467b8d211`
  (the keccak of the typehash literal above; cross-checked by the
  `typehash_matches_pinned_constant` hermetic test).
- `DOMAIN_SEPARATOR_BASE_SEPOLIA_V1 = 0x9d1538887c3954f21ebe2602655bba85334719e130e5ba4a5c729bde968f0c62`
  (captured from `cast call ... domainSeparator()` on D-017 at 3.1
  plan-gate time 2026-05-14; cross-checked by the
  `domain_separator_matches_pinned_constant` test which constructs the
  domain via alloy's `eip712_domain!` macro).

## 65-byte signature shape (L1)

The signature is laid out as `r (32) ‖ s (32) ‖ v (1)` with:

- `v ∈ {27, 28}` — the legacy non-EIP-155 form. EIP-712 typed-data
  binds the chain id into the domain separator, NOT into `v`.
- `s ≤ secp256k1n/2` — canonical-low-s per EIP-2 / EIP-2098. Enforced
  defensively via `Signature::normalize_s()` even though k256 0.13.x
  produces low-s by default; the on-chain contract rejects high-s
  sigs (contract line 433) so this is a load-bearing structural
  invariant, not a cosmetic detail.

## Caller flow (production)

```text
caller fills RevisionFieldsV1 {
    vault_id, account_id, parent_revision,
    device_id = left-pad-20(wallet.address()),  // R-a Path B
    schema_version, enc_payload_hash,           // = keccak256(encPayload)
}
        │
        ▼
Vault::sign_revision_v1(fields, ChainEnv::BaseSepolia)
        │  (calls require_active() — L5 session gate)
        ▼
pangolin_chain::build_signed_revision_v1(&EvmWallet, fields, env)
        │  (1) load_deployed_address(env, "RevisionLogV1")
        │  (2) assert == EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA
        │      (L-domain-binding cross-check)
        │  (3) construct domain via eip712_domain!
        │  (4) struct_hash(fields)
        │  (5) digest = keccak(0x1901 || sep || struct_hash)
        │  (6) wallet.signer().sign_hash_sync(&digest) → 65-byte sig
        │  (7) defensive normalize_s + structural asserts
        ▼
SignedRevisionV1 { fields, signature: [u8; 65] }
        │
        ▼
(MVP-2 issue 3.3 broadcast layer consumes this output verbatim:
 abi.encodeCall(publishRevision, (fields..., signature)) → eth_sendRawTransaction)
```

## What 3.1 does NOT ship

Per the master plan scope-discipline + the plan-gate Out-of-scope list:

- **No on-chain broadcast.** That's MVP-2 issue 3.3 (direct-submit
  transport). 3.1 produces the bytes; 3.3 sends them.
- **No Rust verifier.** Per R-d, the production verifier ships with
  MVP-2 issue 4.1 (slow-mode chain sync, the first downstream
  consumer). 3.1 has a `#[cfg(test)] fn recover_v1_for_test(...)` for
  hermetic round-trip coverage; that helper is NOT in the public API.
- **No chain-sync read path.** MVP-2 issues 4.1 / 4.2.
- **No re-sign migration of legacy v0 PoC records.** Per R-a (clean
  break), v0 records stay orphaned; nothing in 3.1 walks the
  `revisions` table.

## Test surface

Hermetic-only per R-e; no live RPC in CI. The `#[ignore]` integration
test `cross_check_against_live_d017` is a runbook entry the builder
runs locally before merge to spot-check that the pinned constants
still match the deployed contract's `domainSeparator()` view fn.

See `crates/pangolin-chain/src/secp256k1_signing.rs` `#[cfg(test)]
mod tests` for the full enumeration:

- `typehash_matches_pinned_constant`
- `domain_separator_matches_pinned_constant`
- `build_signed_revision_v1_produces_65_byte_sig`
- `build_signed_revision_v1_canonical_s`
- `build_signed_revision_v1_v_in_27_or_28`
- `recover_v1_for_test_round_trip`
- `per_field_tamper_changes_signer` (all 6 fields)
- `wrong_chain_id_produces_different_signer`
- `canonical_s_boundary`
- `#[ignore]` `cross_check_against_live_d017`

Session-gate coverage lives in
`crates/pangolin-store/src/vault.rs::tests::sign_revision_v1_requires_active_session`:
three legs (Locked / Active / idle-expired) mirroring the existing
`evm_wallet_accessor_works_on_active_only` shape.

## Why no FFI changes

3.1 stays inside Rust core per the 1.5 + 3.2 doctrine
(`docs/architecture/ffi-surface.md`). The signing surface is
session-gated via `Vault::sign_revision_v1` which is reachable only
from the same Rust callers that already hold a `Vault` handle. The
host UI never sees the secp256k1 scalar; only the produced 65-byte
signature crosses any boundary, and that crossing happens through the
broadcast layer (3.3) which lives entirely below Rust core too.
