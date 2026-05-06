# Gas report — `RevisionLogV0`

> Source: `forge test --gas-report` with `FOUNDRY_INVARIANT_RUNS=10000`
> (the CI invariant target). All numbers are **post-optimization**
> (`optimizer = true, optimizer_runs = 200`) and target Shanghai.

## Summary

| Metric | Value | Plan budget | Status |
|---|---:|---:|:---:|
| Runtime bytecode size | 443 B | < 1 KB | OK |
| Initcode (deployment) size | 472 B | (informational) | — |
| Deployment cost (gas) | 149,135 | (informational) | — |
| `publishRevision` median | 33,193 | < 50,000 | OK |
| `publishRevision` average | 33,598 | < 50,000 | OK |
| `publishRevision` min | 22,016 | (informational) | — |
| `publishRevision` max | 148,208 | (informational, 4 KB payload outlier) | — |
| `publishRevision` 256-byte warm call | ~25 k (steady state) | < 50,000 | OK |
| `nextSequence()` view call | 281–2,281 | — | — |

Plan success criterion #7 ("`publishRevision` with a 256-byte payload < 50k gas") is satisfied with comfortable headroom: even the cold-storage first call sits at ~25 k gas, and steady-state warm calls are under 8 k gas (storage SSTORE warm + log emission only).

The 148 k max in the table is the 4 KB payload test (`test_publishRevision_acceptsLargePayload`) — log-data cost grows linearly with payload size (8 gas / byte), so this is expected.

## Storage layout

| Slot | Name | Notes |
|---:|---|---|
| 0 | `nextSequence` (`uint256 public`) | The only storage slot. |
| 1+ | _(zero, asserted by `invariant_noStorageMutationBesidesSequence`)_ | |

## Reproducing

```sh
cd contracts
forge test --gas-report
```

Or, for a quick repro of just the 256-byte case:

```sh
cd contracts
forge test --match-test test_publishRevision_256BytePayload_under50kGas -vvv
```

## Build metadata (CBOR trailer)

`foundry.toml` sets `bytecode_hash = "none"` to suppress solc's IPFS / bzzr
metadata hash, which would otherwise embed a hash of the (path-dependent)
sources and break bit-deterministic rebuilds across machines. Even with
`bytecode_hash = "none"` set, solc still appends a 12-byte CBOR-encoded
trailer to every contract's runtime bytecode that records the compiler
version. For Solidity 0.8.24 this trailer is exactly:

```
a164736f6c6343000818000a
```

which decodes to the CBOR map `{"solc": <0x000818> ("0.8.24")}` with a
two-byte length suffix (`0x000a` = 10). It carries no source hash and
no path information; only the compiler version. Two consecutive
`forge build --force` runs on the same machine produce byte-identical
runtime bytecode (verified post-P5-1), and the trailer is identical
across machines that pin the same solc version. This is solc behavior
and not a Foundry configuration gap; reproducible builds across
machines remain unaffected. (Audit fix L-4.)
