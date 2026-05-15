# Privacy mitigation (Phase-2 hook scaffolding)

> **Scope:** MVP-2 issue 3.6 — the trait / enum / fail-loudly stub
> scaffolding that Phase-2 Enhanced Privacy Mode (per-revision wallet
> rotation; CoinJoin pre-mixing of funder top-ups; optional fresh-
> address-per-vault) plugs into when MVP-3 / MVP-4 lands. **NO
> production logic for any rotation / mixing / fresh-address behavior
> ships in 3.6.** This document records the architectural-locking
> shape that ships; the Phase-2 implementation roadmap lives at the
> bottom.
>
> Source: `crates/pangolin-chain/src/privacy/{mod.rs, default.rs,
> enhanced.rs, tests.rs}`. Spec references: Whitepaper §8.3, master
> plan §5 row 3.6, D-006 (on-chain observability mitigation).

## What 3.6 ships

Three publicly-exported items from `pangolin-chain`:

1. **`PrivacyMode` enum** — the user-facing privacy-mode knob.
   ```rust
   pub enum PrivacyMode {
       Default,          // bit-for-bit 3.5 behaviour (no-op)
       EnhancedPrivacy,  // Phase-2 mode; currently fail-loudly stubbed
   }
   ```
   Variants are stable APIs (L3); renaming them is a BREAKING change
   to Phase-2 work.

2. **`PrivacyStrategy` trait** — the internal hook-points contract
   Phase-2 will pin against. Three methods, one per master plan §5 row
   3.6 mode:
   ```rust
   pub trait PrivacyStrategy: Send + Sync {
       fn derive_wallet_for_revision(
           &self,
           device_key: &DeviceKey,
           revision_index: u64,
       ) -> Result<EvmWallet, PrivacyError>;

       fn transform_funder_response(
           &self,
           funder_response: FunderResponseShape,
       ) -> Result<FunderResponseShape, PrivacyError>;

       fn select_address_for_vault(
           &self,
           vault_id: [u8; 32],
           default_address: Address,
       ) -> Result<Address, PrivacyError>;
   }
   ```
   Method signatures are stable APIs (L3); renaming or re-shaping
   their arguments is a BREAKING change to Phase-2 work.

3. **Two impls**:
   - `DefaultStrategy` — verbatim no-op. Returns the existing single
     device wallet, the funder response unchanged, the default
     address. Bit-for-bit equivalent to 3.5 (L1 + L4).
   - `EnhancedPrivacyStrategy` — fail-loudly stub. Every hook returns
     `Err(PrivacyError::NotYetImplemented { mode: EnhancedPrivacy,
     hook: "<method-name>" })` BEFORE doing any work (L7).

`FunderResponseShape` is a local marker shape inside
`pangolin-chain::privacy` carrying the two load-bearing fields the
real `pangolin_funder_client::TopUpResponse` carries (`tx_hash` +
`eth_transferred_wei`). It exists to avoid a circular dep
(`pangolin-funder-client → pangolin-chain → pangolin-funder-client`)
— the actual funder-client crate does not depend on `pangolin-chain`
in its production tree. Phase-2 may promote this to a richer shape;
3.6 deliberately keeps it minimal.

## L1..L7 invariants (load-bearing)

| # | Invariant | Where it lives |
|---|---|---|
| **L1** | ZERO production logic for rotation / mixing / fresh-address. `DefaultStrategy` is a verbatim no-op preserving 3.5 behaviour bit-for-bit. | `crates/pangolin-chain/src/privacy/default.rs` — every hook body is one line by design. |
| **L2** | No new external crate dep. All scaffolding uses primitives already in the workspace (`alloy`, `thiserror`, `pangolin-crypto`). | env-quirk #15 advisories check is not triggered. |
| **L3** | Hook signatures are stable APIs. Phase-2 (MVP-3 / MVP-4) will pin against them. Renaming a hook = BREAKING change to Phase-2 work. | Pinned by the variant-label test + the byte-identity test (drift in shape would fail one of the two). |
| **L4** | ZERO observable difference from 3.5 when `PrivacyMode::Default` is selected. Bytewise-identical signatures, calldata, balance-state outputs. | The byte-identity test `default_strategy_revision_signature_matches_pre_3_6_baseline` is the mechanical lock; CI re-runs it every PR. |
| **L5** | `forbid(unsafe_code)` preserved on every NEW `.rs` file. AGPL-3.0-or-later SPDX header on every new file. HIGH-1 + Q3 + L7 of prior issues preserved. | Mechanical; covered by CI. |
| **L6** | No schema migration. The scaffolding is compile-time abstractions only; no `.pvf` changes. | §18.7 schema-version stays at the 3.5 value. |
| **L7** | `EnhancedPrivacy` MUST fail loudly when instantiated. Silent fallback to `Default` is REJECTED. | `crates/pangolin-chain/src/privacy/enhanced.rs` + three fail-loudly tests in `tests.rs`. |

## Why this ships in MVP-2 (not deferred to MVP-3 / MVP-4)

The point is **architectural locking**: the hook shapes get pinned
while §3.x is fresh in everyone's head, so when Phase-2 actually
lands in a later MVP the surfaces don't need to be re-shaped.

The bytewise-identity fixture test is the load-bearing property: if
the no-op default path is verifiably bit-equivalent to the 3.5
baseline, then 3.6 is provably a no-op at the byte level. Phase-2
implementers can add real logic to `EnhancedPrivacyStrategy` (or to a
new strategy impl that the `PrivacyMode::EnhancedPrivacy` adapter
maps to) without having to refactor consumer crates.

## Consumer-crate hook points (R-c distributed-impl pattern)

3.6 scaffolding ships the trait + impls in `pangolin-chain::privacy`.
Consumer crates DO NOT yet thread `&dyn PrivacyStrategy` parameters
through their production fn signatures — that's Phase-2 work. What
3.6 verifies is that consumers CAN construct + call the trait from
their test boundaries today:

- **`pangolin-chain::secp256k1_signing`** — `issue_3_6_default_strategy_yields_same_signed_revision`
  test pins the signing-primitive consumer boundary: a
  `SignedRevisionV1` built with `DefaultStrategy::derive_wallet_for_revision`
  equals one built with the direct `derive_evm_wallet` call.
- **`pangolin-store::Vault`** — two tests pin the store consumer
  boundary: `issue_3_6_default_strategy_select_address_for_vault_is_pass_through`
  + `issue_3_6_default_strategy_derive_wallet_matches_vault_wallet`.
- **`pangolin-funder-client`** — `issue_3_6_default_strategy_transform_funder_response_is_pass_through`
  pins the funder-client consumer boundary. The dev-dep on
  `pangolin-chain` is scoped to tests; production funder-client does
  NOT depend on `pangolin-chain` (the crate's L1 invariant is
  preserved).

## Phase-2 implementation roadmap (deferred to MVP-3 / MVP-4)

3.6 scaffolds three Phase-2 modes per master plan §5 row 3.6. Each
mode's actual implementation lives in a future issue:

1. **Per-revision wallet rotation.** A Phase-2 implementer replaces
   `EnhancedPrivacyStrategy::derive_wallet_for_revision`'s body to
   derive a fresh EVM wallet keyed by `revision_index`. The exact
   key scheme (sequence number vs vault-keyed index) is a Phase-2
   decision; 3.6 names it `revision_index: u64` so either path is
   shapable. The revision-signing path
   (`pangolin-chain::secp256k1_signing::build_signed_revision_v1`)
   today takes a `&EvmWallet` parameter; Phase-2 will inject the
   per-revision wallet via the orchestrating caller (no signature
   change to `build_signed_revision_v1`).

2. **CoinJoin pre-mixing of funder top-ups.** A Phase-2 implementer
   wires a concrete CoinJoin client (Whirlpool / JoinMarket / etc.)
   into `EnhancedPrivacyStrategy::transform_funder_response`. The
   concrete mixer choice is its own audit-gated decision; 3.6 ships
   the hook surface only. The `FunderResponseShape` marker may
   promote to a richer type at that point.

3. **Optional fresh-address-per-vault.** A Phase-2 implementer wires
   `EnhancedPrivacyStrategy::select_address_for_vault` to derive a
   vault-keyed address. Address aggregation (balance reads across N
   derived wallets) is a separate Phase-2 plumbing problem.

## Whitepaper §8.3 vs master plan §5 row 3.6 — the documented gap

Whitepaper §8.3 names only **CoinJoin mixing of on-chain updates /
commitments**. Master plan §5 row 3.6 expands this to THREE modes
(per-revision wallet rotation + CoinJoin pre-mixing of funder top-ups
+ optional fresh-address-per-vault). 3.6 scaffolds all three per the
master plan, with §8.3 cited as the broader Whitepaper-level posture.
The Phase-2 issue that lands the real impl will reconcile the formal
spec.

## See also

- `docs/issue-plans/3.6.md` — the plan-gate doc with Q-a..Q-d /
  R-a..R-d / L1..L7 verbatim.
- `THREAT_MODEL.md` — the "Privacy Mitigation Phase-2 hooks (3.6
  scaffolding)" per-component row.
- `DECISIONS.md` — D-row recording R-a..R-d.
- `docs/architecture/device.md` — §6 "EVM wallet (MVP-2 issue 3.2)"
  documents the device wallet lifecycle that the 3.6 hooks will
  Phase-2-rotate.
