# Funder service — one-way ETH dispenser (MVP-2 issue 3.4)

> **Status:** Code merged 2026-05-15. D-019 split-key redeploy is the
> operational follow-up; D-018 stays as the smoke-test instance.
>
> **Reach:** the funder service lives at `services/funder/` and is the
> FIRST off-chain HTTP service in the Pangolin codebase. It is a
> standalone tokio binary; the rest of the codebase reaches it only via
> the wire protocol defined in `crates/pangolin-funder-client/`.

## One-line scope

A long-running daemon that (a) accepts a top-up request from a device,
(b) verifies a signed `Credit` attestation from `PAYMENT_AUTHORITY` plus
a client-signed device-binding proof, (c) signs and submits a
`Redemption` attestation as the contract `REDEMPTION_AUTHORITY` to
decrement the user's on-chain balance, (d) sends ETH to the requesting
device wallet (ETH-transfer leg deferred to the L-payment-order
operational hardening — see "Out of scope" below), and (e) returns a
typed receipt the client crate can verify. All of this is rate-limited
per address + globally; stateless beyond a small payment ledger; and
**mechanically incapable** of signing a revision or submitting a publish
tx (L1 + L11).

## R-a..R-g resolutions (verbatim)

| Resolution | Decision | Module |
|---|---|---|
| **R-a** | axum + tower + tower-http + tokio | `src/http/{mod,routes,top_up,health}.rs` |
| **R-b** | In-memory rate limit + SQLite payment ledger | `src/rate_limit.rs`, `src/ledger.rs` |
| **R-c** | Signed Credit attestation only (no chain-balance fallback) | `src/http/top_up.rs::verify_credit_signature` |
| **R-d** | Fresh D-019 testnet redeploy with split keys (operational follow-up) | `contracts/deploy/.env.sepolia` |
| **R-e** | Layered: per-address token bucket (10 / 10-min) + global cap (200/hour) | `src/rate_limit.rs` |
| **R-f** | `FunderSigner` trait + `FileKeystoreSigner` impl; HSM scaffolded | `src/signer.rs` |
| **R-g** | Client-signed device-binding (no contract change) | `crates/pangolin-funder-client/src/lib.rs` |

## L1..L12 invariants (preserved)

1. **L1:** funder never signs revisions / submits revision-publish txs.
   Mechanical defense: `services/funder/Cargo.toml` does NOT directly
   dep on `pangolin-store` / `pangolin-core` / `pangolin-crypto` /
   `pangolin-ffi` — only on `pangolin-chain` + `pangolin-funder-client`.
   CI invariant: `grep -E "^pangolin-(store|core|crypto|ffi)\s*=" services/funder/Cargo.toml | wc -l` → 0.
2. **L2:** stateless beyond payment ledger. Restart reconstructs from
   on-chain `nonce[userId]` + the ledger's `attestation_hash` UNIQUE.
3. **L3:** per-address rate limit + HTTP 429 + `Retry-After` + JSON
   class. Leaks no internal counter state.
4. **L4:** read-only against chain except for redemption + ETH-transfer.
   alloy `sol!` block in `chain_submit::entitlement_registry_binding`
   declares ONLY `redeem` / `balance` / `nonce` / authority views / the
   `Redeemed` event — never `publishRevision`.
5. **L5:** funder wallet bounded; cold-wallet refill is operator's job.
6. **L6:** HTTP surface is `POST /funder/v1/top-up` + `GET /funder/v1/health`.
   No admin / debug / metrics.
7. **L7:** dep direction preserved (`pangolin-store → pangolin-chain`;
   funder is its own tree).
8. **L8:** every new dep is justified in `Cargo.toml` per-line. No
   new crypto crates. `serde` lands in the funder crate only — the
   `pangolin-crypto` serde-ban is preserved because the funder is
   separate.
9. **L9:** `forbid(unsafe_code)` on every new `.rs` file.
10. **L10:** AGPL SPDX header on every new `.rs` file.
11. **L11:** redemption submit is a SEPARATE codepath
    (`chain_submit::submit_redemption_v1`); it shares the gas-cap /
    retry / receipt-mismatch primitives with `publish_revision_v1` but
    is not a wrapper.
12. **L12:** INFO logs never carry `userId` / `deviceAddress` /
    signature bytes. Every WARN includes only the error-class tag.

## Threat-model touch points

See `THREAT_MODEL.md` for the per-component table. Funder-specific
threats:

- **L-funder-impersonation** — mitigated by the funder signing its
  own responses (deferred to 18.10; the `FunderResponse` typed-data
  envelope is the design but not shipped in 3.4).
- **L-credit-attestation-replay** — mitigated by `payments.attestation_hash UNIQUE`.
- **L-funder-wallet-key-leak** — mitigated by hot-wallet balance
  ceiling (operator-managed) + per-tx caps (deferred to 18.5).
- **L-DOS-eth-drain** — mitigated by layered rate limit (R-e) + the
  contract's `balance[userId]` bounding per-user loss.
- **L-funder-service-MITM** — mitigated by HTTPS-only operator policy
  (reverse proxy in front; the funder binds to 127.0.0.1 by default).
- **L-payment-order** — partial mitigation in 3.4; full state-machine
  for the redeem → ETH-transfer race lands in 18.5.
- **L-userId-deviceAddress-binding** — mitigated by R-g (client-signed
  device-binding); see `FUNDER_DEVICE_BINDING_DOMAIN_V1` in
  `pangolin-funder-client`.

## HTTP surface

### `POST /funder/v1/top-up`

Request body (JSON):

```json
{
  "credit": {
    "user_id": "0x<32 bytes hex>",
    "amount": "0x<hex>",       // OR decimal string
    "nonce": 0,
    "schema_version": 1,
    "expires_at": 2000000000,
    "signature": "0x<65 bytes hex>"
  },
  "device_binding_sig": "0x<65 bytes hex>",
  "device_address": "0x<20 bytes hex>"
}
```

Successful response (HTTP 200):

```json
{
  "redeem_tx_hash": "0x...",
  "eth_transfer_tx_hash": "0x...",
  "eth_transferred_wei": "0x..."
}
```

Error responses (HTTP 4xx / 5xx) all share the body shape:

```json
{"error": "<class-tag>", "retry_after_seconds": <only on 429>}
```

Class tags: `rate_limited`, `bad_request`, `credit_signature_invalid`,
`credit_expired`, `credit_schema_unsupported`, `device_binding_invalid`,
`already_redeemed`, `chain_submit_failed`, `ledger_error`,
`configuration_error`, `internal_error`.

### `GET /funder/v1/health`

Returns `{ok, commit, registry, chain_id, signer_address, payment_authority, device_binding_domain}`.
The `device_binding_domain` field lets a client sanity-check
protocol-version compatibility before signing a request (R-g (5)).

## Configuration env vars

| Var | Default | Purpose |
|---|---|---|
| `FUNDER_CHAIN_ENV` | `base-sepolia` | One of `base-sepolia` / `base-mainnet` / `dev`. |
| `FUNDER_BIND_ADDR` | `127.0.0.1:8080` | HTTP bind address. |
| `FUNDER_RPC_URL` | `https://sepolia.base.org` | Base Sepolia RPC. |
| `FUNDER_LEDGER_PATH` | `./funder-ledger.sqlite` | SQLite payment ledger. |
| `FUNDER_KEYSTORE_PATH` | _unset_ | Foundry keystore path. |
| `FUNDER_KEYSTORE_PASSPHRASE_FILE` | _unset_ | If set, reads passphrase from file; else stdin TTY. |
| `FUNDER_PRIVATE_KEY_HEX` | _unset_ | Dev-only override; mutually exclusive with `FUNDER_KEYSTORE_PATH`. |
| `FUNDER_RATE_LIMIT_BUCKET_SIZE` | 10 | Per-address bucket size. |
| `FUNDER_RATE_LIMIT_REPLENISH_SECS` | 600 | Per-address replenish interval. |
| `FUNDER_RATE_LIMIT_GLOBAL_CAP` | 200 | Global cap per hour. |
| `FUNDER_BODY_SIZE_LIMIT_BYTES` | 16384 | HTTP body cap (DoS defense). |
| `RUST_LOG` | `info,tower_http=info` | Tracing filter; `debug` exposes per-request fields per L12. |

## Deploy runbook reference

See `docs/RELEASE-CONTRACTS.md` for the D-019 split-key redeploy
procedure + the `pangolin-funder-dev` keystore creation steps. The
DECISIONS.md template for the post-deploy commit is also there.

## Out of scope (explicit)

- **ETH-transfer leg.** 3.4 lands the redeem submit + ledger row +
  redeem-receipt cross-check; the ETH-transfer to `device_address`
  + the L-payment-order state machine are deferred to MVP-2 issue
  18.5's operational hardening pass. Until then,
  `eth_transfer_tx_hash` mirrors the redemption tx hash + the
  `eth_transferred_wei` field is zero.
- **HSM signer.** R-f scaffolded as `FunderSigner` trait; only
  `FileKeystoreSigner` ships in 3.4.
- **TLS termination.** Operator runs a reverse proxy (nginx /
  caddy / Cloudflare). The funder binds to 127.0.0.1 by default to
  make this discipline mechanical.
- **D-019 redeploy itself.** Code merged in 3.4; Kelvin runs the
  deploy + commits the JSON + pinned-constant updates after merge.
- **Funder response signature (`FunderResponse` envelope).** Design
  in the L-section of the plan-gate doc; deferred to 18.10.
- **Multi-region / horizontal scaling.** Single-instance binary;
  18.5 territory.
