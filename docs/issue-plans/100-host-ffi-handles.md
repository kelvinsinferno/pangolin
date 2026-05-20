<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #100 — MVP-3-host-FFI-handles (plan-gate DRAFT)

**Status: DRAFT — awaiting Kelvin's resolved decisions (Q-a..Q-f below).**
**Base tip: `7aa04cc` (#99 merged, CI green). Last item in the pre-MVP-3 cleanup batch (5/5).**

## Headline finding (reframes the cycle)

The CLI-V1 freeze note (DECISIONS.md R-g) assumed the 4 stubs are blocked because they "require chain-adapter / signer / Credit-attestation UniFFI handles." Code reading shows that framing is partly wrong, in a way that makes #100 **safer and smaller** than the 5-8h estimate implied: the secret material these flows need — the gas-paying EVM wallet + its signer — **already lives inside the unlocked `Vault`** (derived from the sealed device key on unlock, 3.2 `ActiveState::evm_wallet`) and never has to cross the FFI boundary.

- Top-up sources the signer engine-side: `vault.evm_wallet().signer().clone()` (`apps/cli/src/commands/top_up.rs:70-72`) — no signer handle crosses anything.
- Pull builds its own provider internally and needs no adapter + no signer (`Vault::pull_once(rpc_url, env, vault_id)`, read-only).
- Flush / lock-with-drain build the adapter from a keystore in the CLI (`flush.rs:45`) but the engine also exposes `BaseSepoliaAdapter::new_with_device_key(rpc_url, deployment_path, &DeviceKey)` (`base_sepolia.rs:319`), which derives the same wallet from the vault's device key.

So the real blocker is **not** "cross a `ChainAdapter` trait object or a signer." It is two narrower problems: **(A)** how the host supplies the small non-secret config each call needs (RPC URL — in 3/4 frozen sigs; deployment-file path; the `Credit` attestation for top-up); and **(B)** the `!Send` async-execution problem the `vault_pull_once` stub explicitly calls out (`sync_status.rs:559-562`).

## Scope

**Wires the 4 surface-locked FFI stub bodies** so host shells (Tauri/iOS/Android) drive the same flows the CLI already drives:

| Stub | File:line | Engine method |
|---|---|---|
| `vault_flush_publish_queue(handle, force)` | `publish_queue.rs:129` | `Vault::flush_publish_queue(&adapter, &device_key, force)` |
| `vault_lock_with_drain(handle)` | `session.rs:534` | `Vault::lock_with_drain(&adapter, &device_key)` |
| `vault_pull_once(handle, rpc_url)` | `sync_status.rs:578` | `Vault::pull_once(rpc_url, env, vault_id)` |
| `vault_initiate_top_up(handle, funder_url)` | `balance.rs:290` | `pangolin_funder_client::initiate_top_up(funder_url, credit, &signer)` |

**NOT in scope:** the direct-WS-transport wrapper (#99 deferred follow-up); any change to the 4 engine methods (they exist + are tested — FFI bridge only); new CLI subcommands; D-017 fixture recapture (mechanical); host-side indexer-spawn handshake (separate MVP-3 host-shell cycle — flagged in Q-e-adjacent note).

## Recommended architecture

**Engine-side adapter construction from a per-call non-secret config; zero secret material crosses FFI.** Each binding: takes non-secret config (RPC URL + deployment path; + `Credit` Record for top-up) → briefly locks the vault guard, reads the sealed device key / derived wallet already in the unlocked session, constructs the adapter engine-side (or sources the signer for top-up; pull needs neither) → runs the async engine call → maps the typed error into `FfiError`. Mirrors the `balance_monitor_start` posture (read under brief guard, release, run).

**The `!Send` execution bridge (the one non-trivial element).** `Vault` is `!Send` (RefCell-bearing `rusqlite::Connection` + `dyn Clock`); flush/lock-with-drain/pull hold `&mut Vault` across `.await`, so they can't be plain `#[uniffi::export] async fn` (UniFFI wants `Send` futures). **Recommended: keep the exported fn synchronous (`pub fn`) and drive the async engine call to completion on a locally-built `tokio::runtime::Builder::new_current_thread()` runtime** — the future never leaves the calling thread, so `!Send` is fine; host calls it blocking from a worker thread (hosts already expect this for chain calls). ~20-line helper reused across 3 bindings. Alternatives (dedicated vault-executor thread; UniFFI foreign-executor async) are heavier / version-fragile — rejected.

## L1..L10 invariants

- **L1 — No secret material crosses FFI (HARD; D-006 / 3.5 R-d).** No DeviceKey/PrivateKeySigner/keystore-password/seed crosses any binding; signing wallet read engine-side from the unlocked Vault.
- **L2 — Engine methods unchanged.** #100 adds only the FFI bridge layer in `crates/pangolin-ffi/src/*`.
- **L3 — Frozen wire shape preserved or additively amended only.** The 3 frozen Records keep their fields + `schema_version` slot; new input params/Records may be added (established additive-amendment pattern). `vault_initiate_top_up` MUST be additively amended to carry the `Credit` (§ signature gap).
- **L4 — Active-session gate at the FFI boundary** (CLI-V1 L5): every binding rejects locked/placeholder vaults with `FfiError::Session` before any chain primitive (already present; preserved).
- **L5 — `forbid(unsafe_code)` everywhere except `pangolin-ffi`.** #100 adds no `unsafe`.
- **L6 — HIGH-1 / Q3 / L7 preserved** (crypto zero-serde; uniffi only in pangolin-ffi; chain-no-store=0). CI guard scripts stay green.
- **L7 — AGPL-3.0-or-later SPDX header on every new/edited file.**
- **L8 — `ChainEnv` hardcoded `BaseSepolia`, not crossed FFI** (it has no uniffi derive; matches `balance.rs:204` + `pull_once` doc). Mainnet = future surface bump.
- **L9 — No new `=`-pinned external dep without `cargo deny check advisories` + `cargo audit`** (env-quirk #15). #100 should need zero new deps (alloy + tokio already in pangolin-ffi). Byte fields cross as hex strings (established convention).
- **L10 — §16 ledger discipline:** plan-gate DRAFT → resolved-decisions LOCKED → builder → adversarial audit → fix-pass → re-audit; `git merge --no-ff`; DECISIONS.md entry appended.

## Signature-drift flags (frozen FFI vs current engine)

1. **`vault_initiate_top_up` missing the `Credit` input — REAL GAP.** Frozen `(handle, funder_url)` (`balance.rs:290`) but `initiate_top_up` needs `(funder_url, credit, &signer)`. Cannot function without the attestation. Must be additively amended (Q-c).
2. **`vault_flush_publish_queue` / `vault_lock_with_drain` carry no RPC URL / deployment path** but their adapters need both. Must be additively amended with config (Q-a). Their doc-comments anticipated this.
3. **flush/lock-with-drain engine methods take a `device_key: &DeviceKey`** the CLI satisfies with a throwaway `DeviceKey::generate()` (`flush.rs:55`) — the gas-paying wallet is internal to the adapter (two-key PoC model). The binding can mint the same ephemeral throwaway internally (no host input). `Vault` deliberately exposes no `device_key` accessor, so this is the established posture — flagged so the builder doesn't think the device key must come from the host.
4. **`vault_pull_once` is cleanest** — only blocker is the `!Send` bridge; no adapter/signer/extra config needed.

## Open decisions for Kelvin (Q-a..Q-f)

See the conversation / DECISIONS.md LOCKED entry — each Q is framed in plain English with a recommendation + tradeoff. Summary:

- **Q-a** — bundle per-call config into one `FfiChainConfig { rpc_url, deployment_path, prefer_websocket }` Record (recommended) vs loose args vs env var.
- **Q-b** — gas wallet derived engine-side from the vault's device key (recommended; honors L1) vs keystore-file+password over FFI (violates L1).
- **Q-c** — add the top-up `Credit` as a structured `FfiCredit` Record (recommended) vs an opaque JSON string.
- **Q-d** — ship top-up now with hermetic + skip-clean live `#[ignore]` test (recommended) vs defer top-up.
- **Q-e** — fold the `prefer_websocket` toggle in as a passthrough field on the Q-a Record (recommended) vs defer to the WS cycle.
- **Q-f** — hermetic stub-replacement tests for all 4 + 1 live `#[ignore]` per flow (recommended) vs add anvil-fork CI integration (own cycle).

## Estimated effort + test delta

~4-6h (revised down from CLI-V1's 5-8h given no secret-crossing handle + 4 working CLI references). Test delta ~10-16: flip the 4 stub-parity tests to the real path against mock adapter/funder; add per-binding session-gate + error-mapping tests + the `!Send` runtime-bridge round-trip test + 1-4 skip-clean live `#[ignore]` tests.

## Open follow-ups #100 will itself defer

Mainnet `ChainEnv` over FFI; keystore-file gas wallet over FFI (deferred indefinitely if Q-b lands "vault device key"); direct-WS-transport wrapper; host-side indexer-spawn handshake; anvil-fork CI integration.
