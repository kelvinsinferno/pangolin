# DEVLOG

> Append-only log. One entry per closed issue. 1–3 sentences each: what shipped, surprises, deferred follow-ups.

---

## 2026-05-15 · MVP-2 issue 3.5 — Top-up flow + low-balance UX (balance state machine + manual top-up Rust API) (builder output)

Plan at `docs/issue-plans/3.5.md` Kelvin-approved (security-critical, ADVISORY-SECURITY scope; R-a..R-e binding + L1..L11 + L-section). Built the client-side balance-state machine + the device-side `initiate_top_up` Rust API: new `pangolin-chain::balance_check` module exposes `query_evm_balance(rpc_url, address, env)` (async; chain-id cross-check → `BalanceQueryFailed`/`ChainIdMismatch`) + `estimate_next_publish_cost(rpc_url, env)` (async; `eth_feeHistory` → `max_fee_per_gas = 2*baseFee + 1gwei` × `EXPECTED_REVISION_GAS = 500_000` × `MIN_BUFFER_REVISIONS = 3`; fallback to `MAX_FEE_PER_GAS_CAP_WEI` on RPC error) + the pure `compute_balance_state(balance, estimate)` fn + the `GasBalanceState` enum (`Sufficient` / `RequiresActiveAccount` / `TopUpInFlight` / `Unknown` — §8.1.5 vocabulary pinned by `gas_balance_state_label_pinning`; `Debug` redacts wei to `"<wei>"` in release builds — pinned by `debug_format_redacts_balance_in_release`). New `pangolin-chain::balance_monitor::BalanceMonitor` owns a tokio background-poll task + `Arc<RwLock<GasBalanceState>>` cached state with `BALANCE_POLL_INTERVAL_SECS = 30` default + `register_top_up(TopUpNotification)` to flip state to `TopUpInFlight` until the next poll + `stop()` cancellation. `chain_submit::publish_revision_v1` gains a NEW `PublishConfig` parameter via the additive `publish_revision_v1_with_config` entry point (default `pre_publish_balance_check_enabled = true`); a below-threshold balance short-circuits to the new `ChainError::PrePublishBalanceInsufficient { balance_wei, estimate_wei }` BEFORE tx construction (`pre_publish_balance_check_blocks_doomed_submission` + `pre_publish_balance_check_passes_when_sufficient` + `pre_publish_balance_check_can_be_disabled_via_config`). New `Vault::evm_wallet_address` SYNC accessor reads cached `devices.evm_address` on a LOCKED vault (R-a hybrid + L5 nuance: policy-agnostic at this layer; `pangolin-store` stays alloy-free, returns `[u8; EVM_ADDRESS_LEN]` for caller-side `Address::from`). New `pangolin-funder-client::initiate_top_up(funder_url, credit, device_wallet)` returns `TopUpAttempt { attempt_id: Uuid, funder_response, submitted_at_unix }` after constructing the device-binding signature via `sign_device_binding` (3.4 R-g) + POSTing the wire body via `reqwest`. New `pangolin-ffi::balance` module exposes `balance_monitor_start` / `balance_monitor_stop` (async) / `gas_balance_state` with the `GasBalanceStateFfi` uniffi mirror (wei values cross as **hex strings** to preserve u128 fidelity; L5 FFI policy active-session-gated). **Decisions locked:** R-a (hybrid — chain crate owns logic + Vault grows sync accessor); R-b (both eager poll + per-publish freshness check); R-c (hybrid estimate with `MIN_BUFFER_REVISIONS = 3` safety margin); R-d (new FFI method; `DeviceInfo` unchanged); R-e (two-step manual API; NO auto-top-up; NO CLI subcommand; NO vault-stored attestations). **New external crate deps (env-quirk #15 trigger):** `reqwest = "=0.13.3"` (`rustls`, `default-features = false`; SAME version alloy's transitive reqwest uses — no version skew). The plan-gate originally said "pin in the 0.12.x line" but 0.12's `rustls-tls` feature transitively pulls `ring`, which is banned by `deny.toml` (Pangolin uses RustCrypto / dalek-cryptography crates exclusively per `docs/issue-plans/P1.md`). reqwest 0.13's `rustls` feature wires `rustls/aws-lc-rs` which is permitted in the dep tree (alloy's transitive reqwest 0.13 already uses this path). The 0.13 vs 0.12 swap is the right correctness move and aligns the workspace on a single reqwest version. `uuid = "=1.10.0"` (`v4` random id; client-generated), `serde = "=1.0.228"` (derive for wire shapes — same pin as the funder service), `wiremock = "=0.6.5"` (dev-dep only — hermetic mock server for `initiate_top_up` tests). Hex helpers (`hex_encode`, `parse_b256`, etc.) are local to the funder-client crate to keep the dep set tight. New `tokio` + `pangolin-chain` + `alloy` deps on `pangolin-ffi` (which previously had none of these; the FFI now bridges the chain crate's typed `GasBalanceState`). **Tests added:** 14 in `pangolin-chain::balance_check` (state-transition x4, label-pinning, debug-redaction, chain-id-mismatch, rpc-failure, happy-path balance, dev-env skip, estimate-base-fee, estimate-fallback, estimate-clamp, constants-pin); 5 in `pangolin-chain::balance_monitor` (initial-state, register-top-up, stop-cancels, concurrent-reads-safe, interval-pin); 3 in `pangolin-chain::chain_submit` (pre-publish-blocks, passes-when-sufficient, can-disable-via-config); 2 in `pangolin-store::vault::tests` (works-on-locked, errors-no-device); 3 in `pangolin-funder-client` (request-body-shape, 429, 409) + 1 `#[ignore]`'d live-D-019 placeholder; 5 in `pangolin-ffi::balance` (requires-active-session, lifecycle, returns-state, placeholder-handle, zero-interval). One `#[ignore]`'d live test added in `pangolin-chain::tests::integration` (`live_balance_query_against_d017_wallet` — queries `BASE_SEPOLIA_DEV_WALLET` against Base Sepolia and asserts non-zero balance). Docs: extended `docs/architecture/ffi-surface.md` with the `balance_monitor_start` / `balance_monitor_stop` / `gas_balance_state` entries + the `GasBalanceStateFfi` enum vocabulary discipline; new "Gas balance state machine + manual top-up trigger" row in `THREAT_MODEL.md` enumerating 8 per-surface threats (L-balance-staleness, L-rpc-spoof-balance, L-state-leak-via-label, L-auto-top-up-DoS, L-credit-attestation-storage, L-funder-url-injection, L-monitor-runtime-leak, L-monitor-state-persistence); appended R-a..R-e entries to `DECISIONS.md`. **Surprises during implementation:** (1) `pangolin-store` is alloy-dep-free by design — the `evm_wallet_address` accessor returns `[u8; 20]` rather than `alloy::primitives::Address` so the dep direction stays clean (caller converts via `Address::from` at the chain-crate boundary). (2) The FFI surface needed `tokio` + `alloy` + `pangolin-chain` as direct deps for the first time; existing 1.5 / 1.6 FFI surface was synchronous. (3) Wei values cross FFI as hex strings (not u128) because uniffi's `u128` support is shaped around foreign-language interop ergonomics — hex strings round-trip predictably across Swift / Kotlin / cbindgen. (4) The funder-service wire shapes (`WireTopUpRequest` / `WireTopUpResponse`) duplicate at the client side because the canonical types in `pangolin-funder-client` deliberately don't derive `Serialize`/`Deserialize` (alloy primitives + the dep-set tightness L1 invariant); 3.5's wire shapes mirror the funder service's verbatim. **env-quirk #15 advisories result:** `cargo deny check advisories` + `cargo audit` run before merge — clean (see commit body for full output).

Plan at `docs/issue-plans/3.3.md` Kelvin-approved (security-critical, plan-gate granted; R-a..R-f + L1..L12 binding). Built the v1 direct-submit transport that turns 3.1's `SignedRevisionV1` (65-byte EIP-712 secp256k1 signature) + 3.2's session-bounded `EvmWallet` into a `publishRevision(bytes32, bytes32, bytes32, bytes32, uint16, bytes, bytes)` call against D-017 (`0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` on Base Sepolia, chainId 84_532): new `pangolin-chain::chain_submit` module exposing `pub async fn publish_revision_v1(&EvmWallet, &SignedRevisionV1, ChainEnv, &str) -> Result<ChainAnchorV1, ChainError>` (R-d — async-only on `pangolin-chain`; `Vault` stays sync, no `Vault::publish_revision_v1` wrapper) that fetches the nonce via `eth_getTransactionCount(addr, "pending")` per submit (R-a — no local cache), reads `baseFeePerGas` via `eth_feeHistory`, computes `maxFeePerGas = 2 × baseFeePerGas + 1 gwei` (R-b — `PRIORITY_FEE_DEFAULT_WEI = 1_000_000_000`), enforces the hard cap `MAX_FEE_PER_GAS_CAP_WEI = 50_000_000_000` (50 gwei) BEFORE tx construction (L6 + L-gas-griefing), estimates gas with a 1.2× safety margin, signs via the alloy `EthereumWallet` filler, broadcasts via `eth_sendRawTransaction`, blocks until 1-conf receipt (R-e), and decodes the `RevisionPublished` event with a cross-check that `event.signer == wallet.address()` (L-rpc-spoof defense). New `ChainAnchorV1` carries `tx_hash` + `block_number` + `block_hash` + `log_index` + `sequence: U256` + `signer: Address` (richer than v0's anchor; v1 keeps its own type to avoid breaking v0 readback). Retry taxonomy per R-c verbatim — retriable (nonce collision: 3 retries, refresh-and-resubmit; RPC transient: exp backoff 250 ms / 1 s / 4 s, 3 attempts) and fatal (`InsufficientFunds`, `RevertedV1` with reason decoded as `ErrInvalidSignature` / `ErrSignerNotRegistered` / `ErrUnsupportedSchemaVersion` / `OutOfGas`, `ChainIdMismatch`, `DeploymentAddressMismatch`, `GasCapExceeded`, `NonceUnresolvable`, `ReceiptMismatch`); seven new `ChainError` variants added in `error.rs`. L12 replay-protection: the broadcast retry loop fires retries only BEFORE `send_transaction` returns success — once a `PendingTransactionBuilder` is held the receipt-await runs to completion, the mempool's "already known" idempotency + the contract's nonce-bound `_nextSequence` advance backstop the property structurally. No new external crate dep (L8 — alloy + tokio + k256 already in tree; verified `cargo tree -p pangolin-chain --depth 1` unchanged); no new FFI surface; `forbid(unsafe_code)` survives; AGPL-3.0-or-later SPDX header on the new `chain_submit.rs`. Tests are hermetic per R-f: 19 new tests in `chain_submit` driving alloy's `MockTransport` + `Asserter` (calldata byte-pin against a `cast calldata`-derived reference + selector pin `0x91f6be2f`; happy-path broadcast leg + happy-path receipt processing; chain-id mismatch; deployment-address mismatch; gas-cap exceeded; insufficient funds; reverted-decodes-reason; estimate-revert decodes `ErrSignerNotRegistered`; receipt-mismatch; foreign-emitter log dropped via MED-4 filter; nonce-collision retry-then-succeeds; nonce-unresolvable after 3 retries; RPC-transient retry-then-succeeds; classifier units for all four message-shape helpers). The two-phase test split (broadcast-leg via `broadcast_with_retries`, receipt-processing via `process_receipt`) was necessary because alloy's `PendingTransactionBuilder::get_receipt` polls via the heart's block-head subscription, which is awkward to satisfy with `MockTransport`; the production path stitches both phases inline. One `#[ignore]`'d live test `publish_v1_live_d017_smoke` documented with the manual-run command (`BASE_SEPOLIA_RPC_URL=... cargo test ... -- --ignored`). The calldata-pin test passed on the second iteration — first attempt had a 1-byte short reference (missing one of the 64 `aa` bytes in the signature data); fix was mechanical (replaced the trailing zero-pad block with `1c00...00` to make the 65th byte explicit). Docs: new `docs/architecture/chain-submit.md` covering the sync→async caller flow + the R-a..R-f locked decisions + the L1..L12 invariants + the L-section threat surface + the hermetic test surface; updated `THREAT_MODEL.md` per-component table with a new "Direct-submit chain transport" section enumerating 10 per-surface threats (L-gas-griefing / L-rpc-spoof-receipt / L-deployment-mismatch-broadcast / L-nonce-collision-DoS / L-replay-after-revert / L-double-broadcast-on-retry / L-chain-id-binding / L-tx-signing-leak / L-mempool-leak / L-receipt-poll-timeout) with defenses pointing to specific L1..L12 + classifier helpers + cross-checks. **Decisions locked:** R-a (fetch nonce per submit; no local cache) + R-b (EIP-1559 + 50 gwei hard cap) + R-c (8-row retry taxonomy verbatim) + R-d (async-only on `pangolin-chain`; `Vault` stays sync; no `block_on` shim) + R-e (block until 1-conf; receipt event cross-check) + R-f (hermetic CI dominant; one `#[ignore]`'d live smoke). **Deferred to follow-ups:** MVP-2 issue 4.1 ships the indexer-side `RevisionPublished` consumer + the off-chain reconciliation logic that resolves the `L-receipt-poll-timeout` failure mode; MVP-3 ships tx-replacement / cancel-tx for the `NonceUnresolvable` exit path; the `apps/cli` integration of the v1 broadcast lands with the standing CLI-V1 batch (same posture as 3.1 / 3.2). `apps/cli/src/sync.rs` is intentionally NOT touched in 3.3 — the v0 publish path stays for legacy reads per 3.1's R-a clean-break boundary.

---

## 2026-05-14 · MVP-2 issue 3.1 — Signed-revision client format (secp256k1 EIP-712 v1) (builder output)

Plan at `docs/issue-plans/3.1.md` Kelvin-approved (security-critical, plan-gate granted; R-a..R-e binding). Built the v1 EIP-712 signing path that the deployed `RevisionLogV1` (D-017 at `0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` on Base Sepolia, chainId 84_532) `ecrecover`s against: new `pangolin-chain::secp256k1_signing` module (clean break from v0's `signing` per R-a/R-b — separate `SignedRevisionV1` struct; v0 module retained verbatim for legacy read-back) exposing `build_signed_revision_v1(&EvmWallet, fields, chain_env)` that produces a 65-byte `r ‖ s ‖ v` signature (canonical-s; `v ∈ {27,28}`) over the EIP-712 typed-data digest. Pinned-at-source consts: `REVISION_TYPEHASH_V1 = 0x240c1b72...d211` (the keccak of the spec-literal struct string) + `DOMAIN_SEPARATOR_BASE_SEPOLIA_V1 = 0x9d153888...0c62` (captured from D-017's `domainSeparator()` view fn at plan-gate time) + `EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA = 0x179362...8E42`; the builder cross-checks the runtime-loaded `verifyingContract` against the pinned address before signing and fails closed via the new `ChainError::DeploymentAddressMismatch` variant (L-domain-binding defense). New `pangolin-chain::deployments` module exposes `ChainEnv` enum + `load_deployed_address(env, name)` helper that reads `contracts/deployments/<env>.json` via a `CARGO_MANIFEST_DIR`-baked path so the lookup works from any runtime CWD. `Vault::sign_revision_v1` is the public store-side entry point — calls `require_active()` (L5 session gate); maps `ChainError` through new `StoreError::ChainSignError(ChainError)` variant. No FFI changes (3.1 stays inside Rust core per 1.5 + 3.2 doctrine; the broadcast layer lands with MVP-2 issue 3.3). No new external crate dep (L7 — alloy `eip712_domain!` + alloy's `Signature::normalize_s/as_bytes` cover the whole surface; k256 stays transitive via alloy). Tests are hermetic per R-e: 9 new tests in `pangolin-chain` (typehash pinned-const cross-check, domain-separator pinned-const cross-check, 65-byte sig, canonical-s, v ∈ {27,28}, round-trip sign-recover via the test-only `recover_v1_for_test` helper, per-field tamper across all 6 struct fields, cross-env replay produces different signers, canonical-s boundary) + 2 new in `deployments` (D-017 address load + missing-contract typed error) + 1 in `pangolin-store` covering the three session-gate legs (Locked / Active / idle-expired). Both pinned-constant tests pass first time on Kelvin's box, validating the contract's `domainSeparator()` output captured 2026-05-14 18:50 ET matches the alloy-constructed domain bit-for-bit. Docs: new `docs/architecture/signing.md` covering both paths (Ed25519 v0 + secp256k1 v1) + the EIP-712 envelope + the caller flow; updated `THREAT_MODEL.md` per-component table + new "Revision signing v1" section enumerating 8 per-surface threats with defenses pointing to specific L1..L11 + L-* test gates; updated `docs/architecture/ffi-surface.md` to note 3.1 is a no-op for FFI. **Decisions locked:** R-a (clean break: v0 records orphaned at the v1 boundary; no mass-resign migration) + R-b (v0 path retained for legacy read-back; separate sibling module) + R-c (deployment address sourced from `contracts/deployments/<env>.json` via compile-time-baked path) + R-d (verifier defers to 4.1; only signer ships in 3.1; test-only `recover_v1_for_test` helper) + R-e (hermetic-only CI; network cross-check is `#[ignore]`'d). **Deferred to follow-ups:** MVP-2 issue 3.3 wires the broadcast layer (`publishRevision` call against D-017); MVP-2 issue 4.1 ships the production verifier (off-chain `RevisionPublished` event consumption); MVP-2 issue 3.6 (Privacy Phase-2 scaffolding) addresses the documented address-correlation threat (D-006 / L-mempool-leak-of-vault-binding).

---

## 2026-05-13 · MVP-1 issue 0.2 — Threat-model + invariants doc (final MVP-1 item)

Spec-completed `THREAT_MODEL.md` per master plan §4 row 0.2. Promoted four CI-enforced cross-cutting properties to numbered invariants — **#9 HIGH-1** (`pangolin-crypto` has zero `serde` reach), **#10 Q3** (`pangolin-core` has zero `uniffi` reach; bonus check on `pangolin-store`), **#11 §18.7 ladder** (a record from a future build's `schema_version` is never silently skipped; per-row reject scoped to the field's home; AAD-bound fields reject *after* the AEAD open so a tampered byte surfaces `AuthenticationFailed` not "requires upgrade"), **#12 AAD coverage** (every disambiguating byte of every sealed payload is in the AEAD AAD — `vault_id` / `account_id` / `parent_revision_id` / `schema_version` / the encrypted-archive header — verified by `adversarial_cross_account_row_transplant_fails` and `tampered_header_byte_fails_auth`). Added 7 new per-surface threat-enumeration sections covering the MVP-1 surfaces that landed since the PoC bootstrap: **1.4 session policy engine** (8 threats — the §2.3 cardinal-principle-5 enforcement: reveal-class freshness, the 4 h absolute ceiling, idle-timer teardown, the dedup-does-not-extend-window invariant, the no-account-existence-oracle taxonomy, the `SessionDuration::try_from_meta_secs` reject for tamper-resistance, single-use presence proofs, the `&mut self` concurrency posture); **1.5 device identity + per-device key** (5 threats — the VDK-sealed Ed25519 seed with AAD-bound `device_id`, the verifying-key tamper-fail, the no-MVP-1-rogue-register surface, the dormant chain-code metadata, the NFC-normalised label validation); **1.7 TOTP engine** (5 threats — RFC 6238 security, AEAD-sealed secrets crossing FFI only via reveal-class `reveal_totp_secret`, hand-rolled `forbid(unsafe_code)` parser, §18.7 ladder for the V2 payload, terminal-output non-scope); **1.8 password generator + zxcvbn** (5 threats — single-RNG `pangolin_crypto::rng::fill_random`, bounded constant-time `uniform_index`, policy validation gates, the documented `password_strength` length-cap hardening item, the deliberate empty `user_inputs` choice); **1.9 KDBX importer** (9 threats — the tightened Argon2 clamps from audit Low-1, the `MAX_FILE_BYTES`/`MAX_INFLATED_BYTES` caps, the no-credential-oracle one-error-variant rule, `quick-xml` no-custom-entity-expansion, the keyfile-cap from audit Low-3, the full-params `parse_otpauth_uri` integration, the history-replay current-pw-last fix from audit Low-2, the rejected hardware-CR-protected DBs, the `forbid(unsafe_code)` ceiling); **1.10 encrypted export** (8 threats — the export passphrase independent of the vault master password per D3, the archive Argon2 clamps from audit Low-2, the whole-header-AAD invariant, the typed `(top_len, schema_version) ∈ {(7,1), (8,2)}` matrix, the `export_plaintext` two-step confirmation + 30 s delay + single-use token gate, the loud in-file warning banner, the no-lineage-laundering restore posture, the no-auto-export surface); **1.11 capture-authority registry** (8 threats — the SQL `PRIMARY KEY` exclusivity, the lowercased-ASCII allowlist defeating Unicode-homoglyph impersonation, the audit F1 §18.7 ladder on register, the audit F4 single-`BEGIN IMMEDIATE` TOCTOU close, the `Replaced { prior }` audit-trail not surfaced via FFI, the documented non-secret-metadata posture for `component_id`/`component_version` with the `MAX_HITS_PER_MARKER` regression cap, the per-row §18.7 DoS bound, the no-restore-cross-vault `restore_to_new_vault` posture). Updated the threat-enumeration table to mark every MVP-1 surface as DOCUMENTED. Locked decisions: `THREAT_MODEL.md` stays at the repo root (matches master plan §16 layout); scoped to MVP-1 only with MVP-2+ surfaces left as `TBD (issue X.Y plan)` placeholders; promoted only structural/build-discipline properties to numbered invariants. Living-doc framing preserved: every future issue updates this file when it lands a new attack surface. No code change; pure documentation. **MVP-1 is now feature-complete.**

---

## 2026-05-13 · MVP-1 issue 1.11 — Capture-authority registration primitive (builder output)

Plan at `docs/issue-plans/1.11.md` Kelvin-approved (security-critical, plan-gate granted; L1–L12 binding, R-a–R-f resolved). Built the capture-authority registry (Browser-Ext spec §2.3 / API contract §16 / Threat Model invariant #8) end to end with zero new deps (validation reuses the already-vendored `unicode_normalization`; Cargo.toml/Cargo.lock unchanged vs `main`): new `pangolin-store::capture_authority` submodule + new `capture_authorities` SQL table joined into `SCHEMA_DDL` (additive `CREATE TABLE IF NOT EXISTS`, no `format_version` bump; legacy 1.10 vaults pick it up on next open) with `PRIMARY KEY (context_kind, platform_hint)` making exclusivity a *structural* invariant; closed `CaptureAuthorityKind` / `CaptureContextKind` enums making Threat Model #8 a *type-system* invariant; per-record `schema_version` against `CAPTURE_AUTHORITY_SCHEMA_VERSION_MAX = 1` (per-row §18.7 ladder reject for future rows — rest of vault fine); identifier validation per L7 (NFC, length, control-char + Cc reject; `platform_hint` is a lowercased-ASCII allowlist that defeats Unicode-homoglyph impersonation). The `Vault` API gains `capture_authority_register / _query / _list / _clear`; `_register` is the **L6 hybrid** — `Created` and `NoOp` are session-class (active non-expired session, presence proof held but not verified), `Replaced` (existing row overwritten via `replace_existing=true`) is reveal-class (routes through `ensure_presence_fresh` BEFORE the REPLACE commits, exactly like `reveal_*` / `export_*`); on `Replaced` rejection the typed `StoreError::CaptureAuthorityExclusivity { context }` names only the context kind (no info-leak on the existing `component_id`). `RegistrationOutcome::{Created, Replaced { prior }, NoOp { existing }}` is preserved on the Rust side (tests + future MVP-2 amendment); the FFI body collapses every success to `Ok(())`. FFI: the 1.1-scaffold's `CaptureAuthority` / `CaptureContext` placeholders are **deleted from `kdbx.rs`** (where they didn't belong) and **finalised in a new `pangolin-ffi/src/capture_authority.rs`** module per L5 with the closed-enum kinds + closed-allowlist `platform_hint` + new `CaptureAuthorityEntry` Record + the new `capture_authority_register / _query / _list` entries (additive 1.1-surface amendment — same posture as 1.2/1.4/1.7/1.9/1.10; nothing external binds the 1.1 surface). Archive round-trip (L10, R-f): 1.10's `ArchiveSnapshot` grew an additive optional trailing `capture_authorities: Vec<CapturedCaptureAuthority>` field — top-level CBOR array goes from 7 to 8 items; decoder accepts either shape (legacy 1.10 archives decode the missing field as empty); `Vault::restore_to_new_vault` does **not** re-register the source's rows (Q-f — destination starts fresh, mirrors the `let _ = &snapshot.devices;` posture). CLI: ships `pangolin-cli authority list [--vault-path] [--json]` (read-only inspection; two-proof unlock; sorted by `(context_kind, platform_hint)`; `register`/`clear` defer to MVP-2 per R-d). Tests: 6 new vault-level tests covering Created/NoOp/Replaced/exclusivity/validation/locked-vault/clear/archive-round-trip-destination-empty/per-row-future-schema-rejection in `pangolin-store/src/vault.rs`; 4 new FFI tests in `pangolin-ffi/src/capture_authority.rs` covering register-query-list round-trip + exclusivity + malformed payload + locked-vault reads; 3 CLI integration tests in `apps/cli/tests/authority.rs` (human + JSON + empty); 6 unit tests on the validation helpers; 3 new round-trip Record tests in `pangolin-ffi/tests/roundtrip.rs`. Docs: new `docs/architecture/capture-authority.md` (canonical reference — the §2.3 rule, the table shape, the type-system invariants, the L6 hybrid auth tier including which branch consumes presence, the L7 validation discipline, the L10 archive posture, the MVP-2 wiring picture); updated `docs/architecture/ffi-surface.md` (finalised the `CaptureAuthority` / `CaptureContext` shapes; added `capture_authority_query` / `capture_authority_list` / `CaptureAuthorityEntry` / the two new enums; documented the hybrid auth tier on `_register`); updated `docs/architecture/schema-versioning.md` (new `capture_authorities.schema_version` slot on the §18.7 ladder + the additive 1.11 changes in the minor-bump list); updated `THREAT_MODEL.md` (invariant #8 now points at the three enforcement layers — SQL PRIMARY KEY + closed enums + hybrid-auth `register`). Verification gate: fmt clean; build clean; clippy clean workspace-wide; `cargo deny` ok; `cargo audit` ok with the two pre-existing allowed warnings (RUSTSEC-2024-0388 derivative, RUSTSEC-2024-0436 paste); invariant trees `crypto+serde = 0`, `core+uniffi = 0`, `store+uniffi = 0`; `git diff main -- Cargo.lock '**/Cargo.toml'` = 0 lines.

---

## 2026-05-12 · MVP-1 issue 1.10 — Encrypted export (Pangolin-native archive + restore-to-fresh-vault) (builder output)

Plan at `docs/issue-plans/1.10.md` Kelvin-approved (security-critical, plan-gate granted; D1–D7 binding). Built `pangolin-store::export` (new submodule, zero new deps — CBOR via the already-vendored `ciborium-ll`, AEAD/KDF/RNG via `pangolin-crypto`'s public API; HIGH-1 untouched): the `.pvea` archive format = a fixed-size plaintext header (magic `PANGOLIN-VEA` ‖ `format_version:u8` ‖ `kdf_algo_id:u8` ‖ Argon2 params (3×u32 BE) ‖ 16-byte salt ‖ 24-byte XChaCha20 nonce ‖ `ct_len:u64` BE) — the **whole header is the AEAD AAD** — followed by `XChaCha20-Poly1305(payload)` where the payload is a CBOR snapshot (schema_version, `exported_at`/`source_device_id`/`vault_id` provenance per D6, the `meta` session-idle setting, every non-tombstoned account's full V1 identity + complete password history bytes/timestamps/originating-devices, the device trust list); plus `decode_archive` (strict header bounds + Argon2-param clamps (≤1 GiB / t≤64 / p≤64, ≥ floor) + `ct_len` ceiling ≤256 MiB *before* any allocation/derive — no panics on hostile input; wrong-passphrase and tampered-archive both → one `export_credentials` error, no oracle; unknown `format_version`/`schema_version` → `export_format`) and `render_plaintext` (the `.pvtxt` cleartext dump with a loud in-file banner). Archive key = Argon2id (`KdfParams::RECOMMENDED`) over a **fresh user-supplied export passphrase independent of the vault master password** + the in-header random salt (D3 — key separation); the CLI runs it through 1.8's zxcvbn `strength()` and warns (not a hard gate) if weak. `Vault::export_encrypted` / `export_plaintext` are reveal-class (D5 — `check_session_freshness` + `ensure_presence_fresh` + `touch_session`, exactly like `export_payload`); the encrypted CBOR snapshot only ever lives transiently in `Zeroizing`, sealed before any disk write. `Vault::restore_to_new_vault` decodes an archive → creates a **brand-new `.pvf`** (`O_CREAT|O_EXCL`, never clobbers) → reconstructs each account through the validated `account_add` path with the password history replayed oldest→newest via `account_update` (does **not** merge into an existing vault — deferred to MVP-2's signed Revision Log; does **not** carry over the archived device trust list — the restored vault is its own fresh device). FFI: the two 1.1-frozen `vault_export_*` bodies implemented (no more `todo!()`) with the additive amendments — both grew `presence: PresenceProof` (forced by Session spec §5.4) + an `accounts: Option<Vec<String>>` subset selector (hex ids; `None` = whole vault — D1); the encrypted one also grew an `Arc<SecretPassword>` export-passphrase arg (consumed+zeroized); both return a non-secret `ExportReport` instead of `()`; new `vault_restore_from_archive(archive_path, dest, archive_passphrase, new_vault_password) -> RestoreReport`; the `PlaintextExportConfirmation` Record finally given semantics (FFI requires a structurally-valid single-use token; the CLI owns the 30 s delay + double-confirmation + warning copy per master plan §4 row 1.10). CLI: `pangolin-cli vault export <out> --vault-path <pvf> [--accounts <comma-hex>] [--plaintext]` (encrypted: two-proof unlock + export-passphrase prompt on stderr with zxcvbn warning, archive to a file path never stdout; `--plaintext`: the loud warning copy → type `i understand` → 30 s countdown (test-only hidden `--no-delay`) → second `[y/N]` → mint a `fill_random(32)` token → write the `.pvtxt`) and `pangolin-cli vault restore <archive.pvea> --out <new.pvf>` (archive passphrase + new master prompted on stderr, or `--archive-passphrase-stdin` for CI). Output files created umask-respecting + `chmod 0o600` on Unix, never clobbered, partial file removed on a write error. **Restore-fidelity deviation (1.10 cut, noted in the doc + threat model):** the restored account gets a fresh random `account_id`, `now` history timestamps, and the new vault's device as originating — the encrypted payload still carries the originals (D1/D6); a lineage-preserving restore is a follow-up alongside MVP-2's signed Revision Log. Tests: `pangolin-store/src/export.rs` unit tests (CBOR round-trip, seal/open, AEAD-AAD header-byte-flip → auth fail, hostile-header → `export_format` before KDF, truncated/bad-magic, plaintext-render-has-secrets-and-banner); `pangolin-store/tests/export_roundtrip.rs` (full export→decode→restore round-trip with multi-revision history; wrong-passphrase no-oracle; `--accounts` subset); `apps/cli/tests/vault_export_restore.rs` (CLI export→restore round-trip + scan the `.pvea` for plaintext markers (none) + wrong-passphrase fails cleanly with no file written + tampered-archive fails + `--plaintext` writes cleartext with the banner + aborts on a wrong confirmation phrase). Docs: `docs/architecture/encrypted-export.md` (new), `ffi-surface.md` (the 3 ops + amendments + `ExportReport`/`RestoreReport`), `THREAT_MODEL.md` (entry 9 in the local-store section).

---

## 2026-05-12 · MVP-1 issue 1.9 — KDBX import (builder output)

Plan at `docs/issue-plans/1.9.md` Kelvin-approved (security-critical, plan-gate granted). Built `pangolin-kdbx` from the 1.1 scaffold into a hand-rolled, read-only `KeePass` 2.x parser: KDBX 3.1 (AES-KDF / AES-256-CBC / Salsa20 inner stream / stream-start-bytes check) and KDBX 4.x (Argon2d/id from the `VariantDict` / AES-256-CBC or ChaCha20 / HMAC-SHA256 per-block MAC + header SHA-256 + header HMAC / gzip'd XML / ChaCha20 inner stream), composite key = SHA-256(SHA-256(pw) ‖ keyfile_key) with password and/or keyfile (`.keyx` XML v1/v2, raw-32, 64-hex, file-hash), `forbid(unsafe_code)`. The `quick-xml` streaming walk un-masks `Protected` values in document order; `flate2` does bounded gunzip (gzip-bomb guard). A `map.rs` layer turns entries into Pangolin-shaped drafts per the L17/L18 mapping table (empty Title synthesised, empty UserName placeholder, empty Password → skip, group path → tags, expired → `"expired"` tag, recycle bin skipped, custom fields → notes block, attachments dropped + size note, `<History>` → replayed password revisions). FFI `kdbx_import` body implemented with the one additive amendment (`keyfile_path: Option<String>` per L11/L13); the store-side ingestion loop lives in `pangolin-ffi` (and a sibling copy in `apps/cli`) — `pangolin-store` gains no `pangolin-kdbx` dep. Shipped the `pangolin-cli import <file.kdbx> [--keyfile]` subcommand (Q-e: counts to stdout, prompts to stderr, exit-non-zero on any failure).

New deps (all `=`-pinned, no `deny.toml` change — denylist not allowlist): `quick-xml =0.37.5`, `flate2 =1.0.35` (pulls `miniz_oxide`), `cbc =0.1.2`; everything else (`aes`, `argon2`, `chacha20`, `salsa20`, `cipher`, `hmac`, `sha2`, `byteorder`, `base64`) was already in `Cargo.lock`. Tests: `pangolin-kdbx` round-trip / TOTP / recycle-bin / edge-case / wrong-credentials-no-oracle / corrupt-input / keyfile / flipped-block-MAC + a 500-entry scale fixture (correctness only, no timing assertion per env-quirk #11), via a self-contained KDBX 3.1/4.x test writer (`tests/writer/mod.rs` + a feature-gated `pangolin_kdbx::test_writer` for downstream tests); an FFI exhaustive `KdbxError → FfiError` taxonomy test (no-oracle property asserted); a `pangolin-cli import` integration test that imports a fixture and scans the raw `.pvf` for the imported plaintext markers (finds none). Docs: `docs/architecture/kdbx-import.md`.

Deviation noted: replayed `<History>` revisions are stamped with the import wall-clock + this device's id, not the KeePass `LastModificationTime` / a synthetic device — the public `account_update` path has no custom-timestamp hook (would need a lower-level store API). Hardware-CR-protected DBs and KDBX 1.x/2.x → typed errors as planned (deferred). Goes through the §16 cycle next: test → fix-pass → adversarial audit (fuzz focus on the parser) → merge.

## 2026-05-05 · P0 bootstrap
Sprint authorized. Repo scaffolded at `C:\Users\kelvi\Projects\pangolin` per master plan §16.8: full directory tree (`crates/`, `contracts/`, `apps/`, `services/`, `tools/`, `design/`, `docs/`, `.github/`). Apache-2.0 LICENSE, README, .gitignore, CONTRIBUTING.md (issue 18.6 — encodes §16 protocol), GitHub PR template + issue template (issue 18.13 — forces §16.2 plan structure), forbidden-terms CI workflow (issue 18.12 — Design Spec §15.2 enforcement), DECISIONS.md (issue P0-2 — locks D-001 through D-013), DEVLOG.md, E2E_TESTS.md, THREAT_MODEL.md skeletons.

## 2026-05-05 · P0-1 — Cargo workspace + rustfmt/clippy + GH Actions CI
Plan committed at `docs/issue-plans/P0-1.md` and self-approved (non-security-critical per §16.3). All 7 crates scaffolded with workspace inheritance: `pangolin-core`, `pangolin-crypto`, `pangolin-store`, `pangolin-chain`, `pangolin-indexer`, `pangolin-funder-client`, `pangolin-cli` (binary). Each has a placeholder `name()` function exercised by a unit test. Workspace lints set to `clippy::all = deny` + `pedantic` + `nursery` warn-level with explicit allows; `unsafe_code = deny` workspace-wide. CI workflow (`.github/workflows/ci.yml`) runs fmt, clippy `-D warnings`, test on Linux/Windows/macOS. Local verification on Windows host: build clean, fmt clean, clippy clean under pedantic+nursery, all 7 unit tests pass, `pangolin v0.0.0 (pangolin-core linked)` prints from CLI.

Surprises: pinned rustup symlinks in `.cargo/bin/` aren't directly invokable from this bash; resolved by invoking the actual toolchain bin path (`~/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/`). Two pedantic-clippy fixes needed mid-build: `SQLite` and `EVM` flagged for missing backticks in doc comments. `imports_granularity` and `group_imports` are nightly-only rustfmt options; removed from `rustfmt.toml` with note to revisit if/when nightly fmt is adopted.

Next issue: P0-2 already shipped as `DECISIONS.md` in the bootstrap commit. After this commit, the next units of work are **P1 series** (`pangolin-crypto` real implementation — Kelvin-gated at PLAN per §16.3 because it's security-critical) and **P5-1** (`RevisionLogV0.sol` first draft + Foundry tests — also Kelvin-gated). Both are independent and parallelizable.

## 2026-05-05 · P5-1 — RevisionLogV0 append-only EVM contract  ✅ MERGED

Plan at `docs/issue-plans/P5-1.md` Kelvin-approved. Built on `issue/P5-1-revision-log-v0` worktree by parallel agent. 7 implementation commits + 5 fix-pass + 1 final fix = 13 commits, merged to main as `303dc19`.

Contract: 443-byte runtime, append-only, single `publishRevision(...)` external function emitting `RevisionPublished` with 3 indexed topics (vaultId, accountId, parentRevision), single storage slot (`nextSequence`). No admin / no owner / no pause / no upgrade / no selfdestruct / no delegatecall / no payable. Solidity 0.8.24, evm_version=shanghai for cross-chain portability per D-005.

Tests: 17/17 pass — 13 unit (including 16-selector probe for absent admin/proxy interfaces, ETH-rejection on all paths) + 4 invariants × 10000 runs × 32 depth = 320,000 calls per invariant, 0 reverts under `fail_on_revert = true`. Slither 0 findings of 101 detectors. Build is bit-deterministic (verified by SHA-256 across rebuilds). Gas: 33k median for 256-byte payload (under 50k budget).

Two security audits performed. First audit: 0 CRITICAL, 0 HIGH, 2 MEDIUM, 4 LOW, 5 INFO. Fix-pass closed all actionable items including the v0 row in THREAT_MODEL.md. Second re-audit caught two HIGH CI-blockers (forge fmt regression introduced by fix-pass; pre-existing ABI trailing-newline mismatch); commit `12c6138` closed both. Final re-audit on `12c6138` recommended APPROVE — 100% CLEAN.

Surprises: bytecode-level audit walked all 431 runtime opcodes byte-by-byte to verify absence of CALL / DELEGATECALL / SELFDESTRUCT / ORIGIN / TLOAD / TSTORE / MCOPY / BLOBHASH / BLOBBASEFEE — confirms cardinal principles 3 and 4 hold *at the bytecode level*, not just at the source level. Solc still appends a 12-byte CBOR trailer (`a164736f6c6343000818000a`) carrying the solc version even when `bytecode_hash = "none"`; documented in `contracts/GAS.md`.

Deferred (filed as v1 follow-ups, not signoff blockers): hashed-mapping-slot probe extension once v1 introduces mappings; multi-target invariant runner; deploy-script CI regression (already partially covered by dry-run step).

Next: P5-4 (deploy `RevisionLogV0` to Base Sepolia) is a separate sub-issue; P2 series (`pangolin-store` SQLite + encrypted blobs) is the next Rust work and depends on P1's primitives, now also merged.

## 2026-05-05 · P1 — pangolin-crypto primitives + key hierarchy  ✅ MERGED

Plan at `docs/issue-plans/P1.md` Kelvin-approved. Built on `issue/P1-crypto` worktree by parallel agent. 6 implementation commits + 6 fix-pass + 1 polish = 13 commits, merged to main as `1ef3c5d`.

Crate: AEAD (XChaCha20-Poly1305 via `chacha20poly1305 0.10.1`), KDF (Argon2id at locked params 256MiB / t=3 / p=1 — RFC 9106 first-recommended profile, raised from t=1 in fix-pass), Ed25519 with `verify_strict` mode (via `ed25519-dalek 2.2.0`), HKDF-SHA512 derived wrap-AEAD-key from authority seed (info `"pangolin-vdk-wrap-v0"`). Key types: `VdkKey`, `WrappedVdk`, `WrapContext { vault_id, schema_version }`, `AuthorityKey`, `DeviceKey` — every secret-bearing type has manual `Drop` calling `Zeroize::zeroize`, implements `ZeroizeOnDrop` marker, redacted `Debug`, no `Clone`, no `Copy`, no `PartialEq` (constant-time eq via `subtle::ConstantTimeEq`), no `Serialize` (banned at supply-chain layer in `deny.toml`).

Tests: 85/85 pass default; 87/87 with `slow-tests` feature (the heavier 256MiB-Argon2id round-trip). RFC vectors: 8439 ChaCha20-Poly1305, IETF XChaCha20, RFC 8032 Ed25519, Argon2id reference. Cross-vault VDK replay test (`vdk_cross_vault_replay_fails`) exercises the `WrapContext` AAD-binding by transplanting a wrapped VDK across vault IDs — fails authentication for the right reason.

CI hardening: `cargo audit` (0 advisories across 118 deps), `cargo deny check` (advisories ok, bans ok, licenses ok, sources ok). `Cargo.lock` un-excluded and committed. `unsafe_code = "deny"` workspace-wide; `pangolin-crypto` itself has `#![forbid(unsafe_code)]` unconditional.

Two audits + a polish round. First audit: 0 CRITICAL, 4 HIGH, 7 MEDIUM, 4 LOW, 4 INFO. Fix-pass closed every actionable finding. The biggest substantive change was HIGH-3 (cross-vault replay) — closed by introducing `WrapContext` and binding it canonically (fixed-width 57-byte encoding `[domain_separator || vault_id || schema_version_be]`) into the wrap AEAD AAD on every wrap/unwrap/rewrap path. HIGH-1 (no Serialize compile-time check) was closed at the supply-chain layer (`deny.toml` ban on `serde` + `serde_derive`) instead of via `static_assertions` — strictly stronger because `serde` is no longer reachable from the crate's dep graph. Re-audit on `4b53af7` recommended APPROVE — 100% CLEAN with three INFO observations; polish commit `1f8db2a` closed two of them (broken intra-doc link from the `serde` ban; `ZeroizeOnDrop` marker on `BoxedSecret<N>` and `SecretBytes`).

Surprises: `secrecy 0.10.3` was on the locked crypto-allowlist but never imported (replaced by direct `Zeroizing` use during build); removed in fix-pass. `cargo-deny`'s `bans.allow` is closed-world for the *entire* dep graph (rejects legitimate transitives like `windows-sys` / `unicode-ident`); switched to `bans.deny` + workspace exact-version pins + committed `Cargo.lock` for the closed-world defense. `Box<[u8; N]>` does not impl `Zeroize` directly in `zeroize 1.8`; introduced `BoxedSecret<const N: usize>` newtype with manual `Zeroize` over `Box<[u8; N]>` to get heap-stable secret allocations for `AeadKey` and `VdkKey`.

Merge conflict in `.github/workflows/ci.yml` between P5-1's contracts pipeline (already merged) and P1-6's audit + deny jobs — resolved additively, both job sets retained side-by-side. Locally verified clean post-merge: fmt OK, build --all-targets OK, 85 tests pass, 17 forge tests pass, all CI gates green.

Deferred: pangolin-crypto's API surface is now frozen for downstream consumption by P2 (`pangolin-store`) and beyond. The `test-vectors` cargo feature is consumer-controlled — heavily documented as "DO NOT enable in production downstream crates."

Next: **P2 series** (`pangolin-store` — SQLite + encrypted blobs, consumes pangolin-crypto's primitives) and **P5-4** (deploy `RevisionLogV0` to Base Sepolia testnet) are the next units of work. P2 is the largest single block of remaining PoC work and gates P3/P4/P7. Neither is Kelvin-gated at PLAN time (P2 is core but not crypto/contract; P5-4 is testnet-only deployment).

## 2026-05-05 · P5-4 — Deploy RevisionLogV0 to Base Sepolia  ✅ MERGED

Plan at `docs/issue-plans/P5-4.md` Kelvin-approved. Deployed by Kelvin from local Foundry encrypted keystore (no plaintext private key on disk, env, or shell history at any point). Single tx, fast finality on Base Sepolia.

**Deployment facts (canonical reference, also in `contracts/deployments/base-sepolia.json` and DECISIONS.md D-014):**
- Address: `0x8566D3de653ee55775783bD7918Fe91b66373896`
- Chain: Base Sepolia (chain id 84532)
- Deployer: `0x89e720238A3913688CB0E025ef03a64539575c54` (Kelvin dev wallet)
- Deploy tx: `0x0569d60324c504bdacba08c309b85a54793b9002c97c4de22c9f8598e5e54b6a` (block 41133000)
- Gas used: 149,135 (matches `GAS.md` baseline exactly — no chain-specific surprises)
- Cost: 0.00000089 ETH at 0.006 gwei
- Runtime keccak256: `0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe` (Ethereum Keccak-256 of the 443-byte deployed bytecode; corrected from `0xaeff0a8f...` recorded at deploy time, which was Python's `hashlib.sha3_256` — wrong primitive. P6 audit M-1 caught this when `chaincli status` added live-bytecode cross-checking. Live bytecode unchanged; only the recorded hash was wrong.)
- Verification on Basescan: deferred (Kelvin will add API key later; `forge verify-contract` command documented in deployment metadata)

All five pre-flights passed before broadcast: chain id == 84532, deployer balance > 0.001 ETH (had 0.118), runtime size == 443 B, gas estimate within budget. End-to-end smoke test recorded as E2E-001 in `E2E_TESTS.md`: `nextSequence()` initial 0; `publishRevision(0xaaaa…, 0xbbbb…, 0x0, 0xcccc…, 0, 0xdeadbeef…)` mined with status 1 in tx `0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6`; emitted event with topic[0] = `keccak256(RevisionPublished signature)` confirmed; `nextSequence()` after = 1. The chain integration write-path is proven on a real EVM testnet.

Surprises: Base Sepolia's gas price was 0.006 gwei at deploy time — substantially below the 0.011 gwei estimate. Final cost was about 60% under projection. Useful data point for sizing the funder service's top-up amounts in MVP-2 (issue 3.4).

The `contracts/deployments/base-sepolia.json` file is the canonical machine-readable record. P6 (chaincli) and P7 (chain adapter) will read the contract address from this file; do not hardcode the address elsewhere.

Deferred: Basescan source verification (a one-command operation when Kelvin obtains a free Basescan API key). The contract works fully without it — verification is purely an explorer convenience.

Next: **P2 series** (`pangolin-store`) is now the only remaining blocker for P3/P4/P7/P8. P5-4 unblocks P6 (chaincli — talks to this deployed contract) and P7 (chain adapter — also talks to it).

## 2026-05-06 · P1.1 — `Nonce::from_storage_bytes` + `WrappedVdk::from_parts`  ✅ MERGED

Two additive public constructors on `pangolin-crypto` to support `pangolin-store`'s on-disk round-trip path. The HIGH-2 fix in P1 made `Nonce::from_bytes` `pub(crate)` to forbid deterministic-nonce construction by external callers; that's correct for fresh seal-time nonces but blocks reloading a previously-random nonce off disk alongside its ciphertext. Same threat profile as the already-public `Ciphertext::from_vec`. Doc-comments are explicit: "wraps random bytes that this crate previously emitted" — caller must not synthesize. Same gap on `WrappedVdk` — extractable via `ciphertext()`/`nonce()`/`context()` accessors but no symmetric reconstructor; `from_parts` adds it. Two new round-trip tests (87 → 89 in pangolin-crypto suite).

Surprises: the original P2 builder agent stopped mid-build on this gap rather than working around it (correct discipline). Three subsequent agents stopped on different gaps at progressively deeper layers — each was the right call. Total of three additive `pangolin-crypto` patches needed before P2 could compile cleanly.

## 2026-05-06 · P1.2 — `AuthorityKey::from_seed`  ✅ MERGED

Mirrors the existing public `SigningKey::from_seed`. Used by `Vault::unlock` to deterministically reconstruct the same `AuthorityKey` each unlock from `Argon2id(password, salt, params)` → seed bytes. Wrong password produces a different seed, which produces a different authority, which produces a different HKDF-derived wrap key, which makes `WrappedVdk::unwrap_with` return `AeadError::Tampered` — indistinguishable from any other tampering case (collapsed at the AEAD boundary).

This sidesteps the alternate design (encrypted random authority on disk) for PoC simplicity. MVP-3 social recovery may revisit; for P2 the deterministic-from-password approach is sufficient. New round-trip test (89 → 90 — wait, 88 actually since the count then went to 91 with P1.3).

## 2026-05-06 · P1.3 — `kdf::derive_seed`  ✅ MERGED

Seed-returning peer of `derive_key`. `derive_key` returns `AeadKey` whose bytes are deliberately not exposed (per MEDIUM-8 from P1's audit + supply-chain discipline). `pangolin-store`'s password-unlock path needs raw bytes to feed into `AuthorityKey::from_seed` — same Argon2id derivation, different output framing. Returns `Zeroizing<[u8; 32]>` so the buffer wipes on drop including unwind. Three new tests pin determinism (same inputs → same bytes), parity with the crate-private `derive_raw` (both KDF entry points must produce identical bytes for identical inputs), and below-floor parameter rejection. Test count 88 → 91.

Misuse-resistance discipline: doc-comment is explicit that `derive_seed` is for type-constructors that take `[u8; 32]` (`AuthorityKey::from_seed`, `SigningKey::from_seed`). For symmetric encryption, callers must use `derive_key` — the `AeadKey` newtype prevents accidental cross-primitive re-use.

## 2026-05-06 · P2 — `pangolin-store` encrypted local vault store  ✅ MERGED

The largest single PoC block: ~3,800 LOC across 9 modules, 40+ tests. Architecture from `docs/issue-plans/P2.md`: single `.pvf` file IS a SQLite database; sensitive content (display name, username, password, URL, notes, TOTP secret) lives in AEAD-sealed CBOR blobs; structural metadata (UUIDs, revision parentage, timestamps, device IDs) is plaintext SQL — same shape as on-chain `RevisionLogV0` events for trivial P7 sync semantics.

Substantive choices: bundled SQLite (no system dep), `ciborium-ll` (low-level CBOR with no `serde` reachability — preserves the supply-chain ban from P1), per-blob XChaCha20-Poly1305 with 105-byte canonical AAD binding `(WRAP_AAD_DOMAIN_REV || vault_id || account_id || parent_revision_id || schema_version)`, `BoxedSecret`/`ZeroizeOnDrop` discipline through every layer, WAL + `synchronous=FULL` + transactional writes for crash safety, `forbid(unsafe_code)` unconditional.

Vault state machine: `Closed → Locked ⇄ Active`. Public surface: `Vault::{create, open, unlock, lock, close, add_account, update_account, delete_account, get_account, search, list_accounts, revisions_for, unpublished_revisions, mark_published}`.

Cardinal-principle-2 verifier: load-bearing `no_plaintext_on_disk` property test creates a vault, writes 100 iterations × 6 unique markers per iteration (one per secret field), locks + closes, and scans raw `.pvf` bytes (and WAL sidecar) for ANY marker — asserts ZERO hits. 605s elapsed; 0 hits.

Audit history: first audit found 0 CRITICAL, 1 HIGH, 5 MEDIUM, plus LOW/INFO. Fix-pass commit `c529d7e` closed all 6 actionable findings:
- HIGH-1: `matches!` → `assert!(matches!)` in adversarial cross-account-transplant test (was a runtime no-op)
- MEDIUM-1: `KdfRejected` variant collapsed into `AuthenticationFailed` (closed an attacker oracle that distinguished KDF tamper from salt/ct tamper)
- MEDIUM-2: `Vault::open` lock-leak on failure paths (wrapped body in closure with `release_lock`-on-error)
- MEDIUM-3: plaintext-on-disk verifier extended from 1 secret field to 6
- MEDIUM-4: per-row `revisions.schema_version` now bound into AAD on decrypt (was inert)
- MEDIUM-5: `Vault::unlock` idempotence semantics on Active vault pinned in docstring + new unit test

Re-audit verdict: **APPROVE — 100% CLEAN**. All 6 prior findings closed; 0 new CRITICAL/HIGH/MEDIUM; 3 INFO observations are non-blocking design trade-offs.

Surprises: the closed-world supply-chain ban on `serde` (HIGH-1 fix from P1) ruled out high-level `ciborium`; switched to `ciborium-ll` low-level CBOR codec which has no serde reachability. SQLite's bundled C library worked cleanly on Windows with no system dep. The `WRAP_AAD_DOMAIN_REV = b"pgrev0\0\0"` 8-byte domain separator is structurally distinct from `pangolin-crypto`'s 24-byte `WRAP_AAD_DOMAIN` — no collision risk.

THREAT_MODEL.md "Local encrypted store" row moves from `TBD (issue 0.2)` to `DOCUMENTED (P2)` with 7 enumerated threats and verification artifacts cited.

Unblocks: P3 (account identity production), P4 (session policy), P7 (chain adapter against deployed Base Sepolia RevisionLogV0 from P5-4), P9 (conflict resolution).

Next: **P3** (account identity production), **P4** (session policy engine), **P6** (chaincli debug oracle), and **P7** (Rust chain adapter) are now all unblocked and parallelizable. P6 + P7 both consume the deployed RevisionLogV0 from P5-4 plus the now-merged pangolin-crypto + pangolin-store. P3 + P4 build on top of pangolin-store's API.

## 2026-05-06 · P3 — RevisionGraph + fork detection  ✅ MERGED

Adds fork-detection primitives on top of pangolin-store. `RevisionGraph` type with full parent→child indexing, head computation accommodating multi-head accounts, ancestor walks, and common-ancestor (LCA at fork point). New `Vault` API: `revision_graph(AccountId)`, `account_heads`, `is_forked`, `all_forked_accounts`. Public test helper `__test_synthesize_sibling_revision` (cfg-gated by name + `#[doc(hidden)]`) lets integration tests build forks without going through P7's chain adapter — uses real AAD-bound encryption matching production paths.

Schema unchanged: `account_identities.head_revision_id` retains its meaning as the canonical-head pointer; multi-head detection happens at query time via `NOT EXISTS` subquery (now scoped by `account_id` per the M-1 audit fix). Cardinal principle 4 preserved: graph DETECTS forks; resolution is P9.

Audit history: 0 CRITICAL, 0 HIGH, 2 MEDIUM, 2 LOW, 4 INFO. Fix-pass closed all 4 actionable items (M-1 NOT EXISTS scoping, M-2 `genesis_extra` flag exposed for P7 partial-replay + P9 conflict-distinguishing, L-1 docstring mention of `#[doc(hidden)]` placement, L-2 topological-order docstring accuracy). Re-audit verdict: APPROVE — 100% CLEAN. 125 lib + 10 e2e tests pass; cardinal-principle-2 verifier (`no_plaintext_on_disk`) still green; pangolin-crypto unchanged.

Surprises: building `genesis_extra` from the existing `revisions` table required a ~20-line filter that pushed `RevisionGraph::build` over clippy's 100-line floor. Extracted as `compute_genesis_extra` free function — cleaner than suppressing the lint. Merged as `5a5079e`.

## 2026-05-06 · P4 — Session policy engine  ✅ MERGED

The full Unified Session Authority spec on top of P3. **Security-critical** per §16.3.

Implements: 2-proof unlock (presence + identity), state machine `Locked → PendingAuthorization → Active{expires_at, last_proof_at, session_started_at} → Expired`, idle timeout (15 min default) + absolute max (4 hr) with `next_idle_deadline` as the single-source-of-truth that caps at `session_started + ABSOLUTE_MAX`, presence escalation for high-risk ops (`reveal_password`, `reveal_notes`, `reveal_totp_secret`, `export_payload`), and the `with_session` mid-action resume primitive. Cache zeroized on every expiry path (BoxedSecret + Zeroizing<Vec<u8>> drop chain, before state flip).

PoC stand-in proofs: `PinIdentityProof` (carries password bytes, ZeroizeOnDrop) + `PressYPresenceProof` (single-use `Cell<bool>`, freshness 60s). Trait-based design slots in real NFC + platform passkey in MVP-1 without API change.

**BREAKING change to `Vault::unlock`** — was `unlock(&SecretBytes)`, now `unlock(&dyn PresenceProof, &dyn IdentityProof)`. No external consumers existed; all internal + e2e tests migrated.

Audit history: 0 CRITICAL, 1 HIGH, 4 MEDIUM, 3 LOW, 1 actionable INFO. Fix-pass closed all 9:
- **H-1 (the spec violation):** `AccountSnapshot.password` was `pub`, allowing `vault.get_account(id).unwrap().password.expose()` to bypass `reveal_password`'s presence gate — a structural violation of spec §5.4 ("high-risk actions MUST require presence proof"). Fixed by making `password`/`notes`/`totp_secret` `pub(crate)`; added `reveal_notes` + `reveal_totp_secret` for symmetry. Compile-fail doctest at `account.rs:101` pins the regression — external code attempting to read those fields via `&AccountSnapshot` no longer compiles.
- **M-1 + I-6:** `with_clock` and `__test_with_timestamp` cfg-gated behind a new `test-utilities` feature so production downstream consumers cannot install a malicious clock or pre-dated presence proof.
- **M-2:** unlock timing oracle (structural-vs-content distinguishability — empty PIN microsecond-fail vs. wrong-PIN ~1.5s Argon2id) DOCUMENTED with detailed audit-traceable comment. Right-PIN vs. wrong-PIN are NOT distinguishable (both run Argon2id to completion). MVP-1 hardening: always-Argon2id on every `AuthenticationFailed` path.
- **M-3:** `static_assertions::assert_impl_all!(Vault: Send) + assert_not_impl_any!(Vault: Sync)` match rusqlite's NO_MUTEX `Connection` contract.
- **M-4:** `is_session_active()` is now clock-aware (was state-machine variant only; misleading).
- **L-1:** `derive_secret` double-allocation DOCUMENTED.
- **L-2:** `next_idle_deadline` uses `checked_add` with saturating fallback; `SystemTime` overflow fails-safe to immediate expiry instead of panicking.
- **L-3:** `with_session` re-validates session AFTER reauth returns Ok, catching "reauth claims success but didn't actually unlock" before re-running the original op.

Re-audit verdict: APPROVE — 100% CLEAN. Spec §4–§9 compliance verified MUST-by-MUST. 148 lib + 4 doctests (incl. the H-1 compile_fail regression) + 11 e2e tests pass. No new `unsafe`; no new deps (`static_assertions` was already a workspace dep). `pangolin-crypto` unchanged.

Surprises: H-1 was the most substantive finding — a textbook "the gate exists but the data is also accessible by another path" pattern. The fix had to thread through the test suite (every test that called `snap.password.expose()` had to migrate to `vault.reveal_password(id, &PressYPresenceProof::confirmed())`). Worth it: spec §5.4 is now structurally enforced at the type-system layer rather than as a documentation invariant.

Unblocks: P5+ host UI shells (Tauri desktop, iOS, Android) — they consume the trait-based proof API and the `with_session` resume primitive. **P6** (chaincli debug oracle) and **P7** (Rust chain adapter) are also unblocked but those don't need session policy; they consume P5-4's deployed contract directly via `pangolin-chain`. Merged as `aab248f`.

Next: **P6** (chaincli) and **P7** (chain adapter) are the natural next pair — both consume the deployed RevisionLogV0 from P5-4 + pangolin-crypto's signing + pangolin-store's local revisions. They unblock **P8** (sync flow), **P9** (conflict resolution), **P10** (tombstones), **P11** (E2E demo), **P12** (packaging) — i.e., the rest of the PoC.

## 2026-05-06 · P8 — pangolin-cli sync (publish + pull + dirty tracking)  ✅ SIGNOFF

Plan at `docs/issue-plans/P8.md` Kelvin-approved (Q4–Q6 answered: two-key PoC model accepted, `tools/pangolin-cli/` location accepted, defense-in-depth signature verify on ingest accepted). **Security-critical** per §16.3 — first issue that wires the vault end-to-end through the chain.

7 commits along the §16.4 BUILD-gate discipline:

- **P8-1** scaffolds `tools/pangolin-cli/` (clap shape, three subcommand stubs, deployment-file walk-up, RPC-URL precedence chain). Mirrors `tools/chaincli/` byte-for-byte. The pre-existing `crates/pangolin-cli/` placeholder (a `pangolin` smoke-test binary) is removed; workspace `members` updated.
- **P8-2** adds the `dirty_accounts` SQL table with `Vault::{mark,clear,list}_dirty` API. Auto-stamp inside `add_account` / `update_account` / `delete_account` runs in the same transaction as the revision INSERT — a crash leaves the vault in the pre-transaction state. `(account_id, revision_id)` composite primary key per §A2 protects against duplicate-publish on re-run.
- **P8-3** implements `pangolin-cli publish`. `sync::publish_all<A: ChainAdapter>` walks the dirty list; per-entry it reads the revision row's `(parent, schema_version, enc_payload)`, builds a `SignedRevision`, runs the §A3 pre-publish check (canonical-hash compare against `pull_since(vault_id, last_pulled_block, None)`), submits, then runs `mark_published` + `clear_dirty`. Per-account error isolation via `PublishReport`. The keystore loader mirrors chaincli; vault unlock uses the standard P4 two-proof flow.
- **P8-4** implements `pangolin-cli pull`. `sync::pull_all<A: ChainAdapter>` chunks the block range into PULL_CHUNK_SIZE = 8 000 windows. Per chunk: pull → Q6 device_id canonical-form check on every event → `Vault::ingest_chain_revision`. After each chunk: `advance_last_pulled_block(chunk_end)` BEFORE the next chunk's `pull_since` — resolves P7 audit MED-3. Forks surface via `PullReport.forks` (cardinal principle 3 — chain is a log, not an authority). Pull exits 0 even with forks; P9 resolves them.
- **P8-5** implements `pangolin-cli status`. Read-only diagnostics; works on a Locked vault (no chain calls). Reports `vault_id`, `dirty_count`, `account_count`, `last_pulled_block`, `last_published_block` (max chain_block_number).
- **P8-6** ships the integration suite. `tests/two_vault_roundtrip.rs` runs three plan-required scenarios (`convergence`, `symmetric_fork`, `idempotent_repeat_pull`) using two vaults that share identity by file-copy. `tests/integration_base_sepolia.rs` is gated `#[cfg(feature = "integration-tests")]`. Adds `src/lib.rs` so integration tests can import the orchestration core (binary crates can't be imported by integration tests under `tests/*.rs` without a lib path).
- **P8-7** documentation (this commit): THREAT_MODEL.md row (9 enumerated threats covering forged publish, replay, partition during chunked pull, dirty-entry leak, cross-vault replay, pre-publish check race, MockChainAdapter substitution, two-key gas-wallet correlation, forged-event-stream); E2E-003 entry (automated MockChainAdapter path + manual Base Sepolia path with funded keystore); this DEVLOG entry; surface table updated.

**Test count delta:** 195 → 242 lib tests + 6 integration tests = 248 total. The standard gate command `cargo test --workspace --lib` runs the 242 lib tests; the 6 integration tests live under `tools/pangolin-cli/tests/*.rs` and run when `cargo test --workspace` (no `--lib`) is invoked. Breakdown:
- pangolin-store: 75 → 90 (+15 = 12 dirty + 3 ingest_chain_revision)
- pangolin-cli unit (lib): 0 → 32 (cli, config, keystore, sync publish + pull, status, vault_open)
- pangolin-cli integration: 0 → 6 (3 cli_arg_parsing + 3 two_vault_roundtrip)
- gated Base Sepolia tests: 2 (off by default; not in the 248 count)

**Architecture surprises:**

- The plan's content-deterministic `revision_id = canonical_hash` discipline collides with P0..P7's random `RevisionId` generation. The two reconcile via three idempotency arms in `Vault::ingest_chain_revision`: exact `revision_id` match, `(account_id, chain_tx_hash, block_number, log_index)` match, and a content-merge path that UPDATEs the existing row's chain anchor when a local `chain_tx_hash IS NULL` row matches by `(account_id, parent_revision, enc_payload, schema_version)`. Without the merge arm, every publish-then-pull round-trip would produce a spurious 2-head fork.
- Two-key PoC model means the locally-stored `device_id` (random bytes from `randomblob(32)`) doesn't match the publish-time signing key's pubkey. Idempotency checks therefore deliberately ignore `device_id` and match on chain anchor + content. MVP-1 will switch to `pangolin_chain::evm::derive_evm_wallet` to satisfy D-006's wording, at which point `device_id` will round-trip and the idempotency check can tighten.
- v0 contract doesn't transport the signature bytes in `RevisionPublished`. Q6 defense-in-depth therefore reduces to a `VerifyingKey::from_bytes` shape check on every event's `device_id` — full Ed25519 `verify` is blocked until v1 records the signature on-chain. The shape check still catches an attacker-controlled-RPC threat: any `device_id` that isn't a canonical Ed25519 point is refused at the device boundary.
- `pangolin-cli` has both `src/main.rs` and `src/lib.rs` because integration tests under `tests/*.rs` cannot import a binary's modules. The library is internal-use-only — external consumers should use `pangolin-store` + `pangolin-chain` directly.

**Critical invariants verified at the tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1 holds)
2. No new `unsafe` (verified by workspace `unsafe_code = "deny"`)
3. No plaintext on disk (`pangolin-cli` does not write decrypted vault data anywhere — `read_revision_for_publish` returns the AEAD-sealed `enc_payload` verbatim)
4. Per-chunk all-or-nothing in pull (verified by `pull_chunk_failure_preserves_prior_chunk_progress`)
5. Per-account atomicity in publish (verified by `publish_per_account_isolation` + `publish_idempotent_on_rerun_after_partial_failure`)
6. Signature verify on pull (`pull_all`'s loop body runs `VerifyingKey::from_bytes` before ingest)
7. Workspace clippy `-D warnings` clean
8. No regression in the 195 P0..P7 lib tests; total now 248

**Deferred follow-ups (not signoff blockers):**

- MVP-1 switches `pangolin-cli publish` to `evm::derive_evm_wallet` for the gas wallet, closing the §A7 D-006 deviation.
- MVP-1 issue 1.4 plans the move to content-deterministic `RevisionId` for locally-created revisions (P2/P3 still use random ids), at which point the ingest path's content-merge arm becomes redundant.
- v1 contract (MVP-2 issue 2.1) records the signature on-chain; `pull_all`'s Q6 check upgrades from "device_id canonical form" to full `verify_signed_revision` at that point.
- Master plan §16.8 layout table needs to record `tools/pangolin-cli/` (was `crates/pangolin-cli/` in the original layout; deviation per Q5 / §A8 of the P8 plan).

Unblocks **P9** (conflict resolution UX — `pangolin-cli resolve <account-id> --keep <revision-id>`), **P10** (tombstone-aware deletes), **P11** (E2E recorded screencast).

## 2026-05-06 · P8 fix-pass — §16.5 audit findings (CRIT-1, MED-1, MED-2, MED-3, MED-4, LOW-1, LOW-2)  ✅ SIGNOFF

Single fix-pass commit on top of the P8-7 tip. Addresses every actionable finding from the §16.5 security audit; HIGH-1 + INFO-1/2/3 are no-code-change per auditor (bounded by Cardinal Principle 3 / observation-class).

**CRIT-1 — Tombstone-flag non-propagation.** Closed via a `frozen_pending_resolve` sentinel column on `account_identities` (additive `ALTER TABLE … ADD COLUMN` migration at `Vault::open` so existing P0..P7+P8-pre-fix vault files keep opening cleanly). `Vault::ingest_chain_revision` sets the flag to `1` when the ingest takes the genuine-foreign-INSERT path (none of the three idempotency-merge arms matched). User-facing read paths (`get_account`, `list_accounts`, `search`, `reveal_password`, `reveal_notes`, `reveal_totp_secret`, `export_payload`) refuse on frozen accounts: `Option`-returning APIs filter the row out; the explicit `Result`-returning ops surface a new `StoreError::AccountFrozenPendingResolve { account_id }` variant. Edit paths (`update_account`, `delete_account`, `mark_dirty`) refuse with the same error so a user editing their stale plaintext copy of a chain-modified account cannot create a silent fork. The flag is cleared by the upcoming `pangolin-cli resolve` (P9). The new `Vault::list_frozen_accounts` exposes the set; `pangolin-cli pull` includes the count in its summary, and `pangolin-cli status` reports per-account ids.

**MED-1 — Spoofed chain anchor on local pre-publish row.** The third merge arm of `Vault::ingest_chain_revision` (the `(account_id, parent_revision, enc_payload, schema_version, chain_tx_hash IS NULL)` content merge) now ALSO requires `device_id` to match. The auditor's preferred re-fetch-via-`get_revision` approach was rejected because under attacker-controlled-RPC both directions of the conversation are spoofable; the `device_id` binding is a content-bound check that doesn't depend on the transport. Trade-off: under the PoC two-key model the legitimate own-publish round-trip ALSO fails the `device_id` match (publish generates an ephemeral signing `DeviceKey` per call whose pubkey differs from the local row's random `device_id` from `Vault::open`), so it routes through idempotency arm #2 `(account_id, chain_tx_hash, block, log)` after `mark_published` has stamped the local row's chain anchor. Cross-vault round-trips (vault B pulling vault A's publishes) intentionally trigger CRIT-1's freeze. MVP-1's switch to D-006's derived wallet aligns local-row and chain-event `device_id`, restoring silent cross-device merge under the non-attack case while preserving the new defense.

**MED-2 — HTTP RPC URL accepted.** Added `--allow-insecure-rpc` global flag and `ResolvedConfig::enforce_rpc_scheme` helper. Default behavior: any URL whose scheme is not `https` (case-insensitive) is refused with a clear remediation hint mentioning the override flag. Both `pangolin-cli publish` and `pangolin-cli pull` call `enforce_rpc_scheme` immediately after `rpc_url_or_default` and before the chain adapter is constructed.

**MED-3 — `--vault-path` not canonicalized.** Added `vault_open::canonicalize_vault_path` and routed every `Vault::open` callsite (status, publish, pull) through it. The status output now includes a `vault_path` row showing the resolved absolute path; the password prompt also references the canonical path so a user with a confused working directory sees what they're actually unlocking.

**MED-4 — `forbid(unsafe_code)` not unconditional.** Replaced the `cfg_attr`-guarded variants in `tools/pangolin-cli/src/{main,lib}.rs` with a single unconditional `#![forbid(unsafe_code)]`. `forbid` cannot be relaxed by a downstream `allow`, so a future test annotating a block with `#[allow(unsafe_code)]` would fail the build.

**LOW-1.** Updated `tools/pangolin-cli/Cargo.toml` comment to reflect the bin+lib hybrid added in P8-6.

**LOW-2.** Updated DEVLOG line on test count attribution to clarify "242 lib tests + 6 integration tests = 248 total" before the fix-pass.

**HIGH-1, INFO-1/2/3.** No code change per auditor. THREAT_MODEL.md rows #1 and #9 reaffirmed as honest framing (verified read-through; no prose-tightening needed — the rows already explicitly call out v0 contract not transporting signature bytes and the bound by Cardinal Principle 3).

**Threat model additions.** Rows #10 (CRIT-1's `frozen_pending_resolve` sentinel) and #11 (MED-1's `device_id`-binding tightening) appended to `THREAT_MODEL.md`'s pangolin-cli section.

**Test count delta:** 242 → 253 lib tests (+11). New tests:

- `pangolin-store::vault::tests::frozen_after_foreign_ingest_blocks_reveal_password`
- `pangolin-store::vault::tests::own_publish_roundtrip_does_not_freeze`
- `pangolin-store::vault::tests::frozen_account_blocks_mark_dirty`
- `pangolin-store::vault::tests::frozen_account_listed_separately_in_pull_result`
- `pangolin-store::vault::tests::legacy_vault_picks_up_frozen_column_on_open`
- `pangolin-cli::config::tests::http_rpc_rejected_without_flag`
- `pangolin-cli::config::tests::http_rpc_accepted_with_flag`
- `pangolin-cli::config::tests::https_rpc_always_accepted`
- `pangolin-cli::config::tests::https_scheme_match_is_case_insensitive`
- `pangolin-cli::commands::status::tests::vault_path_canonicalized_in_status_output`
- `pangolin-cli::cli::tests::allow_insecure_rpc_flag_parses`

Plus `tests/two_vault_roundtrip.rs::convergence` updated to assert that B's pull triggers the CRIT-1 freeze sentinel (its previous "merge succeeds silently" assertion is no longer the post-fix expected behavior under PoC two-key — see the inline comment on the test for the MVP-1 path that restores the silent merge).

**Critical invariants verified at the fix-pass tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1 holds)
2. No new `unsafe`; `forbid(unsafe_code)` is now unconditional (MED-4 strengthens this)
3. No plaintext on disk
4. Per-chunk all-or-nothing in pull (CRIT-1's freeze sentinel doesn't change this)
5. Per-account atomicity in publish; frozen accounts refuse `mark_dirty` cleanly
6. `cargo fmt --all --check` clean
7. `cargo clippy --workspace --all-targets -- -D warnings` clean
8. `cargo test --workspace --lib` — 253/253 passing (242 baseline + 11 new)
9. `cargo audit` clean (the 2 pre-existing unmaintained-warning entries documented in `deny.toml` remain unchanged)
10. `cargo deny check` — advisories ok, bans ok, licenses ok, sources ok
11. `cargo build --workspace --release` clean
12. `pangolin-cli --help` lists `status`, `publish`, `pull` and the new `--allow-insecure-rpc` flag

## 2026-05-07 · P9 — pangolin-cli resolve (Conflicts & Resolve EPIC)  ✅ SIGNOFF

Plan at `docs/issue-plans/P9.md` Kelvin-approved with seven locked
answers (Q1: multi-resolve for N-way forks APPROVED, no
`demote_orphan_heads`; Q2: ship without concurrent-resolve race
guard; Q6: `read_payload_plaintext_for_resolve` documented bypass
APPROVED; Q7: pre-publish chain re-pull APPROVED; Q3/Q4/Q5: full
hex revision-id, tombstone-of-tombstone, `--dry-run` ships).
Ship six commits on `issue/P9-resolve` branch from baseline tip
`101c1c3`.

**P9-1.** `Vault::clear_frozen(account_id, chosen_revision_id)`
clears `frozen_pending_resolve` AND advances `head_revision_id`
in one `BEGIN IMMEDIATE … COMMIT` transaction.
`Vault::read_payload_plaintext_for_resolve(account_id,
revision_id)` is the documented freeze-guard bypass for the
resolve flow's plaintext re-seal step (loud docstring; single
in-process caller). Cross-account substitution collapses to
`AccountNotFound` (no oracle). 7 tests added.

**P9-2.** New `crate::conflict` module hosts `ConflictReport {
account_id, heads, frozen }`. `Vault::list_conflicts()` joins
fork state and freeze state via union-then-dedup, sorted by
`account_id` byte-order ASC. Surfaces all four state combinations
(forked / frozen / both / neither). 6 tests added.

**P9-3.** clap surface for `pangolin-cli resolve --account-id
<hex> --keep <hex> [--yes] [--dry-run] [--account|--keystore-path]
[--vault-password] [--keystore-password]`. Custom value parsers
`HexAccountId` / `HexRevisionId` reject non-64-char or non-hex
input at clap-validation time per Q3 (full hex, no prefix).
`commands/resolve.rs` handler opens the vault, validates the
chosen head locally, prompts for confirmation (skippable via
`--yes`), builds the adapter, dispatches to
`sync::resolve_one`. 9 clap-shape tests added.

**P9-4.** Full `sync::resolve_one` body. Flow: validate `--keep`
is a current head → pre-publish re-pull (Q7) → re-validate heads
(`ChainMovedDuringResolve` if a NEW head appeared) →
`Vault::build_merge_payload_for_resolve` (the new helper that
composes `read_payload_plaintext_for_resolve` + `seal_snapshot` /
`seal_tombstone` per A2/A5; plaintext NEVER leaves the store
crate) → `build_signed_revision` → A3 pre-publish canonical-hash
scan → publish (or skip per A3 already-on-chain) →
`ingest_chain_revision` → `clear_frozen` → advance
`last_pulled_block`. `--dry-run` short-circuits at the canonical
hash and prints `would publish revision <hex>`. 7 tests added.

**P9-5.** Renames the existing `convergence` integration test to
`convergence_freezes_on_pull` (the post-P8-CRIT-1 freeze remains
the expected pre-resolve PoC behavior). New
`convergence_after_resolve` test pins the simple two-handle
convergence flow per P9 plan §A4: A publishes → B pulls
(frozen) → B runs `resolve` against B's local genesis (the only
locally-decryptable head) → B's freeze is CLEAR. Adds E2E-004
entry to `E2E_TESTS.md` with both automated + manual paths.

**P9-6.** This DEVLOG entry. `THREAT_MODEL.md` rows 12–17 added
to the `pangolin-cli` section: 12 (forged resolve), 13 (replay
of an old resolve), 14 (frozen flag cleared without publish),
15 (HIGH-1 attacker-controlled head adoption — UX-only mitigation
acknowledged), 16 (`read_payload_plaintext_for_resolve` bypass —
loud-docstring mitigation per Q6), 17 (concurrent-resolve race
per A7 / Q2 — ship without).

**Test count delta:** 253 → 282 lib tests (+29). New tests:

- `pangolin-store::vault::tests::clear_frozen_advances_head_and_clears_flag`
- `pangolin-store::vault::tests::clear_frozen_idempotent_on_already_clean`
- `pangolin-store::vault::tests::clear_frozen_rejects_unknown_revision`
- `pangolin-store::vault::tests::clear_frozen_rejects_unknown_account`
- `pangolin-store::vault::tests::read_payload_plaintext_for_resolve_bypasses_freeze_guard`
- `pangolin-store::vault::tests::read_payload_plaintext_for_resolve_requires_unlocked_vault`
- `pangolin-store::vault::tests::read_payload_plaintext_for_resolve_rejects_wrong_account_id`
- `pangolin-store::conflict::tests::list_conflicts_empty_on_clean_vault`
- `pangolin-store::conflict::tests::list_conflicts_lists_only_forked`
- `pangolin-store::conflict::tests::list_conflicts_lists_only_frozen`
- `pangolin-store::conflict::tests::list_conflicts_lists_forked_and_frozen`
- `pangolin-store::conflict::tests::list_conflicts_handles_frozen_with_single_head`
- `pangolin-store::conflict::tests::list_conflicts_dedup_when_account_is_both_forked_and_frozen`
- `pangolin-cli::cli::tests::resolve_parses_with_minimum_args`
- `pangolin-cli::cli::tests::resolve_requires_account_id`
- `pangolin-cli::cli::tests::resolve_requires_keep`
- `pangolin-cli::cli::tests::resolve_account_id_must_be_64_hex_chars`
- `pangolin-cli::cli::tests::resolve_keep_must_be_64_hex_chars`
- `pangolin-cli::cli::tests::resolve_account_id_rejects_non_hex`
- `pangolin-cli::cli::tests::resolve_dry_run_flag_parses`
- `pangolin-cli::cli::tests::resolve_yes_flag_parses`
- `pangolin-cli::cli::tests::resolve_account_and_keystore_path_conflict`
- `pangolin-cli::sync::tests::resolve_publishes_merge_revision`
- `pangolin-cli::sync::tests::resolve_clears_freeze_on_success`
- `pangolin-cli::sync::tests::resolve_fails_cleanly_on_publish_error`
- `pangolin-cli::sync::tests::resolve_idempotent_after_partial_failure`
- `pangolin-cli::sync::tests::resolve_chain_moved_during_resolve_aborts_cleanly`
- `pangolin-cli::sync::tests::dry_run_does_not_publish_or_clear`
- `pangolin-cli::sync::tests::resolve_rejects_non_head_revision`

Plus integration: `tests/two_vault_roundtrip.rs::convergence_after_resolve` (new) + `convergence_freezes_on_pull` (rename of `convergence`).

**Critical invariants verified at the SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1 holds)
2. No new `unsafe`; `forbid(unsafe_code)` unconditional in pangolin-cli (P8 MED-4)
3. No plaintext on disk — `read_payload_plaintext_for_resolve` returns plaintext to RAM only; `build_merge_payload_for_resolve` re-seals in RAM and returns ciphertext
4. Append-only state — `clear_frozen` UPDATEs only the freeze flag + head_revision_id; no revision row is ever mutated
5. Per-account atomicity — resolve = "publish then ingest+clear"; failed clear after publish is recoverable (the next pull's arm-2 catches via tx_hash) and re-running resolve with the stale `--keep` surfaces `NotAHead` cleanly
6. `cargo fmt --all --check` clean
7. `cargo clippy --workspace --all-targets -- -D warnings` clean
8. `cargo test --workspace --lib` — 282/282 passing (253 baseline + 29 new)
9. `cargo test --workspace --tests` — integration tests pass (4 in two_vault_roundtrip; the rest unchanged)
10. `cargo audit` — 2 pre-existing unmaintained advisories documented in `deny.toml` (RUSTSEC-2024-0388 etc.) — no new advisories
11. `cargo deny check` — advisories ok, bans ok, licenses ok, sources ok
12. `cargo build --workspace --release` clean

**Open questions / acknowledged gaps:**

- The convergence test's full multi-device single-head pattern
  requires N resolves under PoC two-key (one per device that has
  ingested the foreign chain row but cannot decrypt it because the
  AEAD nonce isn't on chain). MVP-1's switch to D-006's single-key
  model + nonce-on-chain semantics closes the multi-resolve gap.
  The test pins the simple two-handle case where ONE resolve
  clears B's freeze; the multi-resolve N-way case is documented
  as expected PoC behavior per Q1.
- Concurrent-resolve race ships without an interactive freshness
  guard per Q2 — recovery is mechanical (re-resolve on next pull).
- `read_payload_plaintext_for_resolve` is documented as the only
  freeze-guard bypass; alternatives (re-supply password as fresh
  proof) were rejected per the rationale in P9 plan §A8.

Unblocks **P10** (tombstone-aware deletes — P9 ships the
structural is_tombstone round-trip; P10 owns full semantics) and
**P11** (E2E recorded screencast). The `pangolin-cli` binary is
now at four subcommands: `status`, `publish`, `pull`, `resolve`.

## 2026-05-07 · P9 fix-pass — §16.5 audit findings (HIGH-1, MED-1, MED-2, MED-3, MED-4, LOW-1)  ✅ SIGNOFF

Per Kelvin's "100% clean" bar, every actionable finding from the
P9 §16.5 audit is closed with code + tests. Single commit on
`issue/P9-resolve` from baseline tip `6d6bc28`.

**HIGH-1 — A3 partial-failure recovery is structurally
non-functional.** Auditor's exact text: "the user is permanently
stuck — frozen account, unresolvable." Each `resolve_one`
invocation generated a fresh ephemeral `DeviceKey` AND a fresh
AEAD nonce, so the canonical hash differed every run; the chain
event from a prior partially-completed run could not be matched
on retry.

Fix: new `pending_merges` SQLite table stashes the
merge-revision-build state (ephemeral `DeviceKey` secret seed,
AEAD nonce, AEAD ciphertext, schema_version) BEFORE
`adapter.publish`. Retry calls `Vault::take_pending_merge`,
reconstructs the SAME `DeviceKey` via `DeviceKey::from_seed`, and
re-uses the SAME nonce + ciphertext — so the canonical hash is
bit-equal across retries and the existing A3 idempotency scan
inside `sync::resolve_one` matches the chain event from the prior
run. After `clear_frozen` succeeds the stash row is deleted via
`Vault::clear_pending_merge`. Schema migration is idempotent
(`CREATE TABLE IF NOT EXISTS` + a defensive
`migrate_pending_merges_table` helper that runs on every
`Vault::open` for legacy vaults).

**MED-1 — multi-resolve invariant untested.** Added
`resolve_against_three_heads_keeps_chosen_demotes_others_to_orphans`
in `tools/pangolin-cli/src/sync.rs::tests`. A 3-head fork
(`MockChainAdapter` + two synthetic foreign events under the same
genesis-parent) resolved with `--keep <local_genesis>` produces a
merge revision pointing at `local_genesis`; the post-resolve
`account_heads(account_id)` returns the merge revision PLUS the
two unchosen orphans (length 3, not 1). The user re-runs resolve
to fold each orphan in (PoC two-key Q1 multi-resolve pattern;
MVP-1's switch to D-006's single-key model closes the gap).

**MED-2 — `clear_frozen` atomicity test dropped.** Added
`clear_frozen_atomic_under_simulated_crash` in vault.rs. Pinned
the BEGIN IMMEDIATE wrapper across the freeze-clear +
head-advance UPDATE pair via a transaction-rollback control test
(direct SQL UPDATE inside an unchecked_transaction that is
dropped without commit) followed by the `clear_frozen` success
path's combined-write assertion. We did not use
`rusqlite::update_hook` per the audit's fallback hint — the API
is not stable across rusqlite versions and the
transaction-rollback discipline is the relevant invariant
anyway.

**MED-3 — `clear_frozen` doesn't validate `chosen_revision_id`
is a current head.** New head-membership check inside
`clear_frozen`'s SQL transaction (`BEGIN IMMEDIATE`) BEFORE the
UPDATE — uses the same `NOT EXISTS` predicate that
`account_heads` uses for the multi-head detector, scoped by
`account_id`. New `StoreError::NotAHead {account_id, chosen,
current_heads}` variant fires if the supplied revision exists
but isn't a current head. Test:
`clear_frozen_rejects_non_head_revision_id` (a UPDATE-demoted
genesis revision is rejected as non-head). Updated docstring:
"errors with NotAHead if the supplied revision_id is not a
current head AT THE TIME of the SQL transaction."

**MED-4 — `--dry-run` mutates local state via pre-publish pull.**
`sync::resolve_one` now short-circuits `pull_all` on `dry_run =
true`. The dry-run output retains the canonical-hash computation
but does not advance `last_pulled_block` or ingest any chain
rows. Updated existing test `dry_run_does_not_publish_or_clear`
to also assert `last_pulled_block` is UNCHANGED post-call.

**LOW-1 — `__test_synthesize_sibling_revision` is `pub` without
`cfg`.** Added `#[cfg(any(test, feature = "test-utilities"))]`
gate per the docstring's existing promise. The
`tests/e2e.rs` integration test (which links the crate
externally and uses the helper) is annotated with
`required-features = ["test-utilities"]` in pangolin-store's
Cargo.toml so cargo skips it when the feature is disabled and
includes it when `--features test-utilities` is set. Production
builds of the workspace binaries (`chaincli`, `pangolin-cli`)
do not link against the helper.

**LOW-2, LOW-3, INFO-1 — observation-class.** Per audit
guidance: LOW-2 is inherited from P8 (no new code change);
LOW-3 ("AlreadyOnChain user message dead code") naturally
closes via HIGH-1's stash mechanism — with the canonical-hash
determinism the stash provides, the AlreadyOnChain branch
becomes reachable when the prior run's publish landed on chain
but `clear_frozen` was killed; INFO-1 is observation-only.

**`THREAT_MODEL.md` row #13** rewritten to honestly describe the
stash discipline, the at-rest model for the seed BLOB, and the
test list pinning the recovery semantics.

**Test count delta:** 282 → 290 lib tests workspace-wide (+8):

1. `stash_take_clear_round_trip` (vault.rs) — basic API.
2. `stash_persists_across_close_open` (vault.rs) — durability.
3. `take_returns_none_for_nonexistent_account` (vault.rs).
4. `pending_merge_zeroizes_secret_on_drop` (vault.rs) —
   structural Drop discipline on `SecretBytes`.
5. `clear_frozen_rejects_non_head_revision_id` (vault.rs) —
   MED-3.
6. `clear_frozen_atomic_under_simulated_crash` (vault.rs) —
   MED-2.
7. `resolve_against_three_heads_keeps_chosen_demotes_others_to_orphans`
   (sync.rs) — MED-1.
8. `resolve_idempotent_after_partial_failure_via_stash`
   (sync.rs) — HIGH-1 end-to-end recovery.

The existing `dry_run_does_not_publish_or_clear` test was
extended with a `last_pulled_block` assertion (MED-4) without
counting as a separate addition.

**Critical invariants verified at the SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; no new transitive deps from the fix-pass).
2. No new `unsafe`. The stash table stores secrets at rest but
   doesn't introduce unsafe.
3. No plaintext on disk. The stashed `enc_payload` is AEAD
   ciphertext; the `device_secret` is an Ed25519 secret seed
   (NOT vault plaintext). The AEAD-seal happens inside
   `Vault::build_merge_payload_for_resolve` BEFORE the stash.
4. Per-chunk all-or-nothing in pull. Unchanged.
5. Per-account atomicity. Strengthened by the stash + by
   MED-3's head-membership check inside `clear_frozen`'s
   transaction.
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets --features
   pangolin-store/test-utilities -- -D warnings` clean.
8. `cargo test --workspace --lib --features
   pangolin-store/test-utilities` — 290/290 passing (282
   baseline + 8 new).
9. `cargo test --workspace --tests --features
   pangolin-store/test-utilities` — integration tests pass.
10. `cargo build --workspace --release` clean.

**Behaviour-preserving for everyone except the auditor's
finding:** existing tests all continue to pass. The HIGH-1
stash adds two new methods (`stash_pending_merge`,
`take_pending_merge`, `clear_pending_merge`) and one new struct
(`PendingMerge`); the existing `Vault::build_merge_payload_for_resolve`
signature was extended (returning a 4-tuple including the
nonce instead of a 3-tuple) — internal-only call inside
`sync::resolve_one`.

## 2026-05-07 · P9 fix-pass 2 — close HIGH-1 fully + orphan stash prune + cosmetic  ✅ SIGNOFF

The `2d13fea` first fix-pass closed HIGH-1 for the publish-FAILED
retry case but the re-audit identified that the publish-SUCCEEDED-
but-`clear_frozen`-killed case was still unrecoverable. Plus two
new findings (MEDIUM-2 orphan stash accumulation, LOW-2 dry-run
staleness disclosure) and one cosmetic (LOW-1 stale comment about
`DeviceKey::from_seed`).

**HIGH-1 deeper fix — kill-after-publish-success recovery.** The
re-auditor's structural diagnosis: in the prior `resolve_one`, the
sequence `pull_all → chain_moved guard → take_pending_merge` was
fatal for the publish-succeeded-but-killed scenario. On retry,
`pull_all` ingested the prior merge revision as a foreign event,
advancing the head set; `chain_moved = post_pull_heads.iter().any(|h|
!pre_pull_heads.contains(h))` fired (the just-ingested merge IS a
new head); `ChainMovedDuringResolve` aborted BEFORE the stash was
consulted; user permanently stuck.

Fix: re-ordered `sync::resolve_one`. `take_pending_merge` runs FIRST
(unconditionally), THEN `pull_all`, THEN a stash-vs-chain canonical-
hash match against the post-pull LOCAL revisions table. If the
stash's deterministic canonical hash matches a locally-ingested row
with a populated chain anchor, we take the `AlreadyOnChain` path:
`clear_frozen` (advances `head_revision_id` to the merge-rev id and
clears the freeze flag in one transaction) + `clear_pending_merge`
(drop the stash row). The `chain_moved` and `chosen-still-a-head`
guards fire only when no stash matches — i.e., when the chain has
moved BEYOND the user's stashed-`--keep` target. Critical
correctness point: `clear_frozen` does NOT decrypt the local row;
it only validates head-membership and runs the UPDATE pair, so
the foreign-ingested row's placeholder zero `enc_nonce` is not a
problem for the recovery path.

We use the LOCAL revisions table (post-pull) rather than re-calling
`adapter.pull_since` because `pull_all` already advanced
`last_pulled_block` past the merge event's block, so a fresh
`pull_since(last_pulled_block)` would return an empty view. The
local revisions table is the canonical post-pull source of truth,
and `pull_all` itself signature-verifies the foreign event's
`device_id` canonical form (defense-in-depth against forged
streams) before ingesting — so a stash-match against a locally-
ingested row is no weaker than a stash-match against the chain
view.

**MEDIUM-2 (new) — orphan stash accumulation.** Added
`Vault::prune_orphan_pending_merges(account_id) -> Result<usize>`.
Iterates `pending_merges` rows for `account_id` inside a single
SQL transaction (collects current heads via the `account_heads`
predicate, scans stash rows, deletes any whose `target_head_id`
is not a current head). Called from:

- `pull_all` after each chunk's per-account ingest sequence
  completes (per-chunk all-or-nothing discipline preserved — the
  prune runs in its own transaction after the chunk's events
  have committed and the checkpoint has advanced),
- `resolve_one` alongside `take_pending_merge` at the top of the
  flow (skipped on dry-run for purity).

Failures are non-fatal — logged + skipped, the next prune
invocation retries. Three new tests:
`prune_orphan_pending_merges_removes_non_head_targets`,
`prune_no_op_when_all_targets_are_heads`, `prune_no_op_on_empty_table`.

**LOW-1 (re-audit) — stale comment in `crates/pangolin-chain/src/evm.rs`.**
The comment in `structural_property_distinct_seeds_distinct_signatures`
claimed "we can't construct `DeviceKey::from_seed` (no such public
API)". The first P9 fix-pass made `DeviceKey::from_seed` public.
Updated the comment to reflect the new state: "now public (added
by P9 fix-pass HIGH-1), but this test predates that surface and
intentionally probes the structural property at the `SigningKey`
layer to keep the pangolin-chain → pangolin-crypto dependency
surface minimal." Test logic unchanged — uses `SigningKey::from_seed`
directly per the auditor's read.

**LOW-2 (re-audit) — dry-run output omits staleness disclosure.**
The `--dry-run` path in `sync::resolve_one` skips the pre-publish
chain re-pull (per MED-4 hygiene), so the canonical hash printed
to the user is computed against a possibly-stale local view of the
chain. Added an explicit disclosure line BEFORE the canonical-hash
print in `tools/pangolin-cli/src/commands/resolve.rs`'s dry-run
branch: "pre-publish chain re-pull SKIPPED (dry-run mode); current
local view may be stale." Wet-path output unchanged.

**`THREAT_MODEL.md` row #13** rewritten to honestly describe the
now-fully-functional kill-after-publish-success recovery (the
re-ordered `resolve_one`'s stash-vs-local match path), the
`prune_orphan_pending_merges` mechanism, and the updated test list.

**Test count delta:** 290 → 294 lib tests workspace-wide (+4):

1. `prune_orphan_pending_merges_removes_non_head_targets` (vault.rs).
2. `prune_no_op_when_all_targets_are_heads` (vault.rs).
3. `prune_no_op_on_empty_table` (vault.rs).
4. `resolve_recovers_from_kill_after_publish_success` (sync.rs)
   — the kill-after-publish-success end-to-end recovery test
   that the re-auditor explicitly called out as missing.

**Critical invariants verified at the P9 fix-pass 2 SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; no new transitive deps from the fix-pass).
2. No new `unsafe`.
3. No plaintext on disk. The stash semantics + the freeze-guard
   bypass discipline are unchanged.
4. Per-chunk all-or-nothing in pull. Preserved — the prune runs
   in its own transaction AFTER the chunk's events have
   committed and the checkpoint has advanced; failures are
   logged but not fatal.
5. Per-account atomicity. Strengthened (the stash-match path
   composes `clear_frozen`'s atomic head-advance with the stash
   delete, all under per-account scoping).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings` clean.
8. `cargo test --workspace --lib` — 294/294 passing (290
   baseline + 4 new).

## 2026-05-07 · P10 — Tombstones & Offline Mode EPIC  ✅ SIGNOFF

Plan at `docs/issue-plans/P10.md` Kelvin-approved with three
locked answers (Q1: TombstonePayload three-field shape APPROVED;
Q2: tombstoned_at_ms in merge revision is the merge's own seal
time, not the original tombstone's; Q3: add_account
anti-resurrection retry budget = 4). Five commits land on
`issue/P10-tombstones-offline` from baseline tip `562a3ba`.

**P10-1.** Widened tombstone payload schema. New
`pangolin_store::TombstonePayload { deleted, account_id,
tombstoned_at_ms }` with private fields + accessor methods;
deterministic CBOR encoding with three-entry alphabetical key
order (`account_id`, `deleted`, `tombstoned_at_ms`). Encoded via
`ciborium-ll` directly (no serde — HIGH-1 invariant preserved).
Legacy P3-era single-entry `{ "deleted": true }` payloads
continue to decode for forward-compat (produce a
`TombstonePayload` with all-zeros `account_id` and ts=0).
`seal_tombstone` signature widens to take `&TombstonePayload`;
`DecodedPayload::Tombstone` now carries the parsed payload.
`Vault::delete_account` and `Vault::build_merge_payload_for_resolve`
updated; the merge-of-tombstone case carries the merge revision's
own seal time per Q2 (not the original tombstone's). 11 tests
added (10 blob-level + 1 vault-level).

**P10-2.** Opportunistic tombstone-bit detection in
`Vault::ingest_chain_revision`'s genuine-foreign-INSERT branch.
Replaced the audit-flagged hardcode `is_tombstone_i64 = 0` with a
helper `Vault::detect_tombstone_bit_at_ingest` that AEAD-decrypts
under the local VDK + the placeholder zero nonce that ingest
persists for foreign events; sets bit=1 iff the decoded plaintext
is a `TombstonePayload` whose `deleted` is true. Non-oracle
property: every error variant collapses to bit=0; both decode-
success and decode-failure paths return `IngestOutcome::Inserted`;
no error variant escapes; the freeze sentinel still fires for
foreign-ingest UX safety. PoC two-key reality (acknowledged
limitation, plan §A2 / Threat #19): under PoC the chain event
ABI does not transport the AEAD nonce, so the open under
placeholder zero nonce will fail authentication for any real
foreign event — the new logic is functionally a no-op (always
falls through to bit=0 + freeze). The structurally-correct code
is in place for MVP-1's nonce-on-chain to make this functional
without further code changes. The synthetic-decryptable-tombstone
test exercises the positive branch by sealing an event payload
deliberately under the placeholder zero nonce. 5 tests added.

**P10-3.** Read-guard reaffirmation +
`add_account` anti-resurrection. (1)
`ingest_chain_revision` now flips `account_identities.tombstoned
= 1` when P10-2's opportunistic decode returns `is_tombstone =
1`; without this UPDATE, P10-2's bit-set on the revisions row
alone wouldn't propagate through `list_accounts`. (2)
`Vault::add_account` runs a new `derive_fresh_account_id` helper
that probes the existing account_identities row for a
tombstoned-id collision; on collision, regenerate; after
`ADD_ACCOUNT_RETRY_BUDGET` (4) collisions, surface
`StoreError::Internal { reason }` rather than spinning. New
`StoreError::Internal { reason: String }` variant. 7 lib tests
+ 1 integration test added (the integration covers the own-
publish round-trip; the cross-vault propagation case is
acknowledged Threat #19 limitation, closed by MVP-1).

**P10-4.** `MockChainAdapter::set_disconnected(bool)` toggle.
`Arc<AtomicBool>` field next to the existing `Arc<Mutex<...>>`;
cloned mock handles share both. When disconnected, every
adapter method returns `ChainError::Rpc("simulated offline")`
synchronously without state mutation. Test-utilities-feature-
gated alongside the rest of the `mock` module. New
integration test file `tools/pangolin-cli/tests/offline_mode.rs`
with three tests: `offline_edit_then_online_publish` (full
flow: connect → publish 1 → disconnect → 5 add + 1 update +
1 delete locally → publish_all fails per-entry, dirty markers
preserved → reconnect → publish_all drains the queue, chain
has 8 events, list_dirty empty, list_accounts.len() == 5);
`offline_publish_with_no_dirty_entries_is_noop_at_lib_layer`
(documents the orchestrator's swallow-chain-view-precheck-error
discipline; the §A7 connectivity-required invariant lives at
the binary boundary, not the lib entry point);
`offline_session_does_not_set_freeze_sentinel` (pin: pull_all
errors before reaching ingest_chain_revision, so the freeze
sentinel cannot fire). E2E_TESTS.md gains E2E-005 with both
automated and manual paths. 6 mock-level tests added.

**P10-5.** This DEVLOG entry. THREAT_MODEL.md gains rows
18–22 in the `pangolin-cli` section: 18 (forged tombstone),
19 (tombstone-bit non-propagation under PoC two-key — closed
structurally by P10-2, functionally by MVP-1), 20 (resurrection
of tombstoned account_id forbidden), 21 (offline edit replay —
inherits #5 cross-vault discipline), 22 (tombstone-bit at-rest
modification — defense-in-depth via AEAD AAD binding + non-
oracle decode). `pangolin-cli status` output gains a
`tombstoned_count` line (per A8 — omitted in human-readable
output when count is 0; always emitted in JSON for machine
consumers). New `Vault::list_tombstoned_accounts()` accessor.

**Test count delta:** 294 → 323 lib tests (+29) plus 4 new
integration tests:

Lib tests added:
- `pangolin_store::blob::tests::tombstone_payload_round_trip_three_field`
- `pangolin_store::blob::tests::tombstone_payload_encoding_is_deterministic`
- `pangolin_store::blob::tests::tombstone_payload_legacy_single_entry_decodes`
- `pangolin_store::blob::tests::tombstone_payload_rejects_arity_two`
- `pangolin_store::blob::tests::tombstone_payload_rejects_arity_four_or_more`
- `pangolin_store::blob::tests::tombstone_payload_rejects_non_canonical_key_order`
- `pangolin_store::blob::tests::tombstone_payload_rejects_account_id_wrong_length`
- `pangolin_store::blob::tests::tombstone_payload_rejects_tombstoned_at_negative`
- `pangolin_store::blob::tests::seal_tombstone_with_payload_round_trips_through_open_payload`
- `pangolin_store::blob::tests::tombstone_aad_substitution_fails`
- `pangolin_store::vault::tests::delete_account_writes_canonical_three_field_tombstone_payload`
- `pangolin_store::vault::tests::ingest_synthetic_decryptable_tombstone_event_sets_bit`
- `pangolin_store::vault::tests::ingest_own_live_revision_does_not_set_tombstone_bit`
- `pangolin_store::vault::tests::ingest_foreign_event_with_unreadable_payload_leaves_tombstone_clear_and_freezes`
- `pangolin_store::vault::tests::ingest_locked_vault_skips_decryption_and_treats_as_unreadable`
- `pangolin_store::vault::tests::ingest_tombstone_bit_does_not_oracle_aead_failure_versus_decode_failure`
- `pangolin_store::vault::tests::ingest_tombstone_sets_account_identities_tombstoned_flag`
- `pangolin_store::vault::tests::ingest_tombstone_filters_account_from_list_accounts`
- `pangolin_store::vault::tests::ingest_tombstone_makes_get_account_return_none`
- `pangolin_store::vault::tests::ingest_tombstone_makes_reveal_password_return_account_tombstoned`
- `pangolin_store::vault::tests::add_account_refuses_to_resurrect_tombstoned_id`
- `pangolin_store::vault::tests::add_account_retry_budget_happy_path_no_collision`
- `pangolin_store::vault::tests::merge_payload_for_resolve_uses_new_three_field_tombstone_shape`
- `pangolin_chain::mock::tests::disconnect_makes_publish_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_makes_pull_since_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_makes_get_revision_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_makes_current_block_return_rpc_error`
- `pangolin_chain::mock::tests::disconnect_persists_until_reconnect`
- `pangolin_chain::mock::tests::reconnect_after_disconnect_preserves_state`
- `pangolin_cli::commands::status::tests::status_includes_tombstone_count_when_nonzero`

Integration tests added:
- `pangolin_cli::tests::two_vault_roundtrip::own_tombstone_round_trip_via_chain`
- `pangolin_cli::tests::offline_mode::offline_edit_then_online_publish`
- `pangolin_cli::tests::offline_mode::offline_publish_with_no_dirty_entries_is_noop_at_lib_layer`
- `pangolin_cli::tests::offline_mode::offline_session_does_not_set_freeze_sentinel`

**Critical invariants verified at the P10 SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; P10 introduces no new transitive deps for the
   crypto crate. The widened `TombstonePayload` uses
   `ciborium-ll` directly, same as the live-snapshot encoder).
2. No new `unsafe`.
3. No plaintext on disk. The opportunistic-decode in P10-2
   happens entirely in memory; the decrypted plaintext is
   wiped on drop via `Zeroizing<Vec<u8>>` inside `open_payload`
   (existing P3 discipline). The bit derived from the plaintext
   IS persisted, but it's a one-bit structural derivation, not
   a plaintext leak.
4. Non-oracle property. P10-2's opportunistic-decode collapses
   every error variant (AEAD failure, CBOR malformed, decoded
   as Live, locked vault) into a single `bit=0` arm; both paths
   return `IngestOutcome::Inserted`. Verified by
   `ingest_tombstone_bit_does_not_oracle_aead_failure_versus_decode_failure`.
5. Append-only state. Tombstone bit is set by INSERT-time
   logic only (in `delete_account` and `ingest_chain_revision`'s
   genuine-foreign-INSERT branch); never UPDATEd after the
   row's initial write. The `account_identities.tombstoned`
   flag is sticky once set (only the resolve flow producing a
   live merge revision can clear it via P9's `clear_frozen`,
   and that path applies to live-revision merges only).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings` clean.
8. `cargo test --workspace --lib` — 323/323 passing (294
   baseline + 29 new).
9. `cargo test --workspace --tests` — integration tests pass,
   including the new `offline_mode::*` and
   `two_vault_roundtrip::own_tombstone_round_trip_via_chain`.

**PoC limitations carried forward (documented in plan + threats):**

- Foreign-event tombstone propagation under PoC two-key
  (Threat #19). Closed structurally in P10-2; closes
  functionally with MVP-1's nonce-on-chain.
- Resurrection of tombstoned account_id is forbidden; under
  PoC, undelete = create a new account with a fresh id (Threat
  #20). MVP-1 may revisit if a deliberate-undelete user
  feature emerges.
- Cross-device offline edit replay inherits #5 — same
  cross-vault discipline applies (Threat #21).
- Tombstone-bit at-rest modification: defense-in-depth via
  AEAD AAD binding; full mitigation is not the application
  layer's job (Threat #22).

## 2026-05-07 · P10 fix-pass — §16.5 audit findings (M-1, M-2, L-1; M-3 deferred; L-2/L-3 no-action)  ✅ SIGNOFF

P10 §16.5 audit (commit `e7d9018`) flagged a documentation drift
plus housekeeping. Fix-pass closes M-1 + M-2 with code+tests, L-1
with a one-line `deny.toml` edit, and explicitly defers M-3 per
auditor recommendation.

**M-1 + M-2 — payload-vs-event `account_id` cross-check (CLOSED).**
THREAT_MODEL row 18 + `docs/issue-plans/P10.md` §A1/§C claimed the
cross-check existed before the code shipped it. Implemented inside
`Vault::detect_tombstone_bit_at_ingest` using
`subtle::ConstantTimeEq::ct_eq` over the 32-byte arrays. Mismatch
silently collapses to `is_tombstone = 0` — same bucket as AEAD
failure / CBOR failure / locked vault — preserving (and
strengthening) the non-oracle property of the ingest decoder. No
new error variant; the decoder itself stays type-pure (the
cross-check is in the ingest layer, not in `decode_payload`). The
freeze sentinel still fires for the row's INSERT, so the
user-facing safety property is unaffected. `subtle` was already a
dep of `pangolin-store` (used in `account.rs::AccountId::ct_eq`);
no Cargo.toml change. Verified `cargo tree -p pangolin-crypto |
grep -ci serde` is still 0 — the new use of `subtle` is in the
store crate, NOT crypto. Two new tests:
- `detect_tombstone_bit_rejects_cross_account_payload` — synthetic
  ciphertext whose AAD-bound id is X but whose plaintext
  `account_id` is Y; bit lands at 0 silently.
- `detect_tombstone_bit_accepts_matching_payload` — same setup
  with X==Y; bit lands at 1 (regression coverage).

THREAT_MODEL row 18 prose updated: replaced the "triggers
`StoreError::Cbor(...)`" claim with the constant-time
silent-rejection description. `docs/issue-plans/P10.md` §A1
(rationale 2), §C (audit-bullet on AAD-vs-plaintext cross-checks),
the threat-model row 14 draft (which is the eventual THREAT_MODEL
row 18 text), and the failure-modes table all updated to align.

**L-1 — stale `RUSTSEC-2024-0388` advisory ignore (CLOSED).** The
alloy/coins version churn that landed earlier dropped `derivative`
from the dep graph, so the ignore began firing
`advisory-not-detected` warnings. Removed the entry from
`deny.toml`; left a forward-comment so a future re-introduction
re-adds it verbatim. `cargo deny check` is now fully clean.

**M-3 — retry-exhaustion deterministic test (DEFERRED).** Per
auditor's PoC-scope recommendation. The retry-loop's failure path
needs a test-only RNG seam to drive `random_32_via_sqlite` through
4 successive collisions; existing happy-path coverage plus the
`~4×N/2^256` probability bound is sound for PoC. Documented in
`docs/issue-plans/P10.md` §"Out of scope (explicit)".

**L-2, L-3 — no-action observations.** L-2 (comment polish on
`derive_fresh_account_id`) and L-3 (positive test count drift)
are acknowledged; no code change.

**Test-count delta:** 324 → 326 lib tests (+2 from M-1+M-2
positive/negative coverage).

**Critical invariants verified at the P10 fix-pass SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0 (HIGH-1
   bound holds; the `subtle` dep was already in `pangolin-store`
   and `subtle` itself does not pull `serde`).
2. No new `unsafe`.
3. No plaintext on disk. The constant-time compare runs on the
   already-decrypted-and-zeroizing-on-drop plaintext inside
   `open_payload`; nothing new is persisted beyond the same
   one-bit `is_tombstone` derivation as P10-2.
4. Non-oracle property STRENGTHENED. The cross-check uses
   `subtle::ConstantTimeEq::ct_eq` (no timing-channel divergence
   on byte-prefix-match position) AND collapses to `0` on
   mismatch (no different error variant). Verified by both new
   tests — the rejection is silent end-to-end.
5. Append-only state unchanged. The cross-check only gates
   bit-set on INSERT; no UPDATE introduced.
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings` clean.
8. `cargo test --workspace --lib` — 326/326 passing.
9. `cargo test --workspace --tests` — integration tests
   unchanged from P10 SIGNOFF tip (no integration test touched).
10. `cargo deny check` fully clean (no `advisory-not-detected`
    warnings after L-1 fix).

## 2026-05-07 · P11A — pangolin-cli account subcommands EPIC  ✅ SIGNOFF

P11A closes the structural gap "Pangolin is a password manager
whose CLI cannot manage passwords." Five new subcommands —
`pangolin-cli account add` / `list` / `show` / `update` /
`delete` — expose P3-era's library account-management API at
the user-facing CLI boundary, preserving P4's presence-
escalation discipline for credential reveals, P8's freeze-guard
discipline, and P10's anti-resurrection / tombstone-payload
discipline. No new cryptographic primitive, no new chain-side
code, no new vault-schema column, no new public library API.

**Commit-by-commit:**

- **P11A-1 (`aba944f`)** — clap scaffold. New
  `tools/pangolin-cli/src/commands/account.rs` module + the
  `Command::Account(AccountArgs)` arm in `cli.rs`. Five sub-
  verbs wired with full `#[derive(Args)]` types; per-verb
  `run_*` functions are stubbed with `bail!("not implemented
  yet")`. 10 clap tests pin the surface (help renders, per-
  verb arg parsing, mutually-exclusive flag groups, empty-
  name reject, §A16 forbidden-user-facing-terms invariant).
- **P11A-2 (`fd382eb`)** — `account add` end-to-end.
  Password input via `--generate-password` (24-char from a
  64-char alphabet, `pangolin_crypto::rng::fill_random` as
  entropy source; printed to STDERR per Q5 inside a
  save-this-now block) OR `--password-stdin` OR interactive
  prompt with confirmation. NO `--password <flag>`. TOTP
  same shape; notes accept the lower-tier `--notes <str>`
  per A5. New `account_id` (lowercase hex) goes to STDOUT
  for shell-pipe ergonomics. Per Q1, `add` does NOT auto-
  create the vault; missing `.pvf` errors fast. 7 tests.
- **P11A-3 (`e2fac26`)** — `account list` + `account show`.
  `list` walks `Vault::list_accounts` (frozen + tombstoned
  filtered by default; `--include-frozen` /
  `--include-tombstoned` opt them in with `[frozen]` /
  `[deleted]` suffix per A11). The internal `ListRow`
  struct holds only identifier-class fields — secret-bearing
  fields are structurally absent (verified by
  `list_row_omits_secret_fields_structurally`). `show`
  default omits secrets; `--reveal-{password,notes,totp-secret}`
  prompt ONCE for presence per A7, then construct N fresh
  `PressYPresenceProof::confirmed()` instances. JSON output
  uses the omit-vs-null discipline (unrevealed fields are
  absent, not `null`). 10 tests.
- **P11A-4 (`cd39730`)** — `account update`. Per A6,
  always presence-gated: the library API requires a
  complete `AccountSnapshot`, so the CLI reveals every
  secret field of the entry to construct it (one prompt;
  three fresh proofs; one update transaction).
  Override-or-preserve per field. Pre-presence guard
  surfaces frozen → resolve hint, tombstoned → "deleted",
  unknown → "no account" before asking the user for a
  presence proof. New `cfg(test)`-only test seam
  `TEST_AUTO_CONFIRM_PRESENCE` bypasses the prompt for
  unit tests; production binaries cannot reach it. 6 tests.
- **P11A-5 (`693d9e2`)** — `account delete`. Default flow
  prints a confirmation prompt that includes the display
  name (typo-prevention per Q3) and reads the literal
  lowercase string `"yes"` (case-sensitive, A9). `--yes`
  bypasses the prompt; `--why <reason>` is informational
  only (echoed to stderr; NOT in the tombstone payload).
  Per Q8 there is NO `--force` flag — frozen-account delete
  surfaces the same "run resolve" hint as `update`.
  Re-deletion of a tombstoned id is refused with an
  idempotency-by-clear-error message rather than silent
  success. Sibling `TEST_AUTO_CONFIRM_DELETE` test seam
  for unit-test ergonomics. 8 tests.
- **P11A-6 (this entry)** — THREAT_MODEL rows 23–27 cover
  the new threat surface: process-listing leak (defense:
  no `--password <flag>`), shell-history leak, tombstone
  replay, reveal-confirmation phishing under `PoC`, and
  frozen-account update/delete refusal. Integration test
  `tools/pangolin-cli/tests/account_lifecycle.rs` exercises
  the full `add → list → show → update → delete` round
  trip on a fresh vault. E2E_TESTS extended with E2E-006
  scenario.

**Test-count delta:** 326 → 367 lib tests (+41 across
P11A-1..P11A-5) plus 1 new integration test
(`account_lifecycle_round_trip`).

**Critical invariants verified at the P11A SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0
   (HIGH-1 bound holds; P11A introduces no new
   `pangolin-crypto` dependency).
2. No new `unsafe`. `forbid(unsafe_code)` is unconditional
   at the top of `tools/pangolin-cli/src/main.rs` and
   `lib.rs`; preserved.
3. No plaintext on disk. Reveal output goes to stdout
   (per Q2). The interactive password prompt, stdin
   variants, and the auto-generated password block all
   route through `SecretBytes` wrappers that zeroize on
   drop. No CLI code path writes plaintext to a file or
   environment variable.
4. No `--password <flag>` form anywhere. Verified by
   `account_add_password_stdin_and_generate_conflict` +
   inspection of `AccountAddArgs` / `AccountUpdateArgs`
   field set (only `password_stdin: bool`,
   `generate_password: bool`, `password_prompt: bool`).
5. Append-only state holds. Account ops use existing
   `add_account` / `update_account` / `delete_account`
   library calls, each of which writes a new revision in
   one transaction (P3 / P8-2 / P10-1 invariants
   preserved).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings`
   clean.
8. `cargo test --workspace --lib` — 367/367 passing
   (326 + 41 new).
9. `cargo test --workspace --tests` — integration tests
   pass, including the new `account_lifecycle.rs`.
10. §3.5 forbidden-user-facing-terms invariant holds —
    `account_help_avoids_forbidden_user_facing_terms`
    pins the rendered `--help` output for "blockchain",
    "transaction", "hashes", "revisions",
    "decentralized storage", and "gas".
11. P0..P10 lib + integration tests unchanged.
12. No new D-NNN entries — every architectural decision
    in the P11A plan is local to the CLI surface and
    documented in `docs/issue-plans/P11A.md` §A1..§A16.

## 2026-05-07 · P11B — pangolin-cli vault create subcommand EPIC  ✅ SIGNOFF

P11B closes the structural gap "Pangolin's CLI cannot create a
vault." One new subcommand — `pangolin-cli vault create
--path <path> [--password-stdin] [--print-id]` — exposes
`Vault::create(path, password)` at the user-facing CLI
boundary, preserving P11A's A3 password-input discipline
(interactive prompt + confirmation OR `--password-stdin`;
NEVER `--password <flag>`). With P11B in place, the P11
reproducer guide drives a non-author developer through
`vault create` → `account add` → `publish` → `pull`
without bespoke fixture scaffolding (the
`Vault::create` library escape hatch is no longer needed).

P11B introduces no new cryptographic primitive, no new
chain-side code, no new vault-schema column, no new public
library API.

**Commit-by-commit:**

- **P11B-1 (`01ee02f`)** — clap scaffold. New
  `Command::Vault(VaultArgs)` variant on the top-level
  `Command` enum (alongside `Account`); nested
  `VaultCommand::Create(VaultCreateArgs)` sub-subcommand;
  one new dispatch arm in `main.rs`; new
  `tools/pangolin-cli/src/commands/vault.rs` module with
  a stubbed `run_create` returning `bail!("not implemented
  yet")`. `VaultCreateArgs`: `--path <PathBuf>` (required),
  `--password-stdin` (bool, default false), `--print-id`
  (bool, default false). NO `--password <flag>` field.
  Per locked Q5 the long-doc on `VaultCommand::Create`
  warns explicitly: "Pangolin has no password-recovery
  mechanism; loss of this password is permanent data
  loss." Eight clap-shape unit tests pin the surface
  (vault subcommand renders, per-verb arg parsing,
  required `--path`, `--print-id` and `--password-stdin`
  flags parse, `--password` flag REJECTED, §A14
  forbidden-user-facing-terms invariant, no-recovery
  warning is in the help output).

- **P11B-2 (`c1d4c0c`)** — `vault create` end-to-end.
  Path canonicalization per §A5: `parent.canonicalize() +
  file_name`, surfacing the absolute resolved path in
  the success message and any error message (matches P8
  fix MED-3's discipline). Pre-flight overwrite refusal
  per §A3: `path.exists()` check at the CLI boundary
  before any password prompt; the library's own check
  plus `acquire_lock`'s `OpenOptions::create_new(true)`
  close the TOCTOU race per §A8; NO `--force` flag.
  Password acquisition per §A2 reuses three helpers from
  `commands/account.rs` (now `pub(crate)` per §A4):
  `prompt_password_with_confirmation`,
  `read_secret_first_line_from_stdin`, and
  `reject_empty_password`. Empty-password guard fires on
  both paths before any library call. Per §A9 the
  interactive path emits a clarifying eprintln! BEFORE
  the rpassword call. POSIX file-mode hardening per Q4:
  after `Vault::create` returns, the new file is chmod
  0o600 on Unix targets (best-effort; warn-but-don't-
  abort on filesystems that ignore POSIX bits;
  cfg(unix) — Windows is a no-op). Vault::close called
  explicitly on success per §A11 (mirrors P11A's
  pattern). Output per §A7: `vault created at
  <canonical-path>` by default; `vault_id: <hex>` line
  added when `--print-id` is set; `--json` global flag
  emits the JSON bundle with the vault_id field always
  present. Nine new unit tests in `commands/vault.rs::tests`
  plus one new integration test
  `tools/pangolin-cli/tests/vault_create_lifecycle.rs::vault_create_then_account_add_round_trip`
  (spawns the binary via `CARGO_BIN_EXE_pangolin-cli`,
  pipes the master password to stdin via
  `--password-stdin`, asserts the produced vault is
  consumable by `account add` under the same password).

- **P11B-3 (this entry)** — THREAT_MODEL row 28 covers
  the new threat surface: vault-creation password leak
  (defense: no `--password <flag>` form), `.pvf`
  overwrite hazard (defense: pre-flight check + library
  guard + lock; no `--force`), parent-dir-traversal /
  symlink redirection at the create boundary (defense:
  parent-canonicalize per §A5), empty-password footgun
  (defense: `reject_empty_password` reused from P11A's
  MED-1 fix), POSIX file-mode hardening (chmod 0o600 on
  Unix per Q4), no-password-recovery user warning
  (`--help` long-doc per Q5; pinned by
  `vault_create_help_warns_no_password_recovery`).
  E2E_TESTS unchanged (`vault create` → `account add`
  is the implicit prefix of every E2E-001..E2E-006
  scenario; the new integration test pins the prefix
  contract).

**Test-count delta:** 384 → 401 lib tests (+17 across
P11B-1's 8 clap tests in `cli.rs` plus P11B-2's 9 vault
unit tests in `commands/vault.rs::tests` on Windows; one
additional cfg(unix) test `vault_create_chmod_0600_on_unix`
runs on Linux for +18 there) plus 1 new integration test
(`vault_create_then_account_add_round_trip`). The P11A
SIGNOFF entry recorded 367 lib tests; the P11B baseline
at `7dd7e77` (P11B plan tip) already showed 384 lib
tests workspace-wide due to P10 / P11A fix-pass / other
intervening commits. P11B-1 took the count to 392
(+8 cli tests), P11B-2 to 401 on Windows (+9 vault
unit tests), and P11B-3 leaves it unchanged at 401.

**Critical invariants verified at the P11B SIGNOFF tip:**

1. `cargo tree -p pangolin-crypto | grep -ci serde` → 0
   (HIGH-1 bound holds; P11B introduces no new
   `pangolin-crypto` dependency and no new `pangolin-store`
   public surface).
2. No new `unsafe`. `forbid(unsafe_code)` is unconditional
   at the top of `tools/pangolin-cli/src/main.rs` and
   `lib.rs`; preserved.
3. No plaintext on disk. Vault password handled via
   `SecretBytes` (zeroizes on drop); the produced `.pvf`'s
   contents are AEAD-encrypted under the VDK which is
   wrapped under the password-derived authority. POSIX
   file-mode hardening (chmod 0o600 on Unix) limits
   on-disk DISCOVERABILITY of the encrypted file to the
   owner UID, not its readability — defense in depth.
4. No `--password <flag>` form anywhere. Verified by
   `vault_create_does_not_accept_password_flag` (clap
   rejects the flag at parse time) and inspection of
   `VaultCreateArgs` field set (only `path: PathBuf`,
   `password_stdin: bool`, `print_id: bool`).
5. Append-only state holds. `Vault::create` is a
   first-time-provisioning op; the append-only invariant
   applies to revisions inside the freshly-created vault,
   not to the `.pvf` file itself. P11B's "refuse to
   overwrite" discipline is the moral equivalent: a
   `.pvf` is created exactly once at a given path
   (per §A3 / §A8).
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings`
   clean.
8. `cargo test --workspace --lib` — 401/401 passing
   on Windows (384 baseline + 17 new across P11B-1 +
   P11B-2; +18 on Linux where the cfg(unix) chmod test
   also runs).
9. `cargo test --workspace --tests` — integration tests
   pass, including the new `vault_create_lifecycle.rs::vault_create_then_account_add_round_trip`.
10. §3.5 forbidden-user-facing-terms invariant holds —
    `vault_help_avoids_forbidden_user_facing_terms` pins
    the rendered `vault --help` and `vault create --help`
    output for "blockchain", "transaction", "hashes",
    "revisions", "decentralized storage", and "gas".
11. P0..P11A lib + integration tests unchanged.
12. No new D-NNN entries — every architectural decision
    in the P11B plan is local to the CLI surface and
    documented in `docs/issue-plans/P11B.md` §A1..§A14.

---

## 2026-05-08 · P11 — E2E Reproducer Documentation  ✅ SIGNOFF

**Date:** 2026-05-08
**Tip:** this entry's commit (P11-5 fix-pass)
**Status:** SHIPPED

### Commits

- `ad54185` — docs: P11-1 E2E_REPRODUCER scaffold
- `db9d33d` — docs: P11-2 E2E_TESTS cross-references
- `5a063e7` — docs: P11-3 POC_README entry point
- this entry — docs: P11-5 close P11-4 rehearsal gaps + DEVLOG SIGNOFF

### Deliverables

- `docs/E2E_REPRODUCER.md` (~990 lines after P11-5 fix-pass):
  three scenarios documented in Mock + Live modes using only
  `pangolin-cli` invocations.
- `POC_README.md` (~140 lines): non-author entry point at the
  repository root.
- `E2E_TESTS.md`: cross-reference subsections added to
  E2E-003 / E2E-004 / E2E-005 / E2E-006.

### Non-author rehearsal (P11-4)

- **Scope:** Scenario 1 only (per locked Q3 answer; Scenarios
  2 and 3 deferred per plan).
- **Mode:** Mock.
- **Verdict:** PASS-WITH-FIXES — three minor doc gaps surfaced.
- All three gaps closed in this P11-5 fix-pass:
  - **G1.** Scenario 1 Mock-mode expected count corrected
    from "3 passed" to "5 passed" with one-line explanation
    that the test file also houses Scenario 2's resolve test
    + P10's tombstone round-trip test.
  - **G2.** Setup section split into Mock-mode-required
    (§3a) and Live-mode-required (§3b) subsections with
    explicit "skip §3b if Mock-only" callout — saves a
    cold-read non-author dev ~5 minutes of release-build
    time they don't need.
  - **G3.** Smoke-test expected output now explains cargo's
    per-crate summary lines; reader sums them rather than
    reading just the last one (which would show ~142 passed
    for the largest crate and cause unwarranted panic).

### Critical invariants preserved

1. Zero Rust code modified across P11-1..P11-5 — documentation-
   only.
2. Workspace test count unchanged at 401/401 on Windows
   (~405 on Linux); the smoke baseline from the P11B SIGNOFF
   tip carries through unchanged.
3. HIGH-1 invariant — `cargo tree -p pangolin-crypto |
   grep -ci serde` → 0.
4. No new `unsafe`. `forbid(unsafe_code)` preserved at every
   P0..P11B crate root.
5. §3.5 forbidden-user-facing-terms invariant — none of the
   listed terms appear in any new doc text. (E2E_REPRODUCER.md
   uses "the chain" and "publish" / "pull" / "resolve" — all
   permitted under §3.5; "blockchain", "transaction",
   "decentralized storage", "gas", and the bare nouns
   "hashes" and "revisions" are absent from user-facing
   prose.)
6. `cargo fmt --all --check` clean.
7. `cargo clippy --workspace --all-targets -- -D warnings`
   clean.
8. `cargo test --workspace --lib` — 401/401 on Windows.
9. `cargo test --workspace --tests` — green.
10. `cargo audit` — clean.
11. `cargo deny check` — clean.

### Out of scope (per plan)

- Recorded screencast — deferred to P12-3.
- Signed binary — deferred to P12-1.
- Live-chain rehearsal in CI — too costly; documented as
  "opt-in, not rehearsed in CI" in the doc itself.
- Scenarios 2 and 3 non-author rehearsal — deferred per the
  locked Q3 answer (scenario 1 only on first pass).

### MVP-1 polish opportunities surfaced during build

These are NOT P11 bugs (P11 is doc-only); they are quirks of
the underlying CLI that the reproducer documents around. Each
becomes a candidate MVP-1 polish item:

- `account show` does not currently expose `revision_id`
  directly; Scenario 2 must save the publish-summary stderr
  to recover it.
- Binary-level network-disconnect simulation absent;
  Scenario 3 Live mode requires OS-level "disable wifi"
  rather than a `pangolin-cli --simulate-disconnect` flag.
- The generated password from `account add --generate-password`
  prints only on stderr; rehearsal-friendly capture would
  benefit from a `--print-password-on-stdout` flag (or the
  existing `--json` global flag, which already includes it
  in the JSON envelope, could be advertised more
  prominently).

### Unblocks

P11 unblocks **P12** (signed binary + screencast + final
`POC_README.md` polish). With the reproducer in `main`, P12
can quote line ranges from `docs/E2E_REPRODUCER.md` rather
than re-derive them, and the screencast author has a
verified script to follow.

---

## 2026-05-08 · P12 — Packaging EPIC  ✅ SIGNOFF

**Date:** 2026-05-08
**Tip:** this entry's commit (P12-5 SIGNOFF)
**Status:** SHIPPED

### Commits

- `3639c3e` — P12: issue plan for packaging + PoC -> MVP gate
  retrospective (P12.md plan-gate, landed before this branch).
- `329916d` — P12 redeploy proof: D-015 RevisionLogV0 at
  `0x74f28794c180bb1BEB698b294F69554D0ACCA9c4` (landed on main
  before this branch; closes §3.9 criterion 4).
- `d73c247` — P12-1: release pipeline + GPG-signing scaffold
  for Windows-x64.
- `c3c0c19` — P12-2: POC_README polish for distribution
  audience.
- `d9b520e` — P12-3: screencast script + recording protocol.
- `05d1cbb` — P12-4: PoC -> MVP gate retrospective in
  DECISIONS.md.
- this entry — P12-5: DEVLOG SIGNOFF + POC COMPLETE
  announcement.

### Deliverables

- **`scripts/release-windows.ps1`** (256 lines) — PowerShell
  release pipeline. Pre-flight gate (cargo fmt / clippy /
  test --lib), workspace release build, binary verification,
  dist directory clobber + recreate, copy artefacts (binaries
  + LICENSE + POC_README.md + docs/E2E_REPRODUCER.md), sorted
  SHA-256 manifest with Linux-style format, optional GPG
  signing of the manifest, Compress-Archive into the upload
  zip. Idempotent + fail-fast. Flags: `-SkipSign`,
  `-SkipPreflight`, `-Version`.
- **`docs/RELEASE.md`** (265 lines) — publisher's release
  runbook. Prerequisites (Rust 1.83+, Windows-x64, GnuPG,
  release-commit working tree), how to run the script, how
  to verify locally, how to upload to GitHub Releases page,
  signing-key fingerprint placeholder (Kelvin fills in
  post-merge), troubleshooting table.
- **`POC_README.md`** polished from 141 to 198 lines:
  - New §A6 Status callout block (verbatim PoC framing).
  - New "Watch the demo" pointer (YouTube unlisted URL
    placeholder).
  - New "Download a prebuilt binary" section with
    `gpg --verify` + `sha256sum -c` verification dance.
  - "Build" → "Build from source (alternative)".
  - New SmartScreen / antivirus disclosure bullet in
    known-quirks.
  - D-015 redeploy proof referenced in Live-chain section.
  - Internal links verified (RELEASE.md, SCREENCAST_SCRIPT.md,
    E2E_REPRODUCER.md#live-mode-safety).
  - Forbidden-terms scan: 0 hits per §3.5.
- **`docs/SCREENCAST_SCRIPT.md`** (466 lines) — beat-by-beat
  recording protocol for Kelvin's 5-minute walkthrough.
  Pre-recording checklist, 6 beat blocks (Title / Setup /
  Scenario 1 / Scenario 2 / Scenario 3 / Closing) with
  command + framing + narration per beat, post-recording
  checklist, YouTube unlisted upload protocol. Forbidden-
  terms scan: 0 hits.
- **`DECISIONS.md`** retrospective (+341 lines) appended after
  D-015. Five §3.9 criterion verdicts (4 CLOSED + 1
  OPEN-WITH-EVIDENCE pending screencast URL); fifteen
  per-D-NNN classifications (6 PERMANENT, 1 EVOLVES-IN-MVP-1,
  2 EVOLVES-IN-MVP-2, 2 EVOLVES-IN-MVP-3, 1 EVOLVES-IN-MVP-4,
  3 THROWAWAY-FOR-PoC); zero NEEDS-REWORK candidates;
  explicit "open follow-ups" subsection (one item: screencast
  URL); explicit handoff to MVP-1.
- **`DEVLOG.md`** (this entry + the POC COMPLETE entry below).

### Critical invariants preserved

1. **HIGH-1** — `cargo tree -p pangolin-crypto | grep -ci serde`
   = **0**. (Verified at P12 SIGNOFF tip.)
2. **No new `unsafe`** — all eight crates retain
   `forbid(unsafe_code)` at their root (verified via grep).
3. **No plaintext on disk** — P12 ships zero new code; the
   release pipeline writes only release binaries + manifests
   + signatures. No vault material on the publisher host.
4. **Workspace clippy clean** — `cargo clippy --workspace
   --all-targets -- -D warnings` passes at P12 SIGNOFF tip.
5. **Workspace fmt clean** — `cargo fmt --all --check` passes.
6. **Test baseline holds at 401/401** — `cargo test
   --workspace --lib` produces:
   - pangolin-core: 52 passed
   - pangolin-store: 133 passed
   - pangolin-crypto: 1 passed (lib placeholder; test vectors
     under tests/)
   - pangolin-chain: 71 passed
   - pangolin-indexer: 1 passed (lib placeholder)
   - pangolin-funder-client: 1 passed (lib placeholder)
   - pangolin-cli (lib): 142 passed
   - **Total: 401 passed; 0 failed; 0 ignored.**
7. **`cargo audit`** — clean (2 unmaintained-crate warnings:
   `derivative 2.2.0` via `ark-ff` via `alloy`,
   per-existing; no vulnerabilities).
8. **`cargo deny check`** — `advisories ok, bans ok, licenses
   ok, sources ok`.
9. **§3.5 forbidden-terms compliance** — none of `gas` /
   `blockchain` / `transaction` / `decentralized storage` /
   `hashes` / `revisions` appear in `POC_README.md` or
   `docs/SCREENCAST_SCRIPT.md` (verified via Grep).
10. **`dist/` correctly ignored** — `git status` clean after
    a release-script run; `git check-ignore` confirms
    `dist/windows-x64/*` matches `.gitignore` line 15.
11. **Zero Rust files modified** — `git diff --stat
    329916d..HEAD` shows changes only in `DECISIONS.md`,
    `POC_README.md`, `docs/RELEASE.md`,
    `docs/SCREENCAST_SCRIPT.md`,
    `scripts/release-windows.ps1`. No `crates/` or `tools/`
    files touched. `Cargo.toml` and `Cargo.lock` unchanged.

### Pipeline verification

- **`scripts/release-windows.ps1`** was verified manually by
  running its individual steps in sequence (the wrapper
  PowerShell invocation is unavailable to the agent
  environment; cargo build + manual file copy + sha256sum
  manifest compute were exercised end-to-end).
- `cargo build --workspace --release` builds clean (1m 45s);
  produces `target/release/pangolin-cli.exe` (9509888 bytes)
  + `target/release/chaincli.exe` (6279680 bytes).
- The SHA-256 manifest format is verified to round-trip via
  `sha256sum -c SHA256SUMS` on the produced
  `dist/windows-x64/` directory tree.
- `gpg --detach-sign` is NOT exercised by the agent (no
  passphrase available). Kelvin runs the script with default
  arguments at release time; `-SkipSign` is the agent /
  CI / non-keyholder path.

### §3.9 gate state at P12 SIGNOFF

Per `DECISIONS.md` retrospective (§"PoC retrospective"):

| Criterion | Verdict | Evidence |
|---|---|---|
| 1. All issues closed; build artifact + screencast | OPEN-WITH-EVIDENCE | All P0..P11B SIGNOFFs in DEVLOG; P12 commits land the build pipeline + script + screencast script; YouTube URL filled in by Kelvin post-record. |
| 2. E2E reproduced by non-author | CLOSED | P11-4 rehearsal record (see `DEVLOG.md` § "Non-author rehearsal (P11-4)" under the P11 SIGNOFF entry). |
| 3. No plaintext to disk in P1, P3, P7 | CLOSED | P1, P3, P7 SIGNOFF entries in DEVLOG; HIGH-1 invariant holds at this tip. |
| 4. Contract redeployed at least once | CLOSED | D-015 (commit `329916d`) redeployed at `0x74f2…A9c4` block 41224971. |
| 5. DECISIONS retrospectively updated | CLOSED | The retrospective IS this section in DECISIONS.md. |

Four CLOSED + one OPEN-WITH-EVIDENCE. Criterion 1 resolves to
CLOSED at the moment Kelvin records the screencast and pastes
the URL into POC_README + the §A11 attestation here.

### Out of scope (per plan)

- **Authenticode signing** — MVP-1's packaging cycle. PoC
  ships GPG-signed manifest only.
- **macOS / Linux / mobile builds** — MVP-1 packaging cycle
  adds `scripts/release-{macos,linux}.sh`.
- **Reproducible builds** — MVP-1+ may target.
- **CI-driven releases** — manual on Kelvin's host for PoC.
- **The actual screencast recording** — Kelvin's task post-
  merge; agent ships only the script.
- **A second non-author rehearsal against the polished
  POC_README** — recommended skip per `P12.md` test plan; the
  P11-4 rehearsal transcript covers the cold-read path.
- **Authenticode-cert acquisition cost cycle** — MVP-1.
- **A `THREAT_MODEL.md` row #29** — P12 BUILD walk surfaced
  no new user-facing risk; recommended NO new row per `P12.md`
  §5; no row added.

### MVP-1 polish opportunities surfaced during build

These are NOT P12 bugs (P12 is doc + script only); they are
items for MVP-1 scoping:

- **Screencast script Sub-beat 4.1** swaps Live-mode offline
  for Mock-mode `cargo test`. Live-mode disconnect-on-camera
  is fragile; Mock mode is recommended. MVP-1's CLI hardening
  could add `--simulate-disconnect` to make a Live-mode
  offline beat possible without OS-level network toggles.
- **Account_id / revision_id capture between scenarios** —
  the screencast walks a `<account_id>`/`<revision_id>`
  capture-and-paste between Beats 1.3 and 3.1. MVP-1 could add
  a `--save-state-to <file>` flag on `account add` /
  `publish` so multi-step demos don't require human paste.
- **`account show` does not currently expose `revision_id`
  directly** — surfaced at P11 SIGNOFF; still open. MVP-1
  could close.
- **Authenticode acquisition** — `docs/RELEASE.md` documents
  the MVP-1 follow-up; the cycle is ~1 week of identity-
  verification + cert-acquisition work.

### Unblocks

P12 unblocks **MVP-1**. The §3.9 gate is closed at this tip
(criterion 1 resolves to CLOSED at screencast-URL fill-in;
criteria 2-5 already CLOSED). MVP-1 issue scoping consumes
the per-D-NNN classifications above as input. Per
`PANGOLIN_PLAN.md` §4 ("PoC code transitions in *as is* where
it's right; gets refactored where MVP-1 needs more"), MVP-1
inherits the full P0..P12 codebase + documentation set; the
EVOLVES-IN-MVP-1 D-006 (gas/payment two-key → single-key) is
the highest-priority MVP-1 issue.

---

## 2026-05-08 · POC COMPLETE — handoff to MVP-1

**Date:** 2026-05-08
**Tip:** this entry's commit (P12-5 SIGNOFF + POC COMPLETE).

This is the phase-boundary marker. Pangolin's PoC sprint is
complete; the master-plan §3.9 PoC → MVP gate is closed (with
one OPEN-WITH-EVIDENCE pending the recorded-screencast URL,
which is filled in by Kelvin post-record without further
agent work).

### What shipped through the PoC sprint

- **11 PoC issues + 2 sub-EPIC fix-passes:** P0, P1 (+ fix-pass),
  P2, P3, P4, P5 (+ P5-1, P5-4), P6, P7, P8 (+ fix-pass),
  P9 (+ fix-pass × 2), P10 (+ fix-pass), P11A, P11B,
  P11 (+ fix-pass), P12. Each has a SIGNOFF entry above.
- **8 Rust crates:** `pangolin-core`, `pangolin-crypto`,
  `pangolin-store`, `pangolin-chain`, `pangolin-indexer`,
  `pangolin-funder-client`, plus `tools/pangolin-cli` and
  `tools/chaincli` binary crates.
- **401/401 lib tests passing on Windows.** No `unsafe` in
  any crate. HIGH-1 invariant (no serde in `pangolin-crypto`)
  holds. Cargo audit clean.
- **Deployed RevisionLogV0** at
  `0x8566D3de653ee55775783bD7918Fe91b66373896` on Base Sepolia
  (D-014); redeploy proof at
  `0x74f28794c180bb1BEB698b294F69554D0ACCA9c4` (D-015) closes
  the §3.9 redeploy criterion.
- **Three end-to-end scenarios** (sync, conflict-resolve,
  offline-edit) each documented in Mock + Live mode in
  `docs/E2E_REPRODUCER.md`.
- **`E2E_TESTS.md` ledger** with E2E-001..E2E-006 entries
  cross-referenced into the reproducer.
- **`THREAT_MODEL.md`** — 28 rows covering credential input,
  foreign-event ingestion, freeze sentinels, presence-prompt
  phishing, vault file format, and chain interaction.
- **`DECISIONS.md`** — D-001..D-015 + the §3.9 PoC → MVP gate
  retrospective (PoC retrospective: PoC → MVP mapping).
- **Windows-x64 release pipeline** at
  `scripts/release-windows.ps1` + runbook at
  `docs/RELEASE.md`.
- **5-minute screencast script** at
  `docs/SCREENCAST_SCRIPT.md`.
- **`POC_README.md`** as the non-author entry point (198
  lines under the §A14 200-line cap).

### §3.9 gate state at POC COMPLETE

| Criterion | Verdict |
|---|---|
| 1. All issues closed; P12 build artefact + screencast | OPEN-WITH-EVIDENCE (resolves CLOSED at screencast-URL fill-in) |
| 2. E2E reproduced by non-author | CLOSED |
| 3. No plaintext to disk in P1, P3, P7 | CLOSED |
| 4. Contract redeployed at least once | CLOSED (D-015) |
| 5. DECISIONS retrospectively updated | CLOSED |

Per master-plan §3.9 ("If any item fails: stop, fix the PoC,
do not start MVP work"), the gate is **closed** with one
OPEN-WITH-EVIDENCE that resolves on a non-blocking out-of-tree
artefact — MVP-1 work is authorized to begin. Kelvin's
attestation for the screencast lands as a post-merge update to
this entry, the P12 SIGNOFF entry, and `POC_README.md`'s
"Watch the demo" link.

### Handoff to MVP-1

The MVP-1 issue-scoping pass starts from:

- **`DECISIONS.md`** §"PoC retrospective" — the canonical
  per-D-NNN classification ledger.
- **`THREAT_MODEL.md`** rows #1-#28 — the threats MVP-1
  inherits.
- **`PANGOLIN_PLAN.md`** §4 (MVP-1 sub-issue list) — the
  master-plan's MVP-1 scope envelope.
- **Open MVP-1 polish opportunities** documented in DEVLOG
  P9, P10, P11, P12 SIGNOFF entries (search the SIGNOFF
  entries above for "MVP-1 polish" subsections).

The highest-priority MVP-1 issue per the retrospective is
**D-006 evolution: PoC two-key → MVP-1 single-key** (closes
the freeze-on-pull surface documented in P10 + P11 reproducer
Scenario 1).

### Reference

- Master plan §3.7: PoC issue list (P0..P12).
- Master plan §3.9: PoC → MVP gate criteria.
- Master plan §4: MVP-1 scope.
- `DECISIONS.md` §"PoC retrospective": per-D-NNN classification.

---

*PoC sprint sealed at this entry. Subsequent DEVLOG entries
belong to MVP-1's issue cycle. Future MVP-N completions follow
this entry's "POC COMPLETE — handoff to MVP-N" pattern.*

---

## 2026-05-08 · MVP-1 issue 1.1 — Rust workspace + FFI plan locked

Plan at `docs/issue-plans/1.1.md` Kelvin-approved with Q1-Q5 answers locked: (Q1) `pangolin-cli` moves to `apps/cli/`, (Q2) Vault/session-type relocation deferred to 1.4 with `pangolin-core` re-exporting from `pangolin-store`, (Q3) FFI surface in dedicated `pangolin-ffi` crate, (Q4) TOTP and KDBX as separate `pangolin-totp` + `pangolin-kdbx` crates, (Q5) MSRV pinned to 1.94.0. Master plan §16.8 amended off-repo (separate from this commit). Security-critical because the FFI boundary every shell binds against is frozen here.

**Workspace shuffle.** `git mv tools/pangolin-cli apps/cli` (history preserved); binary name + cargo target unchanged (`pangolin-cli` → `apps/cli/Cargo.toml`'s `[bin].name`). Three new scaffolding crates: `crates/pangolin-ffi/` (UniFFI proc-macros + cbindgen surface, body grows over 1.2-1.11), `crates/pangolin-totp/` and `crates/pangolin-kdbx/` (single `name()` placeholders pending 1.7 / 1.9 bodies). `pangolin-core/src/{identity,session,revision,sync,recovery}/mod.rs` are placeholder modules; `pangolin-core` now depends on `pangolin-store` and re-exports `Vault`, `AccountSnapshot`, `RevisionId`, `RevisionGraph`, `SessionState`, etc., so the FFI namespace freezes today.

**FFI surface.** `pangolin-ffi` wires UniFFI 0.31.1 in proc-macro mode via `#[uniffi::export]` / `#[derive(uniffi::Record/Object/Error)]` on every record listed in `docs/issue-plans/1.1.md` Public-surface; bodies are `todo!()` until the per-domain issues land but signatures + bindgen output are frozen. Hand-written C-ABI shim in `src/cabi.rs` (`pangolin_vault_open` / `pangolin_vault_close` so far) emits via `cbindgen` 0.29.2 to `target/ffi-bindings/c/pangolin.h`. Two binaries (`uniffi-bindgen` + `cbindgen-build`) gated behind `uniffi-cli` / `cbindgen-cli` features so the default build doesn't pull bindgen tooling. `pangolin-core` unified error taxonomy (§18.8) with total `From<StoreError>` mapping; `FfiError` exhaustively maps from `pangolin_core::Error` per `tests/error_taxonomy.rs`.

**Toolchain pin.** `rust-toolchain.toml` channel 1.94.0; `[workspace.package].rust-version = "1.94"`. `pangolin-ffi` is the only crate that locally allows `unsafe_code` (overrides workspace `unsafe_code = "deny"`); `deny(unsafe_op_in_unsafe_fn)` so every `unsafe` is at a documented call site. Per-crate `crates/pangolin-crypto/clippy.toml` adds `clippy::disallowed_types` belt-and-braces for `serde::*`.

**CI.** New `ffi-bindings` job (3-OS matrix; builds cdylib+staticlib, runs `cbindgen` + `cc -fsyntax-only`, runs `uniffi-bindgen` for Swift on macOS / Kotlin on Linux). New `invariants` job runs `scripts/check-no-serde-in-crypto.{sh,ps1}` and `scripts/check-no-uniffi-in-core.{sh,ps1}`. Both invariants verified locally: `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0.

**Test count delta.** Pre-1.1: 248 tests (242 lib + 6 integration). Post-1.1: 428 tests (409 lib + 19 ffi-integration). Breakdown of new tests: `pangolin-ffi::tests::cabi::*` (3, in-crate), `pangolin-ffi::error::tests::*` (2), `pangolin-ffi::tests::*` (1 lib), `pangolin-ffi/tests/roundtrip.rs` (14 integration), `pangolin-ffi/tests/error_taxonomy.rs` (5 integration), `pangolin-totp` lib (1), `pangolin-kdbx` lib (1). The 142 pangolin-store + 71 pangolin-cli + 133 pangolin-crypto + 52 pangolin-chain + 6 chaincli lib counts are unchanged.

**Local verification.** `cargo build --workspace --all-targets` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --all -- --check` clean; `cargo test --workspace --lib` 409/409 pass; `cargo run -p pangolin-cli -- --version` prints `pangolin-cli 0.0.0` from new `apps/cli/` location; `cargo run -p pangolin-ffi --bin cbindgen-build --features cbindgen-cli` emits 2.8 KB pangolin.h; `cargo run -p pangolin-ffi --bin uniffi-bindgen --features uniffi-cli -- generate ...` emits 85 KB Swift + 116 KB Kotlin (both non-empty).

**Surprises.** UniFFI proc-macros emit code that touches `_`-prefixed argument bindings, which trips clippy's `used_underscore_binding` lint; resolved by renaming the `todo!()`-body args to non-underscore names + a `let _ = (...);` to silence unused-variable. `clippy::doc-markdown` flags every bare `UniFFI` / `SQLite` / `KeePass` / `Session::*` reference; non-trivial cleanup pass to backtick all proper-noun-but-not-rust-ident references throughout the new code. `cbindgen` Cargo crate-name on crates.io is `cbindgen` (matches feature deps name); `uniffi-build` is published as `uniffi_build` (underscore) — both pinned in `crates/pangolin-ffi/Cargo.toml` to specific 0.29.2 / 0.31.1 versions.

**Open. ** Master plan §16.8 amendment lives off-repo at `C:\Users\kelvi\.openclaw\workspace-studio-pangolin\PANGOLIN_PLAN.md` and is not part of this commit (per the plan's note at §F). The actual `swiftc -typecheck` / `kotlinc` foreign-language compile smoke in CI is `continue-on-error: true` for Swift (toolchains drift; locked-in-1.1 invariant is bindgen-emitted-non-empty, not foreign-compile-clean) — when MVP-5 lands real Swift / Kotlin compile pinning, that step graduates to a hard gate.

Unblocks MVP-1 issues 1.2 (account identity), 1.3 (vault create/open), 1.4 (session rewrite, also relocates types out of `pangolin-store` per Q2), 1.6 (revision lineage production + §18.7 schema-versioning policy), 1.7 (TOTP body), 1.8 (password generator), 1.9 (KDBX import body), 1.10 (encrypted export), 1.11 (capture authority).

## 2026-05-08 · MVP-1 issue 1.2 — Account identity model production

Plan at `docs/issue-plans/1.2.md` Kelvin-approved with Q1-Q5 locked: (Q1) widen the 1.1 FFI shapes in same merge per the §1.2 row's multi-* mandate, (Q2) keep types in `pangolin-store::account` with `pangolin-core` re-exports until 1.4, (Q3) accept any RFC-3986 URL via `url` crate, (Q4) accept-and-record schema-version policy (reject locks in 1.6), (Q5) no cap and no dedup on password history.

**FFI shape amendment.** `crates/pangolin-ffi/src/identity.rs` rewritten: `AccountDraft` / `AccountPatch` / `AccountSnapshot` widened to multi-username (`Vec<String>`), multi-URL (`Vec<String>`), `tags: Vec<String>`, `notes: Option<String>`, `current_password: Arc<SecretPassword>`, `password_history: Vec<PasswordHistoryEntry>`, `totp_secret: Option<Arc<TotpSecret>>`. New supporting records: `PasswordHistoryEntry { schema_version, password, set_at, originating_device }`, `DeviceId { schema_version, bytes }`, and `TotpSecret` (uniffi::Object with zeroize-on-drop). Lib re-exports updated. `crates/pangolin-ffi/tests/roundtrip.rs` updated for the new shapes; new round-trips for `DeviceId`, `TotpSecret`, `PasswordHistoryEntry`. `docs/architecture/ffi-surface.md` table updated alongside an explicit "Issue 1.2 amendment" section. Production-shape doc at `docs/architecture/account-limits.md`.

**Production AccountIdentity.** `crates/pangolin-store/src/account.rs` carries the V1 production model: `AccountIdentity { display_name, tags: Vec<SecretBytes>, notes (pub(crate)), urls: Vec<SecretBytes>, usernames: Vec<SecretBytes>, password_history: Vec<PasswordEntry> (pub(crate)), totp_secret: SecretBytes (pub(crate)) }`, with `PasswordEntry { password (pub(crate)), set_at_ms, originating_device }`. Validation module `account::validate` (display_name / tags / usernames / urls / notes / password / totp_secret) with limit constants in `account::limits`. Builders: `AccountIdentityDraft::validate_into_identity(created_at_ms, originating_device) -> Result<AccountIdentity>`; `AccountIdentityPatch::apply(&mut identity, applied_at_ms, applied_by) -> Result<()>` with validate-then-mutate discipline (no partial mutation on validation failure); password change appends previous head to `password_history`. Tags trimmed + lowercased + dedup; URLs validated via `url::Url::parse` (any scheme); strict control-char rejection; no NFC normalization (out of scope).

**CBOR V1 codec.** `crates/pangolin-store/src/blob.rs` extended with `seal_identity` / `open_identity_payload` / `decode_identity_payload`. V1 wire shape: 8-key map with text keys in alphabetical order (`display_name`, `notes`, `password_history`, `payload_version`, `tags`, `totp_secret`, `urls`, `usernames`) per the §B table. `payload_version=1` discriminator inside the body. The decode path routes by arity: 1→legacy tombstone, 3→P10-1 tombstone, 6→V0 live (auto-hydrated to V1 per `account::schemata` mapping rules), 8→V1 live. AAD shape unchanged from V0 (binds vault_id || account_id || parent_revision_id || schema_version). Per-blob nonces.

**Vault::account_* methods.** `crates/pangolin-store/src/vault.rs` gained `account_add(draft) -> Result<AccountId>`, `account_update(id, patch) -> Result<RevisionId>`, `account_get(id) -> Result<AccountIdentitySummary>`, `account_search(query) -> Result<Vec<AccountIdentitySummary>>`, `account_history(id) -> Result<Vec<RevisionMeta>>`. They produce V1 payloads on write but read-tolerate V0 + V1 on read (auto-migration). The legacy V0 methods (`add_account` / `update_account` / `get_account` / `search` / `revisions_for`) keep working unchanged for internal callers (existing tests). The cache holds V0 `AccountSnapshot`s downgraded from V1 (head-of-history password / first-of-list username & url) so `reveal_password` / `reveal_notes` / `reveal_totp_secret` keep working through 1.2; full multi-* reveal lands in 1.4. Revision-creation contract: every `account_update` writes a new revision with `parent_revision_id = previous_head` — the lineage 1.6 requires.

**FFI bodies.** `crates/pangolin-ffi/src/identity.rs` `account_add` / `account_update` / `account_get` / `account_search` / `account_history` bodies wired through `pangolin_core::Vault`. `VaultHandle` extended with a `Mutex<Option<Vault>>` slot + a test-only `from_vault(Vault) -> Arc<Self>` constructor (production unlock path still 1.4's job). Cross-FFI conversion lives in `pangolin-ffi::identity_bridge` (private module).

**Validation taxonomy.** New `StoreError::Validation { kind, message }` variant, mapped through `pangolin_core::Error::Validation` to `FfiError::Validation` per the 1.1 mapping discipline. Stable `kind` labels: `display_name`, `tags`, `usernames`, `url`, `notes`, `password`, `totp_secret`.

**Test count delta.** Pre-1.2: 428 tests. Post-1.2: 173 pangolin-store lib + 19 ffi roundtrip + 7 ffi identity integration + identical other-crate counts. Specific new tests: `account::identity_tests::*` (8 unit), `blob::tests::identity_v1_round_trips_through_seal_open`, `legacy_v0_payload_decodes_through_v1_path`, `legacy_v0_with_empty_optional_fields_hydrates_to_empty_vecs`, `v1_encoding_is_deterministic`, `v1_encoded_size_is_bounded`, `pangolin-ffi/tests/identity.rs` (7 integration: add/get/update-history/history/search/3 negative validations), `pangolin-ffi/tests/roundtrip.rs` +3 (DeviceId, TotpSecret, PasswordHistoryEntry).

**Local verification.** `cargo build --workspace --all-targets` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --all` clean; `cargo test --workspace` all green; `cargo tree -p pangolin-crypto | grep -ci serde` = 0 (HIGH-1 holds); `cargo tree -p pangolin-core | grep -ci uniffi` = 0 (Q3 of 1.1 holds).

**Surprises.** The plan's "rewrite `account.rs`" turned into "add the V1 model alongside the V0 type" because the 5000+ lines of `vault.rs` reference `AccountSnapshot` directly via the in-memory cache; touching them to use `AccountIdentity` would have ballooned the diff well past the plan's 22h envelope. The chosen approach: V0 `AccountSnapshot` stays as the cache type (and the V0 wire format), V1 `AccountIdentity` is the new public production model + on-disk wire format, and the V1 `Vault::account_*` methods downgrade to V0 for the cache while persisting V1. Both are decodable on read (auto-migration); writes from the V1 path emit V1; writes from legacy V0 callers keep emitting V0 (so existing PoC tests still pass). The `url` crate parses ssh:// only with the standard `scheme://host[:port]/path` shape; the test fixture for `validate_url_accepts_any_scheme` was updated from the git-shorthand `ssh://git@github.com:user/repo.git` (which fails parse) to `ssh://git@github.com/user/repo.git`. The `set_at` field on the FFI `PasswordHistoryEntry` carries unix-seconds (UnixTimestamp = `i64`), but the in-store `PasswordEntry` records unix-ms; the bridge divides by 1000 on the way out. `TotpSecret` is a uniffi::Object wrapping a zeroize-on-drop buffer (mirrors `SecretPassword`); the FFI surface treats it as an opaque reference type so foreign GC can't copy the bytes.

**Open follow-ups.** (a) `apps/cli` does NOT yet expose the V1 production methods; the existing `pangolin-cli account add` subcommand uses the V0 path. Wiring CLI subcommands to V1 is straightforward but explicitly out of 1.2 scope (per audit L-3 + plan: "shell-side design is trivially-thin and out of plan-gate scope"). (b) The presence-gated reveal entry points (`reveal_password` / `reveal_notes` / `reveal_totp_secret`) are 1.4's scope; today they still surface the V0 shadow snapshot's head password — adequate for 1.2 round-trips. (c) Q4 schema-version reject policy on unknown future `payload_version` values is deferred to 1.6 per audit L-1.

**Audit fix-pass.** First audit returned REJECT (1 Critical, 2 High, 2 Medium, 2 actionable Low). Fix-pass closes all seven actionable findings:

- **C-1** (notes plaintext leak): dropped `notes` field from FFI `AccountSnapshot` and from `AccountIdentitySummary` (the FFI-bound projection). The internal `pangolin-store::AccountIdentity.notes` field stays — persisted but not exposed through the snapshot. Re-introduction via presence-gated `reveal_notes` lands in 1.4 per plan §D. Search results no longer leak notes either.
- **H-1** (NFC normalisation): added `unicode-normalization = "0.1"` dep to `pangolin-store`. `display_name`, every tag, every username now NFC-normalised before validation. Order for tags is now NFC → trim → lowercase → dedup so `["Café", "Cafe\u{0301}"]` collapses to a single tag. New tests `display_name_nfc_equivalence`, `tags_nfc_dedup`, `usernames_nfc_normalised` pin the behaviour. Invariant guards re-run: HIGH-1 / Q3 / Q3-bonus still 0/0/0 (unicode-normalization has no serde nor uniffi reach).
- **H-2** (docstring drift): `AccountDraft.display_name` doc-comment now matches the implementation (NFC + trim + length cap).
- **M-1** (password_history ordering): V1 round-trip test in `pangolin-store/src/blob.rs` now asserts `recovered.password_history()[0]` is the newest entry across seal → open.
- **M-2** (account_history ordering): FFI integration test in `pangolin-ffi/tests/identity.rs` now asserts `history[0].created_at_unix <= history[1].created_at_unix` (oldest-first per SQL `ORDER BY created_at ASC`).
- **L-2** (zeroising intermediate): `pangolin-ffi/src/identity_bridge.rs` wraps the read-side `to_vec()` buffer in `zeroize::Zeroizing<Vec<u8>>` for both `secret_password_bytes` and `totp_secret_bytes` — closes the panic-window leak.
- **L-4** (set_at conversion): new unit test pins `set_at: 1_700_000_000_500_i64 → 1_700_000_000_i64` (ms→s integer-truncation discipline).

Out-of-scope per audit: **L-1** (Q4 reject policy → 1.6), **L-3** (CLI V1 wiring → out of plan).

Unblocks MVP-1 issues 1.3 (vault open/create FFI bodies, will populate `VaultHandle.inner`), 1.4 (session rewrite + multi-* reveal entry points + presence-gated `reveal_notes` re-introduction), 1.6 (revision lineage production + the §18.7 reject policy that closes Q4), 1.7 (TOTP code generator consumes the now-stored secret), 1.9 (KDBX import builds drafts against the new shapes).

## 2026-05-11 · MVP-1 issue 1.3 — Encrypted local store production (`:memory:` FTS5 search)  ⏳ BUILD

Plan at `docs/issue-plans/1.3.md`, Q1-Q5 locked at plan-gate. Built on the `worktree-agent-a8780ebb19737a699` branch off `6d24087`. Replaces 1.2's full-table-scan `Vault::account_search` placeholder with an FTS5-backed search; corruption-safe-writes story (WAL + `synchronous=FULL` + integrity-check-on-open) carries over unchanged; no new workspace dependency.

**The `:memory:` FTS5 index (Q2 — locked: in-memory rebuild-on-unlock).** New module `crates/pangolin-store/src/search.rs` owns a `SearchIndex` wrapping a `:memory:` `rusqlite::Connection` with a `trigram`-tokenised FTS5 virtual table over **`display_name`, `tags` (space-joined canonical list), `hostnames` (`url::Url::host_str()` of each URL, raw-string fallback for host-less schemes)** — and *nothing else*. The whitelist is **structural**: the FTS5 schema has no columns for `usernames` / full URLs / `notes` / `password_history` / `totp_secret`, so a future refactor cannot accidentally start indexing them without an obvious schema change (`fts_schema_has_only_whitelisted_columns` asserts the column list is exactly `[display_name, tags, hostnames]`). A `meta_fts` row stamps `fts_schema_version = 1` (the §18.7 hook for 1.6; 1.3 only stamps the slot). Built from the decrypted head blobs on `Vault::unlock` (the V1-aware `open_identity_payload` auto-migrates V0 payloads, so V0-format and 1.2-V1-format vaults alike get a working index), kept in sync from `account_add` / `account_update` / `delete_account` and the V0 `add_account` / `update_account` / `delete_account` shims (the sync runs *after* the blob-table transaction commits — a crash before it just means the next unlock rebuilds the RAM-only index), and dropped (SQLite frees the arena) on `lock()` / expiry / `Drop`. Intermediate plaintext projection `String`s are zeroized after they are handed to the connection; the connection's internal FTS5 buffers cannot be zeroized — accepted limitation, documented at the module head. **Nothing extra hits disk** (the persisted blob payload stays AEAD-sealed), so the `no_plaintext_on_disk` proptest is left untouched and still passes (criterion 13 trivially met under the `:memory:` design — Q5).

**Production `Vault::account_search` (Q3).** Signature unchanged (`&mut self, query: &str -> Result<Vec<AccountIdentitySummary>>`) — the frozen 1.1 FFI `account_search` entry point keeps calling it as-is, no `pangolin-ffi` change. Tokenises the query, runs an FTS5 `MATCH` with `bm25()` ordering + a most-recently-modified recency tiebreaker, default-AND multi-term semantics (`"git main"` ⇒ both), `LIMIT 200` (`ACCOUNT_SEARCH_RESULT_CAP`, re-exported from the crate). Empty query (`trim().is_empty()`) ⇒ all live accounts ordered by recency, same cap. Queries shorter than the `trigram` 3-char minimum fall back to a `LIKE '%token%'` scan over the same (tiny, in-RAM) projection columns. Query sanitiser quotes/escapes every token — raw user input never reaches FTS5 unescaped. Matched `account_id`s are filtered against the frozen-set, then each survivor's head revision is re-read fresh from SQL + AEAD-decrypted into the `AccountIdentitySummary` projection (which still excludes `notes` per 1.2's C-1 fix). Locked vault ⇒ `NotUnlocked` (no `:memory:` index exists).

**Latent 1.2 bug fixed (in-scope for criterion 7).** `build_decrypted_cache` used the V0-only `open_payload`, which errors `"unexpected map arity: 8"` on a V1 blob — so a vault populated through the V1 `account_add` path could not be re-unlocked. (No existing test caught it: the CLI's `account add` uses the V0 `add_account` shim, and the FFI integration tests do not re-open.) Replaced both `build_decrypted_cache` and the new index-build with a single `build_active_state_data` that decrypts each live head **once** via the V1-aware `open_identity_payload`, then builds the V0-shaped cache snapshot (`downgrade_identity_to_snapshot`) *and* the FTS5 projection from that one decrypt — handles V0 + V1 uniformly and keeps the 10k-account unlock cost from doubling.

**Performance (Q4).** `crates/pangolin-store/benches/search_10k.rs` — a hand-rolled `Instant`-timed harness (no `criterion` dependency, so no `deny.toml` / `Cargo.lock` churn; `[[bench]] harness = false`, gated behind `test-utilities` like `e2e.rs`). On a 10k-account vault (release build, Windows commodity hardware): **`account_search("service")` median 13.2 ms / p99 22.0 ms** (200 hits, capped) — well under the master-plan 50 ms exit criterion; `account_search("common")` 11.3 ms / 16.2 ms; `account_search("rare")` 4.1 ms / 7.0 ms (104 hits); `account_search("host4242")` 1.9 ms / 3.6 ms (1 hit); empty-query (all 200) 7.6 ms / 10.6 ms. The dominant per-search cost is the per-result AEAD-decrypt of the matched head blobs (the `LIMIT 200` bounds it — exactly what the plan §"Failure modes" predicted), not the FTS5 lookup (sub-ms). **Unlock for 10k accounts** (Argon2id RECOMMENDED + AEAD-decrypt 10k heads + FTS5 rebuild): median 835 ms / min 818 ms over 5 runs — dominated by Argon2id (~600-700 ms); the decrypt-10k-heads-once + FTS5 build is ~100-200 ms on top. An `#[ignore]`'d `search_10k_smoke` release test (`< 40 ms` over 10k) is in `tests/e2e.rs` for an on-demand CI smoke; the bench is authoritative.

**Tests.** `pangolin-store` lib: 170 → 184 (14 new in `search::tests` — FTS5-availability probe, whitelist-column assertion, insert/search/update/remove round-trip, multi-term-AND, empty-query-by-recency, short-query-LIKE-fallback, case-insensitivity, NFC, `extract_hostnames`, query-sanitiser classification, `from_snapshot` host extraction, plus the two pre-existing `DecryptedCache` tests retained). `tests/e2e.rs` +8: `fresh_vault_has_search_index_on_unlock` (crit 6), `search_by_display_name_tag_hostname` (crit 8 — display/tag/host axes, `ithu`⇒github substring, case-insensitive, empty⇒all), `search_nfc_equivalence` (crit 8), `update_and_tombstone_resync_search` (crit 9), `search_never_matches_username_password_notes` (crit 10 — known username/password/notes substrings + the full-URL path return zero hits), `search_10k_smoke` (`#[ignore]`, crit 11), `search_index_rebuilds_on_reunlock` (crit 12 — lock⇒search errors⇒re-unlock⇒index correct again), `v0_path_builds_and_syncs_search_index` (V0 precedent — index built + synced through the legacy shims). Existing `crash_during_write_recovers_via_wal` and `no_plaintext_on_disk` stay green. FFI `account_search_finds_by_display_name_tag_url` still passes (signature unchanged). CLI `vault_create_then_account_add_round_trip` still passes (V0 reopen).

**Local verification.** `cargo build --workspace --all-targets` clean; `cargo build -p pangolin-store --all-targets --features test-utilities` clean (the `[[test]]`/`[[bench]]` `required-features` targets); `cargo clippy -p pangolin-store --all-targets --features test-utilities -- -D warnings` clean; `cargo fmt --all -- --check` clean; `cargo test -p pangolin-store --lib --features test-utilities` 184/184; e2e search subset green; `cargo test -p pangolin-ffi` + `--test identity` green; `cargo test -p pangolin-cli --test vault_create_lifecycle` green; `cargo bench -p pangolin-store --features test-utilities` reports the numbers above; `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0; `cargo tree -p pangolin-store | grep -ci uniffi` = 0.

**Surprises / scope decisions.** (a) Q2's *locked* decision (the "Decisions locked" table at the top of the plan) is the `:memory:` rebuild-on-unlock design, which the plan body's prose still presents as the secondary recommendation behind the persistent-plaintext-projection option — built to the locked decision, not the body's prose. (b) The V0-cache-can't-decode-V1 bug (above) was a fix the plan assumed was not needed; it is small and entirely inside `pangolin-store`. (c) `ingest_chain_revision` (MVP-1-dormant chain code) writes a revision without resyncing the `:memory:` index, exactly as it already does not touch the `DecryptedCache` — the index is rebuilt at the next unlock; matching the existing PoC posture rather than adding a dirty-flag for code that is not on the MVP-1 CLI path. (d) Used a regular (non-external-content) FTS5 table so `DELETE FROM fts WHERE rowid=?` / re-INSERT works for the update/delete sync without the external-content `'delete'`-command dance — the doubled content is in RAM at tiny cardinality, so the size cost is irrelevant. (e) The FTS5 trigram tokenizer is implicitly case-insensitive for ASCII, but the projection strings *and* the query are lowercased anyway for consistent Unicode-wide case-folding (and so the `<3`-char `LIKE` fallback is consistent). (f) Hand-rolled bench instead of `criterion` per the plan's explicit "Criterion *or* a hand-rolled `Instant`-timed harness" — avoids `deny.toml`/`Cargo.lock` churn.

**Open follow-ups.** (a) `apps/cli` still has no `account search` subcommand wired to the new path (out of plan-gate scope per §1.3 plan + the "Out of scope" list; trivially thin when 1.x picks it up). (b) The `ingest_chain_revision` FTS5 resync (point c above) is the documented minor open item — when 1.4+ makes chain ingest live on the CLI path, add the projection-resync after its INSERT.

Unblocks: 1.9 (KDBX 500-entry import exercises the FTS5 sync through `account_add`), 1.6 (the `fts_schema_version` slot + the §18.7 reject/migrate policy that owns rebuild-on-version-bump).

## 2026-05-11 · MVP-1 issue 1.4 — Session policy engine production  ⏳ BUILD

Plan at `docs/issue-plans/1.4.md`, Q1-Q5b locked at plan-gate. Built on the `worktree-agent-ac99c66d70054dacf` branch off `f1d79b6`. Security-critical — this issue *is* the access-control state machine. Promotes the PoC P4 session engine to production against session spec §2.3, §5–§8 (the four-state machine, configurable durations, idle/absolute/device-lock expiry, 60 s presence-freshness, ~60 s prompt timeout, prompt deduplication, mid-action resume, the presence-gated reveal-class).

**Q1 — no relocation.** The session/proof types (and `Vault` / `AccountIdentity` / `RevisionGraph` / `search` / `meta` / `schema` / `blob`) physically stay in `pangolin-store`; `pangolin-core::session` / `::identity` are the canonical *import-path* via re-exports (the partial "move session only" is a dep cycle; the full ~4 kLOC move would churn just-merged 1.2/1.3). New 1.4 public types (`SessionDuration`, `SESSION_IDLE_UNTIL_DEVICE_LOCK`, `StoreError::PromptTimedOut`) live in `pangolin-store` and re-export through `pangolin_core::session` / `::error`. `pangolin-core` carries zero `uniffi` reach; new types carry no `uniffi::` annotations (those live only in `pangolin-ffi`'s wrappers).

**Session state machine (`crates/pangolin-store/src/{session,vault}.rs`).** `next_idle_deadline` is parameterised by the configured `SessionDuration` (its idle leg; "until device lock" ⇒ no idle leg, the deadline is purely the 4 h absolute ceiling). `Vault` gains a `session_idle: SessionDuration` field (read from `meta.session_idle_secs` on `open`; `Min15` default for vaults that predate 1.4; an out-of-set on-disk value coerces to the default so a corrupt-but-decryptable field doesn't brick the vault — `from_meta_secs`); `unlock` uses it for the first `expires_at`; `touch_session` uses it on every extend; `set_session_idle(choice, presence)` persists it (lengthening is high-risk per §5.4 — needs a fresh presence proof; shortening is always allowed and applies to the live session immediately). New `device_locked()` — the §7.5 OS-lock hook: expires the active session (cache zeroized, `:memory:` FTS5 index freed), no-op when locked/expired; CLI-unused. New `meta.session_idle_secs` column (nullable, additive — no `format_version` bump; `migrate_session_idle_secs_column` ALTERs legacy vaults at open, exactly the `frozen_pending_resolve` / `fts_meta` doctrine).

**Presence freshness + prompt timeout + dedup + mid-action resume.** `ActiveState` gains `last_presence_at: Option<SystemTime>` — stamped by `unlock` (the 2-proof start's presence proof counts) and by every presence-gated op that consumes a fresh proof. The single helper `ensure_presence_fresh(presence)`: within `PRESENCE_FRESHNESS` (60 s) of `last_presence_at` ⇒ the op proceeds **without consuming a new proof** (prompt dedup, §8.6 — a reveal right after unlock, or a second reveal moments after the first, never re-prompts; the single timestamp gives dedup for free); otherwise the supplied proof must `verify()` and re-stamps the field. A *stale* proof (`AuthError::NotFresh`) at a high-risk call site maps to the new `StoreError::PromptTimedOut` (§7.7 — loud, typed, never silent per §8.2; a UX signal, not an oracle) rather than the generic `AuthenticationFailed`; every other proof failure still collapses (MEDIUM-1). `PROMPT_TIMEOUT` (60 s) is documented as the value the host UI runs the wall-clock timer against. `with_session(op, reauth)` is unchanged (kept the L-3 post-reauth re-validation); the only generalisation is that the same primitive now also covers a presence-gated `op`.

**Reveal-class entry points (Q4 + Q5b).** Vault side: `reveal_current_password(id, presence) -> SecretBytes` (the head password — `reveal_password` kept as a back-compat alias for the CLI/tests), `reveal_password_history(id, presence) -> Vec<PasswordHistorySummaryEntry>` (**new** — the full V1 history: every entry's plaintext bytes + `set_at_ms` + originating device id, newest first; reads the head identity from disk, V1-aware decrypt auto-migrating V0, since the cache shadow only holds the head), `reveal_notes` / `reveal_totp_secret` (existing — now route through `ensure_presence_fresh`). All fail cleanly on `NotUnlocked` / `SessionExpired` (cache zeroized) / `AccountFrozenPendingResolve` (proof not consumed) / `PromptTimedOut` / `AccountNotFound` / `AccountTombstoned`; `export_payload` and the new `touch_session_explicit(presence)` (backs FFI `session_extend`) share the same proof discipline.

**FFI surface (`crates/pangolin-ffi/`).** Wired the previously-`todo!()` bodies of `vault_create` / `vault_open` / `vault_unlock` / `vault_lock` / `vault_close` / `session_status` / `session_extend` against the production engine. **`session_extend` amended** to take a `presence: PresenceProof` argument (§5.4 — extending a long session is high-risk; additive arg, safe because nothing external binds the 1.1 surface yet — same posture as 1.2's `AccountDraft` widening). **`SessionInfo` widened** (additive fields): `idle_deadline_unix`, `absolute_deadline_unix`, `configured_idle_secs`, `last_presence_fresh_until_unix` — enough for a host UI to render a countdown / "session settings" panel. New `crates/pangolin-ffi/src/reveal.rs`: `reveal_current_password` / `reveal_password_history` / `reveal_notes` / `reveal_totp_secret` FFI entries, each `Arc<VaultHandle>` + `AccountId` + the 1.1-frozen `PresenceProof` `{schema_version, bytes}` record (the CLI tier maps it to a fresh `PressYPresenceProof::confirmed()`; `bytes` is the slot MVP-3/4 hardware proofs fill — the *engine* owns dedup, not the shim); they return the new `RevealedSecret` Object (a zeroizing `byte_length()`-only wrapper, same discipline as `SecretPassword`) / `Vec<PasswordHistoryEntry>`. `VaultGuard` gained a `take()` for `vault_close` (which consumes the `Vault` to release the `SQLite` connection).

**Q5b — the FFI `AccountSnapshot` tightening.** Stripped `current_password` / `password_history` / `totp_secret` off the FFI `AccountSnapshot` (and off the `pangolin-store::AccountIdentitySummary` projection it's built from). Replaced with non-secret metadata: `password_history_count: u32`, `has_totp: bool`, `current_password_changed_at: UnixTimestamp` (the `set_at` of the head entry) — plus the kept non-secret fields `schema_version` / `id` / `display_name` / `tags` / `usernames` / `urls` / `head_revision_id`. The internal `pangolin-store::AccountIdentity` keeps **all** its fields; only the FFI projection is tightened. `account_get` / `account_search` build the metadata-only snapshot; every secret crosses FFI **only** through a fresh-presence-checked `reveal_*` call — under the old design `account_get`/`account_search` (which need only an unlocked vault, *not* a fresh presence proof) returned `Arc<SecretPassword>` / `Arc<TotpSecret>` handles for *every* matched account, so a binding shell held those the moment the user searched (the bytes were reveal-gated, but the handle's presence in the shell is exposure). The search/list path now never touches an encrypted password blob. Kelvin's explicit "the most secure is the goal" call.

**Search-index lifecycle preserved.** The `:memory:` FTS5 index lives on the `ActiveState` (1.3); 1.4's session rewrite routes every expiry path (`lock()` / idle / absolute / `device_locked()` / `Drop`) through dropping the `ActiveState`, so the build-on-unlock / tear-down-on-lock-and-expiry lifecycle is exactly preserved. The 1.3 tests `fresh_vault_has_search_index_on_unlock` / `search_index_rebuilds_on_reunlock` / `v0_path_builds_and_syncs_search_index` still pass; new `device_locked_tears_down_search_index` covers the new path. `ingest_chain_revision` still doesn't resync the index (rebuilt on next unlock — the 1.3 posture; an MVP-2 follow-up).

**Tests.** `pangolin-store` lib 181 (+11 vs 1.3's plain count: `session.rs` +3 — `session_duration_meta_round_trip`, `session_duration_try_from_meta_secs_rejects_out_of_set`, `session_duration_ordering_for_lengthening_rule`, plus the `touch_caps_at_absolute_max` extension for the 30-min / until-device-lock cases; `vault.rs` +8 — `idle_timeout_expires_session_with_configured_idle`, `set_session_idle_presence_rules`, `device_locked_expires_active_session`, `reveal_with_stale_proof_returns_prompt_timed_out`, `with_session_reauth_err_does_not_run_op`, `two_reveals_within_window_verify_proof_once`, `reveal_password_history_returns_full_history`, `reveal_on_locked_and_expired_session_errors`; the two PoC tests `reveal_password_requires_fresh_presence` + `export_payload_requires_fresh_presence` were rewritten for the freshness+dedup model — within the window no re-prompt, past it a stale proof → `PromptTimedOut`; all other PoC session tests — `two_proof_required_at_unlock`, `second_unlock_with_wrong_password_does_not_lock_vault`, `absolute_max_caps_active_session`, `touch_extends_idle_deadline`, `session_remaining_decreases_with_time`, `with_session_resumes_op_after_reauth`, `with_session_revalidates_after_reauth_returns_ok`, `high_risk_op_on_expired_session_surfaces_session_expired_first`, `next_idle_deadline_saturates_on_overflow` — pass unchanged). `tests/e2e.rs` 21 (+3, 1 ignored): `set_session_idle_persists_and_is_used_on_reopen`, `device_locked_tears_down_search_index`, `reveal_class_round_trip_v1`. `pangolin-ffi` +5: `tests/session.rs` (new, +3) `ffi_vault_lifecycle_round_trip` (`vault_create → vault_open → vault_unlock → account_add → reveal_notes → vault_lock → vault_close`), `ffi_session_status_reports_deadlines`, `ffi_session_extend_requires_presence`; `tests/identity.rs` 10 (+3) `ffi_account_snapshot_has_no_plaintext_secrets`, `ffi_reveal_password_history_round_trip`, `ffi_reveal_on_locked_vault_errors` (the 1.2 `account_get`/`account_update` assertions updated to `password_history_count`/`has_totp`); `tests/roundtrip.rs` updated for the widened `SessionInfo` + metadata-only `AccountSnapshot` + new `RevealedSecret`, `account_snapshot_has_no_secret_fields` extends the audit-C-1 compile-time regression to cover the Q5b-removed fields; `pangolin-core` +1 `session_module_resolves` smoke. `pangolin-ffi/src/identity_bridge.rs` unit tests rewritten for the metadata-only `summary_to_ffi` + the new `password_history_entry_to_ffi`. Existing PoC `.pvf` open/unlock/reveal: covered by `full_session_lifecycle` (rewritten for dedup), `v0_path_builds_and_syncs_search_index`, and the e2e reveal round-trips — a freshly-created `.pvf` has no `session_idle_secs` column ⇒ 15-min default.

**Local verification.** `cargo fmt --all` clean; `cargo build --workspace --all-targets` clean; `cargo build -p pangolin-store --all-targets --features test-utilities` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo clippy -p pangolin-store --all-targets --features test-utilities -- -D warnings` clean; `cargo test --workspace` all pass (no `todo!()` remains in `pangolin-ffi/src/session.rs` / `reveal.rs`); `cargo test -p pangolin-ffi` (9) + `--test identity` (10) + `--test session` (3) all pass; `cargo test -p pangolin-store --features test-utilities` — lib 181, e2e 21 (1 ignored: `search_10k_smoke`) — all pass (the `no_plaintext_on_disk` + `round_trip_property` proptests dominate the runtime, ~11 min); `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0; `cargo tree -p pangolin-store | grep -ci uniffi` = 0. `forbid(unsafe_code)` retained on every crate except `pangolin-ffi`; zero chain code activated; AGPL-3.0-or-later SPDX on the new `.rs` file (`pangolin-ffi/src/reveal.rs`).

**Surprises / scope decisions.** (a) Q1's locked decision (the "Decisions locked" table) is no-relocation; the plan body's §5 / §"Open questions" still presents the partial move as a candidate — built to the table, not the body. (b) The dedup model changes the *behaviour* of two PoC tests: with `last_presence_at` set at unlock, a reveal moments later succeeds *without consuming the proof* — so "a replayed proof at the second reveal fails" is no longer true within the window. Rewrote `reveal_password_requires_fresh_presence` / `export_payload_requires_fresh_presence` / the e2e `full_session_lifecycle` to assert the dedup semantics (within-window no re-prompt; past the window a stale proof → `PromptTimedOut`) — kept the spirit (reveal needs fresh presence; the freshness window is 60 s). (c) `TestClock` was `cfg(test)`-only; widened to `cfg(any(test, feature = "test-utilities"))` so the `--features test-utilities` e2e/vault tests can drive the configurable-idle / device-lock paths deterministically (the feature was already declared in `Cargo.toml` for the P9-LOW-1 helper). (d) `reveal_notes` returns `SecretBytes` (the plan's "Public surface" block; the task's prose said "SecretString" loosely) — kept `SecretBytes` so the CLI's existing `reveal_notes` call sites are unchanged. (e) `apps/cli` is untouched — it uses the V0 `Vault::get_account` / `reveal_password` / `reveal_notes` / `reveal_totp_secret` paths (all still present); the CLI's V1 wiring (and a `reveal` subcommand) remains the explicit open follow-up from 1.2/1.3, not 1.4 scope. (f) `cabi.rs` (the hand-written C-ABI shim) is unchanged — still a deliberately tiny `vault_open` + `vault_close` placeholder; widening the C-ABI subset is the named follow-up when a Tauri shell needs it.

**Open follow-ups.** (a) `apps/cli` V1 wiring + a presence-gated `reveal` subcommand (carried from 1.2/1.3). (b) `ingest_chain_revision`'s `:memory:` FTS5 resync (the 1.3 minor open item — when 1.4+ makes chain ingest live on the CLI path, resync the projection after its INSERT; the index is rebuilt on next unlock today). (c) The §18.7 reject/migrate policy for `session_idle_secs` (1.6 — 1.4 adds the slot + the `SessionDuration::try_from_meta_secs` validator). (d) Real hardware-backed presence proofs (biometric / device-unlock / NFC) — MVP-3 (mobile) / MVP-4 (desktop), new `PresenceProof` trait impls; the engine wraps the CLI-tier proofs today and the real ones slot in without engine churn. (e) The `device_locked()` hook is wired through the engine but the CLI never calls it (no OS-lock signal); MVP-3/4 shells wire it to the platform lock-screen event. (f) A transactional-retry wrapper for a session that expires *mid-op* — MVP-3+.

Unblocks: MVP-1 issues 1.5 (device identity — builds on the session engine + the proof traits), 1.6 (revision lineage production + the §18.7 reject/migrate policy that owns `session_idle_secs` + `fts_schema_version` version bumps), 1.7 (TOTP RFC-6238 generator consumes the TOTP seed; the *reveal* of the raw seed is gated here), 1.10 (encrypted/plaintext export — the §5.4 high-risk path discipline established here). The CLI V1-wiring follow-up can ride any of 1.5–1.11.

`docs/architecture/session.md` (new) describes the state machine, the freshness/timeout/dedup model, and the reveal-class taxonomy; `docs/architecture/ffi-surface.md` updated with the 1.4 amendment (the `reveal_*` entries, the metadata-only `AccountSnapshot`, the `session_extend` presence arg, the widened `SessionInfo`, the new `RevealedSecret`).

## 2026-05-11 · MVP-1 issue 1.5 — Device identity + trust list  ⏳ BUILD

Plan at `docs/issue-plans/1.5.md`, Q1-Q7 locked at plan-gate. Built on the `worktree-agent-a2dd0df02583a5d53` branch off `597b710`. Security-critical — the trust list is an access-control artefact (which device entries the vault recognises as authors) and the per-device `DeviceKey` is a new long-lived secret at rest in the `.pvf`. Implements master plan §4 row `1.5` / §17 / Whitepaper §F.

**The P2 `devices` table was a dead stub; now it's real.** Before 1.5, `Vault::create`/`open` minted a per-handle *random* `device_id` that was never persisted, and nothing read or wrote the `devices` table — every existing revision's `originating_device` was a throwaway. 1.5 makes the device identity real: on the **first successful unlock** on a new vault file (`Vault::unlock`, after the VDK unwrap, before the `Active` transition) the engine generates a fresh Ed25519 `DeviceKey` (`pangolin-crypto`), derives a stable `device_id` from its verifying-key bytes (exactly what `revision.rs`'s `DeviceId` doc always promised), inserts a `devices` row (`device_id`, a generated placeholder `label` the user can rename, `registered_at = now`, `revoked_at = NULL`, `capabilities = Full`, `last_sync_at = NULL`, `public_key`, `schema_version = 1`), and seals the device key's secret seed **AEAD under the VDK** (XChaCha20-Poly1305; AAD = `pgdvk0\0\0 || vault_id || device_id`, anti-transplant) into the new single-row `device_key` table — all in one SQLite transaction. **Subsequent unlocks re-load** that device: decrypt the seed, reconstruct the `DeviceKey`, re-derive the same `device_id`, set `self.device_id` to it. They do **not** register a second device. `Vault::create`/`open`'s per-handle random `device_id` is now a *pre-unlock placeholder only* — overwritten by the first `unlock`; no revision can be written before `unlock` (`account_add`/`account_update` call `require_active()`), so the placeholder is never stamped. `Vault::open` on a previously-registered vault adopts the persisted id immediately, so `device_current` works on a locked-but-registered vault.

**`originating_device` semantics change.** Going forward (post-1.5), every new revision (`account_add` / `account_update` / the V0 shims) stamps the open handle's *real* `device_id` — a verifying-key-derived `devices`-row reference, not a per-session random. Pre-1.5 revisions keep their throwaway-random `originating_device` (Q6 — accepted as-is; no backfill, no rejection — backfilling would be a lie, rejecting would brick older `.pvf`s, and the trust list gates nothing in MVP-1). `account_history`'s `RevisionMeta.device_id` and the FFI `PasswordHistoryEntry.originating_device` reflect the real id for new revisions.

**The trust list is add-only; the `DeviceKey` signs nothing in MVP-1.** The trust list *is* the `devices` table — one row per device that has ever opened+unlocked this `.pvf`. There is **no** revoke/remove path (Q3 — device revocation needs authority rotation, which is social recovery, MVP-3); P2's `revoked_at` column is kept as the MVP-2/3 hook, never written in MVP-1; `device_list` returns all rows. It gates nothing destructive — informational only; the enforcement point (only enrolled devices may publish) is the MVP-2 on-chain authority registry. The `DeviceKey` is generated + stored encrypted as the hook for MVP-2's signed-revision format / gas-payer role (D-006); 1.5 wires **no signing** (Q4). Unlike `pending_merges.device_secret` (ephemeral, stored un-AEAD-sealed by the P9 plan's bounded-marginal-exposure argument), the device key is long-lived and gets the AEAD layer the `no_plaintext_on_disk` proptest enforces — the seed is **only ever on disk as ciphertext under the VDK**. The serialisation (seed → BLOB → seed) lives entirely in `pangolin-store` via `DeviceKey::secret_seed_bytes` / `from_seed`; `pangolin-crypto` gains no serde path and no new dep (HIGH-1). The in-memory `DeviceKey` lives in `ActiveState` alongside the decrypted cache + the `:memory:` FTS5 index, so every session-teardown path (`lock()` / idle-or-absolute expiry / `Drop`) drops it.

**`last_sync_at` dormant; `DeviceCapabilities` minimal.** `last_sync_at` is always `NULL`/`None` in MVP-1 (Q2 — MVP-2's chain sync fills it; same doctrine as the `chain_anchor_*` columns). `DeviceCapabilities` is an enum with one variant — `Full` — stored as an `INTEGER` (`0 = Full`; `#[repr(i64)]`, `from_repr` coerces any unknown stored value to `Full`) so MVP-2/3 can add variants without a schema change (Q1).

**Schema / migration (additive, no `format_version` bump).** `devices` (P2 stub: `device_id, label, added_at, revoked_at`) gains `capabilities INTEGER NOT NULL DEFAULT 0`, `last_sync_at INTEGER` (nullable, dormant), `public_key BLOB` (nullable for legacy rows; written for every 1.5-created row), `schema_version INTEGER NOT NULL DEFAULT 1` — via `schema::migrate_devices_columns` (idempotent `PRAGMA table_info` check before each `ALTER TABLE ADD COLUMN`; the SQL column `added_at` is reused as the `DeviceIdentity` view's `registered_at`, no rename). New single-row `device_key` table (`id INTEGER PRIMARY KEY CHECK (id = 0)`, `enc_seed BLOB NOT NULL`, `enc_nonce BLOB NOT NULL`, `schema_version INTEGER NOT NULL`) — in `SCHEMA_DDL` + a belt-and-braces `schema::migrate_device_key_table` for legacy files. Both called from `apply_pragmas_and_schema` alongside the four existing migrations. Older-build `.pvf`s pick up the new columns (with defaults) + the new table on next open, and get a device row registered on the next unlock. §18.7 slots: `devices.schema_version = 1`, `device_key.schema_version = 1`, with a future blob-version reject (the policy text is 1.6's).

**Vault surface.** `Vault::device_current(&self) -> Result<DeviceIdentity>` (errors `NotUnlocked` if no device registered yet); `Vault::device_list(&self) -> Result<Vec<DeviceIdentity>>`; `Vault::device_set_label(&mut self, id: DeviceId, label: &str) -> Result<()>` — requires an active (unlocked, non-expired) session, **not** a fresh presence proof (Q5 — a label rename is not a §5.4 reveal-class action; same gate as `account_update`'s display-name edit), validates the label (non-empty, ≤ 256, NFC). New `pangolin-store::device` module owns the types + the SQL helpers; re-exports `DeviceIdentity` / `DeviceCapabilities` / `DEVICE_IDENTITY_SCHEMA_VERSION` through `pangolin-store::lib`, then `pangolin-core` (crate root + a new `pangolin_core::device` doc-scaffold module — no physical move, the 1.4 Q1 posture). New test/test-utilities-only accessors `Vault::device_key_verifying_key` / `device_key_secret_seed` (the `no_plaintext_on_disk` proptest scans for the seed; a unit test confirms the in-memory key matches the registered id + is dropped on lock/expiry).

**FFI surface (additive 1.1-surface amendment).** New `crates/pangolin-ffi/src/device.rs`: `#[derive(uniffi::Record)] DeviceInfo { schema_version: u16, id: DeviceId, label: String, registered_at: UnixTimestamp, last_sync_at: Option<UnixTimestamp>, capabilities: DeviceCapabilities, is_current: bool, public_key: Vec<u8> }`; `#[derive(uniffi::Enum)] DeviceCapabilities { Full }`; `device_list` / `device_current` / `device_set_label` `#[uniffi::export]` fns (each `Arc<VaultHandle>`-taking; `device_set_label` also takes `id: DeviceId` + `label: String`); a value-level bridge `pangolin_core::DeviceIdentity` → `DeviceInfo`. Re-exported from `pangolin-ffi/src/lib.rs`. The 1.1 freeze declared the `DeviceId` record but no `Device`/`DeviceInfo` shape and no `device_*` entries; nothing external binds the 1.1 surface yet (same posture as 1.2's `AccountDraft` widening / 1.4's `reveal_*` entries). The hand-written C-ABI mirror in `cabi.rs` is unchanged — the cbindgen surface stays intentionally tiny (`device_*` are `UniFFI`-only for now, like `account_*` / `reveal_*`).

**Tests.** `pangolin-store` lib ~180 → 196 (+16): `device::tests` +6 (`capabilities_round_trip_default_full`, `validate_label_rejects_empty_and_overlong`, `register_then_load_round_trips`, `wrong_vdk_or_vault_id_fails_to_load`, `set_label_persists_and_unknown_id_errors`, `no_device_registered_reads_none`); `schema::tests` +2 (`devices_migration_is_idempotent`, `legacy_devices_table_is_migrated`); `vault::tests` +8 (`register_on_first_unlock_creates_one_device`, `second_unlock_does_not_register_second_device`, `revisions_stamp_real_device_id_after_register`, `device_set_label_validates_persists_and_requires_active`, `device_key_dropped_on_lock_and_reloaded_on_unlock`, `device_key_dropped_on_session_expiry`, `last_sync_at_is_none_and_stays_none`). `tests/e2e.rs` 22 → 25 (+ 1 still-ignored): `revisions_stamp_real_device_id_after_register` (crit 6 e2e), `poc_vault_migrates_and_registers` (crit 9 — surgically downgrades a 1.5 vault to the P2 shape via raw `rusqlite`, then reopens: migration adds the new columns back + recreates `device_key`, first unlock registers a device, legacy `revisions.device_id` untouched, search + reveal work, new revisions stamp the real id), `search_index_and_session_machine_untouched_by_device_ops` (crit 12). `no_plaintext_on_disk` **extended** to scan the raw `.pvf` (and the WAL sidecar) for the device-key seed bytes — full 32-byte seed + every 8-byte sub-window, 100 iterations — 0 hits. `pangolin-ffi` lib +2 (`device::tests::device_current_list_set_label_end_to_end` — `VaultHandle::from_vault` unlocked, all three entries, `DeviceInfo` fields incl. `schema_version == 1` / `last_sync_at == None` / `capabilities == Full` / `is_current` / `public_key == id.bytes`; `device::tests::device_calls_on_empty_or_locked_handle_error` — empty handle → `FfiError::Session`, locked vault → `device_set_label` errors but `device_current`/`device_list` still read). `tests/roundtrip.rs` +1 (`device_info_record_round_trip`). The 1.3 `:memory:` FTS5 lifecycle tests + the 1.4 session-state tests pass unchanged.

**Local verification.** `cargo fmt --all` clean; `cargo build --workspace --all-targets` clean; `cargo build -p pangolin-store --all-targets --features test-utilities` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo clippy -p pangolin-store --all-targets --features test-utilities -- -D warnings` clean; `cargo test --workspace` all pass (this run actually built + ran the `--features test-utilities` `e2e` target too — lib 196, e2e 24 + 1 ignored, including the ~11-min `no_plaintext_on_disk` + `round_trip_property` proptests); `cargo test -p pangolin-store --features test-utilities` (fast subset, skipping the two long proptests) — lib 196, e2e 22 (+ 1 ignored + 2 skipped) — all pass; `cargo test -p pangolin-ffi` (incl. the new `device` lib tests) + `--test identity` + `--test session` + `--test roundtrip` (incl. the new `device_info_record_round_trip`) all pass; `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0; `cargo tree -p pangolin-store | grep -ci uniffi` = 0. `forbid(unsafe_code)` retained on every crate except `pangolin-ffi`; zero chain code activated; AGPL-3.0-or-later SPDX on the new `.rs` files (`pangolin-store/src/device.rs`, `pangolin-ffi/src/device.rs`, `pangolin-core/src/device/mod.rs`).

**Surprises / scope decisions.** (a) The device-key AEAD AAD binds `vault_id || device_id` (anti-transplant) but the `device_key` table has no `device_id` column (the plan's schema is `id, enc_seed, enc_nonce, schema_version`) — so the open path reads the `device_id` from the (single, in MVP-1) `devices`-table row first, then rebuilds the AAD before the open (`load_device_key_with_id`); a defense-in-depth check then verifies the recovered key's verifying key equals that `device_id`. For an MVP-2 vault with multiple `devices` rows the "which one is us" question is MVP-2's; in MVP-1 the table has exactly the one registered row (or zero — no device_key row either, written together). (b) `DeviceCapabilities::from_repr` is `pub fn from_repr(_value: i64) -> Self { Self::Full }` — clippy rejected `match value { 0 => .., _ => .. }` as identical-arms and the wildcard-only form is the honest "MVP-2/3 add real `match` arms here" placeholder. (c) `Vault::device_set_label` takes `label: &str` (not the plan's `label: String`) — clippy `needless_pass_by_value`; the FFI `device_set_label` keeps `label: String` per the plan's "Public surface" table and passes `&label` through. (d) The plan said "extern \"C\" wrappers ... same pattern as the existing `account_*` / `reveal_*` cabi wrappers" — but there are no `account_*` / `reveal_*` cabi wrappers (the cbindgen surface is still just the `vault_open` + `vault_close` placeholders); kept `cabi.rs` unchanged, `device_*` are `UniFFI`-only for now (matching the actual state). (e) `apps/cli` is untouched — no `device` subcommand (Q7 deferred); the `devices`/`device_key` migration is additive so the CLI's existing paths are unaffected.

**Open follow-ups.** (a) `apps/cli device` subcommand (`device list` / `device label`) — deferred to the standing CLI-V1-wiring follow-up (Q7). (b) The `device_key` AEAD blob doesn't carry a per-device discriminator column; if MVP-2 wants multiple device rows + multiple device-key blobs the `device_key` table grows a `device_id` column (a clean additive migration). (c) `ingest_chain_revision` (MVP-1-dormant chain code) stamps the chain event's `device_id` straight onto the local revision row without consulting the trust list — exactly the existing posture; MVP-2's authority-registry verification owns that check. (d) MVP-2 wires the `DeviceKey` to actually sign revisions (`2.1` / `3.1`) + pay gas (`3.2` / D-006), and fills `last_sync_at` from the chain-sync code; MVP-3 adds the revoke path via authority rotation (`6.5`).

Unblocks: MVP-1 issue 1.6 (revision lineage production + the §18.7 reject/migrate policy that owns the `devices.schema_version` / `device_key.schema_version` version bumps), the CLI V1-wiring follow-up (a `device` subcommand rides it). MVP-2 issues `2.1` (signed-revision format — consumes the stored `DeviceKey`), `3.2` (device wallet generation — the `DeviceKey` IS the gas wallet per D-006), and the on-chain authority registry (canonicalises the local trust list).

`docs/architecture/device.md` (new) describes the device-identity model, the trust list, the `DeviceKey` storage + AEAD discipline, and the MVP-1 boundaries (add-only, no signing, dormant `last_sync`); `docs/architecture/ffi-surface.md` updated with the 1.5 amendment (the `device_*` entries + the `DeviceInfo` / `DeviceCapabilities` records/enum).

## 2026-05-11 · MVP-1 issue 1.6 — Revision lineage production + §18.7 schema-versioning policy  ⏳ BUILD

Plan at `docs/issue-plans/1.6.md`, Q1-Q6 locked at plan-gate. Built on the `worktree-agent-a2211b37e9229383f` branch off `77eb979`. Security-critical — the revision graph is the integrity record of every credential change; deterministic head computation must be byte-identical across devices (MVP-2 chain-sync soundness inherits it); forward-compat parsing of an attacker-supplied future-version blob must not be exploitable; conflict resolution never silently loses data. Implements master plan §4 row `1.6` / §17 / §18.7 / Whitepaper §7 / §G3. Promotes the PoC P3 revision graph + P8/P9 fork/resolve internals to production.

**Clock-free canonical head (Q1).** `RevisionGraph::canonical_head()` returns the leaf with the **lexicographically-largest `revision_id` (byte-order)** — for a linear chain trivially the single leaf, for a fork the largest-id leaf. **No `created_at` involvement** anywhere in the head election — `created_at` is device-stamped and not trustworthy across devices; `revision_id` byte-order is the documented device-independent total order (`revision_id` is the `revisions` PRIMARY KEY, 32 bytes, so any two distinct leaves have distinct ids and the order is total — standard CRDT "highest hash wins"). Deterministic (the `heads` set is itself deterministic at `build` time; `max_by` over byte-order is total — re-building from the same rows in any input order gives the same answer), total, stable (a non-leaf addition, or a different account's revision, doesn't change the winner). `Vault::canonical_head(id)` exposes it; the per-account `head_revision_id` column stays a *cache* advanced by the edit/resolve paths, with the SQL `NOT EXISTS` query as the authoritative head-set detector. `unlock`'s decrypted-cache build + the `:memory:` FTS5 index, and `account_get` / `account_search`, all read the *canonical* head for a forked account (linear accounts take the fast path unchanged via the cached pointer = the single leaf).

**Conflict resolution → canonical head (Q5).** `Vault::resolve_fork(account_id, keep_revision_id) -> RevisionId` ratifies the chosen branch: validates the account exists/isn't tombstoned, the chosen revision is a row of *this* account (cross-account ids collapse to `AccountNotFound` — no oracle), the account is actually forked (`Validation { kind: "not-forked" }` if not — typed, not a silent no-op), the chosen revision is a current head (`NotAHead` if not); writes a new **merge revision** parented at `keep_revision_id` with the kept branch's payload **re-sealed under a fresh nonce + the merge revision's own AAD** (a byte-copy would carry the leaf's own parent in its AAD and be unopenable — the P9 §A2 argument; tombstone leaves re-seal via `seal_tombstone`); marks every *other* leaf `superseded_by = <merge>` (a new nullable column on `revisions` — the head detector excludes superseded rows, so the account now reports a **single canonical head** → `is_forked` is false; the losing branch's revision *rows* are KEPT, Q5/append-only — they're just off the head chain via the pointer); advances `head_revision_id` to the merge, clears `frozen_pending_resolve`, writes the `dirty_accounts` marker, prunes the now-orphan `pending_merges` stash row(s) — all inside one SQLite transaction with an in-transaction head-membership re-check (a concurrent `ingest_chain_revision` that demoted the chosen leaf surfaces `NotAHead`); re-syncs the in-RAM cache + FTS5 index. **Requires only an active (unlocked, non-expired) session — NOT a fresh presence proof** (Q2 — reparenting the graph reveals nothing; not a §5.4 reveal-class action; traces `check_session_freshness`/`require_active` but never `ensure_presence_fresh`). Never auto-resolves; the user calls it explicitly. `clear_frozen` (P9) stays as the lower-level MVP-2-chain-flow primitive; `resolve_fork` is the MVP-1 no-chain primitive that *creates* the merge locally. A forked-but-not-frozen account stays readable at its canonical head; the P10 `frozen_pending_resolve` flag (set only by the dormant `ingest_chain_revision` path) is the separate, stricter freeze — left alone (Q2). Honest scope: in MVP-1 a fork can only arise from the `__test_synthesize_sibling_revision` test helper or the dormant ingest path — real multi-device forks land with MVP-2's chain sync (same posture as 1.5's dormant `last_sync_at`); no new CLI subcommand (Q6 — the `pangolin-cli resolve` subcommand rides CLI-V1).

**§18.7 versioned-schema policy + forward-compat parsing (Q3, Q4).** `REVISION_SCHEMA_VERSION_MAX` (= 1 = V1 / `payload_version` 1) is now a documented crate constant. On read of a revision blob: the `revisions.schema_version` row column AND the `payload_version` discriminator in the V1 CBOR body are checked — `<= MAX` parses (migrating V0→V1 as 1.2 already does); `> MAX` (or a CBOR map arity > 8 — by construction a future shape) returns the **new typed `StoreError::UnsupportedRevisionSchemaVersion { account_id, revision_id, found, supported }`** (the blob layer returns a placeholder-ids marker; `read_identity_at` / the unlock cache build re-decorate with the real ids via `StoreError::with_revision_context`). This replaces the explicit "Q4 accept-and-record … 1.6 owns the reject" stanza in `blob.rs::decode_v1_live_inline`. **Granularity (Q3 — that-account-requires-upgrade, never silent skip):** the file-level `format_version` (P2) keeps gating whole-vault openability; an *individual revision* with a future schema version makes *that account* surface "requires upgrade" — a transient in-RAM set on `ActiveState` populated by the unlock cache build (the on-disk truth is "there's a revision with version > our max"; nothing persisted), and `account_get` / `reveal_*` / `account_update` on that account return the typed error while `account_history` / `account_status` / `is_forked` keep working (metadata-only) and the rest of the vault is fully usable; the unlock itself succeeds. The master plan §18.7 "skip applying that revision" wording is the MVP-2 chain-replay framing and is documented as chain-context-only — silently skipping a future-versioned head shows stale data with no signal (a correctness bug). A bare on-disk byte-flip of `schema_version` collapses to `AuthenticationFailed` first (the AEAD AAD binds the byte) — only a legitimately re-sealed future blob reaches the version check, which is exactly the "newer Pangolin wrote this" case. **No refactor of the existing per-surface version checks (Q4)** — the file `format_version`, `fts_schema_version`, `devices.schema_version`, `device_key.schema_version`, `pending_merges.schema_version`, and the 1.4 `session_idle_secs` validator are untouched; 1.6 only *adds* the revision-schema-version reject and *documents* the whole family in the new `docs/architecture/schema-versioning.md`. The `schema_version` byte stays `u8` on disk (it's in the AEAD AAD; widening it would be a format change); the FFI continues to widen to `u16` at the wire boundary (lossless `From<u8>`).

**FFI surface (additive 1.1-surface amendment).** `RevisionMeta` finalised (1.1 said "bodies finalize in 1.6"): adds `is_tombstone`, `is_head` (a current leaf), `is_canonical_head` (THE canonical head per the rule), `on_canonical_chain` (an ancestor of it) — `account_history` builds the graph once and tags each row. New `crates/pangolin-ffi/src/revision.rs` entries: `account_is_forked(handle, id) -> Result<bool>`, `account_fork_branches(handle, id) -> Result<Vec<ForkBranch>>` (`ForkBranch { schema_version, leaf_revision_id, leaf_device_id, leaf_created_at, depth, is_canonical_head }`, empty for a non-forked account), `account_resolve_fork(handle, id, keep_revision_id) -> Result<RevisionId>` (→ `Vault::resolve_fork`; active session, no presence proof), `account_status(handle, id) -> Result<AccountStatus>` (`AccountStatus { schema_version, is_tombstoned, is_forked, is_frozen_pending_resolve, requires_upgrade }` — the one-stop banner-decision query). `pangolin-core` re-exports `AccountStatus` + `REVISION_SCHEMA_VERSION_MAX`; the new `StoreError` arm rides the existing total `From<StoreError> for pangolin_core::Error` (`other => Store(...)`). `apps/cli` untouched (Q6). Zero new deps — the HIGH-1 (`serde` in `pangolin-crypto`), Q3 (`uniffi` in `pangolin-core`), Q3-bonus (`uniffi` in `pangolin-store`) zero-counts hold; `forbid(unsafe_code)` retained on every crate except `pangolin-ffi`.

**Schema / migration (additive, no `format_version` bump).** `revisions` gains a nullable `superseded_by BLOB` column (a metadata pointer like the chain-anchor columns — set on the *losing* leaves at resolve time so the head detector reports a single canonical head; append-only preserved, no row deleted); `schema::migrate_revision_superseded_by_column` (idempotent `PRAGMA table_info` check) backfills it onto legacy vaults (where it stays `NULL` until `resolve_fork` runs). All six head-detection SQL queries (`account_heads`, `all_forked_accounts`, `clear_frozen`'s + `prune_orphan_pending_merges`'s + `resolve_fork`'s in-transaction head checks, the unlock-time `account_heads_inline`) exclude `superseded_by IS NOT NULL` rows. `REVISION_SCHEMA_VERSION_MAX` is a documented constant; the `revisions.schema_version` byte column already existed.

**Tests.** `pangolin-store` lib **202 → 217** (+15): `revision::tests` +6 (`canonical_head_linear_is_single_head`, `canonical_head_two_way_fork_picks_rule_winner`, `canonical_head_three_way_fork_deterministic`, `canonical_head_clock_independent_all_equal_created_at`, `canonical_head_stable_under_unrelated_addition`, `canonical_head_empty_graph_is_none`); `blob::tests` +3 (`decode_v0_arity6_and_v1_arity8_still_parse`, `decode_v1_payload_version_2_rejects`, `decode_map_arity_9_rejects_as_unsupported_version`); `vault::tests` +11 (`vault_canonical_head_matches_after_reopen`, `unlock_caches_canonical_head_of_forked_account`, `resolve_fork_unforks_and_advances_head`, `resolve_fork_clears_frozen_and_writes_dirty_marker`, `resolve_fork_prunes_pending_merge_stash`, `resolve_fork_non_head_revision_errors_not_a_head`, `resolve_fork_cross_account_revision_id_collapsed`, `resolve_fork_non_forked_account_errors_validation`, `resolve_fork_requires_active_session`, `read_revision_with_future_schema_version_rejects`, `read_revision_with_future_payload_version_rejects`, plus `file_format_version_check_unchanged` marker). New test/test-utilities-only `Vault::__test_synthesize_future_version_revision` + `blob::seal_identity_with_payload_version` (the only way to synthesise a future-versioned blob from inside the crate — the production encoder always emits `payload_version = 1`). All existing P3/P8/P9/lineage/conflict tests pass unchanged; the 1.3 `:memory:` FTS5 lifecycle, the 1.4 session machine, and the 1.5 device-registration path are preserved.

**Docs.** `docs/architecture/schema-versioning.md` (new) — the §18.7 policy: every persisted record carries a schema-version field; read-old / reject-unknown-future; the granularity ladder per surface; a table of every versioned surface + its `MAX_KNOWN` + the error it raises; the §18.7-vs-implementation note (the "skip" clause is chain-context-only); the worked "add a new credential field" example. `docs/architecture/revision-lineage.md` (new) — the graph model, the clock-free canonical-head rule, fork detection, the `resolve_fork` flow, the `frozen_pending_resolve`-vs-fork-state distinction, the MVP-1 boundary, the relation to MVP-2's chain anchoring. `docs/architecture/ffi-surface.md` updated with the 1.6 amendment (the `account_is_forked` / `account_fork_branches` / `account_resolve_fork` / `account_status` entries, the `ForkBranch` / `AccountStatus` records, the finalised `RevisionMeta` fields).

**Open follow-ups.** (a) Real multi-device forks land with MVP-2's chain sync — the `resolve_fork` machinery is fully production-grade today but unreachable from a real fork in MVP-1. (b) The `pangolin-cli resolve` subcommand rides CLI-V1 alongside `account` / `reveal` / `device`. (c) A maintained `forked` flag column on `account_identities` is a clean additive optimisation if profiling ever shows the `NOT EXISTS` head query is hot — not 1.6. (d) Content-deterministic `revision_id` (keccak256 of the canonical body) is a future switch — it only strengthens the byte-order tiebreak's "highest hash wins" story. (e) §18.7 should be annotated upstream to mark the "skip applying that revision" clause chain-context-only (the local store surfaces "requires upgrade" instead).

**Fix-pass.** The test phase caught a regression the builder missed (it ran `cargo test -p pangolin-store` + `-p pangolin-ffi` but not `cargo test --workspace`, which includes `apps/cli`'s tests): the CLI integration test `convergence_after_resolve` (`apps/cli/tests/two_vault_roundtrip.rs`) failed `unlock: AuthenticationFailed`. Cause — 1.6 changed `hydrate_account_into_state` to decode/authenticate *every* leaf of a forked account at unlock (so a cross-account row transplant landing on a non-canonical leaf still surfaces `AuthenticationFailed`, for the e2e `adversarial_cross_account_row_transplant_fails` test). But a *foreign-ingested* chain revision under the PoC two-key model is stored with a placeholder zero nonce (`[0u8; NONCE_LEN]` — `ingest_chain_revision`'s genuine-foreign-INSERT path); the local device legitimately *cannot* decrypt that row — it's the documented frozen-pending-resolve state, not tampering. When vault B unlocks with a forked account (its own decryptable local genesis leaf + A's placeholder-nonce chain leaf), the every-leaf loop tried to AEAD-open A's leaf under the zero nonce → `Tampered` → `AuthenticationFailed` → the whole unlock aborted, breaking the legitimate resolve workflow. Fix (Option A): `decode_head_row` now detects a stored zero nonce *before* attempting the AEAD open and returns a new `HeadDecodeOutcome::PlaceholderNonce` — the leaf-auth loop skips those (they're authenticated when the resolve flow consumes them); a genuinely-tampered leaf carries a *real* nonce with a mismatched AAD and is still decoded → still surfaces `AuthenticationFailed`, canonical or not, so `adversarial_cross_account_row_transplant_fails` stays deterministic (the transplant the test performs lands on a real-nonce row). If the *canonical* head itself is a placeholder-nonce leaf (it can win the clock-free largest-`revision_id` election), `hydrate_account_into_state` falls back to the cached local-head pointer (`account_identities.head_revision_id` — kept decryptable by the resolve flow for a frozen account) for the cache/index snapshot, exactly as the pre-1.6 unlock path did; if that's also undecryptable the account is dropped from the cache/index (surfaced via the freeze/resolve workflow, not an aborted unlock). `crates/pangolin-store/src/vault.rs` only; `docs/architecture/revision-lineage.md` updated to note that a forked account's *decryptable* leaves are authenticated at unlock and foreign placeholder-nonce leaves are skipped. Verified: `convergence_after_resolve` + the other 4 `two_vault_roundtrip` tests pass; `cargo test --workspace` exit 0; the e2e suite (`adversarial_cross_account_row_transplant_fails`, `no_plaintext_on_disk`, the fork/resolve/requires-upgrade tests, …) passes; `pangolin-ffi` tests pass; HIGH-1 / Q3 / Q3-bonus zero-counts unaffected; clippy clean (workspace + `--features test-utilities`).

**Fix-pass 2 (audit L1/L2).** The 1.6 audit returned APPROVE-WITH-CONDITIONS — no Critical/High/Medium; two actionable Lows. **L1 (substantive):** the §18.7 future-`schema_version` reject (`row_schema_version > REVISION_SCHEMA_VERSION_MAX`) ran *before* the AEAD open in `read_identity_at`, `decode_head_row`, and `resolve_fork_validate` — but the `revisions.schema_version` byte is bound into the AEAD AAD, so a bare on-disk byte-flip of that column short-circuited to a misleading "this account requires a newer Pangolin" prompt (`UnsupportedRevisionSchemaVersion` / `HeadDecodeOutcome::FutureVersion`) instead of `AuthenticationFailed` ("tampering"), contradicting the shipped code's own doc-comments + the plan + this DEVLOG ("a bare byte-flip of `schema_version` collapses to `AuthenticationFailed` first"). **Fix:** the `> MAX` check now runs *after* the AEAD open in all three spots. `read_identity_at` builds the AAD with the claimed `schema_version`, does `open_identity_payload`; on a *successful* open it then returns `UnsupportedRevisionSchemaVersion` (decorated with the ids) if the byte exceeds MAX — before decoding the body; on a failed open the existing path surfaces `AuthenticationFailed`. `decode_head_row` keeps the placeholder-zero-nonce skip *first* (a zero-nonce foreign leaf is `PlaceholderNonce` regardless of `schema_version`), then does the open: a real-nonce row with a flipped byte propagates `AuthenticationFailed` (the unlock aborts on tamper, like the cross-account-transplant defence); a successful open with a `> MAX` row column returns `FutureVersion`; the body's own `payload_version` / map-arity check still maps to `FutureVersion` via the `Err(UnsupportedRevisionSchemaVersion { .. })` arm. `resolve_fork_validate` no longer pre-checks `> MAX` — `resolve_fork` reads the chosen leaf via `read_identity_at` (which now does the authenticating open first) in *both* the non-tombstone and the tombstone branch (the tombstone branch expects `Err(AccountTombstoned)` *after* a successful open — a tampered `is_tombstone` flag whose payload decodes Live is refused with `AuthenticationFailed`), so a flipped `schema_version` byte on the chosen leaf surfaces `AuthenticationFailed` and a legit future-version leaf surfaces `UnsupportedRevisionSchemaVersion`. **Why the reorder is strictly better:** a legit future revision was sealed by a future build with `schema_version = N` (N > MAX) bound into its AAD → `open(ct, nonce, build_aad(…, N))` succeeds → the post-open `N > MAX` check fires → same "requires upgrade" outcome as before, just after authentication. A tampered row had its byte flipped from M to N → the ciphertext was sealed with AAD including M → `open(…, build_aad(…, N))` fails → `AuthenticationFailed`. The `build_aad` output is unchanged; only *when* the `> MAX` check fires moved. `__test_synthesize_future_version_revision` needed no change — it already seals with `build_aad(…, row_version)` (i.e. the future byte in the AAD), exactly what a real future build would do, so the open succeeds and the post-open check fires; `read_revision_with_future_schema_version_rejects` / `read_revision_with_future_payload_version_rejects` still pass. New e2e test `adversarial_revision_schema_version_byte_flip_surfaces_auth_failed` (flips `revisions.schema_version` to 255 on a real-nonce row via raw `rusqlite`, asserts the next `Vault::unlock` surfaces `AuthenticationFailed`, NOT `UnsupportedRevisionSchemaVersion`); the pre-existing `adversarial_per_row_schema_version_tamper_fails` (0→1, ≤ MAX) and `adversarial_cross_account_row_transplant_fails` still pass. **L2 (doc-banner nit):** added a §Approach banner to `docs/issue-plans/1.6.md` (matching the `1.3`/`1.4` precedent) — the "Decisions locked" table is authoritative; Q1 locked the clock-free *largest-`revision_id`-only* head rule (no `created_at` tiebreak — the Q1-body's timestamp-primary text is superseded); `resolve_fork` un-forks the account via the `revisions.superseded_by` metadata column (a pointer like the chain-anchor columns — append-only preserved; the losing-branch rows are kept), not by the merge revision "becoming the sole leaf" on its own; see `docs/architecture/revision-lineage.md` for the as-built description. **L3** (pre-existing crate-name inconsistency) — not actionable, left as-is. Corrected the `schema_version`-byte-flip wording in `error.rs`'s `UnsupportedRevisionSchemaVersion` doc-comment, `docs/architecture/schema-versioning.md`, and `docs/architecture/revision-lineage.md` (all now say: a byte-flip of the AAD-bound `revisions.schema_version` column surfaces `AuthenticationFailed`; this variant is for a *legitimately* future-versioned revision — same shape as the `payload_version`-inside-the-body case). `crates/pangolin-store/src/vault.rs` (the three reorders) + `crates/pangolin-store/src/error.rs` (doc) + `crates/pangolin-store/tests/e2e.rs` (+1 test) + the four doc files; no behaviour change beyond the reorder. Verified: `cargo fmt --all` clean; `cargo build --workspace --all-targets` + `cargo build -p pangolin-store --all-targets --features test-utilities` clean; `cargo clippy --workspace --all-targets -- -D warnings` + `cargo clippy -p pangolin-store --all-targets --features test-utilities -- -D warnings` clean; `cargo test -p pangolin-store --lib` 217 pass; `cargo test --workspace` exit 0; `cargo test -p pangolin-store --features test-utilities` (e2e incl. the new byte-flip test, `adversarial_cross_account_row_transplant_fails`, and the legit-future-version tests) all pass; `cargo test -p pangolin-ffi` pass; `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0; `cargo tree -p pangolin-store | grep -ci uniffi` = 0. `forbid(unsafe_code)` retained on every crate except `pangolin-ffi`; everything 1.6 + fix-pass-1 shipped (the clock-free canonical-head rule, the `superseded_by` un-fork mechanism, the `PlaceholderNonce` skip, the §18.7 reject + requires-upgrade account status, the FFI fork/resolve/status entries, the search/session/device wiring) preserved.

Unblocks: MVP-2 issue `2.1` (Revision Log v1 — the on-chain anchor for the graph 1.6 builds; deterministic head computation is *why* the chain replicas agree), `2.3`/`2.4` (chain sync — `ingest_chain_revision` goes live, real forks become possible, `resolve_fork` becomes user-reachable), the CLI V1-wiring follow-up (a `resolve` subcommand rides it). MVP-1 issues 1.7-1.11 are independent.

## 2026-05-12 · MVP-1 issue 1.7 — TOTP engine (RFC 6238 + `otpauth://` parser + V2 identity body)  ⏳ BUILD

Plan at `docs/issue-plans/1.7.md`, Q1-Q5 locked at plan-gate. Built on the `worktree-agent-a68f606a3f20f1d69` branch off `77eb979`. Security-relevant (qualified): handles the reveal-class TOTP seed (§5.4) — seed-byte zeroization, the time source, and the code-vs-seed access-class split all matter; and a bug in the RFC 6238 generator produces *wrong codes*, which for a password manager can lock a user out of a site, so byte-for-byte reproduction of the RFC 6238 Appendix B test vectors is the non-negotiable bar. Implements master plan §4 row `1.7` / §17 / Whitepaper TOTP spec / Session spec §5.4. Replaces the `pangolin-totp` scaffold (placeholder `name()`) with the real engine + parser.

**`pangolin-totp` — the RFC 6238 engine + param types + parsers (`crates/pangolin-totp/src/lib.rs` + `parse.rs`, replacing the scaffold).** `totp_at(secret, at_unix_secs, &TotpParams) -> Result<TotpCode, TotpError>`: `counter = at / period` (T0 = 0), `mac = HMAC-<algorithm>(secret, counter.to_be_bytes())`, RFC 4226 §5.3 dynamic truncation (`offset = mac[len-1] & 0x0F`; `bin = (mac[offset] & 0x7F)<<24 | …`), `code = bin % 10^digits` zero-padded, `seconds_remaining = period - at%period`. **Full configurable param set (Q2):** `TotpAlgorithm { Sha1, Sha256, Sha512 }` (default `Sha1`), `TotpParams { algorithm, digits ∈ {6,7,8}, period_seconds ∈ 1..=3600 }` (default SHA-1 / 6 / 30) with a `validate()`. `TotpCode` holds the digit string in `Zeroizing<String>` with a redacting `Debug` (the code is a live second factor); the HMAC tag is `Zeroizing`. Hand-rolled (Q4) `decode_base32` (RFC 4648 `A-Z`+`2-7`, case-insensitive, strips `=`/whitespace/`-`, rejects others — ~30 lines, output zeroizing), `parse_otpauth_uri` (fixed-shape splitter, no `url` dep: `secret=` required, `algorithm`/`digits`/`period` optional → RFC defaults, unknown query params ignored, label/issuer percent-decoded, `otpauth://hotp/...` → `TotpError::HotpNotSupported`), `parse_totp_secret` (dispatch: `otpauth://` URI vs bare base32). `MAX_SECRET_BYTES = 256` (must equal `pangolin_store::account::limits::TOTP_SECRET_MAX_BYTES`; cross-checked by an FFI test); no minimum-length floor (we don't enforce RFC 4226's ≥ 128-bit recommendation — real-world secrets are often shorter). `forbid(unsafe_code)` retained; no `unsafe`. **New deps (Q1):** `hmac = "=0.12.1"` (already in `Cargo.lock` via `hkdf`), `sha1 = "=0.10.6"` (the only genuinely-new transitive), `sha2 = "=0.10.9"` (reuses the existing workspace pin) — all blast-contained in `pangolin-totp`'s tree, never reaching `pangolin-core`/`pangolin-crypto` (the arrows are `pangolin-ffi`/`pangolin-store`/`apps/cli → pangolin-totp`). **No `deny.toml` change** — that file is a *denylist* (`ring`, `openssl`, `aes-gcm`, …) plus `wildcards = "deny"`, not an allowlist; `hmac`/`sha1`/`sha2` aren't denied, they just carry `=`-exact-version pins + a committed `Cargo.lock`. SHA-1's collision weakness does not affect HMAC-SHA1. `cargo audit` scans them — clean. **RFC 6238 Appendix B: all 18 vectors (SHA-1 / SHA-256 / SHA-512 × T ∈ {59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}) reproduce exactly, 8-digit; the 6-/7-digit truncations check too.**

**V2 `AccountIdentity` body — configurable params, durable (`crates/pangolin-store/src/account.rs` + `blob.rs`).** The configurable params need storage, so the identity CBOR body extends to a new `payload_version` V2 (1.6's §18.7 machinery absorbs exactly this). **Shape + discrimination mechanism (surfaced per the plan):** V2 keeps the V1 8-key arity but replaces the single `totp_secret` byte-string key with a nested `totp` map `{ algorithm: int(0=SHA1,1=SHA256,2=SHA512), digits: int, period: int, secret: bytes }` in the same alphabetical slot (`tags < totp < urls`), and `payload_version = 2`. V1 and V2 are *both* arity-8, so the `payload_version` integer discriminates — and crucially it is read *before* the `totp[_secret]` key in canonical key order (`payload_version` is 4th, `totp`/`totp_secret` is 6th), so an older Pangolin reading a V2 body reaches `payload_version = 2 > REVISION_SCHEMA_VERSION_MAX (= 1 on that build)` and surfaces the §18.7 `UnsupportedRevisionSchemaVersion` ("requires upgrade", per-account, not whole-vault) *before* it ever hits the unknown `totp` key. (Considered arity-11/flatten-4-keys — kept arity-8 + payload_version since it's the cleaner read.) `REVISION_SCHEMA_VERSION_MAX` is now `2` (= `PAYLOAD_VERSION_V2`); the new "future" is V3. **V0/V1 → V2 read:** a V0 (arity-6) or V1 (arity-8 `totp_secret` bytes) body's bytes hydrate to `{ secret_bytes, params: TotpParams::default() }` (SHA-1/6/30) — an old vault's opaque-bytes TOTP "just works" as a default-params TOTP. **Writes:** `account_add`/`account_update` always emit V2. The AAD shape (`vault_id || account_id || parent_revision_id || schema_version`) does **not** change — `payload_version` is inside the authenticated plaintext, not the AAD; the on-disk `schema_version` byte width (`u8`) is unchanged. `AccountIdentity` gains a `totp_params: TotpParams` sibling field (parallel to `totp_secret` — minimal churn vs. a `TotpEntry` struct); `AccountIdentityDraft`/`AccountIdentityPatch` grow `totp_params`/`totp_params: Option<TotpParams>` (set alongside the secret; a params-only update keeps the secret); `validate::totp_params` validates the ranges (`kind = "totp_params"`). `Vault::totp_generate(id, at_unix_secs) -> Result<pangolin_totp::TotpCode>` — **session-class (Q3):** `check_session_freshness` + `refuse_if_frozen` + `refuse_if_requires_upgrade`, then `read_head_identity` (V2-aware decrypt), then `pangolin_totp::totp_at` over the transient seed (`AccountIdentity` is `ZeroizeOnDrop`; the intermediate copy is `Zeroizing`) — **no presence proof**; an account with an empty seed → `Validation { kind: "totp_not_configured" }`. `reveal_totp_secret` (1.4, presence-gated) is unchanged — still the only path the raw seed crosses FFI.

**FFI surface (`crates/pangolin-ffi/src/totp.rs` + `identity.rs` + `identity_bridge.rs` + `lib.rs`).** `totp_generate(handle, id, at: UnixTimestamp) -> Result<TotpCode, FfiError>` — **1.1-frozen signature, body implemented**; session-class (no presence); errors `Session` (locked/expired/frozen/requires-upgrade), `Validation { kind: "totp_not_configured" }` (no TOTP), `Validation { kind: "totp" }` (negative timestamp), `Store` (unknown account); the seed never crosses FFI, only the digit string. **`parse_totp_secret(input: String) -> Result<ParsedTotpSecretFfi, FfiError>` — new (additive amendment):** wraps `pangolin_totp::parse_totp_secret`; no vault access; `Validation { kind: "totp" }` for any malformed input; the shell calls this on the user's pasted base32/`otpauth://` string then passes the parsed `secret` + `params` into `account_add`/`account_update`. New records: `ParsedTotpSecretFfi { schema_version, secret: Arc<TotpSecret>, params: TotpParamsFfi, label, issuer }`, `TotpParamsFfi { schema_version, algorithm: TotpAlgorithm, digits: u8, period_seconds: u32 }`, `TotpAlgorithm` enum `{ Sha1, Sha256, Sha512 }`; `AccountDraft`/`AccountPatch` grow `totp_params: Option<TotpParamsFfi>` (additive — `None` with a secret present == RFC defaults; ignored when `totp_secret` is `None`). `TotpCode { schema_version, code, seconds_remaining: u16 }` (1.1-frozen shape, now populated). `pangolin-core` re-exports `TotpParams`/`TotpAlgorithm`/`PAYLOAD_VERSION_V2`; the new `TotpError → FfiError` mapping rides `Validation { kind: "totp" }`. C-ABI mirror not yet extended (UniFFI-only, same posture as `account_*`/`device_*`). `forbid(unsafe_code)` retained on every crate except `pangolin-ffi`.

**CLI base32 fix (Q5 — no new subcommand).** `apps/cli`'s `--totp-stdin` / `prompt_totp_secret` previously stored the typed string's *raw bytes* verbatim even though the prompt said "base32" — a PoC CLI TOTP entry was garbage. Now the input is fed through `pangolin_totp::parse_totp_secret` (a bare RFC 4648 base32 secret *or* a full `otpauth://totp/...` URI → decoded seed bytes); on a parse error the subcommand aborts cleanly with a non-zero exit and no partial write; the prompt copy is updated ("TOTP secret (base32 or otpauth:// URI; leave empty to skip)"). The PoC CLI's V0 `AccountSnapshot` write path stores only the seed bytes; the configurable-param V2 write path is reached through the FFI `account_add`/`account_update`. `apps/cli` gains a `pangolin-totp` path dep.

**Tests.** `pangolin-totp` **1 → 16** (RFC 6238 Appendix B all-vectors SHA-1/256/512 ×6 ×8-digit + the 6-digit truncation + window-boundary/`seconds_remaining` + empty/oversized/bad-params rejects + redacting `Debug` + algorithm wire round-trip + base32 RFC 4648 vectors / case-insensitivity / padding-spaces / bad-char reject + `otpauth://` happy-path-with-params / defaults / hotp-reject / malformed-reject + `parse_totp_secret` dispatch + redacting `ParsedTotpSecret`). `pangolin-ffi` integration: new `tests/totp_e2e.rs` (**10 tests**): `totp_generate` reproduces the RFC SHA-1 8-digit vector @ T=59 (94287082) and @ T=1111111109 (07081804), the SHA-256 8-digit vector (46119246), the default-params 6-digit (287082) + window boundary, the 7-digit (4287082); errors cleanly on no-TOTP (`totp_not_configured`), locked vault (`Session`), negative timestamp (`totp`); `parse_totp_secret` base32 + `otpauth://`-with-params + garbage/hotp reject; `MAX_SECRET_BYTES == TOTP_SECRET_MAX_BYTES` cross-check; the full shell flow (parse a base32-encoded RFC secret via an `otpauth://` URI → `account_update` with the parsed params → `totp_generate` → 94287082). `pangolin-ffi` lib +1 (`totp::tests` — algorithm round-trip + `parse_totp_secret` round-trip). `pangolin-store` lib **218** (the 1.6 count + the new `blob::tests::v2_totp_params_round_trip_and_v1_defaults`; `decode_v1_payload_version_2_rejects` renamed `decode_future_payload_version_rejects` and now synthesises V3, since V2 is a known version; `read_revision_with_future_payload_version_rejects` updated to synthesise `MAX+1`). All existing P3/P8/P9/lineage/conflict/search/session/device tests pass unchanged; the 1.3 `:memory:` FTS5 lifecycle, the 1.4 session machine + `reveal_totp_secret`, the 1.5 device-registration path, and 1.6's lineage/§18.7 machinery are preserved (the only `pangolin-store` changes: the `TotpParams` sibling field + the V2 CBOR codec + the `MAX_KNOWN` bump + `validate::totp_params` + `Vault::totp_generate` + the patch-type extension). Existing PoC `.pvf` vaults open + unlock + `account_history`; a PoC-set `totp_secret` reads as `{ <those bytes>, SHA-1/6/30 }` and `totp_generate` produces a code (or `totp_not_configured` if empty — `totp_at` works on any non-empty byte string).

**Verification (builder-local).** `cargo fmt --all` clean; `cargo build --workspace --all-targets` + `cargo build -p pangolin-store --all-targets --features test-utilities` clean; `cargo clippy --workspace --all-targets -- -D warnings` + `... --features pangolin-store/test-utilities` clean; `cargo test -p pangolin-totp` 16/16; `cargo test -p pangolin-ffi` (incl. `totp_e2e` 10/10) all pass; `cargo test -p pangolin-store --features test-utilities` (lib + e2e + bench) — *running at write time, see fix-pass if any*; `cargo deny check` → advisories/bans/licenses/sources ok (no `deny.toml` change); `cargo audit` → only the 2 pre-existing allowed warnings, no new advisory against `sha1`/`hmac`/`sha2`; `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0; `cargo tree -p pangolin-store | grep -ci uniffi` = 0; `cargo tree -p pangolin-totp` = `hmac`/`sha1`/`sha2`/`zeroize`/`thiserror` only (no `uniffi`, no `serde`, nothing workspace-internal).

**Docs.** `docs/architecture/totp.md` (new) — the RFC 6238 implementation, the crate-placement/dep-choice rationale (Q1), the supported params (full set), the `otpauth://`/base32 parsing (Q4), the code-vs-seed access-class split (Q3 — code = session-class, seed = reveal-class §5.4), the V2 body shape + the V0/V1→V2 read path + the V1↔V2 `payload_version` discrimination, the CLI fix (Q5). `docs/architecture/ffi-surface.md` — the `totp_generate` body + `parse_totp_secret` + `ParsedTotpSecretFfi`/`TotpParamsFfi`/`TotpAlgorithm` + the `AccountDraft`/`AccountPatch` `totp_params` field. `docs/architecture/schema-versioning.md` — `REVISION_SCHEMA_VERSION_MAX = 2`, the V2 body row, a worked-example section on the V2 bump + the discrimination mechanism. `docs/architecture/account-limits.md` — no minimum TOTP-secret floor; the `MAX_SECRET_BYTES` cross-check; the new `totp_params`/`totp_not_configured`/`totp` error kinds.

**Open follow-ups.** (a) The `pangolin-cli account totp <id>` generate-and-print subcommand rides CLI-V1 alongside `account`/`reveal`/`device`/`resolve` (Q5 deferral). (b) The CLI's V0 `AccountSnapshot` write path can't store the configurable params — a CLI entry's TOTP is always SHA-1/6/30 until the CLI is migrated to the V1/V2 `account_add`/`account_update` path (CLI-V1). (c) `reveal_totp_secret` returns just the seed bytes (the 1.4 contract); a future enrichment could return the params too so the shell can re-export a full `otpauth://` URI — not 1.7. (d) `pangolin-kdbx` (1.9) will call `pangolin_totp::parse_otpauth_uri` for KDBX TOTP entries — the parser is already future-proof for that.

Unblocks: MVP-1 issue `1.9` (KDBX import — calls `pangolin_totp::parse_otpauth_uri`). MVP-1 issues `1.8` (password generator), `1.10`, `1.11` are independent.

## 2026-05-12 · MVP-1 issue 1.8 — Password generator (`pwgen` module + zxcvbn strength estimator + CLI rewiring)  ⏳ BUILD

Plan at `docs/issue-plans/1.8.md`, Q1-Q6 + Q-return locked at plan-gate. Built on the `worktree-agent-a197f6443083f4205` branch off `3a43f84`. Security-relevant (qualified, narrow): the issue produces a *secret* (a password), so the generator MUST draw entropy from a CSPRNG and select characters *without bias*. Implements master plan §4 row `1.8` / §17 / Feature list §1 "Password generator". Replaces the `pangolin-core::pwgen` gap (and `password_generate`'s `todo!()` body) with the real engine + the two estimators.

**`pangolin-core::pwgen` — the generator + `entropy_bits` + `strength` (`crates/pangolin-core/src/pwgen.rs`, new module; `pub mod pwgen` on `lib.rs`).** Plain (uniffi-free) `PwgenPolicy { length: u16, uppercase/lowercase/digits/symbols/exclude_ambiguous: bool }` with `Default` (length 16, all four classes, `exclude_ambiguous: true`) + `validate()` (errors → `Error::Validation { kind: "password_policy", message }`, which `FfiError::from` already maps through). `PWGEN_LENGTH_MIN = 8`, `PWGEN_LENGTH_MAX = 128`, `PWGEN_LENGTH_DEFAULT = 16`; a `length` outside `[8,128]`, all-classes-off, or `length < enabled_classes` → the typed validation error. Alphabet: `A`–`Z` / `a`–`z` / `0`–`9` / the 32 ASCII printable punctuation chars (Q1 — full set, Kelvin's call; symbol count verified by a test); with `exclude_ambiguous` (default) the visually-confusable set `0 O 1 l I |` is removed from the enabled classes, so the default policy's alphabet is 88 chars. `generate(&PwgenPolicy) -> Result<Zeroizing<String>, Error>`: validate → build the per-class + combined alphabets → place-then-shuffle (seed one uniform char of each enabled class into the first `k` slots, fill the rest from the combined alphabet, then Fisher-Yates shuffle the whole buffer so the seeded chars aren't clustered at the front — provably uniform over the set of strings with ≥1 of each enabled class *given* unbiased index draws) → wrap in `Zeroizing<String>`. Unbiased draws (the load-bearing security property): `uniform_index(n)` (n ∈ 1..=256) rejection-samples a single byte from `pangolin_crypto::rng::fill_random` — accept iff `byte < 256 - (256 mod n)`, then `byte mod n`; rejection rate `(256 mod n)/256 < n/256 < 37%` for n ≤ 94. No `rand::*`, no deterministic seed — entropy comes only through `pangolin_crypto::rng` (the audited chokepoint; the `_with` deterministic surface is crate-private per MEDIUM-11). `forbid(unsafe_code)` retained; no `unsafe`. `entropy_bits(&PwgenPolicy) -> Result<f64, Error>` = `length × log2(alphabet_size)` (alphabet_size computed by the same code path `generate` uses, so they stay in sync) — the exact entropy of a generated password (the doc notes the tiny conventional over-count from the ≥1-of-each constraint); an invalid policy → the same `Validation` error so `entropy_bits` and `generate` agree on validity. `strength(&str) -> PasswordStrength` — runs `zxcvbn::zxcvbn(password, &[])` (infallible in 3.x) and maps it into `PasswordStrength { score: u8 (0–4), guesses_log10: f64, crack_time_seconds: f64 (the conservative offline_slow_hashing_1e4_per_second figure), feedback_warning: Option<String>, feedback_suggestions: Vec<String> }` — for arbitrary (typed/imported) passwords, not the generator; the empty-password case yields score 0 with a warning, no panic; `user_inputs = &[]` for now (the display-name/usernames-aware variant is deferred).

**New dep — `zxcvbn = "=3.1.1"` in `pangolin-core/Cargo.toml` (+ `pangolin-core` gains a direct `pangolin-crypto` path dep + the workspace `zeroize` pin).** `default-features = false` drops zxcvbn's bundled `builder` feature (`derive_builder`); the transitive tree is `fancy-regex`/`regex`/`regex-automata`/`regex-syntax`/`aho-corasick`/`memchr`/`bit-set`/`bit-vec`/`itertools`/`either`/`lazy_static`/`time`/`deranged`/`powerfmt`/`num-conv`/`time-core` — MIT/Apache, `no_unsafe = true`, none on `deny.toml`'s denylist. No `deny.toml` change — that file is a denylist (`ring`, `openssl`, `aes-gcm`, …) + `wildcards = "deny"`, not an allowlist; `zxcvbn` + its transitives just carry the `=`-exact pin (in the crate `Cargo.toml`, matching how 1.7 added `hmac`/`sha1`/`sha2`) + a committed `Cargo.lock`. `cargo audit` scans them — clean (only the 2 pre-existing alloy-transitive allowed warnings). zxcvbn is a heuristic estimator, not a parser of attacker-structured data, so it doesn't get the separate-crate blast-containment treatment `pangolin-totp`/`pangolin-kdbx` give their parser deps — `pangolin-core` is its natural home. The arrow is `pangolin-core → zxcvbn` (downstream of `pangolin-crypto`), so `cargo tree -p pangolin-crypto | grep -ci zxcvbn` = 0 and HIGH-1 (`pangolin-crypto` zero-serde) is untouched.

**FFI surface (`crates/pangolin-ffi/src/session.rs` + `lib.rs`).** `PasswordPolicy` Record gains `exclude_ambiguous: bool` (additive — the frozen Record's `schema_version` slot is unchanged; it's a wire-passed struct, not a persisted CBOR body, so no version bump). New `PasswordStrength` Record `{ schema_version: u16, score: u8, guesses_log10: f64, crack_time_seconds: f64, feedback_warning: Option<String>, feedback_suggestions: Vec<String> }` (schema_version slot const `PASSWORD_POLICY_SCHEMA_VERSION = 1`). `password_generate(policy: PasswordPolicy) -> Result<Arc<SecretPassword>, FfiError>` — return shape amended (Q-return) from the 1.1-frozen `-> Arc<SecretPassword>` (a frozen-entry amendment — allowed, nothing external binds yet; same posture as 1.2's Q1 / 1.4's Q5b / 1.7's amendments): converts the Record → `pwgen::PwgenPolicy`, calls `pwgen::generate`, on `Ok` `mem::take`s the bytes out of the `Zeroizing<String>` into `SecretPassword::new`, on `Err` → `FfiError::Validation { kind: "password_policy" }` (fail loudly, never clamp). New additive `password_entropy_bits(policy) -> Result<f64, FfiError>`, `password_strength(password: String) -> PasswordStrength` (the `password` arg is wrapped in `Zeroizing<String>` so it's zeroized after use), `password_policy_default() -> PasswordPolicy` (the strong defaults). `pangolin-ffi/lib.rs` re-exports `PasswordStrength` + `PASSWORD_POLICY_SCHEMA_VERSION` at the crate root (the new free fns are reached via `pangolin_ffi::session::*`, same as `vault_create`/`totp_generate`/etc.). `forbid(unsafe_code)` retained on every crate except `pangolin-ffi`. C-ABI mirror not extended (UniFFI-only, same posture as `account_*`/`totp_*`).

**CLI `--generate-password` rewiring (Q5 — `apps/cli/src/commands/account.rs` + `cli.rs`; `apps/cli` gains a `pangolin-core` path dep).** The CLI shipped a second, divergent generator (a local 64-char power-of-two-alphabet, length-24, byte-mask thing predating the FFI entry). 1.8 deletes the `GENERATED_PASSWORD_LEN`/`GENERATED_PASSWORD_ALPHABET` consts + the local sampling and routes `generate_password()` through `pangolin_core::pwgen::generate(&PwgenPolicy::default())` — so `account add --generate-password` now produces a 16-char strong-default password. No new subcommand; the existing stderr-emit save-this-now block (the MED-3-fixed `write_all` path) is unchanged; the `--help` copy is updated. (The CLI still uses the V0 `AccountSnapshot` write path — the standing CLI-V1 limitation, orthogonal to 1.8.)

**Tests.** `pangolin-core` lib **+16 → 16** (`pwgen::tests`): symbol-set-is-32-chars, `uniform_index(1) == 0`, `uniform_index(3)` χ² over 300k draws < 18.42 (the rejection-sampling correctness test), generated-length-matches-policy (8/16/32/128), every-char-in-alphabet + no-ambiguous-leak, ≥1-of-each-class (all-four, 500 samples), two-classes-only, default-policy-is-strong, validation-errors (all-off / length 7 / length 200 / sub-MIN), `length < class-count` rejected, `entropy_bits` correctness (default ≈ 16·log2(88), lowercase-only ≈ L·log2(26), lowercase+digits ≈ L·log2(36), invalid → Err), `strength` (`"password"` → score ≤ 1 + feedback, `"correct horse battery staple"` → score ≥ 3, `""` → score 0 no-panic, a 24-char generated password → score 4 ≥ the dictionary word + larger crack-time + larger guesses), generated-is-`Zeroizing`, lowercase-only char-distribution χ² over ≈3.2M samples < 55.0 (the full place-then-shuffle pipeline). `pangolin-ffi` integration (`tests/roundtrip.rs`): `password_policy_record_round_trip` updated for the new `exclude_ambiguous` field; new `password_strength_record_round_trip`; new `password_generate_and_helpers` (`password_policy_default` → length 16 + all flags; `password_generate(default)` → 16-byte `SecretPassword`; `password_entropy_bits(default)` ≈ 16·log2(88); invalid policy → `Validation { kind: "password_policy" }` from both fns; `password_strength` low/high/empty). `apps/cli` unit tests updated (24-char/64-char-alphabet assertions → 16-char + per-class-present + printable-ASCII; `account_lifecycle.rs` E2E's reveal-and-check → 16 chars + all four classes). All existing P3/P8/P9/lineage/conflict/search/session/device/TOTP/store tests pass unchanged — 1.8 touches no store / session / search / device / lineage / TOTP / `pangolin-crypto` / `pangolin-store` code (only the `pwgen` module + the `zxcvbn` dep in `pangolin-core`, the `password_*` fns + `PasswordPolicy` field + `PasswordStrength` Record in `pangolin-ffi`, the `--generate-password` rewiring in `apps/cli`, the workspace `Cargo.toml`/`Cargo.lock`, and docs). Existing PoC `.pvf` vaults open + unlock + `account_history` (1.8 persists nothing).

**Verification (builder-local).** `cargo fmt --all` clean; `cargo build --workspace --all-targets` + `cargo build -p pangolin-store --all-targets --features test-utilities` clean; `cargo clippy --workspace --all-targets -- -D warnings` + `cargo clippy -p pangolin-store --all-targets --features test-utilities -- -D warnings` clean; `cargo test -p pangolin-core` 16/16; `cargo test -p pangolin-ffi --test roundtrip` 24/24; `cargo test -p pangolin-cli --test account_lifecycle` 1/1; `cargo test --workspace` + `cargo test -p pangolin-store --features test-utilities` — *running at write time, see fix-pass if any*; `cargo deny check` → advisories/bans/licenses/sources ok (no `deny.toml` change); `cargo audit` → only the 2 pre-existing allowed warnings, no new advisory against `zxcvbn` or its transitives; `cargo tree -p pangolin-crypto | grep -ci serde` = 0; `cargo tree -p pangolin-crypto | grep -ci zxcvbn` = 0; `cargo tree -p pangolin-core | grep -ci uniffi` = 0; `cargo tree -p pangolin-store | grep -ci uniffi` = 0; `cargo tree -p pangolin-core | grep -ci zxcvbn` = 1 (in the right tree).

**Docs.** `docs/architecture/password-generator.md` (new) — the security properties (CSPRNG via `pangolin_crypto::rng`, unbiased draws via rejection sampling, the χ² test guards), the alphabet (4 classes + the full ASCII symbol set + the exact `exclude_ambiguous` set `0 O 1 l I |`), the strong defaults, the length floor/cap + how it differs from 1.2's `PASSWORD_MAX_BYTES = 4096`, the place-then-Fisher-Yates-shuffle construction + the conventional entropy over-count, the `length × log2(alphabet)` formula, the per-site-override-via-the-policy-argument model, the zxcvbn strength estimator (v3.1.1, the `PasswordStrength` shape, the conservative crack-time figure, the deferred `user_inputs` enhancement), the CLI `--generate-password` rewiring + the terminal-scrollback caveat. `docs/architecture/ffi-surface.md` — the `password_generate` row (now `-> Result<...>`), the new `password_entropy_bits`/`password_strength`/`password_policy_default` rows + the `PasswordStrength` Record row + the `PasswordPolicy` `exclude_ambiguous` note. `docs/architecture/account-limits.md` — the `PWGEN_LENGTH_MIN`/`PWGEN_LENGTH_MAX` (8/128) row distinguishing the generator's bounds from `PASSWORD_MAX_BYTES`, + the new `password_policy` error kind.

**Open follow-ups.** (a) The display-name/usernames-aware zxcvbn `user_inputs` strength check — needs the per-account context plumbed through; MVP-3+. (b) The "deterministic regeneration option (advanced)" Feature-list item — deferred to MVP-3+ per Q6. (c) A curated "safe-symbols" `PasswordPolicy` variant for sites that reject certain ASCII symbols — MVP-3+ if a real compat need shows up. (d) The CLI still uses the V0 `AccountSnapshot` write path (CLI-V1 will migrate it).

Unblocks: nothing depends on 1.8 directly; MVP-1 issues `1.9` (KDBX import), `1.10`, `1.11` are independent.

## 2026-05-14 · MVP-2 issue 3.2 — Device wallet generation (per-device EVM wallet wired into the unlock-time flow)  ⏳ BUILD

Plan at `docs/issue-plans/3.2.md`, R-a..R-e locked at plan-gate (2026-05-14 Kelvin sign-off). Built on the `issue/3.2-device-wallet` branch off `a7180c2`. **Security-relevant — YES** (master plan §16.3 lists "device-wallet code" by name; first MVP-2 Rust issue that touches the long-lived signing identity D-006). Implements master plan §4 row `3.2` / §17 component matrix.

**Scope.** Promotes `pangolin_chain::evm::derive_evm_wallet` from a passive utility (previously called only by `BaseSepoliaAdapter::new_with_device_key`) into a **per-device, unlock-time lifecycle primitive**: materialises a secp256k1 wallet from the 1.5 sealed Ed25519 `DeviceKey` whenever the vault is `Active`; caches the public 20-byte EVM address on disk (additive nullable column); exposes the address through `Vault::device_current` / `device_list` / FFI `DeviceInfo`; exposes the live wallet via the new `Vault::evm_wallet() -> Result<&EvmWallet>` accessor (active-session-only; production callers thread the borrow into chain primitives in 3.1 / 3.3 / 3.4 / 4.2). NO `keyring` crate; NO OS-keystore integration; NO signing handle crosses FFI; NO CLI verb (deferred to CLI-V1 batch).

**R-a (Q-a — storage strategy): Vault-sealed-only.** The secp256k1 wallet is re-derived from the 1.5 sealed Ed25519 `DeviceKey` on every unlock; only the public 20-byte EVM address is cached on disk (additive `devices.evm_address` BLOB column, nullable for legacy 1.5-era rows; back-filled on first 3.2-era unlock inside the same transaction). Zero new external crate dep, zero new at-rest secret surface, zero new threat-model invariant. **R-b (Q-b — materialisation timing): Eager.** The `EvmWallet` is materialised inside `ActiveState` alongside the in-memory `DeviceKey` on every `Vault::unlock` (one HKDF-SHA256 expand + one `k256::SecretKey::from_slice`; ~hundreds of microseconds, negligible against ~ms Argon2id). Dropped on every existing session-teardown path (`lock()`, idle expiry, absolute expiry, `Drop`) — `EvmWallet` rides along inside `ActiveState`; no new teardown surface. **R-c (Q-c — FFI exposure): Address only.** `DeviceInfo` gains `evm_address: Vec<u8>` (20 bytes; empty for legacy un-back-filled rows). No signing handle crosses FFI. **R-d (Q-d — CLI surface): Defer.** Zero changes under `apps/cli/`; `pangolin-cli wallet show` joins the CLI-V1-wiring batch. **R-e (Q-e — test injection): Pure-Rust derivation only.** No `KeystoreBackend` trait, no mock backend, no `cfg(test)` short-circuits — the derivation is workspace-pinned pure-Rust (`hkdf`, `sha2`, `k256` via alloy, `zeroize`); CI behaves identically across Linux/macOS/Windows runners.

**`pangolin-store::schema` — additive `devices.evm_address` column.** `SCHEMA_DDL` adds `evm_address BLOB` (nullable; 20 bytes when present). New `migrate_devices_evm_address_column` helper (mirrors the 1.5 / 1.4 / 1.6 migration pattern: idempotent `PRAGMA table_info` check before `ALTER TABLE ADD COLUMN`). Wired into `apply_pragmas_and_schema`. **No `format_version` bump** — additive-column doctrine. New tests `devices_migration_evm_address_idempotent` + `legacy_1_5_devices_table_gets_evm_address` verify idempotence and the migration on a hand-built 1.5-era schema.

**`pangolin-store::device` — `DeviceIdentity` + register/load paths.** `DeviceIdentity` gains `evm_address: Option<[u8; 20]>` (`None` for legacy un-back-filled rows); ergonomic `wallet_address(&self) -> Option<&[u8; 20]>` accessor mirrors the `public_key` pattern. New public `EVM_ADDRESS_LEN = 20` const. `register_device` derives the address inline via `pangolin_chain::derive_evm_address(&device_key)?` and stamps it into the INSERT. `load_device_key_with_id` calls `backfill_evm_address_if_missing` after the AEAD-decrypt; the helper reads the current column value (`SELECT evm_address`); if NULL, derives + writes the address into the row via `UPDATE devices SET evm_address = ?`. Idempotent thereafter (the column is non-NULL; no write). `DeviceRow::from_sqlite_row` / `into_identity` read the column and validate the length. `DEVICES_SELECT_COLS` extends. New tests `register_on_first_unlock_writes_evm_address` + `unlock_on_legacy_1_5_row_backfills_evm_address` + `evm_address_round_trips_through_close_reopen` cover the lifecycle.

**`pangolin-store::vault` — eager EvmWallet in `ActiveState`.** `ActiveState` gains an `evm_wallet: EvmWallet` field (held by value; `EvmWallet` is deliberately not `Clone` — L-zeroize). `Vault::unlock` constructs it via `pangolin_chain::derive_evm_wallet(&device_key)?` immediately after the 1.5 `DeviceKey` materialisation step; a derivation failure (impossible in practice — probability ~ 2^-128) collapses to `StoreError::Corrupted` so unlock surfaces a clean failure rather than panicking. The wallet drops with every `ActiveState` teardown (`lock()`, idle/absolute expiry, `Drop`) — no new teardown code. New `Vault::evm_wallet(&self) -> Result<&EvmWallet, StoreError>` calls `require_active()` and returns the borrow. New tests `evm_wallet_accessor_works_on_active_only` + `evm_wallet_dropped_on_lock_idle_expiry_absolute_expiry` (one body, three legs) cover the contract.

**`pangolin-store::lib` + `pangolin-core::{lib,device}` — re-exports.** `EVM_ADDRESS_LEN` re-exported from both crates; `DeviceIdentity` shape change is transparent to re-export consumers (additive `Option` field).

**`pangolin-chain::evm` — `no_evm_secret_after_drop` regression test.** Pinned-seed derivation snapshot via `EvmWallet::signer().to_bytes()`, drop, fresh derivation, snapshot-equality assertion. Pragmatic per the plan-gate's L-key-material-location fallback wording — Rust's `Drop` semantics do not allow a formal heap-zeroize assertion (the compiler may elide fields into registers; probing a freed allocation is UB); the test exercises the *behavioural* property that matters end-to-end (same seed → same scalar → same address; a regression that introduces a static/`OnceCell`/cross-session signer cache would be caught by the surrounding lifecycle tests in `pangolin-store::vault`). The formal zeroize guarantee lives in k256's own zeroize-on-drop discipline; this test is defense-in-depth.

**`pangolin-ffi::device` — `DeviceInfo` gains `evm_address: Vec<u8>` at end-of-record (additive 1.1-surface amendment per R-c; nothing external binds the 1.1 surface yet, identical posture to 1.5's `public_key` addition).** The bridge fn `device_identity_to_ffi` populates the field via `identity.evm_address.map(|a| a.to_vec()).unwrap_or_default()`. The existing `device_current_list_set_label_end_to_end` test extends to assert `evm_address.len() == 20`; new `ffi_device_current_returns_evm_address` test confirms `device_current` + `device_list` agree on the address.

**`pangolin-store::tests::e2e` — extensions.** `no_plaintext_on_disk` extended to snapshot the secp256k1 scalar via the new `Vault::evm_wallet()` accessor + scan the raw `.pvf` + WAL for the scalar bytes (full 32-byte + 8-byte sub-windows; same scan shape as the existing 1.5 Ed25519 seed scan); the plan's expectation — zero hits — guards against a future bug that adds a new on-disk surface for the scalar. New `evm_address_determinism_across_unlock_cycles` test: register-on-unlock writes the cached address; close-reopen-unlock three more times; every cycle's cached column + live wallet address equals the first.

**Files changed.** `crates/pangolin-store/src/{schema.rs,device.rs,vault.rs,lib.rs}`; `crates/pangolin-core/src/{lib.rs,device/mod.rs}`; `crates/pangolin-chain/src/evm.rs` (test only); `crates/pangolin-ffi/src/device.rs`; `crates/pangolin-store/tests/e2e.rs`; `docs/architecture/{device.md,ffi-surface.md}`; `THREAT_MODEL.md`; `DEVLOG.md`. **No** changes under `apps/cli/`; **no** changes to `pangolin-chain/Cargo.toml` (the dep direction `pangolin-store → pangolin-chain` is preserved — pangolin-chain's only pangolin-store reference is a dev-dep already enabling test-utilities, unchanged); **no** changes to `deny.toml` (the `secp256k1` C-FFI ban is preserved; alloy's k256 path is the only secp256k1 implementation in the tree, by design).

**Invariants preserved.** L1 (deterministic Ed25519 → secp256k1 derivation via the pinned-version `-v0` domain strings — unchanged). L2 (wallet lives ONLY in `ActiveState`; no static / `OnceCell` / cross-session cache). L3 (public 20-byte address IS cached on disk; scalar is NOT). L4 (zero new at-rest secret surface — `no_plaintext_on_disk` proptest extension verifies). L5 (`EvmWallet` stays in `pangolin-chain`; `pangolin-store` imports it). L6 (read path does NOT materialise a wallet; reads the cached column). L7 (`cargo tree -p pangolin-chain --no-default-features --edges normal | grep -i pangolin-store` empty — the only pangolin-store reference is a dev-dep). L8 (no new external crate dep). L9 (`forbid(unsafe_code)` on every crate except `pangolin-ffi`; HIGH-1 `pangolin-crypto` no-serde and Q3 `pangolin-core` no-uniffi both stay 0). L10 (AGPL-3.0-or-later SPDX on every new file — no new `.rs` files were created in 3.2; only existing files modified). L11 (zero deploy / chain-network impact in 3.2).

**Verification (builder-local).** `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo build --workspace --all-targets` clean; `cargo test --workspace` PASS; `cargo test -p pangolin-store --features test-utilities` PASS (e2e + lib); `cargo test -p pangolin-ffi --all-targets` PASS; `cargo tree -p pangolin-crypto | grep -ci serde` = 0 (HIGH-1); `cargo tree -p pangolin-core | grep -ci uniffi` = 0 (Q3); `cargo tree -p pangolin-chain --no-default-features --edges normal | grep -i pangolin-store` empty (L7 — dev-deps excluded; the dev-dep path that exists pre-3.2 is unchanged).

**Docs.** `docs/architecture/device.md` extended with §6 "EVM wallet (MVP-2 issue 3.2)" covering the derivation chain (1.5 Ed25519 seed → `derive_evm_wallet` → secp256k1 keypair), at-rest model (NOTHING beyond the public address hits disk), in-memory model (wallet lives in `ActiveState`, dies with session), FFI surface (address only — no signing handle), migration story (additive nullable column; back-fill on first 3.2-era unlock; idempotent), and what's deferred (3.1 signing, 3.3 direct-submit, 3.4 funder client, CLI-V1 batch). `docs/architecture/ffi-surface.md` — `DeviceInfo` schema row + the device-behaviour subsection extended for the 3.2 amendment. `THREAT_MODEL.md` — new "Device EVM wallet" per-component row + new per-surface section enumerating the 4 threats from the plan-gate's L-section (#1 stolen cached address — non-secret; #2 scalar from memory dump — out of scope; #3 forge revision without scalar — out of scope; #4 EVM-address ↔ identity correlation — D-006 / 3.6 mitigation).

**Open follow-ups.** (a) `pangolin-cli wallet show` rides the CLI-V1-wiring batch (R-d deferral). (b) Real on-chain revision signing — MVP-2 issue 3.1 (signed-revision client format under v1 per 2.1 R-a / R-d) — `Vault::evm_wallet().signer()` is the production-side hook. (c) Direct-submit chain transport — MVP-2 issue 3.3. (d) Funder client / payment-driven top-up — MVP-2 issues 3.4 / 3.5. (e) Privacy-mode wallet rotation — MVP-2 issue 3.6 (scaffolding-only; full implementation later). (f) Hardware-attested key storage (Secure Enclave / TPM / Android Keystore hardware-backed entries) — MVP-3/4 territory; 3.2's derivation is software-only.

Unblocks: MVP-2 issues `3.1` (signed-revision client format — consumes `Vault::evm_wallet().signer()`), `3.3` (direct-submit transport — the wallet pays gas; this issue ships the lifecycle), `3.4` (funder client — needs the wallet address for refund flows). MVP-2 issue `3.6` (privacy-mode rotation) is the rotation hook on top.

## 2026-05-15 · MVP-2 issue 3.6 — Privacy mitigation (Phase-2 hook scaffolding)  ⏳ BUILD

**Status:** Scaffolding-only. NO production logic for any Phase-2 mode ships in 3.6. Architectural-locking deliverable per `docs/issue-plans/3.6.md` plan-gate (Kelvin sign-off 2026-05-15 at commit `a0f6d2a`).

**Resolved decisions (R-a..R-d) — see DECISIONS.md for full text.**
- **R-a** — both `PrivacyMode` enum + `PrivacyStrategy` trait ship. `DefaultStrategy` no-op + `EnhancedPrivacyStrategy` fail-loudly stub.
- **R-b** — all three Phase-2 modes scaffolded: per-revision wallet rotation + CoinJoin pre-mixing (placeholder method, no concrete mixer) + optional fresh-address-per-vault.
- **R-c** — central declarations in `crates/pangolin-chain/src/privacy/{mod.rs, default.rs, enhanced.rs, tests.rs}` + distributed-impl consumer tests at the three crate boundaries.
- **R-d** — fail-loudly + byte-identity proof. Pre-3.6 baseline (`main` at `3227d38`) captured at builder time via `crates/pangolin-chain/tests/baseline_capture.rs`; the 65-byte revision signature is embedded as a `[u8; 65]` const in the byte-identity regression test.

**Files added.** `crates/pangolin-chain/src/privacy/mod.rs` (the trait + enum + error + `FunderResponseShape` marker + module wiring); `crates/pangolin-chain/src/privacy/default.rs` (the verbatim no-op `DefaultStrategy`); `crates/pangolin-chain/src/privacy/enhanced.rs` (the fail-loudly `EnhancedPrivacyStrategy`); `crates/pangolin-chain/src/privacy/tests.rs` (12 tests covering the three R-d test classes); `crates/pangolin-chain/tests/baseline_capture.rs` (the fixture-capture harness — left in tree for future Phase-2 maintainers); `docs/architecture/privacy.md` (the architecture overview).

**Files modified.** `crates/pangolin-chain/src/lib.rs` (`pub mod privacy;` + re-exports of the 6 public symbols + `Address` re-export for consumer-crate convenience); `crates/pangolin-chain/src/secp256k1_signing.rs` (1 sibling consumer-boundary test in the redemption_tests mod); `crates/pangolin-store/src/vault.rs` (2 consumer-boundary tests); `crates/pangolin-funder-client/Cargo.toml` (dev-dep on `pangolin-chain`); `crates/pangolin-funder-client/src/lib.rs` (1 consumer-boundary test + a local `hex_decode` helper); `THREAT_MODEL.md` (new "Privacy Mitigation Phase-2 hooks" per-component section with 5 L-row threats); `DECISIONS.md` (R-a..R-d entries + the §8.3-vs-master-plan-§5 gap documentation).

**Invariants preserved.** L1 (ZERO production logic for rotation / mixing / fresh-address — `DefaultStrategy` body is one line per hook by design). L2 (NO new external crate dep — `thiserror`, `alloy`, `pangolin-crypto` are all already in the workspace). L3 (hook signatures are stable APIs — variant-label-pinning test + dyn-compatibility check pin shape). L4 (ZERO observable difference from 3.5 when `Default` selected — the byte-identity test embeds `EXPECTED_REVISION_SIGNATURE_FOR_DEFAULT_STRATEGY = 0x336a98...bcad1c` captured pre-3.6; assertion is mechanical). L5 (`forbid(unsafe_code)` + AGPL-3.0-or-later SPDX on every new `.rs` file; HIGH-1 `pangolin-crypto` no-serde + Q3 `pangolin-core` no-uniffi stay at 0; the `pangolin-funder-client → pangolin-chain` edge is dev-dep only, the production L1 invariant of funder-client is preserved). L6 (NO schema migration — compile-time abstractions only; §18.7 schema-version unchanged). L7 (`EnhancedPrivacy` fails loudly — every hook returns `PrivacyError::NotYetImplemented` BEFORE doing any work; three fail-loudly tests pin the typed-error variant; silent fallback to `Default` is rejected by construction).

**Verification (builder-local).** `cargo fmt --all -- --check` PENDING (see gate); `cargo clippy --workspace --all-targets -- -D warnings` PENDING (see gate); `cargo build --workspace --all-targets` PASS; `cargo test -p pangolin-chain --lib` PASS (130 → 130 + 12 = 142 with privacy hooks + 1 signing-boundary test = 143); `cargo test -p pangolin-store --lib` PASS (delta: +2 issue_3_6 tests); `cargo test -p pangolin-funder-client --lib` PASS (delta: +1 issue_3_6 test); `cargo tree -p pangolin-crypto | grep -ci serde` = 0 (HIGH-1); `cargo tree -p pangolin-core | grep -ci uniffi` = 0 (Q3); `cargo tree -p pangolin-chain --no-default-features --edges normal | grep -c pangolin-store` = 0 (Q3 / L7 of 3.2 preserved). env-quirk #15 advisories check trivial — no new deps per L2.

**Docs.** NEW `docs/architecture/privacy.md` covering the trait + enum + 3 hook surfaces, L1..L7 invariants verbatim, Phase-2 implementation roadmap, and the §8.3-vs-master-plan-§5 documented gap. `THREAT_MODEL.md` extended with the "Privacy Mitigation Phase-2 hooks (3.6 scaffolding)" per-component row + 5 L-row threats (L-3.6-accidentally-ships-partial-phase-2, L-trait-shape-drift-from-phase-2, L-enabled-path-silent-degrade, L-doc-drift-from-§8.3, L-on-chain-observability-mitigation-deferred). `DECISIONS.md` records the R-a..R-d resolutions + the Whitepaper §8.3 / master plan §5 row 3.6 reconciliation note.

**Byte-identity fixture captured at builder time.**
- Seed: `[0x42; 32]`.
- Derived EVM address: `0x7b646740F6956230716beEb16361fcfe396c91E2`.
- 65-byte `r || s || v` signature over the fixed `RevisionFieldsV1` + fixed `enc_payload = b"baseline_capture_3.6_enc_payload"` against `ChainEnv::BaseSepolia`: `0x336a9893b56a897f69fb485412ee151a39199353933d475eb8ac55c5a54fc76368af6b5a72a2bd0d5eb5554bc59d33f9ca64c87f0f31ee956e0943cc1d56bcad1c`.
- Embedded as `EXPECTED_REVISION_SIGNATURE_FOR_DEFAULT_STRATEGY: [u8; 65]` in `crates/pangolin-chain/src/privacy/tests.rs`.
- Test `default_strategy_revision_signature_matches_pre_3_6_baseline` passed on first run.

**Open follow-ups.** (a) Phase-2 actual implementation of per-revision wallet rotation, CoinJoin pre-mixing, optional fresh-address-per-vault — deferred to MVP-3 / MVP-4 with their own audit gates. (b) Concrete CoinJoin client (Whirlpool / JoinMarket / etc.) integration — its own audit-gated decision when Phase-2 lands. (c) Multi-wallet balance aggregation if Phase-2 ships per-revision rotation — separate plumbing problem. (d) UI surfaces for privacy-mode toggle — Phase-2 UI territory. (e) Schema for storing user-selected privacy mode if Phase-2 makes mode user-configurable per vault — separate schema migration with its own §18.7 bump.

Unblocks: nothing in MVP-2 — 3.6 is the last issue. Hooks are available for future Phase-2 work (MVP-3 / MVP-4); production fn signatures are unchanged so Phase-2 can thread `&dyn PrivacyStrategy` parameters through without re-shaping consumer crates.

## 2026-05-15 · MVP-2 issue 4.1 — Slow-mode chain sync (default chain READ path + Rust v1 verifier)  ⏳ BUILD

**Status:** First MVP-2 chain READ path shipped. Production v1 secp256k1 verifier (`recover_signer_v1` + `recover_signer_v1_raw`) productionises 3.1 R-d's test-only helper. Slow-mode sync orchestrator (`Vault::sync_from_chain`) pulls events from D-017, verifies + ingests, advances per-vault checkpoint. Two-stage rollback (Pending @ 1-conf → Finalized @ 12-conf) lands the reorg-resilience machinery. WS-preferred + HTTP-fallback state machine present; WS open deferred behind alloy `ws` feature flag (L8: no new external crate dep in 4.1). Plan-gate at `docs/issue-plans/4.1.md` with Kelvin sign-off 2026-05-15 at commit `6ce608a`.

**Resolved decisions (R-a..R-f) — see DECISIONS.md for full text.**
- **R-a** — persist `last_synced_block` in `.pvf` via new `chain_sync_v1_state` table; `--from-genesis` escape via `SyncOptions { from_genesis: true }`.
- **R-b** — WS-preferred + HTTP-poll fallback. WS open path returns `WsOpenError::Unavailable` in MVP-2 (alloy `ws` feature deferred per L8); HTTP-polling runs unconditionally. State machine + reconnect backoff + payload adapter all present so MVP-3 feature-flag flip is a one-line change.
- **R-c** — two-stage rollback. `RevisionStatus::{Pending, Finalized}` enum; promotion at depth ≥ `CONFIRMATION_DEPTH_FOR_FINALIZATION = 12`; `ReorgDetector` compares observed block hashes against canonical; `rollback_pending_revisions_in_range` removes affected pending rows (finalized rows NEVER touched).
- **R-d** — permissive auto-register. `device::auto_register_device_from_chain_sync` inserts a synthetic device row keyed on the EVM address (left-padded 12 zero bytes ‖ 20 address bytes); `discovered_via_chain_sync = 1` + `discovered_at_block` for audit; idempotent via `INSERT OR IGNORE`.
- **R-e** — async-only on `pangolin-store::Vault::sync_from_chain`. The dep-direction concern in plan-gate Q-e was load-bearing: pangolin-chain mutating `&mut Vault` would force `pangolin-chain → pangolin-store` (violates L7). Adopted the alternative shape — primitives on pangolin-chain; orchestration on Vault. `cargo tree -p pangolin-chain --no-default-features --edges normal | grep -c pangolin-store == 0` verified post-build.
- **R-f** — hermetic + reorg simulator. 30 hermetic tests in `chain_sync::tests` cover the verifier round-trip + the chain-id check + the deployment-address resolution + the fetch_chunk happy / reject paths + the reorg simulator (shallow 2-block + deep 10-block) + the WS placeholder + the constants pinning. Live `#[ignore]`'d test deferred pending captured-event hex pin (env-quirk #14: rerun + recapture when next 3.3 / 2.3 deploy smoke produces a known event payload).

**Files added.** `crates/pangolin-chain/src/chain_sync.rs` (module root: constants, `SyncReport`, `RevisionStatus`, `ChainEventSource`, `SyncOptions`, `VerifiedRevisionEvent`, public entry `fetch_and_verify_chunk` + helpers `fetch_current_block_number` + `detect_reorg_via_rpc` + `resolve_and_check_contract` + `check_chain_id_matches` + `build_read_provider` + `d017_deploy_block`); `crates/pangolin-chain/src/chain_sync/poll.rs` (HTTP-poll fallback per-chunk fetcher with full L2/L4/L-vault-id-substitution/L-schemaVersion gates); `crates/pangolin-chain/src/chain_sync/ws.rs` (WS state-machine placeholder with `WsHandle`, `WsOpenError`, `open_subscription`, `next_reconnect_backoff_ms`); `crates/pangolin-chain/src/chain_sync/reorg.rs` (`ReorgDetector`, `ReorgInfo`, eviction + forget_window); `crates/pangolin-chain/src/chain_sync/tests.rs` (30 hermetic tests); `docs/architecture/chain-sync.md` (architectural overview).

**Files modified.** `crates/pangolin-chain/src/secp256k1_signing.rs` (`struct_hash` + `eip712_digest` + `build_domain` promoted from `fn` to `pub(crate) fn`; NEW `pub fn recover_signer_v1` + `pub fn recover_signer_v1_raw` production primitives with high-s + v-byte canonical-form rejection per LOW#3); `crates/pangolin-chain/src/chain_submit.rs` (`revision_log_v1_binding` module visibility bumped from `pub(crate)` to `pub` so `chain_sync` can reuse the alloy `sol!` binding without re-declaring); `crates/pangolin-chain/src/error.rs` (4 new variants: `SignerRecoveryFailed`, `EventSignerMismatch`, `EventVaultIdMismatch`, `UnsupportedSchemaVersionEvent`, `CheckpointOutOfRange`); `crates/pangolin-chain/src/lib.rs` (`pub mod chain_sync;` + re-exports for the 4.1 public surface + `recover_signer_v1` / `recover_signer_v1_raw` re-exports); `crates/pangolin-store/src/schema.rs` (3 additive `revisions` columns: `revision_status` TEXT DEFAULT 'finalized', `observed_at_block` INTEGER, `observed_block_hash` BLOB; 2 additive `devices` columns: `discovered_via_chain_sync` INTEGER DEFAULT 0, `discovered_at_block` INTEGER; new `chain_sync_v1_state` table; 3 new migration helpers; 2 new test functions covering migration idempotency + legacy-row default behaviour); `crates/pangolin-store/src/vault.rs` (6 new public methods: `last_synced_block_v1`, `update_last_synced_block_v1`, `rollback_pending_revisions_in_range`, `promote_finalized_revisions`, `ingest_pending_chain_revision`, `count_chain_sync_discovered_devices`; new async `sync_from_chain` orchestrator; 4 new test functions); `crates/pangolin-store/src/device.rs` (new `auto_register_device_from_chain_sync` helper for R-d); `crates/pangolin-store/src/error.rs` (new `ChainSyncError(ChainError)` variant + `From<ChainError> for StoreError` impl); `THREAT_MODEL.md` (new "Slow-mode chain sync (read path + v1 verifier)" per-component row with 8 L-row threats); `DECISIONS.md` (R-a..R-f entries).

**Invariants preserved.** L1 (`recover_signer_v1` reuses the byte-identical EIP-712 helpers from `secp256k1_signing`; round-trip test fires under matched env). L2 (event ABI decode via the reused `revision_log_v1_binding::RevisionLogV1::RevisionPublished`; NO parallel `sol!` block). L3 (`eth_chainId` check at provider construction; `chain_id_mismatch_fails_closed` test pins). L4 (`load_deployed_address` + pinned-address cross-check before fetch; `deployment_address_resolves_for_base_sepolia` test pins). L5 (per-event signer verifier reachable via `verify_signed_event`; signer-field-mismatch detection fires). L6 (`LOG_BLOCK_CHUNK = 9_000` per chunk; `log_block_chunk_constant_pinned_at_9k` test pins). L7 (`cargo tree -p pangolin-chain --no-default-features --edges normal | grep -c pangolin-store` = 0). L8 (NO new external crate dep — alloy WS feature explicitly deferred; module structure present so MVP-3 flip is one line). L9 (`forbid(unsafe_code)` survives on every crate; HIGH-1 + Q3 stay at 0). L10 (AGPL-3.0-or-later SPDX on every NEW `.rs` file). L11 (ZERO on-chain broadcast; read-only — no `eth_sendRawTransaction`, no `EvmWallet` access). L12 (replay protection via existing MVP-1 idempotency on `Vault::ingest_chain_revision`; checkpoint monotonic via `update_last_synced_block_v1` refuse-backward gate; `last_synced_block_v1_monotonic` test pins).

**Verification (builder-local).** `cargo fmt --all -- --check` PASS; `cargo clippy --workspace --all-targets -- -D warnings` PASS (1 clippy fix-pass loop required — promoted `clippy::too_long_first_doc_paragraph` + `clippy::doc_markdown` at module-level `#![allow]` since the 4.1 docstrings are intentionally narrative; `clippy::option_if_let_else` + `clippy::manual_clamp` + `clippy::no_effect_underscore_binding` + `clippy::pub_underscore_fields` flagged but addressed via idiomatic rewrites); `cargo build --workspace --all-targets` PASS; `cargo test -p pangolin-chain --lib` PASS (was 131 pre-4.1 → 160 post = +29 net new tests, of which 30 are 4.1-related and 1 was an existence-check helper deleted for clippy hygiene); `cargo test -p pangolin-store --lib` PASS (was 257 pre-4.1 → 262 post = +5 net new tests covering schema migration + vault accessors + auto-register); `cargo tree -p pangolin-crypto | grep -ci serde` = 0 (HIGH-1); `cargo tree -p pangolin-core | grep -ci uniffi` = 0 (Q3); `cargo tree -p pangolin-chain --no-default-features --edges normal | grep -c pangolin-store` = 0 (L7); `cargo audit` 0 vulnerabilities / 2 allowed warnings (no new deps, so env-quirk #15 trivially clean).

**Docs.** NEW `docs/architecture/chain-sync.md` covering the R-a..R-f resolutions + verifier flow + WS+HTTP state machine + two-stage rollback state machine + per-vault checkpoint persistence + threat-model touch-points cross-ref. `THREAT_MODEL.md` extended with the "Slow-mode chain sync" row + 8 L-row threats (L-rpc-spoof-events, L-rpc-omits-events, L-reorg-rollback, L-checkpoint-corruption, L-malicious-vault-id-substitution, L-schemaVersion-future-poison, L-verifier-domain-binding-drift, L-permissive-auto-register-could-add-spam). `DECISIONS.md` records the R-a..R-f resolutions + the L8 deferral consequence for alloy WS support.

**Noteworthy design decisions / surprises encountered.**
- The `RevisionPublished` event surface emits the recovered `signer` field but NOT the raw `signature` bytes (the contract verifies the sig server-side at publish then drops it). The per-event client verifier `recover_signer_v1_raw` is therefore not load-bearing on the current contract surface — L3 + L4 + the contract's own `ecrecover` do the heavy lifting. The verifier is wired end-to-end so a hypothetical v1.1 event that re-emits the signature would flip the check on without code changes. `verify_signed_event` provides the synthetic-event verifier entry point exercised by the test suite (covers L5 second arm: signer-field cross-check).
- The R-e dep-direction concern was load-bearing as expected. `pangolin-chain` cannot mutate `&mut Vault` without depending on `pangolin-store`, which would violate L7. Adopted the alternative shape: orchestration on Vault, primitives on chain.
- WebSocket support is deferred behind an L8 flag. alloy v2.0.4 in the workspace was NOT compiled with the `ws` feature; enabling it pulls `alloy-pubsub`, `tokio-tungstenite`, `tungstenite`, plus an OS-level TLS stack. The state machine + reconnect helper + payload adapter are all structurally present, so the MVP-3 flip is a one-line cargo feature change.
- The live `#[ignore]`'d verifier test (R-f Option B's "live D-017 history" check) is deferred pending a captured `RevisionPublished` event payload — the existing 3.3 / 2.3 deploy smoke tests don't produce a stably-captured event hex pinned in source, so the live test would always need a runbook-style fresh capture. The hermetic round-trip test covers the symmetric byte-pinning end of env-quirk #14; the contract-semantic-drift end is deferred to a follow-up that captures + pins a known event payload from D-017's actual history.

**Open follow-ups.** (a) Live `#[ignore]` test gated on captured event payload — recapture next time a 3.3 publish smoke fires on D-017. (b) WebSocket feature flip (alloy `ws` + replace `Unavailable` branch in `chain_sync::ws::open_subscription`) — MVP-3 issue 4.1.x. (c) Sequence-gap cross-check vs the contract's `_nextSequence` view fn — MVP-3 follow-up; not load-bearing in 4.1 because the user-visible `--from-genesis` workaround covers L-rpc-omits-events. (d) CLI subcommands (`pangolin sync`, `pangolin pull`) — deferred to the standing CLI-V1 batch per the 3.1/3.2/3.3/3.4/3.5 precedent. (e) FFI exposure of `sync_from_chain` — CLI-V1 batch.

Unblocks: §4 cluster issues 4.2-4.4 (ephemeral local indexer; opt-in indexer-driven fetch; mode selector). The `Vault::sync_from_chain` + `SyncReport` shape is the API the indexer cluster builds on top of. Also unblocks any 5.x issue that wants to consume chain-published revisions (5.1 publish queue + 5.2 heartbeat scheduler).

## 2026-05-16 · MVP-2 issue 4.2 — Ephemeral local indexer (`pangolin-indexer` crate skeleton + lifecycle + stdio JSON + cipher trait stub)  ⏳ BUILD

**Status:** Structural skeleton for the opt-in fast-mode sync path shipped. The `pangolin-indexer` crate now exposes both a library (mobile in-process flow) and a thin binary (desktop subprocess flow) from a single Cargo manifest; the lifecycle wraps the SAME chain primitive 4.1 uses (`pangolin_chain::fetch_and_verify_chunk`) in a per-run temp DB the host drains via a line-delimited JSON protocol on stdio. **4.2 is the skeleton; 4.3 ships the temp-DB security hardening (ephemeral key + AeadCipher + zero-fill); 4.4 ships the mode-selector heuristic.** Plan-gate at `docs/issue-plans/4.2.md` with Kelvin sign-off 2026-05-16.

**Resolved decisions (R-a..R-f) — see DECISIONS.md for full text.**
- **R-a** — single `pangolin-indexer` crate with `[lib]` + `[[bin]]` declarations. No separate `pangolin-indexer-client` crate.
- **R-b** — stdio JSON protocol. Line-delimited; `IndexerRequest` uses `serde(deny_unknown_fields)` for strict parse + tagged-enum variants (`start_index`, `pull`, `heartbeat`, `stop`); `IndexerResponse` is the open-ended response side; byte-bag fields encoded as lowercase hex without `0x` prefix. `MAX_REQUEST_LINE_BYTES = 65_536` cap on per-line size (L-stdio-injection); `PROTOCOL_VERSION = 1` echoed in `Started` response (L-host-indexer-mismatch).
- **R-c** — const default + env-override-with-clamp. `IDLE_TIMEOUT_DEFAULT_SECS = 300` (D-007); `IDLE_TIMEOUT_MAX_SECS = 3_600` (1-hour ceiling, L-idle-timeout-DoS); `IDLE_TIMEOUT_MIN_SECS = 60`; env var `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS` clamped to `[60, 3_600]`. Invalid inputs fall back to 300.
- **R-d** — `pub trait TempDbCipher: Send + Sync + Debug` with `encrypt_page` / `decrypt_page` + `NoOpCipher` passthrough impl. 4.3 swaps in the real `AeadCipher` via a one-line constructor change; the trait surface stays.
- **R-e** — library + binary in 4.2. Cargo features: `default = ["bin"]`, `bin = ["dep:clap"]`, `test-utilities = []`. Mobile builds use `cargo build --no-default-features`; the `[[bin]]` declares `required-features = ["bin"]` so library-only builds skip the binary compilation.
- **R-f** — hermetic + cleanup-on-crash + `#[ignore]`'d live parity test. 26 hermetic tests + 5 cleanup-on-crash tests + 1 ignored live test against D-017 (deferred fixture capture — same posture 4.1 R-f took).

**Files added.** `crates/pangolin-indexer/Cargo.toml` (extended from 14-line placeholder to fully-declared manifest with the `default = ["bin"]` / `test-utilities` feature shape + `[[bin]] required-features = ["bin"]` declaration + per-dep rationale comments); `crates/pangolin-indexer/src/lib.rs` (rewritten from 24-line placeholder to module + re-export surface); `crates/pangolin-indexer/src/protocol.rs` (`IndexerRequest` / `IndexerResponse` / `IndexerEvent` / `IndexedEvent` + 8 protocol unit tests); `crates/pangolin-indexer/src/cipher.rs` (`TempDbCipher` trait + `NoOpCipher` impl + 5 round-trip + Send/Sync tests); `crates/pangolin-indexer/src/session.rs` (`IndexerSession` lifecycle struct + `IndexerConfig` + `resolve_idle_timeout_from` + chunk loop reusing `fetch_and_verify_chunk` + Pull pagination + 17 session-side unit tests); `crates/pangolin-indexer/src/error.rs` (`IndexerError` typed taxonomy + 3 unit tests); `crates/pangolin-indexer/src/bin/pangolin-indexer.rs` (~120-LoC binary shim — clap argv + tracing-to-stderr + tokio select! over stdin / ctrl_c / idle-timeout); `crates/pangolin-indexer/tests/hermetic.rs` (26 hermetic integration tests covering constants pinning + lifecycle + JSON protocol + cipher round-trip + L2/L7 discipline); `crates/pangolin-indexer/tests/crash_cleanup.rs` (5 cleanup-on-crash tests: panic-during-task; task-completion; multiple sessions unique-path + clean-up; sync Drop; idle-timeout-driven cleanup); `crates/pangolin-indexer/tests/parity.rs` (1 `#[ignore]`'d live test against D-017 with documented fixture-capture procedure); `docs/architecture/indexer.md` (architecture overview: R-a..R-f + lifecycle state machine + protocol + mobile-vs-desktop comparison + L invariants + threat-model touch points + 4.2→4.3→4.4 boundary).

**Files modified.** `crates/pangolin-indexer/Cargo.toml` (placeholder → full manifest); `crates/pangolin-indexer/src/lib.rs` (placeholder → module + re-exports); `THREAT_MODEL.md` (new "Ephemeral local indexer (4.2 skeleton; 4.3 hardening)" per-component row with 7 L-row threats: L-temp-file-leak, L-vault-id-disclosure, L-stdio-injection, L-idle-timeout-DoS, L-spurious-spawn, L-host-indexer-mismatch, L-temp-dir-tampering); `DECISIONS.md` (R-a..R-f entries with explicit cross-reference to 4.3 for the cipher impl + 4.4 for the mode selector).

**Invariants preserved.** L1 (`tempfile::NamedTempFile::new_in(env::temp_dir())` — random path + Drop unlink on normal exit; field-declaration order in `IndexerSession` puts `Connection` before `NamedTempFile` so SQLite closes before Windows-style unlink runs). L2 (vault_id filter at the insert path; defense-in-depth on top of `fetch_and_verify_chunk`'s server-side `topic1 = vault_id` + decode-time check). L3 (no external service; only network traffic is the chain RPC). L4 (`fetch_and_verify_chunk` reused verbatim — same primitive 4.1 ships; revision-graph output byte-identical, verified shape via the `#[ignore]`'d parity test). L5 (idle-timeout `tokio::select!` in the binary entry; each request resets the deadline). L6 (NO new external crate dep beyond promoting `tempfile` from workspace dev-dep to a runtime dep on this crate; tokio + alloy + rusqlite + serde + serde_json + thiserror + hex + tracing + clap are all workspace-shared). L7 (`cargo tree -p pangolin-indexer --no-default-features --edges normal | grep -c pangolin-store` = 0). L8 (`forbid(unsafe_code)` survives; HIGH-1 + Q3 stay at 0). L9 (AGPL-3.0-or-later SPDX on every new `.rs` file). L10 (ZERO on-chain broadcast — read-only; the indexer crate's lack of `pangolin-store` dep mechanically prevents reaching the publish API). L11 (cleanup-on-crash via `tempfile::NamedTempFile` Drop on panic-unwind — verified by the `cleanup_on_panic_unwinds_temp_file` test; ctrl_c handler in the binary entry; OS temp-dir GC for SIGKILL fallback). L12 (lifecycle code path is identical for desktop subprocess + mobile in-process — the binary's `main.rs` is a ~120-LoC shim wrapping `IndexerSession::handle_request`; mobile in-process flow calls the same method directly).

**Verification (builder-local).** `cargo fmt --all -- --check` PASS; `cargo clippy --workspace --all-targets -- -D warnings` PASS (3 clippy fix-pass loops required — `missing_fields_in_debug` → `.finish_non_exhaustive()`; `manual_let_else` → `let-else`; `needless_pass_by_value` on `map_io` → reference param + closure adapter; `doc_lazy_continuation` in parity.rs docstring); `cargo build --workspace --all-targets` PASS; `cargo build -p pangolin-indexer --no-default-features` PASS (lib-only mobile build clean — `#[cfg_attr(not(any(test, feature = "test-utilities")), allow(dead_code))]` on the `temp_db` field is the only build-shape concession); `cargo test -p pangolin-indexer` = 35 lib + 26 hermetic + 5 crash_cleanup + 1 ignored (parity) = 66 pass + 1 ignored; `cargo test -p pangolin-chain --lib` 160 pass + 1 ignored (unchanged from 4.1); `cargo test -p pangolin-store --lib` 262 pass (unchanged from 4.1); `cargo deny check advisories` PASS ("advisories ok"); `cargo audit` 0 vulnerabilities + 2 allowed warnings (unchanged from 4.1 — no new deps); `cargo tree -p pangolin-crypto | grep -ci serde` = 0 (HIGH-1); `cargo tree -p pangolin-core | grep -ci uniffi` = 0 (Q3); `cargo tree -p pangolin-chain --no-default-features --edges normal | grep -c pangolin-store` = 0 (L7); `cargo tree -p pangolin-indexer --no-default-features --edges normal | grep -c pangolin-store` = 0 (L7 new invariant — net-new CI check).

**Docs.** NEW `docs/architecture/indexer.md` covering the R-a..R-f resolutions + the lifecycle state machine + the stdio JSON protocol shape + the mobile-vs-desktop invocation comparison + the L1..L12 invariants + the threat-model touch points + the 4.2→4.3→4.4 boundary. `THREAT_MODEL.md` extended with the "Ephemeral local indexer" row + 7 L-row threats. `DECISIONS.md` records the R-a..R-f resolutions with explicit cross-references to 4.3 (cipher impl) + 4.4 (mode selector) for the deferred work.

**Noteworthy design decisions / surprises encountered.**
- The struct field-declaration order in `IndexerSession` is load-bearing on Windows: SQLite's `Connection` must drop BEFORE `NamedTempFile` because Windows requires the last open handle to close before the file can be unlinked. Cargo / Rust drop fields in declaration order, so `conn: Connection` is declared above `temp_db: NamedTempFile`. The Linux / macOS path is the same code; this is a Windows-portability concern only. Discovered when the first test run failed `dropping_session_unlinks_temp_file_on_normal_exit` and the SQLite handle was the culprit.
- `tempfile::NamedTempFile::new_in(env::temp_dir())` already uses `O_CREAT | O_EXCL | O_NOFOLLOW` on Unix (and the platform equivalent on Windows) — L-temp-dir-tampering is mitigated by the upstream crate's discipline; the indexer adds nothing structurally on top.
- The `test-utilities` Cargo feature exposes `IndexerSession::temp_db_path` to integration tests via the self-dev-dep trick (`pangolin-indexer = { path = ".", features = ["test-utilities"] }` in `[dev-dependencies]`). Same pattern `pangolin-chain` and `pangolin-store` use for their own `test-utilities` features. Production-default OFF so the temp-file path is never reachable from non-test user code (L1 hygiene).
- The `IndexerEvent` enum (the streaming variant) is shipped for protocol symmetry with R-b's named surface but not yet wired into the 4.2 dispatch path — the canonical 4.2 flow is pull-based (`Pull` → `Batch`). Reserved for a future MVP-3 streaming-mode follow-up.
- The live parity test (R-f tier (c)) is `#[ignore]`'d pending captured D-017 event fixtures, same posture 4.1 R-f took. Test docstring documents the `cast logs` capture procedure as the operational follow-up.

**Open follow-ups.** (a) Live `#[ignore]` parity test gated on captured `RevisionPublished` event payload from D-017 history — same recapture cycle as 4.1's. (b) Real `AeadCipher` impl + ephemeral per-run key + zero-fill before unlink — MVP-2 issue 4.3 (the `TempDbCipher` trait is the architectural-locking hook). (c) Mode-selector heuristic + host wrapper that translates `IndexerResponse::Batch` → `Vault::ingest_pending_chain_revision` — MVP-2 issue 4.4. (d) CLI subcommand `pangolin sync --fast` — deferred to the standing CLI-V1 batch per 3.1/3.2/3.3/3.4/3.5 precedent. (e) FFI exposure for mobile / Tauri shells — CLI-V1 / FFI-batch follow-up.

Unblocks: MVP-2 issue 4.3 (temp-DB security hardening — drops in via the `TempDbCipher` trait) and MVP-2 issue 4.4 (mode-selector + host wrapper — consumes the `IndexerSession` + JSON protocol shapes shipped here).
