# P1 fix-pass — `pangolin-crypto` audit closure

> **Status:** all actionable HIGH / MEDIUM / LOW / INFO findings from the
> post-build audit are closed on `issue/P1-crypto`. This file is appended
> per the fix-pass process; the original `P1.md` plan body is unchanged.

## Findings closed (in commit order)

| Finding | Severity | Commit | Where it lands |
|---|---|---|---|
| HIGH-4 | HIGH | `13c1834` | drop unused `secrecy` from workspace + crate `Cargo.toml` |
| LOW-13 | LOW | `13c1834` | unconditional `#![forbid(unsafe_code)]` in `lib.rs` |
| INFO-16 | INFO | `13c1834` | refresh stale `assert_not_impl_all!` comments |
| HIGH-1 | HIGH | `591a901` | ban `serde` + `serde_derive` in `deny.toml` `[bans] deny` (Option A) |
| HIGH-2 | HIGH | `591a901` | `Nonce::from_bytes` → `pub(crate)` in production builds; `pub` only behind `test-vectors` feature, which the crate's own integration tests enable via dev-dep self-reference |
| HIGH-3 | HIGH | `623ae2d` | new `WrapContext { vault_id, schema_version }` threaded through `wrap`/`unwrap_with`/`rewrap` and stored on `WrappedVdk`; encoded form `WRAP_AAD_DOMAIN \|\| vault_id \|\| schema_version` is the AEAD AAD (Option A) |
| MEDIUM-9 | MEDIUM | `623ae2d` | `WrappedVdk::rewrap` now takes `&self` |
| MEDIUM-10 | MEDIUM | `623ae2d` | **skipped** — HIGH-3 closed via Option A (AAD binding); folding `vault_id` into the HKDF salt would be redundant and is documented inline in `WrappedVdk::seal_under` |
| MEDIUM-5 | MEDIUM | `8d852b6` | `KdfParams::OUTPUT_LEN` const + lockstep test against `KEY_LEN` |
| MEDIUM-6 | MEDIUM | `8d852b6` | raise `MIN_TIME_COST` to 3 (RFC 9106 §4.4 first recommended); barely-above / barely-below tests + `slow-tests`-gated end-to-end derive at the floor |
| MEDIUM-7 | MEDIUM | `8d852b6` | explicit `out.zeroize()` after `AeadKey::from_bytes` in `derive_key`; regression-marker test |
| MEDIUM-8 | MEDIUM | `9787ea0` | new `secret::BoxedSecret<N>` heap-allocated zero-on-drop newtype; `AeadKey` now stores its key in `BoxedSecret<KEY_LEN>` (`SigningKey`-backed types remain dalek-managed per the audit's caveat) |
| MEDIUM-11 | MEDIUM | `9787ea0` | every `*::generate_with` constructor and `Nonce::random_with` is `pub(crate)`; `RngCore` re-export is `pub(crate)`; `OsRng`/`CryptoRng` remain `pub` |
| LOW-12 | LOW | `9787ea0` | `AeadKey::open` collapses ALL upstream causes (incl. `InvalidKey` branch) to `Tampered`; doc updated |
| LOW-14 | LOW | `9787ea0` | `secret_bytes_drop_does_not_panic_under_unwind` → `secret_bytes_drop_runs_during_unwind` + atomic-recording `DropCounter` harness |
| LOW-15 | LOW | `9787ea0` | `AeadKey::open` short-circuits on `len < TAG_LEN` with `Tampered`; new unit test |

INFO-17/18/19 are non-actionable observations and were skipped per the
audit instruction.

## Test-coverage gaps closed

| Gap | Closing test(s) |
|---|---|
| Wrong-size VDK plaintext / truncated wrap ciphertext | `keys::tests::vdk_tampered_ciphertext_fails` exercises the wrap-AEAD path; `aead::tests::open_rejects_buffer_shorter_than_tag` exercises the AEAD-layer guard |
| Proptest for VDK wrap/unwrap (≥1000 cases) | `keys::tests::vdk_wrap_unwrap_proptest` (1024 cases) |
| Proptest for empty plaintext + empty AAD | `aead::tests::empty_plaintext_empty_aad_round_trip` |
| `KdfParams::validate` boundary at `time_cost = MIN_TIME_COST` | `kdf::tests::barely_above_time_cost_floor_validates` and `kdf::tests::barely_below_time_cost_floor_is_rejected` |
| Cross-vault VDK replay (HIGH severity) | `keys::tests::vdk_cross_vault_replay_fails`, `keys::tests::vdk_schema_version_mismatch_fails`, `keys::tests::vdk_same_vault_correct_context_unwraps`, plus public-surface counterpart `vdk_cross_vault_replay_via_public_surface_is_rejected` |
| `derive_key` zeroizes intermediate `out` | `kdf::tests::derive_key_zeroizes_intermediate_buffer_regression_marker` (best-effort, documented as such) |

## API surface diff

Removed (from `pub` → `pub(crate)`):

- `aead::Nonce::from_bytes` (now feature-gated `pub` under `test-vectors`)
- `aead::AeadKey::generate_with`
- `aead::Nonce::random_with`
- `sign::SigningKey::generate_with`
- `keys::VdkKey::generate_with`
- `keys::VdkKey::wrap_with` (removed entirely — was unused)
- `keys::AuthorityKey::generate_with`
- `keys::DeviceKey::generate_with`
- `rng::RngCore` re-export

Added:

- `keys::WrapContext { vault_id: [u8; 32], schema_version: u8 }`
- `keys::VAULT_ID_LEN: usize = 32`
- `kdf::KdfParams::OUTPUT_LEN: u32 = 32` (`#[doc(hidden)]`)
- `keys::WrappedVdk::context() -> &WrapContext`
- `secret::BoxedSecret<const N: usize>` (`new`, `as_array`, `as_slice`,
  `Zeroize`, `Drop`, `Debug`)

Signature-changed (API-breaking but acceptable per spec — no external
consumers exist yet):

- `VdkKey::wrap(&self, &AuthorityKey)` → `VdkKey::wrap(&self,
  &AuthorityKey, &WrapContext)`
- `WrappedVdk::rewrap(self, ...)` → `WrappedVdk::rewrap(&self,
  &AuthorityKey, &AuthorityKey, &WrapContext)`

## Cargo features added

- `test-vectors` — widens `aead::Nonce::from_bytes` to `pub` so the
  crate's own RFC KAT integration tests in `tests/test_vectors.rs` can
  reach it. Production downstream crates MUST NOT enable this feature;
  the dev-dep self-reference enables it only for the integration-test
  compile target.

## Deviations / skipped items

- MEDIUM-10 (HKDF salt = None): **skipped** by design. HIGH-3 closed
  the cross-vault replay attack via AAD binding (Option A); folding
  `vault_id` into the HKDF salt would be redundant. Rationale recorded
  in `WrappedVdk::seal_under`.
- INFO-17/18/19: non-actionable observations per the audit, skipped.

## Verification snapshot

- `cargo test --workspace --all-targets`: **79 passed; 0 failed**
  (61 unit + 4 unit-in-other-crates + 14 integration in
  `pangolin-crypto`, plus the workspace's other crates' tests — see
  per-package counts in the commit description).
- `cargo test --features slow-tests --workspace --lib`:
  **67 passed; 0 failed** (adds the two `slow-tests`-gated KDF derives).
- `cargo fmt --all --check`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean (no
  new `allow` attributes added at the lint level — the only
  `#[allow(...)]` is the local one inside `KdfParams::OUTPUT_LEN` to
  document the `usize`-to-`u32` const cast that is pinned by a runtime
  test).
- `cargo audit`: 0 vulnerabilities.
- `cargo deny check`: `advisories ok, bans ok, licenses ok, sources ok`
  (warnings about unused license allowances are expected — the dropped
  `secrecy` and the absence of any `Zlib` / `Unicode-DFS-2016` / etc.
  licensed crates in the current dep tree).
