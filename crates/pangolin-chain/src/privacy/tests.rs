// SPDX-License-Identifier: AGPL-3.0-or-later
//! Privacy hook tests (MVP-2 issue 3.6, R-d test classes).
//!
//! Three test classes per R-d:
//!
//! 1. **Compile-time trait shape.** Assert
//!    `DefaultStrategy: Send + Sync` and
//!    `EnhancedPrivacyStrategy: Send + Sync` (via `assert_send_sync`).
//!    Assert the trait is dyn-compatible via `Box<dyn PrivacyStrategy>`.
//! 2. **Byte-identity vs the 3.5 baseline.** The
//!    [`EXPECTED_REVISION_SIGNATURE_FOR_DEFAULT_STRATEGY`] constant is
//!    captured from the pre-3.6 `main` baseline (`3227d38`) at builder
//!    time via the `crates/pangolin-chain/tests/baseline_capture.rs`
//!    harness; the regression test re-runs the equivalent path through
//!    [`DefaultStrategy`] and asserts byte-equality. A drift here means
//!    [`DefaultStrategy`] is no longer a verbatim no-op — fires loudly
//!    in CI. The other two hooks (`transform_funder_response` /
//!    `select_address_for_vault`) are trivial identity functions; the
//!    byte-identity property is structurally enforced (pass-through
//!    by construction) and pinned via direct equality.
//! 3. **Fail-loudly.** Three tests, one per
//!    [`EnhancedPrivacyStrategy`] hook, asserting the typed
//!    [`PrivacyError::NotYetImplemented`] variant fires with the
//!    expected `mode` + `hook` fields.

use super::{
    DefaultStrategy, EnhancedPrivacyStrategy, FunderResponseShape, PrivacyError, PrivacyMode,
    PrivacyStrategy,
};
use alloy::primitives::{address, b256, hex, keccak256, Address, U256};

use crate::evm::derive_evm_wallet;
use crate::secp256k1_signing::{build_signed_revision_v1, RevisionFieldsV1};
use crate::ChainEnv;
use pangolin_crypto::keys::DeviceKey;

// =====================================================================
// R-d test class (a): compile-time trait shape.
// =====================================================================

/// Compile-time `Send + Sync` assertion. Used by the
/// [`default_strategy_is_send_sync`] +
/// [`enhanced_strategy_is_send_sync`] tests below.
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn default_strategy_is_send_sync() {
    assert_send_sync::<DefaultStrategy>();
}

#[test]
fn enhanced_strategy_is_send_sync() {
    assert_send_sync::<EnhancedPrivacyStrategy>();
}

#[test]
fn boxed_dyn_privacy_strategy_is_send_sync() {
    // The `dyn PrivacyStrategy` shape is the one Phase-2 will pass
    // around at hook callsites. Asserting `Box<dyn PrivacyStrategy +
    // Send + Sync>` is `Send + Sync` pins both that the trait is dyn-
    // compatible (no `Self`-returning methods, no generic methods) AND
    // that the supertrait bounds carry through erasure.
    assert_send_sync::<Box<dyn PrivacyStrategy + Send + Sync>>();
}

#[test]
fn privacy_mode_variant_labels_pinned() {
    // Variant LABEL stability (L3): renaming any variant breaks
    // Phase-2 work. The `Debug` impl reflects the variant name; a
    // rename would change the string.
    assert_eq!(format!("{:?}", PrivacyMode::Default), "Default");
    assert_eq!(
        format!("{:?}", PrivacyMode::EnhancedPrivacy),
        "EnhancedPrivacy"
    );
}

// =====================================================================
// R-d test class (b): byte-identity vs the 3.5 baseline.
// =====================================================================

/// The fixed seed used to derive the test wallet. Identical to the seed
/// in `crates/pangolin-chain/tests/baseline_capture.rs`. **Do not
/// change** without re-capturing the baseline.
const FIXED_SEED: [u8; 32] = [0x42; 32];

/// The address derived from `FIXED_SEED` via
/// `derive_evm_wallet(DeviceKey::from_seed(FIXED_SEED))` against the
/// pre-3.6 baseline (`main` at `3227d38`). Captured at builder time
/// via `crates/pangolin-chain/tests/baseline_capture.rs`.
const EXPECTED_DEFAULT_WALLET_ADDRESS: Address =
    address!("0x7b646740F6956230716beEb16361fcfe396c91E2");

/// The 65-byte `r || s || v` signature produced by
/// `build_signed_revision_v1(derive_evm_wallet(DeviceKey::from_seed(FIXED_SEED)),
/// fixed_fields, fixed_enc_payload, BaseSepolia)` against the pre-3.6
/// baseline (`main` at `3227d38`). Captured at builder time via
/// `crates/pangolin-chain/tests/baseline_capture.rs`.
///
/// **L4 verbatim: a drift here is a behavioural-drift regression.** If
/// a future PR fails this assertion, either (a) [`DefaultStrategy`]
/// has stopped being a verbatim no-op (the fix is to revert the change
/// or coordinate a fresh capture + DEVLOG entry explaining the drift)
/// or (b) the underlying signing primitive
/// (`build_signed_revision_v1` / `derive_evm_wallet`) has changed (the
/// fix is to investigate the upstream change with the audit/security
/// lens before recapturing).
const EXPECTED_REVISION_SIGNATURE_FOR_DEFAULT_STRATEGY: [u8; 65] = hex!(
    "336a9893b56a897f69fb485412ee151a39199353933d475eb8ac55c5a54fc763\
     68af6b5a72a2bd0d5eb5554bc59d33f9ca64c87f0f31ee956e0943cc1d56bcad\
     1c"
);

/// Build the fixed `RevisionFieldsV1` the baseline-capture harness +
/// the byte-identity test both consume. Mirrors
/// `crates/pangolin-chain/tests/baseline_capture.rs::fixed_fields`
/// verbatim — any drift breaks the byte-identity property and IS the
/// intended catch.
fn fixed_fields(device_address: Address) -> RevisionFieldsV1 {
    let enc_payload = b"baseline_capture_3.6_enc_payload".to_vec();
    let enc_payload_hash = keccak256(&enc_payload).0;
    let mut device_id = [0u8; 32];
    device_id[12..].copy_from_slice(device_address.as_slice());
    RevisionFieldsV1 {
        vault_id: [0xAA; 32],
        account_id: [0xBB; 32],
        parent_revision: [0u8; 32],
        device_id,
        schema_version: 1,
        enc_payload_hash,
    }
}

fn fixed_enc_payload() -> Vec<u8> {
    b"baseline_capture_3.6_enc_payload".to_vec()
}

/// **R-d test class (b) — load-bearing byte-identity proof.**
///
/// Re-runs the pre-3.6 `build_signed_revision_v1` path with
/// [`DefaultStrategy::derive_wallet_for_revision`] supplying the
/// wallet (instead of a direct `derive_evm_wallet` call) and asserts
/// the produced 65-byte signature is byte-equal to
/// [`EXPECTED_REVISION_SIGNATURE_FOR_DEFAULT_STRATEGY`].
///
/// **L4 verbatim.** A drift here means 3.6's [`DefaultStrategy`] is no
/// longer the verbatim no-op the L1/L4 invariants demand. CI re-runs
/// this every PR; a regression is a build break.
#[test]
fn default_strategy_revision_signature_matches_pre_3_6_baseline() {
    let device = DeviceKey::from_seed(FIXED_SEED);

    // Sanity-check the captured address constant first — a drift here
    // would mean the `derive_evm_wallet` primitive itself has changed,
    // which would (correctly) cascade into a signature drift below.
    let wallet_via_default = DefaultStrategy
        .derive_wallet_for_revision(&device, 0)
        .expect("derive via default");
    assert_eq!(
        wallet_via_default.address(),
        EXPECTED_DEFAULT_WALLET_ADDRESS,
        "DefaultStrategy must produce the same EVM address as the pre-3.6 baseline"
    );

    let fields = fixed_fields(wallet_via_default.address());
    let signed = build_signed_revision_v1(
        &wallet_via_default,
        fields,
        fixed_enc_payload(),
        ChainEnv::BaseSepolia,
        84_532,
    )
    .expect("sign via default strategy wallet");

    assert_eq!(
        signed.signature, EXPECTED_REVISION_SIGNATURE_FOR_DEFAULT_STRATEGY,
        "DefaultStrategy must produce byte-identical revision signature to \
         the pre-3.6 baseline; see docs/issue-plans/3.6.md L4"
    );
}

/// **R-d test class (b).** Cross-check that
/// [`DefaultStrategy::derive_wallet_for_revision`] returns the same
/// scalar as a direct [`derive_evm_wallet`] call (the structural form
/// of the byte-identity property). The address comparison is the
/// load-bearing equality; the secret scalar is not asserted directly
/// (the alloy `PrivateKeySigner` does not expose its scalar bytes to
/// safe Rust without `to_bytes()`, which we use here).
#[test]
fn default_strategy_wallet_matches_direct_derive() {
    let device = DeviceKey::from_seed(FIXED_SEED);

    let direct = derive_evm_wallet(&device).expect("direct derive");
    let via_default_idx0 = DefaultStrategy
        .derive_wallet_for_revision(&device, 0)
        .expect("derive via default at idx 0");
    let via_default_idx_99 = DefaultStrategy
        .derive_wallet_for_revision(&device, 99)
        .expect("derive via default at idx 99");

    assert_eq!(
        direct.address(),
        via_default_idx0.address(),
        "DefaultStrategy must match direct derive at idx 0"
    );
    // L1: the index is IGNORED in the default impl. Asserting the
    // address is index-independent pins the no-op property — a
    // future contributor who "accidentally" wires the index into the
    // default impl breaks this test.
    assert_eq!(
        direct.address(),
        via_default_idx_99.address(),
        "DefaultStrategy must ignore revision_index (no-op invariant)"
    );

    // Cross-check on the scalar bytes too (defense in depth — the
    // address is a function of the scalar, so a scalar drift cascades
    // into an address drift, but the explicit check fires more
    // diagnostically if the alloy signer surface changes shape).
    let direct_scalar: [u8; 32] = direct.signer().to_bytes().into();
    let via_default_scalar: [u8; 32] = via_default_idx0.signer().to_bytes().into();
    assert_eq!(
        direct_scalar, via_default_scalar,
        "DefaultStrategy scalar bytes must match direct derive"
    );
}

/// **R-d test class (b).** `transform_funder_response` is the identity
/// function under [`DefaultStrategy`]. The byte-identity property is
/// structurally enforced (pass-through by construction).
#[test]
fn default_strategy_transform_funder_response_is_identity() {
    let response = FunderResponseShape {
        tx_hash: b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        eth_transferred_wei: U256::from(123_456_789_u128),
    };
    let out = DefaultStrategy
        .transform_funder_response(response)
        .expect("default transform must succeed");
    assert_eq!(
        out, response,
        "DefaultStrategy must pass through the funder response unchanged"
    );
}

/// **R-d test class (b).** `select_address_for_vault` returns the
/// supplied default address verbatim under [`DefaultStrategy`].
#[test]
fn default_strategy_select_address_returns_default_verbatim() {
    let default_addr = address!("0x179362Ad7fb7dA664312aEFDdaa53431eb748E42");
    let vault_id_a = [0x11u8; 32];
    let vault_id_b = [0x22u8; 32];

    let out_a = DefaultStrategy
        .select_address_for_vault(vault_id_a, default_addr)
        .expect("default select_address must succeed");
    let out_b = DefaultStrategy
        .select_address_for_vault(vault_id_b, default_addr)
        .expect("default select_address must succeed");

    assert_eq!(
        out_a, default_addr,
        "default address returned verbatim (vault A)"
    );
    assert_eq!(
        out_b, default_addr,
        "default address returned verbatim (vault B)"
    );
    // Pin: vault_id is IGNORED in the default impl.
    assert_eq!(
        out_a, out_b,
        "DefaultStrategy must ignore vault_id (no-op invariant)"
    );
}

// =====================================================================
// R-d test class (c): fail-loudly on EnhancedPrivacyStrategy.
// =====================================================================

#[test]
fn enhanced_strategy_derive_wallet_for_revision_fails_loudly() {
    let device = DeviceKey::from_seed(FIXED_SEED);
    let err = EnhancedPrivacyStrategy
        .derive_wallet_for_revision(&device, 0)
        .expect_err("enhanced strategy must fail loudly");
    assert!(
        matches!(
            err,
            PrivacyError::NotYetImplemented {
                mode: PrivacyMode::EnhancedPrivacy,
                hook: "derive_wallet_for_revision",
            }
        ),
        "expected NotYetImplemented {{ mode: EnhancedPrivacy, hook: \"derive_wallet_for_revision\" }}, got {err:?}"
    );
}

#[test]
fn enhanced_strategy_transform_funder_response_fails_loudly() {
    let response = FunderResponseShape {
        tx_hash: b256!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        eth_transferred_wei: U256::from(1u64),
    };
    let err = EnhancedPrivacyStrategy
        .transform_funder_response(response)
        .expect_err("enhanced strategy must fail loudly");
    assert!(
        matches!(
            err,
            PrivacyError::NotYetImplemented {
                mode: PrivacyMode::EnhancedPrivacy,
                hook: "transform_funder_response",
            }
        ),
        "expected NotYetImplemented {{ mode: EnhancedPrivacy, hook: \"transform_funder_response\" }}, got {err:?}"
    );
}

#[test]
fn enhanced_strategy_select_address_for_vault_fails_loudly() {
    let default_addr = address!("0x0000000000000000000000000000000000000001");
    let err = EnhancedPrivacyStrategy
        .select_address_for_vault([0u8; 32], default_addr)
        .expect_err("enhanced strategy must fail loudly");
    assert!(
        matches!(
            err,
            PrivacyError::NotYetImplemented {
                mode: PrivacyMode::EnhancedPrivacy,
                hook: "select_address_for_vault",
            }
        ),
        "expected NotYetImplemented {{ mode: EnhancedPrivacy, hook: \"select_address_for_vault\" }}, got {err:?}"
    );
}

/// The fail-loudly Display message includes the doc-link reference per
/// L7. A user who debugs the error in their logs gets a clear pointer
/// to the Phase-2 roadmap.
#[test]
fn enhanced_strategy_error_message_references_phase_2_roadmap() {
    let err = PrivacyError::NotYetImplemented {
        mode: PrivacyMode::EnhancedPrivacy,
        hook: "derive_wallet_for_revision",
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("docs/issue-plans/3.6.md"),
        "fail-loudly message must reference the Phase-2 roadmap doc; got: {msg}"
    );
    assert!(
        msg.contains("EnhancedPrivacy"),
        "fail-loudly message must name the mode; got: {msg}"
    );
    assert!(
        msg.contains("derive_wallet_for_revision"),
        "fail-loudly message must name the hook; got: {msg}"
    );
}
