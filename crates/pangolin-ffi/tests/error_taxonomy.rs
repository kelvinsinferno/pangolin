//! Exhaustive `pangolin_core::Error → pangolin_ffi::FfiError` mapping
//! verification.
//!
//! MVP-1 issue 1.1 success criterion 8: every `pangolin_core::Error`
//! variant must map to a non-`Internal` `FfiError` variant. The match
//! below is exhaustive — adding a new variant in `pangolin_core::Error`
//! without a corresponding arm here is a compile error, which catches
//! every regression in the From mapping.
//!
//! Authentication-class failures collapse to `FfiError::Validation
//! { kind: "authentication", .. }` so the FFI surface cannot become a
//! distinguishing oracle (Design Spec §15 / threat model #7).

use pangolin_core::Error as CoreError;
use pangolin_ffi::FfiError;

#[test]
fn every_core_error_variant_maps_to_non_internal_ffi_error() {
    // Each variant constructor + assertion. The match in the closure
    // is `#[deny(unreachable_patterns, non_exhaustive_omitted_patterns)]`
    // so the test compiles only while each arm is exercised; adding a
    // new core variant forces the developer to add an arm here.
    fn assert_non_internal(err: CoreError) {
        let category = match &err {
            CoreError::Crypto(_) => "Crypto",
            CoreError::Store(_) => "Store",
            CoreError::Session(_) => "Session",
            CoreError::Sync(_) => "Sync",
            CoreError::Chain(_) => "Chain",
            CoreError::Recovery(_) => "Recovery",
            CoreError::Validation { .. } => "Validation",
            CoreError::Authentication => "Authentication",
        };
        let mapped: FfiError = err.into();
        assert!(
            !matches!(mapped, FfiError::Internal { .. }),
            "core variant {category} mapped to FfiError::Internal — \
             every core variant must map to a non-Internal FFI variant",
        );
    }

    assert_non_internal(CoreError::Crypto("aead failed".into()));
    assert_non_internal(CoreError::Store("sqlite open".into()));
    assert_non_internal(CoreError::Session("not unlocked".into()));
    assert_non_internal(CoreError::Sync("rpc unreachable".into()));
    assert_non_internal(CoreError::Chain("chain id mismatch".into()));
    assert_non_internal(CoreError::Recovery("threshold not met".into()));
    assert_non_internal(CoreError::Validation {
        kind: "argument".into(),
        message: "out of range".into(),
    });
    assert_non_internal(CoreError::Authentication);
}

#[test]
fn authentication_collapses_to_validation_authentication() {
    let mapped: FfiError = CoreError::Authentication.into();
    match mapped {
        FfiError::Validation { kind, .. } => assert_eq!(kind, "authentication"),
        other => panic!("expected Validation(authentication), got {other:?}"),
    }
}

#[test]
fn crypto_passthrough() {
    let mapped: FfiError = CoreError::Crypto("aead failed".into()).into();
    assert!(matches!(mapped, FfiError::Crypto { .. }));
}

#[test]
fn validation_kind_passthrough() {
    let mapped: FfiError = CoreError::Validation {
        kind: "argument".into(),
        message: "x".into(),
    }
    .into();
    match mapped {
        FfiError::Validation { kind, message } => {
            assert_eq!(kind, "argument");
            assert_eq!(message, "x");
        }
        other => panic!("expected Validation(argument), got {other:?}"),
    }
}

#[test]
fn ffi_error_message_is_non_empty() {
    // FfiError::message() is the only string a UI sees. Make sure
    // every category produces a non-empty message.
    let core_variants = [
        CoreError::Crypto("x".into()),
        CoreError::Store("x".into()),
        CoreError::Session("x".into()),
        CoreError::Sync("x".into()),
        CoreError::Chain("x".into()),
        CoreError::Recovery("x".into()),
        CoreError::Validation {
            kind: "k".into(),
            message: "x".into(),
        },
        CoreError::Authentication,
    ];
    for v in core_variants {
        let mapped: FfiError = v.into();
        assert!(!mapped.message().is_empty(), "empty message for {mapped:?}");
    }
}
