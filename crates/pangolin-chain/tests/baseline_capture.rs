// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-2 issue 3.6 byte-identity baseline capture.
//!
//! Run with `cargo test -p pangolin-chain --test baseline_capture
//! capture_baseline_revision_signature -- --nocapture` to print the
//! hex-encoded 65-byte signature for the fixed-seed
//! `RevisionFieldsV1`.
//!
//! The output is hand-embedded as `EXPECTED_REVISION_SIGNATURE_FOR_DEFAULT_STRATEGY`
//! in `crates/pangolin-chain/src/privacy/tests.rs` (R-d test class b).
//!
//! This file is a builder-time fixture-capture harness; it is left in
//! the tree so a future Phase-2 maintainer can re-capture the baseline
//! if the underlying signing primitive deliberately changes (which
//! would itself be a separately-reviewed event, per the L4 byte-
//! identity invariant of 3.6).

use pangolin_chain::evm::derive_evm_wallet;
use pangolin_chain::secp256k1_signing::{build_signed_revision_v1, RevisionFieldsV1};
use pangolin_chain::ChainEnv;
use pangolin_crypto::keys::DeviceKey;

/// The exact same fixed seed `crates/pangolin-chain/src/privacy/tests.rs`
/// uses for the byte-identity assertion.
const FIXED_SEED: [u8; 32] = [0x42; 32];

/// The exact same fixed `RevisionFieldsV1` the 3.6 test uses.
fn fixed_fields(device_address_bytes: [u8; 20]) -> RevisionFieldsV1 {
    use alloy::primitives::keccak256;
    let enc_payload = b"baseline_capture_3.6_enc_payload".to_vec();
    let enc_payload_hash = keccak256(&enc_payload).0;
    let mut device_id = [0u8; 32];
    device_id[12..].copy_from_slice(&device_address_bytes);
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

#[test]
fn capture_baseline_revision_signature() {
    let device = DeviceKey::from_seed(FIXED_SEED);
    let wallet = derive_evm_wallet(&device).expect("derive wallet");
    let addr_bytes: [u8; 20] = wallet.address().0.into();
    let fields = fixed_fields(addr_bytes);
    let signed =
        build_signed_revision_v1(&wallet, fields, fixed_enc_payload(), ChainEnv::BaseSepolia)
            .expect("build signed revision");

    // Print the hex literal for hand-embedding in
    // `crates/pangolin-chain/src/privacy/tests.rs`. The println output
    // is captured by `cargo test ... -- --nocapture`.
    println!(
        "BASELINE_3_6_REVISION_SIGNATURE_HEX = \"{}\"",
        hex::encode(signed.signature)
    );
    println!(
        "BASELINE_3_6_DEVICE_ADDRESS_HEX = \"{}\"",
        hex::encode(addr_bytes)
    );
}
