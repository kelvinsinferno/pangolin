// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hermetic test suite for the slow-mode chain-sync read path (MVP-2
//! issue 4.1).
//!
//! Mirrors the alloy `Asserter` + `connect_mocked_client` posture used
//! by 3.3's chain_submit tests. Each test pushes an RPC response
//! sequence onto an `Asserter`, drives the chain-sync orchestrator
//! primitive (`fetch_and_verify_chunk` / `verify_signed_event`), then
//! asserts the verified-event shape + rejection accounting.

#![allow(
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::doc_markdown
)]

use alloy::primitives::{address, hex, keccak256, Address, Bloom, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::Log as RpcLog;
use alloy::sol_types::SolEvent;
use alloy::transports::mock::Asserter;
use pangolin_crypto::keys::DeviceKey;

use crate::chain_submit::revision_log_v1_binding::RevisionLogV1;
use crate::deployments::ChainEnv;
use crate::error::ChainError;
use crate::evm::derive_evm_wallet;
use crate::secp256k1_signing::{
    build_signed_revision_v1, recover_signer_v1, recover_signer_v1_raw, RevisionFieldsV1,
    SignedRevisionV1, EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA,
};
use crate::EvmWallet;

use super::filtering_asserter::FilteringAsserter;
use super::poll::{fetch_chunk, verify_signed_event};
use super::reorg::ReorgDetector;
use super::{
    check_chain_id_matches, resolve_and_check_contract, ChainEventSource, RevisionStatus,
    VerifiedRevisionEvent, CONFIRMATION_DEPTH_FOR_FINALIZATION, LOG_BLOCK_CHUNK,
    MAX_KNOWN_CLIENT_SCHEMA_VERSION,
};
use alloy::rpc::client::RpcClient;

// ---------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------

fn fixed_wallet() -> EvmWallet {
    let seed: [u8; 32] = [0x42; 32];
    derive_evm_wallet(&DeviceKey::from_seed(seed)).expect("derive fixed wallet")
}

fn fixed_wallet_b() -> EvmWallet {
    let seed: [u8; 32] = [0x73; 32];
    derive_evm_wallet(&DeviceKey::from_seed(seed)).expect("derive fixed wallet b")
}

fn mock_provider(asserter: &Asserter) -> DynProvider {
    ProviderBuilder::new()
        .connect_mocked_client(asserter.clone())
        .erased()
}

fn sample_enc_payload() -> (Vec<u8>, [u8; 32]) {
    let pre = b"pangolin-chain-sync-test-encpayload".to_vec();
    let h = keccak256(&pre).0;
    (pre, h)
}

fn sample_signed_revision(wallet: &EvmWallet) -> SignedRevisionV1 {
    let (pre, h) = sample_enc_payload();
    let fields =
        RevisionFieldsV1::with_signer_device_id(wallet, [0x11; 32], [0x22; 32], [0x33; 32], 1, h);
    build_signed_revision_v1(wallet, fields, pre, ChainEnv::BaseSepolia, 84_532).expect("sign v1")
}

/// Build an `RpcLog` whose ABI-decoded shape is a `RevisionPublished`
/// event for the given inputs. Mirrors the chain_submit test scaffolding
/// (`build_revision_published_log`) but configurable for vault id,
/// schema version, etc.
fn build_revision_log(
    contract: Address,
    vault_id: [u8; 32],
    account_id: [u8; 32],
    parent_revision: [u8; 32],
    device_id: [u8; 32],
    schema_version: u16,
    enc_payload: &[u8],
    signer: Address,
    tx_hash: B256,
    block_hash: B256,
    block_number: u64,
    log_index: u64,
    sequence: U256,
) -> RpcLog {
    use alloy::primitives::{Log as PrimLog, LogData};
    let seq_topic = B256::from(sequence.to_be_bytes::<32>());
    let vault_topic = B256::from(vault_id);
    let account_topic = B256::from(account_id);
    let topic0 = RevisionLogV1::RevisionPublished::SIGNATURE_HASH;
    let event = RevisionLogV1::RevisionPublished {
        sequence,
        vaultId: vault_id.into(),
        accountId: account_id.into(),
        parentRevision: parent_revision.into(),
        deviceId: device_id.into(),
        schemaVersion: schema_version,
        encPayload: Bytes::copy_from_slice(enc_payload),
        signer,
    };
    let body_data = event.encode_data();
    let log_data = LogData::new(
        vec![topic0, seq_topic, vault_topic, account_topic],
        Bytes::from(body_data),
    )
    .expect("topics + data shape ok");
    RpcLog {
        inner: PrimLog {
            address: contract,
            data: log_data,
        },
        block_hash: Some(block_hash),
        block_number: Some(block_number),
        block_timestamp: None,
        transaction_hash: Some(tx_hash),
        transaction_index: Some(0),
        log_index: Some(log_index),
        removed: false,
    }
}

/// Push the JSON-RPC reply for an `eth_getLogs` returning the given
/// logs. The asserter's response queue replies to the next pending
/// request, so the caller controls ordering by interleaving
/// `push_success` calls and the function under test.
fn push_get_logs_response(asserter: &Asserter, logs: &[RpcLog]) {
    let json = serde_json::to_value(logs).expect("serialize logs");
    asserter.push_success(&json);
}

/// Push the JSON-RPC reply for `eth_chainId` returning the given value.
fn push_chain_id(asserter: &Asserter, chain_id: u64) {
    asserter.push_success(&format!("0x{chain_id:x}"));
}

// ---------------------------------------------------------------------
// Verifier round-trip tests (L1)
// ---------------------------------------------------------------------

/// L1 + Q-e.2: sign + recover round-trip via the production primitive.
#[test]
fn recover_signer_v1_round_trip() {
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let recovered = recover_signer_v1(&signed, ChainEnv::BaseSepolia, 84_532).expect("recover");
    assert_eq!(recovered, wallet.address());
}

/// Same, via the lower-level primitive that takes the raw signature
/// bytes (the event-decode path's natural input shape).
#[test]
fn recover_signer_v1_raw_round_trip() {
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let recovered = recover_signer_v1_raw(
        &signed.fields,
        &signed.signature,
        ChainEnv::BaseSepolia,
        84_532,
    )
    .expect("recover raw");
    assert_eq!(recovered, wallet.address());
}

/// L-rpc-spoof-events: a tampered byte in the sig produces an error or
/// a different recovered address (NOT silently the wallet's address).
#[test]
fn recover_signer_v1_tampered_signature_diverges() {
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    // Flip a byte in the `r` component.
    let mut tampered = signed.signature;
    tampered[0] ^= 0x01;
    let result = recover_signer_v1_raw(&signed.fields, &tampered, ChainEnv::BaseSepolia, 84_532);
    match result {
        Ok(addr) => assert_ne!(
            addr,
            wallet.address(),
            "tampered sig must NOT recover original"
        ),
        Err(ChainError::SignerRecoveryFailed { .. }) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

/// LOW#3 defense-in-depth: a non-canonical (high-s) signature is
/// rejected with `SignerRecoveryFailed` rather than allowed to recover
/// to a malleability twin.
#[test]
fn recover_signer_v1_raw_rejects_high_s() {
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let mut high_s_sig = signed.signature;
    // Flip the high bit of s (byte 32). Any value with the top bit set
    // and byte32 ≠ 0 will be > n/2.
    high_s_sig[32] = 0xFF;
    let result = recover_signer_v1_raw(&signed.fields, &high_s_sig, ChainEnv::BaseSepolia, 84_532);
    assert!(matches!(
        result,
        Err(ChainError::SignerRecoveryFailed { .. })
    ));
}

/// `v` byte ∉ {27,28} is rejected.
#[test]
fn recover_signer_v1_raw_rejects_invalid_v_byte() {
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let mut bad_v = signed.signature;
    bad_v[64] = 29;
    let result = recover_signer_v1_raw(&signed.fields, &bad_v, ChainEnv::BaseSepolia, 84_532);
    assert!(matches!(
        result,
        Err(ChainError::SignerRecoveryFailed { .. })
    ));
}

// ---------------------------------------------------------------------
// Provider construction + cross-checks
// ---------------------------------------------------------------------

#[tokio::test]
async fn check_chain_id_succeeds_when_matched() {
    let asserter = Asserter::new();
    push_chain_id(&asserter, 84_532);
    let provider = mock_provider(&asserter);
    check_chain_id_matches(&provider, ChainEnv::BaseSepolia)
        .await
        .expect("chain id check");
}

#[tokio::test]
async fn chain_id_mismatch_fails_closed() {
    let asserter = Asserter::new();
    push_chain_id(&asserter, 1); // mainnet
    let provider = mock_provider(&asserter);
    let err = check_chain_id_matches(&provider, ChainEnv::BaseSepolia)
        .await
        .expect_err("mismatch");
    match err {
        ChainError::ChainIdMismatch { expected, observed } => {
            assert_eq!(expected, 84_532);
            assert_eq!(observed, 1);
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
}

#[test]
fn deployment_address_resolves_for_base_sepolia() {
    let addr = resolve_and_check_contract(ChainEnv::BaseSepolia).expect("resolve");
    assert_eq!(addr, EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA);
}

// ---------------------------------------------------------------------
// fetch_chunk tests (L2, L4, L6, L-vaultid, L-schemaversion)
// ---------------------------------------------------------------------

#[tokio::test]
async fn fetch_chunk_returns_verified_events() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);

    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
    let tx_hash = B256::repeat_byte(0xAB);
    let block_hash = B256::repeat_byte(0xCC);
    let log = build_revision_log(
        contract,
        signed.fields.vault_id,
        signed.fields.account_id,
        signed.fields.parent_revision,
        signed.fields.device_id,
        signed.fields.schema_version,
        &signed.enc_payload,
        wallet.address(),
        tx_hash,
        block_hash,
        100,
        7,
        U256::from(1u64),
    );
    push_get_logs_response(&asserter, &[log]);

    let (events, rejected) = fetch_chunk(
        &provider,
        ChainEnv::BaseSepolia,
        contract,
        &signed.fields.vault_id,
        50,
        200,
    )
    .await
    .expect("fetch_chunk");
    assert_eq!(events.len(), 1);
    assert_eq!(rejected, 0);
    let ev = &events[0];
    assert_eq!(ev.event.vault_id, signed.fields.vault_id);
    assert_eq!(ev.event.account_id, signed.fields.account_id);
    assert_eq!(ev.signer, wallet.address());
    assert_eq!(ev.block_hash, block_hash);
    assert_eq!(ev.event.anchor.block_number, 100);
    assert_eq!(ev.event.anchor.log_index, 7);
}

#[tokio::test]
async fn fetch_chunk_rejects_foreign_emitter() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
    // Foreign emitter: log address is NOT the expected contract.
    let foreign = address!("0x0000000000000000000000000000000000001234");
    let log = build_revision_log(
        foreign,
        signed.fields.vault_id,
        signed.fields.account_id,
        signed.fields.parent_revision,
        signed.fields.device_id,
        signed.fields.schema_version,
        &signed.enc_payload,
        wallet.address(),
        B256::ZERO,
        B256::ZERO,
        100,
        0,
        U256::from(1u64),
    );
    push_get_logs_response(&asserter, &[log]);
    let (events, rejected) = fetch_chunk(
        &provider,
        ChainEnv::BaseSepolia,
        contract,
        &signed.fields.vault_id,
        50,
        200,
    )
    .await
    .expect("fetch_chunk");
    assert!(events.is_empty());
    assert_eq!(rejected, 1);
}

#[tokio::test]
async fn fetch_chunk_rejects_wrong_vault_id() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
    let other_vault_id = [0x99u8; 32];
    let log = build_revision_log(
        contract,
        other_vault_id,
        signed.fields.account_id,
        signed.fields.parent_revision,
        signed.fields.device_id,
        signed.fields.schema_version,
        &signed.enc_payload,
        wallet.address(),
        B256::ZERO,
        B256::ZERO,
        100,
        0,
        U256::from(1u64),
    );
    push_get_logs_response(&asserter, &[log]);
    let requested_vault = signed.fields.vault_id;
    let (events, rejected) = fetch_chunk(
        &provider,
        ChainEnv::BaseSepolia,
        contract,
        &requested_vault,
        50,
        200,
    )
    .await
    .expect("fetch_chunk");
    assert!(events.is_empty());
    assert_eq!(rejected, 1);
}

// ---------------------------------------------------------------------
// Issue #107 — V1 read-topic regression tests.
//
// The V1 `RevisionPublished` event puts `sequence` at TOPIC1 and
// `vaultId` at TOPIC2. The V1 read path (`fetch_chunk` in HTTP polling
// + `open_subscription` in WS) MUST filter on topic2, not topic1.
//
// The legacy `Asserter` mock returns canned responses without
// inspecting the request — so the buggy `.topic1(vault_id)` filter
// from the original code goes unexercised in hermetic tests. Issue
// #107 introduces `FilteringAsserter` (a `tower::Service<RequestPacket>`
// that parses the `eth_getLogs` filter via `serde_json` + applies
// `Filter::matches`) to close that gap.
//
// **Discrimination:** these tests go RED under the OLD code
// (`.topic1(vault_id)` against the smarter mock filters by topic1 ==
// vaultId, but the queued logs have topic1 == sequence, so nothing
// matches → empty result → test fails) and GREEN under the new code
// (`.topic2(vault_id)` matches the correct topic slot).
// ---------------------------------------------------------------------

/// Build an `RpcLog` with the canonical V1 topic layout:
/// `[topic0, sequence, vaultId, accountId]`. Helper for the #107
/// regression tests to keep their bodies focused on the filter
/// assertion.
#[allow(clippy::too_many_arguments)]
fn v1_log_with_canonical_topics(
    contract: Address,
    vault_id: [u8; 32],
    sequence: u64,
    block_number: u64,
    log_index: u64,
) -> RpcLog {
    let signer = Address::from([0x77u8; 20]);
    build_revision_log(
        contract,
        vault_id,
        [0x33; 32],
        [0u8; 32],
        [0xCC; 32],
        1,
        b"#107-fixture",
        signer,
        B256::repeat_byte(0xCC),
        B256::repeat_byte(0xBB),
        block_number,
        log_index,
        U256::from(sequence),
    )
}

/// **#107 HTTP path regression.** Queue two V1 `RevisionPublished`
/// logs — one for `vault_id = [0xAA; 32]`, one for `[0xBB; 32]`,
/// each with the CORRECT topic layout (topic1 = `sequence`, topic2
/// = `vaultId`). Call `fetch_chunk(..., &[0xAA;32], ...)` against
/// the smarter mock. The mock applies the `Filter.topics` array
/// server-side (per the `Filter::matches` semantics); ONLY the
/// `[0xAA; 32]` log comes back.
///
/// **The discrimination:** under the OLD code
/// (`.topic1(vault_id)`), the smarter mock filters by topic1 ==
/// vault_a — but the logs' topic1 slot holds `sequence`, NOT
/// vault_id, so neither log matches → `fetch_chunk` returns an
/// empty Vec → this assertion fails. Under the NEW code
/// (`.topic2(vault_id)`), the filter binds to topic2 (the actual
/// vault_id slot), so the `[0xAA; 32]` log matches and is returned.
#[tokio::test]
async fn fetch_chunk_filters_by_topic2_not_topic1() {
    let asserter = FilteringAsserter::new();
    let provider = ProviderBuilder::new().connect_client(RpcClient::new(asserter.clone(), true));

    let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
    let vault_a: [u8; 32] = [0xAAu8; 32];
    let vault_b: [u8; 32] = [0xBBu8; 32];

    asserter.push_log(v1_log_with_canonical_topics(contract, vault_a, 1, 100, 0));
    asserter.push_log(v1_log_with_canonical_topics(contract, vault_b, 2, 101, 0));

    let (events, rejected) = fetch_chunk(
        &provider,
        ChainEnv::BaseSepolia,
        contract,
        &vault_a,
        50,
        200,
    )
    .await
    .expect("fetch_chunk");

    // The smart mock applied the server-side filter; vault_b's log
    // never reached the verifier. The verifier sees only vault_a's
    // log + verifies it cleanly → 1 verified, 0 rejected.
    assert_eq!(
        events.len(),
        1,
        "expected exactly 1 matching event for vault_a; got {} \
         (RED on OLD code → 0 events, indicates `.topic1(vault_id)` \
         filtered against `sequence` slot and matched nothing)",
        events.len()
    );
    assert_eq!(rejected, 0);
    assert_eq!(
        events[0].event.vault_id, vault_a,
        "the returned event must be vault_a's, not vault_b's"
    );
    assert_eq!(events[0].event.sequence, 1);
}

/// **#107 HTTP path regression — buggy filter signature.** Demonstrate
/// the bug's *signature* directly: the buggy filter
/// `.topic1(vault_id)` applied to logs whose topic1 is `sequence`
/// returns ZERO matches. This is what the production V1 read path
/// observed against a real RPC.
///
/// This test does NOT exercise `fetch_chunk`; it pins the smart
/// mock's filter semantics so the OTHER #107 test's RED-on-old-code
/// behaviour is well-explained. Together they form the "smart mock
/// catches this class of bug" guarantee.
#[tokio::test]
#[allow(clippy::items_after_statements)]
async fn smart_mock_applies_topic_filter_buggy_topic1_filter_drops_all_logs() {
    let asserter = FilteringAsserter::new();
    let provider = ProviderBuilder::new().connect_client(RpcClient::new(asserter.clone(), true));

    let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
    let vault_a: [u8; 32] = [0xAAu8; 32];
    asserter.push_log(v1_log_with_canonical_topics(contract, vault_a, 1, 100, 0));

    // Issue a manual `get_logs` with the BUGGY filter shape
    // (.topic1(vault_id)). This mirrors what the OLD code did at
    // poll.rs:~196 + ws.rs:~240 before the #107 fix.
    use alloy::eips::BlockNumberOrTag;
    use alloy::rpc::types::Filter;
    let buggy_filter = Filter::new()
        .address(contract)
        .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
        .from_block(BlockNumberOrTag::Number(50))
        .to_block(BlockNumberOrTag::Number(200))
        .topic1(B256::from(vault_a));
    let logs = provider.get_logs(&buggy_filter).await.expect("get_logs");
    assert!(
        logs.is_empty(),
        "buggy .topic1(vault_id) filter must return zero matches: the \
         log's topic1 slot holds `sequence`, not `vaultId`"
    );

    // Same fixture, CORRECT filter — returns the log.
    let correct_filter = Filter::new()
        .address(contract)
        .event_signature(RevisionLogV1::RevisionPublished::SIGNATURE_HASH)
        .from_block(BlockNumberOrTag::Number(50))
        .to_block(BlockNumberOrTag::Number(200))
        .topic2(B256::from(vault_a));
    let logs = provider.get_logs(&correct_filter).await.expect("get_logs");
    assert_eq!(
        logs.len(),
        1,
        "correct .topic2(vault_id) filter must return the matching log"
    );
}

#[tokio::test]
async fn fetch_chunk_rejects_future_schema_version() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let contract = EXPECTED_DEPLOYED_ADDRESS_BASE_SEPOLIA;
    let future_schema = MAX_KNOWN_CLIENT_SCHEMA_VERSION + 1;
    let log = build_revision_log(
        contract,
        signed.fields.vault_id,
        signed.fields.account_id,
        signed.fields.parent_revision,
        signed.fields.device_id,
        future_schema,
        &signed.enc_payload,
        wallet.address(),
        B256::ZERO,
        B256::ZERO,
        100,
        0,
        U256::from(1u64),
    );
    push_get_logs_response(&asserter, &[log]);
    let (events, rejected) = fetch_chunk(
        &provider,
        ChainEnv::BaseSepolia,
        contract,
        &signed.fields.vault_id,
        50,
        200,
    )
    .await
    .expect("fetch_chunk");
    assert!(events.is_empty());
    assert_eq!(rejected, 1);
}

// ---------------------------------------------------------------------
// L5: verify_signed_event covers signer recovery + signer-field
// cross-check end-to-end via the synthetic-signed-event path.
// ---------------------------------------------------------------------

#[test]
fn verify_signed_event_succeeds_for_canonical_input() {
    let wallet = fixed_wallet();
    let signed = sample_signed_revision(&wallet);
    let recovered = verify_signed_event(
        &signed.fields,
        &signed.signature,
        wallet.address(),
        ChainEnv::BaseSepolia,
    )
    .expect("verify");
    assert_eq!(recovered, wallet.address());
}

#[test]
fn verify_signed_event_detects_signer_field_mismatch() {
    let wallet = fixed_wallet();
    let other = fixed_wallet_b();
    let signed = sample_signed_revision(&wallet);
    let err = verify_signed_event(
        &signed.fields,
        &signed.signature,
        other.address(),
        ChainEnv::BaseSepolia,
    )
    .expect_err("mismatch");
    match err {
        ChainError::EventSignerMismatch { claimed, recovered } => {
            assert_eq!(claimed, other.address());
            assert_eq!(recovered, wallet.address());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Status enum + RevisionStatus invariants
// ---------------------------------------------------------------------

#[test]
fn revision_status_pending_and_finalized_predicates() {
    let pending = RevisionStatus::Pending {
        observed_at_block: 100,
        block_hash: B256::ZERO,
    };
    assert!(pending.is_pending());
    assert!(!pending.is_finalized());

    let final_ = RevisionStatus::Finalized;
    assert!(final_.is_finalized());
    assert!(!final_.is_pending());
}

#[test]
fn confirmation_depth_constant_pinned_at_12() {
    assert_eq!(CONFIRMATION_DEPTH_FOR_FINALIZATION, 12);
}

#[test]
fn log_block_chunk_constant_pinned_at_9k() {
    assert_eq!(LOG_BLOCK_CHUNK, 9_000);
}

#[test]
fn max_known_client_schema_version_is_one_in_mvp2() {
    assert_eq!(MAX_KNOWN_CLIENT_SCHEMA_VERSION, 1);
}

// ---------------------------------------------------------------------
// Reorg simulator + reorg detection tests
// ---------------------------------------------------------------------

#[tokio::test]
async fn reorg_simulator_shallow_two_block_rollback() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);
    let mut det = ReorgDetector::default();
    // Record observations at blocks 100, 101, 102 with hashes A, B, C.
    let hash_a = B256::from([0xAAu8; 32]);
    let hash_b = B256::from([0xBBu8; 32]);
    let hash_c = B256::from([0xCCu8; 32]);
    det.record(100, hash_a);
    det.record(101, hash_b);
    det.record(102, hash_c);

    // Synthesize the reorg: blocks 101 + 102 now have different hashes
    // on canonical (B' and C'). Block 100 still matches A.
    // The detector queries eth_getBlockByNumber for each observed
    // height in ascending order (BTreeMap iteration).
    let hash_b_prime = B256::from([0xB2u8; 32]);
    let hash_c_prime = B256::from([0xC2u8; 32]);
    push_block_with_hash(&asserter, 100, hash_a);
    push_block_with_hash(&asserter, 101, hash_b_prime);
    push_block_with_hash(&asserter, 102, hash_c_prime);

    let info = det
        .detect_reorg(&provider)
        .await
        .expect("detect")
        .expect("reorg present");
    assert_eq!(info.affected_block_low, 101);
    assert_eq!(info.affected_block_high, 102);
}

#[tokio::test]
async fn no_reorg_when_block_hashes_match() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);
    let mut det = ReorgDetector::default();
    let h = B256::from([0xAAu8; 32]);
    det.record(100, h);
    push_block_with_hash(&asserter, 100, h);
    let info = det.detect_reorg(&provider).await.expect("detect");
    assert!(info.is_none());
}

#[tokio::test]
async fn deep_reorg_ten_block_rollback() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);
    let mut det = ReorgDetector::default();
    // Record blocks 90..=99 with original hashes; all 10 diverge on
    // canonical.
    for i in 0..10u8 {
        let h = B256::from([i; 32]);
        det.record(90 + u64::from(i), h);
    }
    for i in 0..10u8 {
        let new_h = B256::from([0xF0 | i; 32]);
        push_block_with_hash(&asserter, 90 + u64::from(i), new_h);
    }
    let info = det
        .detect_reorg(&provider)
        .await
        .expect("detect")
        .expect("reorg");
    assert_eq!(info.affected_block_low, 90);
    assert_eq!(info.affected_block_high, 99);
}

#[tokio::test]
async fn synthesize_reorg_helper_drives_forget_window() {
    let asserter = Asserter::new();
    let provider = mock_provider(&asserter);
    let mut det = ReorgDetector::default();
    let h1 = B256::from([0x11u8; 32]);
    let h2 = B256::from([0x22u8; 32]);
    det.record(100, h1);
    det.record(101, h2);
    let h2_prime = B256::from([0x99u8; 32]);
    push_block_with_hash(&asserter, 100, h1);
    push_block_with_hash(&asserter, 101, h2_prime);
    let info = det
        .detect_reorg(&provider)
        .await
        .expect("detect")
        .expect("reorg");
    det.forget_window(info);
    assert!(det.observed_at(100).is_some(), "untouched block kept");
    assert!(det.observed_at(101).is_none(), "affected block forgotten");
}

/// Push an `eth_getBlockByNumber` JSON-RPC reply matching the alloy
/// `Block` shape — only the `hash` field on the header is read by the
/// reorg detector, but the surrounding shape must deserialize.
fn push_block_with_hash(asserter: &Asserter, block_number: u64, block_hash: B256) {
    let block_json = serde_json::json!({
        "number": format!("0x{block_number:x}"),
        "hash": format!("{block_hash:?}"),
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "miner": "0x0000000000000000000000000000000000000000",
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": "0x",
        "size": "0x0",
        "gasLimit": "0x0",
        "gasUsed": "0x0",
        "timestamp": "0x0",
        "transactions": [],
        "uncles": [],
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "0x0000000000000000",
        "baseFeePerGas": "0x0",
    });
    asserter.push_success(&block_json);
}

// ---------------------------------------------------------------------
// fetch_and_verify_chunk integration test — exercises the full chain
// of construction-time cross-checks + chunk fetch in one shot.
// ---------------------------------------------------------------------

// NOTE: `fetch_and_verify_chunk` calls `build_read_provider` which
// dispatches via `ProviderBuilder::connect`; the `Asserter` shape used
// elsewhere requires `connect_mocked_client`, which is only available
// via the in-test helper. We test the orchestration shape end-to-end
// by driving `fetch_chunk` directly with a mocked provider (which is
// what `fetch_and_verify_chunk` does after construction). The
// construction-time paths are covered by `chain_id_mismatch_fails_closed`
// and `deployment_address_resolves_for_base_sepolia` above.

// (compile-time existence of `super::fetch_and_verify_chunk` is checked
// transitively by every other test that uses the chain_sync module + by
// the lib.rs `pub use` re-export.)

// ---------------------------------------------------------------------
// d017_deploy_block constant pinned per env-quirk #14
// ---------------------------------------------------------------------

#[test]
fn d017_deploy_block_is_pinned_for_base_sepolia() {
    // Issue #98 (2026-05-18): chain-verified value. Both prior pins
    // (`23_640_113` in Rust + `41_639_216` in JSON) were rot; the
    // authoritative deploy block was re-derived via `cast code` binary
    // search against the live D-017 contract — see
    // [`super::d017_deploy_block`] docstring for verification commands.
    assert_eq!(super::d017_deploy_block(ChainEnv::BaseSepolia), 41_507_120);
    // Non-pinned envs return 0 so a first sync replays from chain
    // genesis on a fresh deployment.
    assert_eq!(super::d017_deploy_block(ChainEnv::Dev), 0);
}

// ---------------------------------------------------------------------
// Asserter shape mock: silence unused-result warning for the
// VerifiedRevisionEvent type-level checks below.
// ---------------------------------------------------------------------

#[test]
fn verified_revision_event_carries_expected_fields() {
    // Build a minimal VerifiedRevisionEvent to confirm field
    // accessibility at the type level.
    use crate::ChainAnchor;
    let ev = VerifiedRevisionEvent {
        event: crate::RevisionEvent {
            vault_id: [0u8; 32],
            account_id: [0u8; 32],
            parent_revision: [0u8; 32],
            device_id: [0u8; 32],
            schema_version: 1,
            sequence: 1,
            enc_payload: vec![],
            anchor: ChainAnchor {
                tx_hash: [0u8; 32],
                block_number: 0,
                log_index: 0,
                sequence: 0,
            },
        },
        signer: Address::ZERO,
        block_hash: B256::ZERO,
        schema_version: 1,
    };
    assert_eq!(ev.signer, Address::ZERO);
    assert_eq!(ev.block_hash, B256::ZERO);
    assert_eq!(ev.schema_version, 1);
}

#[test]
fn chain_event_source_default_is_http_polling() {
    let default = ChainEventSource::default();
    assert_eq!(default, ChainEventSource::HttpPolling);
}

// ---------------------------------------------------------------------
// Bloom usage — silence unused-import warning if no test below uses it.
// ---------------------------------------------------------------------
#[allow(dead_code)]
const _BLOOM_FORCED_USAGE: Bloom = Bloom::ZERO;

// Hex usage — used implicitly by serde_json::json! macros, also silence.
#[allow(dead_code)]
const _HEX_PIN: [u8; 0] = hex!("");
