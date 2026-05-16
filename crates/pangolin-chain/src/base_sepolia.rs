//! Production `BaseSepoliaAdapter` — alloy-backed implementation of
//! the [`crate::ChainAdapter`] trait against the deployed
//! `RevisionLogV0` contract.
//!
//! Mirrors the discipline established in `tools/chaincli/` (P6):
//!
//! - The contract address comes from the canonical
//!   `contracts/deployments/base-sepolia.json` file, NOT from a
//!   constructor argument. The adapter refuses to talk to an
//!   unexpected contract.
//! - `eth_chainId` is checked at construction time against the
//!   deployment's declared `chain_id`; mismatch fails closed with
//!   [`crate::ChainError::WrongChain`].
//! - Logs returned by `eth_getLogs` are filtered defensively by
//!   emitter address (audit MEDIUM-4) — an honest server-side filter
//!   already excludes other addresses, but a misbehaving RPC could
//!   splice in foreign logs that share the topic-0 hash.
//! - The `RevisionLogV0` Solidity binding is the same `sol!` block
//!   that `tools/chaincli` uses — kept as a per-crate redeclaration
//!   so an auditor can read the literal Solidity-shaped declaration
//!   side-by-side with the `.sol` source.
//!
//! ## Three constructors
//!
//! 1. [`BaseSepoliaAdapter::new_read_only`] — no signer; `publish`
//!    fails with [`ChainError::Wallet`]. Useful for `pull_since` /
//!    `get_revision` without a wallet.
//! 2. [`BaseSepoliaAdapter::new_with_keystore`] — Foundry keystore
//!    decryption (Web3 Secret Storage v3 / scrypt-then-AES-CTR) via
//!    `alloy-signer-local`. Same code path as P6's `chaincli publish`.
//! 3. [`BaseSepoliaAdapter::new_with_device_key`] — derives the EVM
//!    wallet from a Pangolin [`pangolin_crypto::keys::DeviceKey`]
//!    using [`crate::evm::derive_evm_wallet`]. This is the
//!    Pangolin-native path: one device key signs revisions AND pays
//!    gas (per D-006).

use std::path::{Path, PathBuf};

use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, Bytes, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{BlockNumberOrTag, Filter};
use alloy::signers::local::{LocalSigner, PrivateKeySigner};
use alloy::sol;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_crypto::sign::VerifyingKey;

use crate::adapter::ChainAdapter;
use crate::error::ChainError;
use crate::evm::derive_evm_wallet;
use crate::types::{ChainAnchor, EventLocation, RevisionEvent, SignedRevision, VaultId};

// ---------------------------------------------------------------------
// Solidity binding (mirror of tools/chaincli/src/contract.rs).
// ---------------------------------------------------------------------

sol! {
    /// Mirror of `contracts/src/RevisionLogV0.sol`. Audited 2026-05-05.
    /// MUST stay byte-for-byte aligned with the .sol source — see
    /// `tools/chaincli/src/contract.rs` for the same declaration in
    /// the binary-tool surface; if the two ever diverge that is a
    /// bug.
    #[sol(rpc)]
    contract RevisionLogV0 {
        function nextSequence() external view returns (uint256);

        function publishRevision(
            bytes32 vaultId,
            bytes32 accountId,
            bytes32 parentRevision,
            bytes32 deviceId,
            uint8 schemaVersion,
            bytes calldata encPayload
        ) external returns (uint256 sequence);

        event RevisionPublished(
            bytes32 indexed vaultId,
            bytes32 indexed accountId,
            bytes32 indexed parentRevision,
            bytes32 deviceId,
            uint8 schemaVersion,
            uint256 sequence,
            bytes encPayload
        );
    }
}

// ---------------------------------------------------------------------
// Deployment file loader
// ---------------------------------------------------------------------

/// Expected chain id for Base Sepolia. Same constant `tools/chaincli`
/// pins.
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;

/// Name under which `RevisionLogV0` is recorded in the deployment file.
const CONTRACT_NAME: &str = "RevisionLogV0";

/// Maximum block range per `eth_getLogs` call. Public Base Sepolia
/// caps at 10 000; we slightly under-shoot to be tolerant of
/// stricter providers. Same value chaincli uses.
const LOG_BLOCK_CHUNK: u64 = 9_000;

/// Parsed view of the canonical deployment metadata file.
///
/// Stored on the adapter so subsequent `publish` / `pull_since` calls
/// don't have to re-load it. Only the fields the adapter actually
/// uses are retained; everything else in the JSON is ignored.
#[derive(Debug, Clone)]
struct Deployment {
    chain_id: u64,
    contract_address: Address,
    deploy_block: u64,
    /// `bytecode.deployed_runtime_keccak256` — keccak256 of the
    /// runtime bytecode at the deployment's contract address as
    /// recorded at deploy time. Cross-checked at construction time
    /// against the live `eth_getCode` response (P7 audit MED-2).
    runtime_keccak: B256,
}

impl Deployment {
    /// Load + validate the deployment file at `path`.
    ///
    /// Validation rules (audit-safe defaults):
    /// - The file parses as JSON.
    /// - `chain.chain_id` equals [`BASE_SEPOLIA_CHAIN_ID`].
    /// - `contracts.RevisionLogV0.address` parses as an EVM address.
    /// - `contracts.RevisionLogV0.deploy_block` parses as `u64`.
    fn load(path: &Path) -> Result<Self, ChainError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| ChainError::Io(format!("read {}: {}", path.display(), e)))?;
        // We use `serde_json::Value` solely to navigate the JSON tree
        // — none of the deployment fields are payload-bearing
        // (per the audit constraint, no `serde::Deserialize` on chain
        // payload bytes).
        let value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| ChainError::Deployment(format!("invalid JSON: {e}")))?;

        let chain_id = value
            .pointer("/chain/chain_id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ChainError::Deployment("missing /chain/chain_id".into()))?;
        if chain_id != BASE_SEPOLIA_CHAIN_ID {
            return Err(ChainError::Deployment(format!(
                "deployment file declares chain_id {chain_id} (expected \
                 {BASE_SEPOLIA_CHAIN_ID} for Base Sepolia)"
            )));
        }

        let contract_path = format!("/contracts/{CONTRACT_NAME}");
        let contract = value
            .pointer(&contract_path)
            .ok_or_else(|| ChainError::Deployment(format!("missing {contract_path}")))?;

        let address_str = contract
            .pointer("/address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ChainError::Deployment(format!("missing {contract_path}/address")))?;
        // P7 audit MED-1: validate the EIP-55 (mixed-case) checksum,
        // not just hex shape. We pass `None` for the chain id because
        // the deployment file's address is plain EIP-55 (the form
        // Foundry, Etherscan, and the rest of the EVM toolchain emit
        // by default). Passing `Some(BASE_SEPOLIA_CHAIN_ID)` would
        // require the EIP-1191 chain-id-bound checksum variant, which
        // RSK and a few others use but which Foundry does not emit;
        // requiring it here would reject the canonical Pangolin
        // deployment file. A mis-checksummed address (anyone bit-
        // flipped a single hex character's case) is rejected; that's
        // the threat MED-1 names.
        let contract_address = Address::parse_checksummed(address_str, None).map_err(|e| {
            ChainError::Deployment(format!(
                "address {address_str} is not a valid EIP-55 checksummed EVM address: {e}"
            ))
        })?;

        let deploy_block = contract
            .pointer("/deploy_block")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ChainError::Deployment(format!("missing {contract_path}/deploy_block"))
            })?;

        // P7 audit MED-2: parse the recorded runtime keccak so the
        // constructor can cross-check it against the live
        // `eth_getCode` response. The chaincli `Deployment` struct
        // already parses the same field; this brings the production
        // library to parity.
        let runtime_keccak_str = contract
            .pointer("/bytecode/deployed_runtime_keccak256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ChainError::Deployment(format!(
                    "missing {contract_path}/bytecode/deployed_runtime_keccak256"
                ))
            })?;
        let runtime_keccak = runtime_keccak_str.parse::<B256>().map_err(|e| {
            ChainError::Deployment(format!(
                "deployed_runtime_keccak256 is not a valid 0x-prefixed 32-byte \
                 hex value: {runtime_keccak_str} ({e})"
            ))
        })?;

        Ok(Self {
            chain_id,
            contract_address,
            deploy_block,
            runtime_keccak,
        })
    }
}

// ---------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------

/// Production chain adapter. `Send + Sync` via the alloy provider's
/// internal `Arc`-shared transport.
pub struct BaseSepoliaAdapter {
    provider: DynProvider,
    deployment: Deployment,
    /// Optional signer. If `None`, `publish` fails.
    signer_address: Option<Address>,
}

impl core::fmt::Debug for BaseSepoliaAdapter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // We deliberately omit the alloy `provider` field — it is
        // network state, not diagnostic state, and its Debug includes
        // internal RPC client details that bloat logs without aiding
        // debugging. `finish_non_exhaustive` documents the omission.
        f.debug_struct("BaseSepoliaAdapter")
            .field("contract", &self.deployment.contract_address)
            .field("chain_id", &self.deployment.chain_id)
            .field("deploy_block", &self.deployment.deploy_block)
            .field("signer_address", &self.signer_address)
            .finish_non_exhaustive()
    }
}

impl BaseSepoliaAdapter {
    /// Construct a read-only adapter (no signer). `publish` fails
    /// with [`ChainError::Wallet`]; `pull_since` / `get_revision` /
    /// `current_block` work normally.
    pub async fn new_read_only(rpc_url: &str, deployment_path: &Path) -> Result<Self, ChainError> {
        let deployment = Deployment::load(deployment_path)?;
        let provider = ProviderBuilder::new()
            .connect(rpc_url)
            .await
            .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?;
        check_chain_id(&provider, &deployment).await?;
        // P7 audit MED-2: cross-check live runtime bytecode against
        // the deployment file's recorded keccak. Done after the
        // chain-id check so a wrong-chain mismatch has a chance to
        // surface a clearer diagnostic first.
        check_runtime_keccak(&provider, &deployment).await?;
        Ok(Self {
            provider: provider.erased(),
            deployment,
            signer_address: None,
        })
    }

    /// Construct an adapter that signs txs via a Foundry-format
    /// keystore. The password is borrowed (not consumed); the
    /// caller's `SecretBytes` retains ownership and zeroizes itself
    /// when its handle is dropped. `alloy-signer-local`'s
    /// `decrypt_keystore` only borrows the slice for the duration of
    /// the call.
    ///
    /// # Errors
    ///
    /// [`ChainError::Io`] if the keystore file is missing.
    /// [`ChainError::Keystore`] if decryption fails (wrong password,
    /// malformed file).
    /// [`ChainError::Rpc`] / [`ChainError::WrongChain`] for transport
    /// or chain-id failures.
    pub async fn new_with_keystore(
        rpc_url: &str,
        deployment_path: &Path,
        keystore_path: &Path,
        password: &SecretBytes,
    ) -> Result<Self, ChainError> {
        let deployment = Deployment::load(deployment_path)?;
        // P7 audit INFO-1: the password's lifecycle, accurately:
        //
        // - The caller's `SecretBytes` is what owns the password
        //   bytes and what zeroizes them — its `Drop` impl wipes the
        //   underlying buffer when the caller's handle goes away.
        //   Nothing here consumes that buffer.
        // - We hand `decrypt_keystore` a `&str` slice that borrows
        //   into the caller's buffer for the duration of the call.
        //   alloy / eth-keystore reads the bytes, runs the scrypt KDF,
        //   and decrypts; it never takes ownership of our slice.
        // - The decrypted secp256k1 secret key is internalized inside
        //   alloy's `LocalSigner` (a `k256::SecretKey` wrapper that is
        //   `ZeroizeOnDrop`); that's the only piece of secret material
        //   `decrypt_keystore` returns to us.
        //
        // Earlier comments here said "the password is consumed (and
        // zeroized) inside `decrypt_keystore`" — that was misleading.
        // The caller's `SecretBytes` is what zeroizes; the keystore
        // helper only borrows.
        let password_str = std::str::from_utf8(password.expose())
            .map_err(|_| ChainError::Keystore("keystore password is not valid utf-8".into()))?;
        let signer = LocalSigner::decrypt_keystore(keystore_path, password_str)
            .map_err(|e| ChainError::Keystore(format!("{e}")))?;
        Self::with_signer(rpc_url, deployment, signer).await
    }

    /// Construct an adapter signed by the EVM wallet derived from
    /// `device` per [`crate::evm::derive_evm_wallet`]. This is the
    /// Pangolin-native constructor used by the rest of the core.
    ///
    /// Same Pangolin device key always produces the same gas wallet
    /// (D-006).
    pub async fn new_with_device_key(
        rpc_url: &str,
        deployment_path: &Path,
        device: &DeviceKey,
    ) -> Result<Self, ChainError> {
        let deployment = Deployment::load(deployment_path)?;
        let wallet = derive_evm_wallet(device)?;
        Self::with_signer(rpc_url, deployment, wallet.into_signer()).await
    }

    /// Shared internal constructor: build a wallet-bearing provider
    /// and verify chain id + live bytecode.
    async fn with_signer(
        rpc_url: &str,
        deployment: Deployment,
        signer: PrivateKeySigner,
    ) -> Result<Self, ChainError> {
        let signer_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(rpc_url)
            .await
            .map_err(|e| ChainError::Rpc(format!("connect {rpc_url}: {e}")))?;
        check_chain_id(&provider, &deployment).await?;
        // P7 audit MED-2: cross-check live runtime bytecode against
        // the deployment file's recorded keccak. Same fail-closed
        // posture as the chain-id check above. Adds one extra RPC
        // call per `BaseSepoliaAdapter` construction; production
        // hardening cost.
        check_runtime_keccak(&provider, &deployment).await?;
        Ok(Self {
            provider: provider.erased(),
            deployment,
            signer_address: Some(signer_address),
        })
    }

    /// Resolve the canonical `contracts/deployments/base-sepolia.json`
    /// by walking up from `start` until found. Mirrors chaincli's
    /// `Deployment::find_default`.
    pub fn find_deployment_file(start: &Path) -> Option<PathBuf> {
        let mut cur: Option<&Path> = Some(start);
        while let Some(dir) = cur {
            let candidate = dir
                .join("contracts")
                .join("deployments")
                .join("base-sepolia.json");
            if candidate.is_file() {
                return Some(candidate);
            }
            cur = dir.parent();
        }
        None
    }

    /// Address of the wallet (or `None` for read-only adapters).
    /// Useful for diagnostic logging at the adapter callsite.
    #[must_use]
    pub fn signer_address(&self) -> Option<Address> {
        self.signer_address
    }

    /// Block number at which the contract was deployed. `pull_since`
    /// callers can use this as the lower-bound floor for their
    /// initial sync.
    #[must_use]
    pub fn deploy_block(&self) -> u64 {
        self.deployment.deploy_block
    }
}

#[async_trait]
impl ChainAdapter for BaseSepoliaAdapter {
    async fn publish(&self, signed: &SignedRevision) -> Result<ChainAnchor, ChainError> {
        if self.signer_address.is_none() {
            return Err(ChainError::Wallet(
                "BaseSepoliaAdapter was constructed read-only — no signer available",
            ));
        }
        let contract = RevisionLogV0::new(self.deployment.contract_address, &self.provider);
        let pending = contract
            .publishRevision(
                signed.vault_id.into(),
                signed.account_id.into(),
                signed.parent_revision.into(),
                signed.device_id.into(),
                signed.schema_version,
                Bytes::from(signed.enc_payload.clone()),
            )
            .send()
            .await
            .map_err(|e| ChainError::Rpc(format!("publishRevision broadcast: {e}")))?;
        let tx_hash: B256 = *pending.tx_hash();
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| ChainError::Rpc(format!("get_receipt: {e}")))?;
        if !receipt.status() {
            return Err(ChainError::Reverted {
                tx_hash: format!("{tx_hash:?}"),
            });
        }
        let target_topic = RevisionLogV0::RevisionPublished::SIGNATURE_HASH;
        let log = receipt
            .inner
            .logs()
            .iter()
            .find(|l| {
                l.address() == self.deployment.contract_address
                    && l.topics().first().copied() == Some(target_topic)
            })
            .ok_or_else(|| ChainError::MissingEvent {
                tx_hash: format!("{tx_hash:?}"),
            })?;
        let decoded = RevisionLogV0::RevisionPublished::decode_log(&log.inner)
            .map_err(|e| ChainError::Decode(format!("RevisionPublished log: {e}")))?;
        let sequence = u64::try_from(decoded.sequence)
            .map_err(|_| ChainError::Decode("sequence does not fit in u64".into()))?;
        let block_number = receipt.block_number.ok_or_else(|| {
            ChainError::Decode("receipt missing block_number after status==1".into())
        })?;
        let log_index = log
            .log_index
            .ok_or_else(|| ChainError::Decode("RevisionPublished log missing log_index".into()))?;
        Ok(ChainAnchor {
            tx_hash: tx_hash.0,
            block_number,
            log_index,
            sequence,
        })
    }

    async fn pull_since(
        &self,
        vault_id: &VaultId,
        from_block: u64,
        until_block: Option<u64>,
    ) -> Result<Vec<RevisionEvent>, ChainError> {
        // Resolve `until` to a concrete block. The trait says
        // `from_block` is exclusive; alloy's `from_block` filter is
        // inclusive, so we kick the cursor up by one to honor the
        // exclusive-lower contract.
        let to_block = if let Some(t) = until_block {
            t
        } else {
            self.provider
                .get_block_number()
                .await
                .map_err(|e| ChainError::Rpc(format!("eth_blockNumber: {e}")))?
        };
        let mut cursor = from_block.saturating_add(1);
        if cursor > to_block {
            return Ok(Vec::new());
        }
        let topic1: B256 = (*vault_id).into();
        let mut out: Vec<RevisionEvent> = Vec::new();
        while cursor <= to_block {
            let chunk_end = cursor.saturating_add(LOG_BLOCK_CHUNK - 1).min(to_block);
            let filter = Filter::new()
                .address(self.deployment.contract_address)
                .event_signature(RevisionLogV0::RevisionPublished::SIGNATURE_HASH)
                .from_block(BlockNumberOrTag::Number(cursor))
                .to_block(BlockNumberOrTag::Number(chunk_end))
                .topic1(topic1);
            let logs =
                self.provider.get_logs(&filter).await.map_err(|e| {
                    ChainError::Rpc(format!("eth_getLogs {cursor}..={chunk_end}: {e}"))
                })?;
            for log in logs {
                // Audit MEDIUM-4: defensive emitter check. Server-side
                // filter already excluded other addresses; a misbehaving
                // RPC could splice in foreign logs. Drop without
                // surfacing — the chain-side filter is the source of
                // truth, this is belt-and-braces.
                if log.address() != self.deployment.contract_address {
                    continue;
                }
                let decoded = RevisionLogV0::RevisionPublished::decode_log(&log.inner)
                    .map_err(|e| ChainError::Decode(format!("log decode: {e}")))?;
                let sequence = u64::try_from(decoded.sequence)
                    .map_err(|_| ChainError::Decode("sequence does not fit in u64".into()))?;
                let block_number = log
                    .block_number
                    .ok_or_else(|| ChainError::Decode("log missing block_number".into()))?;
                let log_index = log
                    .log_index
                    .ok_or_else(|| ChainError::Decode("log missing log_index".into()))?;
                let tx_hash = log
                    .transaction_hash
                    .ok_or_else(|| ChainError::Decode("log missing transaction_hash".into()))?;
                // P7 audit MED-5: validate the `device_id` bytes are
                // a canonical Ed25519 verifying-key encoding *here*
                // (at the adapter boundary) so downstream consumers
                // (P8 sync, indexer, etc.) can rely on the invariant
                // and don't have to re-check at every callsite. v0
                // contract does not enforce this; v1 will (MVP-2).
                // Catch it now so a P8 consumer doesn't panic on a
                // non-canonical pubkey when it tries to verify the
                // signature.
                let device_id_bytes: [u8; 32] = decoded.deviceId.into();
                if VerifyingKey::from_bytes(device_id_bytes).is_err() {
                    return Err(ChainError::Decode(format!(
                        "device_id is not a canonical Ed25519 verifying key: \
                         0x{}",
                        bytes_to_hex(&device_id_bytes)
                    )));
                }
                out.push(RevisionEvent {
                    vault_id: decoded.vaultId.into(),
                    account_id: decoded.accountId.into(),
                    parent_revision: decoded.parentRevision.into(),
                    device_id: device_id_bytes,
                    schema_version: decoded.schemaVersion,
                    sequence,
                    enc_payload: decoded.encPayload.to_vec(),
                    anchor: ChainAnchor {
                        tx_hash: tx_hash.0,
                        block_number,
                        log_index,
                        sequence,
                    },
                });
            }
            if chunk_end == to_block {
                break;
            }
            cursor = chunk_end + 1;
        }
        Ok(out)
    }

    async fn get_revision(
        &self,
        location: &EventLocation,
    ) -> Result<Option<RevisionEvent>, ChainError> {
        let tx_hash: B256 = location.tx_hash.into();
        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| ChainError::Rpc(format!("eth_getTransactionReceipt: {e}")))?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        let target_topic = RevisionLogV0::RevisionPublished::SIGNATURE_HASH;
        let log_opt = receipt
            .inner
            .logs()
            .iter()
            .find(|l| {
                l.address() == self.deployment.contract_address
                    && l.topics().first().copied() == Some(target_topic)
                    && l.log_index == Some(location.log_index)
            })
            .cloned();
        let Some(log) = log_opt else {
            return Ok(None);
        };
        let decoded = RevisionLogV0::RevisionPublished::decode_log(&log.inner)
            .map_err(|e| ChainError::Decode(format!("log decode: {e}")))?;
        let sequence = u64::try_from(decoded.sequence)
            .map_err(|_| ChainError::Decode("sequence does not fit in u64".into()))?;
        let block_number = log
            .block_number
            .ok_or_else(|| ChainError::Decode("log missing block_number".into()))?;
        // P7 audit MED-5: same canonical-Ed25519 check as in
        // `pull_since`. See that function's MED-5 comment for
        // rationale.
        let device_id_bytes: [u8; 32] = decoded.deviceId.into();
        if VerifyingKey::from_bytes(device_id_bytes).is_err() {
            return Err(ChainError::Decode(format!(
                "device_id is not a canonical Ed25519 verifying key: 0x{}",
                bytes_to_hex(&device_id_bytes)
            )));
        }
        Ok(Some(RevisionEvent {
            vault_id: decoded.vaultId.into(),
            account_id: decoded.accountId.into(),
            parent_revision: decoded.parentRevision.into(),
            device_id: device_id_bytes,
            schema_version: decoded.schemaVersion,
            sequence,
            enc_payload: decoded.encPayload.to_vec(),
            anchor: ChainAnchor {
                tx_hash: location.tx_hash,
                block_number,
                log_index: location.log_index,
                sequence,
            },
        }))
    }

    async fn current_block(&self) -> Result<u64, ChainError> {
        self.provider
            .get_block_number()
            .await
            .map_err(|e| ChainError::Rpc(format!("eth_blockNumber: {e}")))
    }

    /// **MVP-2 issue 5.1 R-e — pre-flight batch balance gate.**
    ///
    /// Uses the existing 3.5 helpers `query_evm_balance_with_provider`
    /// + `estimate_next_publish_cost_with_provider` against the
    /// adapter's already-held alloy provider (no new RPC connection).
    /// Returns `Ok(None)` only on read-only adapter (no signer
    /// address); production write-capable adapters always return
    /// `Ok(Some(...))`. `U256`-to-`u128` conversion saturates at
    /// `u128::MAX` for defense-in-depth (vanishingly impractical for
    /// either balance or estimate to exceed `u128::MAX` wei).
    async fn pre_flight_batch_balance(
        &self,
        queued_count: usize,
    ) -> Result<Option<crate::adapter::BatchBalanceCheck>, ChainError> {
        // Read-only adapter cannot publish at all, so the pre-flight
        // gate is moot. Returning None lets the flush proceed to
        // publish_one which will surface ChainError::Wallet per row.
        let Some(address) = self.signer_address else {
            return Ok(None);
        };

        // BaseSepoliaAdapter is unambiguously the BaseSepolia env;
        // the deployment file's chain_id is asserted at construction
        // to equal BASE_SEPOLIA_CHAIN_ID.
        let env = crate::ChainEnv::BaseSepolia;

        let per_revision_estimate =
            crate::balance_check::estimate_next_publish_cost_with_provider(&self.provider, env)
                .await?;

        let balance =
            crate::balance_check::query_evm_balance_with_provider(&self.provider, address, env)
                .await?;

        let queued_count_u256 = alloy::primitives::U256::from(queued_count as u64);
        let total_cost = per_revision_estimate.saturating_mul(queued_count_u256);

        let total_estimated_cost_wei: u128 = total_cost.try_into().unwrap_or(u128::MAX);
        let current_balance_wei: u128 = balance.try_into().unwrap_or(u128::MAX);

        Ok(Some(crate::adapter::BatchBalanceCheck {
            total_estimated_cost_wei,
            current_balance_wei,
        }))
    }
}

/// Lowercase-hex encode a fixed-size byte slice without pulling a
/// `hex` crate dep. Used by the MED-5 device-id-rejection diagnostic.
fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        // SAFETY of unwrap: writing two hex chars to a String never
        // fails. Using `core::fmt::Write` so we don't pull `format!`
        // into a tight loop.
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Confirm that the RPC's reported chain id matches the deployment.
async fn check_chain_id<P: Provider>(
    provider: &P,
    deployment: &Deployment,
) -> Result<(), ChainError> {
    let observed = provider
        .get_chain_id()
        .await
        .map_err(|e| ChainError::Rpc(format!("eth_chainId: {e}")))?;
    if observed != deployment.chain_id {
        return Err(ChainError::WrongChain {
            expected: deployment.chain_id,
            observed,
        });
    }
    Ok(())
}

/// P7 audit MED-2: cross-check live runtime bytecode against the
/// deployment file's recorded `deployed_runtime_keccak256`.
///
/// `eth_getCode(deployment.contract_address)` returns the runtime
/// bytecode at the address (the post-constructor bytes that actually
/// execute on call). We hash it with keccak256 and compare against the
/// recorded value. A mismatch returns
/// [`ChainError::DeploymentMismatch`] with both digests, formatted
/// as 0x-prefixed hex so the operator can paste them into `cast`.
///
/// This catches three threat profiles:
///
/// 1. **Tampered deployment file** redirecting the adapter to a
///    foreign contract on the same chain that happens to expose the
///    same selectors.
/// 2. **CREATE2 redeployment collision** at the recorded address but
///    with substituted code.
/// 3. **Misbehaving / MITM'd RPC** rewriting `eth_getCode` to point
///    at attacker-controlled bytecode (the cross-check fails closed
///    because the recorded keccak in the deployment file is signed
///    out-of-band by the workspace history, not by the RPC).
///
/// Cost: one extra `eth_getCode` per `BaseSepoliaAdapter` construction.
/// Acceptable for production hardening — chaincli has done the same
/// check in `commands/status.rs` since P6.
async fn check_runtime_keccak<P: Provider>(
    provider: &P,
    deployment: &Deployment,
) -> Result<(), ChainError> {
    let live_code = provider
        .get_code_at(deployment.contract_address)
        .await
        .map_err(|e| {
            ChainError::Rpc(format!(
                "eth_getCode {:?}: {e}",
                deployment.contract_address
            ))
        })?;
    let live_keccak: B256 = keccak256(live_code.as_ref());
    if live_keccak != deployment.runtime_keccak {
        return Err(ChainError::DeploymentMismatch {
            expected: format!("{:?}", deployment.runtime_keccak),
            found: format!("{live_keccak:?}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Deployment, BASE_SEPOLIA_CHAIN_ID};
    use crate::error::ChainError;

    /// The canonical workspace deployment file parses cleanly and
    /// matches the recorded chain id + contract address.
    #[test]
    fn workspace_deployment_file_parses() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("CARGO_MANIFEST_DIR has at least two ancestors")
            .join("contracts")
            .join("deployments")
            .join("base-sepolia.json");
        let dep = Deployment::load(&path).expect("real deployment file parses");
        assert_eq!(dep.chain_id, BASE_SEPOLIA_CHAIN_ID);
        // The contract address is the canonical Base Sepolia
        // RevisionLogV0 deployment.
        assert_eq!(
            format!("{:?}", dep.contract_address).to_ascii_lowercase(),
            "0x8566d3de653ee55775783bd7918fe91b66373896"
        );
        assert!(dep.deploy_block > 0, "deploy_block must be set");
        // P7 audit MED-2: the recorded runtime keccak parses and
        // matches the canonical value cross-checked by chaincli's
        // status command.
        assert_eq!(
            format!("{:?}", dep.runtime_keccak).to_ascii_lowercase(),
            "0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe"
        );
    }

    /// A deployment file declaring a wrong chain id is rejected at
    /// load time, not later.
    #[test]
    fn wrong_chain_id_rejected_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let json = r#"{
            "chain": { "chain_id": 1, "rpc_default": "https://x" },
            "contracts": {
                "RevisionLogV0": {
                    "address": "0x8566D3de653ee55775783bD7918Fe91b66373896",
                    "deploy_block": 1
                }
            }
        }"#;
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write");
        let err = Deployment::load(&p).expect_err("wrong chain id rejected");
        let msg = format!("{err}");
        assert!(
            matches!(err, ChainError::Deployment(_)),
            "expected Deployment error, got: {msg}"
        );
        assert!(
            msg.contains("chain_id"),
            "expected chain_id message, got: {msg}"
        );
    }

    /// A missing `contracts.RevisionLogV0` is rejected.
    #[test]
    fn missing_contract_record_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let json = r#"{ "chain": { "chain_id": 84532, "rpc_default": "x" }, "contracts": {} }"#;
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write");
        let err = Deployment::load(&p).expect_err("missing contract rejected");
        assert!(matches!(err, ChainError::Deployment(_)));
    }

    /// `find_deployment_file` walks upward and returns Some when run
    /// from inside the workspace.
    #[test]
    fn find_deployment_walks_upward() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // CARGO_MANIFEST_DIR == crates/pangolin-chain. Walking up
        // should find contracts/deployments/base-sepolia.json at the
        // workspace root.
        let found = super::BaseSepoliaAdapter::find_deployment_file(&manifest);
        assert!(found.is_some(), "should find the canonical deployment file");
        let path = found.unwrap();
        assert!(path.is_file());
        assert!(path.to_string_lossy().contains("base-sepolia.json"));
    }

    /// Malformed JSON is rejected with a clean error.
    #[test]
    fn malformed_json_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, b"{ not valid").expect("write");
        let err = Deployment::load(&p).expect_err("bad json rejected");
        assert!(matches!(err, ChainError::Deployment(_)));
    }

    /// IO errors (missing file) surface as `ChainError::Io`, not
    /// `ChainError::Deployment`, so callers can distinguish
    /// "deployment file missing entirely" from "deployment file
    /// present but malformed".
    #[test]
    fn missing_file_yields_io_error() {
        let p = std::path::Path::new("/no/such/path/base-sepolia.json");
        let err = Deployment::load(p).expect_err("missing file rejected");
        assert!(
            matches!(err, ChainError::Io(_)),
            "expected ChainError::Io for missing file, got: {err:?}"
        );
    }

    /// P7 audit MED-2: a deployment file missing
    /// `bytecode.deployed_runtime_keccak256` is rejected at load
    /// time. The constructor's runtime-keccak cross-check needs this
    /// field; refusing to load a file that doesn't carry it is the
    /// fail-closed posture.
    #[test]
    fn missing_runtime_keccak_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let json = r#"{
            "chain": { "chain_id": 84532, "rpc_default": "https://x" },
            "contracts": {
                "RevisionLogV0": {
                    "address": "0x8566D3de653ee55775783bD7918Fe91b66373896",
                    "deploy_block": 1
                }
            }
        }"#;
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write");
        let err = Deployment::load(&p).expect_err("missing runtime keccak rejected");
        let msg = format!("{err}");
        assert!(
            matches!(err, ChainError::Deployment(_)),
            "expected Deployment error, got: {msg}"
        );
        assert!(
            msg.contains("deployed_runtime_keccak256"),
            "expected runtime-keccak missing message, got: {msg}"
        );
    }

    /// P7 audit MED-2: a deployment file whose runtime keccak is not
    /// a valid 0x-prefixed 32-byte hex string is rejected.
    #[test]
    fn malformed_runtime_keccak_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let json = r#"{
            "chain": { "chain_id": 84532, "rpc_default": "https://x" },
            "contracts": {
                "RevisionLogV0": {
                    "address": "0x8566D3de653ee55775783bD7918Fe91b66373896",
                    "deploy_block": 1,
                    "bytecode": {
                        "deployed_runtime_keccak256": "not-a-hex-string"
                    }
                }
            }
        }"#;
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write");
        let err = Deployment::load(&p).expect_err("malformed keccak rejected");
        let msg = format!("{err}");
        assert!(
            matches!(err, ChainError::Deployment(_)),
            "expected Deployment error, got: {msg}"
        );
        assert!(
            msg.contains("not a valid 0x-prefixed"),
            "expected hex-parse error, got: {msg}"
        );
    }

    /// P7 audit MED-2: the `check_runtime_keccak` helper computes the
    /// digest of the live bytecode and compares against the
    /// deployment record. We can't reach the live network from a unit
    /// test, so this checks the helper's *comparison* logic by
    /// running an in-process anvil-style provider via alloy's
    /// `MockProvider` is similarly out-of-scope; instead we assert
    /// the construction-time wiring at the type level by ensuring
    /// `DeploymentMismatch` carries both digests as 0x-prefixed
    /// strings and round-trips through `Display`. Live cross-check
    /// is exercised by the gated integration test.
    #[test]
    fn deployment_mismatch_error_format() {
        let err = ChainError::DeploymentMismatch {
            expected: "0xaaaa".into(),
            found: "0xbbbb".into(),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("0xaaaa"),
            "expected 'expected' field in msg: {msg}"
        );
        assert!(
            msg.contains("0xbbbb"),
            "expected 'found' field in msg: {msg}"
        );
        assert!(
            msg.contains("keccak"),
            "message should reference keccak: {msg}"
        );
    }

    /// P7 audit MED-1: a deployment file whose contract address has
    /// the right hex bytes but a wrong EIP-55 checksum is rejected at
    /// load time. The canonical address has mixed case
    /// (`0x8566D3de...`); flipping it to all-lowercase breaks the
    /// EIP-55 invariant and must trip `Address::parse_checksummed`.
    #[test]
    fn mis_checksummed_address_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Same hex bytes as the canonical address but with the
        // checksum case mangled (all-lowercase). Plain `parse::<Address>()`
        // would accept this (it's still 20 valid hex bytes); EIP-55
        // checksummed parsing must reject it.
        let json = r#"{
            "chain": { "chain_id": 84532, "rpc_default": "https://x" },
            "contracts": {
                "RevisionLogV0": {
                    "address": "0x8566d3de653ee55775783bd7918fe91b66373896",
                    "deploy_block": 1
                }
            }
        }"#;
        let p = dir.path().join("base-sepolia.json");
        std::fs::write(&p, json).expect("write");
        let err = Deployment::load(&p).expect_err("mis-checksummed address rejected");
        let msg = format!("{err}");
        assert!(
            matches!(err, ChainError::Deployment(_)),
            "expected Deployment error, got: {msg}"
        );
        assert!(
            msg.contains("EIP-55"),
            "expected EIP-55-checksum error message, got: {msg}"
        );
    }
}
