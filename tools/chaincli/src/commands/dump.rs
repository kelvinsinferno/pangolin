//! `chaincli dump --tx <hash>` (or `--block N --log-index I`) — fetch
//! and pretty-print a single `RevisionPublished` event.
//!
//! Selectors are mutually exclusive: either `--tx` OR
//! (`--block` + `--log-index`), enforced via clap's argument groups.

use alloy::primitives::{keccak256, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{BlockNumberOrTag, Filter};
use alloy::sol_types::SolEvent;
use anyhow::{anyhow, bail, Context, Result};
use clap::Args;

use crate::client::Deployment;
use crate::contract::RevisionLogV0;
use crate::format::{b64_encode, ListedRevision};

#[derive(Debug, Clone, Args)]
#[group(required = true, multiple = false)]
pub struct DumpSelector {
    /// Transaction hash containing the revision event.
    #[arg(long)]
    pub tx: Option<B256>,
    /// Block number — must be paired with `--log-index`.
    #[arg(long, requires = "log_index")]
    pub block: Option<u64>,
}

#[derive(Debug, Clone, Args)]
pub struct DumpArgs {
    #[command(flatten)]
    pub selector: DumpSelector,

    /// `--log-index <i>` — the log's position within the block. Only
    /// meaningful when paired with `--block`.
    #[arg(long, requires = "block")]
    pub log_index: Option<u64>,

    /// Emit a single JSON object instead of the human-readable form.
    #[arg(long)]
    pub json: bool,
}

/// Run the `dump` sub-command.
pub async fn run(deployment: &Deployment, rpc_url: &str, args: DumpArgs) -> Result<()> {
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .with_context(|| format!("failed to connect to RPC at {rpc_url}"))?;

    let log = if let Some(tx_hash) = args.selector.tx {
        let receipt = provider
            .get_transaction_receipt(tx_hash)
            .await
            .context("eth_getTransactionReceipt RPC call failed")?
            .ok_or_else(|| anyhow!("transaction {tx_hash:?} not found"))?;
        // Find the FIRST RevisionPublished log in the receipt.
        let target_topic = RevisionLogV0::RevisionPublished::SIGNATURE_HASH;
        receipt
            .inner
            .logs()
            .iter()
            .find(|l| {
                l.address() == deployment.contract_address
                    && l.topics().first().copied() == Some(target_topic)
            })
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "transaction {tx_hash:?} has no RevisionPublished log emitted by {:?}",
                    deployment.contract_address
                )
            })?
    } else {
        let block = args
            .selector
            .block
            .ok_or_else(|| anyhow!("internal: --block missing despite clap group"))?;
        let log_index = args
            .log_index
            .ok_or_else(|| anyhow!("internal: --log-index missing despite clap group"))?;
        let filter = Filter::new()
            .address(deployment.contract_address)
            .event_signature(RevisionLogV0::RevisionPublished::SIGNATURE_HASH)
            .from_block(BlockNumberOrTag::Number(block))
            .to_block(BlockNumberOrTag::Number(block));
        let logs = provider
            .get_logs(&filter)
            .await
            .context("eth_getLogs RPC call failed")?;
        logs.into_iter()
            .find(|l| l.log_index == Some(log_index))
            .ok_or_else(|| {
                anyhow!(
                    "no RevisionPublished log at (block {block}, log_index {log_index}) on {:?}",
                    deployment.contract_address
                )
            })?
    };

    if log.address() != deployment.contract_address {
        bail!(
            "log emitter {:?} does not match deployment contract {:?}",
            log.address(),
            deployment.contract_address
        );
    }

    let decoded = RevisionLogV0::RevisionPublished::decode_log(&log.inner)
        .context("log did not decode as RevisionPublished")?;
    let payload_bytes = decoded.encPayload.to_vec();
    let payload_keccak = keccak256(&payload_bytes);
    let row = ListedRevision {
        sequence: u64::try_from(decoded.sequence)
            .map_err(|_| anyhow!("sequence does not fit in u64"))?,
        block: log.block_number.unwrap_or_default(),
        log_index: log.log_index.unwrap_or_default(),
        tx: log.transaction_hash.unwrap_or_default(),
        vault_id: decoded.vaultId,
        account_id: decoded.accountId,
        parent_revision: decoded.parentRevision,
        device_id: decoded.deviceId,
        schema_version: decoded.schemaVersion,
        payload: payload_bytes,
        payload_keccak,
    };

    if args.json {
        println!("{}", row.to_jsonl());
    } else {
        // Text dump format includes both hex AND base64 of the
        // payload, per the plan's `chaincli dump` example.
        println!(
            "RevisionPublished event in block {} of {:?}:",
            row.block, deployment.contract_address
        );
        println!("  vaultId           : {:?}", row.vault_id);
        println!("  accountId         : {:?}", row.account_id);
        println!("  parentRevision    : {:?}", row.parent_revision);
        println!("  deviceId          : {:?}", row.device_id);
        println!("  schemaVersion     : {}", row.schema_version);
        println!("  sequence          : {}", row.sequence);
        println!("  encPayload (hex)  : {}", hex::encode(&row.payload));
        println!("  encPayload (b64)  : {}", b64_encode(&row.payload));
        println!("  payload_keccak256 : {:?}", row.payload_keccak);
        println!("  log_index         : {}", row.log_index);
        println!("  tx                : {:?}", row.tx);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DumpArgs;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(subcommand)]
        cmd: HarnessSub,
    }

    #[derive(Debug, clap::Subcommand)]
    enum HarnessSub {
        Dump(DumpArgs),
    }

    fn parse(args: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
    }

    #[test]
    fn tx_or_block_log_index_required() {
        // Empty selectors → clap's required group fails.
        let err = parse(&["dump"]).expect_err("no selector should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("--tx") || msg.contains("--block"),
            "expected required-group error mentioning --tx/--block: {msg}"
        );
    }

    #[test]
    fn tx_alone_parses() {
        let _ = parse(&[
            "dump",
            "--tx",
            "0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6",
        ])
        .expect("--tx alone parses");
    }

    #[test]
    fn block_and_log_index_pair_parses() {
        let _ = parse(&["dump", "--block", "41133109", "--log-index", "1"])
            .expect("--block --log-index pair parses");
    }

    #[test]
    fn block_without_log_index_rejected() {
        // clap's `requires = "log_index"` should fire.
        let err = parse(&["dump", "--block", "41133109"])
            .expect_err("--block without --log-index should fail");
        assert!(format!("{err}").contains("--log-index"));
    }

    #[test]
    fn tx_and_block_mutually_exclusive() {
        let err = parse(&[
            "dump",
            "--tx",
            "0x5cb4a7f4242838303964a7196b5326380b72d803d5d2e8f73d2c9d46664f7ba6",
            "--block",
            "41133109",
            "--log-index",
            "1",
        ])
        .expect_err("--tx + --block must be mutually exclusive");
        let msg = format!("{err}");
        assert!(
            msg.contains("cannot be used with") || msg.contains("--tx") || msg.contains("--block"),
            "expected mutual-exclusion error: {msg}"
        );
    }
}
