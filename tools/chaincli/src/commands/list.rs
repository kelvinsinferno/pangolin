//! `chaincli list --vault-id <0x...>` — query `RevisionPublished` events
//! filtered by `vaultId`. Output: JSON-Lines by default; `--text` for
//! a tabular human form.

use alloy::primitives::{keccak256, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::client::Deployment;
use crate::contract::RevisionLogV0;
use crate::format::{Format, ListedRevision};

#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Vault id to filter on (32-byte hex, 0x-prefixed). Required —
    /// chaincli refuses to dump every revision in the contract.
    #[arg(long, value_parser = parse_b256)]
    pub vault_id: B256,

    /// Optional account-id refiner (32-byte hex).
    #[arg(long, value_parser = parse_b256)]
    pub account_id: Option<B256>,

    /// Earliest block to scan from. Defaults to the contract's
    /// `deploy_block` per the deployment file (no point scanning older
    /// blocks — the contract didn't exist).
    #[arg(long)]
    pub from_block: Option<u64>,

    /// Latest block to scan to. Defaults to `latest` (most recent
    /// canonical block at the time of the call).
    #[arg(long)]
    pub to_block: Option<u64>,

    /// Output format. `jsonl` (default) is one JSON object per line;
    /// `text` is human-readable multi-line per record.
    #[arg(long, value_enum, default_value_t = FormatArg::Jsonl)]
    pub format: FormatArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FormatArg {
    Jsonl,
    Text,
}

impl From<FormatArg> for Format {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Jsonl => Self::Jsonl,
            FormatArg::Text => Self::Text,
        }
    }
}

fn parse_b256(s: &str) -> Result<B256, String> {
    s.parse::<B256>()
        .map_err(|e| format!("not a 32-byte 0x-prefixed hex value: {e}"))
}

/// Public Base Sepolia caps `eth_getLogs` at a `10_000`-block range
/// per call. We chunk so the user doesn't have to think about it.
/// Chosen to be slightly under the cap so providers with stricter
/// limits (most have 9k or 10k) still answer.
const BLOCK_CHUNK: u64 = 9_000;

/// Run the `list` sub-command.
pub async fn run(deployment: &Deployment, rpc_url: &str, args: ListArgs) -> Result<()> {
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .with_context(|| format!("failed to connect to RPC at {rpc_url}"))?;

    let from_block = args.from_block.unwrap_or(deployment.deploy_block);
    let to_block = if let Some(t) = args.to_block {
        t
    } else {
        provider
            .get_block_number()
            .await
            .context("eth_blockNumber RPC call failed")?
    };
    if from_block > to_block {
        return Err(anyhow!(
            "from_block ({from_block}) is greater than to_block ({to_block})"
        ));
    }

    let format: Format = args.format.into();
    let mut cursor = from_block;
    while cursor <= to_block {
        let chunk_end = cursor.saturating_add(BLOCK_CHUNK - 1).min(to_block);
        let mut filter = Filter::new()
            .address(deployment.contract_address)
            .event_signature(RevisionLogV0::RevisionPublished::SIGNATURE_HASH)
            .from_block(cursor)
            .to_block(chunk_end)
            .topic1(args.vault_id);
        if let Some(acct) = args.account_id {
            filter = filter.topic2(acct);
        }

        let logs = provider.get_logs(&filter).await.with_context(|| {
            format!("eth_getLogs RPC call failed for blocks {cursor}..={chunk_end}")
        })?;

        for log in logs {
            let decoded =
                RevisionLogV0::RevisionPublished::decode_log(&log.inner).with_context(|| {
                    format!(
                        "log at block {:?} index {:?} did not decode as RevisionPublished",
                        log.block_number, log.log_index
                    )
                })?;
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
            match format {
                Format::Jsonl => println!("{}", row.to_jsonl()),
                Format::Text => println!("{}", row.to_text()),
            }
        }

        if chunk_end == to_block {
            break;
        }
        cursor = chunk_end + 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_b256, ListArgs};
    use alloy::primitives::B256;
    use clap::Parser;

    /// Wrap `ListArgs` in a tiny harness so clap parses argv as a real
    /// sub-command would. Mirrors how the real binary invokes it.
    #[derive(Debug, Parser)]
    struct Harness {
        #[command(subcommand)]
        cmd: HarnessSub,
    }

    #[derive(Debug, clap::Subcommand)]
    enum HarnessSub {
        List(ListArgs),
    }

    fn parse(args: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
    }

    #[test]
    fn arg_parsing_required_vault_id() {
        // No --vault-id → clap rejects.
        let err = parse(&["list"]).expect_err("missing --vault-id should fail");
        assert!(format!("{err}").contains("--vault-id"));
    }

    #[test]
    fn arg_parsing_happy_path() {
        let args = parse(&[
            "list",
            "--vault-id",
            "0xaaaa000000000000000000000000000000000000000000000000000000000000",
        ])
        .expect("happy path parses");
        match args.cmd {
            HarnessSub::List(a) => {
                assert_eq!(
                    a.vault_id,
                    B256::from_slice(&{
                        let mut b = [0u8; 32];
                        b[0] = 0xaa;
                        b[1] = 0xaa;
                        b
                    })
                );
                assert!(a.account_id.is_none());
                assert!(a.from_block.is_none());
                assert_eq!(a.format, super::FormatArg::Jsonl);
            }
        }
    }

    #[test]
    fn arg_parsing_full_refiners() {
        let args = parse(&[
            "list",
            "--vault-id",
            "0xaaaa000000000000000000000000000000000000000000000000000000000000",
            "--account-id",
            "0xbbbb000000000000000000000000000000000000000000000000000000000000",
            "--from-block",
            "12345",
            "--to-block",
            "67890",
            "--format",
            "text",
        ])
        .expect("full-flag parse");
        match args.cmd {
            HarnessSub::List(a) => {
                assert!(a.account_id.is_some());
                assert_eq!(a.from_block, Some(12_345));
                assert_eq!(a.to_block, Some(67_890));
                assert_eq!(a.format, super::FormatArg::Text);
            }
        }
    }

    #[test]
    fn arg_parsing_invalid_vault_id_rejected() {
        let err = parse(&["list", "--vault-id", "not-a-hex"])
            .expect_err("non-hex --vault-id should fail");
        assert!(format!("{err}").contains("not a 32-byte"));
    }

    #[test]
    fn parse_b256_zero() {
        let z = parse_b256("0x0000000000000000000000000000000000000000000000000000000000000000")
            .expect("zero parses");
        assert_eq!(z, B256::ZERO);
    }
}
