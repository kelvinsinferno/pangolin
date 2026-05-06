//! `chaincli publish` — write a new revision to the deployed contract.
//!
//! Wallet handling matches P5-4 byte-for-byte:
//! - `--account <name>` resolves to `~/.foundry/keystores/<name>` on
//!   Linux/macOS and `%USERPROFILE%\.foundry\keystores\<name>` on
//!   Windows. The `--keystore-path <path>` flag overrides the
//!   directory lookup for tests.
//! - The keystore password is read from the terminal without echo via
//!   `rpassword`. **Never** from an env var, **never** from argv,
//!   **never** written to disk in plaintext, **never** logged.
//! - `LocalSigner::decrypt_keystore` does the actual decryption inside
//!   `alloy-signer-local` (which is the same eth-keystore code path
//!   Foundry's `cast` uses). chaincli does not invent crypto here.
//!
//! On success, prints the resulting tx hash, block number, and
//! `sequence` returned by `publishRevision`. The `sequence` lets the
//! caller cross-check `nextSequence()` after the call to confirm the
//! state mutated.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::LocalSigner;
use alloy::sol_types::SolEvent;
use anyhow::{anyhow, Context, Result};
use clap::Args;

use crate::client::Deployment;
use crate::contract::RevisionLogV0;

#[derive(Debug, Clone, Args)]
pub struct PublishArgs {
    #[arg(long, value_parser = parse_b256)]
    pub vault_id: B256,

    #[arg(long, value_parser = parse_b256)]
    pub account_id: B256,

    #[arg(long, value_parser = parse_b256)]
    pub parent_revision: B256,

    #[arg(long, value_parser = parse_b256)]
    pub device_id: B256,

    #[arg(long)]
    pub schema_version: u8,

    /// Hex-encoded `encPayload`. May start with `0x`. NOT decoded
    /// structurally by chaincli — the bytes go directly into the
    /// `publishRevision` calldata. Use this to write known-bytes test
    /// vectors when debugging sync.
    #[arg(long)]
    pub payload_hex: String,

    /// Foundry keystore name. Resolved against
    /// `$FOUNDRY_DIR/keystores/<name>` (default
    /// `~/.foundry/keystores/<name>`).
    #[arg(long)]
    pub account: String,

    /// Override the keystore directory. Useful for tests against a
    /// fixture keystore.
    #[arg(long)]
    pub keystore_dir: Option<std::path::PathBuf>,
}

fn parse_b256(s: &str) -> Result<B256, String> {
    s.parse::<B256>()
        .map_err(|e| format!("not a 32-byte 0x-prefixed hex value: {e}"))
}

/// Run the `publish` sub-command.
pub async fn run(deployment: &Deployment, rpc_url: &str, args: PublishArgs) -> Result<()> {
    // 1. Resolve and validate the keystore path BEFORE prompting for
    //    password — it would be cruel to prompt only to fail.
    let keystore_dir = if let Some(p) = args.keystore_dir.as_ref() {
        p.clone()
    } else {
        default_keystore_dir().context("could not locate Foundry keystore directory")?
    };
    let keystore_path = keystore_dir.join(&args.account);
    if !keystore_path.is_file() {
        return Err(anyhow!(
            "keystore file not found: {} (set --keystore-dir or --account)",
            keystore_path.display()
        ));
    }

    // 2. Decode the payload hex BEFORE prompting too — fail-fast.
    let payload_bytes = decode_payload_hex(&args.payload_hex)
        .context("--payload-hex did not decode as hexadecimal bytes")?;

    // 3. Prompt for password without echo.
    let password = rpassword::prompt_password(format!(
        "Enter password for keystore {}: ",
        keystore_path.display()
    ))
    .context("failed to read keystore password from terminal")?;

    // 4. Decrypt — this can take a few seconds (scrypt). The password
    //    string is moved into the call; alloy's eth-keystore zeroizes
    //    the decrypted private-key bytes after `LocalSigner` is
    //    constructed.
    let signer = LocalSigner::decrypt_keystore(&keystore_path, &password)
        .context("keystore decryption failed (wrong password?)")?;
    drop(password);
    let signer_address: Address = signer.address();
    eprintln!("Decrypted keystore for account {signer_address:?}");

    // 5. Connect to the RPC with the wallet attached.
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(rpc_url)
        .await
        .with_context(|| format!("failed to connect to RPC at {rpc_url}"))?;

    // 6. Sanity-check the chain id matches the deployment file.
    let chain_id = provider
        .get_chain_id()
        .await
        .context("eth_chainId RPC call failed")?;
    if chain_id != deployment.chain_id {
        return Err(anyhow!(
            "RPC chain_id ({chain_id}) does not match deployment \
             chain_id ({}). Refusing to broadcast.",
            deployment.chain_id
        ));
    }

    // 7. Submit `publishRevision` and wait for the receipt.
    let contract = RevisionLogV0::new(deployment.contract_address, &provider);
    let pending = contract
        .publishRevision(
            args.vault_id,
            args.account_id,
            args.parent_revision,
            args.device_id,
            args.schema_version,
            Bytes::from(payload_bytes),
        )
        .send()
        .await
        .context("failed to broadcast publishRevision transaction")?;
    let tx_hash = *pending.tx_hash();
    eprintln!("submitted: {tx_hash:?} — waiting for receipt...");
    let receipt = pending
        .get_receipt()
        .await
        .context("failed to await transaction receipt")?;
    if !receipt.status() {
        return Err(anyhow!(
            "transaction {tx_hash:?} reverted: status=0 in receipt"
        ));
    }

    // 8. Decode the emitted event for the user.
    let target_topic = RevisionLogV0::RevisionPublished::SIGNATURE_HASH;
    let log = receipt
        .inner
        .logs()
        .iter()
        .find(|l| {
            l.address() == deployment.contract_address
                && l.topics().first().copied() == Some(target_topic)
        })
        .ok_or_else(|| {
            anyhow!(
                "tx {tx_hash:?} succeeded but emitted no RevisionPublished log on {:?}",
                deployment.contract_address
            )
        })?;
    let decoded = RevisionLogV0::RevisionPublished::decode_log(&log.inner)
        .context("emitted log did not decode as RevisionPublished")?;

    println!("tx_hash      : {tx_hash:?}");
    println!(
        "block        : {}",
        receipt.block_number.unwrap_or_default()
    );
    println!("from         : {signer_address:?}");
    println!("contract     : {:?}", deployment.contract_address);
    println!("sequence     : {}", decoded.sequence);
    println!("vault_id     : {:?}", decoded.vaultId);
    println!("account_id   : {:?}", decoded.accountId);
    println!("parent       : {:?}", decoded.parentRevision);
    println!("device_id    : {:?}", decoded.deviceId);
    println!("schema_v     : {}", decoded.schemaVersion);

    Ok(())
}

/// Resolve the default Foundry keystore directory.
///
/// Foundry honors `$FOUNDRY_DIR/keystores`, defaulting to
/// `$HOME/.foundry/keystores` (Linux/macOS) or
/// `%USERPROFILE%\.foundry\keystores` (Windows). We mirror the
/// resolution rule without parsing Foundry config — same as `cast`.
fn default_keystore_dir() -> Result<std::path::PathBuf> {
    if let Ok(custom) = std::env::var("FOUNDRY_DIR") {
        return Ok(std::path::PathBuf::from(custom).join("keystores"));
    }
    let home = home_dir().ok_or_else(|| anyhow!("could not determine $HOME / %USERPROFILE%"))?;
    Ok(home.join(".foundry").join("keystores"))
}

/// Cross-platform `$HOME` / `%USERPROFILE%` resolver. Avoids the
/// `home`/`dirs` crates so chaincli's dep set stays small.
fn home_dir() -> Option<std::path::PathBuf> {
    if cfg!(windows) {
        if let Ok(p) = std::env::var("USERPROFILE") {
            if !p.is_empty() {
                return Some(std::path::PathBuf::from(p));
            }
        }
    }
    if let Ok(p) = std::env::var("HOME") {
        if !p.is_empty() {
            return Some(std::path::PathBuf::from(p));
        }
    }
    None
}

/// Decode a `0x`-prefixed-or-bare hex string into bytes. Whitespace
/// inside the string is rejected (we'd rather fail loudly than guess).
pub fn decode_payload_hex(input: &str) -> Result<Vec<u8>> {
    let stripped = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(stripped).context("hex decoding failed")?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{decode_payload_hex, PublishArgs};
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(subcommand)]
        cmd: HarnessSub,
    }

    #[derive(Debug, clap::Subcommand)]
    enum HarnessSub {
        Publish(PublishArgs),
    }

    fn parse(args: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
    }

    #[test]
    fn arg_parsing_happy_path() {
        let args = parse(&[
            "publish",
            "--vault-id",
            "0xaaaa000000000000000000000000000000000000000000000000000000000000",
            "--account-id",
            "0xbbbb000000000000000000000000000000000000000000000000000000000000",
            "--parent-revision",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--device-id",
            "0xcccc000000000000000000000000000000000000000000000000000000000000",
            "--schema-version",
            "0",
            "--payload-hex",
            "0xdeadbeef",
            "--account",
            "pangolin-dev",
        ])
        .expect("happy path parses");
        match args.cmd {
            HarnessSub::Publish(a) => {
                assert_eq!(a.account, "pangolin-dev");
                assert_eq!(a.payload_hex, "0xdeadbeef");
                assert_eq!(a.schema_version, 0);
                assert!(a.keystore_dir.is_none());
            }
        }
    }

    #[test]
    fn arg_parsing_requires_account_flag() {
        let err = parse(&[
            "publish",
            "--vault-id",
            "0xaaaa000000000000000000000000000000000000000000000000000000000000",
            "--account-id",
            "0xbbbb000000000000000000000000000000000000000000000000000000000000",
            "--parent-revision",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--device-id",
            "0xcccc000000000000000000000000000000000000000000000000000000000000",
            "--schema-version",
            "0",
            "--payload-hex",
            "0xdeadbeef",
            // No --account.
        ])
        .expect_err("missing --account should fail");
        assert!(format!("{err}").contains("--account"));
    }

    #[test]
    fn arg_parsing_invalid_payload_hex_caught_at_decode() {
        // `--payload-hex` is parsed as a String at clap-time, so clap
        // accepts even non-hex input. The decode step in
        // `decode_payload_hex` is what enforces validity.
        assert!(decode_payload_hex("not-hex").is_err());
        assert!(decode_payload_hex("0xZZZZ").is_err());
    }

    #[test]
    fn decode_payload_hex_with_and_without_prefix() {
        assert_eq!(
            decode_payload_hex("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_payload_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(decode_payload_hex("").unwrap(), Vec::<u8>::new());
    }
}
