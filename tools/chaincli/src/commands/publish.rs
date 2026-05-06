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

use std::path::{Component, Path};

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::LocalSigner;
use alloy::sol_types::SolEvent;
use anyhow::{anyhow, bail, Context, Result};
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
    // 1. Validate `--account` is a simple keystore name, not a path.
    //    `Path::join` happily takes absolute paths and `..` components
    //    verbatim, which would let an attacker who controls argv steer
    //    chaincli at an arbitrary file. We require a single
    //    `Component::Normal` — no separators, no `..`, no `.`, no
    //    absolute prefix, not empty.
    validate_account_name(&args.account).context("--account validation failed")?;

    // 2. Resolve and validate the keystore path BEFORE prompting for
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

    // 3. Decode the payload hex BEFORE prompting too — fail-fast.
    let payload_bytes = decode_payload_hex(&args.payload_hex)
        .context("--payload-hex did not decode as hexadecimal bytes")?;

    // 4. Prompt for password without echo. The password is stored in a
    //    `Zeroizing<String>` so the heap buffer is overwritten (not
    //    merely deallocated) when the binding goes out of scope. The
    //    workspace `zeroize` dep enables the `alloc` feature so
    //    `String: Zeroize` is in scope.
    let password: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
        rpassword::prompt_password(format!(
            "Enter password for keystore {}: ",
            keystore_path.display()
        ))
        .context("failed to read keystore password from terminal")?,
    );

    // 5. Decrypt — this can take a few seconds (scrypt).
    //
    // ZEROIZE BOUNDARY (audit MEDIUM-3): the actual zeroize guarantee
    // for the decrypted *private key* lives in `alloy-signer-local`'s
    // `LocalSigner`, which wraps a `k256::ecdsa::SigningKey` (built on
    // a `k256::SecretKey`, which is `ZeroizeOnDrop`). It is NOT
    // provided by `eth-keystore` itself. `eth-keystore`'s `decrypt_key`
    // returns a plain `Vec<u8>` of the raw 32-byte private key; that
    // intermediate buffer is dropped without being overwritten before
    // the bytes reach `SigningKey::from_slice` (audit MEDIUM-2).
    // Removing this transient exposure requires a fork of
    // `eth-keystore` and is therefore an accepted upstream limitation.
    // The password buffer (above) is the only piece of secret material
    // chaincli itself owns — and that one IS zeroized via `Zeroizing`.
    let signer = LocalSigner::decrypt_keystore(&keystore_path, password.as_str())
        .context("keystore decryption failed (wrong password?)")?;
    // No explicit drop of `password` — the `Zeroizing` wrapper handles
    // wipe-on-drop at end of scope.
    let signer_address: Address = signer.address();
    eprintln!("Decrypted keystore for account {signer_address:?}");

    // 6. Connect to the RPC with the wallet attached.
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(rpc_url)
        .await
        .with_context(|| format!("failed to connect to RPC at {rpc_url}"))?;

    // 7. Sanity-check the chain id matches the deployment file.
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

    // 8. Submit `publishRevision` and wait for the receipt.
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

    // 9. Decode the emitted event for the user.
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

/// Reject `--account` values that aren't simple keystore filenames.
///
/// `keystore_dir.join(name)` is unsafe with attacker-controlled `name`:
/// `Path::join` takes absolute paths verbatim, and `..` components
/// climb out of `keystore_dir`. Threat model is "attacker controls
/// argv" (low impact), but the lift is cheap and aligns chaincli with
/// the same hygiene Foundry's `cast` enforces. Per audit LOW-5, we
/// require the value to be exactly one path component, and that
/// component must be `Component::Normal` (not `..`, not `.`, not a
/// root or prefix).
fn validate_account_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("--account must be a simple keystore name; got empty string");
    }
    // `Path::components` skips redundant separators but DOES emit
    // `Component::CurDir` for `.`, `Component::ParentDir` for `..`,
    // and `Component::Prefix`/`RootDir` for absolute paths — exactly
    // the cases we want to catch.
    let path = Path::new(name);
    let mut components = path.components();
    let first = components
        .next()
        .ok_or_else(|| anyhow!("--account must be a simple keystore name; got empty path"))?;
    if components.next().is_some() {
        bail!("--account must be a simple keystore name; got {name} (contains path separators)");
    }
    match first {
        Component::Normal(_) => Ok(()),
        Component::CurDir | Component::ParentDir => {
            bail!("--account must be a simple keystore name; got {name} (path-traversal component)")
        }
        Component::RootDir | Component::Prefix(_) => {
            bail!("--account must be a simple keystore name; got {name} (absolute path)")
        }
    }
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
    use super::{decode_payload_hex, validate_account_name, PublishArgs};
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

    #[test]
    fn validate_account_name_accepts_plain_name() {
        validate_account_name("pangolin-dev").expect("plain name accepted");
        validate_account_name("dev_account").expect("underscores allowed");
        validate_account_name("dev.account").expect("dots inside name allowed");
        validate_account_name("a").expect("single-char name allowed");
    }

    #[test]
    fn validate_account_name_rejects_empty() {
        let err = validate_account_name("").expect_err("empty rejected");
        assert!(format!("{err:#}").contains("empty"));
    }

    #[test]
    fn validate_account_name_rejects_forward_slash() {
        let err = validate_account_name("foo/bar").expect_err("/ rejected");
        assert!(format!("{err:#}").contains("path separators"));
    }

    #[test]
    #[cfg(windows)]
    fn validate_account_name_rejects_backslash() {
        let err = validate_account_name("foo\\bar").expect_err("backslash rejected");
        assert!(format!("{err:#}").contains("path separators"));
    }

    #[test]
    fn validate_account_name_rejects_parent_dir() {
        let err = validate_account_name("..").expect_err(".. rejected");
        let msg = format!("{err:#}");
        // On Windows `..` alone may surface as a `Normal` component
        // depending on parser quirks; we still want to reject it via
        // either the path-separator branch or the traversal branch.
        // The current check classifies it as ParentDir → traversal.
        assert!(
            msg.contains("path-traversal") || msg.contains("path separators"),
            "expected traversal rejection for `..`, got: {msg}"
        );
    }

    #[test]
    fn validate_account_name_rejects_dot() {
        let err = validate_account_name(".").expect_err(". rejected");
        assert!(format!("{err:#}").contains("path-traversal"));
    }

    #[test]
    fn validate_account_name_rejects_traversal_compound() {
        let err = validate_account_name("../etc/passwd").expect_err("../ traversal rejected");
        // Compound paths fail at the multi-component check.
        assert!(format!("{err:#}").contains("path separators"));
    }

    #[test]
    #[cfg(unix)]
    fn validate_account_name_rejects_absolute_unix() {
        let err = validate_account_name("/etc/passwd").expect_err("absolute unix path rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("absolute path") || msg.contains("path separators"),
            "expected absolute-path or separator rejection, got: {msg}"
        );
    }

    #[test]
    #[cfg(windows)]
    fn validate_account_name_rejects_absolute_windows() {
        let err = validate_account_name("C:\\Windows\\System32\\config")
            .expect_err("absolute windows path rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("absolute path") || msg.contains("path separators"),
            "expected absolute-path or separator rejection, got: {msg}"
        );
    }
}
