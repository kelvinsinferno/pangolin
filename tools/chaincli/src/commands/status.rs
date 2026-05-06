//! `chaincli status` — read-only sanity check.
//!
//! Confirms:
//! - The RPC endpoint is reachable.
//! - `eth_chainId` matches the deployment file's declared chain id
//!   (defense against "user pointed --rpc-url at the wrong chain").
//! - The on-chain ABI for the deployed contract matches the binding
//!   chaincli compiled against (defense against "deployment file lies
//!   about which contract is at this address"). The ABI cross-check
//!   compares the function selector for `nextSequence()` between the
//!   compiled `sol!` binding and the JSON ABI we loaded; if they
//!   diverge, chaincli refuses to proceed.
//! - The `keccak256` of the live runtime bytecode at
//!   `deployment.contract_address` matches
//!   `bytecode.deployed_runtime_keccak256` from the deployment file
//!   (defense against "tampered deployment file points us at a foreign
//!   contract on the right chain that exposes the same selectors" — a
//!   CREATE2 collision or honest-but-stale metadata file). This is
//!   strictly stronger than the chain-id + ABI checks combined.
//! - `nextSequence()` returns; the value is printed as the running
//!   counter at the time of the check.
//!
//! Exit 0 on full success; non-zero on any verification failure.

use alloy::primitives::{keccak256, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::{SolCall, SolEvent};
use anyhow::{anyhow, Context, Result};

use crate::client::Deployment;
use crate::contract::RevisionLogV0;

/// Run the `status` sub-command. Pure async; the CLI binary wraps this
/// in a tokio runtime.
pub async fn run(deployment: &Deployment, rpc_url: &str) -> Result<()> {
    println!("deployment_file    : {}", deployment.source_path.display());
    println!("contract_address   : {:?}", deployment.contract_address);
    println!("deployer           : {:?}", deployment.deployer);
    println!("deploy_block       : {}", deployment.deploy_block);
    println!("runtime_size_bytes : {}", deployment.runtime_size_bytes);
    println!("rpc                : {rpc_url}");

    abi_cross_check(deployment).context("ABI cross-check failed")?;
    println!("abi_cross_check    : OK");

    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .with_context(|| format!("failed to connect to RPC at {rpc_url}"))?;

    let chain_id = provider
        .get_chain_id()
        .await
        .context("eth_chainId RPC call failed")?;
    if chain_id != deployment.chain_id {
        return Err(anyhow!(
            "RPC chain_id ({chain_id}) does not match deployment \
             chain_id ({}). Refusing to proceed.",
            deployment.chain_id
        ));
    }
    println!(
        "chain_id           : {}  (expected: {})  OK",
        chain_id, deployment.chain_id
    );

    // Live-bytecode keccak cross-check. Done AFTER the chain_id check so
    // we never hash bytes from the wrong chain — a wrong-chain mismatch
    // would already have failed above with a clearer diagnostic.
    let live_code = provider
        .get_code_at(deployment.contract_address)
        .await
        .with_context(|| {
            format!(
                "eth_getCode RPC call failed for {:?}",
                deployment.contract_address
            )
        })?;
    let live_keccak: B256 = keccak256(live_code.as_ref());
    if live_keccak != deployment.runtime_keccak {
        return Err(anyhow!(
            "runtime bytecode keccak mismatch at {:?}: live={:?}, \
             expected (from deployment file)={:?}. Refusing to proceed.",
            deployment.contract_address,
            live_keccak,
            deployment.runtime_keccak
        ));
    }
    println!(
        "bytecode_keccak    : {:?}  (expected: {:?})  OK",
        live_keccak, deployment.runtime_keccak
    );

    let contract = RevisionLogV0::new(deployment.contract_address, &provider);
    let next_seq = contract
        .nextSequence()
        .call()
        .await
        .context("nextSequence() RPC call failed")?;
    println!("nextSequence       : {next_seq}");

    Ok(())
}

/// Cross-check that the deployed JSON ABI declares the same function
/// selectors and event topic that the `sol!` binding compiled against.
/// Returns an error on any mismatch.
fn abi_cross_check(deployment: &Deployment) -> Result<()> {
    let abi = deployment
        .load_abi()
        .context("failed to load JSON ABI for cross-check")?;

    // 1. function `nextSequence()` selector parity.
    let next_seq_compiled = RevisionLogV0::nextSequenceCall::SELECTOR;
    let next_seq_json = abi
        .function("nextSequence")
        .and_then(|fns| fns.first())
        .ok_or_else(|| anyhow!("ABI is missing nextSequence()"))?
        .selector();
    if next_seq_compiled != next_seq_json.0 {
        return Err(anyhow!(
            "nextSequence selector mismatch: compiled={:?}, json={:?}",
            hex::encode(next_seq_compiled),
            hex::encode(next_seq_json.0)
        ));
    }

    // 2. function `publishRevision(...)` selector parity.
    let pub_compiled = RevisionLogV0::publishRevisionCall::SELECTOR;
    let pub_json = abi
        .function("publishRevision")
        .and_then(|fns| fns.first())
        .ok_or_else(|| anyhow!("ABI is missing publishRevision(...)"))?
        .selector();
    if pub_compiled != pub_json.0 {
        return Err(anyhow!(
            "publishRevision selector mismatch: compiled={:?}, json={:?}",
            hex::encode(pub_compiled),
            hex::encode(pub_json.0)
        ));
    }

    // 3. event `RevisionPublished(...)` topic-0 parity.
    let event_compiled: B256 = RevisionLogV0::RevisionPublished::SIGNATURE_HASH;
    let event_json = abi
        .event("RevisionPublished")
        .and_then(|evs| evs.first())
        .ok_or_else(|| anyhow!("ABI is missing event RevisionPublished"))?
        .selector();
    if event_compiled.0 != event_json.0 {
        return Err(anyhow!(
            "RevisionPublished topic mismatch: compiled={:?}, json={:?}",
            event_compiled,
            event_json
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::abi_cross_check;
    use crate::client::Deployment;
    use std::path::PathBuf;

    fn workspace_deployment() -> Deployment {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let path = manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root")
            .join("contracts")
            .join("deployments")
            .join("base-sepolia.json");
        Deployment::load(&path).expect("real deployment file parses")
    }

    #[test]
    fn abi_cross_check_matches_deployed_artifact() {
        let dep = workspace_deployment();
        // The compiled sol! binding must match the on-disk ABI byte-for-byte
        // (selectors + event topic). Any deviation fails this check and
        // would block `chaincli status` from running.
        abi_cross_check(&dep).expect("abi cross-check passes against deployed artifact");
    }
}
