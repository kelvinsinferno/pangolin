//! `pangolin-cli resolve` — fork / freeze conflict resolution.
//!
//! User-facing release valve for the two related "vault is in an
//! inconsistent state with the chain" conditions P8 introduced
//! (`is_forked` + `frozen_pending_resolve`). The user picks one of
//! the account's current heads via `--keep <revision-id>`; this
//! command publishes a merge revision pointing at that head and
//! clears the freeze flag locally on success.
//!
//! ## End-to-end flow (per P9 plan §A2 / §A3)
//!
//! 1. Resolve global config, open + unlock the vault, resolve the
//!    keystore, build the chain adapter — same shape as `publish`.
//! 2. Validate the user's `--account-id` exists and `--keep` is
//!    one of its current heads; refuse otherwise.
//! 3. **Pre-publish re-pull (Q7).** Run `pull_all` to bring the
//!    local view current. If a NEW head has appeared since the user
//!    invoked resolve (chain moved), abort cleanly so the user can
//!    re-run against the freshest heads.
//! 4. Read the chosen revision's plaintext via the freeze-guard
//!    bypass (`Vault::read_payload_plaintext_for_resolve`) — the
//!    user's `--keep <id>` is the proof-of-intent that authorizes
//!    this single read.
//! 5. Re-seal the plaintext under a fresh nonce with the merge
//!    revision's own AAD (`parent_revision_id` = chosen head's
//!    `revision_id`). A byte-copy of the source ciphertext would
//!    have a stale AAD baked in; re-seal is mandatory per P9 plan
//!    §A2.
//! 6. Build a `SignedRevision` via `build_signed_revision`, publish
//!    via `ChainAdapter::publish`, ingest the resulting event back
//!    into the local store via `Vault::ingest_chain_revision`, and
//!    call `Vault::clear_frozen` to advance the local head pointer
//!    and clear the freeze flag.
//! 7. Print the per-run summary on stderr (or JSON-Lines on stdout
//!    if `--json` is set globally).
//!
//! `--dry-run` short-circuits at step 5 and prints the merge
//! revision's canonical hash without publishing or clearing the
//! flag. The plaintext IS materialised in memory transiently to
//! compute the canonical hash (the AAD-binds-parent invariant
//! makes this unavoidable — see §A2); the snapshot is dropped
//! (zeroized) immediately after the seal call.

use std::io::Write as _;

use anyhow::{bail, Context, Result};
use pangolin_chain::BaseSepoliaAdapter;
use pangolin_crypto::keys::DeviceKey;
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{AccountId, RevisionId};

use crate::cli::{GlobalArgs, ResolveArgs};
use crate::config::ResolvedConfig;
use crate::keystore::{read_keystore_password, resolve_keystore_path};
use crate::sync::{resolve_one, ResolveOutcome};
use crate::vault_open::open_and_unlock;

/// Run the `resolve` subcommand.
#[allow(clippy::too_many_lines)] // Linear flow: resolve config →
                                 // open vault → validate heads → confirm with user → build adapter →
                                 // drive orchestrator → print summary. Factoring sub-helpers obscures
                                 // the audit-reviewable order rather than clarifying it.
pub async fn run(global: &GlobalArgs, args: ResolveArgs) -> Result<()> {
    let cfg = ResolvedConfig::from_args(global)?;
    let deployment_path = cfg.require_deployment_file()?.clone();

    // Resolve keystore path BEFORE prompting for vault password —
    // fail-fast if the keystore file is missing.
    let keystore_path = resolve_keystore_path(
        args.account.as_deref(),
        args.keystore_dir.as_deref(),
        args.keystore_path.as_deref(),
    )?;

    // Open + unlock the vault. Resolve needs an Active session
    // because the chosen revision's plaintext must be decrypted
    // (`read_payload_plaintext_for_resolve`) and re-sealed.
    let mut vault = open_and_unlock(&args.vault_path, args.vault_password.as_deref())
        .context("vault open + unlock failed")?;

    let account_id = AccountId::from_bytes(args.account_id.0);
    let chosen_revision_id = RevisionId::from_bytes(args.keep.0);

    // Defensive: surface a clear error if `--keep` is not currently
    // a head of the account, BEFORE any chain call. The
    // `resolve_one` orchestrator re-validates this after the
    // pre-publish pull (so a chain-moved-during-resolve case
    // surfaces with a distinct error), but a fast-path local check
    // here gives the user immediate feedback for the common
    // user-typo case.
    let heads = vault
        .account_heads(account_id)
        .context("account_heads lookup failed (account_id unknown?)")?;
    if !heads.contains(&chosen_revision_id) {
        bail!(
            "the supplied --keep revision is not a current head of the account; \
             current heads: {:?}",
            heads
                .iter()
                .map(|h| hex::encode(h.as_bytes()))
                .collect::<Vec<_>>()
        );
    }

    // Print the planned action to stderr regardless of --dry-run /
    // --yes — Cardinal Principle 4 ("never silent merge"): the user
    // should always see what's about to happen.
    eprintln!(
        "resolve: account {} → keep revision {}",
        hex::encode(account_id.as_bytes()),
        hex::encode(chosen_revision_id.as_bytes())
    );
    if heads.len() > 1 {
        eprintln!(
            "  (this account has {} heads; resolve handles ONE — re-run for each)",
            heads.len()
        );
    }

    // Read the keystore password BEFORE the confirmation prompt so
    // a no-confirmation `--yes` invocation has all credentials
    // ready. Same prompt order as `publish`.
    let keystore_password =
        read_keystore_password(&keystore_path, args.keystore_password.as_deref())?;
    let password_secret = SecretBytes::new(keystore_password.as_bytes().to_vec());
    drop(keystore_password);

    if !args.yes && !args.dry_run {
        eprint!("proceed? [y/N]: ");
        std::io::stderr().flush().ok();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("failed to read confirmation from stdin")?;
        let trimmed = buf.trim();
        if !trimmed.eq_ignore_ascii_case("y") && !trimmed.eq_ignore_ascii_case("yes") {
            bail!("aborted by user (no confirmation)");
        }
    }

    // Build the adapter (same shape as `publish`).
    let rpc_url_default = read_deployment_default_rpc(&deployment_path)?;
    let rpc_url = cfg.rpc_url_or_default(&rpc_url_default);
    cfg.enforce_rpc_scheme(&rpc_url)?;
    let adapter = BaseSepoliaAdapter::new_with_keystore(
        &rpc_url,
        &deployment_path,
        &keystore_path,
        &password_secret,
    )
    .await
    .context("failed to construct BaseSepoliaAdapter")?;
    drop(password_secret);

    // Ephemeral signing key — PoC two-key model, same as `publish`.
    let device = DeviceKey::generate();

    // Drive the orchestrator.
    let outcome = resolve_one(
        &mut vault,
        &adapter,
        &device,
        account_id,
        chosen_revision_id,
        args.dry_run,
    )
    .await
    .context("resolve_one failed")?;

    if cfg.json {
        let value = match &outcome {
            ResolveOutcome::DryRun {
                planned_revision_id,
            } => serde_json::json!({
                "outcome": "dry_run",
                "planned_revision_id": hex::encode(planned_revision_id),
            }),
            ResolveOutcome::Published {
                revision_id,
                anchor,
            } => serde_json::json!({
                "outcome": "published",
                "revision_id": hex::encode(revision_id),
                "tx_hash": format!("0x{}", hex::encode(anchor.tx_hash)),
                "block_number": anchor.block_number,
                "log_index": anchor.log_index,
                "sequence": anchor.sequence,
            }),
            ResolveOutcome::AlreadyOnChain {
                revision_id,
                anchor,
            } => serde_json::json!({
                "outcome": "already_on_chain",
                "revision_id": hex::encode(revision_id),
                "tx_hash": format!("0x{}", hex::encode(anchor.tx_hash)),
                "block_number": anchor.block_number,
                "log_index": anchor.log_index,
                "sequence": anchor.sequence,
            }),
        };
        println!("{value}");
    } else {
        match &outcome {
            ResolveOutcome::DryRun {
                planned_revision_id,
            } => {
                // P9 fix-pass 2 — LOW-2. The dry-run path skips the
                // pre-publish chain re-pull (per MED-4 hygiene), so
                // the canonical hash below is computed against the
                // last-known-local view of the chain. Surface this
                // staleness disclosure BEFORE the hash so the user
                // can decide whether to re-run `pangolin-cli pull`
                // first.
                eprintln!(
                    "dry run: pre-publish chain re-pull SKIPPED \
                     (dry-run mode); current local view may be stale"
                );
                eprintln!(
                    "dry run: would publish merge revision {}",
                    hex::encode(planned_revision_id)
                );
            }
            ResolveOutcome::Published {
                revision_id,
                anchor,
            } => {
                eprintln!(
                    "resolve summary: published merge revision {} at block {} log {} seq {}",
                    hex::encode(revision_id),
                    anchor.block_number,
                    anchor.log_index,
                    anchor.sequence,
                );
            }
            ResolveOutcome::AlreadyOnChain {
                revision_id,
                anchor,
            } => {
                eprintln!(
                    "resolve summary: merge revision {} was already on chain at block {} log {} seq {} \
                     (recovery from prior partial failure)",
                    hex::encode(revision_id),
                    anchor.block_number,
                    anchor.log_index,
                    anchor.sequence,
                );
            }
        }
    }
    Ok(())
}

/// Pluck `chain.rpc_default` from the deployment file. Mirror of
/// the same helper in `commands/publish.rs` and `commands/pull.rs`;
/// duplicated rather than factored out per the same rationale (each
/// command is independent).
fn read_deployment_default_rpc(path: &std::path::Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read deployment file at {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("deployment file {} is not valid JSON", path.display()))?;
    let s = value
        .pointer("/chain/rpc_default")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("deployment file missing /chain/rpc_default (string)"))?;
    Ok(s.to_owned())
}
