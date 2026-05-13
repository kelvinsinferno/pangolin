//! `pangolin-cli authority` — capture-authority registry inspection
//! (MVP-1 issue 1.11, R-d).
//!
//! MVP-1 ships only `authority list` — a read-only view of the
//! `capture_authorities` table. Per R-d, `register` / `clear` CLI
//! subcommands defer to MVP-2 (the browser extension's native-messaging
//! host is the real consumer for those flows; building them in 1.11
//! would land code that MVP-2 deprecates within one cycle).

use anyhow::{Context, Result};
use pangolin_store::CaptureAuthorityKind;

use crate::cli::{AuthorityArgs, AuthorityCommand, AuthorityListArgs, GlobalArgs};

/// Top-level dispatch for `pangolin-cli authority <verb>`.
#[allow(clippy::unused_async)]
pub async fn run(global: &GlobalArgs, args: AuthorityArgs) -> Result<()> {
    match args.command {
        AuthorityCommand::List(sub) => run_list(global, sub).await,
    }
}

/// Run `pangolin-cli authority list`.
#[allow(clippy::unused_async)]
async fn run_list(global: &GlobalArgs, args: AuthorityListArgs) -> Result<()> {
    // Two-proof unlock via the shared helper (same shell as the
    // `vault export` / `account *` subcommands use).
    let mut vault =
        crate::vault_open::open_and_unlock(&args.vault_path, args.vault_password.as_deref())
            .context("vault open + unlock failed")?;
    let entries = vault
        .capture_authority_list()
        .context("capture-authority list failed")?;

    // Two surface modes: human-readable single line per entry; or
    // JSON-Lines (one JSON object per entry per line). The `--json`
    // local flag is preferred over the global because the global was
    // designed for chain-orchestration summaries, not list emit; but
    // we still honour the global flag if `--json` is set anywhere.
    let json_mode = args.json || global.json;

    if entries.is_empty() && !json_mode {
        println!("(no capture authorities registered)");
        return Ok(());
    }

    for entry in &entries {
        if json_mode {
            let summary = serde_json::json!({
                "schema_version": entry.schema_version,
                "context_kind": context_label(entry.context.kind),
                "platform_hint": entry.context.platform_hint,
                "authority_kind": authority_label(entry.authority.kind),
                "component_id": entry.authority.component_id,
                "component_version": entry.authority.component_version,
                "registered_at_ms": entry.registered_at,
            });
            println!("{summary}");
        } else {
            let hint = entry
                .context
                .platform_hint
                .as_deref()
                .unwrap_or("(no platform hint)");
            println!(
                "{ctx:<10} {hint:<12} -> {kind:<18} {id} {version}",
                ctx = context_label(entry.context.kind),
                kind = authority_label(entry.authority.kind),
                id = entry.authority.component_id,
                version = entry.authority.component_version,
            );
        }
    }
    vault.close().context("vault close failed")?;
    Ok(())
}

fn context_label(kind: pangolin_store::CaptureContextKind) -> &'static str {
    use pangolin_store::CaptureContextKind as K;
    match kind {
        K::Desktop => "desktop",
        K::Browser => "browser",
        K::MobileOs => "mobile_os",
    }
}

fn authority_label(kind: CaptureAuthorityKind) -> &'static str {
    match kind {
        CaptureAuthorityKind::Desktop => "desktop",
        CaptureAuthorityKind::BrowserExtension => "browser_extension",
        CaptureAuthorityKind::MobileOsAutofill => "mobile_os_autofill",
    }
}
