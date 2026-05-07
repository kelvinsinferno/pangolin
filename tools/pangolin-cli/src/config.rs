//! Resolved runtime configuration for `pangolin-cli`.
//!
//! Pulls together the global flags from [`crate::cli::GlobalArgs`]
//! into a struct that subcommand handlers consume directly. The two
//! pieces of work this module does:
//!
//! 1. **Deployment-file discovery.** If `--deployment-file` is not
//!    given, we walk up from the current directory until
//!    `contracts/deployments/base-sepolia.json` is found. Same rule
//!    `chaincli` uses — `pangolin-chain::BaseSepoliaAdapter` already
//!    has a `find_deployment_file` helper, which we delegate to.
//! 2. **RPC-URL resolution.** Precedence chain: `--rpc-url` flag >
//!    `$BASE_SEPOLIA_RPC_URL` env var > deployment file's
//!    `chain.rpc_default`. The flag-and-env steps are handled by
//!    [`crate::cli::GlobalArgs::rpc_url`] (clap's `env` feature reads
//!    the env var when the flag is absent); the third fallback runs
//!    here against the deployment metadata.
//!
//! Reading the deployment JSON is deliberately deferred until a
//! subcommand actually needs it — `pangolin-cli status --vault-path <p>`
//! works against an offline vault without the JSON file present (it
//! doesn't make any chain calls).

use std::path::PathBuf;

use anyhow::{anyhow, Result};

use crate::cli::GlobalArgs;

/// Resolved global configuration consumed by subcommand handlers.
//
// P8-1 stub: the fields are wired in this commit but only consumed in
// P8-3 / P8-4 / P8-5. The `#[allow(dead_code)]` guard lets `cargo
// clippy --workspace --all-targets -- -D warnings` pass on the
// scaffold commit.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Path to the deployment-record JSON. May be `None` when the
    /// caller did not supply `--deployment-file` AND the auto-walk
    /// from CWD did not find one. Subcommands that need chain access
    /// surface a clear error in that case.
    pub deployment_file: Option<PathBuf>,
    /// The RPC URL flag's value (or env-var-supplied value via clap's
    /// `env` feature). The deployment-file fallback is applied at
    /// the moment the chain adapter is built — see
    /// [`Self::rpc_url_or_default`].
    pub rpc_url_flag: Option<String>,
    /// **P8 fix MED-2.** When `true`, `enforce_rpc_scheme` permits
    /// non-`https` RPC URLs (e.g., `http://localhost:8545` for
    /// local-anvil testing). Default `false` — production callers
    /// should never need to flip this on.
    pub allow_insecure_rpc: bool,
    /// `--json` toggle.
    pub json: bool,
}

// P8-1 stub: the helper methods land in P8-3 / P8-4 once the chain
// adapter is wired in. Tests below already exercise them.
#[allow(dead_code)]
impl ResolvedConfig {
    /// Build a `ResolvedConfig` from the parsed global flags. If
    /// `--deployment-file` is not given, walks up from the current
    /// directory looking for the canonical deployment record.
    pub fn from_args(global: &GlobalArgs) -> Result<Self> {
        let deployment_file = if let Some(p) = global.deployment_file.as_ref() {
            Some(p.clone())
        } else {
            // Walk up from CWD looking for
            // `contracts/deployments/base-sepolia.json`. We use the
            // same helper `pangolin-chain::BaseSepoliaAdapter` exposes
            // so the resolution rule is consistent across all the
            // workspace's chain consumers.
            let cwd = std::env::current_dir()
                .map_err(|e| anyhow!("could not read current working directory: {e}"))?;
            pangolin_chain::BaseSepoliaAdapter::find_deployment_file(&cwd)
        };
        Ok(Self {
            deployment_file,
            rpc_url_flag: global.rpc_url.clone(),
            allow_insecure_rpc: global.allow_insecure_rpc,
            json: global.json,
        })
    }

    /// Apply the third step of the RPC-URL precedence chain: if the
    /// flag/env stage produced nothing, fall back to the deployment
    /// file's `chain.rpc_default`. Caller passes the already-loaded
    /// default value because reading the JSON is the chain-adapter's
    /// job (not the config's).
    pub fn rpc_url_or_default(&self, deployment_default: &str) -> String {
        match self.rpc_url_flag.as_deref() {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => deployment_default.to_owned(),
        }
    }

    /// **P8 fix MED-2.** Refuse a non-`https` RPC URL unless the
    /// caller explicitly opted in via `--allow-insecure-rpc`. Should
    /// be called by every subcommand that constructs a chain
    /// adapter immediately after `rpc_url_or_default`.
    ///
    /// Errors carry a clear remediation hint so a user pointing
    /// `pangolin-cli` at `http://localhost:8545` for local anvil
    /// testing knows the exact flag to add.
    pub fn enforce_rpc_scheme(&self, url: &str) -> Result<()> {
        // Treat `https://...` (any case) as the only acceptable
        // scheme by default. The check is scheme-prefix-only — the
        // adapter does its own URL-parse validation downstream;
        // this is a defense-in-depth gate that fails fast before
        // any keystore prompt or RPC dial.
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("https://") {
            return Ok(());
        }
        if self.allow_insecure_rpc {
            return Ok(());
        }
        Err(anyhow!(
            "RPC URL must use https; pass --allow-insecure-rpc to override (use only for local development). got: {url}"
        ))
    }

    /// Require the deployment-file path; fail with a clear error if
    /// it could not be auto-resolved.
    pub fn require_deployment_file(&self) -> Result<&PathBuf> {
        self.deployment_file.as_ref().ok_or_else(|| {
            anyhow!(
                "could not locate contracts/deployments/base-sepolia.json. \
                 Run pangolin-cli from the Pangolin workspace or pass \
                 --deployment-file <path>."
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ResolvedConfig;
    use crate::cli::GlobalArgs;

    fn args(rpc_flag: Option<&str>) -> GlobalArgs {
        GlobalArgs {
            deployment_file: None,
            rpc_url: rpc_flag.map(ToOwned::to_owned),
            allow_insecure_rpc: false,
            json: false,
        }
    }

    /// `rpc_url_or_default` returns the flag value when one was given.
    #[test]
    fn rpc_flag_takes_precedence_over_default() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: Some("https://flag.test/rpc".into()),
            allow_insecure_rpc: false,
            json: false,
        };
        assert_eq!(
            cfg.rpc_url_or_default("https://default.test/rpc"),
            "https://flag.test/rpc"
        );
    }

    /// `rpc_url_or_default` falls back to the deployment default when
    /// no flag was given.
    #[test]
    fn deployment_default_is_used_when_flag_absent() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: None,
            allow_insecure_rpc: false,
            json: false,
        };
        assert_eq!(
            cfg.rpc_url_or_default("https://default.test/rpc"),
            "https://default.test/rpc"
        );
    }

    /// `rpc_url_or_default` ignores an empty flag value (treats it as
    /// "not set"). Defensive against scripts that pass `--rpc-url ""`.
    #[test]
    fn empty_rpc_flag_falls_through_to_default() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: Some(String::new()),
            allow_insecure_rpc: false,
            json: false,
        };
        assert_eq!(
            cfg.rpc_url_or_default("https://default.test/rpc"),
            "https://default.test/rpc"
        );
    }

    /// `require_deployment_file` errors when none is set.
    #[test]
    fn require_deployment_file_errors_when_unset() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: None,
            allow_insecure_rpc: false,
            json: false,
        };
        let err = cfg.require_deployment_file().unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("base-sepolia.json"),
            "expected helpful error mentioning the deployment file, got: {msg}"
        );
    }

    /// `from_args` produces a config that mirrors its inputs (the
    /// deployment-file walk is best-effort; if no file is found it
    /// stays `None`).
    #[test]
    fn from_args_passes_through_flags() {
        let g = args(Some("https://flag.test/rpc"));
        let cfg = ResolvedConfig::from_args(&g).expect("from_args ok");
        assert_eq!(cfg.rpc_url_flag.as_deref(), Some("https://flag.test/rpc"));
        assert!(!cfg.allow_insecure_rpc, "default is secure");
    }

    /// **P8 fix MED-2.** An `http://` RPC URL is refused by default.
    #[test]
    fn http_rpc_rejected_without_flag() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: Some("http://localhost:8545".into()),
            allow_insecure_rpc: false,
            json: false,
        };
        let err = cfg
            .enforce_rpc_scheme("http://localhost:8545")
            .expect_err("non-https must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("https"),
            "error message must mention https; got: {msg}"
        );
        assert!(
            msg.contains("--allow-insecure-rpc"),
            "error must mention the override flag; got: {msg}"
        );
    }

    /// **P8 fix MED-2.** With `--allow-insecure-rpc`, an `http://`
    /// URL is accepted (for local-anvil testing).
    #[test]
    fn http_rpc_accepted_with_flag() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: Some("http://localhost:8545".into()),
            allow_insecure_rpc: true,
            json: false,
        };
        cfg.enforce_rpc_scheme("http://localhost:8545")
            .expect("with --allow-insecure-rpc, http is permitted");
    }

    /// `https://` is always accepted, regardless of the
    /// `allow_insecure_rpc` flag.
    #[test]
    fn https_rpc_always_accepted() {
        for allow_insecure_rpc in [false, true] {
            let cfg = ResolvedConfig {
                deployment_file: None,
                rpc_url_flag: Some("https://example.test/rpc".into()),
                allow_insecure_rpc,
                json: false,
            };
            cfg.enforce_rpc_scheme("https://example.test/rpc")
                .expect("https is always accepted");
        }
    }

    /// HTTPS-scheme matching is case-insensitive (per RFC 3986
    /// scheme-name canonicalization).
    #[test]
    fn https_scheme_match_is_case_insensitive() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: None,
            allow_insecure_rpc: false,
            json: false,
        };
        cfg.enforce_rpc_scheme("HTTPS://example.test/rpc")
            .expect("HTTPS:// is accepted");
        cfg.enforce_rpc_scheme("Https://example.test/rpc")
            .expect("Https:// is accepted");
    }
}
