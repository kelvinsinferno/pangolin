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
            json: false,
        }
    }

    /// `rpc_url_or_default` returns the flag value when one was given.
    #[test]
    fn rpc_flag_takes_precedence_over_default() {
        let cfg = ResolvedConfig {
            deployment_file: None,
            rpc_url_flag: Some("https://flag.test/rpc".into()),
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
    }
}
