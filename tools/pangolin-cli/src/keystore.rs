//! Foundry-keystore resolution helpers.
//!
//! The actual keystore decryption lives in
//! `pangolin-chain::BaseSepoliaAdapter::new_with_keystore`, which
//! delegates to `alloy-signer-local`. This module just resolves
//! `--account <name>` against the standard Foundry keystore
//! directory (or the explicit `--keystore-dir` / `--keystore-path`
//! overrides) and prompts for the password without echo.
//!
//! The pattern mirrors `tools/chaincli/src/commands/publish.rs`
//! byte-for-byte; we deliberately do not share code with chaincli
//! per `P8.md` ("`pangolin-cli` reuses patterns from chaincli, but
//! does not import any chaincli code").

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

/// Resolve the keystore path from `--account` / `--keystore-dir` /
/// `--keystore-path`. Validates the `--account` value as a simple
/// filename (no path separators, no `..`) before joining onto the
/// keystore directory.
pub fn resolve_keystore_path(
    account: Option<&str>,
    keystore_dir: Option<&Path>,
    keystore_path: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(p) = keystore_path {
        if !p.is_file() {
            return Err(anyhow!("keystore file not found: {}", p.display()));
        }
        return Ok(p.to_path_buf());
    }
    let account = account.ok_or_else(|| {
        anyhow!(
            "publish requires either --account <name> or \
             --keystore-path <path>"
        )
    })?;
    validate_account_name(account).context("--account validation failed")?;
    let dir = if let Some(d) = keystore_dir {
        d.to_path_buf()
    } else {
        default_keystore_dir().context("could not locate Foundry keystore directory")?
    };
    let candidate = dir.join(account);
    if !candidate.is_file() {
        return Err(anyhow!(
            "keystore file not found: {} (set --keystore-dir or --account)",
            candidate.display()
        ));
    }
    Ok(candidate)
}

/// Read the keystore password — either from `--keystore-password`
/// (echoes in `ps`; for CI/scripted use only) or by prompting the
/// terminal without echo via `rpassword`. Returns the password
/// wrapped in `zeroize::Zeroizing<String>` so the heap buffer is
/// overwritten on drop.
pub fn read_keystore_password(
    keystore_path: &Path,
    flag_value: Option<&str>,
) -> Result<zeroize::Zeroizing<String>> {
    if let Some(s) = flag_value {
        if s.is_empty() {
            bail!("--keystore-password was passed but is empty");
        }
        return Ok(zeroize::Zeroizing::new(s.to_owned()));
    }
    let prompt = format!("Enter password for keystore {}: ", keystore_path.display());
    let entered = rpassword::prompt_password(prompt)
        .context("failed to read keystore password from terminal")?;
    Ok(zeroize::Zeroizing::new(entered))
}

/// Reject `--account` values that aren't simple keystore filenames.
/// Same discipline as chaincli's `validate_account_name`.
fn validate_account_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("--account must be a simple keystore name; got empty string");
    }
    let path = Path::new(name);
    let mut components = path.components();
    let first = components
        .next()
        .ok_or_else(|| anyhow!("--account must be a simple keystore name; got empty path"))?;
    if components.next().is_some() {
        bail!(
            "--account must be a simple keystore name; got {name} \
             (contains path separators)"
        );
    }
    match first {
        Component::Normal(_) => Ok(()),
        Component::CurDir | Component::ParentDir => bail!(
            "--account must be a simple keystore name; got {name} \
             (path-traversal component)"
        ),
        Component::RootDir | Component::Prefix(_) => bail!(
            "--account must be a simple keystore name; got {name} \
             (absolute path)"
        ),
    }
}

/// Default Foundry keystore directory: `$FOUNDRY_DIR/keystores`,
/// falling back to `$HOME/.foundry/keystores` (Linux/macOS) or
/// `%USERPROFILE%\.foundry\keystores` (Windows).
fn default_keystore_dir() -> Result<PathBuf> {
    if let Ok(custom) = std::env::var("FOUNDRY_DIR") {
        return Ok(PathBuf::from(custom).join("keystores"));
    }
    let home = home_dir().ok_or_else(|| anyhow!("could not determine $HOME / %USERPROFILE%"))?;
    Ok(home.join(".foundry").join("keystores"))
}

fn home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        if let Ok(p) = std::env::var("USERPROFILE") {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
    }
    if let Ok(p) = std::env::var("HOME") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::validate_account_name;

    #[test]
    fn validate_accepts_plain_name() {
        validate_account_name("dev").expect("ok");
        validate_account_name("dev-account").expect("ok");
        validate_account_name("a.b").expect("ok");
    }

    #[test]
    fn validate_rejects_empty() {
        let err = validate_account_name("").expect_err("empty rejected");
        assert!(format!("{err:#}").contains("empty"));
    }

    #[test]
    fn validate_rejects_separator() {
        let err = validate_account_name("foo/bar").expect_err("/ rejected");
        assert!(format!("{err:#}").contains("path separators"));
    }

    #[test]
    fn validate_rejects_parent_dir() {
        // ".." can surface either as ParentDir or as having a parent
        // component depending on platform path-parser quirks; both
        // get rejected.
        let err = validate_account_name("..").expect_err(".. rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("path-traversal") || msg.contains("path separators"));
    }
}
