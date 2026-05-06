//! Vault open + unlock helpers.
//!
//! Common path used by every subcommand: open the `.pvf` file, prompt
//! for the vault password (or use `--vault-password`), then unlock
//! with the standard P4 two-proof flow (presence + identity). The
//! returned `Vault` is in `Active` state; the caller can run any
//! credential or metadata op on it.

use std::path::Path;

use anyhow::{bail, Context, Result};
use pangolin_crypto::secret::SecretBytes;
use pangolin_store::session::{PinIdentityProof, PressYPresenceProof};
use pangolin_store::Vault;

/// Open the `.pvf` at `path` and unlock it. Prompts for the password
/// without echo if `flag_value` is `None`.
pub fn open_and_unlock(path: &Path, flag_value: Option<&str>) -> Result<Vault> {
    let mut vault = Vault::open(path).with_context(|| {
        format!(
            "failed to open vault at {} (file missing? wrong format?)",
            path.display()
        )
    })?;
    let password = read_vault_password(path, flag_value)?;
    let presence = PressYPresenceProof::confirmed();
    let identity = PinIdentityProof::new(password);
    vault
        .unlock(&presence, &identity)
        .context("vault unlock failed (wrong password?)")?;
    Ok(vault)
}

/// Open the `.pvf` at `path` WITHOUT unlocking. Useful for `status`
/// when the user just wants the metadata-only counters
/// (`last_pulled_block`, dirty count, etc.) without typing the
/// password.
//
// P8-3: defined here for use by `status` (P8-5). Marked
// `#[allow(dead_code)]` until that consumer lands.
#[allow(dead_code)]
pub fn open_locked(path: &Path) -> Result<Vault> {
    let vault = Vault::open(path).with_context(|| {
        format!(
            "failed to open vault at {} (file missing? wrong format?)",
            path.display()
        )
    })?;
    Ok(vault)
}

/// Read the vault password — either from `--vault-password` (echoes
/// in `ps`; for CI/scripted use only) or by prompting the terminal
/// without echo via `rpassword`. Returns a `SecretBytes` that
/// zeroizes on drop.
fn read_vault_password(vault_path: &Path, flag_value: Option<&str>) -> Result<SecretBytes> {
    if let Some(s) = flag_value {
        if s.is_empty() {
            bail!("--vault-password was passed but is empty");
        }
        return Ok(SecretBytes::new(s.as_bytes().to_vec()));
    }
    let prompt = format!("Enter password for vault {}: ", vault_path.display());
    let entered = rpassword::prompt_password(prompt)
        .context("failed to read vault password from terminal")?;
    Ok(SecretBytes::new(entered.into_bytes()))
}
