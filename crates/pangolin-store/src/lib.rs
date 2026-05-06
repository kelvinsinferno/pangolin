//! Encrypted local store for Pangolin.
//!
//! `SQLite` + encrypted blobs. Corruption-safe writes (WAL +
//! transactional schema). Per cardinal principle 2: no plaintext at
//! rest. The full design is documented in `docs/issue-plans/P2.md`.
//!
//! ## Public surface
//!
//! `Vault` is the only credential-bearing public type — every other
//! module is plumbing for it. Snapshots ([`account::AccountSnapshot`])
//! and identifiers ([`account::AccountId`], [`revision::RevisionId`]) are
//! the value types you'll feed in and read back.
//!
//! ```no_run
//! use std::path::Path;
//! use pangolin_crypto::secret::SecretBytes;
//! use pangolin_store::{Vault, AccountSnapshot};
//!
//! let pwd = SecretBytes::new(b"correct horse battery staple".to_vec());
//! Vault::create(Path::new("./vault.pvf"), &pwd)?;
//! let mut v = Vault::open(Path::new("./vault.pvf"))?;
//! v.unlock(&pwd)?;
//! // … add_account / search / update_account / lock / close …
//! # Ok::<(), pangolin_store::StoreError>(())
//! ```

#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

pub mod account;
pub mod error;
pub mod revision;
pub mod vault;

pub(crate) mod blob;
pub(crate) mod meta;
pub(crate) mod schema;
pub(crate) mod search;

pub use account::{AccountId, AccountSnapshot};
pub use error::{Result, StoreError};
pub use revision::{ChainAnchor, DeviceId, RevisionId, RevisionMeta};
pub use vault::{Vault, VaultState};

/// Returns the crate name. Useful for diagnostics and version reporting.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-store"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-store");
    }
}
