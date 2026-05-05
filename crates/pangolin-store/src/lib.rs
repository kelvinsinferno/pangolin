//! Encrypted local store for Pangolin.
//!
//! `SQLite` + encrypted blobs. Corruption-safe writes (WAL + atomic blob
//! rename). Per cardinal principle 2: no plaintext at rest. Real
//! implementation lands in the P2 series.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for P0-1.
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
