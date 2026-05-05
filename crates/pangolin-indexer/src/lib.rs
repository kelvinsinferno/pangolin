//! Ephemeral local indexer for Pangolin.
//!
//! Per D-007: no persistent indexer service. This library indexes only the
//! caller's `vault_id` from chain events and auto-deletes its temp database
//! when the sync completes or after an idle timeout. Real implementation
//! lands in MVP-2 issues 4.2–4.4.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for P0-1.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-indexer"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-indexer");
    }
}
