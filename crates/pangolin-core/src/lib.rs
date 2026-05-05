//! Pangolin core vault engine.
//!
//! This crate is the single source of truth for security-critical logic:
//! account identity, encryption + key management, immutable revision model,
//! conflict detection, sync orchestration, session policy, and social
//! recovery client logic.
//!
//! Per master plan §0 cardinal principle 1: clients are thin shells that
//! ask this crate for decisions. They never reimplement security logic.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for P0-1; real surface lands in P3+ / MVP-1.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-core"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-core");
    }
}
