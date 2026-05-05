//! `EVM` chain adapter for Pangolin.
//!
//! Direct-submit transport (per D-006: no relay; device key signs and pays
//! gas). Signed-revision builder. Real implementation lands in the P7
//! series.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for P0-1.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-chain"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-chain");
    }
}
