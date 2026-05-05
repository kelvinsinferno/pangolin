//! Client for the Pangolin funder service.
//!
//! Per D-006: the funder is a one-way ETH dispenser. This client requests
//! top-ups when the device wallet's balance is insufficient for the next
//! revision. The client never holds vault keys; the funder never signs or
//! submits transactions. Real implementation lands in MVP-2 issue 3.5.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for P0-1.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-funder-client"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-funder-client");
    }
}
