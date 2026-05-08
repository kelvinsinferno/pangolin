//! TOTP (RFC 6238) code generation for Pangolin.
//!
//! Per MVP-1 issue 1.1 (Q4), the TOTP implementation lives in its own
//! crate so the per-crate `forbid(unsafe_code)` and per-crate `deny.toml`
//! scopes can be tightest possible: any RFC 6238 implementation bug is
//! blast-contained, the HMAC-SHA1 dependency surface never reaches
//! `pangolin-core`, and `pangolin-crypto`'s zero-serde audit boundary is
//! preserved.
//!
//! Body lands in MVP-1 issue 1.7. This is a scaffolding crate from 1.1
//! that holds the workspace member slot and the placeholder `name()`
//! function so dependent crates can compile against the namespace.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for MVP-1 issue 1.1; real surface lands in 1.7.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-totp"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-totp");
    }
}
