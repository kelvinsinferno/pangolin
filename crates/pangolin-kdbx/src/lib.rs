//! KDBX (`KeePass`) import for Pangolin.
//!
//! Per MVP-1 issue 1.1 (Q4), KDBX import lives in its own crate so the
//! XML-parser / kdbx-parsing dependency surface never reaches
//! `pangolin-core`'s tree, the per-crate `forbid(unsafe_code)` is
//! tightest possible, and `pangolin-crypto`'s zero-serde audit boundary
//! is preserved.
//!
//! Body lands in MVP-1 issue 1.9. This is a scaffolding crate from 1.1
//! that holds the workspace member slot and the placeholder `name()`
//! function so dependent crates can compile against the namespace.

#![cfg_attr(not(test), forbid(unsafe_code))]

/// Returns the crate name. Placeholder for MVP-1 issue 1.1; real surface lands in 1.9.
#[must_use]
pub fn name() -> &'static str {
    "pangolin-kdbx"
}

#[cfg(test)]
mod tests {
    use super::name;

    #[test]
    fn crate_name_is_set() {
        assert_eq!(name(), "pangolin-kdbx");
    }
}
