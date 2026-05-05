//! Pangolin CLI — thin shell over `pangolin-core`.
//!
//! For P0-1 this binary just prints a version banner so CI and humans can
//! verify the workspace builds end-to-end. Real subcommands (init, unlock,
//! publish, pull, resolve) land in the P8 series.

#![cfg_attr(not(test), forbid(unsafe_code))]

fn main() {
    let core = pangolin_core::name();
    println!("pangolin v{} ({} linked)", env!("CARGO_PKG_VERSION"), core);
}

#[cfg(test)]
mod tests {
    /// Smoke test: the binary entry point compiles and `pangolin-core` is reachable.
    /// End-to-end output verification belongs in an integration test once the
    /// CLI grows real subcommands.
    #[test]
    fn core_is_linked() {
        assert_eq!(pangolin_core::name(), "pangolin-core");
    }
}
