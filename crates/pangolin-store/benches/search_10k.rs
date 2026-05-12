// SPDX-License-Identifier: AGPL-3.0-or-later
//! MVP-1 issue 1.3 — 10k-account search benchmark.
//!
//! Hand-rolled `Instant`-timed harness (no `criterion` dependency — the
//! workspace pins a closed crate set and adding criterion's tree would
//! be churn). Builds a 10k-account vault, then measures:
//!
//!   1. `Vault::account_search` for a common single-term query, a rarer
//!      tag query, and a hostname query — target **< 50 ms** per the
//!      master-plan exit criterion (we aim for well under it).
//!   2. The unlock-time `:memory:` FTS5 index rebuild for 10k accounts
//!      (the cost the `:memory:` design adds on top of the AEAD decrypts
//!      `unlock` already does).
//!
//! Run with: `cargo bench -p pangolin-store --features test-utilities`
//! (the bench needs the same `test-utilities` feature gate as the e2e
//! integration tests — see `Cargo.toml`'s `[[bench]]` entry). Output is
//! plain `eprintln!` lines so `PowerShell` stdout-redirection quirks
//! (#5/#6) don't apply — nothing is written to stdout.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::time::Instant;

use pangolin_crypto::secret::SecretBytes;
use pangolin_store::{
    AccountIdentityDraft, PinIdentityProof, PressYPresenceProof, TotpParams, Vault,
    ACCOUNT_IDENTITY_SCHEMA_VERSION,
};

const N: u32 = 10_000;
const ITERS: u32 = 50;

fn pwd() -> SecretBytes {
    SecretBytes::new(b"bench-password-correct-horse".to_vec())
}
fn pin() -> PinIdentityProof {
    PinIdentityProof::new(pwd())
}
fn presence() -> PressYPresenceProof {
    PressYPresenceProof::confirmed()
}

fn draft(i: u32) -> AccountIdentityDraft {
    AccountIdentityDraft {
        schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
        display_name: format!("Service {i}"),
        tags: vec![
            "bench".to_owned(),
            if i.is_multiple_of(97) {
                "rare".to_owned()
            } else {
                "common".to_owned()
            },
        ],
        usernames: vec![format!("user{i}@example.com")],
        urls: vec![format!("https://host{i}.example/path")],
        notes: String::new(),
        password: SecretBytes::new(b"pw".to_vec()),
        totp_secret: SecretBytes::new(Vec::new()),
        totp_params: TotpParams::default(),
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn time_query(v: &mut Vault, query: &str, iters: u32) -> (f64, f64, usize) {
    let mut samples: Vec<f64> = Vec::with_capacity(iters as usize);
    let mut last_hits = 0;
    for _ in 0..iters {
        let t0 = Instant::now();
        let hits = v.account_search(query).expect("search ok");
        samples.push(t0.elapsed().as_secs_f64() * 1000.0);
        last_hits = hits.len();
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (
        percentile(&samples, 0.5),
        percentile(&samples, 0.99),
        last_hits,
    )
}

fn main() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("bench10k.pvf");
    Vault::create(&path, &pwd()).expect("create");

    eprintln!("[search_10k] building {N}-account vault …");
    let build0 = Instant::now();
    {
        let mut v = Vault::open(&path).expect("open");
        v.unlock(&presence(), &pin()).expect("unlock");
        for i in 0..N {
            v.account_add(draft(i)).expect("account_add");
        }
        v.lock();
        v.close().expect("close");
    }
    eprintln!(
        "[search_10k] populated {N} accounts in {:?}",
        build0.elapsed()
    );

    // Measure the unlock-time index rebuild (the `:memory:` FTS5 build
    // is part of `unlock`; `unlock` also runs Argon2id + AEAD-decrypts
    // every head, so this is the total unlock cost — the FTS build is
    // the marginal add on top of those).
    let mut rebuild_samples: Vec<f64> = Vec::new();
    for _ in 0..5 {
        let t0 = Instant::now();
        let mut v = Vault::open(&path).expect("open");
        v.unlock(&presence(), &pin()).expect("unlock");
        rebuild_samples.push(t0.elapsed().as_secs_f64() * 1000.0);
        v.lock();
        v.close().expect("close");
    }
    rebuild_samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    eprintln!(
        "[search_10k] unlock (Argon2id + decrypt {N} heads + FTS5 rebuild): median {:.1} ms / min {:.1} ms over 5 runs",
        percentile(&rebuild_samples, 0.5),
        rebuild_samples[0]
    );

    // Now the search measurements.
    let mut v = Vault::open(&path).expect("open");
    v.unlock(&presence(), &pin()).expect("unlock");

    let (med, p99, hits) = time_query(&mut v, "service", ITERS);
    eprintln!(
        "[search_10k] account_search(\"service\")  median {med:.3} ms / p99 {p99:.3} ms / {hits} hits (capped at 200) over {ITERS} iters"
    );
    // No hard timing assertion here — this bench is a *measurement* tool,
    // not a perf gate. `cargo test --workspace --all-targets` runs benches
    // in debug mode on CI (a slow shared runner), where a 50 ms target
    // is unattainable even though release-mode on a fast host meets it
    // easily. The authoritative gate is the `#[ignore]`'d
    // `search_10k_smoke` test in `tests/e2e.rs`, which is opt-in and runs
    // with `--release --features test-utilities -- --ignored` per Q4 of
    // `docs/issue-plans/1.3.md`.

    let (med, p99, hits) = time_query(&mut v, "common", ITERS);
    eprintln!(
        "[search_10k] account_search(\"common\")   median {med:.3} ms / p99 {p99:.3} ms / {hits} hits"
    );

    let (med, p99, hits) = time_query(&mut v, "rare", ITERS);
    eprintln!(
        "[search_10k] account_search(\"rare\")     median {med:.3} ms / p99 {p99:.3} ms / {hits} hits"
    );

    let (med, p99, hits) = time_query(&mut v, "host4242", ITERS);
    eprintln!(
        "[search_10k] account_search(\"host4242\") median {med:.3} ms / p99 {p99:.3} ms / {hits} hits"
    );

    let (med, p99, _) = time_query(&mut v, "", ITERS);
    eprintln!(
        "[search_10k] account_search(\"\") (all)   median {med:.3} ms / p99 {p99:.3} ms / 200 hits (capped)"
    );

    v.lock();
    v.close().expect("close");
    eprintln!("[search_10k] done.");
}
