// SPDX-License-Identifier: AGPL-3.0-or-later
//! Funder service entry point.
//!
//! Per MVP-2 issue 3.4: spin up an axum HTTP server bound to the
//! configured port, load the keystore, open the `SQLite` ledger, read
//! the `EntitlementRegistry`'s `PAYMENT_AUTHORITY` address from chain
//! at startup (R-c), and serve until graceful SIGTERM.

#![forbid(unsafe_code)]

use std::sync::Arc;

use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use alloy::sol;
use tokio::signal;
use tracing_subscriber::EnvFilter;

use pangolin_chain::load_deployed_address;
use pangolin_funder::{
    config::FunderConfig,
    error::FunderError,
    http::{routes::router, AppState},
    ledger::PaymentLedger,
    rate_limit::RateLimiter,
    signer::{FileKeystoreSigner, FunderSigner},
};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("pangolin-funder fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), FunderError> {
    // ---- Tracing ----
    // Default to INFO; operator overrides via `RUST_LOG`. The funder
    // never emits userId / deviceAddress / Credit-attestation bytes
    // at INFO per L12 — see handler call sites for the
    // class-tag-only event shape.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // ---- Config ----
    let cfg = FunderConfig::from_env()?;
    tracing::info!(
        target: "pangolin_funder::main",
        bind_addr = %cfg.bind_addr,
        chain_env = ?cfg.chain_env,
        "starting funder service"
    );

    // ---- Signer ----
    let signer = load_signer(&cfg)?;
    tracing::info!(
        target: "pangolin_funder::main",
        signer_address = %signer.address(),
        "funder signer loaded"
    );

    // ---- Ledger ----
    let ledger = PaymentLedger::open(&cfg.ledger_path).map_err(|e| {
        FunderError::Configuration(format!("open ledger at {}: {e}", cfg.ledger_path.display()))
    })?;

    // ---- Registry address ----
    let registry_address = load_deployed_address(cfg.chain_env, "EntitlementRegistry")?;
    tracing::info!(
        target: "pangolin_funder::main",
        registry = %registry_address,
        "EntitlementRegistry address loaded from deployment file"
    );

    // ---- Read PAYMENT_AUTHORITY (R-c cache-at-startup) ----
    let payment_authority = read_payment_authority(&cfg.rpc_url, registry_address).await?;
    tracing::info!(
        target: "pangolin_funder::main",
        payment_authority = %payment_authority,
        "PAYMENT_AUTHORITY cached from on-chain read"
    );

    // ---- State + router ----
    let rate_limiter = RateLimiter::new(cfg.rate_limit);
    let state = AppState {
        signer,
        ledger,
        rate_limiter,
        registry_address,
        payment_authority,
        chain_env: cfg.chain_env,
        rpc_url: cfg.rpc_url.clone(),
    };
    let app = router(state, cfg.body_size_limit_bytes);

    // ---- Serve ----
    let listener = tokio::net::TcpListener::bind(cfg.bind_addr)
        .await
        .map_err(|e| FunderError::Configuration(format!("bind {}: {e}", cfg.bind_addr)))?;
    tracing::info!(target: "pangolin_funder::main", "funder listening on {}", cfg.bind_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| FunderError::Configuration(format!("axum serve: {e}")))?;
    Ok(())
}

fn load_signer(cfg: &FunderConfig) -> Result<Arc<dyn FunderSigner>, FunderError> {
    // Prefer keystore path; fall back to dev private-key env var only
    // when the keystore is unset. Both `Some` is rejected to keep the
    // path unambiguous.
    match (cfg.keystore_path.as_ref(), cfg.dev_private_key_hex.as_ref()) {
        (Some(path), None) => {
            let passphrase = if let Some(p) = cfg.keystore_passphrase_file.as_ref() {
                FileKeystoreSigner::read_passphrase_from_file(p)?
            } else {
                // No passphrase-file: read from stdin (TTY).
                eprint!("funder keystore passphrase: ");
                let mut buf = String::new();
                std::io::Write::flush(&mut std::io::stderr()).ok();
                std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut buf)
                    .map_err(|e| FunderError::Keystore(format!("read passphrase: {e}")))?;
                buf.trim().to_owned()
            };
            let signer = FileKeystoreSigner::from_keystore(path, &passphrase)?;
            Ok(Arc::new(signer))
        }
        (None, Some(hex)) => {
            let signer = FileKeystoreSigner::from_private_key_hex(hex)?;
            Ok(Arc::new(signer))
        }
        (Some(_), Some(_)) => Err(FunderError::Configuration(
            "set EITHER FUNDER_KEYSTORE_PATH or FUNDER_PRIVATE_KEY_HEX, not both".into(),
        )),
        (None, None) => Err(FunderError::Configuration(
            "no signer configured; set FUNDER_KEYSTORE_PATH (production) or FUNDER_PRIVATE_KEY_HEX (dev)"
                .into(),
        )),
    }
}

// alloy `sol!` binding for the single view fn we call at startup.
// Scoped to this module so the funder's main never grows a broader
// EntitlementRegistry surface here (the redeem path lives in
// pangolin-chain's `chain_submit::EntitlementRegistry` binding).
sol! {
    #[sol(rpc)]
    contract EntitlementRegistryViews {
        function PAYMENT_AUTHORITY() external view returns (address);
    }
}

async fn read_payment_authority(
    rpc_url: &str,
    registry_address: Address,
) -> Result<Address, FunderError> {
    let provider = ProviderBuilder::new()
        .connect(rpc_url)
        .await
        .map_err(|e| FunderError::Configuration(format!("connect RPC {rpc_url}: {e}")))?;
    let registry = EntitlementRegistryViews::new(registry_address, provider);
    let result = registry
        .PAYMENT_AUTHORITY()
        .call()
        .await
        .map_err(|e| FunderError::Configuration(format!("read PAYMENT_AUTHORITY(): {e}")))?;
    Ok(result)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            s.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!(target: "pangolin_funder::main", "shutdown signal received");
}
