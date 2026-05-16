// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 R-e desktop subprocess entry — thin shim.
//!
//! Per L12 + R-e: the lifecycle logic is in
//! `pangolin_indexer::IndexerSession`. This binary's job is to:
//!
//! 1. Parse argv (`--rpc-url`, `--env`).
//! 2. Initialise `tracing_subscriber` to stderr (R-b: stdout is
//!    reserved for the JSON protocol).
//! 3. Resolve `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS` via the library
//!    helper.
//! 4. Construct an `IndexerSession` with `NoOpCipher` (4.3 swaps
//!    this in).
//! 5. Run the stdio loop:
//!    `BufReader<stdin>::lines()` → `serde_json::from_str` →
//!    `session.handle_request(req).await` → `serde_json::to_string`
//!    + write line to stdout.
//! 6. Exit cleanly on a `Stop` request, an idle-timeout fire, or
//!    a ctrl_c / SIGTERM (per L11 — both Drop + signal handler
//!    fire on shutdown).

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::signal;
use tokio::time::{sleep_until, Instant};
use tracing_subscriber::EnvFilter;

use pangolin_chain::ChainEnv;
use pangolin_crypto::rng::fill_random;
use pangolin_crypto::secret::SecretBytes;
use pangolin_indexer::{
    AeadCipher, IndexerConfig, IndexerError, IndexerRequest, IndexerResponse, IndexerSession,
    MAX_REQUEST_LINE_BYTES,
};

#[derive(Debug, Parser)]
#[command(
    name = "pangolin-indexer",
    about = "Pangolin ephemeral local indexer (MVP-2 issue 4.2). Reads RevisionPublished events from D-017; writes a per-run temp DB; auto-deletes on completion or idle timeout."
)]
struct Cli {
    /// Chain RPC URL (HTTP or HTTPS). Required.
    #[arg(long, env = "PANGOLIN_INDEXER_RPC_URL")]
    rpc_url: String,

    /// Chain environment. One of `base-sepolia`, `base-mainnet`,
    /// `dev`. Defaults to `base-sepolia` (the only env with a
    /// pinned D-017 in MVP-2).
    #[arg(
        long,
        env = "PANGOLIN_INDEXER_CHAIN_ENV",
        default_value = "base-sepolia"
    )]
    env: String,
}

fn parse_env(s: &str) -> Result<ChainEnv, String> {
    match s.to_ascii_lowercase().as_str() {
        "base-sepolia" | "base_sepolia" | "basesepolia" => Ok(ChainEnv::BaseSepolia),
        "base-mainnet" | "base_mainnet" | "basemainnet" => Ok(ChainEnv::BaseMainnet),
        "dev" | "local" => Ok(ChainEnv::Dev),
        other => Err(format!("unknown chain env: {other:?}")),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        // L1/L11 hygiene: stderr is fine for the operator-visible
        // exit message; stdout would corrupt the JSON protocol
        // stream if the host is still reading.
        eprintln!("pangolin-indexer fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), IndexerError> {
    // ---- Tracing (stderr) ----
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,pangolin_indexer=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr) // R-b: stdout reserved for protocol.
        .init();

    // ---- CLI ----
    let cli = Cli::parse();
    let env = parse_env(&cli.env).map_err(|m| IndexerError::Config { message: m })?;
    let config = IndexerConfig::new(cli.rpc_url, env);
    let idle = Duration::from_secs(config.idle_timeout_secs);
    tracing::info!(
        target: "pangolin_indexer::bin",
        chain_env = ?config.env,
        idle_timeout_secs = config.idle_timeout_secs,
        "starting indexer session"
    );

    // ---- Session ----
    // 4.3 R-b + L10: production builds construct `AeadCipher` with
    // a fresh random 32-byte key per run. The key never persists to
    // disk; on Drop the SecretBytes wrapper zeroes it.
    //
    // For host integrations that want a deterministic key derived
    // from the device secret (e.g., the desktop CLI wrapper that
    // already holds an unlocked Vault), the in-process API
    // `pangolin_chain::derive_indexer_key` produces an equivalent
    // 32-byte SecretBytes. The standalone `pangolin-indexer` binary
    // does NOT receive the device secret — it generates a fresh key
    // here so the binary's blast radius stays minimal (4.3 plan-gate
    // L-indexer-grows-pangolin-crypto-secret-material-reach).
    let mut key_bytes = [0u8; 32];
    fill_random(&mut key_bytes);
    let cipher = AeadCipher::new_arc(SecretBytes::new(key_bytes.to_vec()));
    // Wipe the stack-side copy now that the bytes are inside the
    // SecretBytes heap allocation.
    {
        use zeroize::Zeroize;
        key_bytes.zeroize();
    }
    let mut session = IndexerSession::new(config, cipher)?;

    // ---- Stdio loop ----
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    let mut deadline = Instant::now() + idle;
    loop {
        tokio::select! {
            biased;

            // L11 / R-e: ctrl_c triggers a clean shutdown. The
            // Drop on `session` unlinks the temp file as the
            // function unwinds.
            _ = signal::ctrl_c() => {
                tracing::info!(target: "pangolin_indexer::bin", "ctrl_c received; shutting down");
                let resp = IndexerResponse::Stopped;
                write_response(&mut stdout, &resp).await.ok();
                return Ok(());
            }

            // L5 / R-c: idle timeout fires. Drop the session +
            // exit cleanly so the host learns the indexer is
            // gone (and the temp file is gone).
            () = sleep_until(deadline) => {
                tracing::info!(target: "pangolin_indexer::bin", "idle timeout fired; shutting down");
                let resp = IndexerResponse::Error {
                    message: IndexerError::IdleTimeout.to_protocol_message(),
                };
                write_response(&mut stdout, &resp).await.ok();
                return Err(IndexerError::IdleTimeout);
            }

            // Next stdin line.
            line = reader.next_line() => {
                let Some(raw) = line? else {
                    // EOF on stdin. Host closed the pipe; exit.
                    tracing::info!(target: "pangolin_indexer::bin", "stdin EOF; shutting down");
                    return Ok(());
                };
                // L-stdio-injection: enforce the per-line byte cap.
                if raw.len() > MAX_REQUEST_LINE_BYTES {
                    let resp = IndexerResponse::Error {
                        message: format!(
                            "request line exceeds {MAX_REQUEST_LINE_BYTES}-byte cap"
                        ),
                    };
                    write_response(&mut stdout, &resp).await?;
                    continue;
                }
                deadline = Instant::now() + idle;
                match serde_json::from_str::<IndexerRequest>(&raw) {
                    Ok(req) => {
                        let is_stop = matches!(req, IndexerRequest::Stop);
                        let response = match session.handle_request(req).await {
                            Ok(r) => r,
                            Err(e) => IndexerResponse::Error {
                                message: e.to_protocol_message(),
                            },
                        };
                        write_response(&mut stdout, &response).await?;
                        if is_stop {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        let resp = IndexerResponse::Error {
                            message: format!("protocol error: {e}"),
                        };
                        write_response(&mut stdout, &resp).await?;
                    }
                }
            }
        }
    }
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    stdout: &mut W,
    resp: &IndexerResponse,
) -> Result<(), IndexerError> {
    let line = serde_json::to_string(resp).map_err(|e| IndexerError::ProtocolError {
        message: format!("serialise response: {e}"),
    })?;
    stdout.write_all(line.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}
