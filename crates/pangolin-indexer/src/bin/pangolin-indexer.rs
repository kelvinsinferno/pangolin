// SPDX-License-Identifier: AGPL-3.0-or-later
//! 4.2 R-e desktop subprocess entry — thin shim.
//!
//! Per L12 + R-e: the lifecycle logic is in
//! `pangolin_indexer::IndexerSession`. This binary's job is to:
//!
//! 1. Parse argv (`--rpc-url`, `--env`).
//! 2. Initialise `tracing_subscriber` to stderr (R-b: stdout is
//!    reserved for the JSON protocol).
//! 3. **§4.3 per-column AEAD (ARCH-1): consume the binary handshake**
//!    on stdin BEFORE the chain-RPC config and the protocol loop.
//!    The host (CLI / Tauri / mobile FFI wrapper) derives the
//!    ephemeral AEAD key from the device secret via
//!    `pangolin_chain::derive_indexer_key` and writes the
//!    length-prefixed CBOR-framed `IndexerHandshake` to the binary's
//!    stdin. The binary deserialises, zeroizes the staging buffer,
//!    and constructs `AeadCipher` from the received key. The
//!    `OsRng::fill_bytes`/`fill_random` random-key path the §4.3
//!    baseline used is GONE — the binary no longer generates its
//!    own key.
//! 4. Resolve `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS` via the library
//!    helper.
//! 5. Construct an `IndexerSession` with the per-column `AeadCipher`.
//! 6. Run the stdio loop:
//!    `BufReader<stdin>::lines()` → `serde_json::from_str` →
//!    `session.handle_request(req).await` → `serde_json::to_string`
//!    + write line to stdout.
//! 7. Exit cleanly on a `Stop` request, an idle-timeout fire, or
//!    a ctrl_c / SIGTERM (per L11 — both Drop + signal handler
//!    fire on shutdown).
//!
//! ## Host caller contract (MVP-3 host-FFI cycle)
//!
//! See [`pangolin_indexer::handshake`] for the full spawn-and-write
//! sequence. The binary expects the handshake bytes BEFORE any line-
//! delimited JSON; if the handshake fails (truncated, malformed CBOR,
//! wrong field shape), the binary exits with a fatal stderr message
//! and a non-zero exit code WITHOUT writing anything to stdout (so
//! the host's JSON protocol parser is never confused by a partial
//! response).

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::signal;
use tokio::time::{sleep_until, Instant};
use tracing_subscriber::EnvFilter;

use pangolin_chain::ChainEnv;
use pangolin_crypto::secret::SecretBytes;
use pangolin_indexer::{
    read_handshake, AeadCipher, IndexerConfig, IndexerError, IndexerRequest, IndexerResponse,
    IndexerSession, MAX_REQUEST_LINE_BYTES,
};
use zeroize::Zeroize;

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

    // ---- §4.3 per-column AEAD (ARCH-1): consume binary handshake ----
    //
    // The host (CLI / Tauri / mobile FFI wrapper) MUST have written
    // a length-prefixed CBOR `IndexerHandshake` to our stdin BEFORE
    // the first protocol request. We read it synchronously via
    // `std::io::stdin().lock()` BEFORE switching to tokio's async
    // stdin for the line-delimited protocol loop. Mixing the two is
    // safe here because we consume exactly the handshake bytes
    // (4-byte length prefix + body) up-front; everything that
    // follows on the same FD is a clean newline-terminated JSON
    // stream that tokio's BufReader picks up.
    //
    // R-e (ARCH-1) rationale: the standalone binary NEVER imports
    // `DeviceKey` (`L-indexer-grows-pangolin-crypto-secret-
    // material-reach` defense); the host derives via
    // `pangolin_chain::derive_indexer_key(device_key, run_nonce)`
    // and pipes the 32-byte derived key to us through this
    // handshake. The pre-§4.3-per-column-AEAD path used
    // `OsRng::fill_bytes` to mint an ad-hoc per-run key — that
    // satisfied the "ephemeral" property but failed the "derived
    // from device secret" property of master plan §5 row 4.3. The
    // handshake closes that gap.
    let handshake = {
        let mut stdin_sync = std::io::stdin().lock();
        read_handshake(&mut stdin_sync).map_err(|e| IndexerError::Config {
            message: format!("indexer handshake failed: {e}"),
        })?
    };
    // Move the derived key into a heap-allocated `SecretBytes` (the
    // zeroize-on-drop wrapper) and IMMEDIATELY zeroize the local
    // `IndexerHandshake.derived_key` stack-side array. The
    // `IndexerHandshake::Drop` impl also runs zeroize on Drop, so
    // this is belt-and-suspenders — but the explicit zeroize here
    // makes the discipline grep-able for the audit.
    let cipher = {
        let mut key_bytes = handshake.derived_key;
        let cipher_arc = AeadCipher::new_arc(SecretBytes::new(key_bytes.to_vec()));
        key_bytes.zeroize();
        cipher_arc
    };
    // The run_nonce is non-secret (it's HKDF salt). We don't carry
    // it forward into the session for 4.3; future cycles may mix it
    // into the AAD or surface it in diagnostics. The handshake's
    // Drop impl handles cleanup.
    drop(handshake);

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
