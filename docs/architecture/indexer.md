# Ephemeral local indexer (MVP-2 issues 4.2 + 4.3)

> Source: `crates/pangolin-indexer/` + `crates/pangolin-chain/src/evm.rs`
> (`derive_indexer_key`). Plan-gates:
> [`docs/issue-plans/4.2.md`](../issue-plans/4.2.md) +
> [`docs/issue-plans/4.3.md`](../issue-plans/4.3.md). D-007 in
> [`DECISIONS.md`](../../DECISIONS.md). Threat-model rows in
> [`THREAT_MODEL.md`](../../THREAT_MODEL.md).

## Scope

The Pangolin client offers two chain-read modes:

- **Slow mode (4.1; default).** `Vault::sync_from_chain` issues
  chunked `eth_getLogs` directly, verifying + ingesting one chunk at
  a time. Adequate for incremental syncs.
- **Fast mode (4.2; opt-in).** The client spawns an **ephemeral
  local indexer** that wraps the SAME chain primitives in an
  isolated subprocess (desktop) or `tokio` task (mobile),
  buffering verified events in a per-run temp DB the host drains
  in batches.

Per D-007: there is no persistent indexer service. The indexer runs
locally; the temp DB is auto-deleted on completion or after idle
timeout.

4.2 shipped the **structural skeleton + the JSON protocol + the
lifecycle hooks**. **4.3 (shipped 2026-05-16) hardens the temp DB**:
real `AeadCipher` impl of `TempDbCipher` using XChaCha20-Poly1305
from `pangolin-crypto::aead` with a per-page random 24-byte nonce;
HKDF-SHA256-derived ephemeral 32-byte key via
`pangolin_chain::derive_indexer_key(device, run_nonce)` wrapped in
`pangolin-crypto::SecretBytes`; two-pass `secure_zero_fill` (random
4-KiB chunks + fsync, then zeros + fsync) called from
`IndexerSession::Drop` BEFORE the `NamedTempFile` unlink. 4.4 ships
the mode-selector heuristic ("when does the host spawn the indexer
vs. just call slow-mode?").

## R-a..R-f resolutions

Locked by Kelvin sign-off 2026-05-16; full text in
[`DECISIONS.md`](../../DECISIONS.md).

- **R-a** — single `pangolin-indexer` crate with `lib.rs` + a
  `[[bin]]` target under `src/bin/pangolin-indexer.rs`. No separate
  client crate.
- **R-b** — stdio JSON protocol. Line-delimited JSON on stdin
  (requests) and stdout (responses). Stderr reserved for `tracing`
  logs.
- **R-c** — `IDLE_TIMEOUT_DEFAULT_SECS = 300`, env override via
  `PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS`, clamp `[60, 3_600]`.
- **R-d** — `TempDbCipher` trait + `NoOpCipher` passthrough stub in
  4.2; **4.3 ships `AeadCipher`** (production XChaCha20-Poly1305
  with per-page random nonce + `SecretBytes`-wrapped ephemeral key)
  + `CipherError::{TagMismatch, FramingTooShort}` typed error
  surface (signature change: `decrypt_page` returns
  `Result<Vec<u8>, CipherError>`). `NoOpCipher` is now behind
  `#[cfg(any(test, feature = "test-utilities"))]` (L10).
- **R-e** — library + binary in 4.2. Cargo features: `default =
  ["bin"]`, `bin = ["dep:clap"]`. Mobile builds use
  `--no-default-features`.
- **R-f** — hermetic + cleanup-on-crash + `#[ignore]`'d live parity
  test.

## Lifecycle state machine

```
+---------+   StartIndex   +---------+   chunk loop   +---------+
| Created | ─────────────▶ | Started | ─────────────▶ | Indexed |
+---------+                +---------+                +---------+
    │                          │                          │
    │ Drop                     │ Heartbeat                │ Pull
    ▼                          │ (resets idle timer)      ▼
[temp DB                       │                       +---------+
 unlinked]                     │                       |  Batch  |
                               │                       +---------+
                               ▼
                          +---------+      Stop       +---------+
                          | Running | ──────────────▶ | Stopped |
                          +---------+                 +---------+
                               │                          │
                               │ idle-timeout              │ Drop
                               ▼                          ▼
                          +---------+              [temp DB unlinked]
                          | IdleExit |
                          +---------+
                               │
                               ▼
                          [temp DB unlinked]
```

The same struct (`IndexerSession`) lives in both flows (R-e + L12).
The desktop binary's `main.rs` is a thin shim that wires argv +
stdio + ctrl_c + idle-timeout; the mobile in-process flow calls
`session.handle_request` directly on a `tokio::spawn`'d task.

## Stdio JSON protocol (R-b)

### Request shapes

```jsonc
{ "type": "start_index", "vault_id": "<64-hex>", "start_block": 0,
  "end_block": null }
{ "type": "pull", "batch_size": 64 }
{ "type": "heartbeat" }
{ "type": "stop" }
```

### Response shapes

```jsonc
{ "type": "started", "protocol_version": 1, "vault_id": "<64-hex>" }
{ "type": "batch", "events": [ /* IndexedEvent[] */ ] }
{ "type": "progress", "fetched_blocks": N, "total_blocks": M,
  "last_block_processed": K }
{ "type": "heartbeat" }
{ "type": "complete", "last_block": N }
{ "type": "stopped" }
{ "type": "error", "message": "..." }
```

### Wire-format rules

- **Hex encoding:** lowercase, no `0x` prefix, for every byte-bag
  field (`vault_id`, `account_id`, `parent_revision`, `device_id`,
  `signer`, `block_hash`, `tx_hash`, `enc_payload`).
- **Request strict parse:** `serde(deny_unknown_fields)`. Unknown
  variant → `IndexerResponse::Error`.
- **Per-line cap:** `MAX_REQUEST_LINE_BYTES = 65_536`. Larger lines
  are rejected before any parse attempt (L-stdio-injection).
- **Protocol version:** `IndexerResponse::Started` carries
  `protocol_version = 1`. Host validates on first response;
  mismatch → host kills indexer (L-host-indexer-mismatch).

## Mobile in-process vs desktop subprocess (R-e + L12)

| Aspect | Desktop subprocess | Mobile in-process |
|---|---|---|
| Process | Separate `pangolin-indexer.exe` | Same Tokio runtime as host |
| Transport | Stdio JSON (BufReader → stdout) | Direct `session.handle_request().await` |
| Lifetime | Until `Stop` / idle / ctrl_c / EOF | Until host drops the session |
| Cleanup-on-crash | `tempfile` Drop + OS temp-dir sweep | `tempfile` Drop on panic-unwind |
| Cargo features | `default = ["bin"]` | `--no-default-features` |

The lifecycle code (`IndexerSession`) is identical for both. The
binary entry is a ~50-line shim; the mobile flow calls the same
`handle_request` directly.

## L invariants (full list in `docs/issue-plans/4.2.md`)

1. **Temp DB never persists past process exit.** `NamedTempFile`'s
   Drop unlinks on normal exit; OS temp-dir GC sweeps on abnormal
   exit. Field-declaration order pins SQLite close before tempfile
   unlink (Windows requires the last handle to close before unlink).
2. **Temp DB contains only the bound `vault_id`'s data.** The
   `topic1 = vault_id` server-side filter, the
   `decoded.vaultId == requested` decode-time check (4.1 inherited),
   and a third compare at insert time give defense-in-depth.
3. **No external service.** Only network call is the chain RPC.
4. **Identical revision-graph output vs 4.1 slow mode.** Both modes
   call `pangolin_chain::fetch_and_verify_chunk`. Verified via the
   `#[ignore]`'d live parity test (`tests/parity.rs`).
5. **Idle timeout fires.** The binary's `tokio::select!` races the
   stdin line against `sleep_until(deadline)`; each request resets
   the deadline. Default 300s; env override clamped `[60, 3_600]`.
6. **No new external crate dep beyond `tempfile`.** Everything else
   is workspace-shared.
7. **No `pangolin-store` import.** CI invariant: `cargo tree -p
   pangolin-indexer --no-default-features --edges normal | grep -c
   pangolin-store == 0`.
8. **`forbid(unsafe_code)`.** Enforced at lib + bin entry.
9. **AGPL SPDX header on every `.rs` file.**
10. **ZERO on-chain broadcast.** Read-only.
11. **Cleanup-on-crash discipline.** `tempfile::NamedTempFile` Drop
    fires on panic-unwind (workspace `panic = unwind`); ctrl_c
    handler in the binary; OS temp-dir GC is the SIGKILL fallback.
12. **Same lifecycle code path in desktop subprocess + mobile
    in-process.** `IndexerSession` is the shared struct.

## Threat-model touch points

4.2 adds the **Ephemeral local indexer** row to
[`THREAT_MODEL.md`](../../THREAT_MODEL.md) with seven per-surface
entries: L-temp-file-leak, L-vault-id-disclosure,
L-stdio-injection, L-idle-timeout-DoS, L-spurious-spawn,
L-host-indexer-mismatch, L-temp-dir-tampering. See the plan-gate
doc + the threat-model row for the full defense statements.

## 4.2 → 4.3 → 4.4 boundary

| Issue | Scope | Status |
|---|---|---|
| 4.2 | Skeleton + stdio JSON + lifecycle + `NoOpCipher` stub. | SHIPPED 2026-05-16 |
| **4.3** | Real `AeadCipher` impl: per-run ephemeral HKDF-derived key, XChaCha20-Poly1305 page encryption, two-pass random+zero overwrite before unlink, `SecretBytes` wrapper. | **SHIPPED 2026-05-16** |
| 4.4 | Mode-selector heuristic. When does the host spawn the indexer vs. just call slow-mode? Plus the host wrapper that translates `IndexerResponse::Batch` → `Vault::ingest_pending_chain_revision`. | Pending |

The architectural-locking property held: 4.3's binary swap was a
~10-line constructor change (`NoOpCipher::new_arc()` →
`AeadCipher::new_arc(SecretBytes::new(fresh_random_key))`), with
the `TempDbCipher` trait surface receiving a single signature
change (`decrypt_page` → `Result<Vec<u8>, CipherError>`) to
propagate AEAD tag-mismatch as a typed error rather than silently
returning corrupt plaintext.

### 4.3 security properties (shipped)

- **`AeadCipher` in `crates/pangolin-indexer/src/cipher.rs`.** Each
  `encrypt_page(plaintext)` returns `nonce ‖ ciphertext_with_tag`
  (24 + plaintext.len() + 16 bytes); `decrypt_page` splits the
  nonce off + opens the AEAD. Per-page random 24-byte nonce
  generated via `pangolin_crypto::rng::fill_random` — the 192-bit
  XChaCha20 nonce makes collision negligible.
- **`derive_indexer_key` in `crates/pangolin-chain/src/evm.rs`.**
  `fn derive_indexer_key(device: &DeviceKey, run_nonce: &[u8; 16])
   -> Result<SecretBytes, ChainError>`. HKDF-SHA256(IKM = device's
  Ed25519 seed; salt = run_nonce; info =
  `"pangolin-indexer-tempdb-key-v1"`). Domain-separated from
  `derive_evm_wallet` (`"pangolin-chain-evm-wallet-v0"`) and from
  the VDK wrap-key (`"pangolin-vdk-wrap-v0"`). Deterministic for
  `(device, run_nonce)` pair; per-run nonce ensures fresh key per
  session.
- **`secure_zero_fill` in `crates/pangolin-indexer/src/session.rs`.**
  Two-pass overwrite: (1) random 4-KiB chunks via `fill_random` +
  fsync; (2) zeros + fsync. Then `NamedTempFile` Drop unlinks.
  Called from `IndexerSession::Drop` with load-bearing ordering —
  the `Connection` is closed FIRST (via `Option::take`) so the
  re-open inside `secure_zero_fill` succeeds on Windows; then
  `NamedTempFile` drops + unlinks. Documented limit: SSD wear-
  leveling may write the overwrite to a different physical block;
  the AEAD encryption + ephemeral-key combination is the primary
  defense.

### 4.3 deferred / non-shipped scope

- Per-column AEAD wrapping into `IndexerSession::persist_chunk` (INSERT)
  and `handle_pull` (SELECT). The cipher is constructed and probed
  end-to-end on every session start, but BLOB columns are still
  inserted/selected as plaintext. The trait surface + key
  derivation + zero-fill are the load-bearing 4.3 deliverables; the
  per-column wrap is additive and lands without a wire-format break.
- AAD binding per page (`vault_id || page_id || schema_version`).
- Raw-disk no-plaintext integration test.

These follow-ups can land in 4.4 or a 4.3.1 fix-pass.
