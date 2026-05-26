<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-E — Native-messaging host (Rust binary, extension ↔ desktop bridge) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-26.** Three architectural decisions resolved (trust model, wire protocol, install scope); remaining defaults self-locked. Decisions captured in §0a.

## 0. One-paragraph summary

Stand up the `apps/native-messaging-host/` Rust binary that bridges the Chromium MV3 extension (MVP-4-C) to the Tauri desktop process (MVP-4-B). Chrome launches the host as a subprocess via the native-messaging protocol when the extension calls `chrome.runtime.connectNative`; the host reads framed JSON-RPC 2.0 messages on stdin, relays them to the running desktop via a per-user OS-local IPC channel, and writes responses back on stdout. Trust model: per-install secret token in the OS keychain plus Chrome's manifest-pinned extension-ID gate (two locks). Install scope: per-user manifests for Chrome / Chromium / Brave / Edge. First-run wizard in the desktop registers the manifest paths + generates the token; uninstall reverses cleanly.

## 0a. RESOLVED decisions

**Kelvin-approved (2026-05-26):**

- **Trust model = per-install handshake token + extension-ID gate (the strongest option).** At install time the desktop generates a random 32-byte token via `pangolin_crypto::rng::fill_random`, stores it in the OS keychain via the `keyring` crate (Windows Credential Manager / macOS Keychain Services / Linux libsecret-via-secret-service), and writes a sibling token file under `~/.local/share/pangolin/native-host-token` (mode 0600) for the host binary to read at startup. First message from the extension MUST include the token; the host verifies (constant-time) before opening the IPC channel to the desktop. Chrome's manifest-pinned `allowed_origins: ["chrome-extension://<id>/"]` check fires upstream and is the OUTER lock; the handshake is the INNER lock.
- **Wire protocol = JSON-RPC 2.0** over the native-messaging frame (4-byte little-endian length + UTF-8 JSON body, per Chrome's protocol). Industry-standard envelope; debuggable with any JSON-RPC inspector. Methods are dotted (e.g. `vault.list_accounts`, `vault.account_show`, `session.status`); errors use JSON-RPC's `{code, message, data}` shape mapped from the desktop's `DesktopError` taxonomy.
- **Install scope = per-user, all Chromium-family browsers.** Manifest installed at per-user paths for Chrome AND Chromium AND Brave AND Edge. No admin/sudo at install. Per-OS path resolution + the actual write happens in the desktop's first-run wizard (next sub-issue's polish; this slice ships a CLI subcommand `pangolin-desktop install-native-host` that the wizard will eventually call).

**Self-locked:**

- **Native host = Rust binary, no Tauri / no GUI.** Tiny crate (`apps/native-messaging-host/`, ~600–900 LoC). Deps: `tokio` (async stdio + IPC), `serde_json` (workspace), `pangolin_crypto` (constant-time token compare via `subtle::ConstantTimeEq`), `keyring` (=3.x; cross-platform keystore), `interprocess` (=2.x; cross-platform named-pipe / Unix-domain-socket).
- **IPC channel between native host ↔ desktop**: per-user named pipe on Windows (`\\.\pipe\studio.kelvinsinferno.pangolin\<user-sid-hash>`), Unix-domain-socket on Linux + macOS (`$XDG_RUNTIME_DIR/pangolin/native-host.sock` on Linux, `~/Library/Application Support/Pangolin/native-host.sock` on macOS). Mode 0600. The pipe/socket carries the SAME JSON-RPC 2.0 envelope that the native-messaging frame carries (no re-encoding; the host is a transparent relay once auth fires).
- **Desktop IPC server**: NEW Rust module `apps/desktop/src/ipc/` runs alongside the Tauri main loop on a background `tokio::spawn`; accepts only one connection at a time (single-host pattern); listens on the same per-user pipe/socket path the native host expects.
- **Token rotation**: on uninstall, both the keychain entry and the sibling token file are zeroed. On a token-mismatch handshake failure, the host emits a `auth_failed` JSON-RPC error + exits 1; Chrome shows the extension's connection error in the popup. No retry loop.
- **Methods this slice ships** (minimum runnable surface; matches MVP-4-B's first surface):
  - `session.status` → `{ vault_open: bool, vault_unlocked: bool }` (no account data; cheap heartbeat for the popup's connection indicator).
  - `vault.list_accounts` → `[FfiAccountSummary]` (only when unlocked; `auth.session_locked` error otherwise).
  - `vault.account_show(id)` → `FfiAccountSummary` (full account metadata; no password).
  - `vault.copy_password(id)` → `null` (Rust-side; password NEVER crosses to the extension — same H-1 discipline as MVP-4-B).
  - **Deliberately deferred:** `vault.reveal_password` (extension never holds plaintext); autofill / form-detection methods (MVP-4-G); the other 12 methods in Browser-Ext spec §5–§16.
- **CSP impact on the extension**: the extension's `manifest.json` already allows `nativeMessaging` permission (MVP-4-C added it). No further extension changes this slice — the popup keeps showing "Desktop not connected" until MVP-4-G wires the actual UI to `chrome.runtime.connectNative`.
- **AGPL SPDX + `forbid(unsafe_code)`** on every new Rust file.
- **`publish = false`** on the new crate.

## 0b. What NOT to ship in this slice

- The MV3 popup UI changes to actually connect via the host (deferred to MVP-4-G, alongside autofill).
- Autofill / form-detection / origin-binding methods (MVP-4-G; the 16 message types in Browser-Ext spec §5–§16 minus the 4 listed above).
- Firefox + Safari extension support (MVP-4 back-half if time allows; otherwise MVP-4.5).
- Auto-update of the native-messaging host binary (post-MVP-4).
- Code signing of the host binary (release-time work).
- Per-OS installer packaging (MSI / DMG / deb / rpm) (release-time work).
- Telemetry / metrics from the host (out of scope).

## 1. Scope

**Built in MVP-4-E:**

- `apps/native-messaging-host/` (NEW crate) — `publish = false`; binary name `pangolin-native-messaging-host`. Deps: `tokio = { workspace = true }`, `serde_json = { workspace = true }`, `keyring = "=3.x"`, `interprocess = "=2.x"`, `pangolin-crypto = { path = "../../crates/pangolin-crypto" }` (for `subtle::ConstantTimeEq` + `Zeroizing`), `zeroize = { workspace = true }`.
- `apps/native-messaging-host/src/main.rs` — entry; reads framed JSON-RPC from stdin, performs auth handshake, opens IPC to desktop, relays bidirectionally.
- `apps/native-messaging-host/src/frame.rs` — Chrome's 4-byte-LE-length native-messaging frame codec. Round-trip tests pin the byte form.
- `apps/native-messaging-host/src/auth.rs` — handshake token load (keychain primary; sibling file fallback) + constant-time verify.
- `apps/native-messaging-host/src/ipc.rs` — connect-to-desktop on the per-user pipe/socket; relay JSON-RPC bytes.
- `apps/native-messaging-host/src/error.rs` — typed `HostError` enum mapping to JSON-RPC error codes.
- `apps/desktop/src/ipc/mod.rs` (NEW module on the desktop side) — accept-one-connection IPC server, parses JSON-RPC requests, dispatches to the desktop's existing command handlers (which already exist in `apps/desktop/src/commands/`), serializes responses.
- `apps/desktop/src/ipc/dispatch.rs` — maps JSON-RPC `method` strings to the four shipped commands.
- `apps/desktop/src/commands/install_native_host.rs` (NEW Tauri command + CLI subcommand) — generates the handshake token, stores in keychain + sibling file, writes the native-messaging manifest at the per-user paths for Chrome/Chromium/Brave/Edge across Win/macOS/Linux.
- `apps/desktop/src/main.rs` — start the IPC server background task during `tauri::Builder` setup.
- New CI job `native-messaging-host` in `.github/workflows/ci.yml` — Rust-side build + unit tests + manifest-write integration test against a temp HOME.
- The `desktop` job already exists; this slice adds an `install_native_host` smoke step that calls the CLI subcommand with a temp HOME + asserts the manifest landed at the right per-OS path.
- Hermetic tests: frame round-trip (byte-identical), token verification (correct + wrong tokens), IPC connect + JSON-RPC dispatch + error mapping, per-OS manifest path resolution, install-and-uninstall round-trip (temp HOME).

**Deferred (NOT this slice):** per §0b.

## 2. Splittable? — ONE slice

The host binary + the desktop's IPC server + the install-paths code all need to land together for any end-to-end test to pass. Splitting forces a half-bridged extension between PRs. ONE slice → focused audit (the auth-token discipline + the IPC perimeter + the manifest-install paths + the JSON-RPC error mapping) → merge.

## 3. Design

### 3.1 Architecture

```text
┌─────────────────┐  4-byte-LE-len + JSON-RPC 2.0  ┌──────────────────┐
│ Chromium MV3    │  ◀──── stdin / stdout ────▶   │  native-messaging │
│ popup (MV-4-C)  │       (Chrome spawns + kills)  │  host binary      │
│                 │                                │  (this slice)     │
└─────────────────┘                                └────────┬─────────┘
                                                            │
                              per-user named pipe (Win)     │
                              Unix-domain-socket (Unix)     │
                              mode 0600, JSON-RPC 2.0       │
                                                            ▼
                                                  ┌──────────────────┐
                                                  │  Tauri desktop   │
                                                  │  IPC server task │
                                                  │  (this slice)    │
                                                  │                  │
                                                  │  ↓               │
                                                  │  pangolin-ffi    │
                                                  └──────────────────┘
```

Lifecycle:
1. User starts the desktop app. First run: install-wizard registers the native-messaging manifest at per-user Chrome/Chromium/Brave/Edge paths + generates the handshake token + stores in OS keychain. The desktop's IPC server begins listening on the per-user pipe/socket.
2. User opens the browser, opens the Pangolin extension popup. Popup calls `chrome.runtime.connectNative('studio.kelvinsinferno.pangolin.host')`. Chrome spawns the native host binary as a subprocess.
3. Native host's first frame from the extension: `{"method": "auth.handshake", "params": {"token": "<base64 32-byte token>"}, ...}`. Host loads the expected token from keychain (or sibling file fallback), constant-time-compares. Mismatch → emits `auth_failed` JSON-RPC error + exits 1.
4. On success, host opens the IPC channel to the desktop. From here forward the host is a transparent JSON-RPC relay: extension's stdin → IPC; IPC response → extension's stdout. Errors map per `error.rs`.
5. User closes the popup. Chrome kills the host subprocess (SIGTERM on Unix, TerminateProcess on Windows). Host's drop handler closes the IPC channel cleanly. Desktop's IPC server returns to accepting state.

### 3.2 Wire shapes

**Native-messaging frame** (Chrome's protocol; non-negotiable):
```text
[u32 LE length] [UTF-8 JSON body of `length` bytes]
```

**Handshake** (first frame extension → host):
```jsonc
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "auth.handshake",
  "params": { "token": "<base64url, no-padding, 32 bytes>" }
}
```

**Success response**:
```jsonc
{ "jsonrpc": "2.0", "id": 1, "result": { "host_version": "0.0.0", "protocol_version": 1 } }
```

**Auth failure**:
```jsonc
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32001, "message": "auth_failed" } }
```

**Subsequent calls** are relayed transparently; the host adds a `_relay_id` envelope ONLY in its IPC channel to the desktop (so request/response can be paired in a multi-message session). Removed before writing back to stdout.

### 3.3 Per-OS manifest paths (per-user)

| OS | Browser | Path |
|---|---|---|
| Linux | Chrome | `~/.config/google-chrome/NativeMessagingHosts/studio.kelvinsinferno.pangolin.host.json` |
| Linux | Chromium | `~/.config/chromium/NativeMessagingHosts/...` |
| Linux | Brave | `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/...` |
| Linux | Edge | `~/.config/microsoft-edge/NativeMessagingHosts/...` |
| macOS | Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/...` |
| macOS | Chromium | `~/Library/Application Support/Chromium/NativeMessagingHosts/...` |
| macOS | Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/...` |
| macOS | Edge | `~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/...` |
| Windows | All Chromium | Registry: `HKCU\Software\<Vendor>\<Product>\NativeMessagingHosts\studio.kelvinsinferno.pangolin.host` → `(default)` = manifest JSON path under `%APPDATA%\Pangolin\native-host\manifest.json` |

Vendor / product paths per Chrome's docs: <https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location>.

### 3.4 Token storage

Primary store: OS keychain via the `keyring` crate.
- Service name: `studio.kelvinsinferno.pangolin`
- Account name: `native-messaging-host-token`
- Value: 32 random bytes, base64url-encoded.

Sibling file fallback: `~/.local/share/pangolin/native-host-token` (Linux), `~/Library/Application Support/Pangolin/native-host-token` (macOS), `%APPDATA%\Pangolin\native-host-token` (Windows). Mode 0600 on Unix; user-only ACL on Windows. ONLY used by the native host binary at startup (because the keychain crate's per-OS dependencies may not be available in a Chrome-spawned process context on some Linux distros without an unlocked keyring at session start; the file is the fallback).

Token rotation on uninstall (`pangolin-desktop uninstall-native-host`): keychain entry deleted + file overwritten with zeros + unlinked.

## 4. L-invariants

- **L1 zero-secret-crosses.** The handshake token is the ONLY secret in the host's process. The vault VDK / passwords / signing keys stay in the desktop process; the IPC channel only carries metadata + non-secret-class JSON-RPC params + `copy_password(id)` calls (which route the plaintext entirely Rust-side via the Tauri command; the host relays only `id` strings + result-OK signals).
- **L2 no new atomic surface.** The host wraps existing desktop commands (vault.list_accounts → accounts_list; vault.account_show → account_show; vault.copy_password → copy_password_to_clipboard). No new state-machine work.
- **L3 fail-closed.** Bad token, bad frame, malformed JSON-RPC, unknown method, IPC disconnect — all fail-closed with typed JSON-RPC errors. Never proceed with partial state.
- **L4 session-gating** is enforced inside the desktop's existing command handlers; the host doesn't re-check.
- **L5** new external deps: `keyring = "=3.x"`, `interprocess = "=2.x"`. Both widely-used (1Password's Linux app uses keyring, VSCode uses interprocess-equivalent). `cargo deny check` MUST pass after adding them; expect zero new advisories (verify before push).
- **L6 testnet-only / D-011.** This slice does not touch chain code.
- **L7 errors carry no secret.** `HostError` -> JSON-RPC `{code, message, data}`; `data` never embeds the token or VDK material.
- **L8 tests:** frame round-trip, token verify (correct + wrong + empty + too-short + wrong-base64), IPC connect/disconnect, JSON-RPC dispatch (each of the 4 methods + an unknown method), per-OS path resolution, install + uninstall round-trip (temp HOME). At least one end-to-end test that drives the full path (host stdin → IPC → desktop's accounts_list → response on host stdout).
- **L9 §16 ledger** — DECISIONS / DEVLOG on merge.

## 5. Open decisions — pre-locked (two carve-outs for the builder)

- **Q-a (keyring crate version): builder's call** between `keyring = "=3.6.x"` (latest stable; works on all 3 OSes) and a slightly older `=3.5.x` if 3.6 hits a Linux secret-service issue. Either is fine. Pin to whatever has zero RUSTSEC advisories at build time; report which.
- **Q-b (interprocess vs hand-rolled platform code): builder's call.** `interprocess = "=2.x"` is the standard cross-platform abstraction (used by tower / lapin / dozens of other crates). The hand-rolled alternative (`tokio::net::UnixListener` on Unix + `tokio::net::NamedPipeServer` on Windows) is one less dep but ~3x the per-OS code. Default to `interprocess` unless the builder sees a security-class concern.

All other decisions are locked per §0a.

## 6. Places that need care

- **Constant-time token compare** is mandatory. The builder MUST use `subtle::ConstantTimeEq::ct_eq` for the handshake check; a regular `==` is a timing oracle. There is no fallback or `if .. == ..` allowed on the token bytes.
- **`Drop` for the host process must zero the token + close IPC channel.** Token loaded into a `Zeroizing<Vec<u8>>` from the keystore; never copied into a plain `String` / `Vec<u8>`.
- **Chrome spawns the host as a subprocess every time the extension connects.** The host has NO long-running state. All state lives in the desktop. The token-storage path must be readable in the Chrome-spawned process environment (which may have a minimal $HOME / no keyring agent on some Linux setups). The sibling-file fallback is the safety net.
- **The IPC pipe/socket path is per-user.** On a shared-machine threat model (multi-user system), each user gets their own desktop + their own pipe. The host's IPC connect MUST validate the pipe's owner = current EUID before sending the first byte. On Windows, the named pipe ACL must be `S-1-3-4` (current user) only.
- **Manifest paths differ subtly across Chromium derivatives.** Brave's NativeMessagingHosts directory is NESTED under `BraveSoftware/Brave-Browser/`, not `Brave/`. Edge has its own path. The install code must enumerate all of them + write each + report which succeeded.
- **`forbid(unsafe_code)`** on every new Rust file. `keyring` + `interprocess` both internally use unsafe, but that's pre-audited; the wrapper crate boundary IS the safety perimeter.
- **JSON-RPC `id` correlation**: each request from the extension has an `id`; responses must echo it. The host MUST NOT generate its own ids or drop client ids. The IPC relay preserves them.

## 7. Success criteria

- `cargo build -p pangolin-native-messaging-host` clean on Linux + macOS + Windows.
- `cargo test --workspace --exclude pangolin-desktop -- --skip vault_create_password_stdin_path_works --skip vault_create_rejects_empty_password_via_stdin` ✓ (pangolin-desktop continues to be excluded from workspace builds due to Tauri Linux deps; pangolin-native-messaging-host is included).
- `cargo audit --deny warnings <existing --ignore set>` ✓ (no new advisories from keyring + interprocess).
- `cargo deny check advisories bans licenses sources` ✓.
- New CI job `native-messaging-host` green on `ubuntu-latest`.
- `desktop` job's new `install_native_host` smoke step green.
- Cardinal invariants still 0.
- Manual end-to-end (documented in README): start desktop → install-native-host wizard → open Chrome → load unpacked extension → popup connects → calls `session.status` → response visible. Repeat with Brave; verify the manifest landed in Brave's path.

## 8. Out of scope (filed for follow-up)

- All §0b items.
- Multi-host arbitration (if two desktop processes are running for the same user, which one wins). Single-host single-user is the assumption.
- Auto-reconnect on desktop restart (the popup currently shows "Desktop not connected" on a closed connection; the user-driven reopen-popup retry is enough).
- A formal threat model for the trust boundary (defer to D-011 audit).
- Localized install-error messages (English-only).
- Firefox WebExtensions native-messaging — same protocol as Chrome but different manifest path; MVP-4-back-half if Firefox lands as a target.
