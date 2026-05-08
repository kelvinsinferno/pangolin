# Pangolin FFI surface (frozen at MVP-1 issue 1.1)

> **Status:** Frozen 2026-05-08 by MVP-1 issue 1.1 (`docs/issue-plans/1.1.md`).
> Bodies of the listed entry points land issue-by-issue (1.2 → 1.11);
> *signatures* are locked. After-MVP-1 changes are additive only —
> never field/variant removals, never argument-type changes.

## Scope

This document is the canonical reference for what crosses the FFI
boundary between the Pangolin Rust core and every consumer shell:

- **Tauri (desktop, MVP-4):** consumes `pangolin.h` via cbindgen.
- **iOS (MVP-5):** consumes `pangolin.swift` via UniFFI.
- **Android (MVP-5):** consumes `pangolin.kt` via UniFFI.
- **Browser-extension native messaging host (MVP-4 issue 7.2.2):**
  consumes `pangolin.h` via cbindgen.

Implementations live in
[`crates/pangolin-ffi/`](../../crates/pangolin-ffi). Per Q3 of the
issue 1.1 plan-gate, every type and entry point named here lives in
that crate (NOT in `pangolin-core`).

## Generation pipeline

| Output | Generator | Command |
|---|---|---|
| `target/ffi-bindings/c/pangolin.h` | cbindgen 0.29.x | `cargo run -p pangolin-ffi --bin cbindgen-build --features cbindgen-cli` |
| `target/ffi-bindings/swift/pangolin_ffi.swift` | uniffi-bindgen 0.31.x | `cargo run -p pangolin-ffi --bin uniffi-bindgen --features uniffi-cli -- generate --library target/debug/libpangolin_ffi.<so\|dylib\|dll> --language swift --out-dir target/ffi-bindings/swift --no-format` |
| `target/ffi-bindings/kotlin/uniffi/pangolin_ffi/pangolin_ffi.kt` | uniffi-bindgen 0.31.x | `... --language kotlin --out-dir target/ffi-bindings/kotlin --no-format` |
| `target/debug/libpangolin_ffi.{so,dylib,a}` / `pangolin_ffi.{dll,lib}` | cargo | `cargo build -p pangolin-ffi` |

CI runs the full pipeline on Linux + macOS + Windows under the
`ffi-bindings` job in `.github/workflows/ci.yml`.

## Locked entry points

Every signature below is frozen. Bodies land in the issues listed in
the right-most column.

### Vault lifecycle

| Function | Lands in |
|---|---|
| `vault_create(path: &str, password: &SecretPassword) -> Result<(), FfiError>` | 1.3 |
| `vault_open(path: &str) -> Result<VaultHandle, FfiError>` | 1.3 |
| `vault_unlock(h: &VaultHandle, p: &SecretPassword, presence: PresenceProof) -> Result<SessionInfo, FfiError>` | 1.4 |
| `vault_lock(h: &VaultHandle) -> Result<(), FfiError>` | 1.4 |
| `vault_close(h: VaultHandle) -> Result<(), FfiError>` | 1.4 |

### Identity

| Function | Lands in |
|---|---|
| `account_add(h: &VaultHandle, draft: AccountDraft) -> Result<AccountId, FfiError>` | 1.2 |
| `account_update(h: &VaultHandle, id: AccountId, patch: AccountPatch) -> Result<RevisionId, FfiError>` | 1.2 |
| `account_search(h: &VaultHandle, query: &str) -> Result<Vec<AccountSnapshot>, FfiError>` | 1.2 |
| `account_get(h: &VaultHandle, id: AccountId) -> Result<AccountSnapshot, FfiError>` | 1.2 |
| `account_history(h: &VaultHandle, id: AccountId) -> Result<Vec<RevisionMeta>, FfiError>` | 1.2 |

### Session

| Function | Lands in |
|---|---|
| `session_status(h: &VaultHandle) -> SessionInfo` | 1.4 |
| `session_extend(h: &VaultHandle) -> Result<SessionInfo, FfiError>` | 1.4 |

### TOTP

| Function | Backed by | Lands in |
|---|---|---|
| `totp_generate(h: &VaultHandle, id: AccountId, at: UnixTimestamp) -> Result<TotpCode, FfiError>` | `pangolin-totp` | 1.7 |

### Password generator

| Function | Lands in |
|---|---|
| `password_generate(policy: PasswordPolicy) -> SecretPassword` | 1.8 |

### KDBX import

| Function | Backed by | Lands in |
|---|---|---|
| `kdbx_import(h: &VaultHandle, path: &str, kdbx_password: &SecretPassword) -> Result<KdbxImportReport, FfiError>` | `pangolin-kdbx` | 1.9 |

### Encrypted export

| Function | Lands in |
|---|---|
| `vault_export_encrypted(h: &VaultHandle, dest: &str) -> Result<(), FfiError>` | 1.10 |
| `vault_export_plaintext(h: &VaultHandle, dest: &str, second_confirmation: PlaintextExportConfirmation) -> Result<(), FfiError>` | 1.10 |

### Capture authority

| Function | Lands in |
|---|---|
| `capture_authority_register(h: &VaultHandle, authority: CaptureAuthority, context: CaptureContext) -> Result<(), FfiError>` | 1.11 |

## Records and enums that cross the boundary

| Type | UniFFI shape | Carries user data | Schema-version slot |
|---|---|---|---|
| `SecretPassword` | Object (`Arc<Self>`) | Yes (password bytes) | n/a (opaque) |
| `PresenceProof` | Record | Yes (proof bytes) | `schema_version: u16` |
| `SessionInfo` | Record | No | `schema_version: u16` |
| `VaultHandle` | Object (`Arc<Self>`) | Indirect (holds vault state) | n/a (opaque) |
| `AccountId` | Record | No | `schema_version: u16` |
| `AccountDraft` | Record | Yes (full account at create) | `schema_version: u16` |
| `AccountPatch` | Record | Yes (partial update) | `schema_version: u16` |
| `AccountSnapshot` | Record | Yes (read-back account) | `schema_version: u16` |
| `RevisionId` | Record | No | `schema_version: u16` |
| `RevisionMeta` | Record | No | `schema_version: u16` |
| `TotpCode` | Record | Yes (decimal code + window) | `schema_version: u16` |
| `UnixTimestamp` | type alias for `i64` | No | n/a |
| `PasswordPolicy` | Record | No (policy flags) | `schema_version: u16` |
| `KdbxImportReport` | Record | No (counts + category labels) | `schema_version: u16` |
| `PlaintextExportConfirmation` | Record | Yes (confirmation token) | `schema_version: u16` |
| `CaptureAuthority` | Record | No | `schema_version: u16` |
| `CaptureContext` | Record | No | `schema_version: u16` |

Schema-version policy text is locked in MVP-1 issue 1.6 (master plan
§18.7). Issue 1.1 commits to the *slot* — every record listed above
that holds user data exposes a `schema_version: u16` field; 1.6 will
finalise read-only-old / reject-future / migration semantics.

## `FfiError` — the §18.8 taxonomy

```rust
#[derive(uniffi::Error)]
pub enum FfiError {
    Crypto      { message: String },
    Store       { message: String },
    Session     { message: String },
    Sync        { message: String },
    Chain       { message: String },
    Recovery    { message: String },
    Validation  { kind: String, message: String },
    Internal    { message: String },
}
```

### Mapping discipline

- `pangolin_core::Error → FfiError` is **total** (every variant maps).
  Verified by `crates/pangolin-ffi/tests/error_taxonomy.rs`.
- **`Internal` is reserved** for genuine "this should never happen"
  paths. The exhaustive-match test asserts no `pangolin_core::Error`
  variant maps to `Internal`.
- **Authentication-class collapse.** Wrong password, tampered
  ciphertext, KDF parameter tamper, presence-proof replay all map to
  `FfiError::Validation { kind: "authentication", message: "authentication failed" }`.
  Per Design Spec §15 / threat model row #7, the FFI surface MUST NOT
  become a distinguishing oracle.

### `message()` discipline

`FfiError::message()` is the only string a UI ever shows. Per Design
Spec §15:

- It is a UI-safe string (no plaintext).
- It is a non-secret category label, not a structured error.
- The `Debug` derive on `FfiError` is also UI-safe by construction —
  every variant carries only category-label `String`s, never raw
  bytes from the operation that failed.

## Types that DO NOT cross the boundary

For traceability and audit clarity, types in the workspace that are
deliberately NOT crossing FFI:

- **`pangolin_crypto::*`.** Raw keys, AEAD nonces, ed25519 secret
  bytes, `BoxedSecret`, `SecretBytes`, `WrappedVdk`, `AeadKey`,
  `SigningKey`, `AuthorityKey`, `DeviceKey`, `VdkKey`. All stay
  internal; the FFI surface deals in opaque `SecretPassword` /
  `PresenceProof` envelopes only.
- **The SQLite connection handle** (`rusqlite::Connection`) — never
  surfaces; all queries go through `pangolin_store::Vault`'s typed
  accessor methods.
- **`pangolin_store::RevisionGraph`** — internal data structure; only
  `RevisionMeta` summaries cross.
- **All `pangolin_chain::*` types.** Dormant for MVP-1; the chain
  adapter is not on the FFI surface even when 2.x activates it (the
  FFI layer calls `pangolin-chain` indirectly via sync orchestration
  in `pangolin-core`).
- **The C-ABI internal `PangolinVaultHandle`** struct in
  `crates/pangolin-ffi/src/cabi.rs` — exposed at the C ABI but the
  *contained* `VaultHandle` is opaque (`*const VaultHandle`).

## Drift discipline

`crates/pangolin-ffi/tests/roundtrip.rs` walks every locked-in-1.1
record / object and asserts it can be constructed and round-tripped
through the UniFFI scaffolding. As 1.2-1.11 land bodies, the round-
trip test gains real-call assertions (today the function bodies are
`todo!()`).

The C-ABI surface (`crates/pangolin-ffi/src/cabi.rs`) is intentionally
narrower than the UniFFI surface — Tauri / native-messaging-host
shells call only the subset that needs C-ABI (today: `vault_open` +
`vault_close`). When 1.3 / 1.4 widen the C-ABI subset, every `extern
"C"` function listed in `cabi.rs` must mirror a UniFFI export, OR be
explicitly marked "C-only" with a reason.

## References

- Master plan §16.8 — Repository layout (amended for issue 1.1).
- Master plan §17 — Component matrix (FFI surface, frozen at MVP-1).
- Master plan §18.7 — Schema-versioning policy (locked in 1.6).
- Master plan §18.8 — Error / Result type taxonomy.
- Whitepaper §B — single Rust core engine; thin shells.
- Design Spec §15 — UI-safe error rendering.
- `THREAT_MODEL.md` row #7 — indistinguishability discipline.
- `docs/issue-plans/1.1.md` — issue plan + locked decisions Q1-Q5.
