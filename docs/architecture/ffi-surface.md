# Pangolin FFI surface (frozen at MVP-1 issue 1.1)

> **Status:** Frozen 2026-05-08 by MVP-1 issue 1.1 (`docs/issue-plans/1.1.md`).
> Amended 2026-05-08 by MVP-1 issue 1.2 per Q1 of
> `docs/issue-plans/1.2.md` to widen `AccountDraft` /
> `AccountPatch` / `AccountSnapshot` to the production multi-username,
> multi-URL, tags, password-history, TOTP shape Whitepaper §6 mandates.
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
| `account_search(h: &VaultHandle, query: &str) -> Result<Vec<AccountSnapshot>, FfiError>` | 1.2 (impl 1.3) |
| `account_get(h: &VaultHandle, id: AccountId) -> Result<AccountSnapshot, FfiError>` | 1.2 |
| `account_history(h: &VaultHandle, id: AccountId) -> Result<Vec<RevisionMeta>, FfiError>` | 1.2 |

**`account_search` behaviour (MVP-1 issue 1.3).** The signature is
frozen at 1.1; 1.3 supplies the production body. Search is backed by an
in-RAM (`:memory:`) SQLite FTS5 index over the *non-secret* searchable
projection of every live account — `display_name`, the canonical
`tags`, and the `url::Url::host_str()`-derived hostname of each URL,
and **never** `usernames` / full URLs / `notes` / passwords / TOTP
secrets (the whitelist is structural — the FTS5 schema has no columns
for those). Tokenizer = `trigram` (true arbitrary-substring match —
`"ithu"` finds `"github.com"`); results are `bm25()`-ranked with a
most-recently-modified recency tiebreaker; multi-term queries are
default-AND (`"git main"` ⇒ both); the result list is capped at 200
(`pangolin_store::ACCOUNT_SEARCH_RESULT_CAP`). An empty / whitespace
query returns every live account, recency-ordered, same cap. Queries
shorter than 3 characters fall back to a substring scan over the same
projection columns. Tombstoned accounts never appear; frozen accounts
are filtered out. The index is rebuilt from the decrypted blobs on
every `vault_unlock` (so V0-format and 1.2-V1-format vaults alike get a
working index) and torn down on `vault_lock` / `vault_close` — nothing
extra is written to disk. See `docs/architecture/search.md` for the
full design. `FfiError::NotUnlocked` if the vault is locked.

### Session

| Function | Lands in |
|---|---|
| `session_status(h: &VaultHandle) -> SessionInfo` | 1.4 (bodies live; `SessionInfo` widened — see the 1.4 amendment) |
| `session_extend(h: &VaultHandle, presence: PresenceProof) -> Result<SessionInfo, FfiError>` | 1.4 (**signature amended** — added the `presence` arg; §5.4 "extend long sessions" is high-risk) |

### Reveal (presence-gated — MVP-1 issue 1.4 amendment)

| Function | Lands in |
|---|---|
| `reveal_current_password(h: &VaultHandle, id: AccountId, presence: PresenceProof) -> Result<RevealedSecret, FfiError>` | 1.4 (**new** entry point) |
| `reveal_password_history(h: &VaultHandle, id: AccountId, presence: PresenceProof) -> Result<Vec<PasswordHistoryEntry>, FfiError>` | 1.4 (**new** entry point) |
| `reveal_notes(h: &VaultHandle, id: AccountId, presence: PresenceProof) -> Result<RevealedSecret, FfiError>` | 1.4 (**new** entry point) |
| `reveal_totp_secret(h: &VaultHandle, id: AccountId, presence: PresenceProof) -> Result<RevealedSecret, FfiError>` | 1.4 (**new** entry point) |

**Reveal-class behaviour (MVP-1 issue 1.4 — Session spec §5.4).** Each
`reveal_*` requires an active session **plus** a presence proof that is
*fresh now* — meaning within the 60 s `PRESENCE_FRESHNESS` window of the
last successful presence (which includes the `vault_unlock`'s presence
proof). Within that window no re-prompt is needed (prompt deduplication,
§8.6 — two reveals moments apart use one proof). Outside it, the
supplied proof must verify; a *stale* proof (the prompt aged past
`PROMPT_TIMEOUT` ≈ 60 s before the user answered) surfaces
`FfiError::Session` (the `PromptTimedOut` cause — §7.7, loud and typed,
never silent per §8.2), while any other proof failure collapses to
`FfiError::Validation { kind: "authentication" }`. A locked vault →
`NotUnlocked`, an expired session → `SessionExpired`, a frozen account →
`AccountFrozenPendingResolve` — all surfaced *before* the proof is
consumed, so the caller can re-auth and retry. The CLI tier maps the
1.1-frozen `PresenceProof` `{schema_version, bytes}` record to a fresh
`PressYPresenceProof::confirmed()` (the `bytes` field is the slot
MVP-3/4 hardware-backed presence proofs fill). Returned secret bytes
zero on drop (`RevealedSecret` — a `byte_length()`-only Object, same
discipline as `SecretPassword`).

### Device identity + trust list (MVP-1 issue 1.5 amendment)

| Function | Lands in |
|---|---|
| `device_list(h: &VaultHandle) -> Result<Vec<DeviceInfo>, FfiError>` | 1.5 (**new** entry point) |
| `device_current(h: &VaultHandle) -> Result<DeviceInfo, FfiError>` | 1.5 (**new** entry point) |
| `device_set_label(h: &VaultHandle, id: DeviceId, label: String) -> Result<(), FfiError>` | 1.5 (**new** entry point) |

**Device behaviour (MVP-1 issue 1.5 — Whitepaper §F).** The trust list
is the engine's `devices` table — one row per device that has ever
opened+unlocked this `.pvf`. The row is created **on first unlock**
(register-on-unlock: the engine generates an Ed25519 `DeviceKey`, derives
the `device_id` from its verifying-key bytes, persists the `devices` row
and the AEAD-sealed device-key seed). It is **add-only** in MVP-1 — no
revoke/remove path (device revocation needs authority rotation, which is
MVP-3); the `revoked_at` column is the MVP-2/3 hook. It gates nothing
destructive — it is the local record + the MVP-2 on-chain-authority-
registry hook; `originating_device` on every post-1.5 revision is the
open handle's real `device_id` (pre-1.5 revisions keep their throwaway-
random value, accepted as-is). `device_list` / `device_current` work on a
*locked* vault that has been unlocked at least once (the row is
persisted); on a brand-new vault opened-but-never-unlocked there is no
device row yet → `FfiError::Session`. `device_set_label` requires an
**active (unlocked, non-expired) session only** — NOT a fresh presence
proof (a label rename is not a Session spec §5.4 reveal-class action) —
and validates the label (non-empty, ≤ 256 chars, NFC-normalised). The
`DeviceKey` is generated + stored encrypted but **signs nothing in
MVP-1** — it is the hook for MVP-2's signed-revision format / gas-payer
role; `last_sync_at` is a **dormant column** (always `None` in MVP-1;
MVP-2's chain sync fills it). These are an **additive 1.1-surface
amendment** — the 1.1 freeze declared the `DeviceId` record but no
`Device` / `DeviceInfo` shape and no `device_*` entries; nothing external
binds the 1.1 surface yet (same posture as 1.2's `AccountDraft` widening
and 1.4's `reveal_*` entries). The C-ABI mirror in `cabi.rs` is not yet
extended for these (the cbindgen surface remains intentionally tiny —
`device_*` are `UniFFI`-only for now, same as `account_*` / `reveal_*`).

### Revision lineage + fork resolution (MVP-1 issue 1.6 amendment)

| Function | Lands in |
|---|---|
| `account_is_forked(h: &VaultHandle, id: AccountId) -> Result<bool, FfiError>` | 1.6 (**new** entry point) |
| `account_fork_branches(h: &VaultHandle, id: AccountId) -> Result<Vec<ForkBranch>, FfiError>` | 1.6 (**new** entry point) |
| `account_resolve_fork(h: &VaultHandle, id: AccountId, keep_revision_id: RevisionId) -> Result<RevisionId, FfiError>` | 1.6 (**new** entry point) |
| `account_status(h: &VaultHandle, id: AccountId) -> Result<AccountStatus, FfiError>` | 1.6 (**new** entry point) |
| `account_history(h: &VaultHandle, id: AccountId) -> Result<Vec<RevisionMeta>, FfiError>` | 1.6 finalises `RevisionMeta` (was scaffolded in 1.1) — see below |

**Revision-lineage behaviour (MVP-1 issue 1.6 — Whitepaper §7 / §G3,
master plan §17 / §18.7).** `RevisionMeta` is finalised: it now carries
`is_tombstone`, `is_head` (a current leaf of the graph), `is_canonical_head`
(THE canonical head per the clock-free rule: the leaf with the
lexicographically-largest `revision_id` — no `created_at` involvement),
and `on_canonical_chain` (an ancestor of the canonical head). `ForkBranch`
= `{ schema_version, leaf_revision_id, leaf_device_id, leaf_created_at,
depth, is_canonical_head }` — enough metadata for the user to choose
which branch to keep. `AccountStatus` = `{ schema_version, is_tombstoned,
is_forked, is_frozen_pending_resolve, requires_upgrade }` — the one-stop
banner-decision query (`requires_upgrade` is true when the account's
canonical head carries a revision schema version newer than this build
understands — §18.7; reveals/edits on it return `FfiError::Store`
carrying `UnsupportedRevisionSchemaVersion`). `account_resolve_fork`
ratifies the chosen branch (writes a merge revision parented at it,
un-forks the account, clears any `frozen_pending_resolve` flag, keeps
the losing branch's revisions for audit, prunes only the
`pending_merges` stash); it requires an **active (unlocked, non-expired)
session only — NOT a fresh presence proof** (reparenting the graph
reveals nothing; not a §5.4 reveal-class action) and **never
auto-resolves**. A locked / expired session → `FfiError::Session`; a
non-forked account → `FfiError::Validation { kind: "not-forked" }`; a
non-head `keep_revision_id` → `FfiError::Store` (carrying `NotAHead`).
`account_is_forked` / `account_fork_branches` / `account_status` work on
a *locked* vault (graph queries are metadata-only); `requires_upgrade`
is only meaningful on an `Active` vault. In MVP-1 a fork can only arise
from the test helper or the dormant `ingest_chain_revision` path — real
multi-device forks land with MVP-2's chain sync (honest scope, same
posture as 1.5's dormant `last_sync_at`). No new CLI subcommand (the
`pangolin-cli resolve` subcommand rides CLI-V1). These are an **additive
1.1-surface amendment** — the 1.1 freeze declared `RevisionId` /
`RevisionMeta` (bodies "finalize in 1.6") but no `fork_*` / `resolve_*`
entries; nothing external binds the 1.1 surface yet. The C-ABI mirror is
not yet extended (UniFFI-only, same as `account_*` / `device_*`). The
§18.7 schema-versioning policy this finalises is documented in
`docs/architecture/schema-versioning.md`; the lineage model in
`docs/architecture/revision-lineage.md`.

### TOTP (MVP-1 issue 1.7 — body implemented + additive amendment)

| Function | Backed by | Status |
|---|---|---|
| `totp_generate(h: &VaultHandle, id: AccountId, at: UnixTimestamp) -> Result<TotpCode, FfiError>` | `pangolin-totp` → `Vault::totp_generate` | **1.1-frozen signature — body implemented in 1.7.** Session-class (Q3): an unlocked, non-expired vault is enough, no presence proof. Errors: `Session` (locked / expired / frozen / requires-upgrade account); `Validation { kind: "totp_not_configured" }` (no TOTP secret on the account); `Validation { kind: "totp" }` (negative timestamp); `Store` (unknown / tombstoned account). The seed never crosses FFI — only the digit string does. |
| `parse_totp_secret(input: String) -> Result<ParsedTotpSecretFfi, FfiError>` | `pangolin-totp::parse_totp_secret` | **new (additive amendment).** Parses a bare RFC 4648 base32 secret *or* a full `otpauth://totp/...` URI into `{ secret: Arc<TotpSecret>, params: TotpParamsFfi, label, issuer }`. No vault access. Errors: `Validation { kind: "totp" }` for any malformed input (bad base32, malformed URI, `otpauth://hotp/...`, unknown algorithm, out-of-range digits/period, empty secret). The shell calls this on the user's pasted string, then passes the parsed `secret` + `params` into `account_add` / `account_update`. |

New records: `TotpCode { schema_version, code: String, seconds_remaining: u16 }` (1.1-frozen shape, now populated); `ParsedTotpSecretFfi { schema_version, secret: Arc<TotpSecret>, params: TotpParamsFfi, label: Option<String>, issuer: Option<String> }`; `TotpParamsFfi { schema_version, algorithm: TotpAlgorithm, digits: u8, period_seconds: u32 }`; `TotpAlgorithm` enum `{ Sha1, Sha256, Sha512 }`. `AccountDraft` / `AccountPatch` grow a `totp_params: Option<TotpParamsFfi>` field (additive — `None` when a secret is present means "RFC 6238 defaults" — SHA-1 / 6 / 30; ignored when `totp_secret` is `None`). `reveal_totp_secret` (1.4) is unchanged — still the only path the raw seed crosses FFI, presence-gated. `account_update`'s `totp_secret` doubled-`Option` semantics are unchanged. The C-ABI mirror is not yet extended (UniFFI-only, same posture as `account_*` / `device_*`). See `docs/architecture/totp.md`.

### Password generator

| Function | Lands in |
|---|---|
| `password_generate(policy: PasswordPolicy) -> Result<SecretPassword, FfiError>` | 1.8 (return shape amended from `-> SecretPassword`; invalid policy → `Validation { kind: "password_policy" }`) |
| `password_entropy_bits(policy: PasswordPolicy) -> Result<f64, FfiError>` | 1.8 (additive — `length × log2(alphabet_size)`; invalid policy → `Validation { kind: "password_policy" }`) |
| `password_strength(password: String) -> PasswordStrength` | 1.8 (additive — zxcvbn-style estimate for arbitrary passwords; infallible; the `password` arg is zeroized after use) |
| `password_policy_default() -> PasswordPolicy` | 1.8 (additive — the strong defaults: length 16, all four classes, `exclude_ambiguous: true`) |

`PasswordPolicy` gained an `exclude_ambiguous: bool` field in 1.8
(additive). `PasswordStrength` Record (1.8): `{ schema_version: u16,
score: u8 (0–4), guesses_log10: f64, crack_time_seconds: f64 (the
conservative offline-slow-hashing 10k-guesses/s estimate),
feedback_warning: Option<String>, feedback_suggestions: Vec<String> }`.
See `password-generator.md` for the generator's design + the
unbiased-draw / CSPRNG guarantees.

### KDBX import

| Function | Backed by | Lands in |
|---|---|---|
| `kdbx_import(handle: Arc<VaultHandle>, path: String, kdbx_password: Arc<SecretPassword>, keyfile_path: Option<String>) -> Result<KdbxImportReport, FfiError>` | `pangolin-kdbx` | **1.9 — implemented** |

> **1.9 amendment (additive, per `docs/issue-plans/1.9.md` L11/L13):**
> the 1.1-frozen `kdbx_import` signature grew an optional
> `keyfile_path: Option<String>` argument so a `.kdbx` protected by a
> keyfile (in addition to / instead of a password) can be imported.
> Allowed since nothing external binds the FFI yet (same posture as the
> 1.2 / 1.7 amendments). `KdbxImportReport { schema_version, imported,
> skipped, failed, failure_kinds }` stays frozen. Parse-level failures
> (bad file / wrong password / wrong-or-missing keyfile / corrupt
> header) collapse to `FfiError::Validation` with a `kdbx_*` `kind`
> label (no decryption oracle — wrong-password and wrong-keyfile are
> indistinguishable); per-entry validation failures are non-fatal and
> counted by category in `failure_kinds`. See
> `docs/architecture/kdbx-import.md`.

### Encrypted export

| Function | Lands in |
|---|---|
| `vault_export_encrypted(handle: Arc<VaultHandle>, dest: String, passphrase: Arc<SecretPassword>, accounts: Option<Vec<String>>, presence: PresenceProof) -> Result<ExportReport, FfiError>` | **1.10 — implemented** |
| `vault_export_plaintext(handle: Arc<VaultHandle>, dest: String, confirmation: PlaintextExportConfirmation, accounts: Option<Vec<String>>, presence: PresenceProof) -> Result<ExportReport, FfiError>` | **1.10 — implemented** |
| `vault_restore_from_archive(archive_path: String, dest: String, archive_passphrase: Arc<SecretPassword>, new_vault_password: Arc<SecretPassword>) -> Result<RestoreReport, FfiError>` | **1.10 — added (additive)** |

> **1.10 amendments (additive, per `docs/issue-plans/1.10.md` L2/L9 +
> D1/D2/D4/D5):** both 1.1-frozen `vault_export_*` signatures grew a
> `presence: PresenceProof` (forced by Session spec §5.4 — "export
> vault" is reveal-class; the frozen signature predates 1.4's presence
> model) and an `accounts: Option<Vec<String>>` subset selector (hex
> account ids; `None` = the whole vault — D1); the encrypted entry also
> grew an export-passphrase arg (`Arc<SecretPassword>`, consumed +
> zeroized — a *fresh* passphrase, independent of the vault master
> password). Both now return a non-secret `ExportReport { schema_version,
> account_count, bytes_written, encrypted }` instead of `()`. A new
> `vault_restore_from_archive` entry (D2/D4) decodes an archive and
> writes a brand-new `.pvf` (`O_CREAT|O_EXCL` — never clobbers; does NOT
> merge into an existing vault), returning `RestoreReport { schema_version,
> account_count, device_count }`. The frozen `PlaintextExportConfirmation
> { schema_version, token }` Record is finally given semantics: the FFI
> requires a structurally-valid single-use `token` (a missing/empty token
> → `FfiError::Validation { kind: "export_not_confirmed" }`); the
> CLI/UI owns the double-confirmation + 30 s delay + warning copy (master
> plan §4 row 1.10). `UnixTimestamp` is reused for the D6 `exported_at`
> inside the encrypted payload. Error mapping: a wrong export passphrase
> *or* a tampered archive → one `FfiError::Validation { kind:
> "export_credentials" }` (no oracle); bad header/CBOR/unknown version →
> `export_format`; oversized archive → `export_too_large`; IO →
> `export_io`. See `docs/architecture/encrypted-export.md`.

### Capture authority

Browser-Ext spec §2.3 / API contract §16 / Threat Model invariant #8.
The registry records which component (desktop / browser-ext / mobile-OS
autofill) owns credential capture per context, with the
`(context_kind, platform_hint)` key making exclusivity structural.

| Function | Lands in |
|---|---|
| `capture_authority_register(h: &VaultHandle, presence: PresenceProof, authority: CaptureAuthority, context: CaptureContext, replace_existing: bool) -> Result<(), FfiError>` | 1.11 |
| `capture_authority_query(h: &VaultHandle, context: CaptureContext) -> Result<Option<CaptureAuthorityEntry>, FfiError>` | 1.11 |
| `capture_authority_list(h: &VaultHandle) -> Result<Vec<CaptureAuthorityEntry>, FfiError>` | 1.11 |

**Auth tier (L6, R-c — HYBRID).** `capture_authority_register` takes a
`PresenceProof` argument always but consumes it only on the `Replaced`
branch:

- **Created** (first registration for a `(kind, platform_hint)` key) —
  session-class. The presence proof argument is held but not verified.
- **NoOp** (re-register with byte-identical payload) — session-class.
- **Replaced** (existing row overwritten via `replace_existing=true`) —
  reveal-class. Routes through `ensure_presence_fresh` BEFORE the
  REPLACE commits; a stale proof → `FfiError::Session` with the
  `PromptTimedOut` reason.

`capture_authority_query` and `capture_authority_list` are session-class
(no presence).

**Exclusivity (L8).** A second register with a *different* payload AND
`replace_existing=false` surfaces
`FfiError::Validation { kind: "capture_authority_exclusivity" }`; the
message names the context kind only — no info-leak on the existing
`component_id`.

**Validation (L7).** `component_id` (≤ 256 chars, NFC, no control
chars, no leading/trailing whitespace, non-empty), `component_version`
(≤ 64 chars, same character classes), and `platform_hint`
(lowercased-ASCII allowlist: `chrome` / `firefox` / `edge` / `safari` /
`chromium` / `webview` / `ios` / `android` / `windows` / `macos` /
`linux`). Violations →
`FfiError::Validation { kind: "capture_authority" }`. The kind /
context_kind discriminators are closed `uniffi::Enum`s (adding a
variant is a §18.7 minor bump).

The Rust API on `Vault` additionally exposes a `capture_authority_clear`
test/MVP-2 helper (not on the FFI surface in 1.11) and the
`RegistrationOutcome::{Created, Replaced { prior }, NoOp { existing }}`
discriminator (the FFI body collapses every success to `Ok(())` — the
discriminator stays on the store side for tests + a future MVP-2
amendment that may surface the `prior` payload).

## Records and enums that cross the boundary

| Type | UniFFI shape | Carries user data | Schema-version slot |
|---|---|---|---|
| `SecretPassword` | Object (`Arc<Self>`) | Yes (password bytes) | n/a (opaque) |
| `TotpSecret` | Object (`Arc<Self>`) | Yes (totp bytes) | n/a (opaque) |
| `RevealedSecret` | Object (`Arc<Self>`) | Yes (a revealed secret byte string — head password / notes / raw TOTP seed; `byte_length()`-only) | n/a (opaque) |
| `PresenceProof` | Record | Yes (proof bytes) | `schema_version: u16` |
| `SessionInfo` | Record | No (timestamps + flags + configured idle) | `schema_version: u16` |
| `VaultHandle` | Object (`Arc<Self>`) | Indirect (holds vault state) | n/a (opaque) |
| `AccountId` | Record | No | `schema_version: u16` |
| `DeviceId` | Record | No | `schema_version: u16` |
| `DeviceInfo` | Record | No (1.5 — device id, label, registered-at, dormant last-sync, capability flags, is-current, public verifying key) | `schema_version: u16` |
| `DeviceCapabilities` | Enum (`uniffi::Enum`) | No (1.5 — `Full` in MVP-1; grows later) | n/a (closed enum) |
| `AccountDraft` | Record | Yes (full account at create — multi-username, multi-URL, tags, password, optional TOTP) | `schema_version: u16` |
| `AccountPatch` | Record | Yes (partial update; password change appends to history) | `schema_version: u16` |
| `AccountSnapshot` | Record | **No** (1.4 Q5b — metadata only: display name, tags, usernames, URLs, head revision id, password-history *count*, `has_totp` flag, current-password-changed-at timestamp; the secrets come from `reveal_*`) | `schema_version: u16` |
| `PasswordHistoryEntry` | Record | Yes (one historical password value — returned only by the presence-gated `reveal_password_history`) | `schema_version: u16` |
| `RevisionId` | Record | No | `schema_version: u16` |
| `RevisionMeta` | Record | No | `schema_version: u16` |
| `TotpCode` | Record | Yes (decimal code + window) | `schema_version: u16` |
| `UnixTimestamp` | type alias for `i64` | No | n/a |
| `PasswordPolicy` | Record | No (policy flags — `length`, `uppercase`, `lowercase`, `digits`, `symbols`, `exclude_ambiguous` (1.8)) | `schema_version: u16` |
| `PasswordStrength` | Record | No (1.8 — zxcvbn score, guesses-log10, conservative crack-time-seconds, optional feedback warning + suggestions) | `schema_version: u16` |
| `KdbxImportReport` | Record | No (counts + category labels) | `schema_version: u16` |
| `PlaintextExportConfirmation` | Record | Yes (1.10 — the single-use plaintext-export confirmation token; the FFI requires it to be structurally non-empty) | `schema_version: u16` |
| `ExportReport` | Record | No (1.10 — `account_count`, `bytes_written`, `encrypted` flag) | `schema_version: u16` |
| `RestoreReport` | Record | No (1.10 — `account_count`, `device_count`) | `schema_version: u16` |
| `CaptureAuthority` | Record | No (1.11 — `kind: CaptureAuthorityKind` + `component_id: String` + `component_version: String`; the 1.1 placeholder `origin: String` shape is replaced) | `schema_version: u16` |
| `CaptureContext` | Record | No (1.11 — `kind: CaptureContextKind` + `platform_hint: Option<String>`; the 1.1 placeholder `label: String` shape is replaced) | `schema_version: u16` |
| `CaptureAuthorityEntry` | Record | No (1.11 — `context: CaptureContext`, `authority: CaptureAuthority`, `registered_at: UnixTimestamp`) | `schema_version: u16` |
| `CaptureAuthorityKind` | Enum (`uniffi::Enum`) | No (1.11 — `Desktop` / `BrowserExtension` / `MobileOsAutofill`; closed enum, Browser-Ext spec §2.3 / Threat Model #8) | n/a (closed enum) |
| `CaptureContextKind` | Enum (`uniffi::Enum`) | No (1.11 — `Desktop` / `Browser` / `MobileOs`; closed enum) | n/a (closed enum) |

### Issue 1.2 amendment: production AccountIdentity shape

```rust
pub struct AccountDraft {
    pub schema_version: u16,
    pub display_name: String,                        // ≤ 256 chars; non-empty after trim
    pub tags: Vec<String>,                           // ≤ 32 entries; ≤ 64 chars each
    pub usernames: Vec<String>,                      // ≥ 1; ≤ 16 entries; ≤ 320 chars each
    pub urls: Vec<String>,                           // ≤ 32 entries; any RFC-3986 scheme
    pub notes: Option<String>,                       // ≤ 65 536 chars when Some
    pub current_password: Arc<SecretPassword>,
    pub totp_secret: Option<Arc<TotpSecret>>,
}

pub struct AccountPatch {
    pub schema_version: u16,
    pub display_name: Option<String>,
    pub tags: Option<Vec<String>>,                   // Some(replace), None(unchanged)
    pub usernames: Option<Vec<String>>,
    pub urls: Option<Vec<String>>,
    pub notes: Option<String>,
    pub current_password: Option<Arc<SecretPassword>>, // triggers history append
    pub totp_secret: Option<Option<Arc<TotpSecret>>>,  // doubled Option: clear vs unchanged
}

pub struct AccountSnapshot {
    pub schema_version: u16,
    pub id: AccountId,
    pub display_name: String,
    pub tags: Vec<String>,
    pub usernames: Vec<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub current_password: Arc<SecretPassword>,       // head of history
    pub password_history: Vec<PasswordHistoryEntry>,
    pub totp_secret: Option<Arc<TotpSecret>>,
    pub head_revision_id: RevisionId,
}

pub struct PasswordHistoryEntry {
    pub schema_version: u16,
    pub password: Arc<SecretPassword>,
    pub set_at: UnixTimestamp,
    pub originating_device: DeviceId,
}

pub struct DeviceId {
    pub schema_version: u16,
    pub bytes: Vec<u8>,                              // 32 bytes
}
```

Schema-version policy text is locked in MVP-1 issue 1.6 (master plan
§18.7). Issue 1.1 commits to the *slot* — every record listed above
that holds user data exposes a `schema_version: u16` field; 1.6 will
finalise read-only-old / reject-future / migration semantics.

### Issue 1.4 amendment: session-policy production (Q4 / Q5b)

MVP-1 issue 1.4 promotes the session engine to production and adjusts
the FFI surface in three additive ways (nothing external binds the 1.1
surface yet, so removing the over-shared secret fields from a frozen
shape is safe — same posture as 1.2's `AccountDraft` widening):

1. **`AccountSnapshot` is tightened to metadata-only (Q5b — the strict
   reveal-gated model).** It loses `current_password`, `password_history`,
   and `totp_secret` (the over-sharing 1.2's plan §D intended to avoid)
   and gains `password_history_count: u32`, `has_totp: bool`, and
   `current_password_changed_at: UnixTimestamp` (the `set_at` of the
   head history entry). Every secret crosses FFI **only** through the
   presence-gated `reveal_*` entries — the search/list path never touches
   an encrypted password blob and a binding shell never holds a secret
   handle just because the user searched.
2. **New `reveal_*` entry points** (see the "Reveal" table above) — the
   canonical way reveal-class secrets cross FFI, each presence-gated.
   They return `RevealedSecret` (a new zeroizing `byte_length()`-only
   Object) / `Vec<PasswordHistoryEntry>`.
3. **`session_extend` gains a `presence: PresenceProof` argument** —
   extending a long session is high-risk per §5.4. And **`SessionInfo`
   widens** (additive fields) to carry the idle / absolute deadlines, the
   configured idle duration in seconds, and the presence-freshness
   horizon, so a host UI can render a countdown / "session settings"
   panel.

```rust
pub struct AccountSnapshot {
    pub schema_version: u16,
    pub id: AccountId,
    pub display_name: String,                        // non-secret per the V1 model
    pub tags: Vec<String>,
    pub usernames: Vec<String>,
    pub urls: Vec<String>,
    pub head_revision_id: RevisionId,
    pub password_history_count: u32,                 // count only; bytes via reveal_password_history
    pub has_totp: bool,                              // flag only; seed via reveal_totp_secret
    pub current_password_changed_at: UnixTimestamp,  // set_at of the head history entry; 0 if empty
}

pub struct SessionInfo {
    pub schema_version: u16,
    pub last_refresh_unix: i64,                       // most recent activity touch; 0 when not active
    pub is_active: bool,
    pub idle_deadline_unix: i64,                      // 1.4 (additive); 0 when not active
    pub absolute_deadline_unix: i64,                  // 1.4 (additive); 4h ceiling; 0 when not active
    pub configured_idle_secs: i64,                    // 1.4 (additive); 300/900/1800/3600/14400 or -1
    pub last_presence_fresh_until_unix: i64,          // 1.4 (additive); 0 when not active
}

#[derive(uniffi::Object)]
pub struct RevealedSecret { /* zeroizing byte buffer; byte_length() only */ }
```

The `pangolin_store::Vault` side adds `reveal_current_password` /
`reveal_password_history` / `reveal_notes` / `reveal_totp_secret`
(all presence-gated; `reveal_password` is kept as a back-compat alias
for `reveal_current_password`), `touch_session_explicit(presence)`
(backs `session_extend`), `set_session_idle(SessionDuration, Option<&dyn PresenceProof>)`
(lengthening needs presence; shortening does not), and `device_locked()`
(the §7.5 OS-lock hook — CLI unused). New public types live in
`pangolin-store::session` and are re-exported via `pangolin_core::session`
(`SessionDuration`, `PROMPT_TIMEOUT`, `SESSION_IDLE_UNTIL_DEVICE_LOCK`,
`StoreError::PromptTimedOut`). See `docs/architecture/session.md` for
the state machine, the freshness/timeout/dedup model, and the
reveal-class taxonomy.

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
- `docs/issue-plans/1.2.md` — `AccountIdentity` production model (the
  `AccountDraft`/`AccountPatch`/`AccountSnapshot` widening amendment).
- `docs/issue-plans/1.4.md` — session-policy production (Q1-Q5b: the
  reveal-class entries, the `AccountSnapshot` tightening, the
  `session_extend` presence arg).
- `docs/architecture/session.md` — the session state machine, the
  presence-freshness / prompt-timeout / dedup model, the reveal-class
  taxonomy.
- Session spec §2.3 / §5 / §7 / §8 — the session invariant, the
  high-risk-action gate, the timing rules, the prompt behaviour.
