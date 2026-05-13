<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Capture Authority Registry (master plan §16 / Browser-Ext spec §2.3)

Locked by MVP-1 issue 1.11. Plan doc: `docs/issue-plans/1.11.md`.

## The rule

Browser-Ext spec §2.3 "Capture Authority Rule" states: **only one
component may detect and prompt for credential events per context**.
Browser context ⇒ the extension owns capture. Desktop apps context ⇒
the desktop client owns capture. Mobile context ⇒ the OS autofill
subsystem owns capture. This is Threat Model invariant #8.

1.11 makes that rule structurally enforceable. The capture-authority
registry is a vault-level SQL table whose PRIMARY KEY makes
exclusivity a type-system property (not a string convention), with
typed errors on conflict and a hybrid auth tier that gates *replacement*
of an existing registration behind a fresh presence proof.

## On-disk shape

```sql
-- pangolin-store: capture_authorities table
CREATE TABLE IF NOT EXISTS capture_authorities (
    context_kind        INTEGER NOT NULL,  -- 0=Desktop, 1=Browser, 2=MobileOs
    platform_hint       TEXT    NOT NULL DEFAULT '',
    authority_kind      INTEGER NOT NULL,  -- 0=Desktop, 1=BrowserExtension, 2=MobileOsAutofill
    component_id        TEXT    NOT NULL,
    component_version   TEXT    NOT NULL,
    registered_at       INTEGER NOT NULL,  -- unix-ms; advances on every replace
    schema_version      INTEGER NOT NULL,  -- §18.7 ladder; max = 1 in MVP-1
    PRIMARY KEY (context_kind, platform_hint)
);
```

Non-secret metadata, plaintext at rest — same posture as the `devices`
table's `label`. Additive `CREATE TABLE IF NOT EXISTS` (no
`format_version` bump). Legacy 1.10 vaults pick the table up on next
open through `apply_pragmas_and_schema` (the existing migration
mechanism). NULL `platform_hint` is coalesced to `''` so the PRIMARY
KEY treats it as a distinct key value — a `(kind, None)` registration
is structurally distinct from a `(kind, Some("chrome"))` one.

## Type-system invariants

Both discriminators are **closed enums**, making Threat Model invariant
#8 a type-system invariant rather than a string convention:

- `CaptureAuthorityKind` ∈ `{ Desktop, BrowserExtension, MobileOsAutofill }`.
- `CaptureContextKind` ∈ `{ Desktop, Browser, MobileOs }`.

Adding a 4th variant in either enum is a §18.7 minor bump (additive
enum-value addition). A future-versioned row's discriminator that this
build doesn't recognise rejects at decode for that row only.

## Validation discipline (L7)

`component_id`: non-empty after trim; ≤ 256 chars; NFC-normalised;
reject control chars (Unicode Cc range), surrogates (impossible in
Rust `&str`, kept self-documenting), `\0..\x1f` (covered by `Cc`); no
leading or trailing whitespace.

`component_version`: ≤ 64 chars, NFC, same character classes; empty is
permitted (some components have no well-defined version yet).

`platform_hint`: lowercased ASCII; one of a closed allowlist:
`chrome` / `firefox` / `edge` / `safari` / `chromium` / `webview` /
`ios` / `android` / `windows` / `macos` / `linux`. The lowercased-
ASCII rule defeats Unicode-homoglyph impersonation
(e.g. `chr` + zero-width space + `ome`).

All rejections surface as
`StoreError::CaptureAuthorityValidation { reason }` →
`FfiError::Validation { kind: "capture_authority" }`. No panics.

## Auth tier — HYBRID (L6, R-c)

`Vault::capture_authority_register` takes a presence proof but its
verification depends on the outcome:

| Outcome   | Trigger                                                              | Auth tier      | Presence consumed?                |
|-----------|----------------------------------------------------------------------|----------------|-----------------------------------|
| `Created` | No existing row for the `(kind, platform_hint)` key.                 | Session-class  | No (held but not verified).       |
| `NoOp`    | Existing row, payload byte-identical to the call's input.            | Session-class  | No.                               |
| `Replaced`| Existing row, *different* payload, `replace_existing=true`.          | **Reveal-class** | **Yes** — `ensure_presence_fresh` runs before the REPLACE commits. |
| `CaptureAuthorityExclusivity` (error) | Existing row, different payload, `replace_existing=false`. | n/a (rejection) | No.                               |

The threat shape: setting up a brand-new registration is benign
metadata; *replacing* an existing one is the moment a stale-session
attacker could silently redirect future capture events to a rogue
helper. The hybrid tier is exactly tuned to that — first register is
session-class (the cheap path), replace requires the same fresh
presence proof as `reveal_*` / `export_*` (Session spec §5.4
discipline).

`capture_authority_query` and `capture_authority_list` are
session-class — `NotUnlocked` / `SessionExpired` on a locked / expired
vault, no presence required.

## Exclusivity — reject on conflict (L8, R-e)

Default behaviour: a register that would clobber an existing
*different* registration is **rejected** with
`StoreError::CaptureAuthorityExclusivity { context }`
→ `FfiError::Validation { kind: "capture_authority_exclusivity" }`.
The error message names the context kind only (`desktop` / `browser` /
`mobile_os`) — **no info-leak** on the existing `component_id`. A
curious caller cannot probe the registry by submitting candidate
registrations and reading the rejection; the legitimate read path is
`capture_authority_query` / `capture_authority_list`.

Caller opts into replacement via `replace_existing: bool`. Per L6,
that branch *also* requires a fresh presence proof — opt-in alone is
not enough.

`registered_at` advances on every `Replaced` (small forensic audit
trail). A full audit-log table of register/replace events is *not*
built in 1.11 — MVP-2's signed Revision Log + entitlement registry is
the real home for chronological audit material.

## FFI surface

```rust
// pangolin-ffi: capture_authority.rs
pub enum CaptureAuthorityKind { Desktop, BrowserExtension, MobileOsAutofill }
pub enum CaptureContextKind   { Desktop, Browser, MobileOs }

pub struct CaptureAuthority {
    pub schema_version: u16,
    pub kind: CaptureAuthorityKind,
    pub component_id: String,
    pub component_version: String,
}

pub struct CaptureContext {
    pub schema_version: u16,
    pub kind: CaptureContextKind,
    pub platform_hint: Option<String>,
}

pub struct CaptureAuthorityEntry {
    pub schema_version: u16,
    pub context: CaptureContext,
    pub authority: CaptureAuthority,
    pub registered_at: UnixTimestamp,
}

pub fn capture_authority_register(
    handle: Arc<VaultHandle>,
    presence: PresenceProof,
    authority: CaptureAuthority,
    context: CaptureContext,
    replace_existing: bool,
) -> Result<(), FfiError>;
pub fn capture_authority_query(
    handle: Arc<VaultHandle>,
    context: CaptureContext,
) -> Result<Option<CaptureAuthorityEntry>, FfiError>;
pub fn capture_authority_list(
    handle: Arc<VaultHandle>,
) -> Result<Vec<CaptureAuthorityEntry>, FfiError>;
```

The 1.1 scaffold parked `CaptureAuthority` / `CaptureContext` in
`pangolin-ffi/src/kdbx.rs` (where they don't belong). 1.11 relocates
them to `pangolin-ffi/src/capture_authority.rs` and finalises the
shapes per L5. Nothing external binds the 1.1 surface yet (the
original `register` body was `todo!()`), so this is an additive
amendment — same posture as 1.2/1.4/1.7/1.9/1.10.

### Rust API on `Vault`

```rust
impl Vault {
    pub fn capture_authority_register(
        &mut self,
        presence: &dyn PresenceProof,
        authority: CaptureAuthority,
        context: CaptureContext,
        replace_existing: bool,
    ) -> Result<RegistrationOutcome, StoreError>;

    pub fn capture_authority_query(
        &mut self,
        context: CaptureContext,
    ) -> Result<Option<CaptureAuthorityEntry>, StoreError>;

    pub fn capture_authority_list(
        &mut self,
    ) -> Result<Vec<CaptureAuthorityEntry>, StoreError>;

    // Not on the FFI surface in 1.11; tests + the future MVP-2
    // "extension uninstalled" hook.
    pub fn capture_authority_clear(
        &mut self,
        context: CaptureContext,
    ) -> Result<bool, StoreError>;
}

pub enum RegistrationOutcome {
    Created,
    Replaced { prior: CaptureAuthority },
    NoOp { existing: CaptureAuthority },
}
```

The FFI body for `capture_authority_register` collapses every success
outcome to `Ok(())`. The `RegistrationOutcome` discriminator stays on
the store side for tests + a future MVP-2 amendment that may surface
the `prior` payload on `Replaced` (out of scope for 1.11).

## Archive round-trip (L10, R-f)

1.10's `ArchiveSnapshot` grows an additive optional `capture_authorities:
Vec<CapturedCaptureAuthority>` field at the end of the top-level CBOR
array. The encoder always emits it (even when empty) to keep the
format stable; the decoder accepts either the legacy 7-item shape (1.10
archives — the missing trailing field decodes as empty) or the 1.11
8-item shape. No schema-version bump on the archive payload —
`ARCHIVE_SNAPSHOT_SCHEMA_VERSION` stays at 1 because the change is
structurally additive (a trailing optional element).

`Vault::restore_to_new_vault` does **not** re-register the archive's
registry — the destination vault starts with an empty registry. The
destination is a new environment (new device, possibly new OS); the
source's registration is stale; the user re-registers helpers on the
new device (when they're also re-installing extensions anyway).
Mirrors the `snapshot.devices` posture. The archive *does* carry the
registry for archive fidelity / a future MVP-3+ advanced-restore flow
that may opt to honour it.

## CLI

```
pangolin-cli authority list --vault-path <pvf> [--json]
```

Read-only inspection of the registry. Two-proof unlock (same shell as
`vault export`); prints one line per registered authority sorted by
`(context_kind, platform_hint)`; `--json` emits JSON-Lines. ~30 LoC.

`register` / `clear` CLI subcommands **defer to MVP-2**: by then the
browser extension's native-messaging host is the real consumer of those
flows; CLI versions written now would be vestigial within one cycle
(per R-d).

## Threat model invariant #8 — enforcement summary

The capture-authority rule (Threat Model #8 / Browser-Ext spec §2.3) is
now enforced at three layers:

1. **Structural (SQL).** `PRIMARY KEY (context_kind, platform_hint)`
   prevents two rows for the same key at the storage layer. The
   write-side `INSERT OR REPLACE` (only on the Replace branch) is the
   single point that can mutate an existing key.
2. **Type-system (Rust).** Closed `uniffi::Enum`s make adding a new
   kind a deliberate language-level change (§18.7 minor bump), not a
   string-convention drift.
3. **API (Vault).** `register` is the only entry that writes the
   table; it routes through `validate_authority` + `validate_context`
   + the exclusivity check + the hybrid auth-tier gate before any DDL
   change. There is no way to bypass any of those checks and reach the
   underlying SQL from outside the crate.

## MVP-2 wiring (forward-looking)

When MVP-2 ships the browser extension + native-messaging host, the
JSON-RPC `capture.authority.register` message (API contract §16) will
route to `capture_authority_register` over the same FFI. The hybrid
auth tier is already in place — a user installing the extension for
the first time goes through the session-class Created path; a user
switching to a different extension or changing the extension's
identifier goes through the reveal-class Replaced path with a presence
prompt. Zero migration in MVP-2; the threat model is correct from day
one.

## See also

- `docs/issue-plans/1.11.md` — the locked plan + resolved decisions.
- `docs/architecture/ffi-surface.md#capture-authority` — the
  authoritative FFI signature table.
- `docs/architecture/schema-versioning.md` — the §18.7 ladder (the
  capture-authority slot is one of the per-row entries).
- `THREAT_MODEL.md` invariant #8.
