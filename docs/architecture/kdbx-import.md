<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# KDBX import (MVP-1 issue 1.9)

`pangolin-kdbx` is a hand-rolled, **read-only** parser for `KeePass` 2.x
`.kdbx` files plus a mapping layer that turns `KeePassXC` entries into
Pangolin `AccountIdentity` drafts. It is a **leaf crate** depended on
only by `pangolin-ffi` (the frozen `kdbx_import` FFI body) and `apps/cli`
(the `pangolin-cli import` subcommand). The XML / gzip / KDBX-container
dependency surface never reaches `pangolin-core` or `pangolin-crypto`
(master-plan §16.8 footnote 2: blast-contained parser bug), and the
crate is `#![cfg_attr(not(test), forbid(unsafe_code))]`.

## Supported formats

| Format | KDF | Outer cipher | Block authentication | Inner payload | Inner random stream |
|---|---|---|---|---|---|
| **KDBX 3.1** | AES-KDF (AES-256-ECB transform `rounds` times → SHA-256) | AES-256-CBC | stream-start-bytes prefix check | gzip'd XML | Salsa20 (fixed KeePass IV `E830094B97205D2A`) |
| **KDBX 4.x** | Argon2d / Argon2id (params from the `VariantDict`) | AES-256-CBC **or** ChaCha20 | HMAC-SHA256 per-block MAC (+ header SHA-256 + header HMAC) | inner-header TLVs then gzip'd XML | ChaCha20 |

The crypto primitives are the already-vendored RustCrypto crates
(`aes`, `cbc`, `chacha20`, `salsa20`, `argon2`, `hmac`, `sha2`); only
the container-format glue is ours.

Out of scope (typed errors / future issues):

- **Writing `.kdbx`** (export to `KeePass`).
- **KDBX 1.x / 2.x** (`.kdb`, pre-release 2.x) → `KdbxError::UnsupportedVersion`.
- **TwoFish** outer cipher → `KdbxError::UnsupportedCipher`.
- **YubiKey / hardware HMAC-SHA1 challenge-response** databases →
  `KdbxError::UnsupportedCredential` ("unsupported credential type") —
  needs hardware I/O an offline CLI can't do; no architectural debt
  (Pangolin's future hardware-unlock rides FIDO2/WebAuthn, not legacy CR).
- **CSV / 1Password / Bitwarden / LastPass / Chrome** imports — each its
  own future importer.
- An `AccountIdentity` attachment slot (so KDBX attachments could be
  stored) — an MVP-3+ schema bump.

## Credential model

The composite key is `SHA-256( SHA-256(password) || keyfile_key )` per
the KeePass spec, with either component optional (but at least one
required). Keyfile forms supported: a `KeePass` 2.x `.keyx` / `<KeyFile>`
XML keyfile (v1 base64-32 or v2 hex-32 with the `Data Hash="…"` check),
a raw 32-byte file, a 64-hex-character file, or — fallback — any other
file's `SHA-256`.

**No decryption oracle.** A wrong password, a wrong-or-missing keyfile,
a failed block-MAC, a failed header-HMAC, and a failed KDBX3
stream-start-bytes check **all** collapse to one `KdbxError::WrongCredentials`
variant (mapped at the FFI boundary to `FfiError::Validation { kind:
"kdbx_credentials" }`). The KDF (Argon2 / AES-KDF) runs before the
failure is known, so timing is dominated by the intentionally-slow KDF.

## Field mapping (`KeePassXC` → `AccountIdentity`)

| `KeePassXC` source | → `AccountIdentityDraft` slot | Edge cases |
|---|---|---|
| `Title` | `display_name` | empty → synthesise (`(untitled — <UserName>)` / `(untitled — <host>)` / `Imported entry`); truncated to 256 chars |
| `UserName` | `usernames[0]` | empty → `"(no username)"` placeholder (the model requires ≥1); truncated to 320 bytes |
| `URL` | `urls[0]` | empty → omitted; unparseable-looking (no `://` and no `.`) → dropped; capped 2048 bytes / 32 URLs |
| `Password` (Protected) | `password` | **empty → the entry is skipped** (counted, non-secret reason — an entry with no password isn't a credential); truncated to 4096 bytes |
| `Notes` | `notes` | augmented with a custom-fields block and an attachment-size note (below); truncated to 65 536 bytes with a `[notes truncated]` marker on overflow |
| `otp` field (an `otpauth://totp/…` URI) **or** `TimeOtp-Secret-Base32` (+ `TimeOtp-Period` / `TimeOtp-Digits` / `TimeOtp-Algorithm`) | `totp_secret` + `totp_params` (full params, no coercion) | normalised to an `otpauth://` URI and fed through `pangolin_totp::parse_*`; a `hotp://` URI or any parse failure → TOTP dropped (the entry still imports) |
| `<Tags>` (`;`/`,`-split) ∪ group-path components (minus `Root` / the recycle bin) ∪ `"expired"` | `tags` | deduped case-insensitively; capped 64 bytes / 32 tags |
| `<Times>` `Expires=True` + past `ExpiryTime` | an `"expired"` tag | imported (not skipped) — data preservation; the user can filter |
| recycle-bin group entries (`<Meta><RecycleBinUUID>`) | — | **skipped entirely** (recursively); counted in the `skipped` count |
| duplicate entries / `KeePass` clones | — | **imported all** (no dedup — Pangolin has no natural dedup key) |
| custom `<String>` keys (anything not in `{Title,UserName,Password,URL,Notes,otp,TimeOtp-*}`) | appended to `notes` | as a `--- Imported custom fields ---` labelled block |
| binary attachments (`<Binary>` / the inner-header binary pool) | — | **dropped**; a size-only redacted note `[N attachment(s) not imported, ~X KiB total]` is appended to `notes`. No attachment bytes ever land anywhere. (KDBX3 attachments live in `<Meta><Binaries>`, which we do not parse; their bytes are still never touched and `N` reads `0` for KDBX3.) |
| per-entry `<History>` | replayed into Pangolin's password-history slot | after `account_add`, the **distinct** historical `Password` values (oldest→newest, consecutive equals deduped, the one equal to the current password dropped, capped at 64) are replayed as `account_update` calls. **Limitation:** the public `account_update` path stamps each replayed revision with the *import* wall-clock and this device's id, not the KeePass `LastModificationTime` / a synthetic device — preserving custom timestamps would need a lower-level store API. |

## Error taxonomy

`pangolin_kdbx::KdbxError` (a `thiserror` enum, `#[non_exhaustive]`,
`Debug`/`Display` never echo secret bytes / entry titles / usernames):

`Io`, `NotKdbx`, `UnsupportedVersion`, `FileTooLarge`, `CorruptHeader`,
`CorruptPayload`, `BlockHmacMismatch` (internal — folded into
`WrongCredentials` at the public boundary), `WrongCredentials` (the
no-oracle collapse), `UnsupportedCredential`, `UnsupportedKdf`,
`KdfParamsRejected`, `UnsupportedCipher`, `XmlMalformed`,
`TooManyEntries`, `InflatedTooLarge`.

FFI mapping (`pangolin-ffi/src/kdbx.rs::map_kdbx_err`): `WrongCredentials`
/ `BlockHmacMismatch` → `Validation { kind: "kdbx_credentials" }`;
`UnsupportedCredential` → `kind: "kdbx_unsupported_credential"`;
`FileTooLarge` / `TooManyEntries` / `InflatedTooLarge` → `kind:
"kdbx_too_large"`; `Io` → `kind: "kdbx_io"`; everything else (and any
future variant) → `kind: "kdbx_format"`. Per-entry mapping failures are
**non-fatal** — counted by category in `KdbxImportReport.failure_kinds`
(non-secret labels: `empty_password`, `no_fields`, `validation_<kind>`,
`store_error`), never a panic.

## Adversarial hardening

- `forbid(unsafe_code)` — no UB even on a hostile file.
- Bounded file size (`KDBX_MAX_FILE_BYTES` = 64 MiB), inflated-payload
  size (`KDBX_MAX_INFLATED_BYTES` = 256 MiB — gzip-bomb guard, streamed
  inflate with a bounded buffer), entry count (`KDBX_MAX_ENTRIES` =
  100 000), header-field length (1 MiB), `VariantDict` entry count (64)
  and value size (1 MiB), XML event count (8 M), XML nesting depth
  (256), and per-element text length (16 MiB).
- KDF params sanity-clamped: AES-KDF `rounds` ≤ 1e8; Argon2 memory ≤
  1 GiB, iterations ≤ 1000, parallelism ≤ 64, salt 8..=64 bytes,
  KiB-aligned → otherwise `KdfParamsRejected` / `CorruptHeader`.
- Lying length / size fields, truncated headers/payloads, unbalanced
  XML, non-UTF-8 element names/text, and unknown KDBX
  versions/signatures all surface as typed errors, never a panic.
- KDBX4 block-MAC and header-HMAC are *verified* (constant-time tag
  compare via `subtle`); a flipped ciphertext/header byte → rejected.
- XML entity-expansion: `quick-xml` resolves only the five predefined
  entities (which cannot expand a billion-laughs payload); custom DTD
  entities are not expanded.

## Secret discipline

Every parsed password / TOTP seed / notes value / keyfile-bytes stays in
`zeroize::Zeroizing` inside `pangolin-kdbx` and is moved into
`SecretBytes` only at the `AccountIdentityDraft` boundary. All
secret-bearing types redact their `Debug`. `KdbxImportReport` and all
`failure_kinds` strings are non-secret category labels only — never entry
titles, usernames, or byte material. The KDBX master password `String`
that crosses the FFI / CLI is wrapped in `Zeroizing` and zeroized after
the KDF consumes it. Imported credentials route through
`Vault::account_add` (same AEAD seal as typed ones), so the
`no_plaintext_on_disk` property holds by construction; the
`pangolin-cli import` integration test (`apps/cli/tests/import_kdbx.rs`)
scans the raw `.pvf` for the imported plaintext markers and finds none.

## FFI surface

`kdbx_import(handle: Arc<VaultHandle>, path: String, kdbx_password:
Arc<SecretPassword>, keyfile_path: Option<String>) ->
Result<KdbxImportReport, FfiError>` — the 1.1-frozen entry, implemented
with the one additive amendment (the optional `keyfile_path`, per 1.9
L11/L13; nothing external binds the FFI yet, same posture as the 1.2 /
1.7 amendments). `KdbxImportReport { schema_version, imported, skipped,
failed, failure_kinds }` stays frozen. The store-side ingestion loop
lives in `pangolin-ffi` (and a sibling copy in `apps/cli`) — `pangolin-store`
gains **no** `pangolin-kdbx` dep.

## CLI

`pangolin-cli import <file.kdbx> [--keyfile <path>] --vault-path <vault.pvf>`
— prompts for the vault password and then the KDBX file's password on
**stderr** (without echo, via `rpassword`); `--vault-password` /
`--kdbx-password` flags exist for CI. Prints the import counts
(`imported` / `skipped` / `failed` / `failure_kinds`) on **stdout** (or a
JSON-Lines object under `--json`); exits non-zero if any entry failed.
Never echoes a secret.

## Scale

The 500-entry exit-criterion fixture (`pangolin-kdbx/tests/scale.rs`)
builds a 500-entry KDBX 4.x file, parses + maps it, and spot-checks
fields — **correctness assertions only, no hard timing assertion**
(env-quirk #11: this test runs in debug mode under
`cargo test --workspace`; any release-mode perf smoke would be
`#[ignore]`'d).
