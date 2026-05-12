# TOTP engine (RFC 6238) — `pangolin-totp`

> MVP-1 issue 1.7. The RFC 6238 generator + the `otpauth://` / base32
> parser + the configurable-param types. See `docs/issue-plans/1.7.md`.

## Crate placement

`pangolin-totp` is a standalone workspace crate, not a `pangolin-core`
sub-module (master plan §16.8): the per-crate `forbid(unsafe_code)` and
`deny.toml` scopes are tightest possible, any RFC 6238 / parser bug is
blast-contained, and the HMAC dependency surface never reaches
`pangolin-core` / `pangolin-crypto`. The dependency arrows are
`pangolin-ffi → pangolin-totp` and `pangolin-store → pangolin-totp` and
`apps/cli → pangolin-totp` — one-way; nothing points back. `pangolin-totp`
is a near-leaf: its only deps are `hmac` + `sha1` + `sha2` + `zeroize` +
`thiserror`. No `uniffi`, no `serde`.

## Dependency choice (Q1)

`pangolin-totp` pulls its **own** `hmac = "=0.12.1"` (already in the lock
via `hkdf`), `sha1 = "=0.10.6"` (the only genuinely-new transitive), and
`sha2 = "=0.10.9"` (the existing workspace pin, reused). It does **not**
route HMAC through `pangolin-crypto` — keeping that audited crate's API
and `deny.toml` scope untouched, and preserving HIGH-1 (`pangolin-crypto`
zero-serde) by construction. SHA-1's collision weakness does not affect
HMAC-SHA1 (no known practical attack). `deny.toml` needed **no** change:
it is a *denylist* (`ring`, `openssl`, `aes-gcm`, …) plus
`wildcards = "deny"`, not an allowlist — `hmac`/`sha1`/`sha2` aren't
denied; they just carry `=`-exact-version pins and a committed
`Cargo.lock` entry. `cargo audit` scans them — clean as of this build.

## RFC 6238 generation

`totp_at(secret: &[u8], at_unix_secs: u64, params: &TotpParams) ->
Result<TotpCode, TotpError>`:

- `counter = at_unix_secs / params.period_seconds` (T0 = 0).
- `mac = HMAC-<algorithm>(key = secret, msg = counter.to_be_bytes())`
  (8-byte big-endian counter).
- Dynamic truncation (RFC 4226 §5.3): `offset = mac[len-1] & 0x0F`;
  `bin = (mac[offset] & 0x7F)<<24 | mac[offset+1]<<16 |
  mac[offset+2]<<8 | mac[offset+3]`.
- `code = bin % 10^digits`, left-zero-padded to `digits`.
- `seconds_remaining = period - (at % period)` — the time-drift surface
  for the UI countdown. Pangolin *generates* codes; it never validates
  an incoming code, so there is no T±1 drift window (that is a
  server-side concern).
- The HMAC tag is held in `zeroize::Zeroizing` (it is a function of the
  seed); the `TotpCode`'s digit string is held in `Zeroizing<String>`
  (the code is a live second factor) and `TotpCode`'s `Debug` redacts it.

The engine reproduces the **RFC 6238 Appendix B test vectors** exactly
for all three algorithms × all six listed timestamps, 8-digit (and the
6-/7-digit truncations). This is the non-negotiable correctness gate
(`crates/pangolin-totp/src/lib.rs` `#[cfg(test)]` + the FFI e2e tests).

## Supported parameters (Q2 — full configurable set)

| Param | Values | Default |
|---|---|---|
| `algorithm` | `SHA1` / `SHA256` / `SHA512` | `SHA1` |
| `digits` | `6`, `7`, `8` (validated) | `6` |
| `period_seconds` | `1..=3600` (validated) | `30` |

The params travel with the secret in storage — see "V2 body" below.

## `otpauth://` / base32 parsing (Q4 — hand-rolled)

- `decode_base32(s) -> Result<Zeroizing<Vec<u8>>, TotpError>` — RFC 4648
  base32 (`A-Z` + `2-7`), case-insensitive, strips trailing `=` padding
  and embedded ASCII whitespace (and `-`), rejects any other char with a
  typed error. ~30 lines; output zeroizing.
- `parse_otpauth_uri(uri)` — parses `otpauth://totp/<label>?secret=BASE32
  &issuer=X&algorithm=SHA1|SHA256|SHA512&digits=6|7|8&period=N`. `secret=`
  required; `algorithm`/`digits`/`period` optional → RFC defaults;
  unknown query params ignored; label/issuer percent-decoded. An
  `otpauth://hotp/...` (counter-based) URI → `TotpError::HotpNotSupported`.
- `parse_totp_secret(input)` — the front door: dispatches to
  `parse_otpauth_uri` if `input` starts with `otpauth://`, else treats
  it as a bare base32 secret with default params. Empty/whitespace-only
  input → `TotpError::EmptySecret` (distinct from "no TOTP configured").
- Secret length: any non-empty seed up to `MAX_SECRET_BYTES = 256` is
  accepted (we do not enforce the RFC 4226 ≥ 128-bit recommendation —
  real-world secrets are frequently shorter). `MAX_SECRET_BYTES` must
  equal `pangolin_store::account::limits::TOTP_SECRET_MAX_BYTES`; an FFI
  integration test cross-checks them.

## Code vs. seed — access classes

- **Generating a code** (`totp_generate(handle, id, at)` →
  `pangolin_store::Vault::totp_generate`) is **session-class** (Q3): only
  an unlocked, non-expired vault is required — *no presence proof*. The
  code is the ephemeral, user-facing artifact (refreshed every `period`
  seconds; a presence prompt per code would be intolerable friction).
  Generating a code does decrypt the seed transiently inside
  `pangolin-store` / `pangolin-totp`, but the seed bytes never cross the
  FFI — only the digit string does — and the transient plaintext
  (`AccountIdentity` is `ZeroizeOnDrop`; the intermediate copy is
  `Zeroizing`) wipes before returning.
- **Revealing the raw seed** (`reveal_totp_secret`, 1.4) stays
  **reveal-class** (§5.4): the seed / QR / `otpauth://` URI export is
  presence-gated. That path is unchanged by 1.7.

## V2 `AccountIdentity` body + the V0/V1 → V2 read path

The configurable params need durable storage, so the `AccountIdentity`
CBOR body extends to a new **`payload_version` V2** (1.6's §18.7
machinery absorbs exactly this kind of extension):

- **Shape:** V2 keeps the V1 8-key arity but replaces the single
  `totp_secret` byte-string key with a nested `totp` map
  `{ algorithm: int(0=SHA1,1=SHA256,2=SHA512), digits: int, period: int,
  secret: bytes }` in the same alphabetical slot (`tags < totp < urls`).
  `payload_version = 2`.
- **Discrimination:** V1 and V2 are *both* arity-8, so the
  `payload_version` integer discriminates — and crucially it is read
  *before* the `totp[_secret]` key in canonical key order
  (`payload_version` is 4th, `totp`/`totp_secret` is 6th). So an older
  Pangolin reading a V2 body sees `payload_version = 2 >
  REVISION_SCHEMA_VERSION_MAX (= 1 on that build)` and surfaces the
  §18.7 "requires upgrade" account status *before* it ever reaches the
  unknown `totp` key — per-account, not whole-vault. This build's
  `REVISION_SCHEMA_VERSION_MAX` is now `2`, so V2 is a known version and
  the new "future" is V3.
- **V0/V1 → V2 read:** a V0 (6-key) or V1 (8-key) body's `totp_secret`
  bytes hydrate to `{ secret_bytes: <those bytes>, params:
  TotpParams::default() }` (SHA-1 / 6 / 30) — so an old vault's
  opaque-bytes TOTP "just works" as a default-params SHA-1/6/30 TOTP.
- **Writes:** `account_add` / `account_update` always emit V2 (the
  encoder writes the nested `totp` map). The AAD shape
  (`vault_id || account_id || parent_revision_id || schema_version`) does
  **not** change — `payload_version` is inside the authenticated
  plaintext, not in the AAD. The on-disk `schema_version` byte width
  (`u8`) is unchanged.

## CLI base32 fix (Q5)

No new CLI subcommand (deferred to CLI-V1). But 1.7 closes the latent
gap where `apps/cli`'s `--totp-stdin` / `prompt_totp_secret` stored the
typed string's *raw bytes* verbatim even though the prompt said "base32"
— a PoC CLI TOTP entry was garbage. The input is now fed through
`pangolin_totp::parse_totp_secret` (a bare base32 secret *or* a full
`otpauth://` URI); on success the decoded seed bytes are stored, on a
parse error the subcommand aborts cleanly with a non-zero exit and no
partial write. (The PoC CLI's `V0` `AccountSnapshot` write path stores
only the seed bytes; the configurable-param `V2` write path is reached
through the FFI `account_add` / `account_update` whose `totp_params`
field carries the parsed params.)
