# Account-identity validation limits (MVP-1 issue 1.2)

> **Status:** Locked 2026-05-08 by MVP-1 issue 1.2
> (`docs/issue-plans/1.2.md` §E). Surfaces as
> `pangolin_store::account::limits` constants. Future tuning is
> additive only (raising caps or relaxing rules; **never tightening**
> caps so existing valid drafts remain valid).

| Constant | Value | Applies to | Validation |
|----------|------:|------------|------------|
| `DISPLAY_NAME_MAX_CHARS` | 256 | `AccountDraft.display_name`, `AccountPatch.display_name` | NFC-normalised → trimmed → non-empty → length ≤ cap; no control chars (except `\t`) |
| `TAGS_MAX_COUNT` | 32 | `AccountDraft.tags`, `AccountPatch.tags` | NFC-normalised → trimmed → lowercased → deduplicated; preserved order |
| `TAG_MAX_CHARS` | 64 | each tag | NFC-normalised → trimmed → non-empty → length ≤ cap; no control chars |
| `USERNAMES_MAX_COUNT` | 16 | `AccountDraft.usernames`, `AccountPatch.usernames` | ≥ 1 entry required at create-time |
| `USERNAME_MAX_CHARS` | 320 | each username | trim → NFC-normalised → length ≤ cap (RFC-5321 email cap); no control chars |
| `URLS_MAX_COUNT` | 32 | `AccountDraft.urls`, `AccountPatch.urls` | parse via `url::Url::parse`; canonical re-serialised form stored |
| `URL_MAX_CHARS` | 2 048 | each URL | per-scheme syntax checked by `url` crate (any scheme accepted per Q3) |
| `NOTES_MAX_CHARS` | 65 536 | `AccountDraft.notes`, `AccountPatch.notes` | any UTF-8 |
| `PASSWORD_MAX_BYTES` | 4 096 | `AccountDraft.current_password`, `AccountPatch.current_password` | non-empty; arbitrary bytes |
| `TOTP_SECRET_MAX_BYTES` | 256 | `AccountDraft.totp_secret`, `AccountPatch.totp_secret` (when `Some`) | byte-length only; RFC-6238 validation defers to MVP-1 issue 1.7 |

## Error mapping

Every validation failure surfaces a typed error with a stable `kind`
label that maps 1:1 from `pangolin_core::Error::Validation { kind }` to
`pangolin_ffi::FfiError::Validation { kind }`:

| Failure | `kind` |
|---------|--------|
| display_name empty / over-long / control chars | `display_name` |
| tag invalid (empty, over-long, control chars) | `tags` |
| too many tags | `tags` |
| username invalid | `usernames` |
| no usernames supplied | `usernames` |
| too many usernames | `usernames` |
| URL parse failure / over-long | `url` |
| too many URLs | `url` |
| notes over-long | `notes` |
| password empty / over-long | `password` |
| TOTP secret over-long | `totp_secret` |

## Unicode NFC normalisation (audit H-1)

`display_name`, every `tag`, and every `username` are NFC-normalised
on validation so visually-identical inputs compare equal regardless of
the user's IME / paste source. For example:

- `"Café"` (precomposed `U+00E9`) and `"Cafe\u{0301}"` (`e` + combining
  acute) produce identical stored bytes.
- For tags, NFC + lowercase + dedup eliminates "look-alike duplicate"
  entries that differ only in precomposed vs. decomposed form.

Pipeline order:

| Field | Order |
|-------|-------|
| `display_name` | NFC → trim → empty-check → length ≤ cap → control-char check |
| each tag | NFC → trim → empty-check → length ≤ cap → control-char check → lowercase → dedup |
| each username | trim → empty-check → NFC → length ≤ cap → control-char check |

Notes and URLs are intentionally NOT NFC-normalised — notes are
free-form prose that may legitimately preserve a user's original byte
sequence, and URL canonicalisation is delegated to the `url::Url`
parser (which performs its own host / path canonicalisation).

## Forward-compatibility

Per Q4 of the 1.2 plan-gate: `schema_version` is **accept-and-record**
in 1.2. The validator does NOT reject drafts that supply a future
`schema_version`. The reject policy lands in MVP-1 issue 1.6 alongside
the `payload_version`-on-disk forward-compat semantics.
