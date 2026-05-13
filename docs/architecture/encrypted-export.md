<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Encrypted export (MVP-1 issue 1.10)

A **Pangolin-native, self-contained encrypted vault archive** — a
portable, AEAD-sealed snapshot of a vault you can move to a new device
or keep off-site as a backup. Plus the spec-mandated, double-confirmed,
delayed, loudly-warned **plaintext export** branch, and a `restore`
path that writes a brand-new `.pvf` from a decoded archive.

This is **not** a `.kdbx` / CSV / 1Password / Bitwarden writer (1.9
explicitly deferred format-export; interop-export to other managers is a
later issue). It is *Pangolin's* export — two flavours: encrypted
(default) and the guarded cleartext branch.

The format/codec/decoder lives in `pangolin-store::export`; the
presence-gated entry points (`Vault::export_encrypted`,
`Vault::export_plaintext`, `Vault::restore_to_new_vault`) live in
`pangolin-store::vault`; the FFI wrappers (`vault_export_encrypted`,
`vault_export_plaintext`, `vault_restore_from_archive`) live in
`pangolin-ffi::session`; the CLI surface is `pangolin-cli vault export`
and `pangolin-cli vault restore`.

## File extensions

- **`.pvea`** — Pangolin Vault Encrypted Archive (parallels `.pvf`).
- **`.pvtxt`** — the cleartext `--plaintext` dump (unmistakably
  different name).

The CLI suggests/documents these but does not enforce the extension on
the user-supplied output path.

## Archive byte layout (encrypted form)

```
[ magic: b"PANGOLIN-VEA"          12 bytes, fixed ]
[ format_version: u8              = 1             ]
[ kdf_algo_id: u8                 = 1 (Argon2id)  ]
[ kdf_memory_kib: u32 (big-endian)               ]
[ kdf_time_cost:  u32 (big-endian)               ]
[ kdf_parallelism: u32 (big-endian)              ]
[ salt:  16 bytes  (KdfSalt::random)             ]
[ nonce: 24 bytes  (Nonce::random — XChaCha20)   ]
[ ct_len: u64 (big-endian)                       ]
[ ciphertext: ct_len bytes ]   ; XChaCha20-Poly1305(payload, AAD = the fixed-size header above)
```

The **entire fixed-size header** (everything before the ciphertext, as
its canonical byte form) is the AEAD **AAD** — so any tamper with the
magic / version / KDF params / salt / nonce / `ct_len` makes the open
fail authentication (it is not a mis-parse, it is an auth failure).
`ct_len` is also length-checked against the remaining file bytes with a
generous ceiling (> 256 MiB → typed `export_too_large`).

## Two-axis versioning

- **`format_version: u8`** (container) — bumped on any header-layout
  change. An unknown value → typed `export_format` error (the §18.7
  pattern; never a silent partial read).
- **`schema_version: u16`** (the CBOR payload shape, inside the
  ciphertext) — independent of the container version. An unknown value
  → typed `export_format` error.

(Same two-axis approach as the vault's `format_version` vs the CBOR-body
`schema_version`. See `docs/architecture/schema-versioning.md`.)

## Credential model — the archive key (D3)

The encrypted archive is sealed with XChaCha20-Poly1305 under a 256-bit
key derived (Argon2id, the same `pangolin_crypto::kdf::KdfParams::
RECOMMENDED` the vault file uses — ≈256 MiB / t=3 / p=1) over

- a **fresh, user-supplied export passphrase** — **independent of the
  vault master password**, and
- a random 16-byte salt stored in the archive's plaintext header (bound
  as the AEAD AAD).

**Key separation:** a leaked archive passphrase never compromises the
vault, and a leaked vault password never compromises archives — you can
escrow/hand off the archive with a distinct secret. (Deriving from the
VDK would couple the archive to the vault password — rejected. A raw key
the user must store — operationally unacceptable for a consumer password
manager — rejected.) This is the standard pattern (KeePass exports,
`age`).

The export prompts for the passphrase twice (confirm-match) on **stderr**
and runs it through 1.8's zxcvbn `strength()`: a weak passphrase
surfaces a **warning** on stderr (it is the only thing protecting a
portable copy of every secret), but it is **not a hard gate**. The
plaintext-export branch has no passphrase, so no KDF and no zxcvbn check.

The only randomness used (salt + nonce) is
`pangolin_crypto::rng::fill_random` (via `KdfSalt::random()` /
`Nonce::random()`) — single-CSPRNG discipline, matching the vault.

## Snapshot scope (D1) — what's inside the ciphertext

The encrypted-archive payload is a **full move-to-new-device backup**, a
CBOR document (`ciborium-ll` — the same codec family the `AccountIdentity`
wire body uses; nothing pulls serde into `pangolin-crypto`):

- `schema_version`, `exported_at` (unix seconds), `source_device_id`
  (32 bytes), `vault_id` (32 bytes) — the **D6 provenance fingerprint**,
  *inside* the ciphertext (a finder can't tell which device/vault it
  came from).
- The vault `meta` settings carried over: the session idle-timeout.
- Every (non-tombstoned) account: the full V1 identity — display name,
  tags, urls, usernames, notes, TOTP secret + params — plus the
  **complete password history** (the historical password *bytes*, with
  their change timestamps and originating-device ids), head first.
- The device trust list (device ids + labels + added-at timestamps).

With `--accounts <comma-list-of-64-hex-ids>` the export is narrowed to
the selected accounts — *same archive format either way*, the flag just
narrows what's included (useful for sharing a handful of logins).

The serialized snapshot only ever lives transiently in `Zeroizing`
inside `export_encrypted`, sealed before anything touches disk; the
on-disk `.pvea` is ciphertext + the non-secret header only — test
`encrypted_export_then_restore_round_trip_and_no_plaintext_on_disk`
scans the archive bytes for the plaintext markers and asserts zero hits.

## Reveal-class gating (D5)

Both `vault_export_encrypted` and `vault_export_plaintext` are
**reveal-class** — they route through 1.4's session-freshness +
presence-freshness + touch-session machinery, exactly like the existing
`reveal_*` ops and `Vault::export_payload`. Session spec §5.4 lists
"export vault" as a high-risk action requiring explicit presence even
mid-session, and bulk-materialising every sealed secret into a portable
artifact is exactly the risk §5.4 is about. `vault_restore_from_archive`
operates on a file path + an archive passphrase (not an unlocked vault),
so it does not take a session/presence proof — but it validates the
archive cryptographically.

## The plaintext-export branch (`--plaintext`) — D4

Master plan §4 row 1.10: "Plaintext export guarded behind
double-confirmation + 30 s delay + warning copy." The CLI/UI owns these
guards; the FFI/engine just requires a structurally-valid single-use
`PlaintextExportConfirmation { schema_version, token }` token (a missing
or empty token → typed `export_not_confirmed`). The CLI flow:

1. Print the loud warning copy to stderr.
2. Require the user to type the exact confirmation phrase `i understand`.
3. Sleep 30 seconds with a visible countdown on stderr (a literal
   `std::thread::sleep` in the CLI binary — a test-only hidden
   `--no-delay` flag skips it so CI doesn't wait). Ctrl-C aborts.
4. A final `[y/N]`.
5. Mint a fresh single-use token (`fill_random(32)`), call
   `vault_export_plaintext`, write the `.pvtxt` file.

The `.pvtxt` file is a JSON-like document with a prominent in-file
banner (`*** WARNING: THIS FILE CONTAINS YOUR VAULT PASSWORDS IN
CLEARTEXT ***`) and a `"WARNING"` field — and it does contain every
password / note / TOTP seed in cleartext, by design (no KDF, no AEAD).
That is the point, and why it is dangerous.

## The restore path (D2) — decode + create-a-fresh-`.pvf`

`pangolin_store::decode_archive(bytes, passphrase)` parses the header
(strict bounds; truncation, magic mismatch, unknown version/algo,
hostile Argon2 params all → typed `export_format` *before* any
allocation or Argon2 derivation), derives the archive key, AEAD-opens
with the header as AAD, and CBOR-decodes the snapshot. A **wrong
passphrase and a tampered archive both surface as one typed error**
(`export_credentials`) — no oracle distinguishing them; the
intentionally-slow Argon2id derive runs before the failure is known so
timing is dominated by the KDF.

`Vault::restore_to_new_vault(dest, snapshot, new_master_password)`
provisions a **brand-new `.pvf`** at `dest` (`O_CREAT|O_EXCL` — never
clobbers), unlocks it, and reconstructs each archived account through the
normal validated `account_add` path (the head identity) with the
password history replayed oldest→newest via `account_update` (so the
restored vault has the same head password *and* the same number of
historical password values, with their plaintext bytes). The decoded
snapshot is `ZeroizeOnDrop` — it is wiped when the call returns.

**1.10 restore-fidelity note.** The restored account gets a *fresh*
random `account_id` (not the source vault's), `now` timestamps on the
history entries (not the originals), and the new vault's device as the
originating device. The archived **device trust list** is **not**
re-written into the new vault: the restored `.pvf` is its own fresh
device (registered on its first unlock), and grafting the source's
device rows would (a) make this build's device-key-load path elect the
wrong device row (it picks the oldest `added_at`) and fail, and (b)
graft foreign device identities with no key material. The encrypted
archive payload still carries the source ids / timestamps /
originating-devices / device list (D1/D6) for any future
lineage-preserving restore. **1.10 does NOT merge an archive into an
*existing* vault** — that is deferred to MVP-2 (Revision Log v1 with
signature verification — the proper reconciliation + cryptographic-
provenance substrate; pre-MVP-2 there is no signed Revision Log, so
merging would graft foreign revisions in on "it decrypted under the
passphrase" alone, with no provenance check — exactly what the threat
model wants signature-gated), with MVP-3 (recovery + guardians) as the
fallback home.

## Adversarial hardening summary

- **Header parser** — strict bounds (truncation, lying `ct_len`, magic
  mismatch, unknown `format_version` / `kdf_algo_id`); Argon2 memory
  clamped ≤ 1 GiB, time-cost ≤ 64, parallelism ≤ 64 (and ≥ the
  crypto-crate floor) *before* any derivation — a hostile archive can't
  OOM us or make Argon2 run for minutes; `ct_len` ceiling ≤ 256 MiB.
  No panics on any malformed input — all typed `StoreError::Validation`
  variants. `forbid(unsafe_code)` on every crate but `pangolin-ffi`, so
  no UB even on a hostile file.
- **AEAD-AAD binding** — the whole header is the AAD; a one-byte flip in
  the magic / version / KDF params / salt / nonce / `ct_len` fails the
  open (not a mis-parse).
- **No oracle** — wrong passphrase and tampered archive both → one
  `export_credentials` error; timing dominated by the slow Argon2id
  derive.
- **Secret discipline** — the CBOR snapshot only in `Zeroizing`, sealed
  before any disk write; the encrypted archive is ciphertext + a
  non-secret header; the restore path zeroizes the decoded snapshot
  after writing the new vault; export/archive passphrases zeroized after
  the KDF; no secret in any `Debug` impl, error message (category labels
  + counts only), or stdout.
- **File permissions** — output files created umask-respecting +
  `chmod 0o600` on Unix; never clobbered (`create_new(true)`); a partial
  file is removed on a write error. The archive bytes are written to a
  user-named file path, never stdout (PowerShell stdout/UTF-8
  env-quirk).
- **The plaintext path** is the one path writing cleartext secrets to
  disk — opt-in behind presence + the §16 double-confirmation + 30 s
  delay + warning copy + the in-file banner + a structurally-valid
  single-use token.

## Out of scope (later issues)

- Writing `.kdbx` / CSV / 1Password / Bitwarden / LastPass / Chrome
  export.
- Cloud / remote backup (auto-upload).
- Merging an archive into an *existing* vault — MVP-2 (fallback MVP-3).
- Lineage-preserving restore (original ids/timestamps/devices) —
  follow-up alongside MVP-2's signed Revision Log.
- The social-recovery / guardians flow — MVP-3.
- GUI export wizard — MVP-3+.
- Hardware-bound export keys — MVP-3/4, if ever.
