<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Schema-Versioning Policy (master plan §18.7)

Locked by MVP-1 issue 1.6. This is the durable artifact every later
issue follows when it adds or evolves a persisted record.

## The rule

1. **Every persisted record carries a schema-version field.** A file
   header, a CBOR-body discriminator, a SQL column, a meta value, or an
   FFI wire field — whichever is the natural home.
2. **Read discipline — read-old, reject-unknown-future.** On read:
   - version `<=` this build's `MAX_KNOWN` → parse it, migrating an
     older shape to the current one if needed (the V0→V1 hydrate-on-read
     in `blob.rs` is the worked example);
   - version `>` `MAX_KNOWN` → **reject with a clean typed error.** No
     crash, no panic, and — critically — **never silently skip the
     record**: a record from the future is real state, so showing the
     last-understood state with no signal is a correctness bug.
3. **Granularity ladder — the reject's blast radius matches where the
   field lives:**
   - **file `format_version`** (P2, `meta` table) → the *whole vault*
     refuses to open (`StoreError::UnsupportedFormatVersion`). A newer
     build wrote a file-format change this build cannot parse safely.
   - **revision `schema_version` row column / `payload_version` CBOR
     discriminator** → *that account* surfaces a "requires upgrade"
     status (`StoreError::UnsupportedRevisionSchemaVersion`).
     Metadata-only reads keep working where possible
     (`account_history`, `account_status`, `is_forked`); reveals,
     edits, and head-decryption on that account are blocked with the
     typed error. The rest of the vault is fully usable. The unlock
     itself succeeds.
   - **`fts_schema_version`** (1.3 `meta` value) → the `:memory:` FTS5
     index is `:memory:` and rebuilt every unlock, so a mismatch is
     handled at rebuild time; never reaches disk.
   - **`devices.schema_version` / `device_key.schema_version`** (1.5) →
     the device-identity / device-key surface; a future value rejects
     at load time for that record (the trust list / key load fails
     cleanly).
   - **`pending_merges.schema_version`** (P9) → the resolve-stash row;
     a future value rejects at `take_pending_merge` (`Corrupted`-class
     if it's structurally wrong; otherwise the resolve flow fails
     cleanly).
   - **`meta.session_idle_secs` validator** (1.4) → the session-idle
     choice; an unknown value is rejected by
     `SessionDuration::try_from_meta_secs` (the cap engine refuses to
     run on a config it doesn't recognise).
   - **FFI `schema_version: u16` fields** — every record that crosses
     the FFI **and** carries user data exposes a `u16` slot (widened
     from the on-disk `u8` where applicable, losslessly). Changing an
     FFI signature requires a version bump + bindings regeneration —
     the FFI surface is frozen (issue 1.1).
4. **Major vs minor bump.** A *major* (breaking) bump is one where an
   older client cannot parse the new shape (a new required field, a
   reordered/renamed key, a structural change). A *minor* (additive)
   bump is one where an older client can ignore the addition (a new
   table, a new nullable column, a new optional field). MVP-1's
   additive store changes (`sync_state`, `dirty_accounts`,
   `pending_merges`, `session_idle_secs`, the 1.5 `devices` columns,
   the 1.6 `superseded_by` column) are *minor* — no `format_version`
   bump. A major bump requires the migration path below.
5. **Migration path for a major bump.** Local store: ship the new
   `MAX_KNOWN`, keep a `decode_vN_…` function that hydrates the old
   shape on read (dual-read), and write the new shape going forward.
   On chain (MVP-2): deploy the v2 contract, dual-read both event
   schemas for a transition period, then cut over.

## The versioned-surface table (as of issue 1.6)

| Surface | Where | Field | `MAX_KNOWN` (this build) | Error on a future value | Blast radius |
|---|---|---|---|---|---|
| Vault file format | `meta.format_version` (P2) | `u8` (stored as INTEGER) | `crate::meta::FORMAT_VERSION` | `StoreError::UnsupportedFormatVersion` | whole vault unopenable |
| Revision row schema | `revisions.schema_version` (P2) | `u8` (stored as INTEGER; also a byte in the AEAD AAD) | `REVISION_SCHEMA_VERSION_MAX` (= 1) | `StoreError::UnsupportedRevisionSchemaVersion` | that account "requires upgrade" |
| Revision payload discriminator | `payload_version` in the V1 CBOR body (1.2) | `u8` (V0 = 0 = arity-6 map; V1 = 1 = arity-8 map) | `REVISION_SCHEMA_VERSION_MAX` (= 1) | `StoreError::UnsupportedRevisionSchemaVersion` (a future `payload_version`, or a map arity > 8) | that account "requires upgrade" |
| FTS5 index schema | `meta` value `fts_schema_version` (1.3) | `u32` | `FTS_SCHEMA_VERSION` (= 1) | rebuilt every unlock; mismatch handled at rebuild | none on disk |
| Device-identity record | `devices.schema_version` (1.5) | `u8` (stored as INTEGER; default 1) | `DEVICE_IDENTITY_SCHEMA_VERSION` (= 1) | clean reject at device load | that device record |
| Device-key record | `device_key.schema_version` (1.5) | `u8` (stored as INTEGER) | `DEVICE_IDENTITY_SCHEMA_VERSION` (= 1) | clean reject at key load | that key record |
| Resolve-stash record | `pending_merges.schema_version` (P9) | `u8` (stored as INTEGER) | inherited from the revision being resolved | `Corrupted` / clean resolve-flow failure | that stash row |
| Session-idle choice | `meta.session_idle_secs` (1.4) | a sentinel integer (`{300,900,1800,3600,14400}` s, or `-1` for until-device-lock, or `NULL` = 15-min default) | the recognised set | `SessionDuration::try_from_meta_secs` rejects | session-config refuses to run |
| FFI user-data records | `schema_version: u16` slot on every FFI `Record` carrying user data (1.1) | `u16` | `ACCOUNT_IDENTITY_SCHEMA_VERSION` (= 1) etc. | bindings mismatch; signature change ⇒ version bump + regen | FFI consumer |

## The §18.7-vs-implementation note (Q3)

Master plan §18.7 says an old client receiving a newer `schema_version`
it can't parse should "log a warning and **skip applying that revision**
until updated." That wording is the **MVP-2 chain-replay framing** — in
chain replay, a revision is one event in an ordered stream, and a
replica can defer applying an event it doesn't understand. For the
**local MVP-1 store** that clause is *unsound*: a head revision with a
future version *is* the account's current state, so "skip the revision"
would show stale data with no signal. The 1.6 implementation therefore
reads §18.7's "skip" clause as "skip *for the purpose of chain-replay
ordering*", and the local-store behaviour is the granularity ladder
above — surface "requires upgrade" on that account, keep the rest of the
vault working. §18.7 should be annotated to mark the "skip" clause
chain-context-only.

## Worked example — adding a new credential field (the §18.7 acceptance)

Say MVP-1.x adds a `recovery_email` field to the credential record:

1. Add `recovery_email` to the V1→V2 CBOR shape (a new key, arity 9).
2. Bump the encoder's `PAYLOAD_VERSION` to 2 and
   `REVISION_SCHEMA_VERSION_MAX` to 2.
3. Add `decode_v2_live_inline` that decodes the arity-9 V2 map; keep
   `decode_v1_live_inline` (hydrating V1→V2 on read by defaulting
   `recovery_email = ""`). This is the dual-read transition.
4. New revisions are written as V2. An *old* client reading a V2 blob
   hits `payload_version = 2 > MAX_KNOWN = 1` → it returns
   `UnsupportedRevisionSchemaVersion` for that account, surfaces
   "requires upgrade", and the user updates Pangolin.
5. The file-level `format_version` does **not** change (this is an
   additive credential-field change, not a file-format change).
