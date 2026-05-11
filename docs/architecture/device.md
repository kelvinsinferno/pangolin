# Device identity + local trust list (MVP-1 issue 1.5)

> Implements master plan §4 row `1.5` / §17 component matrix
> ("Device identity + trust list — core — 1.5 — Whitepaper §F") and
> Whitepaper §5 / §F (Authority & Access Hierarchy; the Key & Authority
> Model diagram). Frozen plan: `docs/issue-plans/1.5.md`.

## What landed

Every `.pvf` now knows which device it runs on. On the **first
successful unlock** on a new vault file the engine registers a device
entry (`Vault::unlock`, after the VDK is unwrapped):

1. generates a fresh Ed25519 [`DeviceKey`] (`pangolin-crypto`);
2. derives a stable `device_id` from that key's verifying-key bytes —
   exactly what `revision.rs`'s `DeviceId` doc-comment always promised
   ("the verifying-key bytes of the device's signing keypair");
3. inserts a `devices` row (`device_id`, a generated placeholder
   `label` the user can rename later, `registered_at = now`,
   `revoked_at = NULL`, `capabilities = Full`, `last_sync_at = NULL`,
   `public_key`, `schema_version = 1`);
4. seals the device key's secret seed **AEAD under the VDK**
   (XChaCha20-Poly1305; AAD = `pgdvk0\0\0 || vault_id || device_id`,
   anti-transplant) and stores the ciphertext + nonce in the single-row
   `device_key` table.

All in one SQLite transaction. **Subsequent unlocks re-load that
device** — they decrypt the stored seed, reconstruct the `DeviceKey`,
re-derive the same `device_id`, and set the handle's `device_id` to it.
They do **not** register a second device.

The per-handle random `device_id` that `Vault::create` / `Vault::open`
mint is now a **pre-unlock placeholder only** — overwritten by the
first `unlock`'s register/load step. No revision can be written before
`unlock` (`account_add` / `account_update` call `require_active()`), so
the placeholder is never stamped onto a revision. `Vault::open` on a
vault that has already had a device registered adopts the persisted id
straight away, so `device_current` works on a locked-but-previously-
registered vault. (Before 1.5 the P2 `devices` table was a dead stub —
`Vault::create`/`open` minted a per-handle random `device_id` that was
never persisted, and nothing read or wrote the table. 1.5 makes it
real.)

## The trust list

The trust list **is** the `devices` table.

- **Add-only.** A device registers itself on first unlock; there is
  **no** MVP-1 path to remove / revoke a device. Device revocation is
  tied to authority rotation (re-wrap the VDK under a new authority,
  atomically revoke old devices) — that is social recovery, MVP-3. The
  `revoked_at` column the P2 stub already had is kept as the MVP-2/3
  hook; MVP-1 never writes it; `device_list` returns all rows.
- **Gates nothing destructive.** Whether a revision's
  `originating_device` is "in the trust list" is *informational* in
  MVP-1 — the enforcement point (only enrolled devices may publish) is
  the MVP-2 on-chain authority registry. 1.5 introduces **no**
  trust-check that rejects anything (that would risk bricking older-
  build `.pvf`s whose revisions carry orphan random
  `originating_device`s).
- **`originating_device`.** Going forward (post-1.5), every new
  revision (`account_add` / `account_update` / the V0 shims) stamps the
  open handle's real `device_id` — a real `devices`-row reference,
  verifying-key-derived. Pre-1.5 revisions keep their throwaway-random
  value (accepted as-is — no backfill, no rejection).

## The `DeviceKey` — generated + stored, signs nothing in MVP-1

The per-device Ed25519 keypair is the MVP-2 on-chain revision signer +
gas wallet (D-006 — same key signs revisions and pays gas; MVP-2 issue
`2.1` Signed-revision format / `3.2` Device wallet generation). MVP-1
has **zero chain code**, so 1.5 generates + persists the keypair
(encrypted in the `.pvf`) as the hook; it wires **no signing**.

It is a long-lived secret. Unlike `pending_merges.device_secret` (an
*ephemeral* merge-signing seed the P9 plan documents as stored
un-AEAD-sealed by a bounded-marginal-exposure argument), the device key
gets the AEAD layer the `no_plaintext_on_disk` proptest enforces for
every other secret — the seed is **only** ever on disk as XChaCha20-
Poly1305 ciphertext under the VDK. The serialisation (seed → BLOB →
seed) lives **entirely in `pangolin-store`**: `pangolin-crypto` gains no
serde path and no new dep (HIGH-1 preserved); the seed crosses the
`pangolin-crypto` → `pangolin-store` boundary only as a
`Zeroizing<[u8; 32]>` headed straight into the seal (via
`DeviceKey::secret_seed_bytes`) / out of the open (via
`DeviceKey::from_seed`).

The in-memory `DeviceKey` lives in `ActiveState` alongside the
decrypted cache + the `:memory:` FTS5 index, so every session-teardown
path (`lock()` / idle-or-absolute expiry / `Drop`) drops it. `DeviceKey`
is `assert_not_impl_any!(Clone, Copy)`, zeroizes on drop, and redacts
`Debug` (P1 invariants).

## `last_sync_at` — dormant

The `last_sync_at` column exists on the device row; it is **always
`NULL` / `None` in MVP-1**. MVP-2's chain-sync code populates it (the
last time this device published-or-pulled through the contract) — the
same doctrine the schema already uses for the `chain_anchor_*` columns
on revisions. A host UI renders "never synced" / hides the field.

## Capability flags

`DeviceCapabilities` is an enum with one variant in MVP-1 — `Full` (can
do everything) — stored as a small integer column (`capabilities
INTEGER NOT NULL DEFAULT 0`, `0 = Full`) so MVP-2/3 can add variants
(read-only seats, browser-extension-as-a-limited-device, …) without a
schema change. An unknown stored value coerces to `Full` (forward-
compat: a corrupt-but-readable column does not brick the vault).

## Schema / migration

- `devices` (P2 stub: `device_id, label, added_at, revoked_at`) gains
  four additive columns: `capabilities INTEGER NOT NULL DEFAULT 0`,
  `last_sync_at INTEGER` (nullable, dormant), `public_key BLOB`
  (nullable for legacy rows; written for every row 1.5 creates),
  `schema_version INTEGER NOT NULL DEFAULT 1`. The SQL column `added_at`
  is reused as the `DeviceIdentity` view's `registered_at` (no rename —
  needless churn). Migrated via `schema::migrate_devices_columns`
  (idempotent `PRAGMA table_info` check before each `ALTER TABLE ADD
  COLUMN`).
- New single-row `device_key` table: `id INTEGER PRIMARY KEY CHECK (id =
  0)`, `enc_seed BLOB NOT NULL`, `enc_nonce BLOB NOT NULL`,
  `schema_version INTEGER NOT NULL`. In `SCHEMA_DDL` (`CREATE TABLE IF
  NOT EXISTS`) + a belt-and-braces `schema::migrate_device_key_table`
  for legacy files.
- **No `format_version` bump** — additive tables/columns, the same
  doctrine the four existing migrations follow. Older-build `.pvf`s pick
  up the new columns (with defaults) + the new table on next open, and
  get a device row registered on the next unlock.
- §18.7 schema-version slots: `devices.schema_version = 1` and
  `device_key.schema_version = 1`; a future device-key blob version is
  rejected (reject-unknown-future-versions discipline); the policy text
  itself is 1.6's job.

## Public surface

| Layer | Surface |
|---|---|
| `pangolin-store` (`device` module, re-exported via `lib.rs`) | `pub struct DeviceIdentity { device_id, label, registered_at, last_sync_at: Option<i64>, capabilities: DeviceCapabilities, public_key: Option<VerifyingKey>, is_current: bool }`; `pub enum DeviceCapabilities { Full }`; `pub const DEVICE_IDENTITY_SCHEMA_VERSION: u16 = 1`; `pub fn validate_label`, `device_id_from_key`, `register_device`, `load_device_key_with_id`, `read_registered_device_id`, `list_devices`, `read_device`, `set_device_label` |
| `pangolin-store` (`Vault`) | `device_current(&self) -> Result<DeviceIdentity>`; `device_list(&self) -> Result<Vec<DeviceIdentity>>`; `device_set_label(&mut self, id: DeviceId, label: &str) -> Result<()>` (requires an active session — Q5: no presence proof) |
| `pangolin-core` | re-exports `DeviceIdentity`, `DeviceCapabilities`, `DEVICE_IDENTITY_SCHEMA_VERSION` at the crate root + under `pangolin_core::device::*` (no physical move — 1.4 Q1 posture) |
| `pangolin-ffi` (`device` module) | `#[derive(uniffi::Record)] DeviceInfo { schema_version, id: DeviceId, label, registered_at: UnixTimestamp, last_sync_at: Option<UnixTimestamp>, capabilities: DeviceCapabilities, is_current, public_key: Vec<u8> }`; `#[derive(uniffi::Enum)] DeviceCapabilities { Full }`; `device_list` / `device_current` / `device_set_label` `#[uniffi::export]` fns — additive 1.1-surface amendment |
| storage | `devices` gains `capabilities` / `last_sync_at` / `public_key` / `schema_version`; new `device_key` table — additive migration, no `format_version` bump |

The `account_*` / `session_*` / `reveal_*` FFI signatures are untouched;
the 1.3 `:memory:` FTS5 search-index lifecycle and the 1.4 session state
machine are untouched (1.5 only inserts the register/load step into
`Vault::unlock`, after the VDK unwrap, before the `Active` transition).

## References

- `docs/issue-plans/1.5.md` — the frozen plan (decisions Q1–Q7).
- `docs/issue-plans/P1.md` — the `DeviceKey` key-hierarchy type.
- `docs/issue-plans/P2.md` — the original `devices` stub.
- `docs/issue-plans/1.4.md` — the `meta.session_idle_secs` migration
  pattern this issue's migrations follow.
- Whitepaper §5 / §F + the Key & Authority Model diagram — the
  per-device keypair, the device's role in the authority hierarchy, the
  trust list, capability flags, `last_sync`, the on-chain authority
  registry (MVP-2 — for MVP-1 the trust list is purely local).
- `docs/architecture/ffi-surface.md` — the `DeviceInfo` /
  `DeviceCapabilities` records + the `device_*` entries.
