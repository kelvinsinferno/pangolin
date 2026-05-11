# Account search — the `:memory:` FTS5 index (MVP-1 issue 1.3)

Reference doc for the search subsystem in `pangolin-store`. Source of
truth: `crates/pangolin-store/src/search.rs` + `Vault::account_search`,
`Vault::unlock`, `account_add` / `account_update` / `delete_account`
(and the V0 `add_account` / `update_account` / `delete_account` shims)
in `crates/pangolin-store/src/vault.rs`. Plan: `docs/issue-plans/1.3.md`.

## What it is

`Vault::account_search(query) -> Vec<AccountIdentitySummary>` is backed
by a SQLite **FTS5** virtual table that lives in a **`:memory:`
connection** held by `ActiveState` — i.e. it exists only while the
vault is unlocked, only in RAM, and is rebuilt from the decrypted
account blobs on every `unlock`. Nothing extra is written to the `.pvf`
file: the persisted blob payload stays AEAD-sealed, so the
`no_plaintext_on_disk` proptest is unaffected (Q2/Q5 of the plan).

## The whitelist (structural, not policy)

The FTS5 table has exactly three columns:

| Column | Source | Notes |
|---|---|---|
| `display_name` | `AccountIdentity.display_name` | NFC-normalised by 1.2's validator; lowercased here for the index |
| `tags` | space-joined `AccountIdentity.tags` | already lowercased + deduped by 1.2's validator |
| `hostnames` | space-joined `url::Url::parse(u).host_str()` of each `AccountIdentity.urls` entry | for schemes with no host (`mailto:`, `app://settings`, …) the raw serialised URL string is used as the fallback token so non-http URLs stay searchable; lowercased |

The schema has **no columns** for `usernames`, full URLs (only the
host), `notes`, `password_history`, or `totp_secret`. The whitelist is
*structural* — those fields are simply never written to the index, so a
future refactor cannot start indexing them without an obvious schema
change. (Master plan §4 row 1.3: "FTS5 on non-secret fields only —
name, tags, hostnames; never on usernames/passwords." Notes are
recovery-class per spec §5.4; usernames are credential-class.) The test
`search::tests::fts_schema_has_only_whitelisted_columns` asserts the
column list is exactly `[display_name, tags, hostnames]`; the e2e test
`search_never_matches_username_password_notes` asserts a known username
/ password / notes substring returns zero hits.

## Schema (the `:memory:` connection)

```sql
CREATE TABLE meta_fts (
    id                 INTEGER PRIMARY KEY CHECK (id = 0),
    fts_schema_version INTEGER NOT NULL          -- = 1 (the §18.7 hook for 1.6)
);
CREATE TABLE accounts (
    rowid      INTEGER PRIMARY KEY,              -- surrogate key for FTS5
    account_id BLOB    NOT NULL UNIQUE,          -- the real 32-byte id
    updated_at INTEGER NOT NULL                  -- last_modified_at, for the recency tiebreaker
);
CREATE VIRTUAL TABLE account_fts USING fts5(
    display_name, tags, hostnames,
    tokenize = 'trigram'
);
-- account_fts.rowid <-> accounts.rowid is 1:1
```

It is a *regular* (non-external-content) FTS5 table — so the
update/delete sync can `DELETE FROM account_fts WHERE rowid=?` and
re-INSERT without the external-content `'delete'`-command dance. The
doubled content (once in the FTS index, once as the stored columns)
costs nothing at our cardinality and is RAM-only.

## Tokenizer = `trigram` (Q1)

`trigram` indexes overlapping 3-character grams, giving true
arbitrary-substring ("contains") matching — `"ithu"` finds
`"github.com"`. Trade-off: queries shorter than 3 characters cannot be
matched by trigram, so `Vault::account_search` falls back to a
`LIKE '%token%'` scan over the (tiny, in-RAM) projection columns for
short queries. The projection strings *and* the query are lowercased so
matching is case-insensitive across Unicode (trigram itself is
case-insensitive only for ASCII).

## Query semantics (Q3)

- **Tokenisation:** split on whitespace; each token is lowercased and
  (for the FTS path) wrapped in a double-quoted FTS5 phrase with
  embedded quotes doubled. Raw user input never reaches FTS5 unescaped.
- **Multi-term:** default AND — `"git main"` returns accounts matching
  both substrings.
- **Ranking:** `ORDER BY bm25(account_fts), accounts.updated_at DESC` —
  relevance first, most-recently-modified breaks ties.
- **Result cap:** 200 (`pangolin_store::ACCOUNT_SEARCH_RESULT_CAP`,
  re-exported from the crate). Bounds the per-result blob-decrypt cost
  and the FFI marshalling cost.
- **Empty query** (`trim().is_empty()`): returns every live account,
  `updated_at DESC`, same cap — the "show everything before I type"
  search-as-you-type behaviour 1.2's placeholder also had.
- **Filtering:** tombstoned accounts are not in the index at all;
  frozen accounts (`account_identities.frozen_pending_resolve = 1`) are
  filtered out at query time (the freeze flag can flip at runtime via
  `ingest_chain_revision`, so query-time filtering is the only correct
  place).
- **Locked vault:** `StoreError::NotUnlocked` (no `:memory:` index
  exists when the vault is locked) — same posture as other
  unlock-gated reads.

`account_search` returns full `AccountIdentitySummary` rows (not just
ids) so a caller can render the result list without a follow-up
`account_get` per hit. The summary excludes `notes` per 1.2's audit C-1
fix; that is unchanged.

## Lifecycle

| Event | What happens to the index |
|---|---|
| `Vault::unlock` (success) | `build_active_state_data` decrypts every live head once (V1-aware `open_identity_payload`, so V0-format and 1.2-V1-format vaults alike), builds the V0-shaped `DecryptedCache` snapshot *and* the FTS5 projection from that one decrypt, populates a fresh `SearchIndex`. |
| `account_add` / V0 `add_account` | after the blob-table transaction commits, the new account's projection is inserted into the `:memory:` index (V0 shim: no tags; the single `url` is host-extracted). |
| `account_update` / V0 `update_account` | after the new revision commits, the account's `:memory:` row is rewritten (`DELETE` + `INSERT` on the FTS rowid) with the new projection + recency stamp. |
| `delete_account` (tombstone) | the account's `:memory:` row is removed — a tombstoned account never appears in search. |
| `lock()` / session expiry / `Drop` | `ActiveState` drops, the `:memory:` `rusqlite::Connection` drops, SQLite frees the whole arena. |

The sync writes run *after* the SQLite blob-table transaction commits,
not inside it (the `:memory:` index is a separate connection — it can't
be in the same transaction). That is safe because the index is RAM-only
and rebuilt fresh on every unlock: a crash between the blob commit and
the index update just means the next unlock rebuilds the index from the
(committed) blobs. An interrupted FTS5 update can never desync
persistently. (The e2e test `search_index_rebuilds_on_reunlock`
exercises this: drop the in-RAM index by locking, re-unlock, the index
is correct again — rebuilt from the blob table.)

### Accepted limitation

SQLite's internal FTS5 buffers hold the lowercased projection strings in
plaintext and cannot be zeroized — that is intrinsic to using SQLite for
the index. The intermediate Rust `String`s the projection builder
constructs (`SearchProjection`, which `impl Drop` → `Zeroize`) are
zeroized after they're handed to the connection. Tearing down the
`:memory:` connection on lock frees the whole arena. This is the cost of
the `:memory:`-SQLite design (vs. a hand-rolled in-RAM trigram index);
it is the same metadata-exposure class a stolen `.pvf` already has
(account count, revision graph, timestamps) restricted to the unlocked
session's lifetime, which is strictly better than the persistent
plaintext-projection alternative the plan rejected.

## The `fts_schema_version` hook

`meta_fts.fts_schema_version` is stamped `1` by 1.3. The §18.7
reject/migrate policy — "if `fts_schema_version` < current, drop +
rebuild" (e.g. on a future tokenizer change) — is **1.6's** commit. 1.3
only *stamps* the slot. (The index is rebuilt from the intact blob table
on every unlock anyway, so a future tokenizer swap is a no-op for
migration in practice; the slot is for explicitness, mirroring the
"policy slot" doctrine 1.1/1.2 used for the FFI `schema_version: u16`.)

## Performance

`crates/pangolin-store/benches/search_10k.rs` — a hand-rolled
`Instant`-timed harness (no `criterion` dependency; `[[bench]] harness =
false`, gated behind the `test-utilities` feature). On a 10k-account
vault (release build, commodity Windows host) `account_search` is well
under the master-plan 50 ms exit criterion — median ~13 ms / p99 ~22 ms
for a common single-term query (200 hits, capped), low single-digit ms
for rarer terms. The dominant per-search cost is the per-result AEAD
decrypt of the matched head blobs (the `LIMIT 200` bounds it), not the
FTS5 lookup (sub-ms). The unlock-time index rebuild for 10k accounts is
~100-200 ms on top of the AEAD-decrypt-10k-heads pass `unlock` already
does (which is itself dwarfed by Argon2id, ~600-700 ms). An `#[ignore]`'d
`search_10k_smoke` release test in `tests/e2e.rs` (`< 40 ms` over 10k)
is the on-demand CI smoke; the bench is authoritative. Numbers are
recorded in the DEVLOG signoff entry for issue 1.3.

## What 1.3 does NOT do

- No CLI `account search` subcommand wired to the new path (the FFI
  surface and `Vault::account_search` are done; the shell-side UX is
  out of plan-gate scope).
- No `ingest_chain_revision` resync (it writes a revision without
  resyncing the `:memory:` index, exactly as it already doesn't touch
  the `DecryptedCache` — the index is rebuilt at the next unlock; chain
  ingest is MVP-1-dormant). When 1.4+ makes chain ingest live on the
  CLI path, add the projection-resync after its INSERT.
- No `fts_schema_version` reject/migrate policy — 1.6.

## References

- `docs/issue-plans/1.3.md` — the plan + locked Q1-Q5.
- `docs/architecture/ffi-surface.md` — the frozen `account_search` FFI
  entry point + its behaviour note.
- Master plan §4 row 1.3 — "FTS5 on non-secret fields only".
- Whitepaper §C1 — "Fast search" + "No plaintext secrets at rest".
- Master plan §18.7 — schema-versioning policy (1.6 owns the FTS
  reject/migrate trigger).
