<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Revision Lineage (Whitepaper §7, master plan §17 / row 1.6)

Locked by MVP-1 issue 1.6. Promotes the PoC P3 revision graph + P8/P9
fork/resolve internals to production.

## The graph model

Each account has a per-account revision graph: an append-only tree of
immutable `revisions` rows. Every edit (`account_add` / `account_update`
/ `account_delete`) writes a new row referencing its parent through
`parent_revision_id`; a *genesis* revision uses the all-zero parent
sentinel. A **fork** is two (or more) revisions sharing the same parent
— it can only arise in MVP-1 from the `__test_synthesize_sibling_revision`
test helper or the dormant `ingest_chain_revision` path (real
multi-device forks land with MVP-2's chain sync). A revision with no
children is a **leaf**; a linear account has exactly one leaf, a forked
account has ≥ 2.

`RevisionGraph::build` (in `pangolin-store/src/revision.rs`) indexes the
parent→child structure: BFS topological order, cycle detection
(`Corrupted`), duplicate-id detection (`Corrupted`), dangling-parent
orphans treated as synthetic roots, multi-genesis tiebreak. It carries
only non-secret `RevisionMeta` (never `enc_payload`).

## The canonical head — clock-free (Q1)

`RevisionGraph::canonical_head()` returns the **leaf with the
lexicographically-largest `revision_id` (byte-order)**. For a linear
chain that's trivially the single leaf; for a fork the largest-id leaf
wins. **No `created_at` involvement** — `created_at` is device-stamped
and not trustworthy across devices (a buggy/malicious device could stamp
a future timestamp to hijack the election); `revision_id` byte-order is
the documented device-independent total order (`revision_id` is the
`revisions` PRIMARY KEY, 32 bytes, so any two distinct leaves have
distinct ids and the order is total). This is the standard CRDT
"highest hash wins" tiebreak — the cleanest story for proving that
MVP-2's chain replicas agree (sync soundness inherits this rule).

Properties: deterministic (the `heads` set is itself deterministic at
`build` time; `max_by` over byte-order is total — re-building from the
same rows in any input order gives the same answer); total; stable
(adding a non-leaf revision, or a revision to a different account, does
not change which leaf wins).

The per-account `account_identities.head_revision_id` column is a
*cache* of the canonical head, advanced by the edit paths and the
resolve flow. The authoritative head-*set* detector is the SQL
`NOT EXISTS` query (scoped by `account_id`, per the P3 audit M-1; in 1.6
it also excludes `superseded_by IS NOT NULL` rows — see below). On
unlock, the in-RAM decrypted cache + the `:memory:` FTS5 index are built
from each account's *canonical* head: for a forked account that's
`canonical_head()`, not the cached pointer; for a linear account the
cached pointer IS the single leaf, so the fast path is untouched.
`account_get` / `account_search` likewise read the canonical head for a
forked account.

**Leaf authentication at unlock.** For a forked account the unlock cache
build does not only decode the canonical head — it decodes (and thus
AEAD-authenticates) every *decryptable* leaf of the revision graph, so a
tampered leaf surfaces `AuthenticationFailed` and aborts the unlock
regardless of which leaf is canonical (defends against a cross-account
row transplant — the row's `account_id`/parent/`schema_version` are
bound into the AEAD AAD — that lands on a non-canonical leaf). Leaves
whose stored nonce is the **placeholder zero nonce** are *skipped*: those
are foreign-ingested chain revisions sealed by another device that this
device legitimately cannot decrypt under the PoC two-key model (the
`ingest_chain_revision` genuine-foreign-INSERT path writes the
placeholder) — that is the documented frozen-pending-resolve state, not
tampering, and those leaves are authenticated when the resolve flow
consumes them, not at unlock. The distinguisher is unambiguous: a
genuinely-tampered leaf carries a *real* nonce with a mismatched AAD; a
foreign placeholder leaf carries the all-zero nonce. If the *canonical*
head itself is a placeholder-nonce leaf (it can win the clock-free
largest-`revision_id` election), the cache/index snapshot falls back to
the cached local-head pointer (`account_identities.head_revision_id`,
which the resolve flow keeps pointing at a leaf this device can decrypt
for a frozen account); if that too is undecryptable the account is left
out of the cache/index (surfaced via the freeze/resolve workflow, never
as an aborted unlock).

## Fork detection (Q2)

`Vault::is_forked(id)` = `account_heads(id).len() > 1`. Cheap — the SQL
`NOT EXISTS` query with the `idx_revisions_parent` index, no maintained
flag column. `all_forked_accounts()` is the "needs attention" set;
`list_conflicts()` (P9) is `forked OR frozen`.

A forked account stays **readable at its canonical head**;
reveals/edits are *not* blocked by fork-state alone (Q2 — matches
Whitepaper §7's "conflicts are surfaced, not blocking"). The separate,
stricter `frozen_pending_resolve` flag (P8/P10) — set only by the
dormant `ingest_chain_revision` path — *does* block reads and edits
until resolved; it is distinct from fork-state and 1.6 leaves its
semantics alone.

## Conflict resolution → canonical head (Whitepaper §G3, Q5)

`Vault::resolve_fork(account_id, keep_revision_id) -> RevisionId`
ratifies `keep_revision_id` (which must be a current head of the forked
graph) as the surviving branch:

1. Validates the account exists + isn't tombstoned; the chosen revision
   is a row of *this* account (cross-account ids collapse to
   `AccountNotFound` — no oracle); the account is actually forked
   (`Validation { kind: "not-forked" }` if not — typed, not a silent
   no-op); the chosen revision is a current head (`NotAHead` if not).
2. Writes a new **merge revision** parented at `keep_revision_id`. Its
   payload = the kept branch's head payload, re-sealed under a fresh
   nonce + the merge revision's own AAD (`parent_revision_id =
   keep_revision_id`, `schema_version` inherited from the chosen leaf).
   A byte-copy of the chosen leaf's ciphertext would carry the leaf's
   *own* parent baked into its AAD and be unopenable as the merge row —
   the re-seal is mandatory (the P9 §A2 argument). If the chosen leaf
   is a tombstone, the merge is re-sealed via `seal_tombstone` —
   resolving to a tombstone ratifies the deletion.
3. Marks every *other* current leaf `superseded_by = <merge>` (a new
   nullable column on `revisions`, added by 1.6's idempotent migration).
   The head detector excludes superseded rows, so the account now
   reports a **single canonical head** (the merge revision — which is
   also the largest `revision_id` leaf, being newest) → `is_forked` is
   `false`. The losing branch's revision rows are **kept** (Q5 — audit
   / recovery; append-only is the cardinal principle; they're just off
   the head chain now via `superseded_by`).
4. Advances `head_revision_id` to the merge revision, clears
   `frozen_pending_resolve`, writes the `dirty_accounts` marker (the
   merge revision is unpublished — MVP-2's publish path consumes it),
   prunes the now-orphan `pending_merges` stash row(s). All steps 2-4
   inside one SQLite transaction (head membership is re-checked inside
   the transaction so a concurrent `ingest_chain_revision` that demoted
   the chosen leaf surfaces `NotAHead`). Re-syncs the in-RAM cache +
   FTS5 index to the new canonical head.

`resolve_fork` requires only an active (unlocked, non-expired) session —
**NOT a fresh presence proof** (Q2): reparenting the graph reveals
nothing; it ratifies a branch the user already authored (it is not a
Session spec §5.4 reveal-class action). It traces through
`check_session_freshness` / `require_active` but never
`ensure_presence_fresh`. It never auto-resolves — the user must call it
explicitly; no silent merge anywhere (Whitepaper §G3, master plan
cardinal principle 4).

`Vault::clear_frozen` (P9) stays as the *lower-level* primitive for the
MVP-2 chain flow (the merge revision already exists, having been
published + re-ingested; just clear the flag + advance the head);
`resolve_fork` is the MVP-1 no-chain primitive that *creates* the merge
revision locally and then does the same.

## "Requires upgrade" (§18.7 — see `schema-versioning.md`)

If an account's canonical head carries a revision-row `schema_version`
or a CBOR `payload_version` newer than `REVISION_SCHEMA_VERSION_MAX`,
that account is marked "requires upgrade" (an in-RAM set populated on
unlock — not a persisted column; the on-disk truth is "there's a
revision with version > our max"). `account_get` / `reveal_*` /
`account_update` on it return `StoreError::UnsupportedRevisionSchemaVersion`;
`account_history` / `account_status` / `is_forked` keep working
(metadata-only); the rest of the vault is unaffected. `account_status`
surfaces `requires_upgrade`, `is_forked`, `is_frozen_pending_resolve`,
`is_tombstoned` in one query.

## MVP-1 boundary / MVP-2 hooks

- A real multi-device fork cannot occur in MVP-1 — the machinery is
  fully production-grade and fully tested (via the test helper), and
  `resolve_fork` is real and FFI-exposed, but the only ways a fork
  arises are the test helper or the dormant `ingest_chain_revision`
  path (MVP-2-only). This is the honest scope (same posture as 1.5's
  dormant `last_sync_at` / unsigned `DeviceKey`).
- The revision graph 1.6 builds is exactly what MVP-2's chain Revision
  Log v1 (`2.1`) anchors; the clock-free canonical-head rule is *why*
  the chain replicas agree on the head.
- A content-deterministic `revision_id` (keccak256 of the canonical
  revision body) is a future switch — noted in `revision.rs`; it only
  *strengthens* the byte-order tiebreak's "highest hash wins" story.
- The `pangolin-cli resolve` subcommand rides the CLI-V1 issue
  alongside `account` / `reveal` / `device` (Q6 — no new CLI subcommand
  in 1.6).
