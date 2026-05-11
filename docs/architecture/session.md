# Session policy engine

> MVP-1 issue 1.4 (`docs/issue-plans/1.4.md`). The access-control state
> machine: the session invariant, presence-freshness, prompt timeout,
> prompt deduplication, mid-action resume, the reveal-class taxonomy.
> Promotes the PoC P4 engine to production against session spec §2.3,
> §5–§8. Physically lives in `crates/pangolin-store/src/{session,vault}.rs`;
> re-exported through `pangolin_core::session` (Q1 — no relocation).

## The session invariant (master plan cardinal principle 5 / spec §2.3)

> Start = 2 proofs (presence + identity). Maintain = 1 proof. Expired =
> 2 proofs again. High-risk actions require explicit presence even
> mid-session. This rule is universal and MUST NOT be violated.

- A session is **local-only**, **auto-expiring**, **non-permanent**,
  **non-transferable between devices**, **never on-chain** (spec §2.2).
- It exists only while a `Vault` is `Active` — the unwrapped VDK and the
  decrypted-account cache live on the `ActiveState`; every non-`Active`
  state holds no plaintext.

## States (spec §4)

```text
   Locked ──unlock(presence, identity)──▶ Active
   Active ──idle > configured idle──▶ Expired   (cache zeroized, :memory: FTS5 index freed)
   Active ──now > session_started + ABSOLUTE_MAX (4 h)──▶ Expired
   Active ──device_locked()──▶ Expired           (the spec §7.5 OS-lock hook)
   Active ──lock()──▶ Locked
   Expired ──unlock(presence, identity)──▶ Active
```

`SessionState` (`pangolin_store::session`):

- **`Locked`** — no plaintext; next op needs the full 2-proof unlock.
- **`Active { expires_at, last_proof_at, session_started_at }`** — cache
  live; credential ops permitted. `last_proof_at` is the instant of the
  most recent activity touch; `session_started_at` anchors the
  absolute-max ceiling (touch never extends it).
- **`Expired`** — was `Active`; idle timer or absolute-max fired (or
  `device_locked()` was called). Cache zeroized *before* the state flip;
  next op needs the 2-proof unlock. The vault transitions through this
  state and the next `check_session_freshness` settles it / returns
  `SessionExpired`.
- **`PendingAuthorization`** — a reserved UX state for a host UI's
  mid-action prompt (one proof received, awaiting the other, or a
  high-risk action awaiting presence). The engine treats it as
  "not Active"; the actual proof gathering is the host UI's job (the
  storage layer ships no prompt-state machine — `with_session` is the
  primitive shells wrap).

`check_session_freshness` is the strict gate at the top of every
cache-bearing credential op: `Active` & `now <= expires_at` ⇒ `Ok`;
`Active` & `now > expires_at` ⇒ drop the `ActiveState` (zeroizing the
cache + freeing the `:memory:` FTS5 index) → flip to `Expired` → return
`SessionExpired`; `Locked` ⇒ `NotUnlocked`; `Expired` ⇒ `SessionExpired`;
`PendingAuthorization` ⇒ `SessionPending`. `touch_session` extends
`expires_at` on every successful op via `next_idle_deadline(now,
session_started_at, idle)` — which caps at `session_started_at +
ABSOLUTE_MAX_DEFAULT`, so constant activity cannot stretch a session
past the 4 h ceiling.

## Timing (spec §7)

| Constant | Value | Spec | Notes |
|---|---|---|---|
| `IDLE_TIMEOUT_DEFAULT` | 15 min | §7.1 | default idle window for vaults that predate 1.4 |
| `ABSOLUTE_MAX_DEFAULT` | 4 h | §7.4 | the absolute ceiling; **not configurable** (it is the longest configurable session, so picking "4 hours" means idle == absolute and the session can't be extended) |
| `PRESENCE_FRESHNESS` | 60 s | §7.6 ("30–60 s") | the upper bound the spec permits — adopted for usability; also the prompt-dedup window |
| `PROMPT_TIMEOUT` | 60 s | §7.7 ("~60 s") | the host UI runs the wall-clock timer; a proof that aged past this at a reveal site → `PromptTimedOut` |

### Configurable idle duration (`SessionDuration`, spec §7.2)

Users may choose one of `5 / 15 / 30 / 60 / 240 min` or "until device
lock". Persisted in the vault `meta.session_idle_secs` column
(`300 / 900 / 1800 / 3600 / 14400` seconds, or `-1` =
`SESSION_IDLE_UNTIL_DEVICE_LOCK`):

- Absent column (a vault written before 1.4) ⇒ `SessionDuration::Min15`.
- An out-of-set value (a corrupt-but-decryptable meta field) ⇒ the
  15-min default too — a damaged-but-readable field must not brick the
  vault. The public-API validator `SessionDuration::try_from_meta_secs`
  *rejects* out-of-set values with `Validation { kind: "session_duration" }`
  (the §18.7 hook 1.6 builds on; 1.4 only adds the slot + the validator).
- "Until device lock" ⇒ no idle leg at all; only the absolute-max
  ceiling bounds the session, and `device_locked()` expires it
  immediately. CLI builds have no OS-lock signal, so this behaves like
  "until process exit".

`Vault::set_session_idle(choice, presence)` persists the choice and
applies it to the live session immediately (a *shortening* can move the
deadline earlier than now, which the next freshness check treats as an
expiry). **Lengthening** the session is a high-risk action per §5.4
("extend long sessions") — `presence` must be `Some(&proof)` (a stale
proof → `PromptTimedOut`; `None` → `PresenceProofRequired`).
**Shortening** (or setting the same value) is always allowed and may
pass `None`. An attacker who edits `session_idle_secs` on a stolen
`.pvf` lengthens only the *next* session — they still need the password
to unlock, and the 4 h absolute ceiling bounds it regardless.

### Device-lock hook (spec §7.5)

`Vault::device_locked()` — if the session is `Active`, drops the cache +
VDK (zeroizing every cached snapshot, freeing the `:memory:` index) and
flips to `Expired`; no-op when `Locked` / `Expired` / `Pending`. It is
the storage-layer hook for MVP-3 (mobile) / MVP-4 (desktop) shells to
call on the OS lock-screen event. For the CLI it is unused (a terminal
has no OS-lock signal — the explicit `lock()` covers the user-driven
case); the hook exists so the state machine "leaves the door open".

## Proof types

Trait-based so the real hardware-backed presence proofs (biometric /
device-unlock / NFC) slot in for MVP-3/4 without engine churn:

- **`PresenceProof`** — confirms physical presence; non-replayable;
  quick. CLI tier: `PressYPresenceProof` (a single-use terminal
  "press y" confirmation that stores a `created_at` and rejects when
  `now - created_at > PRESENCE_FRESHNESS`; a second `verify()` returns
  `PresenceAlreadyConsumed`).
- **`IdentityProof`** — confirms user identity; device-local;
  rate-limited; may be biometric-backed. CLI tier: `PinIdentityProof`
  (the vault password, structurally validated then run through the
  KDF + AEAD unwrap chain — a wrong PIN runs the full Argon2id
  derivation before AEAD failure, preserving MEDIUM-1
  indistinguishability; zeroize-on-drop; redacted `Debug`).

`unlock(presence, identity)` is the 2-proof start: both must verify (any
proof-class failure collapses to `AuthenticationFailed`); the password
runs through Argon2id → AEAD-unwrap of the VDK → rebuild the cache + the
`:memory:` FTS5 index. The first `expires_at` derives from the
configured idle; `last_presence_at` is stamped to "now" (the unlock's
presence proof counts — see below). A failed re-`unlock` on an `Active`
vault leaves the prior session intact (the vault does not auto-lock).

## Presence freshness + prompt timeout + prompt dedup (spec §5.4, §7.6, §7.7, §8.6)

The single source of truth for "is presence fresh *right now*" is the
`ActiveState`'s `last_presence_at: Option<SystemTime>` and the
`ensure_presence_fresh(presence)` check that every high-risk op runs:

1. If `now - last_presence_at <= PRESENCE_FRESHNESS` (60 s) — the op
   proceeds **without consuming the supplied proof**. This is the
   prompt-dedup case (§8.6): a reveal moments after unlock, or a second
   reveal moments after the first, sees "presence fresh" and never
   re-prompts. The single `last_presence_at` timestamp gives dedup for
   free — concurrent reveals share one proof.
2. Otherwise the supplied proof must `verify()`. On success,
   `last_presence_at = now`. On failure: a **stale** proof
   (`AuthError::NotFresh`) at a high-risk call site means the host UI
   prompted, the user took >60 s, the proof's `created_at` is now stale
   — this maps to `StoreError::PromptTimedOut` (§7.7 — loud, typed,
   never silent per §8.2; a UX signal "re-run the action", *not* an
   oracle — a timed-out prompt reveals nothing about any secret). Any
   other proof failure (replayed, empty, generic) collapses to
   `AuthenticationFailed` per the MEDIUM-1 indistinguishability
   discipline.

Ordering at a high-risk call site (security-critical):
`check_session_freshness` → `refuse_if_frozen` (P8 CRIT-1) →
`ensure_presence_fresh` → do the op → `touch_session`. The first two
steps run *before* the proof is consumed, so a locked/expired session or
a frozen account surfaces with the proof un-consumed and recoverable.

## Mid-action resume (spec §8.5)

`Vault::with_session(op, reauth)`:

```text
match check_session_freshness() {
    Ok(())               => op(self)
    Err(SessionExpired)  => reauth(self)?; check_session_freshness()?; op(self)
    Err(other)           => Err(other)
}
```

If a session is found expired at-or-before the start of the op, the host
UI's re-auth callback runs (the 2-proof unlock, or a fresh presence
proof for a presence-gated `op`) and then the op resumes — transparently
per §8.3. If `reauth` errors (user cancelled, wrong PIN), `op` does NOT
run and the error propagates. The post-reauth `check_session_freshness`
re-validation (audit L-3) catches a `reauth` that returns `Ok(())`
without actually re-`Active`-ing the vault (or one that burned enough
time to leave it active-but-already-expired) ⇒ `SessionExpired`; `op`
never runs against an invalid session. **Known limitation:** a session
that expires *mid-op* (e.g. during a ~1.5 s Argon2id inside `op`) is not
retried — `op` returns whatever it returned; a transactional-retry
wrapper is MVP-3+ scope.

## Reveal-class entry points (spec §5.4)

High-risk reveal-class assets per §5.4 (and the Phase-2 note): the head
password, the full password history, free-form notes, the raw TOTP
shared-secret seed (recovery material is MVP-3 scope). Each
`Vault::reveal_*` is presence-gated via `ensure_presence_fresh` and
fails cleanly on `NotUnlocked` (locked) / `SessionExpired` (expired,
cache zeroized) / `AccountFrozenPendingResolve` (frozen, proof not
consumed) / `PromptTimedOut` (stale proof) / `AccountNotFound` /
`AccountTombstoned`:

- `reveal_current_password(id, presence) -> SecretBytes` — the head
  password (`reveal_password` is a kept back-compat alias). Reads from
  the in-memory cache shadow.
- `reveal_password_history(id, presence) -> Vec<PasswordHistorySummaryEntry>`
  — the **full** V1 history: every entry's plaintext bytes + `set_at_ms`
  timestamp + originating device id, newest first. Reads the head
  identity from disk (V1-aware decrypt, auto-migrating V0 payloads) —
  the cache shadow only holds the head password.
- `reveal_notes(id, presence) -> SecretBytes` — the decrypted notes
  (recovery-class — recovery phrases / security-question answers).
- `reveal_totp_secret(id, presence) -> SecretBytes` — the raw TOTP seed
  (1.7's RFC-6238 generator consumes it internally without a reveal;
  exporting/revealing the *seed* is the high-risk action this gates).
  Empty when no TOTP configured.

`export_payload(id, presence)` is the same proof discipline (active
session + fresh presence) for the migration/backup primitive.
`touch_session_explicit(presence)` is the explicit single-proof
"maintain" leg (backs the FFI `session_extend`).

### Q5b — the strict reveal-gated model (the FFI projection)

The internal `pangolin-store::AccountIdentity` keeps **all** its fields.
But the FFI `AccountSnapshot` (and the `pangolin-store::AccountIdentitySummary`
projection it is built from) carries **zero secret material**: only
display name, tags, usernames, URLs (non-secret per the V1 model), the
head revision id, the password-history *count*, a `has_totp` flag, and
the current-password-changed-at timestamp. Every secret crosses FFI
**only** through the presence-gated `reveal_*` entries — `account_get` /
`account_search` need only an unlocked vault, *not* a fresh presence
proof, so under the previous design they returned `Arc<SecretPassword>`
/ `Arc<TotpSecret>` handles for *every* matched account, and a binding
shell held those the moment the user searched (the bytes were
reveal-gated, but the handle's presence in the shell is exposure:
coercible later byte-reveal, serialization-bug leak, debug-dump). The
strict model: the search/list path never touches an encrypted password
blob; every secret crossing is a fresh-presence-checked `reveal_*` call,
and only the specific secret requested. See `docs/architecture/ffi-surface.md`
§"Issue 1.4 amendment" for the FFI shapes.

## Search-index lifecycle (unchanged from 1.3)

The `:memory:` FTS5 search index lives on the `ActiveState` — built from
the decrypted head blobs on `unlock`, kept in sync from `account_add` /
`account_update` / `delete_account` (+ the V0 shims), and freed by
SQLite when the `ActiveState` drops (`lock()`, idle/absolute expiry,
`device_locked()`, `Drop`). 1.4's session rewrite routes every expiry
path through dropping the `ActiveState`, so the lifecycle is preserved
exactly. `ingest_chain_revision` (dormant chain code) still does not
resync the index — it's rebuilt on the next unlock (the 1.3 posture; an
MVP-2 follow-up).

## Wall-clock skew

`SystemClock` reads `SystemTime::now()` on each call (no caching), so a
backward jump can spuriously extend or expire a session. The PoC accepts
this; the `Clock` trait is the seam — MVP-3/4 may switch to `Instant`
(monotonic). `next_idle_deadline` is overflow-safe (a year-262k clock
saturates to "expire now", never "extend forever").

## References

- Master plan §0 cardinal principle 5 — the session invariant.
- Session spec §2.2 / §2.3 / §3 / §4 / §5 / §7 / §8.
- `docs/issue-plans/P4.md` — the PoC session engine this promotes.
- `docs/issue-plans/1.4.md` — the production issue (Q1-Q5b locked).
- `docs/architecture/ffi-surface.md` — the FFI shapes (the 1.4
  amendment: `reveal_*`, the `AccountSnapshot` tightening, `session_extend`).
- `docs/architecture/search.md` — the `:memory:` FTS5 search index.
- `THREAT_MODEL.md` row #7 — the indistinguishability discipline.
