<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Issue #105 — Recovery-core HARDENING (host-callable FFI surface + atomic re-split persistence) — plan-gate LOCKED

**Status: LOCKED — Kelvin sign-off 2026-05-20. Q-a..Q-g resolved (see §0a). SPLIT into #105a (atomic persistence fix) FIRST, then #105b (FFI surface).** Mirrors the §16 plan-gate format of `103-recovery-client.md` / `104b-recovery-orchestration.md`. The engineering follow-up to the merged #104b recovery orchestration (`ab8d33e`). Recovery stays **TESTNET-ONLY (Base Sepolia) until the D-011 external audit clears** (unchanged; #105 inherits the same hard pre-mainnet gate).

**Base (all merged):** #102 RecoveryV1 contract `97cbe4c`; #103 chain-client `17e2313`; #104a escrow primitive `1271766`; #104b orchestration `ab8d33e`. #100 host-FFI-handles established the `VaultHandle` / engine-side-secret model this issue mirrors.

## 0a. RESOLVED decisions (Kelvin sign-off 2026-05-20)

- **Q-a SPLIT → #105a (atomic persistence fix) FIRST, then #105b (FFI surface).** The atomic fix is a real at-rest forward-security bug today, small + hermetic (no anvil), and gives the FFI a clean primitive to call. Ship it on its own focused PR with the crash-injection gate; FFI follows.
- **Q-b FFI thickness → THIN per-step bindings** (one fn per #103 on-chain broadcast, mirroring `vault_initiate_top_up`; off-chain escrow + atomic commit as their own calls). Engine signs engine-side; the host owns the multi-day/72h choreography + countdown.
- **Q-c → confirmed: NO secret crosses the boundary** (VDK/RWK/share-scalar/password stay engine-side; only opaque zeroizing `Arc` Objects + non-secret context cross). L1.
- **Q-d → expose BOTH roles in #105b** (recovering-device + guardian `open_share`/`sign_approve`) so recovery is usable + testable end-to-end.
- **Q-e → idempotent/retryable** partial recovery (on-chain rotation durable + not re-driven; off-chain finish-up re-runnable because OLD escrow stays live until the atomic commit succeeds). L8.
- **Q-f → guardian roster is a HOST-SUPPLIED INPUT** to the FFI (all M X25519 pubkeys + EVM addrs); engine does not discover guardians. The backup format/transport that restores the roster in a lost-everything recovery is deferred to 6.x — flagged as the dependency that gates a lost-everything re-seal (GAP 2).
- **Q-g → coarse, non-oracular error taxonomy** via `FfiError::Recovery` (below-threshold / share-rejected / persistence-failed / chain-step-failed; crypto distinctions collapsed).
- **Build order:** #105a builder→audit→merge, THEN #105b builder→audit→merge. Each gated; merge/push at Kelvin's boundary.

## 0. One-paragraph summary

#104b made Option-2 social recovery functionally end-to-end on testnet, but left two engineering follow-ups it deliberately deferred. **(1) FFI/uniffi entry points** (Q-i, deferred to "6.x"): the pure `pangolin-core::recovery::orchestration` drivers are not yet callable from a phone/desktop app — there is no host-facing surface that composes the pure drivers + the `pangolin-store` persistence + the on-chain #103 broadcasts into entry points a shell can invoke. **(2) The re-split persistence-ordering contract** the #104b audit flagged is currently a *doc-comment* on `recover_vdk_from_shares` ("Caller persistence ordering"), not an enforced atomic operation: the caller must persist `write_recovery_escrow(re_split)` AND the new-password re-wrap (`recover_with_new_password`) together, and a crash *between* the two leaves a re-keyed daily wrap alongside stale escrow rows whose OLD shares still reconstruct the OLD RWK — a real forward-security hole (L6 violation at-rest). #105 turns that contract into a single ATOMIC store entry point and exposes the recovery flow over FFI, mirroring #100's handle/engine-side-secret discipline. It introduces **no new crypto** — composition, persistence atomicity, and boundary plumbing only.

## 1. Scope

**#105 builds:**

1. **Atomic re-split persistence (the correctness fix).** A single `Vault` method (working name `Vault::commit_recovery_rekey`) on `pangolin-store/src/vault.rs` that, in **ONE `unchecked_transaction()` on `self.conn`**, performs BOTH writes that `recover_vdk_from_shares` today leaves to two separate caller-driven transactions: (a) the new-password re-wrap of the daily `WrappedVdk` (the body of `recover_with_new_password`) AND (b) `write_recovery_escrow` of the forward-security `re_split` artifacts. The escrow write's internal `unchecked_transaction()` is refactored to accept a borrowed transaction so it can join the meta-write under one commit. A crash anywhere before `tx.commit()` rolls BOTH back — the old escrow + old daily wrap survive intact (recoverable again), and there is never a window where a new daily wrap coexists with stale OLD-RWK escrow rows.
2. **The recovery FFI surface** (`crates/pangolin-ffi/src/recovery.rs`, new) — host-callable entry points on / alongside the existing `VaultHandle`, covering BOTH device roles (recovering device + guardian). Per-step thin chain bindings (mirroring `vault_initiate_top_up`) drive the #103 broadcasts engine-side; the off-chain escrow steps + the atomic commit are exposed as their own entry points. NO secret (VDK, RWK, share plaintext, password) is ever returned across the boundary — secrets are read/held engine-side inside the `Vault`/handle, exactly as #100 established (`vault_initiate_top_up` reads the signer engine-side and clones it; never returns it).
3. **The `FfiError::Recovery` mapping wired** (the variant already exists, reserved for MVP-3) + a recovery-specific FFI error taxonomy (guardian-threshold, share-decode, epoch-mismatch, partial-recovery-retry) collapsing through the §18.8 taxonomy without becoming a distinguishing oracle.
4. **Regression gates:** a hermetic crash-injection test for the atomic fix (simulate a panic between the two writes; assert NO stale escrow survives + the daily wrap is unchanged), and an FFI round-trip test that drives the recovery entry points end-to-end against the existing anvil lifecycle (extending #104b's coupled E2E rather than duplicating it).

**Deferred (own cycles / later):**
- **Recovery WIZARD UX** (countdown timers, guardian-roster screens, QR/app share transport) — #105 ships the *callable surface*; the screens + the human-to-human share transport channel remain 6.x (unchanged from #104b Q-h/Q-i framing).
- **#103-C revocation-on-read** — separate (touches the 4.1 reader).
- **Guardian-set mutation / share refresh without a recovery** — R-e immutable in v1.
- Live-testnet `#[ignore]` E2E (needs a pinned Base Sepolia RecoveryV1 address — same posture as #103/#101).

## 2. Splittable? — recommendation: **persistence-fix FIRST as its own tiny issue (#105a), THEN the FFI (#105b)**

These are genuinely separable and have different risk profiles, so — unlike #104b (one indivisible composition) — splitting is the right call:

- **The atomic persistence fix is a real correctness gap that exists TODAY**, independent of any FFI. It is small (one `Vault` method + refactoring `write_recovery_escrow`'s transaction boundary to accept a borrowed `&Transaction`), hermetic-testable (no anvil needed — pure store crash-injection), and *should land first* so the forward-security hole is closed regardless of when the UX cycle picks up the FFI. It also gives the FFI a single clean atomic primitive to call, rather than the FFI having to re-orchestrate two writes correctly itself.
- **The FFI surface is larger, lower-correctness-risk, higher-design-surface** (the thick-vs-thin chain question, the guardian-role split, the error taxonomy), and its merge gate is an FFI round-trip test that *depends on* the atomic primitive existing.

**Recommend: #105a (atomic persistence) merges first as a focused PR with the crash-injection gate; #105b (FFI surface) follows on top.** Both can live on one tracking issue (#105) if Kelvin prefers a single ledger entry. Surfaced as **Q-a**. (If Kelvin wants them bundled, the persistence fix still lands as the first commit on the branch with its own test gate.)

## 3. The host-callable flow (designed; decisions surfaced in §5)

### 3.1 The atomic-persistence fix (the #105a core)

**Finding (confirmed by reading the code):** the escrow write (`recovery_escrow` + `recovery_guardians` tables) and the daily-wrap re-key (`meta` table) **all live in the SAME sqlite database file** (the vault `.pvf`) and the `Vault` holds a **single `conn: Connection`** (`vault.rs:305`). So a single transaction CAN span all three tables — **atomicity is achievable in-tree, no separate-store fallback is needed.** The gap is purely that today they run as TWO independent `unchecked_transaction()` scopes invoked separately:
- `recover_with_new_password` (`vault.rs:1152`) calls `meta::write(&self.conn, …)` (its own implicit write) and commits.
- `write_recovery_escrow` (`recovery_escrow.rs:150`) opens its OWN `conn.unchecked_transaction()` and commits internally.

**Design:** introduce `Vault::commit_recovery_rekey(&mut self, recovered_vdk: VdkKey, new_password: &SecretBytes, re_split: OnboardingArtifacts) -> Result<()>` that:
1. opens ONE `let tx = self.conn.unchecked_transaction()?;`
2. derives the new password authority + re-wraps the daily `WrappedVdk` (the existing `recover_with_new_password` body), writing the new `meta` row **through `tx`** (not `&self.conn`);
3. writes the `re_split` escrow + guardians **through the SAME `tx`** — this requires refactoring `write_recovery_escrow` to take a `&rusqlite::Transaction` (or a generic connection-like) instead of opening its own (a new `write_recovery_escrow_tx` inner fn; the existing public fn becomes a thin "open tx → call inner → commit" wrapper so #104b callers/tests are unaffected);
4. `tx.commit()?` once. On any error before commit, the `Drop` of the un-committed `tx` rolls BOTH writes back (the established `clear_frozen` discipline at `vault.rs:12077`).
5. updates in-memory `self.meta` + `self.active`/`session_state` ONLY after a successful commit (so a rolled-back write doesn't desync memory from disk).

The escrow write needs the **VDK column-AEAD key** (`vdk_aead`) to double-wrap the sealed-share copies (Q-g) — sourced engine-side from `recovered_vdk.aead_key()`, the same VDK that was just re-wrapped (it is dropped/zeroized at the end exactly as `recover_with_new_password` does today).

### 3.2 Recovery FFI entry points (the #105b surface)

Mirroring the #100 model (`VaultHandle = Mutex<Option<Vault>>`; secrets held engine-side; chain calls driven on a local runtime via `block_on_local`; nothing secret returned). The proposed surface (final shapes frozen in the build, like the 1.1 freeze):

**Recovering-device role:**
- `vault_onboard_guardians(handle, guardian_x25519_pubs, guardian_evm_addrs, threshold)` → composes `onboard_guardian_escrow` + `write_recovery_escrow` engine-side, returns a non-secret `FfiOnboardingResult { merkle_root_hex, epoch, schema_version }` for the host to push on-chain (or drives `set_guardian_set_v1` itself per Q-b).
- The five on-chain lifecycle broadcasts as **thin per-step bindings** (Q-b): `vault_recovery_initiate(handle, rpc_url, …)`, `vault_recovery_approve(handle, rpc_url, guardian, …)`, `vault_recovery_finalize(handle, rpc_url, …)`, plus a status read — each a `block_on_local` wrapper over the #103 `*_recovery_v1` fns, signer read engine-side.
- `vault_recover_from_shares(handle, opened_shares, …)` → calls `recover_vdk_from_shares` engine-side, holds the recovered VDK + `re_split` engine-side (NEVER returned), then immediately calls `Vault::commit_recovery_rekey` (the #105a atomic primitive) with the new password. Returns only a non-secret `FfiRecoveryResult { new_epoch, schema_version }`.

**Guardian role** (Q-d — the host app is also someone's guardian):
- `vault_guardian_open_share(handle, sealed_share)` → opens the guardian's OWN sealed share with their engine-side X25519 secret (`open_sealed_share`), returns the opened `Share` **as an opaque `Arc` Object** (like `SecretPassword`), NOT raw bytes — the host hands it to the recovering device's transport without ever seeing the scalar.
- `vault_guardian_sign_approve(handle, …)` → builds + signs the `Approve` EIP-712 (the #103 `recovery_signing` path) engine-side.

### 3.3 What crosses the boundary (Q-c)

Only non-secret context crosses: merkle-root bytes, epoch counters, t/M, guardian X25519 *public* keys + EVM addresses, tx hashes, the opaque `Share`/`SealedShare`/password Objects. The VDK, RWK, share *scalars*, and the password *bytes* stay engine-side inside the `Vault`/handle and are zeroized on drop — identical to #100's signer discipline.

## 4. L1..L11 invariants (proposed — mirror 103/104b style)

- **L1 (zero-secret-crosses-FFI — LOAD-BEARING)** No VDK, RWK, plaintext `Share`, RecoveryWrapKey, or password ever crosses the uniffi/cabi boundary as readable bytes. Secrets are read/held engine-side inside the `Vault`/`VaultHandle`; the only secret-bearing types that cross do so as opaque zeroizing `Arc` Objects (the `SecretPassword` pattern). Inherits #100 / Design Spec §15.
- **L2 (atomic re-split persistence — the #105a core)** The new-password daily re-wrap (`meta`) and the `re_split` escrow write (`recovery_escrow` + `recovery_guardians`) MUST commit in ONE sqlite transaction or not at all. There is no reachable on-disk state where a post-recovery daily wrap coexists with a pre-recovery (OLD-RWK) escrow generation. Asserted by the crash-injection regression gate.
- **L3 (byte-identical VDK)** Unchanged from #104b L3 — the recovered VDK is unwrapped, never re-derived; the FFI path never calls `VdkKey::generate`. The atomic commit re-wraps the SAME recovered VDK.
- **L4 (forward security preserved end-to-end)** The atomic fix is what makes #104b L6 hold *at rest under crash*: after `commit_recovery_rekey` returns Ok, the OLD shares cannot reconstruct the live RWK; after a crash before commit, the OLD escrow is still the live generation (recoverable, not stranded). Inherits #104b L6.
- **L5 (session-gated FFI)** Every recovery FFI entry point that touches vault secrets is active-session-gated at the boundary (the #100 L4 posture — `require_unlocked`/`lock_vault().as_mut()?`), before any escrow or chain primitive runs.
- **L6 (thin chain bindings, engine-side signing)** The five on-chain broadcasts cross FFI as per-step bindings; the secp256k1 signer is read engine-side and cloned (never returned), driven on `block_on_local` exactly like `vault_initiate_top_up`. The host orchestrates the *sequence*; the engine never embeds chain-sequencing policy.
- **L7 (recovery error model is non-oracular)** FFI recovery errors collapse through `FfiError::Recovery` / the §18.8 taxonomy so a caller cannot distinguish "wrong share" from "tampered wrapper" from "below threshold" beyond the coarse category needed for UX (the authentication-class collapse discipline from `error.rs`).
- **L8 (idempotent / retryable partial recovery)** A recovery interrupted between on-chain finalize and the off-chain atomic commit is safely retryable: re-running `vault_recover_from_shares` with the same opened shares is well-defined (the OLD escrow is still live until the atomic commit succeeds; the on-chain rotation is already durable on-chain and is not re-driven). Surfaced as Q-e.
- **L9 (testnet-only)** Recovery (contract + client + escrow + this FFI) stays Base-Sepolia-only until the D-011 external audit clears. The FFI exposes no mainnet recovery path.
- **L10 (`forbid(unsafe_code)` EXCEPT `pangolin-ffi`)** Every new file carries the AGPL SPDX header. `pangolin-ffi` is the ONLY crate allowed `unsafe` (its per-crate `[lints]` override + `deny(unsafe_op_in_unsafe_fn)`); the new `recovery.rs` adds no new `unsafe` of its own. `pangolin-core::recovery` stays zero-uniffi (the FFI wraps it from `pangolin-ffi`, dependency arrow ffi→core only — `cargo tree -p pangolin-core | grep -ci uniffi` stays `0`).
- **L11 (crash-injection regression gate = the #105a merge gate)** A hermetic test MUST simulate a crash (panic / forced rollback) between the meta-write and the escrow-write inside `commit_recovery_rekey`, then re-open the vault and assert: the OLD escrow generation is intact, the daily wrap still opens under the OLD password, and NO new-epoch escrow row survives. Breaking the single-transaction wrapping turns this RED. (env-quirk #14 class — the structural defence.)
- **L12** §16 ledger; `git merge --no-ff`; zero new pinned deps (pure composition — expect ZERO); every change needs explicit Kelvin approval at the merge boundary.

## 5. Open decisions for Kelvin (Q-a … Q-g) — recommendation + plain-English stakes

**Q-a — ship the persistence fix FIRST as its own small issue, or bundle it with the FFI?**
- *Term:* "atomic persistence" = making two database writes succeed-together-or-fail-together, so a power-loss/crash can't leave the vault half-updated.
- *Recommendation:* **persistence fix FIRST (#105a), FFI second (#105b)** — see §2.
- *Plain-English stakes:* The persistence gap is a *real bug that exists right now*: if a phone dies at the wrong half-second during recovery, the user's vault could end up in a state where old guardian pieces still unlock the old key — the exact "forward security" promise we made. It's small and fixable without any app-facing work, so closing it shouldn't wait for the UX cycle. **Stakes: confirm we treat the correctness gap as urgent and land it on its own, rather than letting it ride along with the bigger (and slower) app-plumbing work.**

**Q-b — how "thick" is the FFI? Does it drive the on-chain steps, or does the host drive chain calls and feed results back?** (the central shape question)
- *Term:* the recovery has on-chain steps (start recovery / each guardian approves / finalize after 72h) that live in `pangolin-chain`. "Thick" = one FFI call does the whole recovery including chain. "Thin" = the app calls the engine for each step.
- *Recommendation:* **thin, per-step bindings** — one FFI function per on-chain broadcast (mirroring the existing `vault_initiate_top_up`), plus the off-chain escrow + the atomic commit as their own calls. The engine signs engine-side; the app sequences the steps and renders the 72h countdown.
- *Plain-English stakes:* recovery is a multi-day, multi-party process with a mandatory 72-hour delay and human guardians acting at their own pace — it CANNOT be a single blocking "do the recovery" call. The app needs to drive each step, show progress, survive being closed and reopened, and let guardians approve whenever they're ready. A thin surface matches that reality and matches how every other chain action already works in the app. **Stakes: confirm the engine stays a toolbox of steps and the app owns the choreography — not a single magic button.**

**Q-c — confirm NO secret ever leaves the engine to the app.**
- *Recommendation:* **confirmed/enforced (L1).** The decryption key, the recovery key, the raw guardian pieces, and the password all stay inside the engine; the app only ever gets non-secret things (a merkle root, an epoch number, transaction hashes) or opaque sealed handles it can't read.
- *Plain-English stakes:* this is the #100 rule that the secrets live in the Rust core and the app (which could be compromised, screenshotted, or memory-dumped) never holds them. **Stakes: confirm we hold the line — even the recovered guardian "pieces" the recovering device assembles never surface to the app as readable bytes; they're used engine-side and dropped.**

**Q-d — does #105 also expose the GUARDIAN-side entry points (open my sealed share + sign Approve), or only the recovering device's flow?**
- *Term:* every user is potentially someone else's guardian, so the same app needs a "help my friend recover" mode, not just a "recover my own vault" mode.
- *Recommendation:* **expose both roles in #105b.** The guardian needs `vault_guardian_open_share` + `vault_guardian_sign_approve`; without them the recovering-device flow has no counterpart to talk to and can't be exercised end-to-end.
- *Plain-English stakes:* recovery is two-sided — the person recovering AND the guardians helping them both run this same app. If we only build the recovering side, no one can actually help, and we can't even test the full loop. The cost is a slightly bigger surface now. **Stakes: confirm we build both halves in this cycle so recovery is actually usable (and testable) end-to-end, rather than shipping a one-sided stub.**

**Q-e — idempotency / retry of a partially-completed recovery.**
- *Term:* the on-chain part (rotating who controls the vault) is permanent once it lands; the off-chain part (re-keying + re-splitting) happens after. If the app crashes between them, what happens on retry?
- *Recommendation:* **make the off-chain step safely re-runnable** (L8): the on-chain rotation is already durable and isn't re-done; re-running the share-reconstruction + atomic commit with the same pieces is well-defined because the OLD escrow stays live until the atomic commit succeeds.
- *Plain-English stakes:* recovery spans days and the app will get closed/crash mid-flow — the user must be able to resume without bricking their vault or having to restart the 72-hour clock. **Stakes: confirm "safe to retry the local finish-up step" is a requirement, so a mid-recovery crash is a resume, not a disaster.** (This is the *behavioural* peer of the Q-a *transactional* fix.)

**Q-f — where do the guardian X25519 pubkeys + the guardian roster come from at the FFI layer for the forward-security re-seal?** (the #104b Q-c build sub-detail)
- *Term:* every successful recovery automatically re-seals fresh pieces to ALL M guardians — which means the recovering device must (re)obtain all M guardians' public encryption keys, even the ones who didn't participate.
- *Recommendation:* the FFI accepts the full guardian roster (all M X25519 pubkeys + EVM addresses) as an **input** to `vault_recover_from_shares` / `vault_onboard_guardians`; the host sources them from the recovered guardian-set backup (participants supply theirs with their piece; non-participants come from the backup config or opportunistic completion). The engine does NOT fetch them.
- *Plain-English stakes:* in a "lost everything" recovery the device has no local memory of who the guardians are, yet must re-seal new pieces to all of them. We've already decided (#104b Q-c) that the recovered guardian-set config carries those public keys. **Stakes: confirm the FFI takes the roster as a host-supplied input (the app is responsible for restoring it from the backup), rather than the engine trying to discover guardians itself.** Flag: if the roster restore mechanism (the backup format) isn't pinned, the re-seal can't complete — this is the one place the merged code doesn't yet hand the FFI everything it needs (see §6).

**Q-g — the recovery FFI error taxonomy.**
- *Recommendation:* route everything through the existing `FfiError::Recovery` variant with coarse, non-oracular categories (below-threshold, share-rejected, persistence-failed, chain-step-failed); collapse the cryptographic distinctions (wrong share vs tampered wrapper) the way `error.rs` already collapses wrong-password vs tampered-ciphertext.
- *Plain-English stakes:* error messages must help the user ("you need more guardians to approve") without leaking clues an attacker could use to probe the crypto. **Stakes: confirm coarse, safe error categories — useful for UX, useless as an oracle.**

## 6. Where the merged code does NOT cleanly support host exposure (GAP FLAGS)

1. **(Q-a / §3.1) The atomic commit needs `write_recovery_escrow` to relinquish its own transaction.** Today `write_recovery_escrow` opens + commits its OWN `unchecked_transaction()` internally (`recovery_escrow.rs:167`). To share one transaction with the meta re-wrap, #105a must refactor it to a `*_tx(&Transaction, …)` inner fn (the public fn becomes a thin open/commit wrapper). This is a small, mechanical, additive refactor — no behaviour change for existing #104b callers/tests — but it IS a change to a merged audited surface, so call it out for the in-house re-audit. **The good news (confirmed): `recovery_escrow`, `recovery_guardians`, and `meta` are all in the same `.pvf` and the `Vault` holds one `Connection`, so no separate-store fallback / write-ahead reconciliation is needed — a single transaction genuinely closes the gap.**
2. **(Q-f) The guardian-roster restore path is not yet a pinned surface.** `recover_vdk_from_shares` takes the full `&[guardian_x25519_pubs]` as an input (good — the pure driver is already roster-agnostic), and `read_recovery_escrow` returns the stored guardian pubkeys for an existing local vault. But in a *lost-everything* recovery there is no local vault to read from, so the FFI must accept the roster from a host-restored backup whose **format is not defined in the merged code** (#104b Q-c left "recovered guardian-set config carries the pubkeys" as a build sub-detail). #105b can take the roster as a host-supplied FFI input and defer the backup *format/transport* to 6.x, but the dependency must be flagged: **without a roster source, the mandatory forward-security re-seal cannot complete a lost-everything recovery.**
3. **(`Share` across FFI) The opened `Share` must cross from guardian-app to recovering-app without becoming readable bytes.** `recover_vdk_from_shares` consumes `Vec<Share>`, and `Share` is a `!Clone` zeroizing type with no `serde` (by #104b L1 design). Exposing the guardian's "open my share → hand it over" step over FFI needs an opaque `Arc`-Object carrier (the `SecretPassword` pattern) plus a serialization-for-transport story that does NOT route through `serde` on the secret path. #105b designs the opaque carrier; the *transport* (QR/app-channel) stays 6.x. Flag: this is the one place the zero-serde-on-secrets discipline and "must move between two apps" requirement are in tension — resolve with an explicit, audited, length-checked byte envelope, not a derived `serde` impl.

No other gaps: the #104b orchestration drivers, the #103 chain client, and the #100 handle model otherwise compose cleanly for host exposure.

## 7. Test posture

- **#105a (atomic persistence):** crash-injection regression gate (L11) — drive `commit_recovery_rekey`, force a rollback between the meta-write and the escrow-write (a test-only fault-injection hook or a transaction that fails its second statement), re-open the vault, assert OLD escrow + OLD daily wrap intact and NO new-epoch escrow row; positive path (commit succeeds → new epoch live, old shares dead, new password opens); the existing `write_recovery_escrow` round-trip + `recover_with_new_password` tests stay green through the refactor (proves the open/commit wrapper is behaviour-preserving).
- **#105b (FFI):** FFI round-trip on `VaultHandle` exercising onboard → (drive #103 lifecycle) → recover-from-shares → atomic commit, asserting only non-secret outputs cross and a session gate rejects every entry point on a locked handle (the #100 `is_placeholder`/`require_unlocked` pattern); a guardian-role round-trip (open share → sign Approve); an FFI error-taxonomy test (every recovery failure maps to `FfiError::Recovery` / the collapsed `Validation`, never `Internal`, mirroring `tests/error_taxonomy.rs`); extend (do not duplicate) #104b's coupled anvil E2E to drive through the FFI entry points where practical.

## 8. Effort + risk

~1 week for #105a (small, hermetic, high-value correctness fix) + ~2 weeks for #105b (boundary plumbing + the two-role surface + error taxonomy). NO new crypto, NO new deps (pure composition + a transaction refactor). Risk is concentrated in: (1) **the transaction refactor of an audited store fn** (mechanical but touches `recovery_escrow.rs` — the crash-injection gate is the structural defence), and (2) **the opaque `Share` carrier across FFI** (must not regress the zero-serde-on-secrets discipline — GAP 3). Lower headline risk than #104a/#104b; the value is closing a real at-rest forward-security hole and unblocking the recovery UX cycle.

## 9. Where it lives

- `crates/pangolin-store/src/vault.rs` — new `Vault::commit_recovery_rekey` (the atomic entry point); `recover_with_new_password` body refactored to write through a shared `&Transaction`.
- `crates/pangolin-store/src/recovery_escrow.rs` — `write_recovery_escrow` split into a `*_tx(&Transaction, …)` inner fn + a thin open/commit wrapper (additive, behaviour-preserving).
- `crates/pangolin-ffi/src/recovery.rs` (new) + re-exports in `lib.rs` — the recovering-device + guardian entry points, the `FfiOnboardingResult` / `FfiRecoveryResult` records, the opaque `Share` carrier; wires `FfiError::Recovery`.
- `crates/pangolin-chain/tests` — extend the #104b coupled anvil E2E to drive the FFI entry points.

## 10. Whitepaper / model alignment

#105 changes no crypto and no on-chain surface; it hardens the *engineering* around the merged Option-2 recovery. The dual-authority model (#104b §3 / L5: on-chain secp256k1 `vaultAuthority` + off-chain Ed25519 password-`AuthorityKey`, independent) is preserved; #105 only ensures the off-chain re-key + re-split persist atomically and become callable from the host. Recovery remains TESTNET-ONLY until D-011. No spec addendum needed beyond the #104b dual-authority clarification already flagged.
