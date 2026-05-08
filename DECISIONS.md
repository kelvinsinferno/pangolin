# Decision Log

> Locked architectural and operational decisions for Pangolin.
> Companion to the master plan (`../../.openclaw/workspace-studio-pangolin/PANGOLIN_PLAN.md`).
> Decisions in this file are **not relitigated without Kelvin approval.**

---

## D-001 · Codebase substrate
**Date locked:** 2026-05-05
**Decision:** Rust core (single source of truth) + Tauri/Swift/Kotlin shells. **Not** a KeePassXC fork.
**Why:** KeePassXC is reference-only — for KDBX import compatibility, local-vault behavior lessons, browser-extension implementation patterns, and PoC inspiration. The actual codebase is Rust core with thin platform shells from day one.
**Spec ref:** Whitepaper §B; Kelvin direction 2026-05-05.

## D-002 · License
**Date locked:** 2026-05-05
**Decision:** Apache-2.0.
**Why:** Explicit patent grant; same permissive baseline as MIT but better contributor protection. Re-license possible later if needed.
**Spec ref:** Master plan §2.

## D-003 · Execution model
**Date locked:** 2026-05-05
**Decision:** Claude Code is the executor. Subagents parallelize independent work. Kelvin reviews security-critical issues (§16.3) and authorizes external actions (App Store / Play Console / mainnet deploy / audit firm / brand taste / closed beta).
**Why:** No human dev team to hire or onboard. Agent-orchestrated execution with strict §16 protocol gates.
**Spec ref:** Master plan §1.5.

## D-004 · Sprint authorization
**Date locked:** 2026-05-05
**Decision:** Authorized. P0 begins immediately.
**Why:** Two consecutive weeks at "no sprint authorization" cleared.

## D-005 · Mainnet target chain
**Date locked:** 2026-05-05
**Decision:** Base. Privacy-chain optionality preserved as a **binding contract-portability constraint**: contracts must use no Base-specific opcodes and no L2-specific storage tricks. The vault data model must permit future dual-chain readability for migration.
**Why:** Cheap, fast, EVM, permissive faucets for testnet. Privacy chain may be added later (e.g., as an alternative deployment target for users who want it).
**Spec ref:** Whitepaper §D; master plan §2.

## D-006 · Gas / payment model — funder, not relay
**Date locked:** 2026-05-05
**Decision:** **No relay service.** Each device's keypair is both the revision signer (verified by contract) and the gas payer. Pangolin operates a one-way **funder service** that, on confirmed payment from the user, sends ETH to the requesting device's wallet. The funder never signs revisions, never submits transactions, never sees vault data, never holds custody of vault keys.
**Why:** Kelvin direction 2026-05-05. Eliminates relay infrastructure; keeps custody fully self-sovereign; "user never sees gas" promise satisfied by the wallet being built into the app and topped up automatically on payment.
**Privacy mitigation (Phase 2):** Device wallet addresses are observable on-chain — Enhanced Privacy Mode (CoinJoin pre-mixing of funder top-ups, optional per-revision wallet rotation) addresses this.
**Spec ref:** Master plan §5 (MVP-2 issues 3.2–3.6); Whitepaper §8.3.

## D-007 · Indexer model — no persistent service
**Date locked:** 2026-05-05
**Decision:** **No persistent indexer service.** Default sync = slow-mode direct chain reads. For large syncs (e.g., new device pulling 5,000 revisions), the client offers to spawn an **ephemeral local indexer**: runs on the user's own machine for the duration of the sync, indexes only the user's vault_id, and auto-deletes its temp database when sync completes or after idle timeout.
**Why:** Kelvin direction 2026-05-05. Eliminates persistent metadata leak risk. No multi-tenant correlation surface. No hosting question.
**Implementation:** `crates/pangolin-indexer/` library + standalone binary. Desktop spawns as subprocess; mobile runs as in-process thread. Random-path encrypted temp DB; explicit zero-fill before unlink; cleanup on crash via OS-level temp-file conventions.
**Spec ref:** Master plan §5 (MVP-2 issues 4.1–4.4).

## D-008 · Entitlement registry — same chain
**Date locked:** 2026-05-05
**Decision:** Entitlement registry contract deployed on the **same EVM chain** as the Revision Log.
**Why:** One deployment, one set of operational concerns, one set of audit targets.
**Spec ref:** Master plan §5 (MVP-2 issue 2.2).

## D-009 · Guardian threshold
**Date locked:** 2026-05-05
**Decision:** Contract-level enforced. **Floor: 2-of-3. Recommended default: 3-of-5. Ceiling: 9-of-15.**
**Why:** Below 2-of-3 social recovery is meaningless (1-of-1 is a single point of failure; 1-of-2 means either guardian can take over alone). 3-of-5 tolerates one guardian going dark plus one lying. 9-of-15 is the practical UX/gas ceiling.
**Spec ref:** Master plan §6 (MVP-3 issue 2.2 recovery contract); Whitepaper §F.

## D-010 · Team composition
**Date locked:** 2026-05-05
**Decision:** Subagent-parallel. Up to 4 builder agents in flight depending on phase (see master plan §9.6).
**Why:** Replaces human-team model. Coding throughput compresses; external dependencies (App Store, audit cycles, recovery delay windows) are the new bottlenecks.

## D-011 · External audit
**Date locked:** 2026-05-05 (deferred decision)
**Decision:** Deferred. Will revisit before MVP-3 mainnet deployment.
**Why:** Mandatory before MVP-3 (recovery contract is the highest-risk surface). Not blocking for PoC, MVP-1, or MVP-2 testnet.
**Spec ref:** Master plan §9.1.

## D-012 · Closed-beta size
**Date locked:** 2026-05-05 (deferred decision)
**Decision:** Deferred. Revisit when MVP-4 reaches feature-complete.
**Spec ref:** Master plan §11.

## D-013 · Repository location
**Date locked:** 2026-05-05
**Decision:** `C:\Users\kelvi\Projects\pangolin` (Windows host).
**Why:** Consistent with Kelvin's Mammoth-pattern of code in `Projects/`. Spec assets remain in `C:\Users\kelvi\Desktop\Kelvinsinferno studio\Pangolin\`.

## D-014 · PoC RevisionLog deployed address (Base Sepolia)
**Date locked:** 2026-05-05
**Decision:** `RevisionLogV0` deployed at `0x8566D3de653ee55775783bD7918Fe91b66373896` on Base Sepolia (chain id `84532`). Deploy tx `0x0569d60324c504bdacba08c309b85a54793b9002c97c4de22c9f8598e5e54b6a` in block `41133000`. Deployer: `0x89e720238A3913688CB0E025ef03a64539575c54` (Kelvin dev wallet). Runtime keccak256 (Ethereum Keccak-256, NOT NIST SHA3-256): `0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe`. Smoke-tested end-to-end: read + write + state mutation + event emission all verified. **Correction note:** P5-4's recording script accidentally used Python's `hashlib.sha3_256` (NIST SHA3-256, different padding) and recorded `0xaeff0a8fc34b478cb4c93b6f5bfd293cc12dd5f0a65a997c7c022b23f3e4e2d0` — wrong primitive. P6 audit M-1 caught this when `chaincli status` started cross-checking the live bytecode hash; corrected to the actual Keccak-256 value above. Live bytecode unchanged; only the recorded hash was wrong.
**Why:** Per master plan §3.7 (P5-4) and D-005 (Base is the testnet target). Recording here so downstream PoC issues (P6 chaincli, P7 chain adapter, P8 sync) point at a single canonical address. v1 (MVP-2 issue 2.1) will live at a separate address with signature verification; this v0 stays append-only-immutable wherever it currently sits on chain.
**Spec ref:** Whitepaper §D1; master plan §3.7 EPIC: Contract; full metadata in `contracts/deployments/base-sepolia.json`.

## D-015 · PoC RevisionLog redeploy proof (Base Sepolia)
**Date locked:** 2026-05-08
**Decision:** `RevisionLogV0` redeployed (unchanged source) at `0x74f28794c180bb1BEB698b294F69554D0ACCA9c4` on Base Sepolia (chain id `84532`). Deploy tx `0xe68ebcbbd342f71ae2e1766904c70f8fd2860c02c2c38142caad6bffc35d48c3` in block `41224971`. Same deployer wallet as D-014. Identical gas profile (149,135 gas at 0.006 gwei) to D-014 — same bytecode, same `solc 0.8.24` artifact, same expected runtime keccak `0xdbab504e86eca48cbedf61bb1fbc04ab17a5bb880d5a468cbb64e4b64e95c6fe`. **This contract is NOT wired to any production code path** — `chaincli`, `pangolin-chain`, `pangolin-cli` all continue to point at D-014's `0x8566...3896`. The redeploy is purely operational evidence.
**Why:** Closes §3.9 PoC → MVP gate criterion (4): "Contract redeployed at least once (proves redeploy-on-bug is real)." Per Q1 of P12 plan-gate, locked option (a) — actually redeploy rather than argue latent capability. Verified the existing `contracts/script/DeployRevisionLogV0.s.sol` script + Kelvin's `pangolin-dev` Foundry keystore + Base Sepolia testnet pipeline still works end-to-end as of 2026-05-08, two days after D-014.
**Spec ref:** Master plan §3.9 PoC → MVP gate; full metadata in `contracts/deployments/base-sepolia.json` under the `RevisionLogV0_redeploy_proof` key.

---

## PoC retrospective: PoC → MVP mapping

> **Status:** Locked at P12 SIGNOFF (2026-05-08).
> **Spec reference:** `PANGOLIN_PLAN.md` §3.9 (PoC → MVP gate);
> `docs/issue-plans/P12.md` §A12 (classification lens), §A13
> (verdict template).
> **Closes:** master-plan §3.9 PoC → MVP gate criterion (5)
> ("DECISIONS.md retrospectively updated: which PoC choices map
> to MVP, which are throwaway, which need rework").

This section is **the §3.9 retrospective**. It walks the five
master-plan §3.9 criteria and every D-NNN entry above, classifies
each, and names the follow-up items that close any criterion not
met at this tip.

### §3.9 criteria

Verdict values per `P12.md` §A13:
- **CLOSED** — criterion fully met; evidence is in-tree.
- **OPEN-WITH-EVIDENCE** — criterion met but evidence is manual
  / outside-the-tree (e.g., a YouTube link); reviewer takes the
  attestation on the maintainer's word.
- **NEEDS-FOLLOWUP** — criterion NOT met at P12 SIGNOFF; the
  retrospective names the follow-up item that closes it.

#### §3.9 criterion 1 — All 33 issues closed; P12 build artifact + screencast available

**Verdict:** OPEN-WITH-EVIDENCE.
**Evidence:** All P0..P11B issues SIGNOFF entries in `DEVLOG.md`
(11 SIGNOFF entries between commits `ad54185` and `1202`).
P12 commit chain (`d73c247`, `c3c0c19`, `d9b520e`, this commit,
SIGNOFF) lands the release-build pipeline (`scripts/release-windows.ps1`),
the polished `POC_README.md`, and the screencast script
(`docs/SCREENCAST_SCRIPT.md`). The actual recorded screencast is
a YouTube-unlisted upload Kelvin produces post-merge per
`P12.md` §A11; the URL lands in `POC_README.md` and the P12
SIGNOFF entry at attestation time.
**Outstanding:** The screencast video itself is recorded
out-of-tree; verdict moves to CLOSED once the URL is filled in
post-record.

#### §3.9 criterion 2 — `E2E_TESTS.md` reproduced by a non-author developer from clean clone

**Verdict:** CLOSED.
**Evidence:** P11-4 non-author rehearsal transcript at
`docs/issue-plans/P11-rehearsal.md` records a successful
Scenario-1 cold-read walkthrough by a non-author agent (Mock
mode). Per P11 SIGNOFF + locked Q3 answer, Scenarios 2/3 are
deferred from rehearsal; the rehearsal scope was sufficient to
validate the reproducer's cold-read clarity. P11-5 fix-pass
closed the three doc-gap findings (G1: count-from-3-to-5, G2:
mock vs live setup split, G3: smoke-output explanation) so the
reproducer-as-of-this-tip is the rehearsed-clean version.
**Outstanding:** None.

#### §3.9 criterion 3 — Code review of P1, P3, P7 confirms no plaintext written to disk

**Verdict:** CLOSED.
**Evidence:**
- **P1** (`crates/pangolin-crypto`) — SIGNOFF entry in `DEVLOG.md`
  at the P1 fix-pass; Cardinal Principle 2 ("no plaintext on
  disk; no plaintext leaves the device") is the audit's load-
  bearing invariant. The crypto crate ships zero I/O surfaces;
  all secrets transit `Zeroizing<Vec<u8>>` wrappers; serde is
  forbidden via `deny.toml` (`HIGH-1: cargo tree -p pangolin-crypto |
  grep -ci serde = 0`).
- **P3** (`crates/pangolin-store`) — SIGNOFF entry in `DEVLOG.md`
  at the P3 build + audit. Vault file format is encrypted-
  envelope; the only on-disk surface is the ChaCha20-Poly1305
  ciphertext + AEAD tag + KDF salt + nonce. SQLite cache for
  metadata is encrypted at the row level for fields that derive
  from secrets.
- **P7** (`crates/pangolin-chain`) — SIGNOFF entry in `DEVLOG.md`
  at the P7 build. The chain adapter ingests on-chain events as
  bytes-in/bytes-out — never deserializes structurally
  attacker-controlled payloads; the encrypted blob the contract
  carries is opaque to the chain crate (decryption happens in
  `pangolin-store` after pull, key-bound to the vault password
  + device key).

The P3 + P7 retro-walk at this tip confirms no regression: the
relevant crates have zero new I/O surfaces between their
SIGNOFF entries and `main` tip `329916d`. P11-4 rehearsal also
exercised the disk-write path (vault create + account add +
publish) without observing plaintext leakage.
**Outstanding:** None.

#### §3.9 criterion 4 — Contract redeployed at least once (proves redeploy-on-bug is real)

**Verdict:** CLOSED.
**Evidence:** D-015 (above). `RevisionLogV0` was redeployed at
`0x74f28794c180bb1BEB698b294F69554D0ACCA9c4` on Base Sepolia
(deploy tx `0xe68ebcbbd342f71ae2e1766904c70f8fd2860c02c2c38142caad6bffc35d48c3`,
block `41224971`). Same source, same `solc 0.8.24` artifact,
same expected runtime keccak256. Recorded in
`contracts/deployments/base-sepolia.json` under the
`RevisionLogV0_redeploy_proof` key. Per `P12.md` §8 Q1, locked
option (a) — actually redeploy rather than argue latent
capability — was selected. The redeploy is purely operational
evidence; `chaincli`, `pangolin-chain`, `pangolin-cli` continue
to point at the canonical D-014 address.
**Outstanding:** None.

#### §3.9 criterion 5 — DECISIONS.md retrospectively updated: which PoC choices map to MVP, which are throwaway, which need rework

**Verdict:** CLOSED.
**Evidence:** This section. Per-D-NNN classification + rationale
follows below.
**Outstanding:** None.

---

### Per-decision classifications

Classification values per `P12.md` §A12:
- **PERMANENT** — carries forward to MVP-N+ unchanged.
- **EVOLVES-IN-MVP-N** — survives but changes shape in MVP-N;
  the MVP-N issue list owns the evolution.
- **THROWAWAY-FOR-PoC** — served the PoC and is retired; no
  MVP-N successor.
- **NEEDS-REWORK** — known-defective; the PoC tip carries a
  surface that MVP-1+ must revisit before the next phase exits.

#### D-001 · Codebase substrate (Rust core + thin shells)
**Classification:** PERMANENT.
**Rationale:** The Rust core IS the codebase. MVP-1's CLI
hardening, MVP-2's contract evolution, MVP-3's mobile shells,
and MVP-4's beta polish all build on top of `crates/pangolin-{
core,crypto,store,chain,indexer,funder-client}`. The substrate
choice does not require revisiting; "thin shells" is reaffirmed
each phase as new shell layers (Tauri desktop, Swift iOS, Kotlin
Android) wrap the Rust core via UniFFI bindings. No change of
substrate is contemplated through MVP-4.

#### D-002 · License (Apache-2.0)
**Classification:** PERMANENT.
**Rationale:** License doesn't change between phases. Apache-2.0
covers all PoC..MVP-4 deliverables uniformly. The patent grant
remains the load-bearing rationale; nothing the MVP roadmap adds
challenges that.

#### D-003 · Execution model (Claude Code as executor)
**Classification:** PERMANENT (operational).
**Rationale:** Continues into MVP-1+ unchanged. Subagent
parallelization (D-010) and Kelvin's authority on
security-critical issues + external-action sign-offs (App Store,
audit firm engagement, mainnet deploy) carry through every
phase. This is an operational rather than architectural
decision; revisiting would imply hiring a human team, which the
master plan explicitly does not.

#### D-004 · Sprint authorization
**Classification:** THROWAWAY-FOR-PoC.
**Rationale:** D-004 was a one-time sprint-start unblock — the
"P0 begins immediately" gate that closed two weeks of
no-sprint-authorization. MVP-1 starts under standing
authorization (no per-sprint approval cycle implied by the
master plan). The decision text remains in this file as
historical record of when the PoC sprint actually began, but it
has no MVP-N successor.

#### D-005 · Mainnet target chain (Base)
**Classification:** EVOLVES-IN-MVP-2.
**Rationale:** Base remains the chain through MVP-2 (issue 2.1
deploys the v1 contract at a new address; issue 2.2 deploys the
entitlement registry on the same chain per D-008). The
**privacy-chain optionality** (binding contract-portability
constraint preserved in D-005's text) starts to bite at MVP-2:
v1's signature-verification logic + entitlement registry must
remain portable to a privacy chain target if MVP-3+ adds one.
The chain choice itself does not change; the surface deployed on
it does.

#### D-006 · Gas / payment model — funder, not relay
**Classification:** EVOLVES-IN-MVP-1.
**Rationale:** The PoC's two-key model (revision-signer + on-chain
payer being the same keystore) produces the freeze-on-pull
sentinel (CRIT-1; documented in P10 + P11 reproducer Scenario 1).
MVP-1's single-key model collapses the two roles into one
device key per device, removing the freeze surface. The
**funder service itself** (Kelvin's one-way ETH top-up on
confirmed payment) is MVP-2 work (issues 3.2–3.6); MVP-1
preserves the same-key signer + payer pattern but eliminates
the cross-device freeze by making each device's key a
first-class chain-acknowledged signer rather than a
shared-by-password derivation. The PoC's two-key model is the
load-bearing PoC compromise; it ships with documented quirks
(see `THREAT_MODEL.md` rows on freeze sentinels and
multi-resolve convergence) and does not survive into MVP-1
unchanged.

#### D-007 · Indexer model — no persistent service
**Classification:** PERMANENT (architecture).
**Rationale:** "Default sync = slow-mode direct chain reads" is
the load-bearing architectural commitment; "ephemeral local
indexer for large syncs" is the opt-in MVP-2 implementation
(issues 4.1–4.4). MVP-2 does NOT replace D-007; it implements
the latent ephemeral-local-indexer the PoC promised. The PoC
ships only the slow-mode path (no persistent service, no
ephemeral indexer either); MVP-2 adds the ephemeral surface
without changing D-007's architectural shape.

#### D-008 · Entitlement registry — same chain
**Classification:** EVOLVES-IN-MVP-2.
**Rationale:** PoC has no entitlement registry (the funder
service that drives entitlements is also MVP-2 per D-006); the
"same chain" commitment binds D-008's MVP-2 deployment target.
MVP-2 issue 2.2 introduces the registry on Base alongside the v1
RevisionLog (D-005-adjacent). Doesn't alter the PoC tip; the
decision is forward-loaded.

#### D-009 · Guardian threshold (floor 2-of-3, recommended 3-of-5, ceiling 9-of-15)
**Classification:** EVOLVES-IN-MVP-3.
**Rationale:** PoC has no guardians; MVP-3's recovery-contract
issue (master plan §6 issue 2.2 in MVP-3 numbering) introduces
the threshold contract with these floor / default / ceiling
values. The decision is forward-loaded; it doesn't constrain
the PoC tip but binds MVP-3's contract surface.

#### D-010 · Team composition (subagent-parallel)
**Classification:** PERMANENT (operational).
**Rationale:** Continues unchanged. Up to 4 builder agents in
flight remains the throughput model through MVP-4. The bottleneck
shifts (App Store review, audit cycles, recovery delay windows)
but the team-composition decision does not.

#### D-011 · External audit (deferred)
**Classification:** EVOLVES-IN-MVP-3.
**Rationale:** The decision text is itself "revisit before MVP-3
mainnet deployment." The recovery contract is the highest-risk
surface; an external audit is mandatory before MVP-3 ships to
mainnet. Not blocking for PoC, MVP-1, or MVP-2 testnet — those
phases stay in-house (peer-reviewed by Kelvin per §16.3). MVP-3
is where this decision converts from "deferred" to "active
engagement with an audit firm."

#### D-012 · Closed-beta size (deferred)
**Classification:** EVOLVES-IN-MVP-4.
**Rationale:** The decision text is itself "revisit when MVP-4
reaches feature-complete." MVP-4 owns the closed-beta cycle;
this decision converts then. Doesn't constrain PoC..MVP-3.

#### D-013 · Repository location (`C:\Users\kelvi\Projects\pangolin`)
**Classification:** PERMANENT (operational).
**Rationale:** Workspace path is stable. If it changes (e.g.,
Kelvin moves machines), that's an operational note recorded
in DEVLOG, not a re-decision. The repository's GitHub identity
(`github.com/kelvinsinferno/pangolin`) is the load-bearing
public reference and is unchanged.

#### D-014 · PoC RevisionLog deployed address (`0x8566D3...896` on Base Sepolia)
**Classification:** THROWAWAY-FOR-PoC.
**Rationale:** v0 (this contract) is the PoC's append-only log
without signature verification; MVP-2 issue 2.1 ships v1 at a
**different** address with on-chain signature verification, and
v1 supersedes v0 entirely. The PoC `0x8566D3...896` address is
preserved in DECISIONS.md as historical record (and remains
queryable on Base Sepolia indefinitely — append-only contracts
can't be retracted), but it is not the MVP-2+ target. The
**decision record** stays in this file forever; the **contract**
is throwaway. (Per `P12.md` §8 Q9: this classification refers to
the contract surface, not the historical decision-record entry.)

#### D-015 · PoC RevisionLog redeploy proof (`0x74f2...A9c4` on Base Sepolia)
**Classification:** THROWAWAY-FOR-PoC.
**Rationale:** Same logic as D-014. D-015 is the §3.9 criterion
(4) "redeploy-on-bug is real" proof; the contract itself is
identical bytecode at a fresh address, never wired into any
production code path. MVP-2 v1's deploy will be a third
address; D-015's contract is operational evidence only. The
**decision record** stays in this file as the §3.9 criterion-4
audit trail; the **contract** is throwaway.

---

### NEEDS-REWORK candidates surfaced during retrospective

**None.** Per `P12.md` §A12 rationale 2, the explicit absence
of NEEDS-REWORK items is the most important assertion of this
retrospective: P0..P11B audits caught their own bugs at SIGNOFF
time, and no PoC decision is known to be actively wrong for
MVP-1's purposes (only "evolves" or "throwaway" as classified
above).

If a future MVP-1 scoping pass identifies a NEEDS-REWORK
candidate (a PoC decision that's actively wrong, not just
throwaway), that finding lands as a new D-NNN entry above this
retrospective with a `Reworks: D-NNN` cross-reference; this
retrospective is not retroactively edited.

---

### Open follow-ups (criterion-level)

The §3.9 criteria walk surfaced exactly **one open follow-up**:

- **Criterion 1, screencast URL.** The recorded screencast is a
  Kelvin-recorded out-of-tree artefact (per `P12.md` §A7 +
  §A11). At the moment of this retrospective's commit the
  screencast URL is a placeholder in `POC_README.md`. Resolution
  steps:
  1. Kelvin records per `docs/SCREENCAST_SCRIPT.md`.
  2. Kelvin uploads to YouTube unlisted.
  3. Kelvin pastes the URL into `POC_README.md` and the P12
     SIGNOFF DEVLOG entry; criterion 1 verdict moves from
     OPEN-WITH-EVIDENCE to CLOSED at that commit.

No other criterion has an outstanding follow-up. Criteria 2, 3,
4, and 5 are CLOSED at this tip.

---

### Handoff to MVP-1

Items the MVP-1 issue-scoping pass inherits from this
retrospective:

- **EVOLVES-IN-MVP-1 candidates:** D-006 (PoC two-key →
  single-key migration). MVP-1's first issues should walk the
  freeze surface (per `THREAT_MODEL.md` rows on freeze
  sentinels) and scope the single-key replacement.
- **EVOLVES-IN-MVP-2 candidates:** D-005 (privacy-chain
  portability), D-008 (entitlement registry), D-014/D-015 (v1
  contract deploy at a new address with signature verification).
  MVP-2's contract-side issues consume these directly.
- **EVOLVES-IN-MVP-3 candidates:** D-009 (guardian threshold),
  D-011 (external audit engagement).
- **EVOLVES-IN-MVP-4 candidates:** D-012 (closed-beta size).
- **THROWAWAY items:** D-004, D-014, D-015 — no MVP-N successor.
  Historical record only.
- **PERMANENT items:** D-001, D-002, D-003, D-007, D-010,
  D-013 — carry forward unchanged.

The retrospective's classifications are the canonical reference
for MVP-1 issue scoping. If MVP-1 finds reason to revise a
classification, the revision lands as a new D-NNN entry; this
retrospective is not retroactively edited. (The PoC retrospective
is sealed at P12 SIGNOFF.)

---

## Decision template (for future entries)

```
## D-NNN · <short title>
**Date locked:** YYYY-MM-DD
**Decision:** <one or two sentences>
**Why:** <rationale, with constraints or threats this addresses>
**Spec ref:** <which spec section this implements/derives from>
```
