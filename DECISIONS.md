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

---

## Decision template (for future entries)

```
## D-NNN · <short title>
**Date locked:** YYYY-MM-DD
**Decision:** <one or two sentences>
**Why:** <rationale, with constraints or threats this addresses>
**Spec ref:** <which spec section this implements/derives from>
```
