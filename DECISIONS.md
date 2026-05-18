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

## D-016 · Per-IP-spec relicense (supersedes D-002)
**Date locked:** 2026-05-08
**Decision:** Core code in this repository is licensed under **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later). The Pangolin Licensing & Intellectual Property Specification mandates a per-layer license map: AGPLv3 for core applications (vault engine, sync logic, recovery logic, capture authority, local storage, session policy, TOTP handling, credential management); Apache-2.0 for SDKs, hardware integration specs, extension/agent APIs, client libraries, and protocol wrappers; CC BY-SA for documentation; trademark protection for Pangolin branding. The current PoC codebase falls entirely within the "core applications" layer, so the entire workspace ships under AGPL-3.0-or-later as of this commit. Apache-2.0 will apply to integration-surface crates as they land in MVP-1+ (FFI/UniFFI bindings, hardware integration helpers, agent SDKs). Per-crate `Cargo.toml` `license` fields are the canonical declaration; `LICENSE-RATIONALE.md` documents the layer map for verifiers and contributors.
**Why:** D-002 (locked at P0 on 2026-05-05) chose Apache-2.0 across the board because the IP spec had not yet been authored. The IP spec is the load-bearing source of truth for licensing strategy; AGPLv3 ensures hosted forks must publish modifications, modifications to security-critical behavior remain inspectable, and the ecosystem stays transparent — properties Apache-2.0 cannot guarantee. Re-licensing before the first GitHub push is materially less disruptive than re-licensing after public clones exist.
**Supersedes:** D-002 (Apache-2.0). D-002 stays as historical record; subsequent license discussion references D-016.
**Spec ref:** `Pangolin Licensing & Intellectual Property Specification` (`Desktop/Kelvinsinferno studio/Pangolin/Pangolin Licensing & Intellectual Property Specification.pdf`); see also `LICENSE-RATIONALE.md` at repo root.

## D-017 · MVP-2 RevisionLogV1 deployed address (Base Sepolia)
**Date locked:** 2026-05-14
**Decision:** `RevisionLogV1` deployed at `0x179362Ad7fb7dA664312aEFDdaa53431eb748E42` on Base Sepolia (chain id `84532`). Deploy tx `0x22e464123c7fc1c71a161350d521ed7946975b0a9a3b9fd232d8846327cacd19` in block `41639216` (timestamp `2026-05-14T18:07:28Z`). Deployer: `0x89e720238A3913688CB0E025ef03a64539575c54` (same Kelvin dev wallet as D-014/D-015 per 2.3 R-a). Runtime keccak256: `0x5220ac27b023082183b62e9739ae40692551aa4495e94bfe1f4c8da4cf727f43`. Runtime bytecode 1,825 B (matches the 2.1 plan-gate's audited size verbatim; well under EIP-170's 24,576 ceiling). Gas used 451,478 at 0.006 gwei = 0.0000027 ETH. **Verified source on Basescan** via the V2 multichain Standard-JSON-Input flow (the 2.3 deploy pipeline's auto-verify failed because foundry 1.0.0-stable pre-dates Etherscan's V2 endpoint migration; the wrapper's `--verifier-url` flag was switched to V2 in `b421f95` but the in-script verify path is blocked until foundry is bumped — see 2.3 follow-up below). Smoke-tested live: `MAX_KNOWN_SCHEMA_VERSION()` returns `1`; constructor took no arguments (the 2.1 contract has no constructor body).
**Why:** Per master plan §5 row 2.3 and 2.1 R-a. The MVP-2 RevisionLog v1 contract — adds on-chain signature verification (`ecrecover` + EIP-712 typed-data) + a write-additive device-key registry + per-event `uint16 schemaVersion` — is the substrate every MVP-2 sync issue (3.1 signed-revision client format, 3.3 direct-submit transport, 4.1 slow-mode chain sync) points at. v0 (D-014) stays append-only-immutable wherever it sits; v1 lives at this fresh address with the new signing primitive locked in 2.1 R-a.
**Spec ref:** Master plan §5 (MVP-2 row 2.3); 2.1 R-a (Path B signing primitive); full metadata in `contracts/deployments/base-sepolia.json` under the `RevisionLogV1` key.

## D-018 · MVP-2 EntitlementRegistry deployed address (Base Sepolia)
**Date locked:** 2026-05-14
**Decision:** `EntitlementRegistry` deployed at `0x08F8c394EB0c04ba0A4FBA1e64507b88F4b59D8d` on Base Sepolia (chain id `84532`). Deploy tx `0x914f5d97dc4b7c78e85ef3ab0d33d0e5c0fa741e3aaa407fc83461e028e94cd0` in block `41640322` (timestamp `2026-05-14T18:44:20Z`). Deployer: same Kelvin dev wallet as D-014/D-015/D-017. Runtime keccak256: `0xca252c6eaa70553a3fb040b9493c2b9db2a34fb7abc782a3ddeb74b1b35dd1f7`. Runtime bytecode 2,464 B (matches the 2.2 plan-gate's audited size). Gas used 593,592 at 0.006 gwei = 0.0000036 ETH. Constructor arguments (ABI-encoded, three 32-byte words): `PAYMENT_AUTHORITY = 0x89e720238A3913688CB0E025ef03a64539575c54`, `REDEMPTION_AUTHORITY = 0x89e720238A3913688CB0E025ef03a64539575c54`, `initial schemaVersion = 1`. **Per 2.3 R-b + 2.2 L8: both authority addresses set to the pangolin-dev wallet for the testnet deploy** — collapses 2.2's split-trust property (R-a of 2.2) but is the minimal smoke-test surface; no real money flows on testnet. Production-grade split keys ship with MVP-2 issue 3.4 (funder service) at a fresh deployment. **The testnet contract from 2.3 stays put as a smoke-test instance and is not wired to production.** Verified source on Basescan via the same V2 Standard-JSON-Input flow as D-017. Smoke-tested live: `PAYMENT_AUTHORITY()` returns the expected dev wallet; `MAX_KNOWN_SCHEMA_VERSION()` returns `1`.
**Why:** Per master plan §5 row 2.3 + D-008 (entitlement registry locked as the MVP-2 per-user paid-balance ledger). 2.2 ships the contract; 2.3 ships the deploy pipeline; D-018 records the resulting testnet smoke-test instance. Production-split-authority redeployment happens with MVP-2 issue 3.4; D-018 is not the production address.
**Spec ref:** Master plan §5 (MVP-2 rows 2.2 + 2.3); D-008 (entitlement registry); 2.2 R-a/R-b/R-e; full metadata in `contracts/deployments/base-sepolia.json` under the `EntitlementRegistry` key.

## D-019 · EntitlementRegistry redeploy with split authorities (Base Sepolia)

**Date locked:** 2026-05-17

**Decision:** `EntitlementRegistry` redeployed at `0xdDa04e427e95e50Cfd22703A76CAE2E1Da4F5fCD` on Base Sepolia (chain id `84532`). Deploy tx `0x06ab93d4b121a80283b1b6b035c4cc004f5e9859126e3039d7984d03981ba4b1` in block `41645807` (timestamp `2026-05-17T23:52:29Z`). Deployer: same `pangolin-dev` wallet (`0x89e720238A3913688CB0E025ef03a64539575c54`) as D-014/D-015/D-017/D-018. Runtime keccak256: `0xca252c6eaa70553a3fb040b9493c2b9db2a34fb7abc782a3ddeb74b1b35dd1f7` (identical to D-018 since contract source is unchanged — only constructor args differ). Runtime bytecode 2,464 B. Gas used 593,592 at 0.006 gwei = 0.0000036 ETH. Constructor arguments (ABI-encoded, three 32-byte words): `PAYMENT_AUTHORITY = 0x89e720238A3913688CB0E025ef03a64539575c54` (pangolin-dev wallet — issues Credit purchase attestations; same wallet that signed D-018), `REDEMPTION_AUTHORITY = 0xaeE7E9bf859d938CB087D1e567221cffba9455AC` (pangolin-funder-dev wallet — NEW keystore created 2026-05-17 via `cast wallet new $HOME/.foundry/keystores` then renamed; funded with 0.03 ETH from pangolin-dev via tx `0xe8ec3b563239b3b20ff44173dec7e33af8c799ec97c5698eca3068fdff354dbb`; signs redemption authorizations dispensed alongside ETH top-ups per 3.4 funder lifecycle), `initial schemaVersion = 1`. Domain separator pinned post-deploy: `0xb33d25188e5fc32cf5021ce63f28ee4ffb13d1d9a4ca720c46272f4c87c42fd0` (captured via `cast call <D-019> "DOMAIN_SEPARATOR()(bytes32)"`). **Production-grade key separation** per 2.2 R-a + 3.4 R-d: REDEMPTION_AUTHORITY compromise no longer enables balance inflation via `credit` (PAYMENT_AUTHORITY is a separate signer). Source `crates/pangolin-chain/src/secp256k1_signing.rs` constants `EXPECTED_ENTITLEMENT_REGISTRY_ADDRESS_BASE_SEPOLIA` + `ENTITLEMENT_DOMAIN_SEPARATOR_BASE_SEPOLIA_V1` updated in this commit to match. `contracts/deploy/.env.sepolia` updated to use the split-key addresses. `contracts/deployments/base-sepolia.json` adds the canonical `EntitlementRegistry` entry (D-019); the D-018 entry renamed to `EntitlementRegistry_D018_smoke_test_superseded` with cross-references. **D-018 (`0x08F8c394EB0c04ba0A4FBA1e64507b88F4b59D8d`) remains on chain** — immutable; no admin / pause / selfdestruct — as historical record but is NO LONGER referenced by any production code path. Smoke-tested live: `PAYMENT_AUTHORITY()` returns pangolin-dev; `REDEMPTION_AUTHORITY()` returns pangolin-funder-dev; `DOMAIN_SEPARATOR()` returns the pinned hex. Verification status VERIFIED via Basescan auto-attribution (2026-05-17) — D-019 has byte-identical runtime bytecode to D-018; Basescan's verifier auto-attributed D-018's already-verified source to D-019 without an explicit upload. Confirmed by checking https://sepolia.basescan.org/address/0xdDa04e427e95e50Cfd22703A76CAE2E1Da4F5fCD#code — green verified checkmark + "Similar Match: 0x08F8c394...8F4b59D8d" attribution line. No follow-up needed.

**Why:** Per master plan §4 row 3.4 + R-d of `docs/issue-plans/3.4.md`. 2.2's split-trust property (R-a) is load-bearing for the funder threat model (L-funder-wallet-key-leak): the REDEMPTION_AUTHORITY compromise must not also enable balance inflation via `credit`. D-018 collapsed authorities for the 2.3 smoke-test pass; D-019 ships real split keys under the same contract source. After CLI-V1 closed all functional MVP-2 deferrals (a458675), this is the first item in the pre-MVP-3 cleanup batch.

**Spec ref:** Master plan §4 row 3.4; `docs/issue-plans/3.4.md` R-d; full deploy procedure logged in `contracts/deployments/base-sepolia.json` under the canonical `EntitlementRegistry` key (D-019 supersedes the prior D-018 entry which is renamed to `EntitlementRegistry_D018_smoke_test_superseded`).

---

## MVP-2 issue 3.5 resolved decisions (R-a..R-e) — 2026-05-15

> **Status:** Locked at the 3.5 plan-gate by Kelvin's sign-off on
> Q-a..Q-e (`docs/issue-plans/3.5.md` "Resolved decisions" table).
> Builder agent shipped under `818cfa5..HEAD` of the
> `issue/3.5-balance-state` worktree.

### R-a · Balance-state tracker location — hybrid

The chain crate owns the balance/estimate logic as free async fns
(`pangolin-chain::balance_check::{query_evm_balance,
estimate_next_publish_cost, compute_balance_state}`); the `Vault`
grows a SYNC `evm_wallet_address` accessor that reads the cached
`devices.evm_address` column. Vault stays sync per the 1.5 / 3.2 /
3.3 doctrine. **Why:** preserves dep direction
(pangolin-store → pangolin-chain) + keeps the policy/mechanism split
(chain helper policy-agnostic; FFI accessor active-session-gated).

### R-b · Balance-check timing — both eager poll + per-publish freshness check

A `pangolin-chain::balance_monitor::BalanceMonitor` struct owns a
tokio background-poll task + an `Arc<RwLock<GasBalanceState>>`
cached state. Host starts via FFI (`balance_monitor_start`); the
monitor task refreshes every `BALANCE_POLL_INTERVAL_SECS = 30`.
SEPARATELY, `chain_submit::publish_revision_v1` performs a
SYNCHRONOUS pre-submit balance check BEFORE tx construction (gated
by `PublishConfig::pre_publish_balance_check_enabled`, default
`true`). A below-threshold balance → new variant
`ChainError::PrePublishBalanceInsufficient { balance_wei,
estimate_wei }`. **Why:** advisory monitor + authoritative
per-publish freshness check defends both UX (cached state for
rendering) and correctness (no doomed broadcast).

### R-c · Next-publish cost estimate — hybrid with `MIN_BUFFER_REVISIONS = 3`

Dynamic via `eth_feeHistory` → `max_fee_per_gas = 2*baseFee + 1
gwei` (reused from 3.3's formula verbatim) × `EXPECTED_REVISION_GAS
= 500_000` × `MIN_BUFFER_REVISIONS = 3`. On RPC error / empty
fee-history → fall back to `MAX_FEE_PER_GAS_CAP_WEI = 50 gwei`
(conservative ceiling). Computed value is clamped to the same per-tx
gas-cap defined in 3.3. **Why:** dynamic in the common case;
fail-safe pessimistic on RPC failure (under-stating the cost would
render `Sufficient` for a user who actually faces a spike).

### R-d · FFI surface — new method; `DeviceInfo` unchanged

`pub fn gas_balance_state(handle, monitor) -> Result<GasBalanceStateFfi,
FfiError>` reads the cached state. `balance_monitor_start` +
`balance_monitor_stop` (async) own the lifecycle. `DeviceInfo` shape
stays stable. Locked vault at the FFI boundary → `FfiError::Session`
(active-session-gated at the FFI policy layer; chain-crate helper
remains policy-agnostic per R-a). Wei values cross as **hex strings**
to preserve u128 fidelity. **Why:** mirrors §8.1.5 vocabulary; keeps
the `DeviceInfo` shape stable; matches 1.4 / 1.5's additive-FFI
discipline.

### R-e · Top-up trigger — two-step manual API

`pangolin-funder-client` ships `pub async fn initiate_top_up(funder_url,
credit, device_wallet) -> Result<TopUpAttempt, FunderClientError>`.
Host plumbs the Credit attestation at call-time + the device wallet's
secp256k1 signer. **NO** vault-stored attestations; **NO** auto-top-up;
**NO** CLI subcommand (CLI-V1 deferral per 3.1/3.2/3.3/3.4 precedent).
The monitor optionally accepts `BalanceMonitor::register_top_up(attempt)`
to transition cached state to `TopUpInFlight` until the next poll.
Adds `reqwest = "=0.13.3"` (`rustls` / aws-lc-rs; default-features
off; matches alloy's transitive reqwest version — the 0.12 line's
`rustls-tls` feature pulls the banned `ring`, hence the 0.13 pin) +
`uuid = "=1.10.0"` as direct funder-client deps. **Why:** master plan
§5 row 3.5 says "user pays out-of-band", which favours manual; Option B
(auto-top-up) widens vault on-disk surface materially and is MVP-3
territory.

**env-quirk #15 advisories result:** `cargo deny check advisories` +
`cargo audit` run before merge — see DEVLOG.

**Spec ref:** `docs/issue-plans/3.5.md`; `docs/architecture/ffi-surface.md`
(amended); `THREAT_MODEL.md` (gas-balance state machine row).

---

## MVP-2 issue 3.6 resolved decisions (R-a..R-d) — 2026-05-15

> **Status:** Locked at the 3.6 plan-gate by Kelvin's sign-off on
> Q-a..Q-d (`docs/issue-plans/3.6.md` "Resolved decisions" table at
> commit `a0f6d2a`). Builder agent shipped under the
> `issue/3.6-privacy-scaffolding` worktree.
>
> **Status of the deliverable:** **scaffolding only**; ZERO production
> logic for rotation / mixing / fresh-address ships in 3.6. Phase-2
> Enhanced Privacy Mode implementation is deferred to MVP-3 / MVP-4.
> See `docs/architecture/privacy.md` for the architectural overview
> and `docs/issue-plans/3.6.md` for the L1..L7 invariants verbatim.

### R-a · Abstraction shape — both `PrivacyMode` enum + `PrivacyStrategy` trait

The enum (`PrivacyMode::{Default, EnhancedPrivacy}`) is the user-
facing config surface; the trait (`PrivacyStrategy: Send + Sync`) is
the internal hook-points contract with three methods
(`derive_wallet_for_revision`, `transform_funder_response`,
`select_address_for_vault`). `DefaultStrategy` is a verbatim no-op
preserving 3.5 behaviour bit-for-bit (L1 + L4); `EnhancedPrivacyStrategy`
is a fail-loudly stub returning `PrivacyError::NotYetImplemented`
from every hook (L7). **Why:** matches the 3.4 `FunderSigner` trait +
`FileKeystoreSigner` impl pattern (user-facing config + trait-based
impl); architectural-locking property holds without the dyn-dispatch
overhead becoming a hot-path concern.

### R-b · All three Phase-2 modes scaffolded

Per-revision wallet rotation hook + CoinJoin pre-mixing of funder
top-ups hook + optional fresh-address-per-vault hook. CoinJoin reduced
to a placeholder method on the trait (no concrete mixer wiring — the
chosen mixer is a Phase-2 audit-gated decision). **Why:** Whitepaper
§8.3 names only CoinJoin; master plan §5 row 3.6 expands to all three
modes. 3.6 scaffolds master plan §5 row 3.6 per Kelvin's call; the
Phase-2 issue will reconcile the formal-spec gap. Closing all three
at the architectural level so MVP-3 / MVP-4 Phase-2 work has clean
plug-points for any of them.

### R-c · Central in `pangolin-chain::privacy` + distributed-impl consumer tests

Enum + trait + error type + `DefaultStrategy` / `EnhancedPrivacyStrategy`
impls all live in `crates/pangolin-chain/src/privacy/{mod.rs,
default.rs, enhanced.rs, tests.rs}`. NO new workspace crate. Consumer
crates (`pangolin-chain::secp256k1_signing`, `pangolin-store::Vault`,
`pangolin-funder-client`) ship 3.6 touchpoint tests asserting the
trait is callable + the no-op default preserves byte-identity at
their consumer boundaries. Production fn signatures are NOT yet
threaded with `&dyn PrivacyStrategy` parameters — that's Phase-2
work. The `pangolin-funder-client` dev-dep on `pangolin-chain` is
scoped to tests (the production L1 invariant of that crate is
preserved). **Why:** central declarations live where wallet
primitives already are (`pangolin-chain::evm`); impls live next to
the callsites they hook into; no new crate edge in production.

### R-d · Fail-loudly + byte-identity proof

Three test classes in `crates/pangolin-chain/src/privacy/tests.rs`:
(a) compile-time trait shape (`Send + Sync` on impls + on `Box<dyn
PrivacyStrategy + Send + Sync>` + variant-label pinning); (b) byte-
identity vs the 3.5 baseline (a `[u8; 65]` const captured from `main`
at `3227d38` via the builder-time
`crates/pangolin-chain/tests/baseline_capture.rs` harness; the 3.6
test re-runs the equivalent path through `DefaultStrategy` and
asserts byte-equality); (c) fail-loudly (3 tests, one per hook,
asserting `PrivacyError::NotYetImplemented { mode: EnhancedPrivacy,
hook: "..." }` fires). **Why:** the byte-identity property is the
load-bearing L4 invariant — CI catches a regression immediately.

### Whitepaper-§8.3-vs-master-plan-§5 gap (documented)

§8.3 names only CoinJoin mixing; master plan §5 row 3.6 expands to
THREE modes (rotation + CoinJoin + fresh-address-per-vault). 3.6
scaffolds master plan §5 row 3.6 per Kelvin's R-b call. The Phase-2
issue that lands the real impl will reconcile the formal-spec gap.

**env-quirk #15 advisories result:** TRIVIAL — L2 invariant verbatim
means no new external crate dep, so `cargo deny check advisories` +
`cargo audit` are unchanged from 3.5. See DEVLOG.

**Spec ref:** `docs/issue-plans/3.6.md`; `docs/architecture/privacy.md`
(new); `THREAT_MODEL.md` (new "Privacy Mitigation Phase-2 hooks
(3.6 scaffolding)" row). Master plan §5 row 3.6 + D-006 + Whitepaper
§8.3 are the underlying spec references.

---

## MVP-2 issue 4.1 resolved decisions (R-a..R-f) — 2026-05-15

> **Status:** Locked. Plan-gate sign-off in `docs/issue-plans/4.1.md`
> "Resolved decisions" table at commit `6ce608a`. Builder agent
> shipped under the `issue/4.1-chain-sync` worktree.
>
> **Scope:** ship the first MVP-2 issue that reads from chain — the
> §4 cluster's default-mode foundation. Consumes `RevisionPublished`
> events from D-017; filters by vault id; per-event recovers the
> secp256k1 signer via the production Rust v1 verifier
> (`recover_signer_v1` + `recover_signer_v1_raw`); feeds verified
> events into `Vault::ingest_pending_chain_revision` + advances a
> per-vault `last_synced_block` checkpoint. See
> `docs/issue-plans/4.1.md` for the L1..L12 invariants and the
> threat model rows for the load-bearing risks (L-rpc-spoof-events,
> L-rpc-omits-events, L-reorg-rollback, L-checkpoint-corruption,
> L-malicious-vault-id-substitution, L-verifier-domain-binding-drift,
> L-schemaVersion-future-poison).

### R-a · Checkpoint persistence — persist in `.pvf` (Option A + escape hatch)

New single-row `chain_sync_v1_state` table (id = 0; CHECK enforces
single-row) holds `(chain_env_tag, last_synced_block, last_synced_at,
schema_version)`. Distinct from the v0-era `sync_state` table so the
v0 readback + v1 chain sync advance independently. The `SyncOptions
{ from_genesis: true }` flag is the user-facing escape hatch (Option
C) — `pangolin sync --from-genesis` (future CLI-V1 batch) calls into
`Vault::sync_from_chain` with this option set. **Why:** the §4
cluster's "slow mode" framing matches "first sync is slow, subsequent
syncs are fast" — Option B (in-memory only) makes every session slow,
undermining the framing.

### R-b · Event fetch — WebSocket preferred, HTTP-poll fallback (deferred WS)

`ChainEventSource` enum (`WebSocket` / `HttpPolling`) tracks which
backend ran for `SyncReport.event_source`. The state machine + the
reconnect-with-backoff helper + the adapter that converts WS payloads
to the same shape HTTP polling produces are fully present in
`crates/pangolin-chain/src/chain_sync/{ws.rs, poll.rs}`. **NOTE on L8
deferral:** alloy's WS provider lives behind the `ws` feature on the
umbrella `alloy` crate; enabling it pulls `alloy-pubsub`,
`tokio-tungstenite`, `tungstenite`, and an OS-level tls stack. The
MVP-2 workspace `Cargo.toml` does NOT enable that feature (per L8 —
no new external crate dep in 4.1). The WS-open path in
`chain_sync::ws::open_subscription` returns `WsOpenError::Unavailable`
immediately so the orchestrator falls back to HTTP polling
unconditionally in this MVP-2 build. The MVP-3 issue 4.1.x feature-
flag flip is: (a) add `features = ["ws", ...]` to the `alloy` dep;
(b) replace the `Unavailable` branch in `open_subscription` with a
real `ProviderBuilder::new().on_ws(...)` call. Every other consumer
(the orchestrator, the reorg detector, the verifier) is shape-stable
across both branches.

### R-c · Reorg handling — two-stage optimistic finalize + rollback

`RevisionStatus::Pending { observed_at_block, block_hash }` for
optimistic 1-conf application; promote to `RevisionStatus::Finalized`
at depth ≥ `CONFIRMATION_DEPTH_FOR_FINALIZATION = 12`. The
`revisions` table gains three additive columns (`revision_status`
TEXT DEFAULT 'finalized'; `observed_at_block` INTEGER; `observed_block_hash`
BLOB). The reorg detector (`pangolin_chain::chain_sync::reorg::ReorgDetector`)
caches `(block_number → block_hash)` observations, compares against
canonical chain on every poll iteration, returns a `ReorgInfo`
window for the orchestrator to feed into
`Vault::rollback_pending_revisions_in_range(block_low, block_high)`.
`Vault::promote_finalized_revisions(current_head)` runs after every
chunk to advance pending → finalized at the 12-depth threshold. Tests
cover (a) happy-path 1-conf insert; (b) shallow 2-block reorg
rollback; (c) deep 10-block reorg rollback; (d) finalized rows never
rolled back; (e) depth-5 rows stay pending.

### R-d · Device cross-check — permissive auto-register

`devices` table gains two additive columns (`discovered_via_chain_sync`
INTEGER DEFAULT 0; `discovered_at_block` INTEGER). New helper
`device::auto_register_device_from_chain_sync(conn, evm_address,
discovered_at_block, now_ms) -> Result<bool>` inserts a synthetic
device row whose `device_id` is the EVM address left-padded with 12
zero bytes; idempotent via `INSERT OR IGNORE`. `public_key` is NULL
because the chain event carries no Ed25519 verifying key — the
contract emits only the secp256k1 signer's EVM address. **Why:** the
contract enforces device registration on-chain at publish time (per
2.1 R-b self-bootstrap), so any revision that's on chain has been
signed by a registered device. Client-side strict-check breaks
multi-device sync (a second device legitimately self-bootstrapping
looks "unknown" to the first device until it syncs).

### R-e · API surface — async-only on `pangolin-store::Vault` (L7-preserving)

The orchestration helper `Vault::sync_from_chain(&mut self, rpc_url,
env, vault_id, options) -> Result<SyncReport, StoreError>` lives on
`pangolin-store::Vault` (NOT on `pangolin-chain`) because the
direction `pangolin-chain → pangolin-store` would violate L7. The
primitives (signer recovery, event-decode + verify chunk fetch, the
reorg detector, the WS placeholder) live on `pangolin-chain` and
expose only sync-safe + async-safe public functions; the Vault-side
orchestrator drives them. The dep-direction concern flagged in
plan-gate R-e was the load-bearing call here — we adopted the
alternative shape (Vault hosts the orchestration; chain hosts the
primitives). L7 invariant verified: `cargo tree -p pangolin-chain
--no-default-features --edges normal | grep -c pangolin-store == 0`.

### R-f · Test surface — hermetic + reorg simulator (live `#[ignore]`'d)

Three test classes in `crates/pangolin-chain/src/chain_sync/tests.rs`
+ inline `crates/pangolin-store/src/vault.rs::tests`: (a) hermetic
with alloy `Asserter` — round-trip verifier (`recover_signer_v1` +
`recover_signer_v1_raw`); high-s rejection (LOW#3 defense-in-depth);
wrong-v-byte rejection; tampered-sig rejection; chain-id mismatch;
deployment-address resolution; foreign-emitter rejection; wrong
vault-id rejection; future-schema-version rejection;
signer-field-mismatch detection; (b) reorg simulator — shallow
2-block + deep 10-block + forget_window state mgmt; (c) Vault
accessor tests — `last_synced_block_v1` round-trip + monotonic
guard; rollback_pending skips finalized; promote_finalized at
12-conf threshold; auto-register idempotency. The live
`#[ignore]`'d `live_recover_signer_from_d017_history` test is NOT
shipped in 4.1 — Kelvin's call to defer pending the captured-event
hex pin (env-quirk #14: rerun + recapture when the next 3.3 / 2.3
deploy smoke produces a known event payload).

**Spec ref:** `docs/issue-plans/4.1.md`; `THREAT_MODEL.md` (new
"Slow-mode chain sync (read path + v1 verifier)" row). Master plan
§4 (slow-mode chain sync cluster) + §16.3 (chain reader / sync
security-critical surface) are the underlying spec references.

---

## MVP-2 issue 4.2 resolved decisions (R-a..R-f) — 2026-05-16

> **Status:** Locked. Plan-gate sign-off in `docs/issue-plans/4.2.md`
> "Resolved decisions" table. Builder agent shipped under the
> `issue/4.2-ephemeral-indexer` worktree.
>
> **Scope:** ship the structural skeleton for the opt-in fast-mode
> sync path. Stands up the `pangolin-indexer` crate as a single
> library + binary entry, wraps the SAME chain primitive 4.1 ships
> (`pangolin_chain::fetch_and_verify_chunk`) in a per-run temp DB
> backed lifecycle, defines the stdio JSON protocol the host uses to
> drive the indexer, and stubs the `TempDbCipher` trait so 4.3 can
> swap in the real AEAD impl without callsite churn. **4.2 is the
> skeleton; 4.3 is the security hardening (ephemeral key + zero-fill
> + AEAD layer); 4.4 is the mode-selector heuristic.** See
> `docs/issue-plans/4.2.md` for the L1..L12 invariants and the
> threat-model row for the load-bearing risks (L-temp-file-leak,
> L-vault-id-disclosure, L-stdio-injection, L-idle-timeout-DoS,
> L-spurious-spawn, L-host-indexer-mismatch, L-temp-dir-tampering).

### R-a · Crate organization — single crate (library + binary)

`crates/pangolin-indexer/` exposes `[lib]` + `[[bin]]` from one
Cargo.toml. `src/lib.rs` re-exports `IndexerSession`,
`IndexerConfig`, `IndexerRequest`, `IndexerResponse`, `IndexedEvent`,
`TempDbCipher`, `NoOpCipher`, `IndexerError`, and the lifecycle
constants. `src/bin/pangolin-indexer.rs` is a ~120-LoC shim that
wires argv (via clap) + stdio I/O + ctrl_c + idle-timeout +
`IndexerSession::handle_request` dispatch. NO separate
`pangolin-indexer-client` crate (plan-gate Q-a Option C was tabled
in favour of the simpler single-crate shape). **Why:** mirrors the
funder shape's substrate idea but without the cross-crate
bookkeeping; mobile in-process flow imports the library directly,
desktop subprocess flow spawns the binary — both call the same
`IndexerSession` API.

### R-b · Communication channel — stdio JSON (line-delimited, tag-discriminated)

Host writes one JSON `IndexerRequest` per line on the indexer's
stdin; the indexer writes one `IndexerResponse` per line on stdout.
Stderr is reserved for `tracing` logs (so the host can capture both
streams separately). `IndexerRequest` is a `serde(tag = "type",
deny_unknown_fields)` enum with variants `start_index`, `pull`,
`heartbeat`, `stop`; `IndexerResponse` is a `serde(tag = "type")`
enum (forward-compat: response fields can grow additively) with
variants `started`, `batch`, `progress`, `heartbeat`, `complete`,
`stopped`, `error`. Byte-bag fields (`vault_id`, `signer`,
`block_hash`, `tx_hash`, `parent_revision`, `device_id`,
`account_id`, `enc_payload`) are encoded as lowercase hex strings
without `0x` prefix for cross-platform JSON compat. **L-stdio-
injection defense:** `MAX_REQUEST_LINE_BYTES = 65_536` cap rejects
oversized lines before any parse attempt; unknown variants +
unknown fields are rejected via `deny_unknown_fields`. **L-host-
indexer-mismatch defense:** `IndexerResponse::Started` carries a
`protocol_version` field equal to const `PROTOCOL_VERSION = 1`; the
host MUST cross-check on receipt and abort on mismatch. Mobile
in-process callers skip the framing layer and call
`session.handle_request` directly with the same enums.

### R-c · Idle timeout — const default + env override with hard ceiling clamp

`pub const IDLE_TIMEOUT_DEFAULT_SECS: u64 = 300` (5 minutes per
D-007); `pub const IDLE_TIMEOUT_MAX_SECS: u64 = 3_600` (1-hour hard
ceiling — L-idle-timeout-DoS bound); `pub const
IDLE_TIMEOUT_MIN_SECS: u64 = 60` (lower floor for sanity).
`PANGOLIN_INDEXER_IDLE_TIMEOUT_SECS` env var overrides the default;
the resolver clamps the parsed value to `[60, 3_600]` so a hostile
env-var setting cannot push the timeout outside this range.
Invalid env values (non-numeric, empty) fall back to the
`300`-second default. Implementation: a pure function
`resolve_idle_timeout_from(raw: Option<&str>) -> u64` lets hermetic
tests exercise the clamp logic without process-global `env::set_var`.

### R-d · Temp DB security boundary — 4.2 ships skeleton + `TempDbCipher` trait stub

4.2 ships: (a) `tempfile::NamedTempFile::new_in(env::temp_dir())`
for random-path + OS-temp-dir cleanup-on-crash (L1 + L11);
(b) `pub trait TempDbCipher: Send + Sync + Debug` with
`encrypt_page(&self, plaintext) -> Vec<u8>` + `decrypt_page(&self,
ciphertext) -> Vec<u8>`; (c) `NoOpCipher` impl that returns input
unchanged; (d) lifecycle wiring (the `IndexerSession` holds an
`Arc<dyn TempDbCipher>`) + auto-delete on normal exit via the
field-declaration-order discipline (`Connection` drops before
`NamedTempFile` so the Windows unlink succeeds). 4.3 adds: (e) the
ephemeral per-run encryption key (256-bit random; never persisted;
process-memory-only); (f) `AeadCipher` impl (XChaCha20-Poly1305 per
page; reuses `pangolin-crypto`); (g) explicit zero-fill before
unlink; (h) potential SQLite cipher / raw-file AEAD integration.
**Architectural-locking property:** 4.3's swap is a single-line
constructor change (`NoOpCipher::new_arc()` →
`AeadCipher::new_arc()`); the trait surface stays.

### R-e · Mobile + desktop — library + binary, gated via Cargo features

Library exposes `IndexerSession` (mobile in-process entry + tests);
binary in `src/bin/pangolin-indexer.rs` wires argv + stdio +
`IndexerSession::run`. Cargo features: `default = ["bin"]`, `bin =
["dep:clap"]`, `test-utilities = []`. Mobile builds pass
`--no-default-features` to omit clap + the binary entirely.
`[[bin]] required-features = ["bin"]` ensures library-only builds
skip the binary compilation. The `test-utilities` feature exposes
`IndexerSession::temp_db_path` to integration tests + downstream
test harnesses (production-default OFF for L1 hygiene). L12
verified: the lifecycle code path is identical in both flows; the
only difference is how the host invokes it
(`std::process::Command::spawn(...)` vs.
`tokio::spawn(session.handle_request(...))`).

### R-f · Test depth — hermetic + cleanup-on-crash + `#[ignore]`'d live parity (max coverage)

Three test classes shipped: (a) **hermetic** —
`tests/hermetic.rs`: 26 tests covering constants pinning (R-c
clamp bounds; `PROTOCOL_VERSION = 1`; `PULL_BATCH_SIZE_MAX`;
`MAX_REQUEST_LINE_BYTES`), lifecycle (temp-file existence +
unlink-on-drop; Debug-impl path leak hygiene), stdio JSON
contract (round-trip + reject malformed + reject unknown variant +
reject unknown field), heartbeat / stop dispatch, pull-before-
start-index error, `NoOpCipher` round-trip + Send+Sync,
`IndexedEvent` JSON pinning. (b) **cleanup-on-crash** —
`tests/crash_cleanup.rs`: 5 tests covering panic-during-task →
Drop unlinks (L11 panic branch); task-completion → Drop unlinks;
multiple sessions get unique paths + all clean up; sync-context
Drop without async runtime; idle-timeout-driven cleanup path.
(c) **`#[ignore]`'d live parity** — `tests/parity.rs`: 1 test
that spawns the indexer against a live `BASE_SEPOLIA_RPC_URL` +
`PANGOLIN_INDEXER_VAULT_ID` env, drains, and (once a known D-017
event fixture is captured — same deferral as 4.1 R-f) compares
byte-for-byte against slow-mode 4.1 output. **Builder note on
fixture deferral:** no historical `RevisionPublished` event has
been captured from D-017 yet; the test docstring documents the
`cast logs` capture procedure for the operational follow-up.

**Test counts at SIGNOFF:** 35 lib + 26 hermetic + 5 crash_cleanup
+ 1 ignored live = 66 pass + 1 ignored. L7 invariant verified:
`cargo tree -p pangolin-indexer --no-default-features --edges
normal | grep -c pangolin-store == 0`. Lib-only build
(`cargo build -p pangolin-indexer --no-default-features`) succeeds
clean (R-e mobile flow). `cargo deny check advisories` clean (no
new deps beyond promoting `tempfile` from dev-dep to runtime dep
on the indexer); `cargo audit` 0 vulnerabilities, 2 allowed
warnings (unchanged from 4.1).

**Open follow-ups (deferred to 4.3 / 4.4):** (a) `AeadCipher` real
impl + ephemeral key + zero-fill before unlink (4.3 — the
`TempDbCipher` trait is the hook). (b) Mode-selector heuristic +
host wrapper that translates `IndexerResponse::Batch` →
`Vault::ingest_pending_chain_revision` (4.4). (c) Live parity test
event fixture capture — same deferral as 4.1 R-f; one-shot `cast
logs` against D-017 once a known event payload exists.

**Spec ref:** `docs/issue-plans/4.2.md`; `docs/architecture/indexer.md`;
`THREAT_MODEL.md` (new "Ephemeral local indexer (4.2 skeleton; 4.3
hardening)" row). Master plan §5 row 4.2 + D-007 (no persistent
indexer service) + §16.3 (chain reader / sync security-critical
surface) are the underlying spec references.

---

## MVP-2 issue 4.3 resolved decisions (R-a..R-e) — 2026-05-16

**Date locked:** 2026-05-16 (Kelvin: "use the most secure combination")

**Decision:** MVP-2 issue 4.3 (indexer security properties) ships the
real `AeadCipher` impl of 4.2's `TempDbCipher` trait, HKDF-derived
ephemeral key, and two-pass `secure_zero_fill` before unlink. Five
resolved decisions (Kelvin sign-off 2026-05-16):

- **R-a · Key derivation source.** Purpose-derived sub-key via
  `pangolin-chain::evm::derive_indexer_key(device: &DeviceKey,
  run_nonce: &[u8; 16]) -> SecretBytes`. HKDF-SHA256(IKM = device's
  Ed25519 secret seed bytes via `DeviceKey::secret_seed_bytes()`;
  salt = `run_nonce`; info = `"pangolin-indexer-tempdb-key-v1"`).
  32-byte output wrapped in `pangolin_crypto::SecretBytes`. Versioned
  domain separator distinct from `derive_evm_wallet`'s
  `"pangolin-chain-evm-wallet-v0"` and from
  `pangolin_crypto::keys::WRAP_KEY_INFO`'s `"pangolin-vdk-wrap-v0"`.
  Deterministic for `(device, run_nonce)` pair (verified by hermetic
  tests). The host (CLI / Vault wrapper) calls `derive_indexer_key`
  and passes the result to `AeadCipher::new_arc(key)`; the indexer
  binary itself generates a fresh random key per run (it never
  receives the device secret — minimum-blast-radius posture).

- **R-b · AEAD layer.** `AeadCipher` impl of `TempDbCipher` in
  `crates/pangolin-indexer/src/cipher.rs`. Each `encrypt_page`
  generates a fresh random 24-byte nonce via
  `pangolin_crypto::rng::fill_random`, seals via
  `XChaCha20Poly1305::seal(key, nonce, &[], plaintext)`, returns
  `nonce ‖ ciphertext_with_tag`. `decrypt_page` splits the nonce off
  + opens the AEAD, surfaces tag-mismatch as `CipherError::TagMismatch`.
  **Trait signature change vs 4.2:** `decrypt_page` now returns
  `Result<Vec<u8>, CipherError>` (was `Vec<u8>`) so tampered
  ciphertext propagates as a typed error rather than silently
  returning corrupt plaintext. `NoOpCipher` updated to match;
  production code path uses `AeadCipher` exclusively (`NoOpCipher`
  is gated behind `#[cfg(any(test, feature = "test-utilities"))]`).

- **R-c · Zero-fill discipline.** Two-pass overwrite
  `secure_zero_fill(&Path)` helper in
  `crates/pangolin-indexer/src/session.rs`: pass 1 writes 4-KiB
  chunks of cryptographically-random data via `fill_random` to the
  full file length + fsyncs; pass 2 overwrites with zeros + fsyncs.
  Then `NamedTempFile`'s Drop unlinks. **Override of plan-gate's
  single-pass-zero recommendation** — Kelvin's explicit
  "most-secure-feasible" choice. Called from `IndexerSession::Drop`
  via the loadbearing ordering: `Option::take(&mut self.conn)` →
  `secure_zero_fill(path)` → `Option::take(&mut self.temp_db)` so
  the SQLite handle is released BEFORE the overwrite re-opens the
  path (Windows-required). Documented limit: SSD wear-leveling may
  redirect writes; the AEAD encryption + ephemeral-key combination
  is the primary defense.

- **R-d · Memory wrapper.** `pangolin-crypto::SecretBytes` for both
  the derived indexer key + the `AeadCipher`'s stored key.
  **Override of plan-gate's `Zeroizing<[u8; 32]>` recommendation.**
  Stricter type discipline: callers must invoke `.expose()` to
  access the bytes, so leak paths are grep-able in audits. The
  `pangolin-indexer → pangolin-crypto` dep edge is added (new edge
  vs 4.2's set) — verified via `cargo tree` that `pangolin-indexer
  → pangolin-store` direction stays at 0 (the L7 invariant from
  4.2).

- **R-e · Test surface.** Hermetic + adversarial-decode (most-
  secure-feasible). (1) AeadCipher round-trip across input sizes 0,
  1, 100, 4096, 65536 bytes; (2) nonce-distinctness across 1000
  encryptions of identical plaintext; (3) adversarial decode —
  tag-tamper, nonce-tamper, body-tamper, wrong-key, truncated-frame
  all surface `CipherError::TagMismatch` or `FramingTooShort`;
  (4) zero-fill verification — write known plaintext, call helper,
  assert all-zeros final state; (5) `derive_indexer_key`
  determinism, nonce-sensitivity, device-sensitivity,
  EVM-wallet-domain non-collision.

**Why:** Master plan §5 row 4.3 ("encrypted with ephemeral key
derived from device secret") + D-007 verbatim ("Random-path
encrypted temp DB; explicit zero-fill before unlink; cleanup on
crash via OS-level temp-file conventions"). 4.2 shipped the
random-path + cleanup-on-crash properties; 4.3 closes the
L-temp-file-leak surface with the encryption + zero-fill +
ephemeral-key combination. Kelvin's "most-secure combination"
directive overrode the plan-gate recommendations on R-c
(single-pass → random+zero) and R-d (Zeroizing → SecretBytes).

**Deferred:** (a) The L-cipher-not-wired-into-sql-path raw-disk-
no-plaintext test from the plan-gate L-section — 4.3 ships the
AeadCipher trait surface + constructor probe but does not wire
the cipher into every BLOB column of `persist_chunk` /
`handle_pull`; the temp DB's per-column ciphertext wrapping is a
follow-on item that can land additively without a wire-format
break. The cipher is constructed, the probe runs end-to-end on
every session start, and the in-memory key is properly handled —
column-level wrapping is the next concrete step. (b) AAD per page
(`vault_id || page_id || schema_version`) — currently sealed with
empty AAD; the AEAD authentication still binds the page contents,
but cross-row replay within a session is not yet defended at the
AAD layer. (c) Per-run `run_nonce` persistence in the temp DB's
`indexer_meta` table — not needed in 4.3 because the binary
generates a fresh random key per run (cold restart = new key
anyway).

**Spec ref:** `docs/issue-plans/4.3.md` (R-a..R-e table line);
`crates/pangolin-indexer/src/{cipher.rs, session.rs}`;
`crates/pangolin-chain/src/evm.rs` (`derive_indexer_key`,
`INDEXER_KEY_DOMAIN`); `THREAT_MODEL.md` (updated "Ephemeral
local indexer" row); `docs/architecture/indexer.md` (4.2/4.3
boundary).

---

## MVP-2 issue 4.4 resolved decisions (R-a..R-e) — 2026-05-16

**Date locked:** 2026-05-16 (Kelvin reframed Q-a around first-sync
scenario; plan-gate recommendations adopted with the collapse
spelled out)

**Decision:** MVP-2 issue 4.4 (sync-mode selector) ships the
client-side picker that decides between 4.1's in-process slow-mode
sync and 4.2/4.3's ephemeral fast-mode indexer. Five resolved
decisions (Kelvin sign-off 2026-05-16):

- **R-a · Heuristic — first-sync-only.**
  `vault.last_synced_block_v1().is_none()` ⇒ `SyncMode::OfferFast`;
  else `SyncMode::Slow` (subject to R-b override). NO threshold,
  NO env-var override, NO `eth_getLogs` count, NO clamps. The
  ≥100-revision threshold from the master plan §5 row 4.4 wording
  collapses entirely. Long-offline-catchup users get slow-mode;
  tolerable UX cost.

- **R-b · Preference flag — three-state `meta.sync_mode_preference TEXT`
  column.** Values: `NULL` (= `Auto` = default), `'always_slow'`,
  `'always_fast'`. Additive nullable column, idempotent migration
  (`migrate_sync_mode_preference_column` in
  `crates/pangolin-store/src/schema.rs`), **NO `format_version`
  bump.** Mirrors the 1.4 `session_idle_secs` precedent byte-for-byte
  in shape — `read_sync_mode_preference` / `write_sync_mode_preference`
  in `meta.rs`, `Vault::sync_mode_preference` / `set_sync_mode_preference`
  accessors. Cleartext (L2) — UX state, not secret material.
  `SyncModePreference::from_meta_str(Some("garbage"))` returns
  `StoreError::Corrupted` so a tampered cleartext flag is loudly
  rejected rather than silently degrading.

- **R-c · API shape — pure picker as a `Vault` method.**
  `impl Vault { pub async fn select_sync_mode(&self, rpc_url: &str,
  env: ChainEnv) -> Result<SyncMode> }`. Returns the decision; caller
  renders prompt + spawns indexer on user assent (L1 — selector
  NEVER auto-spawns). **The `async fn` signature is locked even
  though the current implementation never awaits** — the API
  reserves the option for future heuristics to call
  `pangolin_chain::fetch_current_block_number` without breaking the
  public API. `rpc_url` + `env` parameters are placeholders for that
  future refinement; today the body only reads vault-local state
  (`last_synced_block_v1` + `sync_mode_preference`).

  **Deviation from plan-gate spec:** the spec literal showed
  `Result<SyncMode, ChainError>` but every other `Vault` method in
  `pangolin-store::vault` returns `Result<T, StoreError>` (= the
  crate's `Result<T>` alias). The picker fires no chain errors today
  (no RPC call) and surfaces only `StoreError::Sqlite` /
  `StoreError::Corrupted`, so `Result<SyncMode, StoreError>` is the
  correct taxon. `StoreError` already has a `From<ChainError>` impl
  for future heuristics that DO call the chain. The deviation is
  documented in the commit body + this entry.

- **R-d · Test depth — hermetic + doc-spec parity.** 11 unit tests
  + 1 const-pin test + 2 schema migration tests = 14 new tests
  total. NO proptest. NO live test (pure logic; env-quirk #14
  inapplicable). Coverage:
  `select_sync_mode_returns_offer_fast_for_first_sync`,
  `select_sync_mode_returns_slow_after_first_sync`,
  `select_sync_mode_respects_always_slow`,
  `select_sync_mode_respects_always_slow_with_checkpoint`,
  `select_sync_mode_respects_always_fast`,
  `select_sync_mode_respects_always_fast_with_checkpoint`,
  `sync_mode_preference_round_trip_always_slow`,
  `sync_mode_preference_round_trip_always_fast`,
  `sync_mode_preference_default_is_auto`,
  `sync_mode_preference_can_be_cleared` (incl. NULL-storage
  pin), `from_meta_str_rejects_unknown_value`,
  `sync_mode_preference_meta_str_round_trip` (exhaustive
  three-variant round-trip + literal-string drift defense),
  `migrate_sync_mode_preference_column_idempotent`,
  `migrate_sync_mode_preference_column_on_legacy_vault`.

- **R-e · `SyncMode` shape — 3-variant unit enum.**
  `enum SyncMode { Slow, OfferFast, AlwaysFast }`. Carries no
  payload (the heuristic doesn't compute a count; the host renders
  its own prompt copy). The plan-gate option of adding a
  `last_synced_block: Option<u64>` payload to OfferFast / AlwaysFast
  was rejected as YAGNI; the 3-variant unit-enum is the simpler
  shape and matches the "first sync OR explicit user preference"
  semantic exactly.

**Master plan §5 row 4.4 wording amendment.** Kelvin's reframing
during plan-gate sign-off shifted the row from "<100 unsynced
revisions → slow-mode in-process. ≥100 → offer 'Spin up faster
sync?'" to "first sync on this device → offer fast; else slow".
The threshold concept dropped entirely. Per project doctrine,
master plan §5 is NOT retroactively edited; DECISIONS.md is
authoritative for this amendment (same precedent as the 4.1 R-b
WS-deferral and the 4.3 R-c/R-d overrides). The plan-gate
`docs/issue-plans/4.4.md` is the load-bearing R-a..R-e source.

**Why:** The original master-plan threshold framing ("≥100 unsynced
revisions") assumed a block-distance proxy as a UX nudge; the actual
user scenario that ≥100 covers is almost exclusively first-sync-on-
this-device (a steady-state user with ≥100 unsynced revisions has
already configured their machine and is presumably online enough
that 100 won't accumulate uneventfully). Collapsing the heuristic
to "first sync" removes the threshold-tuning surface, the env-var
override surface, the clamp-range surface, and the eth_getLogs
counting surface — all in service of a UX nudge that the user can
override per-vault via the preference flag. The cleartext
preference flag is the right doctrine inheritance from 1.4 (UX
state belongs in `meta` cleartext alongside `session_idle_secs`,
not in the AEAD payload — L2).

**Deferred:** (a) FFI exposure of `select_sync_mode` /
`sync_mode_preference` accessors — deferred to a CLI-V1 batch
follow-up per 3.x/4.x precedent. (b) CLI subcommand wiring
(`pangolin sync-mode set always_slow` etc.) — same batch. (c)
`VaultMeta` export-struct integration (round-trip of the
preference through `.pvea` archive export/restore) — additive
follow-up; plan-gate explicitly defers per the "Affected crates"
table.

**Spec ref:** `docs/issue-plans/4.4.md` (Resolved decisions table);
`crates/pangolin-store/src/vault.rs` (`SyncMode`,
`SyncModePreference`, `Vault::select_sync_mode`,
`Vault::sync_mode_preference`, `Vault::set_sync_mode_preference`);
`crates/pangolin-store/src/meta.rs` (`read_sync_mode_preference`,
`write_sync_mode_preference`);
`crates/pangolin-store/src/schema.rs::migrate_sync_mode_preference_column`;
`THREAT_MODEL.md` ("Sync-mode selector (4.4)" deep-dive section);
`docs/architecture/chain-sync.md` (Sync-mode selector section).

---

## MVP-2 issue 5.1 resolved decisions (R-a..R-h) — 2026-05-16

**Date locked:** 2026-05-16 (Kelvin took plan-gate recommendations
across all eight Q's; the plan agent's two reframings — cross-account
batching impossible without contract redeploy, and 5.1 being a layer
on top of P8-2/P8-3 not a fresh queue — both stood)

**Decision:** MVP-2 issue 5.1 (publish queue + batching) layers a
**30-second same-account coalescing window** on top of the existing
P8-2 `dirty_accounts` table + P8-3 `publish_all` orchestrator so N
rapid edits to the same account within a 30s window flush as ONE
chain transaction (the latest revision; intermediate revisions stay
in the local lineage but their dirty markers are pruned before flush).
Per master plan §5 row 5.1 verbatim. Eight resolved decisions:

- **R-a · Window duration.** `pub const BATCH_WINDOW_SECS_DEFAULT: u64 = 30;` + `PANGOLIN_BATCH_WINDOW_SECS` env-var override clamped `1..=300`. Mirrors 4.2 R-c / 4.4 R-a precedent.

- **R-b · Drain triggers.** Mandatory: window elapsed + manual flush + four session-teardown paths (lock / idle-expire / 4h-absolute / `device_locked`). Optional caps: count = 100 dirty markers + byte = 1 MB total `enc_payload`. App-shutdown skipped (dirty markers are SQLite-persisted by P8-2; no in-memory state to lose).

- **R-c · Coalescing scope — per-account verbatim.** Cross-account batching at the chain layer is **impossible** without redeploying D-017 (the `RevisionPublished` event carries one `accountId` per call). Master plan's "multiple edits to same account" wording is the only feasible reading. N different accounts edited in the window = N chain txs (one per account, all submitted in the same flush invocation). No V3 schema_version bump, no payload format change.

- **R-d · Queue persistence — none new.** The existing `dirty_accounts` table IS the queue. 5.1 only adds in-memory window state to `ActiveState`: `window_started_at_unix_ms: Option<i64>`, `window_elapsed_flush_enabled: bool` (default `false` per L11), `last_flush_failed_balance: bool` (diagnostic). On-disk markers survive lock/crash unaltered. No schema change, no `format_version` bump.

- **R-e · Pre-flush balance gate — top-of-flush total-cost check.** Before any chain submit, sum `post_coalescing_count × estimate_next_publish_cost`; if balance < total, return `BatchFlushError::BalanceInsufficientForBatch { needed, available, queued_count }` BEFORE any chain submission. Per-revision gate (3.3 `pre_publish_balance_gate`) still runs as defense-in-depth. Everything-or-nothing semantics; rare multi-account flushes pick predictability over partial progress.

- **R-f · Blocked-queue append.** New edits during balance-block append to the dirty markers normally; the next flush attempt re-runs coalescing across the merged set. Local edits NEVER refused (vault is a local password store first; chain submission is asynchronous to local UX). Caps (R-b) clamp runaway growth.

- **R-g · Test surface — hermetic + 1 live `#[ignore]` test.** ~22 hermetic tests covering window state machine, coalescing rule (including tombstone-wins-tie and clock-skew resistance), drain on teardown via host orchestration, balance gate, caps, concurrency. One `#[ignore]`'d live test against D-017 (same posture as 3.3 / 4.1 / 4.2 / 4.3 R-f). No proptest.

- **R-h · Relationship to P8-2/P8-3 — LAYER + refactor.** Move `apps/cli/src/sync.rs::publish_all` + `publish_one` into a new `pangolin-store::publish` module. Both 5.1's new `Vault::flush_publish_queue` AND the existing CLI `publish_all` call into the same library helper. CLI's `publish_all` becomes a thin shell; behavior preserved verbatim (every CLI sync test passes UNCHANGED after the move).

**Why:** P8-2's `dirty_accounts` table already auto-tracks every edit at the SQL-transaction level; P8-3's `publish_all` already walks the list, dedupes via the A3 check, signs + submits + marks published. 5.1 is the 30s coalescing layer master plan §5 row 5.1 calls for — not a fresh queue. The cross-account batching framing in early plan-gate iteration was incompatible with the deployed contract; the plan agent caught this and Kelvin's "100+ unsynced is only original import" framing from 4.4 transferred directly to "multi-account edits in 30s is rare → everything-or-nothing balance gate is acceptable." 5.1 ships the queue primitive (manual flush + opt-in window-elapsed flush + drain-on-teardown via host orchestration); 5.4 will wire the always-on auto-flush.

**Drain-on-teardown deviation from plan-gate L1 wording:** the plan-gate L1 row read "queue ALWAYS drains on every session-teardown path." 5.1 ships the primitive (`flush_publish_queue`) but does NOT auto-invoke it from inside `Vault::lock()` / `check_session_freshness` / `device_locked()` because those methods are sync and `flush_publish_queue` is async. Forcing them async would ripple through every call site in 1.4 session policy + P2 lock semantics for a benefit the host can already achieve explicitly (calling `flush_publish_queue` before `lock()`). Dirty markers ALWAYS persist through teardown regardless. 5.4 will introduce the host-side orchestration layer that fires pre-lock flush automatically.

**Spec ref:** `PANGOLIN_PLAN.md` §5 row 5.1 ("Coalesce multiple edits to same account within 30s window into a single revision | Cost + UX"); `docs/issue-plans/5.1.md` (resolved decisions table + Q-a..Q-h disposition + L-section).

**Reference (load-bearing):** `crates/pangolin-store/src/publish.rs` (NEW module — extracted from CLI per R-h; hosts `publish_all_for_vault` / `publish_one` / `BatchFlushReport` / `BatchFlushError` / `PublishQueueState`); `crates/pangolin-store/src/vault.rs` (5.1 constants `BATCH_WINDOW_SECS_DEFAULT/MIN/MAX/ENV_VAR` + `PUBLISH_QUEUE_COUNT_CAP/BYTE_CAP_BYTES`; new methods `flush_publish_queue` / `publish_queue_state` / `enable_window_elapsed_flush` / `coalesce_dirty_markers` / `resolve_batch_window_secs`; `ActiveState` extension with the three new fields); `apps/cli/src/sync.rs` (thin-shell over `pangolin_store::publish`); `docs/architecture/publish-queue.md` (R-a..R-h spelled out + drain trigger matrix + API surface); `THREAT_MODEL.md` ("Publish queue + batching (5.1)" deep-dive section).

---

## MVP-2 issue 5.2 resolved decisions (R-a..R-f) — 2026-05-16

**Date locked:** 2026-05-16 (Kelvin took all four surfaced plan-gate recommendations; Q-d offline backoff + Q-f test surface defaulted to plan-gate defaults; plan agent's two key findings — `sync_from_chain` takes raw `rpc_url`/`env`/`vault_id` rather than `ChainAdapter`; zero `tokio::spawn` precedent in `pangolin-store` — both stood)

**Decision:** MVP-2 issue 5.2 (pull loop) ships the per-cycle async primitive `Vault::pull_once(rpc_url, env, &vault_id) -> Result<PullReport, PullError>` that re-runs the 4.4 sync-mode picker and dispatches: `Slow` delegates to 4.1's `Vault::sync_from_chain` verbatim (NO duplicate logic; inherits the full L1..L12 defensive surface); `OfferFast` / `AlwaysFast` return signal-only — the engine NEVER spawns the indexer subprocess (host owns that decision per 4.4 L1 + 5.2 L2). Per master plan §5 row 5.2 verbatim: "On unlock + periodic (every 60s while session active). Apply non-conflicted heads automatically." Six resolved decisions:

- **R-a · Pull loop location — host-owned timer.** Vault exposes the `pull_once(...)` async primitive only. The host (CLI / Tauri shell / mobile UI) owns the `tokio::time::interval` scheduler. NO `tokio::spawn` surface inside `pangolin-store` (preserves the zero-spawn discipline; verified by Grep that today the crate has zero `tokio::spawn` calls). Mirrors 5.1 R-h posture verbatim. 5.4's eventual `SyncOrchestrator` wires this naturally.

- **R-b · Interval shape.** `pub const PULL_INTERVAL_SECS_DEFAULT: u64 = 60;` + `PANGOLIN_PULL_INTERVAL_SECS` env-var override clamped `5..=3600`. The `5` lower bound defends L-pull-flood (12 pulls/min ceiling, well below any realistic RPC rate-limit); the `3600` upper bound caps staleness a malicious host wrapper could push. Helper pair `resolve_pull_interval_secs()` + `resolve_pull_interval_secs_from(env_value)` mirrors 5.1's `resolve_batch_window_secs[_from]` pattern verbatim for testability without `env::set_var` (which is a process-global side effect).

- **R-c · Picker invocation — re-pick per cycle.** Every `pull_once` call invokes `Vault::select_sync_mode` first; acts on the result. Cheap (single SQL read + None check; no RPC under the 4.4 first-sync-only heuristic). Preference flips take effect on the next tick. NO cache-invalidation surface. Note: under the 4.4 first-sync-only heuristic, once the first cycle's `Slow` path advances the checkpoint, every subsequent re-pick returns `Slow` deterministically. Additionally, every successful `pull_once` stamps `ActiveState.last_pull_at_unix_ms: Option<i64>` (diagnostic — 5.4 will consume for the "Synced N min ago" indicator state machine; not persisted across `lock()` / unlock).

- **R-d · Offline backoff — flat retry at 60s.** On `Err(PullError::Chain(_))`, the host's canonical loop body just retries on the next regular interval. Host scheduler concern; the engine does NOT implement backoff state; 5.4 owns the "Offline" indicator state machine. Exponential / linear backoff buys little against a 60-second cadence; 5.4 will fold this into the indicator state machine if needed.

- **R-e · Cancellation discipline — `PullError::NoActiveSession`.** Host scheduler's canonical loop body: `match vault.pull_once(...).await { Err(PullError::NoActiveSession) => break, ... }`. Mirrors 5.1's `BatchFlushError::NoActiveSession` posture verbatim. No new `tokio::sync` primitive; no new accessor. Worst-case lock→exit latency: one tick (≤60s default); the post-lock call returns immediately without any RPC (the `if self.active.is_none()` early-return short-circuits BEFORE the picker or any chain primitive — L-pull-after-lock-races defense).

- **R-f · Test surface — hermetic + 1 live `#[ignore]` test.** 14 hermetic tests in `crates/pangolin-store/src/pull.rs::tests` covering picker dispatch (OfferFast / AlwaysFast / re-pick per cycle / AlwaysSlow), cancellation (NoActiveSession on locked / device_locked / no-RPC-call-before-short-circuit), chain error + checkpoint preservation, env-var clamps (default / min / max / non-parseable / in-range), diagnostic stamp (set on Active / None on locked), error display + From-impls. Plus `crates/pangolin-store/tests/pull_live.rs` (`#[ignore]`'d live test against D-017 — deferred to fixture-capture follow-up; same operational posture as 4.1 / 4.2 / 4.3 / 5.1 live tests). No proptest (overkill for the simple state machine).

**Why:** Master plan §5 row 5.2 ("On unlock + periodic (every 60s while session active). Apply non-conflicted heads automatically.") is the spec. The plan-gate caught two load-bearing simplifications: (a) `pangolin-store` has ZERO `tokio::spawn` calls today (the codebase discipline is "host owns spawns"); a Vault-owned timer would have introduced the first spawn surface AND required either `Arc<Mutex<Vault>>` (refactor every call site) or `LocalSet` (forces a shape on every host) because Vault is `!Sync` — R-a host-owned posture cleanly avoids both. (b) `sync_from_chain` takes raw `rpc_url` + `env` + `vault_id` (NOT a `ChainAdapter`); the OfferFast / AlwaysFast branches are signal-only (host invokes the indexer with its own adapter machinery on accept). The builder shipped adapter-less `pull_once(rpc_url, env, &vault_id)` per the plan-gate's weak recommendation — minimal API surface; if 5.4's `SyncOrchestrator` later needs an adapter, the additive change is to introduce a second method that threads it through.

**Adapter-less API shape — builder discretion accepted:** The plan-gate left the choice between `pull_once(adapter, rpc_url, env, &vault_id)` and `pull_once(rpc_url, env, &vault_id)` to the builder, with a weak recommendation for adapter-less. The builder shipped adapter-less because (i) Slow-mode delegates to `sync_from_chain` which takes raw `rpc_url` / `env` / `vault_id`; (ii) OfferFast / AlwaysFast are signal-only (engine doesn't need an adapter); (iii) keeps the API minimal + matches what the underlying primitive already needs. No deviation from the plan-gate recommendation.

**Spec ref:** `PANGOLIN_PLAN.md` §5 row 5.2 ("On unlock + periodic (every 60s while session active). Apply non-conflicted heads automatically. | Convergence"); `docs/issue-plans/5.2.md` (resolved decisions table + Q-a..Q-f disposition + L1..L10 + L-section threat surface).

**Reference (load-bearing):** `crates/pangolin-store/src/pull.rs` (NEW module — `PullReport` + `PullError` + `PULL_INTERVAL_SECS_DEFAULT/MIN/MAX/ENV_VAR` constants + 14 hermetic tests); `crates/pangolin-store/src/vault.rs` (NEW methods `pull_once` + `resolve_pull_interval_secs[_from]` + `last_pull_at_unix_ms` + `ActiveState.last_pull_at_unix_ms` field); `crates/pangolin-store/src/lib.rs` (re-exports `pull::{PullError, PullReport, PULL_INTERVAL_SECS_*}`); `crates/pangolin-store/tests/pull_live.rs` (NEW `#[ignore]`'d live test); `docs/architecture/pull-loop.md` (NEW — R-a host-owned timer rationale + canonical host scheduler loop body + SyncMode dispatch table + env-var override + R-d offline backoff + R-c diagnostic stamp + drain triggers + UX contract for OfferFast + relationship to 5.1 + 5.4 + threat model cross-ref); `docs/architecture/chain-sync.md` (extended with §Pull-loop cross-ref); `THREAT_MODEL.md` ("Pull loop (5.2)" deep-dive section with seven L-rows).

---

## MVP-2 issue 5.3 resolved decisions (R-a..R-g) — 2026-05-16

**Date locked:** 2026-05-16 (Kelvin took all four surfaced plan-gate recommendations; Q-b self-publish defense + Q-f auto-resolve + Q-g test surface defaulted to plan-gate defaults; plan agent's key finding stands — 5.3 is FFI-surfacing + PullReport extension + ConflictReport enrichment + diff accessor on top of already-shipped 1.6/P8/P9 machinery).

**Decision:** MVP-2 issue 5.3 (conflict detection + resolution plumbing) ships the FFI binding for `list_conflicts`, a per-pull-tick conflict-diff signal on `PullReport`, the breaking-change enrichment of `ConflictReport` (per-branch metadata), and a thin `Vault::snapshot_conflicts` + `Vault::list_conflicts_since` accessor pair for the 5.4 indicator state machine. ZERO change to `ingest_chain_revision` / `refuse_if_frozen` / `canonical_head` election / merge-revision build paths — 5.3 surfaces the existing state; it does not re-trigger or re-elect. Per master plan §5 row 5.3 verbatim: "Core reports conflicts; UI consumes via FFI; publish-resolution path produces canonical head." Seven resolved decisions:

- **R-a · Auto-freeze trigger — confirm existing P8 CRIT-1 behaviour.** 5.3 ships ZERO change to `ingest_chain_revision`. The freeze fires today on every genuine-foreign-INSERT (covers both true fork AND fresh-foreign-account first-revision). Plan-gate Option A: smallest 5.3 footprint; no risk of regression on a heavily-tested P9 path. UX refinement deferred to MVP-3 user testing.

- **R-b · Self-publish loopback — confirm existing 5.1 flush + 5.2 idempotency arm #1.** 5.3 ships ZERO change. 5.1's `flush_publish_queue` stamps the anchor inline on the local row via `mark_published`; the next 5.2 pull-tick's `ingest_chain_revision` matches via idempotency arm #1 (exact-hash), returns `IngestOutcome::AlreadyPresent`, does NOT fire the freeze. Mandatory regression test `pull_after_local_publish_does_not_self_freeze` lands in `crates/pangolin-store/src/pull.rs::tests` — drives 5.1 `flush_publish_queue` against a `MockChainAdapter`, then replays the round-trip event through `ingest_chain_revision`, asserts `account_status().is_frozen_pending_resolve == false`. **The test PASSED on first run.**

- **R-c · PullReport extension — bake delta into PullReport.** Extend `PullReport` with `newly_frozen_accounts: Vec<AccountId>` + `newly_forked_accounts: Vec<AccountId>` + `newly_resolved_accounts: Vec<AccountId>`. Computed in `pull_once`: pre-tick snapshot of `(frozen, forked)` via `snapshot_conflicts`, post-tick snapshot, set-difference. Two extra cheap O(N-conflicted) queries per tick. Single-call surface; host scheduler gets per-tick deltas; set-difference is directional (already-frozen carry-overs do NOT re-surface, defending L-PullReport-delta-overcounts-on-existing-frozen).

- **R-d · ConflictReport shape — enrich (breaking change).** Replace `heads: Vec<RevisionId>` with `branches: Vec<ConflictBranchSummary { revision_id, parent, device_id, observed_at_block, schema_version, is_tombstone, on_canonical_chain }>`. Single round-trip for host's conflict-resolution screen. Breaking change bounded to `pangolin-store::conflict` tests + the conflict.rs tests themselves (`pangolin-cli resolve` does not consume `ConflictReport.heads` — it goes through `Vault::account_heads` directly; verified via Grep). The `observed_at_block` source-of-truth: prefer the chain-sync annotation set inside `ingest_pending_chain_revision`; fall back to `chain_block_number` from the `mark_published` anchor stamp for self-publish round-trips so the host UI always has *some* "first-seen-on-chain" anchor.

- **R-e · FFI binding — ship `vault_list_conflicts` in 5.3.** NEW `pub fn vault_list_conflicts(handle: Arc<VaultHandle>) -> Result<Vec<FfiConflictReport>, FfiError>` in `crates/pangolin-ffi/src/revision.rs`. `FfiConflictReport` + `FfiConflictBranchSummary` mirror the enriched `ConflictReport` in UniFFI-compatible form (flatten `RevisionId` → `Vec<u8>` per existing FFI convention). Per L2, the call does NOT decrypt, does NOT call `get_account` / `reveal_password`, does NOT touch the `refuse_if_frozen` guard.

- **R-f · Auto-resolve heuristics — defer.** No auto-resolve in 5.3 (no byte-identical, no last-writer-wins, no opt-in flag). Existing `Vault::resolve_fork` + `Vault::clear_frozen` are the only resolution primitives. Cardinal Principle 4 ("never silent merge") is bright-line. Revisits MVP-2 5.5+ at earliest, after user testing.

- **R-g · Test surface — hermetic + 1 live `#[ignore]`.** 14 hermetic tests (6 `conflict.rs::tests` + 8 new `pull.rs::tests`) + `crates/pangolin-store/tests/conflict_live.rs` (`#[ignore]`'d shape-only two-vault simulation — same operational posture as 5.1 / 5.2 live tests; fixture-capture is the follow-up). No proptest.

**Why:** Master plan §5 row 5.3 is the spec. The plan-gate caught the load-bearing simplification: the conflict-detection + freeze + canonical-head election + merge-revision-build paths are all already shipped under 1.6 + P8 + P9 and unchanged here; 5.3 is plumbing on top. The R-d enrichment is a one-time breaking change to fold N+1 host round-trips into a single call before any UI consumer ships (CLI-V1 deferred; Tauri / mobile shells haven't started). The R-c PullReport extension is the smallest-API-surface way to give the host scheduler the per-tick signal it needs.

**Plan-gate finding stood:** `pangolin-cli resolve` does NOT consume `ConflictReport.heads`; it calls `Vault::account_heads` directly. The R-d breaking change therefore had zero downstream call-site updates (other than the in-crate conflict.rs tests themselves).

**Spec ref:** `PANGOLIN_PLAN.md` §5 row 5.3 ("Core reports conflicts; UI consumes via FFI; publish-resolution path produces canonical head | Convergence"); `docs/issue-plans/5.3.md` (resolved decisions table + Q-a..Q-g disposition + L1..L11 + L-section threat surface).

**Reference (load-bearing):** `crates/pangolin-store/src/conflict.rs` (enriched `ConflictReport` + new `ConflictBranchSummary` / `ConflictSnapshot` / `ConflictDelta` + 9 hermetic tests); `crates/pangolin-store/src/vault.rs` (rewritten `list_conflicts` body + NEW `snapshot_conflicts` + `list_conflicts_since` + `read_observed_at_block` + free `diff_conflict_snapshots` + `pull_once` extension); `crates/pangolin-store/src/pull.rs` (extended `PullReport` with three `newly_*` fields + 8 hermetic tests including the mandatory `pull_after_local_publish_does_not_self_freeze` regression); `crates/pangolin-store/src/lib.rs` (re-exports `ConflictBranchSummary` / `ConflictDelta` / `ConflictSnapshot`); `crates/pangolin-store/tests/conflict_live.rs` (NEW `#[ignore]`'d live test); `crates/pangolin-core/src/lib.rs` (re-exports the new conflict types); `crates/pangolin-ffi/src/revision.rs` (NEW `vault_list_conflicts` FFI entry + `FfiConflictReport` + `FfiConflictBranchSummary`); `crates/pangolin-ffi/src/lib.rs` (re-exports); `docs/architecture/conflict-surface.md` (NEW — what 5.3 ships + per-cycle semantics + canonical host scheduler reaction loop + relationship to P9 resolve_fork + relationship to 5.4 indicator state machine + L1..L11 invariant preservation table + threat-model cross-ref); `docs/architecture/chain-sync.md` (extended with §Conflict-surface cross-ref); `THREAT_MODEL.md` ("Conflict surfacing (5.3)" row).

---

## MVP-2 issue 5.4 resolved decisions (R-a..R-h) — 2026-05-17

**Date locked:** 2026-05-17 (Kelvin took all four surfaced plan-gate recommendations; Q-c offline threshold + Q-d tick coordination + Q-f watch channel + Q-g test surface defaulted to plan-gate recommendations. The architectural blocker on engine-side orchestrator (R-a Options A/D) stands: `Vault` is intentionally `!Sync` (P4 audit M-3) so any background-task variant would require `Arc<Mutex<Vault>>` reworking every callsite — substantial structural change well out of scope for an MVP-2 tail-end issue. R-a Option C ships the smallest §5.x cycle.)

**Decision:** MVP-2 issue 5.4 (sync orchestrator state machine) ships the host-side indicator state machine that fuses 5.1 `flush_publish_queue` + 5.2 `pull_once` + 5.3 `snapshot_conflicts` + 4.4 `SyncMode` + 3.5 `BalanceMonitor` into a single 6-variant `SyncStatus` pill (`Synced` / `Syncing { mode }` / `Offline { consecutive_failures }` / `ConflictsPending { count }` / `BlockedOnBalance { needed_wei, available_wei }` / `ActionRequired { reason }`) that the host UI renders. ZERO change to `ingest_chain_revision` / `flush_publish_queue` / `pull_once` / `select_sync_mode` / `BalanceMonitor` behavior — 5.4 is read-side aggregation over inputs already shipped under 5.1 / 5.2 / 5.3 / 4.4 / 3.5. Per master plan §5 row 5.4 verbatim: "`Synced / Syncing... / Offline` state machine — Sync." 5.4 is the LAST functional MVP-2 §5.x issue. Eight resolved decisions:

- **R-a · Orchestrator location — pure host concept.** `pangolin-store` ships ONLY: SyncStatus enum + pure `compute_next_status(prev, inputs) -> SyncStatus` transition function + `Vault::sync_status_inputs()` bundling accessor + (R-e) `Vault::lock_with_drain` async method. Host (CLI / Tauri / mobile) owns the `tokio::interval` timer + the state-machine loop + the optional `tokio::sync::watch` channel. ZERO new tokio surface in engine; matches 5.2 R-a verbatim. Options A / D (engine-side `Arc<Mutex<Vault>>` background task) rejected — `Vault` is intentionally `!Sync` (P4 audit M-3); reconciliation would be a substantial MVP-3 cycle, not MVP-2.

- **R-b · SyncStatus enum shape — 6-variant single enum.** `Synced` / `Syncing { mode: SyncMode }` / `Offline { consecutive_failures: u32 }` / `ConflictsPending { count: u32 }` / `BlockedOnBalance { needed_wei: u128, available_wei: u128 }` / `ActionRequired { reason: String }`. Vocabulary follows §8.1.5 discipline (L5) — NEVER pricing copy. The indicator chip renders as a SINGLE pill; one variant at a time. The 6-variant superset captures the spec's 3 verbatim + the three load-bearing exception states.

- **R-c · Offline threshold — `OFFLINE_THRESHOLD_FAILURES: u32 = 3`.** Consecutive `PullError::Chain(_)` failures before transitioning to `Offline`. Counter resets on FIRST `Ok(_)` from `pull_once` (any variant — including signal-only OfferFast / AlwaysFast cycles per L4). At 60s pull cadence, ~3 min before the indicator surfaces a real outage; tolerates one-off RPC blips.

- **R-d · Tick coordination — interleaved two-timer host loop.** Pull fires when 60s pull-interval elapses; flush fires when 30s flush-window elapses; state-machine update on EITHER event. The canonical host loop body (`docs/architecture/sync-orchestrator.md`) uses `tokio::select!` with two timer arms. Each primitive's natural cadence preserved (5.1 R-a 30s + 5.2 R-b 60s).

- **R-e · Pre-lock drain — `Vault::lock_with_drain(adapter, device_key) -> Result<(), BatchFlushError>`.** NEW async method: runs `flush_publish_queue(force=true)` BEFORE dropping `active`; on flush failure (network / balance / store) STILL proceeds to drop `active` (best-effort per L3); flush error RETURNED to caller AFTER lock runs. Existing sync `lock()` untouched for emergency / device_locked paths. **Closes the 5.1 L1 deviation properly.**

- **R-f · Status accessor shape — read + watch channel (HOST-side).** Engine ships only SyncStatus enum + transition function; the `tokio::sync::watch::Sender<SyncStatus>` channel lives in HOST code (under R-a Option C). Host subscribes via `watch::Receiver<SyncStatus>`; UI re-renders on every change. Matches Tauri / mobile observer patterns; engine stays minimal.

- **R-g · Test surface — hermetic + 1 live `#[ignore]`.** 20 hermetic transition-function + Vault tests + 3 FFI tests + 1 live test in `tests/sync_status_live.rs` (`#[ignore]`'d; fixture-capture follow-up). No proptest. Matches §5.x precedent verbatim.

- **R-h · FFI exposure — ship `vault_sync_status` in 5.4.** NEW `FfiSyncStatus` UniFFI enum + `FfiSyncMode` mirror (4.4 didn't ship one; additive 1.1-surface amendment) + `FfiSyncStatusInputs` + `FfiSyncStatusSnapshot` + `vault_sync_status(handle, prev_status, inputs) -> Result<FfiSyncStatusSnapshot, FfiError>`. Thin wrapper: lift FFI inputs → call `Vault::sync_status_inputs` → call `compute_next_status(prev, inputs)` → bundle snapshot. Engine FFI does NOT hold orchestrator state. Wei values cross FFI as hex strings (`needed_wei_hex: "0x..."`) per 3.5 `GasBalanceStateFfi` precedent — preserves u128 fidelity past UniFFI's u64 integer limit.

**Why:** Master plan §5 row 5.4 is the spec ("`Synced / Syncing... / Offline` state machine — Sync"). The plan-gate caught the load-bearing simplification: 5.4's primitives are all read-side aggregation over already-shipped surfaces (5.1 publish queue + 5.2 pull cycle + 5.3 conflict snapshot + 4.4 sync mode + 3.5 balance monitor). The R-a Option C pure-host-concept choice is the smallest engine footprint that still ships the state machine; no `!Sync` Vault reconciliation. The R-e `lock_with_drain` primitive closes the 5.1 L1 deviation properly — the existing sync `lock()` cannot await a flush. The R-h FFI ships the indicator the host UI needs without deflecting the spec's "indicator chip" wording.

**Plan-gate findings stood:** (a) `Vault::!Sync` (P4 audit M-3) blocks engine-side orchestrator without substantial reconciliation; (b) 4.4 didn't ship an FFI mirror of `SyncMode` so 5.4 introduces `FfiSyncMode` as an additive 1.1-surface amendment; (c) u128 wei values must cross FFI as hex strings (3.5 BalanceMonitor pattern) because UniFFI's integer types max at u64 (= ~18.4 ETH in wei).

**Spec ref:** `PANGOLIN_PLAN.md` §5 row 5.4 ("`Synced / Syncing... / Offline` state machine — Sync"); `docs/issue-plans/5.4.md` (resolved decisions table + Q-a..Q-h disposition + L1..L11 + L-section threat surface).

**Reference (load-bearing):** `crates/pangolin-store/src/sync_status.rs` (NEW — `SyncStatus` 6-variant enum + pure `compute_next_status` + type-erased outcome shapes + 20 hermetic tests); `crates/pangolin-store/src/vault.rs::sync_status_inputs` (NEW bundling accessor); `crates/pangolin-store/src/vault.rs::lock_with_drain` (NEW pre-lock drain primitive — 4 hermetic tests in `lock_with_drain_tests` submodule); `crates/pangolin-store/src/lib.rs` (re-exports); `crates/pangolin-core/src/lib.rs` (re-exports SyncStatus / SyncStatusInputs / LastPullOutcome / LastFlushOutcome / PullErrorKind / BatchFlushErrorKind / compute_next_status / OFFLINE_THRESHOLD_FAILURES / SYNCED_STALENESS_THRESHOLD_MS); `crates/pangolin-ffi/src/sync_status.rs` (NEW — `vault_sync_status` + `FfiSyncStatus` enum + `FfiSyncMode` mirror + `FfiSyncStatusInputs` / `FfiSyncStatusSnapshot` records + 3 hermetic tests); `crates/pangolin-ffi/src/lib.rs` (re-exports); `crates/pangolin-store/tests/sync_status_live.rs` (NEW `#[ignore]`'d live test); `docs/architecture/sync-orchestrator.md` (NEW — what 5.4 ships + R-a host-owned loop rationale + canonical host scheduler loop body + SyncStatus transition table + pre-lock drain contract + relationship to 5.1 / 5.2 / 5.3 / 4.4 / 3.5 + threat-model cross-ref); `docs/architecture/pull-loop.md` (extended with §Sync-orchestrator cross-ref); `docs/architecture/publish-queue.md` (extended with §Sync-orchestrator cross-ref + §Pre-lock-drain); `docs/architecture/conflict-surface.md` (extended with §Sync-orchestrator cross-ref); `THREAT_MODEL.md` ("Sync orchestrator (5.4)" row covering L-offline-flapping + L-status-leaks-balance-detail + L-orchestrator-leaks-past-lock + L-conflict-pill-flashes-on-self-publish + L-balance-state-stale-vs-flush-error + L-pre-lock-drain-races-with-edit + L-pre-lock-drain-flush-failure-blocks-teardown).

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
(11 SIGNOFF entries between commits `ad54185` and `070258f`).
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
**Evidence:** P11-4 non-author rehearsal record (see `DEVLOG.md`
§ "Non-author rehearsal (P11-4)" under the P11 SIGNOFF entry)
captures a successful Scenario-1 cold-read walkthrough by a
non-author agent (Mock mode). Per P11 SIGNOFF + locked Q3 answer, Scenarios 2/3 are
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

---

## Issue CLI-V1 — CLI + FFI wiring batch (resolved 2026-05-17)

Closes the deferred §3.x / §4.x / §5.x CLI + FFI gaps. R-a..R-i
locked verbatim from `docs/issue-plans/cli-v1.md`:

| Resolution | Decision |
|---|---|
| **R-a** | Single CLI-V1 batch — ~1200 LoC, 7 new subcommands + canonical host scheduler + 12 FFI bindings in one cycle. |
| **R-b** | Mixed nested subcommand grammar: `sync flush\|queue-status\|pull-status\|loop` (verb-group) + `sync-mode show\|set` + `wallet show` + `balance show` + `top-up` (flat). |
| **R-c** | Ship both `sync loop` (long-running) AND one-shot verbs (`flush`, `pull`, `queue-status`, `pull-status`). Loop uses `lock_with_drain` on SIGINT. |
| **R-d** | Combined resolve mode — no-flag interactive TTY (via `std::io::IsTerminal`); flags-only preserved as scripted form. Non-TTY without flags → friendly error. |
| **R-e** | Universal `--json` on every new verb. Per-event lines stay on stderr; per-tick `sync loop` emits JSON-Lines on stdout when `--json` set. |
| **R-f** | Per-verb smoke + integration tests + a dedicated `sync_loop.rs` integration file. ~37 new tests across CLI + FFI. |
| **R-g** | Ship all 12 FFI gap fills: `vault_pull_once`, `vault_last_pull_at_unix_ms`, `vault_flush_publish_queue`, `vault_publish_queue_state`, `vault_enable_window_elapsed_flush`, `vault_coalesce_dirty_markers`, `vault_select_sync_mode`, `vault_sync_mode_preference`, `vault_set_sync_mode_preference`, `vault_lock_with_drain`, `vault_evm_wallet_address`, `vault_initiate_top_up`. **8 of 12 are fully wired in CLI-V1.** The remaining 4 (`vault_flush_publish_queue`, `vault_lock_with_drain`, `vault_pull_once`, `vault_initiate_top_up`) ship as **surface-locked stubs** returning `FfiError::Internal` with operator guidance ("use the CLI for now"); they require chain-adapter / signer / Credit-attestation UniFFI handles that aren't yet on the FFI surface (the `ChainAdapter` trait is async + `Send + Sync` + `BaseSepoliaAdapter::new_with_keystore` threads a `SecretBytes` keystore password — wrapping this for UniFFI is itself a substantial security-boundary cycle estimated at ~5-8h). **Follow-up cycle: `MVP-3-host-FFI-handles`** — to be created when MVP-3 host work begins (Tauri / iOS / Android shells); it wires the 4 stub bodies once the chain-adapter / signer / funder-credit UniFFI Objects ship. The stub signatures + record types (`FfiBatchFlushReport`, `FfiPullReport`, `FfiTopUpAttempt`) are locked so MVP-3 wires bodies without changing the wire shape; each stub has a parity test asserting the stub-as-stub error path. |
| **R-h** | Pre-lock drain retrofit on chain-touching commands only — `publish` / `pull` / `resolve` / `flush` / `sync loop` / `top-up` use `Vault::lock_with_drain`. Pure-local verbs keep `Vault::close`. |
| **R-i** | Hermetic test suite + one live `#[ignore]` test (`tests/sync_loop_live.rs`) that skips cleanly on missing env vars. |

---

## Issue 4.3-per-column-aead — closes §4.3-baseline audit deferrals (resolved 2026-05-17)

Closes the three documented audit deferrals from the §4.3-baseline
cycle (per-column wrapping, AAD binding, binary
key-derivation-not-pinned). R-a..R-e locked verbatim:

| Resolution | Decision |
|---|---|
| **R-a** | **Per-column wrapping.** `TempDbCipher::{encrypt_page, decrypt_page}` gain an `aad: &[u8]` parameter. `persist_chunk` wraps each of the 8 BLOB columns (`vault_id, account_id, parent_revision, device_id, enc_payload, signer, block_hash, tx_hash`) via the cipher before INSERT; `handle_pull` unwraps each via the cipher after SELECT. Integer columns (`page_seq, schema_version, sequence, block_number, log_index`) stay plaintext on disk (they're index / AAD / sort material, not secret). |
| **R-b** | **AAD format.** Fixed-width 42-byte concat: `vault_id (32) ‖ page_id_BE_u64 (8) ‖ schema_version_BE_u16 (2)`. Pinned by the new `PER_COLUMN_AAD_LEN: usize = 42` const + byte-pin test (`aad_byte_pin_for_known_triple` in `proptest_aad_perturbations.rs`). |
| **R-c** | **`page_seq` source = AtomicU64 (Option δ).** New `IndexerSession::page_seq_counter: AtomicU64` starts at 0 and increments by 1 per row inserted via `persist_chunk` (via `fetch_add(1, Ordering::SeqCst)`). The value is also persisted in a new `page_seq INTEGER NOT NULL UNIQUE` column in `cached_revisions` so `handle_pull` can reconstruct the AAD from the row's stored sequence (rather than counting rows). The UNIQUE constraint is defense-in-depth (a duplicate page_seq would surface as an INSERT failure rather than silently overwriting AAD-dependent data). Schema migration is in-place (ephemeral DB; no `.pvf` change). |
| **R-d** | **Test surface (Option C).** Hermetic in-source + 1 live `#[ignore]` + proptest module. ~38 new tests: 5 AAD-binding tests in `cipher.rs::tests`; 7 in `tests/raw_disk_no_plaintext_per_column.rs` (incl. `temp_db_file_contains_no_plaintext_after_persist`, `cross_page_cut_and_paste_surfaces_cipher_tamper`, `pull_after_persist_recovers_plaintexts_under_per_column_aad`, `page_seq_counter_increments_monotonically_across_persist_chunks`); 9 proptest cases in `tests/proptest_aad_perturbations.rs` (cross-page paste, cross-session replay, cross-schema paste, same-AAD round-trip, single-byte ciphertext perturbation, single-byte AAD perturbation × 1024 iterations each + byte-pin asserts + handshake CBOR round-trip); 4 in `tests/handshake_ipc.rs` (subprocess-spawn round-trip + truncated/oversize prefix rejection + `binary_random_key_path_removed` source-scan regression); 1 `#[ignore]` in `tests/live_per_column_wrap.rs`. |
| **R-e (ARCH-1)** | **Binary handshake — host derives + sends.** The standalone `pangolin-indexer` binary's `OsRng::fill_bytes` random-key path is REMOVED. Replaced with stdin handshake reading a length-prefixed CBOR `IndexerHandshake { derived_key: [u8; 32], run_nonce: [u8; 16] }` BEFORE the chain-RPC config and the protocol loop. Host caller (CLI / Tauri / mobile FFI) holds the `DeviceKey`, derives via `pangolin_chain::derive_indexer_key(device_key, run_nonce)`, and writes the handshake. Binary zeroizes the stdin buffer post-deserialise. New `crates/pangolin-indexer/src/handshake.rs` module ships the typed message + `ciborium-ll` CBOR codec + length-prefix framing + zeroize helper. Rejected alternatives: ARCH-0 (binary mints random key; defect: doesn't satisfy master plan §5 "derived from device secret"); ARCH-2 (binary imports DeviceKey directly; rejected on `L-indexer-grows-pangolin-crypto-secret-material-reach`); ARCH-3 (binary reads key file from argv; rejected as more complex without security benefit). |

**Closed audit deferrals:**
- **Deferral #1 (per-column wrapping):** CLOSED via R-a. Raw-disk-no-plaintext property is now mechanically enforced for the 8 BLOB columns; per-column-AEAD-wrapping integration tests run on every PR.
- **Deferral #2 (binary key derivation):** CLOSED via R-e ARCH-1. Master plan §5 row 4.3 "derived from device secret" property is now fulfilled by the host-side `derive_indexer_key` path; the binary's secret-material reach stays minimal (never imports `DeviceKey`).
- **Deferral #3 (AAD binding):** CLOSED via R-b + R-c. Cross-page-cut-and-paste, cross-session-replay, and future-schema-version-poison all manifest as `CipherTamper` at decrypt time.

**Forward-compat note for MVP-3-host-FFI-handles cycle:** the
`pangolin-cli` does not currently spawn the `pangolin-indexer`
binary; the host-caller contract is documented in the
`IndexerHandshake` docstring so MVP-3 host work wires the
spawn-and-write sequence mechanically. The handshake wire format
is FORWARD-COMPATIBLE — additive CBOR fields can land without
bumping the wire schema (the decoder rejects unknown keys via the
strict canonical-shape check, but a coordinated additive field
bump would relax the second-key check via the standard plan-gate
cadence).
