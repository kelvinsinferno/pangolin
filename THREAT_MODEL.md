# Threat Model — Pangolin

> Living document. Initial scaffold from PoC bootstrap; populated to full spec as MVP-1 issue 0.2.
> Source: Whitepaper §4. **Threat-model claims must not be expanded without Kelvin approval (workspace research-agent rules).**

---

## Scope: what Pangolin defends against

- **Device loss or theft** — encrypted-at-rest local store; no plaintext on disk; biometric / PIN required to unlock.
- **Cloud or vendor compromise** — no vendor-hosted vault; server compromise reveals only encrypted blobs.
- **Account takeover via phishing** — domain binding on every credential request (API contract §4.3); origin mismatch blocks autofill.
- **Password reuse cascades** — per-account identity model; rotation history.
- **Service shutdowns or data unavailability** — vault works fully offline; chain log + ephemeral indexer mean no Pangolin-operated service is required for read.

## Out of scope: what Pangolin does NOT claim to protect against

- **Fully compromised operating systems** — OS root attacker can read process memory.
- **Kernel-level malware** — same.
- **Physical coercion** — Pangolin cannot defend against the user being forced to unlock under duress (Phase-2 Secondary Vault concept partially addresses this; not in MVP-1 scope).
- **Cryptographic failures** — if XChaCha20-Poly1305 or Ed25519 is broken, Pangolin breaks. We assume modern primitives are sound.

## Security invariants (to be expanded in MVP-1 issue 0.2)

These are non-negotiable. Every issue that touches a relevant surface must verify it does not violate any of these.

1. **No plaintext writes to disk.** All payloads encrypted client-side before any persistence (local store, log, network).
2. **Relay/funder/indexer cannot forge revisions.** Contract verifies client signature; all encryption client-side.
3. **Indexer cannot decrypt.** Serves encrypted blobs only.
4. **Recovery requires N-of-M + delay.** Enforced in contract; delay window cancelable by current authority.
5. **Session authority never stored on-chain.** Local-only, time-bounded, non-transferable.
6. **Guardians never see VDK.** Recovery rotates *authority* and re-wraps VDK; never re-derives.
7. **Hardware is never required.** Identity proof always satisfies as fallback.
8. **Capture authority is exclusive per context.** One component owns capture per browser/desktop/mobile.

## Threat enumeration (to be expanded)

Per-component threat enumeration lands as part of MVP-1 issue 0.2 and is updated continuously as new attack surfaces are added.

| Surface | Phase | Status |
|---|---|---|
| Local encrypted store | MVP-1 | TBD (issue 0.2) |
| Session policy engine | MVP-1 | TBD (issue 0.2) |
| Revision Log v0 contract | PoC | DOCUMENTED (P5-1) |
| Revision Log v1 contract | MVP-2 | TBD (issue 2.1 plan) |
| Funder service | MVP-2 | TBD (issue 3.4 plan) |
| Ephemeral local indexer | MVP-2 | TBD (issue 4.2 plan) |
| Recovery contract | MVP-3 | TBD (issue 2.2 recovery plan) |
| Browser extension | MVP-4 | TBD (issue 7.2.x plans) |
| Native messaging boundary | MVP-4 | TBD (issue 7.2.2 plan) |
| iOS / Android autofill extensions | MVP-5 | TBD (issue 8.x plans) |

### Revision Log v0 contract

> Source: `docs/issue-plans/P5-1.md` §"Threat enumeration". v0 is the PoC
> append-only log: zero on-chain validation, no admin keys, no upgrades.
> v1 (MVP-2 issue 2.1) will add signature verification and a "signer
> must be a registered device key for vaultId" check; the v0 differences
> are noted inline below.

1. **Adversary publishes garbage to a vault's log to slow sync.** Defense: clients filter by `vaultId` topic; per-vault `eth_getLogs` is unaffected by other vaults' garbage. Gas cost falls on the adversary. *v0 difference:* v0 has no on-chain authentication, so any address can call `publishRevision` with arbitrary bytes. v1 will require a valid signature; v0 explicitly does not.
2. **Adversary publishes a fake "next revision" forking a user's account.** Defense: client-side conflict detection (master plan MVP-1 issue 1.6) detects multiple heads. User resolves explicitly per Whitepaper §7. *v0 difference:* same client-side detection applies; v0's lack of signature checks does not change the resolution path because the client always treats on-chain data as untrusted.
3. **Adversary tampers with on-chain ciphertext.** Defense: AEAD AAD binds revision metadata (P1-1 design). Tampered ciphertext fails authentication on the client. The contract is *not* the integrity layer; AEAD is. *v0 difference:* none — encrypt-then-MAC on the client fails closed regardless of contract version.
4. **Chain reorg or network partition.** Defense: clients tolerate reorgs by tracking `(blockNumber, logIndex)` per known revision; on reorg, re-pull from the last known stable block. Out of scope for the contract; in scope for `pangolin-chain` (issue P7). *v0 difference:* none — reorg tolerance is a client concern.
5. **Permanent contract corruption (storage attack).** Defense: contract has only one storage slot (`nextSequence`); no functions write to other slots. The `invariant_noStorageMutationBesidesSequence` test asserts this under fuzzed call sequences (10,000 runs × 32-call depth in CI). *v0 difference:* v0 has no mappings, but the invariant additionally probes a sample of hashed (mapping-style) slots so the assertion future-proofs for v1's mapping storage.
