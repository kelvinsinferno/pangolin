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
| Revision Log v1 contract | MVP-2 | TBD (issue 2.1 plan) |
| Funder service | MVP-2 | TBD (issue 3.4 plan) |
| Ephemeral local indexer | MVP-2 | TBD (issue 4.2 plan) |
| Recovery contract | MVP-3 | TBD (issue 2.2 recovery plan) |
| Browser extension | MVP-4 | TBD (issue 7.2.x plans) |
| Native messaging boundary | MVP-4 | TBD (issue 7.2.2 plan) |
| iOS / Android autofill extensions | MVP-5 | TBD (issue 8.x plans) |
