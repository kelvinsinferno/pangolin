
## 9. Library selection (2026-05-20; for the auditor pre-opinion)

Verified against the codebase: HIGH-1 is `cargo tree -p pangolin-crypto | grep -ci serde == 0`. Existing set is all RustCrypto/dalek. Recommendations:

| Primitive | Crate (pin) | License | serde / HIGH-1 | Audit / advisories |
|---|---|---|---|---|
| Shamir / VSS | **`vsss-rs` 5.4, `default-features=false`, `features=["alloc"]`, Gf256 (constant-time GF(2^8)) field** | Apache-2.0 OR MIT | serde is in DEFAULT ⇒ MUST disable default-features; `dep:serde`-gated, `ecdh` path serde-free (verified from manifest). **BUILDER MUST `cargo tree -p pangolin-crypto` after adding to confirm count stays 0** (couldn't 100%-verify the transitive `serdect` edge without local resolution). VSS (Feldman/Pedersen) upgrade path in the same crate if the auditor wants per-share verifiability. | No RustSec advisories; RustCrypto/dalek ecosystem |
| X25519 seal | **`crypto_box` 0.9.1, `default-features=false`, `features=["seal","alloc","rand_core"]`** (libsodium sealed_box: ephemeral-X25519 → KDF → AEAD) | Apache-2.0 OR MIT | serde optional, NOT default (verified) | **Cure53-audited (v0.7.1), no significant findings**; no advisories; dalek ecosystem |

**Runners-up:** `gf256` crate's `shamir` module (constant-time, no serde, no VSS path) if vsss-rs's tree fails the serde check; `x25519-dalek` + hand-assembled HPKE (more ecosystem-consistent but hand-composed glue the auditor must review) for sealing.

**DISQUALIFIED: `sharks`** — RUSTSEC-2024-0398 (biased polynomial coefficients leak secret bytes when a secret is shared multiple times — exactly our failure mode). Unmaintained.

Shared transitive: both ride `curve25519-dalek` (we already do via `ed25519-dalek` v2; RUSTSEC-2024-0344 fixed ≥4.1.3 — managed, not new exposure).

## 10. Auditor pre-opinion ask (the package to put in front of the external firm — D-011)

- **Construction (Scheme A):** VDK wrapped twice — (a) daily under the password-derived key; (b) under a fresh 32-byte RecoveryWrapKey (RWK). RWK is t-of-M Shamir-split (t = on-chain guardian threshold 2..9, M = guardianCount 3..15) over constant-time GF(2^8) via `vsss-rs`. Each share sealed to a guardian's X25519 pubkey via `crypto_box` sealed-box. Recovery: collect ≥t shares → reconstruct RWK → unwrap VDK → re-wrap under a fresh RWK + re-split + re-distribute (rotation on every recovery).
- **Libraries to opine on:** `vsss-rs` 5.4 (Gf256, default-features off) for sharing; `crypto_box` 0.9 (`seal`) for per-share sealing — both Apache/MIT, RustCrypto/dalek ecosystem, on the same audited primitives as the existing `pangolin-crypto`.
- **Composition to opine on:** Shamir → seal-to-X25519 → reconstruct → unwrap → re-wrap/re-distribute; the HIGH-1 zero-serde invariant on the secret-bearing path; the dual-authority mapping (secp256k1 on-chain `vaultAuthority` vs Ed25519 password-derived wrap-authority + a fresh password on recovery).
- **Known/accepted properties (confirm acceptable, NOT findings):** (1) any t colluding guardians can reconstruct RWK — the intended threshold feature; (2) onboarding-device trust out of scope v1; (3) plain Shamir gives no per-share verifiability — ask whether they want Feldman/Pedersen VSS (same crate, no swap) for guardian-side verification at onboarding.

**NEXT ACTION (Kelvin-owned): engage the D-011 external audit firm for this pre-opinion before the Workstream-B build is locked.** The build LOCK + dispatch waits on the pre-opinion. (Sources for the library vetting are in the session log / DECISIONS.)
