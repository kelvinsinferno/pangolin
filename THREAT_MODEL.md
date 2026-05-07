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
| Local encrypted store | PoC | DOCUMENTED (P2) |
| Session policy engine | MVP-1 | TBD (issue 0.2) |
| Revision Log v0 contract | PoC | DOCUMENTED (P5-1) |
| Pangolin chain adapter (`pangolin-chain`) | PoC | DOCUMENTED (P7) |
| Pangolin sync orchestrator (`pangolin-cli`) | PoC | DOCUMENTED (P8 + P9) |
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

### Local encrypted store (`pangolin-store`)

> Source: `docs/issue-plans/P2.md` §"Threat enumeration". The
> `pangolin-store` crate persists vaults as single `.pvf` SQLite files
> with all sensitive payload bytes wrapped in `XChaCha20-Poly1305`
> AEAD ciphertext bound by a deterministic 105-byte AAD. The crate
> consumes only `pangolin-crypto`'s public API; it ships no new
> primitives.

1. **Attacker reads disk image of locked vault.** Defense: every sensitive value lives inside an AEAD-sealed BLOB column. Decrypting any blob requires the `AuthorityKey`-derived wrap key, which requires the user password. The vault file's structural metadata (account count, revision parentage, timestamps) is visible — same as the on-chain log; this is a known design tradeoff (see threat #1 of the Revision Log v0 row above).
2. **Attacker steals a `WrappedVdk` blob.** Defense: AEAD ciphertext is computationally infeasible to break absent the password. The wrap key is derived through `HKDF-SHA512(authority.seed_bytes, info = "pangolin-vdk-wrap-v0", L = 32)`; the authority itself is reconstructed from `Argon2id(password, salt, params)` via `AuthorityKey::from_seed` at every unlock.
3. **Attacker tampers with row contents to cross-account or cross-vault transplant.** Defense: every revision blob's AEAD AAD binds `WRAP_AAD_DOMAIN_REV (8B "pgrev0\0\0") || vault_id (32B) || account_id (32B) || parent_revision_id (32B) || schema_version (1B)` for a fixed 105-byte deterministic encoding. A row whose `account_id` (or `parent_revision_id` or `vault_id` or `schema_version`) has been edited authenticates with a different AAD than the one used at seal time and the open path returns `AeadError::Tampered`, which `pangolin-store` collapses to `StoreError::AuthenticationFailed`. Verified by the `adversarial_cross_account_row_transplant_fails` integration test.
4. **Attacker has memory dump after vault was unlocked.** Defense: every secret-bearing type implements `ZeroizeOnDrop` and routes through `BoxedSecret` (heap-allocated, wiped in place on drop) or `SecretBytes` (Zeroizing-wrapped Vec). `Vault::lock` drops the in-memory `DecryptedCache`, which transitively drops every `AccountSnapshot` and zeroes its `SecretBytes` fields. Best-effort; not a guarantee against attackers with kernel-level access (out of scope per top-level threat model).
5. **Concurrent corruption from two opens.** Defense: `Vault::open` takes a sidecar `.lock` file via `OpenOptions::create_new(true)`; a second open observes the file and returns `StoreError::AlreadyOpen`. Verified by the `vault::tests::double_open_fails` unit test. After a hard crash the lock file remains and operators must remove it manually before reopening — documented operational hazard, not a security failure.
6. **Format-version downgrade attack.** Defense: `Vault::open` reads the `format_version` byte from the meta row before any AEAD work and surfaces `StoreError::UnsupportedFormatVersion` for any version newer than this build understands. Verified by the `adversarial_unknown_format_version_clean_error` integration test (which writes `99` directly to the meta column).
7. **KDF parameter tampering on disk.** Defense: KDF params live in plaintext on the meta row (they MUST be readable before unlock to feed the same Argon2id parameters back into `derive_seed`). Sub-floor params are rejected by `KdfParams::validate` at `pangolin-crypto`'s public boundary; tampering that keeps params in-range but changes their values (e.g., shifting `time_cost`, or flipping a bit in the salt) produces a different derived seed. Both cases collapse into `StoreError::AuthenticationFailed` via the `From<KdfError>` impl in `error.rs`, which means an attacker who tampers with the KDF params cannot distinguish the result from a salt-tamper or ciphertext-tamper or wrong-password attempt — the failure variant is identical across all four cases (this collapsing is the MEDIUM-1 fix from the P2 audit; previously a separate `KdfRejected` variant let the attacker oracle the cause). Verified by the `adversarial_kdf_param_tampering_fails` integration test, which exercises both sub-floor and salt-tamper paths and asserts both surface `AuthenticationFailed`.

### Pangolin chain adapter (`pangolin-chain`)

> Source: `docs/issue-plans/P7.md` §"Failure modes considered" and the
> P7 build-gate. The `pangolin-chain` crate wraps the deployed
> `RevisionLogV0` contract behind an async `ChainAdapter` trait;
> `BaseSepoliaAdapter` is the production impl, `MockChainAdapter` the
> test-only impl gated behind the `test-utilities` feature.

1. **Adversary-controlled RPC returns garbage logs.** Defense: alloy's
   typed `sol!` binding decodes every `RevisionPublished` log
   structurally; a misbehaving response that does not match the ABI
   surfaces as `ChainError::Decode` and is never silently consumed.
   `pull_since` additionally re-checks the emitter address per log
   (audit MEDIUM-4 from the P6 chaincli build) — server-side filters
   already exclude foreign emitters, but a misbehaving RPC could
   splice in logs from other contracts that share the topic-0 hash;
   those are dropped without surfacing.
2. **Wrong-chain RPC redirects.** Defense: every constructor checks
   `eth_chainId` against the deployment file's declared `chain_id`
   at construction time and refuses to proceed on mismatch with
   `ChainError::WrongChain`. Same fail-closed posture chaincli holds
   (P6 audit M-3).
3. **Tampered deployment file.** Defense: `Deployment::load` enforces
   `chain_id == 84_532` (Base Sepolia) and the address is parsed from
   the file with a strict `Address::parse` that rejects malformed
   hex. The runtime-bytecode keccak cross-check is NOT mirrored from
   chaincli into pangolin-chain because the adapter is not the
   "truth-serum" surface — that's chaincli's role; an audit
   follow-up could lift the keccak check into the adapter at the cost
   of an extra `eth_getCode` per construction.
4. **Tx revert on publish.** Defense: receipt status flag = 0
   surfaces as `ChainError::Reverted { tx_hash }` carrying only the
   tx hash. The caller (P8 sync orchestration) decides retry policy.
5. **Chain reorg after a successful publish.** Defense: out of scope
   for P7. Every successful `publish` is treated as anchored even
   though the block could theoretically reorg out. P8 (sync
   orchestration) is responsible for detecting reorgs by re-checking
   `(block_number, log_index)` across pull cycles. Documented at the
   `BaseSepoliaAdapter` level; the trait does not expose a reorg API
   in v0.
6. **EVM address observability.** Defense (acknowledgement, not
   mitigation): the `evm::derive_evm_wallet` derivation produces a
   secp256k1 wallet whose 20-byte address is the gas-paying signer
   for every revision the device publishes. Anyone observing the
   chain learns that all revisions paid by this address come from
   the same device — i.e., the device's gas wallet is a stable
   pseudonymous identifier across writes from the same device. This
   is a known privacy tradeoff per D-006; the matching tradeoff for
   the device-id field on each revision is documented in the
   `RevisionLogV0` row above. Phase-2 mitigations (per-publish
   relayed payment, address rotation) are deferred to MVP-2 issue
   3.4.
7. **Ed25519 → secp256k1 derivation correlation.** Defense: the
   derivation goes Ed25519-sign over a domain message → 64-byte sig
   → HKDF-SHA256 expand → 32-byte secp256k1 scalar (rejection-sampled
   if it lands at zero or ≥ N). The HKDF expand is one-way: an
   attacker who recovers the secp256k1 scalar (e.g., from a leaked
   keystore) cannot recover the Ed25519 secret seed in polynomial
   time. Same-seed → same-address determinism is asserted by
   `evm::tests::derive_is_deterministic`; cryptographic separation
   is structural via HKDF.

   *Cryptographic assumption (P7 audit HIGH-1, named explicitly):*
   the security argument requires **Ed25519-deterministic-sign to be
   treated as a PRF in the seed when the message is fixed** —
   i.e., for a fixed domain message `m` and uniformly random 32-byte
   seed `s`, `Sign(s, m)` is computationally indistinguishable from
   uniform 64 bytes to any adversary that does not know `s`. This is
   not a standard Ed25519 hardness assumption, but it is structurally
   similar to one that deterministic Ed25519 already relies on
   internally: RFC 8032 §5.1.6 derives the per-signature nonce as
   `r = SHA-512(prefix || msg)` with `prefix` being a seed-expanded
   half, and the signature-unforgeability proof requires that round
   of SHA-512 to be PRF-like in `prefix`. The composition
   `Sign(seed, fixed-msg) → HKDF-Expand(...)` extends that one-round
   assumption to the full Ed25519 primitive plus an HMAC-SHA256-based
   HKDF expand; each additional layer can only preserve or strengthen
   the PRF property. Directionality: the leak of the secp256k1 scalar
   does NOT leak the Ed25519 seed (HKDF-Expand is one-way via HMAC
   preimage resistance); the reverse direction is the derivation
   itself, no hardness claim required.
8. **Signed-revision forgery (cross-device).** Defense: `signing.rs`
   binds the canonical hash to `device_id` (= the device's Ed25519
   verifying key bytes), and the signature is verified under that
   embedded pubkey. An attacker who substitutes a different `device_id`
   into a captured `SignedRevision` will not have the matching secret
   key to re-sign, and the existing signature will fail verification.
   Asserted by `signing::tests::substituted_device_id_fails_verification`.

   *v1 forward-prep — what actually transfers (P7 audit HIGH-2).* v0
   contract does NOT verify signatures on-chain (P5-1 audit threat #2);
   v1 (MVP-2 issue 2.1) will. The earlier framing claimed P7 was
   "forward-prep so MVP-2 doesn't need a client-side migration"; that
   overstated the case. Two plausible v1 paths exist and only the
   *canonical-hash* part is path-independent:

   - **Path A: Solidity Ed25519 verifier.** Cost ≈ 500k gas per
     verification (lower-bound figure for current pure-Solidity
     Ed25519 implementations). On Base mainnet (an L2) at typical 2026
     fees that's ~$0.01–0.02 per verify; on Ethereum L1 it's
     ~$25–50/verify, which makes Path A L2-only in practice. Under
     Path A, the existing `signing.rs` API surface
     (`SignedRevision`, the Ed25519 `signature` field, `device_id`
     semantics as Ed25519 verifying-key bytes, `build_signed_revision`,
     `verify_signed_revision`) survives unchanged.
   - **Path B: v1 switches to secp256k1.** Likely on L1 mainnet for
     cost reasons (`ecrecover` is the 3 000-gas precompile, ~150x
     cheaper than the cheapest Solidity Ed25519). Under Path B,
     `device_id` semantics change from Ed25519 verifying-key bytes to
     a secp256k1 EVM-address (or a separately-registered v1 device
     key per vault), the `signature` field type changes, and the
     canonical-hash construction may need re-keying so the digest
     binds the secp256k1 identity. The current `signing.rs` is
     Path-A-shaped; Path B would require a new `secp256k1_signing.rs`
     (or a refactor to a generic `Signer` trait abstracting both
     primitives), and stored `SignedRevision` records on disk would
     need to be re-signed before re-broadcast under v1.

   What survives in **both** paths: the canonical-hash structure
   (keccak256 of fixed-width fields, payload reduced to its keccak
   digest, versioned domain separator). What survives in **only
   Path A**: the Ed25519 signature semantics and the current
   `signing.rs` API. The honest claim is: "the canonical-hash
   construction transfers; the signature primitive may not".
9. **`MockChainAdapter` substitution in production.** Defense: the
   mock is `cfg(any(test, feature = "test-utilities"))`-gated.
   Production downstream consumers (`pangolin-store`, `pangolin-cli`)
   do not enable the `test-utilities` feature in their default Cargo
   manifests; doing so would require an explicit Cargo.toml edit
   that an audit reviewer would catch. The crate-level docstring
   names the gate as a security boundary (P7 success criterion 11).

#### Verification artifacts

The `tests/e2e.rs::no_plaintext_on_disk` property test is the load-bearing
cardinal-principle-2 verifier for this layer: it creates a vault, writes
≥100 accounts whose password fields carry unique random markers, locks +
closes the vault, and scans the raw bytes of the `.pvf` file (and the WAL
sidecar when present) for each marker — asserting zero matches across
all writes. Runs on every `cargo test` invocation in CI; a marker hit
would indicate a regression in the seal/AAD discipline and would block
the PR.

### Pangolin sync orchestrator (`pangolin-cli`)

> Source: `docs/issue-plans/P8.md` §"Threat model row" and the P8
> build-gate. The `pangolin-cli` binary at `tools/pangolin-cli/` is
> the user-facing PoC orchestrator that drives `pangolin-chain` to
> publish dirty revisions and pull chain events into the local
> vault. It does not introduce new cryptographic primitives; the
> threats below concern orchestration, idempotency, and the
> publish/pull state machine.

1. **Forged publish (foreign device claiming to be the user's).**
   Defense: revisions are signed by an Ed25519 device key via
   `signing::build_signed_revision`, which binds the canonical-hash
   digest to the device's Ed25519 verifying-key bytes (`device_id`).
   v0 contract does **not** verify on-chain; v1 will (MVP-2 issue
   2.1). Per Q6 plan-gate decision, `pull_all` runs a defense-in-
   depth `VerifyingKey::from_bytes` check on every event's
   `device_id` BEFORE invoking `Vault::ingest_chain_revision` — an
   event whose `device_id` is not a canonical Ed25519 point is
   refused at the device boundary. Full signature verification (the
   Ed25519 `verify` step over the canonical hash) is blocked until
   v1 records the signature on-chain; v0's `RevisionPublished` event
   ABI does not transport the signature bytes. *PoC two-key model
   note:* under the §A7 deviation from D-006, `pangolin-cli`
   generates an ephemeral signing `DeviceKey` per run (the
   gas-paying secp256k1 wallet is the Foundry keystore). MVP-1 will
   switch to `evm::derive_evm_wallet` so the same Pangolin device
   key signs revisions and pays gas — closing the deviation while
   preserving the canonical-hash discipline.
2. **Replay of an old signed revision.** Defense: the canonical-
   hash digest binds `parent_revision`. A revision with a stale
   parent cannot apply to a moved-on head; ingestion only
   structurally succeeds when the parent matches the local head OR
   surfaces as a fork (per Cardinal Principle 3 the chain is a log,
   not an authority — the local store records what the chain says
   happened). Re-publishing the same revision is additionally
   guarded by the A3 pre-publish check (`pull_since` →
   canonical-hash compare → skip-if-already-on-chain), preventing
   double-publish after a kill mid-publish.
3. **Network partition during chunked pull.** Defense: per A5, the
   chunked-pull design means a chunk failure preserves prior
   chunks' progress on disk via `advance_last_pulled_block` per
   chunk. Re-running `pangolin-cli pull` resumes from the new
   `last_pulled_block`. This resolves P7 audit MED-3 without
   altering the `ChainAdapter` trait shape.
4. **Dirty-entry leak.** Defense: the `dirty_accounts` table stores
   only `(account_id, revision_id, marked_at)`. `account_id` is
   already an attacker-observable identifier on-chain (the
   `RevisionPublished` event includes it as topic 2). `revision_id`
   is the canonical-hash digest of the revision payload, which
   becomes observable on chain anyway when the revision publishes.
   `marked_at` is a unix-ms timestamp local to the device — the
   only piece of new metadata, and it leaks only "when did this
   device edit account X for the n-th time," visible only to an
   attacker who has already compromised the local vault file (in
   which case they have the AEAD-protected ciphertext, dwarfing
   the timing leak).
5. **Replay protection across vaults.** Defense: `vault_id` is
   bound into `signing::canonical_hash`, so a revision signed for
   vault A cannot be replayed against vault B even by the same
   device. The chain event includes `vault_id` as topic 1; pulled
   events for vault B never include vault A's revisions because
   `pull_since` filters server-side on `vault_id` topic equality.
6. **Pre-publish check race.** Defense (acknowledgement): the A3
   pre-publish check runs `adapter.pull_since(vault_id,
   last_pulled_block, None)` before any re-attempt. The race is:
   two devices publish the same `(parent, payload)` simultaneously
   and both A3 checks succeed (each sees the chain without the
   other's revision yet). Both publishes succeed and create a fork.
   This is **expected behavior** — concurrent edits by independent
   devices fork; the fork surfaces on the next pull (A4); P9
   resolves it. The race is not a defect.
7. **Misuse of `MockChainAdapter` in the binary.** Defense:
   `pangolin-cli` does not enable `pangolin-chain`'s
   `test-utilities` feature in its default `[dependencies]` table
   — only in `[dev-dependencies]`. `MockChainAdapter` is therefore
   not constructible from the production build. Tests compile with
   the feature enabled; humans who try to substitute the mock for
   a real adapter would have to edit `tools/pangolin-cli/Cargo.toml`,
   which an audit reviewer would catch. P7 audit's gating
   discipline is inherited.
8. **Two-key model gas-wallet correlation (D-006 deviation).**
   Defense (acknowledgement): the gas-paying secp256k1 wallet
   (Foundry keystore) is **separate** from the device's Ed25519
   revision-signing key. The gas wallet's address appears as the
   `tx.from` on every publish; an observer who learns "address X
   paid gas for these revisions" can correlate all publishes from
   the same machine across all vaults that share the keystore. This
   is the same observability surface as P7 audit threat #6 (EVM
   address observability) and the same Phase-2 mitigation applies
   (per-publish wallet rotation via funder service, MVP-2 issue
   3.4). The PoC-specific divergence from D-006 (which mandates
   *one* keypair as both signer and gas payer) is documented in
   §A7 of the P8 plan; MVP-1 will switch to
   `pangolin_chain::evm::derive_evm_wallet` to satisfy D-006's
   wording.
9. **Forged-event-stream from compromised RPC.** Defense: per Q6
   defense-in-depth, every event surfaced by `pull_since` is
   subjected to a `VerifyingKey::from_bytes` check on its
   `device_id` before reaching `ingest_chain_revision`. An RPC
   that splices events with garbage `device_id` bytes is rejected
   at the device boundary. v0 contract has no signature semantics;
   this client-side check is the load-bearing defense until v1
   records the signature on-chain (MVP-2 issue 2.1).
10. **Tombstone / foreign-edit non-propagation across vault file
    copies (P8 fix-pass CRIT-1).** Defense: when
    `Vault::ingest_chain_revision` lands an event that does not
    match any of the three idempotency-merge arms, the
    `account_identities.frozen_pending_resolve` sentinel column
    is set to `1` for the affected account. Once set, every
    user-facing read (`get_account`, `list_accounts`, `search`,
    `reveal_password`, `reveal_notes`, `reveal_totp_secret`,
    `export_payload`) refuses on the account — `get_account`
    returns `None`; `list_accounts` and `search` filter the row
    out; the reveal/export ops surface
    `StoreError::AccountFrozenPendingResolve { account_id }`.
    Edits (`update_account`, `delete_account`, `mark_dirty`)
    refuse with the same error, so a user editing their stale
    plaintext copy of a chain-modified account cannot create a
    silent fork. The flag is cleared by the upcoming
    `pangolin-cli resolve` subcommand (P9). The defense closes
    the "vault A creates account, vault B copies the file, vault
    A tombstones on chain, vault B's `reveal_password` still
    returns plaintext" attack the §16.5 audit identified. The
    schema column is added at vault open via
    `migrate_frozen_pending_resolve_column` so existing
    P0..P7+P8-pre-fix vault files keep opening cleanly.
11. **Spoofed chain anchor on local pre-publish row (P8 fix-pass
    MED-1).** Defense: the third merge arm of
    `Vault::ingest_chain_revision` (the content-merge that stamps
    a chain anchor onto an existing local pre-publish row) now
    requires `device_id` to match alongside `(account_id,
    parent_revision, enc_payload, schema_version)` and
    `chain_tx_hash IS NULL`. An attacker controlling the RPC
    would have to produce an event whose `device_id` matches the
    victim's locally-stored row's `device_id` — under the PoC
    two-key model that field is set from `Vault.device_id`
    (random per vault-handle bytes generated at `Vault::open`),
    not visible on the chain. A forged event with a different
    `device_id` falls through to the genuine-foreign-INSERT path,
    which sets the CRIT-1 freeze sentinel — i.e., a forgery
    surfaces as a refused-read rather than a silent merge. The
    audit's preferred re-fetch-via-`get_revision` approach was
    rejected because under attacker-controlled-RPC both
    directions of the conversation are spoofable; the device_id
    binding is a content-bound check that doesn't depend on the
    transport. Trade-off: the legitimate own-publish round-trip
    under PoC two-key model also fails the device_id match
    (publish generates an ephemeral signing `DeviceKey` per call
    whose pubkey differs from the local row's random
    `device_id`), so it routes through idempotency arm #2
    `(account_id, chain_tx_hash, block, log)` after
    `mark_published` has stamped the local row's chain anchor.
    Cross-vault round-trips (vault B pulling vault A's
    publishes) intentionally trigger the freeze under threat #10
    above. MVP-1's switch to the derived wallet (D-006) aligns
    local-row and chain-event `device_id`, restoring silent
    cross-device merge under the non-attack case while
    preserving the device_id binding's defense.

12. **Forged resolve (foreign device claiming to be the user's,
    publishing a merge revision under the user's account).**
    Defense: the merge revision is signed by the device's
    Ed25519 `DeviceKey` via `signing::build_signed_revision`,
    same path as `publish`. The canonical hash binds
    `parent_revision` (= the chosen head's `revision_id`),
    `account_id`, `vault_id`, `device_id`, and `enc_payload`. v0
    contract does not verify on-chain; v1 will (MVP-2 issue 2.1).
    Per Q6 defense-in-depth, the receiving device's `pull_all`
    runs `VerifyingKey::from_bytes` on the merge event's
    `device_id` before invoking `Vault::ingest_chain_revision`
    — same gate that catches forged publish events. The PoC
    two-key model carries forward unchanged: resolve generates
    an ephemeral `DeviceKey` per run.
13. **Replay of an old resolve, AND partial-failure recovery
    between `adapter.publish` and `clear_frozen` (P9 fix-pass
    HIGH-1).** Defense: the canonical hash binds
    `parent_revision`. A resolve replay against a moved-on head
    (someone else has published a descendant in the meantime,
    advancing the head past the chosen one) lands as another
    fork rather than a duplicate, surfacing on the next pull as
    the concurrent-resolve race described in P9 plan §A7.
    Re-publishing the same merge revision with a stale parent
    is additionally guarded by the resolve flow's pre-publish
    check (Q7-APPROVED): `pull_all` runs first and then
    re-validates `account_heads`; if the chosen revision is no
    longer a head OR a NEW head appeared,
    `ResolveError::ChainMovedDuringResolve` aborts the resolve
    cleanly.

    **Recovery from a kill between `adapter.publish` and
    `clear_frozen` is via the `pending_merges` stash** (added
    by P9 fix-pass HIGH-1; deepened by P9 fix-pass 2 HIGH-1;
    resolves the audit's "the user is permanently stuck —
    frozen account, unresolvable" finding). The merge-revision-
    build state — ephemeral `DeviceKey` secret seed (32 bytes),
    AEAD nonce (24 bytes), and the AEAD-sealed merge revision
    ciphertext — is persisted to a new SQLite table
    `pending_merges` BEFORE `adapter.publish`. The retry path
    looks up the stash via `Vault::take_pending_merge`,
    reconstructs the SAME `DeviceKey` from the stashed seed,
    and re-uses the SAME ciphertext + nonce — so the canonical
    hash is bit-equal across retries and the chain event from
    the prior partially-completed run can be matched on retry.

    **Re-ordered `sync::resolve_one` (P9 fix-pass 2 HIGH-1
    deeper fix).** `take_pending_merge` runs BEFORE the
    `pull_all` + `chain_moved` guard. After `pull_all`, the
    stash's deterministic canonical hash is matched against
    the post-pull LOCAL revisions table (the merge revision is
    ingested by `pull_all` if the prior publish landed); if a
    matching row with a populated chain anchor exists,
    `resolve_one` takes the `AlreadyOnChain` path: skips
    publish, calls `clear_frozen` (which advances
    `head_revision_id` to the merge-rev id and clears the
    freeze flag in one transaction), and clears the stash. The
    `ChainMovedDuringResolve` branch only fires when the chain
    has a head NOT matching any stash for the user's
    `(account_id, --keep)` pair — kill-after-publish-success
    recovery is genuinely complete end-to-end, not just kill-
    before-publish-reaches-chain. `clear_frozen` succeeds even
    on a foreign-ingested row whose `enc_nonce` is the
    placeholder zero, because `clear_frozen` only validates
    head-membership + advances the head pointer — it does not
    decrypt the row.

    **Orphan stash pruning (P9 fix-pass 2 MEDIUM-2).**
    `Vault::prune_orphan_pending_merges(account_id)` deletes
    stash rows whose `target_head_id` is no longer a current
    head. Called from `pull_all` after each chunk's per-
    account ingest sequence completes (separate transaction,
    so the per-chunk all-or-nothing discipline is preserved),
    and from `resolve_one` alongside `take_pending_merge`. A
    user-changed `--keep`, `ChainMovedDuringResolve`, or any
    other path that abandons a stash row is bounded — the
    32-byte Ed25519 seed does not accumulate at rest
    indefinitely. Three tests pin the prune semantics:
    `prune_orphan_pending_merges_removes_non_head_targets`,
    `prune_no_op_when_all_targets_are_heads`,
    `prune_no_op_on_empty_table`.

    Without the stash + the re-ordered flow, each retry would
    generate a fresh ephemeral `DeviceKey` AND a fresh AEAD
    nonce — the canonical hash would differ every run, the
    chain event from the prior run could not be matched, and
    `ChainMovedDuringResolve` would fire on the merge-revision-
    foreign-ingest path before any recovery code ran, leaving
    the user permanently stuck with a frozen account.

    The stash row contains an Ed25519 secret seed at rest in
    the vault file as a SQLite BLOB column, NOT additionally
    AEAD-sealed. The reasoning is bounded-marginal-exposure:
    at-rest exposure of the `.pvf` file already compromises
    the VDK and worse (every account's encrypted ciphertext,
    every chain anchor, every `account_identities` row), so
    the marginal exposure of an ephemeral merge-signing key
    that is discarded after `clear_frozen` succeeds (and
    additionally pruned per MEDIUM-2 if abandoned) is
    bounded. The stashed `enc_payload` is AEAD ciphertext
    (NOT plaintext — cardinal principle 2 holds; the seal
    happens inside `Vault::build_merge_payload_for_resolve`
    BEFORE the stash). Tests pinning the recovery semantics:
    `stash_take_clear_round_trip`,
    `stash_persists_across_close_open`,
    `take_returns_none_for_nonexistent_account`,
    `pending_merge_zeroizes_secret_on_drop`,
    `resolve_idempotent_after_partial_failure_via_stash` (the
    publish-failed retry test),
    `resolve_recovers_from_kill_after_publish_success` (the
    kill-after-publish-success retry test added by P9 fix-pass
    2), plus the three prune tests above.
14. **Frozen flag cleared without publish.** Defense: the
    `Vault::clear_frozen` API takes `chosen_revision_id` as a
    parameter and atomically advances `head_revision_id` to it;
    the resolve flow ALWAYS calls `clear_frozen` only after a
    successful publish + ingest of the merge revision. There is
    no API path that clears the freeze flag without a
    corresponding revision row in the local store —
    `clear_frozen` errors with `StoreError::RevisionNotFound`
    if the supplied `chosen_revision_id` does not exist as a
    `revisions` row for the account. A malicious local actor
    with vault-file access could `UPDATE account_identities SET
    frozen_pending_resolve = 0` directly via sqlite tooling,
    but that's the same as them tampering with any other row —
    not a defense the application layer can mount.
15. **User keeps an attacker-controlled head (HIGH-1 from P8
    audit).** Defense (acknowledgement, UX-only): under the
    threat model where a malicious RPC injects events with
    garbage `device_id`, P8 fix CRIT-1 freezes the account so
    the user cannot read the stale plaintext. If the user then
    runs `pangolin-cli resolve --keep <id>` where `<id>`
    references one of the attacker-injected events, they have
    explicitly adopted attacker-controlled state. The
    mitigation is UX: `pangolin-cli resolve` prints the
    metadata of each candidate head so the user can spot an
    unfamiliar `device_id` (a foreign device they don't
    recognise). Full defense requires v1 contract on-chain
    signature verification (MVP-2 issue 2.1); PoC ships with
    the UX surfacing as the only defense against this class.
    Documented as a known UX-bound gap.
16. **`Vault::read_payload_plaintext_for_resolve` as a
    documented freeze-guard bypass.** The resolve flow needs
    to read the chosen revision's plaintext to re-seal it
    under the merge revision's AAD (per P9 plan §A2 — a
    byte-copy of the source ciphertext would carry the source
    row's `parent_revision_id` baked into the AAD, producing
    an unopenable merge row). The bypass is gated by the
    user's `--keep <id>` argument as proof-of-intent: the user
    has named the specific revision they want to ratify, so we
    trust the read for that one revision for the duration of
    one resolve invocation. The accessor is loudly documented
    (`DOCUMENTED FREEZE-GUARD BYPASS — DO NOT CALL FROM ANY
    PATH EXCEPT pangolin-cli resolve`) and has a single
    in-process caller. Cross-account substitution is blocked:
    supplying a `revision_id` that belongs to a different
    account collapses to `StoreError::AccountNotFound` so the
    method is not an oracle. Per P9 plan Q6 / §A8, this is the
    accepted design trade-off; an alternative
    "user re-supplies password as fresh proof" model has
    higher UX friction without measurable security gain
    (the user is already past the unlock proof at the
    `--keep` step). MVP-1 may revisit if audit feedback
    surfaces a stronger bypass discipline.
17. **Concurrent-resolve race (P9 plan §A7 — Q2 APPROVED to
    ship without a guard).** Defense (acknowledgement):
    devices A and B running `pangolin-cli resolve` on the same
    forked account concurrently both pass their pre-publish
    re-pull (each sees the chain without the other's merge
    yet) and both successfully publish. The result is yet
    another fork: parent = chosen_head, two children (A's
    merge and B's merge). The next pull from any device
    surfaces the new fork; the user resolves it again. This is
    the same class of race as P8 threat #6 (concurrent edits
    by independent devices fork; the fork surfaces on next
    pull). The recovery is mechanical (re-resolve) and the
    race window is small (concurrent resolve attempts on the
    same fork require both devices to be online and aware of
    the fork at the same instant). P11 may add an interactive
    freshness guard ("verify chosen head is still a head as of
    right now"); P9 ships without it per Kelvin's locked
    answer Q2.
