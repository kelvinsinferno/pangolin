//! The `ChainAdapter` async trait — the only interface
//! `pangolin-store` and `pangolin-cli` are allowed to depend on.
//!
//! ## Why `async_trait`
//!
//! Stable Rust supports `async fn` directly in trait definitions
//! ("async fn in trait" / RPITIT) but the resulting trait is not
//! `dyn`-compatible without an explicit `Box<dyn Future>` shim. The
//! consumer pattern is `Vault::sync_publish<A: ChainAdapter>(adapter:
//! &A)` (P8) and downstream tests use `&dyn ChainAdapter` to avoid
//! generic plumbing through every callsite. `#[async_trait]` boxes the
//! future for us so the trait stays dyn-compatible.
//!
//! ## Send + Sync
//!
//! Adapters live behind a shared reference; we want them callable from
//! any tokio task. Both impls (`MockChainAdapter` and
//! `BaseSepoliaAdapter`) keep their state in `Arc<Mutex<_>>` /
//! `Arc<dyn Provider>` so this bound is satisfied trivially.

use async_trait::async_trait;

use crate::error::ChainError;
use crate::types::{ChainAnchor, EventLocation, RevisionEvent, SignedRevision, VaultId};

/// Async transport for `RevisionLogV0` reads + writes.
///
/// All methods are network-bound for the production impl; the
/// in-memory `MockChainAdapter` makes them effectively synchronous via
/// `Mutex`. Both impls share the same trait so swapping one for the
/// other (in tests) requires no callsite changes.
///
/// **Cardinal principle 3**: this trait is a transport. It returns
/// events; it never decides what to do with them. The application of
/// pulled events to local state is `pangolin-store`'s job (P8).
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    /// Publish a signed revision. Returns the on-chain anchor.
    ///
    /// Failure modes:
    /// - `ChainError::Rpc` — network failure mid-broadcast. Tx may or
    ///   may not have mined; caller should retry via `pull_since` and
    ///   check the anchor before re-publishing.
    /// - `ChainError::Reverted` — the tx made it on-chain but the
    ///   receipt's status flag was 0 (out-of-gas, contract revert).
    /// - `ChainError::WrongChain` — the RPC reports a different
    ///   `chain_id` than the deployment file we loaded. Fail-closed.
    /// - `ChainError::Wallet` — adapter was constructed read-only and
    ///   has no signer.
    async fn publish(&self, signed: &SignedRevision) -> Result<ChainAnchor, ChainError>;

    /// Stream events for `vault_id` since (and excluding) `from_block`.
    ///
    /// Yields `RevisionEvent`s in chain order
    /// (block ASC → `log_index` ASC). Bounded by `until_block` (None =
    /// current head). The `from_block` is **exclusive** so a caller
    /// can pass `last_pulled_block` and not re-fetch the boundary
    /// event.
    ///
    /// ## All-or-nothing semantics (P7 audit MED-3 — deferred)
    ///
    /// The Base Sepolia impl chunks `eth_getLogs` calls into 9 000-
    /// block windows because the public RPC caps at 10 000. Each
    /// chunk's events are accumulated into a single `Vec` that is
    /// only returned after every chunk succeeds. If chunk N succeeds
    /// and chunk N+1 fails (e.g., transient RPC flake), **all** of
    /// chunk N's events are discarded and the caller sees a single
    /// `ChainError::Rpc`. The caller has to retry from `from_block`
    /// from scratch.
    ///
    /// This is fine for short ranges and small backlogs but amplifies
    /// latency under flaky RPC conditions for large catch-up syncs
    /// (e.g., a vault that has been offline for weeks). The right fix
    /// is to expose granular per-chunk progress — for instance via a
    /// streaming variant
    /// (`pull_since_streaming(...) -> impl Stream<Item = ...>`) or a
    /// callback (`pull_since_with_progress(..., on_chunk: F)`) — so
    /// P8's sync orchestrator can advance its checkpoint after every
    /// successful chunk and resume mid-range on retry.
    ///
    /// **Decision: defer the trait-shape change to P8.** P7 is the
    /// transport layer; the partial-progress design touches sync
    /// semantics that belong to P8 (sync-orchestration), and locking
    /// the trait shape now would prejudge that design. P8 implementers:
    /// see this docstring before reaching for `pull_since` on a long
    /// catch-up path.
    // TODO: MED-3 (P7 audit): partial-progress reporting deferred to P8.
    async fn pull_since(
        &self,
        vault_id: &VaultId,
        from_block: u64,
        until_block: Option<u64>,
    ) -> Result<Vec<RevisionEvent>, ChainError>;

    /// Look up a single event by tx hash + log index. Used for
    /// replays and disputes.
    ///
    /// Returns `Ok(None)` if the tx exists but the locator's
    /// `log_index` does not point at a `RevisionPublished` log emitted
    /// by the canonical contract address. Returns
    /// `Err(ChainError::Rpc)` on transport failure.
    async fn get_revision(
        &self,
        location: &EventLocation,
    ) -> Result<Option<RevisionEvent>, ChainError>;

    /// Current chain head block. Used for sync-checkpoint advancement.
    ///
    /// Returns the most recent canonical block number at the time of
    /// the call. Reorgs may move this number backward in extreme
    /// cases; reorg handling is P8's job.
    async fn current_block(&self) -> Result<u64, ChainError>;
}
