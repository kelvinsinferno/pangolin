//! Value types exchanged between the adapter and its callers.
//!
//! All payload-bearing types use **fixed-size byte arrays**, not
//! `Vec<u8>`, for the 32-byte identifiers (`vault_id`, `account_id`,
//! `parent_revision`, `device_id`, `tx_hash`). This is the discipline
//! P7 imposes on top of P2's looser SQL-shaped `ChainAnchor` (which
//! used `Vec<u8>` because of how rusqlite returns BLOBs); the SQL
//! conversion happens at the `mark_published` boundary in
//! `pangolin-store`.
//!
//! ## What is NOT here
//!
//! - **No `serde::Deserialize`** on any payload-bearing type. The plan
//!   forbids it (security-critical constraint): chain bytes are raw
//!   `Vec<u8>` and never parsed structurally by this crate.
//!   `pangolin-store::blob` is the only place that decodes
//!   `enc_payload` into structured form, and it does so under AEAD
//!   authentication.
//! - **No `serde::Serialize` either** — the same audit posture, plus
//!   it would force the type to live in alloy's `serde` graph.
//! - **No `Eq` on `SignedRevision`** — the signature byte is the only
//!   thing that varies between two equivalent signed revisions, and
//!   the type carries it. Equality of two `SignedRevision`s is mostly
//!   a smoke-test concern, not a production primitive.

use core::fmt;

use pangolin_crypto::sign::{Signature, SIGNATURE_LEN};

/// 32-byte vault identifier.
///
/// Same shape as `pangolin_crypto::keys::VAULT_ID_LEN` —
/// `pangolin-chain` does not re-export that constant because it's a
/// layer above the crypto primitives, but the byte-width must always
/// match.
pub type VaultId = [u8; 32];

// ---------------------------------------------------------------------
// SignedRevision
// ---------------------------------------------------------------------

/// A revision signed by the local device, ready to be submitted to the
/// chain via `ChainAdapter::publish`.
///
/// **v0 contract** (`RevisionLogV0`) ignores the signature; **v1**
/// (MVP-2 issue 2.1) will verify it on-chain. Building the signature
/// into the client now means MVP-2 doesn't need a client-side
/// migration.
///
/// The signature is over a domain-separated keccak-hash of the
/// canonical-encoded args — see [`crate::signing`] for the canonical
/// form.
///
/// `enc_payload` is the AEAD-sealed bytes from `pangolin-store::blob`,
/// already authenticated under the vault's VDK + AAD. This crate
/// treats it as opaque.
#[derive(Clone)]
pub struct SignedRevision {
    /// 32-byte vault id.
    pub vault_id: VaultId,
    /// 32-byte account id.
    pub account_id: [u8; 32],
    /// 32-byte parent revision id (genesis sentinel = all zeros).
    pub parent_revision: [u8; 32],
    /// 32-byte device id (the device's Ed25519 verifying-key bytes per
    /// MVP-1; same as `pangolin_crypto::sign::VerifyingKey::to_bytes`).
    pub device_id: [u8; 32],
    /// AEAD-payload schema version; matches the `schema_version` byte
    /// in `pangolin-store::blob`.
    pub schema_version: u8,
    /// Raw AEAD-sealed payload bytes. Opaque to this crate.
    pub enc_payload: Vec<u8>,
    /// Detached Ed25519 signature over the canonical hash. v0 contract
    /// ignores; v1 will verify under the device's verifying key.
    pub signature: Signature,
}

impl fmt::Debug for SignedRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedRevision")
            .field("vault_id", &HexBytes(&self.vault_id))
            .field("account_id", &HexBytes(&self.account_id))
            .field("parent_revision", &HexBytes(&self.parent_revision))
            .field("device_id", &HexBytes(&self.device_id))
            .field("schema_version", &self.schema_version)
            .field("enc_payload_len", &self.enc_payload.len())
            // The signature is public material; show full hex.
            .field("signature", &HexBytes(&self.signature.to_bytes()))
            .finish()
    }
}

// ---------------------------------------------------------------------
// ChainAnchor
// ---------------------------------------------------------------------

/// Recorded position of a revision on chain.
///
/// **Canonical type**: `pangolin-store` re-exports this same type from
/// `pangolin-chain` per success criterion 6 of `docs/issue-plans/P7.md`.
/// Field shapes are fixed-size + unsigned where the underlying chain
/// guarantees non-negativity (block numbers, log indices, sequences
/// are all `u64`); the SQL conversion at the `mark_published` boundary
/// widens to `i64` because `rusqlite` columns are signed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    /// 32-byte transaction hash.
    pub tx_hash: [u8; 32],
    /// Block number on Base Sepolia. `u64` because Ethereum block
    /// numbers are non-negative and fit in 64 bits well past any
    /// realistic chain lifetime.
    pub block_number: u64,
    /// Index of the `RevisionPublished` log within the block's log
    /// stream. Same `u64` reasoning.
    pub log_index: u64,
    /// The contract's `nextSequence` counter value at the time of
    /// publish. Lets a downstream consumer cross-check the on-chain
    /// state against what they think they wrote.
    pub sequence: u64,
}

impl fmt::Debug for ChainAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainAnchor")
            .field("tx_hash", &HexBytes(&self.tx_hash))
            .field("block_number", &self.block_number)
            .field("log_index", &self.log_index)
            .field("sequence", &self.sequence)
            .finish()
    }
}

// ---------------------------------------------------------------------
// RevisionEvent
// ---------------------------------------------------------------------

/// A `RevisionPublished` event observed on chain — what
/// `ChainAdapter::pull_since` returns.
///
/// Every byte field comes straight from the on-chain log (decoded
/// via alloy's typed binding); the `enc_payload` is passed through
/// unparsed, exactly as it was submitted. Whether those bytes are
/// genuine is the caller's concern (AEAD authentication via
/// `pangolin-store::blob` will surface tampering).
#[derive(Clone)]
pub struct RevisionEvent {
    /// 32-byte vault id.
    pub vault_id: VaultId,
    /// 32-byte account id.
    pub account_id: [u8; 32],
    /// 32-byte parent revision id (genesis sentinel = all zeros).
    pub parent_revision: [u8; 32],
    /// 32-byte device id.
    pub device_id: [u8; 32],
    /// AEAD-payload schema version.
    pub schema_version: u8,
    /// On-chain sequence number assigned by the contract.
    pub sequence: u64,
    /// Raw AEAD-sealed payload bytes. Opaque to this crate.
    pub enc_payload: Vec<u8>,
    /// Where this event was anchored on chain.
    pub anchor: ChainAnchor,
}

impl fmt::Debug for RevisionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevisionEvent")
            .field("vault_id", &HexBytes(&self.vault_id))
            .field("account_id", &HexBytes(&self.account_id))
            .field("parent_revision", &HexBytes(&self.parent_revision))
            .field("device_id", &HexBytes(&self.device_id))
            .field("schema_version", &self.schema_version)
            .field("sequence", &self.sequence)
            .field("enc_payload_len", &self.enc_payload.len())
            .field("anchor", &self.anchor)
            .finish()
    }
}

// ---------------------------------------------------------------------
// EventLocation
// ---------------------------------------------------------------------

/// Locator for a single event on chain — `ChainAdapter::get_revision`
/// argument.
///
/// Used for replays and disputes. The event's parent block number is
/// not part of the locator because alloy's `eth_getTransactionReceipt`
/// already returns the receipt by tx hash; the `log_index` disambiguates
/// among multiple `RevisionPublished` logs in the same tx (common
/// when a future v1 contract emits batched revisions).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EventLocation {
    /// 32-byte transaction hash.
    pub tx_hash: [u8; 32],
    /// Index of the `RevisionPublished` log within the block.
    pub log_index: u64,
}

impl fmt::Debug for EventLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventLocation")
            .field("tx_hash", &HexBytes(&self.tx_hash))
            .field("log_index", &self.log_index)
            .finish()
    }
}

// ---------------------------------------------------------------------
// Hex-format helper
// ---------------------------------------------------------------------

/// Newtype wrapper that prints a fixed-size byte array as hex in
/// `Debug` output. Avoids pulling `hex::encode` into every Debug impl
/// and keeps the formatting stable across runs (no `format!`
/// allocations beyond the inline write).
struct HexBytes<'a>(&'a [u8]);

impl fmt::Debug for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mirrors how `chaincli::format` writes hex for its JSONL output.
        // The `0x` prefix is intentional — it makes copy-paste into
        // `cast` / Etherscan trivially correct.
        write!(f, "0x")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// Compile-time guarantee: `Signature` is 64 bytes (Ed25519 detached).
// If `pangolin-crypto` ever bumps the signature width this fails to
// compile, prompting a P7 review of the signed-revision shape.
const _: () = assert!(SIGNATURE_LEN == 64);

#[cfg(test)]
mod tests {
    use super::{ChainAnchor, EventLocation, RevisionEvent, SignedRevision};
    use pangolin_crypto::sign::{Signature, SIGNATURE_LEN};

    fn dummy_signature() -> Signature {
        Signature::from_bytes([0x42; SIGNATURE_LEN])
    }

    #[test]
    fn signed_revision_debug_does_not_print_payload_bytes() {
        let sr = SignedRevision {
            vault_id: [0x01; 32],
            account_id: [0x02; 32],
            parent_revision: [0x03; 32],
            device_id: [0x04; 32],
            schema_version: 0,
            enc_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: dummy_signature(),
        };
        let printed = format!("{sr:?}");
        // Length is OK to print; the actual bytes are not.
        assert!(
            printed.contains("enc_payload_len: 4"),
            "expected enc_payload_len summary, got: {printed}"
        );
        assert!(
            !printed.contains("deadbeef"),
            "raw payload bytes must not appear in Debug, got: {printed}"
        );
    }

    #[test]
    fn chain_anchor_debug_prints_hex_tx_hash() {
        let a = ChainAnchor {
            tx_hash: [0xAB; 32],
            block_number: 12345,
            log_index: 7,
            sequence: 99,
        };
        let printed = format!("{a:?}");
        assert!(
            printed.contains("0xabab"),
            "expected hex tx hash, got: {printed}"
        );
        assert!(printed.contains("12345"));
        assert!(printed.contains("99"));
    }

    #[test]
    fn chain_anchor_eq_compares_all_fields() {
        let a = ChainAnchor {
            tx_hash: [0xAA; 32],
            block_number: 1,
            log_index: 2,
            sequence: 3,
        };
        let b = ChainAnchor {
            tx_hash: [0xAA; 32],
            block_number: 1,
            log_index: 2,
            sequence: 3,
        };
        let c = ChainAnchor { sequence: 4, ..a };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn event_location_debug_prints_hex() {
        let loc = EventLocation {
            tx_hash: [0xCD; 32],
            log_index: 1,
        };
        let printed = format!("{loc:?}");
        assert!(printed.contains("0xcdcd"));
    }

    #[test]
    fn revision_event_debug_redacts_payload() {
        let ev = RevisionEvent {
            vault_id: [0x01; 32],
            account_id: [0x02; 32],
            parent_revision: [0x03; 32],
            device_id: [0x04; 32],
            schema_version: 0,
            sequence: 42,
            enc_payload: vec![0xCA, 0xFE],
            anchor: ChainAnchor {
                tx_hash: [0xEE; 32],
                block_number: 1,
                log_index: 0,
                sequence: 42,
            },
        };
        let printed = format!("{ev:?}");
        assert!(printed.contains("enc_payload_len: 2"));
        assert!(!printed.contains("cafe"));
    }
}
