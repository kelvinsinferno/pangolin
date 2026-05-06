//! Account-identity types — the in-memory snapshot of a fully-decrypted
//! account at a point in time.
//!
//! [`AccountSnapshot`] holds plaintext credential material. Per the
//! cardinal-principle-2 discipline, instances of this type:
//!
//! - **Never derive `Clone`/`Copy`/`PartialEq`** so accidental
//!   duplication or non-constant-time equality is rejected at compile
//!   time.
//! - **Implement [`zeroize::ZeroizeOnDrop`]** through their owning
//!   secret-buffer fields ([`pangolin_crypto::secret::SecretBytes`]).
//! - **Override [`core::fmt::Debug`] to redact every secret field.**
//!
//! Identifiers ([`AccountId`]) are non-secret and intentionally
//! [`Copy`]/[`Eq`]/`Hash`-able — they're the keys in the
//! [`crate::search`] cache and need to round-trip through `SQLite` columns.

use core::fmt;

use pangolin_crypto::secret::SecretBytes;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

/// Length in bytes of an [`AccountId`].
pub const ACCOUNT_ID_LEN: usize = 32;

/// Stable, opaque per-account identifier.
///
/// 32 random bytes generated client-side at account creation. Treated as
/// a UUIDv4-style opaque blob; not a hash of the content. The same value
/// appears as `accountId` on the on-chain `RevisionPublished` event and
/// inside the AEAD AAD on every revision blob, so cross-account
/// transplant attempts fail authentication.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId(pub(crate) [u8; ACCOUNT_ID_LEN]);

impl AccountId {
    /// Generate a fresh random `AccountId` from the OS CSPRNG.
    ///
    /// Routes through `pangolin-crypto`'s public RNG entry by way of
    /// [`pangolin_crypto::aead::Nonce::random`] is overkill — for a
    /// non-secret id we just use `getrandom` directly via `rand_core`,
    /// but `pangolin-crypto` does not expose a raw "fill some bytes"
    /// API. Routing through `Nonce::random` and copying the first 32
    /// bytes would conflate distinct types; we instead use the OS
    /// `getrandom` crate's static path via `chacha20poly1305`'s
    /// transitive rand feature… which we don't have. Cleaner: we ask
    /// `pangolin-crypto` for a fresh `AeadKey` and read the bytes via
    /// the public API. But `AeadKey` does not expose its bytes either.
    ///
    /// Resolution: `SQLite` assigns no client-controlled bytes; we
    /// generate via `rusqlite::Connection::pragma_query` for
    /// `sqlite_random` — but that is also not stable.
    ///
    /// We therefore call into [`pangolin_crypto::keys::DeviceKey`]'s
    /// public verifying-key path: a freshly-generated `DeviceKey` has a
    /// public 32-byte verifying key whose bytes are uniformly random
    /// (Ed25519 is point-deterministic from a uniform seed; the
    /// resulting public bytes are uniform after compression). However
    /// that's wasteful per call.
    ///
    /// **Decision (P2-1):** the simplest correct path is to take the
    /// caller-supplied bytes — typically produced by `SQLite`'s
    /// `randomblob(32)`. Public API users either pass bytes they
    /// produced themselves or let `Vault::add_account` synthesize via
    /// `SQLite`'s random function. We keep this constructor for
    /// downstream use.
    #[must_use]
    pub fn from_bytes(bytes: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes for storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Decrypted plaintext of an account's "current state" — the in-memory
/// representation an unlocked vault hands back to its caller.
///
/// Every field is heap-allocated and zero-on-drop. The struct itself is
/// [`zeroize::ZeroizeOnDrop`] (via its fields) and deliberately has no
/// derive of `Clone`, `Copy`, `PartialEq`, or `Serialize`. Equality on
/// secret fields uses [`subtle::ConstantTimeEq`] through
/// [`Self::ct_eq`]; non-secret identity equality is not provided —
/// callers compare by [`AccountId`] outside the snapshot.
pub struct AccountSnapshot {
    /// Human-readable display name. Plaintext — but still encrypted at
    /// rest because revealing service display names is a credential
    /// metadata leak.
    pub display_name: SecretBytes,
    /// Login-username field.
    pub username: SecretBytes,
    /// Password.
    pub password: SecretBytes,
    /// Service URL the credential applies to.
    pub url: SecretBytes,
    /// Free-form notes.
    pub notes: SecretBytes,
    /// Optional TOTP secret. Empty `SecretBytes` when not configured.
    pub totp_secret: SecretBytes,
}

impl AccountSnapshot {
    /// Construct a snapshot from already-allocated [`SecretBytes`] field
    /// owners. The caller is responsible for using the typed wrappers —
    /// raw `Vec<u8>` parameters would invite leakage.
    #[must_use]
    pub fn new(
        display_name: SecretBytes,
        username: SecretBytes,
        password: SecretBytes,
        url: SecretBytes,
        notes: SecretBytes,
        totp_secret: SecretBytes,
    ) -> Self {
        Self {
            display_name,
            username,
            password,
            url,
            notes,
            totp_secret,
        }
    }

    /// Constant-time equality across every secret field.
    ///
    /// Distinct from `PartialEq` (which is deliberately not implemented):
    /// callers that compare snapshots in tests must reach for this to
    /// avoid a non-constant-time comparison sneaking in.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let mut acc = self
            .display_name
            .expose()
            .ct_eq(other.display_name.expose());
        acc &= self.username.expose().ct_eq(other.username.expose());
        acc &= self.password.expose().ct_eq(other.password.expose());
        acc &= self.url.expose().ct_eq(other.url.expose());
        acc &= self.notes.expose().ct_eq(other.notes.expose());
        acc &= self.totp_secret.expose().ct_eq(other.totp_secret.expose());
        acc
    }
}

impl fmt::Debug for AccountSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountSnapshot")
            .field("display_name", &"<redacted>")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("url", &"<redacted>")
            .field("notes", &"<redacted>")
            .field("totp_secret", &"<redacted>")
            .finish()
    }
}

// AccountSnapshot's fields are SecretBytes, which carry their own
// `Drop`+`ZeroizeOnDrop` discipline (the inner `Zeroizing<Vec<u8>>`
// wipes its allocation on drop). Drop-as-trait propagates field-by-
// field, so the snapshot is zero-on-drop transitively. The marker impl
// below makes the discipline self-documenting; we deliberately do NOT
// add a manual `Drop` here because that would *prevent* the field
// `SecretBytes` drops from running automatically (a Drop impl on the
// outer type still drops the fields after, but the marker is enough).
impl ZeroizeOnDrop for AccountSnapshot {}

#[cfg(test)]
mod tests {
    use super::{AccountId, AccountSnapshot};
    use pangolin_crypto::secret::SecretBytes;

    #[test]
    fn account_id_debug_is_hex() {
        let id = AccountId::from_bytes([0xABu8; 32]);
        let printed = format!("{id:?}");
        assert!(printed.starts_with("AccountId("));
        assert!(printed.contains("ab"));
    }

    #[test]
    fn snapshot_debug_redacts_every_field() {
        // Markers chosen so they cannot collide with any field-name
        // string in the redacted Debug output.
        let snap = AccountSnapshot::new(
            SecretBytes::new(b"github-marker-77".to_vec()),
            SecretBytes::new(b"alice-marker-88".to_vec()),
            SecretBytes::new(b"hunter2-marker-99".to_vec()),
            SecretBytes::new(b"https://example.com/marker-aa".to_vec()),
            SecretBytes::new(b"some-private-marker-bb".to_vec()),
            SecretBytes::new(b"totpmarker-cc".to_vec()),
        );
        let printed = format!("{snap:?}");
        // Every secret marker must be absent. The Debug struct legend
        // has its own field names ("display_name", "username", ...) but
        // those are NOT plaintext from the user.
        for marker in &[
            "github-marker-77",
            "alice-marker-88",
            "hunter2-marker-99",
            "example.com/marker-aa",
            "some-private-marker-bb",
            "totpmarker-cc",
        ] {
            assert!(
                !printed.contains(marker),
                "snapshot Debug leaked plaintext marker {marker}: {printed}"
            );
        }
        assert!(printed.contains("<redacted>"));
    }

    #[test]
    fn snapshot_ct_eq_matches_equal_inputs() {
        let a = AccountSnapshot::new(
            SecretBytes::new(b"a".to_vec()),
            SecretBytes::new(b"b".to_vec()),
            SecretBytes::new(b"c".to_vec()),
            SecretBytes::new(b"d".to_vec()),
            SecretBytes::new(b"e".to_vec()),
            SecretBytes::new(b"f".to_vec()),
        );
        let b = AccountSnapshot::new(
            SecretBytes::new(b"a".to_vec()),
            SecretBytes::new(b"b".to_vec()),
            SecretBytes::new(b"c".to_vec()),
            SecretBytes::new(b"d".to_vec()),
            SecretBytes::new(b"e".to_vec()),
            SecretBytes::new(b"f".to_vec()),
        );
        let c = AccountSnapshot::new(
            SecretBytes::new(b"a".to_vec()),
            SecretBytes::new(b"b".to_vec()),
            SecretBytes::new(b"different".to_vec()),
            SecretBytes::new(b"d".to_vec()),
            SecretBytes::new(b"e".to_vec()),
            SecretBytes::new(b"f".to_vec()),
        );
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }
}
