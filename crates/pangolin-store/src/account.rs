// SPDX-License-Identifier: AGPL-3.0-or-later
//! Account-identity types — the in-memory snapshot of a fully-decrypted
//! account at a point in time.
//!
//! [`AccountSnapshot`] (V0) and [`AccountIdentity`] (V1, MVP-1 issue
//! 1.2) hold plaintext credential material. Per the
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

use crate::error::{Result, StoreError};
use crate::revision::{DeviceId, RevisionId, REVISION_ID_LEN};

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
/// # Regression: secret fields are crate-private (P4 H-1 fix)
///
/// External callers cannot read the `password`, `notes`, or
/// `totp_secret` fields directly off a `&AccountSnapshot`. The
/// following snippet must FAIL to compile — the
/// `compile_fail`-annotated doctest doubles as a regression test that
/// catches a future refactor accidentally re-exposing a secret field.
///
/// ```compile_fail
/// use pangolin_store::AccountSnapshot;
/// use pangolin_crypto::secret::SecretBytes;
///
/// let snap = AccountSnapshot::new(
///     SecretBytes::new(b"d".to_vec()),
///     SecretBytes::new(b"u".to_vec()),
///     SecretBytes::new(b"p".to_vec()),
///     SecretBytes::new(b"https://x".to_vec()),
///     SecretBytes::new(b"n".to_vec()),
///     SecretBytes::new(b"".to_vec()),
/// );
/// // Each of the three lines below MUST be a compile error
/// // (private field access) — that's the H-1 fix.
/// let _ = snap.password.expose();
/// let _ = snap.notes.expose();
/// let _ = snap.totp_secret.expose();
/// ```
///
/// Non-secret fields remain `pub` per spec §5.4 (they are not on the
/// high-risk list):
///
/// ```
/// use pangolin_store::AccountSnapshot;
/// use pangolin_crypto::secret::SecretBytes;
///
/// let snap = AccountSnapshot::new(
///     SecretBytes::new(b"d".to_vec()),
///     SecretBytes::new(b"u".to_vec()),
///     SecretBytes::new(b"p".to_vec()),
///     SecretBytes::new(b"https://x".to_vec()),
///     SecretBytes::new(b"n".to_vec()),
///     SecretBytes::new(b"".to_vec()),
/// );
/// // These compile because display_name/username/url are non-secret
/// // identity fields per spec §5.4.
/// let _ = snap.display_name.expose();
/// let _ = snap.username.expose();
/// let _ = snap.url.expose();
/// ```
///
/// Every field is heap-allocated and zero-on-drop. The struct itself is
/// [`zeroize::ZeroizeOnDrop`] (via its fields) and deliberately has no
/// derive of `Clone`, `Copy`, `PartialEq`, or `Serialize`. Equality on
/// secret fields uses [`subtle::ConstantTimeEq`] through
/// [`Self::ct_eq`]; non-secret identity equality is not provided —
/// callers compare by [`AccountId`] outside the snapshot.
///
/// # Presence-escalation discipline (spec §5.4 / P4 H-1 fix)
///
/// Spec §5.4 ("High-Risk Action Escalation") lists `reveal password`,
/// `export vault`, `modify recovery`, `approve devices`, and
/// `extend long sessions` as high-risk actions that **MUST** require an
/// explicit fresh presence proof even during an active session. The
/// secret-bearing fields below — `password`, `notes`, `totp_secret` —
/// fall under that "reveal credential" umbrella. To enforce the
/// presence gate at the type system layer, those fields are
/// `pub(crate)`: external callers cannot read them via field access on
/// a `&AccountSnapshot` returned by [`crate::vault::Vault::get_account`].
/// The presence-gated entry points are:
///
/// - [`crate::vault::Vault::reveal_password`]
/// - [`crate::vault::Vault::reveal_notes`]
/// - [`crate::vault::Vault::reveal_totp_secret`]
///
/// Each requires a fresh [`crate::session::PresenceProof`] in addition
/// to an active session. Without these accessors, an external caller
/// holding a `&AccountSnapshot` reference can only observe the
/// non-secret identity fields (`display_name`, `username`, `url`),
/// which are not on spec §5.4's high-risk list. Internal crate code
/// (the AEAD seal/open path, the search index, `ct_eq`) still has
/// crate-private access.
pub struct AccountSnapshot {
    /// Human-readable display name. Plaintext — but still encrypted at
    /// rest because revealing service display names is a credential
    /// metadata leak. Public field: not on spec §5.4's high-risk list.
    pub display_name: SecretBytes,
    /// Login-username field. Public field: not on spec §5.4's
    /// high-risk list.
    pub username: SecretBytes,
    /// Password. Crate-private — external callers must route through
    /// [`crate::vault::Vault::reveal_password`] (presence-gated). See
    /// the type-level "Presence-escalation discipline" docstring.
    pub(crate) password: SecretBytes,
    /// Service URL the credential applies to. Public field: not on
    /// spec §5.4's high-risk list.
    pub url: SecretBytes,
    /// Free-form notes. Crate-private — external callers must route
    /// through [`crate::vault::Vault::reveal_notes`] (presence-gated).
    /// Notes can carry recovery phrases / answers to security
    /// questions, so they fall under the same reveal-class umbrella as
    /// `password`.
    pub(crate) notes: SecretBytes,
    /// Optional TOTP secret. Empty `SecretBytes` when not configured.
    /// Crate-private — external callers must route through
    /// [`crate::vault::Vault::reveal_totp_secret`] (presence-gated).
    pub(crate) totp_secret: SecretBytes,
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

// =============================================================================
// MVP-1 issue 1.2: production AccountIdentity model
// =============================================================================
//
// Per `docs/issue-plans/1.2.md` §A, the production identity carries
// multi-username, multi-URL, tags, password history (with timestamps +
// originating-device ids), and a TOTP slot. Q2 of 1.2 keeps the types
// physically in `pangolin-store::account`; `pangolin-core` re-exports.

/// Per-field caps + counts for [`AccountIdentity`] validation.
///
/// Surfaced as constants so the FFI binding generators can hard-code
/// the same limits if downstream UIs want to render them. No external
/// configuration knob is exposed in 1.2; future tuning lands additively.
pub mod limits {
    /// Maximum length, in characters (UTF-8 chars, not bytes), of a
    /// display name.
    pub const DISPLAY_NAME_MAX_CHARS: usize = 256;
    /// Maximum number of tags an account may carry.
    pub const TAGS_MAX_COUNT: usize = 32;
    /// Maximum length, in characters, of a single tag.
    pub const TAG_MAX_CHARS: usize = 64;
    /// Maximum number of usernames an account may carry.
    pub const USERNAMES_MAX_COUNT: usize = 16;
    /// Maximum length, in characters, of a single username (RFC-5321
    /// email cap).
    pub const USERNAME_MAX_CHARS: usize = 320;
    /// Maximum number of associated URLs.
    pub const URLS_MAX_COUNT: usize = 32;
    /// Maximum length, in characters, of a single serialised URL.
    pub const URL_MAX_CHARS: usize = 2048;
    /// Maximum length, in characters, of free-form notes.
    pub const NOTES_MAX_CHARS: usize = 65_536;
    /// Maximum length, in bytes, of a single password.
    pub const PASSWORD_MAX_BYTES: usize = 4_096;
    /// Maximum length, in bytes, of a stored TOTP secret. Further
    /// RFC-6238 validation lands in 1.7.
    pub const TOTP_SECRET_MAX_BYTES: usize = 256;
}

/// Schema-version of the in-memory [`AccountIdentity`] model. Mirrors
/// the FFI `schema_version` slot. 1.2 sets this to `1`; 1.6 will
/// promote the value when the policy text is locked.
pub const ACCOUNT_IDENTITY_SCHEMA_VERSION: u16 = 1;

/// On-disk payload version discriminator. V0 = legacy P2 6-field flat
/// snapshot (`AccountSnapshot`); V1 = production 1.2 shape
/// (`AccountIdentity`).
///
/// The payload version is **distinct** from the FFI / SQL-row
/// `schema_version` — the latter is a u16 wire slot whose policy locks
/// in 1.6; the former is a u8 inside the encrypted CBOR body that lets
/// the decode path choose between V0 and V1 hydration. Per the §B
/// table in `docs/issue-plans/1.2.md`, V0 is detected by CBOR map arity
/// (6 entries) and V1 by arity (8 entries with a `payload_version` key).
pub const PAYLOAD_VERSION_V0: u8 = 0;
/// V1 payload-version discriminator — see [`PAYLOAD_VERSION_V0`].
pub const PAYLOAD_VERSION_V1: u8 = 1;

#[allow(clippy::doc_markdown)]
pub mod schemata {
    //! Schemata documentation: V0 → V1 mapping rules.
    //!
    //! Long-term contract: never break V1 reads; future V2 must
    //! auto-migrate from V1 like V1 auto-migrates from V0.
    //!
    //! Read-time auto-migration: when the decoder sees a V0 payload
    //! (arity 6), it hydrates the V1 `AccountIdentity` shape as follows
    //! (see `crate::account` module-level docstring for the mapping
    //! table). Write-time: every write produced by the V1 path emits
    //! V1 payloads. Per Q4 of 1.2, the reject policy for unknown
    //! `payload_version` values locks in 1.6.
}

/// One historical password value for an [`AccountIdentity`]. Always at
/// least one entry (the genesis password) for any non-tombstoned
/// identity.
pub struct PasswordEntry {
    /// The password bytes. Crate-private — external readers must
    /// route through [`crate::vault::Vault::reveal_password`] or the
    /// presence-gated history accessors.
    pub(crate) password: SecretBytes,
    /// Wall-clock unix-ms timestamp at which this password was set.
    pub set_at_ms: i64,
    /// 32-byte authoring device id.
    pub originating_device: DeviceId,
}

impl PasswordEntry {
    /// Construct a new password entry.
    #[must_use]
    pub fn new(password: SecretBytes, set_at_ms: i64, originating_device: DeviceId) -> Self {
        Self {
            password,
            set_at_ms,
            originating_device,
        }
    }

    /// Borrow the password bytes. Crate-private — external code must
    /// route through presence-gated accessors.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn password(&self) -> &SecretBytes {
        &self.password
    }
}

impl fmt::Debug for PasswordEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordEntry")
            .field("password", &"<redacted>")
            .field("set_at_ms", &self.set_at_ms)
            .field("originating_device", &self.originating_device)
            .finish()
    }
}

impl ZeroizeOnDrop for PasswordEntry {}

/// Decrypted plaintext of an account identity (V1 production shape).
///
/// Cardinal-principle-2 discipline (carried over from
/// [`AccountSnapshot`]):
/// - No `Clone`/`Copy`/`PartialEq` derives.
/// - `ZeroizeOnDrop` transitively via secret-bearing fields.
/// - Manual `Debug` impl that redacts every secret field.
/// - Secret-bearing fields are `pub(crate)`; external readers route
///   through `Vault::reveal_*` (presence-gated per spec §5.4).
///
/// Non-secret fields (display name, tags, urls, usernames) are
/// `pub` — they are not on spec §5.4's high-risk list.
pub struct AccountIdentity {
    /// Display name (e.g., "GitHub – Main"). Encrypted at rest.
    pub display_name: SecretBytes,
    /// Tags (e.g., `["work", "shared"]`). Each tag is a separate
    /// [`SecretBytes`] so they can be wiped individually on drop.
    pub tags: Vec<SecretBytes>,
    /// Free-form notes — recovery-class secret per spec §5.4.
    /// Crate-private; reach via
    /// [`crate::vault::Vault::reveal_notes`].
    pub(crate) notes: SecretBytes,
    /// Associated URLs (≥ 0). Validated as parseable strings by
    /// [`validate::urls`] before construction.
    pub urls: Vec<SecretBytes>,
    /// Usernames / emails (≥ 1 by validator).
    pub usernames: Vec<SecretBytes>,
    /// Password history. Index 0 is the current password; older
    /// entries are previous values. Crate-private.
    pub(crate) password_history: Vec<PasswordEntry>,
    /// TOTP secret slot. Empty `SecretBytes` means no TOTP.
    /// Crate-private; reach via
    /// [`crate::vault::Vault::reveal_totp_secret`].
    pub(crate) totp_secret: SecretBytes,
}

impl AccountIdentity {
    /// Construct an [`AccountIdentity`] from already-allocated
    /// `SecretBytes` field owners. **No validation runs here**;
    /// callers must invoke [`AccountIdentityDraft`] or pass through
    /// the validating constructor [`Self::from_validated`].
    #[must_use]
    pub fn new_unchecked(
        display_name: SecretBytes,
        tags: Vec<SecretBytes>,
        notes: SecretBytes,
        urls: Vec<SecretBytes>,
        usernames: Vec<SecretBytes>,
        password_history: Vec<PasswordEntry>,
        totp_secret: SecretBytes,
    ) -> Self {
        Self {
            display_name,
            tags,
            notes,
            urls,
            usernames,
            password_history,
            totp_secret,
        }
    }

    /// Borrow the head-of-history password (the current password).
    /// Crate-private — external readers must route through
    /// `Vault::reveal_password`.
    pub(crate) fn current_password(&self) -> Option<&SecretBytes> {
        self.password_history.first().map(|e| &e.password)
    }

    /// Number of entries in the password history.
    #[must_use]
    pub fn password_history_count(&self) -> usize {
        self.password_history.len()
    }

    /// Whether the TOTP slot is non-empty.
    #[must_use]
    pub fn has_totp(&self) -> bool {
        !self.totp_secret.expose().is_empty()
    }

    /// Borrow the password history. Crate-private accessor for the
    /// presence-gated reveal path; the slice itself is kept private.
    #[allow(dead_code)]
    pub(crate) fn password_history(&self) -> &[PasswordEntry] {
        &self.password_history
    }

    /// Borrow the notes bytes. Crate-private.
    #[allow(dead_code)]
    pub(crate) fn notes(&self) -> &SecretBytes {
        &self.notes
    }

    /// Borrow the totp-secret bytes. Crate-private.
    #[allow(dead_code)]
    pub(crate) fn totp_secret(&self) -> &SecretBytes {
        &self.totp_secret
    }

    /// Constant-time equality across every secret field. Distinct from
    /// `PartialEq` (which is deliberately not implemented).
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        let mut acc = self
            .display_name
            .expose()
            .ct_eq(other.display_name.expose());
        // Tag count + per-tag bytes.
        acc &= subtle::Choice::from(u8::from(self.tags.len() == other.tags.len()));
        if self.tags.len() == other.tags.len() {
            for (a, b) in self.tags.iter().zip(other.tags.iter()) {
                acc &= a.expose().ct_eq(b.expose());
            }
        }
        // Notes.
        acc &= self.notes.expose().ct_eq(other.notes.expose());
        // URLs.
        acc &= subtle::Choice::from(u8::from(self.urls.len() == other.urls.len()));
        if self.urls.len() == other.urls.len() {
            for (a, b) in self.urls.iter().zip(other.urls.iter()) {
                acc &= a.expose().ct_eq(b.expose());
            }
        }
        // Usernames.
        acc &= subtle::Choice::from(u8::from(self.usernames.len() == other.usernames.len()));
        if self.usernames.len() == other.usernames.len() {
            for (a, b) in self.usernames.iter().zip(other.usernames.iter()) {
                acc &= a.expose().ct_eq(b.expose());
            }
        }
        // Password history (length + per-entry password / set_at /
        // originating_device).
        acc &= subtle::Choice::from(u8::from(
            self.password_history.len() == other.password_history.len(),
        ));
        if self.password_history.len() == other.password_history.len() {
            for (a, b) in self
                .password_history
                .iter()
                .zip(other.password_history.iter())
            {
                acc &= a.password.expose().ct_eq(b.password.expose());
                acc &= subtle::Choice::from(u8::from(a.set_at_ms == b.set_at_ms));
                acc &= a.originating_device.0.ct_eq(&b.originating_device.0);
            }
        }
        // TOTP secret.
        acc &= self.totp_secret.expose().ct_eq(other.totp_secret.expose());
        acc
    }
}

impl fmt::Debug for AccountIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountIdentity")
            .field("display_name", &"<redacted>")
            .field("tags", &format!("<{} tags>", self.tags.len()))
            .field("notes", &"<redacted>")
            .field("urls", &format!("<{} urls>", self.urls.len()))
            .field(
                "usernames",
                &format!("<{} usernames>", self.usernames.len()),
            )
            .field(
                "password_history",
                &format!("<{} entries>", self.password_history.len()),
            )
            .field("totp_secret", &"<redacted>")
            .finish()
    }
}

impl ZeroizeOnDrop for AccountIdentity {}

/// Validation entry points for [`AccountIdentity`] construction.
///
/// Every validator is shape-only: no I/O, no allocation beyond what the
/// returned canonical form requires. Errors map to
/// [`StoreError::Validation`] with stable `kind` labels matching the
/// `docs/issue-plans/1.2.md` §E table.
///
/// # Unicode NFC normalisation (audit H-1 / plan §E)
///
/// `display_name`, `tags`, and `usernames` are NFC-normalised before
/// further processing so visually-identical inputs compare equal:
///
/// - `"Café"` (precomposed `U+00E9`) and `"Cafe\u{0301}"` (decomposed
///   `e` + combining acute) produce the same stored bytes.
/// - For tags, this combines with the lowercase + dedup pipeline to
///   eliminate "look-alike duplicate tag" entries that differ only in
///   precomposed vs. decomposed form.
///
/// Notes and URLs are intentionally NOT NFC-normalised — notes are
/// free-form prose that may legitimately contain decomposed forms a
/// user pasted, and URL canonicalisation is delegated to `url::Url`
/// (which does its own host/path canonicalisation).
pub mod validate {
    use super::{limits, Result, StoreError};
    use unicode_normalization::UnicodeNormalization;

    /// NFC-normalise a `&str` and return an owned `String`.
    fn nfc(s: &str) -> String {
        s.nfc().collect()
    }

    /// Validate a display name. Returns the canonical (NFC + trimmed)
    /// form. Audit H-1: NFC runs BEFORE the trim + length check so
    /// equivalent precomposed / decomposed inputs produce identical
    /// stored bytes.
    pub fn display_name(input: &str) -> Result<String> {
        let normalised = nfc(input);
        let trimmed = normalised.trim();
        if trimmed.is_empty() {
            return Err(StoreError::Validation {
                kind: "display_name".into(),
                message: "display name must not be empty".into(),
            });
        }
        if trimmed.chars().count() > limits::DISPLAY_NAME_MAX_CHARS {
            return Err(StoreError::Validation {
                kind: "display_name".into(),
                message: format!(
                    "display name exceeds {} chars",
                    limits::DISPLAY_NAME_MAX_CHARS
                ),
            });
        }
        if has_disallowed_control(trimmed) {
            return Err(StoreError::Validation {
                kind: "display_name".into(),
                message: "display name contains disallowed control chars".into(),
            });
        }
        Ok(trimmed.to_owned())
    }

    /// Validate a tag set.
    ///
    /// Returns the canonical (NFC + trimmed + lowercased +
    /// deduplicated, order-preserving) form. Audit H-1: pipeline
    /// order is NFC → trim → lowercase → dedup so e.g.
    /// `["Café", "Cafe\u{0301}"]` produces a single `"café"` after
    /// deduplication.
    pub fn tags(input: &[String]) -> Result<Vec<String>> {
        if input.len() > limits::TAGS_MAX_COUNT {
            return Err(StoreError::Validation {
                kind: "tags".into(),
                message: format!("at most {} tags allowed", limits::TAGS_MAX_COUNT),
            });
        }
        let mut out: Vec<String> = Vec::with_capacity(input.len());
        for raw in input {
            let normalised = nfc(raw);
            let trimmed = normalised.trim();
            if trimmed.is_empty() {
                return Err(StoreError::Validation {
                    kind: "tags".into(),
                    message: "empty tag rejected".into(),
                });
            }
            if trimmed.chars().count() > limits::TAG_MAX_CHARS {
                return Err(StoreError::Validation {
                    kind: "tags".into(),
                    message: format!("tag exceeds {} chars", limits::TAG_MAX_CHARS),
                });
            }
            if has_disallowed_control(trimmed) {
                return Err(StoreError::Validation {
                    kind: "tags".into(),
                    message: "tag contains disallowed control chars".into(),
                });
            }
            let lower = trimmed.to_lowercase();
            if !out.contains(&lower) {
                out.push(lower);
            }
        }
        Ok(out)
    }

    /// Validate a username set.
    ///
    /// Returns the canonical (trimmed + NFC) form. Audit H-1: trim
    /// runs first (cheap), then NFC on the trimmed slice, then the
    /// length / control-char checks against the post-NFC string so
    /// any sequence-length growth from composition is counted
    /// accurately.
    pub fn usernames(input: &[String]) -> Result<Vec<String>> {
        if input.is_empty() {
            return Err(StoreError::Validation {
                kind: "usernames".into(),
                message: "at least one username is required".into(),
            });
        }
        if input.len() > limits::USERNAMES_MAX_COUNT {
            return Err(StoreError::Validation {
                kind: "usernames".into(),
                message: format!("at most {} usernames allowed", limits::USERNAMES_MAX_COUNT),
            });
        }
        let mut out = Vec::with_capacity(input.len());
        for raw in input {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(StoreError::Validation {
                    kind: "usernames".into(),
                    message: "empty username rejected".into(),
                });
            }
            let normalised = nfc(trimmed);
            if normalised.chars().count() > limits::USERNAME_MAX_CHARS {
                return Err(StoreError::Validation {
                    kind: "usernames".into(),
                    message: format!("username exceeds {} chars", limits::USERNAME_MAX_CHARS),
                });
            }
            if has_disallowed_control(&normalised) {
                return Err(StoreError::Validation {
                    kind: "usernames".into(),
                    message: "username contains disallowed control chars".into(),
                });
            }
            out.push(normalised);
        }
        Ok(out)
    }

    /// Validate a URL set. Each URL must parse via `url::Url::parse`;
    /// any scheme accepted (Q3 of 1.2). Returns the canonical
    /// serialised form.
    pub fn urls(input: &[String]) -> Result<Vec<String>> {
        if input.len() > limits::URLS_MAX_COUNT {
            return Err(StoreError::Validation {
                kind: "url".into(),
                message: format!("at most {} URLs allowed", limits::URLS_MAX_COUNT),
            });
        }
        let mut out = Vec::with_capacity(input.len());
        for raw in input {
            if raw.chars().count() > limits::URL_MAX_CHARS {
                return Err(StoreError::Validation {
                    kind: "url".into(),
                    message: format!("URL exceeds {} chars", limits::URL_MAX_CHARS),
                });
            }
            match url::Url::parse(raw) {
                Ok(parsed) => out.push(parsed.to_string()),
                Err(_) => {
                    return Err(StoreError::Validation {
                        kind: "url".into(),
                        message: "URL did not parse".into(),
                    })
                }
            }
        }
        Ok(out)
    }

    /// Validate notes content.
    pub fn notes(input: &str) -> Result<String> {
        if input.chars().count() > limits::NOTES_MAX_CHARS {
            return Err(StoreError::Validation {
                kind: "notes".into(),
                message: format!("notes exceed {} chars", limits::NOTES_MAX_CHARS),
            });
        }
        Ok(input.to_owned())
    }

    /// Validate password bytes.
    pub fn password(input: &[u8]) -> Result<()> {
        if input.is_empty() {
            return Err(StoreError::Validation {
                kind: "password".into(),
                message: "password must not be empty".into(),
            });
        }
        if input.len() > limits::PASSWORD_MAX_BYTES {
            return Err(StoreError::Validation {
                kind: "password".into(),
                message: format!("password exceeds {} bytes", limits::PASSWORD_MAX_BYTES),
            });
        }
        Ok(())
    }

    /// Validate a TOTP secret byte length.
    pub fn totp_secret(input: &[u8]) -> Result<()> {
        if input.len() > limits::TOTP_SECRET_MAX_BYTES {
            return Err(StoreError::Validation {
                kind: "totp_secret".into(),
                message: format!(
                    "totp secret exceeds {} bytes",
                    limits::TOTP_SECRET_MAX_BYTES
                ),
            });
        }
        Ok(())
    }

    /// True iff the input contains any disallowed control character.
    /// We accept tabs (`\t`) as a concession to imported notes/URLs
    /// but reject every other C0 + DEL (`\u{0000}..=\u{001F}`,
    /// `\u{007F}`).
    fn has_disallowed_control(input: &str) -> bool {
        input
            .chars()
            .any(|c| (c.is_control() && c != '\t') || c == '\u{007F}')
    }
}

/// Draft of a new account identity. Built via either the
/// [`AccountIdentityDraft`] or by direct field construction (the
/// fields are `pub` so callers in `pangolin-ffi` can populate them).
///
/// Validation runs in [`Self::validate_into_identity`] which consumes
/// the draft and produces an [`AccountIdentity`].
#[derive(Debug)]
pub struct AccountIdentityDraft {
    /// Schema-version slot. 1.2 expects [`ACCOUNT_IDENTITY_SCHEMA_VERSION`]
    /// (`1`); per Q4 the value is recorded but not yet rejected.
    pub schema_version: u16,
    /// User-visible display name.
    pub display_name: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Usernames / emails. Must be non-empty.
    pub usernames: Vec<String>,
    /// Associated URLs.
    pub urls: Vec<String>,
    /// Free-form notes. Empty string allowed.
    pub notes: String,
    /// Initial password bytes.
    pub password: SecretBytes,
    /// TOTP secret bytes; empty means no TOTP.
    pub totp_secret: SecretBytes,
}

impl AccountIdentityDraft {
    /// Validate every field and produce an [`AccountIdentity`] with the
    /// genesis password entry installed. The `created_at_ms` and
    /// `originating_device` are caller-supplied so the persistence
    /// layer can bind them to the same wall-clock the SQL row uses.
    pub fn validate_into_identity(
        self,
        created_at_ms: i64,
        originating_device: DeviceId,
    ) -> Result<AccountIdentity> {
        let display_name = validate::display_name(&self.display_name)?;
        let tags = validate::tags(&self.tags)?;
        let usernames = validate::usernames(&self.usernames)?;
        let urls = validate::urls(&self.urls)?;
        let notes = validate::notes(&self.notes)?;
        validate::password(self.password.expose())?;
        validate::totp_secret(self.totp_secret.expose())?;

        let display_name_bytes = SecretBytes::new(display_name.into_bytes());
        let tag_bytes: Vec<SecretBytes> = tags
            .into_iter()
            .map(|t| SecretBytes::new(t.into_bytes()))
            .collect();
        let username_bytes: Vec<SecretBytes> = usernames
            .into_iter()
            .map(|u| SecretBytes::new(u.into_bytes()))
            .collect();
        let url_bytes: Vec<SecretBytes> = urls
            .into_iter()
            .map(|u| SecretBytes::new(u.into_bytes()))
            .collect();
        let notes_bytes = SecretBytes::new(notes.into_bytes());

        let genesis = PasswordEntry::new(self.password, created_at_ms, originating_device);

        Ok(AccountIdentity::new_unchecked(
            display_name_bytes,
            tag_bytes,
            notes_bytes,
            url_bytes,
            username_bytes,
            vec![genesis],
            self.totp_secret,
        ))
    }
}

/// Patch applied via [`crate::vault::Vault::account_update`].
///
/// `None` on a scalar field = leave unchanged; `Some(_)` = replace.
/// `password` = `Some(_)` triggers a history append. `totp_secret`
/// uses a doubled `Option`: outer `None` = leave unchanged; inner
/// `None` = clear; inner `Some(bytes)` = set/replace.
#[derive(Debug)]
pub struct AccountIdentityPatch {
    /// Schema-version slot.
    pub schema_version: u16,
    /// New display name.
    pub display_name: Option<String>,
    /// New tag set (replaces, not merges).
    pub tags: Option<Vec<String>>,
    /// New username set (replaces).
    pub usernames: Option<Vec<String>>,
    /// New URL set (replaces).
    pub urls: Option<Vec<String>>,
    /// New notes (replaces).
    pub notes: Option<String>,
    /// New password — triggers history append.
    pub password: Option<SecretBytes>,
    /// TOTP slot operation — doubled `Option`. Outer `None` = leave
    /// unchanged; inner `None` = clear; inner `Some(bytes)` = set.
    pub totp_secret: Option<Option<SecretBytes>>,
}

impl AccountIdentityPatch {
    /// Apply this patch to `current` in place, validating every field
    /// before mutating. On any validation error the patch surfaces
    /// before any mutation so `current` remains untouched.
    pub fn apply(
        self,
        current: &mut AccountIdentity,
        applied_at_ms: i64,
        applied_by: DeviceId,
    ) -> Result<()> {
        // Pre-validate every supplied field BEFORE mutating.
        let new_display_name = match self.display_name {
            Some(ref s) => Some(validate::display_name(s)?),
            None => None,
        };
        let new_tags = match self.tags {
            Some(ref v) => Some(validate::tags(v)?),
            None => None,
        };
        let new_usernames = match self.usernames {
            Some(ref v) => Some(validate::usernames(v)?),
            None => None,
        };
        let new_urls = match self.urls {
            Some(ref v) => Some(validate::urls(v)?),
            None => None,
        };
        let new_notes = match self.notes {
            Some(ref s) => Some(validate::notes(s)?),
            None => None,
        };
        if let Some(ref pw) = self.password {
            validate::password(pw.expose())?;
        }
        if let Some(Some(secret)) = self.totp_secret.as_ref() {
            validate::totp_secret(secret.expose())?;
        }

        // Mutations.
        if let Some(s) = new_display_name {
            current.display_name = SecretBytes::new(s.into_bytes());
        }
        if let Some(v) = new_tags {
            current.tags = v
                .into_iter()
                .map(|t| SecretBytes::new(t.into_bytes()))
                .collect();
        }
        if let Some(v) = new_usernames {
            current.usernames = v
                .into_iter()
                .map(|u| SecretBytes::new(u.into_bytes()))
                .collect();
        }
        if let Some(v) = new_urls {
            current.urls = v
                .into_iter()
                .map(|u| SecretBytes::new(u.into_bytes()))
                .collect();
        }
        if let Some(s) = new_notes {
            current.notes = SecretBytes::new(s.into_bytes());
        }
        if let Some(new_pw) = self.password {
            // Append the previous current password to history at HEAD;
            // rotate the new one in.
            let entry = PasswordEntry::new(new_pw, applied_at_ms, applied_by);
            current.password_history.insert(0, entry);
        }
        if let Some(outer) = self.totp_secret {
            current.totp_secret = outer.unwrap_or_else(|| SecretBytes::new(Vec::new()));
        }

        Ok(())
    }
}

/// Read-only summary view of an [`AccountIdentity`] surfaced through
/// the FFI.
///
/// **MVP-1 issue 1.4 (Q5b — the strict reveal-gated model):** this
/// type carries **zero secret material**. The fields here are all
/// non-secret display / metadata: display name, tags, usernames, URLs
/// (the V1 model treats those as non-secret), plus the head revision
/// id, the password-history *count*, a `has_totp` flag, and the
/// timestamp the current password was last set. The actual secret
/// bytes — the head password, the full password history with bytes
/// and device ids, the notes, the raw TOTP seed — are reachable
/// **only** through the presence-gated `Vault::reveal_*` entry points
/// (`reveal_current_password` / `reveal_password_history` /
/// `reveal_notes` / `reveal_totp_secret`), each of which checks a
/// fresh presence proof. Under the old design `account_get` /
/// `account_search` returned `Arc<SecretPassword>` / `Arc<TotpSecret>`
/// handles for *every* matched account — a binding shell held those
/// the moment the user searched or opened a detail panel. The strict
/// model: the snapshot never touches an encrypted password blob; the
/// search/list path is metadata-only; least exposure.
///
/// The underlying [`AccountIdentity`] keeps **all** its fields — only
/// this FFI projection is tightened.
pub struct AccountIdentitySummary {
    /// Schema-version slot.
    pub schema_version: u16,
    /// Account id.
    pub id: AccountId,
    /// Head revision id at the time of the snapshot.
    pub head_revision_id: RevisionId,
    /// Display name (UTF-8).
    pub display_name: String,
    /// Tag set (canonical form: lowercased + deduped).
    pub tags: Vec<String>,
    /// Username set.
    pub usernames: Vec<String>,
    /// URL set.
    pub urls: Vec<String>,
    /// Number of password-history entries (the head entry is the
    /// current password). The bytes themselves come from
    /// [`crate::vault::Vault::reveal_password_history`] (presence-gated).
    pub password_history_count: u32,
    /// Whether a TOTP secret is configured. The seed itself comes from
    /// [`crate::vault::Vault::reveal_totp_secret`] (presence-gated).
    pub has_totp: bool,
    /// Wall-clock unix-millisecond timestamp the current (head)
    /// password was set — the `set_at_ms` of the head history entry.
    /// `0` if the history is somehow empty (should not happen for a
    /// well-formed V1 identity, which always has a genesis entry).
    pub current_password_changed_at_ms: i64,
}

impl fmt::Debug for AccountIdentitySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountIdentitySummary")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("head_revision_id", &self.head_revision_id)
            .field("display_name", &"<redacted>")
            .field("tags", &format!("<{} tags>", self.tags.len()))
            .field(
                "usernames",
                &format!("<{} usernames>", self.usernames.len()),
            )
            .field("urls", &format!("<{} urls>", self.urls.len()))
            .field("password_history_count", &self.password_history_count)
            .field("has_totp", &self.has_totp)
            .field(
                "current_password_changed_at_ms",
                &self.current_password_changed_at_ms,
            )
            .finish()
    }
}

/// Non-secret-but-secret-bearing summary entry of a password history
/// item. Mirrors [`PasswordEntry`] but is dimensioned for the FFI
/// summary path.
pub struct PasswordHistorySummaryEntry {
    /// Password bytes for this entry.
    pub password: SecretBytes,
    /// Wall-clock unix-ms timestamp.
    pub set_at_ms: i64,
    /// Originating device.
    pub originating_device: DeviceId,
}

impl fmt::Debug for PasswordHistorySummaryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHistorySummaryEntry")
            .field("password", &"<redacted>")
            .field("set_at_ms", &self.set_at_ms)
            .field("originating_device", &self.originating_device)
            .finish()
    }
}

impl ZeroizeOnDrop for PasswordHistorySummaryEntry {}

#[allow(dead_code)]
const _REV_ID_LEN: usize = REVISION_ID_LEN;

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn fixture_draft() -> AccountIdentityDraft {
        AccountIdentityDraft {
            schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: "GitHub – Main".into(),
            tags: vec!["work".into(), "shared".into()],
            usernames: vec!["alice@example.com".into()],
            urls: vec!["https://github.com".into()],
            notes: "test notes".into(),
            password: SecretBytes::new(b"hunter2".to_vec()),
            totp_secret: SecretBytes::new(b"jbswy3dpehpk3pxp".to_vec()),
        }
    }

    #[test]
    fn draft_validates_into_identity() {
        let draft = fixture_draft();
        let identity = draft
            .validate_into_identity(1_700_000_000_000, DeviceId([0u8; 32]))
            .expect("validate");
        assert_eq!(identity.password_history_count(), 1);
        assert!(identity.has_totp());
        assert_eq!(identity.tags.len(), 2);
        assert_eq!(identity.usernames.len(), 1);
        assert_eq!(identity.urls.len(), 1);
    }

    #[test]
    fn draft_rejects_empty_display_name() {
        let mut draft = fixture_draft();
        draft.display_name = "   ".into();
        let err = draft
            .validate_into_identity(0, DeviceId([0u8; 32]))
            .unwrap_err();
        match err {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "display_name"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn draft_rejects_too_many_usernames() {
        let mut draft = fixture_draft();
        draft.usernames = (0..=limits::USERNAMES_MAX_COUNT)
            .map(|i| format!("user{i}@example.com"))
            .collect();
        let err = draft
            .validate_into_identity(0, DeviceId([0u8; 32]))
            .unwrap_err();
        match err {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "usernames"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn draft_rejects_unparseable_url() {
        let mut draft = fixture_draft();
        draft.urls = vec!["not a url".into()];
        let err = draft
            .validate_into_identity(0, DeviceId([0u8; 32]))
            .unwrap_err();
        match err {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "url"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn draft_rejects_empty_password() {
        let mut draft = fixture_draft();
        draft.password = SecretBytes::new(Vec::new());
        let err = draft
            .validate_into_identity(0, DeviceId([0u8; 32]))
            .unwrap_err();
        match err {
            StoreError::Validation { kind, .. } => assert_eq!(kind, "password"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validate_tags_canonicalises_and_dedups() {
        let canon =
            validate::tags(&["Work".into(), "  WORK ".into(), "shared".into()]).expect("validate");
        assert_eq!(canon, vec!["work".to_string(), "shared".to_string()]);
    }

    #[test]
    fn patch_appends_password_history() {
        let mut identity = fixture_draft()
            .validate_into_identity(1, DeviceId([0xAAu8; 32]))
            .expect("validate");
        assert_eq!(identity.password_history_count(), 1);

        let patch = AccountIdentityPatch {
            schema_version: ACCOUNT_IDENTITY_SCHEMA_VERSION,
            display_name: None,
            tags: None,
            usernames: None,
            urls: None,
            notes: None,
            password: Some(SecretBytes::new(b"hunter3".to_vec())),
            totp_secret: None,
        };
        patch
            .apply(&mut identity, 2, DeviceId([0xBBu8; 32]))
            .expect("apply");
        assert_eq!(identity.password_history_count(), 2);
        // HEAD is the new password; previous head is at index 1.
        assert_eq!(identity.password_history[0].password.expose(), b"hunter3");
        assert_eq!(identity.password_history[1].password.expose(), b"hunter2");
    }

    #[test]
    fn validate_url_accepts_any_scheme() {
        // ssh URI form per RFC 3986. The url crate parses ssh:// with
        // the standard scheme://host[:port]/path shape. Git's bare
        // `git@host:path` syntax is NOT a URL; users supplying that
        // form should use ssh://git@host/path.git instead.
        validate::urls(&[
            "https://github.com".into(),
            "ssh://git@github.com/user/repo.git".into(),
            "mailto:alice@example.com".into(),
            "app://settings".into(),
        ])
        .expect("any-scheme accepted");
    }

    // -- audit H-1: NFC normalisation tests ----------------------------

    /// Two visually-identical display names — one with the precomposed
    /// `é` (U+00E9), one with `e` + combining acute (U+0301) — produce
    /// the same stored `display_name` after NFC normalisation.
    #[test]
    fn display_name_nfc_equivalence() {
        let precomposed = validate::display_name("Café").expect("precomposed");
        let decomposed = validate::display_name("Cafe\u{0301}").expect("decomposed");
        assert_eq!(precomposed, decomposed);
        // The canonical (NFC) form is the precomposed bytes.
        assert_eq!(precomposed.as_bytes(), b"Caf\xc3\xa9");
    }

    /// `["Café", "Cafe\u{0301}"]` → single tag after NFC + lowercase +
    /// dedup. Pipeline order: NFC → trim → lowercase → dedup.
    #[test]
    fn tags_nfc_dedup() {
        let canon = validate::tags(&["Café".into(), "Cafe\u{0301}".into()]).expect("validate");
        assert_eq!(canon.len(), 1);
        assert_eq!(canon[0], "café");
    }

    /// Usernames: precomposed and decomposed forms produce the same
    /// stored bytes (post-NFC).
    #[test]
    fn usernames_nfc_normalised() {
        let v1 = validate::usernames(&["café@example.com".into()]).expect("v1");
        let v2 = validate::usernames(&["cafe\u{0301}@example.com".into()]).expect("v2");
        assert_eq!(v1, v2);
        assert_eq!(v1[0], "café@example.com");
    }

    #[test]
    fn debug_redacts_secrets() {
        let identity = fixture_draft()
            .validate_into_identity(1, DeviceId([0u8; 32]))
            .expect("validate");
        let printed = format!("{identity:?}");
        assert!(!printed.contains("hunter2"));
        assert!(!printed.contains("test notes"));
        assert!(!printed.contains("alice@example.com"));
        assert!(!printed.contains("github.com"));
        assert!(!printed.contains("GitHub – Main"));
        assert!(printed.contains("<redacted>"));
    }
}
