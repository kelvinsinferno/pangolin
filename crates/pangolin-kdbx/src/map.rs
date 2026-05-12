// SPDX-License-Identifier: AGPL-3.0-or-later
//! Mapping layer: a [`crate::KdbxEntry`] → a Pangolin-shaped account
//! draft ([`MappedEntry`]), with per-entry non-fatal skip reasons.
//!
//! This module deliberately does *not* depend on `pangolin-store` — it
//! returns plain owned fields that the consumer (`pangolin-ffi` / the
//! CLI) turns into an `AccountIdentityDraft`. Keeps the dep arrow
//! one-way (`pangolin-ffi`/`apps/cli` → `pangolin-kdbx`).

use pangolin_totp::ParsedTotpSecret;
use zeroize::Zeroizing;

use crate::read::{KdbxDatabase, KdbxEntry};
use crate::Secret;

/// Validator caps mirrored from `pangolin_store::account::limits`
/// (kept local to avoid a `pangolin-store` dep; the consumer's
/// validator is the real enforcement — these just pre-truncate so a
/// hostile field doesn't fail the whole entry).
pub mod caps {
    /// `display_name` max chars.
    pub const DISPLAY_NAME_MAX: usize = 256;
    /// `username` max bytes.
    pub const USERNAME_MAX: usize = 320;
    /// `url` max bytes.
    pub const URL_MAX: usize = 2048;
    /// max urls.
    pub const URLS_MAX: usize = 32;
    /// `tag` max bytes.
    pub const TAG_MAX: usize = 64;
    /// max tags.
    pub const TAGS_MAX: usize = 32;
    /// `notes` max bytes.
    pub const NOTES_MAX: usize = 65_536;
    /// `password` max bytes.
    pub const PASSWORD_MAX: usize = 4096;
}

/// A KeePass field key that maps to a *named* `AccountIdentity` slot
/// (everything else is treated as a custom field appended to `notes`).
fn is_known_key(k: &str) -> bool {
    matches!(
        k,
        "Title" | "UserName" | "Password" | "URL" | "Notes" | "otp"
    ) || k.starts_with("TimeOtp-")
}

/// One successfully-mapped entry, ready for `Vault::account_add`.
///
/// Secret-bearing; `Debug` is redacting.
pub struct MappedEntry {
    /// → `display_name` (always non-empty after synthesis).
    pub display_name: String,
    /// → `usernames` (always ≥1 after placeholder injection).
    pub usernames: Vec<String>,
    /// → `urls` (may be empty).
    pub urls: Vec<String>,
    /// → `notes` (may be empty; may carry a custom-fields block and an
    /// attachment-size note).
    pub notes: String,
    /// → `password` (`SecretBytes` at the consumer boundary).
    pub password: Secret,
    /// → `totp_secret` + `totp_params`, or `None` if no usable TOTP.
    pub totp: Option<ParsedTotpSecret>,
    /// → `tags` (KeePass `<Tags>` ∪ group path; `"expired"` if expired).
    pub tags: Vec<String>,
    /// Historical `Password` values, oldest→newest, deduped against
    /// consecutive equals and the current password, capped at
    /// [`crate::KDBX_MAX_HISTORY_PER_ENTRY`]. Each carries an optional
    /// Unix-second timestamp from the KeePass history entry.
    pub history_passwords: Vec<(Secret, Option<i64>)>,
}

impl core::fmt::Debug for MappedEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MappedEntry")
            .field("display_name_len", &self.display_name.len())
            .field("username_count", &self.usernames.len())
            .field("url_count", &self.urls.len())
            .field("notes_len", &self.notes.len())
            .field("password_len", &self.password.len())
            .field("has_totp", &self.totp.is_some())
            .field("tags", &self.tags)
            .field("history_len", &self.history_passwords.len())
            .finish()
    }
}

/// Why a particular source entry was skipped (counted, never imported).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySkip {
    /// The entry had no (or an empty) `Password` field — not a credential.
    EmptyPassword,
    /// The entry had no usable `<String>` fields at all.
    NoFields,
}

impl EntrySkip {
    /// A non-secret category label for a `failure_kinds`-style report.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::EmptyPassword => "empty_password",
            Self::NoFields => "no_fields",
        }
    }
}

/// The result of mapping a whole database.
pub struct MapResult {
    /// Successfully-mapped entries (ready to ingest).
    pub entries: Vec<MappedEntry>,
    /// Per-entry skip reasons (counted but not imported).
    pub skipped: Vec<EntrySkip>,
    /// Number of recycle-bin entries the parser dropped.
    pub recycle_bin_entries: usize,
}

impl core::fmt::Debug for MapResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MapResult")
            .field("mapped", &self.entries.len())
            .field("skipped", &self.skipped.len())
            .field("recycle_bin_entries", &self.recycle_bin_entries)
            .finish()
    }
}

/// Map every entry of a parsed database.
#[must_use]
pub fn map_database(db: &KdbxDatabase) -> MapResult {
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let attachment_note = if db.binary_count > 0 {
        Some(format!(
            "[{} attachment(s) not imported, ~{} KiB total]",
            db.binary_count,
            db.binary_total_bytes.div_ceil(1024)
        ))
    } else {
        None
    };
    for e in &db.entries {
        match map_entry(e, attachment_note.as_deref()) {
            Ok(m) => entries.push(m),
            Err(s) => skipped.push(s),
        }
    }
    MapResult {
        entries,
        skipped,
        recycle_bin_entries: db.recycle_bin_entries,
    }
}

fn val_str(e: &KdbxEntry, key: &str) -> String {
    e.field(key)
        .map(|v| v.as_str_lossy().into_owned())
        .unwrap_or_default()
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Map a single entry. `Err` = the entry is skipped (counted).
#[allow(clippy::too_many_lines)]
fn map_entry(e: &KdbxEntry, attachment_note: Option<&str>) -> Result<MappedEntry, EntrySkip> {
    if e.strings.is_empty() {
        return Err(EntrySkip::NoFields);
    }
    // Password — empty ⇒ skip (an entry with no password isn't a
    // credential, per L18).
    let password_str = val_str(e, "Password");
    if password_str.trim().is_empty() {
        return Err(EntrySkip::EmptyPassword);
    }
    let mut password_bytes = e
        .field("Password")
        .map(|v| v.value.to_vec())
        .unwrap_or_default();
    if password_bytes.len() > caps::PASSWORD_MAX {
        password_bytes.truncate(caps::PASSWORD_MAX);
    }
    let password: Secret = Zeroizing::new(password_bytes);

    let title = val_str(e, "Title");
    let username_raw = val_str(e, "UserName");
    let url_raw = val_str(e, "URL");
    let notes_raw = val_str(e, "Notes");

    // display_name — synthesise if empty.
    let display_name = if title.trim().is_empty() {
        if !username_raw.trim().is_empty() {
            format!("(untitled — {})", username_raw.trim())
        } else if !url_raw.trim().is_empty() {
            // host-ish portion if possible
            let host = url_raw
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("");
            if host.is_empty() {
                "Imported entry".to_string()
            } else {
                format!("(untitled — {host})")
            }
        } else {
            "Imported entry".to_string()
        }
    } else {
        title.trim().to_string()
    };
    let display_name = truncate_chars(&display_name, caps::DISPLAY_NAME_MAX);

    // usernames — ≥1; placeholder if empty.
    let username = if username_raw.trim().is_empty() {
        "(no username)".to_string()
    } else {
        truncate_bytes(username_raw.trim(), caps::USERNAME_MAX)
    };
    let usernames = vec![username];

    // urls — at most 1 from the URL field; drop unparseable rather than
    // fail. The consumer's validator parses with the `url` crate; here
    // we only do a cheap sanity check + truncate.
    let mut urls = Vec::new();
    let url_trim = url_raw.trim();
    if !url_trim.is_empty() && url_trim.len() <= caps::URL_MAX {
        // Accept it if it looks like a scheme://… or host-ish thing;
        // the real parse happens downstream. KeePass `{S:..}` / `cmd://`
        // placeholders: keep verbatim — any scheme is allowed (1.2 Q3).
        if url_trim.contains("://") || url_trim.contains('.') {
            urls.push(url_trim.to_string());
        }
        // else: drop it (downstream validator would reject a bare word).
    }
    if urls.len() > caps::URLS_MAX {
        urls.truncate(caps::URLS_MAX);
    }

    // notes — base + custom-fields block + attachment note.
    let mut notes = notes_raw;
    let custom: Vec<&crate::read::KdbxStringValue> =
        e.strings.iter().filter(|s| !is_known_key(&s.key)).collect();
    if !custom.is_empty() {
        if !notes.is_empty() {
            notes.push('\n');
        }
        notes.push_str("--- Imported custom fields ---");
        for s in custom {
            notes.push('\n');
            notes.push_str(&s.key);
            notes.push_str(": ");
            notes.push_str(&s.as_str_lossy());
        }
    }
    if let Some(an) = attachment_note {
        if !notes.is_empty() {
            notes.push('\n');
        }
        notes.push_str(an);
    }
    let mut notes = truncate_bytes(&notes, caps::NOTES_MAX);
    if notes.len() == caps::NOTES_MAX {
        // Add a marker (best-effort; trims a little more to fit).
        let marker = "\n[notes truncated]";
        notes = truncate_bytes(&notes, caps::NOTES_MAX - marker.len());
        notes.push_str(marker);
    }

    // TOTP — from `otp` (an otpauth:// URI) or the `TimeOtp-*` fields.
    let totp = extract_totp(e);

    // tags — KeePass <Tags> ∪ group path ∪ "expired".
    let mut tags: Vec<String> = Vec::new();
    for t in &e.tags {
        tags.push(truncate_bytes(t.trim(), caps::TAG_MAX));
    }
    for g in &e.group_path {
        let g = g.trim();
        if !g.is_empty() {
            tags.push(truncate_bytes(g, caps::TAG_MAX));
        }
    }
    let now = current_unix_secs();
    let expired = e.expires && e.expiry_time_unix.is_some_and(|t| t < now);
    if expired {
        tags.push("expired".to_string());
    }
    // Dedup case-insensitively, preserve order, cap.
    let mut seen = std::collections::HashSet::new();
    tags.retain(|t| !t.is_empty() && seen.insert(t.to_ascii_lowercase()));
    if tags.len() > caps::TAGS_MAX {
        tags.truncate(caps::TAGS_MAX);
    }

    // History passwords — distinct, oldest→newest, dedup consecutive
    // equals + the current password, cap.
    let mut history: Vec<(Secret, Option<i64>)> = Vec::new();
    let mut prev: Option<Vec<u8>> = None;
    for (pw, ts) in &e.history_passwords {
        if pw.is_empty() {
            continue;
        }
        let bytes: Vec<u8> = pw.to_vec();
        if prev.as_deref() == Some(bytes.as_slice()) {
            continue;
        }
        if bytes == *password {
            // The most recent history entry that equals the current
            // password is redundant.
            continue;
        }
        if bytes.len() > caps::PASSWORD_MAX {
            // Skip an over-long historical password rather than truncate
            // (truncation would corrupt it).
            continue;
        }
        prev = Some(bytes.clone());
        history.push((Zeroizing::new(bytes), *ts));
        if history.len() >= crate::KDBX_MAX_HISTORY_PER_ENTRY {
            break;
        }
    }

    Ok(MappedEntry {
        display_name,
        usernames,
        urls,
        notes,
        password,
        totp,
        tags,
        history_passwords: history,
    })
}

/// Extract a usable TOTP config from an entry, or `None`. KeePassXC
/// stores it either as an `otp` field holding an `otpauth://totp/...`
/// URI, or as `TimeOtp-Secret-Base32` (+ `TimeOtp-Period` /
/// `TimeOtp-Digits` / `TimeOtp-Algorithm`). HOTP / unparseable → `None`.
fn extract_totp(e: &KdbxEntry) -> Option<ParsedTotpSecret> {
    if let Some(otp) = e.field("otp") {
        let s = otp.as_str_lossy();
        let t = s.trim();
        if !t.is_empty() {
            if let Ok(p) = pangolin_totp::parse_totp_secret(t) {
                return Some(p);
            }
        }
    }
    // KeePassXC native TimeOtp-* scheme.
    if let Some(b32) = e.field("TimeOtp-Secret-Base32") {
        let secret = b32.as_str_lossy();
        let secret = secret.trim();
        if !secret.is_empty() {
            let period = e
                .field("TimeOtp-Period")
                .and_then(|v| v.as_str_lossy().trim().parse::<u32>().ok())
                .filter(|p| *p >= 1);
            let digits = e
                .field("TimeOtp-Digits")
                .and_then(|v| v.as_str_lossy().trim().parse::<u8>().ok())
                .filter(|d| matches!(d, 6..=8));
            let algo = e
                .field("TimeOtp-Algorithm")
                .map(|v| v.as_str_lossy().trim().to_ascii_uppercase());
            // Build an otpauth:// URI so the 1.7 parser does all
            // validation/normalisation in one place.
            let mut uri = format!("otpauth://totp/imported?secret={secret}");
            if let Some(p) = period {
                uri.push_str(&format!("&period={p}"));
            }
            if let Some(d) = digits {
                uri.push_str(&format!("&digits={d}"));
            }
            if let Some(a) = algo {
                // Map KeePassXC's "HMAC-SHA-1"/"HMAC-SHA-256"/... to the
                // otpauth `SHA1`/`SHA256`/`SHA512` spelling.
                let canon = a
                    .replace("HMAC-", "")
                    .replace("HMAC", "")
                    .replace("SHA-", "SHA")
                    .replace('-', "");
                if matches!(canon.as_str(), "SHA1" | "SHA256" | "SHA512") {
                    uri.push_str(&format!("&algorithm={canon}"));
                }
            }
            if let Ok(p) = pangolin_totp::parse_otpauth_uri(&uri) {
                return Some(p);
            }
        }
    }
    None
}

/// Current Unix seconds (used only for the `expired` decision; no hard
/// timing assertion anywhere).
fn current_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
