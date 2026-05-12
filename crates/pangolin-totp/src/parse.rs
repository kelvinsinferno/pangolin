// SPDX-License-Identifier: AGPL-3.0-or-later
//! `otpauth://` URI + bare-base32 secret parsing.
//!
//! Hand-rolled per MVP-1 issue 1.7 (Q4): a ~30-line RFC 4648 base32
//! decoder plus a fixed-shape `otpauth://totp/...` splitter — no `url` /
//! `data-encoding` crate dependency. The decoded secret is wrapped in
//! [`zeroize::Zeroizing`].

use zeroize::Zeroizing;

use crate::{TotpAlgorithm, TotpError, TotpParams, MAX_SECRET_BYTES};

/// The result of parsing a user- or KDBX-supplied TOTP string.
///
/// `label` and `issuer` are advisory metadata (the shell may use them to
/// pre-fill a display name); `pangolin-store` only persists
/// `{ secret_bytes, params }`.
pub struct ParsedTotpSecret {
    /// The raw shared-secret seed bytes (zeroizing).
    pub secret_bytes: Zeroizing<Vec<u8>>,
    /// The TOTP parameters (algorithm / digits / period).
    pub params: TotpParams,
    /// Optional `otpauth://` label (the account name).
    pub label: Option<String>,
    /// Optional `issuer=` query value.
    pub issuer: Option<String>,
}

impl core::fmt::Debug for ParsedTotpSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParsedTotpSecret")
            .field("secret_bytes", &"<redacted>")
            .field("secret_len", &self.secret_bytes.len())
            .field("params", &self.params)
            .field("label", &self.label)
            .field("issuer", &self.issuer)
            .finish()
    }
}

/// Decode an RFC 4648 base32 string into raw bytes.
///
/// Accepts the uppercase alphabet `A-Z` + `2-7`, case-insensitively;
/// tolerates and strips trailing `=` padding and embedded ASCII
/// whitespace (some sites print the secret in space-separated quads).
/// Any other character is rejected.
///
/// # Errors
/// [`TotpError::InvalidBase32`] for a bad character or an invalid bit
/// remainder.
pub fn decode_base32(input: &str) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 5 / 8 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in input.chars() {
        if ch == '=' || ch.is_ascii_whitespace() || ch == '-' {
            // Padding / formatting separators are ignored. (`-` appears
            // in some space-quad renderings; `=` is RFC padding.)
            continue;
        }
        let val: u32 = match ch.to_ascii_uppercase() {
            c @ 'A'..='Z' => u32::from(c as u8 - b'A'),
            c @ '2'..='7' => u32::from(c as u8 - b'2') + 26,
            other => {
                return Err(TotpError::InvalidBase32 {
                    reason: format!("invalid character {other:?}"),
                })
            }
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).expect("masked to a byte"));
        }
    }
    // Any leftover bits must be zero padding (< 5 bits worth of a
    // partial group); a non-zero remainder means a malformed string.
    if bits >= 5 || (buffer & ((1u32 << bits) - 1) != 0 && bits > 0) {
        return Err(TotpError::InvalidBase32 {
            reason: "non-zero trailing bits".into(),
        });
    }
    Ok(Zeroizing::new(out))
}

/// Parse a full `otpauth://totp/<label>?secret=...&...` URI.
///
/// `secret=` is required; `algorithm` / `digits` / `period` are optional
/// and default to SHA1 / 6 / 30. Unknown query parameters are ignored.
/// An `otpauth://hotp/...` URI is rejected ([`TotpError::HotpNotSupported`]).
///
/// # Errors
/// [`TotpError::MalformedUri`] / [`TotpError::HotpNotSupported`] /
/// [`TotpError::UnsupportedAlgorithm`] / [`TotpError::InvalidBase32`] /
/// [`TotpError::InvalidDigits`] / [`TotpError::InvalidPeriod`] /
/// [`TotpError::EmptySecret`] / [`TotpError::SecretTooLong`].
pub fn parse_otpauth_uri(input: &str) -> Result<ParsedTotpSecret, TotpError> {
    let rest = input
        .strip_prefix("otpauth://")
        .ok_or_else(|| TotpError::MalformedUri {
            reason: "missing otpauth:// scheme".into(),
        })?;
    // Split into "host/path" and "query".
    let (host_path, query) = match rest.split_once('?') {
        Some((hp, q)) => (hp, q),
        None => (rest, ""),
    };
    let (host, path) = match host_path.split_once('/') {
        Some((h, p)) => (h, p),
        None => (host_path, ""),
    };
    match host.to_ascii_lowercase().as_str() {
        "totp" => {}
        "hotp" => return Err(TotpError::HotpNotSupported),
        other => {
            return Err(TotpError::MalformedUri {
                reason: format!("unexpected otpauth type {other:?}"),
            })
        }
    }
    let label = if path.is_empty() {
        None
    } else {
        Some(percent_decode(path))
    };

    let mut secret_str: Option<String> = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits: u8 = 6;
    let mut period: u32 = 30;
    let mut issuer: Option<String> = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret_str = Some(v),
            "algorithm" => algorithm = TotpAlgorithm::parse(&v)?,
            "digits" => {
                digits = v.parse::<u8>().map_err(|_| TotpError::InvalidDigits(0))?;
            }
            "period" => {
                period = v.parse::<u32>().map_err(|_| TotpError::InvalidPeriod(0))?;
            }
            "issuer" => issuer = Some(v),
            _ => {} // unknown query params ignored
        }
    }
    let secret_str = secret_str.ok_or_else(|| TotpError::MalformedUri {
        reason: "missing secret= parameter".into(),
    })?;
    let secret_bytes = decode_base32(&secret_str)?;
    finish(
        secret_bytes,
        TotpParams {
            algorithm,
            digits,
            period_seconds: period,
        },
        label,
        issuer,
    )
}

/// Parse either a full `otpauth://` URI or a bare base32 secret.
///
/// If `input` starts with `otpauth://` it is parsed as a URI; otherwise
/// the whole string is treated as a bare base32 secret with the RFC
/// default parameters (SHA1 / 6 / 30).
///
/// # Errors
/// As [`parse_otpauth_uri`] / [`decode_base32`], plus
/// [`TotpError::EmptySecret`] for an empty/whitespace-only input.
pub fn parse_totp_secret(input: &str) -> Result<ParsedTotpSecret, TotpError> {
    let trimmed = input.trim();
    if trimmed.starts_with("otpauth://") {
        return parse_otpauth_uri(trimmed);
    }
    if trimmed.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    let secret_bytes = decode_base32(trimmed)?;
    finish(secret_bytes, TotpParams::default(), None, None)
}

fn finish(
    secret_bytes: Zeroizing<Vec<u8>>,
    params: TotpParams,
    label: Option<String>,
    issuer: Option<String>,
) -> Result<ParsedTotpSecret, TotpError> {
    if secret_bytes.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if secret_bytes.len() > MAX_SECRET_BYTES {
        return Err(TotpError::SecretTooLong {
            len: secret_bytes.len(),
            max: MAX_SECRET_BYTES,
        });
    }
    params.validate()?;
    Ok(ParsedTotpSecret {
        secret_bytes,
        params,
        label,
        issuer,
    })
}

/// Minimal percent-decode for `otpauth://` label / query values. Decodes
/// `%XX` escapes and `+` → space; leaves any malformed escape verbatim.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_known_vectors() {
        // RFC 4648 §10 base32 test vectors.
        assert_eq!(&**decode_base32("MY======").unwrap(), b"f");
        assert_eq!(&**decode_base32("MZXQ====").unwrap(), b"fo");
        assert_eq!(&**decode_base32("MZXW6===").unwrap(), b"foo");
        assert_eq!(&**decode_base32("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(&**decode_base32("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(&**decode_base32("MZXW6YTBOI======").unwrap(), b"foobar");
        // The classic Google Authenticator demo secret.
        assert_eq!(
            &**decode_base32("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
    }

    #[test]
    fn base32_case_insensitive_and_spaces() {
        assert_eq!(
            decode_base32("mzxw6ytb").unwrap().to_vec(),
            decode_base32("MZXW6YTB").unwrap().to_vec()
        );
        assert_eq!(
            decode_base32("MZXW 6YTB OI").unwrap().to_vec(),
            decode_base32("MZXW6YTBOI").unwrap().to_vec()
        );
    }

    #[test]
    fn base32_rejects_bad_chars() {
        assert!(matches!(
            decode_base32("MZXW0YTB"),
            Err(TotpError::InvalidBase32 { .. })
        ));
        assert!(matches!(
            decode_base32("MZXW!YTB"),
            Err(TotpError::InvalidBase32 { .. })
        ));
    }

    #[test]
    fn otpauth_happy_path_with_params() {
        let uri = "otpauth://totp/ACME%20Co:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60";
        let p = parse_otpauth_uri(uri).unwrap();
        assert_eq!(p.params.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(p.params.digits, 8);
        assert_eq!(p.params.period_seconds, 60);
        assert_eq!(p.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(p.label.as_deref(), Some("ACME Co:alice@acme.com"));
        assert_eq!(&*p.secret_bytes, b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn otpauth_defaults_when_omitted() {
        let p = parse_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(p.params, TotpParams::default());
    }

    #[test]
    fn otpauth_rejects_hotp_and_malformed() {
        assert_eq!(
            parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=0").unwrap_err(),
            TotpError::HotpNotSupported
        );
        assert!(matches!(
            parse_otpauth_uri("otpauth://totp/x"),
            Err(TotpError::MalformedUri { .. })
        ));
        assert!(matches!(
            parse_otpauth_uri("https://totp/x?secret=AA"),
            Err(TotpError::MalformedUri { .. })
        ));
        assert!(matches!(
            parse_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=md5"),
            Err(TotpError::UnsupportedAlgorithm(_))
        ));
        assert!(matches!(
            parse_otpauth_uri("otpauth://totp/x?secret=!!!notbase32"),
            Err(TotpError::InvalidBase32 { .. })
        ));
    }

    #[test]
    fn parse_totp_secret_dispatch() {
        let bare = parse_totp_secret("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(bare.params, TotpParams::default());
        assert_eq!(&*bare.secret_bytes, b"Hello!\xde\xad\xbe\xef");
        let uri = parse_totp_secret("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8").unwrap();
        assert_eq!(uri.params.digits, 8);
        assert_eq!(
            parse_totp_secret("   ").unwrap_err(),
            TotpError::EmptySecret
        );
    }

    #[test]
    fn parsed_debug_redacts_secret() {
        let p = parse_totp_secret("JBSWY3DPEHPK3PXP").unwrap();
        let printed = format!("{p:?}");
        assert!(printed.contains("<redacted>"));
    }
}
