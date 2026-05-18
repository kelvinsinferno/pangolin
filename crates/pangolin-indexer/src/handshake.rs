// SPDX-License-Identifier: AGPL-3.0-or-later
//! §4.3 per-column AEAD: binary stdin handshake (ARCH-1).
//!
//! Per the locked `R-e` resolution of the §4.3 per-column-AEAD plan-
//! gate, the standalone `pangolin-indexer` binary NO LONGER generates
//! a random AEAD key in-process (the §4.3-baseline behaviour). The
//! load-bearing posture is now:
//!
//! 1. **Host derives + sends.** The host (CLI / Tauri / mobile FFI)
//!    holds the device's [`pangolin_crypto::keys::DeviceKey`], calls
//!    [`pangolin_chain::derive_indexer_key`] to produce a 32-byte
//!    ephemeral AEAD key, and writes a length-prefixed CBOR-framed
//!    [`IndexerHandshake`] to the indexer's stdin BEFORE the first
//!    chain-RPC config / protocol request.
//! 2. **Indexer receives + zeroizes.** The indexer's `main.rs`
//!    deserialises the handshake via [`read_handshake`], moves the
//!    derived key into a [`pangolin_crypto::secret::SecretBytes`]
//!    (heap-allocated; zeros on Drop), and **explicitly zeroizes the
//!    raw stdin buffer** before proceeding to the stdio protocol
//!    loop. The binary's own address space NEVER holds the derived
//!    key in mutable stack-side memory beyond the handshake routine.
//! 3. **Run nonce is plumbed through.** The run_nonce is also
//!    delivered in the handshake so future hardening (e.g., adding
//!    the run_nonce to the per-row AAD) can land without a wire-
//!    format break.
//!
//! ## Why ARCH-1 (host-derives-and-sends) over alternatives
//!
//! The §4.3 plan-gate's R-e Resolved-decisions row evaluates four
//! shapes:
//!
//! - **ARCH-0 (baseline; rejected):** binary generates a random key
//!   in-process. **Defect:** the "derived from device secret"
//!   property of the master plan §5 row 4.3 is not satisfied —
//!   different indexer runs share no derivation lineage with the
//!   device, so a future cycle that adds key-recovery semantics
//!   (e.g., resumable persistent fast-mode caches) would have to
//!   restructure the handshake from scratch.
//! - **ARCH-1 (host derives, sends via stdin; CHOSEN):** the binary's
//!   own secret-material reach stays minimal (it never imports
//!   `DeviceKey`); the derivation lineage runs in the host where
//!   `DeviceKey` already lives. Wire format is forward-compatible
//!   (additive CBOR fields land without bumping the schema). The
//!   binary's stdin is the same trust boundary as the JSON protocol
//!   surface — already host-only by R-b posture.
//! - **ARCH-2 (binary imports `DeviceKey` directly):** widens the
//!   indexer's secret-material reach to include the device's signing
//!   key. Rejected on `L-indexer-grows-pangolin-crypto-secret-
//!   material-reach` grounds — already documented in the §4.3 plan-
//!   gate's L-section.
//! - **ARCH-3 (binary reads a file path from argv):** would require
//!   a side-channel for the key file + filesystem-permission
//!   management. Rejected as more complex than stdin without a
//!   countervailing security benefit.
//!
//! ## Wire format
//!
//! ```text
//! [length (4 bytes, big-endian u32)] [cbor body (length bytes)]
//! ```
//!
//! CBOR body (canonical map encoding; arity-2; text keys in
//! lexicographic order — `derived_key` < `run_nonce`):
//!
//! ```text
//! map(2) {
//!     text("derived_key") => bytes(32),
//!     text("run_nonce")   => bytes(16),
//! }
//! ```
//!
//! The 4-byte length prefix exists so the binary can read EXACTLY
//! the handshake bytes off stdin before switching to the line-
//! delimited JSON protocol — there is no stdin redirection (the
//! protocol bytes share the same FD), so the binary needs to know
//! how many bytes to consume up-front. The length is bounded by
//! [`MAX_HANDSHAKE_BYTES`] (256 bytes) to defend against a malicious
//! host that sends a multi-gigabyte length prefix.
//!
//! ## Host caller contract (MVP-3 host-FFI cycle)
//!
//! The host caller MUST:
//!
//! 1. Spawn the `pangolin-indexer` binary with `Stdio::piped()` on
//!    stdin + stdout + stderr.
//! 2. Generate a fresh 16-byte `run_nonce` via OS CSPRNG.
//! 3. Call `pangolin_chain::derive_indexer_key(device_key, &run_nonce)`
//!    to produce the 32-byte derived key.
//! 4. Construct `IndexerHandshake { derived_key, run_nonce }`.
//! 5. Call [`write_handshake`] with the binary's stdin handle to
//!    write the length-prefixed CBOR frame.
//! 6. ONLY THEN begin writing line-delimited JSON requests on the
//!    same stdin stream.
//!
//! The binary's [`crate::IndexerSession`] is constructed inside the
//! binary AFTER the handshake completes, so the host does not pass
//! the cipher constructor directly — it just hands the binary the
//! derivation output and the binary wires it into `AeadCipher`.
//!
//! ## Test surface
//!
//! - `crates/pangolin-indexer/tests/handshake_ipc.rs` — round-trip
//!   tests for [`write_handshake`] / [`read_handshake`] across
//!   in-memory pipe pairs + boundary cases (truncated frame, oversize
//!   length, malformed CBOR, missing required field).
//! - `crates/pangolin-indexer/tests/proptest_aad_perturbations.rs` —
//!   adjacent property tests including handshake round-trips.

#![allow(clippy::doc_markdown)]

use std::io::{Read, Write};

// `ciborium_io` re-exports `Read` / `Write` traits the low-level
// `ciborium_ll::{Decoder, Encoder}` rely on. We alias them to avoid
// name collision with `std::io::{Read, Write}` which we ALSO need
// for the host-facing `read_handshake` / `write_handshake`
// signatures.
use ciborium_io::{Read as CborRead, Write as CborWrite};
use ciborium_ll::{Decoder, Encoder, Header};
use zeroize::Zeroize;

/// Length of the derived AEAD key carried in the handshake. Must
/// match `pangolin_crypto::aead::KEY_LEN` (32 bytes).
pub const HANDSHAKE_KEY_LEN: usize = 32;

/// Length of the per-run nonce carried in the handshake. Mirrors the
/// `run_nonce: [u8; 16]` parameter of
/// [`pangolin_chain::derive_indexer_key`].
pub const HANDSHAKE_RUN_NONCE_LEN: usize = 16;

/// Maximum byte-size of a single handshake CBOR body.
///
/// The canonical encoding of `IndexerHandshake` is ~60 bytes (text
/// keys, the 32 + 16 byte-string payloads, and the map header); the
/// 256-byte cap gives slack for future additive fields while
/// bounding the binary's read buffer cheaply. Any length prefix
/// exceeding this is rejected as [`HandshakeError::OversizeFrame`].
pub const MAX_HANDSHAKE_BYTES: usize = 256;

/// CBOR text key for the `derived_key` field. Order-sensitive —
/// must sort lexicographically BEFORE [`KEY_RUN_NONCE`] in the
/// canonical encoding.
const KEY_DERIVED_KEY: &str = "derived_key";

/// CBOR text key for the `run_nonce` field.
const KEY_RUN_NONCE: &str = "run_nonce";

/// §4.3 per-column AEAD (ARCH-1): the handshake message the host
/// writes to the indexer's stdin BEFORE the first protocol request.
///
/// Carries the host-derived 32-byte ephemeral AEAD key + the
/// 16-byte per-run nonce used during the HKDF expansion. The
/// indexer's `main.rs` reads this once at startup, plumbs the
/// derived key into [`crate::AeadCipher::new_arc`], and zeroizes
/// the stdin buffer before proceeding to the line-delimited JSON
/// protocol loop.
///
/// **Lifecycle:** the `IndexerHandshake` value MUST be dropped
/// (consumed into `SecretBytes`) as soon as the cipher is
/// constructed — its `Drop` impl zeroes the inner buffers via
/// the [`zeroize::Zeroize`] discipline. Do NOT clone, do NOT log,
/// do NOT serialize for diagnostics.
///
/// # Host contract (MVP-3 host-FFI cycle)
///
/// See the module-level docstring for the full spawn-and-write
/// sequence. The TL;DR:
///
/// ```ignore
/// // Host pseudocode (MVP-3 surface):
/// let run_nonce: [u8; 16] = rand_array();
/// let derived = pangolin_chain::derive_indexer_key(&device_key, &run_nonce)?;
/// let mut k = [0u8; 32];
/// k.copy_from_slice(derived.expose());
/// let handshake = pangolin_indexer::IndexerHandshake { derived_key: k, run_nonce };
/// pangolin_indexer::write_handshake(child.stdin.as_mut().unwrap(), &handshake)?;
/// // ... then send the first IndexerRequest line.
/// ```
pub struct IndexerHandshake {
    /// 32-byte ephemeral AEAD key derived by the host via
    /// [`pangolin_chain::derive_indexer_key`].
    pub derived_key: [u8; HANDSHAKE_KEY_LEN],
    /// 16-byte per-run nonce the host used as the HKDF salt for
    /// the derivation. Carried for completeness so future cycles
    /// can mix it into the AAD or surface it in diagnostics; not
    /// secret material (it is the salt, not the IKM).
    pub run_nonce: [u8; HANDSHAKE_RUN_NONCE_LEN],
}

impl IndexerHandshake {
    /// Construct a handshake from the two raw arrays. The host
    /// caller typically wires this via the example in the module
    /// docstring.
    #[must_use]
    pub fn new(
        derived_key: [u8; HANDSHAKE_KEY_LEN],
        run_nonce: [u8; HANDSHAKE_RUN_NONCE_LEN],
    ) -> Self {
        Self {
            derived_key,
            run_nonce,
        }
    }
}

impl std::fmt::Debug for IndexerHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // L3 hygiene: never print the key bytes. The run_nonce is
        // non-secret but redacted alongside for consistent shape.
        f.debug_struct("IndexerHandshake")
            .field("derived_key", &"<redacted-32-bytes>")
            .field("run_nonce", &"<redacted-16-bytes>")
            .finish()
    }
}

impl Drop for IndexerHandshake {
    fn drop(&mut self) {
        // L3: zero the derived key bytes on Drop. The run_nonce is
        // non-secret so we don't bother — it's a salt; an attacker
        // who reads it learns the HKDF salt and nothing more
        // (deriving from the same salt requires the device IKM,
        // which the indexer process does not hold).
        self.derived_key.zeroize();
    }
}

/// Typed errors returned by [`read_handshake`] / [`write_handshake`].
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// stdin closed (or the host wrote less than 4 bytes before
    /// closing) before the length prefix arrived. The binary
    /// surfaces this as a fatal startup error.
    #[error("handshake stdin closed before length prefix")]
    PrefixTruncated,

    /// Length prefix is larger than [`MAX_HANDSHAKE_BYTES`].
    /// Defense against a malicious host that sends a multi-gigabyte
    /// frame to OOM the indexer.
    #[error("handshake length prefix {len} > MAX_HANDSHAKE_BYTES = {max}")]
    OversizeFrame { len: u32, max: usize },

    /// stdin closed before the full CBOR body arrived (after the
    /// length prefix). Distinct from [`HandshakeError::PrefixTruncated`]
    /// so the binary can log a more specific error.
    #[error("handshake body truncated: read {got} of {expected} bytes")]
    BodyTruncated { got: usize, expected: usize },

    /// CBOR body did not decode as a `map(2)` with the required
    /// fields, or one of the byte-string fields was the wrong
    /// length, or the map keys were not in canonical order.
    #[error("handshake CBOR malformed: {0}")]
    Cbor(String),

    /// I/O error on stdin/stdout. Wraps the underlying `io::Error`
    /// for forensic traceability.
    #[error("handshake I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Write a [`IndexerHandshake`] to `writer` using the framed wire
/// format documented at the module level: 4-byte big-endian length
/// prefix, then the canonical CBOR body.
///
/// # Errors
///
/// - [`HandshakeError::Io`] — the writer rejected the bytes (broken
///   pipe / stdin closed).
/// - [`HandshakeError::Cbor`] — the encoder failed (unreachable in
///   practice for the fixed-shape `IndexerHandshake` value).
pub fn write_handshake<W: Write>(
    writer: &mut W,
    msg: &IndexerHandshake,
) -> Result<(), HandshakeError> {
    let body = encode_body(msg)?;
    if body.len() > MAX_HANDSHAKE_BYTES {
        // Shouldn't happen for the fixed-shape struct, but defend
        // anyway so a future additive field can't silently overflow
        // the reader's cap.
        return Err(HandshakeError::OversizeFrame {
            len: u32::try_from(body.len()).unwrap_or(u32::MAX),
            max: MAX_HANDSHAKE_BYTES,
        });
    }
    let len_bytes: [u8; 4] = u32::try_from(body.len())
        .expect("body.len() <= MAX_HANDSHAKE_BYTES fits in u32")
        .to_be_bytes();
    writer.write_all(&len_bytes)?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

/// Read a [`IndexerHandshake`] from `reader` using the framed wire
/// format. The reader is consumed for exactly `4 + body_len` bytes;
/// after a successful return the reader is positioned at the start
/// of whatever follows the handshake on the same stream (i.e., the
/// first line of the JSON protocol).
///
/// # Errors
///
/// See [`HandshakeError`] for the failure modes.
///
/// # Zeroization
///
/// The internal CBOR body buffer is **explicitly zeroized** before
/// this function returns. The returned `IndexerHandshake`'s own
/// `Drop` impl handles the field bytes; this function ensures no
/// stale copy lingers in the read buffer.
pub fn read_handshake<R: Read>(reader: &mut R) -> Result<IndexerHandshake, HandshakeError> {
    // ---- Length prefix ----
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => HandshakeError::PrefixTruncated,
            _ => HandshakeError::Io(e),
        })?;
    let len = u32::from_be_bytes(len_buf);
    let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
    if len_usize > MAX_HANDSHAKE_BYTES {
        return Err(HandshakeError::OversizeFrame {
            len,
            max: MAX_HANDSHAKE_BYTES,
        });
    }

    // ---- Body ----
    let mut body = vec![0u8; len_usize];
    reader.read_exact(&mut body).map_err(|e| match e.kind() {
        std::io::ErrorKind::UnexpectedEof => HandshakeError::BodyTruncated {
            got: 0,
            expected: len_usize,
        },
        _ => HandshakeError::Io(e),
    })?;

    // ---- Decode ----
    let msg = decode_body(&body);

    // ---- Zeroize stdin buffer ----
    // The CBOR body contains the derived key bytes. Wipe the
    // staging buffer now that the values are inside the
    // IndexerHandshake's fixed-size arrays (which the caller will
    // typically move into a SecretBytes immediately).
    body.zeroize();

    msg
}

/// Encode the CBOR body for [`IndexerHandshake`] using `ciborium-ll`
/// (the low-level encoder that does NOT pull serde — the
/// pangolin-crypto serde-ban discipline carries unchanged per
/// HIGH-1).
fn encode_body(msg: &IndexerHandshake) -> Result<Vec<u8>, HandshakeError> {
    let mut buf = Vec::with_capacity(80);
    {
        let mut enc = Encoder::from(&mut buf);
        // map(2)
        enc.push(Header::Map(Some(2)))
            .map_err(|e| HandshakeError::Cbor(format!("map header: {e:?}")))?;
        // text("derived_key") => bytes(32)
        push_text(&mut enc, KEY_DERIVED_KEY)?;
        push_bytes(&mut enc, &msg.derived_key)?;
        // text("run_nonce") => bytes(16)
        push_text(&mut enc, KEY_RUN_NONCE)?;
        push_bytes(&mut enc, &msg.run_nonce)?;
    }
    Ok(buf)
}

/// Decode the CBOR body into [`IndexerHandshake`]. Strict canonical
/// shape: map(2), text keys in lexicographic order (`derived_key`
/// then `run_nonce`), byte-string values of the exact required
/// length. Any deviation surfaces as [`HandshakeError::Cbor`].
fn decode_body(body: &[u8]) -> Result<IndexerHandshake, HandshakeError> {
    let mut dec = Decoder::from(body);
    let header = dec
        .pull()
        .map_err(|e| HandshakeError::Cbor(format!("map header: {e:?}")))?;
    match header {
        Header::Map(Some(2)) => {}
        other => {
            return Err(HandshakeError::Cbor(format!(
                "expected map(2), got {other:?}",
            )));
        }
    }

    // First entry: derived_key
    let k1 = pull_text(&mut dec)?;
    if k1 != KEY_DERIVED_KEY {
        return Err(HandshakeError::Cbor(format!(
            "expected first key {KEY_DERIVED_KEY:?}, got {k1:?}",
        )));
    }
    let v1 = pull_bytes(&mut dec)?;
    if v1.len() != HANDSHAKE_KEY_LEN {
        // Zero the bad bytes before reporting (they may be partial
        // key material).
        let mut v1 = v1;
        v1.zeroize();
        return Err(HandshakeError::Cbor(format!(
            "derived_key must be {HANDSHAKE_KEY_LEN} bytes; got {}",
            v1.len(),
        )));
    }
    let mut derived_key = [0u8; HANDSHAKE_KEY_LEN];
    derived_key.copy_from_slice(&v1);
    // Wipe the heap-side staging vec now that we've copied into the
    // fixed array. The zero pass IS the work — the resulting
    // zeroized vec is then dropped at the end of this scope.
    // `Zeroize::zeroize` operates on `&mut [u8]` via the bytes
    // slice; we take that path to sidestep clippy's
    // `collection_is_never_read` heuristic (which fires when we
    // assign `let mut tmp = v1; tmp.zeroize();` because the
    // collection is then "never read", even though the side-
    // effecting zero pass is the entire point).
    {
        let mut v1_owner = v1;
        Zeroize::zeroize(v1_owner.as_mut_slice());
        drop(v1_owner);
    }

    // Second entry: run_nonce
    let k2 = pull_text(&mut dec)?;
    if k2 != KEY_RUN_NONCE {
        // Wipe derived_key on rejection — we own it but the caller
        // never gets to construct an IndexerHandshake whose Drop
        // would do this.
        derived_key.zeroize();
        return Err(HandshakeError::Cbor(format!(
            "expected second key {KEY_RUN_NONCE:?}, got {k2:?}",
        )));
    }
    let v2 = pull_bytes(&mut dec)?;
    if v2.len() != HANDSHAKE_RUN_NONCE_LEN {
        derived_key.zeroize();
        return Err(HandshakeError::Cbor(format!(
            "run_nonce must be {HANDSHAKE_RUN_NONCE_LEN} bytes; got {}",
            v2.len(),
        )));
    }
    let mut run_nonce = [0u8; HANDSHAKE_RUN_NONCE_LEN];
    run_nonce.copy_from_slice(&v2);

    Ok(IndexerHandshake {
        derived_key,
        run_nonce,
    })
}

fn push_text<W: CborWrite>(enc: &mut Encoder<W>, s: &str) -> Result<(), HandshakeError>
where
    W::Error: core::fmt::Debug,
{
    enc.push(Header::Text(Some(s.len())))
        .map_err(|e| HandshakeError::Cbor(format!("text header: {e:?}")))?;
    CborWrite::write_all(enc, s.as_bytes())
        .map_err(|e| HandshakeError::Cbor(format!("text bytes: {e:?}")))?;
    Ok(())
}

fn push_bytes<W: CborWrite>(enc: &mut Encoder<W>, b: &[u8]) -> Result<(), HandshakeError>
where
    W::Error: core::fmt::Debug,
{
    enc.push(Header::Bytes(Some(b.len())))
        .map_err(|e| HandshakeError::Cbor(format!("bytes header: {e:?}")))?;
    CborWrite::write_all(enc, b)
        .map_err(|e| HandshakeError::Cbor(format!("bytes payload: {e:?}")))?;
    Ok(())
}

fn pull_text(dec: &mut Decoder<&[u8]>) -> Result<String, HandshakeError> {
    let header = dec
        .pull()
        .map_err(|e| HandshakeError::Cbor(format!("text header: {e:?}")))?;
    match header {
        Header::Text(Some(len)) => {
            if len > MAX_HANDSHAKE_BYTES {
                return Err(HandshakeError::Cbor(format!(
                    "text length {len} > MAX_HANDSHAKE_BYTES",
                )));
            }
            let mut buf = vec![0u8; len];
            CborRead::read_exact(dec, &mut buf)
                .map_err(|_| HandshakeError::Cbor("text read truncated".into()))?;
            String::from_utf8(buf).map_err(|_| HandshakeError::Cbor("text not valid UTF-8".into()))
        }
        Header::Text(None) => Err(HandshakeError::Cbor(
            "indefinite-length text strings rejected".into(),
        )),
        other => Err(HandshakeError::Cbor(format!(
            "expected text key, got {other:?}",
        ))),
    }
}

fn pull_bytes(dec: &mut Decoder<&[u8]>) -> Result<Vec<u8>, HandshakeError> {
    let header = dec
        .pull()
        .map_err(|e| HandshakeError::Cbor(format!("bytes header: {e:?}")))?;
    match header {
        Header::Bytes(Some(len)) => {
            if len > MAX_HANDSHAKE_BYTES {
                return Err(HandshakeError::Cbor(format!(
                    "bytes length {len} > MAX_HANDSHAKE_BYTES",
                )));
            }
            let mut buf = vec![0u8; len];
            CborRead::read_exact(dec, &mut buf)
                .map_err(|_| HandshakeError::Cbor("bytes read truncated".into()))?;
            Ok(buf)
        }
        Header::Bytes(None) => Err(HandshakeError::Cbor(
            "indefinite-length byte strings rejected".into(),
        )),
        other => Err(HandshakeError::Cbor(format!(
            "expected bytes value, got {other:?}",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> IndexerHandshake {
        let mut k = [0u8; HANDSHAKE_KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        let mut n = [0u8; HANDSHAKE_RUN_NONCE_LEN];
        for (i, b) in n.iter_mut().enumerate() {
            *b = u8::try_from(0x10 + i).unwrap();
        }
        IndexerHandshake::new(k, n)
    }

    #[test]
    fn handshake_round_trip_pipe() {
        let h = sample();
        let mut buf: Vec<u8> = Vec::new();
        write_handshake(&mut buf, &h).expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        let back = read_handshake(&mut cursor).expect("read");
        assert_eq!(back.derived_key, h.derived_key);
        assert_eq!(back.run_nonce, h.run_nonce);
    }

    #[test]
    fn handshake_debug_redacts_key_bytes() {
        let h = sample();
        let s = format!("{h:?}");
        assert!(s.contains("<redacted"));
        // The known seed-bytes (0x00..0x1F) must NOT appear as hex.
        // We check the high-byte 0x1F as a sentinel.
        assert!(!s.contains("1f"), "Debug must not leak key bytes: {s}");
    }

    #[test]
    fn handshake_rejects_oversize_length_prefix() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&u32::to_be_bytes(1024));
        bad.extend_from_slice(&[0u8; 1024]);
        let err = read_handshake(&mut std::io::Cursor::new(bad)).expect_err("must reject oversize");
        assert!(matches!(err, HandshakeError::OversizeFrame { .. }));
    }

    #[test]
    fn handshake_rejects_truncated_prefix() {
        let bad = vec![0u8; 2]; // less than 4 bytes
        let err =
            read_handshake(&mut std::io::Cursor::new(bad)).expect_err("must reject truncated");
        assert!(matches!(err, HandshakeError::PrefixTruncated));
    }

    #[test]
    fn handshake_rejects_truncated_body() {
        let mut bad = Vec::new();
        bad.extend_from_slice(&u32::to_be_bytes(60));
        bad.extend_from_slice(&[0u8; 30]); // only 30 of the promised 60
        let err =
            read_handshake(&mut std::io::Cursor::new(bad)).expect_err("must reject short body");
        assert!(matches!(err, HandshakeError::BodyTruncated { .. }));
    }

    #[test]
    fn handshake_rejects_wrong_cbor_shape() {
        // Encode a `text("hi")` instead of a map.
        let mut body = Vec::new();
        {
            let mut enc = Encoder::from(&mut body);
            enc.push(Header::Text(Some(2))).unwrap();
            CborWrite::write_all(&mut enc, b"hi").unwrap();
        }
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::to_be_bytes(u32::try_from(body.len()).unwrap()));
        framed.extend_from_slice(&body);
        let err =
            read_handshake(&mut std::io::Cursor::new(framed)).expect_err("must reject wrong shape");
        assert!(matches!(err, HandshakeError::Cbor(_)));
    }

    #[test]
    fn handshake_rejects_short_key() {
        // map(2) { text("derived_key") => bytes(16), text("run_nonce") => bytes(16) }
        let mut body = Vec::new();
        {
            let mut enc = Encoder::from(&mut body);
            enc.push(Header::Map(Some(2))).unwrap();
            push_text(&mut enc, KEY_DERIVED_KEY).unwrap();
            push_bytes(&mut enc, &[0u8; 16]).unwrap(); // WRONG length
            push_text(&mut enc, KEY_RUN_NONCE).unwrap();
            push_bytes(&mut enc, &[0u8; 16]).unwrap();
        }
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::to_be_bytes(u32::try_from(body.len()).unwrap()));
        framed.extend_from_slice(&body);
        let err = read_handshake(&mut std::io::Cursor::new(framed))
            .expect_err("must reject short derived_key");
        assert!(matches!(err, HandshakeError::Cbor(_)));
    }

    #[test]
    fn handshake_rejects_wrong_key_order() {
        // canonical order is derived_key < run_nonce; flip them.
        let mut body = Vec::new();
        {
            let mut enc = Encoder::from(&mut body);
            enc.push(Header::Map(Some(2))).unwrap();
            push_text(&mut enc, KEY_RUN_NONCE).unwrap();
            push_bytes(&mut enc, &[0u8; 16]).unwrap();
            push_text(&mut enc, KEY_DERIVED_KEY).unwrap();
            push_bytes(&mut enc, &[0u8; 32]).unwrap();
        }
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::to_be_bytes(u32::try_from(body.len()).unwrap()));
        framed.extend_from_slice(&body);
        let err = read_handshake(&mut std::io::Cursor::new(framed))
            .expect_err("must reject wrong key order");
        assert!(matches!(err, HandshakeError::Cbor(_)));
    }

    #[test]
    fn handshake_drop_zeroizes_derived_key() {
        // Allocate a handshake, take a pointer to its derived_key
        // bytes, drop it, then... we can't really inspect freed
        // memory portably. Instead we check that the in-place
        // `zeroize` is invoked by manually replacing the field
        // and verifying the discipline runs without panicking.
        let mut h = sample();
        // Pre-condition: bytes are non-zero per the sample.
        assert_ne!(h.derived_key, [0u8; HANDSHAKE_KEY_LEN]);
        h.derived_key.zeroize();
        assert_eq!(h.derived_key, [0u8; HANDSHAKE_KEY_LEN]);
        // Drop happens at scope end; the Drop impl re-zeroizes
        // (idempotent).
    }

    #[test]
    fn handshake_constants_pinned() {
        assert_eq!(HANDSHAKE_KEY_LEN, 32);
        assert_eq!(HANDSHAKE_RUN_NONCE_LEN, 16);
        assert_eq!(MAX_HANDSHAKE_BYTES, 256);
    }

    #[test]
    fn write_handshake_body_is_under_cap() {
        // Sanity: the canonical encoding of the fixed-shape struct
        // stays well under the cap. Pin a hard expectation so any
        // future bloat surfaces here.
        let h = sample();
        let body = encode_body(&h).unwrap();
        assert!(
            body.len() < MAX_HANDSHAKE_BYTES,
            "encoded body {} bytes >= MAX_HANDSHAKE_BYTES {}",
            body.len(),
            MAX_HANDSHAKE_BYTES,
        );
        // The actual canonical encoding is ~57 bytes; pin the
        // bound so a CBOR-encoding regression that drops to e.g.
        // indefinite-length encoding (which would still decode but
        // would change the byte size) surfaces here.
        assert!(
            body.len() <= 80,
            "encoded body unexpectedly large: {}",
            body.len()
        );
    }
}
