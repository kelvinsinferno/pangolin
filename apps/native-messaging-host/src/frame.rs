// SPDX-License-Identifier: AGPL-3.0-or-later
//! Chrome native-messaging frame codec.
//!
//! Chrome's native-messaging protocol wraps each JSON body in a 4-byte
//! little-endian length prefix. The body is UTF-8 JSON. Chrome limits
//! a single frame to 1 MB; oversize frames are a Chrome-side hard fail
//! that closes the channel, so we reject them on read with a
//! deterministic typed error before any parsing happens.
//!
//! Reference: <https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-protocol>
//!
//! Wire format:
//!
//! ```text
//! [u32 little-endian length] [UTF-8 JSON body of `length` bytes]
//! ```
//!
//! The codec is intentionally `tokio::io::AsyncRead{,Write}`-shaped so
//! the same primitives work for stdin/stdout (the extension side) AND
//! the IPC channel (the desktop side). Round-trip tests pin the byte
//! form per L8.

#![forbid(unsafe_code)]

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::HostError;

/// Chrome's per-frame size cap (1 MB; the documented limit).
pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Read one Chrome native-messaging frame.
///
/// Reads the 4-byte LE length prefix, then exactly `length` bytes of
/// body. Returns the raw body bytes (caller is responsible for UTF-8
/// + JSON validation).
///
/// # Errors
///
/// - [`HostError::FrameLengthRead`] if the 4-byte prefix can't be read
///   (typically EOF when Chrome closes stdin).
/// - [`HostError::FrameOversize`] if the prefix declares > 1 MB.
/// - [`HostError::FrameBodyRead`] if the body short-reads.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, HostError> {
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .await
        .map_err(|_| HostError::FrameLengthRead)?;
    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_FRAME_BYTES {
        return Err(HostError::FrameOversize(len));
    }
    let mut body = vec![0u8; len as usize];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| HostError::FrameBodyRead)?;
    Ok(body)
}

/// Write one Chrome native-messaging frame.
///
/// Writes the 4-byte LE length prefix followed by `body`.
///
/// # Errors
///
/// - [`HostError::FrameOversize`] if `body.len() > 1 MB`.
/// - [`HostError::Io`] for any underlying write failure.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> Result<(), HostError> {
    let len = u32::try_from(body.len()).map_err(|_| HostError::FrameOversize(u32::MAX))?;
    if len > MAX_FRAME_BYTES {
        return Err(HostError::FrameOversize(len));
    }
    let prefix = len.to_le_bytes();
    writer
        .write_all(&prefix)
        .await
        .map_err(|_| HostError::Io("write prefix"))?;
    writer
        .write_all(body)
        .await
        .map_err(|_| HostError::Io("write body"))?;
    writer.flush().await.map_err(|_| HostError::Io("flush"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    /// Round-trip: write then read recovers the same bytes.
    #[tokio::test]
    async fn write_then_read_round_trip() {
        let mut buf: Vec<u8> = Vec::new();
        let body = b"{\"jsonrpc\":\"2.0\",\"id\":1}".to_vec();
        write_frame(&mut buf, &body).await.expect("write");

        // The wire-shape pin: first 4 bytes are the LE length.
        let expected_len = u32::try_from(body.len()).unwrap().to_le_bytes();
        assert_eq!(&buf[..4], &expected_len);
        assert_eq!(&buf[4..], &body[..]);

        // Now read it back.
        let mut reader = BufReader::new(Cursor::new(buf));
        let got = read_frame(&mut reader).await.expect("read");
        assert_eq!(got, body);
    }

    /// Empty body is a valid frame (length = 0).
    #[tokio::test]
    async fn empty_body_is_ok() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, b"").await.expect("write empty");
        assert_eq!(buf, vec![0, 0, 0, 0]);

        let mut reader = BufReader::new(Cursor::new(buf));
        let got = read_frame(&mut reader).await.expect("read empty");
        assert!(got.is_empty());
    }

    /// Wire-shape pin: a known-good frame produces a byte-identical
    /// stream regardless of host endianness (`u32::to_le_bytes`
    /// guarantees little-endian).
    #[tokio::test]
    async fn wire_form_is_little_endian_pinned() {
        let mut buf: Vec<u8> = Vec::new();
        // A 5-byte body — `0x05 0x00 0x00 0x00` is the LE prefix.
        write_frame(&mut buf, b"hello").await.expect("write");
        assert_eq!(
            buf,
            vec![0x05, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o']
        );
    }

    /// A length-prefix declaring > 1 MB is rejected without reading
    /// any of the body. The reader's position after the call is
    /// (just past the prefix) — the body bytes are NOT consumed.
    #[tokio::test]
    async fn oversize_prefix_is_rejected_fail_closed() {
        let mut buf: Vec<u8> = Vec::new();
        let too_big: u32 = MAX_FRAME_BYTES + 1;
        buf.extend_from_slice(&too_big.to_le_bytes());
        // Don't bother with a body — the reader should error before
        // trying to read more.
        let mut reader = BufReader::new(Cursor::new(buf));
        let err = read_frame(&mut reader)
            .await
            .expect_err("oversize rejected");
        assert!(matches!(err, HostError::FrameOversize(n) if n == too_big));
    }

    /// EOF on the prefix (Chrome closed stdin) surfaces a clean
    /// `FrameLengthRead` error.
    #[tokio::test]
    async fn eof_on_prefix_is_frame_length_read() {
        let mut reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let err = read_frame(&mut reader).await.expect_err("eof");
        assert!(matches!(err, HostError::FrameLengthRead));
    }

    /// Short body (length prefix promises 10 bytes, only 3 follow) is
    /// a `FrameBodyRead` error — the reader sees the size mismatch.
    #[tokio::test]
    async fn short_body_is_frame_body_read() {
        let mut buf: Vec<u8> = Vec::new();
        let claimed: u32 = 10;
        buf.extend_from_slice(&claimed.to_le_bytes());
        buf.extend_from_slice(b"abc"); // only 3 bytes, not 10
        let mut reader = BufReader::new(Cursor::new(buf));
        let err = read_frame(&mut reader).await.expect_err("short body");
        assert!(matches!(err, HostError::FrameBodyRead));
    }

    /// `write_frame` rejects an oversized body without writing anything
    /// beyond the prefix. (We do not partially-write — the
    /// oversize guard is up-front.)
    #[tokio::test]
    async fn write_rejects_oversize_body() {
        let mut buf: Vec<u8> = Vec::new();
        let too_big = vec![0u8; (MAX_FRAME_BYTES + 1) as usize];
        let err = write_frame(&mut buf, &too_big).await.expect_err("oversize");
        assert!(matches!(err, HostError::FrameOversize(_)));
        // No bytes should have been written (the guard fires before
        // any I/O).
        assert!(buf.is_empty());
    }

    /// Exactly-1MB body is accepted (the limit is inclusive — Chrome's
    /// docs say "up to 1 MB").
    #[tokio::test]
    async fn write_accepts_exactly_max_size() {
        let mut buf: Vec<u8> = Vec::new();
        let body = vec![0u8; MAX_FRAME_BYTES as usize];
        write_frame(&mut buf, &body).await.expect("at-limit ok");
        let mut reader = BufReader::new(Cursor::new(buf));
        let got = read_frame(&mut reader).await.expect("at-limit ok read");
        assert_eq!(got.len(), MAX_FRAME_BYTES as usize);
    }
}
