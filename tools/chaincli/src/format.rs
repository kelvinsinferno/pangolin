//! Output formatters — text + JSON-Lines.
//!
//! Pipe-friendly defaults. Per `docs/issue-plans/P6.md` Output safety
//! note: never decode `encPayload` structurally; always print as raw
//! hex / base64.

use alloy::primitives::B256;

/// Output format selector. Maps 1:1 to a flag the user picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// JSON-Lines (one record per line). Default.
    #[default]
    Jsonl,
    /// Human-readable tabular form.
    Text,
}

/// One row of `RevisionPublished` event data, ready for printing in
/// either format. We keep the raw bytes (`payload`) and never let
/// anything else in chaincli interpret them — they go into the output
/// formatter directly as hex / base64.
#[derive(Debug, Clone)]
pub struct ListedRevision {
    pub sequence: u64,
    pub block: u64,
    pub log_index: u64,
    pub tx: B256,
    pub vault_id: B256,
    pub account_id: B256,
    pub parent_revision: B256,
    pub device_id: B256,
    pub schema_version: u8,
    pub payload: Vec<u8>,
    pub payload_keccak: B256,
}

impl ListedRevision {
    /// Render this revision as a single JSON object (no surrounding
    /// array / newline). Caller wraps with newlines for JSON-Lines.
    pub fn to_jsonl(&self) -> String {
        let value = serde_json::json!({
            "sequence": self.sequence,
            "block": self.block,
            "log_index": self.log_index,
            "tx": format!("{:?}", self.tx),
            "vault_id": format!("{:?}", self.vault_id),
            "account_id": format!("{:?}", self.account_id),
            "parent_revision": format!("{:?}", self.parent_revision),
            "device_id": format!("{:?}", self.device_id),
            "schema_version": self.schema_version,
            "payload_len": self.payload.len(),
            "payload_hex": format!("0x{}", hex::encode(&self.payload)),
            "payload_keccak": format!("{:?}", self.payload_keccak),
        });
        // `serde_json::Value::to_string` is single-line.
        value.to_string()
    }

    /// Render as a tab-aligned text record. Multi-line by design — the
    /// `--text` flag is for humans, not pipes.
    pub fn to_text(&self) -> String {
        format!(
            "sequence       : {}\n\
             block          : {}\n\
             log_index      : {}\n\
             tx             : {:?}\n\
             vault_id       : {:?}\n\
             account_id     : {:?}\n\
             parent_revision: {:?}\n\
             device_id      : {:?}\n\
             schema_version : {}\n\
             payload_len    : {}\n\
             payload (hex)  : 0x{}\n\
             payload_keccak : {:?}\n",
            self.sequence,
            self.block,
            self.log_index,
            self.tx,
            self.vault_id,
            self.account_id,
            self.parent_revision,
            self.device_id,
            self.schema_version,
            self.payload.len(),
            hex::encode(&self.payload),
            self.payload_keccak,
        )
    }
}

/// Naive base64 encoder (RFC 4648 standard alphabet, no padding
/// stripping). Pulling a `base64` crate just for the `dump` command
/// would expand the dep set; the chaincli `format` module needs only
/// to print bytes for human eyes, never to decode them. Tested below.
#[allow(clippy::cast_possible_truncation)]
pub fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        let b2 = bytes[i + 2];
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    match rem {
        0 => {}
        1 => {
            let b0 = bytes[i];
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[((b0 & 0x03) << 4) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let b0 = bytes[i];
            let b1 = bytes[i + 1];
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(ALPHABET[((b1 & 0x0F) << 2) as usize] as char);
            out.push('=');
        }
        _ => unreachable!(),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{b64_encode, Format, ListedRevision};
    use alloy::primitives::B256;

    fn sample() -> ListedRevision {
        ListedRevision {
            sequence: 42,
            block: 41_133_109,
            log_index: 1,
            tx: B256::repeat_byte(0x5C),
            vault_id: B256::repeat_byte(0xAA),
            account_id: B256::repeat_byte(0xBB),
            parent_revision: B256::ZERO,
            device_id: B256::repeat_byte(0xCC),
            schema_version: 0,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            payload_keccak: B256::repeat_byte(0x77),
        }
    }

    #[test]
    fn jsonlines_round_trip() {
        let r = sample();
        let line = r.to_jsonl();
        // Each line must parse back as a JSON object — that's the
        // entire promise of JSON-Lines.
        let v: serde_json::Value =
            serde_json::from_str(&line).expect("formatter line is valid JSON");
        assert!(v.is_object());
        assert_eq!(v["sequence"], 42);
        assert_eq!(v["block"], 41_133_109);
        assert_eq!(v["payload_hex"].as_str().unwrap(), "0xdeadbeef");
        assert_eq!(v["payload_len"], 4);
        // No newlines inside the formatted record (JSON-Lines invariant).
        assert!(!line.contains('\n'));
    }

    #[test]
    fn text_format_aligned() {
        let r = sample();
        let s = r.to_text();
        // Documented columns must each appear, in order. We don't pin
        // exact byte-positions because that would be brittle, but every
        // row has its label.
        for label in &[
            "sequence       :",
            "block          :",
            "log_index      :",
            "tx             :",
            "vault_id       :",
            "account_id     :",
            "parent_revision:",
            "device_id      :",
            "schema_version :",
            "payload_len    :",
            "payload (hex)  :",
            "payload_keccak :",
        ] {
            assert!(s.contains(label), "text format missing {label}\nfull:\n{s}");
        }
    }

    #[test]
    fn format_default_is_jsonl() {
        assert_eq!(Format::default(), Format::Jsonl);
    }

    #[test]
    fn b64_encode_matches_canonical() {
        // RFC 4648 test vectors.
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        // Smoke-test deployment payload.
        assert_eq!(
            b64_encode(&[
                0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
                0xBE, 0xEF
            ]),
            "3q2+796tvu/erb7v3q2+7w=="
        );
    }
}
