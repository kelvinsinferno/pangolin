// SPDX-License-Identifier: AGPL-3.0-or-later
//! Test-only KDBX **writer** — builds tiny, valid KDBX 3.1 and 4.x byte
//! streams in memory so the parser can round-trip against known
//! content. Self-contained (no `pangolin-kdbx`-internal deps); the
//! cipher/KDF UUIDs are the public KeePass spec constants.

#![allow(
    dead_code,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::format_push_string,
    clippy::too_many_lines,
    clippy::redundant_clone,
    clippy::type_complexity,
    clippy::option_if_let_else,
    clippy::cast_possible_truncation,
    clippy::manual_let_else,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::semicolon_if_nothing_returned,
    clippy::too_long_first_doc_paragraph,
    clippy::missing_const_for_fn,
    missing_debug_implementations
)]

use aes::cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use base64::Engine as _;
use hmac::Mac as _;
use sha2::{Digest, Sha256, Sha512};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

const SALSA20_IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
const SIG1: u32 = 0x9AA2_D903;
const SIG2: u32 = 0xB54B_FB67;
const CIPHER_AES256: [u8; 16] = [
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
];
const CIPHER_CHACHA20: [u8; 16] = [
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
];
const KDF_ARGON2ID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

#[derive(Clone, Default)]
pub struct TestEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub extra: Vec<(String, String, bool)>,
    pub tags: Vec<String>,
    pub group_path: Vec<String>,
    pub history: Vec<(String, Option<String>)>,
    pub expires: bool,
    pub expiry_time: Option<String>,
    pub recycled: bool,
}

impl TestEntry {
    pub fn simple(title: &str, user: &str, pw: &str) -> Self {
        Self {
            title: title.into(),
            username: user.into(),
            password: pw.into(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Copy)]
pub enum WriteCipher {
    Aes256Cbc,
    ChaCha20,
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

struct XmlBuilder<'a> {
    out: String,
    apply: Box<dyn FnMut(&mut [u8]) + 'a>,
}
impl XmlBuilder<'_> {
    fn protected_value(&mut self, plain: &str) -> String {
        let mut bytes = plain.as_bytes().to_vec();
        (self.apply)(&mut bytes);
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    }
}

fn emit_str(b: &mut XmlBuilder, key: &str, val: &str, protected: bool) {
    b.out.push_str("<String><Key>");
    b.out.push_str(&xml_escape(key));
    b.out.push_str("</Key>");
    if protected {
        let v = b.protected_value(val);
        b.out
            .push_str(&format!(r#"<Value Protected="True">{v}</Value>"#));
    } else {
        b.out.push_str("<Value>");
        b.out.push_str(&xml_escape(val));
        b.out.push_str("</Value>");
    }
    b.out.push_str("</String>");
}

fn emit_entry_inner(b: &mut XmlBuilder, e: &TestEntry, password: &str, last_mod: Option<&str>) {
    b.out.push_str("<Entry>");
    b.out.push_str("<UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>");
    emit_str(b, "Title", &e.title, false);
    emit_str(b, "UserName", &e.username, false);
    emit_str(b, "Password", password, true);
    if !e.url.is_empty() {
        emit_str(b, "URL", &e.url, false);
    }
    if !e.notes.is_empty() {
        emit_str(b, "Notes", &e.notes, false);
    }
    for (k, v, p) in &e.extra {
        emit_str(b, k, v, *p);
    }
    if !e.tags.is_empty() {
        b.out.push_str("<Tags>");
        b.out.push_str(&xml_escape(&e.tags.join(";")));
        b.out.push_str("</Tags>");
    }
    b.out.push_str("<Times>");
    b.out.push_str(&format!(
        "<Expires>{}</Expires>",
        if e.expires { "True" } else { "False" }
    ));
    if let Some(t) = &e.expiry_time {
        b.out.push_str(&format!("<ExpiryTime>{t}</ExpiryTime>"));
    }
    if let Some(lm) = last_mod {
        b.out.push_str(&format!(
            "<LastModificationTime>{lm}</LastModificationTime>"
        ));
    }
    b.out.push_str("</Times>");
}

fn emit_entry(b: &mut XmlBuilder, e: &TestEntry) {
    emit_entry_inner(b, e, &e.password, None);
    if !e.history.is_empty() {
        b.out.push_str("<History>");
        for (pw, lm) in &e.history {
            let mut he = e.clone();
            he.history.clear();
            emit_entry_inner(b, &he, pw, lm.as_deref());
            b.out.push_str("</Entry>");
        }
        b.out.push_str("</History>");
    }
    b.out.push_str("</Entry>");
}

fn build_xml(
    entries: &[TestEntry],
    recycle_bin_uuid: &[u8; 16],
    apply: impl FnMut(&mut [u8]) + 'static,
) -> Vec<u8> {
    let mut b = XmlBuilder {
        out: String::new(),
        apply: Box::new(apply),
    };
    let rb_b64 = base64::engine::general_purpose::STANDARD.encode(recycle_bin_uuid);
    b.out
        .push_str(r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>"#);
    b.out
        .push_str("<KeePassFile><Meta><Generator>pangolin-test</Generator>");
    b.out
        .push_str(&format!("<RecycleBinUUID>{rb_b64}</RecycleBinUUID>"));
    b.out
        .push_str("<RecycleBinEnabled>True</RecycleBinEnabled></Meta><Root>");
    b.out
        .push_str("<Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name>");
    let mut ctr: u64 = 1;
    for e in entries.iter().filter(|e| !e.recycled) {
        for g in &e.group_path {
            ctr += 1;
            let mut uuid = [0u8; 16];
            uuid[..8].copy_from_slice(&ctr.to_le_bytes());
            let u = base64::engine::general_purpose::STANDARD.encode(uuid);
            b.out.push_str(&format!(
                "<Group><UUID>{u}</UUID><Name>{}</Name>",
                xml_escape(g)
            ));
        }
        emit_entry(&mut b, e);
        for _ in &e.group_path {
            b.out.push_str("</Group>");
        }
    }
    b.out.push_str(&format!(
        "<Group><UUID>{rb_b64}</UUID><Name>Recycle Bin</Name>"
    ));
    for e in entries.iter().filter(|e| e.recycled) {
        emit_entry(&mut b, e);
    }
    b.out.push_str("</Group></Group></Root></KeePassFile>");
    b.out.into_bytes()
}

fn composite_key_pw(password: &str) -> [u8; 32] {
    let h = Sha256::digest(Sha256::digest(password.as_bytes()));
    let mut a = [0u8; 32];
    a.copy_from_slice(&h);
    a
}

fn composite_key_pw_keyfile(password: Option<&str>, keyfile32: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    if let Some(p) = password {
        h.update(Sha256::digest(p.as_bytes()));
    }
    h.update(keyfile32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h.finalize());
    a
}

fn aes_kdf(composite: &[u8; 32], seed: &[u8; 32], rounds: u64) -> [u8; 32] {
    let cipher = aes::Aes256::new_from_slice(seed).unwrap();
    let mut block = *composite;
    for _ in 0..rounds {
        let (lo, hi) = block.split_at_mut(16);
        let mut b0 = aes::cipher::generic_array::GenericArray::clone_from_slice(lo);
        let mut b1 = aes::cipher::generic_array::GenericArray::clone_from_slice(hi);
        cipher.encrypt_block(&mut b0);
        cipher.encrypt_block(&mut b1);
        lo.copy_from_slice(&b0);
        hi.copy_from_slice(&b1);
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&Sha256::digest(block));
    a
}

fn argon2id(composite: &[u8; 32], salt: &[u8], mem_kib: u32, iters: u32, par: u32) -> [u8; 32] {
    let params = argon2::Params::new(mem_kib, iters, par, Some(32)).unwrap();
    let ctx = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    ctx.hash_password_into(composite, salt, &mut out).unwrap();
    out
}

fn master_key(seed: &[u8; 32], transformed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(transformed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h.finalize());
    a
}
fn hmac_base(seed: &[u8; 32], transformed: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(seed);
    h.update(transformed);
    h.update([0x01u8]);
    let mut a = [0u8; 64];
    a.copy_from_slice(&h.finalize());
    a
}
fn block_key(base: &[u8; 64], idx: u64) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(idx.to_le_bytes());
    h.update(base);
    let mut a = [0u8; 64];
    a.copy_from_slice(&h.finalize());
    a
}
fn pkcs7_pad(data: &mut Vec<u8>) {
    let pad = 16 - (data.len() % 16);
    data.extend(std::iter::repeat_n(u8::try_from(pad).unwrap(), pad));
}
fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}
fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], mut data: Vec<u8>) -> Vec<u8> {
    pkcs7_pad(&mut data);
    let mut enc = Aes256CbcEnc::new(key.into(), iv.into());
    for chunk in data.chunks_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        enc.encrypt_block_mut(block);
    }
    data
}

fn push_field32(h: &mut Vec<u8>, id: u8, data: &[u8]) {
    h.push(id);
    h.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    h.extend_from_slice(data);
}
fn push_field16(h: &mut Vec<u8>, id: u8, data: &[u8]) {
    h.push(id);
    h.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
    h.extend_from_slice(data);
}

/// Build a KDBX 4.x file (Argon2id, gzip, given outer cipher, ChaCha20
/// inner stream).
pub fn build_kdbx4(
    entries: &[TestEntry],
    password: Option<&str>,
    keyfile32: Option<&[u8; 32]>,
    cipher: WriteCipher,
) -> Vec<u8> {
    let composite = match keyfile32 {
        Some(kf) => composite_key_pw_keyfile(password, kf),
        None => composite_key_pw(password.expect("password or keyfile")),
    };
    let master_seed = [0x11u8; 32];
    let kdf_salt = [0x22u8; 32];
    let transformed = argon2id(&composite, &kdf_salt, 16, 1, 1);
    let mkey = master_key(&master_seed, &transformed);
    let hbase = hmac_base(&master_seed, &transformed);
    let recycle_bin_uuid = [0x55u8; 16];

    let inner_key = [0x33u8; 64];
    let ih = Sha512::digest(inner_key);
    let mut ck = [0u8; 32];
    ck.copy_from_slice(&ih[..32]);
    let mut cn = [0u8; 12];
    cn.copy_from_slice(&ih[32..44]);
    let xml = {
        let mut s = chacha20::ChaCha20::new(&ck.into(), &cn.into());
        build_xml(entries, &recycle_bin_uuid, move |buf| {
            s.apply_keystream(buf)
        })
    };

    let mut inner = Vec::new();
    inner.push(1u8); // INNER_RANDOM_STREAM_ID
    inner.extend_from_slice(&4u32.to_le_bytes()); // length of the u32 value
    inner.extend_from_slice(&3u32.to_le_bytes()); // value: 3 = ChaCha20
    inner.push(2u8); // INNER_RANDOM_STREAM_KEY
    inner.extend_from_slice(&u32::try_from(inner_key.len()).unwrap().to_le_bytes());
    inner.extend_from_slice(&inner_key);
    inner.push(0u8); // END
    inner.extend_from_slice(&0u32.to_le_bytes());
    let mut payload = inner;
    payload.extend_from_slice(&xml);
    let compressed = gzip(&payload);

    let (cipher_uuid, iv): ([u8; 16], Vec<u8>) = match cipher {
        WriteCipher::Aes256Cbc => (CIPHER_AES256, vec![0x44u8; 16]),
        WriteCipher::ChaCha20 => (CIPHER_CHACHA20, vec![0x44u8; 12]),
    };
    let ct = match cipher {
        WriteCipher::Aes256Cbc => {
            let iv16: [u8; 16] = iv.as_slice().try_into().unwrap();
            aes_cbc_encrypt(&mkey, &iv16, compressed.clone())
        }
        WriteCipher::ChaCha20 => {
            let nonce: [u8; 12] = iv.as_slice().try_into().unwrap();
            let mut d = compressed.clone();
            let mut c = chacha20::ChaCha20::new(&mkey.into(), &nonce.into());
            c.apply_keystream(&mut d);
            d
        }
    };

    let mut header = Vec::new();
    header.extend_from_slice(&SIG1.to_le_bytes());
    header.extend_from_slice(&SIG2.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&4u16.to_le_bytes());
    push_field32(&mut header, 2, &cipher_uuid);
    push_field32(&mut header, 3, &1u32.to_le_bytes());
    push_field32(&mut header, 4, &master_seed);
    push_field32(&mut header, 7, &iv);
    let mut vd = Vec::new();
    vd.extend_from_slice(&0x0100u16.to_le_bytes());
    let vd_bytes = |vd: &mut Vec<u8>, key: &[u8], val: &[u8]| {
        vd.push(0x42);
        vd.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());
        vd.extend_from_slice(key);
        vd.extend_from_slice(&u32::try_from(val.len()).unwrap().to_le_bytes());
        vd.extend_from_slice(val);
    };
    let vd_u32 = |vd: &mut Vec<u8>, key: &[u8], v: u32| {
        vd.push(0x04);
        vd.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());
        vd.extend_from_slice(key);
        vd.extend_from_slice(&4u32.to_le_bytes());
        vd.extend_from_slice(&v.to_le_bytes());
    };
    let vd_u64 = |vd: &mut Vec<u8>, key: &[u8], v: u64| {
        vd.push(0x05);
        vd.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());
        vd.extend_from_slice(key);
        vd.extend_from_slice(&8u32.to_le_bytes());
        vd.extend_from_slice(&v.to_le_bytes());
    };
    vd_bytes(&mut vd, b"$UUID", &KDF_ARGON2ID);
    vd_bytes(&mut vd, b"S", &kdf_salt);
    vd_u32(&mut vd, b"P", 1);
    vd_u64(&mut vd, b"M", 16 * 1024);
    vd_u64(&mut vd, b"I", 1);
    vd_u32(&mut vd, b"V", 0x13);
    vd.push(0x00);
    push_field32(&mut header, 11, &vd);
    header.push(0u8);
    header.extend_from_slice(&0u32.to_le_bytes());

    let header_sha = Sha256::digest(&header);
    let hk = block_key(&hbase, u64::MAX);
    let mut hm = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&hk).unwrap();
    hm.update(&header);
    let header_hmac = hm.finalize().into_bytes();

    let mut out = header.clone();
    out.extend_from_slice(&header_sha);
    out.extend_from_slice(&header_hmac);
    {
        let bk = block_key(&hbase, 0);
        let mut bm = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&bk).unwrap();
        bm.update(&0u64.to_le_bytes());
        bm.update(&u32::try_from(ct.len()).unwrap().to_le_bytes());
        bm.update(&ct);
        out.extend_from_slice(&bm.finalize().into_bytes());
        out.extend_from_slice(&u32::try_from(ct.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&ct);
    }
    {
        let bk = block_key(&hbase, 1);
        let mut bm = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(&bk).unwrap();
        bm.update(&1u64.to_le_bytes());
        bm.update(&0u32.to_le_bytes());
        out.extend_from_slice(&bm.finalize().into_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }
    out
}

/// Build a KDBX 3.1 file (AES-KDF rounds=2, gzip, AES-256-CBC, Salsa20
/// inner stream). Password-only.
pub fn build_kdbx3(entries: &[TestEntry], password: &str) -> Vec<u8> {
    let composite = composite_key_pw(password);
    let master_seed = [0x11u8; 32];
    let transform_seed = [0x22u8; 32];
    let rounds = 2u64;
    let transformed = aes_kdf(&composite, &transform_seed, rounds);
    let mkey = master_key(&master_seed, &transformed);
    let iv = [0x44u8; 16];
    let stream_start = [0x66u8; 32];
    let inner_key = [0x33u8; 32];
    let recycle_bin_uuid = [0x55u8; 16];
    let salsa_key = Sha256::digest(inner_key);
    let xml = {
        let mut s = salsa20::Salsa20::new(&salsa_key, &SALSA20_IV.into());
        build_xml(entries, &recycle_bin_uuid, move |buf| {
            s.apply_keystream(buf)
        })
    };
    let compressed = gzip(&xml);
    let mut plaintext = stream_start.to_vec();
    plaintext.extend_from_slice(&compressed);
    let ct = aes_cbc_encrypt(&mkey, &iv, plaintext);

    let mut header = Vec::new();
    header.extend_from_slice(&SIG1.to_le_bytes());
    header.extend_from_slice(&SIG2.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&3u16.to_le_bytes());
    push_field16(&mut header, 2, &CIPHER_AES256);
    push_field16(&mut header, 3, &1u32.to_le_bytes());
    push_field16(&mut header, 4, &master_seed);
    push_field16(&mut header, 5, &transform_seed);
    push_field16(&mut header, 6, &rounds.to_le_bytes());
    push_field16(&mut header, 7, &iv);
    push_field16(&mut header, 8, &inner_key);
    push_field16(&mut header, 9, &stream_start);
    push_field16(&mut header, 10, &2u32.to_le_bytes());
    header.push(0u8);
    header.extend_from_slice(&0u16.to_le_bytes());

    let mut out = header;
    out.extend_from_slice(&ct);
    out
}
