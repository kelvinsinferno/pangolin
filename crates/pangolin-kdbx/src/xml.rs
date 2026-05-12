// SPDX-License-Identifier: AGPL-3.0-or-later
//! KDBX inner-XML walk: `<KeePassFile><Meta>...<Root><Group>...<Entry>`.
//!
//! Streaming (`quick-xml`), no DOM. Custom-entity expansion is *not*
//! performed (`quick-xml` only resolves the five predefined XML
//! entities, which cannot expand a billion-laughs payload); we
//! additionally cap event count and nesting depth to bound a hostile
//! file.

use base64::Engine as _;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::KdbxError;
use crate::payload::InnerStream;
use crate::read::{KdbxEntry, KdbxStringValue, KdbxTimes};
use crate::Secret;

/// Hard cap on XML events processed — bounds CPU/memory on a hostile
/// file with millions of tiny elements.
const MAX_EVENTS: usize = 8_000_000;
/// Hard cap on element nesting depth.
const MAX_DEPTH: usize = 256;
/// Hard cap on the cumulative text length of a single element's body.
const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;

/// The parsed XML tree (only the bits we need).
pub struct ParsedXml {
    /// All live entries, in document order, with their group-path
    /// components attached. Entries inside the recycle-bin group are
    /// *excluded*.
    pub entries: Vec<KdbxEntry>,
    /// Number of entries skipped because they were in the recycle bin.
    pub recycle_bin_entries: usize,
}

#[derive(Default)]
struct EntryBuild {
    strings: Vec<KdbxStringValue>,
    tags: Vec<String>,
    times: KdbxTimes,
    history: Vec<HistEntry>,
    cur_key: Option<String>,
    cur_val: Option<Secret>,
    cur_protected: bool,
}

struct HistEntry {
    password: Option<Secret>,
    last_mod_unix: Option<i64>,
}

/// Per-`<Group>` frame.
struct GroupFrame {
    name: String,
    uuid: Option<String>,
    /// `true` once we know this group (or an ancestor) is the recycle bin.
    in_recycle: bool,
}

/// Parse the `<KeePassFile>` XML, running the inner random stream over
/// each `Protected="True"` value in document order.
///
/// # Errors
/// [`KdbxError::XmlMalformed`] / [`KdbxError::TooManyEntries`].
#[allow(clippy::too_many_lines)]
pub fn parse_kdbx_xml(xml: &[u8], stream: &mut InnerStream) -> Result<ParsedXml, KdbxError> {
    let text = core::str::from_utf8(xml)
        .map_err(|_| KdbxError::XmlMalformed("inner XML is not valid UTF-8".into()))?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);

    let mut path: Vec<String> = Vec::new();
    let mut groups: Vec<GroupFrame> = Vec::new();
    let mut recycle_bin_uuid: Option<String> = None;
    let mut entry_stack: Vec<EntryBuild> = Vec::new();
    let mut entries: Vec<KdbxEntry> = Vec::new();
    let mut recycle_skipped = 0usize;
    let mut text_buf = String::new();
    let mut events = 0usize;

    let mut decode_protected = |b64: &str| -> Result<Secret, KdbxError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim().as_bytes())
            .map_err(|_| KdbxError::XmlMalformed("bad base64 in Protected value".into()))?;
        let mut v = raw;
        stream.apply(&mut v);
        Ok(zeroize::Zeroizing::new(v))
    };

    // `Empty(e)` (self-closing) is handled by synthesising a Start then
    // an End; quick-xml gives us a separate event so we treat it inline.
    loop {
        let ev = reader
            .read_event()
            .map_err(|e| KdbxError::XmlMalformed(format!("xml: {e}")))?;
        events += 1;
        if events > MAX_EVENTS {
            return Err(KdbxError::XmlMalformed("too many XML events".into()));
        }
        match ev {
            Event::Eof => break,
            Event::Start(e) => {
                if path.len() >= MAX_DEPTH {
                    return Err(KdbxError::XmlMalformed("XML nesting too deep".into()));
                }
                let name = local_name(e.name().local_name().as_ref())?;
                let protected = read_protected_attr(&e)?;
                on_start(
                    &name,
                    protected,
                    &mut groups,
                    &mut entry_stack,
                    path.last().map(String::as_str),
                    &recycle_bin_uuid,
                );
                path.push(name);
                text_buf.clear();
            }
            Event::Empty(e) => {
                // Self-closing: a Start immediately followed by an End,
                // with empty text. We push then pop the element.
                let name = local_name(e.name().local_name().as_ref())?;
                let protected = read_protected_attr(&e)?;
                let parent = path.last().map(String::as_str);
                on_start(
                    &name,
                    protected,
                    &mut groups,
                    &mut entry_stack,
                    parent,
                    &recycle_bin_uuid,
                );
                // Immediately close with empty text.
                let parent_after_self = parent;
                on_end(
                    &name,
                    "",
                    parent_after_self,
                    &mut groups,
                    &mut recycle_bin_uuid,
                    &mut entry_stack,
                    &mut entries,
                    &mut recycle_skipped,
                    &mut decode_protected,
                )?;
            }
            Event::Text(t) => {
                let s = t
                    .unescape()
                    .map_err(|e| KdbxError::XmlMalformed(format!("text: {e}")))?;
                if text_buf.len() + s.len() > MAX_TEXT_BYTES {
                    return Err(KdbxError::XmlMalformed("element text too large".into()));
                }
                text_buf.push_str(&s);
            }
            Event::CData(t) => {
                let s = core::str::from_utf8(t.as_ref())
                    .map_err(|_| KdbxError::XmlMalformed("CDATA not UTF-8".into()))?;
                if text_buf.len() + s.len() > MAX_TEXT_BYTES {
                    return Err(KdbxError::XmlMalformed("element CDATA too large".into()));
                }
                text_buf.push_str(s);
            }
            Event::End(_e) => {
                let name = path
                    .pop()
                    .ok_or_else(|| KdbxError::XmlMalformed("unbalanced XML".into()))?;
                let parent = path.last().map(String::as_str);
                let text = std::mem::take(&mut text_buf);
                on_end(
                    &name,
                    &text,
                    parent,
                    &mut groups,
                    &mut recycle_bin_uuid,
                    &mut entry_stack,
                    &mut entries,
                    &mut recycle_skipped,
                    &mut decode_protected,
                )?;
            }
            _ => {}
        }
    }

    if !entry_stack.is_empty() {
        return Err(KdbxError::XmlMalformed("unclosed Entry".into()));
    }
    Ok(ParsedXml {
        entries,
        recycle_bin_entries: recycle_skipped,
    })
}

#[allow(clippy::too_many_arguments)]
fn on_start(
    name: &str,
    protected: bool,
    groups: &mut Vec<GroupFrame>,
    entry_stack: &mut Vec<EntryBuild>,
    parent: Option<&str>,
    _recycle_bin_uuid: &Option<String>,
) {
    match name {
        "Group" => {
            let inherit = groups.last().is_some_and(|g| g.in_recycle);
            groups.push(GroupFrame {
                name: String::new(),
                uuid: None,
                in_recycle: inherit,
            });
        }
        "Entry" => {
            entry_stack.push(EntryBuild::default());
        }
        "String" => {
            if let Some(top) = entry_stack.last_mut() {
                top.cur_key = None;
                top.cur_val = None;
                top.cur_protected = false;
            }
        }
        "Value" if parent == Some("String") => {
            if let Some(top) = entry_stack.last_mut() {
                top.cur_protected = protected;
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn on_end(
    name: &str,
    text: &str,
    parent: Option<&str>,
    groups: &mut Vec<GroupFrame>,
    recycle_bin_uuid: &mut Option<String>,
    entry_stack: &mut Vec<EntryBuild>,
    entries: &mut Vec<KdbxEntry>,
    recycle_skipped: &mut usize,
    decode_protected: &mut dyn FnMut(&str) -> Result<Secret, KdbxError>,
) -> Result<(), KdbxError> {
    match name {
        "RecycleBinUUID" if parent == Some("Meta") => {
            let t = text.trim();
            if !t.is_empty() && !t.chars().all(|c| c == 'A' || c == '=') {
                // KeePass writes an all-'A' base64 (16 zero bytes) when
                // there is no recycle bin; ignore that sentinel.
                *recycle_bin_uuid = Some(t.to_string());
            }
        }
        "UUID" if parent == Some("Group") => {
            if let Some(g) = groups.last_mut() {
                let u = text.trim().to_string();
                let is_rb = recycle_bin_uuid
                    .as_deref()
                    .is_some_and(|rb| rb.eq_ignore_ascii_case(&u));
                g.uuid = Some(u);
                if is_rb {
                    g.in_recycle = true;
                }
            }
        }
        "Name" if parent == Some("Group") => {
            if let Some(g) = groups.last_mut() {
                g.name = text.to_string();
            }
        }
        "Key" if parent == Some("String") => {
            if let Some(top) = entry_stack.last_mut() {
                top.cur_key = Some(text.to_string());
            }
        }
        "Value" if parent == Some("String") => {
            if let Some(top) = entry_stack.last_mut() {
                let val: Secret = if top.cur_protected {
                    decode_protected(text)?
                } else {
                    zeroize::Zeroizing::new(text.as_bytes().to_vec())
                };
                top.cur_val = Some(val);
            }
        }
        "String" if parent == Some("Entry") => {
            if let Some(top) = entry_stack.last_mut() {
                if let Some(k) = top.cur_key.take() {
                    let v = top
                        .cur_val
                        .take()
                        .unwrap_or_else(|| zeroize::Zeroizing::new(Vec::new()));
                    let protected = top.cur_protected;
                    top.strings.push(KdbxStringValue {
                        key: k,
                        value: v,
                        protected,
                    });
                }
            }
        }
        "Tags" if parent == Some("Entry") => {
            if let Some(top) = entry_stack.last_mut() {
                for part in text.split([';', ',']) {
                    let p = part.trim();
                    if !p.is_empty() {
                        top.tags.push(p.to_string());
                    }
                }
            }
        }
        "Expires" if parent == Some("Times") => {
            if let Some(top) = entry_stack.last_mut() {
                top.times.expires = text.trim().eq_ignore_ascii_case("true");
            }
        }
        "ExpiryTime" if parent == Some("Times") => {
            if let Some(top) = entry_stack.last_mut() {
                top.times.expiry_time_raw = Some(text.trim().to_string());
            }
        }
        "LastModificationTime" if parent == Some("Times") => {
            if let Some(top) = entry_stack.last_mut() {
                top.times.last_mod_raw = Some(text.trim().to_string());
            }
        }
        "Entry" => {
            let built = entry_stack
                .pop()
                .ok_or_else(|| KdbxError::XmlMalformed("Entry stack underflow".into()))?;
            if parent == Some("History") {
                // Historical revision of the parent entry.
                if let Some(parent_entry) = entry_stack.last_mut() {
                    let pw = built
                        .strings
                        .iter()
                        .find(|s| s.key == "Password")
                        .map(|s| s.value.clone());
                    let last_mod = built
                        .times
                        .last_mod_raw
                        .as_deref()
                        .and_then(parse_kdbx_time);
                    parent_entry.history.push(HistEntry {
                        password: pw,
                        last_mod_unix: last_mod,
                    });
                }
                return Ok(());
            }
            // Live top-level entry.
            if groups.last().is_some_and(|g| g.in_recycle) {
                *recycle_skipped += 1;
                return Ok(());
            }
            if entries.len() >= crate::KDBX_MAX_ENTRIES {
                return Err(KdbxError::TooManyEntries {
                    limit: crate::KDBX_MAX_ENTRIES,
                });
            }
            // Group path: every group frame's name except the first
            // ("Root") and any empty/recycle-ish names.
            let group_path: Vec<String> = groups
                .iter()
                .skip(1)
                .map(|g| g.name.clone())
                .filter(|n| !n.is_empty())
                .collect();
            let history: Vec<(Secret, Option<i64>)> = built
                .history
                .into_iter()
                .filter_map(|h| h.password.map(|p| (p, h.last_mod_unix)))
                .collect();
            entries.push(KdbxEntry {
                strings: built.strings,
                tags: built.tags,
                group_path,
                expires: built.times.expires,
                expiry_time_unix: built
                    .times
                    .expiry_time_raw
                    .as_deref()
                    .and_then(parse_kdbx_time),
                history_passwords: history,
            });
        }
        "Group" => {
            groups
                .pop()
                .ok_or_else(|| KdbxError::XmlMalformed("Group stack underflow".into()))?;
        }
        _ => {}
    }
    Ok(())
}

fn read_protected_attr(e: &quick_xml::events::BytesStart<'_>) -> Result<bool, KdbxError> {
    for attr in e.attributes() {
        let attr = attr.map_err(|er| KdbxError::XmlMalformed(format!("attr: {er}")))?;
        if attr.key.as_ref() == b"Protected" {
            let v = attr
                .unescape_value()
                .map_err(|er| KdbxError::XmlMalformed(format!("attr: {er}")))?;
            return Ok(v.eq_ignore_ascii_case("true"));
        }
    }
    Ok(false)
}

fn local_name(ln: &[u8]) -> Result<String, KdbxError> {
    core::str::from_utf8(ln)
        .map(str::to_string)
        .map_err(|_| KdbxError::XmlMalformed("non-UTF-8 element name".into()))
}

/// Parse a KeePass timestamp (ISO-8601 string, KDBX3; or base64 LE i64
/// seconds-since-0001, KDBX4) → Unix seconds.
#[must_use]
pub fn parse_kdbx_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.len() >= 10 && s.as_bytes()[4] == b'-' {
        return parse_iso8601(s);
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .ok()?;
    if raw.len() < 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&raw[..8]);
    let secs_since_0001 = i64::from_le_bytes(arr);
    secs_since_0001.checked_sub(62_135_596_800)
}

fn parse_iso8601(s: &str) -> Option<i64> {
    if s.len() < 19 {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse::<i64>().ok() };
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let min = num(14, 16)?;
    let sec = num(17, 19)?;
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3_600 + min * 60 + sec)
}
