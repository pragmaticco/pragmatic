//! Redacted views of slot content (design 4.10).
//!
//! Redaction is a view, never a write: the journal keeps its bytes and its
//! chain. A viewer without `view_raw` never receives salts, raw journal
//! bytes or the bytes of anything binary, and the text it receives has
//! personal data and secrets replaced.
//!
//! Each slot is parsed as strict JSON when it can be:
//!
//! - **Binary fields** are replaced by
//!   `[binary media_type=… bytes=n sha256=…]` and never served: Anthropic
//!   content blocks whose `source.type` is `base64`, `data:` URLs (OpenAI
//!   image inputs), `file_data`, OpenAI image outputs' `b64_json`,
//!   `input_audio.data`, and codec `{"$bytes": …}` objects, as the core's
//!   `redact::binary::scan` recognizes them. They are never scanned either; a detector
//!   finding "personal data" inside base64 would be noise.
//! - **Text** (every other string, and numbers, which can hold a card
//!   number) goes through the core detectors and the configured patterns.
//! - **Object keys** go through them too: a map keyed by email address,
//!   phone number or card number is as common as a list of them. When two
//!   keys redact alike (`[email]` twice), later ones get a suffix
//!   (`[email] (2)`), so the view stays strict JSON with every member.
//!
//! Every slot goes through the core's `redact::binary::scan` first, which
//! reads JSON in one pass with no nesting limit and every copy of a
//! repeated key, and replaces each binary value with its placeholder in
//! place. The view is built from that text, never from the slot's own
//! bytes, so a slot that is JSON but not *strict* JSON (a repeated key,
//! nesting past 64), which is then parsed leniently (a repeated key keeps
//! its last value), can no longer hide an attachment behind a second copy
//! of a key. Slots that are not JSON at all are redacted as text, with any
//! embedded `data:...;base64,...` URL replaced first and, since their
//! structure is unknown, any run of 256 or more base64 characters withheld
//! as binary; so is a slot that starts like JSON but could not be read to
//! its end. Slots that are not UTF-8 are binary and never served without
//! `view_raw`.
//!
//! A streamed model reply (an event stream) holds its text in deltas of a
//! few characters, where no detector sees a value split across them. When
//! the reassembled text of such a slot (`redact::stream`) holds something
//! a detector or pattern finds, the view shows that reassembled text,
//! redacted, instead of the events.
//!
//! Redaction does not look inside images, PDFs or audio, and regex
//! redaction is not de-identification: the documentation says so.

use std::collections::HashSet;

use pragmatic::encoding::{base64_decode, hex_encode};
use pragmatic::json::{self, Json};
use pragmatic::redact::{self, binary, stream, Kind};
use pragmatic::sha256::sha256;
use regex::Regex;
use serde::Serialize;

use crate::config::{ConfigError, RedactionConfig};

/// What a configured pattern's matches are replaced with.
pub const PATTERN_PLACEHOLDER: &str = "[redacted]";

/// The shortest run of base64 characters withheld as binary from text
/// whose structure is unknown.
pub const BASE64_RUN: usize = 256;

/// The redaction rules of one server.
#[derive(Debug, Clone)]
pub struct Redactor {
    kinds: Vec<Kind>,
    patterns: Vec<Regex>,
    data_url: Regex,
    base64_run: Regex,
}

/// A binary value that was withheld from a view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BinaryInfo {
    pub media_type: String,
    pub bytes: u64,
    pub sha256: String,
}

impl BinaryInfo {
    fn of(media_type: &str, bytes: &[u8]) -> BinaryInfo {
        BinaryInfo {
            media_type: media_type.to_string(),
            bytes: bytes.len() as u64,
            sha256: hex_encode(&sha256(bytes)),
        }
    }

    /// `[binary media_type=… bytes=n sha256=…]`.
    pub fn placeholder(&self) -> String {
        format!(
            "[binary media_type={} bytes={} sha256={}]",
            self.media_type, self.bytes, self.sha256
        )
    }
}

/// A slot's content as a viewer without `view_raw` sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redacted {
    /// Redacted text (possibly re-serialized JSON).
    Text(String),
    /// Bytes that are not UTF-8: described, never served.
    Binary(BinaryInfo),
}

impl Redactor {
    /// Build the rules from the `[redaction]` section.
    pub fn new(config: &RedactionConfig) -> Result<Redactor, ConfigError> {
        let mut patterns = Vec::new();
        for (i, p) in config.patterns.iter().enumerate() {
            patterns.push(
                Regex::new(p).map_err(|e| ConfigError(format!("redaction.patterns[{i}]: {e}")))?,
            );
        }
        Ok(Redactor {
            kinds: config.kinds()?,
            patterns,
            data_url: Regex::new(
                r"data:([A-Za-z0-9.+/-]*)(?:;[A-Za-z0-9=._-]+)*;base64,([A-Za-z0-9+/]*=*)",
            )
            .expect("static pattern"),
            base64_run: Regex::new(&format!(r"[A-Za-z0-9+/_-]{{{BASE64_RUN},}}={{0,2}}"))
                .expect("static pattern"),
        })
    }

    /// The names of the detectors in use, for evidence bundles.
    pub fn detector_names(&self) -> Vec<&'static str> {
        self.kinds.iter().map(|k| k.name()).collect()
    }

    /// SHA-256 of the canonical JSON array of the configured patterns, as
    /// an evidence bundle's `redaction.patterns_sha256` states it (design
    /// 5.1), so a bundle can say which patterns were applied without
    /// listing them, and a verifier holding the list can check it.
    pub fn patterns_sha256(&self) -> String {
        let patterns: Vec<&str> = self.patterns.iter().map(Regex::as_str).collect();
        hex_encode(&pragmatic::evidence::patterns_sha256(&patterns))
    }

    /// The SHA-256 of the canonical JSON array of the configured patterns
    /// (an evidence bundle's `redaction.patterns_sha256`).
    pub fn patterns_digest(&self) -> pragmatic::sha256::Digest {
        let patterns: Vec<&str> = self.patterns.iter().map(Regex::as_str).collect();
        pragmatic::evidence::patterns_sha256(&patterns)
    }

    /// Whether an evidence bundle redacted with `mode` (design 5.1:
    /// `none`, `detectors`, `binary` or `all`) withholds a slot holding
    /// `bytes`. Slots are withheld whole, never altered inside.
    ///
    /// - `binary` withholds every slot that holds or may hold binary
    ///   content: the core scan's binary fields, a slot that starts like
    ///   JSON but could not be read to its end (what was not read is never
    ///   assumed free of attachments), and, in text that is not JSON, a
    ///   `data:` URL or a run of 256 or more base64 characters, as the
    ///   server's views treat them.
    /// - `detectors` withholds those too (detectors cannot inspect
    ///   attachments), and every slot whose text a configured detector or
    ///   pattern matches, object keys and numbers included.
    pub fn withholds(&self, mode: &str, bytes: &[u8]) -> bool {
        match mode {
            "none" => false,
            "binary" | "detectors" => {
                let scanned = binary::scan(bytes);
                if scanned.may_hold_binary() {
                    return true;
                }
                let Some(text) = scanned.text else {
                    return true;
                };
                let json_like = text.trim_start().starts_with(['{', '[']);
                if !json_like && (self.base64_run.is_match(&text) || self.data_url.is_match(&text))
                {
                    return true;
                }
                mode == "detectors"
                    && (self.detects(&text) || stream::texts(bytes).iter().any(|t| self.detects(t)))
            }
            _ => true,
        }
    }

    /// Whether a configured detector or pattern finds something in `text`.
    fn detects(&self, text: &str) -> bool {
        !redact::find(text, &self.kinds).is_empty()
            || self.patterns.iter().any(|p| p.is_match(text))
    }

    /// Redact free text: embedded `data:` URLs, then the detectors, then
    /// the configured patterns.
    pub fn redact_text(&self, text: &str) -> String {
        let text = self.data_url.replace_all(text, |c: &regex::Captures<'_>| {
            let media = c.get(1).map_or("", |m| m.as_str());
            let media = if media.is_empty() {
                "application/octet-stream"
            } else {
                media
            };
            let b64 = c.get(2).map_or("", |m| m.as_str());
            binary_of_base64(media, b64).placeholder()
        });
        let (mut out, _) = redact::redact(&text, &self.kinds);
        for p in &self.patterns {
            if p.is_match(&out) {
                out = p.replace_all(&out, PATTERN_PLACEHOLDER).into_owned();
            }
        }
        out
    }

    /// Redact one slot's bytes (see the module documentation).
    pub fn redact_slot(&self, bytes: &[u8]) -> Redacted {
        let scanned = binary::scan(bytes);
        let Some(text) = scanned.text else {
            return Redacted::Binary(BinaryInfo::of("application/octet-stream", bytes));
        };
        if scanned.incomplete {
            // Not read to its end: what follows may hold attachments, so it
            // is treated as text of unknown structure.
            return Redacted::Text(self.redact_loose_text(&text));
        }
        let doc = match json::parse(&text) {
            Ok(doc) => Some(doc),
            Err(_) => lenient(&text),
        };
        match doc {
            Some(doc) if is_container(&doc) => {
                Redacted::Text(self.redact_json(doc, None).to_string())
            }
            Some(_) => Redacted::Text(self.redact_text(&text)),
            None => Redacted::Text(
                self.redact_stream(bytes)
                    .unwrap_or_else(|| self.redact_loose_text(&text)),
            ),
        }
    }

    /// The reassembled, redacted text of a streamed reply in which a
    /// detector or pattern finds something only once its deltas are joined
    /// (see the module documentation); `None` otherwise.
    fn redact_stream(&self, bytes: &[u8]) -> Option<String> {
        let parts = stream::texts(bytes);
        if !parts.iter().any(|t| self.detects(t)) {
            return None;
        }
        let mut out = String::from("[event stream: its text reassembled and redacted]\n");
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                out.push_str("\n\n");
            }
            out.push_str(&self.redact_loose_text(part));
        }
        Some(out)
    }

    /// Redact text whose structure is unknown: long base64 runs are
    /// withheld as binary first (they may be an image or a document), then
    /// the text rules apply.
    fn redact_loose_text(&self, text: &str) -> String {
        let text = self
            .base64_run
            .replace_all(text, |c: &regex::Captures<'_>| {
                binary_of_base64(
                    "application/octet-stream",
                    c.get(0).map_or("", |m| m.as_str()),
                )
                .placeholder()
            });
        self.redact_text(&text)
    }

    /// Redact a JSON value in place of its binary fields and text.
    /// `key` is the member name the value sits under.
    fn redact_json(&self, value: Json, key: Option<&str>) -> Json {
        match value {
            Json::String(s) if is_placeholder(&s) => Json::String(s),
            Json::String(s) => {
                if let Some(b) = self.data_url_binary(&s) {
                    return Json::String(b.placeholder());
                }
                if matches!(key, Some("file_data") | Some("b64_json")) {
                    return Json::String(
                        binary_of_base64("application/octet-stream", &s).placeholder(),
                    );
                }
                Json::String(self.redact_text(&s))
            }
            Json::Number(n) => {
                let redacted = self.redact_text(n.as_str());
                if redacted == n.as_str() {
                    Json::Number(n)
                } else {
                    Json::String(redacted)
                }
            }
            Json::Array(items) => Json::Array(
                items
                    .into_iter()
                    .map(|v| self.redact_json(v, None))
                    .collect(),
            ),
            Json::Object(members) => Json::Object(self.redact_object(members, key)),
            other => other,
        }
    }

    /// Redact an object's members, keys included (see the module
    /// documentation). Binary shapes are recognized by the original keys.
    fn redact_object(
        &self,
        members: Vec<(String, Json)>,
        key: Option<&str>,
    ) -> Vec<(String, Json)> {
        let binary_data = binary_member(&members, key);
        let mut names = HashSet::with_capacity(members.len());
        members
            .into_iter()
            .map(|(k, v)| {
                let value = match (&binary_data, &v) {
                    (Some((field, media)), Json::String(s))
                        if k == *field && !is_placeholder(s) =>
                    {
                        Json::String(binary_of_base64(media, s).placeholder())
                    }
                    _ => self.redact_json(v, Some(&k)),
                };
                (unique_name(self.redact_text(&k), &mut names), value)
            })
            .collect()
    }

    fn data_url_binary(&self, s: &str) -> Option<BinaryInfo> {
        if !s.starts_with("data:") {
            return None;
        }
        let c = self.data_url.captures(s)?;
        if c.get(0)?.start() != 0 {
            return None;
        }
        let media = c.get(1).map_or("", |m| m.as_str());
        let media = if media.is_empty() {
            "application/octet-stream"
        } else {
            media
        };
        let b64 = &s[c.get(2)?.start()..];
        Some(binary_of_base64(media, b64))
    }
}

/// A binary value the core scan already replaced: kept as it is (its size
/// and digest describe the original bytes, which a second pass would
/// replace with the placeholder's own).
fn is_placeholder(s: &str) -> bool {
    s.starts_with("[binary media_type=") && s.ends_with(']') && !s.contains('\n')
}

fn is_container(doc: &Json) -> bool {
    matches!(doc, Json::Object(_) | Json::Array(_) | Json::String(_))
}

/// A member name not yet used in its object: `name`, or `name (2)`,
/// `name (3)`, ... after it.
fn unique_name(name: String, used: &mut HashSet<String>) -> String {
    if used.insert(name.clone()) {
        return name;
    }
    (2u64..)
        .map(|n| format!("{name} ({n})"))
        .find(|candidate| used.insert(candidate.clone()))
        .expect("an unused name")
}

/// JSON that the strict parser refuses but a common one reads (a repeated
/// key keeps its last value, nesting up to 128). Only ever given the core
/// scan's text, whose binary values (in every copy of a repeated key) are
/// already placeholders, so dropping a copy here cannot uncover one.
fn lenient(text: &str) -> Option<Json> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .map(from_serde)
}

fn from_serde(v: serde_json::Value) -> Json {
    use serde_json::Value as V;
    match v {
        V::Null => Json::Null,
        V::Bool(b) => Json::Bool(b),
        V::Number(n) => {
            json::Number::parse(&n.to_string()).map_or(Json::String(n.to_string()), Json::Number)
        }
        V::String(s) => Json::String(s),
        V::Array(items) => Json::Array(items.into_iter().map(from_serde).collect()),
        V::Object(map) => Json::Object(map.into_iter().map(|(k, v)| (k, from_serde(v))).collect()),
    }
}

/// If this object is one of the known binary shapes, the member that holds
/// the bytes and its media type:
///
/// - `{"type": "base64", "media_type": "...", "data": "..."}` (an
///   Anthropic `source`);
/// - `{"data": "...", "format": "wav"}` under `input_audio`;
/// - `{"$bytes": "..."}` (the codec's bytes form).
fn binary_member(members: &[(String, Json)], key: Option<&str>) -> Option<(&'static str, String)> {
    let get = |name: &str| {
        members
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| match v {
                Json::String(s) => Some(s.as_str()),
                _ => None,
            })
    };
    if get("type") == Some("base64") && get("data").is_some() {
        let media = get("media_type").unwrap_or("application/octet-stream");
        return Some(("data", media.to_string()));
    }
    if key == Some("input_audio") && get("data").is_some() {
        let media = get("format").map_or("audio/unknown".to_string(), |f| format!("audio/{f}"));
        return Some(("data", media));
    }
    if members.len() == 1 && get("$bytes").is_some() {
        return Some(("$bytes", "application/octet-stream".to_string()));
    }
    None
}

/// Describe base64 text: its decoded bytes when it decodes, otherwise the
/// text itself (either way nothing of it is served).
fn binary_of_base64(media_type: &str, text: &str) -> BinaryInfo {
    let text = text.strip_prefix("data:").map_or(text, |rest| {
        rest.split_once(";base64,").map_or(text, |(_, b64)| b64)
    });
    match base64_decode(text) {
        Ok(bytes) => BinaryInfo::of(media_type, &bytes),
        Err(_) => BinaryInfo::of(media_type, text.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pragmatic::encoding::base64_encode;

    fn redactor() -> Redactor {
        Redactor::new(&RedactionConfig {
            patterns: vec![r"ACME-\d{6}".into()],
            ..RedactionConfig::default()
        })
        .unwrap()
    }

    fn text(r: Redacted) -> String {
        match r {
            Redacted::Text(t) => t,
            Redacted::Binary(b) => panic!("binary {b:?}"),
        }
    }

    #[test]
    fn text_detectors_and_patterns() {
        let r = redactor();
        let out = r.redact_text("mail jane.doe@example.com about ACME-123456, ip 10.1.2.3");
        assert!(!out.contains("jane.doe"));
        assert!(!out.contains("123456"));
        assert!(!out.contains("10.1.2.3"));
        assert!(
            out.contains("[email]") && out.contains(PATTERN_PLACEHOLDER) && out.contains("[ipv4]")
        );
    }

    #[test]
    fn anthropic_base64_sources_are_withheld_and_described() {
        let png = vec![0x89u8, b'P', b'N', b'G', 1, 2, 3];
        let slot = format!(
            r#"{{"role":"user","content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{}"}}}},{{"type":"text","text":"call +1 415 555 0100"}}]}}"#,
            base64_encode(&png)
        );
        let out = text(redactor().redact_slot(slot.as_bytes()));
        assert!(!out.contains(&base64_encode(&png)));
        assert!(out.contains("[binary media_type=image/png bytes=7 sha256="));
        assert!(out.contains(&hex_encode(&sha256(&png))));
        assert!(!out.contains("555 0100"));
        // Structure survives, in its original key order.
        assert!(out.starts_with(r#"{"role":"user","content":[{"type":"image""#));
    }

    #[test]
    fn data_urls_file_data_audio_and_codec_bytes() {
        let b64 = base64_encode(b"%PDF-1.7 secret");
        let r = redactor();
        let cases = [
            format!(
                r#"{{"type":"image_url","image_url":{{"url":"data:image/jpeg;base64,{b64}"}}}}"#
            ),
            format!(
                r#"{{"type":"file","file":{{"filename":"a.pdf","file_data":"data:application/pdf;base64,{b64}"}}}}"#
            ),
            format!(r#"{{"type":"input_audio","input_audio":{{"data":"{b64}","format":"wav"}}}}"#),
            format!(r#"{{"arg":{{"$bytes":"{b64}"}}}}"#),
        ];
        for (case, media) in cases.iter().zip([
            "image/jpeg",
            "application/pdf",
            "audio/wav",
            "application/octet-stream",
        ]) {
            let out = text(r.redact_slot(case.as_bytes()));
            assert!(!out.contains(&b64), "{out}");
            assert!(
                out.contains(&format!("media_type={media} bytes=15")),
                "{out}"
            );
        }
    }

    #[test]
    fn data_urls_inside_plain_text_are_withheld() {
        let b64 = base64_encode(b"jpeg bytes here");
        let t = format!("see data:image/jpeg;base64,{b64} for the scan");
        let out = text(redactor().redact_slot(t.as_bytes()));
        assert!(!out.contains(&b64));
        assert!(out.contains("[binary media_type=image/jpeg bytes=15"));
    }

    #[test]
    fn numbers_holding_cards_are_redacted() {
        let out = text(redactor().redact_slot(br#"{"card":4111111111111111,"n":42}"#));
        assert!(!out.contains("4111111111111111"), "{out}");
        assert!(out.contains(r#""n":42"#));
    }

    #[test]
    fn non_utf8_is_binary_and_bad_json_is_text() {
        match redactor().redact_slot(&[0xff, 0xfe, 0x00]) {
            Redacted::Binary(b) => assert_eq!(b.bytes, 3),
            other => panic!("{other:?}"),
        }
        // Duplicate keys: not strict JSON, read leniently and redacted.
        let out = text(redactor().redact_slot(br#"{"a":"x@y.example","a":"z@w.example"}"#));
        assert!(
            !out.contains("x@y.example") && !out.contains("z@w.example"),
            "{out}"
        );
        // Not JSON at all: text rules, and long base64 runs withheld.
        let blob = base64_encode(&[7u8; 300]);
        let out =
            text(redactor().redact_slot(format!("{{oops {blob} mail a@b.example").as_bytes()));
        assert!(!out.contains(&blob), "{out}");
        assert!(
            out.contains("[binary media_type=application/octet-stream bytes=300"),
            "{out}"
        );
        assert!(out.contains("[email]"), "{out}");
        // A JSON string slot is redacted inside.
        let out = text(redactor().redact_slot(br#""write to bob@example.org""#));
        assert!(out.contains("[email]"), "{out}");
    }

    #[test]
    fn object_keys_are_redacted_and_stay_unique() {
        let slot = br#"{"contacts":{"jane.doe@example.com":{"orders":3},"bob@example.org":1,"[email]":2},"cards":{"4111111111111111":"visa"},"plain":true}"#;
        let out = text(redactor().redact_slot(slot));
        for seed in ["jane.doe", "bob@example.org", "4111111111111111"] {
            assert!(!out.contains(seed), "{out}");
        }
        let doc = pragmatic::json::parse(&out).expect("the view is strict JSON");
        let contacts = doc.get("contacts").unwrap().as_object().unwrap();
        let names: Vec<&str> = contacts.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["[email]", "[email] (2)", "[email] (3)"]);
        assert!(out.contains(r#""plain":true"#));
    }

    #[test]
    fn binary_fields_are_withheld_from_json_that_is_not_strict() {
        let b64 = base64_encode(b"\x89PNG\r\n\x1a\n a photo of a passport");
        let repeated = format!(
            r#"{{"role":"user","role":"user","content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{b64}"}}}}]}}"#
        );
        let deep = format!(
            "{}{{\"type\":\"base64\",\"media_type\":\"image/png\",\"data\":\"{b64}\"}}{}",
            "[".repeat(70),
            "]".repeat(70)
        );
        for slot in [repeated, deep] {
            assert!(pragmatic::json::parse(&slot).is_err());
            let out = text(redactor().redact_slot(slot.as_bytes()));
            assert!(!out.contains(&b64), "{out}");
            assert!(out.contains("[binary media_type=image/png"), "{out}");
        }
    }

    #[test]
    fn pattern_digest_is_stable() {
        let a = redactor().patterns_sha256();
        assert_eq!(a, redactor().patterns_sha256());
        assert_eq!(a.len(), 64);
        // The digest evidence bundles carry: the canonical JSON array.
        assert_eq!(
            a,
            hex_encode(&sha256(br#"["ACME-\\d{6}"]"#)),
            "patterns_sha256 is SHA-256 of the canonical JSON array"
        );
    }

    #[test]
    fn evidence_modes_withhold_whole_slots() {
        let r = redactor();
        let plain = b"the weather is fine";
        let email = b"write to jane.doe@example.com";
        let pattern = b"order ACME-123456 shipped";
        let image = format!(
            r#"{{"source":{{"type":"base64","media_type":"image/png","data":"{}"}}}}"#,
            base64_encode(b"png bytes")
        );
        let blob = format!("log: {}", base64_encode(&[1u8; 300]));
        let unread = b"[1, 2";
        for (mode, bytes, want) in [
            ("none", image.as_bytes(), false),
            ("all", plain.as_slice(), true),
            ("binary", plain.as_slice(), false),
            ("binary", email.as_slice(), false),
            ("binary", image.as_bytes(), true),
            ("binary", blob.as_bytes(), true),
            ("binary", unread.as_slice(), true),
            ("binary", &[0xff, 0xfe][..], true),
            ("detectors", plain.as_slice(), false),
            ("detectors", email.as_slice(), true),
            ("detectors", pattern.as_slice(), true),
            ("detectors", image.as_bytes(), true),
            (
                "detectors",
                br#"{"jane.doe@example.com":1}"#.as_slice(),
                true,
            ),
        ] {
            assert_eq!(
                r.withholds(mode, bytes),
                want,
                "{mode} {:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        assert_eq!(hex_encode(&r.patterns_digest()), r.patterns_sha256());
    }

    /// A second `type` member in an Anthropic source block: a lenient
    /// parse keeps the last copy and no longer sees a base64 block, but the
    /// core scan reads every copy, and the view is built from its text.
    #[test]
    fn a_repeated_key_never_uncovers_an_attachment() {
        let b64 = base64_encode(&[0x89u8; 300]);
        let slot = format!(
            r#"{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{b64}","type":"base64-image"}}}}"#
        );
        let out = text(redactor().redact_slot(slot.as_bytes()));
        assert!(!out.contains(&b64), "{out}");
        assert!(
            out.contains("[binary media_type=image/png bytes=300 sha256="),
            "the placeholder describes the original bytes: {out}"
        );
        // A strict slot's placeholder is the same as before.
        let strict = format!(
            r#"{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{b64}"}}}}"#
        );
        let out = text(redactor().redact_slot(strict.as_bytes()));
        assert!(
            out.contains("[binary media_type=image/png bytes=300 sha256="),
            "{out}"
        );
    }

    /// A streamed reply that holds an email only across its deltas is shown
    /// as its reassembled text, redacted; evidence `detectors` withholds it.
    #[test]
    fn a_value_split_across_stream_deltas_is_redacted() {
        let mut stream = String::new();
        for d in ["Done, mailed ", "jane", ".doe@", "example.com", "."] {
            stream.push_str("event: content_block_delta\ndata: ");
            stream.push_str(&format!(
                r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{d}"}}}}"#
            ));
            stream.push_str("\n\n");
        }
        let r = redactor();
        let out = text(r.redact_slot(stream.as_bytes()));
        assert!(out.contains("[email]"), "{out}");
        assert!(!out.contains("jane") && !out.contains(".doe"), "{out}");
        assert!(r.withholds("detectors", stream.as_bytes()));
        assert!(!r.withholds("binary", stream.as_bytes()));
        // A stream with nothing to redact is shown as it was.
        let calm = stream.replace("jane", "the").replace(".doe@", " team at ");
        let out = text(r.redact_slot(calm.as_bytes()));
        assert!(out.contains("content_block_delta"), "{out}");
    }

    #[test]
    fn openai_image_outputs_are_withheld() {
        let b64 = base64_encode(b"\x89PNG image bytes");
        let slot = format!(r#"{{"created":1,"data":[{{"b64_json":"{b64}"}}]}}"#);
        let out = text(redactor().redact_slot(slot.as_bytes()));
        assert!(!out.contains(&b64), "{out}");
        assert!(
            out.contains("[binary media_type=application/octet-stream bytes=16"),
            "{out}"
        );
    }
}
