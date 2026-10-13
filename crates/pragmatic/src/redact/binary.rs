//! Binary content inside slots: images, PDFs, audio and raw bytes (design
//! section 4.10).
//!
//! Model requests and responses carry attachments as base64 inside JSON:
//! an Anthropic image or document block, an OpenAI `data:` URL, a file or
//! an audio clip. Shown as text they are megabytes of noise, scanned by the
//! text detectors they produce false matches, and nothing in them is
//! readable anyway. Every view of a slot therefore goes through [`scan`]
//! first, which finds those fields and describes each one by what can be
//! said without showing it: its media type, its decoded size and the
//! SHA-256 of its decoded bytes, so an auditor holding the original file
//! can still tell whether it is the one that was sent.
//!
//! A slot is read as JSON when it parses as JSON. These values are binary:
//!
//! - an object with `"type": "base64"` and a string `data` (Anthropic
//!   `source` blocks for images and documents), typed by its `media_type`;
//! - any string of the form `data:<media type>;base64,<payload>` (OpenAI
//!   image and file inputs, and data URLs anywhere else);
//! - the string value of a `file_data` member (OpenAI file inputs that are
//!   not data URLs) and of a `b64_json` member (OpenAI image outputs);
//! - the `data` string of an `input_audio` object, typed `audio/<format>`;
//! - the string in an object whose only member is `$bytes` (the codec's
//!   encoding of raw bytes).
//!
//! A slot that is not UTF-8 is binary as a whole. Detection is structural,
//! never content sniffing: a base64-looking string anywhere else is text,
//! and redaction of text is the detectors' job ([`super::find`]).

use crate::json::Json;
use crate::sha256::{hex, sha256, Digest};

/// The media type reported when nothing better is known.
pub const OCTET_STREAM: &str = "application/octet-stream";

/// The most bytes of a slot [`scan`] tries to read as JSON. Larger slots are
/// still scanned (as text or as non-UTF-8 binary), only not parsed: a slot
/// is at most 64 MiB, and parsing that into a tree several times its size
/// just to render a page is not worth the memory.
pub const MAX_JSON_SCAN: usize = 16 << 20;

/// One binary value found in a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryField {
    /// RFC 6901 JSON Pointer to the value inside the slot's JSON, or the
    /// empty string when the whole slot is binary.
    pub pointer: String,
    /// The declared media type, or [`OCTET_STREAM`].
    pub media_type: String,
    /// The size of the decoded bytes (of the text itself when it does not
    /// decode as base64).
    pub bytes: u64,
    /// SHA-256 of the decoded bytes (of the text itself when it does not
    /// decode).
    pub sha256: Digest,
}

impl BinaryField {
    /// `[binary media_type=… bytes=n sha256=…]`, the text that stands in for
    /// the value in every redacted view.
    pub fn placeholder(&self) -> String {
        format!(
            "[binary media_type={} bytes={} sha256={}]",
            self.media_type,
            self.bytes,
            hex(&self.sha256)
        )
    }

    fn of_bytes(pointer: String, media_type: &str, data: &[u8]) -> BinaryField {
        BinaryField {
            pointer,
            media_type: clean_media_type(media_type),
            bytes: data.len() as u64,
            sha256: sha256(data),
        }
    }

    /// A field for base64 `text`, measured by its decoded bytes when it
    /// decodes and by the text otherwise.
    fn of_base64(pointer: String, media_type: &str, text: &str) -> BinaryField {
        match lenient_base64(text) {
            Some(data) => BinaryField::of_bytes(pointer, media_type, &data),
            None => BinaryField::of_bytes(pointer, media_type, text.as_bytes()),
        }
    }
}

/// What a slot holds, for display and redaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scanned {
    /// The slot as text with every binary value replaced by its
    /// [`placeholder`](BinaryField::placeholder). `None` when the slot is
    /// not UTF-8 (then [`binary`](Self::binary) describes the whole slot).
    /// When nothing was replaced this is the slot's text exactly; otherwise
    /// it is the JSON re-serialized compactly.
    pub text: Option<String>,
    /// The binary values found, in document order.
    pub binary: Vec<BinaryField>,
}

impl Scanned {
    /// True if the slot holds any binary content.
    pub fn has_binary(&self) -> bool {
        !self.binary.is_empty()
    }
}

/// Classify a slot's bytes: text, JSON with binary fields, or binary.
pub fn scan(bytes: &[u8]) -> Scanned {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Scanned {
            text: None,
            binary: vec![BinaryField::of_bytes(String::new(), OCTET_STREAM, bytes)],
        };
    };
    let looks_like_json = matches!(
        text.trim_start().as_bytes().first(),
        Some(b'{') | Some(b'[')
    );
    if !looks_like_json || bytes.len() > MAX_JSON_SCAN {
        return plain(text);
    }
    let Ok(mut doc) = Json::parse(text) else {
        return plain(text);
    };
    let mut binary = Vec::new();
    replace_binary(&mut doc, None, &mut String::new(), &mut binary);
    if binary.is_empty() {
        return plain(text);
    }
    Scanned {
        text: Some(doc.to_string()),
        binary,
    }
}

/// True if `bytes` holds binary content by the rules of [`scan`].
pub fn contains_binary(bytes: &[u8]) -> bool {
    scan(bytes).has_binary()
}

fn plain(text: &str) -> Scanned {
    Scanned {
        text: Some(text.to_string()),
        binary: Vec::new(),
    }
}

/// Walk `value`, replacing each binary value with its placeholder string
/// and recording it. `pointer` is the JSON Pointer of `value`, and `parent`
/// the member name it sits under, if any.
fn replace_binary(
    value: &mut Json,
    parent: Option<&str>,
    pointer: &mut String,
    out: &mut Vec<BinaryField>,
) {
    match value {
        Json::String(s) => {
            if let Some(field) = data_url(s, pointer) {
                *s = field.placeholder();
                out.push(field);
            }
        }
        Json::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let len = pointer.len();
                pointer.push('/');
                pointer.push_str(&i.to_string());
                replace_binary(item, None, pointer, out);
                pointer.truncate(len);
            }
        }
        Json::Object(members) => {
            let typed = object_media_type(members, parent);
            for (key, member) in members.iter_mut() {
                let len = pointer.len();
                pointer.push('/');
                push_pointer_token(pointer, key);
                let declared = match (&typed, key.as_str()) {
                    (Some(t), _) if t.field == key.as_str() => Some(t.media_type.as_str()),
                    (_, "file_data") | (_, "b64_json") => Some(OCTET_STREAM),
                    _ => None,
                };
                match (declared, &mut *member) {
                    (Some(media), Json::String(s)) => {
                        // A data URL keeps its own media type.
                        let field = data_url(s, pointer)
                            .unwrap_or_else(|| BinaryField::of_base64(pointer.clone(), media, s));
                        *s = field.placeholder();
                        out.push(field);
                    }
                    _ => replace_binary(member, Some(key), pointer, out),
                }
                pointer.truncate(len);
            }
        }
        _ => {}
    }
}

/// Which member of an object is binary because of the object's shape.
struct Typed {
    field: &'static str,
    media_type: String,
}

fn object_media_type(members: &[(String, Json)], parent: Option<&str>) -> Option<Typed> {
    let get = |k: &str| members.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let text = |k: &str| get(k).and_then(Json::as_str);
    // The codec's bytes: exactly one member, `$bytes`.
    if members.len() == 1 && members[0].0 == "$bytes" && members[0].1.as_str().is_some() {
        return Some(Typed {
            field: "$bytes",
            media_type: OCTET_STREAM.to_string(),
        });
    }
    // OpenAI: "input_audio": {"data": "...", "format": "wav"}.
    if parent == Some("input_audio") && text("data").is_some() {
        let format = text("format").unwrap_or("");
        return Some(Typed {
            field: "data",
            media_type: if format.is_empty() {
                OCTET_STREAM.to_string()
            } else {
                format!("audio/{format}")
            },
        });
    }
    // Anthropic: {"type": "base64", "media_type": "...", "data": "..."}.
    if text("type") == Some("base64") && text("data").is_some() {
        return Some(Typed {
            field: "data",
            media_type: text("media_type").unwrap_or(OCTET_STREAM).to_string(),
        });
    }
    None
}

/// A `data:<media type>;base64,<payload>` string, if `s` is one.
fn data_url(s: &str, pointer: &str) -> Option<BinaryField> {
    let rest = s.strip_prefix("data:")?;
    let (header, payload) = rest.split_once(',')?;
    let media = header.strip_suffix(";base64")?;
    let media = media.split(';').next().unwrap_or("");
    let media = if media.is_empty() {
        OCTET_STREAM
    } else {
        media
    };
    Some(BinaryField::of_base64(pointer.to_string(), media, payload))
}

/// Escape one JSON Pointer reference token (RFC 6901 section 4).
fn push_pointer_token(pointer: &mut String, key: &str) {
    for c in key.chars() {
        match c {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            c => pointer.push(c),
        }
    }
}

/// A media type restricted to the RFC 6838 name characters and a sane
/// length, so a placeholder can always be parsed back and never carries
/// markup or spaces from the slot.
fn clean_media_type(media: &str) -> String {
    let ok = |c: char| c.is_ascii_alphanumeric() || "!#$&^_.+-/".contains(c);
    if media.is_empty() || media.len() > 127 || !media.chars().all(ok) {
        OCTET_STREAM.to_string()
    } else {
        media.to_ascii_lowercase()
    }
}

/// Decode base64 the way attachments are actually written: standard or
/// URL-safe alphabet, padding optional, ASCII white space ignored.
fn lenient_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut padding = false;
    for b in text.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        if padding {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    (bits < 6).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base64_encode;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nnot really a picture";

    #[test]
    fn plain_text_and_json_without_binary_are_unchanged() {
        let s = scan(b"hello world");
        assert_eq!(s.text.as_deref(), Some("hello world"));
        assert!(!s.has_binary());
        let json = br#"{ "messages": [ {"role": "user", "content": "hi"} ] }"#;
        let s = scan(json);
        assert_eq!(s.text.as_deref().map(str::as_bytes), Some(&json[..]));
        assert!(!s.has_binary());
    }

    #[test]
    fn non_utf8_is_binary_as_a_whole() {
        let s = scan(&[0xff, 0x00, 0x10]);
        assert!(s.text.is_none());
        assert_eq!(s.binary.len(), 1);
        assert_eq!(s.binary[0].pointer, "");
        assert_eq!(s.binary[0].media_type, OCTET_STREAM);
        assert_eq!(s.binary[0].bytes, 3);
        assert_eq!(s.binary[0].sha256, sha256(&[0xff, 0x00, 0x10]));
    }

    #[test]
    fn anthropic_base64_sources_are_replaced() {
        let b64 = base64_encode(PNG);
        let body = format!(
            r#"{{"content":[{{"type":"image","source":{{"type":"base64","media_type":"image/png","data":"{b64}"}}}},{{"type":"text","text":"what is this"}}]}}"#
        );
        let s = scan(body.as_bytes());
        assert_eq!(s.binary.len(), 1);
        let f = &s.binary[0];
        assert_eq!(f.pointer, "/content/0/source/data");
        assert_eq!(f.media_type, "image/png");
        assert_eq!(f.bytes, PNG.len() as u64);
        assert_eq!(f.sha256, sha256(PNG));
        let text = s.text.unwrap();
        assert!(!text.contains(&b64));
        assert!(text.contains(&f.placeholder()));
        assert!(text.contains("what is this"));
    }

    #[test]
    fn data_urls_file_data_audio_and_codec_bytes() {
        let b64 = base64_encode(PNG);
        let body = format!(
            r#"[{{"image_url":{{"url":"data:image/jpeg;base64,{b64}"}}}},
                {{"file":{{"file_data":"{b64}","filename":"a.pdf"}}}},
                {{"input_audio":{{"data":"{b64}","format":"wav"}}}},
                {{"$bytes":"{b64}"}},
                {{"data":[{{"b64_json":"{b64}"}}]}}]"#
        );
        let s = scan(body.as_bytes());
        let pointers: Vec<&str> = s.binary.iter().map(|f| f.pointer.as_str()).collect();
        assert_eq!(
            pointers,
            [
                "/0/image_url/url",
                "/1/file/file_data",
                "/2/input_audio/data",
                "/3/$bytes",
                "/4/data/0/b64_json"
            ]
        );
        let types: Vec<&str> = s.binary.iter().map(|f| f.media_type.as_str()).collect();
        assert_eq!(
            types,
            [
                "image/jpeg",
                OCTET_STREAM,
                "audio/wav",
                OCTET_STREAM,
                OCTET_STREAM
            ]
        );
        assert!(s.binary.iter().all(|f| f.sha256 == sha256(PNG)));
        assert!(!s.text.unwrap().contains(&b64));
    }

    #[test]
    fn pointers_escape_keys_and_media_types_are_cleaned() {
        let body = r#"{"a/b~c":{"type":"base64","media_type":"<script>","data":"QUJD"}}"#;
        let s = scan(body.as_bytes());
        assert_eq!(s.binary[0].pointer, "/a~1b~0c/data");
        assert_eq!(s.binary[0].media_type, OCTET_STREAM);
        assert_eq!(s.binary[0].bytes, 3);
    }

    #[test]
    fn base64_that_does_not_decode_is_measured_as_text() {
        let s = scan(br#"{"$bytes":"not base64!"}"#);
        assert_eq!(s.binary[0].bytes, "not base64!".len() as u64);
        assert_eq!(s.binary[0].sha256, sha256(b"not base64!"));
    }

    #[test]
    fn lenient_base64_accepts_what_attachments_use() {
        assert_eq!(lenient_base64("QUJD").unwrap(), b"ABC");
        assert_eq!(lenient_base64("QUI=").unwrap(), b"AB");
        assert_eq!(lenient_base64("QUI").unwrap(), b"AB");
        assert_eq!(lenient_base64("QU\nJD").unwrap(), b"ABC");
        assert_eq!(lenient_base64("-_8=").unwrap(), vec![0xfb, 0xff]);
        assert!(lenient_base64("Q").is_none());
        assert!(lenient_base64("QU=JD").is_none());
        assert!(lenient_base64("QU*D").is_none());
    }

    #[test]
    fn data_url_needs_base64() {
        let s = scan(br#"["data:text/plain,hello"]"#);
        assert!(!s.has_binary());
    }
}
