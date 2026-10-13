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
//! A slot that starts like JSON (its first non-white-space character is
//! `{` or `[`) is read as JSON. These values are binary:
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
//!
//! # Reading JSON without trusting it
//!
//! The scanner is a single pass over the text that never builds a tree, so
//! it has no size limit and no nesting limit: a 30 MB image request, an
//! attachment nested 70 arrays deep, a repeated key, `NaN`, a lone
//! surrogate escape, none of which strict JSON (design 3.7) accepts, are
//! all still scanned. Attachments are what redaction must never miss, so
//! the scanner reads more than strict JSON, never less: a repeated key is
//! read in every copy, and bare words such as `NaN` are values.
//!
//! What it cannot read, it does not guess about. A slot that starts like
//! JSON but cannot be read to its end (truncated, or text that merely
//! starts with `[`) is [`Scanned::incomplete`]: whatever was found before
//! the scanner stopped is reported, and callers that redact treat the rest
//! as possibly binary ([`Scanned::may_hold_binary`]), so an attachment is
//! never assumed absent from a slot that was not read.

use crate::sha256::{hex, sha256, Digest};

/// The media type reported when nothing better is known.
pub const OCTET_STREAM: &str = "application/octet-stream";

/// The longest JSON Pointer reported for a binary field, in bytes. Deeper
/// or longer paths end in `/…`: the pointer is for people, and capping it
/// keeps a hostile slot (a long key above thousands of values) from making
/// the scan quadratic.
pub const MAX_POINTER: usize = 1024;

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
    /// [`placeholder`](BinaryField::placeholder) (as a JSON string, in
    /// place, keeping the rest of the text as it was). `None` when the slot
    /// is not UTF-8 (then [`binary`](Self::binary) describes the whole
    /// slot). When nothing was replaced this is the slot's text exactly.
    pub text: Option<String>,
    /// The binary values found, in document order.
    pub binary: Vec<BinaryField>,
    /// The slot starts like JSON but could not be read to its end, so it
    /// may hold attachments the scan did not reach. `text` then still has
    /// every value found before the scan stopped replaced.
    pub incomplete: bool,
}

impl Scanned {
    /// True if the slot holds any binary content.
    pub fn has_binary(&self) -> bool {
        !self.binary.is_empty()
    }

    /// True if the slot may hold binary content: some was found, or the
    /// slot could not be read to its end. Redaction withholds such slots,
    /// since an attachment in a slot that was not read is never assumed to
    /// be absent.
    pub fn may_hold_binary(&self) -> bool {
        self.has_binary() || self.incomplete
    }
}

/// Classify a slot's bytes: text, JSON with binary fields, or binary.
pub fn scan(bytes: &[u8]) -> Scanned {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Scanned {
            text: None,
            binary: vec![BinaryField::of_bytes(String::new(), OCTET_STREAM, bytes)],
            incomplete: false,
        };
    };
    let first = text.bytes().find(|b| !is_json_space(*b));
    if !matches!(first, Some(b'{') | Some(b'[')) {
        return plain(text);
    }
    let mut scanner = Scanner::new(text);
    let complete = scanner.document();
    if scanner.found.is_empty() {
        let mut s = plain(text);
        s.incomplete = !complete;
        return s;
    }
    let (text, binary) = scanner.finish();
    Scanned {
        text: Some(text),
        binary,
        incomplete: !complete,
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
        incomplete: false,
    }
}

fn is_json_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// A byte that may appear in a bare value: numbers, `true`, `false`,
/// `null`, and the non-JSON words some encoders write (`NaN`,
/// `Infinity`).
fn is_bare(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
}

/// The member names the rules of [`scan`] care about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Data,
    Bytes,
    FileData,
    B64Json,
    Type,
    MediaType,
    Format,
    InputAudio,
    Other,
}

impl Key {
    fn of(name: &str) -> Key {
        match name {
            "data" => Key::Data,
            "$bytes" => Key::Bytes,
            "file_data" => Key::FileData,
            "b64_json" => Key::B64Json,
            "type" => Key::Type,
            "media_type" => Key::MediaType,
            "format" => Key::Format,
            "input_audio" => Key::InputAudio,
            _ => Key::Other,
        }
    }
}

/// A string token in the text: the byte range of its contents (between the
/// quotes) and whether it has escapes.
#[derive(Clone, Copy, Debug)]
struct Token {
    start: usize,
    end: usize,
    escaped: bool,
}

/// An object being read. Whether a `data` or `$bytes` member is binary
/// depends on the whole object (its `type`, its members, its parent), and
/// JSON does not order members, so those strings are kept as candidates
/// and decided when the object closes.
#[derive(Debug)]
struct Object {
    /// The pointer length of the object itself.
    pointer: usize,
    under_input_audio: bool,
    members: usize,
    key: Key,
    type_base64: bool,
    media_type: Option<String>,
    format: Option<String>,
    data: Vec<Token>,
    bytes: Option<Token>,
}

#[derive(Debug)]
enum Frame {
    Array { pointer: usize, index: usize },
    Object(Box<Object>),
}

/// What the scanner expects next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// A value (an array element, a member value or the document).
    Value,
    /// The first element of an array, or `]`.
    ElementOrClose,
    /// The first member of an object, or `}`.
    KeyOrClose,
    /// A member name after `,`.
    Key,
    Colon,
    CommaOrClose,
    /// Nothing but white space after the document.
    End,
}

/// A single pass over JSON-like text, finding binary values (see the
/// module documentation).
struct Scanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    pointer: String,
    stack: Vec<Frame>,
    /// Each binary value found, with the byte range of its token
    /// (including the quotes) to replace.
    found: Vec<(usize, usize, BinaryField)>,
}

impl<'a> Scanner<'a> {
    fn new(text: &'a str) -> Scanner<'a> {
        Scanner {
            text,
            bytes: text.as_bytes(),
            pos: 0,
            pointer: String::new(),
            stack: Vec::new(),
            found: Vec::new(),
        }
    }

    /// Read the document. True if it was read to its end and nothing but
    /// white space follows it.
    fn document(&mut self) -> bool {
        let mut expect = Expect::Value;
        loop {
            while self.pos < self.bytes.len() && is_json_space(self.bytes[self.pos]) {
                self.pos += 1;
            }
            let Some(&b) = self.bytes.get(self.pos) else {
                return expect == Expect::End;
            };
            let next = match expect {
                Expect::End => return false,
                Expect::Value => self.value(b),
                Expect::ElementOrClose if b == b']' => self.close(b),
                Expect::ElementOrClose => {
                    self.enter_element();
                    self.value(b)
                }
                Expect::KeyOrClose if b == b'}' => self.close(b),
                Expect::KeyOrClose | Expect::Key => self.key(b),
                Expect::Colon if b == b':' => {
                    self.pos += 1;
                    Some(Expect::Value)
                }
                Expect::Colon => None,
                Expect::CommaOrClose if b == b',' => {
                    self.pos += 1;
                    self.next_member()
                }
                Expect::CommaOrClose => self.close(b),
            };
            match next {
                Some(e) => expect = e,
                None => return false,
            }
        }
    }

    /// A value starting at `b`.
    fn value(&mut self, b: u8) -> Option<Expect> {
        match b {
            b'{' => {
                self.pos += 1;
                let under_input_audio = self.member_key() == Some(Key::InputAudio);
                self.stack.push(Frame::Object(Box::new(Object {
                    pointer: self.pointer.len(),
                    under_input_audio,
                    members: 0,
                    key: Key::Other,
                    type_base64: false,
                    media_type: None,
                    format: None,
                    data: Vec::new(),
                    bytes: None,
                })));
                Some(Expect::KeyOrClose)
            }
            b'[' => {
                self.pos += 1;
                self.stack.push(Frame::Array {
                    pointer: self.pointer.len(),
                    index: 0,
                });
                Some(Expect::ElementOrClose)
            }
            b'"' => {
                let token = self.string()?;
                self.string_value(token);
                Some(self.after_value())
            }
            b if is_bare(b) => {
                while self.pos < self.bytes.len() && is_bare(self.bytes[self.pos]) {
                    self.pos += 1;
                }
                Some(self.after_value())
            }
            _ => None,
        }
    }

    /// What follows a complete value: the end of the document, or a comma
    /// or close in the container. A member's pointer token is dropped.
    fn after_value(&mut self) -> Expect {
        match self.stack.last_mut() {
            None => Expect::End,
            Some(Frame::Array { pointer, .. }) => {
                self.pointer.truncate(*pointer);
                Expect::CommaOrClose
            }
            Some(Frame::Object(o)) => {
                self.pointer.truncate(o.pointer);
                o.members += 1;
                o.key = Key::Other;
                Expect::CommaOrClose
            }
        }
    }

    /// After a comma: the next element or member.
    fn next_member(&mut self) -> Option<Expect> {
        match self.stack.last_mut()? {
            Frame::Array { index, .. } => {
                *index += 1;
                self.enter_element();
                Some(Expect::Value)
            }
            Frame::Object(_) => Some(Expect::Key),
        }
    }

    /// Push the pointer token of the current array element.
    fn enter_element(&mut self) {
        if let Some(Frame::Array { index, .. }) = self.stack.last() {
            let token = index.to_string();
            self.push_token(&token);
        }
    }

    /// A member name starting at `b`.
    fn key(&mut self, b: u8) -> Option<Expect> {
        if b != b'"' {
            return None;
        }
        let token = self.string()?;
        let name = self.decode(token);
        let mut escaped = String::with_capacity(name.len());
        for c in name.chars() {
            match c {
                '~' => escaped.push_str("~0"),
                '/' => escaped.push_str("~1"),
                c => escaped.push(c),
            }
        }
        self.push_token(&escaped);
        if let Some(Frame::Object(o)) = self.stack.last_mut() {
            o.key = Key::of(&name);
        }
        Some(Expect::Colon)
    }

    /// `]` or `}` closing the innermost container.
    fn close(&mut self, b: u8) -> Option<Expect> {
        let matches = matches!(
            (self.stack.last()?, b),
            (Frame::Array { .. }, b']') | (Frame::Object(_), b'}')
        );
        if !matches {
            return None;
        }
        self.pos += 1;
        match self.stack.pop()? {
            Frame::Array { pointer, .. } => self.pointer.truncate(pointer),
            Frame::Object(o) => {
                self.pointer.truncate(o.pointer);
                self.decide(*o);
            }
        }
        Some(self.after_value())
    }

    /// The name of the member whose value is being read, if in an object.
    fn member_key(&self) -> Option<Key> {
        match self.stack.last()? {
            Frame::Object(o) => Some(o.key),
            Frame::Array { .. } => None,
        }
    }

    /// A string value: binary at once if its member name or its form says
    /// so; a candidate if the object's shape will decide; and the members
    /// that describe a shape are noted.
    fn string_value(&mut self, token: Token) {
        let key = self.member_key();
        if matches!(key, Some(Key::FileData) | Some(Key::B64Json)) {
            let value = self.decode(token);
            let field = data_url(&value, &self.pointer).unwrap_or_else(|| {
                BinaryField::of_base64(self.pointer.clone(), OCTET_STREAM, &value)
            });
            self.record(token, field);
            return;
        }
        if self.looks_like_data_url(token) {
            let value = self.decode(token);
            if let Some(field) = data_url(&value, &self.pointer) {
                self.record(token, field);
                return;
            }
        }
        let Some(Frame::Object(o)) = self.stack.last_mut() else {
            return;
        };
        match o.key {
            Key::Data => o.data.push(token),
            Key::Bytes => o.bytes = Some(token),
            Key::Type | Key::MediaType | Key::Format => {
                let key = o.key;
                let value = decode(self.text, token);
                let Some(Frame::Object(o)) = self.stack.last_mut() else {
                    return;
                };
                match key {
                    Key::Type => o.type_base64 |= value == "base64",
                    Key::MediaType if o.media_type.is_none() => o.media_type = Some(value),
                    Key::Format if o.format.is_none() => o.format = Some(value),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Apply the object rules of the module documentation to a closed
    /// object. The pointer is the object's own.
    fn decide(&mut self, o: Object) {
        if o.members == 1 {
            if let Some(token) = o.bytes {
                self.typed(token, "$bytes", OCTET_STREAM);
                return;
            }
        }
        let media = if o.under_input_audio {
            match o.format.as_deref() {
                Some(f) if !f.is_empty() => format!("audio/{f}"),
                _ => OCTET_STREAM.to_string(),
            }
        } else if o.type_base64 {
            o.media_type.unwrap_or_else(|| OCTET_STREAM.to_string())
        } else {
            return;
        };
        for token in o.data {
            self.typed(token, "data", &media);
        }
    }

    /// Record the string member `name` of the object at the current
    /// pointer as binary of `media` (a data URL keeps its own type).
    fn typed(&mut self, token: Token, name: &str, media: &str) {
        let len = self.pointer.len();
        self.push_token(name);
        let value = self.decode(token);
        let field = data_url(&value, &self.pointer)
            .unwrap_or_else(|| BinaryField::of_base64(self.pointer.clone(), media, &value));
        self.pointer.truncate(len);
        self.record(token, field);
    }

    fn record(&mut self, token: Token, field: BinaryField) {
        // The token's quotes are part of what is replaced.
        self.found.push((token.start - 1, token.end + 1, field));
    }

    /// Append `/token` to the pointer, or `/…` once it would grow past
    /// [`MAX_POINTER`].
    fn push_token(&mut self, token: &str) {
        const ELLIPSIS: &str = "/\u{2026}";
        if self.pointer.ends_with(ELLIPSIS) {
            return;
        }
        if self.pointer.len() + 1 + token.len() > MAX_POINTER - ELLIPSIS.len() {
            self.pointer.push_str(ELLIPSIS);
        } else {
            self.pointer.push('/');
            self.pointer.push_str(token);
        }
    }

    /// Read a string token at `pos` (an opening quote). Leniently: raw
    /// control characters are accepted; only an unterminated string fails.
    fn string(&mut self) -> Option<Token> {
        let start = self.pos + 1;
        let mut i = start;
        let mut escaped = false;
        while let Some(&b) = self.bytes.get(i) {
            match b {
                b'"' => {
                    self.pos = i + 1;
                    return Some(Token {
                        start,
                        end: i,
                        escaped,
                    });
                }
                b'\\' => {
                    escaped = true;
                    i += 2;
                }
                _ => i += 1,
            }
        }
        None
    }

    fn decode(&self, token: Token) -> String {
        decode(self.text, token)
    }

    /// Whether a string could be a data URL: its raw text starts with
    /// `data:`, or it has escapes (which could spell `data:`).
    fn looks_like_data_url(&self, token: Token) -> bool {
        token.escaped || self.text[token.start..token.end].starts_with("data:")
    }

    /// The text with every binary value replaced, and the fields in
    /// document order.
    fn finish(mut self) -> (String, Vec<BinaryField>) {
        self.found.sort_by_key(|(start, _, _)| *start);
        let mut out = String::with_capacity(self.text.len());
        let mut at = 0;
        let mut fields = Vec::with_capacity(self.found.len());
        for (start, end, field) in self.found {
            out.push_str(&self.text[at..start]);
            out.push('"');
            out.push_str(&field.placeholder());
            out.push('"');
            at = end;
            fields.push(field);
        }
        out.push_str(&self.text[at..]);
        (out, fields)
    }
}

/// A string token's value, decoding escapes leniently: an unknown escape
/// keeps its character, and an escape that is not a whole character (a lone
/// surrogate, bad hex) becomes U+FFFD.
fn decode(text: &str, token: Token) -> String {
    let raw = &text[token.start..token.end];
    if !token.escaped {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => out.push(unicode_escape(&mut chars)),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// The character of a `\u` escape (its `u` already read), joining a
/// surrogate pair.
fn unicode_escape(chars: &mut std::str::Chars<'_>) -> char {
    let hex4 = |chars: &mut std::str::Chars<'_>| -> Option<u32> {
        let digits: String = chars.by_ref().take(4).collect();
        if digits.len() == 4 {
            u32::from_str_radix(&digits, 16).ok()
        } else {
            None
        }
    };
    let Some(first) = hex4(chars) else {
        return '\u{fffd}';
    };
    if (0xd800..0xdc00).contains(&first) {
        let mut ahead = chars.clone();
        if ahead.next() == Some('\\') && ahead.next() == Some('u') {
            if let Some(second) = hex4(&mut ahead) {
                if (0xdc00..0xe000).contains(&second) {
                    *chars = ahead;
                    let c = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                    return char::from_u32(c).unwrap_or('\u{fffd}');
                }
            }
        }
        return '\u{fffd}';
    }
    char::from_u32(first).unwrap_or('\u{fffd}')
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

    /// The Anthropic image block of [`PNG`] (or of `data`), as JSON text.
    fn image(data: &str) -> String {
        format!(r#"{{"type":"base64","media_type":"image/png","data":"{data}"}}"#)
    }

    #[test]
    fn slots_of_any_size_are_scanned() {
        // 17 MiB of base64, beyond what the old tree parser would read.
        let big = base64_encode(&vec![0x42u8; 13 << 20]);
        let body = format!(
            r#"{{"messages":[{{"role":"user","content":[{{"type":"image","source":{}}}]}}]}}"#,
            image(&big)
        );
        assert!(body.len() > 16 << 20);
        let s = scan(body.as_bytes());
        assert!(!s.incomplete);
        assert_eq!(s.binary.len(), 1);
        assert_eq!(s.binary[0].pointer, "/messages/0/content/0/source/data");
        assert_eq!(s.binary[0].bytes, 13 << 20);
        assert!(s.text.unwrap().len() < 1024);
    }

    #[test]
    fn nesting_depth_is_unlimited() {
        let mut doc = image(&base64_encode(PNG));
        for _ in 0..10_000 {
            doc = format!("[{doc}]");
        }
        let s = scan(doc.as_bytes());
        assert!(!s.incomplete);
        assert_eq!(s.binary.len(), 1);
        assert_eq!(s.binary[0].sha256, sha256(PNG));
        // The pointer is capped, and says so.
        assert!(s.binary[0].pointer.len() <= MAX_POINTER);
        assert!(s.binary[0].pointer.ends_with("/\u{2026}"));
    }

    #[test]
    fn what_strict_json_refuses_is_still_scanned() {
        let b64 = base64_encode(PNG);
        // Members in any order, a repeated key in every copy, NaN, a lone
        // surrogate, escaped slashes and an escaped "data:".
        let cases = [
            format!(r#"{{"data":"{b64}","media_type":"image/png","type":"base64"}}"#),
            format!(r#"{{"type":"base64","data":"{b64}","data":"{b64}"}}"#),
            format!(r#"[NaN, -Infinity, {}]"#, image(&b64)),
            format!(r#"["\ud800", {}]"#, image(&b64)),
            format!(r#"["data:image\/png;base64,{b64}"]"#),
            format!(r#"["\u0064ata:image/png;base64,{b64}"]"#),
        ];
        for (i, case) in cases.iter().enumerate() {
            let s = scan(case.as_bytes());
            assert!(!s.incomplete, "{i}");
            assert!(s.has_binary(), "{i}: {case}");
            assert!(s.binary.iter().all(|f| f.sha256 == sha256(PNG)), "{i}");
            assert!(!s.text.unwrap().contains(&b64), "{i}");
        }
        assert_eq!(scan(cases[1].as_bytes()).binary.len(), 2);
    }

    #[test]
    fn slots_not_read_to_their_end_may_hold_binary() {
        let b64 = base64_encode(PNG);
        // Truncated after one attachment: it is found, the rest is unknown.
        let cut = format!(r#"[{}, {{"type":"base64","data":"QU"#, image(&b64));
        let s = scan(cut.as_bytes());
        assert!(s.incomplete && s.may_hold_binary());
        assert_eq!(s.binary.len(), 1);
        // Text that only starts like JSON.
        let s = scan(b"[INFO] job finished");
        assert!(s.incomplete && s.may_hold_binary() && !s.has_binary());
        assert_eq!(s.text.as_deref(), Some("[INFO] job finished"));
        // Plain text and complete JSON without binary are clean.
        assert!(!scan(b"hello [world]").may_hold_binary());
        assert!(!scan(br#" {"a": [1, 2.5e3, true, null]} "#).may_hold_binary());
    }

    #[test]
    fn object_rules_follow_the_whole_object() {
        let b64 = base64_encode(PNG);
        // input_audio types its data even when it also says base64.
        let s = scan(
            format!(r#"{{"input_audio":{{"type":"base64","data":"{b64}","format":"wav"}}}}"#)
                .as_bytes(),
        );
        assert_eq!(s.binary[0].media_type, "audio/wav");
        // $bytes is codec bytes only as the sole member.
        assert!(!scan(format!(r#"{{"$bytes":"{b64}","x":1}}"#).as_bytes()).has_binary());
        // A data member of an untyped object is text.
        assert!(!scan(format!(r#"{{"data":"{b64}"}}"#).as_bytes()).has_binary());
        // Replacement keeps the rest of the text as it was.
        let s = scan(format!("{{ \"keep\" : 1,\n \"file_data\": \"{b64}\" }}").as_bytes());
        let text = s.text.unwrap();
        assert!(text.starts_with("{ \"keep\" : 1,\n \"file_data\": \"[binary "));
        assert!(text.ends_with("]\" }"));
    }

    #[test]
    fn data_url_needs_base64() {
        let s = scan(br#"["data:text/plain,hello"]"#);
        assert!(!s.has_binary());
    }
}
