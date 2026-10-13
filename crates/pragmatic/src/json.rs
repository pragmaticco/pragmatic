//! A minimal, strict JSON (RFC 8259) value type, parser and serializer.
//!
//! Journal notes carry small JSON documents (`run.start`, `erasure`, ...)
//! and evidence bundles are JSON files that auditors read with whatever
//! tools they have. The core crate is zero-dependency, so instead of serde
//! this module provides exactly what those formats need, with two
//! properties a general-purpose library does not promise:
//!
//! - **Strict input.** The parser accepts RFC 8259 JSON and nothing else:
//!   no trailing commas, comments, single quotes, `NaN`, leading zeros,
//!   byte-order mark, unpaired surrogate escapes or repeated object keys,
//!   and nesting is capped at [`MAX_DEPTH`]. Evidence is adversarial input,
//!   and every leniency is a place where two parsers can disagree about
//!   what a document says.
//! - **Exact numbers.** A [`Number`] keeps its original text, so integers
//!   such as cursors, sizes and Unix times round-trip exactly even beyond
//!   2^53, where an `f64` would silently round them.
//!
//! Objects are an ordered list of pairs, so serialization preserves key
//! order and output is stable byte for byte.
//!
//! RFC 8259 only says object names "SHOULD be unique", and parsers that
//! accept repeats disagree about them: JavaScript's `JSON.parse`, Python's
//! `json` and Go's `encoding/json` keep the last value, others keep the
//! first. `{"verified":false,"verified":true}` would then mean different
//! things to the server and to an auditor's script, so the parser rejects
//! any object that repeats a key (after unescaping), as I-JSON (RFC 7493
//! section 2.3) requires. Objects with more than a few members are checked
//! with a hash set, so the check stays linear in the number of keys.
//! Values built in code can still repeat a key; [`Json::duplicate_key`]
//! finds one before serialization.

use std::collections::HashSet;
use std::fmt::{self, Write as _};

/// The deepest nesting of arrays and objects the parser accepts. A top-level
/// array is depth 1. The cap keeps recursion (and so stack use) bounded on
/// hostile input.
pub const MAX_DEPTH: usize = 128;

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Json>),
    /// Members in document order. Parsed objects never repeat a key; see
    /// [`Json::duplicate_key`] for objects built in code.
    Object(Vec<(String, Json)>),
}

/// A JSON number, stored as its RFC 8259 text.
///
/// Keeping the text (rather than an `f64`) means a `u64` such as
/// `18446744073709551615` survives a parse and re-serialize unchanged, and
/// that serializing a parsed document reproduces its numbers exactly.
/// Equality is textual: `1` and `1.0` are different numbers here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Number(String);

impl Number {
    /// Validate `text` against the RFC 8259 number grammar
    /// (`-? (0 | [1-9][0-9]*) (.[0-9]+)? ([eE][+-]?[0-9]+)?`).
    pub fn parse(text: &str) -> Option<Number> {
        match scan_number(text.as_bytes(), 0) {
            Some(end) if end == text.len() => Some(Number(text.to_string())),
            _ => None,
        }
    }

    /// A number for a finite `f64`, or `None` for NaN and infinities (which
    /// JSON cannot represent).
    ///
    /// Uses the shortest decimal text that reads back as the same `f64`,
    /// switching to exponent form for very large or very small magnitudes so
    /// the text stays short.
    pub fn from_f64(value: f64) -> Option<Number> {
        if !value.is_finite() {
            return None;
        }
        let magnitude = value.abs();
        let text = if magnitude != 0.0 && !(1e-6..1e21).contains(&magnitude) {
            format!("{value:e}")
        } else {
            format!("{value}")
        };
        debug_assert!(Number::parse(&text).is_some(), "bad float text {text}");
        Some(Number(text))
    }

    /// The number's text, exactly as parsed or generated.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if the text has no fraction and no exponent.
    pub fn is_integer(&self) -> bool {
        !self.0.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'))
    }

    /// The value as an `f64`, rounded to nearest. Magnitudes beyond the
    /// `f64` range become infinite.
    pub fn as_f64(&self) -> f64 {
        // The JSON number grammar is a subset of what `f64::from_str`
        // accepts, so this cannot fail on a validated `Number`.
        self.0.parse().unwrap_or(f64::NAN)
    }

    /// The value as a `u64`, if it is written as an integer (no fraction or
    /// exponent) and fits. Negative zero (`-0`) is zero.
    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_integer() {
            return None;
        }
        // `u64::from_str` rejects any leading '-', even on zero.
        let text = if self.0 == "-0" { "0" } else { &self.0 };
        text.parse().ok()
    }

    /// The value as an `i64`, if it is written as an integer (no fraction or
    /// exponent) and fits.
    pub fn as_i64(&self) -> Option<i64> {
        if self.is_integer() {
            self.0.parse().ok()
        } else {
            None
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

macro_rules! number_from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for Number {
            fn from(v: $t) -> Number {
                Number(v.to_string())
            }
        }
        impl From<$t> for Json {
            fn from(v: $t) -> Json {
                Json::Number(Number::from(v))
            }
        }
    )*};
}
number_from_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl From<Number> for Json {
    fn from(n: Number) -> Json {
        Json::Number(n)
    }
}

impl From<bool> for Json {
    fn from(b: bool) -> Json {
        Json::Bool(b)
    }
}

impl From<&str> for Json {
    fn from(s: &str) -> Json {
        Json::String(s.to_string())
    }
}

impl From<String> for Json {
    fn from(s: String) -> Json {
        Json::String(s)
    }
}

impl From<Vec<Json>> for Json {
    fn from(items: Vec<Json>) -> Json {
        Json::Array(items)
    }
}

impl Json {
    /// Parse a complete JSON text (RFC 8259). Surrounding whitespace is
    /// allowed; anything else after the value is an error.
    pub fn parse(text: &str) -> Result<Json, JsonError> {
        parse(text)
    }

    /// The member named `key`, if this is an object. A parsed object never
    /// repeats a key; for one built in code that does, this is the first.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// The boolean, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The number, if this is a number.
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Json::Number(n) => Some(n),
            _ => None,
        }
    }

    /// See [`Number::as_u64`].
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(Number::as_u64)
    }

    /// See [`Number::as_i64`].
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(Number::as_i64)
    }

    /// See [`Number::as_f64`].
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().map(Number::as_f64)
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The members in document order, if this is an object.
    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(members) => Some(members),
            _ => None,
        }
    }

    /// True for `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// The first key that appears twice in the same object, searching the
    /// whole document depth first. `None` means every object has unique
    /// keys, so all conforming parsers agree on what the document says.
    ///
    /// [`parse`] already rejects repeated keys, so this matters only for
    /// values built in code. It runs in time linear in the number of keys.
    pub fn duplicate_key(&self) -> Option<&str> {
        match self {
            Json::Array(items) => items.iter().find_map(Json::duplicate_key),
            Json::Object(members) => {
                let mut seen = HashSet::with_capacity(members.len());
                if let Some((key, _)) = members.iter().find(|(k, _)| !seen.insert(k.as_str())) {
                    return Some(key);
                }
                members.iter().find_map(|(_, v)| v.duplicate_key())
            }
            _ => None,
        }
    }
}

/// Compact serialization: no whitespace, keys in stored order, strings
/// escaped per RFC 8259. `to_string()` comes from this impl.
impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Json::Null => f.write_str("null"),
            Json::Bool(true) => f.write_str("true"),
            Json::Bool(false) => f.write_str("false"),
            Json::Number(n) => f.write_str(n.as_str()),
            Json::String(s) => write_string(f, s),
            Json::Array(items) => {
                f.write_char('[')?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    fmt::Display::fmt(item, f)?;
                }
                f.write_char(']')
            }
            Json::Object(members) => {
                f.write_char('{')?;
                for (i, (key, value)) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write_string(f, key)?;
                    f.write_char(':')?;
                    fmt::Display::fmt(value, f)?;
                }
                f.write_char('}')
            }
        }
    }
}

/// Write `s` as a JSON string literal. Only what RFC 8259 requires is
/// escaped (quote, backslash, control characters); everything else,
/// including non-ASCII, is written as UTF-8. Runs of plain bytes are copied
/// in one call.
fn write_string(out: &mut impl fmt::Write, s: &str) -> fmt::Result {
    out.write_char('"')?;
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let escape: &str = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            0x00..=0x1f => "",
            _ => continue,
        };
        // Every byte that reaches here is ASCII, so `start..i` and `i + 1`
        // are char boundaries.
        out.write_str(&s[start..i])?;
        if escape.is_empty() {
            write!(out, "\\u{b:04x}")?;
        } else {
            out.write_str(escape)?;
        }
        start = i + 1;
    }
    out.write_str(&s[start..])?;
    out.write_char('"')
}

/// Why a JSON text was rejected, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError {
    /// Byte offset into the input where the problem was detected.
    pub offset: usize,
    /// What was wrong.
    pub reason: &'static str,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.reason)
    }
}

impl std::error::Error for JsonError {}

/// Parse a complete JSON text (RFC 8259). See [`Json::parse`].
pub fn parse(text: &str) -> Result<Json, JsonError> {
    let mut p = Parser {
        src: text,
        bytes: text.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(p.err("unexpected data after the value"));
    }
    Ok(value)
}

/// Objects with at most this many members are checked for repeated keys by
/// scanning the members already parsed, which needs no allocation and is
/// faster than hashing for the small objects that journal notes use.
const LINEAR_KEY_SCAN: usize = 16;

/// True if `key` is already a member. Small objects are scanned; once an
/// object reaches [`LINEAR_KEY_SCAN`] members its keys move into `index`,
/// so a document with many keys is still checked in linear time.
fn is_repeat(index: &mut Option<HashSet<String>>, members: &[(String, Json)], key: &str) -> bool {
    if let Some(set) = index {
        return !set.insert(key.to_string());
    }
    if members.iter().any(|(k, _)| k == key) {
        return true;
    }
    if members.len() + 1 >= LINEAR_KEY_SCAN {
        let keys = members.iter().map(|(k, _)| k.clone());
        *index = Some(keys.chain([key.to_string()]).collect());
    }
    false
}

/// Scan an RFC 8259 number starting at `start`; return the end offset, or
/// `None` if the bytes there are not a number.
fn scan_number(b: &[u8], start: usize) -> Option<usize> {
    let digits = |mut i: usize| {
        let from = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        (i > from).then_some(i)
    };
    let mut i = start;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    // Integer part: a lone zero, or a nonzero digit then any digits.
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => i = digits(i)?,
        _ => return None,
    }
    if b.get(i) == Some(&b'.') {
        i = digits(i + 1)?;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        i = digits(i)?;
    }
    Some(i)
}

struct Parser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, reason: &'static str) -> JsonError {
        JsonError {
            offset: self.pos,
            reason,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// RFC 8259 whitespace is exactly space, tab, line feed and carriage
    /// return (no form feed, no Unicode spaces, no byte-order mark).
    fn skip_ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.pos += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("expected a value")),
        }
    }

    fn literal(&mut self, word: &'static str, value: Json) -> Result<Json, JsonError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        match scan_number(self.bytes, self.pos) {
            Some(end) => {
                let text = &self.src[self.pos..end];
                self.pos = end;
                Ok(Json::Number(Number(text.to_string())))
            }
            None => Err(self.err("invalid number")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, JsonError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, JsonError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        self.pos += 1; // '{'
        let mut members: Vec<(String, Json)> = Vec::new();
        // Keys seen so far, once the object outgrows a linear scan.
        let mut index: Option<HashSet<String>> = None;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected a string key"));
            }
            let key_at = self.pos;
            let key = self.string()?;
            if is_repeat(&mut index, &members, &key) {
                return Err(JsonError {
                    offset: key_at,
                    reason: "duplicate object key",
                });
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value(depth)?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    /// Parse a string literal starting at the opening quote.
    fn string(&mut self) -> Result<String, JsonError> {
        self.pos += 1; // '"'
        let mut out = String::new();
        let mut run = self.pos;
        loop {
            let Some(b) = self.peek() else {
                return Err(self.err("unterminated string"));
            };
            match b {
                b'"' => {
                    out.push_str(&self.src[run..self.pos]);
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    out.push_str(&self.src[run..self.pos]);
                    self.pos += 1;
                    self.escape(&mut out)?;
                    run = self.pos;
                }
                0x00..=0x1f => return Err(self.err("unescaped control character in string")),
                // Any other byte, including UTF-8 continuation bytes: the
                // input is a `&str`, so the run stays valid UTF-8 and is
                // copied whole at the next quote or backslash.
                _ => self.pos += 1,
            }
        }
    }

    /// Decode one escape sequence; `pos` is just past the backslash.
    fn escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        let Some(b) = self.peek() else {
            return Err(self.err("unterminated escape"));
        };
        self.pos += 1;
        let c = match b {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{08}',
            b'f' => '\u{0c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => self.unicode_escape()?,
            _ => {
                self.pos -= 1;
                return Err(self.err("invalid escape"));
            }
        };
        out.push(c);
        Ok(())
    }

    /// Decode `XXXX` after `\u`, joining a UTF-16 surrogate pair written as
    /// two escapes. Unpaired surrogates are rejected: they cannot be held in
    /// a Rust `String`, and replacing them would change the document.
    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let first = self.hex4()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !self.bytes[self.pos..].starts_with(b"\\u") {
                    return Err(self.err("unpaired high surrogate"));
                }
                self.pos += 2;
                let second = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(self.err("high surrogate not followed by a low surrogate"));
                }
                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.err("unpaired low surrogate")),
            _ => first,
        };
        char::from_u32(code).ok_or_else(|| self.err("invalid code point"))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let digit = self
                .peek()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or_else(|| self.err("expected four hex digits"))?;
            v = v * 16 + digit;
            self.pos += 1;
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Json {
        parse(text).unwrap_or_else(|e| panic!("{text:?} should parse: {e}"))
    }

    // Accepted inputs, in the spirit of JSONTestSuite's y_ cases.
    const VALID: &[&str] = &[
        "[]",
        "{}",
        "[null]",
        "[true]",
        "[false]",
        "[0]",
        "[-0]",
        "[1]",
        "[-1]",
        "[1.5]",
        "[-0.0]",
        "[1e10]",
        "[1E10]",
        "[1e+10]",
        "[1e-10]",
        "[1.5E-2]",
        "[-1.0e-0]",
        "[123456789012345678901234567890]",
        "[\"\"]",
        "[\"a\"]",
        "[\"\\u0000\"]",
        "[\"\\uD834\\uDD1E\"]",
        "[\"\\ud834\\udd1e\"]",
        "[\"\\u00e9\"]",
        "[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"]",
        "[\"\u{20ac}\u{1d11e}\"]",
        "[\"\u{7f}\"]",
        "{\"a\":1}",
        "{\"\":0}",
        "{\"a\":1,\"A\":2,\"a \":3}",
        "{\"a\":[{\"b\":null}]}",
        "[1,2,3]",
        "[[[[]]]]",
        " \t\r\n[ 1 , 2 ]\n ",
        "{ \"a\" : true }",
        "\"top-level string\"",
        "123",
        "-0.5",
        "null",
        "true",
        "false",
    ];

    // Rejected inputs, in the spirit of JSONTestSuite's n_ cases.
    const INVALID: &[&str] = &[
        "",
        " ",
        "[",
        "]",
        "{",
        "}",
        "[1,]",
        "[,1]",
        "[1,,2]",
        "[1 2]",
        "[1}",
        "{\"a\":1]",
        "{\"a\":1,}",
        "{,}",
        "{\"a\"}",
        "{\"a\" 1}",
        "{\"a\":}",
        "{a:1}",
        "{'a':1}",
        "{1:1}",
        "['a']",
        "[01]",
        "[-01]",
        "[00]",
        "[-]",
        "[- 1]",
        "[1.]",
        "[.1]",
        "[1.e1]",
        "[2.e3]",
        "[1e]",
        "[0e]",
        "[1e+]",
        "[1.0e]",
        "[+1]",
        "[NaN]",
        "[Infinity]",
        "[-Infinity]",
        "[0x10]",
        "[tru]",
        "[True]",
        "[nul]",
        "[nulll]",
        "[\"abc]",
        "[\"\\x\"]",
        "[\"\\a\"]",
        "[\"\\u12\"]",
        "[\"\\u12G4\"]",
        "[\"\\uD800\"]",
        "[\"\\uDC00\"]",
        "[\"\\uD800\\u0041\"]",
        "[\"\\uD800x\"]",
        "[\"\\uD800\\\"]",
        "[\"a\tb\"]",
        "[\"a\nb\"]",
        "[\"\u{0}\"]",
        "[\"\\",
        "\"\\",
        "[1] [2]",
        "[1]x",
        "/* c */ []",
        "[] // c",
        "[1,2,3",
        "{\"a\":1",
        "\u{feff}[]",
        "\u{c}[]",
        "[\u{a0}1]",
        "[1]\u{0}",
        "{\"a\":1,\"a\":2}",
        "{\"a\":1,\"a\":1}",
        "{\"a\":1,\"\\u0061\":2}",
        "[{\"x\":{\"y\":1,\"y\":2}}]",
    ];

    #[test]
    fn accepts_valid_documents() {
        for text in VALID {
            ok(text);
        }
    }

    #[test]
    fn rejects_invalid_documents() {
        for text in INVALID {
            assert!(parse(text).is_err(), "{text:?} should be rejected");
        }
    }

    #[test]
    fn error_reports_offset() {
        let e = parse("[1,]").unwrap_err();
        assert_eq!(e.offset, 3);
        assert_eq!(e.to_string(), "invalid JSON at byte 3: expected a value");
    }

    #[test]
    fn valid_documents_round_trip() {
        for text in VALID {
            let value = ok(text);
            let again = ok(&value.to_string());
            assert_eq!(again, value, "{text:?}");
            // Serialization is a fixed point after one pass.
            assert_eq!(again.to_string(), value.to_string());
        }
    }

    #[test]
    fn compact_input_serializes_identically() {
        let text = r#"{"format":"pragmatic-evidence/1","anchors":[{"leaf_index":3,"tree_size":41,"ok":true,"x":null,"f":-2.5e-3}],"s":"a\"b\\c\nd\u0001"}"#;
        assert_eq!(ok(text).to_string(), text);
    }

    #[test]
    fn escapes_on_output() {
        let s = Json::from(
            "q\" b\\ nl\n cr\r tab\t bs\u{8} ff\u{c} nul\u{0} us\u{1f} del\u{7f} \u{e9}/",
        );
        assert_eq!(
            s.to_string(),
            "\"q\\\" b\\\\ nl\\n cr\\r tab\\t bs\\b ff\\f nul\\u0000 us\\u001f del\u{7f} \u{e9}/\""
        );
    }

    #[test]
    fn decodes_unicode_escapes() {
        assert_eq!(ok("\"\\u00e9\"").as_str(), Some("\u{e9}"));
        assert_eq!(ok("\"\\u20AC\"").as_str(), Some("\u{20ac}"));
        assert_eq!(ok("\"\\uD83D\\uDE00\"").as_str(), Some("\u{1f600}"));
        assert_eq!(ok("\"\\uDBFF\\uDFFF\"").as_str(), Some("\u{10ffff}"));
        assert_eq!(ok("\"a\\u0000b\"").as_str(), Some("a\u{0}b"));
        assert_eq!(ok("\"\\/\"").as_str(), Some("/"));
        // Raw multi-byte UTF-8 next to escapes.
        assert_eq!(
            ok("\"\u{1d11e}\\n\u{e9}\"").as_str(),
            Some("\u{1d11e}\n\u{e9}")
        );
    }

    #[test]
    fn integers_round_trip_exactly() {
        let doc =
            ok("[18446744073709551615,-9223372036854775808,9007199254740993,18446744073709551616]");
        let items = doc.as_array().unwrap();
        assert_eq!(items[0].as_u64(), Some(u64::MAX));
        assert_eq!(items[1].as_i64(), Some(i64::MIN));
        // 2^53 + 1 is not representable as f64 but survives as text.
        assert_eq!(items[2].as_u64(), Some(9_007_199_254_740_993));
        assert_eq!(items[3].as_u64(), None);
        assert_eq!(items[3].as_f64(), Some(18446744073709551616.0));
        assert_eq!(
            doc.to_string(),
            "[18446744073709551615,-9223372036854775808,9007199254740993,18446744073709551616]"
        );
        assert_eq!(Json::from(u64::MAX).to_string(), "18446744073709551615");
        assert_eq!(Json::from(-7i32).to_string(), "-7");
    }

    #[test]
    fn number_accessors() {
        assert_eq!(ok("1.5").as_u64(), None);
        assert_eq!(ok("1e2").as_u64(), None);
        assert_eq!(ok("1e2").as_f64(), Some(100.0));
        assert_eq!(ok("-1").as_u64(), None);
        assert_eq!(ok("-1").as_i64(), Some(-1));
        assert_eq!(ok("-0").as_i64(), Some(0));
        assert_eq!(ok("-0").as_u64(), Some(0));
        assert_eq!(ok("0").as_u64(), Some(0));
        assert_eq!(ok("1e400").as_f64(), Some(f64::INFINITY));
        assert_eq!(ok("\"1\"").as_u64(), None);
        assert!(Number::parse("01").is_none());
        assert!(Number::parse("1 ").is_none());
        assert_eq!(Number::parse("-1.5e3").unwrap().as_f64(), -1500.0);
    }

    #[test]
    fn floats_serialize_as_valid_json() {
        for v in [
            0.0,
            -0.0,
            1.0,
            -1.5,
            0.1,
            1e-7,
            1.5e-300,
            1e21,
            1e300,
            f64::MAX,
            f64::MIN_POSITIVE,
            5e-324,
        ] {
            let n = Number::from_f64(v).unwrap();
            assert!(Number::parse(n.as_str()).is_some(), "{v} -> {n}");
            assert_eq!(n.as_f64(), v, "{v} -> {n}");
        }
        assert_eq!(Number::from_f64(0.1).unwrap().as_str(), "0.1");
        assert_eq!(Number::from_f64(1e300).unwrap().as_str(), "1e300");
        assert!(Number::from_f64(f64::NAN).is_none());
        assert!(Number::from_f64(f64::INFINITY).is_none());
    }

    #[test]
    fn depth_limit() {
        let deep = |n: usize| "[".repeat(n) + &"]".repeat(n);
        assert!(parse(&deep(MAX_DEPTH)).is_ok());
        assert_eq!(
            parse(&deep(MAX_DEPTH + 1)).unwrap_err().reason,
            "nesting too deep"
        );
        let objects = |n: usize| "{\"a\":".repeat(n) + "0" + &"}".repeat(n);
        assert!(parse(&objects(MAX_DEPTH)).is_ok());
        assert!(parse(&objects(MAX_DEPTH + 1)).is_err());
        // Far past the limit must fail fast, not overflow the stack.
        assert!(parse(&"[".repeat(1_000_000)).is_err());
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        // The offset points at the repeated key.
        let e = parse(r#"{"verified":false,"verified":true}"#).unwrap_err();
        assert_eq!((e.offset, e.reason), (18, "duplicate object key"));
        // Keys are compared after unescaping.
        assert!(parse(r#"{"a":1,"\u0061":2}"#).is_err());
        assert!(parse(r#"[{"x":0},{"y":{"z":1,"z":1}}]"#).is_err());
        // The same key in different objects is fine.
        let doc = ok(r#"{"a":{"a":1},"b":[{"a":2},{"a":3}]}"#);
        assert_eq!(doc.duplicate_key(), None);
        // A repeat past the linear-scan threshold is still caught.
        for n in [
            LINEAR_KEY_SCAN - 1,
            LINEAR_KEY_SCAN,
            LINEAR_KEY_SCAN + 1,
            100,
        ] {
            let keys: Vec<String> = (0..n).map(|i| format!("\"k{i}\":{i}")).collect();
            let unique = format!("{{{}}}", keys.join(","));
            assert_eq!(ok(&unique).as_object().unwrap().len(), n);
            for repeat in [0, n / 2, n - 1] {
                let text = format!("{{{},\"k{repeat}\":0}}", keys.join(","));
                assert!(parse(&text).is_err(), "n={n} repeat={repeat}");
            }
        }
    }

    #[test]
    fn duplicate_key_reports_built_documents() {
        let doc = Json::Object(vec![
            ("a".into(), 1u64.into()),
            (
                "b".into(),
                Json::Object(vec![("c".into(), 1u64.into()), ("c".into(), 2u64.into())]),
            ),
            ("a".into(), 3u64.into()),
        ]);
        assert_eq!(doc.get("a").and_then(Json::as_u64), Some(1));
        assert_eq!(doc.duplicate_key(), Some("a"));
        let nested = Json::from(vec![Json::Object(vec![
            ("z".into(), Json::Null),
            ("z".into(), Json::Null),
        ])]);
        assert_eq!(nested.duplicate_key(), Some("z"));
        // Serialization keeps every member, in order, and the result does
        // not parse.
        assert_eq!(doc.to_string(), r#"{"a":1,"b":{"c":1,"c":2},"a":3}"#);
        assert!(parse(&doc.to_string()).is_err());
    }

    #[test]
    fn many_keys_stay_linear() {
        // 200,000 keys (about 2.5 MB). Comparing every key with every
        // earlier one would take minutes; hashing takes milliseconds.
        let n = 200_000;
        let body: Vec<String> = (0..n).map(|i| format!("\"key{i}\":{i}")).collect();
        let text = format!("{{{}}}", body.join(","));
        let doc = ok(&text);
        assert_eq!(doc.duplicate_key(), None);
        let repeated = format!("{{{},\"key0\":0}}", body.join(","));
        assert_eq!(parse(&repeated).unwrap_err().reason, "duplicate object key");
        let mut members = doc.as_object().unwrap().to_vec();
        members.push(("key7".into(), Json::Null));
        assert_eq!(Json::Object(members).duplicate_key(), Some("key7"));
    }

    #[test]
    fn accessors() {
        let doc = ok(r#"{"s":"x","n":7,"b":false,"z":null,"a":[1,"two"],"o":{}}"#);
        assert_eq!(doc.get("s").and_then(Json::as_str), Some("x"));
        assert_eq!(doc.get("n").and_then(Json::as_u64), Some(7));
        assert_eq!(doc.get("b").and_then(Json::as_bool), Some(false));
        assert!(doc.get("z").unwrap().is_null());
        assert_eq!(
            doc.get("a").and_then(Json::as_array).map(<[Json]>::len),
            Some(2)
        );
        assert_eq!(
            doc.get("o").and_then(Json::as_object).map(<[_]>::len),
            Some(0)
        );
        assert_eq!(doc.get("missing"), None);
        assert_eq!(doc.get("s").unwrap().get("s"), None);
        assert_eq!(doc.get("n").and_then(Json::as_str), None);
    }

    #[test]
    fn builds_documents() {
        let doc = Json::Object(vec![
            ("format".into(), "pragmatic-evidence/1".into()),
            ("entries".into(), 57u64.into()),
            ("keyed".into(), false.into()),
            (
                "slots".into(),
                Json::from(vec![Json::from(vec![12u64.into(), 0u64.into()])]),
            ),
            ("note".into(), Json::Null),
        ]);
        assert_eq!(
            doc.to_string(),
            r#"{"format":"pragmatic-evidence/1","entries":57,"keyed":false,"slots":[[12,0]],"note":null}"#
        );
        assert_eq!(Json::parse(&doc.to_string()).unwrap(), doc);
    }
}
