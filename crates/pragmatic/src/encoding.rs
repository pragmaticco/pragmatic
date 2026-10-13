//! Strict lowercase hex and RFC 4648 base64, encode and decode.
//!
//! Evidence bundles, checkpoints and verifier keys carry hashes, keys and
//! signatures as text, and the same bytes are read by the server, the CLI,
//! the Python verifier and auditors' own scripts. A lenient decoder (one
//! that accepts uppercase hex, missing padding, whitespace or stray bits)
//! lets two different texts stand for the same bytes, so a document can be
//! altered without changing what any tool reports, and two tools can
//! disagree about whether a document is well formed. The decoders here
//! accept exactly one text for each byte string:
//!
//! - **Hex** is lowercase `0-9a-f`, two digits per byte. Uppercase is
//!   rejected (design section 3.7: "Hex is lowercase with exact length").
//! - **Base64** is the RFC 4648 section 4 standard alphabet (`+` and `/`)
//!   with `=` padding to a multiple of four characters, and the unused low
//!   bits of the last symbol must be zero (RFC 4648 section 3.5). This is
//!   the canonical form that C2SP `signed-note` and `tlog-checkpoint`
//!   require decoders to enforce. Unpadded, URL-safe and line-wrapped
//!   input is rejected.
//!
//! The `_exact` variants also check the decoded length, which is how a
//! field that must hold a 32-byte hash or a 64-byte signature is read.
//!
//! Inputs here are public (hashes, public keys, signatures), so nothing is
//! constant time.

use std::fmt;

/// Why a hex or base64 text was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The text length cannot be a valid encoding: odd for hex, not a
    /// multiple of four for base64.
    Length,
    /// The byte at `offset` is outside the alphabet (including uppercase
    /// hex digits, whitespace and the URL-safe base64 characters).
    Character { offset: usize },
    /// Base64 padding is misplaced, or there are more than two `=`.
    Padding,
    /// The last base64 symbol has nonzero unused bits, so a different
    /// text would decode to the same bytes.
    NonCanonical,
    /// The text decodes, but not to the number of bytes required.
    WrongLength { expected: usize, actual: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Length => f.write_str("invalid encoded length"),
            DecodeError::Character { offset } => {
                write!(f, "invalid character at offset {offset}")
            }
            DecodeError::Padding => f.write_str("invalid base64 padding"),
            DecodeError::NonCanonical => f.write_str("non-canonical base64 (nonzero padding bits)"),
            DecodeError::WrongLength { expected, actual } => {
                write!(f, "decoded {actual} bytes, expected {expected}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex, two digits per byte.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_DIGITS[usize::from(b >> 4)] as char);
        out.push(HEX_DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// The value of a lowercase hex digit.
fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Decode lowercase hex of any even length.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    let t = text.as_bytes();
    if !t.len().is_multiple_of(2) {
        return Err(DecodeError::Length);
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    for (i, pair) in t.chunks_exact(2).enumerate() {
        let hi = hex_value(pair[0]).ok_or(DecodeError::Character { offset: 2 * i })?;
        let lo = hex_value(pair[1]).ok_or(DecodeError::Character { offset: 2 * i + 1 })?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

/// Decode lowercase hex that must be exactly `N` bytes (`2 * N` digits).
pub fn hex_decode_exact<const N: usize>(text: &str) -> Result<[u8; N], DecodeError> {
    to_array(hex_decode(text)?)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648 section 4) with `=` padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                out.push(BASE64_ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The 6-bit value of a standard-alphabet base64 symbol.
fn base64_value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decode canonical, padded, standard-alphabet base64.
///
/// Rejects anything another text could also decode to: missing or extra
/// padding, padding before the end, characters outside the standard
/// alphabet (whitespace, `-`, `_`), and nonzero unused bits in the last
/// symbol (for example `"QR=="`, which a lenient decoder reads as the same
/// single byte as `"QQ=="`).
pub fn base64_decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    let t = text.as_bytes();
    if !t.len().is_multiple_of(4) {
        return Err(DecodeError::Length);
    }
    let pad = t.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return Err(DecodeError::Padding);
    }
    let data = &t[..t.len() - pad];
    let mut out = Vec::with_capacity(t.len() / 4 * 3);
    for (q, quad) in data.chunks(4).enumerate() {
        let mut n = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            let offset = 4 * q + i;
            let v = base64_value(c).ok_or(if c == b'=' {
                DecodeError::Padding
            } else {
                DecodeError::Character { offset }
            })?;
            n |= v << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        match quad.len() {
            4 => out.extend_from_slice(&bytes),
            // Two symbols carry 12 bits for one byte: the low 4 must be 0.
            2 if n & 0xffff == 0 => out.push(bytes[0]),
            // Three symbols carry 18 bits for two bytes: the low 2 must be 0.
            3 if n & 0xff == 0 => out.extend_from_slice(&bytes[..2]),
            2 | 3 => return Err(DecodeError::NonCanonical),
            // A final group of one symbol (`x===`) was excluded by the
            // padding count; this is unreachable but not worth a panic.
            _ => return Err(DecodeError::Padding),
        }
    }
    Ok(out)
}

/// Decode canonical base64 that must be exactly `N` bytes.
pub fn base64_decode_exact<const N: usize>(text: &str) -> Result<[u8; N], DecodeError> {
    to_array(base64_decode(text)?)
}

fn to_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], DecodeError> {
    let actual = bytes.len();
    bytes.try_into().map_err(|_| DecodeError::WrongLength {
        expected: N,
        actual,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(
            hex_decode("000fa5ff").unwrap(),
            vec![0x00, 0x0f, 0xa5, 0xff]
        );
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&all)).unwrap(), all);
    }

    #[test]
    fn hex_is_strict() {
        assert_eq!(hex_decode("abc"), Err(DecodeError::Length));
        assert_eq!(hex_decode("AB"), Err(DecodeError::Character { offset: 0 }));
        assert_eq!(hex_decode("aB"), Err(DecodeError::Character { offset: 1 }));
        assert_eq!(hex_decode("0g"), Err(DecodeError::Character { offset: 1 }));
        assert_eq!(hex_decode(" 0"), Err(DecodeError::Character { offset: 0 }));
        assert_eq!(
            hex_decode("0x00"),
            Err(DecodeError::Character { offset: 1 })
        );
        // Non-ASCII never decodes (and never splits a char).
        assert!(hex_decode("\u{e9}").is_err());
    }

    #[test]
    fn hex_exact_length() {
        assert_eq!(hex_decode_exact::<2>("beef").unwrap(), [0xbe, 0xef]);
        assert_eq!(
            hex_decode_exact::<2>("be"),
            Err(DecodeError::WrongLength {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            hex_decode_exact::<2>("beefee"),
            Err(DecodeError::WrongLength {
                expected: 2,
                actual: 3
            })
        );
        assert_eq!(hex_decode_exact::<0>("").unwrap(), [0u8; 0]);
    }

    #[test]
    fn base64_rfc4648_vectors() {
        // RFC 4648 section 10.
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(base64_encode(plain.as_bytes()), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn base64_round_trips_every_length_and_byte() {
        let all: Vec<u8> = (0..=255).collect();
        for len in 0..=all.len() {
            let data = &all[all.len() - len..];
            let text = base64_encode(data);
            assert_eq!(base64_decode(&text).unwrap(), data, "len {len}");
        }
        // Both extra symbols of the standard alphabet.
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64_decode("+/8=").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn base64_rejects_non_canonical_text() {
        // Nonzero unused bits.
        assert_eq!(base64_decode("QR=="), Err(DecodeError::NonCanonical));
        assert_eq!(base64_decode("QUJ="), Err(DecodeError::NonCanonical));
        // "Zm9=" carries the bytes of "fo" plus two set bits; only "Zm8="
        // is accepted for them.
        assert_eq!(base64_decode("Zm8="), Ok(b"fo".to_vec()));
        assert_eq!(base64_decode("Zm9="), Err(DecodeError::NonCanonical));
        // Missing or extra padding.
        assert_eq!(base64_decode("Zg"), Err(DecodeError::Length));
        assert_eq!(base64_decode("Zg="), Err(DecodeError::Length));
        assert_eq!(base64_decode("Zg==="), Err(DecodeError::Length));
        assert_eq!(base64_decode("Z==="), Err(DecodeError::Padding));
        assert_eq!(base64_decode("===="), Err(DecodeError::Padding));
        assert_eq!(base64_decode("Zg==Zg=="), Err(DecodeError::Padding));
        assert_eq!(base64_decode("Z=g="), Err(DecodeError::Padding));
        // Characters outside the standard alphabet.
        assert_eq!(
            base64_decode("Zm9v\nYmF"),
            Err(DecodeError::Character { offset: 4 })
        );
        assert_eq!(
            base64_decode("Zm9 Zg=="),
            Err(DecodeError::Character { offset: 3 })
        );
        assert_eq!(
            base64_decode("-_8="),
            Err(DecodeError::Character { offset: 0 })
        );
        assert_eq!(
            base64_decode("+_8="),
            Err(DecodeError::Character { offset: 1 })
        );
        assert!(base64_decode("Zm9\u{e9}").is_err());
    }

    #[test]
    fn base64_exact_length() {
        let root = [7u8; 32];
        let text = base64_encode(&root);
        assert_eq!(text.len(), 44);
        assert_eq!(base64_decode_exact::<32>(&text).unwrap(), root);
        assert_eq!(
            base64_decode_exact::<31>(&text),
            Err(DecodeError::WrongLength {
                expected: 31,
                actual: 32
            })
        );
    }

    #[test]
    fn errors_display() {
        assert_eq!(
            DecodeError::Character { offset: 3 }.to_string(),
            "invalid character at offset 3"
        );
        assert_eq!(
            DecodeError::WrongLength {
                expected: 32,
                actual: 31
            }
            .to_string(),
            "decoded 31 bytes, expected 32"
        );
    }
}
