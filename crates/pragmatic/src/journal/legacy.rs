//! Read-only support for format 1 journals (Pragmatic 0.4 and 0.5, spec
//! 2.16).
//!
//! Format 1 is a 12-byte header (`PRAGJRNL`, version 1) and frames of
//! `len u32 ‖ payload ‖ hash`, chained as `h_i = H(h_{i-1} ‖ cursor ‖
//! payload)` from an all-zero genesis. A payload is a tag byte followed by
//! `u64`-length-prefixed fields. There are no branches, slots, salts or
//! flags, and nothing in the header says whether the chain is keyed: the
//! caller supplies the key it was written with, or none.
//!
//! These journals are parsed into [`Event::Legacy`](super::Event::Legacy)
//! entries so they can be listed, verified and exported. Appending to one is
//! refused.

use crate::sha256::{Digest, DIGEST_LEN};
use crate::value::Value;

use super::codec::chain_h;
use super::Cursor;

/// Bytes in a format 1 header.
pub(crate) const HEADER_LEN: usize = 12;

/// The format 1 header.
pub(crate) fn header() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(super::MAGIC);
    h[8..12].copy_from_slice(&1u32.to_le_bytes());
    h
}

/// An event of a format 1 journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegacyEvent {
    /// A model call and its sampled outcome.
    OracleDraw {
        prompt: Value,
        outcome: Value,
        provenance: String,
    },
    /// A value received on a channel.
    ChannelRecv { channel: String, value: Value },
    /// The write-ahead intent of an effect.
    EffectIntent { name: String, arg: Value },
    /// An effect's committed result.
    EffectCommit { name: String, result: Value },
    /// An effect written off by recovery.
    EffectCompensated { name: String },
    /// A clock read.
    Clock { nanos: u64 },
    /// The program's identity.
    Program { name: String, hash: String },
}

/// The format 1 payload encoding: `tag ‖ (u64 len ‖ bytes)*`.
pub(crate) fn encode(event: &LegacyEvent) -> Vec<u8> {
    fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
    }
    let mut buf = Vec::new();
    match event {
        LegacyEvent::OracleDraw {
            prompt,
            outcome,
            provenance,
        } => {
            buf.push(1);
            put(&mut buf, prompt.as_bytes());
            put(&mut buf, outcome.as_bytes());
            put(&mut buf, provenance.as_bytes());
        }
        LegacyEvent::ChannelRecv { channel, value } => {
            buf.push(2);
            put(&mut buf, channel.as_bytes());
            put(&mut buf, value.as_bytes());
        }
        LegacyEvent::EffectIntent { name, arg } => {
            buf.push(3);
            put(&mut buf, name.as_bytes());
            put(&mut buf, arg.as_bytes());
        }
        LegacyEvent::EffectCommit { name, result } => {
            buf.push(4);
            put(&mut buf, name.as_bytes());
            put(&mut buf, result.as_bytes());
        }
        LegacyEvent::EffectCompensated { name } => {
            buf.push(5);
            put(&mut buf, name.as_bytes());
        }
        LegacyEvent::Clock { nanos } => {
            buf.push(6);
            buf.extend_from_slice(&nanos.to_le_bytes());
        }
        LegacyEvent::Program { name, hash } => {
            buf.push(7);
            put(&mut buf, name.as_bytes());
            put(&mut buf, hash.as_bytes());
        }
    }
    buf
}

/// Append the frame `len ‖ payload ‖ hash` to `out`.
pub(crate) fn encode_frame(out: &mut Vec<u8>, event: &LegacyEvent, hash: &Digest) {
    let payload = encode(event);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(hash);
}

/// Decode a format 1 payload; the whole payload must be consumed, and text
/// fields must be UTF-8.
pub(crate) fn decode(bytes: &[u8]) -> Result<LegacyEvent, &'static str> {
    struct R<'a>(&'a [u8]);
    impl R<'_> {
        fn field(&mut self) -> Result<Vec<u8>, &'static str> {
            if self.0.len() < 8 {
                return Err("record ends early");
            }
            let len = u64::from_le_bytes(self.0[..8].try_into().unwrap());
            self.0 = &self.0[8..];
            if len > self.0.len() as u64 {
                return Err("field length exceeds the record");
            }
            let (head, rest) = self.0.split_at(len as usize);
            self.0 = rest;
            Ok(head.to_vec())
        }
        fn text(&mut self) -> Result<String, &'static str> {
            String::from_utf8(self.field()?).map_err(|_| "text field is not UTF-8")
        }
        fn value(&mut self) -> Result<Value, &'static str> {
            Ok(Value(self.field()?))
        }
    }
    let (&tag, rest) = bytes.split_first().ok_or("empty record")?;
    let mut r = R(rest);
    let event = match tag {
        1 => LegacyEvent::OracleDraw {
            prompt: r.value()?,
            outcome: r.value()?,
            provenance: r.text()?,
        },
        2 => LegacyEvent::ChannelRecv {
            channel: r.text()?,
            value: r.value()?,
        },
        3 => LegacyEvent::EffectIntent {
            name: r.text()?,
            arg: r.value()?,
        },
        4 => LegacyEvent::EffectCommit {
            name: r.text()?,
            result: r.value()?,
        },
        5 => LegacyEvent::EffectCompensated { name: r.text()? },
        6 => {
            if r.0.len() < 8 {
                return Err("record ends early");
            }
            let nanos = u64::from_le_bytes(r.0[..8].try_into().unwrap());
            r.0 = &r.0[8..];
            LegacyEvent::Clock { nanos }
        }
        7 => LegacyEvent::Program {
            name: r.text()?,
            hash: r.text()?,
        },
        _ => return Err("unknown record kind"),
    };
    if !r.0.is_empty() {
        return Err("trailing bytes in record");
    }
    Ok(event)
}

/// `h_i = H(h_{i-1} ‖ u64 LE cursor ‖ payload)`.
pub(crate) fn link(key: Option<&[u8]>, prev: &Digest, cursor: Cursor, payload: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(DIGEST_LEN + 8 + payload.len());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(&cursor.to_le_bytes());
    buf.extend_from_slice(payload);
    chain_h(key, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_events() -> Vec<LegacyEvent> {
        vec![
            LegacyEvent::OracleDraw {
                prompt: "p".into(),
                outcome: "o".into(),
                provenance: "test".into(),
            },
            LegacyEvent::ChannelRecv {
                channel: "c".into(),
                value: "v".into(),
            },
            LegacyEvent::EffectIntent {
                name: "n".into(),
                arg: "a".into(),
            },
            LegacyEvent::EffectCommit {
                name: "n".into(),
                result: "r".into(),
            },
            LegacyEvent::EffectCompensated { name: "n".into() },
            LegacyEvent::Clock { nanos: 42 },
            LegacyEvent::Program {
                name: "agent".into(),
                hash: "abc".into(),
            },
        ]
    }

    #[test]
    fn every_kind_round_trips() {
        for ev in all_events() {
            assert_eq!(decode(&encode(&ev)).unwrap(), ev);
        }
    }

    #[test]
    fn matches_the_0_5_writer_byte_for_byte() {
        // The format 1 writer still ships for the existing runtime; its
        // encoding must be exactly what this reader expects.
        use crate::journal_v1::Event as V1;
        let pairs = [
            (
                V1::OracleDraw {
                    prompt: "p".into(),
                    outcome: "o".into(),
                    provenance: "x".into(),
                },
                LegacyEvent::OracleDraw {
                    prompt: "p".into(),
                    outcome: "o".into(),
                    provenance: "x".into(),
                },
            ),
            (V1::Clock { nanos: 9 }, LegacyEvent::Clock { nanos: 9 }),
        ];
        for (v1, legacy) in pairs {
            assert_eq!(v1.encode(), encode(&legacy));
        }
    }

    #[test]
    fn rejects_malformed_payloads() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[99]).is_err());
        let mut long = encode(&LegacyEvent::Clock { nanos: 1 });
        long.push(0);
        assert_eq!(decode(&long), Err("trailing bytes in record"));
        let mut bad_len = vec![5u8];
        bad_len.extend_from_slice(&100u64.to_le_bytes());
        assert_eq!(decode(&bad_len), Err("field length exceeds the record"));
        let mut not_utf8 = vec![5u8];
        not_utf8.extend_from_slice(&1u64.to_le_bytes());
        not_utf8.push(0xff);
        assert_eq!(decode(&not_utf8), Err("text field is not UTF-8"));
    }
}
