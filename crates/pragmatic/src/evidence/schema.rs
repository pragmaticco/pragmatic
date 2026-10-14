//! Strict reading of evidence JSON objects (design 3.7).
//!
//! Every object in a bundle has a fixed set of keys. All of them must be
//! present (optional values are `null`, never absent) and no other key is
//! accepted, so a bundle has exactly one shape and a field a verifier does
//! not know about can never carry meaning past it. Integers must be
//! written `0|[1-9][0-9]*`, hex is lowercase with its exact length and
//! base64 is canonical. Error messages name the path of the offending
//! value, never its content.

use crate::encoding::hex_decode_exact;
use crate::json::Json;

/// An object whose key set has been checked.
pub(crate) struct Obj<'a> {
    value: &'a Json,
    at: String,
}

impl<'a> Obj<'a> {
    /// Check that `value` is an object with exactly `keys`. `at` is its
    /// path, for messages.
    pub(crate) fn new(value: &'a Json, at: &str, keys: &[&str]) -> Result<Obj<'a>, String> {
        let members = value
            .as_object()
            .ok_or_else(|| format!("{at} is not an object"))?;
        for (k, _) in members {
            if !keys.contains(&k.as_str()) {
                return Err(format!("{at} has an unknown key {k:?}"));
            }
        }
        for k in keys {
            if value.get(k).is_none() {
                return Err(format!("{at} is missing the key {k:?}"));
            }
        }
        Ok(Obj {
            value,
            at: at.to_string(),
        })
    }

    /// The member `k`, which [`Obj::new`] checked is present.
    pub(crate) fn get(&self, k: &str) -> &'a Json {
        self.value.get(k).expect("key set checked")
    }

    fn path(&self, k: &str) -> String {
        format!("{}.{k}", self.at)
    }

    pub(crate) fn str(&self, k: &str) -> Result<&'a str, String> {
        self.get(k)
            .as_str()
            .ok_or_else(|| format!("{} is not a string", self.path(k)))
    }

    pub(crate) fn opt_str(&self, k: &str) -> Result<Option<&'a str>, String> {
        match self.get(k) {
            Json::Null => Ok(None),
            v => v
                .as_str()
                .map(Some)
                .ok_or_else(|| format!("{} is not a string or null", self.path(k))),
        }
    }

    pub(crate) fn u64(&self, k: &str) -> Result<u64, String> {
        self.get(k)
            .as_u64_strict()
            .ok_or_else(|| format!("{} is not a non-negative integer", self.path(k)))
    }

    pub(crate) fn bool(&self, k: &str) -> Result<bool, String> {
        self.get(k)
            .as_bool()
            .ok_or_else(|| format!("{} is not a boolean", self.path(k)))
    }

    pub(crate) fn array(&self, k: &str) -> Result<&'a [Json], String> {
        self.get(k)
            .as_array()
            .ok_or_else(|| format!("{} is not an array", self.path(k)))
    }

    /// An optional object member: `null` or an object.
    pub(crate) fn opt_obj(&self, k: &str) -> Result<Option<&'a Json>, String> {
        match self.get(k) {
            Json::Null => Ok(None),
            v @ Json::Object(_) => Ok(Some(v)),
            _ => Err(format!("{} is not an object or null", self.path(k))),
        }
    }

    pub(crate) fn hex<const N: usize>(&self, k: &str) -> Result<[u8; N], String> {
        hex_decode_exact::<N>(self.str(k)?).map_err(|e| format!("{}: {e}", self.path(k)))
    }

    pub(crate) fn hex32(&self, k: &str) -> Result<[u8; 32], String> {
        self.hex::<32>(k)
    }

    /// An array of 32-byte hex digests.
    pub(crate) fn digests(&self, k: &str) -> Result<Vec<[u8; 32]>, String> {
        self.array(k)?
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.as_str()
                    .and_then(|s| hex_decode_exact::<32>(s).ok())
                    .ok_or_else(|| {
                        format!(
                            "{}[{i}] is not a 32-byte lowercase hex digest",
                            self.path(k)
                        )
                    })
            })
            .collect()
    }
}

/// A `[cursor, slot]` pair.
pub(crate) fn slot_pair(v: &Json) -> Option<(u64, u8)> {
    match v.as_array()? {
        [c, s] => Some((c.as_u64_strict()?, s.as_u8_strict()?)),
        _ => None,
    }
}
