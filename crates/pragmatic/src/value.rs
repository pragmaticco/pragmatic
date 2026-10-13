//! `Value` - the realized outcome of a journaled step.
//!
//! The calculus treats realized oracle outcomes, channel messages, and effect
//! results as closed, irreducible *values* (paper §4.1). The runtime carries
//! them as immutable byte strings: the Journal must be able to store and
//! replay any outcome byte-for-byte without interpreting it, and agents
//! almost always move text (prompts and completions), so `Value` is a thin
//! wrapper over bytes with string conveniences.
//!
//! # Sharing
//!
//! The bytes are reference counted, so cloning a `Value` never copies them.
//! That matters for the journal's deduplication refs (spec 2.5): a ref's
//! content is its target's content, and a journal read from disk hands the
//! very same buffer to the target and to every ref. Without sharing, a file
//! of small ref slots pointing at one large slot would decode to the large
//! slot's size once per ref (a 300 KB file to 250 MiB), which is how an
//! adversarial journal could exhaust a verifier's memory. Equality compares
//! the pointers first, so comparing a ref with its target is free too.

use std::fmt;
use std::sync::Arc;

/// A realized value: opaque bytes, usually UTF-8 text. Cloning is cheap.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Value(Arc<Vec<u8>>);

impl Value {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Value(Arc::new(bytes.into()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, copied only if another `Value` still shares them.
    pub fn into_bytes(self) -> Vec<u8> {
        Arc::try_unwrap(self.0).unwrap_or_else(|shared| (*shared).clone())
    }

    /// Lossy UTF-8 view - realized model outputs are text in practice.
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True if both values share one buffer (a deduplication ref and its
    /// target, say), so a caller can count memory rather than content.
    pub fn shares_bytes_with(&self, other: &Value) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::new(s.as_bytes())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::new(s.into_bytes())
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::new(b)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::new(b)
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Value({:?})", self.as_str())
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_and_compare() {
        let a = Value::from("payload");
        let b = a.clone();
        assert!(a.shares_bytes_with(&b));
        assert_eq!(a, b);
        let c = Value::from("payload");
        assert!(!a.shares_bytes_with(&c));
        assert_eq!(a, c, "equality is by content");
        assert_eq!(b.into_bytes(), b"payload".to_vec());
        assert_eq!(c.into_bytes(), b"payload".to_vec());
        assert_eq!(Value::default().len(), 0);
    }
}
