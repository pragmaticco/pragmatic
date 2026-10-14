//! Witness operators and the independence policy (design 4.7 and 5.3).
//!
//! An anchor is worth what its witnesses are independent of each other and
//! of the server's operator. Two time-stamp authorities run by the same
//! company are one point of failure (one compromised signing service, one
//! subpoena), so independence is counted by *operator*, not by witness. A
//! checkpoint is *independently anchored* once witnesses from at least
//! `min_independent_operators` distinct operators (default 2) have
//! verified, and only then does a run's `anchored_entries` advance.
//!
//! Operators are compared after [`canonical_operator`], which also folds
//! brands that belong to one company onto one name: Entrust's public
//! certificate business went to Sectigo, and QuoVadis is part of DigiCert,
//! so `entrust` counts as `sectigo` and `quovadis` (including QuoVadis EU)
//! as `digicert`. The CLI's verifier applies the same mapping (design 5.3
//! step 10), so the server and an auditor count the same anchors as
//! independent.
//!
//! The server's own Ed25519 signature on the checkpoint is
//! operator-controlled and never counts.

use std::collections::BTreeSet;

/// Brands folded onto the operator that owns them.
const ALIASES: &[(&str, &str)] = &[
    ("entrust", "sectigo"),
    ("quovadis", "digicert"),
    ("quovadis-eu", "digicert"),
];

/// The operator name independence is counted by: trimmed, lowercase, runs
/// of white space and underscores turned into one `-`, then the brand
/// aliases applied (`"QuoVadis EU"` becomes `"digicert"`).
pub fn canonical_operator(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending_dash = false;
    for c in name.trim().chars() {
        if c.is_whitespace() || c == '_' || c == '-' {
            pending_dash = !out.is_empty();
            continue;
        }
        if pending_dash {
            out.push('-');
            pending_dash = false;
        }
        out.extend(c.to_lowercase());
    }
    ALIASES
        .iter()
        .find(|(alias, _)| *alias == out)
        .map_or(out, |(_, owner)| owner.to_string())
}

/// `min_independent_operators`: how many distinct operators must have
/// verified a checkpoint before it counts as independently anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndependencePolicy {
    /// Default 2. Zero means the server's signature alone advances
    /// `anchored_entries` (`allow_self_anchoring` deployments, whose
    /// bundles say `"independent": false`).
    pub min_independent_operators: usize,
}

impl Default for IndependencePolicy {
    fn default() -> Self {
        IndependencePolicy {
            min_independent_operators: 2,
        }
    }
}

impl IndependencePolicy {
    /// The distinct canonical operators among `operators`, sorted.
    pub fn distinct<'a>(operators: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        operators
            .into_iter()
            .map(canonical_operator)
            .filter(|o| !o.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// True if the verified witnesses' `operators` meet the policy.
    pub fn is_independent<'a>(&self, operators: impl IntoIterator<Item = &'a str>) -> bool {
        IndependencePolicy::distinct(operators).len() >= self.min_independent_operators
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_names() {
        assert_eq!(canonical_operator("DigiCert"), "digicert");
        assert_eq!(canonical_operator("  Sectigo "), "sectigo");
        assert_eq!(canonical_operator("Entrust"), "sectigo");
        assert_eq!(canonical_operator("QuoVadis EU"), "digicert");
        assert_eq!(canonical_operator("quovadis_eu"), "digicert");
        assert_eq!(canonical_operator("QuoVadis"), "digicert");
        assert_eq!(canonical_operator("Free  TSA"), "free-tsa");
        assert_eq!(canonical_operator("-x-"), "x");
        assert_eq!(canonical_operator(""), "");
    }

    #[test]
    fn independence_counts_operators_with_aliases() {
        let policy = IndependencePolicy::default();
        // Two brands of one operator are one operator.
        assert!(!policy.is_independent(["Sectigo", "Entrust"]));
        assert!(!policy.is_independent(["DigiCert", "QuoVadis EU"]));
        assert!(!policy.is_independent(["digicert", "DigiCert"]));
        // Two operators are independent.
        assert!(policy.is_independent(["DigiCert", "Entrust"]));
        assert!(policy.is_independent(["QuoVadis EU", "Sectigo", "Entrust"]));
        assert_eq!(
            IndependencePolicy::distinct(["QuoVadis EU", "Sectigo", "Entrust", "DigiCert"]),
            vec!["digicert".to_string(), "sectigo".to_string()]
        );
        // Empty names never count.
        assert!(!policy.is_independent(["", " ", "digicert"]));
        // A stricter policy, and the self-anchoring policy.
        let three = IndependencePolicy {
            min_independent_operators: 3,
        };
        assert!(!three.is_independent(["digicert", "sectigo", "entrust"]));
        assert!(three.is_independent(["digicert", "sectigo", "globalsign"]));
        let none = IndependencePolicy {
            min_independent_operators: 0,
        };
        assert!(none.is_independent([]));
    }
}
