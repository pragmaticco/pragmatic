//! Which retention rules apply to a run (design 4.9).
//!
//! Several `[[retention]]` policies can match one run. Each value is then
//! the most restrictive one:
//!
//! - `retain_min_days`: the largest (every obligation to keep is met);
//! - `erasure`: `deny_during_min` over `allow`;
//! - `shred_after_days` and `delete_after_days`: the smallest non-zero
//!   value (every obligation to dispose of data is met), but never earlier
//!   than the combined minimum; 0 (never) only when every matching policy
//!   says never.
//!
//! The combined schedule can therefore never shred or delete inside a
//! retention minimum, even when the minimum comes from one policy and the
//! schedule from another.

use std::collections::BTreeMap;

use crate::config::{ErasurePolicy, RetentionPolicy};

/// The rules that apply to one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Effective {
    pub retain_min_days: u64,
    /// 0 means never.
    pub shred_after_days: u64,
    /// 0 means never.
    pub delete_after_days: u64,
    pub deny_erasure_during_min: bool,
}

/// True if a policy matches the run: the prefix matches and every label in
/// the policy is on the run with the same value.
pub fn matches(policy: &RetentionPolicy, run_id: &str, labels: &BTreeMap<String, String>) -> bool {
    run_id.starts_with(policy.matcher.prefix.as_str())
        && policy
            .matcher
            .labels
            .iter()
            .all(|(k, v)| labels.get(k) == Some(v))
}

/// The combined rules for a run, or `None` when no policy matches.
pub fn effective(
    policies: &[RetentionPolicy],
    run_id: &str,
    labels: &BTreeMap<String, String>,
) -> Option<Effective> {
    let matching: Vec<&RetentionPolicy> = policies
        .iter()
        .filter(|p| matches(p, run_id, labels))
        .collect();
    if matching.is_empty() {
        return None;
    }
    let min = matching
        .iter()
        .map(|p| p.retain_min_days)
        .max()
        .unwrap_or(0);
    let soonest = |f: fn(&RetentionPolicy) -> u64| {
        matching
            .iter()
            .map(|p| f(p))
            .filter(|&d| d > 0)
            .min()
            .map_or(0, |d| d.max(min))
    };
    Some(Effective {
        retain_min_days: min,
        shred_after_days: soonest(|p| p.shred_after_days),
        delete_after_days: soonest(|p| p.delete_after_days),
        deny_erasure_during_min: matching
            .iter()
            .any(|p| p.erasure == ErasurePolicy::DenyDuringMin),
    })
}

/// What retention should do to a run of this age.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Nothing,
    Shred,
    Delete,
}

const DAY: i64 = 86_400;

impl Effective {
    /// The action for a run last updated at `updated_at` (Unix seconds),
    /// at `now`. `has_content` is false when nothing is left to shred.
    pub fn action(&self, updated_at: i64, now: i64, has_content: bool) -> Action {
        let age = now - updated_at;
        if self.delete_after_days > 0 && age >= self.delete_after_days as i64 * DAY {
            return Action::Delete;
        }
        if has_content && self.shred_after_days > 0 && age >= self.shred_after_days as i64 * DAY {
            return Action::Shred;
        }
        Action::Nothing
    }

    /// The end of the retention minimum, in Unix seconds.
    pub fn retain_until(&self, updated_at: i64) -> i64 {
        updated_at + self.retain_min_days as i64 * DAY
    }

    /// True if erasure must be refused at `now`.
    pub fn erasure_locked(&self, updated_at: i64, now: i64) -> bool {
        self.deny_erasure_during_min && now < self.retain_until(updated_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RetentionMatch;

    fn policy(prefix: &str, min: u64, shred: u64, delete: u64, deny: bool) -> RetentionPolicy {
        RetentionPolicy {
            matcher: RetentionMatch {
                prefix: prefix.into(),
                labels: BTreeMap::new(),
            },
            retain_min_days: min,
            shred_after_days: shred,
            delete_after_days: delete,
            erasure: if deny {
                ErasurePolicy::DenyDuringMin
            } else {
                ErasurePolicy::Allow
            },
        }
    }

    #[test]
    fn overlapping_policies_take_the_most_restrictive_values() {
        let ps = vec![
            policy("", 30, 0, 365, false),
            policy("eu/", 7, 60, 90, true),
        ];
        let none = BTreeMap::new();
        let e = effective(&ps, "eu/1", &none).unwrap();
        assert_eq!(e.retain_min_days, 30);
        assert_eq!(e.shred_after_days, 60);
        assert_eq!(e.delete_after_days, 90);
        assert!(e.deny_erasure_during_min);
        let us = effective(&ps, "us/1", &none).unwrap();
        assert_eq!(us.delete_after_days, 365);
        assert_eq!(us.shred_after_days, 0);
        assert!(!us.deny_erasure_during_min);
    }

    #[test]
    fn a_schedule_never_undercuts_another_policys_minimum() {
        let ps = vec![policy("", 100, 0, 0, false), policy("a", 0, 10, 20, false)];
        let e = effective(&ps, "a1", &BTreeMap::new()).unwrap();
        assert_eq!(e.shred_after_days, 100);
        assert_eq!(e.delete_after_days, 100);
    }

    #[test]
    fn labels_must_all_match() {
        let mut p = policy("", 1, 0, 0, false);
        p.matcher.labels.insert("tier".into(), "gold".into());
        let mut labels = BTreeMap::new();
        assert!(effective(std::slice::from_ref(&p), "x", &labels).is_none());
        labels.insert("tier".into(), "gold".into());
        assert!(effective(&[p], "x", &labels).is_some());
    }

    #[test]
    fn actions_by_age() {
        let e = Effective {
            retain_min_days: 1,
            shred_after_days: 2,
            delete_after_days: 3,
            deny_erasure_during_min: true,
        };
        assert_eq!(e.action(0, DAY, true), Action::Nothing);
        assert_eq!(e.action(0, 2 * DAY, true), Action::Shred);
        assert_eq!(e.action(0, 2 * DAY, false), Action::Nothing);
        assert_eq!(e.action(0, 3 * DAY, true), Action::Delete);
        assert!(e.erasure_locked(0, DAY - 1));
        assert!(!e.erasure_locked(0, DAY));
    }
}
