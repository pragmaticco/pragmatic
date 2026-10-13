//! Inputs for the anchoring lag metric (design 4.7): the age of the oldest
//! append that is not yet independently anchored.
//!
//! The lag is the window in which an insider with root on the server could
//! rewrite history undetected, so it is a metric and an alert. Neither the
//! anchorer nor the journal alone knows it: append times live on the
//! append path, and what is anchored is decided by witnesses. The server
//! tells a [`LagTracker`] about both, and reads the lag from it.
//!
//! Memory stays bounded however long anchoring is down: appends within one
//! second of each other share a record, and a run keeps at most
//! [`MAX_RECORDS_PER_RUN`] records, merging its oldest two when it would
//! exceed that. Merging keeps the older time and the larger entry count,
//! so the reported lag can only be larger than the truth, never smaller.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Records kept per run before the oldest are merged.
pub const MAX_RECORDS_PER_RUN: usize = 64;

/// Appends closer together than this share one record.
const GRANULARITY: Duration = Duration::from_secs(1);

/// One group of appends: the entry count after the last of them, and the
/// time of the first.
#[derive(Clone, Copy, Debug)]
struct Pending {
    entries_after: u64,
    first_at: Instant,
}

/// Tracks unanchored appends per run. See the module documentation.
#[derive(Debug, Default)]
pub struct LagTracker {
    runs: HashMap<String, VecDeque<Pending>>,
}

impl LagTracker {
    pub fn new() -> LagTracker {
        LagTracker::default()
    }

    /// An append to `run_id` made the journal `entries_after` entries long
    /// at `at` (after its fsync).
    pub fn record_append(&mut self, run_id: &str, entries_after: u64, at: Instant) {
        let queue = self.runs.entry(run_id.to_string()).or_default();
        if let Some(last) = queue.back_mut() {
            if at.saturating_duration_since(last.first_at) < GRANULARITY {
                last.entries_after = last.entries_after.max(entries_after);
                return;
            }
        }
        queue.push_back(Pending {
            entries_after,
            first_at: at,
        });
        if queue.len() > MAX_RECORDS_PER_RUN {
            let oldest = queue.pop_front().expect("non-empty");
            let next = queue.front_mut().expect("non-empty");
            next.first_at = oldest.first_at.min(next.first_at);
            next.entries_after = next.entries_after.max(oldest.entries_after);
        }
    }

    /// `run_id`'s first `anchored_entries` entries are now independently
    /// anchored (the [`crate::Advanced`] report of a batch).
    pub fn record_anchored(&mut self, run_id: &str, anchored_entries: u64) {
        let Some(queue) = self.runs.get_mut(run_id) else {
            return;
        };
        while queue
            .front()
            .is_some_and(|p| p.entries_after <= anchored_entries)
        {
            queue.pop_front();
        }
        if queue.is_empty() {
            self.runs.remove(run_id);
        }
    }

    /// Stop tracking a run (deleted or tombstoned).
    pub fn forget(&mut self, run_id: &str) {
        self.runs.remove(run_id);
    }

    /// The time of the oldest unanchored append, if any.
    pub fn oldest_unanchored(&self) -> Option<Instant> {
        self.runs
            .values()
            .filter_map(|q| q.front().map(|p| p.first_at))
            .min()
    }

    /// The anchoring lag at `now`: zero when everything is anchored.
    pub fn lag(&self, now: Instant) -> Duration {
        self.oldest_unanchored()
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t))
    }

    /// Runs with unanchored appends.
    pub fn pending_runs(&self) -> usize {
        self.runs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lag_is_the_age_of_the_oldest_unanchored_append() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut lag = LagTracker::new();
        assert_eq!(lag.lag(t0), Duration::ZERO);
        lag.record_append("a", 1, t0);
        lag.record_append("a", 2, t0 + s(10));
        lag.record_append("b", 5, t0 + s(20));
        assert_eq!(lag.lag(t0 + s(30)), s(30));
        assert_eq!(lag.pending_runs(), 2);
        // Anchoring a prefix of "a" that covers only its first append.
        lag.record_anchored("a", 1);
        assert_eq!(lag.lag(t0 + s(30)), s(20));
        lag.record_anchored("a", 2);
        assert_eq!(lag.lag(t0 + s(30)), s(10));
        lag.record_anchored("b", 7);
        assert_eq!(lag.lag(t0 + s(30)), Duration::ZERO);
        assert_eq!(lag.pending_runs(), 0);
    }

    #[test]
    fn appends_within_a_second_share_a_record() {
        let t0 = Instant::now();
        let mut lag = LagTracker::new();
        lag.record_append("a", 1, t0);
        lag.record_append("a", 2, t0 + Duration::from_millis(500));
        // Anchoring entry 1 does not clear the group holding entry 2.
        lag.record_anchored("a", 1);
        assert_eq!(lag.oldest_unanchored(), Some(t0));
        lag.record_anchored("a", 2);
        assert_eq!(lag.oldest_unanchored(), None);
    }

    #[test]
    fn memory_is_bounded_and_merging_never_understates() {
        let t0 = Instant::now();
        let mut lag = LagTracker::new();
        for i in 0..1000u64 {
            lag.record_append("a", i + 1, t0 + Duration::from_secs(i * 2));
        }
        assert!(lag.runs["a"].len() <= MAX_RECORDS_PER_RUN);
        assert_eq!(lag.oldest_unanchored(), Some(t0));
        // Anchoring part of the history keeps the reported oldest time at
        // or before the true oldest unanchored append (entry 501, at
        // 1000 s).
        lag.record_anchored("a", 500);
        let oldest = lag.oldest_unanchored().unwrap();
        assert!(oldest <= t0 + Duration::from_secs(1000));
        lag.record_anchored("a", 1000);
        assert_eq!(lag.oldest_unanchored(), None);
        lag.record_append("x", 1, t0);
        lag.forget("x");
        assert_eq!(lag.pending_runs(), 0);
    }
}
