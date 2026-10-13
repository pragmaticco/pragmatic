//! When batches run (design 4.7): every `interval_secs` when new leaves
//! exist, within 30 seconds of any run's successful `attempt.end`, and on
//! demand (`anchor=now`).
//!
//! The server owns the timer task; this type only keeps the arithmetic in
//! one place so the 30-second promise and the interval bounds are applied
//! the same way everywhere.

use std::time::{Duration, Instant};

/// The default interval: 10 minutes.
pub const DEFAULT_INTERVAL_SECS: u64 = 600;
/// The shortest allowed interval.
pub const MIN_INTERVAL_SECS: u64 = 60;
/// The longest allowed interval.
pub const MAX_INTERVAL_SECS: u64 = 3600;
/// How soon a batch runs after a successful `attempt.end`.
pub const ATTEMPT_END_DELAY: Duration = Duration::from_secs(30);

/// Check `interval_secs` against the allowed range (60 to 3600).
pub fn validate_interval(secs: u64) -> Result<Duration, String> {
    if (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&secs) {
        Ok(Duration::from_secs(secs))
    } else {
        Err(format!(
            "anchoring interval_secs must be {MIN_INTERVAL_SECS} to {MAX_INTERVAL_SECS}, got {secs}"
        ))
    }
}

/// The next time a batch is due.
#[derive(Clone, Debug)]
pub struct BatchSchedule {
    interval: Duration,
    next_regular: Instant,
    soon: Option<Instant>,
}

impl BatchSchedule {
    /// A schedule whose first regular batch is one interval after `now`.
    pub fn new(interval: Duration, now: Instant) -> BatchSchedule {
        BatchSchedule {
            interval,
            next_regular: now + interval,
            soon: None,
        }
    }

    /// A run ended an attempt successfully: a batch is due within
    /// [`ATTEMPT_END_DELAY`]. Later calls never push that deadline back.
    pub fn attempt_ended(&mut self, now: Instant) {
        let deadline = now + ATTEMPT_END_DELAY;
        self.soon = Some(self.soon.map_or(deadline, |s| s.min(deadline)));
    }

    /// An on-demand batch (`anchor=now`): due immediately.
    pub fn request_now(&mut self, now: Instant) {
        self.soon = Some(now);
    }

    /// When the next batch is due.
    pub fn next_due(&self) -> Instant {
        self.soon
            .map_or(self.next_regular, |s| s.min(self.next_regular))
    }

    /// True if a batch should run at `now`.
    pub fn is_due(&self, now: Instant) -> bool {
        now >= self.next_due()
    }

    /// A batch ran (or found nothing to anchor) at `now`.
    pub fn batch_ran(&mut self, now: Instant) {
        self.next_regular = now + self.interval;
        self.soon = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_bounds() {
        assert!(validate_interval(59).is_err());
        assert!(validate_interval(3601).is_err());
        assert_eq!(validate_interval(60).unwrap(), Duration::from_secs(60));
        assert!(validate_interval(DEFAULT_INTERVAL_SECS).is_ok());
    }

    #[test]
    fn attempt_end_brings_the_batch_forward() {
        let t0 = Instant::now();
        let mut s = BatchSchedule::new(Duration::from_secs(600), t0);
        assert_eq!(s.next_due(), t0 + Duration::from_secs(600));
        s.attempt_ended(t0 + Duration::from_secs(5));
        assert_eq!(s.next_due(), t0 + Duration::from_secs(35));
        // A later attempt.end does not delay it.
        s.attempt_ended(t0 + Duration::from_secs(20));
        assert_eq!(s.next_due(), t0 + Duration::from_secs(35));
        assert!(!s.is_due(t0 + Duration::from_secs(34)));
        assert!(s.is_due(t0 + Duration::from_secs(35)));
        s.batch_ran(t0 + Duration::from_secs(35));
        assert_eq!(s.next_due(), t0 + Duration::from_secs(635));
        s.request_now(t0 + Duration::from_secs(40));
        assert!(s.is_due(t0 + Duration::from_secs(40)));
    }
}
