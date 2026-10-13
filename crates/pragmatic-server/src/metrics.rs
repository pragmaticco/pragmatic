//! `/metrics` in the Prometheus text format (design 4.12).
//!
//! Metrics carry no run ids and no label values: a metrics scraper is
//! usually far less protected than the server, and run ids can name
//! customers or people. Every metric is a process-wide number.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Upper bounds of the append latency histogram, in seconds.
const BUCKETS: [f64; 12] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Process-wide counters and gauges.
#[derive(Debug, Default)]
pub struct Metrics {
    appends_total: AtomicU64,
    append_buckets: [AtomicU64; BUCKETS.len()],
    append_count: AtomicU64,
    append_sum_ns: AtomicU64,
    runs: AtomicU64,
    anchor_failures_total: AtomicU64,
    chain_broken_total: AtomicU64,
    dangling_effects: AtomicU64,
    tokens_issued: AtomicU64,
    tokens_revoked: AtomicU64,
    tokens_rejected: AtomicU64,
}

/// Numbers that live elsewhere, read when the page is rendered.
#[derive(Debug, Default, Clone, Copy)]
pub struct Gauges {
    pub access_log_lag_seconds: f64,
    pub anchor_lag_seconds: f64,
    pub tokens_active: u64,
}

impl Metrics {
    /// One accepted append and how long it took, fsync included.
    pub fn observe_append(&self, took: Duration) {
        self.appends_total.fetch_add(1, Ordering::Relaxed);
        let secs = took.as_secs_f64();
        for (i, bound) in BUCKETS.iter().enumerate() {
            if secs <= *bound {
                self.append_buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.append_count.fetch_add(1, Ordering::Relaxed);
        self.append_sum_ns
            .fetch_add(took.as_nanos() as u64, Ordering::Relaxed);
    }

    pub fn set_runs(&self, n: u64) {
        self.runs.store(n, Ordering::Relaxed);
    }

    pub fn add_runs(&self, delta: i64) {
        if delta >= 0 {
            self.runs.fetch_add(delta as u64, Ordering::Relaxed);
        } else {
            let _ = self
                .runs
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(delta.unsigned_abs()))
                });
        }
    }

    pub fn anchor_failed(&self) {
        self.anchor_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn chain_broken(&self) {
        self.chain_broken_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_dangling_effects(&self, n: u64) {
        self.dangling_effects.store(n, Ordering::Relaxed);
    }

    pub fn token_issued(&self) {
        self.tokens_issued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn token_revoked(&self) {
        self.tokens_revoked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn token_rejected(&self) {
        self.tokens_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// The number of accepted appends so far.
    pub fn appends(&self) -> u64 {
        self.appends_total.load(Ordering::Relaxed)
    }

    /// The fraction of appends that took at most `bound` seconds, where
    /// `bound` is one of the histogram's bucket bounds (`None` otherwise).
    /// Load tests read latency percentiles from it.
    pub fn append_fraction_within(&self, bound: f64) -> Option<f64> {
        let i = BUCKETS.iter().position(|b| *b == bound)?;
        let total = self.append_count.load(Ordering::Relaxed);
        if total == 0 {
            return Some(1.0);
        }
        Some(self.append_buckets[i].load(Ordering::Relaxed) as f64 / total as f64)
    }

    /// The page.
    pub fn render(&self, g: Gauges) -> String {
        let mut out = String::new();
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        counter(
            &mut out,
            "pragmatic_appends_total",
            "Appends accepted.",
            load(&self.appends_total),
        );
        out.push_str(
            "# HELP pragmatic_append_seconds Server-side append latency, fsync included.\n",
        );
        out.push_str("# TYPE pragmatic_append_seconds histogram\n");
        for (i, bound) in BUCKETS.iter().enumerate() {
            let _ = writeln!(
                out,
                "pragmatic_append_seconds_bucket{{le=\"{bound}\"}} {}",
                load(&self.append_buckets[i])
            );
        }
        let count = load(&self.append_count);
        let _ = writeln!(
            out,
            "pragmatic_append_seconds_bucket{{le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(
            out,
            "pragmatic_append_seconds_sum {}",
            load(&self.append_sum_ns) as f64 / 1e9
        );
        let _ = writeln!(out, "pragmatic_append_seconds_count {count}");
        gauge(
            &mut out,
            "pragmatic_runs",
            "Runs stored.",
            load(&self.runs) as f64,
        );
        counter(
            &mut out,
            "pragmatic_anchor_failures_total",
            "Anchoring batches or witnesses that failed.",
            load(&self.anchor_failures_total),
        );
        counter(
            &mut out,
            "pragmatic_chain_broken_total",
            "Journals found damaged.",
            load(&self.chain_broken_total),
        );
        gauge(
            &mut out,
            "pragmatic_dangling_effects",
            "Runs with an effect left without a result and no lease activity for twice the lease TTL.",
            load(&self.dangling_effects) as f64,
        );
        out.push_str(
            "# HELP pragmatic_tokens_total Token lifecycle events and rejected credentials.\n",
        );
        out.push_str("# TYPE pragmatic_tokens_total counter\n");
        for (kind, v) in [
            ("issued", load(&self.tokens_issued)),
            ("revoked", load(&self.tokens_revoked)),
            ("rejected", load(&self.tokens_rejected)),
        ] {
            let _ = writeln!(out, "pragmatic_tokens_total{{kind=\"{kind}\"}} {v}");
        }
        gauge(
            &mut out,
            "pragmatic_tokens_active",
            "Tokens that are neither revoked nor expired, configured ones included.",
            g.tokens_active as f64,
        );
        gauge(
            &mut out,
            "pragmatic_access_log_lag_seconds",
            "Age of the oldest access-log record not yet durable.",
            g.access_log_lag_seconds,
        );
        gauge(
            &mut out,
            "pragmatic_anchor_lag_seconds",
            "Age of the oldest append not yet in an anchoring batch.",
            g.anchor_lag_seconds,
        );
        out
    }
}

fn counter(out: &mut String, name: &str, help: &str, v: u64) {
    let _ = writeln!(
        out,
        "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}"
    );
}

fn gauge(out: &mut String, name: &str, help: &str, v: f64) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_buckets_are_cumulative() {
        let m = Metrics::default();
        m.observe_append(Duration::from_micros(500));
        m.observe_append(Duration::from_millis(3));
        m.observe_append(Duration::from_secs(10));
        let page = m.render(Gauges::default());
        assert!(page.contains("pragmatic_appends_total 3"));
        assert!(page.contains("pragmatic_append_seconds_bucket{le=\"0.001\"} 1"));
        assert!(page.contains("pragmatic_append_seconds_bucket{le=\"0.005\"} 2"));
        assert!(page.contains("pragmatic_append_seconds_bucket{le=\"+Inf\"} 3"));
        assert!(page.contains("pragmatic_append_seconds_count 3"));
    }

    #[test]
    fn every_design_metric_is_present() {
        let m = Metrics::default();
        m.add_runs(3);
        m.add_runs(-1);
        m.token_rejected();
        let page = m.render(Gauges::default());
        for name in [
            "pragmatic_appends_total",
            "pragmatic_append_seconds",
            "pragmatic_runs 2",
            "pragmatic_anchor_failures_total",
            "pragmatic_chain_broken_total",
            "pragmatic_dangling_effects",
            "pragmatic_tokens_total{kind=\"rejected\"} 1",
            "pragmatic_access_log_lag_seconds",
        ] {
            assert!(page.contains(name), "{name}");
        }
    }
}
