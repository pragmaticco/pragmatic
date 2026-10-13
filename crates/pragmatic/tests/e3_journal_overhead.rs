//! **E3 - Journaling overhead.**
//!
//! (a) Journal append is O(1): mean append latency at 1k entries and at 1M
//!     entries must be within a small constant factor (flat, no growth with
//!     log length).
//! (b) Replay speedup: replaying a run performs zero oracle calls, so under
//!     a latency-injected oracle replay is orders of magnitude faster than
//!     recording.
//!
//! Each appended entry is a format 2 `DrawResult`: two content slots, each
//! salted from the operating system's CSPRNG and committed with SHA-256,
//! then chained. Run with `--release` for the headline numbers (the long
//! log is 1M entries there; unoptimized SHA-256 is slow enough that debug
//! builds measure flatness at 100k). The assertions are deliberately loose
//! so the suite stays green under debug builds and CI noise: E3 asserts
//! *shape* (flatness, speedup), not absolute nanoseconds.

use std::time::{Duration, Instant};

use pragmatic::journal::ROOT;
use pragmatic::{Content, Ctx, Event, Fault, Journal, Oracle, Runtime, Value};

fn result_event(i: u64) -> Event {
    Event::DrawResult {
        intent: i,
        meta: r#"{"outcome":"ok"}"#.to_string(),
        head: Content::from(format!("head-{i}")),
        body: Content::from(format!("outcome-{i}")),
    }
}

/// Mean in-memory append latency over `n` appends starting from an empty
/// log. Frames are marked persisted every 4096 appends, as a sink would,
/// so the pending buffer stays bounded.
fn mean_append_nanos(n: u64) -> f64 {
    let mut j = Journal::new(None);
    // Build events up front so the measurement isolates the append path
    // itself (salt, commitments, encode, chain hash, push), not `format!`.
    let events: Vec<Event> = (0..n).map(result_event).collect();
    let start = Instant::now();
    for (i, ev) in events.into_iter().enumerate() {
        j.append(ROOT, ev).unwrap();
        if i % 4096 == 4095 {
            j.mark_persisted(j.len());
        }
    }
    let total = start.elapsed();
    assert_eq!(j.len(), n);
    total.as_nanos() as f64 / n as f64
}

/// The long log: 1M entries in release builds, 100k in debug builds.
const LONG: u64 = if cfg!(debug_assertions) {
    100_000
} else {
    1_000_000
};

#[test]
fn e3_append_latency_flat_to_one_million() {
    let at_1k = mean_append_nanos(1_000);
    let at_1m = mean_append_nanos(LONG);
    println!("mean append: {at_1k:.0} ns @ 1k entries, {at_1m:.0} ns @ {LONG} entries");
    // O(1) claim: the per-append cost at 1M entries is within 8x of the cost
    // at 1k (in practice it's ~1x; the slack absorbs allocator effects and
    // debug-build noise).
    assert!(
        at_1m < at_1k * 8.0,
        "append latency grew with journal length: {at_1k:.0} ns @1k vs {at_1m:.0} ns @1M"
    );
}

/// An oracle with injected latency, standing in for a real model call.
struct SlowOracle {
    delay: Duration,
}

impl Oracle for SlowOracle {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        std::thread::sleep(self.delay);
        Ok(Value::from(format!("echo({prompt})")))
    }
    fn provenance(&self) -> String {
        "slow-oracle".to_string()
    }
}

#[test]
fn e3_replay_speedup_under_latency_injected_oracle() {
    const STEPS: usize = 40;
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let mut last = Value::from("start");
        for i in 0..STEPS {
            last = ctx.oracle(format!("step {i}: {last}"))?;
        }
        Ok(last)
    };

    let rt = Runtime::in_memory(SlowOracle {
        delay: Duration::from_millis(5),
    });

    let t0 = Instant::now();
    let recorded = rt.run("speed", agent).unwrap();
    let record_time = t0.elapsed();

    let t1 = Instant::now();
    let replayed = rt.replay("speed", agent).unwrap();
    let replay_time = t1.elapsed();

    assert_eq!(recorded.trace, replayed.trace);
    let speedup = record_time.as_secs_f64() / replay_time.as_secs_f64().max(1e-9);
    println!("record: {record_time:?}, replay: {replay_time:?}, speedup: {speedup:.0}x");
    // Record pays STEPS × 5 ms of model latency (real calls take hundreds
    // of milliseconds); replay pays none. Even with generous slack this
    // must be a large multiple.
    assert!(
        speedup > 50.0,
        "replay should be dramatically faster than record; got {speedup:.1}x"
    );
}
