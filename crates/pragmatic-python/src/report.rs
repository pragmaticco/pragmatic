//! The result of an attempt, as Python sees it.

use pyo3::prelude::*;

use pragmatic_rt::TraceLabel;

/// The result of driving one attempt to completion.
#[pyclass(frozen, module = "pragmatic._native")]
pub struct RunReport {
    #[pyo3(get)]
    run_id: String,
    /// The agent's output: its `str` return value, or the canonical JSON of
    /// any other value.
    #[pyo3(get)]
    output: String,
    /// Journal length after this attempt, notes included.
    #[pyo3(get)]
    journal_len: u64,
    /// Steps served from the journal.
    #[pyo3(get)]
    replayed_steps: u64,
    /// Model calls made in this attempt.
    #[pyo3(get)]
    fresh_steps: u64,
    /// Hex head of the tamper-evident hash chain, or None for an empty run.
    #[pyo3(get)]
    chain_head: Option<String>,
    /// The observable trace: (cursor, kind, summary) triples. Identical
    /// between a recorded run and its replay (T1).
    #[pyo3(get)]
    trace: Vec<(u64, String, String)>,
    /// Recorded programs whose hash changed and that this attempt accepted
    /// under `on_code_change="continue"`: `(branch, cursor, from, to)`.
    #[pyo3(get)]
    program_changes: Vec<(Vec<u32>, u64, String, String)>,
}

#[pymethods]
impl RunReport {
    fn __repr__(&self) -> String {
        format!(
            "RunReport(run_id={:?}, journal_len={}, replayed_steps={}, fresh_steps={})",
            self.run_id, self.journal_len, self.replayed_steps, self.fresh_steps
        )
    }
}

fn trace_label(l: &TraceLabel) -> (u64, String, String) {
    match l {
        TraceLabel::Oracle {
            cursor, outcome, ..
        } => (*cursor, "oracle".to_string(), outcome.as_str().into_owned()),
        TraceLabel::Effect {
            cursor,
            name,
            result,
            ..
        } => (
            *cursor,
            "effect".to_string(),
            format!("{name} -> {}", result.as_str()),
        ),
        TraceLabel::Recv {
            cursor,
            channel,
            value,
            ..
        } => (
            *cursor,
            "recv".to_string(),
            format!("{channel} ? {}", value.as_str()),
        ),
        TraceLabel::Clock { cursor, nanos, .. } => {
            (*cursor, "clock".to_string(), nanos.to_string())
        }
        TraceLabel::Random {
            cursor,
            source,
            value,
            ..
        } => (
            *cursor,
            "random".to_string(),
            format!("{source} -> {}", value.as_str()),
        ),
        TraceLabel::Done { output } => (u64::MAX, "done".to_string(), output.as_str().into_owned()),
        other => (
            other.cursor().unwrap_or(u64::MAX),
            "other".to_string(),
            String::new(),
        ),
    }
}

/// The Python report of a core report.
pub fn convert_report(r: pragmatic_rt::RunReport) -> RunReport {
    RunReport {
        trace: r.trace.iter().map(trace_label).collect(),
        program_changes: r
            .program_changes
            .into_iter()
            .map(|c| (c.branch, c.cursor, c.from, c.to))
            .collect(),
        output: r.output.as_str().into_owned(),
        journal_len: r.journal_len,
        replayed_steps: r.replayed_steps,
        fresh_steps: r.fresh_steps,
        chain_head: r.chain_head.map(|h| pragmatic_rt::sha256::hex(&h)),
        run_id: r.run_id,
    }
}
