//! `#[pragmatic::durable]`: the program's identity is journaled on the
//! calling branch and checked on every replay; changed code fails loudly
//! instead of misreplaying (assumption A2, enforced), unless the run's
//! code-change policy accepts the change.

#![cfg(feature = "macros")]

mod common;

use common::crash_before;
use pragmatic::{Ctx, Event, Fault, OnCodeChange, RunOptions, Runtime, SeededOracle, Value};

#[pragmatic::durable]
fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the task")?;
    let step = ctx.oracle(format!("execute: {plan}"))?;
    Ok(Value::from(format!("done: {step}")))
}

// Same name, different body: a "deployed new version" of the agent.
mod v2 {
    use super::*;

    #[pragmatic::durable]
    pub fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
        let plan = ctx.oracle("plan the task")?;
        let step = ctx.oracle(format!("execute: {plan}"))?;
        // A harmless edit: a different body, the same steps.
        Ok(Value::from(format!("done: {}", step.as_str())))
    }
}

// Extra parameters after the ctx are fine.
#[pragmatic::durable]
fn parameterized(ctx: &mut Ctx, depth: u32) -> Result<Value, Fault> {
    let mut last = ctx.oracle("start")?;
    for i in 0..depth {
        last = ctx.oracle(format!("refine {i}: {last}"))?;
    }
    Ok(last)
}

// An explicit version names the program instead of its source hash.
#[pragmatic::durable(version = "2")]
fn versioned(ctx: &mut Ctx) -> Result<Value, Fault> {
    ctx.oracle("versioned")
}

mod versioned_edit {
    use super::*;

    #[pragmatic::durable(version = "2")]
    pub fn versioned(ctx: &mut Ctx) -> Result<Value, Fault> {
        // Edited source, same declared version.
        let out = ctx.oracle("versioned")?;
        Ok(out)
    }
}

#[test]
fn program_identity_is_journaled_first() {
    let rt = Runtime::in_memory(SeededOracle::new(1));
    rt.run("r", research).unwrap();
    let journal = rt.snapshot("r").unwrap();
    let entries = journal.program_entries();
    match &entries[0].event {
        Event::Program { name, hash } => {
            assert_eq!(name, "research");
            assert_eq!(hash.len(), 16);
            assert!(entries[0].branch.is_empty(), "on the calling (root) branch");
        }
        other => panic!("first event should be Program, got {other:?}"),
    }
}

#[test]
fn replay_and_resume_check_program_identity() {
    let rt = Runtime::in_memory(SeededOracle::new(2));
    let recorded = rt.run("r", research).unwrap();

    // Same code: replay is exact.
    let replayed = rt.replay("r", research).unwrap();
    assert_eq!(recorded.trace, replayed.trace);

    // Resume of a complete run: everything (marker included) replays.
    let resumed = rt.resume("r", research).unwrap();
    assert_eq!(resumed.output, recorded.output);
    assert_eq!(resumed.fresh_steps, 0);

    // Crash after the first draw: the marker and that draw replay; only
    // the lost draw is sampled again.
    crash_before(rt.backend(), "r", 3);
    let resumed = rt.resume("r", research).unwrap();
    assert_eq!(
        resumed.replayed_steps, 2,
        "program marker + first draw replayed"
    );
    assert_eq!(resumed.fresh_steps, 1, "only the lost draw re-sampled");
    assert!(resumed.output.as_str().starts_with("done: "));
}

#[test]
fn changed_code_refuses_to_replay() {
    let rt = Runtime::in_memory(SeededOracle::new(3));
    rt.run("r", research).unwrap();

    // "Deploy v2", then try to replay the old journal under it.
    let err = rt.replay("r", v2::research).unwrap_err();
    let program = rt.snapshot("r").unwrap().program_entries()[0].cursor;
    match err {
        Fault::JournalDesync { cursor, found, .. } => {
            assert_eq!(cursor, program, "identity is checked before any step");
            assert!(found.contains("on_code_change='continue'"), "{found}");
        }
        other => panic!("expected JournalDesync, got {other}"),
    }

    // Accepting the change for this replay works, and is reported.
    let report = rt
        .replay_with(
            "r",
            RunOptions::default().with_on_code_change(OnCodeChange::Continue),
            v2::research,
        )
        .unwrap();
    assert_eq!(report.program_changes.len(), 1);
    assert_eq!(report.program_changes[0].cursor, program);
}

#[test]
fn extra_parameters_work() {
    let rt = Runtime::in_memory(SeededOracle::new(4));
    let recorded = rt.run("p", |ctx: &mut Ctx| parameterized(ctx, 3)).unwrap();
    let replayed = rt
        .replay("p", |ctx: &mut Ctx| parameterized(ctx, 3))
        .unwrap();
    assert_eq!(recorded.trace, replayed.trace);
}

#[test]
fn explicit_version_survives_source_edits() {
    let rt = Runtime::in_memory(SeededOracle::new(5));
    let recorded = rt.run("v", versioned).unwrap();
    let journal = rt.snapshot("v").unwrap();
    assert!(matches!(
        &journal.program_entries()[0].event,
        Event::Program { name, hash } if name == "versioned" && hash == "2"
    ));
    let replayed = rt.replay("v", versioned_edit::versioned).unwrap();
    assert_eq!(replayed.output, recorded.output);
    assert!(replayed.program_changes.is_empty());
}

#[test]
fn markers_land_on_the_branch_that_calls() {
    #[pragmatic::durable]
    fn child(ctx: &mut Ctx, i: u32) -> Result<Value, Fault> {
        ctx.oracle(format!("child {i}"))
    }
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let parts = ctx.parallel(2, |i, c| child(c, i))?;
        Ok(Value::from(parts.len().to_string()))
    };
    let rt = Runtime::in_memory(SeededOracle::new(6));
    rt.run("b", agent).unwrap();
    let journal = rt.snapshot("b").unwrap();
    let programs: Vec<Vec<u32>> = journal
        .program_entries()
        .iter()
        .filter(|e| matches!(e.event, Event::Program { .. }))
        .map(|e| e.branch.clone())
        .collect();
    assert_eq!(programs, vec![vec![0], vec![1]]);
    rt.replay("b", agent).unwrap();
}
