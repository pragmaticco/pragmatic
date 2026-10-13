//! `#[pragmatic::durable]`: the program's identity is journaled at step
//! zero and verified on every replay - changed code fails loudly instead of
//! misreplaying (assumption A2, enforced).

#![cfg(feature = "macros")]

use pragmatic::journal_v1::Event;
use pragmatic::{Ctx, Fault, Runtime, SeededOracle, Value};

#[pragmatic::durable]
fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the task")?;
    let step = ctx.oracle(format!("execute: {plan}"))?;
    Ok(Value::from(format!("done: {step}")))
}

// Same name, different body - a "deployed new version" of the agent.
mod v2 {
    use super::*;

    #[pragmatic::durable]
    pub fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
        let plan = ctx.oracle("plan the task")?;
        let step = ctx.oracle(format!("execute CAREFULLY: {plan}"))?;
        Ok(Value::from(format!("done: {step}")))
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

#[test]
fn program_identity_is_journaled_first() {
    let mut rt = Runtime::in_memory(SeededOracle::new(1));
    rt.run("r", research).unwrap();
    let entries = rt.journal("r").unwrap().entries().to_vec();
    match &entries[0].event {
        Event::Program { name, hash } => {
            assert_eq!(name, "research");
            assert_eq!(hash.len(), 16);
        }
        other => panic!("first event should be Program, got {other:?}"),
    }
}

#[test]
fn replay_and_resume_verify_program_identity() {
    let mut rt = Runtime::in_memory(SeededOracle::new(2));
    let recorded = rt.run("r", research).unwrap();

    // Same code: replay is exact.
    let replayed = rt.replay("r", research).unwrap();
    assert_eq!(recorded.trace, replayed.trace);

    // Resume of a complete run: everything (marker included) replays.
    let resumed = rt.resume("r", research).unwrap();
    assert_eq!(resumed.output, recorded.output);
    assert_eq!(resumed.fresh_steps, 0);

    // Crash + resume: the marker and surviving draw replay from the journal;
    // only the lost tail is re-sampled (fresh outcome - the model is
    // nondeterministic, and that is fine: it is journaled going forward).
    rt.journal("r").unwrap().truncate(2).unwrap();
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
    let mut rt = Runtime::in_memory(SeededOracle::new(3));
    rt.run("r", research).unwrap();

    // "Deploy v2", then try to replay the old journal under it.
    let err = rt.replay("r", v2::research).unwrap_err();
    match err {
        Fault::JournalDesync { cursor, found, .. } => {
            assert_eq!(cursor, 0, "identity is checked before any step");
            assert!(found.contains("changed since this journal was recorded"));
        }
        other => panic!("expected JournalDesync, got {other}"),
    }
}

#[test]
fn extra_parameters_work() {
    let mut rt = Runtime::in_memory(SeededOracle::new(4));
    let recorded = rt.run("p", |ctx: &mut Ctx| parameterized(ctx, 3)).unwrap();
    let replayed = rt
        .replay("p", |ctx: &mut Ctx| parameterized(ctx, 3))
        .unwrap();
    assert_eq!(recorded.trace, replayed.trace);
}
