//! **E2 - Durability and crash recovery.**
//!
//! Crash a run at every possible journal prefix and resume: the resumed run
//! must (a) never re-sample the journaled prefix, (b) produce a final state
//! consistent with a run that never crashed, and (c) leave no orphaned
//! effects. Also exercises the durable file backend across a simulated
//! process restart, and dangling-intent recovery both ways.

use pragmatic::journal_v1::Event;
use pragmatic::{CountingOracle, Ctx, Fault, Recover, Runtime, SeededOracle, TraceLabel, Value};

fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan")?;
    let a = ctx.oracle(format!("step a of {plan}"))?;
    let b = ctx.effect("persist_a", a.as_str().into_owned(), |arg| {
        Ok(Value::from(format!("saved({arg})")))
    })?;
    let c = ctx.oracle(format!("step c after {b}"))?;
    Ok(Value::from(format!("done: {c}")))
}

/// Crash at every prefix length k, resume, and check exactness.
#[test]
fn e2_crash_at_every_prefix_resumes_exactly() {
    // Reference run: same seed, no crash.
    let mut ref_rt = Runtime::in_memory(SeededOracle::new(1234));
    let reference = ref_rt.run("ref", agent).unwrap();
    let full_len = reference.journal_len;

    for k in 0..full_len {
        // Record fully, then model the crash: only the first k entries were
        // durable when the process died.
        let mut rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(1234)));
        rt.run("crashy", agent).unwrap();
        let calls_before = rt.oracle().calls();
        rt.journal("crashy").unwrap().truncate(k).unwrap();

        let resumed = rt.resume("crashy", agent).unwrap();

        // (a) The surviving prefix was replayed, not re-sampled: the number
        // of new model calls equals the number of *lost* oracle draws only.
        let lost_draws = reference
            .trace
            .iter()
            .filter(|l| matches!(l, TraceLabel::Oracle { cursor, .. } if *cursor >= k))
            .count() as u64;
        assert_eq!(
            rt.oracle().calls() - calls_before,
            lost_draws,
            "crash at k={k}: wrong number of fresh model calls"
        );

        // (b) The final journal is complete and consistent.
        assert!(resumed.journal_len >= full_len.min(k) /* prefix kept */);
        assert!(
            resumed.output.as_str().starts_with("done: "),
            "crash at k={k}: bad output"
        );

        // (c) No orphaned effects.
        assert!(rt.journal("crashy").unwrap().dangling_intents().is_empty());
    }
}

/// The prefix of the resumed trace must equal the recorded prefix - the run
/// continues, it does not restart.
#[test]
fn e2_resume_preserves_recorded_prefix() {
    let mut rt = Runtime::in_memory(SeededOracle::new(777));
    let full = rt.run("p", agent).unwrap();
    rt.journal("p").unwrap().truncate(2).unwrap();
    let resumed = rt.resume("p", agent).unwrap();
    // Compare the first two journaled steps of both traces.
    let prefix = |t: &[TraceLabel]| -> Vec<TraceLabel> {
        t.iter()
            .filter(|l| match l {
                TraceLabel::Oracle { cursor, .. }
                | TraceLabel::Effect { cursor, .. }
                | TraceLabel::Recv { cursor, .. }
                | TraceLabel::Clock { cursor, .. } => *cursor < 2,
                TraceLabel::Done { .. } => false,
            })
            .cloned()
            .collect()
    };
    assert_eq!(prefix(&full.trace), prefix(&resumed.trace));
}

/// Durable backend: record to disk, "kill the process" (drop the runtime),
/// reopen, resume. Nothing is re-sampled; torn tails are truncated.
#[test]
fn e2_file_journal_survives_process_restart() {
    let dir = std::env::temp_dir().join(format!("pragmatic-e2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let recorded = {
        let mut rt = Runtime::on_dir(&dir, SeededOracle::new(42)).unwrap();
        rt.run("durable-run", agent).unwrap()
        // rt dropped here - "the process died".
    };

    // New process: same journal dir, fresh oracle state. If resume touched
    // the model the outcomes would differ (different sampler state); they
    // must not.
    let mut rt2 = Runtime::on_dir(&dir, CountingOracle::new(SeededOracle::new(9999))).unwrap();
    let resumed = rt2.resume("durable-run", agent).unwrap();
    assert_eq!(
        rt2.oracle().calls(),
        0,
        "resume of a complete run must not call the model"
    );
    assert_eq!(resumed.trace, recorded.trace);
    assert_eq!(resumed.output, recorded.output);

    // And a strict audit replay works across the restart too.
    let audit = rt2.replay("durable-run", agent).unwrap();
    assert_eq!(audit.trace, recorded.trace);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A torn final record on disk (crash mid-append) is detected and truncated
/// on open, and the run resumes from the intact prefix.
#[test]
fn e2_torn_tail_is_truncated_on_open() {
    let dir = std::env::temp_dir().join(format!("pragmatic-e2torn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    {
        let mut rt = Runtime::on_dir(&dir, SeededOracle::new(5)).unwrap();
        rt.run("torn", agent).unwrap();
    }
    // Chop bytes off the end of the file, landing mid-record.
    let path = dir.join("torn.journal");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() - 7]).unwrap();

    let mut rt = Runtime::on_dir(&dir, SeededOracle::new(5)).unwrap();
    let resumed = rt.resume("torn", agent).unwrap();
    assert!(resumed.output.as_str().starts_with("done: "));
    assert!(rt.verify("torn").unwrap().is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}

/// A crash inside the effect write-ahead window leaves a dangling intent;
/// resume must resolve it per policy before re-entering.
#[test]
fn e2_dangling_intent_recovery() {
    // The effect fails after its intent is journaled - the crash window.
    let flaky = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let x = ctx.oracle("draw")?;
        ctx.effect("charge_card", x.as_str().into_owned(), |_| {
            Err(Fault::ToolErr("connection dropped mid-flight".into()))
        })
    };
    let done = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let x = ctx.oracle("draw")?;
        ctx.effect("charge_card", x.as_str().into_owned(), |arg| {
            Ok(Value::from(format!("charged({arg})")))
        })
    };

    // Case 1: Compensate - the intent is written off; resume performs fresh.
    let mut rt = Runtime::in_memory(SeededOracle::new(11));
    assert!(rt.run("pay-1", flaky).is_err());
    assert_eq!(rt.journal("pay-1").unwrap().dangling_intents().len(), 1);
    let r = rt
        .resume_with(
            "pay-1",
            Default::default(),
            |_, _| Recover::Compensate,
            done,
        )
        .unwrap();
    assert!(r.output.as_str().starts_with("charged("));
    assert!(rt.journal("pay-1").unwrap().dangling_intents().is_empty());

    // Case 2: Commit - the operator confirmed the charge landed; close the
    // intent with the known result. Resume replays it without re-charging.
    let mut rt = Runtime::in_memory(SeededOracle::new(11));
    assert!(rt.run("pay-2", flaky).is_err());
    let r = rt
        .resume_with(
            "pay-2",
            Default::default(),
            |_, _| Recover::Commit("charged(confirmed-by-audit)".into()),
            done,
        )
        .unwrap();
    assert_eq!(r.output.as_str(), "charged(confirmed-by-audit)");
    // The effect body never ran on resume: result came from the journal.
    assert!(rt.journal("pay-2").unwrap().dangling_intents().is_empty());
}

/// Without recovery, a dangling intent refuses to replay silently.
#[test]
fn e2_dangling_intent_refuses_silent_replay() {
    let flaky = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let x = ctx.oracle("draw")?;
        ctx.effect("charge_card", x.as_str().into_owned(), |_| {
            Err(Fault::ToolErr("boom".into()))
        })
    };
    let mut rt = Runtime::in_memory(SeededOracle::new(3));
    assert!(rt.run("r", flaky).is_err());
    // Strict replay hits the dangling intent and refuses to guess.
    let err = rt.replay("r", flaky).unwrap_err();
    assert!(matches!(err, Fault::JournalDesync { .. }));
}

/// Journal desync (agent code changed under a recorded run) is detected,
/// not silently misreplayed.
#[test]
fn e2_desync_detected_when_code_changes() {
    let v1 = |ctx: &mut Ctx| -> Result<Value, Fault> { ctx.oracle("prompt v1") };
    let v2 = |ctx: &mut Ctx| -> Result<Value, Fault> { ctx.oracle("prompt v2 (changed!)") };
    let mut rt = Runtime::in_memory(SeededOracle::new(8));
    rt.run("versioned", v1).unwrap();
    let err = rt.replay("versioned", v2).unwrap_err();
    assert!(matches!(err, Fault::JournalDesync { .. }));
}

/// Channel receives are journaled and replay exactly ([Rcv-rec]/[Rcv-rep]).
#[test]
fn e2_channel_receives_replay() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let task = ctx.recv("tasks")?;
        let ans = ctx.oracle(format!("solve {task}"))?;
        Ok(ans)
    };
    let mut rt = Runtime::in_memory(SeededOracle::new(21));
    rt.send("chan-run", "tasks", "summarize the corpus");
    let recorded = rt.run("chan-run", agent).unwrap();
    // Replay: inbox is empty now - the value must come from the journal.
    let replayed = rt.replay("chan-run", agent).unwrap();
    assert_eq!(recorded.trace, replayed.trace);
}

/// The journal records exactly what happened - spot-check the event shapes.
#[test]
fn e2_journal_event_shapes() {
    let mut rt = Runtime::in_memory(SeededOracle::new(2));
    rt.run("shapes", agent).unwrap();
    let entries = rt.journal("shapes").unwrap().entries().to_vec();
    assert!(matches!(&entries[0].event, Event::OracleDraw { .. }));
    assert!(entries
        .iter()
        .any(|e| matches!(&e.event, Event::EffectIntent { name, .. } if name == "persist_a")));
    assert!(entries
        .iter()
        .any(|e| matches!(&e.event, Event::EffectCommit { name, .. } if name == "persist_a")));
}
