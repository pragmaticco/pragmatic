//! **E2 - Durability and crash recovery.**
//!
//! Crash a run at every possible journal prefix and resume: the resumed run
//! must (a) never re-sample the journaled prefix, (b) produce a final state
//! consistent with a run that never crashed, and (c) leave no orphaned
//! effects. Also exercises the durable file backend across a simulated
//! process restart, torn tails, and recovery of draws and effects left open
//! or failed, at and away from the frontier of their branch (spec 2.12).

mod common;

use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;

use common::{crash_before, keyed, note_kinds, RemoteBackend, TempDir};
use pragmatic::journal::note;
use pragmatic::{
    CountingOracle, Ctx, EffectOutcome, Event, Fault, Mode, Oracle, Recover, RecoverRequest,
    RunOptions, Runtime, SeededOracle, TraceLabel, Value,
};

fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan")?;
    let a = ctx.oracle(format!("step a of {plan}"))?;
    let b = ctx.effect("persist_a", a.as_str().into_owned(), |arg| {
        Ok(Value::from(format!("saved({arg})")))
    })?;
    let c = ctx.oracle(format!("step c after {b}"))?;
    Ok(Value::from(format!("done: {c}")))
}

/// The program entries of a run, as `(kind, branch)`.
fn kinds(rt: &Runtime<impl Oracle>, run: &str) -> Vec<&'static str> {
    rt.snapshot(run)
        .unwrap()
        .program_entries()
        .iter()
        .map(|e| e.event.kind_name())
        .collect()
}

/// Crash at every program-entry prefix length k, resume, and check
/// exactness.
#[test]
fn e2_crash_at_every_prefix_resumes_exactly() {
    let reference_rt = Runtime::in_memory(SeededOracle::new(1234));
    reference_rt.run("ref", agent).unwrap();
    let reference = reference_rt.snapshot("ref").unwrap();
    let program = reference.program_entries();
    assert_eq!(
        kinds(&reference_rt, "ref"),
        [
            "DrawIntent",
            "DrawResult",
            "DrawIntent",
            "DrawResult",
            "EffectIntent",
            "EffectResult",
            "DrawIntent",
            "DrawResult"
        ]
    );

    for k in 0..=program.len() {
        let rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(1234)));
        rt.run("crashy", agent).unwrap();
        let calls_before = rt.oracle().calls();
        let before = rt.snapshot("crashy").unwrap();
        crash_before(rt.backend(), "crashy", k);

        let resumed = rt.resume("crashy", agent).unwrap();

        // (a) The surviving prefix was replayed, not re-sampled: the new
        // model calls are exactly the responses the crash destroyed (a
        // surviving intent whose response was lost is re-issued).
        let lost_responses = program[k.min(program.len())..]
            .iter()
            .filter(|e| matches!(e.event, Event::DrawResult { .. }))
            .count() as u64;
        assert_eq!(
            rt.oracle().calls() - calls_before,
            lost_responses,
            "crash at k={k}: wrong number of fresh model calls"
        );
        assert_eq!(resumed.fresh_steps, lost_responses, "k={k}");

        // (b) The run finished, and the surviving prefix is unchanged.
        assert!(resumed.output.as_str().starts_with("done: "), "k={k}");
        let after = rt.snapshot("crashy").unwrap();
        let (old, new) = (before.program_entries(), after.program_entries());
        for i in 0..k.min(old.len()) {
            assert_eq!(old[i].hash, new[i].hash, "k={k}: entry {i} changed");
        }
        assert!(after.audit().is_ok(), "k={k}");

        // (c) No orphaned effects: every intent has a result.
        let results: HashSet<u64> = after
            .entries()
            .iter()
            .filter_map(|e| match e.event {
                Event::EffectResult { intent, .. } | Event::DrawResult { intent, .. } => {
                    Some(intent)
                }
                _ => None,
            })
            .collect();
        for e in after.entries() {
            if matches!(
                e.event,
                Event::EffectIntent { .. } | Event::DrawIntent { .. }
            ) {
                assert!(
                    results.contains(&e.cursor),
                    "k={k}: intent {} open",
                    e.cursor
                );
            }
        }
    }
}

/// The prefix of the resumed trace equals the recorded prefix: the run
/// continues, it does not restart.
#[test]
fn e2_resume_preserves_recorded_prefix() {
    let rt = Runtime::in_memory(SeededOracle::new(777));
    let full = rt.run("p", agent).unwrap();
    crash_before(rt.backend(), "p", 4);
    let cut = rt.snapshot("p").unwrap().len();
    let resumed = rt.resume("p", agent).unwrap();
    let prefix = |t: &[TraceLabel]| -> Vec<TraceLabel> {
        t.iter()
            .filter(|l| l.cursor().is_some_and(|c| c < cut))
            .cloned()
            .collect()
    };
    assert_eq!(prefix(&full.trace).len(), 2);
    assert_eq!(prefix(&full.trace), prefix(&resumed.trace));
}

/// Durable backend: record to disk, "kill the process" (drop the runtime),
/// reopen, resume. Nothing is re-sampled.
#[test]
fn e2_file_journal_survives_process_restart() {
    let dir = TempDir::new("e2-restart");
    let recorded = {
        let rt = Runtime::on_dir(&dir.0, SeededOracle::new(42)).unwrap();
        rt.run("durable-run", agent).unwrap()
        // rt dropped here: "the process died".
    };

    // New process: same journal dir, fresh oracle state. If resume touched
    // the model the outcomes would differ; they must not.
    let rt2 = Runtime::on_dir(&dir.0, CountingOracle::new(SeededOracle::new(9999))).unwrap();
    let resumed = rt2.resume("durable-run", agent).unwrap();
    assert_eq!(
        rt2.oracle().calls(),
        0,
        "resume of a complete run must not call the model"
    );
    assert_eq!(keyed(&resumed.trace), keyed(&recorded.trace));
    assert_eq!(resumed.output, recorded.output);

    // And a strict audit replay works across the restart too.
    let audit = rt2.replay("durable-run", agent).unwrap();
    assert_eq!(audit.trace, recorded.trace);
    assert_eq!(rt2.runs().unwrap(), vec!["durable-run".to_string()]);
}

/// A torn final frame on disk (crash mid-append) is moved aside and
/// truncated by the next writer, which records it, and the run resumes from
/// the intact prefix.
#[test]
fn e2_torn_tail_is_truncated_on_open() {
    let dir = TempDir::new("e2-torn");
    {
        let rt = Runtime::on_dir(&dir.0, SeededOracle::new(5)).unwrap();
        rt.run("torn", agent).unwrap();
    }
    let backend = pragmatic::DirBackend::new(&dir.0).unwrap();
    let path = backend.journal_path("torn");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() - 7]).unwrap();

    let rt = Runtime::on_dir(&dir.0, SeededOracle::new(5)).unwrap();
    // A reader sees the valid prefix and never writes.
    let report = rt.verify("torn").unwrap();
    assert!(report.is_ok() && report.torn_bytes > 0);
    assert_eq!(std::fs::read(&path).unwrap().len(), bytes.len() - 7);

    let resumed = rt.resume("torn", agent).unwrap();
    assert!(resumed.output.as_str().starts_with("done: "));
    let journal = rt.snapshot("torn").unwrap();
    assert!(note_kinds(&journal).contains(&note::TORN_TAIL.to_string()));
    let start = journal
        .entries()
        .iter()
        .rev()
        .find(|e| e.event.note_kind() == Some(note::ATTEMPT_START))
        .unwrap();
    let Event::Note { data, .. } = &start.event else {
        unreachable!()
    };
    assert!(!data.contains("\"torn_bytes\":0"), "{data}");
    assert!(rt.verify("torn").unwrap().is_ok());
    let moved = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".torn-"));
    assert!(moved, "the torn bytes were not kept");
}

/// The agent of the effect-recovery tests: a draw, then an effect counted
/// by `performed`.
fn charging(performed: Rc<Cell<u32>>) -> impl Fn(&mut Ctx) -> Result<Value, Fault> {
    move |ctx: &mut Ctx| {
        let x = ctx.oracle("draw")?;
        let performed = performed.clone();
        ctx.effect("charge_card", x.as_str().into_owned(), move |arg| {
            performed.set(performed.get() + 1);
            Ok(Value::from(format!("charged({arg})")))
        })
    }
}

/// Crash with the effect's intent durable and its result lost.
fn crash_inside_effect<O: Oracle>(rt: &Runtime<O>, run: &str) {
    let snap = rt.snapshot(run).unwrap();
    let result = snap
        .entries()
        .iter()
        .find(|e| matches!(e.event, Event::EffectResult { .. }))
        .unwrap();
    rt.crash_truncate(run, result.cursor).unwrap();
}

/// A crash inside the effect write-ahead window leaves an intent without a
/// result; resume decides it before re-entering.
#[test]
fn e2_dangling_effect_recovery() {
    // Compensate: the intent is written off; the effect is performed again
    // under a new intent.
    let performed = Rc::new(Cell::new(0));
    let rt = Runtime::in_memory(SeededOracle::new(11));
    rt.run("pay-1", charging(performed.clone())).unwrap();
    crash_inside_effect(&rt, "pay-1");
    let r = rt
        .resume_with(
            "pay-1",
            RunOptions::default(),
            |_, _| Recover::Compensate,
            charging(performed.clone()),
        )
        .unwrap();
    assert!(r.output.as_str().starts_with("charged("));
    assert_eq!(performed.get(), 2);
    let journal = rt.snapshot("pay-1").unwrap();
    let outcomes: Vec<EffectOutcome> = journal
        .entries()
        .iter()
        .filter_map(|e| match e.event {
            Event::EffectResult { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect();
    assert_eq!(outcomes, [EffectOutcome::Compensated, EffectOutcome::Ok]);
    let recovery = journal
        .entries()
        .iter()
        .find(|e| e.event.note_kind() == Some(note::RECOVERY))
        .unwrap();
    let Event::Note { data, .. } = &recovery.event else {
        unreachable!()
    };
    assert!(data.contains("\"decision\":\"compensate\""), "{data}");
    // Strict replay of the recovered run skips the written-off intent.
    let audit = rt.replay("pay-1", charging(performed.clone())).unwrap();
    assert_eq!(audit.output, r.output);
    assert_eq!(performed.get(), 2);

    // Commit: the operator confirmed the charge landed. Resume replays the
    // committed result without charging again.
    let performed = Rc::new(Cell::new(0));
    let rt = Runtime::in_memory(SeededOracle::new(11));
    rt.run("pay-2", charging(performed.clone())).unwrap();
    crash_inside_effect(&rt, "pay-2");
    let r = rt
        .resume_with(
            "pay-2",
            RunOptions::default(),
            |name, _| {
                assert_eq!(name, "charge_card");
                Recover::Commit("charged(confirmed-by-audit)".into())
            },
            charging(performed.clone()),
        )
        .unwrap();
    assert_eq!(r.output.as_str(), "charged(confirmed-by-audit)");
    assert_eq!(performed.get(), 1, "the effect ran on record only");
}

/// Without a decision, an intent without a result is never guessed at.
#[test]
fn e2_dangling_effect_refuses_silent_replay() {
    let performed = Rc::new(Cell::new(0));
    let rt = Runtime::in_memory(SeededOracle::new(3));
    rt.run("r", charging(performed.clone())).unwrap();
    crash_inside_effect(&rt, "r");
    let intent = rt
        .snapshot("r")
        .unwrap()
        .entries()
        .iter()
        .find(|e| matches!(e.event, Event::EffectIntent { .. }))
        .unwrap()
        .cursor;
    // Strict replay: the recorded run ended inside the effect.
    assert_eq!(
        rt.replay("r", charging(performed.clone())).unwrap_err(),
        Fault::ReplayExhausted { cursor: intent }
    );
    // `run` re-enters without recovery: the open intent is a fault.
    assert_eq!(
        rt.run("r", charging(performed.clone())).unwrap_err(),
        Fault::DanglingEffect { cursor: intent }
    );
    assert_eq!(performed.get(), 1);
}

/// A server-backed runtime has no default for an intent without a result.
#[test]
fn e2_remote_backend_requires_a_recovery_policy() {
    let memory = pragmatic::MemoryBackend::new();
    let rt = Runtime::with_backend(
        Box::new(RemoteBackend(memory.clone())),
        SeededOracle::new(4),
    );
    let performed = Rc::new(Cell::new(0));
    rt.run("remote", charging(performed.clone())).unwrap();
    crash_inside_effect(&rt, "remote");
    let err = rt
        .resume("remote", charging(performed.clone()))
        .unwrap_err();
    assert!(matches!(err, Fault::DanglingEffect { .. }), "{err:?}");
    let r = rt
        .resume_with(
            "remote",
            RunOptions::default(),
            |_, _| Recover::Compensate,
            charging(performed.clone()),
        )
        .unwrap();
    assert!(r.output.as_str().starts_with("charged("));
}

/// An effect whose perform fails is recorded as failed; an agent that
/// handled the failure replays identically, without performing again.
#[test]
fn e2_failed_effect_replays_as_a_failure() {
    let attempts = Rc::new(Cell::new(0));
    let agent = {
        let attempts = attempts.clone();
        move |ctx: &mut Ctx| -> Result<Value, Fault> {
            let attempts = attempts.clone();
            let lookup = ctx.effect("lookup", "user 7", move |_| {
                attempts.set(attempts.get() + 1);
                Err(Fault::ToolErr("index offline".into()))
            });
            let fallback = match lookup {
                Ok(v) => v,
                Err(Fault::ToolErr(m)) => Value::from(format!("fallback after: {m}")),
                Err(other) => return Err(other),
            };
            ctx.oracle(format!("answer with {fallback}"))
        }
    };
    let rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(8)));
    let recorded = rt.run("f", agent.clone()).unwrap();
    assert_eq!(attempts.get(), 1);
    let journal = rt.snapshot("f").unwrap();
    assert!(journal.entries().iter().any(|e| matches!(
        &e.event,
        Event::EffectResult { outcome: EffectOutcome::Failed, error_kind, .. } if error_kind == "ToolErr"
    )));

    // Not at the frontier (the agent continued): never retried.
    let resumed = rt.resume("f", agent.clone()).unwrap();
    assert_eq!(attempts.get(), 1);
    assert_eq!(resumed.output, recorded.output);
    let replayed = rt.replay("f", agent).unwrap();
    assert_eq!(replayed.trace, recorded.trace);
    assert_eq!(rt.oracle().calls(), 1);
}

/// The agent of the frontier-failure tests: an effect that fails until
/// `succeed_from` attempts have been made.
fn flaky_tool(
    attempts: Rc<Cell<u32>>,
    succeed_from: u32,
) -> impl Fn(&mut Ctx) -> Result<Value, Fault> {
    move |ctx: &mut Ctx| {
        let attempts = attempts.clone();
        ctx.effect("send", "hello", move |arg| {
            attempts.set(attempts.get() + 1);
            if attempts.get() >= succeed_from {
                Ok(Value::from(format!("sent({arg})")))
            } else {
                Err(Fault::ToolErr("503".into()))
            }
        })
    }
}

/// A failed effect at the frontier of its branch (the attempt failed on it)
/// is retried on resume by default; a policy can let the failure stand or
/// commit a result instead.
#[test]
fn e2_frontier_failed_effect_recovery() {
    // Default: retry.
    let attempts = Rc::new(Cell::new(0));
    let rt = Runtime::in_memory(SeededOracle::new(1));
    assert_eq!(
        rt.run("retry", flaky_tool(attempts.clone(), 2))
            .unwrap_err(),
        Fault::ToolErr("503".into())
    );
    let r = rt.resume("retry", flaky_tool(attempts.clone(), 2)).unwrap();
    assert_eq!(r.output.as_str(), "sent(hello)");
    assert_eq!(attempts.get(), 2);
    let journal = rt.snapshot("retry").unwrap();
    let data: Vec<String> = journal
        .entries()
        .iter()
        .filter_map(|e| match &e.event {
            Event::Note { kind, data, .. } if kind == note::RECOVERY => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(data.len(), 1);
    assert!(data[0].contains("\"decision\":\"retry\""), "{}", data[0]);
    assert_eq!(
        rt.replay("retry", flaky_tool(attempts.clone(), 2))
            .unwrap()
            .output,
        r.output
    );

    // Fail: the failure stands and replays; the effect is not performed.
    let attempts = Rc::new(Cell::new(0));
    let rt = Runtime::in_memory(SeededOracle::new(1));
    rt.run("fail", flaky_tool(attempts.clone(), 99))
        .unwrap_err();
    let mut fail = |req: &RecoverRequest<'_>| {
        assert_eq!(req.failure.map(|f| f.1), Some("503"));
        Recover::Fail
    };
    let mut attempt = rt
        .begin_with("fail", Mode::Resume, RunOptions::default(), &mut fail)
        .unwrap();
    let result = flaky_tool(attempts.clone(), 99)(&mut attempt.ctx());
    assert_eq!(result.clone().unwrap_err(), Fault::ToolErr("503".into()));
    assert!(attempt.finish(result).is_err());
    assert_eq!(attempts.get(), 1);

    // Commit: a result decided by the policy.
    let attempts = Rc::new(Cell::new(0));
    let rt = Runtime::in_memory(SeededOracle::new(1));
    rt.run("commit", flaky_tool(attempts.clone(), 99))
        .unwrap_err();
    let mut commit = |_: &RecoverRequest<'_>| Recover::Commit("sent(by hand)".into());
    let mut attempt = rt
        .begin_with("commit", Mode::Resume, RunOptions::default(), &mut commit)
        .unwrap();
    let result = flaky_tool(attempts.clone(), 99)(&mut attempt.ctx());
    let report = attempt.finish(result).unwrap();
    assert_eq!(report.output.as_str(), "sent(by hand)");
    assert_eq!(attempts.get(), 1);
}

/// An oracle that fails the calls whose numbers (from 1) are listed.
struct FailingOn {
    inner: CountingOracle<SeededOracle>,
    fail: HashSet<u64>,
}

impl Oracle for FailingOn {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        let out = self.inner.call(prompt);
        if self.fail.contains(&self.inner.calls()) {
            return Err(Fault::OracleErr("overloaded".into()));
        }
        out
    }
}

fn failing_on(seed: u64, calls: &[u64]) -> FailingOn {
    FailingOn {
        inner: CountingOracle::new(SeededOracle::new(seed)),
        fail: calls.iter().copied().collect(),
    }
}

fn two_draws(ctx: &mut Ctx) -> Result<Value, Fault> {
    let a = ctx.oracle("first")?;
    let b = ctx.oracle(format!("second after {a}"))?;
    Ok(b)
}

/// A draw whose response was lost is re-issued under the same intent; a
/// failed draw at the frontier is re-issued on resume; a failed draw the
/// agent handled replays as the same failure.
#[test]
fn e2_draw_recovery() {
    // Lost response: the intent survives and is re-issued.
    let rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(2)));
    rt.run("lost", two_draws).unwrap();
    let snap = rt.snapshot("lost").unwrap();
    let intents: Vec<u64> = snap
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::DrawIntent { .. }))
        .map(|e| e.cursor)
        .collect();
    let last_result = snap
        .entries()
        .iter()
        .rev()
        .find(|e| matches!(e.event, Event::DrawResult { .. }))
        .unwrap()
        .cursor;
    rt.crash_truncate("lost", last_result).unwrap();
    let calls = rt.oracle().calls();
    rt.resume("lost", two_draws).unwrap();
    assert_eq!(rt.oracle().calls(), calls + 1);
    let after = rt.snapshot("lost").unwrap();
    let after_intents: Vec<u64> = after
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::DrawIntent { .. }))
        .map(|e| e.cursor)
        .collect();
    assert_eq!(
        after_intents, intents,
        "no new intent: the same one is re-issued"
    );

    // A failed call at the frontier: the attempt failed on it, resume calls
    // the model again for the same intent.
    let rt = Runtime::in_memory(failing_on(2, &[2]));
    assert_eq!(
        rt.run("err", two_draws).unwrap_err(),
        Fault::OracleErr("overloaded".into())
    );
    // Strict replay reproduces the failure without calling the model.
    assert_eq!(
        rt.replay("err", two_draws).unwrap_err(),
        Fault::OracleErr("overloaded".into())
    );
    let report = rt.resume("err", two_draws).unwrap();
    assert_eq!(rt.oracle().inner.calls(), 3);
    assert_eq!(report.fresh_steps, 1);
    let journal = rt.snapshot("err").unwrap();
    let second = journal
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::DrawIntent { .. }))
        .nth(1)
        .unwrap()
        .cursor;
    let results_for_second = journal
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::DrawResult { intent, .. } if intent == second))
        .count();
    assert_eq!(
        results_for_second, 2,
        "the retry is a new result for the same intent"
    );
    assert_eq!(rt.replay("err", two_draws).unwrap().output, report.output);

    // A failure the agent handled is not at the frontier: replayed, never
    // retried.
    let tolerant = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let a = ctx
            .oracle("first")
            .or_else(|_| Ok::<_, Fault>(Value::from("fallback")))?;
        ctx.oracle(format!("second after {a}"))
    };
    let rt = Runtime::in_memory(failing_on(2, &[1]));
    let recorded = rt.run("handled", tolerant).unwrap();
    assert!(!recorded.output.is_empty());
    let resumed = rt.resume("handled", tolerant).unwrap();
    assert_eq!(rt.oracle().inner.calls(), 2);
    assert_eq!(resumed.output, recorded.output);
}

/// `perform` gets an idempotency key that names the intent; a resumed run
/// performing a written-off effect again gets the new intent's key.
#[test]
fn e2_idempotency_keys() {
    let keys = Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
    let agent = {
        let keys = keys.clone();
        move |ctx: &mut Ctx| -> Result<Value, Fault> {
            let k = keys.clone();
            ctx.effect_keyed("pay", "1 EUR", move |_, key| {
                k.borrow_mut().push(key.to_string());
                Ok(Value::from("paid"))
            })?;
            let k = keys.clone();
            let child = ctx.parallel(2, move |i, c| {
                let k = k.clone();
                c.effect_keyed("child", format!("{i}"), move |_, key| {
                    k.borrow_mut().push(key.to_string());
                    Ok(Value::from("ok"))
                })
            })?;
            Ok(Value::from(format!("{}", child.len())))
        }
    };
    let rt = Runtime::in_memory(SeededOracle::new(1));
    rt.run("keys-1", agent.clone()).unwrap();
    let journal = rt.snapshot("keys-1").unwrap();
    let intents: Vec<(Vec<u32>, u64)> = journal
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::EffectIntent { .. }))
        .map(|e| (e.branch.clone(), e.cursor))
        .collect();
    let expected: Vec<String> = intents
        .iter()
        .map(|(b, c)| {
            let b: Vec<String> = b.iter().map(u32::to_string).collect();
            format!("keys-1/{}/{c}", b.join("."))
        })
        .collect();
    assert_eq!(*keys.borrow(), expected);
    assert!(expected[0].starts_with("keys-1//"));
    assert!(expected[1].starts_with("keys-1/0/"));
}

/// Changed agent code under a recorded run is detected, not misreplayed,
/// and the fault text never contains content.
#[test]
fn e2_desync_detected_when_code_changes() {
    let v1 = |ctx: &mut Ctx| -> Result<Value, Fault> { ctx.oracle("prompt v1 SECRET-A") };
    let v2 = |ctx: &mut Ctx| -> Result<Value, Fault> { ctx.oracle("prompt v2 SECRET-B") };
    let rt = Runtime::in_memory(SeededOracle::new(8));
    rt.run("versioned", v1).unwrap();
    let err = rt.replay("versioned", v2).unwrap_err();
    assert!(matches!(err, Fault::JournalDesync { .. }), "{err:?}");
    let text = format!("{err} {err:?}");
    assert!(!text.contains("SECRET"), "{text}");
}

/// Channel receives are journaled and replay exactly ([Rcv-rec]/[Rcv-rep]).
#[test]
fn e2_channel_receives_replay() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let task = ctx.recv("tasks")?;
        let ans = ctx.oracle(format!("solve {task}"))?;
        Ok(ans)
    };
    let rt = Runtime::in_memory(SeededOracle::new(21));
    rt.send("chan-run", "tasks", "summarize the corpus");
    let recorded = rt.run("chan-run", agent).unwrap();
    // Replay: the inbox is empty now; the value must come from the journal.
    let replayed = rt.replay("chan-run", agent).unwrap();
    assert_eq!(recorded.trace, replayed.trace);
    // An empty inbox on record is a timeout, with nothing journaled.
    assert_eq!(rt.run("empty", agent).unwrap_err(), Fault::Timeout);
    assert!(rt.snapshot("empty").unwrap().program_entries().is_empty());
}

/// The journal records exactly what happened, in the order spec 2.11 sets
/// for a recording attempt.
#[test]
fn e2_journal_shapes_and_note_order() {
    let rt = Runtime::in_memory(SeededOracle::new(2));
    rt.run("shapes", agent).unwrap();
    let journal = rt.snapshot("shapes").unwrap();
    assert_eq!(
        note_kinds(&journal),
        [note::RUN_START, note::ATTEMPT_START, note::ATTEMPT_END]
    );
    assert_eq!(journal.run_start_id().as_deref(), Some("shapes"));
    assert_eq!(
        journal.get(0).unwrap().event.note_kind(),
        Some(note::RUN_START)
    );
    assert_eq!(
        journal.entries().last().unwrap().event.note_kind(),
        Some(note::ATTEMPT_END)
    );
    rt.resume("shapes", agent).unwrap();
    let journal = rt.snapshot("shapes").unwrap();
    assert_eq!(
        note_kinds(&journal),
        [
            note::RUN_START,
            note::ATTEMPT_START,
            note::ATTEMPT_END,
            note::ATTEMPT_START,
            note::ATTEMPT_END
        ]
    );
    let second_start = journal
        .entries()
        .iter()
        .filter(|e| e.event.note_kind() == Some(note::ATTEMPT_START))
        .nth(1)
        .unwrap();
    let Event::Note { data, .. } = &second_start.event else {
        unreachable!()
    };
    assert!(
        data.contains("\"attempt\":2") && data.contains("\"mode\":\"resume\""),
        "{data}"
    );
    assert!(journal.audit().is_ok());
}

/// A failure the agent handled is never retried, even when it was the
/// run's last step: the attempt that saw it ended ok.
#[test]
fn e2_handled_failures_at_the_end_of_a_run_are_not_retried() {
    let attempts = Rc::new(Cell::new(0));
    let agent = {
        let attempts = attempts.clone();
        move |ctx: &mut Ctx| -> Result<Value, Fault> {
            let model = ctx
                .oracle("first")
                .unwrap_or_else(|_| Value::from("no model"));
            let attempts = attempts.clone();
            let tool = ctx
                .effect("notify", "done", move |_| {
                    attempts.set(attempts.get() + 1);
                    Err(Fault::ToolErr("mail server down".into()))
                })
                .unwrap_or_else(|e| Value::from(e.to_string()));
            Ok(Value::from(format!("{model} / {tool}")))
        }
    };
    let rt = Runtime::in_memory(failing_on(3, &[1]));
    let recorded = rt.run("handled-end", agent.clone()).unwrap();
    assert_eq!(
        recorded.output.as_str(),
        "no model / tool error: mail server down"
    );
    let resumed = rt.resume("handled-end", agent.clone()).unwrap();
    assert_eq!(resumed.output, recorded.output);
    assert_eq!(
        attempts.get(),
        1,
        "the handled effect failure was performed again"
    );
    assert_eq!(
        rt.oracle().inner.calls(),
        1,
        "the handled model failure was retried"
    );
    assert_eq!(
        rt.replay("handled-end", agent).unwrap().output,
        recorded.output
    );

    // The same for a failed model call that is the run's last step.
    let last_draw = |ctx: &mut Ctx| -> Result<Value, Fault> {
        Ok(ctx
            .oracle("last")
            .unwrap_or_else(|_| Value::from("fallback")))
    };
    let rt = Runtime::in_memory(failing_on(3, &[1]));
    assert_eq!(
        rt.run("draw-end", last_draw).unwrap().output.as_str(),
        "fallback"
    );
    assert_eq!(
        rt.resume("draw-end", last_draw).unwrap().output.as_str(),
        "fallback"
    );
    assert_eq!(
        rt.oracle().inner.calls(),
        1,
        "the handled model failure was retried"
    );
}

/// Intents opened together on one branch (a streamed model call left open
/// while a tool runs) and both left without a result by a crash, with a
/// later step after them: neither is at the frontier. The draw is re-issued
/// under its own intent and the effect is decided by the policy.
#[test]
fn e2_open_intents_away_from_the_frontier() {
    use pragmatic::journal::ROOT;
    use pragmatic::{DrawStart, EffectStart};

    let rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(4)));
    let root = ROOT.to_vec();
    let question = || vec![Value::from("streamed question")];
    let (draw, effect) = {
        let mut attempt = rt.begin("away", Mode::Run, RunOptions::default()).unwrap();
        let s = attempt.session();
        let DrawStart::Fresh(draw) = s.draw_begin(&root, "stream", question()).unwrap() else {
            panic!("fresh run")
        };
        let EffectStart::Fresh { intent, .. } =
            s.effect_begin(&root, "lookup", Value::from("q")).unwrap()
        else {
            panic!("fresh run")
        };
        s.now(&root).unwrap();
        // The process dies here.
        (draw, intent)
    };

    let mut decided = Vec::new();
    let mut policy = |req: &RecoverRequest<'_>| {
        decided.push((req.name.to_string(), req.intent, req.failure.is_some()));
        Recover::Commit(Value::from("looked up before the crash"))
    };
    let mut attempt = rt
        .begin_with("away", Mode::Resume, RunOptions::default(), &mut policy)
        .unwrap();
    let s = attempt.session();
    assert_eq!(
        s.draw_begin(&root, "stream", question()).unwrap(),
        DrawStart::Fresh(draw),
        "re-issued under the recorded intent"
    );
    s.draw_end(
        draw,
        r#"{"outcome":"ok"}"#.into(),
        Value::default(),
        Value::from("answer"),
    )
    .unwrap();
    assert_eq!(
        s.effect_begin(&root, "lookup", Value::from("q")).unwrap(),
        EffectStart::Replayed(Value::from("looked up before the crash"))
    );
    s.now(&root).unwrap();
    attempt.finish(Ok(Value::from("done"))).unwrap();
    assert_eq!(decided, vec![("lookup".to_string(), effect, false)]);
    assert!(rt.verify("away").unwrap().is_ok());
}
