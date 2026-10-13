//! Regression tests from the adversarial review of the replay and
//! determinism rules (spec 2.7 to 2.12). Each test is a scenario the review
//! found failing; its comment names the defect it guards against.

mod common;

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

use pragmatic::journal::ROOT;
use pragmatic::{
    block_on, AsyncCtx, AsyncRuntime, Content, Ctx, EffectOutcome, EffectStart, Event, Fault, Mode,
    Oracle, RunOptions, Runtime, Value,
};

/// An oracle that answers `answer to <prompt>`, except that it fails the
/// first call for each prompt listed in `fail_once`.
struct FailOnce {
    fail_once: RefCell<HashSet<String>>,
    calls: Cell<u32>,
}

impl FailOnce {
    fn new(prompts: &[&str]) -> FailOnce {
        FailOnce {
            fail_once: RefCell::new(prompts.iter().map(|p| p.to_string()).collect()),
            calls: Cell::new(0),
        }
    }
}

impl Oracle for FailOnce {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        self.calls.set(self.calls.get() + 1);
        let p = prompt.as_str().into_owned();
        if self.fail_once.borrow_mut().remove(&p) {
            return Err(Fault::OracleErr("overloaded".into()));
        }
        Ok(Value::from(format!("answer to {p}")))
    }
}

// ---------------------------------------------------------------------------
// Finding: a failure that a child handled, and whose outcome the parent then
// acted on after the join, is "at the frontier" of the child's branch and is
// retried on resume. The retry changes the child's result, so the parent's
// recorded steps no longer replay: resume fails with JournalDesync, and the
// new result left in the journal breaks every later replay of the run too.
// ---------------------------------------------------------------------------

fn handled_in_child(ctx: &mut Ctx) -> Result<Value, Fault> {
    let parts = ctx.parallel(2, |i, c| {
        if i == 0 {
            // The child handles the failed call and carries on.
            Ok(c.oracle("x").unwrap_or_else(|_| Value::from("fallback")))
        } else {
            c.oracle("y")
        }
    })?;
    // The parent acts on what the children returned.
    let summary = format!("{} | {}", parts[0], parts[1]);
    ctx.effect("send", summary, |a| Ok(Value::from(format!("sent {a}"))))?;
    ctx.oracle("after")
}

#[test]
fn adversarial_handled_child_draw_failure_is_retried_on_resume() {
    let rt = Runtime::in_memory(FailOnce::new(&["x"]));
    {
        // Attempt 1 records the region and the parent's effect, then the
        // process dies before the final draw finishes.
        let mut attempt = rt
            .begin("child-draw", Mode::Run, RunOptions::default())
            .unwrap();
        let mut ctx = attempt.ctx();
        let parts = ctx
            .parallel(2, |i, c| {
                if i == 0 {
                    Ok(c.oracle("x").unwrap_or_else(|_| Value::from("fallback")))
                } else {
                    c.oracle("y")
                }
            })
            .unwrap();
        assert_eq!(parts[0].as_str(), "fallback");
        let summary = format!("{} | {}", parts[0], parts[1]);
        ctx.effect("send", summary, |a| Ok(Value::from(format!("sent {a}"))))
            .unwrap();
        // crash: the attempt is dropped without finish
    }
    // Before any resume, the recorded history replays fine up to the crash.
    let before = rt.replay("child-draw", handled_in_child).unwrap_err();
    assert!(
        matches!(before, Fault::ReplayExhausted { .. }),
        "only the final draw is missing: {before:?}"
    );
    let calls = rt.oracle().calls.get();

    // Resume must replay the child's handled failure ("fallback"), replay the
    // effect, and only make the final call.
    let resumed = rt
        .resume("child-draw", handled_in_child)
        .expect("resume of a run whose child handled a failure");
    assert!(resumed.output.as_str().starts_with("answer to after"));
    assert_eq!(
        rt.oracle().calls.get(),
        calls + 1,
        "resume re-issued the child's handled draw"
    );
    // The recorded history still replays.
    rt.replay("child-draw", handled_in_child).unwrap();
}

fn handled_child_effect(attempts: Rc<Cell<u32>>) -> impl Fn(&mut Ctx) -> Result<Value, Fault> {
    move |ctx: &mut Ctx| {
        let attempts = attempts.clone();
        let parts = ctx.parallel(2, move |i, c| {
            if i == 0 {
                let attempts = attempts.clone();
                Ok(c.effect("charge", "10 EUR", move |_| {
                    attempts.set(attempts.get() + 1);
                    if attempts.get() == 1 {
                        Err(Fault::ToolErr("card declined".into()))
                    } else {
                        Ok(Value::from("charged"))
                    }
                })
                .unwrap_or_else(|_| Value::from("declined")))
            } else {
                c.now().map(|n| Value::from(n.to_string()))
            }
        })?;
        ctx.effect("email", parts[0].as_str().into_owned(), |a| {
            Ok(Value::from(format!("told the customer: {a}")))
        })?;
        ctx.oracle("after")
    }
}

#[test]
fn adversarial_handled_child_effect_failure_is_performed_again_on_resume() {
    let attempts = Rc::new(Cell::new(0));
    let rt = Runtime::in_memory(FailOnce::new(&["after"]));
    // Attempt 1: the charge is declined, the child handles it, the parent
    // emails "declined", and the final draw fails, ending the attempt.
    let err = rt
        .run("child-effect", handled_child_effect(attempts.clone()))
        .unwrap_err();
    assert_eq!(err, Fault::OracleErr("overloaded".into()));
    assert_eq!(attempts.get(), 1);

    // Resume: the agent already told the customer the card was declined.
    // The charge must not be attempted again.
    let resumed = rt.resume("child-effect", handled_child_effect(attempts.clone()));
    assert_eq!(
        attempts.get(),
        1,
        "resume charged the card again after the customer was told it was declined"
    );
    resumed.expect("resume replays the handled decline and the email");
}

// ---------------------------------------------------------------------------
// Finding: the default recovery compensates a dangling effect that is NOT at
// the frontier of its branch. The retry under a new intent can only be
// appended at the end of the branch, but replay continues with the recorded
// start after the written-off intent, so every later resume and replay is a
// JournalDesync. Because the intent now has a result, no policy is ever
// consulted again: the default resume made the run unrecoverable, where a
// Commit policy would have worked before it ran.
// ---------------------------------------------------------------------------

#[test]
fn adversarial_default_recovery_bricks_a_non_frontier_dangling_effect() {
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let root = ROOT.to_vec();
    {
        // Two tool calls in flight on one branch (a framework issuing
        // concurrent calls through one client), then a clock read; the
        // process dies before the second call returns.
        let mut attempt = rt
            .begin("concurrent", Mode::Run, RunOptions::default())
            .unwrap();
        let s = attempt.session();
        let EffectStart::Fresh { intent: a, .. } =
            s.effect_begin(&root, "lookup", Value::from("a")).unwrap()
        else {
            panic!()
        };
        let EffectStart::Fresh { .. } = s.effect_begin(&root, "lookup", Value::from("b")).unwrap()
        else {
            panic!()
        };
        s.effect_end(a, Ok(Value::from("A"))).unwrap();
        s.now(&root).unwrap();
    }
    // The program as the host drives it on every attempt.
    let program = |s: &mut pragmatic::Session| -> Result<Value, Fault> {
        let root = ROOT.to_vec();
        let a = match s.effect_begin(&root, "lookup", Value::from("a"))? {
            EffectStart::Replayed(v) => v,
            EffectStart::Fresh { intent, .. } => {
                s.effect_end(intent, Ok(Value::from("A")))?;
                Value::from("A")
            }
            EffectStart::Failed { message, .. } => return Err(Fault::ToolErr(message)),
        };
        let b = match s.effect_begin(&root, "lookup", Value::from("b"))? {
            EffectStart::Replayed(v) => v,
            EffectStart::Fresh { intent, .. } => {
                s.effect_end(intent, Ok(Value::from("B")))?;
                Value::from("B")
            }
            EffectStart::Failed { message, .. } => return Err(Fault::ToolErr(message)),
        };
        s.now(&root)?;
        Ok(Value::from(format!("{a}{b}")))
    };
    // Default resume (what Runtime::resume and the Supervisor do).
    let mut attempt = rt
        .begin("concurrent", Mode::Resume, RunOptions::default())
        .unwrap();
    let result = program(attempt.session());
    let first = attempt.finish(result);
    // And once more, as a supervisor restart would.
    let mut attempt = rt
        .begin("concurrent", Mode::Resume, RunOptions::default())
        .unwrap();
    let result = program(attempt.session());
    let second = attempt.finish(result);
    // A Commit policy (which works on a fresh copy of this crash, see
    // e2_open_intents_away_from_the_frontier) is never even consulted now.
    let mut consulted = 0;
    let mut commit = |_: &pragmatic::RecoverRequest<'_>| {
        consulted += 1;
        pragmatic::Recover::Commit(Value::from("B"))
    };
    let attempt = rt.begin_with(
        "concurrent",
        Mode::Resume,
        RunOptions::default(),
        &mut commit,
    );
    drop(attempt);
    assert!(
        first.is_ok() || second.is_ok() || consulted > 0,
        "default recovery left the run permanently desynced: {first:?} / {second:?}, \
         and a later policy is consulted {consulted} times"
    );
    // The default resumes appended nothing for the intent: they stopped at
    // it and asked for a decision.
    assert!(
        matches!(first, Err(Fault::DanglingEffect { .. })),
        "{first:?}"
    );
    assert!(
        matches!(second, Err(Fault::DanglingEffect { .. })),
        "{second:?}"
    );
    // The Commit decision was recorded, so the run now completes and
    // replays.
    let mut attempt = rt
        .begin("concurrent", Mode::Resume, RunOptions::default())
        .unwrap();
    let result = program(attempt.session());
    let report = attempt.finish(result).expect("the committed run completes");
    assert_eq!(report.output.as_str(), "AB");
    let mut attempt = rt
        .begin("concurrent", Mode::Replay, RunOptions::default())
        .unwrap();
    let result = program(attempt.session());
    assert_eq!(attempt.finish(result).unwrap().output.as_str(), "AB");
}

/// A policy that answers `Compensate` for an intent away from the frontier
/// (what the Supervisor's restarts do) leaves it undecided rather than
/// writing it off, and is told the intent is not at the frontier.
#[test]
fn adversarial_compensate_never_writes_off_a_non_frontier_effect() {
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let root = ROOT.to_vec();
    {
        let mut attempt = rt.begin("away", Mode::Run, RunOptions::default()).unwrap();
        let s = attempt.session();
        s.effect_begin(&root, "lookup", Value::from("b")).unwrap();
        s.now(&root).unwrap();
    }
    let mut asked = Vec::new();
    let mut compensate = |req: &pragmatic::RecoverRequest<'_>| {
        asked.push(req.at_frontier);
        pragmatic::Recover::Compensate
    };
    let attempt = rt
        .begin_with("away", Mode::Resume, RunOptions::default(), &mut compensate)
        .unwrap();
    drop(attempt);
    assert_eq!(asked, vec![false]);
    let journal = rt.snapshot("away").unwrap();
    assert!(
        !journal
            .entries()
            .iter()
            .any(|e| matches!(e.event, Event::EffectResult { .. })),
        "a non-frontier intent was written off"
    );
}

// ---------------------------------------------------------------------------
// Finding: a result that references an intent of the other kind (an
// EffectResult naming a DrawIntent) was accepted by Journal::append, by
// Journal::parse and by verify(), and then panicked the session on replay
// (`unreachable!`). Anyone who could write an unkeyed journal file could
// crash the auditor that replays it (and abort a C ABI host). The journal
// now refuses to write one, and a stored one is corruption a verifier
// reports and replay faults on.
// ---------------------------------------------------------------------------

#[test]
fn adversarial_mismatched_completion_kind_panics_replay() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> { ctx.oracle("q") };
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    rt.run("mismatch", agent).unwrap();
    let journal = rt.snapshot("mismatch").unwrap();
    let draw = journal
        .entries()
        .iter()
        .find(|e| matches!(e.event, Event::DrawIntent { .. }))
        .unwrap()
        .cursor;
    let forged = Event::EffectResult {
        intent: draw,
        outcome: EffectOutcome::Ok,
        error_kind: String::new(),
        payload: Some(Content::Sealed(Value::from("forged"))),
    };
    let appended = rt
        .with_journal_mut("mismatch", |j| j.append(&[], forged))
        .unwrap();
    assert!(
        matches!(appended, Err(Fault::Unsupported(_))),
        "the journal wrote a result for an intent of the other kind: {appended:?}"
    );
    // The same forgery made in place, without the journal's checks: the
    // draw's own result turned into an effect result.
    let result = journal
        .entries()
        .iter()
        .find(|e| matches!(e.event, Event::DrawResult { .. }))
        .unwrap()
        .cursor;
    rt.with_journal_mut("mismatch", |j| {
        j.tamper(result, |e| {
            e.event = Event::EffectResult {
                intent: draw,
                outcome: EffectOutcome::Ok,
                error_kind: String::new(),
                payload: Some(Content::Sealed(Value::from("forged"))),
            };
            e.slots.truncate(1);
        })
    })
    .unwrap();
    let report = rt.verify("mismatch").unwrap();
    assert_eq!(report.first_bad, Some(result), "{report:?}");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.replay("mismatch", agent)
    }));
    assert!(
        matches!(outcome, Ok(Err(_))),
        "replay of a forged journal panicked or succeeded instead of faulting"
    );
}

// ---------------------------------------------------------------------------
// Finding: a failed draw or effect returns one fault on record and a
// different one on replay. Record hands the agent the oracle's (or
// perform's) own fault; replay returns OracleErr(text) / ToolErr(text). An
// agent that dispatches on the fault (or a Supervisor policy) takes a
// different path on replay: T1 is broken.
// ---------------------------------------------------------------------------

struct Unavailable;

impl Oracle for Unavailable {
    fn call(&self, _: &Value) -> Result<Value, Fault> {
        Err(Fault::Unavailable("model endpoint returned 503".into()))
    }
}

fn degrade_on_unavailable(ctx: &mut Ctx) -> Result<Value, Fault> {
    match ctx.oracle("q") {
        Ok(v) => Ok(v),
        Err(Fault::Unavailable(_)) => Ok(Value::from("degraded")),
        Err(other) => Err(other),
    }
}

#[test]
fn adversarial_failed_draw_replays_as_a_different_fault() {
    let rt = Runtime::in_memory(Unavailable);
    let recorded = rt.run("draw-fault", degrade_on_unavailable).unwrap();
    assert_eq!(recorded.output.as_str(), "degraded");
    let replayed = rt.replay("draw-fault", degrade_on_unavailable);
    assert_eq!(
        replayed.map(|r| r.output),
        Ok(Value::from("degraded")),
        "replay of the same run took a different path"
    );
}

fn slow_tool(ctx: &mut Ctx) -> Result<Value, Fault> {
    match ctx.effect("lookup", "x", |_| Err(Fault::Timeout)) {
        Ok(v) => Ok(v),
        Err(Fault::Timeout) => Ok(Value::from("tool timed out")),
        Err(other) => Err(other),
    }
}

#[test]
fn adversarial_failed_effect_replays_as_a_different_fault() {
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let recorded = rt.run("effect-fault", slow_tool).unwrap();
    assert_eq!(recorded.output.as_str(), "tool timed out");
    let replayed = rt.replay("effect-fault", slow_tool);
    assert_eq!(
        replayed.map(|r| r.output),
        Ok(Value::from("tool timed out")),
        "replay of the same run took a different path"
    );
}

// ---------------------------------------------------------------------------
// Finding: an agent that handles BudgetExhausted (the documented way to stop
// a runaway loop) records a run that strict replay cannot reproduce: the
// budget is not journaled and replay never consults it, so the step that
// raised BudgetExhausted on record raises ReplayExhausted on replay.
// ---------------------------------------------------------------------------

fn until_budget(ctx: &mut Ctx) -> Result<Value, Fault> {
    let mut answers = Vec::new();
    loop {
        match ctx.oracle(format!("step {}", answers.len())) {
            Ok(v) => answers.push(v.as_str().into_owned()),
            Err(Fault::BudgetExhausted) => break,
            Err(other) => return Err(other),
        }
    }
    Ok(Value::from(answers.join(",")))
}

#[test]
fn adversarial_handled_budget_exhaustion_does_not_replay() {
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let recorded = rt
        .run_with("budget", RunOptions::default().with_budget(2), until_budget)
        .unwrap();
    let replayed = rt.replay("budget", until_budget);
    assert_eq!(replayed.map(|r| r.output), Ok(recorded.output));
}

#[test]
fn adversarial_handled_budget_exhaustion_does_not_replay_async() {
    async fn agent(ctx: &mut AsyncCtx<'_, FailOnce>) -> Result<Value, Fault> {
        let parts = ctx
            .parallel(2, |i, mut c| async move {
                let mut n = 0;
                loop {
                    match c.oracle(format!("{i}.{n}")).await {
                        Ok(_) => n += 1,
                        Err(Fault::BudgetExhausted) => return Ok(Value::from(n.to_string())),
                        Err(e) => return Err(e),
                    }
                }
            })
            .await?;
        Ok(Value::from(format!("{} {}", parts[0], parts[1])))
    }
    let rt = AsyncRuntime::in_memory(FailOnce::new(&[]));
    let recorded =
        block_on(rt.run_with("budget-async", RunOptions::default().with_budget(3), agent)).unwrap();
    let replayed = block_on(rt.replay("budget-async", agent));
    assert_eq!(replayed.map(|r| r.output), Ok(recorded.output));
}

// ---------------------------------------------------------------------------
// Finding: a receive on an empty inbox raises Timeout and journals nothing.
// An agent that handles the timeout (wait for an approval, else go on with a
// default) records a run whose next start is whatever followed: replay,
// resume and `run` re-entry all meet that step where the receive expects a
// ChannelRecv, a JournalDesync. The run can never be replayed or resumed.
// ---------------------------------------------------------------------------

fn approval_or_default(ctx: &mut Ctx) -> Result<Value, Fault> {
    let approval = match ctx.recv("approval") {
        Ok(v) => v,
        Err(Fault::Timeout) => Value::from("auto-approved"),
        Err(other) => return Err(other),
    };
    ctx.oracle(format!("proceed: {approval}"))
}

#[test]
fn adversarial_handled_recv_timeout_cannot_be_replayed() {
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let recorded = rt.run("approval", approval_or_default).unwrap();
    assert_eq!(recorded.output.as_str(), "answer to proceed: auto-approved");
    let replayed = rt.replay("approval", approval_or_default);
    assert_eq!(replayed.map(|r| r.output), Ok(recorded.output.clone()));
    // Re-entering the finished run (documented as idempotent) fails too.
    let again = rt.run("approval", approval_or_default);
    assert_eq!(again.map(|r| r.output), Ok(recorded.output));
}

// ---------------------------------------------------------------------------
// Refusals the agent did not handle are not journaled, so the step runs
// again on resume; refusals it handled replay, in children too.
// ---------------------------------------------------------------------------

#[test]
fn adversarial_unhandled_refusals_are_retried_on_resume() {
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let wait = |ctx: &mut Ctx| -> Result<Value, Fault> { ctx.recv("approval") };
    // No message yet: the attempt fails on the receive, and nothing about
    // it is journaled.
    assert_eq!(rt.run("wait", wait).unwrap_err(), Fault::Timeout);
    assert!(rt.snapshot("wait").unwrap().program_entries().is_empty());
    // The message arrives; the resumed run receives it.
    rt.send("wait", "approval", "approved by ops");
    assert_eq!(
        rt.resume("wait", wait).unwrap().output.as_str(),
        "approved by ops"
    );

    // A run stopped by its budget continues once the budget is raised.
    let two = |ctx: &mut Ctx| -> Result<Value, Fault> {
        ctx.oracle("a")?;
        ctx.oracle("b")
    };
    let err = rt
        .run_with("budget", RunOptions::default().with_budget(1), two)
        .unwrap_err();
    assert_eq!(err, Fault::BudgetExhausted);
    let mut attempt = rt
        .begin("budget", Mode::Resume, RunOptions::default().with_budget(2))
        .unwrap();
    let result = two(&mut attempt.ctx());
    assert_eq!(
        attempt.finish(result).unwrap().output.as_str(),
        "answer to b"
    );
}

#[test]
fn adversarial_handled_capability_denial_replays() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let wiped = match ctx.effect("wipe", "prod", |_| Ok(Value::from("wiped"))) {
            Ok(v) => v,
            Err(Fault::CapabilityDenied(name)) => Value::from(format!("not allowed: {name}")),
            Err(other) => return Err(other),
        };
        ctx.oracle(format!("report {wiped}"))
    };
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let recorded = rt
        .run_with("caps", RunOptions::default().with_caps(["read"]), agent)
        .unwrap();
    assert_eq!(
        recorded.output.as_str(),
        "answer to report not allowed: wipe"
    );
    // Replay holds no capability list at all, and still takes the recorded
    // path; so does a re-entry under the same grants.
    assert_eq!(rt.replay("caps", agent).unwrap().output, recorded.output);
    let again = rt
        .run_with("caps", RunOptions::default().with_caps(["read"]), agent)
        .unwrap();
    assert_eq!(again.output, recorded.output);
}

#[test]
fn adversarial_refusal_in_a_child_replays_once_the_parent_carries_on() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let region = ctx.parallel(2, |i, c| {
            if i == 0 {
                c.recv("approval")
            } else {
                c.oracle("side")
            }
        });
        let verdict = match region {
            Ok(parts) => parts[0].clone(),
            Err(Fault::Timeout) => Value::from("no approval"),
            Err(other) => return Err(other),
        };
        ctx.oracle(format!("go: {verdict}"))
    };
    let rt = Runtime::in_memory(FailOnce::new(&[]));
    let recorded = rt.run("child-refusal", agent).unwrap();
    assert_eq!(recorded.output.as_str(), "answer to go: no approval");
    // A message that arrives later does not change the recorded run.
    rt.send("child-refusal", "approval", "late approval");
    assert_eq!(
        rt.replay("child-refusal", agent).unwrap().output,
        recorded.output
    );
    assert_eq!(
        rt.resume("child-refusal", agent).unwrap().output,
        recorded.output
    );
}
