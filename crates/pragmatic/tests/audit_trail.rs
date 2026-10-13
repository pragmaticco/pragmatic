//! The tamper-evident audit trail: hash-chain integrity, keyed (HMAC)
//! journals, and supervisor behavior (restart-from-journal, budgets,
//! capabilities, compensation).

mod common;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use common::TempDir;
use pragmatic::journal::note;
use pragmatic::{
    Content, CountingOracle, Ctx, Decision, Event, Fault, RunOptions, Runtime, SeededOracle,
    Supervisor, Value,
};

fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let a = ctx.oracle("first")?;
    let b = ctx.oracle(format!("second after {a}"))?;
    Ok(b)
}

#[test]
fn chain_verifies_and_flags_tampering() {
    let rt = Runtime::in_memory(SeededOracle::new(1));
    rt.run("audit", agent).unwrap();
    assert!(rt.verify("audit").unwrap().is_ok());

    // Forge the first model response after the fact, in memory: the
    // commitment no longer matches the content.
    let mut journal = rt.snapshot("audit").unwrap();
    let first_result = journal
        .entries()
        .iter()
        .find(|e| matches!(e.event, Event::DrawResult { .. }))
        .unwrap()
        .cursor;
    journal.tamper(first_result, |e| {
        if let Event::DrawResult { body, .. } = &mut e.event {
            *body = Content::from("FORGED OUTCOME");
        }
    });
    assert_eq!(journal.verify(), Err(first_result));
    assert_eq!(journal.audit().first_bad, Some(first_result));

    // The same forgery written to storage: the next reader refuses the file
    // as corrupt at that cursor and never truncates it.
    rt.with_journal_mut("audit", |j| {
        j.tamper(first_result, |e| {
            if let Event::DrawResult { body, .. } = &mut e.event {
                *body = Content::from("FORGED OUTCOME");
            }
        })
    })
    .unwrap();
    let err = rt.verify("audit").unwrap_err();
    assert!(
        err.to_string()
            .contains(&format!("corrupt at cursor {first_result}")),
        "{err}"
    );
    assert!(rt.replay("audit", agent).is_err());
}

#[test]
fn keyed_journal_is_attributable() {
    let dir = TempDir::new("keyed");
    let head = {
        let rt = Runtime::on_dir(&dir.0, SeededOracle::new(4))
            .unwrap()
            .with_key(b"org-signing-key");
        rt.run("signed", agent).unwrap().chain_head
    };

    // Reopening with the right key verifies; the wrong key or no key does
    // not.
    let rt = Runtime::on_dir(&dir.0, SeededOracle::new(4))
        .unwrap()
        .with_key(b"org-signing-key");
    let report = rt.replay("signed", agent).unwrap();
    assert_eq!(report.chain_head, head);
    assert!(rt.verify("signed").unwrap().is_ok());

    let wrong = Runtime::on_dir(&dir.0, SeededOracle::new(4))
        .unwrap()
        .with_key(b"some-other-key");
    assert!(
        wrong.replay("signed", agent).is_err(),
        "a journal keyed under one key must not open under another"
    );
    let unkeyed = Runtime::on_dir(&dir.0, SeededOracle::new(4)).unwrap();
    assert!(matches!(
        unkeyed.verify("signed").unwrap_err(),
        Fault::Unsupported(_)
    ));
}

#[test]
fn supervisor_restarts_transient_faults_from_journal() {
    // An oracle that fails its 2nd live call, succeeds otherwise.
    struct Flaky {
        inner: SeededOracle,
        calls: Cell<u32>,
    }
    impl pragmatic::Oracle for Flaky {
        fn call(&self, prompt: &Value) -> Result<Value, Fault> {
            let n = self.calls.get() + 1;
            self.calls.set(n);
            if n == 2 {
                return Err(Fault::OracleErr("rate limited".into()));
            }
            self.inner.call(prompt)
        }
    }

    let rt = Runtime::in_memory(CountingOracle::new(Flaky {
        inner: SeededOracle::new(10),
        calls: Cell::new(0),
    }));
    let mut sup = Supervisor::new().max_restarts(3);
    let report = sup
        .supervise(&rt, "flaky-run", RunOptions::default(), agent)
        .unwrap();
    assert!(!report.output.is_empty());
    // Attempt 1: draw 1 ok, draw 2 fails (recorded as an error). Attempt 2:
    // draw 1 replayed from the journal (no model call), draw 2 re-issued.
    // Total live calls: 3.
    assert_eq!(
        rt.oracle().calls(),
        3,
        "restart must not re-sample the journaled prefix"
    );
}

#[test]
fn budget_capability_bounds_runaway_loops() {
    let runaway = |ctx: &mut Ctx| -> Result<Value, Fault> {
        loop {
            ctx.oracle("keep going")?; // would never halt on its own
        }
    };
    let rt = Runtime::in_memory(SeededOracle::new(6));
    let err = rt
        .run_with("loopy", RunOptions::default().with_budget(25), runaway)
        .unwrap_err();
    assert_eq!(err, Fault::BudgetExhausted);
    let journal = rt.snapshot("loopy").unwrap();
    let draws = journal
        .program_entries()
        .iter()
        .filter(|e| matches!(e.event, Event::DrawIntent { .. }))
        .count();
    assert_eq!(draws, 25);

    // The budget is per run: a resume replays the 25 draws for free and is
    // refused the 26th.
    let err = rt
        .resume_with(
            "loopy",
            RunOptions::default().with_budget(25),
            |_, _| pragmatic::Recover::Compensate,
            runaway,
        )
        .unwrap_err();
    assert_eq!(err, Fault::BudgetExhausted);
}

#[test]
fn effect_capabilities_are_enforced() {
    let sneaky = |ctx: &mut Ctx| -> Result<Value, Fault> {
        ctx.effect("delete_prod_db", "now", |_| Ok("done".into()))
    };
    let rt = Runtime::in_memory(SeededOracle::new(6));
    let err = rt
        .run_with(
            "capped",
            RunOptions::default().with_caps(["send_email", "write_report"]),
            sneaky,
        )
        .unwrap_err();
    assert!(matches!(err, Fault::CapabilityDenied(name) if name == "delete_prod_db"));
    // Nothing was journaled for the denied effect: it never got an intent.
    assert!(rt.snapshot("capped").unwrap().program_entries().is_empty());
}

#[test]
fn supervisor_compensates_committed_effects_in_reverse() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        ctx.effect("book_flight", "SFO->NRT", |a| {
            Ok(format!("booked({a})").into())
        })?;
        ctx.effect("book_hotel", "Shinjuku", |a| {
            Ok(format!("booked({a})").into())
        })?;
        Err(Fault::ContractViol("itinerary over budget".into()))
    };

    let undone: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(vec![]));
    let undone_ref = undone.clone();

    let rt = Runtime::in_memory(SeededOracle::new(1));
    let mut sup = Supervisor::new()
        .on_fault(|_| Decision::Compensate)
        .compensate_with(move |name, _| undone_ref.borrow_mut().push(name.to_string()));

    let err = sup
        .supervise(&rt, "trip", RunOptions::default(), agent)
        .unwrap_err();
    assert!(matches!(err, Fault::ContractViol(_)));
    // Reverse order: hotel undone before flight.
    assert_eq!(*undone.borrow(), vec!["book_hotel", "book_flight"]);
    // Compensations are journaled as recovery notes, so a later saga never
    // undoes twice, and program replay of the run is unchanged.
    let compensations = |rt: &Runtime<SeededOracle>| {
        rt.snapshot("trip")
            .unwrap()
            .entries()
            .iter()
            .filter(|e| e.event.note_kind() == Some(note::RECOVERY))
            .count()
    };
    assert_eq!(compensations(&rt), 2);
    let mut again = Supervisor::new()
        .on_fault(|_| Decision::Compensate)
        .compensate_with(|name, _| panic!("{name} undone twice"));
    again
        .supervise(&rt, "trip", RunOptions::default(), agent)
        .unwrap_err();
    assert_eq!(compensations(&rt), 2);
    assert!(matches!(
        rt.replay("trip", agent).unwrap_err(),
        Fault::ContractViol(_)
    ));
}

#[test]
fn escalation_wraps_the_fault() {
    let failing = |_: &mut Ctx| -> Result<Value, Fault> { Err(Fault::Timeout) };
    let rt = Runtime::in_memory(SeededOracle::new(1));
    let mut sup = Supervisor::new().on_fault(|_| Decision::Escalate);
    let err = sup
        .supervise(&rt, "child", RunOptions::default(), failing)
        .unwrap_err();
    assert_eq!(err, Fault::Escalated(Box::new(Fault::Timeout)));
}

#[test]
fn default_policy_covers_the_storage_faults() {
    use pragmatic::supervisor::default_policy;
    assert_eq!(
        default_policy(&Fault::Unavailable("503".into())),
        Decision::Restart
    );
    for fault in [
        Fault::Erased { cursor: 1 },
        Fault::Locked {
            retry_after_secs: None,
        },
        Fault::Conflict {
            expected: 1,
            actual: 2,
        },
        Fault::Unsupported("x".into()),
        Fault::TooLarge { size: 2, limit: 1 },
        Fault::DanglingIntent { cursor: 1 },
        Fault::DanglingEffect { cursor: 1 },
        Fault::EffectUnrecorded {
            name: "e".into(),
            intent: 1,
            result: Value::from("r"),
        },
        Fault::LeaseLost,
        Fault::Deleted,
    ] {
        assert_eq!(default_policy(&fault), Decision::Stop, "{fault:?}");
    }
}
