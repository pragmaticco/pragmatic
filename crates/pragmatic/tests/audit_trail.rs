//! The signed, tamper-evident audit trail: hash-chain integrity, keyed
//! (HMAC) attribution, and supervisor behavior (restart-from-journal,
//! budgets, capabilities, compensation).

use pragmatic::journal_v1::Event;
use pragmatic::{
    CountingOracle, Ctx, Decision, Fault, RunOptions, Runtime, SeededOracle, Supervisor, Value,
};
use std::cell::Cell;
use std::rc::Rc;

fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let a = ctx.oracle("first")?;
    let b = ctx.oracle(format!("second after {a}"))?;
    Ok(b)
}

#[test]
fn chain_verifies_and_flags_tampering() {
    let mut rt = Runtime::in_memory(SeededOracle::new(1));
    rt.run("audit", agent).unwrap();
    assert!(rt.verify("audit").unwrap().is_ok());

    // Forge the first oracle outcome after the fact.
    rt.journal("audit").unwrap().tamper(
        0,
        Event::OracleDraw {
            prompt: "first".into(),
            outcome: "FORGED OUTCOME".into(),
            provenance: "attacker".into(),
        },
    );
    assert_eq!(rt.verify("audit").unwrap(), Err(0));
}

#[test]
fn keyed_journal_is_attributable() {
    let dir = std::env::temp_dir().join(format!("pragmatic-keyed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let head = {
        let mut rt = Runtime::on_dir(&dir, SeededOracle::new(4))
            .unwrap()
            .with_key(b"org-signing-key");
        rt.run("signed", agent).unwrap().chain_head
    };

    // Reopening with the right key verifies; the wrong key does not.
    let mut rt = Runtime::on_dir(&dir, SeededOracle::new(4))
        .unwrap()
        .with_key(b"org-signing-key");
    let report = rt.replay("signed", agent).unwrap();
    assert_eq!(report.chain_head, head);

    let mut wrong = Runtime::on_dir(&dir, SeededOracle::new(4))
        .unwrap()
        .with_key(b"some-other-key");
    assert!(
        wrong.replay("signed", agent).is_err(),
        "a journal keyed under one key must not open under another"
    );

    let _ = std::fs::remove_dir_all(&dir);
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

    let mut rt = Runtime::in_memory(CountingOracle::new(Flaky {
        inner: SeededOracle::new(10),
        calls: Cell::new(0),
    }));
    let mut sup = Supervisor::new().max_restarts(3);
    let report = sup
        .supervise(&mut rt, "flaky-run", RunOptions::default(), agent)
        .unwrap();
    assert!(!report.output.is_empty());
    // Attempt 1: draw#1 ok, draw#2 faults. Attempt 2: draw#1 replayed from
    // the journal (no model call), draw#2 fresh. Total live calls: 3.
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
    let mut rt = Runtime::in_memory(SeededOracle::new(6));
    let err = rt
        .run_with("loopy", RunOptions::default().with_budget(25), runaway)
        .unwrap_err();
    assert_eq!(err, Fault::BudgetExhausted);
    assert_eq!(rt.journal("loopy").unwrap().len(), 25);
}

#[test]
fn effect_capabilities_are_enforced() {
    let sneaky = |ctx: &mut Ctx| -> Result<Value, Fault> {
        ctx.effect("delete_prod_db", "now", |_| Ok("done".into()))
    };
    let mut rt = Runtime::in_memory(SeededOracle::new(6));
    let err = rt
        .run_with(
            "capped",
            RunOptions::default().with_caps(["send_email", "write_report"]),
            sneaky,
        )
        .unwrap_err();
    assert!(matches!(err, Fault::CapabilityDenied(name) if name == "delete_prod_db"));
    // Nothing was journaled for the denied effect - it never got an intent.
    assert_eq!(rt.journal("capped").unwrap().len(), 0);
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

    let undone: Rc<std::cell::RefCell<Vec<String>>> = Rc::new(std::cell::RefCell::new(vec![]));
    let undone_ref = undone.clone();

    let mut rt = Runtime::in_memory(SeededOracle::new(1));
    let mut sup = Supervisor::new()
        .on_fault(|_| Decision::Compensate)
        .compensate_with(move |name, _| undone_ref.borrow_mut().push(name.to_string()));

    let err = sup
        .supervise(&mut rt, "trip", RunOptions::default(), agent)
        .unwrap_err();
    assert!(matches!(err, Fault::ContractViol(_)));
    // Reverse order: hotel undone before flight.
    assert_eq!(*undone.borrow(), vec!["book_hotel", "book_flight"]);
    // Compensations are journaled, so replay never double-undoes.
    let comp_count = rt
        .journal("trip")
        .unwrap()
        .entries()
        .iter()
        .filter(|e| matches!(e.event, Event::EffectCompensated { .. }))
        .count();
    assert_eq!(comp_count, 2);
}

#[test]
fn escalation_wraps_the_fault() {
    let failing = |_: &mut Ctx| -> Result<Value, Fault> { Err(Fault::Timeout) };
    let mut rt = Runtime::in_memory(SeededOracle::new(1));
    let mut sup = Supervisor::new().on_fault(|_| Decision::Escalate);
    let err = sup
        .supervise(&mut rt, "child", RunOptions::default(), failing)
        .unwrap_err();
    assert_eq!(err, Fault::Escalated(Box::new(Fault::Timeout)));
}
