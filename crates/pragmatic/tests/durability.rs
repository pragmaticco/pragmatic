//! The durability protocol and the storage boundary (spec 3.1 to 3.4):
//! results released only after persist, sticky persist failure,
//! `EffectUnrecorded`, `DanglingIntent`, locks and snapshots, format 1 read
//! only, erased content never replayed, random draws, notes, and a runtime
//! shared across threads.

mod common;

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use common::{note_kinds, FlakyBackend, TempDir};
use pragmatic::journal::{note, EraseSelector, ErasureNote, ROOT};
use pragmatic::{
    CountingOracle, Ctx, DirBackend, DrawStart, Event, Fault, Mode, Oracle, RunOptions, Runtime,
    SeededOracle, Value,
};

fn three_steps(ctx: &mut Ctx) -> Result<Value, Fault> {
    let a = ctx.oracle("a")?;
    let b = ctx.oracle(format!("b after {a}"))?;
    let t = ctx.now()?;
    Ok(Value::from(format!("{b}@{t}")))
}

#[test]
fn a_persist_failure_is_sticky() {
    let backend = FlakyBackend::new();
    let rt = Runtime::with_backend(
        Box::new(backend.clone()),
        CountingOracle::new(SeededOracle::new(1)),
    );
    // One persist for the opening notes, two for the first draw: the second
    // draw's intent cannot be persisted.
    backend.fail_after(3);
    let seen = Rc::new(Cell::new(0));
    let agent = {
        let seen = seen.clone();
        move |ctx: &mut Ctx| -> Result<Value, Fault> {
            ctx.oracle("a")?;
            let first = ctx.oracle("b").unwrap_err();
            // Every later primitive, on every branch, fails the same way
            // without touching the journal.
            assert_eq!(ctx.now().unwrap_err(), first);
            assert_eq!(ctx.recv("inbox").unwrap_err(), first);
            assert_eq!(ctx.parallel(2, |_, c| c.now()).unwrap_err(), first);
            seen.set(seen.get() + 1);
            Ok(Value::from("returned ok anyway"))
        }
    };
    let err = rt.run("sticky", agent).unwrap_err();
    assert!(
        matches!(&err, Fault::Io(m) if m.contains("disk full")),
        "{err:?}"
    );
    assert_eq!(seen.get(), 1);
    // The model was never called for the draw whose intent was not durable.
    assert_eq!(rt.oracle().calls(), 1);
    // Durable state: the opening notes and the first draw. No attempt.end.
    let journal = rt.snapshot("sticky").unwrap();
    assert_eq!(journal.program_entries().len(), 2);
    assert!(!note_kinds(&journal).contains(&note::ATTEMPT_END.to_string()));

    // The lock was released; the next attempt starts from durable state.
    backend.fail_after(-1);
    let report = rt.resume("sticky", three_steps).unwrap();
    assert_eq!(report.fresh_steps, 1);
    assert!(rt.verify("sticky").unwrap().is_ok());
}

#[test]
fn an_effect_whose_result_cannot_be_recorded_returns_it() {
    let backend = FlakyBackend::new();
    let rt = Runtime::with_backend(Box::new(backend.clone()), SeededOracle::new(2));
    let performed = Rc::new(Cell::new(0));
    let agent = |performed: Rc<Cell<u32>>| {
        move |ctx: &mut Ctx| -> Result<Value, Fault> {
            let performed = performed.clone();
            ctx.effect("transfer", "10 EUR to savings", move |_| {
                performed.set(performed.get() + 1);
                Ok(Value::from("confirmation 77"))
            })
        }
    };
    // Opening notes and the intent persist; the result does not.
    backend.fail_after(2);
    let err = rt.run("unrecorded", agent(performed.clone())).unwrap_err();
    let Fault::EffectUnrecorded {
        name,
        intent,
        result,
    } = &err
    else {
        panic!("{err:?}")
    };
    assert_eq!(name, "transfer");
    assert_eq!(result.as_str(), "confirmation 77");
    assert_eq!(performed.get(), 1);
    // The fault never prints the result itself.
    assert!(!format!("{err} {err:?}").contains("confirmation 77"));

    // The caller logged the result, so recovery can commit it instead of
    // transferring twice.
    backend.fail_after(-1);
    let logged = result.clone();
    let intent = *intent;
    let report = rt
        .resume_with(
            "unrecorded",
            RunOptions::default(),
            move |n, _| {
                assert_eq!(n, "transfer");
                pragmatic::Recover::Commit(logged.clone())
            },
            agent(performed.clone()),
        )
        .unwrap();
    assert_eq!(report.output.as_str(), "confirmation 77");
    assert_eq!(performed.get(), 1);
    let journal = rt.snapshot("unrecorded").unwrap();
    assert!(journal.entries().iter().any(|e| matches!(
        e.event,
        Event::EffectResult { intent: i, .. } if i == intent
    )));
}

#[test]
fn returning_with_an_open_intent_is_dangling() {
    let rt = Runtime::in_memory(SeededOracle::new(3));
    let mut attempt = rt.begin("open", Mode::Run, RunOptions::default()).unwrap();
    let DrawStart::Fresh(intent) = attempt
        .session()
        .draw_begin(&ROOT.to_vec(), "split-phase", vec![Value::from("q")])
        .unwrap()
    else {
        panic!("fresh run")
    };
    // The intent is durable before the call would be made.
    assert!(attempt.session().unpersisted().is_none());
    assert_eq!(
        attempt.finish(Ok(Value::from("done"))).unwrap_err(),
        Fault::DanglingIntent { cursor: intent }
    );
    let journal = rt.snapshot("open").unwrap();
    let end = journal.entries().last().unwrap();
    let Event::Note {
        kind,
        data,
        payload,
    } = &end.event
    else {
        panic!()
    };
    assert_eq!(kind, note::ATTEMPT_END);
    assert!(data.contains("\"fault_kind\":\"DanglingIntent\""), "{data}");
    assert!(
        data.contains(&format!("\"fault_cursor\":{intent}")),
        "{data}"
    );
    assert_eq!(payload.len(), 2);
}

#[test]
fn attempt_end_records_the_outcome() {
    let rt = Runtime::in_memory(SeededOracle::new(4));
    rt.run("ok", three_steps).unwrap();
    let journal = rt.snapshot("ok").unwrap();
    let Event::Note { data, payload, .. } = &journal.entries().last().unwrap().event else {
        panic!()
    };
    assert!(
        data.contains("\"outcome\":\"ok\"") && data.contains("\"fresh\":2"),
        "{data}"
    );
    assert_eq!(payload.len(), 1);
    let report = rt.replay("ok", three_steps).unwrap();
    assert_eq!(payload[0].value(), Some(&report.output));

    rt.run("bad", |ctx: &mut Ctx| {
        ctx.contract(false, "no").map(|_| Value::default())
    })
    .unwrap_err();
    let journal = rt.snapshot("bad").unwrap();
    let Event::Note { data, payload, .. } = &journal.entries().last().unwrap().event else {
        panic!()
    };
    assert!(data.contains("\"fault_kind\":\"ContractViol\""), "{data}");
    assert_eq!(
        payload[1].value().unwrap().as_str(),
        "contract violated: no"
    );
}

#[test]
fn a_live_run_is_locked_but_can_be_replayed() {
    let dir = TempDir::new("locks");
    let rt = Runtime::on_dir(&dir.0, SeededOracle::new(5)).unwrap();
    rt.run("live", three_steps).unwrap();
    let mut attempt = rt
        .begin("live", Mode::Resume, RunOptions::default())
        .unwrap();
    attempt.ctx().oracle("a").unwrap();
    // A second writer is refused, in this process and through another
    // runtime on the same directory.
    let other = Runtime::on_dir(&dir.0, SeededOracle::new(5)).unwrap();
    for rt in [&rt, &other] {
        assert_eq!(
            rt.resume("live", three_steps).unwrap_err(),
            Fault::Locked {
                retry_after_secs: None
            }
        );
    }
    // Auditors replay the durable prefix without a lock.
    let len = rt.snapshot("live").unwrap().len();
    other.replay("live", three_steps).unwrap();
    assert_eq!(rt.snapshot("live").unwrap().len(), len);
    // Dropping the attempt is a crash that releases the lock.
    drop(attempt);
    assert!(rt.resume("live", three_steps).is_ok());
}

#[test]
fn format_1_journals_are_read_only() {
    let dir = TempDir::new("format1");
    let backend = DirBackend::new(&dir.0).unwrap();
    {
        use pragmatic::journal_v1 as v1;
        let mut j = v1::Journal::create(backend.legacy_path("old-run")).unwrap();
        j.append(v1::Event::OracleDraw {
            prompt: "hello".into(),
            outcome: "world".into(),
            provenance: "0.5".into(),
        })
        .unwrap();
        j.sync().unwrap();
    }
    let rt = Runtime::on_dir(&dir.0, SeededOracle::new(6)).unwrap();
    let read_only = Fault::Unsupported(pragmatic::journal::FORMAT1_READ_ONLY.into());
    assert_eq!(rt.run("old-run", three_steps).unwrap_err(), read_only);
    assert_eq!(rt.resume("old-run", three_steps).unwrap_err(), read_only);
    assert_eq!(rt.replay("old-run", three_steps).unwrap_err(), read_only);
    // Verification and listing still work.
    assert!(rt.verify("old-run").unwrap().is_ok());
    assert_eq!(rt.snapshot("old-run").unwrap().format(), 1);
    assert_eq!(rt.runs().unwrap(), vec!["old-run".to_string()]);
}

#[test]
fn erased_content_is_never_a_wildcard() {
    let dir = TempDir::new("erased");
    let rt = Runtime::on_dir(&dir.0, SeededOracle::new(7)).unwrap();
    rt.run("dsar", three_steps).unwrap();
    let journal = rt.snapshot("dsar").unwrap();
    let first_intent = journal
        .program_entries()
        .iter()
        .find(|e| matches!(e.event, Event::DrawIntent { .. }))
        .unwrap()
        .cursor;
    {
        let mut co = rt.backend().checkout("dsar", false, None).unwrap();
        let erased = co
            .erase(
                &EraseSelector::Slots(vec![(first_intent, 0)]),
                &ErasureNote::local("dsar", "subject request"),
            )
            .unwrap();
        assert_eq!(erased, vec![(first_intent, 0)]);
    }
    // The run still verifies, erasure accounted for.
    assert!(rt.verify("dsar").unwrap().is_ok());
    // It can no longer be replayed or resumed.
    for err in [
        rt.replay("dsar", three_steps).unwrap_err(),
        rt.resume("dsar", three_steps).unwrap_err(),
    ] {
        assert_eq!(
            err,
            Fault::Erased {
                cursor: first_intent
            }
        );
    }
}

#[test]
fn random_draws_replay_exactly() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let id = ctx.random("uuid4", "[]")?;
        let x = ctx.random("random", "[]")?;
        let n = ctx.random("randint", "[-3,3]")?;
        let b = ctx.random("bytes", "[16]")?;
        Ok(Value::from(format!("{id} {x} {n} {}", b.len())))
    };
    let rt = Runtime::in_memory(SeededOracle::new(8));
    // Random draws are not subject to the model-call budget.
    let recorded = rt
        .run_with("rand", RunOptions::default().with_budget(0), agent)
        .unwrap();
    let parts: Vec<String> = recorded
        .output
        .as_str()
        .split(' ')
        .map(str::to_string)
        .collect();
    let uuid = &parts[0];
    assert_eq!(uuid.len(), 36);
    assert_eq!(&uuid[14..15], "4", "version 4");
    assert!(
        matches!(&uuid[19..20], "8" | "9" | "a" | "b"),
        "RFC 4122 variant"
    );
    let x: f64 = parts[1].parse().unwrap();
    assert!((0.0..1.0).contains(&x));
    let n: i64 = parts[2].parse().unwrap();
    assert!((-3..=3).contains(&n));
    assert_eq!(parts[3], "16");
    let replayed = rt.replay("rand", agent).unwrap();
    assert_eq!(replayed.output, recorded.output);
    assert_eq!(replayed.trace, recorded.trace);

    // Arguments are part of the match.
    let changed = |ctx: &mut Ctx| -> Result<Value, Fault> { ctx.random("uuid4", "[1]") };
    assert!(matches!(
        rt.replay("rand", changed).unwrap_err(),
        Fault::JournalDesync { .. }
    ));
    for (source, args) in [("dice", "[]"), ("randint", "[5,1]"), ("bytes", "[]")] {
        let err = rt
            .run(&format!("bad-{source}"), |ctx: &mut Ctx| {
                ctx.random(source, args)
            })
            .unwrap_err();
        assert!(matches!(err, Fault::Unsupported(_)), "{source}: {err:?}");
    }
    // Every value of a small range turns up.
    let seen: std::collections::HashSet<String> = (0..64)
        .map(|i| {
            rt.run(&format!("die-{i}"), |ctx: &mut Ctx| {
                ctx.random("randint", "[1,3]")
            })
            .unwrap()
            .output
            .as_str()
            .into_owned()
        })
        .collect();
    assert_eq!(seen.len(), 3);
}

#[test]
fn run_start_records_labels_and_subjects() {
    let rt = Runtime::in_memory(SeededOracle::new(9));
    let opts = RunOptions::default()
        .with_label("team", "support")
        .with_label("env", "prod")
        .with_subjects(["customer-17"]);
    rt.run_with("labelled", opts, three_steps).unwrap();
    let journal = rt.snapshot("labelled").unwrap();
    let Event::Note {
        kind,
        data,
        payload,
    } = &journal.get(0).unwrap().event
    else {
        panic!()
    };
    assert_eq!(kind, note::RUN_START);
    assert!(
        data.contains(r#""labels":{"env":"prod","team":"support"}"#),
        "{data}"
    );
    assert!(data.contains(r#""run_id":"labelled""#) && data.contains(r#""format":2"#));
    assert_eq!(
        payload[0].value().unwrap().as_str(),
        r#"{"subjects":["customer-17"]}"#
    );
    // Labels are structural, so they are checked.
    let bad = RunOptions::default().with_label("Has Spaces", "x");
    assert!(matches!(
        rt.run_with("bad-label", bad, three_steps).unwrap_err(),
        Fault::Unsupported(_)
    ));
    // Run ids are checked too.
    assert!(matches!(
        rt.run("pragmatic:reserved", three_steps).unwrap_err(),
        Fault::Unsupported(_)
    ));
}

/// A stateless oracle, `Sync`, so the runtime is shareable across threads.
struct Echo;

impl Oracle for Echo {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        Ok(Value::from(format!("echo({prompt})")))
    }
}

#[test]
fn one_runtime_drives_many_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Runtime<Echo>>();
    send_sync::<pragmatic::AsyncRuntime<Echo>>();

    let dir = TempDir::new("threads");
    let rt = Arc::new(Runtime::on_dir(&dir.0, Echo).unwrap());
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let rt = rt.clone();
            std::thread::spawn(move || {
                for i in 0..5 {
                    let id = format!("t{t}-{i}");
                    let r = rt.run(&id, three_steps).unwrap();
                    assert_eq!(rt.replay(&id, three_steps).unwrap().output, r.output);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(rt.runs().unwrap().len(), 40);
}
