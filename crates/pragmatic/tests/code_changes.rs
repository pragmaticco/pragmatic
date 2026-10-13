//! Changing agent code under recorded runs: patch markers (`patched`,
//! `deprecate_patch`, spec 2.9) and program identity under both
//! `on_code_change` policies (spec 2.10), including a run resumed under a
//! changed program and then audit-replayed.

mod common;

use common::{crash_before, note_kinds};
use pragmatic::journal::note;
use pragmatic::{Ctx, Event, Fault, Mode, OnCodeChange, RunOptions, Runtime, SeededOracle, Value};

fn old_code(ctx: &mut Ctx) -> Result<Value, Fault> {
    let a = ctx.oracle("a")?;
    let b = ctx.oracle(format!("b after {a}"))?;
    Ok(b)
}

fn patched_code(ctx: &mut Ctx) -> Result<Value, Fault> {
    let a = if ctx.patched("better-a")? {
        ctx.oracle("a, but better")?
    } else {
        ctx.oracle("a")?
    };
    let b = ctx.oracle(format!("b after {a}"))?;
    Ok(b)
}

fn deprecated_code(ctx: &mut Ctx) -> Result<Value, Fault> {
    ctx.deprecate_patch("better-a")?;
    let a = ctx.oracle("a, but better")?;
    let b = ctx.oracle(format!("b after {a}"))?;
    Ok(b)
}

fn markers(rt: &Runtime<SeededOracle>, run: &str) -> Vec<String> {
    rt.snapshot(run)
        .unwrap()
        .program_entries()
        .iter()
        .filter_map(|e| match &e.event {
            Event::Marker { name } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn patched_keeps_old_runs_on_the_old_path() {
    let rt = Runtime::in_memory(SeededOracle::new(1));
    let old = rt.run("old", old_code).unwrap();
    // A run recorded before the patch replays and resumes under the patched
    // code: `patched` is false and consumes nothing.
    assert_eq!(rt.replay("old", patched_code).unwrap().output, old.output);
    assert_eq!(rt.resume("old", patched_code).unwrap().output, old.output);
    assert!(markers(&rt, "old").is_empty());

    // Crash an old run part way; it resumes on the old path and the rest is
    // recorded as the old code would have.
    crash_before(rt.backend(), "old", 2);
    rt.resume("old", patched_code).unwrap();
    assert!(markers(&rt, "old").is_empty());
    assert!(rt.replay("old", old_code).is_ok());
}

#[test]
fn new_runs_take_the_patch_and_record_it() {
    let rt = Runtime::in_memory(SeededOracle::new(2));
    let new = rt.run("new", patched_code).unwrap();
    assert_eq!(markers(&rt, "new"), ["better-a"]);
    assert_eq!(rt.replay("new", patched_code).unwrap().output, new.output);

    // Code without the patch meets the marker and says why it cannot go on.
    match rt.replay("new", old_code).unwrap_err() {
        Fault::JournalDesync { found, .. } => {
            assert!(found.contains("this run took patch 'better-a'"), "{found}")
        }
        other => panic!("{other:?}"),
    }

    // Once no unpatched run can resume, deprecate_patch consumes the marker
    // and never writes one.
    assert_eq!(
        rt.replay("new", deprecated_code).unwrap().output,
        new.output
    );
    rt.run("fresh", deprecated_code).unwrap();
    assert!(markers(&rt, "fresh").is_empty());
    // A run without the marker is unaffected by deprecate_patch itself.
    assert!(rt.replay("fresh", deprecated_code).is_ok());
}

#[test]
fn patched_past_the_end_of_a_strict_replay_is_exhausted() {
    let rt = Runtime::in_memory(SeededOracle::new(3));
    rt.run("short", |ctx: &mut Ctx| ctx.oracle("only")).unwrap();
    let err = rt
        .replay("short", |ctx: &mut Ctx| {
            ctx.oracle("only")?;
            ctx.patched("later")?;
            Ok(Value::from("x"))
        })
        .unwrap_err();
    assert!(matches!(err, Fault::ReplayExhausted { .. }), "{err:?}");
}

fn program(name: &'static str, hash: &'static str) -> impl Fn(&mut Ctx) -> Result<Value, Fault> {
    move |ctx: &mut Ctx| {
        ctx.program_marker(name, hash)?;
        let a = ctx.oracle("a")?;
        let b = ctx.oracle(format!("b after {a}"))?;
        Ok(b)
    }
}

/// `program.change` notes of a journal: `(cursor of the note, data)`.
fn changes(rt: &Runtime<SeededOracle>, run: &str) -> Vec<(u64, String)> {
    rt.snapshot(run)
        .unwrap()
        .entries()
        .iter()
        .filter_map(|e| match &e.event {
            Event::Note { kind, data, .. } if kind == note::PROGRAM_CHANGE => {
                Some((e.cursor, data.clone()))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn refuse_rejects_a_changed_hash_and_continue_records_it() {
    let rt = Runtime::in_memory(SeededOracle::new(4));
    let v1 = rt.run("p", program("agent", "h1")).unwrap();
    let program_cursor = rt.snapshot("p").unwrap().program_entries()[0].cursor;

    // Refuse (the replay default, or explicit on resume).
    assert!(matches!(
        rt.replay("p", program("agent", "h2")).unwrap_err(),
        Fault::JournalDesync { cursor, .. } if cursor == program_cursor
    ));
    let refuse = RunOptions::default().with_on_code_change(OnCodeChange::Refuse);
    assert!(rt
        .resume_with("p", refuse, |_, _| unreachable!(), program("agent", "h2"))
        .is_err());
    assert!(changes(&rt, "p").is_empty());

    // Continue (the resume default): the change is recorded once, before
    // any fresh step, and reported.
    let resumed = rt.resume("p", program("agent", "h2")).unwrap();
    assert_eq!(resumed.output, v1.output);
    assert_eq!(resumed.program_changes.len(), 1);
    let change = &resumed.program_changes[0];
    assert_eq!(
        (change.cursor, change.from.as_str(), change.to.as_str()),
        (program_cursor, "h1", "h2")
    );
    let notes = changes(&rt, "p");
    assert_eq!(notes.len(), 1);
    assert_eq!(
        notes[0].1,
        format!(r#"{{"branch":[],"cursor":{program_cursor},"from":"h1","to":"h2"}}"#)
    );
    // Accepted from now on, under either policy, without another note.
    rt.resume("p", program("agent", "h2")).unwrap();
    assert_eq!(changes(&rt, "p").len(), 1);
    let audit = rt.replay("p", program("agent", "h2")).unwrap();
    assert!(audit.program_changes.is_empty());
    // The recorded hash still matches too.
    rt.replay("p", program("agent", "h1")).unwrap();

    // Strict replay under Continue reports a change and appends nothing.
    let len = rt.snapshot("p").unwrap().len();
    let cont = RunOptions::default().with_on_code_change(OnCodeChange::Continue);
    let report = rt
        .replay_with("p", cont.clone(), program("agent", "h3"))
        .unwrap();
    assert_eq!(report.program_changes.len(), 1);
    assert_eq!(report.program_changes[0].from, "h2");
    assert_eq!(rt.snapshot("p").unwrap().len(), len);

    // A changed name is never accepted.
    assert!(matches!(
        rt.replay_with("p", cont, program("other", "h1"))
            .unwrap_err(),
        Fault::JournalDesync { .. }
    ));
}

#[test]
fn program_entries_meet_only_program_markers() {
    let rt = Runtime::in_memory(SeededOracle::new(5));
    rt.run("marked", program("agent", "h1")).unwrap();
    // A step meeting a recorded Program entry.
    assert!(matches!(
        rt.replay("marked", old_code).unwrap_err(),
        Fault::JournalDesync { .. }
    ));
    // A marker meeting another kind of entry.
    rt.run("plain", old_code).unwrap();
    let cont = RunOptions::default().with_on_code_change(OnCodeChange::Continue);
    assert!(matches!(
        rt.replay_with("plain", cont, program("agent", "h1"))
            .unwrap_err(),
        Fault::JournalDesync { .. }
    ));
}

#[test]
fn resumed_under_a_changed_program_then_audit_replayed() {
    // v2 changes the program and adds a step after the recorded ones.
    let v2 = |ctx: &mut Ctx| -> Result<Value, Fault> {
        ctx.program_marker("agent", "h2")?;
        let a = ctx.oracle("a")?;
        let b = ctx.oracle(format!("b after {a}"))?;
        let c = ctx.oracle(format!("c after {b}"))?;
        Ok(c)
    };
    let rt = Runtime::in_memory(SeededOracle::new(6));
    rt.run("r", program("agent", "h1")).unwrap();
    // The process died after the first draw.
    crash_before(rt.backend(), "r", 3);
    let resumed = rt.resume("r", v2).unwrap();
    assert_eq!(resumed.program_changes.len(), 1);
    let journal = rt.snapshot("r").unwrap();
    // The note precedes every fresh step of the resumed attempt.
    let note_cursor = changes(&rt, "r")[0].0;
    let fresh = journal
        .program_entries()
        .iter()
        .map(|e| e.cursor)
        .filter(|&c| c > note_cursor)
        .count();
    assert_eq!(fresh, 4, "draw b and draw c, intent and result each");
    assert_eq!(
        note_kinds(&journal),
        [
            note::RUN_START,
            note::ATTEMPT_START,
            note::ATTEMPT_START,
            note::PROGRAM_CHANGE,
            note::ATTEMPT_END
        ]
    );

    // The audit replays under v2 with the default Refuse policy, because
    // the run itself accepted v2.
    let audit = rt.replay("r", v2).unwrap();
    assert_eq!(audit.output, resumed.output);
    assert!(audit.program_changes.is_empty());
    // v1 passes the identity check but did not take the last step.
    assert!(matches!(
        rt.replay("r", program("agent", "h1")).unwrap_err(),
        Fault::JournalDesync { expected, .. } if expected == "end of branch"
    ));
}

#[test]
fn begin_reports_changes_through_the_attempt_api() {
    let rt = Runtime::in_memory(SeededOracle::new(7));
    rt.run("a", program("agent", "h1")).unwrap();
    let mut attempt = rt
        .begin(
            "a",
            Mode::Replay,
            RunOptions::default().with_on_code_change(OnCodeChange::Continue),
        )
        .unwrap();
    let result = program("agent", "h9")(&mut attempt.ctx());
    let report = attempt.finish(result).unwrap();
    assert_eq!(report.program_changes[0].to, "h9");
}
