//! Regression tests from the adversarial review of the storage, concurrency
//! and failure paths of the 0.6 core. Every test here is named `adv_*` and
//! asserts the behavior the design (docs/design/system-of-record.md)
//! requires.

mod common;

use std::cell::Cell;
use std::rc::Rc;

use common::{yield_now, FlakyBackend, TempDir};
use pragmatic::{
    block_on, AsyncCtx, AsyncRuntime, Backend, Ctx, Decision, DirBackend, Fault, Runtime,
    SeededOracle, Supervisor, Value,
};

// ---------------------------------------------------------------------------
// Receives
// ---------------------------------------------------------------------------

/// Spec 3.2: a persist failure fails the session and "the next attempt
/// starts from durable state". A delivered message that was never durably
/// received must still be there for that next attempt.
#[test]
fn adv_recv_message_survives_a_failed_persist() {
    let backend = FlakyBackend::new();
    let rt = Runtime::with_backend(Box::new(backend.clone()), SeededOracle::new(1));
    rt.send("inbox-run", "inbox", "wire 500 EUR to account 42");
    // The opening notes persist; the receive's entry does not.
    backend.fail_after(1);
    let err = rt
        .run("inbox-run", |ctx: &mut Ctx| ctx.recv("inbox"))
        .unwrap_err();
    assert!(matches!(err, Fault::Io(_)), "{err:?}");
    // Nothing about the message is durable.
    let durable = rt.snapshot("inbox-run").unwrap();
    assert_eq!(durable.program_entries().len(), 0);

    backend.fail_after(-1);
    let report = rt.resume("inbox-run", |ctx: &mut Ctx| ctx.recv("inbox"));
    assert_eq!(
        report.map(|r| r.output.as_str().into_owned()),
        Ok("wire 500 EUR to account 42".to_string()),
        "the message was taken from the inbox although its receive was never recorded"
    );
}

/// Spec 2.15: an over-limit receive fails with `TooLarge` "before anything
/// is performed". The message must not be consumed by the failed receive.
#[test]
fn adv_recv_too_large_does_not_consume_the_message() {
    let rt = Runtime::in_memory(SeededOracle::new(2));
    let big = vec![b'x'; (64 << 20) + 1];
    rt.send("big-recv", "inbox", big);
    rt.send("big-recv", "inbox", "small follow-up");
    let first = rt.run("big-recv", |ctx: &mut Ctx| ctx.recv("inbox"));
    assert!(matches!(first, Err(Fault::TooLarge { .. })), "{first:?}");
    // Retrying the same receive must hit the same message again, not
    // silently skip to the next one.
    let second = rt.resume("big-recv", |ctx: &mut Ctx| ctx.recv("inbox"));
    assert!(
        matches!(second, Err(Fault::TooLarge { .. })),
        "the over-limit message was consumed by the failed receive: {second:?}"
    );
}

// ---------------------------------------------------------------------------
// EffectUnrecorded
// ---------------------------------------------------------------------------

/// Spec 3.2: `EffectUnrecorded{name, intent, result}` "is raised when
/// perform succeeded but its result could not be persisted". In an async
/// parallel region a sibling's persist failure fails the session while an
/// effect is being performed; the effect's own end must still hand the
/// result back.
#[test]
fn adv_async_sibling_persist_failure_still_reports_effect_unrecorded() {
    let backend = FlakyBackend::new();
    let rt = AsyncRuntime::with_backend(Box::new(backend.clone()), SeededOracle::new(3));
    // Persists: opening notes (1), fork (2), child 0's effect intent (3).
    // Child 1's clock read is the 4th and fails.
    backend.fail_after(3);
    async fn agent(ctx: &mut AsyncCtx<'_, SeededOracle>) -> Result<Value, Fault> {
        let parts = ctx
            .parallel(2, |i, mut c| async move {
                if i == 0 {
                    c.effect("transfer", "10 EUR", async |_: &Value| {
                        // The transfer takes a while; child 1 runs meanwhile.
                        yield_now().await;
                        yield_now().await;
                        Ok(Value::from("confirmation 77"))
                    })
                    .await
                } else {
                    c.now().map(|t| Value::from(t.to_string()))
                }
            })
            .await?;
        Ok(parts[0].clone())
    }
    let err = block_on(rt.run("sibling", agent)).unwrap_err();
    match &err {
        Fault::EffectUnrecorded { name, result, .. } => {
            assert_eq!(name, "transfer");
            assert_eq!(result.as_str(), "confirmation 77");
        }
        other => panic!(
            "the transfer was performed but its result is lost: got {other:?} instead of \
             EffectUnrecorded"
        ),
    }
}

/// Spec 3.2 again, for a result over the 64 MiB slot limit: perform
/// succeeded and its result could not be recorded, so the caller must get
/// `EffectUnrecorded` (with the result), not a bare `TooLarge`.
#[test]
fn adv_effect_result_over_the_limit_is_effect_unrecorded() {
    let rt = Runtime::in_memory(SeededOracle::new(4));
    let performed = Rc::new(Cell::new(0u32));
    let p = performed.clone();
    let err = rt
        .run("big-result", move |ctx: &mut Ctx| {
            ctx.effect("export", "all rows", |_| {
                p.set(p.get() + 1);
                Ok(Value::from(vec![0u8; (64 << 20) + 1]))
            })
        })
        .unwrap_err();
    assert_eq!(performed.get(), 1);
    assert!(
        matches!(err, Fault::EffectUnrecorded { .. }),
        "perform succeeded but the caller cannot see or log its result: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Saga compensation
// ---------------------------------------------------------------------------

/// The saga claims "a later saga never undoes the same effect twice". A
/// persist failure after the compensator ran (the compensation is not on
/// record) makes the next saga undo the same effect again.
#[test]
fn adv_saga_never_undoes_an_effect_twice() {
    let backend = FlakyBackend::new();
    let rt = Runtime::with_backend(Box::new(backend.clone()), SeededOracle::new(5));
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        ctx.effect("charge", "card 1234, 99 EUR", |_| {
            Ok(Value::from("charged"))
        })?;
        ctx.contract(false, "order invalid")?;
        Ok(Value::default())
    };
    let undone = Rc::new(Cell::new(0u32));
    let sup = || {
        let u = undone.clone();
        Supervisor::new()
            .on_fault(|_| Decision::Compensate)
            .compensate_with(move |_, _| u.set(u.get() + 1))
    };
    // Persists of the first attempt: opening notes, effect intent, effect
    // result, attempt.end. The saga's first note is the 5th and fails.
    backend.fail_after(4);
    let first = sup().supervise(&rt, "saga", Default::default(), agent);
    assert!(matches!(first, Err(Fault::Io(_))), "{first:?}");
    // The saga records a compensation before it runs it: with the record
    // refused, the charge is not undone yet.
    assert_eq!(undone.get(), 0, "the compensator ran without a record");

    backend.fail_after(-1);
    let second = sup().supervise(&rt, "saga", Default::default(), agent);
    assert!(matches!(second, Err(Fault::ContractViol(_))), "{second:?}");
    assert_eq!(
        undone.get(),
        1,
        "the same charge was refunded twice: the compensation ran before it was on record"
    );
    // A third saga finds the compensation on record and leaves it alone.
    let third = sup().supervise(&rt, "saga", Default::default(), agent);
    assert!(matches!(third, Err(Fault::ContractViol(_))), "{third:?}");
    assert_eq!(undone.get(), 1);
}

// ---------------------------------------------------------------------------
// DirBackend naming and listing
// ---------------------------------------------------------------------------

/// Spec 3.3: "A format 1 journal is found by the old safe-name rule only
/// when no hashed file exists." A 0.5 run whose id is 64 lowercase hex
/// characters (a content hash, say) is a readable format 1 journal, but
/// `list` skips it because its file name looks like a hashed name.
#[test]
fn adv_list_finds_format1_runs_with_hex_ids() {
    use pragmatic::journal_v1 as v1;
    let dir = TempDir::new("adv-hex-legacy");
    let backend = DirBackend::new(&dir.0).unwrap();
    let id = "3f7a".repeat(16);
    assert_eq!(id.len(), 64);
    {
        let mut j = v1::Journal::create(backend.legacy_path(&id)).unwrap();
        j.append(v1::Event::Clock { nanos: 1 }).unwrap();
        j.sync().unwrap();
    }
    // The run is there and readable...
    assert_eq!(backend.snapshot(&id, None).unwrap().format(), 1);
    // ...but not listed (so `pragmatic runs` and the console never show it).
    assert_eq!(backend.list().unwrap(), vec![id]);
}

/// The old safe-name rule maps distinct ids to one file ("user.42" and
/// "user_42"). With a 0.5 journal for "user_42" on disk, a brand-new 0.6 run
/// "user.42" can never be created, and reading "user.42" returns the other
/// run's journal.
#[test]
fn adv_legacy_name_collision_blocks_a_new_run() {
    use pragmatic::journal_v1 as v1;
    let dir = TempDir::new("adv-legacy-collision");
    let backend = DirBackend::new(&dir.0).unwrap();
    {
        let mut j = v1::Journal::create(backend.legacy_path("user_42")).unwrap();
        j.append(v1::Event::Clock { nanos: 7 }).unwrap();
        j.sync().unwrap();
    }
    assert_eq!(
        backend.legacy_path("user.42"),
        backend.legacy_path("user_42")
    );
    // "user.42" has never existed.
    let rt = Runtime::with_backend(Box::new(backend.clone()), SeededOracle::new(6));
    let created = rt.run("user.42", |ctx: &mut Ctx| {
        ctx.now().map(|t| Value::from(t.to_string()))
    });
    let snap = backend.snapshot("user.42", None);
    assert!(
        created.is_ok() && snap.as_ref().is_ok_and(|j| j.format() == 2),
        "a new run is refused ({created:?}) and reading it returns another run's \
         format 1 journal ({:?} entries)",
        snap.map(|j| j.len())
    );
}

// ---------------------------------------------------------------------------
// Runs that never started
// ---------------------------------------------------------------------------

/// A `run` that fails validation before anything is recorded (bad labels)
/// should leave no run behind: `resume` "requires it" (spec 3.1, `Resume`
/// errors if no journal exists), and `runs()` should not list it. The
/// checkout that `run` takes first creates the journal, so the refused run
/// is listed (memory) and can be resumed as if it had started (both).
fn rejected_run_leaves_no_run_behind(name: &str, backend: Box<dyn Backend>) {
    let rt = Runtime::with_backend(backend, SeededOracle::new(7));
    let bad = pragmatic::RunOptions::default().with_label("Not Valid", "x");
    let err = rt
        .run_with("phantom", bad, |_: &mut Ctx| Ok(Value::default()))
        .unwrap_err();
    assert!(matches!(err, Fault::Unsupported(_)), "{name}: {err:?}");
    let listed = rt.runs().unwrap().contains(&"phantom".to_string());
    let resumed = rt.resume("phantom", |_: &mut Ctx| Ok(Value::from("resumed")));
    assert!(
        !listed && resumed.is_err(),
        "{name}: a run refused before it started is listed ({listed}) or resumable ({:?})",
        resumed.map(|r| r.output)
    );
}

#[test]
fn adv_rejected_run_leaves_no_run_behind_memory() {
    rejected_run_leaves_no_run_behind("memory", Box::new(pragmatic::MemoryBackend::new()));
}

#[test]
fn adv_rejected_run_leaves_no_run_behind_dir() {
    let dir = TempDir::new("adv-phantom");
    rejected_run_leaves_no_run_behind("dir", Box::new(DirBackend::new(&dir.0).unwrap()));
}

// ---------------------------------------------------------------------------
// Probes that pass (kept as regression guards)
// ---------------------------------------------------------------------------

/// Intents are on disk before the model is called or the effect performed
/// (spec 3.2), checked against the file a separate reader sees.
#[test]
fn adv_intents_are_on_disk_before_the_call() {
    use pragmatic::Event;
    let dir = TempDir::new("adv-intent-order");
    let reader = DirBackend::new(&dir.0).unwrap();
    struct Peek(DirBackend);
    impl pragmatic::Oracle for Peek {
        fn call(&self, _: &Value) -> Result<Value, Fault> {
            let snap = self.0.snapshot("order", None).unwrap();
            let last = snap.program_entries().last().map(|e| e.event.kind_name());
            assert_eq!(
                last,
                Some("DrawIntent"),
                "model called before its intent was durable"
            );
            Ok(Value::from("answer"))
        }
    }
    let rt = Runtime::on_dir(&dir.0, Peek(reader.clone())).unwrap();
    rt.run("order", |ctx: &mut Ctx| {
        ctx.oracle("q")?;
        let r = reader.clone();
        ctx.effect("send", "x", move |_| {
            let snap = r.snapshot("order", None).unwrap();
            assert!(matches!(
                snap.program_entries().last().unwrap().event,
                Event::EffectIntent { .. }
            ));
            Ok(Value::from("sent"))
        })
    })
    .unwrap();
}

/// Snapshots taken while a writer appends never report corruption.
#[test]
fn adv_snapshots_during_appends_never_see_corruption() {
    use pragmatic::journal::{note, Content, Event, META, ROOT};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let dir = TempDir::new("adv-snap-stress");
    let b = Arc::new(DirBackend::new(&dir.0).unwrap());
    let mut co = b.checkout("live", true, None).unwrap();
    co.journal
        .append(
            META,
            Event::Note {
                kind: note::RUN_START.into(),
                data: r#"{"format":2,"run_id":"live"}"#.into(),
                payload: vec![],
            },
        )
        .unwrap();
    co.persist().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..3)
        .map(|_| {
            let (b, stop) = (b.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::SeqCst) {
                    let snap = b.snapshot("live", None).expect("snapshot of a live run");
                    assert!(snap.verify().is_ok());
                    n += 1;
                }
                n
            })
        })
        .collect();
    for i in 0..400 {
        // Several frames per persist, some large enough to span pages.
        for k in 0..3 {
            let body = "y".repeat(if k == 1 { 9000 } else { 10 + i });
            co.journal
                .append(
                    ROOT,
                    Event::ChannelRecv {
                        channel: "c".into(),
                        value: Content::from(format!("{i}-{k}-{body}")),
                    },
                )
                .unwrap();
        }
        co.persist().unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    for r in readers {
        assert!(r.join().unwrap() > 0);
    }
}

/// Child half of `adv_real_partial_write_rolls_back`: with RLIMIT_FSIZE just
/// above the journal's size, a persist gets a real short write and then
/// EFBIG. The sink must roll back to its tracked length and stay failed.
#[cfg(unix)]
#[test]
fn adv_fsize_child() {
    use pragmatic::journal::{Content, Event, ROOT};
    use std::ffi::c_int;
    let Ok(dir) = std::env::var("PRAGMATIC_ADV_FSIZE_DIR") else {
        return;
    };
    #[repr(C)]
    struct RLimit {
        cur: u64,
        max: u64,
    }
    extern "C" {
        fn setrlimit(resource: c_int, rlim: *const RLimit) -> c_int;
        fn getrlimit(resource: c_int, rlim: *mut RLimit) -> c_int;
        fn signal(sig: c_int, handler: usize) -> usize;
    }
    const RLIMIT_FSIZE: c_int = 1;
    const SIGXFSZ: c_int = 25;
    const SIG_IGN: usize = 1;
    let b = DirBackend::new(&dir).unwrap();
    let mut co = b.checkout("fsize", false, None).unwrap();
    let len = std::fs::metadata(b.journal_path("fsize")).unwrap().len();
    // SAFETY: plain libc calls on this process's own limits and signals.
    unsafe {
        signal(SIGXFSZ, SIG_IGN);
        let mut old = RLimit { cur: 0, max: 0 };
        assert_eq!(getrlimit(RLIMIT_FSIZE, &mut old), 0);
        let lim = RLimit {
            cur: len + 100,
            max: old.max,
        };
        assert_eq!(setrlimit(RLIMIT_FSIZE, &lim), 0);
    }
    co.journal
        .append(
            ROOT,
            Event::ChannelRecv {
                channel: "c".into(),
                value: Content::from("z".repeat(4000)),
            },
        )
        .unwrap();
    let err = co.persist().unwrap_err();
    println!("FSIZE-ERR {err:?}");
    let after = std::fs::metadata(b.journal_path("fsize")).unwrap().len();
    println!("FSIZE-LEN {len} {after}");
    assert_eq!(after, len, "the short write was not rolled back");
    assert!(co.persist().is_err(), "a failed sink accepted a retry");
    println!("FSIZE-OK");
}

#[cfg(unix)]
#[test]
fn adv_real_partial_write_rolls_back() {
    use pragmatic::journal::{note, Event, META};
    use std::process::Command;
    let dir = TempDir::new("adv-fsize");
    let b = DirBackend::new(&dir.0).unwrap();
    {
        let mut co = b.checkout("fsize", true, None).unwrap();
        co.journal
            .append(
                META,
                Event::Note {
                    kind: note::RUN_START.into(),
                    data: r#"{"format":2,"run_id":"fsize"}"#.into(),
                    payload: vec![],
                },
            )
            .unwrap();
        co.persist().unwrap();
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "adv_fsize_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PRAGMATIC_ADV_FSIZE_DIR", &dir.0)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("FSIZE-OK"),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "{}",
        text.lines()
            .filter(|l| l.starts_with("FSIZE"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let snap = b.snapshot("fsize", None).unwrap();
    assert_eq!((snap.len(), snap.torn_bytes()), (1, 0));
}

/// The parser's documented guarantee: "a single damaged byte never lets a
/// writer truncate acknowledged entries". One flipped byte in the content
/// of the last acknowledged frame (bit rot) is read as a torn tail, and the
/// next writer moves the acknowledged entry aside and truncates it.
#[test]
fn adv_one_flipped_content_byte_in_the_last_frame_is_not_truncated() {
    let dir = TempDir::new("adv-flip-last");
    let rt = Runtime::on_dir(&dir.0, SeededOracle::new(11)).unwrap();
    rt.run("flip", |ctx: &mut Ctx| {
        ctx.effect("pay", "invoice 9", |_| {
            Ok(Value::from("PAID-REFERENCE-0001"))
        })
    })
    .unwrap();
    let backend = DirBackend::new(&dir.0).unwrap();
    let before = rt.snapshot("flip").unwrap();
    let path = backend.journal_path("flip");
    let mut bytes = std::fs::read(&path).unwrap();
    // The last frame is attempt.end, whose payload slot holds the output
    // "PAID-REFERENCE-0001". Flip one bit of it.
    let at = bytes
        .windows(19)
        .rposition(|w| w == b"PAID-REFERENCE-0001")
        .unwrap();
    bytes[at] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    // Readers must not see one entry fewer, silently.
    let snap = rt.snapshot("flip");
    let report = rt.verify("flip");
    // A writer must not remove the acknowledged entry from the journal.
    let resumed = rt.resume("flip", |ctx: &mut Ctx| {
        ctx.effect("pay", "invoice 9", |_| {
            Ok(Value::from("PAID-REFERENCE-0001"))
        })
    });
    let on_disk = std::fs::read(&path).unwrap();
    let last = before.len() - 1;
    assert!(
        snap.is_err() && resumed.is_err() && on_disk == bytes,
        "one damaged byte: snapshot {:?} entries, resume {:?}, file {} (was {} bytes)",
        snap.as_ref().map(|j| j.len()),
        resumed.map(|_| ()),
        on_disk.len(),
        bytes.len(),
    );
    // A verifier is told where the damage is.
    let report = report.unwrap();
    assert_eq!(report.first_bad, Some(last), "{report:?}");
    assert!(!report.is_ok());
}
