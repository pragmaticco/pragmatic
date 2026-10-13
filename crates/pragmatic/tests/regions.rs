//! Parallel regions (spec 2.7): fork numbering, the seven region rules,
//! completeness at join and at the agent's return, nesting, and the budget
//! shared by concurrent children.

mod common;

use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Waker};

use common::{keyed, note_kinds, yield_now, Staggered};
use pragmatic::journal::{note, ROOT};
use pragmatic::{
    block_on, AsyncCtx, AsyncRuntime, Ctx, Event, Fault, Mode, RunOptions, Runtime, SeededOracle,
    Value,
};

/// The `Fork` entries of a run: `(branch, base, children)`.
fn forks(journal: &pragmatic::Journal) -> Vec<(Vec<u32>, u32, u32)> {
    journal
        .program_entries()
        .iter()
        .filter_map(|e| match e.event {
            Event::Fork { base, children } => Some((e.branch.clone(), base, children)),
            _ => None,
        })
        .collect()
}

#[test]
fn lowest_index_failure_wins_not_the_first_in_time() {
    // Child 2 fails at once, child 0 fails last, child 1 succeeds. The
    // region waits for all three and raises child 0's failure.
    let order: Rc<RefCell<Vec<u32>>> = Rc::new(RefCell::new(Vec::new()));
    async fn drive(
        rt: &AsyncRuntime<Staggered>,
        order: Rc<RefCell<Vec<u32>>>,
        replay: bool,
    ) -> Result<pragmatic::RunReport, Fault> {
        let order2 = order.clone();
        let agent = async move |ctx: &mut AsyncCtx<'_, Staggered>| -> Result<Value, Fault> {
            let order = order2.clone();
            let out = ctx
                .parallel(3, |i, mut c| {
                    let order = order.clone();
                    async move {
                        match i {
                            2 => {
                                order.borrow_mut().push(2);
                                Err(Fault::ContractViol("child 2".into()))
                            }
                            1 => c.oracle("child 1 works").await,
                            _ => {
                                let v = c.oracle("child 0 starts").await?;
                                for _ in 0..5 {
                                    yield_now().await;
                                }
                                order.borrow_mut().push(0);
                                Err(Fault::ContractViol(format!("child 0 after {v}")))
                            }
                        }
                    }
                })
                .await;
            match out {
                Ok(_) => Ok(Value::from("unreachable")),
                Err(Fault::ContractViol(m)) => Ok(Value::from(format!("region failed: {m}"))),
                Err(other) => Err(other),
            }
        };
        if replay {
            rt.replay("fail", agent).await
        } else {
            rt.run("fail", agent).await
        }
    }
    let rt = AsyncRuntime::in_memory(Staggered::new(4));
    let recorded = block_on(drive(&rt, order.clone(), false)).unwrap();
    assert_eq!(*order.borrow(), vec![2, 0], "child 2 failed first in time");
    assert!(
        recorded
            .output
            .as_str()
            .starts_with("region failed: child 0 after"),
        "{}",
        recorded.output
    );
    // Child 1 ran to completion although siblings failed.
    let journal = rt.snapshot("fail").unwrap();
    assert!(journal
        .program_entries()
        .iter()
        .any(|e| e.branch == [1] && matches!(e.event, Event::DrawResult { .. })));
    // The agent handled the region failure and returned ok: the failed
    // children are exempt from completeness.
    order.borrow_mut().clear();
    let replayed = block_on(drive(&rt, order.clone(), true)).unwrap();
    assert_eq!(replayed.output, recorded.output);
    assert_eq!(keyed(&replayed.trace), keyed(&recorded.trace));
}

#[test]
fn sync_regions_run_every_child_and_raise_the_lowest_failure() {
    let ran = Rc::new(RefCell::new(Vec::new()));
    let agent = {
        let ran = ran.clone();
        move |ctx: &mut Ctx| -> Result<Value, Fault> {
            let ran = ran.clone();
            let out = ctx.parallel(4, move |i, c| {
                ran.borrow_mut().push(i);
                let v = c.oracle(format!("child {i}"))?;
                if i == 1 || i == 3 {
                    return Err(Fault::ToolErr(format!("child {i} failed")));
                }
                Ok(v)
            });
            out.map(|v| Value::from(v.len().to_string()))
                .or_else(|e| Ok(Value::from(e.to_string())))
        }
    };
    let rt = Runtime::in_memory(SeededOracle::new(1));
    let r = rt.run("s", agent.clone()).unwrap();
    assert_eq!(*ran.borrow(), vec![0, 1, 2, 3]);
    assert_eq!(r.output.as_str(), "tool error: child 1 failed");
    assert_eq!(rt.replay("s", agent).unwrap().output, r.output);
}

#[test]
fn fork_numbering_never_reuses_child_ids() {
    let agent = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let a = ctx.parallel(2, |i, c| c.oracle(format!("first region {i}")))?;
        let b = ctx.parallel(3, |i, c| {
            let inner = c.parallel(2, |j, cc| cc.oracle(format!("nested {i}.{j}")))?;
            Ok(Value::from(inner.len().to_string()))
        })?;
        Ok(Value::from(format!("{} {}", a.len(), b.len())))
    };
    let rt = Runtime::in_memory(SeededOracle::new(2));
    rt.run("n", agent).unwrap();
    let journal = rt.snapshot("n").unwrap();
    assert_eq!(
        forks(&journal),
        vec![
            (vec![], 0, 2),
            (vec![], 2, 3),
            (vec![2], 0, 2),
            (vec![3], 0, 2),
            (vec![4], 0, 2),
        ]
    );
    let branches: std::collections::BTreeSet<Vec<u32>> = journal
        .program_entries()
        .iter()
        .map(|e| e.branch.clone())
        .collect();
    for b in [vec![0], vec![1], vec![2, 0], vec![2, 1], vec![4, 1]] {
        assert!(branches.contains(&b), "{b:?}");
    }
    rt.replay("n", agent).unwrap();

    // Replaying under code that asks for another child count is a desync
    // at the fork.
    let changed = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let a = ctx.parallel(3, |i, c| c.oracle(format!("first region {i}")))?;
        Ok(Value::from(a.len().to_string()))
    };
    let first_fork = journal
        .program_entries()
        .iter()
        .find(|e| matches!(e.event, Event::Fork { .. }))
        .unwrap()
        .cursor;
    assert!(matches!(
        rt.replay("n", changed).unwrap_err(),
        Fault::JournalDesync { cursor, .. } if cursor == first_fork
    ));
}

#[test]
fn suspended_and_joined_branches_refuse_steps() {
    let rt = Runtime::in_memory(SeededOracle::new(3));
    let mut attempt = rt.begin("rules", Mode::Run, RunOptions::default()).unwrap();
    let s = attempt.session();
    let root = ROOT.to_vec();
    let children = s.fork(&root, 2).unwrap();
    assert_eq!(children, vec![vec![0], vec![1]]);
    let suspended = Fault::Unsupported("branch is suspended in a parallel region".into());
    // Rule 5: the parent is suspended while the region is open.
    assert_eq!(s.now(&root).unwrap_err(), suspended);
    assert_eq!(s.fork(&root, 1).unwrap_err(), suspended);
    // A branch no fork created is refused.
    assert!(matches!(s.now(&vec![7]), Err(Fault::Unsupported(_))));
    // Joining something other than the open region is refused.
    assert!(s.join(&root, &children[..1], &[true]).is_err());
    s.now(&children[0]).unwrap();
    s.join(&root, &children, &[true, true]).unwrap();
    // Rule 6: a child after its region joined.
    assert_eq!(s.now(&children[0]).unwrap_err(), suspended);
    // The parent runs again, and the next region numbers on.
    s.now(&root).unwrap();
    assert_eq!(s.fork(&root, 1).unwrap(), vec![vec![2]]);
    s.join(&root, &[vec![2]], &[true]).unwrap();
    attempt.finish(Ok(Value::from("ok"))).unwrap();
}

#[test]
fn completeness_at_join_and_at_return() {
    let recorded = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let parts = ctx.parallel(2, |i, c| {
            let a = c.oracle(format!("{i} a"))?;
            c.oracle(format!("{i} b {a}"))
        })?;
        ctx.oracle(format!("merge {}", parts.len()))
    };
    let rt = Runtime::in_memory(SeededOracle::new(4));
    rt.run("c", recorded).unwrap();
    let journal = rt.snapshot("c").unwrap();
    let second_of_child_1 = journal
        .program_entries()
        .iter()
        .filter(|e| e.branch == [1] && matches!(e.event, Event::DrawIntent { .. }))
        .nth(1)
        .unwrap()
        .cursor;

    // Child 1 now stops after one draw: its branch has an unconsumed step
    // when it returns, so the region fails at join, in every mode.
    let shorter_child = |ctx: &mut Ctx| -> Result<Value, Fault> {
        let parts = ctx.parallel(2, |i, c| {
            let a = c.oracle(format!("{i} a"))?;
            if i == 1 {
                return Ok(a);
            }
            c.oracle(format!("{i} b {a}"))
        })?;
        ctx.oracle(format!("merge {}", parts.len()))
    };
    for mode in ["replay", "resume"] {
        let err = match mode {
            "replay" => rt.replay("c", shorter_child),
            _ => rt.resume("c", shorter_child),
        }
        .unwrap_err();
        match err {
            Fault::JournalDesync {
                cursor, expected, ..
            } => {
                assert_eq!(cursor, second_of_child_1, "{mode}");
                assert_eq!(expected, "end of branch");
            }
            other => panic!("{mode}: {other:?}"),
        }
    }

    // The agent returns before its last recorded step: the check at return.
    let early = |ctx: &mut Ctx| -> Result<Value, Fault> {
        ctx.parallel(2, |i, c| {
            let a = c.oracle(format!("{i} a"))?;
            c.oracle(format!("{i} b {a}"))
        })?;
        Ok(Value::from("early"))
    };
    let err = rt.replay("c", early).unwrap_err();
    assert!(
        matches!(&err, Fault::JournalDesync { expected, .. } if expected == "end of branch"),
        "{err:?}"
    );
}

#[test]
fn regions_nest_at_most_32_deep() {
    fn nest(ctx: &mut Ctx, depth: u32) -> Result<Value, Fault> {
        if depth == 0 {
            return ctx.oracle("leaf");
        }
        let mut out = ctx.parallel(1, |_, c| nest(c, depth - 1))?;
        Ok(out.remove(0))
    }
    let rt = Runtime::in_memory(SeededOracle::new(5));
    rt.run("deep", |ctx: &mut Ctx| nest(ctx, 32)).unwrap();
    let leaf = rt.snapshot("deep").unwrap();
    assert_eq!(leaf.program_entries().last().unwrap().branch.len(), 32);
    rt.replay("deep", |ctx: &mut Ctx| nest(ctx, 32)).unwrap();
    assert!(matches!(
        rt.run("deeper", |ctx: &mut Ctx| nest(ctx, 33)).unwrap_err(),
        Fault::Unsupported(_)
    ));
}

#[test]
fn an_empty_region_journals_nothing() {
    let rt = Runtime::in_memory(SeededOracle::new(6));
    let r = rt
        .run("empty", |ctx: &mut Ctx| {
            let v: Vec<Value> = ctx.parallel(0, |_, c| c.oracle("never"))?;
            Ok(Value::from(v.len().to_string()))
        })
        .unwrap();
    assert_eq!(r.output.as_str(), "0");
    assert!(rt.snapshot("empty").unwrap().program_entries().is_empty());
}

#[test]
fn budget_is_shared_by_concurrent_children() {
    async fn hungry(ctx: &mut AsyncCtx<'_, Staggered>) -> Result<Value, Fault> {
        let parts = ctx
            .parallel(5, |i, mut c| async move {
                let mut last = Value::from("");
                for k in 0..3 {
                    last = c.oracle(format!("{i}.{k}")).await?;
                }
                Ok(last)
            })
            .await?;
        Ok(Value::from(parts.len().to_string()))
    }
    let rt = AsyncRuntime::in_memory(Staggered::new(7));
    let err =
        block_on(rt.run_with("budget", RunOptions::default().with_budget(7), hungry)).unwrap_err();
    assert_eq!(err, Fault::BudgetExhausted);
    let journal = rt.snapshot("budget").unwrap();
    let intents = journal
        .program_entries()
        .iter()
        .filter(|e| matches!(e.event, Event::DrawIntent { .. }))
        .count();
    assert_eq!(intents, 7, "never more model calls than the budget");
    assert_eq!(rt.oracle().calls(), 7);
    // Every intent got its response: no call was left open by the refusal.
    let results = journal
        .program_entries()
        .iter()
        .filter(|e| matches!(e.event, Event::DrawResult { .. }))
        .count();
    assert_eq!(results, 7);
}

/// A waker that does nothing, for polling a future by hand.
fn noop_waker() -> Waker {
    struct Noop;
    impl std::task::Wake for Noop {
        fn wake(self: std::sync::Arc<Self>) {}
    }
    Waker::from(std::sync::Arc::new(Noop))
}

#[test]
fn dropping_a_running_attempt_is_a_crash() {
    async fn agent(ctx: &mut AsyncCtx<'_, Staggered>) -> Result<Value, Fault> {
        let parts = ctx
            .parallel(2, |i, mut c| async move {
                c.oracle(format!("child {i}")).await?;
                loop {
                    yield_now().await;
                }
                #[allow(unreachable_code)]
                Ok::<Value, Fault>(Value::default())
            })
            .await?;
        Ok(Value::from(parts.len().to_string()))
    }
    let rt = AsyncRuntime::in_memory(Staggered::new(8));
    {
        let mut fut = Box::pin(rt.run("cancel", agent));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in 0..20 {
            assert!(fut.as_mut().poll(&mut cx).is_pending());
        }
        // The task is cancelled from outside.
    }
    let journal = rt.snapshot("cancel").unwrap();
    assert!(!note_kinds(&journal).contains(&note::ATTEMPT_END.to_string()));
    assert_eq!(
        journal
            .program_entries()
            .iter()
            .filter(|e| matches!(e.event, Event::DrawResult { .. }))
            .count(),
        2
    );
    // The lock was released: the run can be resumed.
    let resumed = block_on(
        rt.resume("cancel", async |ctx: &mut AsyncCtx<'_, Staggered>| {
            let parts = ctx
                .parallel(
                    2,
                    |i, mut c| async move { c.oracle(format!("child {i}")).await },
                )
                .await?;
            Ok(Value::from(parts.len().to_string()))
        }),
    )
    .unwrap();
    assert_eq!(resumed.output.as_str(), "2");
    assert_eq!(resumed.fresh_steps, 0);
}
