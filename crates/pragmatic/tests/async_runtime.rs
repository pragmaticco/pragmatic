//! The async runtime carries the same guarantees as the sync one: replay
//! determinism, crash recovery without re-sampling, strict replay never
//! touching the model - driven by the built-in `block_on` (no executor
//! dependency).

use pragmatic::{
    block_on, AsyncCtx, AsyncOracle, AsyncRuntime, CountingOracle, Fault, SeededOracle, Value,
};

type TestOracle = CountingOracle<SeededOracle>;

async fn agent(ctx: &mut AsyncCtx<'_, TestOracle>) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the task").await?;
    let weight: u64 = plan.as_bytes().iter().map(|b| *b as u64).sum();
    let steps = (weight % 3) + 1;
    let mut findings = Vec::new();
    for i in 0..steps {
        findings.push(ctx.oracle(format!("probe {i}: {plan}")).await?);
    }
    let stored = ctx
        .effect(
            "publish",
            format!("{} findings", findings.len()),
            async |arg| Ok(Value::from(format!("s3://{arg}"))),
        )
        .await?;
    Ok(Value::from(format!("done: {stored}")))
}

#[test]
fn async_replay_determinism_100_of_100() {
    for seed in 0..100 {
        let mut rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(seed)));
        let recorded = block_on(rt.run("r", agent)).expect("record");
        let calls = rt.oracle().calls();

        let replayed = block_on(rt.replay("r", agent)).expect("replay");
        assert_eq!(
            rt.oracle().calls(),
            calls,
            "seed {seed}: replay called the model"
        );
        assert_eq!(
            recorded.trace, replayed.trace,
            "seed {seed}: trace diverged"
        );
        assert_eq!(replayed.fresh_steps, 0);
    }
}

/// A structurally fixed agent (same step count on every path), so the
/// number of lost draws after a crash is well-defined regardless of which
/// outcomes get re-sampled.
async fn fixed_agent(ctx: &mut AsyncCtx<'_, TestOracle>) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan").await?;
    let a = ctx.oracle(format!("step a: {plan}")).await?;
    let stored = ctx
        .effect("persist", a.as_str().into_owned(), async |arg| {
            Ok(Value::from(format!("saved({arg})")))
        })
        .await?;
    let c = ctx.oracle(format!("step c: {stored}")).await?;
    Ok(Value::from(format!("done: {c}")))
}

#[test]
fn async_crash_resume_never_resamples_prefix() {
    let mut rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(7)));
    let full = block_on(rt.run("c", fixed_agent)).expect("record");
    for k in 0..full.journal_len {
        let mut rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(7)));
        block_on(rt.run("c", fixed_agent)).unwrap();
        let before = rt.oracle().calls();
        rt.journal("c").unwrap().truncate(k).unwrap();
        let resumed = block_on(rt.resume("c", fixed_agent)).expect("resume");
        assert!(resumed.output.as_str().starts_with("done: "), "k={k}");
        // Replayed steps were served without new model calls beyond the
        // lost tail.
        let lost = full
            .trace
            .iter()
            .filter(|l| matches!(l, pragmatic::TraceLabel::Oracle { cursor, .. } if *cursor >= k))
            .count() as u64;
        assert_eq!(
            rt.oracle().calls() - before,
            lost,
            "k={k}: re-sampled the prefix"
        );
    }
}

/// A natively-async oracle (yields once before answering) exercises real
/// suspension inside a journaled step.
struct YieldingOracle(SeededOracle);

impl AsyncOracle for YieldingOracle {
    fn call(&self, prompt: &Value) -> impl std::future::Future<Output = Result<Value, Fault>> + '_ {
        let prompt = prompt.clone();
        async move {
            // Yield to the executor once, then answer - proves the runtime
            // survives suspension points mid-step.
            yield_once().await;
            pragmatic::Oracle::call(&self.0, &prompt)
        }
    }

    fn provenance(&self) -> String {
        "yielding-oracle".to_string()
    }
}

async fn yield_once() {
    struct Yield(bool);
    impl std::future::Future for Yield {
        type Output = ();
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.0 {
                std::task::Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        }
    }
    Yield(false).await
}

#[test]
fn natively_async_oracle_with_suspension_points() {
    async fn two_steps(ctx: &mut AsyncCtx<'_, YieldingOracle>) -> Result<Value, Fault> {
        let a = ctx.oracle("first").await?;
        let b = ctx.oracle(format!("second: {a}")).await?;
        Ok(b)
    }
    let mut rt = AsyncRuntime::in_memory(YieldingOracle(SeededOracle::new(3)));
    let recorded = block_on(rt.run("y", two_steps)).unwrap();
    let replayed = block_on(rt.replay("y", two_steps)).unwrap();
    assert_eq!(recorded.trace, replayed.trace);
}

#[test]
fn async_durable_macro_works() {
    #[pragmatic::durable]
    async fn marked(ctx: &mut AsyncCtx<'_, TestOracle>) -> Result<Value, Fault> {
        ctx.oracle("hello").await
    }

    let mut rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(1)));
    let recorded = block_on(rt.run("m", marked)).unwrap();
    // First journaled event is the program identity.
    assert!(matches!(
        rt.journal("m").unwrap().entries()[0].event,
        pragmatic::journal_v1::Event::Program { .. }
    ));
    let replayed = block_on(rt.replay("m", marked)).unwrap();
    assert_eq!(recorded.trace, replayed.trace);
}

#[test]
fn async_file_journal_survives_restart() {
    let dir = std::env::temp_dir().join(format!("pragmatic-async-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let recorded = {
        let mut rt =
            AsyncRuntime::on_dir(&dir, CountingOracle::new(SeededOracle::new(42))).unwrap();
        block_on(rt.run("d", agent)).unwrap()
    };
    let mut rt2 = AsyncRuntime::on_dir(&dir, CountingOracle::new(SeededOracle::new(999))).unwrap();
    let resumed = block_on(rt2.resume("d", agent)).unwrap();
    assert_eq!(rt2.oracle().calls(), 0);
    assert_eq!(resumed.trace, recorded.trace);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: a journal holding a compensated effect pair followed by the
/// re-performed pair (`Intent, Compensated, Intent, Commit`) must replay by
/// consuming BOTH pairs - falling through after the compensated pair used to
/// skip the second pair and desync every later step.
#[test]
fn compensated_then_recommitted_effect_replays_exactly() {
    let flaky_then_fine = |fail: bool| {
        move |ctx: &mut pragmatic::Ctx| -> Result<Value, Fault> {
            let x = ctx.oracle("draw")?;
            let r = ctx.effect("charge", x.as_str().into_owned(), |arg| {
                if fail {
                    Err(Fault::ToolErr("boom".into()))
                } else {
                    Ok(Value::from(format!("charged({arg})")))
                }
            })?;
            // A step AFTER the effect - the one that desyncs if the effect
            // replay loop is wrong.
            ctx.oracle(format!("receipt for {r}"))
        }
    };

    let mut rt = pragmatic::Runtime::in_memory(SeededOracle::new(5));
    assert!(rt.run("cc", flaky_then_fine(true)).is_err()); // dangling intent
    let resumed = rt.resume("cc", flaky_then_fine(false)).unwrap(); // compensate + fresh pair

    // Journal now holds Intent, Compensated, Intent, Commit. Strict replay
    // must walk all of it and reproduce the resumed trace exactly.
    let replayed = rt.replay("cc", flaky_then_fine(false)).unwrap();
    assert_eq!(replayed.trace, resumed.trace);
    assert_eq!(replayed.fresh_steps, 0);
}
