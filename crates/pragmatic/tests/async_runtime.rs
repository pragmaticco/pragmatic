//! The async runtime carries the same guarantees as the sync one: replay
//! determinism, crash recovery without re-sampling, strict replay never
//! touching the model, driven by the built-in `block_on` (no executor
//! dependency).

mod common;

use common::{crash_before, keyed};
use pragmatic::{
    block_on, AsyncCtx, AsyncOracle, AsyncRuntime, CountingOracle, Event, Fault, SeededOracle,
    Value,
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
        let rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(seed)));
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
    let rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(7)));
    block_on(rt.run("c", fixed_agent)).expect("record");
    let full = rt.snapshot("c").unwrap();
    let program = full.program_entries();
    for k in 0..=program.len() {
        let rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(7)));
        block_on(rt.run("c", fixed_agent)).unwrap();
        let before = rt.oracle().calls();
        crash_before(rt.backend(), "c", k);
        let resumed = block_on(rt.resume("c", fixed_agent)).expect("resume");
        assert!(resumed.output.as_str().starts_with("done: "), "k={k}");
        // Replayed steps were served without new model calls beyond the
        // responses the crash destroyed.
        let lost = program[k.min(program.len())..]
            .iter()
            .filter(|e| matches!(e.event, Event::DrawResult { .. }))
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
            // Yield to the executor once, then answer: the runtime survives
            // suspension points mid-step.
            common::yield_now().await;
            pragmatic::Oracle::call(&self.0, &prompt)
        }
    }

    fn provenance(&self) -> String {
        "yielding-oracle".to_string()
    }
}

#[test]
fn natively_async_oracle_with_suspension_points() {
    async fn two_steps(ctx: &mut AsyncCtx<'_, YieldingOracle>) -> Result<Value, Fault> {
        let a = ctx.oracle("first").await?;
        let b = ctx.oracle(format!("second: {a}")).await?;
        Ok(b)
    }
    let rt = AsyncRuntime::in_memory(YieldingOracle(SeededOracle::new(3)));
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

    let rt = AsyncRuntime::in_memory(CountingOracle::new(SeededOracle::new(1)));
    let recorded = block_on(rt.run("m", marked)).unwrap();
    // The first journaled step is the program identity.
    assert!(matches!(
        rt.snapshot("m").unwrap().program_entries()[0].event,
        Event::Program { .. }
    ));
    let replayed = block_on(rt.replay("m", marked)).unwrap();
    assert_eq!(recorded.trace, replayed.trace);
}

#[test]
fn async_file_journal_survives_restart() {
    let dir = common::TempDir::new("async-restart");
    let recorded = {
        let rt = AsyncRuntime::on_dir(&dir.0, CountingOracle::new(SeededOracle::new(42))).unwrap();
        block_on(rt.run("d", agent)).unwrap()
    };
    let rt2 = AsyncRuntime::on_dir(&dir.0, CountingOracle::new(SeededOracle::new(999))).unwrap();
    let resumed = block_on(rt2.resume("d", agent)).unwrap();
    assert_eq!(rt2.oracle().calls(), 0);
    assert_eq!(resumed.trace, recorded.trace);
}

/// A journal holding a written-off effect followed by its re-performed
/// retry (`Intent, Compensated, Intent, Ok`) replays by skipping the first
/// pair: falling through after the compensated pair would desync every
/// later step.
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
            // A step AFTER the effect: the one that desyncs if the effect
            // replay loop is wrong.
            ctx.oracle(format!("receipt for {r}"))
        }
    };

    let rt = pragmatic::Runtime::in_memory(SeededOracle::new(5));
    assert!(rt.run("cc", flaky_then_fine(true)).is_err()); // failed effect
    let resumed = rt.resume("cc", flaky_then_fine(false)).unwrap(); // retried

    let replayed = rt.replay("cc", flaky_then_fine(false)).unwrap();
    assert_eq!(replayed.trace, resumed.trace);
    assert_eq!(replayed.fresh_steps, 0);
}

/// Children of an async region run concurrently and are journaled on their
/// own branches; the region waits for all of them.
#[test]
fn async_parallel_children_run_concurrently() {
    async fn agent(ctx: &mut AsyncCtx<'_, YieldingOracle>) -> Result<Value, Fault> {
        let parts = ctx
            .parallel(3, |i, mut c| async move {
                let a = c.oracle(format!("a{i}")).await?;
                let b = c.oracle(format!("b{i}: {a}")).await?;
                Ok(b)
            })
            .await?;
        let joined: Vec<String> = parts.iter().map(|v| v.as_str().into_owned()).collect();
        ctx.oracle(joined.join(",")).await
    }
    let rt = AsyncRuntime::in_memory(YieldingOracle(SeededOracle::new(9)));
    let recorded = block_on(rt.run("conc", agent)).unwrap();
    let journal = rt.snapshot("conc").unwrap();
    // Every model call yields once, so the three children opened their
    // first draws before any of them finished: concurrent, not sequential.
    let first_three: Vec<&'static str> = journal
        .program_entries()
        .iter()
        .skip(1)
        .take(3)
        .map(|e| e.event.kind_name())
        .collect();
    assert_eq!(first_three, ["DrawIntent", "DrawIntent", "DrawIntent"]);
    let replayed = block_on(rt.replay("conc", agent)).unwrap();
    assert_eq!(keyed(&recorded.trace), keyed(&replayed.trace));
}
