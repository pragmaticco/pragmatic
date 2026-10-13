//! **E1 - Replay determinism (T1, empirically).**
//!
//! For 1000 independently seeded stochastic runs: record the run, then
//! replay it strictly (model never called) and assert the observable trace
//! and output are identical. The landing-page claim "1000 / 1000 replay
//! determinism across the reference test suite" is this test.
//!
//! The branch-interleaving variants record agents whose parallel children
//! interleave their steps in the journal, then replay them with a different
//! interleaving (replayed steps never wait on the model), and check every
//! child's value and the whole trace as `(branch, cursor, label)`.

mod common;

use common::{keyed, Staggered};
use pragmatic::{
    block_on, AsyncCtx, AsyncRuntime, CountingOracle, Ctx, Fault, Runtime, SeededOracle,
    TraceLabel, Value,
};

/// A branching, stochastic agent: samples a plan, branches on the realized
/// outcome (so control flow depends on nondeterminism), loops a data-driven
/// number of times, and commits an effect.
fn agent(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan the task")?;
    // Branch on realized randomness: byte sum picks the strategy.
    let weight: u64 = plan.as_bytes().iter().map(|b| *b as u64).sum();
    let steps = (weight % 4) + 1;
    let mut findings = Vec::new();
    for i in 0..steps {
        let f = ctx.oracle(format!("probe step {i} of plan {plan}"))?;
        if f.as_str().starts_with("halt") {
            break; // data-dependent early exit
        }
        findings.push(f);
    }
    let t = ctx.now()?;
    let report = ctx.effect(
        "write_report",
        format!("{} findings @{t}", findings.len()),
        |arg| Ok(Value::from(format!("stored({arg})"))),
    )?;
    Ok(report)
}

#[test]
fn e1_replay_determinism_1000_of_1000() {
    let mut identical = 0u32;
    const N: u64 = 1000;
    for seed in 0..N {
        let rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(seed)));
        let run_id = format!("e1-{seed}");

        let recorded = rt.run(&run_id, agent).expect("record run succeeds");
        let calls_after_record = rt.oracle().calls();

        let replayed = rt.replay(&run_id, agent).expect("replay succeeds");

        // Zero model calls during replay: the oracle was never consulted.
        assert_eq!(
            rt.oracle().calls(),
            calls_after_record,
            "seed {seed}: replay called the model"
        );
        // The whole observable trace is identical, output included.
        assert_eq!(
            keyed(&recorded.trace),
            keyed(&replayed.trace),
            "seed {seed}: trace diverged"
        );
        assert_eq!(
            recorded.output, replayed.output,
            "seed {seed}: output diverged"
        );
        assert_eq!(
            replayed.fresh_steps, 0,
            "seed {seed}: replay recorded fresh steps"
        );
        identical += 1;
    }
    assert_eq!(identical, N as u32, "replay determinism must be {N}/{N}");
}

#[test]
fn e1_distinct_seeds_actually_diverge() {
    // Sanity check that E1 is not vacuous: the oracle is genuinely
    // stochastic across seeds, so identical traces are earned, not implied.
    let mut outputs = std::collections::HashSet::new();
    for seed in 0..50 {
        let rt = Runtime::in_memory(SeededOracle::new(seed));
        let r = rt.run("x", agent).unwrap();
        outputs.insert(r.output.as_str().into_owned());
    }
    assert!(
        outputs.len() > 10,
        "seeded runs should diverge; got {} distinct outputs",
        outputs.len()
    );
}

#[test]
fn e1_replay_is_idempotent() {
    // Replaying a prefix does not extend the journal (Lemma 5.3): strict
    // replay appends nothing, not even notes.
    let rt = Runtime::in_memory(SeededOracle::new(99));
    let recorded = rt.run("idem", agent).unwrap();
    let len = recorded.journal_len;
    let r1 = rt.replay("idem", agent).unwrap();
    let r2 = rt.replay("idem", agent).unwrap();
    assert_eq!(r1.journal_len, len);
    assert_eq!(r2.journal_len, len);
    assert_eq!(rt.snapshot("idem").unwrap().len(), len);
    assert_eq!(r1.trace, r2.trace);
}

// ---------------------------------------------------------------------
// Branch interleaving
// ---------------------------------------------------------------------

/// A sync agent with a parallel region whose children each make a
/// data-dependent number of draws.
fn fan_out(ctx: &mut Ctx) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan")?;
    let parts = ctx.parallel(3, |i, c| {
        let first = c.oracle(format!("child {i} of {plan}"))?;
        let extra = first.as_bytes().iter().map(|b| *b as usize).sum::<usize>() % 3;
        let mut last = first;
        for k in 0..extra {
            last = c.oracle(format!("child {i} refine {k}: {last}"))?;
        }
        Ok(last)
    })?;
    let joined: Vec<String> = parts.iter().map(|v| v.as_str().into_owned()).collect();
    ctx.oracle(format!("merge {}", joined.join("|")))
}

#[test]
fn e1_sync_regions_replay_exactly() {
    for seed in 0..200 {
        let rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(seed)));
        let recorded = rt.run("fan", fan_out).unwrap();
        let calls = rt.oracle().calls();
        let replayed = rt.replay("fan", fan_out).unwrap();
        assert_eq!(rt.oracle().calls(), calls, "seed {seed}");
        assert_eq!(
            keyed(&recorded.trace),
            keyed(&replayed.trace),
            "seed {seed}"
        );
        assert_eq!(recorded.output, replayed.output);
        // Every child's steps sit on its own branch.
        let branches: std::collections::BTreeSet<Vec<u32>> = recorded
            .trace
            .iter()
            .filter_map(|l| l.branch().cloned())
            .collect();
        assert!(branches.contains(&vec![0]) && branches.contains(&vec![2]));
    }
}

async fn async_fan_out(ctx: &mut AsyncCtx<'_, Staggered>) -> Result<Value, Fault> {
    let plan = ctx.oracle("plan").await?;
    let parts = ctx
        .parallel(4, |i, mut c| {
            let plan = plan.clone();
            async move {
                let a = c.oracle(format!("child {i} of {plan}")).await?;
                let b = c.oracle(format!("child {i} again: {a}")).await?;
                let t = c.now()?;
                Ok(Value::from(format!("{b}@{t}")))
            }
        })
        .await?;
    let joined: Vec<String> = parts.iter().map(|v| v.as_str().into_owned()).collect();
    Ok(Value::from(joined.join("|")))
}

/// True if the entries of some child branch are not contiguous in the
/// journal: another branch's entries sit between them.
fn interleaved(journal: &pragmatic::Journal) -> bool {
    let branches: Vec<Vec<u32>> = journal
        .program_entries()
        .iter()
        .map(|e| e.branch.clone())
        .filter(|b| !b.is_empty())
        .collect();
    let runs = 1 + branches.windows(2).filter(|w| w[0] != w[1]).count();
    let distinct: std::collections::HashSet<&Vec<u32>> = branches.iter().collect();
    runs > distinct.len()
}

#[test]
fn e1_async_regions_replay_under_a_different_interleaving() {
    let mut saw_interleaving = false;
    for seed in 0..100 {
        let rt = AsyncRuntime::in_memory(Staggered::new(seed));
        let recorded = block_on(rt.run("afan", async_fan_out)).unwrap();
        saw_interleaving |= interleaved(&rt.snapshot("afan").unwrap());
        let calls = rt.oracle().calls();
        // Replayed draws never yield, so the children run in another order.
        let replayed = block_on(rt.replay("afan", async_fan_out)).unwrap();
        assert_eq!(rt.oracle().calls(), calls, "seed {seed}");
        assert_eq!(
            keyed(&recorded.trace),
            keyed(&replayed.trace),
            "seed {seed}"
        );
        assert_eq!(recorded.output, replayed.output, "seed {seed}");
        // A resume of the finished run replays it too.
        let resumed = block_on(rt.resume("afan", async_fan_out)).unwrap();
        assert_eq!(resumed.output, recorded.output);
        assert_eq!(resumed.fresh_steps, 0);
    }
    assert!(saw_interleaving, "the children never interleaved");
}

fn lines(v: &Value) -> Vec<String> {
    v.as_str().split('\n').map(str::to_string).collect()
}

#[test]
fn e1_identical_prompt_best_of_n() {
    // Every child asks the same question. Positional matching per branch
    // gives each child back its own sample, not the first one recorded.
    fn best_of(ctx: &mut Ctx) -> Result<Value, Fault> {
        let samples = ctx.parallel(5, |_, c| c.oracle("write a haiku about logs"))?;
        let text: Vec<String> = samples.iter().map(|v| v.as_str().into_owned()).collect();
        Ok(Value::from(text.join("\n")))
    }
    let rt = Runtime::in_memory(CountingOracle::new(SeededOracle::new(17)));
    let recorded = rt.run("best", best_of).unwrap();
    let samples = lines(&recorded.output);
    assert_eq!(samples.len(), 5);
    let distinct: std::collections::HashSet<&String> = samples.iter().collect();
    assert_eq!(
        distinct.len(),
        5,
        "the sampler is stateful, so samples differ"
    );

    let replayed = rt.replay("best", best_of).unwrap();
    assert_eq!(rt.oracle().calls(), 5);
    assert_eq!(lines(&replayed.output), samples);
    for (i, sample) in samples.iter().enumerate() {
        let on_branch: Vec<&TraceLabel> = replayed
            .trace
            .iter()
            .filter(|l| l.branch() == Some(&vec![i as u32]))
            .collect();
        assert!(
            matches!(on_branch.as_slice(),
                [TraceLabel::Oracle { outcome, .. }] if outcome.as_str() == sample.as_str()),
            "child {i} got another child's sample"
        );
    }

    // The async version, with children whose model calls finish out of
    // index order.
    async fn best_of_async(ctx: &mut AsyncCtx<'_, Staggered>) -> Result<Value, Fault> {
        let samples = ctx
            .parallel(4, |_, mut c| async move { c.oracle("same prompt").await })
            .await?;
        let text: Vec<String> = samples.iter().map(|v| v.as_str().into_owned()).collect();
        Ok(Value::from(text.join("\n")))
    }
    let rt = AsyncRuntime::in_memory(Staggered::new(3));
    let recorded = block_on(rt.run("best", best_of_async)).unwrap();
    let samples = lines(&recorded.output);
    let replayed = block_on(rt.replay("best", best_of_async)).unwrap();
    for (i, sample) in samples.iter().enumerate() {
        assert_eq!(&lines(&replayed.output)[i], sample, "child {i}");
        let child = vec![i as u32];
        let label = replayed
            .trace
            .iter()
            .find(|l| l.branch() == Some(&child))
            .unwrap();
        assert!(
            matches!(label, TraceLabel::Oracle { outcome, .. } if outcome.as_str() == sample.as_str())
        );
    }
    assert_eq!(keyed(&recorded.trace), keyed(&replayed.trace));
}
