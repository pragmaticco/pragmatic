# Concepts

Pragmatic implements the **Agentical** calculus: a probabilistic process
calculus for durable multi-agent LLM systems. This page maps the theory onto
the API you actually use.

## The problem shape

Durable execution engines (Temporal, Restate, DBOS…) give you
crash-recoverable workflows by replaying an event history - but their replay
model **assumes deterministic code**. LLM calls aren't deterministic, so
every engine isolates them as cached opaque "activities." That works, but
the engine has no model of the call: no probabilistic reasoning, no
information-flow guarantees, and replay stays sound only while you keep all
surrounding code deterministic by hand.

Pragmatic starts from the nondeterminism instead:

- an LLM call is a **draw from a probability distribution** (the Oracle);
- every realized draw is **journaled in the same atomic step it is
  consumed**;
- replay **reads outcomes back** rather than re-sampling.

Theorem **T1 (replay soundness)**: replaying a journal reproduces the
recorded run's trace exactly, with probability 1. Proved in the paper and
demonstrated empirically by this repo's E1 suite (1000/1000). A Lean 4
mechanization of the operational core is in progress: the model and the
theorem statements are formalized, the proof bodies are not yet discharged.

## The two modes

Every step your agent takes runs in one of two modes, chosen per step:

| | record (`[O-rec]`) | replay (`[O-rep]`) |
|---|---|---|
| `ctx.oracle(p)` | sample the model, append `OracleDraw` | read the recorded outcome; model not called |
| `ctx.effect(n, a, f)` | append intent → run `f` → append commit | return recorded commit; world not touched |
| `ctx.recv(c)` | pop inbox, append `ChannelRecv` | read the recorded value |
| `ctx.now()` | read clock, append `Clock` | read the recorded time |

A **resumed** run starts in replay against its surviving journal and falls
through to record exactly where the journal ends (`[O-resume]`). A **strict
replay** (`Runtime::replay`) never falls through - the oracle is replaced by
one that refuses, so "the model is never consulted" is enforced, not
promised.

## The Journal

Append-only, per-run, cursor-keyed. The key of an entry is just its position
- a monotone count, independent of any realized value, which is what makes
record and replay land on the same entry (paper Lemma 5.1; no hashes or
program counters in keys).

Entries form a hash chain: `h_i = H(h_{i-1} ‖ cursor ‖ payload)` with
SHA-256, or HMAC-SHA-256 under a runtime key (`Runtime::with_key`). Any
post-hoc edit breaks the chain at that cursor; `pragmatic verify` walks it.
On disk the journal is a length-prefixed append-only file; a crash mid-write
leaves a torn tail that is detected and truncated on open - after a crash,
the journal *is* its durable prefix (paper Def. 3.12).

## Durable effects and the crash window

External writes use a three-phase write-ahead discipline:

1. `EffectIntent` journaled **before** the world can change;
2. your closure performs the effect;
3. `EffectCommit` journaled with the result.

A crash between 1 and 3 leaves a **dangling intent** - the runtime knows the
effect *may* have happened but not whether it completed. On resume you
resolve it explicitly (`Runtime::resume_with`):

- `Recover::Commit(result)` - you checked the world (or the effect is
  idempotent and you re-ran it); replay will reuse this result.
- `Recover::Compensate` - write it off; the resumed run performs it fresh.

No effect is ever silently orphaned, and strict replay refuses to guess:
that's the **no-orphaned-effect** property (paper L4).

## Program identity (assumption A2, enforced)

T1 assumes the *same program* is replayed. `#[pragmatic::durable]` turns
that assumption into a check: it hashes the function's source tokens and
journals `Program { name, hash }` as step zero. Deploy a changed agent and
try to replay an old journal, and you get a `JournalDesync` fault at cursor
0 - before a single step can misreplay.

## Faults, the Supervisor, and capabilities

Failures are well-typed `Fault` values (`OracleErr`, `ToolErr`, `Timeout`,
`BudgetExhausted`, `ContractViol`, `CapabilityDenied`, …), and the
`Supervisor` maps them to decisions: **restart** (resume from the journal -
the transition T1 certifies), **compensate** (undo committed effects in
reverse, journaled so replay never double-undoes), **escalate**, or
**stop**.

Two capability types bound a run (`RunOptions`): a **budget** on oracle
draws (a runaway loop becomes a `BudgetExhausted` fault with a defined
supervisor response) and an **effect allowlist** (an agent without the
`charge_card` capability cannot even journal the intent).

## Memory and information flow

`Store` is a labeled key-value memory over the two-point lattice
`Low ⊑ High`: no read-up, no write-down. This is the runtime discipline
behind **T2 (probabilistic noninterference)** - secret inputs cannot flow
into public observations. Memory is internally determined, so it is *not*
journaled; replay reconstructs it by re-execution.

## Sync, async, Python - one semantics

The record/replay primitives live in one place (the attempt's `Session`:
`draw_begin`/`draw_end`, `effect_begin`/`effect_end`, `recv`, `now`,
`random`, `fork`/`join`) and every surface - sync `Ctx`, async `AsyncCtx`,
and the Python `Ctx` - drives those same primitives. Strict replay's "the model is never called"
holds identically everywhere because the mode check runs *before* the
fresh-sample path, not because an oracle was swapped out. Journals are
byte-compatible across all three surfaces and the CLI.

## What's deliberately out of scope (v0.4)

- **Distributed journals**: one process, local files. The managed/cloud
  backend (hosted journaling, shared console, alerting) is the commercial
  layer on top.
- **Lean mechanization**: T1/T2/T3 are proved on paper and enforced in the
  runtime. The Lean 4 development formalizes the model and states T1, but no
  theorem is machine-checked yet.
