//! `Ctx`: the durable execution context handed to your agent.
//!
//! One code path, two semantics. Your agent calls `ctx.oracle(...)`,
//! `ctx.effect(...)`, `ctx.recv(...)`, `ctx.now()`; the context decides, per
//! step, whether the outcome is *replayed* from the journal ([O-rep],
//! [Eff-rep], [Rcv-rep]) or *recorded* fresh ([O-rec], [Eff-intent/commit],
//! [Rcv-rec]). A resumed run replays its surviving prefix and falls through
//! to recording at the tail ([O-resume]); the agent cannot tell the
//! difference, which is exactly Theorem T1's content.
//!
//! A `Ctx` is a branch of a [`Session`]: the root branch for the agent
//! itself, a child branch inside [`Ctx::parallel`]. Every step goes through
//! the session with the context's branch, so replay matches each branch's
//! steps on their own, whatever order the branches ran in.

use std::collections::{BTreeMap, HashSet};

use crate::fault::Fault;
use crate::journal::{Branch, Cursor};
use crate::json::Json;
use crate::oracle::Oracle;
use crate::session::{meta_outcome, DrawStart, EffectStart, Session, META_OK};
use crate::value::Value;

/// One observable step of a run. The trace is the object T1 speaks about:
/// record and replay produce identical labels, compared as `(branch,
/// cursor, label)`. A report's trace is sorted by cursor, so branches that
/// interleaved differently on record and on replay still compare equal.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceLabel {
    /// The model call whose intent is at `cursor` realized `outcome`.
    Oracle {
        branch: Branch,
        cursor: Cursor,
        outcome: Value,
    },
    /// The effect whose intent is at `cursor` committed `result`.
    Effect {
        branch: Branch,
        cursor: Cursor,
        name: String,
        result: Value,
    },
    /// A channel receive at `cursor`.
    Recv {
        branch: Branch,
        cursor: Cursor,
        channel: String,
        value: Value,
    },
    /// A journaled clock read.
    Clock {
        branch: Branch,
        cursor: Cursor,
        nanos: u64,
    },
    /// A journaled random draw.
    Random {
        branch: Branch,
        cursor: Cursor,
        source: String,
        value: Value,
    },
    /// The run halted with `output`.
    Done { output: Value },
}

impl TraceLabel {
    /// The cursor of the step, or `None` for [`TraceLabel::Done`].
    pub fn cursor(&self) -> Option<Cursor> {
        match self {
            TraceLabel::Oracle { cursor, .. }
            | TraceLabel::Effect { cursor, .. }
            | TraceLabel::Recv { cursor, .. }
            | TraceLabel::Clock { cursor, .. }
            | TraceLabel::Random { cursor, .. } => Some(*cursor),
            TraceLabel::Done { .. } => None,
        }
    }

    /// The branch of the step, or `None` for [`TraceLabel::Done`].
    pub fn branch(&self) -> Option<&Branch> {
        match self {
            TraceLabel::Oracle { branch, .. }
            | TraceLabel::Effect { branch, .. }
            | TraceLabel::Recv { branch, .. }
            | TraceLabel::Clock { branch, .. }
            | TraceLabel::Random { branch, .. } => Some(branch),
            TraceLabel::Done { .. } => None,
        }
    }
}

/// What to do when a recorded `Program` entry names the running program
/// but with a different hash (spec 2.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OnCodeChange {
    /// Fail with [`Fault::JournalDesync`] unless the hash is the recorded
    /// one, or one a `program.change` note already accepted for that entry.
    Refuse,
    /// Accept a changed hash under the same name. A recording attempt
    /// appends a `program.change` note before any fresh step; strict replay
    /// reports the change in
    /// [`RunReport::program_changes`](crate::RunReport::program_changes).
    Continue,
}

/// Per-run execution limits, grants (capabilities) and run metadata.
#[derive(Clone, Debug, Default)]
pub struct RunOptions {
    /// The most model calls the run may make. Replayed calls never count;
    /// the draws already in the journal at checkout do. `None` is
    /// unbounded. (Paper Remark 3.14: converts a runaway loop into a
    /// well-typed fault.)
    pub budget: Option<u64>,
    /// Effect names this run holds capabilities for. `None` = all effects
    /// allowed; `Some` = allowlist, anything else is `CapabilityDenied`.
    pub caps: Option<HashSet<String>>,
    /// The code-change policy; `None` is `Continue` for run and resume and
    /// `Refuse` for replay.
    pub on_code_change: Option<OnCodeChange>,
    /// Labels recorded in `run.start` when the run is created: at most 32,
    /// keys `[a-z0-9_.-]{1,64}`, values of at most 256 bytes. Labels are
    /// structural and never erased, so they must not hold personal data.
    pub labels: BTreeMap<String, String>,
    /// Data subjects of the run, recorded in an erasable payload slot of
    /// `run.start` when the run is created.
    pub subjects: Vec<String>,
    /// The agent program's `(name, hash)`, recorded in `attempt.start` for
    /// information. It does not make replay stricter; see
    /// [`Ctx::program_marker`] for that.
    pub program: Option<(String, String)>,
    /// The names of the request-normalization rules an SDK matches model
    /// calls under (spec 6.6), recorded in `attempt.start` so an auditor
    /// can see what replay loosened. Empty when requests are compared
    /// exactly, which is all the core does on its own.
    pub normalization: Vec<String>,
}

impl RunOptions {
    pub fn with_budget(mut self, draws: u64) -> Self {
        self.budget = Some(draws);
        self
    }

    pub fn with_caps<I: IntoIterator<Item = S>, S: Into<String>>(mut self, caps: I) -> Self {
        self.caps = Some(caps.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_on_code_change(mut self, policy: OnCodeChange) -> Self {
        self.on_code_change = Some(policy);
        self
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    pub fn with_subjects<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        subjects: I,
    ) -> Self {
        self.subjects = subjects.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_program(mut self, name: impl Into<String>, hash: impl Into<String>) -> Self {
        self.program = Some((name.into(), hash.into()));
        self
    }

    pub fn with_normalization<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        rules: I,
    ) -> Self {
        self.normalization = rules.into_iter().map(Into::into).collect();
        self
    }
}

/// The `meta` of a draw whose model call failed with `fault`: outcome
/// `error`, the fault's kind as `error_type` so replay raises the same
/// fault, and for a timeout the transport class `error_kind` (spec 2.6).
pub(crate) fn error_meta(fault: &Fault) -> String {
    let mut members = Vec::new();
    if *fault == Fault::Timeout {
        members.push(("error_kind".to_string(), Json::from("timeout")));
    }
    members.push(("error_type".to_string(), Json::from(fault.kind())));
    members.push(("outcome".to_string(), Json::from("error")));
    Json::Object(members).to_string()
}

/// The message recorded in the body of a failed draw.
pub(crate) fn error_body(fault: &Fault) -> Value {
    Value::from(fault.recorded_message())
}

/// The fault a recorded failed draw raises: the recorded fault when its
/// `error_type` is a core fault kind that carries no more than a message,
/// a timeout for the transport class `timeout`, and otherwise (other
/// faults, or a draw recorded by an SDK with its own error types)
/// [`Fault::OracleErr`] with the recorded message.
pub(crate) fn draw_failure(meta: &str, body: &Value) -> Fault {
    let meta = crate::journal::strict_json_field(meta);
    let field = |key: &str| {
        meta.as_ref()
            .and_then(|m| m.get(key).and_then(|v| v.as_str().map(str::to_string)))
    };
    let message = body.as_str();
    if let Some(fault) = field("error_type").and_then(|t| Fault::from_recorded(&t, &message)) {
        return fault;
    }
    if field("error_kind").as_deref() == Some("timeout") {
        return Fault::Timeout;
    }
    Fault::OracleErr(message.into_owned())
}

/// Record a failed model call at `intent` and return the fault the agent
/// gets: the one replay will raise, so the agent takes the same path on
/// record and on replay (T1). For every fault that carries no more than a
/// message that is the oracle's own fault.
pub(crate) fn failed_draw(
    session: &mut Session,
    intent: Cursor,
    fault: &Fault,
) -> Result<Fault, Fault> {
    let (meta, body) = (error_meta(fault), error_body(fault));
    session.draw_end(intent, meta.clone(), Value::default(), body.clone())?;
    Ok(draw_failure(&meta, &body))
}

/// The recorded `(error_kind, message)` of a fault raised by `perform`.
pub(crate) fn effect_failure(fault: &Fault) -> (String, String) {
    (fault.kind().to_string(), fault.recorded_message())
}

/// The fault a recorded failed effect raises: the recorded fault when its
/// `error_kind` is a core fault kind that carries no more than a message,
/// otherwise (other faults, or an exception type recorded by another SDK)
/// [`Fault::ToolErr`] with the recorded message (spec 2.12).
pub(crate) fn effect_fault(kind: &str, message: String) -> Fault {
    Fault::from_recorded(kind, &message).unwrap_or(Fault::ToolErr(message))
}

/// Record a failed effect at `intent` and return the fault the agent gets:
/// the one replay will raise (see [`failed_draw`]).
pub(crate) fn failed_effect(
    session: &mut Session,
    intent: Cursor,
    fault: &Fault,
) -> Result<Fault, Fault> {
    let (kind, message) = effect_failure(fault);
    session.effect_end(intent, Err((kind.clone(), message.clone())))?;
    Ok(effect_fault(&kind, message))
}

/// The response of a replayed draw: the body, or the recorded failure.
pub(crate) fn replayed_draw(meta: &str, body: Value) -> Result<Value, Fault> {
    if meta_outcome(meta).as_deref() == Some("error") {
        Err(draw_failure(meta, &body))
    } else {
        Ok(body)
    }
}

/// The durable execution context: one branch of one attempt.
pub struct Ctx<'a> {
    session: &'a mut Session,
    branch: Branch,
    oracle: &'a dyn Oracle,
}

impl<'a> Ctx<'a> {
    /// A context for `branch` of `session`, calling `oracle` for fresh
    /// model calls. [`Attempt::ctx`](crate::Attempt::ctx) builds the root
    /// context; hosts that drive a [`Session`] themselves can build their
    /// own.
    pub fn new(session: &'a mut Session, branch: Branch, oracle: &'a dyn Oracle) -> Ctx<'a> {
        Ctx {
            session,
            branch,
            oracle,
        }
    }

    /// The branch this context steps on.
    pub fn branch(&self) -> &Branch {
        &self.branch
    }

    /// The session, for split-phase steps (bindings that make model calls
    /// and perform effects themselves).
    pub fn session(&mut self) -> &mut Session {
        self.session
    }

    /// `let x ⇐ oracle(e)`: one model call, journaled once.
    ///
    /// The intent is persisted before the model is called and the response
    /// after; a failed call is recorded too, and the agent gets the fault
    /// replay will raise (the oracle's own, for any fault that carries no
    /// more than a message), so an agent that handles the error replays
    /// identically. Replay reads the recorded response back
    /// and never calls the model ([O-rep]); a resumed run switches from
    /// replay to recording exactly where the branch's journal ends
    /// ([O-resume]).
    pub fn oracle(&mut self, prompt: impl Into<Value>) -> Result<Value, Fault> {
        let prompt = prompt.into();
        let provenance = self.oracle.provenance();
        match self
            .session
            .draw_begin(&self.branch, &provenance, vec![prompt.clone()])?
        {
            DrawStart::Replayed { meta, body, .. } => replayed_draw(&meta, body),
            DrawStart::Fresh(intent) => match self.oracle.call(&prompt) {
                Ok(outcome) => {
                    self.session.draw_end(
                        intent,
                        META_OK.to_string(),
                        Value::default(),
                        outcome.clone(),
                    )?;
                    Ok(outcome)
                }
                Err(fault) => Err(failed_draw(self.session, intent, &fault)?),
            },
        }
    }

    /// Journal (or check) the identity of the agent program on this
    /// branch. Emitted automatically at the top of every
    /// `#[pragmatic::durable]` function; call it by hand if you don't use
    /// the macro.
    ///
    /// On record, appends `Program { name, hash }`. On replay, checks the
    /// recorded identity under the run's
    /// [`OnCodeChange`] policy: a changed program fails
    /// as [`Fault::JournalDesync`] *before* any step can misreplay, turning
    /// assumption A2 ("the same term is replayed") into an enforced
    /// property.
    pub fn program_marker(&mut self, name: &str, hash: &str) -> Result<(), Fault> {
        self.session.program_marker(&self.branch, name, hash)
    }

    /// `do[f] e`: a durable effect under the write-ahead discipline (paper
    /// §4.5):
    ///
    /// 1. [Eff-intent]  journal `EffectIntent` *before* touching the world;
    /// 2. [Eff-perform] run `perform` (your tool call or external write);
    /// 3. [Eff-commit]  journal `EffectResult` with the result, or with the
    ///    failure if `perform` returned an error.
    ///
    /// Replay reuses the recorded result and does **not** re-perform
    /// ([Eff-rep]); a recorded failure replays as the fault `perform`
    /// returned (or, for a fault that carries more than a message,
    /// [`Fault::ToolErr`] with its text, on record and replay alike). A crash between 1 and 3 leaves an intent
    /// without a result, which [`Runtime::resume`](crate::Runtime::resume)
    /// decides before re-entering: the no-orphaned-effect property.
    pub fn effect(
        &mut self,
        name: &str,
        arg: impl Into<Value>,
        perform: impl FnOnce(&Value) -> Result<Value, Fault>,
    ) -> Result<Value, Fault> {
        self.effect_keyed(name, arg, |arg, _key| perform(arg))
    }

    /// [`effect`](Self::effect), with `perform` also given the effect's
    /// idempotency key, `<run_id>/<branch>/<intent cursor>`. The key is the
    /// same whenever this intent is performed, so a downstream service can
    /// deduplicate a retry after a crash.
    pub fn effect_keyed(
        &mut self,
        name: &str,
        arg: impl Into<Value>,
        perform: impl FnOnce(&Value, &str) -> Result<Value, Fault>,
    ) -> Result<Value, Fault> {
        let arg = arg.into();
        match self.session.effect_begin(&self.branch, name, arg.clone())? {
            EffectStart::Replayed(result) => Ok(result),
            EffectStart::Failed { kind, message } => Err(effect_fault(&kind, message)),
            EffectStart::Fresh {
                intent,
                idempotency_key,
            } => match perform(&arg, &idempotency_key) {
                Ok(result) => {
                    self.session.effect_end(intent, Ok(result.clone()))?;
                    Ok(result)
                }
                Err(fault) => Err(failed_effect(self.session, intent, &fault)?),
            },
        }
    }

    /// `x ← c?`: receive on a channel. Receives are journaled because the
    /// value arrives from outside this replay scope (invariant I4); replay
    /// reads it back ([Rcv-rep]).
    pub fn recv(&mut self, channel: &str) -> Result<Value, Fault> {
        self.session.recv(&self.branch, channel)
    }

    /// A journaled clock read: time is externally determined, so it is
    /// recorded like any other draw and replays exactly.
    pub fn now(&mut self) -> Result<u64, Fault> {
        self.session.now(&self.branch)
    }

    /// A journaled random draw: `source` is `uuid4` (args `[]`), `random`
    /// (args `[]`), `randint` (args `[a, b]`) or `bytes` (args `[n]`). See
    /// [`Session::random`].
    pub fn random(&mut self, source: &str, args: &str) -> Result<Value, Fault> {
        self.session.random(&self.branch, source, args)
    }

    /// True if this run takes the patch `name` (spec 2.9): runs recorded
    /// before the patch existed keep their old path, new runs take the new
    /// one. See [`Session::patched`].
    pub fn patched(&mut self, name: &str) -> Result<bool, Fault> {
        self.session.patched(&self.branch, name)
    }

    /// Consume the marker of patch `name` if this run took it; never
    /// records one. Replaces [`patched`](Self::patched) once no run without
    /// the patch can still resume.
    pub fn deprecate_patch(&mut self, name: &str) -> Result<(), Fault> {
        self.session.deprecate_patch(&self.branch, name)
    }

    /// Run `n` children in a parallel region (spec 2.7), one after another,
    /// each on its own child branch. `f(i, ctx)` runs child `i`.
    ///
    /// Every child runs even when an earlier one fails, results come back
    /// in child order, and if any child failed the region fails with the
    /// failure of the lowest-index failed child. A child that returned ok
    /// must have replayed every step its branch recorded. While the region
    /// runs, this context's own branch is suspended.
    pub fn parallel<T>(
        &mut self,
        n: u32,
        mut f: impl FnMut(u32, &mut Ctx<'_>) -> Result<T, Fault>,
    ) -> Result<Vec<T>, Fault> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let children = self.session.fork(&self.branch, n)?;
        let mut results = Vec::with_capacity(children.len());
        for (i, child) in children.iter().enumerate() {
            let mut ctx = Ctx {
                session: &mut *self.session,
                branch: child.clone(),
                oracle: self.oracle,
            };
            results.push(f(i as u32, &mut ctx));
        }
        let ok: Vec<bool> = results.iter().map(Result::is_ok).collect();
        let joined = self.session.join_each(&self.branch, &children, &ok);
        lowest_failure(results, joined)
    }

    /// Assert an agent contract mid-run; a falsified contract is a
    /// well-typed `ContractViol` fault the Supervisor can dispatch on.
    pub fn contract(&self, holds: bool, msg: &str) -> Result<(), Fault> {
        if holds {
            Ok(())
        } else {
            Err(Fault::ContractViol(msg.to_string()))
        }
    }

    /// True while this branch's steps are served from the journal (useful
    /// for logging; agent logic should never branch on this).
    pub fn is_replaying(&self) -> bool {
        self.session.is_replaying(&self.branch)
    }
}

/// The values of a region, or the failure of its lowest-index failed child
/// (its own error, or the completeness check at join).
pub(crate) fn lowest_failure<T>(
    results: Vec<Result<T, Fault>>,
    joined: Vec<Result<(), Fault>>,
) -> Result<Vec<T>, Fault> {
    let mut out = Vec::with_capacity(results.len());
    for (result, join) in results.into_iter().zip(joined) {
        out.push(result?);
        join?;
    }
    Ok(out)
}
