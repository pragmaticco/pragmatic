//! The **Session**: everything one attempt of one run knows (spec 3.1).
//!
//! A session owns the checked-out journal, the sink that persists it and the
//! guard that holds the run, plus the replay indexes the primitives match
//! against. Every journaled primitive takes the branch it runs on, so the
//! same session serves the root of an agent and every child of its parallel
//! regions.
//!
//! # Replay matching (spec 2.7, 2.8)
//!
//! When a session opens, each program branch is indexed into its *start
//! events* (everything except `DrawResult`, `EffectResult` and `Note`).
//! Start events are matched positionally per branch; completions are found
//! through their `intent` reference, so several intents may be open on one
//! branch at once. A step whose branch still has unconsumed start events is
//! replayed; a step at the end of its branch is recorded (or, in strict
//! replay, raises [`Fault::ReplayExhausted`]).
//!
//! # Durability (spec 3.2)
//!
//! A primitive appends its entry and persists it through the sink before it
//! returns, so nothing reaches the agent that the journal could lose. Draw
//! and effect intents are persisted before the model is called or the effect
//! performed. The first persist error makes the session *failed*: every
//! later primitive returns that fault without touching the journal, no
//! `attempt.end` is written, and the next attempt starts from what was
//! durable.
//!
//! # Refusals (spec 2.6)
//!
//! Some steps fail without touching the world: a receive that finds its
//! inbox empty, a draw over the budget, an effect the run has no
//! capability for. An agent may handle such a fault and carry on (wait for
//! an approval, else proceed; draw until the budget runs out), so the fault
//! is part of what the agent observed and replay must raise it again. It is
//! journaled as a `Refusal`, but only once the agent carries on past it:
//! just before the next start event on its branch or on an ancestor branch,
//! or before `attempt.end` when the agent returns ok. A refusal the agent
//! did not carry on past is never written, so a resumed run tries the step
//! again (the message may have arrived, the budget may have been raised).
//!
//! # Notes (spec 2.11)
//!
//! A recording attempt writes `run.start` (only into an empty journal),
//! `attempt.start`, the recovery decisions of a resume, the agent's steps
//! (with `program.change` when a changed program is accepted) and finally
//! `attempt.end`. Strict replay appends nothing.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::backend::{CheckoutGuard, Sink};
use crate::ctx::{OnCodeChange, RunOptions, TraceLabel};
use crate::fault::Fault;
use crate::journal::{
    note, refusal, Branch, Content, Cursor, EffectOutcome, Entry, Event, Journal, TornTail, FORMAT,
    FORMAT1_READ_ONLY, MAX_DEPTH, MAX_SLOT_BYTES, META, META_ID, ROOT,
};
use crate::json::Json;
use crate::sha256::Digest;
use crate::value::Value;

/// Values delivered to a run's channels and not yet received.
pub(crate) type Inbox = Arc<Mutex<HashMap<String, VecDeque<Value>>>>;

/// What an attempt does with the run's journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Create the run if needed, replay its recorded prefix and record the
    /// rest.
    Run,
    /// Continue a crashed run: decide its open intents (recovery), replay
    /// the prefix and record the rest.
    Resume,
    /// Strict replay from a snapshot: no lock, nothing appended, and the
    /// model is never called.
    Replay,
}

impl Mode {
    /// The `mode` recorded in `attempt.start`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Run => "run",
            Mode::Resume => "resume",
            Mode::Replay => "replay",
        }
    }
}

/// How [`Session::draw_begin`] resolved a model call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrawStart {
    /// The journal holds the response; the model must not be called.
    /// `meta` is the recorded strict JSON metadata (`outcome` and friends).
    Replayed {
        intent: Cursor,
        head: Value,
        body: Value,
        meta: String,
    },
    /// The intent at this cursor is durable and the model must be called
    /// now. Finish with [`Session::draw_end`].
    Fresh(Cursor),
}

/// How [`Session::effect_begin`] resolved an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectStart {
    /// The effect completed in an earlier attempt with this result; it must
    /// not be performed again.
    Replayed(Value),
    /// The effect failed in an earlier attempt and the agent observed the
    /// failure, so it fails again identically: `kind` is the recorded error
    /// kind (the exception type, or the fault tag) and `message` its text.
    Failed { kind: String, message: String },
    /// The intent at `intent` is durable and the effect must be performed
    /// now, with `idempotency_key` (`<run_id>/<branch>/<intent cursor>`).
    /// Finish with [`Session::effect_end`].
    Fresh {
        intent: Cursor,
        idempotency_key: String,
    },
}

/// A recovery decision for an effect intent left open or failed by an
/// earlier attempt (spec 2.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recover {
    /// The effect completed (the world was checked, or it is idempotent and
    /// was re-run): record this result. Replay returns it without performing
    /// the effect again.
    Commit(Value),
    /// Write the effect off. The replayed program performs it again under a
    /// new intent. For a failed effect this is the default, and is recorded
    /// as a `retry`. It applies only to an intent at the frontier of its
    /// branch ([`RecoverRequest::at_frontier`]); one away from it is left
    /// undecided, and the replayed program meets it as
    /// [`Fault::DanglingEffect`].
    Compensate,
    /// Let a recorded failure stand, so replay fails the effect again. For
    /// an effect that has no result at all, record it as failed.
    Fail,
}

/// What a recovery policy is asked to decide.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct RecoverRequest<'a> {
    /// The effect's name.
    pub name: &'a str,
    /// The effect's argument.
    pub arg: &'a Value,
    /// The branch the intent is on.
    pub branch: &'a [u32],
    /// The intent's cursor.
    pub intent: Cursor,
    /// `None` for an intent with no result (the process died while the
    /// effect ran); `Some((error_kind, message))` for an intent whose latest
    /// result is a failure.
    pub failure: Option<(&'a str, &'a str)>,
    /// True if no step was recorded after the intent on its branch or on
    /// any branch above it. An intent away from the frontier can only be
    /// decided with [`Recover::Commit`] or [`Recover::Fail`]: steps recorded
    /// after it are in the way of a retry under a new intent, so
    /// [`Recover::Compensate`] leaves it undecided.
    pub at_frontier: bool,
}

/// A recovery policy: one decision per effect intent that needs one.
pub type RecoverPolicy<'p> = &'p mut dyn FnMut(&RecoverRequest<'_>) -> Recover;

/// A recorded program whose hash changed, accepted under
/// [`OnCodeChange::Continue`] (spec 2.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramChange {
    /// The branch of the `Program` entry.
    pub branch: Branch,
    /// The cursor of the `Program` entry.
    pub cursor: Cursor,
    /// The hash in effect before this attempt.
    pub from: String,
    /// The hash of the program now running.
    pub to: String,
}

/// Where a branch stands in this attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    /// Recorded in the journal, but not (yet) created by a fork in this
    /// attempt.
    Dormant,
    /// Steps may run on it.
    Active,
    /// It has an unjoined fork (rule 5).
    Suspended,
    /// Its region has joined (rule 6).
    Closed,
}

/// The replay position and region state of one branch.
#[derive(Debug)]
struct BranchState {
    /// Start events on the branch, in cursor order: the recorded prefix and
    /// then everything appended in this attempt.
    starts: Vec<Cursor>,
    /// Starts below this index are consumed.
    pos: usize,
    /// The base the next fork on this branch numbers its children from.
    next_child: u32,
    status: Status,
    /// The children of the unjoined fork, while suspended.
    region: Vec<Branch>,
}

impl BranchState {
    fn new(status: Status) -> BranchState {
        BranchState {
            starts: Vec::new(),
            pos: 0,
            next_child: 0,
            status,
            region: Vec::new(),
        }
    }

    fn peek(&self) -> Option<Cursor> {
        self.starts.get(self.pos).copied()
    }
}

/// True for the events that are matched positionally on replay.
fn is_start(event: &Event) -> bool {
    !matches!(
        event,
        Event::DrawResult { .. }
            | Event::EffectResult { .. }
            | Event::Note { .. }
            | Event::Legacy(_)
    )
}

/// The structural description of a recorded entry used in desync messages:
/// kinds and fields only, never slot content, because fault text ends up in
/// logs and terminals.
fn describe(event: &Event) -> String {
    match event {
        Event::DrawIntent { parts, .. } => format!("DrawIntent({} request parts)", parts.len()),
        Event::DrawResult { intent, .. } => format!("DrawResult(intent {intent})"),
        Event::ChannelRecv { channel, .. } => format!("ChannelRecv({channel})"),
        Event::EffectIntent { name, .. } => format!("EffectIntent({name})"),
        Event::EffectResult {
            intent, outcome, ..
        } => format!("EffectResult(intent {intent}, {})", outcome.as_str()),
        Event::Clock { .. } => "Clock".to_string(),
        Event::Program { name, hash } => format!("Program({name}, {hash})"),
        Event::Fork { base, children } => format!("Fork(base {base}, {children} children)"),
        Event::Marker { name } => format!("Marker({name}): this run took patch '{name}'"),
        Event::Note { kind, .. } => format!("Note({kind})"),
        Event::Random { source, args, .. } => format!("Random({source}, {args})"),
        Event::Refusal { step, name, fault } => format!("Refusal({step} '{name}': {fault})"),
        other => other.kind_name().to_string(),
    }
}

/// A branch as the idempotency key and messages print it: indices joined
/// by `.`, the root as the empty string.
pub(crate) fn branch_text(branch: &[u32]) -> String {
    branch
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn branch_json(branch: &[u32]) -> Json {
    Json::Array(branch.iter().map(|&i| Json::from(i)).collect())
}

/// A compact JSON object with its keys sorted by their UTF-8 bytes (the
/// canonical serialization of spec 3.7).
fn object(mut members: Vec<(&str, Json)>) -> String {
    members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Json::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
    .to_string()
}

fn note_event(kind: &str, data: String, payload: Vec<Value>) -> Event {
    Event::Note {
        kind: kind.to_string(),
        data,
        payload: payload.into_iter().map(Content::Sealed).collect(),
    }
}

/// The SDK name recorded in `run.start` and `attempt.start`.
const SDK: &str = "pragmatic-rust";

/// The `meta` of a draw that returned normally.
pub(crate) const META_OK: &str = r#"{"outcome":"ok"}"#;

/// The recorded outcome of a draw: `ok`, `error` or `partial`.
pub(crate) fn meta_outcome(meta: &str) -> Option<String> {
    let doc = crate::journal::strict_json_field(meta)?;
    doc.get("outcome")?.as_str().map(str::to_string)
}

/// Check the options of an attempt before anything is checked out or
/// created, so a refused run leaves nothing behind.
pub(crate) fn check_options(opts: &RunOptions) -> Result<(), Fault> {
    check_labels(&opts.labels)
}

/// Check run labels against spec 2.11: at most 32 pairs, keys
/// `[a-z0-9_.-]{1,64}`, values of at most 256 bytes.
fn check_labels(labels: &BTreeMap<String, String>) -> Result<(), Fault> {
    if labels.len() > 32 {
        return Err(Fault::Unsupported("a run has at most 32 labels".into()));
    }
    for (k, v) in labels {
        let key_ok = !k.is_empty()
            && k.len() <= 64
            && k.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
            });
        if !key_ok {
            return Err(Fault::Unsupported(format!(
                "label key '{k}' must be 1 to 64 characters from a-z, 0-9, '_', '.' and '-'"
            )));
        }
        if v.len() > 256 {
            return Err(Fault::Unsupported(format!(
                "the value of label '{k}' is longer than 256 bytes"
            )));
        }
    }
    Ok(())
}

/// All per-attempt state of one run. See the module documentation.
pub struct Session {
    run_id: String,
    mode: Mode,
    journal: Journal,
    /// Persists new frames; `None` in strict replay.
    sink: Option<Box<dyn Sink>>,
    /// Holds the run's lock or lease. Never read: dropping the session
    /// drops it, which releases the run.
    _guard: Option<CheckoutGuard>,
    /// The sticky fault of a failed persist.
    failed: Option<Fault>,
    branches: HashMap<Branch, BranchState>,
    /// The latest completion of every intent: intent cursor to result cursor.
    results: HashMap<Cursor, Cursor>,
    /// Intents this attempt opened (or re-issued) and has not completed,
    /// with their branches.
    open: BTreeMap<Cursor, Branch>,
    /// Frontier draws whose latest result is an error, re-issued on resume.
    reissue: HashSet<Cursor>,
    /// The hashes `program.change` notes accepted for each `Program` entry,
    /// in note order.
    accepted: HashMap<Cursor, Vec<String>>,
    on_code_change: OnCodeChange,
    budget: Option<u64>,
    /// `DrawIntent` entries in the journal when the session opened.
    draws_at_checkout: u64,
    /// `DrawIntent` entries appended by this attempt.
    fresh_intents: u64,
    caps: Option<HashSet<String>>,
    inbox: Option<Inbox>,
    clock: fn() -> u64,
    trace: Vec<TraceLabel>,
    replayed: u64,
    fresh: u64,
    program_changes: Vec<ProgramChange>,
    /// This attempt's number; 0 in strict replay.
    attempt: u64,
    /// Branches that ended in a fault: exempt from completeness, with their
    /// descendants.
    faulted: HashSet<Branch>,
    /// Refusals not journaled yet, in the order they happened, with their
    /// branches (see the module documentation).
    refusals: Vec<(Branch, Event)>,
    /// Messages taken off the inbox whose `ChannelRecv` is appended but not
    /// yet known to be durable: `(cursor, channel, value)`. Only a session
    /// whose sink is detached has any (see [`detach_sink`]); they go back
    /// to the front of their channels if the persist fails or the attempt
    /// is abandoned.
    ///
    /// [`detach_sink`]: Session::detach_sink
    unconfirmed: Vec<(Cursor, String, Value)>,
}

impl fmt::Debug for Session {
    /// Shape only, never content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("run_id", &self.run_id)
            .field("mode", &self.mode)
            .field("journal", &self.journal)
            .field("failed", &self.failed)
            .field("attempt", &self.attempt)
            .finish()
    }
}

impl Session {
    /// A session over `journal`. A recording session (`Run` or `Resume`)
    /// takes the checkout's sink and guard; strict replay has neither.
    pub(crate) fn new(
        run_id: &str,
        mode: Mode,
        journal: Journal,
        checkout: Option<(Box<dyn Sink>, CheckoutGuard)>,
        opts: &RunOptions,
        inbox: Option<Inbox>,
    ) -> Result<Session, Fault> {
        if journal.format() != FORMAT {
            return Err(Fault::Unsupported(FORMAT1_READ_ONLY.into()));
        }
        if mode != Mode::Replay && checkout.is_none() {
            return Err(Fault::Unsupported(
                "a recording session needs a checkout".into(),
            ));
        }
        check_labels(&opts.labels)?;
        let (sink, guard) = match checkout {
            Some((s, g)) => (Some(s), Some(g)),
            None => (None, None),
        };
        let default_policy = if mode == Mode::Replay {
            OnCodeChange::Refuse
        } else {
            OnCodeChange::Continue
        };
        let mut session = Session {
            run_id: run_id.to_string(),
            mode,
            journal,
            sink,
            _guard: guard,
            failed: None,
            branches: HashMap::new(),
            results: HashMap::new(),
            open: BTreeMap::new(),
            reissue: HashSet::new(),
            accepted: HashMap::new(),
            on_code_change: opts.on_code_change.unwrap_or(default_policy),
            budget: opts.budget,
            draws_at_checkout: 0,
            fresh_intents: 0,
            caps: opts.caps.clone(),
            inbox,
            clock: crate::journal::system_clock,
            trace: Vec::new(),
            replayed: 0,
            fresh: 0,
            program_changes: Vec::new(),
            attempt: 0,
            faulted: HashSet::new(),
            refusals: Vec::new(),
            unconfirmed: Vec::new(),
        };
        session.index();
        Ok(session)
    }

    /// Build the replay indexes from the journal (spec 2.7).
    fn index(&mut self) {
        self.branches
            .insert(ROOT.to_vec(), BranchState::new(Status::Active));
        for entry in self.journal.entries() {
            if entry.branch == META {
                if let Event::Note { kind, data, .. } = &entry.event {
                    if kind == note::PROGRAM_CHANGE {
                        if let Some((cursor, to)) = program_change_target(data) {
                            self.accepted.entry(cursor).or_default().push(to);
                        }
                    }
                }
                continue;
            }
            match &entry.event {
                Event::DrawResult { intent, .. } | Event::EffectResult { intent, .. } => {
                    // Reading and appending both refuse a result that names
                    // anything but an earlier intent of its kind on its
                    // branch; skipping one here keeps a journal built some
                    // other way from handing a step another step's record.
                    if completes(&self.journal, entry) {
                        self.results.insert(*intent, entry.cursor);
                    }
                }
                event if is_start(event) => {
                    if matches!(event, Event::DrawIntent { .. }) {
                        self.draws_at_checkout += 1;
                    }
                    self.branches
                        .entry(entry.branch.clone())
                        .or_insert_with(|| BranchState::new(Status::Dormant))
                        .starts
                        .push(entry.cursor);
                }
                _ => {}
            }
        }
    }

    /// Write the opening notes of a recording attempt and, on resume,
    /// decide the open intents (spec 2.11, 2.12), then persist all of it in
    /// one sync. Strict replay writes nothing.
    pub(crate) fn start(
        &mut self,
        opts: &RunOptions,
        torn: Option<&TornTail>,
        policy: Option<RecoverPolicy<'_>>,
        remote: bool,
    ) -> Result<(), Fault> {
        if self.mode == Mode::Replay {
            return Ok(());
        }
        if self.journal.is_empty() {
            if self.mode == Mode::Resume {
                // Only a run that started can be resumed. An empty journal is
                // what a run refused before its first entry (or a torn first
                // write) leaves behind; `run` starts it.
                return Err(Fault::Io(format!(
                    "run '{}' has not started (its journal has no entries); use run to start it",
                    self.run_id
                )));
            }
            let event = self.run_start(opts)?;
            self.append(META, event)?;
        }
        let earlier = self
            .journal
            .entries()
            .iter()
            .filter(|e| e.event.note_kind() == Some(note::ATTEMPT_START))
            .count() as u64;
        self.attempt = earlier + 1;
        let event = self.attempt_start(opts, torn);
        self.append(META, event)?;
        if self.mode == Mode::Resume {
            self.recover(policy, remote)?;
        }
        self.sync()
    }

    fn run_start(&self, opts: &RunOptions) -> Result<Event, Fault> {
        let mut nonce = [0u8; 16];
        crate::rand::fill(&mut nonce).map_err(|e| {
            Fault::Io(format!(
                "operating system random number generator failed: {e}"
            ))
        })?;
        let labels = Json::Object(
            opts.labels
                .iter()
                .map(|(k, v)| (k.clone(), Json::from(v.as_str())))
                .collect(),
        );
        let data = object(vec![
            ("format", Json::from(2u32)),
            ("labels", labels),
            ("nonce", hex_bytes(&nonce).into()),
            ("run_id", self.run_id.as_str().into()),
            ("sdk", SDK.into()),
            ("sdk_version", env!("CARGO_PKG_VERSION").into()),
        ]);
        let payload = if opts.subjects.is_empty() {
            Vec::new()
        } else {
            let subjects = Json::Array(
                opts.subjects
                    .iter()
                    .map(|s| Json::from(s.as_str()))
                    .collect(),
            );
            vec![Value::from(object(vec![("subjects", subjects)]))]
        };
        Ok(note_event(note::RUN_START, data, payload))
    }

    fn attempt_start(&self, opts: &RunOptions, torn: Option<&TornTail>) -> Event {
        let program = match &opts.program {
            Some((name, hash)) => Json::Object(vec![
                ("hash".into(), hash.as_str().into()),
                ("name".into(), name.as_str().into()),
            ]),
            None => Json::Null,
        };
        let data = object(vec![
            ("attempt", self.attempt.into()),
            ("host", crate::sys::host_name().into()),
            ("mode", self.mode.as_str().into()),
            ("pid", std::process::id().into()),
            ("principal", local_principal().into()),
            ("program", program),
            ("sdk", SDK.into()),
            ("sdk_version", env!("CARGO_PKG_VERSION").into()),
            (
                "torn_at_cursor",
                torn.map_or(Json::Null, |t| t.at_cursor.into()),
            ),
            ("torn_bytes", torn.map_or(0, |t| t.bytes).into()),
            ("traceparent", Json::Null),
        ]);
        note_event(note::ATTEMPT_START, data, Vec::new())
    }

    // -----------------------------------------------------------------
    // Recovery (spec 2.12)
    // -----------------------------------------------------------------

    /// Decide every effect intent an earlier attempt left without a result,
    /// every frontier effect whose latest result failed, and mark frontier
    /// draws whose latest result is an error for re-issue.
    ///
    /// Only a failure nothing observed is retried. A failure is observed
    /// when the agent recorded a step after it on its own branch, or on a
    /// branch above it (a parallel child that handled a failed call and
    /// returned, after which the parent carried on with the child's value),
    /// or when an attempt that saw it ended ok. Retrying an observed failure
    /// would change what the agent saw while the steps it took because of
    /// it stay in the journal, so the run could never replay again.
    fn recover(
        &mut self,
        mut policy: Option<RecoverPolicy<'_>>,
        remote: bool,
    ) -> Result<(), Fault> {
        let observed_upto = self.last_ok_end();
        let retryable = |result: Cursor| observed_upto.is_none_or(|end| result > end);
        // Effect intents that need a decision, in cursor order, with
        // whether each is at the frontier.
        let mut effects: Vec<(Cursor, bool)> = Vec::new();
        for entry in self.journal.entries() {
            let latest = self.results.get(&entry.cursor).copied();
            let latest_event = latest.and_then(|r| self.journal.get(r)).map(|e| &e.event);
            match &entry.event {
                Event::EffectIntent { .. } => {
                    let at_frontier = self.at_frontier(entry.cursor, &entry.branch);
                    let pending = match latest {
                        None => true,
                        Some(r) => {
                            at_frontier
                                && retryable(r)
                                && matches!(
                                    latest_event,
                                    Some(Event::EffectResult {
                                        outcome: EffectOutcome::Failed,
                                        ..
                                    })
                                )
                        }
                    };
                    if pending {
                        effects.push((entry.cursor, at_frontier));
                    }
                }
                Event::DrawIntent { .. } if self.at_frontier(entry.cursor, &entry.branch) => {
                    let errored = latest.is_some_and(retryable)
                        && matches!(
                            latest_event,
                            Some(Event::DrawResult { meta, .. })
                                if meta_outcome(meta).as_deref() == Some("error")
                        );
                    if errored {
                        self.reissue.insert(entry.cursor);
                    }
                }
                _ => {}
            }
        }
        for (intent, at_frontier) in effects {
            self.decide(intent, at_frontier, policy.as_deref_mut(), remote)?;
        }
        Ok(())
    }

    /// True if no start event follows `cursor` on `branch` or on any branch
    /// above it (spec 2.12): nothing the agent recorded can have depended on
    /// how the step at `cursor` ended.
    fn at_frontier(&self, cursor: Cursor, branch: &[u32]) -> bool {
        (0..=branch.len()).all(|k| {
            self.branches
                .get(&branch[..k])
                .and_then(|state| state.starts.last())
                .is_none_or(|&last| last <= cursor)
        })
    }

    /// The cursor of the last `attempt.end` whose outcome is `ok`: every
    /// result before it was seen by an agent that then returned normally.
    fn last_ok_end(&self) -> Option<Cursor> {
        self.journal
            .entries()
            .iter()
            .rev()
            .filter(|e| e.event.note_kind() == Some(note::ATTEMPT_END))
            .find(|e| match &e.event {
                Event::Note { data, .. } => crate::journal::strict_json_field(data)
                    .and_then(|d| {
                        d.get("outcome")
                            .and_then(|o| o.as_str().map(str::to_string))
                    })
                    .is_some_and(|o| o == "ok"),
                _ => false,
            })
            .map(|e| e.cursor)
    }

    /// One recovery decision: ask the policy, append the effect's new result
    /// (if any) and the `recovery` note.
    ///
    /// An intent left without a result away from the frontier cannot be
    /// written off: its retry would be a fresh intent at the end of the
    /// branch, while replay meets the steps recorded after it first. Only
    /// an explicit `Commit` or `Fail` decides it; otherwise nothing is
    /// appended, the replayed program meets it as
    /// [`Fault::DanglingEffect`], and a later resume with a policy can
    /// still decide it.
    fn decide<'p>(
        &mut self,
        intent: Cursor,
        at_frontier: bool,
        policy: Option<&mut (dyn FnMut(&RecoverRequest<'_>) -> Recover + 'p)>,
        remote: bool,
    ) -> Result<(), Fault> {
        let entry = self.journal.get(intent).expect("intent exists").clone();
        let Event::EffectIntent { name, arg } = &entry.event else {
            unreachable!("only effect intents are decided")
        };
        let arg = match arg {
            Content::Sealed(v) => v.clone(),
            _ => return Err(Fault::Erased { cursor: intent }),
        };
        let prior = self.results.get(&intent).copied();
        let failure = match prior.and_then(|r| self.journal.get(r)).map(|e| &e.event) {
            Some(Event::EffectResult {
                error_kind,
                payload: Some(Content::Sealed(msg)),
                ..
            }) => Some((error_kind.clone(), msg.as_str().into_owned())),
            Some(Event::EffectResult { .. }) => {
                return Err(Fault::Erased {
                    cursor: prior.unwrap_or(intent),
                })
            }
            _ => None,
        };
        let decision = {
            let request = RecoverRequest {
                name,
                arg: &arg,
                branch: &entry.branch,
                intent,
                failure: failure.as_ref().map(|(k, m)| (k.as_str(), m.as_str())),
                at_frontier,
            };
            match policy {
                Some(p) => p(&request),
                None if failure.is_none() && remote => {
                    return Err(Fault::DanglingEffect { cursor: intent })
                }
                None if !at_frontier => return Ok(()),
                None => Recover::Compensate,
            }
        };
        let (result, label) = match (decision, &failure) {
            (Recover::Commit(v), _) => (self.effect_result(intent, Ok(v))?, "commit"),
            (Recover::Compensate, None) if !at_frontier => return Ok(()),
            (Recover::Compensate, None) => (self.effect_compensated(intent)?, "compensate"),
            (Recover::Compensate, Some(_)) => (self.effect_compensated(intent)?, "retry"),
            (Recover::Fail, None) => (
                self.effect_result(
                    intent,
                    Err((
                        "Dangling".to_string(),
                        "the effect was left without a result by a crash and recovery failed it"
                            .to_string(),
                    )),
                )?,
                "commit",
            ),
            (Recover::Fail, Some(_)) => (prior.expect("failed intents have a result"), "commit"),
        };
        let data = object(vec![
            ("branch", branch_json(&entry.branch)),
            ("decision", label.into()),
            ("intent", intent.into()),
            ("name", name.as_str().into()),
            ("result", result.into()),
        ]);
        self.append(META, note_event(note::RECOVERY, data, Vec::new()))?;
        Ok(())
    }

    fn effect_result(
        &mut self,
        intent: Cursor,
        outcome: Result<Value, (String, String)>,
    ) -> Result<Cursor, Fault> {
        let branch = self
            .journal
            .get(intent)
            .expect("intent exists")
            .branch
            .clone();
        let event = match outcome {
            Ok(v) => Event::EffectResult {
                intent,
                outcome: EffectOutcome::Ok,
                error_kind: String::new(),
                payload: Some(Content::Sealed(v)),
            },
            Err((kind, message)) => Event::EffectResult {
                intent,
                outcome: EffectOutcome::Failed,
                error_kind: kind,
                payload: Some(Content::Sealed(Value::from(message))),
            },
        };
        self.append(&branch, event)
    }

    fn effect_compensated(&mut self, intent: Cursor) -> Result<Cursor, Fault> {
        let branch = self
            .journal
            .get(intent)
            .expect("intent exists")
            .branch
            .clone();
        self.append(
            &branch,
            Event::EffectResult {
                intent,
                outcome: EffectOutcome::Compensated,
                error_kind: String::new(),
                payload: None,
            },
        )
    }

    // -----------------------------------------------------------------
    // Appending and persistence
    // -----------------------------------------------------------------

    /// Append an entry and keep the indexes current. The branch of a start
    /// event must already be indexed (it is the branch being stepped).
    ///
    /// A start event first journals the pending refusals it follows: those
    /// on its own branch and on the branches below it.
    fn append(&mut self, branch: &[u32], event: Event) -> Result<Cursor, Fault> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        if branch != META && is_start(&event) {
            self.flush_refusals(Some(branch))?;
        }
        self.append_entry(branch, event)
    }

    /// [`append`](Self::append) without journaling pending refusals.
    fn append_entry(&mut self, branch: &[u32], event: Event) -> Result<Cursor, Fault> {
        let start = branch != META && is_start(&event);
        let completes = match &event {
            Event::DrawResult { intent, .. } | Event::EffectResult { intent, .. } => Some(*intent),
            _ => None,
        };
        let cursor = self.journal.append(branch, event)?;
        if start {
            let state = self
                .branches
                .get_mut(branch)
                .expect("steps run on indexed branches");
            state.starts.push(cursor);
            state.pos = state.starts.len();
        }
        if let Some(intent) = completes {
            self.results.insert(intent, cursor);
        }
        Ok(cursor)
    }

    /// Journal the pending refusals on `scope` and every branch below it
    /// (all of them for `None`), in the order they happened.
    fn flush_refusals(&mut self, scope: Option<&[u32]>) -> Result<(), Fault> {
        let (due, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.refusals)
            .into_iter()
            .partition(|(b, _)| scope.is_none_or(|s| b.starts_with(s)));
        self.refusals = kept;
        for (b, event) in due {
            self.append_entry(&b, event)?;
        }
        Ok(())
    }

    /// Raise `fault` for a step refused without effect at the end of branch
    /// `b`, and remember the refusal so it is journaled once the agent
    /// carries on past it (see the module documentation). A refusal in the
    /// middle of a recorded branch, or in strict replay, is raised but never
    /// journaled: the branch is not being recorded there.
    fn refuse(&mut self, b: &Branch, step: &str, name: &str, fault: Fault) -> Fault {
        if !self.strict() && self.peek(b).is_none() {
            let event = Event::Refusal {
                step: step.to_string(),
                name: name.to_string(),
                fault: fault.kind().to_string(),
            };
            self.refusals.push((b.clone(), event));
        }
        fault
    }

    /// If the next start on `b` is a refusal of this step, consume it and
    /// return the fault it recorded, which the step raises again.
    fn replayed_refusal(&mut self, b: &Branch, step: &str, name: &str) -> Option<Fault> {
        let c = self.peek(b)?;
        let Event::Refusal {
            step: s,
            name: n,
            fault,
        } = self.event(c)
        else {
            return None;
        };
        if s != step || n != name {
            return None;
        }
        let fault = match fault.as_str() {
            refusal::TIMEOUT => Fault::Timeout,
            refusal::BUDGET_EXHAUSTED => Fault::BudgetExhausted,
            refusal::CAPABILITY_DENIED => Fault::CapabilityDenied(name.to_string()),
            _ => return Some(self.desync(c, format!("a refusal of {step}"))),
        };
        self.consume(b);
        self.replayed += 1;
        Some(fault)
    }

    /// Append and persist: the result of a step is released only after
    /// this returns.
    fn append_synced(&mut self, branch: &[u32], event: Event) -> Result<Cursor, Fault> {
        let cursor = self.append(branch, event)?;
        self.sync()?;
        Ok(cursor)
    }

    /// Persist every buffered frame through the sink, inline. A failure is
    /// sticky: the session is failed from then on (spec 3.2).
    pub fn sync(&mut self) -> Result<(), Fault> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        let Some(sink) = self.sink.as_mut() else {
            return Ok(());
        };
        let Some((at, frames, head)) = self.journal.pending() else {
            return Ok(());
        };
        let size = frames.len() as u64;
        let upto = self.journal.len();
        match sink.persist(at, frames, &head) {
            Ok(()) => {
                self.mark_persisted(upto);
                Ok(())
            }
            Err(e) => {
                let fault = e.into_fault(size);
                self.persist_failed(fault.clone());
                Err(fault)
            }
        }
    }

    /// The frames appended and not yet persisted: `(cursor of the first,
    /// frame bytes, head after them)`. For hosts that persist on a thread of
    /// their own; the primitives persist inline through the sink.
    pub fn unpersisted(&self) -> Option<(u64, Vec<u8>, Digest)> {
        self.journal
            .pending()
            .map(|(at, frames, head)| (at, frames.to_vec(), head))
    }

    /// Record that the first `upto_entries` entries are durable.
    pub fn mark_persisted(&mut self, upto_entries: u64) {
        self.journal.mark_persisted(upto_entries);
        self.unconfirmed.retain(|(c, _, _)| *c >= upto_entries);
    }

    /// Record that a persist done outside the session failed, which fails
    /// the session exactly as an inline persist error would. Messages whose
    /// receives were not durable go back to the front of their channels, so
    /// the next attempt receives them again (spec 3.1).
    pub fn persist_failed(&mut self, fault: Fault) {
        if self.failed.is_none() {
            self.failed = Some(fault);
        }
        self.requeue_unconfirmed();
    }

    /// Take the sink out of the session, for hosts that persist on a thread
    /// of their own (spec 6.2: an async binding persists on a dedicated
    /// executor so its event loop never blocks on storage).
    ///
    /// While the sink is detached, the primitives append their entries and
    /// return without persisting: the host takes the frames with
    /// [`unpersisted`](Self::unpersisted), persists them through the sink
    /// outside any lock on the session, and reports the outcome with
    /// [`mark_persisted`](Self::mark_persisted) or
    /// [`persist_failed`](Self::persist_failed). The durability rule is then
    /// the host's to keep: a step's value may be released only once
    /// [`Journal::persisted_len`] covers the step's entries, and a draw or
    /// effect may be performed only once its intent is durable. Reattach
    /// the sink with [`attach_sink`](Self::attach_sink) before the attempt
    /// finishes, so `attempt.end` is persisted inline.
    ///
    /// Returns `None` for a strict replay, which has no sink.
    pub fn detach_sink(&mut self) -> Option<Box<dyn Sink>> {
        self.sink.take()
    }

    /// Put back a sink taken with [`detach_sink`](Self::detach_sink).
    pub fn attach_sink(&mut self, sink: Box<dyn Sink>) {
        self.sink = Some(sink);
    }

    /// Put the messages of receives that never became durable back at the
    /// front of their channels, newest first so the oldest ends up first.
    pub(crate) fn requeue_unconfirmed(&mut self) {
        let Some(inbox) = &self.inbox else {
            self.unconfirmed.clear();
            return;
        };
        let mut inbox = lock_inbox(inbox);
        for (_, channel, value) in self.unconfirmed.drain(..).rev() {
            inbox.entry(channel).or_default().push_front(value);
        }
    }

    // -----------------------------------------------------------------
    // Branch checks and matching helpers
    // -----------------------------------------------------------------

    /// The checks every journaled step makes first: the session is not
    /// failed, and the branch is active (rules 5 and 6 of spec 2.7).
    fn enter(&self, b: &[u32]) -> Result<(), Fault> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        match self.branches.get(b).map(|s| s.status) {
            Some(Status::Active) => Ok(()),
            Some(Status::Suspended) | Some(Status::Closed) => Err(Fault::Unsupported(
                "branch is suspended in a parallel region".into(),
            )),
            _ => Err(Fault::Unsupported(format!(
                "branch [{}] was not created by a fork in this attempt",
                branch_text(b)
            ))),
        }
    }

    fn peek(&self, b: &[u32]) -> Option<Cursor> {
        self.branches.get(b).and_then(BranchState::peek)
    }

    fn consume(&mut self, b: &[u32]) {
        if let Some(state) = self.branches.get_mut(b) {
            state.pos += 1;
        }
    }

    fn event(&self, cursor: Cursor) -> &Event {
        &self
            .journal
            .get(cursor)
            .expect("indexed cursor exists")
            .event
    }

    fn desync(&self, cursor: Cursor, expected: impl Into<String>) -> Fault {
        Fault::JournalDesync {
            cursor,
            expected: expected.into(),
            found: describe(self.event(cursor)),
        }
    }

    fn exhausted(&self) -> Fault {
        Fault::ReplayExhausted {
            cursor: self.journal.len(),
        }
    }

    fn strict(&self) -> bool {
        self.mode == Mode::Replay
    }

    /// The content of a slot that replay compares or returns. Erased slots
    /// are never wildcards (spec 2.8).
    fn sealed(content: &Content, cursor: Cursor) -> Result<&Value, Fault> {
        match content {
            Content::Sealed(v) => Ok(v),
            _ => Err(Fault::Erased { cursor }),
        }
    }

    fn label(&mut self, label: TraceLabel) {
        self.trace.push(label);
    }

    // -----------------------------------------------------------------
    // Draws
    // -----------------------------------------------------------------

    /// Begin a model call on branch `b` with these request parts.
    ///
    /// Replay returns the recorded response; the model is not called. At
    /// the end of the branch the `DrawIntent` is appended and persisted
    /// before this returns [`DrawStart::Fresh`], so every model call is on
    /// record before it is made. An intent left without a result by a crash
    /// (or, on resume, a frontier intent whose result was an error) is
    /// re-issued: `Fresh` with the recorded intent's cursor.
    ///
    /// A fresh intent is refused with [`Fault::BudgetExhausted`] when the
    /// draws in the journal at checkout plus those opened in this attempt
    /// reach the budget. Replayed draws never charge the budget; a recorded
    /// refusal replays as the same fault.
    pub fn draw_begin(
        &mut self,
        b: &Branch,
        provenance: &str,
        parts: Vec<Value>,
    ) -> Result<DrawStart, Fault> {
        self.enter(b)?;
        if parts.is_empty() {
            return Err(Fault::Unsupported(
                "a draw needs at least one request part".into(),
            ));
        }
        if let Some(fault) = self.replayed_refusal(b, refusal::DRAW, "") {
            return Err(fault);
        }
        if let Some(c) = self.peek(b) {
            let Event::DrawIntent {
                parts: recorded, ..
            } = self.event(c)
            else {
                return Err(self.desync(c, "DrawIntent"));
            };
            for content in recorded {
                Self::sealed(content, c)?;
            }
            if recorded.len() != parts.len() {
                return Err(self.desync(c, format!("DrawIntent({} request parts)", parts.len())));
            }
            if let Some(k) = recorded
                .iter()
                .zip(&parts)
                .position(|(r, p)| r.value() != Some(p))
            {
                return Err(self.desync(
                    c,
                    format!(
                        "DrawIntent({} request parts) with a different part {k}",
                        parts.len()
                    ),
                ));
            }
            let Some(r) = self.results.get(&c).copied() else {
                if self.strict() {
                    return Err(Fault::ReplayExhausted { cursor: c });
                }
                // Dangling: the call is made again for the same intent.
                self.consume(b);
                self.open.insert(c, b.clone());
                return Ok(DrawStart::Fresh(c));
            };
            if !self.strict() && self.reissue.remove(&c) {
                self.consume(b);
                self.open.insert(c, b.clone());
                return Ok(DrawStart::Fresh(c));
            }
            let Event::DrawResult {
                meta, head, body, ..
            } = self.event(r)
            else {
                return Err(self.desync(r, format!("the DrawResult of the intent at {c}")));
            };
            let head = Self::sealed(head, r)?.clone();
            let body = Self::sealed(body, r)?.clone();
            let meta = meta.clone();
            self.consume(b);
            self.replayed += 1;
            if meta_outcome(&meta).as_deref() != Some("error") {
                self.label(TraceLabel::Oracle {
                    branch: b.clone(),
                    cursor: c,
                    outcome: body.clone(),
                });
            }
            return Ok(DrawStart::Replayed {
                intent: c,
                head,
                body,
                meta,
            });
        }
        if self.strict() {
            return Err(self.exhausted());
        }
        if let Some(limit) = self.budget {
            if self.draws_at_checkout + self.fresh_intents >= limit {
                return Err(self.refuse(b, refusal::DRAW, "", Fault::BudgetExhausted));
            }
        }
        let cursor = self.append(
            b,
            Event::DrawIntent {
                provenance: provenance.to_string(),
                parts: parts.into_iter().map(Content::Sealed).collect(),
            },
        )?;
        self.fresh_intents += 1;
        self.open.insert(cursor, b.clone());
        self.sync()?;
        Ok(DrawStart::Fresh(cursor))
    }

    /// Complete the draw at `intent`: append the `DrawResult` and persist
    /// it. Release the response to the agent only after this returns `Ok`.
    ///
    /// `meta` is strict JSON with at least `outcome` (`ok`, `error` or
    /// `partial`). A response too large to record is
    /// [`Fault::TooLarge`]: the call was paid for but is not on record, and
    /// the attempt should fail.
    pub fn draw_end(
        &mut self,
        intent: Cursor,
        meta: String,
        head: Value,
        body: Value,
    ) -> Result<(), Fault> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        let Some(branch) = self.open.get(&intent).cloned() else {
            return Err(Fault::Unsupported(format!(
                "no draw is open at cursor {intent}"
            )));
        };
        if !matches!(self.event(intent), Event::DrawIntent { .. }) {
            return Err(Fault::Unsupported(format!(
                "the intent at cursor {intent} is not a draw"
            )));
        }
        let Some(outcome) = meta_outcome(&meta) else {
            return Err(Fault::Unsupported(
                "draw meta must be strict JSON with an outcome".into(),
            ));
        };
        let ok = outcome != "error";
        let appended = self.append(
            &branch,
            Event::DrawResult {
                intent,
                meta,
                head: Content::Sealed(head),
                body: Content::Sealed(body.clone()),
            },
        );
        if let Err(fault) = appended {
            // The call was made (and paid for) but cannot be recorded: the
            // attempt cannot go on as if it had been (spec 2.15).
            self.failed = Some(fault.clone());
            return Err(fault);
        }
        self.open.remove(&intent);
        self.fresh += 1;
        self.sync()?;
        if ok {
            self.label(TraceLabel::Oracle {
                branch,
                cursor: intent,
                outcome: body,
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Effects
    // -----------------------------------------------------------------

    /// Begin an effect on branch `b`.
    ///
    /// The capability check comes first. Replay returns the recorded result
    /// ([`EffectStart::Replayed`]) or failure ([`EffectStart::Failed`]); an
    /// intent written off by recovery (`compensated`) is skipped together
    /// with its result and matching continues with the next start. At the
    /// end of the branch the `EffectIntent` is appended and persisted before
    /// this returns [`EffectStart::Fresh`]: the intent is durable before the
    /// world can change. An argument over the slot limit is
    /// [`Fault::TooLarge`] before anything is performed.
    pub fn effect_begin(
        &mut self,
        b: &Branch,
        name: &str,
        arg: Value,
    ) -> Result<EffectStart, Fault> {
        self.enter(b)?;
        if let Some(fault) = self.replayed_refusal(b, refusal::EFFECT, name) {
            return Err(fault);
        }
        if self.caps.as_ref().is_some_and(|caps| !caps.contains(name)) {
            let denied = Fault::CapabilityDenied(name.to_string());
            return Err(self.refuse(b, refusal::EFFECT, name, denied));
        }
        while let Some(c) = self.peek(b) {
            let Event::EffectIntent { name: n, arg: a } = self.event(c) else {
                return Err(self.desync(c, format!("EffectIntent({name})")));
            };
            if n != name {
                return Err(self.desync(c, format!("EffectIntent({name})")));
            }
            if Self::sealed(a, c)? != &arg {
                return Err(
                    self.desync(c, format!("EffectIntent({name}) with a different argument"))
                );
            }
            let Some(r) = self.results.get(&c).copied() else {
                return Err(if self.strict() {
                    Fault::ReplayExhausted { cursor: c }
                } else {
                    Fault::DanglingEffect { cursor: c }
                });
            };
            let Event::EffectResult {
                outcome,
                error_kind,
                payload,
                ..
            } = self.event(r)
            else {
                return Err(self.desync(r, format!("the EffectResult of the intent at {c}")));
            };
            match outcome {
                EffectOutcome::Compensated => {
                    // Written off; the next start is the retry.
                    self.consume(b);
                    continue;
                }
                EffectOutcome::Ok => {
                    let result =
                        Self::sealed(payload.as_ref().expect("ok has a payload"), r)?.clone();
                    self.consume(b);
                    self.replayed += 1;
                    self.label(TraceLabel::Effect {
                        branch: b.clone(),
                        cursor: c,
                        name: name.to_string(),
                        result: result.clone(),
                    });
                    return Ok(EffectStart::Replayed(result));
                }
                EffectOutcome::Failed => {
                    let message = Self::sealed(payload.as_ref().expect("failed has a payload"), r)?;
                    let failed = EffectStart::Failed {
                        kind: error_kind.clone(),
                        message: message.as_str().into_owned(),
                    };
                    self.consume(b);
                    self.replayed += 1;
                    return Ok(failed);
                }
            }
        }
        if self.strict() {
            return Err(self.exhausted());
        }
        let cursor = self.append(
            b,
            Event::EffectIntent {
                name: name.to_string(),
                arg: Content::Sealed(arg),
            },
        )?;
        self.open.insert(cursor, b.clone());
        self.sync()?;
        Ok(EffectStart::Fresh {
            intent: cursor,
            idempotency_key: format!("{}/{}/{cursor}", self.run_id, branch_text(b)),
        })
    }

    /// Complete the effect at `intent`: `Ok(result)`, or `Err((error_kind,
    /// message))` when perform raised. The result is appended and persisted
    /// before this returns.
    ///
    /// If `perform` succeeded but its result cannot be recorded, this
    /// returns [`Fault::EffectUnrecorded`] carrying the result, so the
    /// caller can log or reconcile what the world now holds (spec 3.2). That
    /// covers a failed persist, a session another branch's persist failed
    /// while the effect ran, and a result over the slot limit. In each case
    /// the session is failed: the effect is on record only as an intent,
    /// which the next attempt's recovery decides.
    pub fn effect_end(
        &mut self,
        intent: Cursor,
        outcome: Result<Value, (String, String)>,
    ) -> Result<(), Fault> {
        let Some(branch) = self.open.get(&intent).cloned() else {
            return Err(Fault::Unsupported(format!(
                "no effect is open at cursor {intent}"
            )));
        };
        let Event::EffectIntent { name, .. } = self.event(intent) else {
            return Err(Fault::Unsupported(format!(
                "the intent at cursor {intent} is not an effect"
            )));
        };
        let name = name.clone();
        let unrecorded = |fault: Fault, outcome: Option<Value>| match outcome {
            Some(result) => Fault::EffectUnrecorded {
                name: name.clone(),
                intent,
                result,
            },
            None => fault,
        };
        let ok = outcome.as_ref().ok().cloned();
        if let Some(f) = self.failed.clone() {
            return Err(unrecorded(f, ok));
        }
        if let Err(fault) = self.effect_result(intent, outcome) {
            self.failed = Some(fault.clone());
            return Err(unrecorded(fault, ok));
        }
        self.open.remove(&intent);
        if let Err(fault) = self.sync() {
            return Err(unrecorded(fault, ok));
        }
        if let Some(result) = ok {
            self.label(TraceLabel::Effect {
                branch,
                cursor: intent,
                name,
                result,
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Receives, clocks and random draws
    // -----------------------------------------------------------------

    /// Receive on `channel`: replayed from the journal, or taken from the
    /// run's inbox and recorded. An empty inbox is [`Fault::Timeout`], and a
    /// recorded refusal replays as one.
    ///
    /// The message stays in the inbox until its `ChannelRecv` is durable: a
    /// receive over the slot limit, or one whose persist fails, leaves it
    /// for the next receive or the next attempt.
    pub fn recv(&mut self, b: &Branch, channel: &str) -> Result<Value, Fault> {
        self.enter(b)?;
        if let Some(fault) = self.replayed_refusal(b, refusal::RECV, channel) {
            return Err(fault);
        }
        if let Some(c) = self.peek(b) {
            let Event::ChannelRecv { channel: ch, value } = self.event(c) else {
                return Err(self.desync(c, format!("ChannelRecv({channel})")));
            };
            if ch != channel {
                return Err(self.desync(c, format!("ChannelRecv({channel})")));
            }
            let value = Self::sealed(value, c)?.clone();
            self.consume(b);
            self.replayed += 1;
            self.label(TraceLabel::Recv {
                branch: b.clone(),
                cursor: c,
                channel: channel.to_string(),
                value: value.clone(),
            });
            return Ok(value);
        }
        if self.strict() {
            return Err(self.exhausted());
        }
        let front = self.inbox.as_ref().and_then(|inbox| {
            lock_inbox(inbox)
                .get(channel)
                .and_then(VecDeque::front)
                .cloned()
        });
        let Some(value) = front else {
            return Err(self.refuse(b, refusal::RECV, channel, Fault::Timeout));
        };
        let cursor = self.append_synced(
            b,
            Event::ChannelRecv {
                channel: channel.to_string(),
                value: Content::Sealed(value.clone()),
            },
        )?;
        // Durable now, so take it. Only the attempt holding the run receives
        // on its inbox, so the front is still this message. With the sink
        // detached the host persists later: the message is taken now (so a
        // second receive gets the next one) and put back if that persist
        // fails.
        if let Some(inbox) = &self.inbox {
            lock_inbox(inbox)
                .get_mut(channel)
                .and_then(VecDeque::pop_front);
        }
        if self.sink.is_none() && self.journal.persisted_len() <= cursor {
            self.unconfirmed
                .push((cursor, channel.to_string(), value.clone()));
        }
        self.label(TraceLabel::Recv {
            branch: b.clone(),
            cursor,
            channel: channel.to_string(),
            value: value.clone(),
        });
        Ok(value)
    }

    /// A journaled clock read in Unix nanoseconds.
    pub fn now(&mut self, b: &Branch) -> Result<u64, Fault> {
        self.enter(b)?;
        if let Some(c) = self.peek(b) {
            let Event::Clock { nanos } = *self.event(c) else {
                return Err(self.desync(c, "Clock"));
            };
            self.consume(b);
            self.replayed += 1;
            self.label(TraceLabel::Clock {
                branch: b.clone(),
                cursor: c,
                nanos,
            });
            return Ok(nanos);
        }
        if self.strict() {
            return Err(self.exhausted());
        }
        let nanos = (self.clock)();
        let cursor = self.append_synced(b, Event::Clock { nanos })?;
        self.label(TraceLabel::Clock {
            branch: b.clone(),
            cursor,
            nanos,
        });
        Ok(nanos)
    }

    /// Replace the clock [`now`](Self::now) records (tests, fixtures).
    pub fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }

    /// A journaled random draw (spec 2.6): `source` is `uuid4` (args `[]`),
    /// `random` (args `[]`, a float in [0, 1)), `randint` (args `[a, b]`,
    /// inclusive) or `bytes` (args `[n]`). Replay matches source and args
    /// exactly. Random draws are not subject to budget or capabilities.
    pub fn random(&mut self, b: &Branch, source: &str, args: &str) -> Result<Value, Fault> {
        self.enter(b)?;
        if let Some(c) = self.peek(b) {
            let Event::Random {
                source: s,
                args: a,
                value,
            } = self.event(c)
            else {
                return Err(self.desync(c, format!("Random({source}, {args})")));
            };
            if s != source || a != args {
                return Err(self.desync(c, format!("Random({source}, {args})")));
            }
            let value = Self::sealed(value, c)?.clone();
            self.consume(b);
            self.replayed += 1;
            self.label(TraceLabel::Random {
                branch: b.clone(),
                cursor: c,
                source: source.to_string(),
                value: value.clone(),
            });
            return Ok(value);
        }
        if self.strict() {
            return Err(self.exhausted());
        }
        let value = random_value(source, args)?;
        let cursor = self.append_synced(
            b,
            Event::Random {
                source: source.to_string(),
                args: args.to_string(),
                value: Content::Sealed(value.clone()),
            },
        )?;
        self.label(TraceLabel::Random {
            branch: b.clone(),
            cursor,
            source: source.to_string(),
            value: value.clone(),
        });
        Ok(value)
    }

    // -----------------------------------------------------------------
    // Parallel regions (spec 2.7)
    // -----------------------------------------------------------------

    /// Fork `n` child branches of `b`, numbered `b‖m .. b‖(m+n-1)` where `m`
    /// counts the children of every earlier fork on `b`. The `Fork` entry is
    /// appended (or, on replay, matched: `n` and `m` must equal the recorded
    /// values) and `b` is suspended until [`join`](Self::join).
    pub fn fork(&mut self, b: &Branch, n: u32) -> Result<Vec<Branch>, Fault> {
        self.enter(b)?;
        if n == 0 {
            return Err(Fault::Unsupported(
                "a parallel region needs at least one child".into(),
            ));
        }
        let base = self.branches[b].next_child;
        if let Some(c) = self.peek(b) {
            match *self.event(c) {
                Event::Fork {
                    base: rb,
                    children: rn,
                } if rb == base && rn == n => {}
                _ => return Err(self.desync(c, format!("Fork(base {base}, {n} children)"))),
            }
            self.consume(b);
            self.replayed += 1;
        } else {
            if self.strict() {
                return Err(self.exhausted());
            }
            if b.len() + 1 > MAX_DEPTH {
                return Err(Fault::Unsupported(
                    "parallel regions nest at most 32 deep".into(),
                ));
            }
            if u64::from(base) + u64::from(n) > u64::from(META_ID) {
                return Err(Fault::Unsupported(
                    "fork would number a child at or past 0xFFFF_FFFF".into(),
                ));
            }
            self.append_synced(b, Event::Fork { base, children: n })?;
        }
        let children: Vec<Branch> = (base..base + n)
            .map(|i| {
                let mut child = b.clone();
                child.push(i);
                child
            })
            .collect();
        for child in &children {
            let state = self
                .branches
                .entry(child.clone())
                .or_insert_with(|| BranchState::new(Status::Dormant));
            if state.status != Status::Dormant {
                return Err(Fault::Unsupported(format!(
                    "child branch [{}] was already used in this run",
                    branch_text(child)
                )));
            }
            state.status = Status::Active;
        }
        let parent = self.branches.get_mut(b).expect("entered");
        parent.next_child = base + n;
        parent.status = Status::Suspended;
        parent.region = children.clone();
        Ok(children)
    }

    /// Join the region `children` of `parent`. `ok[i]` says whether child
    /// `i` returned normally. Every child that returned ok must have
    /// consumed all of its recorded start events and completed every intent
    /// (completeness at join); children that failed are exempt. The
    /// children are closed and the parent resumes. Returns the failure of
    /// the lowest-index child that fails the check.
    pub fn join(&mut self, parent: &Branch, children: &[Branch], ok: &[bool]) -> Result<(), Fault> {
        self.join_each(parent, children, ok)
            .into_iter()
            .find_map(Result::err)
            .map_or(Ok(()), Err)
    }

    /// [`join`](Self::join), with the check's result for every child, in
    /// child order. Hosts that run the children themselves combine these
    /// with the children's own failures to raise the failure of the
    /// lowest-index failed child (rule 4 of spec 2.7).
    pub fn join_each(
        &mut self,
        parent: &Branch,
        children: &[Branch],
        ok: &[bool],
    ) -> Vec<Result<(), Fault>> {
        let region_ok = self.branches.get(parent).is_some_and(|s| {
            s.status == Status::Suspended && s.region == children && ok.len() == children.len()
        });
        if !region_ok {
            let fault = Fault::Unsupported(
                "join must name the children of the branch's open parallel region".into(),
            );
            return children.iter().map(|_| Err(fault.clone())).collect();
        }
        let mut out = Vec::with_capacity(children.len());
        for (child, &child_ok) in children.iter().zip(ok) {
            let check = match (&self.failed, child_ok) {
                (Some(f), _) => Err(f.clone()),
                (None, true) => self.check_branch_complete(child),
                (None, false) => Ok(()),
            };
            if !child_ok || check.is_err() {
                self.faulted.insert(child.clone());
            }
            if let Some(state) = self.branches.get_mut(child) {
                state.status = Status::Closed;
            }
            out.push(check);
        }
        let state = self.branches.get_mut(parent).expect("checked above");
        state.status = Status::Active;
        state.region.clear();
        out
    }

    /// Completeness of one branch: every recorded start consumed and every
    /// intent on it completed.
    fn check_branch_complete(&self, b: &[u32]) -> Result<(), Fault> {
        let Some(state) = self.branches.get(b) else {
            return Ok(());
        };
        if let Some(c) = state.peek() {
            return Err(self.desync(c, "end of branch"));
        }
        for &c in &state.starts {
            let intent = matches!(
                self.event(c),
                Event::DrawIntent { .. } | Event::EffectIntent { .. }
            );
            if intent && !self.results.contains_key(&c) {
                return Err(Fault::DanglingIntent { cursor: c });
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Patches and program identity (spec 2.9, 2.10)
    // -----------------------------------------------------------------

    /// `patched(name)`: true if this run takes the patch. A recorded
    /// `Marker{name}` is consumed (true); at the end of the branch a marker
    /// is appended (true); before any other recorded step nothing is
    /// consumed (false, the run predates the patch). Strict replay past the
    /// end of the branch is [`Fault::ReplayExhausted`].
    pub fn patched(&mut self, b: &Branch, name: &str) -> Result<bool, Fault> {
        self.enter(b)?;
        if let Some(c) = self.peek(b) {
            if matches!(self.event(c), Event::Marker { name: n } if n == name) {
                self.consume(b);
                self.replayed += 1;
                return Ok(true);
            }
            return Ok(false);
        }
        if self.strict() {
            return Err(self.exhausted());
        }
        self.append_synced(
            b,
            Event::Marker {
                name: name.to_string(),
            },
        )?;
        Ok(true)
    }

    /// `deprecate_patch(name)`: consume a recorded `Marker{name}` if it is
    /// next on the branch, otherwise do nothing. Never appends.
    pub fn deprecate_patch(&mut self, b: &Branch, name: &str) -> Result<(), Fault> {
        self.enter(b)?;
        if let Some(c) = self.peek(b) {
            if matches!(self.event(c), Event::Marker { name: n } if n == name) {
                self.consume(b);
                self.replayed += 1;
            }
        }
        Ok(())
    }

    /// Journal (or check) the identity of the program running on branch
    /// `b` (spec 2.10).
    ///
    /// A recorded `Program` with the same name and hash, or with a hash a
    /// `program.change` note accepted, matches. A changed hash under the same
    /// name is refused under [`OnCodeChange::Refuse`] and accepted under
    /// [`OnCodeChange::Continue`], which in a recording attempt appends a
    /// `program.change` note at once. A changed name, or a recorded step of
    /// another kind, is [`Fault::JournalDesync`] under both policies.
    pub fn program_marker(&mut self, b: &Branch, name: &str, hash: &str) -> Result<(), Fault> {
        self.enter(b)?;
        let Some(c) = self.peek(b) else {
            if self.strict() {
                return Err(self.exhausted());
            }
            self.append_synced(
                b,
                Event::Program {
                    name: name.to_string(),
                    hash: hash.to_string(),
                },
            )?;
            return Ok(());
        };
        let Event::Program { name: rn, hash: rh } = self.event(c) else {
            return Err(self.desync(c, format!("Program({name}, {hash})")));
        };
        if rn != name {
            return Err(self.desync(c, format!("Program({name}, {hash})")));
        }
        let accepted = self.accepted.get(&c);
        let current = accepted.and_then(|a| a.last()).unwrap_or(rh).clone();
        if rh == hash || accepted.is_some_and(|a| a.iter().any(|h| h == hash)) {
            self.consume(b);
            self.replayed += 1;
            return Ok(());
        }
        if self.on_code_change == OnCodeChange::Refuse {
            return Err(Fault::JournalDesync {
                cursor: c,
                expected: format!("Program({name}, {hash})"),
                found: format!(
                    "Program({rn}, {rh}): the source of '{name}' changed since this run was \
                     recorded; pass on_code_change='continue' to replay recorded runs under \
                     changed code"
                ),
            });
        }
        let change = ProgramChange {
            branch: b.clone(),
            cursor: c,
            from: current,
            to: hash.to_string(),
        };
        if !self.strict() {
            let data = object(vec![
                ("branch", branch_json(b)),
                ("cursor", c.into()),
                ("from", change.from.as_str().into()),
                ("to", change.to.as_str().into()),
            ]);
            self.append_synced(META, note_event(note::PROGRAM_CHANGE, data, Vec::new()))?;
            self.accepted.entry(c).or_default().push(hash.to_string());
        }
        self.program_changes.push(change);
        self.consume(b);
        self.replayed += 1;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Inspection
    // -----------------------------------------------------------------

    /// True while branch `b` still has recorded steps to replay.
    pub fn is_replaying(&self, b: &Branch) -> bool {
        self.peek(b).is_some()
    }

    /// The entry at `cursor`.
    pub fn entry(&self, cursor: Cursor) -> Option<&Entry> {
        self.journal.get(cursor)
    }

    /// The journal as this session sees it.
    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// The run id.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The attempt's mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The sticky fault, once a persist has failed.
    pub fn failure(&self) -> Option<&Fault> {
        self.failed.as_ref()
    }

    // -----------------------------------------------------------------
    // The end of an attempt
    // -----------------------------------------------------------------

    /// End the attempt with the agent's result: check completeness when it
    /// returned ok, write `attempt.end` (recording attempts) and persist.
    /// Returns the output, or the fault the attempt ended with.
    pub(crate) fn end(&mut self, result: Result<Value, Fault>) -> Result<Value, Fault> {
        if let Some(f) = self.failed.clone() {
            return Err(result.err().unwrap_or(f));
        }
        let result = match result {
            Ok(v) => self.check_complete().map(|()| v),
            Err(e) => Err(e),
        };
        if self.strict() {
            return result;
        }
        // The agent returned ok, so it carried on past every refusal it saw.
        // A failed attempt drops them: the resumed run tries those steps
        // again.
        let result = match result {
            Ok(v) => self.flush_refusals(None).map(|()| v),
            Err(e) => Err(e),
        };
        let event = self.attempt_end(&result);
        let written = self.append(META, event).and_then(|_| self.sync());
        match (result, written) {
            (Ok(_), Err(f)) => Err(f),
            (result, _) => result,
        }
    }

    /// Completeness at the agent's return: every start event on every
    /// branch that did not end in a fault is consumed (else
    /// `JournalDesync` at the first unconsumed one), then no intent anywhere
    /// is left without a result (else `DanglingIntent`).
    fn check_complete(&self) -> Result<(), Fault> {
        let exempt = |b: &Branch| (0..=b.len()).any(|k| self.faulted.contains(&b[..k]));
        let first = self
            .branches
            .iter()
            .filter(|(b, _)| !exempt(b))
            .filter_map(|(_, s)| s.peek())
            .min();
        if let Some(c) = first {
            return Err(self.desync(c, "end of branch"));
        }
        let dangling = self
            .journal
            .entries()
            .iter()
            .filter(|e| {
                matches!(
                    e.event,
                    Event::DrawIntent { .. } | Event::EffectIntent { .. }
                )
            })
            .find(|e| !self.results.contains_key(&e.cursor));
        if let Some(e) = dangling {
            return Err(Fault::DanglingIntent { cursor: e.cursor });
        }
        Ok(())
    }

    fn attempt_end(&self, result: &Result<Value, Fault>) -> Event {
        let (outcome, kind, cursor, payload) = match result {
            Ok(v) => ("ok", Json::Null, Json::Null, vec![v.clone()]),
            Err(f) => (
                "fault",
                Json::from(f.kind()),
                f.cursor().map_or(Json::Null, Json::from),
                vec![Value::default(), Value::from(f.to_string())],
            ),
        };
        let data = object(vec![
            ("attempt", self.attempt.into()),
            ("fault_cursor", cursor),
            ("fault_kind", kind),
            ("fresh", self.fresh.into()),
            ("outcome", outcome.into()),
            ("passthrough_calls", 0u64.into()),
            ("replayed", self.replayed.into()),
            ("usage_fresh", Json::Object(Vec::new())),
        ]);
        note_event(note::ATTEMPT_END, data, payload)
    }

    /// The trace (sorted by cursor, `Done` last), counts and program changes
    /// of a finished attempt.
    pub(crate) fn into_report(mut self, output: Value) -> crate::runtime::RunReport {
        self.trace
            .sort_by_key(|l| l.cursor().unwrap_or(Cursor::MAX));
        self.trace.push(TraceLabel::Done {
            output: output.clone(),
        });
        crate::runtime::RunReport {
            run_id: self.run_id.clone(),
            output,
            trace: std::mem::take(&mut self.trace),
            journal_len: self.journal.len(),
            chain_head: Some(self.journal.head()),
            replayed_steps: self.replayed,
            fresh_steps: self.fresh,
            program_changes: std::mem::take(&mut self.program_changes),
        }
    }
}

fn lock_inbox(inbox: &Inbox) -> std::sync::MutexGuard<'_, HashMap<String, VecDeque<Value>>> {
    inbox.lock().unwrap_or_else(|e| e.into_inner())
}

/// True if `entry` is a result that completes an earlier intent of its kind
/// on its own branch (the rule [`Journal::append`] and [`Journal::parse`]
/// enforce).
fn completes(journal: &Journal, entry: &Entry) -> bool {
    let (intent, draw) = match &entry.event {
        Event::DrawResult { intent, .. } => (*intent, true),
        Event::EffectResult { intent, .. } => (*intent, false),
        _ => return false,
    };
    journal
        .get(intent)
        .filter(|t| t.cursor < entry.cursor && t.branch == entry.branch)
        .is_some_and(|t| match t.event {
            Event::DrawIntent { .. } => draw,
            Event::EffectIntent { .. } => !draw,
            _ => false,
        })
}

/// `(cursor, to)` of a `program.change` note's data.
fn program_change_target(data: &str) -> Option<(Cursor, String)> {
    let doc = crate::journal::strict_json_field(data)?;
    Some((
        doc.get("cursor")?.as_u64()?,
        doc.get("to")?.as_str()?.to_string(),
    ))
}

/// The local principal recorded in `attempt.start`: the OS user and host,
/// never a name or an email address.
fn local_principal() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    format!("local:{user}@{}", crate::sys::host_name())
}

/// Lowercase hex of any byte string.
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn os_random(buf: &mut [u8]) -> Result<(), Fault> {
    crate::rand::fill(buf).map_err(|e| {
        Fault::Io(format!(
            "operating system random number generator failed: {e}"
        ))
    })
}

fn random_u64() -> Result<u64, Fault> {
    let mut b = [0u8; 8];
    os_random(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Draw a fresh value for a `Random` entry from the OS CSPRNG.
fn random_value(source: &str, args: &str) -> Result<Value, Fault> {
    let bad = |m: &str| Fault::Unsupported(format!("random '{source}': {m}"));
    let parsed =
        crate::journal::strict_json_field(args).ok_or_else(|| bad("args must be strict JSON"))?;
    let list = parsed
        .as_array()
        .ok_or_else(|| bad("args must be a JSON array"))?;
    match source {
        "uuid4" | "random" if !list.is_empty() => Err(bad("args must be []")),
        "uuid4" => {
            let mut b = [0u8; 16];
            os_random(&mut b)?;
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
            let h = hex_bytes(&b);
            Ok(Value::from(format!(
                "{}-{}-{}-{}-{}",
                &h[..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..]
            )))
        }
        "random" => {
            let x = (random_u64()? >> 11) as f64 / (1u64 << 53) as f64;
            Ok(Value::from(format!("{x}")))
        }
        "randint" => {
            let (Some(a), Some(z)) = (
                list.first().and_then(Json::as_i64),
                list.get(1).and_then(Json::as_i64),
            ) else {
                return Err(bad("args must be [a, b] with integers a <= b"));
            };
            if list.len() != 2 || a > z {
                return Err(bad("args must be [a, b] with integers a <= b"));
            }
            let span = (i128::from(z) - i128::from(a) + 1) as u128;
            let offset = if span > u128::from(u64::MAX) {
                u128::from(random_u64()?)
            } else {
                // Rejection sampling keeps every value equally likely.
                let zone = (1u128 << 64) / span * span;
                loop {
                    let x = u128::from(random_u64()?);
                    if x < zone {
                        break x % span;
                    }
                }
            };
            Ok(Value::from((i128::from(a) + offset as i128).to_string()))
        }
        "bytes" => {
            let n = match list {
                [n] => n.as_u64().ok_or_else(|| bad("args must be [n]"))?,
                _ => return Err(bad("args must be [n]")),
            };
            if n > MAX_SLOT_BYTES {
                return Err(Fault::TooLarge {
                    size: n,
                    limit: MAX_SLOT_BYTES,
                });
            }
            let mut b = vec![0u8; n as usize];
            os_random(&mut b)?;
            Ok(Value::from(b))
        }
        _ => Err(Fault::Unsupported(format!(
            "unknown random source '{source}' (expected uuid4, random, randint or bytes)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Backend, MemoryBackend};

    /// A recording session over a fresh in-memory run.
    fn recording(run_id: &str, opts: &RunOptions) -> (MemoryBackend, Session) {
        let backend = MemoryBackend::new();
        let co = backend.checkout(run_id, true, None).unwrap();
        let mut s = Session::new(
            run_id,
            Mode::Run,
            co.journal,
            Some((co.sink, co.guard)),
            opts,
            None,
        )
        .unwrap();
        s.start(opts, None, None, false).unwrap();
        (backend, s)
    }

    #[test]
    fn desync_messages_never_carry_content() {
        let (_b, mut s) = recording("r", &RunOptions::default());
        let root = ROOT.to_vec();
        let DrawStart::Fresh(i) = s
            .draw_begin(&root, "p", vec![Value::from("SECRET PROMPT")])
            .unwrap()
        else {
            panic!()
        };
        s.draw_end(
            i,
            META_OK.into(),
            Value::default(),
            Value::from("SECRET ANSWER"),
        )
        .unwrap();
        s.effect_begin(&root, "send", Value::from("SECRET ARG"))
            .unwrap();
        for e in s.journal.entries() {
            let text = describe(&e.event);
            assert!(!text.contains("SECRET"), "{text}");
        }
    }

    #[test]
    fn steps_persist_before_they_return() {
        let (backend, mut s) = recording("p", &RunOptions::default());
        let root = ROOT.to_vec();
        assert!(s.unpersisted().is_none());
        s.now(&root).unwrap();
        assert!(s.unpersisted().is_none());
        let stored = backend.snapshot("p", None).unwrap();
        assert_eq!(stored.len(), s.journal().len());
    }

    #[test]
    fn an_external_persist_failure_is_sticky() {
        let (_b, mut s) = recording("x", &RunOptions::default());
        let root = ROOT.to_vec();
        s.persist_failed(Fault::LeaseLost);
        // The first failure is the one that sticks.
        s.persist_failed(Fault::Deleted);
        let len = s.journal().len();
        assert_eq!(s.now(&root).unwrap_err(), Fault::LeaseLost);
        assert_eq!(s.fork(&root, 2).unwrap_err(), Fault::LeaseLost);
        assert_eq!(s.sync().unwrap_err(), Fault::LeaseLost);
        assert_eq!(s.journal().len(), len, "nothing appended once failed");
        assert_eq!(s.failure(), Some(&Fault::LeaseLost));
        // attempt.end is not written either.
        assert_eq!(s.end(Ok(Value::from("ok"))).unwrap_err(), Fault::LeaseLost);
        assert_eq!(s.journal().len(), len);
    }

    #[test]
    fn ends_of_unknown_intents_are_refused() {
        let (_b, mut s) = recording("e", &RunOptions::default());
        assert!(matches!(
            s.draw_end(99, META_OK.into(), Value::default(), Value::default()),
            Err(Fault::Unsupported(_))
        ));
        assert!(matches!(
            s.effect_end(99, Ok(Value::default())),
            Err(Fault::Unsupported(_))
        ));
        let root = ROOT.to_vec();
        let EffectStart::Fresh { intent, .. } =
            s.effect_begin(&root, "e", Value::from("a")).unwrap()
        else {
            panic!()
        };
        // A draw end for an effect intent is refused, and the effect still
        // completes normally afterwards.
        assert!(s
            .draw_end(intent, META_OK.into(), Value::default(), Value::default())
            .is_err());
        s.effect_end(intent, Ok(Value::from("r"))).unwrap();
        assert!(s.effect_end(intent, Ok(Value::from("r"))).is_err());
        assert!(matches!(
            s.draw_begin(&root, "p", Vec::new()),
            Err(Fault::Unsupported(_))
        ));
    }

    fn refusal_cursors(s: &Session) -> Vec<(Cursor, Branch)> {
        s.journal()
            .entries()
            .iter()
            .filter(|e| matches!(e.event, Event::Refusal { .. }))
            .map(|e| (e.cursor, e.branch.clone()))
            .collect()
    }

    #[test]
    fn refusals_are_journaled_once_the_agent_carries_on() {
        let (_b, mut s) = recording("refuse", &RunOptions::default());
        let root = ROOT.to_vec();
        let kids = s.fork(&root, 2).unwrap();
        // The session has no inbox at all: every receive finds it empty.
        assert_eq!(s.recv(&kids[0], "approval"), Err(Fault::Timeout));
        // A sibling's steps do not carry child 0 past its refusal.
        s.now(&kids[1]).unwrap();
        assert!(refusal_cursors(&s).is_empty());
        s.join(&root, &kids, &[false, true]).unwrap();
        // The parent's next step does, and the refusal lands before it, on
        // the child's branch.
        s.now(&root).unwrap();
        let clock = s.journal().len() - 1;
        assert_eq!(refusal_cursors(&s), vec![(clock - 1, kids[0].clone())]);
        assert!(s.unpersisted().is_none(), "persisted with the step");
    }

    #[test]
    fn a_failed_attempt_drops_its_refusals() {
        let (_b, mut s) = recording("dropped", &RunOptions::default());
        let root = ROOT.to_vec();
        assert_eq!(s.recv(&root, "approval"), Err(Fault::Timeout));
        assert_eq!(s.end(Err(Fault::Timeout)), Err(Fault::Timeout));
        assert!(refusal_cursors(&s).is_empty());
        // Returning ok after handling it journals it before attempt.end.
        let (_b, mut s) = recording("kept", &RunOptions::default());
        assert_eq!(s.recv(&root, "approval"), Err(Fault::Timeout));
        s.end(Ok(Value::from("default"))).unwrap();
        let refusals = refusal_cursors(&s);
        assert_eq!(refusals.len(), 1);
        assert_eq!(
            s.journal()
                .get(refusals[0].0 + 1)
                .unwrap()
                .event
                .note_kind(),
            Some(note::ATTEMPT_END)
        );
    }

    #[test]
    fn a_draw_response_that_cannot_be_recorded_fails_the_attempt() {
        let (_b, mut s) = recording("big", &RunOptions::default());
        let root = ROOT.to_vec();
        let DrawStart::Fresh(i) = s.draw_begin(&root, "p", vec![Value::from("q")]).unwrap() else {
            panic!()
        };
        // Malformed meta is the caller's mistake: refused, nothing changes.
        assert!(matches!(
            s.draw_end(i, "{}".into(), Value::default(), Value::default()),
            Err(Fault::Unsupported(_))
        ));
        assert!(s.failure().is_none());
        // A response over the slot limit was paid for and cannot be
        // recorded: the attempt cannot go on.
        let huge = Value::from(vec![0u8; (MAX_SLOT_BYTES + 1) as usize]);
        let err = s
            .draw_end(i, META_OK.into(), Value::default(), huge)
            .unwrap_err();
        assert!(matches!(err, Fault::TooLarge { .. }), "{err:?}");
        assert_eq!(s.now(&root).unwrap_err(), err);
    }

    #[test]
    fn a_result_of_the_other_kind_is_never_matched() {
        // Appending and parsing both refuse such a result; a journal built
        // around them (only the tamper hook can) must still fault, not
        // panic.
        let mut j = Journal::new(None);
        let draw = j
            .append(
                ROOT,
                Event::DrawIntent {
                    provenance: "p".into(),
                    parts: vec![Content::from("q")],
                },
            )
            .unwrap();
        j.append(
            ROOT,
            Event::DrawResult {
                intent: draw,
                meta: META_OK.into(),
                head: Content::from(""),
                body: Content::from("a"),
            },
        )
        .unwrap();
        j.tamper(draw + 1, |e| {
            e.event = Event::EffectResult {
                intent: draw,
                outcome: EffectOutcome::Ok,
                error_kind: String::new(),
                payload: Some(Content::from("forged")),
            };
        });
        let opts = RunOptions::default();
        let mut s = Session::new("r", Mode::Replay, j, None, &opts, None).unwrap();
        let root = ROOT.to_vec();
        assert_eq!(
            s.draw_begin(&root, "p", vec![Value::from("q")]),
            Err(Fault::ReplayExhausted { cursor: draw })
        );
    }

    #[test]
    fn labels_are_checked() {
        let ok: BTreeMap<String, String> = [("team.a-1_x".to_string(), "v".to_string())].into();
        assert!(check_labels(&ok).is_ok());
        for (k, v) in [
            ("", "v"),
            ("Upper", "v"),
            ("has space", "v"),
            (&"k".repeat(65)[..], "v"),
            ("k", &"v".repeat(257)[..]),
        ] {
            let bad: BTreeMap<String, String> = [(k.to_string(), v.to_string())].into();
            assert!(check_labels(&bad).is_err(), "{k:?}");
        }
        let many: BTreeMap<String, String> =
            (0..33).map(|i| (format!("k{i}"), String::new())).collect();
        assert!(check_labels(&many).is_err());
    }

    #[test]
    fn random_values_cover_their_ranges() {
        // The full i64 range takes the no-rejection path.
        let v = random_value("randint", "[-9223372036854775808,9223372036854775807]").unwrap();
        assert!(v.as_str().parse::<i64>().is_ok());
        let one = random_value("randint", "[5,5]").unwrap();
        assert_eq!(one.as_str(), "5");
        assert_eq!(random_value("bytes", "[0]").unwrap().len(), 0);
        assert!(matches!(
            random_value("bytes", "[67108865]"),
            Err(Fault::TooLarge { .. })
        ));
        for bad in ["", "{}", "[1.5]", "[1]x"] {
            assert!(random_value("bytes", bad).is_err(), "{bad:?}");
        }
        for _ in 0..200 {
            let x: f64 = random_value("random", "[]")
                .unwrap()
                .as_str()
                .parse()
                .unwrap();
            assert!((0.0..1.0).contains(&x));
        }
    }

    #[test]
    fn branches_print_for_keys_and_messages() {
        assert_eq!(branch_text(&[]), "");
        assert_eq!(branch_text(&[3, 0, 12]), "3.0.12");
        assert_eq!(
            meta_outcome(r#"{"outcome":"partial"}"#).as_deref(),
            Some("partial")
        );
        assert_eq!(meta_outcome("not json"), None);
        assert_eq!(
            object(vec![("b", Json::from(1u8)), ("a", Json::Null)]),
            r#"{"a":null,"b":1}"#
        );
    }

    /// A recording session over a fresh in-memory run, with an inbox.
    fn recording_with_inbox(run_id: &str) -> (MemoryBackend, Session, Inbox) {
        let backend = MemoryBackend::new();
        let co = backend.checkout(run_id, true, None).unwrap();
        let inbox = Inbox::default();
        let opts = RunOptions::default();
        let mut s = Session::new(
            run_id,
            Mode::Run,
            co.journal,
            Some((co.sink, co.guard)),
            &opts,
            Some(inbox.clone()),
        )
        .unwrap();
        s.start(&opts, None, None, false).unwrap();
        (backend, s, inbox)
    }

    fn deliver(inbox: &Inbox, channel: &str, value: &str) {
        lock_inbox(inbox)
            .entry(channel.to_string())
            .or_default()
            .push_back(Value::from(value));
    }

    fn queued(inbox: &Inbox, channel: &str) -> Vec<String> {
        lock_inbox(inbox)
            .get(channel)
            .map(|q| q.iter().map(|v| v.as_str().into_owned()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn a_detached_sink_leaves_persistence_to_the_host() {
        let (backend, mut s, _inbox) = recording_with_inbox("d");
        let root = ROOT.to_vec();
        let durable = s.journal().len();
        let mut sink = s.detach_sink().expect("a recording session has a sink");
        s.now(&root).unwrap();
        let EffectStart::Fresh { intent, .. } =
            s.effect_begin(&root, "send", Value::from("a")).unwrap()
        else {
            panic!("a fresh effect")
        };
        // Appended, not persisted: the host owns the sink now.
        assert_eq!(s.journal().persisted_len(), durable);
        assert_eq!(backend.snapshot("d", None).unwrap().len(), durable);
        let (at, frames, head) = s.unpersisted().expect("two entries are pending");
        assert_eq!(at, durable);
        let upto = s.journal().len();
        sink.persist(at, &frames, &head).unwrap();
        s.mark_persisted(upto);
        assert!(s.unpersisted().is_none());
        assert_eq!(backend.snapshot("d", None).unwrap().len(), upto);
        // Reattached, the end of the attempt persists inline again.
        s.effect_end(intent, Ok(Value::from("r"))).unwrap();
        s.attach_sink(sink);
        s.end(Ok(Value::from("done"))).unwrap();
        assert!(s.unpersisted().is_none());
        assert_eq!(
            backend.snapshot("d", None).unwrap().len(),
            s.journal().len()
        );
    }

    #[test]
    fn receives_go_back_to_the_inbox_when_their_persist_fails() {
        let (backend, mut s, inbox) = recording_with_inbox("q");
        let root = ROOT.to_vec();
        deliver(&inbox, "jobs", "first");
        deliver(&inbox, "jobs", "second");
        deliver(&inbox, "jobs", "third");
        let _sink = s.detach_sink().unwrap();
        // Two receives before any persist: each takes its own message.
        assert_eq!(s.recv(&root, "jobs").unwrap().as_str(), "first");
        assert_eq!(s.recv(&root, "jobs").unwrap().as_str(), "second");
        assert_eq!(queued(&inbox, "jobs"), ["third"]);
        s.persist_failed(Fault::Unavailable("server went away".into()));
        // Neither receive became durable, so both messages are back, in
        // order, for the next attempt.
        assert_eq!(queued(&inbox, "jobs"), ["first", "second", "third"]);
        assert_eq!(
            s.recv(&root, "jobs").unwrap_err(),
            Fault::Unavailable("server went away".into())
        );
        let stored = backend.snapshot("q", None).unwrap();
        assert!(stored
            .entries()
            .iter()
            .all(|e| !matches!(e.event, Event::ChannelRecv { .. })));
    }

    #[test]
    fn durable_receives_stay_taken() {
        let (_backend, mut s, inbox) = recording_with_inbox("k");
        let root = ROOT.to_vec();
        deliver(&inbox, "jobs", "first");
        deliver(&inbox, "jobs", "second");
        let mut sink = s.detach_sink().unwrap();
        assert_eq!(s.recv(&root, "jobs").unwrap().as_str(), "first");
        let (at, frames, head) = s.unpersisted().unwrap();
        sink.persist(at, &frames, &head).unwrap();
        s.mark_persisted(s.journal().len());
        assert_eq!(s.recv(&root, "jobs").unwrap().as_str(), "second");
        s.persist_failed(Fault::LeaseLost);
        // Only the receive that never became durable is handed back.
        assert_eq!(queued(&inbox, "jobs"), ["second"]);
    }

    #[test]
    fn join_each_reports_every_child() {
        let (_b, mut s) = recording("j", &RunOptions::default());
        let root = ROOT.to_vec();
        let children = s.fork(&root, 3).unwrap();
        let EffectStart::Fresh { .. } = s
            .effect_begin(&children[1], "left open", Value::from("x"))
            .unwrap()
        else {
            panic!("a fresh effect")
        };
        let checks = s.join_each(&root, &children, &[true, true, false]);
        assert_eq!(checks.len(), 3);
        assert!(checks[0].is_ok());
        assert!(matches!(checks[1], Err(Fault::DanglingIntent { .. })));
        assert!(checks[2].is_ok(), "a failed child is exempt");
    }
}
