//! The **Supervisor**: the control plane that turns a crashed run into a
//! resumed one (paper §3.8).
//!
//! A supervisor maps faults to decisions: **restart** (re-enter from the
//! journal: precisely the `replay(N, J↾id)` transition T1 certifies sound),
//! **compensate** (run the saga against committed effects, in reverse),
//! **escalate** (re-raise to the parent), or **stop**.

use std::collections::{HashMap, HashSet};

use crate::ctx::{Ctx, RunOptions};
use crate::fault::Fault;
use crate::journal::{note, Content, Cursor, EffectOutcome, Event, META};
use crate::json::Json;
use crate::oracle::Oracle;
use crate::runtime::{Recover, RunReport, Runtime};
use crate::value::Value;

/// A supervisor decision for a fault ([Sup-restart], [Sup-comp], …).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Resume from the journal: replay the recorded prefix, continue fresh.
    Restart,
    /// Undo committed effects in reverse order, then stop with the fault.
    Compensate,
    /// Re-raise to the parent as `Escalated(fault)`.
    Escalate,
    /// Abandon: return the fault as-is.
    Stop,
}

/// Default decision policy: transient faults restart, logical faults stop.
///
/// Storage faults stop too, except [`Fault::Unavailable`]: a lock held by
/// someone else, a conflict, a lost lease, erased content or a deleted run
/// will not go away by trying again immediately, while an unavailable store
/// may.
pub fn default_policy(fault: &Fault) -> Decision {
    match fault {
        Fault::OracleErr(_)
        | Fault::ToolErr(_)
        | Fault::Timeout
        | Fault::Io(_)
        | Fault::Unavailable(_) => Decision::Restart,
        Fault::BudgetExhausted
        | Fault::ContractViol(_)
        | Fault::CapabilityDenied(_)
        | Fault::JournalDesync { .. }
        | Fault::ReplayExhausted { .. }
        | Fault::Escalated(_)
        | Fault::Erased { .. }
        | Fault::Locked { .. }
        | Fault::Conflict { .. }
        | Fault::Unsupported(_)
        | Fault::TooLarge { .. }
        | Fault::DanglingIntent { .. }
        | Fault::DanglingEffect { .. }
        | Fault::EffectUnrecorded { .. }
        | Fault::LeaseLost
        | Fault::Deleted => Decision::Stop,
    }
}

/// How a committed effect is undone during compensation.
type Compensator = Box<dyn FnMut(&str, &Value)>;

/// Drives a run under a fault policy, restarting from the journal up to
/// `max_restarts` times.
pub struct Supervisor {
    max_restarts: u32,
    decide: Box<dyn Fn(&Fault) -> Decision>,
    /// Called for each committed effect during compensation, in reverse
    /// commit order: this is where your saga undoes the world.
    compensator: Option<Compensator>,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Supervisor {
            max_restarts: 3,
            decide: Box::new(default_policy),
            compensator: None,
        }
    }

    pub fn max_restarts(mut self, n: u32) -> Self {
        self.max_restarts = n;
        self
    }

    /// Replace the fault → decision policy.
    pub fn on_fault(mut self, decide: impl Fn(&Fault) -> Decision + 'static) -> Self {
        self.decide = Box::new(decide);
        self
    }

    /// Install the saga: how each committed effect is undone when a
    /// `Compensate` decision fires.
    pub fn compensate_with(mut self, f: impl FnMut(&str, &Value) + 'static) -> Self {
        self.compensator = Some(Box::new(f));
        self
    }

    /// Drive `run_id` to completion under this supervisor. The agent closure
    /// must be re-enterable (it is called once per attempt; each attempt
    /// replays the journaled prefix first, so no work is repeated).
    pub fn supervise<O: Oracle>(
        &mut self,
        rt: &Runtime<O>,
        run_id: &str,
        opts: RunOptions,
        mut agent: impl FnMut(&mut Ctx) -> Result<Value, Fault>,
    ) -> Result<RunReport, Fault> {
        let mut attempt = 0u32;
        // First attempt: create-or-continue.
        let mut outcome = rt.run_with(run_id, opts.clone(), &mut agent);
        loop {
            let fault = match outcome {
                Ok(report) => return Ok(report),
                Err(f) => f,
            };
            match (self.decide)(&fault) {
                Decision::Restart if attempt < self.max_restarts => {
                    attempt += 1;
                    // [Sup-restart]: re-enter the term against J↾id. Effects
                    // a crash left open at the end of their branch are
                    // written off (performed again on re-entry), and a
                    // failure nothing observed is retried. An effect left
                    // open with later steps after it cannot be written off:
                    // the attempt stops with DanglingEffect for a decision.
                    outcome = rt.resume_with(
                        run_id,
                        opts.clone(),
                        |_, _| Recover::Compensate,
                        &mut agent,
                    );
                }
                Decision::Restart => return Err(fault),
                Decision::Compensate => {
                    self.run_saga(rt, run_id)?;
                    return Err(fault);
                }
                Decision::Escalate => return Err(Fault::Escalated(Box::new(fault))),
                Decision::Stop => return Err(fault),
            }
        }
    }

    /// [Sup-comp]: compensations run in reverse commit order against the
    /// effects whose latest result is `ok`. The saga checks the run out
    /// (taking its write lock, like any writer) and records each
    /// compensation as `recovery` notes with decision `compensate` on the
    /// meta branch, so program replay of the run is unchanged.
    ///
    /// The first note (`"saga": "begin"`) is persisted *before* the
    /// compensator runs and the second (`"saga": "done"`) after it returns.
    /// An effect with a `begin` note is never compensated again, so a later
    /// saga never undoes the same effect twice, even when this one dies
    /// between its note and its compensator; a `begin` without a `done`
    /// shows an operator a compensation that may not have finished. If a
    /// note cannot be persisted, the saga stops with that fault before
    /// undoing anything more.
    fn run_saga<O: Oracle>(&mut self, rt: &Runtime<O>, run_id: &str) -> Result<(), Fault> {
        let mut co = rt.checkout(run_id)?;
        let entries = co.journal.entries();
        let mut latest: HashMap<Cursor, Cursor> = HashMap::new();
        let mut undone: HashSet<Cursor> = HashSet::new();
        for e in entries {
            match &e.event {
                Event::EffectResult { intent, .. } => {
                    latest.insert(*intent, e.cursor);
                }
                Event::Note { kind, data, .. } if kind == note::RECOVERY => {
                    if let Some(intent) = saga_note_intent(data) {
                        undone.insert(intent);
                    }
                }
                _ => {}
            }
        }
        // (result cursor, intent cursor, branch, name, result), in commit
        // order.
        let mut committed = Vec::new();
        for e in entries {
            let Event::EffectIntent { name, .. } = &e.event else {
                continue;
            };
            let Some(&r) = latest.get(&e.cursor) else {
                continue;
            };
            if undone.contains(&e.cursor) {
                continue;
            }
            if let Event::EffectResult {
                outcome: EffectOutcome::Ok,
                payload,
                ..
            } = &entries[r as usize].event
            {
                let result = match payload {
                    Some(Content::Sealed(v)) => v.clone(),
                    _ => Value::default(),
                };
                committed.push((r, e.cursor, e.branch.clone(), name.clone(), result));
            }
        }
        committed.sort_by_key(|c| c.0);
        for (result_cursor, intent, branch, name, result) in committed.into_iter().rev() {
            let note = |phase: &str| {
                let data = Json::Object(vec![
                    (
                        "branch".into(),
                        Json::Array(branch.iter().map(|&i| Json::from(i)).collect()),
                    ),
                    ("decision".into(), "compensate".into()),
                    ("intent".into(), intent.into()),
                    ("name".into(), name.as_str().into()),
                    ("result".into(), result_cursor.into()),
                    ("saga".into(), phase.into()),
                ])
                .to_string();
                Event::Note {
                    kind: note::RECOVERY.into(),
                    data,
                    payload: Vec::new(),
                }
            };
            co.journal.append(META, note("begin"))?;
            co.persist()?;
            if let Some(f) = self.compensator.as_mut() {
                f(&name, &result);
            }
            co.journal.append(META, note("done"))?;
            co.persist()?;
        }
        Ok(())
    }
}

/// The intent of a `recovery` note recording a compensation.
fn saga_note_intent(data: &str) -> Option<Cursor> {
    let doc = crate::journal::strict_json_field(data)?;
    if doc.get("decision")?.as_str()? != "compensate" {
        return None;
    }
    doc.get("intent")?.as_u64()
}
