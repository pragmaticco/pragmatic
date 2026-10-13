//! The **Supervisor** - the control plane that turns a crashed run into a
//! resumed one (paper §3.8).
//!
//! A supervisor maps faults to decisions: **restart** (re-enter from the
//! journal - precisely the `replay(N, J↾id)` transition T1 certifies sound),
//! **compensate** (run the saga against committed effects, in reverse),
//! **escalate** (re-raise to the parent), or **stop**.

use crate::ctx::{Ctx, RunOptions};
use crate::fault::Fault;
use crate::journal_v1::Event;
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
    /// commit order - this is where your saga undoes the world.
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
        rt: &mut Runtime<O>,
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
                    // [Sup-restart]: re-enter the term against J↾id. Dangling
                    // intents are written off (performed fresh on re-entry).
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

    /// [Sup-comp]: compensations run in reverse order against the committed
    /// `EffectCommit` entries in the journal, and each is journaled as
    /// `EffectCompensated` so a later replay never double-undoes.
    fn run_saga<O: Oracle>(&mut self, rt: &mut Runtime<O>, run_id: &str) -> Result<(), Fault> {
        let journal = rt.journal(run_id)?;
        // Committed effects not already compensated, in commit order.
        let mut committed: Vec<(String, Value)> = Vec::new();
        for e in journal.entries() {
            match &e.event {
                Event::EffectCommit { name, result } => {
                    committed.push((name.clone(), result.clone()))
                }
                Event::EffectCompensated { name } => {
                    if let Some(i) = committed.iter().rposition(|(n, _)| n == name) {
                        committed.remove(i);
                    }
                }
                _ => {}
            }
        }
        for (name, result) in committed.into_iter().rev() {
            if let Some(f) = self.compensator.as_mut() {
                f(&name, &result);
            }
            journal.append(Event::EffectCompensated { name })?;
        }
        journal.sync()?;
        Ok(())
    }
}
