//! Fault taxonomy (paper Definition 3.13, §4.1 fault tags).
//!
//! Faults are well-typed values, not panics: every failure an agent can hit
//! has a tag the Supervisor can dispatch on. This is what turns "the process
//! died somewhere" into "restart from the journal" as a defined transition.
//!
//! Faults end up in logs, terminals, Python exceptions and HTTP responses, so
//! the text of the storage and journal faults never contains slot content
//! (prompts, responses, tool arguments or results). The one variant that
//! carries content for the caller's benefit ([`Fault::EffectUnrecorded`])
//! prints only its size, in `Display` and in `Debug` alike.

use std::fmt;

use crate::journal::Cursor;
use crate::value::Value;

/// A fault raised during a run.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum Fault {
    /// The oracle (model) call itself failed.
    OracleErr(String),
    /// A durable effect (tool call, external write) failed while performing.
    ToolErr(String),
    /// A deadline was exceeded.
    Timeout,
    /// A budget capability (step or cost limit) was consumed. Converts an
    /// unbounded loop into a well-typed fault with a supervisor response.
    BudgetExhausted,
    /// A verified agent contract was falsified.
    ContractViol(String),
    /// The agent attempted an effect it holds no capability for.
    CapabilityDenied(String),
    /// A fault propagated up from a child agent.
    Escalated(Box<Fault>),
    /// Replay found the journal disagreeing with the program: the re-executed
    /// code asked for a different step than the one recorded at `cursor`.
    /// This is assumption A2 (same term replayed) failing - the agent code
    /// changed between record and replay, or the journal belongs to a
    /// different program.
    JournalDesync {
        cursor: Cursor,
        expected: String,
        found: String,
    },
    /// Strict replay ran past the end of the journal: the recorded run never
    /// got this far (it crashed, or the journal is a prefix). `resume` is the
    /// right verb for continuing such a run; `replay` refuses to sample.
    ReplayExhausted { cursor: Cursor },
    /// Underlying storage failure.
    Io(String),
    /// Replay needed content that has been erased. Erased slots are never
    /// wildcards: an erased run can be verified, not replayed or resumed.
    Erased { cursor: Cursor },
    /// Another writer holds the run (a lock in this process or another, or a
    /// server lease). `retry_after_secs` is the server's hint, if any.
    Locked { retry_after_secs: Option<u64> },
    /// The stored journal changed underneath this writer: it holds `actual`
    /// where `expected` was assumed (a byte length or an entry count,
    /// depending on the store).
    Conflict { expected: u64, actual: u64 },
    /// The operation is not supported for this journal, store or input.
    Unsupported(String),
    /// Content of `size` bytes exceeds a `limit` (a slot, a record or a
    /// request). `size` is 0 when the store did not report it.
    TooLarge { size: u64, limit: u64 },
    /// The agent returned while the intent at `cursor` had no result.
    DanglingIntent { cursor: Cursor },
    /// An effect intent was left without a result by a crash, and this
    /// runtime requires an explicit recovery policy for it.
    DanglingEffect { cursor: Cursor },
    /// `perform` succeeded but its result could not be persisted. The
    /// result is returned so the caller can log or reconcile it.
    EffectUnrecorded {
        name: String,
        intent: Cursor,
        result: Value,
    },
    /// The lease (server) or lock (local) was lost while writing.
    LeaseLost,
    /// The run was deleted and can never be recreated.
    Deleted,
    /// Storage is temporarily unavailable; retrying later may succeed.
    Unavailable(String),
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::OracleErr(m) => write!(f, "oracle error: {m}"),
            Fault::ToolErr(m) => write!(f, "tool error: {m}"),
            Fault::Timeout => write!(f, "timeout"),
            Fault::BudgetExhausted => write!(f, "budget exhausted"),
            Fault::ContractViol(m) => write!(f, "contract violated: {m}"),
            Fault::CapabilityDenied(m) => write!(f, "capability denied: {m}"),
            Fault::Escalated(inner) => write!(f, "escalated: {inner}"),
            Fault::JournalDesync {
                cursor,
                expected,
                found,
            } => write!(
                f,
                "journal desync at cursor {cursor}: program asked for {expected}, journal holds {found}"
            ),
            Fault::ReplayExhausted { cursor } => {
                write!(f, "replay exhausted at cursor {cursor}: recorded run ended here")
            }
            Fault::Io(m) => write!(f, "io error: {m}"),
            Fault::Erased { cursor } => write!(
                f,
                "content at cursor {cursor} has been erased: the run can be verified but not \
                 replayed or resumed"
            ),
            Fault::Locked {
                retry_after_secs: Some(secs),
            } => write!(f, "run is locked by another writer (retry after {secs}s)"),
            Fault::Locked {
                retry_after_secs: None,
            } => write!(f, "run is locked by another writer"),
            Fault::Conflict { expected, actual } => write!(
                f,
                "journal changed underneath this writer: expected {expected}, found {actual}"
            ),
            Fault::Unsupported(m) => write!(f, "unsupported: {m}"),
            Fault::TooLarge { size, limit } => {
                write!(f, "too large: {size} bytes exceeds the limit of {limit}")
            }
            Fault::DanglingIntent { cursor } => write!(
                f,
                "the intent at cursor {cursor} has no result at the end of the attempt"
            ),
            Fault::DanglingEffect { cursor } => write!(
                f,
                "the effect intent at cursor {cursor} was left without a result by a crash; \
                 pass a recovery policy to decide it"
            ),
            Fault::EffectUnrecorded {
                name,
                intent,
                result,
            } => write!(
                f,
                "effect '{name}' (intent at cursor {intent}) succeeded, but its {}-byte result \
                 could not be recorded",
                result.len()
            ),
            Fault::LeaseLost => write!(f, "the run's lease or lock was lost"),
            Fault::Deleted => write!(f, "the run has been deleted"),
            Fault::Unavailable(m) => write!(f, "storage unavailable: {m}"),
        }
    }
}

/// Like a derived `Debug`, except that content is shown only by size.
impl fmt::Debug for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::OracleErr(m) => f.debug_tuple("OracleErr").field(m).finish(),
            Fault::ToolErr(m) => f.debug_tuple("ToolErr").field(m).finish(),
            Fault::Timeout => f.write_str("Timeout"),
            Fault::BudgetExhausted => f.write_str("BudgetExhausted"),
            Fault::ContractViol(m) => f.debug_tuple("ContractViol").field(m).finish(),
            Fault::CapabilityDenied(m) => f.debug_tuple("CapabilityDenied").field(m).finish(),
            Fault::Escalated(inner) => f.debug_tuple("Escalated").field(inner).finish(),
            Fault::JournalDesync {
                cursor,
                expected,
                found,
            } => f
                .debug_struct("JournalDesync")
                .field("cursor", cursor)
                .field("expected", expected)
                .field("found", found)
                .finish(),
            Fault::ReplayExhausted { cursor } => f
                .debug_struct("ReplayExhausted")
                .field("cursor", cursor)
                .finish(),
            Fault::Io(m) => f.debug_tuple("Io").field(m).finish(),
            Fault::Erased { cursor } => f.debug_struct("Erased").field("cursor", cursor).finish(),
            Fault::Locked { retry_after_secs } => f
                .debug_struct("Locked")
                .field("retry_after_secs", retry_after_secs)
                .finish(),
            Fault::Conflict { expected, actual } => f
                .debug_struct("Conflict")
                .field("expected", expected)
                .field("actual", actual)
                .finish(),
            Fault::Unsupported(m) => f.debug_tuple("Unsupported").field(m).finish(),
            Fault::TooLarge { size, limit } => f
                .debug_struct("TooLarge")
                .field("size", size)
                .field("limit", limit)
                .finish(),
            Fault::DanglingIntent { cursor } => f
                .debug_struct("DanglingIntent")
                .field("cursor", cursor)
                .finish(),
            Fault::DanglingEffect { cursor } => f
                .debug_struct("DanglingEffect")
                .field("cursor", cursor)
                .finish(),
            Fault::EffectUnrecorded {
                name,
                intent,
                result,
            } => f
                .debug_struct("EffectUnrecorded")
                .field("name", name)
                .field("intent", intent)
                .field("result", &format_args!("<{} bytes>", result.len()))
                .finish(),
            Fault::LeaseLost => f.write_str("LeaseLost"),
            Fault::Deleted => f.write_str("Deleted"),
            Fault::Unavailable(m) => f.debug_tuple("Unavailable").field(m).finish(),
        }
    }
}

impl Fault {
    /// The variant's name, the tag recorded as `fault_kind` in
    /// `attempt.end` and used by bindings to pick an exception type.
    pub fn kind(&self) -> &'static str {
        match self {
            Fault::OracleErr(_) => "OracleErr",
            Fault::ToolErr(_) => "ToolErr",
            Fault::Timeout => "Timeout",
            Fault::BudgetExhausted => "BudgetExhausted",
            Fault::ContractViol(_) => "ContractViol",
            Fault::CapabilityDenied(_) => "CapabilityDenied",
            Fault::Escalated(_) => "Escalated",
            Fault::JournalDesync { .. } => "JournalDesync",
            Fault::ReplayExhausted { .. } => "ReplayExhausted",
            Fault::Io(_) => "Io",
            Fault::Erased { .. } => "Erased",
            Fault::Locked { .. } => "Locked",
            Fault::Conflict { .. } => "Conflict",
            Fault::Unsupported(_) => "Unsupported",
            Fault::TooLarge { .. } => "TooLarge",
            Fault::DanglingIntent { .. } => "DanglingIntent",
            Fault::DanglingEffect { .. } => "DanglingEffect",
            Fault::EffectUnrecorded { .. } => "EffectUnrecorded",
            Fault::LeaseLost => "LeaseLost",
            Fault::Deleted => "Deleted",
            Fault::Unavailable(_) => "Unavailable",
        }
    }

    /// The text a journal records for this fault when a model call or an
    /// effect fails with it: the message of a variant that carries only a
    /// message, the display text otherwise. Together with
    /// [`kind`](Self::kind) it is what [`from_recorded`](Self::from_recorded)
    /// rebuilds the fault from.
    pub fn recorded_message(&self) -> String {
        match self {
            Fault::OracleErr(m)
            | Fault::ToolErr(m)
            | Fault::ContractViol(m)
            | Fault::CapabilityDenied(m)
            | Fault::Io(m)
            | Fault::Unsupported(m)
            | Fault::Unavailable(m) => m.clone(),
            other => other.to_string(),
        }
    }

    /// Rebuild a fault from its recorded [`kind`](Self::kind) tag and
    /// [`recorded_message`](Self::recorded_message), so a recorded failure
    /// replays as the very fault the agent saw when it was recorded. `None`
    /// for tags that are not fault kinds, and for the variants that carry
    /// more than a message (cursors, sizes, nested faults), which the
    /// journal does not keep; callers fall back to a fault of their own
    /// (and use the same fallback when recording, so both sides agree).
    pub fn from_recorded(kind: &str, message: &str) -> Option<Fault> {
        let m = || message.to_string();
        Some(match kind {
            "OracleErr" => Fault::OracleErr(m()),
            "ToolErr" => Fault::ToolErr(m()),
            "ContractViol" => Fault::ContractViol(m()),
            "CapabilityDenied" => Fault::CapabilityDenied(m()),
            "Io" => Fault::Io(m()),
            "Unsupported" => Fault::Unsupported(m()),
            "Unavailable" => Fault::Unavailable(m()),
            "Timeout" => Fault::Timeout,
            "BudgetExhausted" => Fault::BudgetExhausted,
            "LeaseLost" => Fault::LeaseLost,
            "Deleted" => Fault::Deleted,
            _ => return None,
        })
    }

    /// The journal cursor the fault names, if any (`fault_cursor` in
    /// `attempt.end`). An escalated fault reports its cause's cursor.
    pub fn cursor(&self) -> Option<Cursor> {
        match self {
            Fault::JournalDesync { cursor, .. }
            | Fault::ReplayExhausted { cursor }
            | Fault::Erased { cursor }
            | Fault::DanglingIntent { cursor }
            | Fault::DanglingEffect { cursor } => Some(*cursor),
            Fault::EffectUnrecorded { intent, .. } => Some(*intent),
            Fault::Escalated(inner) => inner.cursor(),
            _ => None,
        }
    }
}

impl std::error::Error for Fault {}

impl From<std::io::Error> for Fault {
    fn from(e: std::io::Error) -> Self {
        Fault::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "the patient's diagnosis is confidential";

    #[test]
    fn content_never_reaches_display_or_debug() {
        let f = Fault::EffectUnrecorded {
            name: "send_email".into(),
            intent: 7,
            result: Value::from(SECRET),
        };
        let shown = f.to_string();
        let debugged = format!("{f:?}");
        assert!(!shown.contains(SECRET) && !debugged.contains(SECRET));
        assert!(shown.contains("send_email") && shown.contains("cursor 7"));
        assert!(debugged.contains(&format!("<{} bytes>", SECRET.len())));
        let escalated = Fault::Escalated(Box::new(f));
        assert!(!format!("{escalated:?}").contains(SECRET));
        assert!(!escalated.to_string().contains(SECRET));
    }

    #[test]
    fn new_faults_display() {
        let cases = [
            (Fault::Erased { cursor: 3 }, "cursor 3 has been erased"),
            (
                Fault::Locked {
                    retry_after_secs: Some(5),
                },
                "retry after 5s",
            ),
            (
                Fault::Locked {
                    retry_after_secs: None,
                },
                "locked by another writer",
            ),
            (
                Fault::Conflict {
                    expected: 10,
                    actual: 12,
                },
                "expected 10, found 12",
            ),
            (Fault::Unsupported("x".into()), "unsupported: x"),
            (Fault::TooLarge { size: 9, limit: 8 }, "9 bytes"),
            (Fault::DanglingIntent { cursor: 4 }, "cursor 4"),
            (Fault::DanglingEffect { cursor: 5 }, "recovery policy"),
            (Fault::LeaseLost, "lease or lock was lost"),
            (Fault::Deleted, "deleted"),
            (Fault::Unavailable("503".into()), "unavailable: 503"),
        ];
        for (fault, needle) in cases {
            assert!(fault.to_string().contains(needle), "{fault}");
            assert!(!format!("{fault:?}").is_empty());
        }
    }

    #[test]
    fn recorded_faults_round_trip() {
        let simple = [
            Fault::OracleErr("overloaded".into()),
            Fault::ToolErr("card declined".into()),
            Fault::ContractViol("x".into()),
            Fault::CapabilityDenied("send".into()),
            Fault::Io("disk".into()),
            Fault::Unsupported("u".into()),
            Fault::Unavailable("503".into()),
            Fault::Timeout,
            Fault::BudgetExhausted,
            Fault::LeaseLost,
            Fault::Deleted,
        ];
        for f in simple {
            assert_eq!(
                Fault::from_recorded(f.kind(), &f.recorded_message()),
                Some(f.clone()),
                "{f:?}"
            );
        }
        // Variants with more than a message are not rebuilt; their text is
        // kept for the caller's fallback.
        let structured = Fault::Erased { cursor: 4 };
        assert_eq!(Fault::from_recorded(structured.kind(), ""), None);
        assert!(structured.recorded_message().contains("cursor 4"));
        assert_eq!(Fault::from_recorded("ValueError", "m"), None);
    }

    #[test]
    fn kinds_and_cursors() {
        assert_eq!(Fault::Erased { cursor: 3 }.kind(), "Erased");
        assert_eq!(Fault::Erased { cursor: 3 }.cursor(), Some(3));
        assert_eq!(Fault::Timeout.cursor(), None);
        let nested = Fault::Escalated(Box::new(Fault::DanglingIntent { cursor: 9 }));
        assert_eq!(nested.kind(), "Escalated");
        assert_eq!(nested.cursor(), Some(9));
    }
}
