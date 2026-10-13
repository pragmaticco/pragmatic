//! # Pragmatic - durable execution for agents that don't run deterministically
//!
//! A zero-dependency Rust runtime that journals every step an agent takes, so
//! it survives any crash and replays exactly - nondeterministic model
//! behavior included.
//!
//! Every durable-execution engine assumes deterministic replay and hacks
//! around LLMs by caching model outputs as opaque activities. Pragmatic
//! models each LLM call as a first-class probability distribution (the
//! [`Oracle`]) and journals every realized outcome to an append-only,
//! hash-chained log (the [`Journal`]). Recovery becomes replay: read back
//! recorded outcomes instead of re-sampling the model. The replay guarantee
//! (T1) is proved in the Agentical calculus - a paper proof, validated here
//! empirically; the Lean 4 mechanization is still in progress. This crate is
//! the runtime that carries the guarantee into production.
//!
//! ## Three guarantees, every run
//!
//! 1. **Journal every step** - each oracle call's realized outcome lands in
//!    an append-only log as the run proceeds ([`Journal`]).
//! 2. **Recover from any crash** - resume exactly where the agent stopped;
//!    recorded outcomes are read back instead of re-sampled
//!    ([`Runtime::resume`]).
//! 3. **Replay faithfully** - reproduce the entire run exactly for debugging
//!    and audit, nondeterministic LLM behavior included
//!    ([`Runtime::replay`], T1).
//!
//! ## In your code
//!
//! ```
//! use pragmatic::{Runtime, SeededOracle, Ctx, Fault, Value};
//!
//! fn research(ctx: &mut Ctx) -> Result<Value, Fault> {
//!     let plan = ctx.oracle("plan the task")?;            // journaled
//!     let mut out = Vec::new();
//!     for step in 0..3 {
//!         out.push(ctx.oracle(format!("probe {step}: {plan}"))?); // journaled
//!     }
//!     Ok(Value::from(format!("report({} findings)", out.len())))
//! }
//!
//! let mut rt = Runtime::in_memory(SeededOracle::new(7));
//! let report = rt.run("research-42", research).unwrap();
//!
//! // Crash anywhere. Resume exactly, no re-sampling:
//! let resumed = rt.resume("research-42", research).unwrap();
//! assert_eq!(resumed.fresh_steps, 0); // everything came from the journal
//!
//! // Replay the whole run, bit for bit, for audit (T1):
//! let audit = rt.replay("research-42", research).unwrap();
//! assert_eq!(audit.trace, report.trace);
//! ```
//!
//! ## Building blocks for the system of record
//!
//! Self-contained, zero-dependency modules shared by the journal, Pragmatic
//! Server and evidence verification:
//!
//! - [`merkle`]: RFC 6962 Merkle tree hashes, inclusion and consistency
//!   proofs, for anchoring many journals under one root.
//! - [`tsp`]: RFC 3161 time-stamp requests, and parsing of responses and
//!   tokens (signature verification is left to OpenSSL).
//! - [`json`]: a strict RFC 8259 parser and compact serializer for notes
//!   and evidence bundles.
//! - [`redact`]: detectors for personal data and secrets, and redaction.
//! - [`rand`]: bytes from the operating system's CSPRNG, for slot salts and
//!   nonces.

pub mod async_runtime;
pub mod ctx;
pub mod fault;
pub mod journal;
pub mod json;
pub mod memory;
pub mod merkle;
pub mod oracle;
pub mod rand;
pub mod redact;
pub mod runtime;
pub mod sha256;
mod store;
pub mod supervisor;
pub mod tsp;
pub mod value;

pub use async_runtime::{block_on, AsyncCtx, AsyncOracle, AsyncRuntime};
pub use ctx::{Ctx, RunOptions, TraceLabel};
pub use fault::Fault;
pub use journal::{Cursor, Entry, Event, Journal};
pub use memory::{Label, Store};
pub use oracle::{CountingOracle, Oracle, RefusingOracle, RetryOracle, SeededOracle};
pub use runtime::{Recover, RunReport, Runtime};
pub use supervisor::{Decision, Supervisor};
pub use value::Value;

/// `#[pragmatic::durable]` - journal the program's identity so a run
/// recorded under one version of your agent refuses to replay under another.
/// See [`Ctx::program_marker`] for the underlying mechanism.
#[cfg(feature = "macros")]
pub use pragmatic_macros::durable;
