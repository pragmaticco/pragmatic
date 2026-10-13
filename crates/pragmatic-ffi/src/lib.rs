//! C ABI for Pragmatic - durable execution for agents that don't run
//! deterministically.
//!
//! One flat `extern "C"` surface over [`pragmatic::Runtime`] and
//! [`pragmatic::Ctx`], designed to be bound from any language with a C FFI
//! (the in-tree C++, Java, Go, and Node.js bindings all sit on this crate). The
//! contract lives in `include/pragmatic.h`.
//!
//! ## String ownership
//!
//! Two rules, no exceptions:
//!
//! 1. Every `char*` the **library returns to you** (outputs, error messages,
//!    report fields) is yours to free with `prag_str_free`.
//! 2. Every `char*` **you return to the library** (from an oracle, agent, or
//!    effect callback) must have been created with `prag_str_new`; the
//!    library takes ownership.
//!
//! `const char*` parameters are borrowed for the duration of the call only.
//!
//! ## Fault propagation
//!
//! Ctx calls that fault return NULL and record the typed fault on the ctx.
//! An agent callback that then returns NULL propagates that recorded fault
//! (so `BudgetExhausted` stays `BudgetExhausted` instead of collapsing into
//! a tool error); an agent that fails on its own reports a tool fault with
//! its `err_out` message. Callbacks must not unwind (longjmp / C++
//! exceptions across the boundary are undefined behavior) - the wrappers
//! catch and convert before returning.

// Every exported fn is `unsafe extern "C"`; the safety contract (string
// ownership, callback discipline, pointer validity) is specified once in
// the module docs above and in include/pragmatic.h rather than repeated
// per function.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use pragmatic::{Fault, Oracle, RunReport, TraceLabel, Value};

// ---------------------------------------------------------------------------
// Status codes (mirrored in pragmatic.h)
// ---------------------------------------------------------------------------

pub const PRAG_OK: i32 = 0;
pub const PRAG_ERR_ORACLE: i32 = 1;
pub const PRAG_ERR_TOOL: i32 = 2;
pub const PRAG_ERR_TIMEOUT: i32 = 3;
pub const PRAG_ERR_BUDGET: i32 = 4;
pub const PRAG_ERR_CONTRACT: i32 = 5;
pub const PRAG_ERR_CAPABILITY: i32 = 6;
pub const PRAG_ERR_ESCALATED: i32 = 7;
pub const PRAG_ERR_DESYNC: i32 = 8;
pub const PRAG_ERR_REPLAY_EXHAUSTED: i32 = 9;
pub const PRAG_ERR_IO: i32 = 10;
pub const PRAG_ERR_INVALID: i32 = 11;
pub const PRAG_ERR_PANIC: i32 = 12;
pub const PRAG_ERR_TAMPERED: i32 = 13;

fn fault_code(f: &Fault) -> i32 {
    match f {
        Fault::OracleErr(_) => PRAG_ERR_ORACLE,
        Fault::ToolErr(_) => PRAG_ERR_TOOL,
        Fault::Timeout => PRAG_ERR_TIMEOUT,
        Fault::BudgetExhausted => PRAG_ERR_BUDGET,
        Fault::ContractViol(_) => PRAG_ERR_CONTRACT,
        Fault::CapabilityDenied(_) => PRAG_ERR_CAPABILITY,
        Fault::Escalated(_) => PRAG_ERR_ESCALATED,
        Fault::JournalDesync { .. } => PRAG_ERR_DESYNC,
        Fault::ReplayExhausted { .. } => PRAG_ERR_REPLAY_EXHAUSTED,
        // Storage and journal faults (erased, locked, conflict, unsupported,
        // too large, dangling, lease lost, deleted, unavailable) share the
        // I/O code; the message carries the detail. The C header is
        // unchanged.
        _ => PRAG_ERR_IO,
    }
}

// ---------------------------------------------------------------------------
// Strings across the boundary
// ---------------------------------------------------------------------------

/// Copy a NUL-terminated string into a library-owned allocation. This is the
/// ONLY valid way to produce a `char*` that a callback returns to the
/// library. Returns NULL if `s` is NULL or contains an interior NUL.
#[no_mangle]
pub unsafe extern "C" fn prag_str_new(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let bytes = CStr::from_ptr(s).to_bytes();
    match CString::new(bytes) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free any `char*` the library returned to the caller (or that
/// `prag_str_new` produced and was never handed back). NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn prag_str_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// A `char*` for the caller (rule 1: caller frees with `prag_str_free`).
/// Interior NULs (possible: `Value` is arbitrary bytes) are replaced so the
/// string always round-trips.
fn out_string(s: &str) -> *mut c_char {
    CString::new(s.replace('\0', "\u{FFFD}"))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

unsafe fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if !err_out.is_null() {
        *err_out = out_string(msg);
    }
}

unsafe fn set_fault(err_out: *mut *mut c_char, f: &Fault) -> i32 {
    set_err(err_out, &f.to_string());
    fault_code(f)
}

/// Borrow an incoming `const char*` as UTF-8, or fail with PRAG_ERR_INVALID.
unsafe fn in_str<'a>(s: *const c_char, what: &str) -> Result<&'a str, String> {
    if s.is_null() {
        return Err(format!("{what} is NULL"));
    }
    CStr::from_ptr(s)
        .to_str()
        .map_err(|_| format!("{what} is not valid UTF-8"))
}

/// Take ownership of a `char*` a callback returned (rule 2: it came from
/// `prag_str_new`).
unsafe fn take_callback_string(s: *mut c_char) -> String {
    let owned = CString::from_raw(s);
    owned.to_string_lossy().into_owned()
}

/// Consume a callback's `err_out` slot into a message, if it set one.
unsafe fn take_callback_err(err: *mut c_char, fallback: &str) -> String {
    if err.is_null() {
        fallback.to_string()
    } else {
        take_callback_string(err)
    }
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

/// Your model call: return a `prag_str_new` completion, or NULL with
/// `*err_out` set (via `prag_str_new`) on failure.
pub type PragOracleFn = unsafe extern "C" fn(
    user: *mut c_void,
    prompt: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char;

/// Your agent body: drive the ctx, return a `prag_str_new` output, or NULL
/// with `*err_out` set on failure (a faulted ctx call propagates its typed
/// fault - see module docs).
pub type PragAgentFn = unsafe extern "C" fn(
    user: *mut c_void,
    ctx: *mut PragCtx,
    err_out: *mut *mut c_char,
) -> *mut c_char;

/// A durable effect's perform step (tool call, external write): return a
/// `prag_str_new` result, or NULL with `*err_out` set on failure.
pub type PragEffectFn = unsafe extern "C" fn(
    user: *mut c_void,
    arg: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char;

/// A `pragmatic::Oracle` backed by a C callback.
struct CallbackOracle {
    func: PragOracleFn,
    user: *mut c_void,
}

impl Oracle for CallbackOracle {
    fn call(&self, prompt: &Value) -> Result<Value, Fault> {
        let c_prompt = out_string(&prompt.as_str());
        let mut err: *mut c_char = std::ptr::null_mut();
        unsafe {
            let out = (self.func)(self.user, c_prompt, &mut err);
            prag_str_free(c_prompt);
            if out.is_null() {
                Err(Fault::OracleErr(take_callback_err(
                    err,
                    "oracle callback failed",
                )))
            } else {
                prag_str_free(err); // success with a stray err message: discard
                Ok(Value::from(take_callback_string(out)))
            }
        }
    }

    fn provenance(&self) -> String {
        "c-ffi-oracle".to_string()
    }
}

// ---------------------------------------------------------------------------
// Ctx
// ---------------------------------------------------------------------------

/// The durable execution context handed to agent callbacks. Valid only for
/// the duration of the callback; the pointer is nulled when the attempt
/// finishes, so a leaked reference fails loudly instead of dangling.
pub struct PragCtx {
    ptr: *mut pragmatic::Ctx<'static>,
    /// The last typed fault a ctx call hit - propagated when the agent
    /// callback subsequently fails, cleared on the next successful call.
    pending: Option<Fault>,
}

impl PragCtx {
    unsafe fn get(&mut self) -> Result<&mut pragmatic::Ctx<'static>, String> {
        self.ptr
            .as_mut()
            .ok_or_else(|| "ctx used outside its run".to_string())
    }
}

unsafe fn ctx_value_call(
    ctx: *mut PragCtx,
    err_out: *mut *mut c_char,
    f: impl FnOnce(&mut pragmatic::Ctx<'static>) -> Result<Value, Fault>,
) -> *mut c_char {
    let Some(wrapper) = ctx.as_mut() else {
        set_err(err_out, "ctx is NULL");
        return std::ptr::null_mut();
    };
    let inner = match wrapper.get() {
        Ok(i) => i,
        Err(m) => {
            set_err(err_out, &m);
            return std::ptr::null_mut();
        }
    };
    match f(inner) {
        Ok(v) => {
            wrapper.pending = None;
            out_string(&v.as_str())
        }
        Err(fault) => {
            set_err(err_out, &fault.to_string());
            wrapper.pending = Some(fault);
            std::ptr::null_mut()
        }
    }
}

/// One model call, journaled once. Record: sample; replay: read back - the
/// model is not called. Returns a caller-owned string, or NULL on fault.
#[no_mangle]
pub unsafe extern "C" fn prag_ctx_oracle(
    ctx: *mut PragCtx,
    prompt: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let prompt = match in_str(prompt, "prompt") {
        Ok(p) => p,
        Err(m) => {
            set_err(err_out, &m);
            return std::ptr::null_mut();
        }
    };
    ctx_value_call(ctx, err_out, |c| c.oracle(prompt))
}

/// A durable effect under the write-ahead discipline. `perform` is your tool
/// call; replay reuses the recorded result without re-performing. Returns a
/// caller-owned string, or NULL on fault.
#[no_mangle]
pub unsafe extern "C" fn prag_ctx_effect(
    ctx: *mut PragCtx,
    name: *const c_char,
    arg: *const c_char,
    perform: PragEffectFn,
    user: *mut c_void,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let (name, arg) = match (in_str(name, "name"), in_str(arg, "arg")) {
        (Ok(n), Ok(a)) => (n, a),
        (Err(m), _) | (_, Err(m)) => {
            set_err(err_out, &m);
            return std::ptr::null_mut();
        }
    };
    ctx_value_call(ctx, err_out, |c| {
        c.effect(name, arg, |a| {
            let c_arg = out_string(&a.as_str());
            let mut err: *mut c_char = std::ptr::null_mut();
            let out = perform(user, c_arg, &mut err);
            prag_str_free(c_arg);
            if out.is_null() {
                Err(Fault::ToolErr(take_callback_err(
                    err,
                    "effect callback failed",
                )))
            } else {
                prag_str_free(err);
                Ok(Value::from(take_callback_string(out)))
            }
        })
    })
}

/// Receive on a channel (journaled). Returns a caller-owned string, or NULL
/// on fault.
#[no_mangle]
pub unsafe extern "C" fn prag_ctx_recv(
    ctx: *mut PragCtx,
    channel: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let channel = match in_str(channel, "channel") {
        Ok(c) => c,
        Err(m) => {
            set_err(err_out, &m);
            return std::ptr::null_mut();
        }
    };
    ctx_value_call(ctx, err_out, |c| c.recv(channel))
}

/// A journaled clock read (nanoseconds since epoch) into `*nanos_out`.
#[no_mangle]
pub unsafe extern "C" fn prag_ctx_now(
    ctx: *mut PragCtx,
    nanos_out: *mut u64,
    err_out: *mut *mut c_char,
) -> i32 {
    let Some(wrapper) = ctx.as_mut() else {
        set_err(err_out, "ctx is NULL");
        return PRAG_ERR_INVALID;
    };
    let inner = match wrapper.get() {
        Ok(i) => i,
        Err(m) => {
            set_err(err_out, &m);
            return PRAG_ERR_INVALID;
        }
    };
    match inner.now() {
        Ok(n) => {
            wrapper.pending = None;
            if !nanos_out.is_null() {
                *nanos_out = n;
            }
            PRAG_OK
        }
        Err(f) => {
            let code = set_fault(err_out, &f);
            wrapper.pending = Some(f);
            code
        }
    }
}

/// Assert an agent contract; a falsified contract faults the run.
#[no_mangle]
pub unsafe extern "C" fn prag_ctx_contract(
    ctx: *mut PragCtx,
    holds: bool,
    msg: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    let msg = match in_str(msg, "msg") {
        Ok(m) => m,
        Err(m) => {
            set_err(err_out, &m);
            return PRAG_ERR_INVALID;
        }
    };
    let Some(wrapper) = ctx.as_mut() else {
        set_err(err_out, "ctx is NULL");
        return PRAG_ERR_INVALID;
    };
    let inner = match wrapper.get() {
        Ok(i) => i,
        Err(m) => {
            set_err(err_out, &m);
            return PRAG_ERR_INVALID;
        }
    };
    match inner.contract(holds, msg) {
        Ok(()) => {
            wrapper.pending = None;
            PRAG_OK
        }
        Err(f) => {
            let code = set_fault(err_out, &f);
            wrapper.pending = Some(f);
            code
        }
    }
}

/// 1 while steps are served from the journal, 0 while recording fresh,
/// -1 if the ctx is invalid.
#[no_mangle]
pub unsafe extern "C" fn prag_ctx_is_replaying(ctx: *mut PragCtx) -> i32 {
    let Some(wrapper) = ctx.as_mut() else {
        return -1;
    };
    match wrapper.get() {
        Ok(inner) => inner.is_replaying() as i32,
        Err(_) => -1,
    }
}

// ---------------------------------------------------------------------------
// RunReport
// ---------------------------------------------------------------------------

/// Trace label kinds (mirrored in pragmatic.h).
pub const PRAG_TRACE_ORACLE: i32 = 0;
pub const PRAG_TRACE_EFFECT: i32 = 1;
pub const PRAG_TRACE_RECV: i32 = 2;
pub const PRAG_TRACE_CLOCK: i32 = 3;
pub const PRAG_TRACE_DONE: i32 = 4;

/// The result of driving one run to completion. Free with
/// `prag_report_free`; string accessors return caller-owned copies.
pub struct PragReport {
    inner: RunReport,
}

unsafe fn report<'a>(r: *const PragReport) -> Option<&'a RunReport> {
    r.as_ref().map(|p| &p.inner)
}

#[no_mangle]
pub unsafe extern "C" fn prag_report_free(r: *mut PragReport) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

/// The agent's output (caller-owned; NULL if `r` is NULL).
#[no_mangle]
pub unsafe extern "C" fn prag_report_output(r: *const PragReport) -> *mut c_char {
    report(r)
        .map(|i| out_string(&i.output.as_str()))
        .unwrap_or(std::ptr::null_mut())
}

/// The run id (caller-owned).
#[no_mangle]
pub unsafe extern "C" fn prag_report_run_id(r: *const PragReport) -> *mut c_char {
    report(r)
        .map(|i| out_string(&i.run_id))
        .unwrap_or(std::ptr::null_mut())
}

/// Hex head of the tamper-evident hash chain (caller-owned), or NULL for an
/// empty run.
#[no_mangle]
pub unsafe extern "C" fn prag_report_chain_head(r: *const PragReport) -> *mut c_char {
    report(r)
        .and_then(|i| i.chain_head.as_ref())
        .map(|h| out_string(&pragmatic::sha256::hex(h)))
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub unsafe extern "C" fn prag_report_journal_len(r: *const PragReport) -> u64 {
    report(r).map(|i| i.journal_len).unwrap_or(0)
}

/// Steps served from the journal this attempt (zero model calls).
#[no_mangle]
pub unsafe extern "C" fn prag_report_replayed_steps(r: *const PragReport) -> u64 {
    report(r).map(|i| i.replayed_steps).unwrap_or(0)
}

/// Steps recorded fresh this attempt.
#[no_mangle]
pub unsafe extern "C" fn prag_report_fresh_steps(r: *const PragReport) -> u64 {
    report(r).map(|i| i.fresh_steps).unwrap_or(0)
}

/// Number of labels in the observable trace (identical between a recorded
/// run and its replay - T1).
#[no_mangle]
pub unsafe extern "C" fn prag_report_trace_len(r: *const PragReport) -> u64 {
    report(r).map(|i| i.trace.len() as u64).unwrap_or(0)
}

/// The kind of trace label `i` (PRAG_TRACE_*), or -1 out of range (or for a
/// kind of step the C ABI does not expose).
#[no_mangle]
pub unsafe extern "C" fn prag_report_trace_kind(r: *const PragReport, i: u64) -> i32 {
    match report(r).and_then(|rep| rep.trace.get(i as usize)) {
        Some(TraceLabel::Oracle { .. }) => PRAG_TRACE_ORACLE,
        Some(TraceLabel::Effect { .. }) => PRAG_TRACE_EFFECT,
        Some(TraceLabel::Recv { .. }) => PRAG_TRACE_RECV,
        Some(TraceLabel::Clock { .. }) => PRAG_TRACE_CLOCK,
        Some(TraceLabel::Done { .. }) => PRAG_TRACE_DONE,
        _ => -1,
    }
}

/// The journal cursor of trace label `i` (u64::MAX for Done / out of range).
#[no_mangle]
pub unsafe extern "C" fn prag_report_trace_cursor(r: *const PragReport, i: u64) -> u64 {
    report(r)
        .and_then(|rep| rep.trace.get(i as usize))
        .and_then(TraceLabel::cursor)
        .unwrap_or(u64::MAX)
}

/// A human-readable summary of trace label `i` (caller-owned), or NULL out
/// of range.
#[no_mangle]
pub unsafe extern "C" fn prag_report_trace_summary(r: *const PragReport, i: u64) -> *mut c_char {
    let summary = match report(r).and_then(|rep| rep.trace.get(i as usize)) {
        Some(TraceLabel::Oracle { outcome, .. }) => outcome.as_str().into_owned(),
        Some(TraceLabel::Effect { name, result, .. }) => format!("{name} -> {}", result.as_str()),
        Some(TraceLabel::Recv { channel, value, .. }) => format!("{channel} ? {}", value.as_str()),
        Some(TraceLabel::Clock { nanos, .. }) => nanos.to_string(),
        Some(TraceLabel::Done { output }) => output.as_str().into_owned(),
        Some(_) | None => return std::ptr::null_mut(),
    };
    out_string(&summary)
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

/// The Pragmatic runtime: journals every step an agent takes under a stable
/// run id, so it survives any crash and replays exactly.
pub struct PragRuntime {
    inner: pragmatic::Runtime<CallbackOracle>,
}

/// Open a runtime. `dir` NULL = in-memory journals (tests, ephemeral runs);
/// otherwise one append-only journal file per run persists under `dir`.
/// `oracle` wraps your model call. `key`/`key_len` (optional: NULL/0)
/// HMAC-signs the journals. Returns NULL with `*err_out` set on failure;
/// free with `prag_runtime_close`.
#[no_mangle]
pub unsafe extern "C" fn prag_runtime_open(
    dir: *const c_char,
    oracle: PragOracleFn,
    user: *mut c_void,
    key: *const u8,
    key_len: usize,
    err_out: *mut *mut c_char,
) -> *mut PragRuntime {
    let cb = CallbackOracle { func: oracle, user };
    let mut inner = if dir.is_null() {
        pragmatic::Runtime::in_memory(cb)
    } else {
        let dir = match in_str(dir, "dir") {
            Ok(d) => d,
            Err(m) => {
                set_err(err_out, &m);
                return std::ptr::null_mut();
            }
        };
        match pragmatic::Runtime::on_dir(dir, cb) {
            Ok(rt) => rt,
            Err(e) => {
                set_err(err_out, &e.to_string());
                return std::ptr::null_mut();
            }
        }
    };
    if !key.is_null() && key_len > 0 {
        inner = inner.with_key(std::slice::from_raw_parts(key, key_len));
    }
    Box::into_raw(Box::new(PragRuntime { inner }))
}

#[no_mangle]
pub unsafe extern "C" fn prag_runtime_close(rt: *mut PragRuntime) {
    if !rt.is_null() {
        drop(Box::from_raw(rt));
    }
}

enum Mode {
    Run,
    Resume,
    Replay,
}

unsafe fn drive(
    rt: *mut PragRuntime,
    run_id: *const c_char,
    agent: PragAgentFn,
    user: *mut c_void,
    mode: Mode,
    report_out: *mut *mut PragReport,
    err_out: *mut *mut c_char,
) -> i32 {
    let Some(rt) = rt.as_mut() else {
        set_err(err_out, "runtime is NULL");
        return PRAG_ERR_INVALID;
    };
    let run_id = match in_str(run_id, "run_id") {
        Ok(r) => r,
        Err(m) => {
            set_err(err_out, &m);
            return PRAG_ERR_INVALID;
        }
    };
    if !report_out.is_null() {
        *report_out = std::ptr::null_mut();
    }

    let agent_fn = |ctx: &mut pragmatic::Ctx| -> Result<Value, Fault> {
        // The C-visible ctx borrows this attempt's Ctx. The pointer is
        // nulled before the attempt returns, so references the binding
        // keeps around cannot dangle.
        let ptr: *mut pragmatic::Ctx<'static> = (ctx as *mut pragmatic::Ctx<'_>).cast();
        let mut wrapper = PragCtx { ptr, pending: None };
        let mut err: *mut c_char = std::ptr::null_mut();
        let out = agent(user, &mut wrapper, &mut err);
        wrapper.ptr = std::ptr::null_mut();
        if out.is_null() {
            match wrapper.pending.take() {
                Some(fault) => {
                    prag_str_free(err); // the typed fault carries the message
                    Err(fault)
                }
                None => Err(Fault::ToolErr(take_callback_err(
                    err,
                    "agent callback failed",
                ))),
            }
        } else {
            prag_str_free(err);
            Ok(Value::from(take_callback_string(out)))
        }
    };

    let result = catch_unwind(AssertUnwindSafe(|| match mode {
        Mode::Run => rt.inner.run(run_id, agent_fn),
        Mode::Resume => rt.inner.resume(run_id, agent_fn),
        Mode::Replay => rt.inner.replay(run_id, agent_fn),
    }));
    match result {
        Ok(Ok(rep)) => {
            if !report_out.is_null() {
                *report_out = Box::into_raw(Box::new(PragReport { inner: rep }));
            }
            PRAG_OK
        }
        Ok(Err(f)) => set_fault(err_out, &f),
        Err(_) => {
            set_err(err_out, "runtime panicked");
            PRAG_ERR_PANIC
        }
    }
}

/// Start (or continue) a durable run. Re-enterable: an existing journal
/// prefix is replayed first, so retries are idempotent. On PRAG_OK,
/// `*report_out` (optional: may be NULL) holds a report to free with
/// `prag_report_free`.
#[no_mangle]
pub unsafe extern "C" fn prag_runtime_run(
    rt: *mut PragRuntime,
    run_id: *const c_char,
    agent: PragAgentFn,
    user: *mut c_void,
    report_out: *mut *mut PragReport,
    err_out: *mut *mut c_char,
) -> i32 {
    drive(rt, run_id, agent, user, Mode::Run, report_out, err_out)
}

/// Resume a crashed run: the journaled prefix is read back (zero model
/// calls, no duplicate effects); recording continues at the tail.
#[no_mangle]
pub unsafe extern "C" fn prag_runtime_resume(
    rt: *mut PragRuntime,
    run_id: *const c_char,
    agent: PragAgentFn,
    user: *mut c_void,
    report_out: *mut *mut PragReport,
    err_out: *mut *mut c_char,
) -> i32 {
    drive(rt, run_id, agent, user, Mode::Resume, report_out, err_out)
}

/// Replay a recorded run bit-for-bit for debugging and audit (T1). The
/// model is never called.
#[no_mangle]
pub unsafe extern "C" fn prag_runtime_replay(
    rt: *mut PragRuntime,
    run_id: *const c_char,
    agent: PragAgentFn,
    user: *mut c_void,
    report_out: *mut *mut PragReport,
    err_out: *mut *mut c_char,
) -> i32 {
    drive(rt, run_id, agent, user, Mode::Replay, report_out, err_out)
}

/// Deliver a value to a run's channel inbox.
#[no_mangle]
pub unsafe extern "C" fn prag_runtime_send(
    rt: *mut PragRuntime,
    run_id: *const c_char,
    channel: *const c_char,
    value: *const c_char,
) -> i32 {
    let Some(rt) = rt.as_mut() else {
        return PRAG_ERR_INVALID;
    };
    match (
        in_str(run_id, "run_id"),
        in_str(channel, "channel"),
        in_str(value, "value"),
    ) {
        (Ok(r), Ok(c), Ok(v)) => {
            rt.inner.send(r, c, v);
            PRAG_OK
        }
        _ => PRAG_ERR_INVALID,
    }
}

/// Verify the run's journal: every chain link and commitment, and that every
/// erased slot is accounted for. PRAG_OK = intact; PRAG_ERR_TAMPERED sets
/// `*bad_cursor_out` (optional) to the first bad entry, wherever in the
/// journal the damage is; any other code is a fault loading the journal
/// (no such run, or a key mismatch).
#[no_mangle]
pub unsafe extern "C" fn prag_runtime_verify(
    rt: *mut PragRuntime,
    run_id: *const c_char,
    bad_cursor_out: *mut u64,
    err_out: *mut *mut c_char,
) -> i32 {
    let Some(rt) = rt.as_mut() else {
        set_err(err_out, "runtime is NULL");
        return PRAG_ERR_INVALID;
    };
    let run_id = match in_str(run_id, "run_id") {
        Ok(r) => r,
        Err(m) => {
            set_err(err_out, &m);
            return PRAG_ERR_INVALID;
        }
    };
    match rt.inner.verify(run_id) {
        Ok(report) if report.is_ok() => PRAG_OK,
        Ok(report) => {
            let (cursor, msg) = match report.first_bad {
                Some(c) => (c, format!("hash chain broken at cursor {c}")),
                None => {
                    let c = report
                        .unaccounted_erasures
                        .iter()
                        .chain(&report.erasure_incomplete)
                        .map(|&(c, _)| c)
                        .chain(report.invalid_erasure_notes.iter().copied())
                        .min()
                        .unwrap_or(u64::MAX);
                    (c, format!("erasure not accounted for at cursor {c}"))
                }
            };
            if !bad_cursor_out.is_null() {
                *bad_cursor_out = cursor;
            }
            set_err(err_out, &msg);
            PRAG_ERR_TAMPERED
        }
        Err(f) => set_fault(err_out, &f),
    }
}

/// The library version ("0.3.0" style), as a caller-owned string.
#[no_mangle]
pub unsafe extern "C" fn prag_version() -> *mut c_char {
    out_string(env!("CARGO_PKG_VERSION"))
}
