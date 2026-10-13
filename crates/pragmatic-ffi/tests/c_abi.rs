//! Drive the C ABI exactly as a foreign binding would: C-compatible
//! callbacks, `prag_str_new` string discipline, record → resume → replay
//! parity, typed fault propagation, and hash-chain verification.

use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

use pragmatic_ffi::*;

/// Turn a caller-owned `char*` from the library into a String (and free it).
unsafe fn take(s: *mut c_char) -> String {
    assert!(!s.is_null());
    let out = CStr::from_ptr(s).to_string_lossy().into_owned();
    prag_str_free(s);
    out
}

/// Build a callback return value the way a C caller must.
unsafe fn give(s: &str) -> *mut c_char {
    let c = CString::new(s).unwrap();
    prag_str_new(c.as_ptr())
}

/// Counts draws through the runtime's `user` pointer, the way a C caller
/// would thread state to a callback. Each test owns its counter, so tests
/// stay isolated when the harness runs them in parallel.
unsafe extern "C" fn counting_oracle(
    user: *mut c_void,
    prompt: *const c_char,
    _err: *mut *mut c_char,
) -> *mut c_char {
    let calls = &*(user as *const AtomicU64);
    let n = calls.fetch_add(1, Ordering::SeqCst);
    let p = CStr::from_ptr(prompt).to_string_lossy();
    give(&format!("completion#{n}({p})"))
}

unsafe extern "C" fn upper_effect(
    _user: *mut c_void,
    arg: *const c_char,
    _err: *mut *mut c_char,
) -> *mut c_char {
    let a = CStr::from_ptr(arg).to_string_lossy().to_uppercase();
    give(&a)
}

unsafe extern "C" fn research_agent(
    _user: *mut c_void,
    ctx: *mut PragCtx,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let fail = |e: *mut c_char| -> *mut c_char {
        if !err_out.is_null() {
            *err_out = e;
        }
        std::ptr::null_mut()
    };
    let mut err: *mut c_char = std::ptr::null_mut();

    let plan_c = CString::new("plan the task").unwrap();
    let plan = prag_ctx_oracle(ctx, plan_c.as_ptr(), &mut err);
    if plan.is_null() {
        return fail(err);
    }
    let plan = take(plan);

    let mut findings = Vec::new();
    for step in 0..3 {
        let prompt = CString::new(format!("probe {step}: {plan}")).unwrap();
        let out = prag_ctx_oracle(ctx, prompt.as_ptr(), &mut err);
        if out.is_null() {
            return fail(err);
        }
        findings.push(take(out));
    }

    let name = CString::new("publish").unwrap();
    let arg = CString::new(format!("{} findings", findings.len())).unwrap();
    let published = prag_ctx_effect(
        ctx,
        name.as_ptr(),
        arg.as_ptr(),
        upper_effect,
        std::ptr::null_mut(),
        &mut err,
    );
    if published.is_null() {
        return fail(err);
    }

    give(&format!("report({})", take(published)))
}

/// An agent that always exhausts a 1-draw budget via the second oracle call.
unsafe extern "C" fn hungry_agent(
    _user: *mut c_void,
    ctx: *mut PragCtx,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let mut err: *mut c_char = std::ptr::null_mut();
    let p = CString::new("only draw").unwrap();
    // Fault the run through a falsified contract, then return NULL without
    // setting err_out: the typed fault must propagate.
    let out = prag_ctx_oracle(ctx, p.as_ptr(), &mut err);
    prag_str_free(out);
    prag_str_free(err);
    let msg = CString::new("must not continue").unwrap();
    let code = prag_ctx_contract(ctx, false, msg.as_ptr(), &mut err);
    assert_eq!(code, PRAG_ERR_CONTRACT);
    prag_str_free(err);
    if !err_out.is_null() {
        *err_out = std::ptr::null_mut();
    }
    std::ptr::null_mut()
}

fn trace_fingerprint(r: *const PragReport) -> Vec<(i32, u64, String)> {
    unsafe {
        (0..prag_report_trace_len(r))
            .map(|i| {
                (
                    prag_report_trace_kind(r, i),
                    prag_report_trace_cursor(r, i),
                    take(prag_report_trace_summary(r, i)),
                )
            })
            .collect()
    }
}

#[test]
fn record_resume_replay_via_c_abi() {
    unsafe {
        static CALLS: AtomicU64 = AtomicU64::new(0);

        let dir = std::env::temp_dir().join(format!("prag-ffi-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_c = CString::new(dir.to_str().unwrap()).unwrap();
        let key = b"ffi-test-key";

        let mut err: *mut c_char = std::ptr::null_mut();
        let rt = prag_runtime_open(
            dir_c.as_ptr(),
            counting_oracle,
            &CALLS as *const AtomicU64 as *mut c_void,
            key.as_ptr(),
            key.len(),
            &mut err,
        );
        assert!(!rt.is_null(), "open failed");

        let run_id = CString::new("ffi-research-1").unwrap();

        // Record.
        CALLS.store(0, Ordering::SeqCst);
        let mut report: *mut PragReport = std::ptr::null_mut();
        let code = prag_runtime_run(
            rt,
            run_id.as_ptr(),
            research_agent,
            std::ptr::null_mut(),
            &mut report,
            &mut err,
        );
        assert_eq!(code, PRAG_OK, "run failed: {}", take(err));
        assert_eq!(CALLS.load(Ordering::SeqCst), 4);
        let output = take(prag_report_output(report));
        assert_eq!(output, "report(3 FINDINGS)");
        assert_eq!(prag_report_fresh_steps(report), 4);
        assert_eq!(prag_report_replayed_steps(report), 0);
        let recorded_trace = trace_fingerprint(report);
        let head = take(prag_report_chain_head(report));
        assert_eq!(head.len(), 64); // hex SHA-256
        prag_report_free(report);

        // Resume: everything comes from the journal, zero model calls.
        let mut resumed: *mut PragReport = std::ptr::null_mut();
        let code = prag_runtime_resume(
            rt,
            run_id.as_ptr(),
            research_agent,
            std::ptr::null_mut(),
            &mut resumed,
            &mut err,
        );
        assert_eq!(code, PRAG_OK, "resume failed: {}", take(err));
        assert_eq!(CALLS.load(Ordering::SeqCst), 4, "resume re-sampled");
        assert_eq!(prag_report_fresh_steps(resumed), 0);
        prag_report_free(resumed);

        // Replay: bit-for-bit trace parity (T1), model never called.
        let mut audit: *mut PragReport = std::ptr::null_mut();
        let code = prag_runtime_replay(
            rt,
            run_id.as_ptr(),
            research_agent,
            std::ptr::null_mut(),
            &mut audit,
            &mut err,
        );
        assert_eq!(code, PRAG_OK, "replay failed: {}", take(err));
        assert_eq!(CALLS.load(Ordering::SeqCst), 4, "replay hit model");
        assert_eq!(trace_fingerprint(audit), recorded_trace);
        prag_report_free(audit);

        // The chain verifies end to end.
        let mut bad: u64 = 0;
        assert_eq!(
            prag_runtime_verify(rt, run_id.as_ptr(), &mut bad, &mut err),
            PRAG_OK
        );

        prag_runtime_close(rt);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn typed_faults_survive_the_boundary() {
    unsafe {
        static CALLS: AtomicU64 = AtomicU64::new(0);

        let mut err: *mut c_char = std::ptr::null_mut();
        let rt = prag_runtime_open(
            std::ptr::null(), // in-memory
            counting_oracle,
            &CALLS as *const AtomicU64 as *mut c_void,
            std::ptr::null(),
            0,
            &mut err,
        );
        assert!(!rt.is_null());

        let run_id = CString::new("ffi-fault-1").unwrap();
        let code = prag_runtime_run(
            rt,
            run_id.as_ptr(),
            hungry_agent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut err,
        );
        // The contract fault must arrive typed, not as a generic tool error.
        assert_eq!(code, PRAG_ERR_CONTRACT);
        let msg = take(err);
        assert!(msg.contains("must not continue"), "got: {msg}");

        prag_runtime_close(rt);
    }
}

#[test]
fn channels_and_version() {
    unsafe {
        static CALLS: AtomicU64 = AtomicU64::new(0);

        let mut err: *mut c_char = std::ptr::null_mut();
        let rt = prag_runtime_open(
            std::ptr::null(),
            counting_oracle,
            &CALLS as *const AtomicU64 as *mut c_void,
            std::ptr::null(),
            0,
            &mut err,
        );
        let run = CString::new("ffi-chan-1").unwrap();
        let chan = CString::new("approvals").unwrap();
        let val = CString::new("approved").unwrap();
        assert_eq!(
            prag_runtime_send(rt, run.as_ptr(), chan.as_ptr(), val.as_ptr()),
            PRAG_OK
        );

        unsafe extern "C" fn recv_agent(
            _user: *mut c_void,
            ctx: *mut PragCtx,
            err_out: *mut *mut c_char,
        ) -> *mut c_char {
            let mut err: *mut c_char = std::ptr::null_mut();
            let chan = CString::new("approvals").unwrap();
            let got = prag_ctx_recv(ctx, chan.as_ptr(), &mut err);
            if got.is_null() {
                if !err_out.is_null() {
                    *err_out = err;
                }
                return std::ptr::null_mut();
            }
            got
        }

        let mut report: *mut PragReport = std::ptr::null_mut();
        let code = prag_runtime_run(
            rt,
            run.as_ptr(),
            recv_agent,
            std::ptr::null_mut(),
            &mut report,
            &mut err,
        );
        assert_eq!(code, PRAG_OK, "run failed: {}", take(err));
        assert_eq!(take(prag_report_output(report)), "approved");
        prag_report_free(report);
        prag_runtime_close(rt);

        assert_eq!(take(prag_version()), env!("CARGO_PKG_VERSION"));
    }
}

#[test]
fn storage_faults_map_to_the_io_code_with_their_message() {
    unsafe {
        static CALLS: AtomicU64 = AtomicU64::new(0);

        let mut err: *mut c_char = std::ptr::null_mut();
        let rt = prag_runtime_open(
            std::ptr::null(),
            counting_oracle,
            &CALLS as *const AtomicU64 as *mut c_void,
            std::ptr::null(),
            0,
            &mut err,
        );
        assert!(!rt.is_null());

        // A reserved run id is `Fault::Unsupported`, which has no code of
        // its own: it arrives as PRAG_ERR_IO with the message intact.
        let reserved = CString::new("pragmatic:internal").unwrap();
        let code = prag_runtime_run(
            rt,
            reserved.as_ptr(),
            research_agent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut err,
        );
        assert_eq!(code, PRAG_ERR_IO);
        let msg = take(err);
        assert!(msg.contains("reserved"), "got: {msg}");

        // Resuming a run that does not exist is an I/O fault too.
        let missing = CString::new("never-recorded").unwrap();
        let mut err: *mut c_char = std::ptr::null_mut();
        let code = prag_runtime_resume(
            rt,
            missing.as_ptr(),
            research_agent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut err,
        );
        assert_eq!(code, PRAG_ERR_IO);
        assert!(take(err).contains("no journal"));

        prag_runtime_close(rt);
    }
}
