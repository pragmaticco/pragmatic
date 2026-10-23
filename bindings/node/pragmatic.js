// pragmatic.js - Node.js binding for the Stet durable-execution runtime.
//
// Binds the C ABI (crates/pragmatic-ffi) through koffi (Node has no built-in
// FFI). Build the library first: cargo build -p pragmatic-ffi. Point the
// binding at it with PRAGMATIC_LIBRARY=/path/to/libpragmatic_ffi.dylib, or
// let it default to ../../target/debug relative to this file.
//
//   const { Runtime } = require('./pragmatic');
//
//   const rt = new Runtime('./journals', (prompt) => callModel(prompt));
//
//   const agent = (ctx) => {
//     const plan = ctx.oracle('plan the task');            // journaled
//     return ctx.effect('publish', plan, (arg) => upload(arg));
//   };
//
//   const report  = rt.run('research-42', agent);    // record
//   const resumed = rt.resume('research-42', agent); // crash-recover
//   const audit   = rt.replay('research-42', agent); // bit-for-bit, no model
//
// Faults surface as FaultError with the PRAG_ERR_* code.

'use strict';

const path = require('node:path');
const koffi = require('koffi');

// Status codes, mirroring pragmatic.h.
const codes = {
  OK: 0,
  ERR_ORACLE: 1,
  ERR_TOOL: 2,
  ERR_TIMEOUT: 3,
  ERR_BUDGET: 4,
  ERR_CONTRACT: 5,
  ERR_CAPABILITY: 6,
  ERR_ESCALATED: 7,
  ERR_DESYNC: 8,
  ERR_REPLAY_EXHAUSTED: 9,
  ERR_IO: 10,
  ERR_INVALID: 11,
  ERR_PANIC: 12,
  ERR_TAMPERED: 13,
};

const TraceKind = Object.freeze({
  ORACLE: 0,
  EFFECT: 1,
  RECV: 2,
  CLOCK: 3,
  DONE: 4,
});

/** A typed runtime fault. */
class FaultError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FaultError';
    this.code = code;
  }
}

function defaultLibrary() {
  const base = path.join(__dirname, '..', '..', 'target', 'debug');
  const name =
    process.platform === 'darwin'
      ? 'libpragmatic_ffi.dylib'
      : process.platform === 'win32'
        ? 'pragmatic_ffi.dll'
        : 'libpragmatic_ffi.so';
  return path.join(base, name);
}

const lib = koffi.load(process.env.PRAGMATIC_LIBRARY || defaultLibrary());

// Library-owned strings: decode to a JS string, then hand the original
// pointer back to prag_str_free.
const strFreeRaw = lib.func('void prag_str_free(void* s)');
const HeapStr = koffi.disposable('PragHeapStr', 'str', strFreeRaw);

// Callback prototypes. Returns stay raw pointers (from prag_str_new); the
// err_out slot is unused from JS - failures are carried via `pending` below
// and the runtime's typed pending-fault path.
const OracleProto = koffi.proto('void* PragOracleFn(void* user, const char* prompt, void* err_out)');
const AgentProto = koffi.proto('void* PragAgentFn(void* user, void* ctx, void* err_out)');
const EffectProto = koffi.proto('void* PragEffectFn(void* user, const char* arg, void* err_out)');

const fns = {
  strNew: lib.func('void* prag_str_new(const char* s)'),
  runtimeOpen: lib.func(
    'void* prag_runtime_open(const char* dir, PragOracleFn* oracle, void* user, const uint8_t* key, size_t key_len, _Out_ PragHeapStr* err_out)'
  ),
  runtimeClose: lib.func('void prag_runtime_close(void* rt)'),
  runtimeRun: lib.func(
    'int prag_runtime_run(void* rt, const char* run_id, PragAgentFn* agent, void* user, _Out_ void** report_out, _Out_ PragHeapStr* err_out)'
  ),
  runtimeResume: lib.func(
    'int prag_runtime_resume(void* rt, const char* run_id, PragAgentFn* agent, void* user, _Out_ void** report_out, _Out_ PragHeapStr* err_out)'
  ),
  runtimeReplay: lib.func(
    'int prag_runtime_replay(void* rt, const char* run_id, PragAgentFn* agent, void* user, _Out_ void** report_out, _Out_ PragHeapStr* err_out)'
  ),
  runtimeSend: lib.func(
    'int prag_runtime_send(void* rt, const char* run_id, const char* channel, const char* value)'
  ),
  runtimeVerify: lib.func(
    'int prag_runtime_verify(void* rt, const char* run_id, _Out_ uint64_t* bad_cursor_out, _Out_ PragHeapStr* err_out)'
  ),
  ctxOracle: lib.func(
    'PragHeapStr prag_ctx_oracle(void* ctx, const char* prompt, _Out_ PragHeapStr* err_out)'
  ),
  ctxEffect: lib.func(
    'PragHeapStr prag_ctx_effect(void* ctx, const char* name, const char* arg, PragEffectFn* perform, void* user, _Out_ PragHeapStr* err_out)'
  ),
  ctxRecv: lib.func(
    'PragHeapStr prag_ctx_recv(void* ctx, const char* channel, _Out_ PragHeapStr* err_out)'
  ),
  ctxNow: lib.func(
    'int prag_ctx_now(void* ctx, _Out_ uint64_t* nanos_out, _Out_ PragHeapStr* err_out)'
  ),
  ctxContract: lib.func(
    'int prag_ctx_contract(void* ctx, bool holds, const char* msg, _Out_ PragHeapStr* err_out)'
  ),
  ctxIsReplaying: lib.func('int prag_ctx_is_replaying(void* ctx)'),
  reportFree: lib.func('void prag_report_free(void* r)'),
  reportOutput: lib.func('PragHeapStr prag_report_output(void* r)'),
  reportRunId: lib.func('PragHeapStr prag_report_run_id(void* r)'),
  reportChainHead: lib.func('PragHeapStr prag_report_chain_head(void* r)'),
  reportJournalLen: lib.func('uint64_t prag_report_journal_len(void* r)'),
  reportReplayed: lib.func('uint64_t prag_report_replayed_steps(void* r)'),
  reportFresh: lib.func('uint64_t prag_report_fresh_steps(void* r)'),
  reportTraceLen: lib.func('uint64_t prag_report_trace_len(void* r)'),
  reportTraceKind: lib.func('int prag_report_trace_kind(void* r, uint64_t i)'),
  reportTraceCursor: lib.func('uint64_t prag_report_trace_cursor(void* r, uint64_t i)'),
  reportTraceSummary: lib.func('PragHeapStr prag_report_trace_summary(void* r, uint64_t i)'),
  version: lib.func('PragHeapStr prag_version()'),
};

/** Produce a callback return value under the library's ownership rule. */
function give(s) {
  return fns.strNew(String(s));
}

// The most recent JS-side callback failure, surfaced when the runtime
// reports a generic tool fault whose message came from a lost JS exception.
let pending = null;

function throwFault(code, message) {
  if (pending !== null) {
    const p = pending;
    pending = null;
    if (code === codes.ERR_TOOL || code === codes.ERR_ORACLE) throw p;
  }
  throw new FaultError(code, message ?? 'unknown fault');
}

/**
 * The durable execution context handed to your agent. Valid only inside the
 * run/resume/replay call that produced it.
 */
class Ctx {
  #raw;

  constructor(raw) {
    this.#raw = raw;
  }

  /**
   * One model call, journaled once. Record: sample; replay: read back - the
   * model is not called.
   */
  oracle(prompt) {
    const err = [null];
    const out = fns.ctxOracle(this.#raw, String(prompt), err);
    if (out === null) throwFault(codes.ERR_ORACLE, err[0]);
    return out;
  }

  /**
   * A durable effect under the write-ahead discipline; replay reuses the
   * recorded result without re-performing.
   */
  effect(name, arg, perform) {
    const cb = koffi.register((_user, cbArg, _errOut) => {
      try {
        return give(perform(cbArg));
      } catch (e) {
        pending = e instanceof Error ? e : new Error(String(e));
        return null;
      }
    }, koffi.pointer(EffectProto));
    try {
      const err = [null];
      const out = fns.ctxEffect(this.#raw, String(name), String(arg), cb, null, err);
      if (out === null) throwFault(codes.ERR_TOOL, err[0]);
      return out;
    } finally {
      koffi.unregister(cb);
    }
  }

  /** Receive on a channel (journaled). */
  recv(channel) {
    const err = [null];
    const out = fns.ctxRecv(this.#raw, String(channel), err);
    if (out === null) throwFault(codes.ERR_TOOL, err[0]);
    return out;
  }

  /** A journaled clock read (nanoseconds since epoch, as BigInt). */
  now() {
    const nanos = [0n];
    const err = [null];
    const code = fns.ctxNow(this.#raw, nanos, err);
    if (code !== codes.OK) throwFault(code, err[0]);
    return BigInt(nanos[0]);
  }

  /** Assert an agent contract; a falsified contract faults the run. */
  contract(holds, message) {
    const err = [null];
    const code = fns.ctxContract(this.#raw, Boolean(holds), String(message), err);
    if (code !== codes.OK) throwFault(code, err[0]);
  }

  /** True while steps are served from the journal. */
  isReplaying() {
    return fns.ctxIsReplaying(this.#raw) === 1;
  }
}

function readReport(raw) {
  try {
    const n = Number(fns.reportTraceLen(raw));
    const trace = [];
    for (let i = 0; i < n; i++) {
      trace.push({
        kind: fns.reportTraceKind(raw, i),
        cursor: BigInt(fns.reportTraceCursor(raw, i)),
        summary: fns.reportTraceSummary(raw, i),
      });
    }
    return {
      runId: fns.reportRunId(raw),
      output: fns.reportOutput(raw),
      chainHead: fns.reportChainHead(raw), // null for an empty run
      journalLen: Number(fns.reportJournalLen(raw)),
      replayedSteps: Number(fns.reportReplayed(raw)),
      freshSteps: Number(fns.reportFresh(raw)),
      trace,
    };
  } finally {
    fns.reportFree(raw);
  }
}

/**
 * The Stet runtime: journals every step an agent takes under a stable
 * run id, so it survives any crash and replays exactly.
 */
class Runtime {
  #raw;
  #oracleCb;

  /**
   * Journals persist under `dir` (one append-only file per run); `oracle`
   * wraps your model, `(prompt) => completion`. Pass a null/empty dir for
   * in-memory journals (tests, ephemeral runs). `key` (Buffer, optional)
   * HMAC-signs the journals.
   */
  constructor(dir, oracle, key = null) {
    this.#oracleCb = koffi.register((_user, prompt, _errOut) => {
      try {
        return give(oracle(prompt));
      } catch (e) {
        pending = e instanceof Error ? e : new Error(String(e));
        return null;
      }
    }, koffi.pointer(OracleProto));
    const err = [null];
    const raw = fns.runtimeOpen(
      dir ? String(dir) : null,
      this.#oracleCb,
      null,
      key,
      key ? key.length : 0,
      err
    );
    if (raw === null) {
      koffi.unregister(this.#oracleCb);
      throw new FaultError(codes.ERR_IO, err[0] ?? 'open failed');
    }
    this.#raw = raw;
  }

  #drive(f, runId, agent) {
    if (this.#raw === undefined) throw new Error('runtime is closed');
    pending = null;
    const cb = koffi.register((_user, rawCtx, _errOut) => {
      try {
        return give(agent(new Ctx(rawCtx)));
      } catch (e) {
        if (pending === null) pending = e instanceof Error ? e : new Error(String(e));
        return null;
      }
    }, koffi.pointer(AgentProto));
    try {
      const report = [null];
      const err = [null];
      const code = f(this.#raw, String(runId), cb, null, report, err);
      if (code !== codes.OK) throwFault(code, err[0]);
      pending = null;
      return readReport(report[0]);
    } finally {
      koffi.unregister(cb);
    }
  }

  /**
   * Start (or continue) a durable run - re-enterable, retries are
   * idempotent.
   */
  run(runId, agent) {
    return this.#drive(fns.runtimeRun, runId, agent);
  }

  /**
   * Resume a crashed run: the journaled prefix is read back (zero model
   * calls, no duplicate effects); recording continues at the tail.
   */
  resume(runId, agent) {
    return this.#drive(fns.runtimeResume, runId, agent);
  }

  /**
   * Replay a recorded run bit-for-bit for debugging and audit (T1). The
   * model is never called.
   */
  replay(runId, agent) {
    return this.#drive(fns.runtimeReplay, runId, agent);
  }

  /** Deliver a value to a run's channel inbox. */
  send(runId, channel, value) {
    if (this.#raw === undefined) throw new Error('runtime is closed');
    fns.runtimeSend(this.#raw, String(runId), String(channel), String(value));
  }

  /**
   * Walk the run's tamper-evident hash chain. Returns true if intact,
   * false on tampering; throws on any other fault.
   */
  verify(runId) {
    if (this.#raw === undefined) throw new Error('runtime is closed');
    const bad = [0n];
    const err = [null];
    const code = fns.runtimeVerify(this.#raw, String(runId), bad, err);
    if (code === codes.OK) return true;
    if (code === codes.ERR_TAMPERED) return false;
    throw new FaultError(code, err[0] ?? 'verify failed');
  }

  /** Release the runtime. */
  close() {
    if (this.#raw !== undefined) {
      fns.runtimeClose(this.#raw);
      koffi.unregister(this.#oracleCb);
      this.#raw = undefined;
    }
  }
}

/** The linked runtime's version. */
function version() {
  return fns.version();
}

module.exports = { Runtime, Ctx, FaultError, TraceKind, codes, version };
