// Package pragmatic is the Go binding for the Stet durable-execution
// runtime: a journal of every step an agent takes (model calls, effects,
// receives, clock reads), so a run survives any crash and replays exactly -
// nondeterministic model behavior included.
//
// It binds the C ABI (crates/pragmatic-ffi) via cgo; build libpragmatic_ffi
// first (cargo build -p pragmatic-ffi).
//
//	rt, _ := pragmatic.Open("./journals", func(prompt string) (string, error) {
//		return callModel(prompt) // journaled
//	}, nil)
//	defer rt.Close()
//
//	agent := func(ctx *pragmatic.Ctx) (string, error) {
//		plan, err := ctx.Oracle("plan the task") // journaled
//		if err != nil {
//			return "", err
//		}
//		return ctx.Effect("publish", plan, func(arg string) (string, error) {
//			return upload(arg) // write-ahead journaled
//		})
//	}
//
//	report, _ := rt.Run("research-42", agent)    // record
//	resumed, _ := rt.Resume("research-42", agent) // crash-recover
//	audit, _ := rt.Replay("research-42", agent)   // bit-for-bit, no model
//
// Faults surface as *pragmatic.Fault with the PRAG_ERR_* code.
package pragmatic

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/pragmatic-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/debug -lpragmatic_ffi
#cgo darwin LDFLAGS: -Wl,-rpath,${SRCDIR}/../../target/debug
#cgo linux LDFLAGS: -Wl,-rpath=${SRCDIR}/../../target/debug
#include <stdlib.h>
#include "pragmatic.h"

// Go-exported bridges (cgo generates char*, not const char*, parameters;
// these thunks adapt to the header's callback signatures).
extern char* goOracleBridge(void* user, char* prompt, char** errOut);
extern char* goAgentBridge(void* user, PragCtx* ctx, char** errOut);
extern char* goEffectBridge(void* user, char* arg, char** errOut);

static char* prag_go_oracle_thunk(void* user, const char* prompt, char** err_out) {
	return goOracleBridge(user, (char*)prompt, err_out);
}
static char* prag_go_agent_thunk(void* user, PragCtx* ctx, char** err_out) {
	return goAgentBridge(user, ctx, err_out);
}
static char* prag_go_effect_thunk(void* user, const char* arg, char** err_out) {
	return goEffectBridge(user, (char*)arg, err_out);
}

static PragRuntime* prag_go_open(const char* dir, void* user, const uint8_t* key,
                                 size_t key_len, char** err_out) {
	return prag_runtime_open(dir, prag_go_oracle_thunk, user, key, key_len, err_out);
}
static int prag_go_run(PragRuntime* rt, const char* id, void* user,
                       PragReport** rep, char** err) {
	return prag_runtime_run(rt, id, prag_go_agent_thunk, user, rep, err);
}
static int prag_go_resume(PragRuntime* rt, const char* id, void* user,
                          PragReport** rep, char** err) {
	return prag_runtime_resume(rt, id, prag_go_agent_thunk, user, rep, err);
}
static int prag_go_replay(PragRuntime* rt, const char* id, void* user,
                          PragReport** rep, char** err) {
	return prag_runtime_replay(rt, id, prag_go_agent_thunk, user, rep, err);
}
static char* prag_go_effect(PragCtx* ctx, const char* name, const char* arg,
                            void* user, char** err) {
	return prag_ctx_effect(ctx, name, arg, prag_go_effect_thunk, user, err);
}
*/
import "C"

import (
	"fmt"
	"runtime/cgo"
	"unsafe"
)

// Fault codes, mirroring pragmatic.h.
const (
	OK              = 0
	ErrOracle       = 1  // the model call itself failed
	ErrTool         = 2  // a durable effect failed
	ErrTimeout      = 3
	ErrBudget       = 4  // step/cost budget consumed
	ErrContract     = 5  // an agent contract was falsified
	ErrCapability   = 6  // effect without a capability
	ErrEscalated    = 7  // fault propagated from a child agent
	ErrDesync       = 8  // journal disagrees with the program
	ErrReplayExh    = 9  // recorded run never got this far
	ErrIO           = 10
	ErrInvalid      = 11
	ErrPanic        = 12
	ErrTampered     = 13 // hash-chain verification failed
)

// Fault is a typed runtime fault.
type Fault struct {
	Code    int
	Message string
}

func (f *Fault) Error() string { return f.Message }

// Oracle wraps your model call: prompt in, completion out.
type Oracle func(prompt string) (string, error)

// Agent is your agent body: drive the ctx, return the run's output.
type Agent func(ctx *Ctx) (string, error)

// Effect is a durable effect's perform step (tool call, external write).
type Effect func(arg string) (string, error)

// TraceKind labels one observable step of a run's trace.
type TraceKind int

const (
	TraceOracle TraceKind = 0
	TraceEffect TraceKind = 1
	TraceRecv   TraceKind = 2
	TraceClock  TraceKind = 3
	TraceDone   TraceKind = 4
)

// TraceLabel is one observable step; the sequence is identical between a
// recorded run and its replay (T1).
type TraceLabel struct {
	Kind    TraceKind
	Cursor  uint64
	Summary string
}

// RunReport is the result of driving one run to completion.
type RunReport struct {
	RunID         string
	Output        string
	ChainHead     string // hex head of the hash chain; "" for an empty run
	JournalLen    uint64
	ReplayedSteps uint64 // steps served from the journal (zero model calls)
	FreshSteps    uint64 // steps recorded fresh this attempt
	Trace         []TraceLabel
}

// take adopts a library-owned char* into a Go string.
func take(s *C.char) string {
	if s == nil {
		return ""
	}
	out := C.GoString(s)
	C.prag_str_free(s)
	return out
}

// give produces a callback return value under the library's ownership rule.
func give(s string) *C.char {
	c := C.CString(s)
	defer C.free(unsafe.Pointer(c))
	return C.prag_str_new(c)
}

func setErr(errOut **C.char, msg string) {
	if errOut != nil {
		*errOut = give(msg)
	}
}

func takeErr(errSlot *C.char, code int, fallback string) *Fault {
	msg := fallback
	if errSlot != nil {
		msg = take(errSlot)
	}
	return &Fault{Code: code, Message: msg}
}

//export goOracleBridge
func goOracleBridge(user unsafe.Pointer, prompt *C.char, errOut **C.char) *C.char {
	oracle := cgo.Handle(user).Value().(Oracle)
	out, err := oracle(C.GoString(prompt))
	if err != nil {
		setErr(errOut, err.Error())
		return nil
	}
	return give(out)
}

//export goAgentBridge
func goAgentBridge(user unsafe.Pointer, ctx *C.PragCtx, errOut **C.char) *C.char {
	agent := cgo.Handle(user).Value().(Agent)
	out, err := agent(&Ctx{raw: ctx})
	if err != nil {
		setErr(errOut, err.Error())
		return nil
	}
	return give(out)
}

//export goEffectBridge
func goEffectBridge(user unsafe.Pointer, arg *C.char, errOut **C.char) *C.char {
	perform := cgo.Handle(user).Value().(Effect)
	out, err := perform(C.GoString(arg))
	if err != nil {
		setErr(errOut, err.Error())
		return nil
	}
	return give(out)
}

// Ctx is the durable execution context handed to your agent. Valid only
// inside the Run/Resume/Replay call that produced it.
type Ctx struct {
	raw *C.PragCtx
}

// Oracle makes one model call, journaled once. Record: sample; replay: read
// back - the model is not called.
func (c *Ctx) Oracle(prompt string) (string, error) {
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))
	var errSlot *C.char
	out := C.prag_ctx_oracle(c.raw, cPrompt, &errSlot)
	if out == nil {
		return "", takeErr(errSlot, ErrOracle, "oracle failed")
	}
	return take(out), nil
}

// Effect runs a durable effect under the write-ahead discipline; replay
// reuses the recorded result without re-performing.
func (c *Ctx) Effect(name, arg string, perform Effect) (string, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	cArg := C.CString(arg)
	defer C.free(unsafe.Pointer(cArg))
	h := cgo.NewHandle(perform)
	defer h.Delete()
	var errSlot *C.char
	out := C.prag_go_effect(c.raw, cName, cArg, unsafe.Pointer(h), &errSlot)
	if out == nil {
		return "", takeErr(errSlot, ErrTool, "effect failed")
	}
	return take(out), nil
}

// Recv receives on a channel (journaled).
func (c *Ctx) Recv(channel string) (string, error) {
	cChannel := C.CString(channel)
	defer C.free(unsafe.Pointer(cChannel))
	var errSlot *C.char
	out := C.prag_ctx_recv(c.raw, cChannel, &errSlot)
	if out == nil {
		return "", takeErr(errSlot, ErrTool, "recv failed")
	}
	return take(out), nil
}

// Now is a journaled clock read (nanoseconds since epoch).
func (c *Ctx) Now() (uint64, error) {
	var nanos C.uint64_t
	var errSlot *C.char
	code := C.prag_ctx_now(c.raw, &nanos, &errSlot)
	if code != C.PRAG_OK {
		return 0, takeErr(errSlot, int(code), "clock failed")
	}
	return uint64(nanos), nil
}

// Contract asserts an agent contract; a falsified contract faults the run.
func (c *Ctx) Contract(holds bool, msg string) error {
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	var errSlot *C.char
	code := C.prag_ctx_contract(c.raw, C.bool(holds), cMsg, &errSlot)
	if code != C.PRAG_OK {
		return takeErr(errSlot, int(code), "contract failed")
	}
	return nil
}

// IsReplaying reports whether steps are being served from the journal.
func (c *Ctx) IsReplaying() bool {
	return C.prag_ctx_is_replaying(c.raw) == 1
}

// Runtime journals every step an agent takes under a stable run id, so it
// survives any crash and replays exactly.
type Runtime struct {
	raw    *C.PragRuntime
	oracle cgo.Handle
}

// Open a runtime. dir "" = in-memory journals (tests, ephemeral runs);
// otherwise one append-only journal file per run persists under dir. key
// (may be nil) HMAC-signs the journals.
func Open(dir string, oracle Oracle, key []byte) (*Runtime, error) {
	h := cgo.NewHandle(oracle)
	var cDir *C.char
	if dir != "" {
		cDir = C.CString(dir)
		defer C.free(unsafe.Pointer(cDir))
	}
	var cKey *C.uint8_t
	if len(key) > 0 {
		cKey = (*C.uint8_t)(unsafe.Pointer(&key[0]))
	}
	var errSlot *C.char
	rt := C.prag_go_open(cDir, unsafe.Pointer(h), cKey, C.size_t(len(key)), &errSlot)
	if rt == nil {
		h.Delete()
		return nil, takeErr(errSlot, ErrIO, "open failed")
	}
	return &Runtime{raw: rt, oracle: h}, nil
}

// Close releases the runtime.
func (rt *Runtime) Close() {
	if rt.raw != nil {
		C.prag_runtime_close(rt.raw)
		rt.raw = nil
		rt.oracle.Delete()
	}
}

type driveFn func(rt *C.PragRuntime, id *C.char, user unsafe.Pointer,
	rep **C.PragReport, err **C.char) C.int

func (rt *Runtime) drive(f driveFn, runID string, agent Agent) (*RunReport, error) {
	cID := C.CString(runID)
	defer C.free(unsafe.Pointer(cID))
	h := cgo.NewHandle(agent)
	defer h.Delete()
	var rep *C.PragReport
	var errSlot *C.char
	code := f(rt.raw, cID, unsafe.Pointer(h), &rep, &errSlot)
	if code != C.PRAG_OK {
		return nil, takeErr(errSlot, int(code), "run failed")
	}
	defer C.prag_report_free(rep)

	n := uint64(C.prag_report_trace_len(rep))
	trace := make([]TraceLabel, 0, n)
	for i := uint64(0); i < n; i++ {
		trace = append(trace, TraceLabel{
			Kind:    TraceKind(C.prag_report_trace_kind(rep, C.uint64_t(i))),
			Cursor:  uint64(C.prag_report_trace_cursor(rep, C.uint64_t(i))),
			Summary: take(C.prag_report_trace_summary(rep, C.uint64_t(i))),
		})
	}
	return &RunReport{
		RunID:         take(C.prag_report_run_id(rep)),
		Output:        take(C.prag_report_output(rep)),
		ChainHead:     take(C.prag_report_chain_head(rep)),
		JournalLen:    uint64(C.prag_report_journal_len(rep)),
		ReplayedSteps: uint64(C.prag_report_replayed_steps(rep)),
		FreshSteps:    uint64(C.prag_report_fresh_steps(rep)),
		Trace:         trace,
	}, nil
}

// Run starts (or continues) a durable run - re-enterable, retries are
// idempotent.
func (rt *Runtime) Run(runID string, agent Agent) (*RunReport, error) {
	return rt.drive(func(r *C.PragRuntime, id *C.char, u unsafe.Pointer,
		rep **C.PragReport, err **C.char) C.int {
		return C.prag_go_run(r, id, u, rep, err)
	}, runID, agent)
}

// Resume continues a crashed run: the journaled prefix is read back (zero
// model calls, no duplicate effects); recording continues at the tail.
func (rt *Runtime) Resume(runID string, agent Agent) (*RunReport, error) {
	return rt.drive(func(r *C.PragRuntime, id *C.char, u unsafe.Pointer,
		rep **C.PragReport, err **C.char) C.int {
		return C.prag_go_resume(r, id, u, rep, err)
	}, runID, agent)
}

// Replay reproduces a recorded run bit-for-bit for debugging and audit
// (T1). The model is never called.
func (rt *Runtime) Replay(runID string, agent Agent) (*RunReport, error) {
	return rt.drive(func(r *C.PragRuntime, id *C.char, u unsafe.Pointer,
		rep **C.PragReport, err **C.char) C.int {
		return C.prag_go_replay(r, id, u, rep, err)
	}, runID, agent)
}

// Send delivers a value to a run's channel inbox.
func (rt *Runtime) Send(runID, channel, value string) {
	cID := C.CString(runID)
	defer C.free(unsafe.Pointer(cID))
	cChannel := C.CString(channel)
	defer C.free(unsafe.Pointer(cChannel))
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	C.prag_runtime_send(rt.raw, cID, cChannel, cValue)
}

// Verify walks the run's tamper-evident hash chain. Returns nil if intact;
// a *Fault with Code ErrTampered (BadCursor set) on tampering.
func (rt *Runtime) Verify(runID string) error {
	cID := C.CString(runID)
	defer C.free(unsafe.Pointer(cID))
	var bad C.uint64_t
	var errSlot *C.char
	code := C.prag_runtime_verify(rt.raw, cID, &bad, &errSlot)
	if code == C.PRAG_OK {
		return nil
	}
	return takeErr(errSlot, int(code), fmt.Sprintf("verification failed at cursor %d", uint64(bad)))
}

// Version reports the linked runtime's version.
func Version() string {
	return take(C.prag_version())
}
