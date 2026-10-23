// Pragmatic.java - Java binding for the Stet durable-execution runtime.
//
// Pure Java over the C ABI (crates/pragmatic-ffi) via java.lang.foreign
// (JDK 22+); no JNI glue to compile. Point it at the built library with
// -Dpragmatic.library=/path/to/libpragmatic_ffi.dylib (or .so / .dll).
//
//   var rt = new Pragmatic.Runtime("./journals", prompt -> callModel(prompt));
//
//   Pragmatic.Agent agent = ctx -> {
//       var plan = ctx.oracle("plan the task");            // journaled
//       return ctx.effect("publish", plan, arg -> upload(arg));
//   };
//
//   var report  = rt.run("research-42", agent);    // record
//   var resumed = rt.resume("research-42", agent); // crash-recover
//   var audit   = rt.replay("research-42", agent); // bit-for-bit, no model
//
// Faults surface as Pragmatic.FaultException. Exceptions thrown by your
// callbacks are caught at the boundary (they must never unwind into the
// runtime) and re-surface from run/resume/replay.

package pragmatic;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.ArrayList;
import java.util.List;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BOOLEAN;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

public final class Pragmatic {
    private Pragmatic() {}

    // Status codes, mirroring pragmatic.h.
    public static final int OK = 0;
    public static final int ERR_ORACLE = 1;
    public static final int ERR_TOOL = 2;
    public static final int ERR_TIMEOUT = 3;
    public static final int ERR_BUDGET = 4;
    public static final int ERR_CONTRACT = 5;
    public static final int ERR_CAPABILITY = 6;
    public static final int ERR_ESCALATED = 7;
    public static final int ERR_DESYNC = 8;
    public static final int ERR_REPLAY_EXHAUSTED = 9;
    public static final int ERR_IO = 10;
    public static final int ERR_INVALID = 11;
    public static final int ERR_PANIC = 12;
    public static final int ERR_TAMPERED = 13;

    /** A runtime fault, carrying the PRAG_ERR_* status code. */
    public static final class FaultException extends RuntimeException {
        private final int code;

        public FaultException(int code, String message) {
            super(message);
            this.code = code;
        }

        public int code() {
            return code;
        }
    }

    /** Your model call: prompt in, completion out. */
    @FunctionalInterface
    public interface Oracle {
        String call(String prompt);
    }

    /** Your agent body: drive the ctx, return the run's output. */
    @FunctionalInterface
    public interface Agent {
        String run(Ctx ctx);
    }

    /** A durable effect's perform step (tool call, external write). */
    @FunctionalInterface
    public interface Effect {
        String perform(String arg);
    }

    /** One observable step of a run's trace. */
    public record TraceLabel(Kind kind, long cursor, String summary) {
        public enum Kind { ORACLE, EFFECT, RECV, CLOCK, DONE }
    }

    // ------------------------------------------------------------------
    // Native surface
    // ------------------------------------------------------------------

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LIB = SymbolLookup.libraryLookup(
            System.getProperty("pragmatic.library", "libpragmatic_ffi"),
            Arena.global());

    private static MethodHandle handle(String name, FunctionDescriptor desc) {
        return LINKER.downcallHandle(
                LIB.find(name).orElseThrow(
                        () -> new UnsatisfiedLinkError("missing symbol: " + name)),
                desc);
    }

    private static final MethodHandle STR_NEW =
            handle("prag_str_new", FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle STR_FREE =
            handle("prag_str_free", FunctionDescriptor.ofVoid(ADDRESS));
    private static final MethodHandle RUNTIME_OPEN = handle("prag_runtime_open",
            FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
    private static final MethodHandle RUNTIME_CLOSE =
            handle("prag_runtime_close", FunctionDescriptor.ofVoid(ADDRESS));
    private static final FunctionDescriptor DRIVE_DESC = FunctionDescriptor.of(
            JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS);
    private static final MethodHandle RUNTIME_RUN = handle("prag_runtime_run", DRIVE_DESC);
    private static final MethodHandle RUNTIME_RESUME = handle("prag_runtime_resume", DRIVE_DESC);
    private static final MethodHandle RUNTIME_REPLAY = handle("prag_runtime_replay", DRIVE_DESC);
    private static final MethodHandle RUNTIME_SEND = handle("prag_runtime_send",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle RUNTIME_VERIFY = handle("prag_runtime_verify",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle CTX_ORACLE = handle("prag_ctx_oracle",
            FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle CTX_EFFECT = handle("prag_ctx_effect",
            FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle CTX_RECV = handle("prag_ctx_recv",
            FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle CTX_NOW = handle("prag_ctx_now",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
    private static final MethodHandle CTX_CONTRACT = handle("prag_ctx_contract",
            FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_BOOLEAN, ADDRESS, ADDRESS));
    private static final MethodHandle CTX_IS_REPLAYING = handle("prag_ctx_is_replaying",
            FunctionDescriptor.of(JAVA_INT, ADDRESS));
    private static final MethodHandle REPORT_FREE =
            handle("prag_report_free", FunctionDescriptor.ofVoid(ADDRESS));
    private static final MethodHandle REPORT_OUTPUT =
            handle("prag_report_output", FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle REPORT_RUN_ID =
            handle("prag_report_run_id", FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle REPORT_CHAIN_HEAD =
            handle("prag_report_chain_head", FunctionDescriptor.of(ADDRESS, ADDRESS));
    private static final MethodHandle REPORT_JOURNAL_LEN =
            handle("prag_report_journal_len", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
    private static final MethodHandle REPORT_REPLAYED =
            handle("prag_report_replayed_steps", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
    private static final MethodHandle REPORT_FRESH =
            handle("prag_report_fresh_steps", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
    private static final MethodHandle REPORT_TRACE_LEN =
            handle("prag_report_trace_len", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
    private static final MethodHandle REPORT_TRACE_KIND =
            handle("prag_report_trace_kind", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG));
    private static final MethodHandle REPORT_TRACE_CURSOR =
            handle("prag_report_trace_cursor", FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_LONG));
    private static final MethodHandle REPORT_TRACE_SUMMARY =
            handle("prag_report_trace_summary", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG));
    private static final MethodHandle VERSION =
            handle("prag_version", FunctionDescriptor.of(ADDRESS));

    // Callback descriptors (oracle/effect share a shape; agent differs only
    // in meaning).
    private static final FunctionDescriptor CALLBACK_DESC =
            FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, ADDRESS);

    /** Adopt a library-owned char* into a String (and free it). */
    private static String take(MemorySegment s) {
        if (s.equals(MemorySegment.NULL)) return null;
        try {
            return s.reinterpret(Long.MAX_VALUE).getString(0);
        } finally {
            try {
                STR_FREE.invokeExact(s);
            } catch (Throwable t) {
                throw new AssertionError(t);
            }
        }
    }

    /** Produce a callback return value under the library's ownership rule. */
    private static MemorySegment give(Arena arena, String s) {
        try {
            return (MemorySegment) STR_NEW.invokeExact(arena.allocateFrom(s));
        } catch (Throwable t) {
            throw new AssertionError(t);
        }
    }

    private static void setErr(Arena arena, MemorySegment errOut, String message) {
        if (errOut.equals(MemorySegment.NULL)) return;
        errOut.reinterpret(ADDRESS.byteSize()).set(ADDRESS, 0, give(arena, message));
    }

    private static String takeErrSlot(MemorySegment errSlot) {
        MemorySegment err = errSlot.get(ADDRESS, 0);
        return err.equals(MemorySegment.NULL) ? null : take(err);
    }

    private static MethodHandle unreflect(Class<?> owner, String name, MethodType type) {
        try {
            return MethodHandles.lookup().findStatic(owner, name, type);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    // ------------------------------------------------------------------
    // Ctx
    // ------------------------------------------------------------------

    /**
     * The durable execution context handed to your agent. Valid only inside
     * the run/resume/replay call that produced it.
     */
    public static final class Ctx {
        private final MemorySegment raw;

        private Ctx(MemorySegment raw) {
            this.raw = raw;
        }

        /**
         * One model call, journaled once. Record: sample; replay: read back
         * - the model is not called.
         */
        public String oracle(String prompt) {
            try (Arena local = Arena.ofConfined()) {
                MemorySegment errSlot = local.allocate(ADDRESS);
                MemorySegment out = (MemorySegment) CTX_ORACLE.invokeExact(
                        raw, local.allocateFrom(prompt), errSlot);
                if (out.equals(MemorySegment.NULL)) {
                    throw new FaultException(ERR_ORACLE, takeErrSlot(errSlot));
                }
                return take(out);
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /**
         * A durable effect under the write-ahead discipline; replay reuses
         * the recorded result without re-performing.
         */
        public String effect(String name, String arg, Effect perform) {
            try (Arena local = Arena.ofConfined()) {
                MemorySegment stub = effectStub(local, perform);
                MemorySegment errSlot = local.allocate(ADDRESS);
                MemorySegment out = (MemorySegment) CTX_EFFECT.invokeExact(
                        raw, local.allocateFrom(name), local.allocateFrom(arg),
                        stub, MemorySegment.NULL, errSlot);
                if (out.equals(MemorySegment.NULL)) {
                    throw new FaultException(ERR_TOOL, takeErrSlot(errSlot));
                }
                return take(out);
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /** Receive on a channel (journaled). */
        public String recv(String channel) {
            try (Arena local = Arena.ofConfined()) {
                MemorySegment errSlot = local.allocate(ADDRESS);
                MemorySegment out = (MemorySegment) CTX_RECV.invokeExact(
                        raw, local.allocateFrom(channel), errSlot);
                if (out.equals(MemorySegment.NULL)) {
                    throw new FaultException(ERR_TOOL, takeErrSlot(errSlot));
                }
                return take(out);
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /** A journaled clock read (nanoseconds since epoch). */
        public long now() {
            try (Arena local = Arena.ofConfined()) {
                MemorySegment nanos = local.allocate(JAVA_LONG);
                MemorySegment errSlot = local.allocate(ADDRESS);
                int code = (int) CTX_NOW.invokeExact(raw, nanos, errSlot);
                if (code != OK) throw new FaultException(code, takeErrSlot(errSlot));
                return nanos.get(JAVA_LONG, 0);
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /** Assert an agent contract; a falsified contract faults the run. */
        public void contract(boolean holds, String message) {
            try (Arena local = Arena.ofConfined()) {
                MemorySegment errSlot = local.allocate(ADDRESS);
                int code = (int) CTX_CONTRACT.invokeExact(
                        raw, holds, local.allocateFrom(message), errSlot);
                if (code != OK) throw new FaultException(code, takeErrSlot(errSlot));
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /** True while steps are served from the journal. */
        public boolean isReplaying() {
            try {
                return (int) CTX_IS_REPLAYING.invokeExact(raw) == 1;
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        // The effect callback trampoline. ThreadLocal carries the Java
        // closure to the static upcall target (the C user pointer is unused
        // so the stub shape stays uniform).
        private static final ThreadLocal<Effect> CURRENT_EFFECT = new ThreadLocal<>();
        private static final MethodHandle EFFECT_TARGET = unreflect(
                Ctx.class, "effectUpcall",
                MethodType.methodType(MemorySegment.class, MemorySegment.class,
                        MemorySegment.class, MemorySegment.class));

        private MemorySegment effectStub(Arena arena, Effect perform) {
            CURRENT_EFFECT.set(perform);
            return LINKER.upcallStub(EFFECT_TARGET, CALLBACK_DESC, arena);
        }

        static MemorySegment effectUpcall(
                MemorySegment user, MemorySegment arg, MemorySegment errOut) {
            try (Arena local = Arena.ofConfined()) {
                Effect perform = CURRENT_EFFECT.get();
                String result = perform.perform(
                        arg.reinterpret(Long.MAX_VALUE).getString(0));
                // give() allocates library-owned memory; the local arena only
                // held the intermediate copy.
                return give(local, result);
            } catch (Throwable t) {
                try (Arena local = Arena.ofConfined()) {
                    setErr(local, errOut, String.valueOf(t.getMessage()));
                }
                return MemorySegment.NULL;
            }
        }
    }

    // ------------------------------------------------------------------
    // RunReport
    // ------------------------------------------------------------------

    /** The result of driving one run to completion. */
    public static final class RunReport implements AutoCloseable {
        private MemorySegment raw;

        private RunReport(MemorySegment raw) {
            this.raw = raw;
        }

        private MemorySegment get() {
            if (raw == null) throw new IllegalStateException("report is closed");
            return raw;
        }

        public String output() {
            try {
                return take((MemorySegment) REPORT_OUTPUT.invokeExact(get()));
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        public String runId() {
            try {
                return take((MemorySegment) REPORT_RUN_ID.invokeExact(get()));
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /** Hex head of the tamper-evident hash chain, or null for an empty run. */
        public String chainHead() {
            try {
                return take((MemorySegment) REPORT_CHAIN_HEAD.invokeExact(get()));
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        public long journalLen() {
            try {
                return (long) REPORT_JOURNAL_LEN.invokeExact(get());
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /** Steps served from the journal (zero model calls). */
        public long replayedSteps() {
            try {
                return (long) REPORT_REPLAYED.invokeExact(get());
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /** Steps recorded fresh this attempt. */
        public long freshSteps() {
            try {
                return (long) REPORT_FRESH.invokeExact(get());
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /**
         * The observable trace - identical between a recorded run and its
         * replay (T1).
         */
        public List<TraceLabel> trace() {
            try {
                long n = (long) REPORT_TRACE_LEN.invokeExact(get());
                List<TraceLabel> out = new ArrayList<>((int) n);
                for (long i = 0; i < n; i++) {
                    int kind = (int) REPORT_TRACE_KIND.invokeExact(get(), i);
                    long cursor = (long) REPORT_TRACE_CURSOR.invokeExact(get(), i);
                    String summary =
                            take((MemorySegment) REPORT_TRACE_SUMMARY.invokeExact(get(), i));
                    out.add(new TraceLabel(TraceLabel.Kind.values()[kind], cursor, summary));
                }
                return out;
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        @Override
        public void close() {
            if (raw != null) {
                try {
                    REPORT_FREE.invokeExact(raw);
                } catch (Throwable t) {
                    throw rethrow(t);
                }
                raw = null;
            }
        }
    }

    // ------------------------------------------------------------------
    // Runtime
    // ------------------------------------------------------------------

    /**
     * The Stet runtime: journals every step an agent takes under a
     * stable run id, so it survives any crash and replays exactly.
     */
    public static final class Runtime implements AutoCloseable {
        private final Arena arena = Arena.ofShared();
        private final Oracle oracle;
        private MemorySegment raw;

        // The oracle upcall closes over this runtime via a ThreadLocal set
        // for the lifetime of the runtime's thread use.
        private static final ThreadLocal<Oracle> CURRENT_ORACLE = new ThreadLocal<>();
        private static final MethodHandle ORACLE_TARGET = unreflect(
                Runtime.class, "oracleUpcall",
                MethodType.methodType(MemorySegment.class, MemorySegment.class,
                        MemorySegment.class, MemorySegment.class));
        private static final ThreadLocal<Agent> CURRENT_AGENT = new ThreadLocal<>();
        private static final MethodHandle AGENT_TARGET = unreflect(
                Runtime.class, "agentUpcall",
                MethodType.methodType(MemorySegment.class, MemorySegment.class,
                        MemorySegment.class, MemorySegment.class));

        /**
         * Journals persist under {@code dir} (one append-only file per run);
         * {@code oracle} wraps your model. Pass null/empty dir for in-memory
         * journals (tests, ephemeral runs).
         */
        public Runtime(String dir, Oracle oracle) {
            this(dir, oracle, null);
        }

        /** As above; {@code key} (may be null) HMAC-signs the journals. */
        public Runtime(String dir, Oracle oracle, byte[] key) {
            this.oracle = oracle;
            MemorySegment stub = LINKER.upcallStub(ORACLE_TARGET, CALLBACK_DESC, arena);
            try (Arena local = Arena.ofConfined()) {
                MemorySegment errSlot = local.allocate(ADDRESS);
                MemorySegment dirSeg = (dir == null || dir.isEmpty())
                        ? MemorySegment.NULL
                        : local.allocateFrom(dir);
                MemorySegment keySeg = (key == null || key.length == 0)
                        ? MemorySegment.NULL
                        : local.allocateFrom(JAVA_BYTE, key);
                MemorySegment rt = (MemorySegment) RUNTIME_OPEN.invokeExact(
                        dirSeg, stub, MemorySegment.NULL, keySeg,
                        (long) (key == null ? 0 : key.length), errSlot);
                if (rt.equals(MemorySegment.NULL)) {
                    throw new FaultException(ERR_IO, takeErrSlot(errSlot));
                }
                this.raw = rt;
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        static MemorySegment oracleUpcall(
                MemorySegment user, MemorySegment prompt, MemorySegment errOut) {
            try (Arena local = Arena.ofConfined()) {
                String completion = CURRENT_ORACLE.get()
                        .call(prompt.reinterpret(Long.MAX_VALUE).getString(0));
                return give(local, completion);
            } catch (Throwable t) {
                try (Arena local = Arena.ofConfined()) {
                    setErr(local, errOut, String.valueOf(t.getMessage()));
                }
                return MemorySegment.NULL;
            }
        }

        static MemorySegment agentUpcall(
                MemorySegment user, MemorySegment ctx, MemorySegment errOut) {
            try (Arena local = Arena.ofConfined()) {
                Ctx wrapped = new Ctx(ctx);
                String output = CURRENT_AGENT.get().run(wrapped);
                return give(local, output);
            } catch (Throwable t) {
                try (Arena local = Arena.ofConfined()) {
                    setErr(local, errOut, String.valueOf(t.getMessage()));
                }
                return MemorySegment.NULL;
            }
        }

        private RunReport drive(MethodHandle f, String runId, Agent agent) {
            if (raw == null) throw new IllegalStateException("runtime is closed");
            CURRENT_ORACLE.set(oracle);
            CURRENT_AGENT.set(agent);
            try (Arena local = Arena.ofConfined()) {
                MemorySegment stub = LINKER.upcallStub(AGENT_TARGET, CALLBACK_DESC, local);
                MemorySegment reportSlot = local.allocate(ADDRESS);
                MemorySegment errSlot = local.allocate(ADDRESS);
                int code = (int) f.invokeExact(raw, local.allocateFrom(runId),
                        stub, MemorySegment.NULL, reportSlot, errSlot);
                if (code != OK) {
                    throw new FaultException(code, takeErrSlot(errSlot));
                }
                return new RunReport(reportSlot.get(ADDRESS, 0));
            } catch (Throwable t) {
                throw rethrow(t);
            } finally {
                CURRENT_AGENT.remove();
            }
        }

        /**
         * Start (or continue) a durable run - re-enterable, retries are
         * idempotent.
         */
        public RunReport run(String runId, Agent agent) {
            return drive(RUNTIME_RUN, runId, agent);
        }

        /**
         * Resume a crashed run: the journaled prefix is read back (zero
         * model calls, no duplicate effects); recording continues at the
         * tail.
         */
        public RunReport resume(String runId, Agent agent) {
            return drive(RUNTIME_RESUME, runId, agent);
        }

        /**
         * Replay a recorded run bit-for-bit for debugging and audit (T1).
         * The model is never called.
         */
        public RunReport replay(String runId, Agent agent) {
            return drive(RUNTIME_REPLAY, runId, agent);
        }

        /** Deliver a value to a run's channel inbox. */
        public void send(String runId, String channel, String value) {
            if (raw == null) throw new IllegalStateException("runtime is closed");
            try (Arena local = Arena.ofConfined()) {
                int ignored = (int) RUNTIME_SEND.invokeExact(raw,
                        local.allocateFrom(runId), local.allocateFrom(channel),
                        local.allocateFrom(value));
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        /**
         * Walk the run's tamper-evident hash chain. Returns true if intact,
         * false on tampering; throws on any other fault.
         */
        public boolean verify(String runId) {
            if (raw == null) throw new IllegalStateException("runtime is closed");
            try (Arena local = Arena.ofConfined()) {
                MemorySegment errSlot = local.allocate(ADDRESS);
                int code = (int) RUNTIME_VERIFY.invokeExact(raw,
                        local.allocateFrom(runId), MemorySegment.NULL, errSlot);
                if (code == OK) return true;
                String err = takeErrSlot(errSlot);
                if (code == ERR_TAMPERED) return false;
                throw new FaultException(code, err);
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }

        @Override
        public void close() {
            if (raw != null) {
                try {
                    RUNTIME_CLOSE.invokeExact(raw);
                } catch (Throwable t) {
                    throw rethrow(t);
                }
                raw = null;
                arena.close();
            }
        }
    }

    /** The linked runtime's version. */
    public static String version() {
        try {
            return take((MemorySegment) VERSION.invokeExact());
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException r) return r;
        if (t instanceof Error e) throw e;
        return new IllegalStateException(t);
    }
}
