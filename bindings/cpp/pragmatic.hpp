// pragmatic.hpp - C++17 binding for the Stet durable-execution runtime.
//
// Header-only RAII wrapper over the C ABI (crates/pragmatic-ffi,
// include/pragmatic.h). Link against libpragmatic_ffi.
//
//   #include "pragmatic.hpp"
//
//   pragmatic::Runtime rt("./journals", [](const std::string& prompt) {
//       return call_your_model(prompt);            // journaled
//   });
//
//   auto agent = [](pragmatic::Ctx& ctx) {
//       auto plan = ctx.oracle("plan the task");   // journaled
//       return ctx.effect("publish", plan, [](const std::string& arg) {
//           return upload(arg);                    // write-ahead journaled
//       });
//   };
//
//   auto report  = rt.run("research-42", agent);    // record
//   auto resumed = rt.resume("research-42", agent); // crash-recover
//   auto audit   = rt.replay("research-42", agent); // bit-for-bit, no model
//
// Faults surface as pragmatic::FaultError. Exceptions thrown by your
// callbacks are caught at the boundary (never unwind into the runtime) and
// re-surface as FaultError from run/resume/replay.

#ifndef PRAGMATIC_HPP
#define PRAGMATIC_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "pragmatic.h"

namespace pragmatic {

/// A runtime fault, carrying the PRAG_ERR_* status code.
class FaultError : public std::runtime_error {
public:
    FaultError(int code, const std::string& what)
        : std::runtime_error(what), code_(code) {}
    int code() const noexcept { return code_; }

private:
    int code_;
};

namespace detail {

/// Adopt a library-owned char* into a std::string.
inline std::string take(char* s) {
    if (s == nullptr) return {};
    std::string out(s);
    prag_str_free(s);
    return out;
}

/// Produce a callback return value under the library's ownership rule.
inline char* give(const std::string& s) { return prag_str_new(s.c_str()); }

[[noreturn]] inline void throw_fault(int code, char* err) {
    std::string msg = err ? take(err) : "unknown fault";
    throw FaultError(code, msg);
}

/// Run a callback body; on exception, set *err_out and return NULL so the
/// exception never crosses the C boundary.
template <typename F>
char* guarded(char** err_out, F&& body) noexcept {
    try {
        return give(body());
    } catch (const std::exception& e) {
        if (err_out) *err_out = prag_str_new(e.what());
        return nullptr;
    } catch (...) {
        if (err_out) *err_out = prag_str_new("unknown C++ exception");
        return nullptr;
    }
}

} // namespace detail

/// One observable step of a run's trace.
struct TraceLabel {
    enum class Kind { Oracle, Effect, Recv, Clock, Done };
    Kind kind;
    std::uint64_t cursor; // UINT64_MAX for Done
    std::string summary;

    bool operator==(const TraceLabel& o) const {
        return kind == o.kind && cursor == o.cursor && summary == o.summary;
    }
};

/// The result of driving one run to completion.
class RunReport {
public:
    explicit RunReport(PragReport* raw) : raw_(raw, prag_report_free) {}

    std::string output() const { return detail::take(prag_report_output(raw_.get())); }
    std::string run_id() const { return detail::take(prag_report_run_id(raw_.get())); }
    /// Hex head of the tamper-evident hash chain ("" for an empty run).
    std::string chain_head() const { return detail::take(prag_report_chain_head(raw_.get())); }
    std::uint64_t journal_len() const { return prag_report_journal_len(raw_.get()); }
    /// Steps served from the journal (zero model calls).
    std::uint64_t replayed_steps() const { return prag_report_replayed_steps(raw_.get()); }
    /// Steps recorded fresh this attempt.
    std::uint64_t fresh_steps() const { return prag_report_fresh_steps(raw_.get()); }

    /// The observable trace - identical between a recorded run and its
    /// replay (T1).
    std::vector<TraceLabel> trace() const {
        std::vector<TraceLabel> out;
        const auto n = prag_report_trace_len(raw_.get());
        out.reserve(n);
        for (std::uint64_t i = 0; i < n; ++i) {
            TraceLabel label;
            switch (prag_report_trace_kind(raw_.get(), i)) {
                case PRAG_TRACE_ORACLE: label.kind = TraceLabel::Kind::Oracle; break;
                case PRAG_TRACE_EFFECT: label.kind = TraceLabel::Kind::Effect; break;
                case PRAG_TRACE_RECV: label.kind = TraceLabel::Kind::Recv; break;
                case PRAG_TRACE_CLOCK: label.kind = TraceLabel::Kind::Clock; break;
                default: label.kind = TraceLabel::Kind::Done; break;
            }
            label.cursor = prag_report_trace_cursor(raw_.get(), i);
            label.summary = detail::take(prag_report_trace_summary(raw_.get(), i));
            out.push_back(std::move(label));
        }
        return out;
    }

private:
    std::unique_ptr<PragReport, void (*)(PragReport*)> raw_;
};

/// The durable execution context handed to your agent. Valid only inside
/// the run/resume/replay call that produced it.
class Ctx {
public:
    using Effect = std::function<std::string(const std::string&)>;

    /// One model call, journaled once. Record: sample; replay: read back -
    /// the model is not called.
    std::string oracle(const std::string& prompt) {
        char* err = nullptr;
        char* out = prag_ctx_oracle(raw_, prompt.c_str(), &err);
        if (out == nullptr) detail::throw_fault(PRAG_ERR_ORACLE, err);
        return detail::take(out);
    }

    /// A durable effect under the write-ahead discipline; replay reuses the
    /// recorded result without re-performing.
    std::string effect(const std::string& name, const std::string& arg,
                       const Effect& perform) {
        char* err = nullptr;
        char* out = prag_ctx_effect(
            raw_, name.c_str(), arg.c_str(),
            [](void* user, const char* a, char** err_out) -> char* {
                return detail::guarded(err_out, [&] {
                    return (*static_cast<const Effect*>(user))(a);
                });
            },
            const_cast<void*>(static_cast<const void*>(&perform)), &err);
        if (out == nullptr) detail::throw_fault(PRAG_ERR_TOOL, err);
        return detail::take(out);
    }

    /// Receive on a channel (journaled).
    std::string recv(const std::string& channel) {
        char* err = nullptr;
        char* out = prag_ctx_recv(raw_, channel.c_str(), &err);
        if (out == nullptr) detail::throw_fault(PRAG_ERR_TOOL, err);
        return detail::take(out);
    }

    /// A journaled clock read (nanoseconds since epoch).
    std::uint64_t now() {
        char* err = nullptr;
        std::uint64_t nanos = 0;
        const int code = prag_ctx_now(raw_, &nanos, &err);
        if (code != PRAG_OK) detail::throw_fault(code, err);
        return nanos;
    }

    /// Assert an agent contract; a falsified contract faults the run.
    void contract(bool holds, const std::string& msg) {
        char* err = nullptr;
        const int code = prag_ctx_contract(raw_, holds, msg.c_str(), &err);
        if (code != PRAG_OK) detail::throw_fault(code, err);
    }

    /// True while steps are served from the journal.
    bool is_replaying() const { return prag_ctx_is_replaying(raw_) == 1; }

private:
    friend class Runtime;
    explicit Ctx(PragCtx* raw) : raw_(raw) {}
    PragCtx* raw_;
};

/// The Stet runtime: journals every step an agent takes under a stable
/// run id, so it survives any crash and replays exactly.
class Runtime {
public:
    using Oracle = std::function<std::string(const std::string&)>;
    using Agent = std::function<std::string(Ctx&)>;

    /// Journals persist under `dir` (one append-only file per run);
    /// `oracle` wraps your model; `key` (optional) HMAC-signs the journals.
    /// Pass an empty `dir` for in-memory journals (tests, ephemeral runs).
    Runtime(const std::string& dir, Oracle oracle, const std::string& key = {})
        : oracle_(std::make_unique<Oracle>(std::move(oracle))),
          raw_(nullptr, prag_runtime_close) {
        char* err = nullptr;
        PragRuntime* rt = prag_runtime_open(
            dir.empty() ? nullptr : dir.c_str(),
            [](void* user, const char* prompt, char** err_out) -> char* {
                return detail::guarded(err_out, [&] {
                    return (*static_cast<Oracle*>(user))(prompt);
                });
            },
            oracle_.get(), key.empty() ? nullptr : reinterpret_cast<const std::uint8_t*>(key.data()),
            key.size(), &err);
        if (rt == nullptr) detail::throw_fault(PRAG_ERR_IO, err);
        raw_.reset(rt);
    }

    /// Start (or continue) a durable run - re-enterable, retries are
    /// idempotent.
    RunReport run(const std::string& run_id, const Agent& agent) {
        return drive(prag_runtime_run, run_id, agent);
    }

    /// Resume a crashed run: the journaled prefix is read back (zero model
    /// calls, no duplicate effects); recording continues at the tail.
    RunReport resume(const std::string& run_id, const Agent& agent) {
        return drive(prag_runtime_resume, run_id, agent);
    }

    /// Replay a recorded run bit-for-bit for debugging and audit (T1). The
    /// model is never called.
    RunReport replay(const std::string& run_id, const Agent& agent) {
        return drive(prag_runtime_replay, run_id, agent);
    }

    /// Deliver a value to a run's channel inbox.
    void send(const std::string& run_id, const std::string& channel,
              const std::string& value) {
        prag_runtime_send(raw_.get(), run_id.c_str(), channel.c_str(),
                          value.c_str());
    }

    /// Walk the run's tamper-evident hash chain. Returns true if intact;
    /// false (with *bad_cursor set, if given) on tampering; throws on any
    /// other fault.
    bool verify(const std::string& run_id, std::uint64_t* bad_cursor = nullptr) {
        char* err = nullptr;
        const int code =
            prag_runtime_verify(raw_.get(), run_id.c_str(), bad_cursor, &err);
        if (code == PRAG_OK) return true;
        if (code == PRAG_ERR_TAMPERED) {
            prag_str_free(err);
            return false;
        }
        detail::throw_fault(code, err);
    }

    /// The linked runtime's version.
    static std::string version() { return detail::take(prag_version()); }

private:
    using DriveFn = int (*)(PragRuntime*, const char*, prag_agent_fn, void*,
                            PragReport**, char**);

    RunReport drive(DriveFn f, const std::string& run_id, const Agent& agent) {
        char* err = nullptr;
        PragReport* report = nullptr;
        const int code = f(
            raw_.get(), run_id.c_str(),
            [](void* user, PragCtx* raw_ctx, char** err_out) -> char* {
                return detail::guarded(err_out, [&] {
                    Ctx ctx(raw_ctx);
                    return (*static_cast<const Agent*>(user))(ctx);
                });
            },
            const_cast<void*>(static_cast<const void*>(&agent)), &report, &err);
        if (code != PRAG_OK) detail::throw_fault(code, err);
        return RunReport(report);
    }

    std::unique_ptr<Oracle> oracle_; // stable address for the C callback
    std::unique_ptr<PragRuntime, void (*)(PragRuntime*)> raw_;
};

} // namespace pragmatic

#endif // PRAGMATIC_HPP
