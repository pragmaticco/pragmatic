/* pragmatic.h - C ABI for the Stet durable-execution runtime.
 *
 * Stet journals every step an agent takes (model calls, effects,
 * receives, clock reads) to an append-only hash-chained log, so a run
 * survives any crash and replays exactly - nondeterministic model behavior
 * included.
 *
 * String ownership, two rules:
 *   1. Every char* the LIBRARY RETURNS to you (outputs, error messages,
 *      report fields) is yours to free with prag_str_free().
 *   2. Every char* YOU RETURN to the library (from an oracle, agent, or
 *      effect callback) must be created with prag_str_new(); the library
 *      takes ownership.
 * const char* parameters are borrowed for the duration of the call only.
 *
 * Callbacks must not unwind (no longjmp, no C++ exceptions across the
 * boundary): report failure by returning NULL with *err_out set via
 * prag_str_new().
 *
 * Thread-safety: a PragRuntime and its reports are single-threaded - drive
 * each runtime from one thread at a time.
 */

#ifndef PRAGMATIC_H
#define PRAGMATIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Status codes                                                        */
/* ------------------------------------------------------------------ */

enum {
    PRAG_OK = 0,
    PRAG_ERR_ORACLE = 1,           /* the model call itself failed        */
    PRAG_ERR_TOOL = 2,             /* a durable effect failed             */
    PRAG_ERR_TIMEOUT = 3,
    PRAG_ERR_BUDGET = 4,           /* step/cost budget consumed           */
    PRAG_ERR_CONTRACT = 5,         /* an agent contract was falsified     */
    PRAG_ERR_CAPABILITY = 6,       /* effect without a capability         */
    PRAG_ERR_ESCALATED = 7,        /* fault propagated from a child agent */
    PRAG_ERR_DESYNC = 8,           /* journal disagrees with the program  */
    PRAG_ERR_REPLAY_EXHAUSTED = 9, /* recorded run never got this far     */
    PRAG_ERR_IO = 10,
    PRAG_ERR_INVALID = 11,         /* NULL / non-UTF-8 argument           */
    PRAG_ERR_PANIC = 12,
    PRAG_ERR_TAMPERED = 13         /* hash-chain verification failed      */
};

/* Trace label kinds (prag_report_trace_kind). */
enum {
    PRAG_TRACE_ORACLE = 0,
    PRAG_TRACE_EFFECT = 1,
    PRAG_TRACE_RECV = 2,
    PRAG_TRACE_CLOCK = 3,
    PRAG_TRACE_DONE = 4
};

/* ------------------------------------------------------------------ */
/* Opaque types                                                        */
/* ------------------------------------------------------------------ */

typedef struct PragRuntime PragRuntime; /* owns the oracle + all journals  */
typedef struct PragCtx PragCtx;         /* one attempt's durable context   */
typedef struct PragReport PragReport;   /* the result of one attempt       */

/* ------------------------------------------------------------------ */
/* Strings                                                             */
/* ------------------------------------------------------------------ */

/* Copy a NUL-terminated string into a library-owned allocation - the only
 * valid way to produce a char* returned from a callback. */
char *prag_str_new(const char *s);

/* Free any char* the library returned. NULL is a no-op. */
void prag_str_free(char *s);

/* ------------------------------------------------------------------ */
/* Callbacks                                                           */
/* ------------------------------------------------------------------ */

/* Your model call: return a prag_str_new() completion, or NULL with
 * *err_out set on failure. */
typedef char *(*prag_oracle_fn)(void *user, const char *prompt,
                                char **err_out);

/* Your agent body: drive the ctx, return a prag_str_new() output, or NULL
 * with *err_out set. If a ctx call faulted, returning NULL propagates that
 * typed fault (budget stays budget, desync stays desync). */
typedef char *(*prag_agent_fn)(void *user, PragCtx *ctx, char **err_out);

/* A durable effect's perform step (tool call, external write). */
typedef char *(*prag_effect_fn)(void *user, const char *arg, char **err_out);

/* ------------------------------------------------------------------ */
/* Runtime                                                             */
/* ------------------------------------------------------------------ */

/* Open a runtime. dir NULL = in-memory journals (tests); otherwise one
 * append-only journal file per run persists under dir and runs survive
 * process crashes. key/key_len (NULL/0 to skip) HMAC-signs the journals.
 * Returns NULL with *err_out set on failure. */
PragRuntime *prag_runtime_open(const char *dir, prag_oracle_fn oracle,
                               void *user, const uint8_t *key, size_t key_len,
                               char **err_out);

void prag_runtime_close(PragRuntime *rt);

/* Start (or continue) a durable run - re-enterable, retries are idempotent.
 * On PRAG_OK, *report_out (optional: pass NULL to skip) must be freed with
 * prag_report_free(). */
int prag_runtime_run(PragRuntime *rt, const char *run_id, prag_agent_fn agent,
                     void *user, PragReport **report_out, char **err_out);

/* Resume a crashed run: the journaled prefix is read back (zero model
 * calls, no duplicate effects); recording continues at the tail. */
int prag_runtime_resume(PragRuntime *rt, const char *run_id,
                        prag_agent_fn agent, void *user,
                        PragReport **report_out, char **err_out);

/* Replay a recorded run bit-for-bit for debugging and audit (T1). The
 * model is never called. */
int prag_runtime_replay(PragRuntime *rt, const char *run_id,
                        prag_agent_fn agent, void *user,
                        PragReport **report_out, char **err_out);

/* Deliver a value to a run's channel inbox. */
int prag_runtime_send(PragRuntime *rt, const char *run_id, const char *channel,
                      const char *value);

/* Walk the run's tamper-evident hash chain. PRAG_OK = intact;
 * PRAG_ERR_TAMPERED sets *bad_cursor_out (optional) to the first bad entry. */
int prag_runtime_verify(PragRuntime *rt, const char *run_id,
                        uint64_t *bad_cursor_out, char **err_out);

/* ------------------------------------------------------------------ */
/* Ctx - inside an agent callback only                                 */
/* ------------------------------------------------------------------ */

/* One model call, journaled once. Record: sample; replay: read back - the
 * model is not called. Caller-owned string, or NULL on fault. */
char *prag_ctx_oracle(PragCtx *ctx, const char *prompt, char **err_out);

/* A durable effect under the write-ahead discipline; replay reuses the
 * recorded result without re-performing. */
char *prag_ctx_effect(PragCtx *ctx, const char *name, const char *arg,
                      prag_effect_fn perform, void *user, char **err_out);

/* Receive on a channel (journaled). */
char *prag_ctx_recv(PragCtx *ctx, const char *channel, char **err_out);

/* A journaled clock read (nanoseconds since epoch) into *nanos_out. */
int prag_ctx_now(PragCtx *ctx, uint64_t *nanos_out, char **err_out);

/* Assert an agent contract; a falsified contract faults the run. */
int prag_ctx_contract(PragCtx *ctx, bool holds, const char *msg,
                      char **err_out);

/* 1 while steps are served from the journal, 0 while recording fresh,
 * -1 if the ctx is invalid. */
int prag_ctx_is_replaying(PragCtx *ctx);

/* ------------------------------------------------------------------ */
/* RunReport                                                           */
/* ------------------------------------------------------------------ */

void prag_report_free(PragReport *r);

char *prag_report_output(const PragReport *r);     /* the agent's output   */
char *prag_report_run_id(const PragReport *r);
char *prag_report_chain_head(const PragReport *r); /* hex, NULL if empty   */
uint64_t prag_report_journal_len(const PragReport *r);
uint64_t prag_report_replayed_steps(const PragReport *r);
uint64_t prag_report_fresh_steps(const PragReport *r);

/* The observable trace - identical between a recorded run and its replay. */
uint64_t prag_report_trace_len(const PragReport *r);
int prag_report_trace_kind(const PragReport *r, uint64_t i);
uint64_t prag_report_trace_cursor(const PragReport *r, uint64_t i);
char *prag_report_trace_summary(const PragReport *r, uint64_t i);

/* The library version, as a caller-owned string. */
char *prag_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PRAGMATIC_H */
