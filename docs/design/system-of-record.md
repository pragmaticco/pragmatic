# Pragmatic 0.6: the system of record for AI agents

Status: design, revision 3 (2026-10-13), after an adversarial review across
cryptography, replay correctness, storage and failure handling, compliance,
developer experience and completeness, amended after the review of the core
runtime (2.4, 2.6 to 2.8, 2.11, 2.12, 2.14, 3.1 to 3.3, 6.7), where
building evidence bundles, the console and the CLI settled open details
(3.5, 4.7, 4.10, 4.14, 5.1 to 5.3, 7), after the adversarial review of
evidence verification, the console and the CLI (1.3, 4.7, 4.10, 4.14, 5.3,
7, 10), with the anchoring library (1.5, 4.1, 4.2, 4.7, 4.8, 5.1) and
after its review (4.1, 4.2, 4.7, 4.8, 5.1 to 5.3, 7, 9, 10), after
building the server (4.1 to 4.5, 4.7 to 4.9, 4.13, 4.17) and after the
security, failure-handling and compliance review of the server (4.1 to
4.13, 4.16, 4.17), while building the Python runtime layer (3.1, 4.4,
4.6, 6.2, 6.3, 6.7) and its journaled model clients (2.6, 2.11, 3.0, 3.1,
6.5, 6.6, 6.7), and after the review of that layer (2.6, 2.7, 2.12, 3.1,
4.6, 6.2 to 6.5), reconciled when the four were integrated (11), and
amended when the server was wired to its components (4.1, 4.4, 4.7, 4.8,
4.14, 4.17, 5.3, 11), when the console took the website's design
(4.14), and after the review of that design (4.14). This
document is the contract
between the components built for 0.6. Everything marked MUST is
normative; where code and this document disagree, one of them is a bug.

Contents: 1 Product, claims and threat model. 2 Journal format v2.
3 Core runtime. 4 Pragmatic Server. 5 Evidence bundles. 6 Python SDK.
7 CLI. 8 Documentation deliverables. 9 Verification plan. 10 Deferred.
11 Integration decisions.

---

## 1. Product, claims and threat model

### 1.1 Product

Pragmatic records what an AI agent does so that the record can be checked
by a party that does not trust the operator, and so that a crashed run can
continue without repeating work. Two pillars, in this order:

1. **System of record.** Every model call, tool call, channel receive,
   random draw and clock read made through Pragmatic's journaled
   interfaces is recorded before its result reaches the agent. The record
   is tamper-evident, anchored with independent witnesses, replayable with
   the model never called, erasable for privacy law while the integrity
   of the rest still verifies, retained by policy, access-controlled and
   attributed, and exportable as an evidence bundle an auditor verifies
   offline against trust roots of their own choosing.
2. **Crash recovery.** A crashed run resumes from its journal on any
   machine, without repeating model calls or committed tool calls, with a
   single-writer guarantee.

### 1.2 Claims and non-claims (normative for all docs, README and UI text)

Permitted verbs: "helps meet", "supports", "provides evidence for".
Forbidden: "compliant", "certified", "WORM", "guarantees compliance",
"tamper-proof". The mapping of regulations to features lives in
`docs/compliance.md` with three columns: requirement, what Pragmatic
provides, what the customer is responsible for.

What a verified anchor proves: a journal prefix of `entries` entries with
chain head `head` existed no later than the witness time. It does not
prove that the content was true when recorded, that nothing happened
outside the journaled interfaces, or anything about a run before its first
anchor.

### 1.3 Threat model (summary; full text in `docs/threat-model.md`)

| Adversary | Can | Cannot (when the stated controls are on) |
|---|---|---|
| Agent code (including prompt-injected tools) | act outside journaled interfaces (unrecorded); hold an agent token scoped to its prefixes | write erased or withheld slots, server-only notes, or touch runs outside its scopes |
| Host operator without the HMAC key (local mode) | read and edit local files | edit a keyed journal undetected |
| Server administrator with root | rewrite unanchored suffixes (at most `interval_secs` old); delete data; with `anchor_run_ids = "hmac"`, re-anchor a rewritten run under a new per-run key, which no audit detects (4.7) | rewrite an anchored prefix, or hide an anchored run from an auditor who audits the anchor log against a pinned independent witness, for runs anchored with plain ids |
| Auditor | read what their token's scopes and `view_raw` allow | recover redacted content (salts are never served with redacted content) |
| Pragmatic Witness (hosted) | refuse service; see `(origin, seq, root)` | learn any content or run id |

### 1.4 Network behavior and telemetry

No component makes network connections except: the SDK to the configured
server and to model APIs through the user's own SDK clients; the server
to configured TSAs, witnesses and webhook URLs; the CLI to URLs named on
its command line (none in 0.6). There is no telemetry, update check or
crash reporting. What leaves a server: TSAs receive a 32-byte digest and a
nonce; a witness receives `(origin, seq, tree_size, root)`; webhooks
receive event type, run id and counts. No content or field data leaves
the server.

### 1.5 Licensing (decided 2026-10-13)

- **Open source, Apache-2.0:** the runtime, SDKs, bindings, CLI, journal
  format, verifier and `pragmatic-console`.
- **Commercial, `crates/pragmatic-server`:** the source stays public in
  this repository under the Business Source License 1.1, so auditors can
  inspect it.
  - Its Additional Use Grant covers only non-production use:
    development, testing and evaluation.
  - Production use needs a commercial license from Pragmatic Research,
    Inc.
  - Each version converts to Apache-2.0 four years after release.
  - The server crate carries its own `LICENSE` file and
    `license = "BUSL-1.1"`, has `publish = false`, is excluded from
    `cargo publish --workspace`, and ships as a container image and
    binaries.
  - The anchoring library the server calls, `crates/pragmatic-anchor`
    (sections 4.7 and 4.8), is part of the same commercial layer under the
    same terms: its own `LICENSE` (BUSL 1.1, Licensed Work "Pragmatic
    Server and anchoring"), `license = "BUSL-1.1"` and `publish = false`.
    The formats it writes come from the Apache-2.0 core, so verifying
    anchors never needs it.
- **No license enforcement in code:** `[license] licensee` from the server
  config is shown in the console footer and in `/v1/info`.

---

## 2. Journal format v2

### 2.1 File header, keying and genesis

```
header (16 bytes):
  magic    8 bytes  "PRAGJRNL"
  version  u32 LE   2
  flags    u32 LE   bit 0 = keyed chain (HMAC-SHA-256); bits 1..31 MUST be 0
```

Opening rules:

- Reserved flag bits set: `InvalidData`.
- Caller supplies a key and bit 0 is clear: `InvalidData` ("journal is
  unkeyed but a key was supplied").
- Bit 0 is set and no key is supplied: `Unsupported`. Never fall back to
  unkeyed verification.

The chain starts from a genesis value bound to the flags:

```
H        = SHA-256, or HMAC-SHA-256(key, ·) when bit 0 is set
h_{-1}   = H( "pragmatic/v2/genesis" ‖ u32 LE flags )
```

HMAC keying makes a journal tamper-evident against parties without the
key. It provides no third-party attribution. Server-stored runs and
evidence bundles are always unkeyed.

### 2.2 Framing

```
frame := len u32 LE ‖ record (len bytes) ‖ hash (32 bytes)
```

### 2.3 Record encoding

All integers are little-endian.

```
record :=
  kind      u8
  at        u64      wall clock of the appending process, Unix ns UTC
  depth     u8       branch depth, 0..=32
  branch    depth × u32
  nfields   u8
  fields    nfields × (u32 len ‖ bytes)
  nslots    u8
  slots     nslots × slot
slot :=
  state       u8          1 sealed, 2 erased, 3 withheld, 4 ref
  commitment  32 bytes
  state 1: salt 16 bytes ‖ len u32 ‖ bytes
  state 2: (nothing)
  state 3: (nothing)
  state 4: target_cursor u64 ‖ target_slot u8
```

`at` is informational. It is chained, is never compared on replay, is not
guaranteed monotonic across machines, and ordering is always the cursor.

### 2.4 Canonical decoding (normative)

A decoder MUST reject the record (as corruption at that cursor, never as a
torn tail) unless all of the following hold:

- The record consumes exactly `len` bytes.
- `kind` is known (2.6). `nfields` and `nslots` match the kind's counts in
  2.6.
- Fixed-width fields have exactly their width. String fields are valid
  UTF-8. JSON fields are strict JSON (3.7).
- `state` is 1, 2 or 4 in a stored journal (3 is valid only inside an
  evidence bundle).
- A ref (4) points to `target_cursor` < this cursor, and the target slot
  exists with state 1 or 2 (never another ref) and an equal commitment.
- A `DrawResult`'s `intent` names an earlier `DrawIntent`, and an
  `EffectResult`'s an earlier `EffectIntent`, on the same branch as the
  result. Replay finds completions through this reference, so one that
  pointed anywhere else would hand a step another step's record.
- A `Refusal`'s step, name and fault fit together (2.6).
- `depth` ≤ 32. The branch is the meta branch `[0xFFFF_FFFF]` if and only
  if the kind is `Note`.
- The slot length does not exceed the bytes remaining in the record.
- Size limits (2.15) hold.

Anything that decodes or verifies a record that came from outside the
process (the server's append path, `Journal::parse` of a file, evidence
verification) MUST decode, re-encode, and byte-compare. The skeleton is
always computed from the re-encoded parsed values.

### 2.5 Commitments, refs and the chain

```
commitment(content) = SHA-256( "pragmatic/v2/slot" ‖ salt ‖ u64 LE len ‖ content )
skeleton(record)    = kind ‖ at ‖ depth ‖ branch ‖ nfields ‖ fields ‖ nslots ‖
                      nslots × (0x01 ‖ commitment)
h_i                 = H( h_{i-1} ‖ u64 LE cursor_i ‖ skeleton(record_i) )
```

Every slot contributes `0x01 ‖ commitment` to the skeleton whatever its
state. Erasing, withholding or deduplicating a slot therefore never
changes a chain hash.

- **Salt:** 16 bytes from the OS CSPRNG (3.7 `rand`), fresh per sealed
  slot, never buffered across appends. If the CSPRNG fails, the append
  fails (`Fault::Io`) with no fallback.
- **Refs (deduplication):** when a slot's content is byte-identical to a
  sealed slot already in the same journal, and is at least 256 bytes, the
  journal writes a ref with the target's commitment instead of a copy.
  Erasing the target makes every ref to it erased. A ref's content (for
  replay) is the target's content.

`verify()` recomputes the commitment of every sealed slot, resolves every
ref, and recomputes every chain link. It reports the first bad cursor.

### 2.6 Event kinds

Fields are structural, never erasable, and MUST NOT contain personal data.
Slots are content and are erasable.

| kind | tag | fields | slots |
|---|---|---|---|
| `DrawIntent` | 1 | provenance (str) | request parts, 1..=255 |
| `DrawResult` | 2 | intent (u64 cursor), meta (JSON) | head, body (exactly 2) |
| `ChannelRecv` | 3 | channel (str) | value (1) |
| `EffectIntent` | 4 | name (str) | arg (1) |
| `EffectResult` | 5 | intent (u64), outcome (`ok`/`failed`/`compensated`), error_kind (str, may be empty) | ok: result (1); failed: message (1); compensated: none (0) |
| `Clock` | 6 | nanos (u64) | none |
| `Program` | 7 | name (str), hash (str) | none |
| `Fork` | 8 | base (u32), children (u32, ≥1) | none |
| `Marker` | 9 | name (str) | none |
| `Note` | 10 | kind (str), data (JSON) | payload, 0..=2 |
| `Random` | 11 | source (str), args (JSON) | value (1) |
| `Refusal` | 12 | step (str), name (str), fault (str) | none |

**DrawResult meta** (written by the SDK; all keys optional except
`outcome`): `{"outcome": "ok"|"error"|"partial", "status": n,
"error_kind": "connect"|"timeout"|"protocol"|"cancelled", "error_type": "...",
"provider": "...",
"model": "...", "stop_reason": "...", "usage": {"input_tokens": n,
"output_tokens": n, "cache_read_tokens": n, "cache_write_tokens": n,
"reasoning_tokens": n}, "latency_ms": n}`. `partial` marks a stream that
was closed before it ended (a stream whose recorded bytes end in the
provider's terminal event, such as `data: [DONE]` or `message_stop`, is
`ok` even when the caller closed it before the connection ended, which
the OpenAI SDK always does). An HTTP response with a status of 400 or
more is `error` with its `status`; a body that broke while it was read is
`error` with its `status`, `error_kind` and `error_type`, and the message
in the head (6.5). A call the agent cancelled and carried on past (2.12)
is `error` with `error_kind` `cancelled` and `error_type`
`asyncio.exceptions.CancelledError`. `error_type` names what the caller's model
client raised when the call failed outside HTTP (a core `Fault` kind such
as `Unavailable` for a Rust oracle, or a Python exception's
`module.QualName`), with the message in the body slot, so replay raises the
same error (2.12). Meta holds no personal data, so usage, model and outcome
survive erasure and shredding.

**Refusal** records a step the runtime refused without touching the world,
so replay raises the same fault where the agent saw it: `step` `recv`
(`name` the channel, `fault` `Timeout`: the inbox was empty), `draw`
(`name` empty, `fault` `BudgetExhausted`) or `effect` (`name` the effect,
`fault` `CapabilityDenied`). It is appended only once the agent carries on
past the fault: before the next start event on its branch or on an
ancestor branch, or before `attempt.end` when the agent returns ok. A
refusal the agent did not carry on past is never journaled, so a resumed
run tries the step again (the message may have arrived, the budget may
have been raised). Name and fault are structural, never personal data.

**Random** sources: `uuid4` (args `[]`, value the canonical UUID string),
`random` (args `[]`, value a float in [0, 1) as shortest round-trip
decimal text), `randint` (args `[a, b]`, value decimal integer text),
`bytes` (args `[n]`, value n raw bytes). Random draws are not subject to
budget or capabilities.

### 2.7 Branches and parallel regions

A branch is a path of `u32`. The root branch is the empty path. The meta
branch `[0xFFFF_FFFF]` holds only `Note`s, and program replay never reads
it.

**Fork numbering.** `fork(n)` on branch `b` appends
`Fork{base: m, children: n}` on `b` and returns the child branches
`b‖m … b‖(m+n−1)`, where `m` is the sum of `children` over every earlier
`Fork` in `b`'s sequence. Child ids are never reused within a run. On
replay the requested `n` and the recomputed `m` MUST equal the recorded
values; otherwise `JournalDesync`. A fork that would produce a child index
≥ `0xFFFF_FFFF` is `Unsupported`.

**Parallel regions** (`Ctx::parallel`, `AsyncCtx::parallel`, Python
`ctx.gather`):

1. The fork is appended synchronously when the region starts.
2. The region completes only after every child has returned or failed. A
   failing child never cancels its siblings.
3. Results come back in child-index order.
4. If any child failed, the region raises the failure of the
   lowest-index failed child, never the first failure in time.
5. While a branch has an unjoined fork, any journaled step on it raises
   `Fault::Unsupported("branch is suspended in a parallel region")`.
6. A step on a child branch after its region joined raises the same
   fault.
7. Cancelling the attempt from outside (task cancellation, interrupt,
   dropping the attempt) is a crash: nothing further is journaled and no
   `attempt.end` is written. A cancellation the agent handles is not a
   crash: a step it cancels and carries on past (a timeout around it)
   ends in a failure result (2.12). A region whose parent is cancelled
   while its children run is joined, once they have all finished, with
   every child failed; a join appends nothing, so a crash still journals
   nothing, and an agent that carries on can step on the parent's branch
   again. A child that ends cancelled while its parent was not cancelled
   (it cancelled itself, or a library did) is a failed child, and the
   region raises an ordinary error for it, never a cancellation.

**Replay indexing.** On open, the journal is indexed per branch into its
*start events*, which are everything except `DrawResult`, `EffectResult`
and `Note`. Start events are matched positionally per branch. Completions
(`DrawResult`, `EffectResult`) are matched by their `intent` reference,
not by position. Several intents may therefore be open on one branch at
once: a stream can stay open while tools run, and a framework can issue
concurrent calls through one client. Concurrent starts on one branch
replay correctly only if they are issued in a deterministic order. Work
that is independent should use parallel regions (separate branches). The
SDK documents this and logs a warning when concurrent starts on a branch
carry identical requests.

**Completeness at join.** When a child returns ok, and when the agent
returns ok, every start event on the branches involved MUST have been
consumed, and every intent must have a completion. Otherwise the result
is `JournalDesync{cursor: first unconsumed, expected: "end of branch"}`.
The check applies to the replayed prefix in every mode. Branches that
ended in a fault are exempt.

**Budget** (model-call limit) is shared by all branches. A replayed draw
never charges the budget and never faults. A fresh `DrawIntent` raises
`BudgetExhausted` if (draws already in the journal at checkout + fresh
draws opened this attempt) ≥ budget, journaled as a `Refusal` once the
agent carries on past it (2.6). A draw aborted before its intent was
appended releases its reservation. Strict replay never consults the
budget: it raises `BudgetExhausted` where a `Refusal` was recorded.

### 2.8 Replay matching rules

| step | consumes | matches when |
|---|---|---|
| draw | next start on b = `DrawIntent` | request parts are equal after the SDK's normalization (6.6); count and order equal |
| draw response | the latest `DrawResult` referencing the intent | always; `partial` serves the recorded bytes and then ends the stream |
| effect | next start on b = `EffectIntent` | name and arg equal |
| effect result | the latest `EffectResult` referencing the intent | see 2.12 |
| recv | `ChannelRecv` | channel equal |
| now | `Clock` | kind only |
| random | `Random` | source and args equal |
| fork | `Fork` | base and children equal |
| patched | `Marker` | see 2.9 |
| program marker | `Program` | see 2.10 |
| draw, recv or effect | `Refusal` | step equal, and name equal (channel or effect name); raises the recorded fault |

Replay consumes an entry only if every slot it compares or returns is
sealed or a ref to a sealed slot. Otherwise it raises
`Fault::Erased{cursor}`. Erased slots are never wildcards. Shredded runs
can be verified but not replayed or resumed.

When the next start event on a branch is a `Marker` and the step is
anything other than `patched` or `deprecate_patch`, the step raises
`JournalDesync` with the hint "this run took patch '<name>'". Markers are
never skipped implicitly.

### 2.9 Markers (code patching)

`patched(name) -> bool` on branch `b`:

- next start on `b` is `Marker{name}`: consume it, return `true`;
- `b` is at its end and not in strict replay: append `Marker{name}`,
  return `true`;
- next start on `b` is anything else: consume nothing, return `false`;
- strict replay past the end of `b`: `ReplayExhausted`.

`deprecate_patch(name)`: if the next start on `b` is `Marker{name}`,
consume it; otherwise do nothing. It never appends.

Lifecycle, documented: add `patched`; once no unmarked run can still
resume, switch to `deprecate_patch`; once no marked run can resume, delete
it. Rolling deploys in which two code versions resume the same run are
unsupported.

### 2.10 Program identity and code changes

`Program{name, hash}` is appended on the calling branch by `durable` (Rust
macro, Python decorator). `hash` is the explicit version when one is
supplied (`@durable(version="2")`), otherwise the source hash.

`on_code_change` takes one of two values. One name is used everywhere:
Rust `OnCodeChange::{Refuse, Continue}` in
`RunOptions.on_code_change: Option<OnCodeChange>`, and Python
`on_code_change="refuse"|"continue"`. `None` means the mode default:
`Continue` for run and resume, `Refuse` for replay.

- **Refuse** accepts the current `(name, hash)` if it equals the recorded
  `Program`, or equals the `to` of a `program.change` note whose `cursor`
  is that `Program` entry. That is the only case where replay reads meta
  notes. The `JournalDesync` message says "pass on_code_change='continue'
  to replay recorded runs under changed code".
- **Continue** additionally accepts a hash change with an equal name. In
  recording modes it appends `Note{program.change, {"branch", "cursor",
  "from", "to"}}` immediately, before any fresh step, once per attempt per
  `Program` entry. In strict replay it appends nothing and sets
  `report.program_changes`.
- Under both policies, a name change, a marker meeting a non-`Program`
  entry, or a non-program step meeting a `Program` entry is
  `JournalDesync`.

### 2.11 Notes

Notes live only on the meta branch. Their data is compact strict JSON with
no personal data; anything personal goes in a payload slot.

| kind | written by | data | payload slots |
|---|---|---|---|
| `run.start` | SDK | `{"run_id": exact id, "nonce": 32 hex, "sdk", "sdk_version", "format": 2, "labels": {...}}` | 0: `{"subjects": [...]}` (optional) |
| `attempt.start` | SDK | `{"attempt": n, "mode": "run"\|"resume", "sdk", "sdk_version", "principal", "program": {"name", "hash"}, "host", "pid", "traceparent", "torn_bytes", "torn_at_cursor"}`, plus `"normalization": [rule names]` when the SDK matches draws under normalization (6.6) | none |
| `attempt.end` | SDK | `{"attempt": n, "outcome": "ok"\|"fault"\|"error", "fault_kind": tag, "fault_cursor": n\|null, "fresh": n, "replayed": n, "usage_fresh": {...}, "passthrough_calls": n}` | 0: output (on ok); 1: fault or error message |
| `program.change` | SDK | `{"branch", "cursor", "from", "to"}` | none |
| `recovery` | SDK | `{"intent": cursor, "result": cursor, "branch", "name", "decision": "commit"\|"compensate"\|"retry"}`, plus `"saga": "begin"\|"done"` for a Supervisor saga's compensation | none |
| `erasure` | server or `pragmatic erase` | `{"slots": [[cursor, slot], ...], "by": token id or "local:<os-user>@<host>", "authenticated": bool, "reason_code", "access_log_cursor": n\|null}` | 0: free-text reason |
| `custody` | server | `{"lease": lease-id hash, "token": token id, "principal", "from_entries", "to_entries", "requests": n, "first_received", "last_received", "clock_skew": bool}` | none |
| `torn_tail` | writer that truncated | `{"offset", "bytes", "sha256", "moved_to"}` | none |

- `principal` and `by` are token ids (or the local OS user), never names
  or emails.
- `usage_fresh` is computed by the core: the sum, per counter, of the
  `usage` objects in the meta of the `DrawResult`s this attempt appended
  (counters that are not non-negative integers are skipped). Replayed
  draws add nothing. `passthrough_calls` is what the SDK reported through
  `Session::count_passthrough` (6.5).
- `program` in `attempt.start` is the agent's source hash, recorded even
  without `durable` as information. It does not change replay strictness.
- `labels`: at most 32 pairs, keys `[a-z0-9_.-]{1,64}`, values at most 256
  bytes, documented as non-personal.
- A Supervisor saga persists the `begin` note before it runs a
  compensator and the `done` note after it returns. An effect with a
  `begin` note is never compensated again; a `begin` without a `done`
  marks a compensation that may not have finished.
- **Server-only kinds:** `erasure`, `custody` and `torn_tail` (server
  side). The server's append path rejects them from clients, and
  `Journal::append` refuses them outside the erase and truncate code
  paths.

**Order for a recording attempt:**

1. `run.start`, if and only if the journal has zero entries
2. `attempt.start`, with n = 1 + the number of earlier `attempt.start` notes
3. recovery (2.12), resume only
4. the agent's steps (with `program.change` when accepted)
5. `attempt.end`, before the final sync

Strict replay appends nothing.

### 2.12 Intents, results, failures and recovery

**Model calls (draws).** `DrawIntent` is appended and persisted before
the request is sent, so every model call attempt is durably on record
before it happens. `DrawResult{intent}` is appended when the response is
complete (or the stream is closed, `partial`) and persisted before the
response is released to the agent. A non-streaming response is released
whole after persistence. A stream's chunks are passed to the caller as
they arrive, and the `DrawResult` with the full body is persisted when
the stream ends or is closed. Transport errors and HTTP errors are
results too (`outcome: error`), so the SDK's own retry loop replays
identically. On replay, retryable error responses are served with a
retry hint that makes the SDK decide as it did when the run was
recorded, at no wait (6.5). A call that fails
outside HTTP (a Rust oracle's fault, a Python callable's exception) is
recorded with its `error_type` (2.6) and replays as the same error: Rust
rebuilds the `Fault` for every kind that carries no more than a message
and otherwise raises `Fault::OracleErr(message)`, on record and replay
alike; Python raises `DrawFailed(type_name, message)`, which is also an
instance of the recorded exception type when the program has it loaded.
An interrupted call (a crash) is not a result: its intent stays
dangling. A call or effect the agent cancels itself and carries on past
(an awaited step under a timeout, a task group cancelling a sibling) is
a result. Once its intent is appended, the cancellation is appended as
its failure (`error_type` `asyncio.exceptions.CancelledError`) without
being persisted, as a stream closed early is (6.5). If the cancellation
is the attempt's crash, the entry is never persisted and goes with the
abandoned attempt; if the agent carries on, it becomes durable with the
next persist, and the attempt can end. Replay waits at such a step until
the task is cancelled again, so the agent's own timeout takes the path it
took. Two narrow cases are documented rather than closed: if another task
of the attempt persists between a crash's cancellation reaching a step
and the attempt being abandoned, the failure becomes durable and recovery
treats it as any unobserved failed result (retried by default); and a
cancellation that arrives after a step completed, while its result is
being made durable, reaches the agent while the journal keeps the result,
which replay then returns.

**Effects.** `EffectIntent` is appended and persisted (acknowledged by the
sink) before `perform` runs. `perform` receives
`idempotency_key = "<run_id>/<branch>/<intent cursor>"`. Its return is
recorded as `EffectResult{outcome: ok}`. If it raises, the failure is
recorded as `EffectResult{outcome: failed, error_kind: <exception type>}`
with the message in the slot. Replay of a failed effect raises
`EffectFailed` (Python: carries the original type name and message, and
is also an instance of the original exception type when the program has
it loaded; Rust: the recorded `Fault` for every kind that carries no more
than a message, otherwise `Fault::ToolErr(message)`, and record returns
the same value as replay), so an agent that caught the exception behaves
identically.

**Frontier.** An intent is *at the frontier* of branch `b` if no start
event on `b`, or on any ancestor branch of `b`, follows it. (A parallel
child that handled a failure and returned, after which the parent carried
on with the child's value, observed that failure even though nothing
followed on the child's own branch.) A *dangling* intent has no result. An
intent's *effective* result is its latest result. A failed result is
*observed* when its intent is not at the frontier, or when a later
`attempt.end` has outcome `ok`.

**Recovery** runs in a recording attempt after `attempt.start` and before
the agent is entered, over frontier intents in cursor order:

- A dangling `DrawIntent` needs no decision. When the replayed program
  re-issues the identical request, the call is made again and a new
  `DrawResult` is appended for the same intent.
- A frontier `DrawIntent` whose effective result is an unobserved
  `error` is re-issued the same way. That is how a failed call that
  crashed the attempt is retried on resume.
- A dangling frontier `EffectIntent` is passed to the recovery policy
  `recover(name, arg, branch, intent_cursor) -> Commit(result) |
  Compensate`. The default is `Compensate` for local backends and an
  error (`Fault::DanglingEffect{cursor}`) for server-backed runtimes,
  which require an explicit policy. `Commit` appends
  `EffectResult{ok}`. `Compensate` appends `EffectResult{compensated}`,
  and the replayed program performs the effect afresh under a new intent.
- A dangling `EffectIntent` away from the frontier (concurrent calls on
  one branch, with later starts recorded while it ran) cannot be written
  off: its retry would be a fresh intent at the end of the branch, while
  replay meets the starts recorded after it first. Only an explicit
  `Commit` or `Fail` decides it. Without a policy (or on `Compensate`)
  nothing is appended, the replayed program raises
  `Fault::DanglingEffect{cursor}` when it reaches the intent, and a later
  resume with a policy can still decide it (server-backed runtimes raise
  `DanglingEffect` during recovery, as for frontier intents). The policy
  request says whether the intent is at the frontier.
- A frontier `EffectIntent` whose effective result is an unobserved
  `failed` is retried by default (its result superseded by
  `compensated`). The policy may instead return `Commit` or `Fail`, in
  which case the failure stands and is replayed.
- Each decision appends a `recovery` note. All recovery entries are
  persisted in one sync before the agent starts.

Observed failed results are never retried: the agent observed them and
continued, so replay must reproduce them.

**Effect replay loop.** An `EffectIntent` whose effective result is
`compensated` is skipped together with its result, and matching continues
with the next start on the branch (a retry under a fresh intent).

**End of attempt.** If the agent returns ok while any intent on any
branch is dangling, the attempt ends with
`Fault::DanglingIntent{cursor}`. A stream draw left open at attempt end
is committed as `partial` with the bytes consumed so far before
`attempt.end` is written.

### 2.13 Erasure

Erasure is performed only by a writer that holds the run's write lock
(DirBackend checkout) or the server, under the run's exclusive lock with
no live lease.

1. Build a new file containing every original frame, with the erased
   slots changed to state 2. Their salt and content are dropped, and so
   are refs, which become erased through their target. Append the
   `erasure` note as the final frame, chained on the old head.
2. Validate before committing: the entry count is old + 1, every
   original chain hash and commitment is unchanged, and the only state
   change is 1 → 2.
3. Commit atomically: write a temp file in the same directory, fsync,
   rename over the journal, then fsync the directory. On Windows use
   `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`
   and skip the directory fsync.
4. Reopen the journal path before any further append.

**`verify()` findings for erasure:**

- `unaccounted_erasures`: erased slots not listed by an `erasure` note at
  a later cursor.
- `erasure_incomplete`: listed slots that are still sealed. Running
  `erase` again repairs this.
- `invalid_erasure_note`: notes listing out-of-range slots.

In unkeyed local journals the check detects erasure without a note (tools,
bit rot). It does not detect a party able to append. On the server, only
the server writes `erasure` notes, and each one points at its access-log
record.

**Match mode.** Erasure accepts either explicit `(cursor, slot)` pairs or
`match: bytes`, which erases every sealed slot whose content contains the
bytes. Dedup refs make one erasure cover every repeated copy of a
conversation message. A streamed model reply is stored as the event stream
the provider sent, with its text split into deltas of a few characters, so
a value the model repeated back never appears as one byte string: `match`
also erases every sealed slot whose reassembled stream text contains the
bytes (Anthropic `text_delta`, `input_json_delta` and `thinking_delta`,
OpenAI Chat `delta.content` and tool-call arguments, OpenAI Responses
`*.delta` events; `redact::stream`), whole.

### 2.14 Torn tails and corruption

`Journal::parse` is pure. It never writes, and it returns
`(entries, valid_len, tail_len)`. The tail starts at the first frame that
is incomplete, fails to decode, fails a commitment, or fails its chain
link.

The journal is **corrupt**, not torn (an error at the failing cursor,
never truncated), if any of the following holds. A writer truncates
whatever is torn, so each rule leans towards corruption whenever the
damage could have hit acknowledged entries.

- Any complete, well-formed frame after the tail start chain-links from
  the 32 bytes before it (or, for the frame right after the failing one,
  from the hash the failing frame's content implies) at any cursor it
  could have: from the failing cursor + 1 up to that + (bytes between the
  tail start and the frame) / (the smallest frame's size). Damage can
  destroy more than one frame (a zeroed sector can take a stored hash and
  the next frame's length), and the second frame after it still chains.
  A reader stops searching after 2^18 chain computations and reports
  corruption.
- The failing frame decodes and its stored hash equals the hash its
  skeleton implies, but a slot's content fails its commitment, and no
  512-byte-aligned block of the file overlapping that content reads as
  all zeros (a crash can keep the block holding the hash and lose a block
  of content, which reads back as zeros; bit rot or tampering does not
  look like that).
- The failing frame decodes with valid commitments, but its stored hash
  is not the implied hash, nor the implied hash with its last bytes zeros
  (a write cut off inside the hash). A wrong key, a cleared keyed flag or
  tampering produce this; a crash does not.
- The failing frame chains correctly but its completion reference breaks
  2.4.

`Journal::audit_bytes` (and `Runtime::verify`, through the backend) reads
past corruption and reports it as `VerifyReport.first_bad`, auditing the
valid prefix, so a verifier learns where tampering starts; `Journal::parse`
refuses the file.

Only a write-lock holder may truncate a torn tail. Before truncating, it
moves the tail bytes to `<name>.torn-<unix_ms>`, then `set_len(valid_len)`
and fsync, and records `torn_bytes` and `torn_at_cursor` in the next
`attempt.start`. Erasure (2.13) removes a run's moved-aside tails before
it commits: they hold bytes of frames that never became entries, which no
erasure can reach inside. The server never truncates below `anchored_entries`; it
raises `chain_broken` instead.

Every read-only consumer ignores bytes past `valid_len` and never writes:
CLI, console, snapshots, strict replay, evidence.

### 2.15 Limits

| limit | value |
|---|---|
| `max_slot_bytes` | 64 MiB (core constant) |
| `max_record_bytes` | 256 MiB (the reader treats larger lengths as corruption) |
| slots per record | 255 |
| branch depth | 32 |
| run id | `^[A-Za-z0-9._:-]{1,200}$`; ids starting with `pragmatic:` are reserved |

An append over `max_slot_bytes` fails with `Fault::TooLarge{size, limit}`.
For an effect argument or a receive this happens before anything is
performed. For a draw response it happens after the call, and is
documented as "paid but unrecorded": the attempt fails.

### 2.16 Format 1 (0.4 and 0.5 journals)

Format 1 journals are read-only in 0.6. `Journal::parse`, `verify`, the
CLI and the console read, verify and export them. Run, resume and replay
on a format 1 journal raise `Fault::Unsupported("journal format 1 is
read-only in 0.6: verify and export it with the CLI")`. 0.4 and 0.5 were
never published to a package registry; CHANGELOG states this break.

---

## 3. Core runtime (`crates/pragmatic`, zero dependencies)

### 3.0 Types

```rust
pub type Branch = Vec<u32>;                       // ROOT = vec![], META = vec![0xFFFF_FFFF]
pub enum Content { Sealed(Value), Erased, Withheld }
#[non_exhaustive] pub enum Event {
    DrawIntent { provenance: String, parts: Vec<Content> },
    DrawResult { intent: Cursor, meta: String, head: Content, body: Content },
    ChannelRecv { channel: String, value: Content },
    EffectIntent { name: String, arg: Content },
    EffectResult { intent: Cursor, outcome: EffectOutcome, error_kind: String, payload: Option<Content> },
    Clock { nanos: u64 },
    Program { name: String, hash: String },
    Fork { base: u32, children: u32 },
    Marker { name: String },
    Note { kind: String, data: String, payload: Vec<Content> },
    Random { source: String, args: String, value: Content },
    Legacy(LegacyEvent),                           // format 1, read-only
}
pub struct SlotMeta { pub commitment: Digest, pub state: SlotState, pub ref_target: Option<(Cursor, u8)> }
pub struct Entry { pub cursor: Cursor, pub at: u64, pub branch: Branch, pub event: Event, pub slots: Vec<SlotMeta>, pub hash: Digest }
pub struct VerifyReport { pub first_bad: Option<Cursor>, pub unaccounted_erasures: Vec<(Cursor, u8)>,
                          pub erasure_incomplete: Vec<(Cursor, u8)>, pub invalid_erasure_notes: Vec<Cursor>,
                          pub torn_bytes: u64 }  // is_ok()
```

Salts stay internal to the journal (never in `Entry`). `Journal::verify()
-> Result<(), Cursor>` stays as the chain-only check; `Journal::audit() ->
VerifyReport` is the full check; `Runtime::verify` returns `VerifyReport`.
`Event`, `Fault`, `TraceLabel` and `VerifyReport` are `#[non_exhaustive]`.
`TraceLabel` variants gain `branch: Branch`. The trace is sorted by
cursor, and T1 tests compare `(branch, cursor, label)`.

### 3.1 Attempts and sessions

```rust
pub enum Mode { Run, Resume, Replay }
impl<O: Oracle> Runtime<O> {
    pub fn with_backend(backend: Box<dyn Backend>, oracle: O) -> Self;
    pub fn begin(&self, run_id: &str, mode: Mode, opts: RunOptions) -> Result<Attempt, Fault>;
    pub fn run / resume / replay / *_with (unchanged signatures, but &self)   // wrappers over begin/finish
    pub fn verify(&self, run_id) -> Result<VerifyReport, Fault>;
    pub fn snapshot(&self, run_id) -> Result<Journal, Fault>;                 // read-only
    pub fn runs(&self) -> Result<Vec<String>, Fault>;
    #[doc(hidden)] pub fn with_journal_mut<R>(&self, run_id, f: impl FnOnce(&mut Journal) -> R) -> Result<R, Fault>; // crash simulation in tests
}
pub struct Attempt { /* owns Session + backend handle + checkout guard */ }
impl Attempt {
    pub fn ctx(&mut self) -> Ctx<'_>;
    pub fn session(&mut self) -> &mut Session;
    pub fn finish(self, result: Result<Value, Fault>) -> Result<RunReport, Fault>; // attempt.end, sync, checkin
}
impl Drop for Attempt { /* checkin without attempt.end: releases lock or lease */ }
```

- Every `Runtime` method takes `&self`, and `Runtime` is `Send + Sync`
  when `O` is.
- The backend handle is an `Arc<dyn Backend>`. Backend methods take
  `&self` and are `Send + Sync`.
- No lock is held across agent code. The backend's internal locks are
  held only inside checkout, checkin, snapshot and persist.
- `evict` remains as a deprecated no-op.
- `Mode::Replay` uses a snapshot (no lock, no lease), so auditors can
  replay live runs' durable prefixes.
- `RunOptions` (labels) are checked before the checkout, so a run refused
  for its options leaves no journal behind. `Mode::Resume` requires a
  started run: a journal with no entries is refused (`run` starts it).
- A receive takes its message off the run's inbox only once its
  `ChannelRecv` is durable: a receive over the slot limit or one whose
  persist fails leaves the message for the next receive or attempt.

`Session` holds all per-attempt state. Every primitive takes the branch:

```rust
impl Session {
    pub fn draw_begin(&mut self, b: &Branch, provenance: &str, parts: Vec<Value>) -> Result<DrawStart, Fault>; // Replayed(intent, head, body, meta) | Fresh(intent cursor)
    pub fn draw_end(&mut self, intent: Cursor, meta: String, head: Value, body: Value) -> Result<(), Fault>;
    pub fn effect_begin(&mut self, b: &Branch, name: &str, arg: Value) -> Result<EffectStart, Fault>;     // Replayed(result) | Failed(kind, msg) | Fresh(intent, idempotency_key)
    pub fn effect_end(&mut self, intent: Cursor, outcome: Result<Value, (String, String)>) -> Result<(), Fault>;
    pub fn recv(&mut self, b, channel) -> Result<Value, Fault>;
    pub fn now(&mut self, b) -> Result<u64, Fault>;
    pub fn random(&mut self, b, source: &str, args: &str) -> Result<Value, Fault>;
    pub fn fork(&mut self, b, n: u32) -> Result<Vec<Branch>, Fault>;
    pub fn join(&mut self, parent: &Branch, children: &[Branch], ok: &[bool]) -> Result<(), Fault>;
    pub fn patched(&mut self, b, name) -> Result<bool, Fault>;
    pub fn deprecate_patch(&mut self, b, name) -> Result<(), Fault>;
    pub fn program_marker(&mut self, b, name, hash) -> Result<(), Fault>;
    pub fn is_replaying(&self, b) -> bool;
    pub fn next_start(&self, b) -> Option<Cursor>;                  // peek, for normalized draw matching (6.6)
    pub fn count_passthrough(&mut self, calls: u64);                // attempt.end.passthrough_calls (6.5)
    pub fn unpersisted(&self) -> Option<(u64, Vec<u8>, Digest)>;   // (at, frames, head after)
    pub fn mark_persisted(&mut self, upto_entries: u64);
    pub fn sync(&mut self) -> Result<(), Fault>;                    // persist inline through the sink
    pub fn entry(&self, cursor) -> Option<&Entry>;
}
```

Bindings that keep an attempt in an object and step it from several
threads and tasks use `Attempt::into_owned() -> OwnedAttempt`: `Send`,
borrowing nothing, with `session()`, `finish(result)` and `abandon()` (a
crash) but no root `Ctx`. A host that persists on a thread of its own
takes the sink with `Session::detach_sink()`: the primitives then append
without persisting, the host persists `unpersisted()` outside any lock on
the session and reports `mark_persisted` or `persist_failed`, and it
reattaches the sink (`attach_sink`) before `finish`, so `attempt.end` is
persisted inline. A receive whose `ChannelRecv` never becomes durable
(its persist fails, or the attempt is abandoned) goes back to the front of
its channel. A failed persist does not prove that nothing was written (a
server can store frames and lose its answer), so a receive put back after
one is *in doubt*: the next recording checkout takes its message off the
channel again if the journal it loads holds that `ChannelRecv` at the
receive's cursor, and a message is never received twice.
`Session::join_each` returns each child's completeness check,
so a host that runs region children itself can raise the failure of the
lowest-index failed child. `RunOptions.normalization` names the
request-normalization rules a host matches draws under; `attempt.start`
records them (6.6).

`Ctx<'a>` is `{ session: &'a mut Session, branch: Branch }` and keeps
today's methods (`oracle`, `effect`, `recv`, `now`, `contract`,
`program_marker`, `is_replaying`) as wrappers. It gains `random`,
`patched`, `deprecate_patch`, and
`parallel<T>(&mut self, n: u32, f: impl FnMut(u32, &mut Ctx<'_>) ->
Result<T, Fault>) -> Result<Vec<T>, Fault>`, which runs children one
after another under the region rules. `AsyncCtx` holds
`&RefCell<Session>` and a branch, never holds the borrow across `.await`,
and its `parallel` drives child futures concurrently with a
zero-dependency join.

### 3.2 Durability protocol and failure

- A step's result is released to the agent only after the frames
  containing it are persisted. Draw and effect intents are persisted
  before the call or effect.
- At most one persist per journal is in flight. A sync arriving during a
  persist waits, then sends everything buffered since.
- **Sticky failure:** any persist error moves the Session to *failed*.
  Every later primitive on every branch returns the same fault without
  touching the journal. `attempt.end` is not written. Checkin discards the
  in-memory journal and releases the lock or lease. The next attempt
  starts from durable state.
- `Fault::EffectUnrecorded{name, intent, result}` is raised when perform
  succeeded but its result could not be persisted, so the caller can log
  the result: a failed persist, a session another branch's persist failed
  while the effect ran, or a result over the slot limit. A result that
  cannot be appended (over a limit), for an effect or a draw, fails the
  session as a persist error does: the call happened and the attempt
  cannot go on as if it had not.

### 3.3 Backends and sinks

```rust
pub trait Backend: Send + Sync {
    fn checkout(&self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Checkout, Fault>; // journal + guard
    fn snapshot(&self, run_id: &str, key: Option<&[u8]>) -> Result<Journal, Fault>;               // no lock, read-only
    fn list(&self) -> Result<Vec<String>, Fault>;
    fn verify(&self, run_id: &str, key: Option<&[u8]>) -> Result<VerifyReport, Fault>;           // provided: snapshot().audit(); file-backed stores read past corruption (2.14)
}
pub trait Sink: Send {
    fn persist(&mut self, at: u64, frames: &[u8], head_after: &Digest) -> Result<(), SinkError>;
    fn rewrite(&mut self, file: &[u8]) -> Result<(), SinkError>;    // erasure and truncation only
    fn remove_copies(&mut self) -> Result<(), SinkError>;           // provided (no-op): erasure removes moved-aside torn tails first
}
pub enum SinkError { Io(std::io::Error), Conflict { expected: u64, actual: u64 }, Locked { retry_after_secs: Option<u64> }, LeaseLost, TooLarge { limit: u64 }, Deleted }
```

Dropping a `Checkout` guard releases the lock or lease and clears the
checked-out mark, regardless of what else still holds references.

**MemoryBackend.** Stores persisted bytes per run. Checkout parses a copy
and marks the run checked out. A second checkout of the same run is
`Fault::Locked`.

**DirBackend (format 2).** File names are `hex(SHA-256(run_id))`:
`<dir>/<64hex>.journal` plus a sidecar `<64hex>.lock`. The lock file is
created on first use and never renamed, truncated or read by readers.
Journal files are never locked. Checkout:

1. Check a process-global registry of held lock paths. If the path is
   held, `Locked`.
2. Open the lock file with `O_CLOEXEC` and `try_lock`.
   - `WouldBlock` → `Locked`
   - ENOTSUP, ENOLCK or EOPNOTSUPP →
     `Unsupported("journal directory does not support file locks")`
   - anything else → `Io`
3. Write `pid`, host and start time into the lock file (for diagnostics
   only).
4. Under the lock, a missing journal (or one shorter than 16 bytes) is
   created by writing the header to a temp file, fsyncing, renaming it
   into place, and fsyncing the directory.
5. Open the journal and compare its file identity (dev and ino on Unix,
   the file id on Windows) with a fresh stat of the path. On a mismatch,
   reopen.
6. Check that `run.start.run_id` equals the requested id. On a mismatch,
   `Fault::Io("run id collides with ...")`.

`list` reads run ids from `run.start`. A format 1 journal is found by the
old safe-name rule only when no hashed file exists and the run id is one
that rule leaves unchanged: the rule maps distinct ids to one file
(`user.42` and `user_42`), so a format 1 journal belongs only to the id
that is its file name. `list` reports format 1 runs by that name, even
when it looks like a hashed name.

The DirSink tracks `(entries, byte_len)`. Before each persist it fstats
the file and returns `Conflict` if the size differs. It writes all frames
with one `write_all` at `byte_len` and then fsyncs. On any write or fsync
error it attempts `set_len(byte_len)` plus fsync and marks itself failed.
An fsync is never retried. DirBackend gives no exclusion across hosts on
network filesystems; the docs say to use the server for that.

The workspace `rust-version` becomes 1.89 (`File::try_lock`).

### 3.4 Faults

New: `Erased{cursor}`, `Locked{retry_after_secs}`,
`Conflict{expected, actual}`, `Unsupported(String)`,
`TooLarge{size, limit}`, `DanglingIntent{cursor}`,
`DanglingEffect{cursor}`, `EffectUnrecorded{name, intent, result}`,
`LeaseLost`, `Deleted`, `Unavailable(String)`.

`supervisor::default_policy` returns `Stop` for all of them except
`Unavailable` (`Restart`). The FFI maps them to the existing `PRAG_ERR_IO`
code with the message preserved; there is no header change.

### 3.5 Pure modules (all zero dependencies, all fuzzed)

- **`rand`**: `fill(&mut [u8]) -> io::Result<()>`. Uses `getrandom(2)` on
  Linux, `getentropy` on macOS and the BSDs, and
  `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)` on Windows. Loops on
  short reads and EINTR. Fails closed. No userspace pool. Any other target
  is `compile_error!`.
- **`merkle`**: RFC 6962 / RFC 9162 tree hash, inclusion and consistency
  proofs, with verification algorithms exactly per RFC 9162 §2.1.3 and
  §2.1.4 (including the proof-length check).
- **`tsp`**: RFC 3161 request encoding and response/TSTInfo parsing
  (strict DER, no signature checks). Responses are accepted only with
  PKIStatus granted or grantedWithMods, a matching nonce, a SHA-256
  imprint OID and no trailing bytes.
- **`json`**: strict JSON (3.7).
- **`redact`**: text detectors, JSON-aware: binary fields are never
  scanned and are reported as binary (4.10).
- **`sha512`**, **`ed25519`**: verify-only RFC 8032 Ed25519, rejecting
  non-canonical S and small-order A or R. Tested against the RFC 8032
  vectors. Used by the CLI, server and Python native module to verify
  pinned signatures.
- **`evidence`**: the bundle format (section 5), `to_json`, `from_json`,
  `verify(bundle, &TrustPolicy, &dyn TsaVerifier) -> EvidenceReport`, and
  `verify_with(.., &Audit)` for the full-log audits of 5.3 step 11. RFC
  3161 signatures go through the `TsaVerifier` trait so the core never runs
  a process: the CLI implements it with `openssl ts -verify`, and
  `NoTsaVerifier` reports every token as unchecked. `Bundle::local(journal,
  run_id, &Redact)` builds an unanchored local bundle and
  `Bundle::withhold(slots)` withholds more (`Journal::withhold` makes the
  state 3 copy). `docs/evidence-format.md` is the normative description.

### 3.6 Testing hooks

A `testing` cargo feature exposes `Backend::crash_truncate(run_id, keep)`
and `with_journal_mut`. The E1, E2 and E3 suites are rewritten on these
hooks, with branch-interleaving variants and identical-prompt
best-of-n cases asserting each child's value. Length and cursor
assertions use `Journal::program_entries()` (which excludes meta).

### 3.7 Strict JSON (everywhere: core, server, Python, CLI)

Strict JSON is RFC 8259 with these additional rules:

- Duplicate keys are an error (Python uses `object_pairs_hook`).
- UTF-8 only, no BOM, no lone surrogates.
- Nesting depth is at most 64.
- Where an integer is expected, it matches `-?(0|[1-9][0-9]*)` and fits
  the target type; fractions and exponents are rejected there.
- Unknown keys in evidence objects are rejected.
- Hex is lowercase with exact length.
- Base64 is the RFC 4648 standard alphabet with canonical padding.
- Canonical serialization sorts object keys by UTF-8 bytes and has no
  insignificant whitespace.

---

## 4. Pragmatic Server (`crates/pragmatic-server`, axum on tokio)

### 4.1 Process and configuration

`pragmatic-server serve --config FILE` (or `PRAGMATIC_CONFIG`), plus these
subcommands: `keygen [--rotate]`, `token new|revoke|list`, `backup`,
`restore`, `verify-data`, `verify-evidence`, `migrate`.

At startup the server takes an exclusive lock on `<data_dir>/server.lock`
and exits if it is held. It refuses to listen on a non-loopback address
unless `allow_plain_http = true` (TLS terminates at the proxy or ingress).
It refuses to start without at least one independent witness (an
`rfc3161` TSA or a `witness`) unless `allow_self_anchoring = true`, in
which case its bundles carry `"independent": false`.

Full TOML schema with defaults, in `deploy/pragmatic.example.toml` and
`docs/server.md`:

```toml
name = ""                            # origin pragmatic/<name>/<log id> (4.7); empty = host name
listen = "127.0.0.1:7272"
data_dir = "/var/lib/pragmatic"
allow_plain_http = false
trusted_proxy_header = ""            # e.g. "x-forwarded-for"
lease_ttl_secs = 60                  # 1 to 3600
max_request_bytes = 268435456
max_clock_skew_secs = 300
public_url = ""
verify_interval_hours = 24

[keys]
signing_key_file = "/etc/pragmatic/server.ed25519"   # the log key (4.7), Go note format; refused inside data_dir unless allow_key_in_data_dir
allow_key_in_data_dir = false
anchor_key_file = ""                 # 32 random bytes; required when anchor_run_ids = "hmac" (4.7)

[bootstrap]
admin_token_sha256 = ""              # first admin; all other tokens are issued through the API

[anchoring]
interval_secs = 600                  # 60 to 3600 (4.7)
min_independent_operators = 2        # at least 1: the server's own signature never counts
# operator is required; roots_pem holds that operator's trust anchors (4.7)
tsa = [ { url = "http://timestamp.digicert.com", operator = "digicert", roots_pem = "/etc/pragmatic/tsa-roots/digicert.pem" } ]
# operator = "" means the witness key's name
witness = [ { url = "https://witness.pragmatic.example", vkey = "<name>+<key id>+<base64>", operator = "", token_file = "..." } ]
allow_self_anchoring = false
anchor_run_ids = "plain"             # or "hmac"

[[retention]]
match = { prefix = "", labels = {} }
retain_min_days = 0
shred_after_days = 0                 # 0 = never
delete_after_days = 0
erasure = "allow"                    # or "deny_during_min"

[redaction]
builtin = ["email", "phone", "ssn", "card", "iban", "ipv4", "secret"]
patterns = []                        # regular expressions

[[webhooks]]
url = ""
secret_file = ""
events = ["chain_broken", "anchor_failed", "regressed", "erasure", "retention", "dangling_effect", "clock_skew", "record_missing", "hold", "access_log_failed"]

[witness_mode]
enabled = false
name = "witness.example.com"         # the cosigner key name (a tlog-cosignature name)
key_file = "/etc/pragmatic/witness.ed25519"
origins = [ { name = "acme", origin = "pragmatic/acme/<log id>", log_vkeys = ["pragmatic/acme/<log id>+<key id>+<base64>"], token_sha256 = "hex" } ]

[license]
licensee = ""
```

### 4.2 Storage

```
<data_dir>/
  FORMAT                              {"data_format": 1}
  server.lock
  tokens.json                         issued tokens (atomic writes)
  runs/<hh>/<64hex>.journal           hh = first 2 hex of SHA-256(run_id)
  runs/<hh>/<64hex>.meta.json         {"format":1, run_id, created_at, updated_at, entries, byte_len, head,
                                       anchored_entries, last_anchor_leaf, leases, holds, status,
                                       unanchored_since, summary (open_intents among it)}
  runs/<hh>/<64hex>.tombstone.json    {run_id, deleted_at, entries, head, policy}
  runs/<hh>/<64hex>.torn-<unix_ms>    torn tails moved aside (removed by erasure)
  holds.json                          legal holds (atomic writes)
  keys.json                           every signing key and its validity window
  index.key                           the subjects index HMAC key (32 bytes)
  anchors/log.leaves                  the cumulative anchor log, append-only
  anchors/sth/<seq 20-digit>.json     one per batch, create_new, never overwritten
  anchors/batches/<seq 20-digit>.json run id of each leaf of the batch (never served raw)
  anchors/witness/<seq 20-digit>/<label>.json
                                      one verified witness result per witness, create_new
  audit/access.journal                the access log, journal format 2
  audit/access.index                  its frame offsets, rebuilt from it at every start
  audit/anchor.json                   the access log's last anchor leaf {leaf_index, entries, head}
  erasure-ledger.jsonl                every erasure, shred, delete and hold change, written before it commits
```

- All JSON files are written as temp file, fsync, rename, fsync directory;
  write-once files (`sth/`, `witness/`) are hard-linked into place instead
  of renamed, so they are never replaced (4.7).
- The index (entries, byte_len, head) is updated only after the journal
  fsync, under the run's lock.
- `meta.json` is rewritten at most once per second per run, and at clean
  shutdown.
- At startup a journal whose size equals `meta.byte_len` and whose last 32
  bytes equal `meta.head` is trusted; otherwise it is parsed again (4.17),
  and it must still hold the history meta recorded: at least
  `meta.entries` entries, entry `meta.entries - 1` hashing to `meta.head`.
  A journal that lost acknowledged entries or rewrote them is damaged
  (`chain_broken`) and never truncated; a torn tail is truncated only when
  the valid prefix covers both `meta.entries` and `anchored_entries`.
- A run whose files cannot be read at startup is *unavailable*: its id
  answers 503 `storage_unavailable`, it is loaded on first use once it
  reads, and its files are never replaced (`PUT` refuses to create a run
  whose journal, meta or tombstone exists on disk). An unreadable
  tombstone still deletes its id (410).
- `/healthz` is live at once. `/readyz` and every run endpoint return 503
  `starting` until the index is ready. Full verification runs in the
  background.
- Any run the anchor log holds a leaf for, with neither a journal nor a
  tombstone, is marked `missing` (webhook `record_missing`), whether or
  not the leaf was independently anchored: the history was written and
  signed, then lost. A missing run never gets a `meta.json` (meta without
  a journal and nothing anchored would be begun again empty at the next
  start).
- Any run with `entries < anchored_entries`, or with fewer entries than
  its last leaf in the anchor log (or as many and another head), is marked
  `regressed`, at startup as well as by a batch, so nothing is appended to
  a rolled-back history before a batch notices. Appends to it get 409
  `regressed` until `pragmatic-server accept-regression RUN`, which is
  logged. Acceptance claims nothing new: `anchored_entries` becomes the
  largest `entries` among the run's independently anchored leaves that
  the journal still holds (entry `entries - 1` hashes to the leaf's head),
  often 0, and the anchoring lag keeps counting. A witness record (4.8) is
  never accepted this way.

### 4.3 Auth, tokens and scopes

A token record is `{id, name, principal, role, scopes, view_raw,
created_at, expires_at, revoked_at}`, stored with `sha256` only.

- `principal` (a person or service identifier) is required.
- `scopes` is a list of run-id prefixes. It is required for every
  non-admin role. `["*"]` must be explicit. An admin's scopes are always
  `["*"]`: tokens, holds and the whole access log cannot be scoped, so an
  admin token with narrower scopes is refused at issue and never
  authenticates if one is found in `tokens.json`.
- The record also holds `created_by`, the token id that issued it, and the
  issue's access-log intent names the new token's id, durable before the
  token exists.
- Roles:

| role | may |
|---|---|
| `agent` | in scope: create runs, lease, append, read a journal only while holding its lease, read summaries |
| `auditor` | in scope: list and read (redacted unless `view_raw`), snapshot journals (`view_raw` only), verify, evidence, anchors, the access log for in-scope runs |
| `admin` | everything, plus tokens, erasure, holds, retention, the full access log |
| `witness_client` | witness mode only, bound to one origin |

- Out-of-scope run endpoints return `not_found`, never `forbidden`.
  Out-of-scope `PUT` returns `forbidden`. Lists are filtered.
- Tokens are issued and revoked through `POST /v1/tokens` and
  `DELETE /v1/tokens/{id}` (admin), or the `token` subcommand, which talks
  to a running server. Each issue and revocation is an access-log record.
  The token value is shown once.
- The console uses tokens: sign-in exchanges a token for a session cookie
  (`HttpOnly`, `SameSite=Strict`, `Secure` when served over HTTPS), with a
  15-minute idle timeout and a 12-hour absolute limit. Sign-in and
  sign-out are logged. OIDC is 0.7.
- `GET /v1/whoami` → `{token_id, name, principal, role, scopes}`.

### 4.4 HTTP API v1

All under `/v1`. Bearer auth. Errors are
`{"error": {"code", "message", ...}}`. Request bodies are strict JSON.

| method and path | role | behavior |
|---|---|---|
| `GET /v1/info` | any | `{server, version, api_version: 1, min_sdk, journal_format: 2, chain: "sha256", lease_ttl_secs, max_request_bytes, max_frame_bytes, server_time, independent_witness: bool, components: {anchoring, evidence, console: "integrated"\|"not_integrated"}, licensee}`; `independent_witness` is false while anchoring is not integrated |
| `GET /v1/whoami` | any | as above |
| `GET /v1/keys` | any | every server signing key `{key_id, public_key, not_before, not_after}` |
| `GET /v1/runs?prefix=&q=&label.k=v&program=&status=&since=&until=&limit=&after=` | any | `{runs: [RunSummary], next}`. `q` matches run id and label values only, never content |
| `GET /v1/runs/{id}` | any | `RunSummary` + `{verify: VerifyReport (cached, incremental)}`; the report carries `damaged` (why the journal is damaged, or null) and is never `ok` for a damaged or missing run |
| `GET /v1/runs/{id}/entries?from=&limit=` | any | `{entries: [Entry JSON (below)], next, total}`; content redacted unless `view_raw`; slots over 64 KiB truncated |
| `GET /v1/runs/{id}/entries/{cursor}/slots/{k}` | any | one slot's content, redaction rules apply |
| `GET /v1/runs/{id}/journal` | agent (with its lease), admin, auditor+view_raw | journal bytes, `Pragmatic-Entries`, `Pragmatic-Head`; a damaged journal answers 409 `chain_broken` before any byte (4.17) |
| `PUT /v1/runs/{id}` | agent, admin | body: the 16-byte header (flags 0); optional header `Pragmatic-Holder: <client uuid>` names the holder of the lease it grants (a resent PUT that finds `run_exists` then renews that lease with `POST lease`). Creates the run and grants a lease atomically: 201 `{lease, ttl_secs, entries}`; or `run_exists`, `run_deleted` |
| `POST /v1/runs/{id}/lease` | agent, admin | body `{"holder": client uuid}`, optional header `Pragmatic-Lease`. Acquire, or renew if same holder and token: 200 `{lease, ttl_secs, entries}`; `run_locked` with `Retry-After` and `{holder_expires_in}` (4.17) |
| `DELETE /v1/runs/{id}/lease` | agent, admin | header `Pragmatic-Lease`; appends the `custody` note; 204 |
| `POST /v1/runs/{id}/frames?at=N` | agent, admin | headers `Pragmatic-Lease`, `Pragmatic-Frames: k`, `Pragmatic-Head`; body = k frames. 200 `{entries, head, duplicate}` |
| `GET /v1/runs/{id}/evidence?redact=&anchor=now` | auditor, admin | evidence bundle; `anchor=now` forces a batch and waits for it. `redact=none` and `redact=binary` (which withholds attachments only) carry text slots unredacted: both need `view_raw` and are raw reads, logged durably before the bundle is served. A damaged journal answers 409 `chain_broken` |
| `POST /v1/runs/{id}/erase` | admin | `{"slots": [[c, s], ...] \| "match": "<text>" \| "all", "reason_code", "reason", "force": false, "allow_unfinished": false}` |
| `POST /v1/holds`, `DELETE /v1/holds/{id}`, `GET /v1/holds` | admin | `{matter, scope: {run_ids} \| {prefix}}` |
| `POST /v1/runs/{id}/accept-regression` | admin | accept a regressed run's journal as its history; logged before it acts (4.2) |
| `POST /v1/subjects/search` | admin | body `{"subject": "..."}`; returns run ids from the subject index |
| `POST /v1/retention/run` | admin | run retention now; report |
| `POST /v1/verify-data` | admin | run verify-data now (4.13); report |
| `GET /v1/anchors?after=&limit=`, `GET /v1/anchors/{seq}` | auditor, admin | signed tree heads and witness results; leaves filtered by scope |
| `GET /v1/anchors/log?from=&to=` | auditor, admin | raw leaves (admin: all; auditor: in-scope leaves with inclusion proofs) |
| `GET /v1/audit?run_id=&after=&limit=` | admin; auditor for in-scope runs | `{records, next}`; an auditor without `run_id` gets the records of its in-scope runs; each record carries its chain `hash`; personal fields are `[withheld]` without `view_raw`; one call examines at most 4,096 records and `next` says where to continue |
| `POST /v1/tokens`, `DELETE /v1/tokens/{id}`, `GET /v1/tokens` | admin | token lifecycle |
| `POST /v1/witness`, `POST /add-checkpoint` | witness_client | 4.8 |
| `GET /v1/witness/log/{origin}?after=` | that origin's auditors, admin | 4.8; at most 1,000 record entries per call, with `next` |
| `POST /v1/witness/resume/{origin}` | admin | body `{"checkpoint", "reason"}`: resume a held witness record from the latest checkpoint it cosigned (4.8); logged before it acts |
| `GET /healthz`, `GET /readyz`, `GET /metrics` | none | `/metrics` carries no run ids or label values |

**RunSummary:** `{run_id, entries, head, created_at, updated_at, status:
"active"|"idle"|"dangling"|"regressed"|"missing", erased_slots,
anchored_entries, unanchored_entries, holds: [id], labels, program,
created_by, last_outcome, attempts, attempt_open, usage: {...}}`.
`attempt_open` is true when an attempt has started and not ended (it is
running, or it crashed), so `last_outcome` belongs to an earlier attempt.

**Entry JSON:** `{cursor, at, branch, kind, fields: {name: value}, slots:
[{state: "sealed"|"erased"|"withheld"|"ref", commitment, text|null,
base64|null, binary: {media_type, bytes, sha256}|null, truncated: bool,
len}], hash}`. `text` is used when the bytes are valid UTF-8, otherwise
`base64`. Salts are never included. `fields` uses the field names of the
table in 2.6; the JSON fields (`DrawResult.meta`, `Note.data`,
`Random.args`) appear as JSON values, not as strings. `len` is null for an
erased slot. The entries endpoint answers `{entries, next, total}`, the
entries in cursor order; `next` is the `from` of the following page and
`null` after the last. A page may be shorter than `limit` while more
follow (it is also bounded by bytes, 4.17), so clients follow `next`,
never the page length.

**Errors and the client action for each:**

| code | status | client action |
|---|---|---|
| `unauthorized`, `forbidden` | 401, 403 | fail the session; never retry |
| `not_found` | 404 | on lease during create: PUT; otherwise fail |
| `run_exists` | 409 | POST lease |
| `run_locked` | 409 | raise `Locked(retry_after)` |
| `lease_lost`, `lease_expired` | 409 | fail the session; raise `LeaseLost` (a subclass of `Locked`) |
| `conflict` | 409 | reconcile through the duplicate rule, otherwise fail; the error object carries the run's `entries` and `head`, so the client can tell which of its frames the server already holds |
| `regressed` | 409 | fail; an admin must act |
| `chain_broken` | 409 | fail; an admin must act (the stored journal is damaged or missing) |
| `on_hold`, `retention_locked` | 409 | erasure refused (admin) |
| `run_deleted` | 410 | raise `Deleted`; never recreate |
| `invalid_frames` | 422 | fail; never retry |
| `payload_too_large` | 413 | fail; raise `TooLarge` |
| `starting`, `storage_unavailable` | 503 + `Retry-After` | resend the identical request until the lease deadline |
| `bad_request` | 400 | fail |
| `not_implemented` | 501 | fail (a component is not part of this build) |

### 4.5 Leases

- One lease per run. Leases persist in `meta.json` and are restored at
  startup with `now + ttl`.
- Expiry is lazy: an expired lease keeps working for its holder until the
  lease is granted to a different holder.
- Expiry is measured on the server's monotonic clock. The client computes
  its deadline as the time the request was sent plus `ttl − ttl/4` on its
  own monotonic clock, and never compares wall clocks.
- The SDK renews every `ttl/3` from a dedicated OS thread for the whole
  checkout, including model calls, effects and recovery callbacks.
  `lease_lost` fails the session.
- When a lease ends (release, takeover, or lazy-expiry takeover), the
  server appends a `custody` note for it under the run lock before
  granting the next lease. A run with no entries yet gets no custody note:
  its first entry must be `run.start`.
- `dangling_effect` and status `dangling` require that no renewal has
  happened for more than `2 × ttl`.
- A holder whose lease was taken over after it expired gets
  `lease_expired`; a released, revoked (forced erasure) or unknown lease
  is `lease_lost`.

### 4.6 Append protocol

The server checks, in this order:

1. auth and scope
2. run exists, or 410 for a tombstone
3. duplicate
4. lease
5. `at`
6. frames
7. write

- **Duplicate:** if `at + k ≤ entries` and the stored hashes at
  `[at, at+k)` equal the hashes in the submitted frames, return 200
  `{entries, head: hash(at+k-1), duplicate: true}` whatever the lease
  state.
- **Frames:** the body must contain exactly `k` complete frames, each
  canonically decoded, re-encoded and byte-compared. Each is checked:
  - sealed commitments are recomputed and refs resolved;
  - chain links are recomputed from the current head;
  - no state 2 or 3, and no server-only note kinds;
  - `at` field skew beyond `max_clock_skew_secs` is accepted but flagged
    for custody;
  - the head after the last frame must equal `Pragmatic-Head`.
- All-or-nothing: write, fsync, then update the index.
- Stored hashes for the duplicate rule come from the writer's journal when
  it is loaded and otherwise from disk by offset: a request from a token
  without the lease never loads a journal.
- Before the body is read, the checks that need no body run (in the same
  order): existence, writability, and, unless `Pragmatic-Head` equals the
  stored hash at `at + k - 1` (a possible resend, which the duplicate rule
  must see), the lease and `at`. A refused body is drained, not buffered.
- The first entry of a run is its `run.start` note naming the run's own
  id, and no later entry is a `run.start` (422 `invalid_frames`).
- Clients resend the identical request on connect errors, timeouts, 502,
  503 and 504 until success, a definitive error, or the lease deadline.
  Before giving up they read the run's `entries` and `head` once, and
  report success if their frames are the last ones stored (an earlier try
  whose answer was lost).
- A duplicate answer whose `entries` exceeds `at + k` means that another
  holder has appended since (a takeover appends at least its custody
  note): the frames are durable, but the client treats its lease as lost
  (`LeaseLost`) and acts on none of them, since the new holder's recovery
  may already have written off an intent among them and performed it
  again.
- **Create:** POST lease. On `not_found`, PUT (which grants the lease).
  On `run_exists`, POST lease again. The client appends `run.start` if and
  only if `entries == 0`.

The client verifies every journal it downloads (chain and commitments)
and compares the returned head after every POST with its own computed
head. A mismatch is `Conflict`.

### 4.7 Anchoring: one cumulative log

The server keeps one append-only RFC 6962 Merkle log of leaves:

```
leaf_data = "pragmatic/v2/leaf" ‖ u8 type (0 run, 1 access log) ‖ u32 len(id) ‖ id ‖
            u64 entries ‖ head(32) ‖ u64 prev_leaf_index (u64::MAX if none)
```

- Integers are little-endian, as everywhere in format 2, and `id` is 1 to
  1024 bytes. The Merkle leaf hash is RFC 6962's `SHA-256(0x00 ‖
  leaf_data)`.
- With `anchor_run_ids = "hmac"`, `id` = HMAC-SHA-256(k_run, run_id) with
  a per-run key k_run, and bundles carry k_run as `anchor_id`, so the
  bundle holder recomputes the leaf without learning other runs' ids. The
  server derives k_run from one secret, the 32 bytes of
  `[keys] anchor_key_file`: k_run = HMAC-SHA-256(anchor_key,
  "pragmatic/v2/anchor-salt" ‖ run_id), domain-separated so no other HMAC
  under the same key can equal it (the anchoring library calls k_run the
  run's `anchor_salt`). Knowing one run's k_run says nothing about
  another's, so the log's other ids stay opaque even to someone who
  guesses candidate run ids. Verifiers check only `id` =
  HMAC-SHA-256(anchor_id, run_id); the derivation of k_run is the
  server's own.
  - Nothing binds k_run to the run: an administrator can rewrite an
    anchored journal and anchor it again as a fresh leaf chain under a new
    key, and the run's earlier leaves read as another run's. Hidden or
    re-keyed anchors of such runs cannot be detected by any audit, so
    verifiers report `anchor_id_unbound` for every bundle with an
    `anchor_id`, and the `--log` audit fails with `log_unauditable`
    rather than pass (5.3). Deployments that need the omission audit
    anchor with `"plain"`, the default. A run id bound to the log key by a
    verifiable random function (RFC 9381) would keep both properties; it
    is deferred (section 10).
- The access log's leaves (type 1) carry the id `access` in both modes. A
  server in witness mode anchors each origin's witness record (4.8), the
  run `pragmatic:witness:<name>`, like any other run.
- Every `interval_secs`, one task snapshots, under each run's lock, the
  fsynced `(entries, head)` of every run and of the access log that
  changed since its last leaf. Runs created by PUT are included even with
  zero entries. Each object names its previous leaf: a run's is in its
  `meta.json` (written at once when a batch places it), the access log's
  in `audit/anchor.json`; at startup both are raised to the anchor log's
  last leaves, which are durable first. At startup and in verify-data the
  access log must still hold the records its last leaf covers, ending in
  its head; otherwise `chain_broken` fires for `pragmatic:access-log`. The
  leaf is the anchor log's own (its head comes from the signed leaf);
  `audit/anchor.json` is only its cache, and one that names a leaf the
  anchor log does not hold is a finding of its own. The current log's hash
  is never taken for the anchored head.
- Leaves are appended to the log in order of (type, raw id bytes).
  Duplicate ids within a batch abort the batch.
- A snapshot with fewer entries than its id's latest leaf, or the same
  entries and another head, contradicts a signed leaf. It is never
  anchored; the server marks the run `regressed`. A snapshot equal to the
  latest leaf is skipped.
- Each batch ends in a **checkpoint**, a signed tree head in the C2SP
  `tlog-checkpoint` format. This is the format used by Go's checksum
  database and Sigstore, so existing witness and verification tooling
  understands it:
  ```
  <origin>\n<tree size, decimal>\n<base64 root>\n
  ```
  - `origin` is `pragmatic/<server name>/<log id>`: the server name from
    config, and a log id of 16 lowercase hex digits, the first 8 bytes of
    SHA-256 of the log's first public key. Witnesses keep their state per
    origin line (4.8), and server names are chosen locally (many will be
    `prod`), so the name alone would collide at a shared witness such as
    the hosted Pragmatic Witness: one log's tree would block the other's,
    and its honest checkpoints would be recorded as fork attempts. The
    origin is fixed when `keygen` makes the first key (it is that key's
    name) and never changes, rotation included.
  - The checkpoint is signed as a C2SP `signed-note` with the server's
    Ed25519 key, with key id = SHA-256(name ‖ 0x0A ‖ 0x01 ‖ pubkey)[:4].
    The key name is the origin. Key files use the Go `sumdb/note` private
    key format, `PRIVATE+KEY+<name>+<key id>+<base64(0x01 ‖ seed)>`.
  - `seq` is the batch number: a gap-free u64 recovered at startup as the
    maximum + 1.
  - The checkpoint file stores the consistency proof from the previous
    tree: `{seq, tree_size, root, checkpoint (the signed note),
    anchor_digest, prev_tree_size, consistency_from_prev, created_at}`.
- **Files and recovery.** `log.leaves` is a 16-byte header (`PRAGLEAF`,
  u32 LE version 1, u32 LE flags 0), then `u32 LE len ‖ leaf_data` per
  leaf. A batch commits in this order, each step fsynced with its
  directory: the leaves, `batches/<seq>.json` (replaced atomically: one
  left by a failed attempt is stale), then `sth/<seq>.json`, which is the
  commit point. Checkpoint files and witness results are *published*:
  written to a temporary file, fsynced, then hard-linked to their name
  (which never replaces a file; a rename after checking the name is free
  where hard links are unsupported), so a crash leaves no file or a
  complete one, never a torn one. At startup the `sth/` and `batches/`
  directories are fsynced first, and the latest checkpoint's tree size
  says how many leaves are real:
  - leaves past it (a crash before the checkpoint was published) are moved
    to `log.leaves.uncommitted-<unix ms>` and the file is truncated, batch
    indexes newer than the latest checkpoint and temporary files are
    removed;
  - a checkpoint file that does not parse (the latest included: it cannot
    be torn, so it was damaged), witness results for a sequence number at
    or past the latest checkpoint's next one (witnesses are asked only
    after a checkpoint is durable, so its file was committed and later
    lost; recovering past it would sign a different tree under the same
    sequence number, a fork, and discard third parties' evidence), a leaf
    inside the checkpointed prefix that does not decode, a checkpoint root
    the leaves do not reproduce, leaves out of order within a batch, or a
    broken `prev_leaf_index` chain is corruption: the server refuses to
    start, having moved or removed nothing. Every checkpoint root is
    recomputed from the leaves at startup. Witness results are never
    deleted.
  - A batch that fails before its checkpoint file exists is rolled back.
    One whose checkpoint file was published but whose directory fsync
    failed may or may not survive a crash, so its leaves are kept and the
    log refuses writes, and asks no witness, until it is reopened (the
    next batch or retry reopens it); recovery then settles it either way.
- **What witnesses timestamp:** `anchor_digest = SHA-256(checkpoint body)`,
  meaning the body only. Signatures and cosignatures can therefore be added
  later without changing the anchored digest.
- **Interval:** `interval_secs`, default 600 (10 minutes), allowed range
  60–3600. A batch runs only when new leaves exist. A batch also runs
  within 30 s of any run's successful `attempt.end`, and on demand
  (`anchor=now`). Commits never wait for witness network calls: a batch's
  commit and the witness passes are serialized separately, and each pass
  stops starting attempts after 5 minutes.
- **Anchoring never blocks journaling.** The anchoring lag (the age of the
  oldest unanchored append) is a metric and an alert. It is the window in
  which an insider could rewrite history undetected. The server measures
  it from its own runs (each records when its oldest append not yet
  independently anchored was made), so it grows whenever anchoring does
  not happen, whatever the reason, and it moves only with the
  `anchored_entries` each batch reports.

Witnesses:

- **`rfc3161`:** the request imprint is SHA-256 with
  hashedMessage = `anchor_digest`, a fresh 64-bit nonce and
  `certReq = true`. Each configured TSA must name its `operator` (an
  empty one is refused) and its `roots_pem`, that operator's trust
  anchors.
  - Before storing a response, the server checks the status, nonce and
    imprint, then verifies the CMS signature with `openssl ts -verify
    -token_in -digest <anchor_digest> -CAfile <configured anchors>
    -partial_chain -untrusted <token certs>`. It stores the full token
    and chain.
  - **Operators are bound to trust anchors, not to labels.** The
    `operator` is configuration text; what gives it meaning is that a
    token verifies only against that operator's anchors. The server
    refuses to start if TSAs of different operators share an anchor
    certificate (by SHA-256 of its DER), since a token from either would
    verify as both. Anchors should be as narrow as the operator allows:
    with `-partial_chain` any certificate in the file is an anchor, so
    pin the CA that issues the operator's own time-stamping certificates
    rather than a general-purpose root, under which others can buy
    time-stamping certificates and pass as the operator. A root works,
    with that risk.
  - The default config uses DigiCert (`http://timestamp.digicert.com`)
    and Sectigo (`http://timestamp.sectigo.com`), each pinned, where the
    operator publishes one, by the CA that issues its public
    time-stamping certificates, otherwise by its root: DigiCert by
    DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1, Sectigo by
    USERTrust RSA Certification Authority. The pinned anchors ship in
    `deploy/tsa-roots/`, one file per operator, with their fingerprints and
    where to obtain each independently in its README.
  - Requests to one TSA are spaced at least 15 s apart.
  - The docs say to obtain written permission from the TSA operators for
    automated use, and list the qualified (eIDAS) providers as a paid
    option.
- **`server-ed25519`:** the checkpoint signature itself. It is always on,
  operator-controlled, and never counted as independent.
- **`witness`:** a C2SP `tlog-witness` cosigner (4.8), such as the hosted
  Pragmatic Witness. Each is configured with its `url` (requests go to
  `<url>/add-checkpoint`), its `cosignature/v1` vkey, an `operator`
  (default, also for an empty value: the key name) and a bearer token.
  The server submits from the size the witness last cosigned for it,
  learning that size from a 409 when it does not know it.

Rules:

- Auditors see the access log's leaves (a count and a head, nothing about
  any run or person), so they can check the records they read, each
  served with its chain hash, against an anchored head.
- The checkpoint file is stored as soon as the server signature exists.
- Every external witness owes a result for every checkpoint. In each
  pass, each witness works through the checkpoints it owes oldest first,
  stops at its first failure, and backs off exponentially (30 s doubling
  to 1 h) as a whole, never per checkpoint: a cosigner is never offered a
  checkpoint while it owes an older one, so it sees the log's
  checkpoints in order (once it has cosigned a newer checkpoint it can
  never cosign an older one; a retry it reports superseded is dropped).
  A per-pass bound (32 checkpoints per witness) only defers the newest,
  never skips older ones. Failed attempts are retried against the same
  checkpoint, RFC 3161 ones with a fresh nonce. Each verified result is
  stored as `anchors/witness/<seq>/<label>.json`; the first per witness
  is kept.
- Witnesses still owed keep being retried after a checkpoint becomes
  independently anchored, until each succeeds or is superseded: a
  verifier counts only the witnesses it trusts (5.2), so a dropped
  witness could leave a bundle short of an auditor's policy. The retry
  queue holds the newest 1024 checkpoints; at startup it is rebuilt from
  the stored results of those checkpoints.
- A checkpoint counts as *independently anchored* once witnesses from at
  least `min_independent_operators` distinct operators (default 2) have
  verified. A run's `anchored_entries` advances only then. Entrust is
  treated as the same operator as Sectigo, and QuoVadis EU as the same
  operator as DigiCert. An alert fires if fewer than the minimum succeed
  for 3 intervals: `anchor_failed` once the anchoring lag exceeds 3 ×
  `interval_secs` (checked by the sweeper, so a quiet server whose
  witnesses are down alerts too), once, re-armed when the lag falls back;
  and after 3 batches in a row end short.
- A run's leaves in different checkpoints can become independent out of
  order (a retry succeeds late), so `anchored_entries` is the largest
  `entries` among its independently anchored leaves.
  `min_independent_operators` is at least 1: the server's signature never
  advances it, so an `allow_self_anchoring` deployment without external
  witnesses keeps `anchored_entries` at 0 and its anchoring lag says so.
- Advancement survives a crash. Witness results are durable before the
  server records the `anchored_entries` they allow, so the first pass
  after startup reports again, for every id, its newest independently
  anchored leaf among the checkpoints the retry queue is rebuilt from.
  The server applies `max`, so the repeat is harmless; without it a
  crash in that window would leave a finished run unanchored forever.
- Each TSA request times out after 30 s.

**Holds and forks.** The server must never sign a different tree under a
sequence number or size it has signed. Two things say it might: a
restore (the backup's anchor log is as old as the backup, 4.13), and a
witness that has seen more of the log than the log holds (a cosigner
reporting a larger tree than the log's, or refusing a checkpoint as
inconsistent with the tree it cosigned, 422). Either *holds* anchoring:
`anchors/hold.json` is written, no checkpoint is signed (a batch answers
with the hold's reason, `anchor=now` with 503), the `anchor_failed`
webhook fires (`fork: true` for a witness's alarm), and only
`pragmatic-server confirm-anchors` lifts it (4.13). A fork alarm is never
retried away. Witnesses still owed results for existing checkpoints keep
being asked.

**Key rotation:** `keygen --rotate` (server stopped) appends a `key.rotate`
record (old and new key ids, signed by both) to the access log. `GET
/v1/keys` lists every key with its validity window. Both keys sign
`"pragmatic/v2/key-rotate\n" ‖ canonical JSON of {at, new_key_id,
new_public_key, old_key_id, old_public_key}`; the note data is those
fields plus `old_signature` and `new_signature`, all hex. Key ids are the
4-byte note key ids, as in checkpoint signature lines and bundle
signatures (5.1); since four bytes identify a key only as a hint, every
place that names a key id also carries the full public key. The origin
does not change on rotation, and the server refuses to sign for a log
whose checkpoints name another origin.

### 4.8 Witness mode

Witness mode implements the C2SP `tlog-witness` protocol, so the server
can cosign checkpoints for other logs and join the public witness network.

- **Endpoint:** with `[witness_mode] enabled`, `POST /add-checkpoint`
  accepts the body defined by `tlog-witness`: an `old <size>` line, the
  consistency proof lines, and the signed checkpoint. (`POST /v1/witness`
  in 4.4 is the same handler.)
- **Who may submit:** each origin is configured with the log's public
  key, and callers authenticate with a `witness_client` token bound to
  that origin. The origin always comes from the configuration, never from
  the body. An origin entry gives its configuration `name` (bound to the
  token, and the `{origin}` of the log endpoint), the checkpoint `origin`
  line and the log's vkeys; a checkpoint naming another origin than the
  token's is refused with 403. All state is per origin line, as in every
  `tlog-witness`, so no two entries may share an origin line or a name:
  the witness refuses such a configuration at startup, and the hosted
  witness's onboarding refuses a log whose origin line is taken (4.7
  makes Pragmatic origins unique).
- **Checks**, in the protocol's order:
  - the log's signature on the checkpoint (403);
  - an old size no larger than the checkpoint's (400);
  - that the old size matches the last size this witness cosigned for the
    origin (otherwise 409 with the witness's current size, as the
    protocol specifies: `<size>\n` as `text/x.tlog.size`);
  - the consistency proof, empty from size 0, and equal roots at equal
    sizes; a size-0 checkpoint must have the empty root (422).
- **What it returns:** a `cosignature/v1` signature line (Ed25519)
  covering `"cosignature/v1\ntime <unix>\n" ‖ checkpoint body`.
- **Its own record:** the witness appends every cosigned checkpoint to its
  own record, which it anchors to its own TSAs.
  `GET /v1/witness/log/{origin}?after=` returns the cosigned history for
  audits.
  - The record of each origin is the server-written run
    `pragmatic:witness:<name>`, named by the origin entry's configuration
    `name` (a reserved id no client can write),
    kept in the run store and anchored in the server's own log like any
    run. It is created whole (header and `run.start` together), and the
    last cosigned size is read from it under the run's lock.
  - The witness stops cosigning for an origin (503) rather than cosign
    from a record that may have forgotten what it cosigned: a damaged
    record (`chain_broken`); a `regressed` one (it holds fewer entries
    than its last leaf in the server's anchor log, or was restored from a
    backup, 4.13); and a `missing` one (gone while the anchor log holds a
    leaf for it). A record is created on first contact only when the
    anchor log holds no leaf for it, so a lost record is never begun
    afresh. `accept-regression` does not apply to witness records.
  - An administrator resumes a held record with the latest checkpoint the
    witness cosigned for the origin, taken from outside the host (the
    witnessed log keeps its cosignatures; so does a witness log streamed
    off the host): `pragmatic-server witness-resume ORIGIN --checkpoint
    FILE` (`POST /v1/witness/resume/{origin}`). The checkpoint must carry
    the log's signature and a valid cosignature from this witness's key,
    and must not be older than, or conflict with, a cosignature the record
    still holds. It is appended as a `witness.resume` note (the same data
    as `witness.cosign`, the cosigned note as its payload), cosigning
    continues from it, and the log endpoint lists it with `resumed: true`.
    A missing record is begun again with it.
  - Each cosigned checkpoint is a `witness.cosign` note `{origin,
    old_size, tree_size, root, timestamp}` whose payload slot holds the
    cosigned checkpoint (the signed note and the cosignature line),
    durable before the cosignature is returned and atomic with the size
    check, so a crash can never make the witness forget a cosignature and
    sign a fork.
  - A correctly signed checkpoint that fails the consistency checks (a
    fork attempt) is recorded as a `witness.reject` note `{origin,
    old_size, tree_size, root, reason}` with the submitted note as its
    payload slot.
  - The log endpoint pages by record cursor: `after` is a cursor, one
    call reads at most 1,000 record entries, and the response is
    `{origin, origin_line, witness, cosigned: [{cursor, at, origin,
    old_size, tree_size, root, timestamp, checkpoint, resumed}], next}`: `origin`
    is the entry's configuration name, `origin_line` its checkpoint origin,
    `witness` the cosigner name, `root` hex, and each `checkpoint` the
    cosigned note (the signed checkpoint with this witness's line), which
    verifies with the witness's vkey alone. The `--witness-log` file of
    5.3 is `{"witness": witness, "origin": origin_line, "checkpoints":
    [every page's cosigned[].checkpoint, in order]}`.
  - The checks and the cosigning are the anchoring library's
    (`WitnessCore`: `check` before the record's lock, `decide` under it),
    so the server and the library's own witness cosign alike.
  - While a record is written its journal is held whole (the store's
    writer keeps the parsed journal), about a kilobyte per cosignature.
    Bounded memory needs a writer that appends from the journal's tail
    state (head, length) and is deferred (10).

Pragmatic Research runs the hosted witness with this same binary. The CLI
ships its public keys, an empty list until it launches.

### 4.9 Erasure, holds, retention, tombstones

- **Erasure**
  - Requires no live lease (`run_locked` with Retry-After), unless
    `force=true`, which revokes the lease so the holder's next call gets
    `lease_lost`.
  - Refused while a hold matches (`on_hold`), and during `retain_min`
    under `erasure = "deny_during_min"` (`retention_locked` with
    `retain_until`; the refusal is logged with reason `legal_obligation`).
  - A run whose last `attempt.end` is not ok needs `allow_unfinished`; the
    response states the run can no longer resume.
  - It takes the run's exclusive RW lock. Readers of entries and evidence
    hold it shared while they read; a journal download holds it for each
    chunk it reads and is aborted once an erasure or deletion has replaced
    or removed the file, so no byte read after the erasure committed is
    served and an erasure never waits for a download.
  - Every refusal comes before anything changes: with `force` the
    selector is checked before the lease is revoked.
  - The access record is made durable, a lease still recorded is ended
    (custody note, `meta.json` written at once), the erasure ledger record
    is written (fsynced), and only then is the file committed per 2.13: a
    restore re-applies the ledger, so no committed erasure may lack its
    record. The note's `by` is the token id, and `access_log_cursor`
    points at its access record.
  - Client-supplied `by` values are not accepted.
- **Holds** are objects. A run is held while any hold matches it,
  including runs created later under a held prefix. Hold changes and
  retention actions take the run's exclusive lock, and retention re-reads
  holds under that lock immediately before acting. Placing and removing a
  hold are erasure-ledger records (with the hold), written before they
  act and announced by the `hold` webhook (without the matter), so a
  restore places and removes them again.
- **Retention**
  - When several policies match, each value is the most restrictive one:
    the largest `retain_min_days`, `deny` over `allow`.
  - Ages count from `updated_at`, and runs with a live lease are skipped.
  - Shred erases every content slot (reason_code `retention`, `by`
    `server:retention`). Delete writes its ledger record, then a
    tombstone, then removes the files. Once the tombstone is durable the
    run is deleted (its tombstone is registered before it leaves the run
    map, so no `PUT` slips in between); files that cannot be removed yet
    are removed at the next start. Tombstoned ids can never be recreated
    (410). Both are erasure-ledger records.
  - Runs with reserved `pragmatic:` ids are never touched by retention.
  - Retention runs hourly and on demand.
  - Validation: shred and delete must each be at least `retain_min`.
  - Combining `shred_after_days` and `delete_after_days` across policies:
    the smallest non-zero value, but never earlier than the combined
    `retain_min_days` (0 only when every matching policy says never).
- **Subjects index:** HMAC(index_key, subject) → run ids, from `run.start`
  payload slots. Entries are removed when the slot is erased. The hashes
  are kept in each run's `meta.json` and searched there; `index_key` is
  `<data_dir>/index.key`. It is
  queried only through admin `POST /v1/subjects/search`, with the
  identifier in the body (never logged).

### 4.10 Redaction and views

Views for tokens without `view_raw` never include salts or raw journal
bytes, and never text slots unredacted: an evidence bundle for such a
token is `detectors` or `all` (`binary` withholds attachments only and
leaves text in clear, so it needs `view_raw` like `none`). Each slot that
starts like JSON is read as JSON, in one pass with no size or nesting
limit and leniently (a repeated key is read in every copy, `NaN` is a
value), since an attachment must never escape detection because a slot
is large, deep or not quite strict JSON:

- Binary fields are replaced by
  `[binary media_type=… bytes=n sha256=…]` and never served. These are
  Anthropic `source.type == "base64"`, OpenAI `data:` URLs, `file_data`,
  `input_audio.data`, OpenAI image `b64_json` and codec `{"$bytes": …}`;
  a slot that is not UTF-8 is binary as a whole. The detection lives in
  the core (`redact::binary::scan`), shared by the server, the console and
  evidence redaction.
- Text is redacted with the built-in detectors plus configured patterns,
  object keys included; keys that redact alike get a suffix (`[email]`,
  `[email] (2)`) so the view stays strict JSON.
- A slot that is JSON but not strict JSON (a repeated key, deep nesting,
  `NaN`) is still scanned for binary fields in every copy of a repeated
  key, and the same rules apply, so its binary fields are withheld.
- Non-JSON slots are redacted as text, and runs of 256 or more base64
  characters in them are withheld as binary.
- A streamed model reply holds its text in deltas, where no detector sees
  a value split across them. When the reassembled text (`redact::stream`)
  holds something a detector or pattern finds, the view shows that text,
  redacted, instead of the events, and evidence `detectors` withholds the
  slot.
- A slot that starts like JSON but cannot be read to its end is reported
  as `incomplete` by the scan, with whatever was found before it stopped.
  Evidence redaction (`binary`, `detectors`) withholds such slots: what
  was not read is never assumed free of attachments. The console says the
  slot was not fully scanned.

The console never inlines base64 larger than 64 KiB. The docs state that
redaction does not inspect images, PDFs or audio, and that regex
redaction is not de-identification.

### 4.11 Access log and custody

Every request to `/v1` and the console is logged, including 401, 403 and
404: `{token_id|null, token_fp (on auth failure: first 8 hex of the
presented credential's SHA-256), principal, role, method, route
(template), run_id, status, raw: bool, cursor_from, cursor_to, source_ip,
user_agent, at}`.

- Query-string values are never logged; only parameter names are, at
  most 32 (the rest are counted). A path's run id is logged only when it
  is well formed (2.15) or names a run the server holds; otherwise as
  `invalid_run_id: {bytes, sha256}`.
- Nothing is kept in memory per record: reads go through an on-disk
  offset index rebuilt at every start, opening and verifying read the log
  frame by frame (the core's `NoteAppender::follow` and `classify_tail`),
  and one read examines at most 4,096 records.
- One writer task appends with group commit (one fsync at most every
  50 ms).
- Erasure, holds, retention, token changes and raw-content reads wait
  for their record to be durable before acting.
- If the access log cannot be written, every authenticated request gets
  503 `storage_unavailable` (fail closed). `/readyz` answers 503 too, the
  `pragmatic_access_log_failed` gauge is 1, and the `access_log_failed`
  webhook fires.
- Viewers without `view_raw` see the personal fields (`principal`,
  `source_ip`, `user_agent`) as `[withheld]`: content detectors do not
  recognize every address or name.
- The access log is never shredded by run policies.
- At startup the server appends `config.loaded {config_sha256, token_ids,
  key_id}`.

Custody for each run is written into the run's own journal as the
`custody` note when each lease ends.

### 4.12 Alerts and metrics

- Webhooks POST JSON with the header
  `Pragmatic-Signature: sha256=<HMAC(secret, body)>`, retried with
  backoff for up to 24 hours.
- `/metrics` exposes `pragmatic_appends_total`,
  `pragmatic_append_seconds` (histogram), `pragmatic_runs`,
  `pragmatic_anchor_failures_total`, `pragmatic_chain_broken_total`,
  `pragmatic_dangling_effects`, `pragmatic_tokens_total{kind}`,
  `pragmatic_access_log_lag_seconds`, `pragmatic_access_log_failed` and
  `pragmatic_anchor_lag_seconds`.
- A run is damaged (`chain_broken` webhook and metric, writes refused,
  listed in verify-data's `failing_run_ids`) when any verification
  finding is not ok: a failing chain or commitment, and also erasure
  accounting that does not add up (2.13). When the only finding is
  `erasure_incomplete`, erasure stays allowed, since erasing again repairs
  it.

### 4.13 Backup, restore, verification, upgrades

- **`backup --to DIR`**
  - Notes the erasure ledger's last record before copying any journal;
    that is the manifest's `ledger_seq`, so everything recorded while the
    backup runs is applied again by a restore (re-applying is harmless).
  - Copies each journal up to its indexed length (opened by fd, so an
    erasure rename is safe), plus meta, anchors, the access log's last
    leaf and the access log, tokens and the erasure ledger, as streams.
  - Writes `manifest.json` signed by the server key.
- **`restore --from DIR [--erasure-ledger FILE] [--trust-key HEX]
  [--anchors DIR]`** (server stopped, empty data directory)
  - Verifies the manifest signature against keys trusted from outside the
    backup: the configured signing key, the keys it replaced (kept next to
    it by `keygen --rotate`), and keys named with `--trust-key`. A key the
    backup's own key ring names proves nothing. Verifies every file's
    SHA-256, again as it copies.
  - Re-applies every ledger entry newer than the snapshot, in order
    (erasures, shreds, deletes and hold changes), without writing records
    the restored ledger already holds.
  - Ends every restored lease with a custody note (`end: "restored"`).
  - Marks runs whose `entries` are fewer than their anchored length as
    `regressed`.
  - The anchor log. The backup's is as old as the backup, and the server
    signed checkpoints after it; signing on from it would sign other
    trees under sequence numbers and sizes already signed, under the same
    key and origin: a fork of the log, which every checkpoint handed out
    since (in bundles, to TSAs and witnesses) contradicts. So either
    `--anchors DIR` restores the anchors directory that survived the
    disaster in place of the backup's (it must continue the backup's
    log: every checkpoint of the backup's is in it, naming the same
    tree), or anchoring is held (4.7) until `confirm-anchors` (server
    stopped) lifts the hold: `--checkpoint FILE` with the newest
    checkpoint the log published (a witness's log or the newest bundle
    has it), which must be the restored log's latest, or `--new-log`,
    which retires the held log to `anchors.retired-<ms>/` and begins a
    new one under a new key (a new origin; `keygen` it into a new key
    file first). The old origin's keys are retired, every run is offered
    to the new log afresh (`anchored_entries` back to 0 until the new
    log's witnesses vouch), and an `anchors.new_log` access record naming
    the old origin and its latest checkpoint links the two logs once the
    new log anchors it. Witnesses must onboard the new origin.
  - In witness mode, every restored witness record is held (`regressed`):
    it has forgotten every cosignature made after the backup, and nothing
    on the host can tell which. Each is resumed with `witness-resume`
    (4.8).
  - Appends a `restore` access record.
  - The docs require streaming the erasure ledger off the host, and keeping
    the anchors directory, or at least the latest checkpoint and witness
    results, somewhere a restore can reach.
- **`verify-data`** runs every `verify_interval_hours` (default 24) and on
  demand (`POST /v1/verify-data`, which the subcommand calls; `--offline`
  works on a stopped server's data directory). It re-verifies every chain, every commitment and every anchor
  inclusion and consistency proof, and records the results in the access
  log.
- **`migrate`** upgrades `data_format`. The server refuses to start on an
  unknown format.

### 4.14 Console

Server-rendered with the shared `pragmatic-console` crate:

- runs list (filters: prefix, labels, program, status, dates)
- run timeline (branches, regions, intents and results, erased, withheld
  and ref slots, notes, attempts, custody)
- verification and anchor status (independent or operator-only)
- evidence download
- holds, erasure and retention (admin)
- access log
- tokens (admin)
- the licensee in the footer, when one is configured (the console's own
  chrome carries no note about configuration that is missing)

The `pragmatic-console` crate (Apache-2.0, no dependencies beyond the
core) renders these pages for the server and the CLI alike:
`render_run(&RunView)` (and `render_run_page`, which also returns where
the next page starts), `render_index(&[RunRow])`,
`render_evidence(&Bundle, &EvidenceReport)` and
`render_csv(&Bundle, &EvidenceReport)`. Pages run no script; all journal
and bundle text is escaped, binary values are summarized, and slot text is
cut at 64 KiB.

- **One design.** The console has the website's design, so the home
  page's picture of a run is a faithful picture of the console: warm
  paper (`#f2efe6`) with lighter leaves on it, hairline rules, EB Garamond
  for words and IBM Plex Mono for data, no bold, square corners, the
  brand's diamond as the only icon, and one colour, terracotta, kept for
  what stopped, failed or broke, or is about to be destroyed. Like the
  website it is always paper: it has no dark scheme and declares
  `color-scheme: light`, so it looks the same on a machine set to dark.
  The masthead is the website's, on the paper with no rule: the mark and
  wordmark, then a breadcrumb (`Pragmatic / journals / refund-20417`
  locally, `Pragmatic / Runs / refund-20417` on the server; a top-level
  page has none, its navigation says where it is). It is a working tool,
  so its type is larger than the website's miniature of it: data at least
  12.5px, labels 11px, every text at least 4.5:1. Numbers in a line of
  words are Garamond's own figures in ink, so the facts line is spaced
  evenly. Every state is said in words as well as by a marker, and the
  words are the same wherever a state is told (the run page, its Run card
  and the runs list). Recorded data never breaks mid-token: hashes, ids
  and model ids are each one unit (a hash shortened to 12 hex characters
  and an ellipsis), a facts line and a kinds line break only between their
  items, and `#N` stays with the word before it. Everything focusable
  shows focus: a button or a checkbox a 2px ring in ink, a text field its
  edge doubled in ink; no rule that removes an outline reaches a checkbox,
  whose native paint hides an edge.
- **Rows, not entries.** The run page is a run sheet (the run id, a
  verification badge, a facts line, a state line, the timeline and the
  chain, whose foot carries the full chain head to copy) with an Evidence
  check card and a Run card, and on the server an Anchoring card before
  them. The cards sit beside the sheet where the page's content is at
  least 1,180px wide, in a 380px column, wide enough for each label and
  its value on one line; below that they go under the sheet, in two
  columns from 640px (the Evidence check card, the tallest, in the
  second, the others in the first), and in one column on a phone. In a
  card narrower than 380px the check's labels sit above their values. A
  local journal has no anchors, and its page says nothing about anchoring
  rather than something negative. The Run card lists the run's attempts
  (each with its start, the Pragmatic Server token that recorded it when
  the server's custody notes name one, its process id, and its outcome),
  its failures and the record keeping after it, each a link to its place
  in the timeline. The user and machine the SDK ran as are personal data
  and stay in the attempt's note, never in the card, so a picture of the
  page does not carry them. On a wide screen the card stays in view while
  a long timeline scrolls, and the facts line's failed and erased counts
  link to their rows. For administrators, erasure is a quiet "Erase content…"
  disclosure at the end of the side column that opens on its form. The
  timeline's rows are built from
  the journal by fixed rules: a step is one row from its intent and every
  result recorded for it (its state follows the latest); `run.start` and
  the first `attempt.start` are one row; each attempt is a group; a result
  whose intent is on an earlier page, or that names no intent, is a row of
  its own; every other entry is a row; record keeping written after the
  run's last attempt (erasure and custody notes) is its own group, "After
  the run", which does not stretch the run's recorded span; and the
  console adds a row where an attempt has no end ("No end: crashed" where
  a later attempt shows it, or at the end of the run what is known:
  running on a live lease, crashed, or for a local journal, which cannot
  say whether a process still writes it, "Attempt 2 is open"). That row
  names the last entry the attempt wrote itself ("attempt 1 stopped after
  #9"), never a note the server wrote (custody, erasure, torn tail), and
  comes right after it: the custody note the server writes when the next
  attempt takes the run follows the crash row, in the crashed attempt's
  group, and an intent that entry left open is named ("during Tool call
  issue_refund"). A call
  with no result that may still be under way (the last entry on its lane,
  in a last attempt that is running or may be) waits in ink; any other is
  interrupted, in terracotta. A recorded failure carries the crash row's
  terracotta rule and wash. Every entry of a page is
  in exactly one row, and each row names all of its entries
  (`draw.intent #2 · draw.ok #3`), the time of its first and the hash of
  its last. Steps an attempt read back (its `replayed` equals the steps
  completed before it) carry a ring, which the attempt's row repeats in
  its words ("4 steps read back") and explains when expanded. A row
  expands (`<details>`, no script) to its entries: what each means for
  replay, its fields, and each slot with its address for erasure
  (`slot 3:1`). A title sits in a `<summary>`, which is a button, so it
  holds no link; the links (to the step performed again, to an intent on
  an earlier page) are in the expanded row. On a phone (a sheet narrower
  than 480px) a row is its title and its kinds line, which wraps between
  entries rather than being cut; the entry hash is in the expanded row.
- **The runs list** speaks the run page's language: each run is a row with
  its state diamond, its id and verification badge, a sentence of its
  state ("Ended ok · 2 attempts · 3 model calls · 14 entries"), and its
  last time and head. On the server the sentence says the state from the
  run summary (which carries `attempts` and `attempt_open`), its entries,
  how far it is anchored and its holds.
- **The console never makes things up.** A row's title is the console's
  own phrase ("Model call", "Tool call", "Run started"), recorded data in
  mono, and accents in the console's words. Recorded content reaches a
  title only as a quoted excerpt of prose (in the console's curly quotes,
  inside `<bdi>`) or a gist of data in mono (`charges ×2, status
  delivered`: an object's members in recorded order, the SDKs' tool-call
  envelopes unwrapped, and a result's members that repeat its input left
  out). A model response names the tools it asks for, or excerpts its
  reply, recognised by the same shape tests as the SDK's `tool_calls`.
  Token counts appear only when draw meta records `usage`, never as 0.
- **Fonts, and what the policy allows.** A single-file page (`export`,
  `render-evidence`) carries its fonts inline as `data:` URIs, and its
  policy is `default-src 'none'; img-src data:; font-src data:;
  style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`: it
  loads nothing and makes no request. `pragmatic serve` and the server
  serve the fonts from their own origin (`/assets/` and `/console/assets/`,
  no credential, under names that carry a hash of the font, with
  `Cache-Control: public, max-age=31536000, immutable`), and their
  policies allow `font-src 'self'` and nothing else from anywhere. The
  crate bundles all four faces, the unmodified Latin subsets Google Fonts
  serves: EB Garamond roman and italic, and IBM Plex Mono regular and
  medium (SIL OFL 1.1, `assets/fonts/OFL-EBGaramond.txt` and
  `OFL-IBMPlexMono.txt`; Plex keeps its Reserved Font Name). Every face
  loads from its bundled file only, never from an installed copy that may
  be another version, so a page looks the same everywhere; Georgia and
  Menlo, scaled to the bundled faces' metrics, stand in while a file
  loads.
- **Pages are bounded.** A run's timeline is shown a page at a time: a
  page ends after 5,000 entries, or before the entry whose detail would
  take the page past 16 MiB of HTML, whichever comes first, and links to
  the next (`RunView.from` and `RunView.page_link`; an exported file names
  the `pragmatic export --from` command that writes the next), so every
  entry is on some page and no page grows with the journal (a 1 GiB
  journal would otherwise be a multi-gigabyte page). What a slot shows is
  capped at 64 KiB of HTML, not of input: indenting and marking up JSON
  can make it many times larger than the text (a nested array of zeros
  grows more than seventy times), and the same cap holds a model call's
  meta and a note's data. Everything a row writes besides its entries is
  bounded too: it names at most five attempts that read it back and five
  later results, and counts the rest; an intent's expanded row names its
  first five results and counts the rest ("Results: #2, #3, #4, #5, #6
  and 99,995 more"), so an intent with any number of results shares its
  page with them; and the Run card lists at most eight
  failures and the first and last attempts of a long run. Attempts are
  found by their start or end cursor, never searched for, so a late page
  of a journal with hundreds of thousands of attempts renders as fast as
  the first. A ref slot links to the slot it repeats rather than showing
  its content again. Recorded field values in an expanded row are set on
  one line with control and bidirectional characters escaped, clipped at
  4,096 characters, and data in mono is isolated (`unicode-bidi:
  isolate`) so right-to-left letters cannot reorder a line.
- **CSV carries its verdict.** `render_csv` takes the report: every row
  carries the verdict and whether the entry is independently anchored, and
  rows are decoded from the bundle's journal, never taken from its
  `records` as stated (only a journal that cannot be read falls back to
  them, with every row `FAILED`).
- **Format 1 runs** are counted (commits as ok effects; format 1 records
  no failures, and the page says so) and shown in full: each recorded
  value in its own block, as a format 2 slot, under a `READ-ONLY` tag.
- **In the server**, the run page is `render_run_page` with a `Frame`
  (the policy, fonts, navigation, and a footer naming the viewer and the
  licensee), a `SlotFilter` that shows every present slot through the
  server's redaction (4.10) for a viewer without `view_raw` (fields stay;
  refs resolve to their target first; an attempt note's `principal` and
  `host` are shown as `[withheld]`, as the access log withholds personal
  fields, and the redaction notice says so), and a `ServerRun`: the run's
  status and holds, its notices, the evidence downloads (auditors and
  administrators), the erasure disclosure (administrators) and, for a
  viewer with `view_raw` only, each token's principal, so the Run card
  can name the token that recorded each attempt. The run's anchoring
  lists each witness of its newest independent anchor (or its newest
  anchor) with its kind and whether the server counts its operator: a TSA
  by the `name` its `[anchoring] tsa` entry gives (`DigiCert`), or else by
  its operator set as an identifier (`digicert`), and, when trusted, with
  the root its pinned anchors chain to (the common name in the first
  pinned certificate's issuer, read once at startup and shown, never
  trusted: `DigiCert Trusted Root G4` for DigiCert's issuing CA,
  `USERTrust RSA Certification Authority` for Sectigo's pinned root).
  The time an anchor proves is shown to the second ("existed no later
  than 14 Oct 2026, 04:24:53 UTC"): a bound rounded down to the minute
  would claim more than the tokens do. The card's head has the hairline
  every card has; only a partial anchor draws its share, as a 2px meter
  on a track inside the card, above the count in words.
  The access log, holds and retention, and tokens are tables on leaves in
  the same frame, stacked as labelled rows on a narrow screen; their cells
  of ids, paths and runs never wrap mid-token. The server's policy is the crate's with `font-src 'self'` and
  `form-action 'self'` (and `frame-ancestors 'none'`), sent as a header
  and in the page; it still loads nothing from anywhere else and runs
  nothing. Its referrer policy is `same-origin`: under `no-referrer` a
  browser sends `Origin: null` with a form's post, which the origin check
  below refuses.
- **Forms.** Every console form that changes something (sign-out, holds,
  retention, erasure, tokens) carries the session's CSRF token, a random
  value kept with the session and compared in constant time, and is
  refused when `Sec-Fetch-Site` is cross-site or `Origin` is not the
  server's; the sign-in form carries the value of a short-lived
  `pragmatic_sign_in` cookie instead. Forms act through the same
  operations as the API, so the access log and the erasure ledger record
  them alike. A finished form redirects to its page with a fixed notice,
  a refused one with its error code, never with text from the request
  (known codes become sentences; an unknown one is shown as a code); a
  new token's value is shown on the page that answers, once.
- **Confirmations.** An action that cannot be undone, or that opens the
  door to one (erasure, removing a hold, revoking a token, running
  retention), answers its first post with a confirmation page and changes
  nothing; only the confirming post, which repeats the fields with
  `confirm=1` and the CSRF token, acts. An erasure's confirmation lists the
  slots it would erase, resolved from the stored journal exactly as the
  erasure resolves them (`Journal::erase_targets`); a run under a hold is
  refused before anything is asked. Previewing "every slot containing"
  says whether the run holds that text, which is a read of its content:
  the preview is recorded in the access log as a raw read
  (`read_raw`, `what: erase_preview`) before it is made.
- **Errors are pages.** A console request that fails is answered with an
  HTML page in the console's frame, with the API's status and
  `Retry-After` (and, for 503 `starting` only, a reload after 5 seconds),
  not with the API's JSON; the access log records it as before. A visitor
  whose session ended is sent to sign in with a notice saying so, and
  signing out says "You are signed out."

### 4.15 Deployment

- `Dockerfile`: multi-stage; the runtime image includes `openssl`; runs
  as non-root with a read-only root filesystem.
- `deploy/docker-compose.yml`.
- `deploy/kubernetes/`: a StatefulSet with `replicas: 1`, update strategy
  `OnDelete`, a PVC, a Secret for the signing key, Service, Ingress, and
  a note on KMS-encrypted storage classes.
- A systemd unit.
- `deploy/pragmatic.example.toml`.
- The docs state that volume encryption is the customer's, as is the data
  region (wherever `data_dir` lives).

### 4.16 Performance targets

These are measured by a load test in CI (release builds) on 4 vCPU with an
SSD:

- `POST /frames` with one frame of 64 KiB or less: p50 ≤ 5 ms and
  p99 ≤ 25 ms server-side, including fsync.
- At least 1,000 appends per second across 200 concurrent runs.
- Startup ≤ 30 s with 1 million runs.
- Journals up to 1 GiB.

### 4.17 Implementation notes and resolutions

Decisions made while building the server, where the sections above were
silent or disagreed:

- **Configuration additions (4.1).** `name` (the server name in the
  anchoring origin; default the host name), `verify_interval_hours`
  (4.13), `[anchoring] min_independent_operators` (4.7), `operator` on TSAs
  and on witnesses (4.7), and the log's keys on witness-mode origins (4.8
  requires them). `interval_secs` defaults to 600 as 4.7 states (4.1
  previously showed 60). Unknown keys are refused. The schema in 4.1 is
  the reconciled one (section 11).
- **The holder of a PUT lease (4.4, 4.5).** `PUT` names no holder, so its
  lease has none until the first `POST lease` that presents the lease id
  in `Pragmatic-Lease`, which records its holder (`PUT` may also name one
  in `Pragmatic-Holder`). A `POST lease` naming a holder without that
  proof is a different holder, so another process using the same token
  cannot adopt a live lease. Renewal also requires the same token.
- **Agents read entries.** The endpoint table makes entries readable by
  any role and the SDK's `rt.entries(id)` needs them, so agents may read
  the entries and slots of in-scope runs (redacted unless `view_raw`). Raw
  journal bytes still need the agent's lease.
- **Custody notes (2.11, 4.5).** `principal` is the token id (2.11 forbids
  names in notes), `lease` is the hex SHA-256 of the lease id, times are
  Unix nanoseconds, and an `end` field says `released`, `expired`,
  `revoked` or `restored` (a lease that came back with a backup and was
  ended by the restore).
- **Status.** `dangling` means an `EffectIntent` without a result and no
  lease activity (renewal or append) for more than `2 × ttl`; dangling
  draws are re-issued on resume and do not count. `updated_at` moves only
  on client appends (and creation), so server-written notes (custody,
  erasure) do not postpone retention.
- **Append order.** A regressed, damaged or missing run answers its
  error (`regressed`, `chain_broken`) right after the existence check,
  before the duplicate rule: its stored hashes cannot be relied on. Header
  and query problems (`bad_request`) and oversized bodies
  (`payload_too_large`) are answered before step 2.
- **Erasure of an unfinished run** without `allow_unfinished` is
  `400 bad_request` with `"unfinished": true`. A run with an expired (not
  live) lease is erasable; its lease is ended with a custody note first.
- **Damaged journals.** A journal that fails to parse at startup, fails
  background verification (any finding that is not ok, erasure accounting
  included), no longer matches its index, or no longer holds the history
  its meta recorded is marked damaged: entries, slots and the console
  serve its valid prefix; a journal download and an evidence bundle, which
  stand for the run's whole history, answer `409 chain_broken` before any
  byte is sent (never `503`, which clients resend: the damage is
  permanent); writes and erasure answer `409 chain_broken` (erasure stays
  allowed when the only finding is `erasure_incomplete`, which erasing
  again repairs), and the `chain_broken` webhook and metric fire. Its
  verify report is never ok: it fails at the first entry the file no
  longer holds, counts only what it holds, and names the damage
  (`damaged`); verify-data counts every damaged and missing run it names.
  It is never truncated or rewritten, and its meta is kept.
- **Unreadable runs (4.2).** Any I/O error reading a run's files at
  startup (or its whole shard directory) makes the run unavailable rather
  than absent, because the client action for `not_found` on a lease is
  `PUT`: answering 404 would let a client replace a history the server
  only failed to read. Unavailable ids answer 503 and are loaded on first
  use once they read; `PUT` never replaces files on disk.
- **The startup shortcut.** A journal is trusted without parsing only when
  its size equals `meta.byte_len` and its last 32 bytes equal `meta.head`,
  because an erasure can change the head without changing the size.
  `meta.json` is written by a flusher, never on the append path, so it lags
  appends by up to a second; lease changes, creation and erasure write it
  at once, and a trusted `meta.json` is not rewritten at startup.
- **Access log records (4.11).** Each record is a note whose `data` holds
  the structural fields and whose single payload slot holds `principal`,
  `source_ip` and `user_agent` (and, for a token issue, the new token's
  name and principal), apart from the structural fields. The format would
  let those slots be erased while the chain verifies, but this build has
  no operation that erases access-log records: the log is a security
  record kept whole (erasing inside a log that is never held in memory
  needs a streaming rewrite, deferred). Request records have kind
  `request`; operations that must be durable before they act first write
  an `intent` record, whose cursor an erasure note's `access_log_cursor`
  names. `trusted_proxy_header` uses the last address in the header. A
  failed write fails closed for every authenticated request until
  restart; unauthenticated requests still get 401. The log is appended
  through the core's `NoteAppender`, written at most 16 MiB per write (so
  a torn tail is never longer than that plus a record, and a restart
  reads at most 64 MiB of tail to classify it), and is never held in
  memory.
- **Backup (4.13).** A live backup copies each journal up to
  `meta.byte_len` (or the last whole frame before it), so it may omit the
  last second of appends. The manifest is signed over SHA-256 of its
  canonical JSON without the signature, and its `ledger_seq` is the
  ledger's position before the first journal was copied. `restore` takes
  anchored lengths from the restored metas, the newer ledger records and
  the anchoring library, and ends leases from the backup with custody
  notes.
- **Integration points.** Anchoring, evidence bundles and the console
  renderer plug in through `pragmatic_server::hooks` (`Anchoring`,
  `EvidenceBuilder`, `ConsoleRenderer`). `serve` uses the integrated
  components, built once the data directory is locked: the anchoring
  library (`anchoring::LibraryAnchoring`), the core evidence module with
  the library's anchor section (`evidence::BundleBuilder`), and
  `pragmatic-console` (`console_ui::ConsoleUi`); `/v1/info` reports them
  `integrated`. Stubs that anchor nothing and answer `501
  not_implemented` remain for tests and embedding, and claim nothing they
  do not do. `verify-evidence` points to the CLI: an auditor should not
  need the operator's server to check its bundles.
- **The anchoring adapter.** A batch hands the library the server's
  snapshots (4.7) as its snapshot provider; the library links each leaf to
  its object's previous leaf from the log itself, so a `meta.json` that
  lags the log can never fork a leaf chain (a repeated snapshot is skipped
  as unchanged). Every batch commits, then runs one witness pass, so
  `anchor=now` waits for the witnesses that answer at once; witnesses
  still owed are retried every 30 s between batches. The adapter reports
  independently anchored leaves (`anchored_entries` advances, the lag
  moves), snapshots the library refuses as regressed or rewritten
  (`AnchorAlert::Contradicted`: the run is marked `regressed` once, and an
  accepted regression is not reported again until the run grows past its
  leaf), failed witness attempts (the failures metric), and three short
  batches in a row (`anchor_failed`). At startup `last_leaves` and
  `anchored_lengths` are read from the log's batch indexes and witness
  results. A batch index that is missing, or does not match its leaves,
  stops nothing: those leaves are read by the ids they carry where they
  are plain (an access-log leaf always is), skipped otherwise, and the
  problem is alerted on. A failed pass at startup is alerted on, never
  ignored. `restore` and `verify-data --offline` open the log without
  witnesses. TSAs need an OpenSSL whose `ts -verify` takes
  `-partial_chain`; the server checks at startup.
- **Evidence from the server.** A bundle is built from the durable
  journal under a share of the byte budget four times its size (the
  journal, its base64 and its records), taken once and held until the
  response is sent in 1 MiB chunks. The latest checkpoint is noted before
  the journal is read, and the bundle's anchors run through it, which is
  also its `latest_checkpoint`: every leaf in that tree was placed before
  the read, so the journal must hold what each covers (a run rolled back
  after it was anchored carries the leaf it contradicts, and its bundle
  fails verification rather than hide the regression), and no leaf of a
  later batch, which may cover appends made after the read, sits inside
  the bundle's latest tree (which the `--log` audit would rightly fail as
  `anchor_omitted`). `independent` is true only when an external witness
  is configured and one of the bundle's anchors is independently
  witnessed. `redaction.detectors` and `patterns_sha256` describe what was
  applied (`detectors` mode only).
- **Reads are bounded by the request (4.4).** Entries and slots are read
  frame by frame at their offsets (64 MiB of offsets cached across runs,
  at most 64 MiB of frames per page); verification, evidence and the
  valid prefix of a damaged journal hold whole journals only within a
  1 GiB budget shared by all of them; a list examines at most 10,000 runs
  per page and returns where to continue.
- **Limits per client (4.16).** A request's headers must arrive within
  30 s (idle kept-alive connections close after it), at most 4,096
  connections are served at once, request bodies being received share a
  1 GiB budget (at least `max_request_bytes`) and must arrive at 256 KiB/s
  after a 30 s grace. These are `server::Limits`, not configuration.
- **Console sessions** live in memory: a restart signs everyone out.
- **Webhook deliveries** waiting for a retry live in memory; the erasure
  ledger is the durable record to stream off the host. Two events were
  added: `hold` (a hold placed or removed: its id, scope and ledger seq,
  never the matter) and `access_log_failed`.

---

## 5. Evidence bundles

### 5.1 Format

A bundle is one strict-JSON file, `<run>.evidence.json`. Above 100 MiB it
becomes a directory with the journal as a separate file referenced by
`sha256`.

```json
{
  "format": "pragmatic-evidence/1",
  "generated_at": "...",
  "generator": "pragmatic-server 0.6.0",
  "requested_by": "token id",
  "run_id": "...",
  "anchor_id": null,
  "independent": true,
  "journal": { "encoding": "base64", "data": "...", "entries": 57, "head": "hex" },
  "redaction": { "mode": "none|detectors|binary|all", "detectors": [...], "patterns_sha256": "hex" },
  "redacted_slots": [[12, 0]],
  "records": [ { "cursor": 0, "at": 0, "branch": [], "kind": "Note", "fields": {}, "slots": [] } ],
  "anchors": [
    { "seq": 41, "tree_size": 9001, "leaf_index": 8990, "leaf": "hex", "inclusion_proof": ["hex"],
      "root": "hex", "checkpoint": "signed note text (body + server signature line)",
      "anchor_digest": "hex SHA-256 of the checkpoint body", "consistency_to_latest": ["hex"],
      "witnesses": [
        { "type": "rfc3161", "tsa": "url", "operator": "digicert", "token": "base64 DER", "certs_pem": "..." },
        { "type": "cosignature", "name": "witness name", "line": "— <name> <base64 keyid ‖ timestamp ‖ signature>" } ] } ],
  "latest_checkpoint": "signed note text",
  "verification_spec": { "url": "https://github.com/pragmaticco/pragmatic/blob/v0.6.0/docs/evidence-format.md", "sha256": "hex" },
  "signature": { "key_id": "hex", "public_key": "hex", "value": "hex over SHA-256 of the canonical bundle without this field" }
}
```

- Redacted slots are withheld whole (state 3, commitment only). Content is
  never altered inside a slot. A ref to a withheld slot stays a ref and
  reads as withheld.
- An `rfc3161` witness object's `operator` is the server's configured
  label, for readers only: a verifier attributes the token from the
  anchors it pins (5.2).
- `anchors` is the run's full leaf chain, from its first leaf through its
  latest in the bundle's `latest_checkpoint`, linked by `prev_leaf_index`.
- `independent` is the generator's claim that its anchors are
  independently witnessed: a server sets it only when one of the bundle's
  anchors met its independence policy. Verifiers decide from their own
  pins and ignore it.
- `leaf` is the hex of the full `leaf_data` (4.7). `anchor_id` is `null`
  with plain run ids, and the lowercase hex of the run's 32-byte key k_run
  with HMAC ids (4.7), so the verifier checks that the leaf's id equals
  `HMAC-SHA-256(anchor_id, run_id)`.
- `records` is the journal decoded for human reading (CSV and HTML
  renderers come from the console crate): one object per entry with
  `cursor, at, branch, kind, fields, slots, hash`, each slot `state,
  commitment, len, text|base64, ref` (normative layout in
  `docs/evidence-format.md` section 4).
- Every object has exactly its listed keys; an absent value is `null`
  (`anchor_id`, `latest_checkpoint`, `verification_spec` and `signature`
  may be null). A bundle built from a local journal is unsigned and
  unanchored.
- `redaction.mode` names the automatic rule the generator applied
  (`detectors` also withholds binary attachments, which detectors cannot
  inspect); slots may also be withheld on request, so `redacted_slots` is
  authoritative. `patterns_sha256` is the SHA-256 of the canonical JSON
  array of the configured patterns.
- `signature.key_id` is the 4-byte signed-note key ID of the log's
  checkpoint key, and `value` is Ed25519 over the 32-byte SHA-256 of the
  canonical bundle without `signature`.
- The directory form holds `evidence.json` and the journal file, with
  `journal` = `{"encoding": "file", "path", "sha256", "entries", "head"}`.

### 5.2 Trust policy

The verifier takes trust only from its own inputs:

- `--tsa-roots OPERATOR=FILE` (repeatable): PEM trust anchors for one TSA
  operator. The operator is required: a token counts for the operator
  whose pinned anchors verify it, never for the operator the bundle
  names, so a bundle cannot make one TSA count twice. Any certificate in
  the file is an anchor (`-partial_chain`), so an auditor can pin the CA
  that issues the operator's time-stamping certificates rather than a
  broad root.
- `--witness-key OPERATOR=VKEY` (repeatable; `OPERATOR=HEX` is accepted
  for a 32-byte cosignature key whose cosigner name is `OPERATOR`)
- `--log-key VKEY`: the log's checkpoint key, which also signs bundles
- the hosted Pragmatic Witness keys built into the CLI, with validity
  windows (an empty list until the witness launches)

Nothing in a bundle is ever a trust anchor. `certs_pem` is passed only as
untrusted intermediates. A TSA certificate must carry EKU
`id-kp-timeStamping`. `server-ed25519` is classified `operator-controlled`
and never counts as independent.

A token's operator comes from the verifier's inputs, never from the
bundle: it is the operator whose anchors verify the token. The `operator`
in a witness object is written by the server, which this verification
does not trust, so it is shown but never counted. A token that verifies
under the anchors of more than one operator counts for none of them, and
the report says so (`tsa_ambiguous`, a warning).

### 5.3 Checks (`pragmatic verify-evidence FILE`)

1. Strict JSON; unknown keys rejected. Bundle signature is verified when
   the key is pinned, otherwise reported as operator-asserted. With a log
   key pinned, a bundle that is unsigned, or signed by another key, fails
   (`bundle_signature`): only the signature covers `generator`,
   `requested_by`, `redaction` and `verification_spec`, which are shown as
   unverified claims unless it verified. (A bundle someone withheld more
   slots from is unsigned, and is verified without `--log-key`.)
2. The journal parses canonically with no trailing bytes. `entries` and
   `head` are recomputed and must match.
3. The chain verifies.
4. `redacted_slots` equals exactly the set of state 3 slots.
5. Every state 2 slot is accounted for by an `erasure` note at a later
   cursor.
6. `records` equals the decoded journal.
7. `run.start.run_id` equals `run_id` (or its HMAC form in leaves).
8. For each anchor:
   - the journal's head after `entries` equals the leaf's head;
   - `leaf` recomputes from its fields;
   - the inclusion proof reproduces `root`, using the RFC 9162 algorithm
     and its length check;
   - the checkpoint body states `tree_size` and `root`;
   - `anchor_digest` = SHA-256(body);
   - the consistency proof links to `latest_checkpoint`;
   - the leaf chain is continuous through `prev_leaf_index`.
   - The checkpoint's server signature is checked against `--log-key` if
     given, and the key that signed it must be named for the checkpoint's
     origin; otherwise it is reported as operator-asserted.
9. For each witness, classify it as `trusted`, `self-asserted` or
   `operator-controlled`:
   - `rfc3161`: for each operator's pinned anchors, run `openssl ts
     -verify -token_in -in <i>.der -digest <anchor_digest> -CAfile
     <that operator's anchors> -partial_chain -untrusted <i>.pem -attime
     <genTime + 1>`. The token is that operator's if exactly one
     operator's anchors verify it (5.2). Use a fresh 0700 temp directory,
     name the files by index, and never go through a shell. The reported
     time is genTime plus accuracy.
   - `cosignature`: verify against pinned `--witness-key` values only.
   - An anchor's reported time ("no later than") is the time at least
     `--min-operators` distinct trusted operators vouch for: each trusted
     operator's earliest witness time, and of those the k-th earliest. One
     operator alone cannot backdate an anchor.
10. **Independence:** count trusted witnesses by distinct *operator*: for
    a token, the operator step 9 attributed it to; for a cosignature, the
    operator its pinned `--witness-key` names. Operator names are
    canonicalized and mapped Entrust to Sectigo and QuoVadis EU to
    DigiCert, so pinning both brands of one company counts it once.
    - `VERIFIED` (exit 0) requires at least `--min-operators` (default 2)
      distinct trusted operators on an anchor whose `entries` equals the
      journal length.
    - `VERIFIED (PARTIAL)` (exit 2) when that is true only for a prefix
      of at least one entry. The report states the unanchored suffix
      length.
    - `UNANCHORED` (exit 3) when no anchor has enough trusted operators,
      or only anchors of 0 entries do (they commit to the genesis head
      every unkeyed journal shares, so they vouch for no content).
    - `FAILED` (exit 1) for any integrity failure, or an audit of step 11
      that was asked for and could not be completed.
11. **Full-log audit (optional):** `--log FILE` (the `leaf` of every
    leaf of an administrator's `GET /v1/anchors/log` pages, from index 0)
    verifies every leaf of the run against
    `latest_checkpoint`, which detects hidden anchors (for plain run ids;
    with `anchor_id` it fails with `log_unauditable`, 4.7).
    `--witness-log FILE` checks the bundle's tree against a witness's
    cosigned history, which detects a forked log: every history checkpoint
    must verify with a pinned key for that witness and be for the bundle's
    origin, every tree size the history and the bundle (its checkpoints,
    and with `--log` the root of every prefix of the log) both name must
    have one root, and the bundle's tree must link to the history (the
    witness cosigned the latest checkpoint, or the history's largest tree
    is one the bundle vouches for). `docs/evidence-format.md` step 11 is
    normative.
12. The bundle's text is never printed as instructions. `--explain`
    prints the verification procedure that ships with the CLI.

Every reported time comes from a signed structure. Unsigned JSON times
are informational and must equal the signed values.

Every finding has a stable code (`docs/evidence-format.md` section 9), and
all are reported, not only the first. Integrity failures make the verdict
`FAILED`. A witness that does not verify against anything pinned is
self-asserted and simply does not count (`tsa_untrusted`,
`cosignature_untrusted`), but a malformed witness, a token over another
digest, or a cosignature line from a pinned key that does not verify is a
failure. A token is `tsa_untrusted` only when OpenSSL ran the check and
reported failure; when it could not run it, the token is `tsa_unchecked`. `--log FILE` takes `{"leaves": [hex...]}`, every leaf from index
0; `--witness-log FILE` takes `{"witness", "origin", "checkpoints":
[signed note...]}`.

`docs/evidence-format.md` and a standard-library-only Python reference
verifier (`tools/verify_evidence.py`, which needs `openssl` on PATH)
implement the same checks, the reference verifier with its own pure-Python
Ed25519 (RFC 8032, with the core's acceptance rules), strict DER and
signed-note parsers, so it checks every signature and takes the same flags.

---

## 6. Python SDK 0.6

### 6.1 Runtime construction

```python
Runtime(store=None, oracle=None, *, token=None, key=None, timeout=30.0,
        require_server=False, volatile=None)          # dir= kept as a deprecated alias
```

- An explicit `store` always wins. With no `store`: `PRAGMATIC_URL`,
  otherwise `ValueError("pass a directory or set PRAGMATIC_URL")`.
- `http://` and `https://` values are server URLs. Plain `http://` is
  allowed only for loopback hosts.
- The token comes from the explicit argument or `PRAGMATIC_TOKEN`. With
  a server URL and no token: `ValueError`.
- With a server URL, an explicit `key` raises `ValueError`;
  `PRAGMATIC_JOURNAL_KEY` is ignored with a warning.
- `require_server=True` (or `PRAGMATIC_REQUIRE_SERVER=1`) makes a local
  store an error.
- With a server, the constructor calls `GET /v1/info` and `/v1/whoami`
  eagerly. It raises `PragmaticError`, naming the URL and status, for auth
  failures, an incompatible `api_version`, `journal_format` or `chain`, or
  an unreachable server.

### 6.2 Attempts, threads and the event loop

- **Thread safety.** The native `Runtime` is `#[pyclass(frozen)]`, Send
  and Sync, and shareable across threads. Rust locks are taken only
  inside `py.allow_threads` and never while calling Python.
- **Attempt ownership.** An attempt is owned by the thread that runs `run`
  (sync), or by the root task of `arun` plus the child tasks created by
  `ctx.gather`. Any other caller raises `PragmaticError("ctx used outside
  the attempt that owns it")`, checked before anything is touched (the
  next-step rule of 6.5 runs only after the check).
- **`arun`, `aresume`, `areplay`.** These run inside the caller's event
  loop: `begin`, then `await agent(ctx)`, then `finish` in a `finally`
  that also runs on `CancelledError`.
- **Persistence.** In async mode persistence runs on a dedicated
  single-thread executor, so the event loop is never blocked; sync mode
  persists inline. A step's value reaches the agent only after it is
  durable.
- **Cancellation.** Checkin is shielded from cancellation and waits for
  any in-flight persist.
- **Sync wrappers.** `run`, `resume` and `replay` on an async agent with no
  running loop use a private loop: one per thread, kept between calls so
  that an async client built once keeps its pooled connections, and never
  the thread's current loop. Each call cancels the tasks the agent left
  running, as `asyncio.run` does; a crash closes the loop. With a running
  loop they raise, pointing to `arun`.
- **Synchronous steps in async attempts.** `ctx.now()`, `ctx.uuid4()`,
  `ctx.recv()`, `ctx.patched()` and the other synchronous steps release
  their values only once durable in async attempts too: they wait for the
  attempt's executor, which stalls the loop for one persist. The awaited
  steps (`adraw`, `aeffect`, `atool`, `arun_tools`, `gather`) never block
  it. Begin, every persist and finish run on that executor, in order.
- **Ownership in practice.** For an async attempt, a thread with no running
  loop that carries the attempt's token (what `asyncio.to_thread` creates)
  is accepted; a synchronous attempt accepts its own thread only.
  Ownership failures raise `NotInRun`. A synchronous `run` whose agent
  returns an awaitable (a lambda that binds an async agent's arguments)
  drives it on a private loop whose main task becomes the attempt's root
  task: from then on the attempt is owned as an `arun` attempt is, so the
  tasks the agent creates itself are refused there too.
- **Timeouts.** `asyncio.timeout` (Python 3.11 and later) runs in the
  caller's task and is the way to time a step out; the cancelled step is a
  result (2.12). `asyncio.wait_for` runs in the caller's task from Python
  3.12, but before that it wraps the awaitable in a task of its own, and
  `asyncio.shield` always does, so a step under them is refused there
  (journaled model clients take the relaxed check of 6.5 and are
  accepted). On 3.9 and 3.10 a timeout that runs in the caller's task
  (the `async-timeout` package) serves.
- **Ending.** An exception that is not an `Exception` (`KeyboardInterrupt`,
  `SystemExit`, `CancelledError`) is a crash: the attempt is abandoned
  (2.7, rule 7). A `CancelledError` the agent caught and carried on past
  never reaches this point; the step it cancelled holds a failure result
  (2.12). Any other exception is recorded in `attempt.end` and
  propagates unchanged; one the runtime raised carries its fault, which
  `attempt.end` records, and any other is recorded as outcome `fault` with
  kind `ToolErr` (the core writes no `error` outcome yet).

### 6.3 Store protocol (Python object called by the native layer)

```python
class Store(Protocol):
    def checkout(self, run_id: str, create: bool) -> bytes: ...   # journal bytes; acquires lock/lease; starts heartbeat
    def snapshot(self, run_id: str) -> bytes: ...                 # no lock
    def persist(self, run_id: str, at: int, frames: bytes, frame_count: int, head_hex: str) -> None: ...
    def checkin(self, run_id: str) -> None: ...                   # stops heartbeat, releases lease
    def list(self) -> list[str]: ...
```

The store raises `pragmatic.Locked`, `Conflict`, `LeaseLost`, `Deleted`,
`TooLarge`, `Unavailable` or `OSError`, which map to the core faults.
`ServerStore` implements 4.4–4.6 with the standard library only:

- a persistent `http.client.HTTPSConnection` per thread with keep-alive
- connect timeout 5 s, read timeout `timeout`
- resends until `PRAGMATIC_SYNC_DEADLINE` (default 120 s) with
  exponential backoff
- reconciliation through the duplicate rule
- `Unavailable` after the deadline

Resolved while building the layer:

- A store holds each journal as whole bytes: the 16-byte header, then
  whole frames. `checkout` and `snapshot` may return `(bytes, entries,
  head_hex)` instead of bytes when the store can vouch for the length and
  head (`ServerStore` passes on the `Pragmatic-Entries` and
  `Pragmatic-Head` headers of the download). The native layer verifies the
  bytes (canonical decoding, chain, commitments) and that they end there. A
  new run's journal is the header, `pragmatic.JOURNAL_HEADER`, which the
  store writes when it creates the run. Runs in Python stores are unkeyed:
  a `key` with one is a `ValueError`, as with a server.
- Without `create`, a missing run is `FileNotFoundError`. A store sets
  `remote = True` when other processes write to it; a resume then needs an
  explicit recovery policy (2.12).
- The caller sees the exception the store raised; the mapping to a core
  fault decides only what the core does with it. `LeaseLost` is a subclass
  of `Locked`, the client action 4.4 names for `lease_lost`.
- Every request `ServerStore` makes is safe to resend: appends by the
  duplicate rule, lease requests by their holder, a `PUT` through the
  create order. A request made under a lease is resent until the earlier
  of the sync deadline and the lease deadline. Appends are split into
  requests of at most the server's `max_request_bytes`; a frame larger
  than the `max_frame_bytes` or `max_request_bytes` the server announced
  is `TooLarge` without being sent. An answer the server sent before it
  read a request's whole body (an early 413 on a connection it then
  closed) is read, never taken for a connection error.
- The renewal thread starts as soon as the lease is granted, so the lease
  is renewed while the journal downloads; the download is resent until
  the earlier of the sync and lease deadlines. Checkin stops the renewal
  thread before it releases the lease: the thread resends nothing once
  asked to stop and gives back at once any grant that still arrives, so a
  renewal can never grant a released lease again.
- An append whose resends ran out, and a duplicate answer from a run that
  has grown past the frames, are handled as 4.6 says: success when the
  run's `entries` and `head` show the frames, `LeaseLost` when another
  holder appended. Receives whose persist failed are in doubt until the
  next checkout (3.1).
- Definitive answers that 4.4 does not map to a named exception
  (`unauthorized`, `forbidden`, `invalid_frames`, `regressed`,
  `chain_broken`, `bad_request`, `not_implemented`) raise
  `pragmatic.ServerError`, a `PragmaticError` with `status`, `code` and
  `url`.

### 6.4 Branches and `ctx.gather`

```python
results = await ctx.gather(lambda c: research(c, "a"), lambda c: research(c, "b"))
```

- A context variable holds `(attempt token, branch)`. Every journaled
  step resolves its branch from it: wrapped clients, `draw`, `tool`,
  `effect`, `recv`, `now`, `random` and friends, `patched`, `gather`.
- The `c` passed to a child is the same `Ctx` object.
- If the variable is unset or belongs to another attempt, the step raises
  with a hint ("use ctx.gather or asyncio.to_thread"). `asyncio.to_thread`
  copies the context variable, so it is supported.
  `loop.run_in_executor` is not.
- Region semantics follow 2.7. Bare coroutines raise `TypeError`.
- There is no sync `ctx.parallel` in Python 0.6.

### 6.5 Journaled clients: one interception point

`ctx.wrap(client)` and `pragmatic.wrap(client)` return a genuine SDK
client: `client.copy(http_client=JournalingHttpClient(...))`, where the
journaling client subclasses `httpx2.Client` or `httpx2.AsyncClient` and
overrides `send()`. This works for Anthropic and OpenAI, sync and async.

- **Version floors:** `anthropic>=1.0` and `openai>=3.0`, the first
  releases built on `httpx2`. Older SDKs raise `Unsupported` with an
  upgrade hint.
- **Starting point:** the research prototype, since superseded by
  `crates/pragmatic-python/python/pragmatic/_http.py` and its tests.
- **Tests:** use `httpx2.MockTransport`, never httpx-patching libraries.
- **Not covered, with the documented alternative:**
  - MCP tool calls, which use the `mcp` package's own client: journal them
    with `ctx.tool`.
  - LiteLLM's own Anthropic handler and legacy-httpx SDKs.

Every HTTP exchange is a draw:

- **Request parts.** `[method ‖ path ‖ query ‖ canonical JSON of the body
  without messages and input]` plus one part per element of
  `messages`/`input` (in chunks when there are more than a record holds,
  below). Transport headers are never recorded, and neither are the
  credentials of tool and MCP server definitions. Core dedup stores
  repeated messages once.
- **Response.** The head is `{"status", "headers": allowlist}`
  (content-type, request-id headers, rate-limit headers are dropped). The
  body is the raw bytes, teed while the caller reads them. A stream
  closed early is `partial`.
- **Meta.** Extracted from the body or the final SSE event: provider,
  model, stop_reason, usage, latency.
- **What the single interception point covers.** `create`,
  `stream=True`, `.stream()` helpers, `.parse()`, `with_raw_response`,
  `with_streaming_response`, `tool_runner`, `count_tokens`, and any
  framework that uses the client: the OpenAI Agents SDK via
  `set_default_openai_client`, Pydantic AI providers, and LangChain
  through `pragmatic.integrations.langchain.journal(llm)`.
- **Journal faults inside `send()`** are raised as a `BaseException`
  carrier that SDK retry and wrapping logic cannot swallow, and are
  unwrapped to the real exception at the runtime boundary.
- **Abandoned streams.** A stream that is never iterated or closed is
  committed as `partial` by `weakref.finalize`, or at the next step its
  caller takes on that branch, or at attempt end, whichever comes first.
- **Outside an attempt.** `pragmatic.wrap(client)` routes to the current
  attempt through the context variable. Outside an attempt it raises
  `NotInRun` unless constructed with `outside="passthrough"`.
- **Unsupported transports.** Websocket and realtime transports,
  `client.post` to non-model hosts, and OpenAI clients with X.509 workload
  identity (which send every request through a transport of their own,
  never through `send()`) raise `Unsupported`; the last is refused when
  the client is wrapped.
- `attempt.end.passthrough_calls` counts calls made under
  `outside="passthrough"`.

Resolved while building the clients:

- **Part 0** is the canonical JSON (3.7 serialization) of `{"method",
  "path", "query", "headers", "body"}`: `query` as sorted `[name, value]`
  pairs, without parameters whose names contain `key`, `token`, `secret`,
  `sig`, `password`, `auth` or `credential` (gateways that take
  credentials in the URL would otherwise put them in the journal, and a
  rotated credential must not desync a replay); `headers` holding only `anthropic-version`, `anthropic-beta` and
  `openai-beta` when sent, since they select API behavior and are not
  transport headers; `body` with each `messages` or `input` list replaced
  by `{"$parts": n}`, so part 0 says which parts follow and the request can
  be rebuilt from its parts for normalization (6.6) and the desync diff.
  The parts are canonical re-encodings of the wire body, the same for the
  same call whatever order the SDK wrote the keys in. A body that is not
  JSON is recorded as a final part as sent, and part 0 carries
  `"raw_body": true`; a multipart body (a file upload, a transcription, an
  image edit) has its boundary, which the HTTP client draws at random for
  every request, replaced by `pragmatic-multipart-boundary`, which part 0
  names as `"boundary"`, so the same upload matches on replay.
- **Long conversations.** A record holds at most 255 slots (2.15). When
  the elements of `messages` and `input` do not fit one part each beside
  part 0, they are stored in chunks: JSON arrays of `g` elements, where
  `g` is the smallest power of two that fits, with the marker
  `{"$parts": n, "$chunk": g}`. Chunk boundaries depend only on the
  element index and `g`, so the earlier chunks of a growing conversation
  stay identical from call to call and are stored once.
- **Credentials in bodies.** Before a request is recorded or matched, the
  members of each element of `tools` and `mcp_servers` named
  `authorization`, `api_key`, `password`, `secret` or `token`, or ending in
  `_token`, `_secret`, `_key` or `_password`, and every value of a
  `headers` object there, are replaced by `"<credential>"` (Anthropic
  `mcp_servers[*].authorization_token`, OpenAI Responses
  `tools[*].authorization` and `tools[*].headers`). Such bearer tokens
  expire within the hour: in the journal they would leak, and a replay
  holding a fresh one would never match. A tool's input schema is never
  inspected.
- **The head's header allowlist** is `content-type`, `request-id`,
  `x-request-id`, `anthropic-workspace-id`, `retry-after`,
  `retry-after-ms` and `x-should-retry`: what the SDKs read to parse,
  identify and retry a response. On record the caller gets the headers
  replay serves, except for the retry hint replay adds to a response the
  SDK may retry (below). The body is the decoded bytes;
  `content-encoding` and `content-length` are never served.
- **Retry hints on replay.** A response the SDKs would not retry (they
  retry 408, 409, 429 and 5xx, and obey `x-should-retry`) is served as
  recorded. A retryable one is served with `retry-after-ms: 1`: both SDKs
  read that header first, and treat a hint of 0 as none at all and fall
  back to their own exponential backoff (half a second and up). The one
  exception is a hint the OpenAI SDK refused to wait for (over its
  two-minute ceiling, so it did not retry): a numeric hint is then served
  as recorded, and one given as an HTTP date, which lies in the past by
  the time of a replay, as the `retry-after-ms` it meant when the
  response arrived, which the head records as `retry_after`; refused, the
  SDK waits for nothing. The Anthropic SDK retries whatever the hint, so
  its replays always get the 1 ms hint. A transport error has no headers
  to carry a hint, so its replay waits the SDK's own backoff before the
  recorded retry.
- **Error results.** A response with a status of 400 or more is read
  whole inside `send()` (the SDK may close a retried one unread) and
  recorded with outcome `error` and its `status`. A transport error is
  recorded with `error_kind`, `error_type` (the httpx2 class) and the
  message in the body slot, and an empty head. The message is journaled
  without credentials: quoted header names and values are cut out (h11
  quotes the offending value, so an API key read from a file with its
  trailing newline would otherwise land in the journal), and so is every
  value of a request header named like a credential. Replay raises a
  `DrawFailed` that is also an instance of the recorded httpx2 class, so
  the SDK wraps and retries it as it did. A body that breaks while it is
  read keeps the bytes read, with the message as `"error"` in the head;
  replay serves the bytes, then raises the same failure.
- **Cancelled exchanges.** An async exchange whose task is cancelled
  (`asyncio.timeout`, `asyncio.wait_for`, a task group, the Agents SDK
  cancelling the model call when an input guardrail trips) is recorded as
  2.12 says: an error result with `error_kind` `cancelled`, the bytes read
  so far, appended without being persisted. Every recording is tracked
  until its result is written, non-streaming ones included, so the end of
  the attempt writes off any left open and a crash drops them. Replay
  serves the recorded bytes and then waits until the task is cancelled
  again.
- **When a stream's result is written.** At the end of the body (durable
  before the end reaches the caller); on `close()`; when the response is
  collected (`weakref.finalize`); at the next journaled step its caller
  (the thread and asyncio task that opened it) takes on its branch, for a
  stream not yet being read (a stream that is being read may stay open
  while tools run, 2.7; a step by another caller, such as a parallel
  LangGraph node on a worker thread, never writes it off); before a
  parallel region joins, for streams on its children; and before
  `attempt.end`. Whichever
  comes first writes `partial` with the bytes read so far, and from then
  on the stream reads no further, so what the agent saw on record is what
  replay serves. A close, a finalizer or the end of a region only appends
  the result: they can run inside a store's persist (a garbage collection)
  or on a thread that must not block, and the entry becomes durable with
  the next persist or the attempt's finish. A crash writes nothing: the
  intent stays dangling and resume makes the call again.
- **The carrier** is `pragmatic.JournalFault` (`.error` holds the fault).
  It carries everything a journal operation raises inside `send()` or a
  stream, store exceptions included, since an SDK would otherwise retry an
  `OSError` as a connection error. `rt.run` and the other entry points
  unwrap it, also from exception groups, and `ctx.gather` treats a child
  that raised one as failed. Code outside a run catches `JournalFault`.
- **Ownership.** A journaled client's draws take a relaxed ownership
  check: the caller's context must carry the attempt's token, whatever its
  thread or task. Frameworks call the model from tasks and worker threads
  they start from the agent's context (the Agents SDK's `run_streamed`,
  LangGraph nodes), and the core matches several open draws on one branch
  by their intents. A start issued while another in-flight draw on the
  same branch has the identical request logs a warning on the `pragmatic`
  logger.
- **Passthrough attribution.** `ctx.wrap(client, outside="passthrough")`
  sends calls made outside its attempt unrecorded and counts them in that
  attempt's `passthrough_calls` while it runs. A `pragmatic.wrap` client's
  passthrough calls happen outside every attempt and are attributed to
  none. A call made from inside a different attempt is always `NotInRun`:
  it would be missing from that attempt's record.
- **The returned client** is an instance of a subclass of the client's
  own class, with the same name, that keeps the journaling client through
  `copy()` and `with_options()` (journaling any `http_client` passed to
  them), allows requests only to the API hosts of the client and its
  copies, and (OpenAI) makes `websocket_base_url` raise `Unsupported`:
  every websocket surface (`responses.connect()`, `realtime.connect()`,
  the Agents SDK websocket transport) reads it before connecting, and its
  traffic never passes through the HTTP client.
- **LangChain.** `ChatAnthropic` offers no way to pass a client in, so
  `journal(llm)` returns a copy whose cached `_client` and `_async_client`
  are journaled; `ChatOpenAI` takes its clients as fields.

### 6.6 Normalization (volatile request fields)

Matching compares normalized request parts. The stored parts are always
the raw wire bytes. The built-in rules replace Agents SDK
`prompt_cache_key` values matching `agents-sdk:run:*` with a fixed token.
`Runtime(volatile=[...])` adds JSON-path rules. The rules are recorded in
`attempt.start.data.normalization` by name, so an auditor can see what was
loosened.

Resolved while building the clients:

- The built-in rule is named `agents-sdk:prompt_cache_key`; a volatile
  rule's name is its path. Paths apply to the request body: `$` then
  `.name`, `['name']`, `[n]`, `[*]` or `.*`; a bad path is a `ValueError`
  when the runtime is built. A matched value becomes `<volatile>`.
- "Raw wire bytes" means the parts as 6.5 encodes them, before any rule
  is applied. To match, the SDK peeks at the next recorded start on the
  branch (`Session::next_start`), rebuilds both bodies from their parts,
  normalizes both, and when they agree begins the draw with the recorded
  parts, so the core's exact comparison holds. A request no rule changes
  is matched exactly, with no peek. A desync's diff compares the
  normalized requests.

### 6.7 Other APIs

- `ctx.uuid4()`, `ctx.random()`, `ctx.randint(a, b)`, `ctx.randbytes(n)`:
  the `Random` kind.
- `ctx.now()`: Clock. `ctx.datetime()` is UTC from one Clock entry.
- `ctx.patched(name)`, `ctx.deprecate_patch(name)`.
- `@pragmatic.durable` and `@pragmatic.durable(version="2")`.
- `ctx.tool`, `ctx.atool`, `ctx.effect`, `ctx.aeffect`, `ctx.run_tools`,
  `ctx.arun_tools`. Perform functions receive `idempotency_key=` when
  their signature accepts it.
- `rt.run`, `arun`, `resume`, `aresume`, `replay` and `areplay`, with
  `budget`, `caps`, `labels`, `subjects`, `on_code_change`, and (resume
  only) `recover`. `recover` may take 2 or 4 arguments
  (`name, arg[, branch, intent_cursor]`) and may be async in `aresume`.
- Recovery policies return the result (`str` or `bytes`) or
  `pragmatic.Recover.commit(result)` to commit, `None` or
  `Recover.COMPENSATE` to compensate, and `Recover.FAIL` to fail. They are
  consulted for effects left without a result; a failed frontier effect is
  retried without asking, as Rust `resume_with` does. A policy that raises
  aborts the resume before anything is recorded (the attempt's opening
  notes and decisions are never persisted), and its exception propagates.
- `rt.verify(id) -> VerifyReport` (`__bool__` = ok). On a server the
  journal is downloaded and verified locally when the token may read it,
  and the server's cached report is returned otherwise (401, 403, 404),
  its verdict kept: a report the server calls failed (`ok: false`,
  `missing`, `damaged`) is never truthy. A journal the server knows is
  damaged (`409 chain_broken`) gives a failing report; any other refusal
  is raised.
- `rt.replay` and `rt.verify` read a server's journal without a lease:
  they need an admin token or an auditor token with `view_raw`. An agent
  token reads a journal only while it holds the run's lease (4.3), so
  replay with one raises `ServerError` naming the tokens that may.
- `rt.runs() -> list[RunSummary]` (built locally for DirBackend: no
  anchors, holds or leases, so `status` is `dangling` or `idle`, and times
  are RFC 3339 UTC).
- `rt.entries(id) -> list[dict]` in the Entry JSON shape.
- `JournalDesync` for a draw carries a diff of normalized request parts:
  the first differing JSON paths, with values shortened. The message is
  never written to a journal field.
- `pragmatic.JournalFault(BaseException)` carries a fault out of a model
  SDK (6.5); it is not a `PragmaticError`.
- Exceptions: `PragmaticError` ⊃ `JournalDesync`, `ReplayExhausted`,
  `Locked(retry_after)`, `Conflict(expected, actual)`, `LeaseLost`,
  `Deleted`, `Erased(cursor)`, `Unsupported`, `TooLarge`, `Unavailable`,
  `DanglingIntent`, `DanglingEffect`, `EffectFailed(type_name, message)`,
  `DrawFailed(type_name, message)`, `EffectUnrecorded(name, intent,
  result)`, `NotInRun`. A replayed `EffectFailed` or `DrawFailed` is also
  an instance of the recorded exception type when the program has that
  type loaded (types are looked up among loaded modules, never imported),
  with the recorded message as its `str()`.
- **Observability.** With `PRAGMATIC_OTEL=1` and `opentelemetry-api`
  importable, the SDK emits one `pragmatic.attempt` span per attempt, plus
  one child span per step: GenAI semantic conventions for draws, and
  `pragmatic.effect` for tools. Spans carry `pragmatic.run_id`, `cursor`,
  `branch` and `replayed`. Content never appears in spans, and replayed
  steps report zero usage. `attempt.start` records `traceparent` (once
  the core takes it in `RunOptions`; until then the field is null).
- `python -m pragmatic push DIR [RUN | --all]` uploads format 2 unkeyed
  local journals to a server; format 1 and keyed journals are refused,
  with an explanation, and so is a journal a server would refuse from a
  client (an erased slot, or a server-written note: a journal erased
  locally with `pragmatic erase`), checked before anything is created on
  the server. Push runs before erasing them, and erase on the server.

---

## 7. CLI 0.6 (zero dependencies)

- `runs`, `show` and `export` understand format 2: branches, regions,
  intents and results, erased, withheld and ref slots, notes, custody,
  attempts and `at` times. Format 1 is read-only.
- `verify` prints the `VerifyReport` and never writes to the file.
- `erase RUN (--cursor N [--slot K] | --match TEXT) --reason-code C
  [--reason TEXT]` works through a DirBackend checkout. Its `by` is
  `local:<os-user>@<host>` with `authenticated: false`. `--cursor` alone
  erases every slot of the entry. `reason_code` is a structural field, so
  it is limited to `[a-z0-9_.:-]{1,64}`; free text goes in `--reason`.
- `evidence RUN -o FILE [--redact none|detectors|binary|all]
  [--detectors NAME,...] [--withhold CURSOR:SLOT]...` builds a local
  bundle (unanchored unless anchors exist), in the directory form above
  100 MiB. Keyed journals are refused.
- `verify-evidence FILE [--tsa-roots OP=F]... [--witness-key OP=VKEY]...
  [--log-key VKEY]... [--min-operators N] [--log F] [--witness-log F]...
  [--openssl | --no-openssl] [--explain]`. The first `openssl` on PATH
  that can check tokens (OpenSSL whose `ts` takes `-attime`, not LibreSSL)
  is used; `--openssl` requires one, and names the unusable binary when
  there is none. A check counts as a rejected token only when OpenSSL ran
  it and reported failure. FILE may be a directory bundle, whose files are
  read only if they are regular files of a sane size (`bundle_file`).
- `render-evidence FILE --format html|csv [-o FILE]`, with the same trust
  flags (the page shows the verification report). It exits with the
  verdict's code, and never writes CSV for a bundle that fails.
- Every file the CLI writes (`-o`, and `render-evidence`'s default next to
  the bundle) is written to a fresh temporary file and renamed into place,
  and a destination that is a symbolic link or not a regular file is
  refused, so a link shipped with a bundle is never written through.
- `export RUN [--from CURSOR]` writes one page of the run (4.14) and says
  where the next starts. `serve` answers only requests whose `Host` is
  its own loopback name (`127.0.0.1`, `localhost` or `[::1]`, with its
  port or none), and refuses requests a browser marks as cross-site, so a
  web page cannot read the console by DNS rebinding.
- Error messages quote journal content (run ids, file names) and are
  printed with control characters escaped, like everything else.
- Usage errors exit 64, distinct from every verification outcome. Trust
  inputs that are malformed or cannot be read (a root, key, log or witness
  history) and a bundle path that cannot be read are usage errors.
- No secrets in argv: `--key-file` and `PRAGMATIC_JOURNAL_KEY` replace
  `--key`. `--key` remains, deprecated, with a warning.

---

## 8. Documentation deliverables

- README: the system-of-record lead plus the recovery pillar, the license
  summary, the no-telemetry statement, and no compliance claims.
- `docs/threat-model.md`
- `docs/compliance.md`: the mapping and the shared-responsibility matrix
  (TLS, NTP, volume encryption, backups, identity provider, designated
  third party under 17a-4, retention configuration)
- `docs/server.md`: install, configuration reference, tokens and scopes,
  sizing, backup and restore, upgrades
- `docs/evidence.md`: an auditor walkthrough with pinned roots
- `docs/evidence-format.md`: normative
- `docs/privacy.md`: fields vs slots, labels and subjects, redaction
  limits, DSAR and retention procedures, a DPIA template
- `docs/python.md`: wrap, gather, patching, streaming, recovery,
  frameworks
- Updates to `docs/usage.md`, `docs/quickstart.md` and
  `docs/concepts.md`, plus CHANGELOG 0.6.0

---

## 9. Verification plan

**Core**
- format 2 encode/decode and canonical rejection, covering every rule in
  2.4
- commitments, refs and dedup
- erasure, including crash injection at every step of 2.13 with defined
  outcomes
- the torn-versus-corrupt classification, and that read-only opens never
  write
- keyed flag downgrade attempts
- format 1 read-only behavior
- branches and regions: failures at different times, lowest-index error,
  reuse protection, completeness at join, identical-prompt best-of-n
- markers and `deprecate_patch`
- both `on_code_change` policies, including resumed-then-audited runs
- recovery for draws and effects (dangling, failed, frontier and
  non-frontier)
- budget under concurrency
- DirBackend locks, identity checks and collisions
- MemoryBackend double checkout
- sticky persist failure
- the RFC 6962/9162 and RFC 8032 vectors, real TSA fixtures, and the JSON
  conformance cases
- `cargo-fuzz` targets for `Journal::parse`, frame decoding, `json`,
  `tsp`, `evidence::from_json` and `ed25519` (`fuzz/`), run for at least
  10 minutes each weekly and before every release (`fuzz.yml`, which
  `release.yml` waits for)

**Python**
- every 0.5 test, ported
- the HTTP-layer journal for both SDKs, sync and async: create, stream,
  helpers, parse, raw response, early close, abandoned stream, retries
  and 4xx/5xx/transport errors
- `arun` in a running loop with 50 concurrent runs
- gather with interleavings and failures
- frameworks end to end: OpenAI Agents SDK, Pydantic AI, LangChain
  ChatAnthropic/ChatOpenAI, LangGraph
- the server store against a real `pragmatic-server` process: crash in
  one process and resume in another, lease takeover, model calls and
  tools longer than the TTL with a competing resume (no duplicate
  perform), a lost response followed by a retry, `run_deleted`,
  `payload_too_large` (`tests/e2e`, besides the mock the SDK suite runs
  against)

**Server**
- every endpoint × role × in-scope and out-of-scope
- append validation (bad chain, bad commitment, state 2/3, server-only
  notes, wrong `at`, duplicate, expired lease)
- anchoring against a local OpenSSL TSA, witness mode fork rejection, key
  rotation
- erasure, holds, retention (minimums, overlaps, races), tombstones
- an access log that fails closed
- a redaction coverage scan of every response surface with seeded
  personal data
- a backup and restore drill with erasure re-application and regression
  detection, and one with the anchoring library and a witness: the
  restored anchor log held, confirmed or continued, never forked
- the load test against 4.16, in release mode in CI (on main and before
  every release), and the build on the minimum supported Rust
- egress blocked in CI

**Evidence (adversarial)**
- a self-signed TSA
- a TSA token relabeled with another `operator` (counted by the
  verifier's anchors, not the label)
- a TSA token whose anchors are pinned for two operators (counted for
  neither, `tsa_ambiguous`)
- a swapped witness key
- an omitted anchor (caught by `--log`)
- an entries or head mismatch
- an erased slot with no note
- a withheld-slot set mismatch
- an altered `records` section
- trailing bytes
- duplicate JSON keys

Each must fail with its specific code.

**End to end**
A Python agent writes to the server, crashes, resumes on a second process,
is anchored with an OpenSSL TSA, has one message erased by `match`, is
exported, and the bundle verifies offline with pinned anchors and fails
with an unpinned root. `tests/e2e` runs this against the real binaries,
with two TSAs of different operators, a concurrent resume refused by the
lease, a tampered bundle, the access log, scopes and a restart, in CI and
with outbound network blocked; `examples/demo` narrates the same steps.

---

## 10. Deferred to 0.7

OIDC sign-in; in-process TLS; server-side OTLP export; local anchoring
from the CLI; Claude Agent SDK capture (hooks and session store);
LiteLLM's own Anthropic handler; a Pydantic AI durable-execution backend;
the TypeScript SDK; multi-replica servers; anchor ids bound to the log key
by a verifiable random function (RFC 9381 ECVRF), so that HMAC-named runs
can be audited for hidden anchors (4.7); witness records in bounded
memory (a writer that appends to a journal from its tail state, 4.8).

---

## 11. Integration decisions

The CLI and evidence, anchoring, server and Python lanes amended this
document in parallel. Where two of them stated the same rule differently,
the stricter or more secure statement was kept, and the code that differs
is brought to it when the server is wired to its components:

- **HMAC anchor ids (4.7, 5.1).** Verifiers check one relation, `id` =
  HMAC-SHA-256(`anchor_id`, run_id), with `anchor_id` the run's key
  k_run. The server derives k_run from `anchor_key` with the anchoring
  library's domain-separated HMAC (`"pragmatic/v2/anchor-salt" ‖
  run_id`), not a bare HMAC of the run id. Bundles with an `anchor_id`
  still report `anchor_id_unbound`, and their `--log` audit
  `log_unauditable`.
- **Leaf ids (4.7).** 1 to 1024 bytes everywhere: the core and reference
  verifiers refuse an empty id, as the anchoring library does.
- **Checkpoint origin (4.7).** `pragmatic/<server name>/<log id>`, fixed by
  the first key (`LogSigner::generate_log`); the server's `name` is only
  its middle component.
- **TSA trust (4.7, 5.2, 5.3).** `--tsa-roots OPERATOR=FILE` requires the
  operator (the CLI had defaulted it to the file name), every certificate
  in the file is an anchor (`-partial_chain`), and a token that verifies
  under the anchors of more than one operator counts for none
  (`tsa_ambiguous`). The server requires every TSA to name its operator
  and refuses operators that share an anchor.
- **Independence (4.7).** `min_independent_operators` is at least 1; the
  anchoring library also accepted 0, which would let the server's own
  signature advance `anchored_entries`.
- **Witnesses (4.1, 4.8).** A witness is configured by its C2SP vkey,
  which names the key and checks its id, rather than a bare public key.
  Witness mode signs cosignatures with a key of its own (`[witness_mode]
  name, key_file`), never the log key, and lists each origin's log vkeys
  so a witnessed log can rotate its key.
- **Witness record (4.8).** The server's per-origin record runs in the
  run store, with every check of the anchoring library's witness and its
  `witness.reject` notes. The anchoring library's single witness journal
  is not used by the server.
- **Key ids (4.7).** The 4-byte note key ids of checkpoints and bundle
  signatures, always next to the full public key, and the anchoring
  library's `key.rotate` record, which binds both key ids to the origin.
  The server's SHA-256 key fingerprints and rotation message give way to
  them.
- **Redaction (4.10).** The core scan finds binary fields (`b64_json`
  included, every copy of a repeated key, no nesting limit, incomplete
  slots reported) and the server's text rules apply on top (object keys
  redacted, base64 runs of 256 characters withheld from non-JSON text).
- **Anchoring lag (4.7).** The server measures it from its own runs, so it
  grows whatever stops anchoring, and lowers it only by the
  `anchored_entries` the anchoring library reports.
- **Server API for SDKs (4.4, 4.6, 6.3).** The server's shapes are the
  contract: `PUT` takes an optional `Pragmatic-Holder` and answers with
  `entries`, a lease is renewed only by the same token, entries pages are
  `{entries, next, total}` and are followed by `next`, and `chain_broken`
  and `not_implemented` are definitive errors (`ServerError` in Python).

Brought to these rules when the server was wired to its components:
the server's configuration (witnesses by vkey, witness mode's own key and
log vkeys, `anchor_key_file`), its keys (the anchoring library's
`LogSigner` and `KeyRotation`, note key ids next to full public keys, a
separate witness key), the witness record (the library's `WitnessCore`
over the run store), the witness log (its pages carry the cosigned notes,
the cosigner name and the origin line, from which the `--witness-log` file
is assembled), `hooks::Anchoring` over the library (contradicted snapshots
reported, `retry_pending` between batches) and the console (4.14).

Server views are built from `redact::binary::scan`'s text (4.10), as
evidence redaction is: a lenient re-parse only ever sees placeholders
where the binary values were.
