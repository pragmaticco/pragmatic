# Pragmatic 0.6: the system of record for AI agents

Status: design, 2026-10-13. This document is the contract between the
components built for 0.6. Formats and protocols here are normative; where
code and this document disagree, one of them is a bug.

## 1. Product shape

Pragmatic records everything an AI agent does, completely, so that the
record can be trusted by someone who does not trust the operator, and so
that a crashed run can continue without repeating work.

Two pillars, in this order:

1. **System of record.** Every model call, tool call, input and clock read
   is captured by construction (the agent cannot act outside the journal).
   The record is tamper-evident, independently anchored, replayable with
   the model provably never called, erasable for privacy law without
   breaking tamper evidence, retained by policy, access-controlled, and
   exportable as an evidence bundle an auditor verifies offline.
2. **Crash recovery.** A crashed run resumes from its journal, on any
   machine, without repeating model calls or committed tool calls, with a
   single-writer guarantee.

Components:

| Component | Where | License role |
|---|---|---|
| Core runtime (journal v2, sessions, branches, storage backends, anchoring and evidence primitives) | `crates/pragmatic` (zero dependencies) | free under the BUSL grant |
| Python SDK | `crates/pragmatic-python` | free under the BUSL grant |
| CLI + console renderer | `crates/pragmatic-cli`, `crates/pragmatic-console` (zero dependencies) | free under the BUSL grant |
| Pragmatic Server (shared store, auth, anchoring, erasure, retention, redaction, access log, evidence, console, alerts) | `crates/pragmatic-server` | commercial layer |

Non-goals for 0.6: an orchestrator (workers, schedulers, timers), a hosted
multi-tenant cloud, distributed consensus, the TypeScript SDK, new language
bindings. C++/Java/Go/Node bindings keep compiling and passing their tests
and gain no new surface.

## 2. Journal format v2

### 2.1 Goals

- Content (prompts, completions, tool inputs and outputs, received
  values) can be erased after the fact while the hash chain still verifies.
- Entries carry a branch so concurrent steps replay deterministically.
- New structural events: `Fork`, `Marker`, `Note`.
- v1 journals remain readable and resumable (root branch only).

### 2.2 File layout

```
header (16 bytes):
  magic    8 bytes  "PRAGJRNL"
  version  u32 LE   2
  flags    u32 LE   bit 0 = keyed chain (HMAC-SHA-256); other bits 0
records, repeated until EOF:
  len      u32 LE   length of `record`
  record   len bytes
  hash     32 bytes chain hash of this entry
```

A torn tail (incomplete `len`, `record` or `hash`) is truncated on open,
exactly as in v1. Integers are little-endian.

### 2.3 Record encoding

```
record :=
  kind        u8
  depth       u8                     branch depth, 0..=32
  branch      depth × u32 LE         branch path; root = depth 0
  nfields     u8
  fields      nfields × (u32 LE len ‖ bytes)
  nslots      u8
  slots       nslots × slot
slot :=
  state       u8                     1 = sealed, 2 = erased
  commitment  32 bytes
  if sealed:
    salt      16 bytes
    len       u32 LE
    bytes     len bytes
```

Fields are structural metadata (names, provenance, numbers). They are never
erasable, and the documentation tells users not to put personal data in
effect names, channel names or run ids that they cannot later delete.
Slots are content and are erasable.

### 2.4 Commitments and the chain

```
commitment(slot) = SHA-256( "pragmatic/v2/slot" ‖ salt ‖ u64 LE len ‖ bytes )
skeleton(record) = record with every slot replaced by (state=1 ‖ commitment)
                   i.e. kind ‖ depth ‖ branch ‖ nfields ‖ fields ‖ nslots ‖ nslots × (0x01 ‖ commitment)
h_i              = H( h_{i-1} ‖ u64 LE cursor_i ‖ skeleton(record_i) )
h_{-1}           = 32 zero bytes
H                = SHA-256, or HMAC-SHA-256(key, ·) when flags bit 0 is set
```

The state byte in the skeleton is always `0x01`, so erasing a slot does
not change the skeleton. `salt` is 16 bytes from the operating system's
CSPRNG (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows), fresh per
slot. The salt makes low-entropy content ("yes", an account number) unguessable
from its commitment once the content and salt are erased.

`verify()` recomputes the commitment of every sealed slot, compares it with
the stored commitment, and recomputes every chain link. It reports the first
bad cursor. Erased slots are taken on their stored commitment.

### 2.5 Event kinds

| kind | tag | fields | slots |
|---|---|---|---|
| `OracleDraw` | 1 | provenance | prompt, outcome |
| `ChannelRecv` | 2 | channel | value |
| `EffectIntent` | 3 | name | arg |
| `EffectCommit` | 4 | name | result |
| `EffectCompensated` | 5 | name | (none) |
| `Clock` | 6 | nanos (8 bytes, u64 LE) | (none) |
| `Program` | 7 | name, hash | (none) |
| `Fork` | 8 | children (4 bytes, u32 LE) | (none) |
| `Marker` | 9 | name | (none) |
| `Note` | 10 | kind, data | zero or one payload slot |

Unknown kinds fail to open (`InvalidData`), never silently skip.

### 2.6 Branches

A branch is a path of `u32`. The root branch is the empty path. The meta
branch is `[0xFFFF_FFFF]` and holds only `Note` events; program replay
never reads it.

`fork(n)` on branch `b` appends `Fork{children: n}` on `b` and returns the
child branches `b ‖ 0 … b ‖ n-1`. Branch ids are derived from program
structure, never from timing, so they are the same on record and replay.

Replay is per branch: on open, the journal is indexed as
`branch -> [cursors in order]`, and each branch keeps its own read
position. Recording appends with the branch tag in whatever order steps
complete. Cursor (global position) remains the chain key. Two branches may
interleave arbitrarily in the file; each branch's own sequence is what
replay checks. This generalizes v1's data-independent cursor keys to
(branch, per-branch index) keys, which are equally data-independent.

On replay, `Fork{children: n}` must match the requested `n`, otherwise
`JournalDesync`.

Budget (model-call limit) is shared by all branches of an attempt.
Capabilities apply to all branches. At most one split-phase step may be
open per branch at a time.

### 2.7 Markers (code patching)

`patched(name) -> bool` on branch `b`:

- recording (journal for `b` exhausted, not strict): append `Marker{name}`,
  return `true`;
- replaying, and the next entry on `b` is `Marker{name}`: consume it,
  return `true`;
- replaying, and the next entry on `b` is anything else (or a different
  marker): consume nothing, return `false`;
- strict replay past the end of `b`: `ReplayExhausted`.

This lets new code take a new path while runs recorded before the change
replay down the old path.

### 2.8 Program identity and code changes

`Program{name, hash}` is still emitted at the root by `durable`. `hash` is
the explicit version string when the user supplies one
(`@durable(version="2")`), otherwise the source hash.

`RunOptions.on_program_change`:

- `Refuse` (default for `replay`): a mismatch is `JournalDesync` at that
  cursor, as in v1.
- `Continue` (default for `resume` and `run`): the mismatch is accepted;
  in recording modes a `Note{kind: "program.change", data: {"from": old,
  "to": new, "cursor": c}}` is appended on the meta branch, and the
  report's `program_changed` is set. Every later step is still checked
  against the journal, so a change that alters any recorded request fails
  at that step.

### 2.9 Notes

Notes live on the meta branch only. Defined kinds (data is compact JSON,
never personal data; any personal content goes in the payload slot):

| kind | data | payload slot |
|---|---|---|
| `run.start` | `{"sdk": "...", "sdk_version": "...", "format": 2}` | none |
| `attempt.start` | `{"mode": "run"\|"resume", "attempt": n, "sdk": "...", "sdk_version": "..."}` | none |
| `attempt.end` | `{"attempt": n, "outcome": "ok"\|"fault"\|"error", "fault": "...", "fresh": n, "replayed": n}` | the output (on ok) |
| `program.change` | `{"from": "...", "to": "...", "cursor": n}` | none |
| `erasure` | `{"slots": [[cursor, slot], ...], "by": "...", "reason_code": "..."}` | free-text reason (erasable) |
| `recovery` | `{"cursor": n, "name": "...", "decision": "commit"\|"compensate"}` | none |

Strict replay never appends anything. `run.start` is the first entry of
every new v2 journal. `attempt.start`/`attempt.end` bracket every `run` and
`resume` attempt.

### 2.10 Erasure

Erasure replaces a slot's salt and bytes with state `2` (the commitment
stays), rewrites the journal file atomically (write a temp file in the same
directory, fsync, rename, fsync the directory), and appends an `erasure`
note listing the erased slots. The chain verifies before and after.
`verify()` additionally reports every erased slot not listed by a later
`erasure` note as an *unaccounted erasure*; that is how silent deletion is
detected. Replay that needs erased content fails with `Fault::Erased{cursor}`.

v1 journals cannot be erased (their chain hashes content directly).

### 2.11 v1 compatibility

v1 files open, verify, replay and resume. Appends to a v1 journal are
written in v1 encoding, root branch only; `fork`, `patched`, notes and
erasure on a v1 journal fail with a clear `Fault::Unsupported` message.
New journals are always v2. Migration would change chain heads and is not
offered.

## 3. Sessions, contexts and storage (core)

### 3.1 Session

All per-attempt state moves into an owned `Session`: the checked-out
`Journal`, mode (record, resume, strict replay), the branch index and
per-branch positions, budget, capabilities, inbox, trace, counters, open
split-phase steps per branch, and options. Every primitive takes the
branch it acts on:

```rust
impl Session {
    pub fn oracle_replay(&mut self, b: &Branch, prompt: &Value) -> Result<Option<Value>, Fault>;
    pub fn oracle_commit(&mut self, b: &Branch, prompt: Value, outcome: Value, provenance: String) -> Result<Value, Fault>;
    pub fn effect_replay(&mut self, b: &Branch, name: &str, arg: &Value) -> Result<Option<Value>, Fault>;
    pub fn effect_begin(&mut self, b: &Branch, name: &str, arg: Value) -> Result<(), Fault>;
    pub fn effect_commit(&mut self, b: &Branch, name: &str, result: Value) -> Result<Value, Fault>;
    pub fn recv(&mut self, b: &Branch, channel: &str) -> Result<Value, Fault>;
    pub fn now(&mut self, b: &Branch) -> Result<u64, Fault>;
    pub fn program_marker(&mut self, name: &str, hash: &str) -> Result<(), Fault>; // root
    pub fn fork(&mut self, b: &Branch, n: u32) -> Result<Vec<Branch>, Fault>;
    pub fn patched(&mut self, b: &Branch, name: &str) -> Result<bool, Fault>;
    pub fn is_replaying(&self, b: &Branch) -> bool;
    pub fn entry(&self, cursor: Cursor) -> Option<&Entry>;
}
```

`Ctx<'a>` becomes `{ session: &'a mut Session, branch: Branch }` and keeps
its current public methods (they delegate with its branch). New:
`Ctx::parallel(n, |i, ctx| ...)`, which forks and runs the children one
after another on the same session (deterministic; sync Rust has no
concurrency here). `AsyncCtx` holds `&RefCell<Session>` plus a branch and
never holds the borrow across an `.await`; `AsyncCtx::parallel` drives the
children's futures concurrently with a zero-dependency join.

Trace labels are collected per attempt and sorted by cursor in the report,
so record and replay produce identical traces even when branches interleave
differently.

`RunReport` gains `program_changed: Option<(String, String)>`.

### 3.2 Backends and sinks

```rust
pub trait Backend: Send {
    /// Load (and lock for writing) the run's journal, creating it if asked.
    fn checkout(&mut self, run_id: &str, create: bool, key: Option<&[u8]>) -> Result<Journal, Fault>;
    /// Return a journal after an attempt; releases the write lock.
    fn checkin(&mut self, run_id: &str, journal: Journal) -> Result<(), Fault>;
    fn list(&mut self) -> Result<Vec<String>, Fault>;
}

pub trait Sink: Send {
    /// Durably persist `frames` (complete `len ‖ record ‖ hash` frames) that
    /// extend the stored journal from entry count `at`.
    fn persist(&mut self, at: u64, frames: &[u8]) -> Result<(), SinkError>;
    /// Atomically replace the whole stored journal (erasure only).
    fn rewrite(&mut self, file: &[u8]) -> Result<(), SinkError>;
}

pub enum SinkError { Io(std::io::Error), Conflict { expected: u64, actual: u64 }, Locked(String) }
```

`Journal::parse(bytes, key)` returns entries and the torn length;
`Journal::from_parts(entries, format, key, sink)` builds a journal over any
sink. Appends buffer framed bytes in memory; `sync()` hands everything
since the last sync to `Sink::persist` with the entry count persisted so
far. Every journaled step still syncs before returning, and effect intents
sync before the effect runs.

Built-in backends:

- `MemoryBackend`: journals live in a map; checkout moves out, checkin
  moves back.
- `DirBackend`: one file per run, `<dir>/<safe-run-id>.journal` (same
  safe-name rule as v1). Checkout takes an exclusive `File::try_lock` on
  the journal file for the duration of the attempt (`Fault::Locked` if
  held). The workspace `rust-version` becomes 1.89.

`Runtime::with_backend(backend, oracle)` and
`AsyncRuntime::with_backend(...)` accept any backend; `in_memory` and
`on_dir` keep working. Runtimes check journals out per attempt and check
them back in when the attempt ends (so locks are held only while a run is
executing). `Runtime::journal(run_id)` returns an owned snapshot for
inspection.

New faults: `Erased { cursor }`, `Locked(String)`, `Conflict { expected,
actual }`, `Unsupported(String)`.

### 3.3 Pure modules (core, zero dependencies)

- `rand`: `fill(&mut [u8])` from the OS CSPRNG.
- `merkle`: RFC 6962 Merkle tree hash with `0x00` leaf and `0x01` node
  prefixes; audit (inclusion) paths, verification, and consistency proofs.
- `tsp`: RFC 3161. Build a DER `TimeStampReq` for a SHA-256 digest with a
  64-bit nonce and `certReq = true`; parse a `TimeStampResp` (status,
  token bytes) and the `TSTInfo` inside the token (policy, message
  imprint algorithm and digest, serial number, `genTime`, nonce, TSA
  name if present). No signature verification (that is OpenSSL's job and
  the server's); the parser must reject malformed DER rather than panic.
- `json`: a minimal JSON value type with a strict parser and a compact
  serializer, enough for notes and evidence bundles.
- `redact`: zero-dependency detectors for emails, phone numbers, US SSNs,
  payment card numbers (Luhn-checked), IBANs, IPv4 addresses and common
  secret formats (API key prefixes, AWS access keys, bearer tokens, PEM
  private keys); `redact(text, detectors) -> (String, Vec<Match>)` with
  replacements like `[email]`.
- `evidence`: the bundle format of section 5, `to_json`/`from_json`, and
  `verify(bundle) -> EvidenceReport`.

## 4. Pragmatic Server

### 4.1 Process

`pragmatic-server --config pragmatic.toml` (plus `token new`,
`keygen`, `verify-data` subcommands). Rust, axum on tokio. TLS is
terminated by the deployment's proxy or ingress; the server listens on
plain HTTP and refuses to start on a non-loopback address without
`allow_plain_http = true` or a `tls` section (rustls) in the config.

### 4.2 Storage

```
<data_dir>/
  runs/<2-hex shard of SHA-256(run_id)>/<safe-run-id>.journal   (journal v2, unkeyed)
  runs/.../<safe-run-id>.meta.json                              (created_at, holds, last lease holder)
  anchors/<batch-id>.json                                       (one file per anchored batch)
  audit/access.journal                                          (the server's own access log, journal v2)
  keys/server.ed25519                                           (signing key, 0600)
```

Server-stored runs use unkeyed SHA-256 chains; their integrity comes from
append-only storage, the access log, and independent anchoring. An index
(run id → entries, head, timestamps, status, erased-slot count, anchored
length) is rebuilt by scanning at startup and kept current on every write.

### 4.3 Auth

Bearer tokens. The config stores `SHA-256(token)` only; comparison is
constant-time. Roles:

| role | may |
|---|---|
| `agent` | create runs, lease, append, read journals (for resume), read run summaries |
| `auditor` | list and read runs (redacted unless the token has `view_raw`), verify, download evidence bundles, read anchors |
| `admin` | everything, plus erase, holds, retention runs, the access log |

The console uses the same tokens: signing in exchanges a token for a
session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` when served over
HTTPS, 12-hour lifetime).

### 4.4 HTTP API v1

All paths under `/v1`. All requests need `Authorization: Bearer <token>`.
Errors are `{"error": {"code": "...", "message": "..."}}` with these codes:
`unauthorized` 401, `forbidden` 403, `not_found` 404, `run_exists` 409,
`run_locked` 409, `conflict` 409, `invalid_frames` 422, `on_hold` 409,
`bad_request` 400.

| method and path | role | behavior |
|---|---|---|
| `GET /v1/info` | any | `{"server": "pragmatic-server", "version": "0.6.0", "journal_format": 2, "chain": "sha256", "lease_ttl_secs": 60}` |
| `GET /v1/runs?prefix=&q=&status=&limit=&after=` | any | `{"runs": [RunSummary], "next": cursor-or-null}` |
| `GET /v1/runs/{id}` | any | `RunSummary` plus `{"verify": {"ok": bool, "first_bad": n\|null, "unaccounted_erasures": [...]}}` |
| `GET /v1/runs/{id}/entries?from=&limit=` | any | entries as JSON, content redacted unless the token may view raw |
| `GET /v1/runs/{id}/journal` | agent, admin, auditor+view_raw | the journal file bytes, `Content-Type: application/vnd.pragmatic.journal`, header `Pragmatic-Entries` |
| `PUT /v1/runs/{id}` | agent, admin | body: the 16-byte v2 header with flags 0. 201, or `run_exists` |
| `POST /v1/runs/{id}/lease` | agent, admin | `{"lease": "<opaque>", "ttl_secs": 60}` or `run_locked` |
| `DELETE /v1/runs/{id}/lease` | agent, admin | header `Pragmatic-Lease`; 204 |
| `POST /v1/runs/{id}/frames?at=N` | agent, admin | header `Pragmatic-Lease`; body `application/vnd.pragmatic.frames` (concatenated frames). 200 `{"entries": n, "head": "hex"}` |
| `GET /v1/runs/{id}/evidence?redact=` | auditor, admin | evidence bundle (section 5) |
| `POST /v1/runs/{id}/erase` | admin | `{"slots": [[cursor, slot], ...] \| "all", "reason": "...", "reason_code": "..."}` → `{"erased": [[c, s], ...], "note_cursor": n}` |
| `POST /v1/runs/{id}/hold`, `DELETE /v1/runs/{id}/hold` | admin | legal hold on/off (blocks erasure and retention) |
| `GET /v1/anchors?limit=&after=` and `GET /v1/anchors/{batch}` | auditor, admin | anchored batches with witnesses |
| `GET /v1/audit?after=&limit=` | admin | access log entries |
| `POST /v1/witness` | witness clients | witness mode only, see 4.8 |
| `GET /healthz`, `GET /metrics` | none | liveness; Prometheus text |

`RunSummary` = `{"run_id", "entries", "head", "created_at", "updated_at",
"status": "active"|"idle"|"dangling", "erased_slots", "anchored_entries",
"hold", "last_outcome": "ok"|"fault"|"error"|null}`. Times are RFC 3339 UTC.

**Append rules.** `POST .../frames` requires a live lease held by the
caller's lease id. `at` must equal the current entry count, else `conflict`
with `{"entries": current}`. The server decodes every frame, checks sealed
commitments, recomputes every chain link from its current head, rejects
unknown kinds and keyed chains, appends, fsyncs, and renews the lease. A
retried request whose frames were already applied gets `conflict`; the
client then reads `GET /v1/runs/{id}` and treats `entries == at + k` with
the expected head as success.

**Leases.** One live lease per run. A lease expires `lease_ttl_secs` after
its last successful append or lease call, so a crashed worker's run can be
resumed elsewhere after at most one TTL. Compare-and-append (`at`) keeps the
journal single-writer even if two leases ever overlapped.

### 4.5 Anchoring

Every `interval_secs` (default 60) the server collects each run whose head
changed since its last anchored state, plus the access log, and builds a
batch:

```
leaf_data = "pragmatic/v2/leaf" ‖ u32 LE len(run_id) ‖ run_id ‖ u64 LE entries ‖ head
leaf hash = SHA-256(0x00 ‖ leaf_data)         (RFC 6962)
root      = RFC 6962 Merkle tree hash over leaves sorted by run_id
```

The root is sent to every configured witness:

- `rfc3161`: one or more TSA URLs. The request's message imprint is
  SHA-256 with `hashedMessage = root`. The token (DER) and the TSA's
  certificate chain (PEM, from config or the token) are stored.
- `server-ed25519`: always on. Signs `"pragmatic/v2/batch" ‖ batch_id ‖
  root ‖ u64 LE unix_seconds`.
- `file`: appends `batch_id root unix_seconds` lines to a configured path
  (for WORM mounts).
- `witness`: another Pragmatic Server in witness mode (4.8), such as the
  hosted Pragmatic Witness.

A batch is stored as `anchors/<batch-id>.json` with its leaves, root and
witness results. A witness failure is recorded and alerted; the batch is
retried on the next interval.

### 4.6 Erasure, holds, retention, redaction

- Erasure (admin API) takes the run's lease, erases the slots, appends the
  `erasure` note, and is recorded in the access log with the reason code.
  Runs on hold refuse.
- Retention policies match run-id prefixes:
  `{prefix, shred_after_days, delete_after_days}`. Shred erases every
  content slot (the skeleton, chain and anchors remain, so the run's
  existence and integrity stay provable). Delete removes the journal file;
  its anchored leaves still prove what existed. Holds suspend both.
  Retention runs hourly and on demand.
- Redaction is applied when serving content to tokens without `view_raw`:
  the core `redact` detectors plus custom regular expressions from config.
  Redaction is a view, never a write.

### 4.7 Access log and alerts

Every authenticated request appends a note to `audit/access.journal`:
`{"token": name, "role": role, "method", "path", "run_id", "status",
"at"}`. Bodies are never logged. The access log is anchored with every
batch.

Webhooks (`POST` JSON) fire on `chain_broken`, `dangling_effect` (an
intent older than `dangling_after_secs` with no live lease),
`anchor_failed`, `erasure`, `retention`.

### 4.8 Witness mode

`[witness] enabled = true` exposes `POST /v1/witness` with body
`{"root": "hex", "batch_id": "...", "origin": "..."}`. The witness appends
the request to its own journal (so its log is itself tamper-evident and
anchored to its own TSAs), signs `"pragmatic/v2/witness" ‖ origin ‖
batch_id ‖ root ‖ u64 LE unix_seconds` with its Ed25519 key, and returns
`{"witness": name, "signed_at": rfc3339, "public_key": hex, "signature":
hex, "log_entry": n}`. Pragmatic Research runs the hosted witness with this
same binary.

### 4.9 Console

Server-rendered HTML with the shared `pragmatic-console` renderer: sign-in,
run list with search and filters, run timeline (branches, erased slots,
notes, attempts), verification and anchor status, evidence download,
erasure and holds (admin), access log (admin), retention status.

### 4.10 Deployment

`Dockerfile` (multi-stage, non-root, read-only root filesystem, data at
`/var/lib/pragmatic`), `deploy/docker-compose.yml`,
`deploy/kubernetes/` (StatefulSet with a PersistentVolumeClaim, Service,
example Ingress), a systemd unit, and `deploy/pragmatic.example.toml`.

## 5. Evidence bundles

One JSON file per run, `<run-id>.evidence.json`:

```json
{
  "format": "pragmatic-evidence/1",
  "generated_at": "2026-10-13T12:00:00Z",
  "generator": "pragmatic-server 0.6.0",
  "run_id": "research-42",
  "journal": { "encoding": "base64", "data": "...", "entries": 57, "head": "hex", "keyed": false },
  "redacted_slots": [[12, 0], [12, 1]],
  "anchors": [
    {
      "batch_id": "2026-10-13T11:59:00Z-0007",
      "anchored_at": "2026-10-13T11:59:01Z",
      "entries": 57, "head": "hex",
      "leaf_index": 3, "tree_size": 41,
      "inclusion_proof": ["hex", "..."],
      "root": "hex",
      "witnesses": [
        { "type": "rfc3161", "tsa": "https://freetsa.org/tsr", "token": "base64 DER", "gen_time": "...", "chain_pem": "-----BEGIN CERTIFICATE-----..." },
        { "type": "server-ed25519", "public_key": "hex", "signature": "hex", "signed_unix": 1791900000 },
        { "type": "witness", "witness": "pragmatic-witness", "public_key": "hex", "signature": "hex", "signed_at": "...", "log_entry": 9 }
      ]
    }
  ],
  "instructions": "How to verify this bundle without Pragmatic software: ..."
}
```

`redacted_slots` lists slots whose content was removed for this export
only; they verify by commitment like erased slots and are not counted as
unaccounted erasures. Every anchor proves the journal prefix of `entries`
entries had head `head` no later than the witness time.

`pragmatic verify-evidence <file>` (CLI, zero dependencies) checks: the
journal parses and its chain verifies; every erased slot is accounted for by
an `erasure` note or listed in `redacted_slots`; for each anchor, the head
at `entries` matches, the leaf hash and inclusion proof reproduce `root`,
and each RFC 3161 token's message imprint equals `root` and its nonce and
time parse. Signature verification of tokens is delegated to OpenSSL:
`--openssl` writes each token and chain to a temp dir and runs
`openssl ts -verify -digest <root> -in <token> -CAfile <chain>`, and the
bundle's `instructions` spell out the same commands for an auditor. Ed25519
signatures are verified by `pragmatic-server verify-evidence` and the
Python SDK.

## 6. Python SDK 0.6

```python
rt = pragmatic.Runtime("./journals")                               # local directory
rt = pragmatic.Runtime("https://pragmatic.corp", token="...")      # Pragmatic Server
# or PRAGMATIC_URL / PRAGMATIC_TOKEN in the environment

rt.run(run_id, agent)                      # sync; async agents run on a private loop
await rt.arun(run_id, agent)               # inside an existing event loop (FastAPI)
rt.resume / await rt.aresume(run_id, agent, recover=None, on_code_change="continue")
rt.replay / await rt.areplay(run_id, agent, allow_code_change=False)
rt.verify(run_id) / rt.runs() / rt.entries(run_id)

results = await ctx.gather(lambda c: a(c), lambda c: b(c))         # parallel branches
results = ctx.parallel(lambda c: a(c), lambda c: b(c))             # sync, one after another
if ctx.patched("use-new-prompt"): ...
ctx.uuid4(); ctx.random(); ctx.randint(a, b); ctx.now(); ctx.datetime()
@pragmatic.durable(version="2")
```

- `Runtime` is safe to share across threads (internally locked); attempts
  are confined to the task that started them.
- A client wrapped with `ctx.wrap` routes each call to the branch of the
  task that makes it (a context variable set by `ctx.gather`), so one
  wrapped client works inside parallel branches. Concurrent journaled
  steps on the same branch are still refused with a message pointing at
  `ctx.gather`.
- `JournalDesync` for a model call carries a readable diff of the
  recorded and new request (the first differing JSON paths, values
  shortened).
- New exceptions: `Locked`, `Conflict`, `Erased`, `Unsupported`, all
  subclasses of `PragmaticError`.
- The server store speaks section 4.4: lease on checkout, `GET` the
  journal, `PUT` the header for a new run, `POST` frames on every sync,
  release the lease on checkin, using only the standard library
  (`urllib`, `ssl`).
- Streaming (`stream=True`, `.stream()` helpers) and `.parse()` are
  journaled: the raw server-sent events are recorded as the outcome and
  replayed through the SDK's own stream classes, so callers receive the
  same objects. A stream closed early journals the events consumed so far.
- Framework integrations are documented and tested where the framework
  accepts an injected SDK client (OpenAI Agents SDK, Pydantic AI,
  LangChain chat models).

## 7. CLI 0.6

New and updated commands (zero dependencies): `runs`, `show` and `export`
understand v2 (branches, erased slots, notes, attempts); `verify` reports
unaccounted erasures; `erase RUN --cursor N [--slot K] --reason-code C`;
`anchor RUN --tsa URL` (local RFC 3161 anchoring over HTTP, storing
`<run>.anchors.json` next to the journal); `evidence RUN -o FILE` (local
bundle); `verify-evidence FILE [--openssl]`; `push --server URL --token T
[RUN|--all]` (upload local journals to a server).

## 8. Verification plan

- Core: unit tests for v2 encode/decode, commitments, erasure (chain still
  verifies, unaccounted erasures detected), torn tails, v1 compatibility
  (open, verify, replay, resume a v1 journal), branches (interleaved
  record, per-branch replay, fork mismatch), markers, program-change
  policies, file locks, sink conflicts, merkle (RFC 6962 vectors), tsp
  (real TSA responses as fixtures), redact, json, evidence. The existing
  E1/E2/E3 suites keep passing, and E1/E2 gain branch-interleaving
  variants.
- Python: existing tests plus `arun` inside a running loop, `gather`
  record/crash/resume/replay with interleavings, patched, code-change
  policies, desync diffs, streaming for both SDKs (sync and async, helpers,
  early close), server store against a real `pragmatic-server` process
  (crash in one process, resume in another, lease conflict, retry after a
  lost response).
- Server: API tests per endpoint and role, append validation (bad chain,
  bad commitment, wrong `at`, expired lease), anchoring against a local
  OpenSSL TSA, erasure and retention, access log, evidence round trip
  through `pragmatic verify-evidence --openssl`.
- End to end: a Python agent writes to the server, crashes, resumes on a
  second process, is anchored, has one slot erased, exports evidence, and
  the bundle verifies offline.
