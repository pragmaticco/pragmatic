# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.6 (built from source; Pragmatic Server in design-partner preview) | ✅ |
| 0.5.x | ✅ |
| < 0.5 | ❌ |

## Reporting a vulnerability

Email **me@aniketh.net** with subject `SECURITY: pragmatic`. Please do not
open a public issue for security reports. You will get an acknowledgment
within 72 hours and a remediation plan or triage decision within 14 days.

## What counts as security-sensitive here

The [threat model](docs/threat-model.md) states what each component is
meant to withstand. A way to break any of the following is in scope.

**The runtime and the journal**

- **Hash-chain forgery**: any way to modify a committed journal entry (or
  reorder/splice entries) that `Journal::verify` accepts.
- **Erasure accounting bypass**: erasing content without an `erasure` note
  in a way that `Journal::audit` or the server's verification accepts, or
  erasing a run under a legal hold or, with
  `erasure = "deny_during_min"`, within its retention minimum.
- **Keyed-journal bypass**: opening or extending an HMAC-keyed journal
  without the key.
- **Replay integrity**: making strict replay (`Runtime::replay`) consult the
  live oracle, perform a durable effect, or produce a trace differing from
  the recorded run.
- **IFC bypass**: reading a `High` cell with `Low` clearance or writing
  `High`-cleared data into a `Low` cell through the `Store` API.
- **Capability bypass**: performing an effect outside a run's granted
  capability set, or exceeding a budget without `BudgetExhausted`.

**Pragmatic Server (0.6)**

- **Authentication and scope bypass**: acting without a valid token,
  beyond a token's role, or on runs outside its scopes, including learning
  that an out-of-scope run exists (such runs must answer `not_found`).
- **Append validation bypass**: the server storing an append that would
  not verify, or an agent writing erased or withheld slots or server-only
  notes.
- **Redaction leaks**: content that a redacted view withholds reaching a
  token without `view_raw`, or a salt served with redacted content.
- **Access-log bypass**: an authenticated request that is not recorded in
  the access log, or any authenticated request served after the access
  log can no longer be written (it must fail closed).
- **Anchor-log and witness forks**: the server signing two inconsistent
  checkpoints of its anchor log, or a server in witness mode cosigning a
  fork of a tree it already cosigned.

**Evidence verification (0.6)**

- **Verifier acceptance**: `pragmatic verify-evidence` or
  `tools/verify_evidence.py` reporting `VERIFIED` or `VERIFIED (PARTIAL)`
  for a forged, altered or unanchored bundle, counting a time-stamp or
  cosignature that does not verify against the pinned roots and keys, or
  passing a `--log` or `--witness-log` audit that should fail.
- **Verifier disagreement**: the two verifiers giving different verdicts
  for the same bundle and trust inputs.

## Known limitations (not vulnerabilities)

- Journals record prompts and completions **in plain text** by design:
  they are the audit trail. Encrypt the volumes and backups that hold
  them, and manage those keys yourself (see the
  [shared-responsibility matrix](docs/compliance.md#shared-responsibility-matrix)).
- The HMAC key authenticates the *runtime that wrote the log*; anyone
  holding the key can rewrite history. Key management is deliberately out
  of scope for the library.
- A server administrator with root can do what the threat model lists for
  that adversary: read all content, delete data, rewrite the unanchored
  end of a run, and, with `anchor_run_ids = "hmac"`, anchor a rewritten
  run again under a new key without any audit detecting it.
- `SeededOracle` is a test sampler, not a CSPRNG.
