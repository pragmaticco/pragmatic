# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.6 (design-partner preview) | ✅ |
| 0.5.x | ✅ |
| < 0.5 | ❌ |

## Reporting a vulnerability

Email **me@aniketh.net** with subject `SECURITY: pragmatic`. Please do not
open a public issue for security reports. You will get an acknowledgment
within 72 hours and a remediation plan or triage decision within 14 days.

## What counts as security-sensitive here

- **Hash-chain forgery**: any way to modify a committed journal entry (or
  reorder/splice entries) that `Journal::verify` accepts.
- **Keyed-journal bypass**: opening or extending an HMAC-keyed journal
  without the key.
- **Replay integrity**: making strict replay (`Runtime::replay`) consult the
  live oracle, perform a durable effect, or produce a trace differing from
  the recorded run.
- **IFC bypass**: reading a `High` cell with `Low` clearance or writing
  `High`-cleared data into a `Low` cell through the `Store` API.
- **Capability bypass**: performing an effect outside a run's granted
  capability set, or exceeding a budget without `BudgetExhausted`.

## Known limitations (not vulnerabilities)

- Journals record prompts and completions **in plaintext** by design - they
  are the audit trail. Protect journal files with filesystem/storage
  controls; encryption at rest is on the roadmap.
- The HMAC key authenticates the *runtime that wrote the log*; anyone
  holding the key can rewrite history. Key management is deliberately out
  of scope for the library.
- `SeededOracle` is a test sampler, not a CSPRNG.
