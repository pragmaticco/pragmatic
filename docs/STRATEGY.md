# Product strategy

*Last revised: 2026-08-08. This document is the durable record of what
Pragmatic is betting on, so that roadmap decisions stay consistent across
releases. Change it deliberately, in a PR, with reasoning.*

## The one-sentence position

Pragmatic is the **black-box recorder for LLM agents**: crash recovery that
never re-pays for a token, and a tamper-evident journal that proves what an
agent actually did.

## The wedge (decided 2026-08)

We lead with **auditability** - tamper-evident, bit-for-bit replay of agent
runs - with **zero-token crash recovery** as the supporting economic
benefit. Rationale:

- Crash recovery alone is contestable: generic durable-execution engines
  (Temporal, Restate, Inngest, DBOS) deliver a good-enough version of it by
  caching activity outputs. We are better in kind, but the buyer feels the
  difference only at the margin.
- Auditability is not contested: no engine treats run history as an audit
  artifact (hash-chained, HMAC-keyed, exportable, replayable with the model
  provably never consulted). Teams deploying agents in regulated or
  high-stakes settings have this problem, budget for it, and no incumbent
  to displace.
- The formal results (T1 proved in the calculus; Lean mechanization still in
  progress) are the *credibility backing*
  for the audit claim - not the headline. Buyers don't purchase theorems;
  they purchase "we can answer the auditor."

The README leads with these two pains, in that order. Marketing, docs, and
demos should do the same.

## Who it's for

1. **Design partners (now):** teams running multi-step agents in production
   who have been burned by (a) a long run dying and re-billing, or (b) an
   incident review that couldn't reconstruct what the agent did. Regulated
   industries (fin-serv, health, legal) are the sharpest version of (b).
2. **Later:** platform teams standardizing how their org runs agents, once
   the hosted console exists.

## Roadmap priorities, in order

Reordered 2026-09-30. The earlier order put adapter parity first, but an
audit found two gaps that block every user before any adapter matters:
nothing was installable (the v0.4.0 release never reached PyPI or
crates.io), and the Python surface only journaled `str -> str` calls, so a
real SDK-based agent had to be rewritten to use Pragmatic. Most agents are
Python calling the Anthropic or OpenAI SDK directly; that is where
adoption is decided.

1. **Installable, and drop-in for Python agents.** Done in v0.5:
   `ctx.wrap(client)` journals the Anthropic and OpenAI SDKs (sync and
   async, Messages, Chat Completions, Responses) with no other code
   changes, and `ctx.run_tools` journals tool execution in each provider's
   format. Release publishing is wired to PyPI trusted publishing and
   crates.io. Next: streaming support, the one common call pattern still
   refused.
2. **Minimal hosted console for design partners.** The commercial layer,
   and the surface the audit buyer (not the developer) actually uses:
   journal upload/sync, a run browser built on the existing console UI,
   retention policy, PII redaction on export, alerting on chain breaks and
   dangling effects, and chain heads anchored outside the customer's
   infrastructure so tamper evidence holds against whoever holds the
   files. Ship embarrassingly small, to 2-3 design partners with a real
   compliance need; let their usage set packaging and pricing.
3. **TypeScript SDK as a first-class citizen.** The same drop-in shape
   (`ctx.wrap` over the official Anthropic/OpenAI TS SDKs), npm-installable
   with prebuilt binaries. The koffi-based Node binding is a proof of the C
   ABI, not a DX.
4. **Only then:** breadth (structured tool-use parity in the Rust
   `pragmatic-openai` adapter, more adapters, framework integrations such
   as LangGraph and the OpenAI Agents SDK, more bindings, distributed
   journals).

## What we are deliberately NOT doing

- **No new language bindings.** C++ / Java / Go / Node bindings are
  **stable, maintenance-only** as of v0.4: they track the C ABI, get bug
  fixes and CI, and do not grow new surface ahead of the core. They exist
  to prove the ABI and serve embedding use cases - not to chase every
  runtime. (Revisit only on concrete customer demand.)
- **No agent framework.** Pragmatic is the runtime under whatever framework
  the user already has. We do not ship planners, memory stores, or prompt
  tooling beyond what journaling requires.
- **No distributed journal until a customer needs it.** Single-process
  local-disk journals are the honest scope; the hosted layer changes
  operations, not semantics.
- **No benchmark-chasing.** The "Measured, not promised" table grows only
  when a claim matters to the wedge.

## Positioning FAQ

**Why not Temporal?** If you run Temporal for general workflows, keep it.
Pragmatic is for when the agent itself must be recoverable and auditable:
the model call is modeled (not an opaque cached activity), a changed agent
fails loudly at cursor 0 instead of diverging silently, and the journal is
an exportable, tamper-evident audit artifact rather than engine-internal
state. Full table in the README.

**Why Apache for the runtime and SDKs?** They are built into customers'
production agents, which is exactly where corporate open-source reviews
reject source-available licenses, and the closest free alternatives are
permissively licensed. The verifier must be free to run for auditors who
do not trust the operator. The value we charge for is the Pragmatic Server
and the hosted witness, which carry their own commercial license. The
runtime moved from BUSL-1.1 to Apache-2.0 on 2026-10-13, before its first
registry release, so no one depended on the earlier terms.

**Why zero dependencies in the core?** The runtime asks to be linked into
someone's production agent. Every transitive dependency is a reason to say
no. Adapters may carry the minimum to speak HTTPS + JSON.

## Signals that the strategy is working

- Design-partner conversations start from the audit story, not the retry
  story.
- A journal HTML export gets attached to a real incident ticket.
- The first commercial-license conversation is pulled by the hosted
  console, not pushed by us.

## Signals to revisit

- Incumbents ship first-class LLM-call modeling with audit-grade history.
- Design partners consistently ask for recovery/cost and shrug at audit -
  then the wedge order flips.
