# Product strategy

*Last revised: 2026-10-13. This document is the durable record of what
Stet is betting on, so that roadmap decisions stay consistent across
releases. Change it deliberately, in a pull request, with reasoning.*

## The one-sentence position

Stet is the **system of record for AI agents**: every model call,
tool call, input and clock read an agent makes through Stet's
journaled interfaces is recorded before its result reaches the agent, in
a tamper-evident journal that can be anchored with independent timestamp
authorities, replayed exactly with the model never called, erased for
privacy law while the rest still verifies, retained by policy,
access-controlled and attributed, and exported as an evidence bundle an
auditor verifies offline against trust roots of their own choosing.

**Crash recovery stays a first-class pillar:** a crashed run resumes from
its journal on any machine without repeating model calls or committed
tool calls.

## The pivot (decided 2026-10-13)

The August 2026 wedge was "auditability first, zero-token crash recovery
second". We keep that order and make it sharper. We lead with the system
of record, meaning a complete, checkable record that a party outside
engineering can rely on, and we keep crash recovery as the second pillar.

Why:

- **Crash recovery alone is well served.** Durable-execution engines
  (Temporal, DBOS, Inngest, the durable backends of agent frameworks)
  already recover workflows. Our recovery differs in kind (the model call
  is modeled, not an opaque cached activity), but recovery is not what an
  auditor asks about.
- **Tamper evidence alone is a building block.** A hash chain is not a
  product on its own.
- **The combination is the product:**
  1. capture that cannot skip a call made through the journaled
     interfaces (a result reaches the agent only after it is recorded);
  2. exact replay with the model never called;
  3. erasure for privacy law that keeps the proof for everything else;
  4. anchoring with independent timestamp authorities and witnesses;
  5. evidence bundles that an auditor verifies offline, trusting only
     roots they chose.
- **Observability tools are partners, not rivals.** Tracing tools such as
  Langfuse, LangSmith and Datadog keep traces in editable databases, with
  retention set by a hosted plan or by the operator's own configuration.
  Teams already use them. We sit beside them as the record that holds up
  to an outsider.
- **The formal results are credibility, not the headline.** T1 (replay
  soundness, proved on paper) backs the replay claim. Buyers buy "we can
  answer the auditor", not theorems.

### A precondition we hold ourselves to

We do not market completeness until it is true for the clients people
actually use. 0.5's `ctx.wrap` proxy does not see every path a framework
can take (for example some LangChain calls, raw responses and the
Anthropic tool runner), and it refuses streaming. 0.6 journals at the SDK's
HTTP layer, which closes those gaps for the Anthropic and OpenAI SDKs.
Until 0.6 ships, our materials say what is and is not captured.

## Who it is for

The deciding test: **someone outside engineering will ask the customer to
prove what the agent did.** That someone may be a customer's security
review, an auditor, an insurer, a regulator or a court.

1. **First: AI-agent startups selling to regulated enterprises.** Series A
   to C companies in fintech, insurtech, healthtech and legaltech, whose
   bank, insurer or hospital customers ask for agent audit trails. The
   trigger is a security questionnaire with an AI section, or a customer
   disputing what an agent did.
2. **Next: the head of AI platform at a regulated company.** Regional
   banks, broker-dealers, insurers and fintech lenders. The trigger is
   internal audit or compliance blocking a launch until agent runs can be
   reconstructed, or examiners asking questions. They need self-hosting,
   single sign-on, roles, retention, erasure and contract terms for EU
   financial rules (DORA). Crash recovery is a bonus for them.
3. **Also: the chief compliance officer or head of AI governance,** who
   needs evidence bundles, access logs, legal hold and retention.

**The first customer runs** AI agents in production, in Python, on the
Anthropic or OpenAI SDKs, and the agents take actions that matter:
moving money, deciding identity or anti-money-laundering cases, handling
claims or underwriting, clinical steps such as prior authorization, legal
filings.

**Three questions that show whether Stet fits:**

1. Does the agent take actions, or does it only answer questions?
2. Does someone outside engineering review what it does?
3. Could they reconstruct exactly what happened in one specific run today?

**Not the focus:** teams that only run chatbots, and hobby users (the
open-source runtime serves them).

## Why now

- Customers' vendor questionnaires now include AI sections, and insurance
  regulators expect insurers to oversee the AI systems they buy from
  vendors (for example, the NAIC model bulletin on insurers' use of AI).
- As agents take actions that matter, we expect examiners, auditors and
  courts to ask for records of what they did.
- The EU AI Act asks high-risk systems to keep automatic logs. Under the
  AI Omnibus those obligations apply from 2 December 2027. That is a
  reason for buyers to budget in 2027, not a reason to buy in 2026.
- **No law requires outside anchoring of AI logs.** Anchoring makes
  evidence stronger and catches insiders who edit logs. It is not a legal
  checkbox, and we never present it as one. The mapping to specific rules
  is in [compliance.md](compliance.md).

## Open core

- **Open source, Apache 2.0 (from release 0.5):** the runtime, the Python
  SDK, the Rust crates and bindings, the CLI, the journal format, the
  offline verifier and the console views. They are built into customers'
  production agents, which is exactly where corporate open-source reviews
  reject source-available licenses, and the closest free alternatives are
  permissively licensed. Our promise is "verify without trusting us", so
  auditors and their clients must be able to run the verifier freely.
- **Commercial: Stet Server.** The shared journal store, independent
  anchoring, retention, erasure, roles, the access log, evidence bundles
  and the console. Its source is public under the Business Source License
  1.1 so auditors can read it; production use needs a commercial license,
  and each version becomes Apache 2.0 four years after release. It is
  self-hosted: we are a software supplier, and customers' prompts and
  outputs never reach us. There is no license enforcement in code.
- **Planned: a hosted independent witness.** Run by Pragmatic Research
  with the same server binary in witness mode. It cosigns anchors and sees
  only hashes.
- **Auditors never pay to verify.** Viewing and verifying are free.
- **Design partners** get a preview of Stet Server now, with
  anchoring, evidence export and the console integrated in 0.6. It is not
  generally available. We do not publish prices; design partners contact
  us.

The runtime moved from the Business Source License to Apache 2.0 on
2026-10-13, before its first registry release, so no one depended on the
earlier terms.

## Roadmap

### 0.5: installable and drop-in for Python (about to be released)

`ctx.wrap(client)` journals the Anthropic and OpenAI SDKs and
`ctx.run_tools` journals tool calls. Apache 2.0. Release publishing is
wired to PyPI and crates.io; the release has not reached them yet.

### 0.6: the system of record (built; Stet Server in design-partner preview)

The contract is [design/system-of-record.md](design/system-of-record.md).
Everything below is implemented in this repository and exercised end to
end by the one-command demo (`examples/demo`) and the end-to-end suite
(`tests/e2e`). Like 0.5, it is not yet on a package registry.

- **Journal format 2:** salted commitments for content, so content can be
  erased without breaking the chain; structural fields that never hold
  personal data; strict canonical encoding.
- **Intents and results:** every model call and tool call is on record
  before it happens, and its result before the agent sees it. Failures
  are recorded and replay as the same errors.
- **Branches and parallel regions,** with exact replay of interleaved work.
- **Erasure** that keeps the chain verifiable, with every erasure recorded.
- **Anchoring:** a Merkle log of every run, time-stamped and cosigned by
  independent operators (two by default).
- **Evidence bundles** and an offline verifier with pinned trust roots,
  plus a second, independent reference verifier.
- **Stet Server:** leases, scoped tokens and roles, the access log,
  holds, retention, redaction, webhooks, backups, witness mode and the
  console.
- **Python SDK:** journaling at the HTTP layer (streaming, `.parse()`,
  frameworks), async attempts, `ctx.gather`, the server store, labels and
  data subjects.

### 0.7

From the design's deferred list: OIDC sign-in; TLS inside the server;
server-side OpenTelemetry export; local anchoring from the CLI; capture
for the Claude Agent SDK; LiteLLM's own Anthropic handler; a Pydantic AI
durable-execution backend; the TypeScript SDK; servers with more than one
replica.

### Trust work for regulated customers

A penetration test of the Server, a security questionnaire answer set, a
data processing agreement, a DORA contract addendum, a data-flow diagram
showing that nothing leaves the customer's network, a hardening guide, and
signed releases with a software bill of materials. SOC 2 comes when a
hosted product has paying users or a customer requires it.

## What we are deliberately not doing

- **No compliance claims.** We say Stet "helps meet", "supports" or
  "provides evidence for" a requirement. We never say that using
  Stet meets a regulation or a standard for the customer, and we
  never say a law requires anchored logs.
- **No hosted multi-tenant journal service in year one.** Self-hosted
  first. It keeps customer data out of our hands and is the main reason we
  can sell to regulated buyers before we hold our own SOC 2 report.
- **No metering or sampling of capture.** Recording every call is the
  product; nothing in how we package it should push a customer to record
  less.
- **No new language bindings.** The C++, Java, Go and Node.js bindings are
  stable and maintenance-only. The next new language is the TypeScript
  SDK in 0.7.
- **No agent framework.** Stet is the runtime under whatever
  framework the customer already uses.
- **No telemetry,** update checks or crash reporting, in any component.
- **No multi-replica server until a customer needs it.** One server per
  deployment in 0.6.
- **No benchmark-chasing.** "Measured, not promised" grows only when a
  claim matters to the position.

## Positioning FAQ

**Why not Temporal?** If you run Temporal for general workflows, keep it.
Stet is for when the agent itself must be recoverable and its record
must convince an outsider: the model call is modeled rather than an
opaque cached activity, a changed agent fails loudly instead of diverging
silently, and the journal is an anchored, exportable audit record rather
than engine-internal history.

**Why not our observability tool?** Keep it for debugging and dashboards.
Its traces sit in an editable database, kept for as long as its retention
settings say. Stet is the record you hand to someone who does not
trust you.

**Why self-hosted?** Regulated buyers do not want agent prompts and
outputs in another vendor's cloud. Self-hosting makes us a software
supplier, so their security team reviews software, not our data center.

**Why zero dependencies in the core?** The runtime asks to be linked into
someone's production agent. Every transitive dependency is a reason to say
no. Adapters carry only what they need to speak HTTPS and JSON.

## Signals that the strategy is working

- Design-partner conversations start from the audit and evidence story,
  not the retry story.
- A customer's auditor, or their customer, verifies an evidence bundle
  offline.
- A real security questionnaire's AI section is answered with Stet.

## Signals to revisit

- **Design partners care about recovery and cost and shrug at audit:**
  flip the pillars.
- **Auditors reject our bundles:** align the format with their
  requirements and with the emerging agent-audit-trail standards.
