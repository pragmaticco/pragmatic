# Privacy

A journal is a complete record of what an agent was told and what it did,
so it usually holds personal data. This page explains what a journal
contains, what can be erased and what cannot, how to handle a person's
request to see or erase their data, how to set retention, where redaction
stops, and how to start a data protection impact assessment (DPIA).

> **Status.** Journal format 2, erasure, labels and subjects, retention,
> holds and Stet Server are 0.6 features. 0.6.0 is built from source
> and not yet published, and Stet Server (retention, holds and
> erasure on the server) is in design-partner preview. Release 0.5
> journals (format 1) cannot erase content; in 0.6 they are read-only.

> **This is not legal advice.** It describes how Stet behaves. How
> privacy law applies to your processing is for you and your counsel to
> decide.

Contents: [Fields and slots](#fields-and-slots) ·
[What can be erased](#what-can-be-erased-and-what-cannot) ·
[Labels, subjects and run ids](#labels-subjects-and-run-ids) ·
[Subject requests and erasure](#subject-requests-and-erasure) ·
[Retention presets](#retention-presets) ·
[Limits of redaction](#limits-of-redaction) ·
[What leaves your network](#what-leaves-your-network) ·
[DPIA template](#dpia-template-outline)

## Fields and slots

Every journal entry has two kinds of data:

- **Fields** are structure: what kind of step this was, on which branch,
  which tool or channel, which model, how many tokens. Fields are part of
  the hash chain directly. **They are never erasable, so they must never
  hold personal data.**
- **Slots** are content: prompts, responses, tool arguments and results,
  received messages, random values. Each slot is sealed with a fresh
  random salt, and only a salted commitment (a hash) enters the chain.
  **Slots are erasable**: erasing one removes its content and its salt,
  and the chain still verifies.

| Step | Fields (kept forever) | Slots (erasable) |
|---|---|---|
| Model call, request (`DrawIntent`) | which model client made it | the request: method and path, settings, and each message |
| Model call, result (`DrawResult`) | which request it answers; outcome, HTTP status, provider, model, stop reason, token usage, latency | the response head (status and a short list of headers) and body |
| Received message (`ChannelRecv`) | channel name | the message |
| Tool call (`EffectIntent`) | tool name | the arguments |
| Tool result (`EffectResult`) | which call it answers; outcome; error type | the result, or the error message |
| Clock read (`Clock`) | the time read | none |
| Random draw (`Random`) | source and arguments | the value |
| Program identity, branches, patches | names and hashes, branch numbers | none |
| Refused step (`Refusal`) | step, name and fault | none |
| Notes | run id, labels, attempt number, mode, SDK version, the principal (a token id, or the OS user for local runs), host name, process id, trace id, usage totals, outcome | the run's data subjects; the run's output or error message; an erasure's free-text reason |

Two things follow:

- **Name tools, channels, labels and run ids without personal data.**
  `tool:send_email` is fine; `tool:email_jane` is not.
- **Some notes describe the machine.** `attempt.start` records the host
  name and process id. If your host names identify people (a developer's
  laptop name, for example), run agents on hosts that do not.
- **Local runs record the OS user name.** In local runs, the principal in
  `attempt.start` is the operating-system user, and a local erasure note
  records `local:<os-user>@<host>`. Both are fields, so they cannot be
  erased. Run agents, and local erasures, under service accounts rather
  than personal logins.

## What can be erased, and what cannot

**Erasable** (the content and its salt are removed; the slot shows as
erased):

- every request part and response of a model call;
- tool arguments, results and error messages;
- received messages and random values;
- note payloads: a run's data subjects, its output, its error message, and
  the free-text reason of an earlier erasure.

**Not erasable:**

- fields (above), including model names, token usage and outcomes;
- run ids and labels;
- commitments and chain hashes (with the salt gone, a commitment can no
  longer be linked to the content it covered);
- anchor-log leaves, which contain run ids unless the server is set to
  `anchor_run_ids = "hmac"` (which weakens what anchoring proves; see
  [run ids](#labels-subjects-and-run-ids));
- the server's access log (token ids, principals, source addresses, user
  agents, run ids, times), which run retention policies never shred;
- the erasure ledger, which records every erasure so restores can repeat
  it.

**What erasure does to a run:**

- The run still verifies. `verify` checks that every erased slot is
  listed by an `erasure` note.
- Replay and resume stop with `Erased` at the first step that needs the
  erased content. Erase a run that has not finished only when you will not
  need to resume it (the server asks you to confirm with
  `allow_unfinished`).
- Repeated content of 256 bytes or more is stored once in a journal, so
  erasing one copy of it erases every copy. Shorter content, such as a
  short reply holding an email address or a name, is stored again in
  every later request that resends the conversation. Erase it with
  `match`, or erase every slot that holds it.

## Labels, subjects and run ids

**Labels** describe a run for search and retention: at most 32 pairs,
keys of lowercase letters, digits, `_`, `.` and `-` (up to 64
characters), values up to 256 bytes. **Labels are fields, so they are not
erasable and must not hold personal data.** Good labels: `team=claims`,
`use_case=fnol-triage`, `record_class=bd-comms`. Bad labels: a customer's
name, email or account number.

**Subjects** name the people a run is about, so you can find their runs
later. They are stored in an erasable slot of the run's first note, and
the server keeps an index of keyed hashes of them, never the identifiers
themselves. Prefer your internal identifiers (`customer:48213`) to emails
or names.

```python
rt.run("claim-7781", triage_agent,
       labels={"team": "claims", "use_case": "fnol-triage"},
       subjects=["customer:48213"])
```

**Run ids** appear in file names (hashed), in the access log, in webhooks
and, unless you choose `anchor_run_ids = "hmac"`, in the anchor log. Use
opaque ids such as `claim-7781` or a UUID, never an email or a name.
Opaque ids are the better way to keep run ids private, because
`anchor_run_ids = "hmac"` trades auditability for that privacy:

- nothing binds a run's anchor key to the run, so a server administrator
  can rewrite an anchored run and anchor it again under a new key, and no
  audit detects it;
- every bundle from such a server reports `anchor_id_unbound`, and an
  auditor's `--log` audit fails with `log_unauditable` instead of showing
  that no anchor was left out.

Keep the default, `"plain"`, wherever an auditor must be able to rule out
hidden or rewritten anchors. Run ids bound to the log key, which would
remove this trade-off, are planned for 0.7.

## Subject requests and erasure

A procedure for a person's request to see (GDPR Article 15) or erase
(Article 17) their data. Adapt it to your own process and deadlines.

### 1. Find the person's runs

- **With Stet Server:** an admin calls `POST /v1/subjects/search`
  with `{"subject": "customer:48213"}`. The identifier is sent in the
  body and is never logged. This finds runs whose subjects named the
  person.
- Then look for runs that mention the person without naming them as a
  subject: by label (`GET /v1/runs?label.team=claims`), by date, or by
  the business record the run belongs to.
- **Local journals:** list runs with `pragmatic runs --dir DIR` and read
  them with `pragmatic show RUN --dir DIR`. There is no subject index for
  local journals.

### 2. Give access

- Export a run with `pragmatic evidence RUN -o FILE --redact none`, or
  from the server with `GET /v1/runs/{id}/evidence?redact=none` (an
  auditor or admin token with `view_raw`).
- Withhold other people's content before you hand it over
  (`--withhold CURSOR:SLOT`). A withheld slot keeps its commitment, so
  the copy still verifies.
- `pragmatic render-evidence FILE --format html` gives a readable copy.

### 3. Check holds and retention

Erasure is refused while a legal hold covers the run (`on_hold`), or
during a retention minimum when the policy says
`erasure = "deny_during_min"` (`retention_locked`, with the date it ends).
The refusal is logged with the reason `legal_obligation`. Decide with
counsel whether an exception to erasure applies, and record the decision.

### 4. Erase

On the server (admin token):

```sh
curl -X POST "$PRAGMATIC_URL/v1/runs/claim-7781/erase" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"match": "jane.doe@example.com", "reason_code": "gdpr_art17"}'
```

Give exactly one of `"match"` (every slot containing that text), `"slots"`
(a list of `[cursor, slot]` pairs) or `"slots": "all"`. A free-text
`"reason"` is stored in an erasable slot.

On a local journal:

```sh
pragmatic erase claim-7781 --match "jane.doe@example.com" \
  --reason-code gdpr_art17 --dir ./journals
```

Local erasure records the local user and host, marked unauthenticated.

**Match mode compares bytes.** It finds only that exact sequence. The
same identifier with other case or spacing, escaped inside JSON, or
inside an image or document is not found. Review the run with
`pragmatic show` and erase the remaining slots by cursor and slot.

### 5. Check the result

`pragmatic verify RUN --dir DIR` (or the run's `verify` report on the
server) must show no unaccounted erasures and no incomplete ones. If an
erasure was interrupted, running it again completes it.

### 6. Erase the copies Stet cannot reach

- **Backups:** keep the erasure ledger off the host so a restore
  re-applies the erasure, and let old backups expire on schedule.
- **Evidence bundles and HTML exports** already given to others.
- **Local journals** on agent hosts, laptops and CI machines, and any
  copy made before a journal was pushed to the server.
- **Model providers' logs**, observability tools, and systems your tools
  wrote to.

### 7. Record your response

Keep the request, the runs found, what was erased or why it was not, and
the date of your answer.

## Retention presets

These are starting points for `[[retention]]` policies in the server's
configuration, one per record class. They are not legal advice: confirm
the period that applies to each class of record with counsel.

| Rule | Minimum | `retain_min_days` | `erasure` |
|---|---|---|---|
| EU AI Act, Articles 19 and 26(6) | at least 6 months | 184 | `allow` |
| SEC 17a-4, core records | 6 years | 2192 | `deny_during_min` |
| SEC 17a-4, communications and other 3-year records | 3 years | 1096 | `deny_during_min` |
| FINRA 4511, where no other period applies | 6 years | 2192 | `deny_during_min` |
| NYDFS 500.6, reconstructing material financial transactions | 5 years | 1827 | `deny_during_min` |
| NYDFS 500.6, cybersecurity audit trails | 3 years | 1096 | `deny_during_min` |
| Colorado SB 26-189 | 3 years | 1096 | your decision |
| California employment rules on automated decisions | 4 years | 1461 | `deny_during_min` |
| FDA 21 CFR Part 11 | as long as the records it covers | your record period | `deny_during_min` |
| Legal hold | until released | use a hold, not a policy | refused while held |

The day counts include leap days, so they are never shorter than the
period. Ages count from a run's last append, which is never earlier than
the record it holds.

```toml
# Broker-dealer communications handled by agents: kept 3 years with no
# erasure, then their content is shredded and the verifiable skeleton
# of each run is kept.
[[retention]]
match = { prefix = "", labels = { record_class = "bd-comms" } }
retain_min_days = 1096
shred_after_days = 1096
erasure = "deny_during_min"

# EU high-risk system logs: at least 6 months, erasure allowed.
[[retention]]
match = { prefix = "eu-hiring-", labels = {} }
retain_min_days = 184
erasure = "allow"
```

A `prefix` is matched against run ids, so use only characters a run id
can hold: letters, digits, `.`, `_`, `:` and `-`. A prefix with any other
character, such as `/`, matches no run.

How policies combine:

- When several policies match a run, each value is the most restrictive
  one: the largest minimum, `deny_during_min` over `allow`, and shred and
  delete ages never earlier than the combined minimum.
- **Shred** erases every content slot (reason `retention`) and keeps the
  verifiable skeleton. **Delete** removes the journal and leaves a
  tombstone; that run id can never be used again.
- Retention runs hourly and on demand, and skips runs that are being
  written.
- A legal hold stops erasure, shredding and deletion of every run it
  covers, including runs created later under a held prefix.

## Limits of redaction

Tokens without `view_raw` see redacted content, and evidence bundles can
withhold slots. Redaction has limits:

- **Images, PDFs and audio are not inspected.** Binary content in model
  requests is never shown in redacted views; it is replaced by a
  placeholder with its media type, size and SHA-256. Text inside an image
  or document is never read or redacted.
- **Regex redaction is not de-identification.** The built-in detectors
  (email, phone, US social security number, card number, IBAN, IPv4
  address, secrets) and your own patterns catch formats. They miss names,
  addresses written as prose, and details that identify someone in
  context. A redacted view can still identify a person.
- **Redaction does not change the journal.** The journal keeps the raw
  content. Tokens with `view_raw`, and anyone who reads the files, see
  everything.
- **Bundles withhold whole slots.** Content is never edited inside a slot.

## What leaves your network

Stet sends no telemetry. With Stet Server self-hosted, prompts,
outputs and other content never reach Pragmatic Research.

- Timestamp authorities receive a 32-byte digest of the anchor log's
  checkpoint and a random nonce.
- Witnesses receive the log's name, a sequence number, the tree size and
  the root hash.
- Webhooks receive an event type, a run id and counts.
- Model providers receive whatever your agent sends them. That is your
  agent's processing, not Stet's.

Erasure in Stet follows the approach that the European Data
Protection Board's guidelines 02/2025 on blockchain (version 2.0, adopted
7 July 2026) describe: keep personal data out of the chain, commit to it
with salted hashes, and delete the data and the salt to erase it. Those
guidelines are about blockchains, so applying them to a journal is an
analogy, not a ruling.

## DPIA template outline

An outline for a data protection impact assessment (GDPR Article 35) of
journaling an AI agent with Stet. Assess the agent's own processing
separately; this covers the record of it.

1. **Description of the processing**
   - The agent: its purpose, the decisions or actions it takes, and who
     is affected.
   - What the journal holds: categories of personal data in prompts,
     responses, tool arguments and results; any special categories
     (health, biometric, financial); the data subjects.
   - Where it is stored (`data_dir`, region, backups), who can read it
     (roles, `view_raw` tokens, administrators), and who receives exports
     (auditors, customers, regulators).
2. **Purpose and lawful basis for keeping the record**
   - Why you keep it: accountability, a legal obligation (name it), the
     security of the system, or the defence of legal claims.
   - Why each retention period is needed (see [retention presets](#retention-presets)).
3. **Necessity and proportionality**
   - Why a complete record of content is needed rather than metadata only.
   - Minimization: no personal data in fields, labels, tool names or run
     ids; internal identifiers as subjects; personal data the model does
     not need kept out of prompts.
   - Redacted views for auditors who do not need raw content.
   - How people exercise their rights: the [procedure above](#subject-requests-and-erasure),
     and its response times.
4. **Risks to people**
   - A breach of a store that concentrates prompts and outputs.
   - Keeping records longer than needed.
   - Identification through fields, labels or metadata that cannot be
     erased.
   - Incomplete erasure: backups, exported bundles, local copies,
     providers.
   - Access by more people than necessary, including auditors.
   - Use of journals for purposes beyond the stated ones, such as staff
     monitoring.
   - Transfers outside your region (model providers; timestamp
     authorities and witnesses receive only hashes).
5. **Measures**
   - From Stet: scoped tokens and roles, the access log, redacted
     views, erasure that keeps the proof, retention policies and holds,
     no telemetry, only hashes sent to timestamp authorities and witnesses.
   - From you: volume and backup encryption, TLS, your identity provider
     and access reviews, data processing agreements with model providers,
     staff training, and the shared responsibilities in
     [compliance.md](compliance.md#shared-responsibility-matrix).
6. **Residual risk and decision**
   - The remaining risk after these measures, the advice of your data
     protection officer, and whether you must consult the supervisory
     authority (Article 36).
7. **Review**
   - Who reviews the assessment, when, and what triggers an early review
     (a new agent, a new data category, a new model provider, a change of
     region).
