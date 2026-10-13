# Threat model

This page says who might want to change or hide an AI agent's record,
what each of them can and cannot do, and which control stops them. It
expands section 1.3 of the [0.6 design](design/system-of-record.md),
which is normative where the two differ.

> **Status.** Journal format 2, erasure, anchoring, evidence bundles and
> Pragmatic Server are 0.6 features in design-partner preview. Release
> 0.5 has the hash chain, keyed journals and local journals only.

Contents: [What we protect](#what-we-protect) ·
[Adversaries](#adversaries) · [Controls](#controls-and-what-each-defends-against) ·
[What anchoring proves](#what-anchoring-proves-and-what-it-does-not) ·
[The unanchored window](#the-unanchored-window) · [HMAC keys](#hmac-keys) ·
[Limits of erasure](#limits-of-erasure) · [Limits of redaction](#limits-of-redaction) ·
[Out of scope](#out-of-scope)

## What we protect

1. **Integrity of the record.** A recorded entry cannot be changed,
   removed, reordered or inserted without detection by a verifier who
   holds the right inputs.
2. **Existence in time.** With anchoring, a verifier can show that a
   journal prefix existed, exactly as it is, no later than a time vouched
   for by parties the operator does not control.
3. **Completeness within the journaled interfaces.** A model answer, tool
   result, received message, random draw or clock read reaches the agent
   only after it is durably recorded.
4. **Confidentiality of content** from parties who are not entitled to
   it: auditors without raw access, witnesses, timestamp authorities and
   webhook receivers.
5. **Erasability of personal content** without breaking the integrity of
   everything else.

We do not protect the truth of what was recorded (a model can be wrong,
an input can be false), and we cannot record what an agent does outside
the journaled interfaces.

## Adversaries

| Adversary | Can | Cannot (when the stated controls are on) |
|---|---|---|
| **Agent code**, including tools hijacked by prompt injection | Act outside the journaled interfaces, unrecorded. Hold an agent token scoped to its run-id prefixes. Append to a run while it holds that run's lease. In local mode, read, edit and delete the journal files its process can reach | Write erased or withheld slots, or server-only notes. Touch runs outside its scopes. Rewrite or delete anything already on Pragmatic Server |
| **Host operator without the HMAC key** (local mode) | Read and edit local journal files. Delete them | Edit a keyed journal without detection |
| **Host operator** (local mode, unkeyed journal) | Read, edit, delete or truncate the files, and recompute the chain after an edit | Hide an edit from someone who holds an earlier copy, such as one pushed to Pragmatic Server or exported as an evidence bundle |
| **Server administrator with root** | Read all content. Delete data. Rewrite the unanchored end of a run (normally at most one anchoring interval old). Stop anchoring | Rewrite an anchored prefix. Hide an anchored run from an auditor who audits the full anchor log against a pinned independent witness |
| **Auditor** | Read what their token's scopes and `view_raw` allow | Recover redacted content: salts are never served with redacted content, and a withheld slot carries only its commitment |
| **Holder of a stolen token** | Whatever that token's role and scopes allow, until it is revoked or expires | Act outside those scopes, or act unlogged: every request, refused ones included, is in the access log |
| **One timestamp authority** (compromised, or simply wrong) | Issue a false time-stamp | Make an anchor count as independent on its own: an anchor needs at least two distinct trusted operators |
| **Pragmatic Witness** (hosted, planned) | Refuse service. See a log name, sequence number, tree size and root hash | Learn any content or run id |
| **Network attacker** between the SDK and the server | Without TLS: read content and tokens, and change traffic | With TLS ending at your proxy or ingress: read or change traffic. The server refuses to listen on a non-loopback address unless you confirm that TLS ends in front of it (`allow_plain_http`) |

## Controls, and what each defends against

| Control | Defends against | Notes |
|---|---|---|
| **Hash chain** (SHA-256 over every entry's structure and its content commitments) | Silent edits, deletions in the middle, reordering, insertion | Anyone who can rewrite the whole file can recompute an unkeyed chain. The chain alone catches accidents and careless edits; it needs anchoring, a key or an earlier copy to catch a deliberate rewrite |
| **Salted content commitments** (a fresh 16-byte random salt per content slot) | Guessing erased or withheld content from its hash | Erasing a slot drops the salt and the content, and leaves the commitment, so the chain still verifies |
| **Canonical decoding** (decode, re-encode and compare bytes) | Two encodings of one record, and parser confusion | Applied to the server's append path, file parsing and evidence verification |
| **Torn-tail versus corruption rules** | Truncating acknowledged entries after damage | A crash can only tear unacknowledged frames at the end. Damage that could have hit acknowledged entries is reported as corruption, never silently cut off |
| **Write-ahead intents** | Missing a call in the record, and repeating a recorded model answer or a committed tool call after a crash | An intent is durable before the call or tool runs; its result is durable before the agent sees it. A call cut off by a crash (intent recorded, result not) can be repeated, and the journal shows it: a model call is sent again, so one paid for but not recorded is paid for twice; a tool call goes to the `recover` policy, with an idempotency key, and local runs perform it again by default (server-backed runs need an explicit policy) |
| **Single writer** (a file lock locally, a lease on the server) | Two copies of an agent continuing one run | Local file locks do not work across machines on network file systems; use Pragmatic Server for that |
| **Server-side validation of every append** | An agent writing records that would not verify, writing erased or withheld slots, or writing server-only notes | The server stores nothing that would fail verification. The client compares the head it computed with the head the server returns |
| **Anchoring** (a Merkle log of every run's state, time-stamped by RFC 3161 authorities and cosigned by witnesses) | A server administrator rewriting or hiding anchored history | See the next two sections for exactly what it proves and the window it leaves |
| **Operator independence** (at least two distinct trusted operators, by default) | One compromised or careless timestamp authority | Entrust is counted as Sectigo and QuoVadis EU as DigiCert, because they share an operator. The server's own signature never counts as independent |
| **Pinned trust roots in the verifier** | A bundle that brings its own fake authorities, witnesses or log | Nothing inside a bundle is trusted. Certificates in a bundle are only intermediates |
| **Full-log and witness-log audits** (`--log`, `--witness-log`) | An operator who leaves anchors out of a bundle, or shows different auditors different logs | Optional checks; an auditor who skips them learns less |
| **Roles and scopes** | Agents and auditors reaching runs that are not theirs | Out-of-scope runs answer `not_found`, so their existence is not revealed |
| **Redacted views** | Auditors without `view_raw` seeing personal content | See [limits of redaction](#limits-of-redaction) |
| **Access log** (itself a hash-chained, anchored journal) | Reads and changes that leave no trace | It fails closed: if it cannot be written, authenticated requests are refused. Direct file access by root bypasses it |
| **Erasure notes and the erasure ledger** | Erasure without a record of who, what and why | Server erasures name the token and point at the access-log record. Local erasures are marked unauthenticated |
| **Holds and retention minimums** | Erasure or deletion of records that must be kept | `erasure = "deny_during_min"` refuses erasure during the retention minimum |
| **Custody notes** | Disputes over which client wrote which entries | Written into the run by the server whenever a lease ends |
| **Regression and missing-run detection** | Restoring an old backup over newer anchored data, or deleting an anchored run without a tombstone | Runs shorter than their anchored length are marked `regressed`; anchored runs with no journal and no tombstone are marked `missing` |
| **Alerts and periodic re-verification** | Problems going unnoticed | Webhooks for a broken chain, failed anchoring, regression, erasure, retention actions, dangling effects, clock skew and missing records |

## What anchoring proves, and what it does not

A verified anchor proves that a journal prefix of a stated number of
entries, ending in a stated chain head, existed no later than the time
the witnesses signed.

It does **not** prove:

- that the content was true when it was recorded;
- that nothing happened outside the journaled interfaces;
- anything about the run before its first anchor;
- that the times written inside entries are right (those are the writing
  machine's clock, informational only; the only proven time is the
  witnesses' time, and it is an upper bound);
- that the journal did not exist earlier than the anchor (a run could
  have been prepared in advance and anchored later);
- who ran the agent, beyond what the server recorded about tokens, which
  is the operator's statement;
- that the server's own signature is independent: it is controlled by the
  operator and is reported as such.

A timestamp authority stamps whatever digest it is sent. Anyone can build
a Merkle log of their own and have it stamped. That is why an auditor
pins the log's key, obtained from the operator through a channel the
auditor trusts, rather than taking it from the bundle.

## The unanchored window

Anchoring never blocks journaling. Entries written since the last
successful anchor are not yet protected against a server administrator
with root: in that window an insider could rewrite them without
detection.

- The window is normally at most one anchoring interval: 10 minutes by
  default, configurable from 1 minute to 1 hour. A batch also runs within
  30 seconds of a run finishing successfully, and on demand when an
  evidence bundle is requested with `anchor=now`.
- When witnesses fail, the window grows. The server retries, exposes the
  *anchoring lag* (the age of the oldest unanchored append) as a metric,
  and raises an alert when fewer than the required number of operators
  succeed for three intervals in a row.
- A verifier reports `VERIFIED (PARTIAL)` and the number of unanchored
  entries at the end when only a prefix is anchored. Treat that suffix as
  the operator's word.
- Local journals have no anchors in 0.6. Their window is the whole run,
  unless a copy was pushed to a server or exported and given to someone
  else.

## HMAC keys

Local journals can be keyed: the chain then uses HMAC-SHA-256 with a
secret key instead of plain SHA-256.

- **What it defends against:** someone who can edit the files but does
  not hold the key cannot change a keyed journal without detection.
- **What it does not do:** HMAC is symmetric. Anyone who holds the key can
  rewrite the whole journal and recompute a valid chain. It gives no
  third-party attribution and proves nothing to an outsider who does not
  trust the key holder. For that, use anchoring.
- **No downgrade:** the keyed flag is in the file header and is part of
  the chain's starting value. A keyed journal opened without a key is
  refused, never checked as unkeyed. A key supplied for an unkeyed
  journal is an error.
- **Key handling:** pass the key with `--key-file` or
  `PRAGMATIC_JOURNAL_KEY`, never on the command line (`--key` remains,
  deprecated, with a warning). Storing, rotating and backing up keys is
  the customer's responsibility. A lost key means the journal can no
  longer be verified or extended.
- **Server runs and evidence bundles are always unkeyed.** Their
  protection comes from the server's checks and from anchoring.

## Limits of erasure

Erasure removes the content of chosen slots (and their salts) from the
journal while every chain hash still verifies, and records an `erasure`
note saying which slots, by whom and why. It cannot reach copies that are
outside that journal file:

- **Backups.** A backup taken before an erasure still holds the content.
  `pragmatic-server restore` re-applies every erasure in the erasure
  ledger that is newer than the backup, so the ledger must be streamed off
  the host. Backups themselves must expire on your schedule.
- **Exported evidence bundles.** A bundle already handed to someone keeps
  whatever content it carried. Erasure cannot recall it. Export with
  redaction (withheld slots carry only their commitment) unless the
  recipient needs the content.
- **Client-side journals.** Local journals on agent hosts, copies made
  before `python -m pragmatic push`, journals in CI artifacts or on
  laptops, and HTML exports are separate copies. Erase them separately.
  For one run, erasure also removes the moved-aside torn tails
  (`*.torn-*` files) that hold bytes of frames that never became entries.
- **Structural fields.** Fields are never erasable: kinds, cursors,
  branches, tool names, channel names, model names, token usage,
  outcomes, labels, token ids, local OS user names, host names and run
  ids. They must not hold personal data. See [privacy.md](privacy.md).
- **Downstream systems.** The model provider's own logs, your
  observability tools and anything a tool sent elsewhere are outside
  Pragmatic.
- **The fact of erasure** is visible by design: the slot shows as erased
  and the note says who erased it.
- **Replay after erasure.** A run with erased content can still be
  verified, but replay and resume stop with `Erased` at the first step
  that needs the erased content.
- **Match mode compares bytes.** Erasing by matching text finds only that
  exact byte sequence. The same identifier written differently (other
  case or spacing, JSON escape sequences, inside an image) is not found.
- **Local erasure is not attributed.** `pragmatic erase` records the
  local user and host, marked unauthenticated. Only the server records an
  authenticated actor.

## Limits of redaction

Redaction shapes what auditors without `view_raw` see, and what evidence
bundles carry. The journal itself keeps the raw content.

- **Images, PDFs and audio are not inspected.** Binary content in model
  requests (base64 images and documents, data URLs, file data, audio
  input) is never served to a redacted view. It is replaced by a
  placeholder giving its media type, size and SHA-256. Any text inside it
  is never read.
- **Regex redaction is not de-identification.** The built-in detectors
  (email, phone, US social security number, card number, IBAN, IPv4
  address, secrets) and your patterns catch formats. They do not catch
  names, addresses written as prose, rare conditions, job titles or other
  details that identify a person in context.
- **Tokens with `view_raw` see everything,** and so does anyone who reads
  the journal files directly.
- **Withheld slots in bundles are whole slots.** Content is never altered
  inside a slot; a slot is either included in full or withheld.

## Out of scope

- Compromise of the machine that runs the agent while it runs: such an
  attacker can feed the agent false inputs, and those false inputs will be
  faithfully recorded.
- Model providers' handling of the prompts they receive.
- Availability: a server administrator can always refuse service or
  delete data. Pragmatic makes deletion of anchored data detectable, not
  impossible.
- Side channels, and denial of service against the server.
- The security of the timestamp authorities and witnesses themselves,
  beyond requiring two independent operators.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
