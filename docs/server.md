# Pragmatic Server

Pragmatic Server stores the journals your agents write, so that every run
has one durable, access-controlled record that you can audit, export as
evidence, erase for privacy law and keep or delete by policy. This guide
covers installing it, configuring it, issuing tokens, sizing, backups and
upgrades.

> **Status.** Pragmatic Server 0.6.0 is in design-partner preview and is
> not generally available. Everything on this page, anchoring, evidence
> bundles and the console included, is implemented in this repository;
> `examples/demo/run.sh` runs it end to end on one machine, and
> `tests/e2e` asserts the same story against the real binary. To join as
> a design partner, contact me@aniketh.net.

Pragmatic Server is licensed under the Business Source License 1.1. You may
use it for development, testing and evaluation. Production use needs a
commercial license from Pragmatic Research, Inc. Each version becomes
Apache-2.0 four years after its release. Its anchoring library,
`crates/pragmatic-anchor`, is under the same terms. Neither crate is
published to crates.io: the server is built from this repository as a
binary or a container image (see [Install](#install)). The SDKs, the CLI,
the verifier and the journal format are Apache-2.0.

Contents: [How it works](#how-it-works) ·
[Anchoring and evidence](#anchoring-and-evidence) · [The console](#the-console) ·
[Install](#install) · [First start](#first-start) ·
[Configuration reference](#configuration-reference) ·
[Tokens, roles and scopes](#tokens-roles-and-scopes) ·
[Leases and appends](#leases-and-appends) ·
[Erasure, holds and retention](#erasure-holds-and-retention) ·
[Redaction](#redaction) · [The access log](#the-access-log) ·
[Alerts and metrics](#alerts-and-metrics) · [Witness mode](#witness-mode) ·
[Sizing and limits](#sizing-and-limits) · [Backup and restore](#backup-and-restore) ·
[Upgrades](#upgrades) · [Command reference](#command-reference)

## How it works

- Each run is one journal file. An agent (through the SDK) creates the run,
  takes its **lease**, and appends frames. Only the lease holder can append,
  so two copies of an agent can never both write the same run.
- The server checks every frame it receives the same way a verifier would:
  the encoding, every content commitment and the hash chain. It never
  stores something that would not verify.
- Auditors read runs through the API or the console. Content is
  **redacted** for them unless their token has `view_raw`.
- Every request, including refused ones, goes into the **access log**,
  itself a hash-chained journal.
- **Anchoring** records the state of every run in a Merkle log whose
  checkpoints are timestamped by independent witnesses, so changes to
  anchored history can be detected. **Evidence bundles** package a run's
  journal with its anchors, signed by the server, for an auditor to verify
  offline against trust roots of their own choosing.
- **Erasure** removes the content of chosen slots while the chain still
  verifies. **Holds** stop erasure and retention for runs under legal hold.
  **Retention** policies shred or delete runs after a set time.

No component makes network connections except the server to the TSAs,
witnesses and webhook URLs you configure. There is no telemetry.

## Anchoring and evidence

Every `interval_secs` (and within 30 seconds of an agent finishing
successfully, and when an auditor asks for `anchor=now`), the server
appends a leaf to its anchor log for every run, and for the access log,
that changed since its last leaf: the journal's length and chain head,
linked to the run's previous leaf. The batch ends in a checkpoint, a C2SP
signed note over the log's root signed with the log key, and every
configured witness is asked for its signature over it: each TSA for an
RFC 3161 token, each `tlog-witness` cosigner for a cosignature.

- A checkpoint is **independently anchored** once witnesses of
  `min_independent_operators` distinct operators have verified. A run's
  `anchored_entries` advances only then; the server's own signature never
  counts. Until then `/v1/runs/{id}` shows the run as unanchored, the
  console shows an operator-only anchor, and
  `pragmatic_anchor_lag_seconds` grows.
- Witnesses that fail are retried every 30 seconds with exponential
  backoff (to an hour) per witness, oldest checkpoint first, until each
  succeeds. A witness failure counts in `pragmatic_anchor_failures_total`.
  The `anchor_failed` webhook fires once the oldest append not
  independently anchored is three anchoring intervals old (checked every
  15 seconds, so a quiet server whose witnesses are down alerts too, once
  until anchoring catches up), and when three batches in a row end short
  of the policy.
- A run whose journal holds fewer entries than its latest leaf, or the
  same entries under another head, was rolled back or rewritten after it
  was anchored. The anchor log refuses it, the server marks the run
  `regressed` (at startup, or at the next batch; appends answer
  `409 regressed`) and fires `regressed`. An administrator who accepts the
  journal runs `pragmatic-server accept-regression RUN`. Acceptance claims
  nothing about anchoring: the run keeps as anchored only what it still
  holds of its independently anchored leaves (often nothing), and its
  anchoring lag keeps counting until a new leaf is witnessed.
- A run the anchor log holds a leaf for, whose files are gone and that has
  no tombstone, is `missing` (webhook `record_missing`).
- If a witness reports having cosigned more of this log than the log
  holds, or refuses a checkpoint as inconsistent with what it cosigned,
  the log has forgotten checkpoints it signed (it was restored from an old
  backup, or rolled back), and signing on would fork it. Anchoring is
  then *held*: no checkpoint is signed until an administrator lifts the
  hold with `confirm-anchors` (see [Restoring the anchor
  log](#restoring-the-anchor-log)), and `anchor_failed` fires with
  `fork: true`.
- TSA tokens are verified with OpenSSL (`openssl ts -verify -partial_chain`
  against the operator's pinned anchors) before they are stored, so
  `openssl` (OpenSSL, not LibreSSL) must be on `PATH` when TSAs are
  configured; the server refuses to start otherwise.
- `GET /v1/anchors`, `GET /v1/anchors/{seq}` and `GET /v1/anchors/log`
  serve checkpoints, witness results and leaves, filtered by scope for
  auditors. The `--log` file of `pragmatic verify-evidence` is
  `{"leaves": [...]}` with each leaf's `leaf` hex, in order from index 0,
  from an administrator's `GET /v1/anchors/log` pages.

**Evidence bundles.** `GET /v1/runs/{id}/evidence?redact=<mode>&anchor=now`
(auditors and administrators; both parameters are optional) answers a
bundle (design section 5): the durable journal, its decoded records, its
whole leaf chain with inclusion proofs, checkpoints, consistency proofs to
the latest checkpoint and every stored witness result, signed with the log
key. `redact` is `none`, `binary` (attachments withheld, text in clear),
`detectors` (the default without `view_raw`) or `all`; `none` and `binary`
carry text unredacted, so they need `view_raw` and are logged as raw
reads. A redacted slot is
withheld whole, so the chain still verifies. The anchors run through the
checkpoint that was the latest when the journal was read, which is the
bundle's latest checkpoint; `independent` is true only when one of them is
independently witnessed. A damaged journal answers `409 chain_broken`.
`anchor=now` runs a batch, and its first witness pass, before the bundle
is built. An auditor verifies the bundle offline:

```sh
pragmatic verify-evidence case-1.evidence.json \
  --tsa-roots digicert=deploy/tsa-roots/digicert.pem \
  --tsa-roots sectigo=deploy/tsa-roots/sectigo.pem \
  --log-key "$(cat log.vkey)"
```

where `log.vkey` is the vkey `keygen` printed, obtained from the operator
out of band. `pragmatic-server verify-evidence` points to that command:
an auditor should not need the operator's server to check its bundles.

## Install

Every option builds from a clone of the repository's `system-of-record`
branch (`git clone -b system-of-record
https://github.com/pragmaticco/pragmatic`), where 0.6 is until it is
merged to `main`. Pick one:

- **Container image.** Build it from the repository root with
  `docker build -t pragmatic-server:0.6.0 .`. The image runs as user 10001,
  works with a read-only root filesystem, and includes `openssl` (used to
  check time-stamp tokens) and the pinned TSA roots in
  `/etc/pragmatic/tsa-roots`.
- **Docker Compose.** `deploy/docker-compose.yml`, with instructions at the
  top of the file.
- **Kubernetes.** `deploy/kubernetes/`: a StatefulSet with one replica,
  `OnDelete` updates, a volume claim, a Secret for the signing key, a
  Service and an Ingress. See its README for encrypted storage.
- **systemd.** Build with `cargo build --release -p pragmatic-server`, then
  follow `deploy/systemd/pragmatic-server.service`.

The server speaks plain HTTP. Run it on a loopback address, or behind a
proxy or ingress that terminates TLS (then set `allow_plain_http = true`).

## First start

1. **Write a configuration.** Copy `deploy/pragmatic.example.toml` to
   `/etc/pragmatic/pragmatic.toml` and edit it. Every key is described
   below.
2. **Create the log key**, outside the data directory:
   ```sh
   pragmatic-server --config /etc/pragmatic/pragmatic.toml keygen
   ```
   It is an Ed25519 signed-note key, in the private key format of Go's
   `sumdb/note`, named for the log's origin `pragmatic/<name>/<log id>`.
   keygen prints the origin and the **vkey**, which auditors pin with
   `--log-key` and witnesses configure; publish it out of band. Keep the
   key readable only by the server's user. The origin never changes:
   `keygen --rotate` (server stopped) makes a new key for the same origin
   and records a `key.rotate` record, signed by both keys, in the access
   log.
3. **Create the first admin token:**
   ```sh
   pragmatic-server token bootstrap
   ```
   prints a token and its SHA-256. Put only the hash in
   `[bootstrap] admin_token_sha256` and keep the token somewhere safe. Every
   other token is issued through the API with this one.
4. **Start it:** `pragmatic-server serve` (the configuration comes from
   `--config` or `PRAGMATIC_CONFIG`).

At startup the server refuses to run when:

- another server already uses the data directory (`server.lock`);
- `listen` is not a loopback address and `allow_plain_http` is false;
- no independent witness (a `[anchoring] tsa` or `witness`) is configured
  and `allow_self_anchoring` is false. With self-anchoring, evidence
  bundles say `"independent": false`;
- a key file (the log key, the anchor key or the witness key) is inside
  `data_dir` (a backup of the data would then carry it) and
  `allow_key_in_data_dir` is false;
- `name` is set and is not the name in the log key's origin;
- TSAs are configured and `openssl` on `PATH` is not an OpenSSL that
  verifies with `-partial_chain`, or two operators' anchor files share a
  certificate;
- the anchor log is damaged (a checkpoint root the leaves do not
  reproduce, a broken leaf chain, witness results for a checkpoint that is
  gone): it is never repaired automatically;
- the data directory has a data format this build does not know;
- the access log is damaged (the server will not append to a log whose
  history it cannot vouch for). A log that holds fewer records than its
  last anchor leaf covers is reported (`chain_broken` for
  `pragmatic:access-log`) and recorded in the log, and the server goes on.

`/healthz` answers as soon as the process listens. `/readyz` and every run
endpoint answer `503 starting` until the index of runs is built; full
verification of every journal then continues in the background. A run
whose files cannot be read at startup (permissions, I/O errors) is
*unavailable*, never absent: its endpoints answer
`503 storage_unavailable`, creating it is refused, and it loads on first
use once its files read again. A tombstone that cannot be read still
deletes its id.

## Configuration reference

The configuration is TOML. Unknown keys are refused, so a misspelled
setting cannot silently fall back to its default.

### Top level

| key | default | meaning |
|---|---|---|
| `name` | host name | The server's name. Anchoring checkpoints use the origin `pragmatic/<name>/<log id>`, where the log id is 16 hex digits of the SHA-256 of the log's first public key, fixed when `keygen` makes that key. Empty means the name in the key; a name the key does not carry is refused. |
| `listen` | `"127.0.0.1:7272"` | IP address and port to listen on. |
| `data_dir` | `"/var/lib/pragmatic"` | Where runs, the access log, tokens and anchors live. |
| `allow_plain_http` | `false` | Allow a non-loopback `listen`. TLS must then terminate in front of the server. |
| `trusted_proxy_header` | `""` | The header your proxy puts the client address in, such as `x-forwarded-for`. The last address in it is logged. Leave empty unless every request comes through that proxy. |
| `lease_ttl_secs` | `60` | How long a lease lasts without renewal (1 to 3600). |
| `max_request_bytes` | `268435456` | The largest request body (256 MiB). |
| `max_clock_skew_secs` | `300` | Entries whose time differs from the server's by more are accepted but flagged in the lease's custody note. |
| `public_url` | `""` | The URL clients use. An `https://` URL makes console cookies `Secure`. |
| `verify_interval_hours` | `24` | How often every chain, commitment and anchor proof is verified again. |

### `[keys]`

| key | default | meaning |
|---|---|---|
| `signing_key_file` | `"/etc/pragmatic/server.ed25519"` | The log key (an Ed25519 signed-note key, written by `keygen`) that signs checkpoints, evidence bundles, backup manifests and key rotations. |
| `allow_key_in_data_dir` | `false` | Allow key files inside `data_dir`. |
| `anchor_key_file` | `""` | 32 random bytes (raw, or 64 hex digits) from which each run's anchor key is derived under `anchor_run_ids = "hmac"`. Required in that mode; `keygen --anchor-key` writes one. |

### `[bootstrap]`

| key | default | meaning |
|---|---|---|
| `admin_token_sha256` | `""` | SHA-256 (lowercase hex) of the first admin token. |

### `[anchoring]`

| key | default | meaning |
|---|---|---|
| `interval_secs` | `600` | Seconds between anchoring batches (60 to 3600). A batch also runs within 30 seconds after an agent finishes successfully. |
| `tsa` | `[]` | RFC 3161 time-stamping authorities: `{ url, operator, roots_pem }`. `roots_pem` holds that operator's pinned trust anchors (a root, or better the CA that issues its time-stamping certificates); `operator` names who runs it and is required. Operators must not share an anchor. |
| `witness` | `[]` | C2SP tlog-witness cosigners: `{ url, vkey, operator, token_file }`. Requests go to `<url>/add-checkpoint`; `vkey` is the witness's `cosignature/v1` verifier key; `operator` defaults to the key name. |
| `allow_self_anchoring` | `false` | Start without an independent witness. |
| `anchor_run_ids` | `"plain"` | `"plain"` puts run ids in anchor leaves; `"hmac"` puts a keyed hash, so the anchor log reveals no run ids. `"hmac"` trades auditability for that privacy: nothing binds a run's anchor key to the run, so an administrator can rewrite an anchored run and anchor it again under a new key without any audit detecting it. Bundles from an `"hmac"` server report `anchor_id_unbound`, and `--log` audits fail with `log_unauditable`. Keep `"plain"` where the omission audit matters; a fix (run ids bound to the log key) is planned for 0.7. |
| `min_independent_operators` | `2` | Distinct witness operators a checkpoint needs before runs count as independently anchored. |

The example configuration uses DigiCert and Sectigo, whose pinned anchors
ship in `deploy/tsa-roots/` (DigiCert by the CA that issues its
time-stamping certificates, Sectigo by its root), with their fingerprints
and how to obtain each independently in `deploy/tsa-roots/README.md`.
Obtain written permission from each TSA operator before automated use; the
server spaces its requests to one TSA at least 15 seconds apart. Qualified
(eIDAS) time-stamping providers, which are paid services, can be configured
like any RFC 3161 TSA.

### `[[retention]]`

Each policy has:

| key | default | meaning |
|---|---|---|
| `match` | `{ prefix = "", labels = {} }` | Runs whose id starts with `prefix` and that carry all of `labels`. |
| `retain_min_days` | `0` | Days after the last append during which content must be kept. |
| `shred_after_days` | `0` | Days after the last append after which every content slot is erased. `0` means never. |
| `delete_after_days` | `0` | Days after the last append after which the run is deleted and its id can never be used again. `0` means never. |
| `erasure` | `"allow"` | `"deny_during_min"` refuses erasure requests while `retain_min_days` applies. |

`shred_after_days` and `delete_after_days` must each be at least
`retain_min_days`. See [Erasure, holds and retention](#erasure-holds-and-retention)
for how several matching policies combine.

### `[redaction]`

| key | default | meaning |
|---|---|---|
| `builtin` | `["email", "phone", "ssn", "card", "iban", "ipv4", "secret"]` | Detectors used for viewers without `view_raw`. `secret` covers API keys, cloud and SaaS tokens, JWTs, bearer credentials, private keys and credential-named values. Individual detector names (`jwt`, `api_key`, ...) work too. |
| `patterns` | `[]` | Extra regular expressions; matches become `[redacted]`. |

### `[[webhooks]]`

| key | default | meaning |
|---|---|---|
| `url` | | Where to POST events. |
| `secret_file` | | A file holding the HMAC secret. |
| `events` | all | Any of `chain_broken`, `anchor_failed`, `regressed`, `erasure`, `retention`, `dangling_effect`, `clock_skew`, `record_missing`, `hold`, `access_log_failed`. |

### `[witness_mode]`

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | Cosign other logs' checkpoints. |
| `name` | `""` | The cosigner name in this witness's signature lines. |
| `key_file` | `""` | The witness key (`keygen --witness` writes it), never the log key. |
| `origins` | `[]` | `{ name, origin, log_vkeys, token_sha256 }`: the configuration name (bound to the log's `witness_client` token, and the `{origin}` of the log endpoint), the checkpoint origin line, the log's verifier keys, and the SHA-256 of the token it authenticates with. No two entries share a name or an origin line. |

### `[license]`

| key | default | meaning |
|---|---|---|
| `licensee` | `""` | Shown in the console footer and in `/v1/info`. Nothing is enforced. |

## Tokens, roles and scopes

Every API request carries a bearer token: `Authorization: Bearer <token>`.
The server stores only each token's SHA-256, compares in constant time, and
shows a token's value once, when it is issued.

Every token names a **principal** (the person or service that uses it) and
has a **role**:

| role | may |
|---|---|
| `agent` | in scope: create runs, take leases, append, read a journal while holding its lease, read summaries and entries |
| `auditor` | in scope: list and read runs (redacted unless `view_raw`), download journals (`view_raw` only), verify, evidence, anchors, and the access log of in-scope runs |
| `admin` | everything, including tokens, erasure, holds, retention and the whole access log |
| `witness_client` | witness mode only, bound to one origin |

**Scopes** are run-id prefixes and are required for every role except
`admin`. `["*"]` means every run and must be written out. A run outside a
token's scopes does not exist for it: the API answers `404`, the same as
for a run that does not exist, and lists leave it out. An admin token
covers every run (tokens, holds and the whole access log cannot be
scoped), so issuing one with narrower scopes is refused; for narrower
access, issue an auditor or agent token.

Issue, list and revoke tokens with the `token` subcommand, which talks to a
running server with an admin token from `PRAGMATIC_TOKEN` (or
`--token-file`):

```sh
export PRAGMATIC_TOKEN=prag_...           # an admin token
pragmatic-server token new --name ci-agents --principal svc-ci \
    --role agent --scope "ci:"            # prints the token once
pragmatic-server token new --name audit --principal auditor@example.com \
    --role auditor --scope "*" --expires-at 2027-01-01T00:00:00Z
pragmatic-server token list
pragmatic-server token revoke tok_0123456789abcdef
```

The same operations are `POST /v1/tokens`, `GET /v1/tokens` and
`DELETE /v1/tokens/{id}`. Each issue and revocation is recorded in the
access log before it takes effect; the record of an issue names the new
token's id, and each token records the token that issued it
(`created_by`).

**Console.** Signing in to the console exchanges a token for a session
cookie (HTTP-only, `SameSite=Strict`, `Secure` over HTTPS). Sessions end
after 15 minutes without a request or 12 hours after sign-in. Revoking a
token ends its sessions at once. See [The console](#the-console).

## The console

The console is at `/console`, rendered by the server with
`pragmatic-console`, the renderer the CLI's `export` and `serve` use, so a
run looks the same wherever it is read.

- **Runs**, filtered by run id prefix, run id or label value, a label,
  program, status and update dates, a page at a time.
- **A run**: its facts, attempts, the timeline (branches and parallel
  regions as nested lanes, intents with their results, erased, withheld and
  ref slots, notes, custody) a page at a time, its verification, and its
  anchoring: independently anchored (with the operators and the time they
  vouch for), anchored by the operator's signature only, or unanchored.
  Without `view_raw`, content is shown through the same redaction as the
  API. Auditors and administrators download evidence bundles from it;
  administrators erase slots from it.
- **The access log**: every record for administrators, the records of
  in-scope runs for auditors, personal fields withheld without `view_raw`.
- **Holds and retention** (administrators): place and remove holds, see
  the retention policies, run retention now.
- **Tokens** (administrators): issue (the value is shown once) and revoke.
- The footer names the viewer and the licensee (`[license] licensee`).

Every page carries a Content-Security-Policy that loads and runs nothing
(no script at all, styles inline, the one image a data URI) and lets forms
submit only to the console itself; pages are never cached or framed. Every
form that changes something carries the session's CSRF token, is refused
when a browser marks it as sent from another site, and acts through the
same operations as the API, so the access log and the erasure ledger
record it the same way. The sign-in form carries an anti-forgery value of
its own. Sign-in and sign-out are recorded in the access log. Console
sessions live in memory: a restart signs everyone out.

## Leases and appends

The SDK handles this for you; it is described here so you can read the
access log and the custody notes.

- A run has at most one lease. The SDK renews it every third of
  `lease_ttl_secs`. A lease that expires keeps working for its holder until
  another holder asks for the run.
- Renewing needs the same token and the same holder id. A lease granted
  when a run is created has no holder id yet: the first renewal must name
  the lease in the `Pragmatic-Lease` header, which records the holder, so
  another process with the same token cannot take a live lease over.
- When a lease ends (released, taken over, or revoked by a forced erasure)
  the server appends a **custody note** to the run: which token held it,
  the entries before and after, how many append requests it made, and
  whether any entry's clock was off by more than `max_clock_skew_secs`.
- An append that the server already stored (a client resending after a
  lost response) is answered as a duplicate, so retries are always safe.
- A request the server can refuse without its body (no lease, a wrong
  `at`) is refused before the body is read.
- A run's first entry is its `run.start` note naming the run's own id;
  frames that start a run under another id are refused.
- A run that has an effect without a result and no lease activity for twice
  the lease time is reported as `dangling` (webhook `dangling_effect`).

## Erasure, holds and retention

**Erasure** (`POST /v1/runs/{id}/erase`, admin) removes the content of
slots while every chain hash still verifies. Give exactly one of
`"slots": [[cursor, slot], ...]`, `"slots": "all"` or `"match": "text"`,
plus a `reason_code` (and optionally a free-text `reason`, which is stored
in an erasable slot). Erasing a repeated message once erases every copy.

- A live lease blocks erasure (`409 run_locked`) unless `"force": true`,
  which revokes the lease.
- A held run is refused (`409 on_hold`).
- During a retention minimum with `erasure = "deny_during_min"`, erasure is
  refused (`409 retention_locked` with `retain_until`), and the refusal is
  logged with the reason `legal_obligation`.
- If the run's last attempt did not finish successfully, erasure needs
  `"allow_unfinished": true`, because the run can no longer be resumed
  afterwards.
- A refused erasure changes nothing: with `"force": true` the selector is
  checked before the lease is revoked.
- Every erasure is written to the erasure ledger first, then to the run as
  an `erasure` note naming the token and pointing at its access-log
  record, and announced by the `erasure` webhook.
- A journal download in progress when an erasure (or a deletion) commits
  is aborted: it never serves bytes read after the erasure.

**Holds** (`POST /v1/holds`, admin) name a matter and a scope of either
explicit `run_ids` or a `prefix`:

```json
{"matter": "Case 12", "scope": {"run_ids": ["research-p1", "research-p2"]}}
{"matter": "Case 12", "scope": {"prefix": "research-p"}}
```

`GET /v1/holds` lists them and `DELETE /v1/holds/{id}` removes one. A held
run cannot be erased, shredded or deleted. A prefix hold also covers runs
created after it. Placing and removing a hold are erasure-ledger records
too (with the hold), so a restore places and removes them again, and each
is announced by the `hold` webhook (without the matter).

**Retention** runs hourly and on demand (`POST /v1/retention/run`). Ages
count from the run's last append. Runs with a live lease are skipped and
checked again next time. When several policies match a run, each value is
the most restrictive one:

- the largest `retain_min_days`;
- `deny_during_min` over `allow`;
- the smallest non-zero `shred_after_days` and `delete_after_days`, but
  never earlier than the combined `retain_min_days`.

A deleted run leaves a tombstone: its id answers `410 run_deleted` forever
and cannot be created again. Once the tombstone is written the run is
deleted, even if some of its files cannot be removed yet (the next start
removes them). Runs with ids starting `pragmatic:` (the server's own
records) and the access log are never touched by retention.

**Subjects.** If the SDK's `run.start` names data subjects, an admin can
find their runs with `POST /v1/subjects/search` (`{"subject": "..."}`). The
index holds only keyed hashes, the identifier in the request is never
logged, and erasing the subjects slot removes the run from the index.

## Redaction

A token without `view_raw` sees content through redaction:

- Images, PDFs, audio and other binary data inside JSON (base64 image
  blocks, `data:` URLs, `file_data`, `b64_json`, `input_audio`, encoded
  bytes) are replaced by `[binary media_type=... bytes=... sha256=...]`
  and never served. JSON that is not strict (a repeated key, deep nesting)
  is read in every copy of a repeated key for this, so its binary fields
  are found too.
- Text is redacted with the built-in detectors and your patterns, and so
  are JSON object keys (a map keyed by email address is common). Keys that
  redact alike get a suffix: `[email]`, `[email] (2)`.
- Content that is not JSON is redacted as text, and any run of 256 or more
  base64 characters in it is withheld as binary.
- A streamed model reply holds its text in deltas of a few characters,
  where no detector sees an email or a number split across them. When its
  reassembled text holds something a detector or pattern finds, the view
  shows that text, redacted, instead of the events, and a `detectors`
  bundle withholds the slot.
- Content that is not UTF-8 is described, never served.
- Evidence bundles for a token without `view_raw` are `detectors` or
  `all`: `binary` withholds attachments only and leaves text in clear.

Redaction is a view: the journal keeps its bytes, and an auditor with
`view_raw` sees them. Redaction does not look inside images, PDFs or
audio, and pattern-based redaction is not de-identification: treat
redacted views as a way to limit exposure, not as anonymized data.

## The access log

Every request to `/v1` and to the console is recorded in
`<data_dir>/audit/access.journal`, including refused ones (401, 403, 404):
token id, role, method, the route template (never the raw path), run id,
status, whether raw content was served, the cursors read, and the names of
query parameters (never their values, at most 32 names). A run id that is
not well formed is recorded as its length and SHA-256 only, so a request
cannot write arbitrary bytes into the log. The principal, source address
and user agent are kept apart from those fields, in the record's payload
slot.

The access log is a security record and is retained: retention policies
never shred it, and this build has no operation that erases its records.
Keeping the personal fields in a payload slot means they could be erased
while the log's chain still verifies; whether and when to do that is for
your records policy, and this build does not offer it.

Erasure, holds, retention, token changes and raw-content reads are recorded
durably before they act. If the access log cannot be written, every
authenticated request is refused with `503 storage_unavailable` until the
problem is fixed and the server restarted: a server that cannot record who
read what serves nothing. `/readyz` then answers 503 (so a load balancer or
Kubernetes stops sending traffic), the `pragmatic_access_log_failed` gauge
is 1, and the `access_log_failed` webhook fires; `/healthz` stays up.

Admins read the log with `GET /v1/audit`; auditors read the records of runs
in their scopes. Viewers without `view_raw` see the personal fields as
`[withheld]`. Each record carries its chain hash (`hash`), and auditors see
the access log's anchor leaves, so a record can be checked against an
anchored head. A read examines at most 4,096 records and returns where to
continue (`next`), whether or not anything matched.

At startup the server records `config.loaded` with the SHA-256 of the
configuration file, the accepted token ids and the signing key id.

## Alerts and metrics

**Webhooks** POST JSON with the event, the run id and counts, never
content. Each request carries
`Pragmatic-Signature: sha256=<HMAC-SHA-256(secret, body)>`; check it before
trusting the body. Deliveries are retried with backoff for up to 24 hours
while the server runs.

**`/metrics`** (Prometheus text, no token) carries no run ids and no label
values:

| metric | meaning |
|---|---|
| `pragmatic_appends_total` | accepted appends |
| `pragmatic_append_seconds` | server-side append latency, fsync included (histogram) |
| `pragmatic_runs` | runs stored |
| `pragmatic_anchor_failures_total` | failed anchoring batches or witnesses |
| `pragmatic_chain_broken_total` | journals found damaged |
| `pragmatic_dangling_effects` | runs with an effect left without a result |
| `pragmatic_tokens_total{kind}` | tokens `issued`, `revoked`, and credentials `rejected` |
| `pragmatic_tokens_active` | tokens currently accepted |
| `pragmatic_access_log_lag_seconds` | age of the oldest access record not yet durable |
| `pragmatic_access_log_failed` | 1 once the access log cannot be written (every authenticated request is refused until a restart) |
| `pragmatic_anchor_lag_seconds` | age of the oldest append not yet independently anchored, measured by the server from its runs |

Alert on `pragmatic_chain_broken_total`, `pragmatic_anchor_failures_total`,
`pragmatic_access_log_failed` and a growing
`pragmatic_anchor_lag_seconds`: the anchoring lag is the window in which
someone with access to the disk could rewrite history without detection.
On a server with no independent witness (`allow_self_anchoring`), it grows
from the first append.

A journal is reported damaged (`chain_broken`) when its chain or a
commitment fails, when it holds fewer entries than were acknowledged or a
different history, and when its erasure accounting does not add up
(content erased without an `erasure` note, which is tampering). A damaged
run refuses writes; one whose only finding is slots an erasure note lists
that hold content again can be repaired by erasing them again. Its verify
report is never ok (`damaged` names why); entries, slots and the console
show the part of it that still verifies, while a journal download and an
evidence bundle answer `409 chain_broken`. `verify-data` lists every
damaged and missing run in `failing_run_ids` and counts them in
`runs_failing`.

## Witness mode

With `[witness_mode] enabled`, the server cosigns other logs' checkpoints
under the C2SP tlog-witness protocol (`POST /add-checkpoint`, also at
`POST /v1/witness`), with the same checks as the anchoring library's
witness. Create the witness key with `keygen --witness`; it prints the
vkey logs configure in their `[anchoring] witness`. Each log authenticates
with a `witness_client` token bound to its origin entry, and the server
checks the log's signature and the consistency proof from the last
checkpoint it cosigned, refusing forks.

Every cosigned checkpoint is recorded, before the cosignature is returned,
in the server-written run `pragmatic:witness:<name>`, which is anchored
like any other run; a fork attempt is recorded there too, as a
`witness.reject` note. `GET /v1/witness/log/{name}?after=<cursor>`
(administrators, and auditors whose scopes cover that run; leave `after`
out for the first page, then pass each page's `next` until it is null)
answers `{origin, origin_line, witness, cosigned, next}`, where each
`cosigned[].checkpoint` is the signed note with this witness's cosignature
line. An auditor's `--witness-log` file is `{"witness": witness, "origin":
origin_line, "checkpoints": [every cosigned[].checkpoint, page by page, in
order]}`.

The witness never cosigns from a record that may have forgotten what it
cosigned, since it could then cosign a fork of a tree it already vouched
for: a damaged record, one that holds less than its last leaf in this
server's anchor log, one restored from a backup, and one whose files are
gone while the anchor log holds a leaf for it. For such an origin
`add-checkpoint` answers `503`, and the record is never begun afresh. To
resume, take the latest checkpoint this witness cosigned for the origin
from outside the host (the witnessed log keeps its cosignatures; a
Pragmatic Server keeps them under `anchors/witness/`), as the signed note
with this witness's cosignature line, and run:

```sh
pragmatic-server witness-resume example-log --checkpoint latest-cosigned.note \
    --reason "restored from the 2026-10-13 backup"
```

The checkpoint must carry the log's signature and this witness's valid
cosignature, and must not be older than, or conflict with, a cosignature
the record still holds. It is recorded as a `witness.resume` note
(`resumed: true` in the log endpoint), and cosigning continues from it.
`accept-regression` does not apply to witness records.

## Sizing and limits

- **Disk.** Journals are about the size of the content agents send and
  receive, plus about 100 bytes per entry; repeated messages of 256 bytes
  or more are stored once. The access log grows by roughly 300 to 500 bytes
  per request and is never shredded; its offset index
  (`audit/access.index`, 20 bytes per record) is rebuilt from it at every
  start. Use an SSD: every append waits for an fsync.
- **Memory.** About 1 KiB per stored run for the index, plus the full
  journal of every run that is being written to (it is loaded while its
  lease is active), plus up to 64 MiB of frame offsets for reading entries
  by position, plus up to 1 GiB of journals held whole by verification and
  evidence at once. Nothing is kept per access-log record. Reading entries
  or a slot reads those frames only (at most 64 MiB of frames per page);
  journal downloads, backups and restores stream.
- **CPU.** Appends are dominated by fsync; verification reads every
  journal, so give auditor-heavy deployments more cores.
- **Limits per client.** A request's headers must arrive within 30
  seconds (an idle kept-alive connection is closed after that too), at most
  4,096 connections are served at once (more wait to be accepted), request
  bodies being received share a budget of 1 GiB (or `max_request_bytes`,
  if larger), and a body must arrive at 256 KiB per second after a
  30-second grace period.
- **Targets** (release build on Linux, 4 vCPU, SSD): one-frame appends of
  up to 64 KiB with a p50 of 5 ms and a p99 of 25 ms server-side, at least
  1,000 appends per second across 200 concurrent runs, startup within 30
  seconds with a million runs, journals up to 1 GiB. The load test is
  `cargo test -p pragmatic-server --release --test perf -- --ignored`, and
  it checks those targets, so run it on comparable hardware. On macOS,
  where every append waits for a full flush to the disk (`F_FULLFSYNC`),
  the append targets are expected to fail: on an Apple silicon laptop the
  test measured about 880 appends per second, with only a few percent of
  appends inside 25 ms.
- **Open files.** Each run being written keeps its journal open; set the
  file limit well above your number of concurrent runs.

## Backup and restore

**Backup** works while the server runs:

```sh
pragmatic-server backup --to /backups/pragmatic-2026-10-13
```

It copies every journal up to the length the server last recorded for it,
the tombstones, anchors, access log, tokens, holds, keys and the erasure
ledger, and writes `manifest.json` listing every file's SHA-256, signed
with the server's key. Appends from the last second before the backup may
be left out. The manifest records the erasure ledger's position from
*before* any journal was copied, so an erasure, deletion or hold change
made while the backup runs is applied again by a restore. The backup holds
personal data and token hashes: encrypt and protect it like the data
volume.

**Stream the erasure ledger off the host.** A backup taken before an
erasure still contains the erased content, and one taken before a legal
hold lacks the hold. To make sure a restore never brings erased data back
or loses a hold, keep a copy of `<data_dir>/erasure-ledger.jsonl`
somewhere else as it grows, by shipping the file. (The `erasure`,
`retention` and `hold` webhooks announce each record, but a hold's matter
is only in the file.)

**Restore** needs the server stopped and an empty data directory:

```sh
pragmatic-server restore --from /backups/pragmatic-2026-10-13 \
    --erasure-ledger /offsite/erasure-ledger.jsonl
```

It checks the manifest's signature against keys it trusts from outside the
backup: the configured signing key and the keys it replaced (which
`keygen --rotate` keeps next to it). Anyone who can write the backup can
write its key ring too, so a key the backup names proves nothing. To
restore a backup signed by a key this host does not have, name its public
key with `--trust-key <64 hex digits>` (repeatable). The restore checks
every file's hash as it copies it, then re-applies every ledger record
newer than the backup, in order: erasures and shreds are performed again,
deleted runs are deleted again, and holds are placed and removed again.
Leases restored from the backup are ended, each with a custody note in its
run. Runs that now have fewer entries than were anchored are marked
`regressed`: appends to them answer `409 regressed` until an admin accepts
the restored history with `pragmatic-server accept-regression RUN`, which
is logged. The restore itself is recorded in the access log.

### Restoring the anchor log

The backup's anchor log is as old as the backup, and the server went on
signing checkpoints after it. A restored server that signed on from it
would sign other trees under sequence numbers and sizes it already signed,
under the same key and origin: a fork of its own log, which every
checkpoint it handed out since (in bundles, to TSAs and witnesses)
contradicts, and which a witness records as a fork attempt. So:

- **If the anchors directory survived** (keep `<data_dir>/anchors` on its
  own volume, or copy it off the host as it grows), restore it in place of
  the backup's: `restore --from DIR --anchors /surviving/anchors`. It must
  continue the backup's log (every checkpoint of the backup's is in it,
  naming the same tree). Anchoring continues where it was, and runs the
  log knows but the backup lacks show as `missing`.
- **Otherwise anchoring is held** after the restore: no checkpoint is
  signed, `anchor=now` answers `503`, and the server says so at startup.
  With the server stopped, lift the hold one of two ways:
  - `pragmatic-server confirm-anchors --checkpoint newest.note`, with the
    newest checkpoint the log published (a witness's log, or the newest
    evidence bundle's `latest_checkpoint`). It must be the restored log's
    latest: then nothing was signed after the backup, and anchoring
    resumes.
  - `pragmatic-server confirm-anchors --new-log` begins a new log under a
    new key, which is a new origin: generate it first with
    `pragmatic-server keygen` into a new key file and point
    `keys.signing_key_file` at it. The held log moves to
    `anchors.retired-<ms>/` (keep it: earlier bundles verify against it),
    the old keys' validity ends, every run is anchored in the new log
    afresh, and an `anchors.new_log` access record names the old origin
    and its latest checkpoint, which the new log's first batch anchors.
    Onboard the new origin at every witness that cosigned the old one.

In witness mode every restored witness record is held as well: it has
forgotten every cosignature made after the backup. Resume each with
`witness-resume` (see [Witness mode](#witness-mode)).

**Verification.** `pragmatic-server verify-data` (on a running server, or
`--offline` when it is stopped) re-verifies every chain, commitment and
anchor proof and records the result in the access log. The server also runs
it every `verify_interval_hours`.

## Upgrades

- Read the changelog for the version you are moving to.
- Take a backup.
- Stop the old server, start the new one. Two servers never share a data
  directory (the second exits), and with Kubernetes the `OnDelete` update
  strategy starts the new pod only after you delete the old one.
- If the new version uses a newer data format, it refuses to start until
  you run `pragmatic-server migrate`. A server also refuses a data format
  newer than its own.
- SDKs resend requests while the server restarts and resume where they
  were, so agents keep running through a restart shorter than the lease
  deadline.

**Key rotation.** `pragmatic-server keygen --rotate` (server stopped)
replaces the signing key: the old key's validity ends, the new key's
begins, both sign a `key.rotate` record in the access log, and the old key
file is kept beside the new one. `GET /v1/keys` lists every key with its
validity window, so earlier signatures stay checkable.

## Command reference

| command | what it does |
|---|---|
| `serve` | run the server |
| `keygen [--rotate \| --witness \| --anchor-key]` | write the log key (printing its origin and vkey), rotate it (server stopped), or write the witness-mode key or the anchor key; never over an existing file |
| `token new\|revoke\|list` | manage tokens on a running server |
| `token bootstrap` | print a fresh token and its SHA-256 for `[bootstrap]` |
| `backup --to DIR` | copy the data directory while the server runs |
| `restore --from DIR [--erasure-ledger FILE] [--trust-key HEX] [--anchors DIR]` | restore into an empty data directory; without `--anchors` anchoring is held |
| `confirm-anchors (--checkpoint FILE \| --new-log)` | lift the hold on a restored or forked anchor log (server stopped) |
| `verify-data [--offline]` | verify everything now |
| `verify-evidence FILE` | points to `pragmatic verify-evidence`, the CLI an auditor verifies bundles with |
| `migrate` | bring the data directory to this build's format |
| `accept-regression RUN` | accept a regressed run's history (logged) |
| `witness-resume ORIGIN --checkpoint FILE [--reason TEXT]` | resume a held witness record from the latest checkpoint it cosigned (logged) |

Every command takes `--config FILE` (or `PRAGMATIC_CONFIG`). Commands that
talk to a running server take `--url` (default: `public_url`, or
`http://<listen>`) and read the admin token from `PRAGMATIC_TOKEN` or
`--token-file`, never from the command line.
