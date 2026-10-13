# Pragmatic Server

Pragmatic Server stores the journals your agents write, so that every run
has one durable, access-controlled record that you can audit, export as
evidence, erase for privacy law and keep or delete by policy. This guide
covers installing it, configuring it, issuing tokens, sizing, backups and
upgrades.

Pragmatic Server is licensed under the Business Source License 1.1. You may
use it for development, testing and evaluation. Production use needs a
commercial license from Pragmatic Research, Inc. Each version becomes
Apache-2.0 four years after its release. The SDKs, the CLI and the journal
format are Apache-2.0.

Contents: [How it works](#how-it-works) ·
[Install](#install) · [First start](#first-start) ·
[Configuration reference](#configuration-reference) ·
[Tokens, roles and scopes](#tokens-roles-and-scopes) ·
[Leases and appends](#leases-and-appends) ·
[Erasure, holds and retention](#erasure-holds-and-retention) ·
[Redaction](#redaction) · [The access log](#the-access-log) ·
[Alerts and metrics](#alerts-and-metrics) · [Witness mode](#witness-mode) ·
[Sizing](#sizing) · [Backup and restore](#backup-and-restore) ·
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
  anchored history can be detected.
- **Erasure** removes the content of chosen slots while the chain still
  verifies. **Holds** stop erasure and retention for runs under legal hold.
  **Retention** policies shred or delete runs after a set time.

No component makes network connections except the server to the TSAs,
witnesses and webhook URLs you configure. There is no telemetry.

## Install

Pick one:

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
2. **Create the signing key**, outside the data directory:
   ```sh
   pragmatic-server --config /etc/pragmatic/pragmatic.toml keygen
   ```
   (`openssl genpkey -algorithm ed25519 -out /etc/pragmatic/server.ed25519`
   works too.) Keep it readable only by the server's user.
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
- the signing key is inside `data_dir` (a backup of the data would then
  carry the key that signs it) and `allow_key_in_data_dir` is false;
- the data directory has a data format this build does not know;
- the access log is damaged (the server will not append to a log whose
  history it cannot vouch for).

`/healthz` answers as soon as the process listens. `/readyz` and every run
endpoint answer `503 starting` until the index of runs is built; full
verification of every journal then continues in the background.

## Configuration reference

The configuration is TOML. Unknown keys are refused, so a misspelled
setting cannot silently fall back to its default.

### Top level

| key | default | meaning |
|---|---|---|
| `name` | host name | The server's name. Anchoring checkpoints use the origin `pragmatic/<name>`; witness mode cosigns under it. |
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
| `signing_key_file` | `"/etc/pragmatic/server.ed25519"` | The Ed25519 key (PKCS#8 PEM) that signs checkpoints, backup manifests and key rotations. |
| `allow_key_in_data_dir` | `false` | Allow the key inside `data_dir`. |

### `[bootstrap]`

| key | default | meaning |
|---|---|---|
| `admin_token_sha256` | `""` | SHA-256 (lowercase hex) of the first admin token. |

### `[anchoring]`

| key | default | meaning |
|---|---|---|
| `interval_secs` | `600` | Seconds between anchoring batches (60 to 3600). A batch also runs within 30 seconds after an agent finishes successfully. |
| `tsa` | `[]` | RFC 3161 time-stamping authorities: `{ url, roots_pem, operator }`. `roots_pem` is the pinned root certificate file; `operator` names who runs it (default: the URL's host). |
| `witness` | `[]` | C2SP tlog-witness cosigners: `{ url, public_key, token_file, name, operator }`. |
| `allow_self_anchoring` | `false` | Start without an independent witness. |
| `anchor_run_ids` | `"plain"` | `"plain"` puts run ids in anchor leaves; `"hmac"` puts a keyed hash, so the anchor log reveals no run ids. |
| `min_independent_operators` | `2` | Distinct witness operators a checkpoint needs before runs count as independently anchored. |

The example configuration uses DigiCert and Sectigo, whose roots ship in
`deploy/tsa-roots/`. Ask TSA operators for written permission before
automated use. Qualified (eIDAS) time-stamping providers are available as a
paid option.

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
| `events` | all | Any of `chain_broken`, `anchor_failed`, `regressed`, `erasure`, `retention`, `dangling_effect`, `clock_skew`, `record_missing`. |

### `[witness_mode]`

| key | default | meaning |
|---|---|---|
| `enabled` | `false` | Cosign other logs' checkpoints. |
| `origins` | `[]` | `{ name, token_sha256, public_key }`: the log's origin line, the SHA-256 of the token it authenticates with, and its signed-note verifier key. |

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
for a run that does not exist, and lists leave it out.

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
access log before it takes effect.

**Console.** Signing in to the console exchanges a token for a session
cookie (HTTP-only, `SameSite=Strict`, `Secure` over HTTPS). Sessions end
after 15 minutes without a request or 12 hours after sign-in. Revoking a
token ends its sessions at once.

## Leases and appends

The SDK handles this for you; it is described here so you can read the
access log and the custody notes.

- A run has at most one lease. The SDK renews it every third of
  `lease_ttl_secs`. A lease that expires keeps working for its holder until
  another holder asks for the run.
- When a lease ends (released, taken over, or revoked by a forced erasure)
  the server appends a **custody note** to the run: which token held it,
  the entries before and after, how many append requests it made, and
  whether any entry's clock was off by more than `max_clock_skew_secs`.
- An append that the server already stored (a client resending after a
  lost response) is answered as a duplicate, so retries are always safe.
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
- Every erasure is written to the run as an `erasure` note naming the token
  and pointing at its access-log record, to the erasure ledger, and to the
  `erasure` webhook.

**Holds** (`POST /v1/holds`, admin) name a matter and either explicit
`run_ids` or a `prefix`. A held run cannot be erased, shredded or deleted.
A prefix hold also covers runs created after it.

**Retention** runs hourly and on demand (`POST /v1/retention/run`). Ages
count from the run's last append. Runs with a live lease are skipped and
checked again next time. When several policies match a run, each value is
the most restrictive one:

- the largest `retain_min_days`;
- `deny_during_min` over `allow`;
- the smallest non-zero `shred_after_days` and `delete_after_days`, but
  never earlier than the combined `retain_min_days`.

A deleted run leaves a tombstone: its id answers `410 run_deleted` forever
and cannot be created again. Runs with ids starting `pragmatic:` (the
server's own records) and the access log are never touched by retention.

**Subjects.** If the SDK's `run.start` names data subjects, an admin can
find their runs with `POST /v1/subjects/search` (`{"subject": "..."}`). The
index holds only keyed hashes, the identifier in the request is never
logged, and erasing the subjects slot removes the run from the index.

## Redaction

A token without `view_raw` sees content through redaction:

- Images, PDFs, audio and other binary data inside JSON (base64 image
  blocks, `data:` URLs, `file_data`, `input_audio`, encoded bytes) are
  replaced by `[binary media_type=... bytes=... sha256=...]` and never
  served.
- Text is redacted with the built-in detectors and your patterns.
- Content that is not UTF-8 is described, never served.

Redaction is a view: the journal keeps its bytes, and an auditor with
`view_raw` sees them. Redaction does not look inside images, PDFs or
audio, and pattern-based redaction is not de-identification: treat
redacted views as a way to limit exposure, not as anonymized data.

## The access log

Every request to `/v1` and to the console is recorded in
`<data_dir>/audit/access.journal`, including refused ones (401, 403, 404):
token id, role, method, the route template (never the raw path), run id,
status, whether raw content was served, the cursors read, and the names of
query parameters (never their values). The principal, source address and
user agent are kept in an erasable slot.

Erasure, holds, retention, token changes and raw-content reads are recorded
durably before they act. If the access log cannot be written, every
authenticated request is refused with `503 storage_unavailable` until the
problem is fixed and the server restarted: a server that cannot record who
read what serves nothing. Admins read the log with `GET /v1/audit`;
auditors read the records of runs in their scopes.

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
| `pragmatic_anchor_lag_seconds` | age of the oldest append not yet anchored |

Alert on `pragmatic_chain_broken_total`, `pragmatic_anchor_failures_total`
and a growing `pragmatic_anchor_lag_seconds`: the anchoring lag is the
window in which someone with access to the disk could rewrite history
without detection.

## Witness mode

With `[witness_mode] enabled`, the server cosigns other logs' checkpoints
under the C2SP tlog-witness protocol (`POST /add-checkpoint`, also at
`POST /v1/witness`). Each log authenticates with a `witness_client` token
bound to its origin, and the server checks the log's signature and the
consistency proof from the last checkpoint it cosigned, refusing forks.
Every cosigned checkpoint is recorded in the server-written run
`pragmatic:witness:<origin>`, which is anchored like any other run;
`GET /v1/witness/log/{origin}` serves the history.

## Sizing

- **Disk.** Journals are about the size of the content agents send and
  receive, plus about 100 bytes per entry; repeated messages of 256 bytes
  or more are stored once. The access log grows by roughly 300 to 500 bytes
  per request and is never shredded. Use an SSD: every append waits for an
  fsync.
- **Memory.** About 1 KiB per stored run for the index, plus the full
  journal of every run that is being written to (it is loaded while its
  lease is active), plus up to 256 MiB of parsed journals cached for
  readers.
- **CPU.** Appends are dominated by fsync; reads of large journals parse
  them, so give auditor-heavy deployments more cores.
- **Targets** (release build, 4 vCPU, SSD): one-frame appends of up to
  64 KiB with a p50 of 5 ms and a p99 of 25 ms server-side, at least 1,000
  appends per second across 200 concurrent runs, startup within 30 seconds
  with a million runs, journals up to 1 GiB. The load test is
  `cargo test -p pragmatic-server --release --test perf -- --ignored`.
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
be left out. The backup holds personal data and token hashes: encrypt and
protect it like the data volume.

**Stream the erasure ledger off the host.** A backup taken before an
erasure still contains the erased content. To make sure a restore never
brings it back, keep a copy of `<data_dir>/erasure-ledger.jsonl` somewhere
else as it grows (for example by shipping the file, or by recording the
`erasure` and `retention` webhooks).

**Restore** needs the server stopped and an empty data directory:

```sh
pragmatic-server restore --from /backups/pragmatic-2026-10-13 \
    --erasure-ledger /offsite/erasure-ledger.jsonl
```

It checks the manifest's signature and every file's hash, copies the data,
and then re-applies every ledger record newer than the backup: erasures
and shreds are performed again and deleted runs are deleted again. Runs
that now have fewer entries than were anchored are marked `regressed`:
appends to them answer `409 regressed` until an admin accepts the restored
history with `pragmatic-server accept-regression RUN`, which is logged. The
restore itself is recorded in the access log.

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
| `keygen [--rotate]` | write a new signing key, or rotate it (server stopped) |
| `token new\|revoke\|list` | manage tokens on a running server |
| `token bootstrap` | print a fresh token and its SHA-256 for `[bootstrap]` |
| `backup --to DIR` | copy the data directory while the server runs |
| `restore --from DIR [--erasure-ledger FILE]` | restore into an empty data directory |
| `verify-data [--offline]` | verify everything now |
| `verify-evidence FILE` | verify an evidence bundle |
| `migrate` | bring the data directory to this build's format |
| `accept-regression RUN` | accept a regressed run's history (logged) |

Every command takes `--config FILE` (or `PRAGMATIC_CONFIG`). Commands that
talk to a running server take `--url` (default: `public_url`, or
`http://<listen>`) and read the admin token from `PRAGMATIC_TOKEN` or
`--token-file`, never from the command line.
