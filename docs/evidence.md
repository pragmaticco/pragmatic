# Verifying an evidence bundle: an auditor's walkthrough

You have been given a file such as `support-ticket-4127.evidence.json` and
asked whether it can be relied on. This guide walks through checking it
yourself, offline, with trust roots you choose. You do not need to trust
the company that ran the agent, its servers, or Pragmatic.

The exact format and every check are specified in
[evidence-format.md](evidence-format.md). This page explains how to use
them.

## What a bundle can and cannot tell you

A bundle holds the record of one agent run: every model call, tool call,
message received, random draw and clock read made through Pragmatic,
chained together so that changing any entry breaks every link after it.
It also holds **anchors**: proof that the record, up to some length,
existed at a certain time, vouched for by independent parties.

If verification succeeds, you know that the journal up to its anchored
length existed, exactly as you see it, no later than the time the
witnesses signed. You do **not** learn that what the agent was told was
true, that the agent did nothing outside the journaled interfaces, or
anything about the run before its first anchor. Content may also be
withheld for privacy; withheld content is listed and its absence is
checked, but you cannot see it.

## 1. Get the verifier

Either of these implements every check:

- `pragmatic verify-evidence`, part of the `pragmatic` command line tool
  (Apache-2.0, no third-party dependencies). It checks everything,
  including the Ed25519 signatures of the log, the witnesses and the
  bundle.
- `tools/verify_evidence.py`, a reference verifier that needs only Python
  3 and `openssl`. It is short enough to read in an afternoon. It cannot
  check Ed25519 signatures (the Python standard library has none), so it
  says so and counts only time-stamp authorities.

Both need `openssl` (version 3 or later) on your `PATH` to check RFC 3161
time-stamps.

`pragmatic verify-evidence --explain` prints the procedure the tool
implements, so you can compare it with the published document.

## 2. Choose what you trust

Nothing inside the bundle is trusted. The bundle names time-stamp
authorities and witnesses and includes their certificates, but those are
only claims until they check out against roots and keys **you** obtained
independently. Gather:

- **Time-stamp authority roots.** For each time-stamp authority (TSA) you
  are willing to rely on, its root certificate, from the authority's own
  website or your operating system's trust store, with the fingerprint
  checked. Pragmatic Server's default TSAs are DigiCert (root "DigiCert
  Trusted Root G4") and Sectigo (root "USERTrust RSA Certification
  Authority"). Give each root the name of the company that runs it.
- **Witness keys.** For each cosigning witness you trust, its verifier key
  (a line such as `witness.example.com+1a2b3c4d+BA...`), from the witness
  operator, and the name of that operator.
- **The log key** of the server that produced the bundle, from its
  operator through a channel you trust (not from the bundle). It lets you
  check the server's checkpoint and bundle signatures. Without it those
  are reported as *operator-asserted*: they show the bundle is internally
  consistent, not who made it.

Independence is counted by **operator**, not by signature: two time-stamp
authorities run by the same company count once. Entrust is counted as
Sectigo and QuoVadis EU as DigiCert. By default an anchor needs two
distinct operators.

## 3. Run it

```sh
pragmatic verify-evidence support-ticket-4127.evidence.json \
  --tsa-roots digicert=DigiCertTrustedRootG4.pem \
  --tsa-roots sectigo=USERTrustRSACertificationAuthority.pem \
  --witness-key "witness-operator=witness.example.com+1a2b3c4d+BA..." \
  --log-key "pragmatic/acme+5e6f7a8b+AQ..."
```

or with the reference verifier:

```sh
python3 tools/verify_evidence.py support-ticket-4127.evidence.json \
  --tsa-roots digicert=DigiCertTrustedRootG4.pem \
  --tsa-roots sectigo=USERTrustRSACertificationAuthority.pem
```

Nothing is sent anywhere: both tools work offline.

## 4. Read the result

The last line, and the exit code, give the verdict:

| verdict | exit | meaning |
|---|---|---|
| `VERIFIED` | 0 | The whole journal is anchored by at least two independent operators you trust. |
| `VERIFIED (PARTIAL)` | 2 | A prefix is anchored that way; the report says how many entries at the end are not. Entries after the last anchor could have been changed by the operator without detection. |
| `UNANCHORED` | 3 | The journal is internally intact, but nothing you trust ties it to a time. It could have been rewritten whole. |
| `FAILED` | 1 | Something does not check out: the bundle is not what it claims to be. |

Above the verdict the report lists each step of the procedure with
`pass`, `FAIL`, `info` or `skip`, each anchor with its witnesses, and every
finding with a code. Each witness is classified:

- **trusted**: it verified against a root or key you pinned, and counts
  for that root's or key's operator;
- **self-asserted**: it did not, so it counts for nothing (a self-signed
  time-stamp, a witness key you did not pin);
- **operator-controlled**: the server's own signature, which never counts.

Times come only from signed structures: a TSA's `genTime` plus its stated
accuracy, or a witness's cosignature timestamp. The bundle's
`generated_at` is shown as an unsigned claim.

Findings you may see, and what to do:

- `tsa_untrusted`: a time-stamp did not verify against any root you
  pinned. Check that you have the right root for that authority; if you
  do, the time-stamp is not evidence.
- `cosignature_untrusted`: a witness signed, but you did not pin its key.
- `operator_asserted`: pass the log key to check the server's signatures.
- `unaccounted_erasure`, `withheld_mismatch`, `records_mismatch`,
  `head_mismatch` and the other failures: the bundle was altered or built
  incorrectly. Ask the producer for a new bundle; do not rely on this one.

## 5. Check that nothing is hidden

A bundle lists the run's anchors, and each anchor points at the one
before it, so an anchor removed from the middle is caught. An anchor
removed from the end (a later anchor that shows a different history) is
caught only against the whole log. If you can obtain the server's full
anchor log (`GET /v1/anchors/log` with an administrator token), pass it:

```sh
pragmatic verify-evidence bundle.json ... --log anchors-log.json
```

The verifier recomputes the log's root, checks it against the bundle's
latest checkpoint, and fails with `anchor_omitted` if the log holds a leaf
for this run that the bundle leaves out.

If a witness publishes its cosigned history, `--witness-log FILE` checks
every checkpoint in the bundle against it, and fails with
`witness_log_fork` if the witness saw a different root for the same tree
size: the log showed different histories to different parties.

## 6. Keep a readable copy

```sh
pragmatic render-evidence bundle.json --format html -o report.html  # plus the same trust flags
pragmatic render-evidence bundle.json --format csv -o records.csv
```

The HTML page shows the verdict, every check, the anchors and the run's
timeline. It makes no network requests and runs no scripts, so it is safe
to attach to a report. The CSV has one row per journal entry for
spreadsheets; cells that a spreadsheet would treat as formulas are
prefixed with `'`.

## Bundles made from a local journal

`pragmatic evidence RUN -o FILE` packages a run journaled to a local
directory. Such a bundle is unsigned and has no anchors (local anchoring
arrives in 0.7), so its verdict is always `UNANCHORED`: it shows the
journal's integrity (chain, commitments, erasures, records), not when it
existed.
