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
  (Apache-2.0, no third-party dependencies).
- `tools/verify_evidence.py`, a reference verifier that needs only Python
  3 and `openssl`. It shares no code with the first: it has its own
  journal, JSON, DER and signed-note parsers and its own Ed25519, so two
  independent programs agreeing on a bundle is stronger evidence than one.

Both check everything, including the Ed25519 signatures of the log, the
witnesses and the bundle, and both take the same flags. Neither is on a
package registry yet: from a clone of the repository, install the first
with `cargo install --path crates/pragmatic-cli`, and run the second as
`python3 tools/verify_evidence.py`. To watch a bundle being produced by
Pragmatic Server and checked both ways, including with the wrong roots and
with one byte changed, run the demo (`examples/demo/run.sh`, step 6).

Both need OpenSSL (version 3 or later) to check RFC 3161 time-stamps, and
use the first `openssl` on your `PATH` that can. macOS ships LibreSSL as
`/usr/bin/openssl`, which cannot check a time-stamp at the time it was
made; it is skipped, and if it is the only one the report says the
time-stamps were not checked (install OpenSSL 3, for example with
Homebrew, and put it first on `PATH`). `--openssl` makes a missing or
unusable OpenSSL an error instead.

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
  checked. Pragmatic Server's example configuration uses DigiCert (root
  "DigiCert Trusted Root G4") and Sectigo (root "USERTrust RSA
  Certification Authority"). Give each file the name of the company that runs it
  (`--tsa-roots OPERATOR=FILE`; the name is required). Every certificate
  in the file is trusted as an anchor, so you can pin the CA that issues
  the authority's time-stamping certificates instead of its root, which
  is narrower: under a public root, others can buy time-stamping
  certificates too.
- **Witness keys.** For each cosigning witness you trust, its verifier key
  (a line such as `witness.example.com+1a2b3c4d+BA...`), from the witness
  operator, and the name of that operator.
- **The log key** of the server that produced the bundle, from its
  operator through a channel you trust (not from the bundle). It lets you
  check the server's checkpoint and bundle signatures, and you need it to
  rule out a log built by someone other than the operator: anyone can
  build a Merkle log for a journal of their own, sign it with a key of
  their own under the log's name, and have public time-stamp authorities
  stamp it, since they stamp whatever they are sent. Without the log key
  those signatures are reported as *operator-asserted*: they show the
  bundle is internally consistent, not who made it. With it, the bundle
  must carry the log's signature: an unsigned bundle, or one signed by
  another key, fails, because only that signature covers the bundle's
  descriptive fields (who asked for it, what made it, its redaction mode
  and the link to this procedure).

Independence is counted by **operator**, not by signature: two time-stamp
authorities run by the same company count once. Entrust is counted as
Sectigo and QuoVadis EU as DigiCert. By default an anchor needs two
distinct operators.

## 3. Run it

```sh
pragmatic verify-evidence support-ticket-4127.evidence.json \
  --tsa-roots digicert=DigiCertTimeStampingCA.pem \
  --tsa-roots sectigo=USERTrustRSACertificationAuthority.pem \
  --witness-key "witness-operator=witness.example.com+1a2b3c4d+BA..." \
  --log-key "pragmatic/acme/0123456789abcdef+5e6f7a8b+AQ..."
```

(`deploy/tsa-roots/README.md` lists the anchors Pragmatic Server's example
configuration pins, with their fingerprints and where to obtain each
yourself. The log key is the vkey `pragmatic-server keygen` printed; get
it from the operator out of band.)

or with the reference verifier, with the same flags:

```sh
python3 tools/verify_evidence.py support-ticket-4127.evidence.json \
  --tsa-roots digicert=DigiCertTimeStampingCA.pem \
  --tsa-roots sectigo=USERTrustRSACertificationAuthority.pem \
  --witness-key "witness-operator=witness.example.com+1a2b3c4d+BA..." \
  --log-key "pragmatic/acme/0123456789abcdef+5e6f7a8b+AQ..."
```

Nothing is sent anywhere: both tools work offline. A trust input that is
malformed or cannot be read (a mistyped key, a missing root file) stops
the tool with exit code 64 before anything is verified, so a mistake in
your own command line never reads as a verdict on the bundle.

## 4. Read the result

The last line, and the exit code, give the verdict:

| verdict | exit | meaning |
|---|---|---|
| `VERIFIED` | 0 | The whole journal is anchored by at least two independent operators you trust. |
| `VERIFIED (PARTIAL)` | 2 | A prefix is anchored that way; the report says how many entries at the end are not. Entries after the last anchor could have been changed by the operator without detection. |
| `UNANCHORED` | 3 | The journal is internally intact, but nothing you trust ties it to a time. It could have been rewritten whole. |
| `FAILED` | 1 | Something does not check out: the bundle is not what it claims to be, or an audit you asked for (`--log`, `--witness-log`) could not be completed. |

Above the verdict the report lists each step of the procedure with
`pass`, `FAIL`, `info` or `skip`, each anchor with its witnesses, and every
finding with a code. Each witness is classified:

- **trusted**: it verified against a root or key you pinned, and counts
  for that root's or key's operator;
- **self-asserted**: it did not, so it counts for nothing (a self-signed
  time-stamp, a witness key you did not pin);
- **operator-controlled**: the server's own signature, which never counts.

Times come only from signed structures: a TSA's `genTime` plus its stated
accuracy, or a witness's cosignature timestamp. The time reported for an
anchor ("no later than") is one that at least as many distinct operators
as independence needs vouch for (with the default of two, the second
earliest among the operators' times), so no single witness can backdate
an anchor on its own. The bundle's `generated_at` is shown as an unsigned
claim.

Findings you may see, and what to do:

- `tsa_untrusted`: a time-stamp did not verify against any root you
  pinned. Check that you have the right root for that authority; if you
  do, the time-stamp is not evidence.
- `tsa_ambiguous`: a time-stamp verified against the files of two or more
  operators you named (they share a CA, or you pinned one company under
  two names), so it counts for none of them. Pin each operator's own
  issuing CA, or one name per company.
- `cosignature_untrusted`: a witness signed, but you did not pin its key.
- `operator_asserted`: pass the log key to check the server's signatures.
- `anchor_id_unbound`: the server names runs in its log by HMAC, under a
  key the bundle itself supplies. That keeps run ids private from log
  readers, but it means nothing can show that the server did not anchor
  another version of this run under another key: hidden anchors cannot be
  ruled out, even with the full log. Treat such a bundle's anchors as
  showing only that this journal existed by the stated time.
- `unaccounted_erasure`, `withheld_mismatch`, `records_mismatch`,
  `head_mismatch` and the other failures: the bundle was altered or built
  incorrectly. Ask the producer for a new bundle; do not rely on this one.

## 5. Check that nothing is hidden

A bundle lists the run's anchors, and each anchor points at the one
before it, so an anchor removed from the middle is caught. An anchor
removed from the end (a later anchor that shows a different history) is
caught only against the whole log. If you can obtain the server's full
anchor log (`GET /v1/anchors/log` with an administrator token), pass it.
The file is `{"leaves": [...]}`, every leaf's `leaf` hex in order from
index 0; the endpoint serves at most 10,000 leaves per request, so ask for
`from=0`, `from=10000` and so on, and join the pages:

```sh
pragmatic verify-evidence bundle.json ... --log anchors-log.json
```

The verifier recomputes the log's root, checks it against the bundle's
latest checkpoint, and fails with `anchor_omitted` if the log holds a leaf
for this run that the bundle leaves out. For a bundle whose server names
runs by HMAC (`anchor_id` is set), this cannot be shown, and the audit
fails with `log_unauditable` rather than pass.

The full log is checked against the bundle's latest checkpoint, a tree
head the server chose. To rule out a server that forked its log (one
history for you, another for everyone else), check it against a witness
that cosigns the log: pass its cosigned history and its key. A Pragmatic
Server in witness mode serves the history at
`GET /v1/witness/log/{name}?after=`; the file is `{"witness": <the
page's witness>, "origin": <its origin_line>, "checkpoints": [every
page's cosigned[].checkpoint, in order]}`, each checkpoint carrying the
witness's cosignature line.

```sh
pragmatic verify-evidence bundle.json ... --log anchors-log.json \
  --witness-key "witness-operator=witness.example.com+1a2b3c4d+BA..." \
  --witness-log witness-history.json
```

The history counts only if every checkpoint in it is signed by the
witness key you pinned (`witness_log_untrusted` otherwise), and only for
the bundle's own log (`witness_log_origin`). The verifier then checks the
witness's roots against the bundle's checkpoints and against the full
log's own leaves at every size the witness cosigned, and fails with
`witness_log_fork` if they differ: the log showed different histories to
different parties. If the bundle's tree cannot be linked to what the
witness saw (`witness_log_mismatch`), pass a full log that reaches the
witness's latest checkpoint.

## 6. Keep a readable copy

```sh
pragmatic render-evidence bundle.json --format html -o report.html  # plus the same trust flags
pragmatic render-evidence bundle.json --format csv -o records.csv
```

The HTML page shows the verdict, every check, the anchors and the run's
timeline (a long timeline shows its first page; the CSV has every entry).
It makes no network requests and runs no scripts, so it is safe to attach
to a report. The CSV has one row per journal entry for spreadsheets, each
row carrying the verdict and whether the entry is independently anchored;
rows are decoded from the journal itself, never copied from the bundle's
`records`, and a bundle that fails verification is not written as CSV at
all. Cells that a spreadsheet would treat as formulas are prefixed with
`'`. Both commands exit with the verdict's code, like `verify-evidence`.
By default they write next to the bundle; they never write through a
symbolic link that came with it.

## Bundles made from a local journal

`pragmatic evidence RUN -o FILE` packages a run journaled to a local
directory. Such a bundle is unsigned and has no anchors (local anchoring
is planned for 0.7), so its verdict is always `UNANCHORED`: it shows the
journal's integrity (chain, commitments, erasures, records), not when it
existed.
