# Evidence bundle format and verification procedure

Format `pragmatic-evidence/1`. This document is normative: a bundle that
does not follow it is invalid, and a verifier that does not perform every
check below is not a Stet evidence verifier. MUST, MUST NOT and
SHOULD are used as in RFC 2119.

Two independent implementations follow it: `pragmatic verify-evidence`
(the CLI, built on the zero-dependency core crate's `evidence` module) and
`tools/verify_evidence.py` (Python standard library and `openssl` only).
For a walkthrough written for auditors, see [evidence.md](evidence.md).

## 1. What a bundle is, and what it proves

A bundle packages one run's journal so a party that trusts neither the
agent's operator nor Pragmatic Research can check it offline. It carries the
journal (with some slots possibly withheld), the same journal decoded as
readable records, and the run's anchors: leaves of an append-only Merkle
log that commit to the journal's chain head at successive lengths, each
witnessed by time-stamp authorities and cosigning witnesses.

A verified anchor proves that a journal prefix of `entries` entries with
chain head `head` existed no later than the witness time. It does not
prove that the content was true when recorded, that nothing happened
outside the journaled interfaces, or anything about the run before its
first anchor.

Nothing in a bundle is a trust anchor. Every key, root and operator name
the verdict depends on comes from the verifier's own inputs (section 7).

## 2. Strict JSON

A bundle is one JSON text (RFC 8259) with these additional rules. A
verifier MUST reject a bundle that breaks any of them (code
`bundle_json` for the first four, `bundle_schema` for the rest):

- UTF-8 only, no byte-order mark, no lone surrogates (escaped or encoded).
- No object repeats a key.
- Arrays and objects nest at most 64 deep.
- Nothing but white space follows the value.
- Every object has exactly the keys listed for it here: none missing, none
  added. An absent value is `null`, never a missing key.
- An integer is written `0|[1-9][0-9]*` (no sign, fraction, exponent or
  leading zero) and fits its type (`u64` unless stated).
- Hex is lowercase and has exactly the stated length.
- Base64 is the RFC 4648 standard alphabet with `=` padding, and the
  unused bits of the last symbol are zero (the canonical encoding).

**Canonical form.** The canonical serialization of a JSON value has no
insignificant white space, sorts every object's keys by the bytes of their
UTF-8 encoding, keeps array order, writes numbers exactly as parsed, and
escapes in strings only `"` (as `\"`), `\` (as `\\`) and the control
characters U+0000 to U+001F (`\b`, `\f`, `\n`, `\r`, `\t`, and
`\u00xx` with lowercase hex for the others). Everything else, including
non-ASCII characters, is written as UTF-8. Bundles are written in
canonical form, and the bundle signature is computed over it.

## 3. The bundle object

| key | type | meaning |
|---|---|---|
| `format` | string | `"pragmatic-evidence/1"` |
| `generated_at` | string | When the bundle was made, `YYYY-MM-DDTHH:MM:SS[.f]Z` (UTC, 1 to 9 fraction digits). Informational. |
| `generator` | string | What made it, such as `pragmatic-server 0.6.0`. Informational. |
| `requested_by` | string | A token id, or `local:<os-user>@<host>` for a local bundle. Informational. |
| `run_id` | string | The run. |
| `anchor_id` | string or null | Section 6.2. |
| `independent` | boolean | The generator's claim that its anchors are independently witnessed. Informational: the verifier decides. |
| `journal` | object | Section 3.1. |
| `redaction` | object | Section 3.2. |
| `redacted_slots` | array | The withheld slots as `[cursor, slot]` pairs, sorted ascending, without repeats. |
| `records` | array | Section 4. |
| `anchors` | array | Section 6, the run's leaf chain, first leaf first. Empty for an unanchored bundle. |
| `latest_checkpoint` | string or null | The log's latest checkpoint as a signed note (section 6.3). Null only when `anchors` is empty. |
| `verification_spec` | object or null | `{"url", "sha256"}`: where this document was published for the generator's version and the SHA-256 (hex) of its bytes. Informational. |
| `signature` | object or null | Section 3.3. Null for an unsigned (local) bundle. |

Unsigned fields (`generated_at`, `generator`, `requested_by`,
`independent`) are informational. Every time a verifier reports comes from
a signed structure. Only the bundle signature covers `generator`,
`requested_by`, `redaction` and `verification_spec`, so a verifier
presents them as unverified claims unless that signature verified with a
pinned log key, and a verifier that pins a log key requires it (step 1).

### 3.1 `journal`

Inline form: `{"encoding": "base64", "data": <base64 of the journal
file>, "entries": n, "head": <hex, 32 bytes>}`.

Directory form, for bundles over 100 MiB: the bundle is a directory
holding `evidence.json` (the bundle object) and the journal file, and
`journal` is `{"encoding": "file", "path": <file name>, "sha256": <hex of
the file's SHA-256>, "entries": n, "head": <hex>}`. `path` is a plain file
name of 1 to 255 characters from `A-Z a-z 0-9 . _ -`, never `.` or `..`.
A verifier reads the file from the bundle's directory and MUST reject it
(code `journal_missing`) if it is absent or its SHA-256 differs.

`entries` and `head` are the generator's statement of the journal's length
and chain head (section 5), checked in step 2.

### 3.2 `redaction`

`{"mode": "none"|"detectors"|"binary"|"all", "detectors": [string...],
"patterns_sha256": <hex>}`.

`mode` names the automatic rule the generator applied: nothing, slots in
which a personal-data or secret detector matched (and slots holding binary
attachments, which detectors cannot inspect), slots holding binary
attachments, or every slot. A slot that starts like JSON but cannot be read
to its end is treated as holding an attachment by the `detectors` and
`binary` rules: what was not read is never assumed clean. Slots can also be withheld on explicit
request, so `redacted_slots` is authoritative and `mode` is
informational. `detectors` names the detectors applied.
`patterns_sha256` is the SHA-256 of the canonical JSON array of the
configured regular expressions (`[]` when there are none).

A withheld slot is left out whole: state 3, commitment only (section 5).
Content is never altered inside a slot.

### 3.3 `signature`

`{"key_id": <hex, 4 bytes>, "public_key": <hex, 32 bytes>, "value": <hex,
64 bytes>}`.

`value` is an Ed25519 signature (RFC 8032) over the 32-byte message
`SHA-256(canonical JSON of the bundle object with the "signature" member
removed)`. The key is the log's checkpoint key (section 6.3), and `key_id`
is its signed-note key ID, `SHA-256(name ‖ 0x0A ‖ 0x01 ‖ public key)[:4]`.
The message is always exactly 32 bytes, while every checkpoint and
cosignature message the same key could sign is longer text, so no
signature can be replayed from one context to the other.

## 4. Records

`records` holds one object per journal entry, in cursor order:

```text
{"cursor": n, "at": n, "branch": [u32...], "kind": string,
 "fields": {...}, "slots": [slot...], "hash": <hex>}
slot := {"state": "sealed"|"erased"|"withheld"|"ref",
         "commitment": <hex>, "len": n|null, "text": string|null,
         "base64": string|null, "ref": [cursor, slot]|null}
```

- `at` is the entry's `at` (Unix nanoseconds, informational), `branch`
  its branch path, `hash` its chain hash `h_cursor`.
- `kind` is the event kind's name: `DrawIntent`, `DrawResult`,
  `ChannelRecv`, `EffectIntent`, `EffectResult`, `Clock`, `Program`,
  `Fork`, `Marker`, `Note`, `Random` or `Refusal`.
- `fields` holds the kind's structural fields under these names (integers
  as numbers, everything else as strings; the JSON fields `meta`, `data`
  and `args` as their exact stored text):

  | kind | fields |
  |---|---|
  | DrawIntent | `provenance` |
  | DrawResult | `intent`, `meta` |
  | ChannelRecv | `channel` |
  | EffectIntent | `name` |
  | EffectResult | `intent`, `outcome`, `error_kind` |
  | Clock | `nanos` |
  | Program | `name`, `hash` |
  | Fork | `base`, `children` |
  | Marker | `name` |
  | Note | `kind`, `data` |
  | Random | `source`, `args` |
  | Refusal | `step`, `name`, `fault` |

- One slot object per slot, in slot order. `state` and `commitment` are
  the slot's stored state and commitment. When the slot's content is
  present (a sealed slot, or a ref whose target is sealed), `len` is its
  length in bytes and the content is in `text` if it is valid UTF-8 and in
  `base64` otherwise (the other is null). Otherwise `len`, `text` and
  `base64` are null. A ref carries its target in `ref`; every other state
  has `ref` null.

Records are derived from the journal and checked against it in step 6, so
they never say anything the chain does not vouch for.

## 5. The journal

The journal is a Stet journal file, format 2 (design section 2), and
always unkeyed. Summary, all integers little-endian:

```text
file   := "PRAGJRNL" ‖ u32 2 ‖ u32 flags (0) ‖ frame*
frame  := u32 len ‖ record (len bytes) ‖ hash (32 bytes)
record := u8 kind ‖ u64 at ‖ u8 depth ‖ depth × u32 branch ‖
          u8 nfields ‖ nfields × (u32 len ‖ bytes) ‖ u8 nslots ‖ slot*
slot   := u8 state ‖ commitment (32 bytes) ‖ body
          state 1 sealed:   salt (16 bytes) ‖ u32 len ‖ content
          state 2 erased:   (nothing)
          state 3 withheld: (nothing)
          state 4 ref:      u64 target cursor ‖ u8 target slot
```

```text
commitment(content) = SHA-256("pragmatic/v2/slot" ‖ salt ‖ u64 len ‖ content)
skeleton(record)    = the record with every slot replaced by 0x01 ‖ commitment
h_{-1}              = SHA-256("pragmatic/v2/genesis" ‖ u32 flags)
h_i                 = SHA-256(h_{i-1} ‖ u64 cursor_i ‖ skeleton(record_i))
```

Every slot enters the chain only through its commitment, so erasing or
withholding it never changes a chain hash. A verifier MUST decode every
record canonically (design 2.4): the record consumes exactly `len` bytes,
the kind is known and its field and slot counts match design 2.6, fixed
fields have their width, text is UTF-8, JSON fields are strict JSON, a ref
points to an earlier slot that is sealed, erased or withheld (never a ref)
and has an equal commitment, a `DrawResult` or `EffectResult` names an
earlier intent of its kind on its own branch, a `Refusal`'s fields fit
each other, the branch is the meta branch `[0xFFFFFFFF]` exactly for
`Note`s, and depth is at most 32; and re-encoding the decoded record MUST
reproduce its bytes. State 3 is valid only inside a bundle.

The journal's `entries` is its number of frames and its `head` is the hash
of its last frame (`h_{-1}` for an empty journal).

## 6. Anchors

Each element of `anchors` is:

| key | type | meaning |
|---|---|---|
| `seq` | integer | The anchoring batch number. |
| `tree_size` | integer | The size of the checkpoint's tree. |
| `leaf_index` | integer | The leaf's index in the log. |
| `leaf` | hex | The leaf data (section 6.1). |
| `inclusion_proof` | array of hex | RFC 9162 inclusion proof of the leaf in the tree of `tree_size`. |
| `root` | hex | The root of that tree. |
| `checkpoint` | string | The checkpoint as a signed note (section 6.3). |
| `anchor_digest` | hex | SHA-256 of the checkpoint body: what the witnesses time-stamp. |
| `consistency_to_latest` | array of hex | RFC 9162 consistency proof from this tree to the tree of `latest_checkpoint`. |
| `witnesses` | array | Section 6.4. |

### 6.1 Leaves

```text
leaf_data = "pragmatic/v2/leaf" ‖ u8 type ‖ u32 len(id) ‖ id ‖
            u64 entries ‖ head (32 bytes) ‖ u64 prev_leaf_index
```

Little-endian. `type` is 0 for a run and 1 for the access log; an id is 1
to 1024 bytes (an empty id is malformed); `prev_leaf_index` is the index of the same id's previous
leaf, or `0xFFFFFFFFFFFFFFFF` for its first; nothing follows it. Leaves are
hashed into the log as RFC 6962 leaves: `SHA-256(0x00 ‖ leaf_data)`, with
interior nodes `SHA-256(0x01 ‖ left ‖ right)`.

### 6.2 Run ids in leaves

When `anchor_id` is null, a run's leaves carry its run id's UTF-8 bytes.
When the server names runs by HMAC (`anchor_run_ids = "hmac"`),
`anchor_id` is the hex of a 32-byte per-run key `k_run` and the leaves
carry `HMAC-SHA-256(k_run, run_id)`. A log reader or witness then never
learns run ids, while the bundle holder can recompute the leaf.

That privacy has a cost a verifier MUST report. The bundle supplies
`k_run`, and nothing binds it to the run: a log operator can anchor a
rewritten journal for the same run as a fresh leaf chain under a new key,
and the run's earlier leaves, under the old key, look like any other run's.
So for a bundle with `anchor_id` set, hidden or re-keyed anchors cannot be
detected, not even with the full log: a verifier reports
`anchor_id_unbound` (warning, step 7), and the full-log audit of step 11
fails with `log_unauditable` instead of passing. Runs whose anchors must be
auditable for omission are anchored with plain ids. (A run id bound to the
log key by a verifiable random function would keep both properties; it is
planned, not part of this format.)

### 6.3 Checkpoints and signatures

A checkpoint is a C2SP `tlog-checkpoint`: the body is three lines, each
ending in a newline: the log origin, the tree size in decimal, and the
root in base64 (further lines are extensions). It is wrapped in a C2SP
`signed-note`: the body, a blank line, and signature lines, each the
character U+2014 EM DASH, a space, the key name, a space, and
`base64(key id ‖ signature)`. The log signs with Ed25519 (signed-note type
`0x01`) under its origin as key name. Its key would sign any origin line,
so a verifier that pins a log key MUST also require that the key which
verifies a checkpoint is named for that checkpoint's origin (step 8):
otherwise the log could fork under a renamed origin, signed by the same
key, where no witness history for its real origin applies.

A cosignature is a C2SP `cosignature/v1` line (type `0x04`):
`base64(key id ‖ u64 big-endian timestamp ‖ signature)`, where the
Ed25519 signature covers `"cosignature/v1\ntime <timestamp>\n" ‖ body`.

Keys are given to a verifier as C2SP verifier keys (vkeys):
`<name>+<hex key id>+<base64(type ‖ public key)>`.

### 6.4 Witnesses

- `{"type": "rfc3161", "tsa": <url>, "operator": <name>, "token": <base64
  DER>, "certs_pem": <PEM>}`: an RFC 3161 time-stamp token (a CMS
  `ContentInfo`) whose message imprint is SHA-256 over `anchor_digest`.
  `certs_pem` holds the TSA's certificate chain as `CERTIFICATE` blocks
  with canonical base64 lines of at most 64 characters, and nothing else.
  `tsa` and `operator` are informational.
- `{"type": "cosignature", "name": <cosigner name>, "line": <signature
  line, without its newline>}`: a `cosignature/v1` line over the
  checkpoint body from the named witness.

The checkpoint's own server signature is the `server-ed25519` witness. It
is always operator-controlled and never counts towards independence.

## 7. Trust inputs

A verifier takes trust only from its own inputs:

- **TSA anchors** (`--tsa-roots OPERATOR=FILE`, repeatable): PEM files of
  trust anchors, each with the operator its tokens count for. The
  operator is required. Every certificate in a file is an anchor (OpenSSL
  `-partial_chain`), so an auditor can pin the CA that issues an
  operator's time-stamping certificates rather than a broad root under
  which others can buy them; a file of roots works as well. A token's
  operator is the operator whose anchors verify it, never the bundle's
  `operator` field, and a token that the anchors of more than one
  operator verify counts for none of them. `certs_pem` is used only as
  untrusted intermediates. The TSA certificate MUST carry the extended key
  usage `id-kp-timeStamping`.
- **Witness keys** (`--witness-key OPERATOR=VKEY`, repeatable; or
  `OPERATOR=HEX` for a 32-byte cosignature key whose cosigner name is
  `OPERATOR`), plus the keys of the hosted witness that Pragmatic Research runs, built
  into the CLI with their validity windows (none until it launches).
- **Log keys** (`--log-key VKEY`, repeatable): the log's Ed25519 checkpoint
  key, which also signs bundles.
- **Minimum operators** (`--min-operators N`, default 2).
- **Operator aliases**: operators that are one company under two names,
  counted once: Entrust as Sectigo, and QuoVadis EU as DigiCert. Names are
  compared in lower case with runs of white space and `_` as one `-`.

## 8. Verification procedure

A verifier performs every step and reports every finding, each with its
code. Codes marked *failure* make the verdict `FAILED`; the others do not.

1. **Strict JSON, known keys** (section 2): `bundle_json`,
   `bundle_schema` (failures). **Bundle signature:** if its `public_key`
   is the key of a pinned log key (with the same key id), the signature
   MUST verify with it (`bundle_signature`, failure). Otherwise a signature
   MUST verify with the key it names (`bundle_signature`, failure). When
   log keys are pinned, the bundle MUST be signed by one of them: a
   pinned log key says which log the bundle comes from, and that log signs
   its bundles, so an unsigned bundle or one signed by any other key fails
   (`bundle_signature`). With no log key pinned, an unsigned bundle is
   reported as such (`unsigned`, info) and a valid signature by an unpinned
   key as operator-asserted (`operator_asserted`, info).
2. **Journal.** For a directory bundle, the verifier reads `evidence.json`
   and the journal file only if each is a regular file (not a symbolic
   link, FIFO or device; the directory comes from the party being
   audited) of a size a bundle can have (`bundle_file`, failure). Decode
   the journal (section 5); undecodable is `journal_parse`, a format 1
   journal `journal_format`, and any bytes after the last complete frame
   `journal_trailing_bytes` (failures). Recompute `entries` and `head`:
   `entries_mismatch`, `head_mismatch` (failures).
3. **Chain.** Every chain link, commitment and ref verifies (`chain`,
   failure).
4. **Withheld slots.** `redacted_slots` equals exactly the set of state 3
   slots, sorted, without repeats (`withheld_mismatch`, failure).
5. **Erasure.** Every erased slot (state 2) is listed by an `erasure` note
   at a later cursor (`unaccounted_erasure`); no slot listed by an
   erasure note still holds content (`erasure_incomplete`); every pair an
   erasure note lists names an existing slot at an earlier cursor
   (`invalid_erasure_note`). All failures.
6. **Records.** `records` equals the records derived from the journal
   (section 4), compared in canonical form (`records_mismatch`, failure).
7. **Run id.** The journal's first entry is a `run.start` note whose
   `run_id` equals `run_id`, and every anchor's leaf carries the run's id
   (section 6.2) (`run_id_mismatch`, failure). A bundle with `anchor_id`
   set is reported as one whose hidden anchors cannot be detected
   (`anchor_id_unbound`, warning; section 6.2).
8. **Anchors.** If there are none, report it (`no_anchors`, info) and go
   to step 10. Otherwise `latest_checkpoint` MUST be a checkpoint
   (`anchor_consistency`, failure), and for each anchor:
   - the leaf decodes exactly as section 6.1 with type 0 (`anchor_leaf`);
   - the journal's head after the leaf's `entries` entries equals the
     leaf's head (`anchor_head_mismatch`);
   - the inclusion proof leads from `SHA-256(0x00 ‖ leaf)` at
     `leaf_index` to `root` in a tree of `tree_size`, by the algorithm of
     RFC 9162 section 2.1.3.2 including its length check
     (`anchor_inclusion`);
   - the checkpoint is a signed note whose body states `tree_size` and
     `root`, with the same origin as `latest_checkpoint`
     (`anchor_checkpoint`);
   - `anchor_digest` is SHA-256 of the checkpoint body (`anchor_digest`);
   - the consistency proof leads from this tree to the latest checkpoint's
     tree, by RFC 9162 section 2.1.4.2 (`anchor_consistency`);
   - the anchors form the run's leaf chain: the first anchor's leaf has no
     previous leaf, each later leaf's `prev_leaf_index` is the previous
     anchor's `leaf_index`, `seq` and `leaf_index` increase, and `entries`
     never decreases (`anchor_chain`);
   - if log keys are pinned, the checkpoint (and `latest_checkpoint`) is
     signed by one of them under the signed-note rules, and a key that
     signed it is named for the checkpoint's origin (`log_signature`;
     section 6.3); otherwise its signature is operator-asserted.

   All of these are failures.
9. **Witnesses.** Classify each witness as *trusted*, *self-asserted* or
   *operator-controlled*:
   - `rfc3161`: the token MUST parse as a time-stamp token
     (`witness_malformed`, failure), its imprint MUST be SHA-256 of
     `anchor_digest` (`tsa_imprint_mismatch`, failure), and `certs_pem`
     MUST be well formed (`witness_malformed`, failure). It is trusted if
     it verifies against the pinned anchors of exactly one operator with

     ```text
     openssl ts -verify -token_in -in <i>.der -digest <anchor_digest>
         -CAfile <one pinned anchors file> -partial_chain -untrusted <i>.pem
         -attime <genTime + 1>
     ```

     run with the token and certificates written to a fresh directory only
     the verifier can read (mode 0700), files named by a counter, the
     arguments passed directly (never through a shell), every path
     absolute, and the digest checked to be 64 lowercase hex digits. Only
     an OpenSSL whose `ts` command takes `-attime` and `-partial_chain` is
     used (LibreSSL's does not, so it cannot check a token at its signing
     time). Every operator's pinned anchors are tried. A token is rejected
     by an operator's anchors only when OpenSSL ran the verification and
     reported it failed (`Verification: FAILED`); a token that verifies
     against no operator's anchors is self-asserted (`tsa_untrusted`,
     warning), and one that verifies against the anchors of more than one
     operator is self-asserted too and counts for none of them
     (`tsa_ambiguous`, warning). One that could not be checked (no usable
     OpenSSL, or OpenSSL did not run the check, as when it answers with a
     usage message) is self-asserted (`tsa_unchecked`, warning), and is
     never reported as rejected by the anchors. The token's time is
     `genTime` plus its accuracy. A trusted token whose bundle `operator`
     disagrees with the operator of the anchors that verify it is reported
     (`operator_mismatch`, warning).
   - `cosignature`: the line MUST parse as a signature line naming the
     witness's `name` (`witness_malformed`, failure). It is trusted if a
     pinned witness key with that name and key id verifies it over the
     checkpoint body and its timestamp lies in the key's validity window;
     the operator is the key's. A line no pinned key matches is
     self-asserted (`cosignature_untrusted`, warning); one from a pinned
     key that does not verify is a failure (`cosignature_invalid`); one
     outside its key's window is self-asserted (`witness_key_expired`,
     warning). The reported time is the cosignature's timestamp.
   - The checkpoint's server signature is operator-controlled.
   - **The anchor's time.** An anchor's prefix existed no later than the
     time at least the minimum number of distinct trusted operators vouch
     for: take each trusted operator's earliest witness time, and of
     those the k-th earliest, where k is the minimum. The plain earliest
     would let one operator (a compromised witness, a TSA with a wrong
     clock) backdate the anchor alone. With fewer than k trusted operators
     giving a time, the anchor reports none.
10. **Independence.** An anchor is independent when it passed every check
    of step 8 and its trusted witnesses come from at least the minimum
    number of distinct operators, after aliasing (section 7). Then:
    - `VERIFIED` (exit 0) when an independent anchor's `entries` equals the
      journal's length;
    - `VERIFIED (PARTIAL)` (exit 2) when independent anchors cover only a
      prefix of at least one entry, reporting the unanchored suffix's
      length;
    - `UNANCHORED` (exit 3) when no anchor is independent, or the only
      independent anchors cover 0 entries: such an anchor commits only to
      the genesis head, which every unkeyed journal shares, so it vouches
      for no content;
    - `FAILED` (exit 1) when any failure was found, whatever else holds,
      including an audit of step 11 that was asked for and could not be
      completed.
11. **Full-log audits** (optional). Each audit asked for MUST be
    completed; one that cannot be is a failure, never a skipped step.
    - **The full log** (`--log`, the file form `{"leaves": [<hex leaf
      data>...]}` with every leaf from index 0): its first `tree_size`
      leaves (the latest checkpoint's size) MUST hash to the latest
      checkpoint's root, and each bundle anchor's leaf MUST equal the
      log's leaf at its index (`log_mismatch`, failure). Every leaf among
      them that carries this run's id MUST be one of the bundle's anchors
      (`anchor_omitted`, failure): this detects a bundle that hides an
      anchor. A run leaf past the latest checkpoint is reported
      (`log_newer`, warning). For a bundle with `anchor_id` set, that
      cannot be shown (section 6.2), and the audit fails with
      `log_unauditable`. The log is checked against the latest
      checkpoint, a tree head the operator chose: on its own it cannot
      show that the operator did not fork the log; the witness history
      below does.
    - **A witness's cosigned history** (`--witness-log`, the file form
      `{"witness": <cosigner name>, "origin": <log origin>,
      "checkpoints": [<signed note>...]}`). A witness cosigns a checkpoint
      only after checking that it extends the last one it cosigned, so its
      history is one chain of consistent tree heads; the audit decides
      whether the bundle's tree is on it.
      - The history MUST be for the bundle's origin, and so must each of
        its checkpoints (`witness_log_origin`, failure).
      - It MUST be the witness's own: at least one checkpoint, and every
        checkpoint signed, under the signed-note rules, by a pinned
        witness key whose name is the history's `witness`, within the
        key's validity window (`witness_log_untrusted`, failure). A
        history whoever handed it over could have written says nothing.
      - The tree heads the bundle vouches for are the latest checkpoint,
        each anchor's checkpoint (each proven consistent with the latest in
        step 8), and, when the full log was given and matched the latest
        checkpoint, the root of the log's first `s` leaves for every size
        `s` the log reaches. The history and these MUST agree on the root
        of every tree size both name (`witness_log_fork`, failure: the log
        showed two histories), and the history MUST NOT name two roots for
        one size (`witness_log_fork`).
      - The bundle's tree MUST be linked to the history: the witness
        cosigned the latest checkpoint itself, or the history's largest
        tree size is one the bundle vouches for (as above) with the same
        root (`witness_log_mismatch`, failure). Without the full log, a
        fork at tree sizes the witness never cosigned, or a witness that
        has since cosigned larger trees, can only be checked against the
        log's leaves, so such a bundle is not linked until `--log` reaches
        the witness's largest tree.
      - Every bundle checkpoint that carries this witness's cosignature
        MUST be in its history (`witness_log_mismatch`, failure).
12. **Presentation.** Text from the bundle is data: a verifier MUST NOT
    print it in a way that can be read as its own output (control
    characters are escaped) and MUST NOT act on it. `pragmatic
    verify-evidence --explain` prints this document.

## 9. Codes

| code | severity | step |
|---|---|---|
| `bundle_json` | failure | 1 |
| `bundle_schema` | failure | 1 |
| `bundle_signature` | failure | 1 |
| `bundle_file` | failure | 2 |
| `unsigned` | info | 1 |
| `operator_asserted` | info | 1 |
| `journal_missing` | failure | 2 |
| `journal_parse` | failure | 2 |
| `journal_format` | failure | 2 |
| `journal_trailing_bytes` | failure | 2 |
| `entries_mismatch` | failure | 2 |
| `head_mismatch` | failure | 2 |
| `chain` | failure | 3 |
| `withheld_mismatch` | failure | 4 |
| `unaccounted_erasure` | failure | 5 |
| `erasure_incomplete` | failure | 5 |
| `invalid_erasure_note` | failure | 5 |
| `records_mismatch` | failure | 6 |
| `run_id_mismatch` | failure | 7 |
| `anchor_id_unbound` | warning | 7 |
| `no_anchors` | info | 8 |
| `anchor_leaf` | failure | 8 |
| `anchor_head_mismatch` | failure | 8 |
| `anchor_inclusion` | failure | 8 |
| `anchor_checkpoint` | failure | 8 |
| `anchor_digest` | failure | 8 |
| `anchor_consistency` | failure | 8 |
| `anchor_chain` | failure | 8 |
| `log_signature` | failure | 8 |
| `witness_malformed` | failure | 9 |
| `tsa_imprint_mismatch` | failure | 9 |
| `cosignature_invalid` | failure | 9 |
| `tsa_untrusted` | warning | 9 |
| `tsa_unchecked` | warning | 9 |
| `tsa_ambiguous` | warning | 9 |
| `cosignature_untrusted` | warning | 9 |
| `witness_key_expired` | warning | 9 |
| `operator_mismatch` | warning | 9 |
| `anchor_omitted` | failure | 11 |
| `log_mismatch` | failure | 11 |
| `log_newer` | warning | 11 |
| `witness_log_fork` | failure | 11 |
| `witness_log_mismatch` | failure | 11 |
| `witness_log_origin` | failure | 11 |
| `witness_log_untrusted` | failure | 11 |
| `log_unauditable` | failure | 11 |

Both verifiers perform every check above, the reference verifier
(`tools/verify_evidence.py`) with its own Ed25519 (RFC 8032, written in
Python against the same acceptance rules), strict DER and signed-note
parsers, so that two programs that share no code must agree on a bundle.

A verifier exits 64, distinct from every verdict, when its own inputs are
at fault: a trust input (root, key, log or witness history) that is
malformed or cannot be read, or a bundle path that cannot be read.
