# End-to-end tests

The whole product story (design section 9, "End to end") against real
processes, using only local resources:

| file | what it is |
|---|---|
| `story.py` | the eight steps, each asserting what it narrates; shared with `examples/demo` |
| `test_story.py` | one pytest test per step, in order; a failed step skips the rest |
| `support_agent.py` | the agent (Anthropic and OpenAI SDKs over scripted `httpx2.MockTransport` APIs, journaled with `ctx.wrap`, a refund tool through `ctx.run_tools`), run as separate processes |
| `local_tsa.py` | two throwaway OpenSSL TSAs (a root plus a TSA certificate with critical `extendedKeyUsage = timeStamping`) served over HTTP by a responder that calls `openssl ts -reply` |
| `harness.py` | builds and starts `pragmatic-server`, issues tokens, calls the API, runs `pragmatic` and `tools/verify_evidence.py` |
| `test_sdk_against_server.py` | the SDK's server store against the real binary rather than the SDK suite's mock: calls longer than the lease with a competing resume, a lost response resent through a dropping proxy, `run_deleted`, `payload_too_large`, and how `verify`, `replay` and `push` report missing, damaged and erased runs |

The steps:

1. two TSAs of different operators, their roots for the verifiers, and two
   unrelated roots;
2. `pragmatic-server` (keygen, `token bootstrap`, both TSAs as independent
   operators, a 60 second anchoring interval, a 10 second lease), an agent
   token scoped to `support:`, an auditor token, and an agent token scoped
   to `billing:`;
3. the agent dies with `os._exit` inside the refund tool after the payment
   provider acted; a second process resumes with a recovery policy that
   asks the provider, while a third gets `Locked`; every model call reached
   the provider once and the tool performed once;
4. the run is independently anchored (a checkpoint witnessed by both
   operators covers every entry), the auditor's view is redacted, and a
   replay makes no calls;
5. an administrator erases the customer's message by `match`: the chain
   verifies, the erasure note names the admin token, and a replay raises
   `Erased`;
6. the auditor's `redact=detectors` bundle is `VERIFIED` (exit 0) with the
   pinned roots, log key and `--min-operators 2`, `UNANCHORED` (exit 3) with
   unrelated roots and `FAILED` (exit 1) with one journal byte changed, in
   both `pragmatic verify-evidence` and `tools/verify_evidence.py`, and
   renders to HTML and CSV;
7. the access log holds the auditor's download and the admin's erasure, and
   an agent token scoped elsewhere gets `not_found`;
8. a restart, with another agent mid-call holding its lease: summaries,
   listing, label filter and subject index are unchanged, the lease still
   refuses a contender, the agent finishes, and `verify-data`, the SDK and
   a fresh bundle all verify.

## Running

```sh
python -m pytest tests/e2e -v      # -s prints the story as it runs
```

The Python running pytest needs the SDK built into it (`maturin develop` in
`crates/pragmatic-python`) and `pytest`, `anthropic`, `openai` and `httpx2`.
`openssl` must be OpenSSL 3 (on a Mac, Homebrew's `openssl@3` is found
without being on `PATH`). The suite runs `cargo build -p pragmatic-server
-p pragmatic-cli` first; set `PRAGMATIC_E2E_SKIP_BUILD=1` to use the
binaries already in the target directory, and
`PRAGMATIC_E2E_PROFILE=release` for release builds. It takes about a minute.
