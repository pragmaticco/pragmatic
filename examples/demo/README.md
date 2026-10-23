# The Stet demo

One command shows the whole product working, step by step, on your own
computer. Nothing is mocked except the AI models themselves: it starts a
real Stet Server, runs a real agent against it, and checks every claim
it makes with the same tools an auditor would use.

## Run it

Open the Terminal app, go to the folder you downloaded Stet into, and
run:

```sh
examples/demo/run.sh
```

If you have not downloaded it yet, these commands do, from the
`system-of-record` branch where the demo lives until it reaches `main`:

```sh
git clone -b system-of-record https://github.com/pragmaticco/pragmatic
cd pragmatic
```

The first run builds Stet from source, which takes a few minutes.
Later runs take about a minute. Add `--open` to open the auditor's report
in your browser at the end:

```sh
examples/demo/run.sh --open
```

If something the demo needs is missing, it stops and prints the one command
that installs it (on a Mac, a `brew install ...` line), then you run
`examples/demo/run.sh` again. What it needs, all free: Rust (to build
Stet), Python 3.10 or later, and OpenSSL 3 (macOS comes with a
different library that cannot check timestamps). If you do not have
Homebrew, the installer for it is at https://brew.sh.

## What you will see

The demo follows a customer support agent at an online shop. The agent
uses Claude to decide what to do and GPT to write notes, the way many
companies build agents today.

1. **Two timestamp authorities start.** These are the independent outside
   parties that countersign the record, like a notary. Two of them run on
   your computer, standing in for two separate companies.
2. **Stet Server starts.** It is the system of record: it stores every
   step every agent takes, in order, in a way that shows any later change.
   It hands out separate keys (tokens) to the agents, to an outside auditor,
   and to another team, each allowed to see only what it should.
3. **The agent crashes in the middle of a refund.** A customer asks for a
   refund on a damaged order. Claude decides to refund it, the agent calls
   the payment provider, and the moment the money moves we kill the
   program. A second copy picks the work up where it stopped: it asks the
   payment provider whether the refund went through instead of refunding
   twice, and it reuses Claude's earlier answer instead of paying for it
   again. A third copy that tries to grab the same work at the same time is
   turned away.
4. **The record is countersigned.** Both timestamp authorities vouch for
   the finished record, so from then on not even the server's operator
   could quietly rewrite it. An auditor can read the run with the
   customer's email address hidden, and can replay the whole run exactly,
   without calling any AI model or moving any money.
5. **The customer asks to be forgotten.** An administrator erases the
   customer's message. The content is gone, yet the record still proves
   that nothing else was touched, and the erasure itself is on the record,
   with who did it.
6. **The auditor checks the evidence.** The auditor downloads an evidence
   file and checks it with two independent tools on their own machine,
   trusting only the authorities they chose. It passes. Then we try to fool
   them: with the wrong authorities it is reported as not anchored, and
   with a single changed byte it fails, and says where.
   The demo also writes a readable report and a spreadsheet of every step.
7. **Who saw what.** The access log shows the auditor's download and the
   administrator's erasure. The other team's key gets "not found" for the
   support run, as if it did not exist.
8. **The server restarts under load.** A second ticket's agent is waiting
   on Claude when the server restarts, as in an upgrade. The agent keeps its
   place, finishes its work, and every proof checks out again.

Each step ends with lines marked `[ok]`: each one is a check that ran and
held. If any check fails, the demo stops and says which.

## What it does to your computer

- It builds Stet inside this folder (`target/`) and keeps a private
  Python environment in `examples/demo/.venv`.
- Everything else (the server's data, the evidence files, the report) goes
  into a new folder under your temporary files, which the demo names at the
  end. Delete it whenever you like.
- The server and the timestamp authorities listen only on your own
  computer (`127.0.0.1`) and are stopped when the demo ends.
- The first run downloads the building blocks Stet is built from.
  After that the demo makes no internet connections: the AI models are
  scripted stand-ins, so no API key or account is used and nothing is
  billed.

## Look around afterwards

```sh
examples/demo/run.sh --keep-running
```

leaves the server running at the end, with its web console, and prints the
address and where to find the administrator's sign-in token. Press Ctrl-C
to stop it.

## For engineers

The demo is the end-to-end suite in `tests/e2e`, narrated. Each step in
`tests/e2e/story.py` asserts what the narration says, and
`python -m pytest tests/e2e -v` runs the same steps in CI.
