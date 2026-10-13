"""The whole product story, end to end, against real processes.

A support agent built on the Anthropic and OpenAI SDKs refunds a damaged
order through Pragmatic Server. Its process dies in the middle of the
refund; a second process resumes the run without paying for a model call
twice or refunding twice, and a third is turned away while the second
holds the run. Two independent time-stamping authorities anchor the
record. The customer asks to be forgotten, and an administrator erases
their message: the record still verifies, and can no longer be replayed.
An auditor downloads the evidence and checks it offline against roots of
their own choosing, which also catches a forged root and a changed byte.
The access log shows who did what, a token for another team sees nothing,
and a restart keeps every lease, index and proof.

``Story`` runs it one step at a time, asserting as it goes, and tells what
happened through a ``Narrator``: the pytest suite (``test_story.py``) and
the demo (``examples/demo``) are the same steps. Every step assumes the
ones before it ran.
"""

from __future__ import annotations

import base64
import csv
import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TextIO

import harness
import local_tsa
import support_agent
from harness import Api, Server, Witness

import pragmatic

RUN = "support:ticket-4127"
SECOND = "support:ticket-4128"
OPERATORS = {"alpha-time": "Alpha Time", "beta-time": "Beta Time"}
LEASE_TTL_SECS = 10
AGENT_TIMEOUT = 240.0
ANCHOR_TIMEOUT = 180.0


class Narrator:
    """Tells the story as it runs, in plain language."""

    def __init__(self, out: TextIO = sys.stdout, width: int = 78):
        self.out = out
        self.width = width

    def step(self, number: int, title: str, why: str) -> None:
        self.out.write(f"\n=== Step {number} of 8: {title} ===\n")
        self._para(why, "")
        self.out.flush()

    def say(self, text: str) -> None:
        self._para(text, "  ")

    def check(self, text: str) -> None:
        self._para(text, "  [ok] ", "       ")

    def quote(self, text: str) -> None:
        self._para(text, '  > "', "    ", end='"')

    def literal(self, label: str, value: str) -> None:
        """A value to copy whole (a key, a path): on a line of its own,
        never wrapped."""
        self._para(label, "  ")
        self.out.write(f"      {value}\n")
        self.out.flush()

    def _para(self, text: str, first: str, rest: Optional[str] = None, end: str = "") -> None:
        lines = textwrap.wrap(
            text + end,
            self.width,
            initial_indent=first,
            subsequent_indent=rest if rest is not None else first,
            break_on_hyphens=False,
        )
        self.out.write("\n".join(lines) + "\n")
        self.out.flush()


class Story:
    """The story's state: the TSAs, the server, the tokens and what each
    step left behind for the next."""

    def __init__(self, work: Path, narrator: Optional[Narrator] = None):
        self.work = work
        self.n = narrator or Narrator()
        self.agent_work = work / "agent"
        self.agent_work.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = work / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.openssl_dir = ""
        self.env: Dict[str, str] = {}
        self.bin_dir = Path()
        self.tsas: Dict[str, local_tsa.TsaResponder] = {}
        self.unrelated_roots: Dict[str, Path] = {}
        self.server: Optional[Server] = None
        self.tokens: Dict[str, Dict[str, str]] = {}
        self.procs: List[subprocess.Popen] = []
        self.bundle: Optional[Path] = None
        self.report_html: Optional[Path] = None
        self.final: Dict[str, Any] = {}

    # -- helpers --------------------------------------------------------------

    @property
    def api(self) -> Api:
        assert self.server is not None, "step 2 starts the server"
        return self.server.api

    @property
    def admin(self) -> str:
        assert self.server is not None
        return self.server.admin_token

    def close(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        if self.server is not None:
            try:
                self.server.stop()
            except RuntimeError:
                pass
        for t in self.tsas.values():
            t.close()

    def _agent_env(self, token: str) -> Dict[str, str]:
        return harness.child_env(
            self.openssl_dir,
            {"PRAGMATIC_URL": self.api.url, "PRAGMATIC_TOKEN": token},
        )

    def _agent(self, mode: str, run_id: str, *flags: str, token: Optional[str] = None) -> subprocess.Popen:
        """Start one process of the support agent (see support_agent.py)."""
        cmd = [
            sys.executable,
            str(harness.E2E / "support_agent.py"),
            mode,
            run_id,
            str(self.agent_work),
            *flags,
        ]
        p = subprocess.Popen(
            cmd,
            env=self._agent_env(token or self.tokens["agent"]["token"]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.procs.append(p)
        return p

    @staticmethod
    def _finish(p: subprocess.Popen, timeout: float = AGENT_TIMEOUT) -> Dict[str, Any]:
        """Wait for an agent process; its exit code and the JSON it printed."""
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            raise AssertionError(f"the agent process did not finish:\n{out}\n{err}")
        doc: Dict[str, Any] = {"exit": p.returncode, "stderr": err}
        lines = [line for line in out.splitlines() if line.startswith("{")]
        if lines:
            doc.update(json.loads(lines[-1]))
        return doc

    def _wait_for(self, path: Path, p: subprocess.Popen, timeout: float = AGENT_TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists():
            if p.poll() is not None:
                doc = self._finish(p)
                raise AssertionError(f"the agent process ended before {path.name}: {doc}")
            if time.monotonic() > deadline:
                raise AssertionError(f"{path.name} did not appear in {timeout:.0f}s")
            time.sleep(0.05)

    def _model_calls(self, run_id: str) -> List[Dict[str, Any]]:
        return [c for c in support_agent.read_lines(self.agent_work / "model-calls.jsonl") if c["run_id"] == run_id]

    def _tool_calls(self, run_id: str) -> List[Dict[str, Any]]:
        return [c for c in support_agent.read_lines(self.agent_work / "tool-calls.jsonl") if c["run_id"] == run_id]

    def _payments(self) -> List[Dict[str, Any]]:
        return support_agent.read_lines(self.agent_work / "payments.jsonl")

    def summary(self, run_id: str, token: Optional[str] = None) -> Dict[str, Any]:
        return self.api.ok("GET", Api.run_path(run_id), token or self.admin)

    def entries(self, run_id: str, token: Optional[str] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        start = 0
        while True:
            page = self.api.ok(
                "GET", Api.run_path(run_id, "/entries"), token or self.admin, query={"from": start, "limit": 1000}
            )
            out.extend(page["entries"])
            if page.get("next") is None:
                return out
            start = page["next"]

    @staticmethod
    def notes(entries: List[Dict[str, Any]], kind: str) -> List[Dict[str, Any]]:
        return [e for e in entries if (e.get("fields") or {}).get("kind") == kind]

    def sdk(self, token: str) -> Any:
        """The Python SDK, connected to the server with ``token``."""
        return pragmatic.Runtime(self.api.url, token=token)

    def trust_flags(self, roots: Dict[str, Path]) -> List[str]:
        flags: List[str] = []
        for operator, pem in roots.items():
            flags += ["--tsa-roots", f"{operator}={pem}"]
        assert self.server is not None
        return flags + ["--log-key", self.server.log_vkey, "--min-operators", "2"]

    @property
    def pinned_roots(self) -> Dict[str, Path]:
        return {op: t.tsa.root_pem for op, t in self.tsas.items()}

    def cli(self, *args: str) -> harness.Verdict:
        return harness.run_tool([str(self.bin_dir / harness.exe("pragmatic")), *args], self.env)

    def reference(self, *args: str) -> harness.Verdict:
        script = harness.REPO / "tools" / "verify_evidence.py"
        return harness.run_tool([sys.executable, "-I", str(script), *args], self.env)

    # -- the steps ------------------------------------------------------------

    def step1_timestamp_authorities(self) -> None:
        self.n.step(
            1,
            "Two independent timestamp authorities",
            "A record is only as trustworthy as the outsiders who vouch for it. Pragmatic "
            "Server asks independent timestamp authorities (the same kind of service that "
            "timestamps signed software and legal documents) to countersign its records. "
            "Here we start two of them on this machine, standing in for two different "
            "companies.",
        )
        self.openssl_dir = harness.find_openssl()
        self.env = harness.child_env(self.openssl_dir)
        openssl = os.path.join(self.openssl_dir, "openssl")
        self.tsas = local_tsa.start_tsas(self.work, OPERATORS, openssl)
        for op, t in self.tsas.items():
            t.check()
            self.n.check(f"{t.tsa.display_name} ({op}) is answering at {t.url}, and its tokens verify")
        # Roots that issued nothing the server will see: what an auditor who
        # pinned the wrong roots would be trusting.
        for i, op in enumerate(OPERATORS, 1):
            self.unrelated_roots[op] = local_tsa.make_ca(
                self.work / f"unrelated-root-{i}", f"Unrelated Root {i}", openssl
            )
        self.n.say(
            "Each one has its own root certificate. An auditor who wants to rely on them "
            "pins those two roots; nothing in the evidence itself is ever trusted."
        )

    def step2_server(self) -> None:
        self.n.step(
            2,
            "Pragmatic Server starts, with tokens for each role",
            "The server is the system of record: every step an agent takes is stored "
            "there, in order, chained by hashes so that nothing can be changed or "
            "removed without it showing. Each person or program gets a token that says "
            "what it may do and which runs it may see.",
        )
        self.bin_dir = harness.build_binaries()
        self.server = Server(
            self.work / "server",
            self.bin_dir,
            self.env,
            name="acme-support",
            witnesses=[Witness(op, t.url, t.tsa.root_pem) for op, t in self.tsas.items()],
            lease_ttl_secs=LEASE_TTL_SECS,
            licensee="Acme Retail (evaluation)",
        )
        self.server.setup()
        self.server.start()
        info = self.api.ok("GET", "/v1/info", self.admin)
        assert info["components"] == {
            "anchoring": "integrated",
            "evidence": "integrated",
            "console": "integrated",
        }, info
        assert info["independent_witness"] is True, info
        self.n.check(
            f"pragmatic-server {info['version']} is up at {self.api.url}, anchoring to "
            f"{len(self.tsas)} timestamp authorities"
        )
        self.n.literal("Its public key, which auditors pin:", self.server.log_vkey)
        self.tokens["agent"] = self.server.issue("support-agents", "svc-support", "agent", ["support:"])
        self.tokens["auditor"] = self.server.issue(
            "external-audit", "auditor@audit-firm.example", "auditor", ["support:"]
        )
        self.tokens["billing"] = self.server.issue("billing-agents", "svc-billing", "agent", ["billing:"])
        who = self.api.ok("GET", "/v1/whoami", self.admin)
        assert who["role"] == "admin", who
        self.tokens["admin"] = {"token": self.admin, "id": who["token_id"]}
        self.n.check("the support agents may write runs whose names start with support:")
        self.n.check("the external auditor may read those runs, with personal data redacted")
        self.n.check("the billing agents may only touch billing: runs")

    def step3_crash_and_resume(self) -> None:
        self.n.step(
            3,
            "The agent crashes in the middle of a refund, and resumes",
            "A customer writes in about a damaged order. The support agent asks Claude, "
            "which decides to refund it, and calls the payment provider. Right after the "
            "money moves, we kill the process, as a crash or a deploy would.",
        )
        ticket = support_agent.TICKETS[RUN]
        self.n.quote(ticket.message)
        first = self._agent("run", RUN, "--crash-in-refund")
        crashed = self._finish(first)
        assert crashed["exit"] == support_agent.CRASH_EXIT, crashed
        assert [c["call"] for c in self._model_calls(RUN)] == ["claude"], self._model_calls(RUN)
        assert len(self._tool_calls(RUN)) == 1 and len(self._payments()) == 1
        self.n.check(
            f"process 1 (pid {first.pid}) died after the refund of ${ticket.amount_usd:.2f} "
            "went through, before it could record the result"
        )
        s = self.summary(RUN)
        self.n.say(
            f"The server holds {s['entries']} entries for the run, among them Claude's "
            "decision and the refund the agent was about to make, but not whether the refund "
            "happened."
        )

        self.n.say(
            "A second process now resumes the run. Its recovery policy asks the payment "
            "provider whether the refund went through, instead of refunding again. While "
            "it works, a third process tries to take the same run."
        )
        second = self._agent("resume", RUN, "--gate", "claude.stream:resumed")
        self._wait_for(self.agent_work / "resumed.ready", second)
        third = self._finish(self._agent("contend", RUN))
        assert third["exit"] == 0 and third.get("outcome") == "locked", third
        self.n.check("process 3 was refused: process 2 holds the run's lease (Locked)")
        (self.agent_work / "resumed.go").write_text("go")
        done = self._finish(second)
        assert done["exit"] == 0 and done.get("outcome") == "ok", done
        calls = self._model_calls(RUN)
        assert [c["call"] for c in calls] == ["claude", "claude.stream", "gpt"], calls
        assert calls[0]["pid"] == first.pid and {c["pid"] for c in calls[1:]} == {second.pid}, calls
        tools = self._tool_calls(RUN)
        assert len(tools) == 1 and tools[0]["pid"] == first.pid, tools
        payments = self._payments()
        assert len(payments) == 1, payments
        refund = payments[0]["refund_id"]
        reply = done["output"]["reply"]
        assert refund in reply, reply
        self.final[RUN] = done
        self.n.check(
            "process 2 finished the run. Claude's decision was read back from the record "
            "instead of being bought again: across the three processes, each of the run's "
            "three model calls (Claude's decision, Claude's reply, GPT's note) reached the "
            "provider exactly once"
        )
        self.n.check(f"the refund was made exactly once ({refund}); the recovery policy found it")
        self.n.say("Claude's streamed reply to the customer:")
        self.n.quote(reply)
        self.n.say("GPT's case note for the CRM:")
        self.n.quote(done["output"]["case_note"])

        entries = self.entries(RUN)
        custody = self.notes(entries, "custody")
        recovery = self.notes(entries, "recovery")
        assert custody, "the takeover of the dead writer's lease left a custody note"
        assert recovery, "the recovery decision was recorded"
        self.n.check(
            f"the record shows the hand-over between processes ({len(custody)} custody "
            f"note{'s' if len(custody) != 1 else ''}) and the recovery decision"
        )

    def step4_anchoring(self) -> None:
        self.n.step(
            4,
            "Both timestamp authorities vouch for the record",
            "Seconds after a run finishes, the server adds its latest state to an "
            "append-only log and asks both timestamp authorities to countersign it. From "
            "then on, not even the server's operator can quietly rewrite that history.",
        )
        deadline = time.monotonic() + ANCHOR_TIMEOUT
        while True:
            s = self.summary(RUN, self.tokens["auditor"]["token"])
            if s["anchored_entries"] == s["entries"]:
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"the run was not independently anchored: {s}\n{self.server.log_tail()}")
            time.sleep(1)
        checkpoints = self.api.ok("GET", "/v1/anchors", self.tokens["auditor"]["token"], query={"limit": 1000})
        covering = [
            cp
            for cp in checkpoints["checkpoints"]
            if any(l.get("run_id") == RUN and l["entries"] == s["entries"] for l in cp["leaves"])
        ]
        assert covering, checkpoints
        cp = covering[-1]
        operators = sorted({w["operator"] for w in cp["witnesses"]})
        assert cp["independent"] is True, cp
        assert operators == sorted(OPERATORS), cp
        self.n.check(
            f"all {s['entries']} entries are anchored in checkpoint {cp['seq']}, countersigned "
            f"by {' and '.join(OPERATORS.values())}"
        )

        ticket = support_agent.TICKETS[RUN]
        seen = json.dumps(self.entries(RUN, self.tokens["auditor"]["token"]))
        assert ticket.email not in seen and "[email]" in seen and ticket.order_id in seen
        self.n.check(
            "the auditor can read the whole run, with the customer's email address shown "
            "as [email]: personal data is redacted for anyone without raw access"
        )

        world = support_agent.World(self.agent_work, RUN)
        before = (len(self._model_calls(RUN)), len(self._tool_calls(RUN)))
        audit = self.sdk(self.admin).replay(RUN, support_agent.make_agent(world))
        assert json.loads(audit.output) == self.final[RUN]["output"]
        assert audit.fresh_steps == 0, audit
        assert (len(self._model_calls(RUN)), len(self._tool_calls(RUN))) == before
        self.n.check(
            "a replay of the run reproduces it exactly from the record: no model was "
            "called and no refund was made"
        )

    def step5_erasure(self) -> None:
        ticket = support_agent.TICKETS[RUN]
        self.n.step(
            5,
            "The customer asks to be forgotten",
            f"{ticket.customer} asks the shop to erase her personal data. An administrator "
            "erases every stored message that contains her email address. The content is "
            "gone for good, but the record around it stays intact and provable.",
        )
        erased = self.api.ok(
            "POST",
            Api.run_path(RUN, "/erase"),
            self.admin,
            json_body={"match": ticket.email, "reason_code": "gdpr_art17", "reason": "erasure request"},
        )
        assert erased["erased"], erased
        s = self.summary(RUN)
        assert s["verify"]["ok"] is True, s
        assert s["erased_slots"] >= 1, s
        notes = self.notes(self.entries(RUN), "erasure")
        assert len(notes) == 1, notes
        note = notes[0]["fields"]["data"]
        assert note["by"] == self.tokens["admin"]["id"] and note["authenticated"] is True, note
        copies = len(erased["erased"])
        self.n.check(
            f"the customer's message is erased everywhere it was stored ({copies} "
            f"cop{'ies' if copies != 1 else 'y'}, one in each request that carried it to "
            f"Claude); the erasure is itself recorded, attributed to the administrator's "
            f"token ({note['by']})"
        )
        rt = self.sdk(self.admin)
        assert rt.verify(RUN), "the chain still verifies after the erasure"
        raw = self.api.request("GET", Api.run_path(RUN, "/journal"), self.admin)
        assert raw.status == 200 and ticket.email.encode() not in raw.body
        self.n.check("the hash chain still verifies end to end, and the email is nowhere in the stored journal")
        world = support_agent.World(self.agent_work, RUN)
        try:
            rt.replay(RUN, support_agent.make_agent(world))
        except pragmatic.Erased as e:
            self.n.check(f"a replay now stops where the erased message was needed (Erased at entry {e.cursor})")
        else:
            raise AssertionError("a replay of erased content succeeded")

    def step6_evidence(self) -> None:
        self.n.step(
            6,
            "An outside auditor checks the evidence, offline",
            "The auditor downloads an evidence bundle, in which anything a personal-data "
            "detector flags is withheld, and checks it on their own machine with two "
            "independent tools, trusting only the roots and the server key they chose. Then "
            "we try to fool them.",
        )
        resp = self.api.request(
            "GET",
            Api.run_path(RUN, "/evidence"),
            self.tokens["auditor"]["token"],
            query={"redact": "detectors", "anchor": "now"},
            timeout=180,
        )
        assert resp.status == 200, resp.body[:500]
        bundle = json.loads(resp.body)
        assert bundle["run_id"] == RUN and bundle["redaction"]["mode"] == "detectors"
        assert bundle["requested_by"] == self.tokens["auditor"]["id"]
        self.bundle = self.evidence_dir / "ticket-4127.evidence.json"
        self.bundle.write_bytes(resp.body)
        withheld = len(bundle["redacted_slots"])
        self.n.check(
            f"downloaded {self.bundle.name}: {bundle['journal']['entries']} entries and "
            f"{len(bundle['anchors'])} anchors, "
            + (
                f"with {withheld} slot{'s' if withheld != 1 else ''} withheld by redaction"
                if withheld
                else "with nothing left to withhold: the customer's message is already erased"
            )
        )

        pinned = self.trust_flags(self.pinned_roots)
        unpinned = self.trust_flags(self.unrelated_roots)
        tampered = self.evidence_dir / "ticket-4127.tampered.json"
        data = bundle["journal"]["data"]
        journal = bytearray(base64.b64decode(data))
        journal[len(journal) // 2] ^= 0x01
        tampered.write_bytes(resp.body.replace(data.encode(), base64.b64encode(bytes(journal))))

        cases = [
            ("the bundle, with the right roots", self.bundle, pinned, 0, "VERIFIED"),
            ("the bundle, with roots that did not sign it", self.bundle, unpinned, 3, "UNANCHORED"),
            ("the bundle with one byte of the journal changed", tampered, pinned, 1, "FAILED"),
        ]
        for what, path, flags, code, verdict in cases:
            cli = self.cli("verify-evidence", str(path), *flags)
            reference = self.reference(str(path), *flags)
            for tool, got in (("pragmatic verify-evidence", cli), ("tools/verify_evidence.py", reference)):
                assert (got.code, got.verdict) == (code, verdict), f"{tool} on {what}:\n{got.output}"
            self.n.check(f"{what}: {verdict} from both verifiers (exit {code})")
            self.n.say(cli.verdict_line)
            for finding in cli.failures:
                self.n.say(f"caught: {finding}")

        html = self.evidence_dir / "ticket-4127.report.html"
        got = self.cli("render-evidence", str(self.bundle), "--format", "html", "-o", str(html), *pinned)
        assert got.code == 0, got.output
        page = html.read_text()
        assert "VERIFIED" in page and RUN in page and "<script" not in page.lower()
        records = self.evidence_dir / "ticket-4127.records.csv"
        got = self.cli("render-evidence", str(self.bundle), "--format", "csv", "-o", str(records), *pinned)
        assert got.code == 0, got.output
        with open(records, newline="") as f:
            rows = list(csv.reader(f))
        assert len(rows) == bundle["journal"]["entries"] + 1, f"{len(rows)} rows"
        assert support_agent.TICKETS[RUN].email not in records.read_text()
        self.report_html = html
        self.n.check(f"wrote a readable report ({html.name}) and every entry as a spreadsheet row ({records.name})")

    def step7_access_log(self) -> None:
        self.n.step(
            7,
            "Who saw what: the access log, and scopes",
            "Every request to the server is written to an access log that is itself "
            "hash-chained and anchored. Tokens only ever see the runs in their scope.",
        )
        records = self.api.audit(self.admin)
        auditor_id = self.tokens["auditor"]["id"]
        downloads = [
            r
            for r in records
            if r.get("route") == "/v1/runs/{id}/evidence"
            and r.get("token_id") == auditor_id
            and r.get("run_id") == RUN
            and r.get("status") == 200
        ]
        assert downloads and downloads[-1].get("redact") == "detectors", downloads
        erasures = [
            r
            for r in records
            if r.get("route") == "/v1/runs/{id}/erase"
            and r.get("token_id") == self.tokens["admin"]["id"]
            and r.get("run_id") == RUN
            and r.get("status") == 200
        ]
        assert len(erasures) == 1, erasures
        self.n.say(f"The access log holds {len(records)} records so far, among them:")
        self.n.check(f"the auditor's evidence download (token {auditor_id}, redacted)")
        self.n.check(f"the administrator's erasure (token {self.tokens['admin']['id']})")

        billing = self.tokens["billing"]["token"]
        resp = self.api.request("GET", Api.run_path(RUN), billing)
        assert (resp.status, resp.code) == (404, "not_found"), resp
        assert self.api.ok("GET", "/v1/runs", billing)["runs"] == []
        try:
            self.sdk(billing).store.summary(RUN)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("an out-of-scope token read the run")
        self.n.check(
            "the billing team's token gets 'not found' for the support run, exactly as if "
            "it did not exist: scopes reveal nothing"
        )

    def step8_restart(self) -> None:
        self.n.step(
            8,
            "The server restarts while an agent is mid-call",
            "A second ticket arrives and its agent is waiting on Claude when the server is "
            "restarted, as in an upgrade. Nothing is lost: leases, indexes and proofs all "
            "come back, and the agent carries on.",
        )
        second = self._agent("run", SECOND, "--gate", "claude:inflight")
        self._wait_for(self.agent_work / "inflight.ready", second)
        before = {r: self.summary(r) for r in (RUN, SECOND)}
        audit_before = len(self.api.audit(self.admin))
        assert self.server is not None
        self.server.restart()
        self.n.check("the server stopped and started again")
        stable = ("entries", "head", "anchored_entries", "erased_slots", "labels", "created_by")
        for r in (RUN, SECOND):
            after = self.summary(r)
            assert {k: after[k] for k in stable} == {k: before[r][k] for k in stable}, (before[r], after)
        listed = self.api.ok("GET", "/v1/runs", self.admin, query={"prefix": "support:"})
        assert sorted(x["run_id"] for x in listed["runs"]) == [RUN, SECOND], listed
        labelled = self.api.ok("GET", "/v1/runs", self.admin, query={"label.queue": "refunds"})
        assert {x["run_id"] for x in labelled["runs"]} == {RUN, SECOND}, labelled
        found = self.api.ok(
            "POST", "/v1/subjects/search", self.admin, json_body={"subject": support_agent.TICKETS[RUN].customer_id}
        )
        assert found["run_ids"] == [RUN], found
        self.n.check("both runs are listed, filtered by label and found by customer, as before")

        contender = self._finish(self._agent("contend", SECOND))
        assert contender.get("outcome") == "locked", contender
        self.n.check("the in-flight agent still holds its run: a second process is refused")
        (self.agent_work / "inflight.go").write_text("go")
        done = self._finish(second)
        assert done["exit"] == 0 and done.get("outcome") == "ok", done
        assert [c["call"] for c in self._model_calls(SECOND)] == ["claude", "claude.stream", "gpt"]
        assert len(self._tool_calls(SECOND)) == 1
        self.n.check("the in-flight agent finished its run without starting over")

        report = self.api.ok("POST", "/v1/verify-data", self.admin, timeout=180)
        assert report["anchors"]["ok"] is True and not report.get("failing_run_ids"), report
        rt = self.sdk(self.admin)
        assert rt.verify(RUN) and rt.verify(SECOND)
        records = self.api.audit(self.admin)
        assert len(records) > audit_before
        assert any(r.get("route") == "/v1/runs/{id}/erase" for r in records)
        resp = self.api.request(
            "GET",
            Api.run_path(RUN, "/evidence"),
            self.tokens["auditor"]["token"],
            query={"anchor": "now"},
            timeout=180,
        )
        assert resp.status == 200, resp.body[:500]
        again = self.evidence_dir / "ticket-4127.after-restart.json"
        again.write_bytes(resp.body)
        got = self.cli("verify-evidence", str(again), *self.trust_flags(self.pinned_roots))
        assert (got.code, got.verdict) == (0, "VERIFIED"), got.output
        self.n.check(
            "every chain, erasure and anchor proof verifies again, the access log kept "
            "every record, and fresh evidence is VERIFIED"
        )

    STEPS: List[Callable[["Story"], None]] = [
        step1_timestamp_authorities,
        step2_server,
        step3_crash_and_resume,
        step4_anchoring,
        step5_erasure,
        step6_evidence,
        step7_access_log,
        step8_restart,
    ]

    def run_all(self) -> None:
        for step in self.STEPS:
            step(self)
