# Compliance mapping

This page maps record-keeping rules that teams running AI agents commonly
face to what Pragmatic provides, and to what stays the customer's job.

> **This is not legal advice.** It describes what Pragmatic does. Whether
> a rule applies to you, which of your records it covers, and what it
> takes to meet it are questions for your own counsel and auditors.
> Rules and dates change; check the current text before relying on any
> row.

> **Status.** Most controls on this page (journal format 2, erasure,
> anchoring, retention, holds, the access log, evidence bundles and
> Pragmatic Server) are 0.6 features in design-partner preview. They are
> not generally available.

## How to read this page

- **"Helps meet"** and **"supports"** mean Pragmatic produces records,
  controls or evidence that the requirement asks for. They never mean
  that using Pragmatic meets the requirement for you.
- Each table has three columns: the requirement, what Pragmatic provides,
  and what you are responsible for.
- The [shared-responsibility matrix](#shared-responsibility-matrix) at the
  end lists the operational controls that are always yours.
- Retention values for each rule, with example configuration, are in
  [privacy.md](privacy.md#retention-presets).

## What we do not claim

- We know of **no law that requires outside anchoring** of AI logs.
  Anchoring makes evidence stronger and catches insiders who edit logs.
  It is not a legal checkbox.
- The EU AI Act asks high-risk systems to keep automatic logs. Its text
  does not ask for logs that cannot be altered, and it does not ask for
  anchoring.
- Pragmatic records only what goes through its journaled interfaces. A
  rule that asks you to log "all" activity covers more than Pragmatic
  sees: see the [threat model](threat-model.md).
- No regulator or standards body has reviewed or endorsed Pragmatic.

## EU

| Requirement | What Pragmatic provides | What you are responsible for |
|---|---|---|
| **EU AI Act, Article 12 (record-keeping).** High-risk AI systems must technically allow the automatic recording of events (logs) over their lifetime, to support traceability, identification of risk situations and post-market monitoring. High-risk obligations apply from **2 December 2027** for the uses listed in Annex III (such as hiring, credit scoring, life and health insurance pricing, public benefits, emergency triage) and from **2 August 2028** for AI in products covered by Annex I, under the AI Omnibus (Regulation 2026/1744, in force since 27 July 2026). Systems already on the market before 2 December 2027 are covered only if their design changes significantly after it (Article 111(2)); systems intended for use by public authorities must comply by 2 August 2030. | **Helps meet** the logging duty for agent activity: every model call, tool call, received message, random draw and clock read made through the journaled interfaces is recorded automatically, before its result reaches the agent, for the life of the run. Each result records the provider, model, outcome and token usage. Labels tie runs to your systems and use cases. The record is tamper-evident and can be anchored (0.6). | Decide whether your system is high-risk and whether you are its provider or deployer. Design what must be logged for your intended purpose (Article 12(2)), and route all relevant activity through the journaled interfaces. Check the consolidated text after the AI Omnibus. |
| **EU AI Act, Article 19 (provider) and Article 26(6) (deployer): keeping logs.** Keep the automatically generated logs under your control for a period appropriate to the intended purpose, **at least six months**, unless other EU or national law (in particular on data protection) says otherwise. Financial institutions keep them as part of their financial-services documentation. | **Supports** retention with a policy minimum (`retain_min_days`) of six months or more, legal holds, and refusal of erasure during the minimum (`erasure = "deny_during_min"`) (0.6). Deleted runs leave tombstones, and an anchored run that disappears without one is flagged as missing. | Choose the period for each system, reconcile it with data-protection law, and configure it. Keep backups for the same period. |
| **DORA, RTS (EU) 2024/1774, Article 12 (logging).** Already applies to EU financial entities. Protect logs against tampering, deletion and unauthorised access; detect failures of logging; synchronise clocks. | **Helps meet** the protection and detection duties for agent logs: a hash chain and salted commitments over every entry; anchoring with at least two independent timestamp operators; roles and scoped tokens; an access log of every request that fails closed; detection of regressed and missing runs; webhooks for a broken chain, failed anchoring and clock skew between clients and the server (0.6). | Synchronise clocks on agent hosts and the server (NTP). Fit Pragmatic into your ICT risk-management framework. Decide with counsel whether your Pragmatic license is an ICT third-party arrangement, and agree the contract terms DORA requires where it is. Encrypt volumes and protect backups. |
| **GDPR, Article 17 (right to erasure).** When a ground in Article 17(1) applies and no exception in Article 17(3) does, erase the personal data without undue delay. | **Supports** erasure of content: erasing a slot removes its content and its salt while every chain hash still verifies, and an `erasure` note records which slots, who erased them and why. Erasure by exact text match covers every repeated copy of a message. A subjects index finds a person's runs. Restores re-apply erasures from the erasure ledger. Erasure during a retention minimum is refused and logged with the reason `legal_obligation`, which supports the Article 17(3) exceptions (0.6). **Structural fields and run ids are not erasable.** | Keep personal data out of fields, labels, tool names and run ids. Decide when an exception applies. Erase copies outside the journal: backups, exported bundles, local journals, model providers' logs. Answer within the GDPR deadlines. See [privacy.md](privacy.md#subject-requests-and-erasure). |

## US financial services

| Requirement | What Pragmatic provides | What you are responsible for |
|---|---|---|
| **SEC Rule 17a-4(f), audit-trail alternative** (broker-dealers; available since the 2022 amendments). Instead of non-rewriteable, non-erasable storage, keep electronic records with a complete time-stamped audit trail of every modification and deletion, the date and time of each action, the identity of whoever acted, and what is needed to re-create the original; be able to verify records and produce them in human-readable and usable electronic formats; keep a backup set. Retention under 17a-4(a) and (b): **6 years** for core records and **3 years** for communications and many other records, the first **2 years** easily accessible. | **Supports** the audit-trail alternative for agent records when you set `erasure = "deny_during_min"` and a `retain_min_days` at or above the applicable period (0.6). Through Pragmatic's interfaces the journal is append-only, and the only change a recorded entry can undergo is erasure, which is then refused during the minimum; every erasure is itself recorded with its time, token and reason. A server administrator with root could still rewrite the unanchored end of a run; anchoring makes changes to anchored entries detectable (see the [threat model](threat-model.md#the-unanchored-window)). Attempt and custody notes name the token and principal that wrote each part of a run. Anchoring gives independent time. Periodic re-verification checks every chain and anchor. Evidence bundles export JSON, and `render-evidence` produces HTML and CSV. | Decide whether agent prompts and outputs are records under the rule (this is not settled). **Provide the designated third party** (or designated executive officer) undertaking. **Keep the duplicate copy**: a backup set held separately. Configure retention per record class, and hold records for examinations. Synchronise clocks. |
| **FINRA Rule 4511 (books and records).** Make and preserve required books and records, for **6 years** where no other period applies, in a format and media that meet SEA Rule 17a-4. | **Supports** the same configuration as the 17a-4 row, with a six-year minimum where no other period applies (0.6). The journal records what FINRA's 2026 oversight report suggests firms consider for AI agents: prompt and output logs, model versions, and the agent's actions. | Decide which agent records are books and records. Supervision of agents (under FINRA's supervision rules) is outside Pragmatic. |
| **NYDFS, 23 NYCRR 500.6 (audit trail).** Based on your risk assessment, keep systems designed to reconstruct material financial transactions (keep those records **at least 5 years**) and audit trails designed to detect and respond to cybersecurity events (**at least 3 years**). | **Helps meet** both parts for agent activity: exact replay reconstructs what an agent did and with what inputs; the access log, chain checks and alerts help you detect tampering and misuse; retention minimums of five and three years (0.6). | Scope it through your risk assessment. Feed alerts into your incident response. The rest of Part 500 (access privileges, encryption, monitoring) is yours. |

## US health and life sciences

| Requirement | What Pragmatic provides | What you are responsible for |
|---|---|---|
| **HIPAA Security Rule, 45 CFR 164.312(b) (audit controls).** Implement hardware, software or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information. | **Helps meet** audit controls for agents: every model and tool call through the journaled interfaces is recorded, and with Pragmatic Server every read of a journal is in the access log (0.6). | The journal now holds protected health information itself: encrypt it, restrict access, and include it in your risk analysis. Have business associate agreements with model providers. Set up the "examine" part: who reviews activity, and how often. Check the status of the proposed Security Rule revision. |
| **FDA, 21 CFR 11.10(e) (audit trails).** Use secure, computer-generated, time-stamped audit trails that independently record the date and time of operator entries and actions that create, modify or delete electronic records; changes must not obscure earlier information; keep the trail as long as the records it covers and make it available to the agency. | **Helps meet** the audit-trail control where agents touch regulated records: entries are generated by the runtime, not by the agent's code, and each carries a time. Anchoring gives an independent upper bound on when entries existed. A changed entry breaks the chain, which catches anyone who cannot recompute it; anchoring makes changes to anchored entries detectable even by the operator. With erasure denied during retention, nothing recorded is obscured through Pragmatic's interfaces. A server administrator with root could still rewrite the unanchored end of a run (see the [threat model](threat-model.md#the-unanchored-window)). Evidence bundles and their HTML and CSV renderings support agency review (0.6). | Validate the system for its intended use (11.10(a)). Limit system access (11.10(d)) and map tokens to people. Electronic signatures (Part 11, subpart C) are outside Pragmatic. Synchronise clocks: the time in each entry comes from the machine that wrote it. Set retention to match the records. |

## Automated decisions (US states)

| Requirement | What Pragmatic provides | What you are responsible for |
|---|---|---|
| **Colorado SB 26-189** (signed 14 May 2026; duties from **1 January 2027**). For automated decisions in employment, education, lending, insurance, housing, health care and essential government services: give notice, explain an adverse decision (check the enacted text and the Attorney General's rules for the timing), offer human review where commercially reasonable, and keep records for **3 years**. | **Supports** explanation and review: each decision's run is an exact, replayable record of what the agent was given and what it did. Labels link runs to decisions. A three-year retention minimum (0.6). | Decide which decisions are covered. Write the notices and explanations, and run the human review process. |
| **California privacy agency rules on automated decision-making technology** (duties from **1 January 2027**; risk assessments due **31 December 2027**). Notice, opt-out and access rights for automated decisions. | **Supports** access requests with per-person decision records: the subjects index finds a person's runs, and evidence bundles export them with redaction (0.6). | Notices, opt-outs, risk assessments, and the response to each request. |
| **California employment regulations on automated-decision systems** (since **1 October 2025**). Keep employment records, including automated-decision data, for **4 years**. | **Supports** keeping agent records for hiring and employment decisions with a four-year retention minimum and erasure denied during it (0.6). | Decide which records are covered, and keep the rest of the employment file. |

## Standards and assurance frameworks

| Requirement | What Pragmatic provides | What you are responsible for |
|---|---|---|
| **ISO/IEC 42001, Annex A control A.6.2.8 (AI system recording of event logs).** Determine at which phases of the AI system life cycle event logs are recorded, at least while the system is in use. | **Provides evidence for** the control: journals show that every journaled call was recorded while agents ran, and evidence bundles let an auditor check that independently. | Define the logging phases in your AI management system, and document why. |
| **SOC 2, CC7.2 (monitoring for anomalies).** Monitor system components for anomalies that indicate malicious acts, natural disasters and errors, and analyze them to decide whether they are security events. | **Supports** monitoring of the agent record: webhooks for a broken chain, failed anchoring, regressed or missing runs, dangling tool calls and clock skew; metrics for anchoring lag and the access log; daily re-verification (0.6). | Route alerts to people, analyze them, and respond. Pragmatic Server sits inside your system boundary, so its operation is part of your controls. |
| **AIUC-1, E015 (Log AI system activity).** A mandatory control: keep logs of AI system processes, actions and agent outputs, where permitted, to support incident investigation. Its requirement text does not specify tamper evidence or a retention period. | **Provides evidence for** the control: the journal and evidence bundles. | Show that every agent in scope runs through Pragmatic. |
| **AIUC-1, E009 (Monitor third-party access).** A mandatory control: monitor and log third-party API connections, sessions and data access. | **Provides evidence for** model API calls made through wrapped clients (provider, model, status and the full exchange) and for tool calls journaled with `ctx.tool` or `ctx.run_tools`. | Journal other third-party calls through `ctx.tool`, including MCP tool calls. |

## Shared-responsibility matrix

| Area | Pragmatic | You |
|---|---|---|
| **TLS** | The server speaks plain HTTP and refuses to listen on a non-loopback address unless you confirm TLS ends in front of it (`allow_plain_http`). The SDK refuses plain `http://` except to loopback. TLS inside the server is planned for 0.7. | Terminate TLS at your proxy or ingress, with your certificates and cipher policy. |
| **Time (NTP)** | Each entry records the writing machine's clock, for information. The server flags clients whose clock differs from its own by more than `max_clock_skew_secs`. The only proven time comes from timestamp authorities and witnesses. | Synchronise clocks on agent hosts and the server, and monitor them. |
| **Volume encryption** | Journals are plain text by design. The Kubernetes manifests point to storage classes encrypted with a key-management service. | Encrypt volumes and backups, and manage those keys. Choose the data region (wherever `data_dir` lives). |
| **Backups** | `pragmatic-server backup` (with a signed manifest) and `restore`, which re-applies erasures from the erasure ledger and flags runs that went back in time. Periodic re-verification of all data. | Schedule backups, keep them off the host, stream the erasure ledger off the host, test restores, and expire backups on your retention schedule. Keep the separate backup set that SEC 17a-4 asks for. |
| **Identity provider** | Tokens with a role, scopes and a named principal; an access log of every request; console sessions with idle and absolute timeouts. OIDC sign-in is planned for 0.7. | Map principals to people, issue and revoke tokens, review access regularly, and protect the bootstrap admin token. |
| **Retention configuration** | Policies with a minimum, shred and delete ages, and an erasure rule; legal holds; tombstones. When several policies match, the most restrictive value wins. | Choose the periods for each record class and jurisdiction, configure them, and place holds. |
| **Timestamp authority permissions** | Default configuration with DigiCert and Sectigo and their pinned roots; requests to one authority spaced at least 15 seconds apart; support for any RFC 3161 authority, including qualified (eIDAS) providers. | Get written permission from each authority's operator for automated use, or contract a provider. Choose the operators you rely on. |
| **SEC 17a-4 designated third party** | Evidence bundles that a third party can verify independently, offline. | Provide the designated third party (or designated executive officer) undertaking and the duplicate copy. |
| **Signing and journal keys** | The server's signing key is kept outside the data directory by default, and key rotation is recorded in the access log. Journal keys are read from a file or an environment variable; the command-line flag is deprecated. | Generate, store, back up and rotate keys. Give auditors the server's public key through a channel they trust. |
| **Network egress** | No telemetry. The server connects only to the timestamp authorities, witnesses and webhook URLs you configure, and sends them no content. | Restrict egress to those endpoints. |
| **Model providers** | Calls through wrapped clients are recorded; transport headers such as API keys are not. | Contracts with model providers (data processing and business associate agreements) and their own data retention. |
| **Coverage** | Records everything that goes through the journaled interfaces. | Route all model and tool calls through them, and test that your framework's calls appear in the journal. |
| **Availability** | One server per deployment in 0.6. | High availability, disaster recovery and capacity. |
| **Legal judgments** | This mapping. | Whether each rule applies, what counts as a record, lawful bases, and impact assessments. |
