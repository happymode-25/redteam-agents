# redteam-agents — Complete Build Plan

From today's MVP scaffold to a platform that honestly covers every catalog
section it claims, with a defensible safety model and measurable detection
quality.

**Guiding principle from day one:** the product's value is not "we scan
everything" — it is "we check what we check, with evidence, and we tell you
exactly what we could not check." Every phase below ends in the coverage
matrix getting more CHECKED rows and zero dishonest ones.

---

## Current state (MVP scaffold — done)

- Pipeline: plan → recon → analyze → gated verification → report
- Agents: planner, recon, analyst, exploit, reporter (model-agnostic JSON
  tool-loop, hybrid hosted/local routing)
- Tools: subfinder, httpx, nmap, nuclei, web_security_checks, tls_check,
  email_auth_check, http_request, record_finding
- Safety: ScopeGuard (domain/CIDR allowlist, private-IP block, rate limit,
  kill switch), human gates on the active stage
- Findings carry CWE/CVSS/CVE; every report renders the 28-section coverage
  matrix

---

## Phase 0 — Trust before features (1–2 weeks)

**Status: implemented** — all four safety holes closed (redirect hops
scope-checked, resolve-and-pin, docker runner for the sandbox story,
hash-linked audit log) and the eval harness exists (`eval/`, cassette
record/replay, Juice Shop golden target, scorecards). The adversarial
scope-escape suite (`tests/`) covers redirect escapes, DNS rebinding,
IP/host obfuscation, userinfo tricks, IDN homographs, kill-switch behavior
and audit tamper detection — 25 tests, wired into CI
(`.github/workflows/redteam-agents-ci.yml`, fully offline). Remaining:
network-layer egress allowlist in the lab infrastructure (needs the host's
Docker/network setup), and committing eval cassettes so CI can also run
replay-mode scorecards.

Nothing new ships until the current system is *measurable* and *closed*.

### 0.1 Safety holes found in code review (do first — they are real)

| Hole | Fix |
|---|---|
| Redirect escape: `requests` follows redirects to **out-of-scope hosts** (http_request, web_config, httpx) | Wrap the HTTP layer: resolve each redirect hop through `ScopeGuard.authorize()` before following; cap hops |
| DNS TOCTOU: scope is checked on the hostname, then the tool resolves it — DNS rebinding can move the target between check and connect | Resolve-and-pin: resolve to IP once, verify IP in scope, connect to the pinned IP with `Host`/SNI preserved |
| No egress backstop: a tool bug bypasses ScopeGuard | Run all tool subprocesses + HTTP in a container/namespace with an **egress allowlist** (only scoped IPs + model API). ScopeGuard is the policy; the network layer is the enforcement |
| No audit trail | Append-only `audit.jsonl`: every tool call, target, args hash, decision (allowed/denied/confirmed), timestamp. Tamper-evident chain (hash-linked) |

### 0.2 Evaluation harness (the thing that makes everything else science)

- **Golden target suite**: deliberately-vulnerable local apps with known
  ground truth — OWASP Juice Shop, DVWA, NodeGoat, a couple of intentionally
  vulnerable VMs you own. All containerized, all on an isolated lab network.
- **Scoring per run**: known issues found (recall), false positives
  (precision), steps used, wall time, token cost. Stored as JSON, trended.
- **Fixture mode**: tools replay recorded outputs; LLM calls recorded/replayed.
  CI runs the full pipeline with zero network access — determinism test +
  prompt-regression test.
- **Quality gates for later phases**: recall ≥ 70% on the golden suite,
  false-positive rate ≤ 5% before any new detection surface is added.

**Exit criteria:** every run produces a scorecard; the four safety holes are
closed; CI can replay a full assessment offline.

---

## Phase 1 — Depth on the unauthenticated surface (2–4 weeks)

Unlocks more of catalog sections 1, 4, 12, 25 — the "CHECKED" tier gets
actually thorough.

**Status: partial — 1.1 discovery, CVE correlation, 1.2 detection policy, and
1.3 triage quality implemented.**
Shipped: `katana_scan` (double scope enforcement: katana `-fs rdn` + rate/page
caps, then every URL re-authorized through the guard), `content_discovery`
(ffuf + built-in wordlist, rate-limited), `api_discovery` (OpenAPI/Swagger
summarization + GraphQL introspection probe via ScopedSession), `cve_lookup`
(NVD + CISA KEV + EPSS with 24h feed cache and `intel.enabled` privacy
toggle); plus 1.2: the nuclei scan policy enforced in code (severity floor,
tag universe, hard DoS ban, `-duc` always, template pinning via
`template_dir` + `expected_commit`, manual-only updates) and the custom check
plugin format (`checks/*.py`: manifest + `run(ctx)`, loader validation,
`PluginTool` with output cap and `requires_active` gating; two example
checks: `exposed_vcs`, `robots_recon`); plus 1.3 triage quality: deterministic
root-cause clustering (normalized title + CWE + host → one finding with all
instance URLs, cross-host merge forbidden), evidence standards (`confirmed`
requires a tool-observed response pair — enforced at the record tool, the
store, and the report; unsupported confirmations are downgraded with an
inline caveat, never deleted), and partial-confirmation disclosure
("confirmed on k of N URLs"). All wired into prompts/config, covered by 106
offline tests in CI.
Remaining: the Juice Shop baseline recall score (needs the lab up), then
Phase 2 (authenticated testing).

### 1.1 Discovery

- **Crawler**: katana (or headless-browser later) with scope enforcement per
  URL; robots/sitemap ingestion; JS bundle link extraction
- **Content discovery**: ffuf with per-host rate limits and wordlist
  selection driven by tech stack (the analyst agent proposes, code enforces)
- **API discovery**: OpenAPI/Swagger endpoint exposure, GraphQL
  introspection tool, parameter inventory from crawled traffic

### 1.2 Detection

- **Nuclei pack curation**: tag-level curation per tech stack; severity
  floors; template pinning + update policy (reviewed, not auto-latest)
- **CVE correlation** (section 25 upgrade): fingerprinted versions → NVD/OSV
  lookup → findings with CVE + KEV flag + EPSS score; distinguishes
  "vulnerable version" from "exploitation likely"
- **Custom check plugin format**: a Python check = a manifest (id, section,
  schema, prereqs, severity default) + a `run()` with strict I/O limits.
  Registry loads them; agents see them like built-in tools. This is where
  catalog coverage grows without touching the core.

### 1.3 Triage quality

- Agent-side dedup + clustering by root cause (one misconfig, 40 URLs → one
  finding with 40 instances)
- Evidence standards: every confirmed finding must carry a request/response
  pair; the reporter agent cannot invent findings the store lacks

**Exit criteria:** Juice Shop recall ≥ 80% unauthenticated; zero scope
escapes in 50 randomized redirect/rebinding tests in the lab.

---

## Phase 2 — Authenticated testing (3–5 weeks)

The biggest coverage unlock: catalog sections 2, 3, 11 and most of 4 and 10.

**Status: partial — 2.1 identity plumbing, 2.2 authorization engines, and the
JWT-static half of 2.3 implemented.** The headline exit gate (zero credential
leaks) is implemented and enforced in CI; the lab-scored IDOR recall gate is
still pending the lab being up (same blocker as the Phase 1 Juice Shop
baseline).

### 2.1 Identity plumbing — implemented

- Credential vault in config (env refs or encrypted file — never written to
  findings/reports/logs; a redaction pass guards the audit log)
- Login strategies: form login (agent-driven with deterministic replay once
  working), session-cookie injection, API key/Bearer headers, JWT handling
- **Multi-identity sessions**: N identities (e.g. admin/user/anonymous or
  user-A/user-B) held in separate cookie jars

### 2.2 Authorization testing — deterministic engines, agent judgment
**implemented** (IDOR/BOLA + BFLA + schema diff; GET/HEAD only — state-changing
probes stay manual)

- **IDOR/BOLA diff engine** (sections 3, 4): replay the same requests under
  two identities; any response that leaks the other user's object = finding.
  The diff logic is code, not prompt — the agent only chooses *which*
  requests to replay and interprets results
- **BFLA checks**: privileged endpoints called with low-privilege tokens
- **Mass-assignment / excessive data**: response schema diff between
  authenticated and unauthenticated, and vs documented schema

### 2.3 Auth & session analysis (section 2) — implemented; interactive
OTP/password-reset stepping still manual

- JWT static checks — **shipped**: `alg=none`, kid injection patterns
  (path traversal / SQL metachars / URL), key-control headers
  (`jwk`/`jku`/`x5u`/`x5c` → suspected, server acceptance untested),
  weak-secret check against a ~35-entry wordlist (offline, never
  online-password-spraying), expiry/claim analysis, sensitive-payload
  detection
- Account-enumeration diffing — **shipped** (`account_enum`): two
  wrong-password probes (real vs generated account), verdicts in code,
  operator-gated (CWE-204)
- Session lifecycle — **shipped** (`session_check`): cookie flags
  (HttpOnly/Secure/SameSite/lifetime), logout invalidation via
  replay-after-logout (`logout_url` on the identity), fixation
  (pre-auth cookie vs post-login identifier)
- Password-reset/OTP flows: still gated, step-by-step with operator
  confirmation per state change (only remaining 2.3 gap)

### 2.4 Business logic (section 11) — the human-heavy one

- Workflow planner — **shipped** (`workflow_plan` / `workflow_step` /
  `workflow_status`): the exploit agent proposes a stateful test plan
  (checkout, coupon, quota, refund…) of 1..20 ordered steps; the state
  machine is strict (only the next unexecuted step runs, out-of-order
  refused) and recorded to a redacted `artifacts/workflow-<id>.json` so
  replays are reproducible; every request is its own operator approval
  showing the real method + URL (the step is in `ACTIVE_TOOLS`)
- Race-condition tester — **shipped** (`race_burst`): bounded parallel
  request bursts (2..5 workers, one operator approval for the whole
  burst, POST/PUT/PATCH only) for double-spend/TOCTOU; the agent declares
  the invariant (`expect_success_max`), the verdict is computed in code
  (confirmed = successes beyond the invariant, CWE-362)
- Everything defaults to **skipped** — `safety.business_logic: false` in
  config makes all three refuse to run; credentials still come from the
  operator's env-configured identities

**Exit criteria:** IDOR detected on 100% of planted IDORs in the lab API
(pending — needs the lab running); authenticated recall lifts golden-suite
numbers by ≥ 1.5× (pending — same dependency); zero credential leaks across
findings, reports, audit logs (**done** — `tests/test_leak.py` runs as the
CI gate over the LLM observation channel too).

---

## Phase 3 — Beyond-web modalities (4–8 weeks, parallelizable)

Each module takes the platform from "web+network" to a section of the
catalog that was OUT OF BAND. Pick by customer need; they're independent.

| Module | Unlocks | Tools/integration | Access needed |
|---|---|---|---|
| **Repo/SCA mode** | 13, 24, parts of 12/15 | gitleaks (secrets), semgrep (SAST), osv-scanner (deps), checkov/tfsec (IaC), syft (SBOM) — agent triages outputs | Repo read access |
| **Cloud posture** | 7 | Public-surface first: bucket/blob exposure, metadata-endpoint checks (SSRF templates). Credentialed mode: Prowler/ScoutSuite read-only, agent summarizes | None → then read-only cloud role |
| **Container/K8s** | 15 | trivy (images), kube-linter/kubeaudit (cluster, read-only) | Image registry / read-only kubeconfig |
| **AD assessment** | 17 | bloodhound-python, netexec enums — all read-only collection; attack-path analysis is report-only, no abuse | Domain credentials |
| **AI/LLM red team** | 19 | Prompt-injection harness (direct + indirect via tool output), excessive-agency tests, RAG leakage probes against in-scope AI endpoints | AI endpoint in scope |
| **Mobile** | 14 | APK static: manifest audit, hardcoded secrets, exported components (lowest priority) | APK artifact |

Hard rules for this phase: credentialed modules run **read-only** by
default; AD/cloud abuse paths are documented in the report, never executed;
OT/ICS (26) and DoS (22) stay excluded from automation permanently.

**Exit criteria per module:** its catalog rows move to CHECKED/PARTIAL with
a lab-validated detection test in the golden suite.

---

## Phase 4 — Productization (ongoing from Phase 1, completes after 3)

- **Engagement model**: customers → engagements → scope files → authorization
  letter attached; scope changes are signed-off events in the audit log
- **Review queue**: triage UI for findings (confirm/false-positive/accept
  risk); human decisions feed back as few-shot examples into triage prompts
- **Remote approval**: confirm active requests from phone (the exploit-stage
  gate becomes a push notification, not a terminal prompt)
- **Scheduling & CI**: cron runs with drift detection (new findings vs last
  run), GitHub Action for repo mode, ticket export (Jira/Linear) with
  dedup keys
- **Report formats**: HTML/PDF with CVSS v4 vectors, EPSS/KEV enrichment,
  executive + technical splits, per-catalog-section coverage page
- **Cost governance**: per-run token budgets, per-role model downgrades on
  budget pressure, caching of repeated tool output, monthly cost-per-engagement
  dashboard
- **Check marketplace**: signed plugin packs; review process; versioning

---

## Cross-cutting workstreams (never "done")

### Safety & authorization
- Network-layer egress allowlist as the true enforcement boundary
- Scope policy tests: adversarial suite of redirect chains, DNS rebinding,
  IPv6/decimal-IP obfuscation, unicode homoglyphs in scope entries
- Kill switch → control-plane (cancel any run from anywhere)

### Detection quality
- Golden suite grows with every customer-reported miss (regression culture)
- False-positive budget enforced per tool: a tool exceeding 10% FP over N
  runs gets demoted to "informational" until fixed
- LLM routing tuned by cost/quality curves from eval data, not vibes

### Legal & compliance
- Engagement templates per jurisdiction; retention policies for findings
  and captured data; PII handling rules in evidence storage (section 23
  applies to us too)

---

## Sequencing summary

```
Phase 0: trust + eval ──── everything else depends on this
Phase 1: depth (web/API) ─┐
Phase 2: auth testing ────┼──► Phase 3 modules in parallel (pick by need)
Phase 4: productization ──┘         │
                                    └──► platform covers all scannable rows
```

## Success metrics

| Metric | MVP now | After Phase 1 | After Phase 2 |
|---|---|---|---|
| Golden-suite recall | unmeasured | ≥ 80% unauth | ≥ 80% incl. auth cases |
| False-positive rate | unmeasured | ≤ 5% | ≤ 5% |
| Catalog rows CHECKED/PARTIAL | 9 of 28 | 13 of 28 | 19 of 28 |
| Scope escapes in adversarial suite | unknown | 0 | 0 |
| Credential leaks in artifacts | unknown | 0 | 0 |

## Top risks

1. **Agent reliability on logic bugs** — business-logic flaws resist
   automation; mitigation: human-gated workflows, deterministic diff engines
   where possible, honest "needs manual review" outputs.
2. **Tool sprawl** — every new binary is supply-chain risk; mitigation:
   containerized toolchain image, pinned versions, checksum verification.
3. **Cost runaway** — long agent loops on hosted models; mitigation: hard
   step budgets (exists), token budgets (Phase 4), eval-driven model routing.
4. **Legal exposure** — mitigation: scope allowlists are the product's spine,
   authorization letters attached to engagements, audit log is append-only.
