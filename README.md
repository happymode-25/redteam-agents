# redteam-agents

Multi-agent autonomous red team / vulnerability assessment system (PentAGI-style).

A planner agent breaks an assessment into phases, executor agents run real
security tooling (nmap, nuclei, httpx, subfinder), an analyst agent triages
results into findings, and a gated exploit agent drafts/sends proof-of-concept
requests with human approval. A reporter agent writes everything up.

## Architecture

```
                        ┌──────────────────────────────────────────┐
                        │              Orchestrator                │
                        │  plan → recon → analyze → (gate) → report │
                        └───────┬──────────────────────────────────┘
                                │ every tool call passes through
                        ┌───────▼────────┐
                        │   ScopeGuard   │  allowlist · CIDR match · private-
                        │  kill switch   │  IP block · rate limit · kill switch
                        └───────┬────────┘
                                │
     ┌──────────┬───────────────┼───────────────┬──────────────┐
     ▼          ▼               ▼               ▼              ▼
 Planner    Recon agent    Analyst agent   Exploit agent   Reporter
 (hosted)   subfinder      nuclei          http_request    (hosted)
            httpx          cve_lookup      nuclei
            katana         http_request    record_finding
            ffuf           record_finding
            nmap
     │          │               │               │              │
     └──────────┴───────────────┴───────────────┴──────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   Hybrid LLM router    │
                    │ hosted: planning/exploit│
                    │ local (Ollama): triage  │
                    └────────────────────────┘
```

**Hybrid model routing** (config `llm.roles`): reasoning-heavy roles
(planner, exploit, reporter) run on a hosted model; noisy triage/parse work
(analyst) runs on a local Ollama model so raw target data stays on your machine.

## Hard safety model

The LLM **never** talks to the network directly. Every tool execution is
wrapped by `ScopeGuard`, which is plain code the prompt cannot influence:

1. **Target allowlist** — exact-domain or subdomain-of-allowlisted match;
   CIDR allowlist for IPs. Everything else raises `ScopeViolation` and
   aborts the stage.
2. **Private IP blocking** — RFC1918/loopback/link-local targets are refused
   unless `scope.allow_private: true` (for authorized internal tests).
3. **Rate limiting** — per-host token bucket.
4. **Kill switch** — Ctrl+C, or touch `artifacts/KILLSWITCH` mid-run, and
   every agent stops at the next step boundary.
5. **Human gate** — the exploit stage only runs with `--allow-active`, and
   each raw HTTP request requires interactive confirmation (skippable with
   `--yes` for scripted authorized runs).

Prompt injection through tool output cannot widen scope: tool results are
data, and authorization happens in code after the model has spoken.

## Requirements

- Python 3.10+
- External tools on PATH (install what you need; missing tools degrade
  gracefully and are simply not offered to the agents):
  - [nmap](https://nmap.org)
  - [nuclei](https://github.com/projectdiscovery/nuclei)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [subfinder](https://github.com/projectdiscovery/subfinder)
  - [katana](https://github.com/projectdiscovery/katana) (Phase 1 crawling)
  - [ffuf](https://github.com/ffuf/ffuf) (Phase 1 content discovery)
- For the local leg: [Ollama](https://ollama.com) with a tool-capable model,
  e.g. `ollama pull qwen3-coder:30b` (any decent instruct model works).
- For the hosted leg: an API key for an OpenAI-compatible endpoint
  (OpenAI, OpenRouter, ...) or Anthropic.

On Windows, WSL2 is recommended for the external tooling; the Python code
itself is cross-platform.

## Setup

```bash
cd redteam-agents
python -m venv .venv && .venv\Scripts\activate    # or source .venv/bin/activate
pip install -r requirements.txt
copy config.example.yaml config.yaml              # Windows
# cp config.example.yaml config.yaml              # macOS/Linux
```

Edit `config.yaml`:

- `llm.hosted` — endpoint + model + `api_key_env` (name of the env var
  holding your key; the key itself is never stored in the file)
- `llm.local` — Ollama endpoint + model
- `scope.allow_domains` / `scope.allow_cidrs` — **the only targets the
  system may ever touch**

```bash
set OPENAI_API_KEY=sk-...     # Windows; export on macOS/Linux
ollama serve                   # if not already running
```

## Usage

```bash
# Assessment of an in-scope target (scanning + triage + report)
python main.py --target example.com --config config.yaml

# Include the exploit/PoC stage (asks before every raw HTTP request)
python main.py --target example.com --config config.yaml --allow-active

# Scripted run (CI / air-gapped lab): skip per-request prompts
python main.py --target 10.0.0.0/24 --config config.yaml --allow-active --yes
```

Reports land in `artifacts/`:

- `report-<timestamp>.md` — executive summary, findings table, per-finding detail
- `findings.json` — machine-readable findings
- `KILLSWITCH` — create this file to stop a running assessment

## Vulnerability catalog coverage

The full 28-section vulnerability catalog cannot be verified by any single
black-box scan. Every report therefore includes a **coverage matrix** stating
per catalog section whether it was CHECKED, PARTIAL, NEEDS CREDS, OUT OF BAND,
HUMAN REVIEW, or NEVER AUTO — and why. Summary of the mapping:

| Tier | Catalog sections | Mechanism |
|---|---|---|
| CHECKED every run | 5, 9, 12, 20, 25, 27 | nmap, tls_check, web_security_checks, email_auth_check, nuclei + CWE/CVSS/CVE on findings |
| PARTIAL | 1, 4, 6, 8, 10, 23 | unauthenticated surface only; with identities configured, 4 also gets authenticated authz/data-exposure checks |
| NEEDS CREDS | 2, 3, 11 | operator supplies accounts; with identities configured, 3 becomes CHECKED (idor_diff + bfla_check) and 2 PARTIAL (jwt_check + login verification) **only when those tools actually ran** — the matrix upgrades per run, never on configuration alone |
| OUT OF BAND | 7, 13–19, 24, 26 | cloud creds, repos, clusters, APKs, AD, AI systems — different tooling |
| HUMAN REVIEW | 21, 28 | organizational, not scannable |
| NEVER AUTO | 22, 26 | DoS and active ICS testing are deliberately excluded for safety |

Dependency-free check modules (`web_security_checks`, `tls_check`,
`email_auth_check`) work without installing nmap/nuclei — only the external
CLI tools are optional.

## Phase 0 hardening (implemented)

- **Redirect escape closed** — `ScopedSession` follows redirects manually;
  every hop passes the scope allowlist and DNS check
- **DNS rebinding closed** — `Guard.resolve()` resolves once, rejects
  non-global answers (unless `allow_private`), and connections are pinned to
  the verified IP (SNI/cert validation stay on the real hostname)
- **Audit trail** — `artifacts/audit.jsonl`, hash-linked append-only chain of
  every scope decision, tool call, confirmation and agent lifecycle event;
  verify with `redteam.audit.verify_chain()`
- **Sandbox runner** — `safety.runner: docker` executes CLI tools in the
  hardened toolchain container (`docker/toolchain.Dockerfile`,
  `--cap-drop ALL`, memory/pids limits). Network-layer egress allowlisting
  remains an infrastructure responsibility (compose lab binds to 127.0.0.1)
- **Eval harness** — `eval/` with a Juice Shop golden target, ground-truth
  scoring (recall/precision candidates), and `live | record | replay`
  cassette modes so CI can run the full pipeline fully offline
  (`--mode replay`; misses never execute real tools or API calls)

Known limitation: `getaddrinfo` pinning is process-global per request —
agents execute sequentially, which the orchestrator guarantees; if you add
parallel tool execution, revisit the pin (e.g. move to per-connection
adapters).

## Phase 1 depth (implemented)

Four new discovery/intelligence layers, all wired into the recon/analyst
prompts:

| Tool | What it does | Safety / honesty notes |
|---|---|---|
| `katana_scan` | crawls an origin (configurable depth, JS endpoint extraction), returns discovered URLs | two scope layers: katana runs with `-fs rdn` (root-domain scope) + rate cap (30 rps) + 100 pages/domain crawler-trap limit, **and** every URL is re-authorized through the scope guard before agents see it (`filter_in_scope`) — out-of-scope hits are dropped and counted |
| `content_discovery` | ffuf hidden-path discovery with a built-in ~120-entry wordlist (`wordlists/common-paths.txt`), custom wordlist path supported | rate-limited (default 20 rps), results capped |
| `api_discovery` | probes common OpenAPI/Swagger locations, summarizes valid specs (title, paths, auth schemes, paths declaring no security), probes GraphQL endpoints with **one read-only introspection query** | every request via `ScopedSession` (per-hop scope + DNS pinning) |
| `cve_lookup` | NVD keyword lookup for fingerprinted product/version → CVEs with CVSS/CWE, plus CISA **KEV** flag and **EPSS** exploit-probability scores, cached 24h | privacy: sends target-derived keywords to third-party APIs (nvd.nist.gov, cisa.gov, api.first.org) — set `intel.enabled: false` to disable completely; on failure it reports the gap instead of inventing CVEs from model memory |

Config: new `intel:` section (`enabled`, `nvd_api_key_env`,
`cache_ttl_hours`) in `config.example.yaml`. The toolchain Docker image
now also builds katana and ffuf (Go 1.27.2, build toolchain purged after).

### Scan policy + custom checks (Phase 1.2)

The nuclei scan policy is enforced in **code**, not by prompt
(`nuclei:` config section):

| Control | Behavior |
|---|---|
| Severity floor | `severity_floor` clamps every scan; a request entirely below the floor fails loudly instead of silently scanning more |
| Tag universe | agents propose tags, code filters them through `tags_include`/`tags_exclude`; dropped tags are reported in the result |
| DoS hard-ban | `dos` is never scanned — not even if an operator puts it in the include universe (catalog section 22 is permanently excluded) |
| Template pinning | `template_dir` + `expected_commit`: the tool refuses to scan when the checkout HEAD does not match the reviewed pin; unpinned template sets are called out in every result |
| No auto-update | `-duc` is always passed; `update_policy` accepts `manual` only — templates change when a human reviews the diff |

### Custom check plugins (`checks/*.py`)

Catalog coverage grows through one-file Python checks. Each file has a
`MANIFEST` dict (id, catalog section 1–28, JSON-schema parameters, default
severity, optional `requires_active`) and a `run(ctx)` returning
`{"summary": str, "findings": [...]}`. The loader validates manifests and
skips broken files with a warning — a bad check never blocks a run. Valid
plugins appear to the agents as normal tools whose description names their
catalog section (`[custom check · §24 ...]`).

**Trust model, stated plainly:** plugins are operator-installed local code —
review them like any dependency; they run in-process with full Python. The
LLM never writes or modifies them; it only decides when to call one. Plugin
HTTP traffic still goes through the injected `ScopedSession` (scope guard +
DNS pinning apply), a scope violation aborts the stage, and oversized plugin
output is truncated by a fixed I/O cap.

Two checks ship as examples: `exposed_vcs` (deep VCS metadata:
`.git/config`, `.hg`, `.bzr` — complements `web_security_checks'`
`.git/HEAD` probe, section 24) and `robots_recon` (sensitive-path disclosure
in robots.txt, section 12).

### Triage quality (Phase 1.3)

Both controls are deterministic code (`redteam/triage.py`) — applied to the
finding store regardless of who wrote a finding, and the reporter agent
cannot route around them:

| Control | Behavior |
|---|---|
| Root-cause clustering | findings grouping by (normalized title, CWE, host) merge into ONE finding at report time with every instance URL listed — one misconfig on 40 URLs is reported once, not 40 times. Cross-host findings never merge (blast radius stays honest) |
| Evidence standard | a finding can only be `confirmed` when its evidence contains a tool-observed response (request/response pair); otherwise it is stored/reported as `suspected` with an inline `[evidence-standard]` caveat — downgraded, never deleted |
| Partial confirmation | when a cluster is confirmed on only k of N instance URLs, the report says exactly that, and each instance URL is marked demonstrated or not |

## Phase 2 authenticated testing (implemented)

Catalog sections 2, 3, 4 and most of 10 move from "needs creds" to testable.
The agent never sees credentials; it only names operator-configured
identities.

### Identity plumbing (`identities:` in config)

Secrets are referenced by **env var name only** — config files, findings,
reports and audit logs never carry values:

```yaml
identities:
  - name: alice
    kind: form                      # form | cookie | bearer | apikey
    login_url: https://shop.test/rest/user/login
    username_env: ALICE_EMAIL
    password_env: ALICE_PASSWORD
    verify_url: https://shop.test/rest/user/whoami   # optional proof of login
    verify_marker: "alice"
    logout_url: https://shop.test/logout     # optional; enables the logout probe
  - name: bob
    kind: cookie
    cookie_env: BOB_SESSION_COOKIE
```

`SessionManager` (`redteam/auth.py`) holds a **separate ScopedSession per
identity** (own cookie jar + headers), so two principals can replay the same
request independently. Login strategies: form login (deterministic POST,
optional verify_url/marker gate), static cookie, bearer token, API key
header. A login that fails verification leaves **no half-open session**; the
failure is audit-logged and surfaced as a ToolError naming the env var, never
the value. Login and verification traffic goes through the same per-hop scope
authorization + DNS pinning as every other request.

### Redaction pass (`redteam/redact.py`)

Every resolved secret is registered with a process-wide redactor **before any
network call**, and four exit channels are scrubbed. Cookies the target sets
during login are registered too, so the operator's live session identifier
can never appear verbatim in any output (the logout/fixation probes compare
identifiers in memory and report only redacted evidence).

| Channel | Where |
|---|---|
| Audit log | `AuditLog.record` (values scrubbed before hashing — the chain stays verifiable) |
| Findings store | `SharedState.add_finding` (title/target/evidence/remediation) |
| Rendered report | final document pass in `render_report` |
| **LLM observations** | `Agent._execute_tool` — tool output is scrubbed before it becomes context for the hosted model (a target echoing our password back cannot reach a third-party API) |

Target-found secrets are deliberately *not* scrubbed — those are findings.
`tests/test_leak.py` is the CI gate: it drives a simulated authenticated
engagement with deliberately leaky inputs and asserts no registered secret
survives in any of the four channels (Phase 2 exit criterion).

### Authorization engines — code decides, the agent only chooses

The agent picks *which* URL and *which* identities; the verdict is computed in
`redteam/tools/` and never by a prompt:

| Tool | Method | Verdicts | Notes |
|---|---|---|---|
| `idor_diff` | GET/HEAD only | `confirmed` (B's response contains A's `object_marker`), `suspected` (near-identical bodies, no marker), `access_control_ok` (B denied / differs), `inconclusive` (A can't read it, marker invalid) | CWE-639. Containment overlap ≥ 0.8 over ≥ 3 scalar values; JSON-aware, line fallback for HTML |
| `bfla_check` | GET/HEAD only | same ladder plus soft-denial detection (`{"error":"unauthorized"}` with HTTP 200 counts as denied) | CWE-285. `suspected` = low-priv identity got an undenied 2xx from a privileged endpoint |
| `schema_diff` | GET only | `confirmed` (unauthenticated response carries sensitive-named fields **with values**), `suspected` (fields beyond operator `expected_fields`), `no_issue`, `inconclusive` | CWE-200. CSRF/nonce fields excluded; auth-only fields reported as context, not findings |
| `jwt_check` | static, no traffic | `confirmed` (HS* signature verifies against a ~35-entry well-known secret list, or claims carry sensitive data — payloads are only base64), `suspected` (alg `none`, key-material/kid injection surface, no `exp`, > 30-day lifetime), `no_issue` | CWE-798/200/347/613/22/89. Key-control headers (`jwk`/`jku`/`x5u`/`x5c`) and traversal/SQL/URL patterns in `kid` are flagged. RS*/ES* signatures cannot be verified locally. `source` provenance is required for confirmed findings |
| `account_enum` | 2× POST or GET probes | `confirmed` (existence wording only in the fake-account response), `suspected` (status/body discrepancy), `no_issue` (identical), `inconclusive` | CWE-204. Same locally generated wrong password for both probes — never from config; echoed usernames are normalized away; operator-gated (consumes failed-login attempts) |
| `session_check` | GET, plus one logout POST | `confirmed` (cookie readable after logout, identifier unchanged across login, missing HttpOnly/Secure on the session cookie), `suspected` (missing SameSite, > 24h lifetime), `no_issue`, `inconclusive` | CWE-613/384/1004/614/1275. `logout` needs `logout_url` on the identity; `fixation` needs a URL that issues a pre-auth cookie; the only write is the identity's own logout (operator-gated) |

Authorization probing is **read-only for the target's data**: methods other
than GET/HEAD are refused in code, and mass-assignment (writing `role`/owner
fields) stays manual. The only state changes these engines ever perform are
on our own sessions — the identity's own logout in `session_check` and the
two failed-login attempts in `account_enum` — and both are operator-gated as
active tools.

Each engine returns a request/response evidence pair plus a `recommendation`
(`record_finding ... confirmed` / `do NOT record a finding`) so verdict →
handling is deterministic instead of a judgement call.

### Business-logic workflows (Phase 2.4, section 11)

Stateful abuse — double-spend, coupon stacking, quota bypass, refund gaming
— needs ordered writes, so it is split across three tools plus a bounded
race tester. **Everything refuses to run until the operator sets
`safety.business_logic: true`**, and even then every single request is
individually approved:

| Tool | Network | What it does |
|---|---|---|
| `workflow_plan` | none | The agent proposes 1..20 ordered steps (method, URL, payload, `expect_status`); scope violations abort at plan time; returns an 8-hex `plan_id` |
| `workflow_step` | 1 request per call | Executes **exactly the next** step — out-of-order or rerun requests are refused with the executed/pending lists. In `ACTIVE_TOOLS`: the operator sees the real `METHOD URL (workflow id, step n/N 'name')` before it is sent. The transition (request echo, status, timing, body hash/excerpt) is appended to `artifacts/workflow-<id>.json` — a redacted, replayable record of the state machine |
| `workflow_status` | none | Read-only state machine: executed/pending steps, per-step status/timing |
| `race_burst` | 2..5 concurrent writes (POST/PUT/PATCH only) | One operator approval fires a bounded burst; the agent declares the invariant (`expect_success_max`, default 1; `expect_status`/`success_marker` define success). Verdicts in code: `confirmed` = more successes than allowed (CWE-362), `suspected` = unexpected status or divergent same-status bodies, `no_issue` = serialized, `inconclusive` = burst never succeeded |

Anonymous flows keep one cookie jar per plan (steps share session state);
identity flows run on the logged-in identity's `ScopedSession`. Rejected
step → the flow stops with whatever was recorded.

## Testing

```bash
python -m unittest discover -s tests -v
```

Sixteen suites, all fully offline (no target traffic, no API keys):

- `tests/test_scope_adversarial.py` — the scope-escape attack suite:
  redirect escapes (out-of-scope host, unlisted IP), redirect loops,
  kill-switch mid-chain, decimal-IP/userinfo/suffix/homograph obfuscation,
  IDN→punycode normalization on both sides of the comparison, private IPv6,
  DNS rebinding simulation, and audit coverage of denials.
- `tests/test_fixtures_and_audit.py` — replay is hard-offline (exploding
  tool/provider prove real implementations never run on hit or miss), live
  mode never writes cassettes, and the audit chain detects edits/reorders
  (tail truncation limitation is tested and documented — anchor externally).
- `tests/test_phase1.py` — Phase 1 parsers (katana jsonl, ffuf JSON,
  OpenAPI summary) with scope filtering, `cve_lookup` against mocked
  NVD/KEV/EPSS APIs (incl. caching, disabled-intel no-network guarantee),
  `intel` config parsing, and full orchestrator tool-registration wiring.
- `tests/test_nuclei_policy.py` — severity-floor clamping, tag universe
  filtering, the hard DoS ban (config cannot re-enable it), template pin
  accept/mismatch/refuse against a throwaway git repo, `-duc` always on,
  and policy config parsing (auto-update rejected).
- `tests/test_plugins.py` — plugin loader validation (bad manifests are
  skipped with warnings, duplicates refused), PluginTool behavior (output
  cap, `requires_active` gating, scope violations abort the stage instead
  of degrading), and orchestrator wiring incl. built-in shadow refusal.
- `tests/test_triage.py` — evidence standards (confirmed without a
  response artifact is downgraded to suspected at every writer: tool,
  store, report) and root-cause clustering (title/CWE/host grouping,
  instance roll-up, cross-host separation, partial-confirmation disclosure).
- `tests/test_identity.py` — identity config parsing (all four kinds,
  env-var-only secrets, validation and duplicate rejection) and the
  redaction pass across audit log, findings and report.
- `tests/test_session.py` — session manager with a fake transport: form
  login + token extraction, verification gating, no-half-open-session rule,
  static cookie/bearer/apikey injection, scope violations aborting and
  audited, secret-free status payloads, session tools.
- `tests/test_idor.py` — every IDOR verdict branch as a pure function,
  similarity math (JSON containment + line fallback), tool behavior
  (marker confirmation, same-identity refusal, GET/HEAD-only enforcement,
  evidence redaction), orchestrator wiring.
- `tests/test_authz.py` — BFLA verdicts incl. soft denials, schema-diff
  verdicts (sensitive anonymous exposure, documented-schema extras,
  CSRF exclusion), tool behavior and **coverage-matrix honesty** (section 3
  upgrades only when idor_diff/bfla_check actually ran).
- `tests/test_jwt.py` — real HMAC-crafted tokens: weak-secret verification,
  alg none, kid/key-control headers (jwk/jku/x5u/x5c, traversal/SQL in kid),
  missing/long/expired `exp`, sensitive claims, RS256 structure-only,
  provenance marker in evidence, redaction.
- `tests/test_enumeration.py` — account-existence oracle: pure verdict
  (explicit existence wording vs status/body discrepancy vs echo-only
  difference), wrong-password-never-from-config, username redaction,
  GET/POST probe forms.
- `tests/test_session_check.py` — session lifecycle: cookie-flag verdicts
  (HttpOnly/Secure/SameSite/lifetime), logout replay-after-logout,
  fixation (unchanged pre-auth identifier vs rotation), redacted evidence.
- `tests/test_workflow.py` — business-logic state machine: step parsing
  and strict in-order execution (out-of-order sends nothing), disabled-by-
  default refusal, artifact round-trip through the redaction pass, identity
  vs anonymous session continuity, coverage section-11 honesty, and the
  operator prompts that must show the real method + URL.
- `tests/test_race.py` — bounded burst tester: pure `burst_verdict`
  tables (double-spend confirmed, unexpected-status/divergence suspected,
  consistent conflicts = no issue), count/method caps, worker seeding with
  identity credentials, transport errors → inconclusive, and
  ScopeViolation escaping the thread pool (stage-abort invariant).
- `tests/test_leak.py` — the Phase 2 exit gate: one simulated authenticated
  engagement with deliberately leaky inputs proves no registered secret
  survives in the LLM observation, audit log (chain still verifies),
  findings JSON, report markdown, or login error messages.

CI runs all sixteen on every push/PR touching this directory
(`.github/workflows/redteam-agents-ci.yml`).

## Legal / ethics

Only run this against systems you own or have **written authorization** to
test. Unauthorized scanning and exploitation are crimes in most jurisdictions
even when performed by an autonomous system. The scope allowlist is your
authorization boundary — keep it narrow, keep the rate limits sane, and keep
a human in the loop for the exploit stage.

## MVP status — what works and what doesn't

Works now:
- Full pipeline: plan → passive/active recon → crawl/content/API discovery →
  nuclei triage → CVE/KEV/EPSS correlation → findings → Markdown report
- Scope enforcement, rate limiting, kill switch, human gating
- **Authenticated testing**: multi-identity sessions (form/cookie/bearer/API
  key), deterministic IDOR/BOLA and BFLA diff engines, response-schema
  (excessive-data) diff, JWT static checks (incl. kid/key-control),
  account-enumeration diffing and session lifecycle probes (cookie flags,
  logout invalidation, fixation) — read-only for the target's data, with a
  credential redaction pass over audit log, findings, report and the
  LLM observation channel (CI leak gate)
- **Business-logic testing** (opt-in via `safety.business_logic: true`):
  ordered workflow plans with a recorded state machine
  (`workflow_plan`/`workflow_step`/`workflow_status`) where the operator
  approves every individual request, plus bounded ≤ 5-worker race bursts
  (`race_burst`) with code-computed double-spend verdicts (CWE-362)
- Hybrid hosted/local model routing per agent role
- Graceful degradation when an external tool is missing
- Eval harness with record/replay cassettes + offline CI suite

Deliberately NOT in the MVP (roadmap):
- Real exploitation / weaponized PoCs (the exploit agent sends read-only
  verification requests only)
- State-changing authorization probes: mass-assignment writes
  (`role`/owner field injection) stay manual (race bursts ARE automated
  behind `safety.business_logic` + per-burst approval — Phase 2.4)
- Password-reset/OTP stepping with interactive operator confirmation
  (account-enumeration diffing IS automated — `account_enum` — Phase 2.3)
- Active Directory / internal network attack paths
