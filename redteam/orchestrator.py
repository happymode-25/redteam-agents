"""Orchestrator: runs the plan -> recon -> analyze -> (gate) -> report pipeline."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

from .agents.analyst import ANALYST_PROMPT
from .agents.base import Agent, AgentResult
from .agents.exploit import EXPLOIT_PROMPT
from .agents.planner import PLANNER_PROMPT
from .agents.recon import RECON_PROMPT
from .agents.reporter import REPORTER_PROMPT
from .audit import AuditLog
from .auth import SessionManager
from .budget import BudgetExceeded, TokenBudget, format_usage
from .config import AppConfig
from .drift import (compare, load_snapshot, render_drift_markdown,
                    save_snapshot, snapshot, snapshot_path)
from .egress import EgressFirewall
from .fixtures import FixtureManager, FixtureProvider, FixtureTool
from .htmlreport import render_html
from .llm import Router
from .plugins import PluginTool, load_plugins
from .report import render_report
from .review import load_reviews
from .sandbox import configure_runner
from .scope import Guard, KillSwitchEngaged, ScopeViolation
from .state import SharedState
from .tools.dns_email import EmailAuthCheckTool
from .tools.api_discovery import ApiDiscoveryTool
from .tools.bfla import BflaCheckTool
from .tools.cve_lookup import CveLookupTool
from .tools.enumeration import AccountEnumTool
from .tools.race import RaceBurstTool
from .tools.ffuf import ContentDiscoveryTool
from .tools.http_request import HttpRequestTool
from .tools.httpx import HttpxTool
from .tools.idor import IdoDiffTool
from .tools.jwt import JwtCheckTool
from .tools.katana import KatanaTool
from .tools.nmap import NmapTool
from .tools.nuclei import NucleiTool
from .tools.record import RecordFindingTool
from .tools.schema import SchemaDiffTool
from .tools.session import SessionLoginTool, SessionLogoutTool, SessionStatusTool
from .tools.session_check import SessionCheckTool
from .tools.workflow import (WorkflowPlanTool, WorkflowStatusTool,
                             WorkflowStepTool)
from .tools.subfinder import SubfinderTool
from .tools.tls_check import TlsCheckTool
from .tools.web_config import WebSecurityChecksTool
from .tools.base import ToolRegistry
# Phase 3 modules (catalog sections 7, 14, 15, 17, 19) — registered below
# only when the operator configured their input.
from .tools.ad import AdAnalyzeTool, AdCollectTool
from .tools.ai_probe import AiEndpointProbeTool, PromptProbeTool
from .tools.cloudposture import BucketExposureTool, CloudPostureReportTool
from .tools.k8s import ImageScanTool, KubeAuditTool, KubeLintTool
from .tools.mobile import (ApkBadgingTool, DecompileSecretScanTool,
                           ManifestAuditTool)

# Tools that send traffic directly at the target with attacker-shaped requests
ACTIVE_TOOLS = {"http_request", "account_enum", "session_check",
                "workflow_step", "race_burst"}


class Orchestrator:
    def __init__(
        self,
        cfg: AppConfig,
        allow_active: bool = False,
        auto_yes: bool = False,
        mode: str | None = None,
    ):
        self.cfg = cfg
        self.allow_active = allow_active
        self.auto_yes = auto_yes
        self.mode = mode or cfg.safety.mode

        self.artifacts = Path(cfg.safety.artifacts_dir).resolve()
        self.artifacts.mkdir(parents=True, exist_ok=True)

        self._emit(f"subprocess runner: {configure_runner(cfg.safety)}")
        self.audit = AuditLog(self.artifacts / "audit.jsonl")
        self.audit.record("run_start", actor="orchestrator",
                          detail={"target_mode": self.mode, "allow_active": allow_active})
        self.fixtures = FixtureManager(cfg.safety.cassette_dir, self.mode)

        self.state = SharedState()
        self.budget = TokenBudget(cfg.budget)
        self.router = Router(cfg.llm,
                             wrap=lambda p: FixtureProvider(p, self.fixtures),
                             budget=self.budget)
        self.guard = Guard.from_config(cfg.scope, self.artifacts, audit=self.audit)
        # Phase 2.1: multi-identity sessions (cookie jars isolated per identity)
        self.sessions = SessionManager(cfg.identities, self.guard, audit=self.audit)
        self.used_tools: set[str] = set()

        tools = [
            SubfinderTool(),
            HttpxTool(),
            KatanaTool(self.guard),
            ContentDiscoveryTool(),
            ApiDiscoveryTool(self.guard),
            NmapTool(),
            NucleiTool(cfg.nuclei),
            CveLookupTool(cfg.intel, self.artifacts / "intel"),
            WebSecurityChecksTool(self.guard),
            TlsCheckTool(self.guard),
            EmailAuthCheckTool(),
            HttpRequestTool(self.guard),
            RecordFindingTool(self.state),
            # Phase 2.1: identity lifecycle
            SessionLoginTool(self.sessions),
            SessionStatusTool(self.sessions),
            SessionLogoutTool(self.sessions),
            # Phase 2.2: deterministic authorization testing
            IdoDiffTool(self.sessions),
            BflaCheckTool(self.sessions),
            SchemaDiffTool(self.sessions),
            JwtCheckTool(),
            AccountEnumTool(self.sessions),
            SessionCheckTool(self.sessions),
            # Phase 2.4: business-logic workflows + bounded race tester
            # (both refuse to run until safety.business_logic is enabled;
            #  workflow_step/race_burst sit behind the per-call operator gate)
            WorkflowPlanTool(self.sessions, self.artifacts,
                             enabled=cfg.safety.business_logic),
            WorkflowStepTool(self.sessions, self.artifacts,
                             enabled=cfg.safety.business_logic),
            WorkflowStatusTool(self.artifacts),
            RaceBurstTool(self.sessions, enabled=cfg.safety.business_logic),
        ]

        # Phase 3 modules (sections 7/14/15/17/19): registered only when the
        # operator configured their input — every schema is argument-free, so
        # the model cannot redirect them at anything else. Config alone
        # changes no coverage claim: only tools that RUN upgrade a row.
        if cfg.k8s.image:
            tools.append(ImageScanTool(cfg.k8s.image))
        if cfg.k8s.lint_dir:
            tools.append(KubeLintTool(cfg.k8s.lint_dir))
        if cfg.k8s.kubeconfig:
            tools.append(KubeAuditTool(cfg.k8s.kubeconfig,
                                       context=cfg.k8s.context))
        if cfg.ai.endpoint:
            # ctor fails closed if auth_env names an unset var (also checked
            # at load); the token is redacted the moment it is read.
            tools.append(AiEndpointProbeTool(self.guard, cfg.ai.endpoint,
                                             auth_env=cfg.ai.auth_env,
                                             timeout=cfg.ai.timeout))
            tools.append(PromptProbeTool(self.guard, cfg.ai.endpoint,
                                         auth_env=cfg.ai.auth_env,
                                         timeout=cfg.ai.timeout,
                                         model=cfg.ai.model))
        if cfg.cloud.org_hints:
            tools.append(BucketExposureTool(self.guard, cfg.cloud.org_hints,
                                            timeout=cfg.cloud.timeout))
        if cfg.cloud.report_path:
            tools.append(CloudPostureReportTool(Path(cfg.cloud.report_path),
                                                cfg.cloud.report_kind))
        if cfg.ad.dc_ip and cfg.ad.domain:
            tools.append(AdCollectTool(cfg.ad.dc_ip, cfg.ad.domain,
                                       enabled=cfg.ad.collect))
        if cfg.ad.analyze_report:
            tools.append(AdAnalyzeTool(Path(cfg.ad.analyze_report),
                                       max_depth=cfg.ad.max_depth))
        if cfg.mobile.manifest_path:
            tools.append(ManifestAuditTool(Path(cfg.mobile.manifest_path)))
        if cfg.mobile.apk_path:
            tools.append(ApkBadgingTool(Path(cfg.mobile.apk_path)))
        if cfg.mobile.decompiled_dir:
            tools.append(DecompileSecretScanTool(
                Path(cfg.mobile.decompiled_dir)))

        # custom check plugins: operator-installed code, agent-invokable
        checks_dir = Path(cfg.safety.checks_dir).resolve()
        plugins, plugin_warnings = load_plugins(checks_dir)
        builtin_names = {t.name for t in tools}
        for plugin in plugins:
            if plugin.manifest.id in builtin_names:
                self._emit(f"plugin skipped: id '{plugin.manifest.id}' "
                           f"shadows a built-in tool ({plugin.source})")
                continue
            tools.append(PluginTool(plugin, self.guard, allow_active=allow_active))
        for warning in plugin_warnings:
            self._emit(f"plugin warning: {warning}")
        if plugins:
            self._emit(f"loaded {len(plugins)} custom check(s) from {checks_dir}")
        # record_finding mutates live state from replayed decisions — never cassetted
        wrapped = [
            t if isinstance(t, RecordFindingTool) else FixtureTool(t, self.fixtures)
            for t in tools
        ]
        self.registry = ToolRegistry(wrapped)

    # ---- human-in-the-loop -------------------------------------------------

    def _user_fn(self, question: str) -> str:
        try:
            return input(f"\nOPERATOR INPUT NEEDED:\n  {question}\n  > ").strip() or "Proceed."
        except EOFError:
            return "No — proceed with what you have."

    def _pre_tool_hook(self, tool_name: str, args: dict) -> None:
        # record what actually ran this engagement (coverage honesty)
        self.used_tools.add(tool_name)
        if tool_name not in ACTIVE_TOOLS:
            return
        if self.auto_yes and not self.cfg.safety.require_confirmation_for_active:
            return
        if not self.auto_yes:
            prompt = self._active_prompt(tool_name, args)
            if not self._confirm(prompt):
                raise ScopeViolation(
                    f"operator rejected active request "
                    f"({tool_name}); try another approach"
                )

    def _active_prompt(self, tool_name: str, args: dict) -> str:
        """What the operator sees before a state-changing tool runs: always
        the real method + target. workflow_step resolves its URL from the
        recorded plan so the approval shows exactly what will be sent."""
        if tool_name == "workflow_step":
            return self._workflow_step_prompt(args)
        if tool_name == "race_burst":
            count = args.get("count", 5)
            return (f"{args.get('method', 'POST')} {args.get('url', '?')} "
                    f"× {count} concurrent requests (one burst)")
        method = args.get("method", "GET")
        target = args.get("url", "?")
        return f"{method} {target}"

    def _workflow_step_prompt(self, args: dict) -> str:
        plan_id = str(args.get("plan_id") or "")
        requested = args.get("step")
        try:
            import json as _json
            wf = _json.loads(
                (self.artifacts / f"workflow-{plan_id}.json")
                .read_text(encoding="utf-8")
            )
            steps = wf.get("steps", [])
            nxt = len(wf.get("transitions", []))
            req = str(requested).strip() if requested is not None else "next"
            if req.lower() in ("", "next"):
                idx = nxt
            elif req.isdigit():
                idx = int(req) - 1        # operator sees 1-based step numbers
            else:
                idx = next((i for i, s in enumerate(steps)
                            if s.get("name") == req), nxt)
            if 0 <= idx < len(steps):
                step = steps[idx]
                return (f"{step.get('method')} {step.get('url')}  "
                        f"(workflow {plan_id}, step {idx + 1}/{len(steps)} "
                        f"'{step.get('name')}')")
        except Exception:
            pass  # fall through to the generic form below
        return (f"workflow_step plan={plan_id or '?'} "
                f"step={requested if requested else 'next'!r}")

    def _confirm(self, prompt: str) -> bool:
        try:
            answer = input(f"\nACTIVE REQUEST: {prompt}\n  Send it? [y/N] > ").strip().lower()
            return answer in ("y", "yes")
        except EOFError:
            return False

    # ---- agents ------------------------------------------------------------

    def _agent(self, name: str, role: str, prompt: str) -> Agent:
        return Agent(
            name=name,
            role=role,
            system_prompt=prompt,
            router=self.router,
            registry=self.registry,
            guard=self.guard,
            state=self.state,
            max_steps=self.cfg.safety.max_agent_steps,
            observation_max_chars=self.cfg.safety.observation_max_chars,
            emit=self._emit,
            user_fn=self._user_fn,
            pre_tool_hook=self._pre_tool_hook,
            audit=self.audit,
        )

    @staticmethod
    def _emit(msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)

    # ---- pipeline ----------------------------------------------------------

    def run(self, target: str, goal: str = "full-scope assessment") -> Path:
        # Fail fast if the primary target is not authorized.
        authorized_host = self.guard.authorize(target)

        scope_note = (
            f"ALLOWED domains: {self.cfg.scope.allow_domains or '[]'}; "
            f"ALLOWED CIDRs: {self.cfg.scope.allow_cidrs or '[]'}; "
            f"subdomains={'allowed' if self.cfg.scope.allow_subdomains else 'forbidden'}; "
            f"private IPs={'allowed' if self.cfg.scope.allow_private else 'blocked'}"
        )

        results: dict[str, AgentResult] = {}

        self._emit(f"\n=== Stage 1/5: PLANNING (target={authorized_host}) ===")
        results["plan"] = self._agent("planner", "planner", PLANNER_PROMPT).run(
            f"Target: {target}\nGoal: {goal}\nScope boundary: {scope_note}\n\n"
            "Produce the assessment plan."
        )
        self.state.set_note("plan", results["plan"].output)
        self._stage_checkpoint()      # survive host restarts between stages

        self._emit("\n=== Stage 2/5: RECON ===")
        results["recon"] = self._agent("recon", "recon", RECON_PROMPT).run(
            f"Target: {target}\nScope boundary: {scope_note}\n\n"
            f"Assessment plan to execute (recon phases only):\n{results['plan'].output}"
        )
        self.state.set_note("recon", results["recon"].output)
        self._stage_checkpoint()

        self._emit("\n=== Stage 3/5: VULN ANALYSIS ===")
        results["analysis"] = self._agent("analyst", "analyst", ANALYST_PROMPT).run(
            f"Target: {target}\nScope boundary: {scope_note}\n\n"
            f"RECON SUMMARY:\n{results['recon'].output}\n\n"
            "Triage, scan with nuclei, and record findings."
        )
        self.state.set_note("analysis", results["analysis"].output)
        self._stage_checkpoint()

        if self.allow_active:
            self._emit("\n=== Stage 4/5: ACTIVE VERIFICATION (human-gated) ===")
            findings_brief = self._findings_brief()
            results["verification"] = self._agent("exploit", "exploit", EXPLOIT_PROMPT).run(
                f"Target: {target}\nScope boundary: {scope_note}\n\n"
                f"ANALYST TRIAGE:\n{results['analysis'].output}\n\n"
                f"CURRENT FINDINGS:\n{findings_brief}\n\n"
                "Verify or disprove suspected issues with minimal read-only requests."
            )
            self.state.set_note("verification", results["verification"].output)
            self._stage_checkpoint()
        else:
            self._emit("\n=== Stage 4/5: ACTIVE VERIFICATION skipped (--allow-active not set) ===")

        self._emit("\n=== Stage 5/5: REPORTING ===")
        reporter_input = (
            f"FINDINGS STORE (JSON):\n{self._findings_brief()}\n\n"
            f"PLAN NOTE:\n{self.state.get_note('plan')}\n\n"
            f"RECON NOTE:\n{self.state.get_note('recon')}\n\n"
            f"ANALYSIS NOTE:\n{self.state.get_note('analysis')}\n\n"
            f"VERIFICATION NOTE:\n{self.state.get_note('verification') or '(stage skipped)'}"
        )
        results["report"] = self._agent("reporter", "reporter", REPORTER_PROMPT).run(reporter_input)

        return self._write_report(target, results["report"].output)

    def _findings_brief(self) -> str:
        import json

        findings = [f.__dict__ for f in self.state.sorted_findings()]
        if not findings:
            return "(no findings recorded yet)"
        return json.dumps(findings, indent=2, ensure_ascii=False)

    def _stage_checkpoint(self) -> None:
        """Persist progress after each pipeline stage so a host restart
        mid-run still leaves findings/notes + tool cassettes on disk for
        post-mortem analysis (the final report writes everything itself)."""
        self.fixtures.save()
        self.state.save(self.artifacts / "state-latest.json")

    def _write_report(self, target: str, narrative: str) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_path = self.artifacts / f"report-{stamp}.md"
        findings_path = self.artifacts / f"findings-{stamp}.json"
        html_path = self.artifacts / f"report-{stamp}.html"

        # Phase 4: diff against the previous snapshot for this target, apply
        # human review decisions, and include cost-governance usage.
        state_path = snapshot_path(self.artifacts, target)
        previous = load_snapshot(state_path)
        current = snapshot(target, self.state.sorted_findings())
        drift = compare(previous, current)
        reviews = load_reviews(self.artifacts / "reviews.json")

        text = render_report(
            target=target, narrative=narrative, state=self.state,
            identities=bool(self.cfg.identities),
            tools_used=self.used_tools,
            usage=format_usage(None, self.budget),
            drift_md=render_drift_markdown(
                drift, previous_ts=(previous or {}).get("ts")),
            reviews=reviews,
        )
        report_path.write_text(text, encoding="utf-8")
        html_path.write_text(render_html(text), encoding="utf-8")
        save_snapshot(state_path, current)
        self.state.save(findings_path)
        self.fixtures.save()
        self.audit.record("run_end", actor="orchestrator",
                          detail={"report": str(report_path),
                                  "report_html": str(html_path),
                                  "findings": len(self.state.findings),
                                  "drift": drift.counts,
                                  "usage": self.budget.totals(),
                                  "stats": self.fixtures.counts})
        self._emit(f"run stats: {self.fixtures.counts}")
        self._emit(f"report: {report_path}")
        self._emit(f"report (html): {html_path}")
        return report_path


def run_pipeline(cfg: AppConfig, target: str, allow_active: bool, auto_yes: bool,
                 mode: str | None = None) -> Path:
    try:
        firewall = EgressFirewall.from_config(cfg)
        firewall.install()
    except ScopeViolation as exc:
        print(f"\nEgress firewall setup error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    try:
        orch = Orchestrator(cfg, allow_active=allow_active, auto_yes=auto_yes, mode=mode)
        firewall.audit = orch.audit
        orch._emit(firewall.describe())
        try:
            return orch.run(target)
        except KillSwitchEngaged:
            orch._emit("\nKill switch engaged. Writing partial report with findings so far...")
            return orch._write_report(target, "Assessment aborted by kill switch. Partial report.")
        except BudgetExceeded as exc:
            orch._emit(f"\nToken budget exhausted: {exc}. Writing partial report...")
            return orch._write_report(
                target,
                f"Assessment stopped: {exc}. Partial report — stages that did "
                "not run were not assessed; do not read the coverage matrix as "
                "complete.")
        except ScopeViolation as exc:
            orch._emit(f"\nScope violation on primary target: {exc}")
            raise SystemExit(2) from exc
        except KeyboardInterrupt:
            orch.guard.kill.trip()
            orch._emit("\nInterrupted. Writing partial report...")
            return orch._write_report(target, "Assessment interrupted by operator. Partial report.")
    finally:
        firewall.uninstall()
