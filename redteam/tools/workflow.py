"""Stateful business-logic workflow engine (Phase 2.4, catalog section 11).

Business-logic abuse (double-spend, coupon stacking, quota bypass, refund
gaming) is stateful: it needs an ordered sequence of authenticated requests,
and every state change must be approved by a human. The job splits the way
this platform's safety model requires:

  workflow_plan    — the AGENT proposes an ordered step list (method, url,
                     payload, expected status). NO traffic. Scope violations
                     propagate and abort the stage, as everywhere else.
  workflow_step    — executes EXACTLY ONE step, and only if it is the next
                     unexecuted step (strict state machine; out-of-order
                     requests are refused with the executed/pending lists).
                     The tool is in ACTIVE_TOOLS, so the operator confirms
                     every single request with the real method + URL shown
                     (one tool call = one state transition = one approval).
                     The transition (request echo, response summary, timing,
                     expectation result) is appended to a JSON artifact —
                     the recorded state machine makes the flow replayable.
  workflow_status  — read-only view of that state machine.

Safety/design notes:
- The artifact is saved through the redaction pass; observations reaching
  the agent are already scrubbed, so plans normally contain no registered
  secrets. Response excerpts in transitions are target data (findings, not
  scrubbed — consistent with the findings policy).
- Requests flow through the identity's ScopedSession (per-hop scope + DNS
  pinning, jar continuity) or, for anonymous flows, one persistent
  anonymous session per plan so cookies survive between steps.
- Everything refuses to run unless the operator enabled
  `safety.business_logic` in config (defense in depth: ACTIVE_TOOLS still
  demands a per-request confirmation when it is enabled).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..auth import SessionManager
from ..http import ScopedSession
from ..redact import redactor
from .base import Tool, ToolError, ToolResult

MAX_PLAN_STEPS = 20
PLAN_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
PLAN_ID_RE = re.compile(r"^[0-9a-f]{8}$")
BODY_EXCERPT = 400
MAX_NAME = 64

# Anonymous flows keep one cookie jar per plan across tool calls (a signup ->
# verify -> dashboard flow would break with a fresh session every step).
_ANON_SESSIONS: dict[str, ScopedSession] = {}

_DISABLED_MSG = (
    "business-logic testing is disabled — set `safety.business_logic: true` "
    "in config (each request still needs operator confirmation when enabled)"
)


@dataclass
class Step:
    name: str
    method: str
    url: str
    data: dict | None = None
    json_body: Any | None = None
    headers: dict = field(default_factory=dict)
    expect_status: list[int] | None = None

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "name": self.name, "method": self.method, "url": self.url,
        }
        if self.data is not None:
            out["data"] = self.data
        if self.json_body is not None:
            out["json"] = self.json_body
        if self.headers:
            out["headers"] = self.headers
        if self.expect_status:
            out["expect_status"] = self.expect_status
        return out


@dataclass
class Workflow:
    id: str
    label: str
    identity: str
    created_at: str
    steps: list[Step]
    transitions: list[dict] = field(default_factory=list)

    @property
    def next_index(self) -> int:
        return len(self.transitions)

    @property
    def complete(self) -> bool:
        return self.next_index >= len(self.steps)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "identity": self.identity,
            "created_at": self.created_at,
            "steps": [s.to_dict() for s in self.steps],
            "transitions": self.transitions,
        }

    def save(self, artifacts: Path) -> Path:
        path = artifacts / f"workflow-{self.id}.json"
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        path.write_text(redactor.scrub(payload), encoding="utf-8")
        return path

    @classmethod
    def load(cls, artifacts: Path, plan_id: str) -> "Workflow":
        if not PLAN_ID_RE.match(plan_id or ""):
            raise ToolError(
                f"invalid plan_id {plan_id!r} — expected the 8-hex id "
                "returned by workflow_plan"
            )
        path = artifacts / f"workflow-{plan_id}.json"
        if not path.exists():
            raise ToolError(
                f"unknown workflow plan {plan_id!r} — call workflow_plan first"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            steps = [
                Step(
                    name=str(s["name"]),
                    method=str(s["method"]),
                    url=str(s["url"]),
                    data=s.get("data"),
                    json_body=s.get("json"),
                    headers=s.get("headers") or {},
                    expect_status=s.get("expect_status"),
                )
                for s in raw["steps"]
            ]
        except (ValueError, KeyError, TypeError) as exc:
            raise ToolError(f"workflow artifact unreadable: {exc}") from exc
        return cls(
            id=str(raw.get("id", plan_id)),
            label=str(raw.get("label", "")),
            identity=str(raw.get("identity", "")),
            created_at=str(raw.get("created_at", "")),
            steps=steps,
            transitions=list(raw.get("transitions", [])),
        )


def _parse_expect_status(raw: Any) -> list[int] | None:
    if raw is None:
        return None
    values = raw if isinstance(raw, list) else [raw]
    if not values:
        return None
    out: list[int] = []
    for v in values:
        try:
            iv = int(v)
        except (TypeError, ValueError) as exc:
            raise ToolError(f"expect_status must be integers, got {v!r}") from exc
        if not 100 <= iv <= 599:
            raise ToolError(f"expect_status out of range: {iv}")
        out.append(iv)
    return out


def parse_steps(raw: Any) -> list[Step]:
    """Validate the agent's proposed step list (pure, no traffic)."""
    if not isinstance(raw, list) or not raw:
        raise ToolError(
            "steps must be a non-empty array of objects like "
            "{\"name\": \"add-to-cart\", \"method\": \"POST\", \"url\": \"...\"}"
        )
    if len(raw) > MAX_PLAN_STEPS:
        raise ToolError(
            f"at most {MAX_PLAN_STEPS} steps per plan (got {len(raw)}); "
            "split the flow into stages"
        )
    steps: list[Step] = []
    names: set[str] = set()
    for i, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ToolError(f"step {i} must be an object, got {type(item).__name__}")
        name = str(item.get("name") or f"step{i}").strip()
        if not name or len(name) > MAX_NAME:
            raise ToolError(f"step {i}: name must be 1..{MAX_NAME} characters")
        if name in names:
            raise ToolError(f"duplicate step name {name!r}")
        names.add(name)

        method = str(item.get("method", "GET")).upper()
        if method not in PLAN_METHODS:
            raise ToolError(
                f"step {name!r}: method must be one of {PLAN_METHODS}, got {method!r}"
            )
        url = str(item.get("url") or "")
        if not url.startswith(("http://", "https://")):
            raise ToolError(f"step {name!r}: url must be http(s), got {url[:60]!r}")

        data = item.get("data")
        if data is not None:
            if not isinstance(data, dict):
                raise ToolError(f"step {name!r}: data must be an object of form fields")
            for key, value in data.items():
                scalar = isinstance(value, (str, int, float, bool)) or value is None
                if not isinstance(key, str) or not scalar:
                    raise ToolError(
                        f"step {name!r}: data.{key} must be a string/number/bool"
                    )
        headers = item.get("headers") or {}
        if not isinstance(headers, dict) or any(
            not isinstance(k, str) or not isinstance(v, str)
            for k, v in headers.items()
        ):
            raise ToolError(f"step {name!r}: headers must be a string→string object")

        steps.append(
            Step(
                name=name,
                method=method,
                url=url,
                data=dict(data) if isinstance(data, dict) else None,
                json_body=item.get("json"),
                headers=dict(headers),
                expect_status=_parse_expect_status(item.get("expect_status")),
            )
        )
    return steps


def resolve_next(wf: Workflow, requested: Any) -> tuple[int, Step]:
    """Strict state machine: only the next unexecuted step may run.

    requested: None/""/"next" -> next step; an index or a step name ->
    must BE the next step, otherwise ToolError listing executed/pending.
    """
    if wf.complete:
        raise ToolError(
            f"workflow {wf.id} is complete ({len(wf.steps)} of "
            f"{len(wf.steps)} steps executed) — propose a new plan with "
            "workflow_plan to retry the flow"
        )
    nxt = wf.next_index
    if requested is None or str(requested).strip().lower() in ("", "next"):
        idx = nxt
    else:
        req = str(requested).strip()
        idx = next(
            (i for i, s in enumerate(wf.steps) if s.name == req),
            int(req) - 1 if req.isdigit() else None,   # 1-based index
        )
        if idx is None or idx < 0 or idx >= len(wf.steps):
            raise ToolError(
                f"no step named or numbered {requested!r}; steps: "
                f"{[(i + 1, s.name) for i, s in enumerate(wf.steps)]}"
            )
    if idx != nxt:
        done = [t.get("name") for t in wf.transitions]
        pending = [s.name for s in wf.steps[nxt:]]
        raise ToolError(
            f"steps run in order — next is {wf.steps[nxt].name!r} "
            f"(#{nxt + 1}/{len(wf.steps)}); executed: {done or 'none'}; "
            f"pending: {pending}"
        )
    return idx, wf.steps[idx]


class WorkflowPlanTool(Tool):
    name = "workflow_plan"
    description = (
        "Propose an ordered business-logic test plan (checkout, coupon, "
        "quota, refund, signup flows...). NO requests are sent here: you "
        "supply 1..20 steps (name, method, url, optional data/json/headers, "
        "optional expect_status) and get back a plan_id. Execute the steps "
        "one at a time with workflow_step — the operator confirms every "
        "single request. Steps always run in order; the recorded state "
        "machine is saved as an artifact so a human can replay it. Requires "
        "safety.business_logic: true in config."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "label": {"type": "string",
                      "description": "Short flow name, e.g. 'checkout with "
                                     "coupon'"},
            "identity": {"type": "string",
                         "description": "Configured identity to run the flow "
                                        "under (must be logged in via "
                                        "session_login); omit for anonymous"},
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "method": {"type": "string",
                                   "enum": list(PLAN_METHODS)},
                        "url": {"type": "string"},
                        "data": {"type": "object",
                                 "description": "form fields (POST/PUT)"},
                        "json": {"description": "JSON body"},
                        "headers": {"type": "object"},
                        "expect_status": {
                            "description": "HTTP status(es) this step should "
                                           "return (int or list); default "
                                           "2xx-3xx",
                        },
                    },
                    "required": ["method", "url"],
                },
            },
        },
        "required": ["steps"],
    }

    def __init__(self, sessions: SessionManager, artifacts: Path,
                 enabled: bool = True):
        self.sessions = sessions
        self.artifacts = Path(artifacts)
        self.enabled = enabled

    def run(self, args: dict[str, Any]) -> ToolResult:
        if not self.enabled:
            raise ToolError(_DISABLED_MSG)
        label = str(args.get("label") or "business-logic flow")
        identity = str(args.get("identity") or "")
        if identity:
            self.sessions.identity(identity)  # exists-check only, no login
        steps = parse_steps(args.get("steps"))
        # fail fast on scope violations before anything is proposed;
        # hop-time authorization in ScopedSession still applies later
        for step in steps:
            self.sessions.guard.authorize(step.url)

        wf = Workflow(
            id=uuid.uuid4().hex[:8],
            label=label,
            identity=identity,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            steps=steps,
        )
        path = wf.save(self.artifacts)
        return ToolResult(
            ok=True,
            summary=(
                f"workflow {wf.id} planned: {len(steps)} steps in order "
                f"({', '.join(s.name for s in steps)}). Nothing was sent yet — "
                "advance it one step at a time with workflow_step; the "
                "operator confirms each request."
            ),
            data={
                "plan_id": wf.id,
                "label": label,
                "identity": identity or "(anonymous)",
                "steps": [s.name for s in steps],
                "next_step": steps[0].name,
                "artifact": str(path),
            },
        )


class WorkflowStepTool(Tool):
    name = "workflow_step"
    description = (
        "Execute the NEXT step of a workflow plan — exactly one request per "
        "call, only in plan order (out-of-order requests are refused with "
        "the executed/pending lists). The operator sees the real method + "
        "URL and approves or rejects it; a rejection aborts the flow. The "
        "transition (request, response status/excerpt, timing, expectation) "
        "is appended to the plan artifact for reproducible replay. Returns "
        "evidence suitable for record_finding if the response shows a "
        "business-rule violation. Requires safety.business_logic: true."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "plan_id": {"type": "string",
                        "description": "The 8-hex id from workflow_plan"},
            "step": {"description": "Step name or 1-based index; omit or "
                                    "'next' for the next unexecuted step"},
        },
        "required": ["plan_id"],
    }

    def __init__(self, sessions: SessionManager, artifacts: Path,
                 enabled: bool = True):
        self.sessions = sessions
        self.artifacts = Path(artifacts)
        self.enabled = enabled

    def run(self, args: dict[str, Any]) -> ToolResult:
        if not self.enabled:
            raise ToolError(_DISABLED_MSG)
        wf = Workflow.load(self.artifacts, str(args.get("plan_id") or ""))
        idx, step = resolve_next(wf, args.get("step"))

        if wf.identity:
            sess = self.sessions.get_session(wf.identity)  # login required
        else:
            sess = _ANON_SESSIONS.get(wf.id)
            if sess is None:
                sess = ScopedSession(self.sessions.guard, timeout=15,
                                     max_redirects=5)
                _ANON_SESSIONS[wf.id] = sess

        t0 = time.monotonic()
        resp = sess.request(
            step.method, step.url,
            data=step.data, json=step.json_body,
            headers=step.headers or None,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        body = resp.text or ""
        if step.expect_status:
            expect_met = resp.status_code in step.expect_status
            expected = str(step.expect_status)
        else:
            expect_met = 200 <= resp.status_code < 400
            expected = "2xx-3xx"

        wf.transitions.append({
            "index": idx,
            "name": step.name,
            "method": step.method,
            "url": step.url,
            "request": {k: v for k, v in step.to_dict().items() if k != "name"},
            "status": resp.status_code,
            "expect_met": expect_met,
            "expect_status": step.expect_status,
            "elapsed_ms": elapsed_ms,
            "body_len": len(body),
            "body_sha1": hashlib.sha1(
                body[:100_000].encode("utf-8", "replace")).hexdigest(),
            "body_excerpt": body[:BODY_EXCERPT],
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
        path = wf.save(self.artifacts)

        next_step = None if wf.complete else wf.steps[wf.next_index].name
        evidence = redactor.scrub(
            f"workflow {wf.id} step {idx + 1}/{len(wf.steps)} "
            f"'{step.name}': {step.method} {step.url} -> status "
            f"{resp.status_code} (expected {expected}) elapsed {elapsed_ms}ms\n"
            f"response: {body[:BODY_EXCERPT]}"
        )
        if expect_met:
            recommendation = (
                "continue: execute the next step (or workflow_status); when "
                "the flow demonstrates a business-rule violation, "
                "record_finding with THIS evidence (status + response pair)"
            )
        else:
            recommendation = (
                "unexpected status — if it reveals a logic flaw, "
                "record_finding (suspected) with this evidence; otherwise "
                "fix the plan inputs/expect_status and propose a fresh plan"
            )
        return ToolResult(
            ok=True,
            summary=(
                f"workflow_step '{step.name}': status {resp.status_code} — "
                f"{'as expected' if expect_met else 'UNEXPECTED'}; next: "
                f"{next_step or 'none (flow complete)'}"
            ),
            data={
                "plan_id": wf.id,
                "step": step.name,
                "index": idx + 1,
                "total": len(wf.steps),
                "status": resp.status_code,
                "expect_met": expect_met,
                "result": "expected" if expect_met else "unexpected_status",
                "next_step": next_step,
                "complete": wf.complete,
                "evidence": evidence,
                "recommendation": recommendation,
                "artifact": str(path),
            },
        )


class WorkflowStatusTool(Tool):
    name = "workflow_status"
    description = (
        "Read-only view of a workflow plan's recorded state machine: which "
        "steps executed (with status/timing), which are pending, and the "
        "next step. No requests are sent."
    )
    binary = None
    parameters = {
        "type": "object",
        "properties": {
            "plan_id": {"type": "string"},
        },
        "required": ["plan_id"],
    }

    def __init__(self, artifacts: Path):
        self.artifacts = Path(artifacts)

    def run(self, args: dict[str, Any]) -> ToolResult:
        wf = Workflow.load(self.artifacts, str(args.get("plan_id") or ""))
        executed = [s.name for s in wf.steps[:wf.next_index]]
        pending = [s.name for s in wf.steps[wf.next_index:]]
        return ToolResult(
            ok=True,
            summary=(
                f"workflow {wf.id} ({wf.label}): {len(executed)}/"
                f"{len(wf.steps)} steps executed; "
                f"next: {pending[0] if pending else 'none (complete)'}"
            ),
            data={
                "plan_id": wf.id,
                "label": wf.label,
                "identity": wf.identity or "(anonymous)",
                "total_steps": len(wf.steps),
                "executed": executed,
                "pending": pending,
                "next_step": pending[0] if pending else None,
                "transitions": [
                    {"step": t.get("name"), "status": t.get("status"),
                     "expect_met": t.get("expect_met"),
                     "elapsed_ms": t.get("elapsed_ms")}
                    for t in wf.transitions
                ],
                "artifact": str(self.artifacts / f"workflow-{wf.id}.json"),
            },
        )
