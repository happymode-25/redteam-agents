"""Base agent: a model-agnostic JSON tool-calling loop.

Works with any instruct model (hosted or local) — no native function-calling
required. The model replies either with a tool call, a request for user input,
or a final answer; the loop feeds tool results back as observations until the
agent finishes or hits its step budget.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from ..audit import AuditLog
from ..llm import Router
from ..redact import redactor
from ..scope import Guard, KillSwitchEngaged, ScopeViolation
from ..state import SharedState
from ..tools.base import ToolError, ToolRegistry

PROTOCOL_PREAMBLE = """\
You operate security tooling against an AUTHORIZED target. Reply with EXACTLY ONE
JSON object per turn, in one of these three shapes:

  {"action": "tool", "tool": "<tool_name>", "args": {<tool arguments>}}
  {"action": "ask_user", "question": "<question for the operator>"}
  {"action": "final", "answer": "<your final output for this stage>"}

Rules:
- Use the provided tools to gather real evidence. NEVER invent tool output.
- If a tool reports a scope violation, do not retry it with a different target;
  move on or finish.
- If a tool fails or is unavailable, adapt and continue with other options.
- When you have enough evidence (or tools are exhausted), emit "final".
- Keep the final answer factual, structured with headings, and explicit about
  what was and was not verified.
"""


def _compact_tool_list(registry: ToolRegistry) -> str:
    """One line per tool: name(args) — what it does.

    The pretty-printed JSON schema dump is ~24k chars for a full registry.
    On a CPU-only local model that is several minutes of prompt processing per
    step, and a 4k-context model silently truncates it. This keeps every tool
    discoverable — names, argument names/types, required vs optional, short
    hints — at roughly a fifth of the size. Argument validation still happens
    against the real schema when the call is parsed, so the compact form is
    presentation only, never enforcement.
    """
    lines: list[str] = []
    for schema in registry.schemas():
        params = schema.get("parameters") or {}
        props = params.get("properties") or {}
        required = set(params.get("required") or [])
        args: list[str] = []
        for name, spec in props.items():
            spec = spec if isinstance(spec, dict) else {}
            ptype = str(spec.get("type") or "string")
            hint = " ".join(str(spec.get("description") or "").split())
            if len(hint) > 70:
                hint = hint[:69].rstrip() + "…"
            args.append(
                f"{name}{'' if name in required else '?'}:{ptype}"
                + (f' "{hint}"' if hint else "")
            )
        desc = " ".join(str(schema.get("description") or "").split())
        if len(desc) > 110:
            desc = desc[:109].rstrip() + "…"
        lines.append(f"- {schema.get('name')}({', '.join(args)}) — {desc}")
    return "\n".join(lines)


@dataclass
class AgentResult:
    agent: str
    output: str
    steps_used: int
    tool_calls: int


def _extract_json(reply: str) -> dict[str, Any] | None:
    """Pull the LAST JSON object out of a model reply (they may wrap in ```json)."""
    candidates: list[str] = []
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", reply, re.DOTALL)
    candidates.extend(reversed(fenced))
    candidates.append(reply.strip())
    # balanced-brace scan from the last '{' backwards
    for start in range(len(reply) - 1, -1, -1):
        if reply[start] != "{":
            continue
        depth = 0
        for i in range(start, len(reply)):
            if reply[i] == "{":
                depth += 1
            elif reply[i] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(reply[start : i + 1])
                    break
        if len(candidates) > 12:
            break
    for text in candidates:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "action" in obj:
            return obj
    return None


class Agent:
    def __init__(
        self,
        name: str,
        role: str,
        system_prompt: str,
        router: Router,
        registry: ToolRegistry,
        guard: Guard,
        state: SharedState,
        max_steps: int = 25,
        observation_max_chars: int = 6000,
        emit: Callable[[str], None] = print,
        user_fn: Callable[[str], str] | None = None,
        pre_tool_hook: Callable[[str, dict], None] | None = None,
        audit: AuditLog | None = None,
    ):
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.router = router
        self.registry = registry
        self.guard = guard
        self.state = state
        self.max_steps = max_steps
        self.observation_max_chars = observation_max_chars
        self.emit = emit
        self.user_fn = user_fn or (lambda q: "Proceed.")
        self.pre_tool_hook = pre_tool_hook
        self.audit = audit
        self._tool_calls = 0
        self._system_prompt: str | None = None

    def _audit(self, event: str, **fields) -> None:
        if self.audit is not None:
            self.audit.record(event, actor=self.name, **fields)

    def _system(self) -> str:
        if self._system_prompt is None:
            self._system_prompt = (
                f"{self.system_prompt}\n\n{PROTOCOL_PREAMBLE}\n\n"
                "Available tools (name(args) — what it does; args are passed in "
                "the JSON 'args' object, '?' marks optional, quotes are hints):\n"
                f"{_compact_tool_list(self.registry)}"
            )
        return self._system_prompt

    def run(self, task: str) -> AgentResult:
        provider = self.router.for_role(self.role)
        messages: list[dict] = [{"role": "user", "content": task}]
        self.emit(f"[{self.name}] starting (model={provider.model})")
        self._audit("agent_start", detail={"role": self.role, "model": provider.model})

        for step in range(1, self.max_steps + 1):
            self.guard.kill.check()
            reply = provider.complete(self._system(), messages)
            messages.append({"role": "assistant", "content": reply})
            parsed = _extract_json(reply)

            if parsed is None:
                observation = (
                    "Your reply did not contain a valid JSON action object. "
                    "Reply with exactly one JSON object as specified."
                )
                self.emit(f"[{self.name}] step {step}: unparseable reply, reprompting")
                messages.append({"role": "user", "content": observation})
                continue

            action = parsed.get("action")

            if action == "final":
                answer = str(parsed.get("answer", ""))
                self.emit(f"[{self.name}] finished after {step} step(s)")
                self._audit("agent_final", detail={"steps": step, "tool_calls": self._tool_calls})
                return AgentResult(self.name, answer, step, self._tool_calls)

            if action == "ask_user":
                question = str(parsed.get("question", "Continue?"))
                self.emit(f"[{self.name}] asks: {question}")
                answer = self.user_fn(question)
                self._audit("ask_user", detail={"question": question[:500],
                                                "answer": answer[:500]})
                messages.append(
                    {"role": "user", "content": f"Operator response: {answer}"}
                )
                continue

            if action == "tool":
                tool_name = str(parsed.get("tool", ""))
                args = parsed.get("args") or {}
                if not isinstance(args, dict):
                    args = {}
                observation = self._execute_tool(tool_name, args)
                self.emit(f"[{self.name}] step {step}: {observation.splitlines()[0][:160]}")
                messages.append(
                    {"role": "user", "content": f"TOOL RESULT:\n{observation}"}
                )
                continue

            messages.append(
                {"role": "user", "content": f"Unknown action {action!r}. Use the JSON protocol."}
            )

        self.emit(f"[{self.name}] step budget exhausted ({self.max_steps})")
        return AgentResult(
            self.name,
            "Agent stopped: step budget exhausted before a final answer.",
            self.max_steps,
            self._tool_calls,
        )

    def _execute_tool(self, tool_name: str, args: dict) -> str:
        """Run a tool and scrub the observation before it becomes LLM
        context: tool results leave this machine for the hosted model, so
        any registered identity secret appearing in raw output (e.g. a
        target echoing our password back) is redacted at this choke point."""
        return redactor.scrub(self._execute_tool_raw(tool_name, args))

    def _execute_tool_raw(self, tool_name: str, args: dict) -> str:
        tool = self.registry.get(tool_name)
        if tool is None:
            return f"ERROR: unknown tool '{tool_name}'. Check the tool list and retry."

        ok, reason = tool.available()
        if not ok:
            return f"ERROR: tool '{tool_name}' unavailable: {reason}. Use other tools."

        if self.pre_tool_hook:
            self.pre_tool_hook(tool_name, args)

        # Scope/rate/kill-switch enforcement happens HERE, in code, not in the prompt.
        target = str(args.get("target") or args.get("url") or args.get("domain") or "")
        if not target and isinstance(args.get("targets"), list) and args["targets"]:
            target = str(args["targets"][0])

        try:
            if target:
                self.guard.run(target, lambda: None)  # authorize + rate-limit first
            result = tool.run(args)
            self._tool_calls += 1
            self._audit("tool_call", tool=tool_name, target=target, decision="allowed",
                        detail={"args": {k: str(v)[:200] for k, v in args.items()},
                                "summary": result.summary[:300]})
            return result.to_observation(self.observation_max_chars)
        except ScopeViolation as exc:
            self._audit("tool_call", tool=tool_name, target=target, decision="denied",
                        detail={"error": str(exc)[:500]})
            return f"SCOPE VIOLATION: {exc}. This target is out of scope — do not retry it."
        except KillSwitchEngaged:
            self._audit("tool_call", tool=tool_name, target=target,
                        decision="aborted_kill_switch")
            raise
        except ToolError as exc:
            self._audit("tool_call", tool=tool_name, target=target, decision="error",
                        detail={"error": str(exc)[:500]})
            return f"TOOL ERROR ({tool_name}): {exc}"
