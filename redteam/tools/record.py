"""record_finding tool: lets an agent write a finding into SharedState."""

from __future__ import annotations

from typing import Any

from ..state import Finding, SharedState
from ..triage import evidence_supported
from .base import Tool, ToolResult


class RecordFindingTool(Tool):
    name = "record_finding"
    description = (
        "Record a vulnerability finding into the shared findings store. "
        "Only record issues you have evidence for from tool output — never "
        "speculative findings. Use status 'confirmed' only when a tool result "
        "directly demonstrated the issue."
    )
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Short vulnerability title"},
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
            },
            "target": {"type": "string", "description": "Affected URL/host/port"},
            "evidence": {"type": "string", "description": "Key evidence excerpt from tool output"},
            "remediation": {"type": "string", "description": "Fix guidance"},
            "status": {
                "type": "string",
                "enum": ["suspected", "confirmed"],
                "description": "confirmed = directly demonstrated by a tool result",
            },
            "cwe": {"type": "string", "description": "CWE id if known, e.g. CWE-89"},
            "cvss": {"type": "string", "description": "CVSS score if known, e.g. 9.8"},
            "cves": {"type": "string", "description": "Comma-separated CVE ids if known"},
        },
        "required": ["title", "severity", "target"],
    }

    def __init__(self, state: SharedState):
        self.state = state

    def run(self, args: dict[str, Any]) -> ToolResult:
        status = str(args.get("status", "suspected"))
        evidence = str(args.get("evidence", ""))
        probe = Finding(
            id="_probe", title=str(args.get("title", "")), severity="info",
            target=str(args.get("target", "")), evidence=evidence, status=status,
        )
        # Evidence standard, enforced in code: a finding can only be
        # 'confirmed' when its evidence shows a tool-observed response.
        if status == "confirmed" and not evidence_supported(probe):
            status = "suspected"
            evidence = (evidence + "\n[evidence-standard] recorded as suspected: "
                        "evidence lacked a tool-observed response, so 'confirmed' "
                        "is not permitted").strip()
        finding = self.state.add_finding(
            title=str(args["title"]),
            severity=str(args.get("severity", "info")),
            target=str(args["target"]),
            evidence=evidence,
            remediation=str(args.get("remediation", "")),
            tool="agent",
            status=status,
            cwe=str(args.get("cwe", "")),
            cvss=str(args.get("cvss", "")),
            cves=str(args.get("cves", "")),
        )
        return ToolResult(
            ok=True,
            summary=f"Recorded finding {finding.id} [{finding.severity}] "
                    f"[{finding.status}] {finding.title}",
            data={"id": finding.id, "status": finding.status},
        )
