"""nmap port/service scan wrapper (XML output parsed structurally)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from .base import Tool, ToolError, ToolResult


class NmapTool(Tool):
    name = "nmap_scan"
    description = (
        "Port and service scan with nmap against an authorized IP or hostname. "
        "Runs with a fixed safe flag set (-Pn --open, optional -sV) and returns "
        "open ports with detected services/versions."
    )
    binary = "nmap"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP or hostname (must be in scope)"},
            "ports": {
                "type": "string",
                "description": "Port spec like '22,80,443' or '1-1024'. Default: top 1000 ports.",
            },
            "service_detection": {
                "type": "boolean",
                "description": "Add -sV version detection (slower). Default false.",
            },
        },
        "required": ["target"],
    }

    def run(self, args: dict[str, Any]) -> ToolResult:
        target = str(args["target"])
        cmd = ["nmap", "-oX", "-", "-Pn", "--open"]
        ports = args.get("ports")
        if ports:
            cmd += ["-p", str(ports)]
        else:
            cmd += ["--top-ports", "1000"]
        if args.get("service_detection"):
            cmd += ["-sV", "--version-intensity", "2"]
        cmd += ["--host-timeout", "10m", target]

        proc = self.shell(cmd, timeout=900)
        if not proc.stdout.strip():
            raise ToolError(f"nmap produced no XML output (stderr: {proc.stderr[:300]})")
        return self._parse(proc.stdout)

    def _parse(self, xml_text: str) -> ToolResult:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise ToolError(f"could not parse nmap XML: {exc}") from exc

        hosts: list[dict[str, Any]] = []
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addr_el = host.find("address")
            ip = addr_el.get("addr", "?") if addr_el is not None else "?"
            open_ports = []
            for p in host.findall("ports/port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                open_ports.append(
                    {
                        "port": p.get("portid"),
                        "protocol": p.get("protocol"),
                        "service": svc.get("name") if svc is not None else None,
                        "product": svc.get("product") if svc is not None else None,
                        "version": svc.get("version") if svc is not None else None,
                    }
                )
            if open_ports:
                hosts.append({"ip": ip, "open_ports": open_ports})

        total = sum(len(h["open_ports"]) for h in hosts)
        summary = f"nmap found {total} open port(s) on {len(hosts)} host(s)"
        if not hosts:
            summary = "nmap found no open ports on the target"
        return ToolResult(ok=True, summary=summary, data={"hosts": hosts}, raw=xml_text)
