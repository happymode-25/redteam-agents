"""Active Directory / internal-network module (catalog section 17).

Two tools and one hard boundary: REPORT-ONLY — no path in this module is
ever executed. Collection is passive (LDAP + Global Catalog + GC-LSAP
reads); the analysis only DOCUMENTS the paths the graph shows.

- ad_collect  — operator-gated passive BloodHound CE collection
                (bloodhound-python). The DC and the domain are
                operator-configured and FIXED at construction and the JSON
                schema exposes no arguments, so the model can never redirect
                the collector. Credentials are NEVER accepted as tool
                arguments: bloodhound-python uses the ambient Kerberos
                ticket / environment, and the argv we build has no -u/-p.
- ad_analyze  — deterministic analysis of an operator-supplied BloodHound
                JSON graph (path FIXED at construction, empty schema again);
                no binary, no traffic, pure parsers.

Verdict ladder (enforced in CODE, see tools/sca.py):
  attack paths            suspected — a documented path is an EXPOSURE, not
                          an executed compromise; nothing was run to obtain
                          it, so it cannot be 'confirmed'.
  Kerberoastable accounts confirmed — a STATIC directory fact: the account
                          carries SPNs, so it is roastable (ATTACK NOT
                          EXECUTED: no ticket was requested, no hash cracked).

Evidence carries the `scanner:` marker (state.py evidence standard).
"""

from __future__ import annotations

import json
import re
import tempfile
from collections import deque
from pathlib import Path
from typing import Any

from ..redact import redactor
from .base import Tool, ToolError, ToolResult

_RAW_CAP = 200_000        # bytes of raw scanner stdout kept per tool result
_COLLECT_TIMEOUT = 1800   # seconds; a full domain collection is slow

# Collections requested from bloodhound-python (all read-only queries).
_COLLECTIONS = (
    "Group", "LocalAdmin", "Session", "LoggedOn", "Trusts", "ACL",
    "Container", "ObjectProps", "SPNTargets", "RDP",
)

# Privileged group names, matched case-insensitively against the display
# name ("DOMAIN ADMINS@CORP.LOCAL", "BUILTIN\\ADMINISTRATORS").
_ADMIN_NAME_RE = re.compile(
    r"(DOMAIN ADMINS|ENTERPRISE ADMINS|ADMINISTRATORS)@?", re.I
)

# Edge kinds that can move an attacker toward a privileged group. Anything
# else (HasSession, AllowedToDelegate, ...) is NOT a traversal edge.
_ATTACK_EDGES = {
    "MemberOf", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
    "Owns", "AdminTo", "CanRDP", "ExecuteDCOM", "ForceChangePassword",
    "AddMember", "AddSelf", "AllExtendedRights",
    "DS-Replication-Get-Changes", "SQLAdmin",
}
_ATTACK_EDGES_LOWER = {kind.lower() for kind in _ATTACK_EDGES}

# Only these node labels start a documented path ("NON-privileged
# USERS/COMPUTERS"); a group is a hop, never an entry point.
_SOURCE_LABELS = {"user", "computer"}

_MAX_PATHS = 10      # attack paths turned into records
_MAX_KERBERO = 10    # Kerberoastable accounts turned into records
_MAX_FILES = 50      # collection artifacts listed in the tool result

_GATED_MSG = ("ad collection is operator-gated: enable ad.collect in the "
              "config / construct with enabled=True")


def _cap(text: str, n: int) -> str:
    """Truncate long prose (titles, SPN lists, paths) for the evidence."""
    text = str(text or "")
    return text if len(text) <= n else text[:n] + "..."


def _truthy(value: Any) -> bool:
    """Directory booleans arrive as True/False, 1/0 or 'true'/'false'."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _first(mapping: dict, keys: tuple[str, ...]) -> str:
    """First non-empty value among `keys` (exports vary in spelling)."""
    for key in keys:
        value = mapping.get(key)
        if value:
            return str(value)
    return ""


def _node_id(node: dict) -> str:
    return _first(node, ("objectId", "objectid", "id", "ObjectIdentifier"))


def _node_props(node: dict) -> dict:
    props = node.get("properties")
    return props if isinstance(props, dict) else {}


def _node_name(node: dict) -> str:
    name = _first(_node_props(node),
                  ("name", "samaccountname", "Name", "displayname"))
    return name or _node_id(node) or "unknown-node"


def _spn_list(props: dict) -> list[str]:
    """SPNs as a list — the property is a string in old exports, a list in
    new ones."""
    raw = props.get("serviceprincipalnames")
    if raw is None:
        raw = props.get("ServicePrincipalNames")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple, set)):
        return []
    out: list[str] = []
    for item in raw:
        out.extend(part.strip() for part in
                   str(item).replace(";", ",").split(",") if part.strip())
    return out


def _edge_kind(edge: dict) -> str:
    return _first(edge, ("kind", "label", "relationship", "type"))


def _edge_ends(edge: dict) -> tuple[str, str]:
    return (_first(edge, ("start", "source", "from")),
            _first(edge, ("end", "target", "to")))


def build_graph(data: dict) -> dict:
    """Pure: BloodHound node-list JSON -> the working graph.

    Returns the adjacency over ATTACK edges, the display names, the admin
    targets and the orphan-edge count. Defensive: a node without an object
    id and an edge pointing at an unknown node are skipped (the latter are
    counted as orphan_edges) instead of raising.
    """
    if not isinstance(data, dict):
        raise ToolError(f"not a BloodHound graph JSON ({type(data).__name__})")
    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise ToolError("not a BloodHound graph JSON (no nodes)")
    raw_edges = data.get("edges")
    if raw_edges is None:
        raw_edges = []
    if not isinstance(raw_edges, list):
        raise ToolError("not a BloodHound graph JSON (edges is not a list)")

    node_list: list[dict] = []
    names: dict[str, str] = {}
    labels: dict[str, str] = {}
    skipped = 0
    for raw in raw_nodes:
        if not isinstance(raw, dict) or not _node_id(raw):
            skipped += 1
            continue
        node_list.append(raw)
        names[_node_id(raw)] = _node_name(raw)
        labels[_node_id(raw)] = _first(raw, ("label", "type")).strip()

    adjacency: dict[str, list[tuple[str, str]]] = {oid: [] for oid in names}
    orphan_edges = edge_count = 0
    for raw in raw_edges:
        if not isinstance(raw, dict):
            orphan_edges += 1
            continue
        start, end = _edge_ends(raw)
        if not start or not end or start not in names or end not in names:
            orphan_edges += 1
            continue
        edge_count += 1
        kind = _edge_kind(raw)
        if kind.lower() in _ATTACK_EDGES_LOWER:
            adjacency[start].append((kind, end))
    for edges in adjacency.values():
        edges.sort(key=lambda ke: (ke[0], names.get(ke[1], ""), ke[1]))

    admin_oids: list[str] = []
    for raw in node_list:
        oid = _node_id(raw)
        props = _node_props(raw)
        if labels.get(oid, "").lower() != "group":
            continue
        if (_ADMIN_NAME_RE.search(names.get(oid, ""))
                or _truthy(props.get("admincount"))):
            admin_oids.append(oid)

    # A principal that is a DIRECT member of a privileged group is already
    # privileged: it is the target, not a documented path.
    admin_set = set(admin_oids)
    privileged = {oid for oid, edges in adjacency.items()
                  for kind, end in edges
                  if kind.lower() == "memberof" and end in admin_set}

    return {
        "node_list": node_list, "names": names, "labels": labels,
        "adjacency": adjacency, "admin_oids": admin_oids,
        "privileged_oids": privileged, "orphan_edges": orphan_edges,
        "node_count": len(node_list), "edge_count": edge_count,
        "skipped_nodes": skipped,
    }


def find_paths_to_da(graph: dict, max_depth: int = 8) -> list[list[str]]:
    """Pure: shortest attack paths from non-privileged principals to the
    privileged groups.

    `graph` is either a raw BloodHound node-list dict or the working graph
    from build_graph(). Sources are Users and Computers that are NOT already
    direct members of a privileged group; traversal follows attack edges
    only (MemberOf/GenericAll/AdminTo/...). Returns hop lists of display
    names, shortest first, deterministically ordered.
    """
    g = graph if "adjacency" in graph else build_graph(graph)
    adjacency, names, labels = g["adjacency"], g["names"], g["labels"]
    admin = set(g["admin_oids"])
    privileged = set(g["privileged_oids"])
    if not admin:
        return []
    try:
        max_depth = int(max_depth)
    except (TypeError, ValueError) as exc:
        raise ToolError(f"max_depth must be an integer, got {max_depth!r}") from exc
    if max_depth < 1:
        return []

    # Backward BFS from the privileged groups: one pass gives the distance
    # of every node to the nearest admin group.
    reverse: dict[str, list[str]] = {oid: [] for oid in adjacency}
    for oid, edges in adjacency.items():
        for _kind, end in edges:
            reverse.setdefault(end, []).append(oid)
    dist: dict[str, int | None] = {oid: None for oid in adjacency}
    queue: deque[str] = deque()
    for oid in sorted(admin):
        dist[oid] = 0
        queue.append(oid)
    while queue:
        cur = queue.popleft()
        depth = dist[cur]
        if depth is None or depth >= max_depth:
            continue
        for prev in sorted(reverse.get(cur, [])):
            if dist[prev] is None:
                dist[prev] = depth + 1
                queue.append(prev)

    paths: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for oid in sorted(adjacency, key=lambda o: names.get(o, "")):
        if oid in admin or oid in privileged:
            continue
        if labels.get(oid, "").lower() not in _SOURCE_LABELS:
            continue
        depth = dist.get(oid)
        if depth is None or depth < 1 or depth > max_depth:
            continue
        chain, cur = [oid], oid
        while dist.get(cur) not in (None, 0):
            nxt = next((end for _kind, end in adjacency[cur]
                        if dist.get(end) == dist[cur] - 1), None)
            if nxt is None:
                break
            chain.append(nxt)
            cur = nxt
        hop_names = [names.get(o, o) for o in chain]
        if tuple(hop_names) not in seen:
            seen.add(tuple(hop_names))
            paths.append(hop_names)
    paths.sort(key=lambda p: (len(p), p))
    return paths


def kerberoastable_users(nodes: list[dict]) -> list[dict]:
    """Pure: principals carrying SPNs — roastable offline.

    A directory fact (hasspn plus a non-empty SPN list), so the record is
    'confirmed': the defect exists in the directory. ATTACK NOT EXECUTED:
    no ticket was requested and no hash was cracked.
    """
    out: list[dict] = []
    for raw in nodes or []:
        if not isinstance(raw, dict):
            continue
        props = _node_props(raw)
        spns = _spn_list(props) if _truthy(props.get("hasspn")) else []
        if not spns:
            continue
        name = _node_name(raw)
        spn_text = _cap(", ".join(spns), 120)
        out.append({
            "name": name,
            "object_id": _node_id(raw),
            "domain": str(props.get("domain") or ""),
            "spns": spns,
            "severity": "medium",
            "cwe": "CWE-256",
            "record": {
                "title": f"Kerberoastable account: {name}",
                "severity": "medium",
                "status": "confirmed",   # static directory fact: SPNs exist
                "cwe": "CWE-256",
                "cvss": "",
                "target": name,
                "evidence": redactor.scrub(
                    f"scanner: BloodHound properties show SPNs on {name} "
                    f"({spn_text}) — roastable offline. ATTACK NOT EXECUTED: "
                    "no Kerberos ticket was requested and no hash was cracked."
                ),
                "remediation": (
                    "Move the service to a gMSA or another managed account "
                    "that cannot log on interactively, or set a long random "
                    "password on the account. ATTACK NOT EXECUTED: the SPN was "
                    "reported from the directory, nothing was roasted."
                ),
            },
        })
    return out


def parse_bh_graph(data: dict, max_depth: int = 8) -> dict:
    """Pure: BloodHound node-list JSON -> the analysis summary.

    'nodes' and 'edges' count the graph entries that could be used (a node
    without an object id and an edge pointing at an unknown node are
    skipped; the latter are counted in 'orphan_edges'). 'paths' are
    documented attack paths (report-only — nothing was executed).
    """
    g = build_graph(data)
    return {
        "nodes": g["node_count"],
        "edges": g["edge_count"],
        "paths": find_paths_to_da(g, max_depth=max_depth),
        "kerberoastable": kerberoastable_users(g["node_list"]),
        "admin_groups": sorted(g["names"].get(oid, oid)
                               for oid in g["admin_oids"]),
        "orphan_edges": g["orphan_edges"],
        "skipped_nodes": g["skipped_nodes"],
    }


def _graph_domain(data: Any) -> str:
    """Domain of the first node that carries one ('unknown-domain' if
    none)."""
    nodes = data.get("nodes") if isinstance(data, dict) else None
    for raw in nodes or []:
        if isinstance(raw, dict):
            domain = _first(_node_props(raw), ("domain", "Domain")).strip()
            if domain:
                return domain
    return "unknown-domain"


class AdCollectTool(Tool):
    """Passive Active Directory collection with bloodhound-python.

    REPORT-ONLY — no path in this module is ever executed. This tool only
    READS the directory; it never compromises anything.

    Read-only LDAP + Global Catalog + GC-LSAP queries against a FIXED
    operator-configured DC and domain (both set at construction; the schema
    exposes no arguments, so the model cannot redirect the collector).
    Credentials are NEVER accepted as tool arguments: bloodhound-python
    authenticates with the ambient Kerberos ticket / environment, and the
    argv built here never contains -u or -p.

    Operator-gated: the tool refuses to run unless it was constructed with
    enabled=True (config ad.collect). The collection archive is written to
    a temporary directory; analyse it with ad_analyze.
    """
    name = "ad_collect"
    description = (
        "Passive Active Directory collection with bloodhound-python (LDAP + "
        "Global Catalog + GC-LSAP reads only) against a FIXED "
        "operator-configured DC and domain. Operator-gated: requires "
        "ad.collect in the config. Credentials come from the ambient "
        "Kerberos ticket or environment — this tool never accepts a "
        "username or password. Writes a BloodHound archive to a temporary "
        "directory for ad_analyze. No arguments: DC and domain are fixed at "
        "construction."
    )
    binary = "bloodhound-python"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, dc_ip: str, domain: str, enabled: bool = False,
                 timeout: int = _COLLECT_TIMEOUT):
        self.dc_ip = str(dc_ip)
        self.domain = str(domain)
        self.enabled = bool(enabled)
        self.timeout = int(timeout)

    def run(self, args: dict[str, Any]) -> ToolResult:
        if not self.enabled:
            raise ToolError(_GATED_MSG)

        out_dir = Path(tempfile.mkdtemp(prefix="ad-collect-"))
        cmd = ["bloodhound-python", "-d", self.domain, "-dc", self.dc_ip,
               "-c", ",".join(_COLLECTIONS),
               "--outputdirectory", str(out_dir), "--no-cache"]
        proc = self.shell(cmd, timeout=self.timeout)
        if proc.returncode != 0:
            raise ToolError(f"bloodhound-python failed (rc={proc.returncode}): "
                            f"{(proc.stderr or '')[-300:]}")
        files = sorted(p.name for p in out_dir.iterdir())[:_MAX_FILES]
        return ToolResult(
            ok=True,
            summary=(f"ad_collect: collected {len(files)} artifact(s) from "
                     f"{self.domain} via {self.dc_ip} into {out_dir}"),
            data={
                "collected": True,
                "domain": self.domain,
                "dc": self.dc_ip,
                "output_dir": str(out_dir),
                "collections": list(_COLLECTIONS),
                "files": files,
                "note": ("The resulting archive/JSON is evidence: handle it "
                         "per the retention policy. Analysis is a separate "
                         "step (ad_analyze) — no attack path is ever executed."),
            },
            raw=(proc.stdout or "")[:_RAW_CAP],
        )


class AdAnalyzeTool(Tool):
    """Deterministic analysis of an operator-supplied BloodHound graph.

    The graph path is FIXED at construction and the schema exposes no
    arguments, so the model cannot point the analysis at another file. No
    binary, no traffic: pure parsing of the JSON the operator collected.

    REPORT-ONLY — no path in this module is ever executed. Attack paths are
    reported as 'suspected' (a documented path is an exposure, not an
    executed compromise); Kerberoastable accounts are 'confirmed' because
    the directory state proves the SPNs exist (ATTACK NOT EXECUTED).
    """
    name = "ad_analyze"
    description = (
        "Deterministic analysis of a FIXED operator-supplied BloodHound "
        "JSON graph: documented attack paths to privileged groups and "
        "Kerberoastable accounts. REPORT-ONLY — no path in this module is "
        "ever executed. Attack paths are 'suspected' (a documented path is "
        "an exposure, not an executed compromise); a Kerberoastable account "
        "is 'confirmed' because the directory state proves the SPNs exist "
        "(no ticket requested, no hash cracked). No arguments: the graph "
        "path is fixed at construction."
    )
    binary = None
    parameters = {"type": "object", "properties": {}}

    def __init__(self, report_path: Path, max_depth: int = 8):
        self.report_path = Path(report_path)
        self.max_depth = int(max_depth)

    def run(self, args: dict[str, Any]) -> ToolResult:
        try:
            raw = self.report_path.read_text(encoding="utf-8",
                                             errors="replace")
        except OSError as exc:
            raise ToolError(f"cannot read BloodHound JSON at "
                            f"{self.report_path}: {exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ToolError(f"BloodHound JSON is malformed: {exc}") from exc

        graph = parse_bh_graph(data, max_depth=self.max_depth)
        domain = _graph_domain(data)

        records: list[dict[str, Any]] = []
        for hops in graph["paths"][:_MAX_PATHS]:
            chain = " -> ".join(hops)
            records.append({
                "title": _cap(f"AD attack path to Domain Admins via {chain}",
                              200),
                "severity": "high" if len(hops) <= 3 else "medium",
                "status": "suspected",   # documented path, never executed
                "cwe": "CWE-269", "cvss": "", "target": domain,
                "evidence": redactor.scrub(
                    f"scanner: BloodHound path {chain} ({len(hops) - 1} hops)"
                    " — REPORT-ONLY, path not executed"),
                "remediation": (
                    "Break the chain at the weakest hop: remove nested "
                    "membership / tighten ACL / scope admin rights; verify "
                    "with the same collection after change."),
            })
        for account in graph["kerberoastable"][:_MAX_KERBERO]:
            records.append(dict(account["record"]))

        paths_total = len(graph["paths"])
        kerb_total = len(graph["kerberoastable"])
        return ToolResult(
            ok=True,
            summary=(f"ad_analyze: {paths_total} documented path(s) to "
                     f"privileged groups ({min(paths_total, _MAX_PATHS)} "
                     f"shown), {kerb_total} Kerberoastable account(s) "
                     f"({min(kerb_total, _MAX_KERBERO)} shown) — REPORT-ONLY, "
                     "no path executed"),
            data={
                "paths_total": paths_total,
                "paths_shown": min(paths_total, _MAX_PATHS),
                "kerberoastable_total": kerb_total,
                "kerberoastable_shown": min(kerb_total, _MAX_KERBERO),
                "node_count": graph["nodes"],
                "edge_count": graph["edges"],
                "orphan_edges": graph["orphan_edges"],
                "admin_groups": graph["admin_groups"],
                "domain": domain,
                "paths": graph["paths"][:_MAX_PATHS],
                "records": records,
                "note": ("REPORT-ONLY: attack paths are documented from the "
                         "graph, never executed."),
            },
        )
