"""Active Directory / internal-network module (catalog section 17).

Covers: the operator gate on passive collection, the exact argv built for
bloodhound-python (never a credential), the pure BloodHound graph parsers
(path finding, Kerberoastable accounts, orphan edges, max depth), the
verdict ladder (attack paths 'suspected', SPN accounts 'confirmed'), the
evidence marker, and the end-to-end analysis tool.

No network, no real domain, no bloodhound binary: the subprocess call goes
through a scripted runner and every fixture is inline JSON.
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from redteam.state import Finding, evidence_supported
from redteam.tools.ad import (AdAnalyzeTool, AdCollectTool, _cap,
                              build_graph, find_paths_to_da,
                              kerberoastable_users, parse_bh_graph)
from redteam.tools.base import LocalRunner, ToolError, set_runner

# --- fixture identifiers -----------------------------------------------------
ALICE = "S-1-5-21-111-222-333-1001"
BOB = "S-1-5-21-111-222-333-1002"
HELP_DESK = "G-1001"
SVC_MGMT = "G-1002"
DEPLOY = "G-1003"
OPS_TEAM = "G-1004"
DOMAIN_ADMINS = "G-1005"
BACKUP = "G-1006"
WEB01 = "C-1001"
FILE01 = "C-1002"


def _node(label, oid, name, domain="CORP.LOCAL", **props):
    properties = {"name": name, "domain": domain}
    properties.update(props)
    return {"label": label, "objectId": oid, "properties": properties}


def fixture_graph():
    """Realistic BloodHound-style graph.

    Two documented paths to Domain Admins (3 nodes and 5 nodes), one
    Kerberoastable user (ALICE), noise edges (AdminTo/GenericAll/HasSession)
    that lead nowhere, and one orphan edge pointing at an unknown node.
    """
    nodes = [
        _node("User", ALICE, "ALICE@CORP.LOCAL", hasspn=True,
              serviceprincipalnames="MSSQLSvc/db.corp.local:1433",
              enabled=True, admincount=False),
        _node("User", BOB, "BOB@CORP.LOCAL", hasspn=False,
              serviceprincipalnames=[], enabled=True, admincount=False),
        _node("Group", HELP_DESK, "HELP_DESK@CORP.LOCAL", admincount=False),
        _node("Group", SVC_MGMT, "SVC_MGMT@CORP.LOCAL"),
        _node("Group", DEPLOY, "DEPLOY@CORP.LOCAL"),
        _node("Group", OPS_TEAM, "OPS_TEAM@CORP.LOCAL"),
        _node("Group", DOMAIN_ADMINS, "DOMAIN ADMINS@CORP.LOCAL",
              admincount=True),
        _node("Group", BACKUP, "BACKUP_ADMINS@CORP.LOCAL", admincount=False),
        _node("Computer", WEB01, "WEB01.CORP.LOCAL", admincount=False),
        _node("Computer", FILE01, "FILE01.CORP.LOCAL"),
    ]
    edges = [
        {"kind": "MemberOf", "start": ALICE, "end": HELP_DESK},
        {"kind": "MemberOf", "start": HELP_DESK, "end": DOMAIN_ADMINS},
        {"kind": "MemberOf", "start": BOB, "end": SVC_MGMT},
        {"kind": "MemberOf", "start": SVC_MGMT, "end": DEPLOY},
        {"kind": "MemberOf", "start": DEPLOY, "end": OPS_TEAM},
        {"kind": "MemberOf", "start": OPS_TEAM, "end": DOMAIN_ADMINS},
        {"kind": "AdminTo", "start": BACKUP, "end": FILE01},
        {"kind": "GenericAll", "start": BACKUP, "end": WEB01},
        {"kind": "HasSession", "start": WEB01, "end": ALICE},
        {"kind": "MemberOf", "start": "G-GHOST", "end": ALICE},   # orphan
    ]
    return {"nodes": nodes, "edges": edges}


def chain_graph(depth=11):
    """A single path of `depth` hops from a user to Domain Admins."""
    nodes = [_node("User", "U-1", "DEEPUSER@CORP.LOCAL")]
    edges = []
    prev = "U-1"
    for i in range(1, depth):
        oid = f"G-{i}"
        nodes.append(_node("Group", oid, f"CHAIN{i}@CORP.LOCAL"))
        edges.append({"kind": "MemberOf", "start": prev, "end": oid})
        prev = oid
    nodes.append(_node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                       admincount=True))
    edges.append({"kind": "MemberOf", "start": prev, "end": "G-DA"})
    return {"nodes": nodes, "edges": edges}


def many_paths_graph(count=12):
    """`count` distinct users, each one hop away from a privileged group."""
    nodes = []
    edges = []
    for i in range(count):
        nodes.append(_node("User", f"U-{i}", f"USER{i:02d}@CORP.LOCAL"))
        nodes.append(_node("Group", f"G-{i}", f"GROUP{i:02d}@CORP.LOCAL"))
        edges.append({"kind": "MemberOf", "start": f"U-{i}", "end": f"G-{i}"})
        edges.append({"kind": "MemberOf", "start": f"G-{i}", "end": "G-DA"})
    nodes.append(_node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                       admincount=True))
    return {"nodes": nodes, "edges": edges}


def _proc(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout, stderr)


class ScriptedRunner:
    """Fake subprocess runner. Emulates bloodhound-python writing its
    collection archives into --outputdirectory."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, cmd, timeout=None, stdin=None):
        self.calls.append(cmd)
        name = Path(cmd[0]).name
        spec = self.responses.get(name)
        if spec is None:
            return _proc(cmd, rc=127,
                         stderr=f"unexpected binary invoked: {name}")
        files = spec.get("files")
        if files:
            out_dir = Path(cmd[cmd.index("--outputdirectory") + 1])
            for i in range(files):
                (out_dir / f"collection_{i:03d}.zip").write_text(
                    "archive", encoding="utf-8")
        return _proc(cmd, rc=spec.get("rc", 0),
                     stdout=spec.get("stdout", ""),
                     stderr=spec.get("stderr", ""))


class ExplodingRunner:
    """Any subprocess call is a bug for the analysis tool."""

    def __init__(self):
        self.calls = []

    def run(self, cmd, timeout=None, stdin=None):
        self.calls.append(cmd)
        raise AssertionError(f"the analysis tool must not shell out: {cmd}")


def write_graph(graph) -> Path:
    tmp = Path(tempfile.mkdtemp())
    path = tmp / "bloodhound.json"
    path.write_text(json.dumps(graph), encoding="utf-8")
    return path


class TestParseBhGraph(unittest.TestCase):
    def setUp(self):
        self.graph = parse_bh_graph(fixture_graph())

    def test_node_and_edge_counts(self):
        self.assertEqual(self.graph["nodes"], 10)
        # 10 edge records, one of them orphaned -> 9 usable
        self.assertEqual(self.graph["edges"], 9)

    def test_orphan_edge_is_counted_and_skipped(self):
        self.assertEqual(self.graph["orphan_edges"], 1)

    def test_exactly_two_paths_to_domain_admins(self):
        self.assertEqual(len(self.graph["paths"]), 2)
        lengths = sorted(len(p) for p in self.graph["paths"])
        self.assertEqual(lengths, [3, 5])

    def test_path_hop_lists(self):
        paths = {tuple(p) for p in self.graph["paths"]}
        self.assertIn(("ALICE@CORP.LOCAL", "HELP_DESK@CORP.LOCAL",
                       "DOMAIN ADMINS@CORP.LOCAL"), paths)
        self.assertIn(("BOB@CORP.LOCAL", "SVC_MGMT@CORP.LOCAL",
                       "DEPLOY@CORP.LOCAL", "OPS_TEAM@CORP.LOCAL",
                       "DOMAIN ADMINS@CORP.LOCAL"), paths)

    def test_path_ordering_is_deterministic(self):
        first = parse_bh_graph(fixture_graph())["paths"]
        second = parse_bh_graph(fixture_graph())["paths"]
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first, key=lambda p: (len(p), p)))

    def test_admin_groups_are_listed(self):
        self.assertEqual(self.graph["admin_groups"],
                         ["DOMAIN ADMINS@CORP.LOCAL"])

    def test_kerberoastable_accounts_are_listed(self):
        self.assertEqual(len(self.graph["kerberoastable"]), 1)
        self.assertEqual(self.graph["kerberoastable"][0]["name"],
                         "ALICE@CORP.LOCAL")

    def test_noise_edges_do_not_create_paths(self):
        for path in self.graph["paths"]:
            self.assertNotIn("WEB01.CORP.LOCAL", path)
            self.assertNotIn("FILE01.CORP.LOCAL", path)

    def test_max_depth_is_respected(self):
        deep = parse_bh_graph(chain_graph(depth=11), max_depth=8)
        self.assertEqual(deep["paths"], [])

    def test_path_returned_when_depth_allows(self):
        deep = parse_bh_graph(chain_graph(depth=11), max_depth=11)
        self.assertEqual(len(deep["paths"]), 1)
        self.assertEqual(len(deep["paths"][0]), 12)

    def test_missing_nodes_key_raises(self):
        with self.assertRaises(ToolError) as ctx:
            parse_bh_graph({"edges": []})
        self.assertIn("no nodes", str(ctx.exception))

    def test_empty_node_list_raises(self):
        with self.assertRaises(ToolError):
            parse_bh_graph({"nodes": [], "edges": []})

    def test_non_dict_input_raises(self):
        with self.assertRaises(ToolError):
            parse_bh_graph(["not", "a", "graph"])

    def test_edges_not_a_list_raises(self):
        with self.assertRaises(ToolError):
            parse_bh_graph({"nodes": fixture_graph()["nodes"], "edges": 7})

    def test_node_without_object_id_is_skipped(self):
        graph = fixture_graph()
        graph["nodes"].append({"label": "User",
                                "properties": {"name": "GHOST@CORP.LOCAL"}})
        parsed = parse_bh_graph(graph)
        self.assertEqual(parsed["nodes"], 10)
        self.assertEqual(parsed["skipped_nodes"], 1)

    def test_alternative_edge_shape_is_accepted(self):
        graph = {
            "nodes": [
                _node("User", "U-1", "CARL@CORP.LOCAL"),
                _node("Group", "G-1", "OPS@CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"label": "MemberOf", "source": "U-1", "target": "G-1"},
                      {"label": "MemberOf", "source": "G-1", "target": "G-DA"}],
        }
        parsed = parse_bh_graph(graph)
        self.assertEqual(parsed["paths"],
                         [["CARL@CORP.LOCAL", "OPS@CORP.LOCAL",
                           "DOMAIN ADMINS@CORP.LOCAL"]])

    def test_edge_kinds_are_matched_case_insensitively(self):
        graph = {
            "nodes": [
                _node("User", "U-1", "CARL@CORP.LOCAL"),
                _node("Group", "G-1", "OPS@CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"kind": "memberof", "start": "U-1", "end": "G-1"},
                      {"kind": "MemberOf", "start": "G-1", "end": "G-DA"}],
        }
        self.assertEqual(len(parse_bh_graph(graph)["paths"]), 1)

    def test_non_attack_edges_are_not_traversed(self):
        graph = {
            "nodes": [
                _node("User", "U-1", "CARL@CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"kind": "HasSession", "start": "U-1", "end": "G-DA"}],
        }
        self.assertEqual(parse_bh_graph(graph)["paths"], [])


class TestFindPathsToDa(unittest.TestCase):
    def test_simple_chain_returns_hop_list(self):
        graph = {
            "nodes": [
                _node("User", "U-1", "CARL@CORP.LOCAL"),
                _node("Group", "G-1", "OPS@CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"kind": "MemberOf", "start": "U-1", "end": "G-1"},
                      {"kind": "MemberOf", "start": "G-1", "end": "G-DA"}],
        }
        self.assertEqual(find_paths_to_da(graph),
                         [["CARL@CORP.LOCAL", "OPS@CORP.LOCAL",
                           "DOMAIN ADMINS@CORP.LOCAL"]])

    def test_no_path_returns_empty_list(self):
        graph = {
            "nodes": [
                _node("User", "U-1", "CARL@CORP.LOCAL"),
                _node("Group", "G-1", "OPS@CORP.LOCAL"),
            ],
            "edges": [{"kind": "MemberOf", "start": "U-1", "end": "G-1"}],
        }
        self.assertEqual(find_paths_to_da(graph), [])

    def test_accepts_raw_json_or_built_graph(self):
        raw = fixture_graph()
        self.assertEqual(find_paths_to_da(raw),
                         find_paths_to_da(build_graph(raw)))

    def test_direct_membership_is_not_a_path(self):
        """A principal that is already a direct member of the privileged
        group is privileged, not an attack path."""
        graph = {
            "nodes": [
                _node("User", "U-1", "DAISER@CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"kind": "MemberOf", "start": "U-1", "end": "G-DA"}],
        }
        self.assertEqual(find_paths_to_da(graph), [])

    def test_only_users_and_computers_are_sources(self):
        """Groups are hops, never entry points."""
        graph = {
            "nodes": [
                _node("Group", "G-1", "OPS@CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"kind": "MemberOf", "start": "G-1", "end": "G-DA"}],
        }
        self.assertEqual(find_paths_to_da(graph), [])

    def test_computer_is_a_valid_source(self):
        graph = {
            "nodes": [
                _node("Computer", "C-1", "HOST01.CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"kind": "GenericAll", "start": "C-1", "end": "G-DA"}],
        }
        self.assertEqual(find_paths_to_da(graph),
                         [["HOST01.CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"]])

    def test_max_depth_one_keeps_only_direct_edges(self):
        graph = {
            "nodes": [
                _node("User", "U-1", "CARL@CORP.LOCAL"),
                _node("Group", "G-1", "OPS@CORP.LOCAL"),
                _node("Group", "G-DA", "DOMAIN ADMINS@CORP.LOCAL",
                      admincount=True),
            ],
            "edges": [{"kind": "MemberOf", "start": "U-1", "end": "G-1"},
                      {"kind": "MemberOf", "start": "G-1", "end": "G-DA"}],
        }
        self.assertEqual(find_paths_to_da(graph, max_depth=1), [])

    def test_no_admin_group_means_no_paths(self):
        graph = {
            "nodes": [_node("User", "U-1", "CARL@CORP.LOCAL"),
                      _node("Group", "G-1", "OPS@CORP.LOCAL")],
            "edges": [{"kind": "MemberOf", "start": "U-1", "end": "G-1"}],
        }
        self.assertEqual(find_paths_to_da(graph), [])


class TestKerberoastableUsers(unittest.TestCase):
    def test_hasspn_with_spn_is_a_confirmed_finding(self):
        nodes = [_node("User", "U-1", "ALICE@CORP.LOCAL", hasspn=True,
                       serviceprincipalnames="MSSQLSvc/db.corp.local:1433")]
        found = kerberoastable_users(nodes)
        self.assertEqual(len(found), 1)
        record = found[0]["record"]
        self.assertEqual(record["status"], "confirmed")
        self.assertEqual(record["cwe"], "CWE-256")
        self.assertEqual(record["severity"], "medium")
        self.assertEqual(record["title"],
                         "Kerberoastable account: ALICE@CORP.LOCAL")

    def test_evidence_carries_the_scanner_marker(self):
        nodes = [_node("User", "U-1", "ALICE@CORP.LOCAL", hasspn=True,
                       serviceprincipalnames="MSSQLSvc/db.corp.local:1433")]
        record = kerberoastable_users(nodes)[0]["record"]
        self.assertTrue(record["evidence"].startswith("scanner:"))
        self.assertIn("roastable offline", record["evidence"])

    def test_attack_not_executed_is_stated(self):
        nodes = [_node("User", "U-1", "ALICE@CORP.LOCAL", hasspn=True,
                       serviceprincipalnames="MSSQLSvc/db.corp.local:1433")]
        record = kerberoastable_users(nodes)[0]["record"]
        self.assertIn("ATTACK NOT EXECUTED", record["remediation"])
        self.assertIn("ATTACK NOT EXECUTED", record["evidence"])

    def test_hasspn_false_is_excluded(self):
        nodes = [_node("User", "U-1", "BOB@CORP.LOCAL", hasspn=False,
                       serviceprincipalnames="MSSQLSvc/db.corp.local:1433")]
        self.assertEqual(kerberoastable_users(nodes), [])

    def test_empty_spn_list_is_excluded(self):
        nodes = [_node("User", "U-1", "BOB@CORP.LOCAL", hasspn=True,
                       serviceprincipalnames=[])]
        self.assertEqual(kerberoastable_users(nodes), [])

    def test_spn_given_as_a_list(self):
        nodes = [_node("User", "U-1", "BOB@CORP.LOCAL", hasspn=True,
                       serviceprincipalnames=["MSSQLSvc/db.corp.local:1433",
                                              "HTTP/web.corp.local:80"])]
        found = kerberoastable_users(nodes)
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]["spns"]), 2)

    def test_spn_text_is_capped(self):
        nodes = [_node("User", "U-1", "BOB@CORP.LOCAL", hasspn=True,
                       serviceprincipalnames=[f"svc{i}" for i in range(60)])]
        record = kerberoastable_users(nodes)[0]["record"]
        self.assertLess(len(record["evidence"]), 300)

    def test_malformed_nodes_are_skipped(self):
        self.assertEqual(kerberoastable_users(["junk", None, 5]), [])


class TestAdAnalyzeTool(unittest.TestCase):
    def setUp(self):
        self.runner = ExplodingRunner()
        set_runner(self.runner)
        self.addCleanup(set_runner, LocalRunner())
        self.path = write_graph(fixture_graph())
        self.tool = AdAnalyzeTool(self.path)

    def test_analysis_never_shells_out(self):
        self.tool.run({})
        self.assertEqual(self.runner.calls, [])

    def test_end_to_end_counts(self):
        result = self.tool.run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["paths_total"], 2)
        self.assertEqual(result.data["paths_shown"], 2)
        self.assertEqual(result.data["kerberoastable_total"], 1)
        self.assertEqual(result.data["kerberoastable_shown"], 1)
        self.assertEqual(result.data["node_count"], 10)
        self.assertEqual(result.data["edge_count"], 9)

    def test_path_records_are_suspected_and_report_only(self):
        result = self.tool.run({})
        path_records = [r for r in result.data["records"]
                        if r["title"].startswith("AD attack path")]
        self.assertEqual(len(path_records), 2)
        for record in path_records:
            self.assertEqual(record["status"], "suspected")
            self.assertEqual(record["cwe"], "CWE-269")
            self.assertIn("REPORT-ONLY", record["evidence"])
            self.assertIn("path not executed", record["evidence"])
            self.assertTrue(record["evidence"].startswith("scanner:"))

    def test_path_severity_follows_the_hop_count(self):
        result = self.tool.run({})
        path_records = [r for r in result.data["records"]
                        if r["title"].startswith("AD attack path")]
        by_title = {r["title"]: r for r in path_records}
        short = next(r for r in path_records if "HELP_DESK" in r["title"])
        long = next(r for r in path_records if "SVC_MGMT" in r["title"])
        self.assertEqual(short["severity"], "high")
        self.assertEqual(long["severity"], "medium")
        self.assertEqual(len(by_title), 2)

    def test_kerberoastable_record_is_confirmed(self):
        result = self.tool.run({})
        spn_records = [r for r in result.data["records"]
                        if r["title"].startswith("Kerberoastable")]
        self.assertEqual(len(spn_records), 1)
        record = spn_records[0]
        self.assertEqual(record["status"], "confirmed")
        self.assertEqual(record["cwe"], "CWE-256")
        self.assertIn("ALICE@CORP.LOCAL", record["evidence"])

    def test_confirmed_record_passes_the_evidence_standard(self):
        result = self.tool.run({})
        record = next(r for r in result.data["records"]
                      if r["status"] == "confirmed")
        finding = Finding(id="x", title=record["title"], severity="medium",
                          target=record["target"], evidence=record["evidence"],
                          status="confirmed")
        self.assertTrue(evidence_supported(finding))

    def test_no_path_record_is_ever_confirmed(self):
        result = self.tool.run({})
        for record in result.data["records"]:
            if record["title"].startswith("AD attack path"):
                self.assertNotEqual(record["status"], "confirmed")

    def test_target_domain_is_derived_from_the_graph(self):
        result = self.tool.run({})
        self.assertEqual(result.data["domain"], "CORP.LOCAL")
        for record in result.data["records"]:
            if record["title"].startswith("AD attack path"):
                self.assertEqual(record["target"], "CORP.LOCAL")

    def test_unknown_domain_fallback(self):
        graph = fixture_graph()
        for node in graph["nodes"]:
            node["properties"].pop("domain", None)
        result = AdAnalyzeTool(write_graph(graph)).run({})
        self.assertEqual(result.data["domain"], "unknown-domain")

    def test_paths_are_capped_at_ten(self):
        result = AdAnalyzeTool(write_graph(many_paths_graph(12))).run({})
        self.assertEqual(result.data["paths_total"], 12)
        self.assertEqual(result.data["paths_shown"], 10)
        self.assertEqual(len(result.data["records"]), 10)

    def test_empty_graph_raises(self):
        path = write_graph({"nodes": [], "edges": []})
        with self.assertRaises(ToolError) as ctx:
            AdAnalyzeTool(path).run({})
        self.assertIn("no nodes", str(ctx.exception))

    def test_malformed_json_raises(self):
        tmp = Path(tempfile.mkdtemp()) / "bad.json"
        tmp.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ToolError) as ctx:
            AdAnalyzeTool(tmp).run({})
        self.assertIn("malformed", str(ctx.exception))

    def test_missing_file_raises(self):
        missing = Path(tempfile.mkdtemp()) / "nope.json"
        with self.assertRaises(ToolError):
            AdAnalyzeTool(missing).run({})

    def test_schema_takes_no_arguments(self):
        self.assertEqual(self.tool.parameters,
                         {"type": "object", "properties": {}})

    def test_max_depth_is_a_constructor_option(self):
        deep = AdAnalyzeTool(write_graph(chain_graph(depth=11)), max_depth=8)
        result = deep.run({})
        self.assertEqual(result.data["paths_total"], 0)

    def test_docstring_states_report_only(self):
        self.assertIn("REPORT-ONLY", AdAnalyzeTool.__doc__)
        self.assertIn("no path in this module is ever executed",
                      AdAnalyzeTool.__doc__)


class TestAdCollectTool(unittest.TestCase):
    def setUp(self):
        self.runner = ScriptedRunner({"bloodhound-python": {"rc": 0}})
        set_runner(self.runner)
        self.addCleanup(set_runner, LocalRunner())

    def _tool(self, enabled=True):
        return AdCollectTool("10.0.0.5", "CORP.LOCAL", enabled=enabled)

    def test_disabled_refuses_to_run(self):
        with self.assertRaises(ToolError) as ctx:
            self._tool(enabled=False).run({})
        message = str(ctx.exception)
        self.assertIn("operator-gated", message)
        self.assertIn("ad.collect", message)
        self.assertEqual(self.runner.calls, [])

    def test_enabled_collects(self):
        result = self._tool().run({})
        self.assertTrue(result.ok)
        self.assertTrue(result.data["collected"])
        self.assertTrue(Path(result.data["output_dir"]).is_dir())
        self.assertIn("Group", result.data["collections"])
        self.assertIn("SPNTargets", result.data["collections"])

    def test_argv_is_exact_and_carries_no_credentials(self):
        self._tool().run({})
        cmd = self.runner.calls[0]
        self.assertEqual(cmd[0], "bloodhound-python")
        self.assertEqual(cmd[cmd.index("-d") + 1], "CORP.LOCAL")
        self.assertEqual(cmd[cmd.index("-dc") + 1], "10.0.0.5")
        self.assertEqual(cmd[cmd.index("-c") + 1],
                         "Group,LocalAdmin,Session,LoggedOn,Trusts,ACL,"
                         "Container,ObjectProps,SPNTargets,RDP")
        self.assertIn("--outputdirectory", cmd)
        self.assertIn("--no-cache", cmd)
        # credentials come from the ambient ticket — never from argv
        for forbidden in ("-u", "-p", "--user", "--password", "-pw"):
            self.assertNotIn(forbidden, cmd)

    def test_no_secret_leaks_into_the_result(self):
        result = self._tool().run({})
        blob = json.dumps(result.data)
        self.assertNotIn("password", blob.lower())

    def test_collection_list_is_capped_at_fifty_entries(self):
        self.runner.responses["bloodhound-python"]["files"] = 60
        result = self._tool().run({})
        self.assertEqual(len(result.data["files"]), 50)

    def test_failure_raises_with_the_stderr_tail(self):
        stderr = "A" * 400 + "BOOM"
        self.runner.responses["bloodhound-python"] = {"rc": 1, "stderr": stderr}
        with self.assertRaises(ToolError) as ctx:
            self._tool().run({})
        message = str(ctx.exception)
        self.assertIn("BOOM", message)
        self.assertIn(stderr[-300:], message)
        self.assertNotIn("A" * 300, message)

    def test_schema_takes_no_arguments(self):
        self.assertEqual(self._tool().parameters,
                         {"type": "object", "properties": {}})

    def test_docstring_states_report_only_and_passive(self):
        doc = AdCollectTool.__doc__
        self.assertIn("REPORT-ONLY", doc)
        self.assertIn("no path in this module is ever executed", doc)
        self.assertIn("read-only", doc.lower())


class TestCapHelper(unittest.TestCase):
    def test_short_text_untouched(self):
        self.assertEqual(_cap("abc", 10), "abc")

    def test_long_text_truncated_with_marker(self):
        out = _cap("x" * 50, 10)
        self.assertTrue(out.startswith("x" * 10))
        self.assertTrue(out.endswith("..."))
        self.assertEqual(len(out), 13)

    def test_none_becomes_empty(self):
        self.assertEqual(_cap(None, 10), "")


if __name__ == "__main__":
    unittest.main()
