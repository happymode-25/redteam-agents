"""Cloud posture module (catalog section 7).

Covers: storage URL construction from fixed operator hints (sanitization —
a weird hint can never reach a URL), the bucket response classification
ladder (confirmed / no_issue / inconclusive with `response:` evidence,
redaction and caps), guard-before-request ordering and ScopeViolation
propagation that aborts the probe loop, the Prowler and ScoutSuite parsers
over inline realistic reports (FAIL-only recording, conservative walking
with a depth cap), the fixed-path report tool, the evidence standard for
every confirmed record, and the no-argument schemas.

No network, no real scanner binaries: ScopedSession is patched with a fake
serving canned responses per URL and the guard is a recording stand-in.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests

from redteam.redact import redactor
from redteam.scope import ScopeViolation
from redteam.state import Finding, evidence_supported
from redteam.tools.base import ToolError
from redteam.tools.cloudposture import (BucketExposureTool, CloudPostureInput,
                                        CloudPostureReportTool,
                                        classify_bucket_response,
                                        parse_prowler, parse_scoutsuite,
                                        prowler_status_counts, sanitize_hint,
                                        scout_unparsed, scout_unparsed_count,
                                        storage_urls, walk_scoutsuite)

AWS_URL = "https://acme.s3.amazonaws.com/"
GCP_URL = "https://storage.googleapis.com/acme"
AZ_URL = "https://acme.blob.core.windows.net/?comp=list"
AWS_DEV = "https://acme-dev.s3.amazonaws.com/"
GCP_DEV = "https://storage.googleapis.com/acme-dev"
AZ_DEV = "https://acme-dev.blob.core.windows.net/?comp=list"

S3_LISTING = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>acme-backups</Name><Prefix></Prefix><KeyCount>10</KeyCount>
  <Contents><Key>exports/key-01.csv</Key><Size>1048576</Size></Contents>
  <Contents><Key>exports/key-02.csv</Key><Size>2048</Size></Contents>
  <Contents><Key>exports/key-03.csv</Key><Size>4096</Size></Contents>
  <Contents><Key>exports/key-04.csv</Key><Size>128</Size></Contents>
  <Contents><Key>exports/key-05.csv</Key><Size>256</Size></Contents>
  <Contents><Key>exports/key-06.csv</Key><Size>64</Size></Contents>
  <Contents><Key>exports/key-07.csv</Key><Size>32</Size></Contents>
</ListBucketResult>"""

AZURE_LISTING = """<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://acme.blob.core.windows.net/">
  <Blobs>
    <Blob><Name>logs/app-01.log</Name></Blob>
    <Blob><Name>logs/app-02.log</Name></Blob>
  </Blobs>
</EnumerationResults>"""

GCS_LISTING = json.dumps({
    "kind": "storage#bucket", "id": "acme", "selfLink": "https://x/acme",
    "items": [{"name": "logs/app-01.log", "size": "128"},
              {"name": "logs/app-02.log", "size": "256"}],
})

DENIED_XML = ('<Error><Code>AccessDenied</Code>'
              '<Message>Access Denied</Message>'
              '<RequestId>0F3D4E5C6B7A8901</RequestId></Error>')
AZURE_DENIED = ('<Error><Code>AuthorizationPermissionDenied</Code>'
                '<Message>This request is not authorized to perform container '
                'list operations.</Message></Error>')
NOTFOUND_XML = ('<Error><Code>NoSuchBucket</Code><BucketName>nope</BucketName>'
                '<Message>The specified bucket does not exist</Message></Error>')
CONTAINER_NOTFOUND = ('<Error><Code>ContainerNotFound</Code>'
                      '<Message>The specified container does not exist.'
                      '</Message></Error>')

PROWLER_JSON = json.dumps({
    "findings": [
        {"CheckID": "checkov_s3_1", "ServiceName": "s3", "Status": "FAIL",
         "Severity": "critical",
         "CheckTitle": "S3 bucket allows public read access",
         "ResourceDetails": {
             "ResourceArn": "arn:aws:s3:::acme-public-assets",
             "AccountId": "111122223333", "ResourceType": "AwsS3Bucket"},
         "Description": "The S3 bucket has an ACL that grants public read.",
         "Remediation": {"Recommendation": {
             "Text": "Enable S3 Block Public Access at bucket and account "
                     "level."}}},
        {"CheckID": "iam_mfa_enabled_for_console_access", "ServiceName": "iam",
         "Status": "FAIL", "Severity": "high",
         "CheckTitle": "MFA is enabled for console access",
         "ResourceDetails": {
             "ResourceArn": "arn:aws:iam::111122223333:user/alice",
             "AccountId": "111122223333"},
         "Description": "The IAM user has console access without MFA.",
         "Remediation": {"Recommendation": {
             "Text": "Enable a virtual MFA device for the IAM user."}}},
        {"CheckID": "s3_bucket_default_encryption", "ServiceName": "s3",
         "Status": "PASS", "Severity": "medium",
         "CheckTitle": "S3 bucket has default encryption enabled",
         "ResourceDetails": {"ResourceArn": "arn:aws:s3:::acme-private"},
         "Remediation": {"Recommendation": {"Text": "n/a"}}},
        {"CheckID": "cloudtrail_multi_region_enabled", "ServiceName": "cloudtrail",
         "Status": "INCONCISE", "Severity": "medium",
         "CheckTitle": "CloudTrail multi-region is enabled",
         "ResourceDetails": {"ResourceArn":
                             "arn:aws:cloudtrail:us-east-1:111122223333:trail/acme"},
         "Remediation": {"Recommendation": {
             "Text": "Enable a multi-region CloudTrail trail."}}},
    ],
    "summary": {"resources": 4, "pass": 1, "fail": 2},
})

MINI_PROWLER = json.dumps({
    "findings": [
        {"CheckID": "iam_root_hardware_mfa_enabled", "ServiceName": "iam",
         "Status": "FAIL", "Severity": "informational",
         "CheckTitle": "Hardware MFA is enabled for the root account",
         "ResourceDetails": {"ResourceArn": "arn:aws:iam::111122223333:root"},
         "CWEs": ["CWE-308"],
         "Remediation": {"Recommendation": {
             "Text": "Enable a hardware MFA device for the root account."}}},
    ],
})

SCOUT_JSON = json.dumps({
    "aws": {
        "iam": {
            "credentials": {
                "users": {
                    "alice": {"level": "dangerous",
                              "desc": "Access key exposed in a public repository",
                              "items": {"active_key_1": "AKIA0EXAMPLEKEY0"}},
                    "bob": {"level": "WARNING",
                            "desc": "Console password has never been used",
                            "items": {"password_last_used": None}},
                },
            },
            "policies": {
                "AdministratorAccess": {"level": "WARNING", "attached_users": 3},
            },
        },
        "s3": {
            "buckets": {
                "acme-public": {"public": True, "acl": "private",
                                "region": "us-east-1", "logging": False},
                "acme-acl-open": {"acl": "public-read", "region": "us-east-1"},
                "acme-private": {"public": False, "acl": "private",
                                 "region": "us-east-1"},
            },
        },
    },
    "metadata": {"name": "AWS", "account_id": "111122223333"},
})


class FakeResponse:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text


class FakeSession:
    """Stands in for ScopedSession (patched at module level): canned
    (status, text) per URL, or an Exception instance to raise. Records the
    request order so guard-before-request can be asserted."""

    responses: dict = {}
    calls: list = []
    order: list = []

    def __init__(self, guard=None, **kwargs):
        pass

    def get(self, url, **kwargs):
        FakeSession.calls.append(url)
        FakeSession.order.append(("session", url))
        spec = FakeSession.responses.get(url, (404, ""))
        if isinstance(spec, Exception):
            raise spec
        return FakeResponse(*spec)


class FakeGuard:
    """Minimal Guard stand-in: records guard.run targets (with order) and
    raises ScopeViolation on the fail_on-th call (1-based)."""

    def __init__(self, order, fail_on=None):
        self.order = order
        self.fail_on = fail_on
        self.calls = []

    def run(self, target, fn, *args, **kwargs):
        self.calls.append(target)
        self.order.append(("guard", target))
        if self.fail_on is not None and len(self.calls) == self.fail_on:
            raise ScopeViolation(f"{target} is not in the scope allowlist")
        return fn(*args, **kwargs)


class TestStorageUrls(unittest.TestCase):
    def test_exact_output_for_hints(self):
        self.assertEqual(storage_urls(["acme", "acme-dev"]), [
            ("aws", AWS_URL), ("gcp", GCP_URL), ("azure", AZ_URL),
            ("aws", AWS_DEV), ("gcp", GCP_DEV), ("azure", AZ_DEV),
        ])

    def test_hint_is_stripped_and_lowered(self):
        self.assertEqual(storage_urls(["  ACME "]),
                         [("aws", AWS_URL), ("gcp", GCP_URL), ("azure", AZ_URL)])
        self.assertEqual(sanitize_hint(" Acme-Dev "), "acme-dev")

    def test_invalid_hints_are_skipped(self):
        for bad in ("acme corp", "prod.acme", "   ", None, 42, "acme/../etc",
                    "a" * 64):
            self.assertIsNone(sanitize_hint(bad), bad)
        self.assertEqual(storage_urls(["acme corp", "prod.acme", "", None]), [])

    def test_weird_hints_never_reach_a_url(self):
        weird = ["../etc", "acme&x=1", "x#y", "$HOME", "%2e%2e", "a/b",
                 "acme?role=", "acme corp", "a" * 300, "acme.evil.com"]
        self.assertEqual([u for _, u in storage_urls(weird)], [])
        self.assertEqual(storage_urls(["ok"]), [
            ("aws", "https://ok.s3.amazonaws.com/"),
            ("gcp", "https://storage.googleapis.com/ok"),
            ("azure", "https://ok.blob.core.windows.net/?comp=list"),
        ])
        for hint in ("ok", "-dash-", "0", "acme-dev"):
            expected = {
                "aws": f"https://{hint}.s3.amazonaws.com/",
                "gcp": f"https://storage.googleapis.com/{hint}",
                "azure": f"https://{hint}.blob.core.windows.net/?comp=list",
            }
            for cloud, url in storage_urls([hint]):
                self.assertEqual(url, expected[cloud])
                self.assertNotIn(" ", url)
                self.assertNotIn("..", url)


class TestClassifyBucketResponse(unittest.TestCase):
    def test_listing_is_confirmed_with_cwe200(self):
        cls = classify_bucket_response("aws", 200, S3_LISTING, AWS_URL)
        self.assertEqual(cls["verdict"], "confirmed")
        self.assertEqual(cls["severity"], "high")
        self.assertEqual(cls["cwe"], "CWE-200")
        self.assertTrue(cls["evidence"].startswith("response:"))
        self.assertIn(AWS_URL, cls["evidence"])
        self.assertIn("status 200", cls["evidence"])
        self.assertIn("public object listing", cls["evidence"])
        self.assertIn("exports/key-01.csv", cls["evidence"])

    def test_sample_keys_capped_at_five(self):
        cls = classify_bucket_response("aws", 200, S3_LISTING, AWS_URL)
        self.assertIn("exports/key-05.csv", cls["evidence"])
        self.assertNotIn("exports/key-06.csv", cls["evidence"])

    def test_azure_and_gcs_listings_are_confirmed(self):
        az = classify_bucket_response("azure", 200, AZURE_LISTING, AZ_URL)
        self.assertEqual(az["verdict"], "confirmed")
        self.assertIn("logs/app-01.log", az["evidence"])
        gcs = classify_bucket_response("gcp", 200, GCS_LISTING, GCP_URL)
        self.assertEqual(gcs["verdict"], "confirmed")
        self.assertIn("logs/app-01.log", gcs["evidence"])

    def test_denied_is_no_issue(self):
        denied = classify_bucket_response("aws", 403, DENIED_XML, AWS_URL)
        self.assertEqual(denied["verdict"], "no_issue")
        self.assertIn("denied", denied["note"])
        self.assertEqual(denied["evidence"], "")
        az = classify_bucket_response("azure", 403, AZURE_DENIED, AZ_URL)
        self.assertEqual(az["verdict"], "no_issue")

    def test_missing_is_no_issue(self):
        missing = classify_bucket_response("aws", 404, NOTFOUND_XML, AWS_URL)
        self.assertEqual(missing["verdict"], "no_issue")
        self.assertIn("does not exist", missing["note"])
        bare = classify_bucket_response("azure", 404, CONTAINER_NOTFOUND, AZ_URL)
        self.assertEqual(bare["verdict"], "no_issue")

    def test_ambiguous_stays_inconclusive(self):
        for status, body in [(500, "Internal Server Error"),
                             (200, "<html>please sign in</html>"),
                             (403, "<html>Forbidden</html>"),
                             (301, "")]:
            cls = classify_bucket_response("aws", status, body, AWS_URL)
            self.assertEqual(cls["verdict"], "inconclusive", (status, body))
            self.assertEqual(cls["evidence"], "")
        timed_out = classify_bucket_response("aws", None,
                                             "HTTPSConnectionPool: read timed out")
        self.assertEqual(timed_out["verdict"], "inconclusive")
        self.assertIn("no HTTP response", timed_out["note"])

    def test_evidence_is_capped_and_redacted(self):
        redactor.clear()
        self.addCleanup(redactor.clear)
        redactor.register("hunter2-super-secret")
        body = S3_LISTING.replace("exports/key-01.csv",
                                  "exports/hunter2-super-secret.csv")
        cls = classify_bucket_response("aws", 200, body, AWS_URL)
        self.assertIn("[REDACTED]", cls["evidence"])
        self.assertNotIn("hunter2-super-secret", cls["evidence"])
        huge = ("<ListBucketResult>" + "".join(
            f"<Contents><Key>{'X' * 200}-{i:04d}</Key></Contents>"
            for i in range(200)) + "</ListBucketResult>")
        cls = classify_bucket_response("aws", 200, huge, AWS_URL)
        self.assertEqual(cls["verdict"], "confirmed")
        self.assertLessEqual(len(cls["evidence"]), 300)


class FakesBase(unittest.TestCase):
    def setUp(self):
        FakeSession.responses = {}
        FakeSession.calls = []
        FakeSession.order = []
        self.guard = FakeGuard(FakeSession.order)
        self.patcher = mock.patch("redteam.tools.cloudposture.ScopedSession",
                                  FakeSession)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)


class TestBucketExposureTool(FakesBase):
    def _tool(self, hints=("acme",), fail_on=None):
        self.guard = FakeGuard(FakeSession.order, fail_on=fail_on)
        return BucketExposureTool(self.guard, list(hints))

    def test_mixed_verdicts_counts_and_records(self):
        FakeSession.responses = {
            AWS_URL: (200, S3_LISTING),
            GCP_URL: (403, DENIED_XML),
            AZ_URL: (404, NOTFOUND_XML),
            AWS_DEV: (500, "Internal Server Error"),
            GCP_DEV: (200, S3_LISTING),
            AZ_DEV: (403, AZURE_DENIED),
        }
        result = self._tool(("acme", "acme-dev")).run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["probed"], 6)
        self.assertEqual(result.data["confirmed"], 2)
        verdicts = {e["url"]: e["verdict"] for e in result.data["buckets"]}
        self.assertEqual(verdicts, {
            AWS_URL: "confirmed", GCP_URL: "no_issue", AZ_URL: "no_issue",
            AWS_DEV: "inconclusive", GCP_DEV: "confirmed", AZ_DEV: "no_issue",
        })
        for entry in result.data["buckets"]:
            if entry["verdict"] == "confirmed":
                rec = entry["record"]
                self.assertEqual(rec["status"], "confirmed")
                self.assertEqual(rec["cwe"], "CWE-200")
                self.assertEqual(rec["target"], entry["url"])
                self.assertIn("response:", rec["evidence"])
            else:
                self.assertNotIn("record", entry)

    def test_guard_authorizes_before_every_request(self):
        FakeSession.responses = {url: (404, "")
                                 for url in (AWS_URL, GCP_URL, AZ_URL)}
        self._tool(("acme",)).run({})
        self.assertEqual(self.guard.calls, FakeSession.calls)
        self.assertEqual(len(FakeSession.order), 6)
        for i, (actor, target) in enumerate(FakeSession.order):
            self.assertEqual(actor, "guard" if i % 2 == 0 else "session", i)
            self.assertEqual(target, self.guard.calls[i // 2])

    def test_scope_violation_aborts_remaining_probes(self):
        FakeSession.responses = {url: (200, S3_LISTING)
                                 for url in (AWS_URL, GCP_URL, AZ_URL,
                                             AWS_DEV, GCP_DEV, AZ_DEV)}
        tool = self._tool(("acme", "acme-dev"), fail_on=2)
        with self.assertRaises(ScopeViolation):
            tool.run({})
        self.assertEqual(len(FakeSession.calls), 1)   # only the first probe ran
        self.assertEqual(len(FakeSession.order), 3)   # guard, session, guard!

    def test_transport_error_is_inconclusive(self):
        FakeSession.responses = {AWS_URL: requests.Timeout("connect timeout")}
        result = self._tool(("acme",)).run({})
        entry = result.data["buckets"][0]
        self.assertEqual(entry["verdict"], "inconclusive")
        self.assertIn("no HTTP response", entry["note"])
        self.assertEqual(result.data["confirmed"], 0)

    def test_invalid_hints_are_skipped_with_a_note(self):
        FakeSession.responses = {url: (404, "")
                                 for url in (AWS_URL, GCP_URL, AZ_URL)}
        result = self._tool(("acme corp", "  ", "ACME")).run({})
        self.assertEqual(result.data["probed"], 3)
        self.assertEqual(result.data["skipped_hints"], ["acme corp", "  "])
        self.assertIn("skipped", result.data["note"])
        for entry in result.data["buckets"]:
            self.assertNotIn(" ", entry["url"])

    def test_summary_reports_the_confirmed_count(self):
        FakeSession.responses = {AWS_URL: (200, S3_LISTING),
                                 GCP_URL: (403, DENIED_XML),
                                 AZ_URL: (404, "")}
        result = self._tool(("acme",)).run({})
        self.assertIn("3 storage URL(s) probed", result.summary)
        self.assertIn("1 public listing(s) confirmed", result.summary)


class TestProwlerParser(unittest.TestCase):
    def setUp(self):
        self.findings = parse_prowler(PROWLER_JSON)

    def test_only_failures_become_findings(self):
        self.assertEqual(len(self.findings), 2)
        self.assertEqual({f["check_id"] for f in self.findings},
                         {"checkov_s3_1", "iam_mfa_enabled_for_console_access"})

    def test_severity_maps_directly(self):
        critical, high = self.findings
        self.assertEqual(critical["severity"], "critical")
        self.assertEqual(high["severity"], "high")
        mini = parse_prowler(MINI_PROWLER)[0]
        self.assertEqual(mini["severity"], "info")     # informational -> info
        unlabelled = parse_prowler(json.dumps({"findings": [
            {"CheckID": "x", "Status": "FAIL"}]}))[0]
        self.assertEqual(unlabelled["severity"], "medium")

    def test_evidence_carries_scanner_marker_and_check_id(self):
        for f in self.findings:
            rec = f["record"]
            self.assertEqual(rec["status"], "confirmed")
            self.assertTrue(rec["evidence"].startswith("scanner: prowler"))
            self.assertIn(f["check_id"], rec["evidence"])
            self.assertIn("FAIL", rec["evidence"])
            self.assertIn(f["resource"], rec["evidence"])
            self.assertEqual(rec["cvss"], "")            # never invented
        critical = self.findings[0]["record"]
        self.assertIn("(critical)", critical["evidence"])
        self.assertEqual(critical["target"],
                         "arn:aws:s3:::acme-public-assets")
        self.assertIn("Block Public Access", critical["remediation"])

    def test_cwe_is_carried_when_the_report_provides_it(self):
        rec = parse_prowler(MINI_PROWLER)[0]["record"]
        self.assertEqual(rec["cwe"], "CWE-308")
        self.assertIn("(informational)", rec["evidence"])
        self.assertEqual(parse_prowler(PROWLER_JSON)[0]["record"]["cwe"], "")

    def test_pass_and_inconcise_are_counted_not_recorded(self):
        self.assertEqual(prowler_status_counts(PROWLER_JSON),
                         {"FAIL": 2, "PASS": 1, "INCONCISE": 1})
        pass_only = json.dumps({"findings": [
            {"CheckID": "s3_bucket_default_encryption", "Status": "PASS",
             "Severity": "medium"}]})
        self.assertEqual(parse_prowler(pass_only), [])
        self.assertEqual(prowler_status_counts(pass_only), {"PASS": 1})

    def test_malformed_report_raises_tool_error(self):
        with self.assertRaises(ToolError):
            parse_prowler("not json at all")
        with self.assertRaises(ToolError):
            parse_prowler('{"checks": []}')
        with self.assertRaises(ToolError):
            parse_prowler("[]")


class TestScoutParser(unittest.TestCase):
    def setUp(self):
        self.node = json.loads(SCOUT_JSON)
        self.findings = walk_scoutsuite(self.node)

    def test_explicit_markers_are_flagged(self):
        by_path = {f["path"]: f for f in self.findings}
        self.assertEqual(set(by_path), {
            "aws/iam/credentials/users/alice",
            "aws/s3/buckets/acme-public",
            "aws/s3/buckets/acme-acl-open",
        })
        alice = by_path["aws/iam/credentials/users/alice"]
        self.assertEqual(alice["marker"], "level=dangerous")
        self.assertEqual(alice["severity"], "high")
        pub = by_path["aws/s3/buckets/acme-public"]
        self.assertIn("public", pub["marker"])
        self.assertEqual(pub["severity"], "medium")
        acl = by_path["aws/s3/buckets/acme-acl-open"]
        self.assertEqual(acl["marker"], "acl=public-read")

    def test_ambiguous_branches_are_not_guessed(self):
        blob = json.dumps(self.findings)
        self.assertNotIn("bob", blob)
        self.assertNotIn("AdministratorAccess", blob)
        self.assertNotIn("acme-private", blob)
        # the two WARNING blocks are counted as ambiguous, not flagged
        self.assertEqual(scout_unparsed_count(self.node), 2)
        self.assertEqual(scout_unparsed(SCOUT_JSON), 2)

    def test_records_are_confirmed_with_the_scanner_marker(self):
        for f in self.findings:
            rec = f["record"]
            self.assertEqual(rec["status"], "confirmed")
            self.assertTrue(rec["evidence"].startswith("scanner: scoutsuite"))
            self.assertIn(f["path"], rec["evidence"])

    def test_depth_cap_terminates_deep_recursion(self):
        deep = {"leaf": "end"}
        for _ in range(2000):        # unbounded recursion would blow up
            deep = {"child": deep}
        self.assertIsInstance(walk_scoutsuite(deep), list)
        self.assertGreaterEqual(scout_unparsed_count(deep), 1)

    def test_malformed_report_raises_tool_error(self):
        with self.assertRaises(ToolError):
            parse_scoutsuite("{ definitely not json")
        with self.assertRaises(ToolError):
            parse_scoutsuite("[1, 2, 3]")
        for value in (None, 42, "no markers here", []):
            self.assertEqual(walk_scoutsuite(value), [])


class TestCloudPostureReportTool(unittest.TestCase):
    def _write(self, text):
        path = Path(tempfile.mkdtemp()) / "report.json"
        path.write_text(text, encoding="utf-8")
        return path

    def test_missing_and_empty_files_are_tool_errors(self):
        missing = Path(tempfile.mkdtemp()) / "nope.json"
        with self.assertRaises(ToolError) as cm:
            CloudPostureReportTool(missing, "prowler").run({})
        self.assertLessEqual(len(str(cm.exception)), 300)
        with self.assertRaises(ToolError) as cm:
            CloudPostureReportTool(self._write("  \n"), "scout").run({})
        self.assertIn("empty", str(cm.exception))

    def test_prowler_report_counts_and_summary(self):
        result = CloudPostureReportTool(self._write(PROWLER_JSON),
                                         "prowler").run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["count"], 2)
        self.assertEqual(result.data["report_kind"], "prowler")
        self.assertEqual(result.data["status_counts"],
                         {"FAIL": 2, "PASS": 1, "INCONCISE": 1})
        self.assertIn("2 failed check(s) recorded", result.summary)
        self.assertIn("1 passed, 1 inconclusive", result.summary)

    def test_prowler_report_without_failures(self):
        pass_only = json.dumps({"findings": [
            {"CheckID": "s3_bucket_default_encryption", "ServiceName": "s3",
             "Status": "PASS", "Severity": "medium",
             "CheckTitle": "S3 bucket has default encryption enabled",
             "ResourceDetails": {"ResourceArn": "arn:aws:s3:::acme-private"}}]})
        result = CloudPostureReportTool(self._write(pass_only),
                                         "prowler").run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["count"], 0)
        self.assertIn("no failed checks", result.summary)

    def test_scout_report_counts_and_unparsed(self):
        result = CloudPostureReportTool(self._write(SCOUT_JSON),
                                         "scout").run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["count"], 3)
        self.assertEqual(result.data["unparsed"], 2)
        self.assertEqual(result.data["report_kind"], "scout")
        self.assertIn("3 explicit danger finding(s)", result.summary)
        self.assertIn("2 ambiguous structure(s)", result.summary)

    def test_invalid_kind_is_rejected(self):
        path = self._write(PROWLER_JSON)
        with self.assertRaises(ValueError):
            CloudPostureReportTool(path, "nessus")
        with self.assertRaises(ValueError):
            CloudPostureInput(path, "")


class TestEvidenceAndSchemas(FakesBase):
    def test_confirmed_records_pass_the_evidence_standard(self):
        FakeSession.responses = {AWS_URL: (200, S3_LISTING)}
        bucket = BucketExposureTool(self.guard, ["acme"]).run({})
        evidences = [bucket.data["buckets"][0]["record"]["evidence"],
                     parse_prowler(PROWLER_JSON)[0]["record"]["evidence"],
                     walk_scoutsuite(json.loads(SCOUT_JSON))[0]["record"]
                     ["evidence"]]
        for evidence in evidences:
            finding = Finding(id="x", title="t", severity="high", target="t",
                              evidence=evidence, status="confirmed")
            self.assertTrue(evidence_supported(finding), evidence[:80])

    def test_tools_expose_no_arguments(self):
        tools = [BucketExposureTool(self.guard, ["acme"]),
                 CloudPostureReportTool(Path("prowler.json"), "prowler")]
        for tool in tools:
            self.assertEqual(tool.parameters,
                             {"type": "object", "properties": {}}, tool.name)
            self.assertIsNone(tool.binary)
            self.assertTrue(tool.available()[0], tool.name)


if __name__ == "__main__":
    unittest.main()
