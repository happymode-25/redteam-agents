"""Mobile application assessment (catalog section 14).

Covers: the pure manifest parser (namespaced, namespace-free and
malformed input), the deterministic verdict ladder (manifest defects
confirmed, heuristic signals suspected), the exported-component severity
ladder and its record cap, the aapt badging inventory parser, the
read-only tool wiring (fixed paths, no LLM-redirectable arguments),
graceful degradation when aapt is absent, and the decompiled-source
secret scan (file/size caps, skipped binaries, scrubbed evidence, the
confirmed/suspected split).

No network, no real binaries, no device: subprocess calls go through a
scripted runner and every artifact is an inline sample or a tmp file.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from redteam.redact import redactor
from redteam.state import Finding, evidence_supported
from redteam.tools import mobile
from redteam.tools.base import LocalRunner, ToolError, set_runner
from redteam.tools.mobile import (ApkBadgingTool, DecompileSecretScanTool,
                                  ManifestAuditTool,
                                  exported_component_candidates,
                                  manifest_findings, parse_aapt_badging,
                                  parse_manifest_xml)

MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo"
    android:versionCode="42"
    android:versionName="1.4.2">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <application
        android:label="Demo"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
        <activity android:name="com.example.demo.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <provider
            android:name="com.example.demo.data.Provider"
            android:authorities="com.example.demo.provider"
            android:exported="true" />
        <service
            android:name="com.example.demo.sync.SyncService"
            android:exported="false" />
        <receiver
            android:name="com.example.demo.BootReceiver"
            android:exported="true"
            android:permission="com.example.demo.permission.INTERNAL">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
"""

# namespace-free variant (aapt-style / stripped manifest)
MANIFEST_XML_PLAIN = """<manifest package="com.example.plain" versionName="2.0">
    <uses-sdk minSdkVersion="21" targetSdkVersion="30" />
    <uses-permission name="android.permission.INTERNET" />
    <application debuggable="false" allowBackup="false">
        <activity name="com.example.plain.Main">
            <intent-filter>
                <action name="android.intent.action.MAIN" />
                <category name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

BADGING = """package: name='com.example.demo' versionCode='42' versionName='1.4.2'
sdkVersion:'24'
targetSdkVersion:'33'
uses-permission:'android.permission.INTERNET'
uses-permission:'android.permission.CAMERA'
application-label:'Demo App'
application: label='Demo App' icon='res/mipmap/ic_launcher.png'
launchable-activity: name='com.example.demo.MainActivity' label='Demo App' icon='res/mipmap/ic_launcher.png'
"""

BADGING_NO_TARGET = """package: name='com.example.demo' versionCode='7' versionName='0.9'
sdkVersion:'21'
uses-permission:'android.permission.INTERNET'
"""

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GOOGLE_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv"


def _proc(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout, stderr)


class ScriptedRunner:
    """Fake subprocess runner keyed by binary name."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, cmd, timeout=None, stdin=None):
        self.calls.append(cmd)
        name = Path(cmd[0]).name
        spec = self.responses.get(name)
        if spec is None:
            return _proc(cmd, rc=127, stderr=f"unexpected binary invoked: {name}")
        return _proc(cmd, rc=spec.get("rc", 0),
                     stdout=spec.get("stdout", ""), stderr=spec.get("stderr", ""))


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _parsed(**overrides) -> dict:
    """Minimal parsed-manifest dict for one rule in isolation."""
    base = {
        "package": "com.example.demo",
        "version": "1.4.2",
        "min_sdk": 24,
        "target_sdk": 33,
        "permissions": [],
        "flags": {"debuggable": False, "allow_backup": False, "cleartext": False,
                  "test_only": False, "network_security_config": False},
        "components": [],
        "entry_point": None,
        "parse_notes": [],
    }
    base.update(overrides)
    return base


def _component(kind="provider", name="com.example.demo.Thing", exported=True,
               permission=None, actions=None, main_launcher=False) -> dict:
    return {"kind": kind, "name": name, "exported": exported,
            "exported_explicit": exported, "has_intent_filter": bool(actions),
            "permission": permission, "actions": actions or [],
            "main_launcher": main_launcher}


class TestParseManifestXml(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_manifest_xml(MANIFEST_XML)

    def test_package_and_versions(self):
        self.assertEqual(self.parsed["package"], "com.example.demo")
        self.assertEqual(self.parsed["version"], "1.4.2")
        self.assertEqual(self.parsed["min_sdk"], 24)
        self.assertEqual(self.parsed["target_sdk"], 33)

    def test_permissions_are_collected(self):
        self.assertEqual(len(self.parsed["permissions"]), 6)
        self.assertIn("android.permission.READ_SMS", self.parsed["permissions"])
        self.assertIn("android.permission.READ_CONTACTS",
                      self.parsed["permissions"])

    def test_application_flags(self):
        flags = self.parsed["flags"]
        self.assertTrue(flags["debuggable"])
        self.assertTrue(flags["allow_backup"])
        self.assertTrue(flags["cleartext"])
        self.assertFalse(flags["test_only"])
        self.assertFalse(flags["network_security_config"])

    def test_components_are_extracted(self):
        kinds = [c["kind"] for c in self.parsed["components"]]
        self.assertEqual(kinds, ["activity", "provider", "service", "receiver"])

    def test_explicit_exported_attribute_is_honoured(self):
        by_name = {c["name"]: c for c in self.parsed["components"]}
        provider = by_name["com.example.demo.data.Provider"]
        service = by_name["com.example.demo.sync.SyncService"]
        self.assertTrue(provider["exported"])
        self.assertFalse(service["exported"])
        self.assertIsNone(provider["permission"])

    def test_exported_defaults_to_true_when_intent_filter_present(self):
        activity = self.parsed["components"][0]
        self.assertIsNone(activity["exported_explicit"])
        self.assertTrue(activity["has_intent_filter"])
        self.assertTrue(activity["exported"])

    def test_main_launcher_component_is_identified(self):
        activity = self.parsed["components"][0]
        self.assertTrue(activity["main_launcher"])
        self.assertEqual(activity["actions"], ["android.intent.action.MAIN"])
        self.assertEqual(self.parsed["entry_point"],
                         "com.example.demo.MainActivity")

    def test_receiver_permission_is_captured(self):
        receiver = self.parsed["components"][3]
        self.assertEqual(receiver["permission"],
                         "com.example.demo.permission.INTERNAL")

    def test_namespace_free_manifest_parses(self):
        plain = parse_manifest_xml(MANIFEST_XML_PLAIN)
        self.assertEqual(plain["package"], "com.example.plain")
        self.assertEqual(plain["version"], "2.0")
        self.assertEqual(plain["min_sdk"], 21)
        self.assertEqual(plain["target_sdk"], 30)
        self.assertEqual(plain["permissions"],
                         ["android.permission.INTERNET"])
        self.assertFalse(plain["flags"]["debuggable"])
        self.assertFalse(plain["flags"]["allow_backup"])
        self.assertTrue(plain["components"][0]["main_launcher"])

    def test_malformed_xml_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_manifest_xml("<manifest><application>")
        with self.assertRaises(ValueError):
            parse_manifest_xml("")

    def test_minimal_manifest_has_notes_and_no_components(self):
        minimal = parse_manifest_xml('<manifest package="com.example.min"/>')
        self.assertEqual(minimal["package"], "com.example.min")
        self.assertIsNone(minimal["min_sdk"])
        self.assertIsNone(minimal["target_sdk"])
        self.assertEqual(minimal["components"], [])
        self.assertIsNone(minimal["flags"]["network_security_config"])
        self.assertTrue(minimal["parse_notes"])


class TestManifestFindings(unittest.TestCase):
    def _one(self, **overrides) -> dict:
        return manifest_findings(_parsed(**overrides))[0]

    def test_debuggable_is_confirmed_high(self):
        rec = self._one(flags={**_parsed()["flags"], "debuggable": True})
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["severity"], "high")
        self.assertEqual(rec["cwe"], "CWE-489")
        self.assertTrue(rec["evidence"].startswith("scanner: "))
        self.assertIn("android:debuggable=true", rec["evidence"])

    def test_test_only_is_confirmed_high(self):
        rec = self._one(flags={**_parsed()["flags"], "test_only": True})
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["severity"], "high")
        self.assertEqual(rec["cwe"], "CWE-489")
        self.assertIn("android:testOnly=true", rec["evidence"])

    def test_allow_backup_is_confirmed_medium(self):
        rec = self._one(flags={**_parsed()["flags"], "allow_backup": True})
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["severity"], "medium")
        self.assertEqual(rec["cwe"], "CWE-530")

    def test_cleartext_is_confirmed_medium(self):
        rec = self._one(flags={**_parsed()["flags"], "cleartext": True})
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["severity"], "medium")
        self.assertEqual(rec["cwe"], "CWE-319")
        self.assertIn("networkSecurityConfig", rec["evidence"])

    def test_exported_provider_is_high(self):
        rec = self._one(components=[_component("provider")])
        self.assertEqual(rec["severity"], "high")
        self.assertEqual(rec["cwe"], "CWE-926")
        self.assertEqual(rec["status"], "confirmed")
        self.assertIn("com.example.demo.Thing", rec["evidence"])

    def test_exported_service_is_high(self):
        rec = self._one(components=[_component("service")])
        self.assertEqual(rec["severity"], "high")
        self.assertEqual(rec["cwe"], "CWE-926")

    def test_exported_receiver_is_medium(self):
        rec = self._one(components=[_component("receiver")])
        self.assertEqual(rec["severity"], "medium")
        self.assertEqual(rec["cwe"], "CWE-926")

    def test_exported_activity_is_medium(self):
        rec = self._one(components=[_component("activity")])
        self.assertEqual(rec["severity"], "medium")
        self.assertEqual(rec["cwe"], "CWE-926")

    def test_launcher_activity_is_not_flagged(self):
        records = manifest_findings(_parsed(components=[
            _component("activity", name="com.example.demo.MainActivity",
                       actions=["android.intent.action.MAIN"],
                       main_launcher=True)]))
        self.assertEqual(records, [])
        self.assertEqual(exported_component_candidates(_parsed(components=[
            _component("activity", name="com.example.demo.MainActivity",
                       actions=["android.intent.action.MAIN"],
                       main_launcher=True)])), [])

    def test_component_with_permission_is_not_flagged(self):
        records = manifest_findings(_parsed(components=[
            _component("provider", permission="com.example.demo.permission.X")]))
        self.assertEqual(records, [])

    def test_non_exported_component_is_not_flagged(self):
        records = manifest_findings(_parsed(components=[
            _component("provider", exported=False)]))
        self.assertEqual(records, [])

    def test_dangerous_permissions_produce_one_combined_record(self):
        records = manifest_findings(_parsed(permissions=[
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS"]))
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["status"], "suspected")
        self.assertEqual(rec["severity"], "medium")
        self.assertEqual(rec["cwe"], "CWE-255")
        self.assertIn("READ_SMS", rec["evidence"])
        self.assertIn("READ_CONTACTS", rec["evidence"])

    def test_old_target_sdk_is_suspected(self):
        rec = self._one(target_sdk=25)
        self.assertEqual(rec["status"], "suspected")
        self.assertEqual(rec["severity"], "medium")
        self.assertEqual(rec["cwe"], "CWE-1104")

    def test_missing_target_sdk_produces_no_record(self):
        self.assertEqual(manifest_findings(_parsed(target_sdk=None)), [])

    def test_current_target_sdk_produces_no_record(self):
        self.assertEqual(manifest_findings(_parsed(target_sdk=33)), [])

    def test_every_record_carries_scanner_marker_and_manifest_target(self):
        records = manifest_findings(parse_manifest_xml(MANIFEST_XML))
        self.assertTrue(records)
        for rec in records:
            self.assertTrue(rec["evidence"].startswith("scanner: "))
            self.assertEqual(rec["target"], "com.example.demo (manifest)")
            self.assertEqual(rec["record_source"], "mobile")
            self.assertTrue(rec["remediation"])

    def test_confirmed_records_pass_the_evidence_standard(self):
        records = manifest_findings(parse_manifest_xml(MANIFEST_XML))
        for rec in records:
            if rec["status"] != "confirmed":
                continue
            finding = Finding(id="x", title=rec["title"], severity="high",
                              target=rec["target"], evidence=rec["evidence"],
                              status="confirmed")
            self.assertTrue(evidence_supported(finding), rec["title"])

    def test_component_records_are_capped(self):
        components = [_component("provider", name=f"com.example.demo.P{i}")
                      for i in range(30)]
        records = manifest_findings(_parsed(components=components))
        self.assertEqual(len(records), mobile._MAX_COMPONENT_RECORDS)
        self.assertEqual(len(exported_component_candidates(
            _parsed(components=components))), 30)


class TestAaptBadging(unittest.TestCase):
    def setUp(self):
        self.info = parse_aapt_badging(BADGING)

    def test_package_and_versions(self):
        self.assertEqual(self.info["package"], "com.example.demo")
        self.assertEqual(self.info["version"], "1.4.2")
        self.assertEqual(self.info["version_code"], "42")

    def test_sdk_levels_are_coerced_to_ints(self):
        self.assertEqual(self.info["min_sdk"], 24)
        self.assertEqual(self.info["target_sdk"], 33)

    def test_permissions_label_and_launcher(self):
        self.assertEqual(self.info["permissions"],
                         ["android.permission.INTERNET",
                          "android.permission.CAMERA"])
        self.assertEqual(self.info["label"], "Demo App")
        self.assertEqual(self.info["launcher"]["name"],
                         "com.example.demo.MainActivity")
        self.assertEqual(self.info["launcher"]["label"], "Demo App")

    def test_missing_target_sdk_is_none(self):
        info = parse_aapt_badging(BADGING_NO_TARGET)
        self.assertIsNone(info["target_sdk"])
        self.assertEqual(info["min_sdk"], 21)
        self.assertEqual(info["package"], "com.example.demo")

    def test_empty_output_is_all_none(self):
        info = parse_aapt_badging("")
        self.assertIsNone(info["package"])
        self.assertIsNone(info["target_sdk"])
        self.assertEqual(info["permissions"], [])


class TestManifestAuditTool(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.manifest = _write(self.tmp, "AndroidManifest.xml", MANIFEST_XML)
        self.tool = ManifestAuditTool(self.manifest)

    def test_end_to_end_findings_and_counts(self):
        result = self.tool.run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["package"], "com.example.demo")
        self.assertEqual(result.data["components_total"], 4)
        self.assertEqual(result.data["components_exported"], 3)
        self.assertEqual(len(result.data["records"]), 5)
        self.assertEqual(len(result.data["findings"]), 5)
        self.assertIn("manifest audit of com.example.demo", result.summary)
        self.assertIn("4 confirmed", result.summary)

    def test_records_are_confirmed_or_suspected_only(self):
        statuses = {r["status"] for r in self.tool.run({}).data["records"]}
        self.assertTrue(statuses <= {"confirmed", "suspected"})

    def test_missing_manifest_raises_tool_error_with_basename(self):
        missing = self.tmp / "NotThere.xml"
        with self.assertRaises(ToolError) as ctx:
            ManifestAuditTool(missing).run({})
        self.assertIn("NotThere.xml", str(ctx.exception))
        self.assertNotIn(str(self.tmp), str(ctx.exception))

    def test_malformed_manifest_raises_tool_error(self):
        bad = _write(self.tmp, "bad.xml", "<manifest><application>")
        with self.assertRaises(ToolError):
            ManifestAuditTool(bad).run({})

    def test_schema_is_empty_so_the_path_cannot_be_redirected(self):
        self.assertEqual(self.tool.parameters,
                         {"type": "object", "properties": {}})

    def test_component_cap_is_reported_in_the_data(self):
        providers = "".join(
            f'<provider android:name="com.example.demo.P{i}" '
            'android:exported="true" />' for i in range(30))
        xml = MANIFEST_XML.replace("</application>", providers + "</application>")
        path = _write(self.tmp, "many.xml", xml)
        result = ManifestAuditTool(path).run({})
        component_records = [r for r in result.data["records"]
                             if r["cwe"] == "CWE-926"]
        self.assertEqual(len(component_records), mobile._MAX_COMPONENT_RECORDS)
        self.assertIn("note", result.data)
        self.assertIn("capped", result.data["note"])


class TestApkBadgingTool(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.apk = self.tmp / "demo.apk"
        self.apk.write_bytes(b"PK\x03\x04fake-apk")
        self.runner = ScriptedRunner({"aapt": {"stdout": BADGING}})
        set_runner(self.runner)
        self.addCleanup(set_runner, LocalRunner())

    def test_argv_is_exact_and_the_result_is_inventory(self):
        result = ApkBadgingTool(self.apk).run({})
        self.assertTrue(result.ok)
        self.assertEqual(self.runner.calls[0],
                         ["aapt", "dump", "badging", str(self.apk)])
        self.assertEqual(result.data["package"], "com.example.demo")
        self.assertEqual(result.data["target_sdk"], 33)
        self.assertIn("inventory: com.example.demo v1.4.2 target 33",
                      result.summary)

    def test_inventory_produces_no_records(self):
        result = ApkBadgingTool(self.apk).run({})
        self.assertNotIn("records", result.data)
        self.assertNotIn("findings", result.data)

    def test_non_zero_return_code_is_a_tool_error(self):
        set_runner(ScriptedRunner({"aapt": {"rc": 1, "stderr": "bad apk"}}))
        with self.assertRaises(ToolError) as ctx:
            ApkBadgingTool(self.apk).run({})
        self.assertIn("bad apk", str(ctx.exception))

    def test_unavailable_when_aapt_is_not_installed(self):
        with mock.patch("shutil.which", return_value=None):
            ok, reason = ApkBadgingTool(self.apk).available()
        self.assertFalse(ok)
        self.assertIn("not found on PATH", reason)

    def test_schema_is_empty_so_the_apk_cannot_be_redirected(self):
        self.assertEqual(ApkBadgingTool(self.apk).parameters,
                         {"type": "object", "properties": {}})


class TestDecompileSecretScanTool(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _tool(self) -> DecompileSecretScanTool:
        return DecompileSecretScanTool(self.tmp)

    def test_aws_key_is_a_confirmed_record(self):
        _write(self.tmp, "src/Config.java",
               f'public static final String AWS = "{AWS_KEY}";\n')
        result = self._tool().run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["findings"], 1)
        rec = result.data["record_list"][0]
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["severity"], "high")
        self.assertEqual(rec["cwe"], "CWE-798")
        self.assertEqual(rec["target"], "src/Config.java:1")
        self.assertTrue(rec["evidence"].startswith("scanner: "))
        self.assertIn("LIVENESS NOT TESTED", rec["evidence"])

    def test_credential_literal_is_only_suspected(self):
        _write(self.tmp, "src/Api.kt",
               'val apiKey = "s3cr3t-value-abcdef123"\n')
        rec = self._tool().run({}).data["record_list"][0]
        self.assertEqual(rec["status"], "suspected")
        self.assertEqual(rec["severity"], "medium")
        self.assertEqual(rec["cwe"], "CWE-798")

    def test_private_key_block_is_confirmed(self):
        _write(self.tmp, "assets/id_rsa",
               "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
        rec = self._tool().run({}).data["record_list"][0]
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["cwe"], "CWE-321")

    def test_google_api_key_is_confirmed(self):
        _write(self.tmp, "src/Google.java",
               f'String KEY = "{GOOGLE_KEY}";\n')
        rec = self._tool().run({}).data["record_list"][0]
        self.assertEqual(rec["status"], "confirmed")
        self.assertEqual(rec["severity"], "medium")

    def test_binary_files_are_skipped(self):
        _write(self.tmp, "res/logo.png", f'AKIAIOSFODNN7EXAMPLE\n')
        _write(self.tmp, "lib/libnative.so", f'AKIAIOSFODNN7EXAMPLE\n')
        _write(self.tmp, "src/Ok.java", "int x = 1;\n")
        result = self._tool().run({})
        self.assertEqual(result.data["files_scanned"], 1)
        self.assertEqual(result.data["findings"], 0)

    def test_files_scanned_count_and_multiple_findings(self):
        _write(self.tmp, "src/A.java", f'String AWS = "{AWS_KEY}";\n')
        _write(self.tmp, "src/B.kt", 'val apiKey = "s3cr3t-value-abcdef123"\n')
        _write(self.tmp, "src/C.java", "int x = 1;\n")
        result = self._tool().run({})
        self.assertEqual(result.data["files_scanned"], 3)
        self.assertEqual(result.data["findings"], 2)
        self.assertEqual(result.data["records"], 2)
        statuses = sorted(r["status"] for r in result.data["record_list"])
        self.assertEqual(statuses, ["confirmed", "suspected"])

    def test_oversized_file_is_skipped(self):
        _write(self.tmp, "src/Huge.java", "A" * 600_000)
        _write(self.tmp, "src/Small.java", "int x = 1;\n")
        result = self._tool().run({})
        self.assertEqual(result.data["files_scanned"], 1)

    def test_max_files_cap_is_enforced(self):
        for i in range(5):
            _write(self.tmp, f"src/F{i}.java", "int x = 1;\n")
        with mock.patch.object(mobile, "_MAX_FILES", 2):
            result = self._tool().run({})
        self.assertEqual(result.data["files_scanned"], 2)

    def test_record_cap_is_enforced_and_noted(self):
        for i in range(60):
            _write(self.tmp, f"src/K{i}.java", f'String AWS = "{AWS_KEY}";\n')
        result = self._tool().run({})
        self.assertEqual(result.data["findings"], 60)
        self.assertEqual(result.data["records"], mobile._MAX_SECRET_RECORDS)
        self.assertIn("record cap reached", result.data["note"])

    def test_evidence_window_is_capped_and_scrubbed(self):
        redactor.register("OPERATOR-TOKEN-9")
        self.addCleanup(redactor.clear)
        padding = "B" * 200
        _write(self.tmp, "src/Long.java",
               f'{padding} OPERATOR-TOKEN-9 "{AWS_KEY}"\n')
        rec = self._tool().run({}).data["record_list"][0]
        context = rec["evidence"].split("context: ", 1)[1]
        self.assertLessEqual(len(context), 120)
        self.assertNotIn("OPERATOR-TOKEN-9", rec["evidence"])
        self.assertIn("[REDACTED]", rec["evidence"])

    def test_confirmed_records_pass_the_evidence_standard(self):
        _write(self.tmp, "src/Config.java", f'String AWS = "{AWS_KEY}";\n')
        for rec in self._tool().run({}).data["record_list"]:
            finding = Finding(id="x", title=rec["title"], severity="high",
                              target=rec["target"], evidence=rec["evidence"],
                              status=rec["status"])
            self.assertTrue(evidence_supported(finding))

    def test_missing_directory_raises_tool_error(self):
        with self.assertRaises(ToolError) as ctx:
            DecompileSecretScanTool(self.tmp / "nope").run({})
        self.assertIn("nope", str(ctx.exception))

    def test_empty_directory_is_ok_with_no_findings(self):
        result = self._tool().run({})
        self.assertTrue(result.ok)
        self.assertEqual(result.data["files_scanned"], 0)
        self.assertEqual(result.data["findings"], 0)
        self.assertIn("no files scanned", result.summary)

    def test_schema_is_empty_so_the_directory_cannot_be_redirected(self):
        self.assertEqual(self._tool().parameters,
                         {"type": "object", "properties": {}})


if __name__ == "__main__":
    unittest.main()
