"""Mobile application assessment (catalog section 14).

Static, OFFLINE analysis of an operator-supplied Android artifact: the
DECODED AndroidManifest.xml, an `aapt dump badging` inventory, and a
decoded source tree. READ-ONLY and device-free by construction:

- Nothing is installed, executed, launched, or pushed. No device is ever
  touched and adb is never invoked; the APK is only ever READ from disk.
- The analyzed paths are FIXED at construction time and the tools expose
  NO path argument in their JSON schema, so the LLM can never redirect a
  scanner at another artifact.
- An APK's AndroidManifest.xml is BINARY (AXML) and needs aapt or apktool
  to decode. This module never decodes one itself: apk_badging depends on
  `aapt` and degrades gracefully (available() -> False, "`aapt` not found
  on PATH"; APK_BADGING_UNAVAILABLE is the note to surface) when the
  binary is absent, while manifest_audit keeps working on a PRE-DECODED
  manifest with no binary at all.
- android:* flags are read LITERALLY: an absent attribute is reported as
  false, not as the platform default, and the difference is written into
  parse_notes so an operator reviews it by hand instead of the tool
  guessing on their behalf.
- Evidence carries the `scanner:` marker (state.py evidence standard).
  The verdict ladder says exactly what a static artifact proves:
    manifest_audit    confirmed — the manifest itself states the defect
                               (android:debuggable="true", an exported
                               provider with no permission, ...).
    decompile_secrets confirmed — the credential literal is proven by
                               file:line; liveness is NEVER tested (the
                               credential is reported, never used).
                    suspected — heuristic source patterns (a "token = ..."
                               literal) that need a human dataflow review.
    apk_badging       no finding — inventory artifact only.
- Target secrets found in the artifact ARE the finding and stay in the
  evidence; only OUR OWN registered credentials are scrubbed
  (redactor.scrub). Evidence keeps the rule name, the line number and a
  120-character context window, nothing more.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ..redact import redactor
from .base import Tool, ToolError, ToolResult

_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_COMPONENT_KINDS = ("activity", "service", "receiver", "provider")

_MAX_COMPONENT_RECORDS = 25   # one record per exported component, capped
_MAX_SECRET_RECORDS = 50
_MAX_FILES = 2000             # files read per decompile scan
_MAX_FILE_BYTES = 500_000     # larger files are skipped, not truncated
_RAW_CAP = 200_000
_AAPT_TIMEOUT = 300

APK_BADGING_UNAVAILABLE = "apk_badging unavailable (aapt not installed)"

# dangerous permissions worth a review (short names, no package prefix)
_DANGEROUS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "READ_CALL_LOG",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "READ_PHONE_STATE",
}

# exported-component severity ladder (CWE-926: improper export of an
# Android application component)
_COMPONENT_LADDER = {
    "provider": ("high", "CWE-926"),
    "service": ("high", "CWE-926"),
    "receiver": ("medium", "CWE-926"),
    "activity": ("medium", "CWE-926"),
}

# binary payload extensions that carry no reviewable source
_SKIP_EXTS = {"png", "jpg", "jpeg", "gif", "webp", "ico", "so", "dex", "otf",
              "ttf", "mp3", "mp4", "jar", "arsc"}

# (name, pattern, cwe, severity) — pure regex rules, unit-testable
_SECRET_RULES = (
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "CWE-798", "high"),
    ("private-key-block", re.compile(
        r"-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
     "CWE-321", "high"),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
     "CWE-798", "medium"),
    ("hardcoded-credential-literal", re.compile(
        r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*[\"'][^\"']{12,}[\"']"),
     "CWE-798", "medium"),
)
# a pattern-proven credential defect is 'confirmed' (file:line proves it);
# the generic literal rule is a heuristic and stays 'suspected'
_CONFIRMED_RULES = {"aws-access-key-id", "private-key-block", "google-api-key"}

_SECRET_REMEDIATION = {
    "aws-access-key-id": (
        "Rotate the AWS key id in IAM, remove it from the app, and move the "
        "call behind a backend you control — a secret shipped in a client is "
        "a public secret."
    ),
    "private-key-block": (
        "Delete the private key from the artifact, rotate the key pair, and "
        "keep private material on the server side only."
    ),
    "google-api-key": (
        "Restrict the key (API + Android package + signing certificate) in the "
        "Google Cloud console and move the call behind a backend you control."
    ),
    "hardcoded-credential-literal": (
        "Move the literal into a backend or a build-time secret; confirm it "
        "is not a placeholder before treating it as a live credential."
    ),
}


# --------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------

def _local(tag: str) -> str:
    """Local tag name with the namespace stripped."""
    return str(tag).split("}")[-1]


def _attr(el: ET.Element, name: str) -> str | None:
    """Attribute lookup tolerant of the android namespace being absent.

    Handles the namespaced form ({ns}name), the namespace-free form
    (name) and the aapt-style form (android:name).
    """
    for key in ("{%s}%s" % (_ANDROID_NS, name), name, "android:%s" % name):
        val = el.get(key)
        if val is not None:
            return str(val)
    return None


def _bool_attr(el: ET.Element, name: str) -> bool | None:
    """Boolean attribute value, or None when the attribute is absent."""
    raw = _attr(el, name)
    if raw is None:
        return None
    return str(raw).strip().lower() == "true"


def _int_attr(el: ET.Element, name: str) -> int | None:
    """Integer attribute value, or None when absent/unparseable."""
    raw = _attr(el, name)
    if raw is None:
        return None
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


def _short(value: str) -> str:
    """'android.permission.READ_SMS' -> 'READ_SMS'."""
    return str(value or "").rsplit(".", 1)[-1]


def _xml_context(text: str, exc: ET.ParseError) -> str:
    """Short (300 char) context around a malformed manifest."""
    try:
        line = int(getattr(exc, "position", (0, 0))[0] or 0)
    except (TypeError, ValueError, IndexError):
        line = 0
    lines = (text or "").splitlines()
    snippet = lines[line - 1][:300] if 0 < line <= len(lines) else ""
    return (f"manifest XML is malformed at line {line}: {exc}"
            + (f" | context: {snippet}" if snippet else ""))


def _window(line: str, start: int, width: int = 120) -> str:
    """At most `width` characters of the matching line around the match."""
    line = line.rstrip()
    if len(line) <= width:
        return line.strip()
    left = max(0, start - 20)
    return line[left:left + width].strip()


def _record(title: str, severity: str, status: str, cwe: str, target: str,
            evidence: str, remediation: str) -> dict:
    """One finding record (same field set the platform records elsewhere)."""
    return {
        "title": title,
        "severity": severity,
        "status": status,
        "cwe": cwe,
        "target": target,
        "evidence": redactor.scrub(evidence),
        "remediation": remediation,
        "record_source": "mobile",
    }


# --------------------------------------------------------------------------
# manifest parsing
# --------------------------------------------------------------------------

def parse_manifest_xml(text: str) -> dict:
    """Decoded AndroidManifest.xml -> normalized manifest facts.

    Pure function: no file access, no network. Accepts the namespaced
    form, a namespace-free variant and apktool output. A malformed
    document raises ValueError (the tool turns it into a ToolError with a
    short context window).
    """
    try:
        root = ET.fromstring(text or "")
    except ET.ParseError as exc:
        raise ValueError(_xml_context(text, exc)) from exc

    notes: list[str] = []
    if _local(root.tag) != "manifest":
        notes.append(f"root element is <{_local(root.tag)}>, expected <manifest>")

    package = root.get("package") or None
    version = _attr(root, "versionName")
    min_sdk = target_sdk = None
    for child in root:
        if _local(child.tag) == "uses-sdk":
            min_sdk = _int_attr(child, "minSdkVersion")
            target_sdk = _int_attr(child, "targetSdkVersion")
            break

    permissions: list[str] = []
    for child in root:
        tag = _local(child.tag)
        if tag == "uses-permission":
            name = _attr(child, "name")
            if name:
                permissions.append(name)
        elif tag == "uses-permission-sdk-23":
            notes.append("a <uses-permission-sdk-23> variant is present and "
                         "is not counted in the permission list")

    app = next((c for c in root if _local(c.tag) == "application"), None)
    components: list[dict] = []
    entry_point: str | None = None
    if app is None:
        notes.append("no <application> element — component and flag checks "
                     "were skipped")
        flags = {"debuggable": False, "allow_backup": False, "cleartext": False,
                 "test_only": False, "network_security_config": None}
    else:
        flags = {
            "debuggable": _bool_attr(app, "debuggable") or False,
            "allow_backup": _bool_attr(app, "allowBackup") or False,
            "cleartext": _bool_attr(app, "usesCleartextTraffic") or False,
            "test_only": _bool_attr(app, "testOnly") or False,
            "network_security_config": (
                _attr(app, "networkSecurityConfig") is not None),
        }
        if _attr(app, "allowBackup") is None:
            notes.append("android:allowBackup is absent — the platform "
                         "default is true, so review backup exposure by hand")
        if flags["network_security_config"] is False:
            notes.append("no android:networkSecurityConfig — transport "
                         "pinning is not configured")
        if not flags["cleartext"] and target_sdk is not None and target_sdk < 28:
            notes.append("android:usesCleartextTraffic is absent and "
                         "targetSdk < 28 — the platform default permits "
                         "cleartext traffic")
        for child in app:
            kind = _local(child.tag)
            if kind not in _COMPONENT_KINDS:
                continue
            name = _attr(child, "name") or ""
            filters = [f for f in child if _local(f.tag) == "intent-filter"]
            actions: list[str] = []
            categories: list[str] = []
            for filt in filters:
                for sub in filt:
                    sub_name = _attr(sub, "name") or ""
                    if _local(sub.tag) == "action":
                        actions.append(sub_name)
                    elif _local(sub.tag) == "category":
                        categories.append(sub_name)
            exported_raw = _bool_attr(child, "exported")
            has_filter = bool(filters)
            # platform rule: without an explicit android:exported a
            # component is exported only when it declares an intent-filter
            exported = has_filter if exported_raw is None else exported_raw
            main_launcher = ("MAIN" in {_short(a) for a in actions}
                             and "LAUNCHER" in {_short(c) for c in categories})
            if not name:
                notes.append(f"a <{kind}> has no android:name — it is listed "
                             "without an identifier")
            if main_launcher and not entry_point:
                entry_point = name or None
            components.append({
                "kind": kind,
                "name": name,
                "exported": exported,
                "exported_explicit": exported_raw,
                "has_intent_filter": has_filter,
                "permission": _attr(child, "permission"),
                "actions": actions,
                "main_launcher": main_launcher,
            })

    return {
        "package": package,
        "version": version,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": permissions,
        "flags": flags,
        "components": components,
        "entry_point": entry_point,
        "parse_notes": notes,
    }


def exported_component_candidates(parsed: dict) -> list[dict]:
    """Components the exported-component rule may report.

    Exported AND without a permission. The launcher activity is excluded:
    it is expected to be exported, so flagging it would be noise.
    """
    out: list[dict] = []
    for comp in parsed.get("components") or []:
        if not comp.get("exported"):
            continue
        if comp.get("permission"):
            continue
        if comp.get("main_launcher"):
            continue
        out.append(comp)
    return out


def manifest_findings(parsed: dict) -> list[dict]:
    """Deterministic verdict ladder over a parsed manifest.

    Pure function: no file access, no network. Every record carries the
    'scanner:' marker and a target of '{package} (manifest)'. Manifest
    misconfigurations are 'confirmed' (the manifest states the defect);
    heuristic signals (dangerous permissions, an outdated targetSdk) stay
    'suspected'.
    """
    package = str(parsed.get("package") or "unknown-package")
    target = f"{package} (manifest)"
    flags = parsed.get("flags") or {}
    records: list[dict] = []

    if flags.get("debuggable"):
        records.append(_record(
            title=f"Debuggable application build: {package}",
            severity="high", status="confirmed", cwe="CWE-489", target=target,
            evidence=(f"scanner: manifest android:debuggable=true on "
                      f"{package} — debug bridges attachable"),
            remediation=('Set android:debuggable="false" for release builds '
                         "and build from the release template; keep debug "
                         "builds out of the distributed artifact."),
        ))

    if flags.get("test_only"):
        records.append(_record(
            title=f"Test-only build shipped: {package}",
            severity="high", status="confirmed", cwe="CWE-489", target=target,
            evidence=(f"scanner: manifest android:testOnly=true on {package} "
                      "— the artifact is marked test-only"),
            remediation=('Remove android:testOnly="true" from the release '
                         "manifest and ship the production build."),
        ))

    if flags.get("allow_backup"):
        records.append(_record(
            title=f"Application data backup enabled: {package}",
            severity="medium", status="confirmed", cwe="CWE-530", target=target,
            evidence=(f"scanner: manifest android:allowBackup=true on "
                      f"{package} — app data is included in device backups"),
            remediation=('Set android:allowBackup="false" (or an explicit '
                         "data-extraction-rules file that excludes sensitive "
                         "data) for release builds."),
        ))

    if flags.get("cleartext"):
        pinning = ("" if flags.get("network_security_config")
                   else "; no android:networkSecurityConfig pins transport")
        records.append(_record(
            title=f"Cleartext HTTP permitted: {package}",
            severity="medium", status="confirmed", cwe="CWE-319", target=target,
            evidence=(f"scanner: manifest android:usesCleartextTraffic=true on "
                      f"{package} — plaintext HTTP is permitted{pinning}"),
            remediation=('Set android:usesCleartextTraffic="false" and add a '
                         "network security config that pins certificates for "
                         "every host the app talks to."),
        ))

    for comp in exported_component_candidates(parsed)[:_MAX_COMPONENT_RECORDS]:
        kind = str(comp.get("kind") or "component")
        severity, cwe = _COMPONENT_LADDER.get(kind, ("medium", "CWE-926"))
        name = str(comp.get("name") or "<unnamed>")
        actions = ", ".join(comp.get("actions") or []) or "none"
        records.append(_record(
            title=f"Exported {kind} without permission: {name}",
            severity=severity, status="confirmed", cwe=cwe, target=target,
            evidence=(f"scanner: manifest {kind} {name} is exported with no "
                      f"android:permission — intent action(s): {actions}"),
            remediation=(f'Set android:exported="false" on the {kind}, or '
                         'protect it with android:permission="<your '
                         'signature permission>" and validate the caller.'),
        ))

    target_sdk = parsed.get("target_sdk")
    if target_sdk is not None and int(target_sdk) < 26:
        records.append(_record(
            title=f"Outdated platform target: {package} (targetSdk {target_sdk})",
            severity="medium", status="suspected", cwe="CWE-1104", target=target,
            evidence=(f"scanner: manifest android:targetSdkVersion={target_sdk} "
                      f"on {package} — below API 26, so the platform security "
                      "defaults are not enforced"),
            remediation=("Raise android:targetSdkVersion to a current API "
                         "level (26 at minimum) and re-test the behaviour the "
                         "newer defaults change."),
        ))

    dangerous = sorted({_short(p) for p in (parsed.get("permissions") or [])}
                       & _DANGEROUS)
    if dangerous:
        records.append(_record(
            title=f"Dangerous permissions requested: {', '.join(dangerous)}",
            severity="medium", status="suspected", cwe="CWE-255", target=target,
            evidence=(f"scanner: manifest on {package} requests dangerous "
                      f"permission(s): {', '.join(dangerous)} — a permission "
                      "request is not proof of misuse"),
            remediation=("Confirm each permission is needed, drop the unused "
                         "ones, and request dangerous permissions at runtime "
                         "with a user prompt instead of at install time."),
        ))

    return records


# --------------------------------------------------------------------------
# aapt inventory
# --------------------------------------------------------------------------

def _kv(line: str, key: str) -> str | None:
    """Value of a `key='value'` pair in an aapt badging line."""
    match = re.search(r"%s=(?:'([^']*)'|\"([^\"]*)\"|(\S+))" % re.escape(key),
                       line)
    if not match:
        return None
    for group in match.groups():
        if group is not None:
            return group
    return ""


def _quoted_value(line: str) -> str | None:
    """Value of a `key:'value'` line (aapt quotes it with single quotes)."""
    _, _, rest = line.partition(":")
    return rest.strip().strip("'\"").strip() or None


def _as_int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_aapt_badging(text: str) -> dict:
    """`aapt dump badging` output -> normalized APK inventory.

    Pure function: no file access, no network. Missing fields are None
    (never guessed) and SDK versions are coerced to ints.
    """
    package = version = version_code = label = None
    min_sdk = target_sdk = None
    permissions: list[str] = []
    launcher = {"name": None, "label": None, "icon": None}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("package:"):
            package = _kv(line, "name")
            version_code = _kv(line, "versionCode")
            version = _kv(line, "versionName")
        elif line.startswith("targetSdkVersion:"):
            target_sdk = _as_int(_quoted_value(line))
        elif line.startswith("sdkVersion:"):
            min_sdk = _as_int(_quoted_value(line))
        elif line.startswith("uses-permission:"):
            perm = _quoted_value(line)
            if perm:
                permissions.append(perm)
        elif line.startswith("application-label:"):
            label = _quoted_value(line)
        elif line.startswith("launchable-activity:"):
            launcher = {
                "name": _kv(line, "name"),
                "label": _kv(line, "label"),
                "icon": _kv(line, "icon"),
            }
    return {
        "package": package,
        "version": version,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "permissions": permissions,
        "label": label,
        "launcher": launcher,
    }


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------

class ManifestAuditTool(Tool):
    """Static audit of a PRE-DECODED AndroidManifest.xml.

    READ-ONLY: the manifest file is only read. Nothing is installed,
    launched, or pushed, and no device is touched. The manifest path is
    operator-supplied and FIXED at construction — the schema exposes no
    arguments, so the LLM cannot redirect the audit at another artifact.
    The APK's binary AXML manifest must be decoded first (aapt/apktool);
    this tool never decodes one itself.
    """
    name = "manifest_audit"
    description = (
        "Static audit of a FIXED operator-provided, PRE-DECODED "
        "AndroidManifest.xml: debuggable/testOnly builds, backup exposure, "
        "cleartext traffic, exported components without a permission, "
        "outdated targetSdk and dangerous permission requests. Manifest "
        "defects are status 'confirmed' (the manifest states them); "
        "heuristic signals stay 'suspected'. READ-ONLY: the file is read, "
        "nothing is installed or launched, no device is touched. No "
        "arguments: the manifest path is fixed at construction."
    )
    parameters = {"type": "object", "properties": {}}

    def __init__(self, manifest_path: Path):
        self.manifest_path = Path(manifest_path)

    def run(self, args: dict[str, Any]) -> ToolResult:
        path = self.manifest_path
        if not path.is_file():
            raise ToolError(f"decoded manifest not found: {path.name}")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ToolError(f"could not read manifest {path.name}: {exc}") from exc
        try:
            parsed = parse_manifest_xml(text)
        except ValueError as exc:
            raise ToolError(redactor.scrub(
                f"could not parse manifest {path.name}: {exc}")) from exc

        records = manifest_findings(parsed)
        components = parsed.get("components") or []
        exported = sum(1 for c in components if c.get("exported"))
        confirmed = sum(1 for r in records if r["status"] == "confirmed")
        package = parsed.get("package") or "unknown-package"
        data: dict[str, Any] = {
            "package": package,
            "version": parsed.get("version"),
            "min_sdk": parsed.get("min_sdk"),
            "target_sdk": parsed.get("target_sdk"),
            "components_total": len(components),
            "components_exported": exported,
            "permissions": parsed.get("permissions") or [],
            "flags": parsed.get("flags") or {},
            "parse_notes": parsed.get("parse_notes") or [],
            "findings": [{"title": r["title"], "severity": r["severity"],
                          "status": r["status"], "cwe": r["cwe"],
                          "target": r["target"]} for r in records],
            "records": records,
        }
        candidates = exported_component_candidates(parsed)
        component_records = [r for r in records if r["cwe"] == "CWE-926"]
        if len(candidates) > len(component_records):
            data["note"] = (
                f"component findings capped at {len(component_records)} of "
                f"{len(candidates)} exported unprotected components")
        return ToolResult(
            ok=True,
            summary=(f"manifest audit of {package}: {len(records)} findings "
                     f"({confirmed} confirmed)"),
            data=data,
        )


class ApkBadgingTool(Tool):
    """APK inventory via `aapt dump badging`.

    READ-ONLY: aapt only reads the APK file. Nothing is installed or
    launched and no device is touched. The APK path is operator-supplied
    and FIXED at construction — the schema exposes no arguments. When
    `aapt` is missing from PATH the tool degrades gracefully
    (available() -> False); manifest_audit keeps working on a
    pre-decoded manifest.
    """
    name = "apk_badging"
    description = (
        "Inventory of a FIXED operator-provided APK with `aapt dump badging` "
        "(package, version, SDK levels, permissions, launcher activity). "
        "Inventory only: no finding is produced. READ-ONLY: the APK is only "
        "read, never installed or launched, and no device is touched. "
        "Degrades gracefully when aapt is not installed. No arguments: the "
        "APK path is fixed at construction."
    )
    binary = "aapt"
    parameters = {"type": "object", "properties": {}}

    def __init__(self, apk_path: Path):
        self.apk_path = Path(apk_path)

    def run(self, args: dict[str, Any]) -> ToolResult:
        cmd = ["aapt", "dump", "badging", str(self.apk_path)]
        proc = self.shell(cmd, timeout=_AAPT_TIMEOUT)
        stdout = (proc.stdout or "").strip()
        if proc.returncode != 0:
            raise ToolError(f"aapt failed (rc={proc.returncode}): "
                            f"{((proc.stderr or stdout or '')[:300])}")
        info = parse_aapt_badging(stdout)
        package = info.get("package") or "unknown-package"
        version = info.get("version") or "?"
        target = info.get("target_sdk")
        return ToolResult(
            ok=True,
            summary=(f"inventory: {package} v{version} target "
                     f"{target if target is not None else 'unknown'}"),
            data={**info, "permission_count": len(info["permissions"]),
                  "apk": self.apk_path.name},
            raw=stdout[:_RAW_CAP],
        )


class DecompileSecretScanTool(Tool):
    """Hardcoded-credential scan of a DECODED source tree.

    READ-ONLY: files are only read; nothing is compiled, installed, or
    executed, and no device is touched. The directory is
    operator-supplied and FIXED at construction — the schema exposes no
    arguments, so the LLM cannot redirect the scan. A credential literal
    proven by file:line is 'confirmed' (liveness is NEVER tested — the
    credential is reported, never used); the generic "token = ..." rule is
    a heuristic and stays 'suspected'.
    """
    name = "decompile_secrets"
    description = (
        "Hardcoded-credential scan of a FIXED operator-provided decoded "
        "source tree (e.g. apktool output): AWS access key ids, private key "
        "blocks, Google API keys and credential literals. Pattern-proven "
        "matches are status 'confirmed' (file:line) and liveness is never "
        "tested — credentials are reported, never used; generic credential "
        "literals stay 'suspected' pending a dataflow review. READ-ONLY: "
        "files are read only. No arguments: the directory is fixed at "
        "construction."
    )
    parameters = {"type": "object", "properties": {}}

    def __init__(self, decompiled_dir: Path, max_files: int = _MAX_FILES):
        self.decompiled_dir = Path(decompiled_dir)
        self.max_files = max_files

    def _iter_files(self, root: Path, limit: int):
        """Yield candidate text files under root (deterministic order)."""
        count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                if Path(name).suffix.lower().lstrip(".") in _SKIP_EXTS:
                    continue
                path = Path(dirpath) / name
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size > _MAX_FILE_BYTES:
                    continue
                count += 1
                if count > limit:
                    return
                yield path

    def run(self, args: dict[str, Any]) -> ToolResult:
        root = self.decompiled_dir
        if not root.is_dir():
            raise ToolError(f"decompiled directory not found: {root.name}")
        # the constructor may lower the ceiling but never raise it above the
        # module cap (tests patch _MAX_FILES to exercise the cap)
        limit = max(0, min(int(self.max_files), _MAX_FILES))
        files_scanned = 0
        matches: list[dict] = []
        for path in self._iter_files(root, limit):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1
            rel = path.relative_to(root).as_posix()
            for lineno, line in enumerate(text.splitlines(), 1):
                for name, pattern, cwe, severity in _SECRET_RULES:
                    for match in pattern.finditer(line):
                        window = _window(line, match.start())
                        status = ("confirmed" if name in _CONFIRMED_RULES
                                  else "suspected")
                        evidence = (f"scanner: {name} at {rel}:{lineno} — "
                                    f"context: {window}")
                        if status == "confirmed":
                            evidence += (" LIVENESS NOT TESTED: the credential "
                                         "was reported, never used.")
                        matches.append({
                            "rule": name,
                            "file": rel,
                            "line": lineno,
                            "severity": severity,
                            "status": status,
                            "record": _record(
                                title=f"Hardcoded credential ({name}) in {rel}:{lineno}",
                                severity=severity, status=status, cwe=cwe,
                                target=f"{rel}:{lineno}", evidence=evidence,
                                remediation=_SECRET_REMEDIATION.get(
                                    name, "Move the credential out of the "
                                          "artifact and rotate it."),
                            ),
                        })
        records = [m["record"] for m in matches[:_MAX_SECRET_RECORDS]]
        confirmed = sum(1 for r in records if r["status"] == "confirmed")
        data: dict[str, Any] = {
            "files_scanned": files_scanned,
            "findings": len(matches),
            "records": len(records),
            "record_list": records,
        }
        if len(matches) > len(records):
            data["note"] = (f"record cap reached: {len(records)} of "
                            f"{len(matches)} matches are reported")
        if not files_scanned:
            return ToolResult(ok=True, summary=("decompile_secrets: no files "
                                                "scanned"), data=data)
        return ToolResult(
            ok=True,
            summary=(f"decompile_secrets: {len(records)} finding(s) in "
                     f"{files_scanned} file(s) ({confirmed} confirmed)"),
            data=data,
        )
