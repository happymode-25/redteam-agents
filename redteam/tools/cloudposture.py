"""Cloud posture checks (vulnerability catalog section 7).

Two tools, safety rules enforced in CODE, mirroring tools/sca.py:

- bucket_exposure probes ONLY the well-known object-listing URLs of
  organization-name hints FIXED at construction (the hints ARE the
  authorization; the schema takes no arguments). Every URL passes
  Guard.run() (scope + rate limit + kill switch) BEFORE the transport
  exists; only listing GETs are sent — no writes, no credentials, no
  destructive call. Verdicts, decided in code: 'confirmed' (an anonymous
  listing was served -> CWE-200, `response:` evidence), 'no_issue' (denied
  or missing bucket), 'inconclusive' (timeout, bare 403, marker-less 200,
  3xx) — never upgraded, never guessed.
- cloud_posture_report parses a LOCAL report the operator already produced
  with credentials (Prowler v3 / ScoutSuite JSON): the path is fixed at
  construction, no network, no arguments. A failed check and ScoutSuite's
  explicit danger markers are deterministic scanner verdicts -> 'confirmed'
  with `scanner:` evidence; PASS entries and ambiguous structures are
  counted, never recorded. No CVSS is invented; CWE/CVE ids are carried
  only when the report provides them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from ..http import ScopedHttpError, ScopedSession
from ..redact import redactor
from ..scope import Guard
from .base import Tool, ToolError, ToolResult

_RAW_CAP = 200_000     # chars of the source report kept in ToolResult.raw
_BODY_CAP = 100_000    # chars of a listing body read for classification
_EVIDENCE_CAP = 300    # chars of evidence one finding may carry
_KEY_SAMPLE = 5        # max sample object keys quoted in the evidence
_MAX_DEPTH = 10        # ScoutSuite walker depth cap (deep trees terminate)
_MAX_HINT = 63         # a DNS label is at most 63 characters

_HINT_RE = re.compile(r"[a-z0-9-]+")
_XML_KEY_RE = re.compile(r"<Key>([^<]{1,200})</Key>")
_XML_NAME_RE = re.compile(r"<Name>([^<]{1,200})</Name>")
_JSON_KEY_RE = re.compile(r'"name"\s*:\s*"([^"]{1,200})"')

# listing markers only ever appear in a served object listing
_LISTING_MARKERS = ("<Name>", "<Key>", "Contents>", "Blobs>", '"storage#bucket"')
_DENIED_MARKERS = ("AccessDenied", "AuthorizationPermissionDenied")
_MISSING_MARKERS = ("NoSuchBucket", "ContainerNotFound", "BlobNotFound")
_PROWLER_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
                     "low": "low", "informational": "info"}
_PUBLIC_KEYS = ("public", "publicly_accessible")     # ScoutSuite markers
_PUBLIC_TRUE = ("true", "yes", "1")
_PUBLIC_ACLS = ("public-read", "public_read", "publicread", "public-rw",
                "public_rw")


def sanitize_hint(hint: Any) -> str | None:
    """Normalize one operator hint (strip + lower). None when the result is
    not a plain [a-z0-9-] name of DNS-label length: invalid hints are
    SKIPPED, never repaired and never injected into a URL."""
    if not isinstance(hint, str):
        return None
    h = hint.strip().lower()
    if not h or len(h) > _MAX_HINT or not _HINT_RE.fullmatch(h):
        return None
    return h


def storage_urls(hints: list) -> list[tuple[str, str]]:
    """Pure: the (cloud, url) listing-GET candidates of every valid hint.
    Invalid hints contribute nothing."""
    out: list[tuple[str, str]] = []
    for hint in hints:
        h = sanitize_hint(hint)
        if h is None:
            continue
        out += [
            ("aws", f"https://{h}.s3.amazonaws.com/"),
            ("gcp", f"https://storage.googleapis.com/{h}"),
            ("azure", f"https://{h}.blob.core.windows.net/?comp=list"),
        ]
    return out


def _record(title: str, severity: str, target: str, evidence: str,
            remediation: str, cwe: str = "", cves: str = "") -> dict[str, Any]:
    """One confirmed record in the platform's record shape. The CVSS score is
    NEVER invented: an empty string means 'not scored'."""
    return {
        "title": title,
        "severity": severity,
        "status": "confirmed",
        "cwe": cwe,
        "cves": cves,
        "cvss": "",
        "target": target,
        "evidence": redactor.scrub(evidence)[:_EVIDENCE_CAP],
        "remediation": remediation,
    }


def _listing_evidence(target: str, status: int, body: str) -> str:
    """`response:`-marked evidence for a served listing: at most 5 sample
    object keys (S3 keys, then Azure names, then the GCS JSON), never the
    raw body."""
    keys = ([k.strip() for k in _XML_KEY_RE.findall(body)]
            or [k.strip() for k in _XML_NAME_RE.findall(body)]
            or [k.strip() for k in _JSON_KEY_RE.findall(body)])
    sample: list[str] = []
    for key in keys:
        if key and key not in sample:
            sample.append(key[:80])
        if len(sample) >= _KEY_SAMPLE:
            break
    text = f"response: GET {target} status {status} — public object listing"
    if sample:
        text += f" (sample keys: {', '.join(sample)})"
    return redactor.scrub(text)[:_EVIDENCE_CAP]


def _verdict(verdict: str, note: str, severity: str = "", cwe: str = "",
             evidence: str = "") -> dict[str, Any]:
    """One rung of the ladder, in one shape."""
    return {"verdict": verdict, "severity": severity, "cwe": cwe,
            "evidence": evidence, "note": note}


def classify_bucket_response(cloud: str, status: int | None, body: str,
                             url: str = "") -> dict[str, Any]:
    """Pure: one probe response -> {verdict, severity, cwe, evidence, note}.

    Always returns a dict (never None): every response lands on exactly one
    rung of the ladder, so a probe is never silently dropped. An explicit
    deny or not-found answer wins over a stray marker. Listing markers ->
    'confirmed' (high, CWE-200); 403 with a deny code, 404 or a not-found
    code -> 'no_issue'; no response, a bare 403, a marker-less 200 or a 3xx
    -> 'inconclusive'.
    """
    target = url or f"<{cloud}>"
    if status is None:
        return _verdict("inconclusive", redactor.scrub(
            f"no HTTP response (timeout or transport error): "
            f"{str(body or '')[:120]}"))
    text = body or ""
    if status == 403 and any(m in text for m in _DENIED_MARKERS):
        return _verdict("no_issue", "bucket/container exists but the listing "
                                    "is denied (private)")
    if status == 404 or any(m in text for m in _MISSING_MARKERS):
        return _verdict("no_issue", "bucket/container does not exist")
    if any(m in text for m in _LISTING_MARKERS):
        return _verdict(
            "confirmed",
            "anonymous object listing served: object keys are readable "
            "without credentials",
            severity="high", cwe="CWE-200",
            evidence=_listing_evidence(target, status, text))
    return _verdict("inconclusive",
                    f"no listing markers and no explicit deny/missing "
                    f"response (status {status})")


class BucketExposureTool(Tool):
    """READ-ONLY public-storage exposure probe over FIXED operator hints.

    The hints are the authorization: configured at construction, no arguments
    in the schema, so the LLM cannot redirect the probe.
    """

    name = "bucket_exposure"
    description = (
        "Read-only public-storage exposure check: GETs the well-known "
        "object-listing URLs (S3, GCS, Azure Blob) of organization-name "
        "hints FIXED at construction — no arguments, so the LLM cannot aim "
        "it at another name. Every URL passes the scope guard before the "
        "request; only listing GETs are sent. An anonymous object listing "
        "is 'confirmed' (CWE-200); a denied or missing bucket is no-issue; "
        "anything else stays inconclusive."
    )
    parameters = {"type": "object", "properties": {}}

    def __init__(self, guard: Guard, org_hints: list[str], timeout: int = 20):
        self._guard = guard
        self.org_hints = list(org_hints)
        self.timeout = timeout

    def run(self, args: dict[str, Any]) -> ToolResult:
        candidates = storage_urls(self.org_hints)
        skipped = [str(h) for h in self.org_hints if sanitize_hint(h) is None]
        session = None
        buckets: list[dict[str, Any]] = []
        confirmed = 0
        for cloud, url in candidates:
            # scope + rate limit + kill switch BEFORE any transport exists; a
            # ScopeViolation propagates and aborts the whole probe loop.
            self._guard.run(url, lambda: None)
            if session is None:
                session = ScopedSession(self._guard, timeout=self.timeout)
            try:
                resp = session.get(url, timeout=self.timeout,
                                   allow_redirects=False)
                status, body = resp.status_code, (resp.text or "")[:_BODY_CAP]
            except (requests.RequestException, ScopedHttpError, OSError) as exc:
                # a transport error is 'no response', never a verdict
                status, body = None, str(exc)
            cls = classify_bucket_response(cloud, status, body, url)
            entry: dict[str, Any] = {"cloud": cloud, "url": url, **cls}
            if cls["verdict"] == "confirmed":
                confirmed += 1
                entry["record"] = _record(
                    f"Public object listing ({cloud}): {url}", "high", url,
                    cls["evidence"],
                    "Deny anonymous listing: make the bucket/container "
                    "private (block public access, drop public ACL grants), "
                    "then re-run bucket_exposure to confirm the listing now "
                    "returns 403.",
                    cwe="CWE-200")
            buckets.append(entry)
        data: dict[str, Any] = {"buckets": buckets, "probed": len(candidates),
                                "confirmed": confirmed}
        if skipped:
            data["skipped_hints"] = skipped
            data["note"] = (f"{len(skipped)} hint(s) skipped (only plain "
                            "[a-z0-9-] names are allowed) — never injected "
                            "into a URL")
        summary = (f"bucket_exposure: {len(candidates)} storage URL(s) probed, "
                   f"{confirmed} public listing(s) confirmed")
        return ToolResult(ok=True, summary=summary, data=data, raw="")


@dataclass
class CloudPostureInput:
    """The fixed input of cloud_posture_report: a local report path and its
    format, operator-supplied at construction — never an LLM argument, so
    the tool cannot be pointed at another file or another format."""

    report_path: Path
    kind: str  # "prowler" | "scout"

    def __post_init__(self) -> None:
        if self.kind not in ("prowler", "scout"):
            raise ValueError(
                f"unsupported report kind {self.kind!r}: expected 'prowler' "
                f"or 'scout'")
        self.report_path = Path(self.report_path)


def _load_json(text: str, kind: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ToolError(f"{kind} report is not valid JSON: {exc}"[:300]) from exc


def _ids(item: dict, keys: tuple[str, ...]) -> list[str]:
    """Ids the upstream report provides (CWE/CVE are carried, never
    invented)."""
    out: list[str] = []
    for key in keys:
        value = item.get(key)
        if isinstance(value, list):
            out += [str(v) for v in value if v]
        elif isinstance(value, str) and value.strip():
            out.append(value.strip())
    return list(dict.fromkeys(out))


def parse_prowler(text: str) -> list[dict]:
    """Prowler v3 JSON -> one finding per Status == 'FAIL' check.

    A failed check is a deterministic scanner verdict -> the record is
    'confirmed' with `scanner:` evidence. PASS/INCONCISE entries are never
    recorded (prowler_status_counts tallies them for the summary). Severity
    maps directly from the upstream label (informational -> info, unknown
    -> medium); nothing is computed and no CVSS is invented.
    """
    raw = _load_json(text, "prowler")
    findings = raw.get("findings") if isinstance(raw, dict) else None
    if not isinstance(findings, list):
        raise ToolError("unexpected prowler report shape (no 'findings' list)"
                        [:300])
    out: list[dict] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        if str(item.get("Status") or "").strip().upper() != "FAIL":
            continue
        check = str(item.get("CheckID") or "unknown-check")
        raw_sev = str(item.get("Severity") or "").strip().lower()
        severity = _PROWLER_SEVERITY.get(raw_sev, "medium")
        details = item.get("ResourceDetails")
        details = details if isinstance(details, dict) else {}
        resource = str(details.get("ResourceArn") or details.get("ResourceId")
                       or "?")
        title = str(item.get("CheckTitle") or check)[:300]
        cwe = (_ids(item, ("CWEs", "CWE")) or [""])[0][:50]
        cves = ",".join(_ids(item, ("CVEs", "CVE")))[:200]
        rec = item.get("Remediation")
        rec = rec.get("Recommendation") if isinstance(rec, dict) else None
        rec = rec.get("Text") if isinstance(rec, dict) else None
        remediation = str(rec or "Fix the resource configuration per the "
                                 "Prowler check.")[:400]
        out.append({
            "check_id": check,
            "service": str(item.get("ServiceName") or ""),
            "severity": severity,
            "resource": resource,
            "title": title,
            "cwe": cwe,
            "cves": cves,
            "record": _record(
                f"Cloud misconfiguration: {check} on {resource}", severity,
                resource,
                f"scanner: prowler {check} FAIL ({raw_sev or severity}) on "
                f"{resource} — {title}",
                remediation, cwe=cwe, cves=cves),
        })
    return out


def prowler_status_counts(text: str) -> dict[str, int]:
    """Pure Status tally (FAIL/PASS/INCONCISE/...) for the tool summary:
    only FAIL becomes a finding, every other status is counted."""
    raw = _load_json(text, "prowler")
    findings = raw.get("findings") if isinstance(raw, dict) else None
    counts: dict[str, int] = {}
    for item in findings if isinstance(findings, list) else []:
        key = (str(item.get("Status") or "UNKNOWN").upper()
               if isinstance(item, dict) else "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _is_public(value: Any, acl: bool = False) -> bool:
    """Truthy public marker: a real True, an explicit true-ish string or 1
    (False, 'private', 'no' are not public). An ACL counts only when it is
    one of the public-read variants."""
    if acl:
        return isinstance(value, str) and value.strip().lower() in _PUBLIC_ACLS
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _PUBLIC_TRUE
    if isinstance(value, (int, float)):
        return value == 1
    return False


def _scout_marker(node: dict) -> tuple[str, str] | None:
    """(marker, severity) of an EXPLICIT danger marker in this node, else
    None: level == 'dangerous', a truthy public / publicly_accessible flag,
    or a public-read ACL."""
    level = node.get("level")
    if isinstance(level, str) and level.strip().lower() == "dangerous":
        return "level=dangerous", "high"   # the scanner's own grade
    for key in _PUBLIC_KEYS:
        if key in node and _is_public(node[key]):
            return f"{key}={node[key]}", "medium"
    if "acl" in node and _is_public(node["acl"], acl=True):
        return f"acl={node['acl']}", "medium"
    return None


def _scout_ambiguous(node: dict) -> bool:
    """True for a structure the conservative rule refuses to guess at: a
    level that is not 'dangerous' or a public-ish key whose value cannot be
    evaluated. Ambiguity is COUNTED, never turned into a finding."""
    if "level" in node:
        level = node.get("level")
        if not (isinstance(level, str)
                and level.strip().lower() == "dangerous"):
            return True
    for key in _PUBLIC_KEYS + ("acl",):
        if isinstance(node.get(key), (dict, list)):
            return True
    return False


def _scout_finding(path: tuple[str, ...], marker: tuple[str, str]) -> dict:
    marker_text, severity = marker
    where = "/".join(path) or "(root)"
    return {
        "path": where,
        "marker": marker_text,
        "severity": severity,
        "record": _record(
            f"Cloud posture danger: {marker_text} at {where}", severity, where,
            f"scanner: scoutsuite flagged {marker_text} at {where} — "
            "explicit danger marker in the operator's scanner report (local "
            "parse; the cloud was not re-checked this run)",
            "Review the resource at this path and remove the public or "
            "dangerous configuration (least privilege, private ACLs, scoped "
            "access), then re-run the posture scanner to confirm the marker "
            "is gone."),
    }


def _walk_scout(node: Any, path: tuple[str, ...], depth: int):
    """Generator of ('finding', payload) / ('ambiguous', path) events."""
    if isinstance(node, dict):
        marker = _scout_marker(node)
        ambiguous = False
        if marker is not None:
            yield "finding", _scout_finding(path, marker)
        else:
            ambiguous = _scout_ambiguous(node)
            if ambiguous:
                yield "ambiguous", path
        if depth >= _MAX_DEPTH:
            if node and not ambiguous:
                yield "ambiguous", path   # subtree truncated at the cap
            return
        for key, child in node.items():
            yield from _walk_scout(child, path + (str(key),), depth + 1)
    elif isinstance(node, list):
        if depth >= _MAX_DEPTH:
            if node:
                yield "ambiguous", path
            return
        for idx, child in enumerate(node):
            yield from _walk_scout(child, path + (f"[{idx}]",), depth + 1)


def walk_scoutsuite(node: Any, path: tuple[str, ...] = (),
                    depth: int = 0) -> list[dict]:
    """Pure recursive walker over a parsed ScoutSuite report: EXPLICIT danger
    markers only. Conservative = fewer, higher-confidence findings — a
    structure the rule cannot evaluate is counted, never guessed. The depth
    is capped at _MAX_DEPTH so a pathological report terminates."""
    return [payload for kind, payload in _walk_scout(node, tuple(path), depth)
            if kind == "finding"]


def scout_unparsed_count(node: Any, path: tuple[str, ...] = (),
                         depth: int = 0) -> int:
    """Pure count of the structures the conservative rule did NOT turn into a
    finding (non-danger levels, un-evaluable shapes, depth truncation)."""
    return sum(1 for kind, _ in _walk_scout(node, tuple(path), depth)
               if kind == "ambiguous")


def parse_scoutsuite(text: str) -> list[dict]:
    """ScoutSuite JSON -> conservative danger findings via walk_scoutsuite."""
    raw = _load_json(text, "scout")
    if not isinstance(raw, dict):
        raise ToolError(f"unexpected scout report shape: {type(raw).__name__}"
                        [:300])
    return walk_scoutsuite(raw)


def scout_unparsed(text: str) -> int:
    """Pure count of the ambiguous structures of a ScoutSuite report."""
    raw = _load_json(text, "scout")
    if not isinstance(raw, dict):
        raise ToolError(f"unexpected scout report shape: {type(raw).__name__}"
                        [:300])
    return scout_unparsed_count(raw)


class CloudPostureReportTool(Tool):
    """Parse an operator-produced cloud posture report — LOCAL FILE ONLY.

    The report path and format are fixed at construction, so the tool reads
    one file the operator already generated with their own credentials: no
    network, no credential use, no arguments.
    """

    name = "cloud_posture_report"
    description = (
        "Parse a cloud posture report the operator already produced with "
        "credentials (Prowler v3 JSON or ScoutSuite JSON) from a local path "
        "FIXED at construction — no arguments, no network, no credentials: "
        "the tool only reads and parses a file. Failed checks and explicit "
        "danger markers become 'confirmed' records with scanner: evidence; "
        "PASS entries and ambiguous structures are counted, never recorded."
    )
    parameters = {"type": "object", "properties": {}}

    def __init__(self, report_path: Path, kind: str):
        self.source = CloudPostureInput(Path(report_path), kind)

    def run(self, args: dict[str, Any]) -> ToolResult:
        src = self.source
        try:
            text = src.report_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ToolError(
                f"cannot read {src.kind} report {src.report_path}: {exc}"[:300]
            ) from exc
        if not text.strip():
            raise ToolError(f"{src.kind} report is empty: {src.report_path}"
                            [:300])

        if src.kind == "prowler":
            findings = parse_prowler(text)
            counts = prowler_status_counts(text)
            passed = counts.get("PASS", 0)
            other = sum(v for k, v in counts.items() if k not in ("FAIL", "PASS"))
            summary = (f"cloud_posture_report (prowler): {len(findings)} "
                       f"failed check(s) recorded; {passed} passed, {other} "
                       "inconclusive skipped" if findings else
                       f"cloud_posture_report (prowler): no failed checks "
                       f"({passed} passed, {other} inconclusive)")
            data: dict[str, Any] = {"count": len(findings), "findings": findings,
                                    "status_counts": counts,
                                    "report_kind": "prowler"}
        else:
            findings = parse_scoutsuite(text)
            unparsed = scout_unparsed(text)
            summary = (f"cloud_posture_report (scout): {len(findings)} explicit "
                       f"danger finding(s); {unparsed} ambiguous structure(s) "
                       "left unparsed")
            data = {"count": len(findings), "findings": findings,
                    "unparsed": unparsed, "report_kind": "scout"}
        return ToolResult(ok=True, summary=summary, data=data,
                          raw=redactor.scrub(text[:_RAW_CAP]))
