"""CVE intelligence: NVD lookup + EPSS exploit probability + CISA KEV flag.

IMPORTANT PRIVACY NOTE: this tool calls THIRD-PARTY APIs (NVD, first.org,
CISA) with product/version keywords derived from the target. Those vendors
see the keywords. Disable with `intel.enabled: false` for engagements where
target fingerprints must not leave the machine (the local model still
handles everything else).

Intel responses are cached on disk (default 24h) to respect public rate
limits — NVD allows ~5 req/30s without an API key; we make one query per
tool call and sleep between calls.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from ..config import IntelConfig
from .base import Tool, ToolError, ToolResult

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
EPSS_ENDPOINT = "https://api.first.org/data/v1/epss"


def _map_cve(vuln: dict) -> dict | None:
    cve = vuln.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    metrics = cve.get("metrics") or {}
    score = vector = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData") or {}
            score = data.get("baseScore") or arr[0].get("baseScore")
            vector = data.get("vectorString") or arr[0].get("vectorString")
            break
    weaknesses = [
        w.get("value")
        for w in (cve.get("weaknesses") or [])
        for w in w.get("description", [])
        if w.get("value", "").startswith("CWE-")
    ]
    return {
        "cve": cve_id,
        "cvss": score,
        "cvss_vector": vector,
        "cwes": sorted(set(weaknesses))[:5],
        "published": cve.get("published", "")[:10],
        "summary": desc[:400],
        "kev": False,
        "epss": None,
    }


class CveLookupTool(Tool):
    name = "cve_lookup"
    description = (
        "Look up known CVEs for a fingerprinted product/vendor/version: NVD "
        "matching with CVSS, exploitation probability (EPSS), and CISA "
        "Known Exploited Vulnerabilities status. Use after nmap -sV or web "
        "tech detection surfaces a concrete version. Uses third-party "
        "intel APIs unless intel.enabled is false."
    )
    parameters = {
        "type": "object",
        "properties": {
            "product": {"type": "string", "description": "Product name, e.g. 'openssh'"},
            "version": {"type": "string", "description": "Version string, e.g. '8.4p1'"},
            "vendor": {"type": "string", "description": "Optional vendor name"},
            "max_results": {"type": "integer", "description": "Cap results, default 5"},
        },
        "required": ["product"],
    }

    def __init__(self, intel: IntelConfig, cache_dir: Path):
        self.intel = intel
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # --- cached feeds ---------------------------------------------------------
    def _cache_fresh(self, path: Path) -> bool:
        if not path.exists():
            return False
        age = datetime.now(timezone.utc).timestamp() - path.stat().st_mtime
        return age < self.intel.cache_ttl_hours * 3600

    def _kev_map(self) -> dict[str, dict]:
        path = self.cache_dir / "kev.json"
        if self._cache_fresh(path):
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        try:
            resp = requests.get(KEV_FEED, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            raise ToolError(f"CISA KEV feed unavailable: {exc}") from exc
        mapping = {
            v.get("cveID"): {
                "dueDate": v.get("dueDate"),
                "ransomware": v.get("ransomwareCampaignUse", "") == "Known",
            }
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        }
        path.write_text(json.dumps(mapping), encoding="utf-8")
        return mapping

    def _epss_map(self, cve_ids: list[str]) -> dict[str, dict]:
        if not cve_ids:
            return {}
        digest = hashlib.sha1(",".join(sorted(cve_ids)).encode()).hexdigest()[:16]
        path = self.cache_dir / f"epss-{digest}.json"
        if self._cache_fresh(path):
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        try:
            resp = requests.get(EPSS_ENDPOINT, params={"cve": ",".join(cve_ids)}, timeout=30)
            resp.raise_for_status()
            rows = resp.json().get("data", [])
        except (requests.RequestException, ValueError) as exc:
            raise ToolError(f"EPSS API unavailable: {exc}") from exc
        mapping = {
            r.get("cve"): {"epss": r.get("epss"), "percentile": r.get("percentile")}
            for r in rows if r.get("cve")
        }
        path.write_text(json.dumps(mapping), encoding="utf-8")
        return mapping

    # --- tool ----------------------------------------------------------------
    def run(self, args: dict[str, Any]) -> ToolResult:
        if not self.intel.enabled:
            return ToolResult(
                ok=True,
                summary="CVE intel lookups disabled (intel.enabled: false) — "
                        "no third-party API calls made",
                data={"disabled": True},
            )

        product = str(args["product"]).strip()
        version = str(args.get("version") or "").strip()
        vendor = str(args.get("vendor") or "").strip()
        max_results = max(1, min(int(args.get("max_results") or 5), 20))
        keyword = " ".join(p for p in (vendor, product, version) if p)

        headers = {}
        api_key_env = self.intel.nvd_api_key_env
        if api_key_env:
            key = os.environ.get(api_key_env, "")
            if key:
                headers["apiKey"] = key

        try:
            resp = requests.get(
                NVD_ENDPOINT,
                params={"keywordSearch": keyword, "resultsPerPage": 10},
                headers=headers,
                timeout=45,
            )
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            raise ToolError(f"NVD lookup failed for '{keyword}': {exc}") from exc
        time.sleep(1)  # be polite to the public NVD rate limit

        matches = [m for m in (_map_cve(v) for v in data.get("vulnerabilities", [])) if m]
        matches = matches[:max_results]
        if not matches:
            return ToolResult(
                ok=True,
                summary=f"no CVE matches in NVD for '{keyword}'",
                data={"keyword": keyword, "total_available": data.get("totalResults", 0)},
            )

        try:
            kev = self._kev_map()
        except ToolError:
            kev = {}  # degrade: report without KEV flags
        try:
            epss = self._epss_map([m["cve"] for m in matches])
        except ToolError:
            epss = {}

        for m in matches:
            m["kev"] = m["cve"] in kev
            if m["cve"] in kev:
                m["kev_detail"] = kev[m["cve"]]
            if m["cve"] in epss:
                m["epss"] = epss[m["cve"]]

        kev_count = sum(1 for m in matches if m["kev"])
        summary = (
            f"'{keyword}': {len(matches)} CVE match(es) "
            f"({kev_count} in CISA KEV)"
        )
        return ToolResult(ok=True, summary=summary,
                          data={"keyword": keyword, "matches": matches})
