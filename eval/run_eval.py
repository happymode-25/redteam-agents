#!/usr/bin/env python3
"""Eval runner: run the pipeline against a golden target and score it
against ground truth. Produces a JSON scorecard with recall, precision
candidates, missed truths, and call/cost stats.

Usage:
  # lab must be up (Docker-free, loopback only):
  #   python lab/vulnserver.py            # or docker compose for juice-shop
  python eval/run_eval.py --config config.yaml --target lab --mode record
  python eval/run_eval.py --config config.yaml --target lab --mode replay

The process-level egress firewall (redteam.egress) wraps the run exactly
like run_pipeline/run_repo_scan do: install before the Orchestrator,
uninstall in finally.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import replace
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

from redteam.config import ScopeConfig, load_config
from redteam.egress import EgressFirewall
from redteam.orchestrator import Orchestrator
from redteam.scope import ScopeViolation


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Score a pipeline run against ground truth")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--targets", default=str(Path(__file__).parent / "targets.yaml"))
    p.add_argument("--target", required=True, help="Target name from targets.yaml")
    p.add_argument("--mode", choices=["live", "record", "replay"], default="live")
    p.add_argument("--allow-active", action="store_true")
    p.add_argument("--yes", action="store_true")
    return p.parse_args()


def load_target(path: Path, name: str) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    targets = data.get("targets") or {}
    if name not in targets:
        available = ", ".join(targets) or "(none)"
        raise SystemExit(f"target '{name}' not found in {path}; available: {available}")
    return targets[name]


def score(findings: list[dict], truth: list[dict]) -> dict:
    matched_truth: set[int] = set()
    rows = []
    for f in findings:
        blob = f"{f.get('title', '')} {f.get('target', '')} {f.get('evidence', '')}"
        hit_idx = None
        for idx, t in enumerate(truth):
            if any(re.search(pattern, blob, re.IGNORECASE) for pattern in t.get("match", [])):
                hit_idx = idx
                break
        if hit_idx is not None:
            matched_truth.add(hit_idx)
        rows.append({
            "finding": f.get("id"),
            "title": f.get("title", "")[:90],
            "severity": f.get("severity"),
            "status": f.get("status"),
            "matched_truth": truth[hit_idx]["id"] if hit_idx is not None else None,
        })

    total_truth = len(truth)
    recall = len(matched_truth) / total_truth if total_truth else 0.0
    tp = sum(1 for r in rows if r["matched_truth"])
    precision = tp / len(rows) if rows else None
    fp_candidates = [r for r in rows if not r["matched_truth"] and r["status"] == "confirmed"]
    missed = [truth[i]["id"] for i in range(total_truth) if i not in matched_truth]

    return {
        "recall": round(recall, 3),
        "precision_candidate": round(precision, 3) if precision is not None else None,
        "truth_items": total_truth,
        "truth_matched": len(matched_truth),
        "findings_total": len(rows),
        "findings_matched": tp,
        "false_positive_candidates": fp_candidates,
        "missed_truth": missed,
        "per_finding": rows,
    }


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    target = load_target(Path(args.targets), args.target)

    scope = ScopeConfig(
        allow_domains=[d.lower() for d in target.get("scope", {}).get("allow_domains", [])],
        allow_cidrs=list(target.get("scope", {}).get("allow_cidrs", [])),
        allow_subdomains=bool(target.get("scope", {}).get("allow_subdomains", True)),
        allow_private=bool(target.get("scope", {}).get("allow_private", False)),
        rate_limit_per_host_per_min=int(
            target.get("scope", {}).get("rate_limit_per_host_per_min", 60)),
    )
    eval_artifacts = Path("artifacts") / "eval" / args.target
    cfg = replace(cfg, scope=scope,
                  safety=replace(cfg.safety, artifacts_dir=str(eval_artifacts)))

    # scope is final now — install the process-level egress allowlist on the
    # same policy the tools' ScopeGuard enforces.
    try:
        firewall = EgressFirewall.from_config(cfg)
        firewall.install()
    except ScopeViolation as exc:
        print(f"Egress firewall setup error: {exc}", file=sys.stderr)
        return 2
    try:
        orch = Orchestrator(cfg, allow_active=args.allow_active,
                            auto_yes=args.yes, mode=args.mode)
        firewall.audit = orch.audit
        print(firewall.describe())
        report_path = orch.run(target["url"])

        scorecard = {
            "target": args.target,
            "url": target["url"],
            "mode": args.mode,
            "ts": datetime.now().isoformat(),
            "stats": orch.fixtures.counts,
            "score": score([f.__dict__ for f in orch.state.sorted_findings()],
                           target.get("truth", [])),
        }

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        scorecard_path = eval_artifacts / f"eval-{args.target}-{stamp}.json"
        scorecard_path.parent.mkdir(parents=True, exist_ok=True)
        scorecard_path.write_text(json.dumps(scorecard, indent=2),
                                  encoding="utf-8")

        s = scorecard["score"]
        print("\n=== EVAL SCORECARD ===")
        print(f"target:    {args.target} ({target['url']})  mode={args.mode}")
        print(f"recall:    {s['truth_matched']}/{s['truth_items']} = {s['recall']:.0%}")
        print(f"precision: {s['findings_matched']}/{s['findings_total']} findings match truth"
              + (f" (candidate precision {s['precision_candidate']:.0%})"
                 if s["precision_candidate"] is not None else ""))
        if s["missed_truth"]:
            print(f"missed:    {', '.join(s['missed_truth'])}")
        if s["false_positive_candidates"]:
            print(f"FP candidates (confirmed, unmatched): "
                  f"{len(s['false_positive_candidates'])}")
        print(f"calls:     {orch.fixtures.counts}")
        print(f"report:    {report_path}")
        print(f"scorecard: {scorecard_path}")
        return 0
    finally:
        firewall.uninstall()


if __name__ == "__main__":
    raise SystemExit(main())
