#!/usr/bin/env python3
"""redteam-agents CLI.

Usage:
  python main.py --target example.com --config config.yaml
  python main.py --target example.com --config config.yaml --allow-active
  python main.py --target 10.0.0.0/24 --config config.yaml --allow-active --yes
  python main.py --repo /path/to/checkout --config config.yaml   # Repo/SCA mode
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from redteam.config import load_config
from redteam.orchestrator import run_pipeline
from redteam.repo import run_repo_scan
from redteam.tools.base import ToolRegistry
from redteam.tools import (
    HttpRequestTool, HttpxTool, NmapTool, NucleiTool, RecordFindingTool, SubfinderTool,
)
from redteam.tools.sca import (
    DepScanTool, IacScanTool, SastScanTool, SbomBuildTool, SecretScanTool,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Multi-agent autonomous red team assessment")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--target",
                        help="Primary target: domain, URL, host, or CIDR (must be in scope)")
    target.add_argument("--repo", metavar="PATH",
                        help="Repo/SCA mode: assess a local repository checkout instead "
                             "of a live target (offline scanners, no target traffic)")
    p.add_argument("--config", default="config.yaml", help="Path to config file")
    p.add_argument("--allow-active", action="store_true",
                   help="Enable the active verification stage (human-gated PoC requests)")
    p.add_argument("--yes", action="store_true",
                   help="Auto-approve active verification requests (scripted/authorized runs only)")
    p.add_argument("--goal", default="full-scope assessment: network surface + web application",
                   help="Engagement goal passed to the planner")
    p.add_argument("--mode", choices=["live", "record", "replay"], default=None,
                   help="Override safety.mode: live normal, record stores cassettes, "
                        "replay runs fully offline from cassettes")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        example = config_path.parent / "config.example.yaml"
        hint = f" Copy {example} to {config_path} and edit it." if example.exists() else ""
        print(f"Config not found: {config_path}.{hint}", file=sys.stderr)
        return 1

    cfg = load_config(config_path)

    if args.yes and not args.allow_active:
        print("--yes has no effect without --allow-active", file=sys.stderr)

    if args.repo:
        return _main_repo(cfg, args)

    # Tool availability preflight — warn early, degrade gracefully later.
    registry = ToolRegistry([SubfinderTool(), HttpxTool(), NmapTool(), NucleiTool()])
    for tool in registry.available_tools():
        pass
    missing = [t.name for t in [SubfinderTool(), HttpxTool(), NmapTool(), NucleiTool()]
               if not t.available()[0]]
    if missing:
        print(f"Note: tools not found on PATH, agents will work around them: "
              f"{', '.join(missing)}", file=sys.stderr)

    print(f"Target:  {args.target}")
    print(f"Mode:    {args.mode or cfg.safety.mode}")
    print(f"Scope:   domains={cfg.scope.allow_domains} cidrs={cfg.scope.allow_cidrs} "
          f"private={'allowed' if cfg.scope.allow_private else 'blocked'}")
    print(f"Models:  hosted={cfg.llm.hosted.model} local={cfg.llm.local.model}")
    print(f"Active:  {'ON (human-gated)' if args.allow_active else 'OFF'}")
    print()

    report_path = run_pipeline(cfg, args.target, args.allow_active, args.yes,
                               mode=args.mode)

    print(f"\nReport:  {report_path}")
    print(f"Details: {Path(cfg.safety.artifacts_dir).resolve()}")
    return 0


def _main_repo(cfg, args) -> int:
    """Repo/SCA mode: local checkout, offline scanners, no target traffic."""
    root = Path(args.repo)
    if not root.exists() or not root.is_dir():
        print(f"Repo root is not a directory: {root}", file=sys.stderr)
        return 1

    missing = [b for b in ("syft", "gitleaks", "osv-scanner", "semgrep", "checkov")
               if not shutil.which(b)]
    if missing:
        print(f"Note: scanners not found on PATH, the coverage matrix will say so: "
              f"{', '.join(missing)}", file=sys.stderr)

    print(f"Repo:    {root.resolve()}")
    print(f"Mode:    {args.mode or cfg.safety.mode} (repo/SCA — local checkout)")
    print(f"Scope:   repo allowlist={cfg.repo.path_allowlist or 'any path (operator CLI is the authorization)'}")
    print(f"OSV:     {'online — package names+versions go to the OSV API' if cfg.repo.osv_online else 'offline local OSV database'}")
    print(f"Models:  hosted={cfg.llm.hosted.model} local={cfg.llm.local.model}")
    print()

    try:
        report_path = run_repo_scan(cfg, root, mode=args.mode)
    except ValueError as exc:
        print(f"Repo scan error: {exc}", file=sys.stderr)
        return 1

    print(f"\nReport:  {report_path}")
    print(f"Details: {Path(cfg.safety.artifacts_dir).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
