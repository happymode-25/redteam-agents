"""Per-run token budget and cost governance (Phase 4).

Token counts here are ESTIMATES (characters / 4). Both backends expose some
usage metadata, but not consistently; the purpose of this module is a hard
ceiling on how much work a run can perform, not billing-grade accounting.
The estimate is deliberately conservative on the high side for ASCII payloads
and is reported as "approx/" with a tilde everywhere so nobody mistakes it
for a bill.

When the budget is exhausted:
  * on_exhausted='stop'      -> BudgetExceeded propagates, the run stops and
                               writes a partial report (honest, bounded);
  * on_exhausted='downgrade' -> the role that hit the limit is switched to
                               the local backend and becomes exempt from
                               further checks for the rest of the run (the
                               cheap tier finishes the work, the report
                               footer records the downgrade). A role that is
                               already on the local backend has nothing
                               cheaper to fall back to and raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class BudgetExceeded(RuntimeError):
    """The configured token budget for the run (or a role) is exhausted."""


@dataclass
class BudgetConfig:
    max_total_tokens: int = 0          # 0 = unlimited
    per_role: dict[str, int] = field(default_factory=dict)  # role -> limit
    on_exhausted: str = "stop"         # stop | downgrade


def estimate_tokens(system: str, messages: list[dict], reply: str = "") -> int:
    """~ tokens for one completion call (prompt + reply)."""
    chars = len(system or "")
    chars += sum(len(str(m.get("content", ""))) for m in messages)
    chars += len(reply or "")
    return max(1, chars // 4)


class TokenBudget:
    def __init__(self, cfg: BudgetConfig | None = None):
        self.cfg = cfg or BudgetConfig()
        if self.cfg.max_total_tokens < 0:
            raise ValueError("budget.max_total_tokens must be >= 0")
        for role, limit in self.cfg.per_role.items():
            if int(limit) < 0:
                raise ValueError(f"budget.per_role[{role}] must be >= 0")
        if self.cfg.on_exhausted not in ("stop", "downgrade"):
            raise ValueError(
                f"budget.on_exhausted must be stop|downgrade, "
                f"got {self.cfg.on_exhausted!r}")
        self.used_total = 0
        self.used_role: dict[str, int] = {}
        self.exempt: set[str] = set()     # roles allowed to run past the
                                          # budget after an explicit downgrade

    # --- enforcement -------------------------------------------------------
    def check(self, role: str) -> None:
        """Raise BudgetExceeded before a call that would exceed the budget.
        Exempt roles (explicit downgrades) are allowed to continue."""
        if role in self.exempt:
            return
        limit = self.cfg.max_total_tokens
        if limit and self.used_total >= limit:
            raise BudgetExceeded(
                f"run token budget exhausted "
                f"(~{self.used_total} used of {limit})")
        role_limit = self.cfg.per_role.get(role)
        if role_limit and self.used_role.get(role, 0) >= role_limit:
            raise BudgetExceeded(
                f"role '{role}' token budget exhausted "
                f"(~{self.used_role.get(role, 0)} used of {role_limit})")

    def charge(self, role: str, tokens: int) -> None:
        self.used_total += max(0, int(tokens))
        self.used_role[role] = self.used_role.get(role, 0) + max(0, int(tokens))

    def note_downgrade(self, role: str) -> None:
        self.exempt.add(role)

    # --- reporting ---------------------------------------------------------
    def totals(self) -> dict[str, Any]:
        return {
            "estimated_tokens_total": self.used_total,
            "estimated_tokens_per_role": dict(self.used_role),
            "limit_total": self.cfg.max_total_tokens,
            "limit_per_role": dict(self.cfg.per_role),
            "on_exhausted": self.cfg.on_exhausted,
            "downgrades": sorted(self.exempt),
        }

    def describe(self) -> str:
        limit = self.cfg.max_total_tokens
        head = (f"token budget: ~{self.used_total} used"
                + (f" / {limit}" if limit else " (no total limit)"))
        roles = ", ".join(f"{r}~{n}" for r, n in sorted(self.used_role.items()))
        if not roles:
            roles = "no completions yet"
        extra = (f"; downgraded to local: {', '.join(sorted(self.exempt))}"
                 if self.exempt else "")
        return f"{head}; per role: {roles}{extra}"


def format_usage(usage: dict[str, int] | None, budget: TokenBudget | None = None) -> str:
    """One-line report footer for estimated LLM usage (or '')."""
    if budget is not None:
        return budget.describe()
    if not usage:
        return ""
    total = usage.get("total", sum(usage.values()))
    roles = ", ".join(f"{r}~{n}" for r, n in sorted(usage.items()) if r != "total")
    return f"LLM usage (estimated tokens): total~{total}" + (f"; {roles}" if roles else "")
