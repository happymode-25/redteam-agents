"""Hybrid LLM access layer.

Two backends (hosted API, local Ollama) behind one interface. The Router
dispatches per agent role so triage stays local while planning runs hosted.
Both backends are called through plain HTTP (requests) — no SDK dependency —
so any OpenAI-compatible endpoint works.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

import requests

from .budget import BudgetExceeded, TokenBudget, estimate_tokens
from .config import LLMConfig, ProviderConfig, resolve_api_key


class LLMError(Exception):
    pass


class Provider(ABC):
    model: str = ""

    @abstractmethod
    def complete(self, system: str, messages: list[dict]) -> str:
        """messages: [{"role": "user"|"assistant", "content": str}, ...]"""


class OpenAICompatProvider(Provider):
    def __init__(self, cfg: ProviderConfig):
        self.base_url = cfg.base_url
        self.api_key = resolve_api_key(cfg)
        self.model = cfg.model
        self.timeout = cfg.timeout
        self.max_tokens = cfg.max_tokens

    def complete(self, system: str, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "temperature": 0.1,
        }
        if self.max_tokens:
            payload["max_tokens"] = self.max_tokens
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"] or ""
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"OpenAI-compatible call to {self.base_url} failed: {exc}") from exc


class AnthropicProvider(Provider):
    def __init__(self, cfg: ProviderConfig):
        self.base_url = cfg.base_url or "https://api.anthropic.com"
        self.api_key = resolve_api_key(cfg)
        self.model = cfg.model
        self.timeout = cfg.timeout
        self.max_tokens = cfg.max_tokens

    def complete(self, system: str, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "system": system,
            "messages": messages,
            "max_tokens": self.max_tokens or 4096,
            "temperature": 0.1,
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        try:
            resp = requests.post(
                f"{self.base_url}/v1/messages",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return "".join(
                block.get("text", "") for block in data.get("content", [])
                if block.get("type") == "text"
            )
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise LLMError(f"Anthropic call to {self.base_url} failed: {exc}") from exc


def build_provider(cfg: ProviderConfig) -> Provider:
    if cfg.provider == "openai_compatible":
        return OpenAICompatProvider(cfg)
    if cfg.provider == "anthropic":
        return AnthropicProvider(cfg)
    raise ValueError(f"unknown provider type: {cfg.provider}")


class MeteredProvider(Provider):
    """Per-role proxy: enforces the run token budget and records usage.

    Tokens are ESTIMATED (chars/4) rather than taken from provider metadata:
    not every backend reports usage consistently, and the goal is a hard work
    ceiling, not billing-grade accounting. When the budget is exhausted a
    hosted role can be downgraded to the local backend (on_exhausted=
    'downgrade'); a role already on the local backend raises, because there
    is nothing cheaper to fall back to.
    """

    def __init__(self, role: str, inner: Provider, router: "Router"):
        self.role = role
        self._inner = inner
        self._router = router

    @property
    def model(self) -> str:
        return self._inner.model

    def complete(self, system: str, messages: list[dict]) -> str:
        budget = self._router.budget
        if budget is not None:
            try:
                budget.check(self.role)
            except BudgetExceeded:
                if budget.cfg.on_exhausted != "downgrade":
                    raise
                downgraded = self._router.downgrade(self.role)
                if downgraded is None:
                    raise
                self._inner = downgraded
                budget.note_downgrade(self.role)
        text = self._inner.complete(system, messages)
        tokens = estimate_tokens(system, messages, text)
        self._router.record_usage(self.role, tokens)
        if budget is not None:
            budget.charge(self.role, tokens)
        return text


class Router:
    """Dispatches each agent role to its configured backend."""

    def __init__(self, cfg: LLMConfig, wrap=None,
                 budget: TokenBudget | None = None):
        """wrap: optional callable applied to every built provider
        (used by the fixture layer to record/replay LLM calls)."""
        hosted = build_provider(cfg.hosted)
        local = build_provider(cfg.local)
        if wrap is not None:
            hosted, local = wrap(hosted), wrap(local)
        self._backends = {"hosted": hosted, "local": local}
        self._roles = dict(cfg.roles)
        self.budget = budget
        self.usage: dict[str, int] = {}      # role -> estimated tokens

    def record_usage(self, role: str, tokens: int) -> None:
        self.usage[role] = self.usage.get(role, 0) + max(0, int(tokens))

    def downgrade(self, role: str) -> Provider | None:
        """Send a hosted role to the local backend for the rest of the run.
        Returns the local provider, or None when the role is already local."""
        backend = self._roles.get(role, "hosted")
        if backend == "local":
            return None
        self._roles[role] = "local"
        return self._backends.get("local")

    def for_role(self, role: str) -> Provider:
        backend = self._roles.get(role, "hosted")
        provider = self._backends.get(backend)
        if provider is None:
            raise ValueError(f"role '{role}' maps to unknown backend '{backend}'")
        return MeteredProvider(role, provider, self)
