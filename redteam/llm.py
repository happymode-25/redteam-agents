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

    def complete(self, system: str, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "temperature": 0.1,
        }
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

    def complete(self, system: str, messages: list[dict]) -> str:
        payload = {
            "model": self.model,
            "system": system,
            "messages": messages,
            "max_tokens": 4096,
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


class Router:
    """Dispatches each agent role to its configured backend."""

    def __init__(self, cfg: LLMConfig, wrap=None):
        """wrap: optional callable applied to every built provider
        (used by the fixture layer to record/replay LLM calls)."""
        hosted = build_provider(cfg.hosted)
        local = build_provider(cfg.local)
        if wrap is not None:
            hosted, local = wrap(hosted), wrap(local)
        self._backends = {"hosted": hosted, "local": local}
        self._roles = dict(cfg.roles)

    def for_role(self, role: str) -> Provider:
        backend = self._roles.get(role, "hosted")
        provider = self._backends.get(backend)
        if provider is None:
            raise ValueError(f"role '{role}' maps to unknown backend '{backend}'")
        return provider
