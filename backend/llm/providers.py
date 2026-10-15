"""Model-provider abstraction: Claude API, local Ollama, scripted (tests)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import requests


class ProviderUnavailable(Exception):
    pass


@dataclass
class LlmResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class Provider:
    name = "base"
    model = ""
    local = False

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> LlmResponse:  # pragma: no cover
        raise NotImplementedError


class ClaudeProvider(Provider):
    name = "claude"

    def __init__(self, api_key: str, model: str, timeout: int = 60):
        self.api_key, self.model, self.timeout = api_key, model, timeout

    def complete(self, system, user, max_tokens=2000):
        try:
            r = requests.post("https://api.anthropic.com/v1/messages", timeout=self.timeout,
                              headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                                       "content-type": "application/json"},
                              json={"model": self.model, "max_tokens": max_tokens, "system": system,
                                    "messages": [{"role": "user", "content": user}]})
            r.raise_for_status()
            d = r.json()
        except (requests.RequestException, ValueError) as e:
            raise ProviderUnavailable(f"claude: {type(e).__name__}") from e
        text = "".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
        u = d.get("usage", {})
        return LlmResponse(text, u.get("input_tokens", 0), u.get("output_tokens", 0))


class OllamaProvider(Provider):
    name = "ollama"
    local = True

    def __init__(self, base_url: str, model: str, timeout: int = 120):
        self.base_url, self.model, self.timeout = base_url.rstrip("/"), model, timeout

    def complete(self, system, user, max_tokens=2000):
        try:
            r = requests.post(f"{self.base_url}/api/chat", timeout=self.timeout,
                              json={"model": self.model, "stream": False, "options": {"num_predict": max_tokens},
                                    "messages": [{"role": "system", "content": system},
                                                 {"role": "user", "content": user}]})
            r.raise_for_status()
            d = r.json()
        except (requests.RequestException, ValueError) as e:
            raise ProviderUnavailable(f"ollama: {type(e).__name__}") from e
        return LlmResponse(d.get("message", {}).get("content", ""), d.get("prompt_eval_count", 0), d.get("eval_count", 0))


class ScriptedProvider(Provider):
    """Test double: returns queued strings, or calls ``fn(system, user, purpose_hint)``."""
    name = "scripted"
    local = True

    def __init__(self, responses: list[str] | None = None, fn: Callable | None = None, local: bool = True):
        self.responses, self.fn, self.local = list(responses or []), fn, local
        self.calls: list[tuple[str, str]] = []
        self.model = "scripted"

    def complete(self, system, user, max_tokens=2000):
        self.calls.append((system, user))
        if self.fn:
            return LlmResponse(self.fn(system, user))
        if not self.responses:
            raise ProviderUnavailable("scripted: no response queued")
        return LlmResponse(self.responses.pop(0), 10, 10)
