"""Chooses a provider per client data policy, enforces token budgets, logs every call, parses JSON."""
from __future__ import annotations

import datetime as dt
import json
import re

from sqlalchemy import func, select

from backend.config import Config
from backend.db import session
from backend.llm.providers import ClaudeProvider, OllamaProvider, Provider, ProviderUnavailable
from backend.models import Client, LlmCall, utcnow


class LlmRouter:
    def __init__(self, cfg: Config, providers: dict[str, Provider] | None = None):
        self.cfg = cfg
        if providers is None:
            providers = {}
            if cfg.anthropic_api_key:
                providers["claude"] = ClaudeProvider(cfg.anthropic_api_key, cfg.anthropic_model, cfg.llm_timeout_seconds)
            providers["ollama"] = OllamaProvider(cfg.ollama_url, cfg.ollama_model, cfg.llm_timeout_seconds * 2)
        self.providers = providers

    def candidates(self, client: Client) -> list[Provider]:
        pol = client.ai_policy
        if pol == "disabled":
            return []
        order = ["claude", "ollama", "scripted"] if pol == "cloud_allowed" else ["ollama", "scripted"]
        out = [self.providers[n] for n in order if n in self.providers]
        if pol == "local_only":
            out = [p for p in out if p.local]          # hard guarantee: local-only never reaches a cloud provider
        return out

    def _tokens_this_month(self, tenant_id: int) -> int:
        start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return session().scalar(select(func.coalesce(func.sum(LlmCall.input_tokens + LlmCall.output_tokens), 0))
                                .where(LlmCall.tenant_id == tenant_id, LlmCall.at >= start)) or 0

    def ask_json(self, client: Client, task_id: int | None, purpose: str, system: str, user: str,
                 max_tokens: int = 2000) -> tuple[dict | None, str]:
        """Return (parsed_json | None, provider_label).  Never raises: AI is advisory and may be unavailable."""
        s = session()
        if self._tokens_this_month(client.tenant_id) >= self.cfg.llm_monthly_token_budget:
            return None, "budget_exhausted"
        for p in self.candidates(client):
            try:
                resp = p.complete(system, user, max_tokens)
            except ProviderUnavailable as e:
                s.add(LlmCall(tenant_id=client.tenant_id, task_id=task_id, provider=p.name, model=p.model,
                              purpose=purpose, prompt=user[:20000], ok=False, error=str(e)))
                s.flush()
                continue
            obj = extract_json(resp.text)
            s.add(LlmCall(tenant_id=client.tenant_id, task_id=task_id, provider=p.name, model=p.model, purpose=purpose,
                          prompt=user[:20000], response=resp.text[:20000], input_tokens=resp.input_tokens,
                          output_tokens=resp.output_tokens, ok=obj is not None,
                          error=None if obj is not None else "unparseable JSON"))
            s.flush()
            if obj is not None:
                return obj, f"{p.name}:{p.model}"
        return None, "none"


def extract_json(text: str) -> dict | None:
    text = text.strip()
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else None
    except ValueError:
        pass
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            v = json.loads(m.group(0))
            return v if isinstance(v, dict) else None
        except ValueError:
            return None
    return None
