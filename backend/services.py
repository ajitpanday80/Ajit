"""Process-wide service container (config, vault, policy engine)."""
from __future__ import annotations

from dataclasses import dataclass

from backend.config import Config
from backend.policies.engine import PolicyEngine
from backend.vault import Vault


@dataclass
class Services:
    cfg: Config
    vault: Vault
    policy: PolicyEngine
    llm: object | None = None  # backend.llm.router.LlmRouter, set at app start


_services: Services | None = None


def init_services(cfg: Config) -> Services:
    global _services
    _services = Services(cfg=cfg, vault=Vault(cfg.master_keys), policy=PolicyEngine(cfg))
    return _services


def svc() -> Services:
    assert _services is not None, "init_services() not called"
    return _services
