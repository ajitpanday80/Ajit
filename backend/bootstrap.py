"""Initialise DB, services and LLM router for any process (API, Celery worker, CLI)."""
from __future__ import annotations

from backend.config import Config
from backend.db import create_all, init_db
from backend.llm.router import LlmRouter
from backend.services import init_services


def bootstrap(cfg: Config, *, create_tables: bool = False):
    init_db(cfg.database_url)
    if create_tables:
        create_all()
    s = init_services(cfg)
    s.llm = LlmRouter(cfg)
    return s
