"""Background jobs.  ``enqueue`` runs inline (dev/tests) or via Celery (production).

Every job re-establishes its tenant scope: workers never run with ambient cross-tenant access.
"""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import select

from backend.db import remove_session, session
from backend.models import Evidence, Tenant, utcnow
from backend.services import svc
from backend.tenancy import system_scope, tenant_scope

log = logging.getLogger(__name__)


def _investigate(task_id: int):
    from backend.orchestrator.engine import run_investigation
    run_investigation(task_id)


def _execute(plan_id: int, user_id: int | None = None):
    from backend.executor.engine import GateFailed, execute_plan
    try:
        execute_plan(plan_id, actor_user_id=user_id)
    except GateFailed as e:
        log.warning("execution refused: %s", e)


def _recover():
    from backend.executor.engine import recover_interrupted_runs
    recover_interrupted_runs()


def _purge_raw_evidence():
    cutoff = utcnow() - dt.timedelta(days=svc().cfg.evidence_retention_days)
    for e in session().scalars(select(Evidence).where(Evidence.collected_at < cutoff, Evidence.raw_encrypted.is_not(None))):
        e.raw_encrypted = None
    session().commit()


JOBS = {"investigate": _investigate, "execute_plan": _execute, "recover": _recover, "purge_raw": _purge_raw_evidence}


def run_job(name: str, tenant_id: int | None, *args):
    try:
        if tenant_id is None:                      # platform-wide maintenance jobs iterate tenants explicitly
            with system_scope():
                tenants = [t.id for t in session().scalars(select(Tenant))]
            for tid in tenants:
                with tenant_scope(tid):
                    JOBS[name](*args)
        else:
            with tenant_scope(tenant_id):
                JOBS[name](*args)
        session().commit()
    except Exception:
        session().rollback()
        raise
    finally:
        remove_session()


def enqueue(name: str, tenant_id: int | None, *args) -> None:
    if svc().cfg.jobs_inline:
        # keep the caller's session/scope: inline runs share the request transaction boundary
        JOBS[name](*args)
        session().commit()
        return
    from workers.celery_app import celery
    celery.send_task("msp.run_job", args=[name, tenant_id, *args])
