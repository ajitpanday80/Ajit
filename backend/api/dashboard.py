"""Aggregated numbers for the overview dashboard (one query set, tenant-scoped automatically)."""
from __future__ import annotations

import datetime as dt
from collections import Counter

from flask import Blueprint, g, request
from sqlalchemy import select

from backend import audit
from backend.api.common import ApiError, authenticated
from backend.db import session
from backend.models import ChangePlan, Client, Device, Investigation, Task, WorkflowEvent, utcnow

bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

OPEN_STATES = {"SUBMITTED", "DIAGNOSING", "ANALYZING", "AWAITING_APPROVAL", "APPROVED", "PRECHECKING", "BACKING_UP",
               "EXECUTING", "VERIFYING", "ROLLING_BACK", "EXPIRED"}
ATTENTION_STATES = ("AWAITING_APPROVAL", "NEEDS_HUMAN", "FAILED", "ABORTED", "EXPIRED")
RUN_OUTCOMES = ("SUCCEEDED", "ROLLED_BACK", "NEEDS_HUMAN", "ABORTED", "FAILED")
SEVERITIES = ("critical", "high", "medium", "low", "info")


@bp.get("/summary")
@authenticated("task.read")
def summary():
    try:
        days = int(request.args.get("days", 14))
    except ValueError:
        raise ApiError("days must be an integer")
    if days not in (7, 14, 30, 90):
        raise ApiError("days must be one of 7, 14, 30, 90")
    s = session()
    since = (utcnow() - dt.timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    tasks = list(s.scalars(select(Task).where(Task.created_at >= since)))
    all_open = list(s.scalars(select(Task).where(Task.state.in_(OPEN_STATES))))

    per_day = Counter(t.created_at.date().isoformat() for t in tasks)
    series = [{"date": (since + dt.timedelta(days=i)).date().isoformat(),
               "count": per_day.get((since + dt.timedelta(days=i)).date().isoformat(), 0)} for i in range(days)]

    outcomes = Counter(t.state for t in tasks)
    finished_runs = sum(outcomes[k] for k in RUN_OUTCOMES if k != "FAILED") or 0
    success = outcomes["SUCCEEDED"]
    success_rate = round(100 * success / finished_runs, 1) if finished_runs else None

    sev = Counter()
    for inv in s.scalars(select(Investigation).where(Investigation.created_at >= since)):
        for f in inv.findings or []:
            sev[f.get("severity", "info")] += 1

    dev_types = {d.id: d.device_type for d in s.scalars(select(Device))}
    by_type = Counter(dev_types.get(t.device_id, "unknown") for t in tasks)

    done = [t for t in tasks if t.completed_at]
    mttr = round(sum((t.completed_at - t.created_at).total_seconds() for t in done) / len(done) / 60, 1) if done else None

    titles = {t.id: t.title for t in s.scalars(select(Task).order_by(Task.id.desc()).limit(300))}
    attention = [{"id": t.id, "title": t.title, "state": t.state, "mode": t.mode, "at": t.updated_at.isoformat() + "Z"}
                 for t in s.scalars(select(Task).where(Task.state.in_(ATTENTION_STATES)).order_by(Task.updated_at.desc()).limit(8))]
    recent, seen = [], set()
    for w in s.scalars(select(WorkflowEvent).order_by(WorkflowEvent.id.desc()).limit(80)):   # latest transition per task
        if w.task_id in seen:
            continue
        seen.add(w.task_id)
        recent.append({"task_id": w.task_id, "title": titles.get(w.task_id, f"Task {w.task_id}"), "to_state": w.to_state,
                       "actor": w.actor, "at": w.at.isoformat() + "Z"})
        if len(recent) == 8:
            break

    clients = list(s.scalars(select(Client)))
    ok, _ = audit.verify_chain(g.user.tenant_id)
    return {
        "days": days,
        "kpis": {"open": len(all_open), "awaiting_approval": sum(1 for t in all_open if t.state == "AWAITING_APPROVAL"),
                 "investigations": len(tasks), "success_rate": success_rate, "runs_finished": finished_runs,
                 "high_findings": sev["critical"] + sev["high"], "mttr_minutes": mttr},
        "per_day": series,
        "by_severity": [{"severity": k, "count": sev[k]} for k in SEVERITIES],
        "by_device_type": [{"type": k, "count": v} for k, v in by_type.most_common()],
        "attention": attention, "recent": recent,
        "posture": {"clients": len(clients), "devices": len(dev_types),
                    "maintenance_enabled": sum(1 for c in clients if c.maintenance_enabled),
                    "local_only": sum(1 for c in clients if c.ai_policy == "local_only"),
                    "pending_plans": s.query(ChangePlan).filter(ChangePlan.status == "pending_approval").count(),
                    "audit_chain_ok": ok},
    }
