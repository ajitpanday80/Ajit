"""Central orchestrator: tasks → specialist agents → consolidated investigation → (plan for approval)."""
from __future__ import annotations

import logging

from backend import audit
from backend.agents import agent_for
from backend.agents.base import SEV_RANK, AgentResult
from backend.approvals import manager as changes
from backend.db import session
from backend.models import Client, Device, DiagnosticResult, Investigation, Task, User
from backend.operations.registry import Risk, get_spec
from backend.orchestrator import workflow

log = logging.getLogger(__name__)
MAX_PLAN_STEPS = 5


def run_investigation(task_id: int) -> Task:
    s = session()
    task = s.get(Task, task_id)
    if task is None or task.state != "SUBMITTED":
        return task
    device = s.get(Device, task.device_id)
    client = s.get(Client, task.client_id)
    requester = s.get(User, task.requested_by) if task.requested_by else None
    role = requester.role if requester else None
    try:
        workflow.advance(task, "DIAGNOSING", actor="orchestrator")
        s.commit()
        cls = agent_for(device.device_type)
        if cls is None:
            raise RuntimeError(f"no specialist agent for device type '{device.device_type}'")
        res: AgentResult = cls(task, device, client, role).run()
        s.add(DiagnosticResult(tenant_id=task.tenant_id, task_id=task.id, agent=res.agent, status=res.status,
                               summary=res.summary, findings=res.findings, evidence_ids=res.evidence_ids,
                               uncertainty=res.uncertainty, proposals=res.proposals, ai_used=res.ai_used))
        workflow.advance(task, "ANALYZING", actor="orchestrator")
        findings = sorted({f["title"]: f for f in res.findings}.values(), key=lambda f: -SEV_RANK[f["severity"]])
        proposals = _clean_proposals(res.proposals, device)
        root = res.root_cause or (findings[0]["title"] if findings else "")
        recs = [f"{p['operation']} {p['params']} — {p['rationale']}" for p in proposals]
        s.add(Investigation(tenant_id=task.tenant_id, task_id=task.id, summary=res.summary, root_cause=root,
                            confidence=res.confidence if res.confidence else "low", findings=findings,
                            recommendations=recs, uncertainty=res.uncertainty, ai_used=res.ai_used))
        s.commit()
        if task.mode == "analysis_only" or not proposals:
            return _complete(task, "analysis only: findings reported, no changes made" if task.mode == "analysis_only"
                             else "no remediation proposed")
        if not client.maintenance_enabled:
            return _complete(task, "maintenance is not enabled for this client; recommendations reported only")
        plan = changes.create_plan(task, device, proposals, rationale=res.summary, created_by="orchestrator")
        workflow.advance(task, "AWAITING_APPROVAL", actor="orchestrator", detail={"plan_id": plan.id, "hash": plan.plan_hash})
        s.commit()
        return task
    except Exception as e:  # noqa: BLE001 - a failed investigation must never leave a task hanging
        log.exception("investigation %s failed", task_id)
        s.rollback()
        task = s.get(Task, task_id)
        if task.state not in workflow.TERMINAL:
            task.result = {"error": f"{type(e).__name__}: {e}"}
            try:
                workflow.advance(task, "FAILED", actor="orchestrator", detail={"error": str(e)[:300]})
            except workflow.InvalidTransition:
                pass
            s.commit()
            _finalize(task)
        return task


def _clean_proposals(props: list[dict], device: Device) -> list[dict]:
    seen, out = set(), []
    for p in props:
        try:
            spec = get_spec(p["operation"])
        except Exception:
            continue
        if spec.risk == Risk.READ or device.device_type not in spec.device_types:
            continue
        key = (p["operation"], tuple(sorted(p["params"].items())))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out[:MAX_PLAN_STEPS]


def _complete(task: Task, note: str) -> Task:
    workflow.advance(task, "COMPLETED", actor="orchestrator", detail={"note": note})
    task.result = {**(task.result or {}), "note": note}
    session().commit()
    _finalize(task)
    return task


def _finalize(task: Task) -> None:
    try:
        from backend.reporting import finalize_task
        finalize_task(task.id)
        session().commit()
    except Exception:  # pragma: no cover
        log.exception("finalize failed")
        session().rollback()
