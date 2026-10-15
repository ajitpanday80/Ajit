"""Change manager: immutable plan creation, approval, and integrity checks."""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from sqlalchemy import select

from backend import audit
from backend.approvals.plans import canonicalize, compute_hash
from backend.auth import rbac
from backend.db import session
from backend.models import Approval, ApprovalEvent, ChangePlan, Device, Task, User, utcnow
from backend.operations.registry import (RecoveryLevel, Risk, get_spec, resolve_probe_params, validate_params)
from backend.orchestrator import workflow
from backend.services import svc


class PlanError(Exception):
    pass


class ApprovalError(Exception):
    pass


def _probe_doc(probe, step_params: dict) -> dict:
    return {"operation": probe.operation, "params": resolve_probe_params(probe, step_params),
            "expect": list(probe.expect)}


def build_steps(task: Task, device: Device, proposals: list[dict]) -> list[dict]:
    """Turn validated proposals into fully-resolved plan steps (everything the executor will rely on)."""
    from backend.executor.runner import run_operation
    steps = []
    for i, prop in enumerate(proposals):
        spec = get_spec(prop["operation"])
        if spec.risk == Risk.READ:
            raise PlanError(f"'{spec.name}' is read-only and does not belong in a change plan")
        if device.device_type not in spec.device_types:
            raise PlanError(f"'{spec.name}' unsupported on {device.device_type}")
        params = validate_params(spec, prop.get("params"))
        # capture the precondition fingerprint now (read-only), so drift before execution is detectable
        pre = _probe_doc(spec.state_probe, params)
        r = run_operation(task, device, pre["operation"], pre["params"], phase="precheck", actor="system")
        steps.append({
            "idx": i, "operation": spec.name, "params": params, "risk": spec.risk.name,
            "rationale": prop.get("rationale", "")[:1000],
            "backup": spec.backup, "min_recovery": spec.min_recovery.name,
            "rollback_candidates": list(spec.rollback_candidates),
            "precondition": _probe_doc(spec.precondition, params) if spec.precondition else None,
            "state_probe": pre, "state_fingerprint": hashlib.sha256(r.stdout.strip().encode()).hexdigest(),
            "verify": _probe_doc(spec.verify, params),
        })
    return steps


def create_plan(task: Task, device: Device, proposals: list[dict], *, rationale: str = "",
                created_by: str = "system") -> ChangePlan:
    s = session()
    if task.mode != "maintenance":
        raise PlanError("Analysis Only tasks cannot have change plans")
    if not proposals:
        raise PlanError("no proposals")
    steps = build_steps(task, device, proposals)
    risk = max(Risk[st["risk"]] for st in steps)
    level = min(RecoveryLevel[st["min_recovery"]] for st in steps)
    version = 1 + len(list(s.scalars(select(ChangePlan).where(ChangePlan.task_id == task.id))))
    doc = {"task_id": task.id, "device_id": device.id, "client_id": task.client_id, "version": version,
           "steps": steps}
    canonical = canonicalize(doc)
    for old in s.scalars(select(ChangePlan).where(ChangePlan.task_id == task.id,
                                                  ChangePlan.status.in_(["pending_approval", "approved"]))):
        old.status = "superseded"
    plan = ChangePlan(tenant_id=task.tenant_id, task_id=task.id, version=version, steps=steps,
                      canonical=canonical, plan_hash=compute_hash(canonical), status="pending_approval",
                      recovery_level=level.name, risk=risk.name, rationale=rationale[:4000], created_by=created_by,
                      requires_second_approver=(risk >= Risk.DESTRUCTIVE) or svc().cfg.env == "production",
                      requires_no_rollback_ack=(level < RecoveryLevel.VERIFIED),
                      expires_at=utcnow() + dt.timedelta(minutes=svc().cfg.plan_ttl_minutes))
    s.add(plan)
    s.flush()
    s.add(ApprovalEvent(tenant_id=task.tenant_id, plan_id=plan.id, kind="created", actor=created_by,
                        detail={"hash": plan.plan_hash, "risk": risk.name, "recovery": level.name}))
    audit.record("plan.create", actor=created_by, tenant_id=task.tenant_id, object_type="change_plan",
                 object_id=plan.id, detail={"hash": plan.plan_hash, "steps": [x["operation"] for x in steps]})
    return plan


def decide(plan: ChangePlan, user: User, decision: str, comment: str = "", acknowledged_no_rollback: bool = False) -> Approval:
    s = session()
    task = s.get(Task, plan.task_id)
    if not rbac.has(user.role, "plan.approve"):
        raise ApprovalError("role may not approve plans")
    if plan.status != "pending_approval":
        raise ApprovalError(f"plan is '{plan.status}', not pending approval")
    if compute_hash(plan.canonical) != plan.plan_hash:
        raise ApprovalError("plan integrity check failed")
    if plan.expires_at < utcnow():
        plan.status = "expired"
        workflow.advance(task, "EXPIRED", actor=f"user:{user.id}", detail={"plan_id": plan.id})
        s.commit()
        raise ApprovalError("plan expired; request a new plan")
    if decision not in ("approve", "reject"):
        raise ApprovalError("decision must be approve or reject")
    if decision == "approve":
        if plan.requires_second_approver and task.requested_by == user.id:
            raise ApprovalError("this plan requires an approver other than the requester")
        if plan.requires_no_rollback_ack and not acknowledged_no_rollback:
            raise ApprovalError("plan has no verified rollback; explicit acknowledgement required")
    ap = Approval(tenant_id=plan.tenant_id, plan_id=plan.id, plan_hash=plan.plan_hash, approver_id=user.id,
                  decision=decision, comment=comment[:2000], acknowledged_no_rollback=acknowledged_no_rollback)
    s.add(ap)
    plan.status = "approved" if decision == "approve" else "rejected"
    s.add(ApprovalEvent(tenant_id=plan.tenant_id, plan_id=plan.id, kind=decision, actor=f"user:{user.id}",
                        detail={"hash": plan.plan_hash, "comment": comment[:500]}))
    audit.record(f"plan.{decision}", actor=f"user:{user.id}", tenant_id=plan.tenant_id,
                 object_type="change_plan", object_id=plan.id, detail={"hash": plan.plan_hash})
    workflow.advance(task, "APPROVED" if decision == "approve" else "REJECTED", actor=f"user:{user.id}",
                     detail={"plan_id": plan.id, "hash": plan.plan_hash})
    s.flush()
    return ap


def latest_approval(plan: ChangePlan) -> Approval | None:
    return session().scalar(select(Approval).where(Approval.plan_id == plan.id).order_by(Approval.id.desc()).limit(1))
