from __future__ import annotations

import json
import time

from flask import Blueprint, Response, g, jsonify, request, stream_with_context
from sqlalchemy import select

from backend import audit
from backend.api.common import ApiError, authenticated, body, need, ser
from backend.approvals import manager as changes
from backend.approvals.manager import ApprovalError
from backend.auth import rbac
from backend.db import remove_session, session
from backend.jobs import enqueue
from backend.models import (Approval, ApprovalEvent, ChangePlan, Client, Device, DiagnosticResult, Evidence, ExecutionRun,
                            ExecutionStep, Investigation, Report, RollbackRun, Task, TimeEntry, VerificationResult,
                            WorkflowEvent, RecoveryCheck)
from backend.orchestrator import workflow
from backend.tenancy import current, set_tenant, reset

bp = Blueprint("tasks", __name__, url_prefix="/api")

TASK_F = ("id", "client_id", "device_id", "title", "description", "mode", "state", "source", "source_ref", "requested_by",
          "result", "created_at", "updated_at", "completed_at")
PLAN_F = ("id", "task_id", "version", "steps", "plan_hash", "status", "recovery_level", "risk",
          "requires_second_approver", "requires_no_rollback_ack", "rationale", "expires_at", "created_at")


def _get(model, id_):
    o = session().get(model, id_)
    if o is None:
        raise ApiError("not found", 404)
    return o


@bp.post("/tasks")
@authenticated("task.create")
def create_task():
    d = body()
    need(d, "device_id", "title", "mode")
    if d["mode"] not in ("analysis_only", "maintenance"):
        raise ApiError("mode must be analysis_only or maintenance")
    if d["mode"] == "maintenance" and not rbac.has(g.user.role, "task.run_maintenance"):
        raise ApiError("role may not request maintenance", 403)
    dev = _get(Device, d["device_id"])
    t = Task(tenant_id=g.user.tenant_id, client_id=dev.client_id, device_id=dev.id, requested_by=g.user.id,
             title=d["title"][:300], description=str(d.get("description", ""))[:8000], mode=d["mode"])
    session().add(t)
    session().flush()
    audit.record("task.create", actor=f"user:{g.user.id}", tenant_id=t.tenant_id, object_type="task", object_id=t.id,
                 detail={"mode": t.mode, "device_id": dev.id})
    session().commit()
    enqueue("investigate", g.user.tenant_id, t.id)
    session().refresh(t)
    return ser(t, *TASK_F), 202


@bp.get("/tasks")
@authenticated("task.read")
def list_tasks():
    q = select(Task).order_by(Task.id.desc()).limit(min(int(request.args.get("limit", 100)), 500))
    for k in ("state", "client_id", "device_id"):
        if request.args.get(k):
            q = q.where(getattr(Task, k) == (int(request.args[k]) if k.endswith("_id") else request.args[k]))
    return jsonify([ser(t, *TASK_F) for t in session().scalars(q)])


@bp.get("/tasks/<int:tid>")
@authenticated("task.read")
def get_task(tid):
    t, s = _get(Task, tid), session()
    out = ser(t, *TASK_F)
    inv = s.scalar(select(Investigation).where(Investigation.task_id == tid).order_by(Investigation.id.desc()))
    out["investigation"] = ser(inv, "summary", "root_cause", "confidence", "findings", "recommendations", "uncertainty",
                               "ai_used") if inv else None
    out["plans"] = [ser(p, *PLAN_F) for p in s.scalars(select(ChangePlan).where(ChangePlan.task_id == tid).order_by(ChangePlan.id))]
    out["runs"] = [_run_dict(r) for r in s.scalars(select(ExecutionRun).where(ExecutionRun.task_id == tid))]
    return out


def _run_dict(r: ExecutionRun) -> dict:
    s = session()
    d = ser(r, "id", "plan_id", "status", "gate_results", "before_state", "after_state", "state_diff", "error", "started_at",
            "finished_at")
    d["steps"] = [ser(x, "step_idx", "operation", "params", "status", "exit_code") for x in
                  s.scalars(select(ExecutionStep).where(ExecutionStep.run_id == r.id).order_by(ExecutionStep.step_idx))]
    d["verifications"] = [ser(v, "step_idx", "check", "passed", "detail") for v in
                          s.scalars(select(VerificationResult).where(VerificationResult.run_id == r.id))]
    d["recovery_checks"] = [ser(c, "level", "passed", "detail") for c in
                            s.scalars(select(RecoveryCheck).where(RecoveryCheck.run_id == r.id))]
    d["rollbacks"] = [ser(x, "status", "steps", "state_restored", "detail") for x in
                      s.scalars(select(RollbackRun).where(RollbackRun.run_id == r.id))]
    return d


@bp.get("/tasks/<int:tid>/timeline")
@authenticated("task.read")
def timeline(tid):
    _get(Task, tid)
    return jsonify([ser(w, "seq", "from_state", "to_state", "actor", "detail", "at") for w in
                    session().scalars(select(WorkflowEvent).where(WorkflowEvent.task_id == tid).order_by(WorkflowEvent.seq))])


@bp.get("/tasks/<int:tid>/evidence")
@authenticated("task.read")
def task_evidence(tid):
    _get(Task, tid)
    return jsonify([ser(e, "id", "phase", "operation", "params", "command_display", "exit_code", "output_sanitized",
                        "output_sha256", "truncated", "duration_ms", "error", "collected_at")
                    for e in session().scalars(select(Evidence).where(Evidence.task_id == tid).order_by(Evidence.id))])


@bp.get("/tasks/<int:tid>/diagnostics")
@authenticated("task.read")
def task_diagnostics(tid):
    _get(Task, tid)
    return jsonify([ser(r, "agent", "status", "summary", "findings", "evidence_ids", "uncertainty", "proposals", "ai_used")
                    for r in session().scalars(select(DiagnosticResult).where(DiagnosticResult.task_id == tid))])


@bp.post("/tasks/<int:tid>/cancel")
@authenticated("task.cancel")
def cancel(tid):
    t = _get(Task, tid)
    try:
        workflow.advance(t, "CANCELLED", actor=f"user:{g.user.id}")
    except workflow.InvalidTransition as e:
        raise ApiError(str(e), 409)
    session().commit()
    return ser(t, *TASK_F)


@bp.get("/tasks/<int:tid>/stream")
@authenticated("task.read")
def stream(tid):
    """Server-Sent Events: live investigation timeline.  Use fetch() + header auth (no token in URL)."""
    _get(Task, tid)
    tenant_id = g.user.tenant_id
    last = int(request.args.get("after", 0))

    @stream_with_context
    def gen():
        nonlocal last
        tok = set_tenant(tenant_id)
        try:
            idle = 0
            while idle < 300:
                evs = list(session().scalars(select(WorkflowEvent).where(WorkflowEvent.task_id == tid,
                                                                         WorkflowEvent.seq > last).order_by(WorkflowEvent.seq)))
                for w in evs:
                    last = w.seq
                    yield f"id: {w.seq}\nevent: transition\ndata: {json.dumps(ser(w, 'seq', 'from_state', 'to_state', 'actor', 'at'))}\n\n"
                task = session().get(Task, tid)
                session().expire_all()
                if task and task.state in workflow.TERMINAL and not evs:
                    yield "event: end\ndata: {}\n\n"
                    return
                idle = 0 if evs else idle + 1
                if not evs:
                    yield ": keepalive\n\n"
                time.sleep(1)
        finally:
            reset(tok)
            remove_session()
    return Response(gen(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})


@bp.post("/tasks/<int:tid>/replan")
@authenticated("task.run_maintenance")
def replan(tid):
    t = _get(Task, tid)
    if t.state not in ("EXPIRED",):
        raise ApiError("only expired plans can be re-planned", 409)
    dev = session().get(Device, t.device_id)
    diag = session().scalar(select(DiagnosticResult).where(DiagnosticResult.task_id == tid).order_by(DiagnosticResult.id.desc()))
    props = diag.proposals if diag else []
    try:
        from backend.orchestrator.engine import _clean_proposals
        plan = changes.create_plan(t, dev, _clean_proposals(props, dev), created_by=f"user:{g.user.id}")
        workflow.advance(t, "AWAITING_APPROVAL", actor=f"user:{g.user.id}", detail={"plan_id": plan.id})
    except (changes.PlanError, workflow.InvalidTransition) as e:
        raise ApiError(str(e), 409)
    session().commit()
    return ser(plan, *PLAN_F), 201


# ---- plans / approvals / execution
@bp.get("/plans")
@authenticated("task.read")
def list_plans():
    q = select(ChangePlan).order_by(ChangePlan.id.desc()).limit(200)
    if request.args.get("status"):
        q = q.where(ChangePlan.status == request.args["status"])
    return jsonify([ser(p, *PLAN_F) for p in session().scalars(q)])


@bp.get("/plans/<int:pid>")
@authenticated("task.read")
def get_plan(pid):
    p = _get(ChangePlan, pid)
    out = ser(p, *PLAN_F)
    out["approvals"] = [ser(a, "approver_id", "decision", "comment", "plan_hash", "acknowledged_no_rollback", "at")
                        for a in session().scalars(select(Approval).where(Approval.plan_id == pid))]
    out["events"] = [ser(e, "kind", "actor", "detail", "at") for e in
                     session().scalars(select(ApprovalEvent).where(ApprovalEvent.plan_id == pid))]
    return out


@bp.post("/plans/<int:pid>/decision")
@authenticated("plan.approve")
def decision(pid):
    p, d = _get(ChangePlan, pid), body()
    need(d, "decision")
    if d.get("plan_hash") and d["plan_hash"] != p.plan_hash:        # approver must approve exactly what they saw
        raise ApiError("plan changed since you loaded it", 409)
    try:
        ap = changes.decide(p, g.user, d["decision"], d.get("comment", ""), bool(d.get("acknowledged_no_rollback")))
        session().commit()
    except (ApprovalError, workflow.InvalidTransition) as e:
        session().rollback()
        raise ApiError(str(e), 409)
    return ser(ap, "id", "decision", "plan_hash", "at")


@bp.post("/plans/<int:pid>/execute")
@authenticated("plan.execute")
def execute(pid):
    p = _get(ChangePlan, pid)
    if p.status != "approved":
        raise ApiError(f"plan is '{p.status}', not approved", 409)
    enqueue("execute_plan", g.user.tenant_id, pid, g.user.id)
    session().expire_all()
    run = session().scalar(select(ExecutionRun).where(ExecutionRun.plan_id == pid).order_by(ExecutionRun.id.desc()))
    return {"accepted": True, "run": _run_dict(run) if run else None}, 202


@bp.get("/runs/<int:rid>")
@authenticated("task.read")
def get_run(rid):
    return _run_dict(_get(ExecutionRun, rid))


# ---- reports / time
@bp.get("/tasks/<int:tid>/report")
@authenticated("report.read")
def task_report(tid):
    _get(Task, tid)
    r = session().scalar(select(Report).where(Report.task_id == tid).order_by(Report.id.desc()))
    if r is None:
        raise ApiError("report not available yet", 404)
    return ser(r, "id", "title", "content", "created_at")


@bp.get("/reports")
@authenticated("report.read")
def list_reports():
    return jsonify([ser(r, "id", "task_id", "title", "created_at") for r in
                    session().scalars(select(Report).order_by(Report.id.desc()).limit(200))])


@bp.get("/tasks/<int:tid>/time")
@authenticated("report.read")
def task_time(tid):
    _get(Task, tid)
    return jsonify([ser(t, "id", "source", "minutes", "note", "started_at", "ended_at", "posted_external")
                    for t in session().scalars(select(TimeEntry).where(TimeEntry.task_id == tid))])
