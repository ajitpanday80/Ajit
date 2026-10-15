"""Execution engine: gates → backup → execute → verify → (rollback).

Hard rule: if approval, permissions, preconditions, locking, backup or recoverability checks fail, no
modification is made.  The same code path enforces it regardless of who (or what AI) asked for the run.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from backend import audit
from backend.approvals.manager import latest_approval
from backend.approvals.plans import compute_hash
from backend.auth import rbac
from backend.backups import BackupFailed, create_and_verify
from backend.connectors.base import ConnectionLost, ConnectorError
from backend.db import session
from backend.executor.runner import run_operation, run_with_reconnect
from backend.models import (ChangePlan, Client, Device, DeviceLock, ExecutionRun, ExecutionStep, Task, User,
                            VerificationResult, utcnow)
from backend.orchestrator import workflow
from backend.policies.engine import PolicyDenied
from backend.rollback import rollback
from backend.services import svc
from backend.verification import capture_state, check, diff_state, evaluate, run_probe

log = logging.getLogger(__name__)
ACTIVE_RUN_STATES = ("PRECHECKING", "BACKING_UP", "EXECUTING", "VERIFYING", "ROLLING_BACK")


class GateFailed(Exception):
    def __init__(self, gate: str, detail: str):
        super().__init__(f"gate '{gate}' failed: {detail}")
        self.gate, self.detail = gate, detail


def _gate(run: ExecutionRun, name: str, ok: bool, detail: str = "ok", fail: str | None = None) -> None:
    """Record a gate.  ``detail`` is shown when it passes, ``fail`` (default: detail) when it does not."""
    shown = detail if ok else (fail or detail)
    gr = dict(run.gate_results or {})
    gr[name] = {"ok": ok, "detail": shown}
    run.gate_results = gr
    session().flush()
    if not ok:
        raise GateFailed(name, shown)


def _heartbeat(run: ExecutionRun) -> None:
    run.heartbeat_at = utcnow()
    session().commit()


def _acquire_lock(device: Device, run: ExecutionRun) -> None:
    s = session()
    cfg = svc().cfg
    for stale in s.scalars(select(DeviceLock).where(DeviceLock.device_id == device.id)):
        if stale.expires_at < utcnow():
            s.delete(stale)
    s.flush()
    s.add(DeviceLock(tenant_id=device.tenant_id, device_id=device.id, run_id=run.id,
                     expires_at=utcnow() + dt.timedelta(seconds=cfg.run_heartbeat_stale_seconds * 4)))
    try:
        s.flush()
    except IntegrityError:
        s.rollback()
        raise GateFailed("device_lock", "another change is already running on this device")


def _release_lock(device_id: int, run_id: int) -> None:
    for lk in session().scalars(select(DeviceLock).where(DeviceLock.device_id == device_id, DeviceLock.run_id == run_id)):
        session().delete(lk)
    session().flush()


# ============================================================================ public API
def execute_plan(plan_id: int, *, actor_user_id: int | None = None) -> ExecutionRun:
    s = session()
    plan = s.get(ChangePlan, plan_id)
    if plan is None:
        raise LookupError("plan not found")
    task = s.get(Task, plan.task_id)
    device = s.get(Device, task.device_id)
    actor = f"user:{actor_user_id}" if actor_user_id else "system"
    if plan.status != "approved":
        raise GateFailed("approval", f"plan status is '{plan.status}', not 'approved'")
    run = ExecutionRun(tenant_id=task.tenant_id, plan_id=plan.id, task_id=task.id, status="PRECHECKING")
    s.add(run)
    s.flush()
    workflow.advance(task, "PRECHECKING", actor=actor, detail={"run_id": run.id})
    audit.record("run.start", actor=actor, tenant_id=task.tenant_id, object_type="execution_run", object_id=run.id,
                 detail={"plan_hash": plan.plan_hash})
    s.commit()
    try:
        _pre_execution_gates(plan, task, device, run, actor_user_id)
    except GateFailed as e:
        return _abort(run, plan, task, device, e)
    except (PolicyDenied, BackupFailed, ConnectorError) as e:
        return _abort(run, plan, task, device, GateFailed(type(e).__name__, str(e)))
    return _drive(run, plan, task, device, actor)


def _abort(run, plan, task, device, e: GateFailed) -> ExecutionRun:
    s = session()
    try:
        s.commit()                 # keep the evidence gathered so far (failed backups, probes, gate results)
    except Exception:  # noqa: BLE001
        s.rollback()
    run = s.get(ExecutionRun, run.id)
    plan = s.get(ChangePlan, plan.id)
    task = s.get(Task, task.id)
    gr = dict(run.gate_results or {})
    gr.setdefault(e.gate, {"ok": False, "detail": e.detail})
    run.gate_results = gr
    run.status, run.error, run.finished_at = "ABORTED", str(e), utcnow()
    plan.status = "aborted"
    _release_lock(task.device_id, run.id)
    workflow.advance(task, "ABORTED", actor="system", detail={"gate": e.gate, "reason": e.detail})
    audit.record("run.aborted", tenant_id=task.tenant_id, object_type="execution_run", object_id=run.id,
                 detail={"gate": e.gate, "reason": e.detail})
    s.commit()
    _finalise(task, run)
    return run


# ============================================================================ gates
def _pre_execution_gates(plan, task, device, run, actor_user_id):
    s = session()
    client = s.get(Client, task.client_id)
    # 1. approval matches the exact plan, in scope and in time
    ap = latest_approval(plan)
    _gate(run, "approval_exists", ap is not None and ap.decision == "approve", fail="no approving decision")
    _gate(run, "approval_matches_plan", ap.plan_hash == plan.plan_hash == compute_hash(plan.canonical),
          fail="approval hash / plan integrity mismatch")
    _gate(run, "approval_fresh", plan.expires_at >= utcnow(), fail="approval window expired")
    if plan.requires_second_approver:
        _gate(run, "second_approver", ap.approver_id != task.requested_by, fail="approver is the requester")
    if plan.requires_no_rollback_ack:
        _gate(run, "no_rollback_ack", ap.acknowledged_no_rollback, fail="no-rollback acknowledgement missing")
    # 2. permissions / mode
    if actor_user_id:
        u = s.get(User, actor_user_id)
        _gate(run, "permission_execute", u is not None and rbac.has(u.role, "plan.execute"), fail="role may not execute")
    _gate(run, "mode_maintenance", task.mode == "maintenance", fail="task is Analysis Only")
    _gate(run, "client_maintenance_enabled", bool(client and client.maintenance_enabled and client.status == "active"),
          fail="maintenance disabled for client")
    # 3. exclusive access to the device
    _acquire_lock(device, run)
    _gate(run, "device_lock", True, "acquired")
    plan.status = "executing"
    s.commit()
    # 4. preconditions + drift detection (read-only)
    for st in plan.steps:
        if st["precondition"]:
            r = run_probe(task, device, st["precondition"], phase="precheck", plan=plan, run=run, step_idx=st["idx"])
            ok, d = evaluate(st["precondition"]["expect"], r)
            _gate(run, f"precondition_{st['idx']}", ok, d)
        cur = run_probe(task, device, st["state_probe"], phase="precheck", plan=plan, run=run, step_idx=st["idx"])
        fp = hashlib.sha256(cur.stdout.strip().encode()).hexdigest()
        _gate(run, f"no_drift_{st['idx']}", fp == st["state_fingerprint"],
              fail="device state changed since the plan was approved — re-plan required")
    s.commit()
    # 5. backup → verify recoverability (BLOCKS modification on failure)
    workflow.advance(task, "BACKING_UP", actor="system", detail={"run_id": run.id})
    run.status = "BACKING_UP"
    s.commit()
    for st in plan.steps:
        try:
            rc = create_and_verify(task, device, plan, run, st)
        except BackupFailed as e:
            _gate(run, f"recovery_{st['idx']}", False, str(e))
        _gate(run, f"recovery_{st['idx']}", rc.passed, f"{rc.level}: {rc.detail}")
    run.before_state = capture_state(task, device, plan, run)
    workflow.advance(task, "EXECUTING", actor="system", detail={"run_id": run.id})
    run.status = "EXECUTING"
    s.commit()


# ============================================================================ drive (resumable)
def _drive(run, plan, task, device, actor) -> ExecutionRun:
    s = session()
    cfg = svc().cfg
    failure: str | None = None
    unreachable = False
    for st in plan.steps:
        idx = st["idx"]
        key = f"{plan.plan_hash}:{idx}"
        es = s.scalar(select(ExecutionStep).where(ExecutionStep.idempotency_key == key))
        if es is not None and es.status == "succeeded":
            continue                                                   # resumed run: already done
        if es is not None and es.status in ("started", "unknown"):
            outcome = _reconcile(task, device, plan, run, st, es)       # did it land before the interruption?
            if outcome is None:
                unreachable = True
                failure = f"step {idx}: device unreachable while reconciling an interrupted step"
                break
            if not outcome:
                failure = f"step {idx}: interrupted and not verified"
                break
            continue
        if es is None:
            es = ExecutionStep(tenant_id=task.tenant_id, run_id=run.id, step_idx=idx, idempotency_key=key,
                               operation=st["operation"], params=st["params"], status="started", started_at=utcnow())
            s.add(es)
            s.commit()                                                 # intent is durable BEFORE we act
        _heartbeat(run)
        try:
            r = run_operation(task, device, st["operation"], st["params"], phase="execution", plan=plan, run=run,
                              step_idx=idx, actor=actor)
            es.exit_code, es.output_sanitized, es.finished_at = r.result.exit_code, r.evidence.output_sanitized, utcnow()
            es.status = "succeeded" if r.ok else "failed"
            s.commit()
            if not r.ok:
                failure = f"step {idx} ({st['operation']}) exited {r.result.exit_code}"
                break
        except ConnectionLost as e:
            es.status = "unknown"
            s.commit()
            outcome = _reconcile(task, device, plan, run, st, es)
            if outcome is None:
                unreachable = True
                failure = f"step {idx}: connection lost and device did not come back ({e})"
                break
            if not outcome:
                failure = f"step {idx}: connection lost; outcome not verified"
                break
        except ConnectorError as e:                                    # could not even connect: nothing ran
            es.status, es.finished_at = "failed_not_run", utcnow()
            s.commit()
            failure = f"step {idx}: connector error before execution: {e}"
            break
        except PolicyDenied as e:
            es.status = "failed_not_run"
            s.commit()
            failure = f"step {idx}: policy denied: {e}"
            break
        # post-check for this step (reconnects/polls)
        if not check(task, device, run, idx, st["verify"], f"post-check step {idx}: {st['operation']}", plan=plan):
            failure = f"step {idx}: post-check failed"
            break
        s.commit()
    if failure is None:
        workflow.advance(task, "VERIFYING", actor="system")
        run.status = "VERIFYING"
        s.commit()
        failure = _final_verification(task, device, plan, run)
    if failure is None:
        return _succeed(run, plan, task, device)
    return _recover(run, plan, task, device, failure, unreachable)


def _reconcile(task, device, plan, run, st, es) -> bool | None:
    """After a lost connection / interrupted worker: ask the device, don't assume.  None = unreachable."""
    try:
        r = run_with_reconnect(task, device, st["verify"]["operation"], st["verify"]["params"], phase="verification",
                               plan=plan, run=run, step_idx=st["idx"], retries=svc().cfg.connect_retries)
    except ConnectorError:
        return None
    ok, d = evaluate(st["verify"]["expect"], r)
    es.status = "succeeded" if ok else "failed"
    es.finished_at = utcnow()
    session().add(VerificationResult(tenant_id=task.tenant_id, run_id=run.id, step_idx=st["idx"],
                                     check=f"reconcile step {st['idx']}", passed=ok, detail=d))
    session().commit()
    return ok


def _final_verification(task, device, plan, run) -> str | None:
    s = session()
    after = capture_state(task, device, plan, run, phase="verification")
    run.after_state = after
    run.state_diff = diff_state(run.before_state, after)
    for st in plan.steps:
        if not check(task, device, run, st["idx"], st["verify"], f"final check step {st['idx']}", retries=2, plan=plan):
            s.commit()
            return f"final verification failed for step {st['idx']} ({st['operation']})"
    s.commit()
    return None


def _succeed(run, plan, task, device) -> ExecutionRun:
    s = session()
    run.status, run.finished_at = "SUCCEEDED", utcnow()
    plan.status = "executed"
    _release_lock(device.id, run.id)
    workflow.advance(task, "SUCCEEDED", actor="system", detail={"run_id": run.id})
    audit.record("run.succeeded", tenant_id=task.tenant_id, object_type="execution_run", object_id=run.id)
    s.commit()
    _finalise(task, run)
    return run


def _recover(run, plan, task, device, failure: str, unreachable: bool) -> ExecutionRun:
    s = session()
    run.error = failure
    audit.record("run.failed", tenant_id=task.tenant_id, object_type="execution_run", object_id=run.id,
                 detail={"error": failure})
    if unreachable:                                                    # cannot act safely without a connection
        return _needs_human(run, plan, task, device, failure + " — evidence preserved, human recovery required")
    workflow.advance(task, "ROLLING_BACK", actor="system", detail={"reason": failure})
    run.status = "ROLLING_BACK"
    s.commit()
    rr = rollback(task, device, plan, run)
    s.commit()
    if rr.state_restored:
        run.status, run.finished_at = "ROLLED_BACK", utcnow()
        plan.status = "executed"
        _release_lock(device.id, run.id)
        workflow.advance(task, "ROLLED_BACK", actor="system", detail={"rollback_id": rr.id})
        audit.record("run.rolled_back", tenant_id=task.tenant_id, object_type="execution_run", object_id=run.id)
        s.commit()
        _finalise(task, run)
        return run
    return _needs_human(run, plan, task, device, f"{failure}; rollback incomplete: {rr.detail}")


def _needs_human(run, plan, task, device, reason: str) -> ExecutionRun:
    s = session()
    run.status, run.error, run.finished_at = "NEEDS_HUMAN", reason, utcnow()
    plan.status = "executed"
    _release_lock(device.id, run.id)
    workflow.advance(task, "NEEDS_HUMAN", actor="system", detail={"reason": reason})
    audit.record("run.needs_human", tenant_id=task.tenant_id, object_type="execution_run", object_id=run.id,
                 detail={"reason": reason})
    s.commit()
    _finalise(task, run)
    return run


def _finalise(task: Task, run: ExecutionRun) -> None:
    """Reporting + integrations are best-effort and can never alter the execution outcome."""
    try:
        from backend.reporting import finalize_task
        finalize_task(task.id)
        session().commit()
    except Exception:  # pragma: no cover
        log.exception("post-run reporting failed")
        session().rollback()


# ============================================================================ interrupted runs
def recover_interrupted_runs() -> list[int]:
    """Resume or settle runs whose worker died.  Run periodically (Celery beat)."""
    s = session()
    cutoff = utcnow() - dt.timedelta(seconds=svc().cfg.run_heartbeat_stale_seconds)
    handled = []
    for run in list(s.scalars(select(ExecutionRun).where(ExecutionRun.status.in_(ACTIVE_RUN_STATES),
                                                          ExecutionRun.heartbeat_at < cutoff))):
        plan, task = s.get(ChangePlan, run.plan_id), s.get(Task, run.task_id)
        device = s.get(Device, task.device_id)
        handled.append(run.id)
        audit.record("run.recovering", tenant_id=task.tenant_id, object_type="execution_run", object_id=run.id,
                     detail={"status": run.status})
        if run.status in ("PRECHECKING", "BACKING_UP"):
            run.status = "ABORTED"
            plan.status = "aborted"
            _release_lock(device.id, run.id)
            workflow.advance(task, "ABORTED", actor="system", detail={"reason": "worker died before execution"})
            s.commit()
        elif run.status == "ROLLING_BACK":
            rr = rollback(task, device, plan, run)
            s.commit()
            if rr.state_restored:
                run.status, run.finished_at = "ROLLED_BACK", utcnow()
                _release_lock(device.id, run.id)
                workflow.advance(task, "ROLLED_BACK", actor="system")
            else:
                _needs_human(run, plan, task, device, f"rollback incomplete after restart: {rr.detail}")
            s.commit()
        else:
            if task.state == "VERIFYING":      # EXECUTING -> VERIFYING is not re-enterable; resume from VERIFYING
                pass
            run.heartbeat_at = utcnow()
            s.commit()
            if run.status == "EXECUTING":
                _drive(run, plan, task, device, "system:recovery")
            else:
                f = _final_verification(task, device, plan, run)
                _succeed(run, plan, task, device) if f is None else _recover(run, plan, task, device, f, False)
    return handled
