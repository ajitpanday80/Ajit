"""Authorised rollback: only operations the approver saw in the plan (``rollback_candidates``) may run."""
from __future__ import annotations

from backend.connectors.base import ConnectorError
from backend.db import session
from backend.executor.runner import run_operation
from backend.models import Backup, ChangePlan, Device, ExecutionRun, ExecutionStep, RollbackRun, Task
from backend.operations.registry import get_spec, validate_params
from backend.services import svc
from sqlalchemy import select


def _word(s: str) -> str:
    s = s.strip()
    return s.splitlines()[0].strip().lower() if s else ""


def _pick_candidate(step: dict, before: str) -> str | None:
    for cand in step["rollback_candidates"]:
        v = get_spec(cand).verify
        if v and v.expect[0] == "equals" and str(v.expect[1]).lower() == before:
            return cand
    return None


def rollback(task: Task, device: Device, plan: ChangePlan, run: ExecutionRun) -> RollbackRun:
    s = session()
    steps_done = {x.step_idx: x for x in s.scalars(select(ExecutionStep).where(ExecutionStep.run_id == run.id))}
    log, restored_all, problems = [], True, []
    for st in reversed(plan.steps):
        es = steps_done.get(st["idx"])
        if es is None or es.status in ("pending", "failed_not_run"):
            continue                                              # never touched the device
        before = _word((run.before_state or {}).get(str(st["idx"]), ""))
        probe = st["state_probe"]
        try:
            cur = _word(run_operation(task, device, probe["operation"], probe["params"], phase="precheck",
                                      plan=plan, run=run, step_idx=st["idx"]).stdout)
            if cur == before:
                log.append({"step": st["idx"], "action": "none", "reason": "state already equals before-state"})
                es.status = "rolled_back"
                continue
            cand = _pick_candidate(st, before)
            if cand is None:
                restored_all = False
                problems.append(f"step {st['idx']}: no authorised rollback operation restores '{before}' (now '{cur}')")
                log.append({"step": st["idx"], "action": "none", "reason": "no candidate"})
                continue
            params = validate_params(get_spec(cand), st["params"])
            r = run_operation(task, device, cand, params, phase="rollback", plan=plan, run=run, step_idx=st["idx"],
                              actor="system:rollback")
            after = _word(run_operation(task, device, probe["operation"], probe["params"], phase="precheck",
                                        plan=plan, run=run, step_idx=st["idx"]).stdout)
            ok = r.ok and after == before
            log.append({"step": st["idx"], "action": cand, "exit": r.result.exit_code, "state_after": after, "ok": ok})
            if ok:
                es.status = "rolled_back"
            else:
                restored_all = False
                problems.append(f"step {st['idx']}: after rollback state is '{after}', expected '{before}'")
        except ConnectorError as e:
            restored_all = False
            problems.append(f"step {st['idx']}: rollback transport error: {e}")
            log.append({"step": st["idx"], "action": "error", "error": str(e)})
    rr = RollbackRun(tenant_id=task.tenant_id, run_id=run.id, steps=log, state_restored=restored_all,
                     status="succeeded" if restored_all else "failed", detail="; ".join(problems))
    s.add(rr)
    s.flush()
    return rr
