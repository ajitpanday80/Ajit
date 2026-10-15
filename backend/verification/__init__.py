"""Post-checks, state capture and before/after comparison (deterministic, never AI-judged)."""
from __future__ import annotations

import re
import time

from backend.connectors.base import ConnectorError
from backend.db import session
from backend.executor.runner import OpResult, run_operation
from backend.models import ChangePlan, Device, ExecutionRun, Task, VerificationResult
from backend.operations.registry import get_spec
from backend.services import svc


def evaluate(expect: list | tuple, res: OpResult) -> tuple[bool, str]:
    kind = expect[0]
    out = res.stdout.strip()
    if kind == "exit0":
        return res.ok, f"exit={res.result.exit_code}"
    if kind == "equals":
        first = out.splitlines()[0].strip().lower() if out else ""
        return first == str(expect[1]).lower(), f"got '{first}', want '{expect[1]}'"
    if kind == "contains":
        return expect[1] in out, f"{'found' if expect[1] in out else 'missing'} '{expect[1]}'"
    if kind == "regex":
        return bool(re.search(expect[1], out)), f"regex {expect[1]}"
    return False, f"unknown predicate {kind}"


def run_probe(task: Task, device: Device, probe: dict, *, phase: str, plan: ChangePlan | None = None,
              run: ExecutionRun | None = None, step_idx: int | None = None) -> OpResult:
    return run_operation(task, device, probe["operation"], probe["params"], phase=phase, plan=plan, run=run,
                         step_idx=step_idx)


def check(task: Task, device: Device, run: ExecutionRun, step_idx: int | None, probe: dict, label: str, *,
          retries: int | None = None, plan: ChangePlan | None = None) -> bool:
    """Run a post-check, polling (the service may need a moment), and persist the outcome."""
    cfg = svc().cfg
    attempts = cfg.verify_retries if retries is None else retries
    passed, detail = False, "no attempt"
    for i in range(max(attempts, 1)):
        try:
            res = run_probe(task, device, probe, phase="verification", plan=plan, run=run, step_idx=step_idx)
            passed, detail = evaluate(probe["expect"], res)
        except ConnectorError as e:
            passed, detail = False, f"probe error: {e}"
        if passed:
            break
        if i < attempts - 1:
            time.sleep(cfg.verify_delay)
    session().add(VerificationResult(tenant_id=task.tenant_id, run_id=run.id, step_idx=step_idx, check=label,
                                     passed=passed, detail=detail))
    session().flush()
    return passed


def capture_state(task: Task, device: Device, plan: ChangePlan, run: ExecutionRun, phase: str = "precheck") -> dict:
    state = {}
    for st in plan.steps:
        res = run_probe(task, device, st["state_probe"], phase=phase, plan=plan, run=run, step_idx=st["idx"])
        state[str(st["idx"])] = res.stdout.strip()
    return state


def diff_state(before: dict, after: dict) -> dict:
    return {k: {"before": before.get(k), "after": after.get(k), "changed": before.get(k) != after.get(k)}
            for k in sorted(set(before) | set(after))}
