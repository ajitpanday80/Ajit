"""Backup & recovery manager.

Each mutating operation names a backup strategy.  A strategy captures pre-change state (using read-only
operations) and *verifies recoverability*.  Honest levels: VERIFIED (state captured + authorised rollback
op exists), EXPORT_ONLY (state captured, no tested restore), NONE.  The executor refuses a step whose
achieved level is below the operation's ``min_recovery``.
"""
from __future__ import annotations

import hashlib
import json

from backend.db import session
from backend.executor.runner import run_operation
from backend.models import Backup, ChangePlan, Device, ExecutionRun, RecoveryCheck, Task
from backend.operations.registry import RecoveryLevel

KNOWN_WORDS = {"active", "inactive", "failed", "activating", "deactivating", "running", "stopped", "paused"}


class BackupFailed(Exception):
    pass


def _service_state(task, device, plan, run, step, *, windows: bool) -> tuple[dict, RecoveryLevel, str]:
    probe = step["state_probe"]
    reads = [run_operation(task, device, probe["operation"], probe["params"], phase="backup", plan=plan, run=run,
                           step_idx=step["idx"]) for _ in range(2)]          # two reads: state must be stable
    words = [r.stdout.strip().splitlines()[0].strip().lower() if r.stdout.strip() else "" for r in reads]
    snap = {"state": words[0], "probe": probe}
    if not windows:
        en = run_operation(task, device, "service_is_enabled", {"unit": step["params"]["unit"]}, phase="backup",
                           plan=plan, run=run, step_idx=step["idx"])
        snap["enabled"] = en.stdout.strip().lower()
    if words[0] != words[1]:
        return snap, RecoveryLevel.NONE, f"state not stable across reads ({words})"
    if words[0] not in KNOWN_WORDS:
        return snap, RecoveryLevel.NONE, f"unrecognised state '{words[0]}'"
    if not step["rollback_candidates"]:
        return snap, RecoveryLevel.EXPORT_ONLY, "state captured but no authorised rollback operation"
    return snap, RecoveryLevel.VERIFIED, "state captured twice and rollback operations are authorised"


def _package_version(task, device, plan, run, step, **_) -> tuple[dict, RecoveryLevel, str]:
    r = run_operation(task, device, step["state_probe"]["operation"], step["state_probe"]["params"], phase="backup",
                      plan=plan, run=run, step_idx=step["idx"])
    ver = r.stdout.strip()
    if not r.ok or not ver:
        return {"version": ver}, RecoveryLevel.NONE, "package version could not be recorded"
    return {"version": ver}, RecoveryLevel.EXPORT_ONLY, "version recorded; downgrade is not guaranteed"


STRATEGIES = {
    "service_state": lambda *a, **k: _service_state(*a, windows=False, **k),
    "service_state_win": lambda *a, **k: _service_state(*a, windows=True, **k),
    "package_version": _package_version,
}


def create_and_verify(task: Task, device: Device, plan: ChangePlan, run: ExecutionRun, step: dict) -> RecoveryCheck:
    s = session()
    strat = STRATEGIES.get(step["backup"])
    if strat is None:
        raise BackupFailed(f"unknown backup strategy '{step['backup']}'")
    snap, level, detail = strat(task, device, plan, run, step)
    blob = json.dumps(snap, sort_keys=True)
    b = Backup(tenant_id=task.tenant_id, run_id=run.id, step_idx=step["idx"], strategy=step["backup"],
               location="db:backups", checksum=hashlib.sha256(blob.encode()).hexdigest(), snapshot=snap,
               status="created")
    s.add(b)
    s.flush()
    need = RecoveryLevel[step["min_recovery"]]
    passed = level >= need and level > RecoveryLevel.NONE
    b.status = "verified" if passed else "failed"
    rc = RecoveryCheck(tenant_id=task.tenant_id, run_id=run.id, backup_id=b.id, level=level.name, passed=passed,
                       detail=f"{detail}; required={need.name}")
    s.add(rc)
    s.flush()
    if not passed:
        raise BackupFailed(f"step {step['idx']} ({step['operation']}): recoverability {level.name} < required "
                           f"{need.name} — {detail}")
    return rc
