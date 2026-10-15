"""Deterministic policy engine.  AI output is never authorisation; this is.

Every operation passes through ``PolicyEngine.authorize`` immediately before a connector is touched.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from sqlalchemy import func, select

from backend.auth import rbac
from backend.config import Config
from backend.connectors.base import SUPPORTED_INTERPRETERS
from backend.db import session
from backend.models import ChangePlan, Client, Device, Evidence, ExecutionRun, Task, utcnow
from backend.operations.registry import Risk, UnknownOperation, ValidationError, get_spec, validate_params

PHASES = ("diagnostics", "precheck", "verification", "execution", "rollback", "backup")


class PolicyDenied(Exception):
    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


@dataclass
class OpRequest:
    task: Task
    device: Device
    operation: str
    params: dict
    phase: str
    actor_role: str | None = None          # None => platform-internal actor (worker)
    plan: ChangePlan | None = None
    run: ExecutionRun | None = None
    step_idx: int | None = None


@dataclass
class Decision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def evaluate(self, r: OpRequest) -> Decision:
        deny: list[str] = []
        if r.phase not in PHASES:
            return Decision(False, [f"unknown phase '{r.phase}'"])
        try:
            spec = get_spec(r.operation)
            validate_params(spec, r.params)
        except UnknownOperation:
            return Decision(False, [f"operation '{r.operation}' is not registered"])
        except ValidationError as e:
            return Decision(False, [f"invalid parameters: {e}"])

        # --- scope
        if r.task.device_id != r.device.id or r.task.tenant_id != r.device.tenant_id:
            deny.append("device is outside the task scope")
        if r.device.status != "active":
            deny.append("device is not active")
        client = session().get(Client, r.device.client_id)
        if client is None or client.status != "active" or client.id != r.task.client_id:
            deny.append("client inactive or outside task scope")
        if r.device.device_type not in spec.device_types:
            deny.append(f"operation not supported on device type '{r.device.device_type}'")
        if spec.interpreter not in SUPPORTED_INTERPRETERS.get(r.device.connector, set()):
            deny.append(f"device connector '{r.device.connector}' cannot run '{spec.interpreter}' operations")

        # --- role (diagnostics requested by a human)
        if r.actor_role is not None and r.phase == "diagnostics" and not rbac.has(r.actor_role, "task.create"):
            deny.append("role may not run diagnostics")

        # --- risk vs phase
        if r.phase in ("diagnostics", "precheck", "verification", "backup"):
            if spec.risk != Risk.READ:
                deny.append(f"{r.phase} phase is read-only; '{r.operation}' is a mutation")
        if r.phase == "diagnostics":
            n = session().scalar(select(func.count(Evidence.id)).where(
                Evidence.device_id == r.device.id,
                Evidence.collected_at > utcnow() - dt.timedelta(minutes=1))) or 0
            if n >= self.cfg.max_diag_ops_per_minute_per_device:
                deny.append("per-device rate limit exceeded")

        if r.phase == "execution":
            deny += self._check_execution(r, spec)
        if r.phase == "rollback":
            deny += self._check_rollback(r)
        return Decision(not deny, deny)

    # ---------------------------------------------------------------- execution / rollback
    def _check_execution(self, r: OpRequest, spec) -> list[str]:
        from backend.approvals.plans import compute_hash
        d: list[str] = []
        if r.task.mode != "maintenance":
            d.append("task is Analysis Only: modifications are not permitted")
        client = session().get(Client, r.device.client_id)
        if client is None or not client.maintenance_enabled:
            d.append("maintenance is not enabled for this client")
        p, run = r.plan, r.run
        if p is None or run is None or r.step_idx is None:
            return d + ["execution requires an approved plan, a run and a step index"]
        if p.task_id != r.task.id or run.plan_id != p.id or run.task_id != r.task.id:
            d.append("plan/run do not belong to this task")
        if p.status != "executing":
            d.append(f"plan status is '{p.status}', not 'executing'")
        if compute_hash(p.canonical) != p.plan_hash:
            d.append("plan integrity check failed (hash mismatch)")
        if p.expires_at < utcnow():
            d.append("plan approval window expired")
        if not (0 <= r.step_idx < len(p.steps)):
            return d + ["step index out of range"]
        step = p.steps[r.step_idx]
        if step["operation"] != r.operation or step["params"] != validate_params(spec, r.params):
            d.append("operation does not match the approved plan step")
        if run.status not in ("EXECUTING",):
            d.append(f"run status is '{run.status}', not 'EXECUTING'")
        return d

    def _check_rollback(self, r: OpRequest) -> list[str]:
        d: list[str] = []
        p, run = r.plan, r.run
        if p is None or run is None or r.step_idx is None:
            return ["rollback requires plan, run and step index"]
        if run.status != "ROLLING_BACK":
            d.append("run is not rolling back")
        if not (0 <= r.step_idx < len(p.steps)):
            return d + ["step index out of range"]
        if r.operation not in p.steps[r.step_idx].get("rollback_candidates", []):
            d.append("operation is not an approved rollback candidate for this step")
        return d

    def authorize(self, r: OpRequest) -> Decision:
        dec = self.evaluate(r)
        if not dec.allowed:
            from backend import audit
            audit.record("policy.denied", actor=f"role:{r.actor_role or 'system'}", tenant_id=r.task.tenant_id,
                         object_type="task", object_id=r.task.id,
                         detail={"operation": r.operation, "phase": r.phase, "reasons": dec.reasons,
                                 "device_id": r.device.id})
        return dec

    def require(self, r: OpRequest) -> None:
        dec = self.authorize(r)
        if not dec.allowed:
            raise PolicyDenied(dec.reasons)
