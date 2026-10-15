"""The single choke point between the platform and remote systems.

policy → credential checkout (audited) → connector → sanitise → evidence.
This is the only module permitted to call ``get_connector`` (see tests/test_architecture.py).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from backend import evidence as ev
from backend.connectors.base import ConnectionLost, ConnectorError, ExecResult, get_connector
from backend.db import session
from backend.models import ChangePlan, Device, Evidence, ExecutionRun, Task
from backend.operations import parsers
from backend.operations.registry import OperationSpec, RenderedCommand, get_spec, render
from backend.policies.engine import OpRequest
from backend.services import svc


@dataclass
class OpResult:
    evidence: Evidence
    result: ExecResult
    spec: OperationSpec
    ok: bool           # exit code in spec.success_codes
    parsed: object = None

    @property
    def stdout(self) -> str:
        return self.result.stdout


def run_operation(task: Task, device: Device, operation: str, params: dict | None, *, phase: str = "diagnostics",
                  actor_role: str | None = None, plan: ChangePlan | None = None, run: ExecutionRun | None = None,
                  step_idx: int | None = None, actor: str = "system") -> OpResult:
    s = svc()
    spec = get_spec(operation)
    cmd: RenderedCommand = render(spec, params)          # validates parameters
    s.policy.require(OpRequest(task=task, device=device, operation=operation, params=cmd.params, phase=phase,
                               actor_role=actor_role, plan=plan, run=run, step_idx=step_idx))
    cred = None
    secrets: tuple[str, ...] = ()
    if device.credential_id:
        cred = s.vault.checkout(device.credential_id, actor=actor, purpose=f"{phase}:{operation}", task_id=task.id)
        secrets = tuple(v for k, v in cred.items() if k in ("password", "private_key", "token", "passphrase") and v)
    connector = get_connector(device, cred, spec.interpreter)
    started = time.monotonic()
    error = None
    res: ExecResult | None = None
    try:
        res = connector.run(cmd)
    except ConnectorError as e:
        error = f"{type(e).__name__}: {e}"
        raise
    finally:
        try:
            connector.close()
        except Exception:  # pragma: no cover
            pass
        raw = res.output if res else ""
        text, truncated = ev.sanitize(raw, secrets, s.cfg.evidence_max_chars)
        e = Evidence(tenant_id=task.tenant_id, task_id=task.id, device_id=device.id, phase=phase,
                     operation=operation, params=cmd.params, command_display=ev.sanitize(cmd.display, secrets)[0],
                     exit_code=res.exit_code if res else None, output_sanitized=text, output_sha256=ev.sha256(text),
                     truncated=truncated, duration_ms=res.duration_ms if res else int((time.monotonic() - started) * 1000),
                     error=error, raw_encrypted=s.vault.encrypt_for_tenant(task.tenant_id, raw.encode()) if raw else None)
        session().add(e)
        session().flush()
    ok = res.exit_code in spec.success_codes
    return OpResult(e, res, spec, ok, parsers.parse(spec.parser, res.stdout) if ok else None)


def run_with_reconnect(*args, retries: int | None = None, **kwargs) -> OpResult:
    """READ-ONLY helper: retry transport failures with a short delay.  Never used for mutations."""
    s = svc()
    n = s.cfg.connect_retries if retries is None else retries
    last: Exception | None = None
    for attempt in range(max(n, 1)):
        try:
            return run_operation(*args, **kwargs)
        except ConnectorError as e:
            last = e
            time.sleep(s.cfg.connect_retry_delay)
    assert last is not None
    raise last
