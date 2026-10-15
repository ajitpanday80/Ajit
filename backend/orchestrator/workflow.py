"""Explicit task state machine.  Every transition is validated, persisted and audited."""
from __future__ import annotations

from sqlalchemy import func, select, update

from backend import audit
from backend.db import session
from backend.models import Task, WorkflowEvent, utcnow

TRANSITIONS: dict[str, set[str]] = {
    "SUBMITTED": {"DIAGNOSING", "CANCELLED", "FAILED"},
    "DIAGNOSING": {"ANALYZING", "FAILED", "CANCELLED"},
    "ANALYZING": {"COMPLETED", "AWAITING_APPROVAL", "FAILED"},
    "AWAITING_APPROVAL": {"APPROVED", "REJECTED", "CANCELLED", "EXPIRED"},
    "EXPIRED": {"AWAITING_APPROVAL", "CANCELLED"},          # re-planned
    "APPROVED": {"PRECHECKING", "CANCELLED", "EXPIRED"},
    "PRECHECKING": {"BACKING_UP", "ABORTED"},
    "BACKING_UP": {"EXECUTING", "ABORTED"},
    "EXECUTING": {"VERIFYING", "ROLLING_BACK", "NEEDS_HUMAN"},
    "VERIFYING": {"SUCCEEDED", "ROLLING_BACK", "NEEDS_HUMAN"},
    "ROLLING_BACK": {"ROLLED_BACK", "NEEDS_HUMAN"},
    # terminal
    "COMPLETED": set(), "REJECTED": set(), "ABORTED": set(), "SUCCEEDED": set(), "FAILED": set(),
    "ROLLED_BACK": set(), "NEEDS_HUMAN": set(), "CANCELLED": set(),
}
TERMINAL = {s for s, nxt in TRANSITIONS.items() if not nxt}


class InvalidTransition(Exception):
    pass


def advance(task: Task, to_state: str, *, actor: str = "system", detail: dict | None = None) -> None:
    s = session()
    s.refresh(task)  # pick up concurrent changes
    frm = task.state
    if to_state not in TRANSITIONS.get(frm, set()):
        raise InvalidTransition(f"{frm} -> {to_state} is not allowed")
    # optimistic lock: only one worker may move the task from this version
    rows = s.execute(update(Task).where(Task.id == task.id, Task.version == task.version)
                     .values(state=to_state, version=task.version + 1, updated_at=utcnow(),
                             completed_at=utcnow() if to_state in TERMINAL else None)).rowcount
    if rows != 1:
        raise InvalidTransition("task was modified concurrently")
    seq = (s.scalar(select(func.max(WorkflowEvent.seq)).where(WorkflowEvent.task_id == task.id)) or 0) + 1
    s.add(WorkflowEvent(tenant_id=task.tenant_id, task_id=task.id, seq=seq, from_state=frm, to_state=to_state,
                        actor=actor, detail=detail or {}))
    audit.record("task.transition", actor=actor, tenant_id=task.tenant_id, object_type="task",
                 object_id=task.id, detail={"from": frm, "to": to_state, **(detail or {})})
    s.flush()
    s.refresh(task)
