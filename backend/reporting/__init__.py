"""Incident reports, time entries and post-run integration hooks."""
from __future__ import annotations

import logging
import math

from sqlalchemy import select

from backend.db import session
from backend.models import (Approval, ChangePlan, Client, Device, Evidence, ExecutionRun, Investigation, Report,
                            RecoveryCheck, RollbackRun, Task, TimeEntry, VerificationResult, WorkflowEvent, utcnow)

log = logging.getLogger(__name__)
TERMINAL_FOR_REPORT = ("COMPLETED", "SUCCEEDED", "FAILED", "ROLLED_BACK", "NEEDS_HUMAN", "ABORTED", "REJECTED")


def build_report(task: Task) -> str:
    s = session()
    device, client = s.get(Device, task.device_id), s.get(Client, task.client_id)
    inv = s.scalar(select(Investigation).where(Investigation.task_id == task.id).order_by(Investigation.id.desc()))
    L = [f"# Incident report: {task.title}", "",
         f"- **Client:** {client.name}", f"- **Device:** {device.hostname} ({device.device_type}, {device.address})",
         f"- **Mode:** {'Analysis Only' if task.mode == 'analysis_only' else 'Troubleshooting & Maintenance'}",
         f"- **Final state:** {task.state}", f"- **Source:** {task.source} {task.source_ref or ''}", ""]
    if inv:
        L += ["## Diagnosis", inv.summary or "_none_", "", f"**Root-cause assessment:** {inv.root_cause or 'undetermined'} "
              f"(confidence: {inv.confidence}; AI: {inv.ai_used})", "", "### Findings"]
        L += [f"- **[{f['severity'].upper()}]** {f['title']} — {f.get('detail', '')[:200]} _(evidence: {f.get('evidence_ids')})_"
              for f in inv.findings] or ["- none"]
        if inv.uncertainty:
            L += ["", "### Uncertainty"] + [f"- {u}" for u in inv.uncertainty]
        if inv.recommendations:
            L += ["", "### Recommendations"] + [f"- {r}" for r in inv.recommendations]
    for plan in s.scalars(select(ChangePlan).where(ChangePlan.task_id == task.id).order_by(ChangePlan.id)):
        L += ["", f"## Change plan v{plan.version} ({plan.status})",
              f"Hash `{plan.plan_hash}` · risk {plan.risk} · recovery {plan.recovery_level}"]
        L += [f"{st['idx'] + 1}. `{st['operation']}` {st['params']} — {st['rationale']}" for st in plan.steps]
        for ap in s.scalars(select(Approval).where(Approval.plan_id == plan.id)):
            L.append(f"- {ap.decision} by user {ap.approver_id} at {ap.at:%Y-%m-%d %H:%M} UTC. {ap.comment}")
    for run in s.scalars(select(ExecutionRun).where(ExecutionRun.task_id == task.id).order_by(ExecutionRun.id)):
        L += ["", f"## Execution run {run.id}: {run.status}"]
        if run.error:
            L.append(f"**Error:** {run.error}")
        L += [f"- gate `{k}`: {'ok' if v['ok'] else 'FAILED'} {v['detail']}" for k, v in (run.gate_results or {}).items()]
        for rc in s.scalars(select(RecoveryCheck).where(RecoveryCheck.run_id == run.id)):
            L.append(f"- recovery check: {rc.level} {'passed' if rc.passed else 'FAILED'} — {rc.detail}")
        for v in s.scalars(select(VerificationResult).where(VerificationResult.run_id == run.id)):
            L.append(f"- verification `{v.check}`: {'pass' if v.passed else 'FAIL'} ({v.detail})")
        if run.state_diff:
            L += ["", "Before/after:"] + [f"- step {k}: `{d['before']}` → `{d['after']}`" for k, d in run.state_diff.items()]
        for rr in s.scalars(select(RollbackRun).where(RollbackRun.run_id == run.id)):
            L.append(f"- rollback: {rr.status} (state restored: {rr.state_restored}) {rr.detail}")
    ev = list(s.scalars(select(Evidence).where(Evidence.task_id == task.id).order_by(Evidence.id)))
    L += ["", "## Evidence log"] + [f"- #{e.id} `{e.operation}` [{e.phase}] exit={e.exit_code} sha256={e.output_sha256[:12]} "
                                    f"{e.collected_at:%H:%M:%S}" for e in ev]
    L += ["", "## Timeline"] + [f"- {w.at:%Y-%m-%d %H:%M:%S} {w.from_state} → {w.to_state} ({w.actor})"
                               for w in s.scalars(select(WorkflowEvent).where(WorkflowEvent.task_id == task.id)
                                                  .order_by(WorkflowEvent.seq))]
    return "\n".join(L)


def finalize_task(task_id: int) -> Report | None:
    """Idempotent: report + time entry + integration hooks once the task is terminal."""
    s = session()
    task = s.get(Task, task_id)
    if task is None or task.state not in TERMINAL_FOR_REPORT:
        return None
    if s.scalar(select(Report).where(Report.task_id == task.id, Report.kind == "incident")):
        return None
    end = task.completed_at or utcnow()
    minutes = max(1, math.ceil((end - task.created_at).total_seconds() / 60))
    s.add(TimeEntry(tenant_id=task.tenant_id, task_id=task.id, source="system", started_at=task.created_at,
                    ended_at=end, minutes=minutes, note=f"Automated investigation: {task.title}"))
    rep = Report(tenant_id=task.tenant_id, task_id=task.id, kind="incident", title=f"Incident report: {task.title}",
                 content=build_report(task))
    s.add(rep)
    s.flush()
    try:
        from backend.integrations.manager import post_task_outcome
        post_task_outcome(task, rep)
    except Exception:  # integrations are best-effort and can never change the outcome
        log.exception("integration hook failed for task %s", task_id)
    return rep
