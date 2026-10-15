"""MSP integrations: Autotask tickets, PRTG alerts, local-model review.

Defaults are conservative: notes + time entries are posted; PRTG acknowledgement and ticket closure are
opt-in per integration and only happen after *verified* success (see ``closure_allowed``).
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from backend import audit
from backend.connectors.autotask.client import AutotaskClient
from backend.connectors.prtg.client import PrtgClient
from backend.db import session
from backend.models import (Client, Device, ExecutionRun, IntegrationAccount, MonitoringAlert, Report, Task, Ticket,
                            TimeEntry, VerificationResult)
from backend.services import svc

log = logging.getLogger(__name__)


# ------------------------------------------------------------------ ingest
def _create_task(integration: IntegrationAccount, client: Client, device: Device, title: str, desc: str,
                 source: str, ref: str) -> Task:
    mode = integration.settings.get("default_mode", "analysis_only")
    t = Task(tenant_id=integration.tenant_id, client_id=client.id, device_id=device.id, title=title[:300],
             description=desc[:8000], mode=mode if mode in ("analysis_only", "maintenance") else "analysis_only",
             source=source, source_ref=ref)
    session().add(t)
    session().flush()
    audit.record("task.create", actor=f"integration:{integration.kind}", tenant_id=t.tenant_id, object_type="task",
                 object_id=t.id, detail={"source": source, "ref": ref})
    return t


def ingest_autotask_ticket(integration: IntegrationAccount, payload: dict) -> tuple[Ticket, Task | None]:
    s = session()
    ext = str(payload["id"])
    tk = s.scalar(select(Ticket).where(Ticket.integration_id == integration.id, Ticket.external_id == ext))
    if tk is not None:
        return tk, s.get(Task, tk.task_id) if tk.task_id else None            # idempotent webhook delivery
    client = s.scalar(select(Client).where(Client.autotask_company_id == str(payload.get("companyID", ""))))
    device = None
    if client:
        q = select(Device).where(Device.client_id == client.id)
        ci, host = payload.get("configurationItemID"), payload.get("deviceHostname")
        device = (s.scalar(q.where(Device.autotask_ci_id == str(ci))) if ci else None) or \
                 (s.scalar(q.where(Device.hostname == host)) if host else None)
    tk = Ticket(tenant_id=integration.tenant_id, integration_id=integration.id, external_id=ext,
                client_id=client.id if client else None, device_id=device.id if device else None,
                title=str(payload.get("title", ""))[:300], status="correlated" if device else "uncorrelated", payload=payload)
    s.add(tk)
    s.flush()
    task = None
    if client and device:
        task = _create_task(integration, client, device, f"Ticket {ext}: {tk.title}", str(payload.get("description", "")),
                            "autotask", ext)
        tk.task_id = task.id
    return tk, task


def ingest_prtg_alert(integration: IntegrationAccount, payload: dict) -> tuple[MonitoringAlert, Task | None]:
    s = session()
    ext = str(payload["sensorid"])
    al = s.scalar(select(MonitoringAlert).where(MonitoringAlert.integration_id == integration.id,
                                                MonitoringAlert.external_id == ext, MonitoringAlert.acknowledged == False))  # noqa: E712
    if al is not None and al.task_id:
        return al, s.get(Task, al.task_id)
    device = s.scalar(select(Device).where(Device.prtg_device_id == str(payload.get("deviceid", ""))))
    al = MonitoringAlert(tenant_id=integration.tenant_id, integration_id=integration.id, external_id=ext,
                         device_id=device.id if device else None, sensor=str(payload.get("sensor", ""))[:200],
                         status=str(payload.get("status", "down"))[:30], payload=payload)
    s.add(al)
    s.flush()
    task = None
    if device:
        client = s.get(Client, device.client_id)
        task = _create_task(integration, client, device, f"PRTG alert: {al.sensor} {al.status}",
                            str(payload.get("message", "")), "prtg", ext)
        al.task_id = task.id
    return al, task


# ------------------------------------------------------------------ outcome
def closure_allowed(task: Task, integration: IntegrationAccount, client: Client) -> tuple[bool, str]:
    """Explicit, deterministic ticket-closure rules.  All must hold."""
    s = session()
    if not integration.settings.get("auto_close", False):
        return False, "auto_close not enabled for this integration"
    if not client.settings.get("allow_auto_close", False):
        return False, "auto close not enabled for this client"
    if task.mode != "maintenance" or task.state != "SUCCEEDED":
        return False, f"task ended {task.state}, not a verified maintenance success"
    run = s.scalar(select(ExecutionRun).where(ExecutionRun.task_id == task.id).order_by(ExecutionRun.id.desc()))
    if run is None or run.status != "SUCCEEDED":
        return False, "no successful execution run"
    bad = s.scalar(select(VerificationResult).where(VerificationResult.run_id == run.id, VerificationResult.passed == False))  # noqa: E712
    final_ok = s.scalar(select(VerificationResult).where(VerificationResult.run_id == run.id,
                                                         VerificationResult.check.like("final check%")))
    if final_ok is None:
        return False, "no final verification recorded"
    # a transient failed attempt during polling is tolerated only if the *final* checks all passed
    finals = list(s.scalars(select(VerificationResult).where(VerificationResult.run_id == run.id,
                                                             VerificationResult.check.like("final check%"))))
    if not all(v.passed for v in finals):
        return False, "a final verification check failed"
    return True, "all closure rules passed"


def post_task_outcome(task: Task, report: Report) -> None:
    s = session()
    s.flush()
    ticket = s.scalar(select(Ticket).where(Ticket.task_id == task.id))
    client = s.get(Client, task.client_id)
    if ticket:
        integ = s.get(IntegrationAccount, ticket.integration_id)
        if integ and integ.enabled and integ.kind == "autotask":
            _autotask_post(task, ticket, integ, client, report)
    alert = s.scalar(select(MonitoringAlert).where(MonitoringAlert.task_id == task.id))
    if alert:
        integ = s.get(IntegrationAccount, alert.integration_id)
        if integ and integ.enabled and integ.kind == "prtg":
            _prtg_ack(task, alert, integ)


def _creds(integ: IntegrationAccount) -> dict:
    return svc().vault.checkout(integ.credential_id, actor=f"integration:{integ.kind}", purpose="integration call") \
        if integ.credential_id else {}


def _autotask_post(task, ticket, integ, client, report) -> None:
    s = session()
    cred = _creds(integ)
    at = AutotaskClient(integ.base_url, cred.get("username", ""), cred.get("secret", ""),
                        integ.settings.get("integration_code", ""))
    try:
        summary = f"Automated {task.mode.replace('_', ' ')} finished: {task.state}. {task.result.get('note', '')}".strip()
        at.add_note(ticket.external_id, f"Platform result: {task.state}", summary + "\n\n" + report.content[:8000])
        te = s.scalar(select(TimeEntry).where(TimeEntry.task_id == task.id, TimeEntry.posted_external == False))  # noqa: E712
        if te and integ.settings.get("post_time", True):
            at.add_time_entry(ticket.external_id, te.minutes, te.note, integ.settings.get("resource_id"))
            te.posted_external = True
        ok, why = closure_allowed(task, integ, client)
        if ok:
            at.set_status(ticket.external_id, int(integ.settings["resolved_status_id"]))
            ticket.status = "closed"
            audit.record("ticket.closed", actor="system", tenant_id=task.tenant_id, object_type="ticket", object_id=ticket.id)
        else:
            at.add_note(ticket.external_id, "Closure not performed", f"Ticket left open for a technician: {why}")
            audit.record("ticket.closure_withheld", actor="system", tenant_id=task.tenant_id, object_type="ticket",
                         object_id=ticket.id, detail={"reason": why})
    except Exception as e:  # noqa: BLE001
        audit.record("integration.error", tenant_id=task.tenant_id, object_type="ticket", object_id=ticket.id,
                     detail={"error": str(e)[:300]})
        log.warning("autotask post failed: %s", e)


def _prtg_ack(task, alert, integ) -> None:
    if not integ.settings.get("auto_ack", False):
        return
    if task.state != "SUCCEEDED":                      # never silence a monitor unless the fix was verified
        return
    cred = _creds(integ)
    try:
        PrtgClient(integ.base_url, cred.get("token", ""), verify_tls=integ.settings.get("verify_tls", True)) \
            .acknowledge(int(alert.external_id), f"Resolved by platform (task {task.id})")
        alert.acknowledged = True
        audit.record("alert.acknowledged", tenant_id=task.tenant_id, object_type="alert", object_id=alert.id)
    except Exception as e:  # noqa: BLE001
        audit.record("integration.error", tenant_id=task.tenant_id, object_type="alert", object_id=alert.id,
                     detail={"error": str(e)[:300]})
