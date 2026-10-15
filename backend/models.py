"""Core database entities.  All client-owned records are TenantScoped."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary,
                        String, Text, UniqueConstraint, event)
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import Mapped, mapped_column

from backend.db import Base
from backend.tenancy import TenantScoped


LongText = Text().with_variant(MEDIUMTEXT(), "mysql")  # MySQL TEXT caps at 64KB


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC, portable across MySQL/SQLite


def _pk() -> Mapped[int]:
    return mapped_column(Integer, primary_key=True, autoincrement=True)


def _ts(**kw):
    return mapped_column(DateTime, default=utcnow, **kw)


# --------------------------------------------------------------------------- identity
class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = _pk()
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)  # per-tenant data key, wrapped by master key
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()


class User(TenantScoped, Base):
    __tablename__ = "users"
    id: Mapped[int] = _pk()
    email: Mapped[str] = mapped_column(String(255), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(40))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- clients & assets
class Client(TenantScoped, Base):
    __tablename__ = "clients"
    id: Mapped[int] = _pk()
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="active")
    # cloud_allowed | local_only | disabled : where client data may be sent for AI analysis
    ai_policy: Mapped[str] = mapped_column(String(20), default="local_only")
    maintenance_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    autotask_company_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()


class Site(TenantScoped, Base):
    __tablename__ = "sites"
    id: Mapped[int] = _pk()
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"))
    name: Mapped[str] = mapped_column(String(200))
    address: Mapped[str] = mapped_column(String(300), default="")
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")


class Device(TenantScoped, Base):
    __tablename__ = "devices"
    id: Mapped[int] = _pk()
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id"), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255))
    address: Mapped[str] = mapped_column(String(255))
    # linux | windows | voip | web | router | firewall | hyperv | backup
    device_type: Mapped[str] = mapped_column(String(30))
    # ssh | winrm | http | fake
    connector: Mapped[str] = mapped_column(String(20), default="ssh")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"), nullable=True)
    labels: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. {"vendor": "vyos", "scheme": "https"}
    prtg_device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    autotask_ci_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = _ts()


class DeviceCapability(TenantScoped, Base):
    __tablename__ = "device_capabilities"
    id: Mapped[int] = _pk()
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    capability: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class DeviceDependency(TenantScoped, Base):
    __tablename__ = "device_dependencies"
    id: Mapped[int] = _pk()
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    depends_on_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    kind: Mapped[str] = mapped_column(String(40), default="runtime")


class Credential(TenantScoped, Base):
    __tablename__ = "credentials"
    id: Mapped[int] = _pk()
    client_id: Mapped[int | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(30))  # ssh_password | ssh_key | winrm_password | api_token
    username: Mapped[str] = mapped_column(String(200), default="")
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)  # Fernet(tenant DEK) of JSON secret payload
    created_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = _ts()
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CredentialAccessAudit(TenantScoped, Base):
    __tablename__ = "credential_access_audit"
    id: Mapped[int] = _pk()
    credential_id: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(100))
    purpose: Mapped[str] = mapped_column(String(200))
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- tasks & workflow
class Task(TenantScoped, Base):
    __tablename__ = "tasks"
    id: Mapped[int] = _pk()
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"))
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    requested_by: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(LongText, default="")
    mode: Mapped[str] = mapped_column(String(20))  # analysis_only | maintenance
    state: Mapped[str] = mapped_column(String(30), default="SUBMITTED", index=True)
    source: Mapped[str] = mapped_column(String(20), default="manual")  # manual | autotask | prtg
    source_ref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class TaskStep(TenantScoped, Base):
    __tablename__ = "task_steps"
    id: Mapped[int] = _pk()
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(30))
    name: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20), default="pending")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = _ts()


class WorkflowEvent(TenantScoped, Base):
    __tablename__ = "workflow_events"
    id: Mapped[int] = _pk()
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    from_state: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_state: Mapped[str] = mapped_column(String(30))
    actor: Mapped[str] = mapped_column(String(100))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- investigation
class Investigation(TenantScoped, Base):
    __tablename__ = "investigations"
    id: Mapped[int] = _pk()
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(20), default="low")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    uncertainty: Mapped[list] = mapped_column(JSON, default=list)
    ai_used: Mapped[str] = mapped_column(String(60), default="none")
    created_at: Mapped[datetime] = _ts()


class Evidence(TenantScoped, Base):
    __tablename__ = "evidence"
    id: Mapped[int] = _pk()
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"), nullable=True, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    phase: Mapped[str] = mapped_column(String(20), default="diagnostics")
    operation: Mapped[str] = mapped_column(String(80))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    command_display: Mapped[str] = mapped_column(LongText, default="")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_sanitized: Mapped[str] = mapped_column(LongText, default="")
    output_sha256: Mapped[str] = mapped_column(String(64), default="")
    raw_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary(16_000_000), nullable=True)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = _ts()


class DiagnosticResult(TenantScoped, Base):
    __tablename__ = "diagnostic_results"
    id: Mapped[int] = _pk()
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    agent: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))
    summary: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    uncertainty: Mapped[list] = mapped_column(JSON, default=list)
    proposals: Mapped[list] = mapped_column(JSON, default=list)
    ai_used: Mapped[str] = mapped_column(String(60), default="none")
    created_at: Mapped[datetime] = _ts()


class LlmCall(TenantScoped, Base):
    __tablename__ = "llm_calls"
    id: Mapped[int] = _pk()
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider: Mapped[str] = mapped_column(String(30))
    model: Mapped[str] = mapped_column(String(80), default="")
    purpose: Mapped[str] = mapped_column(String(60))
    prompt: Mapped[str] = mapped_column(LongText, default="")
    response: Mapped[str] = mapped_column(LongText, default="")
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- change management
class ChangePlan(TenantScoped, Base):
    __tablename__ = "change_plans"
    id: Mapped[int] = _pk()
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    steps: Mapped[list] = mapped_column(JSON)          # frozen after creation
    canonical: Mapped[str] = mapped_column(LongText)       # canonical JSON that was hashed
    plan_hash: Mapped[str] = mapped_column(String(64))
    # pending_approval | approved | rejected | expired | executing | executed | superseded
    status: Mapped[str] = mapped_column(String(24), default="pending_approval")
    recovery_level: Mapped[str] = mapped_column(String(20))
    risk: Mapped[str] = mapped_column(String(20))
    requires_second_approver: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_no_rollback_ack: Mapped[bool] = mapped_column(Boolean, default=False)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = _ts()

    FROZEN = ("task_id", "version", "steps", "canonical", "plan_hash", "recovery_level", "risk",
              "requires_second_approver", "requires_no_rollback_ack", "created_by", "expires_at")


class Approval(TenantScoped, Base):
    __tablename__ = "approvals"
    id: Mapped[int] = _pk()
    plan_id: Mapped[int] = mapped_column(ForeignKey("change_plans.id"), index=True)
    plan_hash: Mapped[str] = mapped_column(String(64))
    approver_id: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(10))  # approve | reject
    comment: Mapped[str] = mapped_column(Text, default="")
    acknowledged_no_rollback: Mapped[bool] = mapped_column(Boolean, default=False)
    at: Mapped[datetime] = _ts()


class ApprovalEvent(TenantScoped, Base):
    __tablename__ = "approval_events"
    id: Mapped[int] = _pk()
    plan_id: Mapped[int] = mapped_column(ForeignKey("change_plans.id"), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(100))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- execution
class ExecutionRun(TenantScoped, Base):
    __tablename__ = "execution_runs"
    id: Mapped[int] = _pk()
    plan_id: Mapped[int] = mapped_column(ForeignKey("change_plans.id"), index=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="PRECHECKING")
    gate_results: Mapped[dict] = mapped_column(JSON, default=dict)
    before_state: Mapped[dict] = mapped_column(JSON, default=dict)
    after_state: Mapped[dict] = mapped_column(JSON, default=dict)
    state_diff: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = _ts()
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ExecutionStep(TenantScoped, Base):
    __tablename__ = "execution_steps"
    __table_args__ = (UniqueConstraint("idempotency_key", name="uq_exec_step_idem"),)
    id: Mapped[int] = _pk()
    run_id: Mapped[int] = mapped_column(ForeignKey("execution_runs.id"), index=True)
    step_idx: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(160))
    operation: Mapped[str] = mapped_column(String(80))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    # pending | started | succeeded | failed | unknown | rolled_back
    status: Mapped[str] = mapped_column(String(20), default="pending")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_sanitized: Mapped[str] = mapped_column(LongText, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Backup(TenantScoped, Base):
    __tablename__ = "backups"
    id: Mapped[int] = _pk()
    run_id: Mapped[int] = mapped_column(ForeignKey("execution_runs.id"), index=True)
    step_idx: Mapped[int] = mapped_column(Integer)
    strategy: Mapped[str] = mapped_column(String(60))
    location: Mapped[str] = mapped_column(String(300), default="")
    checksum: Mapped[str] = mapped_column(String(64), default="")
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="created")
    created_at: Mapped[datetime] = _ts()


class RecoveryCheck(TenantScoped, Base):
    __tablename__ = "recovery_checks"
    id: Mapped[int] = _pk()
    run_id: Mapped[int] = mapped_column(ForeignKey("execution_runs.id"), index=True)
    backup_id: Mapped[int] = mapped_column(ForeignKey("backups.id"))
    level: Mapped[str] = mapped_column(String(20))  # NONE | EXPORT_ONLY | VERIFIED
    passed: Mapped[bool] = mapped_column(Boolean)
    detail: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = _ts()


class VerificationResult(TenantScoped, Base):
    __tablename__ = "verification_results"
    id: Mapped[int] = _pk()
    run_id: Mapped[int] = mapped_column(ForeignKey("execution_runs.id"), index=True)
    step_idx: Mapped[int | None] = mapped_column(Integer, nullable=True)
    check: Mapped[str] = mapped_column(String(120))
    passed: Mapped[bool] = mapped_column(Boolean)
    detail: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = _ts()


class RollbackRun(TenantScoped, Base):
    __tablename__ = "rollback_runs"
    id: Mapped[int] = _pk()
    run_id: Mapped[int] = mapped_column(ForeignKey("execution_runs.id"), index=True)
    status: Mapped[str] = mapped_column(String(20))  # succeeded | failed | not_possible
    steps: Mapped[list] = mapped_column(JSON, default=list)
    state_restored: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    at: Mapped[datetime] = _ts()


class DeviceLock(TenantScoped, Base):
    __tablename__ = "device_locks"
    __table_args__ = (UniqueConstraint("device_id", name="uq_device_lock"),)
    id: Mapped[int] = _pk()
    device_id: Mapped[int] = mapped_column(Integer)
    run_id: Mapped[int] = mapped_column(Integer)
    acquired_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = mapped_column(DateTime)


# --------------------------------------------------------------------------- integrations
class IntegrationAccount(TenantScoped, Base):
    __tablename__ = "integration_accounts"
    id: Mapped[int] = _pk()
    kind: Mapped[str] = mapped_column(String(30))  # autotask | prtg | ollama | shadowprotect
    name: Mapped[str] = mapped_column(String(100))
    base_url: Mapped[str] = mapped_column(String(300), default="")
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"), nullable=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Ticket(TenantScoped, Base):
    __tablename__ = "tickets"
    __table_args__ = (UniqueConstraint("tenant_id", "integration_id", "external_id", name="uq_ticket_ext"),)
    id: Mapped[int] = _pk()
    integration_id: Mapped[int] = mapped_column(ForeignKey("integration_accounts.id"))
    external_id: Mapped[str] = mapped_column(String(64))
    client_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(300), default="")
    status: Mapped[str] = mapped_column(String(30), default="open")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()


class MonitoringAlert(TenantScoped, Base):
    __tablename__ = "monitoring_alerts"
    __table_args__ = (UniqueConstraint("tenant_id", "integration_id", "external_id", name="uq_alert_ext"),)
    id: Mapped[int] = _pk()
    integration_id: Mapped[int] = mapped_column(ForeignKey("integration_accounts.id"))
    external_id: Mapped[str] = mapped_column(String(64))
    device_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    task_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sensor: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(30), default="down")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = _ts()


# --------------------------------------------------------------------------- audit & reporting
class AuditEvent(Base):
    """Append-only, hash-chained.  tenant_id is NULL for platform-level events.

    Deliberately *not* TenantScoped: the chain must be readable for verification
    and written for platform events; reads go through backend.audit only.
    """
    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("tenant_id", "seq", name="uq_audit_chain"),)
    id: Mapped[int] = _pk()
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    seq: Mapped[int] = mapped_column(Integer)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    object_type: Mapped[str] = mapped_column(String(60), default="")
    object_id: Mapped[str] = mapped_column(String(60), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    at: Mapped[datetime] = mapped_column(DateTime)


@event.listens_for(AuditEvent, "before_update")
def _audit_no_update(*_):
    raise PermissionError("audit_events is append-only")


@event.listens_for(AuditEvent, "before_delete")
def _audit_no_delete(*_):
    raise PermissionError("audit_events is append-only")


@event.listens_for(ChangePlan, "before_update")
def _plan_immutable(mapper, connection, target):
    from sqlalchemy import inspect
    state = inspect(target)
    for attr in ChangePlan.FROZEN:
        if state.attrs[attr].history.has_changes():
            raise PermissionError(f"change plan field '{attr}' is immutable")


class Report(TenantScoped, Base):
    __tablename__ = "reports"
    id: Mapped[int] = _pk()
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30), default="incident")
    title: Mapped[str] = mapped_column(String(300))
    content: Mapped[str] = mapped_column(LongText)
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = _ts()


class TimeEntry(TenantScoped, Base):
    __tablename__ = "time_entries"
    id: Mapped[int] = _pk()
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(20), default="system")
    started_at: Mapped[datetime] = mapped_column(DateTime)
    ended_at: Mapped[datetime] = mapped_column(DateTime)
    minutes: Mapped[float] = mapped_column(Float, default=0)
    note: Mapped[str] = mapped_column(Text, default="")
    posted_external: Mapped[bool] = mapped_column(Boolean, default=False)
