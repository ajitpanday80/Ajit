"""Tenant isolation enforced at the ORM layer.

Every ``TenantScoped`` model gets an automatic ``tenant_id == <ctx>`` filter on
every SELECT (including lazy loads) and a flush-time check that rows are never
created for, or moved to, another tenant.  With no context active, tenant-scoped
queries return nothing: forgetting to set a context fails closed, not open.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from sqlalchemy import event, false
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria
from sqlalchemy import ForeignKey, Integer


class TenantViolation(Exception):
    pass


@dataclass(frozen=True)
class TenantContext:
    tenant_id: int | None
    system: bool = False  # explicit, audited bypass for workers/login/bootstrap


_ctx: ContextVar[TenantContext | None] = ContextVar("tenant_ctx", default=None)


def current() -> TenantContext | None:
    return _ctx.get()


@contextmanager
def tenant_scope(tenant_id: int):
    tok = _ctx.set(TenantContext(tenant_id))
    try:
        yield
    finally:
        _ctx.reset(tok)


@contextmanager
def system_scope():
    """Cross-tenant access.  Use only for login lookup, bootstrap and the job runner."""
    tok = _ctx.set(TenantContext(None, system=True))
    try:
        yield
    finally:
        _ctx.reset(tok)


def set_tenant(tenant_id: int):
    """Imperative form for request lifecycles; pair with ``reset(token)``."""
    return _ctx.set(TenantContext(tenant_id))


def reset(token) -> None:
    _ctx.reset(token)


class TenantScoped:
    """Mixin: rows belong to exactly one tenant."""

    tenant_id: Mapped[int] = mapped_column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)


@event.listens_for(Session, "do_orm_execute")
def _apply_tenant_filter(state):
    if not state.is_select or state.is_column_load:
        return
    ctx = current()
    if ctx is not None and ctx.system:
        return
    if ctx is None or ctx.tenant_id is None:
        state.statement = state.statement.options(
            with_loader_criteria(TenantScoped, lambda cls: false(), include_aliases=True)
        )
        return
    tid = ctx.tenant_id
    state.statement = state.statement.options(
        with_loader_criteria(TenantScoped, lambda cls: cls.tenant_id == tid, include_aliases=True)
    )


@event.listens_for(Session, "before_flush")
def _guard_writes(session, flush_context, instances):
    ctx = current()
    if ctx is not None and ctx.system:
        for obj in session.new:
            if isinstance(obj, TenantScoped) and obj.tenant_id is None:
                raise TenantViolation("system scope writes must set tenant_id explicitly")
        return
    for obj in list(session.new):
        if isinstance(obj, TenantScoped):
            if ctx is None or ctx.tenant_id is None:
                raise TenantViolation("no tenant context for write")
            if obj.tenant_id is None:
                obj.tenant_id = ctx.tenant_id
            elif obj.tenant_id != ctx.tenant_id:
                raise TenantViolation("cross-tenant write blocked")
    for obj in session.dirty:
        if isinstance(obj, TenantScoped):
            if ctx is None or ctx.tenant_id != obj.tenant_id:
                raise TenantViolation("cross-tenant update blocked")
    for obj in session.deleted:
        if isinstance(obj, TenantScoped):
            if ctx is None or ctx.tenant_id != obj.tenant_id:
                raise TenantViolation("cross-tenant delete blocked")
