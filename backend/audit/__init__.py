"""Tamper-evident audit trail (per-tenant hash chain)."""
from __future__ import annotations

import hashlib
import json

from sqlalchemy import select

from backend.db import session
from backend.models import AuditEvent, utcnow

GENESIS = "0" * 64


def _digest(prev: str, tenant_id, seq: int, actor: str, action: str, otype: str, oid: str,
            detail: dict, at: str) -> str:
    body = json.dumps([prev, tenant_id, seq, actor, action, otype, oid, detail, at],
                      sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def record(action: str, *, actor: str = "system", tenant_id: int | None = None,
           object_type: str = "", object_id="", detail: dict | None = None) -> AuditEvent:
    s = session()
    last = s.execute(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
                     .order_by(AuditEvent.seq.desc()).limit(1)).scalar_one_or_none()
    seq = (last.seq + 1) if last else 1
    prev = last.hash if last else GENESIS
    at = utcnow().replace(microsecond=0)
    detail = json.loads(json.dumps(detail or {}, default=str))
    ev = AuditEvent(tenant_id=tenant_id, seq=seq, actor=actor, action=action, object_type=object_type,
                    object_id=str(object_id), detail=detail, prev_hash=prev, at=at,
                    hash=_digest(prev, tenant_id, seq, actor, action, object_type, str(object_id),
                                 detail, at.isoformat()))
    s.add(ev)
    s.flush()
    return ev


def list_events(tenant_id: int | None, limit: int = 200, offset: int = 0) -> list[AuditEvent]:
    return list(session().scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
                                  .order_by(AuditEvent.seq.desc()).limit(limit).offset(offset)))


def verify_chain(tenant_id: int | None) -> tuple[bool, int | None]:
    """Return (ok, first_bad_seq)."""
    prev = GENESIS
    expected = 1
    for ev in session().scalars(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
                                .order_by(AuditEvent.seq)):
        if ev.seq != expected or ev.prev_hash != prev:
            return False, ev.seq
        want = _digest(prev, ev.tenant_id, ev.seq, ev.actor, ev.action, ev.object_type, ev.object_id,
                       ev.detail, ev.at.isoformat())
        if want != ev.hash:
            return False, ev.seq
        prev = ev.hash
        expected += 1
    return True, None
