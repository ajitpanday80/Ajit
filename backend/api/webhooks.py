"""Inbound Autotask / PRTG webhooks.  Authenticated by HMAC-SHA256 of the raw body (``X-Signature``)."""
from __future__ import annotations

import hashlib
import hmac

from flask import Blueprint, request

from backend import audit
from backend.api.common import ApiError
from backend.db import session
from backend.integrations.manager import ingest_autotask_ticket, ingest_prtg_alert
from backend.jobs import enqueue
from backend.models import IntegrationAccount
from backend.services import svc
from backend.tenancy import system_scope, tenant_scope

bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")


def _handle(kind: str, integration_id: int, ingest):
    with system_scope():
        integ = session().get(IntegrationAccount, integration_id)
        if integ is None or integ.kind != kind or not integ.enabled:
            raise ApiError("not found", 404)
        tenant_id, cred_id = integ.tenant_id, integ.credential_id
        secret = svc().vault.checkout(cred_id, actor="webhook", purpose="verify webhook").get("webhook_secret") \
            if cred_id else None
        session().commit()
    sig = request.headers.get("X-Signature", "")
    if not secret or not hmac.compare_digest(sig, hmac.new(secret.encode(), request.get_data(), hashlib.sha256).hexdigest()):
        raise ApiError("invalid signature", 401)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ApiError("JSON object required")
    with tenant_scope(tenant_id):
        integ = session().get(IntegrationAccount, integration_id)
        try:
            obj, task = ingest(integ, payload)
        except KeyError as e:
            raise ApiError(f"missing field {e}")
        audit.record("webhook.received", actor=f"integration:{kind}", tenant_id=tenant_id, object_type="integration",
                     object_id=integration_id)
        session().commit()
        if task is not None and task.state == "SUBMITTED":
            enqueue("investigate", tenant_id, task.id)
        return {"accepted": True, "task_id": task.id if task else None}, 202


@bp.post("/autotask/<int:iid>")
def autotask(iid):
    return _handle("autotask", iid, ingest_autotask_ticket)


@bp.post("/prtg/<int:iid>")
def prtg(iid):
    return _handle("prtg", iid, ingest_prtg_alert)
