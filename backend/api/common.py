from __future__ import annotations

from datetime import datetime
from functools import wraps

from flask import current_app, g, jsonify, request

from backend.auth import rbac
from backend.auth.service import AuthError, authenticate
from backend.tenancy import set_tenant


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


def ser(obj, *fields) -> dict:
    out = {}
    for f in fields:
        v = getattr(obj, f)
        out[f] = v.isoformat() + "Z" if isinstance(v, datetime) else v
    return out


def body() -> dict:
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        raise ApiError("JSON object body required")
    return d


def need(d: dict, *keys):
    miss = [k for k in keys if d.get(k) in (None, "")]
    if miss:
        raise ApiError(f"missing field(s): {', '.join(miss)}")


def authenticated(permission: str | None = None):
    """Authenticate the bearer token, bind the tenant scope for this request, check the permission."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            hdr = request.headers.get("Authorization", "")
            if not hdr.startswith("Bearer "):
                raise ApiError("authentication required", 401)
            try:
                user = authenticate(current_app.config["MSP"], hdr[7:])
            except AuthError as e:
                raise ApiError(str(e), 401)
            if permission and not rbac.has(user.role, permission):
                raise ApiError("forbidden", 403)
            g.user = user
            g.tenant_token = set_tenant(user.tenant_id)
            return fn(*a, **kw)
        return wrapper
    return deco
