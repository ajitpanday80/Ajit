from __future__ import annotations

import re

from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import select

from backend import audit
from backend.api.common import ApiError, authenticated, body, need, ser
from backend.auth import rbac
from backend.auth.service import AuthError, create_user, login, revoke_tokens
from backend.db import session
from backend.models import IntegrationAccount, Tenant, User
from backend.services import svc
from backend.tenancy import system_scope

bp = Blueprint("admin", __name__, url_prefix="/api")


@bp.post("/auth/login")
def do_login():
    d = body()
    need(d, "email", "password")
    try:
        token, u = login(current_app.config["MSP"], d["email"], d["password"])
    except AuthError as e:
        raise ApiError(str(e), 401)
    return {"token": token, "user": {"id": u.id, "email": u.email, "name": u.name, "role": u.role,
                                     "tenant_id": u.tenant_id}}


@bp.get("/auth/me")
@authenticated()
def me():
    u = g.user
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "tenant_id": u.tenant_id,
            "permissions": sorted(rbac.MATRIX[u.role])}


@bp.post("/auth/logout")
@authenticated()
def logout():
    revoke_tokens(g.user)
    session().commit()
    return {"ok": True}


# ---- users
@bp.get("/users")
@authenticated("user.manage")
def list_users():
    return jsonify([ser(u, "id", "email", "name", "role", "is_active") for u in session().scalars(select(User))])


@bp.post("/users")
@authenticated("user.manage")
def add_user():
    d = body()
    need(d, "email", "password", "role")
    if d["role"] == "platform_admin":
        raise ApiError("cannot create platform admins here", 403)
    try:
        u = create_user(g.user.tenant_id, d["email"], d["password"], d["role"], d.get("name", ""))
        session().commit()
    except AuthError as e:
        raise ApiError(str(e))
    except Exception:
        session().rollback()
        raise ApiError("could not create user (duplicate email?)", 409)
    return ser(u, "id", "email", "name", "role"), 201


@bp.patch("/users/<int:uid>")
@authenticated("user.manage")
def patch_user(uid):
    u = session().get(User, uid)
    if u is None:
        raise ApiError("not found", 404)
    d = body()
    if "role" in d:
        if d["role"] not in rbac.MATRIX or d["role"] == "platform_admin":
            raise ApiError("invalid role")
        u.role = d["role"]
    if "is_active" in d:
        u.is_active = bool(d["is_active"])
    revoke_tokens(u)
    audit.record("user.update", actor=f"user:{g.user.id}", tenant_id=u.tenant_id, object_type="user", object_id=u.id,
                 detail={k: d[k] for k in ("role", "is_active") if k in d})
    session().commit()
    return ser(u, "id", "email", "role", "is_active")


# ---- tenants (platform admin)
@bp.post("/tenants")
@authenticated("tenant.manage")
def create_tenant():
    d = body()
    need(d, "name", "slug", "admin_email", "admin_password")
    if not re.fullmatch(r"[a-z0-9-]{2,60}", d["slug"]):
        raise ApiError("slug must be lowercase letters, digits, dashes")
    with system_scope():
        s = session()
        if s.scalar(select(Tenant).where(Tenant.slug == d["slug"])):
            raise ApiError("slug already exists", 409)
        t = Tenant(name=d["name"], slug=d["slug"], wrapped_dek=svc().vault.new_wrapped_dek())
        s.add(t)
        s.flush()
        try:
            create_user(t.id, d["admin_email"], d["admin_password"], "tenant_admin")
        except AuthError as e:
            s.rollback()
            raise ApiError(str(e))
        audit.record("tenant.create", actor=f"user:{g.user.id}", object_type="tenant", object_id=t.id)
        s.commit()
    return {"id": t.id, "slug": t.slug}, 201


# ---- audit
@bp.get("/audit")
@authenticated("audit.read")
def list_audit():
    evs = audit.list_events(g.user.tenant_id, limit=min(int(request.args.get("limit", 100)), 500),
                            offset=int(request.args.get("offset", 0)))
    return jsonify([ser(e, "seq", "actor", "action", "object_type", "object_id", "detail", "hash", "at") for e in evs])


@bp.get("/audit/verify")
@authenticated("audit.read")
def verify_audit():
    ok, bad = audit.verify_chain(g.user.tenant_id)
    return {"ok": ok, "first_bad_seq": bad}


# ---- integrations
@bp.get("/integrations")
@authenticated("integration.manage")
def list_integrations():
    return jsonify([ser(i, "id", "kind", "name", "base_url", "enabled", "settings", "credential_id")
                    for i in session().scalars(select(IntegrationAccount))])


@bp.post("/integrations")
@authenticated("integration.manage")
def add_integration():
    d = body()
    need(d, "kind", "name")
    if d["kind"] not in ("autotask", "prtg"):
        raise ApiError("kind must be autotask or prtg")
    settings = d.get("settings") or {}
    if not isinstance(settings, dict):
        raise ApiError("settings must be an object")
    i = IntegrationAccount(tenant_id=g.user.tenant_id, kind=d["kind"], name=d["name"], base_url=d.get("base_url", ""),
                           credential_id=d.get("credential_id"), settings=settings)
    session().add(i)
    session().flush()
    audit.record("integration.create", actor=f"user:{g.user.id}", tenant_id=i.tenant_id, object_type="integration",
                 object_id=i.id, detail={"kind": i.kind})
    session().commit()
    return ser(i, "id", "kind", "name", "base_url", "enabled", "settings"), 201
