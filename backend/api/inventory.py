from __future__ import annotations

from flask import Blueprint, g, jsonify, request
from sqlalchemy import select

from backend import audit
from backend.api.common import ApiError, authenticated, body, need, ser
from backend.db import session
from backend.models import Client, Credential, Device, DeviceCapability, DeviceDependency, Site
from backend.services import svc

bp = Blueprint("inventory", __name__, url_prefix="/api")

CLIENT_F = ("id", "name", "status", "ai_policy", "maintenance_enabled", "autotask_company_id", "settings")
DEVICE_F = ("id", "client_id", "site_id", "hostname", "address", "device_type", "connector", "port", "credential_id",
            "labels", "prtg_device_id", "autotask_ci_id", "status")
DEVICE_TYPES = ("linux", "windows", "voip", "web", "router", "firewall", "hyperv", "backup")
CONNECTORS = ("ssh", "winrm", "http")


def _get(model, id_):
    o = session().get(model, id_)
    if o is None:
        raise ApiError("not found", 404)
    return o


# ---- clients
@bp.get("/clients")
@authenticated("inventory.read")
def list_clients():
    return jsonify([ser(c, *CLIENT_F) for c in session().scalars(select(Client).order_by(Client.name))])


@bp.post("/clients")
@authenticated("inventory.write")
def add_client():
    d = body()
    need(d, "name")
    c = Client(tenant_id=g.user.tenant_id, name=d["name"][:200], autotask_company_id=d.get("autotask_company_id"),
               ai_policy=d.get("ai_policy", "local_only"))
    if c.ai_policy not in ("cloud_allowed", "local_only", "disabled"):
        raise ApiError("invalid ai_policy")
    session().add(c)
    session().flush()
    audit.record("client.create", actor=f"user:{g.user.id}", tenant_id=c.tenant_id, object_type="client", object_id=c.id)
    session().commit()
    return ser(c, *CLIENT_F), 201


@bp.get("/clients/<int:cid>")
@authenticated("inventory.read")
def get_client(cid):
    return ser(_get(Client, cid), *CLIENT_F)


@bp.patch("/clients/<int:cid>")
@authenticated("inventory.write")
def patch_client(cid):
    c, d = _get(Client, cid), body()
    changes = {}
    for k in ("name", "status", "autotask_company_id"):
        if k in d:
            setattr(c, k, d[k])
            changes[k] = d[k]
    if "ai_policy" in d:
        if d["ai_policy"] not in ("cloud_allowed", "local_only", "disabled"):
            raise ApiError("invalid ai_policy")
        c.ai_policy = changes["ai_policy"] = d["ai_policy"]
    if "maintenance_enabled" in d:          # enabling modifications is a privileged, audited decision
        from backend.auth import rbac
        if not rbac.has(g.user.role, "tenant.manage") and g.user.role != "tenant_admin":
            raise ApiError("only a tenant admin may change maintenance enablement", 403)
        c.maintenance_enabled = changes["maintenance_enabled"] = bool(d["maintenance_enabled"])
    if "settings" in d and isinstance(d["settings"], dict):
        c.settings = d["settings"]
    audit.record("client.update", actor=f"user:{g.user.id}", tenant_id=c.tenant_id, object_type="client", object_id=c.id,
                 detail=changes)
    session().commit()
    return ser(c, *CLIENT_F)


# ---- sites
@bp.get("/clients/<int:cid>/sites")
@authenticated("inventory.read")
def list_sites(cid):
    _get(Client, cid)
    return jsonify([ser(s, "id", "client_id", "name", "address", "timezone")
                    for s in session().scalars(select(Site).where(Site.client_id == cid))])


@bp.post("/clients/<int:cid>/sites")
@authenticated("inventory.write")
def add_site(cid):
    _get(Client, cid)
    d = body()
    need(d, "name")
    s = Site(tenant_id=g.user.tenant_id, client_id=cid, name=d["name"], address=d.get("address", ""),
             timezone=d.get("timezone", "UTC"))
    session().add(s)
    session().commit()
    return ser(s, "id", "client_id", "name", "address", "timezone"), 201


# ---- devices
def _validate_device_refs(d: dict, client_id: int):
    if d.get("site_id") is not None:
        site = _get(Site, d["site_id"])
        if site.client_id != client_id:
            raise ApiError("site belongs to a different client")
    if d.get("credential_id") is not None:
        cred = _get(Credential, d["credential_id"])
        if cred.client_id not in (None, client_id):
            raise ApiError("credential belongs to a different client")


@bp.get("/devices")
@authenticated("inventory.read")
def list_devices():
    q = select(Device).order_by(Device.hostname)
    if request.args.get("client_id"):
        q = q.where(Device.client_id == int(request.args["client_id"]))
    return jsonify([ser(x, *DEVICE_F) for x in session().scalars(q)])


@bp.post("/devices")
@authenticated("inventory.write")
def add_device():
    d = body()
    need(d, "client_id", "hostname", "address", "device_type")
    _get(Client, d["client_id"])
    if d["device_type"] not in DEVICE_TYPES:
        raise ApiError(f"device_type must be one of {DEVICE_TYPES}")
    connector = d.get("connector") or ("winrm" if d["device_type"] in ("windows", "hyperv", "backup") else
                                       "ssh")
    if connector not in CONNECTORS:
        raise ApiError(f"connector must be one of {CONNECTORS}")
    _validate_device_refs(d, d["client_id"])
    x = Device(tenant_id=g.user.tenant_id, client_id=d["client_id"], site_id=d.get("site_id"), hostname=d["hostname"][:255],
               address=d["address"][:255], device_type=d["device_type"], connector=connector, port=d.get("port"),
               credential_id=d.get("credential_id"), labels=d.get("labels") or {}, prtg_device_id=d.get("prtg_device_id"),
               autotask_ci_id=d.get("autotask_ci_id"))
    session().add(x)
    session().flush()
    audit.record("device.create", actor=f"user:{g.user.id}", tenant_id=x.tenant_id, object_type="device", object_id=x.id)
    session().commit()
    return ser(x, *DEVICE_F), 201


@bp.get("/devices/<int:did>")
@authenticated("inventory.read")
def get_device(did):
    x = _get(Device, did)
    out = ser(x, *DEVICE_F)
    out["capabilities"] = [ser(c, "capability", "detail") for c in session().scalars(
        select(DeviceCapability).where(DeviceCapability.device_id == did))]
    out["dependencies"] = [ser(c, "depends_on_id", "kind") for c in session().scalars(
        select(DeviceDependency).where(DeviceDependency.device_id == did))]
    return out


@bp.patch("/devices/<int:did>")
@authenticated("inventory.write")
def patch_device(did):
    x, d = _get(Device, did), body()
    _validate_device_refs(d, x.client_id)
    for k in ("hostname", "address", "port", "credential_id", "labels", "status", "prtg_device_id", "autotask_ci_id", "site_id"):
        if k in d:
            setattr(x, k, d[k])
    audit.record("device.update", actor=f"user:{g.user.id}", tenant_id=x.tenant_id, object_type="device", object_id=x.id,
                 detail={k: v for k, v in d.items() if k != "labels"})
    session().commit()
    return ser(x, *DEVICE_F)


@bp.post("/devices/<int:did>/dependencies")
@authenticated("inventory.write")
def add_dependency(did):
    _get(Device, did)
    d = body()
    need(d, "depends_on_id")
    _get(Device, d["depends_on_id"])
    session().add(DeviceDependency(tenant_id=g.user.tenant_id, device_id=did, depends_on_id=d["depends_on_id"],
                                   kind=d.get("kind", "runtime")))
    session().commit()
    return {"ok": True}, 201


# ---- credentials (secrets are write-only through the API)
CRED_KINDS = ("ssh_password", "ssh_key", "winrm_password", "api_token")


@bp.get("/credentials")
@authenticated("inventory.read")
def list_credentials():
    return jsonify([ser(c, "id", "client_id", "name", "kind", "username", "created_at", "rotated_at")
                    for c in session().scalars(select(Credential))])


@bp.post("/credentials")
@authenticated("credential.write")
def add_credential():
    d = body()
    need(d, "name", "kind", "secret")
    if d["kind"] not in CRED_KINDS or not isinstance(d["secret"], dict):
        raise ApiError("invalid credential kind or secret")
    if d.get("client_id") is not None:
        _get(Client, d["client_id"])
    c = svc().vault.store(g.user.tenant_id, name=d["name"], kind=d["kind"], username=d.get("username", ""),
                          secret=d["secret"], client_id=d.get("client_id"), created_by=g.user.id)
    session().commit()
    return ser(c, "id", "client_id", "name", "kind", "username"), 201


@bp.post("/credentials/<int:cid>/rotate")
@authenticated("credential.write")
def rotate_credential(cid):
    _get(Credential, cid)
    d = body()
    need(d, "secret")
    svc().vault.rotate(cid, d["secret"], f"user:{g.user.id}")
    session().commit()
    return {"ok": True}
