"""Tenant isolation, auth/RBAC, vault, audit chain."""
import pytest
from sqlalchemy import select, text

from backend import audit
from backend.auth.service import AuthError, authenticate, hash_password
from backend.db import session
from backend.models import AuditEvent, Client, Credential, Device, User
from backend.services import svc
from backend.tenancy import TenantViolation, system_scope, tenant_scope
from backend.tests.conftest import PW, login


# ------------------------------------------------------------------ tenancy
def test_queries_are_filtered_by_tenant(env):
    with tenant_scope(env.a.id):
        assert [c.id for c in session().scalars(select(Client))] == [env.a.client_id]
    with tenant_scope(env.b.id):
        assert [c.id for c in session().scalars(select(Client))] == [env.b.client_id]


def test_get_by_id_across_tenants_returns_none(env):
    with tenant_scope(env.b.id):
        assert session().get(Client, env.a.client_id) is None
        assert session().get(Device, env.a.device_id) is None


def test_no_context_fails_closed(env):
    assert list(session().scalars(select(Client))) == []


def test_cross_tenant_write_is_blocked(env):
    with tenant_scope(env.a.id):
        session().add(Client(tenant_id=env.b.id, name="evil"))
        with pytest.raises(TenantViolation):
            session().flush()
        session().rollback()


def test_cannot_move_row_to_other_tenant(env):
    with tenant_scope(env.a.id):
        c = session().get(Client, env.a.client_id)
        c.tenant_id = env.b.id
        with pytest.raises(TenantViolation):
            session().flush()
        session().rollback()


def test_api_returns_404_for_other_tenants_objects(env):
    h = login(env, env.b, "technician")
    assert env.http.get(f"/api/clients/{env.a.client_id}", headers=h).status_code == 404
    assert env.http.get(f"/api/devices/{env.a.device_id}", headers=h).status_code == 404
    assert env.http.post("/api/tasks", headers=h, json={"device_id": env.a.device_id, "title": "x", "mode": "analysis_only"}).status_code == 404
    assert env.http.get("/api/clients", headers=h).get_json()[0]["id"] == env.b.client_id


def test_api_cannot_attach_other_tenants_credential(env):
    h = login(env, env.b, "technician")
    r = env.http.patch(f"/api/devices/{env.b.device_id}", headers=h, json={"credential_id": env.a.cred_id})
    assert r.status_code == 404


# ------------------------------------------------------------------ auth / rbac
def test_login_failure_is_generic_and_lockout_works(env):
    for _ in range(5):
        r = env.http.post("/api/auth/login", json={"email": "technician@acme.test", "password": "wrong-password-1"})
        assert r.status_code == 401
    r = env.http.post("/api/auth/login", json={"email": "technician@acme.test", "password": PW})
    assert r.status_code == 401 and "locked" in r.get_json()["error"]
    r = env.http.post("/api/auth/login", json={"email": "nobody@acme.test", "password": "whatever-whatever"})
    assert r.get_json()["error"] == "invalid credentials"


def test_token_revocation_on_logout(env):
    h = login(env, env.a, "viewer")
    assert env.http.get("/api/auth/me", headers=h).status_code == 200
    env.http.post("/api/auth/logout", headers=h)
    assert env.http.get("/api/auth/me", headers=h).status_code == 401


def test_requires_authentication_and_rejects_garbage_token(env):
    assert env.http.get("/api/clients").status_code == 401
    assert env.http.get("/api/clients", headers={"Authorization": "Bearer abc.def.ghi"}).status_code == 401


def test_rbac_matrix_enforced(env):
    viewer, tech, appr = login(env, env.a, "viewer"), login(env, env.a, "technician"), login(env, env.a, "approver")
    assert env.http.post("/api/clients", headers=viewer, json={"name": "n"}).status_code == 403
    assert env.http.post("/api/clients", headers=tech, json={"name": "n"}).status_code == 201
    assert env.http.post("/api/tasks", headers=appr, json={"device_id": env.a.device_id, "title": "t", "mode": "analysis_only"}).status_code == 403
    assert env.http.get("/api/audit", headers=tech).status_code == 403
    assert env.http.get("/api/audit", headers=appr).status_code == 200
    assert env.http.get("/api/users", headers=tech).status_code == 403


def test_weak_password_rejected():
    with pytest.raises(AuthError):
        hash_password("short")


def test_only_tenant_admin_can_enable_maintenance(env):
    tech, admin = login(env, env.a, "technician"), login(env, env.a, "tenant_admin")
    assert env.http.patch(f"/api/clients/{env.a.client_id}", headers=tech, json={"maintenance_enabled": False}).status_code == 403
    assert env.http.patch(f"/api/clients/{env.a.client_id}", headers=admin, json={"maintenance_enabled": False}).status_code == 200


# ------------------------------------------------------------------ vault
def test_credentials_never_returned_or_stored_in_clear(env):
    h = login(env, env.a, "technician")
    r = env.http.post("/api/credentials", headers=h, json={"name": "n", "kind": "api_token", "username": "u",
                                                           "secret": {"token": "TOPSECRETVALUE123"}})
    assert r.status_code == 201 and "TOPSECRET" not in r.get_data(as_text=True)
    assert "TOPSECRET" not in env.http.get("/api/credentials", headers=h).get_data(as_text=True)
    with system_scope():
        raw = session().execute(text("select ciphertext from credentials where id=:i"), {"i": r.get_json()["id"]}).scalar()
    assert b"TOPSECRETVALUE123" not in raw


def test_checkout_is_audited_and_tenant_bound(env):
    from backend.models import CredentialAccessAudit
    from backend.vault import VaultError
    with tenant_scope(env.a.id):
        c = svc().vault.checkout(env.a.cred_id, actor="test", purpose="unit", task_id=None)
        session().commit()
        assert c["password"] == "Sup3rS3cretPW!"
        assert session().scalar(select(CredentialAccessAudit).where(CredentialAccessAudit.purpose == "unit"))
    with tenant_scope(env.b.id):
        with pytest.raises(VaultError):
            svc().vault.checkout(env.a.cred_id, actor="test", purpose="steal")


def test_master_key_rotation_keeps_data_readable(env):
    from cryptography.fernet import Fernet
    from backend.vault import Vault
    old = env.cfg.master_keys
    new = Fernet.generate_key().decode()
    svc().vault = Vault(f"{new},{old}")
    with system_scope():
        assert svc().vault.rewrap_all() == 2
    svc().vault = Vault(new)  # old key retired
    with tenant_scope(env.a.id):
        assert svc().vault.checkout(env.a.cred_id, actor="t", purpose="p")["password"] == "Sup3rS3cretPW!"


# ------------------------------------------------------------------ audit chain
def test_audit_chain_verifies_and_detects_tampering(env):
    with tenant_scope(env.a.id):
        for i in range(3):
            audit.record("x.test", tenant_id=env.a.id, detail={"i": i})
        session().commit()
        assert audit.verify_chain(env.a.id) == (True, None)
    with system_scope():
        session().execute(text("update audit_events set detail='{\"i\": 99}' where tenant_id=:t and action='x.test' and seq=(select min(seq) from audit_events where action='x.test' and tenant_id=:t)"), {"t": env.a.id})
        session().commit()
        ok, bad = audit.verify_chain(env.a.id)
    assert ok is False and bad is not None


def test_audit_events_cannot_be_updated_or_deleted_via_orm(env):
    ev = audit.record("x.y", tenant_id=env.a.id)
    session().commit()
    ev.actor = "attacker"
    with pytest.raises(PermissionError):
        session().flush()
    session().rollback()
    session().delete(session().get(AuditEvent, ev.id))
    with pytest.raises(PermissionError):
        session().flush()
    session().rollback()


def test_audit_api_is_tenant_scoped(env):
    h = login(env, env.b, "approver")
    evs = env.http.get("/api/audit?limit=500", headers=h).get_json()
    assert evs and all("acme" not in str(e["detail"]) for e in evs)
    assert env.http.get("/api/audit/verify", headers=h).get_json()["ok"] is True
