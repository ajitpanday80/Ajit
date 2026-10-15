from __future__ import annotations

import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest

from backend.api import create_app
from backend.auth.service import create_user
from backend.config import Config
from backend.connectors.base import set_connector_factory
from backend.connectors.fake import FakeInfrastructure
from backend.db import remove_session, session
from backend.models import Client, Device, Tenant
from backend.services import svc
from backend.tenancy import system_scope, tenant_scope

PW = "correct-horse-battery"

# cheap argon2 parameters keep the suite fast (production uses library defaults)
import backend.auth.service as _auth
from argon2 import PasswordHasher as _PH
_auth._ph = _PH(time_cost=1, memory_cost=8, parallelism=1)


def seed_tenant(slug: str, address: str = "10.0.0.5") -> SimpleNamespace:
    s = session()
    with system_scope():
        t = Tenant(name=slug.upper(), slug=slug, wrapped_dek=svc().vault.new_wrapped_dek())
        s.add(t)
        s.flush()
        users = {r: create_user(t.id, f"{r}@{slug}.test", PW, r) for r in ("tenant_admin", "approver", "technician", "viewer")}
        users["approver2"] = create_user(t.id, f"approver2@{slug}.test", PW, "approver")
        s.commit()
    with tenant_scope(t.id):
        cred = svc().vault.store(t.id, name="root-ssh", kind="ssh_password", username="msp", secret={"password": "Sup3rS3cretPW!"})
        c = Client(name=f"{slug}-client", maintenance_enabled=True, ai_policy="local_only")
        s.add(c)
        s.flush()
        d = Device(client_id=c.id, hostname=f"web-{slug}", address=address, device_type="linux", connector="ssh",
                   credential_id=cred.id)
        s.add(d)
        s.commit()
        return SimpleNamespace(id=t.id, slug=slug, client_id=c.id, device_id=d.id, cred_id=cred.id,
                               user_ids={k: v.id for k, v in users.items()}, address=address)


@pytest.fixture
def env():
    cfg = Config(database_url="sqlite://", verify_delay=0, connect_retry_delay=0, jobs_inline=True,
                 webhook_secret="x").finalize()
    app = create_app(cfg)
    from backend.db import create_all
    create_all()
    infra = FakeInfrastructure()
    set_connector_factory(infra.factory)
    a = seed_tenant("acme", "10.0.0.5")
    b = seed_tenant("globex", "10.0.1.5")
    infra.host("10.0.0.5")
    infra.host("10.0.1.5")
    http = app.test_client()
    yield SimpleNamespace(app=app, cfg=cfg, http=http, infra=infra, a=a, b=b, host=infra.hosts["10.0.0.5"])
    set_connector_factory(None)
    remove_session()


def login(env, tenant, role="technician") -> dict:
    r = env.http.post("/api/auth/login", json={"email": f"{role}@{tenant.slug}.test", "password": PW})
    assert r.status_code == 200, r.get_json()
    return {"Authorization": f"Bearer {r.get_json()['token']}"}


def sign(secret: str, raw: bytes) -> str:
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
