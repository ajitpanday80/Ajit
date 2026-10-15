"""Operational CLI:  python -m backend.cli <command>

  init-db                         create tables (dev) — production uses `alembic upgrade head`
  bootstrap --slug S --name N --email E --password P [--platform]
                                  create a tenant and its first admin (--platform: platform_admin)
  demo                            seed a demo tenant with a failing nginx device (use with MSP_FAKE_CONNECTORS=1)
  verify-audit [--tenant ID]      verify a tenant's audit hash chain
  rewrap-keys                     re-wrap tenant data keys with the primary master key (after rotation)
"""
from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from backend import audit
from backend.auth.service import create_user
from backend.bootstrap import bootstrap
from backend.config import Config
from backend.db import create_all, session
from backend.models import Client, Device, Tenant
from backend.services import svc
from backend.tenancy import system_scope, tenant_scope


def _tenant(slug: str, name: str, email: str, password: str, role: str) -> Tenant:
    with system_scope():
        s = session()
        if s.scalar(select(Tenant).where(Tenant.slug == slug)):
            sys.exit(f"tenant '{slug}' already exists")
        t = Tenant(name=name, slug=slug, wrapped_dek=svc().vault.new_wrapped_dek())
        s.add(t)
        s.flush()
        create_user(t.id, email, password, role)
        s.commit()
        return t


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="msp")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    b = sub.add_parser("bootstrap")
    b.add_argument("--slug", required=True); b.add_argument("--name", required=True)
    b.add_argument("--email", required=True); b.add_argument("--password", required=True)
    b.add_argument("--platform", action="store_true")
    sub.add_parser("demo")
    v = sub.add_parser("verify-audit"); v.add_argument("--tenant", type=int, default=None)
    sub.add_parser("rewrap-keys")
    a = ap.parse_args(argv)
    cfg = Config.from_env()
    bootstrap(cfg)

    if a.cmd == "init-db":
        create_all(); print("tables created")
    elif a.cmd == "bootstrap":
        t = _tenant(a.slug, a.name, a.email, a.password, "platform_admin" if a.platform else "tenant_admin")
        print(f"tenant {t.id} ({t.slug}) created")
    elif a.cmd == "demo":
        create_all()
        t = _tenant("demo", "Demo MSP", "admin@demo.test", "demo-password-123", "tenant_admin")
        with tenant_scope(t.id):
            for r in ("technician", "approver", "viewer"):
                create_user(t.id, f"{r}@demo.test", "demo-password-123", r)
            cred = svc().vault.store(t.id, name="demo-ssh", kind="ssh_password", username="msp", secret={"password": "demo"})
            c = Client(name="Acme Dental", maintenance_enabled=True, ai_policy="local_only")
            session().add(c); session().flush()
            session().add(Device(client_id=c.id, hostname="demo-web", address="demo-web.example", device_type="linux",
                                 connector="ssh", credential_id=cred.id))
            session().commit()
        print("demo tenant ready: admin@demo.test / technician@demo.test / approver@demo.test (password demo-password-123)")
    elif a.cmd == "verify-audit":
        ok, bad = audit.verify_chain(a.tenant)
        print("audit chain OK" if ok else f"audit chain BROKEN at seq {bad}")
        sys.exit(0 if ok else 2)
    elif a.cmd == "rewrap-keys":
        with system_scope():
            print(f"re-wrapped {svc().vault.rewrap_all()} tenant keys")


if __name__ == "__main__":
    main()
