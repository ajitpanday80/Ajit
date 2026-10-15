"""Credential vault: envelope encryption with per-tenant data keys.

master key(s) (env / KMS-injected) wrap a random per-tenant DEK stored on the
tenant row; credentials are Fernet-encrypted with that DEK.  Plaintext exists
only in memory for the duration of a checkout, and every checkout is audited.
Rotation: prepend a new master key to MASTER_KEYS and call ``rewrap_all``.
"""
from __future__ import annotations

import json

from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy import select

from backend import audit
from backend.db import session
from backend.models import Credential, CredentialAccessAudit, Tenant, utcnow


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, master_keys: str):
        keys = [k.strip() for k in master_keys.split(",") if k.strip()]
        if not keys:
            raise VaultError("no master key configured")
        self._master = MultiFernet([Fernet(k) for k in keys])

    # -- tenant keys
    def new_wrapped_dek(self) -> bytes:
        return self._master.encrypt(Fernet.generate_key())

    def _dek(self, tenant_id: int) -> Fernet:
        t = session().get(Tenant, tenant_id)
        if t is None:
            raise VaultError("unknown tenant")
        return Fernet(self._master.decrypt(t.wrapped_dek))

    def rewrap_all(self) -> int:
        """Re-encrypt every tenant DEK with the current primary master key."""
        s = session()
        n = 0
        for t in s.scalars(select(Tenant)):
            t.wrapped_dek = self._master.rotate(t.wrapped_dek)
            n += 1
        s.commit()
        return n

    # -- generic data encryption (used for raw evidence too)
    def encrypt_for_tenant(self, tenant_id: int, data: bytes) -> bytes:
        return self._dek(tenant_id).encrypt(data)

    def decrypt_for_tenant(self, tenant_id: int, blob: bytes) -> bytes:
        return self._dek(tenant_id).decrypt(blob)

    # -- credentials
    def store(self, tenant_id: int, *, name: str, kind: str, username: str, secret: dict,
              client_id: int | None = None, created_by: int | None = None) -> Credential:
        c = Credential(tenant_id=tenant_id, client_id=client_id, name=name, kind=kind, username=username,
                       ciphertext=self.encrypt_for_tenant(tenant_id, json.dumps(secret).encode()),
                       created_by=created_by)
        session().add(c)
        session().flush()
        audit.record("credential.create", actor=f"user:{created_by}", tenant_id=tenant_id,
                     object_type="credential", object_id=c.id, detail={"name": name, "kind": kind})
        return c

    def rotate(self, credential_id: int, secret: dict, actor: str) -> None:
        c = session().get(Credential, credential_id)
        if c is None:
            raise VaultError("credential not found")
        c.ciphertext = self.encrypt_for_tenant(c.tenant_id, json.dumps(secret).encode())
        c.rotated_at = utcnow()
        audit.record("credential.rotate", actor=actor, tenant_id=c.tenant_id,
                     object_type="credential", object_id=c.id)

    def checkout(self, credential_id: int, *, actor: str, purpose: str, task_id: int | None = None) -> dict:
        """Return decrypted secret payload (+username).  Always audited."""
        c = session().get(Credential, credential_id)
        if c is None:
            raise VaultError("credential not found")  # also hides other tenants' ids
        payload = json.loads(self.decrypt_for_tenant(c.tenant_id, c.ciphertext))
        session().add(CredentialAccessAudit(tenant_id=c.tenant_id, credential_id=c.id, actor=actor,
                                            purpose=purpose, task_id=task_id))
        session().flush()
        return {"kind": c.kind, "username": c.username, **payload}
