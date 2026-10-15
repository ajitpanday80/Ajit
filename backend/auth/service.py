"""Password hashing, login with lockout, and short-lived revocable JWTs."""
from __future__ import annotations

import datetime as dt

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select

from backend import audit
from backend.config import Config
from backend.db import session
from backend.models import User, utcnow
from backend.tenancy import system_scope

_ph = PasswordHasher()
MIN_PASSWORD = 12


class AuthError(Exception):
    pass


def hash_password(pw: str) -> str:
    if len(pw) < MIN_PASSWORD:
        raise AuthError(f"password must be at least {MIN_PASSWORD} characters")
    return _ph.hash(pw)


def create_user(tenant_id: int, email: str, password: str, role: str, name: str = "") -> User:
    from backend.auth.rbac import MATRIX
    if role not in MATRIX:
        raise AuthError("unknown role")
    u = User(tenant_id=tenant_id, email=email.strip().lower(), name=name,
             password_hash=hash_password(password), role=role)
    session().add(u)
    session().flush()
    audit.record("user.create", tenant_id=tenant_id, object_type="user", object_id=u.id,
                 detail={"email": u.email, "role": role})
    return u


def login(cfg: Config, email: str, password: str) -> tuple[str, User]:
    with system_scope():
        u = session().scalar(select(User).where(User.email == email.strip().lower()))
        generic = AuthError("invalid credentials")
        if u is None or not u.is_active:
            _ph.hash("x" * 16)  # equalise timing
            raise generic
        if u.locked_until and u.locked_until > utcnow():
            audit.record("auth.locked", actor=f"user:{u.id}", tenant_id=u.tenant_id)
            session().commit()
            raise AuthError("account temporarily locked")
        try:
            _ph.verify(u.password_hash, password)
        except VerifyMismatchError:
            u.failed_logins += 1
            if u.failed_logins >= cfg.max_failed_logins:
                u.locked_until = utcnow() + dt.timedelta(minutes=cfg.lockout_minutes)
                u.failed_logins = 0
            audit.record("auth.failed", actor=f"user:{u.id}", tenant_id=u.tenant_id)
            session().commit()
            raise generic
        u.failed_logins = 0
        u.locked_until = None
        audit.record("auth.login", actor=f"user:{u.id}", tenant_id=u.tenant_id)
        session().commit()
        return issue_token(cfg, u), u


def issue_token(cfg: Config, u: User) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    return jwt.encode({"sub": str(u.id), "tid": u.tenant_id, "role": u.role, "ver": u.token_version,
                       "iat": now, "exp": now + dt.timedelta(minutes=cfg.jwt_ttl_minutes)},
                      cfg.secret_key, algorithm="HS256")


def authenticate(cfg: Config, token: str) -> User:
    try:
        claims = jwt.decode(token, cfg.secret_key, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError as e:
        raise AuthError("invalid token") from e
    with system_scope():
        u = session().get(User, int(claims["sub"]))
    if u is None or not u.is_active or u.token_version != claims.get("ver") or u.tenant_id != claims.get("tid"):
        raise AuthError("token revoked")
    return u


def revoke_tokens(user: User) -> None:
    user.token_version += 1
