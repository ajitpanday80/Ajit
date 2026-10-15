"""Runtime configuration, read from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.fernet import Fernet


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    env: str = "development"
    database_url: str = "sqlite:///msp_dev.db"
    secret_key: str = ""
    # Comma separated Fernet keys; first encrypts, all decrypt (rotation).
    master_keys: str = ""
    redis_url: str = "redis://localhost:6379/0"
    jobs_inline: bool = True  # run background jobs in-process (dev/tests)
    jwt_ttl_minutes: int = 30
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    llm_monthly_token_budget: int = 2_000_000  # per tenant
    llm_timeout_seconds: int = 60
    evidence_max_chars: int = 64_000
    evidence_retention_days: int = 180
    plan_ttl_minutes: int = 60
    max_diag_ops_per_minute_per_device: int = 30
    connect_retries: int = 3
    connect_retry_delay: float = 2.0
    verify_retries: int = 5
    verify_delay: float = 2.0
    run_heartbeat_stale_seconds: int = 300
    webhook_secret: str = ""
    cors_origins: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get("MSP_ENV", "development")
        c = cls(
            env=env,
            database_url=os.environ.get("DATABASE_URL", cls.database_url),
            secret_key=os.environ.get("SECRET_KEY", ""),
            master_keys=os.environ.get("MASTER_KEYS", ""),
            redis_url=os.environ.get("REDIS_URL", cls.redis_url),
            jobs_inline=_bool("JOBS_INLINE", env != "production"),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            anthropic_model=os.environ.get("ANTHROPIC_MODEL", cls.anthropic_model),
            ollama_url=os.environ.get("OLLAMA_URL", cls.ollama_url),
            ollama_model=os.environ.get("OLLAMA_MODEL", cls.ollama_model),
            webhook_secret=os.environ.get("WEBHOOK_SECRET", ""),
            cors_origins=[o for o in os.environ.get("CORS_ORIGINS", "").split(",") if o],
        )
        c.finalize(persist_dev_key=True)
        return c

    def finalize(self, persist_dev_key: bool = False) -> "Config":
        if self.env == "production":
            missing = [n for n, v in (("SECRET_KEY", self.secret_key), ("MASTER_KEYS", self.master_keys)) if not v]
            if missing:
                raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
        else:
            self.secret_key = self.secret_key or "dev-secret-change-me-dev-secret-change-me"
            if not self.master_keys and persist_dev_key:
                # dev only: keep one key across processes so seeded credentials stay decryptable
                path = os.environ.get("MSP_DEV_KEY_FILE", ".msp_dev_master_key")
                if os.path.exists(path):
                    self.master_keys = open(path).read().strip()
                else:
                    self.master_keys = Fernet.generate_key().decode()
                    with open(path, "w") as fh:
                        os.chmod(path, 0o600) if os.path.exists(path) else None
                        fh.write(self.master_keys)
                    os.chmod(path, 0o600)
            self.master_keys = self.master_keys or Fernet.generate_key().decode()
        return self
