# AI-Powered MSP Infrastructure Operations Platform

Centralised multi-client management · AI-assisted diagnosis · approval-controlled automation.

**Core principle:** AI interprets evidence and proposes plans. The deterministic backend authorises, executes,
verifies and audits. AI output is never itself authorisation to run a command.

```
React/TS dashboard ─► Flask API (auth, RBAC, tenant isolation) ─► Orchestrator ─► Specialist agents ─► LLM (Claude / Ollama)
                                         │                              │
                                         ▼                              ▼
                  Policy engine ─► Operation runner (only path to devices) ─► Typed connectors (SSH / WinRM / HTTP)
                                         │
              Change manager · Backup gates · Executor · Verification · Rollback · Evidence · Audit chain
                                         │
                         MySQL (state)  ·  Redis + Celery (jobs)  ·  Autotask / PRTG / Ollama integrations
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design and [docs/SECURITY.md](docs/SECURITY.md) for the threat model.

## Quick start (no real devices needed)

```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
pytest                                        # 105 tests incl. failure injection

export DATABASE_URL=sqlite:///msp_dev.db MSP_FAKE_CONNECTORS=1
python -m backend.cli demo                    # demo tenant + a device whose nginx is down
flask --app backend.wsgi run -p 5000 &        # API
cd frontend && npm install && npm run dev      # UI on http://localhost:5173
```
Sign in as `technician@demo.test` (start an investigation; pick *Troubleshooting & Maintenance*, description
`service:nginx.service`), then as `approver@demo.test` (approve the exact plan), then execute as the technician.
Password for all demo users: `demo-password-123`. `MSP_FAKE_CONNECTORS` is refused in production.

## Production (Docker Compose)

```bash
cp .env.example .env     # set SECRET_KEY, MASTER_KEYS, MYSQL_* (see comments)
# put TLS certs in deployment/certs/{fullchain,privkey}.pem and pinned SSH host keys in deployment/known_hosts
docker compose up -d     # mysql, redis, migrate (alembic), api, worker, beat, web (nginx + TLS)
docker compose run --rm api python -m backend.cli bootstrap --slug acme --name "Acme MSP" --email admin@acme.example --password '…'
```

## What is implemented

| Area | Where |
|---|---|
| Tenant isolation (ORM-level, fail-closed), RBAC, lockout, revocable JWT | `backend/tenancy.py`, `backend/auth/` |
| Credential vault (per-tenant DEK, master-key rotation, audited checkout) | `backend/vault.py` |
| Hash-chained append-only audit log (+ DB triggers) | `backend/audit/`, `migrations/0002` |
| Typed operation registry (no arbitrary commands) | `backend/operations/` |
| Policy engine (mode, phase, scope, plan binding, rate limits) | `backend/policies/` |
| Single choke point to devices: policy → vault → connector → sanitise → evidence | `backend/executor/runner.py` |
| Specialist agents: Linux, Windows/Hyper-V/ShadowProtect, VoIP, Web, Network, Firewall | `backend/agents/` |
| LLM abstraction: Claude, Ollama, per-client data policy, budgets, call log | `backend/llm/` |
| Orchestrator + explicit workflow state machine | `backend/orchestrator/` |
| Immutable hashed plans, approvals, second-approver & no-rollback acknowledgement | `backend/approvals/` |
| Backup/recovery gates, execution engine, verification, authorised rollback, crash recovery | `backend/backups/`, `executor/engine.py`, `verification/`, `rollback/` |
| Autotask / PRTG integrations (HMAC webhooks, notes, time, guarded ack/closure) | `backend/integrations/`, `backend/connectors/{autotask,prtg}/` |
| Reports, time entries, local-model (Ollama) advisory review | `backend/reporting/` |
| REST API + SSE timeline, Celery workers, React UI, Compose deployment | `backend/api/`, `workers/`, `frontend/`, `docker-compose.yml` |

## Honest limitations (read before production)

* **Not yet exercised against real infrastructure.** The SSH, WinRM and HTTP connectors, Autotask/PRTG clients and
  the MySQL migration/trigger SQL are implemented but were tested only against in-memory fakes/SQLite. Validate each
  in a lab first (the architecture doc says each integration must be implemented and tested separately).
* Mutating operations shipped: systemd service start/stop/restart/reload, Windows service start/stop/restart, apt
  single-package upgrade (no rollback → needs second approver + explicit acknowledgement). No network/firewall
  mutations — add them with commit-confirm semantics before enabling.
* Targets must restrict privileges themselves (sudoers allow-list / JEA endpoint). The registry is defence in depth.
* Pin SSH host keys in `deployment/known_hosts`; the connector refuses unknown hosts.
* Per-tenant LLM token budgets exist; per-user client scoping, SSO/MFA and external audit shipping are not built.
