# Architecture

## Layers
1. **Dashboard** (React/TS) — investigations with live SSE timeline, approvals, inventory, reports, audit.
2. **API** (Flask) — bearer-JWT auth, RBAC, tenant context bound per request, strict validation, security headers.
3. **Orchestrator** — runs one specialist agent per device class, consolidates findings, and (maintenance mode) builds a plan.
4. **AI layer** — `LlmRouter` picks Claude or Ollama by the client's `ai_policy` (`cloud_allowed` / `local_only` / `disabled`).
   Output is JSON-validated; evidence is wrapped in `<evidence>` blocks and declared untrusted; failures degrade to rule-based findings.
5. **Safety & policy** — `PolicyEngine.authorize` is evaluated immediately before every device call.
6. **Execution** — `executor/runner.py` is the only code that may touch a connector (architecture test enforces this).

## Task state machine (`orchestrator/workflow.py`)
```
SUBMITTED → DIAGNOSING → ANALYZING → COMPLETED                       (Analysis Only: stops here)
                                   → AWAITING_APPROVAL → APPROVED → PRECHECKING → BACKING_UP → EXECUTING → VERIFYING → SUCCEEDED
                          REJECTED / EXPIRED(→re-plan)      ↘ABORTED(gate)           ↘ROLLING_BACK → ROLLED_BACK | NEEDS_HUMAN
```
Every transition is validated, optimistic-locked, written to `workflow_events` and the audit chain.

## Safety gates (all enforced in `executor/engine.py`; failure ⇒ nothing is modified)
approval exists → approval hash == plan hash == recomputed hash → not expired → second approver (if required) →
no-rollback acknowledgement (if required) → role may execute → task is maintenance → client has maintenance enabled →
exclusive device lock → per-step precondition → **no state drift since approval** → per-step backup + recoverability
check (`VERIFIED` / `EXPORT_ONLY` / `NONE` vs the operation's minimum).

Then per step: durable intent record (idempotency key `plan_hash:step`) → execute → post-check (polling) → final verification
and before/after diff. Any failure → authorised rollback (only the `rollback_candidates` shown to the approver) →
verify state restored, else `NEEDS_HUMAN` with evidence preserved. Lost connections and dead workers are *reconciled
against the device* (never blindly retried), so an operation is never executed twice. `recover_interrupted_runs` (Celery beat)
settles runs whose heartbeat went stale.

## Operation registry
Each operation: typed pattern-validated params, fixed argv/PowerShell template, risk (`READ/MUTATE/DESTRUCTIVE`), and for
mutations: backup strategy, minimum recovery level, precondition, state probe, post-check, rollback candidates.
Adding a mutation without all of these fails at import time. Router/firewall CLI access is an enumerated `topic`
mapped to vendor commands in a fixed profile table.

## Extending
* New read diagnostic: `register(OperationSpec(...))` in `backend/operations/*`, allow it in an agent's `allowed_ops`.
* New mutation: also add a backup strategy in `backend/backups` and (if reversible) rollback candidates.
* New device class: agent in `agents/specialists.py`, connector in `connectors/`.

## Data model
See `backend/models.py` / `migrations/versions/0001_initial_schema.py`. Client-owned tables use the `TenantScoped` mixin.
