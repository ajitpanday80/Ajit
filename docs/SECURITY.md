# Security model

| Threat | Control |
|---|---|
| Cross-tenant access | ORM-level tenant filter on every SELECT, flush-time write guard, fail-closed with no context, tests per endpoint |
| AI runs / authorises a command | Agents only call `run_operation(phase="diagnostics")`; mutations need approved plan + run + step match (policy), AI proposals are re-validated against the registry |
| Prompt injection via logs/tickets | Evidence delimited + declared untrusted; `<`/`>` neutralised; AI can only request allow-listed *read* ops; output schema-validated |
| Shell injection | No arbitrary-command op; params regex-validated; argv built per token and `shlex`-quoted; PowerShell values single-quoted |
| Secrets leakage | Envelope encryption; write-only API; checkout audited; evidence sanitised before storage *and* before AI; raw output kept encrypted with retention purge |
| Plan tampering / replay | Canonical JSON + SHA-256, ORM immutability, DB triggers (MySQL), hash re-verified at policy and gate; one approval = one execution; expiry |
| Double execution after crash | Idempotency keys, intent-before-action, reconcile via post-check, Celery `acks_late` safe |
| Audit tampering | Per-tenant hash chain, ORM/DB append-only, `/api/audit/verify`, `cli verify-audit` |
| Client data to cloud AI | Per-client `ai_policy`; `local_only` never reaches a cloud provider; post-run review is local-only |
| Auto-closing masks failures | Ticket closure/PRTG ack opt-in per integration *and* client, only after verified success; otherwise a note says why |
| Webhook spoofing | HMAC-SHA256 over the raw body, secret in the vault, constant-time compare |

Operational: rotate `MASTER_KEYS` by prepending a key then `python -m backend.cli rewrap-keys`; pin SSH host keys;
use least-privilege service accounts (sudoers allow-list / JEA) on targets; run behind TLS (nginx config included).
