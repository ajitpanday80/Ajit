"""Database-level append-only audit log and immutable change plans (MySQL triggers).

Application code already forbids these writes; triggers add defence in depth against a compromised app
account or a manual UPDATE.  SQLite (dev/tests) gets equivalent triggers.

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

FROZEN = ("task_id", "version", "steps", "canonical", "plan_hash", "recovery_level", "risk",
          "requires_second_approver", "requires_no_rollback_ack", "created_by", "expires_at")


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "mysql":
        op.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events FOR EACH ROW "
                   "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only'")
        op.execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events FOR EACH ROW "
                   "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only'")
        cond = " OR ".join(f"NOT (OLD.{c} <=> NEW.{c})" for c in FROZEN if c not in ("steps",))
        cond += " OR CAST(OLD.steps AS CHAR) <> CAST(NEW.steps AS CHAR)"
        op.execute(f"CREATE TRIGGER plan_frozen BEFORE UPDATE ON change_plans FOR EACH ROW BEGIN IF {cond} THEN "
                   "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'change plan is immutable'; END IF; END")
    elif dialect == "sqlite":
        op.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events "
                   "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END")
        op.execute("CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events "
                   "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END")


def downgrade() -> None:
    for t in ("audit_no_update", "audit_no_delete", "plan_frozen"):
        op.execute(f"DROP TRIGGER IF EXISTS {t}")
