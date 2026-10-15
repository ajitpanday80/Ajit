"""Role → permission matrix (versioned in code so changes are reviewed)."""
from __future__ import annotations

ROLES = ("tenant_admin", "approver", "technician", "viewer")

P = {
    "inventory.read", "inventory.write",
    "credential.write",
    "task.create", "task.read", "task.run_maintenance", "task.cancel",
    "plan.approve", "plan.execute",
    "report.read", "audit.read", "user.manage", "integration.manage", "tenant.manage",
}

MATRIX: dict[str, frozenset[str]] = {
    "viewer": frozenset({"inventory.read", "task.read", "report.read"}),
    "technician": frozenset({"inventory.read", "inventory.write", "credential.write", "task.create",
                             "task.read", "task.run_maintenance", "task.cancel", "report.read",
                             "plan.execute"}),
    "approver": frozenset({"inventory.read", "task.read", "plan.approve", "report.read", "audit.read"}),
    "tenant_admin": frozenset(P - {"tenant.manage"}),
}
MATRIX["platform_admin"] = frozenset(P)


def has(role: str, permission: str) -> bool:
    return permission in MATRIX.get(role, frozenset())
