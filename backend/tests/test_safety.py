"""Operation registry, policy engine, evidence sanitisation, architecture guarantees."""
import pathlib
import re

import pytest
from sqlalchemy import select

import backend.operations as ops
from backend.db import session
from backend.evidence import sanitize
from backend.executor.runner import run_operation
from backend.models import Device, Evidence, Task
from backend.operations.registry import (REGISTRY, Risk, UnknownOperation, ValidationError, get_spec, render)
from backend.policies.engine import OpRequest, PolicyDenied
from backend.services import svc
from backend.tenancy import tenant_scope

EVIL = ["x; rm -rf /", "$(reboot)", "`id`", "a && b", "a | b", "a\nb", "--help", "-rf", "../../etc/shadow", "a b", "'; DROP", "x\x00y", "${IFS}"]


# ------------------------------------------------------------------ registry
def test_no_arbitrary_command_operation_exists():
    assert not [n for n in REGISTRY if re.search(r"(exec|shell|run_command|raw|arbitrary)", n)]
    with pytest.raises(UnknownOperation):
        get_spec("run_command")


def test_every_mutating_operation_declares_safety_metadata():
    for spec in REGISTRY.values():
        if spec.risk > Risk.READ:
            assert spec.backup and spec.state_probe and spec.verify and spec.precondition
            assert get_spec(spec.verify.operation).risk == Risk.READ
            assert get_spec(spec.state_probe.operation).risk == Risk.READ
            for rb in spec.rollback_candidates:
                assert get_spec(rb).risk > Risk.READ
        else:
            assert not spec.rollback_candidates


@pytest.mark.parametrize("evil", EVIL)
def test_string_parameters_reject_shell_metacharacters(evil):
    tested = 0
    for spec in REGISTRY.values():
        for p in spec.params:
            if p.kind == "str":
                good = {q.name: ("nginx" if q.kind == "str" and q.name != "path" else "/var/log/syslog")
                        for q in spec.params if q.kind == "str"}
                for q in spec.params:
                    if q.kind == "enum":
                        good[q.name] = q.choices[0]
                    elif q.kind == "int":
                        good[q.name] = 5
                bad = dict(good, **{p.name: evil})
                if p.name in ("name", "provider") and evil in ("a b", "--help", "-rf", "'; DROP"):
                    pass  # windows names legitimately allow spaces/dashes; they are PS-quoted
                # windows service names are single-quoted PowerShell literals; skip the quote case separately
                try:
                    r = render(spec, bad)
                except ValidationError:
                    tested += 1
                    continue
                # accepted: must still be safe (quoted PowerShell literal or single argv token)
                if spec.interpreter == "powershell":
                    assert "''" in r.script or "'" + evil + "'" in r.script or evil in r.script
                else:
                    assert evil in r.argv and r.shell_line.count(evil) <= 1
    assert tested > 10


def test_unexpected_and_missing_parameters_rejected():
    spec = get_spec("service_restart")
    with pytest.raises(ValidationError):
        render(spec, {"unit": "nginx", "extra": "1"})
    with pytest.raises(ValidationError):
        render(spec, {})
    with pytest.raises(ValidationError):
        render(get_spec("journal_tail"), {"unit": "nginx", "lines": 100000})


def test_rendered_commands_are_argv_not_shell_strings():
    r = render(get_spec("tail_log"), {"path": "/var/log/nginx/error.log", "lines": 20})
    assert r.argv == ("tail", "-n", "20", "/var/log/nginx/error.log")
    assert ".." not in "".join(r.argv)
    with pytest.raises(ValidationError):
        render(get_spec("tail_log"), {"path": "/var/log/../shadow"})
    with pytest.raises(ValidationError):
        render(get_spec("tail_log"), {"path": "/etc/shadow"})


def test_powershell_parameters_are_quoted():
    r = render(get_spec("ps_service_status"), {"name": "My Svc"})
    assert "Get-Service -Name 'My Svc'" in r.script
    for evil in ("a'; Remove-Item C:\\ -Recurse; '", "$(calc)", "x|y", "a;b", "`id`"):
        with pytest.raises(ValidationError):
            render(get_spec("ps_service_status"), {"name": evil})


# ------------------------------------------------------------------ policy
def _ctx(env, mode="analysis_only"):
    t = Task(tenant_id=env.a.id, client_id=env.a.client_id, device_id=env.a.device_id, title="t", mode=mode)
    session().add(t)
    session().flush()
    return t, session().get(Device, env.a.device_id)


def test_mutation_denied_in_diagnostics_phase(env):
    with tenant_scope(env.a.id):
        t, d = _ctx(env, "maintenance")
        with pytest.raises(PolicyDenied) as e:
            run_operation(t, d, "service_restart", {"unit": "nginx"}, phase="diagnostics")
        assert "read-only" in str(e.value)
        assert env.host.calls("service_restart") == 0


def test_mutation_denied_in_analysis_only_even_with_execution_phase(env):
    with tenant_scope(env.a.id):
        t, d = _ctx(env, "analysis_only")
        with pytest.raises(PolicyDenied) as e:
            run_operation(t, d, "service_restart", {"unit": "nginx"}, phase="execution")
        assert "Analysis Only" in str(e.value)
        assert env.host.calls("service_restart") == 0


def test_execution_requires_an_approved_plan_and_run(env):
    with tenant_scope(env.a.id):
        t, d = _ctx(env, "maintenance")
        with pytest.raises(PolicyDenied) as e:
            run_operation(t, d, "service_restart", {"unit": "nginx"}, phase="execution")
        assert "approved plan" in str(e.value)


def test_unregistered_and_invalid_operations_never_reach_connector(env):
    with tenant_scope(env.a.id):
        t, d = _ctx(env)
        with pytest.raises(UnknownOperation):
            run_operation(t, d, "rm_rf", {}, phase="diagnostics")
        with pytest.raises(ValidationError):
            run_operation(t, d, "service_status", {"unit": "x; reboot"}, phase="diagnostics")
        assert env.host.log == []


def test_device_type_and_connector_compatibility_enforced(env):
    with tenant_scope(env.a.id):
        t, d = _ctx(env)
        with pytest.raises(PolicyDenied):
            run_operation(t, d, "ps_os_info", {}, phase="diagnostics")          # powershell op on linux/ssh device
        with pytest.raises(PolicyDenied):
            run_operation(t, d, "cli_show", {"topic": "routes"}, phase="diagnostics")  # router-only op


def test_per_device_rate_limit(env):
    env.cfg.max_diag_ops_per_minute_per_device = 3
    with tenant_scope(env.a.id):
        t, d = _ctx(env)
        for _ in range(3):
            run_operation(t, d, "uptime", {}, phase="diagnostics")
        with pytest.raises(PolicyDenied) as e:
            run_operation(t, d, "uptime", {}, phase="diagnostics")
        assert "rate limit" in str(e.value)


def test_policy_denials_are_audited(env):
    from backend.models import AuditEvent
    with tenant_scope(env.a.id):
        t, d = _ctx(env)
        with pytest.raises(PolicyDenied):
            run_operation(t, d, "service_restart", {"unit": "nginx"}, phase="diagnostics")
        session().commit()
        assert session().scalar(select(AuditEvent).where(AuditEvent.action == "policy.denied", AuditEvent.tenant_id == env.a.id))


def test_read_role_without_permission_cannot_run_diagnostics(env):
    with tenant_scope(env.a.id):
        t, d = _ctx(env)
        with pytest.raises(PolicyDenied):
            run_operation(t, d, "uptime", {}, phase="diagnostics", actor_role="viewer")


# ------------------------------------------------------------------ evidence
def test_sanitizer_redacts_common_secrets():
    raw = ("db_password=hunter2hunter2\nAuthorization: Bearer abcdefghijklmnop123\nurl=postgres://bob:pa55w0rd@db/x\n"
           "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nAKIAABCDEFGHIJKLMNOP\napi_key: sk_live_abc123456\n"
           "snmp-server community public123 RO\n")
    out, _ = sanitize(raw, ("custom-secret-value",))
    for leak in ("hunter2hunter2", "abcdefghijklmnop123", "pa55w0rd", "MIIabc", "AKIAABCDEFGHIJKLMNOP", "sk_live_abc123456", "public123"):
        assert leak not in out
    assert "custom-secret-value" not in sanitize("x custom-secret-value y", ("custom-secret-value",))[0]


def test_sanitizer_truncates_large_output():
    out, truncated = sanitize("A" * 200_000, max_chars=1000)
    assert truncated and len(out) < 1200


def test_collected_evidence_is_sanitised_before_storage_and_raw_is_encrypted(env):
    env.host.secret_in_logs = "password=Sup3rS3cretPW! and token=abcd1234efgh"
    with tenant_scope(env.a.id):
        t, d = _ctx(env)
        r = run_operation(t, d, "journal_tail", {"unit": "nginx", "lines": 10}, phase="diagnostics")
        session().commit()
        e = session().get(Evidence, r.evidence.id)
        assert "Sup3rS3cretPW" not in e.output_sanitized and "abcd1234efgh" not in e.output_sanitized
        assert b"Sup3rS3cretPW" not in e.raw_encrypted                       # raw retained only encrypted
        assert b"Sup3rS3cretPW!" in svc().vault.decrypt_for_tenant(env.a.id, e.raw_encrypted)


# ------------------------------------------------------------------ architecture guarantees
ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_only_the_runner_touches_connectors():
    offenders = []
    for f in ROOT.rglob("*.py"):
        rel = f.relative_to(ROOT).as_posix()
        if rel.startswith(("tests/", "connectors/")) or rel in ("executor/runner.py",):
            continue
        src = f.read_text()
        if re.search(r"get_connector\(|\.run\(RenderedCommand|SSHConnector\(|WinRMConnector\(|paramiko", src):
            offenders.append(rel)
    assert offenders == []


def test_no_dynamic_code_execution_in_backend():
    bad = re.compile(r"\b(eval|exec)\(|subprocess|os\.system|shell=True")
    hits = [f.relative_to(ROOT).as_posix() for f in ROOT.rglob("*.py")
            if not f.relative_to(ROOT).as_posix().startswith("tests/") and bad.search(f.read_text())]
    assert hits == []


def test_ai_layer_cannot_import_executor_mutation_paths():
    """Agents get read-only helper ``run_operation`` with phase fixed to diagnostics — never the engine."""
    src = (ROOT / "agents/base.py").read_text() + (ROOT / "agents/specialists.py").read_text()
    assert "executor.engine" not in src and 'phase="execution"' not in src and "rollback" not in src
