"""Specialist agents for every device class run only registered read-only operations."""
import pytest
from sqlalchemy import select

from backend.db import session
from backend.models import Device, DiagnosticResult, Evidence, Investigation, Task
from backend.orchestrator.engine import run_investigation
from backend.tenancy import tenant_scope


def make(env, dtype, connector, addr, labels=None, desc=""):
    with tenant_scope(env.a.id):
        d = Device(client_id=env.a.client_id, hostname=f"{dtype}-1", address=addr, device_type=dtype, connector=connector,
                   labels=labels or {})
        session().add(d)
        session().flush()
        t = Task(tenant_id=env.a.id, client_id=env.a.client_id, device_id=d.id, title=f"{dtype} check", description=desc,
                 mode="analysis_only", requested_by=env.a.user_ids["technician"])
        session().add(t)
        session().commit()
        run_investigation(t.id)
        session().refresh(t)
        inv = session().scalar(select(Investigation).where(Investigation.task_id == t.id))
        evid = list(session().scalars(select(Evidence).where(Evidence.task_id == t.id)))
        return t, inv, evid


def test_windows_agent_flags_stopped_automatic_services(env):
    h = env.infra.host("10.9.0.1")
    h.outputs["ps_stopped_auto_services"] = ("Name        State   ExitCode\n----        -----   --------\n"
                                             "Spooler     Stopped 0\ngupdate     Stopped 0\n")
    t, inv, ev = make(env, "windows", "winrm", "10.9.0.1")
    assert t.state == "COMPLETED"
    assert any("Spooler" in f["title"] for f in inv.findings) and not any("gupdate" in f["title"] for f in inv.findings)
    assert all(e.operation.startswith("ps_") for e in ev)


def test_hyperv_and_shadowprotect_checks(env):
    h = env.infra.host("10.9.0.2")
    h.outputs["ps_hyperv_vms"] = "Name State\nDC01 Running\nSQL01 Off\n"
    h.outputs["ps_shadowprotect_service"] = "Name : ShadowProtectSvc\nStatus : Stopped\n"
    t, inv, ev = make(env, "hyperv", "winrm", "10.9.0.2", desc="shadowprotect backup failing")
    titles = " | ".join(f["title"] for f in inv.findings)
    assert "Hyper-V VMs are not running" in titles and "ShadowProtect service is not running" in titles


def test_voip_agent_detects_dead_asterisk_and_bad_trunk(env):
    h = env.infra.host("10.9.0.3")
    h.fail_ops["asterisk_version"] = 1
    h.outputs["asterisk_sip_registry"] = "Host Username State\ntrunk.example 100 Rejected\n"
    t, inv, ev = make(env, "voip", "ssh", "10.9.0.3")
    titles = " | ".join(f["title"] for f in inv.findings)
    assert "Asterisk CLI is not responding" in titles and "SIP trunk registration" in titles
    with tenant_scope(env.a.id):
        props = session().scalar(select(DiagnosticResult).where(DiagnosticResult.agent == "voip")).proposals
    assert any(r["operation"] == "service_restart" and r["params"]["unit"] == "asterisk" for r in props)


def test_web_agent_checks_http_tls_and_config(env):
    h = env.infra.host("10.9.0.4")
    h.outputs["http_probe"] = "status: 503\nelapsed_ms: 900\ntls_days_left: 5\n"
    h.fail_ops["nginx_test_config"] = 1
    t, inv, ev = make(env, "web", "ssh", "10.9.0.4")
    titles = " | ".join(f["title"] for f in inv.findings)
    assert "returned 503" in titles and "expires in 5 days" in titles and "nginx configuration test failed" in titles


def test_network_and_firewall_agents_use_only_enumerated_cli_topics(env):
    h = env.infra.host("10.9.0.5")
    h.outputs["cli_show"] = "eth1 down\n"
    t, inv, ev = make(env, "firewall", "ssh", "10.9.0.5", labels={"vendor": "fortios"})
    assert t.state == "COMPLETED"
    assert {e.params["topic"] for e in ev} == {"version", "interfaces", "routes", "firewall_rules", "vpn_status"}
    assert any("VPN" in f["title"] or "interface" in f["title"] for f in inv.findings)


def test_vendor_profiles_map_topics_to_fixed_commands():
    from backend.connectors.base import ConnectorError
    from backend.connectors.network.profiles import command_for

    class D: labels = {"vendor": "mikrotik"}
    assert command_for(D, "routes") == "/ip route print"
    D.labels = {"vendor": "unknown"}
    with pytest.raises(ConnectorError):
        command_for(D, "routes")
