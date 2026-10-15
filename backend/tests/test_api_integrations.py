"""End-to-end through HTTP, webhooks and MSP integrations."""
import json

import pytest
from sqlalchemy import select

from backend.connectors.autotask import client as at_client
from backend.connectors.prtg import client as prtg_client
from backend.db import session
from backend.models import AuditEvent, Client, Device, IntegrationAccount, MonitoringAlert, Task, Ticket, TimeEntry
from backend.services import svc
from backend.tenancy import tenant_scope
from backend.tests.conftest import login, sign


class FakeResp:
    def __init__(self, data=None):
        self._d, self.content = data or {}, b"{}"

    def raise_for_status(self):
        pass

    def json(self):
        return self._d


def api(env, h, method, url, **kw):
    r = getattr(env.http, method)(url, headers=h, **kw)
    return r.status_code, (r.get_json() if r.is_json else None)


def test_full_http_flow_analysis_then_maintenance(env):
    env.host.services["nginx.service"] = "failed"
    tech, appr = login(env, env.a, "technician"), login(env, env.a, "approver")
    code, task = api(env, tech, "post", "/api/tasks", json={"device_id": env.a.device_id, "mode": "maintenance",
                                                              "title": "nginx down", "description": "service:nginx.service"})
    assert code == 202 and task["state"] == "AWAITING_APPROVAL"                     # inline jobs ran the investigation
    code, detail = api(env, tech, "get", f"/api/tasks/{task['id']}")
    assert detail["investigation"]["findings"] and detail["plans"][0]["status"] == "pending_approval"
    plan = detail["plans"][0]
    # technician cannot approve; execution is refused until approved
    assert api(env, tech, "post", f"/api/plans/{plan['id']}/decision", json={"decision": "approve"})[0] == 403
    assert api(env, tech, "post", f"/api/plans/{plan['id']}/execute")[0] == 409
    # approver must approve the exact hash they saw
    assert api(env, appr, "post", f"/api/plans/{plan['id']}/decision", json={"decision": "approve", "plan_hash": "0" * 64})[0] == 409
    assert api(env, appr, "post", f"/api/plans/{plan['id']}/decision",
               json={"decision": "approve", "plan_hash": plan["plan_hash"], "comment": "go"})[0] == 200
    code, res = api(env, tech, "post", f"/api/plans/{plan['id']}/execute")
    assert code == 202 and res["run"]["status"] == "SUCCEEDED"
    code, detail = api(env, tech, "get", f"/api/tasks/{task['id']}")
    assert detail["state"] == "SUCCEEDED" and detail["runs"][0]["state_diff"]["0"]["after"] == "active"
    assert api(env, tech, "get", f"/api/tasks/{task['id']}/report")[1]["content"].startswith("# Incident report")
    assert [e["to_state"] for e in api(env, tech, "get", f"/api/tasks/{task['id']}/timeline")[1]][-1] == "SUCCEEDED"
    assert api(env, tech, "get", f"/api/tasks/{task['id']}/evidence")[1]
    assert api(env, tech, "get", f"/api/tasks/{task['id']}/time")[1][0]["minutes"] >= 1
    assert api(env, appr, "get", "/api/audit/verify")[1]["ok"] is True


def test_rejected_plan_never_executes(env):
    env.host.services["nginx.service"] = "failed"
    tech, appr = login(env, env.a, "technician"), login(env, env.a, "approver")
    _, task = api(env, tech, "post", "/api/tasks", json={"device_id": env.a.device_id, "mode": "maintenance", "title": "t",
                                                          "description": "service:nginx.service"})
    plan = api(env, tech, "get", f"/api/tasks/{task['id']}")[1]["plans"][0]
    assert api(env, appr, "post", f"/api/plans/{plan['id']}/decision", json={"decision": "reject", "comment": "no"})[0] == 200
    assert api(env, tech, "post", f"/api/plans/{plan['id']}/execute")[0] == 409
    assert env.host.calls("service_restart") == 0
    assert api(env, tech, "get", f"/api/tasks/{task['id']}")[1]["state"] == "REJECTED"


def test_viewer_cannot_request_maintenance_and_validation_errors(env):
    tech = login(env, env.a, "technician")
    assert api(env, tech, "post", "/api/tasks", json={"device_id": env.a.device_id, "mode": "yolo", "title": "t"})[0] == 400
    assert api(env, tech, "post", "/api/tasks", json={"title": "t"})[0] == 400
    assert api(env, tech, "post", "/api/devices", json={"client_id": env.a.client_id, "hostname": "h", "address": "a",
                                                          "device_type": "toaster"})[0] == 400


def test_stream_ends_for_finished_task(env):
    tech = login(env, env.a, "technician")
    _, task = api(env, tech, "post", "/api/tasks", json={"device_id": env.a.device_id, "mode": "analysis_only", "title": "t"})
    r = env.http.get(f"/api/tasks/{task['id']}/stream", headers=tech)
    body = r.get_data(as_text=True)
    assert "event: transition" in body and "event: end" in body and "COMPLETED" in body


def test_security_headers_and_error_shape(env):
    r = env.http.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["Cache-Control"] == "no-store"
    r = env.http.get("/api/nope")
    assert r.status_code == 404 and r.get_json() == {"error": "not found"}


# ------------------------------------------------------------------ integrations
@pytest.fixture
def autotask(env):
    calls = []

    def transport(method, url, **kw):
        calls.append((method, url.split("/V1.0")[1], kw.get("json")))
        return FakeResp({"item": {}})
    at_client.set_transport(transport)
    h = login(env, env.a, "tenant_admin")
    _, cred = api(env, h, "post", "/api/credentials", json={"name": "at", "kind": "api_token", "username": "user",
                                                           "secret": {"secret": "s3", "webhook_secret": "whsec"}})
    _, integ = api(env, h, "post", "/api/integrations", json={
        "kind": "autotask", "name": "AT", "base_url": "https://at.example/atservicesrest", "credential_id": cred["id"],
        "settings": {"integration_code": "code", "default_mode": "analysis_only", "resolved_status_id": 5}})
    with tenant_scope(env.a.id):
        session().get(Client, env.a.client_id).autotask_company_id = "777"
        session().get(Device, env.a.device_id).autotask_ci_id = "42"
        session().commit()
    yield integ, calls
    at_client.set_transport(None)


def post_webhook(env, kind, iid, payload, secret="whsec", sig=None):
    raw = json.dumps(payload).encode()
    return env.http.post(f"/api/webhooks/{kind}/{iid}", data=raw, content_type="application/json",
                         headers={"X-Signature": sig or sign(secret, raw)})


def test_webhook_signature_required(env, autotask):
    integ, _ = autotask
    p = {"id": 1, "title": "t", "companyID": "777", "configurationItemID": "42"}
    assert post_webhook(env, "autotask", integ["id"], p, sig="deadbeef").status_code == 401
    assert post_webhook(env, "autotask", integ["id"], p, secret="wrong").status_code == 401
    assert post_webhook(env, "autotask", 9999, p).status_code == 404
    assert post_webhook(env, "prtg", integ["id"], p).status_code == 404          # wrong kind
    with tenant_scope(env.a.id):
        assert session().scalar(select(Task)) is None


def test_autotask_ticket_drives_investigation_and_posts_note_and_time(env, autotask):
    integ, calls = autotask
    env.host.services["nginx.service"] = "failed"
    r = post_webhook(env, "autotask", integ["id"], {"id": 1001, "title": "Site down", "companyID": "777",
                                                    "configurationItemID": "42", "description": "service:nginx.service"})
    assert r.status_code == 202 and r.get_json()["task_id"]
    again = post_webhook(env, "autotask", integ["id"], {"id": 1001, "title": "Site down", "companyID": "777", "configurationItemID": "42"})
    assert again.get_json()["task_id"] == r.get_json()["task_id"]                  # idempotent redelivery
    with tenant_scope(env.a.id):
        t = session().get(Task, r.get_json()["task_id"])
        assert t.state == "COMPLETED" and t.mode == "analysis_only" and t.source == "autotask"
        assert session().scalar(select(Ticket)).status == "correlated"
        assert env.host.calls("service_restart") == 0
    kinds = [(m, p) for m, p, _ in calls]
    assert ("POST", "/Tickets/1001/Notes") in kinds and ("POST", "/TimeEntries") in kinds
    assert not any(m == "PATCH" for m, _ in kinds)                                  # analysis only never closes a ticket
    assert any("Closure not performed" in (b or {}).get("title", "") for _, _, b in calls)


def test_uncorrelated_ticket_is_stored_but_creates_no_task(env, autotask):
    integ, _ = autotask
    r = post_webhook(env, "autotask", integ["id"], {"id": 5, "title": "x", "companyID": "999"})
    assert r.status_code == 202 and r.get_json()["task_id"] is None
    with tenant_scope(env.a.id):
        assert session().scalar(select(Ticket)).status == "uncorrelated"


def test_ticket_closure_only_after_verified_success_and_only_when_enabled(env, autotask):
    integ, calls = autotask
    env.host.services["nginx.service"] = "failed"
    admin = login(env, env.a, "tenant_admin")
    # opt in everywhere: integration setting + client setting + maintenance default mode
    with tenant_scope(env.a.id):
        i = session().get(IntegrationAccount, integ["id"])
        i.settings = {**i.settings, "auto_close": True, "default_mode": "maintenance"}
        c = session().get(Client, env.a.client_id)
        c.settings = {"allow_auto_close": True}
        session().commit()
    post_webhook(env, "autotask", integ["id"], {"id": 2001, "title": "down", "companyID": "777", "configurationItemID": "42",
                                                 "description": "service:nginx.service"})
    with tenant_scope(env.a.id):
        task = session().scalar(select(Task))
        assert task.state == "AWAITING_APPROVAL"
        assert not any(m == "PATCH" for m, _, _ in calls)
    appr, tech = login(env, env.a, "approver"), login(env, env.a, "technician")
    plan_id = api(env, tech, "get", f"/api/tasks/{task.id}")[1]["plans"][0]["id"]
    api(env, appr, "post", f"/api/plans/{plan_id}/decision", json={"decision": "approve"})
    api(env, tech, "post", f"/api/plans/{plan_id}/execute")
    assert ("PATCH", "/Tickets", {"id": 2001, "status": 5}) in calls
    with tenant_scope(env.a.id):
        assert session().scalar(select(Ticket)).status == "closed"


def test_ticket_not_closed_when_run_rolled_back(env, autotask):
    integ, calls = autotask
    env.host.services["nginx.service"] = "failed"
    env.host.restart_works = False
    with tenant_scope(env.a.id):
        i = session().get(IntegrationAccount, integ["id"])
        i.settings = {**i.settings, "auto_close": True, "default_mode": "maintenance"}
        session().get(Client, env.a.client_id).settings = {"allow_auto_close": True}
        session().commit()
    post_webhook(env, "autotask", integ["id"], {"id": 3, "title": "d", "companyID": "777", "configurationItemID": "42", "description": "service:nginx.service"})
    appr, tech = login(env, env.a, "approver"), login(env, env.a, "technician")
    with tenant_scope(env.a.id):
        task = session().scalar(select(Task))
    plan_id = api(env, tech, "get", f"/api/tasks/{task.id}")[1]["plans"][0]["id"]
    api(env, appr, "post", f"/api/plans/{plan_id}/decision", json={"decision": "approve"})
    api(env, tech, "post", f"/api/plans/{plan_id}/execute")
    assert not any(m == "PATCH" for m, _, _ in calls)
    assert any("Closure not performed" in (b or {}).get("title", "") for _, _, b in calls)


def test_prtg_alert_creates_task_and_ack_requires_verified_success(env):
    acks = []
    prtg_client.set_transport(lambda url, **kw: (acks.append((url, kw["params"])), FakeResp())[1])
    try:
        h = login(env, env.a, "tenant_admin")
        _, cred = api(env, h, "post", "/api/credentials", json={"name": "p", "kind": "api_token", "secret": {"token": "tok", "webhook_secret": "ws"}})
        _, integ = api(env, h, "post", "/api/integrations", json={"kind": "prtg", "name": "P", "base_url": "https://prtg.example",
                                                                    "credential_id": cred["id"], "settings": {"auto_ack": True, "default_mode": "analysis_only"}})
        with tenant_scope(env.a.id):
            session().get(Device, env.a.device_id).prtg_device_id = "2001"
            session().commit()
        r = post_webhook(env, "prtg", integ["id"], {"sensorid": 77, "deviceid": 2001, "sensor": "HTTP", "status": "Down"}, secret="ws")
        assert r.status_code == 202 and r.get_json()["task_id"]
        with tenant_scope(env.a.id):
            al = session().scalar(select(MonitoringAlert))
            assert al.task_id == r.get_json()["task_id"] and al.acknowledged is False
        assert acks == []                                          # analysis only / not verified → monitor stays loud
    finally:
        prtg_client.set_transport(None)


def test_integration_failure_never_changes_outcome(env, autotask):
    integ, _ = autotask
    at_client.set_transport(lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = post_webhook(env, "autotask", integ["id"], {"id": 9, "title": "x", "companyID": "777", "configurationItemID": "42"})
    with tenant_scope(env.a.id):
        assert session().get(Task, r.get_json()["task_id"]).state == "COMPLETED"
        assert session().scalar(select(AuditEvent).where(AuditEvent.action == "integration.error"))


def test_dashboard_summary_is_tenant_scoped_and_accurate(env):
    env.host.services["nginx.service"] = "failed"
    tech, other = login(env, env.a, "technician"), login(env, env.b, "technician")
    api(env, tech, "post", "/api/tasks", json={"device_id": env.a.device_id, "mode": "maintenance", "title": "a1", "description": "service:nginx.service"})
    api(env, tech, "post", "/api/tasks", json={"device_id": env.a.device_id, "mode": "analysis_only", "title": "a2"})
    code, d = api(env, tech, "get", "/api/dashboard/summary?days=14")
    assert code == 200 and d["kpis"]["investigations"] == 2 and d["kpis"]["awaiting_approval"] == 1
    assert sum(x["count"] for x in d["per_day"]) == 2 and len(d["per_day"]) == 14
    assert d["attention"][0]["state"] == "AWAITING_APPROVAL" and d["posture"]["audit_chain_ok"] is True
    assert {x["severity"]: x["count"] for x in d["by_severity"]}["high"] >= 1
    _, o = api(env, other, "get", "/api/dashboard/summary")
    assert o["kpis"]["investigations"] == 0 and o["attention"] == [] and o["recent"] == []
    assert api(env, tech, "get", "/api/dashboard/summary?days=5")[0] == 400
