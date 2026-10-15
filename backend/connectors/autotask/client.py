"""Autotask PSA REST client (tickets, notes, time entries).  Transport is injectable for tests."""
from __future__ import annotations

import requests

_transport = requests.request


def set_transport(fn) -> None:
    global _transport
    _transport = fn or requests.request


class AutotaskError(Exception):
    pass


class AutotaskClient:
    def __init__(self, base_url: str, username: str, secret: str, integration_code: str, timeout: int = 20):
        self.base = base_url.rstrip("/")
        self.headers = {"UserName": username, "Secret": secret, "ApiIntegrationCode": integration_code,
                        "Content-Type": "application/json"}
        self.timeout = timeout

    def _req(self, method: str, path: str, json=None):
        try:
            r = _transport(method, f"{self.base}{path}", headers=self.headers, json=json, timeout=self.timeout)
            r.raise_for_status()
            return r.json() if r.content else {}
        except requests.RequestException as e:
            raise AutotaskError(f"autotask {method} {path}: {type(e).__name__}") from e

    def get_ticket(self, ticket_id: str) -> dict:
        return self._req("GET", f"/V1.0/Tickets/{int(ticket_id)}").get("item", {})

    def add_note(self, ticket_id: str, title: str, description: str, publish: int = 2) -> dict:
        # publish=2 -> internal-only note
        return self._req("POST", f"/V1.0/Tickets/{int(ticket_id)}/Notes",
                         {"title": title[:250], "description": description[:32000], "noteType": 1, "publish": publish})

    def add_time_entry(self, ticket_id: str, minutes: float, summary: str, resource_id: int | None = None) -> dict:
        body = {"ticketID": int(ticket_id), "hoursWorked": round(minutes / 60, 2), "summaryNotes": summary[:8000]}
        if resource_id:
            body["resourceID"] = resource_id
        return self._req("POST", f"/V1.0/TimeEntries", body)

    def set_status(self, ticket_id: str, status_id: int) -> dict:
        return self._req("PATCH", "/V1.0/Tickets", {"id": int(ticket_id), "status": int(status_id)})
