"""PRTG client: sensor lookup and alarm acknowledgement."""
from __future__ import annotations

import requests

_transport = requests.get


def set_transport(fn) -> None:
    global _transport
    _transport = fn or requests.get


class PrtgError(Exception):
    pass


class PrtgClient:
    def __init__(self, base_url: str, api_token: str, timeout: int = 20, verify_tls: bool = True):
        self.base, self.token, self.timeout, self.verify = base_url.rstrip("/"), api_token, timeout, verify_tls

    def _get(self, path: str, params: dict):
        try:
            r = _transport(f"{self.base}{path}", params={**params, "apitoken": self.token}, timeout=self.timeout,
                           verify=self.verify)
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            raise PrtgError(f"prtg {path}: {type(e).__name__}") from e

    def sensor_status(self, sensor_id: int) -> dict:
        return self._get("/api/table.json", {"content": "sensors", "columns": "objid,device,sensor,status,message",
                                             "filter_objid": int(sensor_id)}).json()

    def acknowledge(self, sensor_id: int, message: str) -> None:
        self._get("/api/acknowledgealarm.htm", {"id": int(sensor_id), "ackmsg": message[:200]})
