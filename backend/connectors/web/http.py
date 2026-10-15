"""HTTP(S) probe connector."""
from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone

import requests

from backend.connectors.base import ConnectionLost, Connector, ConnectorError, ExecResult
from backend.operations.registry import RenderedCommand


class HttpConnector(Connector):
    protocols = ("http",)

    def run(self, cmd: RenderedCommand) -> ExecResult:
        d = self.device
        scheme = (d.labels or {}).get("scheme", "https")
        port = f":{d.port}" if d.port else ""
        url = f"{scheme}://{d.address}{port}{cmd.params.get('path', '/')}"
        started = time.monotonic()
        try:
            r = requests.request(cmd.params.get("method", "GET"), url, timeout=cmd.timeout, allow_redirects=False,
                                 verify=(d.labels or {}).get("verify_tls", True))
        except requests.RequestException as e:
            raise ConnectorError(f"http probe failed: {type(e).__name__}") from e
        ms = int((time.monotonic() - started) * 1000)
        lines = [f"status: {r.status_code}", f"elapsed_ms: {ms}", f"bytes: {len(r.content)}",
                 f"server: {r.headers.get('Server', '')}", f"content_type: {r.headers.get('Content-Type', '')}"]
        if scheme == "https":
            lines.append(f"tls_days_left: {self._tls_days_left(d.address, d.port or 443)}")
        code = 0 if r.status_code < 500 else 1
        return ExecResult(code, "\n".join(lines), "", ms, {"status": r.status_code})

    @staticmethod
    def _tls_days_left(host: str, port: int):
        try:
            with socket.create_connection((host, port), timeout=5) as s, \
                    ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
                exp = ssl.cert_time_to_seconds(t.getpeercert()["notAfter"])
                return int((exp - datetime.now(timezone.utc).timestamp()) // 86400)
        except Exception:
            return "unknown"
