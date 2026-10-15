"""PowerShell Remoting over WinRM (pypsrp).  Pair with a JEA endpoint on the target so the remote side
enforces the same restricted-operation guarantee as the registry does here."""
from __future__ import annotations

import time

from backend.connectors.base import ConnectionLost, Connector, ConnectorError, ExecResult
from backend.operations.registry import RenderedCommand


class WinRMConnector(Connector):
    protocols = ("winrm",)

    def _client(self):
        try:
            from pypsrp.client import Client
        except ImportError as e:  # optional dependency
            raise ConnectorError("pypsrp is not installed") from e
        d, cred = self.device, self.credential
        scheme_ssl = (d.labels or {}).get("winrm_ssl", True)
        return Client(d.address, username=cred.get("username"), password=cred.get("password"),
                      port=d.port or (5986 if scheme_ssl else 5985), ssl=scheme_ssl,
                      cert_validation=(d.labels or {}).get("cert_validation", True),
                      configuration_name=(d.labels or {}).get("jea_endpoint", "Microsoft.PowerShell"),
                      operation_timeout=30, connection_timeout=20)

    def run(self, cmd: RenderedCommand) -> ExecResult:
        client = self._client()
        started = time.monotonic()
        try:
            out, streams, had_errors = client.execute_ps(cmd.script)
        except Exception as e:
            raise ConnectionLost(f"winrm failure: {type(e).__name__}: {e}") from e
        err = "\n".join(str(x) for x in streams.error)
        return ExecResult(1 if had_errors else 0, str(out), err, int((time.monotonic() - started) * 1000))
