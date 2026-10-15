"""SSH connector (Linux, VoIP, web hosts, SSH-managed routers/firewalls)."""
from __future__ import annotations

import io
import time

from backend.connectors.base import ConnectionLost, Connector, ConnectorError, ExecResult
from backend.operations.registry import RenderedCommand


class SSHConnector(Connector):
    protocols = ("ssh",)

    def __init__(self, device, credential):
        super().__init__(device, credential)
        self._client = None

    def _connect(self):
        import paramiko
        if self._client is not None:
            return self._client
        c = paramiko.SSHClient()
        c.load_system_host_keys()
        # Host keys must be pinned (known_hosts) — unknown hosts are rejected, never auto-added.
        c.set_missing_host_key_policy(paramiko.RejectPolicy())
        cred = self.credential
        kwargs = dict(hostname=self.device.address, port=self.device.port or 22, username=cred.get("username"),
                      timeout=15, banner_timeout=15, auth_timeout=15, allow_agent=False, look_for_keys=False)
        if cred.get("private_key"):
            kwargs["pkey"] = paramiko.PKey.from_private_key(io.StringIO(cred["private_key"]),
                                                            password=cred.get("passphrase"))
        else:
            kwargs["password"] = cred.get("password")
        try:
            c.connect(**kwargs)
        except Exception as e:
            raise ConnectorError(f"ssh connect failed: {type(e).__name__}: {e}") from e
        self._client = c
        return c

    def _commandline(self, cmd: RenderedCommand) -> str:
        if cmd.interpreter == "cli":
            from backend.connectors.network.profiles import command_for
            return command_for(self.device, cmd.params["topic"])
        return cmd.shell_line

    def run(self, cmd: RenderedCommand) -> ExecResult:
        client = self._connect()
        started = time.monotonic()
        try:
            _, out, err = client.exec_command(self._commandline(cmd), timeout=cmd.timeout)
            stdout = out.read().decode("utf-8", "replace")
            stderr = err.read().decode("utf-8", "replace")
            code = out.channel.recv_exit_status()
        except Exception as e:
            raise ConnectionLost(f"ssh session lost: {type(e).__name__}: {e}") from e
        return ExecResult(code, stdout, stderr, int((time.monotonic() - started) * 1000))

    def close(self):
        if self._client:
            self._client.close()
            self._client = None
