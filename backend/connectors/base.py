"""Connector contract.  Connectors execute a ``RenderedCommand`` and nothing else.

Only ``backend.executor.runner`` may call connectors (enforced by a test).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from backend.operations.registry import RenderedCommand


class ConnectorError(Exception):
    """Connection/transport failure (device unreachable, auth failed, timeout)."""


class ConnectionLost(ConnectorError):
    """Connection dropped mid-operation: outcome of the command is unknown."""


@dataclass
class ExecResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    meta: dict = field(default_factory=dict)

    @property
    def output(self) -> str:
        return self.stdout + (("\n[stderr]\n" + self.stderr) if self.stderr.strip() else "")


class Connector:
    protocols: tuple[str, ...] = ()

    def __init__(self, device, credential: dict | None):
        self.device = device
        self.credential = credential or {}

    def run(self, cmd: RenderedCommand) -> ExecResult:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass


_factory: Callable | None = None


def set_connector_factory(factory: Callable | None) -> None:
    """Override connector creation (tests / simulation).  ``factory(device, credential) -> Connector``."""
    global _factory
    _factory = factory


SUPPORTED_INTERPRETERS = {
    "ssh": {"argv", "cli", "http"},
    "winrm": {"powershell"},
    "http": {"http"},
    "fake": {"argv", "cli", "http", "powershell"},
}


def get_connector(device, credential: dict | None, interpreter: str = "argv") -> Connector:
    if _factory is not None:
        return _factory(device, credential)
    if interpreter == "http":
        from backend.connectors.web.http import HttpConnector
        return HttpConnector(device, credential)
    if interpreter == "powershell":
        from backend.connectors.windows.winrm import WinRMConnector
        return WinRMConnector(device, credential)
    if interpreter in ("argv", "cli"):
        from backend.connectors.linux.ssh import SSHConnector
        return SSHConnector(device, credential)
    raise ConnectorError(f"no connector for '{interpreter}'")
