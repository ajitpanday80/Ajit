"""Deterministic in-memory infrastructure for development, demos and failure-injection tests."""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.connectors.base import ConnectionLost, Connector, ConnectorError, ExecResult
from backend.operations.registry import RenderedCommand

DF = """Filesystem     Size  Used Avail Use% Mounted on
/dev/sda1       50G   {pct}%  ... {pct}% /
tmpfs          2.0G     0  2.0G   0% /dev/shm
"""


@dataclass
class FakeHost:
    services: dict = field(default_factory=lambda: {"nginx.service": "active"})
    win_services: dict = field(default_factory=dict)
    packages: dict = field(default_factory=lambda: {"openssl": "3.0.2"})
    upgrade_version: dict = field(default_factory=dict)
    disk_pct: int = 45
    mem_avail_pct: float = 60
    load1: float = 0.4
    unreachable: bool = False
    restart_works: bool = True           # False: restart leaves the unit failed
    fail_ops: dict = field(default_factory=dict)         # op -> exit code
    lose_before: set = field(default_factory=set)        # drop connection before executing op
    lose_after: set = field(default_factory=set)         # execute op, then drop connection
    outputs: dict = field(default_factory=dict)          # op -> canned stdout override
    log: list = field(default_factory=list)              # (operation, display)
    secret_in_logs: str = ""
    crash_after: set = field(default_factory=set)        # simulate worker death after op took effect
    dies_on_loss: bool = False                           # host stays unreachable once a connection is lost

    def calls(self, op: str) -> int:
        return sum(1 for o, _ in self.log if o == op)


class WorkerCrash(BaseException):
    """Simulates the worker process dying (not catchable by ``except Exception``)."""


class FakeInfrastructure:
    def __init__(self, auto: bool = False):
        self.hosts: dict[str, FakeHost] = {}
        self.auto = auto          # demo mode: unknown addresses get a default healthy host

    def host(self, address: str, **kw) -> FakeHost:
        h = self.hosts.setdefault(address, FakeHost(**kw))
        return h

    def factory(self, device, credential):
        if self.auto and device.address not in self.hosts:
            self.hosts[device.address] = FakeHost()
        return FakeConnector(device, credential, self)


class FakeConnector(Connector):
    protocols = ("fake", "ssh", "winrm", "http")

    def __init__(self, device, credential, infra: FakeInfrastructure):
        super().__init__(device, credential)
        self.infra = infra

    def run(self, cmd: RenderedCommand) -> ExecResult:
        h = self.infra.hosts.get(self.device.address)
        if h is None or h.unreachable:
            raise ConnectorError("host unreachable")
        op = cmd.operation
        if op in h.lose_before:
            h.lose_before.discard(op)
            h.unreachable = h.dies_on_loss
            raise ConnectionLost("connection dropped before command")
        h.log.append((op, cmd.display))
        result = self._exec(h, cmd)
        if op in h.lose_after:
            h.lose_after.discard(op)
            h.unreachable = h.dies_on_loss
            raise ConnectionLost("connection dropped after command ran")
        if op in h.crash_after:
            h.crash_after.discard(op)
            raise WorkerCrash()
        return result

    # ------------------------------------------------------------------
    def _exec(self, h: FakeHost, cmd: RenderedCommand) -> ExecResult:
        op, p = cmd.operation, cmd.params
        if op in h.fail_ops:
            return ExecResult(h.fail_ops[op], "", f"{op} failed (injected)")
        if op in h.outputs:
            return ExecResult(0, h.outputs[op])
        # ---- systemd
        if op in ("service_is_active", "service_status", "service_exists", "service_is_enabled"):
            st = h.services.get(p["unit"])
            if op == "service_exists":
                return ExecResult(0 if st else 1, f"[Unit]\nDescription={p['unit']}\n" if st else "", "" if st else "No files found")
            if st is None:
                return ExecResult(4, "unknown\n")
            if op == "service_is_enabled":
                return ExecResult(0, "enabled\n")
            return ExecResult(0 if st == "active" else 3, f"{st}\n" if op == "service_is_active" else
                              f"● {p['unit']}\n   Active: {st}\n")
        if op in ("service_restart", "service_reload", "service_start", "service_stop"):
            if p["unit"] not in h.services:
                return ExecResult(5, "", "Unit not found")
            if op == "service_stop":
                h.services[p["unit"]] = "inactive"
            else:
                h.services[p["unit"]] = "active" if (h.restart_works or op == "service_start") else "failed"
            return ExecResult(0)
        # ---- windows services
        if op in ("ps_service_state", "ps_service_status", "ps_service_exists"):
            st = h.win_services.get(p["name"])
            if st is None:
                return ExecResult(1, "", "Cannot find any service")
            return ExecResult(0, f"{st}\n")
        if op in ("ps_service_restart", "ps_service_start", "ps_service_stop"):
            if p["name"] not in h.win_services:
                return ExecResult(1, "", "Cannot find any service")
            h.win_services[p["name"]] = "stopped" if op == "ps_service_stop" else (
                "running" if h.restart_works or op == "ps_service_start" else "stopped")
            return ExecResult(0)
        # ---- packages
        if op == "package_version":
            v = h.packages.get(p["package"])
            return ExecResult(0 if v else 1, v or "")
        if op == "package_upgrade":
            h.packages[p["package"]] = h.upgrade_version.get(p["package"], "9.9.9")
            return ExecResult(0, "upgraded")
        # ---- diagnostics
        if op == "disk_usage":
            return ExecResult(0, DF.format(pct=h.disk_pct))
        if op == "memory":
            tot = 8000
            return ExecResult(0, "              total        used        free      shared  buff/cache   available\n"
                                 f"Mem:           {tot}        1000        1000          10        1000       {int(tot * h.mem_avail_pct / 100)}\n")
        if op == "load_average":
            return ExecResult(0, f"{h.load1} {h.load1} {h.load1} 1/200 1234\n")
        if op == "failed_units":
            failed = [u for u, s in h.services.items() if s == "failed"]
            return ExecResult(0, "".join(f"● {u} loaded failed failed {u}\n" for u in failed))
        if op == "journal_tail":
            return ExecResult(0, f"Oct 15 10:00:01 host {p['unit']}[1]: started\n{h.secret_in_logs}")
        if op == "tail_log":
            return ExecResult(0, f"2026/10/15 10:00:00 [error] upstream timed out\n{h.secret_in_logs}")
        if op == "http_probe":
            return ExecResult(0, "status: 200\nelapsed_ms: 40\ntls_days_left: 60\n")
        if op == "ping_host":
            return ExecResult(0, "3 packets transmitted, 3 received, 0% packet loss\n")
        if op == "cli_show":
            return ExecResult(0, f"{p['topic']}: ok\n")
        return ExecResult(0, f"{op}: ok\n")
