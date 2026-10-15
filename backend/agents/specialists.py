from __future__ import annotations

import re

from backend.agents.base import SpecialistAgent

IGNORED_WIN_SERVICES = re.compile(r"^(gupdate|gupdatem|edgeupdate|edgeupdatem|sppsvc|RemoteRegistry|MapsBroker|"
                                  r"TrustedInstaller|clr_optimization.*|CDPUserSvc.*|WbioSrvc|tiledatamodelsvc)$", re.I)


class LinuxAgent(SpecialistAgent):
    name = "linux"
    device_types = ("linux",)
    allowed_ops = ("os_release", "uptime", "load_average", "disk_usage", "inode_usage", "memory", "top_cpu", "top_mem",
                   "listening_ports", "failed_units", "service_status", "service_is_active", "journal_tail",
                   "kernel_messages", "tail_log", "ping_host", "dns_lookup", "package_version")

    def baseline(self):
        ops = [("os_release", {}), ("load_average", {}), ("memory", {}), ("disk_usage", {}), ("failed_units", {})]
        for u in self.hinted_units():
            ops += [("service_is_active", {"unit": u}), ("journal_tail", {"unit": u, "lines": 80})]
        return ops

    def rules(self):
        f, p = [], []
        df = self.first("disk_usage")
        for row in (df.parsed or []) if df else []:
            if row["use_pct"] >= 90:
                f.append(self.finding(f"Filesystem {row['mount']} is {row['use_pct']}% full", "high",
                                      "Disk exhaustion causes service failures; free space or extend the volume.", "disk_usage"))
            elif row["use_pct"] >= 80:
                f.append(self.finding(f"Filesystem {row['mount']} is {row['use_pct']}% full", "medium",
                                      "Approaching capacity.", "disk_usage"))
        mem = self.first("memory")
        if mem and mem.parsed:
            pct = mem.parsed["avail_pct"]
            if pct < 10:
                f.append(self.finding(f"Only {pct}% memory available", "high", "Risk of OOM kills / swapping.", "memory"))
            elif pct < 20:
                f.append(self.finding(f"Low memory ({pct}% available)", "medium", "Monitor for pressure.", "memory"))
        la = self.first("load_average")
        if la and la.parsed and la.parsed["load1"] >= 10:
            f.append(self.finding(f"Very high load average ({la.parsed['load1']})", "high",
                                  "CPU or IO saturation; see top consumers.", "load_average"))
        fu = self.first("failed_units")
        for unit in (fu.parsed or []) if fu else []:
            f.append(self.finding(f"systemd unit {unit} has failed", "high",
                                  "Restarting may restore service; review the journal first.", "failed_units", "journal_tail"))
            p.append({"operation": "service_restart", "params": {"unit": unit}, "source": "rule",
                      "rationale": f"{unit} is in a failed state"})
        for u in self.hinted_units():
            r = self.results.get(f"service_is_active:{sorted({'unit': u}.items())}")
            if r and r.parsed and r.parsed != "active":
                f.append(self.finding(f"Service {u} is {r.parsed}", "high", "The service named in the ticket is not running.",
                                      "service_is_active", "journal_tail"))
                if not any(x["params"].get("unit") == u for x in p):
                    p.append({"operation": "service_restart", "params": {"unit": u}, "source": "rule",
                              "rationale": f"{u} is {r.parsed}"})
        return f, p


class WindowsAgent(SpecialistAgent):
    name = "windows"
    device_types = ("windows", "hyperv", "backup")
    allowed_ops = ("ps_os_info", "ps_disk_usage", "ps_top_cpu", "ps_stopped_auto_services", "ps_service_status",
                   "ps_eventlog", "ps_events_by_provider", "ps_hyperv_vms", "ps_hyperv_vm_status",
                   "ps_hyperv_checkpoints", "ps_shadowprotect_service")

    def baseline(self):
        ops = [("ps_os_info", {}), ("ps_disk_usage", {}), ("ps_stopped_auto_services", {}),
               ("ps_eventlog", {"log": "System", "count": 30})]
        if self.device.device_type == "hyperv":
            ops.append(("ps_hyperv_vms", {}))
        if self.device.device_type == "backup" or "shadowprotect" in (self.task.description or "").lower():
            ops += [("ps_shadowprotect_service", {}), ("ps_events_by_provider", {"provider": "ShadowProtect", "count": 25})]
        return ops

    def rules(self):
        f, p = [], []
        r = self.first("ps_stopped_auto_services")
        names = []
        if r:
            for line in r.stdout.splitlines():
                m = re.match(r"^(\S+)\s+(Stopped|StopPending|Paused)\b", line, re.I)
                if m and not IGNORED_WIN_SERVICES.match(m.group(1)):
                    names.append(m.group(1))
        for n in names[:5]:
            f.append(self.finding(f"Automatic service '{n}' is not running", "high",
                                  "An automatic-start service has stopped.", "ps_stopped_auto_services"))
            p.append({"operation": "ps_service_restart", "params": {"name": n}, "source": "rule",
                      "rationale": f"{n} is configured Automatic but is stopped"})
        sp = self.first("ps_shadowprotect_service")
        if sp and "Running" not in sp.stdout:
            f.append(self.finding("ShadowProtect service is not running", "critical",
                                  "Backups are not being taken.", "ps_shadowprotect_service"))
        ev = self.first("ps_events_by_provider")
        if ev and re.search(r"Level.*:\s*(Error|Critical)", ev.stdout):
            f.append(self.finding("ShadowProtect reported errors", "high", "Recent backup job errors in the event log.",
                                  "ps_events_by_provider"))
        vms = self.first("ps_hyperv_vms")
        if vms and re.search(r"\b(Off|Critical|Paused)\b", vms.stdout):
            f.append(self.finding("One or more Hyper-V VMs are not running", "medium", "VM state is Off/Critical/Paused.",
                                  "ps_hyperv_vms"))
        return f, p


class VoipAgent(LinuxAgent):
    name = "voip"
    device_types = ("voip",)
    allowed_ops = LinuxAgent.allowed_ops + ("asterisk_version", "asterisk_channels", "asterisk_pjsip_endpoints",
                                            "asterisk_sip_peers", "asterisk_sip_registry", "vicidial_processes")

    def baseline(self):
        return super().baseline() + [("asterisk_version", {}), ("asterisk_channels", {}), ("asterisk_sip_registry", {}),
                                     ("vicidial_processes", {})]

    def rules(self):
        f, p = super().rules()
        v = self.first("asterisk_version")
        if v and v.result.exit_code != 0:
            f.append(self.finding("Asterisk CLI is not responding", "critical", "The Asterisk daemon may be down.",
                                  "asterisk_version"))
            p.append({"operation": "service_restart", "params": {"unit": "asterisk"}, "source": "rule",
                      "rationale": "Asterisk is not answering CLI commands"})
        reg = self.first("asterisk_sip_registry")
        if reg and re.search(r"\b(Rejected|Unregistered|Failed|Request Sent)\b", reg.stdout):
            f.append(self.finding("SIP trunk registration problem", "high", "At least one trunk is not Registered.",
                                  "asterisk_sip_registry"))
        return f, p


class WebAgent(LinuxAgent):
    name = "web"
    device_types = ("web",)
    allowed_ops = LinuxAgent.allowed_ops + ("http_probe", "nginx_test_config", "apache_test_config")

    def baseline(self):
        return [("http_probe", {})] + super().baseline() + [("nginx_test_config", {})]

    def rules(self):
        f, p = super().rules()
        h = self.first("http_probe")
        if h:
            m = re.search(r"status:\s*(\d+)", h.stdout)
            if m and int(m.group(1)) >= 500:
                f.append(self.finding(f"HTTP probe returned {m.group(1)}", "high", "Server-side error.", "http_probe"))
            t = re.search(r"tls_days_left:\s*(-?\d+)", h.stdout)
            if t and int(t.group(1)) < 14:
                f.append(self.finding(f"TLS certificate expires in {t.group(1)} days", "high", "Renew the certificate.", "http_probe"))
            elif t and int(t.group(1)) < 30:
                f.append(self.finding(f"TLS certificate expires in {t.group(1)} days", "medium", "Plan a renewal.", "http_probe"))
        else:
            f.append(self.finding("HTTP probe failed", "critical", "The web endpoint did not answer.", "http_probe"))
        n = self.first("nginx_test_config")
        if n and n.result.exit_code != 0:
            f.append(self.finding("nginx configuration test failed", "high", n.result.output[:300], "nginx_test_config"))
        return f, p


class NetworkAgent(SpecialistAgent):
    name = "network"
    device_types = ("router",)
    allowed_ops = ("cli_show", "ping_host", "net_traceroute", "net_interfaces", "net_routes")

    def baseline(self):
        return [("cli_show", {"topic": "version"}), ("cli_show", {"topic": "interfaces"}), ("cli_show", {"topic": "routes"})]

    def rules(self):
        f = []
        r = self.first("cli_show")
        ifs = next((v for k, v in self.results.items() if "interfaces" in k), None)
        if ifs:
            down = [l for l in ifs.stdout.splitlines() if re.search(r"\b(down|disabled)\b", l, re.I) and "admin" not in l.lower()]
            if down:
                f.append(self.finding(f"{len(down)} interface(s) report down", "medium", "\n".join(down[:5]), "cli_show"))
        return f, []


class FirewallAgent(NetworkAgent):
    name = "firewall"
    device_types = ("firewall",)

    def baseline(self):
        return super().baseline() + [("cli_show", {"topic": "firewall_rules"}), ("cli_show", {"topic": "vpn_status"})]

    def rules(self):
        f, p = super().rules()
        vpn = next((v for k, v in self.results.items() if "vpn_status" in k), None)
        if vpn and re.search(r"\b(down|no (ipsec|tunnels?|sa)|not established)\b", vpn.stdout, re.I):
            f.append(self.finding("VPN tunnel(s) not established", "high", vpn.stdout[:300], "cli_show"))
        return f, p


AGENTS = {a.name: a for a in (LinuxAgent, WindowsAgent, VoipAgent, WebAgent, NetworkAgent, FirewallAgent)}
_BY_TYPE = {"linux": LinuxAgent, "windows": WindowsAgent, "hyperv": WindowsAgent, "backup": WindowsAgent,
            "voip": VoipAgent, "web": WebAgent, "router": NetworkAgent, "firewall": FirewallAgent}


def agent_for(device_type: str):
    return _BY_TYPE.get(device_type)
