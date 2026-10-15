from backend.operations.registry import (HOST, UNIT, OperationSpec, Param, Probe, RecoveryLevel, Risk, register)

LINUX = frozenset({"linux", "voip", "web"})
SSHLIKE = frozenset({"linux", "voip", "web", "router", "firewall"})
LOGPATH = Param("path", pattern=r"/var/log/[A-Za-z0-9._/-]{1,150}", forbid=("..", "//"))
UNIT_P = Param("unit", pattern=UNIT)


def _read(name, desc, argv, dev=LINUX, params=(), parser=None, success=(0,), timeout=30):
    return register(OperationSpec(name, desc, Risk.READ, dev, "argv", params=params, argv=argv,
                                  parser=parser, success_codes=success, timeout=timeout))


_read("os_release", "OS identification", ("cat", "/etc/os-release"))
_read("uptime", "Uptime and load", ("uptime",))
_read("load_average", "Load averages", ("cat", "/proc/loadavg"), parser="loadavg")
_read("disk_usage", "Filesystem usage", ("df", "-hP"), parser="df")
_read("inode_usage", "Inode usage", ("df", "-iP"), parser="df")
_read("memory", "Memory usage", ("free", "-m"), parser="free")
_read("top_cpu", "Top CPU consumers", ("ps", "-eo", "pid,user,pcpu,pmem,comm", "--sort=-pcpu"))
_read("top_mem", "Top memory consumers", ("ps", "-eo", "pid,user,pcpu,pmem,comm", "--sort=-pmem"))
_read("listening_ports", "Listening sockets", ("ss", "-tulpn"))
_read("failed_units", "Failed systemd units", ("systemctl", "--failed", "--no-pager", "--plain", "--no-legend"),
      parser="failed_units")
_read("service_status", "systemd unit status", ("systemctl", "status", "{unit}", "--no-pager", "-l"),
      params=(UNIT_P,), success=(0, 3, 4))
_read("service_is_active", "Is the unit active", ("systemctl", "is-active", "{unit}"), params=(UNIT_P,),
      success=(0, 3, 4), parser="state_word")
_read("service_is_enabled", "Is the unit enabled", ("systemctl", "is-enabled", "{unit}"), params=(UNIT_P,),
      success=(0, 1, 3, 4), parser="state_word")
_read("service_exists", "Does the unit exist", ("systemctl", "cat", "{unit}"), params=(UNIT_P,))
_read("journal_tail", "Recent journal lines for a unit",
      ("journalctl", "-u", "{unit}", "-n", "{lines}", "--no-pager"),
      params=(UNIT_P, Param("lines", "int", min=1, max=500, default=100, required=False)))
_read("kernel_messages", "Kernel warnings/errors", ("dmesg", "--level=err,warn", "-T"), success=(0, 1))
_read("tail_log", "Tail a file under /var/log", ("tail", "-n", "{lines}", "{path}"),
      params=(LOGPATH, Param("lines", "int", min=1, max=500, default=100, required=False)))
_read("file_sha256", "Checksum of a log file", ("sha256sum", "{path}"), params=(LOGPATH,))
_read("ping_host", "ICMP reachability from the device", ("ping", "-c", "3", "-W", "2", "{host}"),
      dev=SSHLIKE, params=(Param("host", pattern=HOST),), success=(0, 1, 2))
_read("dns_lookup", "Resolve a name on the device", ("getent", "hosts", "{host}"),
      params=(Param("host", pattern=HOST),), success=(0, 2))
_read("package_version", "Installed package version", ("dpkg-query", "-W", "-f=${Version}", "{package}"),
      params=(Param("package", pattern=r"[a-z0-9][a-z0-9+.-]{1,80}"),), success=(0, 1))


# ---- mutations (privileged via sudo -n; sudoers on the target must whitelist exactly these) ----
def _svc(name, verb, desc, risk, expect_word, rollbacks):
    return register(OperationSpec(
        name, desc, risk, LINUX, "argv", params=(UNIT_P,),
        argv=("sudo", "-n", "systemctl", verb, "{unit}"),
        backup="service_state", min_recovery=RecoveryLevel.VERIFIED,
        precondition=Probe("service_exists", {"unit": "{unit}"}),
        state_probe=Probe("service_is_active", {"unit": "{unit}"}),
        verify=Probe("service_is_active", {"unit": "{unit}"}, ("equals", expect_word)),
        rollback_candidates=rollbacks, timeout=90))


_svc("service_restart", "restart", "Restart a systemd unit", Risk.MUTATE, "active", ("service_start", "service_stop"))
_svc("service_reload", "reload", "Reload a systemd unit", Risk.MUTATE, "active", ("service_start", "service_stop"))
_svc("service_start", "start", "Start a systemd unit", Risk.MUTATE, "active", ("service_stop",))
_svc("service_stop", "stop", "Stop a systemd unit", Risk.MUTATE, "inactive", ("service_start",))

register(OperationSpec(
    "package_upgrade", "Upgrade a single package", Risk.DESTRUCTIVE, LINUX, "argv",
    params=(Param("package", pattern=r"[a-z0-9][a-z0-9+.-]{1,80}"),),
    argv=("sudo", "-n", "apt-get", "install", "--only-upgrade", "-y", "{package}"),
    backup="package_version", min_recovery=RecoveryLevel.EXPORT_ONLY,   # version recorded, no tested downgrade
    precondition=Probe("package_version", {"package": "{package}"}, ("regex", r"\S")),   # must be installed
    state_probe=Probe("package_version", {"package": "{package}"}),
    verify=Probe("package_version", {"package": "{package}"}, ("regex", r"\S")),         # still installed
    rollback_candidates=(), timeout=600))
