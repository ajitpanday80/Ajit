from backend.operations.registry import (WIN_NAME, OperationSpec, Param, Probe, RecoveryLevel, Risk, register)

WIN = frozenset({"windows", "hyperv", "backup"})
NAME_P = Param("name", pattern=WIN_NAME)


def _ps(name, desc, script, params=(), parser=None, timeout=60):
    return register(OperationSpec(name, desc, Risk.READ, WIN, "powershell", params=params, script=script,
                                  parser=parser, timeout=timeout))


_ps("ps_os_info", "OS and uptime",
    "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,LastBootUpTime,"
    "FreePhysicalMemory,TotalVisibleMemorySize | Format-List")
_ps("ps_disk_usage", "Disk usage",
    "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free | Format-Table -AutoSize")
_ps("ps_top_cpu", "Top CPU processes",
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,WS | Format-Table -AutoSize")
_ps("ps_stopped_auto_services", "Automatic services that are stopped",
    "Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | "
    "Select-Object Name,State,ExitCode | Format-Table -AutoSize")
_ps("ps_service_status", "Service status", "Get-Service -Name {name} | Format-List Name,Status,StartType",
    params=(NAME_P,))
_ps("ps_service_state", "Service state word", "(Get-Service -Name {name}).Status.ToString().ToLower()",
    params=(NAME_P,), parser="state_word")
_ps("ps_service_exists", "Service exists", "Get-Service -Name {name} -ErrorAction Stop | Out-Null",
    params=(NAME_P,))
_ps("ps_eventlog", "Recent event log entries",
    "Get-WinEvent -FilterHashtable @{LogName={log}; Level=1,2,3} -MaxEvents {count} | "
    "Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List",
    params=(Param("log", "enum", choices=("System", "Application")),
            Param("count", "int", min=1, max=200, default=50, required=False)))
_ps("ps_events_by_provider", "Recent events from one provider (e.g. ShadowProtect)",
    "Get-WinEvent -FilterHashtable @{ProviderName={provider}} -MaxEvents {count} | "
    "Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-List",
    params=(Param("provider", pattern=r"[A-Za-z0-9 ._-]{1,80}"),
            Param("count", "int", min=1, max=200, default=25, required=False)))
_ps("ps_hyperv_vms", "Hyper-V virtual machines",
    "Get-VM | Select-Object Name,State,Status,CPUUsage,MemoryAssigned,Uptime | Format-Table -AutoSize")
_ps("ps_hyperv_vm_status", "One Hyper-V VM", "Get-VM -Name {name} | Format-List Name,State,Status,Heartbeat",
    params=(NAME_P,))
_ps("ps_hyperv_checkpoints", "VM checkpoints", "Get-VMSnapshot -VMName {name} | Format-Table -AutoSize",
    params=(NAME_P,))
_ps("ps_shadowprotect_service", "ShadowProtect service state",
    "Get-Service -Name 'ShadowProtectSvc' | Format-List Name,Status,StartType")


def _winsvc(name, verb, desc, expect, rollbacks):
    return register(OperationSpec(
        name, desc, Risk.MUTATE, frozenset({"windows"}), "powershell", params=(NAME_P,),
        script=f"{verb} -Name {{name}} -ErrorAction Stop",
        backup="service_state_win", min_recovery=RecoveryLevel.VERIFIED,
        precondition=Probe("ps_service_exists", {"name": "{name}"}),
        state_probe=Probe("ps_service_state", {"name": "{name}"}),
        verify=Probe("ps_service_state", {"name": "{name}"}, ("equals", expect)),
        rollback_candidates=rollbacks, timeout=120))


_winsvc("ps_service_restart", "Restart-Service", "Restart a Windows service", "running",
        ("ps_service_start", "ps_service_stop"))
_winsvc("ps_service_start", "Start-Service", "Start a Windows service", "running", ("ps_service_stop",))
_winsvc("ps_service_stop", "Stop-Service", "Stop a Windows service", "stopped", ("ps_service_start",))
