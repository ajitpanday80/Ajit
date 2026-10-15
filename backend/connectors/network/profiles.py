"""Fixed vendor profiles mapping a read-only topic to a CLI command."""
from __future__ import annotations

from backend.connectors.base import ConnectorError

PROFILES: dict[str, dict[str, str]] = {
    "vyos": {"version": "show version", "interfaces": "show interfaces", "routes": "show ip route",
             "firewall_rules": "show firewall", "vpn_status": "show vpn ipsec sa", "nat": "show nat source rules",
             "system_resources": "show system memory", "arp": "show arp"},
    "cisco_ios": {"version": "show version", "interfaces": "show ip interface brief", "routes": "show ip route",
                  "firewall_rules": "show access-lists", "vpn_status": "show crypto session",
                  "nat": "show ip nat translations", "system_resources": "show processes cpu",
                  "arp": "show ip arp"},
    "fortios": {"version": "get system status", "interfaces": "get system interface physical",
                "routes": "get router info routing-table all", "firewall_rules": "show firewall policy",
                "vpn_status": "get vpn ipsec tunnel summary", "nat": "show firewall central-snat-map",
                "system_resources": "get system performance status", "arp": "get system arp"},
    "mikrotik": {"version": "/system resource print", "interfaces": "/interface print",
                 "routes": "/ip route print", "firewall_rules": "/ip firewall filter print",
                 "vpn_status": "/ip ipsec active-peers print", "nat": "/ip firewall nat print",
                 "system_resources": "/system resource print", "arp": "/ip arp print"},
    "linux": {"version": "uname -a", "interfaces": "ip -s link", "routes": "ip route",
              "firewall_rules": "nft list ruleset", "vpn_status": "ipsec statusall",
              "nat": "nft list table ip nat", "system_resources": "free -m", "arp": "ip neigh"},
}


def command_for(device, topic: str) -> str:
    vendor = (device.labels or {}).get("vendor", "linux")
    try:
        return PROFILES[vendor][topic]
    except KeyError:
        raise ConnectorError(f"no '{topic}' command for vendor '{vendor}'") from None
