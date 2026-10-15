"""Router/firewall read-only operations.  ``cli_show`` takes an enumerated topic; the connector maps it
to the vendor command via a fixed profile table — no free-form CLI is ever accepted."""
from backend.operations.registry import HOST, OperationSpec, Param, Risk, register

NET = frozenset({"router", "firewall"})
TOPICS = ("version", "interfaces", "routes", "firewall_rules", "vpn_status", "system_resources", "nat", "arp")

register(OperationSpec("cli_show", "Vendor 'show' for a fixed topic", Risk.READ, NET, "cli",
                       params=(Param("topic", "enum", choices=TOPICS),), timeout=45))
register(OperationSpec("net_traceroute", "traceroute from a linux-based device", Risk.READ,
                       frozenset({"linux", "router", "firewall"}), "argv",
                       params=(Param("host", pattern=HOST),),
                       argv=("traceroute", "-n", "-m", "15", "-w", "2", "{host}"), timeout=60,
                       success_codes=(0, 1)))
register(OperationSpec("net_interfaces", "ip -s link", Risk.READ, frozenset({"linux", "router", "firewall"}),
                       "argv", argv=("ip", "-s", "link")))
register(OperationSpec("net_routes", "ip route", Risk.READ, frozenset({"linux", "router", "firewall"}),
                       "argv", argv=("ip", "route")))
