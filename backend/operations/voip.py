from backend.operations.registry import OperationSpec, Risk, register

VOIP = frozenset({"voip"})


def _a(name, desc, *cli, parser=None):
    register(OperationSpec(name, desc, Risk.READ, VOIP, "argv", argv=("sudo", "-n", "asterisk", "-rx", *cli),
                           parser=parser))


_a("asterisk_version", "Asterisk version", "core show version")
_a("asterisk_channels", "Active channels", "core show channels")
_a("asterisk_pjsip_endpoints", "PJSIP endpoints", "pjsip show endpoints")
_a("asterisk_sip_peers", "chan_sip peers", "sip show peers")
_a("asterisk_sip_registry", "SIP trunk registry", "sip show registry")
register(OperationSpec("vicidial_processes", "ViciDial/AST processes", Risk.READ, VOIP, "argv",
                       argv=("pgrep", "-af", "AST_"), success_codes=(0, 1)))
