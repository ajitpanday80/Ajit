from backend.operations.registry import OperationSpec, Param, Risk, register

WEB = frozenset({"web"})

register(OperationSpec(
    "http_probe", "HTTP(S) probe of the device: status, latency, TLS expiry", Risk.READ, frozenset({"web", "linux", "voip"}),
    "http", params=(Param("path", pattern=r"/[A-Za-z0-9._~/%-]{0,200}", default="/", required=False, forbid=("..",)),
                    Param("method", "enum", choices=("GET", "HEAD"), default="GET", required=False))))
register(OperationSpec("nginx_test_config", "nginx -t", Risk.READ, WEB, "argv",
                       argv=("sudo", "-n", "nginx", "-t"), success_codes=(0, 1)))
register(OperationSpec("apache_test_config", "apachectl configtest", Risk.READ, WEB, "argv",
                       argv=("sudo", "-n", "apachectl", "configtest"), success_codes=(0, 1)))
