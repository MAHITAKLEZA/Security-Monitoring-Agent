"""Each check module exposes NAME and run(ctx, cfg, state) -> list[Finding]."""

from . import changes, dns_check, exposed_files, headers, malware, ssl_check, third_party, vulnerabilities, wordpress

ALL_CHECKS = {
    mod.NAME: mod
    for mod in (ssl_check, headers, exposed_files, changes, malware, vulnerabilities, dns_check, third_party, wordpress)
}
