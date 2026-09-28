"""Third-party resource checks: inventory, Subresource Integrity, unapproved script origins, dangling domains."""

from urllib.parse import urlparse

import dns.exception
import dns.resolver

from ..http_client import same_site
from ..models import Finding, Severity as S

NAME = "third_party"


def _resolves(resolver, host):
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            resolver.resolve(host, rtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.exception.DNSException:
            continue
    return True  # inconclusive (timeouts/no answer) - don't report


def run(ctx, cfg, state):
    domains, no_sri, scripts_by_host = {}, [], {}
    for _, _, page in ctx.all_pages():
        for r in page.resources:
            if ctx.is_external(r["url"]):
                domains.setdefault(urlparse(r["url"]).hostname, set()).add(r["tag"])
        for s in page.scripts:
            if ctx.is_external(s["src"]):
                scripts_by_host.setdefault(urlparse(s["src"]).hostname, []).append(s["src"])
                if not s["integrity"]:
                    no_sri.append(s["src"])
        for css in page.stylesheets:
            if ctx.is_external(css["href"]) and not css["integrity"]:
                no_sri.append(css["href"])

    findings = [Finding(NAME, f"{len(domains)} third-party domain(s) in use", S.INFO,
                        ", ".join(sorted(domains)),
                        evidence={d: sorted(tags) for d, tags in sorted(domains.items())})]

    if no_sri:
        findings.append(Finding(NAME, "External scripts/stylesheets loaded without Subresource Integrity", S.LOW,
                                f"{len(no_sri)} resource(s) have no integrity= attribute.",
                                "Add integrity/crossorigin attributes for static third-party files; for dynamic "
                                "tags (analytics, pixels) restrict them via CSP instead.",
                                {"resources": sorted(set(no_sri))[:30]}))

    allowed = [d.lower() for d in cfg.get("allowed_script_domains") or []]
    if allowed:
        unapproved = sorted(h for h in scripts_by_host if not any(same_site(h, a) for a in allowed))
        if unapproved:
            findings.append(Finding(NAME, "Scripts loaded from unapproved domains", S.HIGH, ", ".join(unapproved),
                                    "Remove these scripts or add the domains to allowed_script_domains.",
                                    {h: scripts_by_host[h][:5] for h in unapproved}))

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6
    dangling = sorted(h for h in domains if not _resolves(resolver, h))
    if dangling:
        findings.append(Finding(NAME, "Third-party resource domain(s) no longer resolve", S.HIGH, ", ".join(dangling),
                                "An attacker could register an expired domain and serve malicious content. "
                                "Remove these references.", {"domains": dangling}))
    return findings
