"""The one-minute outside watch for sites with SSH access: cheap versions of the SSL, headers, DNS, third-party,
malware, spam and content checks, run every minute next to the file watch. It fetches the homepage once, looks at the
certificate and DNS, and compares with the previous minute. Anything that turned bad or changed in that minute is
returned as an alert item (HIGH, so it goes to Teams at once); the full scan stays the place for the complete report.

The first run only records a baseline. A problem that stays is alerted once, when it appears."""

import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import requests

from ..http_client import same_site
from ..models import Severity as S
from .malware import _scan
from .malware_inside import IFRAME_TAG, SCRIPT_SRC, TAG_SRC
from .ssh_inside import _spam_hits

TAG = "Live watch"
TIMEOUT = 10
MAX_PAGE_CHARS = 2_000_000
SEC_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options")
CDN_IP_LIMIT = 6      # a site with more addresses than this rotates them (CDN): address changes aren't reported
MAX_SEEN_IPS = 50


def _records(resolver, name, rtype):
    try:
        return sorted(r.to_text().lower() for r in resolver.resolve(name, rtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return None      # timed out: keep what we knew


def _external_hosts(regex, html, base, domain, tag_attr=None):
    hosts = set()
    for found in regex.findall(html):
        src = (TAG_SRC.findall(found) or [""])[0] if tag_attr else found
        host = urlparse(urljoin(base, src)).hostname if src else None
        if host and not same_site(host, domain):
            hosts.add(host.lower())
    return hosts


def quick_outside(url, prev):
    """(snapshot to keep, alert items). `prev` is the last snapshot (None = first run: record only)."""
    host = (urlparse(url).hostname or "").lower()
    domain = host.removeprefix("www.")
    snap = dict(prev or {})
    now_bad, items = {}, []   # now_bad: title -> item for conditions that stay until fixed; items: one-time changes

    def change(severity, check, title, detail):
        items.append({"severity": severity, "check": check, "kind": "New problem", "title": f"{TAG}: {title}",
                      "detail": detail})

    def condition(severity, check, title, detail):
        now_bad[f"{TAG}: {title}"] = {"severity": severity, "check": check, "kind": "New problem",
                                      "title": f"{TAG}: {title}", "detail": detail}

    if url.startswith("https"):
        try:
            with socket.create_connection((host, 443), timeout=8) as sock, \
                    ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                days = (ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"]) - time.time()) / 86400
            if days <= 7:
                condition("HIGH", "ssl", "SSL certificate expires within 7 days", f"{host}: {max(days, 0):.0f} day(s) left")
        except ssl.SSLCertVerificationError as exc:
            condition("HIGH", "ssl", "SSL certificate is not valid", exc.verify_message or str(exc))
        except (ssl.SSLError, OSError):
            pass   # can't connect right now: the availability check reports a site that is down

    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "KlezaSecurityAgent/1.0"})
    except requests.RequestException:
        resp = None
    if resp is not None and resp.status_code < 500:
        html = resp.text[:MAX_PAGE_CHARS]
        final = (urlparse(resp.url).hostname or "").lower().removeprefix("www.")
        if prev and prev.get("final_host") and final != prev["final_host"]:
            change("HIGH", "changes", "Homepage now redirects to another site", f"{prev['final_host']} -> {final}")
        snap["final_host"] = final

        present = sorted(h for h in SEC_HEADERS if h in resp.headers)
        for gone in sorted(set((prev or {}).get("headers", [])) - set(present)):
            change("HIGH", "headers", f"Security header removed: {gone}", "It was sent a minute ago and is not any more.")
        snap["headers"] = present

        scripts = _external_hosts(SCRIPT_SRC, html, resp.url, domain)
        frames = _external_hosts(IFRAME_TAG, html, resp.url, domain, tag_attr=True)
        if prev is not None:
            for h in sorted(scripts - set(prev.get("scripts", []))):
                change("HIGH", "third_party", f"New external script on the homepage: {h}", "A script from another site was added.")
            for h in sorted(frames - set(prev.get("frames", []))):
                change("HIGH", "third_party", f"New external iframe on the homepage: {h}", "A frame from another site was added.")
        snap["scripts"], snap["frames"] = sorted(scripts), sorted(frames)

        for name, severity, _, snippet in _scan("homepage", html):
            if severity >= S.HIGH:
                condition("HIGH", "malware", f"Malicious code on the homepage ({name})", snippet[:200])
        for name, _, snippet in _spam_hits(html):
            condition("HIGH", "compromise", f"Spam on the homepage ({name})", snippet[:200])

    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    for rtype in ("NS", "MX"):
        records = _records(resolver, domain, rtype)
        if records is None:
            continue
        old = (prev or {}).get(rtype.lower())
        if old is not None and old != records:
            change("HIGH", "dns", f"DNS {rtype} records changed", f"{', '.join(old) or '(none)'} -> {', '.join(records) or '(none)'}")
        snap[rtype.lower()] = records
    ips = [ip for rtype in ("A", "AAAA") for ip in (_records(resolver, host, rtype) or [])]
    seen = set((prev or {}).get("ips", []))
    if prev is not None and ips and set(ips) - seen and len(seen) <= CDN_IP_LIMIT:
        change("HIGH", "dns", "DNS address of the site changed", f"New: {', '.join(sorted(set(ips) - seen))}")
    snap["ips"] = sorted(seen | set(ips))[:MAX_SEEN_IPS]

    old_bad = set((prev or {}).get("problems", []))
    if prev is not None:
        items += [i for t, i in now_bad.items() if t not in old_bad]
    page_problems = {t for t in old_bad if t.startswith((f"{TAG}: Malicious code", f"{TAG}: Spam"))}
    # A page that couldn't be fetched this minute says nothing about its code: keep what was known
    snap["problems"] = sorted(set(now_bad) | (page_problems if resp is None or resp.status_code >= 500 else set()))
    return snap, ([] if prev is None else items)
