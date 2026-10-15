"""SSL/TLS monitoring: validity, expiry, protocol versions, certificate changes, HTTPS redirect."""

import hashlib
import re
import socket
import ssl
import time
from datetime import datetime, timezone

import requests

from ..models import Finding, Severity as S

NAME = "ssl"
RETRY_DELAYS = (5, 20)   # seconds before the 2nd and 3rd connection attempt
AUTO_RENEW_MAX_DAYS = 100   # certificates valid this long or less are free/auto-renewing (Let's Encrypt: 90)


def _connect(host, port, timeout, context):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.getpeercert(binary_form=True), tls.version()


def _dn(rdns):
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def _org(dn):
    match = re.search(r"organizationName=([^,]*)", dn or "")
    return match.group(1) if match else dn


def _accepts_legacy_tls(host, port, timeout):
    """True if the server negotiates TLS 1.0/1.1; None if the local OpenSSL cannot test it."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        _connect(host, port, timeout, context)
        return True
    except (ssl.SSLError, OSError):
        return False


def _https_redirect(ctx):
    try:
        resp = ctx.session.get(f"http://{ctx.host}/", allow_redirects=False, timeout=ctx.timeout)
    except requests.RequestException:
        return []  # port 80 closed is acceptable
    location = resp.headers.get("Location", "")
    if resp.status_code in (301, 308) and location.startswith("https://"):
        return []
    if resp.status_code in (302, 303, 307) and location.startswith("https://"):
        return [Finding(NAME, "HTTP redirects to HTTPS with a temporary redirect", S.LOW,
                        f"http://{ctx.host}/ returns {resp.status_code} -> {location}",
                        "Use a permanent 301/308 redirect to HTTPS (and HSTS).")]
    return [Finding(NAME, "HTTP is not redirected to HTTPS", S.MEDIUM,
                    f"http://{ctx.host}/ returned {resp.status_code} without an HTTPS redirect",
                    "Redirect all plain-HTTP traffic to HTTPS with a 301/308 response.",
                    {"status": resp.status_code, "location": location})]


def run(ctx, cfg, state):
    if ctx.scheme != "https":
        return [Finding(NAME, "Website is not served over HTTPS", S.CRITICAL, ctx.url,
                        "Serve the site exclusively over HTTPS with a trusted certificate.")]

    st = state.setdefault(NAME, {})
    # A dropped connection or timeout is tried again before it counts: one network blip is not a TLS problem
    for attempt, delay in enumerate((*RETRY_DELAYS, None)):
        try:
            cert, der, protocol = _connect(ctx.host, ctx.port, ctx.timeout, ssl.create_default_context())
            break
        except ssl.SSLCertVerificationError as exc:
            return [Finding(NAME, "SSL certificate validation failed", S.CRITICAL, exc.verify_message or str(exc),
                            f"Install a valid, trusted certificate chain covering {ctx.host}.")]
        except (ssl.SSLError, OSError) as exc:
            if delay is None:
                return [Finding(NAME, "TLS connection failed", S.CRITICAL,
                                f"Failed {attempt + 1} times: {exc.__class__.__name__}: {exc}",
                                "Verify the web server is reachable on port 443 and TLS is configured correctly.")]
            time.sleep(delay)

    findings = []
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    # Free/"lifetime" SSL (Let's Encrypt, ZeroSSL, ...) issues ~90-day certificates that the host replaces on its own
    auto_renewing = (not_after - not_before).days <= AUTO_RENEW_MAX_DAYS
    issuer = _dn(cert.get("issuer", ()))
    fingerprint = hashlib.sha256(der).hexdigest()
    evidence = {
        "subject": _dn(cert.get("subject", ())),
        "issuer": issuer,
        "not_before": cert.get("notBefore"),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "auto_renewing": auto_renewing,
        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
        "protocol": protocol,
        "sha256": fingerprint,
    }

    warn, crit = cfg.get("expiry_warning_days", 30), cfg.get("expiry_critical_days", 7)
    if days_left < 0:
        findings.append(Finding(NAME, "SSL certificate has expired", S.CRITICAL,
                                f"Expired on {not_after:%Y-%m-%d}", "Renew the certificate immediately.", evidence))
    elif auto_renewing and days_left <= cfg.get("auto_renew_failed_days", 3):
        # The host normally swaps these in well before this point, so getting here means renewal has failed
        findings.append(Finding(NAME, f"SSL auto-renewal has failed (expires in {days_left} days)", S.HIGH,
                                f"Issued by {issuer}; expires {not_after:%Y-%m-%d} and no replacement has been installed.",
                                "Renew the free SSL in the hosting panel and check that auto-renewal is turned on.", evidence))
    elif auto_renewing:
        findings.append(Finding(NAME, "SSL certificate is valid (auto-renewing)", S.INFO,
                                f"Issued by {issuer}; expires {not_after:%Y-%m-%d} ({days_left} days) and is replaced "
                                "automatically by the host.", evidence=evidence))
    elif days_left <= crit:
        findings.append(Finding(NAME, f"SSL certificate expires in {days_left} days", S.HIGH,
                                f"Expires {not_after:%Y-%m-%d}", "Renew the certificate now and check auto-renewal.", evidence))
    elif days_left <= warn:
        findings.append(Finding(NAME, f"SSL certificate expires in {days_left} days", S.MEDIUM,
                                f"Expires {not_after:%Y-%m-%d}", "Confirm auto-renewal is working.", evidence))
    else:
        findings.append(Finding(NAME, "SSL certificate is valid", S.INFO,
                                f"Issued by {issuer}; expires {not_after:%Y-%m-%d} ({days_left} days)", evidence=evidence))

    if protocol in ("SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(Finding(NAME, f"Weak TLS protocol negotiated ({protocol})", S.HIGH, "",
                                "Enable TLS 1.2/1.3 only."))
    elif _accepts_legacy_tls(ctx.host, ctx.port, ctx.timeout):
        findings.append(Finding(NAME, "Server accepts deprecated TLS 1.0/1.1", S.MEDIUM, "",
                                "Disable TLS 1.0 and 1.1 (e.g. nginx: ssl_protocols TLSv1.2 TLSv1.3;)."))

    previous = st.get("fingerprint")
    # A new certificate from the same CA is a routine renewal, so only a different CA is reported. CAs are compared by
    # organization because they rotate intermediates between renewals (Let's Encrypt YR1 -> YR2)
    issuer_changed = _org(st.get("issuer")) != _org(issuer)
    if previous and previous != fingerprint and issuer_changed:
        findings.append(Finding(
            NAME, "SSL certificate changed (different issuer)", S.MEDIUM,
            f"Fingerprint {previous[:16]}... -> {fingerprint[:16]}...; issuer: {st.get('issuer')} -> {issuer}",
            "Confirm the renewal/replacement was done by your team. Unexpected certificate or issuer "
            "changes can indicate DNS hijacking or mis-issuance.",
        ))
    st.update(fingerprint=fingerprint, issuer=issuer, not_after=not_after.isoformat())

    findings.extend(_https_redirect(ctx))
    return findings
