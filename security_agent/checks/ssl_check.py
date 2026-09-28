"""SSL/TLS monitoring: validity, expiry, protocol versions, certificate changes, HTTPS redirect."""

import hashlib
import socket
import ssl
from datetime import datetime, timezone

import requests

from ..models import Finding, Severity as S

NAME = "ssl"


def _connect(host, port, timeout, context):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.getpeercert(binary_form=True), tls.version()


def _dn(rdns):
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


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
    try:
        cert, der, protocol = _connect(ctx.host, ctx.port, ctx.timeout, ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        return [Finding(NAME, "SSL certificate validation failed", S.CRITICAL, exc.verify_message or str(exc),
                        f"Install a valid, trusted certificate chain covering {ctx.host}.")]
    except (ssl.SSLError, OSError) as exc:
        return [Finding(NAME, "TLS connection failed", S.CRITICAL, str(exc),
                        "Verify the web server is reachable on port 443 and TLS is configured correctly.")]

    findings = []
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    issuer = _dn(cert.get("issuer", ()))
    fingerprint = hashlib.sha256(der).hexdigest()
    evidence = {
        "subject": _dn(cert.get("subject", ())),
        "issuer": issuer,
        "not_before": cert.get("notBefore"),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
        "protocol": protocol,
        "sha256": fingerprint,
    }

    warn, crit = cfg.get("expiry_warning_days", 30), cfg.get("expiry_critical_days", 7)
    if days_left < 0:
        findings.append(Finding(NAME, "SSL certificate has expired", S.CRITICAL,
                                f"Expired on {not_after:%Y-%m-%d}", "Renew the certificate immediately.", evidence))
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
    if previous and previous != fingerprint:
        issuer_changed = st.get("issuer") != issuer
        findings.append(Finding(
            NAME, "SSL certificate changed" + (" (different issuer)" if issuer_changed else ""),
            S.MEDIUM if issuer_changed else S.LOW,
            f"Fingerprint {previous[:16]}... -> {fingerprint[:16]}...; issuer: {st.get('issuer')} -> {issuer}",
            "Confirm the renewal/replacement was done by your team. Unexpected certificate or issuer "
            "changes can indicate DNS hijacking or mis-issuance.",
        ))
    st.update(fingerprint=fingerprint, issuer=issuer, not_after=not_after.isoformat())

    findings.extend(_https_redirect(ctx))
    return findings
