"""Security header validation: HSTS, CSP, clickjacking, MIME sniffing, referrer, permissions, cookies, disclosure."""

import re

from ..models import Finding, Severity as S

NAME = "headers"

_DISCLOSURE_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime")


def _csp_directives(csp):
    directives = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def _check_hsts(value):
    if not value:
        return [Finding(NAME, "Missing Strict-Transport-Security (HSTS) header", S.MEDIUM,
                        "Browsers may be downgraded to HTTP on first visit or via SSL-stripping.",
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    findings = []
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    max_age = int(match.group(1)) if match else 0
    if max_age < 15552000:
        findings.append(Finding(NAME, "HSTS max-age is shorter than 6 months", S.LOW, value,
                                "Use max-age=31536000 (1 year) or more."))
    if "includesubdomains" not in value.lower():
        findings.append(Finding(NAME, "HSTS does not include subdomains", S.INFO, value,
                                "Add includeSubDomains once all subdomains support HTTPS."))
    return findings


def _check_csp(headers):
    csp = headers.get("Content-Security-Policy")
    if not csp:
        if headers.get("Content-Security-Policy-Report-Only"):
            return [Finding(NAME, "CSP is only in report-only mode", S.LOW,
                            "Content-Security-Policy-Report-Only is set but not enforced.",
                            "Promote the policy to an enforced Content-Security-Policy header.")]
        return [Finding(NAME, "Missing Content-Security-Policy header", S.MEDIUM,
                        "No CSP to limit script sources; XSS and injected skimmer scripts are not mitigated.",
                        "Define a CSP (start with Report-Only), e.g. default-src 'self'; script-src 'self' "
                        "'nonce-...' <trusted domains>; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")]
    findings = []
    d = _csp_directives(csp)
    script_src = d.get("script-src", d.get("default-src", []))
    has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script_src)
    if "'unsafe-inline'" in script_src and not has_nonce_or_hash:
        findings.append(Finding(NAME, "CSP allows 'unsafe-inline' scripts", S.MEDIUM, csp,
                                "Replace 'unsafe-inline' with nonces or hashes."))
    if "'unsafe-eval'" in script_src:
        findings.append(Finding(NAME, "CSP allows 'unsafe-eval'", S.LOW, csp, "Remove 'unsafe-eval' if possible."))
    if any(t in ("*", "http:", "https:", "data:") for t in script_src):
        findings.append(Finding(NAME, "CSP script-src contains a wildcard/scheme source", S.MEDIUM, csp,
                                "List explicit trusted script origins instead of *, http:, https: or data:."))
    missing = [x for x in ("object-src", "base-uri") if x not in d and not (x == "object-src" and "default-src" in d)]
    if missing:
        findings.append(Finding(NAME, f"CSP is missing {', '.join(missing)}", S.LOW, csp,
                                "Add object-src 'none'; base-uri 'self'."))
    return findings


def _set_cookies(resp):
    raw = getattr(resp.raw, "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        return raw.getlist("Set-Cookie")
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []


def _check_cookies(resp):
    findings = []
    for cookie in _set_cookies(resp):
        name = cookie.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in cookie.split(";")[1:]]
        missing = [flag for flag, test in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if not any(a == test or a.startswith(test + "=") for a in attrs)]
        if missing:
            sev = S.MEDIUM if "Secure" in missing else S.LOW
            findings.append(Finding(NAME, f"Cookie '{name}' missing {', '.join(missing)}", sev, "",
                                    "Set Secure, HttpOnly (unless JS needs it) and SameSite=Lax/Strict on cookies."))
    return findings


def run(ctx, cfg, state):
    resp, _ = ctx.home
    h = resp.headers
    findings = _check_hsts(h.get("Strict-Transport-Security")) + _check_csp(h)

    csp = h.get("Content-Security-Policy", "")
    if not h.get("X-Frame-Options") and "frame-ancestors" not in csp.lower():
        findings.append(Finding(NAME, "Missing clickjacking protection", S.MEDIUM,
                                "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                                "Add X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'."))
    if h.get("X-Content-Type-Options", "").lower() != "nosniff":
        findings.append(Finding(NAME, "Missing X-Content-Type-Options: nosniff", S.LOW, "",
                                "Add X-Content-Type-Options: nosniff."))
    referrer = h.get("Referrer-Policy", "")
    if not referrer:
        findings.append(Finding(NAME, "Missing Referrer-Policy header", S.LOW, "",
                                "Add Referrer-Policy: strict-origin-when-cross-origin."))
    elif "unsafe-url" in referrer.lower():
        findings.append(Finding(NAME, "Referrer-Policy leaks full URLs (unsafe-url)", S.LOW, referrer,
                                "Use strict-origin-when-cross-origin."))
    if not h.get("Permissions-Policy"):
        findings.append(Finding(NAME, "Missing Permissions-Policy header", S.LOW, "",
                                "Add e.g. Permissions-Policy: camera=(), microphone=(), geolocation=()."))
    if not h.get("Cross-Origin-Opener-Policy"):
        findings.append(Finding(NAME, "Missing Cross-Origin-Opener-Policy header", S.INFO, "",
                                "Consider Cross-Origin-Opener-Policy: same-origin-allow-popups."))

    for name in _DISCLOSURE_HEADERS:
        value = h.get(name)
        if value and (name != "Server" or re.search(r"\d", value)):
            findings.append(Finding(NAME, f"Technology disclosure via {name} header", S.LOW, f"{name}: {value}",
                                    f"Remove or genericise {name} (nginx: server_tokens off; "
                                    "Next.js: poweredByHeader: false)."))

    acao, acac = h.get("Access-Control-Allow-Origin"), h.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(Finding(NAME, "CORS allows any origin with credentials", S.HIGH, f"ACAO: *, ACAC: {acac}",
                                "Restrict Access-Control-Allow-Origin to trusted origins."))

    findings.extend(_check_cookies(resp))
    return findings
