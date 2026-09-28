"""Common vulnerability checks: outdated server software and JS libraries, mixed content, insecure
forms, dangerous HTTP methods, CORS origin reflection, verbose errors, security.txt and robots.txt."""

import re
from urllib.parse import urlparse

import requests

from ..models import Finding, Severity as S

NAME = "vulnerabilities"

# Oldest versions still receiving upstream security fixes (approximate; distro packages may backport fixes).
MIN_SERVER_VERSIONS = {"nginx": (1, 26, 0), "apache": (2, 4, 62), "php": (8, 1, 0), "openssl": (3, 0, 0)}
SERVER_RX = re.compile(r"(nginx|apache|php|openssl)/(\d+(?:\.\d+)+)", re.I)

# (library, regex over script URL or file header, minimum safe version or None if the whole line is EOL)
JS_LIBRARIES = [
    ("jQuery", re.compile(r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js|jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)", re.I), (3, 5, 0)),
    ("jQuery UI", re.compile(r"jquery-ui[.-](\d+\.\d+\.\d+)|jQuery UI - v(\d+\.\d+\.\d+)", re.I), (1, 13, 2)),
    ("AngularJS", re.compile(r"angular[.-](1\.\d+\.\d+)|AngularJS v(1\.\d+\.\d+)", re.I), None),
    ("Bootstrap", re.compile(r"bootstrap[.-](\d+\.\d+\.\d+)|Bootstrap v(\d+\.\d+\.\d+)", re.I), (3, 4, 1)),
    ("Lodash", re.compile(r"lodash[.-](\d+\.\d+\.\d+)|var VERSION\s*=\s*['\"](4\.\d+\.\d+)['\"];[^;]{0,200}lodash", re.I), (4, 17, 21)),
    ("Moment.js", re.compile(r"moment[.-](\d+\.\d+\.\d+)|//! version : (\d+\.\d+\.\d+)", re.I), (2, 29, 4)),
]

SENSITIVE_ROBOTS = re.compile(r"admin|backup|private|secret|config|internal|staging|debug|\.git|\.env|dump|sql", re.I)
ERROR_SIGNATURES = re.compile(
    r"Traceback \(most recent call last\)|Stack trace:|Fatal error:|Warning: .+ on line \d+|"
    r"at [\w.$<>]+ \([^)]+\.(?:js|ts):\d+:\d+\)|Exception in thread|SQLSTATE\[|ORA-\d{5}|Microsoft OLE DB", re.I)


def _ver(text):
    return tuple(int(p) for p in text.split(".")[:3])


def _server_software(ctx):
    resp, _ = ctx.home
    banner = " ".join(resp.headers.get(h, "") for h in ("Server", "X-Powered-By"))
    findings = []
    for product, version in SERVER_RX.findall(banner):
        minimum = MIN_SERVER_VERSIONS[product.lower()]
        if _ver(version) < minimum:
            findings.append(Finding(NAME, f"Outdated {product} {version} detected", S.MEDIUM,
                                    f"Upstream versions older than {'.'.join(map(str, minimum))} no longer receive "
                                    "security fixes (distribution packages may backport some patches).",
                                    f"Upgrade {product} to a supported release and hide the version banner.",
                                    {"banner": banner.strip()}))
    return findings


def _js_libraries(ctx):
    findings, seen = [], set()
    for _, _, page in ctx.all_pages():
        for script in page.scripts:
            src = script["src"]
            sources = [src]
            if not ctx.is_external(src):
                sources.append(ctx.fetch_text(src)[:4000])
            for text in sources:
                for lib, regex, minimum in JS_LIBRARIES:
                    match = regex.search(text)
                    if not match:
                        continue
                    version = next(g for g in match.groups() if g)
                    if (lib, version) in seen:
                        continue
                    seen.add((lib, version))
                    if minimum is None or _ver(version) < minimum:
                        findings.append(Finding(NAME, f"Vulnerable/EOL JavaScript library: {lib} {version}", S.MEDIUM,
                                                f"Loaded from {src}",
                                                f"Upgrade {lib}" + (f" to >= {'.'.join(map(str, minimum))}." if minimum
                                                                    else " (end-of-life; migrate to a supported framework).")))
    return findings


def _mixed_content_and_forms(ctx):
    findings = []
    for path, _, page in ctx.all_pages():
        if ctx.scheme != "https":
            break
        active = sorted({r["url"] for r in page.resources if r["url"].startswith("http://") and r["tag"] in ("script", "iframe", "link", "object", "embed")})
        passive = sorted({r["url"] for r in page.resources if r["url"].startswith("http://") and r["url"] not in active})
        if active:
            findings.append(Finding(NAME, "Active mixed content (HTTP scripts/styles/frames on HTTPS page)", S.MEDIUM,
                                    f"{len(active)} resource(s) on {path}", "Load all resources over HTTPS.", {"urls": active[:20]}))
        if passive:
            findings.append(Finding(NAME, "Passive mixed content (HTTP images/media on HTTPS page)", S.LOW,
                                    f"{len(passive)} resource(s) on {path}", "Load all resources over HTTPS.", {"urls": passive[:20]}))
        insecure_forms = [f["action"] for f in page.forms if f["action"].startswith("http://")]
        if insecure_forms:
            findings.append(Finding(NAME, "Form submits data over plain HTTP", S.HIGH, ", ".join(insecure_forms),
                                    "Change form actions to HTTPS."))
    return findings


def _http_methods(ctx):
    try:
        resp = ctx.request("OPTIONS", ctx.home_path, allow_redirects=False)
    except requests.RequestException:
        return []
    allowed = {m.strip().upper() for m in (resp.headers.get("Allow", "") + "," +
                                           resp.headers.get("Access-Control-Allow-Methods", "")).split(",") if m.strip()}
    risky = sorted(allowed & {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND"})
    if not risky:
        return []
    return [Finding(NAME, f"Potentially dangerous HTTP methods advertised: {', '.join(risky)}", S.LOW,
                    f"Allow: {', '.join(sorted(allowed))}", "Disable methods that the site does not need.")]


def _cors_reflection(ctx):
    evil = "https://evil-origin.example"
    try:
        resp = ctx.get(ctx.home_path, headers={"Origin": evil}, allow_redirects=False)
    except requests.RequestException:
        return []
    if resp.headers.get("Access-Control-Allow-Origin") != evil:
        return []
    creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
    return [Finding(NAME, "CORS reflects arbitrary Origin" + (" with credentials" if creds else ""),
                    S.HIGH if creds else S.MEDIUM, f"Origin {evil} was echoed in Access-Control-Allow-Origin",
                    "Validate Origin against an allowlist of trusted origins.")]


def _verbose_errors(ctx):
    try:
        resp = ctx.get("/%ff%fe__secmon", allow_redirects=False)
    except requests.RequestException:
        return []
    match = ERROR_SIGNATURES.search(resp.text[:200000])
    if not match:
        return []
    return [Finding(NAME, "Verbose error / stack trace disclosed", S.MEDIUM, f"HTTP {resp.status_code}: ...{match.group(0)}...",
                    "Disable debug output in production and use generic error pages.")]


def _security_txt(ctx):
    try:
        resp = ctx.get("/.well-known/security.txt")
        if resp.status_code == 200 and "contact:" in resp.text.lower():
            return []
    except requests.RequestException:
        pass
    return [Finding(NAME, "No security.txt published", S.INFO, "/.well-known/security.txt not found",
                    "Publish a security.txt (RFC 9116) with a Contact: so researchers can report issues.")]


def _robots(ctx):
    try:
        resp = ctx.get("/robots.txt")
    except requests.RequestException:
        return []
    if resp.status_code != 200:
        return []
    paths = [line.split(":", 1)[1].strip() for line in resp.text.splitlines()
             if line.lower().startswith("disallow:") and SENSITIVE_ROBOTS.search(line)]
    if not paths:
        return []
    return [Finding(NAME, "robots.txt reveals potentially sensitive paths", S.INFO, ", ".join(paths[:15]),
                    "Do not rely on robots.txt to hide sensitive areas; protect them with authentication.")]


def run(ctx, cfg, state):
    findings = []
    for check in (_server_software, _js_libraries, _mixed_content_and_forms, _http_methods,
                  _cors_reflection, _verbose_errors, _security_txt, _robots):
        findings.extend(check(ctx))
    if not any(f.severity > S.INFO for f in findings):
        findings.append(Finding(NAME, "No common vulnerabilities detected", S.INFO))
    return findings
