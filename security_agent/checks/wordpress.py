"""WordPress checks. Unauthenticated: REST user enumeration, XML-RPC, version disclosure and core version status.
With an Application Password (Users > Profile > Application Passwords): plugins and themes (outdated, closed,
abandoned, inactive, optional WPScan vulnerabilities), administrator accounts, application passwords and Site Health."""

import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests

from ..models import Finding, Severity as S

NAME = "wordpress"
WP_API = "https://api.wordpress.org"
WPSCAN_API = "https://wpscan.com/api/v3"
RISKY_USERNAMES = {"admin", "administrator", "root", "test", "demo", "wpadmin", "webmaster"}
SITE_HEALTH_TESTS = ("https-status", "background-updates", "dotorg-communication", "authorization-header")
XMLRPC_PROBE = ('<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName>'
                '<params></params></methodCall>')


def _v(text):
    return tuple(int(p) for p in re.findall(r"\d+", str(text or ""))[:4])


def _json(resp):
    try:
        return resp.json()
    except ValueError:
        return None


def _days_since(stamp):
    """Days since a WordPress timestamp ('2026-08-18 11:42pm GMT', ISO 8601 or unix seconds); None if unparseable."""
    if not stamp:
        return None
    if isinstance(stamp, (int, float)):
        when = datetime.fromtimestamp(stamp, timezone.utc)
    else:
        text = str(stamp).replace(" GMT", "")
        for fmt in ("%Y-%m-%d %I:%M%p", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                when = datetime.strptime(text[:19] if "T" in text else text, fmt).replace(tzinfo=timezone.utc)
                break
            except ValueError:
                continue
        else:
            return None
    return (datetime.now(timezone.utc) - when).days


def _read_secret_file(path):
    """Credentials from a text file: `username=...` and `password=...` lines, or just the password on one line."""
    try:
        lines = [ln.strip() for ln in Path(path).read_text(encoding="utf-8-sig").splitlines()]
    except OSError:
        return {}
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    values = {}
    for line in lines:
        key, sep, value = line.partition("=")
        key = key.strip().lower()
        if sep and key in ("username", "user", "password", "app_password"):
            values["password" if "pass" in key else "username"] = value.strip().strip("\"'")
    if not values and len(lines) == 1:
        values["password"] = lines[0]
    return values


def credentials(cfg):
    """(username, application password) from config.yaml, environment variables or `app_password_file`."""
    secret = _read_secret_file(cfg["app_password_file"]) if cfg.get("app_password_file") else {}
    user = cfg.get("username") or os.environ.get(cfg.get("username_env") or "", "") or secret.get("username", "")
    password = (cfg.get("app_password") or os.environ.get(cfg.get("app_password_env") or "WP_APP_PASSWORD", "")
                or secret.get("password", ""))
    return (user, password) if user and password else None


# ---- unauthenticated ----------------------------------------------------
def _is_wordpress(ctx):
    try:
        resp = ctx.get("/wp-json/")
        data = _json(resp)
        if resp.status_code == 200 and isinstance(data, dict) and "wp/v2" in (data.get("namespaces") or []):
            return data
    except requests.RequestException:
        pass
    try:
        resp, _ = ctx.home
        return {} if re.search(r"/wp-content/|/wp-includes/", resp.text) else None
    except requests.RequestException:
        return None


def _public_checks(ctx):
    findings = []
    try:
        resp = ctx.get("/wp-json/wp/v2/users", params={"per_page": 100})
        users = _json(resp)
        if resp.status_code == 200 and isinstance(users, list) and users:
            slugs = sorted({u.get("slug", "") for u in users if isinstance(u, dict)} - {""})
            findings.append(Finding(NAME, "WordPress usernames exposed via the REST API", S.MEDIUM,
                                    f"/wp-json/wp/v2/users lists {len(slugs)} account(s) to anonymous visitors: "
                                    f"{', '.join(slugs[:10])}",
                                    "Restrict the users endpoint to logged-in users (e.g. with a security plugin or a "
                                    "rest_endpoints filter) so attackers can't harvest login names for brute force.",
                                    {"usernames": slugs[:30]}))
    except requests.RequestException:
        pass

    try:
        resp = ctx.request("POST", "/xmlrpc.php", data=XMLRPC_PROBE, headers={"Content-Type": "text/xml"},
                           allow_redirects=False)
        if resp.status_code == 200 and "<methodResponse>" in resp.text:
            multicall = "system.multicall" in resp.text
            findings.append(Finding(NAME, "XML-RPC is enabled" + (" with system.multicall" if multicall else ""),
                                    S.MEDIUM if multicall else S.LOW,
                                    "xmlrpc.php answers anonymous requests. system.multicall lets an attacker try "
                                    "hundreds of passwords in a single request and bypass login rate limits."
                                    if multicall else "xmlrpc.php answers anonymous requests.",
                                    "Disable XML-RPC (security plugin, 'xmlrpc_enabled' filter or a server rule) "
                                    "unless Jetpack or the mobile app needs it."))
    except requests.RequestException:
        pass

    try:
        resp = ctx.get("/readme.html", allow_redirects=False)
        if resp.status_code == 200 and "WordPress" in resp.text[:5000]:
            findings.append(Finding(NAME, "WordPress readme.html is publicly accessible", S.LOW,
                                    ctx.abs_url("/readme.html"),
                                    "Delete readme.html (it is restored on core updates) or block it at the server."))
    except requests.RequestException:
        pass
    return findings


def _core_version(ctx):
    for path in ("/feed/", ctx.home_path):
        try:
            text = ctx.get(path).text
        except requests.RequestException:
            continue
        match = re.search(r"wordpress\.org/\?v=([\d.]+)|<meta[^>]+generator[^>]+WordPress ([\d.]+)", text, re.I)
        if match:
            return match.group(1) or match.group(2)
    return None


def _core_findings(ctx, version, source):
    findings = []
    if source == "public":
        findings.append(Finding(NAME, f"WordPress version {version} disclosed publicly", S.LOW,
                                "The version appears in the RSS feed / generator meta tag.",
                                "Remove the generator tag (remove_action('wp_head', 'wp_generator') and the "
                                "'the_generator' filter) so attackers can't match your version to exploits."))
    try:
        status = _json(ctx.session.get(f"{WP_API}/core/stable-check/1.0/", timeout=max(ctx.timeout, 30))) or {}
    except requests.RequestException:
        status = {}
    state = status.get(version)
    latest = next((v for v, s in status.items() if s == "latest"), None)
    if state == "insecure":
        findings.append(Finding(NAME, f"WordPress {version} is insecure", S.HIGH,
                                f"wordpress.org marks {version} as insecure (latest: {latest}).",
                                "Update WordPress core immediately and enable automatic minor updates."))
    elif state == "outdated":
        findings.append(Finding(NAME, f"WordPress {version} is outdated", S.MEDIUM, f"Latest release: {latest}.",
                                "Update WordPress core."))
    else:
        findings.append(Finding(NAME, f"WordPress core {version}" + (" is up to date" if state == "latest" else ""),
                                S.INFO, f"Latest release: {latest or 'unknown'}."))
    return findings


# ---- authenticated ------------------------------------------------------
class _Api:
    def __init__(self, ctx, auth):
        self.ctx, self.auth = ctx, auth

    def get(self, path, **params):
        """Returns (status, json) for an authenticated REST call; (None, None) on network errors."""
        try:
            resp = self.ctx.get("/wp-json" + path, params=params or None, auth=self.auth)
        except requests.RequestException:
            return None, None
        return resp.status_code, _json(resp)


def _wporg_info(session, kind, slug, timeout):
    """Latest release info from wordpress.org, {} when the slug isn't hosted there (premium/custom)."""
    params = {"action": f"{kind}_information", "request[slug]": slug}
    for field in ("sections", "versions", "reviews", "screenshots", "description"):
        params[f"request[fields][{field}]"] = 0
    try:
        resp = session.get(f"{WP_API}/{kind}s/info/1.2/", params=params, timeout=timeout)
    except requests.RequestException:
        return None
    data = _json(resp) or {}
    return data if data.get("version") or data.get("error") == "closed" else {}


def _wpscan_vulns(session, token, slug, version, timeout):
    try:
        resp = session.get(f"{WPSCAN_API}/plugins/{slug}", headers={"Authorization": f"Token token={token}"},
                           timeout=timeout)
    except requests.RequestException:
        return []
    vulns = ((_json(resp) or {}).get(slug) or {}).get("vulnerabilities") or [] if resp.status_code == 200 else []
    return [v for v in vulns if not v.get("fixed_in") or _v(version) < _v(v["fixed_in"])]


def _plugin_findings(ctx, api, cfg):
    status, plugins = api.get("/wp/v2/plugins")
    if status != 200 or not isinstance(plugins, list):
        return [Finding(NAME, "Could not list WordPress plugins", S.INFO,
                        f"/wp/v2/plugins returned HTTP {status}. The account needs the 'activate_plugins' capability "
                        "(an administrator).")]
    findings, custom, inactive = [], [], []
    timeout = max(ctx.timeout, 30)
    token = os.environ.get(cfg.get("wpscan_api_token_env") or "WPSCAN_API_TOKEN", "")
    abandoned_days = int(cfg.get("abandoned_plugin_days", 730))

    def lookup(p):
        slug = p.get("plugin", "").split("/")[0]
        info = _wporg_info(ctx.session, "plugin", slug, timeout)
        vulns = _wpscan_vulns(ctx.session, token, slug, p.get("version"), timeout) if token else []
        return p, slug, info, vulns

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lookup, plugins))

    for p, slug, info, vulns in results:
        name, version, active = p.get("name") or slug, p.get("version") or "?", p.get("status") == "active"
        label = f"{name} {version}" + ("" if active else " (inactive)")
        if not active:
            inactive.append(label)
        for v in vulns:
            findings.append(Finding(NAME, f"Vulnerable plugin: {name} {version}", S.HIGH,
                                    v.get("title", "Known vulnerability"),
                                    f"Update {name} to {v['fixed_in']} or later." if v.get("fixed_in")
                                    else f"No fix is available: remove or replace {name}.",
                                    {"plugin": slug, "installed": version, "fixed_in": v.get("fixed_in"),
                                     "references": (v.get("references") or {}).get("cve", [])}))
        if info is None:
            continue
        if not info:
            custom.append(label)
        elif info.get("error") == "closed":
            findings.append(Finding(NAME, f"Plugin removed from wordpress.org: {name}", S.HIGH,
                                    f"{slug} was closed on {info.get('closed_date', '?')} "
                                    f"({info.get('reason_text') or info.get('reason') or 'no reason given'}). "
                                    "Plugins are often closed for unpatched security issues.",
                                    f"Remove {name} or replace it with a maintained alternative."))
        else:
            latest = info["version"]
            if _v(version) < _v(latest):
                findings.append(Finding(NAME, f"Outdated plugin: {name} {version} (latest {latest})",
                                        S.MEDIUM if active else S.LOW,
                                        "Outdated plugins are the most common way WordPress sites are compromised.",
                                        f"Update {name} to {latest} and consider enabling auto-updates for it.",
                                        {"plugin": slug, "installed": version, "latest": latest, "active": active}))
            age = _days_since(info.get("last_updated"))
            if age is not None and age > abandoned_days:
                findings.append(Finding(NAME, f"Possibly abandoned plugin: {name}", S.LOW,
                                        f"No release on wordpress.org for {age} days.",
                                        f"Replace {name} with an actively maintained plugin."))

    if inactive:
        findings.append(Finding(NAME, f"{len(inactive)} inactive plugin(s) installed", S.LOW, ", ".join(inactive),
                                "Delete plugins you don't use: inactive plugin files can still be exploited.",
                                {"plugins": inactive}))
    if custom:
        findings.append(Finding(NAME, f"{len(custom)} premium/custom plugin(s) not tracked on wordpress.org", S.INFO,
                                ", ".join(custom), "Keep these updated through their vendor (licence dashboard)."))
    findings.append(Finding(NAME, f"{len(plugins)} plugin(s) installed", S.INFO,
                            ", ".join(f"{p.get('name')} {p.get('version')}" for p in plugins),
                            evidence={"plugins": [{k: p.get(k) for k in ("plugin", "name", "version", "status")}
                                                  for p in plugins]}
                            | ({} if token else {"note": "Set WPSCAN_API_TOKEN to check known vulnerabilities."})))
    return findings


def _theme_findings(ctx, api):
    status, themes = api.get("/wp/v2/themes")
    if status != 200 or not isinstance(themes, list):
        return []
    findings, inactive = [], []
    for t in themes:
        slug, version, active = t.get("stylesheet", ""), t.get("version") or "?", t.get("status") == "active"
        name = (t.get("name") or {}).get("rendered") if isinstance(t.get("name"), dict) else t.get("name") or slug
        if not active:
            inactive.append(f"{name} {version}")
        info = _wporg_info(ctx.session, "theme", slug, max(ctx.timeout, 30))
        if info and info.get("version") and _v(version) < _v(info["version"]):
            findings.append(Finding(NAME, f"Outdated theme: {name} {version} (latest {info['version']})",
                                    S.MEDIUM if active else S.LOW, "",
                                    f"Update the {name} theme" + ("." if active else " or delete it."),
                                    {"theme": slug, "installed": version, "latest": info["version"]}))
    if len(inactive) > 1:  # keeping one default theme as a fallback is fine
        findings.append(Finding(NAME, f"{len(inactive)} inactive theme(s) installed", S.LOW, ", ".join(inactive),
                                "Delete unused themes, keeping at most one default theme as a fallback."))
    return findings


def _user_findings(api, cfg, me):
    status, admins = api.get("/wp/v2/users", context="edit", roles="administrator", per_page=100)
    if status != 200 or not isinstance(admins, list):
        return [], []
    findings = []
    names = sorted(a.get("username") or a.get("slug", "?") for a in admins)
    max_admins = int(cfg.get("max_admins", 3))
    if len(admins) > max_admins:
        findings.append(Finding(NAME, f"{len(admins)} administrator accounts", S.MEDIUM, ", ".join(names),
                                f"Keep administrators to {max_admins} or fewer; give others Editor or lower roles.",
                                {"administrators": names}))
    risky = [n for n in names if n.lower() in RISKY_USERNAMES]
    if risky:
        findings.append(Finding(NAME, "Administrator with a guessable username", S.MEDIUM, ", ".join(risky),
                                "Create a new admin with a unique username, move content to it and delete this one.",
                                {"usernames": risky}))
    findings.append(Finding(NAME, f"Authenticated as {me.get('username') or me.get('slug')}; "
                                  f"{len(admins)} administrator(s)", S.INFO, ", ".join(names)))
    return findings, admins


def _app_password_findings(api, cfg, admins):
    stale_days = int(cfg.get("stale_app_password_days", 90))
    stale, inventory = [], []
    for admin in admins:
        status, items = api.get(f"/wp/v2/users/{admin['id']}/application-passwords")
        if status != 200 or not isinstance(items, list):
            continue
        user = admin.get("username") or admin.get("slug")
        for item in items:
            used = _days_since(item.get("last_used"))
            created = _days_since(item.get("created"))
            label = f"{user}: {item.get('name')}"
            inventory.append({"user": user, "name": item.get("name"), "created": item.get("created"),
                              "last_used": item.get("last_used"), "last_ip": item.get("last_ip")})
            if (used if used is not None else created or 0) > stale_days:
                stale.append(f"{label} (last used {item.get('last_used') or 'never'})")
    findings = []
    if stale:
        findings.append(Finding(NAME, f"{len(stale)} unused application password(s)", S.LOW, "; ".join(stale),
                                f"Revoke application passwords not used for {stale_days}+ days "
                                "(Users > Profile > Application Passwords).", {"stale": stale}))
    if inventory:
        findings.append(Finding(NAME, f"{len(inventory)} application password(s) on administrator accounts", S.INFO,
                                "; ".join(f"{i['user']}: {i['name']}" for i in inventory),
                                evidence={"application_passwords": inventory}))
    return findings


def _site_health_findings(api):
    findings = []
    for test in SITE_HEALTH_TESTS:
        status, result = api.get(f"/wp-site-health/v1/tests/{test}")
        if status != 200 or not isinstance(result, dict) or result.get("status") == "good":
            continue
        severity = S.MEDIUM if result.get("status") == "critical" else S.LOW
        description = re.sub(r"<[^>]+>", " ", result.get("description") or "")
        findings.append(Finding(NAME, f"Site Health: {result.get('label', test)}", severity,
                                re.sub(r"\s+", " ", description).strip()[:400],
                                "Resolve this under Tools > Site Health in wp-admin.", {"test": test}))
    return findings


def _authenticated_checks(ctx, cfg, auth):
    api = _Api(ctx, auth)
    status, me = api.get("/wp/v2/users/me", context="edit")
    if status != 200 or not isinstance(me, dict):
        code = (me or {}).get("code") if isinstance(me, dict) else None
        hint = ("The server may be stripping the Authorization header (common on Apache/CGI hosts): add "
                "'SetEnvIf Authorization \"(.*)\" HTTP_AUTHORIZATION=$1' to .htaccess, or check the username."
                if code == "rest_not_logged_in" else "Check the username and application password.")
        return [Finding(NAME, "WordPress application password was rejected", S.MEDIUM,
                        f"/wp-json/wp/v2/users/me returned HTTP {status} ({code or 'no error code'}). {hint}",
                        "Create a new application password under Users > Profile and update the environment variable.")]

    findings = []
    if "administrator" not in (me.get("roles") or []):
        findings.append(Finding(NAME, "Application password account is not an administrator", S.INFO,
                                f"Roles: {', '.join(me.get('roles') or [])}. Plugin, user and Site Health checks "
                                "need an administrator account."))
    user_findings, admins = _user_findings(api, cfg, me)
    findings += user_findings
    findings += _plugin_findings(ctx, api, cfg)
    findings += _theme_findings(ctx, api)
    findings += _app_password_findings(api, cfg, admins)
    findings += _site_health_findings(api)

    status, settings = api.get("/wp/v2/settings")
    if status == 200 and isinstance(settings, dict) and str(settings.get("url", "")).startswith("http://"):
        findings.append(Finding(NAME, "WordPress Site Address uses http://", S.MEDIUM, settings["url"],
                                "Set WordPress Address and Site Address to https:// under Settings > General."))
    return findings


def run(ctx, cfg, state):
    if _is_wordpress(ctx) is None:
        return [Finding(NAME, "Not a WordPress site", S.INFO, "No WordPress REST API or wp-content assets found.")]

    findings = _public_checks(ctx)
    version = _core_version(ctx)
    if version:
        findings += _core_findings(ctx, version, "public")

    auth = credentials(cfg)
    if not auth:
        findings.append(Finding(NAME, "Authenticated WordPress checks skipped", S.INFO,
                                "No application password configured, so plugins, themes, users and Site Health "
                                "were not audited.",
                                f"Put the username and application password in the file named by "
                                f"checks.wordpress.app_password_file ({cfg.get('app_password_file') or 'not set'}), "
                                f"or set the {cfg.get('app_password_env') or 'WP_APP_PASSWORD'} environment variable."))
    elif ctx.scheme != "https":
        findings.append(Finding(NAME, "Authenticated WordPress checks skipped (site is not HTTPS)", S.INFO,
                                "The application password is never sent over plain HTTP."))
    else:
        findings += _authenticated_checks(ctx, cfg, auth)
    return findings
