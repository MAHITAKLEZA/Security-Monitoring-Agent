"""Phase 2 for every problem the security checks report: each finding becomes a proposed fix in the site's approval
queue (the same queue, backups, verification and undo as Spam & Compromise, jp_seo_agent/approvals.py).

Fixes the agent can make (after a person approves them):
  harden              a Kleza Site Guard 1.2 setting: a security header, removing X-Powered-By, XML-RPC off, usernames
                      hidden from the REST API, WordPress version hidden, PHP errors hidden, a security.txt
  block_paths         deny exposed files (.env, .git, backups, source maps, readme.html) in the site's .htaccess
  update_plugin/theme/core   install the latest release (Site Guard 1.2)
  deactivate_plugin   a plugin closed on wordpress.org, vulnerable without a fix, or unidentified
  quarantine_dir      move an inactive plugin or theme folder into the quarantine (restorable)
  revoke_app_passwords   application passwords unused for months
  accept_change       accept a page's current content as its new baseline (content-change check)
  quarantine / demote_user   (Spam & Compromise fixes) for scripts in the media library and suspicious administrators
Everything else (certificates, DNS records, server configuration, CORS...) becomes a "fix by hand" proposal with
the exact steps; once it is marked done, the security monitor (guard.py) watches for it coming back.
Each applied fix is verified by running the check again: it counts as verified when the problem is gone.
"""

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from jp_seo_agent import remediate
from jp_seo_agent.files import API
from jp_seo_agent.remediate import RemediationError, _proposal

from .models import Severity as S

TARGETS = {}   # slug -> resolved target, so a fix can run its check again to verify itself
KLEZA_BEGIN, KLEZA_END = "# BEGIN Kleza Guard", "# END Kleza Guard"
SKIP = re.compile(r"could not complete|Scan failed|lookup timed out|registration data unavailable|Baseline recorded|"
                  r"^Inside scan: scanned|could not log in", re.I)


def _v(text):
    return tuple(int(p) for p in re.findall(r"\d+", str(text or ""))[:4])


# ---- what the agent knows about the site when it builds proposals ------------------------------------------
class Env:
    """The site as the fixes see it. WordPress details are looked up once, only when a rule needs them."""

    def __init__(self, target, site):
        self.target, self.site = target, site
        self.slug, self.url = target["slug"], target["url"]
        self.domain = target.get("domain") or (urlparse(self.url).hostname or "").removeprefix("www.")
        self._cache = {}

    def _get(self, key, fetch):
        if key not in self._cache:
            try:
                self._cache[key] = fetch()
            except Exception:   # a lookup failing only means a manual proposal instead of an automatic one
                self._cache[key] = None
        return self._cache[key]

    @property
    def wordpress(self):
        """Logged in with an administrator's application password over HTTPS."""
        from jp_seo_agent import wordpress
        return bool(self.site.wp_auth and self.site.secure and self._get("login", lambda: wordpress.login(self.site)))

    @property
    def guard(self):
        """Kleza Site Guard plugin status (version, folders), or None."""
        def fetch():
            status, data = self.site.wp("GET", f"{API}/status")
            return data if status == 200 and isinstance(data, dict) else None
        return self._get("guard", fetch) if self.wordpress else None

    @property
    def guard12(self):
        return bool(self.guard) and _v(self.guard.get("plugin_version")) >= (1, 2)

    def plugins(self):
        def fetch():
            status, data = self.site.wp("GET", "/wp/v2/plugins")
            return data if status == 200 and isinstance(data, list) else []
        return (self._get("plugins", fetch) or []) if self.wordpress else []

    def themes(self):
        def fetch():
            status, data = self.site.wp("GET", "/wp/v2/themes")
            return data if status == 200 and isinstance(data, list) else []
        return (self._get("themes", fetch) or []) if self.wordpress else []

    def users(self):
        return (self._get("users", lambda: self.site.wp_items("/wp/v2/users", context="edit",
                                                              _fields="id,username,slug,roles,email")) or []) \
            if self.wordpress else []

    def admin_email(self):
        def fetch():
            status, data = self.site.wp("GET", "/wp/v2/settings")
            return (data or {}).get("email") if status == 200 and isinstance(data, dict) else None
        return (self._get("email", fetch) if self.wordpress else None) or f"security@{self.domain}"

    def plugin_by_slug(self, slug):
        return next((p for p in self.plugins() if (p.get("plugin") or "").split("/")[0] == slug), None)

    def file_md5(self, path):
        status, data = self.site.wp("GET", f"{API}/file", params={"path": path})
        return data.get("md5") if status == 200 and isinstance(data, dict) else None


# ---- proposal builders ------------------------------------------------------------------------------------
def proposal(env, f, action, why, risk="low", data=None, subject=None, fingerprint="", preview="", requires=None,
             kind="security"):
    """A proposal for finding f. subject: what is being fixed, stable across scans (regressions link by it)."""
    subj = subject or f"{f.check}:{f.title}"
    p = _proposal(kind, action, f.title if kind == "security" else (data or {}).get("target", f.title), why, risk,
                  fingerprint, {**(data or {}), "subject": subj, "site_slug": env.slug}, preview=preview,
                  source=CHECK_LABEL.get(f.check, f.check), key=subj)
    p.update(check=f.check, severity=f.severity.name, title=f.title, requires=requires)
    return p


def manual(env, f, steps=None, subject=None):
    """Fix by hand: the steps, then 'Done' in the dashboard; the monitor watches for it coming back."""
    steps = steps or f.recommendation or "Fix this in the server or hosting configuration."
    return proposal(env, f, "manual", steps, "none", subject=subject, preview=f.detail or "")


def harden(env, f, key, value, why, risk="low", subject=None):
    if not env.wordpress:
        return manual(env, f, subject=subject)
    return proposal(env, f, "harden", why + " Switched on through the Kleza Site Guard plugin; undo switches it off.",
                    risk, {"key": key, "value": value}, subject=subject or f"{f.check}:{key}",
                    preview=f"{key} = {value}", requires="site_guard_1.2")


HEADER_FIXES = {   # finding title -> (header, value, risk, why)
    "Missing Strict-Transport-Security (HSTS) header": (
        "Strict-Transport-Security", "max-age=31536000", "medium",
        "Tell browsers to use HTTPS only for a year. Only approve if the whole site works over HTTPS."),
    "HSTS max-age is shorter than 6 months": (
        "Strict-Transport-Security", "max-age=31536000", "low", "Raise HSTS max-age to one year."),
    "Missing clickjacking protection": (
        "X-Frame-Options", "SAMEORIGIN", "low", "Stop other sites from framing your pages (clickjacking)."),
    "Missing X-Content-Type-Options: nosniff": (
        "X-Content-Type-Options", "nosniff", "low", "Stop browsers from guessing file types."),
    "Missing Referrer-Policy header": (
        "Referrer-Policy", "strict-origin-when-cross-origin", "low", "Send only your domain, not full URLs, to "
        "other sites."),
    "Referrer-Policy leaks full URLs (unsafe-url)": (
        "Referrer-Policy", "strict-origin-when-cross-origin", "low", "Send only your domain, not full URLs, to "
        "other sites."),
    "Missing Permissions-Policy header": (
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()", "medium",
        "Block camera, microphone and location access for embedded content. Don't approve if a page uses them."),
}
CSP_SUGGESTION = ("Content-Security-Policy: default-src 'self'; script-src 'self' <trusted script domains>; "
                  "object-src 'none'; base-uri 'self'; frame-ancestors 'self'")


def rules_headers(env, f):
    t = f.title
    if t in HEADER_FIXES:
        name, value, risk, why = HEADER_FIXES[t]
        return harden(env, f, f"header:{name}", value, why, risk, subject=f"headers:{name}")
    m = re.match(r"Technology disclosure via (\S+) header", t)
    if m and m.group(1) != "Server":
        return harden(env, f, f"remove_header:{m.group(1)}", True, f"Stop sending the {m.group(1)} header.",
                      subject=f"headers:disclosure:{m.group(1)}")
    if m:
        return manual(env, f, "The Server header is added by the web server, not WordPress: set server_tokens off "
                      "(nginx) or ServerTokens Prod / ServerSignature Off (Apache), or ask your host.")
    if "CSP" in t or "Content-Security-Policy" in t:
        return manual(env, f, f"{f.recommendation} Start with Content-Security-Policy-Report-Only, watch the browser "
                      f"console for a few days, then enforce it. Suggested: {CSP_SUGGESTION}", subject="headers:csp")
    return manual(env, f)


def rules_ssl(env, f):
    t = f.title
    if "expire" in t.lower() or "validation failed" in t or "TLS connection failed" in t:
        return manual(env, f, "Renew or reissue the certificate in the hosting panel (or certbot renew), install the "
                      "full chain, and turn on automatic renewal.", subject="ssl:certificate")
    if "redirect" in t.lower() or "not served over HTTPS" in t:
        return manual(env, f, "Redirect every http:// request to https:// with a permanent 301 at the web server or "
                      "CDN (Apache: RewriteCond %{HTTPS} off / RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} "
                      "[L,R=301]; nginx: return 301 https://$host$request_uri;).", subject="ssl:redirect")
    if "TLS" in t:
        return manual(env, f, "Allow only TLS 1.2 and 1.3 in the web server or CDN settings (nginx: ssl_protocols "
                      "TLSv1.2 TLSv1.3;).", subject="ssl:protocols")
    return manual(env, f)


def _block(env, f, pattern, label, subject, risk="low"):
    if not (env.wordpress and env.guard):
        return manual(env, f, f"{f.recommendation} Apache: add `RewriteRule {pattern} - [F,L]` to .htaccess; nginx: "
                      f"`location ~ {pattern.lstrip('^')} {{ deny all; }}`.", subject=subject)
    return proposal(env, f, "block_paths", f"Deny web access to {label} with a rule in the site's .htaccess "
                    "(Apache/LiteSpeed). The file itself stays where it is; rotate any secret it exposed.",
                    risk, {"patterns": [pattern]}, subject=subject, preview=f"RewriteRule {pattern} - [F,L]",
                    requires="site_guard")


def rules_exposed(env, f):
    if f.title.startswith("JavaScript source maps"):
        return _block(env, f, r"\.map$", "JavaScript source maps (*.map)", "exposed_files:sourcemaps")
    url = (f.evidence or {}).get("url") or ""
    path = urlparse(url).path or (f.detail or "").split(" ", 1)[0]
    base = urlparse(env.url).path.rstrip("/")
    rel = path[len(base):] if base and path.startswith(base) else path
    rel = rel.lstrip("/")
    if not rel:
        return manual(env, f)
    first = rel.split("/", 1)[0]
    if first.startswith(".") and first not in (".env", ".htaccess", ".htpasswd", ".user.ini") or rel.endswith("/"):
        pattern = "^" + re.escape(first) + "(/|$)"      # a whole folder: .git, .svn, .idea, a listing
    else:
        pattern = "^" + re.escape(rel) + "$"
    return _block(env, f, pattern, "/" + rel, f"exposed_files:{rel}")


def rules_changes(env, f):
    m = re.match(r"\[([^\]]+)\] (.*)", f.title)
    if not m:
        return manual(env, f)
    page, change = m.group(1), m.group(2)
    suspicious = re.search(r"script|iframe|[Ff]orm|redirects|inline|header|status", change)
    return proposal(env, f, "accept_change",
                    ("Check this change first: injected scripts, iframes and form targets are how card skimmers and "
                     "redirects get in. If your team made it, accept " if suspicious else "Accept ")
                    + f"the current version of {page} as its new baseline. Undo puts the old baseline back.",
                    "medium" if suspicious else "low", {"page": page}, subject=f"changes:{page}:{change}",
                    fingerprint=hashlib.md5(f"{f.detail}".encode()).hexdigest()[:10], preview=f.detail or "")


def rules_malware(env, f):
    t = f.title
    if t.startswith("Inside scan: "):
        return rules_inside(env, f, t[len("Inside scan: "):])
    if "blacklisted" in t or "Safe Browsing" in t:
        return manual(env, f, "Clean the site first (Spam & Compromise > Remediation), then request a review: Google "
                      "Search Console > Security issues > Request review; Spamhaus DBL: check.spamhaus.org; SURBL: "
                      "surbl.org/surbl-analysis. A third-party script domain that is listed should be removed.")
    return manual(env, f, f"{f.recommendation} The Spam & Compromise check proposes fixes for infected content and "
                  "files; approve them there.")


def rules_inside(env, f, title):
    out = []
    locations = [loc.get("location", "") for loc in (f.evidence or {}).get("locations") or []]
    snippets = {loc.get("location", ""): loc.get("snippet", "") for loc in (f.evidence or {}).get("locations") or []}
    if title in ("Executable or script file in the media library", "SVG upload contains script") and env.guard:
        for loc in locations:
            url = snippets.get(loc, "") if title.startswith("Executable") else ""
            if not url:   # SVG: the snippet is the script; find the file through the media item
                mid = re.search(r"#(\d+)", loc)
                status, media = env.site.wp("GET", f"/wp/v2/media/{mid.group(1)}") if mid else (None, None)
                url = (media or {}).get("source_url", "") if status == 200 and isinstance(media, dict) else ""
            path = urlparse(url).path.lstrip("/")
            md5 = path and env.file_md5(path)
            if md5:
                out.append(proposal(env, f, "quarantine", f"{loc}: a script in the media library. It moves to the "
                                    "plugin's locked quarantine folder and can be restored.", "low",
                                    {"path": path, "md5": md5, "target": path}, subject="file:" + path,
                                    fingerprint=md5, preview=snippets.get(loc, ""), requires="site_guard", kind="file"))
        return out or [manual(env, f)]
    if title in ("Administrator account created recently", "New administrator since the last scan") and env.wordpress:
        me = (getattr(env.site, "login_user", None) or {}).get("id")
        for loc in locations:
            name = re.match(r"user (\S+)", loc)
            user = next((u for u in env.users() if name and (u.get("username") or u.get("slug")) == name.group(1)), None)
            if user and user.get("id") != me:
                roles = user.get("roles") or []
                out.append(proposal(env, f, "demote_user", f"Demote {name.group(1)} to subscriber until someone on "
                                    "your team confirms the account. Undo gives the roles back.", "medium",
                                    {"user_id": user["id"], "roles": roles, "target": f"account '{name.group(1)}'"},
                                    subject=f"user:{user['id']}", fingerprint=f"{user['id']}:{','.join(roles)}",
                                    kind="account"))
        return out or [manual(env, f)]
    if title in ("Unidentified plugin (no author, website or description)", "New plugin installed since the last scan") \
            and env.wordpress:
        for loc in locations:
            m = re.match(r"plugin (\S+)", loc)
            plugin = env.plugin_by_slug(m.group(1).split("/")[0]) if m else None
            if plugin:
                out.append(plugin_off(env, f, plugin, "Nobody can say who installed it: switch it off until someone "
                                      "confirms it."))
        return out or [manual(env, f)]
    return manual(env, f, f"{f.recommendation} Content and file infections get their own fixes under "
                  "Spam & Compromise > Remediation.")


def plugin_off(env, f, plugin, why):
    """Deactivate an active plugin (undo: activate), or quarantine an inactive one's folder (undo: restore)."""
    slug = plugin["plugin"].split("/")[0]
    if plugin.get("status") == "active":
        return proposal(env, f, "deactivate_plugin", why + " Deactivating keeps its files and settings; undo "
                        "activates it again.", "medium", {"plugin": plugin["plugin"], "name": plugin.get("name") or slug},
                        subject=f"wordpress:plugin-off:{slug}", requires="wordpress")
    if not env.guard12:
        return manual(env, f, f"Delete the inactive plugin {slug} (Plugins > Installed Plugins).",
                      subject=f"wordpress:plugin-off:{slug}")
    return proposal(env, f, "quarantine_dir", why + " The plugin is inactive: its folder moves to the quarantine "
                    "and can be restored.", "low", {"path": f"{env.guard.get('plugins_dir')}/{slug}", "name": slug},
                    subject=f"wordpress:plugin-off:{slug}", requires="site_guard_1.2")


def rules_wordpress(env, f):
    t, ev = f.title, f.evidence or {}
    if t.startswith("WordPress usernames exposed"):
        return harden(env, f, "block_user_enum", True, "Hide /wp-json/wp/v2/users and ?author= lookups from visitors "
                      "who aren't logged in.", subject="wordpress:user-enum")
    if t.startswith("XML-RPC is enabled"):
        return harden(env, f, "disable_xmlrpc", True, "Answer xmlrpc.php with 403. Don't approve if Jetpack or the "
                      "WordPress mobile app needs it.", "medium", subject="wordpress:xmlrpc")
    if t.startswith("WordPress readme.html"):
        return _block(env, f, r"^readme\.html$", "/readme.html", "wordpress:readme")
    if re.match(r"WordPress version .* disclosed", t):
        return harden(env, f, "hide_version", True, "Remove the version from the generator tag and the feeds.",
                      subject="wordpress:version-disclosure")
    if re.match(r"WordPress \S+ is (insecure|outdated)", t):
        if not env.guard12:
            return manual(env, f, "Update WordPress under Dashboard > Updates (take a backup first).",
                          subject="wordpress:core-update")
        latest = re.search(r"latest: ([\d.]+)|Latest release: ([\d.]+)", f.detail or "")
        target = next((g for g in (latest.groups() if latest else ()) if g), "")
        return proposal(env, f, "update_core", "Update WordPress core to the latest release. It can't be undone "
                        "from here: take a backup or host snapshot first.", "high", {"latest": target},
                        subject=f"wordpress:core-update:{target}", requires="site_guard_1.2")
    if t.startswith(("Vulnerable plugin:", "Outdated plugin:")):
        slug = ev.get("plugin")
        target = ev.get("fixed_in") or ev.get("latest")
        if t.startswith("Vulnerable") and not target:
            plugin = env.plugin_by_slug(slug)
            return plugin_off(env, f, plugin, "Known vulnerability with no fixed release.") if plugin else manual(env, f)
        if not env.guard12:
            return manual(env, f, f"Update {slug} under Plugins > Installed Plugins.",
                          subject=f"wordpress:plugin-update:{slug}:{target}")
        active = ev.get("active", True)
        return proposal(env, f, "update_plugin", f"Update {slug} from {ev.get('installed')} to the latest release "
                        f"({target} or newer). Updates can't be undone from here.",
                        "medium" if active else "low", {"slug": slug, "target": target},
                        subject=f"wordpress:plugin-update:{slug}:{target}", requires="site_guard_1.2")
    if t.startswith("Outdated theme:"):
        slug = ev.get("theme")
        if not env.guard12:
            return manual(env, f, subject=f"wordpress:theme-update:{slug}:{ev.get('latest')}")
        return proposal(env, f, "update_theme", f"Update the {slug} theme to {ev.get('latest')}. Updates can't be "
                        "undone from here, and changes made directly in the theme's files are lost.", "medium",
                        {"slug": slug, "target": ev.get("latest")},
                        subject=f"wordpress:theme-update:{slug}:{ev.get('latest')}", requires="site_guard_1.2")
    if t.startswith("Plugin removed from wordpress.org:"):
        plugin = env.plugin_by_slug(ev.get("plugin"))
        return plugin_off(env, f, plugin, "Closed on wordpress.org, often for an unfixed security issue; replace it "
                          "with a maintained plugin.") if plugin else manual(env, f)
    if re.match(r"\d+ inactive plugin\(s\) installed", t):
        out = [plugin_off(env, f, p, f"{p.get('name') or p['plugin']} is installed but not used; inactive plugins "
                          "can still be attacked.") for p in env.plugins()
               if p.get("status") == "inactive" and not p["plugin"].startswith("kleza-site-guard/")]
        return out or [manual(env, f)]
    if re.match(r"\d+ inactive theme\(s\) installed", t):
        themes = [th for th in env.themes() if th.get("status") != "active"]
        default = max((th for th in themes if str(th.get("stylesheet", "")).startswith("twenty")),
                      key=lambda th: th.get("stylesheet"), default=None)   # keep one default theme as a fallback
        out = []
        for th in themes:
            if th is default or not env.guard12:
                continue
            out.append(proposal(env, f, "quarantine_dir", f"The {th['stylesheet']} theme isn't used. Its folder moves "
                                "to the quarantine and can be restored.", "low",
                                {"path": f"{env.guard.get('themes_dir')}/{th['stylesheet']}", "name": th["stylesheet"]},
                                subject=f"wordpress:theme-off:{th['stylesheet']}", requires="site_guard_1.2"))
        return out or [manual(env, f)]
    if re.match(r"\d+ unused application password", t):
        if not env.wordpress:
            return manual(env, f)
        days = int(env.target["checks"].get("wordpress", {}).get("stale_app_password_days", 90))
        return proposal(env, f, "revoke_app_passwords", f"Revoke application passwords that haven't been used for "
                        f"{days} days. A revoked password can't be restored; the apps using it need a new one.", "low",
                        {"days": days}, subject="wordpress:stale-app-passwords",
                        fingerprint=hashlib.md5(json.dumps(ev.get("stale") or []).encode()).hexdigest()[:10],
                        preview="\n".join(ev.get("stale") or []), requires="wordpress")
    return manual(env, f)


def rules_vulnerabilities(env, f):
    t = f.title
    if t.startswith("Verbose error"):
        return harden(env, f, "hide_errors", True, "Stop PHP from printing errors and stack traces to visitors.",
                      subject="vulnerabilities:errors")
    if t.startswith("No security.txt"):
        expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT00:00:00Z")
        text = f"Contact: mailto:{env.admin_email()}\nExpires: {expires}\nPreferred-Languages: en\n"
        return harden(env, f, "security_txt", text, "Publish /.well-known/security.txt so researchers know where to "
                      "report security problems (contact: the site's admin email; edit it later if needed).",
                      subject="vulnerabilities:security-txt")
    if "mixed content" in t:
        return manual(env, f, "Change the listed http:// URLs to https:// (Tools such as Better Search Replace can "
                      "update the database), or send Content-Security-Policy: upgrade-insecure-requests.")
    return manual(env, f)


def rules_dns(env, f):
    t, d = f.title, env.domain
    records = {
        "No SPF record": f'Add a TXT record on {d}: "v=spf1 include:<your mail provider> ~all" (or "v=spf1 -all" if '
                         "the domain sends no email).",
        "Multiple SPF records (SPF permerror)": f"Merge the SPF records on {d} into one TXT record.",
        "SPF allows any sender (+all)": f'Replace +all with ~all or -all in the SPF record on {d}.',
        "SPF policy is neutral/permissive": f'End the SPF record on {d} with ~all or -all.',
        "No DMARC record": f'Add a TXT record on _dmarc.{d}: "v=DMARC1; p=quarantine; rua=mailto:dmarc@{d}".',
        "DMARC policy is p=none (monitor only)": f"After checking the DMARC reports, change p=none to p=quarantine "
                                                 f"in the _dmarc.{d} record.",
        "No CAA record": f'Add a CAA record on {d}: 0 issue "letsencrypt.org" (use your certificate authority).',
        "DNSSEC not enabled": "Turn on DNSSEC at your DNS provider and add the DS record at the registrar.",
        "Domain transfer lock not enabled": "Turn on the transfer lock (clientTransferProhibited) at the registrar.",
    }
    if t in records:
        return manual(env, f, records[t] + " DNS changes are made at your DNS provider; the agent can't make them.",
                      subject=f"dns:{t}")
    if t.startswith("Domain registration expires"):
        return manual(env, f, "Renew the domain and turn on auto-renew at the registrar.", subject="dns:expiry")
    if re.match(r"DNS \S+ records changed", t):
        return manual(env, f, "Confirm your team made this DNS change. If not, secure the registrar and DNS provider "
                      "accounts (password, two-factor) and restore the records.", subject=f"dns:{t}")
    return manual(env, f)


def rules_third_party(env, f):
    t = f.title
    if t.startswith("External scripts/stylesheets loaded without Subresource Integrity"):
        return manual(env, f, "Add integrity=\"sha384-...\" crossorigin=\"anonymous\" to the listed tags (use "
                      "versioned CDN URLs), or host the files yourself.", subject="third_party:sri")
    if t.startswith("Third-party resource domain(s) no longer resolve"):
        return manual(env, f, "Remove every reference to these domains now: anyone who registers them can serve "
                      "scripts on your site.", subject="third_party:dead-domains")
    return manual(env, f)


RULES = {"headers": rules_headers, "ssl": rules_ssl, "exposed_files": rules_exposed, "changes": rules_changes,
         "malware": rules_malware, "wordpress": rules_wordpress, "vulnerabilities": rules_vulnerabilities,
         "dns": rules_dns, "third_party": rules_third_party}
CHECK_LABEL = {"ssl": "SSL/TLS", "headers": "Security headers", "exposed_files": "Exposed files",
               "changes": "Content changes", "malware": "Malware", "vulnerabilities": "Vulnerabilities", "dns": "DNS",
               "third_party": "Third-party scripts", "wordpress": "WordPress", "availability": "Availability"}


def build_proposals(env, findings):
    """Proposals for every problem (not INFO) the security checks found; Spam & Compromise has its own."""
    out, seen = [], set()
    for f in findings:
        if f.severity <= S.INFO or f.check in ("compromise", "agent") or SKIP.search(f.title):
            continue
        rule = RULES.get(f.check)
        try:
            made = rule(env, f) if rule else manual(env, f)
        except Exception as exc:   # one rule failing must not hide the problem
            made = manual(env, f, f"{f.recommendation} (Automatic fix unavailable: {exc.__class__.__name__}.)")
        for p in made if isinstance(made, list) else [made]:
            if p["id"] not in seen:
                seen.add(p["id"])
                out.append(p)
    return out


# ---- applying, verifying and undoing ------------------------------------------------------------------------
def _target(p):
    target = TARGETS.get(p["data"].get("site_slug"))
    if target is None:
        raise RemediationError("The site isn't loaded in this agent; restart the dashboard and try again.")
    return target


def _site(target):
    from jp_seo_agent.site import Site
    from .checks.wordpress import credentials
    wp_cfg = target["checks"].get("wordpress", {})
    return Site(target["url"], timeout=target.get("timeout", 20), pages=target.get("pages"),
                wp_auth=credentials(wp_cfg) if wp_cfg.get("enabled") else None)


def still_present(p):
    """Run the proposal's check again and see whether the same problem is still reported. (present, note)"""
    from .agent import run_checks_once   # late import: agent.py imports this module
    target = _target(p)
    findings, completed = run_checks_once(target, [p["check"]])
    if p["check"] not in completed:
        return None, "the check could not run again"
    subjects = {q["data"]["subject"] for q in build_proposals(Env(target, _site(target)), findings)}
    return p["data"]["subject"] in subjects, ""


def verify(p, cache_hint=""):
    present, note = still_present(p)
    if present is None:
        return False, f"Applied; {note}."
    if present:
        return False, "Applied, but the check still reports the problem" + (f" ({cache_hint})" if cache_hint else "") + "."
    return True, "The check no longer reports the problem."


class Handler:
    needs_wordpress = True

    def apply(self, r, p):
        raise NotImplementedError

    def undo(self, r, p, applied):
        raise RemediationError("This fix can't be undone automatically.")

    @staticmethod
    def guard(r, minimum=(1, 2)):
        status, data = r.site.wp("GET", f"{API}/status")
        version = data.get("plugin_version") if status == 200 and isinstance(data, dict) else None
        if not version or _v(version) < minimum:
            raise RemediationError("This fix needs the Kleza Site Guard plugin "
                                   f"{'.'.join(map(str, minimum))} or newer: upload jp_seo_agent/wp-plugin/"
                                   "kleza-site-guard.zip in wp-admin > Plugins > Add New (Replace current).")
        return data


class Harden(Handler):
    def apply(self, r, p):
        self.guard(r)
        d = p["data"]
        res = r._wp("POST", f"{API}/hardening", json={"key": d["key"], "value": d["value"]})
        backup = r._backup(p, {"key": d["key"], "previous": res.get("previous")})
        ok, note = verify(p, cache_hint="a page cache or CDN may still serve the old headers; clear it")
        return {"message": f"Switched on {d['key']}.", "backup": backup, "undo": {"previous": res.get("previous")},
                "verified": ok, "verification": note}

    def undo(self, r, p, applied):
        r._wp("POST", f"{API}/hardening", json={"key": p["data"]["key"],
                                                "value": (applied.get("undo") or {}).get("previous")})
        return f"Switched {p['data']['key']} back to what it was."


def _with_rules(text, tag, patterns, add=True):
    """.htaccess text with this proposal's rules added to (or removed from) the Kleza Guard block at the top."""
    lines = text.splitlines()
    if KLEZA_BEGIN in lines and KLEZA_END in lines:
        start, end = lines.index(KLEZA_BEGIN), lines.index(KLEZA_END)
        block, rest = lines[start + 1:end], lines[:start] + lines[end + 1:]
    else:
        block, rest = [], lines
    rules = [line for line in block if line.startswith("RewriteRule ") and not line.endswith(f"# kleza:{tag}")]
    if add:
        rules += [f"RewriteRule {pat} - [F,L] # kleza:{tag}" for pat in patterns]
    if not rules:
        return "\n".join(rest).lstrip("\n") + "\n"
    new_block = [KLEZA_BEGIN, "<IfModule mod_rewrite.c>", "RewriteEngine On", *rules, "</IfModule>", KLEZA_END]
    return "\n".join(new_block + [""] + rest).rstrip("\n") + "\n"


class BlockPaths(Handler):
    def _write(self, r, p, add):
        self.guard(r, (1, 1))
        try:
            original = r._read_file(".htaccess")
        except RemediationError as exc:
            raise RemediationError("The site has no .htaccess file to add the rule to (an nginx server?). Block the "
                                   "path in the server configuration instead.") from exc
        tag = hashlib.sha1(p["data"]["subject"].encode()).hexdigest()[:8]
        new = _with_rules(original.decode("utf-8", "replace"), tag, p["data"]["patterns"], add).encode("utf-8")
        if new == original:
            return original, None
        entry = r._wp("POST", f"{API}/replace", json={
            "path": ".htaccess", "md5": hashlib.md5(original).hexdigest(),
            "content_base64": base64.b64encode(new).decode(), "new_md5": hashlib.md5(new).hexdigest(),
            "reason": f"proposal {p['id']}: {'block' if add else 'unblock'} {', '.join(p['data']['patterns'])}"})
        return original, entry

    def apply(self, r, p):
        original, entry = self._write(r, p, True)
        backup = r._backup(p, {"path": ".htaccess", "content_base64": base64.b64encode(original).decode()})
        ok, note = verify(p, cache_hint="the server may not read .htaccess (nginx): block it in its configuration")
        return {"message": "Added the deny rule to .htaccess.", "backup": backup,
                "undo": {"quarantine_id": (entry or {}).get("id")}, "verified": ok, "verification": note}

    def undo(self, r, p, applied):
        self._write(r, p, False)   # remove only this proposal's rules; other fixes in the block stay
        return "Removed the deny rule from .htaccess."


class Upgrade(Handler):
    def __init__(self, kind):
        self.kind = kind

    def apply(self, r, p):
        self.guard(r)
        d = p["data"]
        res = r._wp("POST", f"{API}/upgrade", json={"type": self.kind, "item": d.get("slug", "")}, timeout=600)
        backup = r._backup(p, {"type": self.kind, "item": d.get("slug"), "from": res.get("from")})
        if not res.get("updated") and _v(res.get("to")) < _v(d.get("target") or d.get("latest")):
            return {"message": f"Nothing was installed (still {res.get('to')}).", "backup": backup,
                    "verified": False, "verification": "WordPress didn't install a newer version."}
        ok, note = verify(p)
        return {"message": f"Updated {d.get('slug') or 'WordPress'} from {res.get('from')} to {res.get('to')}.",
                "backup": backup, "verified": ok, "verification": note}

    def undo(self, r, p, applied):
        raise RemediationError("An update can't be undone from here. Restore the previous version from a backup or "
                               "the host's snapshot (WP Rollback can reinstall an older wordpress.org release).")


class DeactivatePlugin(Handler):
    def apply(self, r, p):
        plugin = p["data"]["plugin"]
        r._wp("POST", f"/wp/v2/plugins/{plugin}", json={"status": "inactive"})
        backup = r._backup(p, {"plugin": plugin, "status": "active"})
        ok, note = verify(p)
        status, data = r.site.wp("GET", f"/wp/v2/plugins/{plugin}")
        inactive = status == 200 and isinstance(data, dict) and data.get("status") == "inactive"
        return {"message": f"Deactivated {p['data'].get('name')}.", "backup": backup, "undo": {"plugin": plugin},
                "verified": inactive, "verification": "The plugin is inactive." if inactive else note}

    def undo(self, r, p, applied):
        r._wp("POST", f"/wp/v2/plugins/{p['data']['plugin']}", json={"status": "active"})
        return "Activated the plugin again."


class QuarantineDir(Handler):
    def apply(self, r, p):
        self.guard(r)
        entry = r._wp("POST", f"{API}/quarantine-dir", json={"path": p["data"]["path"],
                                                              "reason": f"proposal {p['id']}: {p['title'][:150]}"})
        backup = r._backup(p, {"path": p["data"]["path"], "quarantine_id": entry.get("id")})
        ok, note = verify(p)
        return {"message": f"Moved {p['data']['path']} to the quarantine.", "backup": backup,
                "undo": {"quarantine_id": entry.get("id")}, "verified": ok, "verification": note}

    def undo(self, r, p, applied):
        r._wp("POST", f"{API}/restore", json={"id": (applied.get("undo") or {}).get("quarantine_id")})
        return "Folder restored from the quarantine."


class RevokeAppPasswords(Handler):
    def apply(self, r, p):
        days = int(p["data"].get("days", 90))
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        admins = r.site.wp_items("/wp/v2/users", context="edit", roles="administrator")
        revoked = []
        for admin in admins:
            status, keys = r.site.wp("GET", f"/wp/v2/users/{admin['id']}/application-passwords")
            for k in keys if status == 200 and isinstance(keys, list) else []:
                when = k.get("last_used") or k.get("created")
                try:
                    stamp = datetime.fromisoformat(str(when).replace("Z", "+00:00"))
                except ValueError:
                    continue
                if (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)) < cutoff:
                    r._wp("DELETE", f"/wp/v2/users/{admin['id']}/application-passwords/{k['uuid']}")
                    revoked.append(f"{admin.get('username') or admin.get('slug')}: {k.get('name')}")
        backup = r._backup(p, {"revoked": revoked})
        ok, note = verify(p)
        return {"message": f"Revoked {len(revoked)} application password(s): {', '.join(revoked) or 'none'}.",
                "backup": backup, "verified": ok, "verification": note}


class AcceptChange(Handler):
    needs_wordpress = False

    def _state(self, p):
        from .agent import state_path_for
        return state_path_for(_target(p))

    def apply(self, r, p):
        path, page = self._state(p), p["data"]["page"]
        state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        old = ((state.get("changes") or {}).get("pages") or {}).pop(page, None)
        path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        backup = r._backup(p, {"page": page, "baseline": old})
        return {"message": f"The current version of {page} is the new baseline (recorded at the next scan).",
                "backup": backup, "undo": {"baseline": old}, "verified": True,
                "verification": "The old baseline was set aside; the next scan records the page as it is now."}

    def undo(self, r, p, applied):
        path, page = self._state(p), p["data"]["page"]
        state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        old = (applied.get("undo") or {}).get("baseline")
        if old is not None:
            state.setdefault("changes", {}).setdefault("pages", {})[page] = old
            path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        return "The previous baseline is back; the change is reported again."


HANDLERS = {"harden": Harden(), "block_paths": BlockPaths(), "update_plugin": Upgrade("plugin"),
            "update_theme": Upgrade("theme"), "update_core": Upgrade("core"), "deactivate_plugin": DeactivatePlugin(),
            "quarantine_dir": QuarantineDir(), "revoke_app_passwords": RevokeAppPasswords(),
            "accept_change": AcceptChange()}
for _action, _handler in HANDLERS.items():
    remediate.register(_action, _handler)


def needs_wordpress(p):
    if p["action"] == "manual":
        return False
    handler = HANDLERS.get(p["action"])
    return handler.needs_wordpress if handler else True
