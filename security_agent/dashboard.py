"""Interactive dashboard: a self-contained HTML file generated from the reports, plus an optional
local server (127.0.0.1 only) that adds on-demand scans, adding/removing sites and live refresh."""

import http.cookies
import json
import logging
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests

from .checks import ssh_inside
from .checks.wordpress import _read_secret_file, credentials as wp_credentials
from .ignored import apply_ignored, ignore_key, load_ignored, save_ignored
from .config import _slug, load_managed_sites, resolve_targets, save_managed_sites
from .excel import to_xlsx
from .fixes import TARGETS
from .notify import save_webhook, send_daily_card, send_defense_alert, webhook_status
from .schedule import next_daily_run, schedule_tz

log = logging.getLogger("security_agent.dashboard")
TEMPLATE = Path(__file__).with_name("dashboard.html")
LOGIN_TEMPLATE = Path(__file__).with_name("login.html").read_text(encoding="utf-8")
MAX_HISTORY = 500
XLSX_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
SERVED_SUFFIXES = {".md": "text/plain", ".json": "application/json", ".xlsx": XLSX_TYPE}


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _site_title(config, target):
    """The site's own <title>, taken from the page baseline saved by the content-change check."""
    state = _read_json(Path(config["report"].get("state_dir", "state")) / f"{target['slug']}.json") or {}
    pages = (state.get("changes") or {}).get("pages") or {}
    for page in [*target.get("pages", ["/"]), *pages]:
        title = ((pages.get(page) or {}).get("title") or "").strip()
        if title:
            return " ".join(title.split())
    return ""


def _read_history(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return rows[-MAX_HISTORY:]


def _with_runs(rows, site_dir):
    """Attach each history row's report folder (reports/<site>/<YYYYMMDD-HHMMSS>/) and the report files in it."""
    for row in rows:
        try:
            started = datetime.fromisoformat(str(row.get("started_at"))).astimezone(timezone.utc)
        except ValueError:
            continue
        run = started.strftime("%Y%m%d-%H%M%S")
        try:
            files = sorted(p.name for p in (site_dir / run).iterdir() if p.name.startswith("report."))
        except OSError:
            continue
        if files:
            row["run"], row["files"] = run, files
    return rows


def _login_info(target):
    """What the edit-credentials form needs to show: the kind of inside scan and the username (never a password)."""
    ssh = target["checks"].get("malware", {}).get("ssh")
    if ssh:
        return {"kind": "ssh", "username": ssh.get("username", ""), "editable": bool(target.get("managed"))}
    wp = target["checks"].get("wordpress", {})
    auth = wp_credentials(wp) if wp.get("enabled") else None
    return {"kind": "wordpress", "username": auth[0] if auth else wp.get("username", ""), "has_password": bool(auth),
            "editable": True}


def collect_data(config, targets, server=False, scan_status=None):
    out = Path(config["report"]["output_dir"])
    ignored = load_ignored(config)
    sites = []
    for t in targets:
        site_dir = out / t["slug"]
        sites.append({
            "name": t["name"],
            "title": _site_title(config, t),
            "slug": t["slug"],
            "url": t["url"],
            "pages": t.get("pages", ["/"]),
            "managed": t.get("managed", False),
            "login": _login_info(t) if server else None,
            "latest": apply_ignored(_read_json(site_dir / "latest.json"), ignored.get(t["slug"], {})),
            "history": _with_runs(_read_history(site_dir / "history.jsonl"), site_dir),
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "server": server,
        "scan_status": scan_status,
        "settings": {
            "interval_minutes": config["schedule"]["interval_minutes"],
            "schedule_active": bool(config["schedule"].get("active")),
            "schedule_mode": config["schedule"].get("mode") or ("daily" if config["schedule"].get("daily_at") else "interval"),
            "daily_at": config["schedule"].get("daily_at"),
            "timezone": config["schedule"].get("timezone") or "",
            "teams": webhook_status(config) if server else None,
            "next_scan": (next_daily_run(config["schedule"]["daily_at"], tz=schedule_tz(config["schedule"].get("timezone"))).astimezone().isoformat()
                          if config["schedule"].get("active") and config["schedule"].get("mode") == "daily" else None),
            "fail_on": config["report"]["fail_on"],
            "output_dir": str(out),
            "sites_file": config.get("sites_file", "sites.json"),
            "checks": {name: bool(c.get("enabled", True)) for name, c in config["checks"].items()},
            "admin": {"email": config.get("auth", {}).get("email", ""), "name": config.get("auth", {}).get("name", "Administrator"),
                      "enabled": bool(config.get("auth", {}).get("enabled", False))},
        },
        "sites": sites,
        "ignored": ignored,
    }


def render(data):
    payload = json.dumps(data, default=str).replace("<", "\\u003c")
    return TEMPLATE.read_text(encoding="utf-8").replace("__DASHBOARD_DATA__", payload)


def write_dashboard(config, targets):
    path = Path(config["report"]["output_dir"]) / "dashboard.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(collect_data(config, targets)), encoding="utf-8")
    return path


def _normalize_site_url(raw):
    url = (raw or "").strip()
    if not url:
        raise ValueError("Enter a website URL")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host or not (re.fullmatch(r"[a-z0-9.-]+", host) and ("." in host or host == "localhost")):
        raise ValueError("That doesn't look like a valid website address")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}"


class FixError(Exception):
    """WordPress refused or couldn't make a change."""


class DashboardServer:
    """Serves the dashboard on localhost, runs scans on request and manages dashboard-added sites."""

    def __init__(self, agent, config, targets, host="127.0.0.1", port=8765):
        self.agent, self.config, self.targets = agent, config, targets
        self.host, self.port = host, port
        self.lock = threading.Lock()
        self.status = {"running": False, "site": None, "started_at": None, "finished_at": None, "error": None}
        self.sessions = set()  # active login session tokens (in memory; cleared on restart)
        self.defense_running = {}  # slug -> integrity monitor job running for it ("check", "investigation")
        self.defense_active = False  # the monitor loop is running (--serve)
        self.pending_keys = {}  # key id -> generated SSH private key, until the site it was made for is added
        TARGETS.update({t["slug"]: t for t in targets})

    # ---- auth -------------------------------------------------------------
    @property
    def auth(self):
        return self.config.get("auth") or {}

    def auth_required(self):
        return bool(self.auth.get("enabled", False))

    def check_login(self, email, password):
        a = self.auth
        return (str(email or "").strip().lower() == str(a.get("email", "")).lower()
                and str(password or "") == str(a.get("password", "")))

    def new_session(self):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions.add(token)
        return token

    # ---- sites ------------------------------------------------------------
    def _reload_targets(self):
        self.targets = resolve_targets(self.config)
        self.agent.targets = self.targets
        TARGETS.update({t["slug"]: t for t in self.targets})

    def add_site(self, url, name=None, pages=None, wp_username=None, wp_password=None, ssh=None):
        url = _normalize_site_url(url)
        if any(t["url"].rstrip("/").lower() == url.rstrip("/").lower() for t in self.targets):
            raise ValueError("This website is already being monitored")
        entry = {"url": url}
        name = (name or "").strip()
        if name:
            if len(name) > 60:
                raise ValueError("Name must be 60 characters or fewer")
            entry["name"] = name
        page_list = [p.strip() for p in (pages or []) if p and p.strip()]
        bad = [p for p in page_list if not p.startswith("/")]
        if bad:
            raise ValueError(f"Pages must start with '/': {', '.join(bad)}")
        if page_list:
            entry["pages"] = (["/"] if "/" not in page_list else []) + page_list[:20]
        if ssh:
            self._attach_ssh(entry, url, name, ssh)
        else:
            self._attach_wordpress(entry, url, name, wp_username, wp_password)
        sites = load_managed_sites(self.config)
        sites.append(entry)
        save_managed_sites(self.config, sites)
        self._reload_targets()
        added = next(t for t in self.targets if t["url"].rstrip("/").lower() == url.rstrip("/").lower())
        return added["slug"]

    def _attach_wordpress(self, entry, url, name, wp_username, wp_password):
        """Enable the WordPress check for a dashboard-added site. The application password is written to a
        local secrets/<slug>.env file (never stored in sites.json), matching how config.yaml sites work."""
        wp_username = (wp_username or "").strip()
        wp_password = (wp_password or "").strip()
        if not (wp_username or wp_password):
            return
        wp = {"enabled": True}
        if wp_username:
            wp["username"] = wp_username
        if wp_password:
            slug = _slug(name or urlparse(url).hostname or "site")
            secret_path = Path("secrets") / f"{slug}.env"
            secret_path.parent.mkdir(parents=True, exist_ok=True)
            lines = ([f"username={wp_username}"] if wp_username else []) + [f"password={wp_password}"]
            secret_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            wp["app_password_file"] = secret_path.as_posix()
        entry["checks"] = {"wordpress": wp}

    def generate_ssh_key(self):
        """A new key pair for a site's SSH inside scan: the private key stays on this server, the public key is shown
        so it can be added to the website's server."""
        private, public = ssh_inside.generate_key()
        key_id = secrets.token_urlsafe(12)
        with self.lock:
            self.pending_keys = dict(list(self.pending_keys.items())[-20:])
            self.pending_keys[key_id] = private
        return key_id, public

    def _attach_ssh(self, entry, url, name, ssh):
        """Inside scan over SSH for a site that isn't WordPress. The login and folder are tested first; the private
        key is written to a local secrets/<slug>.ssh.key file (never to sites.json) and the server's host key is
        pinned, so a changed server is reported instead of trusted. Only the username and key are required: the host
        defaults to the site's domain, and the usual SSH ports and website folders are tried."""
        domain = urlparse(url).hostname or ""
        host = str(ssh.get("host") or "").strip().lower() or domain
        if not re.fullmatch(r"[a-z0-9.:-]+", host or ""):
            raise ValueError("Enter the SSH host (server name or IP address)")
        port = str(ssh.get("port") or "").strip()
        if port and not (port.isdigit() and 0 < int(port) < 65536):
            raise ValueError("The SSH port must be a number from 1 to 65535")
        port = int(port) if port else None
        username = str(ssh.get("username") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", username):
            raise ValueError("Enter the SSH username")
        web_root = str(ssh.get("web_root") or "").strip()
        if len(web_root) > 300 or "\n" in web_root:
            raise ValueError("Enter the website folder on the server, e.g. /home/user/public_html")
        with self.lock:
            key_text = self.pending_keys.get(str(ssh.get("key_id") or "")) or str(ssh.get("private_key") or "").strip()
        if "PRIVATE KEY" not in key_text:
            raise ValueError("Generate a key, or paste the private key (it starts with -----BEGIN ... PRIVATE KEY-----)")
        try:
            host_key, port, root = ssh_inside.probe(host, port, username, key_text, web_root, domain)
        except ssh_inside.SSHError as exc:
            raise ValueError(str(exc)) from exc
        slug = _slug(name or urlparse(url).hostname or "site")
        key_path = Path("secrets") / f"{slug}.ssh.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(key_text.strip() + "\n", encoding="utf-8")
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
        with self.lock:
            self.pending_keys.pop(str(ssh.get("key_id") or ""), None)
        entry["checks"] = {"malware": {"ssh": {"host": host, "port": port, "username": username, "web_root": root,
                                               "key_file": key_path.as_posix(), "host_key": host_key}}}

    def remove_site(self, slug):
        target = next((t for t in self.targets if t["slug"] == slug), None)
        if target is None:
            raise ValueError("Unknown site")
        if not target.get("managed"):
            raise ValueError("This site is defined in config.yaml; remove it there")
        sites = [s for s in load_managed_sites(self.config)
                 if s["url"].rstrip("/").lower() != target["url"].rstrip("/").lower()]
        save_managed_sites(self.config, sites)
        self._reload_targets()

    def get_credentials(self, slug):
        """The saved login of a site, for the edit form. Served only to a logged-in dashboard session and never put in
        the dashboard page's data."""
        target = next((t for t in self.targets if t["slug"] == slug), None)
        if target is None:
            raise ValueError("Unknown site")
        ssh = target["checks"].get("malware", {}).get("ssh")
        if ssh:
            try:
                key = Path(ssh["key_file"]).read_text(encoding="utf-8")
            except (OSError, KeyError):
                key = ""
            return {"kind": "ssh", "username": ssh.get("username", ""), "private_key": key}
        wp = target["checks"].get("wordpress", {})
        auth = wp_credentials(wp) if wp.get("enabled") else None
        return {"kind": "wordpress", "username": auth[0] if auth else wp.get("username", ""),
                "password": auth[1] if auth else ""}

    def update_credentials(self, slug, wp_username=None, wp_password=None, ssh=None):
        """Change the inside-scan login of any site. WordPress: the username and application password go to the
        site's secrets file (a blank password keeps the saved one). SSH: the login is tested, then the key is replaced
        (sites added from the dashboard only, since the pinned host key is stored with the site)."""
        target = next((t for t in self.targets if t["slug"] == slug), None)
        if target is None:
            raise ValueError("Unknown site")
        sites = load_managed_sites(self.config)
        entry = next((s for s in sites if s["url"].rstrip("/").lower() == target["url"].rstrip("/").lower()), None)
        if ssh:
            if not target.get("managed") or entry is None:
                raise ValueError("This site is defined in config.yaml; change its SSH login there")
            old = (entry.get("checks") or {}).get("malware", {}).get("ssh", {})
            ssh = {**{"host": old.get("host"), "port": old.get("port"), "web_root": old.get("web_root")},
                   **{k: v for k, v in ssh.items() if v}}
            if not (ssh.get("private_key") or ssh.get("key_id")) and old.get("key_file"):
                ssh["private_key"] = Path(old["key_file"]).read_text(encoding="utf-8")
            probe_entry = {}
            self._attach_ssh(probe_entry, target["url"], slug, ssh)
            entry["checks"] = {**(entry.get("checks") or {}), **probe_entry["checks"]}
            if "wordpress" in entry["checks"]:   # switched to SSH: the WordPress login is no longer used
                entry["checks"]["wordpress"] = {**entry["checks"]["wordpress"], "enabled": False}
        else:
            wp_cfg = target["checks"].get("wordpress", {})
            wp_username, wp_password = (wp_username or "").strip(), (wp_password or "").strip()
            secret_file = wp_cfg.get("app_password_file") or (Path("secrets") / f"{slug}.env").as_posix()
            try:
                saved = _read_secret_file(secret_file)
            except OSError:
                saved = {}
            username = wp_username or wp_cfg.get("username") or saved.get("username", "")
            password = wp_password or saved.get("password", "")
            if not (username and password):
                raise ValueError("Enter the username and the application password")
            path = Path(secret_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"username={username}\npassword={password}\n", encoding="utf-8")
            if entry is not None:
                checks = entry.setdefault("checks", {})
                checks["wordpress"] = {**checks.get("wordpress", {}), "enabled": True, "username": username,
                                       "app_password_file": path.as_posix()}
                checks.get("malware", {}).pop("ssh", None)   # switched to WordPress: stop using the SSH login
        if entry is not None:
            save_managed_sites(self.config, sites)
        self._reload_targets()

    def set_ignored(self, slug, title=None, check=None, severity=None, key=None, ignore=True):
        """Ignore a finding (by its title) or un-ignore one (by its key) for one site."""
        if not any(t["slug"] == slug for t in self.targets):
            raise ValueError("Unknown site")
        key = key or ignore_key(title)
        if not key or len(key) > 500:
            raise ValueError("Invalid finding")
        with self.lock:
            data = load_ignored(self.config)
            entries = data.setdefault(slug, {})
            if ignore:
                entries[key] = {"title": title or entries.get(key, {}).get("title", key), "check": check, "severity": severity}
            else:
                entries.pop(key, None)
            if not entries:
                data.pop(slug, None)
            save_ignored(self.config, data)
        return data

    def fix_wordpress(self, slug, action, item=None):
        """Fix a WordPress issue through the site's REST API with its saved application password, then rescan.
        Core API: remove one plugin (`item` = its folder) or delete every inactive plugin. Updates use the
        hostinger-ai/plugin-update and theme-update abilities (Hostinger AI Assistant plugin), since the core API
        has no update command; sites without that plugin get an error saying so."""
        target = next((t for t in self.targets if t["slug"] == slug), None)
        if target is None:
            raise ValueError("Unknown site")
        if action not in ("remove_plugin", "delete_inactive_plugins", "update_plugin", "update_theme"):
            raise ValueError("Unknown action")
        if action != "delete_inactive_plugins" and not re.fullmatch(r"[A-Za-z0-9._-]+", item or ""):
            raise ValueError("Invalid plugin")
        wp_cfg = target["checks"].get("wordpress", {})
        auth = wp_credentials(wp_cfg) if wp_cfg.get("enabled") else None
        if not auth:
            raise ValueError("No application password is saved for this site")
        origin = "{0.scheme}://{0.netloc}".format(urlparse(target["url"]))
        if not origin.startswith("https://"):
            raise ValueError("The application password is only sent over HTTPS, and this site uses http://")
        api = requests.Session()
        api.auth, api.headers["User-Agent"] = auth, "SecurityMonitor/1.0"

        def call(method, path, **json_body):
            # POST + method override: some hosts block real PUT/DELETE requests
            try:
                resp = api.post(f"{origin}/wp-json/wp/v2{path}", json=json_body or None, timeout=120,
                                headers={} if method == "POST" else {"X-HTTP-Method-Override": method})
            except requests.RequestException as exc:
                raise FixError(f"Could not reach the site: {exc.__class__.__name__}") from exc
            try:
                data = resp.json()
            except ValueError:
                data = None
            if resp.status_code in (401, 403):
                raise FixError("WordPress refused the application password: it must belong to an administrator "
                               f"({(data or {}).get('message') or f'HTTP {resp.status_code}'}).")
            if not resp.ok:
                msg = (data or {}).get("message") if isinstance(data, dict) else None
                raise FixError(re.sub(r"<[^>]+>", "", str(msg or f"WordPress answered HTTP {resp.status_code}"))[:300])
            return data

        def ability(name, **inputs):
            try:
                resp = api.post(f"{origin}/wp-json/wp-abilities/v1/abilities/{name}/run", json={"input": inputs}, timeout=300)
            except requests.RequestException as exc:
                raise FixError(f"Could not reach the site: {exc.__class__.__name__}") from exc
            try:
                data = resp.json()
            except ValueError:
                data = None
            if resp.status_code == 404:
                raise FixError("This site can't be updated with the application password: it needs the Hostinger AI "
                               "Assistant plugin active (it provides the update command).")
            if not resp.ok:
                msg = data.get("message") if isinstance(data, dict) else None
                raise FixError(re.sub(r"<[^>]+>", "", str(msg or f"WordPress answered HTTP {resp.status_code}"))[:300])
            return data if isinstance(data, dict) else {}

        if action == "update_theme":
            ability("hostinger-ai/theme-update", stylesheet=item)
            self.start_scan(slug)
            return f"Updated the {item} theme"

        def remove(p):  # a plugin must be inactive before WordPress lets it be deleted
            if p.get("status") != "inactive":
                call("PUT", f"/plugins/{p['plugin']}", status="inactive")
            call("DELETE", f"/plugins/{p['plugin']}")

        try:
            plugins = api.get(f"{origin}/wp-json/wp/v2/plugins", timeout=60).json()
        except (requests.RequestException, ValueError) as exc:
            raise FixError("Could not list the site's plugins") from exc
        if not isinstance(plugins, list):
            raise FixError("WordPress refused to list plugins: the application password must belong to an administrator.")
        name = lambda p: p.get("name") if isinstance(p.get("name"), str) else p["plugin"].split("/")[0]
        if action == "update_plugin":
            match = next((p for p in plugins if p["plugin"].split("/")[0] == item), None)
            if match is None:
                raise FixError(f"{item} is not installed")
            ability("hostinger-ai/plugin-update", plugin_file=match["plugin"] + ".php")
            after = next((p for p in (api.get(f"{origin}/wp-json/wp/v2/plugins", timeout=60).json() or [])
                          if p.get("plugin") == match["plugin"]), {})
            if after.get("version") == match.get("version"):
                raise FixError(f"WordPress didn't update {name(match)}: it is still {match.get('version')}.")
            message = f"Updated {name(match)} from {match.get('version')} to {after.get('version') or 'the latest version'}"
        elif action == "remove_plugin":
            match = next((p for p in plugins if p["plugin"].split("/")[0] == item), None)
            if match is None:
                message = f"{item} is already gone"
            else:
                remove(match)
                message = f"Removed {name(match)}"
        else:
            inactive = [p for p in plugins if p.get("status") == "inactive"]
            for p in inactive:
                remove(p)
            message = f"Deleted {len(inactive)} inactive plugin(s)" + (f": {', '.join(map(name, inactive))}" if inactive else "")
        self.start_scan(slug)  # confirm the change; harmless if a scan is already running
        return message

    # ---- Phase 2: remediation approval queue (jp_seo_agent) ------------------
    def _remediation(self, slug):
        from jp_seo_agent.approvals import Queue, queue_path
        from jp_seo_agent.site import Site

        target = next((t for t in self.targets if t["slug"] == slug), None)
        if target is None:
            raise ValueError("Unknown site")
        cfg = target["checks"].get("compromise", {})
        wp_cfg = target["checks"].get("wordpress", {})
        auth = wp_credentials(wp_cfg) if wp_cfg.get("enabled") else None
        site = Site(target["url"], timeout=target.get("timeout", 20), pages=target.get("pages"), wp_auth=auth)
        queue = Queue(queue_path(cfg.get("queue_dir"), site.host), site.url)
        return site, queue, Path(cfg.get("backup_dir") or "backups") / site.host, cfg

    def remediation_list(self, slug, check=None):
        """Proposals for one check's page (check=None or "compromise": Spam & Compromise)."""
        from jp_seo_agent.approvals import scope

        from .fixes import needs_wordpress

        site, queue, _, _ = self._remediation(slug)
        wanted = check or "compromise"
        proposals = [{**p, "needs_wp": needs_wordpress(p) if p.get("check") else p["action"] != "manual"}
                     for p in queue.listing() if scope(p) == wanted]
        ids = {p["id"] for p in proposals}
        return {"proposals": proposals, "history": [h for h in queue.data["history"] if h["id"] in ids][-60:][::-1],
                "can_fix": bool(site.wp_auth and site.secure)}

    def remediation_decide(self, slug, ids, decision):
        """Approve (back up, apply, verify), reject or mark done (fixed by hand); approvals start a rescan."""
        from jp_seo_agent.remediate import RemediationError

        from .fixes import needs_wordpress

        site, queue, backups, cfg = self._remediation(slug)
        by = self.auth.get("name") or self.auth.get("email") or "dashboard"
        results = []
        for pid in [str(i) for i in (ids or [])][:50]:
            p = queue.load().proposals.get(pid)
            wp = p is not None and (needs_wordpress(p) if p.get("check") else p["action"] != "manual")
            if decision == "approve" and wp and not (site.wp_auth and site.secure):
                results.append({"id": pid, "status": "error", "error": "This fix needs the site's WordPress "
                                "application password (administrator) and an https:// address."})
                continue
            try:
                results.append(queue.decide(pid, decision, by, site, backups, cfg))
            except RemediationError as exc:
                results.append({"id": pid, "status": "error", "error": str(exc)})
        if decision == "approve" and any(r.get("status") == "applied" for r in results):
            self.start_scan(slug)
        return results

    def remediation_undo(self, slug, pid):
        from jp_seo_agent.remediate import RemediationError

        site, queue, backups, cfg = self._remediation(slug)
        by = self.auth.get("name") or self.auth.get("email") or "dashboard"
        try:
            return queue.undo(str(pid), by, site, backups, cfg)
        except RemediationError as exc:
            raise FixError(str(exc)) from exc

    # ---- Phase 3: autonomous defense (jp_seo_agent.defense, security_agent.guard) ------------
    def _monitor(self, slug):
        from jp_seo_agent.defense import IntegrityMonitor

        site, queue, backups, cfg = self._remediation(slug)
        return IntegrityMonitor(site, cfg, queue, backups,
                                out_dir=Path(self.config["report"]["output_dir"]) / "site_guard")

    def _guard(self, slug):
        from .guard import SecurityGuard

        target = next((t for t in self.targets if t["slug"] == slug), None)
        if target is None:
            raise ValueError("Unknown site")
        return SecurityGuard(target, self.config)

    def defense_status(self, slug, check=None):
        """The autonomous defense card: integrity monitor (Spam & Compromise page) or security monitor (any other
        check's page), with events and investigations for that check."""
        from jp_seo_agent.defense import settings as defense_settings

        monitor = self._monitor(slug)
        data = monitor.status()
        wanted = check or "compromise"
        opts = defense_settings(monitor.cfg)
        with self.lock:
            data["running"] = self.defense_running.get(slug)
        data["check"] = wanted
        data["monitor_active"] = self.defense_active
        data["alerts"] = webhook_status(self.config)["configured"]
        sec = monitor.state.data.get("security_check")
        data["security"] = {"interval_minutes": opts["security_interval_minutes"], "last_check": sec,
                            "next_check": (datetime.fromisoformat(sec["time"]) + timedelta(
                                minutes=opts["security_interval_minutes"])).isoformat() if sec else None}
        last = (data.get("last_check") or {}).get("time")
        if data["enabled"] and data["can_watch"] and last:
            data["next_check"] = (datetime.fromisoformat(last) + timedelta(minutes=data["interval_minutes"])).isoformat()
        mine = lambda e: (e.get("check") or "compromise") == wanted or (e.get("type") in ("setting",))
        data["events"] = [e for e in data["events"] if mine(e) or (wanted == "compromise" and not e.get("check"))]
        data["investigations"] = [i for i in data["investigations"]
                                  if wanted in (i.get("checks") or ["compromise"])]
        data["blocked"] = {k: v for k, v in data["blocked"].items()
                           if (monitor.queue.proposals.get(v.get("proposal")) or {}).get("check", "compromise") == wanted}
        root = Path(self.config["report"]["output_dir"]).resolve()
        for inv in data["investigations"]:   # links the dashboard can open through /files/
            inv["links"] = {}
            for f in inv.get("files") or []:
                try:
                    inv["links"][Path(f).suffix[1:]] = "/files/" + Path(f).resolve().relative_to(root).as_posix()
                except ValueError:
                    pass
        return data

    def _defense_job(self, slug, what, job):
        """Run a defense job for one site in the background; one job per site at a time."""
        with self.lock:
            if self.defense_running.get(slug):
                return False
            self.defense_running[slug] = what

        def run():
            try:
                events = job()
                if events:
                    target = next((t for t in self.targets if t["slug"] == slug), None)
                    if target:
                        send_defense_alert(self.config, target, events)
                    if any(e.get("type") == "recovered" for e in events):
                        self.start_scan(slug)   # refresh the dashboard's findings after an automatic fix
            except Exception:
                log.exception("Autonomous defense job %s failed for %s", what, slug)
            finally:
                with self.lock:
                    self.defense_running.pop(slug, None)

        threading.Thread(target=run, daemon=True).start()
        return True

    def defense_check(self, slug, check=None):
        """Check now: the integrity monitor on the Spam & Compromise page, the security monitor elsewhere."""
        if check and check != "compromise":
            guard = self._guard(slug)
            return self._defense_job(slug, "check", lambda: guard.cycle(self._monitor_run))
        monitor = self._monitor(slug)
        if not monitor.site.wp_auth:
            raise ValueError("The integrity monitor needs the site's WordPress application password")

        def job():
            monitor.check(wait=True)
            return monitor.new_events
        return self._defense_job(slug, "check", job)

    def _monitor_run(self, target, checks):
        return self.agent.monitor_checks(target, checks)

    def defense_investigate(self, slug, check=None):
        if check and check != "compromise":
            guard = self._guard(slug)

            def job():
                with guard.monitor.lock:
                    guard.monitor.state.load()
                    guard.queue.load()
                    guard.current = guard.monitor.state.data.get("security_snapshot") or {}
                    pids = [p["id"] for p in guard.queue.proposals.values()
                            if p.get("check") == check and (p["status"] in ("pending", "failed") or p.get("reinfection"))]
                    guard.monitor.new_events = []
                    guard.monitor._investigate(pids, None, "requested", force=True)
                    guard.monitor.state.save()
                return []
            return self._defense_job(slug, "investigation", job)
        monitor = self._monitor(slug)

        def job():
            monitor.investigate_now()
            return []
        return self._defense_job(slug, "investigation", job)

    def defense_trust(self, slug):
        by = self.auth.get("name") or self.auth.get("email") or "dashboard"
        return self._monitor(slug).trust_baseline(by)

    def defense_auto(self, slug, enabled):
        by = self.auth.get("name") or self.auth.get("email") or "dashboard"
        self._monitor(slug).set_auto(bool(enabled), by)

    def defense_unblock(self, slug, subj):
        by = self.auth.get("name") or self.auth.get("email") or "dashboard"
        self._monitor(slug).unblock(str(subj or ""), by)

    def run_defense_forever(self, first_delay=120):
        """Autonomous defense loop, never while a full scan is running (the scan covers the same ground):
        the integrity monitor for each WordPress site every defense.watch_interval_minutes, and the security
        monitor for every site every defense.security_interval_minutes."""
        from jp_seo_agent.defense import settings as defense_settings

        self.defense_active = True
        time.sleep(first_delay)
        due = lambda last, minutes: not last or datetime.now(timezone.utc) - datetime.fromisoformat(last) >= \
            timedelta(minutes=max(5, float(minutes)))
        while True:
            for target in list(self.targets):
                cfg = target["checks"].get("compromise", {})
                opts = defense_settings(cfg)
                if not opts["enabled"] or self.snapshot_status()["running"]:
                    continue
                slug = target["slug"]
                try:
                    monitor = self._monitor(slug)
                    data = monitor.state.data
                    if monitor.site.wp_auth and cfg.get("enabled", True) and \
                            due((data.get("last_check") or {}).get("time"), opts["watch_interval_minutes"]):
                        self._defense_job(slug, "check", lambda m=monitor: (m.check(), m.new_events)[1])
                    elif due((data.get("security_check") or {}).get("time"), opts["security_interval_minutes"]):
                        guard = self._guard(slug)
                        self._defense_job(slug, "check", lambda g=guard: g.cycle(self._monitor_run))
                except Exception:
                    log.exception("Autonomous defense failed for %s", slug)
            time.sleep(60)

    # ---- scans ------------------------------------------------------------
    def start_scan(self, slug=None, scheduled=False):
        targets = [t for t in self.targets if slug in (None, t["slug"])]
        if not targets:
            return False, "no sites to scan"
        with self.lock:
            if self.status["running"]:
                return False, "a scan is already running"
            self.status.update(running=True, site=slug, error=None, done=0, total=len(targets),
                               started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
        threading.Thread(target=self._scan, args=(targets, scheduled), daemon=True).start()
        return True, "started"

    def _scan(self, targets, scheduled=False):
        error = None
        def scan_one(target):
            self.agent._safe_scan(target)  # never raises; a failed scan is recorded as a finding
            with self.lock:
                self.status["done"] += 1

        try:
            workers = max(1, min(len(targets), int(self.config["report"].get("max_parallel_sites", 2))))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(scan_one, targets))
            write_dashboard(self.config, self.targets)
            if scheduled:  # the daily scan: send the one Teams card with every site's high-risk issues
                send_daily_card(self.config, self.targets)
        except Exception as exc:  # surface to the UI instead of killing the thread silently
            log.exception("Dashboard-triggered scan failed")
            error = f"{exc.__class__.__name__}: {exc}"
        with self.lock:
            self.status.update(running=False, error=error, finished_at=datetime.now(timezone.utc).isoformat())

    def snapshot_status(self):
        with self.lock:
            return dict(self.status)

    # ---- HTTP -------------------------------------------------------------
    def _handler(self):
        server = self
        allowed_hosts = {
            f"127.0.0.1:{self.port}",
            f"localhost:{self.port}",
            f"{self.host}:{self.port}",
            # the live dashboard, reached through the reverse proxy
            "securityagent.kleza.io",
            f"securityagent.kleza.io:{self.port}",
        }
        reports_root = Path(self.config["report"]["output_dir"]).resolve()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                log.debug(fmt, *args)

            def _send(self, code, body, content_type="application/json", filename=None):
                data = body.encode("utf-8") if isinstance(body, str) else body
                self.send_response(code)
                self.send_header("Content-Type", content_type + ("" if content_type == XLSX_TYPE else "; charset=utf-8"))
                if filename:
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()
                self.wfile.write(data)

            def _json(self, code, obj):
                self._send(code, json.dumps(obj, default=str))

            def _host_ok(self):
                # Blocks DNS rebinding: only answer requests addressed to this local server
                return self.headers.get("Host", "") in allowed_hosts

            def _authed(self):
                if not server.auth_required():
                    return True
                cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
                morsel = cookie.get("secmon_session")
                with server.lock:
                    return bool(morsel and morsel.value in server.sessions)

            def _login_page(self, error=False):
                self._send(401 if error else 200, LOGIN_TEMPLATE, "text/html")

            def _serve_report_file(self, rel):
                target = (reports_root / unquote(rel)).resolve()
                if reports_root not in target.parents or target.suffix not in SERVED_SUFFIXES:
                    return self._json(404, {"error": "not found"})
                if target.suffix == ".xlsx":
                    # Scans from before Excel export have no .xlsx yet: build it from the matching .json report
                    source = target.with_suffix(".json")
                    if target.is_file():
                        body = target.read_bytes()
                    elif source.is_file() and (report := _read_json(source)):
                        body = to_xlsx(report)
                    else:
                        return self._json(404, {"error": "not found"})
                    site = target.parent.name if target.stem == "latest" else target.parent.parent.name
                    return self._send(200, body, XLSX_TYPE, filename=f"security-report-{site}.xlsx")
                if not target.is_file():
                    return self._json(404, {"error": "not found"})
                self._send(200, target.read_bytes(), SERVED_SUFFIXES[target.suffix])

            def do_GET(self):
                if not self._host_ok():
                    return self._json(403, {"error": "forbidden host"})
                path = self.path.split("?", 1)[0]
                if path == "/login":
                    return self._login_page()
                if not self._authed():
                    # Unauthenticated: show the login page for the app, 401 for data/file requests
                    return self._login_page() if path in ("/", "/index.html") else self._json(401, {"error": "login required"})
                data = lambda: collect_data(server.config, server.targets, True, server.snapshot_status())
                if path in ("/", "/index.html"):
                    self._send(200, render(data()), "text/html")
                elif path == "/api/data":
                    self._json(200, data())
                elif path == "/api/status":
                    self._json(200, server.snapshot_status())
                elif path in ("/api/remediation", "/api/defense"):
                    query = parse_qs(urlparse(self.path).query)
                    site, check = (query.get("site") or [""])[0], (query.get("check") or [None])[0]
                    try:
                        self._json(200, server.remediation_list(site, check) if path == "/api/remediation"
                                   else server.defense_status(site, check))
                    except ValueError as exc:
                        self._json(400, {"ok": False, "message": str(exc)})
                elif path.startswith("/files/"):
                    self._serve_report_file(path[len("/files/"):])
                else:
                    self._json(404, {"error": "not found"})

            def do_POST(self):
                # The custom header forces a CORS preflight, which is never granted, so other sites can't call this API
                if not self._host_ok() or self.headers.get("X-Dashboard") != "1":
                    return self._json(403, {"error": "forbidden"})
                length = min(int(self.headers.get("Content-Length") or 0), 16384)
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                    if not isinstance(body, dict):
                        raise ValueError
                except ValueError:
                    return self._json(400, {"ok": False, "message": "invalid JSON"})
                path = self.path.split("?", 1)[0]
                if path == "/api/login":
                    if server.check_login(body.get("email"), body.get("password")):
                        token = server.new_session()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Set-Cookie", f"secmon_session={token}; HttpOnly; SameSite=Strict; Path=/")
                        self.send_header("Cache-Control", "no-store")
                        payload = json.dumps({"ok": True}).encode()
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        return self.wfile.write(payload)
                    return self._json(401, {"ok": False, "message": "Wrong email or password"})
                if path == "/api/logout":
                    cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
                    morsel = cookie.get("secmon_session")
                    with server.lock:
                        server.sessions.discard(morsel.value if morsel else None)
                    return self._json(200, {"ok": True})
                if not self._authed():
                    return self._json(401, {"ok": False, "message": "login required"})
                try:
                    if path == "/api/scan":
                        ok, message = server.start_scan(body.get("site") or None)
                        return self._json(202 if ok else 409, {"ok": ok, "message": message})
                    if path == "/api/sites":
                        pages = body.get("pages") or []
                        if isinstance(pages, str):
                            pages = pages.split(",")
                        ssh = body.get("ssh") if isinstance(body.get("ssh"), dict) else None
                        slug = server.add_site(body.get("url"), body.get("name"), pages,
                                               body.get("wp_username"), body.get("wp_password"), ssh)
                        scan = server.start_scan(slug) if body.get("scan") else (False, "not requested")
                        return self._json(201, {"ok": True, "slug": slug, "scan_started": scan[0]})
                    if path == "/api/sites/credentials/get":
                        return self._json(200, {"ok": True, **server.get_credentials(body.get("slug"))})
                    if path == "/api/sites/credentials":
                        ssh = body.get("ssh") if isinstance(body.get("ssh"), dict) else None
                        server.update_credentials(body.get("slug"), body.get("wp_username"), body.get("wp_password"), ssh)
                        scan = server.start_scan(body.get("slug")) if body.get("scan") else (False, "not requested")
                        return self._json(200, {"ok": True, "scan_started": scan[0]})
                    if path == "/api/ssh/keygen":
                        key_id, public = server.generate_ssh_key()
                        return self._json(200, {"ok": True, "key_id": key_id, "public_key": public})
                    if path == "/api/sites/delete":
                        server.remove_site(body.get("slug"))
                        return self._json(200, {"ok": True})
                    if path == "/api/ignore":
                        ignored = server.set_ignored(body.get("site"), body.get("title"), body.get("check"), body.get("severity"),
                                                     body.get("key"), body.get("ignore", True) is not False)
                        return self._json(200, {"ok": True, "ignored": ignored})
                    if path == "/api/remediation/decide":
                        results = server.remediation_decide(body.get("site"), body.get("ids"), body.get("decision"))
                        return self._json(200, {"ok": True, "results": results})
                    if path == "/api/remediation/undo":
                        try:
                            p = server.remediation_undo(body.get("site"), body.get("id"))
                        except FixError as exc:
                            return self._json(502, {"ok": False, "message": str(exc)})
                        return self._json(200, {"ok": True, "proposal": p})
                    if path in ("/api/defense/check", "/api/defense/investigate"):
                        run = server.defense_check if path.endswith("check") else server.defense_investigate
                        started = run(body.get("site"), body.get("check"))
                        return self._json(202 if started else 409, {"ok": started, "message": "started" if started
                                                                    else "Something is already running for this site"})
                    if path == "/api/defense/trust":
                        try:
                            files = server.defense_trust(body.get("site"))
                        except ValueError as exc:
                            return self._json(502, {"ok": False, "message": str(exc)})
                        return self._json(200, {"ok": True, "files": files})
                    if path == "/api/defense/auto":
                        server.defense_auto(body.get("site"), body.get("enabled") is True)
                        return self._json(200, {"ok": True})
                    if path == "/api/defense/unblock":
                        server.defense_unblock(body.get("site"), body.get("subject"))
                        return self._json(200, {"ok": True})
                    if path == "/api/wp-fix":
                        try:
                            message = server.fix_wordpress(body.get("site"), body.get("action"), body.get("item"))
                        except FixError as exc:
                            return self._json(502, {"ok": False, "message": str(exc)})
                        return self._json(200, {"ok": True, "message": message})
                    if path == "/api/teams":
                        save_webhook(server.config, body.get("webhook_url"))
                        return self._json(200, {"ok": True, "teams": webhook_status(server.config)})
                    if path == "/api/teams/test":
                        ok, message = send_daily_card(server.config, server.targets, test=True)
                        return self._json(200 if ok else 502, {"ok": ok, "message": message})
                except ValueError as exc:
                    return self._json(400, {"ok": False, "message": str(exc)})
                self._json(404, {"error": "not found"})

        return Handler

    def serve_forever(self, open_browser=True):
        httpd = ThreadingHTTPServer((self.host, self.port), self._handler())
        url = f"http://{self.host}:{self.port}/"
        print(f"Dashboard running at {url}  (Ctrl+C to stop)", flush=True)
        if open_browser:
            webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
