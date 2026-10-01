"""Interactive dashboard: a self-contained HTML file generated from the reports, plus an optional
local server (127.0.0.1 only) that adds on-demand scans, adding/removing sites and live refresh."""

import http.cookies
import json
import logging
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .config import _slug, load_managed_sites, resolve_targets, save_managed_sites
from .excel import to_xlsx
from .notify import save_webhook, send_daily_card, webhook_status
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


def collect_data(config, targets, server=False, scan_status=None):
    out = Path(config["report"]["output_dir"])
    sites = []
    for t in targets:
        site_dir = out / t["slug"]
        sites.append({
            "name": t["name"],
            "slug": t["slug"],
            "url": t["url"],
            "pages": t.get("pages", ["/"]),
            "managed": t.get("managed", False),
            "latest": _read_json(site_dir / "latest.json"),
            "history": _read_history(site_dir / "history.jsonl"),
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


class DashboardServer:
    """Serves the dashboard on localhost, runs scans on request and manages dashboard-added sites."""

    def __init__(self, agent, config, targets, host="127.0.0.1", port=8765):
        self.agent, self.config, self.targets = agent, config, targets
        self.host, self.port = host, port
        self.lock = threading.Lock()
        self.status = {"running": False, "site": None, "started_at": None, "finished_at": None, "error": None}
        self.sessions = set()  # active login session tokens (in memory; cleared on restart)

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

    def add_site(self, url, name=None, pages=None, wp_username=None, wp_password=None):
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
        allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"{self.host}:{self.port}"}
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
                        slug = server.add_site(body.get("url"), body.get("name"), pages,
                                               body.get("wp_username"), body.get("wp_password"))
                        scan = server.start_scan(slug) if body.get("scan") else (False, "not requested")
                        return self._json(201, {"ok": True, "slug": slug, "scan_started": scan[0]})
                    if path == "/api/sites/delete":
                        server.remove_site(body.get("slug"))
                        return self._json(200, {"ok": True})
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
