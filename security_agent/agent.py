"""Orchestrates checks for one or more sites, persists per-site state, and writes reports."""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests

from .checks import ALL_CHECKS
from .checks.wordpress import credentials as wp_credentials
from .dashboard import write_dashboard
from .http_client import SiteContext
from .models import Finding, Severity as S
from .report import build_report, console_summary, write_reports, write_summary
from .schedule import next_daily_run

log = logging.getLogger("security_agent")


class SecurityMonitoringAgent:
    def __init__(self, config, targets, only_checks=None):
        self.config = config
        self.targets = targets
        self.only = set(only_checks or [])
        self.output_dir = Path(config["report"]["output_dir"])
        self.state_dir = Path(config["report"].get("state_dir", "state"))

    # ---- per-site state -------------------------------------------------
    def _state_path(self, target):
        return self.state_dir / f"{target['slug']}.json"

    def load_state(self, target):
        path = self._state_path(target)
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                log.warning("[%s] State file unreadable; starting with a fresh baseline", target["name"])
        return {}

    def save_state(self, target, state):
        path = self._state_path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    def accept_changes(self):
        """Approve each site's current content as its new change-detection baseline."""
        for target in self.targets:
            state = self.load_state(target)
            state.pop("changes", None)
            self.save_state(target, state)

    # ---- scanning -------------------------------------------------------
    def scan_site(self, target):
        started = datetime.now(timezone.utc)
        ctx = SiteContext(target["url"], timeout=target.get("timeout", 15), user_agent=target.get("user_agent", ""),
                          domain=target.get("domain"), pages=target.get("pages"))
        wp_cfg = target["checks"].get("wordpress", {})
        ctx.wp_auth = wp_credentials(wp_cfg) if wp_cfg.get("enabled") else None
        state = self.load_state(target)
        findings, durations = [], {}

        try:
            resp, _ = ctx.home
            log.info("[%s] Fetched %s -> HTTP %s", target["name"], resp.url, resp.status_code)
            if resp.status_code >= 500:
                findings.append(Finding("availability", f"Website returns HTTP {resp.status_code}", S.HIGH, resp.url,
                                        "Investigate server errors."))
        except requests.RequestException as exc:
            findings.append(Finding("availability", "Website unreachable", S.CRITICAL, str(exc)[:300],
                                    "Check hosting, DNS and TLS configuration."))

        for name, module in ALL_CHECKS.items():
            check_cfg = target["checks"].get(name, {})
            if not check_cfg.get("enabled", True) or (self.only and name not in self.only):
                continue
            log.info("[%s] Running check: %s", target["name"], name)
            t0 = time.monotonic()
            try:
                findings.extend(module.run(ctx, check_cfg, state))
            except Exception as exc:  # one failing check must not stop the scan
                log.exception("[%s] Check %s failed", target["name"], name)
                findings.append(Finding(name, f"Check '{name}' could not complete", S.INFO,
                                        f"{exc.__class__.__name__}: {exc}"[:300]))
            durations[name] = time.monotonic() - t0

        self.save_state(target, state)
        report = build_report(ctx.url, findings, started, datetime.now(timezone.utc), durations)
        report["site"] = target["name"]
        report["report_files"] = [str(p) for p in write_reports(
            report, self.output_dir / target["slug"], started.strftime("%Y%m%d-%H%M%S"))]
        return report

    def _safe_scan(self, target):
        try:
            return self.scan_site(target)
        except Exception as exc:
            log.exception("[%s] Scan failed", target["name"])
            now = datetime.now(timezone.utc)
            report = build_report(target["url"], [Finding("agent", "Scan failed", S.HIGH, repr(exc)[:300])], now, now, {})
            report["site"] = target["name"]
            report["report_files"] = []
            return report

    def run_once(self):
        workers = max(1, min(len(self.targets), int(self.config["report"].get("max_parallel_sites", 2))))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            reports = list(pool.map(self._safe_scan, self.targets))
        for report in reports:
            print(f"\n=== {report['site']} ({report['target']}) ===")
            print(console_summary(report))
            if report["report_files"]:
                print(f"\nReport: {report['report_files'][1]}")
        if len(reports) > 1:
            summary_path = write_summary(reports, self.output_dir)
            print(f"\nCombined summary for {len(reports)} sites: {summary_path}")
        print(f"Dashboard: {write_dashboard(self.config, self.targets)}")
        return reports

    def run_daily(self, at, job=None):
        """Run `job` (default: a scan of every site) each day at local time `at` ("HH:MM")."""
        job = job or self.run_once
        while True:
            target = next_daily_run(at)
            log.info("Next scheduled scan: %s", target.strftime("%Y-%m-%d %H:%M"))
            # Short sleeps against the wall clock, so a PC waking from sleep after the target time still runs the scan
            while (remaining := (target - datetime.now()).total_seconds()) > 0:
                time.sleep(min(remaining, 60))
            try:
                job()
            except Exception:
                log.exception("Scheduled scan failed")

    def run_forever(self, interval_minutes):
        log.info("Monitoring %d site(s) every %s minute(s). Ctrl+C to stop.", len(self.targets), interval_minutes)
        while True:
            try:
                self.run_once()
            except Exception:
                log.exception("Scan round failed")
            time.sleep(max(1, interval_minutes) * 60)
