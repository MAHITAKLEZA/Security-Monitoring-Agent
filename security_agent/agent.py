"""Orchestrates checks for one or more sites, persists per-site state, and writes reports."""

import copy
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests

from .checks import ALL_CHECKS, ssh_inside
from .checks.wordpress import credentials as wp_credentials
from .checks.ssl_check import RETRY_DELAYS
from .dashboard import write_dashboard
from .guard import SecurityGuard
from .http_client import SiteContext
from .models import Finding, Severity as S
from .notify import send_urgent_alert, urgent_from_scan
from .report import build_report, console_summary, write_reports, write_summary
from .schedule import next_daily_run

log = logging.getLogger("security_agent")
CURRENT = None   # the agent of this process, for fixes that run a check again to verify themselves
# A problem that came back (and is waiting for approval, or keeps coming back) is already in the report as itself,
# so it gets no extra finding with a label
GUARD_TITLES = {"recovered": "Fixed again automatically", "recovery_failed": "Automatic fix failed"}


def make_ctx(target):
    ctx = SiteContext(target["url"], timeout=target.get("timeout", 15), user_agent=target.get("user_agent", ""),
                      domain=target.get("domain"), pages=target.get("pages"))
    wp_cfg = target["checks"].get("wordpress", {})
    ctx.wp_auth = wp_credentials(wp_cfg) if wp_cfg.get("enabled") else None
    return ctx


def run_checks_once(target, checks):
    """(findings, completed) of a fresh run of some checks, without changing the saved state."""
    agent = CURRENT or SecurityMonitoringAgent(load_config_default(), [target])
    findings, completed, _, _ = agent.monitor_checks(target, checks)
    return findings, completed


def load_config_default():
    from .config import load_config
    return load_config("config.yaml")


def state_path_for(target):
    agent = CURRENT or SecurityMonitoringAgent(load_config_default(), [target])
    return agent._state_path(target)


def guard_findings(events):
    """Findings in the report for what autonomous defense did with the security checks during this scan."""
    out = []
    for e in events:
        if e.get("type") in GUARD_TITLES and e.get("check") and e["check"] != "compromise":
            out.append(Finding(e["check"], f"{GUARD_TITLES[e['type']]}: {e['title'].split(': ', 1)[-1]}",
                               S.parse(e.get("severity") or "MEDIUM"), e.get("detail", ""),
                               "See Autonomous defense and Remediation on this check's page.",
                               {"event": e.get("id"), "proposal": e.get("proposal")}))
    return out


class SecurityMonitoringAgent:
    def __init__(self, config, targets, only_checks=None):
        global CURRENT
        CURRENT = self
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
    def run_checks(self, target, state, checks=None):
        """Run the enabled checks (all, or only `checks`) for one site against `state`.
        Returns (findings, durations, completed check names, ctx)."""
        global CURRENT
        CURRENT = self
        ctx = make_ctx(target)
        findings, durations, completed = [], {}, ["availability"]
        # A timeout, dropped connection or 5xx is tried again before it counts: one network blip is not an outage
        unreachable = None
        for attempt, delay in enumerate((*RETRY_DELAYS, None)):
            try:
                resp, _ = ctx.home
            except requests.RequestException as exc:
                if delay is None:
                    unreachable = Finding("availability", "Website unreachable", S.CRITICAL,
                                          f"Failed {attempt + 1} times: {exc.__class__.__name__}: {exc}"[:300],
                                          "Check hosting, DNS and TLS configuration.")
                    findings.append(unreachable)
                    break
            else:
                if resp.status_code < 500 or delay is None:
                    log.info("[%s] Fetched %s -> HTTP %s", target["name"], resp.url, resp.status_code)
                    if resp.status_code >= 500:
                        findings.append(Finding("availability", f"Website returns HTTP {resp.status_code}", S.HIGH,
                                                f"{resp.url} ({attempt + 1} attempts)", "Investigate server errors."))
                    break
                ctx.forget(ctx.home_path)
            log.info("[%s] Home page failed (attempt %d), trying again in %ss", target["name"], attempt + 1, delay)
            time.sleep(delay)

        for name, module in ALL_CHECKS.items():
            if ssh_inside.CANCEL.is_set():
                raise ssh_inside.ScanStopped()
            check_cfg = target["checks"].get(name, {})
            if not check_cfg.get("enabled", True) or (self.only and name not in self.only) \
                    or (checks is not None and name not in checks):
                continue
            log.info("[%s] Running check: %s", target["name"], name)
            t0 = time.monotonic()
            try:
                findings.extend(module.run(ctx, check_cfg, state))
                completed.append(name)
            except ssh_inside.ScanStopped:   # the Stop button, not a failure
                raise
            except Exception as exc:  # one failing check must not stop the scan
                log.exception("[%s] Check %s failed", target["name"], name)
                findings.append(Finding(name, f"Check '{name}' could not complete", S.INFO,
                                        f"{exc.__class__.__name__}: {exc}"[:300]))
            durations[name] = time.monotonic() - t0
        if unreachable:   # the TLS failure is the same outage, not a second problem
            tls = [f for f in findings if f.check == "ssl" and f.title == "TLS connection failed"]
            findings = [f for f in findings if f not in tls]
            if tls:
                unreachable.detail = f"{unreachable.detail}; TLS: {tls[0].detail}"[:400]
        return findings, durations, completed, ctx

    def monitor_checks(self, target, checks):
        """Run checks for the security monitor or to verify a fix: the saved state is used but never changed."""
        state = copy.deepcopy(self.load_state(target))
        findings, _, completed, ctx = self.run_checks(target, state, checks)
        return findings, completed, ctx, state

    def scan_site(self, target):
        started = datetime.now(timezone.utc)
        state = self.load_state(target)
        findings, durations, completed, ctx = self.run_checks(target, state)
        self.save_state(target, state)
        # Phase 2 and 3 for the security checks: every problem in the approval queue, regressions, recovery
        try:
            events = SecurityGuard(target, self.config).process(findings, completed, ctx, state, source="scan")
            findings += guard_findings(events)
        except Exception as exc:
            log.exception("[%s] Autonomous defense step failed", target["name"])
            findings.append(Finding("agent", "Autonomous defense step could not complete", S.INFO,
                                    f"{exc.__class__.__name__}: {exc}"[:300]))
        report = build_report(ctx.url, findings, started, datetime.now(timezone.utc), durations)
        report["site"] = target["name"]
        try:
            previous = json.loads((self.output_dir / target["slug"] / "latest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            previous = None
        report["report_files"] = [str(p) for p in write_reports(
            report, self.output_dir / target["slug"], started.strftime("%Y%m%d-%H%M%S"))]
        # Anything urgent goes to Teams now, not at the daily card
        try:
            send_urgent_alert(self.config, target, urgent_from_scan(self.config, target, report, previous, started))
        except Exception:
            log.exception("[%s] Urgent alert failed", target["name"])
        return report

    def _safe_scan(self, target):
        try:
            return self.scan_site(target)
        except ssh_inside.ScanStopped:   # stopped from the dashboard: nothing is saved
            log.info("[%s] Scan stopped", target["name"])
            now = datetime.now(timezone.utc)
            report = build_report(target["url"], [], now, now, {})
            report["site"], report["report_files"] = target["name"], []
            return report
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

    def run_daily(self, at, job=None, tz=None):
        """Run `job` (default: a scan of every site) each day at `at` ("HH:MM") in `tz` (default: local time)."""
        job = job or self.run_once
        while True:
            target = next_daily_run(at, tz=tz)
            log.info("Next scheduled scan: %s", target.strftime("%Y-%m-%d %H:%M"))
            # Short sleeps against the wall clock, so a PC waking from sleep after the target time still runs the scan
            while (remaining := (target - datetime.now(tz)).total_seconds()) > 0:
                time.sleep(min(remaining, 60))
            try:
                job()
            except Exception:
                log.exception("Scheduled scan failed")

    def run_interval(self, interval_minutes, job, wait_first=False):
        """Run `job` now (unless wait_first) and then every `interval_minutes` (the dashboard's scan, so scans never
        overlap)."""
        if wait_first:
            time.sleep(max(1, interval_minutes) * 60)
        while True:
            try:
                job()
            except Exception:
                log.exception("Scheduled scan failed")
            time.sleep(max(1, interval_minutes) * 60)

    def run_forever(self, interval_minutes):
        log.info("Monitoring %d site(s) every %s minute(s). Ctrl+C to stop.", len(self.targets), interval_minutes)
        while True:
            try:
                self.run_once()
            except Exception:
                log.exception("Scan round failed")
            time.sleep(max(1, interval_minutes) * 60)
