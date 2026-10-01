import argparse
import logging
import sys
import threading
import webbrowser

from .agent import SecurityMonitoringAgent
from .checks import ALL_CHECKS
from .config import load_config, resolve_targets
from .dashboard import DashboardServer, write_dashboard
from .models import Severity
from .schedule import next_daily_run, parse_daily_at, schedule_tz


def main(argv=None):
    parser = argparse.ArgumentParser(prog="security_agent", description="Website Security Monitoring Agent")
    parser.add_argument("-c", "--config", default="config.yaml", help="path to config YAML (default: config.yaml)")
    parser.add_argument("--url", action="append", help="site URL to scan instead of the configured ones (repeatable)")
    parser.add_argument("--site", action="append", help="only scan configured site(s) with this name/host (repeatable)")
    parser.add_argument("--list-sites", action="store_true", help="list configured sites and exit")
    parser.add_argument("--checks", help=f"comma-separated subset of checks: {','.join(ALL_CHECKS)}")
    parser.add_argument("--loop", action="store_true", help="run continuously using schedule.interval_minutes")
    parser.add_argument("--interval", type=float, help="minutes between scans in --loop mode")
    parser.add_argument("--accept-changes", action="store_true",
                        help="approve the current content of the selected sites as the new baseline and exit")
    parser.add_argument("--dashboard", action="store_true",
                        help="regenerate reports/dashboard.html from existing reports (no scan) and open it")
    parser.add_argument("--serve", action="store_true",
                        help="serve the interactive dashboard on localhost; scans every site daily at schedule.daily_at "
                             "(use --loop to scan every interval_minutes instead)")
    parser.add_argument("--port", type=int, default=8765, help="dashboard port for --serve (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="don't open a browser for --dashboard/--serve")
    parser.add_argument("--fail-on", help="exit code 2 if worst finding on any site >= this severity (INFO..CRITICAL)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    config = load_config(args.config)
    try:
        targets = resolve_targets(config, args.url)
    except ValueError as exc:
        parser.error(str(exc))
    if not targets and not (args.serve or args.dashboard):
        parser.error("No sites configured: add entries under `targets:` in config.yaml, use Add Link in the dashboard, or pass --url")
    if args.site:
        wanted = {s.lower() for s in args.site}
        targets = [t for t in targets if {t["name"].lower(), t["slug"], t["url"].lower()} & wanted
                   or any(w in t["url"].lower() for w in wanted)]
        if not targets:
            parser.error(f"no configured site matches: {', '.join(args.site)}")
    if args.list_sites:
        for t in targets:
            print(f"{t['name']:<25} {t['url']:<40} pages={','.join(t['pages'])}")
        return 0

    only = [c.strip() for c in args.checks.split(",")] if args.checks else None
    unknown = set(only or []) - set(ALL_CHECKS)
    if unknown:
        parser.error(f"unknown check(s): {', '.join(sorted(unknown))}")

    agent = SecurityMonitoringAgent(config, targets, only)
    if args.accept_changes:
        agent.accept_changes()
        print(f"Baseline cleared for {len(targets)} site(s); the next scan records current content as approved.")
        return 0
    interval = args.interval or config["schedule"]["interval_minutes"]
    if args.loop:  # lets the dashboard show the schedule and next scan time
        config["schedule"].update(interval_minutes=interval, active=True, mode="interval")
    daily_at = config["schedule"].get("daily_at")
    if daily_at:
        try:
            parse_daily_at(daily_at)
        except ValueError as exc:
            parser.error(str(exc))
    if args.dashboard:
        path = write_dashboard(config, targets)
        print(f"Dashboard written: {path}")
        if not args.no_browser:
            webbrowser.open(path.resolve().as_uri())
        return 0
    if args.serve:
        server = DashboardServer(agent, config, targets, port=args.port)
        if args.loop:
            threading.Thread(target=agent.run_forever, args=(interval,), daemon=True).start()
        elif daily_at:
            config["schedule"].update(active=True, mode="daily")
            # Runs through the server so the dashboard shows progress and never overlaps a scan started from the page
            tz = schedule_tz(config["schedule"].get("timezone"))
            # scheduled=True: the Teams card is sent once this daily scan finishes
            threading.Thread(target=agent.run_daily,
                             args=(daily_at, lambda: server.start_scan(None, scheduled=True), tz), daemon=True).start()
            zone = config["schedule"].get("timezone") or "local time"
            print(f"Scanning all sites daily at {daily_at} {zone} "
                  f"(next: {next_daily_run(daily_at, tz=tz):%Y-%m-%d %H:%M})", flush=True)
        server.serve_forever(open_browser=not args.no_browser)
        return 0
    if args.loop:
        agent.run_forever(interval)
        return 0

    reports = agent.run_once()
    fail_on = Severity.parse(args.fail_on or config["report"]["fail_on"])
    worst = max(Severity[r["worst_severity"]] for r in reports)
    return 2 if worst >= fail_on else 0


if __name__ == "__main__":
    sys.exit(main())
