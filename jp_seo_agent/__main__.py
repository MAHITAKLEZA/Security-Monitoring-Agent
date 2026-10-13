import argparse
import logging
import os
import sys
import time
from pathlib import Path

from .agent import SiteGuardAgent
from .approvals import Queue, queue_path
from .defense import IntegrityMonitor
from .remediate import RemediationError
from .site import Site, rank


def _credentials(args):
    """(username, application password) from --wp-credentials-file (username=/password= lines) or env vars."""
    user, password = args.wp_user or os.environ.get("WP_USERNAME", ""), os.environ.get(args.wp_password_env, "")
    if args.wp_credentials_file:
        for line in Path(args.wp_credentials_file).read_text(encoding="utf-8-sig").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                key = key.strip().lower()
                if key in ("username", "user"):
                    user = value.strip().strip("\"'")
                elif key in ("password", "app_password"):
                    password = value.strip().strip("\"'")
    return (user, password) if user and password else None


def _show(p):
    extra = ""
    if p["status"] == "applied":
        extra = f" | {'verified' if p.get('verified') else 'NOT verified'}: {p.get('verification', '')}"
    elif p["status"] == "failed":
        extra = f" | {p.get('error', '')}"
    print(f"  {p['id']}  {p['status']:<9} {p['action']:<19} risk={p['risk']:<6} {p['target'][:70]}{extra}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="jp_seo_agent", description="AI Website Security & Auto-Remediation Agent: "
                                     "SEO spam, redirects, hidden pages and infected files")
    sub = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("url")
    common.add_argument("--wp-user", help="WordPress username (or WP_USERNAME)")
    common.add_argument("--wp-password-env", default="WP_APP_PASSWORD", help="env var holding the application password")
    common.add_argument("--wp-credentials-file", help="file with username=... and password=... lines")
    common.add_argument("--queue-dir", default="state/remediation", help="approval queue folder (default state/remediation)")
    common.add_argument("--backup-dir", default="backups", help="local backups of changed items (default backups)")
    common.add_argument("--timeout", type=float, default=20)
    common.add_argument("-v", "--verbose", action="store_true")

    scan_p = sub.add_parser("scan", parents=[common], help="Phase 1 report, plus Phase 2 proposals in the queue")
    scan_p.add_argument("--page", action="append", help="extra start page path (repeatable, default /)")
    scan_p.add_argument("--site-language", help="site language, e.g. ja (default: from <html lang>)")
    scan_p.add_argument("--allow-path", action="append", help="path prefix where Japanese content is expected")
    scan_p.add_argument("--allow-category", action="append", choices=["japanese", "pharma", "gambling", "adult", "scam"],
                        help="spam family that is legitimate on this site, e.g. gambling for a casino (repeatable)")
    scan_p.add_argument("--max-pages", type=int, default=60, help="pages to crawl (default 60)")
    scan_p.add_argument("--no-file-scan", action="store_true", help="skip the file scan (Site Guard plugin)")
    scan_p.add_argument("--ai", action="store_true", help="also let Claude triage ambiguous hits (needs ANTHROPIC_API_KEY)")
    scan_p.add_argument("--out", default="reports/site_guard", help="report directory (default reports/site_guard)")
    sub.add_parser("queue", parents=[common], help="list the proposed fixes and their status")
    watch_p = sub.add_parser("watch", parents=[common], help="Phase 3 integrity monitor: check files and applied "
                             "fixes, detect reinfections, recover them when allowed")
    watch_p.add_argument("--once", action="store_true", help="one check, then exit (default: keep watching)")
    watch_p.add_argument("--interval", type=float, default=30, help="minutes between checks (default 30)")
    watch_p.add_argument("--auto-recover", action="store_true",
                         help="re-apply approved fixes when their target is reinfected (within the safety limits)")
    sub.add_parser("investigate", parents=[common], help="root-cause investigation (read-only)")
    sub.add_parser("trust-baseline", parents=[common], help="record the current files as the trusted baseline")
    auto_p = sub.add_parser("auto-recover", parents=[common], help="turn automatic recovery on or off for the site")
    auto_p.add_argument("setting", choices=["on", "off"])
    for name, text in (("approve", "approve and apply proposals (backup, apply, verify)"),
                       ("reject", "reject proposals"), ("undo", "undo applied fixes")):
        p = sub.add_parser(name, parents=[common], help=text)
        p.add_argument("ids", nargs="+", help="proposal id(s) from `queue`")
        p.add_argument("--by", default=os.environ.get("USERNAME") or os.environ.get("USER") or "cli",
                       help="who is deciding (recorded in the history)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    site = Site(args.url, timeout=args.timeout, pages=getattr(args, "page", None), wp_auth=_credentials(args))
    queue = Queue(queue_path(args.queue_dir, site.host), site.url)

    if args.command == "scan":
        cfg = {"site_language": args.site_language or "", "allowed_japanese_paths": args.allow_path or [],
               "allowed_spam_categories": args.allow_category or [], "max_pages": args.max_pages,
               "file_scan": not args.no_file_scan}
        agent = SiteGuardAgent(site, cfg, use_ai=args.ai, out_dir=args.out)
        result = agent.scan()
        result["proposals"] = agent.propose(result)
        merged = queue.merge(result["proposals"])
        paths = agent.write_reports(result, "scan")
        print(f"{result['site']}: worst severity {result['worst']}, {len(result['spam_urls'])} spam URL(s). {result['ai']}")
        for f in result["findings"]:
            print(f"  [{f.severity:<8}] {f.title}")
        print(f"Proposed fixes: {len(result['proposals'])} ({merged['new']} new, {merged['resolved']} resolved since last "
              f"scan). Review with: python -m jp_seo_agent queue {args.url}")
        print("Report: " + str(paths[1]))
        return 2 if rank(result["worst"]) >= rank("HIGH") else 0

    if args.command == "queue":
        items = queue.listing()
        print(f"{len(items)} proposal(s) for {site.url} ({queue.path})")
        for p in items:
            _show(p)
        return 0

    if not site.wp_auth:
        parser.error("needs WordPress credentials (--wp-user + WP_APP_PASSWORD, or --wp-credentials-file)")
    if not site.secure:
        parser.error("changes need an https:// site (the application password is never sent over HTTP)")
    by = os.environ.get("USERNAME") or os.environ.get("USER") or "cli"
    if args.command in ("watch", "investigate", "trust-baseline", "auto-recover"):
        monitor = IntegrityMonitor(site, {"queue_dir": args.queue_dir}, queue, Path(args.backup_dir) / site.host)
        if args.command == "auto-recover":
            monitor.set_auto(args.setting == "on", by)
            print(f"Automatic recovery is {args.setting} for {site.url}.")
            return 0
        if args.command == "trust-baseline":
            print(f"Trusted baseline: {monitor.trust_baseline(by)} file(s).")
            return 0
        if args.command == "investigate":
            report = monitor.investigate_now()
            print(report["summary"])
            for c in report["causes"]:
                print(f"  [{c['confidence']:<6}] {c['title']}")
            print("Report: " + report["files"][0])
            return 0
        if args.auto_recover:
            monitor.opts["auto_recover"] = True
        while True:
            summary = monitor.check(wait=True)
            print(f"{summary['time']}  files={summary['files']} added={summary['added']} modified={summary['modified']} "
                  f"removed={summary['removed']} unexplained={summary['unexplained']} guards={summary['guards']} "
                  f"reinfections={summary['reinfections']} recovered={summary['recovered']}"
                  + (f"  error: {summary['error']}" if summary["error"] else "")
                  + (f"  note: {summary['note']}" if summary["note"] else ""))
            for e in monitor.new_events:
                print(f"    [{e['severity']:<8}] {e['title']}")
            if args.once:
                return 2 if any(e["type"] in ("reinfection", "infection", "recovery_failed", "escalated")
                                for e in monitor.new_events) else 0
            time.sleep(max(1.0, args.interval) * 60)
    failed = 0
    backup_dir = Path(args.backup_dir) / site.host
    for pid in args.ids:
        try:
            if args.command == "undo":
                p = queue.undo(pid, args.by, site, backup_dir)
            else:
                p = queue.decide(pid, args.command, args.by, site, backup_dir)
            failed += p["status"] == "failed"
            _show(p)
        except RemediationError as exc:
            failed += 1
            print(f"  {pid}  error: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
