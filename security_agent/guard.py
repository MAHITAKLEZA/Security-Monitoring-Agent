"""Phase 3 for every problem the security checks report (Spam & Compromise has its own integrity monitor).

After every scan, and every defense.security_interval_minutes in between (--serve), each site's security checks run
and every problem goes into the approval queue (fixes.py). Then, with the same machinery as the integrity monitor
(jp_seo_agent/defense.py):
  * a problem that comes back after it was fixed, marked done by hand, or had gone away is a regression: an event,
    a Teams alert when a webhook is set, and an investigation;
  * with automatic recovery on, a fix a person approved is applied again (same limits as for reinfections);
  * the investigation compares what the agent saw now with the previous check: Site Guard plugin and its settings,
    plugins, themes, administrators, the web server/CDN headers, the certificate, DNS records and .htaccess, and
    names the change that most likely undid the fix.
The first run on a site only records what is already wrong; events are raised for regressions and for new HIGH or
CRITICAL problems after that.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from jp_seo_agent.approvals import Queue, queue_path
from jp_seo_agent.defense import IntegrityMonitor, settings as defense_settings
from jp_seo_agent.files import API
from jp_seo_agent.investigate import markdown

from . import fixes

log = logging.getLogger("security_agent.guard")
SECURITY_HEADERS = ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy")
CONFIDENCE = {"high": 0, "medium": 1, "low": 2}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def security_checks(cfg, all_checks):
    wanted = defense_settings(cfg).get("security_checks")
    return [c for c in (wanted or all_checks) if c in all_checks and c != "compromise"]


class SecurityGuard:
    def __init__(self, target, config):
        self.target, self.config = target, config
        self.cfg = target["checks"].get("compromise", {})   # queue, backups and defense settings live there
        self.site = fixes._site(target)
        self.queue = Queue(queue_path(self.cfg.get("queue_dir"), self.site.host), self.site.url)
        self.monitor = IntegrityMonitor(self.site, self.cfg, self.queue,
                                        Path(self.cfg.get("backup_dir") or "backups") / self.site.host,
                                        out_dir=Path(config["report"]["output_dir"]) / "site_guard")
        self.monitor.investigator = self.investigate
        self.current = {}
        fixes.TARGETS[target["slug"]] = target

    @property
    def enabled(self):
        return bool(defense_settings(self.cfg)["enabled"])

    # ---- after a scan or a monitor cycle ----------------------------------------------------------
    def process(self, findings, completed, ctx=None, state=None, source="scan"):
        """Proposals for every problem the completed checks found, merged into the queue; then events, automatic
        recovery and investigation. Returns the new events."""
        completed = [c for c in completed if c != "compromise"]
        env = fixes.Env(self.target, self.site)
        props = fixes.build_proposals(env, [f for f in findings if f.check in completed])
        merged = self.queue.merge(props, scopes=tuple(completed))
        if not self.enabled:
            return []
        self.current = self.snapshot(env, ctx, state or {})
        with self.monitor.lock:
            self.monitor.state.load()
            self.monitor.new_events = []
            data = self.monitor.state.data
            started = data.get("security_started")
            # New problems are announced only once the site has a history, and only the serious ones
            announce = lambda p: bool(started) and p.get("severity") in ("HIGH", "CRITICAL")
            summary = {}
            self.monitor.respond(merged, None, summary, source=source, seen=[p["id"] for p in props],
                                 announce=announce)
            data["security_snapshot"] = self.current
            data.setdefault("security_started", _now())
            data["security_check"] = {"time": _now(), "source": source, "checks": completed,
                                      "problems": len(props), "new": len(merged.get("new_ids") or []),
                                      "regressions": len(merged.get("reinfections") or []),
                                      "recovered": summary.get("recovered", 0)}
            self.monitor.state.save()
        return self.monitor.new_events

    def cycle(self, run_checks):
        """One monitor cycle between scans. run_checks(target, checks) -> (findings, completed, ctx, state)."""
        checks = security_checks(self.cfg, self.config["checks"].keys())
        findings, completed, ctx, state = run_checks(self.target, checks)
        return self.process(findings, completed, ctx, state, source="security monitor")

    # ---- what the site looks like now, for the next investigation ----------------------------------
    def snapshot(self, env, ctx, state):
        snap = {"time": _now()}
        try:
            resp, _ = ctx.home if ctx is not None else (None, None)
            if resp is not None:
                snap.update(server=resp.headers.get("Server"), powered_by=resp.headers.get("X-Powered-By"),
                            headers=sorted(h for h in SECURITY_HEADERS if resp.headers.get(h)))
        except Exception:
            pass
        ssl = state.get("ssl") or {}
        snap.update(cert_issuer=ssl.get("issuer"), cert_fingerprint=ssl.get("fingerprint"))
        snap["dns"] = {k: v for k, v in (state.get("dns") or {}).items() if k in ("A", "AAAA", "NS", "MX", "CNAME")}
        if env.wordpress:
            snap["plugins"] = {(p.get("plugin") or "").split("/")[0]: [p.get("version"), p.get("status")]
                               for p in env.plugins()}
            snap["themes"] = {t.get("stylesheet"): [t.get("version"), t.get("status")] for t in env.themes()}
            snap["admins"] = sorted(u.get("username") or u.get("slug") or "" for u in env.users()
                                    if "administrator" in (u.get("roles") or []))
            snap["guard_version"] = (env.guard or {}).get("plugin_version")
            if env.guard12:
                status, data = self.site.wp("GET", f"{API}/hardening")
                snap["hardening"] = sorted((data or {}).get("settings") or {}) if status == 200 else None
        drift = self.monitor.state.data.get("drift") or {}
        snap["htaccess_changed"] = sorted(p for p in drift if p.rsplit("/", 1)[-1] == ".htaccess")
        return snap

    # ---- root-cause investigation for regressions ---------------------------------------------------
    def investigate(self, monitor, trigger):
        prev = monitor.state.data.get("security_snapshot") or {}
        cur = self.current
        props = [self.queue.proposals[p] for p in trigger.get("proposals") or [] if p in self.queue.proposals]
        checks = set(trigger.get("checks") or [])
        causes = []

        def cause(confidence, title, detail, actions, **evidence):
            causes.append({"confidence": confidence, "title": title, "detail": detail, "actions": actions,
                           "evidence": evidence})

        if prev.get("guard_version") and not cur.get("guard_version") and "plugins" in cur:
            cause("high", "The Kleza Site Guard plugin was deactivated or removed",
                  "The headers and hardening it applies stopped with it.",
                  ["Reactivate it (Plugins > Installed Plugins) and find out who turned it off."])
        lost = sorted(set(prev.get("hardening") or []) - set(cur.get("hardening") or []))
        if lost and cur.get("hardening") is not None:
            cause("high", "Site Guard hardening settings were removed",
                  f"{', '.join(lost)} were switched off outside the agent (or the plugin's settings were reset).",
                  ["Check who has administrator access; re-apply the fixes."], settings=lost)
        if (prev.get("server"), prev.get("powered_by")) != (cur.get("server"), cur.get("powered_by")) and \
                prev.get("time") and checks & {"headers", "ssl", "vulnerabilities", "exposed_files"}:
            cause("high", "The web server or CDN in front of the site changed",
                  f"Server header {prev.get('server')!r} -> {cur.get('server')!r}; X-Powered-By "
                  f"{prev.get('powered_by')!r} -> {cur.get('powered_by')!r}. A hosting move, server update or CDN "
                  "change resets headers, redirects and file rules.",
                  ["Re-apply the headers and rules in the new server/CDN configuration."])
        lost_headers = sorted(set(prev.get("headers") or []) - set(cur.get("headers") or []))
        if lost_headers:
            cause("medium", f"Security header(s) disappeared: {', '.join(lost_headers)}",
                  "They were sent at the previous check.", ["See the other causes for what changed."])
        if prev.get("cert_fingerprint") and prev.get("cert_fingerprint") != cur.get("cert_fingerprint"):
            cause("high" if "ssl" in checks else "low", "The SSL certificate was replaced",
                  f"Issuer {prev.get('cert_issuer')} -> {cur.get('cert_issuer')}.",
                  ["Confirm the renewal was yours; make sure the full chain is installed and auto-renewal works."])
        for rtype in ("NS", "A", "AAAA", "MX", "CNAME"):
            if prev.get("dns", {}).get(rtype) and prev["dns"].get(rtype) != cur.get("dns", {}).get(rtype):
                cause("high", f"DNS {rtype} records changed",
                      f"{prev['dns'][rtype]} -> {cur.get('dns', {}).get(rtype)}. "
                      + ("The site now points at a different server, which doesn't have your fixes."
                         if rtype in ("A", "AAAA", "CNAME") else "The domain is managed somewhere else now."),
                      ["Confirm the change with whoever manages DNS; if nobody does, secure the registrar account."])
        if cur.get("htaccess_changed") and checks & {"exposed_files", "headers", "wordpress", "ssl"}:
            cause("high", ".htaccess was rewritten",
                  "Caching and security plugins regenerate .htaccess and can drop rules added by others.",
                  ["Check which plugin rewrote it (recent updates below); re-apply the fix."],
                  files=cur["htaccess_changed"])
        changed = []
        for kind in ("plugins", "themes"):
            before, after = prev.get(kind) or {}, cur.get(kind) or {}
            if not before:
                continue
            for slug in sorted(set(before) | set(after)):
                a, b = before.get(slug), after.get(slug)
                if a != b:
                    changed.append(f"{kind[:-1]} {slug}: "
                                   + ("installed" if a is None else "removed" if b is None else
                                      f"{a[0]} ({a[1]}) -> {b[0]} ({b[1]})"))
        if changed:
            cause("medium", f"{len(changed)} plugin/theme change(s) since the previous check",
                  "An update, install or activation around the same time is the most common reason a fix stops "
                  "working.", ["Look at the listed changes first."], changes=changed[:30])
        new_admins = sorted(set(cur.get("admins") or []) - set(prev.get("admins") or [])) if prev.get("admins") else []
        if new_admins:
            cause("high", f"New administrator(s): {', '.join(new_admins)}",
                  "Someone who can change the site's settings and plugins was added.",
                  ["Confirm each account with your team; demote or delete unknown ones."])
        by_hand = [p for p in props if (p.get("reinfection") or {}).get("how") == "fixed by hand"]
        if by_hand:
            cause("medium", "It was fixed by hand, outside the agent",
                  "The agent can't see the setting that was changed (hosting panel, server configuration, DNS "
                  "provider), so it can't tell what changed it back.",
                  ["Ask whoever made the fix to check it; prefer a fix the agent can apply and watch."],
                  problems=[p.get("title") for p in by_hand])
        flapping = [p for p in props if (p.get("reinfection") or {}).get("how") == "went away"]
        if flapping:
            cause("low", "The problem comes and goes", "It disappeared without a fix and is back: an intermittent "
                  "server, a CDN with several edge servers, or a cache.", ["Check again in a few minutes."],
                  problems=[p.get("title") for p in flapping])
        if not causes:
            hints = {"ssl": "Certificate auto-renewal may have failed.",
                     "headers": "A plugin, theme or server update may have changed the headers.",
                     "exposed_files": "A deployment or backup plugin may have put the file back.",
                     "wordpress": "Someone with administrator access may have changed it back.",
                     "dns": "Someone with access to the DNS provider changed the records."}
            cause("low", "No change the agent can see explains it",
                  " ".join(hints[c] for c in sorted(checks) if c in hints) or "Check recent changes on the server.",
                  ["Review recent changes with your team and host."])
        causes.sort(key=lambda c: CONFIDENCE[c["confidence"]])
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        report = {"id": stamp, "time": _now(), "site": self.site.url, "trigger": trigger,
                  "summary": f"Most likely: {causes[0]['title']} ({causes[0]['confidence']} confidence).",
                  "causes": causes, "timeline": [], "app_passwords": [], "software": [],
                  "notes": [f"Problems: {', '.join(p.get('title') or p['target'] for p in props[:8])}."]
                  + ([f"Previous check: {prev.get('time')}."] if prev.get("time") else
                     ["No earlier snapshot to compare with; later regressions get a fuller comparison."])}
        folder = Path(self.config["report"]["output_dir"]) / "site_guard" / self.site.host
        folder.mkdir(parents=True, exist_ok=True)
        base = folder / f"investigation-{stamp}"
        report["files"] = [str(base.with_suffix(".md")), str(base.with_suffix(".json"))]
        base.with_suffix(".json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str),
                                             encoding="utf-8")
        base.with_suffix(".md").write_text(markdown(report), encoding="utf-8")
        return report
