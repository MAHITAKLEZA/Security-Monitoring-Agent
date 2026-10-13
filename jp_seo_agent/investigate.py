"""Phase 3, root-cause investigation: read-only.

Runs when the integrity monitor or a scan finds a new infection or a reinfection, and works out how the attacker got
in and what keeps bringing the infection back. Rule-based; it gathers evidence from:
  timeline     other code files changed within a few minutes of each infected file (dropped together)
  persistence  must-use plugins, PHP in uploads, auto_prepend_file and handler rules in .htaccess / .user.ini,
               includes or eval in wp-config.php, oddly named PHP files, and fixes still waiting for approval
  accounts     recently created administrators and recently created or used application passwords
  entry point  outdated or closed plugins and themes, an outdated WordPress core, the plugin that holds the
               infected file, and what the infected locations say about the attacker's access
  pattern      how quickly a fixed target is reinfected (minutes: an active backdoor; about a day: a scheduled task)
Each likely cause gets a confidence (high / medium / low), its evidence and what to do. Nothing on the site changes.
"""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .files import CODE_EXT, HTACCESS_SIGS, FileScan, _get
from .site import days_since

WP_API = "https://api.wordpress.org"
CONFIDENCE = {"high": 0, "medium": 1, "low": 2}
RECENT_DAYS = 30
# Hidden names (.cache.php), double extensions (photo.jpg.php) and random alphanumeric names (a8f3k2x9.php)
ODD_PHP = re.compile(r"(?:^|/)(?:\.[^/]+\.php|[^/]*\.(?:jpe?g|png|gif|ico|txt|css)\.php|[a-z]*\d[a-z\d]{5,}\.php)$", re.I)
WP_CONFIG_BAD = re.compile(r"(?:include|require)(?:_once)?\s*\(?\s*['\"][^'\"]*\.(?:ico|png|jpe?g|gif|txt|css)['\"]|"
                           r"\beval\s*\(|base64_decode\s*\(|gzinflate\s*\(|\$_(?:POST|GET|REQUEST|COOKIE)\s*\[", re.I)


def _v(text):
    return tuple(int(p) for p in re.findall(r"\d+", str(text or ""))[:4])


def _when(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if epoch else "?"


def _parse(stamp):
    try:
        when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def wporg_info(kind, slug):
    """Latest release on wordpress.org: {"version", "closed"}; {} when the slug isn't hosted there."""
    params = {"action": f"{kind}_information", "request[slug]": slug}
    for field in ("sections", "versions", "reviews", "screenshots", "description"):
        params[f"request[fields][{field}]"] = 0
    data = _get(f"{WP_API}/{kind}s/info/1.2/", **params) or {}
    if data.get("error") == "closed":
        return {"closed": True, "version": None}
    return {"version": data.get("version"), "closed": False} if data.get("version") else {}


def latest_core():
    data = _get(f"{WP_API}/core/version-check/1.7/") or {}
    offers = data.get("offers") or []
    return (offers[0] or {}).get("current") if offers else None


class Investigation:
    def __init__(self, site, cfg, queue, files=None, status=None, trigger=None):
        self.site, self.cfg, self.queue = site, cfg, queue
        self.files = files or {}              # path -> {"p", "s", "m", "h"} from the Site Guard plugin
        self.status = status or {}
        self.trigger = trigger or {}
        self.window = int((cfg.get("defense") or {}).get("timeline_minutes", 30)) * 60
        self.causes, self.timeline, self.accounts, self.software, self.notes = [], [], [], [], []
        self.reader = FileScan(site, cfg)
        self.dirs = {k: (self.status.get(k) or "").strip("/") for k in
                     ("plugins_dir", "mu_plugins_dir", "uploads_dir", "themes_dir")}

    def cause(self, confidence, title, detail, actions, **evidence):
        self.causes.append({"confidence": confidence, "title": title, "detail": detail, "actions": actions,
                            "evidence": evidence})

    def under(self, path, key):
        return bool(self.dirs[key]) and path.startswith(self.dirs[key] + "/")

    # ---- evidence -------------------------------------------------------------
    def infected_paths(self):
        paths = set(self.trigger.get("paths") or [])
        for pid in self.trigger.get("proposals") or []:
            p = self.queue.proposals.get(pid)
            if p and p["kind"] == "file":
                paths.add(p["data"].get("path"))
        return sorted(p for p in paths if p)

    def check_timeline(self, infected):
        """Code files changed within the time window of each infected file: likely dropped in the same attack."""
        stamps = [(p, self.files[p].get("m")) for p in infected if p in self.files and self.files[p].get("m")]
        near = {}
        for path, m in stamps:
            for q, f in self.files.items():
                if q != path and q not in infected and CODE_EXT.search(q) and f.get("m") and abs(f["m"] - m) <= self.window:
                    near[q] = f["m"]
        self.timeline = [{"path": p, "changed": _when(m), "infected": True} for p, m in stamps] + \
            [{"path": q, "changed": _when(m), "infected": False} for q, m in sorted(near.items(), key=lambda kv: kv[1])[:40]]
        if near:
            risky = [q for q in near if self.under(q, "uploads_dir") or self.under(q, "mu_plugins_dir")
                     or q.startswith(("wp-admin/", "wp-includes/")) or "/" not in q or ODD_PHP.search(q)]
            self.cause("high" if risky else "medium", f"{len(near)} other code file(s) changed at the same time",
                       f"Changed within {self.window // 60} minutes of the infected file(s)"
                       + (f"; {len(risky)} of them sit where backdoors usually hide" if risky else "")
                       + ". Attackers drop several files at once, and a backdoor left behind reinstalls the rest.",
                       ["Review each listed file; quarantine the ones your team didn't change.",
                        "Modification times can be faked, so also check files the monitor reports as unexplained."],
                       files=sorted(near)[:40], risky=sorted(risky)[:40])

    def check_persistence(self):
        mu = [p for p in self.files if self.under(p, "mu_plugins_dir") and CODE_EXT.search(p)]
        recent_mu = [p for p in mu if _age(_when_iso(self.files[p].get("m"))) <= RECENT_DAYS]
        if recent_mu:
            self.cause("high", "Must-use plugin added or changed recently",
                       "Must-use plugins load on every request and don't appear in the plugin list, which makes them a "
                       "favourite way to reinstall an infection.", ["Open each file; delete the ones you didn't add."],
                       files=recent_mu)
        elif mu:
            self.notes.append(f"{len(mu)} must-use plugin file(s) present: {', '.join(sorted(mu)[:5])}.")
        uploads = [p for p in self.files if self.under(p, "uploads_dir") and CODE_EXT.search(p)]
        if uploads:
            self.cause("high", "PHP files in the uploads folder",
                       "The uploads folder only needs media; PHP there is almost always a web shell that lets the "
                       "attacker come back.", ["Quarantine them (they appear as proposed fixes after a scan).",
                                               "Block PHP execution in wp-content/uploads with an .htaccess rule."],
                       files=sorted(uploads)[:40])
        configs = [p for p in self.files if p.rsplit("/", 1)[-1].lower() in (".htaccess", ".user.ini", "php.ini")]
        bad_config = {}
        for path in sorted(configs, key=lambda p: (p.count("/"), p))[:20]:
            text = self.reader.read(path) or ""
            found = [label for label, regex, _ in HTACCESS_SIGS if regex.search(text)]
            if found:
                bad_config[path] = found
        if bad_config:
            prepend = any("auto_" in label for labels in bad_config.values() for label in labels)
            self.cause("high", "Server configuration loads or routes to attacker code",
                       ("auto_prepend_file runs a chosen PHP file before every page, so the infection survives any "
                        "clean-up of the files themselves. " if prepend else "")
                       + "Rewrite or handler rules were found that serve attacker code.",
                       ["Remove the listed lines (proposed as 'Remove malicious lines' after a scan).",
                        "Check the hosting control panel's PHP settings for auto_prepend_file too."],
                       files=bad_config)
        if "wp-config.php" in self.files:
            text = self.reader.read("wp-config.php") or ""
            hits = sorted({m.group(0)[:60] for m in WP_CONFIG_BAD.finditer(text)})
            if hits:
                self.cause("high", "wp-config.php contains suspicious code",
                           "wp-config.php runs on every request; code in it reloads the infection.",
                           ["Compare it with a clean copy and remove anything your team didn't add (it's never "
                            "changed automatically).", "Rotate the database password and the salts afterwards."],
                           matches=hits[:10])
        odd = [p for p in self.files if CODE_EXT.search(p) and ODD_PHP.search(p)
               and not (self.under(p, "plugins_dir") or self.under(p, "themes_dir"))]
        if odd:
            self.cause("medium", "Oddly named PHP files", "Random-looking names, hidden names and double extensions "
                       "(image.jpg.php) are typical of dropped backdoors.", ["Review and quarantine them."],
                       files=sorted(odd)[:40])
        waiting = [p for p in self.queue.proposals.values() if p["status"] in ("pending", "failed")
                   and p["kind"] == "file" and p["id"] not in (self.trigger.get("proposals") or [])]
        if waiting:
            self.cause("high" if any(p["action"] != "manual" for p in waiting) else "medium",
                       f"{len(waiting)} infected file(s) still not fixed",
                       "A backdoor that stays on the site reinstalls everything that was cleaned.",
                       ["Approve or handle the waiting fixes under Remediation first."],
                       files=[p["target"] for p in waiting[:40]])

    def check_accounts(self):
        users = self.site.wp_items("/wp/v2/users", context="edit", _fields="id,username,slug,roles,registered_date")
        me = (getattr(self.site, "login_user", None) or {}).get("id")
        admins = [u for u in users if "administrator" in (u.get("roles") or [])]
        new_admins = [u for u in admins if _age(u.get("registered_date")) <= RECENT_DAYS]
        if new_admins:
            self.cause("high", f"{len(new_admins)} administrator(s) created in the last {RECENT_DAYS} days",
                       "Attackers add administrator accounts so they can log back in after a clean-up.",
                       ["Confirm each one with your team; delete the ones nobody owns.",
                        "Then change every administrator's password."],
                       accounts=[f"{u.get('username') or u.get('slug')} (registered {u.get('registered_date')})"
                                 for u in new_admins])
        for u in admins[:10]:
            status, keys = self.site.wp("GET", f"/wp/v2/users/{u['id']}/application-passwords")
            if status != 200 or not isinstance(keys, list):
                continue
            for k in keys:
                row = {"user": u.get("username") or u.get("slug"), "name": k.get("name"), "created": k.get("created"),
                       "last_used": k.get("last_used"), "last_ip": k.get("last_ip"), "yours": u.get("id") == me}
                self.accounts.append(row)
        fresh = [a for a in self.accounts if _age(a["created"]) <= RECENT_DAYS]
        if fresh:
            others = [a for a in fresh if not a["yours"]]
            self.cause("medium" if others else "low",
                       f"{len(fresh)} application password(s) created in the last {RECENT_DAYS} days",
                       "An application password gives full REST API access without the login page or two-factor "
                       "authentication. " + ("The one this agent uses is listed too." if others else
                                             "All belong to the account this agent logs in with; one is the agent's."),
                       ["Revoke the ones you don't recognise (Users > Profile > Application Passwords)."],
                       passwords=fresh)

    def check_software(self, infected):
        status, plugins = self.site.wp("GET", "/wp/v2/plugins")
        plugins = plugins if status == 200 and isinstance(plugins, list) else []
        status, themes = self.site.wp("GET", "/wp/v2/themes")
        themes = themes if status == 200 and isinstance(themes, list) else []
        items = [("plugin", (p.get("plugin") or "").split("/")[0], p.get("version"), p.get("status"),
                  p.get("name") if isinstance(p.get("name"), str) else None) for p in plugins if p.get("plugin")]
        items += [("theme", t.get("stylesheet"), t.get("version"), t.get("status"),
                   (t.get("name") or {}).get("raw") if isinstance(t.get("name"), dict) else t.get("name"))
                  for t in themes if t.get("stylesheet")]
        items = items[:60]
        with ThreadPoolExecutor(max_workers=6) as pool:
            infos = list(pool.map(lambda i: wporg_info(i[0], i[1]), items))
        outdated, closed, inactive = [], [], []
        for (kind, slug, version, state, name), info in zip(items, infos):
            row = {"kind": kind, "slug": slug, "name": name or slug, "version": version, "status": state,
                   "latest": (info or {}).get("version"), "closed": bool((info or {}).get("closed"))}
            self.software.append(row)
            if row["closed"]:
                closed.append(row)
            elif row["latest"] and version and _v(version) < _v(row["latest"]):
                outdated.append(row)
            if state == "inactive":
                inactive.append(row)
        label = lambda r: f"{r['name']} {r['version']}" + (f" (latest {r['latest']})" if r["latest"] else "")
        # The plugin or theme that holds an infected file
        for path in infected:
            for kind, key in (("plugin", "plugins_dir"), ("theme", "themes_dir")):
                if self.under(path, key):
                    slug = path[len(self.dirs[key]) + 1:].split("/", 1)[0]
                    row = next((r for r in self.software if r["kind"] == kind and r["slug"] == slug), None)
                    if row:
                        risky = row in outdated or row in closed
                        self.cause("high" if risky else "medium", f"The infection is inside the {kind} {row['name']}",
                                   f"{path} belongs to {label(row)}"
                                   + (", which is outdated or no longer maintained, a likely way in." if risky else "."),
                                   [f"Update or reinstall {row['name']} from a clean copy"
                                    + (", or replace it: it was closed on wordpress.org." if row["closed"] else ".")],
                                   file=path, software=row)
        if closed:
            self.cause("high", f"{len(closed)} plugin(s)/theme(s) closed on wordpress.org",
                       "Closed plugins are often closed for an unfixed security issue and get no more updates.",
                       ["Remove them or replace them with a maintained alternative."], software=[label(r) for r in closed])
        if outdated:
            self.cause("medium" if len(outdated) < 3 else "high", f"{len(outdated)} outdated plugin(s)/theme(s)",
                       "Known vulnerabilities in outdated plugins are the most common way into WordPress sites.",
                       ["Update them all, starting with the ones that accept uploads or form input."],
                       software=[label(r) for r in outdated])
        if len(inactive) >= 3:
            self.notes.append(f"{len(inactive)} inactive plugins/themes: their code can still be reached and attacked. "
                              "Delete the ones you don't use.")
        version, latest = self.status.get("wp_version"), latest_core()
        if version and latest and _v(version) < _v(latest):
            self.cause("medium", f"WordPress {version} is outdated (latest {latest})",
                       "Older releases have published vulnerabilities.", ["Update WordPress core."])

    def check_access(self, infected):
        """What the infected locations say about the attacker's access."""
        core = [p for p in infected if p.startswith(("wp-admin/", "wp-includes/")) or ("/" not in p and CODE_EXT.search(p))]
        uploads = [p for p in infected if self.under(p, "uploads_dir")]
        content_only = not infected and any(s.startswith("content:") for s in self.trigger.get("subjects") or [])
        if core:
            self.cause("medium", "The attacker could write WordPress core files",
                       "That needs file-write access: stolen hosting, SFTP or control-panel credentials, another "
                       "infected site on the same hosting account, or code execution through a vulnerable plugin.",
                       ["Change the hosting, SFTP/SSH and database passwords.",
                        "Check other sites on the same hosting account."], files=core)
        if uploads:
            self.cause("medium", "Files were written into uploads",
                       "Usually an upload form or plugin that accepts files without checking them, or a web shell "
                       "already on the site.", ["Update form and upload plugins; block PHP in wp-content/uploads."],
                       files=uploads)
        if content_only:
            self.cause("medium", "Only WordPress content was changed",
                       "Content is changed through an account (stolen password or application password) or a "
                       "plugin vulnerability, not through the files.",
                       ["Reset the passwords of everyone who can publish; revoke unknown application passwords."])

    def check_pattern(self):
        """How fast fixed targets come back."""
        fast = daily = 0
        chains = []
        for pid in self.trigger.get("proposals") or []:
            p = self.queue.proposals.get(pid)
            r = (p or {}).get("reinfection")
            if not r:
                continue
            fixed, back = _parse(r.get("fixed_at")), _parse(r.get("detected"))
            hours = (back - fixed).total_seconds() / 3600 if fixed and back else None
            chains.append({"target": p["target"], "times": r.get("count"), "hours_after_fix": round(hours, 1)
                           if hours is not None else None})
            if hours is not None and hours < 2:
                fast += 1
            elif hours is not None and 20 <= hours <= 28:
                daily += 1
        if fast:
            self.cause("high", "Reinfected within two hours of the fix",
                       "Something on the server rewrites the target almost immediately: a backdoor called on every "
                       "request (auto_prepend_file, a must-use plugin, code in wp-config.php or the theme) or a "
                       "process left running by the attacker.",
                       ["Check the persistence findings above first.",
                        "Ask the host to look for unknown processes and cron jobs on the account."], reinfections=chains)
        elif daily:
            self.cause("high", "Reinfected about a day after the fix",
                       "A scheduled task reinstalls it: a WP-Cron event added by malware or a server cron job.",
                       ["List WP-Cron events (WP Crontrol plugin or `wp cron event list`) and delete unknown ones.",
                        "Check the hosting control panel's cron jobs."], reinfections=chains)
        elif chains:
            self.notes.append("Reinfections: " + "; ".join(f"{c['target'][:60]} came back {c['hours_after_fix']}h "
                                                            "after the fix" for c in chains[:5]) + ".")

    # ---- run ------------------------------------------------------------------
    def run(self):
        infected = self.infected_paths()
        steps = [lambda: self.check_timeline(infected), self.check_persistence, self.check_accounts,
                 lambda: self.check_software(infected), lambda: self.check_access(infected), self.check_pattern]
        for step in steps:
            try:
                step()
            except Exception as exc:   # one failing lookup must not stop the investigation
                self.notes.append(f"Part of the investigation failed: {exc.__class__.__name__}: {exc}"[:300])
        if not self.files:
            self.notes.append("No file inventory (the Kleza Site Guard plugin isn't available), so file timeline and "
                              "persistence checks were skipped.")
        self.causes.sort(key=lambda c: CONFIDENCE.get(c["confidence"], 9))
        top = self.causes[0] if self.causes else None
        summary = (f"Most likely: {top['title']} ({top['confidence']} confidence)." if top else
                   "No clear cause found from what the agent can see. Check the hosting account (passwords, cron "
                   "jobs, other sites) and the server's access logs around the time of the infection.")
        return {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "site": self.site.url,
                "trigger": {**self.trigger, "paths": infected}, "summary": summary, "causes": self.causes,
                "timeline": self.timeline, "app_passwords": self.accounts, "software": self.software,
                "notes": self.notes}


def _when_iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat() if epoch else None


def _age(stamp):
    """Days since an ISO timestamp; a large number when unknown (0 is a valid age, so no `or` default)."""
    days = days_since(stamp)
    return 10 ** 6 if days is None else days


def investigate(site, cfg, queue, files=None, status=None, trigger=None, out_dir="reports/site_guard"):
    """Run an investigation and write investigation-<time>.md/.json next to the scan reports."""
    report = Investigation(site, cfg, queue, files, status, trigger).run()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    folder = Path(out_dir) / site.host
    folder.mkdir(parents=True, exist_ok=True)
    base = folder / f"investigation-{stamp}"
    report["id"] = stamp
    report["files"] = [str(base.with_suffix(".md")), str(base.with_suffix(".json"))]
    base.with_suffix(".json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    base.with_suffix(".md").write_text(markdown(report), encoding="utf-8")
    return report


def markdown(r):
    lines = [f"# Root-cause investigation: {r['site']}", "", f"- Time: {r['time']}",
             f"- Trigger: {r['trigger'].get('reason', 'manual')}", f"- {r['summary']}", "",
             "Read-only: nothing on the site was changed by this investigation.", "", "## Likely causes", ""]
    if not r["causes"]:
        lines += ["None found.", ""]
    for n, c in enumerate(r["causes"], 1):
        lines += [f"### {n}. {c['title']} ({c['confidence']} confidence)", "", c["detail"], ""]
        lines += [f"- {a}" for a in c["actions"]] + [""]
        if c["evidence"]:
            lines += ["```", json.dumps(c["evidence"], indent=2, ensure_ascii=False, default=str)[:3000], "```", ""]
    if r["timeline"]:
        lines += ["## Timeline", "", "| Changed | File | |", "|---|---|---|"]
        lines += [f"| {t['changed']} | {t['path']} | {'infected' if t['infected'] else ''} |" for t in r["timeline"]]
        lines.append("")
    if r["app_passwords"]:
        lines += ["## Application passwords (administrators)", "", "| User | Name | Created | Last used | Last IP |",
                  "|---|---|---|---|---|"]
        lines += [f"| {a['user']} | {a['name']} | {a['created']} | {a['last_used'] or 'never'} | {a['last_ip'] or ''} |"
                  for a in r["app_passwords"]]
        lines.append("")
    if r["notes"]:
        lines += ["## Notes", ""] + [f"- {n}" for n in r["notes"]] + [""]
    return "\n".join(lines)
