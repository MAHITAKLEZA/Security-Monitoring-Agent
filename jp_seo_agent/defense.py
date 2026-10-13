"""Phase 3: autonomous defense.

Continuous integrity monitoring
    Every few minutes (defense.watch_interval_minutes) the monitor lists the site's files through the Site Guard
    plugin and compares them with a baseline. Changes that match an official wordpress.org checksum (core and plugin
    updates) or one of our own fixes are folded into the baseline; every other changed file is read and checked
    with the scan's signatures, so new infections are found between the daily scans. Changes it can't explain are
    listed as "unexplained" until someone trusts the current files as the new baseline.
    It also re-checks every fix that is still applied: a quarantined file must stay gone, a restored file must keep
    its clean checksum, a trashed or cleaned post must stay clean and a demoted account must stay a subscriber.

Reinfection detection
    A problem found again on a target whose fix is still applied is a reinfection; the queue links it to that fix
    (approvals.py) and the monitor raises an event.

Root-cause investigation
    A new infection or a reinfection starts an investigation (investigate.py): read-only, written next to the reports.

Controlled automatic recovery
    Off unless switched on (defense.auto_recover, or per site from the dashboard). Even then, only a reinfection of a
    fix that a person approved is applied again, and only when:
      * its action is in defense.auto_actions (never "manual"), and for a returning quarantined file only when it is
        the same file or matches a malware signature;
      * the target hasn't been recovered automatically max_auto_per_target times in 7 days (then a person has to fix
        the root cause), and the site is under max_auto_per_day automatic recoveries in 24 hours;
      * no earlier automatic recovery of that target failed or couldn't be verified.
    It goes through the same path as a person's approval: change check, local backup, apply, verify, undo.
"""

import hashlib
import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import wordpress
from .approvals import AUTO_BY, Queue, by_person, queue_path, scope, subject
from .files import FileScan
from .investigate import investigate
from .remediate import _proposal, content_proposals, file_proposals

log = logging.getLogger("jp_seo_agent.defense")

DEFAULTS = {
    "enabled": True,
    "watch_interval_minutes": 30,
    "auto_recover": False,
    "auto_actions": ["quarantine", "restore_core", "restore_plugin_file", "clean_config", "trash", "strip_spam",
                     "demote_user", "harden", "block_paths", "deactivate_plugin", "quarantine_dir",
                     "revoke_app_passwords", "update_plugin", "update_theme"],
    "security_interval_minutes": 60,  # the security checks re-run between scans (security_agent/guard.py)
    "security_checks": [],            # which ones; empty = all except compromise
    "max_auto_per_day": 10,
    "max_auto_per_target": 3,
    "max_reads": 30,                  # changed files read per cycle
    "max_guards": 100,                # applied content/account fixes re-checked per cycle
    "ignore_paths": ["wp-content/cache/", "wp-content/upgrade/", "wp-content/updraft/"],
    "investigate_cooldown_minutes": 360,
    "timeline_minutes": 30,
}
MAX_EVENTS, MAX_INVESTIGATIONS, MAX_DRIFT = 300, 20, 500
REPLACE_ACTIONS = ("restore_core", "restore_plugin_file", "clean_config")
_LOCKS, _LOCKS_GUARD = {}, threading.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse(stamp):
    try:
        return datetime.fromisoformat(str(stamp))
    except (TypeError, ValueError):
        return None


def settings(cfg):
    return {**DEFAULTS, **((cfg or {}).get("defense") or {})}


def state_path(cfg, host):
    return Path((cfg or {}).get("defense_dir") or "state/defense") / f"{host}.json"


def _lock(path):
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(str(Path(path).resolve()), threading.Lock())


def _differs(a, b):
    """a, b: [md5, size, mtime]. Files over 5 MB have no checksum: compare size and time instead."""
    return a[0] != b[0] if a[0] and b[0] else list(a[1:]) != list(b[1:])


class DefenseState:
    """state/defense/<host>.json: baseline, unexplained changes, events, investigations, automatic recoveries."""

    def __init__(self, path):
        self.path = Path(path)
        self.data = {}
        self.load()

    def load(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        self.data = {"baseline": None, "drift": {}, "events": [], "investigations": [], "recoveries": [],
                     "blocked": {}, "auto_recover": None, "last_check": None, **(data if isinstance(data, dict) else {})}
        return self

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        tmp.replace(self.path)

    def event(self, kind, severity, title, detail="", **extra):
        when = _now()
        entry = {"id": hashlib.sha1(f"{when}|{kind}|{title}|{len(self.data['events'])}".encode()).hexdigest()[:10],
                 "time": when, "type": kind, "severity": severity, "title": title, "detail": detail[:1000], **extra}
        self.data["events"] = (self.data["events"] + [entry])[-MAX_EVENTS:]
        return entry


class IntegrityMonitor:
    def __init__(self, site, cfg, queue=None, backup_dir=None, out_dir="reports/site_guard"):
        self.site, self.cfg = site, cfg or {}
        self.opts = settings(self.cfg)
        self.queue = queue or Queue(queue_path(self.cfg.get("queue_dir"), site.host), site.url)
        self.backup_dir = Path(backup_dir or Path(self.cfg.get("backup_dir") or "backups") / site.host)
        self.out_dir = out_dir
        self.path = state_path(self.cfg, site.host)
        self.lock = _lock(self.path)
        self.state = DefenseState(self.path)
        self.expect_ja = (self.cfg.get("site_language") or "").lower().startswith("ja")
        self.new_events = []
        self.investigator = None   # callable(monitor, trigger) -> report; default: the file-level investigation

    # ---- settings changed from the dashboard --------------------------------------
    def auto_enabled(self):
        own = self.state.data.get("auto_recover")
        return bool(self.opts["auto_recover"] if own is None else own)

    def set_auto(self, enabled, by=""):
        with self.lock:
            self.state.load()
            self.state.data["auto_recover"] = bool(enabled)
            self.state.event("setting", "INFO", f"Automatic recovery turned {'on' if enabled else 'off'}",
                             f"Changed by {by or 'unknown'}.")
            self.state.save()

    def unblock(self, subj, by=""):
        with self.lock:
            self.state.load()
            if self.state.data["blocked"].pop(subj, None) is not None:
                self.state.event("setting", "INFO", f"Automatic recovery allowed again for {subj.split(':', 1)[-1]}",
                                 f"By {by or 'unknown'}.")
            self.state.save()

    def trust_baseline(self, by=""):
        """Record the site's current files as the trusted baseline and clear the unexplained changes."""
        fs = FileScan(self.site, self.cfg)
        status, listing = fs.fetch()
        if listing is None:
            raise ValueError(fs.findings[0].detail if fs.findings else "The file list is not available.")
        files = self._inventory(listing)
        with self.lock:
            self.state.load()
            self.state.data.update(baseline={"files": files, "at": _now(), "trusted": True, "by": by,
                                             "wp_version": status.get("wp_version")}, drift={})
            self.state.event("baseline", "INFO", f"Current files trusted as the baseline ({len(files)} files)",
                             f"By {by or 'unknown'}.")
            self.state.save()
        return len(files)

    # ---- one monitoring cycle -----------------------------------------------------
    def check(self, wait=False):
        """Run one cycle; returns its summary, or None when another cycle for this site is still running."""
        if not self.lock.acquire(blocking=wait, timeout=900 if wait else -1):
            return None
        try:
            self.state.load()
            self.new_events = []
            summary = self._check()
            self.state.data["last_check"] = summary
            self.state.save()
            return summary
        finally:
            self.lock.release()

    def _event(self, *args, **kwargs):
        entry = self.state.event(*args, **kwargs)
        self.new_events.append(entry)
        return entry

    def _check(self):
        summary = {"time": _now(), "files": None, "added": 0, "modified": 0, "removed": 0, "verified": 0,
                   "unexplained": 0, "guards": 0, "proposals": 0, "reinfections": 0, "recovered": 0, "error": None,
                   "note": None}
        if not (self.site.wp_auth and self.site.secure):
            summary["error"] = "Monitoring needs the site's WordPress application password and an https:// address."
            return summary
        if not wordpress.login(self.site):
            summary["error"] = f"WordPress login failed (HTTP {getattr(self.site, 'login_status', None)})."
            return summary
        self.queue.load()
        proposals, fs = [], None
        if self.cfg.get("file_scan", True):
            fs = FileScan(self.site, {**self.cfg, "max_file_reads": self.opts["max_reads"]})
            status, listing = fs.fetch()
            if listing is not None:
                proposals += self._files(fs, status, listing, summary)
            else:
                summary["note"] = (fs.findings[0].detail if fs.findings else "File list unavailable") + \
                    " Content and account fixes are still checked."
                fs = None
        proposals += self._guards(summary)
        summary["proposals"] = len(proposals)
        merged = self.queue.merge(proposals, partial=True) if proposals else {"new_ids": [], "reinfections": []}
        self.respond(merged, fs, summary, source="integrity monitor", seen=[p["id"] for p in proposals])
        return summary

    @staticmethod
    def _files_from(listing):
        return {f["p"]: f for f in listing.get("files", []) if isinstance(f, dict) and f.get("p")}

    def _inventory(self, listing):
        ignore = tuple(self.opts["ignore_paths"])
        return {p: [f.get("h"), f.get("s"), f.get("m")] for p, f in self._files_from(listing).items()
                if not p.startswith(ignore)}

    def _applied(self, kinds):
        return [p for p in self.queue.proposals.values() if p["status"] == "applied" and p["kind"] in kinds]

    def _files(self, fs, status, listing, summary):
        cur = self._inventory(listing)
        summary["files"] = len(cur)
        base = self.state.data.get("baseline")
        if not base or not base.get("files"):
            base = self.state.data["baseline"] = {"files": dict(cur), "at": _now(), "trusted": False, "by": "",
                                                  "wp_version": status.get("wp_version")}
            self._event("baseline", "INFO", f"Integrity baseline recorded ({len(cur)} files)",
                        "Recorded automatically on the first check. Once the site is known to be clean, confirm it "
                        "with Trust current files.")
        bfiles = base["files"]
        added = [p for p in cur if p not in bfiles]
        removed = [p for p in bfiles if p not in cur]
        modified = [p for p in cur if p in bfiles and _differs(cur[p], bfiles[p])]
        summary.update(added=len(added), modified=len(modified), removed=len(removed))

        # Fixes still applied whose result no longer holds (a quarantined file is back, a restored one changed)
        file_fixes = self._applied(("file",))
        guarded = set()
        for p in file_fixes:
            path, now = p["data"].get("path"), cur.get(p["data"].get("path"))
            new_md5 = (p.get("applied") or {}).get("new_md5")
            if now and (p["action"] == "quarantine" or (p["action"] in REPLACE_ACTIONS and now[0] != new_md5)):
                guarded.add(path)
        summary["guards"] += len(file_fixes)

        focus = set(added) | set(modified) | guarded
        props = []
        fs.files, fs.status = self._files_from(listing), status   # for an investigation, even with no changes
        if focus:
            fs.run(self.expect_ja, focus=focus, status=status, listing=listing)
            props = file_proposals(fs)
            covered = {subject(p) for p in props}
            for p in file_fixes:   # a quarantined file that is back but matched nothing: still worth a decision
                path = p["data"].get("path")
                if p["action"] != "quarantine" or path not in guarded or "file:" + path in covered or not cur[path][0]:
                    continue
                same = cur[path][0] == p["data"].get("md5")
                extra = {} if same else {"auto_ok": False}
                props.append({**_proposal(
                    "file", "quarantine", path,
                    f"This file was quarantined on {p.get('applied_at')} and is back at the same path"
                    + (" with the same content." if same else ". Its content is different and matched no malware "
                       "signature, so check it before approving."),
                    "low" if same else "medium", cur[path][0], {"path": path, "md5": cur[path][0]},
                    preview=p.get("preview") or "", source="Integrity monitor"), **extra})

        # Fold explained changes into the baseline; keep the rest as unexplained until someone trusts them
        proposed = {p["data"].get("path") for p in props}
        hits = {h["path"]: h for h in fs.hits}
        flagged = proposed | set(hits)
        quarantined = {p["data"]["path"] for p in file_fixes if p["action"] == "quarantine"}
        fixed_md5 = {p["data"]["path"]: (p.get("applied") or {}).get("new_md5") for p in file_fixes
                     if p["action"] in REPLACE_ACTIONS}
        undone = {(p["data"].get("path"), p["data"].get("md5")) for p in self.queue.proposals.values()
                  if p["status"] == "undone" and p["kind"] == "file"}
        drift = self.state.data.setdefault("drift", {})
        verified = 0
        for path in added + modified + removed:
            entry = cur.get(path)
            explained = (path in fs.verified or (entry is None and path in quarantined)
                         or (entry and fixed_md5.get(path) and entry[0] == fixed_md5[path])
                         or (entry and (path, entry[0]) in undone))
            if explained and path not in flagged:
                verified += path in fs.verified
                if entry is None:
                    bfiles.pop(path, None)
                else:
                    bfiles[path] = entry
                drift.pop(path, None)
                continue
            change = "added" if path in added else "removed" if path in removed else "modified"
            md5 = entry[0] if entry else None
            known = drift.get(path)
            if known and known.get("md5") == md5 and known.get("change") == change:
                known["flagged"] = path in flagged
                continue
            drift[path] = {"change": change, "md5": md5, "seen": _now(), "flagged": path in flagged,
                           "mtime": entry[2] if entry else None}
            if path not in flagged and change != "removed":
                self._event("drift", "LOW", f"Unexplained change: {path} ({change})",
                            "Not part of an official update and no malware signature matched. Trust current files "
                            "once you know the change is yours.", path=path)
            elif path in hits and path not in proposed:   # e.g. a signature in theme code: reported, no safe fix
                self._event("suspicious", "MEDIUM", f"Changed file matches a malware signature: {path}",
                            ", ".join(hits[path]["signatures"]), path=path)
        for path in [p for p in drift if p not in added + modified + removed]:
            drift.pop(path)   # back to its baseline state
        if len(drift) > MAX_DRIFT:
            for path in sorted(drift, key=lambda p: drift[p]["seen"])[:len(drift) - MAX_DRIFT]:
                drift.pop(path)
        base["wp_version"] = status.get("wp_version")
        summary.update(verified=verified, unexplained=sum(1 for d in drift.values() if not d["flagged"]))
        return props

    def _guards(self, summary):
        """Re-check applied content and account fixes; proposals for the ones that no longer hold."""
        out = []
        for p in self._applied(("content", "account"))[: self.opts["max_guards"]]:
            summary["guards"] += 1
            d = p["data"]
            if p["kind"] == "content":
                ctype = wordpress.content_type(d.get("route"))
                status, item = self.site.wp("GET", f"{d.get('route')}/{d.get('item_id')}", params={"context": "edit"})
                if not ctype or status != 200 or not isinstance(item, dict) or item.get("status") == "trash":
                    continue
                entry = wordpress.inspect_item(self.site, self.cfg, self.expect_ja, ctype, item)
                if entry and entry["heuristic"] == "spam":
                    entry.pop("_text", None)
                    out += content_proposals(self.site, [entry], self.expect_ja, self.cfg)
            elif p["action"] == "demote_user":
                status, user = self.site.wp("GET", f"/wp/v2/users/{d['user_id']}", params={"context": "edit"})
                roles = (user or {}).get("roles") or [] if isinstance(user, dict) else []
                if status == 200 and set(roles) - {"subscriber"}:
                    name = user.get("username") or user.get("slug") or f"user #{d['user_id']}"
                    out.append(_proposal("account", "demote_user", f"account '{name}' ({', '.join(roles)})",
                                         f"Demoted to subscriber on {p.get('applied_at')} and given the roles "
                                         f"{', '.join(roles)} again since: demote it again, then find who changed it.",
                                         "medium", f"{d['user_id']}:{','.join(roles)}",
                                         {"user_id": d["user_id"], "roles": roles}, source="Integrity monitor",
                                         key=f"user:{d['user_id']}"))
        return out

    # ---- after a cycle or a scan: events, automatic recovery, investigation -----------
    def respond(self, merged, fs=None, summary=None, source="scan", seen=(), announce=None):
        """Raise events for new problems and for problems that came back, recover the eligible ones and start an
        investigation. `seen`: ids of every proposal found this time, so a reinfection that is still there is
        recovered once automatic recovery is switched on. `announce(p)`: whether a new problem deserves an event
        (default: all). Expects self.lock to be held and self.state loaded."""
        summary = summary if summary is not None else {}
        self.queue.load()
        reinfections = [pid for pid in merged.get("reinfections") or [] if pid in self.queue.proposals]
        waiting = [pid for pid in seen if pid not in reinfections and pid in self.queue.proposals
                   and self.queue.proposals[pid]["status"] == "pending" and self.queue.proposals[pid].get("reinfection")]
        new = [pid for pid in merged.get("new_ids") or [] if pid not in reinfections and pid in self.queue.proposals
               and (announce is None or announce(self.queue.proposals[pid]))]
        for pid in reinfections:
            p, r = self.queue.proposals[pid], self.queue.proposals[pid]["reinfection"]
            if scope(p) == "compromise":
                title, severity = f"Reinfection: {p['target']}", "CRITICAL"
            else:
                title, severity = f"Came back: {p.get('title') or p['target']}", \
                    "HIGH" if p.get("severity") in ("HIGH", "CRITICAL") else "MEDIUM"
            how = {"fix": f"Fixed on {r.get('fixed_at')} (approved by {r.get('approved_by') or 'unknown'})",
                   "fixed by hand": f"Marked fixed by hand on {r.get('fixed_at')} by {r.get('fixed_by') or 'unknown'}",
                   }.get(r.get("how", "fix"), f"Gone since {r.get('fixed_at')} without a fix from the agent")
            self._event("reinfection", severity, title, f"{how}, and found again by the {source}. Time "
                        f"{r.get('count')} it came back.", proposal=pid, subject=subject(p), check=scope(p))
        for pid in new:
            p = self.queue.proposals[pid]
            what = "infection" if scope(p) == "compromise" else "problem"
            self._event("infection", "HIGH", f"New {what} found by the {source}: {p.get('title') or p['target']}",
                        p["why"], proposal=pid, subject=subject(p), check=scope(p))
        summary["reinfections"] = len(reinfections)
        summary["recovered"] = self.auto_recover(reinfections + waiting) if reinfections or waiting else 0
        if reinfections or new:
            self._investigate(reinfections + new, fs, "reinfection" if reinfections else "new infection")
        return self.new_events

    def hold_reason(self, p):
        """Why a reinfection proposal must wait for a person, or None when it can be recovered automatically."""
        r = p.get("reinfection") or {}
        subj = subject(p)
        if p["status"] != "pending":
            return f"It is {p['status']}, not pending."
        if p["action"] not in self.opts["auto_actions"]:
            return "This kind of fix is never applied automatically." if p["action"] != "manual" else \
                "It has to be fixed by hand."
        if p.get("auto_ok") is False:
            return "The file at this path is different from the one that was quarantined and matched no malware " \
                   "signature, so a person has to decide."
        if not by_person(r.get("approved_by")):
            return "The original fix wasn't approved by a person."
        if subj in self.state.data["blocked"]:
            return f"Automatic recovery is stopped for this target: {self.state.data['blocked'][subj]['reason']}"
        if not (self.site.wp_auth and self.site.secure):
            return "Fixes need the site's WordPress application password and an https:// address."
        now = datetime.now(timezone.utc)
        recent = [x for x in self.state.data["recoveries"] if (_parse(x["time"]) or now) > now - timedelta(days=7)]
        mine = [x for x in recent if x["subject"] == subj]
        if len(mine) >= self.opts["max_auto_per_target"]:
            return (f"Already recovered automatically {len(mine)} times in 7 days, so the cause is still there. A "
                    "person has to fix the root cause (see the investigation) and approve this one.")
        if sum(1 for x in recent if (_parse(x["time"]) or now) > now - timedelta(days=1)) >= self.opts["max_auto_per_day"]:
            return f"The daily limit of {self.opts['max_auto_per_day']} automatic recoveries was reached."
        return None

    def auto_recover(self, pids):
        if not self.auto_enabled():
            off = "Automatic recovery is off for this site; approve it by hand."
            for pid in pids:
                if self.queue.proposals[pid].get("auto_note") != off:
                    self.queue.annotate(pid, auto_note=off)
            return 0
        recovered = 0
        for pid in pids:
            self.queue.load()
            p = self.queue.proposals.get(pid)
            if p is None:
                continue
            reason, subj = self.hold_reason(p), subject(p)
            if reason:
                if reason != p.get("auto_note"):   # once per reason, not on every cycle
                    self.queue.annotate(pid, auto_note=reason)
                    limit = reason.startswith("Already recovered")
                    self._event("escalated" if limit else "held", "HIGH",
                                f"Not recovered automatically: {p['target']}", reason, proposal=pid, subject=subj, check=scope(p))
                continue
            r = p["reinfection"]
            by = f"{AUTO_BY} (reinfection of {r['of']}, first approved by {r['approved_by']})"
            result = self.queue.decide(pid, "approve", by, self.site, self.backup_dir, self.cfg)
            ok = result.get("status") == "applied" and bool(result.get("verified"))
            self.state.data["recoveries"] = (self.state.data["recoveries"] + [
                {"time": _now(), "subject": subj, "proposal": pid, "ok": ok, "status": result.get("status")}])[-500:]
            if ok:
                recovered += 1
                self.queue.annotate(pid, auto_note=None)
                self._event("recovered", "MEDIUM", f"Recovered automatically: {p['target']}",
                            f"{p['action']}: {result.get('verification')}", proposal=pid, subject=subj, check=scope(p))
            else:
                why = result.get("error") if result.get("status") == "failed" else \
                    f"Applied but not verified: {result.get('verification')}"
                self.state.data["blocked"][subj] = {"reason": f"the automatic fix on {_now()} failed ({why})",
                                                    "time": _now(), "proposal": pid}
                self._event("recovery_failed", "HIGH", f"Automatic recovery failed: {p['target']}",
                            f"{why} Automatic recovery is stopped for this target until a person allows it again.",
                            proposal=pid, subject=subj, check=scope(p))
        return recovered

    def _investigate(self, pids, fs, reason, force=False):
        """Run an investigation unless the same targets were investigated within the cooldown."""
        last = (self.state.data["investigations"] or [None])[-1]
        subjects = sorted({subject(self.queue.proposals[pid]) for pid in pids if pid in self.queue.proposals})
        if not force and last and set(subjects) <= set(last.get("subjects") or []):
            age = datetime.now(timezone.utc) - (_parse(last["time"]) or datetime.min.replace(tzinfo=timezone.utc))
            if age < timedelta(minutes=self.opts["investigate_cooldown_minutes"]):
                return None
        checks = sorted({scope(self.queue.proposals[pid]) for pid in pids if pid in self.queue.proposals})
        trigger = {"reason": reason, "proposals": pids, "subjects": subjects, "checks": checks}
        if self.investigator:   # e.g. the security monitor's own investigation (security_agent/guard.py)
            report = self.investigator(self, trigger)
        else:
            report = investigate(self.site, self.cfg, self.queue, files=fs.files if fs else None,
                                 status=fs.status if fs else None, trigger=trigger, out_dir=self.out_dir)
        entry = {"id": report["id"], "time": report["time"], "reason": reason, "summary": report["summary"],
                 "subjects": subjects, "checks": checks,
                 "causes": [{k: c[k] for k in ("confidence", "title", "detail", "actions")} for c in report["causes"][:8]],
                 "files": report["files"]}
        self.state.data["investigations"] = (self.state.data["investigations"] + [entry])[-MAX_INVESTIGATIONS:]
        self._event("investigation", "INFO", "Root-cause investigation finished", report["summary"],
                    investigation=report["id"], check=checks[0] if len(checks) == 1 else None)
        return report

    def investigate_now(self, reason="requested"):
        """An investigation on demand (dashboard / command line), covering what is waiting or was reinfected."""
        with self.lock:
            self.state.load()
            self.queue.load()
            self.new_events = []
            pids = [p["id"] for p in self.queue.proposals.values()
                    if p["status"] in ("pending", "failed") or p.get("reinfection")]
            fs = FileScan(self.site, self.cfg)
            status, listing = fs.fetch() if (self.site.wp_auth and self.site.secure) else (None, None)
            if listing is not None:
                fs.files, fs.status = self._files_from(listing), status
            report = self._investigate(pids, fs if listing is not None else None, reason, force=True)
            self.state.save()
            return report

    # ---- for the dashboard ------------------------------------------------------
    def status(self):
        self.state.load()
        d, base = self.state.data, self.state.data.get("baseline") or {}
        now = datetime.now(timezone.utc)
        day = [x for x in d["recoveries"] if (_parse(x["time"]) or now) > now - timedelta(days=1)]
        own = d.get("auto_recover")
        return {
            "enabled": bool(self.opts["enabled"]),
            "can_watch": bool(self.site.wp_auth and self.site.secure),
            "interval_minutes": self.opts["watch_interval_minutes"],
            "auto_recover": self.auto_enabled(),
            "auto_source": "site" if own is not None else "config",
            "limits": {k: self.opts[k] for k in ("max_auto_per_day", "max_auto_per_target", "auto_actions")},
            "recoveries_today": len(day),
            "baseline": {k: base.get(k) for k in ("at", "trusted", "by", "wp_version")} | {"files": len(base.get("files") or {})}
            if base else None,
            "last_check": d.get("last_check"),
            "drift": sorted(({"path": p, **v} for p, v in d["drift"].items()), key=lambda x: x["seen"], reverse=True)[:200],
            "events": d["events"][-80:][::-1],
            "investigations": d["investigations"][::-1],
            "blocked": d["blocked"],
            "guards": sum(1 for p in self.queue.load().proposals.values() if p["status"] == "applied"),
        }


def after_scan(site, cfg, queue, merged, result, proposals=(), backup_dir=None, out_dir="reports/site_guard"):
    """Phase 3 part of a full scan: events, automatic recovery and investigation for what the scan merged
    (`proposals`: everything the scan proposed). Returns the new events."""
    if not settings(cfg)["enabled"]:
        return []
    monitor = IntegrityMonitor(site, cfg, queue, backup_dir, out_dir)
    with monitor.lock:
        monitor.state.load()
        monitor.new_events = []
        fs = result.get("file_scan")
        monitor.respond(merged, fs if fs is not None and fs.files else None, source="scan",
                        seen=[p["id"] for p in proposals])
        monitor.state.save()
    return monitor.new_events
