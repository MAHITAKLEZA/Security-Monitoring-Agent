"""Phase 2 approval queue: proposals waiting for a decision, what was done, and an audit history.

One JSON file per site (state/remediation/<host>.json by default), shared by the dashboard and the command line.
Statuses: pending -> approved -> applied (verified or not) | failed;  pending -> rejected;  applied -> undone.
A pending proposal that a later scan no longer produces becomes "resolved" (fixed some other way); a resolved or
undone one whose problem is detected again goes back to pending.
Each proposal's id is derived from the action, what is being fixed and its fingerprint (checksum or modification
time), so the same infection keeps the same id across scans and its decision is remembered.

Reinfection (Phase 3): a problem found again on a file, content item or account whose fix is still applied. The same
infection (same id) goes back to pending with the earlier fix kept in past_fixes; a different one on the same target
is linked to that fix. Either way the proposal gets a "reinfection" record (which fix, who approved the original,
how many times) that the integrity monitor uses to decide on automatic recovery (defense.py).
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .remediate import RemediationError, Remediator

_LOCKS = {}
_LOCKS_GUARD = threading.Lock()
MAX_HISTORY = 500
AUTO_BY = "auto-recovery"     # decided_by prefix for fixes applied by the integrity monitor, not a person
REFRESH = ("why", "risk", "data", "preview", "source", "severity", "title")   # updated from each new detection


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def queue_path(queue_dir, host):
    return Path(queue_dir or "state/remediation") / f"{host}.json"


def subject(p):
    """What a proposal fixes, whatever its fingerprint: one file, content item, account or security problem."""
    d = p.get("data") or {}
    if d.get("subject"):
        return d["subject"]
    if p.get("kind") == "file" and d.get("path"):
        return "file:" + d["path"]
    if p.get("kind") == "content" and d.get("route"):
        return f"content:{d['route']}#{d.get('item_id')}"
    if p.get("kind") == "account" and d.get("user_id") is not None:
        return f"user:{d['user_id']}"
    return f"{p.get('kind')}:{p.get('target')}"


def by_person(by):
    return bool(by) and not str(by).startswith(AUTO_BY)


def scope(p):
    """The check a proposal belongs to; Spam & Compromise proposals predate the field."""
    return p.get("check") or "compromise"


class Queue:
    def __init__(self, path, site_url=""):
        self.path = Path(path)
        with _LOCKS_GUARD:
            self.lock = _LOCKS.setdefault(str(self.path.resolve()), threading.RLock())
        self.data = {"site": site_url, "proposals": {}, "history": []}
        self.load()

    def load(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("proposals"), dict):
                self.data = data
        except (OSError, ValueError):
            pass
        return self

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        tmp.replace(self.path)

    def log(self, pid, event, by="", message=""):
        self.data["history"].append({"time": _now(), "id": pid, "event": event, "by": by, "message": message[:500]})
        self.data["history"] = self.data["history"][-MAX_HISTORY:]

    @property
    def proposals(self):
        return self.data["proposals"]

    def listing(self):
        order = {"pending": 0, "failed": 1, "approved": 2, "applied": 3, "done": 4, "undone": 5, "rejected": 6,
                 "resolved": 7}
        rank = {"high": 0, "medium": 1, "low": 2, "none": 3}
        return sorted(self.proposals.values(), key=lambda p: (order.get(p["status"], 9), rank.get(p["risk"], 9),
                                                             p["kind"], p["target"]))

    def active_fix(self, subj, exclude=None):
        """The newest fix still in effect for this target (applied, or done by hand), or None."""
        fixes = [p for p in self.proposals.values()
                 if p["status"] in ("applied", "done") and p["id"] != exclude and subject(p) == subj]
        return max(fixes, key=lambda p: p.get("applied_at") or p.get("decided_at") or "", default=None)

    @staticmethod
    def _reinfection(fix, approved=True):
        """approved=False: the problem had gone away without a fix from the agent (resolved), so there is no fix a
        person approved that could be re-applied automatically."""
        prior = fix.get("reinfection") or {}
        return {"of": fix["id"],
                "approved_by": (prior.get("approved_by") or fix.get("decided_by") or "") if approved else "",
                "count": int(prior.get("count") or 0) + 1, "detected": _now(),
                "fixed_at": fix.get("applied_at") or fix.get("decided_at") or fix.get("resolved_at"),
                "fixed_by": (fix.get("decided_by") or "") if approved else "",
                "how": {"applied": "fix", "done": "fixed by hand"}.get(fix["status"], "went away")}

    # ---- after each scan ----
    def merge(self, proposals, partial=False, scopes=("compromise",)):
        """Add new proposals, refresh pending ones, mark pending ones of the checks in `scopes` that are no longer
        found as resolved (not when `partial`: the integrity monitor only checks some targets). Returns
        {"new": n, "new_ids": [ids], "resolved": n, "reinfections": [ids]}: proposals for a problem that came back
        after it was fixed, done by hand, or had gone away."""
        with self.lock:
            self.load()
            seen, new, reinfections = set(), [], []
            for p in proposals:
                seen.add(p["id"])
                cur = self.proposals.get(p["id"])
                if cur is None:
                    cur = self.proposals[p["id"]] = {**p, "created": _now(), "last_seen": _now()}
                    self.log(p["id"], "proposed", "", f"{p['action']}: {p['target']}")
                    new.append(p["id"])
                    fix = self.active_fix(subject(p), exclude=p["id"])
                    if fix:   # something new on a target that was already fixed
                        cur["reinfection"] = self._reinfection(fix)
                        fix["reappeared"] = _now()
                        reinfections.append(p["id"])
                        self.log(p["id"], "reinfection", "", f"{p['target']} was fixed by {fix['id']} on "
                                 f"{fix.get('applied_at')} and is infected again.")
                    continue
                cur["last_seen"] = _now()
                if cur["status"] == "resolved":   # it had gone away without our fix, and it is back: a regression
                    cur.update({k: p[k] for k in REFRESH if k in p})
                    cur.update(status="pending", reinfection=self._reinfection(cur, approved=False), reappeared=_now())
                    reinfections.append(p["id"])
                    self.log(p["id"], "detected again", "", f"{p['target']} had gone away and is back.")
                elif cur["status"] in ("pending", "failed", "undone"):
                    cur.update({k: p[k] for k in REFRESH if k in p})
                    if cur["status"] == "undone":
                        cur["status"] = "pending"
                        self.log(p["id"], "detected again", "", p["target"])
                elif cur["status"] == "done":   # marked fixed by hand, found again
                    reinfection = self._reinfection(cur)
                    cur.setdefault("past_fixes", []).append({k: cur.get(k) for k in ("decided_by", "decided_at")})
                    cur.update({k: p[k] for k in REFRESH if k in p})
                    cur.update(status="pending", reinfection=reinfection, reappeared=_now())
                    reinfections.append(p["id"])
                    self.log(p["id"], "regression", "", "Marked as fixed by hand, and the problem is back.")
                elif cur["status"] == "applied":
                    # The very same infection is back: the earlier fix is kept in past_fixes and it waits again
                    reinfection = self._reinfection(cur)
                    cur.setdefault("past_fixes", []).append(
                        {k: cur.get(k) for k in ("decided_by", "decided_at", "applied_at", "applied", "verified",
                                                 "verification")})
                    cur.update({k: p[k] for k in REFRESH if k in p})
                    cur.update(status="pending", reinfection=reinfection, reappeared=_now(), applied=None,
                               verified=None, verification=None, error=None)
                    reinfections.append(p["id"])
                    self.log(p["id"], "reinfection", "", "The same problem is back after it was fixed.")
            resolved = 0
            for pid, cur in self.proposals.items():
                if not partial and pid not in seen and cur["status"] == "pending" and scope(cur) in scopes:
                    cur.update(status="resolved", resolved_at=_now())
                    resolved += 1
                    self.log(pid, "resolved", "", "No longer detected by the latest scan.")
            self.save()
            return {"new": len(new), "new_ids": new, "resolved": resolved, "reinfections": reinfections}

    def annotate(self, pid, **fields):
        """Set extra fields on a proposal (e.g. why automatic recovery was held back)."""
        with self.lock:
            self.load()
            if pid in self.proposals:
                self.proposals[pid].update(fields)
                self.save()

    # ---- decisions ----
    def decide(self, pid, decision, by, site, backup_dir, cfg=None):
        """Approve (and apply) or reject one proposal. Returns the updated proposal."""
        with self.lock:
            self.load()
            p = self.proposals.get(pid)
            if p is None:
                raise RemediationError("Unknown proposal.")
            if decision in ("reject", "done"):   # done: fixed by hand; watched for regressions like a fix
                if p["status"] not in ("pending", "failed"):
                    raise RemediationError(f"This proposal is {p['status']}, not pending.")
                p.update(status="rejected" if decision == "reject" else "done", decided_by=by, decided_at=_now())
                self.log(pid, "rejected" if decision == "reject" else "done by hand", by)
                self.save()
                return p
            if decision != "approve":
                raise RemediationError("Unknown decision.")
            if p["status"] not in ("pending", "failed"):
                raise RemediationError(f"This proposal is {p['status']}, not pending.")
            if p["action"] == "manual":
                raise RemediationError("This one has to be fixed by hand; mark it done once it is fixed.")
            p.update(status="approved", decided_by=by, decided_at=_now())
            self.log(pid, "approved", by, f"{p['action']}: {p['target']}")
            self.save()
            try:
                result = Remediator(site, backup_dir, cfg).apply(p)
            except RemediationError as exc:
                p.update(status="failed", error=str(exc), applied_at=_now())
                self.log(pid, "failed", by, str(exc))
                self.save()
                return p
            p.update(status="applied", applied=result, applied_at=_now(), error=None,
                     verified=result.get("verified"), verification=result.get("verification"))
            self.log(pid, "applied", by, f"{result['message']} Verification: {result.get('verification')}")
            self.save()
            return p

    def undo(self, pid, by, site, backup_dir, cfg=None):
        with self.lock:
            self.load()
            p = self.proposals.get(pid)
            if p is None or p["status"] != "applied":
                raise RemediationError("Only an applied fix can be undone.")
            message = Remediator(site, backup_dir, cfg).undo(p, p.get("applied") or {})
            p.update(status="undone", undone=_now(), undone_by=by)
            self.log(pid, "undone", by, message)
            self.save()
            return p
