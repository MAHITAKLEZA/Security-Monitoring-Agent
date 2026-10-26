"""Phase 2: safe remediation. Nothing here runs unless a person approves the proposal.

  propose   turn Phase 1 results into concrete, reviewable fixes (proposals), each with a preview and a risk level:
              content  trash a spam item / restore the newest clean revision / strip the injected blocks
              account  demote a recently created account that wrote spam
              file     quarantine a malicious file / restore a modified core or plugin file from the official
                       wordpress.org copy (clean baseline) / remove malicious lines from .htaccess or .user.ini
            Anything that can't be fixed safely becomes a "manual" proposal that explains what to do.
  apply     for one approved proposal: refuse if the target changed since the scan, back it up locally, make the
            change (files: through the Site Guard plugin, which keeps the original in its quarantine folder), then
            verify the fix (the item, file or spam URL is checked again).
  undo      put the original back.
"""

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

from .files import API, ORG_HEADERS, core_checksums, plugin_checksums
from .scoring import score, spam_kinds, strip_html, verdict
from .site import GOOGLEBOT_UA, days_since
from .wordpress import _raw, code_problems

BLOCK_TOKEN = re.compile(r"<!--\s+(/)?wp:[a-z0-9/-]+(?:\s+\{.*?\})?\s*(/)?-->", re.S)
RECENT_ACCOUNT_DAYS = 30
SVN_CORE = ("https://core.svn.wordpress.org/tags/{version}/{path}",
            "https://raw.githubusercontent.com/WordPress/WordPress/{version}/{path}")   # official read-only mirror
SVN_PLUGIN = ("https://plugins.svn.wordpress.org/{slug}/tags/{version}/{rel}",
              "https://plugins.svn.wordpress.org/{slug}/trunk/{rel}")
# .htaccess / .user.ini lines that are malicious on their own, and rewrite blocks that send search engines elsewhere
BAD_CONFIG_LINE = re.compile(r"auto_(?:prepend|append)_file|(?:AddHandler|AddType|SetHandler)[^\n]*(?:php|x-httpd)"
                             r"[^\n]*\.(?:jpe?g|png|gif|ico|txt|html?)\b", re.I)
SEARCH_COND = re.compile(r"RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|yandex|baidu|bot|"
                         r"spider|crawl)", re.I)
BAD_RULE = re.compile(r"RewriteRule\s+\S*\\?\.html?\$?\S*\s+\S*\.php\?", re.I)
EXTERNAL_TARGET = re.compile(r"RewriteRule\s+\S+\s+(https?://[^\s\[]+)", re.I)

MANUAL_STEPS = [
    "Google Search Console > Settings > Users and permissions: remove owners and users you don't recognise. "
    "Attackers verify themselves as owners to submit their spam sitemaps.",
    "Delete unknown Google verification files (google*.html) and meta tags you didn't add.",
    "Make the spam URLs return 404 or 410, then ask Google to drop them with Search Console > Removals. The list is "
    "in the spam URL file next to the report.",
    "Regenerate the sitemap and resubmit it in Search Console. Remove sitemap lines you didn't add from robots.txt.",
    "Change every WordPress administrator password, revoke unknown application passwords, delete unknown accounts, "
    "rotate hosting/SFTP/database passwords and the salts in wp-config.php.",
    "Update WordPress core, themes and plugins, and remove the ones you don't use. The hack usually gets in through "
    "an outdated plugin.",
]


# ---- content helpers ------------------------------------------------------------------
def _units(markup):
    """Split content into removable units: top-level Gutenberg blocks, or paragraphs for classic content.
    Joining the units gives back the original markup."""
    if "<!-- wp:" not in markup:
        return re.split(r"(?<=\n)(?=\s*\n)", markup)
    units, depth, start = [], 0, 0
    for match in BLOCK_TOKEN.finditer(markup):
        closing, self_closing = match.group(1), match.group(2)
        if depth == 0 and match.start() > start:
            units.append(markup[start:match.start()])
            start = match.start()
        if self_closing:
            if depth == 0:
                units.append(markup[start:match.end()])
                start = match.end()
        elif closing:
            depth = max(depth - 1, 0)
            if depth == 0:
                units.append(markup[start:match.end()])
                start = match.end()
        else:
            depth += 1
    if start < len(markup):
        units.append(markup[start:])
    return units


def _dangerous(site, markup, cfg):
    """Injected code other than a plain external script embed."""
    return [p for p in code_problems(site, markup, cfg) if p[0] != "external script"]


def _is_clean(site, markup, expect_ja, cfg):
    return verdict(score(strip_html(markup)), expect_ja) != "spam" and not _dangerous(site, markup, cfg)


def _strip(site, markup, expect_ja, cfg, snippet=""):
    """(cleaned content, removed units) with spam and malicious-code units removed, or (None, []) if the spam can't
    be separated from legitimate content."""
    kept, removed = [], []
    for unit in _units(markup):
        text = strip_html(unit)
        sc = score(text)
        spam_unit = (verdict(sc, expect_ja, min_kana=2) == "spam" and (sc["ratio"] >= 0.3 or not sc["kana"])) or \
            bool(snippet and snippet.strip() and snippet.strip()[:60] in text) or bool(_dangerous(site, unit, cfg))
        (removed if spam_unit else kept).append(unit)
    cleaned = "".join(kept)
    if not removed or not strip_html(cleaned) or not _is_clean(site, cleaned, expect_ja, cfg):
        return None, []
    return cleaned, removed


def _clean_revision(site, item, expect_ja, cfg):
    status, revisions = site.wp("GET", f"{item['route']}/{item['id']}/revisions",
                                params={"context": "edit", "per_page": 100})
    if status != 200 or not isinstance(revisions, list):
        return None
    for rev in revisions:  # newest first
        content, title = _raw(rev.get("content")), _raw(rev.get("title"))
        if content and _is_clean(site, f"{title} {content}", expect_ja, cfg):
            return rev
    return None


def clean_config(text):
    """(cleaned text, removed lines) for .htaccess / .user.ini / php.ini. A rewrite block (its RewriteCond lines and
    RewriteRule) is removed when it sends search engines or search visitors to a PHP script or another domain;
    blocks that only forbid access ([F]) are kept."""
    out, removed, block = [], [], []

    def flush(bad):
        (removed if bad else out).extend(block)
        block.clear()

    for line in text.splitlines(keepends=True):
        s = line.strip()
        if re.match(r"RewriteCond\b", s, re.I):
            block.append(line)
            continue
        if re.match(r"RewriteRule\b", s, re.I):
            block.append(line)
            forbids = re.search(r"\[[^\]]*\bF\b[^\]]*\]|\s-\s*\[", s)
            external = EXTERNAL_TARGET.search(s)
            bad = not forbids and (bool(BAD_RULE.search(s)) or any(SEARCH_COND.search(b) for b in block)
                                   and bool(external or re.search(r"\.php\b", s)))
            flush(bad)
            continue
        if block:
            flush(False)
        (removed if BAD_CONFIG_LINE.search(s) else out).append(line)
    if block:
        flush(False)
    return "".join(out), removed


# ---- proposals --------------------------------------------------------------------------
def _proposal(kind, action, target, why, risk, fingerprint, data, preview="", source="", key=None):
    """key identifies what is being fixed (post route#id, file path, user id); target is only for display."""
    pid = hashlib.sha1(f"{action}|{key or target}|{fingerprint}".encode()).hexdigest()[:12]
    return {"id": pid, "kind": kind, "action": action, "target": target, "why": why, "risk": risk,
            "fingerprint": fingerprint, "data": data, "preview": preview[:4000], "source": source, "status": "pending"}


def content_proposals(site, items, expect_ja, cfg):
    out = []
    for item in items:
        if item["kind"] != "spam" and not item["kinds"] and not any(p != "external script" for p, _ in item["code"]) \
                and not item.get("ai"):
            continue   # only external script embeds: reported, nothing to fix
        raw = item["raw"]
        target = f"{item['label']} #{item['id']} \"{item['title'][:60]}\" ({item['status']})"
        key = f"{item['route']}#{item['id']}"
        fp = item.get("modified") or hashlib.md5(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()
        data = {"route": item["route"], "item_id": item["id"], "link": item["link"], "status": item["status"],
                "modified": item.get("modified")}
        if item.get("ai") and item["ai"]["confidence"] == "low":
            out.append(_proposal("content", "manual", target, "Unclear whether this is spam; review it by hand.",
                                 "none", fp, data, source="WordPress content", key=key))
            continue
        if item["kind"] == "spam" and item["trashable"]:
            out.append(_proposal("content", "trash", target,
                                 "The whole item is spam created by the attacker. It moves to the WordPress trash "
                                 "(restorable for 30 days) and its URL stops serving spam.", "low", fp, data,
                                 preview=strip_html(_raw(raw.get("content")))[:600], source="WordPress content", key=key))
            continue
        content = _raw(raw.get("content"))
        rev = _clean_revision(site, item, expect_ja, cfg) if item["revisions"] else None
        cleaned, removed = _strip(site, content, expect_ja, cfg, (item.get("ai") or {}).get("spam_snippet", ""))
        if cleaned is not None:
            out.append(_proposal("content", "strip_spam", target, f"Remove {len(removed)} injected block(s) and keep "
                                 "the rest of the content unchanged.", "low", fp,
                                 {**data, "new": {"content": cleaned}},
                                 preview="Removed:\n" + "\n---\n".join(u.strip()[:800] for u in removed),
                                 source="WordPress content", key=key))
        elif rev:
            when = rev.get("modified_gmt") or rev.get("date_gmt")
            out.append(_proposal("content", "restore_revision", target,
                                 f"Restore revision {rev.get('id')} from {when}, the newest one without spam. Edits made "
                                 "after it are lost (they stay in the revision history).", "medium", fp,
                                 {**data, "revision_id": rev.get("id"),
                                  "new": {"title": _raw(rev.get("title")), "content": _raw(rev.get("content")),
                                          "excerpt": _raw(rev.get("excerpt"))}},
                                 preview=f"Revision {rev.get('id')} ({when}):\n" + strip_html(_raw(rev.get("content")))[:800],
                                 source="WordPress content", key=key))
        else:
            out.append(_proposal("content", "manual", target, "No clean revision and the spam can't be separated "
                                 "automatically; edit it by hand.", "none", fp, data, source="WordPress content",
                                 key=key))
    return out


def account_proposals(site, items):
    users = getattr(site, "wp_users", {}) or {}
    me = (getattr(site, "login_user", None) or {}).get("id")
    out = []
    for uid in sorted({i["author"] for i in items if i["author"] and (i["kind"] == "spam" or i["kinds"])}):
        u = users.get(uid)
        if not u or uid == me or not set(u.get("roles") or []) - {"subscriber"}:
            continue   # a subscriber can't publish or change anything
        name = u.get("username") or u.get("slug") or f"user #{uid}"
        age = days_since(u.get("registered_date"))
        target = f"account '{name}' ({', '.join(u.get('roles') or [])})"
        if age is not None and age <= RECENT_ACCOUNT_DAYS:
            out.append(_proposal("account", "demote_user", target,
                                 f"Created {age} day(s) ago and wrote spam: demote it to subscriber so it can't publish "
                                 "or change anything. Delete it in wp-admin once you're sure.", "medium",
                                 f"{uid}:{','.join(u.get('roles') or [])}", {"user_id": uid, "roles": u.get("roles")},
                                 source="WordPress accounts", key=f"user:{uid}"))
        else:
            out.append(_proposal("account", "manual", target, "An established account wrote spam, so its password was "
                                 "probably stolen: reset its password and revoke its application passwords.", "none",
                                 f"{uid}", {"user_id": uid}, source="WordPress accounts", key=f"user:{uid}"))
    return out


def file_proposals(fs):
    """Proposals from a FileScan (files.py)."""
    if fs is None or not fs.files:
        return []
    out, done = [], set()
    hits = {h["path"]: h for h in fs.hits}
    benign = lambda p: bool(hits.get(p, {}).get("ai")) and hits[p]["ai"]["classification"] == "benign"
    md5 = lambda p: (fs.files.get(p) or {}).get("h") or ""

    def quarantine(path, why, risk="low"):
        if path in done or benign(path) or not md5(path):
            return
        done.add(path)
        h = hits.get(path)
        out.append(_proposal("file", "quarantine", path, why + " It moves to the plugin's locked quarantine folder and "
                             "can be restored.", risk, md5(path), {"path": path, "md5": md5(path)},
                             preview=(", ".join(h["signatures"]) + "\n\n" + h["snippet"]) if h else "",
                             source="Files"))

    issues = fs.issues
    for p in issues.get("core_modified", []):
        done.add(p)
        out.append(_proposal("file", "restore_core", p, f"Replace with the official WordPress {fs.wp_version} copy "
                             "(checked against wordpress.org's checksum before it is written).", "low", md5(p),
                             {"path": p, "md5": md5(p), "version": fs.wp_version},
                             preview=("Signatures: " + ", ".join(hits[p]["signatures"]) + "\n\n" + hits[p]["snippet"])
                             if p in hits else "Differs from the official file.", source="Files"))
    for p in issues.get("core_unknown", []):
        quarantine(p, "Not part of WordPress but placed in a core folder.")
    for p in issues.get("uploads_php", []):
        quarantine(p, "PHP file in the uploads folder (almost always a web shell).")
    for p in issues.get("disguised_uploads", []):
        quarantine(p, "Script with a second extension in the uploads folder (a disguised web shell).")
    for p, h in hits.items():
        if any("uploaded image" in s for s in h["signatures"]):
            quarantine(p, "Uploaded image with PHP code hidden inside it.")
    plugins_dir = issues.get("plugins_dir") or ""
    for p in issues.get("plugin_modified", []):
        slug, rel = p[len(plugins_dir) + 1:].split("/", 1)
        done.add(p)
        out.append(_proposal("file", "restore_plugin_file", p, f"Replace with the official {slug} "
                             f"{fs.plugins.get(slug)} copy from wordpress.org (checksum verified).", "low", md5(p),
                             {"path": p, "md5": md5(p), "slug": slug, "version": fs.plugins.get(slug), "rel": rel},
                             preview=("Signatures: " + ", ".join(hits[p]["signatures"]) + "\n\n" + hits[p]["snippet"])
                             if p in hits else "Differs from the official file.", source="Files"))
    for p in issues.get("plugin_unknown", []) + issues.get("root_php", []) + issues.get("mu_plugins", []):
        if p in hits:
            quarantine(p, "Unknown file that matched malware signatures.", "medium")
    for p, h in hits.items():
        name = p.rsplit("/", 1)[-1].lower()
        if p in done or benign(p):
            continue
        if name.endswith(".ico") and any("ico" in s for s in h["signatures"]):
            quarantine(p, "PHP code hidden in an icon file.")
        elif name in (".htaccess", ".user.ini", "php.ini"):
            text = fs.texts.get(p, "")
            cleaned, removed = clean_config(text)
            done.add(p)
            if removed and cleaned != text:
                new = cleaned.encode("utf-8")
                out.append(_proposal("file", "clean_config", p, f"Remove {len(removed)} malicious line(s); the rest "
                                     "of the file is kept.", "medium", md5(p),
                                     {"path": p, "md5": md5(p), "new_b64": base64.b64encode(new).decode(),
                                      "new_md5": hashlib.md5(new).hexdigest()},
                                     preview="Lines removed:\n" + "".join(removed), source="Files"))
            else:
                out.append(_proposal("file", "manual", p, "Suspicious server configuration that can't be cleaned "
                                     "line by line; review it by hand.", "none", md5(p), {"path": p},
                                     preview=h["snippet"], source="Files"))
        elif h["severity"] in ("HIGH", "CRITICAL"):
            done.add(p)
            out.append(_proposal("file", "manual", p, "Malicious code inside a file the site needs (theme or custom "
                                 "code), so it can't be quarantined safely. Remove the code by hand or reinstall the "
                                 "theme/plugin.", "none", md5(p), {"path": p},
                                 preview=", ".join(h["signatures"]) + "\n\n" + h["snippet"], source="Files"))
    return out


def build_proposals(site, result, cfg):
    """All proposals for a Phase 1 result (SiteGuardAgent.scan())."""
    items = result.get("items") or []
    return (content_proposals(site, items, result.get("expect_japanese"), cfg) + account_proposals(site, items)
            + file_proposals(result.get("file_scan")))


# ---- apply / verify / undo ----------------------------------------------------------------
class RemediationError(Exception):
    pass


def _download(urls, expected):
    for url in urls:
        try:
            resp = requests.get(url, timeout=60, headers=ORG_HEADERS)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and hashlib.md5(resp.content).hexdigest() in expected:
            return resp.content
    return None


ACTIONS = {}   # action -> handler with apply(remediator, proposal) and undo(remediator, proposal, applied)


def register(action, handler):
    """Add a fix type from outside this module (security_agent/fixes.py adds the fixes for the security checks).
    The handler's apply() returns the same dict as the built-in ones, including verified and verification."""
    ACTIONS[action] = handler


class Remediator:
    def __init__(self, site, backup_dir, cfg=None):
        self.site, self.cfg = site, cfg or {}
        self.backup_dir = Path(backup_dir)

    def _backup(self, proposal, payload):
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = self.backup_dir / f"{stamp}-{proposal['id']}.json"
        path.write_text(json.dumps({"proposal": {k: v for k, v in proposal.items() if k != "data"},
                                    "original": payload}, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        return str(path)

    def _wp(self, method, route, **kwargs):
        status, data = self.site.wp(method, route, **kwargs)
        if status is None:
            raise RemediationError("Could not reach the site.")
        if status in (401, 403):
            raise RemediationError(f"WordPress refused the change (HTTP {status}): the application password must "
                                   "belong to an administrator.")
        if status == 404 and route.startswith(API):
            raise RemediationError("The Kleza Site Guard plugin (v1.1 or newer) is not active on the site.")
        if status == 409:
            raise RemediationError("The target changed since the scan. Scan again, then review the new proposal.")
        if status >= 400:
            message = data.get("message") if isinstance(data, dict) else None
            raise RemediationError(f"HTTP {status}: {message or 'request failed'}")
        return data

    # ---- apply ----
    def apply(self, p):
        """Apply one approved proposal. Returns a dict for the queue: message, backup, undo info, verification."""
        if p["action"] in ACTIONS:
            return ACTIONS[p["action"]].apply(self, p)
        handler = getattr(self, f"_apply_{p['action']}", None)
        if handler is None:
            raise RemediationError("This proposal has to be fixed by hand.")
        result = handler(p, p["data"])
        ok, note = self.verify(p, result)
        result.update(verified=ok, verification=note)
        return result

    def _current_item(self, d):
        item = self._wp("GET", f"{d['route']}/{d['item_id']}", params={"context": "edit"})
        if d.get("modified") and item.get("modified_gmt") and item["modified_gmt"] != d["modified"]:
            raise RemediationError("The item was edited after the scan. Scan again, then review the new proposal.")
        return item

    def _apply_trash(self, p, d):
        item = self._current_item(d)
        backup = self._backup(p, item)
        self._wp("DELETE", f"{d['route']}/{d['item_id']}")   # no force: the trash, never a permanent delete
        return {"message": "Moved to the trash.", "backup": backup, "undo": {"status": item.get("status") or "draft"}}

    def _apply_content(self, p, d):
        item = self._current_item(d)
        backup = self._backup(p, item)
        body = {k: v for k, v in d["new"].items() if v is not None and (k == "content" or v)}
        self._wp("POST", f"{d['route']}/{d['item_id']}", json=body)
        return {"message": "Content cleaned.", "backup": backup,
                "undo": {k: _raw(item.get(k)) for k in ("title", "content", "excerpt")}}

    _apply_strip_spam = _apply_restore_revision = _apply_content

    def _apply_demote_user(self, p, d):
        user = self._wp("GET", f"/wp/v2/users/{d['user_id']}", params={"context": "edit"})
        backup = self._backup(p, {"id": user.get("id"), "username": user.get("username"), "roles": user.get("roles")})
        self._wp("POST", f"/wp/v2/users/{d['user_id']}", json={"roles": ["subscriber"]})
        return {"message": "Demoted to subscriber.", "backup": backup, "undo": {"roles": user.get("roles")}}

    def _read_file(self, path):
        data = self._wp("GET", f"{API}/file", params={"path": path})
        return base64.b64decode(data.get("content_base64") or "")

    def _apply_quarantine(self, p, d):
        original = self._read_file(d["path"])
        backup = self._backup(p, {"path": d["path"], "content_base64": base64.b64encode(original).decode()})
        entry = self._wp("POST", f"{API}/quarantine", json={"path": d["path"], "md5": d["md5"],
                                                             "reason": f"proposal {p['id']}: {p['why'][:200]}"})
        return {"message": "Moved to quarantine.", "backup": backup, "undo": {"quarantine_id": entry.get("id")}}

    def _replace(self, p, d, content, what):
        original = self._read_file(d["path"])
        backup = self._backup(p, {"path": d["path"], "content_base64": base64.b64encode(original).decode()})
        entry = self._wp("POST", f"{API}/replace", json={
            "path": d["path"], "md5": d["md5"], "content_base64": base64.b64encode(content).decode(),
            "new_md5": hashlib.md5(content).hexdigest(), "reason": f"proposal {p['id']}: {what}"})
        return {"message": what, "backup": backup, "undo": {"quarantine_id": entry.get("id")},
                "new_md5": hashlib.md5(content).hexdigest()}

    def _apply_restore_core(self, p, d):
        expected = core_checksums(d["version"], "en_US").get(d["path"])
        content = expected and _download([u.format(version=d["version"], path=d["path"]) for u in SVN_CORE], {expected})
        if not content:
            raise RemediationError("Could not download a verified official copy of this file from wordpress.org.")
        return self._replace(p, d, content, f"Restored the official WordPress {d['version']} file.")

    def _apply_restore_plugin_file(self, p, d):
        expected = (plugin_checksums(d["slug"], d["version"]) or {}).get(d["rel"])
        content = expected and _download([u.format(**d) for u in SVN_PLUGIN], expected)
        if not content:
            raise RemediationError("Could not download a verified official copy of this file from wordpress.org.")
        return self._replace(p, d, content, f"Restored the official {d['slug']} {d['version']} file.")

    def _apply_clean_config(self, p, d):
        return self._replace(p, d, base64.b64decode(d["new_b64"]), "Removed the malicious lines.")

    # ---- post-fix verification ----
    def verify(self, p, result):
        """(verified, note): the change is in place and, for content, the spam URL no longer serves spam."""
        d, action = p["data"], p["action"]
        try:
            if action == "trash":
                item = self._wp("GET", f"{d['route']}/{d['item_id']}", params={"context": "edit"})
                if item.get("status") != "trash":
                    return False, f"The item's status is {item.get('status')}, not trash."
                return self._url_clean(d.get("link"))
            if action in ("strip_spam", "restore_revision"):
                item = self._wp("GET", f"{d['route']}/{d['item_id']}", params={"context": "edit"})
                markup = f"{_raw(item.get('title'))} {_raw(item.get('content'))}"
                if not _is_clean(self.site, markup, False, self.cfg):
                    return False, "Spam is still present in the saved content."
                return self._url_clean(d.get("link"))
            if action == "demote_user":
                user = self._wp("GET", f"/wp/v2/users/{d['user_id']}", params={"context": "edit"})
                return (user.get("roles") == ["subscriber"],
                        "Account is now a subscriber." if user.get("roles") == ["subscriber"] else f"Roles: {user.get('roles')}")
            if action == "quarantine":
                status, _ = self.site.wp("GET", f"{API}/file", params={"path": d["path"]})
                return (status == 404, "The file is gone from its path." if status == 404 else f"The file is still there (HTTP {status}).")
            if action in ("restore_core", "restore_plugin_file", "clean_config"):
                content = self._read_file(d["path"])
                good = hashlib.md5(content).hexdigest() == result.get("new_md5")
                return good, "The file now matches the clean copy." if good else "The file doesn't match the clean copy."
        except RemediationError as exc:
            return False, f"Could not verify: {exc}"
        return False, "No verification for this action."

    def _url_clean(self, url):
        if not url:
            return True, "Change confirmed in WordPress."
        resp, markup = self.site.fetch(url, GOOGLEBOT_UA)
        if resp is None:
            return False, "Change confirmed in WordPress, but the page could not be loaded to check it."
        if resp.status_code in (404, 410) or not spam_kinds(score(strip_html(markup))):
            return True, f"Change confirmed; the URL now returns HTTP {resp.status_code} without spam."
        return False, f"The URL still serves spam (HTTP {resp.status_code}); a page cache may need clearing."

    # ---- undo ----
    def undo(self, p, applied):
        u, d, action = applied.get("undo") or {}, p["data"], p["action"]
        if action in ACTIONS:
            return ACTIONS[action].undo(self, p, applied)
        if action == "trash":
            self._wp("POST", f"{d['route']}/{d['item_id']}", json={"status": u.get("status") or "draft"})
            return "Restored from the trash."
        if action in ("strip_spam", "restore_revision"):
            self._wp("POST", f"{d['route']}/{d['item_id']}", json={k: u.get(k, "") for k in ("title", "content", "excerpt")})
            return "Original content restored."
        if action == "demote_user":
            self._wp("POST", f"/wp/v2/users/{d['user_id']}", json={"roles": u.get("roles") or []})
            return "Original roles restored."
        if u.get("quarantine_id"):
            self._wp("POST", f"{API}/restore", json={"id": u["quarantine_id"]})
            return "Original file restored from quarantine."
        raise RemediationError("Nothing to undo for this proposal.")
