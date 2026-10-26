"""Phase 1, file scan (WordPress, through the Kleza Site Guard plugin in wp-plugin/): read-only.

Compares WordPress core and wordpress.org plugin files with the official checksums, finds PHP files where none
belong (uploads, core folders, the site root), lists must-use plugins and recently changed code, then reads the
most suspicious files and looks for backdoors, cloaking, spam generators and injected spam. Claude reviews the
signature hits so legitimate code that happens to match (base64 in a plugin, a bot check in an SEO plugin) is
recognised instead of reported as malware.
"""

import base64
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from .scoring import describe, score, spam_kinds
from .site import Finding

API = "/kleza-guard/v1"
CODE_EXT = re.compile(r"\.(?:php\d?|phtml|phar|pht|phps|inc)$", re.I)
SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PHP_SIGS = [
    ("eval() of decoded or request data", r"\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|"
     r"strrev|rawurldecode|hex2bin|\$_(?:POST|GET|REQUEST|COOKIE|SERVER))", "CRITICAL"),
    ("assert() on request data", r"\bassert\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)", "CRITICAL"),
    ("preg_replace /e code execution", r"preg_replace\s*\(\s*['\"](.)[^'\"]*\1[imsxu]*e[imsxu]*['\"]", "CRITICAL"),
    ("shell command run from request data", r"\b(?:system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*"
     r"\$_(?:POST|GET|REQUEST|COOKIE|SERVER)", "CRITICAL"),
    ("function name taken from request data", r"\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(", "CRITICAL"),
    ("known web shell", r"FilesMan|c99shell|r57shell|\bWSO\s*[0-9.]+|b374k|AlfaTeam|IndoXploit|Mr\.Combet", "CRITICAL"),
    ("search-engine User-Agent check (cloaking)", r"HTTP_USER_AGENT[^;\n]{0,200}(?:googlebot|google|bingbot|yahoo|slurp|"
     r"baiduspider|yandex)", "HIGH"),
    ("search-engine referrer check (redirect cloaking)", r"HTTP_REFERER[^;\n]{0,200}(?:google|bing|yahoo|yandex|baidu)",
     "HIGH"),
    ("remote code downloaded and run or saved", r"(?:file_get_contents|curl_exec|fopen)\s*\([^;]{0,200}https?://"
     r"[^;]{0,300}(?:eval|include|require|file_put_contents)", "HIGH"),
    ("include of a non-PHP file", r"(?:include|require)(?:_once)?\s*\(?[^;]{0,150}\.(?:ico|png|jpe?g|gif|txt|css)['\"]",
     "HIGH"),
    ("long base64 blob (obfuscation)", r"['\"][A-Za-z0-9+/]{3000,}={0,2}['\"]", "MEDIUM"),
    ("hex-escaped string (obfuscation)", r"(?:\\x[0-9a-fA-F]{2}){60,}", "MEDIUM"),
    ("create_function() (deprecated, used by malware)", r"\bcreate_function\s*\(", "MEDIUM"),
    ("file written from request data", r"\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,120}\$_(?:POST|GET|REQUEST|COOKIE)",
     "CRITICAL"),
    ("file upload saved without checks", r"move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]tmp_name['\"]\s*\]"
     r"\s*,\s*[^;]*\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]", "HIGH"),
    ("callback run on request data", r"\b(?:call_user_func(?:_array)?|array_map|array_filter|usort|uasort|uksort|"
     r"register_shutdown_function|forward_static_call)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)", "CRITICAL"),
    ("eval of a decoded variable", r"\$(\w+)\s*=\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|strrev)"
     r"\s*\([^;]{0,3000};[^{}]{0,300}\beval\s*\(\s*\$\1\b", "CRITICAL"),
    ("backtick shell command from request data", r"`[^`\n]{0,80}\$_(?:POST|GET|REQUEST|COOKIE)[^`\n]{0,80}`", "CRITICAL"),
    ("errors silenced with remote include", r"@\s*(?:include|require)(?:_once)?\s*\(?\s*['\"]?https?://", "CRITICAL"),
    ("variable function built from character codes", r"(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}", "HIGH"),
    ("known web shell (more families)", r"Weevely|China Chopper|Mini Shell|Gecko Shell|PHPSpy|Dx\.?shell|webshell|"
     r"Priv8|Safe.?mode:\s|Uname:\s", "HIGH"),
]
HTACCESS_SIGS = [
    ("auto_prepend_file / auto_append_file", r"auto_(?:prepend|append)_file", "CRITICAL"),
    ("rewrite based on search-engine User-Agent", r"RewriteCond\s+%\{HTTP_USER_AGENT\}[^\n]*(?:google|bing|yahoo|bot|"
     r"spider|crawl)", "HIGH"),
    ("rewrite based on search-engine referrer", r"RewriteCond\s+%\{HTTP_REFERER\}[^\n]*(?:google|bing|yahoo|yandex|baidu)",
     "HIGH"),
    ("PHP execution enabled for image or text files", r"(?:AddHandler|AddType|SetHandler)[^\n]*(?:php|x-httpd)[^\n]*"
     r"\.(?:jpe?g|png|gif|ico|txt|html?)", "HIGH"),
    (".html URLs rewritten to a PHP script (spam generator)", r"RewriteRule\s+\S*\\?\.html?\$?\S*\s+\S*\.php\?", "HIGH"),
]
# Malicious uploads that hide from the plain ".php" test: a script with a second extension (shell.php.jpg, run by
# servers that map any ".php." name to PHP), pages and programs dropped among the media, and PHP inside a real image.
MEDIA_EXT = re.compile(r"\.(?:jpe?g|png|gif|webp|bmp|ico|tiff?)$", re.I)
DISGUISED_EXT = re.compile(r"\.(?:php\d?|phtml|phar|pht|phps|inc|cgi|pl|py|sh|asp|aspx|jsp|exe|dll)\.[a-z0-9]{1,5}$", re.I)
UPLOAD_PAGE_EXT = re.compile(r"\.(?:html?|xhtml|js|mjs|exe|dll|msi|bat|cmd|scr|vbs|hta|jar|sh)$", re.I)
PHP_OPEN_TAG = re.compile(r"<\?php|<\?=", re.I)
PHP_SIGS = [(n, re.compile(p, re.I), s) for n, p, s in PHP_SIGS]
HTACCESS_SIGS = [(n, re.compile(p, re.I), s) for n, p, s in HTACCESS_SIGS]
EXTERNAL_REWRITE = re.compile(r"RewriteRule\s+\S+\s+(https?://[^\s\[]+)", re.I)


ORG_HEADERS = {"User-Agent": "KlezaSiteGuard/1.1 (+https://kleza.io)"}   # wordpress.org refuses the default UA


def _get(url, **params):
    try:
        resp = requests.get(url, params=params or None, timeout=30, headers=ORG_HEADERS)
        return resp.json() if resp.status_code == 200 else None
    except (requests.RequestException, ValueError):
        return None


# Checksums of a released version never change: kept for the life of the process. A failed lookup is retried after
# MISS_TTL seconds, so the integrity monitor (Phase 3) doesn't ask wordpress.org again on every cycle.
_CHECKSUMS, _CHECKSUMS_LOCK, MISS_TTL = {}, threading.Lock(), 6 * 3600


def _cached(key, fetch):
    with _CHECKSUMS_LOCK:
        hit = _CHECKSUMS.get(key)
    if hit and (hit[1] or time.time() - hit[0] < MISS_TTL):
        return hit[1]
    value = fetch()
    with _CHECKSUMS_LOCK:
        _CHECKSUMS[key] = (time.time(), value)
    return value


def core_checksums(version, locale):
    return _cached(("core", version, locale), lambda: _core_checksums(version, locale))


def plugin_checksums(slug, version):
    return _cached(("plugin", slug, version), lambda: _plugin_checksums(slug, version))


def _core_checksums(version, locale):
    for loc in dict.fromkeys([locale or "en_US", "en_US"]):
        data = _get("https://api.wordpress.org/core/checksums/1.0/", version=version, locale=loc)
        sums = (data or {}).get("checksums")
        if isinstance(sums, dict) and version in sums and isinstance(sums[version], dict):
            sums = sums[version]
        if isinstance(sums, dict) and sums:
            return sums
    return {}


def _plugin_checksums(slug, version):
    data = _get(f"https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json")
    files = (data or {}).get("files")
    if not isinstance(files, dict):
        return None
    return {path: set(v["md5"] if isinstance(v.get("md5"), list) else [v.get("md5")]) for path, v in files.items()}


class FileScan:
    def __init__(self, site, cfg, ai=None):
        self.site, self.cfg, self.ai = site, cfg, ai
        self.findings, self.hits = [], []
        self.stats = {}
        self.inventory = []
        self.expect_ja = False
        # Structured results for Phase 2 proposals
        self.issues = {}           # category -> [path]
        self.files = {}            # path -> {"p", "s", "m", "h"}
        self.texts = {}            # path -> content, for files that matched a signature
        self.plugins = {}          # plugin folder -> version (wordpress.org plugins with checksums)
        self.wp_version = None
        self.status = {}           # the plugin's /status answer (folders, versions, server time)
        self.verified = set()      # paths that match an official wordpress.org checksum

    def add(self, title, severity, paths, detail, recommendation, **evidence):
        paths = list(paths)
        shown = ", ".join(paths[:8]) + (f" and {len(paths) - 8} more" if len(paths) > 8 else "")
        self.findings.append(Finding("files", title + (f" ({len(paths)})" if len(paths) > 1 else ""), severity,
                                     f"{detail} {shown}.".strip(), recommendation,
                                     {"files": paths[:200], "count": len(paths), **evidence}))

    def read(self, path):
        status, data = self.site.wp("GET", f"{API}/file", params={"path": path})
        if status != 200 or not isinstance(data, dict):
            return None
        try:
            return base64.b64decode(data.get("content_base64") or "").decode("utf-8", errors="replace")
        except ValueError:
            return None

    def fetch(self):
        """(status, listing) from the Site Guard plugin; a finding explains why when either is unavailable."""
        status_code, status = self.site.wp("GET", f"{API}/status")
        if status_code != 200 or not isinstance(status, dict):
            hint = ("Install and activate the Kleza Site Guard plugin (jp_seo_agent/wp-plugin) to scan the site's files."
                    if status_code == 404 else f"The Site Guard plugin answered HTTP {status_code}; the application "
                    "password must belong to an administrator.")
            self.findings.append(Finding("files", "File scan not available", "INFO", hint,
                                         "File-level infections (cloaking code, backdoors, spam generators) can't be "
                                         "seen without it."))
            return None, None
        code, listing = self.site.wp("GET", f"{API}/files", timeout=300)
        if code != 200 or not isinstance(listing, dict):
            self.findings.append(Finding("files", "File scan failed", "INFO", f"Listing files returned HTTP {code}."))
            return status, None
        return status, listing

    def run(self, expect_ja=False, focus=None, status=None, listing=None):
        """Full scan, or with `focus` (a set of paths) only the integrity and signature checks for those files: the
        integrity monitor (Phase 3) passes the files that changed since its baseline. `status` and `listing` can be
        passed in when the caller already fetched them."""
        self.expect_ja = expect_ja
        if status is None or listing is None:
            status, listing = self.fetch()
            if listing is None:
                return self
        inside = (lambda p: True) if focus is None else (lambda p: p in focus)
        files = {f["p"]: f for f in listing.get("files", []) if isinstance(f, dict) and f.get("p")}
        self.inventory = list(files.values())
        self.files, self.wp_version, self.status = files, status.get("wp_version"), status
        dirs = {k: (status.get(k) or "").strip("/") for k in
                ("content_dir", "plugins_dir", "mu_plugins_dir", "uploads_dir", "themes_dir")}
        self.stats = {"files": len(files), "truncated": bool(listing.get("truncated")),
                      "wp_version": status.get("wp_version"), "plugin_version": status.get("plugin_version")}
        to_read = {}   # path -> reason

        def under(path, key):
            return bool(dirs[key]) and path.startswith(dirs[key] + "/")

        # ---- WordPress core against the official checksums ----
        core = core_checksums(status.get("wp_version"), status.get("locale"))
        if core:
            core_files = {p: m for p, m in core.items() if not p.startswith("wp-content/")}
            modified = sorted(p for p, m in core_files.items() if p in files and inside(p) and files[p].get("h")
                              and files[p]["h"] != m)
            self.verified.update(p for p, m in core_files.items() if p in files and files[p].get("h") == m)
            in_core_dirs = [p for p in files if p.startswith(("wp-admin/", "wp-includes/")) and p not in core_files
                            and inside(p)]
            root_php = [p for p in files if "/" not in p and CODE_EXT.search(p) and p not in core_files
                        and p != "wp-config.php" and inside(p)]
            if modified:
                self.add("Modified WordPress core files", "HIGH", modified,
                         "These files differ from the official WordPress release:",
                         "Reinstall WordPress core (Dashboard > Updates > Re-install) after reviewing the changes.")
            if in_core_dirs:
                self.add("Unknown files in WordPress core folders", "HIGH", sorted(in_core_dirs),
                         "Not part of WordPress, but placed in wp-admin or wp-includes:",
                         "Classic backdoor location. Review and quarantine them.")
            if root_php:
                self.add("Unexpected PHP files in the site root", "MEDIUM", sorted(root_php),
                         "Not part of WordPress:", "Remove them unless you know what they are.")
            self.issues.update(core_modified=modified, core_unknown=sorted(in_core_dirs), root_php=sorted(root_php))
            for p in modified + in_core_dirs + root_php:
                to_read.setdefault(p, "core integrity")
        else:
            self.stats["core_checksums"] = "unavailable"

        # ---- plugins against wordpress.org checksums ----
        _, plugins = self.site.wp("GET", "/wp/v2/plugins")
        plugins = plugins if isinstance(plugins, list) else []
        targets = [(p["plugin"].split("/")[0], p.get("version")) for p in plugins
                   if "/" in (p.get("plugin") or "") and p.get("version")]
        if focus is not None:   # only the plugins that hold a changed file
            touched = {q[len(dirs["plugins_dir"]) + 1:].split("/", 1)[0] for q in focus
                       if dirs["plugins_dir"] and q.startswith(dirs["plugins_dir"] + "/")}
            targets = [t for t in targets if t[0] in touched]
        targets = targets[: int(self.cfg.get("max_plugin_checksums", 40))]
        with ThreadPoolExecutor(max_workers=6) as pool:
            sums = dict(zip(targets, pool.map(lambda t: plugin_checksums(*t), targets)))
        modified_plugin, unknown_plugin, verified = [], [], 0
        for (slug, _), checks in sums.items():
            if not checks or not dirs["plugins_dir"]:
                continue
            verified += 1
            self.plugins[slug] = dict(targets).get(slug)
            prefix = f"{dirs['plugins_dir']}/{slug}/"
            for path, f in files.items():
                if not path.startswith(prefix):
                    continue
                rel = path[len(prefix):]
                if rel in checks:
                    if f.get("h") and f["h"] not in checks[rel]:
                        if inside(path):
                            modified_plugin.append(path)
                    elif f.get("h"):
                        self.verified.add(path)
                elif CODE_EXT.search(rel) and inside(path):
                    unknown_plugin.append(path)
        self.stats["plugins_verified"] = verified
        if modified_plugin:
            self.add("Modified plugin files", "HIGH", sorted(modified_plugin),
                     "These plugin files differ from the wordpress.org release:",
                     "Reinstall the plugin from wordpress.org after reviewing the changes.")
        if unknown_plugin:
            self.add("Unknown PHP files inside wordpress.org plugins", "MEDIUM", sorted(unknown_plugin),
                     "Not part of the official plugin release:", "Review them; malware hides inside trusted plugins.")
        self.issues.update(plugin_modified=sorted(modified_plugin), plugin_unknown=sorted(unknown_plugin))
        for p in modified_plugin + unknown_plugin:
            to_read.setdefault(p, "plugin integrity")

        # ---- PHP where it doesn't belong, must-use plugins, server config ----
        uploads_php = sorted(p for p in files if under(p, "uploads_dir") and CODE_EXT.search(p) and inside(p))
        if uploads_php:
            self.add("PHP files in the uploads folder", "HIGH", uploads_php,
                     "The uploads folder should only hold media:", "Almost always a web shell. Quarantine them.")
        uploads = [p for p in files if under(p, "uploads_dir") and inside(p)]
        disguised = sorted(p for p in uploads if DISGUISED_EXT.search(p))
        if disguised:
            self.add("Disguised script in the uploads folder", "HIGH", disguised,
                     "Script names with a second extension, a common way to slip a web shell past upload filters:",
                     "Almost always a web shell. Quarantine them and find out how they were uploaded.")
        upload_pages = sorted(p for p in uploads if UPLOAD_PAGE_EXT.search(p))
        if upload_pages:
            self.add("Web pages or programs in the uploads folder", "MEDIUM", upload_pages,
                     "The uploads folder should only hold media; attackers host phishing pages and malware here:",
                     "Open each file; delete it if your team didn't upload it.")
        self.issues.update(disguised_uploads=disguised, upload_pages=upload_pages)
        mu = sorted(p for p in files if under(p, "mu_plugins_dir") and CODE_EXT.search(p) and inside(p))
        if mu:
            self.add("Must-use plugins installed", "LOW", mu, "Always loaded and hidden from the plugin list:",
                     "Confirm each one; attackers use mu-plugins for persistence.")
        self.issues.update(uploads_php=uploads_php, mu_plugins=mu, plugins_dir=dirs["plugins_dir"])
        for p in uploads_php + disguised + mu:
            to_read.setdefault(p, "location")
        for p in files:
            name = p.rsplit("/", 1)[-1].lower()
            if not inside(p):
                continue
            if name in (".htaccess", ".user.ini", "php.ini", "wp-config.php"):
                to_read.setdefault(p, "server configuration")
            elif name.endswith(".ico") and (p not in core or (name != "favicon.ico" and "/" in p
                                                               and not p.startswith(("wp-admin/", "wp-includes/")))):
                to_read.setdefault(p, "icon file")
        theme = dirs["themes_dir"] and f"{dirs['themes_dir']}/{status.get('stylesheet')}/"
        for name in ("functions.php", "header.php", "footer.php", "index.php"):
            if theme and theme + name in files and inside(theme + name):
                to_read.setdefault(theme + name, "active theme")

        if focus is None:
            recent_days = int(self.cfg.get("recent_days", 7))
            cutoff = (status.get("time") or time.time()) - recent_days * 86400
            recent = sorted((p for p, f in files.items() if CODE_EXT.search(p) and (f.get("m") or 0) >= cutoff),
                            key=lambda p: -files[p]["m"])
            if recent:
                self.add(f"Code files changed in the last {recent_days} days", "INFO", recent,
                         "Useful for finding when and where an infection started:", "")
            for p in recent:
                to_read.setdefault(p, "recently changed")
        else:   # every changed code file that isn't an official wordpress.org copy is read
            for p in sorted(focus):
                if p in files and p not in self.verified and (CODE_EXT.search(p) or p.rsplit("/", 1)[-1].lower()
                                                               in (".htaccess", ".user.ini", "php.ini")):
                    to_read.setdefault(p, "changed since the trusted baseline")

        # Uploaded images are checked for PHP hidden inside them: new ones in a monitor cycle, recent ones in a scan
        recent_days = int(self.cfg.get("recent_days", 7))
        cutoff = (status.get("time") or time.time()) - recent_days * 86400
        images = [p for p in uploads if MEDIA_EXT.search(p) and (focus is not None or (files[p].get("m") or 0) >= cutoff)]
        for p in sorted(images, key=lambda p: -(files[p].get("m") or 0))[: int(self.cfg.get("max_image_reads", 40))]:
            to_read.setdefault(p, "uploaded image")

        self.scan_contents(dict(list(to_read.items())[: int(self.cfg.get("max_file_reads", 80))]))
        return self

    def scan_contents(self, to_read):
        hits = []
        for path, reason in to_read.items():
            text = self.read(path)
            if text is None:
                continue
            name = path.rsplit("/", 1)[-1].lower()
            media = bool(MEDIA_EXT.search(name))   # binary: only a PHP tag means something
            sigs = [] if media else HTACCESS_SIGS if name in (".htaccess", ".user.ini", "php.ini") else PHP_SIGS
            found = []
            if media and not name.endswith(".ico") and (m := PHP_OPEN_TAG.search(text)):
                found.append(("PHP code hidden in an uploaded image", "CRITICAL", text[max(m.start() - 150, 0):m.end() + 300]))
            for label, regex, severity in sigs:
                m = regex.search(text)
                if m:
                    found.append((label, severity, text[max(m.start() - 150, 0):m.end() + 150]))
            if name == ".htaccess":
                for url in EXTERNAL_REWRITE.findall(text):
                    if self.site.is_external(url):
                        found.append(("rewrite to another domain", "MEDIUM", url))
                        break
            if name.endswith(".ico") and "<?php" in text:
                found.append(("PHP code hidden in an .ico file", "CRITICAL", text[:300]))
            if "/languages/" not in path and not media:
                sc = score(text)
                kinds = spam_kinds(sc, self.expect_ja)
                if kinds:
                    found.append((f"{describe(kinds)} spam text in a code file", "HIGH", text[:300]))
            if found:
                self.texts[path] = text
                hits.append({"id": str(len(hits)), "path": path, "reason": reason,
                             "signatures": [f[0] for f in found], "severity": max((f[1] for f in found), key=SEVERITY.get),
                             "snippet": "\n...\n".join(f[2] for f in found)[:3000]})
        self.stats["files_read"] = len(to_read)

        verdicts = self.ai.review_files(hits) if self.ai and self.ai.enabled and hits else {}
        groups = {}
        for h in hits:
            v = verdicts.get(h["id"])
            h["ai"] = v.model_dump() if v else None
            if v and v.classification == "benign" and v.confidence != "low":
                key = ("Code that matched a malware signature but was reviewed as legitimate", "INFO", "")
            else:
                severity = h["severity"] if not v or v.classification == "malicious" else \
                    ("MEDIUM" if h["severity"] in ("HIGH", "CRITICAL") else h["severity"])
                key = (f"Malicious code signature: {h['signatures'][0]}", severity, v.reason if v else "")
            groups.setdefault(key, []).append(h)
        for (title, severity, why), group in sorted(groups.items(), key=lambda kv: -SEVERITY.get(kv[0][1], 0)):
            self.add(title, severity, [h["path"] for h in group], (why + " Files:") if why else "Files:",
                     "" if severity == "INFO" else "Inspect the code; if your team didn't write it, quarantine the file "
                     "(Phase 2) and find how it got there.",
                     hits=[{k: h[k] for k in ("path", "signatures", "reason", "snippet", "ai")} for h in group[:20]])
        self.hits = hits
