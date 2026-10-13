"""Phase 1, WordPress content inspection: read-only, through the REST API with an application password.

Finds whole spam items (posts, pages, reusable blocks, templates, including drafts and private ones), spam and
malicious code (scripts, redirects, hidden links, iframes) injected into legitimate content, the accounts that wrote
them, recently created administrators, and spam in the site title/tagline. Heuristic hits and ambiguous items are
triaged by Claude (ai.py) before they are reported or remediated.
"""

import re
from collections import Counter
from urllib.parse import urlparse

from .scoring import (JS_REDIRECT, LINK_HREF, META_REFRESH, OBFUSCATED_REDIRECT, REFERRER_CHECK, allowed_path,
                      describe, hidden_blocks, score, spam_kinds, strip_html, verdict)
from .site import Finding, days_since, same_site

STATUSES = "publish,future,draft,pending,private"
# (REST route, label, supports the status filter, can be moved to the trash, has revisions)
CONTENT_TYPES = (
    ("/wp/v2/posts", "post", True, True, True),
    ("/wp/v2/pages", "page", True, True, True),
    ("/wp/v2/blocks", "reusable block", True, True, True),
    ("/wp/v2/templates", "template", False, False, False),
    ("/wp/v2/template-parts", "template part", False, False, False),
)
AI_KIND = {"spam_page": "spam", "injected_spam": "injected"}
SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)", re.I)
INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
IFRAME_SRC = re.compile(r"<iframe\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)", re.I)
RECENT_ADMIN_DAYS = 14
# Public CDNs and common vendors whose scripts are routinely pasted into content (forms, carousels, widgets)
KNOWN_SCRIPT_DOMAINS = (
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com", "code.jquery.com",
    "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "googletagmanager.com", "google-analytics.com",
    "google.com", "gstatic.com", "youtube.com", "vimeo.com", "zoho.com", "zohopublic.com", "zohopublic.in",
    "zoho.in", "hubspot.com", "hsforms.net", "hs-scripts.com", "typeform.com", "calendly.com", "jotform.com",
    "facebook.net", "twitter.com", "platform.twitter.com", "instagram.com", "linkedin.com", "tagembed.com",
    "elfsight.com", "trustpilot.com", "mailchimp.com", "list-manage.com", "wistia.com", "stripe.com", "paypal.com",
)


def _raw(value):
    if isinstance(value, dict):
        return value.get("raw") or value.get("rendered") or ""
    return value if isinstance(value, str) else ""


def login(site):
    """The authenticated user, or None. The HTTP status of the attempt is kept in site.login_status."""
    if not site.wp_auth or not site.secure:
        return None
    if getattr(site, "login_user", None):
        return site.login_user
    status, me = site.wp("GET", "/wp/v2/users/me", params={"context": "edit"})
    site.login_status = status
    site.login_user = me if status == 200 and isinstance(me, dict) else None
    return site.login_user


def code_problems(site, markup, cfg):
    """Malicious code injected into content: [(problem, detail)]."""
    trusted = list(KNOWN_SCRIPT_DOMAINS) + [d.lower() for d in cfg.get("trusted_script_domains") or []]
    is_trusted = lambda url: any(same_site(urlparse(site.abs_url(url)).hostname or "", d) for d in trusted)
    problems = []
    for src in SCRIPT_SRC.findall(markup):
        if site.is_external(src) and not is_trusted(src):
            problems.append(("external script", src))
    for code in INLINE_SCRIPT.findall(markup):
        external = [a or b for a, b in JS_REDIRECT.findall(code) if site.is_external(a or b)]
        if external or OBFUSCATED_REDIRECT.search(code) or REFERRER_CHECK.search(code):
            problems.append(("redirect script", (external or [code.strip()])[0][:200]))
    meta = META_REFRESH.search(markup)
    if meta and site.is_external(meta.group(1)):
        problems.append(("meta refresh redirect", meta.group(1)[:200]))
    for block in hidden_blocks(markup):
        external = [u for u in LINK_HREF.findall(block) if site.is_external(u)]
        if external:
            problems.append(("hidden external links", ", ".join(external[:3])))
            break
    for src in IFRAME_SRC.findall(markup):
        if site.is_external(src) and "display:none" in markup.replace(" ", "").lower():
            problems.append(("hidden iframe", src))
            break
    return problems


ITEM_FIELDS = "id,title,content,excerpt,status,slug,author,link,modified_gmt"


def content_type(route):
    """(route, label, has_status, trashable, revisions) for a REST route, or None."""
    return next((t for t in CONTENT_TYPES if t[0] == route), None)


def inspect_item(site, cfg, expect_ja, ctype, item):
    """One content item (REST answer, context=edit) checked for spam and injected code: the entry described in
    scan_items, or None when it looks clean. Used by the scan and by the integrity monitor (Phase 3)."""
    route, label, _, trashable, revisions = ctype
    allowed = cfg.get("allowed_japanese_paths") or []
    allowed_kinds = tuple(cfg.get("allowed_spam_categories") or ())
    title = strip_html(_raw(item.get("title")))
    markup = " ".join(filter(None, (_raw(item.get("content")), _raw(item.get("excerpt")))))
    body = strip_html(markup)
    link = item.get("link") or ""
    expect = expect_ja or bool(link and allowed_path(link, allowed))
    tsc, csc, whole = score(title), score(body), score(f"{title} {body}")
    kinds = spam_kinds(whole, expect, allowed=allowed_kinds)
    result = "spam" if kinds else verdict(whole, expect, allowed=allowed_kinds)
    code = code_problems(site, markup, cfg)
    if not result and not code:
        return None
    # Attacker-made items carry spam titles; a normal title means spam was injected into real content
    # (often more spam text than real text, so the body ratio can't decide)
    title_spam = bool(spam_kinds(tsc, expect, min_kana=2, allowed=allowed_kinds)) or \
        (not expect and "japanese" not in allowed_kinds and tsc["kana"] >= 2)
    return {"route": route, "label": label, "id": item.get("id"), "title": title[:120],
            "status": item.get("status", ""), "author": item.get("author"), "link": link,
            "modified": item.get("modified_gmt"), "score": whole, "kinds": kinds, "code": code,
            "heuristic": "spam" if (kinds or code) else result, "ai": None,
            "kind": "spam" if kinds and (title_spam or (not title and csc["ratio"] >= 0.5)) else "injected",
            "trashable": trashable, "revisions": revisions, "raw": item, "_text": body}


def scan_items(site, cfg, expect_ja, ai=None):
    """Infected content items. Each: route, label, id, title, status, author, link, kind ('spam' = the whole item,
    'injected' = spam or code inside legitimate content), kinds (spam families), code (malicious code problems),
    score, ai (verdict dict or None), trashable, revisions, raw."""
    found, ambiguous = [], []
    for ctype in CONTENT_TYPES:
        params = {"context": "edit", "_fields": ITEM_FIELDS}
        if ctype[2]:
            params["status"] = STATUSES
        for item in site.wp_items(ctype[0], **params):
            if item.get("status") == "trash":
                continue
            entry = inspect_item(site, cfg, expect_ja, ctype, item)
            if entry:
                (found if entry["heuristic"] == "spam" else ambiguous).append(entry)

    if ai and ai.enabled:
        candidates = found + ambiguous
        verdicts = ai.classify([{"id": f"{i['route']}#{i['id']}", "title": i["title"], "text": i["_text"],
                                 "context": f"WordPress {i['label']} ({i['status']})"
                                 + (f"; injected code found: {i['code']}" if i["code"] else "")} for i in candidates])
        found = []
        for item in candidates:
            v = verdicts.get(f"{item['route']}#{item['id']}")
            if v is None:  # AI gave no verdict: keep heuristic hits, drop ambiguous ones
                if item["heuristic"] == "spam":
                    found.append(item)
                continue
            item["ai"] = v.model_dump()
            if v.classification in AI_KIND:
                item["kind"] = AI_KIND[v.classification]
                found.append(item)
            elif item["code"]:  # Claude found the text legitimate, but injected code is still worth a look
                item["kind"] = "injected"
                found.append(item)
    for item in found:
        item.pop("_text", None)
    return found


def scan(site, cfg, expect_ja, ai=None):
    """(findings, items, spam_urls) for the content inspection; ([], [], {}) without usable credentials."""
    if not site.wp_auth:
        return [], [], {}
    if not site.secure:
        return [Finding("wordpress", "WordPress inspection skipped: site is not HTTPS", "INFO",
                        "The application password is never sent over plain HTTP.")], [], {}
    me = login(site)
    if not me:
        status = getattr(site, "login_status", None)
        why = ("the site could not be reached" if status is None else
               f"WordPress rejected the application password (HTTP {status})" if status in (401, 403) else
               f"WordPress answered HTTP {status}")
        return [Finding("wordpress", "WordPress inspection could not log in", "MEDIUM" if status in (401, 403) else "INFO",
                        f"Logging in failed: {why}.",
                        "Check the username and application password (wp-admin > Users > Profile).")], [], {}

    items = scan_items(site, cfg, expect_ja, ai)
    users = {u.get("id"): u for u in site.wp_items("/wp/v2/users", context="edit",
                                                   _fields="id,username,slug,roles,registered_date")}
    site.wp_users = users
    findings = []

    def where(group):
        shown = ", ".join(f"{i['label']} #{i['id']} \"{i['title'][:40]}\" ({i['status']})" for i in group[:5])
        return shown + (f" and {len(group) - 5} more" if len(group) > 5 else "")

    def evidence(group):
        return {"count": len(group), "items": [{k: i[k] for k in ("label", "id", "title", "status", "link", "kind")}
                                               | {"spam": i["kinds"], "code": i["code"][:3],
                                                  "ai_reason": (i["ai"] or {}).get("reason", "")} for i in group[:50]]}

    spam = [i for i in items if i["kind"] == "spam"]
    injected_spam = [i for i in items if i["kind"] == "injected" and (i["kinds"] or (i["ai"] and not i["code"]))]
    injected_code = [i for i in items if i["kind"] == "injected" and i["code"] and i not in injected_spam]
    families = describe(sorted({k for i in spam + injected_spam for k in i["kinds"]}))
    if spam:
        findings.append(Finding("wordpress", f"{len(spam)} {families} spam item(s) inside WordPress", "CRITICAL",
                                f"Found in {where(spam)}.", "Created by the attacker. Approve moving them to the trash "
                                "(Phase 2 quarantine) after checking the list.", evidence(spam)))
    if injected_spam:
        findings.append(Finding("wordpress", f"Spam injected into {len(injected_spam)} legitimate item(s)", "CRITICAL",
                                f"Found in {where(injected_spam)}.",
                                "Restore the last clean revision or remove the injected blocks.", evidence(injected_spam)))
    # Redirects, hidden links and hidden iframes are injection patterns; a plain external script is often an embed
    dangerous = [i for i in injected_code if any(p != "external script" for p, _ in i["code"])]
    embeds = [i for i in injected_code if i not in dangerous]
    if dangerous:
        findings.append(Finding("wordpress", f"Suspicious code injected into {len(dangerous)} item(s)", "HIGH",
                                f"Redirects, hidden links or hidden iframes in {where(dangerous)}.",
                                "Open each item in the code editor; remove code your team didn't add.",
                                evidence(dangerous)))
    if embeds:
        findings.append(Finding("wordpress", f"Scripts from unrecognised domains in {len(embeds)} item(s)", "LOW",
                                f"External scripts embedded in {where(embeds)}.",
                                "Confirm your team added them. If so, add the domain to "
                                "checks.compromise.trusted_script_domains.", evidence(embeds)))
    for author_id, n in Counter(i["author"] for i in spam + injected_spam if i["author"]).most_common(5):
        u = users.get(author_id, {})
        name = u.get("username") or u.get("slug") or f"user #{author_id}"
        findings.append(Finding("wordpress", f"Account '{name}' authored {n} spam item(s)", "HIGH",
                                f"Roles: {', '.join(u.get('roles') or ['unknown'])}; registered {u.get('registered_date', '?')}.",
                                "The account is compromised or was created by the attacker. Reset its password and "
                                "application passwords, or delete it if nobody on your team owns it.",
                                {"user": name, "user_id": author_id, "items": n}))
    for u in users.values():
        age = days_since(u.get("registered_date"))
        if "administrator" in (u.get("roles") or []) and age is not None and age <= RECENT_ADMIN_DAYS:
            findings.append(Finding("wordpress", f"Administrator '{u.get('username') or u.get('slug')}' created recently",
                                    "HIGH", f"Registered {u.get('registered_date')} ({age} day(s) ago).",
                                    "Attackers add administrators as a backdoor. Confirm someone on your team created it.",
                                    {"user_id": u.get("id")}))
    status, settings = site.wp("GET", "/wp/v2/settings")
    if status == 200 and isinstance(settings, dict):
        meta = f"{settings.get('title', '')} {settings.get('description', '')}"
        if verdict(score(meta), expect_ja, min_kana=2) == "spam":
            findings.append(Finding("wordpress", "Spam in the site title or tagline", "CRITICAL", meta[:200],
                                    "Restore the title and tagline in Settings > General."))
        host = (urlparse(str(settings.get("url") or "")).hostname or "").lower()
        if host and not (same_site(host, site.domain) or same_site(site.host, host)):
            findings.append(Finding("wordpress", "WordPress site address points to another domain", "CRITICAL",
                                    settings.get("url", ""), "Restore the WordPress Address and Site Address in "
                                    "Settings > General; visitors can be redirected."))
    spam_urls = {i["link"]: f"WordPress {i['label']} #{i['id']}" for i in spam if i["link"] and i["status"] == "publish"}
    return findings, items, spam_urls
