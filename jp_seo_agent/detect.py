"""Phase 1, outside detection: read-only, works on any site, no credentials.

Compromised sites hide their spam from the owner, so the site is examined the way Google and search visitors see it:
  * crawl the site as a visitor and as Googlebot: spam only for Googlebot = cloaking
  * SEO spam of any family (Japanese keyword hack, pharma, gambling, adult, scam) in visible or hidden content
  * hidden spam links, malicious redirects (HTTP, meta refresh, JavaScript, search-visitor-only, mobile-only)
  * spam and suspicious URLs in the sitemaps and links, sitemaps on other domains in robots.txt
  * a page generator answering made-up URLs with spam
"""

import html as html_lib
import random
import re
import string
from collections import defaultdict
from urllib.parse import unquote, urlparse

from .crawl import crawl
from .scoring import (CATEGORY_TERMS, JS_REDIRECT, KANA, LINK_HREF, META_REFRESH, MOBILE_CHECK, OBFUSCATED_REDIRECT,
                      REFERRER_CHECK, allowed_path, describe, hidden_blocks, without_hidden, page_score, score, spam_kinds,
                      strip_html, terms_of, verdict)
from .site import BROWSER_UA, GOOGLEBOT_UA, MOBILE_UA, Finding

GOOGLE_REFERER = "https://www.google.com/search?q=site"
HTML_LANG = re.compile(r"<html\b[^>]*\blang\s*=\s*[\"']?([a-zA-Z]{2,3})", re.I)
LOC = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</loc>", re.I | re.S)
SITEMAP_DIRECTIVE = re.compile(r"(?im)^\s*sitemap\s*:\s*(\S+)")
INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
# URL shapes used by spam generators: /abc12345.html, /12345678.html, /?xyz=123456
SPAM_URL = re.compile(r"/(?:[a-z]{1,8}\d{3,}|\d{5,})\.(?:html?|php)$|[?&][a-z0-9]{2,8}=\d{4,}(?:&|$)", re.I)
SPAM_SLUG = re.compile(r"(?<![a-z0-9])(?:" + "|".join(re.escape(t.replace(" ", "-")) for terms in CATEGORY_TERMS.values()
                                                   for t in terms if " " in t or len(t) > 5) + r")(?![a-z0-9])", re.I)
DEFAULT_SITEMAPS = ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml")
MIN_PAGE_TEXT = 50       # characters of visible text below which a visitor page is a stub (bot challenge, JS app)
MAX_LISTED = 5
CLOAK_FIX = ("Cloaking code checks the User-Agent or referrer, usually in .htaccess, index.php, wp-config.php, a theme's "
             "functions.php or a fake plugin. The file scan (Site Guard plugin) looks for it.")


class _Group:
    """Collects the same problem across many pages into one finding."""

    def __init__(self):
        self.groups = defaultdict(list)   # (title, severity, detail, recommendation) -> [(url, evidence)]

    def add(self, title, severity, url, detail="", recommendation="", **evidence):
        self.groups[(title, severity, detail, recommendation)].append((url, evidence))

    def findings(self):
        out = []
        for (title, severity, detail, rec), hits in self.groups.items():
            urls = list(dict.fromkeys(u for u, _ in hits))
            shown = ", ".join(urlparse(u).path or "/" for u in urls[:MAX_LISTED])
            more = f" and {len(urls) - MAX_LISTED} more" if len(urls) > MAX_LISTED else ""
            out.append(Finding("outside", title + (f" ({len(urls)} pages)" if len(urls) > 1 else ""), severity,
                               (detail + " " if detail else "") + f"Found on {shown}{more}.", rec,
                               {"count": len(urls), "pages": [{"url": u, **e} for u, e in hits[:50]]}))
        return out


class OutsideScan:
    def __init__(self, site, cfg):
        self.site, self.cfg = site, cfg
        self.allowed_paths = cfg.get("allowed_japanese_paths") or []
        self.allowed_kinds = tuple(cfg.get("allowed_spam_categories") or ())
        self.group = _Group()
        self.extra = []           # findings that aren't per page
        self.spam_urls = {}       # url -> how it was found
        self.suspicious_urls = {} # url -> why (not confirmed as spam)
        self.candidates = []      # ambiguous pages for AI triage: {"url", "title", "text", "how"}
        self.stats = {"pages": 0, "sitemaps": 0, "sitemap_urls": 0}
        self.expect_ja = self._expects_japanese()

    @property
    def findings(self):
        return self.extra + self.group.findings()

    def _expects_japanese(self):
        lang = (self.cfg.get("site_language") or "").lower()
        if not lang:
            for ua in (BROWSER_UA, GOOGLEBOT_UA):  # the visitor page can be an empty bot-challenge stub
                _, markup = self.site.fetch(self.site.url, ua, max_bytes=50_000)
                match = HTML_LANG.search(markup)
                if match:
                    lang = match.group(1).lower()
                    break
        return lang.startswith("ja")

    def judge(self, url, markup, min_kana=10):
        """(verdict, kinds, score, title, text) for a page's HTML."""
        sc, title, text = page_score(markup)
        expect = self.expect_ja or allowed_path(url, self.allowed_paths)
        return (verdict(sc, expect, min_kana, self.allowed_kinds), spam_kinds(sc, expect, min_kana, self.allowed_kinds),
                sc, title, text)

    # ---- per page -----------------------------------------------------------------
    def analyse(self, page):
        site, url = self.site, page.url
        visitor = self.judge(url, without_hidden(page.html)) if page.status else (None, [], None, "", "")
        full = self.judge(url, page.html) if page.status else (None, [], None, "", "")   # including hidden parts
        bot = self.judge(url, page.bot_html) if page.bot_status else (None, [], None, "", "")
        cloaked = [k for k in bot[1] if k not in full[1]]   # spam families only Googlebot gets

        if visitor[0] == "spam":
            self.spam_urls[url] = f"{describe(visitor[1])} spam content"
            self.group.add(f"{describe(visitor[1]).capitalize()} spam content visible on the site", "CRITICAL", url,
                           "Visitors see SEO spam.", "Find out how it got there (WordPress content or files) before "
                           "removing it.", page_title=visitor[3][:150], terms=terms_of(visitor[2], visitor[1])[:10])
        elif cloaked and page.status and len(full[4]) < MIN_PAGE_TEXT:
            self.group.add("Googlebot gets spam but visitors get an almost empty page", "MEDIUM", url,
                           "Probably a bot challenge for visitors, so cloaking can't be confirmed.",
                           "Check the page with Search Console > URL Inspection > View crawled page.",
                           terms=terms_of(bot[2], cloaked)[:10])
        elif cloaked:
            self.spam_urls[url] = f"cloaked {describe(cloaked)} spam for Googlebot"
            self.group.add(f"Cloaked {describe(cloaked)} spam served only to Googlebot", "CRITICAL", url,
                           "Visitors get a normal page, Googlebot gets spam.", CLOAK_FIX,
                           googlebot_title=bot[3][:150], terms=terms_of(bot[2], cloaked)[:10])
        elif "japanese" in (visitor[0], bot[0]):
            text, title = (visitor[4], visitor[3]) if visitor[0] == "japanese" else (bot[4], bot[3])
            self.candidates.append({"url": url, "title": title, "text": text, "how": "unexpected Japanese text"})

        if page.html:
            self.hidden(url, page.html)
            self.redirect_code(url, page.html)
        if page.final_url and site.is_external(page.final_url):
            bot_external = page.bot_final_url and site.is_external(page.bot_final_url)
            target = urlparse(page.final_url).hostname or ""
            redirector = bool(target) and target in unquote(urlparse(url).query)   # e.g. /out?to=https://target/
            if not bot_external and page.bot_status == 200 and not redirector:
                self.spam_urls.setdefault(url, "redirects visitors away")
                self.group.add("Visitors are redirected to another domain, Googlebot is not", "CRITICAL", url,
                               "A conditional redirect: search engines see the page, visitors are sent elsewhere.",
                               CLOAK_FIX, location=page.final_url)
            else:
                self.group.add("Page redirects to another domain", "LOW", url,
                               "Expected for intentional redirects; investigate if you don't recognise the target.",
                               "", location=page.final_url)

    def hidden(self, url, markup):
        hidden_links = []   # external links hidden off-screen or shrunk to nothing, across the whole page
        for block, seo_style in hidden_blocks(markup, with_style=True):
            text = strip_html(block)
            external = [u for u in LINK_HREF.findall(block) if self.site.is_external(u)]
            sc = score(text)
            kinds = spam_kinds(sc, self.expect_ja, 2, self.allowed_kinds)
            if not kinds and external:  # a single spam word next to a hidden external link is enough
                kinds = [k for k, v in sc["categories"].items() if v and k not in self.allowed_kinds]
            if kinds:
                self.spam_urls.setdefault(url, "hidden spam")
                self.group.add(f"Hidden {describe(kinds)} spam in the page", "HIGH", url,
                               "Spam text hidden from visitors with CSS but readable by search engines.",
                               "Remove it from the content or template that outputs it.",
                               terms=terms_of(sc, kinds)[:10], links=external[:5])
            elif seo_style:  # menus use display:none, not off-screen or zero-size boxes
                hidden_links += external
        # Counted per page: injections often put each link in its own hidden box
        if len({urlparse(u).hostname for u in hidden_links}) >= 2:
            self.group.add("Links to external sites hidden off-screen", "MEDIUM", url,
                           "Links moved off-screen or shrunk to nothing are a classic SEO spam injection.",
                           "Check the template or content block that outputs them.", links=hidden_links[:10])

    def redirect_code(self, url, markup):
        meta = META_REFRESH.search(markup)
        if meta and self.site.is_external(html_lib.unescape(meta.group(1))):
            self.group.add("Meta refresh redirect to another domain", "HIGH", url,
                           "The page sends visitors elsewhere with <meta http-equiv=refresh>.",
                           "Remove the tag unless the redirect is intentional.", location=meta.group(1)[:200])
        for script in INLINE_SCRIPT.findall(markup):
            targets = [a or b for a, b in JS_REDIRECT.findall(script)]
            external = [t for t in targets if self.site.is_external(t)]
            conditional = REFERRER_CHECK.search(script) or MOBILE_CHECK.search(script)
            if external and conditional:
                self.spam_urls.setdefault(url, "conditional JavaScript redirect")
                self.group.add("JavaScript redirect for search or mobile visitors", "CRITICAL", url,
                               "Inline script redirects visitors who come from a search engine or a phone.",
                               "Malicious redirect code: find where it is injected (content, theme or plugin files).",
                               location=external[0][:200], snippet=script.strip()[:300])
            elif OBFUSCATED_REDIRECT.search(script):
                self.group.add("Obfuscated JavaScript redirect", "HIGH", url,
                               "Inline script builds a redirect from encoded text, a common malware technique.",
                               "Inspect the script; remove it if your team didn't add it.", snippet=script.strip()[:300])
            elif external:
                self.group.add("JavaScript redirect to another domain", "MEDIUM", url,
                               "Inline script sets location to an external site.",
                               "Confirm the redirect is intentional.", location=external[0][:200])

    def conditional_redirects(self, urls):
        """Redirects that only happen for visitors from Google or on phones."""
        site = self.site
        for url in urls:
            plain, _ = site.fetch(url, BROWSER_UA, redirects=False, max_bytes=1)
            plain_loc = plain.headers.get("Location", "") if plain is not None and plain.is_redirect else ""
            for label, ua in (("from Google", BROWSER_UA), ("on phones arriving from Google", MOBILE_UA)):
                resp, _ = site.fetch(url, ua, referer=GOOGLE_REFERER, redirects=False, max_bytes=1)
                location = resp.headers.get("Location", "") if resp is not None and resp.is_redirect else ""
                if location and site.is_external(location) and location != plain_loc:
                    self.spam_urls.setdefault(url, f"redirects visitors {label}")
                    self.group.add(f"Visitors {label} are redirected to another domain", "CRITICAL", url,
                                   "The redirect only happens for search visitors, so the owner never sees it.",
                                   "Look for code checking HTTP_REFERER or the User-Agent in .htaccess and PHP files.",
                                   location=location[:200])
                    break

    # ---- site wide ------------------------------------------------------------------
    def sitemaps(self):
        site, cfg = self.site, self.cfg
        robots, robots_text = site.fetch("/robots.txt", GOOGLEBOT_UA, max_bytes=200_000)
        declared = SITEMAP_DIRECTIVE.findall(robots_text) if robots is not None and robots.status_code == 200 else []
        for url in declared:
            if site.is_external(url):
                self.extra.append(Finding("outside", "robots.txt declares a sitemap on another domain", "HIGH", url,
                                          "Attackers add their own sitemaps to get spam pages indexed. Remove the "
                                          "line unless you know why it is there.", {"sitemap": url}))
        queue = [u for u in declared if not site.is_external(u)] or [site.abs_url(p) for p in DEFAULT_SITEMAPS]
        seen, page_urls, dead = set(), [], []
        max_sitemaps, max_urls = int(cfg.get("max_sitemaps", 20)), int(cfg.get("max_sitemap_urls", 5000))
        while queue and len(seen) < max_sitemaps and len(page_urls) < max_urls:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            resp, text = site.fetch(url, GOOGLEBOT_UA, max_bytes=10_000_000)
            if resp is None or resp.status_code != 200 or "<loc" not in text.lower():
                if resp is not None and url in declared:
                    dead.append(url)
                continue
            locs = [html_lib.unescape(u) for u in LOC.findall(text)]
            if re.search(r"<sitemapindex\b", text, re.I):
                queue += [u for u in locs if not site.is_external(u)]
            else:
                page_urls += locs
        # Leftover from a spam hack: robots.txt still lists the attacker's numbered sitemaps after the pages were removed
        if len(dead) >= 3:
            self.extra.append(Finding("outside", f"robots.txt lists {len(dead)} sitemaps that don't exist", "MEDIUM",
                                      site.abs_url("/robots.txt"),
                                      "Attackers add their own sitemaps to robots.txt to get spam pages indexed; these "
                                      "are left over even if the spam pages are gone. Remove the sitemap lines you "
                                      "didn't add and check Search Console for unknown owners.",
                                      {"sitemaps": dead[:20]}))
        page_urls = list(dict.fromkeys(page_urls))[:max_urls]
        self.stats.update(sitemaps=len(seen), sitemap_urls=len(page_urls))
        for url in page_urls:
            self.check_url(url, "sitemap")
        return page_urls

    def check_url(self, url, source):
        """Flag URLs whose shape or words look like spam (confirmed later by fetching them)."""
        if allowed_path(url, self.allowed_paths) or url in self.suspicious_urls:
            return
        parsed = urlparse(url)
        tail = parsed.path + ("?" + parsed.query if parsed.query else "")
        if self.site.is_external(url):
            source += ", another domain"   # sister domains in sitemaps are normal; only the words decide
        if not self.expect_ja and "japanese" not in self.allowed_kinds and KANA.search(unquote(url)):
            self.suspicious_urls[url] = f"Japanese text in URL ({source})"
        elif SPAM_SLUG.search(unquote(tail)):
            self.suspicious_urls[url] = f"spam words in URL ({source})"
        elif source == "sitemap" and SPAM_URL.search(tail):  # the shape is common in normal links (archives, trackers)
            self.suspicious_urls[url] = f"spam generator URL shape ({source})"

    def generator_probe(self, home_title):
        """Doorway generators answer any URL of the right shape with a fresh spam page."""
        site = self.site
        word = "".join(random.choices(string.ascii_lowercase, k=5))
        number = random.randint(10000, 99999)
        for path in (f"/{word}{number}.html", f"/?{word[:3]}={number}"):
            resp, markup = site.fetch(path, GOOGLEBOT_UA)
            if resp is None or resp.status_code != 200:
                continue
            result, kinds, _, title, _ = self.judge(resp.url, markup)
            if result == "spam" and title != home_title:
                self.spam_urls[resp.url] = "generated for a made-up URL"
                self.extra.append(Finding("outside", "A spam page generator answers made-up URLs", "CRITICAL",
                                          f"The made-up URL {path} returns HTTP 200 with {describe(kinds)} spam for Googlebot.",
                                          "A script on the server generates spam pages on demand, usually a PHP file "
                                          "included from index.php or .htaccess. Cleaning the database alone won't stop it.",
                                          {"probe": path, "url": resp.url}))
                return

    def run(self):
        cfg, site = self.cfg, self.site
        sitemap_urls = self.sitemaps()
        start = list(dict.fromkeys([site.url] + [site.abs_url(p) for p in site.pages]
                                   + [u for u in self.suspicious_urls if not site.is_external(u)][:20]
                                   + [u for u in sitemap_urls if not site.is_external(u)][:int(cfg.get("sitemap_sample", 20))]))
        pages = crawl(site, start, max_pages=int(cfg.get("max_pages", 60)), workers=int(cfg.get("crawl_workers", 3)))
        self.stats["pages"] = len(pages)
        for page in pages.values():
            self.analyse(page)
            for href in LINK_HREF.findall(page.bot_html or ""):  # links only Googlebot sees
                self.check_url(href, "Googlebot-only link" if href not in (page.html or "") else "link")
        self.conditional_redirects(list(pages)[:int(cfg.get("redirect_probe_pages", 5))])
        if cfg.get("probe_random_paths", True):
            home = pages.get(next(iter(pages), ""), None)
            self.generator_probe(page_score(home.bot_html)[1] if home else "")

        unconfirmed = {u: why for u, why in self.suspicious_urls.items() if u not in self.spam_urls}
        if unconfirmed:
            listed = sorted(unconfirmed)
            self.extra.append(Finding("outside", f"{len(unconfirmed)} suspicious URL(s) found", "MEDIUM",
                                      "URLs whose shape or words look like spam pages: " + ", ".join(listed[:3])
                                      + (f" and {len(listed) - 3} more." if len(listed) > 3 else "."),
                                      "Open them as Googlebot (Search Console > URL Inspection). Spam pages must return "
                                      "404/410 after cleanup.", {"urls": [{"url": u, "why": unconfirmed[u]}
                                                                          for u in listed[:100]]}))
        return self
