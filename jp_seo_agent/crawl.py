"""Site crawler: follows internal links from the start pages (plus a sample of sitemap URLs), fetching every page
as a visitor and as Googlebot so cloaked content shows up as a difference between the two."""

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlparse

from .site import BROWSER_UA, GOOGLEBOT_UA

HREF = re.compile(r"<a\b[^>]*\bhref\s*=\s*[\"']?([^\"'\s>]+)", re.I)
SKIP_EXT = re.compile(r"\.(?:jpe?g|png|gif|webp|svg|ico|bmp|avif|pdf|zip|gz|rar|7z|mp[34]|mov|avi|webm|woff2?|ttf|"
                      r"eot|css|js|json|xml|txt|docx?|xlsx?|pptx?|csv)$", re.I)
SKIP_PATH = re.compile(r"^/(?:wp-admin|wp-login\.php|wp-json|xmlrpc\.php|cart|checkout|my-account|feed)(?:/|$)|/feed/?$", re.I)


@dataclass
class Page:
    url: str
    status: int = 0                # visitor
    html: str = ""
    final_url: str = ""
    bot_status: int = 0            # Googlebot
    bot_html: str = ""
    bot_final_url: str = ""
    depth: int = 0


def _normalise(url):
    url = urldefrag(url)[0]
    parsed = urlparse(url)
    return parsed._replace(path=parsed.path or "/").geturl()


def crawl(site, start_urls, max_pages=60, workers=4):
    """Breadth-first crawl of same-site HTML pages. Returns {url: Page}."""
    pages, seen = {}, set()
    queue = []
    for url in start_urls:
        url = _normalise(site.abs_url(url))
        if url not in seen and not site.is_external(url):
            seen.add(url)
            queue.append((url, 0))

    def fetch(item):
        url, depth = item
        page = Page(url, depth=depth)
        resp, markup = site.fetch(url, BROWSER_UA)
        if resp is not None:
            page.status, page.final_url = resp.status_code, resp.url
            page.html = markup if "html" in resp.headers.get("Content-Type", "html") else ""
        resp, markup = site.fetch(url, GOOGLEBOT_UA)
        if resp is not None:
            page.bot_status, page.bot_final_url = resp.status_code, resp.url
            page.bot_html = markup if "html" in resp.headers.get("Content-Type", "html") else ""
        return page

    with ThreadPoolExecutor(max_workers=workers) as pool:
        while queue and len(pages) < max_pages:
            batch, queue = queue[:max_pages - len(pages)], queue[max_pages - len(pages):]
            for page in pool.map(fetch, batch):
                pages[page.url] = page
                for markup in (page.html, page.bot_html):
                    for href in HREF.findall(markup or ""):
                        link = _normalise(urljoin(page.final_url or page.url, href.strip()))
                        parsed = urlparse(link)
                        if (parsed.scheme not in ("http", "https") or site.is_external(link) or link in seen
                                or SKIP_EXT.search(parsed.path) or SKIP_PATH.search(parsed.path)):
                            continue
                        seen.add(link)
                        queue.append((link, page.depth + 1))
    return pages
