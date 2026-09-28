import threading
from urllib.parse import urljoin, urlparse

import requests

from .html_parser import parse_html


def same_site(host, domain):
    host = (host or "").lower()
    return host == domain or host.endswith("." + domain)


class SiteContext:
    """Shared HTTP session and page cache for all checks in one scan."""

    def __init__(self, url, timeout=15, user_agent="SecurityMonitor/1.0", domain=None, pages=None):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        self.url = url
        self.scheme = parsed.scheme
        self.host = parsed.hostname.lower()
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = (domain or (self.host[4:] if self.host.startswith("www.") else self.host)).lower()
        self.home_path = parsed.path or "/"
        self.pages = pages or [self.home_path]
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
        self._pages = {}
        self._text_cache = {}
        self._lock = threading.Lock()
        self.wp_auth = None  # (username, application password) when the site has WordPress credentials

    def abs_url(self, path_or_url):
        return urljoin(self.origin + "/", path_or_url)

    def request(self, method, path_or_url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        return self.session.request(method, self.abs_url(path_or_url), **kwargs)

    def get(self, path_or_url, **kwargs):
        return self.request("GET", path_or_url, **kwargs)

    def page(self, path="/"):
        """Return (response, PageInfo) for a page, fetched once per scan."""
        if path not in self._pages:
            resp = self.get(path)
            self._pages[path] = (resp, parse_html(resp.text, resp.url))
        return self._pages[path]

    @property
    def home(self):
        return self.page(self.home_path)

    def fetch_limited(self, path_or_url, max_bytes=65536, **kwargs):
        """GET at most `max_bytes` of a body. Returns (response, bytes)."""
        kwargs.setdefault("allow_redirects", False)
        with self.get(path_or_url, stream=True, **kwargs) as resp:
            body = bytearray()
            for chunk in resp.iter_content(8192):
                body.extend(chunk)
                if len(body) >= max_bytes:
                    break
            return resp, bytes(body[:max_bytes])

    def fetch_text(self, url, max_bytes=3_000_000):
        """Fetch a text asset (e.g. JS) once per scan; returns '' on failure."""
        with self._lock:
            if url in self._text_cache:
                return self._text_cache[url]
        try:
            resp, body = self.fetch_limited(url, max_bytes=max_bytes, allow_redirects=True)
            text = body.decode(resp.encoding or "utf-8", errors="replace") if resp.status_code == 200 else ""
        except requests.RequestException:
            text = ""
        with self._lock:
            self._text_cache[url] = text
        return text

    def is_external(self, url):
        host = urlparse(url).hostname
        return bool(host) and not same_site(host, self.domain)

    def all_pages(self):
        """Yield (path, response, PageInfo) for every configured page that loads."""
        for path in self.pages:
            try:
                resp, info = self.page(path)
            except requests.RequestException:
                continue
            yield path, resp, info
