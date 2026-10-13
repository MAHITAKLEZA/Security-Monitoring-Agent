"""Findings and the HTTP view of one site."""

import gzip
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0 Safari/537.36")
MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "Version/17.5 Mobile/15E148 Safari/604.1")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Finding:
    phase: str                       # "outside" | "inside"
    title: str
    severity: str                    # one of SEVERITIES
    detail: str = ""
    recommendation: str = ""
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def rank(severity):
    return SEVERITIES.index(severity)


def days_since(stamp):
    """Days since an ISO 8601 timestamp (as the WordPress REST API returns them); None if unparseable."""
    try:
        when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).days


def same_site(host, domain):
    host = (host or "").lower()
    return host == domain or host.endswith("." + domain)


class Site:
    def __init__(self, url, timeout=20, pages=None, wp_auth=None):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        self.url = url
        self.scheme = parsed.scheme
        self.host = parsed.hostname.lower()
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.domain = self.host[4:] if self.host.startswith("www.") else self.host
        self.pages = pages or [parsed.path or "/"]
        self.timeout = timeout
        self.wp_auth = wp_auth           # (username, application password) or None
        self.session = requests.Session()
        # Shared hosts drop or throttle connections under load: retry those with a short backoff
        retry = Retry(total=3, connect=3, read=2, backoff_factor=1.0, status_forcelist=(429, 502, 503, 504),
                      allowed_methods=frozenset({"GET", "HEAD"}), respect_retry_after_header=True)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=16)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    @property
    def secure(self):
        """Safe to send credentials: HTTPS, or a loopback address (local testing)."""
        return self.scheme == "https" or self.host in ("localhost", "127.0.0.1", "::1")

    def abs_url(self, path_or_url):
        return urljoin(self.origin + "/", path_or_url)

    def is_external(self, url):
        host = urlparse(self.abs_url(url)).hostname
        return bool(host) and not same_site(host, self.domain)

    def fetch(self, url, ua=BROWSER_UA, referer=None, redirects=True, max_bytes=2_000_000):
        """(response, text) for at most `max_bytes` of the body; (None, '') on network error."""
        headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        if referer:
            headers["Referer"] = referer
        try:
            with self.session.get(self.abs_url(url), headers=headers, timeout=self.timeout, stream=True,
                                  allow_redirects=redirects) as resp:
                body = bytearray()
                for chunk in resp.iter_content(16384):
                    body.extend(chunk)
                    if len(body) >= max_bytes:
                        break
        except requests.RequestException:
            return None, ""
        body = bytes(body[:max_bytes])
        if body[:2] == b"\x1f\x8b":  # .xml.gz sitemaps
            try:
                body = gzip.decompress(body)
            except OSError:
                pass
        return resp, body.decode(resp.encoding or "utf-8", errors="replace")

    # ---- WordPress REST API (authenticated) --------------------------------
    def wp(self, method, route, **kwargs):
        """Call /wp-json<route> with the application password. Returns (status, json or None)."""
        kwargs.setdefault("timeout", self.timeout)
        try:
            resp = self.session.request(method, self.abs_url("/wp-json" + route), auth=self.wp_auth, **kwargs)
        except requests.RequestException as exc:
            return None, {"error": str(exc)}
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, None

    def wp_items(self, route, limit=1000, **params):
        """All items of a collection, newest first (at most `limit`); [] if missing or forbidden."""
        out, page = [], 1
        while len(out) < limit:
            try:
                resp = self.session.get(self.abs_url("/wp-json" + route), auth=self.wp_auth, timeout=self.timeout,
                                        params={**params, "per_page": 100, "page": page})
                data = resp.json()
            except (requests.RequestException, ValueError):
                break
            if resp.status_code != 200 or not isinstance(data, list):
                break
            out += data
            if page >= int(resp.headers.get("X-WP-TotalPages") or 1):
                break
            page += 1
        return out[:limit]
