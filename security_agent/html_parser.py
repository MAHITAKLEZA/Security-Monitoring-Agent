from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin

_SKIP_SCHEMES = ("data:", "javascript:", "#", "mailto:", "tel:", "blob:", "about:")
_RESOURCE_ATTRS = {
    "script": "src", "img": "src", "iframe": "src", "frame": "src", "link": "href",
    "embed": "src", "object": "data", "source": "src", "video": "src", "audio": "src",
}


@dataclass
class PageInfo:
    url: str
    title: str = ""
    meta: dict = field(default_factory=dict)
    scripts: list = field(default_factory=list)         # {"src", "integrity"}
    inline_scripts: list = field(default_factory=list)  # script bodies
    stylesheets: list = field(default_factory=list)     # {"href", "integrity"}
    iframes: list = field(default_factory=list)         # {"src", "hidden"}
    forms: list = field(default_factory=list)           # {"action", "method"}
    resources: list = field(default_factory=list)       # {"tag", "url"}
    text: str = ""


def _is_hidden(attrs):
    style = attrs.get("style", "").replace(" ", "").lower()
    if "display:none" in style or "visibility:hidden" in style:
        return True
    return any(attrs.get(dim, "").strip().lower().rstrip("px") in ("0", "1") for dim in ("width", "height"))


class _Parser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.info = PageInfo(url=base_url)
        self._script = None
        self._skip = 0
        self._in_title = False
        self._text = []

    def _abs(self, url):
        url = (url or "").strip()
        if not url or url.lower().startswith(_SKIP_SCHEMES):
            return ""
        return urljoin(self.base, url)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        info = self.info
        if tag in _RESOURCE_ATTRS:
            url = self._abs(a.get(_RESOURCE_ATTRS[tag]))
            if url:
                info.resources.append({"tag": tag, "url": url})
        if tag == "script":
            src = self._abs(a.get("src"))
            if src:
                info.scripts.append({"src": src, "integrity": a.get("integrity", "")})
            else:
                self._script = []
        elif tag == "style":
            self._skip += 1
        elif tag in ("iframe", "frame"):
            info.iframes.append({"src": self._abs(a.get("src")), "hidden": _is_hidden(a)})
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower():
            href = self._abs(a.get("href"))
            if href:
                info.stylesheets.append({"href": href, "integrity": a.get("integrity", "")})
        elif tag == "form":
            action = a.get("action", "").strip()
            info.forms.append({"action": self._abs(action) if action else "", "method": a.get("method", "get").lower()})
        elif tag == "meta":
            name = a.get("name") or a.get("property") or a.get("http-equiv")
            if name:
                info.meta[name.lower()] = a.get("content", "")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            self.info.inline_scripts.append("".join(self._script))
            self._script = None
        elif tag == "style" and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)
        elif self._skip:
            return
        elif self._in_title:
            self.info.title += data
        elif data.strip():
            self._text.append(data)

    def result(self):
        self.info.title = " ".join(self.info.title.split())
        self.info.text = " ".join(" ".join(self._text).split())
        return self.info


def parse_html(html, base_url):
    parser = _Parser(base_url)
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:  # malformed markup: keep whatever was parsed
        pass
    return parser.result()
