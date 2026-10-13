"""Heuristic scoring of web content for SEO spam, hidden content and redirect code."""

import html as html_lib
import re
from urllib.parse import unquote, urlparse

KANA = re.compile(r"[぀-ゟ゠-ヿｦ-ﾟ]")          # hiragana/katakana: Japanese only
CJK = re.compile(r"[぀-ヿ㐀-䶿一-鿿ｦ-ﾟ]")
# Japanese keyword hack vocabulary: counterfeit brand goods, discount and shopping terms
SPAM_TERMS = (
    "ブランドコピー", "N級品", "レプリカ", "スーパーコピー", "コピー品", "偽物", "偽ブランド", "激安", "通販", "送料無料",
    "最安値", "格安", "販売店", "専門店", "新作", "人気", "大人気", "正規品", "代引き", "即納", "着払い", "セール", "割引",
    "口コミ", "楽天", "安い", "店舗", "ブランド", "財布", "バッグ", "腕時計", "時計", "ルイヴィトン", "ヴィトン", "シャネル",
    "グッチ", "エルメス", "ロレックス", "プラダ", "オメガ", "カルティエ", "コーチ", "ナイキ", "アディダス", "モンクレール",
    "シュプリーム", "パネライ",
)
# Counterfeit-selling vocabulary: never legitimate, so it is what decides on Japanese-language sites
# ("偽物" and "レプリカ" are left out: real marketplaces use them in warnings and listings)
COUNTERFEIT_TERMS = ("スーパーコピー", "コピー品", "偽ブランド", "ブランドコピー", "N級品")
SPAM_RE = re.compile("|".join(map(re.escape, sorted(SPAM_TERMS, key=len, reverse=True))))
# Other SEO spam families (two different terms of one family are needed to call it spam)
CATEGORY_TERMS = {
    "pharma": ("viagra", "cialis", "levitra", "kamagra", "tramadol", "xanax", "valium", "phentermine", "ambien",
               "priligy", "propecia", "accutane", "online pharmacy", "without prescription", "no prescription",
               "generic viagra", "buy cialis", "erectile dysfunction pills"),
    "gambling": ("slot gacor", "situs slot", "slot online", "judi online", "judi bola", "togel", "sbobet", "maxwin",
                 "rtp slot", "rtp live", "scatter hitam", "link alternatif", "bandar togel", "casino online",
                 "online casino", "poker online", "slot88", "slot777", "gacor", "pragmatic play", "pg soft"),
    "adult": ("porn", "xxx", "escort service", "escorts", "sex cams", "hentai", "adult dating", "hot singles",
              "nude girls", "onlyfans leak"),
    "scam": ("payday loans", "replica watches", "cheap jerseys", "fake id", "buy followers", "essay writing service",
             "crypto doubler", "free bitcoin", "airdrop claim"),
}
CATEGORY_RE = {cat: re.compile(r"(?<![a-z0-9])(?:" + "|".join(map(re.escape, terms)) + r")(?![a-z0-9])", re.I)
               for cat, terms in CATEGORY_TERMS.items()}
CATEGORY_LABEL = {"japanese": "Japanese", "pharma": "pharma", "gambling": "gambling", "adult": "adult",
                  "scam": "scam"}

TAGS = re.compile(r"<script\b.*?</script>|<style\b.*?</style>|<[^>]+>", re.I | re.S)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
DESCRIPTION = re.compile(r"<meta[^>]+name\s*=\s*[\"']description[\"'][^>]*content\s*=\s*[\"']([^\"']*)", re.I)


def strip_html(markup):
    return " ".join(html_lib.unescape(TAGS.sub(" ", markup or "")).split())


def score(text):
    """Japanese character counts, Japanese spam vocabulary and other spam families found in plain text."""
    chars = len(re.sub(r"\s", "", text))
    cjk = len(CJK.findall(text))
    categories = {}
    for cat, regex in CATEGORY_RE.items():
        found = sorted({m.lower() for m in regex.findall(text)})
        if found:
            categories[cat] = found
    return {"kana": len(KANA.findall(text)), "cjk": cjk, "ratio": round(cjk / chars, 3) if chars else 0.0,
            "terms": sorted(set(SPAM_RE.findall(text))), "categories": categories}


def spam_kinds(sc, expect_japanese=False, min_kana=10, allowed=()):
    """Spam families present: 'japanese', 'pharma', 'gambling', 'adult', 'scam' (minus the allowed ones)."""
    kinds = []
    if "japanese" not in allowed and (sc["kana"] >= min_kana or (sc["kana"] and len(sc["terms"]) >= 2)):
        if expect_japanese:  # shopping words are normal on a Japanese site; counterfeit words are not
            if any(t in COUNTERFEIT_TERMS for t in sc["terms"]) and len(sc["terms"]) >= 3:
                kinds.append("japanese")
        elif len(sc["terms"]) >= 2:
            kinds.append("japanese")
    for cat, terms in sc.get("categories", {}).items():
        if cat not in allowed and len(terms) >= 2:
            kinds.append(cat)
    return kinds


def verdict(sc, expect_japanese=False, min_kana=10, allowed=()):
    """'spam' (any spam family), 'japanese' (unexpected Japanese text without spam vocabulary) or None."""
    if spam_kinds(sc, expect_japanese, min_kana, allowed):
        return "spam"
    if not expect_japanese and "japanese" not in allowed and sc["kana"] >= 50:
        return "japanese"
    return None


def terms_of(sc, kinds=None):
    """Spam words behind a score, for messages."""
    out = list(sc["terms"]) if not kinds or "japanese" in kinds else []
    for cat, terms in sc.get("categories", {}).items():
        if not kinds or cat in kinds:
            out += terms
    return out


def describe(kinds):
    return "/".join(CATEGORY_LABEL.get(k, k) for k in kinds) or "spam"


def page_score(markup):
    """(score, title, plain text) for an HTML page, counting the title and meta description."""
    title = TITLE.search(markup or "")
    desc = DESCRIPTION.search(markup or "")
    body = strip_html(markup)
    text = " ".join(filter(None, (title and title.group(1), desc and desc.group(1), body)))
    return score(text), strip_html(title.group(1)) if title else "", body


def allowed_path(url, allowed_prefixes):
    path = unquote(urlparse(url).path or "/")
    return any(path.startswith(p) for p in allowed_prefixes or [])


# ---- hidden content ---------------------------------------------------------------
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|em|rem)?\s*(?:;|$)|"
                          r"(?:left|top|text-indent)\s*:\s*-\d{3,}px|(?:height|width)\s*:\s*0(?:px)?\s*;[^\"']*overflow\s*:\s*hidden|"
                          r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)", re.I)
SEO_HIDING = re.compile(r"font-size\s*:\s*0|(?:left|top|text-indent)\s*:\s*-\d{3,}px|(?:height|width)\s*:\s*0|"
                        r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)", re.I)
TAG = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>", re.S)
VOID = {"br", "img", "input", "meta", "link", "hr", "source", "area", "base", "col", "embed", "wbr", "track", "param"}
LINK_HREF = re.compile(r"<a\b[^>]*\bhref\s*=\s*[\"']?(https?://[^\"'\s>]+)", re.I)


def hidden_blocks(markup, limit=200, with_style=False):
    """Inner HTML of elements hidden with inline styles or the `hidden` attribute (what visitors can't see).
    with_style=True returns (inner HTML, seo_style) pairs; seo_style is True for off-screen, zero-size, zero-font or
    transparent hiding, which menus and modals (display:none, hidden) don't use."""
    blocks, stack = [], []   # stack of (tag, start, hidden, seo_style)
    for m in TAG.finditer(markup or ""):
        closing, tag, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if tag in VOID or attrs.rstrip().endswith("/"):
            continue
        if not closing:
            style = re.search(r"\bstyle\s*=\s*[\"']([^\"']*)", attrs, re.I)
            hidden = bool(style and HIDDEN_STYLE.search(style.group(1))) or bool(re.search(r"\shidden(?:\s|=|$)", attrs))
            stack.append((tag, m.end(), hidden, bool(style and SEO_HIDING.search(style.group(1)))))
            continue
        while stack:
            open_tag, start, hidden, seo = stack.pop()
            if open_tag == tag:
                if hidden and not any(entry[2] for entry in stack):  # outermost hidden element only
                    blocks.append((markup[start:m.start()], seo) if with_style else markup[start:m.start()])
                    if len(blocks) >= limit:
                        return blocks
                break
    return blocks


def without_hidden(markup):
    """The markup minus hidden elements: what a visitor can actually see."""
    for block in hidden_blocks(markup):
        markup = markup.replace(block, " ", 1)
    return markup


# ---- redirect code ----------------------------------------------------------------
META_REFRESH = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*content\s*=\s*[\"'][^\"']*url\s*=\s*([^\"'>\s]+)", re.I)
JS_REDIRECT = re.compile(r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*[\"'](https?://[^\"']+)|"
                         r"location\.(?:replace|assign)\s*\(\s*[\"'](https?://[^\"']+)", re.I)
REFERRER_CHECK = re.compile(r"document\.referrer[^;]{0,200}(?:google|bing|yahoo|yandex|baidu)|"
                            r"(?:google|bing|yahoo|yandex|baidu)[^;]{0,200}document\.referrer", re.I)
OBFUSCATED_REDIRECT = re.compile(r"(?:location|window\.open)[^;]{0,120}(?:atob|unescape|fromCharCode|decodeURIComponent)\s*\(|"
                                 r"(?:atob|unescape|fromCharCode)\s*\([^;]{0,400}location", re.I)
MOBILE_CHECK = re.compile(r"navigator\.userAgent[^;]{0,200}(?:android|iphone|mobile)", re.I)
