"""Suspicious change detection against a stored baseline.

Tracks signals that matter for security (new script/iframe origins, form targets, title,
security headers, status) plus a similarity score of visible text. Build-hash churn in
bundle filenames is deliberately ignored.
"""

import difflib
import hashlib
from urllib.parse import urlparse

from ..models import Finding, Severity as S

NAME = "changes"
MAX_TEXT_WORDS = 5000
SECURITY_HEADERS = (
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
)


def _hosts(ctx, urls):
    return sorted({urlparse(u).hostname for u in urls if u and ctx.is_external(u)})


def _snapshot(ctx, resp, page):
    words = page.text.split()[:MAX_TEXT_WORDS]
    return {
        "status": resp.status_code,
        "final_url": resp.url,
        "title": page.title,
        "meta_description": page.meta.get("description", ""),
        "generator": page.meta.get("generator", ""),
        "script_domains": _hosts(ctx, (s["src"] for s in page.scripts)),
        "iframe_domains": _hosts(ctx, (i["src"] for i in page.iframes)),
        "form_actions": sorted({f["action"] for f in page.forms if f["action"]}),
        "inline_script_count": len(page.inline_scripts),
        "text_hash": hashlib.sha256(" ".join(words).encode()).hexdigest(),
        "text_words": words,
        "security_headers": {k: resp.headers[k] for k in SECURITY_HEADERS if k in resp.headers},
    }


def _compare(ctx, path, old, new, threshold):
    f = []
    where = f"[{path}] "

    if old["status"] != new["status"]:
        f.append(Finding(NAME, where + f"HTTP status changed {old['status']} -> {new['status']}",
                         S.HIGH if new["status"] >= 400 else S.LOW, "",
                         "Check for outage, defacement or misconfiguration."))
    if urlparse(old["final_url"]).hostname != urlparse(new["final_url"]).hostname:
        f.append(Finding(NAME, where + "Page now redirects to a different host", S.HIGH,
                         f"{old['final_url']} -> {new['final_url']}", "Verify the redirect is intentional (possible hijack)."))

    added = sorted(set(new["script_domains"]) - set(old["script_domains"]))
    if added:
        f.append(Finding(NAME, where + "New third-party script origin(s) appeared", S.HIGH, ", ".join(added),
                         "Confirm each new script origin was added intentionally. Unexpected script origins are "
                         "the typical sign of injected skimmers/malware.", {"added": added}))
    removed = sorted(set(old["script_domains"]) - set(new["script_domains"]))
    if removed:
        f.append(Finding(NAME, where + "Third-party script origin(s) removed", S.INFO, ", ".join(removed)))

    added_iframes = sorted(set(new["iframe_domains"]) - set(old["iframe_domains"]))
    if added_iframes:
        f.append(Finding(NAME, where + "New iframe origin(s) appeared", S.HIGH, ", ".join(added_iframes),
                         "Verify the embedded content is legitimate."))

    added_forms = sorted(set(new["form_actions"]) - set(old["form_actions"]))
    for action in added_forms:
        external = ctx.is_external(action)
        f.append(Finding(NAME, where + ("Form now submits to an external host" if external else "New form target"),
                         S.HIGH if external else S.LOW, action,
                         "Confirm form destinations; external form targets can harvest user data."))

    if old["title"] != new["title"]:
        f.append(Finding(NAME, where + "Page title changed", S.MEDIUM, f"'{old['title']}' -> '{new['title']}'",
                         "Confirm the change was intentional (title changes are common in defacements)."))
    for key, label in (("meta_description", "Meta description"), ("generator", "Generator meta tag")):
        if old[key] != new[key]:
            f.append(Finding(NAME, where + f"{label} changed", S.LOW, f"'{old[key]}' -> '{new[key]}'"))

    if new["inline_script_count"] > old["inline_script_count"] + 3:
        f.append(Finding(NAME, where + "Number of inline scripts increased", S.LOW,
                         f"{old['inline_script_count']} -> {new['inline_script_count']}",
                         "Review newly added inline scripts."))

    for header, value in old["security_headers"].items():
        if header not in new["security_headers"]:
            f.append(Finding(NAME, where + f"Security header removed: {header}", S.MEDIUM, value,
                             "Restore the header; check recent server/CDN config changes."))
        elif new["security_headers"][header] != value:
            f.append(Finding(NAME, where + f"Security header changed: {header}", S.LOW,
                             f"{value} -> {new['security_headers'][header]}"))

    if old["text_hash"] != new["text_hash"]:
        ratio = difflib.SequenceMatcher(None, old["text_words"], new["text_words"], autojunk=False).ratio()
        if ratio < threshold:
            f.append(Finding(NAME, where + "Significant content change detected", S.MEDIUM,
                             f"Visible text similarity to baseline is {ratio:.0%}.",
                             "Review the page for defacement, SEO spam or unauthorized edits.",
                             {"similarity": round(ratio, 3)}))
        else:
            f.append(Finding(NAME, where + "Page content updated", S.INFO,
                             f"Visible text similarity to baseline is {ratio:.0%}.", evidence={"similarity": round(ratio, 3)}))
    return f


def run(ctx, cfg, state):
    baselines = state.setdefault(NAME, {}).setdefault("pages", {})
    threshold = cfg.get("content_similarity_threshold", 0.6)
    findings = []
    for path, resp, page in ctx.all_pages():
        snapshot = _snapshot(ctx, resp, page)
        previous = baselines.get(path)
        if previous is None:
            findings.append(Finding(NAME, f"[{path}] Baseline recorded", S.INFO,
                                    f"{len(snapshot['script_domains'])} external script origins, "
                                    f"{len(snapshot['text_words'])} words of content.",
                                    evidence={"script_domains": snapshot["script_domains"]}))
            baselines[path] = snapshot
            continue
        findings.extend(_compare(ctx, path, previous, snapshot, threshold))
        # Keep the approved baseline so changes stay reported until accepted (--accept-changes),
        # unless auto-update is enabled.
        if cfg.get("auto_update_baseline", False):
            baselines[path] = snapshot
    if not findings:
        findings.append(Finding(NAME, "No changes since last scan", S.INFO))
    return findings
