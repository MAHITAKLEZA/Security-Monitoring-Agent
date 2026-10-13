"""Daily Microsoft Teams card: one Adaptive Card after the scheduled scan, listing only sites with
HIGH/CRITICAL findings (notifications.teams.min_severity), worst site first.

The webhook URL is set from the dashboard (Settings > Teams alerts) and stored in
notifications.teams.webhook_url_file (git-ignored), or taken from the TEAMS_WEBHOOK_URL environment variable."""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

from .ignored import apply_ignored, ignore_key, load_ignored
from .models import Severity as S
from .schedule import schedule_tz

log = logging.getLogger("security_agent.notify")
MAX_PER_SITE = 5


# ---- webhook URL ----------------------------------------------------------
def _cfg(config):
    return (config.get("notifications") or {}).get("teams") or {}


def _webhook_file(config):
    return Path(_cfg(config).get("webhook_url_file") or "secrets/teams.env")


def get_webhook(config):
    url = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if not url:
        try:
            for line in _webhook_file(config).read_text(encoding="utf-8-sig").splitlines():
                key, sep, value = line.strip().partition("=")
                if sep and key.strip().lower() == "webhook_url":
                    url = value.strip().strip("\"'")
        except OSError:
            pass
    return url


def save_webhook(config, url):
    """Store the webhook URL (empty string removes it). Raises ValueError for an invalid URL."""
    url = (url or "").strip()
    path = _webhook_file(config)
    if not url:
        path.unlink(missing_ok=True)
        return
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or any(c.isspace() for c in url):
        raise ValueError("Enter the full https:// webhook URL from Teams Workflows")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Teams webhook for the daily security card (set from the dashboard). Never commit this file.\n"
                    f"webhook_url={url}\n", encoding="utf-8")


def webhook_status(config):
    """What the settings page may show: never the full URL, since it works as a password."""
    url = get_webhook(config)
    host = urlparse(url).hostname or ""
    return {"configured": bool(url), "masked": f"https://{host}/…{url[-6:]}" if url else "",
            "from_env": bool(os.environ.get("TEAMS_WEBHOOK_URL")),
            "min_severity": S.parse(_cfg(config).get("min_severity", "HIGH")).name}


# ---- card -------------------------------------------------------------------
def _state_file(config):
    return Path(config["report"]["state_dir"]) / "teams_card.json"


def _previous_keys(config):
    try:
        return set(json.loads(_state_file(config).read_text(encoding="utf-8"))["keys"])
    except (OSError, ValueError, KeyError):
        return None


def _site_alerts(config, targets, threshold):
    out = Path(config["report"]["output_dir"])
    ignored = load_ignored(config)  # findings hidden with "Ignore" in the dashboard are not sent to Teams
    rows = []
    for t in targets:
        try:
            latest = json.loads((out / t["slug"] / "latest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        latest = apply_ignored(latest, ignored.get(t["slug"], {}))
        alerts = [f for f in latest.get("findings", []) if S.parse(f["severity"]) >= threshold]
        if alerts:
            rows.append({"name": t["name"], "slug": t["slug"], "latest": latest, "alerts": alerts})
    # Worst first: CRITICAL before HIGH, then the lowest risk score
    rows.sort(key=lambda r: (-S.parse(r["latest"]["worst_severity"]), r["latest"].get("risk_score", 100)))
    return rows


def _key(row, finding):
    return f"{row['slug']}|{finding['check']}|{finding['title']}"


def build_card(rows, total_sites, previous_keys, now):
    issues = sum(len(r["alerts"]) for r in rows)
    body = [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True,
         "text": f"Daily High-Risk Alerts · {now:%a %d %b %Y, %H:%M}"},
        {"type": "TextBlock", "isSubtle": True, "spacing": "None", "wrap": True,
         "text": f"{len(rows)} of {total_sites} site(s) with high issues · {issues} issue(s)"},
    ]
    for r in rows:
        body.append({"type": "TextBlock", "weight": "Bolder", "wrap": True, "separator": True, "spacing": "Medium",
                     "text": r["name"]})
        for f in r["alerts"][:MAX_PER_SITE]:
            new = previous_keys is not None and _key(r, f) not in previous_keys
            body.append({"type": "TextBlock", "wrap": True, "spacing": "Small",
                         "color": "Attention" if f["severity"] == "CRITICAL" else "Default",
                         "text": f"**{f['severity']}** · {f['check']} · {f['title']}" + ("  **[NEW]**" if new else "")})
        if len(r["alerts"]) > MAX_PER_SITE:
            body.append({"type": "TextBlock", "isSubtle": True, "spacing": "Small",
                         "text": f"…and {len(r['alerts']) - MAX_PER_SITE} more"})
    content = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
               "version": "1.4", "msteams": {"width": "Full"}, "body": body}
    return {"type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": content}]}


def _post(url, card):
    requests.post(url, json=card, timeout=20).raise_for_status()


def send_daily_card(config, targets, test=False):
    """Send the card after the scheduled scan. Days with no high-risk issues send nothing.

    `test=True` (the dashboard's "Send test card") always posts, without changing what counts as [NEW].
    Returns (ok, message)."""
    url = get_webhook(config)
    if not url:
        return False, "No Teams webhook URL set"
    threshold = S.parse(_cfg(config).get("min_severity", "HIGH"))
    now = datetime.now(schedule_tz(config["schedule"].get("timezone")))
    rows = _site_alerts(config, targets, threshold)
    if rows:
        card = build_card(rows, len(targets), _previous_keys(config), now)
    elif test:
        card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True,
                      "text": f"Test card · {now:%a %d %b %Y, %H:%M}"},
                     {"type": "TextBlock", "wrap": True,
                      "text": f"Teams alerts are connected. No {threshold.name} or higher issues on "
                              f"{len(targets)} site(s) right now, so the daily card would not be sent today."}]}}]}
    else:
        log.info("Daily Teams card: no %s+ issues, nothing sent", threshold.name)
        return True, "No high-risk issues; nothing sent"
    try:
        _post(url, card)
    except requests.RequestException as exc:
        log.warning("Teams card failed: %s", exc)
        return False, f"Teams did not accept the card: {exc.__class__.__name__}"
    if not test:
        path = _state_file(config)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"sent_at": now.isoformat(),
                                    "keys": sorted(_key(r, f) for r in rows for f in r["alerts"])}), encoding="utf-8")
    log.info("Teams card sent (%d site(s) with high-risk issues)", len(rows))
    return True, "Card sent to Teams"


# ---- urgent alerts: right away, not at the daily card ---------------------------


URGENT = (S.HIGH, S.CRITICAL)
EVENT_LABEL = {"reinfection": "Came back after a fix", "infection": "New problem", "recovery_failed":
               "Automatic fix failed", "escalated": "Keeps coming back: needs a person", "held": "Waiting for you",
               "recovered": "Fixed automatically"}


def _sent_file(config):
    return Path(config["report"]["state_dir"]) / "urgent_alerts.json"


def urgent_from_scan(config, target, report, previous, started):
    """What a finished scan needs to tell someone now: HIGH/CRITICAL problems that weren't in the previous report
    (none on a site's first scan; the daily card covers those) plus autonomous defense events from this scan
    (reinfections, problems that came back, automatic fixes). Ignored findings are left out."""
    ignored = load_ignored(config).get(target["slug"], {})
    items = []
    if previous is not None:
        known = {ignore_key(f"{f.get('check')}|{f.get('title')}") for f in previous.get("findings", [])}
        for f in report.get("findings", []):
            if S.parse(f["severity"]) in URGENT and ignore_key(f["title"]) not in ignored \
                    and ignore_key(f"{f['check']}|{f['title']}") not in known:
                items.append({"severity": f["severity"], "title": f["title"], "detail": f.get("detail", ""),
                              "check": f["check"], "kind": "New problem"})
    try:
        state = json.loads((Path(target["checks"].get("compromise", {}).get("defense_dir") or "state/defense")
                            / f"{(urlparse(target['url']).hostname or '').lower()}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    since = started.isoformat(timespec="seconds")
    items += [_event_item(e) for e in state.get("events", []) if e.get("time", "") >= since
              and e.get("type") in EVENT_LABEL and e.get("type") != "infection"]   # new problems are listed above
    return items


def _event_item(e):
    title = e["title"].split(": ", 1)[-1] if e.get("type") in ("reinfection", "infection") else e["title"]
    return {"severity": e.get("severity") or "HIGH", "title": title, "detail": e.get("detail", ""),
            "check": e.get("check") or "compromise", "kind": EVENT_LABEL[e["type"]], "event": e.get("id")}


def send_urgent_alert(config, target, items):
    """One Teams card right away for whatever needs attention now. A new problem already alerted in the last
    notifications.teams.urgent_repeat_hours (24) isn't sent again; events (a reinfection, an automatic fix) always
    are. Sent only when a webhook is set. Returns True when a card was sent."""
    url = get_webhook(config)
    if not items or not url or _cfg(config).get("urgent", True) is False:
        return False
    path = _sent_file(config)
    try:
        sent = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        sent = {}
    now = datetime.now(timezone.utc)
    repeat = timedelta(hours=float(_cfg(config).get("urgent_repeat_hours", 24)))
    fresh, keys = [], set()
    for item in items:
        key = f"{target['slug']}|{item['check']}|{ignore_key(item['title'])}"
        if key in keys:
            continue
        keys.add(key)
        last = sent.get(key)
        if item["kind"] == "New problem" and last and now - datetime.fromisoformat(last) < repeat:
            continue
        fresh.append(item)
    if not fresh:
        return False
    fresh.sort(key=lambda i: -S.parse(i["severity"]))
    local = now.astimezone(schedule_tz(config["schedule"].get("timezone")))
    worst = fresh[0]["severity"]
    body = [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "wrap": True,
             "color": "Attention" if S.parse(worst) in URGENT else "Default",
             "text": f"Needs attention now · {target['name']}"},
            {"type": "TextBlock", "isSubtle": True, "spacing": "None", "wrap": True,
             "text": f"{target['url']} · {local:%a %d %b %Y, %H:%M}"}]
    for item in fresh[:10]:
        body.append({"type": "TextBlock", "wrap": True, "separator": True,
                     "color": "Good" if item["kind"] == "Fixed automatically" else
                     "Attention" if S.parse(item["severity"]) in URGENT else "Warning",
                     "text": f"**{item['severity']}** · {item['kind']} · {item['check']} · {item['title']}"})
        if item.get("detail"):
            body.append({"type": "TextBlock", "wrap": True, "isSubtle": True, "spacing": "None",
                         "text": item["detail"][:400]})
    if len(fresh) > 10:
        body.append({"type": "TextBlock", "isSubtle": True, "text": f"…and {len(fresh) - 10} more"})
    body.append({"type": "TextBlock", "isSubtle": True, "wrap": True, "separator": True,
                 "text": "Open the dashboard for the proposed fixes (Remediation on each check's page)."})
    card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
        "msteams": {"width": "Full"}, "body": body}}]}
    try:
        _post(url, card)
    except requests.RequestException as exc:
        log.warning("Urgent Teams alert failed: %s", exc)
        return False
    for item in fresh:
        sent[f"{target['slug']}|{item['check']}|{ignore_key(item['title'])}"] = now.isoformat(timespec="seconds")
    cutoff = now - timedelta(days=30)
    sent = {k: v for k, v in sent.items() if datetime.fromisoformat(v) > cutoff}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sent, indent=1), encoding="utf-8")
    log.info("Urgent Teams alert sent for %s (%d item(s))", target["name"], len(fresh))
    return True


def send_defense_alert(config, target, events):
    """Alert for what a background check (integrity or security monitor) just found or did."""
    return send_urgent_alert(config, target, [_event_item(e) for e in events if e.get("type") in EVENT_LABEL])
