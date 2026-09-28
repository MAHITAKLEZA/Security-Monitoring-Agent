import copy
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

DEFAULTS = {
    # Settings shared by every site (timeout, user_agent). A single-site config may also put url/domain/pages here.
    "target": {
        "timeout": 15,
        "user_agent": "SecurityMonitor/1.0 (authorized self-monitoring)",
    },
    # List of sites to monitor; each entry: url (required), name, domain, pages, checks (per-site overrides)
    "targets": [],
    "checks": {
        "ssl": {"enabled": True, "expiry_warning_days": 30, "expiry_critical_days": 7},
        "headers": {"enabled": True},
        "exposed_files": {"enabled": True, "max_workers": 4, "max_sourcemap_checks": 5, "extra_paths": []},
        "changes": {"enabled": True, "content_similarity_threshold": 0.6, "auto_update_baseline": False},
        "malware": {
            "enabled": True,
            "scan_same_origin_js": True,
            "max_js_files": 25,
            "trusted_hidden_iframe_domains": ["googletagmanager.com"],
            "safe_browsing_api_key_env": "GSB_API_KEY",
            "inside_scan": True,
            "trusted_script_domains": [],
        },
        "vulnerabilities": {"enabled": True},
        "dns": {"enabled": True, "domain_expiry_warning_days": 45},
        "third_party": {"enabled": True, "allowed_script_domains": []},
        # Off by default; enable per WordPress site. The application password is read from `app_password_env`.
        "wordpress": {
            "enabled": False,
            "username": None,
            "app_password_env": "WP_APP_PASSWORD",
            "app_password_file": None,
            "wpscan_api_token_env": "WPSCAN_API_TOKEN",
            "max_admins": 3,
            "stale_app_password_days": 90,
            "abandoned_plugin_days": 730,
        },
    },
    "report": {"output_dir": "reports", "state_dir": "state", "fail_on": "HIGH", "max_parallel_sites": 2},
    # daily_at: local time (HH:MM) at which the dashboard server (--serve) scans every site
    "schedule": {"interval_minutes": 60, "daily_at": "09:00"},
    # Sites added from the dashboard ("Add Link") are stored here, next to the ones in `targets`
    "sites_file": "sites.json",
    # Login for the --serve dashboard. Set enabled: false to turn the login page off.
    "auth": {"enabled": True, "email": "admin@kleza.io", "password": "change-me", "name": "Administrator"},
}

SHARED_TARGET_KEYS = ("timeout", "user_agent")


def _merge(base, override):
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path=None):
    config = copy.deepcopy(DEFAULTS)
    if path and Path(path).exists():
        with open(path, encoding="utf-8") as fh:
            _merge(config, yaml.safe_load(fh) or {})
    return config


def _slug(text):
    return re.sub(r"[^a-z0-9.-]+", "-", text.lower()).strip("-") or "site"


def _norm_url(url):
    return url.rstrip("/").lower()


def load_managed_sites(config):
    """Sites added from the dashboard (kept separate so config.yaml and its comments are never rewritten)."""
    try:
        data = json.loads(Path(config.get("sites_file") or "sites.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [d for d in data if isinstance(d, dict) and d.get("url")] if isinstance(data, list) else []


def save_managed_sites(config, sites):
    path = Path(config.get("sites_file") or "sites.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(sites, indent=2), encoding="utf-8")
    tmp.replace(path)


def resolve_targets(config, urls=None):
    """Expand the config into one fully-resolved dict per monitored site.

    Sources: `urls` (CLI) if given; otherwise the `targets` list (or legacy single `target.url`)
    plus sites added from the dashboard. May return an empty list.
    """
    base = config["target"]
    if urls:
        entries = [({"url": u}, False) for u in urls]
    else:
        configured = config.get("targets") or ([base] if base.get("url") else [])
        entries = [(e, False) for e in configured]
        known = {_norm_url(e if isinstance(e, str) else e.get("url", "")) for e in configured}
        entries += [(e, True) for e in load_managed_sites(config) if _norm_url(e["url"]) not in known]

    resolved, slugs = [], set()
    for entry, managed in entries:
        if isinstance(entry, str):
            entry = {"url": entry}
        url = entry.get("url")
        if not url:
            raise ValueError(f"Target entry without url: {entry}")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        target = {key: base[key] for key in SHARED_TARGET_KEYS if key in base}
        target.update({"domain": None, "pages": ["/"], "name": None})
        target.update({k: v for k, v in entry.items() if k != "checks"})
        target["url"] = url
        target["managed"] = managed
        target["name"] = target["name"] or urlparse(url).hostname
        target["checks"] = _merge(copy.deepcopy(config["checks"]), entry.get("checks") or {})
        slug, n = _slug(target["name"]), 2
        while slug in slugs:
            slug, n = f"{_slug(target['name'])}-{n}", n + 1
        slugs.add(slug)
        target["slug"] = slug
        resolved.append(target)
    return resolved
