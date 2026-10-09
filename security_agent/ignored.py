"""Findings hidden with "Ignore" in the dashboard. Ignored findings are dropped from the dashboard, its counts and
risk score, and the Teams card; the JSON/Markdown/Excel reports on disk still list everything that was found."""

import json
import re
from pathlib import Path

from .models import Severity as S
from .report import RISK_WEIGHTS, STATUS


def _path(config):
    return Path(config["report"].get("state_dir", "state")) / "ignored.json"


def ignore_key(title):
    """Numbers are ignored so a finding stays hidden when only a version or a count changes
    ("Outdated plugin: Yoast SEO 28.5 (latest 28.6)" and "... 28.6 (latest 28.7)" are the same finding)."""
    return re.sub(r"\d+(?:\.\d+)*", "#", " ".join((title or "").split()).lower())


def load_ignored(config):
    """{site slug: {key: {"title", "check", "severity"}}}"""
    try:
        data = json.loads(_path(config).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out = {}
    for slug, entries in (data.items() if isinstance(data, dict) else []):
        if isinstance(entries, list):  # older format: ["<check>|<title>", ...]
            entries = {ignore_key(e.split("|", 1)[-1]): {"title": e.split("|", 1)[-1], "check": e.split("|", 1)[0]}
                       for e in entries if isinstance(e, str)}
        if isinstance(entries, dict) and entries:
            out[slug] = entries
    return out


def save_ignored(config, data):
    path = _path(config)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def apply_ignored(report, keys):
    """A copy of `report` without the ignored findings, with counts, status and risk score recalculated."""
    if not report or not keys:
        return report
    findings = [f for f in report.get("findings", []) if ignore_key(f.get("title")) not in keys]
    if len(findings) == len(report.get("findings", [])):
        return report
    severities = [S.parse(f["severity"]) for f in findings]
    worst = max(severities, default=S.INFO)
    return {
        **report,
        "findings": findings,
        "ignored_count": len(report.get("findings", [])) - len(findings),
        "severity_counts": {s.name: severities.count(s) for s in sorted(S, reverse=True)},
        "worst_severity": worst.name,
        "security_status": STATUS[worst],
        "risk_score": max(0, 100 - sum(RISK_WEIGHTS[s] for s in severities)),
        "recommendations": [r for r in report.get("recommendations", []) if ignore_key(r.get("title")) not in keys],
    }
