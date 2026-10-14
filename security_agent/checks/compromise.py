"""Website compromise detection (Phase 1), proposed fixes (Phase 2) and autonomous defense (Phase 3), run by the
jp_seo_agent engine.

Crawl: SEO spam of any family (Japanese keyword hack, pharma, gambling, adult, scam), cloaking for Googlebot, hidden
spam links, malicious redirects (HTTP, meta refresh, JavaScript, search-visitor and mobile only), spam sitemaps and
URLs, spam page generators. WordPress (application password): spam items and injected code in content, the accounts
behind them. Files (Kleza Site Guard plugin): core/plugin integrity, PHP in uploads, backdoor and cloaking code.
Optional Claude triage of ambiguous hits (checks.compromise.ai: true); off by default.
Scanning never changes the site: what was found becomes proposed fixes in the site's approval queue, applied only
when someone approves them in the dashboard. The one exception is Phase 3 automatic recovery, off unless switched on:
a reinfection of a fix a person already approved is fixed again, within limits (jp_seo_agent/defense.py)."""

from pathlib import Path

from jp_seo_agent.agent import SiteGuardAgent
from jp_seo_agent.approvals import Queue, queue_path
from jp_seo_agent.defense import DefenseState, after_scan, state_path
from jp_seo_agent.site import Site

from ..models import Finding, Severity as S

NAME = "compromise"
SOURCE = {"outside": "", "wordpress": "WordPress: ", "files": "Files: "}
# Reinfections (also when waiting for approval or coming back again) are reported as the infections themselves
DEFENSE_TITLE = {"recovered": "Reinfection recovered automatically", "recovery_failed": "Automatic recovery failed"}


def _defense_findings(events, host, cfg):
    """Findings for what Phase 3 did during this scan, plus what the integrity monitor still reports."""
    out = []
    for kind, title in DEFENSE_TITLE.items():
        group = [e for e in events if e["type"] == kind]
        if group:
            out.append(Finding(NAME, f"{title} ({len(group)})" if len(group) > 1 else title,
                               S.parse(max((e["severity"] for e in group), key=lambda s: S.parse(s))),
                               " ".join(f"{e['title']}: {e['detail']}" for e in group[:5])[:1500],
                               "See Autonomous defense on this check's page: the investigation lists how the attacker "
                               "probably got in and what keeps reinstalling the infection.",
                               {"events": [{k: e.get(k) for k in ("time", "title", "proposal")} for e in group[:20]]}))
    report = next((e for e in reversed(events) if e["type"] == "investigation"), None)
    if report:
        out.append(Finding(NAME, "Root-cause investigation", S.INFO, report["detail"],
                           "Read the full investigation under Autonomous defense.",
                           {"investigation": report.get("investigation")}))
    drift = [p for p, d in DefenseState(state_path(cfg, host)).data.get("drift", {}).items() if not d.get("flagged")]
    if drift:
        out.append(Finding(NAME, f"Integrity monitor: {len(drift)} unexplained file change(s)", S.LOW,
                           "Changed since the trusted baseline, not part of an official update, no malware signature: "
                           + ", ".join(sorted(drift)[:8]) + (f" and {len(drift) - 8} more." if len(drift) > 8 else "."),
                           "If your team made these changes, use Trust current files under Autonomous defense.",
                           {"files": sorted(drift)[:200]}))
    return out


def run(ctx, cfg, state):
    site = Site(ctx.url, timeout=ctx.timeout, pages=ctx.pages, wp_auth=getattr(ctx, "wp_auth", None))
    agent = SiteGuardAgent(site, cfg, use_ai=cfg.get("ai", False), model=cfg.get("model") or None)
    result = agent.scan()
    queue = Queue(queue_path(cfg.get("queue_dir"), site.host), site.url)
    proposals = agent.propose(result)
    merged = queue.merge(proposals)
    findings = [Finding(NAME, SOURCE.get(f.phase, "") + f.title, S.parse(f.severity), f.detail, f.recommendation,
                        f.evidence) for f in result["findings"]]
    urls = sorted(set(result["spam_urls"]) | set(result["suspicious_urls"]))
    findings.append(Finding(NAME, "Scan summary", S.INFO,
                            f"{result['stats'].get('pages', 0)} page(s) crawled, {len(result['spam_urls'])} spam URL(s) "
                            f"confirmed, {len(result['suspicious_urls'])} suspicious. {result['ai']}",
                            "Spam URLs must return 404/410 after cleanup; then ask Google to drop them with Search "
                            "Console > Removals." if urls else "", {"stats": result["stats"], "urls": urls[:100]}))
    # Phase 3: reinfections of applied fixes, controlled automatic recovery, root-cause investigation
    try:
        events = after_scan(site, cfg, queue, merged, result, proposals,
                            Path(cfg.get("backup_dir") or "backups") / site.host)
    except Exception as exc:  # the scan's own findings still count when this part fails
        events = []
        findings.append(Finding(NAME, "Autonomous defense step could not complete", S.INFO,
                                f"{exc.__class__.__name__}: {exc}"[:300]))
    findings += _defense_findings(events, site.host, cfg)
    pending = [p for p in queue.listing() if p["status"] == "pending" and p["action"] != "manual"]
    if pending:
        findings.append(Finding(NAME, f"{len(pending)} fix(es) waiting for approval", S.MEDIUM,
                                ", ".join(f"{p['action']}: {p['target'][:50]}" for p in pending[:5])
                                + (f" and {len(pending) - 5} more" if len(pending) > 5 else "") + ".",
                                "Review them under Remediation on this check's page. Each fix is backed up, "
                                "verified after it is applied, and can be undone.",
                                {"pending": len(pending), "new": merged["new"], "resolved": merged["resolved"]}))
    # What was found and the file inventory (checksums) at this scan
    state[NAME] = {"spam_urls": urls[:2000],
                   "inventory": {f["p"]: [f.get("h"), f.get("s"), f.get("m")] for f in result["inventory"]}}
    return findings
