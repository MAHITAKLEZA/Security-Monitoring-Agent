"""Runs detection for one site, builds the Phase 2 proposals and writes the reports."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from . import remediate, wordpress
from .detect import OutsideScan
from .files import FileScan
from .site import Finding, rank

try:
    from .ai import AITriage
except ImportError:  # the anthropic SDK isn't installed: heuristics only
    AITriage = None

log = logging.getLogger("jp_seo_agent")
SOURCE_LABEL = {"outside": "Crawl (outside view)", "wordpress": "WordPress content", "files": "Files"}


class _NoAI:
    enabled, model, reviewed = False, "", 0

    def __init__(self, note):
        self.note = note

    def classify(self, items):
        return {}

    def review_files(self, hits):
        return {}


class SiteGuardAgent:
    def __init__(self, site, cfg, use_ai=False, model=None, out_dir="reports/site_guard"):
        self.site, self.cfg = site, cfg
        if AITriage is None:
            self.ai = _NoAI("AI triage unavailable: install the anthropic package. Heuristics only.")
        elif not use_ai:
            self.ai = _NoAI("Rule-based detection (AI triage off).")
        else:
            try:
                self.ai = AITriage(site.url, **({"model": model} if model else {}))
            except Exception as exc:  # e.g. the SDK can't build a client
                self.ai = _NoAI(f"AI triage unavailable: {exc}. Heuristics only.")
        self.out_dir = Path(out_dir) / site.host
        self.stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # ---- Phase 1: detect (read-only) ------------------------------------------------
    def scan(self):
        outside = OutsideScan(self.site, self.cfg).run()
        findings = list(outside.findings)
        spam_urls = dict(outside.spam_urls)

        # AI triage of ambiguous pages (Japanese text without enough spam vocabulary)
        verdicts = self.ai.classify([{"id": c["url"], "title": c["title"], "text": c["text"],
                                      "context": f"public page ({c['how']})"} for c in outside.candidates])
        for c in outside.candidates:
            v = verdicts.get(c["url"])
            if v and v.classification != "legitimate":
                spam_urls[c["url"]] = f"AI: {v.classification}"
                findings.append(Finding("outside", f"AI confirmed spam at {c['url']}",
                                        "CRITICAL" if v.confidence != "low" else "HIGH", v.reason,
                                        "Treat as injected SEO spam.", {"url": c["url"], "ai": v.model_dump()}))
            elif not v:
                findings.append(Finding("outside", f"Unexpected Japanese text at {c['url']}", "MEDIUM",
                                        f"Found via {c['how']}; not confirmed as spam.",
                                        "If the site has Japanese content on purpose, set site_language: ja or "
                                        "allowed_japanese_paths for that section.", {"url": c["url"]}))

        wp_findings, items, wp_urls = wordpress.scan(self.site, self.cfg, outside.expect_ja, self.ai)
        findings += wp_findings
        for url, how in wp_urls.items():
            spam_urls.setdefault(url, how)

        files = None
        if self.site.wp_auth and self.site.secure and self.cfg.get("file_scan", True) and wordpress.login(self.site):
            files = FileScan(self.site, self.cfg, self.ai).run(outside.expect_ja)
            findings += files.findings

        stats = {**outside.stats, "wordpress_items_flagged": len(items),
                 **({f"files_{k}": v for k, v in files.stats.items()} if files else {})}
        if not any(rank(f.severity) > 0 for f in findings):
            findings.append(Finding("outside", "No signs of compromise found", "INFO",
                                    f"Crawled {outside.stats['pages']} page(s) as a visitor and as Googlebot, checked "
                                    f"{outside.stats['sitemap_urls']} sitemap URL(s) and made-up URL probes"
                                    + ("; inspected WordPress content" if self.site.wp_auth else "")
                                    + (f"; scanned {files.stats.get('files', 0)} file(s)" if files and files.stats else "")
                                    + ".", "Cloaking that verifies Google's IP addresses can't be seen from outside; "
                                    "also check Search Console (URL Inspection, Security issues)."))
        findings.sort(key=lambda f: -rank(f.severity))
        note = self.ai.note or (f"AI triage by {self.ai.model}: {self.ai.reviewed} item(s) reviewed."
                                if self.ai.reviewed else "AI triage: no suspicious items needed review.")
        return {"site": self.site.url, "scanned_at": self.stamp, "expect_japanese": outside.expect_ja,
                "stats": stats, "ai": note, "worst": findings[0].severity, "findings": findings,
                "spam_urls": spam_urls, "suspicious_urls": outside.suspicious_urls, "items": items,
                "file_hits": files.hits if files else [], "inventory": files.inventory if files else [],
                "file_scan": files}

    # ---- Phase 2: proposals for the approval queue (nothing is changed here) ------------
    def propose(self, result):
        if not self.site.wp_auth or not wordpress.login(self.site):
            return []
        return remediate.build_proposals(self.site, result, self.cfg)

    # ---- reports ------------------------------------------------------------------
    def write_reports(self, result, kind="scan"):
        self.out_dir.mkdir(parents=True, exist_ok=True)
        base = self.out_dir / f"{kind}-{self.stamp}"
        data = {**{k: v for k, v in result.items() if k != "file_scan"},
                "findings": [f.to_dict() for f in result["findings"]],
                "items": [{k: v for k, v in i.items() if k != "raw"} for i in result["items"]]}
        base.with_suffix(".json").write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        md = base.with_suffix(".md")
        md.write_text(self._markdown(result, kind), encoding="utf-8")
        paths = [base.with_suffix(".json"), md]
        urls = sorted(set(result["spam_urls"]) | set(result.get("suspicious_urls") or {}))
        if urls:
            path = self.out_dir / f"spam-urls-{self.stamp}.txt"
            path.write_text("\n".join(urls) + "\n", encoding="utf-8")
            paths.append(path)
        return paths

    def _markdown(self, r, kind):
        counts = {}
        for f in r["findings"]:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        lines = [f"# Website compromise scan: {r['site']}", "",
                 f"- Scanned: {r['scanned_at']} UTC", f"- Worst severity: **{r['worst']}** ("
                 + ", ".join(f"{n} {s}" for s, n in counts.items()) + ")",
                 f"- Pages crawled: {r['stats'].get('pages', 0)}; sitemap URLs: {r['stats'].get('sitemap_urls', 0)}",
                 f"- Spam URLs confirmed: {len(r['spam_urls'])}; suspicious URLs: {len(r.get('suspicious_urls') or {})}",
                 f"- Files scanned: {r['stats'].get('files_files', 'not scanned (needs the Site Guard plugin)')}",
                 f"- {r['ai']}", "", "Scanning never changes the site; fixes only happen after approval.", ""]
        for source, label in SOURCE_LABEL.items():
            group = [f for f in r["findings"] if f.phase == source]
            if not group:
                continue
            lines += [f"## {label}", ""]
            for f in group:
                lines += [f"### [{f.severity}] {f.title}", "", f.detail, ""]
                if f.recommendation:
                    lines += [f"**Fix:** {f.recommendation}", ""]
        if r.get("proposals") is not None:
            lines += ["## Proposed fixes (waiting for approval)", ""]
            if not r["proposals"]:
                lines += ["Nothing can be fixed automatically" + ("." if self.site.wp_auth else
                                                                  " (no WordPress credentials given)."), ""]
            else:
                lines += ["| Id | Action | Target | Risk | Why |", "|---|---|---|---|---|"]
                for p in r["proposals"]:
                    lines.append(f"| {p['id']} | {p['action']} | {p['target'][:60]} | {p['risk']} | "
                                 f"{p['why'].replace('|', '/')} |")
                lines += ["", "Approve in the dashboard or with `python -m jp_seo_agent approve <url> <id>`.", ""]
            lines += ["## Manual steps", ""]
            lines += [f"{n}. {step}" for n, step in enumerate(remediate.MANUAL_STEPS, 1)] + [""]
        return "\n".join(lines)


JapaneseSeoAgent = SiteGuardAgent  # earlier name, still used by older callers
