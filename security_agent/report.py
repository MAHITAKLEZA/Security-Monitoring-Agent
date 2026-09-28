"""Report generation: JSON + Markdown files and a console summary (no dashboard, no alerts)."""

import json
from collections import Counter
from pathlib import Path

from .excel import to_xlsx
from .models import Severity as S

RISK_WEIGHTS = {S.CRITICAL: 25, S.HIGH: 10, S.MEDIUM: 4, S.LOW: 1, S.INFO: 0}
STATUS = {S.CRITICAL: "CRITICAL", S.HIGH: "AT RISK", S.MEDIUM: "NEEDS ATTENTION", S.LOW: "GOOD", S.INFO: "SECURE"}


def build_report(target, findings, started, finished, check_durations):
    findings = sorted(findings, key=lambda f: (-f.severity, f.check, f.title))
    worst = max((f.severity for f in findings), default=S.INFO)
    counts = Counter(f.severity.name for f in findings)
    score = max(0, 100 - sum(RISK_WEIGHTS[f.severity] for f in findings))
    recommendations, seen = [], set()
    for f in findings:
        if f.severity >= S.LOW and f.recommendation and f.recommendation not in seen:
            seen.add(f.recommendation)
            recommendations.append({"severity": f.severity.name, "title": f.title, "recommendation": f.recommendation})
    per_check = {}
    for f in findings:
        entry = per_check.setdefault(f.check, {"findings": 0, "worst": "INFO"})
        entry["findings"] += 1
        if f.severity > S[entry["worst"]]:
            entry["worst"] = f.severity.name
    for name, seconds in check_durations.items():
        per_check.setdefault(name, {"findings": 0, "worst": "INFO"})["duration_s"] = round(seconds, 2)
    return {
        "target": target,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "security_status": STATUS[worst],
        "worst_severity": worst.name,
        "risk_score": score,
        "severity_counts": {s.name: counts.get(s.name, 0) for s in sorted(S, reverse=True)},
        "checks": per_check,
        "recommendations": recommendations,
        "findings": [f.to_dict() for f in findings],
    }


def to_markdown(report):
    lines = [
        f"# Security Report - {report['target']}",
        "",
        f"- **Scan time:** {report['started_at']} -> {report['finished_at']}",
        f"- **Security status:** {report['security_status']}",
        f"- **Risk score:** {report['risk_score']}/100",
        "",
        "## Risk Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        *[f"| {sev} | {n} |" for sev, n in report["severity_counts"].items()],
        "",
        "| Check | Findings | Worst |",
        "|---|---|---|",
        *[f"| {name} | {c['findings']} | {c['worst']} |" for name, c in report["checks"].items()],
        "",
    ]
    if report["recommendations"]:
        lines += ["## Recommendations", ""]
        lines += [f"{i}. **[{r['severity']}] {r['title']}** - {r['recommendation']}"
                  for i, r in enumerate(report["recommendations"], 1)]
        lines.append("")
    lines += ["## Detailed Findings", ""]
    for f in report["findings"]:
        lines.append(f"### [{f['severity']}] {f['title']}  `{f['check']}`")
        if f["detail"]:
            lines.append(f"\n{f['detail']}")
        if f["recommendation"]:
            lines.append(f"\n**Recommendation:** {f['recommendation']}")
        if f["evidence"]:
            lines.append("\n<details><summary>Evidence</summary>\n\n```json\n"
                         + json.dumps(f["evidence"], indent=2, default=str)[:4000] + "\n```\n</details>")
        lines.append("")
    return "\n".join(lines)


def write_reports(report, output_dir, stamp):
    out = Path(output_dir)
    run_dir = out / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    as_json = json.dumps(report, indent=2, default=str)
    as_md = to_markdown(report)
    as_xlsx = to_xlsx(report)
    paths = []
    for directory in (run_dir, out):
        name = "report" if directory == run_dir else "latest"
        (directory / f"{name}.json").write_text(as_json, encoding="utf-8")
        (directory / f"{name}.md").write_text(as_md, encoding="utf-8")
        (directory / f"{name}.xlsx").write_bytes(as_xlsx)
        paths += [directory / f"{name}.json", directory / f"{name}.md", directory / f"{name}.xlsx"]
    with open(out / "history.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({k: report[k] for k in ("started_at", "security_status", "risk_score", "severity_counts")}) + "\n")
    return paths


def write_summary(reports, output_dir):
    """Combined overview of all monitored sites: reports/summary.md + summary.json."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    reports = sorted(reports, key=lambda r: (-S[r["worst_severity"]], r["risk_score"]))
    rows = [{
        "site": r["site"], "url": r["target"], "security_status": r["security_status"], "risk_score": r["risk_score"],
        "severity_counts": r["severity_counts"], "scanned_at": r["started_at"],
        "top_issues": [f"[{f['severity']}] {f['title']}" for f in r["findings"] if S[f["severity"]] >= S.HIGH][:10],
        "report": r["report_files"][1] if r.get("report_files") else None,
    } for r in reports]
    (out / "summary.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")

    lines = ["# Security Monitoring Summary", "",
             "| Site | Status | Risk score | Critical | High | Medium | Low |", "|---|---|---|---|---|---|---|"]
    for row in rows:
        c = row["severity_counts"]
        lines.append(f"| [{row['site']}]({row['url']}) | {row['security_status']} | {row['risk_score']}/100 | "
                     f"{c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} |")
    for row in rows:
        if row["top_issues"]:
            lines += ["", f"## {row['site']}", "", *[f"- {issue}" for issue in row["top_issues"]]]
    path = out / "summary.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def console_summary(report, min_severity=S.LOW):
    lines = [
        "",
        f"Security status : {report['security_status']}   (risk score {report['risk_score']}/100)",
        "Findings        : " + ", ".join(f"{k} {v}" for k, v in report["severity_counts"].items()),
        "",
    ]
    for f in report["findings"]:
        if S[f["severity"]] >= min_severity:
            lines.append(f"  [{f['severity']:<8}] {f['check']:<15} {f['title']}")
    return "\n".join(lines)
