"""Builds redacted JSON and HTML reports from ScanReport."""
from __future__ import annotations
import html
import json
import shutil
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import config
from core.engine import ScanReport
from models.result import Finding
from reporting.risk_assessment import (
    prioritize_findings,
    score_finding,
    summarize_counts,
)
from services.logger import redact


def collect_findings(report: ScanReport) -> list[Finding]:
    items: list[Finding] = []
    for res in report.results:
        items.extend(res.findings)
    return prioritize_findings(items)


def build_json_report(
    report: ScanReport, out_dir: Path | None = None
) -> Path:
    target_dir = Path(out_dir or config.REPORTS_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)
    findings = collect_findings(report)
    payload = {
        "scan_id": report.scan_id,
        "target_url": redact(report.target_url),
        "mode": report.mode.value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(report.total_duration, 3),
        "summary": summarize_counts(findings),
        "total_findings": len(findings),
        "findings": [
            {
                **asdict(f),
                "risk_score": score_finding(f),
                "description": redact(f.description),
                "affected_url": redact(f.affected_url),
            }
            for f in findings
        ],
    }
    path = target_dir / f"{report.scan_id}.json"
    with path.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2, default=str, ensure_ascii=False)
    return path


def build_html_report(
    report: ScanReport, out_dir: Path | None = None
) -> Path:
    target_dir = Path(out_dir or config.REPORTS_DIR)
    target_dir.mkdir(parents=True, exist_ok=True)
    findings = collect_findings(report)
    counts = summarize_counts(findings)

    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(f.severity.value.upper())}</td>"
            f"<td>{score_finding(f)}</td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td>{html.escape(f.module)}</td>"
            f"<td>{html.escape(f.verification_status.value)}</td>"
            f"<td>{html.escape(redact(f.affected_url))}</td>"
            f"<td>{html.escape(redact(f.description))}</td>"
            "</tr>"
        )
    table_body = "\n".join(rows) or (
        "<tr><td colspan='7'>No active findings.</td></tr>"
    )

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebGuard Report - {html.escape(report.scan_id)}</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
h1,h2{{color:#3fb950}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th,td{{border:1px solid #30363d;padding:8px;text-align:left}}
th{{background:#161b22}}
</style>
</head>
<body>
<h1>WebGuard Security Assessment Report</h1>
<p><strong>Scan ID:</strong> {html.escape(report.scan_id)}</p>
<p><strong>Target:</strong> {html.escape(redact(report.target_url))}</p>
<p><strong>Mode:</strong> {html.escape(report.mode.value)}</p>
<h2>Severity Summary</h2>
<p>{html.escape(str(counts))}</p>
<h2>Findings</h2>
<table>
<thead>
<tr>
<th>Severity</th><th>Score</th><th>Title</th>
<th>Module</th><th>Status</th><th>URL</th><th>Description</th>
</tr>
</thead>
<tbody>
{table_body}
</tbody>
</table>
</body>
</html>
"""
    path = target_dir / f"{report.scan_id}.html"
    path.write_text(doc, encoding="utf-8")
    return path


def export_html_to_hack_wed(
    html_report_path: Path, hack_wed_dir: Path | None = None
) -> Path:
    dest_dir = Path(hack_wed_dir or config.HACK_WED_DIR)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / html_report_path.name
    shutil.copy2(html_report_path, dest_file)
    return dest_file
