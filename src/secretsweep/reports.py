from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .models import Finding, ProjectReport


def severity_badge(severity: str) -> str:
    return {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }.get(severity, severity.upper())


def render_markdown(report: ProjectReport) -> str:
    lines = [
        "# SecretSweep Security Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Project: `{report.root.name}`",
        f"Risk level: **{report.risk_level.upper()}**",
        f"Score: **{report.score}/100**",
        "",
        "## Summary",
        "",
        f"- Findings: {len(report.findings)}",
        f"- Files scanned: {report.stats.files_scanned}",
        f"- Files skipped: {report.stats.files_skipped}",
        f"- Risky files: {report.stats.risky_files}",
        f"- Secret-like values: {report.stats.secrets_found}",
        "",
        "### Findings by Severity",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity, count in report.by_severity().items():
        lines.append(f"| {severity_badge(severity)} | {count} |")

    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings were detected.")
    else:
        for idx, finding in enumerate(report.top_findings(limit=500), start=1):
            lines.extend(_finding_markdown(idx, finding))
    lines.extend([
        "",
        "## Recommended Next Steps",
        "",
        "- Review each finding and confirm whether it is a real secret.",
        "- Rotate any exposed credential that was committed or shared.",
        "- Move real secrets into environment variables or a secret manager.",
        "- Add secret file rules to `.gitignore`.",
        "- Keep only safe example values in `.env.example`.",
        "",
    ])
    return "\n".join(lines).rstrip() + "\n"


def _finding_markdown(index: int, finding: Finding) -> list[str]:
    lines = [
        f"### {index}. {finding.title}",
        "",
        f"- Severity: **{finding.severity.value.upper()}**",
        f"- Rule: `{finding.rule_id}`",
        f"- Location: `{finding.location.display()}`",
        f"- Message: {finding.message}",
    ]
    if finding.masked_value:
        lines.append(f"- Masked value: `{finding.masked_value}`")
    if finding.context:
        lines.extend(["", "```text", finding.context, "```"])
    if finding.suggestion:
        lines.extend(["", f"Suggestion: {finding.suggestion}"])
    lines.append("")
    return lines


def render_json(report: ProjectReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def render_html(report: ProjectReport) -> str:
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.severity.value.upper())}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.location.display())}</td>"
            f"<td>{html.escape(finding.masked_value or '')}</td>"
            f"<td>{html.escape(finding.suggestion or '')}</td>"
            "</tr>"
        )
    body = "\n".join(rows) or "<tr><td colspan='5'>No findings detected.</td></tr>"
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>SecretSweep Security Report</title>
  <style>
    body {{ font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; margin: 0; background: #f7f8fb; color: #172033; }}
    main {{ max-width: 1100px; margin: 40px auto; background: white; border: 1px solid #e5e7eb; border-radius: 16px; padding: 32px; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.06); }}
    h1 {{ margin-top: 0; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 24px 0; }}
    .card {{ background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; }}
    .label {{ color: #64748b; font-size: 13px; }}
    .value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; text-align: left; padding: 12px; vertical-align: top; }}
    th {{ background: #f8fafc; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
<main>
  <h1>SecretSweep Security Report</h1>
  <p>Project: <code>{html.escape(report.root.name)}</code></p>
  <div class=\"summary\">
    <div class=\"card\"><div class=\"label\">Risk Level</div><div class=\"value\">{html.escape(report.risk_level.upper())}</div></div>
    <div class=\"card\"><div class=\"label\">Score</div><div class=\"value\">{report.score}/100</div></div>
    <div class=\"card\"><div class=\"label\">Findings</div><div class=\"value\">{len(report.findings)}</div></div>
    <div class=\"card\"><div class=\"label\">Files Scanned</div><div class=\"value\">{report.stats.files_scanned}</div></div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Masked Value</th><th>Suggestion</th></tr></thead>
    <tbody>
      {body}
    </tbody>
  </table>
</main>
</body>
</html>
"""


def render_report(report: ProjectReport, fmt: str) -> str:
    normalized = fmt.lower()
    if normalized == "markdown":
        return render_markdown(report)
    if normalized == "json":
        return render_json(report)
    if normalized == "html":
        return render_html(report)
    raise ValueError(f"Unsupported report format: {fmt}")
