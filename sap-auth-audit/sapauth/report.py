# SAP Concept: Consultant audit deliverables (HTML dashboard, CSV/JSON working papers, ASCII console summary).
"""Generates report.html, findings.csv, findings.json, and ASCII terminal summary."""

import csv
from datetime import date
import html
import json
from pathlib import Path
from typing import Dict, List

from sapauth.checks import Finding, SEVERITY_WEIGHTS, compute_user_scores
from sapauth.loader import Dataset

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    """Counts findings per severity level."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def write_csv_and_json(findings: List[Finding], out_dir: Path) -> None:
    """Writes findings.csv and findings.json into out_dir."""
    sorted_findings = sorted(
        findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.user, f.rule_id)
    )
    csv_path = out_dir / "findings.csv"
    fieldnames = [
        "user", "category", "rule_id", "severity",
        "title", "detail", "sap_ref", "remediation",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted_findings:
            writer.writerow(item.to_dict())

    json_path = out_dir / "findings.json"
    json_path.write_text(
        json.dumps([item.to_dict() for item in sorted_findings], indent=2),
        encoding="utf-8",
    )


def render_html_report(dataset: Dataset, findings: List[Finding], today: date) -> str:
    """Renders a self-contained HTML security audit report with inline CSS/JS and escaped values."""
    counts = severity_counts(findings)
    top_users = compute_user_scores(findings)[:10]
    sorted_findings = sorted(
        findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.user, f.rule_id)
    )
    sid = html.escape(str(dataset.meta.get("sid", "S4P")))
    client = html.escape(str(dataset.meta.get("client", "100")))
    env = html.escape(str(dataset.meta.get("env", "PROD")))
    date_str = html.escape(today.isoformat())

    user_rows = []
    for rank, u in enumerate(top_users, start=1):
        user_rows.append(
            f"<tr><td>{rank}</td><td><strong>{html.escape(str(u['user']))}</strong></td>"
            f"<td><strong>{int(u['score'])}</strong></td>"
            f"<td>{int(u['critical'])}</td><td>{int(u['high'])}</td>"
            f"<td>{int(u['medium'])}</td><td>{int(u['low'])}</td></tr>"
        )

    finding_rows = []
    for f in sorted_findings:
        sev = html.escape(f.severity)
        finding_rows.append(
            f"<tr data-severity=\"{sev}\">"
            f"<td><span class=\"badge {sev}\">{sev.upper()}</span></td>"
            f"<td><strong>{html.escape(f.user)}</strong></td>"
            f"<td>{html.escape(f.category)}</td>"
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td><strong>{html.escape(f.title)}</strong><div class=\"detail\">{html.escape(f.detail)}</div></td>"
            f"<td>{html.escape(f.sap_ref)}</td>"
            f"<td>{html.escape(f.remediation)}</td>"
            f"</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SAP Authorization &amp; Basis Security Audit - {sid} ({client})</title>
<style>
  :root {{
    --bg: #f4f6f9; --card: #ffffff; --text: #1c2530; --muted: #5a6877;
    --crit: #c92a2a; --high: #d9480f; --med: #e67700; --low: #2b8a3e; --border: #dde3ea;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }}
  .container {{ max-width: 1320px; margin: 0 auto; }}
  header {{ background: #0f2942; color: #fff; padding: 20px 24px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }}
  header h1 {{ margin: 0; font-size: 20px; }}
  .meta {{ font-size: 14px; color: #cfd9e3; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }}
  .card {{ background: var(--card); border-radius: 8px; padding: 16px 20px; border-left: 5px solid var(--border); box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
  .card.critical {{ border-left-color: var(--crit); }}
  .card.high {{ border-left-color: var(--high); }}
  .card.medium {{ border-left-color: var(--med); }}
  .card.low {{ border-left-color: var(--low); }}
  .card .label {{ font-size: 12px; text-transform: uppercase; color: var(--muted); font-weight: 600; }}
  .card .val {{ font-size: 28px; font-weight: 700; margin-top: 4px; }}
  section {{ background: var(--card); border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
  h2 {{ margin: 0 0 14px 0; font-size: 16px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  th {{ background: #f8fafc; font-weight: 600; color: var(--muted); }}
  .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; color: #fff; }}
  .badge.critical {{ background: var(--crit); }}
  .badge.high {{ background: var(--high); }}
  .badge.medium {{ background: var(--med); }}
  .badge.low {{ background: var(--low); }}
  .detail {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .controls {{ display: flex; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }}
  .controls select, .controls input {{ padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; }}
  .controls input {{ flex: 1; min-width: 220px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>SAP Authorization &amp; Basis Security Audit Report</h1>
      <div class="meta">Offline SUIM / PFCG / SoD / RZ11 Assessment</div>
    </div>
    <div class="meta">SID: <strong>{sid}</strong> | Client: <strong>{client}</strong> | Env: <strong>{env}</strong> | Audit Date: <strong>{date_str}</strong></div>
  </header>

  <div class="cards">
    <div class="card critical"><div class="label">Critical</div><div class="val" id="count-critical">{counts['critical']}</div></div>
    <div class="card high"><div class="label">High</div><div class="val" id="count-high">{counts['high']}</div></div>
    <div class="card medium"><div class="label">Medium</div><div class="val" id="count-medium">{counts['medium']}</div></div>
    <div class="card low"><div class="label">Low</div><div class="val" id="count-low">{counts['low']}</div></div>
    <div class="card"><div class="label">Total Findings</div><div class="val" id="count-total">{len(findings)}</div></div>
  </div>

  <section>
    <h2>Top-10 Risky Users (Weights: Critical={SEVERITY_WEIGHTS['critical']}, High={SEVERITY_WEIGHTS['high']}, Medium={SEVERITY_WEIGHTS['medium']}, Low={SEVERITY_WEIGHTS['low']})</h2>
    <table>
      <thead><tr><th>#</th><th>User</th><th>Risk Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>
      <tbody>{"".join(user_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>Audit Findings ({len(findings)})</h2>
    <div class="controls">
      <select id="sevFilter" onchange="filterFindings()">
        <option value="all">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <input type="text" id="searchBox" oninput="filterFindings()" placeholder="Filter by user, rule ID, t-code, role, or keyword...">
    </div>
    <table id="findingsTable">
      <thead><tr><th>Severity</th><th>User</th><th>Category</th><th>Rule</th><th>Finding</th><th>SAP Reference</th><th>Remediation</th></tr></thead>
      <tbody>{"".join(finding_rows)}</tbody>
    </table>
  </section>
</div>
<script>
function filterFindings() {{
  var sev = document.getElementById('sevFilter').value;
  var q = document.getElementById('searchBox').value.toLowerCase();
  var rows = document.querySelectorAll('#findingsTable tbody tr');
  for (var i = 0; i < rows.length; i++) {{
    var r = rows[i];
    var matchSev = (sev === 'all') || (r.getAttribute('data-severity') === sev);
    var matchText = !q || (r.textContent.toLowerCase().indexOf(q) !== -1);
    r.style.display = (matchSev && matchText) ? '' : 'none';
  }}
}}
</script>
</body>
</html>
"""


def format_console_summary(dataset: Dataset, findings: List[Finding], today: date) -> str:
    """Formats an ASCII-only summary table for terminal output."""
    counts = severity_counts(findings)
    top5 = compute_user_scores(findings)[:5]
    sid = dataset.meta.get("sid", "S4P")
    client = dataset.meta.get("client", "100")
    env = dataset.meta.get("env", "PROD")

    lines = [
        "================================================================",
        f" SAP AUTHORIZATION & BASIS SECURITY AUDIT  [{sid} / {client} / {env}]",
        f" Audit Reference Date: {today.isoformat()} | Users Audited: {len(dataset.users)}",
        "================================================================",
        " FINDINGS BY SEVERITY",
        f"   CRITICAL : {counts['critical']:3d}",
        f"   HIGH     : {counts['high']:3d}",
        f"   MEDIUM   : {counts['medium']:3d}",
        f"   LOW      : {counts['low']:3d}",
        f"   TOTAL    : {len(findings):3d}",
        "----------------------------------------------------------------",
        " TOP 5 RISKY USERS (SCORE = 10*CRIT + 5*HIGH + 2*MED + 1*LOW)",
        "   RANK  USER          SCORE   CRIT   HIGH    MED    LOW",
    ]
    for idx, u in enumerate(top5, start=1):
        lines.append(
            f"   {idx:4d}  {u['user']:<12s}  {u['score']:5d}   {u['critical']:4d}   "
            f"{u['high']:4d}   {u['medium']:4d}   {u['low']:4d}"
        )
    lines.append("================================================================")
    return "\n".join(lines)


def generate_reports(dataset: Dataset, findings: List[Finding], out_dir: Path, today: date) -> str:
    """Writes report.html, findings.csv, findings.json to out_dir and returns ASCII summary."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    write_csv_and_json(findings, out_path)
    html_content = render_html_report(dataset, findings, today)
    (out_path / "report.html").write_text(html_content, encoding="utf-8")
    return format_console_summary(dataset, findings, today)