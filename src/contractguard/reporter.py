"""Report generation for HTML and SARIF outputs."""

from __future__ import annotations

import datetime
from typing import Any

from jinja2 import BaseLoader, Environment

from contractguard.engine import Finding, Severity
from contractguard.scorer import compute_score

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ContractGuard Security Report</title>
<style>
  :root {
    --bg: #0b1020; --surface: #131a2c; --surface2: #1a243b; --border: #2d3a5d;
    --text: #edf2ff; --muted: #9aa7c2; --red: #eb5757; --yellow: #f2c94c;
    --blue: #5b8def; --green: #27ae60; --orange: #f2994a;
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; background: var(--bg); color: var(--text); font-family: "Segoe UI", Arial, sans-serif; }
  .container { max-width: 1120px; margin: 0 auto; }
  h1 { margin: 0 0 6px; font-size: 32px; }
  .tagline, .meta, footer { color: var(--muted); }
  .meta { margin-bottom: 24px; }
  .hero { display: grid; grid-template-columns: 120px 1fr; gap: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 24px; }
  .grade { width: 96px; height: 96px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 40px; font-weight: 800; border: 3px solid; }
  .grade-A, .grade-B { color: var(--green); border-color: var(--green); }
  .grade-C { color: var(--yellow); border-color: var(--yellow); }
  .grade-D { color: var(--orange); border-color: var(--orange); }
  .grade-F { color: var(--red); border-color: var(--red); }
  .stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
  .card { min-width: 120px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card .num { font-size: 30px; font-weight: 700; }
  .label { color: var(--muted); font-size: 12px; text-transform: uppercase; }
  .attack { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 24px; }
  .attack h3 { margin-top: 0; }
  .tag { display: inline-block; margin: 4px 8px 0 0; padding: 4px 10px; border-radius: 999px; background: rgba(242,153,74,.12); color: var(--orange); border: 1px solid rgba(242,153,74,.3); font-size: 12px; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { background: var(--surface2); color: var(--muted); font-size: 12px; text-transform: uppercase; }
  tr:last-child td { border-bottom: none; }
  .sev { display: inline-block; border-radius: 4px; padding: 2px 8px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
  .sev.block { background: rgba(235,87,87,.16); color: var(--red); }
  .sev.critical { background: rgba(235,87,87,.12); color: #ff8484; }
  .sev.warning { background: rgba(242,201,76,.14); color: var(--yellow); }
  .sev.info { background: rgba(91,141,239,.14); color: var(--blue); }
  .context { display: inline-block; background: #0a0f1d; border-radius: 4px; padding: 4px 6px; font-family: Consolas, monospace; font-size: 12px; }
  .empty { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 40px; text-align: center; color: var(--green); }
  footer { margin-top: 24px; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
  <h1>ContractGuard Security Report</h1>
  <p class="tagline">Security analysis for source code, configs, queries, and build assets.</p>
  <p class="meta">Analyzer: <strong>{{ analyzer_type }}</strong> | Source: <strong>{{ source_path }}</strong> | Generated: {{ timestamp }}</p>

  <div class="hero">
    <div class="grade grade-{{ grade }}">{{ grade }}</div>
    <div>
      <h2>Security Score: {{ score_value }}/100</h2>
      <p>{{ risk_summary }}</p>
    </div>
  </div>

  <div class="stats">
    <div class="card"><div class="num">{{ total }}</div><div class="label">Total</div></div>
    <div class="card"><div class="num">{{ block }}</div><div class="label">Block</div></div>
    <div class="card"><div class="num">{{ critical }}</div><div class="label">Critical</div></div>
    <div class="card"><div class="num">{{ warning }}</div><div class="label">Warning</div></div>
    <div class="card"><div class="num">{{ info }}</div><div class="label">Info</div></div>
  </div>

  {% if attack_surface %}
  <div class="attack">
    <h3>Attack Surface</h3>
    {% for entry in attack_surface %}<span class="tag">{{ entry }}</span>{% endfor %}
    {% if top_risks %}
    <ul>
      {% for risk in top_risks %}<li>{{ risk }}</li>{% endfor %}
    </ul>
    {% endif %}
  </div>
  {% endif %}

  {% if findings %}
  <table>
    <thead>
      <tr><th>ID</th><th>Severity</th><th>CWE</th><th>Description</th><th>Location</th><th>Context</th><th>Suggestion</th></tr>
    </thead>
    <tbody>
    {% for finding in findings %}
      <tr>
        <td><strong>{{ finding.rule_id }}</strong></td>
        <td><span class="sev {{ finding.severity.value }}">{{ finding.severity.value }}</span></td>
        <td>{{ finding.cwe }}</td>
        <td>{{ finding.description }}</td>
        <td>{{ finding.location }}</td>
        <td><span class="context" title="{{ finding.context | e }}">{{ finding.context | truncate(60) }}</span></td>
        <td>{{ finding.suggestion }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">All clear: no issues found.</div>
  {% endif %}

  <footer>ContractGuard report</footer>
</div>
</body>
</html>"""


def render_html_report(
    findings: list[Finding],
    analyzer_type: str = "",
    source_path: str = "",
) -> str:
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(_HTML_TEMPLATE)

    score_obj = compute_score(findings)
    return template.render(
        findings=findings,
        analyzer_type=analyzer_type,
        source_path=source_path,
        timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        total=len(findings),
        block=sum(1 for item in findings if item.severity == Severity.BLOCK),
        critical=sum(1 for item in findings if item.severity == Severity.CRITICAL),
        warning=sum(1 for item in findings if item.severity == Severity.WARNING),
        info=sum(1 for item in findings if item.severity == Severity.INFO),
        grade=score_obj.grade,
        score_value=score_obj.score,
        risk_summary=score_obj.risk_summary,
        attack_surface=score_obj.attack_surface,
        top_risks=score_obj.top_risks,
    )


def render_sarif_report(
    findings: list[Finding],
    analyzer_type: str = "",
) -> dict[str, Any]:
    severity_map = {
        Severity.INFO: "note",
        Severity.WARNING: "warning",
        Severity.CRITICAL: "error",
        Severity.BLOCK: "error",
    }

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()

    for finding in findings:
        if finding.rule_id not in seen_rule_ids:
            seen_rule_ids.add(finding.rule_id)
            rule_def: dict[str, Any] = {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.description},
                "defaultConfiguration": {"level": severity_map.get(finding.severity, "warning")},
            }
            if finding.cwe:
                rule_def["helpUri"] = f"https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html"
            if finding.attack_vector:
                rule_def["fullDescription"] = {"text": f"Attack vector: {finding.attack_vector}"}
            rules.append(rule_def)

        file_path = finding.location.split(":")[0] if finding.location else ""
        line = 1
        if ":" in finding.location:
            parts = finding.location.rsplit(":", 1)
            try:
                line = int(parts[1])
            except ValueError:
                line = 1

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": severity_map.get(finding.severity, "warning"),
            "message": {"text": f"{finding.description} - {finding.suggestion}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path.replace("\\", "/")},
                        "region": {"startLine": line},
                    }
                }
            ],
        }
        if finding.cwe:
            result["taxa"] = [{"id": finding.cwe, "toolComponent": {"name": "CWE"}}]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ContractGuard",
                        "version": "3.0.0",
                        "informationUri": "https://github.com/contractguard/contractguard",
                        "rules": rules,
                    }
                },
                "invocations": [{"commandLine": analyzer_type or "all"}],
                "results": results,
            }
        ],
    }
