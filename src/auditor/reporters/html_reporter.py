from __future__ import annotations
import os
from jinja2 import Template

HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>AWS Resource Auditor Report</title>
  <style>
    body { font-family: system-ui, Arial, sans-serif; margin: 24px; }
    h1 { margin-bottom: 0; }
    .meta { color: #666; margin-top: 4px; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }
    th { background: #f6f6f6; text-align: left; }
    tr:nth-child(even) { background: #fafafa; }
    .sev-HIGH { color: #b30000; font-weight: bold; }
    .sev-MEDIUM { color: #b36b00; font-weight: bold; }
    .sev-LOW { color: #006bb3; font-weight: bold; }
  </style>
</head>
<body>
<h1>AWS Resource Auditor Report</h1>
<div class="meta">Generated at: {{ generated_at }}</div>
<table>
  <thead>
    <tr>
      <th>Account</th><th>Region</th><th>Service</th><th>Resource</th><th>Severity</th><th>Title</th><th>Details</th><th>Remediation</th>
    </tr>
  </thead>
  <tbody>
  {% for f in findings %}
    <tr>
      <td>{{ f.account_id }}</td>
      <td>{{ f.region }}</td>
      <td>{{ f.service }}</td>
      <td>{{ f.resource_id }}</td>
      <td class="sev-{{ f.severity }}">{{ f.severity }}</td>
      <td>{{ f.title }}</td>
      <td>{{ f.details }}</td>
      <td>{{ f.remediation }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
</body>
</html>
"""

def write_html(findings: list[dict], outdir: str, generated_at: str):
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "findings.html")
    tmpl = Template(HTML)
    html = tmpl.render(findings=findings, generated_at=generated_at)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
