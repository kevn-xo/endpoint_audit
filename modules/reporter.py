# -*- coding: utf-8 -*-
"""
reporter.py - Generates timestamped HTML and JSON audit reports.
HTML report is fully self-contained - no external dependencies.
"""

import json, os
from datetime import datetime


def save_json(data: dict, findings: dict, report_dir: str) -> str:
    """Save raw data + findings as a JSON file. Returns filepath."""
    os.makedirs(report_dir, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = data.get("metadata", {}).get("hostname", "unknown")
    fname    = f"audit_{hostname}_{ts}.json"
    fpath    = os.path.join(report_dir, fname)
    with open(fpath, "w", encoding="utf-8") as f:
        json.dump({"metadata": data.get("metadata"),
                   "findings": findings,
                   "raw_data": data}, f, indent=2, default=str)
    return fpath


def save_html(data: dict, findings: dict, report_dir: str) -> str:
    """Generate a self-contained HTML audit report. Returns filepath."""
    os.makedirs(report_dir, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = data.get("metadata", {}).get("hostname", "unknown")
    fname    = f"audit_{hostname}_{ts}.html"
    fpath    = os.path.join(report_dir, fname)
    meta     = data.get("metadata", {})
    fi       = findings

    risk_color = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f39c12",
        "LOW":      "#27ae60",
    }.get(fi.get("risk_level", "LOW"), "#27ae60")

    def make_table(headers, rows, flag_col=None):
        html  = '<table><thead><tr>'
        html += "".join(f"<th>{h}</th>" for h in headers)
        html += '</tr></thead><tbody>'
        for row in rows:
            flagged = flag_col and row.get(flag_col)
            cls     = ' class="flagged"' if flagged else ""
            html   += f"<tr{cls}>"
            html   += "".join(
                f"<td>{v}</td>" for k, v in row.items()
                if not k.startswith("_")
            )
            html   += "</tr>"
        html += '</tbody></table>'
        return html

    # Build process rows
    proc_rows = []
    for p in data.get("processes", [])[:100]:
        proc_rows.append({
            "PID":    p["pid"],
            "Name":   p["name"],
            "User":   p["username"],
            "RAM MB": p["ram_mb"],
            "Path":   p["exe"][:60],
            "Flags":  ", ".join(p["flags"]) or "-",
            "Risk":   p["risk_score"],
            "_flag":  bool(p["flags"]),
        })

    # Build service rows
    svc_rows = []
    for s in data.get("services", [])[:100]:
        svc_rows.append({
            "Name":      s["name"],
            "State":     s["state"],
            "StartMode": s["start_mode"],
            "Account":   s["service_acct"],
            "Flags":     ", ".join(s["flags"]) or "-",
            "Risk":      s["risk_score"],
            "_flag":     bool(s["flags"]),
        })

    # Build startup rows
    reg_rows = []
    for r in data.get("startup_keys", []):
        reg_rows.append({
            "Hive":   r["hive"],
            "Name":   r["value_name"],
            "Data":   (r["value_data"] or "")[:60],
            "OnDisk": "Yes" if r["exe_exists"] else "NO",
            "Flags":  ", ".join(r["flags"]) or "-",
            "_flag":  bool(r["flags"]),
        })

    # Build network rows
    net_rows = []
    for c in data.get("network", [])[:100]:
        net_rows.append({
            "Process": c["process"],
            "Type":    c["type"],
            "Local":   c["local"],
            "Remote":  c["remote"],
            "Status":  c["status"],
            "Flags":   ", ".join(c["flags"]) or "-",
            "_flag":   bool(c["flags"]),
        })

    # Admin rows
    admin_items = "".join(
        f'<li>{a.get("domain","?")}\\{a.get("name","?")} <small style="color:#888">{a.get("sid","")}</small></li>'
        for a in data.get("admins", [])
    )

    # Top threats section
    threat_cards = "".join(
        f'''<div class="threat-card">
            <div class="t-name">[{t["type"]}] {t["name"]} - Risk Score: {t["score"]}</div>
            <div class="t-detail">Flags: {", ".join(t["flags"])} | {str(t.get("detail",""))[:80]}</div>
        </div>'''
        for t in fi.get("top_threats", [])[:10]
    ) or "<p>None detected.</p>"

    # Software table
    sw_rows = "".join(
        f'<tr><td>{s["name"][:50]}</td><td>{s["version"]}</td><td>{s["vendor"][:30]}</td><td>{s["install_date"]}</td></tr>'
        for s in data.get("software", [])[:50]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Endpoint Audit - {hostname}</title>
  <style>
    body      {{ font-family: 'Segoe UI', sans-serif; background: #0f0f0f;
                color: #e0e0e0; margin: 0; padding: 20px; }}
    h1        {{ color: #00d4ff; border-bottom: 2px solid #00d4ff;
                padding-bottom: 10px; }}
    h2        {{ color: #00d4ff; margin-top: 30px; }}
    .badge    {{ display: inline-block; padding: 6px 16px; border-radius: 4px;
                font-weight: bold; font-size: 1.1em; color: #fff;
                background: {risk_color}; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(3, 1fr);
                  gap: 12px; margin: 20px 0; }}
    .meta-card {{ background: #1a1a2e; border: 1px solid #333;
                  border-radius: 6px; padding: 12px; }}
    .meta-card .label {{ color: #888; font-size: 0.8em;
                         text-transform: uppercase; }}
    .meta-card .value {{ color: #00d4ff; font-size: 1.1em;
                         font-weight: bold; margin-top: 4px; }}
    table     {{ width: 100%; border-collapse: collapse;
                margin: 10px 0; font-size: 0.85em; }}
    th        {{ background: #1a1a2e; color: #00d4ff; padding: 8px;
                text-align: left; border-bottom: 2px solid #333; }}
    td        {{ padding: 6px 8px; border-bottom: 1px solid #222; }}
    tr:hover td       {{ background: #1a1a2e; }}
    tr.flagged td     {{ background: #2d1515; color: #ff6b6b; }}
    tr.flagged:hover td {{ background: #3d1515; }}
    .threat-card {{ background: #1a1a2e; border-left: 4px solid {risk_color};
                    padding: 10px; margin: 8px 0; border-radius: 4px; }}
    .threat-card .t-name   {{ color: #fff; font-weight: bold; }}
    .threat-card .t-detail {{ color: #aaa; font-size: 0.85em; margin-top: 4px; }}
    .section-score {{ float: right; color: #888; font-size: 0.9em; }}
  </style>
</head>
<body>
<h1>Endpoint Audit Report</h1>
<p>
  Host: <strong>{hostname}</strong> &nbsp;|&nbsp;
  IP: <strong>{meta.get("ip_address","?")}</strong> &nbsp;|&nbsp;
  OS: <strong>{meta.get("os_name","?")}</strong> &nbsp;|&nbsp;
  Audit Time: <strong>{meta.get("audit_time","?")}</strong>
</p>
<p>Overall Risk: <span class="badge">
  {fi.get("risk_level","?")} (score: {fi.get("overall_risk",0)})
</span></p>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Total RAM</div>
    <div class="value">{meta.get("total_ram_gb","?")} GB</div>
  </div>
  <div class="meta-card">
    <div class="label">Free RAM</div>
    <div class="value">{meta.get("free_ram_gb","?")} GB</div>
  </div>
  <div class="meta-card">
    <div class="label">Domain</div>
    <div class="value">{meta.get("domain","?")}</div>
  </div>
  <div class="meta-card">
    <div class="label">Last Boot</div>
    <div class="value">{meta.get("last_boot","?")}</div>
  </div>
  <div class="meta-card">
    <div class="label">Processes</div>
    <div class="value">{fi["summary"].get("processes",{}).get("total","?")}</div>
  </div>
  <div class="meta-card">
    <div class="label">Services Running</div>
    <div class="value">{fi["summary"].get("services",{}).get("running","?")}</div>
  </div>
</div>

<h2>Top Threats</h2>
{threat_cards}

<h2>Processes
  <span class="section-score">
    Score: {fi["section_scores"].get("processes",0)}
  </span>
</h2>
{make_table(["PID","Name","User","RAM MB","Path","Flags","Risk"], proc_rows, "_flag")}

<h2>Services
  <span class="section-score">
    Score: {fi["section_scores"].get("services",0)}
  </span>
</h2>
{make_table(["Name","State","StartMode","Account","Flags","Risk"], svc_rows, "_flag")}

<h2>Startup Registry Keys
  <span class="section-score">
    Score: {fi["section_scores"].get("startup_keys",0)}
  </span>
</h2>
{make_table(["Hive","Name","Data","OnDisk","Flags"], reg_rows, "_flag")}

<h2>Local Administrators</h2>
<ul>{admin_items}</ul>

<h2>Network Connections
  <span class="section-score">
    Score: {fi["section_scores"].get("network",0)}
  </span>
</h2>
{make_table(["Process","Type","Local","Remote","Status","Flags"], net_rows, "_flag")}

<h2>Installed Software ({len(data.get("software",[]))} programs)</h2>
<table>
  <thead>
    <tr><th>Name</th><th>Version</th><th>Vendor</th><th>Install Date</th></tr>
  </thead>
  <tbody>{sw_rows}</tbody>
</table>

</body>
</html>"""

    with open(fpath, "w", encoding="utf-8") as f:
        f.write(html)
    return fpath
