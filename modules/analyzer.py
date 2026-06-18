# -*- coding: utf-8 -*-
"""
analyzer.py - Risk scoring and anomaly flagging.
Takes raw collector output and produces a structured findings dict.
"""

def analyze(data: dict) -> dict:
    """
    Input:  raw audit data dict (all collector outputs combined)
    Output: findings dict with risk summary, top threats, section scores
    """
    findings = {
        "overall_risk":    0,
        "risk_level":      "LOW",
        "top_threats":     [],
        "section_scores":  {},
        "summary":         {},
    }

    # -- Processes --
    proc_score = 0
    proc_flags = []
    for p in data.get("processes", []):
        if p["risk_score"] > 0:
            proc_score += p["risk_score"]
            proc_flags.append({
                "type":   "PROCESS",
                "name":   p["name"],
                "pid":    p["pid"],
                "flags":  p["flags"],
                "score":  p["risk_score"],
                "detail": p["exe"],
            })
    findings["section_scores"]["processes"] = proc_score
    findings["summary"]["processes"] = {
        "total":   len(data.get("processes", [])),
        "flagged": len(proc_flags),
    }

    # -- Services --
    svc_score = 0
    svc_flags = []
    for s in data.get("services", []):
        if s["risk_score"] > 0:
            svc_score += s["risk_score"]
            svc_flags.append({
                "type":   "SERVICE",
                "name":   s["name"],
                "state":  s["state"],
                "flags":  s["flags"],
                "score":  s["risk_score"],
                "detail": s["binary_path"],
            })
    findings["section_scores"]["services"] = svc_score
    findings["summary"]["services"] = {
        "total":   len(data.get("services", [])),
        "running": sum(1 for s in data.get("services", []) if s["state"] == "RUNNING"),
        "flagged": len(svc_flags),
    }

    # -- Startup Keys --
    reg_score = 0
    reg_flags = []
    for r in data.get("startup_keys", []):
        if r["risk_score"] > 0:
            reg_score += r["risk_score"]
            reg_flags.append({
                "type":   "STARTUP_KEY",
                "name":   r["value_name"],
                "hive":   r["hive"],
                "flags":  r["flags"],
                "score":  r["risk_score"],
                "detail": r["value_data"],
            })
    findings["section_scores"]["startup_keys"] = reg_score
    findings["summary"]["startup_keys"] = {
        "total":   len(data.get("startup_keys", [])),
        "flagged": len(reg_flags),
    }

    # -- Network --
    net_score = 0
    net_flags = []
    for c in data.get("network", []):
        if "EXTERNAL_CONNECTION" in c.get("flags", []):
            net_score += 3
            net_flags.append({
                "type":   "NETWORK",
                "name":   c["process"],
                "flags":  c["flags"],
                "score":  3,
                "detail": f"{c['local']} -> {c['remote']}",
            })
    findings["section_scores"]["network"] = net_score
    findings["summary"]["network"] = {
        "total":    len(data.get("network", [])),
        "external": len(net_flags),
    }

    # -- Aggregate --
    all_threats = proc_flags + svc_flags + reg_flags + net_flags
    all_threats.sort(key=lambda x: x["score"], reverse=True)
    findings["top_threats"]  = all_threats[:20]
    findings["overall_risk"] = sum(findings["section_scores"].values())
    findings["risk_level"]   = (
        "CRITICAL" if findings["overall_risk"] >= 50 else
        "HIGH"     if findings["overall_risk"] >= 25 else
        "MEDIUM"   if findings["overall_risk"] >= 10 else
        "LOW"
    )

    return findings
