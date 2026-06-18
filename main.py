# -*- coding: utf-8 -*-
"""
main.py - Endpoint Audit Tool
Usage:
  python main.py                        # Full audit, HTML output
  python main.py --output json          # JSON output only
  python main.py --output both          # HTML + JSON
  python main.py --dry-run              # Collect + print, no files written
  python main.py --no-network           # Skip network (faster)
  python main.py --config custom.json   # Use custom config
"""

import argparse, json, os, sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from modules.logger    import get_logger
from modules.collector import (
    collect_system_metadata, collect_processes, collect_services,
    collect_startup_keys,   collect_local_admins,
    collect_network_connections, collect_installed_software,
)
from modules.analyzer  import analyze
from modules.reporter  import save_html, save_json


def load_config(config_path: str) -> dict:
    with open(config_path, encoding="utf-8") as f:
        return json.load(f)


def run_audit(args, cfg, log):
    log.info("=" * 60)
    log.info("ENDPOINT AUDIT STARTED")
    log.info(f"Dry-run mode : {args.dry_run}")
    log.info(f"Output format: {args.output}")
    log.info("=" * 60)

    data = {}

    log.info("Collecting system metadata...")
    data["metadata"] = collect_system_metadata()
    log.info(f"  Host: {data['metadata']['hostname']} | OS: {data['metadata']['os_name']}")

    log.info("Collecting processes...")
    data["processes"] = collect_processes(
        cfg["suspicious_process_paths"],
        cfg["suspicious_process_names"]
    )
    log.info(f"  {len(data['processes'])} processes found.")

    log.info("Collecting services...")
    data["services"] = collect_services(cfg["suspicious_process_paths"])
    log.info(f"  {len(data['services'])} services found.")

    log.info("Collecting startup registry keys...")
    data["startup_keys"] = collect_startup_keys(cfg["startup_reg_keys"])
    log.info(f"  {len(data['startup_keys'])} startup entries found.")

    log.info("Collecting local administrators...")
    data["admins"] = collect_local_admins()
    log.info(f"  {len(data['admins'])} admin accounts found.")

    if not args.no_network:
        log.info("Collecting network connections...")
        data["network"] = collect_network_connections()
        log.info(f"  {len(data['network'])} connections found.")
    else:
        data["network"] = []
        log.info("Network collection skipped (--no-network).")

    log.info("Collecting installed software...")
    data["software"] = collect_installed_software()
    log.info(f"  {len(data['software'])} programs found.")

    log.info("Running risk analysis...")
    findings = analyze(data)
    log.info(f"  Risk level : {findings['risk_level']} (score={findings['overall_risk']})")
    log.info(f"  Top threats: {len(findings['top_threats'])}")

    if args.dry_run:
        log.info("DRY-RUN: No files written.")
        print("\n=== DRY RUN SUMMARY ===")
        print(json.dumps({
            "metadata": data["metadata"],
            "findings": findings,
        }, indent=2, default=str))
        return

    report_dir = os.path.join(BASE_DIR, cfg["report_dir"])

    if args.output in ("html", "both"):
        html_path = save_html(data, findings, report_dir)
        log.info(f"HTML report saved: {html_path}")
        print(f"\n[OK] HTML Report: {html_path}")

    if args.output in ("json", "both"):
        json_path = save_json(data, findings, report_dir)
        log.info(f"JSON report saved: {json_path}")
        print(f"[OK] JSON Report: {json_path}")

    log.info("AUDIT COMPLETE.")


def main():
    parser = argparse.ArgumentParser(
        description="Endpoint Audit Tool - collect, analyze, report."
    )
    parser.add_argument(
        "--output", choices=["html", "json", "both"], default="html",
        help="Output format (default: html)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Collect and analyze only - write no files."
    )
    parser.add_argument(
        "--no-network", action="store_true",
        help="Skip network connection collection (faster)."
    )
    parser.add_argument(
        "--config", default=os.path.join(BASE_DIR, "config.json"),
        help="Path to config JSON file."
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    log = get_logger("audit", os.path.join(BASE_DIR, cfg["log_file"]))

    run_audit(args, cfg, log)


if __name__ == "__main__":
    main()
