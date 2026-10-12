#  endpoint_audit

**One command. Full security snapshot of a Windows endpoint, with a risk score.**
It collects processes, services, startup entries, local admins, network connections, and installed software, runs a risk analysis over everything, and hands you a clean HTML or JSON report with the top threats called out.

---

## Why this exists

When you're triaging a suspicious machine, or just auditing a fleet, you don't want to run ten different commands and eyeball the output. `endpoint_audit` gathers the evidence that matters in a single pass, flags what looks wrong (tools like `mimikatz.exe`, binaries running out of `\Temp\`, nonexistent or unsigned paths), and gives you an overall risk level you can act on.

## Features

- **Seven collectors** in one run: system metadata, processes, services, startup registry keys, local administrators, network connections, installed software
- **Risk analysis** with an overall risk level and score, plus a ranked list of top threats
- **Suspicious-path detection**: flags anything running from `\Temp\`, `\AppData\`, `\Public\`, `\Downloads\`, or `\ProgramData\Temp\`
- **Known-bad tool detection**: flags processes named after common attacker tools (`mimikatz.exe`, `psexec.exe`, `procdump.exe`, `cobaltstrike.exe`, and more)
- **Configurable risk scoring** for suspicious paths, suspicious names, unsigned binaries, and nonexistent paths
- **Reports in HTML, JSON, or both**
- **Dry-run mode**: collect, analyze, and print a summary with no files written
- **`--no-network` flag** to skip connection collection for a faster run
- **Config-driven**: every watch list, score, and path lives in `config.json`

## What it collects

| Collector | What you get |
|---|---|
| System metadata | Hostname, OS, and basic host details |
| Processes | Running processes, checked against suspicious paths and names |
| Services | Services, checked against suspicious paths |
| Startup keys | Registry `Run` / `RunOnce` entries (HKLM + HKCU) |
| Local administrators | Members of the local admin group |
| Network connections | Active connections (skippable with `--no-network`) |
| Installed software | Installed programs |

## How it works

```
 collect_system_metadata ─┐
 collect_processes ───────┤
 collect_services ────────┤
 collect_startup_keys ────┼──▶  data  ──▶  analyze()  ──▶  findings
 collect_local_admins ────┤                                 · risk level
 collect_network_connections ┤                              · overall score
 collect_installed_software ─┘                              · top threats
                                                              │
                                        ┌─────────────────────┴───────────┐
                                        ▼                                 ▼
                                   HTML report                       JSON report
                                (data/reports/)                   (data/reports/)
```

1. **Collect** from every source, with suspicious paths and names from the config applied to processes and services.
2. **Analyze** the combined data into a risk level, an overall score, and a list of top threats.
3. **Report** to HTML, JSON, or both. In dry-run mode, print the summary instead.

## Project structure

```
endpoint_audit/
├── main.py            # CLI entry point and audit pipeline
├── config.json        # Watch lists, risk scores, paths
├── modules/
│   ├── logger.py      # Logging setup
│   ├── collector.py   # All seven data collectors
│   ├── analyzer.py    # Risk analysis and top-threat ranking
│   └── reporter.py    # HTML and JSON report writers
├── data/reports/      # Generated reports
└── logs/              # Runtime logs (audit.log)
```

## Requirements

- **Windows**
- **Python 3.7+**
- An **elevated (Administrator) terminal** for the most complete results
- Windows Python bindings used by the collectors. Check the imports in `modules/collector.py` and install what they need.

## Getting started

```bash
git clone https://github.com/kevn-xo/endpoint_audit.git
cd endpoint_audit
python -m pip install -r requirements.txt
```

Run a full audit and get an HTML report:

```bash
python main.py
```

Try it without writing any files first:

```bash
python main.py --dry-run
```

## Usage

```bash
python main.py                       # Full audit, HTML output
python main.py --output json         # JSON output
python main.py --output both         # HTML + JSON
python main.py --dry-run             # Collect and print, no files written
python main.py --no-network          # Skip network collection (faster)
python main.py --config custom.json  # Use a different config file
```

### CLI options

| Flag | Description |
|---|---|
| `--output {html,json,both}` | Report format (default: `html`) |
| `--dry-run` | Collect and analyze only. Prints a JSON summary, writes no files |
| `--no-network` | Skip network connection collection |
| `--config PATH` | Path to an alternate config file (default: `config.json`) |

## Configuration

Everything lives in `config.json`.

| Key | Description |
|---|---|
| `report_dir` | Where reports are written (default `data/reports`) |
| `baseline_dir` | Baseline directory (default `data/baseline`) |
| `log_dir` / `log_file` | Log location (default `logs/audit.log`) |
| `suspicious_process_paths` | Path fragments that flag a process or service as suspicious |
| `suspicious_process_names` | Process names that flag a process as a known attacker tool |
| `critical_services` | Services treated as critical |
| `startup_reg_keys` | Registry keys to scan for startup entries, each as `{hive, path}` |
| `risk_path_score` | Score for a suspicious path (default `5`) |
| `risk_name_score` | Score for a suspicious name (default `8`) |
| `risk_unsigned_score` | Score for an unsigned binary (default `4`) |
| `risk_nonexistent_score` | Score for a path that doesn't exist (default `6`) |

### Default watch lists

**Suspicious paths:** `\Temp\`, `\AppData\`, `\Public\`, `\Downloads\`, `\ProgramData\Temp\`

**Suspicious process names:** `mimikatz.exe`, `nc.exe`, `ncat.exe`, `psexec.exe`, `wce.exe`, `pwdump.exe`, `procdump.exe`, `cobaltstrike.exe`

**Critical services:** `WinDefend`, `EventLog`, `wuauserv`, `MpsSvc`, `Spooler`, `LanmanServer`

**Startup keys:** `Run` and `RunOnce` under both `HKLM` and `HKCU`

Add your own tools, paths, and services to any list.

### Default risk scores

| Finding | Score |
|---|---|
| Suspicious process name | 8 |
| Nonexistent path | 6 |
| Suspicious path | 5 |
| Unsigned binary | 4 |

## Sample dry-run output

```
=== DRY RUN SUMMARY ===
{
  "metadata": {
    "hostname": "WORKSTATION-01",
    "os_name": "...",
    ...
  },
  "findings": {
    "risk_level": "...",
    "overall_risk": ...,
    "top_threats": [ ... ]
  }
}
```

## Use cases

- **Incident triage**: grab a fast, structured picture of a suspect machine
- **Security audits**: spot unmanaged admins, odd startup entries, and risky software
- **Hardening checks**: confirm critical services are present and nothing runs from user-writable folders
- **Evidence capture**: save a point-in-time JSON snapshot for later comparison

## Known limitations

- Windows only.
- Detection is rule-based (paths, names, signatures), so it flags what looks suspicious. It is not a replacement for EDR.
- Results are a point-in-time snapshot of the host.

