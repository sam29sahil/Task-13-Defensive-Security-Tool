# Defensive Security Tool — Authentication Log Analyzer

A Python utility for offline analysis of authentication logs. It summarizes successful and failed logins, flags repeated failures by source IP and account, and exports a CSV report.

**Assessment:** Task 13 — Build a Small Defensive Security Tool.

## Objectives
- Parse synthetic or authorized authentication CSV logs.
- Count successful and failed events.
- Flag IP addresses and accounts with repeated failures.
- Export findings to CSV and verify behavior with unit tests.

## Structure
```text
README.md
requirements.txt
src/security_analyzer.py
sample_data/auth_logs.csv
tests/test_analyzer.py
reports/.gitkeep
```

## Requirements
Python 3.9+. No third-party dependencies; the project uses the Python standard library.

## Setup and execution
```bash
git clone https://github.com/sam29sahil/Task-13-Defensive-Security-Tool.git
cd Task-13-Defensive-Security-Tool
python -m venv .venv
# Activate the environment, then:
python src/security_analyzer.py --input sample_data/auth_logs.csv --report reports/findings.csv --threshold 3
python -m unittest discover -s tests -v
```

Windows PowerShell activation: `.\.venv\Scripts\Activate.ps1`  
Linux/Kali activation: `source .venv/bin/activate`

## Input schema
CSV headers: `timestamp,username,source_ip,status`. Status must be `success` or `failed`; IP addresses are validated. The included records are synthetic documentation-only addresses.

## Detection logic
At the configured threshold (default 3), the analyzer creates a finding for a source IP or account with at least that many failed events in the file. Severity is a simple prioritization hint, not proof of malicious activity. NAT, mistyped passwords, testing, and duplicate records may cause false positives; distributed attempts may evade per-IP thresholds.

## Test evidence
Run the unit-test command locally and retain the actual output as evidence. The repository documentation does not claim tests have passed until they are executed in an environment.

## Safety and limitations
Offline-only: the tool does not connect to, scan, geolocate, or block IPs. Use only synthetic data or logs you are authorized to analyze. It does not establish attacker identity or intent and does not perform rolling time-window correlation.

## References
- Python `csv`: https://docs.python.org/3/library/csv.html
- Python `argparse`: https://docs.python.org/3/library/argparse.html
- Python `unittest`: https://docs.python.org/3/library/unittest.html
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

## Author
Educational cybersecurity assessment project. Review and run the program yourself, and be prepared to explain its logic, assumptions, false positives, and limitations.
