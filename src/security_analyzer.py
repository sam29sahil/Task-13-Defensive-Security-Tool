#!/usr/bin/env python3
"""Offline authentication-log analyzer for defensive learning."""
from __future__ import annotations
import argparse
import csv
import ipaddress
import sys
from collections import Counter
from pathlib import Path

REQUIRED_COLUMNS = {"timestamp", "username", "source_ip", "status"}
VALID_STATUSES = {"success", "failed"}

def load_events(input_path: Path) -> list[dict]:
    """Load CSV events and reject malformed rows with useful line numbers."""
    events = []
    with input_path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Input CSV is empty or has no header.")
        missing = REQUIRED_COLUMNS.difference(reader.fieldnames)
        if missing:
            raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
        for line_number, row in enumerate(reader, start=2):
            timestamp = (row.get("timestamp") or "").strip()
            username = (row.get("username") or "").strip()
            raw_ip = (row.get("source_ip") or "").strip()
            status = (row.get("status") or "").strip().lower()
            if not all((timestamp, username, raw_ip, status)):
                raise ValueError(f"Line {line_number}: required value is blank.")
            if status not in VALID_STATUSES:
                raise ValueError(f"Line {line_number}: status must be 'success' or 'failed'.")
            try:
                source_ip = str(ipaddress.ip_address(raw_ip))
            except ValueError as exc:
                raise ValueError(f"Line {line_number}: invalid source_ip {raw_ip!r}.") from exc
            events.append({"timestamp": timestamp, "username": username,
                           "source_ip": source_ip, "status": status})
    return events

def analyze_events(events: list[dict], threshold: int = 3) -> tuple[dict, list[dict]]:
    """Return event summary and threshold-based IP/account findings."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    ip_failures, account_failures = Counter(), Counter()
    success_count = failed_count = 0
    rows = list(events)
    for event in rows:
        status = event["status"].strip().lower()
        if status == "success":
            success_count += 1
        elif status == "failed":
            failed_count += 1
            ip_failures[event["source_ip"]] += 1
            account_failures[event["username"]] += 1
        else:
            raise ValueError(f"Unsupported status in event: {status!r}")
    findings = []
    for ip, count in sorted(ip_failures.items()):
        if count >= threshold:
            findings.append({"finding_type":"repeated_failures_from_ip","subject":ip,
                "failed_attempts":count,"threshold":threshold,
                "severity":"high" if count >= threshold * 2 else "medium",
                "description":"Source IP reached the configured failed-login threshold."})
    for username, count in sorted(account_failures.items()):
        if count >= threshold:
            findings.append({"finding_type":"repeated_failures_for_account","subject":username,
                "failed_attempts":count,"threshold":threshold,"severity":"medium",
                "description":"Account reached the configured failed-login threshold."})
    summary = {"total_events":len(rows),"successful_logins":success_count,
        "failed_logins":failed_count,"unique_source_ips":len({e["source_ip"] for e in rows}),
        "unique_usernames":len({e["username"] for e in rows}),
        "threshold":threshold,"finding_count":len(findings)}
    return summary, findings

def write_report(findings: list[dict], output_path: Path) -> None:
    """Write findings to CSV, including headers when there are no findings."""
    columns = ["finding_type","subject","failed_attempts","threshold","severity","description"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(findings)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze an authorized authentication CSV offline.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--report", type=Path, default=Path("reports/findings.csv"))
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args(argv)
    if args.threshold < 1:
        print("Error: --threshold must be at least 1.", file=sys.stderr)
        return 2
    if not args.input.is_file():
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 2
    try:
        events = load_events(args.input)
        summary, findings = analyze_events(events, args.threshold)
        write_report(findings, args.report)
    except (OSError, ValueError, csv.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print("Authentication Log Analysis\n---------------------------")
    for key, value in summary.items():
        print(f"{key.replace('_', ' ').title()}: {value}")
    print(f"Report written to: {args.report}")
    if findings:
        print("\nFindings:")
        for item in findings:
            print(f"- [{item['severity'].upper()}] {item['finding_type']}: "
                  f"{item['subject']} ({item['failed_attempts']} failures)")
    else:
        print("\nNo findings met the configured threshold.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
