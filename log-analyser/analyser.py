#!/usr/bin/env python3
"""
Log Analyser & Anomaly Detector
===============================
Parses web server access logs and flags security-relevant anomalies:
brute-force attempts, scanning behaviour, common attack signatures, and
suspicious request volumes from individual IPs.

Built to demonstrate security operations thinking — turning raw log data
into actionable detection signals, the defensive counterpart to the
offensive tooling in this portfolio.

Author: Ciaron Archer
Purpose: Educational / authorised use only.
"""

import argparse
import re
from collections import defaultdict, Counter
from datetime import datetime

# Regex for the Combined Log Format used by Apache and Nginx.
# Capturing the IP, timestamp, request line, status code, and user agent
# gives us everything needed for behavioural analysis.
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]*"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"[^"]*"\s+"(?P<agent>[^"]*)")?'
)

# Attack signatures to look for in request paths. These map to the same
# vulnerability classes the offensive tools in this portfolio test for —
# seeing both sides reinforces how detection and exploitation relate.
ATTACK_SIGNATURES = {
    "SQL Injection": ["union select", "or '1'='1", "order by", "'--", "1=1", "' or "],
    "XSS": ["<script", "onerror=", "javascript:", "alert("],
    "Path Traversal": ["../", "..\\", "/etc/passwd", "win.ini"],
    "Command Injection": [";cat ", "|whoami", "&&", "`id`", "$(", ";ls"],
    "Scanner/Tool": ["sqlmap", "nikto", "nmap", "masscan", "acunetix", "dirbuster"],
}

# Thresholds for volumetric detections. In production these would be tuned
# against a baseline; sensible defaults are used here.
BRUTE_FORCE_THRESHOLD = 10   # failed auth (401/403) from one IP
SCAN_THRESHOLD = 20          # 404s from one IP suggests directory scanning
REQUEST_VOLUME_THRESHOLD = 100  # total requests from one IP


def parse_log(path):
    """Parse a log file into a list of structured request records."""
    records = []
    unparsed = 0
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                match = LOG_PATTERN.search(line)
                if match:
                    records.append(match.groupdict())
                elif line.strip():
                    unparsed += 1
    except FileNotFoundError:
        print(f"[!] Log file not found: {path}")
        return None
    if unparsed:
        print(f"[i] {unparsed} line(s) did not match the expected format and were skipped")
    return records


def detect_attack_signatures(records):
    """Scan request paths for known attack signatures."""
    findings = defaultdict(list)
    for r in records:
        path_lower = r["path"].lower()
        for attack, signatures in ATTACK_SIGNATURES.items():
            if any(sig in path_lower for sig in signatures):
                findings[attack].append((r["ip"], r["path"][:80]))
    return findings


def detect_brute_force(records):
    """Flag IPs with many authentication failures (401/403)."""
    failures = defaultdict(int)
    for r in records:
        if r["status"] in ("401", "403"):
            failures[r["ip"]] += 1
    return {ip: n for ip, n in failures.items() if n >= BRUTE_FORCE_THRESHOLD}


def detect_scanning(records):
    """Flag IPs generating many 404s — typical of directory brute forcing."""
    not_found = defaultdict(int)
    for r in records:
        if r["status"] == "404":
            not_found[r["ip"]] += 1
    return {ip: n for ip, n in not_found.items() if n >= SCAN_THRESHOLD}


def detect_high_volume(records):
    """Flag IPs making an unusually high number of total requests."""
    volume = Counter(r["ip"] for r in records)
    return {ip: n for ip, n in volume.items() if n >= REQUEST_VOLUME_THRESHOLD}


def report(records):
    """Run all detections and print a structured report."""
    print(f"\n{'='*64}")
    print(f"  Log Analyser & Anomaly Detector")
    print(f"  Records analysed: {len(records)}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*64}\n")

    signatures = detect_attack_signatures(records)
    if signatures:
        print("[!] ATTACK SIGNATURES DETECTED\n")
        for attack, hits in signatures.items():
            print(f"    {attack}: {len(hits)} request(s)")
            for ip, path in hits[:3]:
                print(f"       {ip}  ->  {path}")
            if len(hits) > 3:
                print(f"       ... and {len(hits) - 3} more")
            print()

    brute = detect_brute_force(records)
    if brute:
        print("[!] POSSIBLE BRUTE FORCE (repeated 401/403)\n")
        for ip, n in sorted(brute.items(), key=lambda x: -x[1]):
            print(f"       {ip}  ->  {n} auth failures")
        print()

    scanning = detect_scanning(records)
    if scanning:
        print("[!] POSSIBLE DIRECTORY SCANNING (repeated 404)\n")
        for ip, n in sorted(scanning.items(), key=lambda x: -x[1]):
            print(f"       {ip}  ->  {n} not-found responses")
        print()

    volume = detect_high_volume(records)
    if volume:
        print("[!] HIGH REQUEST VOLUME\n")
        for ip, n in sorted(volume.items(), key=lambda x: -x[1]):
            print(f"       {ip}  ->  {n} total requests")
        print()

    if not any((signatures, brute, scanning, volume)):
        print("  No anomalies detected above configured thresholds.\n")

    print(f"{'='*64}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyse web server access logs for security anomalies."
    )
    parser.add_argument("logfile", help="Path to an Apache/Nginx access log")
    args = parser.parse_args()

    records = parse_log(args.logfile)
    if records:
        report(records)


if __name__ == "__main__":
    main()
