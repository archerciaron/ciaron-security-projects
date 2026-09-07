# Security Tools Portfolio

A collection of security tools I built from scratch in Python and Bash to deepen my hands-on offensive and defensive security skills. Each tool implements a technique from first principles rather than wrapping an existing framework, so I understand not just *what* it does but *why* it works.

## About me

I'm a cyber security professional with 3+ years of experience in a regulated financial services environment, currently focused on offensive security. I'm working through the HackTheBox CPTS certification and hold CompTIA Network+ and Security+. I built these tools to turn the theory I use day to day into working code — and because I genuinely enjoy understanding systems below the abstraction layer.

## The tools

### [Network Scanner & Service Enumerator](./network-scannerr)
A multi-threaded TCP port scanner with banner grabbing, built on raw sockets. Demonstrates the TCP handshake, socket programming, and safe concurrency with a thread pool and queue.

### [Web Vulnerability Scanner](./web-vuln-scanner)
Tests web parameters for reflected XSS, error-based SQL injection, and path traversal. Demonstrates adversarial thinking in code and the professional discipline of flagging findings for manual verification.

### [Log Analyser & Anomaly Detector](./log-analyser)
The defensive counterpart to the offensive tools — parses web server logs and detects attack signatures, brute force, scanning, and volume anomalies. Demonstrates detection-engineering thinking and the two-sided relationship between attack and defence.

## Themes across the portfolio

- **Built from first principles** — each tool implements its core technique directly rather than calling a ready-made library that does the work
- **Both sides of security** — offensive tooling (scanning, enumeration, cracking) alongside defensive tooling (log analysis, detection)
- **Professional discipline** — automated findings are flagged for manual verification, mirroring how real engagements are run
- **Systems thinking** — sockets, DNS, the TCP handshake, hashing, and Linux internals, all handled explicitly

## Running the tools

All Python tools require Python 3.6+ and use only the standard library except the web scanner, which uses `requests`:

```bash
pip install requests
```

Each tool has its own README with usage examples and an explanation of the concepts it demonstrates.

## Responsible use

Every tool in this repository is for educational purposes and authorised security assessments only. They should only ever be run against systems you own or have explicit written permission to test. Understanding how these techniques work is what makes both better attackers and better defenders.
