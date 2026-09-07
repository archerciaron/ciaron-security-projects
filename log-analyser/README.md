# Log Analyser & Anomaly Detector

A Python tool that parses web server access logs and flags security-relevant anomalies: attack signatures, brute-force attempts, directory scanning, and suspicious request volumes.

## What it does

- Parses Apache/Nginx Combined Log Format using regex
- Detects attack signatures in request paths (SQLi, XSS, traversal, command injection, scanner tools)
- Flags brute-force attempts from repeated authentication failures
- Detects directory scanning from high volumes of 404 responses
- Identifies IPs generating unusually high request volumes

## Why I built it

Most of my portfolio is offensive tooling, and I wanted to build the defensive counterpart to show I understand both sides. Coordinating security testing at work taught me that finding a vulnerability is only half the story — detecting the attack matters just as much. This tool takes the same attack classes my offensive scanners generate and detects them from the defender's side, which reinforced how exploitation and detection relate to each other.

## Usage

```bash
python3 analyser.py /var/log/nginx/access.log
python3 analyser.py sample_access.log
```

## Key concepts demonstrated

- **Log parsing** — regex extraction of structured fields from raw log lines
- **Signature-based detection** — matching request paths against known attack patterns
- **Behavioural detection** — thresholds for brute force, scanning, and volume anomalies
- **Security operations thinking** — turning raw data into actionable detection signals
- **Efficient aggregation** — using `defaultdict` and `Counter` for clean counting

## Detection thresholds

The volumetric thresholds (brute force, scanning, request volume) are configurable constants at the top of the script. In a production SOC these would be tuned against a baseline of normal traffic to balance detection sensitivity against false positives — a trade-off I learned to appreciate reviewing detection gaps at work.

## Why this matters for detection engineering

Building this made the relationship between attack and defence concrete: every offensive technique leaves a signature, and knowing what an attack looks like in code makes you far better at detecting it in logs. That two-sided understanding is exactly what makes a security engineer effective.

## Disclaimer

For educational and authorised use only.
