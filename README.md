# Network Scanner & Service Enumerator

A multi-threaded TCP port scanner with service identification and banner grabbing, written in Python using raw sockets.

## What it does

- Scans a target host across a specified port range using concurrent worker threads
- Confirms open ports by completing the TCP three-way handshake
- Identifies common services by port and attempts active banner grabbing
- Reports results in a clean, readable format

## Why I built it

I wanted to understand port scanning from first principles rather than just running Nmap. Building this taught me how the TCP handshake works at the socket level, how service banners can be used for fingerprinting, and how to coordinate concurrent work safely across threads using a queue and locks.

## Usage

```bash
# Scan the top 1024 ports with default threading
python3 scanner.py 192.168.1.1

# Scan specific ports
python3 scanner.py 192.168.1.1 -p 22,80,443,8080

# Scan a full range with more threads
python3 scanner.py scanme.nmap.org -p 1-65535 -t 200
```

## Key concepts demonstrated

- **Socket programming** — raw TCP connections using Python's `socket` library
- **The TCP handshake** — `connect_ex()` completes SYN → SYN-ACK → ACK to confirm open ports
- **Concurrency** — a thread pool pulling from a shared `Queue`, with locks to protect shared state
- **Banner grabbing** — reading service announcements for fingerprinting
- **Graceful error handling** — distinguishing closed ports, unreachable hosts, and resolution failures

## Design notes

Full TCP connect scanning is used here for reliability and clarity. In a real engagement a SYN (half-open) scan is stealthier because it never completes the handshake — a natural next extension of this tool would be raw packet crafting with `scapy` to implement SYN scanning.

## Disclaimer

This tool is for educational purposes and authorised security assessments only. Only scan systems you own or have explicit written permission to test.

## The tools

### [Network Scanner & Service Enumerator](./network-scannerr)
A multi-threaded TCP port scanner with banner grabbing, built on raw sockets. Demonstrates the TCP handshake, socket programming, and safe concurrency with a thread pool and queue.

### [Subdomain Enumerator](./subdomain-enum)
A threaded DNS enumeration tool for the reconnaissance phase. Demonstrates DNS resolution, attack-surface mapping, and efficient concurrent network I/O.

