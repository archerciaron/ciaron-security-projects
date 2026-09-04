#!/usr/bin/env python3
"""
Subdomain Enumerator
====================
A threaded DNS subdomain enumeration tool. Discovers valid subdomains of a
target domain by resolving candidates from a wordlist and reporting those
that resolve to an IP address.

Built to demonstrate understanding of the DNS protocol, reconnaissance
methodology, and efficient concurrent I/O.

Author: Ciaron Archer
Purpose: Educational / authorised security assessment use only.

DISCLAIMER: Only enumerate domains you own or are authorised to assess.
Reconnaissance against third parties without permission may be unlawful.
"""

import argparse
import socket
import threading
from queue import Queue
from datetime import datetime

print_lock = threading.Lock()
found = []
found_lock = threading.Lock()

# A small built-in wordlist so the tool works out of the box. For real use,
# supply a larger list (e.g. SecLists) via the -w flag.
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "dns",
    "admin", "portal", "vpn", "remote", "api", "dev", "staging", "test",
    "app", "web", "secure", "shop", "blog", "mobile", "m", "beta",
    "cpanel", "webdisk", "autodiscover", "gateway", "cloud", "git",
    "jenkins", "jira", "confluence", "gitlab", "docker", "kibana",
    "grafana", "prometheus", "internal", "intranet", "corp", "office",
]


def resolve_subdomain(domain, sub):
    """
    Attempt to resolve a candidate subdomain to an IP.

    A successful gethostbyname() means the DNS A record exists, confirming
    the subdomain is live. Failure raises gaierror, which we treat as
    'does not exist' — the expected outcome for most candidates.
    """
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        with found_lock:
            found.append((fqdn, ip))
        with print_lock:
            print(f"[+] {fqdn:<40} -> {ip}")
    except socket.gaierror:
        pass  # Subdomain does not resolve — expected for most candidates
    except socket.error:
        pass


def worker(domain, queue):
    """Worker thread: resolve candidates until the queue is empty."""
    while not queue.empty():
        sub = queue.get()
        resolve_subdomain(domain, sub)
        queue.task_done()


def load_wordlist(path):
    """Load subdomain candidates from a file, one per line."""
    try:
        with open(path, "r", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {path} — using built-in list")
        return DEFAULT_WORDLIST


def run(domain, wordlist, thread_count):
    print(f"\n{'='*60}")
    print(f"  Subdomain Enumerator — {domain}")
    print(f"  Candidates: {len(wordlist)}  |  Threads: {thread_count}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    queue = Queue()
    for sub in wordlist:
        queue.put(sub)

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(domain, queue))
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()

    print(f"\n{'='*60}")
    print(f"  Enumeration complete — {len(found)} subdomain(s) found")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="Threaded DNS subdomain enumerator.")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50,
                        help="Number of worker threads (default: 50)")
    args = parser.parse_args()

    wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_WORDLIST
    run(args.domain, wordlist, args.threads)


if __name__ == "__main__":
    main()
