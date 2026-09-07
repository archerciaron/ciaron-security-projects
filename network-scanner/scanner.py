#!/usr/bin/env python3
"""
Network Scanner & Service Enumerator
=====================================
A multi-threaded TCP port scanner with service and banner identification.

Built to demonstrate low-level networking concepts: raw socket programming,
the TCP three-way handshake, concurrent connection handling, and service
fingerprinting from banner responses.

Author: Ciaron Archer
Purpose: Educational / authorised security assessment use only.

DISCLAIMER: Only scan systems you own or have explicit written permission
to test. Unauthorised port scanning may be illegal in your jurisdiction.
"""

import socket
import argparse
import threading
from queue import Queue
from datetime import datetime

# Thread-safe structures for coordinating worker threads
print_lock = threading.Lock()
results = []
results_lock = threading.Lock()

# Common service mappings for quick identification when no banner is returned.
# In a real engagement this supplements — but never replaces — active
# banner grabbing, since services frequently run on non-standard ports.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def grab_banner(sock):
    """
    Attempt to read a service banner from an open socket.

    Many services (SSH, FTP, SMTP) announce themselves on connection.
    We set a short timeout so a silent service does not stall the scan.
    """
    try:
        sock.settimeout(2)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except (socket.timeout, OSError):
        return ""


def scan_port(target, port):
    """
    Attempt a full TCP connection to a single port.

    A successful connect() completes the three-way handshake, confirming
    the port is open and accepting connections. We then attempt a banner
    grab before closing the socket cleanly.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        # connect_ex returns 0 on success rather than raising — cleaner for scanning
        if sock.connect_ex((target, port)) == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner = grab_banner(sock)
            with results_lock:
                results.append((port, service, banner))
            with print_lock:
                banner_display = f" | {banner[:60]}" if banner else ""
                print(f"[+] {port:>5}/tcp open  {service}{banner_display}")
        sock.close()
    except socket.gaierror:
        with print_lock:
            print(f"[!] Hostname could not be resolved: {target}")
    except socket.error:
        pass  # Host unreachable or connection reset — expected during scanning


def worker(target, port_queue):
    """Worker thread: pull ports off the queue until it is empty."""
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port)
        port_queue.task_done()


def run_scan(target, ports, thread_count):
    """Coordinate a threaded scan across the requested port range."""
    print(f"\n{'='*60}")
    print(f"  Network Scanner — target: {target}")
    print(f"  Ports: {min(ports)}-{max(ports)}  |  Threads: {thread_count}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    port_queue = Queue()
    for port in ports:
        port_queue.put(port)

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(target, port_queue))
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()

    print(f"\n{'='*60}")
    print(f"  Scan complete — {len(results)} open port(s) found")
    print(f"{'='*60}")


def parse_ports(port_string):
    """
    Parse a port specification such as '1-1024' or '22,80,443'
    into a list of integers.
    """
    ports = []
    for part in port_string.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP port scanner with banner grabbing."
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan, e.g. '1-1024' or '22,80,443' (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of worker threads (default: 100)")
    args = parser.parse_args()

    # Resolve hostname to IP up front so we fail fast on a bad target
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {args.target}")
        return

    ports = parse_ports(args.ports)
    run_scan(target_ip, ports, args.threads)


if __name__ == "__main__":
    main()
