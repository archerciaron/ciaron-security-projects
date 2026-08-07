# ciaron-security-projects
Security tools built from scratch in Python &amp; Bash — offensive and defensive tooling covering network scanning, web vulnerability detection, log analysis, and privilege escalation enumeration.

# Security Tools Portfolio

A collection of security tools I built from scratch in Python and Bash to deepen my hands-on offensive and defensive security skills. Each tool implements a technique from first principles rather than wrapping an existing framework, so I understand not just *what* it does but *why* it works.

## About me

I'm a cyber security professional with 3+ years of experience in a regulated financial services environment, currently focused on offensive security. I'm working through the HackTheBox CPTS certification and hold CompTIA Network+ and Security+. I built these tools to turn the theory I use day to day into working code — and because I genuinely enjoy understanding systems below the abstraction layer.

## The tools

### [Network Scanner & Service Enumerator](./network-scanner)
A multi-threaded TCP port scanner with banner grabbing, built on raw sockets. Demonstrates the TCP handshake, socket programming, and safe concurrency with a thread pool and queue.
