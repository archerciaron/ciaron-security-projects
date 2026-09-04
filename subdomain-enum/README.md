# Subdomain Enumerator

A threaded DNS subdomain enumeration tool that discovers live subdomains of a target domain by resolving candidates from a wordlist.

## What it does

- Takes a target domain and a wordlist of candidate subdomains
- Resolves each candidate concurrently using DNS lookups
- Reports every subdomain that resolves to a valid IP address
- Ships with a built-in wordlist and supports custom wordlists

## Why I built it

Subdomain enumeration is one of the first steps in the reconnaissance phase of any engagement — it expands the attack surface by revealing hosts that are not obvious from the main domain. I built this to understand the DNS resolution process and to see how reconnaissance tooling balances speed with accuracy through concurrency.

## Usage

```bash
# Use the built-in wordlist
python3 subdomain_enum.py example.com

# Use a custom wordlist (e.g. from SecLists)
python3 subdomain_enum.py example.com -w subdomains-top1million.txt

# Increase thread count for a large wordlist
python3 subdomain_enum.py example.com -w big-list.txt -t 100
```

## Key concepts demonstrated

- **DNS resolution** — using A-record lookups to confirm live hosts
- **Reconnaissance methodology** — understanding where subdomain discovery fits in the kill chain
- **Concurrency** — a thread pool over a shared queue for efficient network I/O
- **Graceful failure handling** — distinguishing non-existent subdomains from genuine errors

## Where this fits in an engagement

Subdomain enumeration sits in the reconnaissance phase. Discovered subdomains often reveal forgotten dev/staging environments, admin portals, or legacy applications that are more vulnerable than production. A natural extension would be to add certificate transparency log searches and passive sources (e.g. crt.sh) to complement active brute forcing.

## Disclaimer

For educational purposes and authorised assessments only. Only enumerate domains you own or have explicit permission to test.
