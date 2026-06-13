#!/usr/bin/env python3
"""
CyberSec Toolkit — Subdomain Enumerator
========================================
Discovers subdomains via async DNS resolution (brute-force wordlist approach).
Works without external deps — uses only stdlib asyncio + socket.

Usage:
    python3 subdomain_enum.py example.com                          # built-in wordlist
    python3 subdomain_enum.py example.com --wordlist subdomains.txt
    python3 subdomain_enum.py example.com --wordlist big.txt --threads 100 --output found.txt

Educational use only. Only run against domains you own or have written permission to test.
"""

import asyncio
import argparse
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# =============================================================================
# Built-in wordlist  (used when no --wordlist is provided)
# =============================================================================
_BUILTIN: List[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "admin", "panel",
    "cpanel", "portal", "vpn", "remote", "rdp", "citrix", "ns1", "ns2", "ns3",
    "mx1", "mx2", "mx", "api", "api-v1", "api-v2", "rest", "graphql",
    "app", "apps", "mobile", "ios", "android", "dev", "develop", "development",
    "staging", "stage", "stg", "uat", "qa", "test", "testing", "sandbox",
    "demo", "preview", "beta", "alpha", "prod", "production", "live",
    "git", "gitlab", "github", "bitbucket", "svn", "repo",
    "jenkins", "ci", "cd", "build", "drone", "travis",
    "jira", "confluence", "wiki", "docs", "documentation", "support",
    "helpdesk", "ticket", "crm", "erp", "sap", "salesforce",
    "cdn", "static", "assets", "media", "img", "images", "files", "upload",
    "download", "storage", "s3", "blob", "backup", "archive",
    "blog", "news", "forum", "community", "social",
    "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    "dashboard", "control", "manage", "management", "monitor", "status",
    "health", "metrics", "stats", "analytics", "tracking",
    "login", "auth", "sso", "oauth", "ldap", "iam",
    "mail2", "email", "calendar", "webdav",
    "db", "database", "mysql", "postgres", "mssql", "oracle", "mongo",
    "redis", "elastic", "kibana", "grafana", "prometheus", "splunk",
    "intranet", "internal", "corp", "office", "extranet",
    "vpn2", "gateway", "proxy", "fw", "firewall", "lb", "loadbalancer",
    "k8s", "kubernetes", "docker", "registry", "harbor",
    "chat", "slack", "teams", "zoom", "meet",
    "old", "legacy", "v1", "v2", "new",
]


# =============================================================================
# Colour helpers
# =============================================================================
def _c(t: str, code: str) -> str:
    return f"\033[{code}m{t}\033[0m"


GREEN  = lambda t: _c(t, "92")
YELLOW = lambda t: _c(t, "93")
CYAN   = lambda t: _c(t, "96")
RED    = lambda t: _c(t, "91")
DIM    = lambda t: _c(t, "2")
BOLD   = lambda t: _c(t, "1")


# =============================================================================
# DNS resolution (runs in thread pool to not block event loop)
# =============================================================================
async def _resolve(
    semaphore: asyncio.Semaphore,
    hostname: str,
) -> Tuple[str, List[str]]:
    """Attempt DNS A-record lookup. Returns (hostname, [ips]) or (hostname, [])."""
    async with semaphore:
        loop = asyncio.get_event_loop()
        try:
            info = await loop.run_in_executor(None, socket.gethostbyname_ex, hostname)
            ips: List[str] = info[2]
            return hostname, ips
        except (socket.gaierror, socket.herror, OSError):
            return hostname, []


async def enumerate(
    domain: str,
    wordlist: List[str],
    max_concurrent: int = 50,
) -> List[Tuple[str, List[str]]]:
    """Run all DNS lookups concurrently. Returns sorted list of (host, ips)."""
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_resolve(semaphore, f"{word}.{domain}") for word in wordlist]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    found = []
    for r in results:
        if isinstance(r, tuple):
            host, ips = r
            if ips:
                found.append((host, ips))
    return sorted(found)


# =============================================================================
# Helpers
# =============================================================================
def load_wordlist(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        print(RED(f"[!] Wordlist not found: {path}"))
        sys.exit(1)
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return words


def verify_domain(domain: str) -> None:
    """Basic sanity check on domain string."""
    import re
    if not re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", domain):
        print(RED(f"[!] '{domain}' doesn't look like a valid domain."))
        sys.exit(1)


def print_banner():
    print(CYAN("""
  ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗
  ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║
  ███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║
  ╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║
  ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝
  Enumerator — CyberSec Toolkit v1.0"""))


# =============================================================================
# Entry point
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Subdomain enumerator via DNS brute-force — educational use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 subdomain_enum.py example.com
  python3 subdomain_enum.py example.com --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  python3 subdomain_enum.py example.com --threads 100 --output subs.txt
        """
    )
    parser.add_argument("domain",    help="Target domain (e.g. example.com)")
    parser.add_argument("--wordlist",metavar="FILE", help="Subdomain wordlist (default: built-in ~100 entries)")
    parser.add_argument("--threads", type=int, default=50, metavar="N",
                        help="Concurrent DNS lookups (default: 50)")
    parser.add_argument("--output",  metavar="FILE", help="Save discovered subdomains to file")
    args = parser.parse_args()

    print_banner()

    domain = args.domain.lower().strip().rstrip(".")
    verify_domain(domain)

    wordlist: List[str]
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        wl_label = f"{args.wordlist} ({len(wordlist):,} entries)"
    else:
        wordlist = _BUILTIN
        wl_label = f"built-in ({len(wordlist)} entries)"

    print(f"\n  {BOLD('Target  :')} {domain}")
    print(f"  {BOLD('Wordlist:')} {wl_label}")
    print(f"  {BOLD('Threads :')} {args.threads}")
    print(f"  {BOLD('Started :')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    start = time.perf_counter()
    found = asyncio.run(enumerate(domain, wordlist, args.threads))
    elapsed = time.perf_counter() - start

    if not found:
        print(YELLOW("  [-] No subdomains discovered."))
    else:
        print(f"  {'SUBDOMAIN':<45} {'IP(S)'}")
        print("  " + "─" * 70)
        for host, ips in found:
            ip_str = ", ".join(ips)
            print(f"  {GREEN(host):<53} {ip_str}")

    print(f"\n  {BOLD('Done in')} {elapsed:.2f}s  —  {GREEN(str(len(found)))} subdomain(s) found.\n")

    if args.output and found:
        with open(args.output, "w") as f:
            for host, ips in found:
                f.write(f"{host}\t{' '.join(ips)}\n")
        print(f"  [+] Results saved → {args.output}")


if __name__ == "__main__":
    main()
