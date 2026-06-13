#!/usr/bin/env python3
"""
CyberSec Toolkit — Async TCP Port Scanner
==========================================
Scans a target for open TCP ports using Python's asyncio for
high-speed concurrent connections without threading overhead.

Usage:
    python3 port_scanner.py 192.168.1.1
    python3 port_scanner.py scanme.nmap.org --ports 1-1024
    python3 port_scanner.py 10.0.0.1 --ports 22,80,443,8080 --timeout 2.0
    python3 port_scanner.py 10.0.0.1 --ports 1-65535 --threads 500 --output report.txt

Educational use only. See ETHICAL_USE.txt before use.
"""

import asyncio
import argparse
import socket
import sys
import time
from datetime import datetime
from typing import List, Tuple, Optional

# =============================================================================
# Common port → service name mappings
# =============================================================================
SERVICE_MAP = {
    20: "FTP-Data",   21: "FTP",         22: "SSH",          23: "Telnet",
    25: "SMTP",       53: "DNS",          67: "DHCP",         68: "DHCP",
    69: "TFTP",       79: "Finger",       80: "HTTP",        110: "POP3",
    111: "RPCBind",  119: "NNTP",        123: "NTP",         135: "MSRPC",
    137: "NetBIOS",  139: "NetBIOS-SSN", 143: "IMAP",        161: "SNMP",
    162: "SNMP-Trap",194: "IRC",         389: "LDAP",        443: "HTTPS",
    445: "SMB",      465: "SMTPS",       514: "Syslog",      515: "LPD",
    587: "Submission",631: "IPP",        636: "LDAPS",       873: "Rsync",
    902: "VMware",   993: "IMAPS",       995: "POP3S",      1080: "SOCKS5",
    1194: "OpenVPN", 1433: "MSSQL",     1521: "Oracle",     1723: "PPTP",
    2049: "NFS",     2181: "Zookeeper", 2375: "Docker",     2376: "Docker-TLS",
    3306: "MySQL",   3389: "RDP",       3690: "SVN",        4444: "Metasploit",
    5432: "PostgreSQL",5900: "VNC",     6379: "Redis",      6443: "K8s-API",
    8080: "HTTP-Alt",8443: "HTTPS-Alt", 8888: "Jupyter",    9200: "Elasticsearch",
    27017: "MongoDB",50000: "DB2",
}

# =============================================================================
# Core async scanner
# =============================================================================
async def _probe_port(
    semaphore: asyncio.Semaphore,
    host: str,
    port: int,
    timeout: float
) -> Tuple[int, bool, str]:
    """Attempt TCP handshake. Returns (port, is_open, service_name)."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True, SERVICE_MAP.get(port, "unknown")
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False, ""


async def run_scan(
    host: str,
    ports: List[int],
    max_concurrent: int = 300,
    timeout: float = 1.0
) -> List[Tuple[int, str]]:
    """Scan all ports and return list of (port, service) for open ones."""
    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_probe_port(semaphore, host, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    open_ports = []
    for r in results:
        if isinstance(r, tuple):
            port, is_open, service = r
            if is_open:
                open_ports.append((port, service))
    return sorted(open_ports)


# =============================================================================
# Helpers
# =============================================================================
def resolve(target: str) -> str:
    """Resolve hostname to IP, exit on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"[!] DNS resolution failed for '{target}': {e}")
        sys.exit(1)


def parse_ports(spec: str) -> List[int]:
    """
    Parse port spec into sorted list of ints.
    Supports: '80', '80,443', '1-1024', '22,80,8000-8100'
    """
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        print(f"[!] Invalid port(s): {invalid}")
        sys.exit(1)
    return sorted(ports)


def progress_bar(done: int, total: int, width: int = 30) -> str:
    filled = int(width * done / total) if total else 0
    return f"[{'█' * filled}{'░' * (width - filled)}] {done}/{total}"


# =============================================================================
# Output
# =============================================================================
def print_banner():
    print("\033[92m" + r"""
  ██████╗ ██████╗ ██████╗ ████████╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██████╔╝██║   ██║██████╔╝   ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║
  ██║     ╚██████╔╝██║  ██║   ██║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝
  Scanner — CyberSec Toolkit v1.0
  github.com/nikhiltomar2712/cybersec
""" + "\033[0m")


def format_results(open_ports: List[Tuple[int, str]], elapsed: float, target: str, ip: str) -> str:
    lines = [
        f"\n  {'PORT':<8} {'STATE':<8} {'SERVICE':<20}",
        "  " + "─" * 38,
    ]
    for port, service in open_ports:
        state_col = "\033[92mopen\033[0m"
        lines.append(f"  {port:<8} {state_col:<16} {service:<20}")
    lines += [
        "  " + "─" * 38,
        f"\n  [*] Target    : {target} ({ip})",
        f"  [*] Open ports: {len(open_ports)}",
        f"  [*] Finished  : {elapsed:.2f}s",
    ]
    return "\n".join(lines)


# =============================================================================
# Entry point
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Async TCP Port Scanner — educational use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 port_scanner.py 192.168.1.1
  python3 port_scanner.py scanme.nmap.org --ports 1-1024
  python3 port_scanner.py 10.0.0.5 --ports 22,80,443,3306 --timeout 2
  python3 port_scanner.py 10.0.0.5 --ports 1-65535 --threads 500 --output out.txt
        """
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("--ports",   default="1-1024", metavar="RANGE",
                        help="Port range/list (default: 1-1024)")
    parser.add_argument("--threads", type=int, default=300, metavar="N",
                        help="Max concurrent connections (default: 300)")
    parser.add_argument("--timeout", type=float, default=1.0, metavar="SEC",
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--output",  metavar="FILE",
                        help="Save results to a text file")
    args = parser.parse_args()

    print_banner()

    ip = resolve(args.target)
    ports = parse_ports(args.ports)

    print(f"  [*] Target   : {args.target} ({ip})")
    print(f"  [*] Ports    : {ports[0]}–{ports[-1]} ({len(ports)} total)")
    print(f"  [*] Threads  : {args.threads}")
    print(f"  [*] Timeout  : {args.timeout}s")
    print(f"  [*] Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    start = time.perf_counter()
    open_ports = asyncio.run(run_scan(ip, ports, args.threads, args.timeout))
    elapsed = time.perf_counter() - start

    print(format_results(open_ports, elapsed, args.target, ip))

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Scan Report — {datetime.now()}\n")
            f.write(f"Target: {args.target} ({ip})\n\n")
            f.write(f"{'PORT':<8} {'STATE':<8} {'SERVICE'}\n")
            f.write("─" * 36 + "\n")
            for port, svc in open_ports:
                f.write(f"{port:<8} {'open':<8} {svc}\n")
        print(f"\n  [+] Report saved → {args.output}")


if __name__ == "__main__":
    main()
