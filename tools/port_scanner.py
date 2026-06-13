#!/usr/bin/env python3
"""
CyberSec Toolkit — Async TCP/UDP Port Scanner
Fixed: Proper async cleanup, timeout handling, service detection
"""
import asyncio
import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor

# Common service signatures
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 9200: "Elasticsearch"
}

async def scan_port_tcp(host: str, port: int, timeout: float = 2.0) -> tuple:
    """Scan a single TCP port. Returns (port, is_open, banner)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = ""
        try:
            writer.write(b"\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = banner.decode(errors="ignore").strip()
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()
        return (port, True, banner)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return (port, False, "")
    except Exception as e:
        return (port, False, str(e))

async def scan_port_udp(host: str, port: int, timeout: float = 2.0) -> tuple:
    """UDP port scan — sends probe and checks for ICMP unreachable."""
    try:
        loop = asyncio.get_event_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # Send a probe (varies by common port)
            probes = {
                53: b"\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
                123: b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00",
                161: b"\x30\x26\x02\x01\x00\x04\x06public\xA1\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0B\x30\x09\x06\x05\x2B\x06\x01\x02\x01\x05\x00",
            }
            probe = probes.get(port, b"\x00")
            sock.sendto(probe, (host, port))
            try:
                data, addr = sock.recvfrom(1024)
                return (port, True, data[:64].hex())
            except socket.timeout:
                # No response could mean open|filtered
                return (port, "open|filtered", "")
    except Exception as e:
        return (port, False, str(e))

async def scan_host(host: str, ports: range, udp: bool = False, max_concurrent: int = 100):
    """Scan multiple ports with concurrency limit."""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def bounded_scan(port):
        async with semaphore:
            if udp:
                return await scan_port_udp(host, port)
            return await scan_port_tcp(host, port)
    
    tasks = [bounded_scan(p) for p in ports]
    results = []
    for task in asyncio.as_completed(tasks):
        result = await task
        if result[1]:  # Port is open or open|filtered
            results.append(result)
            service = COMMON_SERVICES.get(result[0], "Unknown")
            status = "OPEN" if result[1] is True else result[1]
            print(f"[{status}] Port {result[0]:>5} | {service:<15} | {result[2][:50] if result[2] else ''}")
    
    return sorted(results, key=lambda x: x[0])

def main():
    parser = argparse.ArgumentParser(description="Async TCP/UDP Port Scanner")
    parser.add_argument("host", help="Target host/IP")
    parser.add_argument("--ports", "-p", default="1-1024", help="Port range (e.g., 1-1024,80,443,8080)")
    parser.add_argument("--udp", "-u", action="store_true", help="UDP scan")
    parser.add_argument("--timeout", "-t", type=float, default=2.0, help="Timeout per port (seconds)")
    parser.add_argument("--threads", "-T", type=int, default=100, help="Max concurrent connections")
    args = parser.parse_args()

    # Parse port range
    ports = []
    for part in args.ports.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    print(f"{'UDP' if args.udp else 'TCP'} Scanning {args.host} on {len(ports)} ports...")
    print("-" * 60)
    
    try:
        results = asyncio.run(scan_host(args.host, ports, args.udp, args.threads))
        print("-" * 60)
        print(f"Found {len(results)} open ports")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
