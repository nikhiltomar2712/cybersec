#!/usr/bin/env python3
"""
Asynchronous TCP Port Scanner
Scans a target for open ports with service detection.
"""

import asyncio
import socket
import argparse
import sys
from typing import List, Tuple

# Service mapping for common ports
SERVICE_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 161: 'SNMP',
    194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTP-SSL', 514: 'Syslog', 587: 'SMTP',
    636: 'LDAPS', 993: 'IMAP-SSL', 995: 'POP3-SSL',
    1433: 'SQL Server', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 27017: 'MongoDB', 6379: 'Redis'
}


async def check_port(host: str, port: int, timeout: int = 5) -> Tuple[int, bool]:
    """
    Check if a port is open on the target host.
    
    Args:
        host: Target hostname or IP
        port: Port number to check
        timeout: Connection timeout in seconds
        
    Returns:
        Tuple of (port, is_open)
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return (port, True)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return (port, False)


async def scan_ports(host: str, ports: List[int], timeout: int = 5, max_concurrent: int = 100) -> List[int]:
    """
    Scan multiple ports concurrently.
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan
        timeout: Connection timeout per port
        max_concurrent: Maximum concurrent connections
        
    Returns:
        List of open ports
    """
    open_ports = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def bounded_check(port):
        async with semaphore:
            return await check_port(host, port, timeout)
    
    tasks = [bounded_check(port) for port in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, tuple) and result[1]:
            open_ports.append(result[0])
    
    return sorted(open_ports)


def parse_ports(port_spec: str) -> List[int]:
    """
    Parse port specification (e.g., '1-1024' or '22,80,443').
    
    Args:
        port_spec: Port specification string
        
    Returns:
        List of port numbers
    """
    ports = []
    for part in port_spec.split(','):
        if '-' in part:
            start, end = map(int, part.strip().split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part.strip()))
    return list(set(ports))  # Remove duplicates


def get_service_name(port: int) -> str:
    """
    Get the service name for a given port.
    """
    return SERVICE_PORTS.get(port, 'Unknown')


async def main():
    parser = argparse.ArgumentParser(
        description='Async TCP Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 --ports 1-1024
  %(prog)s example.com --ports 22,80,443,3306,5432
  %(prog)s localhost --ports 1-65535 --timeout 10
        """
    )
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('--ports', default='1-1024', help='Port range or list (default: 1-1024)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds')
    parser.add_argument('--max-concurrent', type=int, default=100, help='Max concurrent connections')
    
    args = parser.parse_args()
    
    try:
        print(f"[*] Resolving {args.target}...")
        host_ip = socket.gethostbyname(args.target)
        print(f"[+] Resolved to {host_ip}")
    except socket.gaierror:
        print(f"[-] Could not resolve hostname: {args.target}")
        sys.exit(1)
    
    try:
        ports = parse_ports(args.ports)
        print(f"[*] Scanning {len(ports)} ports on {args.target}...")
        print()
        
        open_ports = await scan_ports(host_ip, ports, args.timeout, args.max_concurrent)
        
        if open_ports:
            print(f"\n[+] Open ports found: {len(open_ports)}\n")
            print("{:<10} {:<20}".format("PORT", "SERVICE"))
            print("-" * 30)
            for port in open_ports:
                service = get_service_name(port)
                print("{:<10} {:<20}".format(port, service))
        else:
            print("[-] No open ports found")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
