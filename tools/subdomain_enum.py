#!/usr/bin/env python3
"""
CyberSec Toolkit — Subdomain Enumerator
Fixed: DNS timeout handling, added wildcard detection, threading
"""
import dns.resolver
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

def check_subdomain(domain: str, subdomain: str, timeout: float = 3.0) -> tuple:
    """Check if subdomain resolves. Returns (subdomain, [records])."""
    full = f"{subdomain}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    try:
        answers = resolver.resolve(full, 'A')
        records = [str(r) for r in answers]
        return (full, records)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None
    except Exception:
        return None

def detect_wildcard(domain: str) -> bool:
    """Detect if domain has wildcard DNS."""
    try:
        resolver = dns.resolver.Resolver()
        random_sub = f"wildcard-test-{hash(domain) % 10000}.{domain}"
        resolver.resolve(random_sub, 'A')
        return True
    except:
        return False

def enumerate_subdomains(domain: str, wordlist: str, threads: int = 50, timeout: float = 3.0):
    """Enumerate subdomains using wordlist."""
    print(f"[*] Target: {domain}")
    
    # Check wildcard
    if detect_wildcard(domain):
        print("[!] WARNING: Wildcard DNS detected. Results may be unreliable.")
    
    # Load wordlist
    try:
        with open(wordlist, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist}")
        sys.exit(1)
    
    print(f"[*] Loaded {len(subdomains)} subdomains. Scanning with {threads} threads...")
    
    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_subdomain, domain, sub, timeout): sub 
            for sub in subdomains
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                print(f"[+] {result[0]:<<40} -> {', '.join(result[1])}")
    
    print(f"\n[*] Found {len(found)} subdomains")
    return found

def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--wordlist", "-w", default="subdomains.txt", help="Subdomain wordlist")
    parser.add_argument("--threads", "-t", type=int, default=50, help="Thread count")
    parser.add_argument("--timeout", "-T", type=float, default=3.0, help="DNS timeout")
    parser.add_argument("--output", "-o", help="Output file")
    args = parser.parse_args()

    results = enumerate_subdomains(args.domain, args.wordlist, args.threads, args.timeout)
    
    if args.output:
        with open(args.output, 'w') as f:
            for sub, records in results:
                f.write(f"{sub} -> {', '.join(records)}\n")
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
