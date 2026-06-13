#!/usr/bin/env python3
"""
DNS Subdomain Enumeration Tool
Performs subdomain enumeration via DNS brute-force.
"""

import dns.resolver
import argparse
import sys
from typing import List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common subdomains wordlist (embedded)
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
    'ns1', 'webdisk', 'ns2', 'cpanel', 'whois', 'autodiscover',
    'autoconfig', 'mail2', 'admin', 'api', 'dev', 'test',
    'staging', 'blog', 'shop', 'support', 'cdn', 'static',
    'images', 'files', 'download', 'upload', 'analytics',
    'accounts', 'auth', 'login', 'register', 'dashboard',
]


def load_wordlist(wordlist_path: str) -> List[str]:
    """
    Load subdomains from a wordlist file.
    
    Args:
        wordlist_path: Path to wordlist file
        
    Returns:
        List of subdomains
    """
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
        return []


def resolve_subdomain(subdomain: str, domain: str) -> tuple:
    """
    Attempt to resolve a subdomain.
    
    Args:
        subdomain: Subdomain to test
        domain: Base domain
        
    Returns:
        Tuple of (full_subdomain, ip) or (None, None)
    """
    try:
        full_domain = f"{subdomain}.{domain}"
        result = dns.resolver.resolve(full_domain, 'A')
        ips = [str(rdata) for rdata in result]
        return (full_domain, ips)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return (None, None)
    except Exception:
        return (None, None)


def enumerate_subdomains(domain: str, wordlist: List[str], threads: int = 10) -> Set[str]:
    """
    Enumerate subdomains for a domain.
    
    Args:
        domain: Target domain
        wordlist: List of subdomains to try
        threads: Number of worker threads
        
    Returns:
        Set of discovered subdomains
    """
    found = set()
    
    print(f"[*] Enumerating subdomains for {domain}")
    print(f"[*] Testing {len(wordlist)} subdomains with {threads} threads\n")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, sub, domain): sub
            for sub in wordlist
        }
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            full_domain, ips = future.result()
            
            if full_domain and ips:
                print(f"[+] {full_domain}: {', '.join(ips)}")
                found.add(full_domain)
            
            if completed % 50 == 0:
                print(f"[*] Progress: {completed}/{len(wordlist)}")
    
    return found


def main():
    parser = argparse.ArgumentParser(
        description='DNS Subdomain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --wordlist subdomains.txt
  %(prog)s example.com --threads 20
  %(prog)s example.com --wordlist custom.txt --threads 50
        """
    )
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--wordlist', help='Custom wordlist file')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads')
    
    args = parser.parse_args()
    
    # Load wordlist
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            sys.exit(1)
    else:
        print(f"[*] Using embedded common subdomains list")
        wordlist = COMMON_SUBDOMAINS
    
    try:
        # Enumerate
        found_subdomains = enumerate_subdomains(args.domain, wordlist, args.threads)
        
        # Summary
        print(f"\n[+] Enumeration complete!")
        print(f"[+] Found {len(found_subdomains)} subdomains:\n")
        
        for sub in sorted(found_subdomains):
            print(f"  - {sub}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        return 1
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
