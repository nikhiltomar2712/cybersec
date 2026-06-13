#!/usr/bin/env python3
"""
Hash Type Identifier & Dictionary Cracker
Identifies hash types and attempts dictionary-based cracking.
"""

import hashlib
import re
import argparse
import sys
from typing import Tuple, Optional

# Hash patterns and their info
HASH_PATTERNS = {
    'MD5': (r'^[a-f0-9]{32}$', 32),
    'SHA-1': (r'^[a-f0-9]{40}$', 40),
    'SHA-256': (r'^[a-f0-9]{64}$', 64),
    'SHA-512': (r'^[a-f0-9]{128}$', 128),
    'NTLM': (r'^[a-f0-9]{32}$', 32),  # Same as MD5, check context
    'Argon2': (r'^\$argon2', -1),
    'BCrypt': (r'^\$2[aby]\$', -1),
}


def identify_hash(hash_value: str) -> Optional[str]:
    """
    Identify the type of hash.
    
    Args:
        hash_value: The hash string to identify
        
    Returns:
        Hash type name or None if unidentified
    """
    hash_lower = hash_value.lower()
    
    for hash_type, (pattern, length) in HASH_PATTERNS.items():
        if re.match(pattern, hash_lower, re.IGNORECASE):
            return hash_type
    
    return None


def crack_hash(hash_value: str, wordlist_path: str, limit: int = 0) -> Optional[str]:
    """
    Attempt to crack a hash using a wordlist.
    
    Args:
        hash_value: Hash to crack
        wordlist_path: Path to wordlist file
        limit: Max attempts (0 = unlimited)
        
    Returns:
        Plaintext if found, None otherwise
    """
    hash_type = identify_hash(hash_value)
    
    if not hash_type:
        print(f"[-] Hash type not recognized")
        return None
    
    # Only support MD5 and SHA-1 for now
    if hash_type not in ['MD5', 'SHA-1', 'SHA-256']:
        print(f"[-] Cracking for {hash_type} not supported yet")
        return None
    
    # Select hash function
    if hash_type == 'MD5':
        hash_func = hashlib.md5
    elif hash_type == 'SHA-1':
        hash_func = hashlib.sha1
    else:
        hash_func = hashlib.sha256
    
    print(f"[*] Attempting to crack {hash_type} hash...")
    print(f"[*] Using wordlist: {wordlist_path}")
    
    try:
        attempts = 0
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                
                attempts += 1
                if limit > 0 and attempts > limit:
                    print(f"[*] Reached limit of {limit} attempts")
                    break
                
                # Try the word as-is
                test_hash = hash_func(word.encode()).hexdigest()
                if test_hash == hash_value.lower():
                    print(f"[+] Match found: {word}")
                    return word
                
                if attempts % 10000 == 0:
                    print(f"[*] Tried {attempts} words...")
        
        print(f"[-] No match found after {attempts} attempts")
        return None
        
    except FileNotFoundError:
        print(f"[-] Wordlist not found: {wordlist_path}")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Hash Type Identifier & Dictionary Cracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 5d41402abc4b2a76b9719d911017c592
  %(prog)s d41d8cd98f00b204e9800998ecf8427e --wordlist rockyou.txt
  %(prog)s abc123def456 --wordlist common.txt --limit 1000
        """
    )
    parser.add_argument('hash', help='Hash to identify and crack')
    parser.add_argument('--wordlist', help='Wordlist file for cracking')
    parser.add_argument('--limit', type=int, default=0, help='Max attempts (0=unlimited)')
    
    args = parser.parse_args()
    
    # Identify hash
    hash_type = identify_hash(args.hash)
    
    if hash_type:
        print(f"[+] Hash identified as: {hash_type}")
        print(f"[+] Hash value: {args.hash}")
        print()
        
        # Attempt cracking if wordlist provided
        if args.wordlist:
            result = crack_hash(args.hash, args.wordlist, args.limit)
            if result:
                print(f"\n[+] Successfully cracked: {result}")
                return 0
            else:
                print(f"\n[-] Cracking failed")
                return 1
        else:
            print("[*] Use --wordlist to attempt cracking")
            return 0
    else:
        print(f"[-] Could not identify hash type")
        print(f"Hash: {args.hash}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
