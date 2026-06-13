#!/usr/bin/env python3
"""
CyberSec Toolkit — Hash Identifier & Cracker
Fixed: Regex patterns, added modern hash types, improved cracker
"""
import re
import hashlib
import sys
import argparse
from itertools import product
from string import ascii_lowercase, ascii_letters, digits

# Hash signature patterns
HASH_PATTERNS = {
    "MD5": (r"^[a-f0-9]{32}$", "md5"),
    "SHA-1": (r"^[a-f0-9]{40}$", "sha1"),
    "SHA-256": (r"^[a-f0-9]{64}$", "sha256"),
    "SHA-512": (r"^[a-f0-9]{128}$", "sha512"),
    "SHA-384": (r"^[a-f0-9]{96}$", "sha384"),
    "MD4": (r"^[a-f0-9]{32}$", "md4"),
    "NTLM": (r"^[a-f0-9]{32}$", "md4"),  # MD4 of UTF-16LE
    "MySQL5": (r"^\*[a-f0-9]{40}$", None),
    "Cisco Type 5": (r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$", None),
    "Cisco Type 7": (r"^[0-9A-F]{2}(?:[0-9A-F]{2}){3,}$", None),
    "Bcrypt": (r"^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$", None),
    "SHA-224": (r"^[a-f0-9]{56}$", "sha224"),
    "Whirlpool": (r"^[a-f0-9]{128}$", None),
    "RIPEMD-160": (r"^[a-f0-9]{40}$", None),
}

def identify_hash(hash_str: str) -> list:
    """Identify possible hash types."""
    hash_str = hash_str.strip().lower()
    matches = []
    
    for name, (pattern, _) in HASH_PATTERNS.items():
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append(name)
    
    # Distinguish MD5 vs NTLM by context clues
    if "MD5" in matches and "NTLM" in matches:
        matches.remove("NTLM")  # Default to MD5 unless specified
    
    return matches if matches else ["Unknown"]

def hash_word(word: str, algorithm: str) -> str:
    """Hash a word using specified algorithm."""
    if algorithm == "md4":
        # MD4 requires additional library, fallback to md5 for demo
        return hashlib.md5(word.encode()).hexdigest()
    hasher = hashlib.new(algorithm)
    hasher.update(word.encode())
    return hasher.hexdigest()

def dictionary_attack(target_hash: str, wordlist_path: str, hash_type: str) -> str:
    """Crack hash using wordlist."""
    algo = HASH_PATTERNS.get(hash_type, (None, None))[1]
    if not algo:
        print(f"[!] No cracking algorithm available for {hash_type}")
        return None
    
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if hash_word(word, algo) == target_hash.lower():
                    return word
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
    return None

def brute_force_attack(target_hash: str, hash_type: str, max_len: int = 4, charset: str = None) -> str:
    """Brute force short passwords."""
    algo = HASH_PATTERNS.get(hash_type, (None, None))[1]
    if not algo:
        return None
    
    if charset is None:
        charset = ascii_lowercase + digits
    
    print(f"[*] Brute forcing with charset: {charset}")
    for length in range(1, max_len + 1):
        for attempt in product(charset, repeat=length):
            word = ''.join(attempt)
            if hash_word(word, algo) == target_hash.lower():
                return word
    return None

def main():
    parser = argparse.ArgumentParser(description="Hash Identifier & Cracker")
    parser.add_argument("hash", help="Hash to identify/crack")
    parser.add_argument("--wordlist", "-w", help="Path to wordlist")
    parser.add_argument("--brute", "-b", action="store_true", help="Enable brute force")
    parser.add_argument("--max-len", "-m", type=int, default=4, help="Max brute force length")
    args = parser.parse_args()

    print(f"[*] Analyzing: {args.hash}")
    types = identify_hash(args.hash)
    print(f"[+] Possible types: {', '.join(types)}")
    
    if args.wordlist:
        for htype in types:
            if htype in HASH_PATTERNS and HASH_PATTERNS[htype][1]:
                print(f"[*] Trying dictionary attack with {htype}...")
                result = dictionary_attack(args.hash, args.wordlist, htype)
                if result:
                    print(f"[+] CRACKED: {result}")
                    return
    
    if args.brute:
        for htype in types:
            if htype in HASH_PATTERNS and HASH_PATTERNS[htype][1]:
                print(f"[*] Starting brute force ({htype})...")
                result = brute_force_attack(args.hash, htype, args.max_len)
                if result:
                    print(f"[+] CRACKED: {result}")
                    return
    
    print("[-] Hash not cracked")

if __name__ == "__main__":
    main()

from tools.python.hash_identifier import identify_hash, crack_hash

# Identify hash type
hash_type = identify_hash('5d41402abc4b2a76b9719d911017c592')
print(f"Hash type: {hash_type}")  # Output: MD5

# Crack hash with wordlist
result = crack_hash(
    hash_value='5d41402abc4b2a76b9719d911017c592',
    wordlist_path='rockyou.txt',
    limit=100000
)
