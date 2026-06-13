#!/usr/bin/env python3
"""
CyberSec Toolkit — Hash Identifier & Cracker
=============================================
Identifies the type of a hash by its length and format, then
optionally cracks it with a dictionary attack.

Usage:
    python3 hash_identifier.py <hash>
    python3 hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
    python3 hash_identifier.py <hash> --type SHA-256 --wordlist words.txt

Supported identification:
    MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
    SHA3-256, SHA3-512, bcrypt, NTLM, MySQL4, MySQL5, WPA-PMK

Supports cracking:
    MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
    SHA3-256, SHA3-512

Educational use only. See ETHICAL_USE.txt before use.
"""

import hashlib
import argparse
import re
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

# =============================================================================
# Hash signature database
# Each entry: (display_name, regex_pattern, hashlib_algo_name | None)
# None means we can identify but not crack with hashlib
# =============================================================================
HASH_DB: List[Tuple[str, str, Optional[str]]] = [
    # ── length-based hex hashes ──────────────────────────────────────────────
    ("MD5",       r"^[a-fA-F0-9]{32}$",   "md5"),
    ("NTLM",      r"^[a-fA-F0-9]{32}$",   None),       # same length as MD5
    ("SHA-1",     r"^[a-fA-F0-9]{40}$",   "sha1"),
    ("MySQL4",    r"^[a-fA-F0-9]{40}$",   None),       # old MySQL pre-4.1
    ("SHA-224",   r"^[a-fA-F0-9]{56}$",   "sha224"),
    ("SHA-256",   r"^[a-fA-F0-9]{64}$",   "sha256"),
    ("SHA3-256",  r"^[a-fA-F0-9]{64}$",   "sha3_256"), # same length as SHA-256
    ("WPA-PMK",   r"^[a-fA-F0-9]{64}$",   None),       # same length as SHA-256
    ("SHA-384",   r"^[a-fA-F0-9]{96}$",   "sha384"),
    ("SHA-512",   r"^[a-fA-F0-9]{128}$",  "sha512"),
    ("SHA3-512",  r"^[a-fA-F0-9]{128}$",  "sha3_512"), # same length as SHA-512
    # ── special format hashes ─────────────────────────────────────────────────
    ("MySQL5",    r"^\*[a-fA-F0-9]{40}$", None),       # MySQL 4.1+  *XXXXXXXX
    ("bcrypt",    r"^\$2[aby]\$\d{2}\$.{53}$", None),  # $2a$12$...
    ("sha512crypt",r"^\$6\$[./a-zA-Z0-9]{8,}\$[./a-zA-Z0-9]{86}$", None),  # Linux shadow
    ("md5crypt",  r"^\$1\$[./a-zA-Z0-9]{8}\$[./a-zA-Z0-9]{22}$", None),   # Linux shadow
    ("LM",        r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", None),            # LMHASH:NTLM
    ("Whirlpool", r"^[a-fA-F0-9]{128}$",  None),
]


# =============================================================================
# Colour helpers
# =============================================================================
def _c(text: str, code: str) -> str:
    """Wrap text in ANSI colour code."""
    return f"\033[{code}m{text}\033[0m"


GREEN  = lambda t: _c(t, "92")
RED    = lambda t: _c(t, "91")
YELLOW = lambda t: _c(t, "93")
CYAN   = lambda t: _c(t, "96")
BOLD   = lambda t: _c(t, "1")


# =============================================================================
# Core functions
# =============================================================================
def identify(h: str) -> List[Tuple[str, Optional[str]]]:
    """Return list of (name, algo) for all hash patterns that match."""
    h = h.strip()
    matches = []
    seen = set()
    for name, pattern, algo in HASH_DB:
        if re.fullmatch(pattern, h) and name not in seen:
            matches.append((name, algo))
            seen.add(name)
    return matches if matches else [("Unknown", None)]


def compute_hash(algo: str, text: str) -> str:
    """Compute hash of text using hashlib."""
    return hashlib.new(algo, text.encode("utf-8")).hexdigest()


def crack_with_wordlist(
    hash_str: str,
    algo: str,
    wordlist_path: str
) -> Optional[str]:
    """
    Dictionary attack: hash each word in wordlist and compare.
    Returns plaintext if found, None otherwise.
    """
    path = Path(wordlist_path)
    if not path.exists():
        print(RED(f"[!] Wordlist not found: {wordlist_path}"))
        sys.exit(1)

    target = hash_str.strip().lower()
    tried = 0
    start = time.perf_counter()

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.rstrip("\n")
                candidate = compute_hash(algo, word)
                if candidate == target:
                    return word
                tried += 1
                if tried % 500_000 == 0:
                    elapsed = time.perf_counter() - start
                    speed = tried / elapsed
                    print(CYAN(f"  [*] {tried:,} words tried  |  {speed:,.0f} hash/s  |  {elapsed:.1f}s elapsed"))
    except PermissionError:
        print(RED(f"[!] Permission denied: {wordlist_path}"))
        sys.exit(1)

    return None


# =============================================================================
# Banner
# =============================================================================
def print_banner():
    print(CYAN("""
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║
  ███████║███████║███████╗███████║
  ██╔══██║██╔══██║╚════██║██╔══██║
  ██║  ██║██║  ██║███████║██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
  Identifier — CyberSec Toolkit v1.0"""))


# =============================================================================
# Entry point
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Hash identifier & dictionary cracker — educational use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Identify only
  python3 hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99

  # Identify + crack
  python3 hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt

  # Force algorithm for cracking
  python3 hash_identifier.py <sha256_hash> --type SHA-256 --wordlist words.txt
        """
    )
    parser.add_argument("hash",      help="The hash string to analyse")
    parser.add_argument("--wordlist",metavar="FILE", help="Wordlist for dictionary attack")
    parser.add_argument("--type",    metavar="ALGO", help="Force hash type (e.g. MD5, SHA-256)")
    args = parser.parse_args()

    print_banner()

    h = args.hash.strip()
    print(f"\n  {BOLD('Hash   :')} {h}")
    print(f"  {BOLD('Length :')} {len(h)}")

    matches = identify(h)
    names = [name for name, _ in matches]
    print(f"\n  {BOLD('Possible type(s):')} {YELLOW(', '.join(names))}")

    # ── detailed breakdown ────────────────────────────────────────────────────
    if names != ["Unknown"]:
        print("\n  ┌─ Details ──────────────────────────────────────────┐")
        for name, algo in matches:
            crack_note = GREEN("✔ can crack") if algo else RED("✘ crack unsupported")
            print(f"  │  {BOLD(name):<22} {crack_note}")
        print("  └────────────────────────────────────────────────────┘")

    # ── optional cracking ─────────────────────────────────────────────────────
    if args.wordlist:
        # Determine which algo to use
        if args.type:
            # User forced a type — find its algo
            forced = next(
                ((n, a) for n, a in matches if n.lower() == args.type.lower()),
                None
            )
            if forced is None:
                # Try global HASH_DB too
                forced = next(
                    ((n, a) for n, p, a in HASH_DB if n.lower() == args.type.lower()),
                    None
                )
            if not forced or not forced[1]:
                print(RED(f"\n[!] Cannot crack hash type '{args.type}' — unsupported algorithm."))
                sys.exit(1)
            crack_name, crack_algo = forced
        else:
            # Pick first crackable match
            crackable = [(n, a) for n, a in matches if a]
            if not crackable:
                print(RED("\n[!] No crackable hash type found. Use --type to specify."))
                sys.exit(1)
            crack_name, crack_algo = crackable[0]

        print(f"\n  [*] Attacking as {BOLD(crack_name)} using {args.wordlist} …")
        start = time.perf_counter()
        result = crack_with_wordlist(h, crack_algo, args.wordlist)
        elapsed = time.perf_counter() - start

        if result:
            print(f"\n  {GREEN('[+] CRACKED!')} Plaintext = {BOLD(repr(result))}  ({elapsed:.2f}s)")
        else:
            print(f"\n  {RED('[-] Not found in wordlist.')} ({elapsed:.2f}s)")
            print("  [i] Try rockyou.txt, darkweb2017.txt, or SecLists/Passwords/")
    else:
        print("\n  [i] Add --wordlist <file> to attempt a dictionary attack.")


if __name__ == "__main__":
    main()
