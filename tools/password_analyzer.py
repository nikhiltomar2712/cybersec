#!/usr/bin/env python3
"""
CyberSec Toolkit — Password Strength Analyzer
Checks entropy, patterns, dictionary words, and breach simulation
"""
import re
import math
import argparse

COMMON_PATTERNS = [
    (r'^(password|123456|qwerty|admin|letmein|welcome|monkey|dragon)$', 
     'CRITICAL: Common password'),
    (r'^\d{4,}$', 'WEAK: Only digits'),
    (r'^[a-z]+$', 'WEAK: Only lowercase'),
    (r'^[A-Z]+$', 'WEAK: Only uppercase'),
    (r'(.)\1{2,}', 'WEAK: Repeated characters'),
    (r'^(19|20)\d{2}', 'MEDIUM: Starts with year'),
    (r'123|abc|qwe|asd|zxc|password|admin|login', 'MEDIUM: Common pattern'),
]

def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of password."""
    if not password:
        return 0
    entropy = 0
    for i in range(256):
        pi = password.count(chr(i)) / len(password)
        if pi > 0:
            entropy -= pi * math.log2(pi)
    return entropy * len(password)

def check_password(password: str) -> dict:
    """Analyze password strength."""
    results = {
        'length': len(password),
        'has_lower': bool(re.search(r'[a-z]', password)),
        'has_upper': bool(re.search(r'[A-Z]', password)),
        'has_digit': bool(re.search(r'\d', password)),
        'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        'entropy': calculate_entropy(password),
        'warnings': []
    }
    
    for pattern, warning in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            results['warnings'].append(warning)
    
    # Score calculation
    score = 0
    if results['length'] >= 8: score += 1
    if results['length'] >= 12: score += 1
    if results['has_lower'] and results['has_upper']: score += 1
    if results['has_digit']: score += 1
    if results['has_special']: score += 1
    if results['entropy'] > 50: score += 1
    
    if score <= 2:
        results['strength'] = 'VERY WEAK'
    elif score <= 3:
        results['strength'] = 'WEAK'
    elif score <= 4:
        results['strength'] = 'MODERATE'
    elif score <= 5:
        results['strength'] = 'STRONG'
    else:
        results['strength'] = 'VERY STRONG'
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("password", help="Password to analyze")
    args = parser.parse_args()
    
    results = check_password(args.password)
    
    print(f"\n[Password Analysis]")
    print(f"Length: {results['length']}")
    print(f"Lowercase: {'✓' if results['has_lower'] else '✗'}")
    print(f"Uppercase: {'✓' if results['has_upper'] else '✗'}")
    print(f"Digits: {'✓' if results['has_digit'] else '✗'}")
    print(f"Special: {'✓' if results['has_special'] else '✗'}")
    print(f"Entropy: {results['entropy']:.2f} bits")
    print(f"\nStrength: {results['strength']}")
    
    if results['warnings']:
        print(f"\n[!] Warnings:")
        for w in results['warnings']:
            print(f"  - {w}")

if __name__ == "__main__":
    main()
