#!/usr/bin/env python3
"""
CyberSec Toolkit — File Forensics Analyzer
Extracts metadata, detects file types, finds hidden data
"""
import os
import sys
import struct
import argparse
from datetime import datetime

def detect_file_type(filepath: str) -> str:
    """Detect file type by magic bytes."""
    with open(filepath, 'rb') as f:
        header = f.read(16)
    
    magic_signatures = {
        b'\x89PNG': "PNG Image",
        b'\xff\xd8\xff': "JPEG Image",
        b'GIF89a': "GIF Image",
        b'GIF87a': "GIF Image",
        b'PK\x03\x04': "ZIP Archive / DOCX / JAR",
        b'Rar!': "RAR Archive",
        b'\x1f\x8b\x08': "GZIP Archive",
        b'\x7fELF': "ELF Executable",
        b'MZ': "Windows Executable",
        b'%PDF': "PDF Document",
    }
    
    for magic, ftype in magic_signatures.items():
        if header.startswith(magic):
            return ftype
    return "Unknown"

def extract_strings(filepath: str, min_length: int = 4) -> list:
    """Extract printable strings from binary."""
    strings = []
    current = ""
    
    with open(filepath, 'rb') as f:
        while True:
            byte = f.read(1)
            if not byte:
                break
            if 32 <= byte[0] <= 126:
                current += chr(byte[0])
            else:
                if len(current) >= min_length:
                    strings.append(current)
                current = ""
    
    if len(current) >= min_length:
        strings.append(current)
    
    return strings

def check_hidden_data(filepath: str) -> dict:
    """Check for hidden data after EOF markers."""
    results = {
        'file_size': os.path.getsize(filepath),
        'eof_markers': {},
        'trailing_data': False
    }
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Check for appended data after common EOF markers
    eof_markers = {
        b'\xff\xd9': "JPEG EOF",
        b'\x00\x00\x00\x00IEND\xaeB`\x82': "PNG EOF",
        b'%%EOF': "PDF EOF",
    }
    
    for marker, name in eof_markers.items():
        pos = data.find(marker)
        if pos != -1:
            end_pos = pos + len(marker)
            results['eof_markers'][name] = end_pos
            if end_pos < len(data) - 1:
                trailing = len(data) - end_pos
                results['trailing_data'] = True
                results['trailing_bytes'] = trailing
    
    return results

def analyze_file(filepath: str):
    """Full file analysis."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return
    
    print(f"\n[File Analysis: {filepath}]")
    print(f"Size: {os.path.getsize(filepath)} bytes")
    print(f"Modified: {datetime.fromtimestamp(os.path.getmtime(filepath))}")
    
    print(f"\n[File Type]")
    print(f"  {detect_file_type(filepath)}")
    
    print(f"\n[Hidden Data Check]")
    hidden = check_hidden_data(filepath)
    if hidden['trailing_data']:
        print(f"  [!] WARNING: {hidden.get('trailing_bytes', 0)} bytes after EOF!")
        print(f"  EOF markers found: {list(hidden['eof_markers'].keys())}")
    else:
        print(f"  [OK] No trailing data detected")
    
    print(f"\n[Interesting Strings]")
    strings = extract_strings(filepath)
    interesting = [s for s in strings if any(k in s.lower() for k in 
                   ['password', 'secret', 'key', 'admin', 'token', 'http', 'flag'])]
    for s in interesting[:20]:
        print(f"  {s[:80]}")
    
    if len(interesting) > 20:
        print(f"  ... and {len(interesting) - 20} more")

def main():
    parser = argparse.ArgumentParser(description="File Forensics Analyzer")
    parser.add_argument("file", help="File to analyze")
    args = parser.parse_args()
    
    analyze_file(args.file)

if __name__ == "__main__":
    main()
