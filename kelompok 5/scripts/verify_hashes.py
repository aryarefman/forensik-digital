#!/usr/bin/env python3
"""
Cryptographic Integrity Verification Engine for Kelompok 5
Examiner: Kelompok 3 (Forensik Digital)
Standard: ISO/IEC 27037 & NIST SP 800-86
"""

import os, hashlib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TARGETS = [
    ("Physical Drive Active File", r"D:\flag-1\opung_archive.jpg"),
    ("Forensic Copy Evidence", os.path.join(BASE_DIR, "evidence", "flag-1", "opung_archive.jpg")),
    ("Recovered Flag (flag.txt)", os.path.join(BASE_DIR, "recovered_files", "flag.txt")),
    ("Recovered Hidden Mission", os.path.join(BASE_DIR, "recovered_files", "hidden_mission.txt")),
    ("Recovered Link (link.txt)", os.path.join(BASE_DIR, "recovered_files", "link.txt")),
    ("Carved PNG (zein_carved.png)", os.path.join(BASE_DIR, "recovered_files", "zein_carved.png")),
]

def hash_file(path):
    if not os.path.exists(path):
        return None, None, 0
    with open(path, 'rb') as f:
        data = f.read()
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256, len(data)

def main():
    print("=" * 105)
    print(f"{'ARTIFACT LABEL':<30} | {'SIZE':<8} | {'MD5 HASH':<32} | {'SHA-256 HASH'}")
    print("=" * 105)
    for label, path in TARGETS:
        md5, sha256, size = hash_file(path)
        if md5:
            print(f"{label:<30} | {size:<8} | {md5:<32} | {sha256}")
        else:
            print(f"{label:<30} | {'NOT FOUND':<8} | {'-'*32} | {'-'*64}")
    print("=" * 105)

if __name__ == '__main__':
    main()
