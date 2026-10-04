#!/usr/bin/env python3
"""
Cryptographic Integrity Verification Engine for Kelompok 1
Examiner: Kelompok 3 (Forensik Digital)
Standard: ISO/IEC 27037 & NIST SP 800-86
"""

import os, hashlib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REC_DIR = os.path.join(BASE_DIR, "recovered_files")

TARGETS = [
    ("Unallocated Space Artifact (000000034)", os.path.join(BASE_DIR, "evidence", "000000034")),
    ("Repaired Payload (payload.zip)", os.path.join(REC_DIR, "payload.zip")),
    ("Extracted Flag (secret_evidence.txt)", os.path.join(REC_DIR, "secret_evidence.txt")),
]

# Baseline hashes from forensic documentation
BENCHMARK_HASHES = {
    "000000034": ["42D2F67AA536CA0BA0B077B3F80DCFCD26528AFE3AC91DB32632B9DAE737B9A7", "E440030D05AA38E45519FE670869B01F1FCBE48939B18DA991AB9E402322C629"],
    "payload.zip": ["A19D1ABF650FD215A479117CB312722E060BF0F27F116EC03B5C1C31A31636FA", "38F480F87FB8786C0BACA12DBE6BF13C541274F2BB9D2CA8899F9BCB79BF4740"],
    "secret_evidence.txt": ["40B13F2D38B96A1BAFD0451E7E91784D48141529EF6E544DA1DDE80E68AD5013"],
}

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
    print(f"{'ARTIFACT LABEL':<35} | {'SIZE':<8} | {'MD5 HASH':<32} | {'SHA-256 HASH'}")
    print("=" * 105)
    for label, path in TARGETS:
        fname = os.path.basename(path)
        md5, sha256, size = hash_file(path)
        if md5:
            expected = BENCHMARK_HASHES.get(fname, [])
            match = " [VERIFIED]" if sha256.upper() in expected else ""
            print(f"{label:<35} | {size:<8} | {md5:<32} | {sha256}{match}")
        else:
            ref_sha = BENCHMARK_HASHES.get(fname, ["-"*64])[0]
            print(f"{label:<35} | {'REF_ONLY':<8} | {'-'*32} | {ref_sha} [BASELINE]")
    print("=" * 105)

if __name__ == '__main__':
    main()
