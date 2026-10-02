#!/usr/bin/env python3
"""
Evidence Extraction & Carving Engine for Kelompok 5
Examiner: Kelompok 3 (Forensik Digital)
Standard: ISO/IEC 27037 & NIST SP 800-86
"""

import os, struct, hashlib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(BASE_DIR, 'evidence')
RECOVERED_DIR = os.path.join(BASE_DIR, 'recovered_files')
os.makedirs(RECOVERED_DIR, exist_ok=True)

def carve_trailing_data():
    img_path = os.path.join(EVIDENCE_DIR, 'flag-1', 'opung_archive.jpg')
    if not os.path.exists(img_path):
        img_path = r'D:\flag-1\opung_archive.jpg'
    
    print(f"[*] Analyzing JPEG file: {img_path}")
    with open(img_path, 'rb') as f:
        data = f.read()
    
    total_size = len(data)
    print(f"[+] Total file size: {total_size} bytes")
    
    # Locate JPEG EOI marker (\xFF\xD9)
    eoi_idx = data.find(b'\xff\xd9')
    if eoi_idx == -1:
        print("[-] EOI marker not found!")
        return None
    
    eoi_end = eoi_idx + 2
    print(f"[+] JPEG EOI marker found at offset: {eoi_idx} (end: {eoi_end})")
    
    trailing_data = data[eoi_end:]
    trailing_len = len(trailing_data)
    print(f"[+] Trailing data detected: {trailing_len} bytes")
    
    if trailing_len > 0:
        trailing_text = trailing_data.decode('utf-8', errors='replace').strip()
        print(f"[!] Extracted Trailing Flag: {trailing_text}")
        
        flag_path = os.path.join(RECOVERED_DIR, 'flag.txt')
        with open(flag_path, 'w', encoding='utf-8') as f:
            f.write(trailing_text + '\n')
        
        hidden_path = os.path.join(RECOVERED_DIR, 'hidden_mission.txt')
        with open(hidden_path, 'w', encoding='utf-8') as f:
            f.write(trailing_text)
            
        print(f"[+] Saved flag to: {flag_path}")
        return trailing_text
    return None

def carve_deleted_png():
    print("[*] Carving deleted PNG from raw disk clusters 6..11...")
    data_offset = 16777216
    cluster_size = 16384
    
    with open(r'\\.\D:', 'rb') as f:
        f.seek(data_offset + (6 - 2) * cluster_size)
        raw_png = f.read(94651)
        
    png_path = os.path.join(RECOVERED_DIR, 'zein_carved.png')
    with open(png_path, 'wb') as f:
        f.write(raw_png)
    
    print(f"[+] Carved {len(raw_png)} bytes to {png_path}")
    print(f"[+] SHA-256: {hashlib.sha256(raw_png).hexdigest()}")

def carve_deleted_link():
    print("[*] Carving deleted link.txt from cluster 12...")
    data_offset = 16777216
    cluster_size = 16384
    
    with open(r'\\.\D:', 'rb') as f:
        f.seek(data_offset + (12 - 2) * cluster_size)
        raw_link = f.read(38)
        
    link_text = raw_link.decode('utf-8', errors='replace').strip()
    link_path = os.path.join(RECOVERED_DIR, 'link.txt')
    with open(link_path, 'w', encoding='utf-8') as f:
        f.write(link_text)
        
    print(f"[+] Carved link: {link_text} -> {link_path}")

def main():
    print("=" * 60)
    print("DFIR EVIDENCE EXTRACTION & CARVING SUITE - KELOMPOK 5")
    print("=" * 60)
    carve_trailing_data()
    carve_deleted_png()
    carve_deleted_link()
    print("\n[+] Extraction & carving completed successfully.")

if __name__ == '__main__':
    main()
