#!/usr/bin/env python3
"""
Payload Decryption & Header Repair Script for Kelompok 1
Examiner: Kelompok 3 (Forensik Digital)
Standard: ISO/IEC 27037 & NIST SP 800-86
"""

import os, sys

def decrypt_payload(unallocated_file_path, output_zip_path):
    print(f"[*] Reading unallocated space artifact: {unallocated_file_path}")
    if not os.path.exists(unallocated_file_path):
        print(f"[-] File not found: {unallocated_file_path}")
        return False
        
    with open(unallocated_file_path, "rb") as f:
        data = f.read()
    
    print(f"[+] Total unallocated image size: {len(data)} bytes")
    
    # Sector 100 relative to physical sector 34: (100 - 34) * 512 = 33,792 bytes (0x8400)
    sector_offset = 33792
    xor_key = 0x5A
    corrupted_magic = bytes([0x84, 0xF7, 0xE4, 0xB5])
    
    print(f"[*] Verifying signature at offset {sector_offset} (0x{sector_offset:04X})...")
    header_raw = data[sector_offset:sector_offset+4]
    print(f"[+] Raw bytes at offset: {header_raw.hex().upper()}")
    
    # Decrypt via XOR 0x5A
    decrypted_stream = bytearray(b ^ xor_key for b in data[sector_offset:])
    print(f"[+] Decrypted pre-repair header: {decrypted_stream[:4].hex().upper()} (Target: DEADBEEF)")
    
    # Repair damaged ZIP magic header (0xDEADBEEF -> PK\x03\x04)
    decrypted_stream[0:4] = bytes([0x50, 0x4B, 0x03, 0x04])
    print(f"[+] Repaired ZIP magic header: {decrypted_stream[:4].hex().upper()} (PK\\x03\\x04)")
    
    # Locate End of Central Directory Record (PK\x05\x06) + 22 bytes
    eocd_pos = decrypted_stream.rfind(b"PK\x05\x06")
    if eocd_pos == -1:
        print("[-] EOCD record not found in decrypted stream.")
        return False
        
    final_zip = decrypted_stream[:eocd_pos + 22]
    print(f"[+] Carved ZIP payload size: {len(final_zip)} bytes (EOCD offset: {eocd_pos})")
    
    with open(output_zip_path, "wb") as f:
        f.write(final_zip)
    print(f"[+] Saved repaired payload to: {output_zip_path}")
    return True

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    recovered_dir = os.path.join(base_dir, "recovered_files")
    os.makedirs(recovered_dir, exist_ok=True)
    
    # Default paths
    sample_file = os.path.join(base_dir, "evidence", "000000034")
    out_file = os.path.join(recovered_dir, "payload.zip")
    
    if os.path.exists(sample_file):
        decrypt_payload(sample_file, out_file)
    else:
        print("[*] Demonstration mode: Run decrypt_payload with path to exported unallocated file '000000034'.")
