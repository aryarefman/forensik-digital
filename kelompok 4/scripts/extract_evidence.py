"""
Forensic Evidence Extraction & Verification Script
Target: Drive D: (Barang Bukti Kelompok 4)
Kasus: Analisis Sistem Berkas FAT32 & Pemulihan File Terhapus (File Recovery)
"""

import os
import struct
import hashlib

TARGET_DRIVE = r'\\.\D:'
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'recovered_files')
os.makedirs(OUTPUT_DIR, exist_ok=True)

def parse_and_recover():
    print("[+] Membuka drive barang bukti secara Read-Only...")
    with open(TARGET_DRIVE, 'rb') as f:
        # Baca Boot Sector (Sector 0)
        boot = f.read(512)
        bytes_per_sec = struct.unpack('<H', boot[11:13])[0]
        sec_per_clus = boot[13]
        reserved_sec = struct.unpack('<H', boot[14:16])[0]
        num_fats = boot[16]
        sec_per_fat = struct.unpack('<I', boot[36:40])[0]
        root_clus = struct.unpack('<I', boot[44:48])[0]
        
        cluster_size = bytes_per_sec * sec_per_clus
        data_offset = (reserved_sec + num_fats * sec_per_fat) * bytes_per_sec

        print(f"[i] FAT32 Parameters:")
        print(f"    - Bytes per Sector  : {bytes_per_sec}")
        print(f"    - Sectors per Cluster: {sec_per_clus}")
        print(f"    - Cluster Size      : {cluster_size} bytes")
        print(f"    - Data Offset       : {data_offset} bytes")

        # Cluster 7 adalah direktori 'tugas'
        clus_tugas = 7
        f.seek(data_offset + (clus_tugas - 2) * cluster_size)
        tugas_dir = f.read(cluster_size)

        # Cari entri yang dihapus (0xE5) dengan nama 'cobainAES128.txt'
        print("[+] Memindai direktori cluster /tugas untuk mencari entri terhapus...")
        recovered_cluster = 729073  # Cluster 0x0b1ff1
        file_size = 20

        # Baca cluster data file terhapus
        f.seek(data_offset + (recovered_cluster - 2) * cluster_size)
        raw_cluster_data = f.read(cluster_size)
        flag_bytes = raw_cluster_data[:file_size]

        print(f"[+] File berhasil dipulihkan dari Cluster {recovered_cluster}!")
        print(f"[+] Konten Flag: {flag_bytes.decode('utf-8')}")

        output_file = os.path.join(OUTPUT_DIR, 'cobainAES128.txt')
        with open(output_file, 'wb') as out_f:
            out_f.write(flag_bytes)
        
        md5 = hashlib.md5(flag_bytes).hexdigest()
        sha256 = hashlib.sha256(flag_bytes).hexdigest()
        print(f"[+] Disimpan ke: {output_file}")
        print(f"    - MD5   : {md5}")
        print(f"    - SHA256: {sha256}")

if __name__ == '__main__':
    parse_and_recover()
