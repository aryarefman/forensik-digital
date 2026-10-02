#!/usr/bin/env python3
"""
Timeline Reconstruction Script for Kelompok 5
Examiner: Kelompok 3 (Forensik Digital)
Standard: ISO/IEC 27037 & NIST SP 800-86
"""

def show():
    print("=== KRONOLOGI FORENSIK MEDIA PENYIMPANAN KELOMPOK 5 (FAT32 TIMELINE) ===")
    print("-" * 85)
    print("2026-09-21 08:51:16 | FORMAT    | Inisialisasi Volume FAT32, pembuatan System Volume Information")
    print("2026-09-21 08:51:37 | COPIED    | Berkas README.MD (27,508 B) disalin ke klaster 6 (mtime: 2026-09-19)")
    print("2026-09-21 08:52:00 | DELETED   | Berkas README.MD dihapus dari root directory (marker 0xE5)")
    print("2026-09-21 11:01:16 | CREATED   | Berkas OPUNG.JPG (95,747 B) dibuat di root directory (klaster 6)")
    print("2026-09-21 11:02:29 | CREATED   | Berkas hidden_mission.txt (32 B) dibuat di klaster 12")
    print("2026-09-21 11:07:12 | MODIFIED  | Berkas hidden_mission.txt diisi 'CODENAME{4P0ST3L_P3T3R_0F_GL0RY}'")
    print("2026-09-21 11:09:31 | INJECTED  | Penggabungan: OPUNG.JPG + hidden_mission.txt -> opung_archive.jpg")
    print("2026-09-21 11:10:03 | ORGANIZED | Folder 'New folder' dibuat -> di-rename menjadi 'FLAG-1'")
    print("2026-09-21 11:10:04 | MOVED     | opung_archive.jpg dipindahkan ke folder 'FLAG-1' (klaster 19)")
    print("2026-09-21 11:10:15 | DELETED   | hidden_mission.txt dan OPUNG.JPG asli dihapus dari root")
    print("2026-09-28 16:11:28 | COPIED    | zein-removebg-preview.png (94,651 B) disalin ke klaster 6..11")
    print("2026-09-28 16:15:40 | DELETED   | zein-removebg-preview.png dihapus dari root (marker 0xE5)")
    print("2026-09-28 16:16:18 | CREATED   | 'New Text Document.txt' dibuat di root directory")
    print("2026-09-28 16:16:24 | DELETED   | Disimpan sebagai link.txt (38 B, klaster 12) lalu dihapus")
    print("-" * 85)
    print("[+] Total Rekonstruksi Event: 14 Operasi Sistem Berkas Terpetakan Sempurna")

if __name__ == '__main__':
    show()
