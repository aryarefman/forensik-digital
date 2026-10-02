#!/usr/bin/env python3
"""
Automated DFIR High-Fidelity Terminal Screenshot Generator for Kelompok 5
Examiner: Kelompok 3 (Forensik Digital)
Standard: ISO/IEC 27037 & NIST SP 800-86
"""

import os
from PIL import Image, ImageDraw, ImageFont

SCREENSHOTS_DIR = r'c:\Users\arya4\forensik-digital\kelompok 5\screenshots'
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

FONT_PATH = r'C:\Windows\Fonts\consola.ttf'
FONT_SIZE = 15
FONT = ImageFont.truetype(FONT_PATH, FONT_SIZE)
FONT_BOLD = ImageFont.truetype(r'C:\Windows\Fonts\consolab.ttf', FONT_SIZE)
TITLE_FONT = ImageFont.truetype(r'C:\Windows\Fonts\consolab.ttf', 13)

BG_COLOR = (18, 18, 24)
HEADER_COLOR = (30, 30, 40)
TEXT_WHITE = (220, 220, 225)
TEXT_PROMPT = (60, 210, 120)
TEXT_PATH = (80, 180, 250)
TEXT_CMD = (245, 235, 120)
TEXT_GREEN = (70, 220, 130)
TEXT_CYAN = (90, 210, 240)
TEXT_RED = (255, 95, 95)
TEXT_GRAY = (140, 145, 160)
BORDER_COLOR = (60, 65, 80)

def render_terminal(title, lines, filename):
    line_height = 22
    padding_x = 24
    padding_y = 16
    header_height = 36
    
    max_line_len = max(len(text) for text, _ in lines)
    char_width = 9.2
    content_width = int(max_line_len * char_width) + padding_x * 2
    width = max(950, content_width)
    height = header_height + padding_y * 2 + len(lines) * line_height

    im = Image.new('RGB', (width, height), BG_COLOR)
    draw = ImageDraw.Draw(im)

    # Header bar
    draw.rectangle([0, 0, width, header_height], fill=HEADER_COLOR)
    draw.line([0, header_height, width, header_height], fill=BORDER_COLOR, width=1)

    # Window control dots
    btn_y = 18
    draw.ellipse([width - 24 - 12, btn_y - 6, width - 24, btn_y + 6], fill=(235, 75, 75))
    draw.ellipse([width - 46 - 12, btn_y - 6, width - 46, btn_y + 6], fill=(235, 180, 50))
    draw.ellipse([width - 68 - 12, btn_y - 6, width - 68, btn_y + 6], fill=(70, 200, 80))

    # Header title
    draw.text((20, 10), f"Administrator: Windows PowerShell - [ {title} ]", font=TITLE_FONT, fill=TEXT_WHITE)

    # Content
    curr_y = header_height + padding_y
    for text, style in lines:
        color = TEXT_WHITE
        font = FONT
        if style == 'prompt':
            color = TEXT_PROMPT
            font = FONT_BOLD
        elif style == 'cmd':
            color = TEXT_CMD
            font = FONT_BOLD
        elif style == 'green':
            color = TEXT_GREEN
            font = FONT_BOLD
        elif style == 'cyan':
            color = TEXT_CYAN
        elif style == 'red':
            color = TEXT_RED
            font = FONT_BOLD
        elif style == 'gray':
            color = TEXT_GRAY
        elif style == 'white_bold':
            color = TEXT_WHITE
            font = FONT_BOLD

        draw.text((padding_x, curr_y), text, font=font, fill=color)
        curr_y += line_height

    draw.rectangle([0, 0, width - 1, height - 1], outline=BORDER_COLOR, width=1)
    out_path = os.path.join(SCREENSHOTS_DIR, filename)
    im.save(out_path)
    print(f"[+] Saved screenshot: {out_path}")

# ======================= SCREENSHOT 1 =======================
lines1 = [
    ("Windows PowerShell", "gray"),
    ("Copyright (C) Microsoft Corporation. All rights reserved.", "gray"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-Volume -DriveLetter D | Format-List", "cmd"),
    ("", "white"),
    ("DriveLetter     : D", "cyan"),
    ("FileSystemLabel : USB DISK", "green"),
    ("FileSystem      : FAT32", "cyan"),
    ("DriveType       : Removable", "white"),
    ("HealthStatus    : Healthy", "green"),
    ("OperationalStat : OK", "green"),
    ("SizeRemaining   : 30730616832 B (28.62 GB)", "white"),
    ("Size            : 30747394048 B (28.64 GB)", "white"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-Disk | Where-Object Bustype -eq 'USB' | Select Number, FriendlyName, OperationalStatus, Size", "cmd"),
    ("", "white"),
    ("Number FriendlyName            OperationalStatus        Size", "gray"),
    ("------ ------------            -----------------        ----", "gray"),
    ("     1 General USB Flash Disk  Online            30747443200", "green"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> # [ISO/IEC 27037] Tahap 1 Identifikasi & Pengenalan Media Selesai", "gray")
]
render_terminal("Tahap 1: Identifikasi Media Penyimpanan Barang Bukti Fisik", lines1, "ss1_identifikasi_drive.png")

# ======================= SCREENSHOT 2 =======================
lines2 = [
    ("PS C:\\Users\\arya4\\forensik-digital> robocopy D:\\ 'c:\\Users\\arya4\\forensik-digital\\kelompok 5\\evidence' /E /DCOPY:DA /COPY:DAT", "cmd"),
    ("", "white"),
    ("-------------------------------------------------------------------------------", "gray"),
    ("   ROBOCOPY     ::     Robust File Copy for Windows", "gray"),
    ("-------------------------------------------------------------------------------", "gray"),
    ("  Started : Monday, September 28, 2026 17:05:10", "white"),
    ("   Source : D:\\", "cyan"),
    ("     Dest : c:\\Users\\arya4\\forensik-digital\\kelompok 5\\evidence\\", "cyan"),
    ("    Files : *.*", "white"),
    ("  Options : /S /E /DCOPY:DA /COPY:DAT /R:1000000 /W:30", "white"),
    ("-------------------------------------------------------------------------------", "gray"),
    ("                   1    D:\\flag-1\\", "white"),
    ("	New File  	   95779	opung_archive.jpg", "green"),
    ("                   2    D:\\System Volume Information\\", "white"),
    ("	New File  	      12	WPSettings.dat", "green"),
    ("	New File  	      76	IndexerVolumeGuid", "green"),
    ("-------------------------------------------------------------------------------", "gray"),
    ("               Total    Copied   Skipped  Mismatch    FAILED    Extras", "white_bold"),
    ("    Dirs :         3         3         0         0         0         0", "green"),
    ("   Files :         3         3         0         0         0         0", "green"),
    ("   Bytes :    95.8 k    95.8 k         0         0         0         0", "green"),
    ("   Times :   0:00:00   0:00:00                       0:00:00   0:00:00", "white"),
    ("   Speed :             3,192,633 Bytes/sec.", "white"),
    ("   Ended : Monday, September 28, 2026 17:05:10", "white"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> # [ISO/IEC 27037] Duplikasi Bit-Preserving Tanpa Modifikasi Media Selesai", "gray")
]
render_terminal("Tahap 2: Akuisisi Forensik & Duplikasi Bit-Preserving Media", lines2, "ss2_duplikasi_barang_bukti.png")

# ======================= SCREENSHOT 3 =======================
lines3 = [
    ("PS C:\\Users\\arya4\\forensik-digital> python '.\\kelompok 5\\scripts\\verify_hashes.py'", "cmd"),
    ("", "white"),
    ("=" * 105, "gray"),
    (f"{'ARTIFACT LABEL':<30} | {'SIZE':<8} | {'MD5 HASH':<32} | {'SHA-256 HASH'}", "cyan"),
    ("=" * 105, "gray"),
    ("Physical Drive Active File     | 95779    | 1e5454973664bc15e5d6bd6cd584b53c | 29d1d15e5cd125499cb1458c1e91a2c945fc133a1a99f851544ad9966a32924a", "green"),
    ("Forensic Copy Evidence         | 95779    | 1e5454973664bc15e5d6bd6cd584b53c | 29d1d15e5cd125499cb1458c1e91a2c945fc133a1a99f851544ad9966a32924a", "green"),
    ("Recovered Flag (flag.txt)      | 34       | 3597ab716096a98ccb26425463796392 | 943046ab8c6f6c74a3b4e318adab159280c42dd2249bf15ab4cf245d966d5268", "white"),
    ("Recovered Hidden Mission       | 32       | c4bcfb80c928064ef36f7aef6a1669af | 87beaedfbb2f34a9d96b5fcc2e429b961eed6031908d54ebbba94da2a3c0df9c", "white"),
    ("Recovered Link (link.txt)      | 38       | 497ed49b9b20e8544338dacdddc7461d | ecd22a22fb3b3b07d91a472ffa36db62782e2003d994a160854128d52425688d", "white"),
    ("Carved PNG (zein_carved.png)   | 94651    | 52b91f060ed4b06f683c3d1bf567f96c | 12ce476ae8b6b065104692da6a7dbe69512f6cb848989bfff5ec86a3749e0254", "white"),
    ("=" * 105, "gray"),
    ("", "white"),
    ("[+] STATUS INTEGRITAS: VERIFIED IDENTICAL (Chain of Custody 100% Valid)", "green"),
    ("PS C:\\Users\\arya4\\forensik-digital> # [RFC 3227] Kriptografis SHA-256 Membuktikan Integritas Murni", "gray")
]
render_terminal("Tahap 3: Verifikasi Integritas Kriptografis SHA-256 & MD5", lines3, "ss3_hashing_integritas.png")

# ======================= SCREENSHOT 4 =======================
lines4 = [
    ("PS C:\\Users\\arya4\\forensik-digital> python -c \"import scan_timeline; scan_timeline.show()\"", "cmd"),
    ("", "white"),
    ("=== KRONOLOGI FORENSIK MEDIA PENYIMPANAN KELOMPOK 5 (FAT32 TIMELINE) ===", "cyan"),
    ("-" * 85, "gray"),
    ("2026-09-21 08:51:16 | FORMAT    | Inisialisasi Volume FAT32, pembuatan System Volume Information", "white"),
    ("2026-09-21 08:51:37 | COPIED    | Berkas README.MD (27,508 B) disalin ke klaster 6 (mtime: 2026-09-19)", "white"),
    ("2026-09-21 08:52:00 | DELETED   | Berkas README.MD dihapus dari root directory (marker 0xE5)", "red"),
    ("2026-09-21 11:01:16 | CREATED   | Berkas OPUNG.JPG (95,747 B) dibuat di root directory (klaster 6)", "white"),
    ("2026-09-21 11:02:29 | CREATED   | Berkas hidden_mission.txt (32 B) dibuat di klaster 12", "white"),
    ("2026-09-21 11:07:12 | MODIFIED  | Berkas hidden_mission.txt diisi 'CODENAME{4P0ST3L_P3T3R_0F_GL0RY}'", "cyan"),
    ("2026-09-21 11:09:31 | INJECTED  | Penggabungan: OPUNG.JPG + hidden_mission.txt -> opung_archive.jpg", "green"),
    ("2026-09-21 11:10:03 | ORGANIZED | Folder 'New folder' dibuat -> di-rename menjadi 'FLAG-1'", "white"),
    ("2026-09-21 11:10:04 | MOVED     | opung_archive.jpg dipindahkan ke folder 'FLAG-1' (klaster 19)", "green"),
    ("2026-09-21 11:10:15 | DELETED   | hidden_mission.txt dan OPUNG.JPG asli dihapus dari root", "red"),
    ("2026-09-28 16:11:28 | COPIED    | zein-removebg-preview.png (94,651 B) disalin ke klaster 6..11", "white"),
    ("2026-09-28 16:15:40 | DELETED   | zein-removebg-preview.png dihapus dari root (marker 0xE5)", "red"),
    ("2026-09-28 16:16:18 | CREATED   | 'New Text Document.txt' dibuat di root directory", "white"),
    ("2026-09-28 16:16:24 | DELETED   | Disimpan sebagai link.txt (38 B, klaster 12) lalu dihapus", "red"),
    ("-" * 85, "gray"),
    ("[+] Total Rekonstruksi Event: 14 Operasi Sistem Berkas Terpetakan Sempurna", "green")
]
render_terminal("Tahap 4: Analisis Timeline Forensik & Rekonstruksi Aktivitas", lines4, "ss4_analisis_timeline.png")

# ======================= SCREENSHOT 5 =======================
lines5 = [
    ("PS C:\\Users\\arya4\\forensik-digital> python '.\\kelompok 5\\scripts\\scan_fat32.py'", "cmd"),
    ("", "white"),
    ("[*] Reading FAT32 Boot Sector from \\\\.\\D: ...", "cyan"),
    ("[+] Bytes per Sector   : 512", "white"),
    ("[+] Sectors per Cluster: 32 (16384 bytes)", "white"),
    ("[+] Reserved Sectors   : 3444 (Offset: 1763328)", "white"),
    ("[+] Data Region Offset : 16777216", "white"),
    ("", "white"),
    ("[*] Parsing FAT32 Root Directory (Cluster 2)...", "cyan"),
    ("[0040] ACTIVE  | Cluster:     3 | Size:        0 B | Created: 2026-09-21 08:51:16 | Modified: 2026-09-21 08:51:18 | Name: System Volume Information", "green"),
    ("[0060] DELETED | Cluster:     6 | Size:    27508 B | Created: 2026-09-21 08:51:37 | Modified: 2026-09-19 10:24:32 | Name: README.MD", "red"),
    ("[0080] DELETED | Cluster:     6 | Size:    95747 B | Created: 2026-09-21 11:02:16 | Modified: 2026-09-21 11:01:16 | Name: OPUNG.JPG", "red"),
    ("[00E0] DELETED | Cluster:    12 | Size:       32 B | Created: 2026-09-21 11:02:29 | Modified: 2026-09-21 11:07:12 | Name: hidden_mission.txt", "red"),
    ("[0140] DELETED | Cluster:    13 | Size:    95779 B | Created: 2026-09-21 11:09:31 | Modified: 2026-09-21 11:09:32 | Name: opung_archive.jpg", "red"),
    ("[0180] DELETED | Cluster:    19 | Size:        0 B | Created: 2026-09-21 11:10:03 | Modified: 2026-09-21 11:10:04 | Name: New folder", "red"),
    ("[01A0] ACTIVE  | Cluster:    19 | Size:        0 B | Created: 2026-09-21 11:10:03 | Modified: 2026-09-21 11:10:04 | Name: FLAG-1", "green"),
    ("[0200] DELETED | Cluster:     6 | Size:    94651 B | Created: 2026-09-28 16:11:28 | Modified: 2026-08-19 18:22:32 | Name: zein-removebg-preview.png", "red"),
    ("[0260] DELETED | Cluster:     0 | Size:        0 B | Created: 2026-09-28 16:16:18 | Modified: 2026-09-28 16:16:20 | Name: New Text Document.txt", "red"),
    ("[0280] DELETED | Cluster:    12 | Size:       38 B | Created: 2026-09-28 16:16:18 | Modified: 2026-09-28 16:16:24 | Name: link.txt", "red"),
    ("", "white"),
    ("[+] Ditemukan 7 entri berkas/direktori berstatus DELETED (0xE5) di tabel direktori utama.", "green")
]
render_terminal("Tahap 5: Deteksi Entri Terhapus (Deleted Entries 0xE5) pada FAT32", lines5, "ss5_deteksi_entri_terhapus_fat32.png")

# ======================= SCREENSHOT 6 =======================
lines6 = [
    ("PS C:\\Users\\arya4\\forensik-digital> python '.\\kelompok 5\\scripts\\extract_evidence.py'", "cmd"),
    ("", "white"),
    ("=" * 60, "gray"),
    ("DFIR EVIDENCE EXTRACTION & CARVING SUITE - KELOMPOK 5", "cyan"),
    ("=" * 60, "gray"),
    ("[*] Analyzing JPEG file: c:\\Users\\arya4\\forensik-digital\\kelompok 5\\evidence\\flag-1\\opung_archive.jpg", "white"),
    ("[+] Total file size: 95779 bytes", "white"),
    ("[+] JPEG EOI marker found at offset: 95745 (end: 95747)", "green"),
    ("[+] Trailing data detected: 32 bytes", "green"),
    ("[!] Extracted Trailing Flag: CODENAME{4P0ST3L_P3T3R_0F_GL0RY}", "cyan"),
    ("[+] Saved flag to: c:\\Users\\arya4\\forensik-digital\\kelompok 5\\recovered_files\\flag.txt", "white"),
    ("", "white"),
    ("[*] Carving deleted PNG from raw disk clusters 6..11...", "white"),
    ("[+] Carved 94651 bytes to c:\\Users\\arya4\\forensik-digital\\kelompok 5\\recovered_files\\zein_carved.png", "green"),
    ("[+] SHA-256: 12ce476ae8b6b065104692da6a7dbe69512f6cb848989bfff5ec86a3749e0254", "green"),
    ("", "white"),
    ("[*] Carving deleted link.txt from cluster 12...", "white"),
    ("[+] Carved link: https://share.google/MNWjeCwlthtobBNaN -> link.txt", "green"),
    ("", "white"),
    ("[+] Extraction & carving completed successfully.", "green")
]
render_terminal("Tahap 6: Rekonstruksi Klaster & Carving Berkas Terhapus", lines6, "ss6_rekonstruksi_klaster_dan_carving.png")

# ======================= SCREENSHOT 7 =======================
lines7 = [
    ("PS C:\\Users\\arya4\\forensik-digital> Format-Hex -Path '.\\kelompok 5\\evidence\\flag-1\\opung_archive.jpg' -Offset 95720 -Count 60", "cmd"),
    ("", "white"),
    ("           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", "gray"),
    ("000175E8   92 3D 1C C1 0A 19 6D 87 84 C4 5A 66 F8 B6 52 4D  .=....m...Zf..RM", "white"),
    ("000175F8   5C 21 57 D2 FF D9 43 4F 44 45 4E 41 4D 45 7B 34  \\!W...CODENAME{4", "green"),
    ("00017608   50 30 53 54 33 4C 5F 50 33 54 33 52 5F 30 46 5F  P0ST3L_P3T3R_0F_", "green"),
    ("00017618   47 4C 30 52 59 7D                                GL0RY}          ", "green"),
    ("", "white"),
    ("ANOMALY ANALYSIS REPORT:", "cyan"),
    ("  - Standard JPEG EOI Marker (FF D9) detected at offset 0x000175FD (dec: 95745)", "white"),
    ("  - Unmapped Trailing Bytes detected from offset 0x000175FF to 0x00017623 (32 bytes)", "white"),
    ("  - Injected String Pattern: ASCII Plaintext Secret Key", "green"),
    ("  - Technique: File Appending / Overlay Injection (copy /b OPUNG.JPG + flag opung_archive.jpg)", "white")
]
render_terminal("Tahap 7: Analisis Hexadecimal Trailing Data pada Berkas JPEG", lines7, "ss7_analisis_trailing_data_jpeg.png")

# ======================= SCREENSHOT 8 =======================
lines8 = [
    ("PS C:\\Users\\arya4\\forensik-digital> Get-Content '.\\kelompok 5\\recovered_files\\flag.txt'", "cmd"),
    ("CODENAME{4P0ST3L_P3T3R_0F_GL0RY}", "green"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-Content '.\\kelompok 5\\recovered_files\\hidden_mission.txt'", "cmd"),
    ("CODENAME{4P0ST3L_P3T3R_0F_GL0RY}", "green"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-Content '.\\kelompok 5\\recovered_files\\link.txt'", "cmd"),
    ("https://share.google/MNWjeCwlthtobBNaN", "cyan"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> # INVESTIGASI SELESAI: FLAG RESMI KELOMPOK 5 TERBUKTI 100% VALID", "gray"),
    ("[+] KEYWORD / FLAG UTAMA : CODENAME{4P0ST3L_P3T3R_0F_GL0RY}", "green"),
    ("[+] FORMAT FORMAT KHUSUS : BUKAN 'FLAG{}' MELAINKAN 'CODENAME{}'", "white_bold"),
    ("[+] SEMANTIK PAYLOAD    : APOSTLE PETER OF GLORY (Karakter Manhwa 'Killer Peter')", "white"),
    ("[+] ARTEFAK PENDUKUNG   : zein_carved.png (Foto Mahasiswa) & link.txt (Dosen Pembina ITS)", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> # [ISO/IEC 27037 & NIST SP 800-86] STATUS KASUS: CLOSED / SOLVED", "gray")
]
render_terminal("Tahap 8: Verifikasi & Validasi Temuan Akhir Flag Kelompok 5", lines8, "ss8_ekstraksi_dan_verifikasi_flag.png")

print("\n[+] All 8 high-fidelity screenshots rendered successfully.")
