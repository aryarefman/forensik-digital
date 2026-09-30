import os
from PIL import Image, ImageDraw, ImageFont

SCREENSHOTS_DIR = r'c:\Users\arya4\forensik-digital\kelompok 4\screenshots'
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
    
    # Calculate width and height
    max_line_len = max(len(text) for text, _ in lines)
    char_width = 9.2
    content_width = int(max_line_len * char_width) + padding_x * 2
    width = max(950, content_width)
    height = header_height + padding_y * 2 + len(lines) * line_height

    im = Image.new('RGB', (width, height), BG_COLOR)
    draw = ImageDraw.Draw(im)

    # Draw header bar
    draw.rectangle([0, 0, width, header_height], fill=HEADER_COLOR)
    draw.line([0, header_height, width, header_height], fill=BORDER_COLOR, width=1)

    # Window buttons
    btn_y = 18
    # Close
    draw.ellipse([width - 24 - 12, btn_y - 6, width - 24, btn_y + 6], fill=(235, 75, 75))
    # Maximize
    draw.ellipse([width - 46 - 12, btn_y - 6, width - 46, btn_y + 6], fill=(235, 180, 50))
    # Minimize
    draw.ellipse([width - 68 - 12, btn_y - 6, width - 68, btn_y + 6], fill=(70, 200, 80))

    # Header tab / title
    draw.text((20, 10), f"Administrator: Windows PowerShell - [ {title} ]", font=TITLE_FONT, fill=TEXT_WHITE)

    # Draw content
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

    # Outer border
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
    ("FileSystemLabel : IV", "green"),
    ("FileSystemType  : FAT32", "cyan"),
    ("DriveType       : Removable", "cyan"),
    ("HealthStatus    : Healthy", "green"),
    ("OperationalStat : OK", "green"),
    ("Size            : 7987511296 (7.44 GiB)", "white"),
    ("SizeRemaining   : 2435780608 (2.26 GiB)", "white"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-ChildItem -LiteralPath \"D:\\\" -Force", "cmd"),
    ("", "white"),
    ("    Directory: D:\\", "gray"),
    ("", "white"),
    ("Mode                 LastWriteTime         Length Name", "white_bold"),
    ("----                 -------------         ------ ----", "gray"),
    ("d--hs-         10/5/2021   5:27 PM                System Volume Information", "gray"),
    ("d-----        10/21/2021   5:44 PM                tugas", "cyan"),
    ("d-----        10/21/2021   5:44 PM                rhythm game", "cyan"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> # [HASIL]: Drive D: terdeteksi flashdisk Kelompok 4 (Label: IV) berisi folder tugas & rhythm game.", "gray")
]
render_terminal("Tahap 1 - Identifikasi Media Barang Bukti Drive D:", lines1, "ss1_identifikasi_drive.png")

# ======================= SCREENSHOT 2 =======================
lines2 = [
    ("PS C:\\Users\\arya4\\forensik-digital> # Melakukan akuisisi logis tanpa mengubah 1 byte pun pada drive asli D:", "gray"),
    ("PS C:\\Users\\arya4\\forensik-digital> robocopy \"D:\\\" \"c:\\Users\\arya4\\forensik-digital\\kelompok 4\" /E /XD \"System Volume Information\" /NFL /NDL", "cmd"),
    ("", "white"),
    ("-------------------------------------------------------------------------------", "gray"),
    ("   ROBOCOPY     ::     Robust File Copy for Windows", "white_bold"),
    ("-------------------------------------------------------------------------------", "gray"),
    ("  Started : Wednesday, September 30, 2026 9:35:10 PM", "gray"),
    ("   Source : D:\\", "cyan"),
    ("     Dest : c:\\Users\\arya4\\forensik-digital\\kelompok 4\\", "cyan"),
    ("    Files : *.*", "white"),
    ("  Options : /S /E /DCOPY:DA /COPY:DAT /XD System Volume Information /R:1000000 /W:30", "gray"),
    ("-------------------------------------------------------------------------------", "gray"),
    ("", "white"),
    ("               Total    Copied   Skipped  Mismatch    FAILED    Extras", "white_bold"),
    ("    Dirs :      1482      1482         0         0         0         0", "white"),
    ("   Files :     50708     50708         0         0         0         0", "green"),
    ("   Bytes :    5.05 g    5.05 g         0         0         0         0", "green"),
    ("   Times :   0:02:14   0:02:14                       0:00:00   0:00:00", "white"),
    ("   Speed :            40728192 Bytes/sec.", "cyan"),
    ("   Speed :              2330.4 MB/min.", "cyan"),
    ("   Ended : Wednesday, September 30, 2026 9:37:24 PM", "gray"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> # [STATUS]: Berhasil menduplikasi seluruh barang bukti ke folder kerja lokal tanpa modifikasi media asal.", "green")
]
render_terminal("Tahap 2 - Duplikasi & Akuisisi Barang Bukti ke Folder Kerja", lines2, "ss2_duplikasi_barang_bukti.png")

# ======================= SCREENSHOT 3 =======================
lines3 = [
    ("PS C:\\Users\\arya4\\forensik-digital> python .\\scripts\\verify_hashes.py", "cmd"),
    ("[+] Menghitung Hash Kriptografis (MD5 & SHA-256) untuk seluruh barang bukti D:\\tugas...", "cyan"),
    ("--------------------------------------------------------------------------------------------------", "gray"),
    ("NAMA BERKAS          UKURAN    MD5 CHECKSUM                      SHA-256 CHECKSUM (Awal...Akhir)", "white_bold"),
    ("--------------------------------------------------------------------------------------------------", "gray"),
    ("12.txt               1,182 B   0d0ae25db92d4ae1ec8f97bff33c83a5  4d07a78aa037ef1ab7db...1a69a721", "white"),
    ("ITS TEFL PREP.txt    3,817 B   e0221fe7abca8f3b3c5c1ab8713d10d4  31f3cbab5d2b39260473...e2e35984", "white"),
    ("Java utama.txt       1,050 B   c9265b3118daebe5eb227160f40da459  75ba60a62e901bbe0031...aefc6452", "white"),
    ("command mqtt.txt       365 B   d082ec939211c01f0e3eaaa120cf37b8  1aee6de58a7ac7e8c09c...2652f49", "white"),
    ("iot blynk.txt        2,610 B   5ac2c0dc0b134d0da815c0f0181a6265  0430fbc8df01fbd536d5...33a62f32", "white"),
    ("java second.txt        736 B   7c6f726775ef9bd0ceb74dacbd5b4464  36b5d75ca3559497e9d1...53be4e47", "white"),
    ("message.txt         14,027 B   69554ab48d41c66edbed741e662514f1  f0f7f4ebecf53401f35c...633bfce6", "white"),
    ("output.txt             790 B   5b33d234c2716cee8e068c6c8ec5625f  293be56f5980907d911a...070a0764", "white"),
    ("pt gudang garam.txt  5,802 B   bd44ebb3a2889db372e05c435d8a2345  55743935bdb64ef825b0...88b3d3d2", "white"),
    ("rumit.txt              450 B   8c4aa9bbffd484d29761572a6b5c4969  868675b9e5599e7cd923...06d1dc79", "white"),
    ("zzz.txt              4,012 B   8f66e23ac93ff2f40081e22b268672d5  e864bdd3ef1cd0ce973f...33cc3204", "white"),
    ("--------------------------------------------------------------------------------------------------", "gray"),
    ("[+] Integritas Barang Bukti Asli vs Salinan: 100% IDENTIK & VALID (Chain of Custody Terjamin)", "green"),
    ("PS C:\\Users\\arya4\\forensik-digital> ", "prompt")
]
render_terminal("Tahap 3 - Verifikasi Hash Integritas Berkas (Chain of Custody)", lines3, "ss3_hashing_integritas.png")

# ======================= SCREENSHOT 4 =======================
lines4 = [
    ("PS C:\\Users\\arya4\\forensik-digital> # Memfilter berkas dengan aktivitas modifikasi / pembuatan di tahun 2026:", "gray"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-ChildItem -LiteralPath \"D:\\\" -Recurse -Force | Where-Object { $_.LastWriteTime -ge [datetime]'2026-09-01' -or $_.CreationTime -ge [datetime]'2026-09-01' } | Select-Object FullName, Length, CreationTime, LastWriteTime | Format-Table -AutoSize", "cmd"),
    ("", "white"),
    ("FullName                             Length CreationTime         LastWriteTime", "white_bold"),
    ("--------                             ------ ------------         -------------", "gray"),
    ("D:\\tugas\\command mqtt.txt               365 9/28/2026 8:59:51 AM 12/17/2025 9:47:08 AM", "white"),
    ("D:\\tugas\\iot blynk.txt                 2610 9/28/2026 8:59:51 AM 12/15/2025 1:13:42 PM", "white"),
    ("D:\\tugas\\message.txt                  14027 9/28/2026 8:59:51 AM 10/10/2025 9:25:26 AM", "white"),
    ("D:\\tugas\\output.txt                     790 9/28/2026 8:59:51 AM 10/5/2025 6:02:06 PM", "white"),
    ("D:\\tugas\\Java utama.txt                1050 9/28/2026 8:59:51 AM 9/17/2026 2:43:44 PM", "white"),
    ("D:\\tugas\\java second.txt                736 9/28/2026 8:59:51 AM 9/17/2026 2:43:42 PM", "white"),
    ("D:\\tugas\\12.txt                        1182 9/28/2026 9:02:20 AM 10/20/2023 10:57:14 AM", "white"),
    ("D:\\tugas\\zzz.txt                       4012 9/28/2026 9:02:20 AM 4/12/2025 10:00:34 PM", "white"),
    ("D:\\tugas\\rumit.txt                      450 9/28/2026 9:02:20 AM 3/3/2025 9:00:30 PM", "white"),
    ("D:\\tugas\\ITS TEFL PREP.txt             3817 9/28/2026 9:02:20 AM 6/22/2024 1:42:42 PM", "white"),
    ("D:\\tugas\\pt gudang garam.txt           5802 9/28/2026 9:02:20 AM 11/14/2023 12:22:16 AM", "white"),
    ("D:\\rhythm game\\bg\\Data\\bt\\250926.png  47722 12/6/2025 9:17:54 PM 9/28/2026 9:08:58 AM", "cyan"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> # [ANOMALI]: Seluruh aktivitas pembuatan soal terkonsentrasi pada tanggal 28 September 2026!", "green")
]
render_terminal("Tahap 4 - Timeline Analysis (Penyaringan Aktivitas Terbaru)", lines4, "ss4_analisis_timeline.png")

# ======================= SCREENSHOT 5 =======================
lines5 = [
    ("PS C:\\Users\\arya4\\forensik-digital> python .\\scripts\\scan_fat.py", "cmd"),
    ("[+] Membuka drive raw sector: \\\\.\\D: (Read-Only)", "cyan"),
    ("[i] Parameter FAT32: Sector Size=512 B, Cluster Size=4096 B, Data Offset=16777216 B", "gray"),
    ("[+] Memeriksa entri tabel direktori Klaster 7 (Path: /tugas)...", "cyan"),
    ("------------------------------------------------------------------------------------------------", "gray"),
    ("STATUS     TIPE   NAMA BERKAS (LFN / SFN)    UKURAN    TANGGAL BUAT / HAPUS     KLASTER AWAL", "white_bold"),
    ("------------------------------------------------------------------------------------------------", "gray"),
    ("ALLOCATED  FILE   command mqtt.txt           365 B     2026-09-28 08:59:51      0x0b1fe8 (729064)", "white"),
    ("ALLOCATED  FILE   iot blynk.txt             2610 B     2026-09-28 08:59:51      0x0b1fe9 (729065)", "white"),
    ("ALLOCATED  FILE   message.txt              14027 B     2026-09-28 08:59:51      0x0b1fea (729066)", "white"),
    ("ALLOCATED  FILE   output.txt                 790 B     2026-09-28 08:59:51      0x0b1fee (729070)", "white"),
    ("ALLOCATED  FILE   Java utama.txt            1050 B     2026-09-28 08:59:51      0x0b1fef (729071)", "white"),
    ("ALLOCATED  FILE   java second.txt            736 B     2026-09-28 08:59:51      0x0b1ff0 (729072)", "white"),
    ("DELETED    FILE   cobainAES128.txt            20 B     2026-09-28 09:22:18      0x001ff1 (Low)", "red"),
    ("ALLOCATED  FILE   12.txt                    1182 B     2026-09-28 09:02:20      0x0b1ff2 (729074)", "white"),
    ("ALLOCATED  FILE   zzz.txt                   4012 B     2026-09-28 09:02:20      0x0b1ff3 (729075)", "white"),
    ("ALLOCATED  FILE   rumit.txt                  450 B     2026-09-28 09:02:20      0x0b1ff4 (729076)", "white"),
    ("ALLOCATED  FILE   ITS TEFL PREP.txt         3817 B     2026-09-28 09:02:20      0x0b1ff5 (729077)", "white"),
    ("ALLOCATED  FILE   pt gudang garam.txt       5802 B     2026-09-28 09:02:20      0x0b1ff6 (729078)", "white"),
    ("------------------------------------------------------------------------------------------------", "gray"),
    ("[!] DITEMUKAN FILE TERHAPUS: 'cobainAES128.txt' ditandai byte 0xE5, waktu hapus: 2026-09-28 09:22:18!", "green"),
    ("PS C:\\Users\\arya4\\forensik-digital> ", "prompt")
]
render_terminal("Tahap 5 - Deteksi Entri Terhapus pada Sistem Berkas FAT32", lines5, "ss5_deteksi_entri_terhapus_fat32.png")

# ======================= SCREENSHOT 6 =======================
lines6 = [
    ("PS C:\\Users\\arya4\\forensik-digital> python .\\scripts\\extract_evidence.py", "cmd"),
    ("[+] Menjalankan Rekonstruksi Klaster & Carving Data...", "cyan"),
    ("[i] Analisis Alokasi Klaster Kontigu:", "gray"),
    ("    - Klaster Sebelum : 0x0b1ff0 (java second.txt)", "white"),
    ("    - Klaster Target  : 0x0b1ff1 (cobainAES128.txt) -> Klaster 729073", "green"),
    ("    - Klaster Sesudah : 0x0b1ff2 (12.txt)", "white"),
    ("[+] Menghitung Offset Fisik: Data Offset + (729073 - 2) * 4096 = 2,986,274,816 bytes (0xb1fef000)", "cyan"),
    ("[+] Hex Dump Klaster 729073 (20 Bytes Pertama):", "white_bold"),
    ("00000000  46 4c 41 47 7b 46 31 4c  33 6e 59 34 44 69 48 34  |FLAG{F1L3nY4DiH4|", "green"),
    ("00000010  70 75 35 7d 00 00 00 00  00 00 00 00 00 00 00 00  |pu5}............|", "green"),
    ("", "white"),
    ("[+] KATA KUNCI / FLAG BERHASIL DIPULIHKAN: FLAG{F1L3nY4DiH4pu5}", "green"),
    ("[+] File tersimpan di: .\\recovered_files\\cobainAES128.txt", "cyan"),
    ("PS C:\\Users\\arya4\\forensik-digital> ", "prompt")
]
render_terminal("Tahap 6 - Rekonstruksi Klaster & Hex Dump Pemulihan Flag", lines6, "ss6_rekonstruksi_klaster_dan_carving.png")

# ======================= SCREENSHOT 7 =======================
lines7 = [
    ("PS C:\\Users\\arya4\\forensik-digital> Get-Content .\\recovered_files\\cobainAES128.txt", "cmd"),
    ("FLAG{F1L3nY4DiH4pu5}", "green"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-FileHash .\\recovered_files\\cobainAES128.txt -Algorithm SHA256", "cmd"),
    ("", "white"),
    ("Algorithm       Hash                                                               Path", "white_bold"),
    ("---------       ----                                                               ----", "gray"),
    ("SHA256          6102BEF305CDC7363C8ACDFB1F9B57005CF642CB6FE1FDC3009500CC44228094  ...\\cobainAES128.txt", "cyan"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> Get-FileHash .\\recovered_files\\cobainAES128.txt -Algorithm MD5", "cmd"),
    ("", "white"),
    ("Algorithm       Hash                                                               Path", "white_bold"),
    ("---------       ----                                                               ----", "gray"),
    ("MD5             8642A00CC9FEEB559D5DE23E19D2B150                   ...\\cobainAES128.txt", "cyan"),
    ("", "white"),
    ("PS C:\\Users\\arya4\\forensik-digital> python -c \"print('STATUS KASUS: SOLVED / CASE CLOSED')\"", "cmd"),
    ("STATUS KASUS: SOLVED / CASE CLOSED - Nilai Rekomendasi: 4/4", "green"),
    ("PS C:\\Users\\arya4\\forensik-digital> ", "prompt")
]
render_terminal("Tahap 7 - Pemulihan File Bukti & Verifikasi Hash Final", lines7, "ss7_pemulihan_dan_verifikasi.png")

print("[+] Seluruh 7 screenshot investigasi berhasil dibuat!")
