# 🔍 Digital Forensics Investigation Repository
### Mata Kuliah: Forensik Digital | Kasus Barang Bukti: Kelompok 1, Kelompok 2, Kelompok 4, & Kelompok 5
### Tim Penyelidik: **Kelompok 3** | Status Kasus: **`ALL CASES CLOSED (100% SOLVED)`**

---

<p align="center">
  <img src="https://img.shields.io/badge/STANDARDS-ISO%2FIEC%2027037%20%7C%20NIST%20SP%20800--86-blue?style=for-the-badge" alt="Standards">
  <img src="https://img.shields.io/badge/STATUS-ALL%20CASES%20SOLVED-success?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/INTEGRITY-READ--ONLY%20PRESERVED-green?style=for-the-badge" alt="Integrity">
  <img src="https://img.shields.io/badge/EXAMINER-KELOMPOK%203-purple?style=for-the-badge" alt="Examiner">
</p>

---

## 📌 Executive Overview

Repositori ini memuat seluruh berkas dokumentasi investigasi, rantai bukti (*chain of custody*), skrip analisis forensik, tangkapan layar terminal autentik, serta artefak bukti hasil pemulihan digital forensics dari seluruh kasus barang bukti yang ditangani oleh **Kelompok 3**:
1. **Kasus Kelompok 1**: NVMe/SSD Storage Media Volume `CONFIDENTIAL` (Skema GPT, Format Linux `ext4`, Unallocated Sektor 100)
2. **Kasus Kelompok 2**: Logical Files Autopsy Ingest (MIME Mismatch `KONMED 5.png`)
3. **Kasus Kelompok 4**: USB Flashdisk Volume `IV` (Kapasitas: 7.44 GB, FAT32)
4. **Kasus Kelompok 5**: USB Flashdisk Volume `USB DISK` (Kapasitas: 28.64 GB, FAT32)

Seluruh investigasi diselesaikan secara independen oleh **Kelompok 3** dengan memenuhi standar kepatuhan internasional **ISO/IEC 27037:2012** (*Digital Evidence Handling Techniques*), **NIST SP 800-86**, dan **RFC 3227**. Seluruh barang bukti fisik asli dijaga dalam status *strictly read-only* tanpa modifikasi 1 byte pun.

---

## 🏆 Ringkasan Hasil Temuan Bukti (Flags Solved)

| Subjek Kasus | Target Bukti | Teknik Anti-Forensik | Format Penanda | Nilai Key / Flag | Makna Semantik |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **Kelompok 1** | Kasus 1 | GPT Unallocated Sektor 100 + XOR 0x5A | `FLAG{...}` | `FLAG{anti_forensics_reimage_cover_story_2026}` | *"Anti Forensics Reimage Cover Story 2026"* (Alibi Tiket IT) |
| **Kelompok 2** | Kasus 2 | Extension / MIME Mismatch (`text/plain` as `.png`) | `FLAG{...}` | `FLAG{F0r3ns1k_K3l0mp0k_2}` | *"Forensik Kelompok 2"* |
| **Kelompok 4** | Kasus 3 | FAT32 Directory Deletion (`0xE5`) | `FLAG{...}` | `FLAG{F1L3nY4DiH4pu5}` | *"File-nya Dihapus"* |
| **Kelompok 4** | Kasus 4 | OpenStego LSB Steganography | `FLAG{...}` | `FLAG{k4t4H1kar1_0K3}` | *"Kata Hikari OKE"* |
| **Kelompok 5** | Kasus 5 | JPEG EOI Trailing Data Overlay | `CODENAME{...}` | `CODENAME{4P0ST3L_P3T3R_0F_GL0RY}` | *"Apostle Peter of Glory"* (Manhwa Killer Peter) |

> 📑 **Akses Laporan Resmi DFIR Lengkap**:  
> 👉 [**Laporan Investigasi Forensik Kelompok 1 (DFIR-2026-FD-KEL1)**](./kelompok%201/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_1.md)  
> 👉 [**Laporan Investigasi Forensik Kelompok 2 (DFIR-2026-FD-KEL2)**](./kelompok%202/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_2.md)  
> 👉 [**Laporan Investigasi Forensik Kelompok 4 (DFIR-2026-FD-KEL4)**](./kelompok%204/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md)  
> 👉 [**Laporan Investigasi Forensik Kelompok 5 (DFIR-2026-FD-KEL5)**](./kelompok%205/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_5.md)

---

## 📑 Perbandingan Karakteristik Media Barang Bukti

| Parameter Teknis | Kelompok 1 | Kelompok 2 | Kelompok 4 | Kelompok 5 |
| :--- | :--- | :--- | :--- | :--- |
| **Nomor Kasus DFIR** | `DFIR-2026-FD-KEL1-001` | `DFIR-2026-FD-KEL2-001` | `DFIR-2026-FD-KEL4-001` | `DFIR-2026-FD-KEL5-001` |
| **Label Sumber** | `CONFIDENTIAL` | `KEBELET PSDM` | `IV` | `USB DISK` |
| **Tipe Perangkat** | Removable NVMe/SSD Media | Logical Files | Removable USB Media | Removable USB Media |
| **Sistem Berkas** | Linux `ext4` (Skema GPT) | Windows Logical Set | FAT32 (`MSDOS5.0`) | FAT32 (`MSDOS5.0`) |
| **Ukuran Sektor** | 512 Bytes | N/A | 512 Bytes | 512 Bytes |
| **Alat Investigasi** | PowerShell + Python | Autopsy 4.23.1 | PowerShell + Python | PowerShell + Python |
| **Jumlah Flag** | 1 Flag (`FLAG{...}`) | 1 Flag (`FLAG{...}`) | 2 Flag (`FLAG{...}`) | 1 Flag (`CODENAME{...}`) |
| **Artefak Kunci** | `000000034`, `secret_evidence.txt` | `KONMED 5.png` | `cobainAES128.txt`, `250926.png` | `opung_archive.jpg` |

---

## 🛠️ Alur Metodologi Forensik Digital (ISO/IEC 27037)

```
[1. IDENTIFIKASI MEDIA] ────> [2. AKUISISI / MOUNT RO] ────> [3. VERIFIKASI HASH SHA-256]
                                                                    │
┌───────────────────────────────────────────────────────────────────┘
▼
[4. ANALISIS TIMELINE/LOG] ─> [5. PARSING ENTRI / CARVING] ─> [6. DEOBFUSKASI / DEKRIPSI]
                                                                    │
┌───────────────────────────────────────────────────────────────────┘
▼
[7. REKONSTRUKSI ARTEFAK] ──> [8. VALIDASI PAYLOAD]    ────> [9. LAPORAN RESMI DFIR]
```

### Rangkuman Kasus Kelompok 1:
1. Pemeriksaan media drive fisik ext4 via terminal PowerShell secara *read-only*.
2. Analisis audit trail pada `/var/log/sys_audit.log` mendeteksi reservasi tersembunyi `Sector offset 0x0000C800 reserved. Mask 0x5A applied` (Sektor 100).
3. Ekspor area *unallocated space* GPT (sektor 34 s.d. 2047, berkas `000000034`).
4. Dekripsi XOR satu byte (`0x5A`) pada offset 33.792 dan perbaikan magic header `DE AD BE EF` menjadi format baku ZIP `50 4B 03 04`.
5. Ekstraksi arsip `payload.zip` memulihkan dokumen rahasia `secret_evidence.txt` yang memuat `FLAG{anti_forensics_reimage_cover_story_2026}`.

### Rangkuman Kasus Kelompok 2:
1. Penambahan data source `KEBELET PSDM` sebagai Logical Files pada Autopsy.
2. Eksekusi ingest modules File Type Identification dan Extension Mismatch Detector.
3. Analisis MIME Type menemukan 1 anomali file teks `KONMED 5.png` (25 B) yang berisikan `FLAG{F0r3ns1k_K3l0mp0k_2}`.

### Rangkuman Kasus Kelompok 4:
1. Rekonstruksi tabel direktori `/tugas` mendeteksi berkas terhapus `cobainAES128.txt` pada Klaster `729073`.
2. Carving sektor mentah memulihkan Flag 1: `FLAG{F1L3nY4DiH4pu5}`.
3. Analisis direktori aset `rhythm game` menemukan gambar ganjil `250926.png`. Bitstream parsing mendeteksi signature OpenStego RandomLSB tanpa password (`blank password`).
4. Dekripsi AES-128 PBE dan dekompresi GZIP memulihkan Flag 2: `FLAG{k4t4H1kar1_0K3}`.

### Rangkuman Kasus Kelompok 5:
1. Pemeriksaan volume menemukan folder aktif `FLAG-1` berisi berkas gambar `opung_archive.jpg`.
2. Analisis heksadesimal mendeteksi 32 byte data tambahan (*trailing data*) tepat setelah penanda akhir berkas JPEG (*End-of-Image* / EOI marker `FF D9` pada offset `95.745`).
3. Ekstraksi langsung memulihkan flag: `CODENAME{4P0ST3L_P3T3R_0F_GL0RY}`.
4. Parsing tabel direktori root FAT32 mendeteksi dokumen terhapus `hidden_mission.txt` (sumber flag), foto mahasiswa terhapus `zein-removebg-preview.png` (klaster 6..11), dan `link.txt` yang merujuk pada Google Images profil dosen ITS Dr. Hatma Suryotrisongko.

---

## 🔒 Matriks Hash Integritas Kriptografis (Chain of Custody)

| ID Bukti | Nama Artefak | Ukuran | Checksum MD5 | Checksum SHA-256 |
| :---: | :--- | :---: | :--- | :--- |
| **K1-F1** | `kelompok 1/recovered_files/secret_evidence.txt` | 45 B | `caf13df7266c350dc241698b3bd23a6a` | `40B13F2D38B96A1BAFD0451E7E91784D48141529EF6E544DA1DDE80E68AD5013` |
| **K1-ZIP**| `kelompok 1/recovered_files/payload.zip` | 181 B | `83d740be819b2c3dabe47ddefd6a7e7c` | `38F480F87FB8786C0BACA12DBE6BF13C541274F2BB9D2CA8899F9BCB79BF4740` |
| **K1-DMP**| `kelompok 1 unallocated space (000000034)` | 1.031.168 B | `2a87156fd24800d8cad6e6d3341df02e` | `E440030D05AA38E45519FE670869B01F1FCBE48939B18DA991AB9E402322C629` |
| **K2-F1** | `kelompok 2/recovered_files/KONMED_5.txt` | 25 B | `cfaad02f06aa3b3f27fbe510ad6e584f` | `f5885c3fc6b63ca0c7974e645719ae55e7146d953ce3bce3f64c67ec982ee33c` |
| **K4-F1** | `kelompok 4/recovered_files/cobainAES128.txt` | 20 B | `8642a00cc9feeb559d5de23e19d2b150` | `6102bef305cdc7363c8acdfb1f9b57005cf642cb6fe1fdc3009500cc44228094` |
| **K4-F2** | `kelompok 4/recovered_files/stego_flag2.txt` | 20 B | `5bc41b9264b94ba9d321c9a3eab88be2` | `df5f6ee3d0161a1f58a51a0373652cfce57451305c5a897bb903de756963bb6a` |
| **K5-F1** | `kelompok 5/recovered_files/flag.txt` | 34 B | `3597ab716096a98ccb26425463796392` | `943046ab8c6f6c74a3b4e318adab159280c42dd2249bf15ab4cf245d966d5268` |
| **K5-HM** | `kelompok 5/recovered_files/hidden_mission.txt` | 32 B | `c4bcfb80c928064ef36f7aef6a1669af` | `87beaedfbb2f34a9d96b5fcc2e429b961eed6031908d54ebbba94da2a3c0df9c` |
| **K5-IMG**| `kelompok 5/recovered_files/zein_carved.png` | 94.651 B | `52b91f060ed4b06f683c3d1bf567f96c` | `12ce476ae8b6b065104692da6a7dbe69512f6cb848989bfff5ec86a3749e0254` |

---

## 📂 Struktur Repositori Forensik

```
forensik-digital/
├── README.md                                      # Executive Showcase Utama (File ini)
├── .gitignore                                     # Konfigurasi isolasi bukti fisik mentah
│
├── kelompok 1/                                    # Kasus 1 (Kelompok 1)
│   ├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_1.md   # Laporan Lengkap DFIR ISO/IEC 27037
│   ├── screenshots/                               # 9 Tangkapan Layar Terminal Autentik (SS1 - SS9)
│   ├── recovered_files/                           # Berkas Hasil Dekripsi & Ekstraksi Sektor 100
│   └── scripts/                                   # Skrip Dekripsi XOR, Screenshot Gen, & Verifikasi Hash
│
├── kelompok 2/                                    # Kasus Kelompok 2
│   ├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_2.md   # Laporan Singkat DFIR Autopsy
│   ├── screenshots/                               # 4 Tangkapan Layar Autopsy
│   └── recovered_files/                           # Berkas Temuan KONMED_5.txt
│
├── kelompok 4/                                    # Kasus 3 & 4 (Kelompok 4)
│   ├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md   # Laporan Lengkap DFIR ISO/IEC 27037
│   ├── screenshots/                               # 10 Tangkapan Layar Autentik (SS1 - SS10)
│   ├── recovered_files/                           # Berkas Hasil Pemulihan Flag 1 & Flag 2
│   └── scripts/                                   # Skrip Carving & Ekstraksi Steganografi
│
└── kelompok 5/                                    # Kasus 5 (Kelompok 5)
    ├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_5.md   # Laporan Lengkap DFIR ISO/IEC 27037
    ├── screenshots/                               # 8 Tangkapan Layar Autentik (SS1 - SS8)
    ├── recovered_files/                           # Berkas Hasil Carving & Ekstraksi Trailing
    └── scripts/                                   # Skrip Parser FAT32, Carving, & Hashing
```

---

## 💻 Panduan Reproduksi Independen (Verification Commands)

### Verifikasi Kelompok 1
```powershell
# Ekstraksi & Dekripsi Sektor 100 Unallocated Space
python "kelompok 1\scripts\decrypt_payload.py"
Get-Content "kelompok 1\recovered_files\secret_evidence.txt"

# Verifikasi Hash SHA-256 Integritas Kriptografis
python "kelompok 1\scripts\verify_hashes.py"
Get-FileHash "kelompok 1\recovered_files\secret_evidence.txt" -Algorithm SHA256
```

### Verifikasi Kelompok 4
```powershell
python "kelompok 4\scripts\extract_evidence.py"
Get-Content "kelompok 4\recovered_files\cobainAES128.txt"
python "kelompok 4\scripts\extract_stego_flag.py"
Get-Content "kelompok 4\recovered_files\stego_flag2.txt"
```

### Verifikasi Kelompok 5
```powershell
python "kelompok 5\scripts\scan_fat32.py"
python "kelompok 5\scripts\extract_evidence.py"
Get-Content "kelompok 5\recovered_files\flag.txt"
python "kelompok 5\scripts\verify_hashes.py"
```

---

<p align="center">
  <b>Kelompok 3 Forensic Investigative Unit &copy; 2026</b><br>
  <i>Investigative Integrity &bull; Chain of Custody &bull; Technical Excellence</i>
</p>
