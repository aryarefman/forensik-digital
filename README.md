# 🔍 Digital Forensics Investigation Repository
### Mata Kuliah: Forensik Digital | Kasus Barang Bukti: Kelompok 4 & Kelompok 5
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

Repositori ini memuat seluruh berkas dokumentasi investigasi, rantai bukti (*chain of custody*), skrip analisis forensik, tangkapan layar autentik, serta artefak bukti hasil pemulihan digital forensics dari dua media penyimpanan fisik USB Flashdisk:
1. **Kasus 1 & 2 (Kelompok 4)**: USB Flashdisk Volume `IV` (Kapasitas: 7.44 GB, FAT32)
2. **Kasus 3 (Kelompok 5)**: USB Flashdisk Volume `USB DISK` (Kapasitas: 28.64 GB, FAT32)

Seluruh investigasi diselesaikan secara independen oleh **Kelompok 3** dengan memenuhi standar kepatuhan internasional **ISO/IEC 27037:2012** (*Digital Evidence Handling Techniques*), **NIST SP 800-86**, dan **RFC 3227**. Seluruh barang bukti fisik asli pada drive eksternal dijaga dalam status *strictly read-only* tanpa modifikasi 1 byte pun.

---

## 🏆 Ringkasan Hasil Temuan Bukti (Flags Solved)

| Subjek Kasus | Target Bukti | Teknik Anti-Forensik | Format Penanda | Nilai Key / Flag | Makna Semantik |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **Kelompok 4** | Kasus 1 | FAT32 Directory Deletion (`0xE5`) | Standar `FLAG{}` | `FLAG{F1L3nY4DiH4pu5}` | *"File-nya Dihapus"* |
| **Kelompok 4** | Kasus 2 | OpenStego LSB Steganography | Standar `FLAG{}` | `FLAG{k4t4H1kar1_0K3}` | *"Kata Hikari OKE"* |
| **Kelompok 5** | Kasus 3 | JPEG EOI Trailing Data Overlay | **Khusus** `CODENAME{}` | `CODENAME{4P0ST3L_P3T3R_0F_GL0RY}` | *"Apostle Peter of Glory"* (Manhwa Killer Peter) |

> 📑 **Akses Laporan Resmi DFIR Lengkap**:  
> 👉 [**Laporan Investigasi Forensik Kelompok 4 (DFIR-2026-FD-KEL4)**](./kelompok%204/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md)  
> 👉 [**Laporan Investigasi Forensik Kelompok 5 (DFIR-2026-FD-KEL5)**](./kelompok%205/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_5.md)

---

## 📑 Perbandingan Karakteristik Media Barang Bukti

| Parameter Teknis | Barang Bukti Kelompok 4 | Barang Bukti Kelompok 5 |
| :--- | :--- | :--- |
| **Nomor Kasus DFIR** | `DFIR-2026-FD-KEL4-001` | `DFIR-2026-FD-KEL5-001` |
| **Volume Label** | `IV` | `USB DISK` |
| **Tipe Perangkat** | Removable USB Storage Media | Removable USB Storage Media |
| **Sistem Berkas** | FAT32 (`MSDOS5.0`) | FAT32 (`MSDOS5.0`) |
| **Ukuran Sektor Fisik** | 512 Bytes | 512 Bytes |
| **Ukuran Klaster** | 4.096 Bytes (8 Sektor/Klaster) | 16.384 Bytes (32 Sektor/Klaster) |
| **Kapasitas Media** | 7.44 GiB (7.987.511.296 B) | 28.64 GiB (30.747.394.048 B) |
| **Jumlah Flag Ditemukan** | 2 Flag (`FLAG{...}`) | 1 Flag Khusus (`CODENAME{...}`) |
| **Artefak Sekunder** | `250926.png` (Stego carrier) | `zein_carved.png`, `link.txt` (Decoy profil dosen) |

---

## 🛠️ Alur Metodologi Forensik Digital (ISO/IEC 27037)

```
[1. IDENTIFIKASI MEDIA] ────> [2. AKUISISI ROBOCOPY] ────> [3. VERIFIKASI HASH SHA-256]
                                                                    │
┌───────────────────────────────────────────────────────────────────┘
▼
[4. ANALISIS TIMELINE]  ────> [5. PARSING ENTRI 0xE5] ───> [6. CLUSTER & FILE CARVING]
                                                                    │
┌───────────────────────────────────────────────────────────────────┘
▼
[7. ANALISIS PAYLOAD]   ────> [8. STEGANO / OVERLAY]  ───> [9. EKSTRAKSI & VALIDASI FLAG]
```

### Rangkuman Kasus Kelompok 4:
1. Rekonstruksi tabel direktori `/tugas` mendeteksi berkas terhapus `cobainAES128.txt` pada Klaster `729073`.
2. Carving sektor mentah memulihkan Flag 1: `FLAG{F1L3nY4DiH4pu5}`.
3. Analisis direktori aset `rhythm game` menemukan gambar ganjil `250926.png`. Bitstream parsing mendeteksi signature OpenStego RandomLSB tanpa password (`blank password`).
4. Dekripsi AES-128 PBE dan dekompresi GZIP memulihkan Flag 2: `FLAG{k4t4H1kar1_0K3}`.

### Rangkuman Kasus Kelompok 5:
1. Pemeriksaan volume menemukan folder aktif `FLAG-1` berisi berkas gambar `opung_archive.jpg`.
2. Analisis heksadesimal mendeteksi 32 byte data tambahan (*trailing data*) tepat setelah penanda akhir berkas JPEG (*End-of-Image* / EOI marker `FF D9` pada offset `95.745`).
3. Ekstraksi langsung memulihkan flag berformat khusus: `CODENAME{4P0ST3L_P3T3R_0F_GL0RY}`.
4. Parsing tabel direktori root FAT32 mendeteksi dokumen terhapus `hidden_mission.txt` (sumber flag), foto mahasiswa terhapus `zein-removebg-preview.png` (klaster 6..11), dan `link.txt` yang merujuk pada Google Images profil dosen ITS Dr. Hatma Suryotrisongko.

---

## 🔒 Matriks Hash Integritas Kriptografis (Chain of Custody)

| ID Bukti | Nama Artefak | Ukuran | Checksum MD5 | Checksum SHA-256 |
| :---: | :--- | :---: | :--- | :--- |
| **K4-F1** | `kelompok 4/recovered_files/cobainAES128.txt` | 20 B | `8642a00cc9feeb559d5de23e19d2b150` | `6102bef305cdc7363c8acdfb1f9b57005cf642cb6fe1fdc3009500cc44228094` |
| **K4-F2** | `kelompok 4/recovered_files/stego_flag2.txt` | 20 B | `5bc41b9264b94ba9d321c9a3eab88be2` | `df5f6ee3d0161a1f58a51a0373652cfce57451305c5a897bb903de756963bb6a` |
| **K5-F1** | `kelompok 5/recovered_files/flag.txt` | 34 B | `3597ab716096a98ccb26425463796392` | `943046ab8c6f6c74a3b4e318adab159280c42dd2249bf15ab4cf245d966d5268` |
| **K5-HM** | `kelompok 5/recovered_files/hidden_mission.txt` | 32 B | `c4bcfb80c928064ef36f7aef6a1669af` | `87beaedfbb2f34a9d96b5fcc2e429b961eed6031908d54ebbba94da2a3c0df9c` |
| **K5-LK** | `kelompok 5/recovered_files/link.txt` | 38 B | `497ed49b9b20e8544338dacdddc7461d` | `ecd22a22fb3b3b07d91a472ffa36db62782e2003d994a160854128d52425688d` |
| **K5-IMG**| `kelompok 5/recovered_files/zein_carved.png` | 94.651 B | `52b91f060ed4b06f683c3d1bf567f96c` | `12ce476ae8b6b065104692da6a7dbe69512f6cb848989bfff5ec86a3749e0254` |

---

## 📂 Struktur Repositori Forensik

```
forensik-digital/
├── README.md                                      # Executive Showcase Utama (File ini)
├── .gitignore                                     # Konfigurasi isolasi bukti fisik mentah
│
├── kelompok 4/                                    # Kasus 1 & 2 (Kelompok 4)
│   ├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md   # Laporan Lengkap DFIR ISO/IEC 27037
│   ├── screenshots/                               # 10 Tangkapan Layar Autentik (SS1 - SS10)
│   ├── recovered_files/                           # Berkas Hasil Pemulihan Flag 1 & Flag 2
│   └── scripts/                                   # Skrip Carving & Ekstraksi Steganografi
│
└── kelompok 5/                                    # Kasus 3 (Kelompok 5)
    ├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_5.md   # Laporan Lengkap DFIR ISO/IEC 27037
    ├── screenshots/                               # 8 Tangkapan Layar Autentik (SS1 - SS8)
    ├── recovered_files/                           # Berkas Hasil Carving & Ekstraksi Trailing
    └── scripts/                                   # Skrip Parser FAT32, Carving, & Hashing
```

---

## 💻 Panduan Reproduksi Independen (Verification Commands)

### Verifikasi Kelompok 4
```powershell
# Ekstraksi Flag 1 (FAT32 Carving)
python "kelompok 4\scripts\extract_evidence.py"
Get-Content "kelompok 4\recovered_files\cobainAES128.txt"

# Ekstraksi Flag 2 (OpenStego LSB Decryption)
python "kelompok 4\scripts\extract_stego_flag.py"
Get-Content "kelompok 4\recovered_files\stego_flag2.txt"
```

### Verifikasi Kelompok 5
```powershell
# Parsing Struktur FAT32 & Entri Terhapus
python "kelompok 5\scripts\scan_fat32.py"

# Ekstraksi Flag Trailing JPEG & Carving Klaster Unallocated
python "kelompok 5\scripts\extract_evidence.py"
Get-Content "kelompok 5\recovered_files\flag.txt"

# Verifikasi Nilai Hash Integritas
python "kelompok 5\scripts\verify_hashes.py"
```

---

<p align="center">
  <b>Kelompok 3 Forensic Investigative Unit &copy; 2026</b><br>
  <i>Investigative Integrity &bull; Chain of Custody &bull; Technical Excellence</i>
</p>
