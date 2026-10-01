# 🔍 Digital Forensics Investigation Repository
### Mata Kuliah: Forensik Digital | Kasus Barang Bukti: Kelompok 4
### Tim Penyelidik: **Kelompok 3** | Status Kasus: **`CASE CLOSED (100% SOLVED)`**

---

<p align="center">
  <img src="https://img.shields.io/badge/STANDARDS-ISO%2FIEC%2027037%20%7C%20NIST%20SP%20800--86-blue?style=for-the-badge" alt="Standards">
  <img src="https://img.shields.io/badge/STATUS-CASE%20SOLVED-success?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/INTEGRITY-READ--ONLY%20PRESERVED-green?style=for-the-badge" alt="Integrity">
  <img src="https://img.shields.io/badge/FLAGS-2%20%2F%202%20RECOVERED-orange?style=for-the-badge" alt="Flags">
</p>

---

## 📌 Executive Summary

Repositori ini memuat seluruh dokumentasi investigasi, rantai bukti (*chain of custody*), skrip forensik, serta berkas bukti hasil pemulihan digital forensics dari barang bukti fisik Flashdisk **Kelompok 4** (Volume Label: `IV`, File System: `FAT32`).

Investigasi diselesaikan oleh **Kelompok 3** dengan memenuhi standar kepatuhan **ISO/IEC 27037:2012** (*Digital Evidence Handling Techniques*) dan **NIST SP 800-86**. Seluruh barang bukti asli pada `Drive D:\` dijaga dalam kondisi *strictly read-only* tanpa modifikasi 1 byte pun.

### 🏆 Hasil Akhir Temuan Bukti (Flags Solved)

| Sasaran Bukti | Metode Penyembunyian | Lokasi Klaster / File Pembawa | Kata Kunci / Flag | Makna Semantik |
| :---: | :---: | :---: | :---: | :--- |
| **Kasus 1** | **FAT32 Deleted Entry Carving** | Sektor Klaster `729073` (`/tugas`) | `FLAG{F1L3nY4DiH4pu5}` | *"File-nya Dihapus"* |
| **Kasus 2** | **OpenStego LSB Steganography** | `rhythm game\bg\Data\bt\250926.png` | `FLAG{k4t4H1kar1_0K3}` | *"Kata Hikari OKE"* |

> 📄 **Laporan Lengkap Resmi (Court-Admissible DFIR Report)** dapat dibaca pada:  
> 👉 [**`kelompok 4/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md`**](./kelompok%204/LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md)

---

## 📑 Daftar Isi Cepat

1. [Spesifikasi Media Barang Bukti](#-spesifikasi-media-barang-bukti)
2. [Alur Metodologi Forensik (10 Tahapan)](#-alur-metodologi-forensik-10-tahapan)
3. [Galeri Screenshot Bukti Autentik](#-galeri-screenshot-bukti-autentik)
4. [Tabel Hash Integritas Kriptografis](#-tabel-hash-integritas-kriptografis)
5. [Struktur Folder Repositori](#-struktur-folder-repositori)
6. [Panduan Reproduksi Independen](#-panduan-reproduksi-independen)

---

## 💾 Spesifikasi Media Barang Bukti

- **Item ID Bukti**: `EVD-2026-KEL4-USB01`
- **Volume Label**: `IV` (Menandakan Kepemilikan Kelompok 4)
- **Tipe Media**: Removable USB Flash Drive (`D:\`)
- **Sistem Berkas**: FAT32 (File Allocation Table 32-bit)
- **Kapasitas Total**: 7.44 GiB (7,987,511,296 Bytes)
- **Kapasitas Terpakai**: 5.17 GiB (5,551,730,688 Bytes)
- **Klaster Size**: 4,096 Bytes (8 Sektor per Klaster)
- **Sektor Fisik**: 512 Bytes

---

## 🛠️ Alur Metodologi Forensik (10 Tahapan)

```
[TAHAP 1: IDENTIFIKASI DRIVE D:] ---> [TAHAP 2: DUPLIKASI ROBOCOPY] ---> [TAHAP 3: HASHING VERIFIKASI]
                                                                                |
[TAHAP 6: CARVING KLASTER 729073] <-- [TAHAP 5: SCAN ENTRI 0xE5 FAT32] <-- [TAHAP 4: TIMELINE ANALYSIS]
        |
[TAHAP 7: VERIFIKASI FLAG 1] -------> [TAHAP 8: DETEKSI STEGO CARRIER] -> [TAHAP 9: ANALISIS OPENSTEGO]
                                                                                |
                                                                        [TAHAP 10: DEKRIPSI & FLAG 2]
```

### Rincian 10 Tahap:
1. **Tahap 1 - Identifikasi Fisik & Logis**: Membaca properti volume `IV` pada drive `D:\`.
2. **Tahap 2 - Preservasi Bukti (Akuisisi Logis)**: Menyalin 50.708 file menggunakan Robocopy dengan proteksi atribut dan stempel waktu.
3. **Tahap 3 - Verifikasi Rantai Bukti (Hashing)**: Menghitung MD5 & SHA-256 berkas tugas asli vs salinan (identik 100%).
4. **Tahap 4 - Timeline Analysis (MACB)**: Mengisolasi transaksi yang terjadi pada tanggal 28 September 2026 (08:59 - 09:22 WIB).
5. **Tahap 5 - Deteksi Entri Terhapus FAT32**: Menemukan entri terhapus bertanda `0xE5` (`cobainAES128.txt`) pada Klaster direktori 7.
6. **Tahap 6 - Rekonstruksi Klaster & Carving**: Rekonstruksi nomor klaster `0x0b1ff1` (Klaster 729073) dan pembacaan sektor mentah.
7. **Tahap 7 - Pemulihan Bukti Flag 1**: Ekstraksi dan verifikasi hash berkas `cobainAES128.txt` (`FLAG{F1L3nY4DiH4pu5}`).
8. **Tahap 8 - Deteksi Anomali Steganografi**: Menemukan 1 berkas PNG ganjil `250926.png` di antara 1.500+ thumbnail JPG osu!.
9. **Tahap 9 - Dekonstruksi Header OpenStego**: Analisis LSB bitstream mengungkap signature `OPENSTEGO`, PRNG seed `98234782L`, dan format blank password.
10. **Tahap 10 - Ekstraksi Steganografi Flag 2**: Mendekripsi AES-128 PBE dan dekompresi GZIP untuk memulihkan `FLAG{k4t4H1kar1_0K3}`.

---

## 📸 Galeri Screenshot Bukti Autentik

Seluruh tangkapan layar di bawah ini merupakan hasil eksekusi terminal PowerShell asli dari stasiun kerja penyelidik:

| Tahap | Keterangan Tindakan Forensik | Pratinjau Tangkapan Layar |
| :---: | :--- | :---: |
| **01** | Identifikasi Volume Flashdisk `IV` (`D:\`) | [Lihat Exhibit 1](./kelompok%204/screenshots/ss1_identifikasi_drive.png) |
| **02** | Akuisisi Logis Robocopy (50.708 Berkas) | [Lihat Exhibit 2](./kelompok%204/screenshots/ss2_duplikasi_barang_bukti.png) |
| **03** | Verifikasi Integritas Checksum MD5 & SHA-256 | [Lihat Exhibit 3](./kelompok%204/screenshots/ss3_hashing_integritas.png) |
| **04** | Analisis Timeline Transaksi 28 September 2026 | [Lihat Exhibit 4](./kelompok%204/screenshots/ss4_analisis_timeline.png) |
| **05** | Deteksi Entri Terhapus FAT32 (Byte `0xE5`) | [Lihat Exhibit 5](./kelompok%204/screenshots/ss5_deteksi_entri_terhapus_fat32.png) |
| **06** | Rekonstruksi Klaster 729073 & Sector Carving | [Lihat Exhibit 6](./kelompok%204/screenshots/ss6_rekonstruksi_klaster_dan_carving.png) |
| **07** | Pemulihan Flag 1 (`cobainAES128.txt`) | [Lihat Exhibit 7](./kelompok%204/screenshots/ss7_pemulihan_dan_verifikasi.png) |
| **08** | Deteksi Anomali Stego Carrier `250926.png` | [Lihat Exhibit 8](./kelompok%204/screenshots/ss8_deteksi_anomali_steganografi.png) |
| **09** | Analisis Struktur Bitstream OpenStego v2 | [Lihat Exhibit 9](./kelompok%204/screenshots/ss9_analisis_header_openstego.png) |
| **10** | Ekstraksi & Dekripsi Steganografi Flag 2 | [Lihat Exhibit 10](./kelompok%204/screenshots/ss10_ekstraksi_flag2_steganografi.png) |

---

## 🔒 Tabel Hash Integritas Kriptografis

| ID Artefak | Nama Berkas | Kategori Bukti | Ukuran | MD5 Hash | SHA-256 Hash |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **FLAG-01** | `cobainAES128.txt` | **Flag 1 (FAT32 Deleted)** | **20 B** | `8642a00cc9feeb559d5de23e19d2b150` | `6102bef305cdc7363c8acdfb1f9b57005cf642cb6fe1fdc3009500cc44228094` |
| **FLAG-02** | `stego_flag2.txt` | **Flag 2 (Steganography)** | **20 B** | `5bc41b9264b94ba9d321c9a3eab88be2` | `df5f6ee3d0161a1f58a51a0373652cfce57451305c5a897bb903de756963bb6a` |
| **CARR-01** | `250926.png` | Carrier Image Steganografi | 47,722 B | `0fe28807d47bfcefe5f0612bb0958ce7` | `f3e8f85f3ba2132d7296064f28682e8c2552e6fc7004f21cf371261cb28a8d05` |

---

## 📂 Struktur Folder Repositori

```
forensik-digital/
├── README.md                                    # Executive Repository Showcase (File ini)
├── .gitignore                                   # Konfigurasi proteksi privasi barang bukti mentah
└── kelompok 4/
    ├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md # Dokumen DFIR Lengkap Standar ISO/IEC 27037
    ├── screenshots/                             # 10 Tangkapan Layar Autentik (SS1 - SS10)
    │   ├── ss1_identifikasi_drive.png
    │   ├── ss2_duplikasi_barang_bukti.png
    │   ├── ss3_hashing_integritas.png
    │   ├── ss4_analisis_timeline.png
    │   ├── ss5_deteksi_entri_terhapus_fat32.png
    │   ├── ss6_rekonstruksi_klaster_dan_carving.png
    │   ├── ss7_pemulihan_dan_verifikasi.png
    │   ├── ss8_deteksi_anomali_steganografi.png
    │   ├── ss9_analisis_header_openstego.png
    │   └── ss10_ekstraksi_flag2_steganografi.png
    ├── recovered_files/                         # Berkas Bukti Hasil Recovery & Ekstraksi
    │   ├── cobainAES128.txt                     # Berkas Flag 1 (File-nya Dihapus)
    │   └── stego_flag2.txt                      # Berkas Flag 2 (Kata Hikari OKE)
    └── scripts/                                 # Perangkat Skrip Forensik Mandiri
        ├── extract_evidence.py                  # Skrip carving Klaster FAT32 (Flag 1)
        ├── extract_stego_flag.py                # Skrip ekstraksi OpenStego LSB (Flag 2)
        ├── scan_fat.py                          # Skrip pembaca entri tabel FAT32
        ├── scan_all_deleted.py                  # Skrip pemindai entri terhapus rekursif
        └── verify_hashes.py                     # Skrip verifikasi checksum MD5 & SHA-256
```

---

## 💻 Panduan Reproduksi Independen

Untuk menguji ulang dan mereproduksi hasil ekstraksi bukti secara independen:

### 1. Ekstraksi Flag 1 (FAT32 Carving)
```powershell
python "kelompok 4\scripts\extract_evidence.py"
Get-Content "kelompok 4\recovered_files\cobainAES128.txt"
```

### 2. Ekstraksi Flag 2 (Steganografi LSB)
```powershell
python "kelompok 4\scripts\extract_stego_flag.py"
Get-Content "kelompok 4\recovered_files\stego_flag2.txt"
```

---

<p align="center">
  <b>Kelompok 3 Forensic Investigative Unit &copy; 2026</b><br>
  <i>Investigative Integrity &bull; Chain of Custody &bull; Technical Excellence</i>
</p>
