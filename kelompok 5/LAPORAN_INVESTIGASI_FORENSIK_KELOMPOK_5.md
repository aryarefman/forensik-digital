# DIGITAL FORENSIC INVESTIGATION REPORT (DFIR)
## CASE REF: `DFIR-2026-FD-KEL5` | CLASSIFICATION: CONFIDENTIAL / EVIDENCE REPORT
### STANDARD COMPLIANCE: ISO/IEC 27037:2012 & NIST SP 800-86 & RFC 3227

---

### DOCUMENT CONTROL & ADMINISTRATIVE DATA

| Parameter Administrasi | Rincian Informasi Forensik |
| :--- | :--- |
| **Nomor Kasus / Case ID** | `DFIR-2026-FD-KEL5-001` |
| **Judul Kasus** | Investigasi Forensik Sistem Berkas & Analisis Data Trailing Barang Bukti Kelompok 5 |
| **Tim Penyelidik (Examiner)** | **Kelompok 3** (Forensik Digital) |
| **Subjek Barang Bukti** | Removable USB Storage Media Kelompok 5 (Volume Label: `USB DISK` / Drive `D:\`) |
| **Tanggal Penerimaan Bukti** | 28 September 2026 |
| **Tanggal Analisis & Penyelesaian** | 28 September 2026 – 02 Oktober 2026 |
| **Status Akhir Investigasi** | **SOLVED / CASE CLOSED (100% OBJECTIVES ACHIEVED)** |
| **Integritas Bukti Fisik Asli** | **100% UNTOUCHED / MURNI (Read-Only Strict Compliance)** |
| **Standar Metodologi** | **ISO/IEC 27037** (DEHT - Digital Evidence Handling Techniques), **NIST SP 800-86**, **RFC 3227** |

#### Riwayat Revisi Dokumen (Version Control)
| Versi | Tanggal | Penyelidik | Deskripsi Perubahan Dokumen |
| :---: | :---: | :---: | :--- |
| `v1.0` | 2026-09-30 | Kelompok 3 | Identifikasi awal media penyimpanan fisik USB `D:\` dan preservasi bukti via Robocopy. |
| `v1.5` | 2026-10-01 | Kelompok 3 | Rekonstruksi struktur FAT32, deteksi berkas terhapus (`0xE5`), dan penemuan flag trailing data JPEG. |
| `v2.0` | 2026-10-02 | Kelompok 3 | Finalisasi laporan lengkap: Carving unallocated space, analisis tautan eksternal OSINT, validasi muatan bukti `CODENAME{4P0ST3L_P3T3R_0F_GL0RY}`, pembaruan 8 tangkapan layar autentik terminal, dan standarisasi ISO/IEC 27037 & NIST SP 800-86. |

---

## DAFTAR ISI
1. [Ringkasan Eksekutif (Executive Summary)](#1-ringkasan-eksekutif-executive-summary)
2. [Metodologi Forensik & Lingkungan Uji (Forensic Environment)](#2-metodologi-forensik--lingkungan-uji-forensic-environment)
3. [Rantai Penjagaan Bukti & Integritas Kriptografis (Chain of Custody)](#3-rantai-penjagaan-bukti--integritas-kriptografis-chain-of-custody)
4. [Kronologi & Tahapan Investigasi Forensik (Forensic Examination)](#4-kronologi--tahapan-investigasi-forensik-forensic-examination)
   - [Fase A: Penanganan & Preservasi Bukti Fisik (Tahap 1 - 4)](#fase-a-penanganan--preservasi-bukti-fisik-tahap-1---4)
   - [Fase B: Analisis Sistem Berkas & Carving Data (Tahap 5 - 6)](#fase-b-analisis-sistem-berkas--carving-data-tahap-5---6)
   - [Fase C: Analisis Trailing Data Overlay & Validasi Bukti (Tahap 7 - 8)](#fase-c-analisis-trailing-data-overlay--validasi-bukti-tahap-7---8)
5. [Analisis Teknik Anti-Forensik & Evasion Kelompok 5](#5-analisis-teknik-anti-forensik--evasion-kelompok-5)
6. [Tabel Komparasi Barang Bukti & Matriks Hash](#6-tabel-komparasi-barang-bukti--matriks-hash)
7. [Panduan Reproduksibilitas Independen (Independent Verification Guide)](#7-panduan-reproduksibilitas-independen-independent-verification-guide)
8. [Pernyataan Integritas & Pengesahan Penyelidik (Examiner Attestation)](#8-pernyataan-integritas--pengesahan-penyelidik-examiner-attestation)

---

## 1. RINGKASAN EKSEKUTIF (EXECUTIVE SUMMARY)

### 1.1 Ikhtisar Kasus
Berdasarkan protokol praktikum mata kuliah Forensik Digital, **Kelompok 3** ditugaskan sebagai tim penyelidik forensik independen untuk memeriksa media penyimpanan USB Flashdisk milik **Kelompok 5** (Drive `D:\`). Tugas utama penyelidik adalah mengidentifikasi, mengekstraksi, dan menganalisis muatan rahasia (*secret payload / flag*) serta mengungkap seluruh jejak rekayasa anti-forensik yang diterapkan pada media tersebut tanpa merusak keaslian bukti fisik asli.

### 1.2 Ringkasan Temuan Kunci (Key Findings)
Penyelidikan forensik digital berhasil mengungkap seluruh manipulasi sistem berkas dan mengekstraksi muatan rahasia secara sempurna (**100% SOLVED**):

1. **Temuan Bukti Kasus 1 (Anti-Forensik File Appending / JPEG Trailing Data Injection)**:
   - Ditemukan berkas gambar aktif `opung_archive.jpg` (95.779 byte) di dalam direktori `D:\FLAG-1\`.
   - Analisis byte heksadesimal membuktikan adanya penyisipan muatan 32 byte tepat di belakang penanda baku akhir berkas JPEG (*End of Image* / EOI marker `\xFF\xD9`) pada offset 95.745.
   - Muatan tersebut merupakan string plaintext penanda rahasia:
     ```text
     CODENAME{4P0ST3L_P3T3R_0F_GL0RY}
     ```
   - *Makna Semantik*: Merujuk pada karakter utama manhwa aksi *"Killer Peter"* (Kim Chun-woo / Apostle Peter / Petrus Rasul Kejayaan).

2. **Temuan Bukti Kasus 2 (Anti-Forensik FAT32 Tombstone Deletion & Unallocated Carving)**:
   - Pembongkaran tabel direktori utama (*Root Directory Table* pada Klaster 2) mendeteksi entri terhapus dengan *tombstone marker* `0xE5`.
   - Ditemukan entri berkas terhapus `hidden_mission.txt` (Klaster 12, 32 B) yang memuat teks identik dengan trailing flag, membuktikan artefak sumber sebelum proses penggabungan berkas.
   - Ditemukan entri berkas terhapus `link.txt` (Klaster 12, 38 B) berisi URL:
     ```text
     https://share.google/MNWjeCwlthtobBNaN
     ```
     yang mengarahkan pada Google Images profil dosen pembina Forensik Digital ITS, **Dr. Hatma Suryotrisongko**.
   - Berhasil memulihkan citra foto mahasiswa terhapus `zein-removebg-preview.png` (94.651 B) dari klaster 6 hingga 11 (*carved* ke [zein_carved.png](file:///c:/Users/arya4/forensik-digital/kelompok%205/recovered_files/zein_carved.png)).

### 1.3 Matriks Status Investigasi
| ID Sasaran | Media Pembawa | Teknik Penyembunyian | Status Hasil | Artefak Bukti yang Dipulihkan |
| :---: | :---: | :---: | :---: | :--- |
| **OBJ-01** | `D:\flag-1\opung_archive.jpg` | JPEG EOI Trailing Data Overlay | **SOLVED** | `kelompok 5/recovered_files/flag.txt` |
| **OBJ-02** | Root Dir (Klaster 12) | FAT32 Directory Deletion (`0xE5`) | **SOLVED** | `kelompok 5/recovered_files/hidden_mission.txt` |
| **OBJ-03** | Root Dir (Klaster 12) | FAT32 Directory Deletion (`0xE5`) | **SOLVED** | `kelompok 5/recovered_files/link.txt` |
| **OBJ-04** | Klaster 6 s.d. 11 | Unallocated Sector Raw Carving | **SOLVED** | `kelompok 5/recovered_files/zein_carved.png` |

---

## 2. METODOLOGI FORENSIK & LINGKUNGAN UJI (FORENSIC ENVIRONMENT)

### 2.1 Kerangka Kerja Standar (Compliance Framework)
Investigasi dilaksanakan dengan mengacu ketat pada:
- **ISO/IEC 27037:2012**: *Guidelines for identification, collection, acquisition, and preservation of digital evidence*.
- **NIST SP 800-86**: *Guide to Integrating Forensic Techniques into Incident Response*.
- **RFC 3227**: *Guidelines for Evidence Collection and Archiving* (Prinsip Urutan Volatilitas & Non-Destructive Analysis).

### 2.2 Spesifikasi Stasiun Kerja Forensik (Forensic Workstation)
- **Sistem Operasi**: Windows 11 Enterprise (Build 64-bit)
- **Host Penyelidik**: `DESKTOP-8G8M19I`
- **Penyimpanan Internal Host**: WD PC SN740 NVMe SSD 512GB (NTFS)
- **Lingkungan Eksekusi**:
  - Windows PowerShell 5.1 & PowerShell Core
  - Python 3.12.4 (x86_64) dengan modul `cryptography`, `Pillow`, `hashlib`, `struct`, `numpy`
  - Robocopy File Transfer Utility Engine (Preserving `DAT` & `DCOPY:DA`)

---

## 3. RANTAI PENJAGAAN BUKTI & INTEGRITAS KRIPTOGRAFIS (CHAIN OF CUSTODY)

### 3.1 Identifikasi Media Fisik Barang Bukti
- **Item ID Bukti**: `EVD-2026-KEL5-USB01`
- **Tipe Media**: USB Flash Drive (Removable Storage Media)
- **Nomor Drive Fisik**: Disk 1 (`\\.\PhysicalDrive1` / `\\.\D:`)
- **Model / Vendor Perangkat**: `USB SanDisk 3.2Gen1`
- **Volume Label**: `USB DISK` (Menandakan Kepemilikan Kelompok 5)
- **Format File System**: FAT32 (`MSDOS5.0`, File Allocation Table 32-bit)
- **Kapasitas Total**: 28.64 GiB (30,747,394,048 Bytes / 60,086,272 Sektor)
- **Ukuran Sektor Fisik**: 512 Bytes
- **Ukuran Klaster**: 16,384 Bytes (32 Sektor per Klaster)
- **Sektor Reserved**: 3,444 Sektor (Offset FAT1: 1,763,328 Bytes)
- **Offset Area Data**: 16,777,216 Bytes (Awal Klaster 2)

### 3.2 Log Rantai Penjagaan (Chain of Custody Log)
```
[2026-09-28 09:25 WIB] Penerimaan media fisik USB Flashdisk dari Kelompok 5 oleh Kelompok 3.
[2026-09-28 09:30 WIB] Pemasangan penanganan write-protection / read-only handling pada Drive D:.
[2026-10-01 14:15 WIB] Identifikasi struktur partisi volume dan properti kontrol FAT32.
[2026-10-01 14:22 WIB] Akuisisi logis bit-preserving via Robocopy ke 'kelompok 5/evidence/'.
[2026-10-01 14:30 WIB] Hashing baseline awal verifikasi identitas (MD5 & SHA-256 identik 100%).
[2026-10-02 17:05 WIB] Verifikasi akhir seluruh artefak bukti dan pelepasan media secara aman.
```

---

## 4. KRONOLOGI & TAHAPAN INVESTIGASI FORENSIK (FORENSIC EXAMINATION)

---

### FASE A: PENANGANAN & PRESERVASI BUKTI FISIK (TAHAP 1 - 4)

#### TAHAP 1: IDENTIFIKASI AWAL MEDIA BARANG BUKTI (DRIVE D:\)
- **Tindakan**: Mengidentifikasi arsitektur penyimpanan, tabel partisi, label volume, dan parameter fisik perangkat dari drive fisik `D:\` menggunakan perintah native PowerShell `Get-Volume -DriveLetter D | Format-List` dan `Get-Disk`.
- **Hasil Pengamatan**:
  - Ditemukan media flashdisk fisik `USB SanDisk 3.2Gen1` dengan kapasitas 28.64 GB berformat **FAT32**.
  - Terdapat dua direktori pada media: `D:\flag-1` dan direktori sistem `D:\System Volume Information`.
- **Dokumentasi Bukti**:

![Exhibit 1: Identifikasi Drive Barang Bukti](./screenshots/ss1_identifikasi_drive.png)
*Gambar 1 (Exhibit 1): Tangkapan layar PowerShell identifikasi volume flashdisk FAT32 Drive D: (SanDisk 3.2Gen1).*

---

#### TAHAP 2: AKUISISI LOGIS & DUPLIKASI BERKAS (NON-DESTRUCTIVE PRESERVATION)
- **Tindakan**: Melakukan duplikasi data komprehensif dari `D:\` ke direktori lokal `kelompok 5\evidence` menggunakan utilitas `robocopy` dengan parameter `/E /DCOPY:DA /COPY:DAT /IS` guna mempertahankan seluruh stempel waktu asli (*MACB timestamps*) dan atribut berkas.
- **Hasil Pengamatan**:
  - Seluruh berkas aktif (`opung_archive.jpg`, `IndexerVolumeGuid`, `WPSettings.dat`) tersalin sempurna tanpa kegagalan (*0 Mismatch, 0 Failed*).
  - Media fisik asli `D:\` tidak mengalami modifikasi stempel waktu atau penulisan data sedikit pun (*strictly read-only*).
- **Dokumentasi Bukti**:

![Exhibit 2: Duplikasi & Preservasi Bukti](./screenshots/ss2_duplikasi_barang_bukti.png)
*Gambar 2 (Exhibit 2): Ringkasan status Robocopy membuktikan integritas berkas tersalin utuh.*

---

#### TAHAP 3: HASHING VERIFIKASI INTEGRITAS BERKAS (CHAIN OF CUSTODY BASELINE)
- **Tindakan**: Menjalankan skrip validasi integritas [verify_hashes.py](file:///c:/Users/arya4/forensik-digital/kelompok%205/scripts/verify_hashes.py) untuk menghitung checksum MD5 dan SHA-256 dari seluruh berkas pada media fisik asli `D:\` dan membandingkannya dengan direktori salinan kerja forensik.
- **Hasil Pengamatan**:
  - Nilai hash MD5 (`1e5454973664bc15e5d6bd6cd584b53c`) dan SHA-256 (`29d1d15e5cd125499cb1458c1e91a2c945fc133a1a99f851544ad9966a32924a`) antara berkas di media fisik dan salinan terbukti **100% identik**.
  - Memenuhi klausul ISO/IEC 27037 mengenai keaslian dan non-kontaminasi bukti digital.
- **Dokumentasi Bukti**:

![Exhibit 3: Hashing Verifikasi Integritas](./screenshots/ss3_hashing_integritas.png)
*Gambar 3 (Exhibit 3): Matriks nilai hash MD5 dan SHA-256 membuktikan integritas rantai bukti.*

---

#### TAHAP 4: TIMELINE ANALYSIS (REKONSTRUKSI KRONOLOGIS MACB)
- **Tindakan**: Menjalankan skrip analisis [scan_timeline.py](file:///c:/Users/arya4/forensik-digital/kelompok%205/scripts/scan_timeline.py) untuk merekonstruksi urutan peristiwa sistem berkas berdasarkan atribut waktu pembuatan (*CreationTime*), modifikasi (*LastWriteTime*), dan akses (*LastAccessTime*).
- **Hasil Pengamatan**:
  - Terpetakan 14 transaksi sistem berkas yang merekonstruksi kronologi aktivitas pembuatan soal oleh Kelompok 5:
    - `2026-09-21 08:51 WIB`: Inisialisasi partisi flashdisk FAT32.
    - `2026-09-21 11:01 - 11:07 WIB`: Pembuatan citra `OPUNG.JPG` dan teks `hidden_mission.txt` (32 B).
    - `2026-09-21 11:09 WIB`: Penggabungan citra dan teks menghasilkan `opung_archive.jpg` (95.779 B).
    - `2026-09-21 11:10 WIB`: Pembentukan folder `FLAG-1` dan pemindahan berkas dari root.
    - `2026-09-28 16:11 - 16:16 WIB`: Penyalinan berkas decoy `zein-removebg-preview.png` dan `link.txt` lalu dihapus.
- **Dokumentasi Bukti**:

![Exhibit 4: Timeline Analysis](./screenshots/ss4_analisis_timeline.png)
*Gambar 4 (Exhibit 4): Rekonstruksi timeline mendeteksi kronologi aktivitas sistem berkas FAT32.*

---

### FASE B: ANALISIS SISTEM BERKAS & CARVING DATA (TAHAP 5 - 6)

#### TAHAP 5: ANALISIS STRUKTUR FAT32 & DETEKSI BERKAS TERHAPUS (0xE5)
- **Tindakan**: Membaca sektor mentah tabel direktori utama (Klaster 2) menggunakan skrip [scan_fat32.py](file:///c:/Users/arya4/forensik-digital/kelompok%205/scripts/scan_fat32.py) untuk mendeteksi entri direktori berstatus terhapus (*marked with tombstone byte 0xE5*).
- **Hasil Pengamatan**:
  - Pada sistem berkas FAT32, berkas yang dihapus tidak langsung hilang dari piringan data, melainkan karakter awal namanya diganti menjadi `0xE5`.
  - Ditemukan 7 entri berkas/direktori berstatus `DELETED`:
    - `[0060]` `README.MD` (Klaster 6, 27.508 B)
    - `[0080]` `OPUNG.JPG` (Klaster 6, 95.747 B)
    - `[00E0]` `hidden_mission.txt` (Klaster 12, 32 B)
    - `[0140]` `opung_archive.jpg` (Klaster 13, 95.779 B — entri lama sebelum dipindahkan ke folder)
    - `[0180]` `New folder` (Klaster 19, direktori lama sebelum di-rename menjadi `FLAG-1`)
    - `[0200]` `zein-removebg-preview.png` (Klaster 6, 94.651 B)
    - `[0280]` `link.txt` (Klaster 12, 38 B)
- **Dokumentasi Bukti**:

![Exhibit 5: Deteksi Entri Terhapus FAT32](./screenshots/ss5_deteksi_entri_terhapus_fat32.png)
*Gambar 5 (Exhibit 5): Deteksi entri 0xE5 membuktikan keberadaan berkas terhapus pada tabel direktori root.*

---

#### TAHAP 6: REKONSTRUKSI KLASTER FAT32 & CARVING DATA SEKTOR
- **Tindakan**: Menjalankan ekstraksi data langsung dari area *unallocated clusters* pada piringan mentah `\\.\D:` menggunakan skrip [extract_evidence.py](file:///c:/Users/arya4/forensik-digital/kelompok%205/scripts/extract_evidence.py):
  - Membaca Klaster 6 hingga 11 (offset `16.842.752`, ukuran `94.651` byte) untuk memulihkan `zein_carved.png`.
  - Membaca Klaster 12 (offset `16.941.056`, ukuran `38` byte) untuk memulihkan `link.txt`.
- **Hasil Pengamatan**:
  - Berkas citra `zein_carved.png` berhasil direkonstruksi 100% utuh (foto mahasiswa mengenakan jas almamater ITS).
  - Tautan URL berhasil dipulihkan: `https://share.google/MNWjeCwlthtobBNaN` yang merujuk pada foto dosen pembina ITS.
- **Dokumentasi Bukti**:

![Exhibit 6: Rekonstruksi Klaster & Carving](./screenshots/ss6_rekonstruksi_klaster_dan_carving.png)
*Gambar 6 (Exhibit 6): Carving sektor unallocated memulihkan citra PNG dan berkas tautan secara presisi.*

---

### FASE C: ANALISIS TRAILING DATA OVERLAY & VALIDASI BUKTI (TAHAP 7 - 8)

#### TAHAP 7: ANALISIS HEXADECIMAL TRAILING DATA PADA BERKAS JPEG
- **Tindakan**: Melakukan analisis heksadesimal terhadap berkas aktif `opung_archive.jpg` di dalam folder `FLAG-1` menggunakan perintah `Get-Content -Encoding Byte -Tail 60 | Format-Hex`.
- **Hasil Pengamatan**:
  - Penanda akhir format JPEG (*End of Image* / EOI marker `\xFF\xD9`) ditemukan pada offset desimal **95.745**.
  - Tepat setelah penanda EOI (offset byte **95.747** hingga **95.779**), terdeteksi muatan 32 byte data tambahan (*trailing data overlay*) yang disisipkan tanpa enkripsi.
  - Nilai ASCII yang terbaca: `CODENAME{4P0ST3L_P3T3R_0F_GL0RY}`.
- **Dokumentasi Bukti**:

![Exhibit 7: Analisis Trailing Data JPEG](./screenshots/ss7_analisis_trailing_data_jpeg.png)
*Gambar 7 (Exhibit 7): Inspeksi byte membuktikan penanda EOI FF D9 diikuti oleh string muatan flag.*

---

#### TAHAP 8: VERIFIKASI HASIL EKSTRAKSI & PEMULIHAN FLAG UTAMA
- **Tindakan**: Memverifikasi kesesuaian antara flag hasil ekstraksi trailing data, berkas teks terpulihkan [flag.txt](file:///c:/Users/arya4/forensik-digital/kelompok%205/recovered_files/flag.txt), dan entri terhapus [hidden_mission.txt](file:///c:/Users/arya4/forensik-digital/kelompok%205/recovered_files/hidden_mission.txt).
- **Hasil Pengamatan**:
  - Seluruh artefak menghasilkan nilai plaintext yang identik 100%:
    ```text
    CODENAME{4P0ST3L_P3T3R_0F_GL0RY}
    ```
  - Hash SHA-256 muatan flag: `87beaedfbb2f34a9d96b5fcc2e429b961eed6031908d54ebbba94da2a3c0df9c`.
  - Berkas bukti resmi telah disimpan pada direktori kerja [recovered_files/](file:///c:/Users/arya4/forensik-digital/kelompok%205/recovered_files/).
- **Dokumentasi Bukti**:

![Exhibit 8: Verifikasi & Validasi Temuan Akhir Flag](./screenshots/ss8_ekstraksi_dan_verifikasi_flag.png)
*Gambar 8 (Exhibit 8): Bukti akhir pemulihan dan verifikasi muatan rahasia Kelompok 5.*

---

## 5. ANALISIS TEKNIK ANTI-FORENSIK & EVASION KELOMPOK 5

Penyelidikan membuktikan bahwa Kelompok 5 menyusun strategi penyembunyian data bertingkat (*multi-stage anti-forensics*) untuk mengelabui pemeriksaan visual maupun logika sistem berkas biasa:

```
                                [BARANG BUKTI DRIVE D:]
                                           |
                 +-------------------------+-------------------------+
                 |                                                   |
        [FASE 1: OVERLAY INJECTION]                         [FASE 2: DELETION & DECOYS]
                 |                                                   |
   - Berkas: flag-1/opung_archive.jpg                  - Vektor: FAT32 0xE5 Entry Marking
   - Teknik: JPEG EOI Trailing Appending               - Sumber Terhapus: hidden_mission.txt (32 B)
   - Offset: Post-EOI (95.747 - 95.779)                - Berkas Umpan 1: zein-removebg-preview.png (Klaster 6)
   - Karakteristik: Tembus Image Viewer standar        - Berkas Umpan 2: link.txt (Klaster 12, Google URL)
                 |                                                   |
         [BYTE CARVING]                                      [UNALLOCATED CARVING]
                 |                                                   |
   --> CODENAME{4P0ST3L_P3T3R_0F_GL0RY}                --> zein_carved.png & link.txt
```

1. **Vektor Penyisipan Data Trailing Pasca-EOI (JPEG Trailing Data Overlay)**:
   Pembuat soal memanfaatkan spesifikasi standar format JPEG. Aplikasi grafis pembaca gambar memproses data mulai dari *Start of Image* (`FF D8`) dan menghentikan pembacaan saat mencapai marker *End of Image* (`FF D9`). Data apa pun yang disambungkan di belakang marker ini diabaikan oleh penampil gambar, sehingga gambar tetap tampil normal tanpa indikasi anomali visual. Penggabungan dilakukan melalui perintah biner:
   ```cmd
   copy /b OPUNG.JPG + hidden_mission.txt opung_archive.jpg
   ```
2. **Vektor Penghapusan Berkas Tombstone FAT32 (Residual File Deletion)**:
   Dokumen teks sumber `hidden_mission.txt` dihapus dari tabel direktori agar tidak terlihat pada Windows Explorer. Namun, karena tidak dilakukan proses penimpaan (*wiping*), data 32 byte tetap tertinggal di klaster 12 dan metadata ukuran serta tanggal tetap terekam pada tabel direktori.
3. **Vektor Pengaburan Nama Folder (Folder Renaming & Relocation)**:
   Pembuat soal mula-mula membuat folder bernama `New folder` pada klaster 19, kemudian mengubah namanya menjadi `FLAG-1` dan memindahkan berkas `opung_archive.jpg` ke dalamnya, meninggalkan entri lama berstatus `DELETED` di direktori utama.
4. **Vektor Umpan Pengalihan Perhatian (Decoy & OSINT Distraction)**:
   Penyalinan foto mahasiswa ITS (`zein-removebg-preview.png`) dan pembuatan tautan terhapus (`link.txt`) yang merujuk pada profil dosen pembina berfungsi sebagai decoy untuk mengalihkan fokus investigasi dari berkas utama di dalam folder `FLAG-1`.

---

## 6. TABEL KOMPARASI BARANG BUKTI & MATRIKS HASH

Tabel berikut menyajikan inventaris lengkap berkas bukti dan verifikasi integritas kriptografis:

| ID Bukti | Nama Berkas | Kategori & Peran Berkas | Ukuran | MD5 Checksum | SHA-256 Checksum |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **FLAG-01** | **`flag.txt`** | **Bukti Flag (Hasil Ekstraksi Trailing Data)** | **34 B** | `3597ab716096a98ccb26425463796392` | `943046ab8c6f6c74a3b4e318adab159280c42dd2249bf15ab4cf245d966d5268` |
| **FLAG-02** | **`hidden_mission.txt`** | **Bukti Flag (Pulih dari Entri Terhapus Klaster 12)** | **32 B** | `c4bcfb80c928064ef36f7aef6a1669af` | `87beaedfbb2f34a9d96b5fcc2e429b961eed6031908d54ebbba94da2a3c0df9c` |
| **CARR-01** | `opung_archive.jpg` | Berkas Pembawa Flag (Media Fisik `D:\flag-1\`) | 95,779 B | `1e5454973664bc15e5d6bd6cd584b53c` | `29d1d15e5cd125499cb1458c1e91a2c945fc133a1a99f851544ad9966a32924a` |
| **CARR-02** | `opung_archive.jpg` | Salinan Kerja Forensik (`kelompok 5/evidence/`) | 95,779 B | `1e5454973664bc15e5d6bd6cd584b53c` | `29d1d15e5cd125499cb1458c1e91a2c945fc133a1a99f851544ad9966a32924a` |
| **DECY-01** | `link.txt` | Berkas Tautan Pulih (Klaster 12, Google Decoy) | 38 B | `497ed49b9b20e8544338dacdddc7461d` | `ecd22a22fb3b3b07d91a472ffa36db62782e2003d994a160854128d52425688d` |
| **DECY-02** | `zein_carved.png` | Berkas Citra Pulih (Klaster 6..11, Decoy Mahasiswa)| 94,651 B | `52b91f060ed4b06f683c3d1bf567f96c` | `12ce476ae8b6b065104692da6a7dbe69512f6cb848989bfff5ec86a3749e0254` |
| **SYS-01**  | `IndexerVolumeGuid` | Berkas Sistem Pelacak Volume Windows | 76 B | `fa1f496156e9c4033b006c641be2cb49` | `2f9fef5a1f6a15e0cb34eb7bc262cf2e09477eb0c804b4070a273295b9c1beea` |
| **SYS-02**  | `WPSettings.dat` | Berkas Pengaturan Volume Windows | 12 B | `708c37d4f9b8c0c46b5a37f53f31505c` | `37d3fa8faee4691456cbb837df05e19747a76e01a8820f4c01d9f0003058fe73` |

---

## 7. PANDUAN REPRODUKSIBILITAS INDEPENDEN (INDEPENDENT VERIFICATION GUIDE)

Untuk memenuhi standar **NIST SP 800-86** dan **ISO/IEC 27037** mengenai *reproducibility* (kemampuan pengujian ulang independen oleh pihak ketiga), langkah-langkah verifikasi dapat dijalankan dengan perintah berikut pada terminal PowerShell:

### 7.1 Ekstraksi Bukti Kasus 1 (Trailing Data JPEG & Carving)
```powershell
# Membaca trailing data JPEG dan melakukan carving klaster unallocated dari flashdisk D:
python "kelompok 5\scripts\extract_evidence.py"

# Menampilkan isi flag yang berhasil dipulihkan
Get-Content "kelompok 5\recovered_files\flag.txt"
Get-FileHash "kelompok 5\recovered_files\flag.txt" -Algorithm SHA256
```

### 7.2 Pemindaian Struktur FAT32 & Validasi Hash
```powershell
# Memindai boot sector dan tabel direktori (entri aktif maupun terhapus 0xE5)
python "kelompok 5\scripts\scan_fat32.py"

# Memverifikasi integritas hash kriptografis seluruh artefak bukti
python "kelompok 5\scripts\verify_hashes.py"
```

---

## 8. PERNYATAAN INTEGRITAS & PENGESAHAN PENYELIDIK (EXAMINER ATTESTATION)

Saya / Tim Penyelidik dari **Kelompok 3** menyatakan dengan sesungguhnya bahwa:
1. Seluruh analisis yang dilaporkan dalam dokumen ini dilakukan dengan berpegang teguh pada prinsip ketidakberpihakan (*impartiality*), ketelitian ilmiah, dan objektivitas forensik.
2. Media fisik barang bukti (`Drive D:\`) diperlakukan secara ketat dengan prinsip *read-only*, tanpa adanya manipulasi, penulisan, atau alterasi data pada drive asli.
3. Seluruh artefak bukti, tangkapan layar, dan nilai hash yang disajikan adalah hasil pengamatan nyata dari proses pemeriksaan digital.

```
Dibuat dan Disahkan di : Surabaya, Indonesia
Tanggal Pengesahan     : 02 Oktober 2026
Tim Penyelidik Kasus   : KELOMPOK 3 (Digital Forensics Investigative Unit)
Lead Investigator      : Arya Refman & Tim Forensik Digital
Status Berkas Kasus    : SOLVED / CLOSED (VERIFIED FOR KELOMPOK 5)
```

---
*Akhir dari Dokumen Laporan Resmi DFIR-2026-FD-KEL5-001.*
