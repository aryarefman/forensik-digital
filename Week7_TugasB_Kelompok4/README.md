# 🔍 Laporan Investigasi Forensik Digital — Tugas B (Kelompok 4 Image)
**Target Image:** `linux_forensic_case.img` (dari repository: [imdfauzan/Fordig-Week7](https://github.com/imdfauzan/Fordig-Week7))  
**Alat Analisis (Tools):** Autopsy 4.23.1 & The Sleuth Kit (TSK)  
**Waktu Analisis:** 18 Oktober 2026  

---

## 1. Informasi Umum Disk Image & Integritas

| Parameter | Keterangan / Nilai |
|---|---|
| **Distribusi File** | `linux_forensic_case.img.gz` (Archive) / `linux_forensic_case.img` (Raw Image) |
| **Filesystem** | Ext4 |
| **Volume Name** | `FORENSIC_CASE` |
| **Ukuran Image** | 268.435.456 bytes (256 MB) |
| **SHA-256 (Archive .gz)** | `a4bf2e4ab4ab43061e27928366ad4d73342d1abc2421d3f1dbe9bf3e1746d01e` (Sesuai `SHA256SUMS-COMPRESSED.txt`) |
| **SHA-256 (Raw .img)** | `2aafa0cef880759743428132c6238dde714e1b747e4a005dc32a4abb45653577` |
| **Waktu Mount Terakhir** | 2026-10-13 12:53:07 WIB pada `/mnt/forensic-case` |

---

## 2. Ringkasan Jawaban Soal Tugas B

### A. Berkas yang Terhapus, Tersembunyi, dan Termodifikasi

| No | Kategori | Nama Berkas & Path | Status Inode & Keterangan |
|---|---|---|---|
| 1 | **Terhapus (Deleted)** | `/project/anggaran_proyek.txt` (terdeteksi di Autopsy sebagai `OrphanFile-16`) | Inode: **16**, Size: **0 byte**, Flags: **Unallocated**. Data block telah dilepas (tidak dapat di-recover kontennya). |
| 2 | **Tersembunyi (Hidden)** | `/project/.catatan.txt` | Inode: **17**, Size: **128 byte**, Flags: **Allocated**. Disembunyikan menggunakan dot prefix (`.`). Berisi catatan internal skenario. |
| 3 | **Termodifikasi (Modified)** | `/project/jadwal_proyek.txt` | Inode: **18**, Size: **132 byte**, Flags: **Allocated**. Diubah dari versi awal pada folder metadata. Deadline diundur secara tidak sah. |

---

### B. Credential / Username yang Melakukan Perubahan & Waktu Kejadian

Berdasarkan analisis file `/evidence/logs/incident.log` dan sinkronisasi metadata inode:

| Aktor (Username) | UID / GID | Aksi | Target Berkas | Waktu Eksekusi (WIB) | Bukti Pendukung |
|---|---|---|---|---|---|
| **`andi`** | 1003 / 1003 | `delete` | `/project/anggaran_proyek.txt` | **2026-10-13 12:56:13** | Catatan `incident.log` baris 1 & timestamps `OrphanFile-16` di Autopsy (Modified/Changed: 12:56:13). |
| **`budi`** | 1004 / 1004 | `modify` | `/project/jadwal_proyek.txt` | **2026-10-13 12:56:28** | Catatan `incident.log` baris 2 & metadata timestamps `jadwal_proyek.txt` (Modified: 12:56:28). |
| **`budi`** | 1004 / 1004 | `hide` | `/project/.catatan.txt` | **2026-10-13 12:56:33** | Catatan `incident.log` baris 3 & isi file `.catatan.txt`: *"Akun terkait: budi"*. |

---

## 3. Detail Temuan & Perbandingan Dokumen

### 3.1 Perbandingan Isi Dokumen Jadwal Proyek (Before vs After)

- **Versi Awal** (`/evidence/metadata/jadwal_versi_awal.txt`):
  ```text
  JADWAL PROYEK PRJ-2026-014
  Rapat awal: 14 Oktober 2026
  Pengumpulan laporan: 20 Oktober 2026
  Persetujuan supervisor: 21 Oktober 2026
  ```
  *(SHA-256: `6bb43bd96d6b0bf7cf27118d26d17b3dccbc527fc885431a552d0557210c042a`)*

- **Versi Termodifikasi** (`/project/jadwal_proyek.txt`):
  ```text
  JADWAL PROYEK PRJ-2026-014
  Rapat awal: 14 Oktober 2026
  Pengumpulan laporan: 25 Oktober 2026
  Persetujuan supervisor: 28 Oktober 2026
  ```
  *(SHA-256: `838d622a0dfabe86a4580846556d542b8d7a4c691bcb7bda54d53dbf3945ee06`)*

**Perubahan yang Dilakukan Budi:**
- Tanggal pengumpulan laporan diundur **5 hari** (20 Okt $\rightarrow$ 25 Okt 2026).
- Tanggal persetujuan supervisor diundur **7 hari** (21 Okt $\rightarrow$ 28 Okt 2026).

---

### 3.2 Isi Berkas Tersembunyi (`/project/.catatan.txt`)
```text
CATATAN INTERNAL
Proyek: PRJ-2026-014
Catatan: Dokumen ini disembunyikan untuk keperluan skenario praktikum.
Akun terkait: budi
```

---

### 3.3 Isi Berkas Catatan Insiden (`/evidence/logs/incident.log`)
```text
2026-10-13T12:56:13+07:00 | actor=andi | action=delete | target=/project/anggaran_proyek.txt
2026-10-13T12:56:28+07:00 | actor=budi | action=modify | target=/project/jadwal_proyek.txt
2026-10-13T12:56:33+07:00 | actor=budi | action=hide | target=/project/.catatan.txt
```

---

## 4. Bukti Tangkapan Layar (Autopsy Screenshots)

Berikut adalah dokumentasi hasil investigasi menggunakan Autopsy 4.23.1 yang tersimpan pada folder `screenshots/`:

1. **File Terhapus (`OrphanFile-16` / `anggaran_proyek.txt`):**  
   ![Deleted Files](screenshots/01_deleted_files_orphan16.png)  
   ![Metadata OrphanFile-16](screenshots/02_orphan16_file_metadata.png)

2. **File Tersembunyi (`.catatan.txt`):**  
   ![Hidden File Content](screenshots/03_catatan_txt_hidden_file.png)  
   ![Metadata Catatan](screenshots/04_catatan_txt_metadata.png)

3. **File Termodifikasi (`jadwal_proyek.txt`):**  
   ![Modified File Content](screenshots/05_jadwal_proyek_modified.png)  
   ![Metadata Jadwal Proyek](screenshots/06_jadwal_proyek_metadata.png)

4. **Bukti Log Insiden (`incident.log`):**  
   ![Incident Log](screenshots/07_incident_log_activity.png)

5. **Bukti Dokumen Pembanding Awal (`jadwal_versi_awal.txt`):**  
   ![Original Document](screenshots/08_jadwal_versi_awal_metadata_evidence.png)
