# 🚨 KASUS INVESTIGASI FORENSIK DIGITAL — KELOMPOK 3
## Kasus: *Insiden Pelanggaran Keamanan & Pembocoran Data Workstation Nusa Meridian*
### Subjek Barang Bukti untuk Kelompok 4 (Tugas B)
**Klasifikasi:** CONFIDENTIAL / FORENSIC EVIDENCE  
**Penyedia Barang Bukti:** **Kelompok 3** (Ganjil)  
**Mitra Penyelidik (Examiner):** **Kelompok 4** (Genap)  
**Format Citra Bukti:** RAW DD Image (`.raw`) & Microsoft Fixed VHD (`.vhd`)  
**Label Volume:** `WIN_EVD_K3` | **Sistem Operasi Asal:** Windows 11 Enterprise (64-bit)

---

## 📌 1. Skenario Insiden (Incident Scenario)

Pada tanggal **12 Oktober 2026**, divisi keamanan siber internal (*Security Operations Center* / SOC) perusahaan **Nusa Meridian Corp** mendeteksi anomali pada salah satu stasiun kerja infrastruktur utama dengan hostname **`NUSA-WS-K3`**. 

Berdasarkan telemetri jaringan, terjadi upaya transfer data mencurigakan ke entitas lepas pantai (*offshore entity*) serta modifikasi konfigurasi pengamanan gateway. Tak lama setelah deteksi anomali, sistem mendeteksi aktivitas pembersihan jejak (*anti-forensics evidence elimination*) yang diduga dilakukan oleh orang dalam (*insider threat*) dengan hak akses administratif.

Tim Tanggap Insiden (*Incident Response*) segera melakukan isolasi logis dan akuisisi bit-stream forensik terhadap volume penyimpanan sistem kerja tersebut. Citra bukti forensik berlabel **`WIN_EVD_K3`** kini diserahkan kepada **Tim Penyelidik Forensik Kelompok 4** untuk diinvestigasi secara mendalam sesuai standar **ISO/IEC 27037:2012** dan **NIST SP 800-86**.

---

## 🎯 2. Sasaran Investigasi (Objectives Tugas B)

Sebagai tim pemeriksa forensik independen, **Kelompok 4** diwajibkan untuk:

1. **Menemukan dan memulihkan berkas yang sengaja DIHAPUS (*Deleted File*)**:
   - Pulihkan berkas dokumen rahasia yang telah dihapus dari direktori stasiun kerja.
   - Temukan kata kunci rahasia / format flag: `FLAG{...}` di dalamnya.
   - Jelaskan metode teknis pemulihan (*unallocated space carving* / tabel entri direktori terhapus `0xE5`).

2. **Menemukan berkas yang DISEMBUNYIKAN (*Hidden File*)**:
   - Identifikasi berkas kritis yang disembunyikan menggunakan atribut khusus sistem operasi Windows (`+h +s`).
   - Ekstraksi konten berkas dan dapatkan flag: `FLAG{...}` di dalamnya.
   - Jelaskan lokasi path direktori dan teknik anti-forensik yang diterapkan pelaku.

3. **Menemukan berkas yang TERMODIFIKASI (*Modified File*)**:
   - Temukan berkas konfigurasi sistem yang telah diinjeksi atau dirusak secara tidak sah.
   - Temukan kata kunci modifikasi / flag: `FLAG{...}` di dalamnya.
   - Analisis perbedaan (*diff*) serta indikator kompromi (*Indicator of Compromise* / IoC).

4. **Identifikasi Kredensial Pelaku (*Attributed Username & Identity*)**:
   - Siapa kredensial / username (*operator account*) yang digunakan untuk mengeksekusi tindakan-tindakan di atas?
   - Temukan identitas domain dan nomor pengenal keamanan (*Security Identifier* / SID) milik akun tersebut.

5. **Rekonstruksi Garis Waktu (*Timeline & Timestamps Reconstruction*)**:
   - Kapan tepatnya masing-masing insiden terjadi?
     - Waktu logon interaktif pelaku.
     - Waktu penghapusan berkas rahasia.
     - Waktu penyembunyian berkas brankas sistem.
     - Waktu modifikasi konfigurasi keamanan.
   - Cantumkan bukti penguat berupa nomor rekaman log audit (*Windows Event Log ID*) dan jejak riwayat konsol perintah (*PowerShell history transcript*).

---

## 🔐 3. Rantai Bukti & Integritas Kriptografis (Chain of Custody)

Sebelum melakukan analisis, pastikan integritas citra bukti sesuai 100% dengan nilai hash resmi berikut:

| Parameter Bukti | Berkas RAW (`.raw`) | Berkas VHD (`.vhd`) |
| :--- | :--- | :--- |
| **Nama Berkas** | `evidence_windows_kelompok3.raw` | `evidence_windows_kelompok3.vhd` |
| **Ukuran** | 268.435.456 Bytes (256 MiB) | 268.435.968 Bytes (256 MiB) |
| **Format** | Raw DD Bitstream (MBR + FAT32 LBA) | Microsoft Fixed Virtual Hard Disk |
| **MD5** | `615e27fa50a4ee9c3e572adf52aa9c6f` | `caa440b906c5faff6a37eb53d5ec77c7` |
| **SHA-1** | `76ff89233d5399728738e7193505ad326d10d73b` | `0e2251812f3a245129b7baec3b8780b5602a0169` |
| **SHA-256** | `f7d5a14124dab46db67ed35e25572442ceacf328bbca852ccbcb613b9eaa5086` | `c05779484da6a583bc53c92b64a5e13987842b0541b80bb996caacf848c99153` |

> 📦 **Paket Arsip Distribusi:**  
> - Nama Berkas: `Fordig_Image_Windows_Kelompok3.zip` (~0.51 MB)  
> - SHA-256: `b04fb5ebaffae000ab084f38835f377aa7e523df7d2c69cce112544239eeee48`

---

## 🛠️ 4. Panduan & Alat Uji yang Disarankan

Investigator Kelompok 4 dapat menggunakan perangkat lunak standar forensik digital:
- **Autopsy Digital Forensics Platform** (v4.20+)
- **AccessData FTK Imager** (Mounting / Logical Tree Export)
- **The Sleuth Kit (TSK)** (`fls`, `icat`, `fsstat`, `srch_strings`)
- **OSForensics / WinHex / HxD**
- **Native Windows Explorer** (Khusus berkas `.vhd`, dapat langsung di-mount dengan klik ganda)

---

## 📝 5. Format Pengumpulan Laporan Tugas B

Laporan investigasi dari Kelompok 4 wajib mencakup:
1. Ringkasan Eksekutif & Identifikasi Bukti (*Case Summary & Evidence Hashing*).
2. Metodologi Investigasi & Alat yang Digunakan.
3. Tabel Temuan Berkas (Nama berkas, status, lokasi direktori, dan nilai `FLAG{...}`).
4. Bukti Kredensial (Username, SID, Domain).
5. Rekonstruksi Kronologi / Timeline Insiden secara detail beserta bukti screenshot / log.
