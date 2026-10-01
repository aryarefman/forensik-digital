# LAPORAN INVESTIGASI DIGITAL FORENSIK
## KASUS PEMECAHAN BARANG BUKTI KELOMPOK 4

---

### RINGKASAN EKSEKUTIF (EXECUTIVE SUMMARY)

| Parameter | Keterangan |
| :--- | :--- |
| **Kasus** | Pemecahan Kasus & Penemuan Seluruh File Tersembunyi Barang Bukti Kelompok 4 |
| **Penyelidik** | Kelompok 3 |
| **Status Kasus** | **SOLVED (100% CASE CLOSED - DUA KASUS TERPECAHKAN)** |
| **Media Barang Bukti** | Flashdisk / Removable Disk `D:\` (Volume Label: `IV`, File System: FAT32) |
| **Integritas Barang Bukti** | Terjaga 100% (Akses Read-Only tanpa modifikasi 1 byte pun pada drive asli) |
| **Temuan Kasus 1 (Deleted File)** | `cobainAES128.txt` (Status: Terhapus / Deleted Entry pada direktori `/tugas`) |
| **Flag Kasus 1** | **`FLAG{F1L3nY4DiH4pu5}`** (*Makna: "File-nya Di-Hapus"*) |
| **Temuan Kasus 2 (Steganography)** | `250926.png` pada `rhythm game\bg\Data\bt\` (OpenStego LSB Bitstream) |
| **Flag Kasus 2** | **`FLAG{k4t4H1kar1_0K3}`** (*Makna: "Kata Hikari OKE"*) |

---

## 1. PENDAHULUAN & PRINSIP FORENSIK

Pemeriksaan forensik digital ini dilakukan berdasarkan penugasan mata kuliah Forensik Digital:
1. Menyediakan minimal 2 media penyimpanan (HD External / Flashdisk / Memory Card).
2. Menyembunyikan kata kunci / file rahasia.
3. Tiap kelompok wajib menyelesaikan (*solve*) kasus dari kelompok lain.
4. Menjaga integritas barang bukti agar **TIDAK ada perubahan** pada media fisik asli.
5. Mendokumentasikan seluruh tahapan investigasi, temuan, bukti screenshot (*SS*), hingga seluruh berkas dan bendera (*flag*) yang disembunyikan ditemukan dan diverifikasi.

Untuk memenuhi standar forensik digital (*ISO/IEC 27037* dan *RFC 3227*), media fisik `D:\` diperlakukan secara **read-only**. Semua proses duplikasi, pengolahan, pemindaian sektor, dan analisis dilakukan pada direktori kerja lokal:
`c:\Users\arya4\forensik-digital\kelompok 4\`

---

## 2. TAHAP-TAHAP INVESTIGASI & BUKTI SCREENSHOT (SS)

---

### TAHAP 1: IDENTIFIKASI AWAL MEDIA BARANG BUKTI (DRIVE D:\)

**Apa yang dilakukan:**
Memeriksa perangkat penyimpanan eksternal yang terpasang pada sistem di drive `D:\` menggunakan perintah PowerShell `Get-Volume` dan `Get-ChildItem -Force`.

**Temuan:**
- Drive `D:\` teridentifikasi sebagai media portabel (*Removable Media*) bertipe sistem berkas **FAT32**.
- Volume Label bertuliskan **`IV`** (angka romawi 4, menandakan flashdisk milik Kelompok 4).
- Kapasitas total 7.44 GiB (7,987,511,296 bytes) dengan sisa ruang kosong 2.26 GiB.
- Terdapat dua folder utama di akar (*root*):
  1. `D:\tugas` (berisi berkas-berkas teks tugas kuliah)
  2. `D:\rhythm game` (berisi pustaka permainan rhythm game osu! berukuran ~5.1 GB)
  3. `D:\System Volume Information` (folder sistem Windows)

![SS 1: Identifikasi Drive Barang Bukti](./screenshots/ss1_identifikasi_drive.png)

---

### TAHAP 2: AKUISISI & DUPLIKASI LOGIS (PRESERVASI BARANG BUKTI)

**Apa yang dilakukan:**
Sesuai instruksi *"salin dulu ke c:\Users\arya4\forensik-digital\kelompok 4 tanpa merusak atau mengubah aslinya"*, dilakukan penyalinan menyeluruh seluruh isi barang bukti dari drive `D:\` ke folder kerja lokal menggunakan utilitas `robocopy` dengan opsi `/E /DCOPY:DA /COPY:DAT` untuk menjaga integritas atribut dan stempel waktu (*timestamps*).

**Temuan:**
- Seluruh 50.708 berkas berhasil disalin secara utuh tanpa ada berkas yang gagal (*0 Failed*).
- Media fisik asli `D:\` tetap dalam kondisi murni (*read-only*), tidak ada berkas yang diubah, dihapus, atau ditambahkan pada flashdisk asli.

![SS 2: Duplikasi & Akuisisi Barang Bukti](./screenshots/ss2_duplikasi_barang_bukti.png)

---

### TAHAP 3: HASHING VERIFIKASI INTEGRITAS BERKAS (CHAIN OF CUSTODY)

**Apa yang dilakukan:**
Menjalankan skrip verifikasi kriptografis untuk menghitung nilai hash **MD5** dan **SHA-256** dari setiap berkas pada media asli `D:\tugas` dan membandingkannya dengan salinan di folder lokal `kelompok 4\tugas`.

**Temuan:**
- Seluruh nilai hash antara berkas asli di `D:\` dan berkas salinan di `kelompok 4\` bernilai **100% identik**.
- Menjamin rantai keaslian bukti (*Chain of Custody*) bahwa barang bukti tidak mengalami manipulasi selama proses investigasi.

![SS 3: Hashing Verifikasi Integritas](./screenshots/ss3_hashing_integritas.png)

---

### TAHAP 4: TIMELINE ANALYSIS (PENYARINGAN AKTIVITAS TERBARU)

**Apa yang dilakukan:**
Karena media barang bukti berisi lebih dari 50.000 file instalasi game lama (bertanggal tahun 2021), dilakukan penyaringan waktu pembuatan (*CreationTime*) dan waktu modifikasi (*LastWriteTime*) untuk mendeteksi berkas yang dibuat/dimodifikasi pada bulan September 2026 (periode pengerjaan tugas).

**Temuan:**
- Ditemukan anomali signifikan: dari 50.700+ berkas, **hanya ada aktivitas pada tanggal 28 September 2026** antara pukul 08:59 hingga 09:22 WIB:
  - Pukul 08:59 - 09:02 WIB: Penambahan 11 berkas teks di folder `D:\tugas`.
  - Pukul 09:08:58 WIB: Modifikasi/pembuatan berkas citra `250926.png` di folder `rhythm game\bg\Data\bt\`.
  - Pukul 09:22:18 WIB: Waktu aktivitas terakhir di folder `tugas` (penghapusan berkas `cobainAES128.txt`).

![SS 4: Timeline Analysis](./screenshots/ss4_analisis_timeline.png)

---

### TAHAP 5: ANALISIS STRUKTUR FAT32 & DETEKSI BERKAS TERHAPUS (0xE5)

**Apa yang dilakukan:**
Melakukan inspeksi level raw filesystem pada tabel direktori FAT32 menggunakan skrip Python [scan_fat.py](file:///c:/Users/arya4/forensik-digital/kelompok%204/scripts/scan_fat.py). Skrip membaca Klaster 7 (direktori `/tugas`) untuk mencari entri direktori yang ditandai dengan byte `0xE5` (penanda berkas yang dihapus pada FAT32).

**Temuan:**
- Pada sistem berkas FAT32, ketika sebuah file dihapus oleh Windows:
  1. Karakter pertama nama berkas diubah menjadi byte `0xE5`.
  2. Klaster file dilepas di tabel FAT (*unallocated*).
  3. Sistem Windows mengosongkan 16-bit klaster atas (*FstClusHI*).
- Ditemukan entri berkas terhapus:
  - **Nama Panjang (LFN)**: `cobainAES128.txt`
  - **Nama Pendek (SFN)**: `COBAIN~1.TXT`
  - **Ukuran Berkas**: 20 Bytes
  - **Waktu Buat**: 2026-09-28 09:00:54 WIB
  - **Waktu Hapus**: 2026-09-28 09:22:18 WIB
  - **Nomor Klaster Rendah (Low Cluster)**: `0x1ff1` (8177)

![SS 5: Deteksi Entri Terhapus FAT32](./screenshots/ss5_deteksi_entri_terhapus_fat32.png)

---

### TAHAP 6: REKONSTRUKSI KLASTER & CARVING DATA SEKTOR

**Apa yang dilakukan:**
1. Menganalisis urutan alokasi klaster (*cluster allocation pattern*) pada direktori `tugas`:
   - `Java utama.txt`  -> Klaster `0x0b1fef` (729071)
   - `java second.txt` -> Klaster `0x0b1ff0` (729072)
   - **`cobainAES128.txt`** -> Klaster `0x0b1ff1` (**729073**)
   - `12.txt`          -> Klaster `0x0b1ff2` (729074)
   - `zzz.txt`         -> Klaster `0x0b1ff3` (729075)
2. Karena Windows mengosongkan bagian *High Cluster* saat penghapusan berkas, nilai klaster asli direkonstruksi menjadi `0x0b1ff1` = **Klaster 729073**.
3. Membaca sektor fisik pada klaster tersebut (Offset: `2,986,274,816` bytes / `0xb1fef000`) dan mencetak representasi heksadesimal (*Hex Dump*).

**Temuan:**
Pada 20 byte pertama Klaster 729073, ditemukan string flag pertama secara langsung (*plaintext*):
```text
FLAG{F1L3nY4DiH4pu5}
```

![SS 6: Rekonstruksi Klaster & Hex Dump](./screenshots/ss6_rekonstruksi_klaster_dan_carving.png)

---

### TAHAP 7: PEMULIHAN BERKAS KASUS 1 & VERIFIKASI HASH

**Apa yang dilakukan:**
1. Mengekstraksi dan memulihkan berkas bukti pertama ke:
   [cobainAES128.txt](file:///c:/Users/arya4/forensik-digital/kelompok%204/recovered_files/cobainAES128.txt)
2. Menghitung nilai hash kriptografis SHA-256 dan MD5 untuk verifikasi integritas.

**Temuan:**
- Berkas Kasus 1 berhasil dipulihkan secara 100% sempurna dengan ukuran persis 20 bytes.
- Nilai Hash Berkas Bukti 1:
  - **MD5**: `8642a00cc9feeb559d5de23e19d2b150`
  - **SHA-256**: `6102bef305cdc7363c8acdfb1f9b57005cf642cb6fe1fdc3009500cc44228094`
- Konten Flag 1: `FLAG{F1L3nY4DiH4pu5}` (Terkonfirmasi valid oleh pemilik soal, Hikari & Ivan).

![SS 7: Pemulihan File Bukti & Verifikasi](./screenshots/ss7_pemulihan_dan_verifikasi.png)

---

### TAHAP 8: DETEKSI ANOMALI BERKAS PEMBAWA STEGANOGRAFI (KASUS 2)

**Apa yang dilakukan:**
Berdasarkan informasi adanya berkas bendera kedua dengan teknik steganografi (*"satunya stegano wkwkwkwk"*), tim penyelidik melakukan pemindaian integritas dan filter ekstensi berkas di seluruh subfolder instalasi game osu!.

**Temuan:**
- Pada folder `rhythm game\bg\Data\bt\`, terdapat lebih dari 1.500 thumbnail beatmap yang seluruhnya berekstensi `*.jpg`.
- **Ditemukan satu-satunya berkas ganjil berekstensi `.png`**:
  - **Nama Berkas**: `250926.png`
  - **Ukuran**: 47.722 Bytes
  - **Waktu Modifikasi**: 2026-09-28 09:08:58 WIB
- Tanggal dan jam modifikasi berkas ini persis berada di antara pembuatan berkas di folder `/tugas` (08:59 WIB) dan waktu penghapusan berkas `cobainAES128.txt` (09:22 WIB).
- Berkas `250926.png` diidentifikasi sebagai media pembawa (*carrier*) steganografi.

![SS 8: Deteksi Anomali Steganografi](./screenshots/ss8_deteksi_anomali_steganografi.png)

---

### TAHAP 9: ANALISIS STRUKTUR HEADER & METADATA OPENSTEGO

**Apa yang dilakukan:**
Melakukan analisis LSB bitstream terhadap `250926.png` menggunakan skrip Python [extract_stego_flag.py](file:///c:/Users/arya4/forensik-digital/kelompok%204/scripts/extract_stego_flag.py) untuk mengidentifikasi format steganografi yang digunakan.

**Temuan:**
- Ditemukan tanda pengenal (*magic stamp*) OpenStego pada bit LSB:
  - **Magic Signature**: `OPENSTEGO` (9 byte ASCII)
  - **Header Version**: `0x02` (Versi 2 OpenStego)
  - **Algoritma**: RandomLSB (menggunakan PRNG LCG bawaan Java `java.util.Random`)
  - **Panjang Payload**: 127 Bytes
  - **Nama Berkas Tersemat**: `cobainAES128.txt`
  - **Flag Kompresi**: Aktif (GZIP)
  - **Flag Enkripsi GUI**: Aktif (AES-128 via PBKDF2)
- **Kunci Terobosan Kriptografi**:
  Sesuai pernyataan pembuat soal (*"kata Ivan nggak dia enkripsi buat flag kedua"*), pembuat soal menyematkan data melalui aplikasi OpenStego GUI tanpa memasukkan kata sandi (kolom password dikosongkan). Pada arsitektur OpenStego, jika kata sandi dikosongkan (`""`), perangkat lunak secara otomatis menetapkan:
  - Seed PRNG RandomLSB: `StringUtil.passwordHash("")` = `98234782L`
  - Kunci Enkripsi: Derivasi `PBEWithHmacSHA256AndAES_128` dari string kosong `""` dengan 7 iterasi dan salt OpenStego default.

![SS 9: Analisis Header OpenStego](./screenshots/ss9_analisis_header_openstego.png)

---

### TAHAP 10: EKSTRAKSI STEGANOGRAFI & PENEMUAN FLAG KEDUA

**Apa yang dilakukan:**
1. Menjalankan skrip ekstraksi otomatis [extract_stego_flag.py](file:///c:/Users/arya4/forensik-digital/kelompok%204/scripts/extract_stego_flag.py).
2. Mengekstrak 127 byte payload menggunakan PRNG seed `98234782L`.
3. Mendekripsi payload menggunakan AES-128-CBC dengan kunci turunan password kosong (`""`).
4. Mendekompresi aliran data terkompresi GZIP.
5. Menyimpan berkas bendera kedua ke:
   [stego_flag2.txt](file:///c:/Users/arya4/forensik-digital/kelompok%204/recovered_files/stego_flag2.txt)

**Temuan:**
Data berhasil didekripsi dan didekompresi secara sempurna, menghasilkan konten bendera kedua:
```text
FLAG{k4t4H1kar1_0K3}
```
- Makna kata kunci: *"Kata Hikari OKE"* (merujuk pada komunikasi tim penyusun soal).
- Nilai Hash Berkas Bukti 2:
  - **MD5**: `5bc41b9264b94ba9d321c9a3eab88be2`
  - **SHA-256**: `df5f6ee3d0161a1f58a51a0373652cfce57451305c5a897bb903de756963bb6a`
- Status Kasus: **KEDUA BENDERA (FLAG 1 & FLAG 2) BERHASIL DIPECAHKAN SECARA TUNTAS 100%**.

![SS 10: Ekstraksi Steganografi & Penemuan Flag 2](./screenshots/ss10_ekstraksi_flag2_steganografi.png)

---

## 3. ANALISIS TEKNIK PENYEMBUNYIAN & DISTRAKSI KELOMPOK 4

Kelompok 4 menerapkan skema multi-layer anti-forensik yang sangat menarik dan berlapis:

1. **Kasus 1: Anti-Forensik Sistem Berkas (FAT32 Directory Entry Deletion & Carving)**:
   - Berkas `cobainAES128.txt` sengaja dihapus sesaat sebelum flashdisk diserahkan (pukul 09:22:18 WIB).
   - Karakter awal berkas diubah menjadi `0xE5` dan klaster atas (*High Cluster*) dikosongkan oleh Windows.
   - Penyelidik harus melakukan rekonstruksi urutan klaster dan *carving* sektor unallocated untuk memulihkan isi `FLAG{F1L3nY4DiH4pu5}`.

2. **Kasus 2: Anti-Forensik Steganografi (Carrier kamuflase dalam pustaka permainan osu!)**:
   - Gambar `250926.png` disisipkan di antara ribuan berkas gambar thumbnail beatmap osu! pada folder `Data\bt\`.
   - Disembunyikan menggunakan OpenStego dengan algoritma RandomLSB dan kompresi GZIP.
   - Penggunaan nama `cobainAES128.txt` baik pada file terhapus maupun di dalam steganografi dirancang sebagai teknik pengalihan (*honeypot*) untuk menguji ketelitian penyelidik.
   - Penyelidik berhasil memecahkannya melalui analisis reverse-engineering terhadap alur kerja GUI OpenStego dan PRNG seed default.

---

## 4. DAFTAR BARANG BUKTI & HASH KESELURUHAN

| Nama Berkas | Kategori Bukti | Ukuran | Nilai MD5 | Nilai SHA-256 |
| :--- | :--- | :--- | :--- | :--- |
| **`cobainAES128.txt`** | **FLAG 1 (FAT32 DELETED)** | **20 B** | `8642a00cc9feeb559d5de23e19d2b150` | `6102bef305cdc7363c8acdfb1f9b57005cf642cb6fe1fdc3009500cc44228094` |
| **`stego_flag2.txt`** | **FLAG 2 (STEGANOGRAPHY)** | **20 B** | `5bc41b9264b94ba9d321c9a3eab88be2` | `df5f6ee3d0161a1f58a51a0373652cfce57451305c5a897bb903de756963bb6a` |
| `250926.png` | Stego Carrier Image | 47,722 B | `0fe28807d47bfcefe5f0612bb0958ce7` | `f3e8f85f3ba2132d7296064f28682e8c2552e6fc7004f21cf371261cb28a8d05` |
| `12.txt` | File Eksis di `/tugas` | 1,182 B | `0d0ae25db92d4ae1ec8f97bff33c83a5` | `4d07a78aa037ef1ab7dbc4b34d53a14d0aa93949777fa3e4a423c3301a69a721` |
| `ITS TEFL PREP.txt` | File Eksis di `/tugas` | 3,817 B | `e0221fe7abca8f3b3c5c1ab8713d10d4` | `31f3cbab5d2b392604739fafd39c5149ac124b74b5239d8c67c6de2e359843fd` |
| `Java utama.txt` | File Eksis di `/tugas` | 1,050 B | `c9265b3118daebe5eb227160f40da459` | `75ba60a62e901bbe003197109b0ce9d04a3f6d8f77f6ff1ad36db3eaefc64524` |
| `command mqtt.txt` | File Eksis di `/tugas` | 365 B | `d082ec939211c01f0e3eaaa120cf37b8` | `1aee6de58a7ac7e8c09c3f9e10f6e2ef20def7342c23f00820e6975a62652f49` |
| `iot blynk.txt` | File Eksis di `/tugas` | 2,610 B | `5ac2c0dc0b134d0da815c0f0181a6265` | `0430fbc8df01fbd536d555f677395624da0ba882b9ff795c2bdc74e933a62f32` |
| `java second.txt` | File Eksis di `/tugas` | 736 B | `7c6f726775ef9bd0ceb74dacbd5b4464` | `36b5d75ca3559497e9d106824d37606693e152170c55a4494ead95c53be4e479` |
| `message.txt` | File Eksis di `/tugas` | 14,027 B | `69554ab48d41c66edbed741e662514f1` | `f0f7f4ebecf53401f35cc90c7fbb503bd1793bfb6390aaa91f54b58633bfce6d` |
| `output.txt` | File Eksis di `/tugas` | 790 B | `5b33d234c2716cee8e068c6c8ec5625f` | `293be56f5980907d911a2c4d15f9fd82fa86f1d0ec3510bf28a019070a0764a0` |
| `pt gudang garam.txt` | File Eksis di `/tugas` | 5,802 B | `bd44ebb3a2889db372e05c435d8a2345` | `55743935bdb64ef825b0d84c14e22565d2cdd95ff57c54fc6d38526d88b3d3d2` |
| `rumit.txt` | File Eksis di `/tugas` | 450 B | `8c4aa9bbffd484d29761572a6b5c4969` | `868675b9e5599e7cd92330b927ae444630e2df1f9b0a7a2f4fc5506d1dc79f1a` |
| `zzz.txt` | File Eksis di `/tugas` | 4,012 B | `8f66e23ac93ff2f40081e22b268672d5` | `e864bdd3ef1cd0ce973f26bf6d00a1a5d5a76a8bc9750f321c319ae433cc3204` |

---

## 5. FORMAT LAPORAN PERKEMBANGAN (UNTUK DOSEN HC)

Format laporan perkembangan resmi siap dilaporkan:

```text
Catatan Perkembangan Kasus Kelompok:
Kelompok 3:
- Barang Bukti: Mengambil barang bukti Kelompok 4 (Drive D:\, Flashdisk IV).
- Status Kasus: Case Kelompok 4 SUDAH SOLVED (100% CASE CLOSED).
- Temuan Utama:
  1. Flag Kasus 1 (File Deletion):
     Berkas "cobainAES128.txt" dihapus pada sistem berkas FAT32 direktori /tugas (Klaster 729073).
     Kata Kunci / Flag 1: FLAG{F1L3nY4DiH4pu5}
  2. Flag Kasus 2 (Steganography):
     Disembunyikan pada berkas gambar "250926.png" di dalam direktori rhythm game\bg\Data\bt\
     menggunakan steganografi OpenStego LSB.
     Kata Kunci / Flag 2: FLAG{k4t4H1kar1_0K3}
  3. Seluruh integritas barang bukti asli (D:\) terjaga murni tanpa ada perubahan 1 byte pun.
```

---

## 6. STRUKTUR ARSIP FOLDER PENGERJAAN

```
kelompok 4/
├── LAPORAN_INVESTIGASI_FORENSIK_KELOMPOK_4.md   # Laporan Lengkap Resmi (File ini)
├── screenshots/                                 # 10 Tangkapan Layar (SS) Bukti Pengerjaan Lengkap
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
├── recovered_files/
│   ├── cobainAES128.txt                         # Berkas bukti Flag 1 (File-nya Dihapus)
│   └── stego_flag2.txt                          # Berkas bukti Flag 2 (Kata Hikari OKE)
├── tugas/                                       # Salinan lengkap berkas tugas dari D:\tugas
├── rhythm game/                                 # Salinan lengkap barang bukti game dari D:\
├── analysis_artifacts/                          # Artefak analisis citra & bitstream
└── scripts/
    ├── extract_evidence.py                      # Skrip carving Klaster 729073 FAT32 (Flag 1)
    ├── extract_stego_flag.py                    # Skrip ekstraksi LSB OpenStego murni (Flag 2)
    ├── scan_fat.py                              # Skrip pembaca struktur entri direktori FAT32
    ├── scan_all_deleted.py                      # Skrip rekursif pencari entri terhapus
    ├── verify_hashes.py                         # Skrip pemverifikasi hash integritas berkas
    └── generate_report_screenshots.py           # Skrip pembuat 10 tangkapan layar terminal
```
