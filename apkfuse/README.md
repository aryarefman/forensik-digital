# APKFuse — Environment Lab & Network Capture

Pada lab ini terdapat custom script Python untuk mount APK secara read-only dan
menjalankan emulator dengan FUSE overlay. Dari environment ini, proses dynamic
analysis dan capturing traffic dapat dilakukan tanpa install APK ke perangkat
utama. Sampel asli ada pada [undangan-g03.zip](undangan-g03.zip).

Objective lab ini mencakup dua hal:

1. Reverse engineering APK untuk mengetahui flow komunikasi ke C2, kemudian
   menjalankan APK dan membaca flag dari respons server.
2. Hardening system pada environment analisis, dengan mengecek isolasi proses,
   akses filesystem, dan jalur network yang digunakan selama APK berjalan.

Jadi, hasil yang dicatat mencakup flag beserta bukti traffic, lalu hasil
pengecekan isolasi lab. Flag yang didapat belum menunjukkan bahwa semua kontrol
keamanan environment sudah berjalan sesuai kebutuhan.

Semua command di bawah dijalankan dari **root repository**, yaitu folder yang
berisi `apkfuse/`. Untuk command `python -m apkfuse.lab`, posisi terminal tetap
di root tersebut.

## 1. Alur environment & isolasi

Pada [lab.py](lab.py), setiap sampel memiliki folder kasus sendiri. ID kasus
diambil dari 12 karakter awal SHA-256 APK.

| Path | Keterangan |
| --- | --- |
| `cases/<case>/static/` | Mount APK dari [fs.py](fs.py). Terdapat file asli, manifest yang sudah di-decode, indeks DEX, dan report. |
| `cases/<case>/env/` | Environment emulator dari `fuse-overlayfs`, dengan golden image sebagai lower layer. |
| `cases/<case>/upper/` | Perubahan pada environment emulator selama run. Folder ini tetap ada setelah lab berhenti. |
| `cases/<case>/out/` | Hasil PCAP, flow mitmproxy, logcat, dan log proses lab. |

Untuk network capture, interface yang digunakan adalah **`lo` di dalam network
namespace emulator**. FUSE sendiri merupakan filesystem. Script lab menjalankan
`tcpdump` pada namespace tersebut, kemudian hasil `netns.pcap` diteruskan ke
Wireshark.

```text
APK asli ── APKFuse ── static/               analisis statis
golden/ + upper/ ── fuse-overlayfs ── env/   penyimpanan emulator

Emulator Android
  └─ proxy TCP :8080 / DNS :53 di namespace lab
       ├─ tcpdump pada lo ── netns.pcap ── pipe ── Wireshark
       └─ bridge socket Unix ── mitmproxy pada host ── jaringan tujuan
```

Pada mode normal, koneksi keluar melalui bridge proxy/DNS ke mitmproxy di host.
Gunakan jaringan analisis yang diizinkan. Jika memakai `--offline`, bridge proxy
dan DNS ke host tidak dibuat.

Capture ini mencatat traffic yang masuk ke jalur proxy/DNS tersebut. Paket pada
virtual NIC Android, UDP lain, atau koneksi yang mengabaikan proxy belum tentu
terlihat pada PCAP ini. Traffic ADB di port `5555` juga dikecualikan oleh script.

### Bagian hardening yang perlu dicek

Pada mount APK terdapat opsi `ro,nosuid,nodev,noexec`. Cek apakah opsi ini aktif,
operasi tulis ditolak, dan hash APK tetap sama. Pada emulator, perubahan
filesystem seharusnya masuk ke `upper/`, sehingga golden image dapat dipakai
sebagai dasar untuk run berikutnya.

Isolasi proses dan path host diatur pada `_ns_argv()` dan `_bwrap_argv()` dalam
[lab.py](lab.py). Bagian ini perlu diuji dari sandbox emulator: cek proses yang
terlihat, path yang dapat diakses, dan apakah aksesnya sesuai bind mount yang
dibuat. Simpan hasilnya bersama log run dan capture.

Untuk network, mode normal saat ini belum memiliki **allowlist tujuan C2**.
Traffic melalui proxy masih dapat menuju alamat lain yang bisa dijangkau host.
Script juga membuka `/etc` dan `/sys` secara read-only, memberi akses ke
`/dev/kvm`, dan meneruskan socket X11 jika emulator dijalankan dengan GUI.
Akses ini tetap perlu diperhitungkan saat menilai isolasi lab.

Jika dilanjutkan untuk hardening, bagian yang perlu diperketat antara lain
tujuan egress, path/perangkat host yang dipetakan, kebijakan syscall, dan batas
resource. Kontrol tambahan tersebut belum dikonfigurasi di sini. Penjelasan
mengenai pengaturan sandbox ada pada
[dokumentasi bubblewrap](https://github.com/containers/bubblewrap#sandbox-security).

## 2. Environment & Tooling — Host

Setup ini menggunakan **Arch Linux x86_64**, mengikuti path `/usr`, `/lib`, dan
`/lib64` yang dipakai script. Pastikan `/dev/kvm`, `/dev/fuse`, serta user/network
namespace dapat digunakan. Jika host berupa VM, akses KVM juga bergantung pada
nested virtualization dari hypervisor.

Clone repository jika belum tersedia:

```bash
git clone --filter=blob:none --sparse https://github.com/aryarefman/forensik-digital.git
cd forensik-digital || exit
git sparse-checkout set apkfuse
```

Install dependency host:

```bash
sudo pacman -S --needed base-devel python python-pip \
  fuse3 fuse-overlayfs bubblewrap socat iproute2 util-linux procps-ng \
  tcpdump wireshark-qt wireshark-cli jdk21-openjdk openssl unzip \
  libx11 libxcb libxkbcommon-x11 libpulse nss mesa
```

Paket Wireshark GUI dan CLI tersedia di
[repository Arch](https://archlinux.org/packages/extra/x86_64/wireshark-qt/).
Tambahkan user ke grup capture, kemudian logout/login agar perubahan grup
berlaku:

```bash
sudo gpasswd -a "$(id -un)" wireshark
```

Pengaturan grup mengikuti
[panduan capture privileges Wireshark](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges#arch-linux-and-derivatives).
Untuk Java, pastikan command `java` tersedia di `/usr/bin`. Sandbox membersihkan
environment sebelum menjalankan `avdmanager`.

Cek akses perangkat dan namespace:

```bash
java -version
test -r /dev/kvm && test -w /dev/kvm && echo "KVM dapat diakses"
test -r /dev/fuse && test -w /dev/fuse && echo "FUSE dapat diakses"
test -w "/run/user/$(id -u)" && echo "Runtime directory tersedia"
unshare --user --map-root-user --net --pid --fork true
```

Jika ada pengecekan yang gagal, periksa izin perangkat atau konfigurasi
namespace terlebih dahulu. Jalankan lab dari sesi login user biasa agar
`/run/user/<uid>` tersedia. Untuk kebutuhan KVM, lihat
[dokumentasi akselerasi emulator](https://developer.android.com/studio/run/emulator-acceleration).

## 3. Setup Python environment

Versi yang tersedia pada environment pengecekan: Python `3.14.7`, pyfuse3
`3.5.0`, Trio `0.34.0`, dan mitmproxy `12.3.1`. Jika memakai versi interpreter
lain, cek kembali kompatibilitas dependency-nya.

```bash
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install \
  'pyfuse3==3.5.0' 'trio==0.34.0' 'mitmproxy==12.3.1'

.venv/bin/python -m apkfuse --help
.venv/bin/python -m apkfuse.lab --help
```

Script menggunakan binding [pyfuse3](https://github.com/libfuse/pyfuse3).
Untuk build, diperlukan header libfuse3, compiler, dan `pkg-config`; detailnya
ada pada [dependency pyfuse3](https://www.rath.org/pyfuse3-docs/install.html).

## 4. Setup Android SDK

Download **Command line tools only → Linux** dari
[halaman Android Studio](https://developer.android.com/studio#command-line-tools-only).
Masukkan path ZIP hasil download ketika diminta. Jika
`base/sdk/cmdline-tools/latest/bin/avdmanager` sudah ada, bagian ekstraksi ini
bisa dilewati.

```bash
read -r -p "Lokasi ZIP Android Command-Line Tools Linux: " LAB_SDK_TOOLS_ZIP
test -f "$LAB_SDK_TOOLS_ZIP"
LAB_SDK_TMP="$(mktemp -d)"
mkdir -p base/sdk/cmdline-tools
unzip -q "$LAB_SDK_TOOLS_ZIP" -d "$LAB_SDK_TMP"
mv "$LAB_SDK_TMP/cmdline-tools" base/sdk/cmdline-tools/latest
rmdir "$LAB_SDK_TMP"
```

Setelah itu, setujui lisensi dan install package SDK:

```bash
base/sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root="$PWD/base/sdk" --licenses
base/sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root="$PWD/base/sdk" \
  'platform-tools' 'emulator' 'system-images;android-33;google_apis;x86_64'

test -x base/sdk/platform-tools/adb
test -x base/sdk/cmdline-tools/latest/bin/avdmanager
base/sdk/emulator/emulator -accel-check
```

System image yang digunakan adalah `google_apis` API 33 x86_64, sesuai
`SYSTEM_IMAGE` pada `lab.py`. Image ini diperlukan untuk proses `adb root`
saat memasang CA; jangan diganti dengan image Google Play. Path SDK tetap di
`base/sdk/` karena script mengacu ke lokasi tersebut.

Untuk syntax package dan `--sdk_root`, lihat
[dokumentasi sdkmanager](https://developer.android.com/tools/sdkmanager).

## 5. Cek Hash Integrity & flow APK

Ekstrak APK asli dari ZIP. Arsip ini berisi satu file `undangan-g03.apk`.

```bash
mkdir -p samples
unzip -n apkfuse/undangan-g03.zip -d samples
printf '%s  %s\n' \
  '0ece697fcdbb4b8306365db7d76e053a96276424ee87a99e0e94cd790907e4b3' \
  'samples/undangan-g03.apk' | sha256sum -c -
```

Hasil pengecekan seharusnya menampilkan `samples/undangan-g03.apk: OK`.

Pada **setiap terminal baru**, masuk ke root repository lalu set variabel
berikut agar command mengarah ke kasus yang sama:

```bash
LAB_APK="$PWD/samples/undangan-g03.apk"
LAB_CASE="$(sha256sum "$LAB_APK" | cut -c1-12)"
LAB_OUT="$PWD/cases/$LAB_CASE/out"
```

Untuk APK ini, nilai `LAB_CASE` adalah `0ece697fcdbb`.

### Core findings dari reverse engineering

Pada [APK asli](undangan-g03.zip), `MainActivity.onCreate()` memanggil `sync()`
yang terdapat di `classes3.dex`. Dari hasil dekompilasi kelas ini dan
`BuildConfig`, terlihat alur request berikut:

1. Endpoint diambil dari `BuildConfig.C2`, lalu aplikasi menggunakan **POST
   Method** dengan `Content-Type: application/json`.
2. Body request berisi `chat_id`, `text`, dan `model`. Nilai pada sampel asli
   adalah `chat_id: g03`, `text: g03 online`, serta model dari `Build.MODEL`.
3. Respons dibaca dari field `result.text`, kemudian dicatat pada logcat dengan
   awalan `payload=`. Pada challenge ini, flag didapat dari respons tersebut.

POST dikirim otomatis oleh APK ketika activity dijalankan. Dari proses reverse
engineering, kita mengetahui tujuan dan bentuk request-nya, lalu mencocokkan
hasil dynamic analysis dengan capture. Mengirim POST secara manual dari host
saja belum memperlihatkan perilaku APK di dalam environment lab.

Server C2 harus dapat dijangkau dan menerima body request yang sesuai. Membuka
URL-nya dengan GET dari browser tidak menjalankan flow yang sama. Jika memakai
`--offline`, perilaku tanpa koneksi keluar masih bisa diperiksa, tetapi flag
dari respons C2 tidak dapat diambil pada run tersebut.

Flow yang diikuti: **reverse engineering APK → running APK → POST ke C2 →
capture respons → cek flag dan logcat**. Selama proses ini, hasil pengecekan
hardening juga tetap dicatat.

## 6. Init lab — Golden image

Jalankan sekali untuk menyiapkan dasar environment:

```bash
.venv/bin/python -m apkfuse.lab init --headless
```

Proses ini membuat AVD `lab`, kunci ADB khusus lab, dan CA mitmproxy. CA dipasang
ke image Android, lalu emulator golden dimatikan. Tunggu sampai terdapat pesan
`golden image ready in .../base/golden`.

Jika golden image sudah tersedia, langsung lanjut ke langkah berikutnya.
`init --force` digunakan jika memang ingin membangun ulang golden image.
Log proses init ada di `base/init-logs/`.

## 7. Running emulator — Terminal A

```bash
.venv/bin/python -m apkfuse.lab run "$LAB_APK" --headless
```

Biarkan Terminal A tetap berjalan. Tunggu pesan berikut:

```text
ready: <nama-paket> installed in an isolated emulator
```

Pada tahap ini APK sudah ter-install, tetapi activity belum dijalankan karena
command di atas tidak memakai `--launch`. Sambungkan Wireshark terlebih dahulu
agar traffic saat aplikasi mulai berjalan bisa diikuti. `tcpdump` sendiri sudah
aktif sejak namespace lab dibuat, termasuk ketika Android boot.

Untuk menampilkan jendela emulator, jalankan tanpa `--headless` pada sesi
X11/XWayland dengan `DISPLAY` dan akses Xauthority yang sesuai. Script
meneruskan socket X11. Keterangan opsi emulator ada pada
[dokumentasi command line emulator](https://developer.android.com/studio/run/emulator-commandline).

Dari terminal lain, cek hasil mount selama lab masih aktif:

```bash
cat "cases/$LAB_CASE/static/manifest.facts"
cat "cases/$LAB_CASE/static/report/summary.json"
ls "cases/$LAB_CASE/static/raw"
findmnt -T "cases/$LAB_CASE/static"
findmnt -T "cases/$LAB_CASE/env"
```

Simpan hasil `findmnt` untuk melihat filesystem dan opsi mount yang benar-benar
aktif. Adanya folder `static/` atau `env/` saja belum menunjukkan bahwa proses
mount berhasil.

## 8. Capturing traffic — Wireshark, Terminal B

Set kembali variabel pada langkah 5, lalu cek file PCAP dan buka Wireshark:

```bash
test -s "$LAB_OUT/netns.pcap"
tail -c +1 -f "$LAB_OUT/netns.pcap" | wireshark -k -i -
```

`tail -c +1` membaca dari byte pertama sehingga header PCAP ikut terkirim.
Opsi `-f` mengikuti data baru, sedangkan Wireshark memakai `-i -` untuk membaca
stdin dan `-k` untuk mulai capture. Cara ini mengikuti
[panduan pipe capture](https://wiki.wireshark.org/CaptureSetup/Pipes#stdin) dan
[manual Wireshark](https://www.wireshark.org/docs/man-pages/wireshark.html).

Wireshark bisa dibuka sebagai user biasa. Data capture sudah diambil oleh lab
dari namespace emulator. Jadi, memilih interface `lo`, `eth0`, atau Wi-Fi pada
host tidak memberikan capture dari namespace yang sama.

Jika muncul `Couldn't run dumpcap in child process: Permission denied`, cek
izin eksekusi, grup capture, dan capability helper `dumpcap`. Mode `-i` tetap
menjalankan helper ini meskipun input berasal dari pipe. Pengaturannya ada pada
[capture privileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges).

Untuk melihat aliran paket dari terminal tanpa helper capture, gunakan TShark:

```bash
tail -c +1 -f "$LAB_OUT/netns.pcap" | tshark -l -r -
```

Jika stdin tidak diterima oleh build Wireshark yang dipakai, coba named pipe:

```bash
LAB_PIPE_DIR="$(mktemp -d)"
mkfifo "$LAB_PIPE_DIR/traffic.pcap"
tail -c +1 -f "$LAB_OUT/netns.pcap" > "$LAB_PIPE_DIR/traffic.pcap" &
LAB_TAIL_PID=$!
wireshark -k -i "$LAB_PIPE_DIR/traffic.pcap"
kill "$LAB_TAIL_PID" 2>/dev/null || true
rm "$LAB_PIPE_DIR/traffic.pcap"
rmdir "$LAB_PIPE_DIR"
```

Named pipe tetap memerlukan helper yang bisa dijalankan; cara ini tidak
menyelesaikan penolakan izin `dumpcap`.

Filter yang bisa dipakai saat melihat hasil capture:

- `dns` untuk query dan respons DNS.
- `http.request || http.response` untuk request dan respons HTTP.
- `http.request.method == "POST"` untuk mencari POST dari aplikasi.
- `http.request.method == "CONNECT"` untuk pembentukan tunnel proxy.
- `tcp.port == 8080` untuk koneksi ke proxy di namespace lab.
- `tls` untuk paket TLS yang dikenali Wireshark.

Terdapat traffic Android dan aplikasi sistem pada PCAP yang sama. Cocokkan
waktu aplikasi dijalankan, hostname, dan nomor stream sebelum menyimpulkan
bahwa request berasal dari sampel. Untuk membaca percakapan, pilih paket lalu
**Follow → TCP Stream**.

## 9. ADB console & trigger APK — Terminal C

Set kembali variabel dari langkah 5, kemudian cek status boot dan buka shell:

```bash
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell getprop sys.boot_completed
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell
```

Command pertama seharusnya menghasilkan `1`. Command kedua membuka shell
Android; gunakan `exit` untuk kembali ke host. Wrapper `lab adb` mengambil
serial dari kasus yang sedang berjalan dan menggunakan server ADB port `5038`.

Untuk mengecek jalur capture terlebih dahulu, buka URL uji dari emulator:

```bash
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell am start \
  -a android.intent.action.VIEW -d http://example.com/
```

Setelah request terlihat pada Wireshark, ambil nama package dari manifest hasil
mount dan jalankan activity utama APK:

```bash
LAB_PACKAGE="$(.venv/bin/python -c \
  'import json,sys; print(json.load(sys.stdin)["package"])' \
  < "cases/$LAB_CASE/static/manifest.facts")"
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell monkey \
  -p "$LAB_PACKAGE" -c android.intent.category.LAUNCHER 1
```

Pada run berikutnya, opsi `--launch` bisa ditambahkan ke `lab run` jika ingin
activity langsung dijalankan. Untuk melihat log Android:

```bash
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" logcat -v threadtime
```

### Cek POST Method ke C2

Saat activity berjalan, `sync()` mengirim request yang sebelumnya ditemukan
pada proses reverse engineering. Gunakan filter
`http.request.method == "POST"`, lalu cocokkan host, path, dan body JSON-nya.
Buka **Follow → TCP Stream** untuk membaca request dan respons pada koneksi
tersebut.

Ringkasan dari PCAP dan logcat juga bisa dicek dengan command berikut. Untuk
hasil lengkap, baca kembali setelah lab berhenti:

```bash
tshark -r "$LAB_OUT/netns.pcap" \
  -Y 'http.request.method == "POST" || http.response' \
  -T fields -e frame.number -e tcp.stream \
  -e http.request.method -e http.response.code
grep -F 'payload=' "$LAB_OUT/logcat.txt"
```

Cocokkan nomor `tcp.stream` pada POST ke C2 dengan responsnya. Jika status
respons `200`, lanjut periksa isi `result.text` dan bandingkan dengan
`payload=` pada logcat. Status `200` saja belum menunjukkan bahwa flag sudah
didapat, dan POST dari aplikasi sistem ke host lain bukan bukti request C2
sampel.

Jika koneksi ke server gagal, catat error dan hasil pengecekan environment.
Pada run tersebut flag belum didapat dari C2, tetapi temuan mengenai isolasi
lab masih dapat dilaporkan.

### Opsional — Emulator console pada port 5554

Console kontrol emulator berbeda dengan shell Android. Port `5554` berada di
namespace lab, sehingga koneksi ke `127.0.0.1:5554` dari host tidak langsung
menjangkaunya. Untuk membuka console pada namespace kasus yang sama:

```bash
LAB_NS_PID="$(pgrep -u "$(id -u)" -f \
  "^unshare .*lab-ns /run/user/$(id -u)/apkfuse/$LAB_CASE ")"
test -n "$LAB_NS_PID"
cat "cases/$LAB_CASE/env/.emulator_console_auth_token"
nsenter --target "$LAB_NS_PID" --user --net -- socat - TCP:127.0.0.1:5554
```

Jika `LAB_NS_PID` kosong, cek apakah run pada Terminal A masih aktif. Setelah
tersambung, masukkan `auth <token-yang-dibaca-dari-file>`, kemudian coba
`avd name` atau `ping`. Gunakan `quit` untuk keluar.

File token mengikuti `HOME=/env` yang dipakai sandbox. Penjelasan autentikasi
dan command console ada pada
[dokumentasi emulator console](https://developer.android.com/studio/run/emulator-console).

## 10. Stop lab & hasil capture

Stop capture pada Wireshark, lalu tutup pembaca pipe di Terminal B. Setelah itu,
tekan **Ctrl+C** pada Terminal A dan tunggu sampai lab selesai membersihkan
proses serta mount. Jika logcat masih berjalan pada Terminal C, hentikan stream
tersebut dengan Ctrl+C juga.

Hasil run tetap tersimpan pada folder kasus:

| Artefak | Keterangan |
| --- | --- |
| `out/netns.pcap` | Capture pada loopback namespace lab. |
| `out/flows.mitm` | Flow yang ditangani mitmproxy pada mode normal. |
| `out/logcat.txt` | Log Android selama run. |
| `out/mitm.log` | Log proxy, termasuk error koneksi dan sertifikat. |
| `out/emulator.log` | Log boot dan proses namespace emulator. |
| `out/apkfuse.log` | Log mount APKFuse. |
| `out/runs.jsonl` | Metadata mulai/berhenti dan nama package per run. |
| `upper/` | Perubahan filesystem environment emulator. |

Buka kembali PCAP atau lihat ringkasan protokol:

```bash
wireshark -r "$LAB_OUT/netns.pcap"
tshark -r "$LAB_OUT/netns.pcap" -q -z io,phs
```

Untuk membaca HTTP/HTTPS yang berhasil diintersepsi mitmproxy:

```bash
.venv/bin/mitmweb --set confdir="$PWD/base/mitmproxy" \
  --no-server -r "$LAB_OUT/flows.mitm"
```

CA yang sudah terpasang di Android tidak otomatis membuat payload TLS di PCAP
menjadi plaintext. Flow bisa dibaca jika aplikasi menerima CA dan intersepsi
berhasil. Certificate pinning atau aturan trust aplikasi masih bisa membuatnya
gagal; lihat [keterangan sertifikat mitmproxy](https://docs.mitmproxy.org/stable/concepts/certificates/).

Jika sampel yang sama dijalankan ulang, lab melanjutkan isi `upper/` sebelumnya.
File `netns.pcap` dan `flows.mitm` dibuka lagi untuk run baru. Jadi, simpan hasil
yang diperlukan setelah lab benar-benar berhenti:

```bash
cp -a "$LAB_OUT" "${LAB_OUT}.saved-$(date +%Y%m%d-%H%M%S)"
```

Pada setiap run, mulai ulang pembaca pipe agar header PCAP yang baru terbaca.
Backup `out/` menyimpan hasil capture dan log, tetapi tidak mengembalikan
emulator ke kondisi awal. Untuk run bersih dari golden image, gunakan salinan
kerja repository dengan `base/golden/` dan tanpa direktori kasus lama.

Pada laporan akhir, catat hasil flag dan hasil hardening. Untuk flag, sertakan
bukti POST dan respons C2. Untuk hardening, sertakan hasil cek hash, mount,
isolasi proses, dan jalur network. Beri status lulus, gagal, atau belum diuji
sesuai hasil pengecekan. Konfigurasi yang ada pada script belum dihitung sebagai
pengujian yang lulus.

## Jika terdapat kendala

| Gejala | Yang dicek |
| --- | --- |
| `No module named pyfuse3` | Gunakan `.venv/bin/python`, lalu cek dependency pada langkah 3. |
| `SDK not found` atau `avdmanager` tidak ada | Cek struktur `base/sdk/cmdline-tools/latest/bin/` pada langkah 4. |
| Versi Java terlalu lama | Cek `archlinux-java status`. Jika diperlukan, pilih JDK 21 dengan `sudo archlinux-java set java-21-openjdk`. |
| `/dev/kvm` atau `/dev/fuse` tidak dapat diakses | Cek virtualisasi, modul perangkat, izin user, dan penerusan perangkat jika menggunakan VM/container. |
| `Operation not permitted` saat `unshare` | Cek dukungan dan kebijakan user/network namespace host. |
| Emulator keluar saat boot | Baca `out/emulator.log` atau `base/init-logs/emulator.log`, lalu cek `emulator -accel-check`. |
| Wireshark gagal menjalankan `dumpcap` | Cek izin dan capability helper. Untuk membaca aliran tanpa helper, gunakan `tshark -l -r -`, atau buka PCAP yang sudah tersimpan. |
| Wireshark tidak menampilkan paket | Cek run masih aktif, path kasus benar, dan PCAP berisi lebih dari header. Jika perlu koneksi keluar, run harus tanpa `--offline`. Coba URL uji di langkah 9. |
| Header PCAP tidak valid | Gunakan `tail -c +1` agar pembacaan dimulai dari byte pertama. Coba named pipe jika stdin tidak diterima. |
| HTTP pada port proxy tidak dikenali | Gunakan **Analyze → Decode As… → HTTP** pada stream proxy TCP yang sesuai. |
| Request ke C2 gagal | Baca `out/mitm.log`, lalu cek koneksi host dan ketersediaan server lab yang dituju APK. |
| Case masih ter-mount | Hentikan run pemilik mount. Jika run sudah berhenti tetapi mount tertinggal, gunakan `fusermount3 -u` pada `cases/<case>/env` dan `cases/<case>/static`. |

## Catatan pengecekan

Command mengikuti [lab.py](lab.py), [fs.py](fs.py), dan
[__main__.py](__main__.py). Pengecekan yang sudah dilakukan mencakup SHA-256
APK asli di dalam ZIP, entry point CLI, serta aliran PCAP melalui
`tail -c +1 -f` dan `tshark -l -r -`. Paket yang ditambahkan setelah pembacaan
dimulai juga berhasil terbaca.

Pada environment pengecekan, mode `-i` masih ditolak saat menjalankan helper
`dumpcap`. Init golden image, boot emulator, console interaktif, GUI Wireshark,
dan capture dari run APK baru belum dijalankan ulang.

POST Method dan pembacaan `result.text` sudah dicocokkan dengan dekompilasi
`MainActivity` pada APK asli serta PCAP lokal yang tersedia. Pada PCAP terdapat
POST dan respons `200` pada stream yang sama. Pengecekan ini memakai rekaman
yang sudah ada, tanpa menghubungi ulang C2, dan belum menjadi hasil audit
hardening.
