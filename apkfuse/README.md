# APKFuse — Panduan Lab APK, Emulator, dan Wireshark

Panduan ini menjalankan `undangan-g03.apk` di emulator Android terisolasi, membuka
konsolnya, lalu menampilkan traffic lab di Wireshark secara langsung. APK dalam
[undangan-g03.zip](undangan-g03.zip) adalah sampel asli untuk analisis; jalankan
sampel di emulator lab.

Semua perintah dijalankan dari **root repository**, yaitu direktori yang berisi
folder `apkfuse/`. Jangan menjalankan `python -m apkfuse.lab` dari dalam folder
`apkfuse/`.

## 1. Kenali alur lab

[lab.py](lab.py) mengatur dua mount FUSE untuk setiap sampel:

| Lokasi | Fungsi |
| --- | --- |
| `cases/<case>/static/` | Mount APK melalui [fs.py](fs.py), dengan opsi `ro,nosuid,nodev,noexec`; berisi APK mentah, manifest terurai, indeks DEX, dan laporan. |
| `cases/<case>/env/` | Mount `fuse-overlayfs` untuk lingkungan emulator, menggabungkan golden image dengan perubahan pada `upper/`. |
| `cases/<case>/upper/` | Perubahan lingkungan emulator yang dipertahankan setelah lab berhenti. |
| `cases/<case>/out/` | PCAP, flow mitmproxy, logcat, dan log proses. |

FUSE adalah filesystem. Titik capture jaringan berada di **interface `lo` dalam
network namespace emulator**. Saat lab mulai, `tcpdump` otomatis menulis
`out/netns.pcap`; Wireshark membaca aliran PCAP tersebut lewat pipe.

```text
APK asli ── APKFuse ── static/               analisis statis
golden/ + upper/ ── fuse-overlayfs ── env/   penyimpanan emulator

Emulator Android
  └─ proxy TCP :8080 / DNS :53 di namespace lab
       ├─ tcpdump pada lo ── netns.pcap ── pipe ── Wireshark
       └─ bridge socket Unix ── mitmproxy pada host ── jaringan tujuan
```

Mode normal menyediakan koneksi keluar melalui mitmproxy pada host. Jalankan di
jaringan analisis yang diizinkan. Opsi `--offline` menghilangkan bridge proxy dan
DNS ke host. Capture ini memperlihatkan traffic yang mencapai jalur proxy/DNS
tersebut, bukan seluruh paket pada virtual NIC Android; traffic UDP lain atau
traffic yang mengabaikan proxy tidak otomatis tercakup. Port ADB `5555`
dikecualikan dari capture oleh script lab.

## 2. Siapkan host Linux

Jalur setup di bawah ditujukan untuk **Arch Linux x86_64**, sesuai tata letak
`/usr`, `/lib`, dan `/lib64` yang digunakan script. Diperlukan akses ke `/dev/kvm`,
`/dev/fuse`, serta dukungan user/network namespace. Untuk host berupa VM, KVM
memerlukan virtualisasi bertingkat yang tersedia dari hypervisor.

Clone repository jika belum ada:

```bash
git clone --filter=blob:none --sparse https://github.com/aryarefman/forensik-digital.git
cd forensik-digital || exit
git sparse-checkout set apkfuse
```

Pasang dependensi host:

```bash
sudo pacman -S --needed base-devel python python-pip \
  fuse3 fuse-overlayfs bubblewrap socat iproute2 util-linux procps-ng \
  tcpdump wireshark-qt wireshark-cli jdk21-openjdk openssl unzip \
  libx11 libxcb libxkbcommon-x11 libpulse nss mesa
```

Paket GUI dan CLI Wireshark tersedia melalui
[repository resmi Arch](https://archlinux.org/packages/extra/x86_64/wireshark-qt/).
Untuk akses helper capture pada paket Arch, tambahkan pengguna ke grup yang
disediakan paket, lalu logout/login agar keanggotaan berlaku:

```bash
sudo gpasswd -a "$(id -un)" wireshark
```

Langkah grup ini mengikuti
[panduan izin capture Wireshark](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges#arch-linux-and-derivatives).
Java harus tersedia melalui `java` di `/usr/bin`, karena sandbox membersihkan
environment sebelum menjalankan `avdmanager`.

```bash
java -version
test -r /dev/kvm && test -w /dev/kvm && echo "KVM dapat diakses"
test -r /dev/fuse && test -w /dev/fuse && echo "FUSE dapat diakses"
test -w "/run/user/$(id -u)" && echo "Runtime directory tersedia"
unshare --user --map-root-user --net --pid --fork true
```

Jika pemeriksaan gagal, selesaikan izin perangkat atau kebijakan namespace
terlebih dahulu. Gunakan sesi login pengguna biasa agar `/run/user/<uid>`
tersedia; jalankan lab sebagai pengguna tersebut. Penjelasan KVM tersedia pada
[dokumentasi akselerasi Android Emulator](https://developer.android.com/studio/run/emulator-acceleration).

## 3. Siapkan Python

Versi dependensi berikut berasal dari environment lokal yang digunakan untuk
memeriksa panduan ini: Python `3.14.7`, pyfuse3 `3.5.0`, Trio `0.34.0`, dan
mitmproxy `12.3.1`. Penggunaan interpreter lain memerlukan pemeriksaan
kompatibilitas dependensi.

```bash
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install \
  'pyfuse3==3.5.0' 'trio==0.34.0' 'mitmproxy==12.3.1'

.venv/bin/python -m apkfuse --help
.venv/bin/python -m apkfuse.lab --help
```

Binding yang dipakai adalah [pyfuse3](https://github.com/libfuse/pyfuse3), bukan
`fusepy`. Build binding memerlukan header libfuse3, compiler, dan `pkg-config`;
lihat [dependensi pyfuse3](https://www.rath.org/pyfuse3-docs/install.html).

## 4. Pasang Android SDK

Unduh paket **Command line tools only → Linux** dari
[halaman resmi Android Studio](https://developer.android.com/studio#command-line-tools-only).
Masukkan lokasi ZIP yang sudah diunduh saat diminta. Jika
`base/sdk/cmdline-tools/latest/bin/avdmanager` sudah tersedia, lewati blok
ekstraksi ini.

```bash
read -r -p "Lokasi ZIP Android Command-Line Tools Linux: " LAB_SDK_TOOLS_ZIP
test -f "$LAB_SDK_TOOLS_ZIP"
LAB_SDK_TMP="$(mktemp -d)"
mkdir -p base/sdk/cmdline-tools
unzip -q "$LAB_SDK_TOOLS_ZIP" -d "$LAB_SDK_TMP"
mv "$LAB_SDK_TMP/cmdline-tools" base/sdk/cmdline-tools/latest
rmdir "$LAB_SDK_TMP"
```

Setujui lisensi, kemudian pasang komponen yang diminta `lab.py`:

```bash
base/sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root="$PWD/base/sdk" --licenses
base/sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root="$PWD/base/sdk" \
  'platform-tools' 'emulator' 'system-images;android-33;google_apis;x86_64'

test -x base/sdk/platform-tools/adb
test -x base/sdk/cmdline-tools/latest/bin/avdmanager
base/sdk/emulator/emulator -accel-check
```

System image harus `google_apis` API 33 x86_64 seperti konstanta `SYSTEM_IMAGE`
di script. Lab membutuhkan akses `adb root` untuk menyiapkan sertifikat CA;
jangan menggantinya dengan image Google Play. Lokasi SDK harus `base/sdk/`,
karena lokasi ini ditentukan oleh kode. Syntax instalasi paket dan pengaturan
`--sdk_root` dirujuk dari [dokumentasi sdkmanager](https://developer.android.com/tools/sdkmanager).

## 5. Ekstrak dan verifikasi APK asli

ZIP hanya berisi `undangan-g03.apk`, tanpa APK patched atau artefak kasus lain.

```bash
mkdir -p samples
unzip -n apkfuse/undangan-g03.zip -d samples
printf '%s  %s\n' \
  '0ece697fcdbb4b8306365db7d76e053a96276424ee87a99e0e94cd790907e4b3' \
  'samples/undangan-g03.apk' | sha256sum -c -
```

Hasil yang diharapkan: `samples/undangan-g03.apk: OK`.

Di **setiap terminal baru**, masuk ke root repository dan jalankan blok variabel
berikut agar contoh selanjutnya menunjuk kasus yang sama:

```bash
LAB_APK="$PWD/samples/undangan-g03.apk"
LAB_CASE="$(sha256sum "$LAB_APK" | cut -c1-12)"
LAB_OUT="$PWD/cases/$LAB_CASE/out"
```

Untuk sampel ini, `LAB_CASE` bernilai `0ece697fcdbb`.

## 6. Inisialisasi lab satu kali

```bash
.venv/bin/python -m apkfuse.lab init --headless
```

Proses ini membuat AVD `lab`, menyiapkan kunci ADB khusus lab, membuat CA
mitmproxy, memasangnya ke image Android, kemudian mematikan emulator golden.
Selesai ketika muncul `golden image ready in .../base/golden`.

Jika golden image sudah ada, lewati tahap ini. `init --force` ditujukan untuk
membangun ulang golden image, sehingga tidak diperlukan untuk run harian.
Log inisialisasi berada di `base/init-logs/`.

## 7. Jalankan emulator dari Terminal A

```bash
.venv/bin/python -m apkfuse.lab run "$LAB_APK" --headless
```

Biarkan terminal ini terbuka. Tunggu sampai muncul:

```text
ready: <nama-paket> installed in an isolated emulator
```

APK sudah terpasang, tetapi activity-nya belum diluncurkan. Urutan ini memberi
waktu untuk menyambungkan Wireshark sebelum memicu aplikasi. Capture sudah
berjalan sejak namespace lab dibuat, termasuk saat Android boot.

Jika membutuhkan jendela emulator, jalankan perintah yang sama tanpa
`--headless` pada sesi X11/XWayland dengan `DISPLAY` dan akses Xauthority yang
valid. Script meneruskan socket X11, bukan socket Wayland. Arti opsi emulator
dirujuk dari [panduan command line Android Emulator](https://developer.android.com/studio/run/emulator-commandline).

Selama lab aktif, hasil mount statis bisa diperiksa dari terminal lain:

```bash
cat "cases/$LAB_CASE/static/manifest.facts"
cat "cases/$LAB_CASE/static/report/summary.json"
ls "cases/$LAB_CASE/static/raw"
findmnt -T "cases/$LAB_CASE/static"
findmnt -T "cases/$LAB_CASE/env"
```

## 8. Hubungkan Wireshark dari Terminal B

Jalankan ulang blok variabel dari langkah 5. Pastikan PCAP sudah dibuat:

```bash
test -s "$LAB_OUT/netns.pcap"
tail -c +1 -f "$LAB_OUT/netns.pcap" | wireshark -k -i -
```

`tail` mengirim file dari byte pertama, termasuk header PCAP, lalu mengikuti
paket baru. `-i -` membuat Wireshark membaca stdin dan `-k` langsung memulai
capture. Cara ini mengikuti
[panduan capture melalui pipe Wireshark](https://wiki.wireshark.org/CaptureSetup/Pipes#stdin)
dan [manual Wireshark](https://www.wireshark.org/docs/man-pages/wireshark.html).

Wireshark dijalankan sebagai pengguna biasa. Lab sudah melakukan capture di
namespace yang benar; memilih `lo`, `eth0`, atau Wi-Fi **milik host** tidak
memberikan sudut pandang jaringan yang sama.

Mode `-i` tetap menjalankan helper `dumpcap`. Jika muncul `Couldn't run dumpcap
in child process: Permission denied`, periksa izin eksekusi, grup capture, dan
capability helper sesuai kebijakan host; lihat
[panduan izin capture Wireshark](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges).
Named pipe tidak mengatasi penolakan eksekusi helper.

Untuk memeriksa aliran paket dari terminal tanpa menjalankan helper capture:

```bash
tail -c +1 -f "$LAB_OUT/netns.pcap" | tshark -l -r -
```

Jika build Wireshark tidak menerima stdin, gunakan named pipe. Dari Terminal B:

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

Filter tampilan yang dapat digunakan:

| Filter | Yang ditampilkan |
| --- | --- |
| `dns` | Query dan respons DNS. |
| `http.request || http.response` | Request dan respons HTTP yang dapat didiseksi. |
| `http.request.method == "CONNECT"` | Pembentukan tunnel proxy HTTP. |
| `tcp.port == 8080` | Koneksi ke proxy pada namespace lab. |
| `tls` | Paket TLS yang dikenali Wireshark. |

PCAP juga berisi traffic Android dan aplikasi sistem. Gunakan waktu peluncuran,
hostname, dan stream untuk membedakan traffic sampel dari traffic latar belakang.
Untuk mengikuti percakapan, pilih paket lalu **Follow → TCP Stream**.

## 9. Buka konsol dan picu aplikasi dari Terminal C

Jalankan ulang blok variabel dari langkah 5. Periksa Android terlebih dahulu:

```bash
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell getprop sys.boot_completed
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell
```

Perintah pertama seharusnya menghasilkan `1`. Perintah kedua membuka shell
Android interaktif. Ketik `exit` untuk kembali ke host. Wrapper `lab adb`
menggunakan serial kasus dan server ADB khusus pada port `5038`.

Untuk menguji jalur capture terlebih dahulu, buka URL uji dari emulator:

```bash
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell am start \
  -a android.intent.action.VIEW -d http://example.com/
```

Lihat request di Wireshark, kemudian ambil nama paket dari manifest hasil mount
dan jalankan activity utama sampel:

```bash
LAB_PACKAGE="$(.venv/bin/python -c \
  'import json,sys; print(json.load(sys.stdin)["package"])' \
  < "cases/$LAB_CASE/static/manifest.facts")"
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" shell monkey \
  -p "$LAB_PACKAGE" -c android.intent.category.LAUNCHER 1
```

Jika ingin langsung meluncurkan aplikasi pada run berikutnya, tambahkan
`--launch` pada perintah `lab run`. Lihat log Android dengan:

```bash
.venv/bin/python -m apkfuse.lab adb "$LAB_CASE" logcat -v threadtime
```

### Opsional: konsol kontrol emulator pada port 5554

Konsol kontrol emulator berbeda dari shell Android. Port `5554` berada di dalam
namespace, sehingga koneksi langsung ke `127.0.0.1:5554` milik host tidak
menjangkaunya. Untuk masuk melalui namespace run yang sama:

```bash
LAB_NS_PID="$(pgrep -u "$(id -u)" -f \
  "^unshare .*lab-ns /run/user/$(id -u)/apkfuse/$LAB_CASE ")"
test -n "$LAB_NS_PID"
cat "cases/$LAB_CASE/env/.emulator_console_auth_token"
nsenter --target "$LAB_NS_PID" --user --net -- socat - TCP:127.0.0.1:5554
```

Jika `LAB_NS_PID` kosong, pastikan Terminal A masih menjalankan kasus ini.
Setelah tersambung, masukkan `auth <token-yang-dibaca-dari-file>`, lalu coba
`avd name` atau `ping`. Ketik `quit` untuk keluar. Lokasi token mengikuti
`HOME=/env` yang ditetapkan sandbox; autentikasi dan perintah konsol dirujuk dari
[dokumentasi konsol Android Emulator](https://developer.android.com/studio/run/emulator-console).

## 10. Hentikan dan simpan hasil

Hentikan capture pada jendela Wireshark dan tutup pembaca pipe di Terminal B.
Di Terminal A, tekan **Ctrl+C** lalu tunggu sampai lab selesai membersihkan
proses dan mount. Jika Terminal C masih menampilkan logcat, hentikan stream itu
dengan Ctrl+C juga.

Hasil analisis tetap berada di:

| Artefak | Isi |
| --- | --- |
| `out/netns.pcap` | Paket pada loopback namespace lab. |
| `out/flows.mitm` | Flow yang ditangani mitmproxy dalam mode normal. |
| `out/logcat.txt` | Log Android yang direkam lab. |
| `out/mitm.log` | Log proxy, termasuk error koneksi atau sertifikat. |
| `out/emulator.log` | Log boot emulator dan proses namespace. |
| `out/apkfuse.log` | Log mount APKFuse. |
| `out/runs.jsonl` | Metadata mulai/berhenti dan nama paket per run. |
| `upper/` | Perubahan filesystem lingkungan emulator. |

Buka ulang PCAP atau baca ringkasannya:

```bash
wireshark -r "$LAB_OUT/netns.pcap"
tshark -r "$LAB_OUT/netns.pcap" -q -z io,phs
```

Untuk melihat HTTP/HTTPS yang berhasil diintersepsi mitmproxy:

```bash
.venv/bin/mitmweb --set confdir="$PWD/base/mitmproxy" \
  --no-server -r "$LAB_OUT/flows.mitm"
```

Pemasangan CA di Android tidak otomatis membuat payload TLS pada PCAP menjadi
plaintext. Flow mitmproxy hanya dapat dibaca jika aplikasi menerima CA dan
intersepsi berhasil; certificate pinning atau kebijakan trust aplikasi dapat
membatasinya. Lihat [penjelasan sertifikat mitmproxy](https://docs.mitmproxy.org/stable/concepts/certificates/).

Run ulang sampel yang sama melanjutkan `upper/` sebelumnya. `netns.pcap` dan
`flows.mitm` dibuka lagi untuk run baru, sehingga salin hasil yang ingin
dipertahankan **setelah lab berhenti**:

```bash
cp -a "$LAB_OUT" "${LAB_OUT}.saved-$(date +%Y%m%d-%H%M%S)"
```

Mulai ulang pembaca pipe setiap run agar Wireshark menerima header PCAP yang
baru. Menyimpan `out/` saja tidak membuat lingkungan emulator kembali bersih.
Untuk eksperimen dari golden image yang bersih, gunakan salinan kerja
repository dengan direktori `base/golden/` dan tanpa direktori kasus lama.

## Jika ada kendala

| Gejala | Pemeriksaan |
| --- | --- |
| `No module named pyfuse3` | Gunakan `.venv/bin/python` dan pasang dependensi langkah 3. |
| `SDK not found` atau `avdmanager` tidak ada | Periksa struktur `base/sdk/cmdline-tools/latest/bin/` dan ulangi langkah SDK. |
| Java yang dipakai terlalu lama | Periksa `archlinux-java status`; jika diperlukan, pilih JDK 21 dengan `sudo archlinux-java set java-21-openjdk`. |
| `/dev/kvm` atau `/dev/fuse` tidak dapat diakses | Periksa virtualisasi, modul perangkat, izin pengguna, dan penerusan perangkat bila host berupa VM/container. |
| `Operation not permitted` saat `unshare` | Periksa dukungan serta kebijakan user/network namespace host. |
| Emulator keluar saat boot | Baca `out/emulator.log` atau `base/init-logs/emulator.log`, lalu cek `emulator -accel-check`. |
| Wireshark menolak menjalankan `dumpcap` | Periksa izin dan kebijakan capability helper. Gunakan `tshark -l -r -` untuk memeriksa aliran tanpa helper, atau buka PCAP yang sudah tersimpan. |
| Wireshark menunggu tanpa paket | Pastikan lab aktif, path kasus benar, PCAP berisi lebih dari header, dan run tidak memakai `--offline` bila mengharapkan koneksi keluar. Coba URL uji di langkah 9. |
| Wireshark melaporkan header tidak valid | Mulai pembaca dari byte pertama dengan `tail -c +1`; jangan gunakan `tail -f` tanpa opsi byte. Coba named pipe jika stdin tidak diterima. |
| HTTP pada port proxy tidak dikenali | Gunakan **Analyze → Decode As… → HTTP** pada stream proxy TCP yang sesuai. |
| Request ke server tujuan gagal | Baca `out/mitm.log`, periksa konektivitas host dan ketersediaan server lab. Sampel asli bergantung pada tujuan jaringan yang dikandung APK. |
| Case dilaporkan masih ter-mount | Hentikan run yang memilikinya. Jika run sudah berhenti dan mount tertinggal, lepas `cases/<case>/env` dan `cases/<case>/static` dengan `fusermount3 -u`. |

## Cakupan verifikasi panduan

Perintah disesuaikan dengan [lab.py](lab.py), [fs.py](fs.py), dan
[__main__.py](__main__.py). Arsip diverifikasi terhadap SHA-256 APK asli,
entry point CLI diperiksa, dan aliran PCAP lewat pipe diuji dengan rekaman
yang sudah ada melalui `tail -c +1 -f` dan `tshark -l -r -`, termasuk paket
yang ditambahkan setelah pembacaan dimulai. Mode capture `-i` terhalang izin
eksekusi helper `dumpcap` pada environment penulisan ini. Inisialisasi golden
image, boot emulator, konsol interaktif, GUI Wireshark, dan capture dari run APK
baru belum dijalankan ulang dalam sesi penulisan ini.
