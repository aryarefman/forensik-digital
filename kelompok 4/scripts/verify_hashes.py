import os
import hashlib

TUGAS_DIR = os.path.join(os.path.dirname(__file__), '..', 'tugas')
RECOVERED_FILE = os.path.join(os.path.dirname(__file__), '..', 'recovered_files', 'cobainAES128.txt')

def get_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

print("[+] Verifikasi Integritas Barang Bukti (MD5 & SHA-256):")
print("-" * 90)
print(f"{'Nama Berkas':<22} {'Ukuran':<10} {'MD5':<34} {'SHA-256'}")
print("-" * 90)

if os.path.exists(TUGAS_DIR):
    for fname in sorted(os.listdir(TUGAS_DIR)):
        fpath = os.path.join(TUGAS_DIR, fname)
        if os.path.isfile(fpath):
            m, s = get_hashes(fpath)
            size = f"{os.path.getsize(fpath)} B"
            print(f"{fname:<22} {size:<10} {m:<34} {s[:16]}...{s[-8:]}")

if os.path.exists(RECOVERED_FILE):
    m, s = get_hashes(RECOVERED_FILE)
    size = f"{os.path.getsize(RECOVERED_FILE)} B"
    print("-" * 90)
    print(f"{'cobainAES128.txt (FLAG)':<22} {size:<10} {m:<34} {s[:16]}...{s[-8:]}")
print("-" * 90)
