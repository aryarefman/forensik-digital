"""
extract_stego_flag.py
======================
Skrip investigasi forensik untuk mengekstraksi Flag Kedua (Steganografi)
dari berkas pembawa '250926.png' (Kelompok 4).

Teknik Steganografi:
- Software: OpenStego 0.8.6 (Algoritma RandomLSB)
- Seed PRNG: 98234782 (Hash dari password kosong / default GUI)
- Enkripsi: AES-128 (PBEWithHmacSHA256AndAES_128, password blank / '')
- Kompresi: GZIP Deflate
- Flag Tersembunyi: FLAG{k4t4H1kar1_0K3}
"""

import os
import hashlib
import gzip
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class JavaRandom:
    """Implementasi PRNG java.util.Random (Linear Congruential Generator)"""
    def __init__(self, seed):
        self.seed = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)

    def next(self, bits):
        self.seed = (self.seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return self.seed >> (48 - bits)

    def nextInt(self, n):
        if (n & -n) == n:
            return (n * self.next(31)) >> 31
        while True:
            val = self.next(31)
            bits = val % n
            if (val - bits + (n - 1)) >= 0:
                return bits

def extract_stego(image_path, output_path):
    print(f"[+] Memuat berkas gambar stego: {image_path}")
    im = Image.open(image_path)
    w, h = im.size
    pixels = im.load()

    # Seed untuk password kosong di OpenStego: 98234782L
    rand = JavaRandom(98234782)
    bit_read = set()

    def read_bytes(n):
        res = bytearray()
        for _ in range(n):
            val = 0
            for _ in range(8):
                while True:
                    x = rand.nextInt(w)
                    y = rand.nextInt(h)
                    ch = rand.nextInt(3)
                    ch_bit = rand.nextInt(1)
                    key = f"{x}_{y}_{ch}_{ch_bit}"
                    if key not in bit_read:
                        bit_read.add(key)
                        break
                r, g, b = pixels[x, y]
                java_rgb = (255 << 24) | (r << 16) | (g << 8) | b
                pixel_bit = (java_rgb >> (ch * 8 + ch_bit)) & 1
                val = (val << 1) | pixel_bit
            res.append(val)
        return bytes(res)

    print("[+] Membaca header OpenStego LSB bitstream...")
    stamp = read_bytes(9)
    version = read_bytes(1)
    if stamp != b"OPENSTEGO":
        raise ValueError(f"Bukan format OpenStego yang valid (stamp={stamp})")

    arr8 = read_bytes(8)
    data_len = arr8[0] | (arr8[1] << 8) | (arr8[2] << 16) | (arr8[3] << 24)
    ch_bits = arr8[4]
    fname_len = arr8[5]
    is_comp = arr8[6]
    is_enc = arr8[7]
    algo = read_bytes(8).rstrip(b"\x00").decode("latin1")
    fname = read_bytes(fname_len).decode("utf-8")

    print(f"    - Stamp        : {stamp.decode('latin1')}")
    print(f"    - Versi        : {version[0]}")
    print(f"    - Payload Len  : {data_len} bytes")
    print(f"    - Nama Berkas  : {fname}")
    print(f"    - Kompresi     : {bool(is_comp)}")
    print(f"    - Enkripsi     : {bool(is_enc)} ({algo})")

    payload = read_bytes(data_len)
    param_len = payload[0]
    param_bytes = payload[1:1+param_len]
    ciphertext = payload[1+param_len:]

    print("[+] Mendekripsi payload (PBEWithHmacSHA256AndAES_128, password blank)...")
    salt = bytes([40, 95, 113, 201, 30, 53, 10, 98])
    key = hashlib.pbkdf2_hmac("sha256", b"", salt, 7, dklen=16)
    iv = param_bytes[-16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    pad_len = plaintext_padded[-1]
    compressed_data = plaintext_padded[:-pad_len]

    print("[+] Mendekompresi data GZIP...")
    flag_data = gzip.decompress(compressed_data)
    flag_str = flag_data.decode("utf-8").strip()

    print("=" * 60)
    print(f"[!] FLAG KEDUA BERHASIL DITEMUKAN: {flag_str}")
    print("=" * 60)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(flag_data)
    print(f"[+] Berkas hasil pemulihan disimpan di: {output_path}")
    return flag_str

if __name__ == "__main__":
    stego_candidates = [
        r"kelompok 4\analysis_artifacts\250926.png",
        r"kelompok 4\rhythm game\bg\Data\bt\250926.png",
        r"D:\rhythm game\bg\Data\bt\250926.png"
    ]
    img = next((p for p in stego_candidates if os.path.exists(p)), None)
    out = r"kelompok 4\recovered_files\stego_flag2.txt"
    if img:
        extract_stego(img, out)
    else:
        print("[-] File gambar 250926.png tidak ditemukan!")
