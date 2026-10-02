from pathlib import Path
import hashlib

EXPECTED_FLAG = 'FLAG{F0r3ns1k_K3l0mp0k_2}'
EXPECTED_SHA256 = '90e4906477a0254757e822bdb9736935fb3662ef156c8b6d38bd614fd1aaccce'

path = Path(__file__).resolve().parent.parent / 'recovered_files' / 'KONMED_5.txt'
data = path.read_bytes()
text = data.decode('utf-8')
sha256 = hashlib.sha256(data).hexdigest()
md5 = hashlib.md5(data).hexdigest()

print(f'File   : {path.name}')
print(f'Size   : {len(data)} bytes')
print(f'MD5    : {md5}')
print(f'SHA256 : {sha256}')
print(f'Content: {text}')
print('Flag valid   :', text == EXPECTED_FLAG)
print('SHA256 valid :', sha256 == EXPECTED_SHA256)
