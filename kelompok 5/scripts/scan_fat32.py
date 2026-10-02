#!/usr/bin/env python3
"""
Forensic FAT32 Parser & Directory Scanner for Drive D: (Kelompok 5)
Examiner: Kelompok 3 (Forensik Digital)
Standard: ISO/IEC 27037 & NIST SP 800-86
"""

import struct, datetime

def parse_fat_datetime(date_bytes, time_bytes, tenth=0):
    val_date = struct.unpack('<H', date_bytes)[0]
    val_time = struct.unpack('<H', time_bytes)[0]
    if val_date == 0:
        return 'N/A'
    year = ((val_date >> 9) & 0x7F) + 1980
    month = (val_date >> 5) & 0x0F
    day = val_date & 0x1F
    hour = (val_time >> 11) & 0x1F
    minute = (val_time >> 5) & 0x3F
    second = (val_time & 0x1F) * 2 + (tenth // 100)
    try:
        dt = datetime.datetime(year, month, day, hour, minute, second)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        return f'{year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}'

def main():
    print("[*] Reading FAT32 Boot Sector from \\\\.\\D: ...")
    with open(r'\\.\D:', 'rb') as f:
        boot = f.read(512)
        bytes_per_sector = struct.unpack('<H', boot[11:13])[0]
        sectors_per_cluster = boot[13]
        reserved_sectors = struct.unpack('<H', boot[14:16])[0]
        num_fats = boot[16]
        sectors_per_fat = struct.unpack('<I', boot[36:40])[0]
        cluster_size = bytes_per_sector * sectors_per_cluster
        fat_offset = reserved_sectors * bytes_per_sector
        data_offset = fat_offset + (num_fats * sectors_per_fat * bytes_per_sector)

        print(f"[+] Bytes per Sector   : {bytes_per_sector}")
        print(f"[+] Sectors per Cluster: {sectors_per_cluster} ({cluster_size} bytes)")
        print(f"[+] Reserved Sectors   : {reserved_sectors} (Offset: {fat_offset})")
        print(f"[+] Data Region Offset : {data_offset}")

        print("\n[*] Parsing FAT32 Root Directory (Cluster 2)...")
        f.seek(data_offset)
        c2 = f.read(cluster_size)

        lfn_buffer = {}
        for i in range(0, 1024, 32):
            entry = c2[i:i+32]
            if entry[0] == 0:
                break
            if entry[11] == 0x0F:
                seq = entry[0] & 0x1F
                chars = (entry[1:11] + entry[14:26] + entry[28:32]).decode('utf-16le', errors='replace').split('\x00')[0]
                lfn_buffer[seq] = chars
                continue

            lfn_name = ''.join(lfn_buffer[k] for k in sorted(lfn_buffer.keys(), reverse=True)) if lfn_buffer else ''
            lfn_buffer.clear()

            status = 'DELETED' if entry[0] == 0xE5 else 'ACTIVE'
            short_name = entry[:11].decode('ascii', errors='replace').strip()
            display_name = lfn_name if lfn_name else short_name
            display_name = display_name.encode('ascii', errors='replace').decode('ascii')

            c_time = parse_fat_datetime(entry[16:18], entry[14:16], entry[13])
            m_time = parse_fat_datetime(entry[24:26], entry[22:24])

            cluster = (struct.unpack('<H', entry[20:22])[0] << 16) | struct.unpack('<H', entry[26:28])[0]
            size = struct.unpack('<I', entry[28:32])[0]

            print(f"[{i:04X}] {status:7} | Cluster: {cluster:5} | Size: {size:8} B | Created: {c_time} | Modified: {m_time} | Name: {display_name}")

if __name__ == '__main__':
    main()
