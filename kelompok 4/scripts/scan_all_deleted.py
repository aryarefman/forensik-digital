import struct

with open(r'\\.\D:', 'rb') as f:
    boot = f.read(512)
    bytes_per_sector = struct.unpack('<H', boot[11:13])[0]
    sectors_per_cluster = boot[13]
    reserved_sectors = struct.unpack('<H', boot[14:16])[0]
    num_fats = boot[16]
    sectors_per_fat = struct.unpack('<I', boot[36:40])[0]
    root_cluster = struct.unpack('<I', boot[44:48])[0]
    cluster_size = bytes_per_sector * sectors_per_cluster
    data_offset = (reserved_sectors + num_fats * sectors_per_fat) * bytes_per_sector

    def read_cluster(c):
        f.seek(data_offset + (c - 2) * cluster_size)
        return f.read(cluster_size)

    # Let's read FAT to follow directory chains
    f.seek(reserved_sectors * bytes_per_sector)
    fat_data = f.read(sectors_per_fat * bytes_per_sector)

    def get_fat_entry(c):
        return struct.unpack('<I', fat_data[c*4:(c+1)*4])[0] & 0x0FFFFFFF

    def get_cluster_chain(start):
        chain = []
        curr = start
        while curr < 0x0FFFFFF8 and curr >= 2:
            chain.append(curr)
            curr = get_fat_entry(curr)
        return chain

    visited_dirs = set()

    def scan_dir(start_clus, path=''):
        if start_clus in visited_dirs or start_clus < 2:
            return
        visited_dirs.add(start_clus)
        chain = get_cluster_chain(start_clus)
        dir_bytes = b''.join(read_cluster(c) for c in chain)

        lfn_parts = []
        for i in range(0, len(dir_bytes), 32):
            entry = dir_bytes[i:i+32]
            if entry[0] == 0:
                break
            if entry[11] == 0x0f:
                # LFN
                name_chunk = entry[1:11] + entry[14:26] + entry[28:32]
                lfn_parts.append(name_chunk)
            elif entry[0] == 0xe5:
                # Deleted entry!
                short_name = entry[:11]
                attr = entry[11]
                high_clus = struct.unpack('<H', entry[20:22])[0]
                low_clus = struct.unpack('<H', entry[26:28])[0]
                size = struct.unpack('<I', entry[28:32])[0]
                full_clus = (high_clus << 16) | low_clus
                wtime = struct.unpack('<H', entry[22:24])[0]
                wdate = struct.unpack('<H', entry[24:26])[0]
                year = ((wdate >> 9) & 0x7f) + 1980
                month = (wdate >> 5) & 0x0f
                day = wdate & 0x1f
                hour = (wtime >> 11) & 0x1f
                minute = (wtime >> 5) & 0x3f
                sec = (wtime & 0x1f) * 2

                lfn_str = ''
                if lfn_parts:
                    try:
                        raw_lfn = b''.join(reversed(lfn_parts))
                        lfn_str = raw_lfn.decode('utf-16le', errors='ignore').split('\x00')[0]
                    except:
                        pass
                print(f'DELETED in {path}: LFN=\"{lfn_str}\" SFN={short_name} Size={size} Date={year}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d} Clus={full_clus}')
                lfn_parts = []
            else:
                attr = entry[11]
                is_dir = bool(attr & 0x10)
                short_name = entry[:11]
                high_clus = struct.unpack('<H', entry[20:22])[0]
                low_clus = struct.unpack('<H', entry[26:28])[0]
                child_clus = (high_clus << 16) | low_clus
                lfn_str = ''
                if lfn_parts:
                    try:
                        raw_lfn = b''.join(reversed(lfn_parts))
                        lfn_str = raw_lfn.decode('utf-16le', errors='ignore').split('\x00')[0]
                    except:
                        pass
                name = lfn_str if lfn_str else short_name.decode('latin1', errors='ignore').strip()
                lfn_parts = []
                if is_dir and name not in ['.', '..']:
                    scan_dir(child_clus, f'{path}/{name}')

    print('Scanning filesystem...')
    scan_dir(root_cluster, '')
    print('Scan complete.')
