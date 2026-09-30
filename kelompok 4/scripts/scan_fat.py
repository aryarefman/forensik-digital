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

    # Let's inspect cluster 7 (TUGAS)
    tugas_data = read_cluster(7)
    print('--- TUGAS directory entries (cluster 7) ---')
    for i in range(0, len(tugas_data), 32):
        entry = tugas_data[i:i+32]
        if entry[0] == 0:
            print(f'End of directory at entry {i//32}')
            break
        if entry[0] == 0xe5:
            clus = (entry[21] << 24) | (entry[20] << 16) | (entry[27] << 8) | entry[26]
            size = struct.unpack('<I', entry[28:32])[0]
            print(f'DELETED ENTRY: raw={entry[:11]} attr={entry[11]} cluster={clus} size={size}')
        elif entry[11] == 0x0f:
            print(f'LFN chunk: {entry[:11]} raw={entry}')
        else:
            name = entry[:11]
            attr = entry[11]
            clus = (entry[21] << 24) | (entry[20] << 16) | (entry[27] << 8) | entry[26]
            size = struct.unpack('<I', entry[28:32])[0]
            print(f'Entry: {name} attr={hex(attr)} cluster={clus} size={size}')
