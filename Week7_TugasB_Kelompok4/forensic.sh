#!/bin/bash
IMG="/mnt/c/Users/nisri/.gemini/antigravity/scratch/fordig-week7/linux_forensic_case.img"

echo "=== FSSTAT ==="
fsstat "$IMG" 2>&1 | head -20

echo ""
echo "=== FLS - ALL FILES (including deleted) ==="
fls -r "$IMG" 2>&1

echo ""
echo "=== ISTAT inode 16 (DELETED/ORPHAN) ==="
istat "$IMG" 16 2>&1

echo ""
echo "=== ISTAT inode 17 (.catatan.txt) ==="
istat "$IMG" 17 2>&1

echo ""
echo "=== ISTAT inode 18 (jadwal_proyek.txt) ==="
istat "$IMG" 18 2>&1

echo ""
echo "=== ISTAT inode 19 (jadwal_awal.sha256) ==="
istat "$IMG" 19 2>&1

echo ""
echo "=== ISTAT inode 20 (jadwal_versi_awal.txt) ==="
istat "$IMG" 20 2>&1

echo ""
echo "=== ISTAT inode 21 (jadwal_baru.sha256) ==="
istat "$IMG" 21 2>&1

echo ""
echo "=== ISTAT inode 22 (incident.log) ==="
istat "$IMG" 22 2>&1

echo ""
echo "=== CONTENT: .catatan.txt (inode 17) ==="
icat "$IMG" 17 2>&1

echo ""
echo "=== CONTENT: jadwal_proyek.txt (inode 18) ==="
icat "$IMG" 18 2>&1

echo ""
echo "=== CONTENT: jadwal_awal.sha256 (inode 19) ==="
icat "$IMG" 19 2>&1

echo ""
echo "=== CONTENT: jadwal_versi_awal.txt (inode 20) ==="
icat "$IMG" 20 2>&1

echo ""
echo "=== CONTENT: jadwal_baru.sha256 (inode 21) ==="
icat "$IMG" 21 2>&1

echo ""
echo "=== CONTENT: incident.log (inode 22) ==="
icat "$IMG" 22 2>&1

echo ""
echo "=== RECOVER DELETED: inode 16 ==="
icat -r "$IMG" 16 2>&1

echo ""
echo "=== SHA256 CHECK: jadwal_proyek.txt vs jadwal_versi_awal.txt ==="
echo "jadwal_proyek.txt SHA256:"
icat "$IMG" 18 2>/dev/null | sha256sum
echo "jadwal_versi_awal.txt SHA256:"
icat "$IMG" 20 2>/dev/null | sha256sum
echo "jadwal_awal.sha256 contents:"
icat "$IMG" 19 2>&1
echo "jadwal_baru.sha256 contents:"
icat "$IMG" 21 2>&1
