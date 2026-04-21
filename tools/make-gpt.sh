#!/bin/bash
# Write GPT (GUID Partition Table) structures to test.img.
# Run AFTER all make-*.sh scripts have populated the filesystem data.
# Writes: protective MBR (LBA 0), GPT header (LBA 1), partition entries
# (LBAs 2-33), and backup GPT at end of disk.
#
# Partition layout (all at 1 MiB-aligned boundaries):
#   1: FAT16         1 MiB  -  17 MiB   (Microsoft Basic Data)
#   2: ext2/3/4     17 MiB  -  33 MiB   (Linux Filesystem)
#   3: UDF          35 MiB  -  37 MiB   (Microsoft Basic Data)
#   4: XFS          37 MiB  - 337 MiB   (Linux Filesystem)
#   5: APFS        337 MiB  - 369 MiB   (Apple APFS)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found."
    exit 1
fi

python3 - "$DISK_IMG" <<'PYEOF'
import struct, sys, binascii, os

disk_path = sys.argv[1]
disk_size = os.path.getsize(disk_path)
sector_size = 512
total_sectors = disk_size // sector_size

# Ensure enough room for backup GPT (33 sectors at end).
# If needed, extend the disk.
min_size = disk_size + 33 * sector_size
if disk_size < min_size:
    with open(disk_path, 'ab') as f:
        f.write(b'\x00' * (min_size - disk_size))
    disk_size = min_size
    total_sectors = disk_size // sector_size

last_lba = total_sectors - 1
first_usable_lba = 34          # after GPT header + 32 sectors of entries
last_usable_lba = last_lba - 33  # before backup entries + backup header

# --- GUID encoding (mixed-endian) ---
def guid_bytes(s):
    """Convert 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX' to 16 bytes (mixed-endian)."""
    parts = s.replace('-', '')
    # First 3 groups: little-endian; last 2 groups: big-endian
    a = int(s.split('-')[0], 16).to_bytes(4, 'little')
    b = int(s.split('-')[1], 16).to_bytes(2, 'little')
    c = int(s.split('-')[2], 16).to_bytes(2, 'little')
    d = bytes.fromhex(s.split('-')[3])
    e = bytes.fromhex(s.split('-')[4])
    return a + b + c + d + e

# Partition type GUIDs
BASIC_DATA    = guid_bytes('EBD0A0A2-B9E5-4433-87C0-68B6B72699C7')  # FAT, UDF
LINUX_FS      = guid_bytes('0FC63DAF-8483-4772-8E79-3D69D8477DE4')  # ext, xfs
APPLE_APFS    = guid_bytes('7C3457EF-0000-11AA-AA11-00306543ECAC')  # APFS
# Disk GUID (fixed for reproducibility)
DISK_GUID     = guid_bytes('A1B2C3D4-E5F6-4789-ABCD-0123456789AB')

def mib_to_lba(mib):
    return (mib * 1024 * 1024) // sector_size

# --- Partition definitions ---
partitions = [
    # (name,    type_guid,   first_lba,              last_lba,             unique_guid_seed)
    ('FAT16',   BASIC_DATA,  mib_to_lba(1),          mib_to_lba(17) - 1,  1),
    ('ext2',    LINUX_FS,    mib_to_lba(17),         mib_to_lba(33) - 1,  2),
    ('UDF',     BASIC_DATA,  mib_to_lba(35),         mib_to_lba(37) - 1,  3),
    ('XFS',     LINUX_FS,    mib_to_lba(37),         mib_to_lba(337) - 1, 4),
    ('APFS',    APPLE_APFS,  mib_to_lba(337),        mib_to_lba(369) - 1, 5),
]

# --- Build partition entries (128 bytes each, 128 entries, = 16384 bytes = 32 sectors) ---
NUM_ENTRIES = 128
ENTRY_SIZE = 128
entries_blob = bytearray(NUM_ENTRIES * ENTRY_SIZE)

for i, (name, type_guid, first, last, seed) in enumerate(partitions):
    off = i * ENTRY_SIZE
    # Type GUID (16 bytes)
    entries_blob[off:off+16] = type_guid
    # Unique GUID (16 bytes) - deterministic from seed
    unique = guid_bytes(f'{seed:08X}-0000-4000-8000-000000000000')
    entries_blob[off+16:off+32] = unique
    # First LBA (8 bytes LE)
    struct.pack_into('<Q', entries_blob, off+32, first)
    # Last LBA (8 bytes LE)
    struct.pack_into('<Q', entries_blob, off+40, last)
    # Attributes (8 bytes) = 0
    # Name (72 bytes, UTF-16LE)
    name_utf16 = name.encode('utf-16-le')[:72]
    entries_blob[off+56:off+56+len(name_utf16)] = name_utf16

entries_crc = binascii.crc32(bytes(entries_blob)) & 0xFFFFFFFF

# --- Build GPT header (92 bytes at LBA 1) ---
def build_gpt_header(my_lba, alt_lba, entries_lba):
    hdr = bytearray(92)
    # Signature
    hdr[0:8] = b'EFI PART'
    # Revision (1.0)
    struct.pack_into('<I', hdr, 8, 0x00010000)
    # Header size
    struct.pack_into('<I', hdr, 12, 92)
    # CRC32 (filled later)
    struct.pack_into('<I', hdr, 16, 0)
    # Reserved
    struct.pack_into('<I', hdr, 20, 0)
    # My LBA
    struct.pack_into('<Q', hdr, 24, my_lba)
    # Alternate LBA
    struct.pack_into('<Q', hdr, 32, alt_lba)
    # First usable LBA
    struct.pack_into('<Q', hdr, 40, first_usable_lba)
    # Last usable LBA
    struct.pack_into('<Q', hdr, 48, last_usable_lba)
    # Disk GUID
    hdr[56:72] = DISK_GUID
    # Partition entry start LBA
    struct.pack_into('<Q', hdr, 72, entries_lba)
    # Number of partition entries
    struct.pack_into('<I', hdr, 80, NUM_ENTRIES)
    # Size of partition entry
    struct.pack_into('<I', hdr, 84, ENTRY_SIZE)
    # CRC32 of partition entries
    struct.pack_into('<I', hdr, 88, entries_crc)
    # Now compute header CRC
    hdr_crc = binascii.crc32(bytes(hdr)) & 0xFFFFFFFF
    struct.pack_into('<I', hdr, 16, hdr_crc)
    return bytes(hdr)

primary_hdr = build_gpt_header(1, last_lba, 2)
backup_entries_lba = last_lba - 32
backup_hdr = build_gpt_header(last_lba, 1, backup_entries_lba)

# --- Build protective MBR (LBA 0) ---
mbr = bytearray(512)
# Partition entry 1 at offset 446 (16 bytes)
mbr[446] = 0x00       # status (not bootable)
# CHS of first sector (LBA 1) — use dummy 0x00,0x02,0x00
mbr[447] = 0x00; mbr[448] = 0x02; mbr[449] = 0x00
mbr[450] = 0xEE       # partition type = GPT protective
# CHS of last sector — use 0xFF,0xFF,0xFF
mbr[451] = 0xFF; mbr[452] = 0xFF; mbr[453] = 0xFF
# LBA of first sector
struct.pack_into('<I', mbr, 454, 1)
# Number of sectors (capped at 0xFFFFFFFF for large disks)
nsectors = min(total_sectors - 1, 0xFFFFFFFF)
struct.pack_into('<I', mbr, 458, nsectors)
# Boot signature
mbr[510] = 0x55
mbr[511] = 0xAA

# --- Write everything to disk ---
with open(disk_path, 'r+b') as f:
    # Protective MBR at LBA 0
    f.seek(0)
    f.write(bytes(mbr))

    # Primary GPT header at LBA 1
    f.seek(sector_size)
    f.write(primary_hdr)
    # Pad to full sector
    f.write(b'\x00' * (sector_size - len(primary_hdr)))

    # Primary partition entries at LBAs 2-33
    f.seek(2 * sector_size)
    f.write(bytes(entries_blob))

    # Backup partition entries
    f.seek(backup_entries_lba * sector_size)
    f.write(bytes(entries_blob))

    # Backup GPT header at last LBA
    f.seek(last_lba * sector_size)
    f.write(backup_hdr)
    f.write(b'\x00' * (sector_size - len(backup_hdr)))

print(f"  GPT written: {len(partitions)} partitions, {total_sectors} sectors ({disk_size // (1024*1024)} MiB)")
for name, _, first, last, _ in partitions:
    size_mib = (last - first + 1) * sector_size // (1024 * 1024)
    print(f"    {name:8s}  LBA {first:>8d} - {last:>8d}  ({size_mib} MiB)")
PYEOF
