#!/bin/bash
# Append a 16 MiB ext2 partition to test.img after the FAT16 region.
# Layout: 1 MiB GPT + 16 MiB FAT16 + 16 MiB ext2 = ext2 at 17 MiB.
# Requires: e2fsprogs (mke2fs), debugfs or e2tools or fuse2fs
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DISK_IMG="$SCRIPT_DIR/../test.img"

if [ ! -f "$DISK_IMG" ]; then
    echo "ERROR: $DISK_IMG not found. Run make-fat16.sh first."
    exit 1
fi

EXT2_OFFSET=$((17 * 1024 * 1024))
EXT2_SIZE=$((16 * 1024 * 1024))
TOTAL_SIZE=$((EXT2_OFFSET + EXT2_SIZE))

# Truncate to include both partitions.
truncate -s "$TOTAL_SIZE" "$DISK_IMG"

# Create a temporary ext2 image.
EXT2_TMP=$(mktemp)
dd if=/dev/zero of="$EXT2_TMP" bs=1M count=16 2>/dev/null

# Format as ext2: 1024-byte blocks, 128-byte inodes, no journal.
mke2fs -t ext2 -b 1024 -I 128 -F -q "$EXT2_TMP"

# Populate with test files using debugfs and temp files.
TMPFILE=$(mktemp)
echo -n "Hello from ext2!" > "$TMPFILE"

TMPFILE2=$(mktemp)
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)) * 4)" > "$TMPFILE2"

TMPFILE3=$(mktemp)
echo -n "File with restricted permissions" > "$TMPFILE3"

# /etc/passwd and /etc/group for Phase 65 (getty/login).
PASSWD_TMP=$(mktemp)
printf 'root::0:0:root:/:/tsh\nuser:pass:1000:1000:user:/:/tsh\n' > "$PASSWD_TMP"

GROUP_TMP=$(mktemp)
printf 'root:x:0:\nusers:x:1000:\n' > "$GROUP_TMP"

# /etc/localtime — minimal TZif v1 header for UTC (Phase 72).
LOCALTIME_TMP=$(mktemp)
python3 -c "
import struct, sys
# TZif v1 header: magic, version, reserved, counts, data
magic = b'TZif'
version = b' '  # v1
reserved = b'\0' * 15
# All counts zero (UTC, no transitions/types)
tzh_ttisgmtcnt = 0
tzh_ttisstdcnt = 0
tzh_leapcnt = 0
tzh_timecnt = 0
tzh_typecnt = 1
tzh_charcnt = 4
hdr = struct.pack('>4s c 15s 6I', magic, version, reserved,
    tzh_ttisgmtcnt, tzh_ttisstdcnt, tzh_leapcnt,
    tzh_timecnt, tzh_typecnt, tzh_charcnt)
# ttinfo: utoff=0, dst=0, idx=0
ttinfo = struct.pack('>lBB', 0, 0, 0)
# designation: 'UTC\0'
desig = b'UTC\0'
sys.stdout.buffer.write(hdr + ttinfo + desig)
" > "$LOCALTIME_TMP"

# /etc/resolv.conf (Phase 73).
RESOLV_TMP=$(mktemp)
printf 'nameserver 10.0.2.3\n' > "$RESOLV_TMP"

# Glibc dynamic linker artifacts (Phase 172): copy real ld-linux + libc.so.6 etc.
# from initramfs/lib64 into the ext2 image so dynamically-linked binaries can
# resolve their interpreter and shared libraries when ext2 is the root mount.
INITRAMFS_DIR="$SCRIPT_DIR/../initramfs"
LD_SO="$INITRAMFS_DIR/lib64/ld-linux-x86-64.so.2"
LIBC_SO="$INITRAMFS_DIR/lib64/libc.so.6"
LIBPTHREAD_SO="$INITRAMFS_DIR/lib64/libpthread.so.0"
GLIBC_DYN_HELLO="$INITRAMFS_DIR/glibc_dyn_hello"
LIBXCVT_DYN_TEST="$INITRAMFS_DIR/libxcvt_dyn_test"
FSPROBE="$INITRAMFS_DIR/fsprobe"

# Tier-0 Xwayland deps: enumerate every .so under initramfs/lib64/ that
# isn't a glibc artifact already handled above so the ext2 root sees the
# same library set as initramfs.
TIER0_LIBS=$(find "$INITRAMFS_DIR/lib64" -maxdepth 1 -name '*.so*' \
    ! -name 'ld-linux-x86-64.so.2' \
    ! -name 'libc.so.6' \
    ! -name 'libpthread.so.0' \
    -printf '%f\n' 2>/dev/null | sort)

# Build dynamic chunks of debugfs commands for the Tier-0 libs and the
# libxcvt_dyn_test binary.  These must end up inside the heredoc below.
TIER0_WRITES=""
TIER0_PERMS=""
for lib in $TIER0_LIBS; do
    TIER0_WRITES+="write $INITRAMFS_DIR/lib64/$lib lib64/$lib"$'\n'
    TIER0_PERMS+="set_inode_field lib64/$lib mode 0100755"$'\n'
done
TEST_WRITE=""
TEST_PERM=""
if [ -f "$LIBXCVT_DYN_TEST" ]; then
    TEST_WRITE="write $LIBXCVT_DYN_TEST libxcvt_dyn_test"
    TEST_PERM="set_inode_field libxcvt_dyn_test mode 0100755"
fi
FSPROBE_WRITE=""
FSPROBE_PERM=""
if [ -f "$FSPROBE" ]; then
    FSPROBE_WRITE="write $FSPROBE fsprobe"
    FSPROBE_PERM="set_inode_field fsprobe mode 0100755"
fi

# Use debugfs to populate the filesystem.
debugfs -w "$EXT2_TMP" <<DEBUGFS_EOF
mkdir testdir
mkdir etc
mkdir usr
mkdir usr/share
mkdir usr/share/zoneinfo
mkdir lib64
write $LD_SO lib64/ld-linux-x86-64.so.2
write $LIBC_SO lib64/libc.so.6
write $LIBPTHREAD_SO lib64/libpthread.so.0
write $GLIBC_DYN_HELLO glibc_dyn_hello
$TEST_WRITE
$FSPROBE_WRITE
${TIER0_WRITES}set_inode_field lib64 mode 040755
set_inode_field lib64/ld-linux-x86-64.so.2 mode 0100755
set_inode_field lib64/libc.so.6 mode 0100755
set_inode_field lib64/libpthread.so.0 mode 0100755
set_inode_field glibc_dyn_hello mode 0100755
$TEST_PERM
$FSPROBE_PERM
${TIER0_PERMS}write $TMPFILE hello.txt
write $TMPFILE2 bench.dat
write $TMPFILE3 secret.txt
write $PASSWD_TMP etc/passwd
write $GROUP_TMP etc/group
set_inode_field hello.txt mode 0100644
set_inode_field hello.txt uid 1000
set_inode_field hello.txt gid 1000
set_inode_field bench.dat mode 0100644
set_inode_field bench.dat uid 0
set_inode_field bench.dat gid 0
set_inode_field secret.txt mode 0100600
set_inode_field secret.txt uid 0
set_inode_field secret.txt gid 0
set_inode_field testdir mode 040755
set_inode_field testdir uid 1000
set_inode_field testdir gid 1000
set_inode_field etc mode 040755
set_inode_field etc uid 0
set_inode_field etc gid 0
set_inode_field etc/passwd mode 0100644
set_inode_field etc/passwd uid 0
set_inode_field etc/passwd gid 0
set_inode_field etc/group mode 0100644
set_inode_field etc/group uid 0
set_inode_field etc/group gid 0
write $LOCALTIME_TMP etc/localtime
set_inode_field etc/localtime mode 0100644
set_inode_field etc/localtime uid 0
set_inode_field etc/localtime gid 0
write $RESOLV_TMP etc/resolv.conf
set_inode_field etc/resolv.conf mode 0100644
set_inode_field etc/resolv.conf uid 0
set_inode_field etc/resolv.conf gid 0
write $LOCALTIME_TMP usr/share/zoneinfo/UTC
set_inode_field usr/share/zoneinfo/UTC mode 0100644
set_inode_field usr mode 040755
set_inode_field usr/share mode 040755
set_inode_field usr/share/zoneinfo mode 040755
DEBUGFS_EOF

rm -f "$TMPFILE" "$TMPFILE2" "$TMPFILE3" "$PASSWD_TMP" "$GROUP_TMP" "$LOCALTIME_TMP" "$RESOLV_TMP"

# Splice the ext2 image into test.img at the ext2 partition offset.
dd if="$EXT2_TMP" of="$DISK_IMG" bs=1M seek=$((EXT2_OFFSET / 1024 / 1024)) conv=notrunc 2>/dev/null
rm -f "$EXT2_TMP"

echo "  ext2 partition appended to test.img at offset $EXT2_OFFSET ($((EXT2_SIZE / 1024)) KiB ext2)"
