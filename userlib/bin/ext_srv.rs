#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux fs/ext2, Linux fs/ext4, e2fsprogs

//! Unified ext2/ext3/ext4 filesystem server.
//!
//! Pure userspace process that reads an ext2/3/4 partition from blk_srv via IPC.
//! The partition starts at a byte offset passed as arg0 (default 16 MiB).
//! Detects the filesystem variant from superblock feature flags:
//!   - ext2: no journal, no extents
//!   - ext3: has_journal but no extents
//!   - ext4: extents and/or 64-bit block numbers
//!
//! Supports multiple block groups, ext4 extent trees (read), and 64-bit
//! block numbers. Write support uses indirect blocks (ext2-compatible).

extern crate userlib;

use core::cell::Cell;
use userlib::syscall;

// --- I/O protocol constants (for talking to blk_srv) ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;

// --- FS protocol constants (served by this server) ---
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_OPEN_LONG: u64 = 0x2002;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
const FS_STAT_LONG: u64 = 0x2302;
/// VFS grants its scratch page here in our aspace for long-path lookups.
const VFS_LONG_PATH_SCRATCH_VA: usize = 0x5_0000_0000;
const FS_CLOSE: u64 = 0x2400;
const FS_CLOSE_OK: u64 = 0x2401;
const FS_CREATE: u64 = 0x2500;
const FS_CREATE_OK: u64 = 0x2501;
const FS_WRITE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;
const FS_DELETE: u64 = 0x2700;
#[allow(dead_code)]
const FS_DELETE_OK: u64 = 0x2701;
const FS_MKDIR: u64 = 0x2A00;
const FS_MKDIR_OK: u64 = 0x2A01;
const FS_UNLINK: u64 = 0x2A20;
const FS_UNLINK_OK: u64 = 0x2A21;
const FS_FSYNC: u64 = 0x2B00;
const FS_FSYNC_OK: u64 = 0x2B01;
const FS_CHMOD: u64 = 0x2E00;
const FS_CHMOD_OK: u64 = 0x2E01;
const FS_UTIMENS: u64 = 0x2900;
const FS_UTIMENS_OK: u64 = 0x2901;
const FS_ERROR: u64 = 0x2F00;

// File lock protocol.
const FS_FLOCK: u64 = 0x2800;
const FS_FLOCK_OK: u64 = 0x2801;
const FS_GETLK: u64 = 0x2810;
const FS_GETLK_OK: u64 = 0x2811;
const FS_SETLK: u64 = 0x2820;
const FS_SETLK_OK: u64 = 0x2821;
const FS_SETLKW: u64 = 0x2830;
const FS_SETLKW_OK: u64 = 0x2831;
const FS_LOCK_ERR: u64 = 0x28FF;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;
const ERR_AGAIN: u64 = 11;

const MAX_OPEN_FILES: usize = 8;
const MAX_INLINE: usize = 24;

// --- ext2/3/4 on-disk constants ---
const EXT2_SUPER_MAGIC: u16 = 0xEF53;
const EXT2_ROOT_INO: u32 = 2;

// Superblock feature flag offsets (relative to superblock start).
// s_feature_compat  at offset 92 (u32)
// s_feature_incompat at offset 96 (u32)
// s_feature_ro_compat at offset 100 (u32)

// COMPAT features.
const EXT3_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;

// INCOMPAT features.
const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0002; // same bit as FILETYPE in compat, but this is incompat
// Note: FILETYPE and 64BIT share bit 0x0002 but are in different flag fields.
// Corrected: INCOMPAT_64BIT = 0x0080
const EXT4_FEATURE_INCOMPAT_64BIT_ACTUAL: u32 = 0x0080;
const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;

// Inode flags (i_flags at inode offset 32).
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

// Extent tree magic.
const EXT4_EXT_MAGIC: u16 = 0xF30A;

// Default block group descriptor sizes.
const EXT2_BGD_SIZE: u16 = 32;

// --- Filesystem variant ---

#[derive(Clone, Copy, PartialEq)]
enum ExtVariant {
    Ext2,
    Ext3,
    Ext4,
}

// --- Helpers ---

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

fn print_hex(n: u64) {
    syscall::debug_puts(b"0x");
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        let nibble = (val & 0xF) as u8;
        buf[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
        val >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

fn read_u16(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
}

fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
    buf[off + 2] = (val >> 16) as u8;
    buf[off + 3] = (val >> 24) as u8;
}

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

fn unpack_name(d0: u64, d1: u64, len: usize) -> [u8; 24] {
    let mut buf = [0u8; 24];
    let words = [d0, d1];
    for i in 0..len.min(16) {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    buf
}

// --- On-disk structures ---

struct Superblock {
    inodes_count: u32,
    blocks_count: u64,       // 64-bit for ext4 64BIT mode
    free_blocks_count: u64,
    free_inodes_count: u32,
    first_data_block: u32,
    block_size: u32,         // in bytes (1024 << s_log_block_size)
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    log_block_size: u32,
    desc_size: u16,          // block group descriptor size (32 for ext2/3, 64 for ext4 64BIT)
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    variant: ExtVariant,
}

impl Superblock {
    fn has_64bit(&self) -> bool {
        self.feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT_ACTUAL != 0
    }

    fn num_block_groups(&self) -> u32 {
        let bc = self.blocks_count as u64;
        let bpg = self.blocks_per_group as u64;
        if bpg == 0 {
            return 1;
        }
        ((bc + bpg - 1) / bpg) as u32
    }
}

struct BlockGroupDesc {
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
}

#[derive(Clone, Copy)]
struct OpenFile {
    inode_num: u32,
    file_size: u64,
    mode: u16,
    uid: u16,
    gid: u16,
    inode_flags: u32,
    block_ptrs: [u32; 15],  // i_block[0..14]: indirect block pointers or extent tree root
    active: bool,
    writable: bool,
    pid: u32,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            inode_num: 0,
            file_size: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            inode_flags: 0,
            block_ptrs: [0; 15],
            active: false,
            writable: false,
            pid: 0,
        }
    }

    fn uses_extents(&self) -> bool {
        self.inode_flags & EXT4_EXTENTS_FL != 0
    }
}

// --- Advisory file lock table ---

const MAX_LOCKS: usize = 32;
const MAX_LOCK_WAITERS: usize = 8;
const LK_RDLCK: u8 = 0;
const LK_WRLCK: u8 = 1;
const LK_UNLCK: u8 = 2;

#[derive(Clone, Copy)]
struct FileLock {
    active: bool,
    inode: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
}

impl FileLock {
    const fn empty() -> Self {
        Self {
            active: false,
            inode: 0,
            pid: 0,
            lock_type: 0,
            start: 0,
            len: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct LockWaiter {
    active: bool,
    reply_port: u64,
    inode: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
}

impl LockWaiter {
    const fn empty() -> Self {
        Self {
            active: false,
            reply_port: 0,
            inode: 0,
            pid: 0,
            lock_type: 0,
            start: 0,
            len: 0,
        }
    }
}

fn ranges_overlap(s1: u64, l1: u64, s2: u64, l2: u64) -> bool {
    let e1 = if l1 == 0 {
        u64::MAX
    } else {
        s1.saturating_add(l1)
    };
    let e2 = if l2 == 0 {
        u64::MAX
    } else {
        s2.saturating_add(l2)
    };
    s1 < e2 && s2 < e1
}

fn lock_conflicts(
    locks: &[FileLock; MAX_LOCKS],
    inode: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
) -> bool {
    for lk in locks.iter() {
        if !lk.active || lk.inode != inode || lk.pid == pid {
            continue;
        }
        if lk.lock_type == LK_RDLCK && lock_type == LK_RDLCK {
            continue;
        }
        if ranges_overlap(lk.start, lk.len, start, len) {
            return true;
        }
    }
    false
}

fn find_conflict(
    locks: &[FileLock; MAX_LOCKS],
    inode: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
) -> Option<usize> {
    for (i, lk) in locks.iter().enumerate() {
        if !lk.active || lk.inode != inode || lk.pid == pid {
            continue;
        }
        if lk.lock_type == LK_RDLCK && lock_type == LK_RDLCK {
            continue;
        }
        if ranges_overlap(lk.start, lk.len, start, len) {
            return Some(i);
        }
    }
    None
}

fn acquire_lock(
    locks: &mut [FileLock; MAX_LOCKS],
    inode: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
) -> bool {
    for lk in locks.iter_mut() {
        if lk.active
            && lk.inode == inode
            && lk.pid == pid
            && ranges_overlap(lk.start, lk.len, start, len)
        {
            lk.active = false;
        }
    }
    for lk in locks.iter_mut() {
        if !lk.active {
            *lk = FileLock {
                active: true,
                inode,
                pid,
                lock_type,
                start,
                len,
            };
            return true;
        }
    }
    false
}

fn release_locks(
    locks: &mut [FileLock; MAX_LOCKS],
    inode: u32,
    pid: u32,
    start: u64,
    len: u64,
) {
    for lk in locks.iter_mut() {
        if lk.active && lk.inode == inode && lk.pid == pid {
            if (start == 0 && len == 0) || ranges_overlap(lk.start, lk.len, start, len) {
                lk.active = false;
            }
        }
    }
}

fn try_wake_waiters(
    locks: &mut [FileLock; MAX_LOCKS],
    waiters: &mut [LockWaiter; MAX_LOCK_WAITERS],
    inode: u32,
) {
    for w in waiters.iter_mut() {
        if !w.active || w.inode != inode {
            continue;
        }
        if !lock_conflicts(locks, w.inode, w.pid, w.lock_type, w.start, w.len) {
            if acquire_lock(locks, w.inode, w.pid, w.lock_type, w.start, w.len) {
                let _ = syscall::reply_to(w.reply_port, FS_FLOCK_OK, 0, 0, 0, 0);
            } else {
                let _ = syscall::reply_to(w.reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
            }
            w.active = false;
        }
    }
}

// --- Block I/O client ---

struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
    grant_va: usize,
    /// Byte offset of the ext partition within the disk image.
    partition_offset: u64,
    /// Per-client nonce counter.  Each IO_READ/IO_WRITE request gets a fresh
    /// nonce in d0; cache_blk echoes it in d1 of the reply.  We discard any
    /// reply whose echo doesn't match — eliminates the stale-reply race that
    /// otherwise made the permanent grant unsafe.
    nonce: Cell<u64>,
}

impl BlkClient {
    fn next_nonce(&self) -> u64 {
        let n = self.nonce.get().wrapping_add(1);
        self.nonce.set(n);
        n
    }

    /// Receive a reply matching `nonce`.  Drops mismatched (stale) replies and
    /// keeps waiting until either a matching reply arrives or recv_msg_timeout
    /// expires with no message at all.  No global deadline — under normal
    /// load the matching reply is the only one in the queue, and the timeout
    /// fires once if the request is genuinely lost.
    fn recv_match(&self, nonce: u64) -> Option<syscall::Message> {
        loop {
            match syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
                Some(rr) if rr.data[1] == nonce => {
                    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
                    // 1 us sleep -- yield_now alone returned immediately when no
                    // other task was ready, leaving a memory-ordering window
                    // open under boot-time concurrency on x86 KVM.
                    syscall::nanosleep(1_000);
                    return Some(rr);
                }
                Some(_) => continue, // stale reply, drop it
                None => return None,
            }
        }
    }

    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
    /// `out` must be <= 512 bytes. Only reads from the sector containing `off`.
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let abs_off = self.partition_offset + off;
        let sector = abs_off / 512;
        let offset_in_sector = (abs_off % 512) as usize;

        let nonce = self.next_nonce();
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_READ,
            nonce,
            sector * 512,
            d2,
            self.grant_va as u64,
        );

        if let Some(rr) = self.recv_match(nonce) {
            if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                let copy_len = out.len().min(512 - offset_in_sector);
                let src = (self.scratch_va + offset_in_sector) as *const u8;
                let dst = out.as_mut_ptr();
                unsafe {
                    for i in 0..copy_len {
                        let b = core::ptr::read_volatile(src.add(i));
                        core::ptr::write_volatile(dst.add(i), b);
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Read a full block (block_size bytes) into memory at `dest`.
    /// Block numbers use u64 for ext4 64-bit support.
    fn read_block(&self, block_num: u64, block_size: u32, dest: usize) -> bool {
        let byte_off = block_num * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let bs = block_size as usize;
        if bs < 512 {
            let mut sec = [0u8; 512];
            if !self.read_bytes(byte_off, &mut sec) {
                return false;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(sec.as_ptr(), dest as *mut u8, bs);
            }
            return true;
        }

        // blk_srv supports multi-sector grant reads up to 4 KiB (one MMU page),
        // so issue one IO_READ for block sizes ≤ 4096; only chunk for larger
        // ext4 blocks (8 KiB / 16 KiB / 32 KiB / 64 KiB).
        const MAX_BATCH: usize = 4096;
        let mut consumed = 0usize;
        while consumed < bs {
            let chunk = (bs - consumed).min(MAX_BATCH);

            let nonce = self.next_nonce();
            let chunk_byte = abs_off + consumed as u64;
            let d2 = (chunk as u64) | ((self.reply_port as u64) << 32);
            syscall::send(
                self.blk_port,
                IO_READ,
                nonce,
                chunk_byte,
                d2,
                self.grant_va as u64,
            );

            let ok = if let Some(rr) = self.recv_match(nonce) {
                if rr.tag == IO_READ_OK && rr.data[0] as usize == chunk {
                    let src = self.scratch_va as *const u8;
                    let dst = (dest + consumed) as *mut u8;
                    unsafe {
                        for i in 0..chunk {
                            let b = core::ptr::read_volatile(src.add(i));
                            core::ptr::write_volatile(dst.add(i), b);
                        }
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !ok {
                return false;
            }
            consumed += chunk;
        }
        true
    }

    /// Write a 512-byte sector at absolute byte offset.
    fn write_sector(&self, abs_byte_off: u64, data: &[u8; 512]) -> bool {
        let src = data.as_ptr();
        let dst = self.scratch_va as *mut u8;
        unsafe {
            for i in 0..512 {
                let b = core::ptr::read_volatile(src.add(i));
                core::ptr::write_volatile(dst.add(i), b);
            }
        }
        let nonce = self.next_nonce();
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_WRITE,
            nonce,
            abs_byte_off,
            d2,
            self.grant_va as u64,
        );
        if let Some(rr) = self.recv_match(nonce) {
            rr.tag == IO_WRITE_OK
        } else {
            false
        }
    }

    /// Read-modify-write: write `data` bytes at byte offset `off` (relative to partition).
    fn write_bytes(&self, off: u64, data: &[u8]) -> bool {
        let abs_off = self.partition_offset + off;
        let sector_start = (abs_off / 512) * 512;
        let offset_in_sector = (abs_off % 512) as usize;

        let mut sec = [0u8; 512];
        let nonce = self.next_nonce();
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_READ,
            nonce,
            sector_start,
            d2,
            self.grant_va as u64,
        );
        let ok = if let Some(rr) = self.recv_match(nonce) {
            if rr.tag == IO_READ_OK {
                let src = self.scratch_va as *const u8;
                let dst = sec.as_mut_ptr();
                unsafe {
                    for i in 0..512 {
                        let b = core::ptr::read_volatile(src.add(i));
                        core::ptr::write_volatile(dst.add(i), b);
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        if !ok {
            return false;
        }

        let copy_len = data.len().min(512 - offset_in_sector);
        sec[offset_in_sector..offset_in_sector + copy_len].copy_from_slice(&data[..copy_len]);

        self.write_sector(sector_start, &sec)
    }

    /// Write a full block from memory at `src` to disk.
    fn write_block(&self, block_num: u64, block_size: u32, src: usize) -> bool {
        let byte_off = block_num * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = block_size / 512;
        if sectors == 0 {
            let mut sec = [0u8; 512];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src as *const u8,
                    sec.as_mut_ptr(),
                    block_size as usize,
                );
            }
            return self.write_bytes(byte_off, &sec[..block_size as usize]);
        }

        for s in 0..sectors {
            let mut sec = [0u8; 512];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (src + (s as usize) * 512) as *const u8,
                    sec.as_mut_ptr(),
                    512,
                );
            }
            let sector_byte = abs_off + (s as u64) * 512;
            if !self.write_sector(sector_byte, &sec) {
                return false;
            }
        }
        true
    }
}

// --- Block group descriptor reading ---

/// Read block group descriptor for block group `bg_idx`.
/// The BGD table starts at the block after the superblock.
fn read_bgd(
    blk: &BlkClient,
    sb: &Superblock,
    bg_idx: u32,
) -> Option<BlockGroupDesc> {
    let bgd_block = if sb.block_size == 1024 { 2u64 } else { 1u64 };
    let desc_size = sb.desc_size as u64;
    let bgd_byte_off = bgd_block * (sb.block_size as u64) + (bg_idx as u64) * desc_size;

    let mut buf = [0u8; 64];
    let read_len = (desc_size as usize).min(64);

    // May need to read across a sector boundary.
    let sector_off = bgd_byte_off % 512;
    let bytes_in_first = (512 - sector_off as usize).min(read_len);

    if !blk.read_bytes(bgd_byte_off, &mut buf[..bytes_in_first]) {
        return None;
    }
    if bytes_in_first < read_len {
        if !blk.read_bytes(
            bgd_byte_off + bytes_in_first as u64,
            &mut buf[bytes_in_first..read_len],
        ) {
            return None;
        }
    }

    let block_bitmap_lo = read_u32(&buf, 0) as u64;
    let inode_bitmap_lo = read_u32(&buf, 4) as u64;
    let inode_table_lo = read_u32(&buf, 8) as u64;

    // For 64-bit mode, read high halves from the extended descriptor.
    let (block_bitmap_hi, inode_bitmap_hi, inode_table_hi) = if sb.has_64bit() && desc_size >= 64 {
        (
            read_u32(&buf, 32) as u64,
            read_u32(&buf, 36) as u64,
            read_u32(&buf, 40) as u64,
        )
    } else {
        (0u64, 0u64, 0u64)
    };

    Some(BlockGroupDesc {
        block_bitmap: block_bitmap_lo | (block_bitmap_hi << 32),
        inode_bitmap: inode_bitmap_lo | (inode_bitmap_hi << 32),
        inode_table: inode_table_lo | (inode_table_hi << 32),
    })
}

// --- Inode reading ---

/// Read an inode from disk. Returns (mode, uid, gid, size, inode_flags, block_ptrs).
/// Supports multiple block groups — locates the correct BGD for the inode.
fn read_inode(
    blk: &BlkClient,
    sb: &Superblock,
    inode_num: u32,
) -> Option<(u16, u16, u16, u64, u32, [u32; 15])> {
    if inode_num == 0 {
        return None;
    }
    let idx = inode_num - 1;
    let bg_idx = idx / sb.inodes_per_group;
    let local_idx = idx % sb.inodes_per_group;

    let bgd = read_bgd(blk, sb, bg_idx)?;

    let inode_offset =
        bgd.inode_table * (sb.block_size as u64) + (local_idx as u64) * (sb.inode_size as u64);

    // Read inode data (up to 256 bytes to cover ext4 extra fields).
    let mut inode_buf = [0u8; 256];
    let read_len = (sb.inode_size as usize).min(256);

    let sector_off = inode_offset % 512;
    let bytes_in_first = (512 - sector_off as usize).min(read_len);

    if !blk.read_bytes(inode_offset, &mut inode_buf[..bytes_in_first]) {
        return None;
    }
    if bytes_in_first < read_len {
        if !blk.read_bytes(
            inode_offset + bytes_in_first as u64,
            &mut inode_buf[bytes_in_first..read_len],
        ) {
            return None;
        }
    }

    let mode = read_u16(&inode_buf, 0);
    let uid = read_u16(&inode_buf, 2);
    let size_lo = read_u32(&inode_buf, 4) as u64;
    let gid = read_u16(&inode_buf, 24);
    let inode_flags = read_u32(&inode_buf, 32);

    // ext4 stores high 32 bits of file size at offset 108 (i_size_high)
    // for regular files (not directories).
    let is_regular = (mode & 0xF000) == 0x8000;
    let size_hi = if is_regular && read_len > 108 {
        read_u32(&inode_buf, 108) as u64
    } else {
        0
    };
    let file_size = size_lo | (size_hi << 32);

    let mut blocks = [0u32; 15];
    for i in 0..15 {
        blocks[i] = read_u32(&inode_buf, 40 + i * 4);
    }

    Some((mode, uid, gid, file_size, inode_flags, blocks))
}

// --- ext4 extent tree resolution ---

/// Resolve a logical block to a physical block using the ext4 extent tree.
/// The extent tree root is stored in i_block[0..14] (60 bytes at inode offset 40).
/// `block_ptrs` contains the raw u32 words from i_block.
fn resolve_extent(
    blk: &BlkClient,
    sb: &Superblock,
    block_ptrs: &[u32; 15],
    logical_block: u64,
    scratch_page: usize,
) -> Option<u64> {
    // Convert block_ptrs to a byte buffer for parsing.
    let mut root = [0u8; 60];
    for i in 0..15 {
        write_u32(&mut root, i * 4, block_ptrs[i]);
    }

    resolve_extent_from_buf(&root, 60, blk, sb, logical_block, scratch_page)
}

/// Parse an extent tree node from a byte buffer and resolve the logical block.
fn resolve_extent_from_buf(
    buf: &[u8],
    buf_len: usize,
    blk: &BlkClient,
    sb: &Superblock,
    logical_block: u64,
    scratch_page: usize,
) -> Option<u64> {
    if buf_len < 12 {
        return None;
    }

    let magic = read_u16(buf, 0);
    let entries = read_u16(buf, 2) as usize;
    let depth = read_u16(buf, 6);

    if magic != EXT4_EXT_MAGIC {
        return None;
    }

    if depth == 0 {
        // Leaf node: extent entries start at offset 12, each 12 bytes.
        for i in 0..entries {
            let off = 12 + i * 12;
            if off + 12 > buf_len {
                break;
            }
            let ee_block = read_u32(buf, off) as u64;
            let ee_len = read_u16(buf, off + 4) as u64;
            // Uninitialized extent: high bit of ee_len is set. Treat as
            // a sparse hole (return zeros) so we don't serve garbage.
            let is_uninit = ee_len > 32768;
            let actual_len = ee_len & 0x7FFF;
            let ee_start_hi = read_u16(buf, off + 6) as u64;
            let ee_start_lo = read_u32(buf, off + 8) as u64;
            let phys_start = (ee_start_hi << 32) | ee_start_lo;

            if logical_block >= ee_block && logical_block < ee_block + actual_len {
                if is_uninit {
                    return None; // sparse hole — caller fills with zeros
                }
                return Some(phys_start + (logical_block - ee_block));
            }
        }
        return None; // logical block not covered by any extent (sparse hole)
    }

    // Internal node: index entries start at offset 12, each 12 bytes.
    // Find the child whose ei_block <= logical_block (largest such entry).
    let mut child_block: Option<u64> = None;
    for i in (0..entries).rev() {
        let off = 12 + i * 12;
        if off + 12 > buf_len {
            continue;
        }
        let ei_block = read_u32(buf, off) as u64;
        if logical_block >= ei_block {
            let ei_leaf_lo = read_u32(buf, off + 4) as u64;
            let ei_leaf_hi = read_u16(buf, off + 8) as u64;
            child_block = Some((ei_leaf_hi << 32) | ei_leaf_lo);
            break;
        }
    }

    let node_block = child_block?;

    // Read the child node block and recurse (iteratively via tail call).
    if !blk.read_block(node_block, sb.block_size, scratch_page) {
        return None;
    }

    let node_buf = unsafe {
        core::slice::from_raw_parts(scratch_page as *const u8, sb.block_size as usize)
    };
    resolve_extent_from_buf(node_buf, sb.block_size as usize, blk, sb, logical_block, scratch_page)
}

// --- Block resolution (indirect or extent) ---

/// Resolve a logical block index to a physical block number.
/// Dispatches to indirect block resolution or extent tree based on inode flags.
fn resolve_block(
    blk: &BlkClient,
    sb: &Superblock,
    inode_flags: u32,
    block_ptrs: &[u32; 15],
    logical_block: u64,
    scratch_page: usize,
) -> Option<u64> {
    if inode_flags & EXT4_EXTENTS_FL != 0 {
        return resolve_extent(blk, sb, block_ptrs, logical_block, scratch_page);
    }
    resolve_indirect(blk, sb, block_ptrs, logical_block as u32, scratch_page)
}

/// Single-slot cache of the most recently read indirect-tier block
/// (dind, ind, or tind).  Sequential reads within the same ind chunk
/// re-resolve through the same dind & ind blocks; before this cache,
/// each FS_READ paid the full 6-sector I/O cost (2 sectors each for
/// dind, ind, and the data block itself), serializing past the
/// kernel's 10 s call watchdog under load.
///
/// We keep two cache slots (one for dind, one for ind) so a triple-
/// indirect read can still benefit from caching.  Cache contents are a
/// raw copy of the block data; the entries are read out via byte
/// offsets the same way `scratch_page` is used.
const IND_CACHE_BLOCK_BYTES: usize = 4096;
struct IndCacheSlot {
    valid: bool,
    block_num: u32,
    contents: [u8; IND_CACHE_BLOCK_BYTES],
}
static mut DIND_CACHE: IndCacheSlot = IndCacheSlot {
    valid: false,
    block_num: 0,
    contents: [0; IND_CACHE_BLOCK_BYTES],
};
static mut IND_CACHE: IndCacheSlot = IndCacheSlot {
    valid: false,
    block_num: 0,
    contents: [0; IND_CACHE_BLOCK_BYTES],
};

/// Read an indirect block into `scratch_page`, consulting the named
/// cache slot first.  On miss, reads from disk and populates the cache.
/// On hit, copies cached bytes into scratch_page so subsequent ptr
/// reads against scratch_page work the same as the uncached path.
fn read_ind_cached(
    blk: &BlkClient,
    sb: &Superblock,
    block_num: u32,
    scratch_page: usize,
    use_dind_slot: bool,
) -> bool {
    let cache = unsafe {
        if use_dind_slot {
            &mut *core::ptr::addr_of_mut!(DIND_CACHE)
        } else {
            &mut *core::ptr::addr_of_mut!(IND_CACHE)
        }
    };
    let bs = sb.block_size as usize;
    if cache.valid && cache.block_num == block_num && bs <= IND_CACHE_BLOCK_BYTES {
        unsafe {
            core::ptr::copy_nonoverlapping(
                cache.contents.as_ptr(), scratch_page as *mut u8, bs,
            );
        }
        return true;
    }
    if !blk.read_block(block_num as u64, sb.block_size, scratch_page) {
        cache.valid = false;
        return false;
    }
    if bs <= IND_CACHE_BLOCK_BYTES {
        unsafe {
            core::ptr::copy_nonoverlapping(
                scratch_page as *const u8, cache.contents.as_mut_ptr(), bs,
            );
        }
        cache.block_num = block_num;
        cache.valid = true;
    }
    true
}

/// Cache the most recently read DATA block too: sequential 16-byte
/// FS_READ chunks (handle_read's inline path) all hit the same 1 KiB
/// block, but without this cache ext_srv re-reads the block from
/// blk_srv every time.  For a 64-byte read split across 4 chunks
/// that's 4× the disk I/O.  We track the disk block number that's
/// currently in `block_buf_va` and skip the read on a hit.
static mut DATA_BLOCK_CACHE_VALID: bool = false;
static mut DATA_BLOCK_CACHE_PHYS: u64 = 0;

/// Invalidate the indirect + data-block caches.  Called from FS_OPEN
/// whenever a fresh file is opened, since the new file may share
/// block numbers with the old file's freed blocks (ext2 reuses) —
/// stale data would silently corrupt subsequent reads.
fn invalidate_ind_caches() {
    unsafe {
        DIND_CACHE.valid = false;
        IND_CACHE.valid = false;
        DATA_BLOCK_CACHE_VALID = false;
    }
}

/// Resolve via traditional ext2/3 indirect block pointers.
fn resolve_indirect(
    blk: &BlkClient,
    sb: &Superblock,
    block_ptrs: &[u32; 15],
    logical_block: u32,
    scratch_page: usize,
) -> Option<u64> {
    let ptrs_per_block = sb.block_size / 4;

    if logical_block < 12 {
        let b = block_ptrs[logical_block as usize];
        if b == 0 {
            return None;
        }
        return Some(b as u64);
    }

    let logical_block = logical_block - 12;
    if logical_block < ptrs_per_block {
        // Single indirect.
        let ind_block = block_ptrs[12];
        if ind_block == 0 {
            return None;
        }
        if !read_ind_cached(blk, sb, ind_block, scratch_page, false) {
            return None;
        }
        let ptr =
            unsafe { core::ptr::read((scratch_page + (logical_block as usize) * 4) as *const u32) };
        if ptr == 0 {
            return None;
        }
        return Some(ptr as u64);
    }

    let logical_block = logical_block - ptrs_per_block;
    if logical_block < ptrs_per_block * ptrs_per_block {
        // Double indirect.
        let dind_block = block_ptrs[13];
        if dind_block == 0 {
            return None;
        }
        if !read_ind_cached(blk, sb, dind_block, scratch_page, true) {
            return None;
        }
        let idx1 = logical_block / ptrs_per_block;
        let ind_block =
            unsafe { core::ptr::read((scratch_page + (idx1 as usize) * 4) as *const u32) };
        if ind_block == 0 {
            return None;
        }
        if !read_ind_cached(blk, sb, ind_block, scratch_page, false) {
            return None;
        }
        let idx2 = logical_block % ptrs_per_block;
        let ptr = unsafe { core::ptr::read((scratch_page + (idx2 as usize) * 4) as *const u32) };
        if ptr == 0 {
            return None;
        }
        return Some(ptr as u64);
    }

    let logical_block = logical_block - ptrs_per_block * ptrs_per_block;
    let pp = ptrs_per_block * ptrs_per_block;
    if logical_block < ptrs_per_block * pp {
        // Triple indirect.
        let tind_block = block_ptrs[14];
        if tind_block == 0 {
            return None;
        }
        if !read_ind_cached(blk, sb, tind_block, scratch_page, true) {
            return None;
        }
        let idx1 = logical_block / pp;
        let dind =
            unsafe { core::ptr::read((scratch_page + (idx1 as usize) * 4) as *const u32) };
        if dind == 0 {
            return None;
        }
        if !read_ind_cached(blk, sb, dind, scratch_page, true) {
            return None;
        }
        let idx2 = (logical_block % pp) / ptrs_per_block;
        let ind =
            unsafe { core::ptr::read((scratch_page + (idx2 as usize) * 4) as *const u32) };
        if ind == 0 {
            return None;
        }
        if !read_ind_cached(blk, sb, ind, scratch_page, false) {
            return None;
        }
        let idx3 = logical_block % ptrs_per_block;
        let ptr = unsafe { core::ptr::read((scratch_page + (idx3 as usize) * 4) as *const u32) };
        if ptr == 0 {
            return None;
        }
        return Some(ptr as u64);
    }

    None
}

// --- Directory operations ---

/// Look up a file by name in a directory inode. Returns inode number if found.
fn dir_lookup(
    blk: &BlkClient,
    sb: &Superblock,
    dir_inode_flags: u32,
    dir_block_ptrs: &[u32; 15],
    dir_size: u64,
    name: &[u8],
    scratch_page: usize,
    block_buf: usize,
) -> Option<u32> {
    let block_size = sb.block_size;
    let num_blocks = ((dir_size + block_size as u64 - 1) / block_size as u64) as u64;

    for blk_idx in 0..num_blocks {
        let phys_block = match resolve_block(blk, sb, dir_inode_flags, dir_block_ptrs, blk_idx, scratch_page) {
            Some(b) => b,
            None => continue,
        };

        if !blk.read_block(phys_block, block_size, block_buf) {
            continue;
        }

        let mut off = 0usize;
        while off + 8 <= block_size as usize {
            let inode = read_u32(
                unsafe { core::slice::from_raw_parts(block_buf as *const u8, block_size as usize) },
                off,
            );
            let rec_len = read_u16(
                unsafe { core::slice::from_raw_parts(block_buf as *const u8, block_size as usize) },
                off + 4,
            ) as usize;
            let name_len = unsafe { *((block_buf + off + 6) as *const u8) } as usize;

            if rec_len == 0 {
                break;
            }
            if inode != 0 && name_len == name.len() {
                let entry_name = unsafe {
                    core::slice::from_raw_parts((block_buf + off + 8) as *const u8, name_len)
                };
                if entry_name == name {
                    return Some(inode);
                }
            }
            off += rec_len;
        }
    }
    None
}

/// Resolve a multi-component path starting from root inode.
/// Returns (inode_num, mode, uid, gid, size, inode_flags, block_ptrs).
fn path_resolve(
    blk: &BlkClient,
    sb: &Superblock,
    name: &[u8],
    scratch_page: usize,
    block_buf: usize,
) -> Option<(u32, u16, u16, u16, u64, u32, [u32; 15])> {
    let mut ino = EXT2_ROOT_INO;
    let (mut mode, mut uid, mut gid, mut size, mut iflags, mut blocks) =
        read_inode(blk, sb, ino)?;

    if name.is_empty() {
        return Some((ino, mode, uid, gid, size, iflags, blocks));
    }

    let mut start = 0;
    while start < name.len() {
        if name[start] == b'/' {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < name.len() && name[end] != b'/' {
            end += 1;
        }
        let component = &name[start..end];

        // Current inode must be a directory.
        if mode & 0xF000 != 0x4000 {
            return None;
        }

        ino = dir_lookup(blk, sb, iflags, &blocks, size, component, scratch_page, block_buf)?;
        let result = read_inode(blk, sb, ino)?;
        mode = result.0;
        uid = result.1;
        gid = result.2;
        size = result.3;
        iflags = result.4;
        blocks = result.5;

        start = end;
    }
    Some((ino, mode, uid, gid, size, iflags, blocks))
}

/// Iterate directory entries. Returns (inode, name, name_len, next_offset).
fn dir_next_entry(
    blk: &BlkClient,
    sb: &Superblock,
    dir_inode_flags: u32,
    dir_block_ptrs: &[u32; 15],
    dir_size: u64,
    start_offset: u64,
    scratch_page: usize,
    block_buf: usize,
) -> Option<(u32, [u8; 255], usize, u64)> {
    let block_size = sb.block_size;
    let mut byte_off = start_offset;

    while byte_off < dir_size {
        let blk_idx = byte_off / block_size as u64;
        let off_in_block = (byte_off % block_size as u64) as usize;

        let phys_block = resolve_block(blk, sb, dir_inode_flags, dir_block_ptrs, blk_idx, scratch_page)?;
        if !blk.read_block(phys_block, block_size, block_buf) {
            return None;
        }

        let buf =
            unsafe { core::slice::from_raw_parts(block_buf as *const u8, block_size as usize) };

        let mut off = off_in_block;
        while off + 8 <= block_size as usize {
            let inode = read_u32(buf, off);
            let rec_len = read_u16(buf, off + 4) as usize;
            let name_len = buf[off + 6] as usize;

            if rec_len == 0 {
                return None;
            }

            let block_start = (byte_off / block_size as u64) * block_size as u64;
            let next = block_start + off as u64 + rec_len as u64;

            if inode != 0 && name_len > 0 {
                let is_dot = name_len == 1 && buf[off + 8] == b'.';
                let is_dotdot = name_len == 2 && buf[off + 8] == b'.' && buf[off + 9] == b'.';

                if !is_dot && !is_dotdot {
                    let mut name = [0u8; 255];
                    let copy_len = name_len.min(255);
                    for i in 0..copy_len {
                        name[i] = buf[off + 8 + i];
                    }
                    return Some((inode, name, name_len, next));
                }
            }

            off += rec_len;
            byte_off = block_start + off as u64;
        }
        // Move to next block.
        byte_off = ((byte_off / block_size as u64) + 1) * block_size as u64;
    }
    None
}

// --- ext2 write support (indirect blocks only) ---

/// Allocate a block from the block bitmap. Returns block number or None.
/// Operates on block group 0 for simplicity (same as original ext2_srv).
fn alloc_block(
    blk: &BlkClient,
    sb: &mut Superblock,
    bitmap_buf: usize,
) -> Option<u64> {
    if sb.free_blocks_count == 0 {
        return None;
    }
    let bgd = read_bgd(blk, sb, 0)?;
    if !blk.read_block(bgd.block_bitmap, sb.block_size, bitmap_buf) {
        return None;
    }
    let bitmap =
        unsafe { core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize) };
    let start = sb.first_data_block as usize;
    let limit = (sb.blocks_per_group as usize).min(sb.blocks_count as usize);
    for bit in start..limit {
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if byte < bitmap.len() && bitmap[byte] & mask == 0 {
            bitmap[byte] |= mask;
            if !blk.write_block(bgd.block_bitmap, sb.block_size, bitmap_buf) {
                return None;
            }
            sb.free_blocks_count -= 1;
            return Some(bit as u64);
        }
    }
    None
}

/// Free a block in the block bitmap (block group 0).
fn free_block(
    blk: &BlkClient,
    sb: &mut Superblock,
    block_num: u64,
    bitmap_buf: usize,
) {
    let bgd = match read_bgd(blk, sb, 0) {
        Some(b) => b,
        None => return,
    };
    if !blk.read_block(bgd.block_bitmap, sb.block_size, bitmap_buf) {
        return;
    }
    let bitmap =
        unsafe { core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize) };
    let bit = block_num as usize;
    let byte = bit / 8;
    let mask = 1u8 << (bit % 8);
    if byte < bitmap.len() {
        bitmap[byte] &= !mask;
        blk.write_block(bgd.block_bitmap, sb.block_size, bitmap_buf);
        sb.free_blocks_count += 1;
    }
}

/// Allocate an inode from the inode bitmap (block group 0).
fn alloc_inode(
    blk: &BlkClient,
    sb: &mut Superblock,
    bitmap_buf: usize,
) -> Option<u32> {
    if sb.free_inodes_count == 0 {
        return None;
    }
    let bgd = read_bgd(blk, sb, 0)?;
    if !blk.read_block(bgd.inode_bitmap, sb.block_size, bitmap_buf) {
        return None;
    }
    let bitmap =
        unsafe { core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize) };
    for bit in 0..sb.inodes_per_group as usize {
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if byte < bitmap.len() && bitmap[byte] & mask == 0 {
            bitmap[byte] |= mask;
            if !blk.write_block(bgd.inode_bitmap, sb.block_size, bitmap_buf) {
                return None;
            }
            sb.free_inodes_count -= 1;
            return Some(bit as u32 + 1);
        }
    }
    None
}

/// Free an inode in the inode bitmap (block group 0).
fn free_inode(
    blk: &BlkClient,
    sb: &mut Superblock,
    inode_num: u32,
    bitmap_buf: usize,
) {
    let bit = (inode_num - 1) as usize;
    let bgd = match read_bgd(blk, sb, 0) {
        Some(b) => b,
        None => return,
    };
    if !blk.read_block(bgd.inode_bitmap, sb.block_size, bitmap_buf) {
        return;
    }
    let bitmap =
        unsafe { core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize) };
    let byte = bit / 8;
    let mask = 1u8 << (bit % 8);
    if byte < bitmap.len() {
        bitmap[byte] &= !mask;
        blk.write_block(bgd.inode_bitmap, sb.block_size, bitmap_buf);
        sb.free_inodes_count += 1;
    }
}

/// Write an inode to disk.
fn write_inode(
    blk: &BlkClient,
    sb: &Superblock,
    inode_num: u32,
    mode: u16,
    uid: u16,
    gid: u16,
    size: u64,
    block_ptrs: &[u32; 15],
) -> bool {
    let idx = inode_num - 1;
    let bg_idx = idx / sb.inodes_per_group;
    let local_idx = idx % sb.inodes_per_group;

    let bgd = match read_bgd(blk, sb, bg_idx) {
        Some(b) => b,
        None => return false,
    };

    let inode_offset =
        bgd.inode_table * (sb.block_size as u64) + (local_idx as u64) * (sb.inode_size as u64);

    let mut inode_buf = [0u8; 128];
    let sector_off = inode_offset % 512;
    let bytes_in_first = (512 - sector_off as usize).min(128);
    if !blk.read_bytes(inode_offset, &mut inode_buf[..bytes_in_first]) {
        return false;
    }
    if bytes_in_first < 128 {
        if !blk.read_bytes(
            inode_offset + bytes_in_first as u64,
            &mut inode_buf[bytes_in_first..128],
        ) {
            return false;
        }
    }

    write_u16(&mut inode_buf, 0, mode);
    write_u16(&mut inode_buf, 2, uid);
    write_u32(&mut inode_buf, 4, size as u32);
    write_u16(&mut inode_buf, 24, gid);
    let used_blocks = block_ptrs.iter().filter(|&&b| b != 0).count() as u32;
    write_u32(&mut inode_buf, 28, used_blocks * (sb.block_size / 512));
    for i in 0..15 {
        write_u32(&mut inode_buf, 40 + i * 4, block_ptrs[i]);
    }

    if !blk.write_bytes(inode_offset, &inode_buf[..bytes_in_first]) {
        return false;
    }
    if bytes_in_first < 128 {
        if !blk.write_bytes(
            inode_offset + bytes_in_first as u64,
            &inode_buf[bytes_in_first..128],
        ) {
            return false;
        }
    }
    true
}

/// Patch i_atime / i_mtime on an existing inode.
fn write_inode_times(
    blk: &BlkClient,
    sb: &Superblock,
    inode_num: u32,
    atime: u32,
    mtime: u32,
) -> bool {
    let idx = inode_num - 1;
    let bg_idx = idx / sb.inodes_per_group;
    let local_idx = idx % sb.inodes_per_group;

    let bgd = match read_bgd(blk, sb, bg_idx) {
        Some(b) => b,
        None => return false,
    };

    let inode_offset =
        bgd.inode_table * (sb.block_size as u64) + (local_idx as u64) * (sb.inode_size as u64);

    let mut buf = [0u8; 32];
    let sector_off = (inode_offset % 512) as usize;
    let bytes_in_first = (512 - sector_off).min(32);
    if !blk.read_bytes(inode_offset, &mut buf[..bytes_in_first]) {
        return false;
    }
    if bytes_in_first < 32 {
        if !blk.read_bytes(
            inode_offset + bytes_in_first as u64,
            &mut buf[bytes_in_first..32],
        ) {
            return false;
        }
    }
    write_u32(&mut buf, 8, atime);
    write_u32(&mut buf, 16, mtime);
    if !blk.write_bytes(inode_offset, &buf[..bytes_in_first]) {
        return false;
    }
    if bytes_in_first < 32 {
        if !blk.write_bytes(
            inode_offset + bytes_in_first as u64,
            &buf[bytes_in_first..32],
        ) {
            return false;
        }
    }
    true
}

/// Flush superblock free counts back to disk.
fn flush_superblock(blk: &BlkClient, sb: &Superblock) {
    let mut sb_buf = [0u8; 64];
    if !blk.read_bytes(1024, &mut sb_buf) {
        return;
    }
    write_u32(&mut sb_buf, 12, sb.free_blocks_count as u32);
    write_u32(&mut sb_buf, 16, sb.free_inodes_count);
    blk.write_bytes(1024, &sb_buf);
}

/// Add a directory entry.
fn dir_add_entry(
    blk: &BlkClient,
    sb: &Superblock,
    dir_inode_flags: u32,
    dir_block_ptrs: &[u32; 15],
    dir_size: u64,
    name: &[u8],
    name_len: usize,
    inode_num: u32,
    file_type: u8,
    scratch_page: usize,
    block_buf: usize,
) -> bool {
    let block_size = sb.block_size;
    let num_blocks = ((dir_size + block_size as u64 - 1) / block_size as u64) as u64;
    let needed = 8 + ((name_len + 3) & !3);

    for b in 0..num_blocks {
        let phys = match resolve_block(blk, sb, dir_inode_flags, dir_block_ptrs, b, scratch_page) {
            Some(p) => p,
            None => continue,
        };
        if !blk.read_block(phys, block_size, block_buf) {
            continue;
        }

        let buf =
            unsafe { core::slice::from_raw_parts_mut(block_buf as *mut u8, block_size as usize) };
        let mut off = 0usize;
        while off < block_size as usize {
            let ino = read_u32(buf, off);
            let rec_len = read_u16(buf, off + 4) as usize;
            if rec_len == 0 {
                break;
            }
            let nlen = buf[off + 6] as usize;

            if ino == 0 && rec_len >= needed {
                write_u32(buf, off, inode_num);
                write_u16(buf, off + 4, rec_len as u16);
                buf[off + 6] = name_len as u8;
                buf[off + 7] = file_type;
                buf[off + 8..off + 8 + name_len].copy_from_slice(&name[..name_len]);
                return blk.write_block(phys, block_size, block_buf);
            }

            let actual = 8 + ((nlen + 3) & !3);
            if ino != 0 && rec_len >= actual + needed {
                let new_off = off + actual;
                let new_rec_len = rec_len - actual;
                write_u16(buf, off + 4, actual as u16);
                write_u32(buf, new_off, inode_num);
                write_u16(buf, new_off + 4, new_rec_len as u16);
                buf[new_off + 6] = name_len as u8;
                buf[new_off + 7] = file_type;
                buf[new_off + 8..new_off + 8 + name_len].copy_from_slice(&name[..name_len]);
                return blk.write_block(phys, block_size, block_buf);
            }

            off += rec_len;
        }
    }
    false
}

/// Remove a directory entry by name.
fn dir_remove_entry(
    blk: &BlkClient,
    sb: &Superblock,
    dir_inode_flags: u32,
    dir_block_ptrs: &[u32; 15],
    dir_size: u64,
    name: &[u8],
    name_len: usize,
    scratch_page: usize,
    block_buf: usize,
) -> Option<u32> {
    let block_size = sb.block_size;
    let num_blocks = ((dir_size + block_size as u64 - 1) / block_size as u64) as u64;

    for b in 0..num_blocks {
        let phys = match resolve_block(blk, sb, dir_inode_flags, dir_block_ptrs, b, scratch_page) {
            Some(p) => p,
            None => continue,
        };
        if !blk.read_block(phys, block_size, block_buf) {
            continue;
        }

        let buf =
            unsafe { core::slice::from_raw_parts_mut(block_buf as *mut u8, block_size as usize) };
        let mut off = 0usize;
        let mut prev_off: Option<usize> = None;
        while off < block_size as usize {
            let ino = read_u32(buf, off);
            let rec_len = read_u16(buf, off + 4) as usize;
            if rec_len == 0 {
                break;
            }
            let nlen = buf[off + 6] as usize;

            if ino != 0 && nlen == name_len {
                let mut matches = true;
                for i in 0..name_len {
                    if buf[off + 8 + i] != name[i] {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    if let Some(po) = prev_off {
                        let prev_rec = read_u16(buf, po + 4) as usize;
                        write_u16(buf, po + 4, (prev_rec + rec_len) as u16);
                    } else {
                        write_u32(buf, off, 0);
                    }
                    blk.write_block(phys, block_size, block_buf);
                    return Some(ino);
                }
            }

            prev_off = Some(off);
            off += rec_len;
        }
    }
    None
}

// ============================================================
// Main entry point
// ============================================================

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [ext_srv] starting\n");

    let partition_offset = if arg0 != 0 { arg0 } else { 16 * 1024 * 1024 };

    syscall::debug_puts(b"  [ext_srv] partition offset=");
    print_num(partition_offset);
    syscall::debug_puts(b"\n");

    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();

    // Look up cache_blk with bounded retry.
    let blk_port = {
        let mut retries = 200u32;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [ext_srv] cache_blk not found, exiting\n");
                syscall::exit(1);
            }
            syscall::nanosleep(10_000_000);
        }
    };

    // Connect to blk_srv.
    let blk_reply = syscall::port_create();
    {
        let (n0, n1, _) = syscall::pack_name(b"blk");
        let d2 = 3u64 | ((blk_reply as u64) << 32);
        syscall::send(blk_port, IO_CONNECT, n0, n1, d2, 0);
    }

    let blk_aspace = if let Some(reply) = syscall::recv_msg(blk_reply) {
        if reply.tag == IO_CONNECT_OK {
            reply.data[2]
        } else {
            syscall::debug_puts(b"  [ext_srv] blk connect FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    } else {
        syscall::debug_puts(b"  [ext_srv] blk no reply\n");
        syscall::exit(1);
        unreachable!()
    };

    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ext_srv] scratch alloc FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_6000,
        partition_offset,
        nonce: Cell::new(0),
    };

    // Establish a permanent grant of `scratch_va` into blk_srv's aspace.  blk_srv
    // copies disk data into this page on every IO_READ and reads from it on every
    // IO_WRITE; granting once at init avoids two extra syscalls per request.  The
    // grant tears down automatically if ext_srv exits or is killed.
    if !syscall::grant_pages(blk.blk_aspace, blk.scratch_va, blk.grant_va, 1, false) {
        syscall::debug_puts(b"  [ext_srv] permanent grant FAILED\n");
        syscall::exit(1);
    }

    // --- Read superblock (at byte offset 1024 within the partition) ---
    let mut sb_buf = [0u8; 512];
    {
        // Retry on both I/O failure AND bad magic.  The first read after
        // boot can come back with race-induced zero data even though the
        // IO_READ_OK reply arrived correctly (see project_phase172_tier1.md
        // for details).  fat_srv and xfs_srv use the same pattern.
        let mut ok = false;
        for attempt in 0..20u32 {
            if blk.read_bytes(1024, &mut sb_buf) {
                let magic = read_u16(&sb_buf, 56);
                if magic == EXT2_SUPER_MAGIC {
                    ok = true;
                    break;
                }
            }
            if attempt > 0 {
                // Evict cache_blk's page covering the SB so the next attempt
                // re-fetches from blk_srv (race-poisoned cache page would
                // otherwise hand back zeros forever).
                const CACHE_INVALIDATE: u64 = 0xC110;
                let nonce = blk.next_nonce();
                let abs_off = blk.partition_offset + 1024;
                let d2 = 4096u64 | ((blk.reply_port as u64) << 32);
                syscall::send(blk.blk_port, CACHE_INVALIDATE, nonce, abs_off, d2, 0);
                let _ = blk.recv_match(nonce);
            }
            if attempt < 19 {
                syscall::nanosleep(50_000_000);
            }
        }
        if !ok {
            let final_magic = read_u16(&sb_buf, 56);
            syscall::debug_puts(b"  [ext_srv] bad magic after retries: ");
            print_hex(final_magic as u64);
            syscall::debug_puts(b"\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    }

    let log_block_size = read_u32(&sb_buf, 24);
    let block_size = 1024u32 << log_block_size;

    // Read feature flags.
    let feature_compat = read_u32(&sb_buf, 92);
    let feature_incompat = read_u32(&sb_buf, 96);
    let feature_ro_compat = read_u32(&sb_buf, 100);

    // Determine variant.
    let has_extents = feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS != 0;
    let has_64bit = feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT_ACTUAL != 0;
    let has_journal_compat = feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL != 0;
    // INCOMPAT bit 0x04 also indicates journal requirement.
    let has_journal_incompat = feature_incompat & 0x0004 != 0;
    let has_journal = has_journal_compat || has_journal_incompat;

    let variant = if has_extents || has_64bit {
        ExtVariant::Ext4
    } else if has_journal {
        ExtVariant::Ext3
    } else {
        ExtVariant::Ext2
    };

    // Block group descriptor size: 64 bytes if 64BIT, else 32.
    let desc_size = if has_64bit {
        let ds = read_u16(&sb_buf, 254);
        if ds >= 64 { ds } else { 64 }
    } else {
        EXT2_BGD_SIZE
    };

    let blocks_count_lo = read_u32(&sb_buf, 4) as u64;
    let blocks_count_hi = if has_64bit {
        read_u32(&sb_buf, 336) as u64
    } else {
        0
    };

    let free_blocks_lo = read_u32(&sb_buf, 12) as u64;
    let free_blocks_hi = if has_64bit {
        read_u32(&sb_buf, 340) as u64
    } else {
        0
    };

    let mut sb = Superblock {
        inodes_count: read_u32(&sb_buf, 0),
        blocks_count: blocks_count_lo | (blocks_count_hi << 32),
        free_blocks_count: free_blocks_lo | (free_blocks_hi << 32),
        free_inodes_count: read_u32(&sb_buf, 16),
        first_data_block: read_u32(&sb_buf, 20),
        block_size,
        blocks_per_group: read_u32(&sb_buf, 32),
        inodes_per_group: read_u32(&sb_buf, 40),
        inode_size: read_u16(&sb_buf, 88),
        log_block_size,
        desc_size,
        feature_compat,
        feature_incompat,
        feature_ro_compat,
        variant,
    };

    // Print variant and stats.
    match variant {
        ExtVariant::Ext2 => syscall::debug_puts(b"  [ext_srv] detected: ext2\n"),
        ExtVariant::Ext3 => syscall::debug_puts(b"  [ext_srv] detected: ext3\n"),
        ExtVariant::Ext4 => syscall::debug_puts(b"  [ext_srv] detected: ext4\n"),
    }
    syscall::debug_puts(b"  [ext_srv] block_size=");
    print_num(block_size as u64);
    syscall::debug_puts(b" inodes=");
    print_num(sb.inodes_count as u64);
    syscall::debug_puts(b" blocks=");
    print_num(sb.blocks_count);
    syscall::debug_puts(b" inode_size=");
    print_num(sb.inode_size as u64);
    syscall::debug_puts(b" desc_size=");
    print_num(desc_size as u64);
    syscall::debug_puts(b" block_groups=");
    print_num(sb.num_block_groups() as u64);
    if has_extents {
        syscall::debug_puts(b" [extents]");
    }
    if has_64bit {
        syscall::debug_puts(b" [64bit]");
    }
    syscall::debug_puts(b"\n");

    // Allocate pages for block reads.
    let block_buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ext_srv] block_buf alloc FAILED\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    };

    let indirect_buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ext_srv] indirect_buf alloc FAILED\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    };

    // Verify root inode.
    {
        let mut root_ok = false;
        for attempt in 0..5u32 {
            if let Some((mode, uid, _gid, size, iflags, _blocks)) = read_inode(&blk, &sb, EXT2_ROOT_INO) {
                syscall::debug_puts(b"  [ext_srv] root inode: mode=");
                print_hex(mode as u64);
                syscall::debug_puts(b" uid=");
                print_num(uid as u64);
                syscall::debug_puts(b" size=");
                print_num(size);
                if iflags & EXT4_EXTENTS_FL != 0 {
                    syscall::debug_puts(b" [extents]");
                }
                syscall::debug_puts(b"\n");
                root_ok = true;
                break;
            }
            if attempt < 4 {
                syscall::nanosleep(50_000_000);
            }
        }
        if !root_ok {
            syscall::debug_puts(b"  [ext_srv] failed to read root inode\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    }

    // Register with name server.
    syscall::ns_register(b"ext", port);
    syscall::ns_register(b"ext_task", my_aspace);

    syscall::debug_puts(b"  [ext_srv] ready, port=");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    let mut open_files = [OpenFile::empty(); MAX_OPEN_FILES];
    let mut file_locks = [FileLock::empty(); MAX_LOCKS];
    let mut lock_waiters = [LockWaiter::empty(); MAX_LOCK_WAITERS];

    // ============================================================
    // Server loop
    // ============================================================
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Block numbers are reused across files; cached
                // indirect blocks from a previously-open file are
                // invalid for this lookup.
                invalidate_ind_caches();

                if let Some((ino, mode, uid, gid, size, iflags, blocks)) =
                    path_resolve(&blk, &sb, name, indirect_buf_va, block_buf_va)
                {
                    let mut handle = u64::MAX;
                    for (i, f) in open_files.iter_mut().enumerate() {
                        if !f.active {
                            f.active = true;
                            f.inode_num = ino;
                            f.file_size = size;
                            f.mode = mode;
                            f.uid = uid;
                            f.gid = gid;
                            f.inode_flags = iflags;
                            f.block_ptrs = blocks;
                            f.pid = caller_pid;
                            handle = i as u64;
                            break;
                        }
                    }
                    if handle == u64::MAX {
                        let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    } else {
                        let _ = syscall::reply(
                            FS_OPEN_OK,
                            handle,
                            size,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1];
                let length = (msg.data[2] & 0xFFFF_FFFF) as u64;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let file = &open_files[handle];
                if offset >= file.file_size {
                    let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                    continue;
                }

                let avail = file.file_size - offset;
                let to_read = length.min(avail);

                let block_idx = offset / sb.block_size as u64;
                let offset_in_block = (offset % sb.block_size as u64) as usize;

                let is_sparse_hole;
                let phys_block =
                    match resolve_block(&blk, &sb, file.inode_flags, &file.block_ptrs, block_idx, indirect_buf_va) {
                        Some(b) => { is_sparse_hole = false; b }
                        None => { is_sparse_hole = true; 0 }
                    };

                if is_sparse_hole {
                    unsafe {
                        core::ptr::write_bytes(
                            block_buf_va as *mut u8,
                            0,
                            sb.block_size as usize,
                        );
                        DATA_BLOCK_CACHE_VALID = false;
                    }
                } else {
                    let cache_hit = unsafe {
                        DATA_BLOCK_CACHE_VALID && DATA_BLOCK_CACHE_PHYS == phys_block
                    };
                    if !cache_hit {
                        if !blk.read_block(phys_block, sb.block_size, block_buf_va) {
                            unsafe { DATA_BLOCK_CACHE_VALID = false; }
                            let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                            continue;
                        }
                        unsafe {
                            DATA_BLOCK_CACHE_PHYS = phys_block;
                            DATA_BLOCK_CACHE_VALID = true;
                        }
                    }
                }

                let bytes_in_block =
                    ((sb.block_size as usize) - offset_in_block).min(to_read as usize);

                if grant_va != 0 {
                    // Volatile u64 stride + Release fence + mfence: cache_srv
                    // empirically needs the same pattern (see its IO_READ
                    // handler) — without it, ld.so reads zeros from grant
                    // pages on the receiving CPU under boot concurrency,
                    // surfacing as "Verdef version 0" in libc when ld.so
                    // loads it under Step H.  ext_srv had no such fence.
                    unsafe {
                        let src = (block_buf_va + offset_in_block) as *const u8;
                        let dst = grant_va as *mut u8;
                        let words = bytes_in_block / 8;
                        let tail_start = words * 8;
                        let src_u64 = src as *const u64;
                        let dst_u64 = dst as *mut u64;
                        for i in 0..words {
                            let v = core::ptr::read_volatile(src_u64.add(i));
                            core::ptr::write_volatile(dst_u64.add(i), v);
                        }
                        for i in tail_start..bytes_in_block {
                            let b = core::ptr::read_volatile(src.add(i));
                            core::ptr::write_volatile(dst.add(i), b);
                        }
                    }
                    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                    #[cfg(target_arch = "x86_64")]
                    unsafe { core::arch::asm!("mfence"); }
                    let _ = syscall::reply(FS_READ_OK, bytes_in_block as u64, 0, 0, 0, 0);
                } else {
                    let inline_len = bytes_in_block.min(MAX_INLINE);
                    let data = unsafe {
                        core::slice::from_raw_parts(
                            (block_buf_va + offset_in_block) as *const u8,
                            inline_len,
                        )
                    };
                    let packed = pack_inline_data(data);
                    let _ = syscall::reply(
                        FS_READ_OK,
                        inline_len as u64,
                        packed[0],
                        packed[1],
                        packed[2],
                        0,
                    );
                }
            }

            FS_READDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let start_offset = msg.data[3];

                let (dir_size, dir_iflags, dir_blocks) = if name_len == 0 {
                    match read_inode(&blk, &sb, EXT2_ROOT_INO) {
                        Some((_, _, _, size, iflags, blocks)) => (size, iflags, blocks),
                        None => {
                            let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                            continue;
                        }
                    }
                } else {
                    let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                    let name = &name_buf[..name_len.min(16)];
                    match path_resolve(&blk, &sb, name, indirect_buf_va, block_buf_va) {
                        Some((_, _, _, _, size, iflags, blocks)) => (size, iflags, blocks),
                        None => {
                            let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                            continue;
                        }
                    }
                };

                match dir_next_entry(
                    &blk,
                    &sb,
                    dir_iflags,
                    &dir_blocks,
                    dir_size,
                    start_offset,
                    indirect_buf_va,
                    block_buf_va,
                ) {
                    Some((inode_num, name, name_len, next_offset)) => {
                        let file_size = if let Some((_, _, _, size, _, _)) =
                            read_inode(&blk, &sb, inode_num)
                        {
                            size
                        } else {
                            0
                        };

                        let mut name_lo = 0u64;
                        let mut name_hi = 0u64;
                        for i in 0..name_len.min(8) {
                            name_lo |= (name[i] as u64) << (i * 8);
                        }
                        for i in 8..name_len.min(16) {
                            name_hi |= (name[i] as u64) << ((i - 8) * 8);
                        }

                        let _ = syscall::reply(
                            FS_READDIR_OK,
                            file_size,
                            name_lo,
                            name_hi,
                            next_offset,
                            0,
                        );
                    }
                    None => {
                        let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                    }
                }
            }

            FS_OPEN_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;
                let _flags = ((msg.data[0] >> 16) & 0xFFFF) as u32;
                let caller_pid = msg.data[1] as u32;

                let mut name = [0u8; 256];
                let nlen = name_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                invalidate_ind_caches();

                if let Some((ino, mode, uid, gid, size, iflags, blocks)) =
                    path_resolve(&blk, &sb, &name[..nlen], indirect_buf_va, block_buf_va)
                {
                    let mut handle = u64::MAX;
                    for (i, f) in open_files.iter_mut().enumerate() {
                        if !f.active {
                            f.active = true;
                            f.inode_num = ino;
                            f.file_size = size;
                            f.mode = mode;
                            f.uid = uid;
                            f.gid = gid;
                            f.inode_flags = iflags;
                            f.block_ptrs = blocks;
                            f.pid = caller_pid;
                            handle = i as u64;
                            break;
                        }
                    }
                    if handle == u64::MAX {
                        let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    } else {
                        let _ = syscall::reply(
                            FS_OPEN_OK,
                            handle,
                            size,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_STAT_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;

                let mut name = [0u8; 256];
                let nlen = name_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some((ino, mode, uid, gid, size, _iflags, _blocks)) =
                    path_resolve(&blk, &sb, &name[..nlen], indirect_buf_va, block_buf_va)
                {
                    let uid_gid = (uid as u64) | ((gid as u64) << 16);
                    let _ = syscall::reply(
                        FS_STAT_OK,
                        size,
                        mode as u64,
                        uid_gid,
                        ino as u64,
                        0,
                    );
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let file = &open_files[handle];
                let uid_gid = (file.uid as u64) | ((file.gid as u64) << 16);
                let _ = syscall::reply(
                    FS_STAT_OK,
                    file.file_size,
                    file.mode as u64,
                    uid_gid,
                    file.inode_num as u64,
                    0,
                );
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN_FILES && open_files[handle].active {
                    let ino = open_files[handle].inode_num;
                    let pid = open_files[handle].pid;
                    if open_files[handle].writable {
                        let f = &open_files[handle];
                        write_inode(
                            &blk,
                            &sb,
                            f.inode_num,
                            f.mode,
                            f.uid,
                            f.gid,
                            f.file_size,
                            &f.block_ptrs,
                        );
                        flush_superblock(&blk, &sb);
                    }
                    open_files[handle].active = false;
                    open_files[handle].writable = false;
                    let mut still_open = false;
                    for f in open_files.iter() {
                        if f.active && f.inode_num == ino && f.pid == pid {
                            still_open = true;
                            break;
                        }
                    }
                    if !still_open {
                        release_locks(&mut file_locks, ino, pid, 0, 0);
                        try_wake_waiters(&mut file_locks, &mut lock_waiters, ino);
                    }
                }
                let _ = syscall::reply(FS_CLOSE_OK, 0, 0, 0, 0, 0);
            }

            FS_CREATE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let ino = match alloc_inode(&blk, &mut sb, block_buf_va) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                let first_block = match alloc_block(&blk, &mut sb, block_buf_va) {
                    Some(b) => b,
                    None => {
                        free_inode(&blk, &mut sb, ino, block_buf_va);
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                unsafe {
                    core::ptr::write_bytes(block_buf_va as *mut u8, 0, sb.block_size as usize);
                }
                blk.write_block(first_block, sb.block_size, block_buf_va);

                let mut block_ptrs = [0u32; 15];
                block_ptrs[0] = first_block as u32;
                write_inode(&blk, &sb, ino, 0o100644, 0, 0, 0, &block_ptrs);

                // Get root directory info for adding entry.
                let root = match read_inode(&blk, &sb, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_iflags, root_blocks) = root;
                if !dir_add_entry(
                    &blk,
                    &sb,
                    root_iflags,
                    &root_blocks,
                    root_size,
                    name,
                    name_len.min(16),
                    ino,
                    1,
                    indirect_buf_va,
                    block_buf_va,
                ) {
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                flush_superblock(&blk, &sb);

                let mut handle = u64::MAX;
                for (i, f) in open_files.iter_mut().enumerate() {
                    if !f.active {
                        f.active = true;
                        f.writable = true;
                        f.inode_num = ino;
                        f.file_size = 0;
                        f.mode = 0o100644;
                        f.uid = 0;
                        f.gid = 0;
                        f.inode_flags = 0;
                        f.block_ptrs = block_ptrs;
                        f.pid = caller_pid;
                        handle = i as u64;
                        break;
                    }
                }
                if handle == u64::MAX {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_CREATE_OK, handle, 0, my_aspace as u64, 0, 0);
                }
            }

            FS_WRITE => {
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN_FILES
                    || !open_files[handle].active
                    || !open_files[handle].writable
                {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                // Write support uses indirect blocks only (ext2-compatible).
                // Extent-based files are read-only.
                if open_files[handle].uses_extents() {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let mut written = 0usize;
                let mut offset = open_files[handle].file_size;

                while written < length {
                    let block_idx = offset / sb.block_size as u64;
                    let offset_in_block = (offset % sb.block_size as u64) as usize;
                    let space_in_block = (sb.block_size as usize) - offset_in_block;
                    let chunk = (length - written).min(space_in_block);

                    if block_idx < 12 {
                        if open_files[handle].block_ptrs[block_idx as usize] == 0 {
                            match alloc_block(&blk, &mut sb, block_buf_va) {
                                Some(b) => {
                                    open_files[handle].block_ptrs[block_idx as usize] = b as u32;
                                    unsafe {
                                        core::ptr::write_bytes(
                                            block_buf_va as *mut u8,
                                            0,
                                            sb.block_size as usize,
                                        );
                                    }
                                    blk.write_block(b, sb.block_size, block_buf_va);
                                }
                                None => break,
                            }
                        }
                    } else {
                        let ind_idx = block_idx as u32 - 12;
                        let ptrs_per_block = sb.block_size / 4;
                        if ind_idx < ptrs_per_block {
                            if open_files[handle].block_ptrs[12] == 0 {
                                match alloc_block(&blk, &mut sb, block_buf_va) {
                                    Some(b) => {
                                        open_files[handle].block_ptrs[12] = b as u32;
                                        unsafe {
                                            core::ptr::write_bytes(
                                                block_buf_va as *mut u8,
                                                0,
                                                sb.block_size as usize,
                                            );
                                        }
                                        blk.write_block(b, sb.block_size, block_buf_va);
                                    }
                                    None => break,
                                }
                            }
                            let ind_blk = open_files[handle].block_ptrs[12] as u64;
                            if !blk.read_block(ind_blk, sb.block_size, indirect_buf_va) {
                                break;
                            }
                            let ptr = unsafe {
                                core::ptr::read(
                                    (indirect_buf_va + (ind_idx as usize) * 4) as *const u32,
                                )
                            };
                            if ptr == 0 {
                                match alloc_block(&blk, &mut sb, block_buf_va) {
                                    Some(b) => {
                                        unsafe {
                                            core::ptr::write(
                                                (indirect_buf_va + (ind_idx as usize) * 4)
                                                    as *mut u32,
                                                b as u32,
                                            );
                                        }
                                        blk.write_block(ind_blk, sb.block_size, indirect_buf_va);
                                        unsafe {
                                            core::ptr::write_bytes(
                                                block_buf_va as *mut u8,
                                                0,
                                                sb.block_size as usize,
                                            );
                                        }
                                        blk.write_block(b, sb.block_size, block_buf_va);
                                    }
                                    None => break,
                                }
                            }
                        } else {
                            break;
                        }
                    }

                    let phys = match resolve_block(
                        &blk,
                        &sb,
                        open_files[handle].inode_flags,
                        &open_files[handle].block_ptrs,
                        block_idx,
                        indirect_buf_va,
                    ) {
                        Some(b) => b,
                        None => break,
                    };

                    if offset_in_block != 0 || chunk < sb.block_size as usize {
                        if !blk.read_block(phys, sb.block_size, block_buf_va) {
                            break;
                        }
                    }

                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (grant_va + written) as *const u8,
                                (block_buf_va + offset_in_block) as *mut u8,
                                chunk,
                            );
                        }
                    }

                    if !blk.write_block(phys, sb.block_size, block_buf_va) {
                        break;
                    }

                    written += chunk;
                    offset += chunk as u64;
                }

                open_files[handle].file_size = offset;

                let _ = syscall::reply(FS_WRITE_OK, written as u64, 0, 0, 0, 0);
            }

            FS_DELETE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let root = match read_inode(&blk, &sb, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_iflags, root_blocks) = root;

                let ino = match dir_lookup(
                    &blk,
                    &sb,
                    root_iflags,
                    &root_blocks,
                    root_size,
                    name,
                    indirect_buf_va,
                    block_buf_va,
                ) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                        continue;
                    }
                };

                let (_, _, _, _size, _iflags, block_ptrs) = match read_inode(&blk, &sb, ino) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Free direct blocks (only for indirect-block files).
                for i in 0..12 {
                    if block_ptrs[i] != 0 {
                        free_block(&blk, &mut sb, block_ptrs[i] as u64, block_buf_va);
                    }
                }
                if block_ptrs[12] != 0 {
                    if blk.read_block(block_ptrs[12] as u64, sb.block_size, block_buf_va) {
                        let ptrs_per_block = sb.block_size / 4;
                        for i in 0..ptrs_per_block as usize {
                            let ptr =
                                unsafe { core::ptr::read((block_buf_va + i * 4) as *const u32) };
                            if ptr != 0 {
                                free_block(&blk, &mut sb, ptr as u64, indirect_buf_va);
                            }
                        }
                    }
                    free_block(&blk, &mut sb, block_ptrs[12] as u64, block_buf_va);
                }

                free_inode(&blk, &mut sb, ino, block_buf_va);

                let zero_ptrs = [0u32; 15];
                write_inode(&blk, &sb, ino, 0, 0, 0, 0, &zero_ptrs);

                dir_remove_entry(
                    &blk,
                    &sb,
                    root_iflags,
                    &root_blocks,
                    root_size,
                    name,
                    name_len.min(16),
                    indirect_buf_va,
                    block_buf_va,
                );

                flush_superblock(&blk, &sb);

                let _ = syscall::reply(FS_DELETE_OK, 0, 0, 0, 0, 0);
            }

            FS_CHMOD => {
                let path_len = (msg.data[0] & 0xFFFF) as usize;
                let mode = ((msg.data[0] >> 16) & 0xFFFF) as u16;

                let mut name = [0u8; 256];
                let nlen = path_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some((ino, old_mode, uid, gid, size, _iflags, blocks)) =
                    path_resolve(&blk, &sb, &name[..nlen], indirect_buf_va, block_buf_va)
                {
                    let new_mode = (old_mode & 0xF000) | (mode & 0x0FFF);
                    if write_inode(&blk, &sb, ino, new_mode, uid, gid, size, &blocks) {
                        for f in open_files.iter_mut() {
                            if f.active && f.inode_num == ino {
                                f.mode = new_mode;
                            }
                        }
                        let _ = syscall::reply(FS_CHMOD_OK, 0, 0, 0, 0, 0);
                    } else {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_UTIMENS => {
                let path_len = (msg.data[0] & 0xFFFF) as usize;
                let atime = msg.data[1] as u32;
                let mtime = msg.data[2] as u32;

                let mut name = [0u8; 256];
                let nlen = path_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some((ino, _mode, _uid, _gid, _size, _iflags, _blocks)) =
                    path_resolve(&blk, &sb, &name[..nlen], indirect_buf_va, block_buf_va)
                {
                    if write_inode_times(&blk, &sb, ino, atime, mtime) {
                        let _ = syscall::reply(FS_UTIMENS_OK, 0, 0, 0, 0, 0);
                    } else {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_FLOCK => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let operation = (msg.data[0] >> 32) as i32;
                let pid = msg.data[1] as u32;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0, 0);
                    continue;
                }
                let ino = open_files[handle].inode_num;
                let is_unlock = operation & 8 != 0;
                let is_nb = operation & 4 != 0;
                let lock_type = if operation & 2 != 0 {
                    LK_WRLCK
                } else if operation & 1 != 0 {
                    LK_RDLCK
                } else {
                    LK_UNLCK
                };

                if is_unlock {
                    release_locks(&mut file_locks, ino, pid, 0, 0);
                    let _ = syscall::reply(FS_FLOCK_OK, 0, 0, 0, 0, 0);
                    try_wake_waiters(&mut file_locks, &mut lock_waiters, ino);
                } else if !lock_conflicts(&file_locks, ino, pid, lock_type, 0, 0) {
                    if acquire_lock(&mut file_locks, ino, pid, lock_type, 0, 0) {
                        let _ = syscall::reply(FS_FLOCK_OK, 0, 0, 0, 0, 0);
                    } else {
                        let _ = syscall::reply(FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0, 0);
                    }
                } else if is_nb {
                    let _ = syscall::reply(FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0, 0);
                } else {
                    let cap = syscall::reply_take();
                    if cap == u64::MAX {
                        continue;
                    }
                    let mut queued = false;
                    for w in lock_waiters.iter_mut() {
                        if !w.active {
                            *w = LockWaiter {
                                active: true,
                                reply_port: cap,
                                inode: ino,
                                pid,
                                lock_type,
                                start: 0,
                                len: 0,
                            };
                            queued = true;
                            break;
                        }
                    }
                    if !queued {
                        let _ = syscall::reply_to(cap, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                    }
                }
            }

            FS_SETLK | FS_SETLKW => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let lock_type = ((msg.data[0] >> 32) & 0xFFFF) as u8;
                let pid = msg.data[3] as u32;
                let start = msg.data[1];
                let len = (msg.data[2] & 0xFFFF_FFFF) as u64;
                let blocking = msg.tag == FS_SETLKW;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0, 0);
                    continue;
                }
                let ino = open_files[handle].inode_num;

                if lock_type == LK_UNLCK {
                    release_locks(&mut file_locks, ino, pid, start, len);
                    let ok_tag = if blocking { FS_SETLKW_OK } else { FS_SETLK_OK };
                    let _ = syscall::reply(ok_tag, 0, 0, 0, 0, 0);
                    try_wake_waiters(&mut file_locks, &mut lock_waiters, ino);
                } else if !lock_conflicts(&file_locks, ino, pid, lock_type, start, len) {
                    if acquire_lock(&mut file_locks, ino, pid, lock_type, start, len) {
                        let ok_tag = if blocking { FS_SETLKW_OK } else { FS_SETLK_OK };
                        let _ = syscall::reply(ok_tag, 0, 0, 0, 0, 0);
                    } else {
                        let _ = syscall::reply(FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0, 0);
                    }
                } else if !blocking {
                    let _ = syscall::reply(FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0, 0);
                } else {
                    let cap = syscall::reply_take();
                    if cap == u64::MAX {
                        continue;
                    }
                    let mut queued = false;
                    for w in lock_waiters.iter_mut() {
                        if !w.active {
                            *w = LockWaiter {
                                active: true,
                                reply_port: cap,
                                inode: ino,
                                pid,
                                lock_type,
                                start,
                                len,
                            };
                            queued = true;
                            break;
                        }
                    }
                    if !queued {
                        let _ = syscall::reply_to(cap, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                    }
                }
            }

            FS_GETLK => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let lock_type = ((msg.data[0] >> 32) & 0xFFFF) as u8;
                let pid = msg.data[3] as u32;
                let start = msg.data[1];
                let len = (msg.data[2] & 0xFFFF_FFFF) as u64;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0, 0);
                    continue;
                }
                let ino = open_files[handle].inode_num;

                match find_conflict(&file_locks, ino, pid, lock_type, start, len) {
                    Some(idx) => {
                        let lk = &file_locks[idx];
                        let d0 = (lk.lock_type as u64) | ((lk.pid as u64) << 32);
                        let _ = syscall::reply(FS_GETLK_OK, d0, lk.start, lk.len, 0, 0);
                    }
                    None => {
                        let d0 = LK_UNLCK as u64;
                        let _ = syscall::reply(FS_GETLK_OK, d0, 0, 0, 0, 0);
                    }
                }
            }

            FS_MKDIR => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let mode = ((msg.data[2] >> 16) & 0xFFFF) as u16;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let ino = match alloc_inode(&blk, &mut sb, block_buf_va) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                let first_block = match alloc_block(&blk, &mut sb, block_buf_va) {
                    Some(b) => b,
                    None => {
                        free_inode(&blk, &mut sb, ino, block_buf_va);
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                unsafe {
                    core::ptr::write_bytes(block_buf_va as *mut u8, 0, sb.block_size as usize);
                }
                blk.write_block(first_block, sb.block_size, block_buf_va);

                let mut block_ptrs = [0u32; 15];
                block_ptrs[0] = first_block as u32;
                let dir_mode = 0o40000 | mode;
                write_inode(
                    &blk,
                    &sb,
                    ino,
                    dir_mode,
                    0,
                    0,
                    sb.block_size as u64,
                    &block_ptrs,
                );

                let root = match read_inode(&blk, &sb, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_iflags, root_blocks) = root;
                if !dir_add_entry(
                    &blk,
                    &sb,
                    root_iflags,
                    &root_blocks,
                    root_size,
                    name,
                    name_len.min(16),
                    ino,
                    2,
                    indirect_buf_va,
                    block_buf_va,
                ) {
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                flush_superblock(&blk, &sb);
                let _ = syscall::reply(FS_MKDIR_OK, 0, 0, 0, 0, 0);
            }

            FS_UNLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let root = match read_inode(&blk, &sb, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_iflags, root_blocks) = root;

                let ino = match dir_lookup(
                    &blk,
                    &sb,
                    root_iflags,
                    &root_blocks,
                    root_size,
                    name,
                    indirect_buf_va,
                    block_buf_va,
                ) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                        continue;
                    }
                };

                let (_, _, _, _size, _iflags, block_ptrs) = match read_inode(&blk, &sb, ino) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                for i in 0..12 {
                    if block_ptrs[i] != 0 {
                        free_block(&blk, &mut sb, block_ptrs[i] as u64, block_buf_va);
                    }
                }
                if block_ptrs[12] != 0 {
                    if blk.read_block(block_ptrs[12] as u64, sb.block_size, block_buf_va) {
                        let ptrs_per_block = sb.block_size / 4;
                        for i in 0..ptrs_per_block as usize {
                            let ptr =
                                unsafe { core::ptr::read((block_buf_va + i * 4) as *const u32) };
                            if ptr != 0 {
                                free_block(&blk, &mut sb, ptr as u64, indirect_buf_va);
                            }
                        }
                    }
                    free_block(&blk, &mut sb, block_ptrs[12] as u64, block_buf_va);
                }

                free_inode(&blk, &mut sb, ino, block_buf_va);

                let zero_ptrs = [0u32; 15];
                write_inode(&blk, &sb, ino, 0, 0, 0, 0, &zero_ptrs);

                dir_remove_entry(
                    &blk,
                    &sb,
                    root_iflags,
                    &root_blocks,
                    root_size,
                    name,
                    name_len.min(16),
                    indirect_buf_va,
                    block_buf_va,
                );

                flush_superblock(&blk, &sb);
                let _ = syscall::reply(FS_UNLINK_OK, 0, 0, 0, 0, 0);
            }

            FS_FSYNC => {
                let handle = msg.data[0] as usize;

                if handle < MAX_OPEN_FILES && open_files[handle].active {
                    let f = &open_files[handle];
                    write_inode(
                        &blk,
                        &sb,
                        f.inode_num,
                        f.mode,
                        f.uid,
                        f.gid,
                        f.file_size,
                        &f.block_ptrs,
                    );
                    flush_superblock(&blk, &sb);
                }

                let _ = syscall::reply(FS_FSYNC_OK, 0, 0, 0, 0, 0);
            }

            _ => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }
    }

    loop {
        core::hint::spin_loop();
    }
}
