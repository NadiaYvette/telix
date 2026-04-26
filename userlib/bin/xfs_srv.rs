#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux fs/xfs, xfsprogs

//! XFS v5 filesystem server.
//!
//! Pure userspace process that reads an XFS partition from cache_blk via IPC.
//! The XFS partition starts at a byte offset passed as arg0 (default 32 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE and write ops.

extern crate userlib;

use core::cell::Cell;
use userlib::syscall;

// --- I/O protocol constants (for talking to cache_blk / blk_srv) ---
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
const FS_CLOSE: u64 = 0x2400;
const FS_CLOSE_OK: u64 = 0x2401;
const FS_CREATE: u64 = 0x2500;
const FS_CREATE_OK: u64 = 0x2501;
const FS_WRITE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;
const FS_DELETE: u64 = 0x2700;
const FS_DELETE_OK: u64 = 0x2701;
const FS_MKDIR: u64 = 0x2A00;
const FS_MKDIR_OK: u64 = 0x2A01;
const FS_UNLINK: u64 = 0x2A20;
#[allow(dead_code)]
const FS_UNLINK_OK: u64 = 0x2A21;
const FS_CHMOD: u64 = 0x2E00;
const FS_CHMOD_OK: u64 = 0x2E01;
const FS_UTIMENS: u64 = 0x2900;
const FS_UTIMENS_OK: u64 = 0x2901;
const FS_SYMLINK: u64 = 0x2C00;
const FS_SYMLINK_OK: u64 = 0x2C01;
const FS_READLINK: u64 = 0x2C10;
const FS_READLINK_OK: u64 = 0x2C11;
const FS_LINK: u64 = 0x2C20;
const FS_LINK_OK: u64 = 0x2C21;
const FS_RENAME: u64 = 0x2C30;
const FS_RENAME_OK: u64 = 0x2C31;
const FS_CHOWN: u64 = 0x2C40;
const FS_CHOWN_OK: u64 = 0x2C41;
const FS_TRUNCATE: u64 = 0x2C50;
const FS_TRUNCATE_OK: u64 = 0x2C51;
const FS_STATFS: u64 = 0x2C60;
const FS_STATFS_OK: u64 = 0x2C61;
const FS_MKNOD: u64 = 0x2D40;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

/// VFS grants its scratch page here for long-path lookups.
const VFS_LONG_PATH_SCRATCH_VA: usize = 0x5_0000_0000;

const MAX_OPEN: usize = 16;
const MAX_INLINE: usize = 24;
const PAGE_SIZE: usize = 4096;

// --- XFS on-disk constants ---
const XFS_SB_MAGIC: u32 = 0x58465342; // "XFSB"
const XFS_AGF_MAGIC: u32 = 0x58414746; // "XAGF"
const XFS_AGI_MAGIC: u32 = 0x58414749; // "XAGI"
const XFS_DINODE_MAGIC: u16 = 0x494E; // "IN"
const XFS_DIR3_BLOCK_MAGIC: u32 = 0x58444233; // "XDB3" (v5 dir block)
const XFS_DIR3_DATA_MAGIC: u32 = 0x58444433; // "XDD3" (v5 dir data block)

// XFS superblock field offsets (big-endian on disk).
const SB_MAGICNUM: usize = 0;
const SB_BLOCKSIZE: usize = 4;
const SB_DBLOCKS: usize = 8;
const SB_LOGSTART: usize = 48;
const SB_ROOTINO: usize = 56;
const SB_AGBLOCKS: usize = 84;
const SB_AGCOUNT: usize = 88;
const SB_SECTSIZE: usize = 102;
const SB_INODESIZE: usize = 104;
const SB_INOPBLOCK: usize = 106;
const SB_VERSIONNUM: usize = 100;
const SB_BLOCKLOG: usize = 120;
const SB_AGBLKLOG: usize = 124;
const SB_INOPBLOG: usize = 123;
const SB_FEATURES_INCOMPAT: usize = 192;

// di_format values.
const XFS_DINODE_FMT_LOCAL: u8 = 1;
const XFS_DINODE_FMT_EXTENTS: u8 = 2;
const XFS_DINODE_FMT_BTREE: u8 = 3;

// S_IFMT constants for di_mode.
const S_IFDIR: u16 = 0o040000;
const S_IFLNK: u16 = 0o120000;
const S_IFREG: u16 = 0o100000;
const S_IFMT: u16 = 0o170000;

const MAX_AG: usize = 16;

// --- Block cache ---
const CACHE_SLOTS: usize = 64;

// =====================================================================
// Helpers
// =====================================================================

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

// --- Big-endian read/write (XFS is big-endian on disk) ---

fn read_be16(buf: &[u8], off: usize) -> u16 {
    ((buf[off] as u16) << 8) | (buf[off + 1] as u16)
}

fn read_be32(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24)
        | ((buf[off + 1] as u32) << 16)
        | ((buf[off + 2] as u32) << 8)
        | (buf[off + 3] as u32)
}

fn read_be64(buf: &[u8], off: usize) -> u64 {
    ((buf[off] as u64) << 56)
        | ((buf[off + 1] as u64) << 48)
        | ((buf[off + 2] as u64) << 40)
        | ((buf[off + 3] as u64) << 32)
        | ((buf[off + 4] as u64) << 24)
        | ((buf[off + 5] as u64) << 16)
        | ((buf[off + 6] as u64) << 8)
        | (buf[off + 7] as u64)
}

fn write_be16(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = (val >> 8) as u8;
    buf[off + 1] = val as u8;
}

fn write_be32(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = (val >> 24) as u8;
    buf[off + 1] = (val >> 16) as u8;
    buf[off + 2] = (val >> 8) as u8;
    buf[off + 3] = val as u8;
}

fn write_be64(buf: &mut [u8], off: usize, val: u64) {
    buf[off] = (val >> 56) as u8;
    buf[off + 1] = (val >> 48) as u8;
    buf[off + 2] = (val >> 40) as u8;
    buf[off + 3] = (val >> 32) as u8;
    buf[off + 4] = (val >> 24) as u8;
    buf[off + 5] = (val >> 16) as u8;
    buf[off + 6] = (val >> 8) as u8;
    buf[off + 7] = val as u8;
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

// =====================================================================
// CRC32c (Castagnoli) — used by XFS v5 for metadata checksums
// =====================================================================

static CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let poly: u32 = 0x82F63B78; // reflected polynomial for CRC32c
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

fn crc32c(init: u32, data: &[u8]) -> u32 {
    let mut crc = init;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[idx];
    }
    crc
}

// =====================================================================
// Data structures
// =====================================================================

#[derive(Clone, Copy)]
struct XfsSb {
    block_size: u32,
    dblocks: u64,
    ag_count: u32,
    ag_blocks: u32,
    root_ino: u64,
    inode_size: u16,
    inopblock: u16,
    inopblog: u8,
    agblklog: u8,
    sect_size: u16,
    logstart: u64,
}

#[derive(Clone, Copy)]
struct AgfHeader {
    bnoroot: u32,
    cntroot: u32,
    bno_level: u32,
    cnt_level: u32,
    freeblks: u32,
    longest: u32,
    length: u32,
}

impl AgfHeader {
    const fn empty() -> Self {
        Self {
            bnoroot: 0,
            cntroot: 0,
            bno_level: 0,
            cnt_level: 0,
            freeblks: 0,
            longest: 0,
            length: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct AgiHeader {
    root: u32,
    level: u32,
    count: u32,
    freecount: u32,
}

impl AgiHeader {
    const fn empty() -> Self {
        Self {
            root: 0,
            level: 0,
            count: 0,
            freecount: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct XfsInode {
    ino: u64,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    nlink: u32,
    format: u8,
    nextents: u32,
    forkoff: u8,
    nblocks: u64,
    // Data fork bytes. v5 core = 176 bytes; for 512-byte inodes, fork = 336 bytes.
    dfork: [u8; 336],
    dfork_len: usize,
}

impl XfsInode {
    const fn empty() -> Self {
        Self {
            ino: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 0,
            format: 0,
            nextents: 0,
            forkoff: 0,
            nblocks: 0,
            dfork: [0u8; 336],
            dfork_len: 0,
        }
    }

    fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        (self.mode & S_IFMT) == S_IFLNK
    }

    #[allow(dead_code)]
    fn is_regular(&self) -> bool {
        (self.mode & S_IFMT) == S_IFREG
    }
}

#[derive(Clone, Copy)]
struct Extent {
    file_off: u64,
    disk_blk: u64,
    count: u32,
}

#[derive(Clone, Copy)]
struct OpenHandle {
    active: bool,
    inode: XfsInode,
    pid: u32,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self {
            active: false,
            inode: XfsInode::empty(),
            pid: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct CacheSlot {
    block_num: u64,
    valid: bool,
    age: u32,
}

impl CacheSlot {
    const fn empty() -> Self {
        Self {
            block_num: u64::MAX,
            valid: false,
            age: 0,
        }
    }
}

// =====================================================================
// Block I/O client (talks to cache_blk)
// =====================================================================

struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
    grant_va: usize,
    partition_offset: u64,
    /// Per-client nonce counter. See cache_srv::BlkClient for the protocol.
    nonce: Cell<u64>,
}

impl BlkClient {
    fn next_nonce(&self) -> u64 {
        let n = self.nonce.get().wrapping_add(1);
        self.nonce.set(n);
        n
    }

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
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
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

    /// Read a full block (block_size bytes) into memory at `dest` VA.
    fn read_block(&self, block_num: u64, block_size: u32, dest: usize) -> bool {
        let byte_off = block_num * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = block_size / 512;

        for s in 0..sectors {
            let nonce = self.next_nonce();
            let sector_byte = abs_off + (s as u64) * 512;
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(
                self.blk_port,
                IO_READ,
                nonce,
                sector_byte,
                d2,
                self.grant_va as u64,
            );

            let ok = if let Some(rr) = self.recv_match(nonce) {
                if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                    let src = self.scratch_va as *const u8;
                    let dst = (dest + (s as usize) * 512) as *mut u8;
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
        }
        true
    }

    /// Write a full block from memory at `src` VA.
    fn write_block(&self, block_num: u64, block_size: u32, src: usize) -> bool {
        let byte_off = block_num * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = block_size / 512;

        for s in 0..sectors {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (src + (s as usize) * 512) as *const u8,
                    self.scratch_va as *mut u8,
                    512,
                );
            }
            let nonce = self.next_nonce();
            let sector_byte = abs_off + (s as u64) * 512;
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(
                self.blk_port,
                IO_WRITE,
                nonce,
                sector_byte,
                d2,
                self.grant_va as u64,
            );
            let ok = if let Some(rr) = self.recv_match(nonce) {
                rr.tag == IO_WRITE_OK
            } else {
                false
            };
            if !ok {
                return false;
            }
        }
        true
    }

    /// Read-modify-write: patch `data` at byte offset `off` (partition-relative)
    /// within a single 512-byte sector.
    fn write_bytes(&self, off: u64, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        let abs_off = self.partition_offset + off;
        let sector_byte = (abs_off / 512) * 512;
        let ofs = (abs_off % 512) as usize;
        if ofs + data.len() > 512 {
            return false;
        }

        // Read the sector.
        let nonce = self.next_nonce();
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_READ,
            nonce,
            sector_byte,
            d2,
            self.grant_va as u64,
        );
        let ok = if let Some(rr) = self.recv_match(nonce) {
            rr.tag == IO_READ_OK && rr.data[0] == 512
        } else {
            false
        };
        if !ok {
            return false;
        }

        // Patch bytes in scratch_va.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (self.scratch_va + ofs) as *mut u8,
                data.len(),
            );
        }

        // Write sector back.
        let nonce = self.next_nonce();
        syscall::send(
            self.blk_port,
            IO_WRITE,
            nonce,
            sector_byte,
            d2,
            self.grant_va as u64,
        );
        if let Some(rr) = self.recv_match(nonce) {
            rr.tag == IO_WRITE_OK
        } else {
            false
        }
    }
}

// =====================================================================
// Block cache
// =====================================================================

static mut CACHE_META: [CacheSlot; CACHE_SLOTS] = [CacheSlot::empty(); CACHE_SLOTS];
static mut CACHE_DATA_VA: usize = 0;
static mut CACHE_AGE: u32 = 0;

fn cache_init() {
    match syscall::mmap_anon(0, CACHE_SLOTS, 1) {
        Some(va) => unsafe {
            CACHE_DATA_VA = va;
        },
        None => {
            syscall::debug_puts(b"  [xfs_srv] cache alloc FAILED\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    }
}

/// Read a block via cache; returns VA of the cached block data.
fn cache_read(blk: &BlkClient, block_num: u64, block_size: u32) -> Option<usize> {
    unsafe {
        // Check if already cached.
        for i in 0..CACHE_SLOTS {
            if CACHE_META[i].valid && CACHE_META[i].block_num == block_num {
                CACHE_AGE += 1;
                CACHE_META[i].age = CACHE_AGE;
                return Some(CACHE_DATA_VA + i * PAGE_SIZE);
            }
        }

        // Find an empty or LRU slot.
        let mut victim = 0usize;
        let mut min_age = u32::MAX;
        for i in 0..CACHE_SLOTS {
            if !CACHE_META[i].valid {
                victim = i;
                break;
            }
            if CACHE_META[i].age < min_age {
                min_age = CACHE_META[i].age;
                victim = i;
            }
        }

        // Read block from disk.
        let dest = CACHE_DATA_VA + victim * PAGE_SIZE;
        if !blk.read_block(block_num, block_size, dest) {
            return None;
        }

        CACHE_AGE += 1;
        CACHE_META[victim] = CacheSlot {
            block_num,
            valid: true,
            age: CACHE_AGE,
        };

        Some(dest)
    }
}

// =====================================================================
// XFS superblock parsing
// =====================================================================

fn parse_superblock(buf: &[u8]) -> Option<XfsSb> {
    let magic = read_be32(buf, SB_MAGICNUM);
    if magic != XFS_SB_MAGIC {
        syscall::debug_puts(b"  [xfs_srv] bad superblock magic: ");
        print_hex(magic as u64);
        syscall::debug_puts(b"\n");
        return None;
    }

    Some(XfsSb {
        block_size: read_be32(buf, SB_BLOCKSIZE),
        dblocks: read_be64(buf, SB_DBLOCKS),
        ag_count: read_be32(buf, SB_AGCOUNT),
        ag_blocks: read_be32(buf, SB_AGBLOCKS),
        root_ino: read_be64(buf, SB_ROOTINO),
        inode_size: read_be16(buf, SB_INODESIZE),
        inopblock: read_be16(buf, SB_INOPBLOCK),
        inopblog: buf[SB_INOPBLOG],
        agblklog: buf[SB_AGBLKLOG],
        sect_size: read_be16(buf, SB_SECTSIZE),
        logstart: read_be64(buf, SB_LOGSTART),
    })
}

// =====================================================================
// AG header parsing
// =====================================================================

static mut AG_F: [AgfHeader; MAX_AG] = [AgfHeader::empty(); MAX_AG];
static mut AG_I: [AgiHeader; MAX_AG] = [AgiHeader::empty(); MAX_AG];

fn read_agf(blk: &BlkClient, sb: &XfsSb, ag: u32) -> Option<AgfHeader> {
    // AGF is at sector 1 of each AG.
    let ag_start_byte = (ag as u64) * (sb.ag_blocks as u64) * (sb.block_size as u64);
    let agf_off = ag_start_byte + (sb.sect_size as u64);

    let mut buf = [0u8; 512];
    if !blk.read_bytes(agf_off, &mut buf) {
        return None;
    }

    let magic = read_be32(&buf, 0);
    if magic != XFS_AGF_MAGIC {
        syscall::debug_puts(b"  [xfs_srv] bad AGF magic in AG ");
        print_num(ag as u64);
        syscall::debug_puts(b": ");
        print_hex(magic as u64);
        syscall::debug_puts(b"\n");
        return None;
    }

    Some(AgfHeader {
        bnoroot: read_be32(&buf, 20),  // agf_roots[0] (bnobt)
        cntroot: read_be32(&buf, 24),  // agf_roots[1] (cntbt)
        bno_level: read_be32(&buf, 28), // agf_levels[0]
        cnt_level: read_be32(&buf, 32), // agf_levels[1]
        freeblks: read_be32(&buf, 48), // agf_freeblks
        longest: read_be32(&buf, 52),  // agf_longest
        length: read_be32(&buf, 12),   // agf_length
    })
}

fn read_agi(blk: &BlkClient, sb: &XfsSb, ag: u32) -> Option<AgiHeader> {
    let ag_start_byte = (ag as u64) * (sb.ag_blocks as u64) * (sb.block_size as u64);
    let agi_byte = ag_start_byte + 2 * (sb.sect_size as u64); // sector 2

    let mut buf = [0u8; 512];
    if !blk.read_bytes(agi_byte, &mut buf) {
        return None;
    }

    let magic = read_be32(&buf, 0);
    if magic != XFS_AGI_MAGIC {
        syscall::debug_puts(b"  [xfs_srv] bad AGI magic in AG ");
        print_num(ag as u64);
        syscall::debug_puts(b": ");
        print_hex(magic as u64);
        syscall::debug_puts(b"\n");
        return None;
    }

    Some(AgiHeader {
        root: read_be32(&buf, 20),      // agi_root
        level: read_be32(&buf, 24),     // agi_level
        count: read_be32(&buf, 16),     // agi_count
        freecount: read_be32(&buf, 28), // agi_freecount
    })
}

fn init_ag_headers(blk: &BlkClient, sb: &XfsSb) {
    let n = (sb.ag_count as usize).min(MAX_AG);
    for ag in 0..n {
        unsafe {
            if let Some(agf) = read_agf(blk, sb, ag as u32) {
                AG_F[ag] = agf;
                syscall::debug_puts(b"  [xfs_srv] AG");
                print_num(ag as u64);
                syscall::debug_puts(b": free=");
                print_num(agf.freeblks as u64);
                syscall::debug_puts(b" longest=");
                print_num(agf.longest as u64);
                syscall::debug_puts(b"\n");
            }
            if let Some(agi) = read_agi(blk, sb, ag as u32) {
                AG_I[ag] = agi;
            }
        }
    }
}

// =====================================================================
// Inode number arithmetic
// =====================================================================

fn ino_ag(ino: u64, sb: &XfsSb) -> u32 {
    (ino >> ((sb.agblklog as u64) + (sb.inopblog as u64))) as u32
}

fn ino_agbno(ino: u64, sb: &XfsSb) -> u32 {
    ((ino >> (sb.inopblog as u64)) & ((1u64 << sb.agblklog) - 1)) as u32
}

fn ino_offset(ino: u64, sb: &XfsSb) -> u32 {
    (ino & ((1u64 << sb.inopblog) - 1)) as u32
}

fn ino_abs_block(ino: u64, sb: &XfsSb) -> u64 {
    let ag = ino_ag(ino, sb);
    let agbno = ino_agbno(ino, sb);
    (ag as u64) * (sb.ag_blocks as u64) + (agbno as u64)
}

// =====================================================================
// Inode reading
// =====================================================================

fn read_inode(blk: &BlkClient, sb: &XfsSb, ino: u64) -> Option<XfsInode> {
    let block = ino_abs_block(ino, sb);
    let offset_in_block = (ino_offset(ino, sb) as usize) * (sb.inode_size as usize);

    let data_va = cache_read(blk, block, sb.block_size)?;

    let buf =
        unsafe { core::slice::from_raw_parts((data_va + offset_in_block) as *const u8, sb.inode_size as usize) };

    let magic = read_be16(buf, 0);
    if magic != XFS_DINODE_MAGIC {
        return None;
    }

    let version = buf[4];
    // v5 (v3 on-disk) inode core is 176 bytes. v1/v2 core is 96/100 bytes.
    let core_size: usize = if version >= 3 { 176 } else { 100 };

    let inode_size = sb.inode_size as usize;
    let forkoff_raw = buf[82]; // di_forkoff
    // If di_forkoff == 0, the entire post-core area is data fork.
    let dfork_end = if forkoff_raw > 0 {
        core_size + (forkoff_raw as usize) * 8
    } else {
        inode_size
    };
    let dfork_len = if dfork_end > core_size {
        (dfork_end - core_size).min(336)
    } else {
        0
    };

    let mut dfork = [0u8; 336];
    if dfork_len > 0 {
        dfork[..dfork_len].copy_from_slice(&buf[core_size..core_size + dfork_len]);
    }

    // Check NREXT64 flag: when set, di_nextents moves from offset 76 (u32) to
    // offset 24 (u64) as di_big_nextents. di_flags2 is at offset 120 (u64).
    let flags2 = if version >= 3 { read_be64(buf, 120) } else { 0 };
    let nrext64 = (flags2 & (1 << 4)) != 0; // XFS_DIFLAG2_NREXT64
    let nextents = if nrext64 {
        read_be64(buf, 24) as u32 // di_big_nextents (only low 32 bits used in practice)
    } else {
        read_be32(buf, 76) // di_nextents
    };

    Some(XfsInode {
        ino,
        mode: read_be16(buf, 2),     // di_mode
        uid: read_be32(buf, 8),      // di_uid
        gid: read_be32(buf, 12),     // di_gid
        size: read_be64(buf, 56),    // di_size
        nlink: read_be32(buf, 16),   // di_nlink
        format: buf[5],              // di_format
        nextents,
        forkoff: forkoff_raw,
        nblocks: read_be64(buf, 64), // di_nblocks
        dfork,
        dfork_len,
    })
}

// =====================================================================
// Extent parsing (128-bit packed records)
// =====================================================================

fn decode_extent(rec: &[u8]) -> Extent {
    // XFS extent records: 16 bytes, big-endian packed.
    // l0 (u64): bit 63 = unwritten flag, bits 62..9 = file offset (54 bits),
    //           bits 8..0 = startblock high (9 bits)
    // l1 (u64): bits 63..21 = startblock low (43 bits), bits 20..0 = blockcount (21 bits)
    let l0 = read_be64(rec, 0);
    let l1 = read_be64(rec, 8);

    let file_off = (l0 >> 9) & 0x003F_FFFF_FFFF_FFFF; // 54 bits
    let disk_blk = ((l0 & 0x1FF) << 43) | (l1 >> 21); // 52 bits
    let count = (l1 & 0x001F_FFFF) as u32; // 21 bits

    Extent {
        file_off,
        disk_blk,
        count,
    }
}

/// Resolve a logical file block to an absolute disk block using extent list (format=2).
fn resolve_extent_list(inode: &XfsInode, logical_blk: u64) -> Option<u64> {
    let nrecs = inode.nextents as usize;
    let max_recs = inode.dfork_len / 16;
    let recs = nrecs.min(max_recs);

    for i in 0..recs {
        let off = i * 16;
        if off + 16 > inode.dfork_len {
            break;
        }
        let ext = decode_extent(&inode.dfork[off..]);
        if logical_blk >= ext.file_off && logical_blk < ext.file_off + (ext.count as u64) {
            return Some(ext.disk_blk + (logical_blk - ext.file_off));
        }
    }
    None
}

/// Resolve a logical file block to an absolute disk block via B+tree (format=3).
fn resolve_btree(
    blk: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    logical_blk: u64,
) -> Option<u64> {
    // B+tree root is stored in the data fork.
    // Root header: level(u16), numrecs(u16), then keys and pointers.
    if inode.dfork_len < 4 {
        return None;
    }
    let level = read_be16(&inode.dfork, 0) as u32;
    let numrecs = read_be16(&inode.dfork, 2) as usize;

    if level == 0 {
        // Leaf: extent records start at offset 4 in dfork.
        for i in 0..numrecs {
            let off = 4 + i * 16;
            if off + 16 > inode.dfork_len {
                break;
            }
            let ext = decode_extent(&inode.dfork[off..]);
            if logical_blk >= ext.file_off && logical_blk < ext.file_off + (ext.count as u64) {
                return Some(ext.disk_blk + (logical_blk - ext.file_off));
            }
        }
        return None;
    }

    // Internal node: keys at offset 4, pointers after keys.
    // Key = startoff (u64, big-endian), pointer = block number (u64, big-endian).
    // Keys start at 4, pointers start at 4 + numrecs * 8.
    let keys_off = 4usize;
    let ptrs_off = keys_off + numrecs * 8;

    // Find the correct child pointer.
    let mut child_idx = 0usize;
    for i in 1..numrecs {
        let key_off = keys_off + i * 8;
        if key_off + 8 > inode.dfork_len {
            break;
        }
        let key = read_be64(&inode.dfork, key_off);
        if logical_blk < key {
            break;
        }
        child_idx = i;
    }

    let ptr_off = ptrs_off + child_idx * 8;
    if ptr_off + 8 > inode.dfork_len {
        return None;
    }
    let mut child_block = read_be64(&inode.dfork, ptr_off);

    // Walk down the tree from disk.
    let mut cur_level = level - 1;
    loop {
        let data_va = cache_read(blk, child_block, sb.block_size)?;
        let buf = unsafe {
            core::slice::from_raw_parts(data_va as *const u8, sb.block_size as usize)
        };

        // Long-form B+tree block header (v5): 72 bytes.
        // bb_magic(4) bb_level(2) bb_numrecs(2) bb_leftsib(8) bb_rightsib(8)
        // bb_blkno(8) bb_lsn(8) bb_uuid(16) bb_owner(8) bb_crc(4) bb_pad(4)
        let hdr_size: usize = 72; // v5 long-form header
        let blk_level = read_be16(buf, 4) as u32;
        let blk_numrecs = read_be16(buf, 6) as usize;

        if blk_level == 0 {
            // Leaf node: extent records after header.
            for i in 0..blk_numrecs {
                let off = hdr_size + i * 16;
                if off + 16 > sb.block_size as usize {
                    break;
                }
                let ext = decode_extent(&buf[off..]);
                if logical_blk >= ext.file_off
                    && logical_blk < ext.file_off + (ext.count as u64)
                {
                    return Some(ext.disk_blk + (logical_blk - ext.file_off));
                }
            }
            return None;
        }

        // Internal node: keys at hdr_size, pointers at hdr_size + numrecs * 8.
        let int_keys_off = hdr_size;
        let int_ptrs_off = int_keys_off + blk_numrecs * 8;

        let mut idx = 0usize;
        for i in 1..blk_numrecs {
            let ko = int_keys_off + i * 8;
            if ko + 8 > sb.block_size as usize {
                break;
            }
            let key = read_be64(buf, ko);
            if logical_blk < key {
                break;
            }
            idx = i;
        }

        let po = int_ptrs_off + idx * 8;
        if po + 8 > sb.block_size as usize {
            return None;
        }
        child_block = read_be64(buf, po);
        cur_level -= 1;

        if cur_level == 0 && blk_level > 1 {
            // Keep going.
        }
    }
}

/// Resolve a logical file block to an absolute disk block.
fn resolve_block(
    blk: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    logical_blk: u64,
) -> Option<u64> {
    match inode.format {
        XFS_DINODE_FMT_EXTENTS => resolve_extent_list(inode, logical_blk),
        XFS_DINODE_FMT_BTREE => resolve_btree(blk, sb, inode, logical_blk),
        _ => None,
    }
}

// =====================================================================
// Directory reading
// =====================================================================

/// Shortform directory lookup: find inode number by name.
fn dir_sf_lookup(inode: &XfsInode, name: &[u8]) -> Option<u64> {
    if inode.dfork_len < 6 {
        return None;
    }
    let d = &inode.dfork[..inode.dfork_len];
    let count = d[0] as usize;
    let i8count = d[1] as usize;
    let use_64 = i8count > 0;

    // Parent inode at offset 2 (4 or 8 bytes).
    let parent_size: usize = if use_64 { 8 } else { 4 };

    // Handle "..".
    if name == b".." {
        let parent_ino = if use_64 {
            read_be64(d, 2)
        } else {
            read_be32(d, 2) as u64
        };
        return Some(parent_ino);
    }

    let mut pos = 2 + parent_size;
    let total = count + i8count; // i8count entries use 8-byte inumbers

    for entry_idx in 0..total {
        if pos >= d.len() {
            break;
        }
        let namelen = d[pos] as usize;
        // offset(2 bytes) at pos+1, skip it
        let entry_name_start = pos + 3;
        if entry_name_start + namelen > d.len() {
            break;
        }
        let entry_name = &d[entry_name_start..entry_name_start + namelen];

        // After name: ftype (1 byte, v5), then inumber (4 or 8 bytes).
        let ftype_off = entry_name_start + namelen;
        let ino_off = ftype_off + 1; // skip ftype

        // First i8count entries use 8-byte inumbers, rest use 4-byte.
        let ino_size: usize = if entry_idx < i8count { 8 } else { 4 };
        if ino_off + ino_size > d.len() {
            break;
        }

        if namelen == name.len() && entry_name == name {
            let ino = if ino_size == 8 {
                read_be64(d, ino_off)
            } else {
                read_be32(d, ino_off) as u64
            };
            return Some(ino);
        }

        pos = ino_off + ino_size;
    }

    None
}

/// Shortform directory iteration: return next entry at or after `offset`.
/// Returns (inode, name_buf, name_len, next_offset).
fn dir_sf_next(
    inode: &XfsInode,
    offset: u32,
) -> Option<(u64, [u8; 256], usize, u32)> {
    if inode.dfork_len < 6 {
        return None;
    }
    let d = &inode.dfork[..inode.dfork_len];
    let count = d[0] as usize;
    let i8count = d[1] as usize;
    let use_64 = i8count > 0;
    let parent_size: usize = if use_64 { 8 } else { 4 };

    let mut pos = 2 + parent_size;
    let total = count + i8count;
    let mut entry_num = 0u32;

    for entry_idx in 0..total {
        if pos >= d.len() {
            break;
        }
        let namelen = d[pos] as usize;
        let entry_name_start = pos + 3;
        if entry_name_start + namelen > d.len() {
            break;
        }

        let ftype_off = entry_name_start + namelen;
        let ino_off = ftype_off + 1;
        let ino_size: usize = if entry_idx < i8count { 8 } else { 4 };
        if ino_off + ino_size > d.len() {
            break;
        }

        if entry_num >= offset {
            let ino = if ino_size == 8 {
                read_be64(d, ino_off)
            } else {
                read_be32(d, ino_off) as u64
            };
            let mut name_buf = [0u8; 256];
            let nlen = namelen.min(255);
            name_buf[..nlen].copy_from_slice(&d[entry_name_start..entry_name_start + nlen]);
            return Some((ino, name_buf, nlen, entry_num + 1));
        }

        pos = ino_off + ino_size;
        entry_num += 1;
    }

    None
}

/// Block/data directory entry scanning. Data block starts with a header;
/// entries follow. Free entries have freetag == 0xFFFF.
fn dir_data_scan(
    buf: &[u8],
    block_size: u32,
    name: Option<&[u8]>,
    start_byte_off: usize,
) -> Option<(u64, [u8; 256], usize, usize)> {
    // v5 data block header: 64 bytes (magic(4), crc(4), blkno(8), lsn(8), uuid(16), owner(8),
    // then bestfree[3] = 3*(offset(u16)+length(u16)) = 12 bytes, pad(4)).
    // For XDB3 (block dir), header is larger: includes leaf tail.
    // For XDD3 (data dir), header is 64 bytes.
    let hdr_size: usize = 64;

    let mut pos = if start_byte_off >= hdr_size {
        start_byte_off
    } else {
        hdr_size
    };

    let bs = block_size as usize;

    while pos + 8 < bs {
        // Check for free entry (freetag 0xFFFF at offset 0).
        let freetag = read_be16(buf, pos);
        if freetag == 0xFFFF {
            // Free entry: freetag(2) + length(2).
            let free_len = read_be16(buf, pos + 2) as usize;
            if free_len == 0 {
                break; // corrupt
            }
            pos += free_len;
            continue;
        }

        // Data entry: inumber(8), namelen(1), name[namelen], ftype(1), tag(2).
        // Total rounded up to 8-byte boundary.
        if pos + 11 > bs {
            break;
        }
        let entry_ino = read_be64(buf, pos);
        let namelen = buf[pos + 8] as usize;
        let name_start = pos + 9;
        if name_start + namelen + 2 > bs {
            break;
        }

        let entry_name = &buf[name_start..name_start + namelen];
        // ftype at name_start + namelen, tag at aligned offset.
        let raw_end = name_start + namelen + 1 + 2; // +1 ftype, +2 tag
        let entry_end = (raw_end + 7) & !7; // round up to 8

        if let Some(target) = name {
            if namelen == target.len() && entry_name == target {
                let mut name_buf = [0u8; 256];
                let nlen = namelen.min(255);
                name_buf[..nlen].copy_from_slice(&buf[name_start..name_start + nlen]);
                return Some((entry_ino, name_buf, nlen, entry_end));
            }
        } else {
            // Iteration mode: return this entry.
            if entry_ino != 0 {
                let mut name_buf = [0u8; 256];
                let nlen = namelen.min(255);
                name_buf[..nlen].copy_from_slice(&buf[name_start..name_start + nlen]);
                return Some((entry_ino, name_buf, nlen, entry_end));
            }
        }

        pos = entry_end;
    }

    None
}

/// Block directory (single-block dir, format=2 with 1 extent): lookup or iterate.
fn dir_block_op(
    blk_client: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    name: Option<&[u8]>,
    byte_offset: usize,
) -> Option<(u64, [u8; 256], usize, usize)> {
    // Get the single extent.
    if inode.dfork_len < 16 {
        return None;
    }
    let ext = decode_extent(&inode.dfork[0..16]);
    if ext.count == 0 {
        return None;
    }

    let data_va = cache_read(blk_client, ext.disk_blk, sb.block_size)?;
    let buf =
        unsafe { core::slice::from_raw_parts(data_va as *const u8, sb.block_size as usize) };

    dir_data_scan(buf, sb.block_size, name, byte_offset)
}

/// Multi-block (leaf/node) directory: lookup by scanning all data blocks.
fn dir_multi_lookup(
    blk_client: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    name: &[u8],
) -> Option<u64> {
    // XFS leaf/node directories store data blocks at logical offsets 0..N,
    // and metadata blocks (leaf, freeindex) at high logical offsets.
    // The data block boundary is at logical block (sb.block_size / 8),
    // i.e., XFS_DIR2_LEAF_OFFSET / block_size. For 4K blocks: 32GB / 4K = 8M.
    // We just scan the extent list and read data blocks at low offsets.
    let max_data_lblk = (sb.block_size as u64) / 8; // rough boundary

    // Scan extents from dfork or btree.
    let nrecs = inode.nextents as usize;
    if inode.format == XFS_DINODE_FMT_EXTENTS {
        let max_recs = inode.dfork_len / 16;
        for i in 0..nrecs.min(max_recs) {
            let off = i * 16;
            if off + 16 > inode.dfork_len {
                break;
            }
            let ext = decode_extent(&inode.dfork[off..]);
            if ext.file_off >= max_data_lblk {
                continue; // leaf/freeindex block, skip
            }
            // Read each block in this extent.
            for b in 0..ext.count {
                let abs_blk = ext.disk_blk + (b as u64);
                if let Some(data_va) = cache_read(blk_client, abs_blk, sb.block_size) {
                    let buf = unsafe {
                        core::slice::from_raw_parts(data_va as *const u8, sb.block_size as usize)
                    };
                    if let Some((ino, _, _, _)) =
                        dir_data_scan(buf, sb.block_size, Some(name), 0)
                    {
                        return Some(ino);
                    }
                }
            }
        }
    } else if inode.format == XFS_DINODE_FMT_BTREE {
        // For btree directories, scan logical blocks 0..N.
        // We don't know the exact count, so iterate until resolve_block fails.
        let mut lblk = 0u64;
        while lblk < max_data_lblk {
            match resolve_btree(blk_client, sb, inode, lblk) {
                Some(abs_blk) => {
                    if let Some(data_va) = cache_read(blk_client, abs_blk, sb.block_size) {
                        let buf = unsafe {
                            core::slice::from_raw_parts(
                                data_va as *const u8,
                                sb.block_size as usize,
                            )
                        };
                        if let Some((ino, _, _, _)) =
                            dir_data_scan(buf, sb.block_size, Some(name), 0)
                        {
                            return Some(ino);
                        }
                    }
                    lblk += 1;
                }
                None => break,
            }
        }
    }
    None
}

/// Multi-block directory iteration.
fn dir_multi_next(
    blk_client: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    offset: u32,
) -> Option<(u64, [u8; 256], usize, u32)> {
    // offset encodes: high 16 bits = logical block index, low 16 bits = byte offset within block.
    let mut lblk_idx = (offset >> 16) as u64;
    let mut byte_off = (offset & 0xFFFF) as usize;
    let max_data_lblk = (sb.block_size as u64) / 8;

    while lblk_idx < max_data_lblk {
        let abs_blk = match resolve_block(blk_client, sb, inode, lblk_idx) {
            Some(b) => b,
            None => {
                lblk_idx += 1;
                byte_off = 0;
                continue;
            }
        };
        if let Some(data_va) = cache_read(blk_client, abs_blk, sb.block_size) {
            let buf = unsafe {
                core::slice::from_raw_parts(data_va as *const u8, sb.block_size as usize)
            };
            if let Some((ino, name_buf, name_len, next_byte)) =
                dir_data_scan(buf, sb.block_size, None, byte_off)
            {
                let next_off = ((lblk_idx as u32) << 16) | (next_byte as u32 & 0xFFFF);
                return Some((ino, name_buf, name_len, next_off));
            }
        }
        lblk_idx += 1;
        byte_off = 0;
    }
    None
}

/// Unified directory lookup.
fn dir_lookup(
    blk_client: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    name: &[u8],
) -> Option<u64> {
    if !inode.is_dir() {
        return None;
    }

    // Handle "." — return the directory's own inode.
    if name == b"." {
        return Some(inode.ino);
    }

    match inode.format {
        XFS_DINODE_FMT_LOCAL => dir_sf_lookup(inode, name),
        XFS_DINODE_FMT_EXTENTS | XFS_DINODE_FMT_BTREE => {
            // Single block or multi-block?
            if inode.format == XFS_DINODE_FMT_EXTENTS && inode.nextents == 1 {
                // Could be single-block dir.
                if let Some((ino, _, _, _)) = dir_block_op(blk_client, sb, inode, Some(name), 0) {
                    return Some(ino);
                }
                // Also check ".." via shortform won't work here, try multi.
                return None;
            }
            dir_multi_lookup(blk_client, sb, inode, name)
        }
        _ => None,
    }
}

/// Unified directory iteration.
fn dir_next(
    blk_client: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    offset: u32,
) -> Option<(u64, [u8; 256], usize, u32)> {
    if !inode.is_dir() {
        return None;
    }

    match inode.format {
        XFS_DINODE_FMT_LOCAL => dir_sf_next(inode, offset),
        XFS_DINODE_FMT_EXTENTS if inode.nextents == 1 => {
            // Single-block dir iteration.
            let byte_off = offset as usize;
            if let Some((ino, name_buf, name_len, next_byte)) =
                dir_block_op(blk_client, sb, inode, None, byte_off)
            {
                Some((ino, name_buf, name_len, next_byte as u32))
            } else {
                None
            }
        }
        _ => dir_multi_next(blk_client, sb, inode, offset),
    }
}

// =====================================================================
// Path resolution
// =====================================================================

fn path_resolve(
    blk_client: &BlkClient,
    sb: &XfsSb,
    path: &[u8],
) -> Option<XfsInode> {
    let root = read_inode(blk_client, sb, sb.root_ino)?;

    if path.is_empty() || path == b"/" {
        return Some(root);
    }

    let mut current = root;

    // Split path by '/'.
    let mut start = 0usize;
    while start < path.len() && path[start] == b'/' {
        start += 1;
    }

    while start < path.len() {
        let mut end = start;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        if end == start {
            start = end + 1;
            continue;
        }

        let component = &path[start..end];

        // If current is a symlink, we would need to follow it.
        // For now, only handle directories.
        if !current.is_dir() {
            return None;
        }

        let child_ino = dir_lookup(blk_client, sb, &current, component)?;
        current = read_inode(blk_client, sb, child_ino)?;

        start = end + 1;
    }

    Some(current)
}

// =====================================================================
// Symlink reading
// =====================================================================

fn read_symlink_target(
    blk_client: &BlkClient,
    sb: &XfsSb,
    inode: &XfsInode,
    out: &mut [u8],
) -> usize {
    if !inode.is_symlink() {
        return 0;
    }
    let target_len = inode.size as usize;
    let copy_len = target_len.min(out.len());

    if inode.format == XFS_DINODE_FMT_LOCAL {
        // Inline symlink target in dfork.
        let avail = copy_len.min(inode.dfork_len);
        out[..avail].copy_from_slice(&inode.dfork[..avail]);
        return avail;
    }

    if inode.format == XFS_DINODE_FMT_EXTENTS {
        // Target stored in data blocks.
        let mut read = 0usize;
        let mut logical = 0u64;
        while read < copy_len {
            if let Some(abs_blk) = resolve_block(blk_client, sb, inode, logical) {
                if let Some(data_va) = cache_read(blk_client, abs_blk, sb.block_size) {
                    let chunk = (copy_len - read).min(sb.block_size as usize);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data_va as *const u8,
                            out[read..].as_mut_ptr(),
                            chunk,
                        );
                    }
                    read += chunk;
                } else {
                    break;
                }
            } else {
                break;
            }
            logical += 1;
        }
        return read;
    }

    0
}

// =====================================================================
// Write infrastructure (Phase C)
// =====================================================================

/// v5 short-form B+tree block header size (bnobt, cntbt, inobt).
const AG_BT_HDR_V5: usize = 56;

/// Scratch page for write operations (set in main).
static mut WRITE_VA: usize = 0;

/// Invalidate all cache entries for a given block.
fn cache_invalidate(block_num: u64) {
    unsafe {
        for i in 0..CACHE_SLOTS {
            if CACHE_META[i].valid && CACHE_META[i].block_num == block_num {
                CACHE_META[i].valid = false;
            }
        }
    }
}

/// Encode an Extent into a 16-byte big-endian packed record.
fn encode_extent(ext: &Extent) -> [u8; 16] {
    let l0: u64 =
        ((ext.file_off & 0x003F_FFFF_FFFF_FFFF) << 9) | ((ext.disk_blk >> 43) & 0x1FF);
    let l1: u64 =
        ((ext.disk_blk & 0x7FF_FFFF_FFFF) << 21) | (ext.count as u64 & 0x001F_FFFF);
    let mut out = [0u8; 16];
    write_be64(&mut out, 0, l0);
    write_be64(&mut out, 8, l1);
    out
}

/// Write an XfsInode's metadata and data fork back to disk (read-modify-write).
fn write_inode(blk: &BlkClient, sb: &XfsSb, inode: &XfsInode) -> bool {
    let block = ino_abs_block(inode.ino, sb);
    let off_in_blk = (ino_offset(inode.ino, sb) as usize) * (sb.inode_size as usize);
    let wva = unsafe { WRITE_VA };

    if !blk.read_block(block, sb.block_size, wva) {
        return false;
    }

    let buf = unsafe {
        core::slice::from_raw_parts_mut(
            (wva + off_in_blk) as *mut u8,
            sb.inode_size as usize,
        )
    };

    // Patch inode core fields.
    write_be16(buf, 2, inode.mode);
    buf[5] = inode.format;
    write_be32(buf, 8, inode.uid);
    write_be32(buf, 12, inode.gid);
    write_be32(buf, 16, inode.nlink);
    write_be64(buf, 56, inode.size);
    write_be64(buf, 64, inode.nblocks);
    buf[82] = inode.forkoff;

    // Handle nextents (NREXT64-aware).
    let version = buf[4];
    let flags2 = if version >= 3 {
        read_be64(buf, 120)
    } else {
        0
    };
    if (flags2 & (1 << 4)) != 0 {
        write_be64(buf, 24, inode.nextents as u64);
    } else {
        write_be32(buf, 76, inode.nextents);
    }

    // Write data fork.
    let core_size: usize = if version >= 3 { 176 } else { 100 };
    if inode.dfork_len > 0 && core_size + inode.dfork_len <= sb.inode_size as usize {
        buf[core_size..core_size + inode.dfork_len]
            .copy_from_slice(&inode.dfork[..inode.dfork_len]);
    }

    cache_invalidate(block);
    blk.write_block(block, sb.block_size, wva)
}

/// Patch a u32 field in the AGF on disk.
fn write_agf_u32(blk: &BlkClient, sb: &XfsSb, ag: u32, field_off: usize, val: u32) -> bool {
    let ag_start = (ag as u64) * (sb.ag_blocks as u64) * (sb.block_size as u64);
    let agf_off = ag_start + (sb.sect_size as u64);
    let mut d = [0u8; 4];
    write_be32(&mut d, 0, val);
    blk.write_bytes(agf_off + field_off as u64, &d)
}

/// Patch a u32 field in the AGI on disk.
fn write_agi_u32(blk: &BlkClient, sb: &XfsSb, ag: u32, field_off: usize, val: u32) -> bool {
    let ag_start = (ag as u64) * (sb.ag_blocks as u64) * (sb.block_size as u64);
    let agi_off = ag_start + 2 * (sb.sect_size as u64);
    let mut d = [0u8; 4];
    write_be32(&mut d, 0, val);
    blk.write_bytes(agi_off + field_off as u64, &d)
}

/// Flush the in-memory AGF to disk.
fn flush_agf(blk: &BlkClient, sb: &XfsSb, ag: u32) -> bool {
    let agf = unsafe { &AG_F[ag as usize] };
    write_agf_u32(blk, sb, ag, 20, agf.bnoroot)
        && write_agf_u32(blk, sb, ag, 24, agf.cntroot)
        && write_agf_u32(blk, sb, ag, 28, agf.bno_level)
        && write_agf_u32(blk, sb, ag, 32, agf.cnt_level)
        && write_agf_u32(blk, sb, ag, 48, agf.freeblks)
        && write_agf_u32(blk, sb, ag, 52, agf.longest)
}

/// Flush the in-memory AGI to disk.
fn flush_agi(blk: &BlkClient, sb: &XfsSb, ag: u32) -> bool {
    let agi = unsafe { &AG_I[ag as usize] };
    write_agi_u32(blk, sb, ag, 16, agi.count)
        && write_agi_u32(blk, sb, ag, 28, agi.freecount)
}

/// Allocate `count` contiguous blocks. Returns absolute block number.
fn alloc_blocks(blk: &BlkClient, sb: &XfsSb, count: u32) -> Option<u64> {
    let n_ag = (sb.ag_count as usize).min(MAX_AG);
    let wva = unsafe { WRITE_VA };

    for ag in 0..n_ag {
        let agf = unsafe { &mut AG_F[ag] };
        if agf.freeblks < count {
            continue;
        }

        let ag_start = (ag as u64) * (sb.ag_blocks as u64);

        // Walk bnobt to leaf level.
        let mut cur_agbno = agf.bnoroot;
        let mut depth = 0u32;
        loop {
            let abs_blk = ag_start + (cur_agbno as u64);
            if !blk.read_block(abs_blk, sb.block_size, wva) {
                break;
            }
            let buf = unsafe {
                core::slice::from_raw_parts_mut(wva as *mut u8, sb.block_size as usize)
            };

            let level = read_be16(buf, 4);
            let numrecs = read_be16(buf, 6) as usize;

            if level > 0 {
                // Internal node: descend to leftmost child.
                if numrecs == 0 {
                    break;
                }
                // bnobt keys are 8 bytes each, pointers are 4 bytes each.
                let ptr_off = AG_BT_HDR_V5 + numrecs * 8;
                if ptr_off + 4 > sb.block_size as usize {
                    break;
                }
                cur_agbno = read_be32(buf, ptr_off);
                depth += 1;
                if depth > 10 {
                    break;
                }
                continue;
            }

            // Leaf level: scan for a free extent with blockcount >= count.
            for i in 0..numrecs {
                let rec_off = AG_BT_HDR_V5 + i * 8;
                let startblock = read_be32(buf, rec_off);
                let blockcount = read_be32(buf, rec_off + 4);

                if blockcount >= count {
                    let alloc_start = startblock;

                    if blockcount == count {
                        // Remove record: shift remaining left.
                        for j in i..numrecs - 1 {
                            let src_off = AG_BT_HDR_V5 + (j + 1) * 8;
                            let dst_off = AG_BT_HDR_V5 + j * 8;
                            let s = read_be32(buf, src_off);
                            let c = read_be32(buf, src_off + 4);
                            write_be32(buf, dst_off, s);
                            write_be32(buf, dst_off + 4, c);
                        }
                        write_be16(buf, 6, (numrecs - 1) as u16);
                    } else {
                        write_be32(buf, rec_off, startblock + count);
                        write_be32(buf, rec_off + 4, blockcount - count);
                    }

                    // Write leaf block back.
                    cache_invalidate(abs_blk);
                    if !blk.write_block(abs_blk, sb.block_size, wva) {
                        return None;
                    }

                    // Update AGF.
                    agf.freeblks -= count;
                    if blockcount == agf.longest {
                        // Recompute longest from this leaf.
                        let nr = read_be16(buf, 6) as usize;
                        let mut ml = 0u32;
                        for j in 0..nr {
                            let c = read_be32(buf, AG_BT_HDR_V5 + j * 8 + 4);
                            if c > ml {
                                ml = c;
                            }
                        }
                        agf.longest = ml;
                    }
                    flush_agf(blk, sb, ag as u32);

                    return Some(ag_start + alloc_start as u64);
                }
            }
            break;
        }
    }
    None
}

/// Free `count` blocks starting at `abs_blk` back to AG free space.
fn free_blocks(blk: &BlkClient, sb: &XfsSb, abs_blk: u64, count: u32) {
    let ag = (abs_blk / (sb.ag_blocks as u64)) as usize;
    if ag >= (sb.ag_count as usize).min(MAX_AG) {
        return;
    }
    let ag_start = (ag as u64) * (sb.ag_blocks as u64);
    let agbno = (abs_blk - ag_start) as u32;
    let agf = unsafe { &mut AG_F[ag] };
    let wva = unsafe { WRITE_VA };

    // Walk bnobt to leaf.
    let mut cur_agbno = agf.bnoroot;
    let mut depth = 0u32;
    loop {
        let blk_abs = ag_start + (cur_agbno as u64);
        if !blk.read_block(blk_abs, sb.block_size, wva) {
            return;
        }
        let buf = unsafe {
            core::slice::from_raw_parts_mut(wva as *mut u8, sb.block_size as usize)
        };
        let level = read_be16(buf, 4);
        let numrecs = read_be16(buf, 6) as usize;

        if level > 0 {
            if numrecs == 0 {
                return;
            }
            let mut child_idx = 0usize;
            for i in 1..numrecs {
                let key_start = read_be32(buf, AG_BT_HDR_V5 + i * 8);
                if agbno < key_start {
                    break;
                }
                child_idx = i;
            }
            let ptr_off = AG_BT_HDR_V5 + numrecs * 8 + child_idx * 4;
            if ptr_off + 4 > sb.block_size as usize {
                return;
            }
            cur_agbno = read_be32(buf, ptr_off);
            depth += 1;
            if depth > 10 {
                return;
            }
            continue;
        }

        // Leaf: insert sorted by startblock, merging with neighbours.
        let mut ins_idx = numrecs;
        for i in 0..numrecs {
            let s = read_be32(buf, AG_BT_HDR_V5 + i * 8);
            if agbno < s {
                ins_idx = i;
                break;
            }
        }

        // Try merge with previous record.
        let mut merged = false;
        if ins_idx > 0 {
            let prev_off = AG_BT_HDR_V5 + (ins_idx - 1) * 8;
            let prev_start = read_be32(buf, prev_off);
            let prev_count = read_be32(buf, prev_off + 4);
            if prev_start + prev_count == agbno {
                let new_count = prev_count + count;
                write_be32(buf, prev_off + 4, new_count);
                // Also merge with next?
                if ins_idx < numrecs {
                    let next_off = AG_BT_HDR_V5 + ins_idx * 8;
                    let next_start = read_be32(buf, next_off);
                    if agbno + count == next_start {
                        let next_count = read_be32(buf, next_off + 4);
                        write_be32(buf, prev_off + 4, new_count + next_count);
                        // Remove next record.
                        for j in ins_idx..numrecs - 1 {
                            let src = AG_BT_HDR_V5 + (j + 1) * 8;
                            let dst = AG_BT_HDR_V5 + j * 8;
                            write_be32(buf, dst, read_be32(buf, src));
                            write_be32(buf, dst + 4, read_be32(buf, src + 4));
                        }
                        write_be16(buf, 6, (numrecs - 1) as u16);
                    }
                }
                merged = true;
            }
        }
        if !merged && ins_idx < numrecs {
            let next_off = AG_BT_HDR_V5 + ins_idx * 8;
            let next_start = read_be32(buf, next_off);
            if agbno + count == next_start {
                let next_count = read_be32(buf, next_off + 4);
                write_be32(buf, next_off, agbno);
                write_be32(buf, next_off + 4, next_count + count);
                merged = true;
            }
        }
        if !merged {
            // Insert new record.
            let max_recs = (sb.block_size as usize - AG_BT_HDR_V5) / 8;
            if numrecs >= max_recs {
                return; // Leaf full (no split impl)
            }
            for j in (ins_idx..numrecs).rev() {
                let src = AG_BT_HDR_V5 + j * 8;
                let dst = AG_BT_HDR_V5 + (j + 1) * 8;
                write_be32(buf, dst, read_be32(buf, src));
                write_be32(buf, dst + 4, read_be32(buf, src + 4));
            }
            write_be32(buf, AG_BT_HDR_V5 + ins_idx * 8, agbno);
            write_be32(buf, AG_BT_HDR_V5 + ins_idx * 8 + 4, count);
            write_be16(buf, 6, (numrecs + 1) as u16);
        }

        cache_invalidate(blk_abs);
        blk.write_block(blk_abs, sb.block_size, wva);

        // Update AGF.
        agf.freeblks += count;
        let new_nr = read_be16(buf, 6) as usize;
        let mut ml = 0u32;
        for j in 0..new_nr {
            let c = read_be32(buf, AG_BT_HDR_V5 + j * 8 + 4);
            if c > ml {
                ml = c;
            }
        }
        agf.longest = ml;
        flush_agf(blk, sb, ag as u32);
        return;
    }
}

/// Allocate a new inode number from the inobt. Returns absolute inode number.
fn alloc_inode_num(blk: &BlkClient, sb: &XfsSb) -> Option<u64> {
    let n_ag = (sb.ag_count as usize).min(MAX_AG);
    let wva = unsafe { WRITE_VA };

    for ag in 0..n_ag {
        let agi = unsafe { &mut AG_I[ag] };
        if agi.freecount == 0 {
            continue;
        }

        let ag_start = (ag as u64) * (sb.ag_blocks as u64);

        // Walk inobt to leaf.
        let mut cur_agbno = agi.root;
        let mut depth = 0u32;
        loop {
            let abs_blk = ag_start + (cur_agbno as u64);
            if !blk.read_block(abs_blk, sb.block_size, wva) {
                break;
            }
            let buf = unsafe {
                core::slice::from_raw_parts_mut(wva as *mut u8, sb.block_size as usize)
            };
            let level = read_be16(buf, 4);
            let numrecs = read_be16(buf, 6) as usize;

            if level > 0 {
                if numrecs == 0 {
                    break;
                }
                // inobt key = startino(u32) = 4 bytes, ptr = agblock(u32) = 4 bytes.
                let ptr_off = AG_BT_HDR_V5 + numrecs * 4;
                if ptr_off + 4 > sb.block_size as usize {
                    break;
                }
                cur_agbno = read_be32(buf, ptr_off);
                depth += 1;
                if depth > 10 {
                    break;
                }
                continue;
            }

            // Leaf: scan for record with free inodes.
            // Record: startino(4) + holemask(2) + count(1) + freecount(1) + free(8) = 16 bytes
            for i in 0..numrecs {
                let rec_off = AG_BT_HDR_V5 + i * 16;
                if rec_off + 16 > sb.block_size as usize {
                    break;
                }
                let startino = read_be32(buf, rec_off);
                let freecount = buf[rec_off + 7];
                if freecount == 0 {
                    continue;
                }

                let free_mask = read_be64(buf, rec_off + 8);
                // Find lowest set bit (1 = free in XFS inobt).
                let mut bit = 0u32;
                while bit < 64 {
                    if (free_mask >> bit) & 1 != 0 {
                        break;
                    }
                    bit += 1;
                }
                if bit >= 64 {
                    continue;
                }

                // Clear the bit, decrement freecount.
                let new_free = free_mask & !(1u64 << bit);
                write_be64(buf, rec_off + 8, new_free);
                buf[rec_off + 7] = freecount - 1;

                cache_invalidate(abs_blk);
                blk.write_block(abs_blk, sb.block_size, wva);

                agi.freecount -= 1;
                flush_agi(blk, sb, ag as u32);

                // Compute absolute inode number.
                let ag_ino = startino + bit;
                let ino = ((ag as u64) << ((sb.agblklog + sb.inopblog) as u64))
                    | (ag_ino as u64);
                return Some(ino);
            }
            break;
        }
    }
    None
}

/// Free an inode number back to the inobt.
fn free_inode_num(blk: &BlkClient, sb: &XfsSb, ino: u64) {
    let ag = ino_ag(ino, sb) as usize;
    if ag >= (sb.ag_count as usize).min(MAX_AG) {
        return;
    }
    let agi = unsafe { &mut AG_I[ag] };
    let ag_start = (ag as u64) * (sb.ag_blocks as u64);
    let wva = unsafe { WRITE_VA };

    let ag_ino =
        (ino & ((1u64 << ((sb.agblklog + sb.inopblog) as u64)) - 1)) as u32;
    let chunk_start = ag_ino & !63;
    let bit = ag_ino & 63;

    // Walk inobt to find the chunk's record.
    let mut cur_agbno = agi.root;
    let mut depth = 0u32;
    loop {
        let abs_blk = ag_start + (cur_agbno as u64);
        if !blk.read_block(abs_blk, sb.block_size, wva) {
            return;
        }
        let buf = unsafe {
            core::slice::from_raw_parts_mut(wva as *mut u8, sb.block_size as usize)
        };
        let level = read_be16(buf, 4);
        let numrecs = read_be16(buf, 6) as usize;

        if level > 0 {
            if numrecs == 0 {
                return;
            }
            let mut child_idx = 0usize;
            for i in 1..numrecs {
                let key = read_be32(buf, AG_BT_HDR_V5 + i * 4);
                if chunk_start < key {
                    break;
                }
                child_idx = i;
            }
            let ptr_off = AG_BT_HDR_V5 + numrecs * 4 + child_idx * 4;
            if ptr_off + 4 > sb.block_size as usize {
                return;
            }
            cur_agbno = read_be32(buf, ptr_off);
            depth += 1;
            if depth > 10 {
                return;
            }
            continue;
        }

        // Leaf: find matching record.
        for i in 0..numrecs {
            let rec_off = AG_BT_HDR_V5 + i * 16;
            if rec_off + 16 > sb.block_size as usize {
                break;
            }
            let startino = read_be32(buf, rec_off);
            if startino == chunk_start {
                let freecount = buf[rec_off + 7];
                let free_mask = read_be64(buf, rec_off + 8);
                write_be64(buf, rec_off + 8, free_mask | (1u64 << bit));
                buf[rec_off + 7] = freecount + 1;

                cache_invalidate(abs_blk);
                blk.write_block(abs_blk, sb.block_size, wva);
                agi.freecount += 1;
                flush_agi(blk, sb, ag as u32);
                return;
            }
        }
        return;
    }
}

/// Initialize a new inode on disk. Returns the XfsInode.
fn init_new_inode(
    blk: &BlkClient,
    sb: &XfsSb,
    ino: u64,
    mode: u16,
    nlink: u32,
) -> Option<XfsInode> {
    let block = ino_abs_block(ino, sb);
    let off_in_blk = (ino_offset(ino, sb) as usize) * (sb.inode_size as usize);
    let wva = unsafe { WRITE_VA };

    if !blk.read_block(block, sb.block_size, wva) {
        return None;
    }

    let buf = unsafe {
        core::slice::from_raw_parts_mut(
            (wva + off_in_blk) as *mut u8,
            sb.inode_size as usize,
        )
    };

    // Zero the inode area.
    for b in buf.iter_mut() {
        *b = 0;
    }

    // Set v5 inode core.
    write_be16(buf, 0, XFS_DINODE_MAGIC);
    write_be16(buf, 2, mode);
    buf[4] = 3; // v3 (on-disk version for v5 XFS)
    buf[5] = XFS_DINODE_FMT_EXTENTS;
    write_be32(buf, 16, nlink);

    cache_invalidate(block);
    if !blk.write_block(block, sb.block_size, wva) {
        return None;
    }

    let dfork_len = (sb.inode_size as usize).saturating_sub(176).min(336);

    Some(XfsInode {
        ino,
        mode,
        uid: 0,
        gid: 0,
        size: 0,
        nlink,
        format: XFS_DINODE_FMT_EXTENTS,
        nextents: 0,
        forkoff: 0,
        nblocks: 0,
        dfork: [0u8; 336],
        dfork_len,
    })
}

/// Add an extent to an inode's dfork (format=2 extents list). In-memory only.
fn inode_add_extent(inode: &mut XfsInode, ext: &Extent) -> bool {
    let cur = inode.nextents as usize;
    let new_off = cur * 16;
    if new_off + 16 > inode.dfork_len {
        return false;
    }
    let encoded = encode_extent(ext);
    inode.dfork[new_off..new_off + 16].copy_from_slice(&encoded);
    inode.nextents += 1;
    inode.nblocks += ext.count as u64;
    true
}

/// Add a directory entry to a shortform directory.
fn dir_sf_add_entry(
    blk: &BlkClient,
    sb: &XfsSb,
    parent: &mut XfsInode,
    child_name: &[u8],
    child_ino: u64,
    ftype: u8,
) -> bool {
    if parent.format != XFS_DINODE_FMT_LOCAL {
        return false;
    }
    let d = &parent.dfork;
    let dlen = parent.dfork_len;
    if dlen < 6 {
        return false;
    }

    let count = d[0] as usize;
    let i8count = d[1] as usize;
    let use_64 = i8count > 0 || child_ino > 0xFFFF_FFFF;
    let ino_size: usize = if use_64 { 8 } else { 4 };
    let parent_size: usize = if i8count > 0 || use_64 { 8 } else { 4 };

    // Find end of current entries.
    let mut pos = 2 + parent_size;
    let total = count + i8count;
    for entry_idx in 0..total {
        if pos >= dlen {
            break;
        }
        let namelen = d[pos] as usize;
        let entry_ino_size: usize = if entry_idx < i8count { 8 } else { 4 };
        pos += 3 + namelen + 1 + entry_ino_size;
    }

    // Check space.
    let entry_size = 1 + 2 + child_name.len() + 1 + ino_size;
    if pos + entry_size > 336 {
        return false;
    }

    // Write entry into dfork.
    let d = &mut parent.dfork;
    d[pos] = child_name.len() as u8;
    d[pos + 1] = 0; // offset hi
    d[pos + 2] = 0; // offset lo
    d[pos + 3..pos + 3 + child_name.len()].copy_from_slice(child_name);
    d[pos + 3 + child_name.len()] = ftype;
    let ino_off = pos + 3 + child_name.len() + 1;
    if use_64 {
        write_be64(d, ino_off, child_ino);
    } else {
        write_be32(d, ino_off, child_ino as u32);
    }

    // Update count.
    if use_64 {
        d[1] = (i8count + 1) as u8;
    } else {
        d[0] = (count + 1) as u8;
    }

    parent.size = (pos + entry_size) as u64;
    write_inode(blk, sb, parent)
}

/// Add an entry to a block-format directory (single data block).
fn dir_block_add_entry(
    blk_client: &BlkClient,
    sb: &XfsSb,
    parent: &XfsInode,
    child_name: &[u8],
    child_ino: u64,
    ftype: u8,
) -> bool {
    if parent.dfork_len < 16 {
        return false;
    }
    let ext = decode_extent(&parent.dfork[0..16]);
    if ext.count == 0 {
        return false;
    }

    let wva = unsafe { WRITE_VA };
    let disk_blk = ext.disk_blk;

    if !blk_client.read_block(disk_blk, sb.block_size, wva) {
        return false;
    }
    let buf = unsafe {
        core::slice::from_raw_parts_mut(wva as *mut u8, sb.block_size as usize)
    };

    let bs = sb.block_size as usize;
    let raw_entry = 8 + 1 + child_name.len() + 1 + 2;
    let needed = (raw_entry + 7) & !7;
    let hdr_size = 64; // v5 data block header
    let mut pos = hdr_size;

    while pos + 8 < bs {
        let freetag = read_be16(buf, pos);
        if freetag == 0xFFFF {
            let free_len = read_be16(buf, pos + 2) as usize;
            if free_len >= needed {
                // Write the new entry here.
                write_be64(buf, pos, child_ino);
                buf[pos + 8] = child_name.len() as u8;
                buf[pos + 9..pos + 9 + child_name.len()].copy_from_slice(child_name);
                buf[pos + 9 + child_name.len()] = ftype;
                // Tag at end of entry (aligned).
                let tag_off = pos + needed - 2;
                write_be16(buf, tag_off, pos as u16);

                // Mark remaining free space.
                let remaining = free_len - needed;
                if remaining >= 8 {
                    write_be16(buf, pos + needed, 0xFFFF);
                    write_be16(buf, pos + needed + 2, remaining as u16);
                }

                cache_invalidate(disk_blk);
                return blk_client.write_block(disk_blk, sb.block_size, wva);
            }
            if free_len == 0 {
                break;
            }
            pos += free_len;
            continue;
        }

        if pos + 11 > bs {
            break;
        }
        let namelen = buf[pos + 8] as usize;
        let raw_end = 8 + 1 + namelen + 1 + 2;
        pos += (raw_end + 7) & !7;
    }

    false
}

/// Remove an entry from a shortform directory. Returns child ino on success.
fn dir_sf_remove_entry(
    blk: &BlkClient,
    sb: &XfsSb,
    parent: &mut XfsInode,
    name: &[u8],
) -> Option<u64> {
    if parent.format != XFS_DINODE_FMT_LOCAL {
        return None;
    }
    let d = &parent.dfork;
    let dlen = parent.dfork_len;
    if dlen < 6 {
        return None;
    }

    let count = d[0] as usize;
    let i8count = d[1] as usize;
    let parent_size: usize = if i8count > 0 { 8 } else { 4 };

    let mut pos = 2 + parent_size;
    let total = count + i8count;

    for entry_idx in 0..total {
        if pos >= dlen {
            break;
        }
        let namelen = d[pos] as usize;
        let entry_name_start = pos + 3;
        if entry_name_start + namelen > dlen {
            break;
        }

        let ftype_off = entry_name_start + namelen;
        let ino_off = ftype_off + 1;
        let ino_size: usize = if entry_idx < i8count { 8 } else { 4 };
        if ino_off + ino_size > dlen {
            break;
        }
        let entry_end = ino_off + ino_size;

        if namelen == name.len() && &d[entry_name_start..entry_name_start + namelen] == name {
            let child_ino = if ino_size == 8 {
                read_be64(d, ino_off)
            } else {
                read_be32(d, ino_off) as u64
            };

            // Remove by shifting.
            let entry_size = entry_end - pos;
            let d = &mut parent.dfork;
            let remaining = dlen - entry_end;
            for i in 0..remaining {
                d[pos + i] = d[entry_end + i];
            }
            for i in (pos + remaining)..dlen {
                d[i] = 0;
            }

            if entry_idx < i8count {
                d[1] = (i8count - 1) as u8;
            } else {
                d[0] = (count - 1) as u8;
            }

            parent.size = parent.size.saturating_sub(entry_size as u64);
            write_inode(blk, sb, parent);
            return Some(child_ino);
        }

        pos = entry_end;
    }
    None
}

/// Remove an entry from a block-format directory. Returns child ino on success.
fn dir_block_remove_entry(
    blk_client: &BlkClient,
    sb: &XfsSb,
    parent: &XfsInode,
    name: &[u8],
) -> Option<u64> {
    if parent.dfork_len < 16 {
        return None;
    }
    let ext = decode_extent(&parent.dfork[0..16]);
    if ext.count == 0 {
        return None;
    }

    let wva = unsafe { WRITE_VA };
    let disk_blk = ext.disk_blk;
    if !blk_client.read_block(disk_blk, sb.block_size, wva) {
        return None;
    }
    let buf = unsafe {
        core::slice::from_raw_parts_mut(wva as *mut u8, sb.block_size as usize)
    };

    let bs = sb.block_size as usize;
    let hdr_size = 64;
    let mut pos = hdr_size;

    while pos + 8 < bs {
        let freetag = read_be16(buf, pos);
        if freetag == 0xFFFF {
            let free_len = read_be16(buf, pos + 2) as usize;
            if free_len == 0 {
                break;
            }
            pos += free_len;
            continue;
        }

        if pos + 11 > bs {
            break;
        }
        let entry_ino = read_be64(buf, pos);
        let namelen = buf[pos + 8] as usize;
        let name_start = pos + 9;
        if name_start + namelen + 2 > bs {
            break;
        }

        let raw_end = 8 + 1 + namelen + 1 + 2;
        let entry_size = (raw_end + 7) & !7;

        if namelen == name.len() && &buf[name_start..name_start + namelen] == name {
            // Mark as free.
            write_be16(buf, pos, 0xFFFF);
            write_be16(buf, pos + 2, entry_size as u16);
            for i in 4..entry_size {
                if pos + i < bs {
                    buf[pos + i] = 0;
                }
            }

            cache_invalidate(disk_blk);
            blk_client.write_block(disk_blk, sb.block_size, wva);
            return Some(entry_ino);
        }

        pos += entry_size;
    }
    None
}

/// Unified: add directory entry.
fn dir_add_entry(
    blk: &BlkClient,
    sb: &XfsSb,
    parent_ino: u64,
    child_name: &[u8],
    child_ino: u64,
    ftype: u8,
) -> bool {
    let mut parent = match read_inode(blk, sb, parent_ino) {
        Some(i) => i,
        None => return false,
    };

    match parent.format {
        XFS_DINODE_FMT_LOCAL => {
            dir_sf_add_entry(blk, sb, &mut parent, child_name, child_ino, ftype)
        }
        XFS_DINODE_FMT_EXTENTS if parent.nextents >= 1 => {
            dir_block_add_entry(blk, sb, &parent, child_name, child_ino, ftype)
        }
        _ => false,
    }
}

/// Unified: remove directory entry. Returns child ino.
fn dir_remove_entry(
    blk: &BlkClient,
    sb: &XfsSb,
    parent_ino: u64,
    name: &[u8],
) -> Option<u64> {
    let mut parent = match read_inode(blk, sb, parent_ino) {
        Some(i) => i,
        None => return None,
    };

    match parent.format {
        XFS_DINODE_FMT_LOCAL => dir_sf_remove_entry(blk, sb, &mut parent, name),
        XFS_DINODE_FMT_EXTENTS if parent.nextents >= 1 => {
            dir_block_remove_entry(blk, sb, &parent, name)
        }
        _ => None,
    }
}

/// Free all data blocks referenced by an inode's extents.
fn free_inode_blocks(blk: &BlkClient, sb: &XfsSb, inode: &XfsInode) {
    if inode.format != XFS_DINODE_FMT_EXTENTS {
        return;
    }
    let nrecs = inode.nextents as usize;
    let max_recs = inode.dfork_len / 16;
    for i in 0..nrecs.min(max_recs) {
        let off = i * 16;
        if off + 16 > inode.dfork_len {
            break;
        }
        let ext = decode_extent(&inode.dfork[off..]);
        if ext.count > 0 && ext.disk_blk != 0 {
            free_blocks(blk, sb, ext.disk_blk, ext.count);
        }
    }
}

// =====================================================================
// Main server
// =====================================================================

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [xfs_srv] starting\n");

    // Partition byte offset from arg0 (default 32 MiB).
    let partition_offset = if arg0 != 0 { arg0 } else { 32 * 1024 * 1024 };

    syscall::debug_puts(b"  [xfs_srv] partition offset=");
    print_num(partition_offset);
    syscall::debug_puts(b"\n");

    // Create port and register with name server.
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"xfs", port);
    syscall::ns_register(b"xfs_task", my_aspace);

    // Look up cache_blk with bounded retry.  Use nanosleep instead of
    // yield_now so the thread truly sleeps, giving CPU time for cache_srv
    // to start (yield_now completes too fast under CPU contention).
    let blk_port = {
        let mut retries = 200u32;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [xfs_srv] cache_blk not found, exiting\n");
                syscall::exit(1);
            }
            syscall::nanosleep(10_000_000); // 10ms per retry, ~2s total
        }
    };

    // Connect to blk_srv via cache.
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
            syscall::debug_puts(b"  [xfs_srv] blk connect FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    } else {
        syscall::debug_puts(b"  [xfs_srv] blk no reply\n");
        syscall::exit(1);
        unreachable!()
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [xfs_srv] scratch alloc FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_3000,
        partition_offset,
        nonce: Cell::new(0),
    };

    // Permanent grant of `scratch_va` into cache_blk's aspace at grant_va.
    // The nonce protocol (see BlkClient::recv_match) makes stale-reply
    // corruption impossible, so per-request grant/revoke is no longer needed.
    if !syscall::grant_pages(blk.blk_aspace, blk.scratch_va, blk.grant_va, 1, false) {
        syscall::debug_puts(b"  [xfs_srv] permanent grant FAILED\n");
        loop { syscall::nanosleep(1_000_000_000_000); }
    }

    // Initialize block cache.
    cache_init();

    // Allocate scratch page for write operations (Phase C).
    match syscall::mmap_anon(0, 1, 1) {
        Some(va) => unsafe {
            WRITE_VA = va;
        },
        None => {
            syscall::debug_puts(b"  [xfs_srv] write scratch alloc FAILED\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    }

    // Read superblock (sector 0).
    syscall::debug_puts(b"  [xfs_srv] reading superblock at partition offset ");
    print_num(partition_offset);
    syscall::debug_puts(b" blk_port=");
    print_num(blk_port);
    syscall::debug_puts(b" blk_aspace=");
    print_num(blk_aspace);
    syscall::debug_puts(b"\n");

    let mut sb_buf = [0u8; 512];
    // Retry reads — cache_blk may not be fully ready yet.
    let mut read_ok = false;
    for _ in 0..20 {
        if blk.read_bytes(0, &mut sb_buf) {
            if read_be32(&sb_buf, 0) == XFS_SB_MAGIC {
                read_ok = true;
                break;
            }
        }
        for _ in 0..100 {
            syscall::yield_now();
        }
    }
    if !read_ok {
        syscall::debug_puts(b"  [xfs_srv] failed to read superblock (no XFS found)\n");
        loop { syscall::nanosleep(1_000_000_000_000); }
    }

    // Debug: dump first 8 bytes to see what we got.
    syscall::debug_puts(b"  [xfs_srv] first 8 bytes: ");
    for i in 0..8 {
        print_hex(sb_buf[i] as u64);
        syscall::debug_puts(b" ");
    }
    syscall::debug_puts(b"\n");

    let sb = match parse_superblock(&sb_buf) {
        Some(s) => s,
        None => {
            syscall::debug_puts(b"  [xfs_srv] invalid superblock\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    };

    syscall::debug_puts(b"  [xfs_srv] XFS: block_size=");
    print_num(sb.block_size as u64);
    syscall::debug_puts(b" ag_count=");
    print_num(sb.ag_count as u64);
    syscall::debug_puts(b" ag_blocks=");
    print_num(sb.ag_blocks as u64);
    syscall::debug_puts(b" root_ino=");
    print_num(sb.root_ino);
    syscall::debug_puts(b" inode_size=");
    print_num(sb.inode_size as u64);
    syscall::debug_puts(b" inopblog=");
    print_num(sb.inopblog as u64);
    syscall::debug_puts(b" agblklog=");
    print_num(sb.agblklog as u64);
    syscall::debug_puts(b"\n");

    // Read AG headers.
    init_ag_headers(&blk, &sb);

    // Verify root inode (retry on transient I/O failure during boot).
    {
        let mut root_ok = false;
        for attempt in 0..5u32 {
            if let Some(root) = read_inode(&blk, &sb, sb.root_ino) {
                syscall::debug_puts(b"  [xfs_srv] root inode: mode=");
                print_hex(root.mode as u64);
                syscall::debug_puts(b" format=");
                print_num(root.format as u64);
                syscall::debug_puts(b" size=");
                print_num(root.size);
                syscall::debug_puts(b"\n");
                root_ok = true;
                break;
            }
            if attempt < 4 {
                syscall::nanosleep(50_000_000); // 50ms backoff
            }
        }
        if !root_ok {
            syscall::debug_puts(b"  [xfs_srv] failed to read root inode\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    }

    syscall::debug_puts(b"  [xfs_srv] ready\n");

    // Open file table.
    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    // Server loop.
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

                if let Some(inode) = path_resolve(&blk, &sb, name) {
                    let mut handle = u64::MAX;
                    for (i, h) in handles.iter_mut().enumerate() {
                        if !h.active {
                            h.active = true;
                            h.inode = inode;
                            h.pid = caller_pid;
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
                            inode.size,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
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

                if let Some(inode) = path_resolve(&blk, &sb, &name[..nlen]) {
                    let mut handle = u64::MAX;
                    for (i, h) in handles.iter_mut().enumerate() {
                        if !h.active {
                            h.active = true;
                            h.inode = inode;
                            h.pid = caller_pid;
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
                            inode.size,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    handles[handle].active = false;
                }
                let _ = syscall::reply(FS_CLOSE_OK, 0, 0, 0, 0, 0);
            }

            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1];
                let length = (msg.data[2] & 0xFFFF_FFFF) as u32;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle].inode;
                if offset >= inode.size {
                    let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                    continue;
                }

                let avail = inode.size - offset;
                let to_read = (length as u64).min(avail) as usize;
                let mut total_read = 0usize;

                if grant_va != 0 {
                    // Grant-based: loop over blocks, copy data to grant VA.
                    while total_read < to_read {
                        let cur_off = offset + (total_read as u64);
                        let logical_blk = cur_off / (sb.block_size as u64);
                        let off_in_blk = (cur_off % (sb.block_size as u64)) as usize;
                        let chunk =
                            (to_read - total_read).min(sb.block_size as usize - off_in_blk);

                        match resolve_block(&blk, &sb, inode, logical_blk) {
                            Some(abs_blk) => {
                                if let Some(data_va) =
                                    cache_read(&blk, abs_blk, sb.block_size)
                                {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (data_va + off_in_blk) as *const u8,
                                            (grant_va + total_read) as *mut u8,
                                            chunk,
                                        );
                                    }
                                    total_read += chunk;
                                } else {
                                    break;
                                }
                            }
                            None => {
                                unsafe {
                                    core::ptr::write_bytes(
                                        (grant_va + total_read) as *mut u8,
                                        0,
                                        chunk,
                                    );
                                }
                                total_read += chunk;
                            }
                        }
                    }
                    let _ = syscall::reply(FS_READ_OK, total_read as u64, 0, 0, 0, 0);
                } else {
                    // Inline: read first block only.
                    let logical_blk = offset / (sb.block_size as u64);
                    let off_in_blk = (offset % (sb.block_size as u64)) as usize;
                    let chunk = to_read.min(sb.block_size as usize - off_in_blk);

                    match resolve_block(&blk, &sb, inode, logical_blk) {
                        Some(abs_blk) => {
                            if let Some(data_va) = cache_read(&blk, abs_blk, sb.block_size) {
                                let inline_len = chunk.min(MAX_INLINE);
                                let data = unsafe {
                                    core::slice::from_raw_parts(
                                        (data_va + off_in_blk) as *const u8,
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
                            } else {
                                let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                            }
                        }
                        None => {
                            // Sparse hole: return zeros.
                            let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                        }
                    }
                }
            }

            FS_READDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let start_offset = msg.data[3] as u32;

                let dir_inode = if name_len == 0 {
                    read_inode(&blk, &sb, sb.root_ino)
                } else {
                    let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                    let name = &name_buf[..name_len.min(16)];
                    path_resolve(&blk, &sb, name)
                };

                let dir_inode = match dir_inode {
                    Some(i) if i.is_dir() => i,
                    _ => {
                        let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                        continue;
                    }
                };

                match dir_next(&blk, &sb, &dir_inode, start_offset) {
                    Some((child_ino, name_buf, name_len, next_offset)) => {
                        // Get child file size.
                        let file_size = if let Some(child) = read_inode(&blk, &sb, child_ino) {
                            child.size
                        } else {
                            0
                        };

                        let mut name_lo = 0u64;
                        let mut name_hi = 0u64;
                        for i in 0..name_len.min(8) {
                            name_lo |= (name_buf[i] as u64) << (i * 8);
                        }
                        for i in 8..name_len.min(16) {
                            name_hi |= (name_buf[i] as u64) << ((i - 8) * 8);
                        }

                        let _ = syscall::reply(
                            FS_READDIR_OK,
                            file_size,
                            name_lo,
                            name_hi,
                            next_offset as u64,
                            0,
                        );
                    }
                    None => {
                        let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                    }
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle].inode;
                let uid_gid = (inode.uid as u64) | ((inode.gid as u64) << 16);
                let _ = syscall::reply(
                    FS_STAT_OK,
                    inode.size,
                    inode.mode as u64,
                    uid_gid,
                    inode.ino,
                    0,
                );
            }

            FS_STAT_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;

                let mut name = [0u8; 256];
                let nlen = name_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some(inode) = path_resolve(&blk, &sb, &name[..nlen]) {
                    let uid_gid = (inode.uid as u64) | ((inode.gid as u64) << 16);
                    let _ = syscall::reply(
                        FS_STAT_OK,
                        inode.size,
                        inode.mode as u64,
                        uid_gid,
                        inode.ino,
                        0,
                    );
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_READLINK => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(inode) = path_resolve(&blk, &sb, name) {
                    if inode.is_symlink() {
                        let mut target = [0u8; 256];
                        let tlen = read_symlink_target(&blk, &sb, &inode, &mut target);
                        let packed = pack_inline_data(&target[..tlen.min(MAX_INLINE)]);
                        let _ = syscall::reply(
                            FS_READLINK_OK,
                            tlen as u64,
                            packed[0],
                            packed[1],
                            packed[2],
                            0,
                        );
                    } else {
                        let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let mut total_free = 0u64;
                let n = (sb.ag_count as usize).min(MAX_AG);
                for i in 0..n {
                    total_free += unsafe { AG_F[i].freeblks } as u64;
                }
                let total_blocks = sb.dblocks;
                let used = total_blocks.saturating_sub(total_free);
                let _ = syscall::reply(
                    FS_STATFS_OK,
                    used,
                    total_free,
                    sb.block_size as u64,
                    0,
                    0,
                );
            }

            // --- Write operations (Phase C) ---

            FS_CREATE | FS_MKNOD => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Allocate inode.
                let ino = match alloc_inode_num(&blk, &sb) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Initialize inode as regular file.
                let new_inode = match init_new_inode(&blk, &sb, ino, 0o100644, 1) {
                    Some(i) => i,
                    None => {
                        free_inode_num(&blk, &sb, ino);
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Add to root directory.
                if !dir_add_entry(&blk, &sb, sb.root_ino, name, ino, 1) {
                    free_inode_num(&blk, &sb, ino);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                // Allocate a handle.
                let mut handle = u64::MAX;
                for (i, h) in handles.iter_mut().enumerate() {
                    if !h.active {
                        h.active = true;
                        h.inode = new_inode;
                        h.pid = caller_pid;
                        handle = i as u64;
                        break;
                    }
                }
                if handle == u64::MAX {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(
                        FS_CREATE_OK,
                        handle,
                        0,
                        my_aspace as u64,
                        0,
                        0,
                    );
                }
            }

            FS_MKDIR => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let mode = ((msg.data[2] >> 16) & 0xFFFF) as u16;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let ino = match alloc_inode_num(&blk, &sb) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                let dir_mode = S_IFDIR | (mode & 0o7777);
                let mut new_dir = match init_new_inode(&blk, &sb, ino, dir_mode, 2) {
                    Some(i) => i,
                    None => {
                        free_inode_num(&blk, &sb, ino);
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Set up as shortform directory with ".." pointing to root.
                new_dir.format = XFS_DINODE_FMT_LOCAL;
                new_dir.dfork[0] = 0; // count
                new_dir.dfork[1] = 0; // i8count
                write_be32(&mut new_dir.dfork, 2, sb.root_ino as u32);
                new_dir.size = 6;
                write_inode(&blk, &sb, &new_dir);

                if !dir_add_entry(&blk, &sb, sb.root_ino, name, ino, 2) {
                    free_inode_num(&blk, &sb, ino);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                let _ = syscall::reply(FS_MKDIR_OK, 0, 0, 0, 0, 0);
            }

            FS_WRITE => {
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let bs = sb.block_size as usize;
                let mut written = 0usize;
                let mut offset = handles[handle].inode.size;

                while written < length {
                    let logical_blk = offset / (sb.block_size as u64);
                    let off_in_blk = (offset % (sb.block_size as u64)) as usize;
                    let space = bs - off_in_blk;
                    let chunk = (length - written).min(space);

                    // Resolve or allocate the physical block.
                    let phys = match resolve_block(
                        &blk,
                        &sb,
                        &handles[handle].inode,
                        logical_blk,
                    ) {
                        Some(b) => b,
                        None => {
                            // Allocate a new block.
                            match alloc_blocks(&blk, &sb, 1) {
                                Some(abs_blk) => {
                                    // Add extent to inode.
                                    let ext = Extent {
                                        file_off: logical_blk,
                                        disk_blk: abs_blk,
                                        count: 1,
                                    };
                                    if !inode_add_extent(
                                        &mut handles[handle].inode,
                                        &ext,
                                    ) {
                                        free_blocks(&blk, &sb, abs_blk, 1);
                                        break;
                                    }
                                    abs_blk
                                }
                                None => break,
                            }
                        }
                    };

                    let wva = unsafe { WRITE_VA };

                    // Read-modify-write for partial blocks; zero for new full blocks.
                    if off_in_blk != 0 || chunk < bs {
                        if !blk.read_block(phys, sb.block_size, wva) {
                            break;
                        }
                    } else {
                        unsafe {
                            core::ptr::write_bytes(wva as *mut u8, 0, bs);
                        }
                    }

                    // Copy data from grant page.
                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (grant_va + written) as *const u8,
                                (wva + off_in_blk) as *mut u8,
                                chunk,
                            );
                        }
                    }

                    cache_invalidate(phys);
                    if !blk.write_block(phys, sb.block_size, wva) {
                        break;
                    }

                    written += chunk;
                    offset += chunk as u64;
                }

                // Update file size and flush inode.
                handles[handle].inode.size = offset;
                write_inode(&blk, &sb, &handles[handle].inode);

                let _ = syscall::reply(FS_WRITE_OK, written as u64, 0, 0, 0, 0);
            }

            FS_DELETE | FS_UNLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Look up the file.
                let root = match read_inode(&blk, &sb, sb.root_ino) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };
                let child_ino = match dir_lookup(&blk, &sb, &root, name) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                        continue;
                    }
                };
                let child = match read_inode(&blk, &sb, child_ino) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Free data blocks.
                free_inode_blocks(&blk, &sb, &child);

                // Remove directory entry.
                dir_remove_entry(&blk, &sb, sb.root_ino, name);

                // Free inode.
                free_inode_num(&blk, &sb, child_ino);

                // Zero inode on disk.
                let mut zeroed = child;
                zeroed.mode = 0;
                zeroed.nlink = 0;
                zeroed.size = 0;
                zeroed.nblocks = 0;
                zeroed.nextents = 0;
                zeroed.dfork = [0u8; 336];
                write_inode(&blk, &sb, &zeroed);

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

                if let Some(mut inode) = path_resolve(&blk, &sb, &name[..nlen]) {
                    inode.mode = (inode.mode & 0xF000) | (mode & 0x0FFF);
                    write_inode(&blk, &sb, &inode);
                    let _ = syscall::reply(FS_CHMOD_OK, 0, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_UTIMENS => {
                let _ = syscall::reply(FS_UTIMENS_OK, 0, 0, 0, 0, 0);
            }

            FS_CHOWN => {
                let path_len = (msg.data[0] & 0xFFFF) as usize;
                let uid = ((msg.data[0] >> 16) & 0xFFFF) as u32;
                let gid = msg.data[1] as u32;

                let mut name = [0u8; 256];
                let nlen = path_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some(mut inode) = path_resolve(&blk, &sb, &name[..nlen]) {
                    inode.uid = uid;
                    inode.gid = gid;
                    write_inode(&blk, &sb, &inode);
                    let _ = syscall::reply(FS_CHOWN_OK, 0, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_TRUNCATE => {
                let handle_lo = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let new_size = msg.data[1];

                if handle_lo >= MAX_OPEN || !handles[handle_lo].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let inode = &mut handles[handle_lo].inode;
                if new_size < inode.size {
                    if new_size == 0 {
                        free_inode_blocks(&blk, &sb, inode);
                        inode.nextents = 0;
                        inode.nblocks = 0;
                        inode.dfork = [0u8; 336];
                    }
                }
                inode.size = new_size;
                write_inode(&blk, &sb, inode);
                let _ = syscall::reply(FS_TRUNCATE_OK, 0, 0, 0, 0, 0);
            }

            FS_SYMLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Extract target from data[3] (up to 8 bytes, null-terminated).
                let target_word = msg.data[3];
                let mut target = [0u8; 8];
                let mut target_len = 0usize;
                for i in 0..8 {
                    let b = (target_word >> (i * 8)) as u8;
                    if b == 0 { break; }
                    target[i] = b;
                    target_len += 1;
                }

                if target_len == 0 {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                // Allocate inode.
                let ino = match alloc_inode_num(&blk, &sb) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Initialize as symlink inode: S_IFLNK | 0o777, format=LOCAL.
                let mut sym_inode = match init_new_inode(&blk, &sb, ino, S_IFLNK | 0o0777, 1) {
                    Some(i) => i,
                    None => {
                        free_inode_num(&blk, &sb, ino);
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Store target inline in dfork.
                sym_inode.format = XFS_DINODE_FMT_LOCAL;
                for i in 0..target_len {
                    sym_inode.dfork[i] = target[i];
                }
                sym_inode.size = target_len as u64;
                write_inode(&blk, &sb, &sym_inode);

                // Add directory entry with ftype=7 (symlink).
                if !dir_add_entry(&blk, &sb, sb.root_ino, name, ino, 7) {
                    free_inode_num(&blk, &sb, ino);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                let _ = syscall::reply(FS_SYMLINK_OK, 0, 0, 0, 0, 0);
            }

            FS_LINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Extract new link name from data[3] (up to 8 bytes, null-terminated).
                let new_word = msg.data[3];
                let mut new_name = [0u8; 8];
                let mut new_nlen = 0usize;
                for i in 0..8 {
                    let b = (new_word >> (i * 8)) as u8;
                    if b == 0 { break; }
                    new_name[i] = b;
                    new_nlen += 1;
                }

                // Look up existing file by name in root directory.
                let root_inode = match read_inode(&blk, &sb, sb.root_ino) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                let target_ino = match dir_lookup(&blk, &sb, &root_inode, name) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Read target inode, increment nlink, write back.
                let mut target_inode = match read_inode(&blk, &sb, target_ino) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };
                target_inode.nlink += 1;
                write_inode(&blk, &sb, &target_inode);

                // Determine ftype from mode.
                let ftype = match target_inode.mode & S_IFMT {
                    S_IFDIR => 2u8,
                    S_IFLNK => 7u8,
                    _ => 1u8, // regular
                };

                // Add new directory entry pointing to same inode.
                if !dir_add_entry(&blk, &sb, sb.root_ino, &new_name[..new_nlen], target_ino, ftype) {
                    // Rollback nlink.
                    target_inode.nlink -= 1;
                    write_inode(&blk, &sb, &target_inode);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                let _ = syscall::reply(FS_LINK_OK, 0, 0, 0, 0, 0);
            }

            FS_RENAME => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let old_name = &name_buf[..name_len.min(16)];

                // Extract new name from data[3] (up to 8 bytes, null-terminated).
                let new_word = msg.data[3];
                let mut new_name = [0u8; 8];
                let mut new_nlen = 0usize;
                for i in 0..8 {
                    let b = (new_word >> (i * 8)) as u8;
                    if b == 0 { break; }
                    new_name[i] = b;
                    new_nlen += 1;
                }

                // Look up old name to get inode number.
                let root_inode = match read_inode(&blk, &sb, sb.root_ino) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                let ino = match dir_lookup(&blk, &sb, &root_inode, old_name) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Get ftype from inode.
                let target_inode = match read_inode(&blk, &sb, ino) {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };
                let ftype = match target_inode.mode & S_IFMT {
                    S_IFDIR => 2u8,
                    S_IFLNK => 7u8,
                    _ => 1u8,
                };

                // Remove old entry, add new entry with same inode.
                if dir_remove_entry(&blk, &sb, sb.root_ino, old_name).is_none() {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                    continue;
                }

                if !dir_add_entry(&blk, &sb, sb.root_ino, &new_name[..new_nlen], ino, ftype) {
                    // Try to re-add old entry on failure.
                    dir_add_entry(&blk, &sb, sb.root_ino, old_name, ino, ftype);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                let _ = syscall::reply(FS_RENAME_OK, 0, 0, 0, 0, 0);
            }

            _ => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }
    }
}
