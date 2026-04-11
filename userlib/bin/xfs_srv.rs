#![no_std]
#![no_main]

//! XFS v5 filesystem server.
//!
//! Pure userspace process that reads an XFS partition from cache_blk via IPC.
//! The XFS partition starts at a byte offset passed as arg0 (default 32 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE and write ops.

extern crate userlib;

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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

#[allow(dead_code)]
fn write_be16(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = (val >> 8) as u8;
    buf[off + 1] = val as u8;
}

#[allow(dead_code)]
fn write_be32(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = (val >> 24) as u8;
    buf[off + 1] = (val >> 16) as u8;
    buf[off + 2] = (val >> 8) as u8;
    buf[off + 3] = val as u8;
}

#[allow(dead_code)]
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
}

impl BlkClient {
    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let abs_off = self.partition_offset + off;
        let sector = abs_off / 512;
        let offset_in_sector = (abs_off % 512) as usize;

        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }

        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_READ,
            0,
            sector * 512,
            d2,
            self.grant_va as u64,
        );

        let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
            if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                let copy_len = out.len().min(512 - offset_in_sector);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (self.scratch_va + offset_in_sector) as *const u8,
                        out.as_mut_ptr(),
                        copy_len,
                    );
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        syscall::revoke(self.blk_aspace, self.grant_va);
        ok
    }

    /// Read a full block (block_size bytes) into memory at `dest` VA.
    fn read_block(&self, block_num: u64, block_size: u32, dest: usize) -> bool {
        let byte_off = block_num * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = block_size / 512;

        for s in 0..sectors {
            if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
                return false;
            }
            let sector_byte = abs_off + (s as u64) * 512;
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(
                self.blk_port,
                IO_READ,
                0,
                sector_byte,
                d2,
                self.grant_va as u64,
            );

            let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
                if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.scratch_va as *const u8,
                            (dest + (s as usize) * 512) as *mut u8,
                            512,
                        );
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };

            syscall::revoke(self.blk_aspace, self.grant_va);
            if !ok {
                return false;
            }
        }
        true
    }

    /// Write a full block from memory at `src` VA.
    #[allow(dead_code)]
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
            if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
                return false;
            }
            let sector_byte = abs_off + (s as u64) * 512;
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(
                self.blk_port,
                IO_WRITE,
                0,
                sector_byte,
                d2,
                self.grant_va as u64,
            );
            let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
                rr.tag == IO_WRITE_OK
            } else {
                false
            };
            syscall::revoke(self.blk_aspace, self.grant_va);
            if !ok {
                return false;
            }
        }
        true
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
            loop {
                core::hint::spin_loop();
            }
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

    // Look up cache_blk with bounded retry.
    let blk_port = {
        let mut retries = 2000;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [xfs_srv] cache_blk not found, exiting\n");
                syscall::exit(1);
            }
            for _ in 0..50 {
                syscall::yield_now();
            }
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
            loop {
                core::hint::spin_loop();
            }
        }
    } else {
        syscall::debug_puts(b"  [xfs_srv] blk no reply\n");
        loop {
            core::hint::spin_loop();
        }
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [xfs_srv] scratch alloc FAILED\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_0000,
        partition_offset,
    };

    // Initialize block cache.
    cache_init();

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
        syscall::exit(1);
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
            loop {
                core::hint::spin_loop();
            }
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

    // Verify root inode.
    if let Some(root) = read_inode(&blk, &sb, sb.root_ino) {
        syscall::debug_puts(b"  [xfs_srv] root inode: mode=");
        print_hex(root.mode as u64);
        syscall::debug_puts(b" format=");
        print_num(root.format as u64);
        syscall::debug_puts(b" size=");
        print_num(root.size);
        syscall::debug_puts(b"\n");
    } else {
        syscall::debug_puts(b"  [xfs_srv] failed to read root inode\n");
        loop {
            core::hint::spin_loop();
        }
    }

    syscall::debug_puts(b"  [xfs_srv] ready\n");

    // Open file table.
    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
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
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    } else {
                        syscall::send(
                            reply_port,
                            FS_OPEN_OK,
                            handle,
                            inode.size,
                            my_aspace as u64,
                            0,
                        );
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_OPEN_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;
                let _flags = ((msg.data[0] >> 16) & 0xFFFF) as u32;
                let reply_port = msg.data[0] >> 32;
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
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    } else {
                        syscall::send(
                            reply_port,
                            FS_OPEN_OK,
                            handle,
                            inode.size,
                            my_aspace as u64,
                            0,
                        );
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    handles[handle].active = false;
                }
            }

            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1];
                let length = (msg.data[2] & 0xFFFF_FFFF) as u32;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle].inode;
                if offset >= inode.size {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
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
                    syscall::send_nb(reply_port, FS_READ_OK, total_read as u64, 0);
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
                                syscall::send(
                                    reply_port,
                                    FS_READ_OK,
                                    inline_len as u64,
                                    packed[0],
                                    packed[1],
                                    packed[2],
                                );
                            } else {
                                syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                            }
                        }
                        None => {
                            // Sparse hole: return zeros.
                            syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                        }
                    }
                }
            }

            FS_READDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
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
                        syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
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

                        syscall::send(
                            reply_port,
                            FS_READDIR_OK,
                            file_size,
                            name_lo,
                            name_hi,
                            next_offset as u64,
                        );
                    }
                    None => {
                        syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                    }
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle].inode;
                let uid_gid = (inode.uid as u64) | ((inode.gid as u64) << 16);
                syscall::send(
                    reply_port,
                    FS_STAT_OK,
                    inode.size,
                    inode.mode as u64,
                    uid_gid,
                    inode.ino,
                );
            }

            FS_STAT_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;
                let reply_port = msg.data[0] >> 32;

                let mut name = [0u8; 256];
                let nlen = name_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some(inode) = path_resolve(&blk, &sb, &name[..nlen]) {
                    let uid_gid = (inode.uid as u64) | ((inode.gid as u64) << 16);
                    syscall::send(
                        reply_port,
                        FS_STAT_OK,
                        inode.size,
                        inode.mode as u64,
                        uid_gid,
                        inode.ino,
                    );
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_READLINK => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(inode) = path_resolve(&blk, &sb, name) {
                    if inode.is_symlink() {
                        let mut target = [0u8; 256];
                        let tlen = read_symlink_target(&blk, &sb, &inode, &mut target);
                        let packed = pack_inline_data(&target[..tlen.min(MAX_INLINE)]);
                        syscall::send(
                            reply_port,
                            FS_READLINK_OK,
                            tlen as u64,
                            packed[0],
                            packed[1],
                            packed[2],
                        );
                    } else {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let reply_port = msg.data[0] >> 32;
                let mut total_free = 0u64;
                let n = (sb.ag_count as usize).min(MAX_AG);
                for i in 0..n {
                    total_free += unsafe { AG_F[i].freeblks } as u64;
                }
                let total_blocks = sb.dblocks;
                let used = total_blocks.saturating_sub(total_free);
                syscall::send(
                    reply_port,
                    FS_STATFS_OK,
                    used,
                    total_free,
                    sb.block_size as u64,
                    0,
                );
            }

            // --- Write operations (stubs for Phase C, return ERR_INVALID for now) ---
            FS_CREATE | FS_MKDIR | FS_MKNOD => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_WRITE => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_DELETE | FS_UNLINK => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_CHMOD => {
                let reply_port = msg.data[0] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_UTIMENS => {
                let reply_port = msg.data[0] >> 32;
                // No-op success for timestamps.
                syscall::send(reply_port, FS_UTIMENS_OK, 0, 0, 0, 0);
            }

            FS_SYMLINK | FS_LINK | FS_RENAME => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_CHOWN => {
                let reply_port = msg.data[0] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_TRUNCATE => {
                let reply_port = msg.data[0] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            _ => {
                // Unknown tag — ignore.
            }
        }
    }
}
