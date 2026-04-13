#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: linux-apfs-rw (by Ernesto A. Fernandez), apfsprogs

//! APFS read-write filesystem server.
//!
//! Pure userspace process that reads/writes an APFS partition via cache_blk IPC.
//! The APFS partition starts at a byte offset passed as arg0 (default 336 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE / FS_READLINK
//! and write ops: FS_CREATE / FS_WRITE / FS_MKDIR / FS_DELETE / FS_RENAME / etc.

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
const FS_FSYNC: u64 = 0x2B00;
const FS_FSYNC_OK: u64 = 0x2B01;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

/// VFS grants its scratch page here for long-path lookups.
const VFS_LONG_PATH_SCRATCH_VA: usize = 0x5_0000_0000;

const MAX_OPEN: usize = 16;
const MAX_INLINE: usize = 24;
const PAGE_SIZE: usize = 4096;

// --- APFS on-disk constants ---
const NX_MAGIC: u32 = 0x4253584E; // 'NXSB' little-endian = bytes 'N','X','S','B'
const APFS_MAGIC: u32 = 0x42535041; // 'APSB' little-endian = bytes 'A','P','S','B'

// Object header size: o_cksum(8) + o_oid(8) + o_xid(8) + o_type(4) + o_subtype(4) = 32
const OBJ_PHYS_SIZE: usize = 32;

// Object type constants
const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x00000001;
const OBJECT_TYPE_BTREE: u32 = 0x00000002;
const OBJECT_TYPE_BTREE_NODE: u32 = 0x00000003;
const OBJECT_TYPE_OMAP: u32 = 0x0000000b;

// Storage type masks
const OBJ_STORAGETYPE_MASK: u32 = 0xc0000000;
const OBJ_PHYSICAL: u32 = 0x40000000;
const OBJ_EPHEMERAL: u32 = 0x80000000;
const OBJECT_TYPE_MASK: u32 = 0x0000ffff;

// B-tree node header: after obj_phys_t
const BTN_FLAGS_OFF: usize = OBJ_PHYS_SIZE;      // u16
const BTN_LEVEL_OFF: usize = OBJ_PHYS_SIZE + 2;  // u16
const BTN_NKEYS_OFF: usize = OBJ_PHYS_SIZE + 4;  // u32
const BTN_TOC_OFF: usize = OBJ_PHYS_SIZE + 8;    // nloc_t (off u16, len u16)
const BTN_FREE_OFF: usize = OBJ_PHYS_SIZE + 12;  // nloc_t
const BTN_KEY_FREE_OFF: usize = OBJ_PHYS_SIZE + 16; // nloc_t
const BTN_VAL_FREE_OFF: usize = OBJ_PHYS_SIZE + 20; // nloc_t
const BTN_DATA_OFF: usize = OBJ_PHYS_SIZE + 24;  // 56 bytes total

// B-tree node flags
const BTNODE_ROOT: u16 = 0x0001;
const BTNODE_LEAF: u16 = 0x0002;
const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;

// btree_info_t size: btree_info_fixed_t(16) + bt_longest_key(4) + bt_longest_val(4) + bt_key_count(8) + bt_node_count(8) = 40
const BTREE_INFO_SIZE: usize = 40;

// B-tree flags
const BTREE_PHYSICAL: u32 = 0x00000010;

// APFS file-system record types (top 4 bits of obj_id_and_type)
const APFS_TYPE_INODE: u8 = 3;
const APFS_TYPE_XATTR: u8 = 4;
const APFS_TYPE_FILE_EXTENT: u8 = 8;
const APFS_TYPE_DIR_REC: u8 = 9;

// Key masks
const OBJ_ID_MASK: u64 = 0x0fffffffffffffffu64;
const OBJ_TYPE_MASK: u64 = 0xf000000000000000u64;
const OBJ_TYPE_SHIFT: u32 = 60;

// Inode constants
const ROOT_DIR_INO_NUM: u64 = 2;

// Inode extended field types
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const INO_EXT_TYPE_NAME: u8 = 4;

// File modes
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

// Directory entry file types (from flags & DREC_TYPE_MASK)
const DREC_TYPE_MASK: u16 = 0x000F;
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
const DT_LNK: u16 = 10;

// xattr flags
const XATTR_DATA_EMBEDDED: u16 = 0x0002;

// Block cache
const CACHE_SLOTS: usize = 64;

// j_inode_val_t offsets (relative to start of value)
const IVAL_PARENT_ID: usize = 0;
const IVAL_PRIVATE_ID: usize = 8;
const IVAL_CREATE_TIME: usize = 16;
const IVAL_MOD_TIME: usize = 24;
const IVAL_CHANGE_TIME: usize = 32;
const IVAL_ACCESS_TIME: usize = 40;
const IVAL_INTERNAL_FLAGS: usize = 48;
const IVAL_NCHILDREN_NLINK: usize = 56; // union: nchildren(i32) or nlink(i32)
const IVAL_DEFAULT_PROT_CLASS: usize = 60;
const IVAL_WRITE_GEN_COUNTER: usize = 64;
const IVAL_BSD_FLAGS: usize = 68;
const IVAL_OWNER: usize = 72;
const IVAL_GROUP: usize = 76;
const IVAL_MODE: usize = 80;
const IVAL_PAD1: usize = 82;
const IVAL_UNCOMPRESSED_SIZE: usize = 84;
const IVAL_XFIELDS: usize = 92; // xfields[] starts here

// j_dstream_t offsets (40 bytes)
const DSTREAM_SIZE: usize = 0;
const DSTREAM_ALLOCED_SIZE: usize = 8;

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

// --- Little-endian read helpers (APFS is little-endian on disk) ---

fn read_le16(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

fn read_le32(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

fn read_le64(buf: &[u8], off: usize) -> u64 {
    (buf[off] as u64)
        | ((buf[off + 1] as u64) << 8)
        | ((buf[off + 2] as u64) << 16)
        | ((buf[off + 3] as u64) << 24)
        | ((buf[off + 4] as u64) << 32)
        | ((buf[off + 5] as u64) << 40)
        | ((buf[off + 6] as u64) << 48)
        | ((buf[off + 7] as u64) << 56)
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
// Fletcher-64 checksum (APFS uses this for all object headers)
// =====================================================================

fn fletcher64(data: &[u8]) -> u64 {
    // APFS Fletcher-64: checksum field (first 8 bytes) must be zeroed before
    // computing. We process 32-bit LE words starting at byte 0.
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    let nwords = data.len() / 4;
    for i in 0..nwords {
        let word = read_le32(data, i * 4) as u64;
        sum1 = (sum1 + word) % 0xFFFFFFFF;
        sum2 = (sum2 + sum1) % 0xFFFFFFFF;
    }
    let ck1 = 0xFFFFFFFF - ((sum1 + sum2) % 0xFFFFFFFF);
    let ck2 = 0xFFFFFFFF - ((sum1 + ck1) % 0xFFFFFFFF);
    (ck2 << 32) | ck1
}

/// Verify Fletcher-64 checksum of an object block.
fn verify_checksum(block_va: usize, block_size: u32) -> bool {
    let buf = unsafe {
        core::slice::from_raw_parts(block_va as *const u8, block_size as usize)
    };
    let stored = read_le64(buf, 0);
    // Zero the checksum field for computation.
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    let nwords = buf.len() / 4;
    for i in 0..nwords {
        let word = if i < 2 {
            0u64 // zero out the 8-byte checksum field (words 0 and 1)
        } else {
            read_le32(buf, i * 4) as u64
        };
        sum1 = (sum1 + word) % 0xFFFFFFFF;
        sum2 = (sum2 + sum1) % 0xFFFFFFFF;
    }
    let ck1 = 0xFFFFFFFF - ((sum1 + sum2) % 0xFFFFFFFF);
    let ck2 = 0xFFFFFFFF - ((sum1 + ck1) % 0xFFFFFFFF);
    let computed = (ck2 << 32) | ck1;
    computed == stored
}

// =====================================================================
// Data structures
// =====================================================================

#[derive(Clone, Copy)]
struct NxSuperblock {
    block_size: u32,
    block_count: u64,
    omap_oid: u64,       // physical OID of container omap
    xp_desc_base: u64,   // checkpoint descriptor area base block
    xp_desc_blocks: u32, // number of blocks in descriptor area
    xp_desc_len: u32,    // how many descriptors used by current checkpoint
    xp_desc_index: u32,  // index of first descriptor in current checkpoint
    xp_data_base: u64,   // checkpoint data area base block
    xp_data_blocks: u32,
    xp_data_len: u32,
    xp_data_index: u32,
    xid: u64,            // transaction ID (from o_xid)
    fs_oid: [u64; 4],    // volume OIDs
}

#[derive(Clone, Copy)]
struct ApfsVolume {
    omap_oid: u64,       // physical OID of volume's object map
    root_tree_oid: u64,  // virtual OID of root file-system B-tree
    xid: u64,            // volume's transaction ID
}

#[derive(Clone, Copy)]
struct ApfsInode {
    ino: u64,
    parent_id: u64,
    private_id: u64,
    mode: u16,
    owner: u32,
    group: u32,
    nlink: u32,
    size: u64,
}

impl ApfsInode {
    const fn empty() -> Self {
        Self {
            ino: 0,
            parent_id: 0,
            private_id: 0,
            mode: 0,
            owner: 0,
            group: 0,
            nlink: 0,
            size: 0,
        }
    }

    fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        (self.mode & S_IFMT) == S_IFLNK
    }
}

#[derive(Clone, Copy)]
struct OpenHandle {
    active: bool,
    inode: ApfsInode,
    pid: u32,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self {
            active: false,
            inode: ApfsInode::empty(),
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
    /// Receive a reply on reply_port.
    /// Uses sleep-based polling to work around the kernel IPC wakeup race
    /// (reschedule IPI is unreliable across CPUs, blocking recv_msg can hang).
    fn recv_reply(&self) -> Option<syscall::Message> {
        // Fast path: reply already queued.
        if let Some(m) = syscall::recv_nb_msg(self.reply_port) {
            return Some(m);
        }
        // Yield-poll: quick check after giving up the timeslice.
        for _ in 0..10 {
            syscall::yield_now();
            if let Some(m) = syscall::recv_nb_msg(self.reply_port) {
                return Some(m);
            }
        }
        // Sleep-poll: sleep briefly then check. The sleep guarantees we get
        // woken by the timer (not relying on IPC wakeup), and the poll checks
        // if the reply arrived while we were asleep.
        for _ in 0..500 {
            syscall::nanosleep(100_000); // 100μs
            if let Some(m) = syscall::recv_nb_msg(self.reply_port) {
                return Some(m);
            }
        }
        // Final attempt: blocking recv.
        syscall::recv_msg(self.reply_port)
    }

    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let abs_off = self.partition_offset + off;
        let sector = abs_off / 512;
        let offset_in_sector = (abs_off % 512) as usize;

        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }

        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_READ, 0, sector * 512, d2, self.grant_va as u64);

        let ok = if let Some(rr) = self.recv_reply() {
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
            syscall::send(self.blk_port, IO_READ, 0, sector_byte, d2, self.grant_va as u64);

            let ok = if let Some(rr) = self.recv_reply() {
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
            let ok = if let Some(rr) = self.recv_reply() {
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
        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_READ,
            0,
            sector_byte,
            d2,
            self.grant_va as u64,
        );
        let ok = if let Some(rr) = self.recv_reply() {
            rr.tag == IO_READ_OK && rr.data[0] == 512
        } else {
            false
        };
        syscall::revoke(self.blk_aspace, self.grant_va);
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
        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }
        syscall::send(
            self.blk_port,
            IO_WRITE,
            0,
            sector_byte,
            d2,
            self.grant_va as u64,
        );
        let ok = if let Some(rr) = self.recv_reply() {
            rr.tag == IO_WRITE_OK
        } else {
            false
        };
        syscall::revoke(self.blk_aspace, self.grant_va);
        ok
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
            syscall::debug_puts(b"  [apfs_srv] cache alloc FAILED\n");
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

/// Read a block via cache; returns VA of the cached block data.
fn cache_read(blk: &BlkClient, block_num: u64, block_size: u32) -> Option<usize> {
    unsafe {
        for i in 0..CACHE_SLOTS {
            if CACHE_META[i].valid && CACHE_META[i].block_num == block_num {
                CACHE_AGE += 1;
                CACHE_META[i].age = CACHE_AGE;
                return Some(CACHE_DATA_VA + i * PAGE_SIZE);
            }
        }

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

        let dest = CACHE_DATA_VA + victim * PAGE_SIZE;
        // Retry block reads to work around intermittent IPC failures.
        let mut ok = false;
        for _attempt in 0..3 {
            if blk.read_block(block_num, block_size, dest) {
                ok = true;
                break;
            }
            syscall::nanosleep(500_000); // 500μs between retries
        }
        if !ok {
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

/// Read a block into the cache and return a slice of the cached data.
fn cache_read_slice(blk: &BlkClient, block_num: u64, bs: u32) -> Option<&'static [u8]> {
    let va = cache_read(blk, block_num, bs)?;
    Some(unsafe { core::slice::from_raw_parts(va as *const u8, bs as usize) })
}

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

/// Scratch page for write operations (set in main).
static mut WRITE_VA: usize = 0;

// =====================================================================
// Fletcher-64 checksum stamping for writes
// =====================================================================

/// Recompute and stamp Fletcher-64 checksum on a block in memory.
fn stamp_checksum(block_va: usize, block_size: u32) {
    let buf = unsafe {
        core::slice::from_raw_parts_mut(block_va as *mut u8, block_size as usize)
    };
    // Zero the checksum field (first 8 bytes).
    for i in 0..8 {
        buf[i] = 0;
    }
    // Compute Fletcher-64.
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    let nwords = buf.len() / 4;
    for i in 0..nwords {
        let word = read_le32(buf, i * 4) as u64;
        sum1 = (sum1 + word) % 0xFFFFFFFF;
        sum2 = (sum2 + sum1) % 0xFFFFFFFF;
    }
    let ck1 = 0xFFFFFFFF - ((sum1 + sum2) % 0xFFFFFFFF);
    let ck2 = 0xFFFFFFFF - ((sum1 + ck1) % 0xFFFFFFFF);
    let checksum = (ck2 << 32) | ck1;
    // Write checksum back.
    write_le64(buf, 0, checksum);
}

// =====================================================================
// Little-endian write helpers
// =====================================================================

fn write_le16(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
}

fn write_le32(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
    buf[off + 2] = (val >> 16) as u8;
    buf[off + 3] = (val >> 24) as u8;
}

fn write_le64(buf: &mut [u8], off: usize, val: u64) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
    buf[off + 2] = (val >> 16) as u8;
    buf[off + 3] = (val >> 24) as u8;
    buf[off + 4] = (val >> 32) as u8;
    buf[off + 5] = (val >> 40) as u8;
    buf[off + 6] = (val >> 48) as u8;
    buf[off + 7] = (val >> 56) as u8;
}

// =====================================================================
// Block allocator (bitmap-based)
// =====================================================================

// Allocation bitmap — covers up to 32768 blocks (128 MiB at 4K blocks).
// One bit per block. Bit set = allocated.
static mut ALLOC_BITMAP: [u64; 512] = [0u64; 512];
static mut ALLOC_TOTAL: u64 = 0;
static mut ALLOC_FREE: u64 = 0;
static mut ALLOC_BITMAP_BLOCK: u64 = 0; // physical block of the bitmap on disk
static mut SPACEMAN_BLOCK: u64 = 0;     // physical block of the space manager
static mut CIB_BLOCK: u64 = 0;          // physical block of the chunk info block

// NX spaceman offsets:
// obj_phys_t: 32 bytes, then sm_block_size(4), sm_blocks_per_chunk(4),
// sm_chunks_per_cib(4), sm_cibs_per_cab(4), sm_dev[2] (48 bytes each = 96)
const SM_BLOCK_SIZE_OFF: usize = OBJ_PHYS_SIZE;          // u32 at 32
const SM_BLOCKS_PER_CHUNK_OFF: usize = OBJ_PHYS_SIZE + 4;// u32 at 36
const SM_CHUNKS_PER_CIB_OFF: usize = OBJ_PHYS_SIZE + 8;  // u32 at 40
const SM_DEV_OFF: usize = OBJ_PHYS_SIZE + 16;            // start of sm_dev[0] at 48
const SD_BLOCK_COUNT_OFF: usize = 0;
const SD_CHUNK_COUNT_OFF: usize = 8;
const SD_CIB_COUNT_OFF: usize = 16;
const SD_FREE_COUNT_OFF: usize = 24;
const SD_ADDR_OFFSET_OFF: usize = 32;

// chunk_info_t offsets
const CI_ADDR_OFF: usize = 8;          // ci_addr: physical block of bitmap
const CI_BLOCK_COUNT_OFF: usize = 16;  // ci_block_count: u32
const CI_FREE_COUNT_OFF: usize = 20;   // ci_free_count: u32
const CI_BITMAP_ADDR_OFF: usize = 24;  // ci_bitmap_addr: u64

// chunk_info_block_t: after obj_hdr(32), ci_index(4), ci_chunk_count(4), then chunk_info_t array
const CIB_INDEX_OFF: usize = OBJ_PHYS_SIZE;
const CIB_CHUNK_COUNT_OFF: usize = OBJ_PHYS_SIZE + 4;
const CIB_CHUNKS_OFF: usize = OBJ_PHYS_SIZE + 8;

/// Parse the space manager at mount to load the allocation bitmap.
fn spaceman_init(blk: &BlkClient, bs: u32, nx_buf: &[u8]) {
    // nx_spaceman_oid is at offset 152 in the container superblock.
    let spaceman_oid = read_le64(nx_buf, 152);
    if spaceman_oid == 0 {
        syscall::debug_puts(b"  [apfs_srv] no spaceman OID\n");
        return;
    }

    // Use the spaceman physical address resolved during checkpoint scan.
    let mut spaceman_phys = unsafe { SPACEMAN_PHYS_FROM_CKPT };
    if spaceman_phys == 0 {
        // Fallback: try xp_data_base + 1 (common for mkapfs: reaper at +0, spaceman at +1).
        let xp_data_base = read_le64(nx_buf, NX_XP_DATA_BASE_OFF);
        spaceman_phys = xp_data_base + 1;
    }

    unsafe { SPACEMAN_BLOCK = spaceman_phys; }

    syscall::debug_puts(b"  [apfs_srv] spaceman at block ");
    print_num(spaceman_phys);
    syscall::debug_puts(b"\n");

    // Read spaceman block.
    let sm_buf = match cache_read_slice(blk, spaceman_phys, bs) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] cannot read spaceman\n");
            return;
        }
    };

    // Parse device[0] to get total blocks and CIB address.
    let dev_base = SM_DEV_OFF;
    let sd_block_count = read_le64(sm_buf, dev_base + SD_BLOCK_COUNT_OFF);
    let sd_chunk_count = read_le64(sm_buf, dev_base + SD_CHUNK_COUNT_OFF);
    let sd_cib_count = read_le32(sm_buf, dev_base + SD_CIB_COUNT_OFF) as u64;
    let sd_free_count = read_le64(sm_buf, dev_base + SD_FREE_COUNT_OFF);
    let sd_addr_offset = read_le32(sm_buf, dev_base + SD_ADDR_OFFSET_OFF) as u64;

    syscall::debug_puts(b"  [apfs_srv] spaceman dev_base=");
    print_num(dev_base as u64);
    syscall::debug_puts(b" blocks=");
    print_num(sd_block_count);
    syscall::debug_puts(b" free=");
    print_num(sd_free_count);
    syscall::debug_puts(b" chunks=");
    print_num(sd_chunk_count);
    syscall::debug_puts(b"\n");

    unsafe {
        ALLOC_TOTAL = sd_block_count;
        ALLOC_FREE = sd_free_count;
    }

    // Find the CIB address. It's stored inline in the spaceman at sd_addr_offset.
    // sd_addr_offset is an offset into the spaceman block where the CIB physical address is.
    if sd_addr_offset == 0 || sd_addr_offset as usize + 8 > bs as usize {
        syscall::debug_puts(b"  [apfs_srv] no CIB addr_offset, no allocator\n");
        return;
    }
    let cib_phys = read_le64(sm_buf, sd_addr_offset as usize);
    if cib_phys == 0 {
        syscall::debug_puts(b"  [apfs_srv] CIB addr is 0\n");
        return;
    }

    unsafe { CIB_BLOCK = cib_phys; }

    // Read the CIB to find the bitmap block.
    let cib_buf = match cache_read_slice(blk, cib_phys, bs) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] cannot read CIB\n");
            return;
        }
    };

    let ci_count = read_le32(cib_buf, CIB_CHUNK_COUNT_OFF) as usize;
    if ci_count == 0 {
        syscall::debug_puts(b"  [apfs_srv] CIB has 0 chunks\n");
        return;
    }

    // Read first chunk_info_t (each is 32 bytes).
    let ci_base = CIB_CHUNKS_OFF;
    let ci_xid = read_le64(cib_buf, ci_base);
    let ci_addr = read_le64(cib_buf, ci_base + 8);
    let ci_block_count = read_le32(cib_buf, ci_base + 16);
    let ci_free_count = read_le32(cib_buf, ci_base + 20);
    let ci_bm_addr = read_le64(cib_buf, ci_base + 24);

    syscall::debug_puts(b"  [apfs_srv] CIB chunk0: bm_addr=");
    print_num(ci_bm_addr);
    syscall::debug_puts(b" blocks=");
    print_num(ci_block_count as u64);
    syscall::debug_puts(b" free=");
    print_num(ci_free_count as u64);
    syscall::debug_puts(b"\n");

    if ci_bm_addr == 0 {
        syscall::debug_puts(b"  [apfs_srv] bitmap addr is 0\n");
        return;
    }

    unsafe { ALLOC_BITMAP_BLOCK = ci_bm_addr; }

    // Read the bitmap block into our static array.
    let bm_buf = match cache_read_slice(blk, ci_bm_addr, bs) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] cannot read bitmap\n");
            return;
        }
    };

    // Copy bitmap data — each u64 covers 64 blocks.
    let words = (bs as usize) / 8;
    unsafe {
        for i in 0..words.min(512) {
            ALLOC_BITMAP[i] = read_le64(bm_buf, i * 8);
        }
    }

    syscall::debug_puts(b"  [apfs_srv] allocator ready\n");
}

/// Allocate `count` consecutive blocks. Returns first block number, or None.
fn block_alloc(count: u32) -> Option<u64> {
    if count == 0 { return None; }
    unsafe {
        if (ALLOC_FREE as u32) < count {
            return None;
        }
        let total_bits = (ALLOC_TOTAL as usize).min(32768);
        // Linear scan for `count` consecutive free bits.
        let mut run_start = 0usize;
        let mut run_len = 0u32;
        for bit in 0..total_bits {
            let word = bit / 64;
            let shift = bit % 64;
            if (ALLOC_BITMAP[word] >> shift) & 1 != 0 {
                // Allocated — reset run.
                run_start = bit + 1;
                run_len = 0;
            } else {
                run_len += 1;
                if run_len >= count {
                    // Found! Mark bits as allocated.
                    let start = run_start;
                    for b in start..start + count as usize {
                        let w = b / 64;
                        let s = b % 64;
                        ALLOC_BITMAP[w] |= 1u64 << s;
                    }
                    ALLOC_FREE -= count as u64;
                    return Some(start as u64);
                }
            }
        }
        None
    }
}

/// Free `count` consecutive blocks starting at `start`.
fn block_free(start: u64, count: u32) {
    unsafe {
        for i in 0..count as u64 {
            let bit = (start + i) as usize;
            if bit < 32768 {
                let w = bit / 64;
                let s = bit % 64;
                ALLOC_BITMAP[w] &= !(1u64 << s);
            }
        }
        ALLOC_FREE += count as u64;
    }
}

/// Flush the allocation bitmap back to disk.
fn flush_bitmap(blk: &BlkClient, bs: u32) -> bool {
    let bm_block = unsafe { ALLOC_BITMAP_BLOCK };
    if bm_block == 0 {
        return true;
    }
    let wva = unsafe { WRITE_VA };
    // Write our bitmap array to the scratch page and write to disk.
    let words = (bs as usize) / 8;
    let buf = unsafe {
        core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize)
    };
    unsafe {
        core::ptr::write_bytes(wva as *mut u8, 0, bs as usize);
    }
    for i in 0..words.min(512) {
        unsafe {
            write_le64(buf, i * 8, ALLOC_BITMAP[i]);
        }
    }
    cache_invalidate(bm_block);
    blk.write_block(bm_block, bs, wva)
}

// =====================================================================
// Global write state
// =====================================================================

// Container-level OID/XID tracking for writes.
static mut NX_NEXT_OID: u64 = 0;
static mut NX_NEXT_XID: u64 = 0;
static mut VOL_NEXT_OBJ_ID: u64 = 0;
static mut VOL_PHYS_BLOCK: u64 = 0;
static mut NX_OMAP_PHYS: u64 = 0;

// Volume superblock field offsets for writes.
const APFS_NUM_FILES_OFF: usize = 0x90;       // apfs_num_files (u64) at 144
const APFS_NUM_DIRS_OFF: usize = 0x98;        // apfs_num_directories (u64) at 152
const APFS_NUM_SYMLINKS_OFF: usize = 0xA0;    // apfs_num_symlinks (u64) at 160
const APFS_NEXT_OBJ_ID_OFF: usize = 0x70;     // apfs_next_obj_id at 112
const NX_NEXT_OID_OFF: usize = 88;            // in container superblock
const NX_NEXT_XID_OFF: usize = 96;            // in container superblock

// =====================================================================
// B-tree modification helpers (CoW)
// =====================================================================

/// Write a modified B-tree node back to disk with CoW.
/// For the omap tree (physical): allocates new block, copies data, stamps checksum, writes.
/// Returns the new physical block number.
fn btree_write_cow_phys(
    blk: &BlkClient, bs: u32, old_block: u64, node_va: usize,
) -> Option<u64> {
    // Allocate a new block for the CoW copy.
    let new_block = block_alloc(1)?;

    // Stamp checksum.
    stamp_checksum(node_va, bs);

    // Write to disk.
    cache_invalidate(new_block);
    if !blk.write_block(new_block, bs, node_va) {
        block_free(new_block, 1);
        return None;
    }

    // Free old block.
    if old_block != 0 {
        block_free(old_block, 1);
    }

    Some(new_block)
}

/// Insert a key/value into a variable-size B-tree leaf node (in memory at `node_va`).
/// Returns true on success. The node must have enough free space.
fn btree_leaf_insert_var(
    node_va: usize, bs: u32,
    key: &[u8], val: &[u8],
    insert_pos: usize,
) -> bool {
    let buf = unsafe {
        core::slice::from_raw_parts_mut(node_va as *mut u8, bs as usize)
    };

    let flags = read_le16(buf, BTN_FLAGS_OFF);
    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;
    let free_off = read_le16(buf, BTN_FREE_OFF) as usize;
    let free_len = read_le16(buf, BTN_FREE_OFF + 2) as usize;

    let data_base = BTN_DATA_OFF;
    let toc_base = data_base + toc_off;
    let key_base = data_base + toc_off + toc_len;
    let val_end = if (flags & BTNODE_ROOT) != 0 {
        bs as usize - BTREE_INFO_SIZE
    } else {
        bs as usize
    };

    let key_len = key.len();
    let val_len = val.len();

    // Compute consumed value space by scanning existing TOC entries.
    // Each kvloc_t: k_off(u16), k_len(u16), v_off(u16), v_len(u16).
    // In APFS, v_off is the cumulative offset from val_end to the START of
    // the value. Total consumed = max(v_off) across all entries.
    let mut val_consumed: usize = 0;
    for i in 0..nkeys {
        let te = toc_base + i * 8;
        if te + 8 > bs as usize { break; }
        let v_off = read_le16(buf, te + 4) as usize;
        if v_off > val_consumed {
            val_consumed = v_off;
        }
    }

    // Key goes at key_base + free_off.
    let key_write_off = key_base + free_off;

    // Value space: values grow backward from val_end.
    // New value's v_off = val_consumed + val_len (cumulative offset).
    let new_val_consumed = val_consumed + val_len;

    // Check that we have room.
    let key_area_end = key_write_off + key_len;
    if new_val_consumed > val_end {
        return false; // no room
    }
    let val_area_start = val_end - new_val_consumed;
    if key_area_end > val_area_start {
        return false; // no room
    }

    // Shift existing TOC entries at insert_pos..nkeys right by 8 bytes.
    if insert_pos < nkeys {
        let src = toc_base + insert_pos * 8;
        let dst = toc_base + (insert_pos + 1) * 8;
        let count = (nkeys - insert_pos) * 8;
        unsafe {
            core::ptr::copy(
                (node_va + src) as *const u8,
                (node_va + dst) as *mut u8,
                count,
            );
        }
    }

    // Write key data.
    if key_write_off + key_len > bs as usize {
        return false;
    }
    buf[key_write_off..key_write_off + key_len].copy_from_slice(key);

    // Write value data.
    let val_write_start = val_end - new_val_consumed;
    if val_write_start + val_len > bs as usize {
        return false;
    }
    buf[val_write_start..val_write_start + val_len].copy_from_slice(val);

    // Write TOC entry (kvloc_t): k_off(u16), k_len(u16), v_off(u16), v_len(u16)
    // v_off = cumulative offset from val_end to value start = val_consumed + val_len
    let toc_entry = toc_base + insert_pos * 8;
    write_le16(buf, toc_entry, free_off as u16);            // key offset relative to key_base
    write_le16(buf, toc_entry + 2, key_len as u16);
    write_le16(buf, toc_entry + 4, new_val_consumed as u16); // cumulative val offset
    write_le16(buf, toc_entry + 6, val_len as u16);

    // Update header.
    write_le32(buf, BTN_NKEYS_OFF, (nkeys + 1) as u32);
    write_le16(buf, BTN_FREE_OFF, (free_off + key_len) as u16);
    write_le16(buf, BTN_FREE_OFF + 2, (free_len.saturating_sub(key_len + val_len + 8)) as u16);
    // Don't touch btn_key_free_list / btn_val_free_list — they're free-list
    // heads for deleted entries (0xFFFF = empty), not consumed counters.

    true
}

/// Delete a key/value from a variable-size B-tree leaf node at position `del_pos`.
fn btree_leaf_delete_var(
    node_va: usize, bs: u32, del_pos: usize,
) -> bool {
    let buf = unsafe {
        core::slice::from_raw_parts_mut(node_va as *mut u8, bs as usize)
    };

    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    if del_pos >= nkeys {
        return false;
    }

    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_base = BTN_DATA_OFF + toc_off;

    // Shift TOC entries left.
    if del_pos + 1 < nkeys {
        let src = toc_base + (del_pos + 1) * 8;
        let dst = toc_base + del_pos * 8;
        let count = (nkeys - del_pos - 1) * 8;
        unsafe {
            core::ptr::copy(
                (node_va + src) as *const u8,
                (node_va + dst) as *mut u8,
                count,
            );
        }
    }

    // Update nkeys.
    write_le32(buf, BTN_NKEYS_OFF, (nkeys - 1) as u32);
    // Note: We don't reclaim key/value space (fragmentation is tolerable for our small trees).

    true
}

/// Insert a key/value into a fixed-size B-tree leaf node (omap).
/// Omap keys are 16 bytes (oid+xid), values are 16 bytes (flags+size+paddr).
fn btree_leaf_insert_fixed(
    node_va: usize, bs: u32,
    key: &[u8], val: &[u8],
    insert_pos: usize,
) -> bool {
    let buf = unsafe {
        core::slice::from_raw_parts_mut(node_va as *mut u8, bs as usize)
    };

    let flags = read_le16(buf, BTN_FLAGS_OFF);
    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;

    let data_base = BTN_DATA_OFF;
    let toc_base = data_base + toc_off;
    let key_base = data_base + toc_off + toc_len;
    let val_end = if (flags & BTNODE_ROOT) != 0 {
        bs as usize - BTREE_INFO_SIZE
    } else {
        bs as usize
    };

    let key_size = 16usize; // omap_key_t: oid(8) + xid(8)
    let val_size = 16usize; // omap_val_t: flags(4) + size(4) + paddr(8)

    // TOC entries for fixed-kv are kvoff_t: 4 bytes each (k_off u16, v_off u16).
    // Shift entries right.
    if insert_pos < nkeys {
        let src = toc_base + insert_pos * 4;
        let dst = toc_base + (insert_pos + 1) * 4;
        let count = (nkeys - insert_pos) * 4;
        unsafe {
            core::ptr::copy(
                (node_va + src) as *const u8,
                (node_va + dst) as *mut u8,
                count,
            );
        }
    }

    // Key goes at key_base + insert_pos * key_size.
    // But we need to shift existing keys right too.
    let key_area = key_base;
    if insert_pos < nkeys {
        let ksrc = key_area + insert_pos * key_size;
        let kdst = key_area + (insert_pos + 1) * key_size;
        let kcount = (nkeys - insert_pos) * key_size;
        unsafe {
            core::ptr::copy(
                (node_va + ksrc) as *const u8,
                (node_va + kdst) as *mut u8,
                kcount,
            );
        }
    }
    buf[key_area + insert_pos * key_size..key_area + insert_pos * key_size + key.len().min(key_size)]
        .copy_from_slice(&key[..key.len().min(key_size)]);

    // Values grow backward from val_end. Value i is at val_end - (i+1)*val_size.
    // Shift existing values left (toward lower addresses).
    if insert_pos < nkeys {
        let vstart = val_end - (nkeys) * val_size;
        let vdst = val_end - (nkeys + 1) * val_size;
        let vcount = (nkeys - insert_pos) * val_size;
        unsafe {
            core::ptr::copy(
                (node_va + vstart) as *const u8,
                (node_va + vdst) as *mut u8,
                vcount,
            );
        }
    }
    let val_start = val_end - (insert_pos + 1) * val_size;
    buf[val_start..val_start + val.len().min(val_size)]
        .copy_from_slice(&val[..val.len().min(val_size)]);

    // Write TOC entry.
    let toc_entry = toc_base + insert_pos * 4;
    write_le16(buf, toc_entry, (insert_pos * key_size) as u16);
    write_le16(buf, toc_entry + 2, ((insert_pos + 1) * val_size) as u16);

    // Fix up TOC entries for subsequent keys (their offsets shifted).
    for i in (insert_pos + 1)..=nkeys {
        let te = toc_base + i * 4;
        write_le16(buf, te, (i * key_size) as u16);
        write_le16(buf, te + 2, ((i + 1) * val_size) as u16);
    }

    write_le32(buf, BTN_NKEYS_OFF, (nkeys + 1) as u32);

    true
}

/// Delete entry at `del_pos` from a fixed-size B-tree leaf (omap).
fn btree_leaf_delete_fixed(
    node_va: usize, bs: u32, del_pos: usize,
) -> bool {
    let buf = unsafe {
        core::slice::from_raw_parts_mut(node_va as *mut u8, bs as usize)
    };

    let flags = read_le16(buf, BTN_FLAGS_OFF);
    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    if del_pos >= nkeys { return false; }

    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;
    let toc_base = BTN_DATA_OFF + toc_off;
    let key_base = BTN_DATA_OFF + toc_off + toc_len;
    let val_end = if (flags & BTNODE_ROOT) != 0 {
        bs as usize - BTREE_INFO_SIZE
    } else {
        bs as usize
    };

    let key_size = 16usize;
    let val_size = 16usize;

    // Shift keys left.
    if del_pos + 1 < nkeys {
        let ksrc = key_base + (del_pos + 1) * key_size;
        let kdst = key_base + del_pos * key_size;
        let kcount = (nkeys - del_pos - 1) * key_size;
        unsafe {
            core::ptr::copy(
                (node_va + ksrc) as *const u8,
                (node_va + kdst) as *mut u8,
                kcount,
            );
        }
    }

    // Shift values right (toward higher addresses).
    if del_pos + 1 < nkeys {
        let old_start = val_end - nkeys * val_size;
        let new_start = val_end - (nkeys - 1) * val_size;
        // Values 0..del_pos need to move right by val_size.
        let vcount = (nkeys - del_pos - 1) * val_size;
        let vsrc = val_end - nkeys * val_size;
        let vdst = val_end - (nkeys - 1) * val_size;
        unsafe {
            core::ptr::copy(
                (node_va + vsrc) as *const u8,
                (node_va + vdst) as *mut u8,
                vcount,
            );
        }
    }

    // Shift TOC left.
    if del_pos + 1 < nkeys {
        let tsrc = toc_base + (del_pos + 1) * 4;
        let tdst = toc_base + del_pos * 4;
        let tcount = (nkeys - del_pos - 1) * 4;
        unsafe {
            core::ptr::copy(
                (node_va + tsrc) as *const u8,
                (node_va + tdst) as *mut u8,
                tcount,
            );
        }
    }

    // Fix up TOC offsets.
    let new_nkeys = nkeys - 1;
    for i in 0..new_nkeys {
        let te = toc_base + i * 4;
        write_le16(buf, te, (i * key_size) as u16);
        write_le16(buf, te + 2, ((i + 1) * val_size) as u16);
    }

    write_le32(buf, BTN_NKEYS_OFF, new_nkeys as u32);
    true
}

/// Update an omap entry: find the entry for `oid`, update its paddr to `new_paddr`.
/// If no entry exists, insert one. Uses CoW on the omap tree root.
/// Returns the new omap tree root physical block, or None on failure.
fn omap_update(
    blk: &BlkClient, bs: u32, omap_phys_block: u64,
    oid: u64, xid: u64, new_paddr: u64,
) -> Option<u64> {
    let wva = unsafe { WRITE_VA };

    // Read omap header.
    let omap_buf = cache_read_slice(blk, omap_phys_block, bs)?;
    let tree_oid = read_le64(omap_buf, OMAP_TREE_OID_OFF);

    // Read the omap B-tree root into scratch.
    if !blk.read_block(tree_oid, bs, wva) {
        return None;
    }

    let buf = unsafe {
        core::slice::from_raw_parts(wva as *const u8, bs as usize)
    };
    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    let flags = read_le16(buf, BTN_FLAGS_OFF);
    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;
    let key_base = BTN_DATA_OFF + toc_off + toc_len;
    let val_end = if (flags & BTNODE_ROOT) != 0 {
        bs as usize - BTREE_INFO_SIZE
    } else {
        bs as usize
    };

    // Search for existing entry with this OID.
    let mut found_pos: Option<usize> = None;
    let mut insert_pos = nkeys; // default: append at end
    for i in 0..nkeys {
        let k_start = key_base + i * 16;
        let k_oid = read_le64(buf, k_start);
        if k_oid == oid {
            found_pos = Some(i);
            break;
        }
        if k_oid > oid && insert_pos == nkeys {
            insert_pos = i;
        }
    }

    if let Some(pos) = found_pos {
        // Update existing entry's paddr in place (then CoW).
        let val_start = val_end - (pos + 1) * 16;
        let mbuf = unsafe {
            core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize)
        };
        write_le64(mbuf, val_start + 8, new_paddr); // ov_paddr at offset 8
        // Update xid in key.
        let k_start = key_base + pos * 16;
        write_le64(mbuf, k_start + 8, xid);
        // Update o_xid in object header.
        write_le64(mbuf, 16, xid);
    } else {
        // Insert new entry.
        let mut omap_key = [0u8; 16];
        write_le64(&mut omap_key, 0, oid);
        write_le64(&mut omap_key, 8, xid);
        let mut omap_val = [0u8; 16];
        write_le32(&mut omap_val, 0, 0); // flags
        write_le32(&mut omap_val, 4, bs); // size
        write_le64(&mut omap_val, 8, new_paddr);

        // Update o_xid.
        let mbuf = unsafe {
            core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize)
        };
        write_le64(mbuf, 16, xid);

        if !btree_leaf_insert_fixed(wva, bs, &omap_key, &omap_val, insert_pos) {
            return None;
        }
    }

    // CoW: write to a new block.
    let new_root = btree_write_cow_phys(blk, bs, tree_oid, wva)?;

    // Update the omap header to point to the new root.
    let wva2 = wva; // reuse scratch
    if !blk.read_block(omap_phys_block, bs, wva2) {
        return None;
    }
    let mbuf = unsafe {
        core::slice::from_raw_parts_mut(wva2 as *mut u8, bs as usize)
    };
    write_le64(mbuf, OMAP_TREE_OID_OFF, new_root);
    write_le64(mbuf, 16, xid); // update o_xid
    stamp_checksum(wva2, bs);
    cache_invalidate(omap_phys_block);
    if !blk.write_block(omap_phys_block, bs, wva2) {
        return None;
    }

    Some(new_root)
}

// =====================================================================
// CRC-32C for APFS directory entry name hashing
// =====================================================================

fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute APFS directory entry name hash.
/// Hash goes in the top 22 bits of name_len_and_hash.
fn drec_name_hash(name: &[u8]) -> u32 {
    // For case-insensitive volumes: hash lowercase.
    // For case-sensitive: hash as-is. We assume case-sensitive for now.
    let hash = crc32c(name);
    (hash & 0xFFFFF800) // top 22 bits, shifted to position (already in high bits after mask? no)
    // Actually: name_len_and_hash = (hash << 10) | (name_len_with_null & 0x3FF)
    // Wait, spec says: top 22 bits = hash, low 10 bits = name length including null.
    // So we need hash >> 10 to fit in 22 bits? No: the hash occupies bits 10..31.
    // name_len_and_hash = (hash_val & 0xFFFFFC00) | ((name_len + 1) & 0x3FF)
    // where hash_val = crc32c result with low 10 bits masked off.
}

fn make_name_len_and_hash(name: &[u8]) -> u32 {
    let hash = crc32c(name);
    let name_len_with_null = (name.len() + 1) as u32;
    (hash & 0xFFFFFC00) | (name_len_with_null & 0x3FF)
}

// =====================================================================
// FS record insert/delete operations
// =====================================================================

/// Find the insertion position for a new record in the fs tree.
/// Returns (node_physical_block, toc_index) for the leaf where the record should go.
fn fs_tree_find_insert_pos(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64, max_xid: u64,
    target_key: u64,
) -> Option<(u64, usize)> {
    // Walk to the leaf. For our small trees, the root IS the leaf.
    let buf = cache_read_slice(blk, fs_root_block, bs)?;
    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    let flags = read_le16(buf, BTN_FLAGS_OFF);
    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;
    let key_base = BTN_DATA_OFF + toc_off + toc_len;

    // Find position where target_key should be inserted (sorted order).
    let mut pos = nkeys;
    for i in 0..nkeys {
        let te = BTN_DATA_OFF + toc_off + i * 8;
        let k_off = read_le16(buf, te) as usize;
        let k_start = key_base + k_off;
        if k_start + 8 > bs as usize { continue; }
        let k = read_le64(buf, k_start);
        if fs_key_cmp(target_key, k) != core::cmp::Ordering::Greater {
            pos = i;
            break;
        }
    }

    Some((fs_root_block, pos))
}

/// Insert a record into the fs tree with CoW.
/// Returns the new fs tree root physical block.
fn fs_tree_insert(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    key: &[u8], val: &[u8],
) -> Option<u64> {
    let wva = unsafe { WRITE_VA };

    // Read the root node into scratch.
    if !blk.read_block(fs_root_block, bs, wva) {
        return None;
    }

    // Find insert position.
    let buf = unsafe { core::slice::from_raw_parts(wva as *const u8, bs as usize) };
    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;
    let key_base = BTN_DATA_OFF + toc_off + toc_len;

    let target_key = if key.len() >= 8 { read_le64(key, 0) } else { 0 };
    let mut pos = nkeys;
    for i in 0..nkeys {
        let te = BTN_DATA_OFF + toc_off + i * 8;
        if te + 4 > bs as usize { continue; }
        let k_off = read_le16(buf, te) as usize;
        let k_start = key_base + k_off;
        if k_start + 8 > bs as usize { continue; }
        let k = read_le64(buf, k_start);
        if fs_key_cmp(target_key, k) != core::cmp::Ordering::Greater {
            // For drec keys, also compare by name.
            if fs_key_cmp(target_key, k) == core::cmp::Ordering::Equal && key.len() > 8 {
                let k_len_entry = read_le16(buf, te + 2) as usize;
                let end = (k_start + k_len_entry).min(bs as usize);
                if k_start < end {
                    let k_full = &buf[k_start..end];
                    // Compare full key bytes.
                    if key > k_full {
                        continue; // keep going
                    }
                }
            }
            pos = i;
            break;
        }
    }

    // Update o_xid.
    let mbuf = unsafe { core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize) };
    write_le64(mbuf, 16, max_xid);

    if !btree_leaf_insert_var(wva, bs, key, val, pos) {
        return None;
    }

    // CoW the fs tree root: allocate new block, update omap.
    let new_phys = btree_write_cow_phys(blk, bs, fs_root_block, wva)?;

    // Update omap to map fs_root_oid → new_phys.
    omap_update(blk, bs, vol_omap_phys, fs_root_oid, max_xid, new_phys)?;

    Some(new_phys)
}

/// Delete a record from the fs tree by matching key bytes.
/// Returns the new fs tree root physical block.
fn fs_tree_delete(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    match_fn: &dyn Fn(&[u8]) -> core::cmp::Ordering,
) -> Option<u64> {
    let wva = unsafe { WRITE_VA };

    if !blk.read_block(fs_root_block, bs, wva) {
        return None;
    }

    let buf = unsafe { core::slice::from_raw_parts(wva as *const u8, bs as usize) };
    let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
    let flags = read_le16(buf, BTN_FLAGS_OFF);
    let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
    let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;
    let key_base = BTN_DATA_OFF + toc_off + toc_len;

    let mut del_pos: Option<usize> = None;
    for i in 0..nkeys {
        let te = BTN_DATA_OFF + toc_off + i * 8;
        let k_off = read_le16(buf, te) as usize;
        let k_len = read_le16(buf, te + 2) as usize;
        let k_start = key_base + k_off;
        if k_start + k_len > bs as usize { continue; }
        let key_data = &buf[k_start..k_start + k_len];
        if match_fn(key_data) == core::cmp::Ordering::Equal {
            del_pos = Some(i);
            break;
        }
    }

    let del_pos = del_pos?;

    let mbuf = unsafe { core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize) };
    write_le64(mbuf, 16, max_xid);

    if !btree_leaf_delete_var(wva, bs, del_pos) {
        return None;
    }

    let new_phys = btree_write_cow_phys(blk, bs, fs_root_block, wva)?;
    omap_update(blk, bs, vol_omap_phys, fs_root_oid, max_xid, new_phys)?;
    Some(new_phys)
}

/// Get current timestamp as nanoseconds since epoch.
/// Since we don't have a real clock, use a counter.
static mut TIME_COUNTER: u64 = 1_700_000_000_000_000_000; // ~2023 in nanoseconds

fn apfs_now() -> u64 {
    unsafe {
        TIME_COUNTER += 1_000_000; // advance 1ms each call
        TIME_COUNTER
    }
}

/// Create an inode record in the fs tree.
/// Returns the new fs tree root physical block.
fn create_inode_record(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    ino: u64, parent_id: u64, mode: u16, is_dir: bool,
) -> Option<u64> {
    // Build key: j_key_t = obj_id_and_type
    let mut key = [0u8; 8];
    write_le64(&mut key, 0, make_fs_key(ino, APFS_TYPE_INODE));

    // Build value: j_inode_val_t (92 bytes fixed + xfields)
    // For a file: add INO_EXT_TYPE_DSTREAM xfield (40 bytes dstream, initially zeroed).
    // For a dir: no dstream needed.
    let now = apfs_now();

    // xfields: xf_blob_t header (4 bytes: xf_num_exts u16 + xf_used_data u16)
    //          then x_field_t array (4 bytes each: x_type u8, x_flags u8, x_size u16)
    //          then field data

    let (xfield_hdr_size, xfield_data_size, num_xfields) = if is_dir {
        // No extended fields for dirs (keep it simple).
        (0usize, 0usize, 0u16)
    } else {
        // One xfield: DSTREAM (40 bytes)
        // xf_blob_t: 4 bytes
        // x_field_t: 4 bytes
        // dstream data: 40 bytes (j_dstream_t)
        // Total: 48 bytes
        (4 + 4, 40, 1u16)
    };

    let val_len = IVAL_XFIELDS + xfield_hdr_size + xfield_data_size;
    let mut val = [0u8; 256]; // max size
    if val_len > 256 { return None; }

    write_le64(&mut val, IVAL_PARENT_ID, parent_id);
    write_le64(&mut val, IVAL_PRIVATE_ID, ino); // private_id == ino for simplicity
    write_le64(&mut val, IVAL_CREATE_TIME, now);
    write_le64(&mut val, IVAL_MOD_TIME, now);
    write_le64(&mut val, IVAL_CHANGE_TIME, now);
    write_le64(&mut val, IVAL_ACCESS_TIME, now);
    write_le64(&mut val, IVAL_INTERNAL_FLAGS, 0);
    if is_dir {
        write_le32(&mut val, IVAL_NCHILDREN_NLINK, 0); // nchildren = 0
    } else {
        write_le32(&mut val, IVAL_NCHILDREN_NLINK, 1); // nlink = 1
    }
    write_le32(&mut val, IVAL_DEFAULT_PROT_CLASS, 0);
    write_le32(&mut val, IVAL_WRITE_GEN_COUNTER, 1);
    write_le32(&mut val, IVAL_BSD_FLAGS, 0);
    write_le32(&mut val, IVAL_OWNER, 0);
    write_le32(&mut val, IVAL_GROUP, 0);
    write_le16(&mut val, IVAL_MODE, mode);
    write_le16(&mut val, IVAL_PAD1, 0);
    write_le64(&mut val, IVAL_UNCOMPRESSED_SIZE, 0);

    if !is_dir && num_xfields > 0 {
        let xf_start = IVAL_XFIELDS;
        // xf_blob_t: num_exts(u16), used_data(u16)
        write_le16(&mut val, xf_start, num_xfields);
        write_le16(&mut val, xf_start + 2, xfield_data_size as u16);
        // x_field_t[0]: type=DSTREAM, flags=0, size=40
        write_le16(&mut val, xf_start + 4, INO_EXT_TYPE_DSTREAM as u16); // x_type + x_flags packed
        // Actually: x_type is u8 at +4, x_flags is u8 at +5, x_size is u16 at +6
        val[xf_start + 4] = INO_EXT_TYPE_DSTREAM;
        val[xf_start + 5] = 0; // x_flags
        write_le16(&mut val, xf_start + 6, 40); // x_size = 40 (j_dstream_t)
        // dstream data (40 bytes): all zero initially (size=0, alloced_size=0, ...)
    }

    fs_tree_insert(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid,
        &key, &val[..val_len])
}

/// Create a directory entry record in the fs tree.
fn create_dir_entry(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    dir_ino: u64, name: &[u8], file_id: u64, ftype: u16,
) -> Option<u64> {
    // Key: j_drec_hashed_key_t
    //   obj_id_and_type (8) + name_len_and_hash (4) + name[] (null-terminated)
    let name_with_null = name.len() + 1;
    let key_len = 8 + 4 + name_with_null;
    let mut key = [0u8; 280]; // max name = 255 + overhead
    if key_len > 280 { return None; }

    write_le64(&mut key, 0, make_fs_key(dir_ino, APFS_TYPE_DIR_REC));
    write_le32(&mut key, 8, make_name_len_and_hash(name));
    key[12..12 + name.len()].copy_from_slice(name);
    key[12 + name.len()] = 0; // null terminator

    // Value: j_drec_val_t
    //   file_id (8) + date_added (8) + flags (2)
    let val_len = 18;
    let mut val = [0u8; 18];
    write_le64(&mut val, 0, file_id);
    write_le64(&mut val, 8, apfs_now());
    write_le16(&mut val, 16, ftype & DREC_TYPE_MASK);

    fs_tree_insert(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid,
        &key[..key_len], &val[..val_len])
}

/// Delete a directory entry by name from the fs tree.
fn delete_dir_entry(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    dir_ino: u64, name: &[u8],
) -> Option<u64> {
    let target_key_hdr = make_fs_key(dir_ino, APFS_TYPE_DIR_REC);

    fs_tree_delete(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid,
        &|key_data: &[u8]| {
            if key_data.len() < 12 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);
            if k_id < dir_ino || (k_id == dir_ino && (k_type as u64) < APFS_TYPE_DIR_REC as u64) {
                return core::cmp::Ordering::Less;
            }
            if k_id > dir_ino || (k_id == dir_ino && k_type > APFS_TYPE_DIR_REC) {
                return core::cmp::Ordering::Greater;
            }
            // Match name.
            let name_len_and_hash = read_le32(key_data, 8);
            let entry_name_len = (name_len_and_hash & 0x3FF) as usize;
            let actual = if entry_name_len > 0 { entry_name_len - 1 } else { 0 };
            if 12 + actual > key_data.len() {
                return core::cmp::Ordering::Less;
            }
            let entry_name = &key_data[12..12 + actual];
            if entry_name.len() == name.len() && entry_name == name {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Less
            }
        },
    )
}

/// Delete an inode record from the fs tree.
fn delete_inode_record(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64, ino: u64,
) -> Option<u64> {
    let target = make_fs_key(ino, APFS_TYPE_INODE);
    fs_tree_delete(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid,
        &|key_data: &[u8]| {
            if key_data.len() < 8 { return core::cmp::Ordering::Less; }
            let k = read_le64(key_data, 0);
            fs_key_cmp(k, target)
        },
    )
}

/// Create a file extent record.
fn create_file_extent(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    private_id: u64, logical_addr: u64, phys_block: u64, length: u64,
) -> Option<u64> {
    // Key: j_file_extent_key_t = obj_id_and_type(8) + logical_addr(8)
    let mut key = [0u8; 16];
    write_le64(&mut key, 0, make_fs_key(private_id, APFS_TYPE_FILE_EXTENT));
    write_le64(&mut key, 8, logical_addr);

    // Value: j_file_extent_val_t = len_and_flags(8) + phys_block_num(8) + crypto_id(8)
    let mut val = [0u8; 24];
    write_le64(&mut val, 0, length); // len_and_flags (no flags)
    write_le64(&mut val, 8, phys_block);
    write_le64(&mut val, 16, 0); // crypto_id = 0

    fs_tree_insert(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid,
        &key, &val)
}

/// Delete all file extent records for a given private_id.
/// Returns the new fs root block, or the original if no extents found.
fn delete_all_file_extents(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, mut fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64, private_id: u64,
) -> u64 {
    // Repeatedly delete extent records until none remain.
    for _ in 0..256 {
        let target = make_fs_key(private_id, APFS_TYPE_FILE_EXTENT);
        let result = fs_tree_delete(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid,
            &|key_data: &[u8]| {
                if key_data.len() < 8 { return core::cmp::Ordering::Less; }
                let k = read_le64(key_data, 0);
                let k_id = fs_key_obj_id(k);
                let k_type = fs_key_type(k);
                if k_id == private_id && k_type == APFS_TYPE_FILE_EXTENT {
                    core::cmp::Ordering::Equal
                } else if k_id < private_id || (k_id == private_id && (k_type as u64) < APFS_TYPE_FILE_EXTENT as u64) {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Greater
                }
            },
        );
        match result {
            Some(new_root) => fs_root_block = new_root,
            None => break,
        }
    }
    fs_root_block
}

/// Update an inode record (delete + re-insert).
fn update_inode_record(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, mut fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    inode: &ApfsInode,
) -> Option<u64> {
    // Delete old inode record.
    if let Some(new_root) = delete_inode_record(blk, bs, vol_omap_phys, fs_root_block,
        fs_root_oid, max_xid, inode.ino) {
        fs_root_block = new_root;
    }
    // Re-insert with updated fields.
    let is_dir = inode.is_dir();
    let mut key = [0u8; 8];
    write_le64(&mut key, 0, make_fs_key(inode.ino, APFS_TYPE_INODE));

    let now = apfs_now();
    let (xfield_hdr_size, xfield_data_size, num_xfields) = if is_dir {
        (0, 0, 0u16)
    } else {
        (8, 40, 1u16) // 4 (blob hdr) + 4 (x_field_t) + 40 (dstream)
    };
    let val_len = IVAL_XFIELDS + xfield_hdr_size + xfield_data_size;
    let mut val = [0u8; 256];

    write_le64(&mut val, IVAL_PARENT_ID, inode.parent_id);
    write_le64(&mut val, IVAL_PRIVATE_ID, inode.private_id);
    write_le64(&mut val, IVAL_CREATE_TIME, now);
    write_le64(&mut val, IVAL_MOD_TIME, now);
    write_le64(&mut val, IVAL_CHANGE_TIME, now);
    write_le64(&mut val, IVAL_ACCESS_TIME, now);
    write_le64(&mut val, IVAL_INTERNAL_FLAGS, 0);
    write_le32(&mut val, IVAL_NCHILDREN_NLINK, inode.nlink);
    write_le32(&mut val, IVAL_DEFAULT_PROT_CLASS, 0);
    write_le32(&mut val, IVAL_WRITE_GEN_COUNTER, 1);
    write_le32(&mut val, IVAL_BSD_FLAGS, 0);
    write_le32(&mut val, IVAL_OWNER, inode.owner);
    write_le32(&mut val, IVAL_GROUP, inode.group);
    write_le16(&mut val, IVAL_MODE, inode.mode);
    write_le16(&mut val, IVAL_PAD1, 0);
    write_le64(&mut val, IVAL_UNCOMPRESSED_SIZE, 0);

    if !is_dir && num_xfields > 0 {
        let xf = IVAL_XFIELDS;
        write_le16(&mut val, xf, num_xfields);
        write_le16(&mut val, xf + 2, xfield_data_size as u16);
        val[xf + 4] = INO_EXT_TYPE_DSTREAM;
        val[xf + 5] = 0;
        write_le16(&mut val, xf + 6, 40);
        // dstream: size, alloced_size, ...
        let ds = xf + 8;
        write_le64(&mut val, ds + DSTREAM_SIZE, inode.size);
        let alloced = ((inode.size + 4095) / 4096) * 4096;
        write_le64(&mut val, ds + DSTREAM_ALLOCED_SIZE, alloced);
    }

    fs_tree_insert(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid,
        &key, &val[..val_len])
}

/// Update parent directory's nchildren count.
fn update_parent_nchildren(
    blk: &BlkClient, bs: u32, vol_omap_phys: u64, fs_root_block: u64,
    fs_root_oid: u64, max_xid: u64,
    parent_ino: u64, delta: i32,
) -> Option<u64> {
    let mut parent = read_inode(blk, bs, vol_omap_phys, fs_root_block, max_xid, parent_ino)?;
    parent.nlink = ((parent.nlink as i32) + delta) as u32;
    update_inode_record(blk, bs, vol_omap_phys, fs_root_block, fs_root_oid, max_xid, &parent)
}

// =====================================================================
// Checkpoint commit
// =====================================================================

/// Flush all metadata to disk: bitmap, space manager, CIB, container superblock.
fn checkpoint_commit(blk: &BlkClient, bs: u32, nx_buf_block: u64) -> bool {
    let wva = unsafe { WRITE_VA };

    // 1. Flush allocation bitmap.
    if !flush_bitmap(blk, bs) {
        syscall::debug_puts(b"  [apfs_srv] bitmap flush failed\n");
        return false;
    }

    // 2. Update CIB free count.
    let cib_block = unsafe { CIB_BLOCK };
    if cib_block != 0 {
        if !blk.read_block(cib_block, bs, wva) {
            return false;
        }
        let mbuf = unsafe {
            core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize)
        };
        // Update ci_free_count in first chunk_info_t.
        let free_count = unsafe { ALLOC_FREE } as u32;
        write_le32(mbuf, CIB_CHUNKS_OFF + 20, free_count);
        // Update o_xid.
        let xid = unsafe { NX_NEXT_XID };
        write_le64(mbuf, 16, xid);
        // Update ci_xid.
        write_le64(mbuf, CIB_CHUNKS_OFF, xid);
        stamp_checksum(wva, bs);
        cache_invalidate(cib_block);
        if !blk.write_block(cib_block, bs, wva) {
            return false;
        }
    }

    // 3. Update space manager free count.
    let sm_block = unsafe { SPACEMAN_BLOCK };
    if sm_block != 0 {
        if !blk.read_block(sm_block, bs, wva) {
            return false;
        }
        let mbuf = unsafe {
            core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize)
        };
        let free_count = unsafe { ALLOC_FREE };
        write_le64(mbuf, SM_DEV_OFF + SD_FREE_COUNT_OFF, free_count);
        let xid = unsafe { NX_NEXT_XID };
        write_le64(mbuf, 16, xid);
        stamp_checksum(wva, bs);
        cache_invalidate(sm_block);
        if !blk.write_block(sm_block, bs, wva) {
            return false;
        }
    }

    // 4. Update container superblock (block 0).
    if !blk.read_block(0, bs, wva) {
        return false;
    }
    let mbuf = unsafe {
        core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize)
    };
    let xid = unsafe { NX_NEXT_XID };
    let next_oid = unsafe { NX_NEXT_OID };
    write_le64(mbuf, 16, xid); // o_xid
    write_le64(mbuf, NX_NEXT_OID_OFF, next_oid);
    write_le64(mbuf, NX_NEXT_XID_OFF, xid + 1);
    stamp_checksum(wva, bs);
    cache_invalidate(0);
    if !blk.write_block(0, bs, wva) {
        return false;
    }

    // Advance XID for next transaction.
    unsafe { NX_NEXT_XID = xid + 1; }

    true
}

/// Update the volume superblock with current file/dir counts.
fn update_volume_superblock(
    blk: &BlkClient, bs: u32, vol_phys_block: u64,
    num_files_delta: i64, num_dirs_delta: i64,
) -> bool {
    let wva = unsafe { WRITE_VA };
    if !blk.read_block(vol_phys_block, bs, wva) {
        return false;
    }
    let mbuf = unsafe {
        core::slice::from_raw_parts_mut(wva as *mut u8, bs as usize)
    };

    // Update counts.
    if num_files_delta != 0 {
        let cur = read_le64(mbuf, APFS_NUM_FILES_OFF) as i64;
        write_le64(mbuf, APFS_NUM_FILES_OFF, (cur + num_files_delta).max(0) as u64);
    }
    if num_dirs_delta != 0 {
        let cur = read_le64(mbuf, APFS_NUM_DIRS_OFF) as i64;
        write_le64(mbuf, APFS_NUM_DIRS_OFF, (cur + num_dirs_delta).max(0) as u64);
    }

    // Update next_obj_id.
    let next_obj = unsafe { VOL_NEXT_OBJ_ID };
    write_le64(mbuf, APFS_NEXT_OBJ_ID_OFF, next_obj);

    // Update o_xid.
    let xid = unsafe { NX_NEXT_XID };
    write_le64(mbuf, 16, xid);

    stamp_checksum(wva, bs);
    cache_invalidate(vol_phys_block);
    blk.write_block(vol_phys_block, bs, wva)
}

// =====================================================================
// Container superblock parsing
// =====================================================================

// nx_superblock_t field offsets (all little-endian):
// obj_phys_t: 0..31 (32 bytes)
// nx_magic: 32..35
// nx_block_size: 36..39
// nx_block_count: 40..47
// nx_features: 48..55
// nx_readonly_compatible_features: 56..63
// nx_incompatible_features: 64..71
// nx_uuid: 72..87
// nx_next_oid: 88..95
// nx_next_xid: 96..103
// nx_xp_desc_blocks: 104..107
// nx_xp_data_blocks: 108..111
// nx_xp_desc_base: 112..119
// nx_xp_data_base: 120..127
// nx_xp_desc_next: 128..131
// nx_xp_data_next: 132..135
// nx_xp_desc_index: 136..139
// nx_xp_desc_len: 140..143
// nx_xp_data_index: 144..147
// nx_xp_data_len: 148..151
// nx_spaceman_oid: 152..159
// nx_omap_oid: 160..167
// nx_reaper_oid: 168..175
// nx_test_type: 176..179
// nx_max_file_systems: 180..183
// nx_fs_oid[0..NX_MAX_FILE_SYSTEMS]: 184..

const NX_MAGIC_OFF: usize = 32;
const NX_BLOCK_SIZE_OFF: usize = 36;
const NX_BLOCK_COUNT_OFF: usize = 40;
const NX_XP_DESC_BLOCKS_OFF: usize = 104;
const NX_XP_DATA_BLOCKS_OFF: usize = 108;
const NX_XP_DESC_BASE_OFF: usize = 112;
const NX_XP_DATA_BASE_OFF: usize = 120;
const NX_XP_DESC_INDEX_OFF: usize = 136;
const NX_XP_DESC_LEN_OFF: usize = 140;
const NX_XP_DATA_INDEX_OFF: usize = 144;
const NX_XP_DATA_LEN_OFF: usize = 148;
const NX_OMAP_OID_OFF: usize = 160;
const NX_MAX_FS_OFF: usize = 180;
const NX_FS_OID_OFF: usize = 184;

fn parse_nx_superblock(buf: &[u8]) -> Option<NxSuperblock> {
    let magic = read_le32(buf, NX_MAGIC_OFF);
    if magic != NX_MAGIC {
        return None;
    }

    let xid = read_le64(buf, 16); // o_xid at offset 16

    let mut fs_oid = [0u64; 4];
    for i in 0..4 {
        fs_oid[i] = read_le64(buf, NX_FS_OID_OFF + i * 8);
    }

    Some(NxSuperblock {
        block_size: read_le32(buf, NX_BLOCK_SIZE_OFF),
        block_count: read_le64(buf, NX_BLOCK_COUNT_OFF),
        omap_oid: read_le64(buf, NX_OMAP_OID_OFF),
        xp_desc_base: read_le64(buf, NX_XP_DESC_BASE_OFF),
        xp_desc_blocks: read_le32(buf, NX_XP_DESC_BLOCKS_OFF),
        xp_desc_len: read_le32(buf, NX_XP_DESC_LEN_OFF),
        xp_desc_index: read_le32(buf, NX_XP_DESC_INDEX_OFF),
        xp_data_base: read_le64(buf, NX_XP_DATA_BASE_OFF),
        xp_data_blocks: read_le32(buf, NX_XP_DATA_BLOCKS_OFF),
        xp_data_len: read_le32(buf, NX_XP_DATA_LEN_OFF),
        xp_data_index: read_le32(buf, NX_XP_DATA_INDEX_OFF),
        xid,
        fs_oid,
    })
}

// =====================================================================
// Checkpoint scanning — find the latest valid container superblock
// =====================================================================

/// Cached spaceman physical block address, set during checkpoint scan.
static mut SPACEMAN_PHYS_FROM_CKPT: u64 = 0;

fn find_latest_checkpoint(blk: &BlkClient, block0: &NxSuperblock) -> Option<NxSuperblock> {
    let bs = block0.block_size;
    let desc_base = block0.xp_desc_base;
    // High bit of xp_desc_blocks is a flag; mask it off for the count.
    let desc_blocks = block0.xp_desc_blocks & 0x7FFFFFFF;

    // Read spaceman_oid from container superblock for checkpoint mapping resolution.
    // nx_spaceman_oid is at offset 152.
    let spaceman_oid = {
        let b0 = match cache_read_slice(blk, 0, bs) {
            Some(b) => b,
            None => &[],
        };
        if b0.len() > 160 { read_le64(b0, 152) } else { 0 }
    };

    if desc_blocks == 0 || desc_blocks > 1024 {
        // Fallback: use block 0 as-is.
        return Some(*block0);
    }

    let mut best_xid: u64 = 0;
    let mut best = *block0;

    for i in 0..desc_blocks {
        let blk_num = desc_base + i as u64;
        let buf = match cache_read_slice(blk, blk_num, bs) {
            Some(b) => b,
            None => continue,
        };

        let o_type = read_le32(buf, 24); // o_type at offset 24
        let obj_type = o_type & OBJECT_TYPE_MASK;

        // Parse checkpoint mapping blocks to find spaceman physical address.
        if obj_type == 0x0c && spaceman_oid != 0 {
            let cpm_count = read_le32(buf, 36) as usize;
            for j in 0..cpm_count {
                let base = 40 + j * 40;
                if base + 40 > bs as usize {
                    break;
                }
                let cpm_oid = read_le64(buf, base + 24);
                if cpm_oid == spaceman_oid {
                    unsafe { SPACEMAN_PHYS_FROM_CKPT = read_le64(buf, base + 32); }
                    break;
                }
            }
        }

        // Check if this is an nx_superblock_t (type = OBJECT_TYPE_NX_SUPERBLOCK)
        if obj_type != OBJECT_TYPE_NX_SUPERBLOCK {
            continue;
        }

        let magic = read_le32(buf, NX_MAGIC_OFF);
        if magic != NX_MAGIC {
            continue;
        }

        let xid = read_le64(buf, 16); // o_xid
        if xid > best_xid {
            if let Some(sb) = parse_nx_superblock(buf) {
                best_xid = xid;
                best = sb;
            }
        }
    }

    if best_xid == 0 {
        // No checkpoint found, use block 0.
        Some(*block0)
    } else {
        Some(best)
    }
}

// =====================================================================
// Object map (omap) B-tree lookup
// =====================================================================

// omap_phys_t field offsets:
// obj_phys_t: 0..31
// om_flags: 32..35
// om_snap_count: 36..39
// om_tree_type: 40..43
// om_snapshot_tree_type: 44..47
// om_tree_oid: 48..55
// om_snapshot_tree_oid: 56..63
// om_most_recent_snap: 64..71
// om_pending_revert_min: 72..79
// om_pending_revert_max: 80..87
const OMAP_TREE_OID_OFF: usize = 48;

/// Look up a virtual OID in an object map, returning the physical block address.
/// The omap B-tree uses fixed-size 16-byte keys (oid u64, xid u64) and
/// 16-byte values (flags u32, size u32, paddr u64).
fn omap_lookup(blk: &BlkClient, bs: u32, omap_phys_block: u64, oid: u64, max_xid: u64) -> Option<u64> {
    // Read the omap_phys_t header to get the B-tree root OID.
    let omap_buf = cache_read_slice(blk, omap_phys_block, bs)?;
    let tree_oid = read_le64(omap_buf, OMAP_TREE_OID_OFF);

    // The omap tree root is a physical object — tree_oid is a physical block number.
    omap_btree_lookup(blk, bs, tree_oid, oid, max_xid)
}

fn omap_btree_lookup(blk: &BlkClient, bs: u32, root_block: u64, oid: u64, max_xid: u64) -> Option<u64> {
    let mut cur_block = root_block;

    // Walk down the B-tree (max 8 levels).
    for _depth in 0..8 {
        let buf = cache_read_slice(blk, cur_block, bs)?;

        let flags = read_le16(buf, BTN_FLAGS_OFF);
        let level = read_le16(buf, BTN_LEVEL_OFF);
        let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
        let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
        let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;

        let data_base = BTN_DATA_OFF;
        let toc_base = data_base + toc_off;
        let key_base = data_base + toc_off + toc_len;

        // Value area ends at block_size for non-root, or block_size - BTREE_INFO_SIZE for root.
        let val_end = if (flags & BTNODE_ROOT) != 0 {
            bs as usize - BTREE_INFO_SIZE
        } else {
            bs as usize
        };

        let is_leaf = (flags & BTNODE_LEAF) != 0 || level == 0;
        let fixed_kv = (flags & BTNODE_FIXED_KV_SIZE) != 0;

        if is_leaf {
            // Search for the best matching key: same oid, highest xid <= max_xid.
            let mut best_paddr: Option<u64> = None;
            let mut best_xid: u64 = 0;

            for i in 0..nkeys {
                let (k_off, v_off) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
                } else {
                    let toc_entry = toc_base + i * 8;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 4) as usize)
                };

                let key_start = key_base + k_off;
                if key_start + 16 > bs as usize {
                    continue;
                }
                let k_oid = read_le64(buf, key_start);
                let k_xid = read_le64(buf, key_start + 8);

                if k_oid == oid && k_xid <= max_xid && k_xid > best_xid {
                    // Value: flags(4) + size(4) + paddr(8)
                    let val_start = val_end - v_off;
                    if val_start >= 16 {
                        let paddr = read_le64(buf, val_start + 8);
                        best_paddr = Some(paddr);
                        best_xid = k_xid;
                    }
                }
            }
            return best_paddr;
        } else {
            // Internal node: find the child to descend into.
            // Keys are sorted by (oid, xid). Find the last key <= (oid, max_xid).
            let mut child_idx = 0;
            for i in 0..nkeys {
                let (k_off, v_off) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
                } else {
                    let toc_entry = toc_base + i * 8;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 4) as usize)
                };

                let key_start = key_base + k_off;
                if key_start + 16 > bs as usize {
                    continue;
                }
                let k_oid = read_le64(buf, key_start);
                let k_xid = read_le64(buf, key_start + 8);

                if k_oid < oid || (k_oid == oid && k_xid <= max_xid) {
                    child_idx = i;
                } else if k_oid > oid {
                    break;
                }
            }

            // Read child OID from value.
            let (_, v_off) = if fixed_kv {
                let toc_entry = toc_base + child_idx * 4;
                (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
            } else {
                let toc_entry = toc_base + child_idx * 8;
                (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 4) as usize)
            };

            let val_start = val_end - v_off;
            // Child OID is at start of value (u64).
            let child_oid = read_le64(buf, val_start);
            // omap tree is physical — child OID is a physical block number.
            cur_block = child_oid;
        }
    }

    None // too deep
}

// =====================================================================
// File-system B-tree operations
// =====================================================================

/// Compose a j_key_t value from an object ID and type.
fn make_fs_key(obj_id: u64, obj_type: u8) -> u64 {
    (obj_id & OBJ_ID_MASK) | ((obj_type as u64) << OBJ_TYPE_SHIFT)
}

/// Extract object ID from a j_key_t.
fn fs_key_obj_id(key: u64) -> u64 {
    key & OBJ_ID_MASK
}

/// Extract object type from a j_key_t.
fn fs_key_type(key: u64) -> u8 {
    ((key & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) as u8
}

/// Compare two j_key_t values: first by obj_id (low 60 bits), then by type (high 4 bits).
/// APFS sorts records by obj_id first, type second — raw u64 compare is wrong because
/// the type is in the high bits.
fn fs_key_cmp(a: u64, b: u64) -> core::cmp::Ordering {
    let a_id = a & OBJ_ID_MASK;
    let b_id = b & OBJ_ID_MASK;
    match a_id.cmp(&b_id) {
        core::cmp::Ordering::Equal => {
            let a_type = (a >> OBJ_TYPE_SHIFT) & 0xF;
            let b_type = (b >> OBJ_TYPE_SHIFT) & 0xF;
            a_type.cmp(&b_type)
        }
        other => other,
    }
}

/// Search the file-system B-tree for a specific record.
/// The fs tree uses virtual OIDs for child nodes (needs omap lookup).
/// Keys are variable-length j_key_t-prefixed records.
/// Returns: (key_bytes_va, key_len, val_bytes_va, val_len) in cache memory.
///
/// `match_fn` receives (key_buf, key_len) and returns:
///   Ordering::Equal => found, return this record
///   Ordering::Less => target is after this key
///   Ordering::Greater => target is before this key
fn fs_tree_lookup<F>(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    root_block: u64,
    max_xid: u64,
    match_fn: &F,
) -> Option<(usize, usize, usize, usize)>
where
    F: Fn(&[u8]) -> core::cmp::Ordering,
{
    let mut cur_block = root_block;

    for _depth in 0..8 {
        let buf = cache_read_slice(blk, cur_block, bs)?;

        let flags = read_le16(buf, BTN_FLAGS_OFF);
        let level = read_le16(buf, BTN_LEVEL_OFF);
        let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
        let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
        let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;

        let data_base = BTN_DATA_OFF;
        let toc_base = data_base + toc_off;
        let key_base = data_base + toc_off + toc_len;

        let val_end = if (flags & BTNODE_ROOT) != 0 {
            bs as usize - BTREE_INFO_SIZE
        } else {
            bs as usize
        };

        let is_leaf = (flags & BTNODE_LEAF) != 0 || level == 0;
        let fixed_kv = (flags & BTNODE_FIXED_KV_SIZE) != 0;

        if is_leaf {
            // Scan leaf for matching key.
            for i in 0..nkeys {
                let (k_off, k_len, v_off, v_len) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    let ko = read_le16(buf, toc_entry) as usize;
                    let vo = read_le16(buf, toc_entry + 2) as usize;
                    // Fixed-size — get sizes from btree_info
                    (ko, 8usize, vo, 8usize) // minimal for j_key_t
                } else {
                    let toc_entry = toc_base + i * 8;
                    let ko = read_le16(buf, toc_entry) as usize;
                    let kl = read_le16(buf, toc_entry + 2) as usize;
                    let vo = read_le16(buf, toc_entry + 4) as usize;
                    let vl = read_le16(buf, toc_entry + 6) as usize;
                    (ko, kl, vo, vl)
                };

                let key_start = key_base + k_off;
                if key_start + k_len > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + k_len];

                match match_fn(key_data) {
                    core::cmp::Ordering::Equal => {
                        let val_start = val_end - v_off;
                        if val_start < v_len {
                            continue;
                        }
                        let va_base = buf.as_ptr() as usize;
                        return Some((
                            va_base + key_start,
                            k_len,
                            va_base + val_start,
                            v_len,
                        ));
                    }
                    core::cmp::Ordering::Greater => {
                        // We've passed the target, stop.
                        return None;
                    }
                    core::cmp::Ordering::Less => {
                        // Keep scanning.
                    }
                }
            }
            return None;
        } else {
            // Internal node: find child to descend into.
            // Non-leaf nodes in fs tree have BTNODE_FIXED_KV_SIZE set (keys are j_key_t,
            // values are oid_t). But the tree itself may use virtual OIDs for children.
            let mut child_idx = 0usize;
            let nk = nkeys;
            for i in 0..nk {
                let (k_off, _k_len) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    (read_le16(buf, toc_entry) as usize, 8usize)
                } else {
                    let toc_entry = toc_base + i * 8;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
                };

                let key_start = key_base + k_off;
                if key_start + 8 > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + 8]; // only compare j_key_t header

                match match_fn(key_data) {
                    core::cmp::Ordering::Less | core::cmp::Ordering::Equal => {
                        child_idx = i;
                    }
                    core::cmp::Ordering::Greater => {
                        break;
                    }
                }
            }

            // Get child OID from value.
            let v_off = if fixed_kv {
                let toc_entry = toc_base + child_idx * 4;
                read_le16(buf, toc_entry + 2) as usize
            } else {
                let toc_entry = toc_base + child_idx * 8;
                read_le16(buf, toc_entry + 4) as usize
            };

            let val_start = val_end - v_off;
            let child_oid = read_le64(buf, val_start);

            // fs tree children are virtual objects — resolve via omap.
            cur_block = omap_lookup(blk, bs, vol_omap_phys, child_oid, max_xid)?;
        }
    }

    None
}

/// Iterate over all records in a B-tree leaf range matching a prefix.
/// Calls `callback(key_slice, val_slice)` for each matching record.
/// Returns false to stop iteration.
/// `prefix_match` returns true for keys that should be visited.
fn fs_tree_iterate<P, C>(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    root_block: u64,
    max_xid: u64,
    skip_count: usize,
    prefix_match: &P,
    callback: &mut C,
) -> bool
where
    P: Fn(&[u8]) -> core::cmp::Ordering,  // Less = before range, Equal = in range, Greater = past range
    C: FnMut(&[u8], &[u8], usize) -> bool, // (key, val, index) -> continue?
{
    // For iteration, we walk to the leftmost leaf containing our range,
    // then scan forward through the leaf.
    let mut cur_block = root_block;

    // Descend to leftmost matching leaf.
    for _depth in 0..8 {
        let buf = cache_read_slice(blk, cur_block, bs);
        let buf = match buf {
            Some(b) => b,
            None => return false,
        };

        let flags = read_le16(buf, BTN_FLAGS_OFF);
        let level = read_le16(buf, BTN_LEVEL_OFF);
        let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
        let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
        let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;

        let data_base = BTN_DATA_OFF;
        let toc_base = data_base + toc_off;
        let key_base = data_base + toc_off + toc_len;
        let val_end = if (flags & BTNODE_ROOT) != 0 {
            bs as usize - BTREE_INFO_SIZE
        } else {
            bs as usize
        };
        let is_leaf = (flags & BTNODE_LEAF) != 0 || level == 0;
        let fixed_kv = (flags & BTNODE_FIXED_KV_SIZE) != 0;

        if is_leaf {
            let mut index = 0usize;
            for i in 0..nkeys {
                let (k_off, k_len, v_off, v_len) = if fixed_kv {
                    let te = toc_base + i * 4;
                    (read_le16(buf, te) as usize, 8, read_le16(buf, te + 2) as usize, 8)
                } else {
                    let te = toc_base + i * 8;
                    (
                        read_le16(buf, te) as usize,
                        read_le16(buf, te + 2) as usize,
                        read_le16(buf, te + 4) as usize,
                        read_le16(buf, te + 6) as usize,
                    )
                };

                let key_start = key_base + k_off;
                if key_start + k_len > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + k_len];

                match prefix_match(key_data) {
                    core::cmp::Ordering::Less => continue,
                    core::cmp::Ordering::Greater => return true,
                    core::cmp::Ordering::Equal => {
                        if index >= skip_count {
                            let val_start = val_end - v_off;
                            if val_start + v_len <= bs as usize {
                                let val_data = &buf[val_start..val_start + v_len];
                                if !callback(key_data, val_data, index) {
                                    return false;
                                }
                            }
                        }
                        index += 1;
                    }
                }
            }
            return true;
        } else {
            // Internal node — descend to leftmost child in range.
            let mut child_idx = 0usize;
            for i in 0..nkeys {
                let k_off = if fixed_kv {
                    read_le16(buf, toc_base + i * 4) as usize
                } else {
                    read_le16(buf, toc_base + i * 8) as usize
                };
                let key_start = key_base + k_off;
                if key_start + 8 > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + 8];
                match prefix_match(key_data) {
                    core::cmp::Ordering::Less | core::cmp::Ordering::Equal => {
                        child_idx = i;
                    }
                    core::cmp::Ordering::Greater => break,
                }
            }

            let v_off = if fixed_kv {
                read_le16(buf, toc_base + child_idx * 4 + 2) as usize
            } else {
                read_le16(buf, toc_base + child_idx * 8 + 4) as usize
            };
            let val_start = val_end - v_off;
            let child_oid = read_le64(buf, val_start);
            cur_block = match omap_lookup(blk, bs, vol_omap_phys, child_oid, max_xid) {
                Some(b) => b,
                None => return false,
            };
        }
    }
    false
}

// =====================================================================
// Volume superblock parsing
// =====================================================================

// apfs_superblock_t field offsets:
// obj_phys_t: 0..31
// apfs_magic: 32..35
// apfs_fs_index: 36..39
// ...
// apfs_features: 64..71
// apfs_readonly_compatible_features: 72..79
// apfs_incompatible_features: 80..87
// ...
// apfs_omap_oid: 160..167  (after several uuid/counter fields)
// apfs_root_tree_oid: 168..175
// ...

const APFS_MAGIC_OFF: usize = 32;
const APFS_OMAP_OID_OFF: usize = 0x80;   // 128
const APFS_ROOT_TREE_OID_OFF: usize = 0x88; // 136

fn parse_volume(blk: &BlkClient, bs: u32, vol_phys_block: u64, xid: u64) -> Option<ApfsVolume> {
    let buf = cache_read_slice(blk, vol_phys_block, bs)?;

    let magic = read_le32(buf, APFS_MAGIC_OFF);
    if magic != APFS_MAGIC {
        syscall::debug_puts(b"  [apfs_srv] bad volume magic: ");
        print_hex(magic as u64);
        syscall::debug_puts(b"\n");
        return None;
    }

    Some(ApfsVolume {
        omap_oid: read_le64(buf, APFS_OMAP_OID_OFF),
        root_tree_oid: read_le64(buf, APFS_ROOT_TREE_OID_OFF),
        xid,
    })
}

// =====================================================================
// Inode reading
// =====================================================================

fn read_inode(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    ino: u64,
) -> Option<ApfsInode> {
    let target_key = make_fs_key(ino, APFS_TYPE_INODE);

    let (_, _, val_va, val_len) = fs_tree_lookup(blk, bs, vol_omap_phys, fs_root_block, max_xid,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            fs_key_cmp(k, target_key)
        },
    )?;

    if val_len < IVAL_XFIELDS {
        return None;
    }

    let val = unsafe { core::slice::from_raw_parts(val_va as *const u8, val_len) };

    let parent_id = read_le64(val, IVAL_PARENT_ID);
    let private_id = read_le64(val, IVAL_PRIVATE_ID);
    let nlink = read_le32(val, IVAL_NCHILDREN_NLINK);
    let owner = read_le32(val, IVAL_OWNER);
    let group = read_le32(val, IVAL_GROUP);
    let mode = read_le16(val, IVAL_MODE);

    // Extract file size from dstream xfield if present.
    let mut size = 0u64;
    if val_len > IVAL_XFIELDS + 4 {
        // xf_blob_t header: xf_num_exts(u16), xf_used_data(u16)
        let xf_num = read_le16(val, IVAL_XFIELDS) as usize;
        // x_field_t array starts at IVAL_XFIELDS + 4, each entry 4 bytes
        let xft_base = IVAL_XFIELDS + 4;
        // Field data starts immediately after x_field_t array (no alignment gap)
        let data_base = xft_base + xf_num * 4;
        let mut data_pos = data_base;
        for i in 0..xf_num {
            let xft = xft_base + i * 4;
            if xft + 4 > val_len { break; }
            let x_type = val[xft];
            let x_size = read_le16(val, xft + 2) as usize;
            if data_pos + x_size > val_len { break; }
            if x_type == INO_EXT_TYPE_DSTREAM && x_size >= 8 {
                size = read_le64(val, data_pos + DSTREAM_SIZE);
            }
            data_pos += x_size;
            // Align field data to 8 bytes.
            data_pos = (data_pos + 7) & !7;
        }
    }

    Some(ApfsInode {
        ino,
        parent_id,
        private_id,
        mode,
        owner,
        group,
        nlink,
        size,
    })
}

// =====================================================================
// Directory operations
// =====================================================================

/// Look up a name in a directory, returning the child's inode number.
fn dir_lookup(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    dir_ino: u64,
    name: &[u8],
) -> Option<u64> {
    // Search for DIR_REC with matching name.
    // Key: j_key_t(8) + name_len_and_hash(4) + name(variable)
    // We match by obj_id == dir_ino, type == DIR_REC, and name comparison.
    let dir_key_min = make_fs_key(dir_ino, APFS_TYPE_DIR_REC);

    let mut found_ino: Option<u64> = None;

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, 0,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);

            if k_id < dir_ino || (k_id == dir_ino && (k_type as u64) < APFS_TYPE_DIR_REC as u64) {
                core::cmp::Ordering::Less
            } else if k_id == dir_ino && k_type == APFS_TYPE_DIR_REC {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], _idx: usize| -> bool {
            // Key: j_key_t(8) + name_len_and_hash(4) + name[]
            if key_data.len() < 12 || val_data.len() < 18 {
                return true;
            }
            let name_len_and_hash = read_le32(key_data, 8);
            let entry_name_len = (name_len_and_hash & 0x3FF) as usize;
            if entry_name_len == 0 {
                return true;
            }
            // Name starts at offset 12 in the key, length includes null terminator.
            let name_start = 12;
            let actual_name_len = if entry_name_len > 0 { entry_name_len - 1 } else { 0 }; // strip null
            if name_start + actual_name_len > key_data.len() {
                return true;
            }
            let entry_name = &key_data[name_start..name_start + actual_name_len];

            if entry_name.len() == name.len() && entry_name == name {
                // Value: file_id(8) + date_added(8) + flags(2)
                let file_id = read_le64(val_data, 0);
                found_ino = Some(file_id);
                return false; // stop
            }
            true // continue
        },
    );

    found_ino
}

/// Iterate directory entries starting at `offset` (entry index).
/// Calls callback with (name, name_len, ino, ftype, next_offset).
/// Returns (name, ino, ftype, next_offset) for the next entry, or None.
fn dir_next_entry(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    dir_ino: u64,
    offset: usize,
) -> Option<([u8; 256], usize, u64, u8, usize)> {
    let mut result: Option<([u8; 256], usize, u64, u8, usize)> = None;

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, offset,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);
            if k_id < dir_ino || (k_id == dir_ino && (k_type as u64) < APFS_TYPE_DIR_REC as u64) {
                core::cmp::Ordering::Less
            } else if k_id == dir_ino && k_type == APFS_TYPE_DIR_REC {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], idx: usize| -> bool {
            if key_data.len() < 12 || val_data.len() < 18 {
                return false;
            }
            let name_len_and_hash = read_le32(key_data, 8);
            let entry_name_len = (name_len_and_hash & 0x3FF) as usize;
            let actual_name_len = if entry_name_len > 0 { entry_name_len - 1 } else { 0 };
            if actual_name_len == 0 || 12 + actual_name_len > key_data.len() {
                return false;
            }

            let mut name_buf = [0u8; 256];
            let copy_len = actual_name_len.min(255);
            name_buf[..copy_len].copy_from_slice(&key_data[12..12 + copy_len]);

            let file_id = read_le64(val_data, 0);
            let flags = read_le16(val_data, 16);
            let ftype = (flags & DREC_TYPE_MASK) as u8;

            result = Some((name_buf, copy_len, file_id, ftype, idx + 1));
            false // stop after first
        },
    );

    result
}

// =====================================================================
// File extent resolution
// =====================================================================

/// Resolve file data at a given byte offset.
/// Returns (physical_block, offset_in_block, extent_remaining_bytes).
fn resolve_file_extent(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    private_id: u64,
    file_offset: u64,
) -> Option<(u64, u32, u64)> {
    // Search for FILE_EXTENT records for this private_id.
    // We need the extent whose logical_addr <= file_offset < logical_addr + len.
    let mut best: Option<(u64, u64, u64)> = None; // (logical_addr, phys_block, len_bytes)

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, 0,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);
            if k_id < private_id || (k_id == private_id && (k_type as u64) < APFS_TYPE_FILE_EXTENT as u64) {
                core::cmp::Ordering::Less
            } else if k_id == private_id && k_type == APFS_TYPE_FILE_EXTENT {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], _idx: usize| -> bool {
            // Key: j_key_t(8) + logical_addr(8)
            if key_data.len() < 16 || val_data.len() < 24 {
                return true;
            }
            let logical_addr = read_le64(key_data, 8);
            let len_and_flags = read_le64(val_data, 0);
            let extent_len = len_and_flags & 0x00ffffffffffffffu64;
            let phys_block = read_le64(val_data, 8);

            if logical_addr <= file_offset && file_offset < logical_addr + extent_len {
                best = Some((logical_addr, phys_block, extent_len));
                return false; // found it
            }
            if logical_addr > file_offset {
                return false; // past our target
            }
            true // keep looking
        },
    );

    let (logical_addr, phys_block, extent_len) = best?;
    let offset_in_extent = file_offset - logical_addr;
    let block_offset = offset_in_extent / bs as u64;
    let offset_in_block = (offset_in_extent % bs as u64) as u32;
    let remaining = extent_len - offset_in_extent;
    Some((phys_block + block_offset, offset_in_block, remaining))
}

// =====================================================================
// Extended attribute (xattr) reading — for symlinks
// =====================================================================

/// Read an extended attribute value by name. Returns data copied into `out`.
fn read_xattr(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    ino: u64,
    attr_name: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut result: Option<usize> = None;

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, 0,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);
            if k_id < ino || (k_id == ino && (k_type as u64) < APFS_TYPE_XATTR as u64) {
                core::cmp::Ordering::Less
            } else if k_id == ino && k_type == APFS_TYPE_XATTR {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], _idx: usize| -> bool {
            // Key: j_key_t(8) + name_len(2) + name[]
            if key_data.len() < 10 || val_data.len() < 4 {
                return true;
            }
            let name_len = read_le16(key_data, 8) as usize;
            let actual_len = if name_len > 0 { name_len - 1 } else { 0 }; // strip null
            if 10 + actual_len > key_data.len() {
                return true;
            }
            let entry_name = &key_data[10..10 + actual_len];

            if entry_name == attr_name {
                // Value: flags(2) + xdata_len(2) + xdata[]
                let flags = read_le16(val_data, 0);
                let xdata_len = read_le16(val_data, 2) as usize;

                if (flags & XATTR_DATA_EMBEDDED) != 0 && xdata_len > 0 {
                    let copy_len = xdata_len.min(out.len()).min(val_data.len() - 4);
                    out[..copy_len].copy_from_slice(&val_data[4..4 + copy_len]);
                    result = Some(copy_len);
                }
                return false; // stop
            }
            true
        },
    );

    result
}

/// Read symlink target. APFS stores symlink targets as xattr "com.apple.fs.symlink".
fn read_symlink_target(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    ino: u64,
    out: &mut [u8],
) -> Option<usize> {
    read_xattr(blk, bs, vol_omap_phys, fs_root_block, max_xid, ino,
        b"com.apple.fs.symlink", out)
}

// =====================================================================
// Path resolution
// =====================================================================

fn path_resolve(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    path: &[u8],
) -> Option<ApfsInode> {
    let mut cur_ino = ROOT_DIR_INO_NUM;
    let mut cur_inode = read_inode(blk, bs, vol_omap_phys, fs_root_block, max_xid, cur_ino)?;

    if path.is_empty() {
        return Some(cur_inode);
    }

    let mut start = 0usize;
    while start < path.len() {
        // Skip slashes.
        if path[start] == b'/' {
            start += 1;
            continue;
        }
        // Find end of component.
        let mut end = start;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        let component = &path[start..end];

        // APFS doesn't store "." and ".." as real directory entries.
        if component == b"." {
            start = end;
            continue;
        }
        if component == b".." {
            // Navigate to parent.
            cur_ino = cur_inode.parent_id;
            cur_inode = read_inode(blk, bs, vol_omap_phys, fs_root_block, max_xid, cur_ino)?;
            start = end;
            continue;
        }

        if !cur_inode.is_dir() {
            return None;
        }

        cur_ino = dir_lookup(blk, bs, vol_omap_phys, fs_root_block, max_xid, cur_ino, component)?;
        cur_inode = read_inode(blk, bs, vol_omap_phys, fs_root_block, max_xid, cur_ino)?;
        start = end;
    }

    Some(cur_inode)
}

// =====================================================================
// Main server
// =====================================================================

// Global volume state (set once during mount).
static mut VOL_OMAP_PHYS: u64 = 0;
static mut FS_ROOT_BLOCK: u64 = 0;
static mut MAX_XID: u64 = u64::MAX;
static mut BLOCK_SIZE: u32 = 4096;
static mut BLOCK_COUNT: u64 = 0;

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [apfs_srv] starting\n");

    // arg0 encoding: low 48 bits = partition byte offset, high 16 bits = blk_port
    let partition_offset = arg0 & 0x0000_FFFF_FFFF_FFFF;
    let passed_blk_port = arg0 >> 48;

    syscall::debug_puts(b"  [apfs_srv] partition offset=");
    print_num(partition_offset);
    syscall::debug_puts(b" blk_hint=");
    print_num(passed_blk_port);
    syscall::debug_puts(b"\n");

    // Create port. Registration deferred until after init completes.
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();

    // Use blk_port passed by kernel via arg0 high bits.
    let blk_port = if passed_blk_port != 0 {
        syscall::debug_puts(b"  [apfs_srv] using blk port=");
        print_num(passed_blk_port);
        syscall::debug_puts(b"\n");
        passed_blk_port
    } else {
        syscall::debug_puts(b"  [apfs_srv] no blk port passed, exiting\n");
        syscall::exit(1);
        0 // unreachable
    };
    // Connect directly to blk_srv using non-blocking send + poll recv.
    syscall::debug_puts(b"  [apfs_srv] connecting to blk_srv...\n");
    let blk_reply = syscall::port_create();
    let blk_aspace = {
        let d2 = 3u64 | ((blk_reply as u64) << 32);
        // Retry the send until it succeeds.
        let mut send_ok = false;
        for _ in 0..10000u32 {
            let sr = syscall::send_nb_4(blk_port, IO_CONNECT, 0, 0, d2, 0);
            if sr == 0 {
                send_ok = true;
                break;
            }
            syscall::yield_now();
        }
        if !send_ok {
            syscall::debug_puts(b"  [apfs_srv] connect send failed\n");
            loop { core::hint::spin_loop(); }
        }
        // Poll for reply.
        let mut aspace = 0u64;
        for _ in 0..50000u32 {
            if let Some(reply) = syscall::recv_nb_msg(blk_reply) {
                if reply.tag == IO_CONNECT_OK {
                    aspace = reply.data[2];
                } else {
                    syscall::debug_puts(b"  [apfs_srv] blk connect FAILED tag=");
                    print_num(reply.tag);
                    syscall::debug_puts(b"\n");
                    loop { core::hint::spin_loop(); }
                }
                break;
            }
            syscall::yield_now();
        }
        if aspace == 0 {
            syscall::debug_puts(b"  [apfs_srv] blk connect timeout\n");
            loop { core::hint::spin_loop(); }
        }
        aspace
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [apfs_srv] scratch alloc FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x7_0000_0000,
        partition_offset,
    };

    syscall::debug_puts(b"  [apfs_srv] connected, aspace=");
    print_num(blk.blk_aspace);
    syscall::debug_puts(b"\n");

    // Initialize block cache.
    cache_init();

    // ---- Phase A: Read container superblock ----
    // APFS always uses 4096-byte blocks.
    let bs: u32 = 4096;
    let block0_buf = match cache_read_slice(&blk, 0, bs) {
        Some(b) if read_le32(b, NX_MAGIC_OFF) == NX_MAGIC => b,
        _ => {
            syscall::debug_puts(b"  [apfs_srv] no APFS container found, exiting\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    let nx_sb = match parse_nx_superblock(block0_buf) {
        Some(s) => s,
        None => {
            syscall::debug_puts(b"  [apfs_srv] invalid container superblock\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] NX container: block_size=");
    print_num(bs as u64);
    syscall::debug_puts(b" blocks=");
    print_num(nx_sb.block_count);
    syscall::debug_puts(b" xid=");
    print_num(nx_sb.xid);
    syscall::debug_puts(b"\n");

    // ---- Phase A3: Checkpoint scanning ----
    syscall::debug_puts(b"  [apfs_srv] scanning checkpoints...\n");
    let nx_sb = match find_latest_checkpoint(&blk, &nx_sb) {
        Some(s) => s,
        None => {
            syscall::debug_puts(b"  [apfs_srv] checkpoint scan failed\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] latest checkpoint xid=");
    print_num(nx_sb.xid);
    syscall::debug_puts(b" omap_oid=");
    print_num(nx_sb.omap_oid);
    syscall::debug_puts(b" fs_oid[0]=");
    print_num(nx_sb.fs_oid[0]);
    syscall::debug_puts(b"\n");

    // ---- Phase C1: Mount first volume ----
    let vol_oid = nx_sb.fs_oid[0];
    if vol_oid == 0 {
        syscall::debug_puts(b"  [apfs_srv] no volume found\n");
        syscall::exit(1);
    }

    // Look up volume OID in container omap.
    let vol_phys_block = match omap_lookup(&blk, bs, nx_sb.omap_oid, vol_oid, nx_sb.xid) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] volume omap lookup failed for oid=");
            print_num(vol_oid);
            syscall::debug_puts(b"\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] volume at block ");
    print_num(vol_phys_block);
    syscall::debug_puts(b"\n");

    let volume = match parse_volume(&blk, bs, vol_phys_block, nx_sb.xid) {
        Some(v) => v,
        None => {
            syscall::debug_puts(b"  [apfs_srv] invalid volume superblock\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] volume omap_oid=");
    print_num(volume.omap_oid);
    syscall::debug_puts(b" root_tree_oid=");
    print_num(volume.root_tree_oid);
    syscall::debug_puts(b"\n");

    // Resolve fs tree root via volume omap.
    let fs_root_block = match omap_lookup(&blk, bs, volume.omap_oid, volume.root_tree_oid, nx_sb.xid) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] fs tree omap lookup failed\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] fs tree root at block ");
    print_num(fs_root_block);
    syscall::debug_puts(b"\n");

    // Store global volume state.
    unsafe {
        VOL_OMAP_PHYS = volume.omap_oid;
        FS_ROOT_BLOCK = fs_root_block;
        MAX_XID = nx_sb.xid;
        BLOCK_SIZE = bs;
        BLOCK_COUNT = nx_sb.block_count;
        NX_OMAP_PHYS = nx_sb.omap_oid;
        VOL_PHYS_BLOCK = vol_phys_block;
    }

    // Verify root directory exists (non-fatal if fails — IPC might be flaky).
    if let Some(root) = read_inode(&blk, bs, volume.omap_oid, fs_root_block, nx_sb.xid, ROOT_DIR_INO_NUM) {
        syscall::debug_puts(b"  [apfs_srv] root dir: mode=");
        print_hex(root.mode as u64);
        syscall::debug_puts(b" nlink=");
        print_num(root.nlink as u64);
        syscall::debug_puts(b"\n");
    } else {
        syscall::debug_puts(b"  [apfs_srv] root dir read failed (continuing anyway)\n");
    }

    // ---- Phase W: Initialize write support ----

    // Allocate scratch page for writes.
    match syscall::mmap_anon(0, 1, 1) {
        Some(va) => unsafe { WRITE_VA = va; },
        None => {
            syscall::debug_puts(b"  [apfs_srv] write scratch alloc FAILED\n");
        }
    }

    // Initialize block allocator and read OIDs from superblock.
    // Use cached superblock data from mount if available, else re-read.
    let block0_opt = cache_read_slice(&blk, 0, bs);
    if let Some(block0_full) = block0_opt {
        spaceman_init(&blk, bs, block0_full);
        unsafe {
            NX_NEXT_OID = read_le64(block0_full, NX_NEXT_OID_OFF);
            NX_NEXT_XID = read_le64(block0_full, NX_NEXT_XID_OFF);
        }
    } else {
        syscall::debug_puts(b"  [apfs_srv] block0 re-read failed, using defaults\n");
        unsafe {
            NX_NEXT_OID = 2048; // safe default
            NX_NEXT_XID = nx_sb.xid + 1;
        }
    }

    // Read volume-level next object ID.
    if let Some(vol_buf) = cache_read_slice(&blk, vol_phys_block, bs) {
        unsafe {
            VOL_NEXT_OBJ_ID = read_le64(vol_buf, APFS_NEXT_OBJ_ID_OFF);
        }
    } else {
        syscall::debug_puts(b"  [apfs_srv] vol re-read failed, using defaults\n");
        unsafe { VOL_NEXT_OBJ_ID = 2048; }
    }

    // Register with name server using non-blocking IPC (avoid lost-wakeup bug).
    {
        let nsrv = syscall::nsrv_port();
        let rp = syscall::port_create();
        let (n0, n1, _) = syscall::pack_name(b"apfs");
        let d3 = 4u64 | (rp << 32);
        let mut registered = false;
        for _ in 0..5000u32 {
            let sr = syscall::send_nb_4(nsrv, 0x1000, n0, n1, port, d3);
            if sr != 0 {
                for _ in 0..50 { syscall::yield_now(); }
                continue;
            }
            for _ in 0..5000u32 {
                if let Some(reply) = syscall::recv_nb_msg(rp) {
                    if reply.tag == 0x1001 {
                        registered = true;
                    }
                    break;
                }
                syscall::yield_now();
            }
            if registered { break; }
            for _ in 0..50 { syscall::yield_now(); }
        }
        syscall::port_destroy(rp);
        if !registered {
            syscall::debug_puts(b"  [apfs_srv] ns_register FAILED\n");
        }
    }
    syscall::debug_puts(b"  [apfs_srv] ready (read-write)\n");

    // Open file table.
    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    let vol_omap = volume.omap_oid;
    let max_xid = nx_sb.xid;
    let mut cur_fs_root = fs_root_block;
    let fs_root_oid = volume.root_tree_oid;

    // ---- Server loop ----
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

                if let Some(inode) = path_resolve(&blk, bs, vol_omap, cur_fs_root, max_xid, name) {
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
                        syscall::send(reply_port, FS_OPEN_OK, handle, inode.size, my_aspace as u64, 0);
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

                let name = unsafe {
                    core::slice::from_raw_parts(VFS_LONG_PATH_SCRATCH_VA as *const u8, name_len.min(4096))
                };

                if let Some(inode) = path_resolve(&blk, bs, vol_omap, cur_fs_root, max_xid, name) {
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
                        syscall::send(reply_port, FS_OPEN_OK, handle, inode.size, my_aspace as u64, 0);
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_CLOSE => {
                let handle_id = msg.data[0] as usize;
                if handle_id < MAX_OPEN && handles[handle_id].active {
                    handles[handle_id].active = false;
                }
            }

            FS_READ => {
                let handle_id = msg.data[0] as usize;
                let offset = msg.data[1];
                let len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if handle_id >= MAX_OPEN || !handles[handle_id].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle_id].inode;
                if offset >= inode.size {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let avail = (inode.size - offset) as usize;
                let read_len = len.min(avail);
                let private_id = inode.private_id;

                // Read data block by block.
                let mut total_read = 0usize;
                let mut file_pos = offset;

                while total_read < read_len {
                    let remaining = read_len - total_read;

                    let (phys_block, off_in_block, _extent_rem) = match resolve_file_extent(
                        &blk, bs, vol_omap, cur_fs_root, max_xid, private_id, file_pos,
                    ) {
                        Some(r) => r,
                        None => break,
                    };

                    let block_va = match cache_read(&blk, phys_block, bs) {
                        Some(va) => va,
                        None => break,
                    };

                    let can_read = (bs - off_in_block) as usize;
                    let chunk = remaining.min(can_read);

                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (block_va + off_in_block as usize) as *const u8,
                                (grant_va + total_read) as *mut u8,
                                chunk,
                            );
                        }
                    }

                    total_read += chunk;
                    file_pos += chunk as u64;
                }

                if grant_va != 0 {
                    syscall::send(reply_port, FS_READ_OK, total_read as u64, 0, 0, 0);
                } else {
                    // Inline read (up to 24 bytes).
                    let inline_len = total_read.min(MAX_INLINE);
                    if inline_len > 0 {
                        let (phys_block, off_in_block, _) = match resolve_file_extent(
                            &blk, bs, vol_omap, cur_fs_root, max_xid, private_id, offset,
                        ) {
                            Some(r) => r,
                            None => {
                                syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                                continue;
                            }
                        };
                        let block_va = match cache_read(&blk, phys_block, bs) {
                            Some(va) => va,
                            None => {
                                syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                                continue;
                            }
                        };
                        let src = unsafe {
                            core::slice::from_raw_parts(
                                (block_va + off_in_block as usize) as *const u8,
                                inline_len,
                            )
                        };
                        let packed = pack_inline_data(src);
                        syscall::send(reply_port, FS_READ_OK, inline_len as u64, packed[0], packed[1], packed[2]);
                    } else {
                        syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    }
                }
            }

            FS_READDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let start_offset = msg.data[3] as usize;

                // Resolve directory path.
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let dir_ino = if name_len == 0 {
                    ROOT_DIR_INO_NUM
                } else {
                    match path_resolve(&blk, bs, vol_omap, cur_fs_root, max_xid, name) {
                        Some(inode) if inode.is_dir() => inode.ino,
                        _ => {
                            syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                            continue;
                        }
                    }
                };

                match dir_next_entry(&blk, bs, vol_omap, cur_fs_root, max_xid, dir_ino, start_offset) {
                    Some((name_buf, name_len, ino, _ftype, next_off)) => {
                        // Pack name into data[1] and data[2].
                        let mut n0 = 0u64;
                        let mut n1 = 0u64;
                        for i in 0..name_len.min(8) {
                            n0 |= (name_buf[i] as u64) << (i * 8);
                        }
                        for i in 8..name_len.min(16) {
                            n1 |= (name_buf[i] as u64) << ((i - 8) * 8);
                        }
                        // Read inode for size.
                        let file_size = match read_inode(&blk, bs, vol_omap, cur_fs_root, max_xid, ino) {
                            Some(i) => i.size,
                            None => 0,
                        };
                        syscall::send(reply_port, FS_READDIR_OK, file_size, n0, n1, next_off as u64);
                    }
                    None => {
                        syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                    }
                }
            }

            FS_STAT => {
                let handle_id = msg.data[0] as usize;
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

                if handle_id >= MAX_OPEN || !handles[handle_id].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle_id].inode;
                let uid_gid = (inode.owner as u64) | ((inode.group as u64) << 32);
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

                let name = unsafe {
                    core::slice::from_raw_parts(VFS_LONG_PATH_SCRATCH_VA as *const u8, name_len.min(4096))
                };

                if let Some(inode) = path_resolve(&blk, bs, vol_omap, cur_fs_root, max_xid, name) {
                    let uid_gid = (inode.owner as u64) | ((inode.group as u64) << 32);
                    syscall::send(reply_port, FS_STAT_OK, inode.size, inode.mode as u64, uid_gid, inode.ino);
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_READLINK => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let ino = if let Some(inode) = path_resolve(&blk, bs, vol_omap, cur_fs_root, max_xid, name) {
                    if !inode.is_symlink() {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                        continue;
                    }
                    inode.ino
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    continue;
                };

                let mut target = [0u8; 256];
                if let Some(len) = read_symlink_target(&blk, bs, vol_omap, cur_fs_root, max_xid, ino, &mut target) {
                    let packed = pack_inline_data(&target[..len.min(MAX_INLINE)]);
                    syscall::send(reply_port, FS_READLINK_OK, len as u64, packed[0], packed[1], packed[2]);
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let reply_port = msg.data[2] >> 32;
                unsafe {
                    let total_blocks = BLOCK_COUNT;
                    let bsize = BLOCK_SIZE as u64;
                    syscall::send(reply_port, FS_STATFS_OK, bsize, total_blocks, 0, 0);
                }
            }

            FS_CREATE | FS_MKNOD => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Allocate new inode OID.
                let ino = unsafe {
                    let id = VOL_NEXT_OBJ_ID;
                    VOL_NEXT_OBJ_ID += 1;
                    id
                };

                // Create inode record.
                let new_root = match create_inode_record(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ino, ROOT_DIR_INO_NUM, S_IFREG | 0o644, false,
                ) {
                    Some(r) => r,
                    None => {
                        syscall::debug_puts(b"  [apfs_srv] CREATE: inode FAILED\n");
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                cur_fs_root = new_root;

                // Create directory entry in root dir.
                let new_root = match create_dir_entry(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, name, ino, DT_REG,
                ) {
                    Some(r) => r,
                    None => {
                        syscall::debug_puts(b"  [apfs_srv] CREATE: drec FAILED\n");
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                cur_fs_root = new_root;

                // Update parent nchildren.
                if let Some(r) = update_parent_nchildren(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, 1,
                ) {
                    cur_fs_root = r;
                }

                // Allocate handle.
                let new_inode = ApfsInode {
                    ino,
                    parent_id: ROOT_DIR_INO_NUM,
                    private_id: ino,
                    mode: S_IFREG | 0o644,
                    owner: 0,
                    group: 0,
                    nlink: 1,
                    size: 0,
                };
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
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                } else {
                    update_volume_superblock(&blk, bs, unsafe { VOL_PHYS_BLOCK }, 1, 0);
                    syscall::send(reply_port, FS_CREATE_OK, handle, 0, my_aspace as u64, 0);
                }
            }

            FS_MKDIR => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let mode = ((msg.data[2] >> 16) & 0xFFFF) as u16;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let ino = unsafe {
                    let id = VOL_NEXT_OBJ_ID;
                    VOL_NEXT_OBJ_ID += 1;
                    id
                };

                let dir_mode = S_IFDIR | (mode & 0o7777);
                let new_root = match create_inode_record(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ino, ROOT_DIR_INO_NUM, dir_mode, true,
                ) {
                    Some(r) => r,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                cur_fs_root = new_root;

                let new_root = match create_dir_entry(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, name, ino, DT_DIR,
                ) {
                    Some(r) => r,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                cur_fs_root = new_root;

                if let Some(r) = update_parent_nchildren(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, 1,
                ) {
                    cur_fs_root = r;
                }

                update_volume_superblock(&blk, bs, unsafe { VOL_PHYS_BLOCK }, 0, 1);
                syscall::send(reply_port, FS_MKDIR_OK, 0, 0, 0, 0);
            }

            FS_WRITE => {
                let handle_id = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[1] >> 32;
                let grant_va = msg.data[2] as usize;

                if handle_id >= MAX_OPEN || !handles[handle_id].active {
                    if reply_port != 0 {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    }
                    continue;
                }

                let block_size = bs as usize;
                let mut written = 0usize;
                let mut offset = handles[handle_id].inode.size;
                let private_id = handles[handle_id].inode.private_id;

                while written < length {
                    let off_in_blk = (offset % (bs as u64)) as usize;
                    let space = block_size - off_in_blk;
                    let chunk = (length - written).min(space);

                    // Allocate a data block.
                    let phys = match block_alloc(1) {
                        Some(b) => b,
                        None => break,
                    };

                    let wva = unsafe { WRITE_VA };

                    // Zero the block first.
                    unsafe {
                        core::ptr::write_bytes(wva as *mut u8, 0, block_size);
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
                    if !blk.write_block(phys, bs, wva) {
                        block_free(phys, 1);
                        break;
                    }

                    // Create file extent record.
                    let logical_addr = (offset / bs as u64) * bs as u64;
                    match create_file_extent(
                        &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                        private_id, logical_addr, phys, bs as u64,
                    ) {
                        Some(r) => cur_fs_root = r,
                        None => break,
                    }

                    written += chunk;
                    offset += chunk as u64;
                }

                // Update file size and inode.
                handles[handle_id].inode.size = offset;
                if let Some(r) = update_inode_record(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    &handles[handle_id].inode,
                ) {
                    cur_fs_root = r;
                }

                if reply_port != 0 {
                    syscall::send(reply_port, FS_WRITE_OK, written as u64, 0, 0, 0);
                }
            }

            FS_DELETE | FS_UNLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Look up file.
                let child_ino = match dir_lookup(&blk, bs, vol_omap, cur_fs_root, max_xid, ROOT_DIR_INO_NUM, name) {
                    Some(i) => i,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                        continue;
                    }
                };

                let child = match read_inode(&blk, bs, vol_omap, cur_fs_root, max_xid, child_ino) {
                    Some(i) => i,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };

                let is_dir = child.is_dir();

                // Free file extent blocks and records.
                if !is_dir {
                    // Collect extent blocks to free.
                    let mut extents_to_free = [(0u64, 0u64); 64];
                    let mut ext_count = 0usize;
                    fs_tree_iterate(
                        &blk, bs, vol_omap, cur_fs_root, max_xid, 0,
                        &|key_data: &[u8]| {
                            if key_data.len() < 8 { return core::cmp::Ordering::Less; }
                            let k = read_le64(key_data, 0);
                            let k_id = fs_key_obj_id(k);
                            let k_type = fs_key_type(k);
                            if k_id < child.private_id || (k_id == child.private_id && (k_type as u64) < APFS_TYPE_FILE_EXTENT as u64) {
                                core::cmp::Ordering::Less
                            } else if k_id == child.private_id && k_type == APFS_TYPE_FILE_EXTENT {
                                core::cmp::Ordering::Equal
                            } else {
                                core::cmp::Ordering::Greater
                            }
                        },
                        &mut |_key_data: &[u8], val_data: &[u8], _idx: usize| -> bool {
                            if val_data.len() >= 16 && ext_count < 64 {
                                let len = read_le64(val_data, 0) & 0x00ffffffffffffffu64;
                                let pblk = read_le64(val_data, 8);
                                extents_to_free[ext_count] = (pblk, len);
                                ext_count += 1;
                            }
                            true
                        },
                    );

                    // Free blocks.
                    for i in 0..ext_count {
                        let (pblk, len) = extents_to_free[i];
                        let blocks = ((len + bs as u64 - 1) / bs as u64) as u32;
                        block_free(pblk, blocks);
                    }

                    // Delete extent records.
                    cur_fs_root = delete_all_file_extents(
                        &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid, child.private_id,
                    );
                }

                // Delete directory entry.
                if let Some(r) = delete_dir_entry(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, name,
                ) {
                    cur_fs_root = r;
                }

                // Delete inode record.
                if let Some(r) = delete_inode_record(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid, child_ino,
                ) {
                    cur_fs_root = r;
                }

                // Update parent.
                if let Some(r) = update_parent_nchildren(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, -1,
                ) {
                    cur_fs_root = r;
                }

                let (fd, dd) = if is_dir { (0i64, -1i64) } else { (-1, 0) };
                update_volume_superblock(&blk, bs, unsafe { VOL_PHYS_BLOCK }, fd, dd);
                syscall::send(reply_port, FS_DELETE_OK, 0, 0, 0, 0);
            }

            FS_TRUNCATE => {
                let handle_lo = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[0] >> 32;
                let new_size = msg.data[1];

                if handle_lo >= MAX_OPEN || !handles[handle_lo].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let inode = &mut handles[handle_lo].inode;
                if new_size == 0 && inode.size > 0 {
                    // Free all extents.
                    // Collect extent blocks to free.
                    let mut extents_to_free = [(0u64, 0u64); 64];
                    let mut ext_count = 0usize;
                    fs_tree_iterate(
                        &blk, bs, vol_omap, cur_fs_root, max_xid, 0,
                        &|key_data: &[u8]| {
                            if key_data.len() < 8 { return core::cmp::Ordering::Less; }
                            let k = read_le64(key_data, 0);
                            let k_id = fs_key_obj_id(k);
                            let k_type = fs_key_type(k);
                            if k_id < inode.private_id || (k_id == inode.private_id && (k_type as u64) < APFS_TYPE_FILE_EXTENT as u64) {
                                core::cmp::Ordering::Less
                            } else if k_id == inode.private_id && k_type == APFS_TYPE_FILE_EXTENT {
                                core::cmp::Ordering::Equal
                            } else {
                                core::cmp::Ordering::Greater
                            }
                        },
                        &mut |_key: &[u8], val_data: &[u8], _idx: usize| -> bool {
                            if val_data.len() >= 16 && ext_count < 64 {
                                let len = read_le64(val_data, 0) & 0x00ffffffffffffffu64;
                                let pblk = read_le64(val_data, 8);
                                extents_to_free[ext_count] = (pblk, len);
                                ext_count += 1;
                            }
                            true
                        },
                    );
                    for i in 0..ext_count {
                        let (pblk, len) = extents_to_free[i];
                        let blocks = ((len + bs as u64 - 1) / bs as u64) as u32;
                        block_free(pblk, blocks);
                    }
                    cur_fs_root = delete_all_file_extents(
                        &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid, inode.private_id,
                    );
                }
                inode.size = new_size;
                if let Some(r) = update_inode_record(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid, inode,
                ) {
                    cur_fs_root = r;
                }
                syscall::send(reply_port, FS_TRUNCATE_OK, 0, 0, 0, 0);
            }

            FS_RENAME => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let old_name = &name_buf[..name_len.min(16)];

                // Extract new name from data[3].
                let new_word = msg.data[3];
                let mut new_name = [0u8; 8];
                let mut new_nlen = 0usize;
                for i in 0..8 {
                    let b = (new_word >> (i * 8)) as u8;
                    if b == 0 { break; }
                    new_name[i] = b;
                    new_nlen += 1;
                }

                // Look up old name.
                let file_id = match dir_lookup(&blk, bs, vol_omap, cur_fs_root, max_xid, ROOT_DIR_INO_NUM, old_name) {
                    Some(i) => i,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                        continue;
                    }
                };

                let target_inode = match read_inode(&blk, bs, vol_omap, cur_fs_root, max_xid, file_id) {
                    Some(i) => i,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                let ftype = match target_inode.mode & S_IFMT {
                    S_IFDIR => DT_DIR,
                    S_IFLNK => DT_LNK,
                    _ => DT_REG,
                };

                // Delete old entry.
                if let Some(r) = delete_dir_entry(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, old_name,
                ) {
                    cur_fs_root = r;
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    continue;
                }

                // Add new entry.
                match create_dir_entry(
                    &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                    ROOT_DIR_INO_NUM, &new_name[..new_nlen], file_id, ftype,
                ) {
                    Some(r) => cur_fs_root = r,
                    None => {
                        // Try to restore old entry.
                        if let Some(r) = create_dir_entry(
                            &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid,
                            ROOT_DIR_INO_NUM, old_name, file_id, ftype,
                        ) {
                            cur_fs_root = r;
                        }
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                }

                syscall::send(reply_port, FS_RENAME_OK, 0, 0, 0, 0);
            }

            FS_CHMOD => {
                let path_len = (msg.data[0] & 0xFFFF) as usize;
                let mode = ((msg.data[0] >> 16) & 0xFFFF) as u16;
                let reply_port = msg.data[0] >> 32;

                let mut name = [0u8; 256];
                let nlen = path_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some(mut inode) = path_resolve(&blk, bs, vol_omap, cur_fs_root, max_xid, &name[..nlen]) {
                    inode.mode = (inode.mode & S_IFMT) | (mode & 0o7777);
                    if let Some(r) = update_inode_record(
                        &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid, &inode,
                    ) {
                        cur_fs_root = r;
                    }
                    syscall::send(reply_port, FS_CHMOD_OK, 0, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_CHOWN => {
                let path_len = (msg.data[0] & 0xFFFF) as usize;
                let uid = ((msg.data[0] >> 16) & 0xFFFF) as u32;
                let reply_port = msg.data[0] >> 32;
                let gid = msg.data[1] as u32;

                let mut name = [0u8; 256];
                let nlen = path_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some(mut inode) = path_resolve(&blk, bs, vol_omap, cur_fs_root, max_xid, &name[..nlen]) {
                    inode.owner = uid;
                    inode.group = gid;
                    if let Some(r) = update_inode_record(
                        &blk, bs, vol_omap, cur_fs_root, fs_root_oid, max_xid, &inode,
                    ) {
                        cur_fs_root = r;
                    }
                    syscall::send(reply_port, FS_CHOWN_OK, 0, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_UTIMENS => {
                let reply_port = msg.data[0] >> 32;
                syscall::send(reply_port, FS_UTIMENS_OK, 0, 0, 0, 0);
            }

            FS_SYMLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                // Stub: symlink creation not yet supported.
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_LINK => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            FS_FSYNC => {
                let reply_port = msg.data[2] >> 32;
                // Flush all metadata to disk.
                checkpoint_commit(&blk, bs, 0);
                syscall::send(reply_port, FS_FSYNC_OK, 0, 0, 0, 0);
            }

            _ => {}
        }
    }
}
