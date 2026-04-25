#![no_std]
#![no_main]
#![allow(static_mut_refs)]

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2024-2026 Nadia Chambers
// Reference: btrfs on-disk format (kernel.org wiki), Linux btrfs driver

//! Btrfs filesystem server (read-write).
//!
//! Pure userspace process that talks to cache_blk via IPC for a btrfs partition.
//! The partition starts at a byte offset passed as arg0 (default 401 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE / FS_CREATE /
//! FS_WRITE / FS_DELETE / FS_MKDIR / FS_RENAME / FS_TRUNCATE / FS_CHMOD etc.

extern crate userlib;
use userlib::syscall;

// =====================================================================
// IPC protocol constants
// =====================================================================
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;

const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_OPEN_LONG: u64 = 0x2002;
const FS_READ_FS: u64 = 0x2100;
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
const FS_WRITE_FS: u64 = 0x2600;
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
const FS_READLINK: u64 = 0x2C10;
const FS_LINK: u64 = 0x2C20;
const FS_RENAME: u64 = 0x2C30;
const FS_RENAME_OK: u64 = 0x2C31;
const FS_CHOWN: u64 = 0x2C40;
const FS_CHOWN_OK: u64 = 0x2C41;
const FS_TRUNCATE: u64 = 0x2C50;
const FS_TRUNCATE_OK: u64 = 0x2C51;
const FS_UNLINK_OK: u64 = 0x2A21;
const FS_STATFS: u64 = 0x2C60;
const FS_STATFS_OK: u64 = 0x2C61;
const FS_MKNOD: u64 = 0x2D40;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
#[allow(dead_code)]
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

const MAX_OPEN: usize = 16;
const MAX_INLINE: usize = 24;
const SECTOR: u64 = 512;

const VFS_LONG_PATH_SCRATCH_VA: usize = 0x5_0000_0000;

// =====================================================================
// Btrfs on-disk format constants
// =====================================================================
const BTRFS_SUPER_OFFSET: u64 = 0x10000; // 64 KiB

// Superblock field offsets
const SB_MAGIC: usize = 64;
const SB_ROOT: usize = 80;
const SB_CHUNK_ROOT: usize = 88;
const SB_TOTAL_BYTES: usize = 112;
const SB_BYTES_USED: usize = 120;
const SB_SECTORSIZE: usize = 144;
const SB_NODESIZE: usize = 148;
const SB_SYS_CHUNK_ARRAY_SIZE: usize = 160;
const SB_ROOT_LEVEL: usize = 198;
const SB_CHUNK_ROOT_LEVEL: usize = 199;
const SB_SYS_CHUNK_ARRAY: usize = 811;

// Key types
const BTRFS_INODE_ITEM_KEY: u8 = 0x01;
const BTRFS_INODE_REF_KEY: u8 = 0x0C;
const BTRFS_DIR_ITEM_KEY: u8 = 0x54;
const BTRFS_DIR_INDEX_KEY: u8 = 0x60;
const BTRFS_EXTENT_DATA_KEY: u8 = 0x6C;
const BTRFS_ROOT_ITEM_KEY: u8 = 0x84;
const BTRFS_CHUNK_ITEM_KEY: u8 = 0xE4;

// Well-known object IDs
const BTRFS_FS_TREE_OBJECTID: u64 = 5;
const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

// File extent types
const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
const BTRFS_FILE_EXTENT_REG: u8 = 1;
const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

// Tree node struct sizes
const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_KEY_SIZE: usize = 17;
const BTRFS_LEAF_ITEM_SIZE: usize = 25;
const BTRFS_KEY_PTR_SIZE: usize = 33;

// ROOT_ITEM offsets (from item data start — after 160-byte embedded inode_item)
const ROOT_ITEM_BYTENR: usize = 176;
const ROOT_ITEM_LEVEL: usize = 238;

// =====================================================================
// CRC32c (Castagnoli) — btrfs uses this for directory name hashing
// =====================================================================
static CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let poly: u32 = 0x82F63B78;
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

fn crc32c_update(init: u32, data: &[u8]) -> u32 {
    let mut crc = init;
    for &b in data {
        let idx = ((crc ^ b as u32) & 0xFF) as usize;
        crc = CRC32C_TABLE[idx] ^ (crc >> 8);
    }
    crc
}

/// Btrfs name hash for DIR_ITEM key offset.  Uses `~1u32` as initial CRC.
fn btrfs_name_hash(name: &[u8]) -> u64 {
    crc32c_update(!1u32, name) as u64
}

// =====================================================================
// Little-endian helpers
// =====================================================================
fn read_le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_le64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn write_le32(buf: &mut [u8], off: usize, v: u32) {
    let b = v.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
}

fn write_le64(buf: &mut [u8], off: usize, v: u64) {
    let b = v.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
    buf[off + 4] = b[4];
    buf[off + 5] = b[5];
    buf[off + 6] = b[6];
    buf[off + 7] = b[7];
}

// =====================================================================
// Btrfs disk key
// =====================================================================
#[derive(Clone, Copy)]
struct BtrfsKey {
    objectid: u64,
    typ: u8,
    offset: u64,
}

fn read_key_at(buf: &[u8], off: usize) -> BtrfsKey {
    BtrfsKey {
        objectid: read_le64(buf, off),
        typ: buf[off + 8],
        offset: read_le64(buf, off + 9),
    }
}

fn key_cmp(a: &BtrfsKey, b: &BtrfsKey) -> i32 {
    if a.objectid != b.objectid {
        return if a.objectid < b.objectid { -1 } else { 1 };
    }
    if a.typ != b.typ {
        return if a.typ < b.typ { -1 } else { 1 };
    }
    if a.offset != b.offset {
        return if a.offset < b.offset { -1 } else { 1 };
    }
    0
}

fn write_key_at(buf: &mut [u8], off: usize, key: &BtrfsKey) {
    write_le64(buf, off, key.objectid);
    buf[off + 8] = key.typ;
    write_le64(buf, off + 9, key.offset);
}

// =====================================================================
// Utility helpers
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
    let mut started = false;
    for shift in (0..16).rev() {
        let nibble = ((n >> (shift * 4)) & 0xF) as u8;
        if nibble != 0 || started {
            started = true;
            let ch = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
            syscall::debug_putchar(ch);
        }
    }
}

fn unpack_name(d0: u64, d1: u64, len: usize) -> [u8; 24] {
    let mut buf = [0u8; 24];
    let words = [d0, d1];
    for i in 0..len.min(16) {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    buf
}

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
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
    /// Read up to 512 bytes at byte offset `off` (relative to partition).
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let abs_off = self.partition_offset + off;
        let sector_byte = abs_off & !511;
        let off_in = (abs_off & 511) as usize;

        if !syscall::grant_pages(
            self.blk_aspace,
            self.scratch_va,
            self.grant_va,
            1,
            false,
        ) {
            return false;
        }

        let d2 = SECTOR | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_READ,
            0,
            sector_byte,
            d2,
            self.grant_va as u64,
        );

        let ok =
            if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
                if rr.tag == IO_READ_OK && rr.data[0] == SECTOR {
                    let copy_len = out.len().min(512 - off_in);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            (self.scratch_va + off_in) as *const u8,
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

    /// Read `len` bytes at **sector-aligned** offset `off` into `dest` VA.
    fn read_range(&self, off: u64, dest: usize, len: usize) -> bool {
        let sectors = (len + 511) / 512;
        for s in 0..sectors {
            let abs = self.partition_offset + off + (s as u64) * SECTOR;
            if !syscall::grant_pages(
                self.blk_aspace,
                self.scratch_va,
                self.grant_va,
                1,
                false,
            ) {
                return false;
            }
            let d2 = SECTOR | ((self.reply_port as u64) << 32);
            syscall::send(
                self.blk_port,
                IO_READ,
                0,
                abs,
                d2,
                self.grant_va as u64,
            );
            let ok =
                if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
                    if rr.tag == IO_READ_OK && rr.data[0] == SECTOR {
                        let chunk = (len - s * 512).min(512);
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                self.scratch_va as *const u8,
                                (dest + s * 512) as *mut u8,
                                chunk,
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

    /// Write `len` bytes from `src` VA to **sector-aligned** byte offset `off`.
    fn write_range(&self, off: u64, src: usize, len: usize) -> bool {
        let sectors = (len + 511) / 512;
        for s in 0..sectors {
            // Copy data into scratch page.
            let chunk = (len - s * 512).min(512);
            unsafe {
                // Zero the scratch first (partial last sector).
                core::ptr::write_bytes(self.scratch_va as *mut u8, 0, 512);
                core::ptr::copy_nonoverlapping(
                    (src + s * 512) as *const u8,
                    self.scratch_va as *mut u8,
                    chunk,
                );
            }
            if !syscall::grant_pages(
                self.blk_aspace,
                self.scratch_va,
                self.grant_va,
                1,
                false,
            ) {
                return false;
            }
            let abs = self.partition_offset + off + (s as u64) * SECTOR;
            let d2 = SECTOR | ((self.reply_port as u64) << 32);
            syscall::send(
                self.blk_port,
                IO_WRITE,
                0,
                abs,
                d2,
                self.grant_va as u64,
            );
            let ok =
                if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
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
// Chunk map: logical → physical address translation
// =====================================================================
const MAX_CHUNKS: usize = 64;

#[derive(Clone, Copy)]
struct ChunkEntry {
    logical: u64,
    length: u64,
    physical: u64, // stripe[0].offset for SINGLE / DUP
}

static mut CHUNKS: [ChunkEntry; MAX_CHUNKS] =
    [ChunkEntry { logical: 0, length: 0, physical: 0 }; MAX_CHUNKS];
static mut CHUNK_COUNT: usize = 0;

fn chunk_add(logical: u64, length: u64, physical: u64) {
    unsafe {
        if CHUNK_COUNT < MAX_CHUNKS {
            CHUNKS[CHUNK_COUNT] = ChunkEntry { logical, length, physical };
            CHUNK_COUNT += 1;
        }
    }
}

fn logical_to_physical(logical: u64) -> Option<u64> {
    unsafe {
        for i in 0..CHUNK_COUNT {
            let c = &CHUNKS[i];
            if logical >= c.logical && logical < c.logical + c.length {
                return Some(c.physical + (logical - c.logical));
            }
        }
    }
    None
}

/// Parse sys_chunk_array from superblock to bootstrap the chunk map.
fn parse_sys_chunk_array(sb: &[u8]) {
    let array_size = read_le32(sb, SB_SYS_CHUNK_ARRAY_SIZE) as usize;
    let base = SB_SYS_CHUNK_ARRAY;
    let mut off = 0usize;

    while off + BTRFS_KEY_SIZE < array_size {
        let key = read_key_at(&sb[base..], off);
        off += BTRFS_KEY_SIZE;

        if off + 48 > array_size {
            break;
        }

        let length = read_le64(&sb[base..], off);
        let num_stripes = read_le16(&sb[base..], off + 44) as usize;

        if num_stripes == 0 || off + 48 + 32 > array_size {
            break;
        }

        let physical = read_le64(&sb[base..], off + 48 + 8); // stripe[0].offset
        chunk_add(key.offset, length, physical);
        off += 48 + 32 * num_stripes;
    }
}

/// Walk chunk tree to build the full logical→physical map.
fn walk_chunk_tree(blk: &BlkClient, chunk_root: u64) {
    walk_chunk_node(blk, chunk_root);
}

fn walk_chunk_node(blk: &BlkClient, logical: u64) {
    let slot = match read_node(blk, logical) {
        Some(s) => s,
        None => return,
    };

    let (level, nritems) = unsafe {
        (NODE_BUF[slot][100], read_le32(&NODE_BUF[slot], 96) as usize)
    };

    if level == 0 {
        // Leaf — extract CHUNK_ITEM entries.
        for i in 0..nritems {
            let (key, data_off, data_sz) = unsafe {
                let buf = &NODE_BUF[slot];
                let hdr = BTRFS_HEADER_SIZE + i * BTRFS_LEAF_ITEM_SIZE;
                let k = read_key_at(buf, hdr);
                let doff = BTRFS_HEADER_SIZE + read_le32(buf, hdr + 17) as usize;
                let dsz = read_le32(buf, hdr + 21) as usize;
                (k, doff, dsz)
            };
            if key.typ == BTRFS_CHUNK_ITEM_KEY && data_sz >= 50 {
                unsafe {
                    let buf = &NODE_BUF[slot];
                    let length = read_le64(buf, data_off);
                    let ns = read_le16(buf, data_off + 44) as usize;
                    if ns > 0 && data_sz >= 48 + 32 {
                        let phys = read_le64(buf, data_off + 48 + 8);
                        chunk_add(key.offset, length, phys);
                    }
                }
            }
        }
    } else {
        // Internal node — collect child pointers then recurse.
        let mut children = [0u64; 64];
        let n = nritems.min(64);
        unsafe {
            for i in 0..n {
                let off =
                    BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE + BTRFS_KEY_SIZE;
                children[i] = read_le64(&NODE_BUF[slot], off);
            }
        }
        for i in 0..n {
            walk_chunk_node(blk, children[i]);
        }
    }
}

// =====================================================================
// Tree-node cache
// =====================================================================
const MAX_NODESIZE: usize = 16384;
const NODE_CACHE_SLOTS: usize = 16;

static mut NODE_BUF: [[u8; MAX_NODESIZE]; NODE_CACHE_SLOTS] =
    [[0; MAX_NODESIZE]; NODE_CACHE_SLOTS];
static mut NODE_ADDR: [u64; NODE_CACHE_SLOTS] = [u64::MAX; NODE_CACHE_SLOTS];
static mut NODE_AGE: [u32; NODE_CACHE_SLOTS] = [0; NODE_CACHE_SLOTS];
static mut CACHE_TICK: u32 = 0;
static mut REAL_NODESIZE: usize = MAX_NODESIZE;

/// Read a tree node at the given **logical** address (translates via chunk map).
fn read_node(blk: &BlkClient, logical: u64) -> Option<usize> {
    unsafe {
        // Cache hit?
        for i in 0..NODE_CACHE_SLOTS {
            if NODE_ADDR[i] == logical {
                CACHE_TICK += 1;
                NODE_AGE[i] = CACHE_TICK;
                return Some(i);
            }
        }

        // Translate logical → physical.
        let physical = logical_to_physical(logical)?;

        // Find LRU slot.
        let mut min_age = u32::MAX;
        let mut slot = 0;
        for i in 0..NODE_CACHE_SLOTS {
            if NODE_ADDR[i] == u64::MAX {
                slot = i;
                break;
            }
            if NODE_AGE[i] < min_age {
                min_age = NODE_AGE[i];
                slot = i;
            }
        }

        let nsz = REAL_NODESIZE;
        if !blk.read_range(
            physical,
            NODE_BUF[slot].as_mut_ptr() as usize,
            nsz,
        ) {
            return None;
        }

        CACHE_TICK += 1;
        NODE_ADDR[slot] = logical;
        NODE_AGE[slot] = CACHE_TICK;
        Some(slot)
    }
}

/// Invalidate a cached node (call after writing it to disk).
fn cache_invalidate_logical(logical: u64) {
    unsafe {
        for i in 0..NODE_CACHE_SLOTS {
            if NODE_ADDR[i] == logical {
                NODE_ADDR[i] = u64::MAX;
                return;
            }
        }
    }
}

/// Compute CRC32c over bytes [32..nodesize) and write into [0..4).
fn node_update_csum(slot: usize) {
    unsafe {
        let nsz = REAL_NODESIZE;
        let crc = crc32c_update(!0u32, &NODE_BUF[slot][32..nsz]);
        write_le32(&mut NODE_BUF[slot], 0, crc);
    }
}

/// Flush a cached node to disk: recompute CRC32c, write via BlkClient.
fn flush_node(blk: &BlkClient, slot: usize) -> bool {
    unsafe {
        let logical = NODE_ADDR[slot];
        if logical == u64::MAX {
            return false;
        }
        node_update_csum(slot);
        let physical = match logical_to_physical(logical) {
            Some(p) => p,
            None => return false,
        };
        let nsz = REAL_NODESIZE;
        blk.write_range(physical, NODE_BUF[slot].as_ptr() as usize, nsz)
    }
}

// =====================================================================
// Block allocator — simple linear allocator from end of largest DATA chunk.
// No free-space tree updates; mkfs.btrfs -f rebuilds on next mount.
// =====================================================================
static mut ALLOC_CHUNK_IDX: usize = 0;
static mut ALLOC_CURSOR: u64 = 0; // logical address of next free block
static mut ALLOC_END: u64 = 0;    // end of the allocating chunk

fn init_allocator() {
    unsafe {
        // Find the largest DATA chunk (type determined by position — typically
        // the last chunk is the largest DATA chunk on a small btrfs image).
        let mut best = 0usize;
        let mut best_len = 0u64;
        for i in 0..CHUNK_COUNT {
            if CHUNKS[i].length > best_len {
                best_len = CHUNKS[i].length;
                best = i;
            }
        }
        ALLOC_CHUNK_IDX = best;
        // Start allocating from 75% into the chunk to avoid existing data.
        ALLOC_CURSOR = CHUNKS[best].logical + (best_len * 3 / 4);
        // Align to nodesize.
        let nsz = REAL_NODESIZE as u64;
        ALLOC_CURSOR = (ALLOC_CURSOR + nsz - 1) & !(nsz - 1);
        ALLOC_END = CHUNKS[best].logical + best_len;
    }
}

/// Allocate `size` bytes of logical space (nodesize-aligned).
/// Returns logical address or None if full.
fn alloc_logical(size: u64) -> Option<u64> {
    unsafe {
        let aligned = (size + (REAL_NODESIZE as u64) - 1) & !((REAL_NODESIZE as u64) - 1);
        if ALLOC_CURSOR + aligned > ALLOC_END {
            return None;
        }
        let addr = ALLOC_CURSOR;
        ALLOC_CURSOR += aligned;
        Some(addr)
    }
}

// =====================================================================
// Superblock update — write bytes_used and root tree pointer back.
// =====================================================================
static mut SB_BUF: [u8; 4096] = [0u8; 4096];

fn flush_superblock(blk: &BlkClient, vol: &BtrfsVol) -> bool {
    unsafe {
        // Re-read superblock so we don't clobber other fields.
        if !blk.read_range(BTRFS_SUPER_OFFSET, SB_BUF.as_mut_ptr() as usize, 4096) {
            return false;
        }
        // Update bytes_used.
        write_le64(&mut SB_BUF, SB_BYTES_USED, vol.bytes_used);
        // Update root tree root pointer (in case it changed — but we do in-place).
        write_le64(&mut SB_BUF, SB_ROOT, vol.fs_tree_root);
        // Recompute superblock CRC32c over [32..4096).
        let crc = crc32c_update(!0u32, &SB_BUF[32..4096]);
        write_le32(&mut SB_BUF, 0, crc);
        blk.write_range(BTRFS_SUPER_OFFSET, SB_BUF.as_ptr() as usize, 4096)
    }
}

// Next inode number counter.
static mut NEXT_INO: u64 = 0;

fn init_next_ino(blk: &BlkClient, vol: &BtrfsVol) {
    // Scan DIR_INDEX entries to find highest objectid in use.
    // Simple: just start at FIRST_FREE_OBJECTID + 256 + scan.
    let mut max_ino = BTRFS_FIRST_FREE_OBJECTID;
    // Walk DIR_INDEX entries from root dir to find max objectid.
    let mut idx = 2u64;
    loop {
        match dir_next_entry(blk, vol, BTRFS_FIRST_FREE_OBJECTID, idx) {
            Some((child_oid, _, _, next)) => {
                if child_oid > max_ino {
                    max_ino = child_oid;
                }
                idx = next;
            }
            None => break,
        }
    }
    unsafe {
        NEXT_INO = max_ino + 1;
    }
}

fn alloc_ino() -> u64 {
    unsafe {
        let ino = NEXT_INO;
        NEXT_INO += 1;
        ino
    }
}

// =====================================================================
// B-tree search
// =====================================================================

/// Floor search: find the largest key ≤ `search`.
/// Returns `(cache_slot, item_index, actual_key)`.
fn tree_search(
    blk: &BlkClient,
    tree_root: u64,
    search: &BtrfsKey,
) -> Option<(usize, usize, BtrfsKey)> {
    let mut logical = tree_root;

    loop {
        let slot = read_node(blk, logical)?;
        let (level, nritems) = unsafe {
            (NODE_BUF[slot][100], read_le32(&NODE_BUF[slot], 96) as usize)
        };
        if nritems == 0 {
            return None;
        }

        if level > 0 {
            // Internal: rightmost key_ptr with key ≤ search.
            let mut idx = 0;
            for i in 1..nritems {
                let k = unsafe {
                    read_key_at(
                        &NODE_BUF[slot],
                        BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE,
                    )
                };
                if key_cmp(&k, search) <= 0 {
                    idx = i;
                } else {
                    break;
                }
            }
            logical = unsafe {
                read_le64(
                    &NODE_BUF[slot],
                    BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE + BTRFS_KEY_SIZE,
                )
            };
        } else {
            // Leaf: floor item.
            let mut floor: Option<(usize, BtrfsKey)> = None;
            for i in 0..nritems {
                let k = unsafe {
                    read_key_at(
                        &NODE_BUF[slot],
                        BTRFS_HEADER_SIZE + i * BTRFS_LEAF_ITEM_SIZE,
                    )
                };
                if key_cmp(&k, search) <= 0 {
                    floor = Some((i, k));
                } else {
                    break;
                }
            }
            return floor.map(|(idx, k)| (slot, idx, k));
        }
    }
}

/// Ceil search: find the smallest key ≥ `search`.
fn tree_search_ge(
    blk: &BlkClient,
    tree_root: u64,
    search: &BtrfsKey,
) -> Option<(usize, usize, BtrfsKey)> {
    let mut logical = tree_root;

    loop {
        let slot = read_node(blk, logical)?;
        let (level, nritems) = unsafe {
            (NODE_BUF[slot][100], read_le32(&NODE_BUF[slot], 96) as usize)
        };
        if nritems == 0 {
            return None;
        }

        if level > 0 {
            let mut idx = 0;
            for i in 1..nritems {
                let k = unsafe {
                    read_key_at(
                        &NODE_BUF[slot],
                        BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE,
                    )
                };
                if key_cmp(&k, search) <= 0 {
                    idx = i;
                } else {
                    break;
                }
            }
            logical = unsafe {
                read_le64(
                    &NODE_BUF[slot],
                    BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE + BTRFS_KEY_SIZE,
                )
            };
        } else {
            // Leaf: first item with key ≥ search.
            for i in 0..nritems {
                let k = unsafe {
                    read_key_at(
                        &NODE_BUF[slot],
                        BTRFS_HEADER_SIZE + i * BTRFS_LEAF_ITEM_SIZE,
                    )
                };
                if key_cmp(&k, search) >= 0 {
                    return Some((slot, i, k));
                }
            }
            return None;
        }
    }
}

/// Get (data_offset_in_node, data_size) for a leaf item.
fn leaf_item_info(slot: usize, index: usize) -> (usize, usize) {
    unsafe {
        let hdr = BTRFS_HEADER_SIZE + index * BTRFS_LEAF_ITEM_SIZE;
        let data_off = BTRFS_HEADER_SIZE + read_le32(&NODE_BUF[slot], hdr + 17) as usize;
        let data_sz = read_le32(&NODE_BUF[slot], hdr + 21) as usize;
        (data_off, data_sz)
    }
}

// =====================================================================
// Leaf modification (in-place, no COW)
// =====================================================================

/// Insert an item into a leaf node at `slot`.  `key` is the item key,
/// `data` is the item payload.  Returns false if the leaf is full.
/// In btrfs leaves: item headers grow forward from HEADER_SIZE, item data
/// grows backward from nodesize.  data_offset in each item header is
/// relative to the start of the header area (not node start) — we store
/// it as "offset from start of data area" per the on-disk format: the
/// value stored is the offset from BTRFS_HEADER_SIZE.
fn leaf_insert_item(
    blk: &BlkClient,
    slot: usize,
    key: &BtrfsKey,
    data: &[u8],
) -> bool {
    unsafe {
        let nsz = REAL_NODESIZE;
        let nritems = read_le32(&NODE_BUF[slot], 96) as usize;

        // Find insertion point (keep sorted order).
        let mut ins = nritems;
        for i in 0..nritems {
            let k = read_key_at(
                &NODE_BUF[slot],
                BTRFS_HEADER_SIZE + i * BTRFS_LEAF_ITEM_SIZE,
            );
            if key_cmp(key, &k) < 0 {
                ins = i;
                break;
            } else if key_cmp(key, &k) == 0 {
                // Key already exists — duplicate.
                return false;
            }
        }

        // Check space: headers end, data start.
        let headers_end = BTRFS_HEADER_SIZE + (nritems + 1) * BTRFS_LEAF_ITEM_SIZE;
        let data_start = if nritems == 0 {
            nsz
        } else {
            // Lowest data_offset among all items.
            let mut lowest = nsz;
            for i in 0..nritems {
                let hdr = BTRFS_HEADER_SIZE + i * BTRFS_LEAF_ITEM_SIZE;
                let d = BTRFS_HEADER_SIZE + read_le32(&NODE_BUF[slot], hdr + 17) as usize;
                if d < lowest {
                    lowest = d;
                }
            }
            lowest
        };

        if headers_end + data.len() > data_start {
            return false; // Leaf full.
        }

        // New data goes just below existing data.
        let new_data_off = data_start - data.len();

        // Shift item headers at [ins..nritems] right by one slot.
        if ins < nritems {
            let src = BTRFS_HEADER_SIZE + ins * BTRFS_LEAF_ITEM_SIZE;
            let dst = BTRFS_HEADER_SIZE + (ins + 1) * BTRFS_LEAF_ITEM_SIZE;
            let count = (nritems - ins) * BTRFS_LEAF_ITEM_SIZE;
            core::ptr::copy(
                NODE_BUF[slot].as_ptr().add(src),
                NODE_BUF[slot].as_mut_ptr().add(dst),
                count,
            );
        }

        // Write new item header.
        let hdr = BTRFS_HEADER_SIZE + ins * BTRFS_LEAF_ITEM_SIZE;
        write_key_at(&mut NODE_BUF[slot], hdr, key);
        // data_offset is relative to BTRFS_HEADER_SIZE.
        write_le32(
            &mut NODE_BUF[slot],
            hdr + 17,
            (new_data_off - BTRFS_HEADER_SIZE) as u32,
        );
        write_le32(&mut NODE_BUF[slot], hdr + 21, data.len() as u32);

        // Write item data.
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            NODE_BUF[slot].as_mut_ptr().add(new_data_off),
            data.len(),
        );

        // Increment nritems.
        write_le32(&mut NODE_BUF[slot], 96, (nritems + 1) as u32);

        // Flush to disk.
        flush_node(blk, slot)
    }
}

/// Delete item at `index` from leaf at `slot`.
fn leaf_delete_item(blk: &BlkClient, slot: usize, index: usize) -> bool {
    unsafe {
        let nritems = read_le32(&NODE_BUF[slot], 96) as usize;
        if index >= nritems {
            return false;
        }

        let nsz = REAL_NODESIZE;
        let del_hdr = BTRFS_HEADER_SIZE + index * BTRFS_LEAF_ITEM_SIZE;
        let del_data_off =
            BTRFS_HEADER_SIZE + read_le32(&NODE_BUF[slot], del_hdr + 17) as usize;
        let del_data_sz = read_le32(&NODE_BUF[slot], del_hdr + 21) as usize;

        // Find lowest data offset among all items (the data area boundary).
        let mut lowest_data = nsz;
        for i in 0..nritems {
            let h = BTRFS_HEADER_SIZE + i * BTRFS_LEAF_ITEM_SIZE;
            let d = BTRFS_HEADER_SIZE + read_le32(&NODE_BUF[slot], h + 17) as usize;
            if d < lowest_data {
                lowest_data = d;
            }
        }

        // Compact data area: shift items with offsets < del_data_off up by del_data_sz.
        // (These are the items whose data is below the deleted item's data.)
        if del_data_off > lowest_data {
            core::ptr::copy(
                NODE_BUF[slot].as_ptr().add(lowest_data),
                NODE_BUF[slot].as_mut_ptr().add(lowest_data + del_data_sz),
                del_data_off - lowest_data,
            );
        }

        // Update data_offsets for items whose data was shifted.
        for i in 0..nritems {
            if i == index {
                continue;
            }
            let h = BTRFS_HEADER_SIZE + i * BTRFS_LEAF_ITEM_SIZE;
            let d = BTRFS_HEADER_SIZE + read_le32(&NODE_BUF[slot], h + 17) as usize;
            if d < del_data_off {
                write_le32(
                    &mut NODE_BUF[slot],
                    h + 17,
                    (d + del_data_sz - BTRFS_HEADER_SIZE) as u32,
                );
            }
        }

        // Shift item headers left.
        if index + 1 < nritems {
            let src = BTRFS_HEADER_SIZE + (index + 1) * BTRFS_LEAF_ITEM_SIZE;
            let dst = del_hdr;
            let count = (nritems - index - 1) * BTRFS_LEAF_ITEM_SIZE;
            core::ptr::copy(
                NODE_BUF[slot].as_ptr().add(src),
                NODE_BUF[slot].as_mut_ptr().add(dst),
                count,
            );
        }

        // Clear last header slot.
        let last_hdr = BTRFS_HEADER_SIZE + (nritems - 1) * BTRFS_LEAF_ITEM_SIZE;
        core::ptr::write_bytes(
            NODE_BUF[slot].as_mut_ptr().add(last_hdr),
            0,
            BTRFS_LEAF_ITEM_SIZE,
        );

        // Decrement nritems.
        write_le32(&mut NODE_BUF[slot], 96, (nritems - 1) as u32);

        flush_node(blk, slot)
    }
}

/// Update the data payload of an existing item at `index` in leaf `slot`.
/// The new data must be the same size as the old data.
fn leaf_update_item_data(
    blk: &BlkClient,
    slot: usize,
    index: usize,
    data: &[u8],
) -> bool {
    let (data_off, data_sz) = leaf_item_info(slot, index);
    if data.len() != data_sz {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            NODE_BUF[slot].as_mut_ptr().add(data_off),
            data.len(),
        );
    }
    flush_node(blk, slot)
}

// =====================================================================
// Tree-level insert/delete (single-leaf, no splits)
// =====================================================================

/// Insert an item into a tree rooted at `tree_root`.
/// Walks down to the correct leaf and inserts there.
fn tree_insert(
    blk: &BlkClient,
    tree_root: u64,
    key: &BtrfsKey,
    data: &[u8],
) -> bool {
    // Walk to the target leaf.
    let mut logical = tree_root;
    loop {
        let slot = match read_node(blk, logical) {
            Some(s) => s,
            None => return false,
        };
        let (level, nritems) = unsafe {
            (NODE_BUF[slot][100], read_le32(&NODE_BUF[slot], 96) as usize)
        };
        if nritems == 0 && level == 0 {
            // Empty leaf — insert directly.
            return leaf_insert_item(blk, slot, key, data);
        }
        if level == 0 {
            return leaf_insert_item(blk, slot, key, data);
        }
        // Internal: find child.
        let mut idx = 0;
        for i in 1..nritems {
            let k = unsafe {
                read_key_at(
                    &NODE_BUF[slot],
                    BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE,
                )
            };
            if key_cmp(&k, key) <= 0 {
                idx = i;
            } else {
                break;
            }
        }
        logical = unsafe {
            read_le64(
                &NODE_BUF[slot],
                BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE + BTRFS_KEY_SIZE,
            )
        };
    }
}

/// Delete an item from a tree.  Returns true if found and deleted.
fn tree_delete(blk: &BlkClient, tree_root: u64, key: &BtrfsKey) -> bool {
    match tree_search(blk, tree_root, key) {
        Some((slot, idx, found)) if key_cmp(&found, key) == 0 => {
            leaf_delete_item(blk, slot, idx)
        }
        _ => false,
    }
}

/// Update an existing item's data in-place (same size only).
fn tree_update(
    blk: &BlkClient,
    tree_root: u64,
    key: &BtrfsKey,
    data: &[u8],
) -> bool {
    match tree_search(blk, tree_root, key) {
        Some((slot, idx, found)) if key_cmp(&found, key) == 0 => {
            leaf_update_item_data(blk, slot, idx, data)
        }
        _ => false,
    }
}

// =====================================================================
// Volume state + superblock parsing
// =====================================================================
struct BtrfsVol {
    #[allow(dead_code)]
    nodesize: u32,
    sectorsize: u32,
    fs_tree_root: u64,
    #[allow(dead_code)]
    fs_tree_level: u8,
    total_bytes: u64,
    bytes_used: u64,
}

/// Parse superblock, bootstrap chunks, walk chunk tree.
/// Returns (BtrfsVol-without-fs-tree, root_tree_root, root_level).
fn parse_superblock(blk: &BlkClient) -> Option<(BtrfsVol, u64, u8)> {
    // Reset state (in case this is a retry).
    unsafe {
        CHUNK_COUNT = 0;
        for i in 0..NODE_CACHE_SLOTS {
            NODE_ADDR[i] = u64::MAX;
        }
    }

    // Read 4096-byte superblock at device offset 0x10000.
    let mut sb = [0u8; 4096];
    if !blk.read_range(BTRFS_SUPER_OFFSET, sb.as_mut_ptr() as usize, 4096) {
        syscall::debug_puts(b"  [btrfs_srv] superblock read failed\n");
        return None;
    }

    if &sb[SB_MAGIC..SB_MAGIC + 8] != b"_BHRfS_M" {
        syscall::debug_puts(b"  [btrfs_srv] bad magic\n");
        return None;
    }

    let nodesize = read_le32(&sb, SB_NODESIZE);
    let sectorsize = read_le32(&sb, SB_SECTORSIZE);
    let root_tree_root = read_le64(&sb, SB_ROOT);
    let root_level = sb[SB_ROOT_LEVEL];
    let chunk_root = read_le64(&sb, SB_CHUNK_ROOT);
    let total_bytes = read_le64(&sb, SB_TOTAL_BYTES);
    let bytes_used = read_le64(&sb, SB_BYTES_USED);

    if (nodesize as usize) > MAX_NODESIZE {
        return None;
    }
    unsafe {
        REAL_NODESIZE = nodesize as usize;
    }

    // Bootstrap chunk map from sys_chunk_array, then walk chunk tree.
    parse_sys_chunk_array(&sb);
    walk_chunk_tree(blk, chunk_root);

    // Verify the chunk map can resolve the root tree root.
    if logical_to_physical(root_tree_root).is_none() {
        return None;
    }

    let vol = BtrfsVol {
        nodesize,
        sectorsize,
        fs_tree_root: 0, // filled in later
        fs_tree_level: 0,
        total_bytes,
        bytes_used,
    };
    Some((vol, root_tree_root, root_level))
}

/// Search root tree for the default FS tree (objectid 5) ROOT_ITEM.
fn find_fs_tree(blk: &BlkClient, root_tree_root: u64) -> Option<(u64, u8)> {
    // Floor-search for (5, ROOT_ITEM, MAX) to find any generation-keyed variant.
    let key = BtrfsKey {
        objectid: BTRFS_FS_TREE_OBJECTID,
        typ: BTRFS_ROOT_ITEM_KEY,
        offset: u64::MAX,
    };
    let (slot, idx, found) = tree_search(blk, root_tree_root, &key)?;

    if found.objectid != BTRFS_FS_TREE_OBJECTID
        || found.typ != BTRFS_ROOT_ITEM_KEY
    {
        return None;
    }

    let (data_off, data_sz) = leaf_item_info(slot, idx);
    if data_sz < ROOT_ITEM_LEVEL + 1 {
        return None;
    }

    let bytenr = unsafe { read_le64(&NODE_BUF[slot], data_off + ROOT_ITEM_BYTENR) };
    let level = unsafe { NODE_BUF[slot][data_off + ROOT_ITEM_LEVEL] };
    Some((bytenr, level))
}

// =====================================================================
// Inode operations
// =====================================================================
#[derive(Clone, Copy)]
struct BtrfsInode {
    objectid: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    #[allow(dead_code)]
    nlink: u32,
}

impl BtrfsInode {
    fn is_dir(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }
}

fn lookup_inode(blk: &BlkClient, vol: &BtrfsVol, objectid: u64) -> Option<BtrfsInode> {
    let key = BtrfsKey { objectid, typ: BTRFS_INODE_ITEM_KEY, offset: 0 };
    let (slot, idx, found) = tree_search(blk, vol.fs_tree_root, &key)?;
    if found.objectid != objectid || found.typ != BTRFS_INODE_ITEM_KEY {
        return None;
    }

    let (data_off, data_sz) = leaf_item_info(slot, idx);
    if data_sz < 160 {
        return None;
    }

    unsafe {
        let buf = &NODE_BUF[slot];
        Some(BtrfsInode {
            objectid,
            size: read_le64(buf, data_off + 16),
            mode: read_le32(buf, data_off + 52),
            uid: read_le32(buf, data_off + 44),
            gid: read_le32(buf, data_off + 48),
            nlink: read_le32(buf, data_off + 40),
        })
    }
}

// =====================================================================
// Directory operations
// =====================================================================

/// Look up a directory entry by name.  Returns target objectid.
fn lookup_dir_entry(
    blk: &BlkClient,
    vol: &BtrfsVol,
    parent_oid: u64,
    name: &[u8],
) -> Option<u64> {
    let hash = btrfs_name_hash(name);
    let key = BtrfsKey {
        objectid: parent_oid,
        typ: BTRFS_DIR_ITEM_KEY,
        offset: hash,
    };
    let (slot, idx, found) = tree_search(blk, vol.fs_tree_root, &key)?;
    if found.objectid != parent_oid
        || found.typ != BTRFS_DIR_ITEM_KEY
        || found.offset != hash
    {
        return None;
    }

    // Walk concatenated dir_items (hash collision handling).
    let (data_off, data_sz) = leaf_item_info(slot, idx);
    let mut off = data_off;
    let end = data_off + data_sz;

    unsafe {
        let buf = &NODE_BUF[slot];
        while off + 30 <= end {
            let target_oid = read_le64(buf, off); // location.objectid
            let data_len = read_le16(buf, off + 25) as usize;
            let name_len = read_le16(buf, off + 27) as usize;
            if off + 30 + name_len > end {
                break;
            }
            let entry_name = &buf[off + 30..off + 30 + name_len];
            if name_len == name.len() && entry_name == name {
                return Some(target_oid);
            }
            off += 30 + name_len + data_len;
        }
    }
    None
}

/// Get the next DIR_INDEX entry at or after `start_index`.
/// Returns `(child_oid, name_buf, name_len, next_index)`.
fn dir_next_entry(
    blk: &BlkClient,
    vol: &BtrfsVol,
    parent_oid: u64,
    start_index: u64,
) -> Option<(u64, [u8; 256], usize, u64)> {
    let key = BtrfsKey {
        objectid: parent_oid,
        typ: BTRFS_DIR_INDEX_KEY,
        offset: start_index,
    };
    let (slot, idx, found) = tree_search_ge(blk, vol.fs_tree_root, &key)?;
    if found.objectid != parent_oid || found.typ != BTRFS_DIR_INDEX_KEY {
        return None;
    }

    let (data_off, data_sz) = leaf_item_info(slot, idx);
    if data_sz < 30 {
        return None;
    }

    unsafe {
        let buf = &NODE_BUF[slot];
        let target_oid = read_le64(buf, data_off); // location.objectid
        let name_len = read_le16(buf, data_off + 27) as usize;
        let nlen = name_len.min(255);

        let mut name_buf = [0u8; 256];
        if data_off + 30 + nlen <= data_off + data_sz {
            for j in 0..nlen {
                name_buf[j] = buf[data_off + 30 + j];
            }
        }
        Some((target_oid, name_buf, nlen, found.offset + 1))
    }
}

// =====================================================================
// Inode / directory / file write helpers
// =====================================================================

/// Build an INODE_ITEM (160 bytes) in a buffer.
fn build_inode_item(size: u64, mode: u32, nlink: u32) -> [u8; 160] {
    let mut buf = [0u8; 160];
    // generation at +0 (u64) — leave 0
    // transid at +8 (u64) — leave 0
    write_le64(&mut buf, 16, size);     // size
    // nbytes at +24 (u64) — same as size for inline
    write_le64(&mut buf, 24, size);
    // block_group at +32 (u64) — leave 0
    write_le32(&mut buf, 40, nlink);    // nlink
    write_le32(&mut buf, 44, 0);        // uid
    write_le32(&mut buf, 48, 0);        // gid
    write_le32(&mut buf, 52, mode);     // mode
    // rdev, flags, sequence all 0
    // atime/ctime/mtime/otime are timespec pairs at offsets 80+ — leave 0
    buf
}

/// Create a new regular file inode + INODE_REF + DIR_ITEM + DIR_INDEX.
/// Returns objectid on success.
fn create_file(
    blk: &BlkClient,
    vol: &BtrfsVol,
    parent_oid: u64,
    name: &[u8],
) -> Option<u64> {
    let ino = alloc_ino();

    // 1. INODE_ITEM
    let inode_data = build_inode_item(0, 0o100644, 1);
    let inode_key = BtrfsKey {
        objectid: ino,
        typ: BTRFS_INODE_ITEM_KEY,
        offset: 0,
    };
    if !tree_insert(blk, vol.fs_tree_root, &inode_key, &inode_data) {
        return None;
    }

    // 2. INODE_REF: (ino, INODE_REF, parent_oid) → index(u64) + namelen(u16) + name
    let mut ref_data = [0u8; 128];
    let dir_index = next_dir_index(blk, vol, parent_oid);
    write_le64(&mut ref_data, 0, dir_index);               // index
    ref_data[8] = name.len() as u8;
    ref_data[9] = (name.len() >> 8) as u8;
    for i in 0..name.len().min(116) {
        ref_data[10 + i] = name[i];
    }
    let ref_key = BtrfsKey {
        objectid: ino,
        typ: BTRFS_INODE_REF_KEY,
        offset: parent_oid,
    };
    if !tree_insert(blk, vol.fs_tree_root, &ref_key, &ref_data[..10 + name.len()]) {
        tree_delete(blk, vol.fs_tree_root, &inode_key);
        return None;
    }

    // 3. DIR_ITEM: (parent, DIR_ITEM, name_hash)
    if !add_dir_entry(blk, vol, parent_oid, name, ino, dir_index) {
        tree_delete(blk, vol.fs_tree_root, &ref_key);
        tree_delete(blk, vol.fs_tree_root, &inode_key);
        return None;
    }

    // 4. Update parent inode size (not critical, skip for simplicity).

    Some(ino)
}

/// Create a new directory.
fn create_dir(
    blk: &BlkClient,
    vol: &BtrfsVol,
    parent_oid: u64,
    name: &[u8],
    mode: u32,
) -> Option<u64> {
    let ino = alloc_ino();
    let dir_mode = 0o040000 | (mode & 0o7777);

    // 1. INODE_ITEM for directory
    let inode_data = build_inode_item(0, dir_mode, 2);
    let inode_key = BtrfsKey {
        objectid: ino,
        typ: BTRFS_INODE_ITEM_KEY,
        offset: 0,
    };
    if !tree_insert(blk, vol.fs_tree_root, &inode_key, &inode_data) {
        return None;
    }

    // 2. INODE_REF
    let mut ref_data = [0u8; 128];
    let dir_index = next_dir_index(blk, vol, parent_oid);
    write_le64(&mut ref_data, 0, dir_index);
    ref_data[8] = name.len() as u8;
    ref_data[9] = (name.len() >> 8) as u8;
    for i in 0..name.len().min(116) {
        ref_data[10 + i] = name[i];
    }
    let ref_key = BtrfsKey {
        objectid: ino,
        typ: BTRFS_INODE_REF_KEY,
        offset: parent_oid,
    };
    if !tree_insert(blk, vol.fs_tree_root, &ref_key, &ref_data[..10 + name.len()]) {
        tree_delete(blk, vol.fs_tree_root, &inode_key);
        return None;
    }

    // 3. DIR_ITEM + DIR_INDEX in parent
    if !add_dir_entry(blk, vol, parent_oid, name, ino, dir_index) {
        tree_delete(blk, vol.fs_tree_root, &ref_key);
        tree_delete(blk, vol.fs_tree_root, &inode_key);
        return None;
    }

    Some(ino)
}

/// Find the next available DIR_INDEX for a parent directory.
fn next_dir_index(blk: &BlkClient, vol: &BtrfsVol, parent_oid: u64) -> u64 {
    // Search for the highest DIR_INDEX entry.
    let key = BtrfsKey {
        objectid: parent_oid,
        typ: BTRFS_DIR_INDEX_KEY,
        offset: u64::MAX,
    };
    match tree_search(blk, vol.fs_tree_root, &key) {
        Some((_, _, found))
            if found.objectid == parent_oid
                && found.typ == BTRFS_DIR_INDEX_KEY =>
        {
            found.offset + 1
        }
        _ => 2, // DIR_INDEX starts at 2.
    }
}

/// Add a DIR_ITEM + DIR_INDEX entry for `child_oid` under `parent_oid`.
fn add_dir_entry(
    blk: &BlkClient,
    vol: &BtrfsVol,
    parent_oid: u64,
    name: &[u8],
    child_oid: u64,
    dir_index: u64,
) -> bool {
    // DIR_ITEM data: location key (17) + transid(8) + data_len(2) + name_len(2) + type(1) + name
    let entry_sz = 30 + name.len();
    let mut entry = [0u8; 286]; // 30 + 256 max
    // location key: (child_oid, INODE_ITEM, 0)
    write_le64(&mut entry, 0, child_oid);   // location.objectid
    entry[8] = BTRFS_INODE_ITEM_KEY;        // location.type
    write_le64(&mut entry, 9, 0);           // location.offset
    // transid at +17 — leave 0
    // data_len at +25
    entry[25] = 0;
    entry[26] = 0;
    // name_len at +27
    entry[27] = name.len() as u8;
    entry[28] = (name.len() >> 8) as u8;
    // type at +29: 1=regular file, 2=directory
    // Peek at child inode to determine type.
    entry[29] = if let Some(inode) = lookup_inode(blk, vol, child_oid) {
        if inode.is_dir() { 2 } else { 1 }
    } else {
        1
    };
    // name at +30
    for i in 0..name.len() {
        entry[30 + i] = name[i];
    }

    let hash = btrfs_name_hash(name);

    // Insert DIR_ITEM.
    let dir_item_key = BtrfsKey {
        objectid: parent_oid,
        typ: BTRFS_DIR_ITEM_KEY,
        offset: hash,
    };
    if !tree_insert(blk, vol.fs_tree_root, &dir_item_key, &entry[..entry_sz]) {
        return false;
    }

    // Insert DIR_INDEX.
    let dir_index_key = BtrfsKey {
        objectid: parent_oid,
        typ: BTRFS_DIR_INDEX_KEY,
        offset: dir_index,
    };
    if !tree_insert(blk, vol.fs_tree_root, &dir_index_key, &entry[..entry_sz]) {
        // Rollback DIR_ITEM.
        tree_delete(blk, vol.fs_tree_root, &dir_item_key);
        return false;
    }

    true
}

/// Remove directory entries (DIR_ITEM + DIR_INDEX + INODE_REF) for `name` under `parent_oid`.
fn remove_dir_entry(
    blk: &BlkClient,
    vol: &BtrfsVol,
    parent_oid: u64,
    name: &[u8],
    child_oid: u64,
) -> bool {
    let hash = btrfs_name_hash(name);

    // Delete DIR_ITEM.
    let dir_item_key = BtrfsKey {
        objectid: parent_oid,
        typ: BTRFS_DIR_ITEM_KEY,
        offset: hash,
    };
    tree_delete(blk, vol.fs_tree_root, &dir_item_key);

    // Find and delete DIR_INDEX — scan for the one pointing to child_oid.
    let mut idx = 2u64;
    loop {
        let key = BtrfsKey {
            objectid: parent_oid,
            typ: BTRFS_DIR_INDEX_KEY,
            offset: idx,
        };
        match tree_search_ge(blk, vol.fs_tree_root, &key) {
            Some((slot, item_idx, found))
                if found.objectid == parent_oid
                    && found.typ == BTRFS_DIR_INDEX_KEY =>
            {
                let (data_off, data_sz) = leaf_item_info(slot, item_idx);
                if data_sz >= 30 {
                    let target = unsafe { read_le64(&NODE_BUF[slot], data_off) };
                    if target == child_oid {
                        tree_delete(blk, vol.fs_tree_root, &found);
                        break;
                    }
                }
                idx = found.offset + 1;
            }
            _ => break,
        }
    }

    // Delete INODE_REF.
    let ref_key = BtrfsKey {
        objectid: child_oid,
        typ: BTRFS_INODE_REF_KEY,
        offset: parent_oid,
    };
    tree_delete(blk, vol.fs_tree_root, &ref_key);

    true
}

/// Update an inode's INODE_ITEM (size, mode, etc.) on disk.
fn update_inode(
    blk: &BlkClient,
    vol: &BtrfsVol,
    inode: &BtrfsInode,
) -> bool {
    let key = BtrfsKey {
        objectid: inode.objectid,
        typ: BTRFS_INODE_ITEM_KEY,
        offset: 0,
    };
    let data = build_inode_item(inode.size, inode.mode, inode.nlink);
    tree_update(blk, vol.fs_tree_root, &key, &data)
}

/// Write inline file data (for small files, ≤ ~3800 bytes).
/// Replaces or creates EXTENT_DATA item with inline type.
fn write_inline_extent(
    blk: &BlkClient,
    vol: &BtrfsVol,
    ino: u64,
    data: &[u8],
) -> bool {
    let key = BtrfsKey {
        objectid: ino,
        typ: BTRFS_EXTENT_DATA_KEY,
        offset: 0,
    };

    // Delete existing extent if any.
    tree_delete(blk, vol.fs_tree_root, &key);

    if data.is_empty() {
        return true;
    }

    // Build inline extent item: 21-byte header + data.
    let item_sz = 21 + data.len();
    let mut item = [0u8; 4096]; // max inline
    // generation at +0 (u64) — 0
    write_le64(&mut item, 0, 0);
    // ram_bytes at +8 (u64) — actual size
    write_le64(&mut item, 8, data.len() as u64);
    // compression at +16 — 0 (none)
    item[16] = 0;
    // encryption at +17 — 0
    item[17] = 0;
    // other_encoding at +18 (u16) — 0
    item[18] = 0;
    item[19] = 0;
    // type at +20 — INLINE
    item[20] = BTRFS_FILE_EXTENT_INLINE;
    // data at +21
    for i in 0..data.len() {
        item[21 + i] = data[i];
    }

    tree_insert(blk, vol.fs_tree_root, &key, &item[..item_sz])
}

/// Write a regular (non-inline) extent for larger files.
/// Allocates a new logical block, writes data, creates EXTENT_DATA item.
fn write_regular_extent(
    blk: &BlkClient,
    vol: &mut BtrfsVol,
    ino: u64,
    file_off: u64,
    data: &[u8],
) -> bool {
    let nsz = unsafe { REAL_NODESIZE as u64 };
    // Round up to nodesize for allocation.
    let alloc_sz = ((data.len() as u64) + nsz - 1) & !(nsz - 1);

    let logical = match alloc_logical(alloc_sz) {
        Some(a) => a,
        None => return false,
    };
    let physical = match logical_to_physical(logical) {
        Some(p) => p,
        None => return false,
    };

    // Write data to disk.
    // Use a temporary buffer for the write (sector-aligned).
    static mut EXTENT_BUF: [u8; 16384] = [0u8; 16384];
    unsafe {
        let wlen = data.len().min(16384);
        core::ptr::write_bytes(EXTENT_BUF.as_mut_ptr(), 0, 16384);
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            EXTENT_BUF.as_mut_ptr(),
            wlen,
        );
        if !blk.write_range(physical, EXTENT_BUF.as_ptr() as usize, alloc_sz as usize) {
            return false;
        }
    }

    vol.bytes_used += alloc_sz;

    // Build EXTENT_DATA item (53 bytes for regular extent).
    let mut item = [0u8; 53];
    // generation at +0
    write_le64(&mut item, 0, 0);
    // ram_bytes at +8
    write_le64(&mut item, 8, data.len() as u64);
    // compression=0, encryption=0, other_encoding=0
    // type at +20 = REGULAR
    item[20] = BTRFS_FILE_EXTENT_REG;
    // disk_bytenr at +21
    write_le64(&mut item, 21, logical);
    // disk_num_bytes at +29
    write_le64(&mut item, 29, alloc_sz);
    // offset at +37 (offset within extent) = 0
    write_le64(&mut item, 37, 0);
    // num_bytes at +45 (logical bytes = data.len)
    write_le64(&mut item, 45, data.len() as u64);

    let key = BtrfsKey {
        objectid: ino,
        typ: BTRFS_EXTENT_DATA_KEY,
        offset: file_off,
    };
    tree_insert(blk, vol.fs_tree_root, &key, &item)
}

/// Free all extent data items for an inode (before deletion).
fn free_file_extents(blk: &BlkClient, vol: &BtrfsVol, ino: u64) {
    // Delete all EXTENT_DATA keys for this inode.
    loop {
        let key = BtrfsKey {
            objectid: ino,
            typ: BTRFS_EXTENT_DATA_KEY,
            offset: 0,
        };
        match tree_search_ge(blk, vol.fs_tree_root, &key) {
            Some((_, _, found))
                if found.objectid == ino
                    && found.typ == BTRFS_EXTENT_DATA_KEY =>
            {
                if !tree_delete(blk, vol.fs_tree_root, &found) {
                    break;
                }
            }
            _ => break,
        }
    }
}

/// Delete a file (or empty directory): remove dir entries, extents, inode.
fn delete_file(
    blk: &BlkClient,
    vol: &BtrfsVol,
    parent_oid: u64,
    name: &[u8],
) -> bool {
    // Look up the child.
    let child_oid = match lookup_dir_entry(blk, vol, parent_oid, name) {
        Some(oid) => oid,
        None => return false,
    };

    // Free file extents.
    free_file_extents(blk, vol, child_oid);

    // Remove dir entries.
    remove_dir_entry(blk, vol, parent_oid, name, child_oid);

    // Delete INODE_ITEM.
    let inode_key = BtrfsKey {
        objectid: child_oid,
        typ: BTRFS_INODE_ITEM_KEY,
        offset: 0,
    };
    tree_delete(blk, vol.fs_tree_root, &inode_key);

    true
}

// =====================================================================
// File extent reading
// =====================================================================

/// Read file data for `inode_oid` at `file_off` into `dest` VA.
/// Returns number of bytes actually read.
fn read_file_data(
    blk: &BlkClient,
    vol: &BtrfsVol,
    inode_oid: u64,
    file_size: u64,
    file_off: u64,
    dest: usize,
    length: usize,
) -> usize {
    if file_off >= file_size {
        return 0;
    }
    let avail = (file_size - file_off) as usize;
    let to_read = length.min(avail);
    let mut total = 0usize;

    while total < to_read {
        let cur_off = file_off + total as u64;
        let key = BtrfsKey {
            objectid: inode_oid,
            typ: BTRFS_EXTENT_DATA_KEY,
            offset: cur_off,
        };
        let (slot, idx, found) = match tree_search(blk, vol.fs_tree_root, &key) {
            Some(r)
                if r.2.objectid == inode_oid
                    && r.2.typ == BTRFS_EXTENT_DATA_KEY =>
            {
                r
            }
            _ => break,
        };

        let (data_off, data_sz) = leaf_item_info(slot, idx);
        if data_sz < 21 {
            break;
        }

        let extent_file_off = found.offset;
        let compression = unsafe { NODE_BUF[slot][data_off + 16] };
        let extent_type = unsafe { NODE_BUF[slot][data_off + 20] };

        if compression != 0 {
            break; // no compression support
        }

        if extent_type == BTRFS_FILE_EXTENT_INLINE {
            let inline_len = data_sz - 21;
            let off_in = (cur_off - extent_file_off) as usize;
            if off_in >= inline_len {
                break;
            }
            let chunk = (to_read - total).min(inline_len - off_in);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    NODE_BUF[slot].as_ptr().add(data_off + 21 + off_in),
                    (dest + total) as *mut u8,
                    chunk,
                );
            }
            total += chunk;
        } else if extent_type == BTRFS_FILE_EXTENT_REG
            || extent_type == BTRFS_FILE_EXTENT_PREALLOC
        {
            if data_sz < 53 {
                break;
            }

            // Extract extent descriptor (before any disk reads that might evict slot).
            let (disk_bytenr, extent_offset, num_bytes) = unsafe {
                let buf = &NODE_BUF[slot];
                (
                    read_le64(buf, data_off + 21),
                    read_le64(buf, data_off + 37),
                    read_le64(buf, data_off + 45),
                )
            };

            let off_in = cur_off - extent_file_off;
            if off_in >= num_bytes {
                // Past this extent — gap/hole — fill zeros.
                let chunk = (to_read - total).min(512);
                unsafe {
                    core::ptr::write_bytes((dest + total) as *mut u8, 0, chunk);
                }
                total += chunk;
                continue;
            }

            let remaining = (num_bytes - off_in) as usize;
            let chunk = (to_read - total).min(remaining);

            if disk_bytenr == 0 {
                // Hole.
                unsafe {
                    core::ptr::write_bytes((dest + total) as *mut u8, 0, chunk);
                }
                total += chunk;
                continue;
            }

            // Translate logical → physical, read sector by sector.
            let disk_logical = disk_bytenr + extent_offset + off_in;
            let mut done = 0usize;
            while done < chunk {
                let cur_log = disk_logical + done as u64;
                let sec_start = cur_log & !511u64;
                let skip = (cur_log & 511) as usize;

                let phys = match logical_to_physical(sec_start) {
                    Some(p) => p,
                    None => break,
                };

                let mut sec = [0u8; 512];
                if !blk.read_bytes(phys, &mut sec) {
                    break;
                }

                let piece = (512 - skip).min(chunk - done);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        sec[skip..].as_ptr(),
                        (dest + total + done) as *mut u8,
                        piece,
                    );
                }
                done += piece;
            }
            total += done;
            if done < chunk {
                break;
            }
        } else {
            break;
        }
    }
    total
}

/// Convenience: read into a `&mut [u8]` slice.
fn read_file_data_buf(
    blk: &BlkClient,
    vol: &BtrfsVol,
    inode_oid: u64,
    file_size: u64,
    file_off: u64,
    out: &mut [u8],
) -> usize {
    read_file_data(
        blk,
        vol,
        inode_oid,
        file_size,
        file_off,
        out.as_mut_ptr() as usize,
        out.len(),
    )
}

// =====================================================================
// Path resolution
// =====================================================================
fn path_resolve(blk: &BlkClient, vol: &BtrfsVol, path: &[u8]) -> Option<BtrfsInode> {
    let mut p = path;
    while !p.is_empty() && p[0] == b'/' {
        p = &p[1..];
    }
    while !p.is_empty() && p[p.len() - 1] == b'/' {
        p = &p[..p.len() - 1];
    }

    if p.is_empty() {
        return lookup_inode(blk, vol, BTRFS_FIRST_FREE_OBJECTID);
    }

    let mut current_oid = BTRFS_FIRST_FREE_OBJECTID;
    let mut start = 0;
    while start < p.len() {
        let mut end = start;
        while end < p.len() && p[end] != b'/' {
            end += 1;
        }
        let component = &p[start..end];
        if component.is_empty() {
            start = end + 1;
            continue;
        }
        current_oid = lookup_dir_entry(blk, vol, current_oid, component)?;
        start = end + 1;
    }

    lookup_inode(blk, vol, current_oid)
}

// =====================================================================
// Open handle table
// =====================================================================
#[derive(Clone, Copy)]
struct OpenHandle {
    active: bool,
    inode: BtrfsInode,
    pid: u32,
}

impl OpenHandle {
    const fn empty() -> Self {
        OpenHandle {
            active: false,
            inode: BtrfsInode {
                objectid: 0,
                size: 0,
                mode: 0,
                uid: 0,
                gid: 0,
                nlink: 0,
            },
            pid: 0,
        }
    }
}

// =====================================================================
// Main entry point + IPC server
// =====================================================================
#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [btrfs_srv] starting\n");

    let partition_offset = if arg0 != 0 { arg0 } else { 401 * 1024 * 1024 };

    syscall::debug_puts(b"  [btrfs_srv] partition offset=");
    print_num(partition_offset);
    syscall::debug_puts(b"\n");

    // --- IPC setup (identical pattern to xfs_srv / ntfs_srv) ---
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"btrfs", port);
    syscall::ns_register(b"btrfs_task", my_aspace);

    let blk_port = {
        let mut retries = 200u32;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [btrfs_srv] cache_blk not found, exiting\n");
                syscall::exit(1);
            }
            syscall::nanosleep(10_000_000);
        }
    };

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
            syscall::debug_puts(b"  [btrfs_srv] blk connect FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    } else {
        syscall::debug_puts(b"  [btrfs_srv] blk no reply\n");
        syscall::exit(1);
        unreachable!()
    };

    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [btrfs_srv] scratch alloc FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_5000,
        partition_offset,
    };

    // --- Parse btrfs superblock, build chunk map, find FS tree ---
    // Wait briefly for cache_srv to connect to blk_srv, then retry mount.
    syscall::nanosleep(200_000_000); // 200 ms initial wait
    let mut vol = {
        let mut attempt = 0u32;
        loop {
            if let Some((mut v, root_tree_root, _root_level)) = parse_superblock(&blk) {
                if let Some((bytenr, level)) = find_fs_tree(&blk, root_tree_root) {
                    v.fs_tree_root = bytenr;
                    v.fs_tree_level = level;
                    if lookup_inode(&blk, &v, BTRFS_FIRST_FREE_OBJECTID).is_some() {
                        syscall::debug_puts(b"  [btrfs_srv] FS tree root=");
                        print_hex(bytenr);
                        syscall::debug_puts(b" level=");
                        print_num(level as u64);
                        syscall::debug_puts(b"\n");
                        break v;
                    }
                }
            }
            attempt += 1;
            if attempt >= 20 {
                syscall::debug_puts(b"  [btrfs_srv] mount failed after retries\n");
                loop { syscall::nanosleep(1_000_000_000_000); }
            }
            syscall::nanosleep(200_000_000); // 200 ms between retries
        }
    };

    // Initialize write infrastructure.
    init_allocator();
    init_next_ino(&blk, &vol);

    syscall::debug_puts(b"  [btrfs_srv] ready (read-write)\n");

    // --- Server loop ---
    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            // ----- FS_OPEN -----
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(inode) = path_resolve(&blk, &vol, name) {
                    match alloc_handle(&mut handles, inode, caller_pid) {
                        Some(h) => {
                            let _ = syscall::reply(
                                FS_OPEN_OK,
                                h as u64,
                                inode.size,
                                my_aspace as u64,
                                0,
                                0,
                            );
                        }
                        None => {
                            let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                        }
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            // ----- FS_OPEN_LONG -----
            FS_OPEN_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;
                let caller_pid = msg.data[1] as u32;
                let mut name = [0u8; 256];
                let nlen = name_len.min(256);
                let src = VFS_LONG_PATH_SCRATCH_VA as *const u8;
                for i in 0..nlen {
                    name[i] = unsafe { *src.add(i) };
                }

                if let Some(inode) = path_resolve(&blk, &vol, &name[..nlen]) {
                    match alloc_handle(&mut handles, inode, caller_pid) {
                        Some(h) => {
                            let _ = syscall::reply(
                                FS_OPEN_OK,
                                h as u64,
                                inode.size,
                                my_aspace as u64,
                                0,
                                0,
                            );
                        }
                        None => {
                            let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                        }
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            // ----- FS_CLOSE -----
            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    handles[handle].active = false;
                }
                let _ = syscall::reply(FS_CLOSE_OK, 0, 0, 0, 0, 0);
            }

            // ----- FS_READ -----
            FS_READ_FS => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1];
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let inode = handles[handle].inode;
                if offset >= inode.size {
                    let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                    continue;
                }

                if grant_va != 0 {
                    let n = read_file_data(
                        &blk,
                        &vol,
                        inode.objectid,
                        inode.size,
                        offset,
                        grant_va,
                        length,
                    );
                    let _ = syscall::reply(FS_READ_OK, n as u64, 0, 0, 0, 0);
                } else {
                    let mut buf = [0u8; 24];
                    let n = read_file_data_buf(
                        &blk,
                        &vol,
                        inode.objectid,
                        inode.size,
                        offset,
                        &mut buf,
                    );
                    let packed = pack_inline_data(&buf[..n.min(MAX_INLINE)]);
                    let _ = syscall::reply(
                        FS_READ_OK,
                        n as u64,
                        packed[0],
                        packed[1],
                        packed[2],
                        0,
                    );
                }
            }

            // ----- FS_READDIR -----
            FS_READDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let start_offset = msg.data[3] as u64;

                let parent_oid = if name_len == 0 {
                    Some(BTRFS_FIRST_FREE_OBJECTID)
                } else {
                    let name_buf =
                        unpack_name(msg.data[0], msg.data[1], name_len);
                    let name = &name_buf[..name_len.min(16)];
                    path_resolve(&blk, &vol, name)
                        .filter(|i| i.is_dir())
                        .map(|i| i.objectid)
                };

                let parent_oid = match parent_oid {
                    Some(oid) => oid,
                    None => {
                        let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                        continue;
                    }
                };

                // DIR_INDEX starts at index 2 (. and .. are implicit).
                let start = if start_offset == 0 { 2u64 } else { start_offset };

                match dir_next_entry(&blk, &vol, parent_oid, start) {
                    Some((child_oid, name_buf, name_len, next_index)) => {
                        let file_size = lookup_inode(&blk, &vol, child_oid)
                            .map(|i| i.size)
                            .unwrap_or(0);

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
                            next_index,
                            0,
                        );
                    }
                    None => {
                        let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                    }
                }
            }

            // ----- FS_STAT -----
            FS_STAT => {
                let handle = msg.data[0] as usize;
                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }
                let inode = &handles[handle].inode;
                let uid_gid =
                    (inode.uid as u64) | ((inode.gid as u64) << 16);
                let _ = syscall::reply(
                    FS_STAT_OK,
                    inode.size,
                    inode.mode as u64,
                    uid_gid,
                    inode.objectid,
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
                if let Some(inode) = path_resolve(&blk, &vol, &name[..nlen]) {
                    let uid_gid =
                        (inode.uid as u64) | ((inode.gid as u64) << 16);
                    let _ = syscall::reply(
                        FS_STAT_OK,
                        inode.size,
                        inode.mode as u64,
                        uid_gid,
                        inode.objectid,
                        0,
                    );
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let free_est = vol.total_bytes.saturating_sub(vol.bytes_used);
                let _ = syscall::reply(
                    FS_STATFS_OK,
                    vol.bytes_used,
                    free_est,
                    vol.sectorsize as u64,
                    0,
                    0,
                );
            }

            // ----- FS_CREATE / FS_MKNOD -----
            FS_CREATE | FS_MKNOD => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                match create_file(&blk, &vol, BTRFS_FIRST_FREE_OBJECTID, name) {
                    Some(ino) => {
                        let inode = match lookup_inode(&blk, &vol, ino) {
                            Some(i) => i,
                            None => {
                                let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                                continue;
                            }
                        };
                        match alloc_handle(&mut handles, inode, caller_pid) {
                            Some(h) => {
                                let _ = syscall::reply(
                                    FS_CREATE_OK,
                                    h as u64,
                                    0,
                                    my_aspace as u64,
                                    0,
                                    0,
                                );
                            }
                            None => {
                                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                            }
                        }
                    }
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    }
                }
            }

            // ----- FS_WRITE -----
            FS_WRITE_FS => {
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let ino = handles[handle].inode.objectid;
                let cur_size = handles[handle].inode.size;

                // For simplicity: collect all data to write.
                // Small files (<= ~3800): use inline extent.
                // Larger: use regular extent.
                if length == 0 {
                    let _ = syscall::reply(FS_WRITE_OK, 0, 0, 0, 0, 0);
                    continue;
                }

                // Read data from grant page into a local buffer.
                static mut WRITE_BUF: [u8; 16384] = [0u8; 16384];
                let wlen = length.min(16384);
                if grant_va != 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            grant_va as *const u8,
                            WRITE_BUF.as_mut_ptr(),
                            wlen,
                        );
                    }
                }

                let new_size = cur_size + wlen as u64;

                let ok = if new_size <= 3800 {
                    // Inline: read existing data, append, rewrite.
                    let mut combined = [0u8; 4096];
                    let existing = if cur_size > 0 {
                        read_file_data_buf(
                            &blk,
                            &vol,
                            ino,
                            cur_size,
                            0,
                            &mut combined[..cur_size as usize],
                        )
                    } else {
                        0
                    };
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            WRITE_BUF.as_ptr(),
                            combined.as_mut_ptr().add(existing),
                            wlen,
                        );
                    }
                    write_inline_extent(
                        &blk,
                        &vol,
                        ino,
                        &combined[..existing + wlen],
                    )
                } else {
                    // Regular extent: write at current EOF.
                    unsafe {
                        write_regular_extent(
                            &blk,
                            &mut vol,
                            ino,
                            cur_size,
                            &WRITE_BUF[..wlen],
                        )
                    }
                };

                if ok {
                    handles[handle].inode.size = new_size;
                    update_inode(&blk, &vol, &handles[handle].inode);
                    let _ = syscall::reply(FS_WRITE_OK, wlen as u64, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                }
            }

            // ----- FS_DELETE / FS_UNLINK -----
            FS_DELETE | FS_UNLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if delete_file(&blk, &vol, BTRFS_FIRST_FREE_OBJECTID, name) {
                    let _ = syscall::reply(FS_UNLINK_OK, 0, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            // ----- FS_MKDIR -----
            FS_MKDIR => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let mode = ((msg.data[2] >> 16) & 0xFFFF) as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let dir_mode = if mode == 0 { 0o755 } else { mode & 0o7777 };
                match create_dir(&blk, &vol, BTRFS_FIRST_FREE_OBJECTID, name, dir_mode)
                {
                    Some(_) => {
                        let _ = syscall::reply(FS_MKDIR_OK, 0, 0, 0, 0, 0);
                    }
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    }
                }
            }

            // ----- FS_RENAME -----
            FS_RENAME => {
                // data[0..1] = old name, data[2] = old_len | new_len<<16,
                // data[3..4] = new name
                let old_len = (msg.data[2] & 0xFFFF) as usize;
                let new_len = ((msg.data[2] >> 16) & 0xFFFF) as usize;
                let old_buf = unpack_name(msg.data[0], msg.data[1], old_len);
                let old_name = &old_buf[..old_len.min(16)];
                let new_buf = unpack_name(msg.data[3], msg.data[4], new_len);
                let new_name = &new_buf[..new_len.min(16)];

                let parent = BTRFS_FIRST_FREE_OBJECTID;
                let child_oid =
                    match lookup_dir_entry(&blk, &vol, parent, old_name) {
                        Some(oid) => oid,
                        None => {
                            let _ = syscall::reply(
                                FS_ERROR,
                                ERR_NOT_FOUND,
                                0,
                                0,
                                0,
                                0,
                            );
                            continue;
                        }
                    };

                // Remove old dir entries.
                remove_dir_entry(&blk, &vol, parent, old_name, child_oid);

                // Add new dir entries.
                let dir_index = next_dir_index(&blk, &vol, parent);

                // Re-add INODE_REF with new name.
                let mut ref_data = [0u8; 128];
                write_le64(&mut ref_data, 0, dir_index);
                ref_data[8] = new_name.len() as u8;
                ref_data[9] = (new_name.len() >> 8) as u8;
                for i in 0..new_name.len().min(116) {
                    ref_data[10 + i] = new_name[i];
                }
                let ref_key = BtrfsKey {
                    objectid: child_oid,
                    typ: BTRFS_INODE_REF_KEY,
                    offset: parent,
                };
                tree_insert(
                    &blk,
                    vol.fs_tree_root,
                    &ref_key,
                    &ref_data[..10 + new_name.len()],
                );

                add_dir_entry(
                    &blk,
                    &vol,
                    parent,
                    new_name,
                    child_oid,
                    dir_index,
                );

                let _ = syscall::reply(FS_RENAME_OK, 0, 0, 0, 0, 0);
            }

            // ----- FS_TRUNCATE -----
            FS_TRUNCATE => {
                let handle = msg.data[0] as usize;
                let new_size = msg.data[1];

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let ino = handles[handle].inode.objectid;

                // Delete all extents and rewrite if new_size > 0.
                free_file_extents(&blk, &vol, ino);

                if new_size > 0 && new_size <= 3800 {
                    // Read existing data, truncate, rewrite as inline.
                    let old_size = handles[handle].inode.size;
                    let read_sz = (new_size as usize).min(old_size as usize);
                    let mut buf = [0u8; 4096];
                    let got = read_file_data_buf(
                        &blk,
                        &vol,
                        ino,
                        old_size,
                        0,
                        &mut buf[..read_sz],
                    );
                    write_inline_extent(&blk, &vol, ino, &buf[..got.min(new_size as usize)]);
                }

                handles[handle].inode.size = new_size;
                update_inode(&blk, &vol, &handles[handle].inode);
                let _ = syscall::reply(FS_TRUNCATE_OK, 0, 0, 0, 0, 0);
            }

            // ----- FS_CHMOD -----
            FS_CHMOD => {
                let handle = msg.data[0] as usize;
                let new_mode = msg.data[1] as u32;

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                // Preserve file type bits, update permission bits.
                let ftype = handles[handle].inode.mode & 0o170000;
                handles[handle].inode.mode = ftype | (new_mode & 0o7777);
                update_inode(&blk, &vol, &handles[handle].inode);
                let _ = syscall::reply(FS_CHMOD_OK, 0, 0, 0, 0, 0);
            }

            // ----- FS_CHOWN -----
            FS_CHOWN => {
                let handle = msg.data[0] as usize;
                let uid = msg.data[1] as u32;
                let gid = msg.data[2] as u32;

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                handles[handle].inode.uid = uid;
                handles[handle].inode.gid = gid;
                update_inode(&blk, &vol, &handles[handle].inode);
                let _ = syscall::reply(FS_CHOWN_OK, 0, 0, 0, 0, 0);
            }

            // ----- FS_UTIMENS -----
            FS_UTIMENS => {
                // Timestamps stored as zero — just acknowledge.
                let _ = syscall::reply(FS_UTIMENS_OK, 0, 0, 0, 0, 0);
            }

            // Unsupported write ops.
            FS_SYMLINK | FS_READLINK | FS_LINK => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }

            _ => {}
        }
    }
}

fn alloc_handle(handles: &mut [OpenHandle; MAX_OPEN], inode: BtrfsInode, pid: u32) -> Option<usize> {
    for (i, h) in handles.iter_mut().enumerate() {
        if !h.active {
            h.active = true;
            h.inode = inode;
            h.pid = pid;
            return Some(i);
        }
    }
    None
}
