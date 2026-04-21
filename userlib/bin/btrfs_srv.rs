#![no_std]
#![no_main]
#![allow(static_mut_refs)]

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2024-2026 Nadia Chambers
// Reference: btrfs on-disk format (kernel.org wiki), Linux btrfs driver

//! Btrfs filesystem server (read-only).
//!
//! Pure userspace process that reads a btrfs partition from cache_blk via IPC.
//! The partition starts at a byte offset passed as arg0 (default 401 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE.

extern crate userlib;
use userlib::syscall;

// =====================================================================
// IPC protocol constants
// =====================================================================
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;

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
const FS_WRITE_FS: u64 = 0x2600;
const FS_DELETE: u64 = 0x2700;
const FS_MKDIR: u64 = 0x2A00;
const FS_UNLINK: u64 = 0x2A20;
const FS_CHMOD: u64 = 0x2E00;
const FS_UTIMENS: u64 = 0x2900;
const FS_SYMLINK: u64 = 0x2C00;
const FS_READLINK: u64 = 0x2C10;
const FS_LINK: u64 = 0x2C20;
const FS_RENAME: u64 = 0x2C30;
const FS_CHOWN: u64 = 0x2C40;
const FS_TRUNCATE: u64 = 0x2C50;
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
#[allow(dead_code)]
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

    syscall::debug_puts(b"  [btrfs_srv] nodesize=");
    print_num(nodesize as u64);
    syscall::debug_puts(b" sectorsize=");
    print_num(sectorsize as u64);
    syscall::debug_puts(b"\n");

    if (nodesize as usize) > MAX_NODESIZE {
        syscall::debug_puts(b"  [btrfs_srv] nodesize too large\n");
        return None;
    }
    unsafe {
        REAL_NODESIZE = nodesize as usize;
    }

    // Bootstrap chunk map from sys_chunk_array.
    parse_sys_chunk_array(&sb);

    syscall::debug_puts(b"  [btrfs_srv] bootstrap chunks: ");
    print_num(unsafe { CHUNK_COUNT } as u64);
    syscall::debug_puts(b"\n");

    // Walk chunk tree for full map.
    walk_chunk_tree(blk, chunk_root);

    syscall::debug_puts(b"  [btrfs_srv] total chunks: ");
    print_num(unsafe { CHUNK_COUNT } as u64);
    syscall::debug_puts(b"\n");

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
    let (mut vol, root_tree_root, _root_level) = match parse_superblock(&blk) {
        Some(v) => v,
        None => {
            syscall::debug_puts(b"  [btrfs_srv] mount failed\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
    };

    match find_fs_tree(&blk, root_tree_root) {
        Some((bytenr, level)) => {
            vol.fs_tree_root = bytenr;
            vol.fs_tree_level = level;
            syscall::debug_puts(b"  [btrfs_srv] FS tree root=");
            print_hex(bytenr);
            syscall::debug_puts(b" level=");
            print_num(level as u64);
            syscall::debug_puts(b"\n");
        }
        None => {
            syscall::debug_puts(b"  [btrfs_srv] FS tree not found\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
    }

    if lookup_inode(&blk, &vol, BTRFS_FIRST_FREE_OBJECTID).is_none() {
        syscall::debug_puts(b"  [btrfs_srv] WARNING: root dir inode not found\n");
    }

    syscall::debug_puts(b"  [btrfs_srv] ready\n");

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

            // Write operations — stubs (read-only filesystem).
            FS_CREATE | FS_MKNOD | FS_WRITE_FS | FS_DELETE | FS_MKDIR
            | FS_UNLINK | FS_CHMOD | FS_UTIMENS | FS_SYMLINK | FS_READLINK
            | FS_LINK | FS_RENAME | FS_CHOWN | FS_TRUNCATE => {
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
