#![no_std]
#![no_main]
#![allow(static_mut_refs)]

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2024-2026 Nadia Chambers
// Reference: Microsoft NTFS on-disk specification, Linux ntfs3 driver

//! NTFS filesystem server (read-only + write support).
//!
//! Pure userspace process that reads an NTFS partition from cache_blk via IPC.
//! The partition starts at a byte offset passed as arg0 (default 369 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE plus write ops.

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
#[allow(dead_code)]
const FS_DELETE_OK: u64 = 0x2701;
const FS_MKDIR: u64 = 0x2A00;
const FS_MKDIR_OK: u64 = 0x2A01;
const FS_UNLINK: u64 = 0x2A20;
#[allow(dead_code)]
const FS_UNLINK_OK: u64 = 0x2A21;
const FS_CHMOD: u64 = 0x2E00;
#[allow(dead_code)]
const FS_CHMOD_OK: u64 = 0x2E01;
const FS_UTIMENS: u64 = 0x2900;
#[allow(dead_code)]
const FS_UTIMENS_OK: u64 = 0x2901;
const FS_SYMLINK: u64 = 0x2C00;
#[allow(dead_code)]
const FS_SYMLINK_OK: u64 = 0x2C01;
const FS_READLINK: u64 = 0x2C10;
#[allow(dead_code)]
const FS_READLINK_OK: u64 = 0x2C11;
const FS_LINK: u64 = 0x2C20;
#[allow(dead_code)]
const FS_LINK_OK: u64 = 0x2C21;
const FS_RENAME: u64 = 0x2C30;
#[allow(dead_code)]
const FS_RENAME_OK: u64 = 0x2C31;
const FS_CHOWN: u64 = 0x2C40;
#[allow(dead_code)]
const FS_CHOWN_OK: u64 = 0x2C41;
const FS_TRUNCATE: u64 = 0x2C50;
#[allow(dead_code)]
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
#[allow(dead_code)]
const PAGE_SIZE: usize = 4096;

// --- NTFS on-disk constants ---

/// "FILE" record signature (little-endian).
const FILE_SIGNATURE: u32 = 0x454C4946; // "FILE"
/// "INDX" index allocation record signature.
const INDX_SIGNATURE: u32 = 0x58444E49; // "INDX"

// Well-known MFT record numbers.
const MFT_RECORD_MFT: u64 = 0;
#[allow(dead_code)]
const MFT_RECORD_MFTMIRR: u64 = 1;
#[allow(dead_code)]
const MFT_RECORD_LOGFILE: u64 = 2;
#[allow(dead_code)]
const MFT_RECORD_VOLUME: u64 = 3;
#[allow(dead_code)]
const MFT_RECORD_ATTRDEF: u64 = 4;
const MFT_RECORD_ROOT: u64 = 5;
#[allow(dead_code)]
const MFT_RECORD_BITMAP: u64 = 6;
#[allow(dead_code)]
const MFT_RECORD_BOOT: u64 = 7;

// Attribute type codes.
const AT_STANDARD_INFORMATION: u32 = 0x10;
const AT_ATTRIBUTE_LIST: u32 = 0x20;
const AT_FILE_NAME: u32 = 0x30;
#[allow(dead_code)]
const AT_OBJECT_ID: u32 = 0x40;
#[allow(dead_code)]
const AT_SECURITY_DESCRIPTOR: u32 = 0x50;
#[allow(dead_code)]
const AT_VOLUME_NAME: u32 = 0x60;
#[allow(dead_code)]
const AT_VOLUME_INFORMATION: u32 = 0x70;
const AT_DATA: u32 = 0x80;
const AT_INDEX_ROOT: u32 = 0x90;
const AT_INDEX_ALLOCATION: u32 = 0xA0;
#[allow(dead_code)]
const AT_BITMAP: u32 = 0xB0;
#[allow(dead_code)]
const AT_REPARSE_POINT: u32 = 0xC0;
const AT_END: u32 = 0xFFFFFFFF;

// File attribute flags (from STANDARD_INFORMATION / FILE_NAME).
const FILE_ATTR_READONLY: u32 = 0x0001;
const FILE_ATTR_HIDDEN: u32 = 0x0002;
const FILE_ATTR_SYSTEM: u32 = 0x0004;
const FILE_ATTR_DIRECTORY: u32 = 0x0010;
#[allow(dead_code)]
const FILE_ATTR_ARCHIVE: u32 = 0x0020;
const FILE_ATTR_REPARSE_POINT: u32 = 0x0400;

// MFT record header flags.
const MFT_RECORD_IN_USE: u16 = 0x0001;
const MFT_RECORD_IS_DIRECTORY: u16 = 0x0002;

// Index entry flags.
const INDEX_ENTRY_NODE: u32 = 0x01;
const INDEX_ENTRY_END: u32 = 0x02;

// FILE_NAME namespace types.
const FILE_NAME_POSIX: u8 = 0;
const FILE_NAME_WIN32: u8 = 1;
const FILE_NAME_DOS: u8 = 2;
const FILE_NAME_WIN32_AND_DOS: u8 = 3;

// S_IFMT for mode encoding.
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
#[allow(dead_code)]
const S_IFLNK: u32 = 0o120000;

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

// --- Little-endian read helpers (NTFS is little-endian on disk) ---

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

/// Case-insensitive ASCII comparison (NTFS is case-insensitive for lookups).
fn name_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        let ca = if a[i] >= b'A' && a[i] <= b'Z' {
            a[i] + 32
        } else {
            a[i]
        };
        let cb = if b[i] >= b'A' && b[i] <= b'Z' {
            b[i] + 32
        } else {
            b[i]
        };
        if ca != cb {
            return false;
        }
    }
    true
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
                Some(rr) if rr.data[1] == nonce => return Some(rr),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let mut remaining = out.len();
        let mut buf_off = 0usize;
        let mut byte_off = off;

        while remaining > 0 {
            let abs_off = self.partition_offset + byte_off;
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

            let ok =
                if let Some(rr) = self.recv_match(nonce) {
                    if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                        let copy_len = remaining.min(512 - offset_in_sector);
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (self.scratch_va + offset_in_sector) as *const u8,
                                out.as_mut_ptr().add(buf_off),
                                copy_len,
                            );
                        }
                        buf_off += copy_len;
                        byte_off += copy_len as u64;
                        remaining -= copy_len;
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

    /// Read a full cluster into memory at `dest` VA.
    fn read_cluster(&self, cluster: u64, cluster_size: u32, dest: usize) -> bool {
        let byte_off = cluster * (cluster_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = cluster_size / 512;

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

            let ok =
                if let Some(rr) = self.recv_match(nonce) {
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

            if !ok {
                return false;
            }
        }
        true
    }

    /// Write a full cluster from memory at `src` VA.
    fn write_cluster(&self, cluster: u64, cluster_size: u32, src: usize) -> bool {
        let byte_off = cluster * (cluster_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = cluster_size / 512;

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
            let ok =
                if let Some(rr) = self.recv_match(nonce) {
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
}

// =====================================================================
// Block cache
// =====================================================================

const CACHE_SLOTS: usize = 64;

#[derive(Clone, Copy)]
struct CacheEntry {
    cluster: u64,
    va: usize,
    valid: bool,
}

static mut CACHE: [CacheEntry; CACHE_SLOTS] = {
    let mut arr = [CacheEntry {
        cluster: 0,
        va: 0,
        valid: false,
    }; CACHE_SLOTS];
    let _ = arr;
    arr
};

static mut CACHE_NEXT: usize = 0;

fn cache_init() {
    for i in 0..CACHE_SLOTS {
        if let Some(va) = syscall::mmap_anon(0, 1, 1) {
            unsafe {
                CACHE[i].va = va;
                CACHE[i].valid = false;
            }
        }
    }
}

fn cache_read(blk: &BlkClient, cluster: u64, cluster_size: u32) -> Option<usize> {
    // Check cache.
    for i in 0..CACHE_SLOTS {
        let e = unsafe { &CACHE[i] };
        if e.valid && e.cluster == cluster {
            return Some(e.va);
        }
    }
    // Miss — evict and read.
    let slot = unsafe { CACHE_NEXT };
    unsafe {
        CACHE_NEXT = (slot + 1) % CACHE_SLOTS;
    }
    let va = unsafe { CACHE[slot].va };
    if va == 0 {
        return None;
    }
    if blk.read_cluster(cluster, cluster_size, va) {
        unsafe {
            CACHE[slot].cluster = cluster;
            CACHE[slot].valid = true;
        }
        Some(va)
    } else {
        None
    }
}

/// Invalidate a cached cluster (after writing to it).
fn cache_invalidate(cluster: u64) {
    for i in 0..CACHE_SLOTS {
        let e = unsafe { &mut CACHE[i] };
        if e.valid && e.cluster == cluster {
            e.valid = false;
        }
    }
}

// =====================================================================
// NTFS volume info (parsed from boot sector)
// =====================================================================

#[derive(Clone, Copy)]
struct NtfsVolume {
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    cluster_size: u32,
    mft_cluster: u64,
    mft_mirror_cluster: u64,
    mft_record_size: u32,
    index_record_size: u32,
    total_sectors: u64,
    total_clusters: u64,
}

fn parse_boot_sector(buf: &[u8]) -> Option<NtfsVolume> {
    // Check OEM ID "NTFS    " at offset 3.
    if buf[3] != b'N' || buf[4] != b'T' || buf[5] != b'F' || buf[6] != b'S' {
        return None;
    }

    let bytes_per_sector = read_le16(buf, 0x0B) as u32;
    let sectors_per_cluster = buf[0x0D] as u32;
    let total_sectors = read_le64(buf, 0x28);
    let mft_cluster = read_le64(buf, 0x30);
    let mft_mirror_cluster = read_le64(buf, 0x38);

    // Clusters per MFT record: if negative, it's a power of 2 in bytes.
    let mft_record_clusters = buf[0x40] as i8;
    let mft_record_size = if mft_record_clusters < 0 {
        1u32 << ((-mft_record_clusters) as u32)
    } else {
        (mft_record_clusters as u32) * sectors_per_cluster * bytes_per_sector
    };

    // Clusters per index record.
    let idx_clusters = buf[0x44] as i8;
    let index_record_size = if idx_clusters < 0 {
        1u32 << ((-idx_clusters) as u32)
    } else {
        (idx_clusters as u32) * sectors_per_cluster * bytes_per_sector
    };

    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let total_clusters = total_sectors / (sectors_per_cluster as u64);

    Some(NtfsVolume {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size,
        mft_cluster,
        mft_mirror_cluster,
        mft_record_size,
        index_record_size,
        total_sectors,
        total_clusters,
    })
}

// =====================================================================
// MFT record parsing
// =====================================================================

/// Maximum MFT record size we handle.
const MAX_MFT_RECORD: usize = 4096;

/// Buffer for reading MFT records.
static mut MFT_BUF: [u8; MAX_MFT_RECORD] = [0u8; MAX_MFT_RECORD];

/// Second buffer for directory traversal (to avoid clobbering MFT_BUF).
static mut MFT_BUF2: [u8; MAX_MFT_RECORD] = [0u8; MAX_MFT_RECORD];

/// Buffer for index allocation records.
static mut INDX_BUF: [u8; 4096] = [0u8; 4096];

/// Scratch buffer for write operations.
static mut WRITE_VA: usize = 0;

/// Apply the NTFS fixup array to a record buffer.
/// The update sequence array replaces the last 2 bytes of each sector
/// with the original values, using the USA at the start of the record.
fn apply_fixup(buf: &mut [u8], record_size: u32, sector_size: u32) -> bool {
    let usa_offset = read_le16(buf, 0x04) as usize;
    let usa_count = read_le16(buf, 0x06) as usize;

    if usa_offset + usa_count * 2 > record_size as usize || usa_count < 2 {
        return false;
    }

    let update_seq_number = read_le16(buf, usa_offset);

    // Each sector's last 2 bytes must match the update sequence number.
    for i in 1..usa_count {
        let sector_end = (i as usize) * (sector_size as usize) - 2;
        if sector_end + 1 >= buf.len() {
            break;
        }
        let on_disk = read_le16(buf, sector_end);
        if on_disk != update_seq_number {
            return false;
        }
        // Replace with the stored original value from the USA.
        let original = read_le16(buf, usa_offset + i * 2);
        buf[sector_end] = original as u8;
        buf[sector_end + 1] = (original >> 8) as u8;
    }
    true
}

/// Read an MFT record by record number into the given buffer.
fn read_mft_record(
    blk: &BlkClient,
    vol: &NtfsVolume,
    record_num: u64,
    buf: &mut [u8],
) -> bool {
    let mft_byte_offset =
        vol.mft_cluster * (vol.cluster_size as u64) + record_num * (vol.mft_record_size as u64);

    if !blk.read_bytes(mft_byte_offset, &mut buf[..vol.mft_record_size as usize]) {
        return false;
    }

    // Check "FILE" signature.
    if read_le32(buf, 0) != FILE_SIGNATURE {
        return false;
    }

    // Apply fixup.
    if !apply_fixup(buf, vol.mft_record_size, vol.bytes_per_sector) {
        return false;
    }

    // Check in-use flag.
    let flags = read_le16(buf, 0x16);
    if flags & MFT_RECORD_IN_USE == 0 {
        return false;
    }

    true
}

// =====================================================================
// Attribute iteration
// =====================================================================

/// An attribute header parsed from an MFT record.
#[derive(Clone, Copy)]
struct AttrHeader {
    attr_type: u32,
    length: u32,
    non_resident: bool,
    name_length: u8,
    name_offset: u16,
    // Resident fields.
    value_length: u32,
    value_offset: u16,
    // Non-resident fields.
    lowest_vcn: u64,
    highest_vcn: u64,
    data_run_offset: u16,
    alloc_size: u64,
    data_size: u64,
    init_size: u64,
    // Offset within the MFT record buffer.
    record_offset: usize,
}

impl AttrHeader {
    fn empty() -> Self {
        AttrHeader {
            attr_type: AT_END,
            length: 0,
            non_resident: false,
            name_length: 0,
            name_offset: 0,
            value_length: 0,
            value_offset: 0,
            lowest_vcn: 0,
            highest_vcn: 0,
            data_run_offset: 0,
            alloc_size: 0,
            data_size: 0,
            init_size: 0,
            record_offset: 0,
        }
    }
}

/// Parse the attribute at `off` in `buf`.
fn parse_attr(buf: &[u8], off: usize) -> Option<AttrHeader> {
    if off + 4 > buf.len() {
        return None;
    }
    let attr_type = read_le32(buf, off);
    if attr_type == AT_END || attr_type == 0 {
        return None;
    }
    if off + 16 > buf.len() {
        return None;
    }
    let length = read_le32(buf, off + 4);
    if length < 16 || (off + length as usize) > buf.len() {
        return None;
    }

    let non_resident = buf[off + 8] != 0;
    let name_length = buf[off + 9];
    let name_offset = read_le16(buf, off + 10);

    let mut hdr = AttrHeader::empty();
    hdr.attr_type = attr_type;
    hdr.length = length;
    hdr.non_resident = non_resident;
    hdr.name_length = name_length;
    hdr.name_offset = name_offset;
    hdr.record_offset = off;

    if non_resident {
        if off + 64 > buf.len() {
            return None;
        }
        hdr.lowest_vcn = read_le64(buf, off + 16);
        hdr.highest_vcn = read_le64(buf, off + 24);
        hdr.data_run_offset = read_le16(buf, off + 32);
        hdr.alloc_size = read_le64(buf, off + 40);
        hdr.data_size = read_le64(buf, off + 48);
        hdr.init_size = read_le64(buf, off + 56);
    } else {
        hdr.value_length = read_le32(buf, off + 16);
        hdr.value_offset = read_le16(buf, off + 20);
    }

    Some(hdr)
}

/// Find an attribute of the given type in an MFT record.
/// If `instance` > 0, skip that many matches (for multiple attributes of same type).
fn find_attr(buf: &[u8], record_size: u32, attr_type: u32, instance: usize) -> Option<AttrHeader> {
    let first_attr = read_le16(buf, 0x14) as usize;
    let mut off = first_attr;
    let mut found = 0usize;

    while off + 4 <= record_size as usize {
        if let Some(hdr) = parse_attr(buf, off) {
            if hdr.attr_type == attr_type {
                if found == instance {
                    return Some(hdr);
                }
                found += 1;
            }
            off += hdr.length as usize;
        } else {
            break;
        }
    }
    None
}

/// Get resident attribute data slice from MFT record buffer.
fn resident_data<'a>(buf: &'a [u8], hdr: &AttrHeader) -> &'a [u8] {
    let start = hdr.record_offset + hdr.value_offset as usize;
    let end = start + hdr.value_length as usize;
    if end <= buf.len() {
        &buf[start..end]
    } else {
        &buf[0..0]
    }
}

// =====================================================================
// Data run decoding (non-resident attribute extents)
// =====================================================================

/// A single extent from a data run.
#[derive(Clone, Copy)]
struct DataRun {
    vcn: u64,
    lcn: i64,   // Signed! Can be negative for sparse extents.
    length: u64, // In clusters.
}

const MAX_RUNS: usize = 64;

/// Decode the data run list from a non-resident attribute.
fn decode_data_runs(buf: &[u8], hdr: &AttrHeader) -> ([DataRun; MAX_RUNS], usize) {
    let mut runs = [DataRun {
        vcn: 0,
        lcn: 0,
        length: 0,
    }; MAX_RUNS];
    let mut count = 0usize;
    let mut vcn = 0u64;
    let mut prev_lcn = 0i64;

    let run_start = hdr.record_offset + hdr.data_run_offset as usize;
    let run_end = hdr.record_offset + hdr.length as usize;
    let mut pos = run_start;

    while pos < run_end && count < MAX_RUNS {
        if pos >= buf.len() {
            break;
        }
        let header_byte = buf[pos];
        if header_byte == 0 {
            break;
        }
        pos += 1;

        let length_size = (header_byte & 0x0F) as usize;
        let offset_size = ((header_byte >> 4) & 0x0F) as usize;

        if length_size == 0 || pos + length_size + offset_size > buf.len() {
            break;
        }

        // Read length (unsigned).
        let mut run_length = 0u64;
        for i in 0..length_size {
            run_length |= (buf[pos + i] as u64) << (i * 8);
        }
        pos += length_size;

        // Read offset (signed).
        let mut run_offset = 0i64;
        if offset_size > 0 {
            for i in 0..offset_size {
                run_offset |= (buf[pos + i] as i64) << (i * 8);
            }
            // Sign-extend.
            let shift = 64 - (offset_size * 8);
            run_offset = (run_offset << shift) >> shift;
            pos += offset_size;
        }

        let lcn = if offset_size == 0 {
            // Sparse run — no physical allocation.
            -1
        } else {
            prev_lcn += run_offset;
            prev_lcn
        };

        runs[count] = DataRun {
            vcn,
            lcn,
            length: run_length,
        };
        vcn += run_length;
        count += 1;
    }

    (runs, count)
}

/// Resolve a VCN (virtual cluster number) to an LCN (logical cluster number).
fn vcn_to_lcn(runs: &[DataRun], count: usize, vcn: u64) -> Option<u64> {
    for i in 0..count {
        let run = &runs[i];
        if vcn >= run.vcn && vcn < run.vcn + run.length {
            if run.lcn < 0 {
                return None; // Sparse.
            }
            let offset = vcn - run.vcn;
            return Some((run.lcn as u64) + offset);
        }
    }
    None
}

// =====================================================================
// Inode (file/directory metadata)
// =====================================================================

#[derive(Clone, Copy)]
struct NtfsInode {
    mft_record: u64,
    file_size: u64,
    alloc_size: u64,
    flags: u32, // FILE_ATTR_* flags
    is_dir: bool,
    mode: u32,
    // Data attribute info.
    data_resident: bool,
    data_value_offset: usize,
    data_value_length: u32,
    data_runs: [DataRun; MAX_RUNS],
    data_run_count: usize,
    // File name (UTF-8, up to 64 bytes).
    name: [u8; 64],
    name_len: usize,
    // Timestamps (100ns intervals since 1601-01-01).
    create_time: u64,
    modify_time: u64,
    access_time: u64,
}

impl NtfsInode {
    fn empty() -> Self {
        NtfsInode {
            mft_record: 0,
            file_size: 0,
            alloc_size: 0,
            flags: 0,
            is_dir: false,
            mode: 0,
            data_resident: false,
            data_value_offset: 0,
            data_value_length: 0,
            data_runs: [DataRun {
                vcn: 0,
                lcn: 0,
                length: 0,
            }; MAX_RUNS],
            data_run_count: 0,
            name: [0u8; 64],
            name_len: 0,
            create_time: 0,
            modify_time: 0,
            access_time: 0,
        }
    }

    fn is_dir(&self) -> bool {
        self.is_dir
    }
}

/// Read and parse an inode from its MFT record number.
/// Uses `buf` as scratch space for the MFT record.
fn parse_inode(buf: &[u8], vol: &NtfsVolume, record_num: u64) -> Option<NtfsInode> {
    let mut inode = NtfsInode::empty();
    inode.mft_record = record_num;

    // Check flags.
    let flags = read_le16(buf, 0x16);
    inode.is_dir = flags & MFT_RECORD_IS_DIRECTORY != 0;

    // Parse STANDARD_INFORMATION for timestamps and file attributes.
    if let Some(si) = find_attr(buf, vol.mft_record_size, AT_STANDARD_INFORMATION, 0) {
        if !si.non_resident {
            let data = resident_data(buf, &si);
            if data.len() >= 48 {
                inode.create_time = read_le64(data, 0);
                inode.modify_time = read_le64(data, 8);
                inode.access_time = read_le64(data, 24);
                inode.flags = read_le32(data, 32);
            }
        }
    }

    // Parse FILE_NAME for the name.
    // Prefer WIN32 or WIN32_AND_DOS namespace over DOS-only.
    let mut best_ns = 0xFFu8;
    let mut inst = 0usize;
    loop {
        match find_attr(buf, vol.mft_record_size, AT_FILE_NAME, inst) {
            Some(fn_attr) if !fn_attr.non_resident => {
                let data = resident_data(buf, &fn_attr);
                if data.len() >= 66 {
                    let namespace = data[65];
                    // Prefer WIN32 > WIN32_AND_DOS > POSIX, skip pure DOS.
                    let dominated = match namespace {
                        FILE_NAME_WIN32 => false,
                        FILE_NAME_WIN32_AND_DOS => best_ns != FILE_NAME_WIN32,
                        FILE_NAME_POSIX => {
                            best_ns != FILE_NAME_WIN32
                                && best_ns != FILE_NAME_WIN32_AND_DOS
                        }
                        FILE_NAME_DOS => true,
                        _ => true,
                    };
                    if !dominated || best_ns == 0xFF {
                        let name_chars = data[64] as usize;
                        let mut utf8_len = 0usize;
                        // Convert UTF-16LE to ASCII (sufficient for test files).
                        for c in 0..name_chars.min(32) {
                            let ch = read_le16(data, 66 + c * 2);
                            if ch < 128 && utf8_len < 64 {
                                inode.name[utf8_len] = ch as u8;
                                utf8_len += 1;
                            } else if utf8_len < 64 {
                                inode.name[utf8_len] = b'?';
                                utf8_len += 1;
                            }
                        }
                        inode.name_len = utf8_len;
                        if namespace != FILE_NAME_DOS {
                            best_ns = namespace;
                        }
                    }
                }
                inst += 1;
            }
            _ => break,
        }
    }

    // Parse DATA attribute (unnamed, instance 0).
    if !inode.is_dir {
        if let Some(data_attr) = find_attr(buf, vol.mft_record_size, AT_DATA, 0) {
            if data_attr.non_resident {
                inode.file_size = data_attr.data_size;
                inode.alloc_size = data_attr.alloc_size;
                inode.data_resident = false;
                let (runs, count) = decode_data_runs(buf, &data_attr);
                inode.data_runs = runs;
                inode.data_run_count = count;
            } else {
                inode.file_size = data_attr.value_length as u64;
                inode.alloc_size = data_attr.value_length as u64;
                inode.data_resident = true;
                inode.data_value_offset =
                    data_attr.record_offset + data_attr.value_offset as usize;
                inode.data_value_length = data_attr.value_length;
            }
        }
    }

    // Build mode.
    if inode.is_dir {
        inode.mode = S_IFDIR | 0o755;
    } else if inode.flags & FILE_ATTR_READONLY != 0 {
        inode.mode = S_IFREG | 0o444;
    } else {
        inode.mode = S_IFREG | 0o644;
    }

    Some(inode)
}

// =====================================================================
// Directory traversal (INDEX_ROOT + INDEX_ALLOCATION B-tree)
// =====================================================================

/// A directory entry from the $I30 index.
#[derive(Clone, Copy)]
struct DirEntry {
    mft_ref: u64,
    name: [u8; 64],
    name_len: usize,
    flags: u32,
}

/// Walk the index entries in a buffer region, searching for `target`.
/// If `target` is None, enumerate and return the entry at position `enum_offset`.
/// Returns (found_mft_ref, next_enum_offset) or None.
fn walk_index_entries(
    blk: &BlkClient,
    vol: &NtfsVolume,
    buf: &[u8],
    entries_offset: usize,
    entries_end: usize,
    target: Option<&[u8]>,
    enum_offset: &mut u32,
    enum_target: u32,
    result: &mut Option<DirEntry>,
) -> bool {
    let mut pos = entries_offset;

    while pos + 16 <= entries_end {
        let entry_length = read_le16(buf, pos + 8) as usize;
        let entry_key_length = read_le16(buf, pos + 10) as usize;
        let entry_flags = read_le32(buf, pos + 12);

        if entry_length < 16 {
            break;
        }

        // Check sub-node pointer (B-tree child) before this entry.
        // The sub-node VCN is at the last 8 bytes of the entry if INDEX_ENTRY_NODE.
        let has_sub = entry_flags & INDEX_ENTRY_NODE != 0;

        if entry_flags & INDEX_ENTRY_END != 0 {
            // End marker — check sub-node if present.
            if has_sub && entry_length >= 24 {
                let sub_vcn = read_le64(buf, pos + entry_length - 8);
                if walk_index_sub(blk, vol, sub_vcn, target, enum_offset, enum_target, result) {
                    return true;
                }
            }
            break;
        }

        // Parse the file name from the index entry.
        // Index entry key starts at offset 16 (for $I30 index it's a FILE_NAME attribute value).
        if entry_key_length >= 66 && pos + 16 + entry_key_length <= entries_end {
            let key = &buf[pos + 16..pos + 16 + entry_key_length];
            let mft_ref = read_le64(buf, pos) & 0x0000_FFFF_FFFF_FFFF;
            let name_chars = key[64] as usize;
            let namespace = key[65];

            // Skip DOS-only names.
            if namespace != FILE_NAME_DOS {
                let mut name = [0u8; 64];
                let mut nlen = 0usize;
                for c in 0..name_chars.min(32) {
                    let ch = read_le16(key, 66 + c * 2);
                    if ch < 128 && nlen < 64 {
                        name[nlen] = ch as u8;
                        nlen += 1;
                    } else if nlen < 64 {
                        name[nlen] = b'?';
                        nlen += 1;
                    }
                }

                if let Some(tgt) = target {
                    // Lookup mode.
                    if name_eq_ci(&name[..nlen], tgt) {
                        *result = Some(DirEntry {
                            mft_ref,
                            name,
                            name_len: nlen,
                            flags: read_le32(key, 56), // FILE_NAME flags
                        });
                        return true;
                    }
                } else {
                    // Enumeration mode.
                    // Visit sub-node first (in-order traversal).
                    if has_sub && entry_length >= 24 {
                        let sub_vcn = read_le64(buf, pos + entry_length - 8);
                        if walk_index_sub(
                            blk,
                            vol,
                            sub_vcn,
                            target,
                            enum_offset,
                            enum_target,
                            result,
                        ) {
                            return true;
                        }
                    }

                    // Skip system files (MFT records < 16 and names starting with '$').
                    let is_system = mft_ref < 16 || (nlen > 0 && name[0] == b'$');
                    if !is_system {
                        if *enum_offset == enum_target {
                            *result = Some(DirEntry {
                                mft_ref,
                                name,
                                name_len: nlen,
                                flags: read_le32(key, 56),
                            });
                            return true;
                        }
                        *enum_offset += 1;
                    }

                    pos += entry_length;
                    continue;
                }
            }
        }

        // Visit sub-node in lookup mode.
        if has_sub && target.is_some() && entry_length >= 24 {
            let sub_vcn = read_le64(buf, pos + entry_length - 8);
            if walk_index_sub(blk, vol, sub_vcn, target, enum_offset, enum_target, result) {
                return true;
            }
        }

        pos += entry_length;
    }

    false
}

/// Read and walk an INDX record at the given VCN.
fn walk_index_sub(
    blk: &BlkClient,
    vol: &NtfsVolume,
    vcn: u64,
    target: Option<&[u8]>,
    enum_offset: &mut u32,
    enum_target: u32,
    result: &mut Option<DirEntry>,
) -> bool {
    // The INDEX_ALLOCATION maps VCN → LCN. We need the parent directory's
    // INDEX_ALLOCATION data runs. For simplicity, we read from the index
    // allocation attribute that was cached by the caller. The VCN directly
    // maps to bytes at vcn * cluster_size in the index allocation data.

    // Read the INDX record from disk. The VCN tells us the byte offset
    // within the index allocation: byte_offset = vcn * cluster_size.
    // We need the data runs from the directory's INDEX_ALLOCATION attribute.
    // For now, use the global INDX_RUNS cache.
    let lcn = match vcn_to_lcn(
        unsafe { &INDX_RUNS },
        unsafe { INDX_RUN_COUNT },
        vcn,
    ) {
        Some(l) => l,
        None => return false,
    };

    // Read the cluster containing the INDX record.
    let mut indx = [0u8; 4096];
    let byte_off = lcn * (vol.cluster_size as u64);
    if !blk.read_bytes(byte_off, &mut indx[..vol.index_record_size as usize]) {
        return false;
    }

    // Check INDX signature.
    if read_le32(&indx, 0) != INDX_SIGNATURE {
        return false;
    }

    // Apply fixup.
    let mut indx_mut = indx;
    if !apply_fixup(
        &mut indx_mut,
        vol.index_record_size,
        vol.bytes_per_sector,
    ) {
        return false;
    }

    // The index node header is at offset 0x18.
    let entries_offset = 0x18 + read_le32(&indx_mut, 0x18) as usize;
    let entries_end = 0x18 + read_le32(&indx_mut, 0x1C) as usize;

    walk_index_entries(
        blk,
        vol,
        &indx_mut,
        entries_offset,
        entries_end,
        target,
        enum_offset,
        enum_target,
        result,
    )
}

/// Cached INDEX_ALLOCATION data runs for the current directory being traversed.
static mut INDX_RUNS: [DataRun; MAX_RUNS] = [DataRun {
    vcn: 0,
    lcn: 0,
    length: 0,
}; MAX_RUNS];
static mut INDX_RUN_COUNT: usize = 0;

/// Look up a name in a directory (given by MFT record number).
fn dir_lookup(
    blk: &BlkClient,
    vol: &NtfsVolume,
    dir_record: u64,
    name: &[u8],
) -> Option<u64> {
    let buf = unsafe { &mut MFT_BUF2 };
    if !read_mft_record(blk, vol, dir_record, buf) {
        return None;
    }

    // Cache INDEX_ALLOCATION data runs.
    if let Some(ia) = find_attr(buf, vol.mft_record_size, AT_INDEX_ALLOCATION, 0) {
        if ia.non_resident {
            let (runs, count) = decode_data_runs(buf, &ia);
            unsafe {
                INDX_RUNS = runs;
                INDX_RUN_COUNT = count;
            }
        }
    } else {
        unsafe {
            INDX_RUN_COUNT = 0;
        }
    }

    // Find INDEX_ROOT attribute.
    let ir = find_attr(buf, vol.mft_record_size, AT_INDEX_ROOT, 0)?;
    if ir.non_resident {
        return None; // INDEX_ROOT is always resident.
    }

    let ir_data = resident_data(buf, &ir);
    if ir_data.len() < 32 {
        return None;
    }

    // Index root header: 16 bytes of index root header, then index node header.
    // Offset 16: entries offset (from start of index node header).
    // Offset 20: total size of index entries.
    let node_offset = 16; // Start of index node header within INDEX_ROOT value.
    let entries_off_rel = read_le32(ir_data, node_offset) as usize;
    let entries_end_rel = read_le32(ir_data, node_offset + 4) as usize;

    let entries_offset = ir.record_offset + ir.value_offset as usize + node_offset + entries_off_rel;
    let entries_end = ir.record_offset + ir.value_offset as usize + node_offset + entries_end_rel;

    let mut result = None;
    let mut dummy = 0u32;
    if walk_index_entries(
        blk,
        vol,
        buf,
        entries_offset,
        entries_end,
        Some(name),
        &mut dummy,
        0,
        &mut result,
    ) {
        return result.map(|e| e.mft_ref);
    }

    None
}

/// Enumerate the next entry in a directory at the given offset.
fn dir_enumerate(
    blk: &BlkClient,
    vol: &NtfsVolume,
    dir_record: u64,
    start_offset: u32,
) -> Option<DirEntry> {
    let buf = unsafe { &mut MFT_BUF2 };
    if !read_mft_record(blk, vol, dir_record, buf) {
        return None;
    }

    // Cache INDEX_ALLOCATION data runs.
    if let Some(ia) = find_attr(buf, vol.mft_record_size, AT_INDEX_ALLOCATION, 0) {
        if ia.non_resident {
            let (runs, count) = decode_data_runs(buf, &ia);
            unsafe {
                INDX_RUNS = runs;
                INDX_RUN_COUNT = count;
            }
        }
    } else {
        unsafe {
            INDX_RUN_COUNT = 0;
        }
    }

    // Find INDEX_ROOT.
    let ir = find_attr(buf, vol.mft_record_size, AT_INDEX_ROOT, 0)?;
    if ir.non_resident {
        return None;
    }

    let ir_data = resident_data(buf, &ir);
    if ir_data.len() < 32 {
        return None;
    }

    let node_offset = 16;
    let entries_off_rel = read_le32(ir_data, node_offset) as usize;
    let entries_end_rel = read_le32(ir_data, node_offset + 4) as usize;

    let entries_offset = ir.record_offset + ir.value_offset as usize + node_offset + entries_off_rel;
    let entries_end = ir.record_offset + ir.value_offset as usize + node_offset + entries_end_rel;

    let mut result = None;
    let mut enum_offset = 0u32;
    walk_index_entries(
        blk,
        vol,
        buf,
        entries_offset,
        entries_end,
        None,
        &mut enum_offset,
        start_offset,
        &mut result,
    );

    result
}

// =====================================================================
// Path resolution
// =====================================================================

/// Resolve a path (e.g., "subdir/hello.txt") to an NtfsInode.
fn path_resolve(blk: &BlkClient, vol: &NtfsVolume, path: &[u8]) -> Option<NtfsInode> {
    let mut current_record = MFT_RECORD_ROOT;

    // Split path by '/'.
    let mut start = 0;
    // Skip leading '/'.
    while start < path.len() && path[start] == b'/' {
        start += 1;
    }

    if start >= path.len() {
        // Root directory.
        let buf = unsafe { &mut MFT_BUF };
        if !read_mft_record(blk, vol, MFT_RECORD_ROOT, buf) {
            return None;
        }
        return parse_inode(buf, vol, MFT_RECORD_ROOT);
    }

    let mut pos = start;
    while pos <= path.len() {
        let is_end = pos == path.len() || path[pos] == b'/';
        if is_end && pos > start {
            let component = &path[start..pos];

            let mft_ref = dir_lookup(blk, vol, current_record, component)?;
            current_record = mft_ref;

            // Skip consecutive slashes.
            while pos < path.len() && path[pos] == b'/' {
                pos += 1;
            }
            start = pos;

            if start >= path.len() {
                // Final component — read and return inode.
                let buf = unsafe { &mut MFT_BUF };
                if !read_mft_record(blk, vol, current_record, buf) {
                    return None;
                }
                return parse_inode(buf, vol, current_record);
            }
        } else {
            pos += 1;
        }
    }

    None
}

// =====================================================================
// File data reading
// =====================================================================

/// Read file data at `offset` for `length` bytes into `dest`.
/// Returns bytes actually read.
fn read_file_data(
    blk: &BlkClient,
    vol: &NtfsVolume,
    inode: &NtfsInode,
    mft_buf: &[u8],
    offset: u64,
    dest: usize,
    length: usize,
) -> usize {
    if offset >= inode.file_size {
        return 0;
    }
    let avail = (inode.file_size - offset) as usize;
    let to_read = length.min(avail);

    if inode.data_resident {
        // Resident data: copy directly from MFT record.
        let data_start = inode.data_value_offset + offset as usize;
        let data_end = data_start + to_read;
        if data_end <= mft_buf.len() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    mft_buf.as_ptr().add(data_start),
                    dest as *mut u8,
                    to_read,
                );
            }
            return to_read;
        }
        return 0;
    }

    // Non-resident data: walk data runs.
    let cluster_size = vol.cluster_size as u64;
    let mut total = 0usize;
    let mut cur_off = offset;

    while total < to_read {
        let vcn = cur_off / cluster_size;
        let off_in_cluster = (cur_off % cluster_size) as usize;
        let chunk = (to_read - total).min(cluster_size as usize - off_in_cluster);

        match vcn_to_lcn(&inode.data_runs, inode.data_run_count, vcn) {
            Some(lcn) => {
                if let Some(data_va) = cache_read(blk, lcn, vol.cluster_size) {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            (data_va + off_in_cluster) as *const u8,
                            (dest + total) as *mut u8,
                            chunk,
                        );
                    }
                    total += chunk;
                    cur_off += chunk as u64;
                } else {
                    break;
                }
            }
            None => {
                // Sparse — fill with zeros.
                unsafe {
                    core::ptr::write_bytes((dest + total) as *mut u8, 0, chunk);
                }
                total += chunk;
                cur_off += chunk as u64;
            }
        }
    }

    total
}

// =====================================================================
// Open file handle table
// =====================================================================

#[derive(Clone, Copy)]
struct OpenHandle {
    active: bool,
    inode: NtfsInode,
    mft_record: u64,
    pid: u32,
}

impl OpenHandle {
    const fn empty() -> Self {
        OpenHandle {
            active: false,
            inode: NtfsInode {
                mft_record: 0,
                file_size: 0,
                alloc_size: 0,
                flags: 0,
                is_dir: false,
                mode: 0,
                data_resident: false,
                data_value_offset: 0,
                data_value_length: 0,
                data_runs: [DataRun {
                    vcn: 0,
                    lcn: 0,
                    length: 0,
                }; MAX_RUNS],
                data_run_count: 0,
                name: [0u8; 64],
                name_len: 0,
                create_time: 0,
                modify_time: 0,
                access_time: 0,
            },
            mft_record: 0,
            pid: 0,
        }
    }
}

// =====================================================================
// Write support: fixup rebuild + MFT writeback
// =====================================================================

/// Rebuild the update sequence array (fixup) in an MFT record buffer
/// before writing it to disk.  The inverse of `apply_fixup`.
fn build_fixup(buf: &mut [u8], record_size: u32, sector_size: u32) {
    let usa_offset = read_le16(buf, 0x04) as usize;
    let usa_count = read_le16(buf, 0x06) as usize;
    if usa_offset + usa_count * 2 > record_size as usize || usa_count < 2 {
        return;
    }

    // Increment the update sequence number.
    let seq = read_le16(buf, usa_offset).wrapping_add(1);
    if seq == 0 {
        write_le16(buf, usa_offset, 1);
    } else {
        write_le16(buf, usa_offset, seq);
    }
    let seq = read_le16(buf, usa_offset);

    // For each sector: save original last-2-bytes into USA, replace with seq.
    for i in 1..usa_count {
        let sector_end = (i as usize) * (sector_size as usize) - 2;
        if sector_end + 1 >= buf.len() {
            break;
        }
        let original = read_le16(buf, sector_end);
        write_le16(buf, usa_offset + i * 2, original);
        write_le16(buf, sector_end, seq);
    }
}

/// Write an MFT record back to disk (rebuilds fixup first).
fn write_mft_record(blk: &BlkClient, vol: &NtfsVolume, record_num: u64, buf: &mut [u8]) -> bool {
    build_fixup(buf, vol.mft_record_size, vol.bytes_per_sector);

    let mft_byte_offset =
        vol.mft_cluster * (vol.cluster_size as u64) + record_num * (vol.mft_record_size as u64);

    // Write sector by sector.
    let sectors = vol.mft_record_size / vol.bytes_per_sector;
    for s in 0..sectors {
        let off = (s as usize) * (vol.bytes_per_sector as usize);
        let abs = mft_byte_offset + (s as u64) * (vol.bytes_per_sector as u64);
        let wva = unsafe { WRITE_VA };
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr().add(off),
                wva as *mut u8,
                vol.bytes_per_sector as usize,
            );
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                wva as *const u8,
                blk.scratch_va as *mut u8,
                vol.bytes_per_sector as usize,
            );
        }
        let abs_off = blk.partition_offset + abs;
        let sector = abs_off / 512;
        let nonce = blk.next_nonce();
        let d2 = 512u64 | ((blk.reply_port as u64) << 32);
        syscall::send(blk.blk_port, IO_WRITE, nonce, sector * 512, d2, blk.grant_va as u64);
        let ok = if let Some(rr) = blk.recv_match(nonce) {
            rr.tag == IO_WRITE_OK
        } else {
            false
        };
        if !ok {
            return false;
        }
    }

    // Invalidate cached clusters that overlap this MFT record.
    let start_cluster = mft_byte_offset / (vol.cluster_size as u64);
    let end_cluster = (mft_byte_offset + vol.mft_record_size as u64 - 1) / (vol.cluster_size as u64);
    for c in start_cluster..=end_cluster {
        cache_invalidate(c);
    }

    true
}

// =====================================================================
// Cluster bitmap ($Bitmap, MFT record 6) — allocate/free clusters
// =====================================================================

/// Bitmap buffer: we read the first 4096 bytes of $Bitmap (covers 32768 clusters).
/// For a 32 MiB partition with 4K clusters, that's 8192 clusters — well within range.
static mut CLUSTER_BITMAP: [u8; 4096] = [0u8; 4096];
static mut CLUSTER_BITMAP_LOADED: bool = false;
/// Data runs for $Bitmap (non-resident).
static mut BITMAP_RUNS: [DataRun; MAX_RUNS] = [DataRun { vcn: 0, lcn: 0, length: 0 }; MAX_RUNS];
static mut BITMAP_RUN_COUNT: usize = 0;

/// Load the cluster bitmap from $Bitmap (MFT record 6).
fn load_cluster_bitmap(blk: &BlkClient, vol: &NtfsVolume) -> bool {
    if unsafe { CLUSTER_BITMAP_LOADED } {
        return true;
    }

    let buf = unsafe { &mut MFT_BUF2 };
    if !read_mft_record(blk, vol, MFT_RECORD_BITMAP, buf) {
        return false;
    }

    if let Some(data_attr) = find_attr(buf, vol.mft_record_size, AT_DATA, 0) {
        if data_attr.non_resident {
            let (runs, count) = decode_data_runs(buf, &data_attr);
            unsafe {
                BITMAP_RUNS = runs;
                BITMAP_RUN_COUNT = count;
            }
            // Read first cluster of bitmap.
            if let Some(lcn) = vcn_to_lcn(&runs, count, 0) {
                if let Some(va) = cache_read(blk, lcn, vol.cluster_size) {
                    let copy_len = (vol.cluster_size as usize).min(4096);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            va as *const u8,
                            CLUSTER_BITMAP.as_mut_ptr(),
                            copy_len,
                        );
                        CLUSTER_BITMAP_LOADED = true;
                    }
                    return true;
                }
            }
        } else {
            // Resident bitmap (tiny volume).
            let data = resident_data(buf, &data_attr);
            let copy_len = data.len().min(4096);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    CLUSTER_BITMAP.as_mut_ptr(),
                    copy_len,
                );
                CLUSTER_BITMAP_LOADED = true;
            }
            return true;
        }
    }
    false
}

/// Flush the cluster bitmap back to disk.
fn flush_cluster_bitmap(blk: &BlkClient, vol: &NtfsVolume) -> bool {
    let runs = unsafe { &BITMAP_RUNS };
    let count = unsafe { BITMAP_RUN_COUNT };
    if count == 0 {
        return false;
    }
    if let Some(lcn) = vcn_to_lcn(runs, count, 0) {
        // Write bitmap cluster.
        let wva = unsafe { WRITE_VA };
        let copy_len = (vol.cluster_size as usize).min(4096);
        unsafe {
            core::ptr::copy_nonoverlapping(
                CLUSTER_BITMAP.as_ptr(),
                wva as *mut u8,
                copy_len,
            );
        }
        cache_invalidate(lcn);
        blk.write_cluster(lcn, vol.cluster_size, wva)
    } else {
        false
    }
}

/// Allocate `count` contiguous clusters.  Returns the first LCN, or None.
fn alloc_clusters(blk: &BlkClient, vol: &NtfsVolume, count: u32) -> Option<u64> {
    if !load_cluster_bitmap(blk, vol) {
        return None;
    }
    let max_cluster = vol.total_clusters.min(4096 * 8) as u32;
    let bitmap = unsafe { &mut CLUSTER_BITMAP };

    // Simple first-fit search.
    let mut run_start = 0u32;
    let mut run_len = 0u32;
    for bit in 0..max_cluster {
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if bitmap[byte as usize] & mask == 0 {
            if run_len == 0 {
                run_start = bit;
            }
            run_len += 1;
            if run_len >= count {
                // Found — mark as used.
                for b in run_start..run_start + count {
                    let by = b / 8;
                    let m = 1u8 << (b % 8);
                    bitmap[by as usize] |= m;
                }
                flush_cluster_bitmap(blk, vol);
                return Some(run_start as u64);
            }
        } else {
            run_len = 0;
        }
    }
    None
}

/// Free `count` clusters starting at `lcn`.
fn free_clusters(blk: &BlkClient, vol: &NtfsVolume, lcn: u64, count: u32) {
    if !load_cluster_bitmap(blk, vol) {
        return;
    }
    let bitmap = unsafe { &mut CLUSTER_BITMAP };
    for i in 0..count {
        let bit = (lcn as u32) + i;
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if (byte as usize) < 4096 {
            bitmap[byte as usize] &= !mask;
        }
    }
    flush_cluster_bitmap(blk, vol);
}

// =====================================================================
// MFT record allocation
// =====================================================================

/// MFT bitmap (tracks which MFT records are in use).
/// Stored as the $BITMAP attribute of $MFT itself (record 0).
static mut MFT_BITMAP: [u8; 512] = [0u8; 512]; // Covers 4096 records.
static mut MFT_BITMAP_LOADED: bool = false;

fn load_mft_bitmap(blk: &BlkClient, vol: &NtfsVolume) -> bool {
    if unsafe { MFT_BITMAP_LOADED } {
        return true;
    }
    let buf = unsafe { &mut MFT_BUF2 };
    if !read_mft_record(blk, vol, MFT_RECORD_MFT, buf) {
        return false;
    }
    // Find $BITMAP attribute in $MFT (not AT_DATA, but AT_BITMAP).
    if let Some(bm) = find_attr(buf, vol.mft_record_size, AT_BITMAP, 0) {
        if !bm.non_resident {
            let data = resident_data(buf, &bm);
            let copy_len = data.len().min(512);
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), MFT_BITMAP.as_mut_ptr(), copy_len);
                MFT_BITMAP_LOADED = true;
            }
            return true;
        }
        // Non-resident bitmap — read first cluster.
        let (runs, count) = decode_data_runs(buf, &bm);
        if let Some(lcn) = vcn_to_lcn(&runs, count, 0) {
            if let Some(va) = cache_read(blk, lcn, vol.cluster_size) {
                let copy_len = 512usize.min(vol.cluster_size as usize);
                unsafe {
                    core::ptr::copy_nonoverlapping(va as *const u8, MFT_BITMAP.as_mut_ptr(), copy_len);
                    MFT_BITMAP_LOADED = true;
                }
                return true;
            }
        }
    }
    false
}

/// Allocate a new MFT record.  Returns the record number.
fn alloc_mft_record(blk: &BlkClient, vol: &NtfsVolume) -> Option<u64> {
    if !load_mft_bitmap(blk, vol) {
        return None;
    }
    let bitmap = unsafe { &mut MFT_BITMAP };
    // Start searching from record 24 (skip system metadata files).
    for rec in 24u32..4096 {
        let byte = rec / 8;
        let mask = 1u8 << (rec % 8);
        if bitmap[byte as usize] & mask == 0 {
            bitmap[byte as usize] |= mask;
            // TODO: flush MFT bitmap back to disk.  For now the in-memory
            // bitmap is authoritative until we restart.
            return Some(rec as u64);
        }
    }
    None
}

/// Free an MFT record.
fn free_mft_record(record_num: u64) {
    if record_num < 24 || record_num >= 4096 {
        return;
    }
    let bitmap = unsafe { &mut MFT_BITMAP };
    let byte = (record_num / 8) as usize;
    let mask = 1u8 << (record_num % 8);
    bitmap[byte] &= !mask;
}

// =====================================================================
// Data run encoding (for building non-resident attributes)
// =====================================================================

/// Encode a single data run into `buf` at `off`.  Returns bytes written.
fn encode_one_run(buf: &mut [u8], off: usize, length: u64, offset: i64) -> usize {
    // Determine bytes needed for length (unsigned).
    let len_bytes = if length <= 0xFF { 1 }
        else if length <= 0xFFFF { 2 }
        else if length <= 0xFF_FFFF { 3 }
        else { 4 };

    // Determine bytes needed for offset (signed).
    let off_bytes = if offset == 0 { 0 }
        else if offset >= -128 && offset <= 127 { 1 }
        else if offset >= -32768 && offset <= 32767 { 2 }
        else if offset >= -8388608 && offset <= 8388607 { 3 }
        else { 4 };

    if off + 1 + len_bytes + off_bytes > buf.len() {
        return 0;
    }

    buf[off] = (len_bytes as u8) | ((off_bytes as u8) << 4);
    let mut pos = off + 1;

    // Write length (little-endian).
    let l = length;
    for i in 0..len_bytes {
        buf[pos + i] = ((l >> (i * 8)) & 0xFF) as u8;
    }
    pos += len_bytes;

    // Write offset (little-endian, signed).
    let o = offset;
    for i in 0..off_bytes {
        buf[pos + i] = ((o >> (i * 8)) & 0xFF) as u8;
    }
    pos += off_bytes;

    pos - off
}

/// Encode a data run list from an array of (lcn, length) pairs.
/// Returns bytes written (including terminating zero).
fn encode_data_runs(buf: &mut [u8], off: usize, runs: &[(u64, u64)], count: usize) -> usize {
    let mut pos = off;
    let mut prev_lcn = 0i64;

    for i in 0..count {
        let lcn = runs[i].0 as i64;
        let length = runs[i].1;
        let offset = lcn - prev_lcn;
        let written = encode_one_run(buf, pos, length, offset);
        if written == 0 {
            break;
        }
        pos += written;
        prev_lcn = lcn;
    }

    // Terminator.
    if pos < buf.len() {
        buf[pos] = 0;
        pos += 1;
    }

    pos - off
}

// =====================================================================
// MFT record construction (for new files/directories)
// =====================================================================

/// Initialize a new MFT record as an empty file.
/// Returns true on success.
fn init_mft_record_file(
    blk: &BlkClient,
    vol: &NtfsVolume,
    record_num: u64,
    filename: &[u8],
    parent_record: u64,
    is_dir: bool,
) -> bool {
    let buf = unsafe { &mut MFT_BUF };
    let rs = vol.mft_record_size as usize;

    // Zero the buffer.
    for b in buf[..rs].iter_mut() {
        *b = 0;
    }

    // FILE signature.
    write_le32(buf, 0, FILE_SIGNATURE);
    // Update sequence offset (at byte 48, typical for 1024-byte records).
    let usa_offset = 48u16;
    let usa_count = (vol.mft_record_size / vol.bytes_per_sector + 1) as u16;
    write_le16(buf, 4, usa_offset);
    write_le16(buf, 6, usa_count);
    // Log file sequence number = 0.
    write_le64(buf, 8, 0);
    // Sequence number.
    write_le16(buf, 16, 1);
    // Hard link count.
    write_le16(buf, 18, 1);
    // Offset to first attribute (after USA).
    let first_attr = (usa_offset + usa_count * 2 + 7) & !7; // Align to 8.
    write_le16(buf, 20, first_attr);
    // Flags: in-use (+ directory if applicable).
    let flags = MFT_RECORD_IN_USE | if is_dir { MFT_RECORD_IS_DIRECTORY } else { 0 };
    write_le16(buf, 22, flags);
    // Used size of record (filled after attributes).
    // Allocated size.
    write_le32(buf, 28, vol.mft_record_size);
    // Base record reference = 0 (this is the base record).
    // Next attribute ID.
    write_le16(buf, 40, 3); // Will use IDs 0, 1, 2.

    // Initialize USA area with sequence number 1.
    write_le16(buf, usa_offset as usize, 1);
    for i in 1..usa_count {
        write_le16(buf, usa_offset as usize + (i as usize) * 2, 0);
    }

    let mut attr_off = first_attr as usize;

    // --- Attribute 1: STANDARD_INFORMATION (0x10) ---
    {
        let si_len = 48u32; // Minimal standard info.
        let attr_len = 24 + si_len; // Resident header (24) + value.
        let aligned_len = (attr_len + 7) & !7;
        write_le32(buf, attr_off, AT_STANDARD_INFORMATION);
        write_le32(buf, attr_off + 4, aligned_len);
        buf[attr_off + 8] = 0; // Resident.
        buf[attr_off + 9] = 0; // Name length.
        write_le16(buf, attr_off + 10, 0); // Name offset.
        write_le16(buf, attr_off + 12, 0); // Flags.
        write_le16(buf, attr_off + 14, 0); // Attribute ID.
        write_le32(buf, attr_off + 16, si_len); // Value length.
        write_le16(buf, attr_off + 20, 24); // Value offset.
        // SI value: timestamps (all zero = epoch) and flags.
        let si_off = attr_off + 24;
        // create_time, modify_time, mft_modify_time, access_time at offsets 0, 8, 16, 24.
        // file_attributes at offset 32.
        let file_attrs = if is_dir { FILE_ATTR_DIRECTORY } else { 0 };
        write_le32(buf, si_off + 32, file_attrs);
        attr_off += aligned_len as usize;
    }

    // --- Attribute 2: FILE_NAME (0x30) ---
    {
        let name_chars = filename.len().min(32);
        // FILE_NAME value: 66 bytes header + name_chars * 2 (UTF-16LE).
        let fn_value_len = 66 + name_chars * 2;
        let attr_len = 24 + fn_value_len as u32;
        let aligned_len = (attr_len + 7) & !7;
        write_le32(buf, attr_off, AT_FILE_NAME);
        write_le32(buf, attr_off + 4, aligned_len);
        buf[attr_off + 8] = 0; // Resident.
        write_le16(buf, attr_off + 12, 0); // Flags.
        write_le16(buf, attr_off + 14, 1); // Attribute ID.
        write_le32(buf, attr_off + 16, fn_value_len as u32);
        write_le16(buf, attr_off + 20, 24);

        let fn_off = attr_off + 24;
        // Parent directory MFT reference.
        write_le64(buf, fn_off, parent_record & 0x0000_FFFF_FFFF_FFFF);
        // Timestamps (0 = epoch).
        // Allocated size, data size (0 for new file).
        // Flags.
        let file_attrs = if is_dir { FILE_ATTR_DIRECTORY } else { 0 };
        write_le32(buf, fn_off + 56, file_attrs);
        // Name length and namespace.
        buf[fn_off + 64] = name_chars as u8;
        buf[fn_off + 65] = FILE_NAME_WIN32_AND_DOS;
        // Name (UTF-16LE).
        for i in 0..name_chars {
            write_le16(buf, fn_off + 66 + i * 2, filename[i] as u16);
        }

        attr_off += aligned_len as usize;
    }

    if is_dir {
        // --- Attribute 3: INDEX_ROOT (0x90) for $I30 ---
        {
            // Index root for an empty directory.
            // Attribute header: name "$I30" (4 UTF-16LE chars).
            let index_name_len = 4u8; // "$I30"
            let index_name = [b'$' as u16, b'I' as u16, b'3' as u16, b'0' as u16];

            // INDEX_ROOT value:
            //   Bytes 0-3: attribute type of indexed (0x30 = FILE_NAME)
            //   Bytes 4-7: collation rule (1 = FILENAME)
            //   Bytes 8-11: index allocation entry size (usually 4096)
            //   Bytes 12-12: clusters per index record
            //   Bytes 13-15: padding
            //   Bytes 16+: index node header
            //     Bytes 0-3: entries offset (from start of node header)
            //     Bytes 4-7: total size of entries
            //     Bytes 8-11: allocated size of entries
            //     Bytes 12-15: flags (0 = leaf, 1 = has sub-nodes)
            //   Then: one end-marker entry (16 bytes with INDEX_ENTRY_END flag)
            let node_hdr_off = 16; // Within the value.
            let end_entry_off = node_hdr_off + 16; // After node header.
            let end_entry_len = 16u32; // Minimal end entry.
            let ir_value_len = end_entry_off + end_entry_len as usize;

            let name_off = 24u16; // Resident header + name offset.
            let name_bytes = (index_name_len as u16) * 2;
            let value_off = ((name_off + name_bytes + 7) & !7) as u16;
            let attr_len = value_off as u32 + ir_value_len as u32;
            let aligned_len = (attr_len + 7) & !7;

            write_le32(buf, attr_off, AT_INDEX_ROOT);
            write_le32(buf, attr_off + 4, aligned_len);
            buf[attr_off + 8] = 0; // Resident.
            buf[attr_off + 9] = index_name_len;
            write_le16(buf, attr_off + 10, name_off);
            write_le16(buf, attr_off + 14, 2); // Attribute ID.
            write_le32(buf, attr_off + 16, ir_value_len as u32);
            write_le16(buf, attr_off + 20, value_off);

            // Write attribute name "$I30" in UTF-16LE.
            let name_start = attr_off + name_off as usize;
            for (i, &ch) in index_name.iter().enumerate() {
                write_le16(buf, name_start + i * 2, ch);
            }

            // Index root value.
            let val_off = attr_off + value_off as usize;
            write_le32(buf, val_off, AT_FILE_NAME); // Indexed attribute type.
            write_le32(buf, val_off + 4, 1);        // Collation rule (FILENAME).
            write_le32(buf, val_off + 8, vol.index_record_size); // Index record size.
            buf[val_off + 12] = if vol.index_record_size <= vol.cluster_size {
                1 // clusters per index record
            } else {
                (vol.index_record_size / vol.cluster_size) as u8
            };

            // Index node header.
            let nh = val_off + node_hdr_off;
            write_le32(buf, nh, 16);                                     // Entries offset.
            write_le32(buf, nh + 4, 16 + end_entry_len);                // Total size.
            write_le32(buf, nh + 8, 16 + end_entry_len);                // Allocated size.
            write_le32(buf, nh + 12, 0);                                 // Flags (leaf).

            // End-marker entry.
            let ee = nh + 16;
            write_le16(buf, ee + 8, end_entry_len as u16); // Entry length.
            write_le16(buf, ee + 10, 0);                    // Key length.
            write_le32(buf, ee + 12, INDEX_ENTRY_END);      // Flags.

            attr_off += aligned_len as usize;
        }
    } else {
        // --- Attribute 3: DATA (0x80) — empty, resident ---
        {
            let attr_len = 24u32; // Resident, no data.
            let aligned_len = (attr_len + 7) & !7;
            write_le32(buf, attr_off, AT_DATA);
            write_le32(buf, attr_off + 4, aligned_len);
            buf[attr_off + 8] = 0; // Resident.
            write_le16(buf, attr_off + 14, 2); // Attribute ID.
            write_le32(buf, attr_off + 16, 0); // Value length = 0.
            write_le16(buf, attr_off + 20, 24);
            attr_off += aligned_len as usize;
        }
    }

    // End marker.
    write_le32(buf, attr_off, AT_END);
    attr_off += 4;

    // Used size.
    write_le32(buf, 24, attr_off as u32);

    // Write record to disk.
    write_mft_record(blk, vol, record_num, buf)
}

// =====================================================================
// Directory index manipulation (add/remove entries in INDEX_ROOT)
// =====================================================================

/// Add an entry to a directory's INDEX_ROOT.
/// Works for small directories where entries fit in the resident INDEX_ROOT.
fn dir_add_entry(
    blk: &BlkClient,
    vol: &NtfsVolume,
    dir_record: u64,
    filename: &[u8],
    child_mft_ref: u64,
    child_flags: u32,
) -> bool {
    let buf = unsafe { &mut MFT_BUF };
    if !read_mft_record(blk, vol, dir_record, buf) {
        return false;
    }

    // Find INDEX_ROOT.
    let ir = match find_attr(buf, vol.mft_record_size, AT_INDEX_ROOT, 0) {
        Some(a) => a,
        None => return false,
    };
    if ir.non_resident {
        return false;
    }

    let val_start = ir.record_offset + ir.value_offset as usize;
    let node_hdr = val_start + 16; // Index node header within IR value.
    let entries_off_rel = read_le32(buf, node_hdr) as usize;
    let total_size = read_le32(buf, node_hdr + 4) as usize;

    let entries_start = node_hdr + entries_off_rel;
    let entries_end = node_hdr + total_size;

    // Build the new index entry.
    let name_chars = filename.len().min(32);
    let key_len = 66 + name_chars * 2; // FILE_NAME attribute value size.
    let entry_len = ((16 + key_len + 7) & !7) as usize; // Aligned.

    // Check if there's room in the MFT record.
    let used = read_le32(buf, 24) as usize;
    if used + entry_len > vol.mft_record_size as usize - 8 {
        return false; // Would overflow — need INDEX_ALLOCATION (not yet implemented).
    }

    // Find insertion point: right before the end marker.
    let mut pos = entries_start;
    let mut insert_pos = entries_start;
    while pos < entries_end {
        let e_len = read_le16(buf, pos + 8) as usize;
        let e_flags = read_le32(buf, pos + 12);
        if e_flags & INDEX_ENTRY_END != 0 {
            insert_pos = pos;
            break;
        }
        if e_len < 16 {
            break;
        }
        pos += e_len;
    }

    // Shift everything after insert_pos to make room.
    let shift_from = insert_pos;
    let shift_len = entries_end - shift_from;
    if shift_len > 0 {
        // Move backward from end to avoid overlap.
        let src = shift_from;
        let dst = shift_from + entry_len;
        for i in (0..shift_len).rev() {
            buf[dst + i] = buf[src + i];
        }
    }

    // Write the new entry at insert_pos.
    let ep = insert_pos;
    // Zero the entry area.
    for b in buf[ep..ep + entry_len].iter_mut() {
        *b = 0;
    }
    // MFT file reference (6 bytes + 2-byte sequence).
    write_le64(buf, ep, child_mft_ref & 0x0000_FFFF_FFFF_FFFF);
    // Entry length.
    write_le16(buf, ep + 8, entry_len as u16);
    // Key length.
    write_le16(buf, ep + 10, key_len as u16);
    // Flags = 0 (leaf, not end).
    write_le32(buf, ep + 12, 0);

    // FILE_NAME key value.
    let key = ep + 16;
    // Parent directory reference.
    write_le64(buf, key, dir_record & 0x0000_FFFF_FFFF_FFFF);
    // File attributes.
    write_le32(buf, key + 56, child_flags);
    // Name length and namespace.
    buf[key + 64] = name_chars as u8;
    buf[key + 65] = FILE_NAME_WIN32_AND_DOS;
    // Name (UTF-16LE).
    for i in 0..name_chars {
        write_le16(buf, key + 66 + i * 2, filename[i] as u16);
    }

    // Update index node header: total size and allocated size.
    let new_total = total_size + entry_len;
    write_le32(buf, node_hdr + 4, new_total as u32);
    write_le32(buf, node_hdr + 8, new_total as u32);

    // Update INDEX_ROOT attribute value length.
    let new_ir_value_len = ir.value_length as usize + entry_len;
    write_le32(buf, ir.record_offset + 16, new_ir_value_len as u32);

    // Update INDEX_ROOT attribute total length.
    let new_attr_len = ir.length as usize + entry_len;
    let aligned_new_attr_len = (new_attr_len + 7) & !7;
    write_le32(buf, ir.record_offset + 4, aligned_new_attr_len as u32);

    // Update MFT record used size.
    let new_used = used + entry_len;
    write_le32(buf, 24, new_used as u32);

    write_mft_record(blk, vol, dir_record, buf)
}

/// Remove an entry from a directory's INDEX_ROOT by filename.
fn dir_remove_entry(
    blk: &BlkClient,
    vol: &NtfsVolume,
    dir_record: u64,
    filename: &[u8],
) -> bool {
    let buf = unsafe { &mut MFT_BUF };
    if !read_mft_record(blk, vol, dir_record, buf) {
        return false;
    }

    let ir = match find_attr(buf, vol.mft_record_size, AT_INDEX_ROOT, 0) {
        Some(a) => a,
        None => return false,
    };
    if ir.non_resident {
        return false;
    }

    let val_start = ir.record_offset + ir.value_offset as usize;
    let node_hdr = val_start + 16;
    let entries_off_rel = read_le32(buf, node_hdr) as usize;
    let total_size = read_le32(buf, node_hdr + 4) as usize;
    let entries_start = node_hdr + entries_off_rel;
    let entries_end = node_hdr + total_size;

    // Find the entry matching filename.
    let mut pos = entries_start;
    while pos < entries_end {
        let e_len = read_le16(buf, pos + 8) as usize;
        let e_key_len = read_le16(buf, pos + 10) as usize;
        let e_flags = read_le32(buf, pos + 12);

        if e_flags & INDEX_ENTRY_END != 0 {
            return false; // Not found.
        }
        if e_len < 16 {
            return false;
        }

        if e_key_len >= 66 && pos + 16 + e_key_len <= entries_end {
            let key = &buf[pos + 16..pos + 16 + e_key_len];
            let name_chars = key[64] as usize;
            let namespace = key[65];

            if namespace != FILE_NAME_DOS {
                let mut name = [0u8; 64];
                let mut nlen = 0;
                for c in 0..name_chars.min(32) {
                    let ch = read_le16(key, 66 + c * 2);
                    if nlen < 64 {
                        name[nlen] = if ch < 128 { ch as u8 } else { b'?' };
                        nlen += 1;
                    }
                }

                if name_eq_ci(&name[..nlen], filename) {
                    // Found — remove by shifting subsequent entries back.
                    let remove_end = pos + e_len;
                    let shift_len = entries_end - remove_end;
                    for i in 0..shift_len {
                        buf[pos + i] = buf[remove_end + i];
                    }
                    // Zero the freed area.
                    for i in 0..e_len {
                        buf[entries_end - e_len + i] = 0;
                    }

                    // Update sizes.
                    let new_total = total_size - e_len;
                    write_le32(buf, node_hdr + 4, new_total as u32);
                    write_le32(buf, node_hdr + 8, new_total as u32);
                    let new_ir_value_len = ir.value_length as usize - e_len;
                    write_le32(buf, ir.record_offset + 16, new_ir_value_len as u32);
                    let new_attr_len = ir.length as usize - e_len;
                    let aligned = (new_attr_len + 7) & !7;
                    write_le32(buf, ir.record_offset + 4, aligned as u32);
                    let used = read_le32(buf, 24) as usize;
                    write_le32(buf, 24, (used - e_len) as u32);

                    return write_mft_record(blk, vol, dir_record, buf);
                }
            }
        }

        pos += e_len;
    }

    false
}

// =====================================================================
// File data write support
// =====================================================================

/// Convert a resident DATA attribute to non-resident, allocating clusters.
/// Returns (new data runs, run count, first lcn) or None.
fn make_data_nonresident(
    blk: &BlkClient,
    vol: &NtfsVolume,
    record_num: u64,
    old_data: &[u8],
) -> Option<(u64, u64)> {
    // Allocate one cluster.
    let lcn = alloc_clusters(blk, vol, 1)?;
    let cluster_size = vol.cluster_size;

    // Write old data + zero-fill to the cluster.
    let wva = unsafe { WRITE_VA };
    unsafe {
        core::ptr::write_bytes(wva as *mut u8, 0, cluster_size as usize);
        if !old_data.is_empty() {
            core::ptr::copy_nonoverlapping(
                old_data.as_ptr(),
                wva as *mut u8,
                old_data.len().min(cluster_size as usize),
            );
        }
    }
    cache_invalidate(lcn);
    if !blk.write_cluster(lcn, cluster_size, wva) {
        free_clusters(blk, vol, lcn, 1);
        return None;
    }

    // Now rewrite the DATA attribute in the MFT record as non-resident.
    let buf = unsafe { &mut MFT_BUF };
    if !read_mft_record(blk, vol, record_num, buf) {
        free_clusters(blk, vol, lcn, 1);
        return None;
    }

    if let Some(data_attr) = find_attr(buf, vol.mft_record_size, AT_DATA, 0) {
        let attr_off = data_attr.record_offset;
        let old_attr_len = data_attr.length as usize;

        // Build a non-resident DATA attribute.
        let data_size = old_data.len() as u64;
        let alloc_size = cluster_size as u64;

        // Non-resident header is 64 bytes + data runs.
        let mut run_buf = [0u8; 16];
        let runs = [(lcn, 1u64)];
        let run_bytes = encode_data_runs(&mut run_buf, 0, &runs, 1);
        let new_attr_len = ((64 + run_bytes + 7) & !7) as usize;

        // Shift subsequent attributes if size changed.
        let size_diff = new_attr_len as isize - old_attr_len as isize;
        let used = read_le32(buf, 24) as usize;
        let after_old = attr_off + old_attr_len;
        let after_new = (attr_off as isize + new_attr_len as isize) as usize;
        let tail_len = used - after_old;

        if size_diff > 0 {
            // Growing: shift tail forward.
            for i in (0..tail_len).rev() {
                buf[after_new + i] = buf[after_old + i];
            }
        } else if size_diff < 0 {
            // Shrinking: shift tail backward.
            for i in 0..tail_len {
                buf[after_new + i] = buf[after_old + i];
            }
        }

        // Zero the attribute area.
        for b in buf[attr_off..attr_off + new_attr_len].iter_mut() {
            *b = 0;
        }

        // Write non-resident header.
        write_le32(buf, attr_off, AT_DATA);
        write_le32(buf, attr_off + 4, new_attr_len as u32);
        buf[attr_off + 8] = 1; // Non-resident.
        buf[attr_off + 9] = 0; // Name length.
        write_le16(buf, attr_off + 10, 0); // Name offset.
        write_le16(buf, attr_off + 14, 2); // Attribute ID.
        write_le64(buf, attr_off + 16, 0); // Lowest VCN.
        write_le64(buf, attr_off + 24, 0); // Highest VCN (0 = one cluster).
        write_le16(buf, attr_off + 32, 64); // Data run offset.
        write_le64(buf, attr_off + 40, alloc_size);
        write_le64(buf, attr_off + 48, data_size);
        write_le64(buf, attr_off + 56, data_size); // Init size.

        // Copy data runs.
        for i in 0..run_bytes {
            buf[attr_off + 64 + i] = run_buf[i];
        }

        // Update used size.
        let new_used = (used as isize + size_diff) as usize;
        write_le32(buf, 24, new_used as u32);

        if write_mft_record(blk, vol, record_num, buf) {
            return Some((lcn, alloc_size));
        }
    }

    free_clusters(blk, vol, lcn, 1);
    None
}

/// Free all data clusters owned by an inode.
fn free_inode_clusters(blk: &BlkClient, vol: &NtfsVolume, inode: &NtfsInode) {
    if inode.data_resident || inode.data_run_count == 0 {
        return;
    }
    for i in 0..inode.data_run_count {
        let run = &inode.data_runs[i];
        if run.lcn >= 0 && run.length > 0 {
            free_clusters(blk, vol, run.lcn as u64, run.length as u32);
        }
    }
}

// =====================================================================
// Main server
// =====================================================================

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [ntfs_srv] starting\n");

    // Partition byte offset from arg0 (default 369 MiB — after APFS).
    let partition_offset = if arg0 != 0 {
        arg0
    } else {
        369 * 1024 * 1024
    };

    syscall::debug_puts(b"  [ntfs_srv] partition offset=");
    print_num(partition_offset);
    syscall::debug_puts(b"\n");

    // Create port and register with name server.
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"ntfs", port);
    syscall::ns_register(b"ntfs_task", my_aspace);

    // Look up cache_blk with bounded retry.
    let blk_port = {
        let mut retries = 200u32;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [ntfs_srv] cache_blk not found, exiting\n");
                syscall::exit(1);
            }
            syscall::nanosleep(10_000_000);
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
            syscall::debug_puts(b"  [ntfs_srv] blk connect FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    } else {
        syscall::debug_puts(b"  [ntfs_srv] blk no reply\n");
        syscall::exit(1);
        unreachable!()
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ntfs_srv] scratch alloc FAILED\n");
            syscall::exit(1);
            unreachable!()
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_4000, // Unique per FS server.
        partition_offset,
        nonce: Cell::new(0),
    };

    // Permanent grant of `scratch_va` into cache_blk's aspace at grant_va.
    // The nonce protocol (see BlkClient::recv_match) makes stale-reply
    // corruption impossible, so per-request grant/revoke is no longer needed.
    if !syscall::grant_pages(blk.blk_aspace, blk.scratch_va, blk.grant_va, 1, false) {
        syscall::debug_puts(b"  [ntfs_srv] permanent grant FAILED\n");
        loop { syscall::nanosleep(1_000_000_000_000); }
    }

    // Initialize block cache.
    cache_init();

    // Allocate write scratch page.
    match syscall::mmap_anon(0, 1, 1) {
        Some(va) => unsafe {
            WRITE_VA = va;
        },
        None => {
            syscall::debug_puts(b"  [ntfs_srv] write scratch alloc FAILED\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
    }

    // Read boot sector (sector 0 of partition).
    let mut boot = [0u8; 512];
    let mut read_ok = false;
    for _ in 0..20 {
        if blk.read_bytes(0, &mut boot) {
            if boot[3] == b'N' && boot[4] == b'T' && boot[5] == b'F' && boot[6] == b'S' {
                read_ok = true;
                break;
            }
        }
        for _ in 0..100 {
            syscall::yield_now();
        }
    }
    if !read_ok {
        syscall::debug_puts(b"  [ntfs_srv] failed to read boot sector (no NTFS found)\n");
        loop {
            syscall::nanosleep(1_000_000_000_000);
        }
    }

    let vol = match parse_boot_sector(&boot) {
        Some(v) => v,
        None => {
            syscall::debug_puts(b"  [ntfs_srv] invalid NTFS boot sector\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
    };

    syscall::debug_puts(b"  [ntfs_srv] NTFS: cluster_size=");
    print_num(vol.cluster_size as u64);
    syscall::debug_puts(b" mft_cluster=");
    print_num(vol.mft_cluster);
    syscall::debug_puts(b" record_size=");
    print_num(vol.mft_record_size as u64);
    syscall::debug_puts(b" total_clusters=");
    print_num(vol.total_clusters);
    syscall::debug_puts(b"\n");

    // Verify MFT by reading record 0 ($MFT).
    {
        let buf = unsafe { &mut MFT_BUF };
        let mut mft_ok = false;
        for attempt in 0..5u32 {
            if read_mft_record(&blk, &vol, MFT_RECORD_MFT, buf) {
                syscall::debug_puts(b"  [ntfs_srv] $MFT record 0 OK\n");
                mft_ok = true;
                break;
            }
            if attempt < 4 {
                syscall::nanosleep(50_000_000);
            }
        }
        if !mft_ok {
            syscall::debug_puts(b"  [ntfs_srv] failed to read $MFT\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
    }

    // Verify root directory (record 5).
    {
        let buf = unsafe { &mut MFT_BUF };
        if read_mft_record(&blk, &vol, MFT_RECORD_ROOT, buf) {
            if let Some(root) = parse_inode(buf, &vol, MFT_RECORD_ROOT) {
                syscall::debug_puts(b"  [ntfs_srv] root dir: is_dir=");
                print_num(root.is_dir as u64);
                syscall::debug_puts(b" flags=");
                print_hex(root.flags as u64);
                syscall::debug_puts(b"\n");
            }
        } else {
            syscall::debug_puts(b"  [ntfs_srv] failed to read root dir\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
    }

    syscall::debug_puts(b"  [ntfs_srv] ready\n");

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

                if let Some(inode) = path_resolve(&blk, &vol, name) {
                    let mut handle = u64::MAX;
                    for (i, h) in handles.iter_mut().enumerate() {
                        if !h.active {
                            h.active = true;
                            h.inode = inode;
                            h.mft_record = inode.mft_record;
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
                            inode.file_size,
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

                if let Some(inode) = path_resolve(&blk, &vol, &name[..nlen]) {
                    let mut handle = u64::MAX;
                    for (i, h) in handles.iter_mut().enumerate() {
                        if !h.active {
                            h.active = true;
                            h.inode = inode;
                            h.mft_record = inode.mft_record;
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
                            inode.file_size,
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
                if offset >= inode.file_size {
                    let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                    continue;
                }

                if grant_va != 0 {
                    // For grant-based reads, we need the MFT record re-read
                    // if data is resident (the record buffer may have been reused).
                    let mft_buf = unsafe { &mut MFT_BUF };
                    if inode.data_resident {
                        if !read_mft_record(&blk, &vol, inode.mft_record, mft_buf) {
                            let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                            continue;
                        }
                    }
                    let bytes = read_file_data(
                        &blk,
                        &vol,
                        inode,
                        mft_buf,
                        offset,
                        grant_va,
                        length as usize,
                    );
                    let _ = syscall::reply(FS_READ_OK, bytes as u64, 0, 0, 0, 0);
                } else {
                    // Inline mode.
                    let avail = inode.file_size - offset;
                    let to_read = (length as u64).min(avail) as usize;
                    let inline_len = to_read.min(MAX_INLINE);

                    if inode.data_resident {
                        let mft_buf = unsafe { &mut MFT_BUF };
                        if !read_mft_record(&blk, &vol, inode.mft_record, mft_buf) {
                            let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                            continue;
                        }
                        let data_start = inode.data_value_offset + offset as usize;
                        let data_end = (data_start + inline_len).min(mft_buf.len());
                        let data = &mft_buf[data_start..data_end];
                        let packed = pack_inline_data(data);
                        let _ = syscall::reply(
                            FS_READ_OK,
                            data.len() as u64,
                            packed[0],
                            packed[1],
                            packed[2],
                            0,
                        );
                    } else {
                        // Non-resident inline: read first cluster.
                        let cluster_size = vol.cluster_size as u64;
                        let vcn = offset / cluster_size;
                        let off_in_cluster = (offset % cluster_size) as usize;

                        match vcn_to_lcn(&inode.data_runs, inode.data_run_count, vcn) {
                            Some(lcn) => {
                                if let Some(data_va) =
                                    cache_read(&blk, lcn, vol.cluster_size)
                                {
                                    let chunk = inline_len
                                        .min(vol.cluster_size as usize - off_in_cluster);
                                    let data = unsafe {
                                        core::slice::from_raw_parts(
                                            (data_va + off_in_cluster) as *const u8,
                                            chunk,
                                        )
                                    };
                                    let packed = pack_inline_data(data);
                                    let _ = syscall::reply(
                                        FS_READ_OK,
                                        chunk as u64,
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
                                // Sparse hole.
                                let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                            }
                        }
                    }
                }
            }

            FS_READDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let start_offset = msg.data[3] as u32;

                let dir_record = if name_len == 0 {
                    Some(MFT_RECORD_ROOT)
                } else {
                    let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                    let name = &name_buf[..name_len.min(16)];
                    // Resolve the directory path.
                    path_resolve(&blk, &vol, name).map(|i| i.mft_record)
                };

                let dir_record = match dir_record {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                        continue;
                    }
                };

                match dir_enumerate(&blk, &vol, dir_record, start_offset) {
                    Some(entry) => {
                        // Get file size by reading the MFT record.
                        let file_size = {
                            let buf = unsafe { &mut MFT_BUF };
                            if read_mft_record(&blk, &vol, entry.mft_ref, buf) {
                                if let Some(inode) = parse_inode(buf, &vol, entry.mft_ref) {
                                    inode.file_size
                                } else {
                                    0
                                }
                            } else {
                                0
                            }
                        };

                        let mut name_lo = 0u64;
                        let mut name_hi = 0u64;
                        for i in 0..entry.name_len.min(8) {
                            name_lo |= (entry.name[i] as u64) << (i * 8);
                        }
                        for i in 8..entry.name_len.min(16) {
                            name_hi |= (entry.name[i] as u64) << ((i - 8) * 8);
                        }

                        let _ = syscall::reply(
                            FS_READDIR_OK,
                            file_size,
                            name_lo,
                            name_hi,
                            (start_offset + 1) as u64,
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
                let _ = syscall::reply(
                    FS_STAT_OK,
                    inode.file_size,
                    inode.mode as u64,
                    0, // uid/gid N/A on NTFS
                    inode.mft_record,
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
                    let _ = syscall::reply(
                        FS_STAT_OK,
                        inode.file_size,
                        inode.mode as u64,
                        0,
                        inode.mft_record,
                        0,
                    );
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let total_clusters = vol.total_clusters;
                // We don't track free clusters (read-only for now).
                let _ = syscall::reply(
                    FS_STATFS_OK,
                    total_clusters, // used (approximate)
                    0,              // free (unknown)
                    vol.cluster_size as u64,
                    0,
                    0,
                );
            }

            // --- Write operations ---

            FS_CREATE | FS_MKNOD => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Allocate a new MFT record.
                let record_num = match alloc_mft_record(&blk, &vol) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Initialize as empty regular file.
                if !init_mft_record_file(&blk, &vol, record_num, name, MFT_RECORD_ROOT, false) {
                    free_mft_record(record_num);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                // Add to root directory's index.
                if !dir_add_entry(&blk, &vol, MFT_RECORD_ROOT, name, record_num, 0) {
                    free_mft_record(record_num);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                // Read back the inode for the handle.
                let inode = {
                    let buf = unsafe { &mut MFT_BUF };
                    if read_mft_record(&blk, &vol, record_num, buf) {
                        parse_inode(buf, &vol, record_num)
                    } else {
                        None
                    }
                };

                let inode = match inode {
                    Some(i) => i,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Allocate a handle.
                let mut handle = u64::MAX;
                for (i, h) in handles.iter_mut().enumerate() {
                    if !h.active {
                        h.active = true;
                        h.inode = inode;
                        h.mft_record = record_num;
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
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let record_num = match alloc_mft_record(&blk, &vol) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Initialize as directory with empty INDEX_ROOT.
                if !init_mft_record_file(&blk, &vol, record_num, name, MFT_RECORD_ROOT, true) {
                    free_mft_record(record_num);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                // Add to parent directory's index.
                if !dir_add_entry(&blk, &vol, MFT_RECORD_ROOT, name, record_num, FILE_ATTR_DIRECTORY) {
                    free_mft_record(record_num);
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

                let cluster_size = vol.cluster_size;
                let record_num = handles[handle].mft_record;
                let mut written = 0usize;
                let mut file_size = handles[handle].inode.file_size;

                // If data is currently resident and we need more than fits,
                // convert to non-resident.
                if handles[handle].inode.data_resident {
                    let current_len = handles[handle].inode.data_value_length as usize;
                    if file_size as usize + length > cluster_size as usize / 2 {
                        // Read old data first.
                        let mut old_data = [0u8; 512];
                        let old_len = current_len.min(512);
                        if old_len > 0 {
                            let mft_buf = unsafe { &mut MFT_BUF };
                            if read_mft_record(&blk, &vol, record_num, mft_buf) {
                                let off = handles[handle].inode.data_value_offset;
                                for i in 0..old_len {
                                    old_data[i] = mft_buf[off + i];
                                }
                            }
                        }

                        match make_data_nonresident(&blk, &vol, record_num, &old_data[..old_len]) {
                            Some((lcn, _alloc)) => {
                                // Refresh inode from disk.
                                let mft_buf = unsafe { &mut MFT_BUF };
                                if read_mft_record(&blk, &vol, record_num, mft_buf) {
                                    if let Some(new_inode) = parse_inode(mft_buf, &vol, record_num) {
                                        handles[handle].inode = new_inode;
                                    }
                                }
                                let _ = lcn;
                            }
                            None => {
                                let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                                continue;
                            }
                        }
                    } else {
                        // Small write — append to resident data in MFT record.
                        let mft_buf = unsafe { &mut MFT_BUF };
                        if !read_mft_record(&blk, &vol, record_num, mft_buf) {
                            let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                            continue;
                        }

                        if let Some(data_attr) = find_attr(mft_buf, vol.mft_record_size, AT_DATA, 0) {
                            if !data_attr.non_resident {
                                let val_off = data_attr.record_offset + data_attr.value_offset as usize;
                                let new_len = current_len + length;
                                if val_off + new_len < vol.mft_record_size as usize - 16 {
                                    // Copy from grant_va.
                                    if grant_va != 0 {
                                        for i in 0..length {
                                            mft_buf[val_off + current_len + i] =
                                                unsafe { *((grant_va + i) as *const u8) };
                                        }
                                    }
                                    // Update value length.
                                    write_le32(mft_buf, data_attr.record_offset + 16, new_len as u32);
                                    write_mft_record(&blk, &vol, record_num, mft_buf);
                                    written = length;
                                    file_size += length as u64;

                                    handles[handle].inode.file_size = file_size;
                                    handles[handle].inode.data_value_length = new_len as u32;
                                }
                            }
                        }

                        let _ = syscall::reply(FS_WRITE_OK, written as u64, 0, 0, 0, 0);
                        continue;
                    }
                }

                // Non-resident write path.
                while written < length {
                    let cur_off = file_size;
                    let vcn = cur_off / (cluster_size as u64);
                    let off_in_cluster = (cur_off % (cluster_size as u64)) as usize;
                    let space = cluster_size as usize - off_in_cluster;
                    let chunk = (length - written).min(space);

                    // Resolve existing cluster or allocate new one.
                    let lcn = match vcn_to_lcn(
                        &handles[handle].inode.data_runs,
                        handles[handle].inode.data_run_count,
                        vcn,
                    ) {
                        Some(l) => l,
                        None => {
                            // Allocate a new cluster.
                            match alloc_clusters(&blk, &vol, 1) {
                                Some(new_lcn) => {
                                    // Add to data runs.
                                    let rc = handles[handle].inode.data_run_count;
                                    if rc < MAX_RUNS {
                                        handles[handle].inode.data_runs[rc] = DataRun {
                                            vcn,
                                            lcn: new_lcn as i64,
                                            length: 1,
                                        };
                                        handles[handle].inode.data_run_count = rc + 1;
                                    }
                                    new_lcn
                                }
                                None => break,
                            }
                        }
                    };

                    let wva = unsafe { WRITE_VA };

                    // Read-modify-write for partial clusters.
                    if off_in_cluster != 0 || chunk < cluster_size as usize {
                        if let Some(va) = cache_read(&blk, lcn, cluster_size) {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    va as *const u8,
                                    wva as *mut u8,
                                    cluster_size as usize,
                                );
                            }
                        } else {
                            unsafe {
                                core::ptr::write_bytes(wva as *mut u8, 0, cluster_size as usize);
                            }
                        }
                    } else {
                        unsafe {
                            core::ptr::write_bytes(wva as *mut u8, 0, cluster_size as usize);
                        }
                    }

                    // Copy data from grant page.
                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (grant_va + written) as *const u8,
                                (wva + off_in_cluster) as *mut u8,
                                chunk,
                            );
                        }
                    }

                    cache_invalidate(lcn);
                    if !blk.write_cluster(lcn, cluster_size, wva) {
                        break;
                    }

                    written += chunk;
                    file_size += chunk as u64;
                }

                // Update file size in the MFT record.
                handles[handle].inode.file_size = file_size;
                handles[handle].inode.alloc_size = file_size; // Approximate.

                // Rewrite the DATA attribute with updated runs and size.
                {
                    let mft_buf = unsafe { &mut MFT_BUF };
                    if read_mft_record(&blk, &vol, record_num, mft_buf) {
                        if let Some(data_attr) = find_attr(mft_buf, vol.mft_record_size, AT_DATA, 0) {
                            if data_attr.non_resident {
                                // Update data_size and init_size.
                                write_le64(mft_buf, data_attr.record_offset + 48, file_size);
                                write_le64(mft_buf, data_attr.record_offset + 56, file_size);
                                // Update alloc_size.
                                let alloc = ((file_size + cluster_size as u64 - 1)
                                    / cluster_size as u64)
                                    * cluster_size as u64;
                                write_le64(mft_buf, data_attr.record_offset + 40, alloc);
                                // Rewrite data runs.
                                let run_off = data_attr.record_offset + data_attr.data_run_offset as usize;
                                let run_space = data_attr.length as usize - data_attr.data_run_offset as usize;
                                // Build run pairs.
                                let inode = &handles[handle].inode;
                                let rc = inode.data_run_count.min(MAX_RUNS);
                                let mut pairs = [(0u64, 0u64); MAX_RUNS];
                                for i in 0..rc {
                                    if inode.data_runs[i].lcn >= 0 {
                                        pairs[i] = (inode.data_runs[i].lcn as u64, inode.data_runs[i].length);
                                    }
                                }
                                // Zero run area.
                                for b in mft_buf[run_off..run_off + run_space].iter_mut() {
                                    *b = 0;
                                }
                                encode_data_runs(mft_buf, run_off, &pairs, rc);

                                // Update highest VCN.
                                let total_vcn: u64 = inode.data_runs[..rc].iter().map(|r| r.length).sum();
                                if total_vcn > 0 {
                                    write_le64(mft_buf, data_attr.record_offset + 24, total_vcn - 1);
                                }

                                write_mft_record(&blk, &vol, record_num, mft_buf);
                            }
                        }
                    }
                }

                let _ = syscall::reply(FS_WRITE_OK, written as u64, 0, 0, 0, 0);
            }

            FS_DELETE | FS_UNLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Look up the file.
                let child_ref = match dir_lookup(&blk, &vol, MFT_RECORD_ROOT, name) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Read the child inode.
                let child_inode = {
                    let buf = unsafe { &mut MFT_BUF };
                    if read_mft_record(&blk, &vol, child_ref, buf) {
                        parse_inode(buf, &vol, child_ref)
                    } else {
                        None
                    }
                };

                if let Some(inode) = child_inode {
                    // Free data clusters.
                    free_inode_clusters(&blk, &vol, &inode);

                    // Remove from directory index.
                    dir_remove_entry(&blk, &vol, MFT_RECORD_ROOT, name);

                    // Mark MFT record as unused.
                    {
                        let buf = unsafe { &mut MFT_BUF };
                        if read_mft_record(&blk, &vol, child_ref, buf) {
                            // Clear in-use flag.
                            let flags = read_le16(buf, 0x16);
                            write_le16(buf, 0x16, flags & !MFT_RECORD_IN_USE);
                            build_fixup(buf, vol.mft_record_size, vol.bytes_per_sector);
                            // Write back (we already built fixup, so write raw).
                            let mft_byte_offset = vol.mft_cluster * (vol.cluster_size as u64)
                                + child_ref * (vol.mft_record_size as u64);
                            blk.read_bytes(0, &mut []); // no-op to keep borrow checker happy
                            let _ = write_mft_record(&blk, &vol, child_ref, buf);
                        }
                    }

                    free_mft_record(child_ref);

                    // Close any open handles to this file.
                    for h in handles.iter_mut() {
                        if h.active && h.mft_record == child_ref {
                            h.active = false;
                        }
                    }

                    let _ = syscall::reply(FS_DELETE_OK, 0, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                }
            }

            FS_TRUNCATE => {
                let handle = msg.data[0] as usize;
                let new_size = msg.data[1];

                if handle >= MAX_OPEN || !handles[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let record_num = handles[handle].mft_record;

                if new_size == 0 {
                    // Truncate to zero: free all data clusters.
                    free_inode_clusters(&blk, &vol, &handles[handle].inode);
                    handles[handle].inode.file_size = 0;
                    handles[handle].inode.alloc_size = 0;
                    handles[handle].inode.data_run_count = 0;
                    handles[handle].inode.data_resident = true;
                    handles[handle].inode.data_value_length = 0;

                    // Rewrite MFT record with empty resident DATA.
                    let mft_buf = unsafe { &mut MFT_BUF };
                    if read_mft_record(&blk, &vol, record_num, mft_buf) {
                        if let Some(data_attr) = find_attr(mft_buf, vol.mft_record_size, AT_DATA, 0) {
                            let attr_off = data_attr.record_offset;
                            let old_len = data_attr.length as usize;
                            // Replace with minimal resident DATA attr.
                            let new_len = 24usize;
                            let aligned = (new_len + 7) & !7;
                            let used = read_le32(mft_buf, 24) as usize;
                            // Shift tail.
                            let after_old = attr_off + old_len;
                            let after_new = attr_off + aligned;
                            let tail = used - after_old;
                            if old_len > aligned {
                                for i in 0..tail {
                                    mft_buf[after_new + i] = mft_buf[after_old + i];
                                }
                            }
                            // Zero and rewrite.
                            for b in mft_buf[attr_off..attr_off + aligned].iter_mut() {
                                *b = 0;
                            }
                            write_le32(mft_buf, attr_off, AT_DATA);
                            write_le32(mft_buf, attr_off + 4, aligned as u32);
                            mft_buf[attr_off + 8] = 0; // Resident.
                            write_le16(mft_buf, attr_off + 14, 2);
                            write_le32(mft_buf, attr_off + 16, 0);
                            write_le16(mft_buf, attr_off + 20, 24);
                            let new_used = used as isize + aligned as isize - old_len as isize;
                            write_le32(mft_buf, 24, new_used as u32);
                            write_mft_record(&blk, &vol, record_num, mft_buf);
                        }
                    }
                } else {
                    // Non-zero truncate: just update size (don't free clusters).
                    handles[handle].inode.file_size = new_size;
                    let mft_buf = unsafe { &mut MFT_BUF };
                    if read_mft_record(&blk, &vol, record_num, mft_buf) {
                        if let Some(data_attr) = find_attr(mft_buf, vol.mft_record_size, AT_DATA, 0) {
                            if data_attr.non_resident {
                                write_le64(mft_buf, data_attr.record_offset + 48, new_size);
                                write_le64(mft_buf, data_attr.record_offset + 56, new_size);
                                write_mft_record(&blk, &vol, record_num, mft_buf);
                            }
                        }
                    }
                }

                let _ = syscall::reply(FS_TRUNCATE_OK, 0, 0, 0, 0, 0);
            }

            FS_RENAME => {
                // data[0..1] = old name, data[2] = old_len | (new_len << 16), data[3] = new name packed.
                let old_len = (msg.data[2] & 0xFFFF) as usize;
                let new_len = ((msg.data[2] >> 16) & 0xFFFF) as usize;
                let old_name_buf = unpack_name(msg.data[0], msg.data[1], old_len);
                let old_name = &old_name_buf[..old_len.min(16)];
                let new_name_buf = unpack_name(msg.data[3], 0, new_len);
                let new_name = &new_name_buf[..new_len.min(8)];

                // Find the old entry.
                let child_ref = match dir_lookup(&blk, &vol, MFT_RECORD_ROOT, old_name) {
                    Some(r) => r,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                        continue;
                    }
                };

                // Read child to get flags.
                let child_flags = {
                    let buf = unsafe { &mut MFT_BUF };
                    if read_mft_record(&blk, &vol, child_ref, buf) {
                        if let Some(inode) = parse_inode(buf, &vol, child_ref) {
                            inode.flags
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                };

                // Remove old index entry.
                if !dir_remove_entry(&blk, &vol, MFT_RECORD_ROOT, old_name) {
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                // Add new index entry.
                if !dir_add_entry(&blk, &vol, MFT_RECORD_ROOT, new_name, child_ref, child_flags) {
                    // Try to restore old entry.
                    dir_add_entry(&blk, &vol, MFT_RECORD_ROOT, old_name, child_ref, child_flags);
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                // Update FILE_NAME attribute in the child MFT record.
                {
                    let buf = unsafe { &mut MFT_BUF };
                    if read_mft_record(&blk, &vol, child_ref, buf) {
                        if let Some(fn_attr) = find_attr(buf, vol.mft_record_size, AT_FILE_NAME, 0) {
                            if !fn_attr.non_resident {
                                let fn_off = fn_attr.record_offset + fn_attr.value_offset as usize;
                                let name_chars = new_name.len().min(32);
                                buf[fn_off + 64] = name_chars as u8;
                                for i in 0..name_chars {
                                    write_le16(buf, fn_off + 66 + i * 2, new_name[i] as u16);
                                }
                                // Zero remaining name bytes.
                                for i in name_chars..32 {
                                    write_le16(buf, fn_off + 66 + i * 2, 0);
                                }
                                write_mft_record(&blk, &vol, child_ref, buf);
                            }
                        }
                    }
                }

                let _ = syscall::reply(FS_RENAME_OK, 0, 0, 0, 0, 0);
            }

            // Stubs for operations not yet implemented.
            FS_CHMOD | FS_UTIMENS | FS_SYMLINK | FS_READLINK | FS_LINK | FS_CHOWN => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }

            _ => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }
    }
}
