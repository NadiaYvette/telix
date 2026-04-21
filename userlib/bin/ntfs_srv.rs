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
}

impl BlkClient {
    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let mut remaining = out.len();
        let mut buf_off = 0usize;
        let mut byte_off = off;

        while remaining > 0 {
            let abs_off = self.partition_offset + byte_off;
            let sector = abs_off / 512;
            let offset_in_sector = (abs_off % 512) as usize;

            if !syscall::grant_pages(
                self.blk_aspace,
                self.scratch_va,
                self.grant_va,
                1,
                false,
            ) {
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

            let ok =
                if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
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

            syscall::revoke(self.blk_aspace, self.grant_va);
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
            if !syscall::grant_pages(
                self.blk_aspace,
                self.scratch_va,
                self.grant_va,
                1,
                false,
            ) {
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

            let ok =
                if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
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
            if !syscall::grant_pages(
                self.blk_aspace,
                self.scratch_va,
                self.grant_va,
                1,
                false,
            ) {
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
    };

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

            // Write operations — stubs for now, ready for future expansion.
            FS_CREATE | FS_MKNOD | FS_WRITE | FS_DELETE | FS_MKDIR | FS_UNLINK | FS_CHMOD
            | FS_UTIMENS | FS_SYMLINK | FS_READLINK | FS_LINK | FS_RENAME | FS_CHOWN
            | FS_TRUNCATE => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }

            _ => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }
    }
}
