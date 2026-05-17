#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux fs/fat, Microsoft FAT specification

//! Unified FAT12/16/32 filesystem server.
//!
//! Pure userspace process that reads FAT12, FAT16, or FAT32 filesystems
//! from blk_srv via IPC.  Detects the variant from cluster count per the
//! Microsoft FAT specification.  Supports subdirectories and long filenames
//! (VFAT/LFN).

extern crate userlib;
use core::cell::Cell;
use core::sync::atomic::{AtomicU64, Ordering};
use userlib::syscall;

/// Reply port registered by linux_srv via FS_SET_READ_REPLY_PORT.
/// 0 = no port; FS_READ_ASYNC silently drops in that case.
static ASYNC_READ_REPLY_PORT: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// IPC protocol constants
// ---------------------------------------------------------------------------

const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;

const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_OPEN_LONG: u64 = 0x2002;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READ_ASYNC: u64 = 0x2102;
const FS_READ_REPLY: u64 = 0x2103;
const FS_SET_READ_REPLY_PORT: u64 = 0x2104;
const FS_SET_READ_REPLY_PORT_OK: u64 = 0x2105;
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
#[allow(dead_code)]
const FS_UNLINK: u64 = 0x2A20;
const FS_UNLINK_OK: u64 = 0x2A21;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

const MAX_OPEN_FILES: usize = 16;
const MAX_INLINE: usize = 24;
const FS_SCRATCH_VA: usize = 0x5_0000_0000;
const MAX_FAT_PAGES: usize = 256; // 1 MiB max FAT cache

// ---------------------------------------------------------------------------
// FAT variant and on-disk structures
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum FatVariant {
    Fat12,
    Fat16,
    Fat32,
}

struct Bpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    root_entry_count: u16,
    total_sectors_16: u16,
    sectors_per_fat_16: u16,
    total_sectors_32: u32,
    // FAT32 extended fields (ignored on FAT12/16):
    sectors_per_fat_32: u32,
    root_cluster: u32,
    #[allow(dead_code)]
    fs_info_sector: u16,
}

struct FatLayout {
    variant: FatVariant,
    fat_start: u32,
    #[allow(dead_code)]
    fat_size_sectors: u32,
    root_dir_start: u32,
    root_dir_sectors: u32,
    root_cluster: u32,
    data_start: u32,
    sectors_per_cluster: u32,
    total_clusters: u32,
}

#[derive(Clone, Copy)]
enum DirLoc {
    FixedRoot,
    Cluster(u32),
}

#[derive(Clone, Copy)]
struct DirEntry {
    name_short: [u8; 11],
    name_long: [u8; 128],
    name_long_len: u8,
    attrs: u8,
    first_cluster: u32,
    file_size: u32,
    sector: u32,
    offset: u16,
}

impl DirEntry {
    const fn empty() -> Self {
        Self {
            name_short: [0; 11],
            name_long: [0; 128],
            name_long_len: 0,
            attrs: 0,
            first_cluster: 0,
            file_size: 0,
            sector: 0,
            offset: 0,
        }
    }

    fn is_dir(&self) -> bool {
        self.attrs & 0x10 != 0
    }
}

#[derive(Clone, Copy)]
struct OpenFile {
    active: bool,
    writable: bool,
    first_cluster: u32,
    file_size: u32,
    dir_sector: u32,
    dir_offset: u16,
    last_cluster: u32,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            active: false,
            writable: false,
            first_cluster: 0,
            file_size: 0,
            dir_sector: 0,
            dir_offset: 0,
            last_cluster: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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

fn to_upper(b: u8) -> u8 {
    if b >= b'a' && b <= b'z' {
        b - 32
    } else {
        b
    }
}

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

fn unpack_name_short(d0: u64, d1: u64, len: usize) -> ([u8; 128], usize) {
    let mut buf = [0u8; 128];
    let n = len.min(16);
    let words = [d0, d1];
    for i in 0..n {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    (buf, n)
}

// ---------------------------------------------------------------------------
// Block I/O client
// ---------------------------------------------------------------------------

struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
    grant_va: usize,
    /// Byte offset of the FAT partition within the disk image.
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

    fn read_sector(&self, sector: u32, out: &mut [u8; 512]) -> bool {
        let nonce = self.next_nonce();
        let offset = self.partition_offset + (sector as u64) * 512;
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_READ,
            nonce,
            offset,
            d2,
            self.grant_va as u64,
        );
        if let Some(rr) = self.recv_match(nonce) {
            if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                let src = self.scratch_va as *const u8;
                let dst = out.as_mut_ptr();
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
        }
    }

    fn write_sector(&self, sector: u32, data: &[u8; 512]) -> bool {
        let src = data.as_ptr();
        let dst = self.scratch_va as *mut u8;
        unsafe {
            for i in 0..512 {
                let b = core::ptr::read_volatile(src.add(i));
                core::ptr::write_volatile(dst.add(i), b);
            }
        }
        let nonce = self.next_nonce();
        let offset = self.partition_offset + (sector as u64) * 512;
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(
            self.blk_port,
            IO_WRITE,
            nonce,
            offset,
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

// ---------------------------------------------------------------------------
// FAT table operations — dispatch on variant
// ---------------------------------------------------------------------------

fn fat_read(fat_va: usize, fat_bytes: usize, cluster: u32, v: FatVariant) -> u32 {
    match v {
        FatVariant::Fat12 => {
            let off = (cluster as usize) * 3 / 2;
            if off + 1 >= fat_bytes {
                return 0;
            }
            let b0 = unsafe { *((fat_va + off) as *const u8) } as u32;
            let b1 = unsafe { *((fat_va + off + 1) as *const u8) } as u32;
            let raw = b0 | (b1 << 8);
            if cluster & 1 == 0 {
                raw & 0xFFF
            } else {
                raw >> 4
            }
        }
        FatVariant::Fat16 => {
            let off = (cluster as usize) * 2;
            if off + 1 >= fat_bytes {
                return 0;
            }
            unsafe { *((fat_va + off) as *const u16) as u32 }
        }
        FatVariant::Fat32 => {
            let off = (cluster as usize) * 4;
            if off + 3 >= fat_bytes {
                return 0;
            }
            unsafe { *((fat_va + off) as *const u32) & 0x0FFF_FFFF }
        }
    }
}

fn fat_write(fat_va: usize, fat_bytes: usize, cluster: u32, value: u32, v: FatVariant) {
    match v {
        FatVariant::Fat12 => {
            let off = (cluster as usize) * 3 / 2;
            if off + 1 >= fat_bytes {
                return;
            }
            let b0 = unsafe { *((fat_va + off) as *const u8) } as u32;
            let b1 = unsafe { *((fat_va + off + 1) as *const u8) } as u32;
            let raw = b0 | (b1 << 8);
            let new = if cluster & 1 == 0 {
                (raw & 0xF000) | (value & 0xFFF)
            } else {
                (raw & 0x000F) | ((value & 0xFFF) << 4)
            };
            unsafe {
                *((fat_va + off) as *mut u8) = new as u8;
                *((fat_va + off + 1) as *mut u8) = (new >> 8) as u8;
            }
        }
        FatVariant::Fat16 => {
            let off = (cluster as usize) * 2;
            if off + 1 >= fat_bytes {
                return;
            }
            unsafe {
                *((fat_va + off) as *mut u16) = value as u16;
            }
        }
        FatVariant::Fat32 => {
            let off = (cluster as usize) * 4;
            if off + 3 >= fat_bytes {
                return;
            }
            let old = unsafe { *((fat_va + off) as *const u32) };
            unsafe {
                *((fat_va + off) as *mut u32) = (old & 0xF000_0000) | (value & 0x0FFF_FFFF);
            }
        }
    }
}

fn is_eoc(cluster: u32, v: FatVariant) -> bool {
    match v {
        FatVariant::Fat12 => cluster >= 0xFF8,
        FatVariant::Fat16 => cluster >= 0xFFF8,
        FatVariant::Fat32 => cluster >= 0x0FFF_FFF8,
    }
}

fn eoc_mark(v: FatVariant) -> u32 {
    match v {
        FatVariant::Fat12 => 0xFFF,
        FatVariant::Fat16 => 0xFFFF,
        FatVariant::Fat32 => 0x0FFF_FFFF,
    }
}

fn find_free_cluster(
    fat_va: usize,
    fat_bytes: usize,
    total_clusters: u32,
    v: FatVariant,
) -> Option<u32> {
    for c in 2..total_clusters + 2 {
        if fat_read(fat_va, fat_bytes, c, v) == 0 {
            return Some(c);
        }
    }
    None
}

fn alloc_cluster(
    fat_va: usize,
    fat_bytes: usize,
    total_clusters: u32,
    v: FatVariant,
) -> Option<u32> {
    let c = find_free_cluster(fat_va, fat_bytes, total_clusters, v)?;
    fat_write(fat_va, fat_bytes, c, eoc_mark(v), v);
    Some(c)
}

fn flush_fat(blk: &BlkClient, fat_va: usize, fat_start: u32, fat_sectors: u32) {
    for i in 0..fat_sectors {
        let mut sec = [0u8; 512];
        unsafe {
            core::ptr::copy_nonoverlapping(
                (fat_va + (i as usize) * 512) as *const u8,
                sec.as_mut_ptr(),
                512,
            );
        }
        blk.write_sector(fat_start + i, &sec);
    }
}

/// Walk a FAT chain starting from `start` for `count` links.
/// walk_chain(start, 0) returns start itself.
fn walk_chain(
    fat_va: usize,
    fb: usize,
    start: u32,
    count: u32,
    v: FatVariant,
) -> Option<u32> {
    if start < 2 {
        return None;
    }
    let mut c = start;
    for _ in 0..count {
        c = fat_read(fat_va, fb, c, v);
        if is_eoc(c, v) || c < 2 {
            return None;
        }
    }
    Some(c)
}

// ---------------------------------------------------------------------------
// 8.3 short name handling
// ---------------------------------------------------------------------------

fn to_8_3(name: &[u8], out: &mut [u8; 11]) {
    *out = [b' '; 11];
    let len = name.len();
    let mut dot_pos = len;
    for (i, &b) in name.iter().enumerate() {
        if b == b'.' {
            dot_pos = i;
            break;
        }
    }
    for i in 0..8.min(dot_pos) {
        out[i] = to_upper(name[i]);
    }
    if dot_pos < len {
        let ext = dot_pos + 1;
        for i in 0..3.min(len - ext) {
            out[8 + i] = to_upper(name[ext + i]);
        }
    }
}

/// Format an 8.3 name as "NAME.EXT" (human-readable). Returns length.
fn from_8_3(raw: &[u8; 11], out: &mut [u8; 13]) -> usize {
    let mut ni = 0;
    let mut base_end = 8;
    while base_end > 0 && raw[base_end - 1] == b' ' {
        base_end -= 1;
    }
    for i in 0..base_end {
        out[ni] = raw[i];
        ni += 1;
    }
    let mut ext_end = 3;
    while ext_end > 0 && raw[8 + ext_end - 1] == b' ' {
        ext_end -= 1;
    }
    if ext_end > 0 {
        out[ni] = b'.';
        ni += 1;
        for i in 0..ext_end {
            out[ni] = raw[8 + i];
            ni += 1;
        }
    }
    ni
}

fn name_fits_8_3(name: &[u8], len: usize) -> bool {
    if len == 0 || len > 12 {
        return false;
    }
    let mut dot_count = 0usize;
    let mut dot_pos = len;
    for i in 0..len {
        let b = name[i];
        if b == b'.' {
            dot_count += 1;
            if dot_count > 1 {
                return false;
            }
            dot_pos = i;
        } else if b == b' ' || b < 0x20 {
            return false;
        }
    }
    if dot_count == 0 {
        len <= 8
    } else {
        dot_pos <= 8 && (len - dot_pos - 1) <= 3
    }
}

/// Generate a unique 8.3 short name from a long name using ~1 suffix.
fn generate_short_name(long_name: &[u8], long_len: usize, out: &mut [u8; 11]) {
    *out = [b' '; 11];
    let mut last_dot = None;
    for i in (0..long_len).rev() {
        if long_name[i] == b'.' {
            last_dot = Some(i);
            break;
        }
    }
    let basis_end = last_dot.unwrap_or(long_len);
    let mut bi = 0;
    for i in 0..basis_end {
        let b = long_name[i];
        if b == b' ' || b == b'.' {
            continue;
        }
        if bi >= 6 {
            break;
        }
        out[bi] = to_upper(b);
        bi += 1;
    }
    if bi == 0 {
        out[0] = b'_';
        bi = 1;
    }
    out[bi] = b'~';
    out[bi + 1] = b'1';
    if let Some(d) = last_dot {
        for i in 0..3 {
            if d + 1 + i >= long_len {
                break;
            }
            out[8 + i] = to_upper(long_name[d + 1 + i]);
        }
    }
}

/// Compute the checksum used by LFN entries to validate the 8.3 name.
fn lfn_checksum(name83: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in name83 {
        sum = ((sum >> 1) | (sum << 7)).wrapping_add(b);
    }
    sum
}

fn name_eq_ci(a: &[u8], a_len: usize, b: &[u8], b_len: usize) -> bool {
    if a_len != b_len {
        return false;
    }
    for i in 0..a_len {
        if to_upper(a[i]) != to_upper(b[i]) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// LFN (VFAT long filename) support
// ---------------------------------------------------------------------------

struct LfnAccum {
    chars: [u16; 260],
    len: usize,
    checksum: u8,
    seq_expected: u8,
    valid: bool,
}

impl LfnAccum {
    const fn new() -> Self {
        Self {
            chars: [0u16; 260],
            len: 0,
            checksum: 0,
            seq_expected: 0,
            valid: false,
        }
    }

    fn reset(&mut self) {
        self.len = 0;
        self.seq_expected = 0;
        self.valid = false;
    }

    /// Feed one 32-byte LFN directory entry.
    fn feed(&mut self, entry: &[u8]) {
        let seq = entry[0];
        let chksum = entry[13];

        if seq & 0x40 != 0 {
            // First LFN entry (highest sequence number).
            self.reset();
            self.checksum = chksum;
            self.seq_expected = seq & 0x3F;
            self.valid = true;
        } else if !self.valid || chksum != self.checksum {
            self.reset();
            return;
        }

        let seq_num = seq & 0x3F;
        if seq_num != self.seq_expected || seq_num == 0 {
            self.reset();
            return;
        }
        self.seq_expected = seq_num - 1;

        // Extract 13 UTF-16 characters from the entry.
        let base = ((seq_num - 1) as usize) * 13;
        let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (ci, &off) in offsets.iter().enumerate() {
            let idx = base + ci;
            if idx >= 260 {
                break;
            }
            let ch = (entry[off] as u16) | ((entry[off + 1] as u16) << 8);
            self.chars[idx] = ch;
        }
        let end = base + 13;
        if end > self.len {
            self.len = end;
        }
    }

    fn is_complete(&self) -> bool {
        self.valid && self.seq_expected == 0
    }

    /// Convert assembled UTF-16 name to UTF-8. Returns length.
    fn to_utf8(&self, out: &mut [u8], max: usize) -> usize {
        let mut oi = 0;
        // Trim trailing 0xFFFF / 0x0000 padding.
        let mut end = self.len;
        while end > 0 && (self.chars[end - 1] == 0xFFFF || self.chars[end - 1] == 0) {
            end -= 1;
        }
        for i in 0..end {
            let ch = self.chars[i];
            if ch == 0 {
                break;
            }
            if ch < 0x80 {
                if oi >= max {
                    break;
                }
                out[oi] = ch as u8;
                oi += 1;
            } else if ch < 0x800 {
                if oi + 1 >= max {
                    break;
                }
                out[oi] = 0xC0 | ((ch >> 6) as u8);
                out[oi + 1] = 0x80 | ((ch & 0x3F) as u8);
                oi += 2;
            } else {
                if oi + 2 >= max {
                    break;
                }
                out[oi] = 0xE0 | ((ch >> 12) as u8);
                out[oi + 1] = 0x80 | (((ch >> 6) & 0x3F) as u8);
                out[oi + 2] = 0x80 | ((ch & 0x3F) as u8);
                oi += 3;
            }
        }
        oi
    }
}

/// Build LFN directory entries for a name.
/// `entries[0]` = sequence 1, `entries[n-1]` = highest sequence (with 0x40 flag).
/// Returns the number of entries written (max 20).
fn build_lfn_entries(
    name: &[u8],
    name_len: usize,
    checksum: u8,
    entries: &mut [[u8; 32]; 20],
) -> usize {
    // Convert UTF-8 → UTF-16.
    let mut u16buf = [0xFFFFu16; 260];
    let mut u16len = 0usize;
    let mut i = 0;
    while i < name_len {
        let b = name[i];
        let ch: u16;
        if b < 0x80 {
            ch = b as u16;
            i += 1;
        } else if b < 0xE0 && i + 1 < name_len {
            ch = (((b & 0x1F) as u16) << 6) | ((name[i + 1] & 0x3F) as u16);
            i += 2;
        } else if i + 2 < name_len {
            ch = (((b & 0x0F) as u16) << 12)
                | (((name[i + 1] & 0x3F) as u16) << 6)
                | ((name[i + 2] & 0x3F) as u16);
            i += 3;
        } else {
            ch = b'?' as u16;
            i += 1;
        }
        if u16len < 255 {
            u16buf[u16len] = ch;
            u16len += 1;
        }
    }
    // NUL terminate.
    if u16len < 260 {
        u16buf[u16len] = 0x0000;
        u16len += 1;
    }

    let num_entries = ((u16len + 12) / 13).max(1).min(20);
    let offsets: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

    for seq in 1..=num_entries {
        let entry = &mut entries[seq - 1];
        *entry = [0u8; 32];
        let base = (seq - 1) * 13;

        entry[0] = seq as u8;
        if seq == num_entries {
            entry[0] |= 0x40;
        }
        entry[11] = 0x0F; // LFN attribute
        entry[13] = checksum;

        for (ci, &off) in offsets.iter().enumerate() {
            let idx = base + ci;
            let ch = if idx < 260 { u16buf[idx] } else { 0xFFFF };
            entry[off] = ch as u8;
            entry[off + 1] = (ch >> 8) as u8;
        }
    }
    num_entries
}

// ---------------------------------------------------------------------------
// Directory abstraction — handles both fixed root and cluster chains
// ---------------------------------------------------------------------------

/// Map a directory-relative sector index to a disk sector number.
fn dir_sector_addr(
    dir: DirLoc,
    sector_idx: u32,
    layout: &FatLayout,
    fat_va: usize,
    fb: usize,
) -> Option<u32> {
    match dir {
        DirLoc::FixedRoot => {
            if sector_idx >= layout.root_dir_sectors {
                return None;
            }
            Some(layout.root_dir_start + sector_idx)
        }
        DirLoc::Cluster(first) => {
            let spc = layout.sectors_per_cluster;
            let cluster_idx = sector_idx / spc;
            let sec_in_cluster = sector_idx % spc;
            let cluster = walk_chain(fat_va, fb, first, cluster_idx, layout.variant)?;
            Some(layout.data_start + (cluster - 2) * spc + sec_in_cluster)
        }
    }
}

fn dir_max_sectors(dir: DirLoc, layout: &FatLayout) -> u32 {
    match dir {
        DirLoc::FixedRoot => layout.root_dir_sectors,
        DirLoc::Cluster(_) => 256, // cap iteration at 256 sectors for safety
    }
}

/// Compute disk (sector, byte_offset) for the Nth 32-byte entry in a dir.
fn dir_entry_addr(
    dir: DirLoc,
    entry_idx: u32,
    layout: &FatLayout,
    fat_va: usize,
    fb: usize,
) -> Option<(u32, usize)> {
    let sec_idx = entry_idx / 16;
    let ent_in_sec = (entry_idx % 16) as usize;
    let disk_sec = dir_sector_addr(dir, sec_idx, layout, fat_va, fb)?;
    Some((disk_sec, ent_in_sec * 32))
}

/// Find a directory entry by name. Supports 8.3 and LFN matching.
fn dir_find(
    dir: DirLoc,
    name: &[u8],
    name_len: usize,
    layout: &FatLayout,
    fat_va: usize,
    fb: usize,
    blk: &BlkClient,
) -> Option<DirEntry> {
    let mut name83 = [0u8; 11];
    to_8_3(&name[..name_len], &mut name83);
    let max_sec = dir_max_sectors(dir, layout);
    let mut lfn = LfnAccum::new();

    for si in 0..max_sec {
        let disk_sec = match dir_sector_addr(dir, si, layout, fat_va, fb) {
            Some(s) => s,
            None => break,
        };
        let mut sec = [0u8; 512];
        if !blk.read_sector(disk_sec, &mut sec) {
            break;
        }

        for e in 0..16u32 {
            let off = (e * 32) as usize;
            let first_byte = sec[off];
            if first_byte == 0x00 {
                return None; // end of directory
            }
            if first_byte == 0xE5 {
                lfn.reset();
                continue;
            }
            let attrs = sec[off + 11];
            if attrs == 0x0F {
                lfn.feed(&sec[off..off + 32]);
                continue;
            }

            // Regular 8.3 entry — check for match.
            let mut matched = false;

            // LFN match.
            if lfn.is_complete() {
                let mut short = [0u8; 11];
                short.copy_from_slice(&sec[off..off + 11]);
                if lfn.checksum == lfn_checksum(&short) {
                    let mut lfn_utf8 = [0u8; 128];
                    let lfn_len = lfn.to_utf8(&mut lfn_utf8, 128);
                    if name_eq_ci(&lfn_utf8, lfn_len, name, name_len) {
                        matched = true;
                    }
                }
            }

            // 8.3 match.
            if !matched && sec[off..off + 11] == name83 {
                matched = true;
            }

            if matched {
                let mut entry = DirEntry::empty();
                entry.name_short.copy_from_slice(&sec[off..off + 11]);
                entry.attrs = attrs;
                entry.first_cluster = read_u16(&sec, off + 26) as u32;
                if layout.variant == FatVariant::Fat32 {
                    entry.first_cluster |= (read_u16(&sec, off + 20) as u32) << 16;
                }
                entry.file_size = read_u32(&sec, off + 28);
                entry.sector = disk_sec;
                entry.offset = off as u16;
                if lfn.is_complete() {
                    entry.name_long_len =
                        lfn.to_utf8(&mut entry.name_long, 128) as u8;
                }
                return Some(entry);
            }
            lfn.reset();
        }
    }
    None
}

/// Iterate directory: return the next visible entry at or after `start_index`.
/// Skips LFN entries, volume labels, ".", and "..".
fn dir_iter(
    dir: DirLoc,
    start_index: u32,
    layout: &FatLayout,
    fat_va: usize,
    fb: usize,
    blk: &BlkClient,
) -> Option<(DirEntry, u32)> {
    let max_sec = dir_max_sectors(dir, layout);
    let mut lfn = LfnAccum::new();
    let mut idx = 0u32;

    for si in 0..max_sec {
        let disk_sec = match dir_sector_addr(dir, si, layout, fat_va, fb) {
            Some(s) => s,
            None => return None,
        };
        let mut sec = [0u8; 512];
        if !blk.read_sector(disk_sec, &mut sec) {
            return None;
        }

        for e in 0..16u32 {
            let off = (e * 32) as usize;
            let first_byte = sec[off];
            if first_byte == 0x00 {
                return None;
            }
            if first_byte == 0xE5 {
                lfn.reset();
                idx += 1;
                continue;
            }
            let attrs = sec[off + 11];
            if attrs == 0x0F {
                lfn.feed(&sec[off..off + 32]);
                idx += 1;
                continue;
            }
            // Skip volume labels.
            if attrs & 0x08 != 0 {
                lfn.reset();
                idx += 1;
                continue;
            }
            // Skip "." and "..".
            if sec[off] == b'.' {
                lfn.reset();
                idx += 1;
                continue;
            }

            idx += 1;
            if idx - 1 < start_index {
                lfn.reset();
                continue;
            }

            let mut entry = DirEntry::empty();
            entry.name_short.copy_from_slice(&sec[off..off + 11]);
            entry.attrs = attrs;
            entry.first_cluster = read_u16(&sec, off + 26) as u32;
            if layout.variant == FatVariant::Fat32 {
                entry.first_cluster |= (read_u16(&sec, off + 20) as u32) << 16;
            }
            entry.file_size = read_u32(&sec, off + 28);
            entry.sector = disk_sec;
            entry.offset = off as u16;
            if lfn.is_complete() {
                let mut short = [0u8; 11];
                short.copy_from_slice(&sec[off..off + 11]);
                if lfn.checksum == lfn_checksum(&short) {
                    entry.name_long_len =
                        lfn.to_utf8(&mut entry.name_long, 128) as u8;
                }
            }
            return Some((entry, idx));
        }
    }
    None
}

/// Find a contiguous run of `count` free directory entry slots.
/// Returns the starting entry index (0-based).
fn dir_find_free_run(
    dir: DirLoc,
    count: u32,
    layout: &FatLayout,
    fat_va: usize,
    fb: usize,
    blk: &BlkClient,
) -> Option<u32> {
    let max_sec = dir_max_sectors(dir, layout);
    let mut run_start = 0u32;
    let mut run_len = 0u32;
    let mut idx = 0u32;

    for si in 0..max_sec {
        let disk_sec = match dir_sector_addr(dir, si, layout, fat_va, fb) {
            Some(s) => s,
            None => break,
        };
        let mut sec = [0u8; 512];
        if !blk.read_sector(disk_sec, &mut sec) {
            break;
        }
        for e in 0..16u32 {
            let off = (e * 32) as usize;
            let b = sec[off];
            if b == 0x00 || b == 0xE5 {
                if run_len == 0 {
                    run_start = idx;
                }
                run_len += 1;
                if run_len >= count {
                    return Some(run_start);
                }
            } else {
                run_len = 0;
            }
            idx += 1;
        }
    }
    None
}

/// Write a raw 32-byte entry at (sector, byte_offset).
fn write_raw_entry(blk: &BlkClient, sector: u32, offset: usize, data: &[u8; 32]) -> bool {
    let mut sec = [0u8; 512];
    if !blk.read_sector(sector, &mut sec) {
        return false;
    }
    sec[offset..offset + 32].copy_from_slice(data);
    blk.write_sector(sector, &sec)
}

/// Write a standard 8.3 directory entry.
fn write_dir_entry_83(
    blk: &BlkClient,
    sector: u32,
    offset: usize,
    name83: &[u8; 11],
    attrs: u8,
    cluster: u32,
    size: u32,
) -> bool {
    let mut sec = [0u8; 512];
    if !blk.read_sector(sector, &mut sec) {
        return false;
    }
    for i in 0..32 {
        sec[offset + i] = 0;
    }
    sec[offset..offset + 11].copy_from_slice(name83);
    sec[offset + 11] = attrs;
    // FAT32 high cluster word.
    write_u16(&mut sec, offset + 20, (cluster >> 16) as u16);
    write_u16(&mut sec, offset + 26, cluster as u16);
    write_u32(&mut sec, offset + 28, size);
    blk.write_sector(sector, &sec)
}

/// Initialise a new directory cluster with "." and ".." entries.
fn init_dir_cluster(
    blk: &BlkClient,
    cluster: u32,
    parent_cluster: u32,
    layout: &FatLayout,
) -> bool {
    let sector = layout.data_start + (cluster - 2) * layout.sectors_per_cluster;
    let mut sec = [0u8; 512];
    // "." entry.
    let dot: [u8; 11] = *b".          ";
    sec[0..11].copy_from_slice(&dot);
    sec[11] = 0x10;
    write_u16(&mut sec, 20, (cluster >> 16) as u16);
    write_u16(&mut sec, 26, cluster as u16);
    // ".." entry.
    let dotdot: [u8; 11] = *b"..         ";
    sec[32..43].copy_from_slice(&dotdot);
    sec[43] = 0x10;
    let pc = if layout.variant == FatVariant::Fat32 && parent_cluster == layout.root_cluster {
        0
    } else {
        parent_cluster
    };
    write_u16(&mut sec, 52, (pc >> 16) as u16);
    write_u16(&mut sec, 58, pc as u16);
    blk.write_sector(sector, &sec)
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Split the first path component from a relative path.
/// Returns (component_start, component_len, rest_start, rest_len) as byte offsets.
fn split_first(path: &[u8], len: usize) -> (usize, usize, usize, usize) {
    let mut start = 0;
    while start < len && path[start] == b'/' {
        start += 1;
    }
    let mut end = start;
    while end < len && path[end] != b'/' {
        end += 1;
    }
    let mut rest = end;
    while rest < len && path[rest] == b'/' {
        rest += 1;
    }
    (start, end - start, rest, len - rest)
}

/// Get the root DirLoc for this filesystem.
fn root_dir(layout: &FatLayout) -> DirLoc {
    if layout.variant == FatVariant::Fat32 {
        DirLoc::Cluster(layout.root_cluster)
    } else {
        DirLoc::FixedRoot
    }
}

/// Resolve a relative path to (parent_directory, name_offset, name_len).
/// For "dir1/dir2/file.txt": returns (DirLoc(dir2), offset_of("file.txt"), 8).
fn resolve_parent(
    path: &[u8],
    path_len: usize,
    layout: &FatLayout,
    fv: usize,
    fb: usize,
    blk: &BlkClient,
) -> Option<(DirLoc, usize, usize)> {
    let mut current = root_dir(layout);
    let (cs, cl, mut rs, mut rl) = split_first(path, path_len);
    if cl == 0 {
        return None;
    }

    if rl == 0 {
        // Single component — parent is root.
        return Some((current, cs, cl));
    }

    // Walk intermediate directories.
    let mut comp_start = cs;
    let mut comp_len = cl;
    loop {
        let entry = dir_find(current, &path[comp_start..], comp_len, layout, fv, fb, blk)?;
        if !entry.is_dir() {
            return None;
        }
        current = DirLoc::Cluster(entry.first_cluster);

        let (ns, nl, nr, nrl) = split_first(&path[rs..], rl);
        let abs_ns = rs + ns;
        if nrl == 0 {
            return Some((current, abs_ns, nl));
        }
        comp_start = abs_ns;
        comp_len = nl;
        rs = rs + nr;
        rl = nrl;
    }
}

/// Resolve a relative path to a DirLoc (for listing directories).
fn resolve_dir(
    path: &[u8],
    path_len: usize,
    layout: &FatLayout,
    fv: usize,
    fb: usize,
    blk: &BlkClient,
) -> Option<DirLoc> {
    if path_len == 0 {
        return Some(root_dir(layout));
    }
    let mut current = root_dir(layout);
    let mut remaining = 0usize;
    let mut rem_len = path_len;

    loop {
        let (cs, cl, rs, rl) = split_first(&path[remaining..], rem_len);
        if cl == 0 {
            break;
        }
        let entry =
            dir_find(current, &path[remaining + cs..], cl, layout, fv, fb, blk)?;
        if !entry.is_dir() {
            return None;
        }
        current = DirLoc::Cluster(entry.first_cluster);
        if rl == 0 {
            break;
        }
        remaining = remaining + rs;
        rem_len = rl;
    }
    Some(current)
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let partition_offset = arg0; // byte offset of FAT partition (0 if unpartitioned)
    syscall::debug_puts(b"  [fat_srv] starting\n");

    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"fat", port);

    // Look up cache_blk with bounded retry.
    let blk_port = {
        let mut retries = 200u32;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [fat_srv] cache_blk not found\n");
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
            syscall::debug_puts(b"  [fat_srv] blk connect FAILED\n");
            syscall::exit(1);
        }
    } else {
        syscall::debug_puts(b"  [fat_srv] blk no reply\n");
        syscall::exit(1);
    };

    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [fat_srv] scratch alloc FAILED\n");
            syscall::exit(1);
        }
    };
    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_0000, // blk_srv grant target (not FS_SCRATCH_VA)
        partition_offset,
        nonce: Cell::new(0),
    };

    // Permanent grant of `scratch_va` into cache_blk's aspace at grant_va.
    // The nonce protocol (see BlkClient::recv_match) makes stale-reply
    // corruption impossible, so per-request grant/revoke is no longer needed.
    if !syscall::grant_pages(blk.blk_aspace, blk.scratch_va, blk.grant_va, 1, false) {
        syscall::debug_puts(b"  [fat_srv] permanent grant FAILED\n");
        syscall::exit(1);
    }

    // -----------------------------------------------------------------------
    // Read boot sector, parse BPB, detect variant.
    // -----------------------------------------------------------------------

    // Retry the boot-sector read.  Under heavy boot-time concurrency the
    // first read can come back with stale/zero data even though the
    // server-side reply was IO_READ_OK (see project_phase172_tier1.md
    // memory-ordering notes).  xfs_srv does the same — without this loop
    // a single bad read leaves fat_srv stuck in nanosleep forever and
    // every subsequent FS_OPEN to "fat" times out at the kernel watchdog.
    let mut boot_sector = [0u8; 512];
    let mut boot_ok = false;
    for attempt in 0..20 {
        if blk.read_sector(0, &mut boot_sector)
            && boot_sector[510] == 0x55
            && boot_sector[511] == 0xAA
        {
            boot_ok = true;
            break;
        }
        // Drop any cache_blk page that covers the boot sector before
        // retrying — otherwise we just re-read the same race-poisoned
        // cached zeros every time.  Same idiom as btrfs_srv on its SB
        // retry path.
        if attempt > 0 {
            const CACHE_INVALIDATE: u64 = 0xC110;
            let nonce = blk.next_nonce();
            let abs_off = blk.partition_offset;
            let d2 = 4096u64 | ((blk.reply_port as u64) << 32);
            syscall::send(blk.blk_port, CACHE_INVALIDATE, nonce, abs_off, d2, 0);
            let _ = blk.recv_match(nonce);
        }
        for _ in 0..100 {
            syscall::yield_now();
        }
    }
    if !boot_ok {
        syscall::debug_puts(b"  [fat_srv] bad boot signature after retries\n");
        loop {
            syscall::nanosleep(1_000_000_000_000);
        }
    }

    let bpb = Bpb {
        bytes_per_sector: read_u16(&boot_sector, 11),
        sectors_per_cluster: boot_sector[13],
        reserved_sectors: read_u16(&boot_sector, 14),
        num_fats: boot_sector[16],
        root_entry_count: read_u16(&boot_sector, 17),
        total_sectors_16: read_u16(&boot_sector, 19),
        sectors_per_fat_16: read_u16(&boot_sector, 22),
        total_sectors_32: read_u32(&boot_sector, 32),
        sectors_per_fat_32: read_u32(&boot_sector, 36),
        root_cluster: read_u32(&boot_sector, 44),
        fs_info_sector: read_u16(&boot_sector, 48),
    };

    let fat_size = if bpb.sectors_per_fat_16 != 0 {
        bpb.sectors_per_fat_16 as u32
    } else {
        bpb.sectors_per_fat_32
    };
    let total_sectors = if bpb.total_sectors_16 != 0 {
        bpb.total_sectors_16 as u32
    } else {
        bpb.total_sectors_32
    };
    let root_dir_sectors = ((bpb.root_entry_count as u32) * 32 + 511) / 512;
    let fat_start = bpb.reserved_sectors as u32;
    let root_dir_start = fat_start + (bpb.num_fats as u32) * fat_size;
    let data_start = root_dir_start + root_dir_sectors;
    let data_sectors = total_sectors.saturating_sub(data_start);
    let total_clusters = if bpb.sectors_per_cluster > 0 {
        data_sectors / (bpb.sectors_per_cluster as u32)
    } else {
        0
    };

    let variant = if total_clusters < 4085 {
        FatVariant::Fat12
    } else if total_clusters < 65525 {
        FatVariant::Fat16
    } else {
        FatVariant::Fat32
    };

    let layout = FatLayout {
        variant,
        fat_start,
        fat_size_sectors: fat_size,
        root_dir_start,
        root_dir_sectors,
        root_cluster: if variant == FatVariant::Fat32 {
            bpb.root_cluster
        } else {
            0
        },
        data_start,
        sectors_per_cluster: bpb.sectors_per_cluster as u32,
        total_clusters,
    };

    syscall::debug_puts(b"  [fat_srv] detected ");
    match variant {
        FatVariant::Fat12 => syscall::debug_puts(b"FAT12"),
        FatVariant::Fat16 => syscall::debug_puts(b"FAT16"),
        FatVariant::Fat32 => syscall::debug_puts(b"FAT32"),
    }
    syscall::debug_puts(b" clusters=");
    print_num(total_clusters as u64);
    syscall::debug_puts(b" spc=");
    print_num(bpb.sectors_per_cluster as u64);
    syscall::debug_puts(b"\n");

    // -----------------------------------------------------------------------
    // Load FAT table into memory.
    // -----------------------------------------------------------------------

    let fat_bytes_needed = (fat_size as usize) * 512;
    let fat_pages = ((fat_bytes_needed + 4095) / 4096).min(MAX_FAT_PAGES);
    let fat_sectors_loaded = ((fat_pages * 4096) / 512).min(fat_size as usize) as u32;

    let fat_va = match syscall::mmap_anon(0, fat_pages, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [fat_srv] FAT alloc failed\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
    };
    for i in 0..fat_sectors_loaded {
        let mut sec = [0u8; 512];
        if !blk.read_sector(fat_start + i, &mut sec) {
            syscall::debug_puts(b"  [fat_srv] FAT sector read failed\n");
            loop {
                syscall::nanosleep(1_000_000_000_000);
            }
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                sec.as_ptr(),
                (fat_va + (i as usize) * 512) as *mut u8,
                512,
            );
        }
    }
    let fb = (fat_sectors_loaded as usize) * 512; // fat cached bytes

    syscall::debug_puts(b"  [fat_srv] FAT loaded (");
    print_num(fat_sectors_loaded as u64);
    syscall::debug_puts(b" sectors), ready\n");

    // -----------------------------------------------------------------------
    // Server loop
    // -----------------------------------------------------------------------

    let mut open_files = [OpenFile::empty(); MAX_OPEN_FILES];

    'msg_loop: loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            // ---------------------------------------------------------------
            // FS_OPEN / FS_OPEN_LONG
            // ---------------------------------------------------------------
            FS_OPEN | FS_OPEN_LONG => {
                let (path_buf, path_len) = if msg.tag == FS_OPEN_LONG {
                    let plen = (msg.data[0] & 0xFFFF) as usize;
                    let mut buf = [0u8; 128];
                    let n = plen.min(128);
                    for i in 0..n {
                        buf[i] = unsafe { *((FS_SCRATCH_VA + i) as *const u8) };
                    }
                    (buf, n)
                } else {
                    let plen = (msg.data[2] & 0xFFFF_FFFF) as usize;
                    unpack_name_short(msg.data[0], msg.data[1], plen)
                };

                let entry = if path_len == 0 {
                    None
                } else if let Some((pdir, ns, nl)) =
                    resolve_parent(&path_buf, path_len, &layout, fat_va, fb, &blk)
                {
                    dir_find(pdir, &path_buf[ns..], nl, &layout, fat_va, fb, &blk)
                } else {
                    None
                };

                if let Some(e) = entry {
                    let mut handle = u64::MAX;
                    for (i, f) in open_files.iter_mut().enumerate() {
                        if !f.active {
                            f.active = true;
                            f.writable = false;
                            f.first_cluster = e.first_cluster;
                            f.file_size = e.file_size;
                            f.dir_sector = e.sector;
                            f.dir_offset = e.offset;
                            f.last_cluster = 0;
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
                            e.file_size as u64,
                            my_aspace as u64,
                            0,
                            0,
                        );
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_SET_READ_REPLY_PORT => {
                ASYNC_READ_REPLY_PORT.store(msg.data[0], Ordering::Release);
                let _ = syscall::reply(FS_SET_READ_REPLY_PORT_OK, 0, 0, 0, 0, 0);
            }

            FS_READ_ASYNC => {
                // Wire format:
                //   d0 = handle (low 32) | length (high 32)
                //   d1 = offset
                //   d2 = grant_va
                //   d3 = correlation
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let length = ((msg.data[0] >> 32) & 0xFFFF_FFFF) as u32;
                let offset = msg.data[1] as u32;
                let grant_va = msg.data[2] as usize;
                let correlation = msg.data[3];
                let reply_port = ASYNC_READ_REPLY_PORT.load(Ordering::Acquire);
                if reply_port == 0 {
                    continue 'msg_loop;
                }
                let send_err = || {
                    let _ = syscall::send_nb_4(
                        reply_port, FS_READ_REPLY, correlation, 0, 0, 0,
                    );
                };
                if handle >= MAX_OPEN_FILES
                    || !open_files[handle].active
                    || grant_va == 0
                {
                    send_err();
                    continue 'msg_loop;
                }
                let file = &open_files[handle];
                if offset >= file.file_size {
                    let _ = syscall::send_nb_4(
                        reply_port, FS_READ_REPLY, correlation, 0, 0, 0,
                    );
                    continue 'msg_loop;
                }

                let avail = file.file_size - offset;
                let to_read = length.min(avail);
                let cluster_size = layout.sectors_per_cluster * 512;
                let target_cluster_idx = offset / cluster_size;
                let offset_in_cluster = offset % cluster_size;

                let cluster = match walk_chain(
                    fat_va,
                    fb,
                    file.first_cluster,
                    target_cluster_idx,
                    variant,
                ) {
                    Some(c) => c,
                    None => {
                        send_err();
                        continue 'msg_loop;
                    }
                };

                let sector_in_cluster = offset_in_cluster / 512;
                let offset_in_sector = offset_in_cluster % 512;
                let sector = layout.data_start
                    + (cluster - 2) * layout.sectors_per_cluster
                    + sector_in_cluster;

                let mut sec = [0u8; 512];
                if !blk.read_sector(sector, &mut sec) {
                    send_err();
                    continue 'msg_loop;
                }

                let bytes_in_sector = (512 - offset_in_sector).min(to_read);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        sec[offset_in_sector as usize..].as_ptr(),
                        grant_va as *mut u8,
                        bytes_in_sector as usize,
                    );
                }
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                #[cfg(target_arch = "x86_64")]
                unsafe { core::arch::asm!("mfence"); }
                let _ = syscall::send_nb_4(
                    reply_port,
                    FS_READ_REPLY,
                    correlation,
                    bytes_in_sector as u64,
                    0,
                    0,
                );
            }

            // ---------------------------------------------------------------
            // FS_READ
            // ---------------------------------------------------------------
            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1] as u32;
                let length = (msg.data[2] & 0xFFFF_FFFF) as u32;
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
                let cluster_size = layout.sectors_per_cluster * 512;
                let target_cluster_idx = offset / cluster_size;
                let offset_in_cluster = offset % cluster_size;

                let cluster = match walk_chain(
                    fat_va,
                    fb,
                    file.first_cluster,
                    target_cluster_idx,
                    variant,
                ) {
                    Some(c) => c,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue 'msg_loop;
                    }
                };

                let sector_in_cluster = offset_in_cluster / 512;
                let offset_in_sector = offset_in_cluster % 512;
                let sector = layout.data_start
                    + (cluster - 2) * layout.sectors_per_cluster
                    + sector_in_cluster;

                let mut sec = [0u8; 512];
                if !blk.read_sector(sector, &mut sec) {
                    let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                    continue;
                }

                let bytes_in_sector = (512 - offset_in_sector).min(to_read);
                if grant_va != 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            sec[offset_in_sector as usize..].as_ptr(),
                            grant_va as *mut u8,
                            bytes_in_sector as usize,
                        );
                    }
                    let _ = syscall::reply(FS_READ_OK, bytes_in_sector as u64, 0, 0, 0, 0);
                } else {
                    let il = (bytes_in_sector as usize).min(MAX_INLINE);
                    let packed = pack_inline_data(
                        &sec[offset_in_sector as usize..(offset_in_sector as usize + il)],
                    );
                    let _ =
                        syscall::reply(FS_READ_OK, il as u64, packed[0], packed[1], packed[2], 0);
                }
            }

            // ---------------------------------------------------------------
            // FS_READDIR
            // ---------------------------------------------------------------
            FS_READDIR => {
                // VFS sends: data[0..1]=path, data[2]=path_len, data[3]=start.
                // Old direct callers: data[0]=start, data[1..3]=0.
                let path_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let (dir, start_offset) = if path_len > 0 && path_len < 128 {
                    let (pb, pl) = unpack_name_short(msg.data[0], msg.data[1], path_len);
                    let d = resolve_dir(&pb, pl, &layout, fat_va, fb, &blk)
                        .unwrap_or(root_dir(&layout));
                    (d, msg.data[3] as u32)
                } else {
                    let start =
                        if msg.data[3] != 0 { msg.data[3] } else { msg.data[0] };
                    (root_dir(&layout), start as u32)
                };

                if let Some((entry, next)) =
                    dir_iter(dir, start_offset, &layout, fat_va, fb, &blk)
                {
                    // Build display name: prefer LFN, else formatted 8.3.
                    let mut display = [0u8; 16];
                    let dlen;
                    if entry.name_long_len > 0 {
                        dlen = (entry.name_long_len as usize).min(16);
                        display[..dlen].copy_from_slice(&entry.name_long[..dlen]);
                    } else {
                        let mut tmp = [0u8; 13];
                        let n = from_8_3(&entry.name_short, &mut tmp);
                        dlen = n.min(16);
                        display[..dlen].copy_from_slice(&tmp[..dlen]);
                    }
                    let mut name_lo = 0u64;
                    let mut name_hi = 0u64;
                    for i in 0..dlen.min(8) {
                        name_lo |= (display[i] as u64) << (i * 8);
                    }
                    for i in 8..dlen.min(16) {
                        name_hi |= (display[i] as u64) << ((i - 8) * 8);
                    }
                    let _ = syscall::reply(
                        FS_READDIR_OK,
                        entry.file_size as u64,
                        name_lo,
                        name_hi,
                        next as u64,
                        0,
                    );
                } else {
                    let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                }
            }

            // ---------------------------------------------------------------
            // FS_STAT / FS_STAT_LONG
            // ---------------------------------------------------------------
            FS_STAT | FS_STAT_LONG => {
                let (path_buf, path_len) = if msg.tag == FS_STAT_LONG {
                    let plen = (msg.data[0] & 0xFFFF) as usize;
                    let mut buf = [0u8; 128];
                    let n = plen.min(128);
                    for i in 0..n {
                        buf[i] = unsafe { *((FS_SCRATCH_VA + i) as *const u8) };
                    }
                    (buf, n)
                } else {
                    let plen = (msg.data[2] & 0xFFFF_FFFF) as usize;
                    unpack_name_short(msg.data[0], msg.data[1], plen)
                };

                let result = if path_len == 0 {
                    // Stat root directory.
                    let mut e = DirEntry::empty();
                    e.attrs = 0x10;
                    Some(e)
                } else if let Some((pdir, ns, nl)) =
                    resolve_parent(&path_buf, path_len, &layout, fat_va, fb, &blk)
                {
                    dir_find(pdir, &path_buf[ns..], nl, &layout, fat_va, fb, &blk)
                } else {
                    None
                };

                if let Some(e) = result {
                    let ftype: u64 = if e.is_dir() { 1 } else { 0 };
                    let mode: u64 = if e.is_dir() { 0o755 } else { 0o644 };
                    let _ = syscall::reply(
                        FS_STAT_OK,
                        e.file_size as u64,
                        ftype | (mode << 16),
                        0,
                        0,
                        0,
                    );
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            // ---------------------------------------------------------------
            // FS_CREATE
            // ---------------------------------------------------------------
            FS_CREATE => {
                let plen = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let (path_buf, path_len) = unpack_name_short(msg.data[0], msg.data[1], plen);

                let (parent_dir, ns, nl) = match resolve_parent(
                    &path_buf, path_len, &layout, fat_va, fb, &blk,
                ) {
                    Some(x) => x,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                        continue;
                    }
                };
                let name = &path_buf[ns..ns + nl];

                let mut name83 = [0u8; 11];
                let mut lfn_ents = [[0u8; 32]; 20];
                let lfn_count;
                if name_fits_8_3(name, nl) {
                    to_8_3(name, &mut name83);
                    lfn_count = 0;
                } else {
                    generate_short_name(name, nl, &mut name83);
                    lfn_count = build_lfn_entries(name, nl, lfn_checksum(&name83), &mut lfn_ents);
                }

                let slots = lfn_count as u32 + 1;
                let start_idx =
                    match dir_find_free_run(parent_dir, slots, &layout, fat_va, fb, &blk) {
                        Some(s) => s,
                        None => {
                            let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                            continue;
                        }
                    };

                let first_cluster =
                    match alloc_cluster(fat_va, fb, layout.total_clusters, variant) {
                        Some(c) => c,
                        None => {
                            let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                            continue;
                        }
                    };

                // Write LFN entries (highest sequence first on disk).
                for i in (0..lfn_count).rev() {
                    let eidx = start_idx + (lfn_count - 1 - i) as u32;
                    if let Some((s, o)) = dir_entry_addr(parent_dir, eidx, &layout, fat_va, fb) {
                        write_raw_entry(&blk, s, o, &lfn_ents[i]);
                    }
                }
                // Write 8.3 entry.
                let eidx83 = start_idx + lfn_count as u32;
                let (ds, do_) =
                    match dir_entry_addr(parent_dir, eidx83, &layout, fat_va, fb) {
                        Some(x) => x,
                        None => {
                            let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                            continue;
                        }
                    };
                write_dir_entry_83(&blk, ds, do_, &name83, 0x20, first_cluster, 0);

                // Allocate handle.
                let mut handle = u64::MAX;
                for (i, f) in open_files.iter_mut().enumerate() {
                    if !f.active {
                        f.active = true;
                        f.writable = true;
                        f.first_cluster = first_cluster;
                        f.file_size = 0;
                        f.dir_sector = ds;
                        f.dir_offset = do_ as u16;
                        f.last_cluster = first_cluster;
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

            // ---------------------------------------------------------------
            // FS_WRITE
            // ---------------------------------------------------------------
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

                let cluster_size = (layout.sectors_per_cluster * 512) as usize;
                let mut written = 0usize;
                let file = &mut open_files[handle];

                while written < length {
                    let file_offset = file.file_size as usize;
                    let offset_in_cluster = file_offset % cluster_size;

                    if file_offset > 0 && offset_in_cluster == 0 {
                        let new_c = match alloc_cluster(fat_va, fb, layout.total_clusters, variant)
                        {
                            Some(c) => c,
                            None => break,
                        };
                        fat_write(fat_va, fb, file.last_cluster, new_c, variant);
                        file.last_cluster = new_c;
                    }

                    let sector_in_cluster = (offset_in_cluster / 512) as u32;
                    let offset_in_sector = offset_in_cluster % 512;
                    let sector = layout.data_start
                        + (file.last_cluster - 2) * layout.sectors_per_cluster
                        + sector_in_cluster;

                    let space = 512 - offset_in_sector;
                    let remaining = length - written;
                    let to_write = remaining.min(space);

                    let mut sec = [0u8; 512];
                    if offset_in_sector != 0 || to_write < 512 {
                        blk.read_sector(sector, &mut sec);
                    }
                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (grant_va + written) as *const u8,
                                sec[offset_in_sector..].as_mut_ptr(),
                                to_write,
                            );
                        }
                    }
                    if !blk.write_sector(sector, &sec) {
                        break;
                    }
                    file.file_size += to_write as u32;
                    written += to_write;
                }
                let _ = syscall::reply(FS_WRITE_OK, written as u64, 0, 0, 0, 0);
            }

            // ---------------------------------------------------------------
            // FS_CLOSE
            // ---------------------------------------------------------------
            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN_FILES && open_files[handle].active {
                    if open_files[handle].writable {
                        flush_fat(&blk, fat_va, layout.fat_start, fat_sectors_loaded);
                        let f = &open_files[handle];
                        let mut sec = [0u8; 512];
                        if blk.read_sector(f.dir_sector, &mut sec) {
                            let off = f.dir_offset as usize;
                            write_u16(&mut sec, off + 26, f.first_cluster as u16);
                            if variant == FatVariant::Fat32 {
                                write_u16(&mut sec, off + 20, (f.first_cluster >> 16) as u16);
                            }
                            write_u32(&mut sec, off + 28, f.file_size);
                            blk.write_sector(f.dir_sector, &sec);
                        }
                    }
                    open_files[handle].active = false;
                }
                let _ = syscall::reply(FS_CLOSE_OK, 0, 0, 0, 0, 0);
            }

            // ---------------------------------------------------------------
            // FS_DELETE
            // ---------------------------------------------------------------
            FS_DELETE => {
                let plen = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let (path_buf, path_len) = unpack_name_short(msg.data[0], msg.data[1], plen);

                let entry = if let Some((pdir, ns, nl)) =
                    resolve_parent(&path_buf, path_len, &layout, fat_va, fb, &blk)
                {
                    dir_find(pdir, &path_buf[ns..], nl, &layout, fat_va, fb, &blk)
                } else {
                    None
                };

                if let Some(e) = entry {
                    // Close open handles to this file.
                    for f in open_files.iter_mut() {
                        if f.active && f.first_cluster == e.first_cluster {
                            f.active = false;
                        }
                    }
                    // Mark directory entry deleted.
                    let mut sec = [0u8; 512];
                    if blk.read_sector(e.sector, &mut sec) {
                        sec[e.offset as usize] = 0xE5;
                        blk.write_sector(e.sector, &sec);
                    }
                    // Free FAT chain.
                    let mut c = e.first_cluster;
                    while c >= 2 && !is_eoc(c, variant) {
                        let next = fat_read(fat_va, fb, c, variant);
                        fat_write(fat_va, fb, c, 0, variant);
                        c = next;
                    }
                    flush_fat(&blk, fat_va, layout.fat_start, fat_sectors_loaded);
                    let _ = syscall::reply(FS_DELETE_OK, 0, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            // ---------------------------------------------------------------
            // FS_MKDIR
            // ---------------------------------------------------------------
            FS_MKDIR => {
                let plen = (msg.data[2] & 0xFFFF) as usize;
                let (path_buf, path_len) = unpack_name_short(msg.data[0], msg.data[1], plen);

                let (parent_dir, ns, nl) = match resolve_parent(
                    &path_buf, path_len, &layout, fat_va, fb, &blk,
                ) {
                    Some(x) => x,
                    None => {
                        let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                        continue;
                    }
                };
                let name = &path_buf[ns..ns + nl];

                let mut name83 = [0u8; 11];
                let mut lfn_ents = [[0u8; 32]; 20];
                let lfn_count;
                if name_fits_8_3(name, nl) {
                    to_8_3(name, &mut name83);
                    lfn_count = 0;
                } else {
                    generate_short_name(name, nl, &mut name83);
                    lfn_count = build_lfn_entries(name, nl, lfn_checksum(&name83), &mut lfn_ents);
                }

                let slots = lfn_count as u32 + 1;
                let start_idx =
                    match dir_find_free_run(parent_dir, slots, &layout, fat_va, fb, &blk) {
                        Some(s) => s,
                        None => {
                            let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                            continue;
                        }
                    };

                let dir_cluster =
                    match alloc_cluster(fat_va, fb, layout.total_clusters, variant) {
                        Some(c) => c,
                        None => {
                            let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                            continue;
                        }
                    };

                // Write LFN entries.
                for i in (0..lfn_count).rev() {
                    let eidx = start_idx + (lfn_count - 1 - i) as u32;
                    if let Some((s, o)) = dir_entry_addr(parent_dir, eidx, &layout, fat_va, fb) {
                        write_raw_entry(&blk, s, o, &lfn_ents[i]);
                    }
                }
                // Write 8.3 entry with directory attribute.
                let eidx83 = start_idx + lfn_count as u32;
                if let Some((ds, do_)) =
                    dir_entry_addr(parent_dir, eidx83, &layout, fat_va, fb)
                {
                    write_dir_entry_83(&blk, ds, do_, &name83, 0x10, dir_cluster, 0);
                }

                // Initialise "." and ".." in the new directory.
                let parent_cluster = match parent_dir {
                    DirLoc::FixedRoot => 0,
                    DirLoc::Cluster(c) => c,
                };
                init_dir_cluster(&blk, dir_cluster, parent_cluster, &layout);

                flush_fat(&blk, fat_va, layout.fat_start, fat_sectors_loaded);
                let _ = syscall::reply(FS_MKDIR_OK, 0, 0, 0, 0, 0);
            }

            // ---------------------------------------------------------------
            // FS_UNLINK — alias for FS_DELETE (works on files and empty dirs)
            // ---------------------------------------------------------------
            0x2A20 => {
                let plen = (msg.data[2] & 0xFFFF) as usize;
                let (path_buf, path_len) = unpack_name_short(msg.data[0], msg.data[1], plen);

                let entry = if let Some((pdir, ns, nl)) =
                    resolve_parent(&path_buf, path_len, &layout, fat_va, fb, &blk)
                {
                    dir_find(pdir, &path_buf[ns..], nl, &layout, fat_va, fb, &blk)
                } else {
                    None
                };

                if let Some(e) = entry {
                    let mut sec = [0u8; 512];
                    if blk.read_sector(e.sector, &mut sec) {
                        sec[e.offset as usize] = 0xE5;
                        blk.write_sector(e.sector, &sec);
                    }
                    let mut c = e.first_cluster;
                    while c >= 2 && !is_eoc(c, variant) {
                        let next = fat_read(fat_va, fb, c, variant);
                        fat_write(fat_va, fb, c, 0, variant);
                        c = next;
                    }
                    flush_fat(&blk, fat_va, layout.fat_start, fat_sectors_loaded);
                    let _ = syscall::reply(FS_UNLINK_OK, 0, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
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
