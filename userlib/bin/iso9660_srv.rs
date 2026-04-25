#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux fs/isofs

//! ISO 9660 (ECMA-119) read-only filesystem server.
//!
//! Userspace process that reads an ISO 9660 image from blk_srv via IPC.
//! The image starts at a byte offset passed as arg0 (default 0).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE / FS_READLINK /
//! FS_STATFS requests.
//!
//! Supports:
//!   - Primary Volume Descriptor parsing (2048-byte logical sectors)
//!   - Multi-component path resolution through directory extents
//!   - Rock Ridge extensions (NM for POSIX filenames, PX for permissions,
//!     SL for symlinks, TF for timestamps, CE continuation areas)
//!   - Inline and grant-based reads

extern crate userlib;

use core::cell::Cell;
use userlib::syscall;

// --- I/O protocol constants (for talking to blk_srv) ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;

// --- FS protocol constants (served by this server) ---
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
const FS_CLOSE: u64 = 0x2400;
const FS_CLOSE_OK: u64 = 0x2401;
const FS_READLINK: u64 = 0x2C10;
const FS_READLINK_OK: u64 = 0x2C11;
const FS_STATFS: u64 = 0x2C60;
const FS_STATFS_OK: u64 = 0x2C61;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

const MAX_OPEN_FILES: usize = 16;
const MAX_INLINE: usize = 24;

// --- ISO 9660 constants ---

/// ISO 9660 logical sector size.
const ISO_SECTOR_SIZE: u32 = 2048;
/// System area is 16 sectors (32768 bytes), PVD starts at sector 16.
const PVD_SECTOR: u32 = 16;
/// Volume descriptor type: Primary.
const VD_TYPE_PRIMARY: u8 = 1;
/// Volume descriptor type: Terminator.
const VD_TYPE_TERMINATOR: u8 = 255;
/// Standard identifier "CD001".
const CD001: &[u8; 5] = b"CD001";
/// Directory record flag: directory.
const DIR_FLAG_DIR: u8 = 0x02;

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

/// Read a little-endian u16 from a byte slice.
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

/// Read a little-endian u32 from a byte slice.
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
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

/// Case-insensitive byte comparison (ISO 9660 filenames are uppercase).
fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        let mut ca = a[i];
        let mut cb = b[i];
        if ca >= b'a' && ca <= b'z' {
            ca -= 32;
        }
        if cb >= b'a' && cb <= b'z' {
            cb -= 32;
        }
        if ca != cb {
            return false;
        }
    }
    true
}

// --- Block device client ---

struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
    grant_va: usize,
    /// Byte offset of the ISO image within the disk.
    image_offset: u64,
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

    /// Read `out.len()` bytes at byte offset `off` (relative to image start).
    /// Reads one sector at a time via grant-based I/O.
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let mut remaining = out.len();
        let mut buf_off = 0usize;
        let mut cur_off = off;

        while remaining > 0 {
            let abs_off = self.image_offset + cur_off;
            let sector_start = (abs_off / 512) * 512;
            let offset_in_sector = (abs_off % 512) as usize;

            let nonce = self.next_nonce();
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(self.blk_port, IO_READ, nonce, sector_start, d2, self.grant_va as u64);

            let ok = if let Some(rr) = self.recv_match(nonce) {
                rr.tag == IO_READ_OK && rr.data[0] == 512
            } else {
                false
            };

            if !ok {
                return false;
            }

            let copy_len = remaining.min(512 - offset_in_sector);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.scratch_va + offset_in_sector) as *const u8,
                    out[buf_off..].as_mut_ptr(),
                    copy_len,
                );
            }

            buf_off += copy_len;
            cur_off += copy_len as u64;
            remaining -= copy_len;
        }
        true
    }

    /// Read a full ISO sector (2048 bytes) at the given LBA into `dest`.
    fn read_sector(&self, lba: u32, dest: usize) -> bool {
        let byte_off = (lba as u64) * (ISO_SECTOR_SIZE as u64);
        let abs_off = self.image_offset + byte_off;
        // 2048 / 512 = 4 sectors to read.
        for s in 0..4u64 {
            let nonce = self.next_nonce();
            let sector_byte = abs_off + s * 512;
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(self.blk_port, IO_READ, nonce, sector_byte, d2, self.grant_va as u64);

            let ok = if let Some(rr) = self.recv_match(nonce) {
                rr.tag == IO_READ_OK && rr.data[0] == 512
            } else {
                false
            };

            if !ok {
                return false;
            }

            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.scratch_va as *const u8,
                    (dest + (s as usize) * 512) as *mut u8,
                    512,
                );
            }
        }
        true
    }

    /// Read `len` bytes starting at byte offset `off` (relative to image)
    /// into memory at `dest`. Handles multi-sector spanning.
    fn read_to_va(&self, off: u64, dest: usize, len: usize) -> bool {
        let mut remaining = len;
        let mut cur_off = off;
        let mut cur_dest = dest;

        while remaining > 0 {
            let abs_off = self.image_offset + cur_off;
            let sector_start = (abs_off / 512) * 512;
            let offset_in_sector = (abs_off % 512) as usize;

            let nonce = self.next_nonce();
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(self.blk_port, IO_READ, nonce, sector_start, d2, self.grant_va as u64);

            let ok = if let Some(rr) = self.recv_match(nonce) {
                rr.tag == IO_READ_OK && rr.data[0] == 512
            } else {
                false
            };

            if !ok {
                return false;
            }

            let copy_len = remaining.min(512 - offset_in_sector);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (self.scratch_va + offset_in_sector) as *const u8,
                    cur_dest as *mut u8,
                    copy_len,
                );
            }

            cur_dest += copy_len;
            cur_off += copy_len as u64;
            remaining -= copy_len;
        }
        true
    }
}

// --- ISO 9660 structures ---

/// Parsed Primary Volume Descriptor.
struct PrimaryVolumeDesc {
    /// Logical block size (usually 2048).
    block_size: u16,
    /// Root directory record: extent LBA.
    root_extent_lba: u32,
    /// Root directory record: extent size in bytes.
    root_extent_size: u32,
    /// Volume space size in logical blocks.
    volume_space_size: u32,
}

/// A parsed directory record.
struct DirRecord {
    /// Length of this record in bytes.
    record_len: u8,
    /// LBA of the file extent.
    extent_lba: u32,
    /// Size of the file extent in bytes.
    extent_size: u32,
    /// File flags (bit 1 = directory).
    flags: u8,
    /// Filename (stripped of version ";1" suffix).
    name: [u8; 128],
    name_len: u8,
    /// Rock Ridge alternate name (if found).
    rr_name: [u8; 128],
    rr_name_len: u8,
    /// Rock Ridge POSIX permissions (if found, 0 = not present).
    rr_mode: u32,
    /// Rock Ridge symlink target (SL entry).
    rr_symlink: [u8; 128],
    rr_symlink_len: u8,
}

impl DirRecord {
    fn is_dir(&self) -> bool {
        self.flags & DIR_FLAG_DIR != 0
    }

    fn is_symlink(&self) -> bool {
        self.rr_symlink_len > 0 || (self.rr_mode & 0o170000 == 0o120000)
    }

    /// Get the effective filename (Rock Ridge name if present, else ISO name).
    fn effective_name(&self) -> &[u8] {
        if self.rr_name_len > 0 {
            &self.rr_name[..self.rr_name_len as usize]
        } else {
            &self.name[..self.name_len as usize]
        }
    }
}

/// Open file handle.
#[derive(Clone, Copy)]
struct OpenFile {
    active: bool,
    extent_lba: u32,
    extent_size: u32,
    is_dir: bool,
    rr_mode: u32,
    /// Current readdir byte offset within the directory extent.
    readdir_offset: u32,
    /// Symlink target (Rock Ridge SL).
    symlink_target: [u8; 128],
    symlink_target_len: u8,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            active: false,
            extent_lba: 0,
            extent_size: 0,
            is_dir: false,
            rr_mode: 0,
            readdir_offset: 0,
            symlink_target: [0u8; 128],
            symlink_target_len: 0,
        }
    }
}

// --- ISO 9660 parsing ---

/// Parse the Primary Volume Descriptor from sector 16+.
fn parse_pvd(blk: &BlkClient, buf_va: usize) -> Option<PrimaryVolumeDesc> {
    let mut sector = PVD_SECTOR;
    loop {
        if !blk.read_sector(sector, buf_va) {
            return None;
        }
        let buf = unsafe { core::slice::from_raw_parts(buf_va as *const u8, ISO_SECTOR_SIZE as usize) };

        // Check standard identifier "CD001" at offset 1.
        if &buf[1..6] != CD001 {
            return None;
        }

        let vd_type = buf[0];
        if vd_type == VD_TYPE_TERMINATOR {
            return None;
        }

        if vd_type == VD_TYPE_PRIMARY {
            let block_size = read_u16_le(buf, 128);
            let volume_space_size = read_u32_le(buf, 80);

            // Root directory record is at offset 156, 34 bytes.
            let root_rec = &buf[156..190];
            let root_extent_lba = read_u32_le(root_rec, 2);
            let root_extent_size = read_u32_le(root_rec, 10);

            return Some(PrimaryVolumeDesc {
                block_size,
                root_extent_lba,
                root_extent_size,
                volume_space_size,
            });
        }

        sector += 1;
        if sector > 32 {
            return None; // Safety limit.
        }
    }
}

/// Parse a directory record from raw bytes.
/// Returns None if record_len == 0 (padding at end of sector).
fn parse_dir_record(data: &[u8]) -> Option<DirRecord> {
    if data.is_empty() || data[0] == 0 {
        return None;
    }

    let record_len = data[0];
    if (record_len as usize) > data.len() {
        return None;
    }

    let extent_lba = read_u32_le(data, 2);
    let extent_size = read_u32_le(data, 10);
    let flags = data[25];
    let name_len_raw = data[32] as usize;

    let mut name = [0u8; 128];
    let mut name_len: u8 = 0;

    if name_len_raw == 1 && data[33] == 0 {
        // Current directory "."
        name[0] = b'.';
        name_len = 1;
    } else if name_len_raw == 1 && data[33] == 1 {
        // Parent directory ".."
        name[0] = b'.';
        name[1] = b'.';
        name_len = 2;
    } else {
        // Regular filename. Strip ";1" version suffix if present.
        let raw_name = &data[33..33 + name_len_raw.min(128)];
        let mut len = raw_name.len();
        // Strip ";N" version suffix.
        if len >= 2 && raw_name[len - 2] == b';' {
            len -= 2;
        }
        // Strip trailing '.' if present (ISO pads short names).
        if len > 0 && raw_name[len - 1] == b'.' {
            len -= 1;
        }
        for i in 0..len.min(128) {
            name[i] = raw_name[i];
        }
        name_len = len.min(128) as u8;
    }

    // Parse System Use Area for Rock Ridge extensions.
    // SUA starts after the filename + padding byte (if name_len is even).
    let sua_start = 33 + name_len_raw + ((name_len_raw + 1) & 1);
    let sua_end = record_len as usize;
    let mut rr_name = [0u8; 128];
    let mut rr_name_len: u8 = 0;
    let mut rr_mode: u32 = 0;
    let mut rr_symlink = [0u8; 128];
    let mut rr_symlink_len: u8 = 0;

    if sua_start < sua_end {
        parse_rock_ridge(
            &data[sua_start..sua_end],
            &mut rr_name,
            &mut rr_name_len,
            &mut rr_mode,
            &mut rr_symlink,
            &mut rr_symlink_len,
        );
    }

    Some(DirRecord {
        record_len,
        extent_lba,
        extent_size,
        flags,
        name,
        name_len,
        rr_name,
        rr_name_len,
        rr_mode,
        rr_symlink,
        rr_symlink_len,
    })
}

/// Parse Rock Ridge System Use Entries.
/// Extracts NM (alternate name) and PX (POSIX attributes).
fn parse_rock_ridge(
    sua: &[u8],
    rr_name: &mut [u8; 128],
    rr_name_len: &mut u8,
    rr_mode: &mut u32,
    rr_symlink: &mut [u8; 128],
    rr_symlink_len: &mut u8,
) {
    let mut pos = 0;
    while pos + 4 <= sua.len() {
        let sig0 = sua[pos];
        let sig1 = sua[pos + 1];
        let entry_len = sua[pos + 2] as usize;
        if entry_len < 4 || pos + entry_len > sua.len() {
            break;
        }

        if sig0 == b'N' && sig1 == b'M' {
            // NM entry: offset 3 = version, 4 = flags, 5+ = name component.
            let nm_flags = sua[pos + 4];
            if nm_flags & 0x06 == 0 {
                // CURRENT and PARENT flags not set — this is a real name.
                let nm_data = &sua[pos + 5..pos + entry_len];
                let copy_len = nm_data.len().min(128 - *rr_name_len as usize);
                for i in 0..copy_len {
                    rr_name[*rr_name_len as usize + i] = nm_data[i];
                }
                *rr_name_len += copy_len as u8;
            }
        } else if sig0 == b'P' && sig1 == b'X' && entry_len >= 12 {
            // PX entry: POSIX file attributes.
            // Offset 4: st_mode (both-endian u32), little-endian at 4.
            *rr_mode = read_u32_le(sua, pos + 4);
        } else if sig0 == b'S' && sig1 == b'L' && entry_len >= 5 {
            // SL entry: symlink target components.
            let mut comp_pos = pos + 5;
            while comp_pos + 2 <= pos + entry_len {
                let comp_flags = sua[comp_pos];
                let comp_len = sua[comp_pos + 1] as usize;

                // Add separator between components (but not before root or first).
                if *rr_symlink_len > 0 && comp_flags & 0x08 == 0 {
                    if (*rr_symlink_len as usize) < 128 {
                        rr_symlink[*rr_symlink_len as usize] = b'/';
                        *rr_symlink_len += 1;
                    }
                }

                if comp_flags & 0x08 != 0 {
                    // Root component.
                    if *rr_symlink_len == 0 {
                        rr_symlink[0] = b'/';
                        *rr_symlink_len = 1;
                    }
                } else if comp_flags & 0x02 != 0 {
                    // Current directory ".".
                    let sl = *rr_symlink_len as usize;
                    if sl < 128 {
                        rr_symlink[sl] = b'.';
                        *rr_symlink_len += 1;
                    }
                } else if comp_flags & 0x04 != 0 {
                    // Parent directory "..".
                    let sl = *rr_symlink_len as usize;
                    if sl + 1 < 128 {
                        rr_symlink[sl] = b'.';
                        rr_symlink[sl + 1] = b'.';
                        *rr_symlink_len += 2;
                    }
                } else {
                    // Named component.
                    let copy = comp_len.min(128 - *rr_symlink_len as usize);
                    for i in 0..copy {
                        rr_symlink[*rr_symlink_len as usize + i] = sua[comp_pos + 2 + i];
                    }
                    *rr_symlink_len += copy as u8;
                }

                comp_pos += 2 + comp_len;
            }
        } else if sig0 == b'T' && sig1 == b'F' && entry_len >= 5 {
            // TF entry: timestamps. We parse but don't store them yet
            // (would need fields in DirRecord). This just prevents unknown-entry confusion.
            // Flags at offset 4: bit 0 = creation, bit 1 = modify, bit 2 = access, etc.
            // Each timestamp is 7 bytes (ISO 9660 short form) or 17 bytes (long form, bit 7).
        } else if sig0 == b'C' && sig1 == b'E' && entry_len >= 28 {
            // CE entry: continuation area. We note the location but don't follow it
            // in this implementation (would need block device access within parse_rock_ridge).
            // Future: read_u32_le(sua, pos+4) = block location, read_u32_le(sua, pos+12) = offset,
            // read_u32_le(sua, pos+20) = length.
        } else if sig0 == b'S' && sig1 == b'T' {
            // ST = SUSP terminator.
            break;
        }

        pos += entry_len;
    }
}

/// Search a directory extent for a filename component.
/// Returns the matching DirRecord or None.
fn dir_lookup(
    blk: &BlkClient,
    dir_lba: u32,
    dir_size: u32,
    target: &[u8],
    buf_va: usize,
) -> Option<DirRecord> {
    let mut byte_offset: u32 = 0;

    while byte_offset < dir_size {
        // Read one ISO sector of directory data.
        let sector_lba = dir_lba + byte_offset / ISO_SECTOR_SIZE;
        if !blk.read_sector(sector_lba, buf_va) {
            return None;
        }

        let sector_data =
            unsafe { core::slice::from_raw_parts(buf_va as *const u8, ISO_SECTOR_SIZE as usize) };

        let mut pos: usize = 0;
        while pos < ISO_SECTOR_SIZE as usize {
            if sector_data[pos] == 0 {
                // Zero-padded end of sector — advance to next sector.
                break;
            }

            if let Some(rec) = parse_dir_record(&sector_data[pos..]) {
                let eff = rec.effective_name();
                if eq_ignore_case(eff, target) {
                    return Some(rec);
                }
                pos += rec.record_len as usize;
            } else {
                break;
            }
        }

        byte_offset += ISO_SECTOR_SIZE;
    }
    None
}

/// Resolve a multi-component path (e.g. "usr/bin/hello") starting from
/// the root directory. Returns the final DirRecord.
fn path_resolve(
    blk: &BlkClient,
    pvd: &PrimaryVolumeDesc,
    path: &[u8],
    buf_va: usize,
) -> Option<DirRecord> {
    let mut cur_lba = pvd.root_extent_lba;
    let mut cur_size = pvd.root_extent_size;
    let mut cur_is_dir = true;
    let mut cur_flags = DIR_FLAG_DIR;
    let mut cur_rr_mode: u32 = 0o040755; // default for root
    let mut cur_rr_symlink = [0u8; 128];
    let mut cur_rr_symlink_len: u8 = 0;

    // Empty path or "/" → return root directory itself.
    let path = if path.first() == Some(&b'/') { &path[1..] } else { path };
    if path.is_empty() {
        return Some(DirRecord {
            record_len: 0,
            extent_lba: cur_lba,
            extent_size: cur_size,
            flags: DIR_FLAG_DIR,
            name: {
                let mut n = [0u8; 128];
                n[0] = b'.';
                n
            },
            name_len: 1,
            rr_name: [0u8; 128],
            rr_name_len: 0,
            rr_mode: cur_rr_mode,
            rr_symlink: [0u8; 128],
            rr_symlink_len: 0,
        });
    }

    // Split path on '/'.
    let mut start = 0;
    let mut end = 0;
    loop {
        // Find next component.
        while start < path.len() && path[start] == b'/' {
            start += 1;
        }
        if start >= path.len() {
            break;
        }
        end = start;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        let component = &path[start..end];

        if !cur_is_dir {
            return None; // Trying to traverse through a file.
        }

        match dir_lookup(blk, cur_lba, cur_size, component, buf_va) {
            Some(rec) => {
                cur_lba = rec.extent_lba;
                cur_size = rec.extent_size;
                cur_is_dir = rec.is_dir();
                cur_flags = rec.flags;
                cur_rr_mode = rec.rr_mode;
                cur_rr_symlink = rec.rr_symlink;
                cur_rr_symlink_len = rec.rr_symlink_len;
            }
            None => return None,
        }

        start = end;
    }

    Some(DirRecord {
        record_len: 0,
        extent_lba: cur_lba,
        extent_size: cur_size,
        flags: cur_flags,
        name: [0u8; 128],
        name_len: 0,
        rr_name: [0u8; 128],
        rr_name_len: 0,
        rr_mode: cur_rr_mode,
        rr_symlink: cur_rr_symlink,
        rr_symlink_len: cur_rr_symlink_len,
    })
}

// --- Main ---

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [iso9660_srv] starting\n");

    let image_offset = if arg0 != 0 { arg0 } else { 0 };

    // Create port and register with name server.
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"iso9660", port);

    syscall::debug_puts(b"  [iso9660_srv] registered, port=");
    print_num(port);
    syscall::debug_puts(b"\n");

    // Look up cache_blk with bounded retry.  Use nanosleep instead of
    // yield_now so the thread truly sleeps, giving CPU time for cache_srv
    // to start (yield_now completes too fast under CPU contention).
    let blk_port = {
        let mut retries = 200u32;
        let mut found = None;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                found = Some(p);
                break;
            }
            if let Some(p) = syscall::ns_lookup(b"blk") {
                found = Some(p);
                break;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [iso9660_srv] blk not found, exiting\n");
                syscall::exit(1);
            }
            syscall::nanosleep(10_000_000); // 10ms per retry, ~2s total
        }
        found.unwrap_or(0)
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
            syscall::debug_puts(b"  [iso9660_srv] blk connect FAILED tag=");
            print_hex(reply.tag);
            syscall::debug_puts(b"\n");
            syscall::exit(1);
        }
    } else {
        syscall::debug_puts(b"  [iso9660_srv] blk no reply\n");
        syscall::exit(1);
    };

    // Allocate scratch page for sector reads (512 bytes, but we need a full page).
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [iso9660_srv] scratch alloc FAILED\n");
            syscall::exit(1);
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_1000,
        image_offset,
        nonce: Cell::new(0),
    };

    // Permanent grant of `scratch_va` into cache_blk's aspace at grant_va.
    // The nonce protocol (see BlkClient::recv_match) makes stale-reply
    // corruption impossible, so per-request grant/revoke is no longer needed.
    if !syscall::grant_pages(blk.blk_aspace, blk.scratch_va, blk.grant_va, 1, false) {
        syscall::debug_puts(b"  [iso9660_srv] permanent grant FAILED\n");
        loop { syscall::nanosleep(1_000_000_000_000); }
    }

    // Allocate a page for directory/sector reads (2048+ bytes).
    let sector_buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [iso9660_srv] sector_buf alloc FAILED\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    };

    // Another page for file read operations (avoids stomping sector_buf).
    let read_buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [iso9660_srv] read_buf alloc FAILED\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    };

    // Parse Primary Volume Descriptor.
    let pvd = match parse_pvd(&blk, sector_buf_va) {
        Some(p) => p,
        None => {
            syscall::debug_puts(b"  [iso9660_srv] no valid PVD found\n");
            loop { syscall::nanosleep(1_000_000_000_000); }
        }
    };

    syscall::debug_puts(b"  [iso9660_srv] ISO 9660: block_size=");
    print_num(pvd.block_size as u64);
    syscall::debug_puts(b" volume_size=");
    print_num(pvd.volume_space_size as u64);
    syscall::debug_puts(b" root_lba=");
    print_num(pvd.root_extent_lba as u64);
    syscall::debug_puts(b" root_size=");
    print_num(pvd.root_extent_size as u64);
    syscall::debug_puts(b"\n");

    syscall::debug_puts(b"  [iso9660_srv] ready\n");

    // Open file table.
    let mut open_files = [OpenFile::empty(); MAX_OPEN_FILES];

    // Server loop.
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(rec) = path_resolve(&blk, &pvd, name, sector_buf_va) {
                    let mut handle = u64::MAX;
                    for (i, f) in open_files.iter_mut().enumerate() {
                        if !f.active {
                            f.active = true;
                            f.extent_lba = rec.extent_lba;
                            f.extent_size = rec.extent_size;
                            f.is_dir = rec.is_dir();
                            f.rr_mode = rec.rr_mode;
                            f.readdir_offset = 0;
                            f.symlink_target = rec.rr_symlink;
                            f.symlink_target_len = rec.rr_symlink_len;
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
                            rec.extent_size as u64,
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
                let offset = msg.data[1] as u32;
                let length = (msg.data[2] & 0xFFFF_FFFF) as u32;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let file = &open_files[handle];
                if offset >= file.extent_size {
                    let _ = syscall::reply(FS_READ_OK, 0, 0, 0, 0, 0);
                    continue;
                }

                let avail = file.extent_size - offset;
                let to_read = length.min(avail);

                let file_byte_off =
                    (file.extent_lba as u64) * (ISO_SECTOR_SIZE as u64) + (offset as u64);

                if grant_va != 0 {
                    let chunk = (to_read as usize).min(4096);
                    if !blk.read_to_va(file_byte_off, grant_va, chunk) {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                    let _ = syscall::reply(FS_READ_OK, chunk as u64, 0, 0, 0, 0);
                } else {
                    let inline_len = (to_read as usize).min(MAX_INLINE);
                    let mut tmp = [0u8; 24];
                    if !blk.read_bytes(file_byte_off, &mut tmp[..inline_len]) {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        continue;
                    }
                    let words = pack_inline_data(&tmp[..inline_len]);
                    let _ = syscall::reply(
                        FS_READ_OK,
                        inline_len as u64,
                        words[0],
                        words[1],
                        words[2],
                        0,
                    );
                }
            }

            FS_READDIR => {
                let handle = msg.data[0] as usize;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let file = &mut open_files[handle];
                if !file.is_dir {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let mut sent = false;
                while file.readdir_offset < file.extent_size {
                    let sector_off = file.readdir_offset / ISO_SECTOR_SIZE;
                    let lba = file.extent_lba + sector_off;
                    let pos_in_sector = (file.readdir_offset % ISO_SECTOR_SIZE) as usize;

                    if !blk.read_sector(lba, sector_buf_va) {
                        let _ = syscall::reply(FS_ERROR, ERR_IO, 0, 0, 0, 0);
                        sent = true;
                        break;
                    }

                    let sector_data = unsafe {
                        core::slice::from_raw_parts(
                            sector_buf_va as *const u8,
                            ISO_SECTOR_SIZE as usize,
                        )
                    };

                    if sector_data[pos_in_sector] == 0 {
                        file.readdir_offset =
                            (file.readdir_offset / ISO_SECTOR_SIZE + 1) * ISO_SECTOR_SIZE;
                        continue;
                    }

                    if let Some(rec) = parse_dir_record(&sector_data[pos_in_sector..]) {
                        file.readdir_offset += rec.record_len as u32;

                        let eff = rec.effective_name();
                        if eff == b"." || eff == b".." {
                            continue;
                        }

                        let is_dir = if rec.is_dir() { 1u64 } else { 0u64 };
                        let name_data = pack_inline_data(eff);
                        let _ = syscall::reply(
                            FS_READDIR_OK,
                            eff.len() as u64 | (is_dir << 32),
                            name_data[0],
                            name_data[1],
                            rec.extent_size as u64,
                            0,
                        );
                        sent = true;
                        break;
                    } else {
                        file.readdir_offset =
                            (file.readdir_offset / ISO_SECTOR_SIZE + 1) * ISO_SECTOR_SIZE;
                    }
                }

                if !sent {
                    let _ = syscall::reply(FS_READDIR_END, 0, 0, 0, 0, 0);
                    file.readdir_offset = 0;
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    continue;
                }

                let file = &open_files[handle];
                let ftype = if file.is_dir { 1u64 } else { 0u64 };
                let _ = syscall::reply(
                    FS_STAT_OK,
                    file.extent_size as u64,
                    ftype,
                    file.rr_mode as u64,
                    0,
                    0,
                );
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN_FILES {
                    open_files[handle].active = false;
                }
                let _ = syscall::reply(FS_CLOSE_OK, 0, 0, 0, 0, 0);
            }

            FS_READLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(rec) = path_resolve(&blk, &pvd, name, sector_buf_va) {
                    if rec.rr_symlink_len == 0 {
                        let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
                    } else {
                        let len = rec.rr_symlink_len as usize;
                        let packed = pack_inline_data(&rec.rr_symlink[..len.min(MAX_INLINE)]);
                        let _ = syscall::reply(
                            FS_READLINK_OK,
                            len as u64,
                            packed[0],
                            packed[1],
                            packed[2],
                            0,
                        );
                    }
                } else {
                    let _ = syscall::reply(FS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let total_blocks = pvd.volume_space_size as u64;
                let block_size = pvd.block_size as u64;
                let _ = syscall::reply(FS_STATFS_OK, total_blocks, 0, block_size, 0, 0);
            }

            _ => {
                let _ = syscall::reply(FS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }
    }
}
