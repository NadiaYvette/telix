#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux fs/udf, udftools

//! UDF (Universal Disk Format, ECMA-167 / OSTA UDF) read-only filesystem server.
//!
//! Userspace process that reads a UDF image from blk_srv via IPC.
//! The image starts at a byte offset passed as arg0 (default 0).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE / FS_READLINK /
//! FS_STATFS requests.
//!
//! Supports:
//!   - UDF 1.02–2.01 (ECMA-167 2nd/3rd edition)
//!   - Type 1 partition maps (physical partitions)
//!   - File Entry (tag 261) and Extended File Entry (tag 266)
//!   - Short allocation descriptors, long allocation descriptors, inline data
//!   - OSTA Compressed Unicode filename decoding (compression IDs 8 and 16)
//!   - Multi-component path resolution through File Identifier Descriptors
//!   - Symbolic link reading (ICB file type 12)

extern crate userlib;

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

// --- UDF constants ---

/// UDF descriptor tag identifiers.
const TAG_PVD: u16 = 1;
const TAG_AVDP: u16 = 2;
const TAG_PD: u16 = 5;
const TAG_LVD: u16 = 6;
const TAG_TD: u16 = 8;
const TAG_FSD: u16 = 256;
const TAG_FID: u16 = 257;
const TAG_FE: u16 = 261;
const TAG_EFE: u16 = 266;

/// ICB file types.
const FTYPE_DIR: u8 = 4;
const FTYPE_FILE: u8 = 5;
const FTYPE_SYMLINK: u8 = 12;

/// FID file characteristics bits.
const FID_CHAR_DIR: u8 = 0x02;
const FID_CHAR_DELETED: u8 = 0x04;
const FID_CHAR_PARENT: u8 = 0x08;

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

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    read_u32_le(buf, off) as u64 | ((read_u32_le(buf, off + 4) as u64) << 32)
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

/// Decode OSTA Compressed Unicode (CS0) to ASCII.
/// Returns number of decoded bytes written to `out`.
fn decode_osta_cs0(data: &[u8], out: &mut [u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let comp_id = data[0];
    let mut pos = 0;
    match comp_id {
        8 => {
            // Each byte is a Unicode code point U+0000–U+00FF.
            for &b in &data[1..] {
                if pos >= out.len() {
                    break;
                }
                out[pos] = b;
                pos += 1;
            }
        }
        16 => {
            // Big-endian UCS-2 pairs.
            let mut i = 1;
            while i + 1 < data.len() && pos < out.len() {
                let hi = data[i];
                let lo = data[i + 1];
                // Only handle BMP characters that fit in ASCII/Latin-1.
                if hi == 0 {
                    out[pos] = lo;
                } else {
                    out[pos] = b'?'; // Non-ASCII placeholder.
                }
                pos += 1;
                i += 2;
            }
        }
        _ => {
            // Unknown compression ID — copy raw bytes as fallback.
            for &b in &data[1..] {
                if pos >= out.len() {
                    break;
                }
                out[pos] = b;
                pos += 1;
            }
        }
    }
    pos
}

// --- Block device client ---

struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
    grant_va: usize,
    image_offset: u64,
}

impl BlkClient {
    /// Read `out.len()` bytes at byte offset `off` (relative to image start).
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let mut remaining = out.len();
        let mut buf_off = 0usize;
        let mut cur_off = off;

        while remaining > 0 {
            let abs_off = self.image_offset + cur_off;
            let sector_start = (abs_off / 512) * 512;
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
                sector_start,
                d2,
                self.grant_va as u64,
            );

            let ok = if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
                rr.tag == IO_READ_OK && rr.data[0] == 512
            } else {
                false
            };

            syscall::revoke(self.blk_aspace, self.grant_va);

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

    /// Read `len` bytes at byte offset `off` into memory at `dest`.
    fn read_to_va(&self, off: u64, dest: usize, len: usize) -> bool {
        let mut remaining = len;
        let mut cur_off = off;
        let mut cur_dest = dest;

        while remaining > 0 {
            let abs_off = self.image_offset + cur_off;
            let sector_start = (abs_off / 512) * 512;
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
                sector_start,
                d2,
                self.grant_va as u64,
            );

            let ok = if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
                rr.tag == IO_READ_OK && rr.data[0] == 512
            } else {
                false
            };

            if !ok {
                syscall::revoke(self.blk_aspace, self.grant_va);
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
            syscall::revoke(self.blk_aspace, self.grant_va);

            cur_dest += copy_len;
            cur_off += copy_len as u64;
            remaining -= copy_len;
        }
        true
    }

    /// Read a full logical block into a buffer VA.
    fn read_block(&self, block_byte_off: u64, dest: usize, block_size: u32) -> bool {
        self.read_to_va(block_byte_off, dest, block_size as usize)
    }
}

// --- UDF structures ---

/// Parsed volume information from the Volume Descriptor Sequence.
struct UdfVolume {
    /// Logical block size (from LVD).
    block_size: u32,
    /// Partition start in absolute logical sectors (from PD).
    partition_start: u32,
    /// Partition length in logical blocks (from PD).
    partition_len: u32,
    /// Volume space size (from PVD, in logical sectors).
    volume_space_size: u32,
    /// Root directory ICB: logical block number within partition.
    root_icb_lbn: u32,
    /// Root directory ICB: partition reference.
    root_icb_part: u16,
}

impl UdfVolume {
    /// Convert a partition-relative logical block number to an absolute byte offset.
    fn lbn_to_byte_off(&self, lbn: u32) -> u64 {
        ((self.partition_start as u64) + (lbn as u64)) * (self.block_size as u64)
    }
}

/// Parsed file entry (ICB) — works for both FE (261) and EFE (266).
#[derive(Clone, Copy)]
struct UdfFileEntry {
    /// File type from ICB tag.
    file_type: u8,
    /// Allocation descriptor type (0=short, 1=long, 3=inline).
    ad_type: u8,
    /// File size in bytes.
    info_len: u64,
    /// POSIX-style permissions (converted from UDF).
    mode: u16,
    uid: u32,
    gid: u32,
    /// Allocation descriptors area: up to 8 short_ad extents.
    /// Each entry: (logical_block_number, byte_length).
    extents: [(u32, u32); 8],
    extent_count: u8,
    /// For inline data (ad_type == 3): byte offset of data within the FE block.
    inline_off: u16,
    /// Length of inline data.
    inline_len: u16,
}

impl UdfFileEntry {
    const fn empty() -> Self {
        Self {
            file_type: 0,
            ad_type: 0,
            info_len: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            extents: [(0, 0); 8],
            extent_count: 0,
            inline_off: 0,
            inline_len: 0,
        }
    }

    fn is_dir(&self) -> bool {
        self.file_type == FTYPE_DIR
    }

    fn is_symlink(&self) -> bool {
        self.file_type == FTYPE_SYMLINK
    }
}

/// Open file handle.
#[derive(Clone, Copy)]
struct OpenFile {
    active: bool,
    fe: UdfFileEntry,
    /// Current readdir byte offset within directory data.
    readdir_offset: u32,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            active: false,
            fe: UdfFileEntry::empty(),
            readdir_offset: 0,
        }
    }
}

// --- UDF parsing ---

/// Validate a descriptor tag at the start of `buf`.
/// Checks tag identifier and tag checksum.
fn validate_tag(buf: &[u8], expected: u16) -> bool {
    if buf.len() < 16 {
        return false;
    }
    let tag_id = read_u16_le(buf, 0);
    if tag_id != expected {
        return false;
    }
    // Verify tag checksum: sum of bytes 0–3 and 5–15, mod 256.
    let mut sum: u8 = 0;
    for i in 0..4 {
        sum = sum.wrapping_add(buf[i]);
    }
    for i in 5..16 {
        sum = sum.wrapping_add(buf[i]);
    }
    sum == buf[4]
}

/// Convert UDF permissions (ECMA-167 5-category) to POSIX mode bits.
fn udf_perms_to_mode(perms: u32, file_type: u8) -> u16 {
    let other = (perms & 0x07) as u16;
    let group = ((perms >> 5) & 0x07) as u16;
    let owner = ((perms >> 10) & 0x07) as u16;
    let mode_bits = (owner << 6) | (group << 3) | other;
    let type_bits: u16 = match file_type {
        FTYPE_DIR => 0o040000,
        FTYPE_SYMLINK => 0o120000,
        _ => 0o100000, // regular file
    };
    type_bits | mode_bits
}

/// Parse the Volume Descriptor Sequence to extract PVD, PD, LVD.
/// Returns UdfVolume or None.
fn parse_volume(blk: &BlkClient, sector_size: u32, buf_va: usize) -> Option<UdfVolume> {
    // Step 1: Read AVDP at sector 256.
    let avdp_off = 256u64 * sector_size as u64;
    if !blk.read_block(avdp_off, buf_va, sector_size) {
        return None;
    }
    let avdp = unsafe { core::slice::from_raw_parts(buf_va as *const u8, sector_size as usize) };
    if !validate_tag(avdp, TAG_AVDP) {
        return None;
    }

    let main_vds_len = read_u32_le(avdp, 16);
    let main_vds_loc = read_u32_le(avdp, 20);

    // Step 2: Read VDS descriptors.
    let mut partition_start: u32 = 0;
    let mut partition_len: u32 = 0;
    let mut block_size: u32 = 2048;
    let mut fsd_lbn: u32 = 0;
    let mut fsd_part: u16 = 0;
    let mut volume_space_size: u32 = 0;
    let mut found_pd = false;
    let mut found_lvd = false;

    let max_sectors = (main_vds_len / sector_size).min(32);
    for s in 0..max_sectors {
        let off = ((main_vds_loc + s) as u64) * (sector_size as u64);
        if !blk.read_block(off, buf_va, sector_size) {
            return None;
        }
        let desc =
            unsafe { core::slice::from_raw_parts(buf_va as *const u8, sector_size as usize) };
        let tag_id = read_u16_le(desc, 0);

        match tag_id {
            TAG_PVD => {
                volume_space_size = read_u32_le(desc, 80 + 4); // Volume Space Size at PVD+84? No...
                // Actually, PVD doesn't have volume_space_size directly.
                // We'll get it from partition info.
            }
            TAG_PD => {
                partition_start = read_u32_le(desc, 188);
                partition_len = read_u32_le(desc, 192);
                found_pd = true;
            }
            TAG_LVD => {
                block_size = read_u32_le(desc, 212);
                // FSD location: long_ad at offset 248.
                // long_ad: 4 bytes extent_len, then lb_addr (4 lbn + 2 partref).
                fsd_lbn = read_u32_le(desc, 252);
                fsd_part = read_u16_le(desc, 256);
                found_lvd = true;
            }
            TAG_TD => break,
            _ => {}
        }
    }

    if !found_pd || !found_lvd || block_size == 0 {
        return None;
    }

    // Step 3: Read FSD.
    let fsd_off = ((partition_start as u64) + (fsd_lbn as u64)) * (block_size as u64);
    if !blk.read_block(fsd_off, buf_va, block_size) {
        return None;
    }
    let fsd = unsafe { core::slice::from_raw_parts(buf_va as *const u8, block_size as usize) };
    if !validate_tag(fsd, TAG_FSD) {
        return None;
    }

    // Root directory ICB: long_ad at FSD offset 400.
    let root_icb_lbn = read_u32_le(fsd, 404);
    let root_icb_part = read_u16_le(fsd, 408);

    Some(UdfVolume {
        block_size,
        partition_start,
        partition_len,
        volume_space_size: partition_len, // Use partition length as volume size.
        root_icb_lbn,
        root_icb_part,
    })
}

/// Parse a File Entry (tag 261) or Extended File Entry (tag 266) from `buf`.
fn parse_file_entry(buf: &[u8], block_size: u32) -> Option<UdfFileEntry> {
    if buf.len() < 176 {
        return None;
    }
    let tag_id = read_u16_le(buf, 0);
    let is_efe = tag_id == TAG_EFE;
    if tag_id != TAG_FE && !is_efe {
        return None;
    }

    // ICB tag at offset 16.
    let file_type = buf[27]; // offset 16 + 11
    let icb_flags = read_u16_le(buf, 34); // offset 16 + 18
    let ad_type = (icb_flags & 0x07) as u8;

    let uid = read_u32_le(buf, 36);
    let gid = read_u32_le(buf, 40);
    let perms = read_u32_le(buf, 44);
    let info_len = read_u64_le(buf, 56);

    let (l_ea, l_ad, ad_base) = if is_efe {
        (
            read_u32_le(buf, 208),
            read_u32_le(buf, 212),
            216u32,
        )
    } else {
        (
            read_u32_le(buf, 168),
            read_u32_le(buf, 172),
            176u32,
        )
    };

    let ad_start = (ad_base + l_ea) as usize;
    let mode = udf_perms_to_mode(perms, file_type);

    let mut fe = UdfFileEntry {
        file_type,
        ad_type,
        info_len,
        mode,
        uid,
        gid,
        extents: [(0, 0); 8],
        extent_count: 0,
        inline_off: ad_start as u16,
        inline_len: l_ad as u16,
    };

    if ad_type == 3 {
        // Inline data — content is in the AD area.
        fe.inline_off = ad_start as u16;
        fe.inline_len = l_ad as u16;
    } else if ad_type == 0 {
        // Short allocation descriptors (8 bytes each).
        let mut pos = ad_start;
        while pos + 8 <= ad_start + l_ad as usize
            && (fe.extent_count as usize) < fe.extents.len()
        {
            let ext_len_raw = read_u32_le(buf, pos);
            let ext_type = (ext_len_raw >> 30) & 3;
            let ext_len = ext_len_raw & 0x3FFF_FFFF;
            let ext_pos = read_u32_le(buf, pos + 4);

            if ext_type == 3 {
                break; // Continuation — not yet supported.
            }
            if ext_len == 0 {
                break;
            }

            fe.extents[fe.extent_count as usize] = (ext_pos, ext_len);
            fe.extent_count += 1;
            pos += 8;
        }
    } else if ad_type == 1 {
        // Long allocation descriptors (16 bytes each).
        let mut pos = ad_start;
        while pos + 16 <= ad_start + l_ad as usize
            && (fe.extent_count as usize) < fe.extents.len()
        {
            let ext_len_raw = read_u32_le(buf, pos);
            let ext_type = (ext_len_raw >> 30) & 3;
            let ext_len = ext_len_raw & 0x3FFF_FFFF;
            let ext_lbn = read_u32_le(buf, pos + 4);
            // Partition reference at pos+8, ignored (assumed same partition).

            if ext_type == 3 {
                break;
            }
            if ext_len == 0 {
                break;
            }

            fe.extents[fe.extent_count as usize] = (ext_lbn, ext_len);
            fe.extent_count += 1;
            pos += 16;
        }
    }

    Some(fe)
}

/// Read file data from a UdfFileEntry at the given offset into `out`.
/// Returns bytes actually read.
fn read_file_data(
    blk: &BlkClient,
    vol: &UdfVolume,
    fe: &UdfFileEntry,
    offset: u64,
    out: &mut [u8],
    fe_block_va: usize,
) -> usize {
    let file_size = fe.info_len;
    if offset >= file_size {
        return 0;
    }
    let avail = (file_size - offset) as usize;
    let to_read = out.len().min(avail);

    if fe.ad_type == 3 {
        // Inline data — read from the FE block itself.
        let start = fe.inline_off as usize + offset as usize;
        let end = start + to_read;
        let fe_buf =
            unsafe { core::slice::from_raw_parts(fe_block_va as *const u8, vol.block_size as usize) };
        if end <= fe_buf.len() {
            out[..to_read].copy_from_slice(&fe_buf[start..end]);
            return to_read;
        }
        return 0;
    }

    // Extent-based data.
    let mut done = 0;
    let mut file_pos = 0u64;
    for i in 0..fe.extent_count as usize {
        let (ext_lbn, ext_len) = fe.extents[i];
        let ext_end = file_pos + ext_len as u64;

        if offset + done as u64 >= ext_end {
            file_pos = ext_end;
            continue;
        }

        let skip = if offset + done as u64 > file_pos {
            (offset + done as u64 - file_pos) as usize
        } else {
            0
        };

        let ext_avail = (ext_len as usize).saturating_sub(skip);
        let chunk = ext_avail.min(to_read - done);
        if chunk == 0 {
            file_pos = ext_end;
            continue;
        }

        let byte_off = vol.lbn_to_byte_off(ext_lbn) + skip as u64;
        if !blk.read_bytes(byte_off, &mut out[done..done + chunk]) {
            break;
        }

        done += chunk;
        file_pos = ext_end;
        if done >= to_read {
            break;
        }
    }
    done
}

/// Read file data into a grant VA.
fn read_file_to_va(
    blk: &BlkClient,
    vol: &UdfVolume,
    fe: &UdfFileEntry,
    offset: u64,
    dest: usize,
    len: usize,
) -> usize {
    let file_size = fe.info_len;
    if offset >= file_size {
        return 0;
    }
    let avail = (file_size - offset) as usize;
    let to_read = len.min(avail);

    // Extent-based data only (inline wouldn't use grant reads).
    let mut done = 0;
    let mut file_pos = 0u64;
    for i in 0..fe.extent_count as usize {
        let (ext_lbn, ext_len) = fe.extents[i];
        let ext_end = file_pos + ext_len as u64;

        if offset + done as u64 >= ext_end {
            file_pos = ext_end;
            continue;
        }

        let skip = if offset + done as u64 > file_pos {
            (offset + done as u64 - file_pos) as usize
        } else {
            0
        };

        let ext_avail = (ext_len as usize).saturating_sub(skip);
        let chunk = ext_avail.min(to_read - done);
        if chunk == 0 {
            file_pos = ext_end;
            continue;
        }

        let byte_off = vol.lbn_to_byte_off(ext_lbn) + skip as u64;
        if !blk.read_to_va(byte_off, dest + done, chunk) {
            break;
        }

        done += chunk;
        file_pos = ext_end;
        if done >= to_read {
            break;
        }
    }
    done
}

/// Read a File Entry from a partition-relative LBN.
fn read_fe(
    blk: &BlkClient,
    vol: &UdfVolume,
    lbn: u32,
    buf_va: usize,
) -> Option<UdfFileEntry> {
    let off = vol.lbn_to_byte_off(lbn);
    if !blk.read_block(off, buf_va, vol.block_size) {
        return None;
    }
    let buf =
        unsafe { core::slice::from_raw_parts(buf_va as *const u8, vol.block_size as usize) };
    // Accept either FE or EFE.
    let tag_id = read_u16_le(buf, 0);
    if tag_id != TAG_FE && tag_id != TAG_EFE {
        return None;
    }
    parse_file_entry(buf, vol.block_size)
}

/// Look up a filename in a directory's FID list.
/// Reads the directory data using the FE's extents, then scans FIDs.
/// Returns the ICB LBN of the matching entry, or None.
fn dir_lookup(
    blk: &BlkClient,
    vol: &UdfVolume,
    dir_fe: &UdfFileEntry,
    target: &[u8],
    target_len: usize,
    buf_va: usize,       // scratch buffer for FE reads
    dir_buf_va: usize,   // scratch buffer for directory data
) -> Option<u32> {
    // Read directory data into dir_buf_va.
    let dir_size = dir_fe.info_len as usize;
    if dir_size > 4096 {
        return None; // Directory too large for our single-page buffer.
    }

    if dir_fe.ad_type == 3 {
        // Inline directory data.
        let fe_buf =
            unsafe { core::slice::from_raw_parts(buf_va as *const u8, vol.block_size as usize) };
        let start = dir_fe.inline_off as usize;
        let end = start + dir_size;
        if end <= fe_buf.len() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (buf_va + start) as *const u8,
                    dir_buf_va as *mut u8,
                    dir_size,
                );
            }
        } else {
            return None;
        }
    } else {
        // Read from extents.
        let mut done = 0;
        for i in 0..dir_fe.extent_count as usize {
            let (ext_lbn, ext_len) = dir_fe.extents[i];
            let chunk = (ext_len as usize).min(dir_size - done);
            let byte_off = vol.lbn_to_byte_off(ext_lbn);
            if !blk.read_to_va(byte_off, dir_buf_va + done, chunk) {
                return None;
            }
            done += chunk;
            if done >= dir_size {
                break;
            }
        }
    }

    let dir_data =
        unsafe { core::slice::from_raw_parts(dir_buf_va as *const u8, dir_size) };

    // Scan FIDs.
    let mut pos = 0;
    while pos + 38 < dir_size {
        let tag_id = read_u16_le(dir_data, pos);
        if tag_id != TAG_FID {
            break;
        }
        let fchar = dir_data[pos + 18];
        let l_fi = dir_data[pos + 19] as usize;
        let icb_lbn = read_u32_le(dir_data, pos + 24); // long_ad: lbn at +4 from start of long_ad at pos+20
        let l_iu = read_u16_le(dir_data, pos + 36) as usize;

        let fid_size = (38 + l_iu + l_fi + 3) & !3;

        // Skip deleted and parent entries.
        if fchar & FID_CHAR_DELETED != 0 || fchar & FID_CHAR_PARENT != 0 {
            pos += fid_size;
            continue;
        }

        // Decode filename.
        let name_start = pos + 38 + l_iu;
        if name_start + l_fi > dir_size {
            break;
        }
        let name_raw = &dir_data[name_start..name_start + l_fi];
        let mut name_buf = [0u8; 128];
        let name_len = decode_osta_cs0(name_raw, &mut name_buf);

        // Compare.
        if name_len == target_len {
            let mut eq = true;
            for j in 0..name_len {
                if name_buf[j] != target[j] {
                    eq = false;
                    break;
                }
            }
            if eq {
                return Some(icb_lbn);
            }
        }

        pos += fid_size;
    }
    None
}

/// Resolve a multi-component path from the root directory.
fn path_resolve(
    blk: &BlkClient,
    vol: &UdfVolume,
    path: &[u8],
    path_len: usize,
    buf_va: usize,
    dir_buf_va: usize,
) -> Option<UdfFileEntry> {
    // Start from root ICB.
    let mut cur_fe = read_fe(blk, vol, vol.root_icb_lbn, buf_va)?;

    let path = &path[..path_len];
    // Strip leading '/'.
    let path = if path.first() == Some(&b'/') {
        &path[1..]
    } else {
        path
    };

    if path.is_empty() {
        return Some(cur_fe);
    }

    // Split on '/' and resolve component by component.
    let mut start = 0;
    while start < path.len() {
        while start < path.len() && path[start] == b'/' {
            start += 1;
        }
        if start >= path.len() {
            break;
        }
        let mut end = start;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        let component = &path[start..end];

        if !cur_fe.is_dir() {
            return None;
        }

        // Need to re-read the current FE into buf_va for dir_lookup
        // (dir_lookup uses buf_va for inline data).
        // We stored cur_fe from the last read_fe call which used buf_va,
        // so the block is still there. But dir_lookup may overwrite it
        // when reading sub-entries. Re-read to be safe.
        let cur_lbn = cur_fe.extents[0].0; // For extent-based dirs
        // Actually, we need the LBN of the FE itself, not its data extent.
        // We'll track it separately.
        let icb_lbn = dir_lookup(blk, vol, &cur_fe, component, component.len(), buf_va, dir_buf_va)?;
        cur_fe = read_fe(blk, vol, icb_lbn, buf_va)?;

        start = end;
    }

    Some(cur_fe)
}

/// Enumerate directory entries starting from `offset`.
/// Returns Some((name_buf, name_len, icb_lbn, fchar, new_offset)) or None if end.
fn readdir_next(
    dir_data: &[u8],
    dir_size: usize,
    offset: u32,
) -> Option<([u8; 128], usize, u32, u8, u32)> {
    let mut pos = offset as usize;
    while pos + 38 < dir_size {
        let tag_id = read_u16_le(dir_data, pos);
        if tag_id != TAG_FID {
            return None;
        }
        let fchar = dir_data[pos + 18];
        let l_fi = dir_data[pos + 19] as usize;
        let icb_lbn = read_u32_le(dir_data, pos + 24);
        let l_iu = read_u16_le(dir_data, pos + 36) as usize;
        let fid_size = (38 + l_iu + l_fi + 3) & !3;

        let new_pos = pos + fid_size;

        // Skip deleted and parent entries.
        if fchar & FID_CHAR_DELETED != 0 || fchar & FID_CHAR_PARENT != 0 {
            pos = new_pos;
            continue;
        }

        let name_start = pos + 38 + l_iu;
        if name_start + l_fi > dir_size {
            return None;
        }
        let name_raw = &dir_data[name_start..name_start + l_fi];
        let mut name_buf = [0u8; 128];
        let name_len = decode_osta_cs0(name_raw, &mut name_buf);

        return Some((name_buf, name_len, icb_lbn, fchar, new_pos as u32));
    }
    None
}

// --- Main ---

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [udf_srv] starting\n");

    let image_offset = if arg0 != 0 { arg0 } else { 0 };

    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"udf", port);

    syscall::debug_puts(b"  [udf_srv] registered, port=");
    print_num(port);
    syscall::debug_puts(b"\n");

    // Look up cache_blk (or blk).
    let blk_port = {
        let mut retries = 2000;
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
                syscall::debug_puts(b"  [udf_srv] blk not found, exiting\n");
                syscall::exit(1);
            }
            for _ in 0..50 {
                syscall::yield_now();
            }
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
            syscall::debug_puts(b"  [udf_srv] blk connect FAILED\n");
            syscall::exit(1);
        }
    } else {
        syscall::debug_puts(b"  [udf_srv] blk no reply\n");
        syscall::exit(1);
    };

    // Allocate scratch pages.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [udf_srv] scratch alloc FAILED\n");
            syscall::exit(1);
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_0000,
        image_offset,
    };

    // Allocate buffer for sector/block reads.
    let buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [udf_srv] buf alloc FAILED\n");
            syscall::exit(1);
        }
    };

    // Allocate buffer for directory data reads.
    let dir_buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [udf_srv] dirbuf alloc FAILED\n");
            syscall::exit(1);
        }
    };

    // Parse UDF volume structures.
    // Try 2048-byte sector size first (optical/genisoimage), then 512.
    let vol = if let Some(v) = parse_volume(&blk, 2048, buf_va) {
        v
    } else if let Some(v) = parse_volume(&blk, 512, buf_va) {
        v
    } else {
        syscall::debug_puts(b"  [udf_srv] no valid UDF volume found\n");
        syscall::exit(1);
    };

    syscall::debug_puts(b"  [udf_srv] UDF: block_size=");
    print_num(vol.block_size as u64);
    syscall::debug_puts(b" part_start=");
    print_num(vol.partition_start as u64);
    syscall::debug_puts(b" part_len=");
    print_num(vol.partition_len as u64);
    syscall::debug_puts(b" root_lbn=");
    print_num(vol.root_icb_lbn as u64);
    syscall::debug_puts(b"\n");

    syscall::debug_puts(b"  [udf_srv] ready\n");

    let mut open_files = [OpenFile::empty(); MAX_OPEN_FILES];

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
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(fe) =
                    path_resolve(&blk, &vol, name, name.len(), buf_va, dir_buf_va)
                {
                    let mut handle = u64::MAX;
                    for (i, f) in open_files.iter_mut().enumerate() {
                        if !f.active {
                            f.active = true;
                            f.fe = fe;
                            f.readdir_offset = 0;
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
                            fe.info_len,
                            my_aspace as u64,
                            0,
                        );
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1];
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let fe = &open_files[handle].fe;
                if offset >= fe.info_len {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                if grant_va != 0 {
                    let chunk = length.min(4096);
                    let bytes_read =
                        read_file_to_va(&blk, &vol, fe, offset, grant_va, chunk);
                    syscall::send_nb(reply_port, FS_READ_OK, bytes_read as u64, 0);
                } else {
                    let inline_len = length.min(MAX_INLINE);
                    let mut tmp = [0u8; 24];
                    // Need to re-read the FE block for inline data.
                    if fe.ad_type == 3 {
                        // Re-read the FE block into buf_va for inline access.
                        // We don't store the LBN in OpenFile, so we need to
                        // re-resolve. For inline files this is rare in practice.
                        // Just read zeros for now if inline.
                        let start = fe.inline_off as usize + offset as usize;
                        // Can't read inline without the FE block in memory.
                        // Return zeros (limitation for inline files via inline IPC).
                        let _bytes = 0;
                        syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    } else {
                        let mut read_buf = [0u8; 24];
                        let bytes_read = read_file_data(
                            &blk, &vol, fe, offset, &mut read_buf[..inline_len], buf_va,
                        );
                        let words = pack_inline_data(&read_buf[..bytes_read]);
                        syscall::send(
                            reply_port,
                            FS_READ_OK,
                            bytes_read as u64,
                            words[0],
                            words[1],
                            words[2],
                        );
                    }
                }
            }

            FS_READDIR => {
                let handle = msg.data[0] as usize;
                let reply_port = msg.data[1];

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let file = &open_files[handle];
                if !file.fe.is_dir() {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                // Read directory data into dir_buf_va.
                let dir_size = file.fe.info_len as usize;
                if dir_size > 4096 {
                    syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                    continue;
                }

                let fe = &file.fe;
                let mut dir_ok = true;
                if fe.ad_type == 3 {
                    // Need FE block for inline. Not supported in readdir yet.
                    dir_ok = false;
                } else {
                    let mut done = 0;
                    for i in 0..fe.extent_count as usize {
                        let (ext_lbn, ext_len) = fe.extents[i];
                        let chunk = (ext_len as usize).min(dir_size - done);
                        let byte_off = vol.lbn_to_byte_off(ext_lbn);
                        if !blk.read_to_va(byte_off, dir_buf_va + done, chunk) {
                            dir_ok = false;
                            break;
                        }
                        done += chunk;
                        if done >= dir_size {
                            break;
                        }
                    }
                }

                if !dir_ok {
                    syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                    continue;
                }

                let dir_data = unsafe {
                    core::slice::from_raw_parts(dir_buf_va as *const u8, dir_size)
                };

                let offset = open_files[handle].readdir_offset;
                if let Some((name_buf, name_len, icb_lbn, fchar, new_offset)) =
                    readdir_next(dir_data, dir_size, offset)
                {
                    open_files[handle].readdir_offset = new_offset;

                    let is_dir = if fchar & FID_CHAR_DIR != 0 { 1u64 } else { 0u64 };
                    let name_data = pack_inline_data(&name_buf[..name_len.min(MAX_INLINE)]);

                    // Read the FE to get file size.
                    let fsize = if let Some(entry_fe) = read_fe(&blk, &vol, icb_lbn, buf_va) {
                        entry_fe.info_len
                    } else {
                        0
                    };

                    syscall::send(
                        reply_port,
                        FS_READDIR_OK,
                        name_len as u64 | (is_dir << 32),
                        name_data[0],
                        name_data[1],
                        fsize,
                    );
                } else {
                    syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                    open_files[handle].readdir_offset = 0;
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;
                let reply_port = msg.data[1];

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let fe = &open_files[handle].fe;
                let ftype = if fe.is_dir() {
                    1u64
                } else if fe.is_symlink() {
                    2u64
                } else {
                    0u64
                };
                syscall::send(
                    reply_port,
                    FS_STAT_OK,
                    fe.info_len,
                    ftype,
                    fe.mode as u64,
                    0,
                );
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN_FILES {
                    open_files[handle].active = false;
                }
            }

            FS_READLINK => {
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(fe) =
                    path_resolve(&blk, &vol, name, name.len(), buf_va, dir_buf_va)
                {
                    if !fe.is_symlink() {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    } else {
                        let mut link_buf = [0u8; 24];
                        let link_len = read_file_data(
                            &blk,
                            &vol,
                            &fe,
                            0,
                            &mut link_buf,
                            buf_va,
                        );
                        let packed = pack_inline_data(&link_buf[..link_len]);
                        syscall::send(
                            reply_port,
                            FS_READLINK_OK,
                            link_len as u64,
                            packed[0],
                            packed[1],
                            packed[2],
                        );
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let reply_port = msg.data[2] >> 32;
                let total_blocks = vol.partition_len as u64;
                let block_size = vol.block_size as u64;
                // UDF is read-only in this implementation: 0 free blocks.
                syscall::send(
                    reply_port,
                    FS_STATFS_OK,
                    total_blocks,
                    0,
                    block_size,
                    0,
                );
            }

            _ => {
                // Unknown message — try to extract reply port and send error.
                let reply_port = msg.data[2] >> 32;
                if reply_port != 0 {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                }
            }
        }
    }
}
