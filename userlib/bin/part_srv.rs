#![no_std]
#![no_main]

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Nadia Chambers

//! GPT/MBR partition table parser.
//!
//! Reads the first few sectors from the block device, parses the protective
//! MBR and GPT header/entries, and serves partition info to other userspace
//! services over IPC.
//!
//! ## IPC protocol
//!
//! - `PART_COUNT`     (0x7200): → data[0] = partition count
//! - `PART_INFO`      (0x7201): data[0] = index
//!     → data[0] = first_lba, data[1] = last_lba,
//!       data[2] = type_guid_low64, data[3] = type_guid_high64
//! - `PART_NAME`      (0x7202): data[0] = index
//!     → data[0..2] = first 24 bytes of UTF-16LE name (packed)
//! - `PART_DISK_GUID` (0x7203): → data[0] = guid_low64, data[1] = guid_high64
//! - `PART_BYTE_RANGE`(0x7204): data[0] = index
//!     → data[0] = first_byte, data[1] = size_bytes

extern crate userlib;

use userlib::syscall;

// --- IPC tags ---
const PART_COUNT: u64 = 0x7200;
const PART_INFO: u64 = 0x7201;
const PART_NAME: u64 = 0x7202;
const PART_DISK_GUID: u64 = 0x7203;
const PART_BYTE_RANGE: u64 = 0x7204;
const PART_ERROR: u64 = 0x72FF;

// --- Block I/O tags ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;

// --- Constants ---
const MAX_PARTITIONS: usize = 32;
const SECTOR_SIZE: u64 = 512;

// --- Partition entry ---
#[derive(Clone, Copy)]
struct GptPartition {
    type_guid: [u8; 16],
    unique_guid: [u8; 16],
    first_lba: u64,
    last_lba: u64,
    attributes: u64,
    name: [u8; 72], // UTF-16LE
}

impl GptPartition {
    const EMPTY: Self = GptPartition {
        type_guid: [0; 16],
        unique_guid: [0; 16],
        first_lba: 0,
        last_lba: 0,
        attributes: 0,
        name: [0; 72],
    };

    fn is_used(&self) -> bool {
        // Unused entries have an all-zero type GUID.
        self.type_guid != [0u8; 16]
    }
}

struct PartState {
    parts: [GptPartition; MAX_PARTITIONS],
    count: usize,
    disk_guid: [u8; 16],
    gpt_valid: bool,
}

// --- Block client (minimal, for reading sectors) ---
struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
    grant_va: usize,
}

impl BlkClient {
    fn read_sector(&self, lba: u64, out: &mut [u8; 512]) -> bool {
        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }
        let offset = lba * SECTOR_SIZE;
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_READ, 0, offset, d2, self.grant_va as u64);
        let ok = if let Some(rr) = syscall::recv_msg_timeout(self.reply_port, 5_000_000) {
            if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.scratch_va as *const u8,
                        out.as_mut_ptr(),
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
        ok
    }
}

// --- Helpers ---

fn print_hex(val: u64) {
    let mut buf = [b'0'; 16];
    let mut v = val;
    for i in (0..16).rev() {
        let nibble = (v & 0xF) as u8;
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        v >>= 4;
    }
    let mut start = 0;
    while start < 15 && buf[start] == b'0' {
        start += 1;
    }
    syscall::debug_puts(b"0x");
    syscall::debug_puts(&buf[start..]);
}

fn print_num(val: u64) {
    if val == 0 {
        syscall::debug_puts(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut v = val;
    let mut i = 20;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    syscall::debug_puts(&buf[i..]);
}

fn le_u16(data: &[u8], off: usize) -> u16 {
    (data[off] as u16) | ((data[off + 1] as u16) << 8)
}

fn le_u32(data: &[u8], off: usize) -> u32 {
    (data[off] as u32)
        | ((data[off + 1] as u32) << 8)
        | ((data[off + 2] as u32) << 16)
        | ((data[off + 3] as u32) << 24)
}

fn le_u64(data: &[u8], off: usize) -> u64 {
    (le_u32(data, off) as u64) | ((le_u32(data, off + 4) as u64) << 32)
}

fn guid_to_u128(g: &[u8; 16]) -> (u64, u64) {
    let lo = le_u64(g, 0);
    let hi = le_u64(g, 8);
    (lo, hi)
}

// --- CRC32 (IEEE, same as used by GPT) ---

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// --- GPT partition name as ASCII (first 36 chars of UTF-16LE) ---

fn gpt_name_ascii(name: &[u8; 72], out: &mut [u8]) -> usize {
    let mut len = 0;
    let max = out.len().min(36);
    let mut i = 0;
    while i + 1 < 72 && len < max {
        let ch = le_u16(name, i);
        if ch == 0 {
            break;
        }
        out[len] = if ch < 128 { ch as u8 } else { b'?' };
        len += 1;
        i += 2;
    }
    len
}

// --- GPT parsing ---

fn parse_gpt(blk: &BlkClient) -> PartState {
    let mut state = PartState {
        parts: [GptPartition::EMPTY; MAX_PARTITIONS],
        count: 0,
        disk_guid: [0; 16],
        gpt_valid: false,
    };

    // Read LBA 0 (protective MBR).
    let mut mbr = [0u8; 512];
    if !blk.read_sector(0, &mut mbr) {
        syscall::debug_puts(b"  [part_srv] failed to read MBR\n");
        return state;
    }

    // Check MBR boot signature.
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        syscall::debug_puts(b"  [part_srv] no MBR signature\n");
        return state;
    }

    // Check for protective MBR (partition type 0xEE at offset 450).
    let part_type = mbr[450];
    if part_type != 0xEE {
        syscall::debug_puts(b"  [part_srv] MBR type ");
        print_hex(part_type as u64);
        syscall::debug_puts(b" (not GPT protective)\n");
        return state;
    }

    // Read LBA 1 (GPT header).
    let mut hdr_buf = [0u8; 512];
    if !blk.read_sector(1, &mut hdr_buf) {
        syscall::debug_puts(b"  [part_srv] failed to read GPT header\n");
        return state;
    }

    // Validate signature "EFI PART".
    if &hdr_buf[0..8] != b"EFI PART" {
        syscall::debug_puts(b"  [part_srv] bad GPT signature\n");
        return state;
    }

    // Validate header CRC32.
    let header_size = le_u32(&hdr_buf, 12) as usize;
    if header_size < 92 || header_size > 512 {
        syscall::debug_puts(b"  [part_srv] bad GPT header size\n");
        return state;
    }
    let stored_crc = le_u32(&hdr_buf, 16);
    // Zero out the CRC field for computation.
    let mut hdr_copy = [0u8; 512];
    hdr_copy[..header_size].copy_from_slice(&hdr_buf[..header_size]);
    hdr_copy[16] = 0;
    hdr_copy[17] = 0;
    hdr_copy[18] = 0;
    hdr_copy[19] = 0;
    let computed_crc = crc32(&hdr_copy[..header_size]);
    if stored_crc != computed_crc {
        syscall::debug_puts(b"  [part_srv] GPT header CRC mismatch\n");
        return state;
    }

    // Parse header fields.
    let _my_lba = le_u64(&hdr_buf, 24);
    let _alt_lba = le_u64(&hdr_buf, 32);
    let _first_usable = le_u64(&hdr_buf, 40);
    let _last_usable = le_u64(&hdr_buf, 48);
    state.disk_guid.copy_from_slice(&hdr_buf[56..72]);

    let entry_start_lba = le_u64(&hdr_buf, 72);
    let num_entries = le_u32(&hdr_buf, 80) as usize;
    let entry_size = le_u32(&hdr_buf, 84) as usize;
    let entries_crc = le_u32(&hdr_buf, 88);

    if entry_size < 128 || entry_size > 512 {
        syscall::debug_puts(b"  [part_srv] bad entry size\n");
        return state;
    }

    syscall::debug_puts(b"  [part_srv] GPT: ");
    print_num(num_entries as u64);
    syscall::debug_puts(b" entries at LBA ");
    print_num(entry_start_lba);
    syscall::debug_puts(b"\n");

    // Read partition entries (they span multiple sectors).
    let entries_bytes = num_entries * entry_size;
    let entries_sectors = (entries_bytes + 511) / 512;

    // We'll accumulate CRC over raw entry data and parse in one pass.
    // Read sector by sector, up to 32 sectors (16384 bytes = 128 entries × 128).
    let max_sectors = entries_sectors.min(32);
    let mut all_entries = [0u8; 32 * 512]; // 16 KiB max
    let mut total_read = 0usize;

    for s in 0..max_sectors {
        let mut sec = [0u8; 512];
        if !blk.read_sector(entry_start_lba + s as u64, &mut sec) {
            syscall::debug_puts(b"  [part_srv] failed to read entry sector\n");
            return state;
        }
        let dst_off = s * 512;
        all_entries[dst_off..dst_off + 512].copy_from_slice(&sec);
        total_read += 512;
    }

    // Validate entries CRC.
    let crc_len = entries_bytes.min(total_read);
    let computed_entries_crc = crc32(&all_entries[..crc_len]);
    if entries_crc != computed_entries_crc {
        syscall::debug_puts(b"  [part_srv] GPT entries CRC mismatch\n");
        return state;
    }

    // Parse entries.
    let max_parse = num_entries.min(MAX_PARTITIONS * 2); // scan more than we store
    for i in 0..max_parse {
        let off = i * entry_size;
        if off + 128 > total_read {
            break;
        }

        let mut entry = GptPartition::EMPTY;
        entry.type_guid.copy_from_slice(&all_entries[off..off + 16]);
        if !entry.is_used() {
            continue;
        }

        entry.unique_guid.copy_from_slice(&all_entries[off + 16..off + 32]);
        entry.first_lba = le_u64(&all_entries, off + 32);
        entry.last_lba = le_u64(&all_entries, off + 40);
        entry.attributes = le_u64(&all_entries, off + 48);
        entry.name.copy_from_slice(&all_entries[off + 56..off + 128]);

        if state.count < MAX_PARTITIONS {
            state.parts[state.count] = entry;
            state.count += 1;

            // Print partition info.
            let mut name_buf = [0u8; 36];
            let name_len = gpt_name_ascii(&entry.name, &mut name_buf);
            syscall::debug_puts(b"    ");
            print_num(state.count as u64);
            syscall::debug_puts(b": ");
            if name_len > 0 {
                syscall::debug_puts(&name_buf[..name_len]);
            } else {
                syscall::debug_puts(b"(unnamed)");
            }
            syscall::debug_puts(b"  LBA ");
            print_num(entry.first_lba);
            syscall::debug_puts(b"-");
            print_num(entry.last_lba);
            let size_mib = (entry.last_lba - entry.first_lba + 1) * SECTOR_SIZE / (1024 * 1024);
            syscall::debug_puts(b" (");
            print_num(size_mib);
            syscall::debug_puts(b" MiB)\n");
        }
    }

    state.gpt_valid = true;
    state
}

// --- Entry point ---

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [part_srv] starting\n");

    // Look up block device with retry.
    let blk_port = {
        let mut retries = 200u32;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            if let Some(p) = syscall::ns_lookup(b"blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [part_srv] no block device found\n");
                loop {
                    core::hint::spin_loop();
                }
            }
            syscall::nanosleep(10_000_000);
        }
    };

    // Connect to block device.
    let blk_reply = syscall::port_create();
    {
        let (n0, n1, _) = syscall::pack_name(b"blk");
        let d2 = 3u64 | ((blk_reply as u64) << 32);
        syscall::send(blk_port, IO_CONNECT, n0, n1, d2, 0);
    }
    let blk_aspace = if let Some(reply) = syscall::recv_msg_timeout(blk_reply, 5_000_000) {
        if reply.tag == IO_CONNECT_OK {
            reply.data[2]
        } else {
            syscall::debug_puts(b"  [part_srv] blk connect failed\n");
            loop {
                core::hint::spin_loop();
            }
        }
    } else {
        syscall::debug_puts(b"  [part_srv] blk no reply\n");
        loop {
            core::hint::spin_loop();
        }
    };

    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [part_srv] scratch alloc failed\n");
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
        grant_va: 0x8_0000_0000, // distinct from other servers
    };

    // Parse GPT.
    let state = parse_gpt(&blk);

    if state.gpt_valid {
        syscall::debug_puts(b"  [part_srv] GPT valid, ");
        print_num(state.count as u64);
        syscall::debug_puts(b" partitions\n");
    } else {
        syscall::debug_puts(b"  [part_srv] no valid GPT found (0 partitions)\n");
    }

    // Register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"part", port);

    syscall::debug_puts(b"  [part_srv] ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // IPC server loop.
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };

        match msg.tag {
            PART_COUNT => {
                let _ = syscall::reply(PART_COUNT, state.count as u64, 0, 0, 0, 0);
            }

            PART_INFO => {
                let idx = msg.data[0] as usize;
                if idx < state.count {
                    let p = &state.parts[idx];
                    let (tg_lo, tg_hi) = guid_to_u128(&p.type_guid);
                    let _ = syscall::reply(
                        PART_INFO,
                        p.first_lba,
                        p.last_lba,
                        tg_lo,
                        tg_hi,
                        0,
                    );
                } else {
                    let _ = syscall::reply(PART_ERROR, 0, 0, 0, 0, 0);
                }
            }

            PART_NAME => {
                let idx = msg.data[0] as usize;
                if idx < state.count {
                    let p = &state.parts[idx];
                    // Pack first 48 bytes of name (24 UTF-16LE chars) into 6 u64s.
                    let d0 = le_u64(&p.name, 0);
                    let d1 = le_u64(&p.name, 8);
                    let d2 = le_u64(&p.name, 16);
                    let _ = syscall::reply(PART_NAME, d0, d1, d2, 0, 0);
                } else {
                    let _ = syscall::reply(PART_ERROR, 0, 0, 0, 0, 0);
                }
            }

            PART_DISK_GUID => {
                let (lo, hi) = guid_to_u128(&state.disk_guid);
                let _ = syscall::reply(PART_DISK_GUID, lo, hi, 0, 0, 0);
            }

            PART_BYTE_RANGE => {
                let idx = msg.data[0] as usize;
                if idx < state.count {
                    let p = &state.parts[idx];
                    let first_byte = p.first_lba * SECTOR_SIZE;
                    let size_bytes = (p.last_lba - p.first_lba + 1) * SECTOR_SIZE;
                    let _ = syscall::reply(PART_BYTE_RANGE, first_byte, size_bytes, 0, 0, 0);
                } else {
                    let _ = syscall::reply(PART_ERROR, 0, 0, 0, 0, 0);
                }
            }

            _ => {
                let _ = syscall::reply(PART_ERROR, 0, 0, 0, 0, 0);
            }
        }
    }
}
