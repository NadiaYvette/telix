#![no_std]
#![no_main]

//! FAT16 filesystem server.
//!
//! Pure userspace process that reads a FAT16 filesystem from blk_srv via IPC.
//! Serves file-level FS_OPEN / FS_READ / FS_CLOSE requests.

extern crate userlib;

use userlib::syscall;

// --- I/O protocol constants (for talking to blk_srv) ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;

// --- FS protocol constants (served by this server) ---
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_CLOSE: u64 = 0x2400;
const FS_CREATE: u64 = 0x2500;
const FS_CREATE_OK: u64 = 0x2501;
const FS_WRITE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;
const FS_DELETE: u64 = 0x2700;
const FS_DELETE_OK: u64 = 0x2701;
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

const MAX_OPEN_FILES: usize = 8;
const MAX_INLINE: usize = 24; // max bytes we can pack into 3 u64 reply words

// --- FAT16 structures ---

struct Bpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    root_entry_count: u16,
    sectors_per_fat: u16,
}

struct Fat16Layout {
    fat_start: u32,
    root_dir_start: u32,
    root_dir_sectors: u32,
    data_start: u32,
    sectors_per_cluster: u32,
}

#[derive(Clone, Copy)]
struct OpenFile {
    first_cluster: u16,
    file_size: u32,
    active: bool,
    writable: bool,
    dir_sector: u32,
    dir_offset: usize,
    last_cluster: u16,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            first_cluster: 0,
            file_size: 0,
            active: false,
            writable: false,
            dir_sector: 0,
            dir_offset: 0,
            last_cluster: 0,
        }
    }
}

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

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

/// Read a u16 from a byte slice at the given offset (little-endian).
fn read_u16(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

/// Read a u32 from a byte slice at the given offset (little-endian).
fn read_u32(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

/// State for communicating with blk_srv.
struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    /// Scratch page VA for block reads (our local mapping).
    scratch_va: usize,
    /// Grant VA in blk_srv's address space.
    grant_va: usize,
}

impl BlkClient {
    /// Read a single 512-byte sector into `out`.
    fn read_sector(&self, sector: u32, out: &mut [u8; 512]) -> bool {
        // Grant our scratch page to blk_srv.
        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }

        let offset = (sector as u64) * 512;
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_READ, 0, offset, d2, self.grant_va as u64);

        let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
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

    /// Write a single 512-byte sector to disk.
    fn write_sector(&self, sector: u32, data: &[u8; 512]) -> bool {
        // Copy data into scratch page.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.scratch_va as *mut u8, 512);
        }

        // Grant our scratch page to blk_srv.
        let grant_ok =
            syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false);
        if !grant_ok {
            syscall::debug_puts(b"  [fat16_srv] GRANT FAILED for write\n");
            return false;
        }

        let offset = (sector as u64) * 512;
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_WRITE, 0, offset, d2, self.grant_va as u64);

        let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
            rr.tag == IO_WRITE_OK
        } else {
            false
        };

        syscall::revoke(self.blk_aspace, self.grant_va);
        ok
    }
}

/// Convert a filename like "HELLO.TXT" to FAT16 8.3 format (11 bytes, space-padded).
fn to_8_3(name: &[u8], out: &mut [u8; 11]) {
    // Fill with spaces.
    *out = [b' '; 11];

    // Find the dot.
    let mut dot_pos = name.len();
    for (i, &b) in name.iter().enumerate() {
        if b == b'.' {
            dot_pos = i;
            break;
        }
    }

    // Copy name part (up to 8 chars).
    for i in 0..8.min(dot_pos) {
        out[i] = to_upper(name[i]);
    }

    // Copy extension (up to 3 chars after dot).
    if dot_pos < name.len() {
        let ext_start = dot_pos + 1;
        for i in 0..3.min(name.len() - ext_start) {
            out[8 + i] = to_upper(name[ext_start + i]);
        }
    }
}

fn to_upper(b: u8) -> u8 {
    if b >= b'a' && b <= b'z' { b - 32 } else { b }
}

/// Write a u16 to a byte slice at the given offset (little-endian).
fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
}

/// Write a u32 to a byte slice at the given offset (little-endian).
fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
    buf[off + 2] = (val >> 16) as u8;
    buf[off + 3] = (val >> 24) as u8;
}

/// Set a FAT16 entry in the in-memory FAT table.
fn set_fat_entry(fat_va: usize, cluster: u16, value: u16) {
    let offset = (cluster as usize) * 2;
    let ptr = (fat_va + offset) as *mut u16;
    unsafe {
        core::ptr::write(ptr, value);
    }
}

/// Find first free cluster (FAT entry == 0x0000). Starts from cluster 2.
fn find_free_cluster(fat_va: usize, max_clusters: usize) -> Option<u16> {
    for c in 2..max_clusters {
        let entry = fat_entry(fat_va, c as u16);
        if entry == 0x0000 {
            return Some(c as u16);
        }
    }
    None
}

/// Allocate a single cluster: find free, mark as end-of-chain (0xFFFF).
fn alloc_cluster(fat_va: usize, max_clusters: usize) -> Option<u16> {
    let c = find_free_cluster(fat_va, max_clusters)?;
    set_fat_entry(fat_va, c, 0xFFFF);
    Some(c)
}

/// Flush the in-memory FAT table back to disk.
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

/// Find a free directory entry in the root directory. Returns (sector, byte_offset_in_sector).
fn find_free_dir_entry(
    blk: &BlkClient,
    layout: &Fat16Layout,
    root_entry_count: u16,
) -> Option<(u32, usize)> {
    let entries_per_sector = 16usize; // 512 / 32
    let total_entries = root_entry_count as usize;
    let mut idx = 0;
    while idx < total_entries {
        let sector_idx = idx / entries_per_sector;
        let mut sec = [0u8; 512];
        if !blk.read_sector(layout.root_dir_start + sector_idx as u32, &mut sec) {
            return None;
        }
        for e in 0..entries_per_sector {
            if idx + e >= total_entries {
                return None;
            }
            let off = e * 32;
            let first_byte = sec[off];
            if first_byte == 0x00 || first_byte == 0xE5 {
                return Some((layout.root_dir_start + sector_idx as u32, off));
            }
        }
        idx += entries_per_sector;
    }
    None
}

/// Write a 32-byte directory entry to a specific sector at a given offset.
fn write_dir_entry(
    blk: &BlkClient,
    sector: u32,
    offset: usize,
    name: &[u8; 11],
    cluster: u16,
    size: u32,
) -> bool {
    let mut sec = [0u8; 512];
    let rd = blk.read_sector(sector, &mut sec);
    if !rd {
        return false;
    }
    // Clear entry.
    for i in 0..32 {
        sec[offset + i] = 0;
    }
    // 8.3 name.
    sec[offset..offset + 11].copy_from_slice(name);
    // Attribute: normal file (0x20 = archive).
    sec[offset + 11] = 0x20;
    // First cluster low.
    write_u16(&mut sec, offset + 26, cluster);
    // File size.
    write_u32(&mut sec, offset + 28, size);
    blk.write_sector(sector, &sec)
}

/// Unpack a filename from FS_OPEN message data words.
fn unpack_name(d0: u64, d1: u64, len: usize) -> [u8; 24] {
    let mut buf = [0u8; 24];
    let words = [d0, d1];
    for i in 0..len.min(16) {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    buf
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [fat16_srv] starting\n");

    // Create port and register with name server.
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"fat16", port);

    syscall::debug_puts(b"  [fat16_srv] registered, port=");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Look up cache_blk (cache server proxy) with bounded retry.
    let blk_port = {
        let mut retries = 2000;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [fat16_srv] cache_blk not found, exiting\n");
                syscall::exit(1);
            }
            for _ in 0..50 {
                syscall::yield_now();
            }
        }
    };

    syscall::debug_puts(b"  [fat16_srv] cache_blk on port ");
    print_num(blk_port as u64);
    syscall::debug_puts(b"\n");

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
            syscall::debug_puts(b"  [fat16_srv] blk connect FAILED\n");
            loop {
                core::hint::spin_loop();
            }
        }
    } else {
        syscall::debug_puts(b"  [fat16_srv] blk no reply\n");
        loop {
            core::hint::spin_loop();
        }
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [fat16_srv] scratch alloc FAILED\n");
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
        grant_va: 0x5_0000_0000,
    };

    // Read boot sector (sector 0).
    let mut boot_sector = [0u8; 512];
    if !blk.read_sector(0, &mut boot_sector) {
        syscall::debug_puts(b"  [fat16_srv] failed to read boot sector\n");
        loop {
            core::hint::spin_loop();
        }
    }

    // Verify boot signature.
    if boot_sector[510] != 0x55 || boot_sector[511] != 0xAA {
        syscall::debug_puts(b"  [fat16_srv] bad boot signature\n");
        loop {
            core::hint::spin_loop();
        }
    }

    // Parse BPB.
    let bpb = Bpb {
        bytes_per_sector: read_u16(&boot_sector, 11),
        sectors_per_cluster: boot_sector[13],
        reserved_sectors: read_u16(&boot_sector, 14),
        num_fats: boot_sector[16],
        root_entry_count: read_u16(&boot_sector, 17),
        sectors_per_fat: read_u16(&boot_sector, 22),
    };

    let layout = Fat16Layout {
        fat_start: bpb.reserved_sectors as u32,
        root_dir_start: bpb.reserved_sectors as u32
            + (bpb.num_fats as u32) * (bpb.sectors_per_fat as u32),
        root_dir_sectors: ((bpb.root_entry_count as u32) * 32 + 511) / 512,
        data_start: 0, // computed below
        sectors_per_cluster: bpb.sectors_per_cluster as u32,
    };
    let layout = Fat16Layout {
        data_start: layout.root_dir_start + layout.root_dir_sectors,
        ..layout
    };

    syscall::debug_puts(b"  [fat16_srv] FAT16: bps=");
    print_num(bpb.bytes_per_sector as u64);
    syscall::debug_puts(b" spc=");
    print_num(bpb.sectors_per_cluster as u64);
    syscall::debug_puts(b" reserved=");
    print_num(bpb.reserved_sectors as u64);
    syscall::debug_puts(b" root_entries=");
    print_num(bpb.root_entry_count as u64);
    syscall::debug_puts(b" fat_sectors=");
    print_num(bpb.sectors_per_fat as u64);
    syscall::debug_puts(b"\n");

    syscall::debug_puts(b"  [fat16_srv] layout: fat@");
    print_num(layout.fat_start as u64);
    syscall::debug_puts(b" rootdir@");
    print_num(layout.root_dir_start as u64);
    syscall::debug_puts(b"(");
    print_num(layout.root_dir_sectors as u64);
    syscall::debug_puts(b"s) data@");
    print_num(layout.data_start as u64);
    syscall::debug_puts(b"\n");

    // Read FAT table into a page.
    let fat_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [fat16_srv] fat alloc FAILED\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };
    // Read FAT sectors (up to 8 sectors = 4096 bytes = 1 page).
    let fat_sectors = (bpb.sectors_per_fat as u32).min(8);
    for i in 0..fat_sectors {
        let mut sec = [0u8; 512];
        if !blk.read_sector(layout.fat_start + i, &mut sec) {
            syscall::debug_puts(b"  [fat16_srv] failed to read FAT sector\n");
            loop {
                core::hint::spin_loop();
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

    syscall::debug_puts(b"  [fat16_srv] FAT loaded, ready\n");

    // Max clusters addressable by the FAT we loaded (fat_sectors * 256 entries per sector).
    let max_clusters = (fat_sectors as usize) * 256;

    // Open file table.
    let mut open_files = [OpenFile::empty(); MAX_OPEN_FILES];

    // Server loop.
    'msg_loop: loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                // data[0] = name_lo, data[1] = name_hi, data[2] = name_len|(reply<<32), data[3] = unused
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;

                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Convert to 8.3 format.
                let mut name83 = [0u8; 11];
                to_8_3(name, &mut name83);

                // Search root directory.
                let mut found = false;
                let mut first_cluster: u16 = 0;
                let mut file_size: u32 = 0;

                'search: for s in 0..layout.root_dir_sectors {
                    let mut sec = [0u8; 512];
                    if !blk.read_sector(layout.root_dir_start + s, &mut sec) {
                        break;
                    }
                    // 16 directory entries per sector (32 bytes each).
                    for e in 0..16 {
                        let off = e * 32;
                        let first_byte = sec[off];
                        if first_byte == 0x00 {
                            break 'search; // No more entries.
                        }
                        if first_byte == 0xE5 {
                            continue; // Deleted entry.
                        }
                        let attrs = sec[off + 11];
                        if attrs & 0x08 != 0 {
                            continue; // Volume label.
                        }
                        if attrs & 0x10 != 0 {
                            continue; // Subdirectory.
                        }

                        // Compare 8.3 name.
                        let entry_name = &sec[off..off + 11];
                        if entry_name == &name83 {
                            first_cluster = read_u16(&sec, off + 26);
                            file_size = read_u32(&sec, off + 28);
                            found = true;
                            break 'search;
                        }
                    }
                }

                if found {
                    // Allocate a handle.
                    let mut handle = u64::MAX;
                    for (i, f) in open_files.iter_mut().enumerate() {
                        if !f.active {
                            f.active = true;
                            f.first_cluster = first_cluster;
                            f.file_size = file_size;
                            f.writable = false;
                            f.dir_sector = 0;
                            f.dir_offset = 0;
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
                            file_size as u64,
                            my_aspace as u64,
                            0,
                        );
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_READ => {
                // data[0] = handle, data[1] = offset, data[2] = length|(reply<<32), data[3] = grant_va
                let handle = msg.data[0] as usize;
                let offset = msg.data[1] as u32;
                let length = (msg.data[2] & 0xFFFF_FFFF) as u32;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;
                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let file = &open_files[handle];
                if offset >= file.file_size {
                    // EOF - return 0 bytes.
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let avail = file.file_size - offset;
                let to_read = length.min(avail);

                // Walk FAT chain to find the cluster containing `offset`.
                let cluster_size = (layout.sectors_per_cluster as u32) * 512;
                let target_cluster_idx = offset / cluster_size;
                let offset_in_cluster = offset % cluster_size;

                let mut cluster = file.first_cluster;
                for _ in 0..target_cluster_idx {
                    cluster = fat_entry(fat_va, cluster);
                    if cluster >= 0xFFF8 {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue 'msg_loop;
                    }
                }

                // Read the sector within this cluster.
                let sector_in_cluster = offset_in_cluster / 512;
                let offset_in_sector = offset_in_cluster % 512;
                let sector = layout.data_start
                    + (cluster as u32 - 2) * layout.sectors_per_cluster
                    + sector_in_cluster;

                let mut sec = [0u8; 512];
                if !blk.read_sector(sector, &mut sec) {
                    syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                    continue;
                }

                let bytes_in_sector = (512 - offset_in_sector).min(to_read);

                if grant_va != 0 {
                    // Grant-based read: copy data into granted page.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            sec[offset_in_sector as usize..].as_ptr(),
                            grant_va as *mut u8,
                            bytes_in_sector as usize,
                        );
                    }
                    syscall::send(reply_port, FS_READ_OK, bytes_in_sector as u64, 0, 0, 0);
                } else {
                    // Inline read.
                    let inline_len = (bytes_in_sector as usize).min(MAX_INLINE);
                    let packed = pack_inline_data(
                        &sec[offset_in_sector as usize..(offset_in_sector as usize + inline_len)],
                    );
                    syscall::send(
                        reply_port,
                        FS_READ_OK,
                        inline_len as u64,
                        packed[0],
                        packed[1],
                        packed[2],
                    );
                }
            }

            FS_READDIR => {
                // data[0] = entry_index, data[2] = reply_port (low 32)
                let start_index = msg.data[0] as u32;
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

                // Iterate root directory from start_index.
                let entries_per_sector = 16u32; // 512 / 32
                let total_entries = (layout.root_dir_sectors * entries_per_sector) as u32;
                let mut found = false;

                let mut idx = start_index;
                while idx < total_entries {
                    let sector_idx = idx / entries_per_sector;
                    let entry_in_sector = idx % entries_per_sector;

                    let mut sec = [0u8; 512];
                    if !blk.read_sector(layout.root_dir_start + sector_idx, &mut sec) {
                        break;
                    }

                    let off = (entry_in_sector * 32) as usize;
                    let first_byte = sec[off];
                    if first_byte == 0x00 {
                        break; // No more entries.
                    }
                    idx += 1;
                    if first_byte == 0xE5 {
                        continue; // Deleted.
                    }
                    let attrs = sec[off + 11];
                    if attrs & 0x08 != 0 || attrs & 0x10 != 0 {
                        continue; // Volume label or subdirectory.
                    }

                    // Format 8.3 name with dot: "HELLO   TXT" → "HELLO.TXT"
                    let raw_name = &sec[off..off + 11];
                    let mut name = [0u8; 13]; // max "12345678.123"
                    let mut ni = 0;
                    // Copy base name (trimming trailing spaces).
                    let mut base_end = 8;
                    while base_end > 0 && raw_name[base_end - 1] == b' ' {
                        base_end -= 1;
                    }
                    for i in 0..base_end {
                        name[ni] = raw_name[i];
                        ni += 1;
                    }
                    // Copy extension (trimming trailing spaces).
                    let mut ext_end = 3;
                    while ext_end > 0 && raw_name[8 + ext_end - 1] == b' ' {
                        ext_end -= 1;
                    }
                    if ext_end > 0 {
                        name[ni] = b'.';
                        ni += 1;
                        for i in 0..ext_end {
                            name[ni] = raw_name[8 + i];
                            ni += 1;
                        }
                    }

                    let file_size = read_u32(&sec, off + 28);

                    // Pack name into 2 u64 words.
                    let mut name_lo = 0u64;
                    let mut name_hi = 0u64;
                    for i in 0..ni.min(8) {
                        name_lo |= (name[i] as u64) << (i * 8);
                    }
                    for i in 8..ni.min(16) {
                        name_hi |= (name[i] as u64) << ((i - 8) * 8);
                    }

                    // FS_READDIR_OK: data[0]=file_size, data[1]=name_lo, data[2]=name_hi, data[3]=next_index
                    syscall::send(
                        reply_port,
                        FS_READDIR_OK,
                        file_size as u64,
                        name_lo,
                        name_hi,
                        idx as u64,
                    );
                    found = true;
                    break;
                }

                if !found {
                    syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                }
            }

            FS_CREATE => {
                // data[0] = name_lo, data[1] = name_hi, data[2] = name_len|(reply<<32)
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;

                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let mut name83 = [0u8; 11];
                to_8_3(name, &mut name83);

                // Find free directory entry.
                let dir_slot = find_free_dir_entry(&blk, &layout, bpb.root_entry_count);
                if dir_slot.is_none() {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }
                let (dir_sector, dir_offset) = dir_slot.unwrap();

                // Allocate first cluster.
                let first_cluster = match alloc_cluster(fat_va, max_clusters) {
                    Some(c) => c,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };

                // Write directory entry with size=0 (will be updated on close).
                write_dir_entry(&blk, dir_sector, dir_offset, &name83, first_cluster, 0);

                // Allocate a handle.
                let mut handle = u64::MAX;
                for (i, f) in open_files.iter_mut().enumerate() {
                    if !f.active {
                        f.active = true;
                        f.writable = true;
                        f.first_cluster = first_cluster;
                        f.file_size = 0;
                        f.dir_sector = dir_sector;
                        f.dir_offset = dir_offset;
                        f.last_cluster = first_cluster;
                        handle = i as u64;
                        break;
                    }
                }
                if handle == u64::MAX {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_CREATE_OK, handle, 0, my_aspace as u64, 0);
                }
            }

            FS_WRITE => {
                // data[0] = handle, data[1] = data_len|(reply<<32), data[2] = grant_va, data[3] = unused
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[1] >> 32;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN_FILES
                    || !open_files[handle].active
                    || !open_files[handle].writable
                {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let cluster_size = (layout.sectors_per_cluster * 512) as usize;
                let mut written = 0usize;
                let file = &mut open_files[handle];

                while written < length {
                    let file_offset = file.file_size as usize;
                    let offset_in_cluster = file_offset % cluster_size;

                    // Check if we need a new cluster (not for the very first write if file_size==0).
                    if file_offset > 0 && offset_in_cluster == 0 {
                        // Current cluster is full, allocate new one.
                        let new_cluster = match alloc_cluster(fat_va, max_clusters) {
                            Some(c) => c,
                            None => break,
                        };
                        // Link old last_cluster -> new_cluster.
                        set_fat_entry(fat_va, file.last_cluster, new_cluster);
                        file.last_cluster = new_cluster;
                    }

                    // Compute physical sector.
                    let sector_in_cluster = (offset_in_cluster / 512) as u32;
                    let offset_in_sector = offset_in_cluster % 512;
                    let sector = layout.data_start
                        + (file.last_cluster as u32 - 2) * layout.sectors_per_cluster
                        + sector_in_cluster;

                    // How much can we write into this sector?
                    let space_in_sector = 512 - offset_in_sector;
                    let remaining = length - written;
                    let to_write = remaining.min(space_in_sector);

                    // Read-modify-write the sector.
                    let mut sec = [0u8; 512];
                    if offset_in_sector != 0 || to_write < 512 {
                        // Partial sector — must read existing data first.
                        blk.read_sector(sector, &mut sec);
                    }

                    // Copy data from grant page into sector buffer.
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

                syscall::send(reply_port, FS_WRITE_OK, written as u64, 0, 0, 0);
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN_FILES && open_files[handle].active {
                    if open_files[handle].writable {
                        // Flush FAT to disk.
                        flush_fat(&blk, fat_va, layout.fat_start, fat_sectors);
                        // Update directory entry with final file size.
                        let f = &open_files[handle];
                        let mut sec = [0u8; 512];
                        blk.read_sector(f.dir_sector, &mut sec);
                        write_u16(&mut sec, f.dir_offset + 26, f.first_cluster);
                        write_u32(&mut sec, f.dir_offset + 28, f.file_size);
                        blk.write_sector(f.dir_sector, &sec);
                    }
                    open_files[handle].active = false;
                }
            }

            FS_DELETE => {
                // data[0] = name_lo, data[1] = name_hi, data[2] = name_len|(reply<<32)
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let mut name83 = [0u8; 11];
                to_8_3(name, &mut name83);

                // Search root directory for the file.
                let mut found_sector = 0u32;
                let mut found_offset = 0usize;
                let mut first_cluster: u16 = 0;
                let mut found = false;

                'del_search: for s in 0..layout.root_dir_sectors {
                    let mut sec = [0u8; 512];
                    if !blk.read_sector(layout.root_dir_start + s, &mut sec) {
                        break;
                    }
                    for e in 0..16 {
                        let off = e * 32;
                        let first_byte = sec[off];
                        if first_byte == 0x00 {
                            break 'del_search;
                        }
                        if first_byte == 0xE5 {
                            continue;
                        }
                        let attrs = sec[off + 11];
                        if attrs & 0x18 != 0 {
                            continue;
                        } // Skip volume label + subdir
                        if &sec[off..off + 11] == &name83 {
                            first_cluster = read_u16(&sec, off + 26);
                            found_sector = layout.root_dir_start + s;
                            found_offset = off;
                            found = true;
                            break 'del_search;
                        }
                    }
                }

                if found {
                    // Close any open handles for this file.
                    for f in open_files.iter_mut() {
                        if f.active && f.first_cluster == first_cluster {
                            f.active = false;
                        }
                    }

                    // Mark directory entry as deleted.
                    let mut sec = [0u8; 512];
                    blk.read_sector(found_sector, &mut sec);
                    sec[found_offset] = 0xE5;
                    blk.write_sector(found_sector, &sec);

                    // Free FAT chain.
                    let mut cluster = first_cluster;
                    while cluster >= 2 && cluster < 0xFFF8 {
                        let next = fat_entry(fat_va, cluster);
                        set_fat_entry(fat_va, cluster, 0x0000);
                        cluster = next;
                    }

                    // Flush FAT to disk.
                    flush_fat(&blk, fat_va, layout.fat_start, fat_sectors);

                    syscall::send(reply_port, FS_DELETE_OK, 0, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            _ => {}
        }
    }

    loop {
        core::hint::spin_loop();
    }
}

/// Read a FAT16 entry for the given cluster number.
fn fat_entry(fat_va: usize, cluster: u16) -> u16 {
    let offset = (cluster as usize) * 2;
    let ptr = (fat_va + offset) as *const u16;
    unsafe { core::ptr::read(ptr) }
}
