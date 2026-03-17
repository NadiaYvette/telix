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

// --- FS protocol constants (served by this server) ---
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_CLOSE: u64 = 0x2400;
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
}

impl OpenFile {
    const fn empty() -> Self {
        Self { first_cluster: 0, file_size: 0, active: false }
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

#[allow(dead_code)]
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
        let d = (val & 0xF) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        val >>= 4;
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
    blk_port: u32,
    blk_aspace: u32,
    reply_port: u32,
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
    let port = syscall::port_create() as u32;
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"fat16", port);

    syscall::debug_puts(b"  [fat16_srv] registered, port=");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Look up blk_srv with retry.
    let blk_port = loop {
        if let Some(p) = syscall::ns_lookup(b"blk") {
            break p;
        }
        for _ in 0..50 { syscall::yield_now(); }
    };

    syscall::debug_puts(b"  [fat16_srv] blk_srv on port ");
    print_num(blk_port as u64);
    syscall::debug_puts(b"\n");

    // Connect to blk_srv.
    let blk_reply = syscall::port_create() as u32;
    {
        let (n0, n1, _) = syscall::pack_name(b"blk");
        let d2 = 3u64 | ((blk_reply as u64) << 32);
        syscall::send(blk_port, IO_CONNECT, n0, n1, d2, 0);
    }

    let blk_aspace = if let Some(reply) = syscall::recv_msg(blk_reply) {
        if reply.tag == IO_CONNECT_OK {
            reply.data[2] as u32
        } else {
            syscall::debug_puts(b"  [fat16_srv] blk connect FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    } else {
        syscall::debug_puts(b"  [fat16_srv] blk no reply\n");
        loop { core::hint::spin_loop(); }
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [fat16_srv] scratch alloc FAILED\n");
            loop { core::hint::spin_loop(); }
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
        loop { core::hint::spin_loop(); }
    }

    // Verify boot signature.
    if boot_sector[510] != 0x55 || boot_sector[511] != 0xAA {
        syscall::debug_puts(b"  [fat16_srv] bad boot signature\n");
        loop { core::hint::spin_loop(); }
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
            loop { core::hint::spin_loop(); }
        }
    };
    // Read FAT sectors (up to 8 sectors = 4096 bytes = 1 page).
    let fat_sectors = (bpb.sectors_per_fat as u32).min(8);
    for i in 0..fat_sectors {
        let mut sec = [0u8; 512];
        if !blk.read_sector(layout.fat_start + i, &mut sec) {
            syscall::debug_puts(b"  [fat16_srv] failed to read FAT sector\n");
            loop { core::hint::spin_loop(); }
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

    // Open file table.
    let mut open_files = [OpenFile::empty(); MAX_OPEN_FILES];

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                // data[0] = name_lo, data[1] = name_hi, data[2] = name_len|(reply<<32), data[3] = unused
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;

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
                            handle = i as u64;
                            break;
                        }
                    }
                    if handle == u64::MAX {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, FS_OPEN_OK,
                            handle, file_size as u64, my_aspace as u64, 0);
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
                let reply_port = (msg.data[2] >> 32) as u32;
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
                        continue;
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
                    syscall::send_nb(reply_port, FS_READ_OK, bytes_in_sector as u64, 0);
                } else {
                    // Inline read.
                    let inline_len = (bytes_in_sector as usize).min(MAX_INLINE);
                    let packed = pack_inline_data(
                        &sec[offset_in_sector as usize
                            ..(offset_in_sector as usize + inline_len)],
                    );
                    syscall::send(reply_port, FS_READ_OK,
                        inline_len as u64, packed[0], packed[1], packed[2]);
                }
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN_FILES {
                    open_files[handle].active = false;
                }
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}

/// Read a FAT16 entry for the given cluster number.
fn fat_entry(fat_va: usize, cluster: u16) -> u16 {
    let offset = (cluster as usize) * 2;
    let ptr = (fat_va + offset) as *const u16;
    unsafe { core::ptr::read(ptr) }
}
