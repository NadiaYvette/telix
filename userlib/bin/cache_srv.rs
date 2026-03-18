#![no_std]
#![no_main]

//! Block device cache server.
//!
//! Sits between filesystem servers (fat16_srv) and the block device server (blk_srv),
//! presenting the same IO_READ/IO_WRITE protocol. Implements a 64-entry direct-mapped
//! sector cache with write-through policy.
//!
//! Registers as "cache_blk" with the name server.

extern crate userlib;

use userlib::syscall;

// --- I/O protocol constants ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;
const IO_STAT: u64 = 0x400;
const IO_STAT_OK: u64 = 0x401;
const IO_CLOSE: u64 = 0x500;
const IO_ERROR: u64 = 0xF00;

// Cache stats query tag.
const CACHE_STATS: u64 = 0xC100;
const CACHE_STATS_OK: u64 = 0xC101;

const SECTOR_SIZE: usize = 512;
const CACHE_SLOTS: usize = 64;
const INVALID_SECTOR: u64 = u64::MAX;

/// Grant VA where clients (fat16_srv) grant their scratch pages to us.
const CLIENT_GRANT_VA: usize = 0x6_0000_0000;
/// Grant VA where we grant our scratch page to blk_srv.
const BLK_GRANT_VA: usize = 0x5_0000_0000;

// --- Cache entry ---
#[derive(Clone, Copy)]
struct CacheEntry {
    sector: u64,
    valid: bool,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self { sector: INVALID_SECTOR, valid: false }
    }
}

// --- Block client (for talking to blk_srv) ---
struct BlkClient {
    blk_port: u32,
    blk_aspace: u32,
    reply_port: u32,
    scratch_va: usize,
}

impl BlkClient {
    fn read_sector(&self, sector: u64, out: &mut [u8; 512]) -> bool {
        // Grant our scratch page to blk_srv.
        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, BLK_GRANT_VA, 1, false) {
            return false;
        }

        let offset = sector * 512;
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_READ, 0, offset, d2, BLK_GRANT_VA as u64);

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

        syscall::revoke(self.blk_aspace, BLK_GRANT_VA);
        ok
    }

    fn write_sector(&self, sector: u64, data: &[u8; 512]) -> bool {
        // Copy data into scratch page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.scratch_va as *mut u8,
                512,
            );
        }

        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, BLK_GRANT_VA, 1, false) {
            return false;
        }

        let offset = sector * 512;
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_WRITE, 0, offset, d2, BLK_GRANT_VA as u64);

        let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
            rr.tag == IO_WRITE_OK
        } else {
            false
        };

        syscall::revoke(self.blk_aspace, BLK_GRANT_VA);
        ok
    }
}

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

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [cache_srv] starting\n");

    // Create port and register as "cache_blk".
    let port = syscall::port_create() as u32;
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"cache_blk", port);

    syscall::debug_puts(b"  [cache_srv] registered on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Look up blk_srv with retry.
    let blk_port = loop {
        if let Some(p) = syscall::ns_lookup(b"blk") {
            break p;
        }
        for _ in 0..50 { syscall::yield_now(); }
    };

    syscall::debug_puts(b"  [cache_srv] blk_srv on port ");
    print_num(blk_port as u64);
    syscall::debug_puts(b"\n");

    // Connect to blk_srv.
    let blk_reply = syscall::port_create() as u32;
    {
        let (n0, n1, _) = syscall::pack_name(b"blk");
        let d2 = 3u64 | ((blk_reply as u64) << 32);
        syscall::send(blk_port, IO_CONNECT, n0, n1, d2, 0);
    }

    let (blk_aspace, disk_capacity) = if let Some(reply) = syscall::recv_msg(blk_reply) {
        if reply.tag == IO_CONNECT_OK {
            (reply.data[2] as u32, reply.data[1])
        } else {
            syscall::debug_puts(b"  [cache_srv] blk connect FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    } else {
        syscall::debug_puts(b"  [cache_srv] blk no reply\n");
        loop { core::hint::spin_loop(); }
    };

    syscall::debug_puts(b"  [cache_srv] connected to blk_srv, capacity=");
    print_num(disk_capacity);
    syscall::debug_puts(b" bytes\n");

    // Allocate scratch page for blk_srv grants.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [cache_srv] scratch alloc FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
    };

    // Allocate cache data page (64 slots × 512 bytes = 32 KiB, fits in one 64 KiB alloc page).
    let cache_data_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [cache_srv] cache data alloc FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    };

    // Initialize cache entries.
    let mut entries = [CacheEntry::empty(); CACHE_SLOTS];
    let mut hits: u64 = 0;
    let mut misses: u64 = 0;

    syscall::debug_puts(b"  [cache_srv] ready (64-entry sector cache)\n");

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            IO_CONNECT => {
                let reply_port = (msg.data[2] >> 32) as u32;
                // Reply with disk capacity and our aspace_id (same protocol as blk_srv).
                syscall::send(reply_port, IO_CONNECT_OK,
                    0, disk_capacity, my_aspace as u64, 0);
            }

            IO_READ => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let grant_va = msg.data[3] as usize;

                let sector = (offset / SECTOR_SIZE) as u64;
                let slot = (sector as usize) % CACHE_SLOTS;

                if entries[slot].valid && entries[slot].sector == sector {
                    // Cache hit — copy from cache data directly.
                    hits += 1;
                    let bytes_read = length.min(SECTOR_SIZE);

                    if grant_va != 0 {
                        let src = (cache_data_va + slot * SECTOR_SIZE) as *const u8;
                        let dst = grant_va as *mut u8;
                        unsafe {
                            core::ptr::copy_nonoverlapping(src, dst, bytes_read);
                        }
                        syscall::send_nb(reply_port, IO_READ_OK, bytes_read as u64, 0);
                    } else {
                        // Inline read (shouldn't happen from fat16_srv, but handle it).
                        let mut buf = [0u8; 512];
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (cache_data_va + slot * SECTOR_SIZE) as *const u8,
                                buf.as_mut_ptr(),
                                SECTOR_SIZE,
                            );
                        }
                        let inline_len = bytes_read.min(40);
                        let packed = pack_inline_data(&buf[..inline_len]);
                        syscall::send(reply_port, IO_READ_OK,
                            inline_len as u64, packed[0], packed[1], packed[2]);
                    }
                } else {
                    // Cache miss — read from blk_srv.
                    misses += 1;
                    let mut buf = [0u8; 512];

                    if blk.read_sector(sector, &mut buf) {
                        // Populate cache slot.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                buf.as_ptr(),
                                (cache_data_va + slot * SECTOR_SIZE) as *mut u8,
                                SECTOR_SIZE,
                            );
                        }
                        entries[slot] = CacheEntry { sector, valid: true };

                        let bytes_read = length.min(SECTOR_SIZE);

                        if grant_va != 0 {
                            let dst = grant_va as *mut u8;
                            unsafe {
                                core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, bytes_read);
                            }
                            syscall::send_nb(reply_port, IO_READ_OK, bytes_read as u64, 0);
                        } else {
                            let inline_len = bytes_read.min(40);
                            let packed = pack_inline_data(&buf[..inline_len]);
                            syscall::send(reply_port, IO_READ_OK,
                                inline_len as u64, packed[0], packed[1], packed[2]);
                        }
                    } else {
                        syscall::send_nb(reply_port, IO_ERROR, 1, 0);
                    }
                }
            }

            IO_WRITE => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let grant_va = msg.data[3] as usize;

                let sector = (offset / SECTOR_SIZE) as u64;
                let slot = (sector as usize) % CACHE_SLOTS;

                let mut buf = [0u8; 512];

                // Copy data from client's grant page.
                if grant_va != 0 {
                    let bytes_to_write = length.min(SECTOR_SIZE);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            grant_va as *const u8,
                            buf.as_mut_ptr(),
                            bytes_to_write,
                        );
                    }
                }

                // Write-through: forward to blk_srv.
                if blk.write_sector(sector, &buf) {
                    // Update cache slot.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            buf.as_ptr(),
                            (cache_data_va + slot * SECTOR_SIZE) as *mut u8,
                            SECTOR_SIZE,
                        );
                    }
                    entries[slot] = CacheEntry { sector, valid: true };

                    syscall::send_nb(reply_port, IO_WRITE_OK, length.min(SECTOR_SIZE) as u64, 0);
                } else {
                    syscall::send_nb(reply_port, IO_ERROR, 1, 0);
                }
            }

            IO_STAT => {
                let reply_port = (msg.data[0] >> 32) as u32;
                syscall::send_nb(reply_port, IO_STAT_OK, disk_capacity, 0);
            }

            IO_CLOSE => {}

            CACHE_STATS => {
                let reply_port = (msg.data[0] >> 32) as u32;
                syscall::send(reply_port, CACHE_STATS_OK, hits, misses, 0, 0);
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}

fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(40) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}
