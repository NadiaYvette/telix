#![no_std]
#![no_main]

//! Page cache server.
//!
//! Sits between filesystem servers (fat16_srv) and the block device server (blk_srv),
//! presenting the same IO_READ/IO_WRITE protocol. Implements a 128-entry page cache
//! with 4 KiB (MMUPAGE_SIZE) granularity, clock-LRU eviction, read-ahead, and
//! write-through policy.
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
const IO_BARRIER: u64 = 0x600;
const IO_BARRIER_OK: u64 = 0x601;
const IO_ERROR: u64 = 0xF00;

const CACHE_STATS: u64 = 0xC100;
const CACHE_STATS_OK: u64 = 0xC101;

const SECTOR_SIZE: usize = 512;
const MMUPAGE_SIZE: usize = 4096;
const SECTORS_PER_PAGE: usize = MMUPAGE_SIZE / SECTOR_SIZE; // 8
const CACHE_ENTRIES: usize = 128;
const HASH_SIZE: usize = 256;
const INVALID: u64 = u64::MAX;
const DATA_ALLOC_PAGES: usize = CACHE_ENTRIES; // 128 pages × MMUPAGE_SIZE (4096) = 512 KiB

/// Grant VA where clients (fat16_srv) grant their scratch pages to us.
const CLIENT_GRANT_VA: usize = 0x6_0000_0000;
/// Grant VA where we grant our scratch page to blk_srv.
const BLK_GRANT_VA: usize = 0x5_0000_0000;

// --- Cache entry (one per 4K page) ---
#[derive(Clone, Copy)]
struct CacheEntry {
    page_number: u64, // INVALID if empty
    referenced: bool,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self {
            page_number: INVALID,
            referenced: false,
        }
    }
}

// --- Hash table entry for O(1) lookup ---
#[derive(Clone, Copy)]
struct HashEntry {
    page_number: u64,
    slot: u8,
    occupied: bool,
}

impl HashEntry {
    const fn empty() -> Self {
        Self {
            page_number: 0,
            slot: 0,
            occupied: false,
        }
    }
}

// --- Page cache state ---
struct PageCache {
    entries: [CacheEntry; CACHE_ENTRIES],
    hash: [HashEntry; HASH_SIZE],
    clock_hand: usize,
    data_va: usize, // base of 512 KiB data pool
    hits: u64,
    misses: u64,
    occupied: u32,
}

impl PageCache {
    fn new(data_va: usize) -> Self {
        Self {
            entries: [CacheEntry::empty(); CACHE_ENTRIES],
            hash: [HashEntry::empty(); HASH_SIZE],
            clock_hand: 0,
            data_va,
            hits: 0,
            misses: 0,
            occupied: 0,
        }
    }

    /// Look up a page in the hash table. Returns cache slot index.
    fn lookup(&self, page_number: u64) -> Option<usize> {
        let mut idx = (page_number as usize) % HASH_SIZE;
        for _ in 0..HASH_SIZE {
            let h = &self.hash[idx];
            if !h.occupied {
                return None;
            }
            if h.page_number == page_number {
                return Some(h.slot as usize);
            }
            idx = (idx + 1) % HASH_SIZE;
        }
        None
    }

    /// Insert a page→slot mapping into the hash table.
    fn hash_insert(&mut self, page_number: u64, slot: usize) {
        let mut idx = (page_number as usize) % HASH_SIZE;
        for _ in 0..HASH_SIZE {
            if !self.hash[idx].occupied {
                self.hash[idx] = HashEntry {
                    page_number,
                    slot: slot as u8,
                    occupied: true,
                };
                return;
            }
            idx = (idx + 1) % HASH_SIZE;
        }
    }

    /// Remove a page from the hash table, rehashing displaced entries.
    fn hash_remove(&mut self, page_number: u64) {
        let mut idx = (page_number as usize) % HASH_SIZE;
        // Find the entry.
        loop {
            if !self.hash[idx].occupied {
                return; // Not found.
            }
            if self.hash[idx].page_number == page_number {
                break;
            }
            idx = (idx + 1) % HASH_SIZE;
        }
        // Remove it.
        self.hash[idx].occupied = false;
        // Rehash displaced entries.
        let mut j = (idx + 1) % HASH_SIZE;
        loop {
            if !self.hash[j].occupied {
                break;
            }
            let entry = self.hash[j];
            self.hash[j].occupied = false;
            // Re-insert.
            let mut k = (entry.page_number as usize) % HASH_SIZE;
            loop {
                if !self.hash[k].occupied {
                    self.hash[k] = entry;
                    break;
                }
                k = (k + 1) % HASH_SIZE;
            }
            j = (j + 1) % HASH_SIZE;
        }
    }

    /// Find a victim slot via clock-LRU sweep. Evicts the victim and returns its index.
    fn clock_evict(&mut self) -> usize {
        // If there are empty slots, use one.
        for i in 0..CACHE_ENTRIES {
            if self.entries[i].page_number == INVALID {
                return i;
            }
        }
        // Clock sweep.
        loop {
            let slot = self.clock_hand;
            self.clock_hand = (self.clock_hand + 1) % CACHE_ENTRIES;
            if self.entries[slot].referenced {
                self.entries[slot].referenced = false;
            } else {
                // Evict this entry.
                self.hash_remove(self.entries[slot].page_number);
                self.entries[slot].page_number = INVALID;
                self.occupied -= 1;
                return slot;
            }
        }
    }

    /// Fill a cache slot by reading 8 sectors from blk_srv.
    fn fill_page(&mut self, blk: &BlkClient, slot: usize, page_number: u64, max_sectors: u64) {
        let base_sector = page_number * SECTORS_PER_PAGE as u64;
        let dest_base = self.data_va + slot * MMUPAGE_SIZE;
        for i in 0..SECTORS_PER_PAGE {
            let sector = base_sector + i as u64;
            if sector < max_sectors {
                let mut buf = [0u8; SECTOR_SIZE];
                if blk.read_sector(sector, &mut buf) {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            buf.as_ptr(),
                            (dest_base + i * SECTOR_SIZE) as *mut u8,
                            SECTOR_SIZE,
                        );
                    }
                } else {
                    // Zero-fill on read failure.
                    unsafe {
                        core::ptr::write_bytes(
                            (dest_base + i * SECTOR_SIZE) as *mut u8,
                            0,
                            SECTOR_SIZE,
                        );
                    }
                }
            } else {
                // Beyond disk capacity — zero-fill.
                unsafe {
                    core::ptr::write_bytes(
                        (dest_base + i * SECTOR_SIZE) as *mut u8,
                        0,
                        SECTOR_SIZE,
                    );
                }
            }
        }
    }

    /// Read handler. Returns data pointer and length, or None on error.
    fn read(
        &mut self,
        blk: &BlkClient,
        offset: usize,
        length: usize,
        max_sectors: u64,
    ) -> Option<(*const u8, usize)> {
        let page_number = (offset / MMUPAGE_SIZE) as u64;
        let off_in_page = offset % MMUPAGE_SIZE;
        let bytes = length.min(MMUPAGE_SIZE - off_in_page);

        if let Some(slot) = self.lookup(page_number) {
            // Cache hit.
            self.entries[slot].referenced = true;
            self.hits += 1;
            let ptr = (self.data_va + slot * MMUPAGE_SIZE + off_in_page) as *const u8;
            Some((ptr, bytes))
        } else {
            // Cache miss.
            self.misses += 1;
            let slot = self.clock_evict();
            self.fill_page(blk, slot, page_number, max_sectors);
            self.entries[slot] = CacheEntry {
                page_number,
                referenced: true,
            };
            self.hash_insert(page_number, slot);
            self.occupied += 1;
            let ptr = (self.data_va + slot * MMUPAGE_SIZE + off_in_page) as *const u8;
            Some((ptr, bytes))
        }
    }

    /// Write handler. Updates cache if page is present (write-no-allocate).
    fn write_update(&mut self, offset: usize, data: *const u8, length: usize) {
        let page_number = (offset / MMUPAGE_SIZE) as u64;
        let off_in_page = offset % MMUPAGE_SIZE;
        if let Some(slot) = self.lookup(page_number) {
            let bytes = length.min(MMUPAGE_SIZE - off_in_page);
            let dst = (self.data_va + slot * MMUPAGE_SIZE + off_in_page) as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(data, dst, bytes);
            }
            self.entries[slot].referenced = true;
        }
    }
}

// --- Block client (for talking to blk_srv) ---
struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
}

impl BlkClient {
    fn read_sector(&self, sector: u64, out: &mut [u8; 512]) -> bool {
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
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.scratch_va as *mut u8, 512);
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
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"cache_blk", port);

    syscall::debug_puts(b"  [cache_srv] registered on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Look up blk_srv with bounded retry.
    let blk_port = {
        let mut retries = 2000;
        loop {
            if let Some(p) = syscall::ns_lookup(b"blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [cache_srv] blk_srv not found, serving without backing\n");
                break u64::MAX;
            }
            for _ in 0..50 {
                syscall::yield_now();
            }
        }
    };

    syscall::debug_puts(b"  [cache_srv] blk_srv on port ");
    print_num(blk_port as u64);
    syscall::debug_puts(b"\n");

    // Connect to blk_srv.
    let blk_reply = syscall::port_create();
    {
        let (n0, n1, _) = syscall::pack_name(b"blk");
        let d2 = 3u64 | ((blk_reply as u64) << 32);
        syscall::send(blk_port, IO_CONNECT, n0, n1, d2, 0);
    }

    let (blk_aspace, disk_capacity) = if let Some(reply) = syscall::recv_msg(blk_reply) {
        if reply.tag == IO_CONNECT_OK {
            (reply.data[2], reply.data[1])
        } else {
            syscall::debug_puts(b"  [cache_srv] blk connect FAILED\n");
            loop {
                core::hint::spin_loop();
            }
        }
    } else {
        syscall::debug_puts(b"  [cache_srv] blk no reply\n");
        loop {
            core::hint::spin_loop();
        }
    };

    let max_sectors = disk_capacity / SECTOR_SIZE as u64;

    syscall::debug_puts(b"  [cache_srv] connected to blk_srv, capacity=");
    print_num(disk_capacity);
    syscall::debug_puts(b" bytes\n");

    // Allocate scratch page for blk_srv grants.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [cache_srv] scratch alloc FAILED\n");
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
    };

    // Allocate 512 KiB data pool (128 entries × 4 KiB = 8 allocation pages).
    let data_va = match syscall::mmap_anon(0, DATA_ALLOC_PAGES, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [cache_srv] data pool alloc FAILED\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    let mut cache = PageCache::new(data_va);

    syscall::debug_puts(b"  [cache_srv] ready (128-entry page cache, 512 KiB)\n");

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            IO_CONNECT => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(
                    reply_port,
                    IO_CONNECT_OK,
                    0,
                    disk_capacity,
                    my_aspace as u64,
                    0,
                );
            }

            IO_READ => {
                let request_id = msg.data[0];
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if let Some((ptr, bytes_read)) = cache.read(&blk, offset, length, max_sectors) {
                    if grant_va != 0 {
                        let dst = grant_va as *mut u8;
                        unsafe {
                            core::ptr::copy_nonoverlapping(ptr, dst, bytes_read);
                        }
                        syscall::send_nb_4(
                            reply_port,
                            IO_READ_OK,
                            bytes_read as u64,
                            request_id,
                            0,
                            0,
                        );
                    } else {
                        // Inline read.
                        let inline_len = bytes_read.min(40);
                        let mut buf = [0u8; 40];
                        unsafe {
                            core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), inline_len);
                        }
                        let packed = pack_inline_data(&buf[..inline_len]);
                        syscall::send(
                            reply_port,
                            IO_READ_OK,
                            inline_len as u64,
                            request_id,
                            packed[0],
                            packed[1],
                        );
                    }
                } else {
                    syscall::send_nb(reply_port, IO_ERROR, 1, 0);
                }
            }

            IO_WRITE => {
                let request_id = msg.data[0];
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                let sector = (offset / SECTOR_SIZE) as u64;
                let mut buf = [0u8; 512];

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
                    // Update cache if page is present (write-no-allocate).
                    cache.write_update(offset, buf.as_ptr(), length.min(SECTOR_SIZE));
                    syscall::send_nb_4(
                        reply_port,
                        IO_WRITE_OK,
                        length.min(SECTOR_SIZE) as u64,
                        request_id,
                        0,
                        0,
                    );
                } else {
                    syscall::send_nb(reply_port, IO_ERROR, 1, 0);
                }
            }

            IO_STAT => {
                let reply_port = msg.data[0] >> 32;
                syscall::send_nb(reply_port, IO_STAT_OK, disk_capacity, 0);
            }

            IO_CLOSE => {}

            IO_BARRIER => {
                let reply_port = msg.data[2] >> 32;
                syscall::send_nb(reply_port, IO_BARRIER_OK, 0, 0);
            }

            CACHE_STATS => {
                let reply_port = msg.data[0] >> 32;
                syscall::send(
                    reply_port,
                    CACHE_STATS_OK,
                    cache.hits,
                    cache.misses,
                    CACHE_ENTRIES as u64,
                    cache.occupied as u64,
                );
            }

            _ => {}
        }
    }

    loop {
        core::hint::spin_loop();
    }
}

fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(40) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}
