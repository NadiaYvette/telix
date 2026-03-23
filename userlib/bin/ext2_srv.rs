#![no_std]
#![no_main]

//! ext2 filesystem server.
//!
//! Pure userspace process that reads an ext2 partition from blk_srv via IPC.
//! The ext2 partition starts at a byte offset passed as arg0 (default 16 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE requests.

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
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
const FS_CLOSE: u64 = 0x2400;
const FS_CREATE: u64 = 0x2500;
const FS_CREATE_OK: u64 = 0x2501;
const FS_WRITE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;
const FS_DELETE: u64 = 0x2700;
const FS_DELETE_OK: u64 = 0x2701;
const FS_ERROR: u64 = 0x2F00;

// File lock protocol.
const FS_FLOCK: u64 = 0x2800;
const FS_FLOCK_OK: u64 = 0x2801;
const FS_GETLK: u64 = 0x2810;
const FS_GETLK_OK: u64 = 0x2811;
const FS_SETLK: u64 = 0x2820;
const FS_SETLK_OK: u64 = 0x2821;
const FS_SETLKW: u64 = 0x2830;
const FS_SETLKW_OK: u64 = 0x2831;
const FS_LOCK_ERR: u64 = 0x28FF;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;
const ERR_AGAIN: u64 = 11;

const MAX_OPEN_FILES: usize = 8;
const MAX_INLINE: usize = 24;

// --- ext2 constants ---
const EXT2_SUPER_MAGIC: u16 = 0xEF53;
const EXT2_ROOT_INO: u32 = 2;

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
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        val >>= 4;
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

// --- ext2 on-disk structures ---

struct Superblock {
    inodes_count: u32,
    blocks_count: u32,
    free_blocks_count: u32,
    free_inodes_count: u32,
    first_data_block: u32,
    block_size: u32,       // in bytes (1024 << s_log_block_size)
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    log_block_size: u32,
}

struct BlockGroupDesc {
    block_bitmap: u32,     // block number of block bitmap
    inode_bitmap: u32,     // block number of inode bitmap
    inode_table: u32,      // block number of inode table start
}

#[derive(Clone, Copy)]
struct OpenFile {
    inode_num: u32,
    file_size: u32,
    mode: u16,
    uid: u16,
    gid: u16,
    block_ptrs: [u32; 15], // i_block[0..14]
    active: bool,
    writable: bool,
    pid: u32,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            inode_num: 0,
            file_size: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            block_ptrs: [0; 15],
            active: false,
            writable: false,
            pid: 0,
        }
    }
}

// --- Advisory file lock table ---

const MAX_LOCKS: usize = 32;
const MAX_LOCK_WAITERS: usize = 8;
const LK_RDLCK: u8 = 0;
const LK_WRLCK: u8 = 1;
const LK_UNLCK: u8 = 2;

#[derive(Clone, Copy)]
struct FileLock {
    active: bool,
    inode: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
}

impl FileLock {
    const fn empty() -> Self {
        Self { active: false, inode: 0, pid: 0, lock_type: 0, start: 0, len: 0 }
    }
}

#[derive(Clone, Copy)]
struct LockWaiter {
    active: bool,
    reply_port: u32,
    inode: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
}

impl LockWaiter {
    const fn empty() -> Self {
        Self { active: false, reply_port: 0, inode: 0, pid: 0, lock_type: 0, start: 0, len: 0 }
    }
}

fn ranges_overlap(s1: u64, l1: u64, s2: u64, l2: u64) -> bool {
    let e1 = if l1 == 0 { u64::MAX } else { s1.saturating_add(l1) };
    let e2 = if l2 == 0 { u64::MAX } else { s2.saturating_add(l2) };
    s1 < e2 && s2 < e1
}

fn ext2_lock_conflicts(
    locks: &[FileLock; MAX_LOCKS], inode: u32, pid: u32, lock_type: u8, start: u64, len: u64,
) -> bool {
    for lk in locks.iter() {
        if !lk.active || lk.inode != inode || lk.pid == pid { continue; }
        if lk.lock_type == LK_RDLCK && lock_type == LK_RDLCK { continue; }
        if ranges_overlap(lk.start, lk.len, start, len) { return true; }
    }
    false
}

fn ext2_find_conflict(
    locks: &[FileLock; MAX_LOCKS], inode: u32, pid: u32, lock_type: u8, start: u64, len: u64,
) -> Option<usize> {
    for (i, lk) in locks.iter().enumerate() {
        if !lk.active || lk.inode != inode || lk.pid == pid { continue; }
        if lk.lock_type == LK_RDLCK && lock_type == LK_RDLCK { continue; }
        if ranges_overlap(lk.start, lk.len, start, len) { return Some(i); }
    }
    None
}

fn ext2_acquire_lock(
    locks: &mut [FileLock; MAX_LOCKS], inode: u32, pid: u32, lock_type: u8, start: u64, len: u64,
) -> bool {
    for lk in locks.iter_mut() {
        if lk.active && lk.inode == inode && lk.pid == pid
            && ranges_overlap(lk.start, lk.len, start, len) { lk.active = false; }
    }
    for lk in locks.iter_mut() {
        if !lk.active {
            *lk = FileLock { active: true, inode, pid, lock_type, start, len };
            return true;
        }
    }
    false
}

fn ext2_release_locks(locks: &mut [FileLock; MAX_LOCKS], inode: u32, pid: u32, start: u64, len: u64) {
    for lk in locks.iter_mut() {
        if lk.active && lk.inode == inode && lk.pid == pid {
            if (start == 0 && len == 0) || ranges_overlap(lk.start, lk.len, start, len) {
                lk.active = false;
            }
        }
    }
}

fn ext2_try_wake_waiters(
    locks: &mut [FileLock; MAX_LOCKS], waiters: &mut [LockWaiter; MAX_LOCK_WAITERS], inode: u32,
) {
    for w in waiters.iter_mut() {
        if !w.active || w.inode != inode { continue; }
        if !ext2_lock_conflicts(locks, w.inode, w.pid, w.lock_type, w.start, w.len) {
            if ext2_acquire_lock(locks, w.inode, w.pid, w.lock_type, w.start, w.len) {
                syscall::send(w.reply_port, FS_FLOCK_OK, 0, 0, 0, 0);
            } else {
                syscall::send(w.reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
            }
            w.active = false;
        }
    }
}

// --- Block I/O client ---

struct BlkClient {
    blk_port: u32,
    blk_aspace: u32,
    reply_port: u32,
    scratch_va: usize,
    grant_va: usize,
    /// Byte offset of the ext2 partition within the disk image.
    partition_offset: u64,
}

impl BlkClient {
    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
    /// `out` must be <= 512 bytes. Only reads from the sector containing `off`.
    fn read_bytes(&self, off: u64, out: &mut [u8]) -> bool {
        let abs_off = self.partition_offset + off;
        let sector = abs_off / 512;
        let offset_in_sector = (abs_off % 512) as usize;

        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }

        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_READ, 0, sector * 512, d2, self.grant_va as u64);

        let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
            if rr.tag == IO_READ_OK && rr.data[0] == 512 {
                let copy_len = out.len().min(512 - offset_in_sector);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (self.scratch_va + offset_in_sector) as *const u8,
                        out.as_mut_ptr(),
                        copy_len,
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

    /// Read a full block (block_size bytes) into memory at `dest`.
    /// Block numbers are relative to partition start.
    fn read_block(&self, block_num: u32, block_size: u32, dest: usize) -> bool {
        let byte_off = (block_num as u64) * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = block_size / 512;
        if sectors == 0 {
            // block_size < 512: read partial sector
            let mut sec = [0u8; 512];
            if !self.read_bytes(byte_off, &mut sec) {
                return false;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    sec.as_ptr(),
                    dest as *mut u8,
                    block_size as usize,
                );
            }
            return true;
        }

        for s in 0..sectors {
            if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
                return false;
            }
            let sector_byte = abs_off + (s as u64) * 512;
            let d2 = 512u64 | ((self.reply_port as u64) << 32);
            syscall::send(self.blk_port, IO_READ, 0, sector_byte, d2, self.grant_va as u64);

            let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
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
            if !ok { return false; }
        }
        true
    }
    /// Write a 512-byte sector at absolute byte offset.
    fn write_sector(&self, abs_byte_off: u64, data: &[u8; 512]) -> bool {
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.scratch_va as *mut u8,
                512,
            );
        }
        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_WRITE, 0, abs_byte_off, d2, self.grant_va as u64);
        let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
            rr.tag == IO_WRITE_OK
        } else {
            false
        };
        syscall::revoke(self.blk_aspace, self.grant_va);
        ok
    }

    /// Read-modify-write: write `data` bytes at byte offset `off` (relative to partition).
    /// Must fit within a single 512-byte sector.
    fn write_bytes(&self, off: u64, data: &[u8]) -> bool {
        let abs_off = self.partition_offset + off;
        let sector_start = (abs_off / 512) * 512;
        let offset_in_sector = (abs_off % 512) as usize;

        // Read the existing sector.
        let mut sec = [0u8; 512];
        if !syscall::grant_pages(self.blk_aspace, self.scratch_va, self.grant_va, 1, false) {
            return false;
        }
        let d2 = 512u64 | ((self.reply_port as u64) << 32);
        syscall::send(self.blk_port, IO_READ, 0, sector_start, d2, self.grant_va as u64);
        let ok = if let Some(rr) = syscall::recv_msg(self.reply_port) {
            if rr.tag == IO_READ_OK {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.scratch_va as *const u8,
                        sec.as_mut_ptr(),
                        512,
                    );
                }
                true
            } else { false }
        } else { false };
        syscall::revoke(self.blk_aspace, self.grant_va);
        if !ok { return false; }

        // Patch in our data.
        let copy_len = data.len().min(512 - offset_in_sector);
        sec[offset_in_sector..offset_in_sector + copy_len].copy_from_slice(&data[..copy_len]);

        // Write sector back.
        self.write_sector(sector_start, &sec)
    }

    /// Write a full block from memory at `src` to disk.
    fn write_block(&self, block_num: u32, block_size: u32, src: usize) -> bool {
        let byte_off = (block_num as u64) * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = block_size / 512;
        if sectors == 0 {
            // block_size < 512
            let mut sec = [0u8; 512];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src as *const u8,
                    sec.as_mut_ptr(),
                    block_size as usize,
                );
            }
            return self.write_bytes(byte_off, &sec[..block_size as usize]);
        }

        for s in 0..sectors {
            let mut sec = [0u8; 512];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (src + (s as usize) * 512) as *const u8,
                    sec.as_mut_ptr(),
                    512,
                );
            }
            let sector_byte = abs_off + (s as u64) * 512;
            if !self.write_sector(sector_byte, &sec) {
                return false;
            }
        }
        true
    }
}

// --- ext2 inode reading ---

/// Read an inode from disk. Returns (mode, uid, gid, size, block_ptrs[0..14]).
fn read_inode(
    blk: &BlkClient,
    sb: &Superblock,
    bgd: &BlockGroupDesc,
    inode_num: u32,
) -> Option<(u16, u16, u16, u32, [u32; 15])> {
    // Inode numbers are 1-based.
    let idx = inode_num - 1;
    let inode_offset = (bgd.inode_table as u64) * (sb.block_size as u64)
        + (idx as u64) * (sb.inode_size as u64);

    // Read the inode (at least 128 bytes). We read in 512-byte sector chunks.
    let mut inode_buf = [0u8; 256];
    let read_len = (sb.inode_size as usize).min(256);

    // We may need to read across a sector boundary.
    let sector_off = inode_offset % 512;
    let bytes_in_first = (512 - sector_off as usize).min(read_len);

    if !blk.read_bytes(inode_offset, &mut inode_buf[..bytes_in_first]) {
        return None;
    }
    if bytes_in_first < read_len {
        if !blk.read_bytes(inode_offset + bytes_in_first as u64,
                           &mut inode_buf[bytes_in_first..read_len]) {
            return None;
        }
    }

    let mode = read_u16(&inode_buf, 0);
    let uid = read_u16(&inode_buf, 2);
    let size = read_u32(&inode_buf, 4);
    let gid = read_u16(&inode_buf, 24);

    let mut blocks = [0u32; 15];
    for i in 0..15 {
        blocks[i] = read_u32(&inode_buf, 40 + i * 4);
    }

    Some((mode, uid, gid, size, blocks))
}

/// Resolve a logical block index to a physical block number, following indirect pointers.
fn resolve_block(
    blk: &BlkClient,
    sb: &Superblock,
    block_ptrs: &[u32; 15],
    logical_block: u32,
    scratch_page: usize,
) -> Option<u32> {
    let ptrs_per_block = sb.block_size / 4;

    if logical_block < 12 {
        // Direct blocks.
        let b = block_ptrs[logical_block as usize];
        if b == 0 { return None; }
        return Some(b);
    }

    let logical_block = logical_block - 12;
    if logical_block < ptrs_per_block {
        // Single indirect.
        let ind_block = block_ptrs[12];
        if ind_block == 0 { return None; }
        if !blk.read_block(ind_block, sb.block_size, scratch_page) {
            return None;
        }
        let ptr = unsafe {
            core::ptr::read((scratch_page + (logical_block as usize) * 4) as *const u32)
        };
        if ptr == 0 { return None; }
        return Some(ptr);
    }

    let logical_block = logical_block - ptrs_per_block;
    if logical_block < ptrs_per_block * ptrs_per_block {
        // Double indirect.
        let dind_block = block_ptrs[13];
        if dind_block == 0 { return None; }
        if !blk.read_block(dind_block, sb.block_size, scratch_page) {
            return None;
        }
        let idx1 = logical_block / ptrs_per_block;
        let ind_block = unsafe {
            core::ptr::read((scratch_page + (idx1 as usize) * 4) as *const u32)
        };
        if ind_block == 0 { return None; }
        if !blk.read_block(ind_block, sb.block_size, scratch_page) {
            return None;
        }
        let idx2 = logical_block % ptrs_per_block;
        let ptr = unsafe {
            core::ptr::read((scratch_page + (idx2 as usize) * 4) as *const u32)
        };
        if ptr == 0 { return None; }
        return Some(ptr);
    }

    // Triple indirect — not supported for now.
    None
}

/// Look up a file by name in a directory inode. Returns inode number if found.
fn dir_lookup(
    blk: &BlkClient,
    sb: &Superblock,
    bgd: &BlockGroupDesc,
    dir_block_ptrs: &[u32; 15],
    dir_size: u32,
    name: &[u8],
    scratch_page: usize,
    block_buf: usize,
) -> Option<u32> {
    let block_size = sb.block_size;
    let num_blocks = (dir_size + block_size - 1) / block_size;

    for blk_idx in 0..num_blocks {
        let phys_block = match resolve_block(blk, sb, dir_block_ptrs, blk_idx, scratch_page) {
            Some(b) => b,
            None => continue,
        };

        if !blk.read_block(phys_block, block_size, block_buf) {
            continue;
        }

        let mut off = 0usize;
        while off + 8 <= block_size as usize {
            let inode = read_u32(unsafe {
                core::slice::from_raw_parts(block_buf as *const u8, block_size as usize)
            }, off);
            let rec_len = read_u16(unsafe {
                core::slice::from_raw_parts(block_buf as *const u8, block_size as usize)
            }, off + 4) as usize;
            let name_len = unsafe { *((block_buf + off + 6) as *const u8) } as usize;

            if rec_len == 0 { break; }
            if inode != 0 && name_len == name.len() {
                let entry_name = unsafe {
                    core::slice::from_raw_parts((block_buf + off + 8) as *const u8, name_len)
                };
                if entry_name == name {
                    return Some(inode);
                }
            }
            off += rec_len;
        }
    }
    None
}

/// Iterate directory entries. `start_index` is the byte offset to resume from.
/// Returns (inode, name, name_len, next_offset) or None if end.
fn dir_next_entry(
    blk: &BlkClient,
    sb: &Superblock,
    dir_block_ptrs: &[u32; 15],
    dir_size: u32,
    start_offset: u32,
    scratch_page: usize,
    block_buf: usize,
) -> Option<(u32, [u8; 16], usize, u32)> {
    let block_size = sb.block_size;
    let mut byte_off = start_offset;

    while byte_off < dir_size {
        let blk_idx = byte_off / block_size;
        let off_in_block = (byte_off % block_size) as usize;

        let phys_block = resolve_block(blk, sb, dir_block_ptrs, blk_idx, scratch_page)?;
        if !blk.read_block(phys_block, block_size, block_buf) {
            return None;
        }

        let buf = unsafe {
            core::slice::from_raw_parts(block_buf as *const u8, block_size as usize)
        };

        let mut off = off_in_block;
        while off + 8 <= block_size as usize {
            let inode = read_u32(buf, off);
            let rec_len = read_u16(buf, off + 4) as usize;
            let name_len = buf[off + 6] as usize;

            if rec_len == 0 { return None; }

            let next = (byte_off - off_in_block as u32) + off as u32 + rec_len as u32;

            if inode != 0 && name_len > 0 {
                // Skip "." and ".."
                let is_dot = name_len == 1 && buf[off + 8] == b'.';
                let is_dotdot = name_len == 2 && buf[off + 8] == b'.' && buf[off + 9] == b'.';

                if !is_dot && !is_dotdot {
                    let mut name = [0u8; 16];
                    let copy_len = name_len.min(16);
                    for i in 0..copy_len {
                        name[i] = buf[off + 8 + i];
                    }
                    return Some((inode, name, name_len, next));
                }
            }

            off += rec_len;
            byte_off = (byte_off - off_in_block as u32) + off as u32;
        }
        // Move to next block
        byte_off = ((byte_off / block_size) + 1) * block_size;
    }
    None
}

// --- ext2 write support ---

/// Allocate a block from the block bitmap. Returns block number or None.
fn alloc_block(
    blk: &BlkClient, sb: &mut Superblock, bgd: &BlockGroupDesc, bitmap_buf: usize,
) -> Option<u32> {
    if sb.free_blocks_count == 0 { return None; }
    // Read block bitmap.
    if !blk.read_block(bgd.block_bitmap, sb.block_size, bitmap_buf) { return None; }
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize)
    };
    // Scan for first zero bit, starting after first_data_block.
    let start = sb.first_data_block as usize;
    for bit in start..sb.blocks_count as usize {
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if byte < bitmap.len() && bitmap[byte] & mask == 0 {
            bitmap[byte] |= mask;
            // Write bitmap back.
            if !blk.write_block(bgd.block_bitmap, sb.block_size, bitmap_buf) { return None; }
            sb.free_blocks_count -= 1;
            return Some(bit as u32);
        }
    }
    None
}

/// Free a block in the block bitmap.
fn free_block(
    blk: &BlkClient, sb: &mut Superblock, bgd: &BlockGroupDesc,
    block_num: u32, bitmap_buf: usize,
) {
    if !blk.read_block(bgd.block_bitmap, sb.block_size, bitmap_buf) { return; }
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize)
    };
    let byte = block_num as usize / 8;
    let mask = 1u8 << (block_num as usize % 8);
    if byte < bitmap.len() {
        bitmap[byte] &= !mask;
        blk.write_block(bgd.block_bitmap, sb.block_size, bitmap_buf);
        sb.free_blocks_count += 1;
    }
}

/// Allocate an inode from the inode bitmap. Returns 1-based inode number or None.
fn alloc_inode(
    blk: &BlkClient, sb: &mut Superblock, bgd: &BlockGroupDesc, bitmap_buf: usize,
) -> Option<u32> {
    if sb.free_inodes_count == 0 { return None; }
    if !blk.read_block(bgd.inode_bitmap, sb.block_size, bitmap_buf) { return None; }
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize)
    };
    // Inode bitmap bit 0 = inode 1. Skip reserved inodes (0..10 typically, but scan from 0).
    // ext2 reserves inodes 1-10 by convention, but the bitmap should already mark them.
    for bit in 0..sb.inodes_per_group as usize {
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if byte < bitmap.len() && bitmap[byte] & mask == 0 {
            bitmap[byte] |= mask;
            if !blk.write_block(bgd.inode_bitmap, sb.block_size, bitmap_buf) { return None; }
            sb.free_inodes_count -= 1;
            return Some(bit as u32 + 1); // 1-based
        }
    }
    None
}

/// Free an inode in the inode bitmap.
fn free_inode(
    blk: &BlkClient, sb: &mut Superblock, bgd: &BlockGroupDesc,
    inode_num: u32, bitmap_buf: usize,
) {
    let bit = (inode_num - 1) as usize;
    if !blk.read_block(bgd.inode_bitmap, sb.block_size, bitmap_buf) { return; }
    let bitmap = unsafe {
        core::slice::from_raw_parts_mut(bitmap_buf as *mut u8, sb.block_size as usize)
    };
    let byte = bit / 8;
    let mask = 1u8 << (bit % 8);
    if byte < bitmap.len() {
        bitmap[byte] &= !mask;
        blk.write_block(bgd.inode_bitmap, sb.block_size, bitmap_buf);
        sb.free_inodes_count += 1;
    }
}

/// Write an inode to disk.
fn write_inode(
    blk: &BlkClient, sb: &Superblock, bgd: &BlockGroupDesc,
    inode_num: u32, mode: u16, uid: u16, gid: u16, size: u32, block_ptrs: &[u32; 15],
) -> bool {
    let idx = inode_num - 1;
    let inode_offset = (bgd.inode_table as u64) * (sb.block_size as u64)
        + (idx as u64) * (sb.inode_size as u64);

    // Read existing inode data to preserve fields we don't modify.
    let mut inode_buf = [0u8; 128];
    let sector_off = inode_offset % 512;
    let bytes_in_first = (512 - sector_off as usize).min(128);
    if !blk.read_bytes(inode_offset, &mut inode_buf[..bytes_in_first]) {
        return false;
    }
    if bytes_in_first < 128 {
        if !blk.read_bytes(inode_offset + bytes_in_first as u64,
                           &mut inode_buf[bytes_in_first..128]) {
            return false;
        }
    }

    // Patch fields.
    write_u16(&mut inode_buf, 0, mode);
    write_u16(&mut inode_buf, 2, uid);
    write_u32(&mut inode_buf, 4, size);
    write_u16(&mut inode_buf, 24, gid);
    // i_blocks: count of 512-byte blocks used by the file.
    let used_blocks = block_ptrs.iter().filter(|&&b| b != 0).count() as u32;
    write_u32(&mut inode_buf, 28, used_blocks * (sb.block_size / 512));
    for i in 0..15 {
        write_u32(&mut inode_buf, 40 + i * 4, block_ptrs[i]);
    }

    // Write back (may span sector boundary).
    if !blk.write_bytes(inode_offset, &inode_buf[..bytes_in_first]) {
        return false;
    }
    if bytes_in_first < 128 {
        if !blk.write_bytes(inode_offset + bytes_in_first as u64,
                            &inode_buf[bytes_in_first..128]) {
            return false;
        }
    }
    true
}

/// Flush superblock free counts back to disk.
fn flush_superblock(blk: &BlkClient, sb: &Superblock) {
    // Superblock is at partition offset 1024. We need to update offsets 12 and 16.
    let mut sb_buf = [0u8; 64];
    if !blk.read_bytes(1024, &mut sb_buf) { return; }
    write_u32(&mut sb_buf, 12, sb.free_blocks_count);
    write_u32(&mut sb_buf, 16, sb.free_inodes_count);
    blk.write_bytes(1024, &sb_buf);
}

/// Add a directory entry to the root directory.
/// Returns true on success.
fn dir_add_entry(
    blk: &BlkClient, sb: &Superblock,
    dir_block_ptrs: &[u32; 15], dir_size: u32,
    name: &[u8], name_len: usize, inode_num: u32, file_type: u8,
    scratch_page: usize, block_buf: usize,
) -> bool {
    let block_size = sb.block_size;
    let num_blocks = (dir_size + block_size - 1) / block_size;
    // Required space: 8 bytes header + name rounded up to 4-byte alignment.
    let needed = 8 + ((name_len + 3) & !3);

    for b in 0..num_blocks {
        let phys = match resolve_block(blk, sb, dir_block_ptrs, b, scratch_page) {
            Some(p) => p,
            None => continue,
        };
        if !blk.read_block(phys, block_size, block_buf) { continue; }

        let buf = unsafe {
            core::slice::from_raw_parts_mut(block_buf as *mut u8, block_size as usize)
        };
        let mut off = 0usize;
        while off < block_size as usize {
            let ino = read_u32(buf, off);
            let rec_len = read_u16(buf, off + 4) as usize;
            if rec_len == 0 { break; }
            let nlen = buf[off + 6] as usize;

            if ino == 0 && rec_len >= needed {
                // Free entry — reuse it.
                write_u32(buf, off, inode_num);
                write_u16(buf, off + 4, rec_len as u16);
                buf[off + 6] = name_len as u8;
                buf[off + 7] = file_type;
                buf[off + 8..off + 8 + name_len].copy_from_slice(&name[..name_len]);
                return blk.write_block(phys, block_size, block_buf);
            }

            // Check if current entry has slack space we can split.
            let actual = 8 + ((nlen + 3) & !3);
            if ino != 0 && rec_len >= actual + needed {
                // Split: shrink current entry, create new entry in slack.
                let new_off = off + actual;
                let new_rec_len = rec_len - actual;
                write_u16(buf, off + 4, actual as u16);
                write_u32(buf, new_off, inode_num);
                write_u16(buf, new_off + 4, new_rec_len as u16);
                buf[new_off + 6] = name_len as u8;
                buf[new_off + 7] = file_type;
                buf[new_off + 8..new_off + 8 + name_len].copy_from_slice(&name[..name_len]);
                return blk.write_block(phys, block_size, block_buf);
            }

            off += rec_len;
        }
    }
    false
}

/// Remove a directory entry by name. Returns the removed inode number, or None.
fn dir_remove_entry(
    blk: &BlkClient, sb: &Superblock,
    dir_block_ptrs: &[u32; 15], dir_size: u32,
    name: &[u8], name_len: usize,
    scratch_page: usize, block_buf: usize,
) -> Option<u32> {
    let block_size = sb.block_size;
    let num_blocks = (dir_size + block_size - 1) / block_size;

    for b in 0..num_blocks {
        let phys = match resolve_block(blk, sb, dir_block_ptrs, b, scratch_page) {
            Some(p) => p,
            None => continue,
        };
        if !blk.read_block(phys, block_size, block_buf) { continue; }

        let buf = unsafe {
            core::slice::from_raw_parts_mut(block_buf as *mut u8, block_size as usize)
        };
        let mut off = 0usize;
        let mut prev_off: Option<usize> = None;
        while off < block_size as usize {
            let ino = read_u32(buf, off);
            let rec_len = read_u16(buf, off + 4) as usize;
            if rec_len == 0 { break; }
            let nlen = buf[off + 6] as usize;

            if ino != 0 && nlen == name_len {
                let mut matches = true;
                for i in 0..name_len {
                    if buf[off + 8 + i] != name[i] { matches = false; break; }
                }
                if matches {
                    // Found it. Merge with previous entry or zero inode.
                    if let Some(po) = prev_off {
                        let prev_rec = read_u16(buf, po + 4) as usize;
                        write_u16(buf, po + 4, (prev_rec + rec_len) as u16);
                    } else {
                        write_u32(buf, off, 0); // zero inode
                    }
                    blk.write_block(phys, block_size, block_buf);
                    return Some(ino);
                }
            }

            prev_off = Some(off);
            off += rec_len;
        }
    }
    None
}

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [ext2_srv] starting\n");

    // Partition byte offset from arg0 (default 16 MiB).
    let partition_offset = if arg0 != 0 { arg0 } else { 16 * 1024 * 1024 };

    syscall::debug_puts(b"  [ext2_srv] partition offset=");
    print_num(partition_offset);
    syscall::debug_puts(b"\n");

    // Create port and register with name server.
    let port = syscall::port_create() as u32;
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"ext2", port);

    syscall::debug_puts(b"  [ext2_srv] registered, port=");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Look up cache_blk with retry.
    let blk_port = loop {
        if let Some(p) = syscall::ns_lookup(b"cache_blk") {
            break p;
        }
        for _ in 0..50 { syscall::yield_now(); }
    };

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
            syscall::debug_puts(b"  [ext2_srv] blk connect FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    } else {
        syscall::debug_puts(b"  [ext2_srv] blk no reply\n");
        loop { core::hint::spin_loop(); }
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ext2_srv] scratch alloc FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    };

    let blk = BlkClient {
        blk_port,
        blk_aspace,
        reply_port: blk_reply,
        scratch_va,
        grant_va: 0x6_0000_0000,
        partition_offset,
    };

    // --- Read superblock (at byte offset 1024 within the partition) ---
    let mut sb_buf = [0u8; 512];
    if !blk.read_bytes(1024, &mut sb_buf) {
        syscall::debug_puts(b"  [ext2_srv] failed to read superblock\n");
        loop { core::hint::spin_loop(); }
    }

    let magic = read_u16(&sb_buf, 56);
    if magic != EXT2_SUPER_MAGIC {
        syscall::debug_puts(b"  [ext2_srv] bad magic: ");
        print_hex(magic as u64);
        syscall::debug_puts(b"\n");
        loop { core::hint::spin_loop(); }
    }

    let log_block_size = read_u32(&sb_buf, 24);
    let block_size = 1024u32 << log_block_size;

    let mut sb = Superblock {
        inodes_count: read_u32(&sb_buf, 0),
        blocks_count: read_u32(&sb_buf, 4),
        free_blocks_count: read_u32(&sb_buf, 12),
        free_inodes_count: read_u32(&sb_buf, 16),
        first_data_block: read_u32(&sb_buf, 20),
        block_size,
        blocks_per_group: read_u32(&sb_buf, 32),
        inodes_per_group: read_u32(&sb_buf, 40),
        inode_size: read_u16(&sb_buf, 88),
        log_block_size,
    };

    syscall::debug_puts(b"  [ext2_srv] ext2: block_size=");
    print_num(block_size as u64);
    syscall::debug_puts(b" inodes=");
    print_num(sb.inodes_count as u64);
    syscall::debug_puts(b" blocks=");
    print_num(sb.blocks_count as u64);
    syscall::debug_puts(b" inode_size=");
    print_num(sb.inode_size as u64);
    syscall::debug_puts(b"\n");

    // --- Read block group descriptor table ---
    // BGD table starts at block 1 if block_size==1024, or block 0's second portion otherwise.
    // For 1024-byte blocks, the BGD table is at block 2 (byte 2048).
    let bgd_block = if block_size == 1024 { 2 } else { 1 };
    let mut bgd_buf = [0u8; 512];
    let bgd_byte_off = (bgd_block as u64) * (block_size as u64);
    if !blk.read_bytes(bgd_byte_off, &mut bgd_buf) {
        syscall::debug_puts(b"  [ext2_srv] failed to read BGD\n");
        loop { core::hint::spin_loop(); }
    }

    // We only support a single block group for the 16 MiB partition.
    let bgd = BlockGroupDesc {
        block_bitmap: read_u32(&bgd_buf, 0),
        inode_bitmap: read_u32(&bgd_buf, 4),
        inode_table: read_u32(&bgd_buf, 8),
    };

    syscall::debug_puts(b"  [ext2_srv] BGD0: inode_table=block ");
    print_num(bgd.inode_table as u64);
    syscall::debug_puts(b"\n");

    // Allocate a page for block reads (directory/indirect block data).
    let block_buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ext2_srv] block_buf alloc FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    };

    // Another page for indirect block resolution (to avoid stomping block_buf).
    let indirect_buf_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ext2_srv] indirect_buf alloc FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    };

    // Read root inode to verify.
    if let Some((mode, uid, gid, size, _blocks)) = read_inode(&blk, &sb, &bgd, EXT2_ROOT_INO) {
        syscall::debug_puts(b"  [ext2_srv] root inode: mode=");
        print_hex(mode as u64);
        syscall::debug_puts(b" uid=");
        print_num(uid as u64);
        syscall::debug_puts(b" size=");
        print_num(size as u64);
        syscall::debug_puts(b"\n");
    } else {
        syscall::debug_puts(b"  [ext2_srv] failed to read root inode\n");
        loop { core::hint::spin_loop(); }
    }

    syscall::debug_puts(b"  [ext2_srv] ready\n");

    // Open file table.
    let mut open_files = [OpenFile::empty(); MAX_OPEN_FILES];
    let mut file_locks = [FileLock::empty(); MAX_LOCKS];
    let mut lock_waiters = [LockWaiter::empty(); MAX_LOCK_WAITERS];

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Read root directory inode.
                let root = match read_inode(&blk, &sb, &bgd, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_blocks) = root;

                // Look up the file in the root directory.
                let inode_num = dir_lookup(
                    &blk, &sb, &bgd, &root_blocks, root_size, name,
                    indirect_buf_va, block_buf_va,
                );

                if let Some(ino) = inode_num {
                    // Read the file's inode.
                    if let Some((mode, uid, gid, size, blocks)) = read_inode(&blk, &sb, &bgd, ino) {
                        // Allocate a handle.
                        let mut handle = u64::MAX;
                        for (i, f) in open_files.iter_mut().enumerate() {
                            if !f.active {
                                f.active = true;
                                f.inode_num = ino;
                                f.file_size = size;
                                f.mode = mode;
                                f.uid = uid;
                                f.gid = gid;
                                f.block_ptrs = blocks;
                                f.pid = caller_pid;
                                handle = i as u64;
                                break;
                            }
                        }
                        if handle == u64::MAX {
                            syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                        } else {
                            syscall::send(reply_port, FS_OPEN_OK,
                                handle, size as u64, my_aspace as u64, 0);
                        }
                    } else {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_READ => {
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
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let avail = file.file_size - offset;
                let to_read = length.min(avail);

                // Determine which block and offset within block.
                let block_idx = offset / sb.block_size;
                let offset_in_block = (offset % sb.block_size) as usize;

                let phys_block = match resolve_block(
                    &blk, &sb, &file.block_ptrs, block_idx, indirect_buf_va,
                ) {
                    Some(b) => b,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };

                if !blk.read_block(phys_block, sb.block_size, block_buf_va) {
                    syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                    continue;
                }

                let bytes_in_block = ((sb.block_size as usize) - offset_in_block).min(to_read as usize);

                if grant_va != 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            (block_buf_va + offset_in_block) as *const u8,
                            grant_va as *mut u8,
                            bytes_in_block,
                        );
                    }
                    syscall::send_nb(reply_port, FS_READ_OK, bytes_in_block as u64, 0);
                } else {
                    let inline_len = bytes_in_block.min(MAX_INLINE);
                    let data = unsafe {
                        core::slice::from_raw_parts(
                            (block_buf_va + offset_in_block) as *const u8,
                            inline_len,
                        )
                    };
                    let packed = pack_inline_data(data);
                    syscall::send(reply_port, FS_READ_OK,
                        inline_len as u64, packed[0], packed[1], packed[2]);
                }
            }

            FS_READDIR => {
                let start_offset = msg.data[0] as u32;
                let reply_port = (msg.data[2] & 0xFFFF_FFFF) as u32;

                // Read root directory inode.
                let root = match read_inode(&blk, &sb, &bgd, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_blocks) = root;

                match dir_next_entry(
                    &blk, &sb, &root_blocks, root_size, start_offset,
                    indirect_buf_va, block_buf_va,
                ) {
                    Some((inode_num, name, name_len, next_offset)) => {
                        // Get file size from inode.
                        let file_size = if let Some((_, _, _, size, _)) = read_inode(&blk, &sb, &bgd, inode_num) {
                            size
                        } else {
                            0
                        };

                        // Pack name into 2 u64 words.
                        let mut name_lo = 0u64;
                        let mut name_hi = 0u64;
                        for i in 0..name_len.min(8) {
                            name_lo |= (name[i] as u64) << (i * 8);
                        }
                        for i in 8..name_len.min(16) {
                            name_hi |= (name[i] as u64) << ((i - 8) * 8);
                        }

                        syscall::send(reply_port, FS_READDIR_OK,
                            file_size as u64, name_lo, name_hi, next_offset as u64);
                    }
                    None => {
                        syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                    }
                }
            }

            FS_STAT => {
                // data[0] = handle, data[2] = reply_port (low 32)
                let handle = msg.data[0] as usize;
                let reply_port = (msg.data[2] & 0xFFFF_FFFF) as u32;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let file = &open_files[handle];
                // FS_STAT_OK: data[0] = size, data[1] = mode, data[2] = uid|(gid<<16), data[3] = inode
                let uid_gid = (file.uid as u64) | ((file.gid as u64) << 16);
                syscall::send(reply_port, FS_STAT_OK,
                    file.file_size as u64, file.mode as u64, uid_gid, file.inode_num as u64);
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN_FILES && open_files[handle].active {
                    let ino = open_files[handle].inode_num;
                    let pid = open_files[handle].pid;
                    if open_files[handle].writable {
                        let f = &open_files[handle];
                        write_inode(&blk, &sb, &bgd, f.inode_num,
                            f.mode, f.uid, f.gid, f.file_size, &f.block_ptrs);
                        flush_superblock(&blk, &sb);
                    }
                    open_files[handle].active = false;
                    open_files[handle].writable = false;
                    // Release locks if no other handles from same PID to same inode.
                    let mut still_open = false;
                    for f in open_files.iter() {
                        if f.active && f.inode_num == ino && f.pid == pid {
                            still_open = true;
                            break;
                        }
                    }
                    if !still_open {
                        ext2_release_locks(&mut file_locks, ino, pid, 0, 0);
                        ext2_try_wake_waiters(&mut file_locks, &mut lock_waiters, ino);
                    }
                }
            }

            FS_CREATE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Allocate inode.
                let ino = match alloc_inode(&blk, &mut sb, &bgd, block_buf_va) {
                    Some(i) => i,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };

                // Allocate first data block.
                let first_block = match alloc_block(&blk, &mut sb, &bgd, block_buf_va) {
                    Some(b) => b,
                    None => {
                        // Roll back inode.
                        free_inode(&blk, &mut sb, &bgd, ino, block_buf_va);
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };

                // Zero out the first data block.
                unsafe {
                    core::ptr::write_bytes(block_buf_va as *mut u8, 0, sb.block_size as usize);
                }
                blk.write_block(first_block, sb.block_size, block_buf_va);

                // Initialize inode: regular file, mode 0644.
                let mut block_ptrs = [0u32; 15];
                block_ptrs[0] = first_block;
                write_inode(&blk, &sb, &bgd, ino, 0o100644, 0, 0, 0, &block_ptrs);

                // Add directory entry to root.
                let root = match read_inode(&blk, &sb, &bgd, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_blocks) = root;
                if !dir_add_entry(&blk, &sb, &root_blocks, root_size,
                    name, name_len.min(16), ino, 1, indirect_buf_va, block_buf_va) {
                    syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                    continue;
                }

                flush_superblock(&blk, &sb);

                // Allocate handle.
                let mut handle = u64::MAX;
                for (i, f) in open_files.iter_mut().enumerate() {
                    if !f.active {
                        f.active = true;
                        f.writable = true;
                        f.inode_num = ino;
                        f.file_size = 0;
                        f.mode = 0o100644;
                        f.uid = 0;
                        f.gid = 0;
                        f.block_ptrs = block_ptrs;
                        f.pid = caller_pid;
                        handle = i as u64;
                        break;
                    }
                }
                if handle == u64::MAX {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_CREATE_OK,
                        handle, 0, my_aspace as u64, 0);
                }
            }

            FS_WRITE => {
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[1] >> 32) as u32;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active
                    || !open_files[handle].writable
                {
                    if reply_port != 0 {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    }
                    continue;
                }

                let mut written = 0usize;
                let mut offset = open_files[handle].file_size;

                while written < length {
                    let block_idx = offset / sb.block_size;
                    let offset_in_block = (offset % sb.block_size) as usize;
                    let space_in_block = (sb.block_size as usize) - offset_in_block;
                    let chunk = (length - written).min(space_in_block);

                    // Ensure we have a block allocated.
                    if block_idx < 12 {
                        if open_files[handle].block_ptrs[block_idx as usize] == 0 {
                            match alloc_block(&blk, &mut sb, &bgd, block_buf_va) {
                                Some(b) => {
                                    open_files[handle].block_ptrs[block_idx as usize] = b;
                                    // Zero the new block.
                                    unsafe {
                                        core::ptr::write_bytes(
                                            block_buf_va as *mut u8, 0,
                                            sb.block_size as usize,
                                        );
                                    }
                                    blk.write_block(b, sb.block_size, block_buf_va);
                                }
                                None => break,
                            }
                        }
                    } else {
                        // Single indirect block support.
                        let ind_idx = block_idx - 12;
                        let ptrs_per_block = sb.block_size / 4;
                        if ind_idx < ptrs_per_block {
                            // Ensure indirect block exists.
                            if open_files[handle].block_ptrs[12] == 0 {
                                match alloc_block(&blk, &mut sb, &bgd, block_buf_va) {
                                    Some(b) => {
                                        open_files[handle].block_ptrs[12] = b;
                                        unsafe {
                                            core::ptr::write_bytes(
                                                block_buf_va as *mut u8, 0,
                                                sb.block_size as usize,
                                            );
                                        }
                                        blk.write_block(b, sb.block_size, block_buf_va);
                                    }
                                    None => break,
                                }
                            }
                            // Read indirect block.
                            let ind_blk = open_files[handle].block_ptrs[12];
                            if !blk.read_block(ind_blk, sb.block_size, indirect_buf_va) {
                                break;
                            }
                            let ptr = unsafe {
                                core::ptr::read(
                                    (indirect_buf_va + (ind_idx as usize) * 4) as *const u32
                                )
                            };
                            if ptr == 0 {
                                match alloc_block(&blk, &mut sb, &bgd, block_buf_va) {
                                    Some(b) => {
                                        unsafe {
                                            core::ptr::write(
                                                (indirect_buf_va + (ind_idx as usize) * 4) as *mut u32,
                                                b,
                                            );
                                        }
                                        blk.write_block(ind_blk, sb.block_size, indirect_buf_va);
                                        // Zero new data block.
                                        unsafe {
                                            core::ptr::write_bytes(
                                                block_buf_va as *mut u8, 0,
                                                sb.block_size as usize,
                                            );
                                        }
                                        blk.write_block(b, sb.block_size, block_buf_va);
                                    }
                                    None => break,
                                }
                            }
                        } else {
                            break; // Beyond single indirect — not supported.
                        }
                    }

                    // Resolve the physical block.
                    let phys = match resolve_block(
                        &blk, &sb, &open_files[handle].block_ptrs, block_idx, indirect_buf_va,
                    ) {
                        Some(b) => b,
                        None => break,
                    };

                    // Read-modify-write if partial block.
                    if offset_in_block != 0 || chunk < sb.block_size as usize {
                        if !blk.read_block(phys, sb.block_size, block_buf_va) {
                            break;
                        }
                    }

                    // Copy data from grant page.
                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (grant_va + written) as *const u8,
                                (block_buf_va + offset_in_block) as *mut u8,
                                chunk,
                            );
                        }
                    }

                    if !blk.write_block(phys, sb.block_size, block_buf_va) {
                        break;
                    }

                    written += chunk;
                    offset += chunk as u32;
                }

                open_files[handle].file_size = offset;

                if reply_port != 0 {
                    syscall::send(reply_port, FS_WRITE_OK, written as u64, 0, 0, 0);
                }
            }

            FS_DELETE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                // Look up file to get inode number.
                let root = match read_inode(&blk, &sb, &bgd, EXT2_ROOT_INO) {
                    Some(r) => r,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };
                let (_, _, _, root_size, root_blocks) = root;

                let ino = match dir_lookup(
                    &blk, &sb, &bgd, &root_blocks, root_size, name,
                    indirect_buf_va, block_buf_va,
                ) {
                    Some(i) => i,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                        continue;
                    }
                };

                // Read inode to get block pointers.
                let (_, _, _, _size, block_ptrs) = match read_inode(&blk, &sb, &bgd, ino) {
                    Some(r) => r,
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                        continue;
                    }
                };

                // Free direct blocks.
                for i in 0..12 {
                    if block_ptrs[i] != 0 {
                        free_block(&blk, &mut sb, &bgd, block_ptrs[i], block_buf_va);
                    }
                }
                // Free single indirect block and its children.
                if block_ptrs[12] != 0 {
                    if blk.read_block(block_ptrs[12], sb.block_size, block_buf_va) {
                        let ptrs_per_block = sb.block_size / 4;
                        for i in 0..ptrs_per_block as usize {
                            let ptr = unsafe {
                                core::ptr::read((block_buf_va + i * 4) as *const u32)
                            };
                            if ptr != 0 {
                                free_block(&blk, &mut sb, &bgd, ptr, indirect_buf_va);
                            }
                        }
                    }
                    free_block(&blk, &mut sb, &bgd, block_ptrs[12], block_buf_va);
                }

                // Free inode.
                free_inode(&blk, &mut sb, &bgd, ino, block_buf_va);

                // Zero out the inode on disk.
                let zero_ptrs = [0u32; 15];
                write_inode(&blk, &sb, &bgd, ino, 0, 0, 0, 0, &zero_ptrs);

                // Remove directory entry.
                dir_remove_entry(&blk, &sb, &root_blocks, root_size,
                    name, name_len.min(16), indirect_buf_va, block_buf_va);

                flush_superblock(&blk, &sb);

                syscall::send(reply_port, FS_DELETE_OK, 0, 0, 0, 0);
            }

            FS_FLOCK => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let operation = (msg.data[0] >> 32) as i32;
                let pid = msg.data[1] as u32;
                let reply_port = (msg.data[2] >> 32) as u32;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0);
                    continue;
                }
                let ino = open_files[handle].inode_num;
                let is_unlock = operation & 8 != 0;
                let is_nb = operation & 4 != 0;
                let lock_type = if operation & 2 != 0 { LK_WRLCK }
                                else if operation & 1 != 0 { LK_RDLCK }
                                else { LK_UNLCK };

                if is_unlock {
                    ext2_release_locks(&mut file_locks, ino, pid, 0, 0);
                    ext2_try_wake_waiters(&mut file_locks, &mut lock_waiters, ino);
                    syscall::send(reply_port, FS_FLOCK_OK, 0, 0, 0, 0);
                } else if !ext2_lock_conflicts(&file_locks, ino, pid, lock_type, 0, 0) {
                    if ext2_acquire_lock(&mut file_locks, ino, pid, lock_type, 0, 0) {
                        syscall::send(reply_port, FS_FLOCK_OK, 0, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                    }
                } else if is_nb {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                } else {
                    let mut queued = false;
                    for w in lock_waiters.iter_mut() {
                        if !w.active {
                            *w = LockWaiter {
                                active: true, reply_port, inode: ino,
                                pid, lock_type, start: 0, len: 0,
                            };
                            queued = true;
                            break;
                        }
                    }
                    if !queued {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                    }
                }
            }

            FS_SETLK | FS_SETLKW => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let lock_type = ((msg.data[0] >> 32) & 0xFFFF) as u8;
                let pid = msg.data[3] as u32;
                let start = msg.data[1];
                let len = (msg.data[2] & 0xFFFF_FFFF) as u64;
                let reply_port = (msg.data[2] >> 32) as u32;
                let blocking = msg.tag == FS_SETLKW;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0);
                    continue;
                }
                let ino = open_files[handle].inode_num;

                if lock_type == LK_UNLCK {
                    ext2_release_locks(&mut file_locks, ino, pid, start, len);
                    ext2_try_wake_waiters(&mut file_locks, &mut lock_waiters, ino);
                    let ok_tag = if blocking { FS_SETLKW_OK } else { FS_SETLK_OK };
                    syscall::send(reply_port, ok_tag, 0, 0, 0, 0);
                } else if !ext2_lock_conflicts(&file_locks, ino, pid, lock_type, start, len) {
                    if ext2_acquire_lock(&mut file_locks, ino, pid, lock_type, start, len) {
                        let ok_tag = if blocking { FS_SETLKW_OK } else { FS_SETLK_OK };
                        syscall::send(reply_port, ok_tag, 0, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                    }
                } else if !blocking {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                } else {
                    let mut queued = false;
                    for w in lock_waiters.iter_mut() {
                        if !w.active {
                            *w = LockWaiter {
                                active: true, reply_port, inode: ino,
                                pid, lock_type, start, len,
                            };
                            queued = true;
                            break;
                        }
                    }
                    if !queued {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                    }
                }
            }

            FS_GETLK => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let lock_type = ((msg.data[0] >> 32) & 0xFFFF) as u8;
                let pid = msg.data[3] as u32;
                let start = msg.data[1];
                let len = (msg.data[2] & 0xFFFF_FFFF) as u64;
                let reply_port = (msg.data[2] >> 32) as u32;

                if handle >= MAX_OPEN_FILES || !open_files[handle].active {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0);
                    continue;
                }
                let ino = open_files[handle].inode_num;

                match ext2_find_conflict(&file_locks, ino, pid, lock_type, start, len) {
                    Some(idx) => {
                        let lk = &file_locks[idx];
                        let d0 = (lk.lock_type as u64) | ((lk.pid as u64) << 32);
                        syscall::send(reply_port, FS_GETLK_OK, d0, lk.start, lk.len, 0);
                    }
                    None => {
                        let d0 = LK_UNLCK as u64;
                        syscall::send(reply_port, FS_GETLK_OK, d0, 0, 0, 0);
                    }
                }
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
