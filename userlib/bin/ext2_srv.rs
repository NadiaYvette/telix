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
const FS_ERROR: u64 = 0x2F00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

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
    block_size: u32,       // in bytes (1024 << s_log_block_size)
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    log_block_size: u32,
}

struct BlockGroupDesc {
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

    let sb = Superblock {
        inodes_count: read_u32(&sb_buf, 0),
        blocks_count: read_u32(&sb_buf, 4),
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
                    open_files[handle].active = false;
                }
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
