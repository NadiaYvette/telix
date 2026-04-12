#![no_std]
#![no_main]

//! APFS read-only filesystem server.
//!
//! Pure userspace process that reads an APFS partition from cache_blk via IPC.
//! The APFS partition starts at a byte offset passed as arg0 (default 48 MiB).
//! Serves FS_OPEN / FS_READ / FS_READDIR / FS_STAT / FS_CLOSE / FS_READLINK.
//! All write operations return ERR_INVALID (read-only driver).

extern crate userlib;

use userlib::syscall;

// --- I/O protocol constants (for talking to cache_blk / blk_srv) ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;

// --- FS protocol constants (served by this server) ---
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_OPEN_LONG: u64 = 0x2002;
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
const FS_STAT_LONG: u64 = 0x2302;
const FS_CLOSE: u64 = 0x2400;
const FS_CREATE: u64 = 0x2500;
const FS_WRITE: u64 = 0x2600;
const FS_DELETE: u64 = 0x2700;
const FS_MKDIR: u64 = 0x2A00;
const FS_UNLINK: u64 = 0x2A20;
const FS_CHMOD: u64 = 0x2E00;
const FS_UTIMENS: u64 = 0x2900;
const FS_SYMLINK: u64 = 0x2C00;
const FS_READLINK: u64 = 0x2C10;
const FS_READLINK_OK: u64 = 0x2C11;
const FS_LINK: u64 = 0x2C20;
const FS_RENAME: u64 = 0x2C30;
const FS_CHOWN: u64 = 0x2C40;
const FS_TRUNCATE: u64 = 0x2C50;
const FS_STATFS: u64 = 0x2C60;
const FS_STATFS_OK: u64 = 0x2C61;
const FS_MKNOD: u64 = 0x2D40;
const FS_ERROR: u64 = 0x2F00;
const FS_FSYNC: u64 = 0x2B00;

const ERR_NOT_FOUND: u64 = 1;
const ERR_IO: u64 = 2;
const ERR_INVALID: u64 = 3;

/// VFS grants its scratch page here for long-path lookups.
const VFS_LONG_PATH_SCRATCH_VA: usize = 0x5_0000_0000;

const MAX_OPEN: usize = 16;
const MAX_INLINE: usize = 24;
const PAGE_SIZE: usize = 4096;

// --- APFS on-disk constants ---
const NX_MAGIC: u32 = 0x4253584E; // 'NXSB' little-endian = bytes 'N','X','S','B'
const APFS_MAGIC: u32 = 0x42535041; // 'APSB' little-endian = bytes 'A','P','S','B'

// Object header size: o_cksum(8) + o_oid(8) + o_xid(8) + o_type(4) + o_subtype(4) = 32
const OBJ_PHYS_SIZE: usize = 32;

// Object type constants
const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x00000001;
const OBJECT_TYPE_BTREE: u32 = 0x00000002;
const OBJECT_TYPE_BTREE_NODE: u32 = 0x00000003;
const OBJECT_TYPE_OMAP: u32 = 0x0000000b;

// Storage type masks
const OBJ_STORAGETYPE_MASK: u32 = 0xc0000000;
const OBJ_PHYSICAL: u32 = 0x40000000;
const OBJ_EPHEMERAL: u32 = 0x80000000;
const OBJECT_TYPE_MASK: u32 = 0x0000ffff;

// B-tree node header: after obj_phys_t
const BTN_FLAGS_OFF: usize = OBJ_PHYS_SIZE;      // u16
const BTN_LEVEL_OFF: usize = OBJ_PHYS_SIZE + 2;  // u16
const BTN_NKEYS_OFF: usize = OBJ_PHYS_SIZE + 4;  // u32
const BTN_TOC_OFF: usize = OBJ_PHYS_SIZE + 8;    // nloc_t (off u16, len u16)
const BTN_FREE_OFF: usize = OBJ_PHYS_SIZE + 12;  // nloc_t
const BTN_KEY_FREE_OFF: usize = OBJ_PHYS_SIZE + 16; // nloc_t
const BTN_VAL_FREE_OFF: usize = OBJ_PHYS_SIZE + 20; // nloc_t
const BTN_DATA_OFF: usize = OBJ_PHYS_SIZE + 24;  // 56 bytes total

// B-tree node flags
const BTNODE_ROOT: u16 = 0x0001;
const BTNODE_LEAF: u16 = 0x0002;
const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;

// btree_info_t size: btree_info_fixed_t(16) + bt_longest_key(4) + bt_longest_val(4) + bt_key_count(8) + bt_node_count(8) = 40
const BTREE_INFO_SIZE: usize = 40;

// B-tree flags
const BTREE_PHYSICAL: u32 = 0x00000010;

// APFS file-system record types (top 4 bits of obj_id_and_type)
const APFS_TYPE_INODE: u8 = 3;
const APFS_TYPE_XATTR: u8 = 4;
const APFS_TYPE_FILE_EXTENT: u8 = 8;
const APFS_TYPE_DIR_REC: u8 = 9;

// Key masks
const OBJ_ID_MASK: u64 = 0x0fffffffffffffffu64;
const OBJ_TYPE_MASK: u64 = 0xf000000000000000u64;
const OBJ_TYPE_SHIFT: u32 = 60;

// Inode constants
const ROOT_DIR_INO_NUM: u64 = 2;

// Inode extended field types
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const INO_EXT_TYPE_NAME: u8 = 4;

// File modes
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

// Directory entry file types (from flags & DREC_TYPE_MASK)
const DREC_TYPE_MASK: u16 = 0x000F;
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
const DT_LNK: u16 = 10;

// xattr flags
const XATTR_DATA_EMBEDDED: u16 = 0x0002;

// Block cache
const CACHE_SLOTS: usize = 64;

// j_inode_val_t offsets (relative to start of value)
const IVAL_PARENT_ID: usize = 0;
const IVAL_PRIVATE_ID: usize = 8;
const IVAL_CREATE_TIME: usize = 16;
const IVAL_MOD_TIME: usize = 24;
const IVAL_CHANGE_TIME: usize = 32;
const IVAL_ACCESS_TIME: usize = 40;
const IVAL_INTERNAL_FLAGS: usize = 48;
const IVAL_NCHILDREN_NLINK: usize = 56; // union: nchildren(i32) or nlink(i32)
const IVAL_DEFAULT_PROT_CLASS: usize = 60;
const IVAL_WRITE_GEN_COUNTER: usize = 64;
const IVAL_BSD_FLAGS: usize = 68;
const IVAL_OWNER: usize = 72;
const IVAL_GROUP: usize = 76;
const IVAL_MODE: usize = 80;
const IVAL_PAD1: usize = 82;
const IVAL_UNCOMPRESSED_SIZE: usize = 84;
const IVAL_XFIELDS: usize = 92; // xfields[] starts here

// j_dstream_t offsets (40 bytes)
const DSTREAM_SIZE: usize = 0;
const DSTREAM_ALLOCED_SIZE: usize = 8;

// =====================================================================
// Helpers
// =====================================================================

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

// --- Little-endian read helpers (APFS is little-endian on disk) ---

fn read_le16(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

fn read_le32(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

fn read_le64(buf: &[u8], off: usize) -> u64 {
    (buf[off] as u64)
        | ((buf[off + 1] as u64) << 8)
        | ((buf[off + 2] as u64) << 16)
        | ((buf[off + 3] as u64) << 24)
        | ((buf[off + 4] as u64) << 32)
        | ((buf[off + 5] as u64) << 40)
        | ((buf[off + 6] as u64) << 48)
        | ((buf[off + 7] as u64) << 56)
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

// =====================================================================
// Fletcher-64 checksum (APFS uses this for all object headers)
// =====================================================================

fn fletcher64(data: &[u8]) -> u64 {
    // APFS Fletcher-64: checksum field (first 8 bytes) must be zeroed before
    // computing. We process 32-bit LE words starting at byte 0.
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    let nwords = data.len() / 4;
    for i in 0..nwords {
        let word = read_le32(data, i * 4) as u64;
        sum1 = (sum1 + word) % 0xFFFFFFFF;
        sum2 = (sum2 + sum1) % 0xFFFFFFFF;
    }
    let ck1 = 0xFFFFFFFF - ((sum1 + sum2) % 0xFFFFFFFF);
    let ck2 = 0xFFFFFFFF - ((sum1 + ck1) % 0xFFFFFFFF);
    (ck2 << 32) | ck1
}

/// Verify Fletcher-64 checksum of an object block.
fn verify_checksum(block_va: usize, block_size: u32) -> bool {
    let buf = unsafe {
        core::slice::from_raw_parts(block_va as *const u8, block_size as usize)
    };
    let stored = read_le64(buf, 0);
    // Zero the checksum field for computation.
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    let nwords = buf.len() / 4;
    for i in 0..nwords {
        let word = if i < 2 {
            0u64 // zero out the 8-byte checksum field (words 0 and 1)
        } else {
            read_le32(buf, i * 4) as u64
        };
        sum1 = (sum1 + word) % 0xFFFFFFFF;
        sum2 = (sum2 + sum1) % 0xFFFFFFFF;
    }
    let ck1 = 0xFFFFFFFF - ((sum1 + sum2) % 0xFFFFFFFF);
    let ck2 = 0xFFFFFFFF - ((sum1 + ck1) % 0xFFFFFFFF);
    let computed = (ck2 << 32) | ck1;
    computed == stored
}

// =====================================================================
// Data structures
// =====================================================================

#[derive(Clone, Copy)]
struct NxSuperblock {
    block_size: u32,
    block_count: u64,
    omap_oid: u64,       // physical OID of container omap
    xp_desc_base: u64,   // checkpoint descriptor area base block
    xp_desc_blocks: u32, // number of blocks in descriptor area
    xp_desc_len: u32,    // how many descriptors used by current checkpoint
    xp_desc_index: u32,  // index of first descriptor in current checkpoint
    xp_data_base: u64,   // checkpoint data area base block
    xp_data_blocks: u32,
    xp_data_len: u32,
    xp_data_index: u32,
    xid: u64,            // transaction ID (from o_xid)
    fs_oid: [u64; 4],    // volume OIDs
}

#[derive(Clone, Copy)]
struct ApfsVolume {
    omap_oid: u64,       // physical OID of volume's object map
    root_tree_oid: u64,  // virtual OID of root file-system B-tree
    xid: u64,            // volume's transaction ID
}

#[derive(Clone, Copy)]
struct ApfsInode {
    ino: u64,
    parent_id: u64,
    private_id: u64,
    mode: u16,
    owner: u32,
    group: u32,
    nlink: u32,
    size: u64,
}

impl ApfsInode {
    const fn empty() -> Self {
        Self {
            ino: 0,
            parent_id: 0,
            private_id: 0,
            mode: 0,
            owner: 0,
            group: 0,
            nlink: 0,
            size: 0,
        }
    }

    fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }

    fn is_symlink(&self) -> bool {
        (self.mode & S_IFMT) == S_IFLNK
    }
}

#[derive(Clone, Copy)]
struct OpenHandle {
    active: bool,
    inode: ApfsInode,
    pid: u32,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self {
            active: false,
            inode: ApfsInode::empty(),
            pid: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct CacheSlot {
    block_num: u64,
    valid: bool,
    age: u32,
}

impl CacheSlot {
    const fn empty() -> Self {
        Self {
            block_num: u64::MAX,
            valid: false,
            age: 0,
        }
    }
}

// =====================================================================
// Block I/O client (talks to cache_blk)
// =====================================================================

struct BlkClient {
    blk_port: u64,
    blk_aspace: u64,
    reply_port: u64,
    scratch_va: usize,
    grant_va: usize,
    partition_offset: u64,
}

impl BlkClient {
    /// Read `len` bytes at byte offset `off` (relative to partition start) into `out`.
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

    /// Read a full block (block_size bytes) into memory at `dest` VA.
    fn read_block(&self, block_num: u64, block_size: u32, dest: usize) -> bool {
        let byte_off = block_num * (block_size as u64);
        let abs_off = self.partition_offset + byte_off;
        let sectors = block_size / 512;

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
            if !ok {
                return false;
            }
        }
        true
    }
}

// =====================================================================
// Block cache
// =====================================================================

static mut CACHE_META: [CacheSlot; CACHE_SLOTS] = [CacheSlot::empty(); CACHE_SLOTS];
static mut CACHE_DATA_VA: usize = 0;
static mut CACHE_AGE: u32 = 0;

fn cache_init() {
    match syscall::mmap_anon(0, CACHE_SLOTS, 1) {
        Some(va) => unsafe {
            CACHE_DATA_VA = va;
        },
        None => {
            syscall::debug_puts(b"  [apfs_srv] cache alloc FAILED\n");
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

/// Read a block via cache; returns VA of the cached block data.
fn cache_read(blk: &BlkClient, block_num: u64, block_size: u32) -> Option<usize> {
    unsafe {
        for i in 0..CACHE_SLOTS {
            if CACHE_META[i].valid && CACHE_META[i].block_num == block_num {
                CACHE_AGE += 1;
                CACHE_META[i].age = CACHE_AGE;
                return Some(CACHE_DATA_VA + i * PAGE_SIZE);
            }
        }

        let mut victim = 0usize;
        let mut min_age = u32::MAX;
        for i in 0..CACHE_SLOTS {
            if !CACHE_META[i].valid {
                victim = i;
                break;
            }
            if CACHE_META[i].age < min_age {
                min_age = CACHE_META[i].age;
                victim = i;
            }
        }

        let dest = CACHE_DATA_VA + victim * PAGE_SIZE;
        if !blk.read_block(block_num, block_size, dest) {
            return None;
        }

        CACHE_AGE += 1;
        CACHE_META[victim] = CacheSlot {
            block_num,
            valid: true,
            age: CACHE_AGE,
        };

        Some(dest)
    }
}

/// Read a block into the cache and return a slice of the cached data.
fn cache_read_slice(blk: &BlkClient, block_num: u64, bs: u32) -> Option<&'static [u8]> {
    let va = cache_read(blk, block_num, bs)?;
    Some(unsafe { core::slice::from_raw_parts(va as *const u8, bs as usize) })
}

// =====================================================================
// Container superblock parsing
// =====================================================================

// nx_superblock_t field offsets (all little-endian):
// obj_phys_t: 0..31 (32 bytes)
// nx_magic: 32..35
// nx_block_size: 36..39
// nx_block_count: 40..47
// nx_features: 48..55
// nx_readonly_compatible_features: 56..63
// nx_incompatible_features: 64..71
// nx_uuid: 72..87
// nx_next_oid: 88..95
// nx_next_xid: 96..103
// nx_xp_desc_blocks: 104..107
// nx_xp_data_blocks: 108..111
// nx_xp_desc_base: 112..119
// nx_xp_data_base: 120..127
// nx_xp_desc_next: 128..131
// nx_xp_data_next: 132..135
// nx_xp_desc_index: 136..139
// nx_xp_desc_len: 140..143
// nx_xp_data_index: 144..147
// nx_xp_data_len: 148..151
// nx_spaceman_oid: 152..159
// nx_omap_oid: 160..167
// nx_reaper_oid: 168..175
// nx_test_type: 176..179
// nx_max_file_systems: 180..183
// nx_fs_oid[0..NX_MAX_FILE_SYSTEMS]: 184..

const NX_MAGIC_OFF: usize = 32;
const NX_BLOCK_SIZE_OFF: usize = 36;
const NX_BLOCK_COUNT_OFF: usize = 40;
const NX_XP_DESC_BLOCKS_OFF: usize = 104;
const NX_XP_DATA_BLOCKS_OFF: usize = 108;
const NX_XP_DESC_BASE_OFF: usize = 112;
const NX_XP_DATA_BASE_OFF: usize = 120;
const NX_XP_DESC_INDEX_OFF: usize = 136;
const NX_XP_DESC_LEN_OFF: usize = 140;
const NX_XP_DATA_INDEX_OFF: usize = 144;
const NX_XP_DATA_LEN_OFF: usize = 148;
const NX_OMAP_OID_OFF: usize = 160;
const NX_MAX_FS_OFF: usize = 180;
const NX_FS_OID_OFF: usize = 184;

fn parse_nx_superblock(buf: &[u8]) -> Option<NxSuperblock> {
    let magic = read_le32(buf, NX_MAGIC_OFF);
    if magic != NX_MAGIC {
        return None;
    }

    let xid = read_le64(buf, 16); // o_xid at offset 16

    let mut fs_oid = [0u64; 4];
    for i in 0..4 {
        fs_oid[i] = read_le64(buf, NX_FS_OID_OFF + i * 8);
    }

    Some(NxSuperblock {
        block_size: read_le32(buf, NX_BLOCK_SIZE_OFF),
        block_count: read_le64(buf, NX_BLOCK_COUNT_OFF),
        omap_oid: read_le64(buf, NX_OMAP_OID_OFF),
        xp_desc_base: read_le64(buf, NX_XP_DESC_BASE_OFF),
        xp_desc_blocks: read_le32(buf, NX_XP_DESC_BLOCKS_OFF),
        xp_desc_len: read_le32(buf, NX_XP_DESC_LEN_OFF),
        xp_desc_index: read_le32(buf, NX_XP_DESC_INDEX_OFF),
        xp_data_base: read_le64(buf, NX_XP_DATA_BASE_OFF),
        xp_data_blocks: read_le32(buf, NX_XP_DATA_BLOCKS_OFF),
        xp_data_len: read_le32(buf, NX_XP_DATA_LEN_OFF),
        xp_data_index: read_le32(buf, NX_XP_DATA_INDEX_OFF),
        xid,
        fs_oid,
    })
}

// =====================================================================
// Checkpoint scanning — find the latest valid container superblock
// =====================================================================

fn find_latest_checkpoint(blk: &BlkClient, block0: &NxSuperblock) -> Option<NxSuperblock> {
    let bs = block0.block_size;
    let desc_base = block0.xp_desc_base;
    // High bit of xp_desc_blocks is a flag; mask it off for the count.
    let desc_blocks = block0.xp_desc_blocks & 0x7FFFFFFF;

    if desc_blocks == 0 || desc_blocks > 1024 {
        // Fallback: use block 0 as-is.
        return Some(*block0);
    }

    let mut best_xid: u64 = 0;
    let mut best = *block0;

    for i in 0..desc_blocks {
        let blk_num = desc_base + i as u64;
        let buf = match cache_read_slice(blk, blk_num, bs) {
            Some(b) => b,
            None => continue,
        };

        // Check if this is an nx_superblock_t (type = OBJECT_TYPE_NX_SUPERBLOCK)
        let o_type = read_le32(buf, 24); // o_type at offset 24
        let obj_type = o_type & OBJECT_TYPE_MASK;
        if obj_type != OBJECT_TYPE_NX_SUPERBLOCK {
            continue;
        }

        let magic = read_le32(buf, NX_MAGIC_OFF);
        if magic != NX_MAGIC {
            continue;
        }

        let xid = read_le64(buf, 16); // o_xid
        if xid > best_xid {
            if let Some(sb) = parse_nx_superblock(buf) {
                best_xid = xid;
                best = sb;
            }
        }
    }

    if best_xid == 0 {
        // No checkpoint found, use block 0.
        Some(*block0)
    } else {
        Some(best)
    }
}

// =====================================================================
// Object map (omap) B-tree lookup
// =====================================================================

// omap_phys_t field offsets:
// obj_phys_t: 0..31
// om_flags: 32..35
// om_snap_count: 36..39
// om_tree_type: 40..43
// om_snapshot_tree_type: 44..47
// om_tree_oid: 48..55
// om_snapshot_tree_oid: 56..63
// om_most_recent_snap: 64..71
// om_pending_revert_min: 72..79
// om_pending_revert_max: 80..87
const OMAP_TREE_OID_OFF: usize = 48;

/// Look up a virtual OID in an object map, returning the physical block address.
/// The omap B-tree uses fixed-size 16-byte keys (oid u64, xid u64) and
/// 16-byte values (flags u32, size u32, paddr u64).
fn omap_lookup(blk: &BlkClient, bs: u32, omap_phys_block: u64, oid: u64, max_xid: u64) -> Option<u64> {
    // Read the omap_phys_t header to get the B-tree root OID.
    let omap_buf = cache_read_slice(blk, omap_phys_block, bs)?;
    let tree_oid = read_le64(omap_buf, OMAP_TREE_OID_OFF);

    // The omap tree root is a physical object — tree_oid is a physical block number.
    omap_btree_lookup(blk, bs, tree_oid, oid, max_xid)
}

fn omap_btree_lookup(blk: &BlkClient, bs: u32, root_block: u64, oid: u64, max_xid: u64) -> Option<u64> {
    let mut cur_block = root_block;

    // Walk down the B-tree (max 8 levels).
    for _depth in 0..8 {
        let buf = cache_read_slice(blk, cur_block, bs)?;

        let flags = read_le16(buf, BTN_FLAGS_OFF);
        let level = read_le16(buf, BTN_LEVEL_OFF);
        let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
        let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
        let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;

        let data_base = BTN_DATA_OFF;
        let toc_base = data_base + toc_off;
        let key_base = data_base + toc_off + toc_len;

        // Value area ends at block_size for non-root, or block_size - BTREE_INFO_SIZE for root.
        let val_end = if (flags & BTNODE_ROOT) != 0 {
            bs as usize - BTREE_INFO_SIZE
        } else {
            bs as usize
        };

        let is_leaf = (flags & BTNODE_LEAF) != 0 || level == 0;
        let fixed_kv = (flags & BTNODE_FIXED_KV_SIZE) != 0;

        if is_leaf {
            // Search for the best matching key: same oid, highest xid <= max_xid.
            let mut best_paddr: Option<u64> = None;
            let mut best_xid: u64 = 0;

            for i in 0..nkeys {
                let (k_off, v_off) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
                } else {
                    let toc_entry = toc_base + i * 8;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 4) as usize)
                };

                let key_start = key_base + k_off;
                if key_start + 16 > bs as usize {
                    continue;
                }
                let k_oid = read_le64(buf, key_start);
                let k_xid = read_le64(buf, key_start + 8);

                if k_oid == oid && k_xid <= max_xid && k_xid > best_xid {
                    // Value: flags(4) + size(4) + paddr(8)
                    let val_start = val_end - v_off;
                    if val_start >= 16 {
                        let paddr = read_le64(buf, val_start + 8);
                        best_paddr = Some(paddr);
                        best_xid = k_xid;
                    }
                }
            }
            return best_paddr;
        } else {
            // Internal node: find the child to descend into.
            // Keys are sorted by (oid, xid). Find the last key <= (oid, max_xid).
            let mut child_idx = 0;
            for i in 0..nkeys {
                let (k_off, v_off) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
                } else {
                    let toc_entry = toc_base + i * 8;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 4) as usize)
                };

                let key_start = key_base + k_off;
                if key_start + 16 > bs as usize {
                    continue;
                }
                let k_oid = read_le64(buf, key_start);
                let k_xid = read_le64(buf, key_start + 8);

                if k_oid < oid || (k_oid == oid && k_xid <= max_xid) {
                    child_idx = i;
                } else if k_oid > oid {
                    break;
                }
            }

            // Read child OID from value.
            let (_, v_off) = if fixed_kv {
                let toc_entry = toc_base + child_idx * 4;
                (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
            } else {
                let toc_entry = toc_base + child_idx * 8;
                (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 4) as usize)
            };

            let val_start = val_end - v_off;
            // Child OID is at start of value (u64).
            let child_oid = read_le64(buf, val_start);
            // omap tree is physical — child OID is a physical block number.
            cur_block = child_oid;
        }
    }

    None // too deep
}

// =====================================================================
// File-system B-tree operations
// =====================================================================

/// Compose a j_key_t value from an object ID and type.
fn make_fs_key(obj_id: u64, obj_type: u8) -> u64 {
    (obj_id & OBJ_ID_MASK) | ((obj_type as u64) << OBJ_TYPE_SHIFT)
}

/// Extract object ID from a j_key_t.
fn fs_key_obj_id(key: u64) -> u64 {
    key & OBJ_ID_MASK
}

/// Extract object type from a j_key_t.
fn fs_key_type(key: u64) -> u8 {
    ((key & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT) as u8
}

/// Compare two j_key_t values: first by obj_id (low 60 bits), then by type (high 4 bits).
/// APFS sorts records by obj_id first, type second — raw u64 compare is wrong because
/// the type is in the high bits.
fn fs_key_cmp(a: u64, b: u64) -> core::cmp::Ordering {
    let a_id = a & OBJ_ID_MASK;
    let b_id = b & OBJ_ID_MASK;
    match a_id.cmp(&b_id) {
        core::cmp::Ordering::Equal => {
            let a_type = (a >> OBJ_TYPE_SHIFT) & 0xF;
            let b_type = (b >> OBJ_TYPE_SHIFT) & 0xF;
            a_type.cmp(&b_type)
        }
        other => other,
    }
}

/// Search the file-system B-tree for a specific record.
/// The fs tree uses virtual OIDs for child nodes (needs omap lookup).
/// Keys are variable-length j_key_t-prefixed records.
/// Returns: (key_bytes_va, key_len, val_bytes_va, val_len) in cache memory.
///
/// `match_fn` receives (key_buf, key_len) and returns:
///   Ordering::Equal => found, return this record
///   Ordering::Less => target is after this key
///   Ordering::Greater => target is before this key
fn fs_tree_lookup<F>(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    root_block: u64,
    max_xid: u64,
    match_fn: &F,
) -> Option<(usize, usize, usize, usize)>
where
    F: Fn(&[u8]) -> core::cmp::Ordering,
{
    let mut cur_block = root_block;

    for _depth in 0..8 {
        let buf = cache_read_slice(blk, cur_block, bs)?;

        let flags = read_le16(buf, BTN_FLAGS_OFF);
        let level = read_le16(buf, BTN_LEVEL_OFF);
        let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
        let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
        let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;

        let data_base = BTN_DATA_OFF;
        let toc_base = data_base + toc_off;
        let key_base = data_base + toc_off + toc_len;

        let val_end = if (flags & BTNODE_ROOT) != 0 {
            bs as usize - BTREE_INFO_SIZE
        } else {
            bs as usize
        };

        let is_leaf = (flags & BTNODE_LEAF) != 0 || level == 0;
        let fixed_kv = (flags & BTNODE_FIXED_KV_SIZE) != 0;

        if is_leaf {
            // Scan leaf for matching key.
            for i in 0..nkeys {
                let (k_off, k_len, v_off, v_len) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    let ko = read_le16(buf, toc_entry) as usize;
                    let vo = read_le16(buf, toc_entry + 2) as usize;
                    // Fixed-size — get sizes from btree_info
                    (ko, 8usize, vo, 8usize) // minimal for j_key_t
                } else {
                    let toc_entry = toc_base + i * 8;
                    let ko = read_le16(buf, toc_entry) as usize;
                    let kl = read_le16(buf, toc_entry + 2) as usize;
                    let vo = read_le16(buf, toc_entry + 4) as usize;
                    let vl = read_le16(buf, toc_entry + 6) as usize;
                    (ko, kl, vo, vl)
                };

                let key_start = key_base + k_off;
                if key_start + k_len > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + k_len];

                match match_fn(key_data) {
                    core::cmp::Ordering::Equal => {
                        let val_start = val_end - v_off;
                        if val_start < v_len {
                            continue;
                        }
                        let va_base = buf.as_ptr() as usize;
                        return Some((
                            va_base + key_start,
                            k_len,
                            va_base + val_start,
                            v_len,
                        ));
                    }
                    core::cmp::Ordering::Greater => {
                        // We've passed the target, stop.
                        return None;
                    }
                    core::cmp::Ordering::Less => {
                        // Keep scanning.
                    }
                }
            }
            return None;
        } else {
            // Internal node: find child to descend into.
            // Non-leaf nodes in fs tree have BTNODE_FIXED_KV_SIZE set (keys are j_key_t,
            // values are oid_t). But the tree itself may use virtual OIDs for children.
            let mut child_idx = 0usize;
            let nk = nkeys;
            for i in 0..nk {
                let (k_off, _k_len) = if fixed_kv {
                    let toc_entry = toc_base + i * 4;
                    (read_le16(buf, toc_entry) as usize, 8usize)
                } else {
                    let toc_entry = toc_base + i * 8;
                    (read_le16(buf, toc_entry) as usize, read_le16(buf, toc_entry + 2) as usize)
                };

                let key_start = key_base + k_off;
                if key_start + 8 > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + 8]; // only compare j_key_t header

                match match_fn(key_data) {
                    core::cmp::Ordering::Less | core::cmp::Ordering::Equal => {
                        child_idx = i;
                    }
                    core::cmp::Ordering::Greater => {
                        break;
                    }
                }
            }

            // Get child OID from value.
            let v_off = if fixed_kv {
                let toc_entry = toc_base + child_idx * 4;
                read_le16(buf, toc_entry + 2) as usize
            } else {
                let toc_entry = toc_base + child_idx * 8;
                read_le16(buf, toc_entry + 4) as usize
            };

            let val_start = val_end - v_off;
            let child_oid = read_le64(buf, val_start);

            // fs tree children are virtual objects — resolve via omap.
            cur_block = omap_lookup(blk, bs, vol_omap_phys, child_oid, max_xid)?;
        }
    }

    None
}

/// Iterate over all records in a B-tree leaf range matching a prefix.
/// Calls `callback(key_slice, val_slice)` for each matching record.
/// Returns false to stop iteration.
/// `prefix_match` returns true for keys that should be visited.
fn fs_tree_iterate<P, C>(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    root_block: u64,
    max_xid: u64,
    skip_count: usize,
    prefix_match: &P,
    callback: &mut C,
) -> bool
where
    P: Fn(&[u8]) -> core::cmp::Ordering,  // Less = before range, Equal = in range, Greater = past range
    C: FnMut(&[u8], &[u8], usize) -> bool, // (key, val, index) -> continue?
{
    // For iteration, we walk to the leftmost leaf containing our range,
    // then scan forward through the leaf.
    let mut cur_block = root_block;

    // Descend to leftmost matching leaf.
    for _depth in 0..8 {
        let buf = cache_read_slice(blk, cur_block, bs);
        let buf = match buf {
            Some(b) => b,
            None => return false,
        };

        let flags = read_le16(buf, BTN_FLAGS_OFF);
        let level = read_le16(buf, BTN_LEVEL_OFF);
        let nkeys = read_le32(buf, BTN_NKEYS_OFF) as usize;
        let toc_off = read_le16(buf, BTN_TOC_OFF) as usize;
        let toc_len = read_le16(buf, BTN_TOC_OFF + 2) as usize;

        let data_base = BTN_DATA_OFF;
        let toc_base = data_base + toc_off;
        let key_base = data_base + toc_off + toc_len;
        let val_end = if (flags & BTNODE_ROOT) != 0 {
            bs as usize - BTREE_INFO_SIZE
        } else {
            bs as usize
        };
        let is_leaf = (flags & BTNODE_LEAF) != 0 || level == 0;
        let fixed_kv = (flags & BTNODE_FIXED_KV_SIZE) != 0;

        if is_leaf {
            let mut index = 0usize;
            for i in 0..nkeys {
                let (k_off, k_len, v_off, v_len) = if fixed_kv {
                    let te = toc_base + i * 4;
                    (read_le16(buf, te) as usize, 8, read_le16(buf, te + 2) as usize, 8)
                } else {
                    let te = toc_base + i * 8;
                    (
                        read_le16(buf, te) as usize,
                        read_le16(buf, te + 2) as usize,
                        read_le16(buf, te + 4) as usize,
                        read_le16(buf, te + 6) as usize,
                    )
                };

                let key_start = key_base + k_off;
                if key_start + k_len > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + k_len];

                match prefix_match(key_data) {
                    core::cmp::Ordering::Less => continue,
                    core::cmp::Ordering::Greater => return true,
                    core::cmp::Ordering::Equal => {
                        if index >= skip_count {
                            let val_start = val_end - v_off;
                            if val_start + v_len <= bs as usize {
                                let val_data = &buf[val_start..val_start + v_len];
                                if !callback(key_data, val_data, index) {
                                    return false;
                                }
                            }
                        }
                        index += 1;
                    }
                }
            }
            return true;
        } else {
            // Internal node — descend to leftmost child in range.
            let mut child_idx = 0usize;
            for i in 0..nkeys {
                let k_off = if fixed_kv {
                    read_le16(buf, toc_base + i * 4) as usize
                } else {
                    read_le16(buf, toc_base + i * 8) as usize
                };
                let key_start = key_base + k_off;
                if key_start + 8 > bs as usize {
                    continue;
                }
                let key_data = &buf[key_start..key_start + 8];
                match prefix_match(key_data) {
                    core::cmp::Ordering::Less | core::cmp::Ordering::Equal => {
                        child_idx = i;
                    }
                    core::cmp::Ordering::Greater => break,
                }
            }

            let v_off = if fixed_kv {
                read_le16(buf, toc_base + child_idx * 4 + 2) as usize
            } else {
                read_le16(buf, toc_base + child_idx * 8 + 4) as usize
            };
            let val_start = val_end - v_off;
            let child_oid = read_le64(buf, val_start);
            cur_block = match omap_lookup(blk, bs, vol_omap_phys, child_oid, max_xid) {
                Some(b) => b,
                None => return false,
            };
        }
    }
    false
}

// =====================================================================
// Volume superblock parsing
// =====================================================================

// apfs_superblock_t field offsets:
// obj_phys_t: 0..31
// apfs_magic: 32..35
// apfs_fs_index: 36..39
// ...
// apfs_features: 64..71
// apfs_readonly_compatible_features: 72..79
// apfs_incompatible_features: 80..87
// ...
// apfs_omap_oid: 160..167  (after several uuid/counter fields)
// apfs_root_tree_oid: 168..175
// ...

const APFS_MAGIC_OFF: usize = 32;
const APFS_OMAP_OID_OFF: usize = 0x80;   // 128
const APFS_ROOT_TREE_OID_OFF: usize = 0x88; // 136

fn parse_volume(blk: &BlkClient, bs: u32, vol_phys_block: u64, xid: u64) -> Option<ApfsVolume> {
    let buf = cache_read_slice(blk, vol_phys_block, bs)?;

    let magic = read_le32(buf, APFS_MAGIC_OFF);
    if magic != APFS_MAGIC {
        syscall::debug_puts(b"  [apfs_srv] bad volume magic: ");
        print_hex(magic as u64);
        syscall::debug_puts(b"\n");
        return None;
    }

    Some(ApfsVolume {
        omap_oid: read_le64(buf, APFS_OMAP_OID_OFF),
        root_tree_oid: read_le64(buf, APFS_ROOT_TREE_OID_OFF),
        xid,
    })
}

// =====================================================================
// Inode reading
// =====================================================================

fn read_inode(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    ino: u64,
) -> Option<ApfsInode> {
    let target_key = make_fs_key(ino, APFS_TYPE_INODE);

    let (_, _, val_va, val_len) = fs_tree_lookup(blk, bs, vol_omap_phys, fs_root_block, max_xid,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            fs_key_cmp(k, target_key)
        },
    )?;

    if val_len < IVAL_XFIELDS {
        return None;
    }

    let val = unsafe { core::slice::from_raw_parts(val_va as *const u8, val_len) };

    let parent_id = read_le64(val, IVAL_PARENT_ID);
    let private_id = read_le64(val, IVAL_PRIVATE_ID);
    let nlink = read_le32(val, IVAL_NCHILDREN_NLINK);
    let owner = read_le32(val, IVAL_OWNER);
    let group = read_le32(val, IVAL_GROUP);
    let mode = read_le16(val, IVAL_MODE);

    // Extract file size from dstream xfield if present.
    let mut size = 0u64;
    if val_len > IVAL_XFIELDS {
        // Parse xfields: x_type(u8) x_flags(u8) x_size(u16), then data[x_size].
        let mut pos = IVAL_XFIELDS;
        while pos + 4 <= val_len {
            let x_type = val[pos];
            let _x_flags = val[pos + 1];
            let x_size = read_le16(val, pos + 2) as usize;
            pos += 4;
            if pos + x_size > val_len {
                break;
            }
            if x_type == INO_EXT_TYPE_DSTREAM && x_size >= 8 {
                size = read_le64(val, pos + DSTREAM_SIZE);
            }
            pos += x_size;
            // Align to 8 bytes.
            pos = (pos + 7) & !7;
        }
    }

    Some(ApfsInode {
        ino,
        parent_id,
        private_id,
        mode,
        owner,
        group,
        nlink,
        size,
    })
}

// =====================================================================
// Directory operations
// =====================================================================

/// Look up a name in a directory, returning the child's inode number.
fn dir_lookup(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    dir_ino: u64,
    name: &[u8],
) -> Option<u64> {
    // Search for DIR_REC with matching name.
    // Key: j_key_t(8) + name_len_and_hash(4) + name(variable)
    // We match by obj_id == dir_ino, type == DIR_REC, and name comparison.
    let dir_key_min = make_fs_key(dir_ino, APFS_TYPE_DIR_REC);

    let mut found_ino: Option<u64> = None;

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, 0,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);

            if k_id < dir_ino || (k_id == dir_ino && (k_type as u64) < APFS_TYPE_DIR_REC as u64) {
                core::cmp::Ordering::Less
            } else if k_id == dir_ino && k_type == APFS_TYPE_DIR_REC {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], _idx: usize| -> bool {
            // Key: j_key_t(8) + name_len_and_hash(4) + name[]
            if key_data.len() < 12 || val_data.len() < 18 {
                return true;
            }
            let name_len_and_hash = read_le32(key_data, 8);
            let entry_name_len = (name_len_and_hash & 0x3FF) as usize;
            if entry_name_len == 0 {
                return true;
            }
            // Name starts at offset 12 in the key, length includes null terminator.
            let name_start = 12;
            let actual_name_len = if entry_name_len > 0 { entry_name_len - 1 } else { 0 }; // strip null
            if name_start + actual_name_len > key_data.len() {
                return true;
            }
            let entry_name = &key_data[name_start..name_start + actual_name_len];

            if entry_name.len() == name.len() && entry_name == name {
                // Value: file_id(8) + date_added(8) + flags(2)
                let file_id = read_le64(val_data, 0);
                found_ino = Some(file_id);
                return false; // stop
            }
            true // continue
        },
    );

    found_ino
}

/// Iterate directory entries starting at `offset` (entry index).
/// Calls callback with (name, name_len, ino, ftype, next_offset).
/// Returns (name, ino, ftype, next_offset) for the next entry, or None.
fn dir_next_entry(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    dir_ino: u64,
    offset: usize,
) -> Option<([u8; 256], usize, u64, u8, usize)> {
    let mut result: Option<([u8; 256], usize, u64, u8, usize)> = None;

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, offset,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);
            if k_id < dir_ino || (k_id == dir_ino && (k_type as u64) < APFS_TYPE_DIR_REC as u64) {
                core::cmp::Ordering::Less
            } else if k_id == dir_ino && k_type == APFS_TYPE_DIR_REC {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], idx: usize| -> bool {
            if key_data.len() < 12 || val_data.len() < 18 {
                return false;
            }
            let name_len_and_hash = read_le32(key_data, 8);
            let entry_name_len = (name_len_and_hash & 0x3FF) as usize;
            let actual_name_len = if entry_name_len > 0 { entry_name_len - 1 } else { 0 };
            if actual_name_len == 0 || 12 + actual_name_len > key_data.len() {
                return false;
            }

            let mut name_buf = [0u8; 256];
            let copy_len = actual_name_len.min(255);
            name_buf[..copy_len].copy_from_slice(&key_data[12..12 + copy_len]);

            let file_id = read_le64(val_data, 0);
            let flags = read_le16(val_data, 16);
            let ftype = (flags & DREC_TYPE_MASK) as u8;

            result = Some((name_buf, copy_len, file_id, ftype, idx + 1));
            false // stop after first
        },
    );

    result
}

// =====================================================================
// File extent resolution
// =====================================================================

/// Resolve file data at a given byte offset.
/// Returns (physical_block, offset_in_block, extent_remaining_bytes).
fn resolve_file_extent(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    private_id: u64,
    file_offset: u64,
) -> Option<(u64, u32, u64)> {
    // Search for FILE_EXTENT records for this private_id.
    // We need the extent whose logical_addr <= file_offset < logical_addr + len.
    let mut best: Option<(u64, u64, u64)> = None; // (logical_addr, phys_block, len_bytes)

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, 0,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);
            if k_id < private_id || (k_id == private_id && (k_type as u64) < APFS_TYPE_FILE_EXTENT as u64) {
                core::cmp::Ordering::Less
            } else if k_id == private_id && k_type == APFS_TYPE_FILE_EXTENT {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], _idx: usize| -> bool {
            // Key: j_key_t(8) + logical_addr(8)
            if key_data.len() < 16 || val_data.len() < 24 {
                return true;
            }
            let logical_addr = read_le64(key_data, 8);
            let len_and_flags = read_le64(val_data, 0);
            let extent_len = len_and_flags & 0x00ffffffffffffffu64;
            let phys_block = read_le64(val_data, 8);

            if logical_addr <= file_offset && file_offset < logical_addr + extent_len {
                best = Some((logical_addr, phys_block, extent_len));
                return false; // found it
            }
            if logical_addr > file_offset {
                return false; // past our target
            }
            true // keep looking
        },
    );

    let (logical_addr, phys_block, extent_len) = best?;
    let offset_in_extent = file_offset - logical_addr;
    let block_offset = offset_in_extent / bs as u64;
    let offset_in_block = (offset_in_extent % bs as u64) as u32;
    let remaining = extent_len - offset_in_extent;
    Some((phys_block + block_offset, offset_in_block, remaining))
}

// =====================================================================
// Extended attribute (xattr) reading — for symlinks
// =====================================================================

/// Read an extended attribute value by name. Returns data copied into `out`.
fn read_xattr(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    ino: u64,
    attr_name: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut result: Option<usize> = None;

    fs_tree_iterate(
        blk, bs, vol_omap_phys, fs_root_block, max_xid, 0,
        &|key_data: &[u8]| {
            if key_data.len() < 8 {
                return core::cmp::Ordering::Less;
            }
            let k = read_le64(key_data, 0);
            let k_id = fs_key_obj_id(k);
            let k_type = fs_key_type(k);
            if k_id < ino || (k_id == ino && (k_type as u64) < APFS_TYPE_XATTR as u64) {
                core::cmp::Ordering::Less
            } else if k_id == ino && k_type == APFS_TYPE_XATTR {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        },
        &mut |key_data: &[u8], val_data: &[u8], _idx: usize| -> bool {
            // Key: j_key_t(8) + name_len(2) + name[]
            if key_data.len() < 10 || val_data.len() < 4 {
                return true;
            }
            let name_len = read_le16(key_data, 8) as usize;
            let actual_len = if name_len > 0 { name_len - 1 } else { 0 }; // strip null
            if 10 + actual_len > key_data.len() {
                return true;
            }
            let entry_name = &key_data[10..10 + actual_len];

            if entry_name == attr_name {
                // Value: flags(2) + xdata_len(2) + xdata[]
                let flags = read_le16(val_data, 0);
                let xdata_len = read_le16(val_data, 2) as usize;

                if (flags & XATTR_DATA_EMBEDDED) != 0 && xdata_len > 0 {
                    let copy_len = xdata_len.min(out.len()).min(val_data.len() - 4);
                    out[..copy_len].copy_from_slice(&val_data[4..4 + copy_len]);
                    result = Some(copy_len);
                }
                return false; // stop
            }
            true
        },
    );

    result
}

/// Read symlink target. APFS stores symlink targets as xattr "com.apple.fs.symlink".
fn read_symlink_target(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    ino: u64,
    out: &mut [u8],
) -> Option<usize> {
    read_xattr(blk, bs, vol_omap_phys, fs_root_block, max_xid, ino,
        b"com.apple.fs.symlink", out)
}

// =====================================================================
// Path resolution
// =====================================================================

fn path_resolve(
    blk: &BlkClient,
    bs: u32,
    vol_omap_phys: u64,
    fs_root_block: u64,
    max_xid: u64,
    path: &[u8],
) -> Option<ApfsInode> {
    let mut cur_ino = ROOT_DIR_INO_NUM;
    let mut cur_inode = read_inode(blk, bs, vol_omap_phys, fs_root_block, max_xid, cur_ino)?;

    if path.is_empty() {
        return Some(cur_inode);
    }

    let mut start = 0usize;
    while start < path.len() {
        // Skip slashes.
        if path[start] == b'/' {
            start += 1;
            continue;
        }
        // Find end of component.
        let mut end = start;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        let component = &path[start..end];

        if !cur_inode.is_dir() {
            return None;
        }

        cur_ino = dir_lookup(blk, bs, vol_omap_phys, fs_root_block, max_xid, cur_ino, component)?;
        cur_inode = read_inode(blk, bs, vol_omap_phys, fs_root_block, max_xid, cur_ino)?;
        start = end;
    }

    Some(cur_inode)
}

// =====================================================================
// Main server
// =====================================================================

// Global volume state (set once during mount).
static mut VOL_OMAP_PHYS: u64 = 0;
static mut FS_ROOT_BLOCK: u64 = 0;
static mut MAX_XID: u64 = u64::MAX;
static mut BLOCK_SIZE: u32 = 4096;
static mut BLOCK_COUNT: u64 = 0;

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [apfs_srv] starting\n");

    let partition_offset = if arg0 != 0 { arg0 } else { 336 * 1024 * 1024 };

    syscall::debug_puts(b"  [apfs_srv] partition offset=");
    print_num(partition_offset);
    syscall::debug_puts(b"\n");

    // Create port and register with name server.
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"apfs", port);
    syscall::ns_register(b"apfs_task", my_aspace);

    // Look up cache_blk with bounded retry.
    let blk_port = {
        let mut retries = 2000;
        loop {
            if let Some(p) = syscall::ns_lookup(b"cache_blk") {
                break p;
            }
            retries -= 1;
            if retries == 0 {
                syscall::debug_puts(b"  [apfs_srv] cache_blk not found, exiting\n");
                syscall::exit(1);
            }
            for _ in 0..50 {
                syscall::yield_now();
            }
        }
    };

    // Connect to blk_srv via cache.
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
            syscall::debug_puts(b"  [apfs_srv] blk connect FAILED\n");
            loop { core::hint::spin_loop(); }
        }
    } else {
        syscall::debug_puts(b"  [apfs_srv] blk no reply\n");
        loop { core::hint::spin_loop(); }
    };

    // Allocate scratch page for block reads.
    let scratch_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [apfs_srv] scratch alloc FAILED\n");
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

    // Initialize block cache.
    cache_init();

    // ---- Phase A: Read container superblock ----
    let mut sb_buf = [0u8; 512];
    let mut read_ok = false;
    for _ in 0..20 {
        if blk.read_bytes(0, &mut sb_buf) {
            if read_le32(&sb_buf, NX_MAGIC_OFF) == NX_MAGIC {
                read_ok = true;
                break;
            }
        }
        for _ in 0..100 {
            syscall::yield_now();
        }
    }
    if !read_ok {
        syscall::debug_puts(b"  [apfs_srv] no APFS container found, exiting\n");
        syscall::exit(1);
    }

    // Need to read the full block for superblock parsing. Read block 0 properly.
    let bs_init = read_le32(&sb_buf, NX_BLOCK_SIZE_OFF);
    let bs = if bs_init > 0 && bs_init <= 65536 { bs_init } else { 4096 };

    let block0_buf = match cache_read_slice(&blk, 0, bs) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] failed to read block 0\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    let nx_sb = match parse_nx_superblock(block0_buf) {
        Some(s) => s,
        None => {
            syscall::debug_puts(b"  [apfs_srv] invalid container superblock\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] NX container: block_size=");
    print_num(bs as u64);
    syscall::debug_puts(b" blocks=");
    print_num(nx_sb.block_count);
    syscall::debug_puts(b" xid=");
    print_num(nx_sb.xid);
    syscall::debug_puts(b"\n");

    // ---- Phase A3: Checkpoint scanning ----
    let nx_sb = match find_latest_checkpoint(&blk, &nx_sb) {
        Some(s) => s,
        None => {
            syscall::debug_puts(b"  [apfs_srv] checkpoint scan failed\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] latest checkpoint xid=");
    print_num(nx_sb.xid);
    syscall::debug_puts(b" omap_oid=");
    print_num(nx_sb.omap_oid);
    syscall::debug_puts(b" fs_oid[0]=");
    print_num(nx_sb.fs_oid[0]);
    syscall::debug_puts(b"\n");

    // ---- Phase C1: Mount first volume ----
    let vol_oid = nx_sb.fs_oid[0];
    if vol_oid == 0 {
        syscall::debug_puts(b"  [apfs_srv] no volume found\n");
        syscall::exit(1);
    }

    // Look up volume OID in container omap.
    let vol_phys_block = match omap_lookup(&blk, bs, nx_sb.omap_oid, vol_oid, nx_sb.xid) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] volume omap lookup failed for oid=");
            print_num(vol_oid);
            syscall::debug_puts(b"\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] volume at block ");
    print_num(vol_phys_block);
    syscall::debug_puts(b"\n");

    let volume = match parse_volume(&blk, bs, vol_phys_block, nx_sb.xid) {
        Some(v) => v,
        None => {
            syscall::debug_puts(b"  [apfs_srv] invalid volume superblock\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] volume omap_oid=");
    print_num(volume.omap_oid);
    syscall::debug_puts(b" root_tree_oid=");
    print_num(volume.root_tree_oid);
    syscall::debug_puts(b"\n");

    // Resolve fs tree root via volume omap.
    let fs_root_block = match omap_lookup(&blk, bs, volume.omap_oid, volume.root_tree_oid, nx_sb.xid) {
        Some(b) => b,
        None => {
            syscall::debug_puts(b"  [apfs_srv] fs tree omap lookup failed\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [apfs_srv] fs tree root at block ");
    print_num(fs_root_block);
    syscall::debug_puts(b"\n");

    // Store global volume state.
    unsafe {
        VOL_OMAP_PHYS = volume.omap_oid;
        FS_ROOT_BLOCK = fs_root_block;
        MAX_XID = nx_sb.xid;
        BLOCK_SIZE = bs;
        BLOCK_COUNT = nx_sb.block_count;
    }

    // Verify root directory exists.
    if let Some(root) = read_inode(&blk, bs, volume.omap_oid, fs_root_block, nx_sb.xid, ROOT_DIR_INO_NUM) {
        syscall::debug_puts(b"  [apfs_srv] root dir: mode=");
        print_hex(root.mode as u64);
        syscall::debug_puts(b" nlink=");
        print_num(root.nlink as u64);
        syscall::debug_puts(b"\n");
    } else {
        syscall::debug_puts(b"  [apfs_srv] cannot read root directory inode\n");
        syscall::exit(1);
    }

    syscall::debug_puts(b"  [apfs_srv] ready (read-only)\n");

    // Open file table.
    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    let vol_omap = volume.omap_oid;
    let max_xid = nx_sb.xid;

    // ---- Server loop ----
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let caller_pid = msg.data[3] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                if let Some(inode) = path_resolve(&blk, bs, vol_omap, fs_root_block, max_xid, name) {
                    let mut handle = u64::MAX;
                    for (i, h) in handles.iter_mut().enumerate() {
                        if !h.active {
                            h.active = true;
                            h.inode = inode;
                            h.pid = caller_pid;
                            handle = i as u64;
                            break;
                        }
                    }
                    if handle == u64::MAX {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, FS_OPEN_OK, handle, inode.size, my_aspace as u64, 0);
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_OPEN_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;
                let _flags = ((msg.data[0] >> 16) & 0xFFFF) as u32;
                let reply_port = msg.data[0] >> 32;
                let caller_pid = msg.data[1] as u32;

                let name = unsafe {
                    core::slice::from_raw_parts(VFS_LONG_PATH_SCRATCH_VA as *const u8, name_len.min(4096))
                };

                if let Some(inode) = path_resolve(&blk, bs, vol_omap, fs_root_block, max_xid, name) {
                    let mut handle = u64::MAX;
                    for (i, h) in handles.iter_mut().enumerate() {
                        if !h.active {
                            h.active = true;
                            h.inode = inode;
                            h.pid = caller_pid;
                            handle = i as u64;
                            break;
                        }
                    }
                    if handle == u64::MAX {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, FS_OPEN_OK, handle, inode.size, my_aspace as u64, 0);
                    }
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_CLOSE => {
                let handle_id = msg.data[0] as usize;
                if handle_id < MAX_OPEN && handles[handle_id].active {
                    handles[handle_id].active = false;
                }
            }

            FS_READ => {
                let handle_id = msg.data[0] as usize;
                let offset = msg.data[1];
                let len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if handle_id >= MAX_OPEN || !handles[handle_id].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle_id].inode;
                if offset >= inode.size {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let avail = (inode.size - offset) as usize;
                let read_len = len.min(avail);
                let private_id = inode.private_id;

                // Read data block by block.
                let mut total_read = 0usize;
                let mut file_pos = offset;

                while total_read < read_len {
                    let remaining = read_len - total_read;

                    let (phys_block, off_in_block, _extent_rem) = match resolve_file_extent(
                        &blk, bs, vol_omap, fs_root_block, max_xid, private_id, file_pos,
                    ) {
                        Some(r) => r,
                        None => break,
                    };

                    let block_va = match cache_read(&blk, phys_block, bs) {
                        Some(va) => va,
                        None => break,
                    };

                    let can_read = (bs - off_in_block) as usize;
                    let chunk = remaining.min(can_read);

                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (block_va + off_in_block as usize) as *const u8,
                                (grant_va + total_read) as *mut u8,
                                chunk,
                            );
                        }
                    }

                    total_read += chunk;
                    file_pos += chunk as u64;
                }

                if grant_va != 0 {
                    syscall::send(reply_port, FS_READ_OK, total_read as u64, 0, 0, 0);
                } else {
                    // Inline read (up to 24 bytes).
                    let inline_len = total_read.min(MAX_INLINE);
                    if inline_len > 0 {
                        let (phys_block, off_in_block, _) = match resolve_file_extent(
                            &blk, bs, vol_omap, fs_root_block, max_xid, private_id, offset,
                        ) {
                            Some(r) => r,
                            None => {
                                syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                                continue;
                            }
                        };
                        let block_va = match cache_read(&blk, phys_block, bs) {
                            Some(va) => va,
                            None => {
                                syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                                continue;
                            }
                        };
                        let src = unsafe {
                            core::slice::from_raw_parts(
                                (block_va + off_in_block as usize) as *const u8,
                                inline_len,
                            )
                        };
                        let packed = pack_inline_data(src);
                        syscall::send(reply_port, FS_READ_OK, inline_len as u64, packed[0], packed[1], packed[2]);
                    } else {
                        syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    }
                }
            }

            FS_READDIR => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let start_offset = msg.data[3] as usize;

                // Resolve directory path.
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let dir_ino = if name_len == 0 {
                    ROOT_DIR_INO_NUM
                } else {
                    match path_resolve(&blk, bs, vol_omap, fs_root_block, max_xid, name) {
                        Some(inode) if inode.is_dir() => inode.ino,
                        _ => {
                            syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                            continue;
                        }
                    }
                };

                match dir_next_entry(&blk, bs, vol_omap, fs_root_block, max_xid, dir_ino, start_offset) {
                    Some((name_buf, name_len, ino, _ftype, next_off)) => {
                        // Pack name into data[1] and data[2].
                        let mut n0 = 0u64;
                        let mut n1 = 0u64;
                        for i in 0..name_len.min(8) {
                            n0 |= (name_buf[i] as u64) << (i * 8);
                        }
                        for i in 8..name_len.min(16) {
                            n1 |= (name_buf[i] as u64) << ((i - 8) * 8);
                        }
                        // Read inode for size.
                        let file_size = match read_inode(&blk, bs, vol_omap, fs_root_block, max_xid, ino) {
                            Some(i) => i.size,
                            None => 0,
                        };
                        syscall::send(reply_port, FS_READDIR_OK, file_size, n0, n1, next_off as u64);
                    }
                    None => {
                        syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                    }
                }
            }

            FS_STAT => {
                let handle_id = msg.data[0] as usize;
                let reply_port = msg.data[2] & 0xFFFF_FFFF;

                if handle_id >= MAX_OPEN || !handles[handle_id].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let inode = &handles[handle_id].inode;
                let uid_gid = (inode.owner as u64) | ((inode.group as u64) << 32);
                syscall::send(
                    reply_port,
                    FS_STAT_OK,
                    inode.size,
                    inode.mode as u64,
                    uid_gid,
                    inode.ino,
                );
            }

            FS_STAT_LONG => {
                let name_len = (msg.data[0] & 0xFFFF) as usize;
                let reply_port = msg.data[0] >> 32;

                let name = unsafe {
                    core::slice::from_raw_parts(VFS_LONG_PATH_SCRATCH_VA as *const u8, name_len.min(4096))
                };

                if let Some(inode) = path_resolve(&blk, bs, vol_omap, fs_root_block, max_xid, name) {
                    let uid_gid = (inode.owner as u64) | ((inode.group as u64) << 32);
                    syscall::send(reply_port, FS_STAT_OK, inode.size, inode.mode as u64, uid_gid, inode.ino);
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                }
            }

            FS_READLINK => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], name_len);
                let name = &name_buf[..name_len.min(16)];

                let ino = if let Some(inode) = path_resolve(&blk, bs, vol_omap, fs_root_block, max_xid, name) {
                    if !inode.is_symlink() {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                        continue;
                    }
                    inode.ino
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    continue;
                };

                let mut target = [0u8; 256];
                if let Some(len) = read_symlink_target(&blk, bs, vol_omap, fs_root_block, max_xid, ino, &mut target) {
                    let packed = pack_inline_data(&target[..len.min(MAX_INLINE)]);
                    syscall::send(reply_port, FS_READLINK_OK, len as u64, packed[0], packed[1], packed[2]);
                } else {
                    syscall::send(reply_port, FS_ERROR, ERR_IO, 0, 0, 0);
                }
            }

            FS_STATFS => {
                let reply_port = msg.data[2] >> 32;
                unsafe {
                    let total_blocks = BLOCK_COUNT;
                    let bsize = BLOCK_SIZE as u64;
                    syscall::send(reply_port, FS_STATFS_OK, bsize, total_blocks, 0, 0);
                }
            }

            // All write operations → read-only error.
            FS_CREATE | FS_WRITE | FS_DELETE | FS_MKDIR | FS_UNLINK |
            FS_CHMOD | FS_UTIMENS | FS_SYMLINK | FS_LINK | FS_RENAME |
            FS_CHOWN | FS_TRUNCATE | FS_MKNOD | FS_FSYNC => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
            }

            _ => {}
        }
    }
}
