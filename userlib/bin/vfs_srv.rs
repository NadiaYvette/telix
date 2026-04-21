#![no_std]
#![no_main]

//! VFS server — central path resolution and mount table.
//!
//! Maintains a mount table mapping path prefixes to filesystem server ports.
//! On VFS_OPEN, resolves the path to the correct FS server, forwards the
//! request, and returns the FS server port + handle to the client so
//! subsequent I/O goes directly to the FS server (bypassing VFS).
//!
//! Wire format (4 data words):
//!   data[0..1] = path bytes (up to 16 bytes, little-endian packed)
//!   data[2]    = path_len(16) | flags(16) | reply_port(32)
//!   data[3]    = fs_port (VFS_MOUNT only, 0 otherwise)

extern crate userlib;

use core::cmp::Ord;
use core::iter::Iterator;
use core::option::Option::{self, None, Some};
use userlib::syscall;

// VFS protocol tags.
const VFS_MOUNT: u64 = 0x6000;
const VFS_UNMOUNT: u64 = 0x6001;
const VFS_OPEN: u64 = 0x6010;
const VFS_OPEN_LONG: u64 = 0x6011;
const VFS_STAT: u64 = 0x6020;
const VFS_STAT_LONG: u64 = 0x6021;
const VFS_READDIR: u64 = 0x6030;

const VFS_OK: u64 = 0x6100;
const VFS_OPEN_OK: u64 = 0x6110;
const VFS_STAT_OK: u64 = 0x6120;
const VFS_READDIR_OK: u64 = 0x6130;
const VFS_READDIR_END: u64 = 0x6131;
const VFS_MKDIR: u64 = 0x6040;
const VFS_MKDIR_OK: u64 = 0x6140;
const VFS_UNLINK: u64 = 0x6050;
const VFS_UNLINK_OK: u64 = 0x6150;
// Phase 173: filesystem realism. Long-path style operations.
const VFS_CHMOD: u64 = 0x6080;
const VFS_CHMOD_OK: u64 = 0x6180;
const VFS_UTIMENS: u64 = 0x6090;
const VFS_UTIMENS_OK: u64 = 0x6190;

// Phase 177+: extended VFS operations.
// Symbolic links.
const VFS_SYMLINK: u64 = 0x60A0;
const VFS_SYMLINK_OK: u64 = 0x61A0;
const VFS_READLINK: u64 = 0x60A1;
const VFS_READLINK_OK: u64 = 0x61A1;
// Hard links.
const VFS_LINK: u64 = 0x60B0;
const VFS_LINK_OK: u64 = 0x61B0;
// Rename (atomic move).
const VFS_RENAME: u64 = 0x60C0;
const VFS_RENAME_OK: u64 = 0x61C0;
// Ownership.
const VFS_CHOWN: u64 = 0x60D0;
const VFS_CHOWN_OK: u64 = 0x61D0;
// Truncate.
const VFS_TRUNCATE: u64 = 0x60E0;
const VFS_TRUNCATE_OK: u64 = 0x61E0;
// Filesystem info (statfs/statvfs).
const VFS_STATFS: u64 = 0x60F0;
const VFS_STATFS_OK: u64 = 0x61F0;
// Access check.
#[allow(dead_code)]
const VFS_ACCESS: u64 = 0x60F1;
#[allow(dead_code)]
const VFS_ACCESS_OK: u64 = 0x61F1;
// Extended attributes (Linux, macOS, Haiku).
const VFS_XATTR_GET: u64 = 0x6200;
const VFS_XATTR_GET_OK: u64 = 0x6210;
const VFS_XATTR_SET: u64 = 0x6201;
const VFS_XATTR_SET_OK: u64 = 0x6211;
const VFS_XATTR_LIST: u64 = 0x6202;
const VFS_XATTR_LIST_OK: u64 = 0x6212;
const VFS_XATTR_REMOVE: u64 = 0x6203;
const VFS_XATTR_REMOVE_OK: u64 = 0x6213;
// Special file creation (mknod).
const VFS_MKNOD: u64 = 0x6220;
const VFS_MKNOD_OK: u64 = 0x6230;
// Fallocate (preallocate space).
const VFS_FALLOCATE: u64 = 0x6240;
const VFS_FALLOCATE_OK: u64 = 0x6250;
// Named streams / alternate data streams (Windows, macOS resource forks).
const VFS_STREAM_OPEN: u64 = 0x6300;
const VFS_STREAM_OPEN_OK: u64 = 0x6310;
const VFS_STREAM_LIST: u64 = 0x6301;
const VFS_STREAM_LIST_OK: u64 = 0x6311;
// Ioctl forwarding to FS servers.
const VFS_IOCTL: u64 = 0x6400;
const VFS_IOCTL_OK: u64 = 0x6410;

const VFS_ERROR: u64 = 0x6F00;

// FS protocol tags (forwarded to underlying FS servers).
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_OPEN_LONG: u64 = 0x2002;
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
const FS_STAT_LONG: u64 = 0x2302;
const FS_CHMOD: u64 = 0x2E00;
const FS_CHMOD_OK: u64 = 0x2E01;
const FS_UTIMENS: u64 = 0x2900;
const FS_UTIMENS_OK: u64 = 0x2901;

// Long-path scratch infrastructure.
//
// linux_srv (or any other personality client) grants a scratch page to VFS at
// LIN_SCRATCH_VA. VFS reads long path bytes from there. VFS in turn grants its
// own scratch page to each FS server's task port at FS_SCRATCH_VA on first
// forward, and writes the relativized path there before sending FS_OPEN_LONG.
const LIN_SCRATCH_VA: usize = 0x5_0000_0000;
const FS_SCRATCH_VA: usize = 0x5_0000_0000;
const MAX_LONG_PATH: usize = 4096;

/// Lazily-allocated VA of VFS's own scratch page (the page granted to FS servers).
static mut VFS_SCRATCH_VA: usize = 0;
// (VFS_FWD_REPLY_PORT removed — call/reply IPC replaces per-request ports.)

fn ensure_vfs_scratch() -> usize {
    unsafe {
        if VFS_SCRATCH_VA == 0 {
            match syscall::mmap_anon(0, 1, 1) {
                Some(va) => VFS_SCRATCH_VA = va,
                None => return 0,
            }
        }
        VFS_SCRATCH_VA
    }
}
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_MKDIR: u64 = 0x2A00;
const FS_MKDIR_OK: u64 = 0x2A01;
const FS_UNLINK: u64 = 0x2A20;
const FS_UNLINK_OK: u64 = 0x2A21;

// Extended FS protocol tags (forwarded to underlying FS servers).
const FS_SYMLINK: u64 = 0x2C00;
const FS_SYMLINK_OK: u64 = 0x2C01;
const FS_READLINK: u64 = 0x2C10;
const FS_READLINK_OK: u64 = 0x2C11;
const FS_LINK: u64 = 0x2C20;
const FS_LINK_OK: u64 = 0x2C21;
const FS_RENAME: u64 = 0x2C30;
const FS_RENAME_OK: u64 = 0x2C31;
const FS_CHOWN: u64 = 0x2C40;
const FS_CHOWN_OK: u64 = 0x2C41;
const FS_TRUNCATE: u64 = 0x2C50;
const FS_TRUNCATE_OK: u64 = 0x2C51;
const FS_STATFS: u64 = 0x2C60;
const FS_STATFS_OK: u64 = 0x2C61;
const FS_XATTR_GET: u64 = 0x2D00;
const FS_XATTR_GET_OK: u64 = 0x2D01;
const FS_XATTR_SET: u64 = 0x2D10;
const FS_XATTR_SET_OK: u64 = 0x2D11;
const FS_XATTR_LIST: u64 = 0x2D20;
const FS_XATTR_LIST_OK: u64 = 0x2D21;
const FS_XATTR_REMOVE: u64 = 0x2D30;
const FS_XATTR_REMOVE_OK: u64 = 0x2D31;
const FS_MKNOD: u64 = 0x2D40;
const FS_MKNOD_OK: u64 = 0x2D41;
const FS_FALLOCATE: u64 = 0x2D50;
const FS_FALLOCATE_OK: u64 = 0x2D51;
const FS_STREAM_OPEN: u64 = 0x2D60;
const FS_STREAM_OPEN_OK: u64 = 0x2D61;
const FS_STREAM_LIST: u64 = 0x2D70;
const FS_STREAM_LIST_OK: u64 = 0x2D71;
const FS_IOCTL: u64 = 0x2D80;
const FS_IOCTL_OK: u64 = 0x2D81;

const ERR_NOT_FOUND: u64 = 1;
const ERR_NO_MOUNT: u64 = 2;
const ERR_INVALID: u64 = 3;
const ERR_FULL: u64 = 4;
const ERR_IO: u64 = 5;

// Inotify notification tag.
const IN_NOTIFY: u64 = 0x7160;
const IN_EVT_OPEN: u64 = 0x020;

/// Inotify server port (looked up lazily, 0xFFFFFFFF = not found yet).
static mut INOTIFY_PORT: u64 = 0xFFFF_FFFF_FFFF_FFFF;

fn notify_inotify(event_mask: u64, path_w0: u64, path_w1: u64) {
    let port = unsafe { INOTIFY_PORT };
    if port == 0xFFFF_FFFF_FFFF_FFFF {
        // Try to look up.
        let p = match syscall::ns_lookup(b"inotify") {
            Some(p) => p,
            None => return,
        };
        unsafe {
            INOTIFY_PORT = p;
        }
        syscall::send_nb_4(p, IN_NOTIFY, event_mask, path_w0, path_w1, 0);
    } else {
        syscall::send_nb_4(port, IN_NOTIFY, event_mask, path_w0, path_w1, 0);
    }
}

const MAX_MOUNTS: usize = 8;
const MAX_PATH: usize = 16; // fits in 2 data words

/// Mount table entry.
struct MountEntry {
    prefix: [u8; MAX_PATH],
    prefix_len: usize,
    fs_port: u64,
    active: bool,
}

impl MountEntry {
    const fn empty() -> Self {
        Self {
            prefix: [0; MAX_PATH],
            prefix_len: 0,
            fs_port: 0,
            active: false,
        }
    }
}

static mut MOUNTS: [MountEntry; MAX_MOUNTS] = [const { MountEntry::empty() }; MAX_MOUNTS];

/// Unpack a path from data[0..1] (up to 16 bytes).
fn unpack_path(d0: u64, d1: u64, len: usize) -> ([u8; MAX_PATH], usize) {
    let mut buf = [0u8; MAX_PATH];
    let actual_len = if len < MAX_PATH { len } else { MAX_PATH };
    for i in 0..actual_len {
        if i < 8 {
            buf[i] = (d0 >> (i * 8)) as u8;
        } else {
            buf[i] = (d1 >> ((i - 8) * 8)) as u8;
        }
    }
    (buf, actual_len)
}

/// Pack a filename (up to 16 bytes) into 2 u64 words for FS_OPEN protocol.
fn pack_name_2(name: &[u8], name_len: usize) -> (u64, u64) {
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    let limit = if name_len < 16 { name_len } else { 16 };
    for i in 0..limit {
        if i < 8 {
            w0 |= (name[i] as u64) << (i * 8);
        } else {
            w1 |= (name[i] as u64) << ((i - 8) * 8);
        }
    }
    (w0, w1)
}

/// Normalize a path: resolve "." and ".." components.
/// Returns the normalized length.
fn normalize_path(buf: &mut [u8; MAX_PATH], len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    // Work with components (at most 4 deep for 16-byte paths).
    let mut comp_start = [0usize; 4];
    let mut comp_len_arr = [0usize; 4];
    let mut ncomp = 0usize;

    let mut i = 0;
    if buf[0] == b'/' {
        i = 1;
    }

    while i < len && ncomp < 4 {
        while i < len && buf[i] == b'/' {
            i += 1;
        }
        if i >= len {
            break;
        }

        let start = i;
        while i < len && buf[i] != b'/' {
            i += 1;
        }
        let clen = i - start;

        if clen == 1 && buf[start] == b'.' {
            continue;
        } else if clen == 2 && buf[start] == b'.' && buf[start + 1] == b'.' {
            if ncomp > 0 {
                ncomp -= 1;
            }
        } else {
            comp_start[ncomp] = start;
            comp_len_arr[ncomp] = clen;
            ncomp += 1;
        }
    }

    // Rebuild path.
    let src = *buf;
    let mut pos = 0;
    buf[pos] = b'/';
    pos += 1;
    for c in 0..ncomp {
        if c > 0 && pos < MAX_PATH {
            buf[pos] = b'/';
            pos += 1;
        }
        for j in 0..comp_len_arr[c] {
            if pos < MAX_PATH {
                buf[pos] = src[comp_start[c] + j];
                pos += 1;
            }
        }
    }
    // Zero rest.
    for k in pos..MAX_PATH {
        buf[k] = 0;
    }
    pos
}

/// Find the longest matching mount prefix for a path.
/// Returns (mount_index, remainder_start) or None.
fn find_mount(path: &[u8; MAX_PATH], path_len: usize) -> Option<(usize, usize)> {
    let mounts = unsafe { &*core::ptr::addr_of!(MOUNTS) };
    let mut best_idx: Option<usize> = None;
    let mut best_len = 0usize;

    for i in 0..MAX_MOUNTS {
        if !mounts[i].active {
            continue;
        }
        let plen = mounts[i].prefix_len;

        // Root mount "/" matches everything.
        if plen == 1 && mounts[i].prefix[0] == b'/' {
            if best_len < 1 {
                best_idx = Some(i);
                best_len = 1;
            }
            continue;
        }

        // Check prefix match.
        if path_len >= plen {
            let mut matches = true;
            for j in 0..plen {
                if path[j] != mounts[i].prefix[j] {
                    matches = false;
                    break;
                }
            }
            // Must match at component boundary.
            if matches && (path_len == plen || path[plen] == b'/') {
                if plen > best_len {
                    best_idx = Some(i);
                    best_len = plen;
                }
            }
        }
    }

    best_idx.map(|idx| {
        let remainder = if best_len == 1 { 1 } else { best_len };
        (idx, remainder)
    })
}

/// Extract the relative path after the mount prefix.
fn relative_path<'a>(
    path: &'a [u8; MAX_PATH],
    path_len: usize,
    prefix_end: usize,
) -> (&'a [u8], usize) {
    let mut start = prefix_end;
    while start < path_len && path[start] == b'/' {
        start += 1;
    }
    (&path[start..path_len], path_len - start)
}

/// Handle VFS_MOUNT: add a mount entry.
/// data[2] = path_len(16) | reply_port(32 in upper), data[3] = fs_port.
fn handle_mount(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let fs_port = data[3];
    let (path, plen) = unpack_path(data[0], data[1], path_len);

    if plen == 0 || plen > MAX_PATH || fs_port == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let mounts = unsafe { &mut *core::ptr::addr_of_mut!(MOUNTS) };

    // Check for existing mount at same path — update it.
    for i in 0..MAX_MOUNTS {
        if mounts[i].active && mounts[i].prefix_len == plen {
            let mut same = true;
            for j in 0..plen {
                if mounts[i].prefix[j] != path[j] {
                    same = false;
                    break;
                }
            }
            if same {
                mounts[i].fs_port = fs_port;
                let _ = syscall::reply(VFS_OK, 0, 0, 0, 0, 0);
                return;
            }
        }
    }

    // Find free slot.
    for i in 0..MAX_MOUNTS {
        if !mounts[i].active {
            mounts[i].prefix = path;
            mounts[i].prefix_len = plen;
            mounts[i].fs_port = fs_port;
            mounts[i].active = true;
            let _ = syscall::reply(VFS_OK, 0, 0, 0, 0, 0);
            return;
        }
    }

    let _ = syscall::reply(VFS_ERROR, ERR_FULL, 0, 0, 0, 0);
}

/// Handle VFS_UNMOUNT: remove a mount entry.
fn handle_unmount(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let (path, plen) = unpack_path(data[0], data[1], path_len);

    let mounts = unsafe { &mut *core::ptr::addr_of_mut!(MOUNTS) };
    for i in 0..MAX_MOUNTS {
        if !mounts[i].active {
            continue;
        }
        if mounts[i].prefix_len != plen {
            continue;
        }
        let mut same = true;
        for j in 0..plen {
            if mounts[i].prefix[j] != path[j] {
                same = false;
                break;
            }
        }
        if same {
            mounts[i].active = false;
            let _ = syscall::reply(VFS_OK, 0, 0, 0, 0, 0);
            return;
        }
    }
    let _ = syscall::reply(VFS_ERROR, ERR_NOT_FOUND, 0, 0, 0, 0);
}

/// Read a long path written into LIN_SCRATCH_VA by a personality client.
/// Returns the number of bytes read into `dst` (clamped to dst.len() and 4096).
fn read_long_path(dst: &mut [u8], path_len: usize) -> usize {
    let n = path_len.min(dst.len()).min(MAX_LONG_PATH);
    let src = LIN_SCRATCH_VA as *const u8;
    for i in 0..n {
        dst[i] = unsafe { *src.add(i) };
    }
    n
}

/// Normalize a long (>16 byte) path in `buf[..len]`. Resolves "." and "..".
/// Returns the new length. Up to 16 components.
fn normalize_long(buf: &mut [u8], len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let mut comp_start = [0usize; 16];
    let mut comp_len_arr = [0usize; 16];
    let mut ncomp = 0usize;

    let mut i = 0;
    if buf[0] == b'/' {
        i = 1;
    }
    while i < len && ncomp < 16 {
        while i < len && buf[i] == b'/' {
            i += 1;
        }
        if i >= len {
            break;
        }
        let start = i;
        while i < len && buf[i] != b'/' {
            i += 1;
        }
        let clen = i - start;
        if clen == 1 && buf[start] == b'.' {
            continue;
        } else if clen == 2 && buf[start] == b'.' && buf[start + 1] == b'.' {
            if ncomp > 0 {
                ncomp -= 1;
            }
        } else {
            comp_start[ncomp] = start;
            comp_len_arr[ncomp] = clen;
            ncomp += 1;
        }
    }

    // Rebuild in a temporary then copy back. Use a stack scratch capped at MAX_LONG_PATH.
    let mut tmp = [0u8; 256];
    let cap = tmp.len().min(len + 1);
    let mut pos = 0;
    if pos < cap {
        tmp[pos] = b'/';
        pos += 1;
    }
    for c in 0..ncomp {
        if c > 0 && pos < cap {
            tmp[pos] = b'/';
            pos += 1;
        }
        for j in 0..comp_len_arr[c] {
            if pos < cap {
                tmp[pos] = buf[comp_start[c] + j];
                pos += 1;
            }
        }
    }
    for k in 0..pos {
        buf[k] = tmp[k];
    }
    pos
}

/// Find longest mount prefix for a long path slice.
fn find_mount_long(path: &[u8]) -> Option<(usize, usize)> {
    let mounts = unsafe { &*core::ptr::addr_of!(MOUNTS) };
    let mut best_idx: Option<usize> = None;
    let mut best_len = 0usize;
    let path_len = path.len();
    for i in 0..MAX_MOUNTS {
        if !mounts[i].active {
            continue;
        }
        let plen = mounts[i].prefix_len;
        if plen == 1 && mounts[i].prefix[0] == b'/' {
            if best_len < 1 {
                best_idx = Some(i);
                best_len = 1;
            }
            continue;
        }
        if path_len >= plen {
            let mut matches = true;
            for j in 0..plen {
                if path[j] != mounts[i].prefix[j] {
                    matches = false;
                    break;
                }
            }
            if matches && (path_len == plen || path[plen] == b'/') {
                if plen > best_len {
                    best_idx = Some(i);
                    best_len = plen;
                }
            }
        }
    }
    best_idx.map(|idx| (idx, best_len))
}

/// Cached fs_port → fs_task → grant-done state.
/// Currently we only support up to 4 distinct FS servers needing long-path
/// forwarding. Each entry caches the discovered task port and remembers
/// whether VFS's scratch page has been granted to it yet.
struct FsScratchEntry {
    fs_port: u64,
    fs_task: u64,
    granted: bool,
}
static mut FS_SCRATCH_TABLE: [FsScratchEntry; 4] = [
    FsScratchEntry { fs_port: 0, fs_task: 0, granted: false },
    FsScratchEntry { fs_port: 0, fs_task: 0, granted: false },
    FsScratchEntry { fs_port: 0, fs_task: 0, granted: false },
    FsScratchEntry { fs_port: 0, fs_task: 0, granted: false },
];

/// Known FS server names for which we will look up `<name>_task` lazily.
const KNOWN_FS_NAMES: &[&[u8]] = &[b"rootfs", b"ext2", b"fat", b"tmpfs"];

/// Discover the task port for a given fs_port by ns-looking-up known FS names
/// until one matches. Returns 0 if not found.
fn discover_fs_task(fs_port: u64) -> u64 {
    for name in KNOWN_FS_NAMES.iter() {
        if let Some(p) = syscall::ns_lookup(name) {
            if p == fs_port {
                // Build "<name>_task".
                let mut buf = [0u8; 32];
                let mut n = 0;
                for &b in name.iter() {
                    if n < buf.len() { buf[n] = b; n += 1; }
                }
                for &b in b"_task".iter() {
                    if n < buf.len() { buf[n] = b; n += 1; }
                }
                if let Some(t) = syscall::ns_lookup(&buf[..n]) {
                    return t;
                }
            }
        }
    }
    0
}

/// Lazily grant VFS's scratch page to the FS server (identified by fs_port).
/// Returns true on success.
fn ensure_fs_scratch_grant(fs_port: u64) -> bool {
    let table = unsafe { &mut *core::ptr::addr_of_mut!(FS_SCRATCH_TABLE) };
    // Look up existing entry.
    let mut slot: Option<usize> = None;
    for (i, e) in table.iter().enumerate() {
        if e.fs_port == fs_port { slot = Some(i); break; }
    }
    let idx = match slot {
        Some(i) => i,
        None => {
            // Allocate a new slot.
            let mut found: Option<usize> = None;
            for (i, e) in table.iter().enumerate() {
                if e.fs_port == 0 { found = Some(i); break; }
            }
            let i = match found { Some(x) => x, None => return false };
            table[i].fs_port = fs_port;
            table[i].fs_task = discover_fs_task(fs_port);
            i
        }
    };
    if table[idx].fs_task == 0 {
        return false;
    }
    if table[idx].granted {
        return true;
    }
    let src_va = ensure_vfs_scratch();
    if src_va == 0 {
        return false;
    }
    let ok = syscall::grant_pages(table[idx].fs_task, src_va, FS_SCRATCH_VA, 1, false);
    if ok {
        table[idx].granted = true;
    }
    ok
}

/// Common long-path forwarder: takes a tag (FS_OPEN_LONG / FS_STAT_LONG),
/// the absolute path, flags, stashed client cap, and forwards to the FS server.
/// Wire format for FS_*_LONG: data[0] = rel_len(16)|flags(16).
/// Path bytes live in FS_SCRATCH_VA in the FS server's aspace.
fn forward_fs_long(
    fs_tag: u64,
    expect_ok: u64,
    abs_path: &[u8],
    flags: u32,
    client_cap: u64,
    err_tag: u64,
) {
    let plen = abs_path.len();
    let (mount_idx, prefix_end) = match find_mount_long(abs_path) {
        Some(r) => r,
        None => {
            syscall::reply_to(client_cap, err_tag, ERR_NO_MOUNT, 0, 0, 0);
            return;
        }
    };

    let fs_port_for_grant = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    if !ensure_fs_scratch_grant(fs_port_for_grant) {
        syscall::reply_to(client_cap, err_tag, ERR_IO, 0, 0, 0);
        return;
    }

    // Compute the relative path inside the FS.
    let mut rel_start = if prefix_end == 1 { 1 } else { prefix_end };
    while rel_start < plen && abs_path[rel_start] == b'/' {
        rel_start += 1;
    }
    let rel = &abs_path[rel_start..];
    let rel_len = rel.len();

    // Write the relative path into VFS's own scratch (which is mapped at
    // FS_SCRATCH_VA in the FS server's aspace via the lazy grant).
    let scratch = unsafe { VFS_SCRATCH_VA };
    if scratch == 0 {
        syscall::reply_to(client_cap, err_tag, ERR_IO, 0, 0, 0);
        return;
    }
    let dst = scratch as *mut u8;
    for i in 0..rel_len.min(MAX_LONG_PATH) {
        unsafe { *dst.add(i) = rel[i] };
    }

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let d0 = (rel_len as u64) | ((flags as u64 & 0xFFFF) << 16);
    if let Some(fs_reply) = syscall::call(fs_port, fs_tag, d0, 0, 0, 0) {
        if fs_reply.tag == expect_ok {
            // Same reply shape as the short variant.
            if expect_ok == FS_OPEN_OK {
                let handle = fs_reply.data[0];
                let size = fs_reply.data[1];
                let fs_aspace = fs_reply.data[2];
                syscall::reply_to(
                    client_cap,
                    VFS_OPEN_OK,
                    fs_port,
                    handle,
                    size,
                    fs_aspace,
                );
            } else if expect_ok == FS_STAT_OK {
                syscall::reply_to(
                    client_cap,
                    VFS_STAT_OK,
                    fs_reply.data[0],
                    fs_reply.data[1],
                    fs_reply.data[2],
                    fs_reply.data[3],
                );
            }
        } else {
            syscall::reply_to(client_cap, err_tag, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, err_tag, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_OPEN_LONG: client has written the absolute path to LIN_SCRATCH_VA.
/// data[0] = path_len(16) | flags(16).
fn handle_open_long(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;
    let flags = ((data[0] >> 16) & 0xFFFF) as u32;

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }
    let client_cap = syscall::reply_take();
    forward_fs_long(FS_OPEN_LONG, FS_OPEN_OK, &buf[..n], flags, client_cap, VFS_ERROR);
}

/// Handle VFS_STAT_LONG: same as VFS_OPEN_LONG but stat-only.
/// data[0] = path_len(16).
fn handle_stat_long(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }
    let client_cap = syscall::reply_take();
    forward_fs_long(FS_STAT_LONG, FS_STAT_OK, &buf[..n], 0, client_cap, VFS_ERROR);
}

/// Handle VFS_CHMOD: long-path. data[0] = path_len(16) | mode(16).
/// Path bytes live at LIN_SCRATCH_VA in our aspace.
fn handle_chmod(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;
    let mode = ((data[0] >> 16) & 0xFFFF) as u32;

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let abs_path = &buf[..n];
    let plen = abs_path.len();
    let (mount_idx, prefix_end) = match find_mount_long(abs_path) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };
    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    if !ensure_fs_scratch_grant(fs_port) {
        let _ = syscall::reply(VFS_ERROR, ERR_IO, 0, 0, 0, 0);
        return;
    }

    let mut rel_start = if prefix_end == 1 { 1 } else { prefix_end };
    while rel_start < plen && abs_path[rel_start] == b'/' {
        rel_start += 1;
    }
    let rel = &abs_path[rel_start..];
    let rel_len = rel.len();
    let scratch = unsafe { VFS_SCRATCH_VA };
    if scratch == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_IO, 0, 0, 0, 0);
        return;
    }
    let dst = scratch as *mut u8;
    for i in 0..rel_len.min(MAX_LONG_PATH) {
        unsafe { *dst.add(i) = rel[i] };
    }

    let client_cap = syscall::reply_take();
    let d0 = (rel_len as u64) | ((mode as u64 & 0xFFFF) << 16);
    if let Some(fs_reply) = syscall::call(fs_port, FS_CHMOD, d0, 0, 0, 0) {
        if fs_reply.tag == FS_CHMOD_OK {
            syscall::reply_to(client_cap, VFS_CHMOD_OK, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_UTIMENS: long-path. data[0] = path_len(16).
/// data[1] = atime_secs, data[2] = mtime_secs.
fn handle_utimens(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;
    let atime = data[1];
    let mtime = data[2];

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let abs_path = &buf[..n];
    let plen = abs_path.len();
    let (mount_idx, prefix_end) = match find_mount_long(abs_path) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };
    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    if !ensure_fs_scratch_grant(fs_port) {
        let _ = syscall::reply(VFS_ERROR, ERR_IO, 0, 0, 0, 0);
        return;
    }

    let mut rel_start = if prefix_end == 1 { 1 } else { prefix_end };
    while rel_start < plen && abs_path[rel_start] == b'/' {
        rel_start += 1;
    }
    let rel = &abs_path[rel_start..];
    let rel_len = rel.len();
    let scratch = unsafe { VFS_SCRATCH_VA };
    if scratch == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_IO, 0, 0, 0, 0);
        return;
    }
    let dst = scratch as *mut u8;
    for i in 0..rel_len.min(MAX_LONG_PATH) {
        unsafe { *dst.add(i) = rel[i] };
    }

    let client_cap = syscall::reply_take();
    let d0 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_UTIMENS, d0, atime, mtime, 0) {
        if fs_reply.tag == FS_UTIMENS_OK {
            syscall::reply_to(client_cap, VFS_UTIMENS_OK, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_OPEN: resolve path, forward FS_OPEN to FS server, return result.
/// data[2] = path_len(16) | flags(16)
fn handle_open(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let _flags = ((data[2] >> 16) & 0xFFFF) as u32;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    // Find mount.
    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };

    // Get relative path within the filesystem.
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    // Forward FS_OPEN to the filesystem server via call/reply.
    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_OPEN, n0, n1, d2, 0) {
        if fs_reply.tag == FS_OPEN_OK {
            let handle = fs_reply.data[0];
            let size = fs_reply.data[1];
            let fs_aspace = fs_reply.data[2];
            syscall::reply_to(
                client_cap,
                VFS_OPEN_OK,
                fs_port as u64,
                handle,
                size,
                fs_aspace,
            );
            // Notify inotify server of file open.
            notify_inotify(IN_EVT_OPEN, data[0], data[1]);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_STAT: resolve path, forward FS_STAT to FS server.
fn handle_stat(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_STAT, n0, n1, d2, 0) {
        if fs_reply.tag == FS_STAT_OK {
            syscall::reply_to(
                client_cap,
                VFS_STAT_OK,
                fs_reply.data[0],
                fs_reply.data[1],
                fs_reply.data[2],
                fs_reply.data[3],
            );
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_READDIR: resolve path, forward FS_READDIR to FS server.
/// Under call/reply, this is per-entry: client sends offset in data[3],
/// VFS forwards one FS_READDIR call, relays the single reply (OK or END).
fn handle_readdir(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let start_offset = data[3];

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_READDIR, n0, n1, d2, start_offset) {
        if fs_reply.tag == FS_READDIR_OK {
            syscall::reply_to(
                client_cap,
                VFS_READDIR_OK,
                fs_reply.data[0],
                fs_reply.data[1],
                fs_reply.data[2],
                fs_reply.data[3],
            );
        } else if fs_reply.tag == FS_READDIR_END {
            syscall::reply_to(client_cap, VFS_READDIR_END, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_MKDIR: resolve path, forward FS_MKDIR to FS server.
/// data[2] = path_len(16) | mode(16)
fn handle_mkdir(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let mode = ((data[2] >> 16) & 0xFFFF) as u32;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = (rel_len as u64) | ((mode as u64) << 16);
    if let Some(fs_reply) = syscall::call(fs_port, FS_MKDIR, n0, n1, d2, 0) {
        if fs_reply.tag == FS_MKDIR_OK {
            syscall::reply_to(client_cap, VFS_MKDIR_OK, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Generic single-path forwarding: resolve path, forward an FS_* tag to the
/// FS server with the same data layout as VFS_MKDIR/VFS_UNLINK, and relay
/// the response back.  Used for most simple path operations.
///
/// `fs_tag` / `fs_ok_tag` / `vfs_ok_tag` identify the operation.
/// `extra_d2_bits` are OR'd into the data[2] word sent to the FS server
/// (above the path_len in low 16 bits and reply_port in high 32 bits).
/// `extra_data` is sent as data[3] to the FS server (for operations
/// that carry additional payload like uid/gid, size, mode, etc.).
fn forward_path_op(
    data: &[u64; 6],
    fs_tag: u64,
    fs_ok_tag: u64,
    vfs_ok_tag: u64,
    extra_d2_bits: u64,
    extra_data: u64,
) {
    let path_len = (data[2] & 0xFFFF) as usize;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = (rel_len as u64) | extra_d2_bits;
    if let Some(fs_reply) = syscall::call(fs_port, fs_tag, n0, n1, d2, extra_data) {
        if fs_reply.tag == fs_ok_tag {
            syscall::reply_to(
                client_cap,
                vfs_ok_tag,
                fs_reply.data[0],
                fs_reply.data[1],
                fs_reply.data[2],
                fs_reply.data[3],
            );
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_SYMLINK: create a symbolic link.
/// data[0..1] = link path (the new symlink), data[2] = len,
/// data[3..4] = target path bytes (up to 16 bytes), data[5] = target length.
fn handle_symlink(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_SYMLINK, n0, n1, d2, data[3]) {
        if fs_reply.tag == FS_SYMLINK_OK {
            syscall::reply_to(client_cap, VFS_SYMLINK_OK, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_READLINK: read symbolic link target.
/// data[0..1] = path, data[2] = len | reply_port.
fn handle_readlink(data: &[u64; 6]) {
    forward_path_op(data, FS_READLINK, FS_READLINK_OK, VFS_READLINK_OK, 0, 0);
}

/// Handle VFS_LINK: create a hard link.
/// data[0..1] = existing path, data[2] = len,
/// data[3..4] = new link path, data[5] = new link path length.
fn handle_link(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_LINK, n0, n1, d2, data[3]) {
        if fs_reply.tag == FS_LINK_OK {
            syscall::reply_to(client_cap, VFS_LINK_OK, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_RENAME: atomic rename/move.
/// data[0..1] = old path, data[2] = old_len,
/// data[3..4] = new path, data[5] = new path length.
fn handle_rename(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_RENAME, n0, n1, d2, data[3]) {
        if fs_reply.tag == FS_RENAME_OK {
            syscall::reply_to(client_cap, VFS_RENAME_OK, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_CHOWN: change file owner/group.
/// data[0..1] = path, data[2] = len | reply_port, data[3] = uid(32) | gid(32).
fn handle_chown(data: &[u64; 6]) {
    forward_path_op(data, FS_CHOWN, FS_CHOWN_OK, VFS_CHOWN_OK, 0, data[3]);
}

/// Handle VFS_TRUNCATE: truncate file to specified size.
/// data[0..1] = path, data[2] = len | reply_port, data[3] = new size.
fn handle_truncate(data: &[u64; 6]) {
    forward_path_op(data, FS_TRUNCATE, FS_TRUNCATE_OK, VFS_TRUNCATE_OK, 0, data[3]);
}

/// Handle VFS_STATFS: query filesystem statistics.
/// data[0..1] = path, data[2] = len | reply_port.
fn handle_statfs(data: &[u64; 6]) {
    forward_path_op(data, FS_STATFS, FS_STATFS_OK, VFS_STATFS_OK, 0, 0);
}

/// Handle VFS_XATTR_GET: get extended attribute.
/// data[0..1] = path, data[2] = len | reply_port, data[3..4] = attr name, data[5] = attr_name_len.
fn handle_xattr_get(data: &[u64; 6]) {
    forward_path_op(data, FS_XATTR_GET, FS_XATTR_GET_OK, VFS_XATTR_GET_OK, 0, data[3]);
}

/// Handle VFS_XATTR_SET: set extended attribute.
/// data[0..1] = path, data[2] = len | reply_port, data[3] = attr name word, data[4] = value word, data[5] = sizes.
fn handle_xattr_set(data: &[u64; 6]) {
    forward_path_op(data, FS_XATTR_SET, FS_XATTR_SET_OK, VFS_XATTR_SET_OK, 0, data[3]);
}

/// Handle VFS_XATTR_LIST: list extended attributes.
/// data[0..1] = path, data[2] = len | reply_port.
fn handle_xattr_list(data: &[u64; 6]) {
    forward_path_op(data, FS_XATTR_LIST, FS_XATTR_LIST_OK, VFS_XATTR_LIST_OK, 0, 0);
}

/// Handle VFS_XATTR_REMOVE: remove extended attribute.
/// data[0..1] = path, data[2] = len | reply_port, data[3] = attr name.
fn handle_xattr_remove(data: &[u64; 6]) {
    forward_path_op(data, FS_XATTR_REMOVE, FS_XATTR_REMOVE_OK, VFS_XATTR_REMOVE_OK, 0, data[3]);
}

/// Handle VFS_MKNOD: create special file (device, FIFO, socket).
/// data[0..1] = path, data[2] = len(16) | mode(16) | reply_port(32), data[3] = dev (major/minor).
fn handle_mknod(data: &[u64; 6]) {
    let mode_bits = (data[2] >> 16) & 0xFFFF;
    forward_path_op(data, FS_MKNOD, FS_MKNOD_OK, VFS_MKNOD_OK, mode_bits << 16, data[3]);
}

/// Handle VFS_FALLOCATE: preallocate space.
/// data[0..1] = path, data[2] = len | reply_port, data[3] = offset, data[4] = length.
fn handle_fallocate(data: &[u64; 6]) {
    forward_path_op(data, FS_FALLOCATE, FS_FALLOCATE_OK, VFS_FALLOCATE_OK, 0, data[3]);
}

/// Handle VFS_STREAM_OPEN: open named stream / alternate data stream.
/// data[0..1] = path:stream, data[2] = len | reply_port.
fn handle_stream_open(data: &[u64; 6]) {
    forward_path_op(data, FS_STREAM_OPEN, FS_STREAM_OPEN_OK, VFS_STREAM_OPEN_OK, 0, 0);
}

/// Handle VFS_STREAM_LIST: list named streams on a file.
/// data[0..1] = path, data[2] = len | reply_port.
fn handle_stream_list(data: &[u64; 6]) {
    forward_path_op(data, FS_STREAM_LIST, FS_STREAM_LIST_OK, VFS_STREAM_LIST_OK, 0, 0);
}

/// Handle VFS_IOCTL: forward ioctl to FS server.
/// data[0..1] = path, data[2] = len | reply_port, data[3] = ioctl cmd, data[4] = arg.
fn handle_ioctl(data: &[u64; 6]) {
    forward_path_op(data, FS_IOCTL, FS_IOCTL_OK, VFS_IOCTL_OK, 0, data[3]);
}

/// Handle VFS_UNLINK: resolve path, forward FS_UNLINK to FS server.
/// data[2] = path_len(16)
fn handle_unlink(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            let _ = syscall::reply(VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0, 0);
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let client_cap = syscall::reply_take();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = rel_len as u64;
    if let Some(fs_reply) = syscall::call(fs_port, FS_UNLINK, n0, n1, d2, 0) {
        if fs_reply.tag == FS_UNLINK_OK {
            syscall::reply_to(client_cap, VFS_UNLINK_OK, 0, 0, 0, 0);
        } else {
            syscall::reply_to(client_cap, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else {
        syscall::reply_to(client_cap, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [vfs_srv] starting\n");

    // Create port and register with name server.
    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"  [vfs_srv] FAIL\n");
        syscall::exit(1);
    }
    syscall::ns_register(b"vfs", port);
    // Publish our task port so personality clients (and other servers) can
    // grant_pages to us for long-path scratch buffers.
    syscall::ns_register(b"vfs_task", syscall::aspace_id());
    syscall::debug_puts(b"  [vfs_srv] ready\n");

    // Main message loop (blocking recv).
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => break,
        };
        match msg.tag {
            VFS_MOUNT => handle_mount(&msg.data),
            VFS_UNMOUNT => handle_unmount(&msg.data),
            VFS_OPEN => handle_open(&msg.data),
            VFS_OPEN_LONG => handle_open_long(&msg.data),
            VFS_STAT => handle_stat(&msg.data),
            VFS_STAT_LONG => handle_stat_long(&msg.data),
            VFS_READDIR => handle_readdir(&msg.data),
            VFS_MKDIR => handle_mkdir(&msg.data),
            VFS_UNLINK => handle_unlink(&msg.data),
            VFS_CHMOD => handle_chmod(&msg.data),
            VFS_UTIMENS => handle_utimens(&msg.data),
            VFS_SYMLINK => handle_symlink(&msg.data),
            VFS_READLINK => handle_readlink(&msg.data),
            VFS_LINK => handle_link(&msg.data),
            VFS_RENAME => handle_rename(&msg.data),
            VFS_CHOWN => handle_chown(&msg.data),
            VFS_TRUNCATE => handle_truncate(&msg.data),
            VFS_STATFS => handle_statfs(&msg.data),
            VFS_XATTR_GET => handle_xattr_get(&msg.data),
            VFS_XATTR_SET => handle_xattr_set(&msg.data),
            VFS_XATTR_LIST => handle_xattr_list(&msg.data),
            VFS_XATTR_REMOVE => handle_xattr_remove(&msg.data),
            VFS_MKNOD => handle_mknod(&msg.data),
            VFS_FALLOCATE => handle_fallocate(&msg.data),
            VFS_STREAM_OPEN => handle_stream_open(&msg.data),
            VFS_STREAM_LIST => handle_stream_list(&msg.data),
            VFS_IOCTL => handle_ioctl(&msg.data),
            _ => {
                let _ = syscall::reply(VFS_ERROR, ERR_INVALID, 0, 0, 0, 0);
            }
        }
    }
}
