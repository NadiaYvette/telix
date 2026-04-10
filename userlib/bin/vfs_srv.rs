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
/// Cached reply port for forward_fs_long (avoids per-request port_create/destroy).
static mut VFS_FWD_REPLY_PORT: u64 = 0;

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
    let reply_port = data[2] >> 32;
    let fs_port = data[3];
    let (path, plen) = unpack_path(data[0], data[1], path_len);

    if plen == 0 || plen > MAX_PATH || fs_port == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
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
                if reply_port != 0 {
                    syscall::send(reply_port, VFS_OK, 0, 0, 0, 0);
                }
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
            if reply_port != 0 {
                syscall::send(reply_port, VFS_OK, 0, 0, 0, 0);
            }
            return;
        }
    }

    if reply_port != 0 {
        syscall::send(reply_port, VFS_ERROR, ERR_FULL, 0, 0, 0);
    }
}

/// Handle VFS_UNMOUNT: remove a mount entry.
fn handle_unmount(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let reply_port = data[2] >> 32;
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
            if reply_port != 0 {
                syscall::send(reply_port, VFS_OK, 0, 0, 0, 0);
            }
            return;
        }
    }
    if reply_port != 0 {
        syscall::send(reply_port, VFS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
    }
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
const KNOWN_FS_NAMES: &[&[u8]] = &[b"rootfs", b"ext2", b"fat16", b"tmpfs"];

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
/// the absolute path, flags, reply_port, and forwards to the FS server.
/// Wire format for FS_*_LONG: data[0] = rel_len(16)|flags(16)|reply_port(32),
/// data[1..] reserved. Path bytes live in FS_SCRATCH_VA in the FS server's aspace.
fn forward_fs_long(
    fs_tag: u64,
    expect_ok: u64,
    abs_path: &[u8],
    flags: u32,
    client_reply: u64,
    err_tag: u64,
) {
    let plen = abs_path.len();
    let (mount_idx, prefix_end) = match find_mount_long(abs_path) {
        Some(r) => r,
        None => {
            if client_reply != 0 {
                syscall::send(client_reply, err_tag, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };

    let fs_port_for_grant = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    if !ensure_fs_scratch_grant(fs_port_for_grant) {
        if client_reply != 0 {
            syscall::send(client_reply, err_tag, ERR_IO, 0, 0, 0);
        }
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
        if client_reply != 0 {
            syscall::send(client_reply, err_tag, ERR_IO, 0, 0, 0);
        }
        return;
    }
    let dst = scratch as *mut u8;
    for i in 0..rel_len.min(MAX_LONG_PATH) {
        unsafe { *dst.add(i) = rel[i] };
    }

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let my_reply = unsafe {
        if VFS_FWD_REPLY_PORT == 0 {
            VFS_FWD_REPLY_PORT = syscall::port_create();
        }
        VFS_FWD_REPLY_PORT
    };
    let d0 = (rel_len as u64) | ((flags as u64 & 0xFFFF) << 16) | ((my_reply as u64) << 32);
    syscall::send(fs_port, fs_tag, d0, 0, 0, 0);

    if let Some(fs_reply) = syscall::recv_msg(my_reply) {
        if fs_reply.tag == expect_ok {
            if client_reply != 0 {
                // Same reply shape as the short variant.
                if expect_ok == FS_OPEN_OK {
                    let handle = fs_reply.data[0];
                    let size = fs_reply.data[1];
                    let fs_aspace = fs_reply.data[2];
                    syscall::send(
                        client_reply,
                        VFS_OPEN_OK,
                        fs_port,
                        handle,
                        size,
                        fs_aspace,
                    );
                } else if expect_ok == FS_STAT_OK {
                    syscall::send(
                        client_reply,
                        VFS_STAT_OK,
                        fs_reply.data[0],
                        fs_reply.data[1],
                        fs_reply.data[2],
                        fs_reply.data[3],
                    );
                }
            }
        } else {
            if client_reply != 0 {
                syscall::send(client_reply, err_tag, fs_reply.data[0], 0, 0, 0);
            }
        }
    } else if client_reply != 0 {
        syscall::send(client_reply, err_tag, ERR_IO, 0, 0, 0);
    }
}

/// Handle VFS_OPEN_LONG: client has written the absolute path to LIN_SCRATCH_VA.
/// data[0] = path_len(16) | flags(16) | reply_port(32).
fn handle_open_long(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;
    let flags = ((data[0] >> 16) & 0xFFFF) as u32;
    let reply_port = data[0] >> 32;

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }
    forward_fs_long(FS_OPEN_LONG, FS_OPEN_OK, &buf[..n], flags, reply_port, VFS_ERROR);
}

/// Handle VFS_STAT_LONG: same as VFS_OPEN_LONG but stat-only.
/// data[0] = path_len(16) | reply_port(32 in upper 32 of bits >=32).
fn handle_stat_long(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;
    let reply_port = data[0] >> 32;

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }
    forward_fs_long(FS_STAT_LONG, FS_STAT_OK, &buf[..n], 0, reply_port, VFS_ERROR);
}

/// Handle VFS_CHMOD: long-path. data[0] = path_len(16) | mode(16) | reply_port(32).
/// Path bytes live at LIN_SCRATCH_VA in our aspace.
fn handle_chmod(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;
    let mode = ((data[0] >> 16) & 0xFFFF) as u32;
    let reply_port = data[0] >> 32;

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }

    let abs_path = &buf[..n];
    let plen = abs_path.len();
    let (mount_idx, prefix_end) = match find_mount_long(abs_path) {
        Some(r) => r,
        None => {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };
    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    if !ensure_fs_scratch_grant(fs_port) {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
        }
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
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
        }
        return;
    }
    let dst = scratch as *mut u8;
    for i in 0..rel_len.min(MAX_LONG_PATH) {
        unsafe { *dst.add(i) = rel[i] };
    }

    let my_reply = syscall::port_create();
    let d0 = (rel_len as u64) | ((mode as u64 & 0xFFFF) << 16) | ((my_reply as u64) << 32);
    syscall::send(fs_port, FS_CHMOD, d0, 0, 0, 0);
    if let Some(fs_reply) = syscall::recv_msg(my_reply) {
        if fs_reply.tag == FS_CHMOD_OK {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_CHMOD_OK, 0, 0, 0, 0);
            }
        } else if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else if reply_port != 0 {
        syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
    syscall::port_destroy(my_reply);
}

/// Handle VFS_UTIMENS: long-path. data[0] = path_len(16) | reply_port(32).
/// data[1] = atime_secs, data[2] = mtime_secs.
fn handle_utimens(data: &[u64; 6]) {
    let path_len = (data[0] & 0xFFFF) as usize;
    let reply_port = data[0] >> 32;
    let atime = data[1];
    let mtime = data[2];

    let mut buf = [0u8; 256];
    let n = read_long_path(&mut buf, path_len);
    let n = normalize_long(&mut buf, n);
    if n == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }

    let abs_path = &buf[..n];
    let plen = abs_path.len();
    let (mount_idx, prefix_end) = match find_mount_long(abs_path) {
        Some(r) => r,
        None => {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };
    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    if !ensure_fs_scratch_grant(fs_port) {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
        }
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
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
        }
        return;
    }
    let dst = scratch as *mut u8;
    for i in 0..rel_len.min(MAX_LONG_PATH) {
        unsafe { *dst.add(i) = rel[i] };
    }

    let my_reply = syscall::port_create();
    let d0 = (rel_len as u64) | ((my_reply as u64) << 32);
    syscall::send(fs_port, FS_UTIMENS, d0, atime, mtime, 0);
    if let Some(fs_reply) = syscall::recv_msg(my_reply) {
        if fs_reply.tag == FS_UTIMENS_OK {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_UTIMENS_OK, 0, 0, 0, 0);
            }
        } else if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
        }
    } else if reply_port != 0 {
        syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
    }
    syscall::port_destroy(my_reply);
}

/// Handle VFS_OPEN: resolve path, forward FS_OPEN to FS server, return result.
/// data[2] = path_len(16) | flags(16) | reply_port(32)
fn handle_open(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let _flags = ((data[2] >> 16) & 0xFFFF) as u32;
    let reply_port = data[2] >> 32;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }

    // Find mount.
    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };

    // Get relative path within the filesystem.
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    // Forward FS_OPEN to the filesystem server.
    // FS_OPEN protocol: data[0]=name_lo, data[1]=name_hi, data[2]=len|(reply<<32)
    let my_reply = syscall::port_create();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = (rel_len as u64) | ((my_reply as u64) << 32);
    syscall::send(fs_port, FS_OPEN, n0, n1, d2, 0);

    // Wait for FS server reply (blocking).
    if let Some(fs_reply) = syscall::recv_msg(my_reply) {
        if fs_reply.tag == FS_OPEN_OK {
            let handle = fs_reply.data[0];
            let size = fs_reply.data[1];
            let fs_aspace = fs_reply.data[2];
            if reply_port != 0 {
                syscall::send(
                    reply_port,
                    VFS_OPEN_OK,
                    fs_port as u64,
                    handle,
                    size,
                    fs_aspace,
                );
            }
            // Notify inotify server of file open.
            notify_inotify(IN_EVT_OPEN, data[0], data[1]);
        } else {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
            }
        }
    } else {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
        }
    }

    syscall::port_destroy(my_reply);
}

/// Handle VFS_STAT: resolve path, forward FS_STAT to FS server.
fn handle_stat(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let reply_port = data[2] >> 32;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let my_reply = syscall::port_create();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = (rel_len as u64) | ((my_reply as u64) << 32);
    syscall::send(fs_port, FS_STAT, n0, n1, d2, 0);

    if let Some(fs_reply) = syscall::recv_msg(my_reply) {
        if fs_reply.tag == FS_STAT_OK {
            if reply_port != 0 {
                syscall::send(
                    reply_port,
                    VFS_STAT_OK,
                    fs_reply.data[0],
                    fs_reply.data[1],
                    fs_reply.data[2],
                    fs_reply.data[3],
                );
            }
        } else {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
            }
        }
    } else if reply_port != 0 {
        syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
    }

    syscall::port_destroy(my_reply);
}

/// Handle VFS_READDIR: resolve path, forward FS_READDIR to FS server.
fn handle_readdir(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let reply_port = data[2] >> 32;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let my_reply = syscall::port_create();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = (rel_len as u64) | ((my_reply as u64) << 32);
    syscall::send(fs_port, FS_READDIR, n0, n1, d2, 0);

    // Stream readdir entries from FS server to client (blocking recv).
    for _ in 0..200 {
        if let Some(fs_reply) = syscall::recv_msg(my_reply) {
            if fs_reply.tag == FS_READDIR_OK {
                if reply_port != 0 {
                    syscall::send(
                        reply_port,
                        VFS_READDIR_OK,
                        fs_reply.data[0],
                        fs_reply.data[1],
                        fs_reply.data[2],
                        fs_reply.data[3],
                    );
                }
            } else if fs_reply.tag == FS_READDIR_END {
                if reply_port != 0 {
                    syscall::send(reply_port, VFS_READDIR_END, 0, 0, 0, 0);
                }
                syscall::port_destroy(my_reply);
                return;
            } else {
                if reply_port != 0 {
                    syscall::send(reply_port, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
                }
                syscall::port_destroy(my_reply);
                return;
            }
        } else {
            break;
        }
    }

    syscall::port_destroy(my_reply);
    if reply_port != 0 {
        syscall::send(reply_port, VFS_READDIR_END, 0, 0, 0, 0);
    }
}

/// Handle VFS_MKDIR: resolve path, forward FS_MKDIR to FS server.
/// data[2] = path_len(16) | mode(16) | reply_port(32)
fn handle_mkdir(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let mode = ((data[2] >> 16) & 0xFFFF) as u32;
    let reply_port = data[2] >> 32;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let my_reply = syscall::port_create();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = (rel_len as u64) | ((mode as u64) << 16) | ((my_reply as u64) << 32);
    syscall::send(fs_port, FS_MKDIR, n0, n1, d2, 0);

    if let Some(fs_reply) = syscall::recv_msg(my_reply) {
        if fs_reply.tag == FS_MKDIR_OK {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_MKDIR_OK, 0, 0, 0, 0);
            }
        } else {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
            }
        }
    } else if reply_port != 0 {
        syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
    }

    syscall::port_destroy(my_reply);
}

/// Handle VFS_UNLINK: resolve path, forward FS_UNLINK to FS server.
/// data[2] = path_len(16) | reply_port(32)
fn handle_unlink(data: &[u64; 6]) {
    let path_len = (data[2] & 0xFFFF) as usize;
    let reply_port = data[2] >> 32;

    let (mut path, plen) = unpack_path(data[0], data[1], path_len);
    let plen = normalize_path(&mut path, plen);

    if plen == 0 {
        if reply_port != 0 {
            syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
        }
        return;
    }

    let (mount_idx, prefix_end) = match find_mount(&path, plen) {
        Some(r) => r,
        None => {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, ERR_NO_MOUNT, 0, 0, 0);
            }
            return;
        }
    };

    let fs_port = unsafe { (*core::ptr::addr_of!(MOUNTS))[mount_idx].fs_port };
    let (rel, rel_len) = relative_path(&path, plen, prefix_end);

    let my_reply = syscall::port_create();
    let (n0, n1) = pack_name_2(rel, rel_len);
    let d2 = (rel_len as u64) | ((my_reply as u64) << 32);
    syscall::send(fs_port, FS_UNLINK, n0, n1, d2, 0);

    if let Some(fs_reply) = syscall::recv_msg(my_reply) {
        if fs_reply.tag == FS_UNLINK_OK {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_UNLINK_OK, 0, 0, 0, 0);
            }
        } else {
            if reply_port != 0 {
                syscall::send(reply_port, VFS_ERROR, fs_reply.data[0], 0, 0, 0);
            }
        }
    } else if reply_port != 0 {
        syscall::send(reply_port, VFS_ERROR, ERR_IO, 0, 0, 0);
    }

    syscall::port_destroy(my_reply);
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
        let msg = match syscall::recv_msg(port) {
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
            _ => {
                let reply_port = msg.data[2] >> 32;
                if reply_port != 0 {
                    syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
                }
            }
        }
    }
}
