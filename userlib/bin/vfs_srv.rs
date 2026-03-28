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
const VFS_STAT: u64 = 0x6020;
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
const VFS_ERROR: u64 = 0x6F00;

// FS protocol tags (forwarded to underlying FS servers).
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
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
/// data[2] = path_len(16) | reply_port(32 in upper), data[3] = fs_port
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
            VFS_STAT => handle_stat(&msg.data),
            VFS_READDIR => handle_readdir(&msg.data),
            VFS_MKDIR => handle_mkdir(&msg.data),
            VFS_UNLINK => handle_unlink(&msg.data),
            _ => {
                let reply_port = msg.data[2] >> 32;
                if reply_port != 0 {
                    syscall::send(reply_port, VFS_ERROR, ERR_INVALID, 0, 0, 0);
                }
            }
        }
    }
}
