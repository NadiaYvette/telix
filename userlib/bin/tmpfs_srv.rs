#![no_std]
#![no_main]

//! tmpfs — in-memory filesystem server.
//!
//! Stores files in dynamically allocated pages. No disk I/O.
//! Serves the standard FS protocol: FS_OPEN, FS_READ, FS_WRITE,
//! FS_CREATE, FS_DELETE, FS_READDIR, FS_STAT, FS_CLOSE.

extern crate userlib;

use userlib::syscall;

// FS protocol constants.
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
const ERR_INVALID: u64 = 3;
const ERR_FULL: u64 = 4;
const ERR_AGAIN: u64 = 11; // EAGAIN

const MAX_FILES: usize = 32;
const MAX_NAME: usize = 16;
const MAX_OPEN: usize = 16;
const MAX_PAGES_PER_FILE: usize = 16; // 16 * 4096 = 64K max per file
const PAGE_SIZE: usize = 4096;
const MAX_INLINE: usize = 24;

#[derive(Clone, Copy)]
struct TmpfsFile {
    name: [u8; MAX_NAME],
    name_len: u8,
    active: bool,
    mode: u16,
    size: u32,
    pages: [usize; MAX_PAGES_PER_FILE], // VA of allocated pages, 0 = unallocated
}

impl TmpfsFile {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME],
            name_len: 0,
            active: false,
            mode: 0,
            size: 0,
            pages: [0; MAX_PAGES_PER_FILE],
        }
    }
}

#[derive(Clone, Copy)]
struct OpenHandle {
    file_idx: usize,
    active: bool,
    writable: bool,
    pid: u32,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self { file_idx: 0, active: false, writable: false, pid: 0 }
    }
}

// --- Advisory file lock table ---

const MAX_LOCKS: usize = 32;
const MAX_LOCK_WAITERS: usize = 8;

const F_RDLCK: u8 = 0;
const F_WRLCK: u8 = 1;
const F_UNLCK: u8 = 2;

#[derive(Clone, Copy)]
struct FileLock {
    active: bool,
    file_idx: u32,      // index into files[] (inode equivalent)
    pid: u32,
    lock_type: u8,      // F_RDLCK or F_WRLCK
    start: u64,
    len: u64,           // 0 = to EOF
}

impl FileLock {
    const fn empty() -> Self {
        Self { active: false, file_idx: 0, pid: 0, lock_type: 0, start: 0, len: 0 }
    }
}

#[derive(Clone, Copy)]
struct LockWaiter {
    active: bool,
    reply_port: u32,
    file_idx: u32,
    pid: u32,
    lock_type: u8,
    start: u64,
    len: u64,
}

impl LockWaiter {
    const fn empty() -> Self {
        Self { active: false, reply_port: 0, file_idx: 0, pid: 0, lock_type: 0, start: 0, len: 0 }
    }
}

/// Check if two byte ranges overlap. len=0 means "to infinity".
fn ranges_overlap(s1: u64, l1: u64, s2: u64, l2: u64) -> bool {
    let e1 = if l1 == 0 { u64::MAX } else { s1.saturating_add(l1) };
    let e2 = if l2 == 0 { u64::MAX } else { s2.saturating_add(l2) };
    s1 < e2 && s2 < e1
}

/// Check if a proposed lock conflicts with existing locks.
/// Returns true if there IS a conflict (cannot acquire).
fn lock_conflicts(
    locks: &[FileLock; MAX_LOCKS],
    file_idx: u32, pid: u32, lock_type: u8, start: u64, len: u64,
) -> bool {
    for lk in locks.iter() {
        if !lk.active || lk.file_idx != file_idx {
            continue;
        }
        // Same PID never conflicts with itself (POSIX: replace).
        if lk.pid == pid {
            continue;
        }
        // Two shared locks don't conflict.
        if lk.lock_type == F_RDLCK && lock_type == F_RDLCK {
            continue;
        }
        // Check range overlap.
        if ranges_overlap(lk.start, lk.len, start, len) {
            return true;
        }
    }
    false
}

/// Find the first conflicting lock (for F_GETLK).
fn find_conflict(
    locks: &[FileLock; MAX_LOCKS],
    file_idx: u32, pid: u32, lock_type: u8, start: u64, len: u64,
) -> Option<usize> {
    for (i, lk) in locks.iter().enumerate() {
        if !lk.active || lk.file_idx != file_idx || lk.pid == pid {
            continue;
        }
        if lk.lock_type == F_RDLCK && lock_type == F_RDLCK {
            continue;
        }
        if ranges_overlap(lk.start, lk.len, start, len) {
            return Some(i);
        }
    }
    None
}

/// Acquire a lock. Removes/replaces existing locks from same PID on overlapping range.
fn acquire_lock(
    locks: &mut [FileLock; MAX_LOCKS],
    file_idx: u32, pid: u32, lock_type: u8, start: u64, len: u64,
) -> bool {
    // Remove existing locks from same PID on same file that overlap.
    for lk in locks.iter_mut() {
        if lk.active && lk.file_idx == file_idx && lk.pid == pid
            && ranges_overlap(lk.start, lk.len, start, len)
        {
            lk.active = false;
        }
    }
    // Allocate new lock slot.
    for lk in locks.iter_mut() {
        if !lk.active {
            *lk = FileLock { active: true, file_idx, pid, lock_type, start, len };
            return true;
        }
    }
    false // lock table full
}

/// Release all locks held by (pid, file_idx) on overlapping range.
/// If start=0 and len=0, release all locks for this (pid, file_idx).
fn release_locks(
    locks: &mut [FileLock; MAX_LOCKS],
    file_idx: u32, pid: u32, start: u64, len: u64,
) {
    for lk in locks.iter_mut() {
        if lk.active && lk.file_idx == file_idx && lk.pid == pid {
            if start == 0 && len == 0 {
                lk.active = false;
            } else if ranges_overlap(lk.start, lk.len, start, len) {
                lk.active = false;
            }
        }
    }
}

/// Try to wake blocked waiters after a lock release.
fn try_wake_waiters(
    locks: &mut [FileLock; MAX_LOCKS],
    waiters: &mut [LockWaiter; MAX_LOCK_WAITERS],
    file_idx: u32,
) {
    for w in waiters.iter_mut() {
        if !w.active || w.file_idx != file_idx {
            continue;
        }
        if !lock_conflicts(locks, w.file_idx, w.pid, w.lock_type, w.start, w.len) {
            // Grant the lock and wake.
            if acquire_lock(locks, w.file_idx, w.pid, w.lock_type, w.start, w.len) {
                syscall::send(w.reply_port, FS_FLOCK_OK, 0, 0, 0, 0);
            } else {
                syscall::send(w.reply_port, FS_LOCK_ERR, ERR_FULL as u64, 0, 0, 0);
            }
            w.active = false;
        }
    }
}

fn unpack_name(d0: u64, d1: u64, len: usize) -> ([u8; MAX_NAME], usize) {
    let mut buf = [0u8; MAX_NAME];
    let actual = len.min(MAX_NAME);
    for i in 0..actual {
        if i < 8 {
            buf[i] = (d0 >> (i * 8)) as u8;
        } else {
            buf[i] = (d1 >> ((i - 8) * 8)) as u8;
        }
    }
    (buf, actual)
}

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

fn find_file(files: &[TmpfsFile; MAX_FILES], name: &[u8], name_len: usize) -> Option<usize> {
    for (i, f) in files.iter().enumerate() {
        if f.active && f.name_len as usize == name_len {
            let mut eq = true;
            for j in 0..name_len {
                if f.name[j] != name[j] { eq = false; break; }
            }
            if eq { return Some(i); }
        }
    }
    None
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [tmpfs_srv] starting\n");

    let port = syscall::port_create() as u32;
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"tmpfs", port);
    syscall::debug_puts(b"  [tmpfs_srv] ready\n");

    let mut files = [TmpfsFile::empty(); MAX_FILES];
    let mut handles = [OpenHandle::empty(); MAX_OPEN];
    let mut locks = [FileLock::empty(); MAX_LOCKS];
    let mut waiters = [LockWaiter::empty(); MAX_LOCK_WAITERS];

    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FS_OPEN => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let caller_pid = msg.data[3] as u32; // PID from d3
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                match find_file(&files, &name, nlen) {
                    Some(fi) => {
                        // Allocate handle.
                        let mut h = u64::MAX;
                        for (i, hnd) in handles.iter_mut().enumerate() {
                            if !hnd.active {
                                hnd.active = true;
                                hnd.writable = false;
                                hnd.file_idx = fi;
                                hnd.pid = caller_pid;
                                h = i as u64;
                                break;
                            }
                        }
                        if h == u64::MAX {
                            syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                        } else {
                            syscall::send(reply_port, FS_OPEN_OK,
                                h, files[fi].size as u64, my_aspace as u64, 0);
                        }
                    }
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    }
                }
            }

            FS_READ => {
                let handle = msg.data[0] as usize;
                let offset = msg.data[1] as u32;
                let length = (msg.data[2] & 0xFFFF_FFFF) as u32;
                let reply_port = (msg.data[2] >> 32) as u32;
                let grant_va = msg.data[3] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let fi = handles[handle].file_idx;
                let file = &files[fi];
                if offset >= file.size {
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let avail = file.size - offset;
                let to_read = length.min(avail) as usize;

                let page_idx = offset as usize / PAGE_SIZE;
                let off_in_page = offset as usize % PAGE_SIZE;
                let bytes_in_page = (PAGE_SIZE - off_in_page).min(to_read);

                if page_idx >= MAX_PAGES_PER_FILE || file.pages[page_idx] == 0 {
                    // No data allocated — return zeros.
                    syscall::send(reply_port, FS_READ_OK, 0, 0, 0, 0);
                    continue;
                }

                let src = file.pages[page_idx] + off_in_page;

                if grant_va != 0 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            src as *const u8,
                            grant_va as *mut u8,
                            bytes_in_page,
                        );
                    }
                    syscall::send_nb(reply_port, FS_READ_OK, bytes_in_page as u64, 0);
                } else {
                    let inline_len = bytes_in_page.min(MAX_INLINE);
                    let data = unsafe {
                        core::slice::from_raw_parts(src as *const u8, inline_len)
                    };
                    let packed = pack_inline_data(data);
                    syscall::send(reply_port, FS_READ_OK,
                        inline_len as u64, packed[0], packed[1], packed[2]);
                }
            }

            FS_READDIR => {
                let start_offset = msg.data[0] as usize;
                let reply_port = (msg.data[2] & 0xFFFF_FFFF) as u32;

                // start_offset is used as an index into the files array.
                let mut found = false;
                for i in start_offset..MAX_FILES {
                    if files[i].active {
                        let f = &files[i];
                        let mut name_lo = 0u64;
                        let mut name_hi = 0u64;
                        let nlen = f.name_len as usize;
                        for j in 0..nlen.min(8) {
                            name_lo |= (f.name[j] as u64) << (j * 8);
                        }
                        for j in 8..nlen.min(16) {
                            name_hi |= (f.name[j] as u64) << ((j - 8) * 8);
                        }
                        syscall::send(reply_port, FS_READDIR_OK,
                            f.size as u64, name_lo, name_hi, (i + 1) as u64);
                        found = true;
                        break;
                    }
                }
                if !found {
                    syscall::send(reply_port, FS_READDIR_END, 0, 0, 0, 0);
                }
            }

            FS_STAT => {
                let handle = msg.data[0] as usize;
                let reply_port = (msg.data[2] & 0xFFFF_FFFF) as u32;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                let fi = handles[handle].file_idx;
                let f = &files[fi];
                syscall::send(reply_port, FS_STAT_OK,
                    f.size as u64, f.mode as u64, 0, fi as u64);
            }

            FS_CLOSE => {
                let handle = msg.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    let fi = handles[handle].file_idx as u32;
                    let pid = handles[handle].pid;
                    handles[handle].active = false;
                    // Check if this PID has any other open handles to the same file.
                    let mut still_open = false;
                    for hnd in handles.iter() {
                        if hnd.active && hnd.file_idx == fi as usize && hnd.pid == pid {
                            still_open = true;
                            break;
                        }
                    }
                    // If no more handles, release all locks for (pid, file).
                    if !still_open {
                        release_locks(&mut locks, fi, pid, 0, 0);
                        try_wake_waiters(&mut locks, &mut waiters, fi);
                    }
                }
            }

            FS_CREATE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let caller_pid = msg.data[3] as u32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                // Check if file already exists.
                if find_file(&files, &name, nlen).is_some() {
                    syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    continue;
                }

                // Find free file slot.
                let mut fi = usize::MAX;
                for (i, f) in files.iter_mut().enumerate() {
                    if !f.active {
                        f.name = name;
                        f.name_len = nlen as u8;
                        f.active = true;
                        f.mode = 0o100644;
                        f.size = 0;
                        f.pages = [0; MAX_PAGES_PER_FILE];
                        fi = i;
                        break;
                    }
                }
                if fi == usize::MAX {
                    syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                    continue;
                }

                // Allocate handle.
                let mut h = u64::MAX;
                for (i, hnd) in handles.iter_mut().enumerate() {
                    if !hnd.active {
                        hnd.active = true;
                        hnd.writable = true;
                        hnd.file_idx = fi;
                        hnd.pid = caller_pid;
                        h = i as u64;
                        break;
                    }
                }
                if h == u64::MAX {
                    files[fi].active = false;
                    syscall::send(reply_port, FS_ERROR, ERR_FULL, 0, 0, 0);
                } else {
                    syscall::send(reply_port, FS_CREATE_OK,
                        h, 0, my_aspace as u64, 0);
                }
            }

            FS_WRITE => {
                let handle = msg.data[0] as usize;
                let length = (msg.data[1] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[1] >> 32) as u32;
                let grant_va = msg.data[2] as usize;

                if handle >= MAX_OPEN || !handles[handle].active
                    || !handles[handle].writable
                {
                    if reply_port != 0 {
                        syscall::send(reply_port, FS_ERROR, ERR_INVALID, 0, 0, 0);
                    }
                    continue;
                }

                let fi = handles[handle].file_idx;
                let mut written = 0usize;
                let mut offset = files[fi].size as usize;

                while written < length {
                    let page_idx = offset / PAGE_SIZE;
                    let off_in_page = offset % PAGE_SIZE;
                    let space = (PAGE_SIZE - off_in_page).min(length - written);

                    if page_idx >= MAX_PAGES_PER_FILE {
                        break; // File too large.
                    }

                    // Allocate page on demand.
                    if files[fi].pages[page_idx] == 0 {
                        match syscall::mmap_anon(0, 1, 1) {
                            Some(va) => {
                                // Zero the page.
                                unsafe {
                                    core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE);
                                }
                                files[fi].pages[page_idx] = va;
                            }
                            None => break,
                        }
                    }

                    let dst = files[fi].pages[page_idx] + off_in_page;
                    if grant_va != 0 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                (grant_va + written) as *const u8,
                                dst as *mut u8,
                                space,
                            );
                        }
                    }

                    written += space;
                    offset += space;
                }

                files[fi].size = offset as u32;

                if reply_port != 0 {
                    syscall::send(reply_port, FS_WRITE_OK, written as u64, 0, 0, 0);
                }
            }

            FS_DELETE => {
                let name_len = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);

                match find_file(&files, &name, nlen) {
                    Some(fi) => {
                        // Free pages.
                        for p in 0..MAX_PAGES_PER_FILE {
                            if files[fi].pages[p] != 0 {
                                syscall::munmap(files[fi].pages[p]);
                                files[fi].pages[p] = 0;
                            }
                        }
                        files[fi].active = false;
                        // Close any open handles to this file.
                        for hnd in handles.iter_mut() {
                            if hnd.active && hnd.file_idx == fi {
                                hnd.active = false;
                            }
                        }
                        syscall::send(reply_port, FS_DELETE_OK, 0, 0, 0, 0);
                    }
                    None => {
                        syscall::send(reply_port, FS_ERROR, ERR_NOT_FOUND, 0, 0, 0);
                    }
                }
            }

            FS_FLOCK => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as usize;
                let operation = (msg.data[0] >> 32) as i32;
                let pid = msg.data[1] as u32;
                let reply_port = (msg.data[2] >> 32) as u32;

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0);
                    continue;
                }
                let fi = handles[handle].file_idx as u32;
                let is_unlock = operation & 8 != 0; // LOCK_UN
                let is_nb = operation & 4 != 0;      // LOCK_NB
                let lock_type = if operation & 2 != 0 { F_WRLCK }
                                else if operation & 1 != 0 { F_RDLCK }
                                else if is_unlock { F_UNLCK }
                                else { F_UNLCK };

                if is_unlock {
                    release_locks(&mut locks, fi, pid, 0, 0);
                    try_wake_waiters(&mut locks, &mut waiters, fi);
                    syscall::send(reply_port, FS_FLOCK_OK, 0, 0, 0, 0);
                } else if !lock_conflicts(&locks, fi, pid, lock_type, 0, 0) {
                    if acquire_lock(&mut locks, fi, pid, lock_type, 0, 0) {
                        syscall::send(reply_port, FS_FLOCK_OK, 0, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_FULL as u64, 0, 0, 0);
                    }
                } else if is_nb {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                } else {
                    // Block — store waiter.
                    let mut queued = false;
                    for w in waiters.iter_mut() {
                        if !w.active {
                            *w = LockWaiter {
                                active: true, reply_port, file_idx: fi,
                                pid, lock_type, start: 0, len: 0,
                            };
                            queued = true;
                            break;
                        }
                    }
                    if !queued {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_FULL as u64, 0, 0, 0);
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

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0);
                    continue;
                }
                let fi = handles[handle].file_idx as u32;

                if lock_type == F_UNLCK {
                    release_locks(&mut locks, fi, pid, start, len);
                    try_wake_waiters(&mut locks, &mut waiters, fi);
                    let ok_tag = if blocking { FS_SETLKW_OK } else { FS_SETLK_OK };
                    syscall::send(reply_port, ok_tag, 0, 0, 0, 0);
                } else if !lock_conflicts(&locks, fi, pid, lock_type, start, len) {
                    if acquire_lock(&mut locks, fi, pid, lock_type, start, len) {
                        let ok_tag = if blocking { FS_SETLKW_OK } else { FS_SETLK_OK };
                        syscall::send(reply_port, ok_tag, 0, 0, 0, 0);
                    } else {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_FULL as u64, 0, 0, 0);
                    }
                } else if !blocking {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_AGAIN as u64, 0, 0, 0);
                } else {
                    // Block — store waiter.
                    let mut queued = false;
                    for w in waiters.iter_mut() {
                        if !w.active {
                            *w = LockWaiter {
                                active: true, reply_port, file_idx: fi,
                                pid, lock_type, start, len,
                            };
                            queued = true;
                            break;
                        }
                    }
                    if !queued {
                        syscall::send(reply_port, FS_LOCK_ERR, ERR_FULL as u64, 0, 0, 0);
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

                if handle >= MAX_OPEN || !handles[handle].active {
                    syscall::send(reply_port, FS_LOCK_ERR, ERR_INVALID as u64, 0, 0, 0);
                    continue;
                }
                let fi = handles[handle].file_idx as u32;

                match find_conflict(&locks, fi, pid, lock_type, start, len) {
                    Some(idx) => {
                        let lk = &locks[idx];
                        let d0 = (lk.lock_type as u64) | ((lk.pid as u64) << 32);
                        syscall::send(reply_port, FS_GETLK_OK, d0, lk.start, lk.len, 0);
                    }
                    None => {
                        // No conflict — return F_UNLCK.
                        let d0 = F_UNLCK as u64;
                        syscall::send(reply_port, FS_GETLK_OK, d0, 0, 0, 0);
                    }
                }
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
