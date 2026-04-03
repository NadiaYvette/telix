#![no_std]
#![no_main]

//! Linux personality server.
//!
//! Receives forwarded Linux syscalls from the kernel's personality routing
//! layer and translates them into Telix-native operations.
//!
//! Message format (from kernel/src/syscall/personality.rs):
//!   tag     = Linux syscall number (x86_64 numbering)
//!   data[0] = arg0
//!   data[1] = arg1
//!   data[2] = arg2
//!   data[3] = arg3
//!   data[4] = caller's task port_id

extern crate userlib;

use userlib::syscall;

// --- Linux x86_64 syscall numbers ---
const __NR_READ: u64 = 0;
const __NR_WRITE: u64 = 1;
const __NR_OPEN: u64 = 2;
const __NR_CLOSE: u64 = 3;
const __NR_STAT: u64 = 4;
const __NR_FSTAT: u64 = 5;
const __NR_LSEEK: u64 = 8;
const __NR_MMAP: u64 = 9;
const __NR_MPROTECT: u64 = 10;
const __NR_MUNMAP: u64 = 11;
const __NR_BRK: u64 = 12;
const __NR_IOCTL: u64 = 16;
const __NR_ACCESS: u64 = 21;
const __NR_WRITEV: u64 = 20;
const __NR_GETPID: u64 = 39;
const __NR_CLONE: u64 = 56;
const __NR_FORK: u64 = 57;
const __NR_VFORK: u64 = 58;
const __NR_EXIT: u64 = 60;
const __NR_WAIT4: u64 = 61;
const __NR_UNAME: u64 = 63;
const __NR_GETCWD: u64 = 79;
const __NR_READLINK: u64 = 89;
const __NR_GETUID: u64 = 102;
const __NR_GETGID: u64 = 104;
const __NR_GETEUID: u64 = 107;
const __NR_GETEGID: u64 = 108;
const __NR_ARCH_PRCTL: u64 = 158;
const __NR_GETTID: u64 = 186;
const __NR_SET_TID_ADDRESS: u64 = 218;
const __NR_CLOCK_GETTIME: u64 = 228;
const __NR_EXIT_GROUP: u64 = 231;
const __NR_OPENAT: u64 = 257;
const __NR_NEWFSTATAT: u64 = 262;
const __NR_SET_ROBUST_LIST: u64 = 273;
const __NR_PRLIMIT64: u64 = 302;
const __NR_GETRANDOM: u64 = 318;
const __NR_RSEQ: u64 = 334;

// arch_prctl subcodes
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;

// Linux errno values
const EPERM: u64 = 1;
const ENOENT: u64 = 2;
const EBADF: u64 = 9;
const EFAULT: u64 = 14;
const ENOTDIR: u64 = 20;
const EINVAL: u64 = 22;
const EAGAIN: u64 = 11;
const ECHILD: u64 = 10;
const ENOSYS: u64 = 38;
const ERANGE: u64 = 34;

/// Return negated errno as u64 (Linux convention).
fn linux_err(e: u64) -> u64 {
    (-(e as i64)) as u64
}

// VFS IPC protocol tags
const VFS_OPEN: u64 = 0x6010;
const VFS_OPEN_OK: u64 = 0x6110;
const VFS_STAT: u64 = 0x6020;
const VFS_STAT_OK: u64 = 0x6120;
const VFS_ERROR: u64 = 0x6F00;

// FS server protocol tags
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_CLOSE: u64 = 0x2400;

// Linux AT_FDCWD
const AT_FDCWD: u64 = 0xFFFF_FFFF_FFFF_FF9C; // -100 as u64

// Per-task state for brk emulation (single-client for now).
static mut BRK_BASE: usize = 0;
static mut BRK_CURRENT: usize = 0;

// Simple fd table (single-client).
const MAX_FDS: usize = 64;
struct FdEntry {
    in_use: bool,
    fs_port: u64,
    handle: u64,
    file_size: u64,
    offset: u64,
}

impl FdEntry {
    const fn empty() -> Self {
        Self { in_use: false, fs_port: 0, handle: 0, file_size: 0, offset: 0 }
    }
}

static mut FD_TABLE: [FdEntry; MAX_FDS] = [const { FdEntry::empty() }; MAX_FDS];
static mut VFS_PORT: u64 = 0;
static mut REPLY_PORT: u64 = 0;

fn alloc_fd() -> Option<usize> {
    unsafe {
        // Skip fds 0-2 (stdin/stdout/stderr are special).
        for i in 3..MAX_FDS {
            if !FD_TABLE[i].in_use {
                FD_TABLE[i].in_use = true;
                return Some(i);
            }
        }
        None
    }
}

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_puts(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut val = n;
    while val > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    syscall::debug_puts(&buf[i..20]);
}

/// Handle Linux write(fd, buf, count) — now with real cross-address-space copy.
fn handle_write(caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0];
    let buf_va = args[1] as usize;
    let count = args[2] as usize;

    if buf_va == 0 || count == 0 {
        return 0;
    }

    if fd == 1 || fd == 2 {
        // stdout/stderr → debug console, copying from caller's address space.
        let mut total = 0usize;
        while total < count {
            let mut tmp = [0u8; 512];
            let chunk = (count - total).min(512);
            let copied = syscall::personality_copy_in(caller_port, buf_va + total, &mut tmp[..chunk]);
            if copied == 0 {
                return if total > 0 { total as u64 } else { linux_err(EFAULT) };
            }
            syscall::debug_puts(&tmp[..copied]);
            total += copied;
        }
        return total as u64;
    }

    // File FDs: write through VFS (not yet implemented).
    linux_err(EBADF)
}

/// Handle Linux writev(fd, iov, iovcnt).
fn handle_writev(caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0];
    let iov_va = args[1] as usize;
    let iovcnt = args[2] as usize;

    if iovcnt == 0 {
        return 0;
    }
    if iov_va == 0 || iovcnt > 1024 {
        return linux_err(EINVAL);
    }

    // Each iovec is { void *iov_base; size_t iov_len; } = 16 bytes on x86_64.
    let mut total = 0u64;
    for i in 0..iovcnt {
        let mut iov_buf = [0u8; 16];
        let copied = syscall::personality_copy_in(caller_port, iov_va + i * 16, &mut iov_buf);
        if copied < 16 {
            return if total > 0 { total } else { linux_err(EFAULT) };
        }
        let base = u64::from_le_bytes([iov_buf[0], iov_buf[1], iov_buf[2], iov_buf[3],
                                        iov_buf[4], iov_buf[5], iov_buf[6], iov_buf[7]]);
        let len = u64::from_le_bytes([iov_buf[8], iov_buf[9], iov_buf[10], iov_buf[11],
                                       iov_buf[12], iov_buf[13], iov_buf[14], iov_buf[15]]);

        if len == 0 {
            continue;
        }
        if base == 0 {
            return if total > 0 { total } else { linux_err(EFAULT) };
        }

        // Delegate to write logic for this chunk.
        let write_args: [u64; 6] = [fd, base, len, 0, 0, 0];
        let r = handle_write(caller_port, &write_args);
        if (r as i64) < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
    }
    total
}

/// Handle Linux read(fd, buf, count).
fn handle_read(caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let buf_va = args[1] as usize;
    let count = args[2] as usize;

    if buf_va == 0 || count == 0 {
        return 0;
    }
    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }

    let (fs_port, handle, offset, file_size) = unsafe {
        if !FD_TABLE[fd].in_use {
            return linux_err(EBADF);
        }
        (FD_TABLE[fd].fs_port, FD_TABLE[fd].handle, FD_TABLE[fd].offset, FD_TABLE[fd].file_size)
    };

    if offset >= file_size {
        return 0; // EOF
    }

    let reply_port = unsafe { REPLY_PORT };
    let remaining = (file_size - offset) as usize;
    let want = count.min(remaining);
    let mut total = 0usize;

    // FS_READ returns max 16 bytes per message.
    while total < want {
        let chunk = (want - total).min(16);
        let d2 = (chunk as u64) | ((reply_port) << 32);
        syscall::send(fs_port, FS_READ, handle, offset + total as u64, d2, 0);
        let resp = match syscall::recv_msg(reply_port) {
            Some(m) => m,
            None => break,
        };
        if resp.tag != FS_READ_OK {
            break;
        }
        let got = (resp.data[0] & 0xFFFF) as usize;
        if got == 0 {
            break;
        }
        // Data is in resp.data[1] (bytes 0-7) and resp.data[2] (bytes 8-15).
        let mut tmp = [0u8; 16];
        let b1 = resp.data[1].to_le_bytes();
        let b2 = resp.data[2].to_le_bytes();
        tmp[..8].copy_from_slice(&b1);
        tmp[8..16].copy_from_slice(&b2);

        let to_write = got.min(chunk);
        let written = syscall::personality_copy_out(caller_port, buf_va + total, &tmp[..to_write]);
        if written == 0 {
            return if total > 0 { total as u64 } else { linux_err(EFAULT) };
        }
        total += to_write;
        unsafe { FD_TABLE[fd].offset += to_write as u64; }
        if got < chunk {
            break; // Short read from FS.
        }
    }
    total as u64
}

/// Open a file via VFS. Returns fd or negated errno.
fn do_open(caller_port: u64, path_va: usize, flags: u64) -> u64 {
    let vfs_port = unsafe { VFS_PORT };
    let reply_port = unsafe { REPLY_PORT };
    if vfs_port == 0 {
        return linux_err(ENOSYS);
    }

    // Copy path from caller (max 16 bytes for VFS protocol).
    let mut path = [0u8; 16];
    let copied = syscall::personality_copy_in(caller_port, path_va, &mut path);
    if copied == 0 {
        return linux_err(EFAULT);
    }

    // Find path length (null-terminated).
    let pathlen = path.iter().position(|&b| b == 0).unwrap_or(copied);
    if pathlen == 0 {
        return linux_err(ENOENT);
    }

    // Pack path into two u64 words (little-endian).
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    for i in 0..pathlen.min(8) {
        w0 |= (path[i] as u64) << (i * 8);
    }
    for i in 8..pathlen.min(16) {
        w1 |= (path[i] as u64) << ((i - 8) * 8);
    }

    let d2 = (pathlen as u64) | ((flags & 0xFFFF) << 16) | ((reply_port) << 32);
    syscall::send(vfs_port, VFS_OPEN, w0, w1, d2, 0);

    let resp = match syscall::recv_msg(reply_port) {
        Some(m) => m,
        None => return linux_err(ENOENT),
    };

    if resp.tag == VFS_ERROR {
        return linux_err(ENOENT);
    }
    if resp.tag != VFS_OPEN_OK {
        return linux_err(ENOENT);
    }

    let fd = match alloc_fd() {
        Some(f) => f,
        None => return linux_err(EBADF),
    };

    unsafe {
        FD_TABLE[fd].fs_port = resp.data[0];
        FD_TABLE[fd].handle = resp.data[1];
        FD_TABLE[fd].file_size = resp.data[2];
        FD_TABLE[fd].offset = 0;
    }

    fd as u64
}

/// Handle Linux open(path, flags, mode).
fn handle_open(caller_port: u64, args: &[u64; 6]) -> u64 {
    do_open(caller_port, args[0] as usize, args[1])
}

/// Handle Linux openat(dirfd, path, flags, mode).
fn handle_openat(caller_port: u64, args: &[u64; 6]) -> u64 {
    let dirfd = args[0];
    let path_va = args[1] as usize;
    let flags = args[2];
    // We only support AT_FDCWD for now.
    if dirfd != AT_FDCWD && (dirfd as i64) >= 0 {
        return linux_err(EBADF);
    }
    do_open(caller_port, path_va, flags)
}

/// Handle Linux close(fd).
fn handle_close(args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    if fd < 3 {
        return 0; // Closing stdin/stdout/stderr is a no-op.
    }
    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }
    unsafe {
        if !FD_TABLE[fd].in_use {
            return linux_err(EBADF);
        }
        // Send FS_CLOSE to the filesystem server.
        let rp = REPLY_PORT;
        let d3 = rp << 32;
        syscall::send(FD_TABLE[fd].fs_port, FS_CLOSE, FD_TABLE[fd].handle, 0, 0, d3);
        // Wait for reply (best-effort).
        let _ = syscall::recv_msg(rp);
        FD_TABLE[fd] = FdEntry::empty();
    }
    0
}

/// Handle Linux lseek(fd, offset, whence).
fn handle_lseek(args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let offset = args[1] as i64;
    let whence = args[2];

    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }
    unsafe {
        if !FD_TABLE[fd].in_use {
            return linux_err(EBADF);
        }
        let new_off = match whence {
            0 => offset, // SEEK_SET
            1 => FD_TABLE[fd].offset as i64 + offset, // SEEK_CUR
            2 => FD_TABLE[fd].file_size as i64 + offset, // SEEK_END
            _ => return linux_err(EINVAL),
        };
        if new_off < 0 {
            return linux_err(EINVAL);
        }
        FD_TABLE[fd].offset = new_off as u64;
        new_off as u64
    }
}

/// Handle stat/fstat/newfstatat — fill a Linux stat struct in caller's memory.
fn handle_stat(caller_port: u64, args: &[u64; 6]) -> u64 {
    let path_va = args[0] as usize;
    let statbuf_va = args[1] as usize;

    let vfs_port = unsafe { VFS_PORT };
    let reply_port = unsafe { REPLY_PORT };
    if vfs_port == 0 {
        return linux_err(ENOSYS);
    }

    // Copy path from caller.
    let mut path = [0u8; 16];
    let copied = syscall::personality_copy_in(caller_port, path_va, &mut path);
    if copied == 0 {
        return linux_err(EFAULT);
    }
    let pathlen = path.iter().position(|&b| b == 0).unwrap_or(copied);

    let mut w0 = 0u64;
    let mut w1 = 0u64;
    for i in 0..pathlen.min(8) {
        w0 |= (path[i] as u64) << (i * 8);
    }
    for i in 8..pathlen.min(16) {
        w1 |= (path[i] as u64) << ((i - 8) * 8);
    }

    let d2 = (pathlen as u64) | ((reply_port) << 32);
    syscall::send(vfs_port, VFS_STAT, w0, w1, d2, 0);

    let resp = match syscall::recv_msg(reply_port) {
        Some(m) => m,
        None => return linux_err(ENOENT),
    };

    if resp.tag == VFS_ERROR || resp.tag != VFS_STAT_OK {
        return linux_err(ENOENT);
    }

    // Build a minimal Linux struct stat (x86_64).
    // sizeof(struct stat) = 144 bytes.
    let mut stat_buf = [0u8; 144];
    let file_size = resp.data[0];
    let mode = resp.data[1] as u32;
    let ino = resp.data[3];

    // st_ino at offset 8 (u64)
    stat_buf[8..16].copy_from_slice(&ino.to_le_bytes());
    // st_mode at offset 24 (u32)
    stat_buf[24..28].copy_from_slice(&mode.to_le_bytes());
    // st_size at offset 48 (i64)
    stat_buf[48..56].copy_from_slice(&file_size.to_le_bytes());
    // st_blksize at offset 56 (i64) — use 4096
    stat_buf[56..64].copy_from_slice(&4096u64.to_le_bytes());

    let written = syscall::personality_copy_out(caller_port, statbuf_va, &stat_buf);
    if written < 144 {
        return linux_err(EFAULT);
    }
    0
}

/// Handle Linux fstat(fd, statbuf).
fn handle_fstat(caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let statbuf_va = args[1] as usize;

    if fd < 3 {
        // stdin/stdout/stderr: return a char device stat.
        let mut stat_buf = [0u8; 144];
        // st_mode = S_IFCHR | 0666
        let mode: u32 = 0o020666;
        stat_buf[24..28].copy_from_slice(&mode.to_le_bytes());
        stat_buf[56..64].copy_from_slice(&4096u64.to_le_bytes());
        let written = syscall::personality_copy_out(caller_port, statbuf_va, &stat_buf);
        if written < 144 {
            return linux_err(EFAULT);
        }
        return 0;
    }

    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }
    unsafe {
        if !FD_TABLE[fd].in_use {
            return linux_err(EBADF);
        }
        let file_size = FD_TABLE[fd].file_size;
        let mut stat_buf = [0u8; 144];
        let mode: u32 = 0o100644; // S_IFREG | 0644
        stat_buf[24..28].copy_from_slice(&mode.to_le_bytes());
        stat_buf[48..56].copy_from_slice(&file_size.to_le_bytes());
        stat_buf[56..64].copy_from_slice(&4096u64.to_le_bytes());
        let written = syscall::personality_copy_out(caller_port, statbuf_va, &stat_buf);
        if written < 144 {
            return linux_err(EFAULT);
        }
    }
    0
}

/// Handle Linux uname(buf).
fn handle_uname(caller_port: u64, args: &[u64; 6]) -> u64 {
    let buf_va = args[0] as usize;
    // Linux struct utsname: 6 fields of 65 bytes each = 390 bytes.
    let mut uts = [0u8; 390];

    fn put_str(buf: &mut [u8], offset: usize, s: &[u8]) {
        let n = s.len().min(64);
        buf[offset..offset + n].copy_from_slice(&s[..n]);
    }

    put_str(&mut uts, 0, b"Linux");          // sysname
    put_str(&mut uts, 65, b"telix");         // nodename
    put_str(&mut uts, 130, b"6.1.0-telix");  // release
    put_str(&mut uts, 195, b"#1 SMP");       // version
    put_str(&mut uts, 260, b"x86_64");       // machine
    put_str(&mut uts, 325, b"(none)");       // domainname

    let written = syscall::personality_copy_out(caller_port, buf_va, &uts);
    if written < 390 {
        return linux_err(EFAULT);
    }
    0
}

/// Handle Linux getrandom(buf, buflen, flags).
fn handle_getrandom(caller_port: u64, args: &[u64; 6]) -> u64 {
    let buf_va = args[0] as usize;
    let buflen = args[1] as usize;

    if buf_va == 0 || buflen == 0 {
        return 0;
    }

    let mut total = 0usize;
    while total < buflen {
        let mut tmp = [0u8; 256];
        let chunk = (buflen - total).min(256);
        // Use Telix getrandom to fill.
        syscall::getrandom(tmp.as_mut_ptr() as usize, chunk);
        let written = syscall::personality_copy_out(caller_port, buf_va + total, &tmp[..chunk]);
        if written == 0 {
            return if total > 0 { total as u64 } else { linux_err(EFAULT) };
        }
        total += written;
    }
    total as u64
}

/// Handle Linux clock_gettime(clockid, tp).
fn handle_clock_gettime(caller_port: u64, args: &[u64; 6]) -> u64 {
    let _clockid = args[0];
    let tp_va = args[1] as usize;

    if tp_va == 0 {
        return linux_err(EFAULT);
    }

    // Get time from Telix (cycles + freq → nanoseconds).
    let cycles = syscall::get_cycles();
    let freq = syscall::get_timer_freq();
    let secs = if freq > 0 { cycles / freq } else { 0 };
    let nsecs = if freq > 0 { ((cycles % freq) * 1_000_000_000) / freq } else { 0 };

    // struct timespec { time_t tv_sec; long tv_nsec; } = 16 bytes on x86_64.
    let mut tp = [0u8; 16];
    tp[0..8].copy_from_slice(&secs.to_le_bytes());
    tp[8..16].copy_from_slice(&nsecs.to_le_bytes());

    let written = syscall::personality_copy_out(caller_port, tp_va, &tp);
    if written < 16 {
        return linux_err(EFAULT);
    }
    0
}

/// Handle Linux getcwd(buf, size).
fn handle_getcwd(caller_port: u64, args: &[u64; 6]) -> u64 {
    let buf_va = args[0] as usize;
    let size = args[1] as usize;

    let cwd = b"/\0";
    if size < cwd.len() {
        return linux_err(ERANGE);
    }

    let written = syscall::personality_copy_out(caller_port, buf_va, cwd);
    if written < cwd.len() {
        return linux_err(EFAULT);
    }
    buf_va as u64
}

/// Handle Linux access(path, mode).
fn handle_access(caller_port: u64, args: &[u64; 6]) -> u64 {
    let path_va = args[0] as usize;
    let _mode = args[1];

    // Check if path exists via VFS stat.
    let stat_args: [u64; 6] = [path_va as u64, 0, 0, 0, 0, 0];
    // We can't call handle_stat without a statbuf, so just try VFS_STAT.
    let vfs_port = unsafe { VFS_PORT };
    let reply_port = unsafe { REPLY_PORT };
    if vfs_port == 0 {
        return linux_err(ENOSYS);
    }

    let mut path = [0u8; 16];
    let copied = syscall::personality_copy_in(caller_port, path_va, &mut path);
    if copied == 0 {
        return linux_err(EFAULT);
    }
    let pathlen = path.iter().position(|&b| b == 0).unwrap_or(copied);

    let mut w0 = 0u64;
    let mut w1 = 0u64;
    for i in 0..pathlen.min(8) {
        w0 |= (path[i] as u64) << (i * 8);
    }
    for i in 8..pathlen.min(16) {
        w1 |= (path[i] as u64) << ((i - 8) * 8);
    }

    let d2 = (pathlen as u64) | ((reply_port) << 32);
    syscall::send(vfs_port, VFS_STAT, w0, w1, d2, 0);

    let resp = match syscall::recv_msg(reply_port) {
        Some(m) => m,
        None => return linux_err(ENOENT),
    };

    if resp.tag == VFS_ERROR || resp.tag != VFS_STAT_OK {
        return linux_err(ENOENT);
    }
    0
}

/// Handle Linux readlink(path, buf, bufsiz).
fn handle_readlink(_caller_port: u64, _args: &[u64; 6]) -> u64 {
    linux_err(EINVAL)
}

/// Handle Linux fork() / vfork() / clone() (basic).
fn handle_fork(caller_port: u64) -> u64 {
    let child_port = syscall::personality_fork(caller_port);
    if child_port == u64::MAX {
        return linux_err(EAGAIN);
    }
    child_port
}

/// Handle Linux wait4(pid, wstatus, options, rusage).
fn handle_wait4(caller_port: u64, args: &[u64; 6]) -> u64 {
    let pid = args[0] as i64;
    let wstatus_va = args[1] as usize;
    let options = args[2] as u32;
    let wnohang = options & 1; // WNOHANG = 1

    // Poll loop for blocking wait.
    for _ in 0..5000 {
        let child_port = syscall::personality_wait4(caller_port, pid, 1); // always WNOHANG
        if child_port == u64::MAX {
            // No children at all → ECHILD
            return linux_err(ECHILD);
        }
        if child_port != 0 {
            // Found an exited child. Write status to caller if requested.
            if wstatus_va != 0 {
                // Normal exit status: (exit_code << 8) & 0xFF00
                // For now, write 0 (exited with code 0).
                let status: u32 = 0;
                let status_bytes = status.to_le_bytes();
                syscall::personality_copy_out(caller_port, wstatus_va, &status_bytes);
            }
            return child_port;
        }
        if wnohang != 0 {
            return 0; // No child ready, WNOHANG.
        }
        syscall::yield_now();
    }
    // Timeout — return 0 (no child ready).
    0
}

/// Handle Linux brk(addr).
fn handle_brk(args: &[u64; 6]) -> u64 {
    let addr = args[0] as usize;

    unsafe {
        if BRK_BASE == 0 {
            BRK_BASE = 0x4000_0000;
            BRK_CURRENT = BRK_BASE;
        }

        if addr == 0 {
            return BRK_CURRENT as u64;
        }

        if addr >= BRK_BASE && addr <= BRK_BASE + 256 * 1024 * 1024 {
            let page_size = syscall::page_size() as usize;
            if addr > BRK_CURRENT {
                let old_pages = (BRK_CURRENT + page_size - 1) / page_size;
                let new_pages = (addr + page_size - 1) / page_size;
                if new_pages > old_pages {
                    let alloc_start = old_pages * page_size;
                    let count = new_pages - old_pages;
                    if syscall::mmap_anon(alloc_start, count, 3).is_none() {
                        return BRK_CURRENT as u64;
                    }
                }
            }
            BRK_CURRENT = addr;
            return BRK_CURRENT as u64;
        }

        BRK_CURRENT as u64
    }
}

/// Handle Linux arch_prctl(code, addr).
fn handle_arch_prctl(args: &[u64; 6]) -> u64 {
    let code = args[0];
    let _addr = args[1];

    match code {
        ARCH_SET_FS => 0,
        ARCH_GET_FS => 0,
        _ => linux_err(ENOSYS),
    }
}

/// Handle Linux set_tid_address(tidptr).
fn handle_set_tid_address(caller_port: u64) -> u64 {
    caller_port
}

/// Handle Linux exit(code) or exit_group(code).
fn handle_exit(caller_port: u64, args: &[u64; 6]) -> u64 {
    let _code = args[0];
    syscall::kill(caller_port);
    0
}

/// Handle Linux getpid/gettid/getuid/geteuid/getgid/getegid.
fn handle_getid(nr: u64) -> u64 {
    match nr {
        __NR_GETPID | __NR_GETTID => syscall::getpid(),
        __NR_GETUID => syscall::getuid() as u64,
        __NR_GETEUID => syscall::geteuid() as u64,
        __NR_GETGID => syscall::getgid() as u64,
        __NR_GETEGID => syscall::getegid() as u64,
        _ => 0,
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    let port = syscall::port_create();
    syscall::personality_register(2, port); // 2 = Linux
    syscall::ns_register(b"linux", port);

    // Set up VFS client port for file operations.
    unsafe {
        REPLY_PORT = syscall::port_create();
        VFS_PORT = syscall::ns_lookup(b"vfs").unwrap_or(0);
    }

    syscall::debug_puts(b"[linux_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => continue,
        };

        let linux_nr = msg.tag;
        let caller_port = msg.data[4];

        let result = match linux_nr {
            __NR_READ => handle_read(caller_port, &msg.data),
            __NR_WRITE => handle_write(caller_port, &msg.data),
            __NR_OPEN => handle_open(caller_port, &msg.data),
            __NR_CLOSE => handle_close(&msg.data),
            __NR_STAT | __NR_NEWFSTATAT => handle_stat(caller_port, &msg.data),
            __NR_FSTAT => handle_fstat(caller_port, &msg.data),
            __NR_LSEEK => handle_lseek(&msg.data),
            __NR_WRITEV => handle_writev(caller_port, &msg.data),
            __NR_ACCESS => handle_access(caller_port, &msg.data),
            __NR_GETCWD => handle_getcwd(caller_port, &msg.data),
            __NR_READLINK => handle_readlink(caller_port, &msg.data),
            __NR_OPENAT => handle_openat(caller_port, &msg.data),
            __NR_FORK | __NR_VFORK => handle_fork(caller_port),
            __NR_CLONE => handle_fork(caller_port), // basic clone = fork
            __NR_WAIT4 => handle_wait4(caller_port, &msg.data),
            __NR_BRK => handle_brk(&msg.data),
            __NR_ARCH_PRCTL => handle_arch_prctl(&msg.data),
            __NR_SET_TID_ADDRESS => handle_set_tid_address(caller_port),
            __NR_EXIT | __NR_EXIT_GROUP => {
                handle_exit(caller_port, &msg.data);
                continue; // Don't reply — task is dead.
            }
            __NR_GETPID | __NR_GETTID | __NR_GETUID | __NR_GETEUID
            | __NR_GETGID | __NR_GETEGID => handle_getid(linux_nr),
            __NR_CLOCK_GETTIME => handle_clock_gettime(caller_port, &msg.data),
            __NR_UNAME => handle_uname(caller_port, &msg.data),
            __NR_GETRANDOM => handle_getrandom(caller_port, &msg.data),

            // Stubs that return success (0) to avoid crashing callers.
            __NR_SET_ROBUST_LIST | __NR_RSEQ => 0,
            __NR_PRLIMIT64 => 0,
            __NR_IOCTL => linux_err(ENOSYS),

            // Anonymous mmap: forward to Telix mmap_anon.
            __NR_MMAP => {
                let addr = msg.data[0] as usize;
                let len = msg.data[1] as usize;
                let prot = msg.data[2] as u8;
                let _flags = msg.data[3];
                let page_size = syscall::page_size() as usize;
                let pages = (len + page_size - 1) / page_size;
                match syscall::mmap_anon(addr, pages, prot) {
                    Some(va) => va as u64,
                    None => u64::MAX, // MAP_FAILED
                }
            }
            __NR_MPROTECT => {
                let addr = msg.data[0] as usize;
                let len = msg.data[1] as usize;
                let prot = msg.data[2] as u8;
                if syscall::mprotect(addr, len, prot) { 0 } else { linux_err(ENOSYS) }
            }
            __NR_MUNMAP => {
                let addr = msg.data[0] as usize;
                if syscall::munmap(addr) { 0 } else { linux_err(ENOSYS) }
            }

            _ => {
                syscall::debug_puts(b"[linux_srv] unhandled nr=");
                print_num(linux_nr);
                syscall::debug_puts(b"\n");
                linux_err(ENOSYS)
            }
        };

        // Reply to the blocked caller.
        syscall::personality_reply(caller_port, result);
    }
}
