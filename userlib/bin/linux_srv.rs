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
const __NR_DUP: u64 = 32;
const __NR_DUP2: u64 = 33;
const __NR_CLONE: u64 = 56;
const __NR_FORK: u64 = 57;
const __NR_VFORK: u64 = 58;
const __NR_EXECVE: u64 = 59;
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
const __NR_DUP3: u64 = 292;
const __NR_PIPE2: u64 = 293;
const __NR_PRLIMIT64: u64 = 302;
const __NR_GETDENTS64: u64 = 217;
const __NR_GETRANDOM: u64 = 318;
const __NR_RSEQ: u64 = 334;
const __NR_CHDIR: u64 = 80;
const __NR_FCHDIR: u64 = 81;
const __NR_MKDIR: u64 = 83;
const __NR_RMDIR: u64 = 84;
const __NR_UNLINK: u64 = 87;
const __NR_UNLINKAT: u64 = 263;
const __NR_MKDIRAT: u64 = 258;

// Phase 127: additional syscall numbers
const __NR_RT_SIGACTION: u64 = 13;
const __NR_RT_SIGPROCMASK: u64 = 14;
const __NR_RT_SIGRETURN: u64 = 15;
const __NR_POLL: u64 = 7;
const __NR_SCHED_YIELD: u64 = 24;
const __NR_MADVISE: u64 = 28;
const __NR_NANOSLEEP: u64 = 35;
const __NR_GETPPID: u64 = 110;
const __NR_SETSID: u64 = 112;
const __NR_GETPGRP: u64 = 111;
const __NR_SETPGID: u64 = 109;
const __NR_GETPGID: u64 = 121;
const __NR_GETSID: u64 = 124;
const __NR_FCNTL: u64 = 72;
const __NR_FTRUNCATE: u64 = 77;
const __NR_GETTIMEOFDAY: u64 = 96;
const __NR_GETRLIMIT: u64 = 97;
const __NR_GETRUSAGE: u64 = 98;
const __NR_PRCTL: u64 = 157;
const __NR_GETTID2: u64 = 186; // alias, already handled above
const __NR_FUTEX: u64 = 202;
const __NR_SCHED_GETAFFINITY: u64 = 204;
const __NR_EPOLL_CREATE: u64 = 213;
const __NR_EPOLL_CTL: u64 = 233;
const __NR_EPOLL_WAIT: u64 = 232;
const __NR_CLOCK_GETRES: u64 = 229;
const __NR_CLOCK_NANOSLEEP: u64 = 230;
const __NR_TGKILL: u64 = 234;
const __NR_PPOLL: u64 = 271;
const __NR_EPOLL_CREATE1: u64 = 291;
const __NR_EPOLL_PWAIT: u64 = 281;
const __NR_MEMFD_CREATE: u64 = 319;
const __NR_STATX: u64 = 332;
const __NR_CLONE3: u64 = 435;

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
const EMFILE: u64 = 24;
const ESPIPE: u64 = 29;
const ERANGE: u64 = 34;
const ENOSYS: u64 = 38;
const ENOTEMPTY: u64 = 39;
const EEXIST: u64 = 17;
const ENOMEM: u64 = 12;
const ENOTTY: u64 = 25;
const ETIMEDOUT: u64 = 110;

// fcntl commands
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;

// File descriptor flags
const FD_CLOEXEC: u32 = 1;

// O_* flags for F_GETFL/F_SETFL
const O_NONBLOCK: u64 = 0x800;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;

/// Return negated errno as u64 (Linux convention).
fn linux_err(e: u64) -> u64 {
    (-(e as i64)) as u64
}

// VFS IPC protocol tags
const VFS_OPEN: u64 = 0x6010;
const VFS_OPEN_OK: u64 = 0x6110;
const VFS_STAT: u64 = 0x6020;
const VFS_STAT_OK: u64 = 0x6120;
const VFS_MKDIR: u64 = 0x6040;
const VFS_MKDIR_OK: u64 = 0x6140;
const VFS_UNLINK: u64 = 0x6050;
const VFS_UNLINK_OK: u64 = 0x6150;
const VFS_READDIR: u64 = 0x6030;
const VFS_READDIR_OK: u64 = 0x6130;
const VFS_READDIR_END: u64 = 0x6131;
const VFS_ERROR: u64 = 0x6F00;

// FS server protocol tags
const FS_READ: u64 = 0x2100;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_CLOSE: u64 = 0x2400;

// Linux AT_FDCWD
const AT_FDCWD: u64 = 0xFFFF_FFFF_FFFF_FF9C; // -100 as u64

// Pipe server protocol tags
const PIPE_CREATE: u64 = 0x5010;
const PIPE_WRITE_TAG: u64 = 0x5020;
const PIPE_READ_TAG: u64 = 0x5030;
const PIPE_CLOSE_TAG: u64 = 0x5040;
const PIPE_OK: u64 = 0x5100;
const PIPE_EOF_TAG: u64 = 0x51FF;

const MAX_FDS: usize = 64;
const MAX_PROCS: usize = 16;

#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    None,
    File,
    Pipe,
    Dir,
}

#[derive(Clone, Copy)]
struct FdEntry {
    in_use: bool,
    kind: FdKind,
    // File: fs_port = FS server port, handle = FS handle
    // Pipe: fs_port = pipe_srv port, handle = pipe handle
    // Dir: dir_path/dir_path_len store the absolute path for VFS_READDIR
    fs_port: u64,
    handle: u64,
    file_size: u64,
    offset: u64,
    dir_path: [u8; 16],
    dir_path_len: u8,
    fd_flags: u32,    // FD_CLOEXEC etc.
    status_flags: u32, // O_NONBLOCK etc.
}

impl FdEntry {
    const fn empty() -> Self {
        Self { in_use: false, kind: FdKind::None, fs_port: 0, handle: 0, file_size: 0, offset: 0, dir_path: [0; 16], dir_path_len: 0, fd_flags: 0, status_flags: 0 }
    }
}

/// Per-process state, keyed by caller_port (unique per Linux task).
#[derive(Clone, Copy)]
struct ProcessState {
    active: bool,
    port: u64,
    fds: [FdEntry; MAX_FDS],
    brk_base: usize,
    brk_current: usize,
    cwd: [u8; 64],
    cwd_len: usize,
}

impl ProcessState {
    const fn empty() -> Self {
        Self {
            active: false,
            port: 0,
            fds: [const { FdEntry::empty() }; MAX_FDS],
            brk_base: 0,
            brk_current: 0,
            cwd: [0u8; 64],
            cwd_len: 0,
        }
    }
}

static mut PROC_TABLE: [ProcessState; MAX_PROCS] = [const { ProcessState::empty() }; MAX_PROCS];
static mut VFS_PORT: u64 = 0;
static mut REPLY_PORT: u64 = 0;
static mut PIPE_PORT: u64 = 0;

/// Find a process slot by caller_port.
fn find_proc(port: u64) -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCS {
            if PROC_TABLE[i].active && PROC_TABLE[i].port == port {
                return Some(i);
            }
        }
    }
    None
}

/// Find or create a process slot for the given caller_port.
fn get_or_init_proc(port: u64) -> Option<usize> {
    if let Some(i) = find_proc(port) {
        return Some(i);
    }
    unsafe {
        for i in 0..MAX_PROCS {
            if !PROC_TABLE[i].active {
                PROC_TABLE[i] = ProcessState::empty();
                PROC_TABLE[i].active = true;
                PROC_TABLE[i].port = port;
                PROC_TABLE[i].cwd[0] = b'/';
                PROC_TABLE[i].cwd_len = 1;
                return Some(i);
            }
        }
    }
    None
}

fn alloc_fd(pi: usize) -> Option<usize> {
    unsafe {
        // Skip fds 0-2 (stdin/stdout/stderr are special).
        for i in 3..MAX_FDS {
            if !PROC_TABLE[pi].fds[i].in_use {
                PROC_TABLE[pi].fds[i].in_use = true;
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
fn handle_write(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
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

    // Check FD table for pipe writes.
    let fd_idx = fd as usize;
    if fd_idx >= MAX_FDS {
        return linux_err(EBADF);
    }
    unsafe {
        if !PROC_TABLE[pi].fds[fd_idx].in_use {
            return linux_err(EBADF);
        }
        if PROC_TABLE[pi].fds[fd_idx].kind == FdKind::Pipe {
            return write_pipe(caller_port, PROC_TABLE[pi].fds[fd_idx].fs_port,
                              PROC_TABLE[pi].fds[fd_idx].handle, buf_va, count);
        }
    }
    linux_err(EBADF)
}

/// Handle Linux writev(fd, iov, iovcnt).
fn handle_writev(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
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
        let r = handle_write(pi, caller_port, &write_args);
        if (r as i64) < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
    }
    total
}

/// Handle Linux read(fd, buf, count).
fn handle_read(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let buf_va = args[1] as usize;
    let count = args[2] as usize;

    if buf_va == 0 || count == 0 {
        return 0;
    }
    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }

    let (kind, fs_port, handle, offset, file_size) = unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use {
            return linux_err(EBADF);
        }
        (PROC_TABLE[pi].fds[fd].kind, PROC_TABLE[pi].fds[fd].fs_port, PROC_TABLE[pi].fds[fd].handle,
         PROC_TABLE[pi].fds[fd].offset, PROC_TABLE[pi].fds[fd].file_size)
    };

    if kind == FdKind::Pipe {
        return read_pipe(caller_port, fs_port, handle, buf_va, count);
    }

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
        unsafe { PROC_TABLE[pi].fds[fd].offset += to_write as u64; }
        if got < chunk {
            break; // Short read from FS.
        }
    }
    total as u64
}

/// Open a file via VFS. Returns fd or negated errno.
fn do_open(pi: usize, caller_port: u64, path_va: usize, flags: u64) -> u64 {
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

    if resp.tag == VFS_ERROR || resp.tag != VFS_OPEN_OK {
        // VFS_OPEN failed — this might be a directory (FS servers don't open dirs).
        // Create a Dir FD so getdents64 can enumerate via VFS_READDIR later.
        // Resolve relative paths by prepending CWD.
        let (dir_path, dir_len) = if path[0] == b'/' {
            (path, pathlen)
        } else {
            unsafe {
                let clen = PROC_TABLE[pi].cwd_len;
                let mut buf = [0u8; 16];
                let mut pos = 0;
                for i in 0..clen { if pos < 16 { buf[pos] = PROC_TABLE[pi].cwd[i]; pos += 1; } }
                if pos > 0 && buf[pos - 1] != b'/' { if pos < 16 { buf[pos] = b'/'; pos += 1; } }
                for i in 0..pathlen { if pos < 16 { buf[pos] = path[i]; pos += 1; } }
                (buf, pos)
            }
        };
        let fd = match alloc_fd(pi) {
            Some(f) => f,
            None => return linux_err(EBADF),
        };
        unsafe {
            PROC_TABLE[pi].fds[fd].kind = FdKind::Dir;
            PROC_TABLE[pi].fds[fd].offset = 0;
            PROC_TABLE[pi].fds[fd].dir_path_len = dir_len as u8;
            for i in 0..dir_len.min(16) { PROC_TABLE[pi].fds[fd].dir_path[i] = dir_path[i]; }
        }
        return fd as u64;
    }

    let fd = match alloc_fd(pi) {
        Some(f) => f,
        None => return linux_err(EBADF),
    };

    unsafe {
        PROC_TABLE[pi].fds[fd].kind = FdKind::File;
        PROC_TABLE[pi].fds[fd].fs_port = resp.data[0];
        PROC_TABLE[pi].fds[fd].handle = resp.data[1];
        PROC_TABLE[pi].fds[fd].file_size = resp.data[2];
        PROC_TABLE[pi].fds[fd].offset = 0;
    }

    fd as u64
}

/// Handle Linux open(path, flags, mode).
fn handle_open(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    do_open(pi, caller_port, args[0] as usize, args[1])
}

/// Handle Linux openat(dirfd, path, flags, mode).
fn handle_openat(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let dirfd = args[0];
    let path_va = args[1] as usize;
    let flags = args[2];
    // We only support AT_FDCWD for now.
    if dirfd != AT_FDCWD && (dirfd as i64) >= 0 {
        return linux_err(EBADF);
    }
    do_open(pi, caller_port, path_va, flags)
}

/// Internal close logic for any FD kind.
fn do_close(pi: usize, fd: usize) {
    unsafe {
        if fd >= MAX_FDS || !PROC_TABLE[pi].fds[fd].in_use {
            return;
        }
        match PROC_TABLE[pi].fds[fd].kind {
            FdKind::File => {
                let rp = REPLY_PORT;
                let d3 = rp << 32;
                syscall::send(PROC_TABLE[pi].fds[fd].fs_port, FS_CLOSE, PROC_TABLE[pi].fds[fd].handle, 0, 0, d3);
                let _ = syscall::recv_msg(rp);
            }
            FdKind::Pipe => {
                let rp = syscall::port_create();
                let d2 = (rp as u64) << 32;
                syscall::send(PROC_TABLE[pi].fds[fd].fs_port, PIPE_CLOSE_TAG, PROC_TABLE[pi].fds[fd].handle, 0, d2, 0);
                let _ = syscall::recv_msg(rp);
                syscall::port_destroy(rp);
            }
            FdKind::Dir => {} // No server handle to close.
            FdKind::None => {}
        }
        PROC_TABLE[pi].fds[fd] = FdEntry::empty();
    }
}

/// Handle Linux close(fd).
fn handle_close(pi: usize, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    if fd < 3 {
        return 0; // Closing stdin/stdout/stderr is a no-op.
    }
    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use {
            return linux_err(EBADF);
        }
    }
    do_close(pi, fd);
    0
}

/// Handle Linux lseek(fd, offset, whence).
fn handle_lseek(pi: usize, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let offset = args[1] as i64;
    let whence = args[2];

    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use {
            return linux_err(EBADF);
        }
        if PROC_TABLE[pi].fds[fd].kind == FdKind::Pipe {
            return linux_err(ESPIPE);
        }
        let new_off = match whence {
            0 => offset, // SEEK_SET
            1 => PROC_TABLE[pi].fds[fd].offset as i64 + offset, // SEEK_CUR
            2 => PROC_TABLE[pi].fds[fd].file_size as i64 + offset, // SEEK_END
            _ => return linux_err(EINVAL),
        };
        if new_off < 0 {
            return linux_err(EINVAL);
        }
        PROC_TABLE[pi].fds[fd].offset = new_off as u64;
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
fn handle_fstat(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
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
        if !PROC_TABLE[pi].fds[fd].in_use {
            return linux_err(EBADF);
        }
        if PROC_TABLE[pi].fds[fd].kind == FdKind::Pipe {
            let mut stat_buf = [0u8; 144];
            let mode: u32 = 0o010600; // S_IFIFO | 0600
            stat_buf[24..28].copy_from_slice(&mode.to_le_bytes());
            stat_buf[56..64].copy_from_slice(&4096u64.to_le_bytes());
            let written = syscall::personality_copy_out(caller_port, statbuf_va, &stat_buf);
            if written < 144 { return linux_err(EFAULT); }
            return 0;
        }
        let file_size = PROC_TABLE[pi].fds[fd].file_size;
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
fn handle_getcwd(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let buf_va = args[0] as usize;
    let size = args[1] as usize;

    unsafe {
        let clen = PROC_TABLE[pi].cwd_len;
        if size < clen + 1 {
            return linux_err(ERANGE);
        }
        // Copy CWD + null terminator.
        let mut buf = [0u8; 65];
        for i in 0..clen { buf[i] = PROC_TABLE[pi].cwd[i]; }
        buf[clen] = 0;
        let written = syscall::personality_copy_out(caller_port, buf_va, &buf[..clen + 1]);
        if written < clen + 1 {
            return linux_err(EFAULT);
        }
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

/// Read from a pipe FD into the caller's buffer via personality_copy_out.
fn read_pipe(caller_port: u64, pipe_port: u64, handle: u64, buf_va: usize, count: usize) -> u64 {
    let rp = syscall::port_create();
    let d2 = (rp as u64) << 32;
    syscall::send(pipe_port, PIPE_READ_TAG, handle, 0, d2, 0);
    let msg = match syscall::recv_msg(rp) {
        Some(m) => m,
        None => {
            syscall::debug_puts(b"[linux_srv] read_pipe: no reply\n");
            syscall::port_destroy(rp);
            return linux_err(EBADF);
        }
    };
    syscall::port_destroy(rp);

    if msg.tag == PIPE_EOF_TAG {
        return 0;
    }
    if msg.tag != PIPE_OK {
        syscall::debug_puts(b"[linux_srv] read_pipe: bad tag=");
        print_num(msg.tag);
        syscall::debug_puts(b"\n");
        return linux_err(EBADF);
    }

    let n = (msg.data[2] as usize).min(16).min(count);
    let mut tmp = [0u8; 16];
    let b0 = msg.data[0].to_le_bytes();
    let b1 = msg.data[1].to_le_bytes();
    tmp[..8].copy_from_slice(&b0);
    tmp[8..16].copy_from_slice(&b1);
    let written = syscall::personality_copy_out(caller_port, buf_va, &tmp[..n]);
    if written == 0 {
        return linux_err(EFAULT);
    }
    written as u64
}

/// Write from the caller's buffer to a pipe FD via personality_copy_in.
fn write_pipe(caller_port: u64, pipe_port: u64, handle: u64, buf_va: usize, count: usize) -> u64 {
    let mut offset = 0usize;
    while offset < count {
        let chunk_len = (count - offset).min(16);
        let mut tmp = [0u8; 16];
        let copied = syscall::personality_copy_in(caller_port, buf_va + offset, &mut tmp[..chunk_len]);
        if copied == 0 {
            syscall::debug_puts(b"[linux_srv] write_pipe: copy_in failed\n");
            return if offset > 0 { offset as u64 } else { linux_err(EFAULT) };
        }
        let mut w0 = 0u64;
        let mut w1 = 0u64;
        for i in 0..copied.min(8) { w0 |= (tmp[i] as u64) << (i * 8); }
        for i in 8..copied { w1 |= (tmp[i] as u64) << ((i - 8) * 8); }
        // Fire-and-forget: d2 low16 = len, high32 = 0xFFFFFFFF (no reply).
        let d2 = (copied as u64) | (0xFFFFFFFF_u64 << 32);
        syscall::send(pipe_port, PIPE_WRITE_TAG, handle, w0, d2, w1);
        offset += copied;
    }
    offset as u64
}

/// Handle Linux pipe2(pipefd, flags).
fn handle_pipe2(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let pipefd_va = args[0] as usize;
    let _flags = args[1]; // O_CLOEXEC/O_NONBLOCK ignored for now

    let pipe_port = unsafe { PIPE_PORT };
    if pipe_port == 0 { return linux_err(ENOSYS); }

    // Create a pipe via pipe_srv.
    let rp = syscall::port_create();
    let d2 = (rp as u64) << 32;
    syscall::send(pipe_port, PIPE_CREATE, 0, 0, d2, 0);
    let msg = match syscall::recv_msg(rp) {
        Some(m) => m,
        None => { syscall::port_destroy(rp); return linux_err(ENOSYS); }
    };
    syscall::port_destroy(rp);
    if msg.tag != PIPE_OK { return linux_err(ENOSYS); }

    let read_handle = msg.data[0];
    let write_handle = msg.data[1];

    // Allocate two FDs.
    let read_fd = match alloc_fd(pi) {
        Some(f) => f,
        None => return linux_err(EMFILE),
    };
    let write_fd = match alloc_fd(pi) {
        Some(f) => f,
        None => {
            unsafe { PROC_TABLE[pi].fds[read_fd] = FdEntry::empty(); }
            return linux_err(EMFILE);
        }
    };

    unsafe {
        PROC_TABLE[pi].fds[read_fd].kind = FdKind::Pipe;
        PROC_TABLE[pi].fds[read_fd].fs_port = pipe_port;
        PROC_TABLE[pi].fds[read_fd].handle = read_handle;
        PROC_TABLE[pi].fds[write_fd].kind = FdKind::Pipe;
        PROC_TABLE[pi].fds[write_fd].fs_port = pipe_port;
        PROC_TABLE[pi].fds[write_fd].handle = write_handle;
    }

    // Write [read_fd, write_fd] as two i32s to the caller.
    let fds: [i32; 2] = [read_fd as i32, write_fd as i32];
    let fds_bytes: [u8; 8] = unsafe { core::mem::transmute(fds) };
    let written = syscall::personality_copy_out(caller_port, pipefd_va, &fds_bytes);
    if written < 8 { return linux_err(EFAULT); }
    0
}

/// Handle Linux dup(oldfd).
fn handle_dup(pi: usize, args: &[u64; 6]) -> u64 {
    let oldfd = args[0] as usize;
    if oldfd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[oldfd].in_use { return linux_err(EBADF); }
        let newfd = match alloc_fd(pi) {
            Some(f) => f,
            None => return linux_err(EMFILE),
        };
        PROC_TABLE[pi].fds[newfd] = PROC_TABLE[pi].fds[oldfd];
        newfd as u64
    }
}

/// Handle Linux dup2(oldfd, newfd).
fn handle_dup2(pi: usize, args: &[u64; 6]) -> u64 {
    let oldfd = args[0] as usize;
    let newfd = args[1] as usize;
    if oldfd >= MAX_FDS || newfd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[oldfd].in_use { return linux_err(EBADF); }
        if oldfd == newfd { return newfd as u64; }
        // Close newfd if open.
        if PROC_TABLE[pi].fds[newfd].in_use { do_close(pi, newfd); }
        PROC_TABLE[pi].fds[newfd] = PROC_TABLE[pi].fds[oldfd];
        newfd as u64
    }
}

/// Handle Linux dup3(oldfd, newfd, flags).
fn handle_dup3(pi: usize, args: &[u64; 6]) -> u64 {
    let oldfd = args[0] as usize;
    let newfd = args[1] as usize;
    if oldfd == newfd { return linux_err(EINVAL); }
    // Reuse dup2 logic.
    handle_dup2(pi, args)
}

/// Handle Linux fork() / vfork() / clone() (basic).
fn handle_fork(pi: usize, caller_port: u64) -> u64 {
    let child_port = syscall::personality_fork(caller_port);
    if child_port == u64::MAX {
        return linux_err(EAGAIN);
    }
    // Clone parent's process state for the child.
    unsafe {
        let mut child_slot = None;
        for i in 0..MAX_PROCS {
            if !PROC_TABLE[i].active {
                child_slot = Some(i);
                break;
            }
        }
        if let Some(ci) = child_slot {
            PROC_TABLE[ci] = PROC_TABLE[pi];
            PROC_TABLE[ci].port = child_port;
        }
        // If no slot available, child runs without tracked state (will auto-create on first syscall).
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
fn handle_brk(pi: usize, args: &[u64; 6]) -> u64 {
    let addr = args[0] as usize;

    unsafe {
        if PROC_TABLE[pi].brk_base == 0 {
            PROC_TABLE[pi].brk_base = 0x4000_0000;
            PROC_TABLE[pi].brk_current = PROC_TABLE[pi].brk_base;
        }

        if addr == 0 {
            return PROC_TABLE[pi].brk_current as u64;
        }

        if addr >= PROC_TABLE[pi].brk_base && addr <= PROC_TABLE[pi].brk_base + 256 * 1024 * 1024 {
            let page_size = syscall::page_size() as usize;
            if addr > PROC_TABLE[pi].brk_current {
                let old_pages = (PROC_TABLE[pi].brk_current + page_size - 1) / page_size;
                let new_pages = (addr + page_size - 1) / page_size;
                if new_pages > old_pages {
                    let alloc_start = old_pages * page_size;
                    let count = new_pages - old_pages;
                    if syscall::mmap_anon(alloc_start, count, 3).is_none() {
                        return PROC_TABLE[pi].brk_current as u64;
                    }
                }
            }
            PROC_TABLE[pi].brk_current = addr;
            return PROC_TABLE[pi].brk_current as u64;
        }

        PROC_TABLE[pi].brk_current as u64
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
fn handle_exit(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let _code = args[0];
    // Close all open FDs for this process.
    unsafe {
        for i in 3..MAX_FDS {
            if PROC_TABLE[pi].fds[i].in_use {
                do_close(pi, i);
            }
        }
        // Free the process slot.
        PROC_TABLE[pi] = ProcessState::empty();
    }
    syscall::kill(caller_port);
    0
}

/// Handle Linux execve(filename, argv, envp).
/// Copies the filename from the client, calls personality_execve.
/// On success, does NOT reply — the kernel wakes the target directly.
/// On failure, returns -ENOENT.
fn handle_execve(pi: usize, caller_port: u64, args: &[u64; 6]) -> Option<u64> {
    let filename_va = args[0] as usize;
    let _argv_va = args[1] as usize;
    let _envp_va = args[2] as usize;

    // Copy filename from the client's address space (null-terminated).
    let mut name_buf = [0u8; 64];
    let copied = syscall::personality_copy_in(caller_port, filename_va, &mut name_buf);
    if copied == 0 {
        return Some(linux_err(EFAULT));
    }

    // Find null terminator.
    let name_len = name_buf[..copied].iter().position(|&b| b == 0).unwrap_or(copied);
    let name = &name_buf[..name_len];

    // Strip leading "/" for initramfs lookup.
    let lookup_name = if name.first() == Some(&b'/') { &name[1..] } else { name };

    let result = syscall::personality_execve(caller_port, lookup_name);
    if result == u64::MAX {
        return Some(linux_err(ENOENT));
    }

    // On success: close CLOEXEC FDs and reset BRK.
    unsafe {
        for i in 3..MAX_FDS {
            if PROC_TABLE[pi].fds[i].in_use && (PROC_TABLE[pi].fds[i].fd_flags & FD_CLOEXEC) != 0 {
                do_close(pi, i);
            }
        }
        PROC_TABLE[pi].brk_base = 0;
        PROC_TABLE[pi].brk_current = 0;
    }

    // Success: the kernel has already woken the target with its new image.
    // Do NOT call personality_reply — return None to signal the main loop to skip reply.
    None
}

/// Resolve a path from caller's address space. If relative, prepend CWD.
/// Returns (absolute_path_buf, path_len).
fn resolve_path(pi: usize, caller_port: u64, path_va: usize) -> ([u8; 64], usize) {
    let mut raw = [0u8; 64];
    let copied = syscall::personality_copy_in(caller_port, path_va, &mut raw);
    if copied == 0 {
        return ([0u8; 64], 0);
    }
    let raw_len = raw[..copied].iter().position(|&b| b == 0).unwrap_or(copied);
    if raw_len == 0 {
        return ([0u8; 64], 0);
    }

    if raw[0] == b'/' {
        // Absolute path — use as-is.
        return (raw, raw_len);
    }

    // Relative path — prepend CWD.
    unsafe {
        let clen = PROC_TABLE[pi].cwd_len;
        let mut buf = [0u8; 64];
        let mut pos = 0;
        // Copy CWD.
        for i in 0..clen {
            if pos < 64 { buf[pos] = PROC_TABLE[pi].cwd[i]; pos += 1; }
        }
        // Add separator if CWD doesn't end with '/'.
        if pos > 0 && buf[pos - 1] != b'/' {
            if pos < 64 { buf[pos] = b'/'; pos += 1; }
        }
        // Copy relative path.
        for i in 0..raw_len {
            if pos < 64 { buf[pos] = raw[i]; pos += 1; }
        }
        (buf, pos)
    }
}

/// Pack a path into VFS protocol format (two u64 words, max 16 bytes).
fn pack_path_vfs(path: &[u8], pathlen: usize) -> (u64, u64, u64) {
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    let len = pathlen.min(16);
    for i in 0..len.min(8) {
        w0 |= (path[i] as u64) << (i * 8);
    }
    for i in 8..len {
        w1 |= (path[i] as u64) << ((i - 8) * 8);
    }
    (w0, w1, len as u64)
}

/// Handle Linux mkdir(path, mode).
fn handle_mkdir(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let path_va = args[0] as usize;
    let mode = args[1] as u32;

    let vfs_port = unsafe { VFS_PORT };
    let reply_port = unsafe { REPLY_PORT };
    if vfs_port == 0 { return linux_err(ENOSYS); }

    let (path, pathlen) = resolve_path(pi, caller_port, path_va);
    if pathlen == 0 { return linux_err(EFAULT); }

    let (w0, w1, plen) = pack_path_vfs(&path, pathlen);
    let d2 = plen | (((mode & 0xFFFF) as u64) << 16) | ((reply_port) << 32);
    syscall::send(vfs_port, VFS_MKDIR, w0, w1, d2, 0);

    match syscall::recv_msg(reply_port) {
        Some(resp) if resp.tag == VFS_MKDIR_OK => 0,
        _ => linux_err(EEXIST),
    }
}

/// Handle Linux mkdirat(dirfd, path, mode).
fn handle_mkdirat(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let dirfd = args[0];
    if dirfd != AT_FDCWD && (dirfd as i64) >= 0 { return linux_err(ENOSYS); }
    let shifted: [u64; 6] = [args[1], args[2], args[3], 0, args[4], args[5]];
    handle_mkdir(pi, caller_port, &shifted)
}

/// Handle Linux unlink(path) / rmdir(path).
fn handle_unlink_impl(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let path_va = args[0] as usize;

    let vfs_port = unsafe { VFS_PORT };
    let reply_port = unsafe { REPLY_PORT };
    if vfs_port == 0 { return linux_err(ENOSYS); }

    let (path, pathlen) = resolve_path(pi, caller_port, path_va);
    if pathlen == 0 { return linux_err(EFAULT); }

    let (w0, w1, plen) = pack_path_vfs(&path, pathlen);
    let d2 = plen | ((reply_port) << 32);
    syscall::send(vfs_port, VFS_UNLINK, w0, w1, d2, 0);

    match syscall::recv_msg(reply_port) {
        Some(resp) if resp.tag == VFS_UNLINK_OK => 0,
        _ => linux_err(ENOENT),
    }
}

/// Handle Linux unlinkat(dirfd, path, flags).
fn handle_unlinkat(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let dirfd = args[0];
    if dirfd != AT_FDCWD && (dirfd as i64) >= 0 { return linux_err(ENOSYS); }
    let shifted: [u64; 6] = [args[1], args[2], args[3], 0, args[4], args[5]];
    handle_unlink_impl(pi, caller_port, &shifted)
}

/// Handle Linux chdir(path).
fn handle_chdir(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let path_va = args[0] as usize;

    let (path, pathlen) = resolve_path(pi, caller_port, path_va);
    if pathlen == 0 { return linux_err(EFAULT); }

    // Verify directory exists via VFS_STAT.
    let vfs_port = unsafe { VFS_PORT };
    let reply_port = unsafe { REPLY_PORT };
    if vfs_port == 0 { return linux_err(ENOSYS); }

    let (w0, w1, plen) = pack_path_vfs(&path, pathlen);
    let d2 = plen | ((reply_port) << 32);
    syscall::send(vfs_port, VFS_STAT, w0, w1, d2, 0);

    match syscall::recv_msg(reply_port) {
        Some(resp) if resp.tag == VFS_STAT_OK => {
            // Update CWD for this process.
            unsafe {
                for i in 0..pathlen.min(64) {
                    PROC_TABLE[pi].cwd[i] = path[i];
                }
                PROC_TABLE[pi].cwd_len = pathlen.min(64);
            }
            0
        }
        _ => linux_err(ENOENT),
    }
}

/// Handle Linux getdents64(fd, dirp, count).
///
/// For simplicity, we use the path stored in the FD entry to do path-based
/// directory listing via the FS server's FS_READDIR protocol (one entry
/// at a time with offset-based pagination).
///
/// Since linux_srv FD entries for directories store the FS server port and
/// a handle, we iterate FS_READDIR on that handle.
///
/// Linux dirent64 layout (x86_64):
/// getdents64 on a Dir FD: use VFS_READDIR (path-based) to enumerate entries.
/// VFS_READDIR: data[0]=path_lo, data[1]=path_hi, data[2]=path_len(16)|reply_port(32)
/// VFS_READDIR_OK: data[0]=size, data[1]=name_lo, data[2]=name_hi, data[3]=next_offset
fn handle_getdents64_dir(pi: usize, caller_port: u64, fd: usize, dirp_va: usize, count: usize) -> u64 {
    let vfs_port = unsafe { VFS_PORT };
    if vfs_port == 0 { return 0; }

    let (path, plen) = unsafe {
        let plen = PROC_TABLE[pi].fds[fd].dir_path_len as usize;
        (PROC_TABLE[pi].fds[fd].dir_path, plen)
    };

    // Pack path for VFS.
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    for i in 0..plen.min(8) { w0 |= (path[i] as u64) << (i * 8); }
    for i in 8..plen.min(16) { w1 |= (path[i] as u64) << ((i - 8) * 8); }

    let rp = syscall::port_create();
    let d2 = (plen as u64) | ((rp as u64) << 32);
    syscall::send(vfs_port, VFS_READDIR, w0, w1, d2, 0);

    // VFS streams entries back: VFS_READDIR_OK* then VFS_READDIR_END.
    let mut buf = [0u8; 2048];
    let mut buf_pos = 0usize;
    let mut entry_idx = 0u64;

    for _ in 0..200 {
        if buf_pos + 280 > count.min(2048) { break; }

        let resp = match syscall::recv_msg(rp) {
            Some(m) => m,
            None => break,
        };

        if resp.tag == VFS_READDIR_END { break; }
        if resp.tag != VFS_READDIR_OK { break; }

        let name_lo = resp.data[1];
        let name_hi = resp.data[2];

        // Unpack filename.
        let mut name = [0u8; 16];
        let mut name_len = 0usize;
        for i in 0..8 {
            let b = ((name_lo >> (i * 8)) & 0xFF) as u8;
            if b == 0 { break; }
            name[name_len] = b;
            name_len += 1;
        }
        if name_len == 8 {
            for i in 0..8 {
                let b = ((name_hi >> (i * 8)) & 0xFF) as u8;
                if b == 0 { break; }
                name[name_len] = b;
                name_len += 1;
            }
        }

        entry_idx += 1;
        let reclen = ((19 + name_len + 1) + 7) & !7;
        if buf_pos + reclen > count.min(2048) { break; }

        let d_ino = entry_idx;
        let d_off = entry_idx as i64;
        buf[buf_pos..buf_pos+8].copy_from_slice(&d_ino.to_le_bytes());
        buf[buf_pos+8..buf_pos+16].copy_from_slice(&d_off.to_le_bytes());
        buf[buf_pos+16..buf_pos+18].copy_from_slice(&(reclen as u16).to_le_bytes());
        buf[buf_pos+18] = 0; // DT_UNKNOWN
        for i in 0..name_len { buf[buf_pos + 19 + i] = name[i]; }
        buf[buf_pos + 19 + name_len] = 0;
        for i in (19 + name_len + 1)..reclen { buf[buf_pos + i] = 0; }
        buf_pos += reclen;
    }

    syscall::port_destroy(rp);

    if buf_pos > 0 {
        let written = syscall::personality_copy_out(caller_port, dirp_va, &buf[..buf_pos]);
        if written == 0 { return linux_err(EFAULT); }
        buf_pos as u64
    } else {
        0
    }
}

/// Linux dirent64 layout:
///   u64 d_ino
///   i64 d_off
///   u16 d_reclen
///   u8  d_type
///   char d_name[] (null-terminated, padded to alignment)
fn handle_getdents64(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let dirp_va = args[1] as usize;
    let count = args[2] as usize;

    // For fd == 3+ use FD table. For raw directory reads,
    // the directory must have been opened first.
    if fd >= MAX_FDS { return linux_err(EBADF); }

    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use { return linux_err(EBADF); }
    }

    // Handle Dir FDs via VFS_READDIR (path-based).
    let is_dir = unsafe { matches!(PROC_TABLE[pi].fds[fd].kind, FdKind::Dir) };
    if is_dir {
        return handle_getdents64_dir(pi, caller_port, fd, dirp_va, count);
    }

    let (fs_port, _handle) = unsafe {
        if PROC_TABLE[pi].fds[fd].kind != FdKind::File { return linux_err(ENOTDIR); }
        (PROC_TABLE[pi].fds[fd].fs_port, PROC_TABLE[pi].fds[fd].handle)
    };

    // Use the FD's offset as the readdir pagination cursor.
    let start_offset = unsafe { PROC_TABLE[pi].fds[fd].offset } as u64;

    let rp = syscall::port_create();
    let mut buf = [0u8; 2048];
    let mut buf_pos = 0usize;
    let mut next_off = start_offset;

    // Read entries one at a time from FS server.
    for _ in 0..200 {
        if buf_pos + 280 > count.min(2048) { break; } // Leave room for next entry

        let d2 = (rp as u64) & 0xFFFF_FFFF;
        syscall::send(fs_port, FS_READDIR, next_off, 0, d2, 0);

        let resp = match syscall::recv_msg(rp) {
            Some(m) => m,
            None => break,
        };

        if resp.tag == FS_READDIR_END { break; }
        if resp.tag != FS_READDIR_OK { break; }

        // FS_READDIR_OK: data[0]=size, data[1]=name_lo, data[2]=name_hi, data[3]=next_offset
        let name_lo = resp.data[1];
        let name_hi = resp.data[2];
        next_off = resp.data[3];

        // Unpack filename (up to 16 bytes).
        let mut name = [0u8; 16];
        let mut name_len = 0usize;
        for i in 0..8 {
            let b = ((name_lo >> (i * 8)) & 0xFF) as u8;
            if b == 0 { break; }
            name[name_len] = b;
            name_len += 1;
        }
        if name_len == 8 {
            for i in 0..8 {
                let b = ((name_hi >> (i * 8)) & 0xFF) as u8;
                if b == 0 { break; }
                name[name_len] = b;
                name_len += 1;
            }
        }

        // Build a Linux dirent64 entry.
        // d_reclen = 8(ino) + 8(off) + 2(reclen) + 1(type) + name_len + 1(null), rounded up to 8.
        let reclen = ((19 + name_len + 1) + 7) & !7;
        if buf_pos + reclen > count.min(2048) { break; }

        let d_ino = next_off as u64 + 1; // Fake inode
        let d_off = next_off as i64;
        let d_type = 0u8; // DT_UNKNOWN

        // d_ino at offset 0
        buf[buf_pos..buf_pos+8].copy_from_slice(&d_ino.to_le_bytes());
        // d_off at offset 8
        buf[buf_pos+8..buf_pos+16].copy_from_slice(&d_off.to_le_bytes());
        // d_reclen at offset 16
        buf[buf_pos+16..buf_pos+18].copy_from_slice(&(reclen as u16).to_le_bytes());
        // d_type at offset 18
        buf[buf_pos+18] = d_type;
        // d_name at offset 19
        for i in 0..name_len {
            buf[buf_pos + 19 + i] = name[i];
        }
        buf[buf_pos + 19 + name_len] = 0; // null terminate
        // Zero pad to reclen
        for i in (19 + name_len + 1)..reclen {
            buf[buf_pos + i] = 0;
        }

        buf_pos += reclen;
    }

    syscall::port_destroy(rp);

    // Update FD offset for next call.
    unsafe { PROC_TABLE[pi].fds[fd].offset = next_off; }

    if buf_pos > 0 {
        let written = syscall::personality_copy_out(caller_port, dirp_va, &buf[..buf_pos]);
        if written == 0 { return linux_err(EFAULT); }
        buf_pos as u64
    } else {
        0 // EOF
    }
}

/// Handle Linux getpid/gettid/getuid/geteuid/getgid/getegid.
// ---- Phase 127 handlers ----

/// Handle Linux fcntl(fd, cmd, arg).
fn handle_fcntl(pi: usize, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let cmd = args[1];
    let arg = args[2];

    if fd >= MAX_FDS {
        return linux_err(EBADF);
    }
    // fds 0-2 (stdin/stdout/stderr) are implicit and always valid.
    if fd >= 3 {
        unsafe {
            if !PROC_TABLE[pi].fds[fd].in_use {
                return linux_err(EBADF);
            }
        }
    }

    match cmd {
        F_GETFD => unsafe { PROC_TABLE[pi].fds[fd].fd_flags as u64 },
        F_SETFD => unsafe {
            PROC_TABLE[pi].fds[fd].fd_flags = arg as u32;
            0
        },
        F_GETFL => unsafe { PROC_TABLE[pi].fds[fd].status_flags as u64 },
        F_SETFL => unsafe {
            // Only O_NONBLOCK and a few flags are settable via F_SETFL.
            PROC_TABLE[pi].fds[fd].status_flags = (PROC_TABLE[pi].fds[fd].status_flags & 0x3) | (arg as u32 & !0x3);
            0
        },
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let min_fd = arg as usize;
            let new_fd = unsafe {
                let mut found = None;
                for i in min_fd.max(3)..MAX_FDS {
                    if !PROC_TABLE[pi].fds[i].in_use {
                        found = Some(i);
                        break;
                    }
                }
                found
            };
            match new_fd {
                Some(nfd) => unsafe {
                    PROC_TABLE[pi].fds[nfd] = PROC_TABLE[pi].fds[fd];
                    PROC_TABLE[pi].fds[nfd].fd_flags = if cmd == F_DUPFD_CLOEXEC { FD_CLOEXEC } else { 0 };
                    nfd as u64
                },
                None => linux_err(EMFILE),
            }
        }
        _ => linux_err(EINVAL),
    }
}

/// Handle Linux ioctl(fd, request, arg).
fn handle_ioctl(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let request = args[1];

    // fds 0-2 are always valid (stdin/stdout/stderr).
    if fd >= 3 && fd < MAX_FDS {
        unsafe { if !PROC_TABLE[pi].fds[fd].in_use { return linux_err(EBADF); } }
    } else if fd >= MAX_FDS {
        return linux_err(EBADF);
    }

    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONBIO: u64 = 0x5421;
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;

    match request {
        TIOCGWINSZ => {
            // Return 80x24 default terminal size.
            // struct winsize { rows(u16), cols(u16), xpixel(u16), ypixel(u16) }
            let buf: [u8; 8] = [
                24, 0,  // rows = 24
                80, 0,  // cols = 80
                0, 0,   // xpixel
                0, 0,   // ypixel
            ];
            let out_va = args[2] as usize;
            if out_va != 0 {
                syscall::personality_copy_out(caller_port, out_va, &buf);
            }
            0
        }
        TIOCSWINSZ => 0, // Ignore set window size.
        FIONBIO => {
            // Set/clear non-blocking on fd.
            if fd < MAX_FDS {
                unsafe {
                    if args[2] != 0 {
                        PROC_TABLE[pi].fds[fd].status_flags |= O_NONBLOCK as u32;
                    } else {
                        PROC_TABLE[pi].fds[fd].status_flags &= !(O_NONBLOCK as u32);
                    }
                }
            }
            0
        }
        TCGETS | TCSETS => linux_err(ENOTTY), // Not a real terminal.
        _ => linux_err(ENOTTY),
    }
}

/// Handle Linux gettimeofday(tv, tz).
fn handle_gettimeofday(caller_port: u64, args: &[u64; 6]) -> u64 {
    let tv_va = args[0] as usize;
    let ns = syscall::clock_gettime();
    let secs = ns / 1_000_000_000;
    let usecs = (ns % 1_000_000_000) / 1_000;

    if tv_va != 0 {
        // struct timeval { tv_sec: i64, tv_usec: i64 }
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&(secs as i64).to_le_bytes());
        buf[8..16].copy_from_slice(&(usecs as i64).to_le_bytes());
        syscall::personality_copy_out(caller_port, tv_va, &buf);
    }
    0
}

/// Handle Linux nanosleep(req, rem) / clock_nanosleep.
fn handle_nanosleep(caller_port: u64, args: &[u64; 6]) -> u64 {
    let req_va = args[0] as usize;
    if req_va == 0 { return linux_err(EFAULT); }

    // Read struct timespec { tv_sec: i64, tv_nsec: i64 } from caller.
    let mut buf = [0u8; 16];
    let copied = syscall::personality_copy_in(caller_port, req_va, &mut buf);
    if copied < 16 { return linux_err(EFAULT); }

    let secs = i64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    let nsecs = i64::from_le_bytes(buf[8..16].try_into().unwrap_or([0; 8]));
    let total_ns = (secs as u64).saturating_mul(1_000_000_000).saturating_add(nsecs as u64);

    if total_ns > 0 {
        syscall::nanosleep(total_ns);
    }
    0
}

/// Handle Linux poll(fds, nfds, timeout) — basic stub.
/// Returns 0 (timeout) for non-zero timeouts, or nfds with POLLNVAL for unknown fds.
fn handle_poll(caller_port: u64, args: &[u64; 6]) -> u64 {
    let _fds_va = args[0] as usize;
    let nfds = args[1] as usize;
    let timeout_ms = args[2] as i32;

    if nfds == 0 {
        // Pure sleep via poll(NULL, 0, timeout).
        if timeout_ms > 0 {
            let ns = (timeout_ms as u64) * 1_000_000;
            syscall::nanosleep(ns);
        }
        return 0;
    }

    // For non-trivial poll, sleep for the timeout and return 0.
    // This is a simplistic stub that prevents infinite busy-loops.
    if timeout_ms > 0 {
        let ns = (timeout_ms as u64).min(100) * 1_000_000;
        syscall::nanosleep(ns);
    } else if timeout_ms == 0 {
        // Non-blocking poll — return immediately.
    } else {
        // Infinite timeout — yield a few times then return 0.
        for _ in 0..10 { syscall::yield_now(); }
    }
    0 // No events ready.
}

/// Handle Linux prctl(option, arg2, arg3, arg4, arg5).
fn handle_prctl(args: &[u64; 6]) -> u64 {
    let option = args[0];
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    const PR_GET_DUMPABLE: u64 = 3;
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_SET_PDEATHSIG: u64 = 1;
    const PR_GET_PDEATHSIG: u64 = 2;

    match option {
        PR_GET_DUMPABLE => 1, // Always dumpable.
        PR_SET_DUMPABLE => 0, // Ignore, return success.
        PR_SET_PDEATHSIG | PR_GET_PDEATHSIG => 0, // Stub.
        PR_SET_NAME | PR_GET_NAME => 0, // Stub.
        _ => linux_err(EINVAL),
    }
}

/// Handle Linux futex(uaddr, op, val, timeout, uaddr2, val3).
/// Stub: FUTEX_WAIT yields, FUTEX_WAKE returns 0.
fn handle_futex(args: &[u64; 6]) -> u64 {
    let _uaddr = args[0];
    let op = args[1] & 0x7F; // Mask out FUTEX_PRIVATE_FLAG
    let _val = args[2];

    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    const FUTEX_WAIT_BITSET: u64 = 9;
    const FUTEX_WAKE_BITSET: u64 = 10;

    match op {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            // Can't implement proper futex without kernel delegation.
            // Yield a few times and return ETIMEDOUT.
            for _ in 0..5 { syscall::yield_now(); }
            linux_err(ETIMEDOUT)
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => 0, // No waiters.
        _ => linux_err(ENOSYS),
    }
}

/// Handle Linux clock_getres(clockid, res).
fn handle_clock_getres(caller_port: u64, args: &[u64; 6]) -> u64 {
    let res_va = args[1] as usize;
    if res_va != 0 {
        // 1ns resolution.
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&0i64.to_le_bytes()); // tv_sec = 0
        buf[8..16].copy_from_slice(&1i64.to_le_bytes()); // tv_nsec = 1
        syscall::personality_copy_out(caller_port, res_va, &buf);
    }
    0
}

/// Handle Linux getppid — return 1 (init).
fn handle_getppid() -> u64 {
    1
}

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

    // Set up VFS and pipe client ports.
    unsafe {
        REPLY_PORT = syscall::port_create();
        VFS_PORT = syscall::ns_lookup(b"vfs").unwrap_or(0);
        PIPE_PORT = syscall::ns_lookup(b"pipe").unwrap_or(0);
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

        // Resolve per-process state index.
        let pi = match get_or_init_proc(caller_port) {
            Some(i) => i,
            None => {
                syscall::personality_reply(caller_port, linux_err(ENOMEM));
                continue;
            }
        };

        let result = match linux_nr {
            __NR_READ => handle_read(pi, caller_port, &msg.data),
            __NR_WRITE => handle_write(pi, caller_port, &msg.data),
            __NR_OPEN => handle_open(pi, caller_port, &msg.data),
            __NR_CLOSE => handle_close(pi, &msg.data),
            __NR_STAT | __NR_NEWFSTATAT => handle_stat(caller_port, &msg.data),
            __NR_FSTAT => handle_fstat(pi, caller_port, &msg.data),
            __NR_LSEEK => handle_lseek(pi, &msg.data),
            __NR_WRITEV => handle_writev(pi, caller_port, &msg.data),
            __NR_ACCESS => handle_access(caller_port, &msg.data),
            __NR_DUP => handle_dup(pi, &msg.data),
            __NR_DUP2 => handle_dup2(pi, &msg.data),
            __NR_GETCWD => handle_getcwd(pi, caller_port, &msg.data),
            __NR_READLINK => handle_readlink(caller_port, &msg.data),
            __NR_OPENAT => handle_openat(pi, caller_port, &msg.data),
            __NR_MKDIR => handle_mkdir(pi, caller_port, &msg.data),
            __NR_MKDIRAT => handle_mkdirat(pi, caller_port, &msg.data),
            __NR_RMDIR | __NR_UNLINK => handle_unlink_impl(pi, caller_port, &msg.data),
            __NR_UNLINKAT => handle_unlinkat(pi, caller_port, &msg.data),
            __NR_CHDIR => handle_chdir(pi, caller_port, &msg.data),
            __NR_FCHDIR => 0, // stub
            __NR_GETDENTS64 => handle_getdents64(pi, caller_port, &msg.data),
            __NR_DUP3 => handle_dup3(pi, &msg.data),
            __NR_PIPE2 => handle_pipe2(pi, caller_port, &msg.data),
            __NR_FORK | __NR_VFORK => handle_fork(pi, caller_port),
            __NR_CLONE => handle_fork(pi, caller_port), // basic clone = fork
            __NR_EXECVE => {
                match handle_execve(pi, caller_port, &msg.data) {
                    Some(err) => err,
                    None => continue, // Success: kernel woke target directly, skip reply.
                }
            }
            __NR_WAIT4 => handle_wait4(caller_port, &msg.data),
            __NR_BRK => handle_brk(pi, &msg.data),
            __NR_ARCH_PRCTL => handle_arch_prctl(&msg.data),
            __NR_SET_TID_ADDRESS => handle_set_tid_address(caller_port),
            __NR_EXIT | __NR_EXIT_GROUP => {
                handle_exit(pi, caller_port, &msg.data);
                continue; // Don't reply — task is dead.
            }
            __NR_GETPID | __NR_GETTID | __NR_GETUID | __NR_GETEUID
            | __NR_GETGID | __NR_GETEGID => handle_getid(linux_nr),
            __NR_CLOCK_GETTIME => handle_clock_gettime(caller_port, &msg.data),
            __NR_UNAME => handle_uname(caller_port, &msg.data),
            __NR_GETRANDOM => handle_getrandom(caller_port, &msg.data),

            // Phase 127: fcntl, ioctl, time, signals, process control.
            __NR_FCNTL => handle_fcntl(pi, &msg.data),
            __NR_IOCTL => handle_ioctl(pi, caller_port, &msg.data),
            __NR_GETTIMEOFDAY => handle_gettimeofday(caller_port, &msg.data),
            __NR_NANOSLEEP => handle_nanosleep(caller_port, &msg.data),
            __NR_CLOCK_NANOSLEEP => {
                // clock_nanosleep(clockid, flags, req, rem): shift args.
                let shifted: [u64; 6] = [msg.data[2], msg.data[3], 0, 0, msg.data[4], 0];
                handle_nanosleep(caller_port, &shifted)
            }
            __NR_CLOCK_GETRES => handle_clock_getres(caller_port, &msg.data),
            __NR_POLL | __NR_PPOLL => handle_poll(caller_port, &msg.data),
            __NR_PRCTL => handle_prctl(&msg.data),
            __NR_FUTEX => handle_futex(&msg.data),
            __NR_GETPPID => handle_getppid(),
            __NR_SCHED_YIELD => { syscall::yield_now(); 0 }
            __NR_GETPGRP => syscall::getpgid(0),
            __NR_SETPGID => {
                if syscall::setpgid(msg.data[0], msg.data[1]) { 0 } else { linux_err(EPERM) }
            }
            __NR_GETPGID => syscall::getpgid(msg.data[0]),
            __NR_SETSID => {
                let r = syscall::setsid();
                if r == u64::MAX { linux_err(EPERM) } else { r }
            }
            __NR_GETSID => syscall::getsid(msg.data[0]),

            // Signal stubs (real delegation requires kernel support).
            __NR_RT_SIGACTION => 0,    // Pretend success.
            __NR_RT_SIGPROCMASK => 0,  // Pretend success.
            __NR_RT_SIGRETURN => 0,
            __NR_TGKILL => 0,         // Ignore for now.

            // Stubs that return success (0) to avoid crashing callers.
            __NR_SET_ROBUST_LIST | __NR_RSEQ => 0,
            __NR_PRLIMIT64 => 0,
            __NR_MADVISE => 0,
            __NR_SCHED_GETAFFINITY => linux_err(ENOSYS),
            __NR_GETRLIMIT | __NR_GETRUSAGE => 0,
            __NR_FTRUNCATE => 0,
            __NR_STATX => linux_err(ENOSYS),

            // epoll stubs — return ENOSYS until real implementation.
            __NR_EPOLL_CREATE | __NR_EPOLL_CREATE1 => linux_err(ENOSYS),
            __NR_EPOLL_CTL => linux_err(ENOSYS),
            __NR_EPOLL_WAIT | __NR_EPOLL_PWAIT => linux_err(ENOSYS),

            __NR_MEMFD_CREATE => linux_err(ENOSYS),
            __NR_CLONE3 => linux_err(ENOSYS),

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
