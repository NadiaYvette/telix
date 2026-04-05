#![no_std]
#![no_main]

//! Linux personality server.
//!
//! Receives forwarded Linux syscalls from the kernel's personality routing
//! layer and translates them into Telix-native operations.
//!
//! Message format (from kernel/src/syscall/personality.rs):
//!   tag     = (syscall_nr & 0xFFFFFFFF) | (caller_port << 32)
//!   data[0..5] = arg0..arg5 (all 6 syscall arguments)

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
const __NR_UMASK: u64 = 95;
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
const __NR_FACCESSAT: u64 = 269;
const __NR_READLINKAT: u64 = 267;
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
const __NR_SOCKET: u64 = 41;
const __NR_CONNECT: u64 = 42;
const __NR_ACCEPT: u64 = 43;
const __NR_SENDTO: u64 = 44;
const __NR_RECVFROM: u64 = 45;
const __NR_SENDMSG: u64 = 46;
const __NR_RECVMSG: u64 = 47;
const __NR_SHUTDOWN: u64 = 48;
const __NR_BIND: u64 = 49;
const __NR_LISTEN: u64 = 50;
const __NR_GETSOCKNAME: u64 = 51;
const __NR_GETPEERNAME: u64 = 52;
const __NR_SOCKETPAIR: u64 = 53;
const __NR_SETSOCKOPT: u64 = 54;
const __NR_GETSOCKOPT: u64 = 55;
const __NR_ACCEPT4: u64 = 288;
const __NR_TIMERFD_CREATE: u64 = 283;
const __NR_TIMERFD_SETTIME: u64 = 286;
const __NR_TIMERFD_GETTIME: u64 = 287;
const __NR_EVENTFD2: u64 = 290;
const __NR_MEMFD_CREATE: u64 = 319;
const __NR_LSTAT: u64 = 6;
const __NR_PREAD64: u64 = 17;
const __NR_PWRITE64: u64 = 18;
const __NR_READV: u64 = 19;
const __NR_FCHMOD: u64 = 91;
const __NR_FCHOWN: u64 = 93;
const __NR_SIGALTSTACK: u64 = 131;
const __NR_FCHOWNAT: u64 = 260;
const __NR_FCHMODAT: u64 = 268;
const __NR_MREMAP: u64 = 25;
const __NR_KILL: u64 = 62;
const __NR_RENAME: u64 = 82;
const __NR_FLOCK: u64 = 73;
const __NR_TRUNCATE: u64 = 76;
const __NR_RENAMEAT: u64 = 264;
const __NR_RENAMEAT2: u64 = 316;
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
const ENOTSOCK: u64 = 88;
const EAFNOSUPPORT: u64 = 97;
const ENOTCONN: u64 = 107;
const ESRCH: u64 = 3;
const ECONNREFUSED: u64 = 111;
const EOPNOTSUPP: u64 = 95;

// Socket address families
const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;

// Socket types
const SOCK_STREAM: u64 = 1;
const _SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0x800;
const SOCK_CLOEXEC: u64 = 0x80000;

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
const PIPE_POLL_TAG: u64 = 0x5050;
const PIPE_OK: u64 = 0x5100;
const PIPE_EOF_TAG: u64 = 0x51FF;

// UDS server protocol tags
const UDS_SOCKET: u64 = 0x8000;
const UDS_BIND: u64 = 0x8010;
const UDS_LISTEN: u64 = 0x8020;
const UDS_CONNECT: u64 = 0x8030;
const UDS_ACCEPT: u64 = 0x8040;
const UDS_SEND: u64 = 0x8050;
const UDS_RECV: u64 = 0x8060;
const UDS_CLOSE: u64 = 0x8070;
const UDS_GETPEERCRED: u64 = 0x8080;
const UDS_POLL_TAG: u64 = 0x8090;
const UDS_GETPEER: u64 = 0x80A0;
const UDS_OK: u64 = 0x8100;
const UDS_EOF: u64 = 0x81FF;
const _UDS_ERROR: u64 = 0x8F00;

// NET server TCP protocol tags
const NET_TCP_CONNECT: u64 = 0x4200;
const NET_TCP_CONNECTED: u64 = 0x4201;
const NET_TCP_SEND: u64 = 0x4300;
const NET_TCP_SEND_OK: u64 = 0x4301;
const NET_TCP_RECV: u64 = 0x4400;
const NET_TCP_DATA: u64 = 0x4401;
const NET_TCP_RECV_NB: u64 = 0x4410;
const NET_TCP_RECV_NONE: u64 = 0x4412;
const NET_TCP_CLOSED: u64 = 0x44FF;
const NET_TCP_CLOSE: u64 = 0x4500;
const NET_TCP_BIND: u64 = 0x4600;
const NET_TCP_LISTEN: u64 = 0x4700;
const NET_TCP_LISTEN_OK: u64 = 0x4701;
const NET_TCP_ACCEPT: u64 = 0x4710;
const NET_TCP_ACCEPT_OK: u64 = 0x4711;

// Epoll constants
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const _EPOLL_CLOEXEC: u64 = 0x80000;

const MAX_FDS: usize = 64;
const MAX_PROCS: usize = 32;
const MAX_EPOLL_INSTANCES: usize = 16;
const MAX_EPOLL_WATCHES: usize = 16;

#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    None,
    File,
    Pipe,
    Dir,
    Socket,
    Epoll,
    EventFd,
    TimerFd,
    MemFd,
}

#[derive(Clone, Copy)]
struct FdEntry {
    in_use: bool,
    kind: FdKind,
    // File: fs_port = FS server port, handle = FS handle
    // Pipe: fs_port = pipe_srv port, handle = pipe handle
    // Socket: fs_port = uds_srv/net_srv port, handle = server handle/conn_id
    // Dir: dir_path/dir_path_len store the absolute path for VFS_READDIR
    fs_port: u64,
    handle: u64,
    file_size: u64,
    offset: u64,
    dir_path: [u8; 16],
    dir_path_len: u8,
    fd_flags: u32,    // FD_CLOEXEC etc.
    status_flags: u32, // O_NONBLOCK etc.
    // Socket-specific metadata:
    sock_domain: u8,  // AF_UNIX=1, AF_INET=2
    sock_type: u8,    // SOCK_STREAM=1, SOCK_DGRAM=2
    sock_state: u8,   // 0=created, 1=bound, 2=listening, 3=connected
    sock_port: u16,   // AF_INET: port number
    sock_ip: u32,     // AF_INET: IP (network byte order)
}

impl FdEntry {
    const fn empty() -> Self {
        Self { in_use: false, kind: FdKind::None, fs_port: 0, handle: 0, file_size: 0, offset: 0, dir_path: [0; 16], dir_path_len: 0, fd_flags: 0, status_flags: 0, sock_domain: 0, sock_type: 0, sock_state: 0, sock_port: 0, sock_ip: 0 }
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
    umask: u32,
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
            umask: 0,
        }
    }
}

static mut PROC_TABLE: [ProcessState; MAX_PROCS] = [const { ProcessState::empty() }; MAX_PROCS];
static mut VFS_PORT: u64 = 0;
static mut REPLY_PORT: u64 = 0;
static mut PIPE_PORT: u64 = 0;
static mut UDS_PORT: u64 = 0;
static mut NET_PORT: u64 = 0;
static mut SOCKETPAIR_SEQ: u32 = 0;

// Epoll subsystem
#[derive(Clone, Copy)]
struct EpollWatch {
    active: bool,
    fd: u8,
    events: u32,
    data: u64,
}

impl EpollWatch {
    const fn empty() -> Self { Self { active: false, fd: 0, events: 0, data: 0 } }
}

#[derive(Clone, Copy)]
struct EpollInstance {
    active: bool,
    owner_port: u64,
    watches: [EpollWatch; MAX_EPOLL_WATCHES],
}

impl EpollInstance {
    const fn empty() -> Self {
        Self { active: false, owner_port: 0, watches: [const { EpollWatch::empty() }; MAX_EPOLL_WATCHES] }
    }
}

static mut EPOLL_TABLE: [EpollInstance; MAX_EPOLL_INSTANCES] = [const { EpollInstance::empty() }; MAX_EPOLL_INSTANCES];

// EventFd / TimerFd subsystem
const MAX_EVENT_INSTANCES: usize = 32;
const EFD_SEMAPHORE: u32 = 1;

#[derive(Clone, Copy)]
struct EventFdSlot {
    active: bool,
    counter: u64,
    flags: u32,  // EFD_SEMAPHORE etc.
}

impl EventFdSlot {
    const fn empty() -> Self { Self { active: false, counter: 0, flags: 0 } }
}

#[derive(Clone, Copy)]
struct TimerFdSlot {
    active: bool,
    interval_ns: u64,
    next_expiry_ns: u64,
    expirations: u64,
}

impl TimerFdSlot {
    const fn empty() -> Self { Self { active: false, interval_ns: 0, next_expiry_ns: 0, expirations: 0 } }
}

static mut EVENTFD_TABLE: [EventFdSlot; MAX_EVENT_INSTANCES] = [const { EventFdSlot::empty() }; MAX_EVENT_INSTANCES];
static mut TIMERFD_TABLE: [TimerFdSlot; MAX_EVENT_INSTANCES] = [const { TimerFdSlot::empty() }; MAX_EVENT_INSTANCES];

// MemFd subsystem
const MAX_MEMFD_INSTANCES: usize = 16;

#[derive(Clone, Copy)]
struct MemFdSlot {
    active: bool,
    va: usize,        // backing memory VA (0 = not allocated)
    capacity: usize,  // allocated bytes (page-aligned)
    size: usize,      // logical file size
}

impl MemFdSlot {
    const fn empty() -> Self { Self { active: false, va: 0, capacity: 0, size: 0 } }
}

static mut MEMFD_TABLE: [MemFdSlot; MAX_MEMFD_INSTANCES] = [const { MemFdSlot::empty() }; MAX_MEMFD_INSTANCES];

// SCM_RIGHTS: pending FD transfers over UDS
const MAX_PENDING_FD_TRANSFERS: usize = 16;
const MAX_FDS_PER_TRANSFER: usize = 4;
const SOL_SOCKET: u32 = 1;
const SCM_RIGHTS: u32 = 1;

#[derive(Clone, Copy)]
struct PendingFdTransfer {
    active: bool,
    receiver_uds_handle: u64,
    fd_count: usize,
    entries: [FdEntry; MAX_FDS_PER_TRANSFER],
}

impl PendingFdTransfer {
    const fn empty() -> Self {
        Self { active: false, receiver_uds_handle: 0, fd_count: 0, entries: [const { FdEntry::empty() }; MAX_FDS_PER_TRANSFER] }
    }
}

static mut PENDING_FD_TRANSFERS: [PendingFdTransfer; MAX_PENDING_FD_TRANSFERS] = [const { PendingFdTransfer::empty() }; MAX_PENDING_FD_TRANSFERS];

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
                PROC_TABLE[i].umask = 0o022;
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
        if PROC_TABLE[pi].fds[fd_idx].kind == FdKind::Socket {
            let dom = PROC_TABLE[pi].fds[fd_idx].sock_domain;
            return write_socket(caller_port, PROC_TABLE[pi].fds[fd_idx].fs_port,
                                PROC_TABLE[pi].fds[fd_idx].handle, dom, buf_va, count);
        }
        if PROC_TABLE[pi].fds[fd_idx].kind == FdKind::EventFd {
            if count < 8 { return linux_err(EINVAL); }
            let idx = PROC_TABLE[pi].fds[fd_idx].handle as usize;
            if idx >= MAX_EVENT_INSTANCES || !EVENTFD_TABLE[idx].active {
                return linux_err(EBADF);
            }
            let mut tmp = [0u8; 8];
            let copied = syscall::personality_copy_in(caller_port, buf_va, &mut tmp);
            if copied < 8 { return linux_err(EFAULT); }
            let val = u64::from_le_bytes(tmp);
            EVENTFD_TABLE[idx].counter = EVENTFD_TABLE[idx].counter.saturating_add(val);
            return 8;
        }
        if PROC_TABLE[pi].fds[fd_idx].kind == FdKind::MemFd {
            let idx = PROC_TABLE[pi].fds[fd_idx].handle as usize;
            if idx >= MAX_MEMFD_INSTANCES || !MEMFD_TABLE[idx].active {
                return linux_err(EBADF);
            }
            let off = PROC_TABLE[pi].fds[fd_idx].offset as usize;
            let needed = off + count;
            // Grow backing memory if needed.
            if needed > MEMFD_TABLE[idx].capacity {
                let ps = syscall::page_size();
                let new_pages = (needed + ps - 1) / ps;
                let new_cap = new_pages * ps;
                match syscall::mmap_anon(0, new_pages, 1 /* RW */) {
                    Some(new_va) => {
                        // Copy old data if any.
                        if MEMFD_TABLE[idx].va != 0 && MEMFD_TABLE[idx].size > 0 {
                            let old_ptr = MEMFD_TABLE[idx].va as *const u8;
                            let new_ptr = new_va as *mut u8;
                            core::ptr::copy_nonoverlapping(old_ptr, new_ptr, MEMFD_TABLE[idx].size);
                            syscall::munmap(MEMFD_TABLE[idx].va);
                        }
                        MEMFD_TABLE[idx].va = new_va;
                        MEMFD_TABLE[idx].capacity = new_cap;
                    }
                    None => return linux_err(ENOMEM),
                }
            }
            // Copy from caller to our buffer.
            let base = MEMFD_TABLE[idx].va;
            let mut total = 0usize;
            while total < count {
                let chunk = (count - total).min(512);
                let dst = core::slice::from_raw_parts_mut((base + off + total) as *mut u8, chunk);
                let copied = syscall::personality_copy_in(caller_port, buf_va + total, dst);
                if copied == 0 { break; }
                total += copied;
            }
            let new_end = off + total;
            if new_end > MEMFD_TABLE[idx].size {
                MEMFD_TABLE[idx].size = new_end;
                PROC_TABLE[pi].fds[fd_idx].file_size = new_end as u64;
            }
            PROC_TABLE[pi].fds[fd_idx].offset = new_end as u64;
            return total as u64;
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

    if kind == FdKind::Socket {
        let dom = unsafe { PROC_TABLE[pi].fds[fd].sock_domain };
        return read_socket(caller_port, fs_port, handle, dom, buf_va, count);
    }

    if kind == FdKind::EventFd {
        if count < 8 { return linux_err(EINVAL); }
        let idx = handle as usize;
        unsafe {
            if idx >= MAX_EVENT_INSTANCES || !EVENTFD_TABLE[idx].active {
                return linux_err(EBADF);
            }
            if EVENTFD_TABLE[idx].counter == 0 {
                return linux_err(EAGAIN);
            }
            let val = if EVENTFD_TABLE[idx].flags & EFD_SEMAPHORE != 0 {
                EVENTFD_TABLE[idx].counter -= 1;
                1u64
            } else {
                let v = EVENTFD_TABLE[idx].counter;
                EVENTFD_TABLE[idx].counter = 0;
                v
            };
            let bytes = val.to_le_bytes();
            syscall::personality_copy_out(caller_port, buf_va, &bytes);
        }
        return 8;
    }

    if kind == FdKind::TimerFd {
        if count < 8 { return linux_err(EINVAL); }
        let idx = handle as usize;
        unsafe {
            if idx >= MAX_EVENT_INSTANCES || !TIMERFD_TABLE[idx].active {
                return linux_err(EBADF);
            }
            check_timerfd_expiry(idx);
            if TIMERFD_TABLE[idx].expirations == 0 {
                return linux_err(EAGAIN);
            }
            let exp = TIMERFD_TABLE[idx].expirations;
            TIMERFD_TABLE[idx].expirations = 0;
            let bytes = exp.to_le_bytes();
            syscall::personality_copy_out(caller_port, buf_va, &bytes);
        }
        return 8;
    }

    if kind == FdKind::MemFd {
        let idx = handle as usize;
        unsafe {
            if idx >= MAX_MEMFD_INSTANCES || !MEMFD_TABLE[idx].active {
                return linux_err(EBADF);
            }
            let sz = MEMFD_TABLE[idx].size;
            if offset as usize >= sz {
                return 0; // EOF
            }
            let avail = sz - offset as usize;
            let want = count.min(avail);
            if MEMFD_TABLE[idx].va == 0 || want == 0 {
                return 0;
            }
            // Copy from our buffer to caller's address space in chunks.
            let base = MEMFD_TABLE[idx].va;
            let mut total = 0usize;
            while total < want {
                let chunk = (want - total).min(512);
                let src = core::slice::from_raw_parts((base + offset as usize + total) as *const u8, chunk);
                let written = syscall::personality_copy_out(caller_port, buf_va + total, src);
                if written == 0 { break; }
                total += written;
            }
            PROC_TABLE[pi].fds[fd].offset += total as u64;
            return total as u64;
        }
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

/// Handle Linux pread64(fd, buf, count, offset).
/// Like read() but uses caller-supplied offset and does NOT update the fd offset.
fn handle_pread64(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let buf_va = args[1] as usize;
    let count = args[2] as usize;
    let offset = args[3];

    if buf_va == 0 || count == 0 { return 0; }
    if fd >= MAX_FDS { return linux_err(EBADF); }

    let (kind, fs_port, handle, file_size) = unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use { return linux_err(EBADF); }
        (PROC_TABLE[pi].fds[fd].kind, PROC_TABLE[pi].fds[fd].fs_port,
         PROC_TABLE[pi].fds[fd].handle, PROC_TABLE[pi].fds[fd].file_size)
    };

    // pread64 is not valid on pipes, sockets, eventfds, timerfds.
    match kind {
        FdKind::Pipe | FdKind::Socket | FdKind::EventFd | FdKind::TimerFd | FdKind::Epoll => {
            return linux_err(ESPIPE);
        }
        _ => {}
    }

    if kind == FdKind::MemFd {
        let idx = handle as usize;
        unsafe {
            if idx >= MAX_MEMFD_INSTANCES || !MEMFD_TABLE[idx].active {
                return linux_err(EBADF);
            }
            let sz = MEMFD_TABLE[idx].size;
            if offset as usize >= sz { return 0; }
            let avail = sz - offset as usize;
            let want = count.min(avail);
            if MEMFD_TABLE[idx].va == 0 || want == 0 { return 0; }
            let base = MEMFD_TABLE[idx].va;
            let mut total = 0usize;
            while total < want {
                let chunk = (want - total).min(512);
                let src = core::slice::from_raw_parts((base + offset as usize + total) as *const u8, chunk);
                let written = syscall::personality_copy_out(caller_port, buf_va + total, src);
                if written == 0 { break; }
                total += written;
            }
            // Do NOT update fd offset.
            return total as u64;
        }
    }

    // Regular file via FS server.
    if offset >= file_size { return 0; }
    let reply_port = unsafe { REPLY_PORT };
    let remaining = (file_size - offset) as usize;
    let want = count.min(remaining);
    let mut total = 0usize;

    while total < want {
        let chunk = (want - total).min(16);
        let d2 = (chunk as u64) | ((reply_port) << 32);
        syscall::send(fs_port, FS_READ, handle, offset + total as u64, d2, 0);
        let resp = match syscall::recv_msg(reply_port) {
            Some(m) => m,
            None => break,
        };
        if resp.tag != FS_READ_OK { break; }
        let got = (resp.data[0] & 0xFFFF) as usize;
        if got == 0 { break; }
        let mut tmp = [0u8; 16];
        let b1 = resp.data[1].to_le_bytes();
        let b2 = resp.data[2].to_le_bytes();
        tmp[..8].copy_from_slice(&b1);
        tmp[8..16].copy_from_slice(&b2);
        let to_write = got.min(chunk);
        let written = syscall::personality_copy_out(caller_port, buf_va + total, &tmp[..to_write]);
        if written == 0 { return if total > 0 { total as u64 } else { linux_err(EFAULT) }; }
        total += to_write;
        // Do NOT update fd offset.
        if got < chunk { break; }
    }
    total as u64
}

/// Handle Linux pwrite64(fd, buf, count, offset).
/// Like write() but uses caller-supplied offset and does NOT update the fd offset.
fn handle_pwrite64(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd_idx = args[0] as usize;
    let buf_va = args[1] as usize;
    let count = args[2] as usize;
    let offset = args[3] as usize;

    if buf_va == 0 || count == 0 { return 0; }
    if fd_idx >= MAX_FDS { return linux_err(EBADF); }

    unsafe {
        if !PROC_TABLE[pi].fds[fd_idx].in_use { return linux_err(EBADF); }
        let kind = PROC_TABLE[pi].fds[fd_idx].kind;

        match kind {
            FdKind::Pipe | FdKind::Socket | FdKind::EventFd | FdKind::TimerFd | FdKind::Epoll => {
                return linux_err(ESPIPE);
            }
            _ => {}
        }

        if kind == FdKind::MemFd {
            let idx = PROC_TABLE[pi].fds[fd_idx].handle as usize;
            if idx >= MAX_MEMFD_INSTANCES || !MEMFD_TABLE[idx].active {
                return linux_err(EBADF);
            }
            let needed = offset + count;
            if needed > MEMFD_TABLE[idx].capacity {
                let ps = syscall::page_size();
                let new_pages = (needed + ps - 1) / ps;
                let new_cap = new_pages * ps;
                match syscall::mmap_anon(0, new_pages, 1) {
                    Some(new_va) => {
                        if MEMFD_TABLE[idx].va != 0 && MEMFD_TABLE[idx].size > 0 {
                            let old_ptr = MEMFD_TABLE[idx].va as *const u8;
                            let new_ptr = new_va as *mut u8;
                            core::ptr::copy_nonoverlapping(old_ptr, new_ptr, MEMFD_TABLE[idx].size);
                            syscall::munmap(MEMFD_TABLE[idx].va);
                        }
                        MEMFD_TABLE[idx].va = new_va;
                        MEMFD_TABLE[idx].capacity = new_cap;
                    }
                    None => return linux_err(ENOMEM),
                }
            }
            let base = MEMFD_TABLE[idx].va;
            let mut total = 0usize;
            while total < count {
                let chunk = (count - total).min(512);
                let dst = core::slice::from_raw_parts_mut((base + offset + total) as *mut u8, chunk);
                let copied = syscall::personality_copy_in(caller_port, buf_va + total, dst);
                if copied == 0 { break; }
                total += copied;
            }
            let new_end = offset + total;
            if new_end > MEMFD_TABLE[idx].size {
                MEMFD_TABLE[idx].size = new_end;
                PROC_TABLE[pi].fds[fd_idx].file_size = new_end as u64;
            }
            // Do NOT update fd offset.
            return total as u64;
        }

        // Regular file write via FS: not supported yet.
        linux_err(EBADF)
    }
}

/// Handle Linux readv(fd, iov, iovcnt).
fn handle_readv(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0];
    let iov_va = args[1] as usize;
    let iovcnt = args[2] as usize;

    if iovcnt == 0 { return 0; }
    if iov_va == 0 || iovcnt > 1024 { return linux_err(EINVAL); }

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
        if len == 0 { continue; }
        if base == 0 { return if total > 0 { total } else { linux_err(EFAULT) }; }

        let read_args: [u64; 6] = [fd, base, len, 0, 0, 0];
        let r = handle_read(pi, caller_port, &read_args);
        if (r as i64) < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
        if r < len { break; } // Short read — don't continue to next iovec.
    }
    total
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
            FdKind::Socket => {
                let rp = syscall::port_create();
                let dom = PROC_TABLE[pi].fds[fd].sock_domain;
                if dom == AF_UNIX as u8 {
                    let d2 = (rp as u64) << 32;
                    syscall::send(PROC_TABLE[pi].fds[fd].fs_port, UDS_CLOSE, PROC_TABLE[pi].fds[fd].handle, 0, d2, 0);
                    let _ = syscall::recv_msg(rp);
                } else if dom == AF_INET as u8 && PROC_TABLE[pi].fds[fd].handle != u64::MAX {
                    syscall::send(PROC_TABLE[pi].fds[fd].fs_port, NET_TCP_CLOSE, PROC_TABLE[pi].fds[fd].handle, rp, 0, 0);
                    let _ = syscall::recv_msg(rp);
                }
                syscall::port_destroy(rp);
            }
            FdKind::Dir => {} // No server handle to close.
            FdKind::Epoll => {
                let idx = PROC_TABLE[pi].fds[fd].handle as usize;
                if idx < MAX_EPOLL_INSTANCES {
                    EPOLL_TABLE[idx] = EpollInstance::empty();
                }
            }
            FdKind::EventFd => {
                let idx = PROC_TABLE[pi].fds[fd].handle as usize;
                if idx < MAX_EVENT_INSTANCES {
                    EVENTFD_TABLE[idx] = EventFdSlot::empty();
                }
            }
            FdKind::TimerFd => {
                let idx = PROC_TABLE[pi].fds[fd].handle as usize;
                if idx < MAX_EVENT_INSTANCES {
                    TIMERFD_TABLE[idx] = TimerFdSlot::empty();
                }
            }
            FdKind::MemFd => {
                let idx = PROC_TABLE[pi].fds[fd].handle as usize;
                if idx < MAX_MEMFD_INSTANCES {
                    if MEMFD_TABLE[idx].va != 0 {
                        syscall::munmap(MEMFD_TABLE[idx].va);
                    }
                    MEMFD_TABLE[idx] = MemFdSlot::empty();
                }
            }
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
        if matches!(PROC_TABLE[pi].fds[fd].kind, FdKind::Pipe | FdKind::Socket | FdKind::Epoll | FdKind::EventFd | FdKind::TimerFd) {
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

/// Handle Linux sched_getaffinity(pid, cpusetsize, mask).
/// Returns a single-CPU affinity mask (CPU 0 only).
fn handle_sched_getaffinity(caller_port: u64, args: &[u64; 6]) -> u64 {
    let _pid = args[0]; // 0 = current
    let cpusetsize = args[1] as usize;
    let mask_va = args[2] as usize;

    if mask_va == 0 { return linux_err(EFAULT); }
    if cpusetsize == 0 { return linux_err(EINVAL); }

    // Fill mask with CPU 0 set (byte 0 = 0x01, rest = 0x00).
    let size = cpusetsize.min(128); // cap at 1024 CPUs
    let mut mask = [0u8; 128];
    mask[0] = 1; // CPU 0
    let written = syscall::personality_copy_out(caller_port, mask_va, &mask[..size]);
    if written < size { return linux_err(EFAULT); }
    size as u64 // returns number of bytes written
}

/// Build a struct statx (256 bytes) from mode, ino, size and write to caller.
fn fill_statx(caller_port: u64, statxbuf_va: usize, mode: u32, ino: u64, file_size: u64) -> u64 {
    let mut sx = [0u8; 256];
    sx[0..4].copy_from_slice(&0x07FFu32.to_le_bytes()); // stx_mask: STATX_BASIC_STATS
    sx[4..8].copy_from_slice(&4096u32.to_le_bytes());    // stx_blksize
    sx[16..20].copy_from_slice(&1u32.to_le_bytes());     // stx_nlink
    sx[28..30].copy_from_slice(&(mode as u16).to_le_bytes()); // stx_mode
    sx[32..40].copy_from_slice(&ino.to_le_bytes());      // stx_ino
    sx[40..48].copy_from_slice(&file_size.to_le_bytes()); // stx_size
    let blocks = (file_size + 511) / 512;
    sx[48..56].copy_from_slice(&blocks.to_le_bytes());   // stx_blocks
    let written = syscall::personality_copy_out(caller_port, statxbuf_va, &sx);
    if written < 256 { return linux_err(EFAULT); }
    0
}

/// Handle Linux statx(dirfd, pathname, flags, mask, statxbuf).
fn handle_statx(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let dirfd = args[0] as i64;
    let path_va = args[1] as usize;
    let flags = args[2];
    let _mask = args[3];
    let statxbuf_va = args[4] as usize;

    if statxbuf_va == 0 { return linux_err(EFAULT); }

    const AT_EMPTY_PATH: u64 = 0x1000;

    // AT_EMPTY_PATH with fd: glibc's fstat() calls statx(fd, "", AT_EMPTY_PATH, ...).
    if (flags & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
        let fd = dirfd as usize;
        if fd < 3 {
            return fill_statx(caller_port, statxbuf_va, 0o020666, 0, 0);
        }
        if fd >= MAX_FDS { return linux_err(EBADF); }
        unsafe {
            if !PROC_TABLE[pi].fds[fd].in_use { return linux_err(EBADF); }
            let kind = PROC_TABLE[pi].fds[fd].kind;
            let file_size = PROC_TABLE[pi].fds[fd].file_size;
            let mode = match kind {
                FdKind::Pipe => 0o010600u32,
                FdKind::Socket => 0o140777u32,
                _ => 0o100644u32,
            };
            return fill_statx(caller_port, statxbuf_va, mode, 0, file_size);
        }
    }

    // Path-based statx: resolve path, query VFS.
    let vfs_port = unsafe { VFS_PORT };
    if vfs_port == 0 { return linux_err(ENOSYS); }

    let (path, pathlen) = resolve_path(pi, caller_port, path_va);
    if pathlen == 0 { return linux_err(EFAULT); }

    // Root "/" — VFS doesn't respond to stat on root, handle it directly.
    if pathlen == 1 && path[0] == b'/' {
        return fill_statx(caller_port, statxbuf_va, 0o040755, 2, 4096);
    }

    let (w0, w1, plen) = pack_path_vfs(&path, pathlen);
    let reply_port = unsafe { REPLY_PORT };
    let d2 = plen | (reply_port << 32);
    syscall::send(vfs_port, VFS_STAT, w0, w1, d2, 0);

    let resp = match syscall::recv_msg(reply_port) {
        Some(m) => m,
        None => return linux_err(ENOENT),
    };
    if resp.tag == VFS_ERROR || resp.tag != VFS_STAT_OK {
        return linux_err(ENOENT);
    }

    fill_statx(caller_port, statxbuf_va, resp.data[1] as u32, resp.data[3], resp.data[0])
}

// Linux resource limit constants
const RLIMIT_CPU: u64 = 0;
const RLIMIT_FSIZE: u64 = 1;
const RLIMIT_DATA: u64 = 2;
const RLIMIT_STACK: u64 = 3;
const RLIMIT_CORE: u64 = 4;
const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_AS: u64 = 9;
const RLIMIT_NPROC: u64 = 6;
const RLIM_INFINITY: u64 = u64::MAX;

/// Handle Linux prlimit64(pid, resource, new_rlim, old_rlim).
/// Returns sensible defaults for common resource limits.
fn handle_prlimit64(caller_port: u64, args: &[u64; 6]) -> u64 {
    let _pid = args[0]; // 0 = current (only supported value)
    let resource = args[1];
    let _new_rlim_va = args[2] as usize; // ignored (read-only)
    let old_rlim_va = args[3] as usize;

    // struct rlimit { rlim_cur: u64, rlim_max: u64 } = 16 bytes
    let (cur, max) = match resource {
        RLIMIT_NOFILE => (1024u64, 4096u64),
        RLIMIT_STACK => (8 * 1024 * 1024, RLIM_INFINITY), // 8 MB default
        RLIMIT_AS | RLIMIT_DATA | RLIMIT_FSIZE => (RLIM_INFINITY, RLIM_INFINITY),
        RLIMIT_CORE => (0, RLIM_INFINITY),
        RLIMIT_CPU => (RLIM_INFINITY, RLIM_INFINITY),
        RLIMIT_NPROC => (4096, 4096),
        _ => (RLIM_INFINITY, RLIM_INFINITY),
    };

    if old_rlim_va != 0 {
        let mut rlim = [0u8; 16];
        rlim[0..8].copy_from_slice(&cur.to_le_bytes());
        rlim[8..16].copy_from_slice(&max.to_le_bytes());
        let written = syscall::personality_copy_out(caller_port, old_rlim_va, &rlim);
        if written < 16 { return linux_err(EFAULT); }
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

/// Handle Linux umask(mask).
fn handle_umask(pi: usize, args: &[u64; 6]) -> u64 {
    let new_mask = (args[0] & 0o777) as u32;
    let old = unsafe { PROC_TABLE[pi].umask };
    unsafe { PROC_TABLE[pi].umask = new_mask; }
    old as u64
}

/// Handle Linux access(path, mode) — existence check via VFS_STAT.
fn handle_access(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let path_va = args[0] as usize;

    let vfs_port = unsafe { VFS_PORT };
    let reply_port = unsafe { REPLY_PORT };
    if vfs_port == 0 {
        return linux_err(ENOSYS);
    }

    let (path, pathlen) = resolve_path(pi, caller_port, path_va);
    if pathlen == 0 {
        return linux_err(EFAULT);
    }

    // Root "/" and other well-known dirs always exist — skip VFS round-trip.
    if pathlen == 1 && path[0] == b'/' {
        return 0;
    }

    let (w0, w1, plen) = pack_path_vfs(&path, pathlen);
    let d2 = plen | ((reply_port) << 32);
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

/// Handle Linux faccessat(dirfd, path, mode, flags).
fn handle_faccessat(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let dirfd = args[0] as i64;
    const AT_FDCWD: i64 = -100;
    if dirfd != AT_FDCWD && dirfd >= 0 {
        return linux_err(ENOSYS);
    }
    // Shift args so path is in [0], mode in [1].
    let shifted: [u64; 6] = [args[1], args[2], args[3], 0, 0, 0];
    handle_access(pi, caller_port, &shifted)
}

/// Handle Linux readlinkat(dirfd, path, buf, bufsiz).
fn handle_readlinkat(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let dirfd = args[0] as i64;
    let path_va = args[1] as usize;
    let buf_va = args[2] as usize;
    let bufsiz = args[3] as usize;
    const AT_FDCWD: i64 = -100;

    if dirfd != AT_FDCWD && dirfd >= 0 {
        return linux_err(ENOSYS);
    }
    if bufsiz == 0 {
        return linux_err(EINVAL);
    }

    // Read the path from caller.
    let mut raw = [0u8; 64];
    let copied = syscall::personality_copy_in(caller_port, path_va, &mut raw);
    if copied == 0 {
        return linux_err(EFAULT);
    }
    let raw_len = raw[..copied].iter().position(|&b| b == 0).unwrap_or(copied);

    // Check for /proc/self/exe
    let proc_self_exe = b"/proc/self/exe";
    if raw_len == proc_self_exe.len() && raw[..raw_len] == proc_self_exe[..] {
        let result = b"/bin/unknown";
        let out_len = result.len().min(bufsiz);
        syscall::personality_copy_out(caller_port, buf_va, &result[..out_len]);
        return out_len as u64;
    }

    // Check for /proc/self/fd/N
    let proc_self_fd = b"/proc/self/fd/";
    if raw_len > proc_self_fd.len() && raw[..proc_self_fd.len()] == proc_self_fd[..] {
        // Parse FD number.
        let mut fd_num: usize = 0;
        for i in proc_self_fd.len()..raw_len {
            let c = raw[i];
            if c < b'0' || c > b'9' {
                return linux_err(EINVAL);
            }
            fd_num = fd_num * 10 + (c - b'0') as usize;
        }
        if fd_num >= MAX_FDS {
            return linux_err(EBADF);
        }
        let entry = unsafe { &PROC_TABLE[pi].fds[fd_num] };
        if !entry.in_use {
            return linux_err(EBADF);
        }
        // Return a synthetic path based on FD kind.
        let result: &[u8] = match entry.kind {
            FdKind::Pipe => b"/dev/pipe",
            FdKind::Socket => b"/dev/socket",
            _ => b"/dev/fd",
        };
        let out_len = result.len().min(bufsiz);
        syscall::personality_copy_out(caller_port, buf_va, &result[..out_len]);
        return out_len as u64;
    }

    linux_err(EINVAL)
}

/// Handle Linux readlink(path, buf, bufsiz).
fn handle_readlink(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    const AT_FDCWD_U64: u64 = (-100i64) as u64;
    let shifted: [u64; 6] = [AT_FDCWD_U64, args[0], args[1], args[2], 0, 0];
    handle_readlinkat(pi, caller_port, &shifted)
}

/// Handle Linux kill(pid, sig).
fn handle_kill(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let pid = args[0] as i64;
    let sig = args[1] as u32;

    if sig == 0 {
        // Signal 0: check if process exists.
        if pid > 0 {
            // Check if we have a proc entry for this pid/port.
            let found = unsafe {
                let mut f = false;
                for i in 0..MAX_PROCS {
                    if PROC_TABLE[i].active && PROC_TABLE[i].port == pid as u64 {
                        f = true;
                        break;
                    }
                }
                f
            };
            return if found { 0 } else { linux_err(ESRCH) };
        }
        return 0; // Signal 0 to self or group — always succeeds.
    }

    if pid > 0 {
        // Send signal to specific process.
        if syscall::kill_sig(pid as u64, sig) { 0 } else { linux_err(ESRCH) }
    } else if pid == 0 {
        // Send to caller's process group.
        let pgid = syscall::getpgid(0);
        if pgid == 0 || pgid == u64::MAX {
            // No group, send to self.
            syscall::kill_sig(caller_port, sig);
            0
        } else {
            if syscall::kill_pgroup(pgid, sig) { 0 } else { linux_err(ESRCH) }
        }
    } else if pid == -1 {
        // Send to all processes — not supported, just send to self.
        syscall::kill_sig(caller_port, sig);
        0
    } else {
        // pid < -1: send to process group -pid.
        let pgid = (-pid) as u64;
        if syscall::kill_pgroup(pgid, sig) { 0 } else { linux_err(ESRCH) }
    }
}

/// Handle Linux tgkill(tgid, tid, sig).
fn handle_tgkill(caller_port: u64, args: &[u64; 6]) -> u64 {
    let _tgid = args[0];
    let tid = args[1];
    let sig = args[2] as u32;
    if sig == 0 { return 0; }
    // Map tid to port — in Telix, tid IS the port for personality tasks.
    if syscall::kill_sig(tid, sig) { 0 } else { linux_err(ESRCH) }
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
fn handle_brk(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let addr = args[0] as usize;

    unsafe {
        if PROC_TABLE[pi].brk_base == 0 {
            PROC_TABLE[pi].brk_base = 0x10_0000_0000;
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
                    if syscall::personality_mmap_anon(caller_port, alloc_start as u64, count as u64, 3).is_none() {
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

fn handle_getid(nr: u64, caller_port: u64) -> u64 {
    match nr {
        __NR_GETPID | __NR_GETTID => caller_port, // return *client's* port, not linux_srv's
        __NR_GETUID => syscall::getuid() as u64,
        __NR_GETEUID => syscall::geteuid() as u64,
        __NR_GETGID => syscall::getgid() as u64,
        __NR_GETEGID => syscall::getegid() as u64,
        _ => 0,
    }
}

// =============================================================================
// Phase 129: Socket syscall handlers
// =============================================================================

/// Read from a socket FD (UDS or TCP).
fn read_socket(caller_port: u64, srv_port: u64, handle: u64, domain: u8, buf_va: usize, count: usize) -> u64 {
    if domain == AF_UNIX as u8 {
        let rp = syscall::port_create();
        let d2 = (rp as u64) << 32;
        syscall::send(srv_port, UDS_RECV, handle, 0, d2, 0);
        let resp = match syscall::recv_msg(rp) {
            Some(m) => m,
            None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
        };
        syscall::port_destroy(rp);
        if resp.tag == UDS_EOF { return 0; }
        if resp.tag != UDS_OK { return linux_err(ECONNREFUSED); }
        let len = (resp.data[2] & 0xFFFF) as usize;
        let got = len.min(count);
        if got == 0 { return 0; }
        let mut tmp = [0u8; 16];
        let b0 = resp.data[0].to_le_bytes();
        let b1 = resp.data[1].to_le_bytes();
        tmp[..8].copy_from_slice(&b0);
        tmp[8..16].copy_from_slice(&b1);
        let written = syscall::personality_copy_out(caller_port, buf_va, &tmp[..got]);
        written as u64
    } else if domain == AF_INET as u8 {
        if handle == u64::MAX { return linux_err(ENOTCONN); }
        let rp = syscall::port_create();
        let d1 = (rp as u64) << 16;
        syscall::send(srv_port, NET_TCP_RECV, handle, d1, 0, 0);
        let resp = match syscall::recv_msg(rp) {
            Some(m) => m,
            None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
        };
        syscall::port_destroy(rp);
        if resp.tag == NET_TCP_CLOSED { return 0; }
        if resp.tag != NET_TCP_DATA { return linux_err(ECONNREFUSED); }
        let len = (resp.data[0] & 0xFFFF) as usize;
        let got = len.min(count);
        if got == 0 { return 0; }
        // TCP data in d1/d2/d3 (up to 24 bytes)
        let mut tmp = [0u8; 24];
        let b1 = resp.data[1].to_le_bytes();
        let b2 = resp.data[2].to_le_bytes();
        let b3 = resp.data[3].to_le_bytes();
        tmp[..8].copy_from_slice(&b1);
        tmp[8..16].copy_from_slice(&b2);
        tmp[16..24].copy_from_slice(&b3);
        let written = syscall::personality_copy_out(caller_port, buf_va, &tmp[..got]);
        written as u64
    } else {
        linux_err(EAFNOSUPPORT)
    }
}

/// Write to a socket FD (UDS or TCP).
fn write_socket(caller_port: u64, srv_port: u64, handle: u64, domain: u8, buf_va: usize, count: usize) -> u64 {
    let mut total = 0usize;
    if domain == AF_UNIX as u8 {
        while total < count {
            let chunk = (count - total).min(16);
            let mut tmp = [0u8; 16];
            let copied = syscall::personality_copy_in(caller_port, buf_va + total, &mut tmp[..chunk]);
            if copied == 0 { break; }
            let w0 = u64::from_le_bytes([tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]]);
            let w1 = u64::from_le_bytes([tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15]]);
            let rp = syscall::port_create();
            let d2 = (copied as u64) | ((rp as u64) << 32);
            syscall::send(srv_port, UDS_SEND, handle, w0, d2, w1);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); break; }
            };
            syscall::port_destroy(rp);
            if resp.tag != UDS_OK { break; }
            let sent = (resp.data[0] & 0xFFFF) as usize;
            total += sent;
            if sent == 0 { break; }
        }
    } else if domain == AF_INET as u8 {
        if handle == u64::MAX { return linux_err(ENOTCONN); }
        while total < count {
            let chunk = (count - total).min(16);
            let mut tmp = [0u8; 16];
            let copied = syscall::personality_copy_in(caller_port, buf_va + total, &mut tmp[..chunk]);
            if copied == 0 { break; }
            let w0 = u64::from_le_bytes([tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]]);
            let w1 = u64::from_le_bytes([tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15]]);
            let rp = syscall::port_create();
            let d1 = (copied as u64) | ((rp as u64) << 16);
            syscall::send(srv_port, NET_TCP_SEND, handle, d1, w0, w1);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); break; }
            };
            syscall::port_destroy(rp);
            if resp.tag != NET_TCP_SEND_OK { break; }
            total += copied;
        }
    } else {
        return linux_err(EAFNOSUPPORT);
    }
    if total == 0 && count > 0 { linux_err(EFAULT) } else { total as u64 }
}

/// Handle Linux socket(domain, type, protocol).
fn handle_socket(pi: usize, _caller_port: u64, args: &[u64; 6]) -> u64 {
    let domain = args[0];
    let type_raw = args[1];
    let _protocol = args[2];

    let base_type = type_raw & 0xF;
    let flags = type_raw & !0xF;

    if base_type != SOCK_STREAM {
        return linux_err(EOPNOTSUPP);
    }

    let fd = match alloc_fd(pi) {
        Some(f) => f,
        None => return linux_err(EMFILE),
    };

    if domain == AF_UNIX {
        let uds_port = unsafe { UDS_PORT };
        if uds_port == 0 { unsafe { PROC_TABLE[pi].fds[fd] = FdEntry::empty(); } return linux_err(EAFNOSUPPORT); }
        // Create UDS socket via uds_srv.
        let rp = syscall::port_create();
        let d2 = (rp as u64) << 32;
        syscall::send(uds_port, UDS_SOCKET, 0, 0, d2, 0);
        let resp = match syscall::recv_msg(rp) {
            Some(m) => m,
            None => { syscall::port_destroy(rp); unsafe { PROC_TABLE[pi].fds[fd] = FdEntry::empty(); } return linux_err(EAFNOSUPPORT); }
        };
        syscall::port_destroy(rp);
        if resp.tag != UDS_OK {
            unsafe { PROC_TABLE[pi].fds[fd] = FdEntry::empty(); }
            return linux_err(ENOMEM);
        }
        let handle = resp.data[0];
        unsafe {
            PROC_TABLE[pi].fds[fd].kind = FdKind::Socket;
            PROC_TABLE[pi].fds[fd].fs_port = uds_port;
            PROC_TABLE[pi].fds[fd].handle = handle;
            PROC_TABLE[pi].fds[fd].sock_domain = AF_UNIX as u8;
            PROC_TABLE[pi].fds[fd].sock_type = base_type as u8;
            PROC_TABLE[pi].fds[fd].sock_state = 0;
        }
    } else if domain == AF_INET {
        let net_port = unsafe { NET_PORT };
        if net_port == 0 { unsafe { PROC_TABLE[pi].fds[fd] = FdEntry::empty(); } return linux_err(EAFNOSUPPORT); }
        // AF_INET: no IPC yet — handle allocated on connect/accept.
        unsafe {
            PROC_TABLE[pi].fds[fd].kind = FdKind::Socket;
            PROC_TABLE[pi].fds[fd].fs_port = net_port;
            PROC_TABLE[pi].fds[fd].handle = u64::MAX; // placeholder
            PROC_TABLE[pi].fds[fd].sock_domain = AF_INET as u8;
            PROC_TABLE[pi].fds[fd].sock_type = base_type as u8;
            PROC_TABLE[pi].fds[fd].sock_state = 0;
        }
    } else {
        unsafe { PROC_TABLE[pi].fds[fd] = FdEntry::empty(); }
        return linux_err(EAFNOSUPPORT);
    }

    // Apply SOCK_NONBLOCK / SOCK_CLOEXEC flags.
    unsafe {
        if flags & SOCK_NONBLOCK != 0 {
            PROC_TABLE[pi].fds[fd].status_flags |= O_NONBLOCK as u32;
        }
        if flags & SOCK_CLOEXEC != 0 {
            PROC_TABLE[pi].fds[fd].fd_flags |= FD_CLOEXEC;
        }
    }

    fd as u64
}

/// Parse a Linux sockaddr_un from caller memory. Returns (name, name_len).
fn parse_sockaddr_un(caller_port: u64, addr_va: usize, addrlen: usize) -> ([u8; 16], usize) {
    let mut buf = [0u8; 110]; // sa_family(2) + sun_path(108)
    let to_read = addrlen.min(110);
    let copied = syscall::personality_copy_in(caller_port, addr_va, &mut buf[..to_read]);
    if copied < 3 {
        return ([0; 16], 0);
    }
    // sun_path starts at offset 2
    let path_len = (copied - 2).min(16);
    let mut name = [0u8; 16];
    for i in 0..path_len {
        name[i] = buf[2 + i];
    }
    (name, path_len)
}

/// Parse a Linux sockaddr_in from caller memory. Returns (ip_be32, port_be16).
fn parse_sockaddr_in(caller_port: u64, addr_va: usize, addrlen: usize) -> (u32, u16) {
    let mut buf = [0u8; 16]; // sockaddr_in is 16 bytes
    let to_read = addrlen.min(16);
    let copied = syscall::personality_copy_in(caller_port, addr_va, &mut buf[..to_read]);
    if copied < 8 {
        return (0, 0);
    }
    // sin_port at offset 2 (big-endian u16)
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    // sin_addr at offset 4 (big-endian u32)
    let ip = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    (ip, port)
}

/// Pack a name into UDS IPC format words (d0=name[0..8], d3=name[8..16]).
fn pack_uds_name(name: &[u8; 16], len: usize) -> (u64, u64) {
    let mut w0 = [0u8; 8];
    let mut w1 = [0u8; 8];
    for i in 0..len.min(8) { w0[i] = name[i]; }
    for i in 8..len.min(16) { w1[i - 8] = name[i]; }
    (u64::from_le_bytes(w0), u64::from_le_bytes(w1))
}

/// Handle Linux bind(fd, addr, addrlen).
fn handle_bind(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let addr_va = args[1] as usize;
    let addrlen = args[2] as usize;

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        if dom == AF_UNIX as u8 {
            let (name, nlen) = parse_sockaddr_un(caller_port, addr_va, addrlen);
            if nlen == 0 { return linux_err(EINVAL); }
            let (w0, w1) = pack_uds_name(&name, nlen);
            let rp = syscall::port_create();
            let d2 = (nlen as u64) | ((rp as u64) << 32);
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, UDS_BIND, PROC_TABLE[pi].fds[fd].handle, w0, d2, w1);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag != UDS_OK { return linux_err(EINVAL); }
            PROC_TABLE[pi].fds[fd].sock_state = 1;
            0
        } else if dom == AF_INET as u8 {
            let (ip, port) = parse_sockaddr_in(caller_port, addr_va, addrlen);
            let _ = ip; // net_srv bind only cares about port
            let rp = syscall::port_create();
            let d1 = (rp as u64) << 32;
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, NET_TCP_BIND, port as u64, d1, 0, 0);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag == 0x4601 { // NET_TCP_BIND_OK
                PROC_TABLE[pi].fds[fd].sock_port = port;
                PROC_TABLE[pi].fds[fd].sock_ip = ip;
                PROC_TABLE[pi].fds[fd].sock_state = 1;
                0
            } else {
                linux_err(EINVAL)
            }
        } else {
            linux_err(EAFNOSUPPORT)
        }
    }
}

/// Handle Linux listen(fd, backlog).
fn handle_listen(pi: usize, _caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let backlog = args[1];

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        if dom == AF_UNIX as u8 {
            let rp = syscall::port_create();
            let d2 = (rp as u64) << 32;
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, UDS_LISTEN, PROC_TABLE[pi].fds[fd].handle, backlog, d2, 0);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag != UDS_OK { return linux_err(EINVAL); }
            PROC_TABLE[pi].fds[fd].sock_state = 2;
            0
        } else if dom == AF_INET as u8 {
            let port = PROC_TABLE[pi].fds[fd].sock_port;
            let rp = syscall::port_create();
            let d2 = (rp as u64) << 32;
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, NET_TCP_LISTEN, port as u64, backlog, d2, 0);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag != NET_TCP_LISTEN_OK { return linux_err(EINVAL); }
            PROC_TABLE[pi].fds[fd].sock_state = 2;
            0
        } else {
            linux_err(EAFNOSUPPORT)
        }
    }
}

/// Handle Linux connect(fd, addr, addrlen).
fn handle_connect(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let addr_va = args[1] as usize;
    let addrlen = args[2] as usize;

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        if dom == AF_UNIX as u8 {
            let (name, nlen) = parse_sockaddr_un(caller_port, addr_va, addrlen);
            if nlen == 0 { return linux_err(EINVAL); }
            let (w0, w1) = pack_uds_name(&name, nlen);
            let rp = syscall::port_create();
            let d2 = (nlen as u64) | ((rp as u64) << 32);
            let pid = syscall::getpid();
            let uid = syscall::getuid() as u64;
            let d3 = pid | (uid << 32);
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, UDS_CONNECT, w0, w1, d2, d3);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag != UDS_OK { return linux_err(ECONNREFUSED); }
            // UDS_CONNECT reply: data[0] = client-end handle
            PROC_TABLE[pi].fds[fd].handle = resp.data[0];
            PROC_TABLE[pi].fds[fd].sock_state = 3;
            0
        } else if dom == AF_INET as u8 {
            let (ip, port) = parse_sockaddr_in(caller_port, addr_va, addrlen);
            let rp = syscall::port_create();
            let d1 = (port as u64) | ((rp as u64) << 16);
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, NET_TCP_CONNECT, ip as u64, d1, 0, 0);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag != NET_TCP_CONNECTED { return linux_err(ECONNREFUSED); }
            PROC_TABLE[pi].fds[fd].handle = resp.data[0]; // conn_id
            PROC_TABLE[pi].fds[fd].sock_port = port;
            PROC_TABLE[pi].fds[fd].sock_ip = ip;
            PROC_TABLE[pi].fds[fd].sock_state = 3;
            0
        } else {
            linux_err(EAFNOSUPPORT)
        }
    }
}

/// Handle Linux accept(fd, addr, addrlen) / accept4(fd, addr, addrlen, flags).
fn handle_accept_inner(pi: usize, caller_port: u64, args: &[u64; 6], flags: u64) -> u64 {
    let fd = args[0] as usize;
    let _addr_va = args[1] as usize;
    let _addrlen_va = args[2] as usize;

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        if PROC_TABLE[pi].fds[fd].sock_state != 2 { return linux_err(EINVAL); }

        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        let new_fd = match alloc_fd(pi) {
            Some(f) => f,
            None => return linux_err(EMFILE),
        };

        if dom == AF_UNIX as u8 {
            let rp = syscall::port_create();
            let d2 = (rp as u64) << 32;
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, UDS_ACCEPT, PROC_TABLE[pi].fds[fd].handle, 0, d2, 0);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); PROC_TABLE[pi].fds[new_fd] = FdEntry::empty(); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag != UDS_OK {
                PROC_TABLE[pi].fds[new_fd] = FdEntry::empty();
                return linux_err(ECONNREFUSED);
            }
            PROC_TABLE[pi].fds[new_fd].kind = FdKind::Socket;
            PROC_TABLE[pi].fds[new_fd].fs_port = PROC_TABLE[pi].fds[fd].fs_port;
            PROC_TABLE[pi].fds[new_fd].handle = resp.data[0]; // accepted handle
            PROC_TABLE[pi].fds[new_fd].sock_domain = AF_UNIX as u8;
            PROC_TABLE[pi].fds[new_fd].sock_type = SOCK_STREAM as u8;
            PROC_TABLE[pi].fds[new_fd].sock_state = 3;
        } else if dom == AF_INET as u8 {
            let port = PROC_TABLE[pi].fds[fd].sock_port;
            let rp = syscall::port_create();
            let d1 = (rp as u64) << 32;
            syscall::send(PROC_TABLE[pi].fds[fd].fs_port, NET_TCP_ACCEPT, port as u64, d1, 0, 0);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); PROC_TABLE[pi].fds[new_fd] = FdEntry::empty(); return linux_err(ECONNREFUSED); }
            };
            syscall::port_destroy(rp);
            if resp.tag != NET_TCP_ACCEPT_OK {
                PROC_TABLE[pi].fds[new_fd] = FdEntry::empty();
                return linux_err(ECONNREFUSED);
            }
            PROC_TABLE[pi].fds[new_fd].kind = FdKind::Socket;
            PROC_TABLE[pi].fds[new_fd].fs_port = PROC_TABLE[pi].fds[fd].fs_port;
            PROC_TABLE[pi].fds[new_fd].handle = resp.data[0]; // conn_id
            PROC_TABLE[pi].fds[new_fd].sock_domain = AF_INET as u8;
            PROC_TABLE[pi].fds[new_fd].sock_type = SOCK_STREAM as u8;
            PROC_TABLE[pi].fds[new_fd].sock_state = 3;
        } else {
            PROC_TABLE[pi].fds[new_fd] = FdEntry::empty();
            return linux_err(EAFNOSUPPORT);
        }

        // Apply accept4 flags.
        if flags & SOCK_NONBLOCK != 0 {
            PROC_TABLE[pi].fds[new_fd].status_flags |= O_NONBLOCK as u32;
        }
        if flags & SOCK_CLOEXEC != 0 {
            PROC_TABLE[pi].fds[new_fd].fd_flags |= FD_CLOEXEC;
        }

        // TODO: write sockaddr back to caller if addr_va != 0

        new_fd as u64
    }
}

/// Handle Linux sendto(fd, buf, len, flags, dest_addr, addrlen).
fn handle_sendto(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let buf_va = args[1] as usize;
    let count = args[2] as usize;
    // args[3] = flags (ignored), args[4]/args[5] = dest_addr/addrlen (ignored for STREAM)

    if fd >= MAX_FDS { return linux_err(EBADF); }
    if buf_va == 0 || count == 0 { return 0; }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        write_socket(caller_port, PROC_TABLE[pi].fds[fd].fs_port, PROC_TABLE[pi].fds[fd].handle, dom, buf_va, count)
    }
}

/// Handle Linux recvfrom(fd, buf, len, flags, src_addr, addrlen).
fn handle_recvfrom(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let buf_va = args[1] as usize;
    let count = args[2] as usize;
    // args[3] = flags, args[4]/args[5] = src_addr/addrlen (ignored for STREAM)

    if fd >= MAX_FDS { return linux_err(EBADF); }
    if buf_va == 0 || count == 0 { return 0; }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        read_socket(caller_port, PROC_TABLE[pi].fds[fd].fs_port, PROC_TABLE[pi].fds[fd].handle, dom, buf_va, count)
    }
}

/// Handle Linux sendmsg(fd, msg, flags).
/// Reads msghdr from caller, gathers iovecs, sends via write_socket.
/// Supports SCM_RIGHTS ancillary data for passing FDs over AF_UNIX sockets.
fn handle_sendmsg(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let msghdr_va = args[1] as usize;
    // args[2] = flags (ignored)

    if fd >= MAX_FDS { return linux_err(EBADF); }
    if msghdr_va == 0 { return linux_err(EFAULT); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }

        // Read msghdr (56 bytes on x86_64): msg_name(8), msg_namelen(8 padded),
        // msg_iov(8), msg_iovlen(8), msg_control(8), msg_controllen(8), msg_flags(4+pad)
        let mut hdr = [0u8; 56];
        let n = syscall::personality_copy_in(caller_port, msghdr_va, &mut hdr);
        if n < 48 { return linux_err(EFAULT); }

        let iov_ptr = u64::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19],
                                           hdr[20], hdr[21], hdr[22], hdr[23]]) as usize;
        let iov_len = u64::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27],
                                           hdr[28], hdr[29], hdr[30], hdr[31]]) as usize;

        // Parse SCM_RIGHTS ancillary data if present.
        let msg_control = u64::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35],
                                               hdr[36], hdr[37], hdr[38], hdr[39]]) as usize;
        let msg_controllen = u64::from_le_bytes([hdr[40], hdr[41], hdr[42], hdr[43],
                                                  hdr[44], hdr[45], hdr[46], hdr[47]]) as usize;

        if msg_control != 0 && msg_controllen >= 20
            && PROC_TABLE[pi].fds[fd].sock_domain == AF_UNIX as u8
        {
            // Read cmsg header: cmsg_len(8) + cmsg_level(4) + cmsg_type(4) = 16 bytes
            let mut cmsg_hdr = [0u8; 16];
            let ch = syscall::personality_copy_in(caller_port, msg_control, &mut cmsg_hdr);
            if ch >= 16 {
                let cmsg_len = u64::from_le_bytes([cmsg_hdr[0], cmsg_hdr[1], cmsg_hdr[2], cmsg_hdr[3],
                                                    cmsg_hdr[4], cmsg_hdr[5], cmsg_hdr[6], cmsg_hdr[7]]) as usize;
                let cmsg_level = u32::from_le_bytes([cmsg_hdr[8], cmsg_hdr[9], cmsg_hdr[10], cmsg_hdr[11]]);
                let cmsg_type = u32::from_le_bytes([cmsg_hdr[12], cmsg_hdr[13], cmsg_hdr[14], cmsg_hdr[15]]);

                if cmsg_level == SOL_SOCKET && cmsg_type == SCM_RIGHTS && cmsg_len > 16 {
                    let payload_len = cmsg_len - 16;
                    let fd_count = payload_len / 4;
                    let fd_count = if fd_count > MAX_FDS_PER_TRANSFER { MAX_FDS_PER_TRANSFER } else { fd_count };

                    if fd_count > 0 {
                        // Read FD array from cmsg data (int32[])
                        let mut fd_buf = [0u8; 16]; // max 4 FDs * 4 bytes
                        let fb = syscall::personality_copy_in(caller_port, msg_control + 16, &mut fd_buf[..fd_count * 4]);
                        if fb >= fd_count * 4 {
                            // Validate FDs and copy entries
                            let mut entries = [FdEntry::empty(); MAX_FDS_PER_TRANSFER];
                            let mut valid = true;
                            for i in 0..fd_count {
                                let src_fd = u32::from_le_bytes([fd_buf[i*4], fd_buf[i*4+1], fd_buf[i*4+2], fd_buf[i*4+3]]) as usize;
                                if src_fd >= MAX_FDS || !PROC_TABLE[pi].fds[src_fd].in_use {
                                    valid = false;
                                    break;
                                }
                                entries[i] = PROC_TABLE[pi].fds[src_fd];
                            }

                            if valid {
                                // Query UDS_GETPEER to find receiver's handle
                                let sender_handle = PROC_TABLE[pi].fds[fd].handle;
                                let uds_port = PROC_TABLE[pi].fds[fd].fs_port;
                                let rp = syscall::port_create();
                                let d2 = (rp as u64) << 32;
                                syscall::send(uds_port, UDS_GETPEER, sender_handle, 0, d2, 0);
                                if let Some(resp) = syscall::recv_msg(rp) {
                                    syscall::port_destroy(rp);
                                    if resp.tag == UDS_OK {
                                        let peer_handle = resp.data[0];
                                        // Find free transfer slot
                                        for s in 0..MAX_PENDING_FD_TRANSFERS {
                                            if !PENDING_FD_TRANSFERS[s].active {
                                                PENDING_FD_TRANSFERS[s].active = true;
                                                PENDING_FD_TRANSFERS[s].receiver_uds_handle = peer_handle;
                                                PENDING_FD_TRANSFERS[s].fd_count = fd_count;
                                                PENDING_FD_TRANSFERS[s].entries = entries;
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    syscall::port_destroy(rp);
                                }
                            }
                        }
                    }
                }
            }
        }

        if iov_ptr == 0 || iov_len == 0 { return 0; }

        // Fast path: single iovec — delegate directly to write_socket
        if iov_len == 1 {
            let mut iov_buf = [0u8; 16];
            let ic = syscall::personality_copy_in(caller_port, iov_ptr, &mut iov_buf);
            if ic < 16 { return linux_err(EFAULT); }
            let base = u64::from_le_bytes([iov_buf[0], iov_buf[1], iov_buf[2], iov_buf[3],
                                            iov_buf[4], iov_buf[5], iov_buf[6], iov_buf[7]]) as usize;
            let len = u64::from_le_bytes([iov_buf[8], iov_buf[9], iov_buf[10], iov_buf[11],
                                           iov_buf[12], iov_buf[13], iov_buf[14], iov_buf[15]]) as usize;
            if base == 0 || len == 0 { return 0; }
            let dom = PROC_TABLE[pi].fds[fd].sock_domain;
            return write_socket(caller_port, PROC_TABLE[pi].fds[fd].fs_port,
                                PROC_TABLE[pi].fds[fd].handle, dom, base, len);
        }

        // Multi-iovec: gather into temporary buffer (max 4096 bytes)
        let max_iovs = if iov_len > 8 { 8 } else { iov_len };
        let mut gather_buf = [0u8; 4096];
        let mut total = 0usize;

        for i in 0..max_iovs {
            let mut iov_buf = [0u8; 16];
            let ic = syscall::personality_copy_in(caller_port, iov_ptr + i * 16, &mut iov_buf);
            if ic < 16 { break; }
            let base = u64::from_le_bytes([iov_buf[0], iov_buf[1], iov_buf[2], iov_buf[3],
                                            iov_buf[4], iov_buf[5], iov_buf[6], iov_buf[7]]) as usize;
            let len = u64::from_le_bytes([iov_buf[8], iov_buf[9], iov_buf[10], iov_buf[11],
                                           iov_buf[12], iov_buf[13], iov_buf[14], iov_buf[15]]) as usize;
            if base == 0 || len == 0 { continue; }
            let avail = 4096 - total;
            let chunk = if len < avail { len } else { avail };
            if chunk == 0 { break; }
            let copied = syscall::personality_copy_in(caller_port, base, &mut gather_buf[total..total + chunk]);
            total += copied;
            if copied < chunk { break; }
        }

        if total == 0 { return 0; }

        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        let srv_port = PROC_TABLE[pi].fds[fd].fs_port;
        let handle = PROC_TABLE[pi].fds[fd].handle;
        send_socket_data(srv_port, handle, dom, &gather_buf[..total])
    }
}

/// Deliver pending SCM_RIGHTS FDs to a recvmsg caller.
/// Checks PENDING_FD_TRANSFERS for the given UDS handle, installs FDs in
/// receiver's process, writes cmsg to caller's msg_control buffer.
/// If no pending FDs, zeroes msg_controllen.
unsafe fn deliver_scm_rights(pi: usize, caller_port: u64, msghdr_va: usize,
                              hdr: &[u8; 56], my_uds_handle: u64, is_af_unix: bool) {
    let msg_control = u64::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35],
                                           hdr[36], hdr[37], hdr[38], hdr[39]]) as usize;
    let msg_controllen = u64::from_le_bytes([hdr[40], hdr[41], hdr[42], hdr[43],
                                              hdr[44], hdr[45], hdr[46], hdr[47]]) as usize;

    // Look for pending FD transfers for this socket
    if is_af_unix && msg_control != 0 && msg_controllen >= 20 {
        for s in 0..MAX_PENDING_FD_TRANSFERS {
            if PENDING_FD_TRANSFERS[s].active
                && PENDING_FD_TRANSFERS[s].receiver_uds_handle == my_uds_handle
            {
                let fd_count = PENDING_FD_TRANSFERS[s].fd_count;
                let cmsg_len = 16 + fd_count * 4;
                // CMSG_SPACE: align to 8 bytes
                let cmsg_space = (cmsg_len + 7) & !7;

                if msg_controllen >= cmsg_space {
                    // Allocate FDs in receiver's process and build cmsg
                    let mut new_fds = [0i32; MAX_FDS_PER_TRANSFER];
                    let mut ok = true;
                    for i in 0..fd_count {
                        match alloc_fd(pi) {
                            Some(nfd) => {
                                PROC_TABLE[pi].fds[nfd] = PENDING_FD_TRANSFERS[s].entries[i];
                                new_fds[i] = nfd as i32;
                            }
                            None => { ok = false; break; }
                        }
                    }

                    if ok {
                        // Build cmsg: cmsghdr (16 bytes) + int32[] FDs
                        let mut cmsg = [0u8; 32]; // max 16 + 4*4 = 32
                        let len_bytes = (cmsg_len as u64).to_le_bytes();
                        cmsg[0..8].copy_from_slice(&len_bytes);
                        let level_bytes = SOL_SOCKET.to_le_bytes();
                        cmsg[8..12].copy_from_slice(&level_bytes);
                        let type_bytes = SCM_RIGHTS.to_le_bytes();
                        cmsg[12..16].copy_from_slice(&type_bytes);
                        for i in 0..fd_count {
                            let fb = new_fds[i].to_le_bytes();
                            cmsg[16 + i*4..16 + i*4 + 4].copy_from_slice(&fb);
                        }
                        syscall::personality_copy_out(caller_port, msg_control, &cmsg[..cmsg_space]);

                        // Update msg_controllen to actual size
                        let clen_bytes = (cmsg_space as u64).to_le_bytes();
                        syscall::personality_copy_out(caller_port, msghdr_va + 40, &clen_bytes);

                        PENDING_FD_TRANSFERS[s].active = false;
                        return;
                    }
                    // If alloc_fd failed, free any we already allocated
                    for i in 0..fd_count {
                        if new_fds[i] > 0 {
                            PROC_TABLE[pi].fds[new_fds[i] as usize] = FdEntry::empty();
                        }
                    }
                }

                // Couldn't deliver — mark consumed anyway to avoid stale entries
                PENDING_FD_TRANSFERS[s].active = false;
                break;
            }
        }
    }

    // No pending FDs or not AF_UNIX: zero msg_controllen
    let zero8 = [0u8; 8];
    syscall::personality_copy_out(caller_port, msghdr_va + 40, &zero8);
}

/// Handle Linux recvmsg(fd, msg, flags).
/// Receives data, scatters into iovecs described by msghdr.
/// Delivers SCM_RIGHTS ancillary data if pending.
fn handle_recvmsg(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let msghdr_va = args[1] as usize;
    // args[2] = flags (ignored)

    if fd >= MAX_FDS { return linux_err(EBADF); }
    if msghdr_va == 0 { return linux_err(EFAULT); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }

        // Read msghdr
        let mut hdr = [0u8; 56];
        let n = syscall::personality_copy_in(caller_port, msghdr_va, &mut hdr);
        if n < 48 { return linux_err(EFAULT); }

        let iov_ptr = u64::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19],
                                           hdr[20], hdr[21], hdr[22], hdr[23]]) as usize;
        let iov_len = u64::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27],
                                           hdr[28], hdr[29], hdr[30], hdr[31]]) as usize;

        if iov_ptr == 0 || iov_len == 0 { return 0; }

        let my_handle = PROC_TABLE[pi].fds[fd].handle;
        let is_af_unix = PROC_TABLE[pi].fds[fd].sock_domain == AF_UNIX as u8;

        // Calculate total iovec capacity
        let max_iovs = if iov_len > 8 { 8 } else { iov_len };
        let mut iov_bases = [0usize; 8];
        let mut iov_lens = [0usize; 8];
        let mut total_cap = 0usize;

        for i in 0..max_iovs {
            let mut iov_buf = [0u8; 16];
            let ic = syscall::personality_copy_in(caller_port, iov_ptr + i * 16, &mut iov_buf);
            if ic < 16 { break; }
            iov_bases[i] = u64::from_le_bytes([iov_buf[0], iov_buf[1], iov_buf[2], iov_buf[3],
                                                iov_buf[4], iov_buf[5], iov_buf[6], iov_buf[7]]) as usize;
            iov_lens[i] = u64::from_le_bytes([iov_buf[8], iov_buf[9], iov_buf[10], iov_buf[11],
                                               iov_buf[12], iov_buf[13], iov_buf[14], iov_buf[15]]) as usize;
            total_cap += iov_lens[i];
        }

        if total_cap == 0 { return 0; }

        // Fast path: single iovec — delegate directly to read_socket
        if max_iovs == 1 || (max_iovs > 1 && iov_lens[1] == 0) {
            if iov_bases[0] == 0 || iov_lens[0] == 0 { return 0; }
            let dom = PROC_TABLE[pi].fds[fd].sock_domain;
            let result = read_socket(caller_port, PROC_TABLE[pi].fds[fd].fs_port,
                                     PROC_TABLE[pi].fds[fd].handle, dom, iov_bases[0], iov_lens[0]);
            deliver_scm_rights(pi, caller_port, msghdr_va, &hdr, my_handle, is_af_unix);
            return result;
        }

        // Multi-iovec: receive into local buffer, then scatter
        let recv_cap = if total_cap > 4096 { 4096 } else { total_cap };
        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        let srv_port = PROC_TABLE[pi].fds[fd].fs_port;
        let handle = PROC_TABLE[pi].fds[fd].handle;
        let mut recv_buf = [0u8; 4096];
        let got = recv_socket_data(srv_port, handle, dom, &mut recv_buf[..recv_cap]);
        if got == 0 || (got as i64) < 0 { return got; }
        let got = got as usize;

        // Scatter into iovecs
        let mut offset = 0usize;
        for i in 0..max_iovs {
            if offset >= got { break; }
            if iov_bases[i] == 0 || iov_lens[i] == 0 { continue; }
            let chunk = if got - offset < iov_lens[i] { got - offset } else { iov_lens[i] };
            syscall::personality_copy_out(caller_port, iov_bases[i], &recv_buf[offset..offset + chunk]);
            offset += chunk;
        }

        deliver_scm_rights(pi, caller_port, msghdr_va, &hdr, my_handle, is_af_unix);

        got as u64
    }
}

/// Send data from a local buffer to a socket (bypassing caller VA).
/// Uses the same inline IPC protocol as write_socket but from local memory.
fn send_socket_data(srv_port: u64, handle: u64, domain: u8, data: &[u8]) -> u64 {
    let mut total = 0usize;
    if domain == AF_UNIX as u8 {
        while total < data.len() {
            let chunk = (data.len() - total).min(16);
            let mut tmp = [0u8; 16];
            tmp[..chunk].copy_from_slice(&data[total..total + chunk]);
            let w0 = u64::from_le_bytes([tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]]);
            let w1 = u64::from_le_bytes([tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15]]);
            let rp = syscall::port_create();
            let d2 = (chunk as u64) | ((rp as u64) << 32);
            syscall::send(srv_port, UDS_SEND, handle, w0, d2, w1);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); break; }
            };
            syscall::port_destroy(rp);
            if resp.tag != UDS_OK { break; }
            let sent = (resp.data[0] & 0xFFFF) as usize;
            total += sent;
            if sent == 0 { break; }
        }
    } else if domain == AF_INET as u8 {
        while total < data.len() {
            let chunk = (data.len() - total).min(16);
            let mut tmp = [0u8; 16];
            tmp[..chunk].copy_from_slice(&data[total..total + chunk]);
            let w0 = u64::from_le_bytes([tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]]);
            let w1 = u64::from_le_bytes([tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15]]);
            let rp = syscall::port_create();
            let d1 = (chunk as u64) | ((rp as u64) << 16);
            syscall::send(srv_port, NET_TCP_SEND, handle, d1, w0, w1);
            let resp = match syscall::recv_msg(rp) {
                Some(m) => m,
                None => { syscall::port_destroy(rp); break; }
            };
            syscall::port_destroy(rp);
            if resp.tag != NET_TCP_SEND_OK { break; }
            total += chunk;
        }
    } else {
        return linux_err(EAFNOSUPPORT);
    }
    if total == 0 && data.len() > 0 { linux_err(EFAULT) } else { total as u64 }
}

/// Receive data from a socket into a local buffer (bypassing caller VA).
/// Uses the same inline IPC protocol as read_socket but to local memory.
fn recv_socket_data(srv_port: u64, handle: u64, domain: u8, buf: &mut [u8]) -> u64 {
    if domain == AF_UNIX as u8 {
        let rp = syscall::port_create();
        let d2 = (rp as u64) << 32;
        syscall::send(srv_port, UDS_RECV, handle, 0, d2, 0);
        let resp = match syscall::recv_msg(rp) {
            Some(m) => m,
            None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
        };
        syscall::port_destroy(rp);
        if resp.tag == UDS_EOF { return 0; }
        if resp.tag != UDS_OK { return linux_err(ECONNREFUSED); }
        let len = (resp.data[2] & 0xFFFF) as usize;
        let got = len.min(buf.len());
        if got == 0 { return 0; }
        let mut tmp = [0u8; 16];
        let b0 = resp.data[0].to_le_bytes();
        let b1 = resp.data[1].to_le_bytes();
        tmp[..8].copy_from_slice(&b0);
        tmp[8..16].copy_from_slice(&b1);
        buf[..got].copy_from_slice(&tmp[..got]);
        got as u64
    } else if domain == AF_INET as u8 {
        let rp = syscall::port_create();
        let d1 = (rp as u64) << 16;
        syscall::send(srv_port, NET_TCP_RECV, handle, d1, 0, 0);
        let resp = match syscall::recv_msg(rp) {
            Some(m) => m,
            None => { syscall::port_destroy(rp); return linux_err(ECONNREFUSED); }
        };
        syscall::port_destroy(rp);
        if resp.tag == NET_TCP_CLOSED { return 0; }
        if resp.tag != NET_TCP_DATA { return linux_err(ECONNREFUSED); }
        let len = (resp.data[0] & 0xFFFF) as usize;
        let got = len.min(buf.len());
        if got == 0 { return 0; }
        let mut tmp = [0u8; 24];
        let b1 = resp.data[1].to_le_bytes();
        let b2 = resp.data[2].to_le_bytes();
        let b3 = resp.data[3].to_le_bytes();
        tmp[..8].copy_from_slice(&b1);
        tmp[8..16].copy_from_slice(&b2);
        tmp[16..24].copy_from_slice(&b3);
        buf[..got].copy_from_slice(&tmp[..got]);
        got as u64
    } else {
        linux_err(EAFNOSUPPORT)
    }
}

/// Handle Linux socketpair(domain, type, protocol, sv[2]).
/// Creates two connected AF_UNIX sockets via bind/listen/connect/accept on a synthetic name.
fn handle_socketpair(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let domain = args[0];
    let type_raw = args[1];
    let _protocol = args[2];
    let sv_va = args[3] as usize; // note: socketpair arg3 is r10 = sv

    if domain != AF_UNIX { return linux_err(EOPNOTSUPP); }
    let base_type = type_raw & 0xF;
    if base_type != SOCK_STREAM { return linux_err(EOPNOTSUPP); }

    let uds_port = unsafe { UDS_PORT };
    if uds_port == 0 { return linux_err(EAFNOSUPPORT); }

    // Allocate two FDs.
    let fd0 = match alloc_fd(pi) {
        Some(f) => f,
        None => return linux_err(EMFILE),
    };
    let fd1 = match alloc_fd(pi) {
        Some(f) => f,
        None => { unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); } return linux_err(EMFILE); }
    };

    // Create two UDS sockets.
    let rp = syscall::port_create();
    let d2 = (rp as u64) << 32;

    // Socket A (will be server side).
    syscall::send(uds_port, UDS_SOCKET, 0, 0, d2, 0);
    let resp_a = match syscall::recv_msg(rp) {
        Some(m) if m.tag == UDS_OK => m,
        _ => { syscall::port_destroy(rp); unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); } return linux_err(ENOMEM); }
    };
    let handle_a = resp_a.data[0];

    // Socket B (will be client side).
    syscall::send(uds_port, UDS_SOCKET, 0, 0, d2, 0);
    let resp_b = match syscall::recv_msg(rp) {
        Some(m) if m.tag == UDS_OK => m,
        _ => { syscall::port_destroy(rp); unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); } return linux_err(ENOMEM); }
    };
    let _handle_b = resp_b.data[0];

    // Generate unique synthetic name for binding.
    let seq = unsafe { SOCKETPAIR_SEQ += 1; SOCKETPAIR_SEQ };
    let mut name = [0u8; 16];
    name[0] = b'_'; name[1] = b's'; name[2] = b'p';
    // Encode seq as decimal.
    let mut val = seq;
    let mut pos = 3usize;
    let mut tmp = [0u8; 10];
    let mut ti = 10;
    if val == 0 { ti -= 1; tmp[ti] = b'0'; }
    while val > 0 && ti > 0 { ti -= 1; tmp[ti] = b'0' + (val % 10) as u8; val /= 10; }
    while ti < 10 && pos < 16 { name[pos] = tmp[ti]; pos += 1; ti += 1; }
    let nlen = pos;

    // Bind socket A.
    let (w0, w1) = pack_uds_name(&name, nlen);
    let d2_bind = (nlen as u64) | ((rp as u64) << 32);
    syscall::send(uds_port, UDS_BIND, handle_a, w0, d2_bind, w1);
    let bind_resp = syscall::recv_msg(rp);
    if bind_resp.is_none() || bind_resp.unwrap().tag != UDS_OK {
        syscall::port_destroy(rp);
        unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); }
        return linux_err(EINVAL);
    }

    // Listen socket A.
    let d2_listen = (rp as u64) << 32;
    syscall::send(uds_port, UDS_LISTEN, handle_a, 1, d2_listen, 0);
    let listen_resp = syscall::recv_msg(rp);
    if listen_resp.is_none() || listen_resp.unwrap().tag != UDS_OK {
        syscall::port_destroy(rp);
        unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); }
        return linux_err(EINVAL);
    }

    // Connect socket B to socket A's name.
    let d2_conn = (nlen as u64) | ((rp as u64) << 32);
    let pid = syscall::getpid();
    let uid = syscall::getuid() as u64;
    let d3_conn = pid | (uid << 32);
    syscall::send(uds_port, UDS_CONNECT, w0, w1, d2_conn, d3_conn);
    let conn_resp = match syscall::recv_msg(rp) {
        Some(m) => m,
        None => { syscall::port_destroy(rp); unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); } return linux_err(ECONNREFUSED); }
    };
    if conn_resp.tag != UDS_OK {
        syscall::port_destroy(rp);
        unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); }
        return linux_err(ECONNREFUSED);
    }
    let client_handle = conn_resp.data[0];

    // Accept on socket A.
    let d2_acc = (rp as u64) << 32;
    syscall::send(uds_port, UDS_ACCEPT, handle_a, 0, d2_acc, 0);
    let acc_resp = match syscall::recv_msg(rp) {
        Some(m) => m,
        None => { syscall::port_destroy(rp); unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); } return linux_err(ECONNREFUSED); }
    };
    syscall::port_destroy(rp);
    if acc_resp.tag != UDS_OK {
        unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); }
        return linux_err(ECONNREFUSED);
    }
    let server_handle = acc_resp.data[0];

    // Set up FD entries: fd0 = server-accepted end, fd1 = client-connected end.
    let flags = type_raw & !0xF;
    unsafe {
        PROC_TABLE[pi].fds[fd0].kind = FdKind::Socket;
        PROC_TABLE[pi].fds[fd0].fs_port = uds_port;
        PROC_TABLE[pi].fds[fd0].handle = server_handle;
        PROC_TABLE[pi].fds[fd0].sock_domain = AF_UNIX as u8;
        PROC_TABLE[pi].fds[fd0].sock_type = SOCK_STREAM as u8;
        PROC_TABLE[pi].fds[fd0].sock_state = 3;
        if flags & SOCK_NONBLOCK != 0 { PROC_TABLE[pi].fds[fd0].status_flags |= O_NONBLOCK as u32; }
        if flags & SOCK_CLOEXEC != 0 { PROC_TABLE[pi].fds[fd0].fd_flags |= FD_CLOEXEC; }

        PROC_TABLE[pi].fds[fd1].kind = FdKind::Socket;
        PROC_TABLE[pi].fds[fd1].fs_port = uds_port;
        PROC_TABLE[pi].fds[fd1].handle = client_handle;
        PROC_TABLE[pi].fds[fd1].sock_domain = AF_UNIX as u8;
        PROC_TABLE[pi].fds[fd1].sock_type = SOCK_STREAM as u8;
        PROC_TABLE[pi].fds[fd1].sock_state = 3;
        if flags & SOCK_NONBLOCK != 0 { PROC_TABLE[pi].fds[fd1].status_flags |= O_NONBLOCK as u32; }
        if flags & SOCK_CLOEXEC != 0 { PROC_TABLE[pi].fds[fd1].fd_flags |= FD_CLOEXEC; }
    }

    // Write [fd0, fd1] back to caller.
    let sv = [fd0 as u32, fd1 as u32];
    let sv_bytes: [u8; 8] = unsafe { core::mem::transmute(sv) };
    let written = syscall::personality_copy_out(caller_port, sv_va, &sv_bytes);
    if written < 8 {
        unsafe { PROC_TABLE[pi].fds[fd0] = FdEntry::empty(); PROC_TABLE[pi].fds[fd1] = FdEntry::empty(); }
        return linux_err(EFAULT);
    }
    0
}

/// Handle Linux getsockname(fd, addr, addrlen).
fn handle_getsockname(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let addr_va = args[1] as usize;
    let addrlen_va = args[2] as usize;

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        let dom = PROC_TABLE[pi].fds[fd].sock_domain;
        if addr_va != 0 && addrlen_va != 0 {
            if dom == AF_UNIX as u8 {
                // Write minimal sockaddr_un (family=AF_UNIX, empty path).
                let mut sa = [0u8; 4];
                sa[0] = AF_UNIX as u8;
                let _ = syscall::personality_copy_out(caller_port, addr_va, &sa);
                let len_bytes = (4u32).to_le_bytes();
                let _ = syscall::personality_copy_out(caller_port, addrlen_va, &len_bytes);
            } else if dom == AF_INET as u8 {
                let mut sa = [0u8; 16];
                sa[0] = AF_INET as u8; sa[1] = 0; // sa_family
                let port_be = PROC_TABLE[pi].fds[fd].sock_port.to_be_bytes();
                sa[2] = port_be[0]; sa[3] = port_be[1];
                let ip_be = PROC_TABLE[pi].fds[fd].sock_ip.to_be_bytes();
                sa[4] = ip_be[0]; sa[5] = ip_be[1]; sa[6] = ip_be[2]; sa[7] = ip_be[3];
                let _ = syscall::personality_copy_out(caller_port, addr_va, &sa);
                let len_bytes = (16u32).to_le_bytes();
                let _ = syscall::personality_copy_out(caller_port, addrlen_va, &len_bytes);
            }
        }
    }
    0
}

/// Handle Linux getpeername(fd, addr, addrlen).
fn handle_getpeername(pi: usize, _caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
            return linux_err(ENOTSOCK);
        }
        if PROC_TABLE[pi].fds[fd].sock_state != 3 {
            return linux_err(ENOTCONN);
        }
    }
    // Stub: return success without filling addr (caller often checks just for ENOTCONN).
    0
}

/// Handle Linux setsockopt — stub that returns 0.
fn handle_setsockopt(_pi: usize, _caller_port: u64, _args: &[u64; 6]) -> u64 {
    0
}

/// Handle Linux getsockopt — stub, with SO_PEERCRED special case.
fn handle_getsockopt(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let level = args[1];
    let optname = args[2];
    let optval_va = args[3] as usize; // note: getsockopt arg3 is r10
    // args[4] = optlen ptr

    const SOL_SOCKET: u64 = 1;
    const SO_PEERCRED: u64 = 17;

    if level == SOL_SOCKET && optname == SO_PEERCRED {
        if fd >= MAX_FDS { return linux_err(EBADF); }
        unsafe {
            if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::Socket {
                return linux_err(ENOTSOCK);
            }
            if PROC_TABLE[pi].fds[fd].sock_domain == AF_UNIX as u8 {
                let rp = syscall::port_create();
                let d2 = (rp as u64) << 32;
                syscall::send(PROC_TABLE[pi].fds[fd].fs_port, UDS_GETPEERCRED, PROC_TABLE[pi].fds[fd].handle, 0, d2, 0);
                let resp = match syscall::recv_msg(rp) {
                    Some(m) => m,
                    None => { syscall::port_destroy(rp); return linux_err(ENOTCONN); }
                };
                syscall::port_destroy(rp);
                if resp.tag == UDS_OK && optval_va != 0 {
                    // struct ucred: pid(i32) + uid(u32) + gid(u32) = 12 bytes
                    let pid = resp.data[0] as u32;
                    let uid_gid = resp.data[1];
                    let uid = uid_gid as u32;
                    let gid = (uid_gid >> 32) as u32;
                    let mut ucred = [0u8; 12];
                    ucred[0..4].copy_from_slice(&pid.to_le_bytes());
                    ucred[4..8].copy_from_slice(&uid.to_le_bytes());
                    ucred[8..12].copy_from_slice(&gid.to_le_bytes());
                    let _ = syscall::personality_copy_out(caller_port, optval_va, &ucred);
                }
                return 0;
            }
        }
    }
    0 // Default: silently succeed.
}

// ---- Epoll handlers ----

/// Poll a single FD for readiness without blocking.
fn poll_single_fd(pi: usize, fd: usize) -> u32 {
    unsafe {
        let entry = &PROC_TABLE[pi].fds[fd];
        match entry.kind {
            FdKind::Pipe => {
                let rp = syscall::port_create();
                let events: u16 = 0x0015; // POLLIN|POLLOUT|POLLHUP
                let d2 = ((rp as u64) << 32) | (events as u64);
                syscall::send(entry.fs_port, PIPE_POLL_TAG, entry.handle, 0, d2, 0);
                let resp = syscall::recv_msg(rp);
                syscall::port_destroy(rp);
                match resp {
                    Some(m) if m.tag == PIPE_OK => m.data[0] as u32,
                    _ => EPOLLERR,
                }
            }
            FdKind::Socket => {
                let dom = entry.sock_domain;
                if dom == AF_UNIX as u8 {
                    let rp = syscall::port_create();
                    let events: u16 = 0x0015; // POLLIN|POLLOUT|POLLHUP
                    let d2 = ((rp as u64) << 32) | (events as u64);
                    syscall::send(entry.fs_port, UDS_POLL_TAG, entry.handle, 0, d2, 0);
                    let resp = syscall::recv_msg(rp);
                    syscall::port_destroy(rp);
                    match resp {
                        Some(m) if m.tag == UDS_OK => m.data[0] as u32,
                        _ => EPOLLERR,
                    }
                } else {
                    // AF_INET: no poll opcode — report writable by default.
                    EPOLLOUT
                }
            }
            FdKind::EventFd => {
                let idx = entry.handle as usize;
                let mut revents = EPOLLOUT;
                if idx < MAX_EVENT_INSTANCES && EVENTFD_TABLE[idx].active && EVENTFD_TABLE[idx].counter > 0 {
                    revents |= EPOLLIN;
                }
                revents
            }
            FdKind::TimerFd => {
                let idx = entry.handle as usize;
                if idx < MAX_EVENT_INSTANCES && TIMERFD_TABLE[idx].active {
                    check_timerfd_expiry(idx);
                    if TIMERFD_TABLE[idx].expirations > 0 { EPOLLIN } else { 0 }
                } else {
                    EPOLLERR
                }
            }
            FdKind::MemFd | FdKind::File | FdKind::Dir => EPOLLIN | EPOLLOUT,
            _ => EPOLLERR,
        }
    }
}

/// Handle epoll_create(size) / epoll_create1(flags).
fn handle_epoll_create1(pi: usize, flags: u64) -> u64 {
    // Allocate an epoll instance.
    let ep_idx = unsafe {
        let mut found = None;
        for i in 0..MAX_EPOLL_INSTANCES {
            if !EPOLL_TABLE[i].active {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return linux_err(EMFILE),
        }
    };

    let fd = match alloc_fd(pi) {
        Some(f) => f,
        None => return linux_err(EMFILE),
    };

    unsafe {
        EPOLL_TABLE[ep_idx].active = true;
        EPOLL_TABLE[ep_idx].owner_port = PROC_TABLE[pi].port;
        EPOLL_TABLE[ep_idx].watches = [const { EpollWatch::empty() }; MAX_EPOLL_WATCHES];

        PROC_TABLE[pi].fds[fd].kind = FdKind::Epoll;
        PROC_TABLE[pi].fds[fd].handle = ep_idx as u64;
        if flags & _EPOLL_CLOEXEC != 0 {
            PROC_TABLE[pi].fds[fd].fd_flags |= FD_CLOEXEC;
        }
    }
    fd as u64
}

/// Handle epoll_ctl(epfd, op, fd, event_ptr).
fn handle_epoll_ctl(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let epfd = args[0] as usize;
    let op = args[1];
    let target_fd = args[2] as usize;
    let event_va = args[3] as usize;

    if epfd >= MAX_FDS || target_fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[epfd].in_use || PROC_TABLE[pi].fds[epfd].kind != FdKind::Epoll {
            return linux_err(EBADF);
        }
        if !PROC_TABLE[pi].fds[target_fd].in_use {
            return linux_err(EBADF);
        }

        let ep_idx = PROC_TABLE[pi].fds[epfd].handle as usize;
        if ep_idx >= MAX_EPOLL_INSTANCES || !EPOLL_TABLE[ep_idx].active {
            return linux_err(EBADF);
        }

        match op {
            EPOLL_CTL_ADD => {
                // Check for duplicate.
                for w in 0..MAX_EPOLL_WATCHES {
                    if EPOLL_TABLE[ep_idx].watches[w].active && EPOLL_TABLE[ep_idx].watches[w].fd == target_fd as u8 {
                        return linux_err(EEXIST);
                    }
                }
                // Read epoll_event from caller: { u32 events, u64 data } = 12 bytes
                let mut ev_buf = [0u8; 12];
                let copied = syscall::personality_copy_in(caller_port, event_va, &mut ev_buf);
                if copied < 12 { return linux_err(EFAULT); }
                let events = u32::from_le_bytes([ev_buf[0], ev_buf[1], ev_buf[2], ev_buf[3]]);
                let data = u64::from_le_bytes([ev_buf[4], ev_buf[5], ev_buf[6], ev_buf[7], ev_buf[8], ev_buf[9], ev_buf[10], ev_buf[11]]);
                // Find empty watch slot.
                for w in 0..MAX_EPOLL_WATCHES {
                    if !EPOLL_TABLE[ep_idx].watches[w].active {
                        EPOLL_TABLE[ep_idx].watches[w] = EpollWatch { active: true, fd: target_fd as u8, events, data };
                        return 0;
                    }
                }
                linux_err(ENOMEM) // No space
            }
            EPOLL_CTL_MOD => {
                let mut ev_buf = [0u8; 12];
                let copied = syscall::personality_copy_in(caller_port, event_va, &mut ev_buf);
                if copied < 12 { return linux_err(EFAULT); }
                let events = u32::from_le_bytes([ev_buf[0], ev_buf[1], ev_buf[2], ev_buf[3]]);
                let data = u64::from_le_bytes([ev_buf[4], ev_buf[5], ev_buf[6], ev_buf[7], ev_buf[8], ev_buf[9], ev_buf[10], ev_buf[11]]);
                for w in 0..MAX_EPOLL_WATCHES {
                    if EPOLL_TABLE[ep_idx].watches[w].active && EPOLL_TABLE[ep_idx].watches[w].fd == target_fd as u8 {
                        EPOLL_TABLE[ep_idx].watches[w].events = events;
                        EPOLL_TABLE[ep_idx].watches[w].data = data;
                        return 0;
                    }
                }
                linux_err(ENOENT)
            }
            EPOLL_CTL_DEL => {
                for w in 0..MAX_EPOLL_WATCHES {
                    if EPOLL_TABLE[ep_idx].watches[w].active && EPOLL_TABLE[ep_idx].watches[w].fd == target_fd as u8 {
                        EPOLL_TABLE[ep_idx].watches[w] = EpollWatch::empty();
                        return 0;
                    }
                }
                linux_err(ENOENT)
            }
            _ => linux_err(EINVAL),
        }
    }
}

/// Handle epoll_wait(epfd, events, maxevents, timeout).
fn handle_epoll_wait(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let epfd = args[0] as usize;
    let events_va = args[1] as usize;
    let maxevents = args[2] as usize;
    let timeout_ms = args[3] as i32;

    if epfd >= MAX_FDS { return linux_err(EBADF); }
    if maxevents == 0 || maxevents > 64 { return linux_err(EINVAL); }

    let ep_idx = unsafe {
        if !PROC_TABLE[pi].fds[epfd].in_use || PROC_TABLE[pi].fds[epfd].kind != FdKind::Epoll {
            return linux_err(EBADF);
        }
        let idx = PROC_TABLE[pi].fds[epfd].handle as usize;
        if idx >= MAX_EPOLL_INSTANCES || !EPOLL_TABLE[idx].active {
            return linux_err(EBADF);
        }
        idx
    };

    let max_iters: u32 = if timeout_ms == 0 {
        1
    } else if timeout_ms > 0 {
        ((timeout_ms as u32) / 5).max(1).min(200)
    } else {
        400 // ~2s for infinite timeout
    };

    for iter in 0..max_iters {
        let mut out_count = 0usize;
        let mut out_buf = [0u8; 12 * 16]; // max 16 events at a time

        let cap = maxevents.min(16);
        unsafe {
            for w in 0..MAX_EPOLL_WATCHES {
                if out_count >= cap { break; }
                if !EPOLL_TABLE[ep_idx].watches[w].active { continue; }

                let fd = EPOLL_TABLE[ep_idx].watches[w].fd as usize;
                if fd >= MAX_FDS || !PROC_TABLE[pi].fds[fd].in_use { continue; }

                let revents = poll_single_fd(pi, fd);
                let matched = (revents & EPOLL_TABLE[ep_idx].watches[w].events)
                    | (revents & (EPOLLERR | EPOLLHUP));

                if matched != 0 {
                    let off = out_count * 12;
                    out_buf[off..off + 4].copy_from_slice(&matched.to_le_bytes());
                    let data = EPOLL_TABLE[ep_idx].watches[w].data;
                    out_buf[off + 4..off + 12].copy_from_slice(&data.to_le_bytes());
                    out_count += 1;
                }
            }
        }

        if out_count > 0 {
            syscall::personality_copy_out(caller_port, events_va, &out_buf[..out_count * 12]);
            return out_count as u64;
        }

        if iter + 1 < max_iters {
            syscall::sleep_ms(5);
        }
    }

    0 // timeout, no events
}

// ---- EventFd / TimerFd handlers ----

fn check_timerfd_expiry(idx: usize) {
    unsafe {
        let slot = &mut TIMERFD_TABLE[idx];
        if slot.next_expiry_ns == 0 { return; }
        let now = syscall::clock_gettime();
        if now < slot.next_expiry_ns { return; }
        slot.expirations += 1;
        if slot.interval_ns > 0 {
            slot.next_expiry_ns += slot.interval_ns;
            if slot.next_expiry_ns <= now {
                slot.next_expiry_ns = now + slot.interval_ns;
            }
        } else {
            slot.next_expiry_ns = 0; // one-shot: disarm
        }
    }
}

/// eventfd2(initval, flags)
fn handle_eventfd2(pi: usize, args: &[u64; 6]) -> u64 {
    let initval = args[0] as u32;
    let flags = args[1] as u32;

    // Allocate table slot.
    let slot_idx = unsafe {
        let mut found = None;
        for i in 0..MAX_EVENT_INSTANCES {
            if !EVENTFD_TABLE[i].active {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return linux_err(EMFILE),
        }
    };

    // Allocate FD.
    let fd = unsafe {
        let mut found = None;
        for i in 3..MAX_FDS {
            if !PROC_TABLE[pi].fds[i].in_use {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return linux_err(EMFILE),
        }
    };

    unsafe {
        EVENTFD_TABLE[slot_idx].active = true;
        EVENTFD_TABLE[slot_idx].counter = initval as u64;
        EVENTFD_TABLE[slot_idx].flags = flags;

        PROC_TABLE[pi].fds[fd] = FdEntry::empty();
        PROC_TABLE[pi].fds[fd].in_use = true;
        PROC_TABLE[pi].fds[fd].kind = FdKind::EventFd;
        PROC_TABLE[pi].fds[fd].handle = slot_idx as u64;
    }

    fd as u64
}

/// timerfd_create(clockid, flags)
fn handle_timerfd_create(pi: usize, _args: &[u64; 6]) -> u64 {
    // Allocate table slot.
    let slot_idx = unsafe {
        let mut found = None;
        for i in 0..MAX_EVENT_INSTANCES {
            if !TIMERFD_TABLE[i].active {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return linux_err(EMFILE),
        }
    };

    // Allocate FD.
    let fd = unsafe {
        let mut found = None;
        for i in 3..MAX_FDS {
            if !PROC_TABLE[pi].fds[i].in_use {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return linux_err(EMFILE),
        }
    };

    unsafe {
        TIMERFD_TABLE[slot_idx] = TimerFdSlot::empty();
        TIMERFD_TABLE[slot_idx].active = true;

        PROC_TABLE[pi].fds[fd] = FdEntry::empty();
        PROC_TABLE[pi].fds[fd].in_use = true;
        PROC_TABLE[pi].fds[fd].kind = FdKind::TimerFd;
        PROC_TABLE[pi].fds[fd].handle = slot_idx as u64;
    }

    fd as u64
}

/// timerfd_settime(fd, flags, new_value, old_value)
/// new_value points to struct itimerspec { timespec it_interval; timespec it_value; }
/// Each timespec is { i64 tv_sec, i64 tv_nsec } = 16 bytes. Total 32 bytes.
fn handle_timerfd_settime(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let _flags = args[1]; // TFD_TIMER_ABSTIME etc. — ignored for now (relative only)
    let new_va = args[2] as usize;
    // args[3] = old_value pointer — ignored (would need copy_out)

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::TimerFd {
            return linux_err(EBADF);
        }
        let idx = PROC_TABLE[pi].fds[fd].handle as usize;
        if idx >= MAX_EVENT_INSTANCES || !TIMERFD_TABLE[idx].active {
            return linux_err(EBADF);
        }

        if new_va == 0 { return linux_err(EFAULT); }

        // Read itimerspec (32 bytes): it_interval (tv_sec, tv_nsec), it_value (tv_sec, tv_nsec)
        let mut buf = [0u8; 32];
        let copied = syscall::personality_copy_in(caller_port, new_va, &mut buf);
        if copied < 32 { return linux_err(EFAULT); }

        let interval_sec = i64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        let interval_nsec = i64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let value_sec = i64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
        let value_nsec = i64::from_le_bytes([buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]]);

        let interval_ns = (interval_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(interval_nsec as u64);
        let value_ns = (value_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(value_nsec as u64);

        TIMERFD_TABLE[idx].interval_ns = interval_ns;
        TIMERFD_TABLE[idx].expirations = 0;
        if value_ns == 0 {
            // Disarm timer.
            TIMERFD_TABLE[idx].next_expiry_ns = 0;
        } else {
            // Relative: set expiry to now + value.
            TIMERFD_TABLE[idx].next_expiry_ns = syscall::clock_gettime() + value_ns;
        }
    }
    0
}

/// timerfd_gettime(fd, curr_value)
fn handle_timerfd_gettime(pi: usize, caller_port: u64, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let curr_va = args[1] as usize;

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use || PROC_TABLE[pi].fds[fd].kind != FdKind::TimerFd {
            return linux_err(EBADF);
        }
        let idx = PROC_TABLE[pi].fds[fd].handle as usize;
        if idx >= MAX_EVENT_INSTANCES || !TIMERFD_TABLE[idx].active {
            return linux_err(EBADF);
        }
        if curr_va == 0 { return linux_err(EFAULT); }

        check_timerfd_expiry(idx);

        let interval_ns = TIMERFD_TABLE[idx].interval_ns;
        let remaining_ns = if TIMERFD_TABLE[idx].next_expiry_ns == 0 {
            0u64
        } else {
            let now = syscall::clock_gettime();
            if now >= TIMERFD_TABLE[idx].next_expiry_ns { 0 } else { TIMERFD_TABLE[idx].next_expiry_ns - now }
        };

        // Write itimerspec: it_interval then it_value
        let mut buf = [0u8; 32];
        let i_sec = (interval_ns / 1_000_000_000) as i64;
        let i_nsec = (interval_ns % 1_000_000_000) as i64;
        let v_sec = (remaining_ns / 1_000_000_000) as i64;
        let v_nsec = (remaining_ns % 1_000_000_000) as i64;
        buf[0..8].copy_from_slice(&i_sec.to_le_bytes());
        buf[8..16].copy_from_slice(&i_nsec.to_le_bytes());
        buf[16..24].copy_from_slice(&v_sec.to_le_bytes());
        buf[24..32].copy_from_slice(&v_nsec.to_le_bytes());
        syscall::personality_copy_out(caller_port, curr_va, &buf);
    }
    0
}

// ---- MemFd handlers ----

/// memfd_create(name, flags) — NR 319
fn handle_memfd_create(pi: usize, _caller_port: u64, _args: &[u64; 6]) -> u64 {
    // Allocate table slot.
    let slot_idx = unsafe {
        let mut found = None;
        for i in 0..MAX_MEMFD_INSTANCES {
            if !MEMFD_TABLE[i].active {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return linux_err(EMFILE),
        }
    };

    // Allocate FD.
    let fd = unsafe {
        let mut found = None;
        for i in 3..MAX_FDS {
            if !PROC_TABLE[pi].fds[i].in_use {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return linux_err(EMFILE),
        }
    };

    unsafe {
        MEMFD_TABLE[slot_idx] = MemFdSlot::empty();
        MEMFD_TABLE[slot_idx].active = true;

        PROC_TABLE[pi].fds[fd] = FdEntry::empty();
        PROC_TABLE[pi].fds[fd].in_use = true;
        PROC_TABLE[pi].fds[fd].kind = FdKind::MemFd;
        PROC_TABLE[pi].fds[fd].handle = slot_idx as u64;
        PROC_TABLE[pi].fds[fd].file_size = 0;
        PROC_TABLE[pi].fds[fd].offset = 0;
    }

    fd as u64
}

/// ftruncate(fd, length) — NR 77
fn handle_ftruncate(pi: usize, args: &[u64; 6]) -> u64 {
    let fd = args[0] as usize;
    let length = args[1] as usize;

    if fd >= MAX_FDS { return linux_err(EBADF); }
    unsafe {
        if !PROC_TABLE[pi].fds[fd].in_use {
            return linux_err(EBADF);
        }
        if PROC_TABLE[pi].fds[fd].kind != FdKind::MemFd {
            return 0; // Stub for non-MemFd (keep existing behavior)
        }
        let idx = PROC_TABLE[pi].fds[fd].handle as usize;
        if idx >= MAX_MEMFD_INSTANCES || !MEMFD_TABLE[idx].active {
            return linux_err(EBADF);
        }

        // Grow backing memory if needed.
        if length > MEMFD_TABLE[idx].capacity {
            let ps = syscall::page_size();
            let new_pages = (length + ps - 1) / ps;
            let new_cap = new_pages * ps;
            match syscall::mmap_anon(0, new_pages, 1 /* RW */) {
                Some(new_va) => {
                    // Zero-init: mmap_anon returns zeroed pages.
                    // Copy old data if any.
                    if MEMFD_TABLE[idx].va != 0 && MEMFD_TABLE[idx].size > 0 {
                        let copy_len = MEMFD_TABLE[idx].size.min(length);
                        let old_ptr = MEMFD_TABLE[idx].va as *const u8;
                        let new_ptr = new_va as *mut u8;
                        core::ptr::copy_nonoverlapping(old_ptr, new_ptr, copy_len);
                        syscall::munmap(MEMFD_TABLE[idx].va);
                    }
                    MEMFD_TABLE[idx].va = new_va;
                    MEMFD_TABLE[idx].capacity = new_cap;
                }
                None => return linux_err(ENOMEM),
            }
        }
        MEMFD_TABLE[idx].size = length;
        PROC_TABLE[pi].fds[fd].file_size = length as u64;
    }
    0
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
        UDS_PORT = syscall::ns_lookup(b"uds").unwrap_or(0);
        NET_PORT = syscall::ns_lookup(b"net").unwrap_or(0);
    }

    syscall::debug_puts(b"[linux_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => continue,
        };

        let linux_nr = msg.tag & 0xFFFF_FFFF;
        let caller_port = msg.tag >> 32;

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
            __NR_PREAD64 => handle_pread64(pi, caller_port, &msg.data),
            __NR_PWRITE64 => handle_pwrite64(pi, caller_port, &msg.data),
            __NR_READV => handle_readv(pi, caller_port, &msg.data),
            __NR_WRITE => handle_write(pi, caller_port, &msg.data),
            __NR_OPEN => handle_open(pi, caller_port, &msg.data),
            __NR_CLOSE => handle_close(pi, &msg.data),
            __NR_STAT | __NR_LSTAT | __NR_NEWFSTATAT => handle_stat(caller_port, &msg.data),
            __NR_FSTAT => handle_fstat(pi, caller_port, &msg.data),
            __NR_LSEEK => handle_lseek(pi, &msg.data),
            __NR_WRITEV => handle_writev(pi, caller_port, &msg.data),
            __NR_ACCESS => handle_access(pi, caller_port, &msg.data),
            __NR_DUP => handle_dup(pi, &msg.data),
            __NR_DUP2 => handle_dup2(pi, &msg.data),
            __NR_GETCWD => handle_getcwd(pi, caller_port, &msg.data),
            __NR_READLINK => handle_readlink(pi, caller_port, &msg.data),
            __NR_READLINKAT => handle_readlinkat(pi, caller_port, &msg.data),
            __NR_UMASK => handle_umask(pi, &msg.data),
            __NR_FACCESSAT => handle_faccessat(pi, caller_port, &msg.data),
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
            __NR_BRK => handle_brk(pi, caller_port, &msg.data),
            __NR_ARCH_PRCTL => handle_arch_prctl(&msg.data),
            __NR_SET_TID_ADDRESS => handle_set_tid_address(caller_port),
            __NR_EXIT | __NR_EXIT_GROUP => {
                handle_exit(pi, caller_port, &msg.data);
                continue; // Don't reply — task is dead.
            }
            __NR_GETPID | __NR_GETTID | __NR_GETUID | __NR_GETEUID
            | __NR_GETGID | __NR_GETEGID => handle_getid(linux_nr, caller_port),
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
            __NR_SIGALTSTACK => 0,  // stub — no alternate signal stack yet
            __NR_TGKILL => handle_tgkill(caller_port, &msg.data),
            __NR_KILL => handle_kill(pi, caller_port, &msg.data),

            // Stubs that return success (0) to avoid crashing callers.
            __NR_SET_ROBUST_LIST | __NR_RSEQ => 0,
            __NR_PRLIMIT64 => handle_prlimit64(caller_port, &msg.data),
            __NR_MADVISE => 0,
            __NR_SCHED_GETAFFINITY => handle_sched_getaffinity(caller_port, &msg.data),
            __NR_GETRLIMIT | __NR_GETRUSAGE => 0,
            __NR_FTRUNCATE => handle_ftruncate(pi, &msg.data),
            __NR_STATX => handle_statx(pi, caller_port, &msg.data),
            __NR_FCHMOD | __NR_FCHMODAT => 0, // stub: single-user, no permission enforcement
            __NR_FCHOWN | __NR_FCHOWNAT => 0, // stub: single-user, no ownership enforcement

            // epoll
            __NR_EPOLL_CREATE => handle_epoll_create1(pi, 0),
            __NR_EPOLL_CREATE1 => handle_epoll_create1(pi, msg.data[0]),
            __NR_EPOLL_CTL => handle_epoll_ctl(pi, caller_port, &msg.data),
            __NR_EPOLL_WAIT | __NR_EPOLL_PWAIT => handle_epoll_wait(pi, caller_port, &msg.data),

            // eventfd / timerfd
            __NR_EVENTFD2 => handle_eventfd2(pi, &msg.data),
            __NR_TIMERFD_CREATE => handle_timerfd_create(pi, &msg.data),
            __NR_TIMERFD_SETTIME => handle_timerfd_settime(pi, caller_port, &msg.data),
            __NR_TIMERFD_GETTIME => handle_timerfd_gettime(pi, caller_port, &msg.data),

            __NR_MEMFD_CREATE => handle_memfd_create(pi, caller_port, &msg.data),
            __NR_CLONE3 => linux_err(ENOSYS),

            // Anonymous mmap: map in caller's address space via personality syscall.
            __NR_MMAP => {
                let addr = msg.data[0] as u64;
                let len = msg.data[1] as usize;
                let prot = msg.data[2] as u64;
                let _flags = msg.data[3];
                let page_size = syscall::page_size() as usize;
                let pages = ((len + page_size - 1) / page_size) as u64;
                match syscall::personality_mmap_anon(caller_port, addr, pages, prot) {
                    Some(va) => va as u64,
                    None => u64::MAX, // MAP_FAILED
                }
            }
            __NR_MPROTECT => {
                let addr = msg.data[0] as usize;
                let len = msg.data[1] as usize;
                let prot = msg.data[2] as u8;
                if syscall::personality_mprotect(caller_port, addr, len, prot) { 0 } else { linux_err(ENOSYS) }
            }
            __NR_MUNMAP => {
                let addr = msg.data[0] as usize;
                if syscall::personality_munmap(caller_port, addr) { 0 } else { linux_err(ENOSYS) }
            }
            __NR_MREMAP => {
                let old_addr = msg.data[0] as usize;
                let old_len = msg.data[1] as usize;
                let new_len = msg.data[2] as usize;
                let page_size = syscall::page_size() as usize;
                let aligned_old = (old_len + page_size - 1) & !(page_size - 1);
                let aligned_new = (new_len + page_size - 1) & !(page_size - 1);
                match syscall::personality_mremap(caller_port, old_addr, aligned_old, aligned_new) {
                    Some(va) => va as u64,
                    None => linux_err(ENOMEM),
                }
            }

            // Stubs: file ops that need VFS extensions.
            __NR_RENAME | __NR_RENAMEAT | __NR_RENAMEAT2 => linux_err(ENOSYS),
            __NR_FLOCK => 0, // stub: no mandatory locking
            __NR_TRUNCATE => linux_err(ENOSYS), // needs VFS_TRUNCATE

            // Phase 129: Socket syscalls.
            __NR_SOCKET => handle_socket(pi, caller_port, &msg.data),
            __NR_CONNECT => handle_connect(pi, caller_port, &msg.data),
            __NR_ACCEPT => handle_accept_inner(pi, caller_port, &msg.data, 0),
            __NR_SENDTO => handle_sendto(pi, caller_port, &msg.data),
            __NR_RECVFROM => handle_recvfrom(pi, caller_port, &msg.data),
            __NR_SENDMSG => handle_sendmsg(pi, caller_port, &msg.data),
            __NR_RECVMSG => handle_recvmsg(pi, caller_port, &msg.data),
            __NR_SHUTDOWN => 0, // stub
            __NR_BIND => handle_bind(pi, caller_port, &msg.data),
            __NR_LISTEN => handle_listen(pi, caller_port, &msg.data),
            __NR_GETSOCKNAME => handle_getsockname(pi, caller_port, &msg.data),
            __NR_GETPEERNAME => handle_getpeername(pi, caller_port, &msg.data),
            __NR_SOCKETPAIR => handle_socketpair(pi, caller_port, &msg.data),
            __NR_SETSOCKOPT => handle_setsockopt(pi, caller_port, &msg.data),
            __NR_GETSOCKOPT => handle_getsockopt(pi, caller_port, &msg.data),
            __NR_ACCEPT4 => {
                let flags = msg.data[3];
                handle_accept_inner(pi, caller_port, &msg.data, flags)
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
