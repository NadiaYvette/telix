//! Userspace file descriptor table.
//!
//! Maps integer FDs to (server_port, server_handle, flags) tuples.
//! dup/dup2/fcntl/ioctl are pure userspace operations on this table;
//! no kernel changes required.

use crate::syscall;

/// Maximum number of open file descriptors per process.
pub const MAX_FDS: usize = 64;

/// FD type tag — determines how read/write/ioctl are routed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FdType {
    /// Slot is unused.
    Free = 0,
    /// Console (serial) I/O — reads/writes go to the console server.
    Console = 1,
    /// Pipe endpoint — reads/writes go through pipe IPC protocol.
    Pipe = 2,
    /// File — reads/writes go to a filesystem server.
    File = 3,
    /// Socket — reads/writes go to the net server.
    Socket = 4,
    /// Generic port — raw IPC, no read/write translation.
    Port = 5,
    /// PTY endpoint — reads/writes go to the PTY server.
    Pty = 6,
}

/// Per-FD flags (stored alongside the entry, not the underlying object).
pub const FD_CLOEXEC: u32 = 1;

/// File status flags (shared across dups of the same underlying object).
pub const O_NONBLOCK: u32 = 0x800;
pub const O_APPEND: u32 = 0x400;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;

/// fcntl commands.
pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_GETLK: i32 = 5;
pub const F_SETLK: i32 = 6;
pub const F_SETLKW: i32 = 7;
pub const F_DUPFD_CLOEXEC: i32 = 0x406;

/// flock() operations.
pub const LOCK_SH: i32 = 1;
pub const LOCK_EX: i32 = 2;
pub const LOCK_NB: i32 = 4;
pub const LOCK_UN: i32 = 8;

/// Lock types for struct Flock / fcntl.
pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;

/// POSIX flock structure for fcntl byte-range locking.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Flock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

/// FS lock protocol tags.
const FS_FLOCK: u64 = 0x2800;
const FS_FLOCK_OK: u64 = 0x2801;
const FS_GETLK: u64 = 0x2810;
const FS_GETLK_OK: u64 = 0x2811;
const FS_SETLK: u64 = 0x2820;
const FS_SETLK_OK: u64 = 0x2821;
const FS_SETLKW: u64 = 0x2830;
const FS_SETLKW_OK: u64 = 0x2831;
const FS_LOCK_ERR: u64 = 0x28FF;

/// ioctl requests.
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const FIONBIO: u32 = 0x5421;
pub const FIONREAD: u32 = 0x541B;

/// IPC tags for ioctl routing to servers.
pub const IOCTL_TAG: u64 = 0x7000;
pub const IOCTL_OK_TAG: u64 = 0x7100;
pub const IOCTL_ERR_TAG: u64 = 0x7F00;

#[derive(Clone, Copy)]
pub struct FdEntry {
    pub fd_type: FdType,
    /// IPC port for the backing server.
    pub port: u32,
    /// Server-side handle (e.g., file handle, connection ID).
    pub handle: u32,
    /// Per-FD flags (FD_CLOEXEC).
    pub fd_flags: u32,
    /// File status flags (O_NONBLOCK, O_APPEND, access mode).
    pub status_flags: u32,
}

impl FdEntry {
    const fn empty() -> Self {
        Self {
            fd_type: FdType::Free,
            port: 0,
            handle: 0,
            fd_flags: 0,
            status_flags: 0,
        }
    }
}

static mut FD_TABLE: [FdEntry; MAX_FDS] = {
    const EMPTY: FdEntry = FdEntry::empty();
    [EMPTY; MAX_FDS]
};

/// Initialize the FD table. Call once at process start.
/// Sets up FDs 0, 1, 2 pointing to the console server.
pub fn fd_init(console_port: u32) {
    unsafe {
        // stdin
        FD_TABLE[0] = FdEntry {
            fd_type: FdType::Console,
            port: console_port,
            handle: 0,
            fd_flags: 0,
            status_flags: O_RDONLY,
        };
        // stdout
        FD_TABLE[1] = FdEntry {
            fd_type: FdType::Console,
            port: console_port,
            handle: 0,
            fd_flags: 0,
            status_flags: O_WRONLY,
        };
        // stderr
        FD_TABLE[2] = FdEntry {
            fd_type: FdType::Console,
            port: console_port,
            handle: 0,
            fd_flags: 0,
            status_flags: O_WRONLY,
        };
    }
}

/// Look up an FD entry. Returns None if out of range or free.
pub fn fd_get(fd: i32) -> Option<FdEntry> {
    if fd < 0 || fd as usize >= MAX_FDS {
        return None;
    }
    let entry = unsafe { FD_TABLE[fd as usize] };
    if entry.fd_type == FdType::Free {
        None
    } else {
        Some(entry)
    }
}

/// Allocate the lowest available FD >= `min_fd` with the given parameters.
/// Returns the FD number, or None if the table is full.
pub fn fd_open(port: u32, handle: u32, fd_type: FdType, status_flags: u32) -> Option<i32> {
    fd_open_at_or_above(0, port, handle, fd_type, status_flags, 0)
}

/// Allocate the lowest available FD >= `min_fd`.
fn fd_open_at_or_above(
    min_fd: i32,
    port: u32,
    handle: u32,
    fd_type: FdType,
    status_flags: u32,
    fd_flags: u32,
) -> Option<i32> {
    let start = if min_fd < 0 { 0 } else { min_fd as usize };
    unsafe {
        for i in start..MAX_FDS {
            if FD_TABLE[i].fd_type == FdType::Free {
                FD_TABLE[i] = FdEntry {
                    fd_type,
                    port,
                    handle,
                    fd_flags,
                    status_flags,
                };
                return Some(i as i32);
            }
        }
    }
    None
}

/// Close an FD. Returns true on success.
pub fn fd_close(fd: i32) -> bool {
    if fd < 0 || fd as usize >= MAX_FDS {
        return false;
    }
    unsafe {
        if FD_TABLE[fd as usize].fd_type == FdType::Free {
            return false;
        }
        FD_TABLE[fd as usize] = FdEntry::empty();
    }
    true
}

/// Duplicate `old_fd` to the lowest available FD.
/// Equivalent to POSIX dup(). The new FD has FD_CLOEXEC cleared.
pub fn dup(old_fd: i32) -> Option<i32> {
    let entry = fd_get(old_fd)?;
    fd_open_at_or_above(0, entry.port, entry.handle, entry.fd_type, entry.status_flags, 0)
}

/// Duplicate `old_fd` to exactly `new_fd`.
/// If `new_fd` is already open, it is silently closed first.
/// Equivalent to POSIX dup2(). Returns new_fd on success.
pub fn dup2(old_fd: i32, new_fd: i32) -> Option<i32> {
    if old_fd == new_fd {
        // POSIX: if equal and old_fd is valid, return new_fd without closing.
        fd_get(old_fd)?;
        return Some(new_fd);
    }
    if new_fd < 0 || new_fd as usize >= MAX_FDS {
        return None;
    }
    let entry = fd_get(old_fd)?;
    unsafe {
        // Close new_fd if open (silently).
        FD_TABLE[new_fd as usize] = FdEntry {
            fd_type: entry.fd_type,
            port: entry.port,
            handle: entry.handle,
            fd_flags: 0, // dup2 clears FD_CLOEXEC
            status_flags: entry.status_flags,
        };
    }
    Some(new_fd)
}

/// fcntl — file descriptor control.
///
/// Supported commands:
/// - `F_DUPFD`: duplicate to lowest FD >= arg
/// - `F_DUPFD_CLOEXEC`: same but set FD_CLOEXEC on the new FD
/// - `F_GETFD`: return FD flags (FD_CLOEXEC)
/// - `F_SETFD`: set FD flags
/// - `F_GETFL`: return file status flags
/// - `F_SETFL`: set file status flags (only O_NONBLOCK and O_APPEND are modifiable)
///
/// Returns -1 on error.
pub fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32 {
    if fd < 0 || fd as usize >= MAX_FDS {
        return -1;
    }
    unsafe {
        let entry = &mut FD_TABLE[fd as usize];
        if entry.fd_type == FdType::Free {
            return -1;
        }
        match cmd {
            F_DUPFD => {
                match fd_open_at_or_above(
                    arg,
                    entry.port,
                    entry.handle,
                    entry.fd_type,
                    entry.status_flags,
                    0,
                ) {
                    Some(new_fd) => new_fd,
                    None => -1,
                }
            }
            F_DUPFD_CLOEXEC => {
                match fd_open_at_or_above(
                    arg,
                    entry.port,
                    entry.handle,
                    entry.fd_type,
                    entry.status_flags,
                    FD_CLOEXEC,
                ) {
                    Some(new_fd) => new_fd,
                    None => -1,
                }
            }
            F_GETFD => entry.fd_flags as i32,
            F_SETFD => {
                entry.fd_flags = arg as u32;
                0
            }
            F_GETFL => entry.status_flags as i32,
            F_SETFL => {
                // Only O_NONBLOCK and O_APPEND are modifiable; access mode bits are preserved.
                let modifiable = O_NONBLOCK | O_APPEND;
                entry.status_flags = (entry.status_flags & !modifiable) | (arg as u32 & modifiable);
                0
            }
            _ => -1,
        }
    }
}

/// ioctl — device control.
///
/// Routes the request to the server backing `fd` via IPC.
/// The server is expected to understand IOCTL_TAG messages.
///
/// Returns 0 on success, -1 on error.
pub fn ioctl(fd: i32, request: u32, arg: u64) -> i32 {
    let entry = match fd_get(fd) {
        Some(e) => e,
        None => return -1,
    };

    match request {
        FIONBIO => {
            // Set/clear O_NONBLOCK based on the pointed-to value.
            // arg is treated as the value directly (1 = nonblock, 0 = blocking).
            if fd < 0 || fd as usize >= MAX_FDS {
                return -1;
            }
            unsafe {
                if arg != 0 {
                    FD_TABLE[fd as usize].status_flags |= O_NONBLOCK;
                } else {
                    FD_TABLE[fd as usize].status_flags &= !O_NONBLOCK;
                }
            }
            0
        }
        _ => {
            // Route to server via IPC.
            let reply_port = syscall::port_create() as u32;
            let d2 = ((reply_port as u64) << 32) | (entry.handle as u64);
            syscall::send(entry.port, IOCTL_TAG, request as u64, arg, d2, 0);
            let result = if let Some(reply) = syscall::recv_msg(reply_port) {
                if reply.tag == IOCTL_OK_TAG { 0 } else { -1 }
            } else {
                -1
            };
            syscall::port_destroy(reply_port);
            result
        }
    }
}

/// flock() — whole-file advisory lock.
///
/// `operation` is LOCK_SH, LOCK_EX, or LOCK_UN, optionally OR'd with LOCK_NB.
/// Returns 0 on success, -1 on error (EAGAIN if LOCK_NB and would block).
pub fn flock(fd: i32, operation: i32) -> i32 {
    let entry = match fd_get(fd) {
        Some(e) => e,
        None => return -1,
    };
    // Only File FDs support locking.
    if entry.fd_type != FdType::File {
        return -1;
    }
    let reply_port = syscall::port_create() as u32;
    let pid = syscall::getpid() as u32;
    let d0 = (entry.handle as u64) | ((operation as u64) << 32);
    let d1 = pid as u64;
    let d2 = (reply_port as u64) << 32;
    syscall::send(entry.port, FS_FLOCK, d0, d1, d2, 0);
    let result = if let Some(reply) = syscall::recv_msg(reply_port) {
        if reply.tag == FS_FLOCK_OK { 0 } else { -1 }
    } else {
        -1
    };
    syscall::port_destroy(reply_port);
    result
}

/// fcntl with Flock argument for F_GETLK/F_SETLK/F_SETLKW.
/// Returns 0 on success, -1 on error. For F_GETLK, `lock` is updated in place.
pub fn fcntl_lock(fd: i32, cmd: i32, lock: &mut Flock) -> i32 {
    let entry = match fd_get(fd) {
        Some(e) => e,
        None => return -1,
    };
    if entry.fd_type != FdType::File {
        return -1;
    }

    let tag = match cmd {
        F_GETLK => FS_GETLK,
        F_SETLK => FS_SETLK,
        F_SETLKW => FS_SETLKW,
        _ => return -1,
    };

    let reply_port = syscall::port_create() as u32;
    let pid = syscall::getpid() as u32;
    let d0 = (entry.handle as u64) | ((lock.l_type as u16 as u64) << 32) | ((lock.l_whence as u16 as u64) << 48);
    let d1 = lock.l_start as u64;
    let d2 = (lock.l_len as u32 as u64) | ((reply_port as u64) << 32);
    let d3 = pid as u64;
    syscall::send(entry.port, tag, d0, d1, d2, d3);

    let ok_tag = match cmd {
        F_GETLK => FS_GETLK_OK,
        F_SETLK => FS_SETLK_OK,
        F_SETLKW => FS_SETLKW_OK,
        _ => 0,
    };

    let result = if let Some(reply) = syscall::recv_msg(reply_port) {
        if reply.tag == ok_tag {
            if cmd == F_GETLK {
                // Unpack result into lock struct.
                lock.l_type = (reply.data[0] & 0xFFFF) as i16;
                lock.l_pid = (reply.data[0] >> 32) as i32;
                lock.l_start = reply.data[1] as i64;
                lock.l_len = reply.data[2] as i64;
            }
            0
        } else {
            -1
        }
    } else {
        -1
    };
    syscall::port_destroy(reply_port);
    result
}

/// Check if an FD is valid (open).
pub fn fd_is_valid(fd: i32) -> bool {
    fd_get(fd).is_some()
}

/// Return the number of open FDs.
pub fn fd_count() -> usize {
    let mut count = 0;
    unsafe {
        for i in 0..MAX_FDS {
            if FD_TABLE[i].fd_type != FdType::Free {
                count += 1;
            }
        }
    }
    count
}

/// Close all FDs with FD_CLOEXEC set. Called during execve.
pub fn fd_close_on_exec() {
    unsafe {
        for i in 0..MAX_FDS {
            if FD_TABLE[i].fd_type != FdType::Free && FD_TABLE[i].fd_flags & FD_CLOEXEC != 0 {
                FD_TABLE[i] = FdEntry::empty();
            }
        }
    }
}
