//! PTY (pseudo-terminal) API for Telix.
//!
//! Communicates with pty_srv to create and manage PTY pairs.

use crate::fd::{self, FdType};
use crate::syscall;

// PTY protocol tags.
const PTY_OPEN: u64 = 0x9000;
const PTY_OPEN_OK: u64 = 0x9001;
const PTY_WRITE: u64 = 0x9010;
const PTY_WRITE_OK: u64 = 0x9011;
const PTY_READ: u64 = 0x9020;
const PTY_READ_OK: u64 = 0x9021;
const PTY_CLOSE: u64 = 0x9030;
const PTY_CLOSE_OK: u64 = 0x9031;
const PTY_IOCTL: u64 = 0x9040;
const PTY_IOCTL_OK: u64 = 0x9041;
const PTY_EOF: u64 = 0x90FF;
const PTY_ERROR: u64 = 0x9F00;

// Termios ioctl requests.
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;

// Termios flags.
pub const ECHO: u32 = 0x0008;
pub const ICANON: u32 = 0x0002;
pub const ISIG: u32 = 0x0001;
pub const OPOST: u32 = 0x0001;
pub const ONLCR: u32 = 0x0004;

/// Look up the PTY server port (cached).
static mut PTY_PORT: u64 = 0;

fn pty_port() -> u64 {
    unsafe {
        if PTY_PORT == 0 {
            if let Some(p) = syscall::ns_lookup(b"pty") {
                PTY_PORT = p;
            }
        }
        PTY_PORT
    }
}

/// Open a PTY pair. Returns (master_fd, slave_fd), or None on failure.
pub fn openpty() -> Option<(i32, i32)> {
    let port = pty_port();
    if port == 0 {
        return None;
    }

    let reply_port = syscall::port_create();
    let pid = syscall::getpid() as u32;
    let d2 = (reply_port as u64) << 32;
    syscall::send(port, PTY_OPEN, 0, 0, d2, pid as u64);

    let result = if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == PTY_OPEN_OK {
            let master_h = (msg.data[0] & 0xFFFF_FFFF) as u32;
            let slave_h = (msg.data[0] >> 32) as u32;

            let master_fd = fd::fd_open(port, master_h, FdType::Pty, fd::O_RDWR)?;
            let slave_fd = match fd::fd_open(port, slave_h, FdType::Pty, fd::O_RDWR) {
                Some(fd) => fd,
                None => {
                    fd::fd_close(master_fd);
                    return None;
                }
            };
            Some((master_fd, slave_fd))
        } else {
            None
        }
    } else {
        None
    };

    syscall::port_destroy(reply_port);
    result
}

/// Write data to a PTY fd. Returns bytes written, or -1 on error.
pub fn pty_write_fd(fd: i32, data: &[u8]) -> isize {
    let entry = match fd::fd_get(fd) {
        Some(e) => e,
        None => return -1,
    };
    if entry.fd_type != FdType::Pty {
        return -1;
    }

    let mut total = 0isize;
    let mut off = 0;
    while off < data.len() {
        let chunk = if data.len() - off > 16 {
            16
        } else {
            data.len() - off
        };
        let mut w0 = 0u64;
        let mut w1 = 0u64;
        for i in 0..chunk {
            if i < 8 {
                w0 |= (data[off + i] as u64) << (i * 8);
            } else {
                w1 |= (data[off + i] as u64) << ((i - 8) * 8);
            }
        }
        let reply_port = syscall::port_create();
        let d2 = (chunk as u64) | ((reply_port as u64) << 32);
        syscall::send(entry.port, PTY_WRITE, entry.handle as u64, w0, d2, w1);
        let ok = if let Some(msg) = syscall::recv_msg(reply_port) {
            msg.tag == PTY_WRITE_OK
        } else {
            false
        };
        syscall::port_destroy(reply_port);
        if !ok {
            break;
        }
        total += chunk as isize;
        off += chunk;
    }
    total
}

/// Read data from a PTY fd. Returns bytes read, 0 on EOF, -1 on error.
pub fn pty_read_fd(fd: i32, buf: &mut [u8]) -> isize {
    let entry = match fd::fd_get(fd) {
        Some(e) => e,
        None => return -1,
    };
    if entry.fd_type != FdType::Pty {
        return -1;
    }

    let reply_port = syscall::port_create();
    let d2 = (reply_port as u64) << 32;
    syscall::send(entry.port, PTY_READ, entry.handle as u64, 0, d2, 0);

    let result = if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == PTY_READ_OK {
            let n = (msg.data[2] & 0xFFFF) as usize;
            let n = if n > buf.len() { buf.len() } else { n };
            // Unpack data from d0, d1.
            let b0 = msg.data[0].to_le_bytes();
            let b1 = msg.data[1].to_le_bytes();
            for i in 0..n {
                if i < 8 {
                    buf[i] = b0[i];
                } else {
                    buf[i] = b1[i - 8];
                }
            }
            n as isize
        } else if msg.tag == PTY_EOF {
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

/// Close a PTY fd.
pub fn pty_close_fd(fd: i32) -> bool {
    let entry = match fd::fd_get(fd) {
        Some(e) => e,
        None => return false,
    };
    if entry.fd_type != FdType::Pty {
        return false;
    }

    let reply_port = syscall::port_create();
    let d2 = (reply_port as u64) << 32;
    syscall::send(entry.port, PTY_CLOSE, entry.handle as u64, 0, d2, 0);
    let _ = syscall::recv_msg(reply_port);
    syscall::port_destroy(reply_port);
    fd::fd_close(fd);
    true
}

/// Send an ioctl to the PTY server.
/// Returns (result0, result1) on success, or None.
pub fn pty_ioctl(fd: i32, request: u32, arg0: u64, arg1: u64) -> Option<(u64, u64)> {
    let entry = match fd::fd_get(fd) {
        Some(e) => e,
        None => return None,
    };
    if entry.fd_type != FdType::Pty {
        return None;
    }

    let reply_port = syscall::port_create();
    let d0 = (entry.handle as u64) | ((request as u64) << 32);
    let d2 = (reply_port as u64) << 32;
    syscall::send(entry.port, PTY_IOCTL, d0, arg0, d2, arg1);

    let result = if let Some(msg) = syscall::recv_msg(reply_port) {
        if msg.tag == PTY_IOCTL_OK {
            Some((msg.data[0], msg.data[1]))
        } else {
            None
        }
    } else {
        None
    };

    syscall::port_destroy(reply_port);
    result
}
