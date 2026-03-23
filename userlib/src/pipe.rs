//! Byte-stream pipes over IPC ports.
//!
//! Legacy API: pipe_write/pipe_read/pipe_close_writer use a raw IPC port
//! with PIPE_DATA/PIPE_EOF tags (used by pipe_upper.rs).
//!
//! New API (Phase 59): pipe() returns FD pairs via the pipe server.
//! pipe_write_fd/pipe_read_fd/pipe_close_fd use the FD table.

use crate::fd::{self, FdType, O_RDONLY, O_WRONLY};
use crate::syscall;

// Legacy tags (raw port protocol, used by pipe_upper).
const PIPE_DATA: u64 = 0x5000;
const PIPE_EOF_LEGACY: u64 = 0x5001;

// Pipe server protocol tags (Phase 59).
const PIPE_CREATE: u64 = 0x5010;
const PIPE_WRITE_TAG: u64 = 0x5020;
const PIPE_READ_TAG: u64 = 0x5030;
const PIPE_CLOSE_TAG: u64 = 0x5040;
const PIPE_OK: u64 = 0x5100;
const PIPE_EOF_TAG: u64 = 0x51FF;

// ── Legacy API (backward compat) ──────────────────────────────────

/// Write `buf` into the pipe, chunking into 16-byte messages.
pub fn pipe_write(pipe_port: u32, buf: &[u8]) {
    let mut offset = 0;
    while offset < buf.len() {
        let chunk_len = (buf.len() - offset).min(16);
        let mut w0 = 0u64;
        let mut w1 = 0u64;
        for i in 0..chunk_len.min(8) {
            w0 |= (buf[offset + i] as u64) << (i * 8);
        }
        for i in 8..chunk_len {
            w1 |= (buf[offset + i] as u64) << ((i - 8) * 8);
        }
        syscall::send(pipe_port, PIPE_DATA, w0, w1, chunk_len as u64, 0);
        offset += chunk_len;
    }
}

/// Signal end-of-stream on the pipe.
pub fn pipe_close_writer(pipe_port: u32) {
    syscall::send(pipe_port, PIPE_EOF_LEGACY, 0, 0, 0, 0);
}

/// Read from the pipe into `buf`. Returns bytes read (0 = EOF).
pub fn pipe_read(pipe_port: u32, buf: &mut [u8]) -> usize {
    if let Some(msg) = syscall::recv_msg(pipe_port) {
        match msg.tag {
            PIPE_DATA => {
                let len = (msg.data[2] as usize).min(16).min(buf.len());
                let words = [msg.data[0], msg.data[1]];
                for i in 0..len {
                    buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
                }
                len
            }
            _ => 0, // PIPE_EOF or unexpected
        }
    } else {
        0
    }
}

// ── New FD-integrated API (Phase 59) ──────────────────────────────

/// Create a pipe, returning (read_fd, write_fd).
/// Requires the pipe server ("pipe") to be running.
pub fn pipe() -> Option<(i32, i32)> {
    let pipe_port = syscall::ns_lookup(b"pipe")?;
    let reply_port = syscall::port_create() as u32;
    let d2 = (reply_port as u64) << 32;
    syscall::send(pipe_port, PIPE_CREATE, 0, 0, d2, 0);
    let msg = syscall::recv_msg(reply_port)?;
    syscall::port_destroy(reply_port);
    if msg.tag != PIPE_OK {
        return None;
    }
    let read_handle = msg.data[0] as u32;
    let write_handle = msg.data[1] as u32;
    let read_fd = fd::fd_open(pipe_port, read_handle, FdType::Pipe, O_RDONLY)?;
    let write_fd = fd::fd_open(pipe_port, write_handle, FdType::Pipe, O_WRONLY)?;
    Some((read_fd, write_fd))
}

/// Write `buf` to a pipe FD. Returns bytes written, or -1 on error.
pub fn pipe_write_fd(fd_num: i32, buf: &[u8]) -> isize {
    let entry = match fd::fd_get(fd_num) {
        Some(e) => e,
        None => return -1,
    };
    let mut offset = 0;
    while offset < buf.len() {
        let chunk_len = (buf.len() - offset).min(16);
        let mut w0 = 0u64;
        let mut w1 = 0u64;
        for i in 0..chunk_len.min(8) {
            w0 |= (buf[offset + i] as u64) << (i * 8);
        }
        for i in 8..chunk_len {
            w1 |= (buf[offset + i] as u64) << ((i - 8) * 8);
        }
        // Fire-and-forget: d2 low16 = len, high32 = 0xFFFFFFFF (no reply).
        let d2 = (chunk_len as u64) | (0xFFFFFFFF_u64 << 32);
        syscall::send(entry.port, PIPE_WRITE_TAG, entry.handle as u64, w0, d2, w1);
        offset += chunk_len;
    }
    buf.len() as isize
}

/// Read from a pipe FD into `buf`. Returns bytes read (0 = EOF, -1 = error).
/// Like POSIX read(), returns as soon as any data is available (short read).
pub fn pipe_read_fd(fd_num: i32, buf: &mut [u8]) -> isize {
    let entry = match fd::fd_get(fd_num) {
        Some(e) => e,
        None => return -1,
    };
    let reply_port = syscall::port_create() as u32;
    let d2 = (reply_port as u64) << 32;
    syscall::send(entry.port, PIPE_READ_TAG, entry.handle as u64, 0, d2, 0);
    let msg = match syscall::recv_msg(reply_port) {
        Some(m) => m,
        None => {
            syscall::port_destroy(reply_port);
            return -1;
        }
    };
    syscall::port_destroy(reply_port);

    if msg.tag == PIPE_EOF_TAG {
        return 0;
    }
    if msg.tag != PIPE_OK {
        return -1;
    }

    let n = (msg.data[2] as usize).min(16);
    let words = [msg.data[0], msg.data[1]];
    let copy_len = n.min(buf.len());
    for i in 0..copy_len {
        buf[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
    }
    copy_len as isize
}

/// Close a pipe FD. Returns true on success.
pub fn pipe_close_fd(fd_num: i32) -> bool {
    let entry = match fd::fd_get(fd_num) {
        Some(e) => e,
        None => return false,
    };
    let reply_port = syscall::port_create() as u32;
    let d2 = (reply_port as u64) << 32;
    syscall::send(entry.port, PIPE_CLOSE_TAG, entry.handle as u64, 0, d2, 0);
    let _ = syscall::recv_msg(reply_port);
    syscall::port_destroy(reply_port);
    fd::fd_close(fd_num);
    true
}
