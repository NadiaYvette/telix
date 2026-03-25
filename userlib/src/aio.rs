//! Async I/O helpers — non-blocking submit, collect, and barrier.
//!
//! Uses the existing `send_nb_4` / `recv_nb_msg` syscalls to provide
//! an async completion model over the standard IO_READ/IO_WRITE protocol.

use crate::syscall;

const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE_OK: u64 = 0x301;
const IO_BARRIER: u64 = 0x600;
const IO_BARRIER_OK: u64 = 0x601;
const IO_ERROR: u64 = 0xF00;

/// Result of an async I/O completion.
pub struct AioResult {
    pub tag: u64,
    pub request_id: u64,
    pub bytes: u64,
}

/// Submit an async read request (non-blocking).
/// Returns true if the message was queued, false if the port queue was full.
pub fn aio_read(
    port: u64,
    offset: u64,
    length: u32,
    reply_port: u64,
    grant_va: usize,
    request_id: u64,
) -> bool {
    let d2 = (length as u64) | ((reply_port as u64) << 32);
    let ret = syscall::send_nb_4(port, IO_READ, request_id, offset, d2, grant_va as u64);
    ret == 0
}

/// Poll for an async I/O completion (non-blocking).
/// Returns `Some(AioResult)` if a completion was available, `None` otherwise.
pub fn aio_collect(reply_port: u64) -> Option<AioResult> {
    let msg = syscall::recv_nb_msg(reply_port)?;
    match msg.tag {
        IO_READ_OK | IO_WRITE_OK => Some(AioResult {
            tag: msg.tag,
            request_id: msg.data[1],
            bytes: msg.data[0],
        }),
        IO_ERROR => Some(AioResult {
            tag: msg.tag,
            request_id: 0,
            bytes: msg.data[0], // error code
        }),
        _ => Some(AioResult {
            tag: msg.tag,
            request_id: msg.data[1],
            bytes: msg.data[0],
        }),
    }
}

/// Send a barrier and block until the server confirms all prior requests are complete.
pub fn aio_barrier(port: u64, reply_port: u64) {
    let d2 = (reply_port as u64) << 32;
    syscall::send(port, IO_BARRIER, 0, 0, d2, 0);
    // Block until IO_BARRIER_OK.
    loop {
        if let Some(msg) = syscall::recv_msg(reply_port) {
            if msg.tag == IO_BARRIER_OK {
                return;
            }
        }
    }
}
