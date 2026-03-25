//! POSIX-like poll() and select() for Telix.
//!
//! Sends POLL_CHECK messages to each FD's backing server to query readiness.
//! Blocking poll uses a yield-loop until an FD is ready or timeout expires.

use crate::fd::{self, FdType};
use crate::syscall;

// POSIX event bits.
pub const POLLIN: u16 = 0x0001;
pub const POLLPRI: u16 = 0x0002;
pub const POLLOUT: u16 = 0x0004;
pub const POLLERR: u16 = 0x0008;
pub const POLLHUP: u16 = 0x0010;
pub const POLLNVAL: u16 = 0x0020;

// Server poll tags.
const PIPE_POLL: u64 = 0x5050;
const UDS_POLL: u64 = 0x8090;
const CON_POLL: u64 = 0x3110;
const PTY_POLL: u64 = 0x9050;
const PIPE_OK: u64 = 0x5100;
const UDS_OK: u64 = 0x8100;
const CON_POLL_OK: u64 = 0x3111;
const PTY_POLL_OK: u64 = 0x9051;

#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: i32,
    pub events: u16,
    pub revents: u16,
}

/// Query a single FD's server for readiness. Returns revents mask.
fn poll_check_fd(entry: &fd::FdEntry, events: u16) -> u16 {
    match entry.fd_type {
        FdType::Console => {
            // Console is always writable (fire-and-forget). Not readable yet.
            let mut rev = 0u16;
            if events & POLLOUT != 0 {
                rev |= POLLOUT;
            }
            rev
        }
        FdType::Pipe => {
            let reply_port = syscall::port_create();
            let d2 = (events as u64) | ((reply_port as u64) << 32);
            syscall::send(entry.port, PIPE_POLL, entry.handle as u64, 0, d2, 0);
            let rev = if let Some(msg) = syscall::recv_msg(reply_port) {
                if msg.tag == PIPE_OK {
                    msg.data[0] as u16
                } else {
                    POLLERR
                }
            } else {
                POLLERR
            };
            syscall::port_destroy(reply_port);
            rev
        }
        FdType::Socket => {
            let reply_port = syscall::port_create();
            let d2 = (events as u64) | ((reply_port as u64) << 32);
            syscall::send(entry.port, UDS_POLL, entry.handle as u64, 0, d2, 0);
            let rev = if let Some(msg) = syscall::recv_msg(reply_port) {
                if msg.tag == UDS_OK {
                    msg.data[0] as u16
                } else {
                    POLLERR
                }
            } else {
                POLLERR
            };
            syscall::port_destroy(reply_port);
            rev
        }
        FdType::File => {
            // Files are always ready.
            let mut rev = 0u16;
            if events & POLLIN != 0 { rev |= POLLIN; }
            if events & POLLOUT != 0 { rev |= POLLOUT; }
            rev
        }
        FdType::Pty => {
            let reply_port = syscall::port_create();
            let d2 = (events as u64) | ((reply_port as u64) << 32);
            syscall::send(entry.port, PTY_POLL, entry.handle as u64, 0, d2, 0);
            let rev = if let Some(msg) = syscall::recv_msg(reply_port) {
                if msg.tag == PTY_POLL_OK {
                    msg.data[0] as u16
                } else {
                    POLLERR
                }
            } else {
                POLLERR
            };
            syscall::port_destroy(reply_port);
            rev
        }
        FdType::Port => {
            // Raw ports — no poll support.
            0
        }
        FdType::Free => POLLNVAL,
    }
}

/// Poll an array of file descriptors for readiness.
///
/// `timeout_ms`: -1 = block forever, 0 = non-blocking, >0 = timeout in ms.
/// Returns the number of FDs with non-zero revents, or 0 on timeout.
pub fn poll(fds: &mut [PollFd], timeout_ms: i32) -> i32 {
    let start = syscall::get_cycles();
    let freq = syscall::get_timer_freq();
    let timeout_cycles = if timeout_ms > 0 {
        (timeout_ms as u64) * freq / 1000
    } else {
        0
    };

    loop {
        let mut ready = 0i32;
        for pfd in fds.iter_mut() {
            pfd.revents = 0;
            let entry = match fd::fd_get(pfd.fd) {
                Some(e) => e,
                None => {
                    pfd.revents = POLLNVAL;
                    ready += 1;
                    continue;
                }
            };
            let revents = poll_check_fd(&entry, pfd.events);
            // POLLERR, POLLHUP, POLLNVAL are always reported regardless of events.
            pfd.revents = revents & (pfd.events | POLLERR | POLLHUP | POLLNVAL);
            if pfd.revents != 0 {
                ready += 1;
            }
        }

        if ready > 0 || timeout_ms == 0 {
            return ready;
        }

        // Check timeout.
        if timeout_ms > 0 {
            let elapsed = syscall::get_cycles() - start;
            if elapsed >= timeout_cycles {
                return 0;
            }
        }

        syscall::yield_now();
    }
}

/// POSIX select() — thin wrapper around poll().
///
/// `readfds`, `writefds`: bitmasks where bit N = FD N. Modified on return.
/// `timeout_ms`: -1 = block forever, 0 = non-blocking, >0 = timeout in ms.
/// Returns total number of ready FDs across all sets.
pub fn select(
    nfds: i32,
    readfds: &mut u64,
    writefds: &mut u64,
    timeout_ms: i32,
) -> i32 {
    let n = if nfds > 64 { 64 } else { nfds as usize };
    let rfds = *readfds;
    let wfds = *writefds;

    // Build PollFd array from bitmasks.
    let mut poll_fds = [PollFd { fd: -1, events: 0, revents: 0 }; 64];
    let mut count = 0usize;
    for i in 0..n {
        let mut events = 0u16;
        if rfds & (1u64 << i) != 0 {
            events |= POLLIN;
        }
        if wfds & (1u64 << i) != 0 {
            events |= POLLOUT;
        }
        if events != 0 {
            poll_fds[count] = PollFd {
                fd: i as i32,
                events,
                revents: 0,
            };
            count += 1;
        }
    }

    let result = poll(&mut poll_fds[..count], timeout_ms);

    // Convert back to bitmasks.
    *readfds = 0;
    *writefds = 0;
    let mut total = 0i32;
    for i in 0..count {
        let pfd = &poll_fds[i];
        let bit = 1u64 << (pfd.fd as u32);
        let mut hit = false;
        if pfd.revents & (POLLIN | POLLHUP | POLLERR) != 0 && rfds & bit != 0 {
            *readfds |= bit;
            hit = true;
        }
        if pfd.revents & (POLLOUT | POLLERR) != 0 && wfds & bit != 0 {
            *writefds |= bit;
            hit = true;
        }
        if hit {
            total += 1;
        }
    }
    total
}
