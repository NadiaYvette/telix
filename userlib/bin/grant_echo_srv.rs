//! grant_echo_srv — call/reply server that echoes a client-leased buffer
//! with ASCII uppercasing applied in-place.
//!
//! **Completion-ABI pilot (Phase 0 step ④).** This server now receives via its
//! completion queue (blocking `io_reap_wait`) and replies via an `OP_REPLY`
//! submission, instead of the legacy `recv_with_cap`/`sys_reply` path. Calling
//! `Rings::setup` marks the task completion-enabled, so the kernel deliver path
//! routes incoming calls into our CQ (and never the recv_or_park/DirectTransfer
//! path that the legacy servers can wedge on). **Clients are unchanged** — they
//! still do a sync `sys_call`; the kernel bridges it: the call lands as a CQE
//! carrying the reply-cap in `delivered_cap`, and our `OP_REPLY` to that handle
//! completes the (legacy, parked) caller.
//!
//! Protocol (unchanged on the wire):
//!   request: tag = GRANT_ECHO_REQ, data[0] = granted_va, data[1] = length
//!   reply:   tag = GRANT_ECHO_OK | data[0] = bytes processed
//!            tag = GRANT_ECHO_ERR | data[0] = error code
//!
//! CQE decode: result = tag, inline[0]=va, inline[1]=len, delivered_cap = the
//! reply-cap handle. OP_REPLY: user_data = reply tag, inline[0] = reply data[0],
//! target_cap = the reply-cap handle.

#![no_std]
#![no_main]

extern crate userlib;

use userlib::completion::{Reply, Request, Rings};
use userlib::syscall;

pub const GRANT_ECHO_REQ: u64 = 0x6E01;
pub const GRANT_ECHO_OK: u64 = 0x6E02;
pub const GRANT_ECHO_ERR: u64 = 0x6E03;

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[grant_echo_srv] starting (completion ABI)\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[grant_echo_srv] port_create FAIL\n");
        syscall::exit(1);
    }
    if !syscall::ns_register(b"grant_echo_srv", port) {
        syscall::debug_puts(b"[grant_echo_srv] ns_register FAIL\n");
        syscall::exit(1);
    }

    // Switch to the completion ABI: allocate our SQ/CQ rings. This sets the
    // task's io_depth, so the kernel deliver path posts incoming calls to our
    // CQ + wakes us out of io_reap_wait (no legacy recv/park wedge).
    let rings = match Rings::setup(8) {
        Some(r) => r,
        None => {
            syscall::debug_puts(b"[grant_echo_srv] io_setup FAIL\n");
            syscall::exit(1);
        }
    };

    syscall::debug_puts(b"[grant_echo_srv] listening (completion)\n");

    // Classic request/reply server over the completion queue via the shared
    // `serve` helper (it does reap_wait → drain → OP_REPLY → submit). The
    // in-place uppercase transform happens inside the handler, before the
    // helper submits the reply — required, since freeing the reply-cap on
    // reply revokes the lease mapping at `va`.
    rings.serve(|req: Request| {
        let reply = if req.tag != GRANT_ECHO_REQ {
            Reply { tag: GRANT_ECHO_ERR, data: [1, 0, 0, 0, 0] }
        } else {
            let va = req.data[0] as usize;
            let len = req.data[1] as usize;
            if va == 0 || len == 0 || len > 4096 {
                Reply { tag: GRANT_ECHO_ERR, data: [2, 0, 0, 0, 0] }
            } else {
                // The leased page is mapped at `va` in our aspace (the client's
                // grant_pages_lease, live until our reply frees the reply-cap).
                unsafe {
                    let p = va as *mut u8;
                    for i in 0..len {
                        let b = core::ptr::read_volatile(p.add(i));
                        let u = if (b'a'..=b'z').contains(&b) { b - 32 } else { b };
                        core::ptr::write_volatile(p.add(i), u);
                    }
                }
                Reply { tag: GRANT_ECHO_OK, data: [len as u64, 0, 0, 0, 0] }
            }
        };
        Some(reply)
    });
}
