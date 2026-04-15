//! grant_echo_test — client side of the call/reply + GrantLease pilot.
//!
//! Spawns grant_echo_srv, stages a grant lease against the server's service
//! port, calls, and verifies:
//!   1. Reply tag/data look right.
//!   2. The source page (in our aspace) was mutated in-place by the server
//!      (uppercased), proving the lease mapped the same physical page on
//!      the server side.
//!   3. A second call with a fresh lease at the SAME dst_va succeeds — this
//!      proves the first lease was auto-revoked on reply (otherwise the
//!      second grant would collide with a stale mapping in the server).

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

const GRANT_ECHO_REQ: u64 = 0x6E01;
const GRANT_ECHO_OK: u64 = 0x6E02;

/// Address in the server's aspace where we want the lease mapped. Chosen to
/// not collide with anything the server might already have mapped.
const DST_VA: usize = 0xB_0000_0000;

fn print_hex(mut n: u64) {
    syscall::debug_puts(b"0x");
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let d = (n & 0xF) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

fn fail(msg: &[u8]) -> ! {
    syscall::debug_puts(b"[grant_echo_test] FAIL: ");
    syscall::debug_puts(msg);
    syscall::debug_puts(b"\n");
    syscall::exit(1);
}

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[grant_echo_test] starting\n");

    // Spawn the server.
    let srv_tid = syscall::spawn(b"grant_echo_srv", 50);
    if srv_tid == u64::MAX {
        fail(b"spawn grant_echo_srv");
    }

    // Wait for the server to register its service port.
    let srv_port = match syscall::ns_lookup_wait(b"grant_echo_srv") {
        Some(p) => p,
        None => fail(b"ns_lookup_wait"),
    };

    // Allocate a source page and seed it with lowercase text.
    let src_va = match syscall::mmap_anon(0, 1, 1) {
        Some(v) => v,
        None => fail(b"mmap_anon"),
    };
    let payload: &[u8] = b"hello grant lease world!";
    let len = payload.len();
    unsafe {
        for (i, b) in payload.iter().enumerate() {
            core::ptr::write_volatile((src_va + i) as *mut u8, *b);
        }
    }

    // --- Round 1: stage a lease, call, verify ---
    if !syscall::grant_pages_lease(srv_port, src_va, DST_VA, 1, false) {
        fail(b"grant_pages_lease #1");
    }

    let reply = match syscall::call(srv_port, GRANT_ECHO_REQ, DST_VA as u64, len as u64, 0, 0) {
        Some(m) => m,
        None => fail(b"call #1"),
    };
    if reply.tag != GRANT_ECHO_OK {
        syscall::debug_puts(b"[grant_echo_test] bad reply tag ");
        print_hex(reply.tag);
        syscall::debug_puts(b"\n");
        syscall::exit(1);
    }
    if reply.data[0] != len as u64 {
        fail(b"reply len mismatch");
    }

    // Source page should have been mutated in place (uppercased).
    let expected: &[u8] = b"HELLO GRANT LEASE WORLD!";
    for i in 0..len {
        let got = unsafe { core::ptr::read_volatile((src_va + i) as *const u8) };
        if got != expected[i] {
            syscall::debug_puts(b"[grant_echo_test] byte ");
            print_hex(i as u64);
            syscall::debug_puts(b" got=");
            print_hex(got as u64);
            syscall::debug_puts(b" want=");
            print_hex(expected[i] as u64);
            syscall::debug_puts(b"\n");
            syscall::exit(1);
        }
    }

    // --- Round 2: same DST_VA proves round-1 lease was auto-revoked ---
    // Reset source to lowercase so we can tell the second round happened.
    unsafe {
        for (i, b) in payload.iter().enumerate() {
            core::ptr::write_volatile((src_va + i) as *mut u8, *b);
        }
    }
    if !syscall::grant_pages_lease(srv_port, src_va, DST_VA, 1, false) {
        fail(b"grant_pages_lease #2 (lease not auto-revoked?)");
    }
    let reply2 = match syscall::call(srv_port, GRANT_ECHO_REQ, DST_VA as u64, len as u64, 0, 0) {
        Some(m) => m,
        None => fail(b"call #2"),
    };
    if reply2.tag != GRANT_ECHO_OK || reply2.data[0] != len as u64 {
        fail(b"round 2 reply");
    }
    for i in 0..len {
        let got = unsafe { core::ptr::read_volatile((src_va + i) as *const u8) };
        if got != expected[i] {
            fail(b"round 2 source mismatch");
        }
    }

    syscall::debug_puts(b"[grant_echo_test] OK\n");
    syscall::exit(0);
}
