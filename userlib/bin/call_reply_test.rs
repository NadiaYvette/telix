//! Golden-path test for seL4-style call/reply IPC.
//!
//! Topology:
//!   - Main thread creates a port, spawns a server thread.
//!   - Server thread: recv_with_cap() on the port, reply() with modified msg.
//!   - Main thread: call() on the port, verifies reply matches expected.

#![no_std]
#![no_main]

extern crate userlib;

use core::sync::atomic::{AtomicU64, Ordering};

use userlib::syscall;

static SERVER_PORT: AtomicU64 = AtomicU64::new(0);
static SERVER_READY: AtomicU64 = AtomicU64::new(0);
static SERVER_DONE: AtomicU64 = AtomicU64::new(0);

const REQ_TAG: u64 = 0x1234_5678;
const REPLY_TAG: u64 = 0x8765_4321;

fn print_num_hex(mut n: u64) {
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

extern "C" fn server_thread_entry(_arg: u64) -> ! {
    let port = SERVER_PORT.load(Ordering::Acquire);
    SERVER_READY.store(1, Ordering::Release);

    syscall::debug_puts(b"  [cr_test] server: waiting for call\n");

    let msg = match syscall::recv_with_cap(port) {
        Some(m) => m,
        None => {
            syscall::debug_puts(b"  [cr_test] server: recv_with_cap FAIL\n");
            SERVER_DONE.store(2, Ordering::Release);
            syscall::exit(1);
        }
    };

    if msg.tag != REQ_TAG {
        syscall::debug_puts(b"  [cr_test] server: wrong tag ");
        print_num_hex(msg.tag);
        syscall::debug_puts(b"\n");
        SERVER_DONE.store(2, Ordering::Release);
        syscall::exit(1);
    }

    syscall::debug_puts(b"  [cr_test] server: got call, replying\n");

    // Reply: tag swapped, data words incremented so main can verify.
    let r = syscall::reply(
        REPLY_TAG,
        msg.data[0].wrapping_add(1),
        msg.data[1].wrapping_add(1),
        msg.data[2].wrapping_add(1),
        msg.data[3].wrapping_add(1),
        0,
    );
    if r != 0 {
        syscall::debug_puts(b"  [cr_test] server: reply FAIL status=");
        print_num_hex(r);
        syscall::debug_puts(b"\n");
        SERVER_DONE.store(2, Ordering::Release);
        syscall::exit(1);
    }

    SERVER_DONE.store(1, Ordering::Release);
    syscall::exit(0);
}

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[cr_test] starting\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[cr_test] port_create FAIL\n");
        syscall::exit(1);
    }
    SERVER_PORT.store(port, Ordering::Release);

    // Spawn server thread.
    let stack_va = syscall::mmap_anon(0, 1, 1).unwrap_or(0);
    if stack_va == 0 {
        syscall::debug_puts(b"[cr_test] stack alloc FAIL\n");
        syscall::exit(1);
    }
    let stack_top = stack_va + syscall::page_size();

    let tid = syscall::thread_create(
        server_thread_entry as u64,
        stack_top as u64,
        0,
    );
    if tid == u64::MAX {
        syscall::debug_puts(b"[cr_test] thread_create FAIL\n");
        syscall::exit(1);
    }

    // Wait for the server to be ready on the port.
    while SERVER_READY.load(Ordering::Acquire) == 0 {
        syscall::yield_now();
    }

    syscall::debug_puts(b"[cr_test] client: calling\n");
    syscall::debug_puts(b"[cr_test] client: pre-syscall\n");

    let reply = match syscall::call(port, REQ_TAG, 10, 20, 30, 40) {
        Some(m) => {
            syscall::debug_puts(b"[cr_test] client: call returned (Some)\n");
            m
        }
        None => {
            syscall::debug_puts(b"[cr_test] call returned None FAIL\n");
            syscall::exit(1);
        }
    };

    if reply.tag != REPLY_TAG {
        syscall::debug_puts(b"[cr_test] wrong reply tag ");
        print_num_hex(reply.tag);
        syscall::debug_puts(b"\n");
        syscall::exit(1);
    }
    if reply.data[0] != 11 || reply.data[1] != 21 || reply.data[2] != 31 || reply.data[3] != 41 {
        syscall::debug_puts(b"[cr_test] wrong reply data FAIL\n");
        syscall::exit(1);
    }

    // Wait for the server thread to finish cleanly.
    while SERVER_DONE.load(Ordering::Acquire) == 0 {
        syscall::yield_now();
    }
    if SERVER_DONE.load(Ordering::Acquire) != 1 {
        syscall::debug_puts(b"[cr_test] server reported error\n");
        syscall::exit(1);
    }

    syscall::debug_puts(b"[cr_test] OK\n");
    syscall::exit(0);
}
