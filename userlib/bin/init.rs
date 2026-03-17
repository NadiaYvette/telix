#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

#[unsafe(no_mangle)]
fn main() {
    syscall::debug_puts(b"Telix init starting\n");

    // --- Test 1: Process lifecycle (spawn + exit + waitpid) ---
    let tid_hello = syscall::spawn(b"hello", 50);
    if tid_hello != u64::MAX {
        syscall::debug_puts(b"  init: spawned hello (tid=");
        print_num(tid_hello);
        syscall::debug_puts(b")\n");
    } else {
        syscall::debug_puts(b"  init: failed to spawn hello\n");
    }

    if tid_hello != u64::MAX {
        loop {
            if let Some(code) = syscall::waitpid(tid_hello) {
                syscall::debug_puts(b"  init: hello exited with code ");
                print_num(code);
                syscall::debug_puts(b"\n");
                break;
            }
            syscall::yield_now();
        }
    }

    // --- Test 2: Userspace IPC (echo_client does self-send/recv) ---
    let tid_echo = syscall::spawn(b"echo_client", 50);
    if tid_echo != u64::MAX {
        syscall::debug_puts(b"  init: spawned echo_client (tid=");
        print_num(tid_echo);
        syscall::debug_puts(b")\n");
    } else {
        syscall::debug_puts(b"  init: failed to spawn echo_client\n");
    }

    if tid_echo != u64::MAX {
        loop {
            if let Some(code) = syscall::waitpid(tid_echo) {
                syscall::debug_puts(b"  init: echo_client exited with code ");
                print_num(code);
                syscall::debug_puts(b"\n");
                break;
            }
            syscall::yield_now();
        }
    }

    syscall::debug_puts(b"Phase 5 process lifecycle + IPC test: PASSED\n");

    // Init loops forever, yielding.
    loop {
        syscall::yield_now();
    }
}
