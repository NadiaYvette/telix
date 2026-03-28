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

/// Cap test child process.
/// arg0 = parent's private port (child gets full cap via arg0 auto-grant,
///   so we test denial using a DIFFERENT approach).
#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [cap_test] child started\n");

    // Test 1: Cap denial — try to RECV from the name server port.
    // We have a SEND cap for it (bootstrap) but NOT a RECV cap.
    // Cap check fails immediately before blocking, returning ECAP=2.
    let nsrv = syscall::nsrv_port();
    let result = syscall::recv(nsrv);
    if result == 2 {
        syscall::debug_puts(b"  [cap_test] recv without RECV cap: denied (err=2) OK\n");
    } else {
        syscall::debug_puts(b"  [cap_test] recv without cap: err=");
        print_num(result);
        syscall::debug_puts(b" FAIL\n");
        syscall::exit(1);
    }

    // Test 2: ns_lookup grants cap — look up a service, then send to it.
    syscall::debug_puts(b"  [cap_test] test2: ns_lookup\n");
    if let Some(svc_port) = syscall::ns_lookup(b"cap_svc") {
        syscall::debug_puts(b"  [cap_test] test2: got port, sending\n");
        let result2 = syscall::send_nb(svc_port, 0x99, 0xBEEF, 0);
        if result2 == 0 {
            syscall::debug_puts(b"  [cap_test] ns_lookup grants cap: send OK\n");
        } else {
            syscall::debug_puts(b"  [cap_test] ns_lookup grants cap: send FAIL\n");
            syscall::exit(1);
        }
    } else {
        syscall::debug_puts(b"  [cap_test] ns_lookup failed FAIL\n");
        syscall::exit(1);
    }

    // Test 3: Quota enforcement — parent set our port quota to 2.
    syscall::debug_puts(b"  [cap_test] test3: quota\n");
    let p1 = syscall::port_create();
    let p2 = syscall::port_create();
    let p3 = syscall::port_create();
    if p1 != u64::MAX && p2 != u64::MAX && p3 == u64::MAX {
        syscall::debug_puts(b"  [cap_test] quota: 2/2 ports created, 3rd denied OK\n");
    } else {
        syscall::debug_puts(b"  [cap_test] quota: FAIL\n");
        syscall::exit(1);
    }

    if p1 != u64::MAX {
        syscall::port_destroy(p1);
    }
    if p2 != u64::MAX {
        syscall::port_destroy(p2);
    }

    syscall::exit(0);
}
