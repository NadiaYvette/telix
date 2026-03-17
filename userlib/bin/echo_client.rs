#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

#[allow(dead_code)]
fn print_hex(n: u64) {
    syscall::debug_puts(b"0x");
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        let d = (val & 0xF) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        val >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  echo_client: IPC self-test\n");

    // Create our own port.
    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"  echo_client: port_create failed\n");
        return;
    }

    // Send a message to our own port (non-blocking since queue is empty).
    let status = syscall::send_nb(port as u32, 0xCAFE, 0xDEAD, 0xBEEF);
    if status != 0 {
        syscall::debug_puts(b"  echo_client: send failed\n");
        return;
    }

    // Receive the message back.
    let status = syscall::recv(port as u32);
    if status != 0 {
        syscall::debug_puts(b"  echo_client: recv failed\n");
        return;
    }

    syscall::debug_puts(b"  echo_client: IPC self-test PASSED\n");
}
