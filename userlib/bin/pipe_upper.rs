#![no_std]
#![no_main]

//! Test binary for pipe IPC: reads from pipe, uppercases, prints via debug_puts.

extern crate userlib;

use userlib::syscall;
use userlib::pipe;

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let pipe_port = arg0;
    let mut buf = [0u8; 16];
    loop {
        let n = pipe::pipe_read(pipe_port, &mut buf);
        if n == 0 {
            break; // EOF
        }
        // Uppercase.
        for i in 0..n {
            if buf[i] >= b'a' && buf[i] <= b'z' {
                buf[i] -= 32;
            }
        }
        syscall::debug_puts(&buf[..n]);
    }
}
