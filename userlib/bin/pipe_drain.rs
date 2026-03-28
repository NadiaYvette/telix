#![no_std]
#![no_main]

//! Silent pipe reader: reads from pipe until EOF, discards data.
//! Used by bench.rs for pipe throughput measurement without serial output.

extern crate userlib;

use userlib::pipe;
use userlib::syscall;

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let pipe_port = arg0;
    let mut buf = [0u8; 16];
    loop {
        let n = pipe::pipe_read(pipe_port, &mut buf);
        if n == 0 {
            break; // EOF
        }
    }
}
