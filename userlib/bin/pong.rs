#![no_std]
#![no_main]

//! IPC echo server for ping-pong benchmark.
//! arg0 = port to listen on.

extern crate userlib;

use userlib::syscall;

const BENCH_PING: u64 = 0x6000;
const BENCH_PONG: u64 = 0x6001;
const BENCH_QUIT: u64 = 0x60FF;

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let port = arg0;
    loop {
        if let Some(msg) = syscall::recv_msg(port) {
            if msg.tag == BENCH_QUIT {
                break;
            }
            if msg.tag == BENCH_PING {
                let reply_port = msg.data[0];
                syscall::send_nb(reply_port, BENCH_PONG, 0, 0);
            }
        }
    }
    syscall::exit(0);
}
