#![no_std]
#![no_main]

//! Grant benchmark helper. Reports aspace_id, then waits for quit.
//! arg0 = coordination port.

extern crate userlib;

use userlib::syscall;

const GRANT_BENCH_ASPACE: u64 = 0x7000;
const GRANT_BENCH_QUIT: u64 = 0x70FF;

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let port = arg0 as u32;
    // Report our aspace_id to the parent.
    let my_aspace = syscall::aspace_id();
    syscall::send_nb(port, GRANT_BENCH_ASPACE, my_aspace as u64, 0);
    // Wait for quit.
    loop {
        if let Some(msg) = syscall::recv_msg(port) {
            if msg.tag == GRANT_BENCH_QUIT {
                break;
            }
        }
    }
    syscall::exit(0);
}
