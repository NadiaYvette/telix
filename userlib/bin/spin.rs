#![no_std]
#![no_main]

//! Trivial process that spins forever, yielding each iteration.
//! Used by the Phase 20 kill test.

extern crate userlib;

use userlib::syscall;

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    loop {
        syscall::yield_block();
    }
}
