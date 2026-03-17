#![no_std]
#![no_main]

extern crate userlib;

#[unsafe(no_mangle)]
fn main() {
    userlib::syscall::debug_puts(b"Telix init starting\n");

    // Spawn the hello program.
    let tid = userlib::syscall::spawn(b"hello", 50);
    if tid != u64::MAX {
        userlib::syscall::debug_puts(b"  init: spawned hello\n");
    } else {
        userlib::syscall::debug_puts(b"  init: failed to spawn hello\n");
    }

    // Init loops forever, yielding.
    loop {
        userlib::syscall::yield_now();
    }
}
