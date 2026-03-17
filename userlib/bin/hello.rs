#![no_std]
#![no_main]

extern crate userlib;

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    userlib::syscall::debug_puts(b"Hello from userspace!\n");
    let tid = userlib::syscall::thread_id();
    userlib::syscall::debug_puts(b"  thread id = ");
    // Print tid as decimal.
    if tid == 0 {
        userlib::syscall::debug_putchar(b'0');
    } else {
        let mut buf = [0u8; 20];
        let mut n = tid;
        let mut i = 0;
        while n > 0 {
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
        while i > 0 {
            i -= 1;
            userlib::syscall::debug_putchar(buf[i]);
        }
    }
    userlib::syscall::debug_putchar(b'\n');
}
