//! Minimal runtime entry point for Telix userspace programs.

unsafe extern "Rust" {
    fn main(arg0: u64, arg1: u64, arg2: u64);
}

/// Entry point called by the ELF loader. Calls main(arg0, arg1, arg2), then exits.
/// Arguments are passed in registers (x0-x2 / a0-a2 / rdi,rsi,rdx) by the kernel.
#[unsafe(no_mangle)]
pub extern "C" fn _start(arg0: u64, arg1: u64, arg2: u64) -> ! {
    unsafe {
        main(arg0, arg1, arg2);
    }
    crate::syscall::exit(0);
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Best-effort: print panic message char by char.
    let msg = b"PANIC: userspace\n";
    for &ch in msg {
        crate::syscall::debug_putchar(ch);
    }
    let _ = info;
    crate::syscall::exit(1);
}
