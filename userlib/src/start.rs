//! Minimal runtime entry point for Telix userspace programs.

unsafe extern "Rust" {
    fn main();
}

/// Entry point called by the ELF loader. Calls main(), then exits.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe { main(); }
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
