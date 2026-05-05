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

/// no_std-friendly fmt::Write that streams formatted output one byte
/// at a time through the kernel's debug putchar syscall.  Used by the
/// panic handler to print the panic Arguments without needing
/// alloc/heap.  Each `write_char` is one syscall, so this is slow —
/// only acceptable on the panic path.
struct DebugWriter;
impl core::fmt::Write for DebugWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        crate::syscall::debug_puts(s.as_bytes());
        Ok(())
    }
}

fn debug_print_num(mut n: u64) {
    if n == 0 {
        crate::syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        crate::syscall::debug_putchar(buf[i]);
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // PANIC line: location (file:line:col) + message.  This is the
    // only signal a panicked thread leaves before exit(1) tears down
    // the whole task — without it, multi-thread tasks (linux_srv,
    // initramfs_srv) silently disappear when one thread faults.
    crate::syscall::debug_puts(b"PANIC: userspace at ");
    if let Some(loc) = info.location() {
        crate::syscall::debug_puts(loc.file().as_bytes());
        crate::syscall::debug_putchar(b':');
        debug_print_num(loc.line() as u64);
        crate::syscall::debug_putchar(b':');
        debug_print_num(loc.column() as u64);
    } else {
        crate::syscall::debug_puts(b"<no location>");
    }
    crate::syscall::debug_puts(b": ");
    let _ = core::fmt::Write::write_fmt(
        &mut DebugWriter,
        core::format_args!("{}", info.message()),
    );
    crate::syscall::debug_putchar(b'\n');
    crate::syscall::exit(1);
}
