//! Early Rust entry point for MIPS64.
//!
//! Called from boot.S after BSS is zeroed and the stack is set up.
//! QEMU Malta YAMON emulation passes: a0=argc, a1=argv pointer array.

use core::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    static __bss_end: u8;
}

/// YAMON argc/argv saved from boot.
static YAMON_ARGC: AtomicUsize = AtomicUsize::new(0);
static YAMON_ARGV: AtomicUsize = AtomicUsize::new(0);

/// Virtual address past the end of the kernel image (in KSEG0).
/// The kernel uses KSEG0 addresses as "physical" addresses throughout,
/// maintaining the PA == VA invariant that the MM subsystem requires.
pub fn kernel_end_addr() -> usize {
    unsafe { &__bss_end as *const u8 as usize }
}

/// Rust entry point called from assembly.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry(argc: usize, argv: usize) -> ! {
    YAMON_ARGC.store(argc, Ordering::Relaxed);
    YAMON_ARGV.store(argv, Ordering::Relaxed);

    crate::println!("Telix booting on MIPS64");
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}

/// Parse YAMON argv to extract kernel command line and save it.
fn extract_yamon_cmdline() {
    let argc = YAMON_ARGC.load(Ordering::Relaxed);
    let argv_ptr = YAMON_ARGV.load(Ordering::Relaxed);
    crate::println!("  YAMON: argc={}, argv={:#x}", argc, argv_ptr);
    if argc == 0 || argv_ptr == 0 || argc > 64 {
        return;
    }

    // YAMON passes argv as an array of pointers to null-terminated strings.
    // argv[0] is the kernel name, argv[1..] are the command line arguments.
    // We concatenate argv[1..] into a single command line string.
    // YAMON passes argv as array of 32-bit pointers (sign-extended to KSEG0).
    let argv = argv_ptr as *const u32;
    let mut buf = [0u8; 256];
    let mut pos = 0;

    for i in 1..argc {
        let raw = unsafe { *argv.add(i) } as usize;
        // Sign-extend 32-bit KSEG0 address to 64-bit.
        let arg = (raw as i32 as i64 as usize) as *const u8;
        if arg.is_null() {
            break;
        }
        if pos > 0 && pos < buf.len() {
            buf[pos] = b' ';
            pos += 1;
        }
        let mut p = arg;
        while pos < buf.len() {
            let c = unsafe { *p };
            if c == 0 {
                break;
            }
            buf[pos] = c;
            pos += 1;
            p = unsafe { p.add(1) };
        }
    }

    if pos > 0 {
        crate::boot::cmdline::save_cmdline(&buf[..pos]);
        crate::println!(
            "  YAMON: cmdline \"{}\"",
            core::str::from_utf8(&buf[..pos]).unwrap_or("?")
        );
    }
}

/// Parse firmware tables. For MIPS64 Malta, extract YAMON argv.
pub fn parse_firmware() {
    extract_yamon_cmdline();
}
