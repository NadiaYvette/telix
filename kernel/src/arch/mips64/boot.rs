//! Early Rust entry point for MIPS64.
//!
//! Called from boot.S after BSS is zeroed and the stack is set up.

unsafe extern "C" {
    static __bss_end: u8;
}

/// Virtual address past the end of the kernel image (in KSEG0).
/// The kernel uses KSEG0 addresses as "physical" addresses throughout,
/// maintaining the PA == VA invariant that the MM subsystem requires.
pub fn kernel_end_addr() -> usize {
    unsafe { &__bss_end as *const u8 as usize }
}

/// Rust entry point called from assembly.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry() -> ! {
    crate::println!("Telix booting on MIPS64");
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}
