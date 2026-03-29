//! Early Rust entry point for LoongArch64.
//!
//! Called from boot.S after BSS is zeroed and the stack is set up.

unsafe extern "C" {
    static __bss_end: u8;
}

/// Physical address past the end of the kernel image.
pub fn kernel_end_addr() -> usize {
    unsafe { &__bss_end as *const u8 as usize }
}

/// Rust entry point called from assembly.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry(_core_id: usize) -> ! {
    crate::println!("Telix booting on LoongArch64");
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}
