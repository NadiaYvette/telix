//! Early Rust entry point for x86-64.
//!
//! Called from boot.S after BSS is zeroed, 64-bit mode is active, and the stack is set up.

unsafe extern "C" {
    static __kernel_end: u8;
}

/// RAM base address (1 MiB, above legacy region).
pub const RAM_BASE: usize = 0x10_0000;

/// Physical address past the end of the kernel image (from linker script).
pub fn kernel_end_addr() -> usize {
    unsafe { &__kernel_end as *const u8 as usize }
}

/// Rust entry point called from assembly.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry(_multiboot_info: usize) -> ! {
    // Serial is available immediately (I/O ports, no MMIO setup needed).
    crate::println!("Telix booting on x86-64");
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}
