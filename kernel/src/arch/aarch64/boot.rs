//! Early Rust entry point for AArch64.
//!
//! Called from boot.S after BSS is zeroed and the stack is set up.
//! x0 contains the physical address of the device tree blob (DTB).

use core::sync::atomic::{AtomicUsize, Ordering};

/// DTB pointer saved from boot for later parsing.
pub static DTB_ADDR: AtomicUsize = AtomicUsize::new(0);

/// QEMU virt machine RAM base address.
pub const QEMU_VIRT_RAM_BASE: usize = 0x4000_0000;

unsafe extern "C" {
    static __kernel_end: u8;
}

/// Physical address past the end of the kernel image (from linker script).
pub fn kernel_end_addr() -> usize {
    unsafe { &__kernel_end as *const u8 as usize }
}

/// Rust entry point called from assembly.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry(dtb_ptr: usize) -> ! {
    DTB_ADDR.store(dtb_ptr, Ordering::Relaxed);

    crate::println!("Telix booting on AArch64");
    crate::println!("  DTB at: {:#x}", dtb_ptr);
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}
