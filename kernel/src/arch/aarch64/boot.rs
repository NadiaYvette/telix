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

/// Parse firmware tables (DTB) to discover hardware.
/// Must be called before phys::init() — the DTB blob lives in physical memory.
pub fn parse_firmware() {
    let dtb = DTB_ADDR.load(Ordering::Relaxed);

    // TODO: QEMU 10.x aarch64 virt doesn't pass DTB address in x0 and
    // doesn't place the DTB at a discoverable address in RAM. Once the
    // bootloader protocol is sorted out, enable scanning here.
    if dtb != 0 {
        crate::println!("  Firmware: DTB at {:#x}", dtb);
        crate::firmware::dtb::parse_aarch64(dtb);
        let nr = crate::firmware::mem_regions().len();
        let nc = crate::firmware::cpu_count();
        let nd = crate::firmware::virtio_devices().len();
        crate::println!("  Firmware: {} mem regions, {} CPUs, {} virtio devices", nr, nc, nd);
    }
}
