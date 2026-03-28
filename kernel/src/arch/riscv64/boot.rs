//! Early Rust entry point for RISC-V 64.
//!
//! Called from boot.S after BSS is zeroed and the stack is set up.
//! a0 contains the physical address of the device tree blob (DTB).

use core::sync::atomic::{AtomicUsize, Ordering};

/// DTB pointer saved from boot for later parsing.
pub static DTB_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Boot hart ID (saved during early boot, used for SMP startup).
pub static BOOT_HART_ID: AtomicUsize = AtomicUsize::new(0);

/// QEMU virt machine RAM base address (RISC-V).
pub const QEMU_VIRT_RAM_BASE: usize = 0x8000_0000;

unsafe extern "C" {
    static __kernel_end: u8;
}

/// Physical address past the end of the kernel image (from linker script).
pub fn kernel_end_addr() -> usize {
    unsafe { &__kernel_end as *const u8 as usize }
}

/// Rust entry point called from assembly.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry(dtb_ptr: usize, hart_id: usize) -> ! {
    // Set tp = 0 for BSP (CPU 0) — used by smp::cpu_id().
    unsafe {
        core::arch::asm!("mv tp, zero");
    }

    DTB_ADDR.store(dtb_ptr, Ordering::Relaxed);
    BOOT_HART_ID.store(hart_id, Ordering::Relaxed);

    crate::println!("Telix booting on RISC-V 64 (boot hart {})", hart_id);
    crate::println!("  DTB at: {:#x}", dtb_ptr);
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}

/// Parse firmware tables (DTB) to discover hardware.
/// Must be called before phys::init() — the DTB blob lives in physical memory.
pub fn parse_firmware() {
    let mut dtb = DTB_ADDR.load(Ordering::Relaxed);

    // If a1 didn't carry a valid DTB address, scan near the top of RAM.
    if dtb == 0 {
        dtb = scan_for_dtb(QEMU_VIRT_RAM_BASE, 256 * 1024 * 1024);
    }

    if dtb != 0 {
        crate::println!("  Firmware: DTB at {:#x}", dtb);
        crate::firmware::dtb::parse_riscv64(dtb);
        let nr = crate::firmware::mem_regions().len();
        let nc = crate::firmware::cpu_count();
        let nd = crate::firmware::virtio_devices().len();
        crate::println!(
            "  Firmware: {} mem regions, {} CPUs, {} virtio devices",
            nr,
            nc,
            nd
        );
    }
}

/// Scan for the FDT magic (0xd00dfeed big-endian) at page-aligned addresses.
fn scan_for_dtb(ram_base: usize, ram_size: usize) -> usize {
    let magic = [0xd0u8, 0x0d, 0xfe, 0xed];
    let top = ram_base + ram_size;

    let mut addr = ram_base;
    while addr < top {
        let p = addr as *const [u8; 4];
        if unsafe { *p } == magic {
            return addr;
        }
        addr += 0x1000;
    }
    0
}
