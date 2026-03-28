//! Early Rust entry point for x86-64.
//!
//! Called from boot.S after BSS is zeroed, 64-bit mode is active, and the stack is set up.
//! EDI (zero-extended to RDI) contains the physical address of the Multiboot info structure.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Multiboot info pointer saved from boot.
pub static MULTIBOOT_INFO: AtomicUsize = AtomicUsize::new(0);

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
pub extern "C" fn _rust_entry(multiboot_info: usize) -> ! {
    MULTIBOOT_INFO.store(multiboot_info, Ordering::Relaxed);

    // Serial is available immediately (I/O ports, no MMIO setup needed).
    crate::println!("Telix booting on x86-64");
    crate::println!("  Multiboot info at: {:#x}", multiboot_info);
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}

/// Parse firmware tables (Multiboot memory map + ACPI MADT).
/// Must be called before phys::init() — Multiboot info is in physical memory.
pub fn parse_firmware() {
    let info = MULTIBOOT_INFO.load(Ordering::Relaxed);
    if info != 0 {
        crate::firmware::multiboot::parse(info);
        let nr = crate::firmware::mem_regions().len();
        crate::println!("  Multiboot: {} memory regions", nr);
    }

    crate::firmware::acpi::find_and_parse();
    let nc = crate::firmware::cpu_count();
    let irq = crate::firmware::irq_controller();
    if nc > 0 {
        crate::println!(
            "  ACPI: {} CPUs, LAPIC at {:#x}, IO APIC at {:#x}",
            nc,
            irq.base0,
            irq.base1
        );
    }
}
