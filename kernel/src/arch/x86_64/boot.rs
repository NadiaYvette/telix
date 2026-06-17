//! Early Rust entry point for x86-64.
//!
//! Called from boot.S after BSS is zeroed, 64-bit mode is active, and the stack is set up.
//! EDI (zero-extended to RDI) contains the physical address of the Multiboot info structure.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Multiboot info pointer saved from boot.
pub static MULTIBOOT_INFO: AtomicUsize = AtomicUsize::new(0);
/// EFI boot info pointer (0 if Multiboot boot).
pub static EFI_BOOT_INFO: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    static __kernel_end: u8;
}

/// RAM base address (1 MiB, above legacy region).
pub const RAM_BASE: usize = 0x10_0000;

/// Physical address past the end of the kernel image (from linker script).
///
/// `__kernel_end` is a linker symbol; its address carries the high-half VMA
/// because the linker links the kernel at `0xFFFFFFFF80100000+`.  We need to
/// return the corresponding PA (= VMA - KERNEL_VIRT_OFFSET) so the phys
/// allocator can correctly compute the managed-RAM range against `ram_end`,
/// which is itself a low PA.
pub fn kernel_end_addr() -> usize {
    const KERNEL_VIRT_OFFSET: usize = 0xFFFFFFFF80000000;
    unsafe { (&__kernel_end as *const u8 as usize) - KERNEL_VIRT_OFFSET }
}

/// High-half VMA past the end of the kernel image (the `__kernel_end` symbol
/// address directly, NOT the PA).  Used as the upper bound of the legitimate
/// kernel-text return-address range for the #208/#233 fp-chain scribble
/// detector (see `write_saved_sp`).
pub fn kernel_end_vma() -> usize {
    unsafe { &__kernel_end as *const u8 as usize }
}

/// High-half base VMA of the kernel image (linker `KERNEL_BASE`).
pub const KERNEL_BASE_VMA: u64 = 0xFFFFFFFF80100000;

/// Rust entry point called from assembly (Multiboot) or EFI stub.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry(boot_info: usize) -> ! {
    // Detect EFI vs Multiboot boot by checking for the "TEFI" magic.
    let magic = unsafe { *(boot_info as *const u32) };
    if magic == crate::firmware::efi_boot::EFI_BOOT_MAGIC {
        EFI_BOOT_INFO.store(boot_info, Ordering::Relaxed);
        crate::println!("Telix booting on x86-64 (EFI)");
        crate::println!("  EFI boot info at: {:#x}", boot_info);
    } else {
        MULTIBOOT_INFO.store(boot_info, Ordering::Relaxed);
        crate::println!("Telix booting on x86-64");
        crate::println!("  Multiboot info at: {:#x}", boot_info);
    }
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());

    crate::kmain()
}

/// Parse firmware tables (Multiboot memory map + ACPI MADT, or EFI boot info).
/// Must be called before phys::init() — firmware data lives in physical memory.
pub fn parse_firmware() {
    let efi = EFI_BOOT_INFO.load(Ordering::Relaxed);
    if efi != 0 {
        // EFI boot path: memory map, framebuffer, and RSDP from EFI loader.
        crate::firmware::efi_boot::parse(efi);
    } else {
        let info = MULTIBOOT_INFO.load(Ordering::Relaxed);
        if info != 0 {
            crate::firmware::multiboot::parse(info);
            let nr = crate::firmware::mem_regions().len();
            crate::println!("  Multiboot: {} memory regions", nr);

            // Extract kernel command line (flags bit 2 → cmdline at offset 16).
            let info_ptr = info as *const u8;
            let flags = unsafe { core::ptr::read_unaligned(info_ptr as *const u32) };
            if flags & (1 << 2) != 0 {
                let cmdline_addr =
                    unsafe { core::ptr::read_unaligned(info_ptr.add(16) as *const u32) }
                        as usize;
                if cmdline_addr != 0 {
                    let ptr = cmdline_addr as *const u8;
                    let mut len = 0usize;
                    while len < 1024 {
                        if unsafe { *ptr.add(len) } == 0 {
                            break;
                        }
                        len += 1;
                    }
                    if len > 0 {
                        let cmdline = unsafe { core::slice::from_raw_parts(ptr, len) };
                        crate::boot::cmdline::save_cmdline(cmdline);
                        crate::println!(
                            "  Multiboot: cmdline \"{}\"",
                            core::str::from_utf8(cmdline).unwrap_or("?")
                        );
                    }
                }
            }
        }
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
