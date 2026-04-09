//! Early Rust entry point for AArch64.
//!
//! Called from boot.S after BSS is zeroed and the stack is set up.
//! x0 contains the physical address of the device tree blob (DTB).

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::firmware::dtb::Fdt;

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
    // QEMU only sets x0 to the DTB address when it thinks it's booting a
    // Linux kernel (raw-image path in `hw/arm/boot.c`). Telix is loaded as
    // an ELF, so QEMU takes the `!is_linux` branch in `do_cpu_reset` and
    // jumps to the entry point with x0 = 0. However, QEMU still drops the
    // DTB at `info->loader_start` (the base of RAM) whenever the ELF image
    // doesn't cover that address. So on x0 == 0 we fall back to scanning
    // the base of RAM for the FDT magic.
    let dtb = {
        let from_x0 = DTB_ADDR.load(Ordering::Relaxed);
        if from_x0 != 0 && fdt_magic_ok(from_x0) {
            from_x0
        } else {
            find_fdt_in_ram().unwrap_or(0)
        }
    };

    if dtb != 0 {
        DTB_ADDR.store(dtb, Ordering::Relaxed);
        crate::println!("  Firmware: DTB at {:#x}", dtb);
        crate::firmware::dtb::parse_aarch64(dtb);
        let nr = crate::firmware::mem_regions().len();
        let nc = crate::firmware::cpu_count();
        let nd = crate::firmware::virtio_devices().len();
        crate::println!(
            "  Firmware: {} mem regions, {} CPUs, {} virtio devices",
            nr,
            nc,
            nd
        );

        // Extract kernel command line from /chosen/bootargs.
        extract_bootargs(dtb);
    } else {
        crate::println!("  Firmware: no DTB found at RAM base; hardware discovery disabled");
    }
}

/// FDT header magic (big-endian 0xd00dfeed).
const FDT_MAGIC_BE: u32 = 0xd00d_feed;

/// Check whether `addr` points at a plausible FDT blob.
fn fdt_magic_ok(addr: usize) -> bool {
    if addr == 0 || addr & 0x7 != 0 {
        return false;
    }
    // Safety: the aarch64 boot path identity-maps RAM; any address in the
    // first GiB of RAM is readable. We bound the scan so the caller never
    // passes a non-RAM address.
    let magic = unsafe { core::ptr::read_volatile(addr as *const u32) };
    u32::from_be(magic) == FDT_MAGIC_BE
}

/// Scan known-plausible DTB locations and return the first one that has
/// the FDT magic in its header. QEMU aarch64 virt, when loading an ELF
/// kernel whose lowest segment is above `info->loader_start`, drops the
/// DTB at `info->loader_start` == 0x40000000 (see `hw/arm/boot.c:937`).
fn find_fdt_in_ram() -> Option<usize> {
    // QEMU is supposed to place the DTB at `info->loader_start` == RAM
    // base when the ELF image doesn't cover it (see `hw/arm/boot.c:937`),
    // but the observed behavior on QEMU 10.1 with ELF `-kernel` loading
    // is that the DTB lands somewhere else. Scan:
    //   - Gap below the kernel image: [0x40000000 .. 0x40080000)
    //   - Above the kernel, before the initrd/stack region, up to 128 MiB
    let kernel_img_start = 0x4008_0000usize;
    let mut addr = QEMU_VIRT_RAM_BASE;
    while addr < kernel_img_start {
        if fdt_magic_ok(addr) {
            return Some(addr);
        }
        addr += 0x1000;
    }
    // Wider scan: first 128 MiB of RAM at 64 KiB granularity, skipping
    // the kernel image itself (whose .text is already occupied).
    let kernel_end = (kernel_end_addr() + 0xFFFF) & !0xFFFFusize;
    let mut addr = kernel_end;
    let end = QEMU_VIRT_RAM_BASE + 0x0800_0000; // 128 MiB
    while addr < end {
        if fdt_magic_ok(addr) {
            return Some(addr);
        }
        addr += 0x1_0000;
    }
    None
}

/// Extract bootargs from DTB /chosen node and save as kernel command line.
fn extract_bootargs(dtb_addr: usize) {
    let data = unsafe {
        let ptr = dtb_addr as *const u8;
        let header = core::slice::from_raw_parts(ptr, 8);
        let total_size = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        core::slice::from_raw_parts(ptr, total_size)
    };
    let fdt = match Fdt::new(data) {
        Ok(f) => f,
        Err(_) => return,
    };
    if let Some(chosen) = fdt.find_node(b"/chosen") {
        if let Some(bootargs) = chosen.property(b"bootargs") {
            // bootargs data may include a trailing null — strip it.
            let mut cmdline = bootargs.data;
            if cmdline.last() == Some(&0) {
                cmdline = &cmdline[..cmdline.len() - 1];
            }
            if !cmdline.is_empty() {
                crate::boot::cmdline::save_cmdline(cmdline);
                crate::println!("  DTB: bootargs \"{}\"",
                    core::str::from_utf8(cmdline).unwrap_or("?"));
            }
        }
    }
}
