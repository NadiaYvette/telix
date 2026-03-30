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
        crate::println!(
            "  Firmware: {} mem regions, {} CPUs, {} virtio devices",
            nr,
            nc,
            nd
        );

        // Extract kernel command line from /chosen/bootargs.
        extract_bootargs(dtb);
    }
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
