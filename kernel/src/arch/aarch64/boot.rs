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
    // Discovery priority:
    //   1. DTB address in x0 (Linux-style boot, rarely works for ELF)
    //   2. Scan RAM for FDT magic (works when QEMU drops DTB at loader_start)
    //   3. Read "etc/fdt" from QEMU fw_cfg MMIO (always works)
    let dtb = {
        let from_x0 = DTB_ADDR.load(Ordering::Relaxed);
        if from_x0 != 0 && fdt_magic_ok(from_x0) {
            from_x0
        } else {
            find_fdt_in_ram().unwrap_or(0)
        }
    };

    // If RAM scan found it, use that address directly.
    let dtb_addr = if dtb != 0 {
        crate::println!("  Firmware: DTB at {:#x} (RAM scan)", dtb);
        DTB_ADDR.store(dtb, Ordering::Relaxed);
        dtb
    } else {
        // Last resort: read DTB from fw_cfg into a static buffer.
        match fwcfg_read_fdt() {
            Some(addr) => {
                crate::println!("  Firmware: DTB at {:#x} (fw_cfg)", addr);
                DTB_ADDR.store(addr, Ordering::Relaxed);
                addr
            }
            None => {
                crate::println!("  Firmware: no DTB found (RAM scan + fw_cfg both failed)");
                return;
            }
        }
    };

    crate::firmware::dtb::parse_aarch64(dtb_addr);
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
    extract_bootargs(dtb_addr);
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

/// Scan RAM for FDT magic. QEMU aarch64 virt places DTB either:
///   - At RAM base (0x40000000) if the kernel doesn't cover it
///   - Just above the kernel image (aligned to page boundary)
///   - At the end of RAM minus DTB size (observed on QEMU 9+)
fn find_fdt_in_ram() -> Option<usize> {
    // Phase 1: Check below the kernel image [0x40000000 .. 0x40080000).
    let kernel_img_start = 0x4008_0000usize;
    let mut addr = QEMU_VIRT_RAM_BASE;
    while addr < kernel_img_start {
        if fdt_magic_ok(addr) {
            return Some(addr);
        }
        addr += 0x1000;
    }
    // Phase 2: Scan above the kernel up to end of RAM (256 MiB) at 4K steps.
    // QEMU may place DTB immediately after the kernel image.
    let kernel_end = (kernel_end_addr() + 0xFFF) & !0xFFFusize;
    let ram_end = QEMU_VIRT_RAM_BASE + 256 * 1024 * 1024;
    let mut addr = kernel_end;
    while addr < ram_end {
        if fdt_magic_ok(addr) {
            return Some(addr);
        }
        addr += 0x1000;
    }
    None
}

// ---------------------------------------------------------------------------
// QEMU fw_cfg MMIO interface (aarch64 virt: base 0x09020000)
// ---------------------------------------------------------------------------

const FWCFG_BASE: usize = 0x0902_0000;
const FWCFG_DATA: usize = FWCFG_BASE + 0x00; // 8-bit read (byte stream)
const FWCFG_SEL: usize = FWCFG_BASE + 0x08; // 16-bit write (selector key, big-endian)

/// Static buffer for DTB read from fw_cfg. 128 KiB covers any QEMU virt DTB.
/// Aligned to 8 bytes so fdt_magic_ok's alignment check passes.
#[repr(C, align(8))]
struct FdtBuf([u8; 128 * 1024]);
static mut FDT_BUF: FdtBuf = FdtBuf([0u8; 128 * 1024]);

unsafe fn fwcfg_select(key: u16) {
    core::ptr::write_volatile(FWCFG_SEL as *mut u16, key.to_be());
}

unsafe fn fwcfg_read_byte() -> u8 {
    core::ptr::read_volatile(FWCFG_DATA as *const u8)
}

unsafe fn fwcfg_read_be32() -> u32 {
    let mut b = [0u8; 4];
    for byte in &mut b {
        *byte = fwcfg_read_byte();
    }
    u32::from_be_bytes(b)
}

unsafe fn fwcfg_read_be16() -> u16 {
    let mut b = [0u8; 2];
    for byte in &mut b {
        *byte = fwcfg_read_byte();
    }
    u16::from_be_bytes(b)
}

/// Read the DTB from QEMU fw_cfg ("etc/fdt" file).
/// Returns the address of the static FDT_BUF on success.
fn fwcfg_read_fdt() -> Option<usize> {
    unsafe {
        // Verify fw_cfg exists: key 0x0000 → signature "QEMU".
        fwcfg_select(0x0000);
        let mut sig = [0u8; 4];
        for b in &mut sig {
            *b = fwcfg_read_byte();
        }
        if &sig != b"QEMU" {
            return None;
        }

        // Read file directory (key 0x0019) to find "etc/fdt".
        fwcfg_select(0x0019);
        let count = fwcfg_read_be32() as usize;
        if count == 0 || count > 2048 {
            return None;
        }

        let mut fdt_key: u16 = 0;
        let mut fdt_size: u32 = 0;

        for _i in 0..count {
            let size = fwcfg_read_be32();
            let key = fwcfg_read_be16();
            let _reserved = fwcfg_read_be16();
            let mut name = [0u8; 56];
            for b in &mut name {
                *b = fwcfg_read_byte();
            }

            if name.starts_with(b"etc/fdt\0") {
                fdt_key = key;
                fdt_size = size;
            }
        }

        if fdt_key == 0 || fdt_size == 0 {
            return None;
        }

        let buf_ptr = core::ptr::addr_of_mut!(FDT_BUF) as *mut u8;
        let buf_cap = 128 * 1024;
        let read_size = (fdt_size as usize).min(buf_cap);

        // Select the FDT file and read into our static buffer.
        fwcfg_select(fdt_key);
        for i in 0..read_size {
            *buf_ptr.add(i) = fwcfg_read_byte();
        }

        // Verify the blob starts with FDT magic.
        let buf_addr = buf_ptr as usize;
        if !fdt_magic_ok(buf_addr) {
            return None;
        }

        crate::println!("  fw_cfg: read {} byte DTB from key {:#x}", read_size, fdt_key);
        Some(buf_addr)
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
