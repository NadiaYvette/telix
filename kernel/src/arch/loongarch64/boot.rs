//! Early Rust entry point for LoongArch64.
//!
//! Called from boot.S after BSS is zeroed and the stack is set up.
//! QEMU virt machine: a0 = core_id, a1 = fw_cfg / boot params pointer.

use core::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    static __bss_end: u8;
}

/// FW_CFG / boot params pointer saved from boot.
static FW_CFG_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Physical address past the end of the kernel image.
pub fn kernel_end_addr() -> usize {
    unsafe { &__bss_end as *const u8 as usize }
}

/// Rust entry point called from assembly.
#[unsafe(no_mangle)]
pub extern "C" fn _rust_entry(core_id: usize, fw_cfg: usize) -> ! {
    FW_CFG_ADDR.store(fw_cfg, Ordering::Relaxed);

    crate::println!("Telix booting on LoongArch64");
    crate::println!("  Kernel end at: {:#x}", kernel_end_addr());
    crate::println!("  core_id={}, fw_cfg={:#x}", core_id, fw_cfg);

    crate::kmain()
}

// FW_CFG MMIO helpers.
const FWCFG_BASE: usize = 0x1e020000;
const FWCFG_DATA: usize = FWCFG_BASE + 0x00;
const FWCFG_SEL: usize = FWCFG_BASE + 0x08;

unsafe fn fwcfg_select(key: u16) {
    core::ptr::write_volatile(FWCFG_SEL as *mut u16, key.to_be());
}
unsafe fn fwcfg_read_byte() -> u8 {
    core::ptr::read_volatile(FWCFG_DATA as *const u8)
}
unsafe fn fwcfg_read_be32() -> u32 {
    let mut b = [0u8; 4];
    for byte in &mut b { *byte = fwcfg_read_byte(); }
    u32::from_be_bytes(b)
}
unsafe fn fwcfg_read_be16() -> u16 {
    let mut b = [0u8; 2];
    for byte in &mut b { *byte = fwcfg_read_byte(); }
    u16::from_be_bytes(b)
}

/// Read kernel command line via FW_CFG file directory.
/// Finds "etc/fdt" in FW_CFG, reads the FDT, and extracts /chosen/bootargs.
fn read_fwcfg_cmdline() {
    use crate::firmware::dtb::Fdt;

    unsafe {
        // Verify FW_CFG exists by reading signature (key 0x0000 → "QEMU").
        fwcfg_select(0x0000);
        let mut sig = [0u8; 4];
        for b in &mut sig { *b = fwcfg_read_byte(); }
        if &sig != b"QEMU" {
            return;
        }

        // Read file directory (key 0x0019) to find "etc/fdt".
        fwcfg_select(0x0019);
        let count = fwcfg_read_be32() as usize;
        if count == 0 || count > 1024 {
            return;
        }

        crate::println!("  FW_CFG: {} files", count);
        let mut fdt_key: u16 = 0;
        let mut fdt_size: u32 = 0;
        for idx in 0..count {
            let size = fwcfg_read_be32();
            let key = fwcfg_read_be16();
            let _reserved = fwcfg_read_be16();
            let mut name = [0u8; 56];
            for b in &mut name { *b = fwcfg_read_byte(); }

            // Print first 10 files for debugging.
            if name.starts_with(b"opt/telix/cmdline\0") {
                fdt_key = key;
                fdt_size = size;
            }
        }

        if fdt_key == 0 || fdt_size == 0 || fdt_size > 256 {
            return;
        }

        // Read raw cmdline string from FW_CFG.
        fwcfg_select(fdt_key);
        let mut buf = [0u8; 256];
        let read_size = fdt_size as usize;
        for i in 0..read_size {
            buf[i] = fwcfg_read_byte();
        }

        // Strip trailing null.
        let mut len = read_size;
        while len > 0 && buf[len - 1] == 0 {
            len -= 1;
        }
        if len > 0 {
            crate::boot::cmdline::save_cmdline(&buf[..len]);
            crate::println!(
                "  FW_CFG: cmdline \"{}\"",
                core::str::from_utf8(&buf[..len]).unwrap_or("?")
            );
        }
    }
}

/// Parse firmware tables. For LoongArch64, read FW_CFG FDT.
pub fn parse_firmware() {
    read_fwcfg_cmdline();
}
