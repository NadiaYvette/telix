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

/// Static buffer for the FW_CFG FDT.  Sized to 64 KiB which covers
/// QEMU virt's typical DTB (a few KiB).  Sits in .bss — no allocator
/// needed because this fires before `phys::init`.
static mut FDT_BUF: [u8; 64 * 1024] = [0u8; 64 * 1024];

/// Read FW_CFG `etc/memmap` and push the available memory regions to
/// the firmware registry.  Returns `true` if any regions were pushed.
///
/// QEMU's `etc/memmap` is a sequence of `e820_entry` records:
///   - base:   u64 little-endian
///   - length: u64 little-endian
///   - type:   u32 little-endian (1 = available, others = reserved)
/// Total 20 bytes per entry.  We push entries with type == 1.
///
/// LoongArch64 QEMU virt uses ACPI tables (no `etc/fdt`), so this is
/// the primary memory-detection path for the arch.
fn read_fwcfg_memmap() -> bool {
    unsafe {
        fwcfg_select(0x0000);
        let mut sig = [0u8; 4];
        for b in &mut sig {
            *b = fwcfg_read_byte();
        }
        if &sig != b"QEMU" {
            return false;
        }

        fwcfg_select(0x0019);
        let count = fwcfg_read_be32() as usize;
        if count == 0 || count > 1024 {
            return false;
        }

        let mut memmap_key: u16 = 0;
        let mut memmap_size: u32 = 0;
        for _ in 0..count {
            let size = fwcfg_read_be32();
            let key = fwcfg_read_be16();
            let _reserved = fwcfg_read_be16();
            let mut name = [0u8; 56];
            for b in &mut name {
                *b = fwcfg_read_byte();
            }
            if name.starts_with(b"etc/memmap\0") {
                memmap_key = key;
                memmap_size = size;
            }
        }

        if memmap_key == 0 || memmap_size == 0 {
            return false;
        }

        // QEMU loongarch64 `etc/memmap` is 24 bytes/entry:
        //   - base:   u64 LE
        //   - length: u64 LE
        //   - type:   u64 LE (1 = available)
        // Two entries for QEMU virt with `-m 2G`: low 256 MiB at 0 and
        // high 1.75 GiB at 0x8000_0000 (the 2 GiB boundary).
        fwcfg_select(memmap_key);
        let mut raw = [0u8; 1024];
        let read_size = (memmap_size as usize).min(raw.len());
        for i in 0..read_size {
            raw[i] = fwcfg_read_byte();
        }
        const ENTRY_BYTES: usize = 24;
        let n_entries = read_size / ENTRY_BYTES;
        let mut pushed = false;
        for i in 0..n_entries {
            let start = i * ENTRY_BYTES;
            let base = u64::from_le_bytes(raw[start..start + 8].try_into().unwrap());
            let length = u64::from_le_bytes(raw[start + 8..start + 16].try_into().unwrap());
            let kind = u64::from_le_bytes(raw[start + 16..start + 24].try_into().unwrap());
            if kind == 1 && length > 0 {
                crate::firmware::push_mem_region(crate::firmware::MemRegion {
                    base,
                    size: length,
                });
                pushed = true;
            }
        }
        pushed
    }
}

/// Read the FDT (`etc/fdt`) from FW_CFG into FDT_BUF and return a
/// borrowed slice.  Returns `None` if FW_CFG is absent or the file
/// isn't present.  Currently unused on loongarch64 (QEMU virt uses
/// ACPI + etc/memmap, not DTB), but kept for any QEMU machine type
/// that does ship a DTB.
#[allow(dead_code)]
fn read_fwcfg_fdt() -> Option<&'static [u8]> {
    unsafe {
        fwcfg_select(0x0000);
        let mut sig = [0u8; 4];
        for b in &mut sig {
            *b = fwcfg_read_byte();
        }
        if &sig != b"QEMU" {
            return None;
        }

        fwcfg_select(0x0019);
        let count = fwcfg_read_be32() as usize;
        if count == 0 || count > 1024 {
            return None;
        }

        let mut fdt_key: u16 = 0;
        let mut fdt_size: u32 = 0;
        for _ in 0..count {
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
        const FDT_BUF_LEN: usize = 64 * 1024;
        let len = (fdt_size as usize).min(FDT_BUF_LEN);
        fwcfg_select(fdt_key);
        let buf_ptr = &raw mut FDT_BUF as *mut u8;
        for i in 0..len {
            *buf_ptr.add(i) = fwcfg_read_byte();
        }
        Some(core::slice::from_raw_parts(buf_ptr as *const u8, len))
    }
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

/// Parse firmware tables. For LoongArch64, read FW_CFG memmap + cmdline.
pub fn parse_firmware() {
    read_fwcfg_cmdline();

    // QEMU loongarch64 virt uses ACPI tables + `etc/memmap` (e820-
    // style entries) rather than a DTB, so read memory regions from
    // there.  Without this the kernel hardcoded 256 MiB regardless of
    // `-m`.
    let _memmap_ok = read_fwcfg_memmap();

    // LoongArch64 QEMU virt: PCI ECAM at hardcoded 0x2000_0000.
    crate::firmware::set_pci_ecam(crate::firmware::PciEcamInfo {
        base: 0x2000_0000,
        size: 256 * 32 * 8 * 4096, // 256 buses
        segment: 0,
        bus_start: 0,
        bus_end: 255,
        _pad: 0,
    });

    // QEMU loongarch64 virt defaults to 4 cores.  Until we parse the
    // ACPI MADT for the real CPU set, register them statically.
    // CSR.CPUID values run 0..N-1.  Capped to MAX_CPUS by
    // detect_cpu_count.
    for id in 0..4u32 {
        crate::firmware::push_cpu(crate::firmware::CpuDesc { id, flags: 1 });
    }
}
