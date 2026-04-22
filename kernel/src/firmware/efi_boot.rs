//! EFI boot info parser.
//!
//! When the kernel is booted via the Telix EFI loader, a BootInfo
//! structure is placed at physical address 0x7000.  This module
//! parses it into the kernel's standard firmware data structures.

/// Magic value in the BootInfo header: "TEFI" = 0x54454649.
pub const EFI_BOOT_MAGIC: u32 = 0x54454649;

const BIF_FRAMEBUFFER: u32 = 1 << 0;
const BIF_RSDP: u32 = 1 << 1;

#[repr(C)]
struct BootInfo {
    magic: u32,
    flags: u32,
    rsdp_addr: u64,
    fb_addr: u64,
    fb_pitch: u32,
    fb_width: u32,
    fb_height: u32,
    fb_bpp: u32,
    mem_count: u32,
    _reserved: u32,
    // Followed by mem_count MemEntry structs.
}

#[repr(C)]
struct MemEntry {
    base: u64,
    size: u64,
    kind: u32, // 1 = usable RAM
    _pad: u32,
}

/// Parse EFI boot info at the given physical address.
pub fn parse(addr: usize) {
    let bi = unsafe { &*(addr as *const BootInfo) };
    if bi.magic != EFI_BOOT_MAGIC {
        crate::println!("  EFI boot: bad magic {:#x}", bi.magic);
        return;
    }

    crate::println!("  EFI boot info at {:#x}", addr);

    // Memory map.
    let entries_base = addr + core::mem::size_of::<BootInfo>();
    let mut usable_bytes: u64 = 0;
    for i in 0..bi.mem_count as usize {
        let entry = unsafe {
            &*((entries_base + i * core::mem::size_of::<MemEntry>()) as *const MemEntry)
        };
        if entry.kind == 1 && entry.size > 0 {
            super::push_mem_region(super::MemRegion {
                base: entry.base,
                size: entry.size,
            });
            usable_bytes += entry.size;
        }
    }
    crate::println!(
        "  EFI memory: {} entries, {} KiB usable",
        bi.mem_count,
        usable_bytes / 1024
    );

    // Framebuffer.
    if bi.flags & BIF_FRAMEBUFFER != 0 && bi.fb_addr != 0 {
        super::set_framebuffer(super::FramebufferInfo {
            addr: bi.fb_addr,
            pitch: bi.fb_pitch,
            width: bi.fb_width,
            height: bi.fb_height,
            bpp: bi.fb_bpp as u8,
            fb_type: 1, // direct RGB
            _pad: [0; 2],
        });
        crate::println!(
            "  EFI framebuffer: {}x{} @ {:#x}",
            bi.fb_width, bi.fb_height, bi.fb_addr
        );
    }

    // RSDP override for ACPI parser.
    if bi.flags & BIF_RSDP != 0 && bi.rsdp_addr != 0 {
        super::set_rsdp_override(bi.rsdp_addr);
        crate::println!("  EFI RSDP: {:#x}", bi.rsdp_addr);
    }
}
