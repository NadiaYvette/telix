//! Multiboot1 info structure parser for x86_64.
//!
//! Parses the memory map from the Multiboot info structure passed by
//! the bootloader via EBX.

/// Parse the Multiboot1 info structure and push discovered RAM regions.
pub fn parse(info_addr: usize) {
    let info = info_addr as *const u8;

    // Multiboot info: flags at offset 0.
    let flags = unsafe { core::ptr::read_unaligned(info as *const u32) };

    // Bit 6: mmap_length and mmap_addr fields are valid.
    if flags & (1 << 6) == 0 {
        crate::println!("  Multiboot: no memory map (flags={:#x})", flags);
        return;
    }

    let mmap_length = unsafe { core::ptr::read_unaligned(info.add(44) as *const u32) } as usize;
    let mmap_addr = unsafe { core::ptr::read_unaligned(info.add(48) as *const u32) } as usize;

    // Bit 12: framebuffer info is valid.
    if flags & (1 << 12) != 0 {
        let fb_addr = unsafe { core::ptr::read_unaligned(info.add(88) as *const u64) };
        let fb_pitch = unsafe { core::ptr::read_unaligned(info.add(96) as *const u32) };
        let fb_width = unsafe { core::ptr::read_unaligned(info.add(100) as *const u32) };
        let fb_height = unsafe { core::ptr::read_unaligned(info.add(104) as *const u32) };
        let fb_bpp = unsafe { core::ptr::read_unaligned(info.add(108) as *const u8) };
        let fb_type = unsafe { core::ptr::read_unaligned(info.add(109) as *const u8) };

        if fb_addr != 0 && fb_width > 0 && fb_height > 0 {
            crate::println!(
                "  Multiboot: framebuffer {}x{}x{} at {:#x} pitch={}",
                fb_width, fb_height, fb_bpp, fb_addr, fb_pitch
            );
            super::set_framebuffer(super::FramebufferInfo {
                addr: fb_addr,
                pitch: fb_pitch,
                width: fb_width,
                height: fb_height,
                bpp: fb_bpp,
                fb_type,
                _pad: [0; 2],
            });
        }
    }

    let mut offset = 0;
    while offset < mmap_length {
        let entry = (mmap_addr + offset) as *const u8;
        // Each entry: size(u32), base(u64), length(u64), type(u32).
        // `size` does NOT include the 4-byte size field itself.
        let entry_size = unsafe { core::ptr::read_unaligned(entry as *const u32) } as usize;
        let base = unsafe { core::ptr::read_unaligned(entry.add(4) as *const u64) };
        let length = unsafe { core::ptr::read_unaligned(entry.add(12) as *const u64) };
        let mem_type = unsafe { core::ptr::read_unaligned(entry.add(20) as *const u32) };

        if mem_type == 1 && length > 0 {
            super::push_mem_region(super::MemRegion { base, size: length });
        }

        offset += entry_size + 4;
    }
}
