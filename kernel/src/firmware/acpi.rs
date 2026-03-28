//! Minimal ACPI table parser for x86_64.
//!
//! Scans for RSDP in the BIOS area, walks RSDT to find the MADT,
//! and parses MADT entries to discover CPU APIC IDs and interrupt
//! controller info.

/// Scan for RSDP and parse ACPI tables.
pub fn find_and_parse() {
    let rsdp = find_rsdp();
    if rsdp == 0 {
        crate::println!("  ACPI: RSDP not found");
        return;
    }
    crate::println!("  ACPI: RSDP at {:#x}", rsdp);

    // RSDP offset 16: RSDT physical address (u32).
    let rsdt_addr = unsafe { core::ptr::read_unaligned((rsdp + 16) as *const u32) } as usize;
    if rsdt_addr == 0 {
        return;
    }

    parse_rsdt(rsdt_addr);
}

/// Scan the BIOS data area (0xE0000..0xFFFFF) for the RSDP signature.
/// Returns the address of the RSDP, or 0 if not found.
fn find_rsdp() -> usize {
    let mut addr = 0xE_0000usize;
    while addr < 0x10_0000 {
        let sig = unsafe { core::slice::from_raw_parts(addr as *const u8, 8) };
        if sig == b"RSD PTR " {
            // Validate checksum: sum of first 20 bytes must be 0.
            let mut sum: u8 = 0;
            for i in 0..20 {
                sum = sum.wrapping_add(unsafe { *((addr + i) as *const u8) });
            }
            if sum == 0 {
                return addr;
            }
        }
        addr += 16;
    }
    0
}

/// Walk the RSDT and parse known tables.
fn parse_rsdt(rsdt_addr: usize) {
    let sig = unsafe { core::slice::from_raw_parts(rsdt_addr as *const u8, 4) };
    if sig != b"RSDT" {
        crate::println!("  ACPI: invalid RSDT signature at {:#x}", rsdt_addr);
        return;
    }

    let length = unsafe { core::ptr::read_unaligned((rsdt_addr + 4) as *const u32) } as usize;
    if length < 36 {
        return;
    }

    // Entries are u32 pointers starting at offset 36.
    let num_entries = (length - 36) / 4;
    for i in 0..num_entries {
        let table_ptr =
            unsafe { core::ptr::read_unaligned((rsdt_addr + 36 + i * 4) as *const u32) } as usize;
        if table_ptr == 0 {
            continue;
        }
        let table_sig = unsafe { core::slice::from_raw_parts(table_ptr as *const u8, 4) };

        if table_sig == b"APIC" {
            parse_madt(table_ptr);
        }
    }
}

/// Parse the MADT (Multiple APIC Description Table).
fn parse_madt(madt_addr: usize) {
    let length = unsafe { core::ptr::read_unaligned((madt_addr + 4) as *const u32) } as usize;

    // Offset 36: Local APIC address (u32).
    let lapic_addr = unsafe { core::ptr::read_unaligned((madt_addr + 36) as *const u32) };

    // Store interrupt controller info (LAPIC + IO APIC).
    super::set_irq_controller(super::IrqControllerInfo {
        kind: 3, // LAPIC + IO APIC
        _pad: 0,
        base0: lapic_addr as u64,
        base1: 0, // Updated below if IO APIC entry found
    });

    // Variable-length entries start at offset 44.
    let mut offset = 44;
    while offset + 2 <= length {
        let entry_type = unsafe { *((madt_addr + offset) as *const u8) };
        let entry_len = unsafe { *((madt_addr + offset + 1) as *const u8) } as usize;
        if entry_len < 2 {
            break;
        }

        match entry_type {
            0 => {
                // Type 0: Processor Local APIC (8 bytes).
                // Byte 2: ACPI processor ID, byte 3: APIC ID, bytes 4-7: flags.
                if entry_len >= 8 {
                    let apic_id = unsafe { *((madt_addr + offset + 3) as *const u8) } as u32;
                    let flags =
                        unsafe { core::ptr::read_unaligned((madt_addr + offset + 4) as *const u32) };
                    // Bit 0 = processor enabled, bit 1 = online capable.
                    let enabled = if flags & 0x3 != 0 { 1u32 } else { 0 };
                    super::push_cpu(super::CpuDesc { id: apic_id, flags: enabled });
                }
            }
            1 => {
                // Type 1: IO APIC (12 bytes).
                // Byte 4-7: IO APIC address.
                if entry_len >= 12 {
                    let io_apic_addr = unsafe {
                        core::ptr::read_unaligned((madt_addr + offset + 4) as *const u32)
                    };
                    let mut info = super::irq_controller();
                    info.base1 = io_apic_addr as u64;
                    super::set_irq_controller(info);
                }
            }
            _ => {}
        }

        offset += entry_len;
    }
}
