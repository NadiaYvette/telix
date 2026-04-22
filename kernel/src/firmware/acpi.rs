//! ACPI table parser for x86_64.
//!
//! Scans for RSDP in the BIOS area, walks RSDT/XSDT to discover all
//! tables, and parses specific tables (MADT for CPUs/interrupt controllers,
//! MCFG for PCI ECAM). Table descriptors are recorded in the firmware
//! module so userspace acpi_srv can map and parse them.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Bounding region of all discovered ACPI tables (set during walk).
static TABLE_REGION_BASE: AtomicUsize = AtomicUsize::new(0);
static TABLE_REGION_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Returns (base, size) of the physical region bounding all ACPI tables.
/// (0, 0) if no ACPI tables were found.
pub fn table_region_bounds() -> (usize, usize) {
    let base = TABLE_REGION_BASE.load(Ordering::Acquire);
    let size = TABLE_REGION_SIZE.load(Ordering::Acquire);
    (base, size)
}

/// Scan for RSDP and parse ACPI tables.
pub fn find_and_parse() {
    let rsdp = find_rsdp();
    if rsdp == 0 {
        crate::println!("  ACPI: RSDP not found");
        return;
    }
    crate::println!("  ACPI: RSDP at {:#x}", rsdp);

    // Check RSDP revision. Revision >= 2 means ACPI 2.0+ with XSDT.
    let revision = unsafe { *((rsdp + 15) as *const u8) };

    if revision >= 2 {
        // XSDT address is a 64-bit pointer at offset 24.
        let xsdt_addr =
            unsafe { core::ptr::read_unaligned((rsdp + 24) as *const u64) } as usize;
        if xsdt_addr != 0 {
            crate::println!("  ACPI: XSDT at {:#x} (rev {})", xsdt_addr, revision);
            walk_sdt(xsdt_addr, true);
            return;
        }
    }

    // Fall back to RSDT (32-bit pointer at offset 16).
    let rsdt_addr =
        unsafe { core::ptr::read_unaligned((rsdp + 16) as *const u32) } as usize;
    if rsdt_addr == 0 {
        return;
    }
    crate::println!("  ACPI: RSDT at {:#x}", rsdt_addr);
    walk_sdt(rsdt_addr, false);
}

/// Walk an RSDT (is_xsdt=false, 4-byte pointers) or XSDT (is_xsdt=true,
/// 8-byte pointers). Records all table descriptors and parses known tables.
fn walk_sdt(sdt_addr: usize, is_xsdt: bool) {
    let expected_sig = if is_xsdt { b"XSDT" } else { b"RSDT" };
    let sig = unsafe { core::slice::from_raw_parts(sdt_addr as *const u8, 4) };
    if sig != expected_sig {
        crate::println!(
            "  ACPI: invalid {} signature at {:#x}",
            if is_xsdt { "XSDT" } else { "RSDT" },
            sdt_addr
        );
        return;
    }

    let length =
        unsafe { core::ptr::read_unaligned((sdt_addr + 4) as *const u32) } as usize;
    if length < 36 {
        return;
    }

    let ptr_size = if is_xsdt { 8 } else { 4 };
    let num_entries = (length - 36) / ptr_size;

    // Track bounding region across all tables (including the root SDT itself).
    let mut min_addr = sdt_addr;
    let mut max_end = sdt_addr + length;

    for i in 0..num_entries {
        let table_ptr = if is_xsdt {
            unsafe {
                core::ptr::read_unaligned((sdt_addr + 36 + i * 8) as *const u64) as usize
            }
        } else {
            unsafe {
                core::ptr::read_unaligned((sdt_addr + 36 + i * 4) as *const u32) as usize
            }
        };
        if table_ptr == 0 {
            continue;
        }

        // Read table signature (4 bytes at +0) and length (u32 at +4).
        let table_sig = unsafe { core::slice::from_raw_parts(table_ptr as *const u8, 4) };
        let table_len =
            unsafe { core::ptr::read_unaligned((table_ptr + 4) as *const u32) };

        // Update bounding region.
        if table_ptr < min_addr {
            min_addr = table_ptr;
        }
        let end = table_ptr + table_len as usize;
        if end > max_end {
            max_end = end;
        }

        // Record table descriptor.
        let mut sig4 = [0u8; 4];
        sig4.copy_from_slice(table_sig);
        super::push_acpi_table(super::AcpiTableDesc {
            signature: sig4,
            _pad: 0,
            phys_addr: table_ptr as u64,
            length: table_len,
            _pad2: 0,
        });

        // Parse known tables.
        if table_sig == b"APIC" {
            parse_madt(table_ptr);
        } else if table_sig == b"MCFG" {
            parse_mcfg(table_ptr, table_len);
        }
    }

    // Store bounding region.
    let region_size = max_end - min_addr;
    TABLE_REGION_BASE.store(min_addr, Ordering::Release);
    TABLE_REGION_SIZE.store(region_size, Ordering::Release);

    crate::println!(
        "  ACPI: {} tables discovered, region {:#x}+{:#x}",
        super::acpi_table_count(),
        min_addr,
        region_size
    );
}

/// Find the RSDP.  If the EFI boot path provided an override, use it;
/// otherwise scan the BIOS data area (0xE0000..0xFFFFF).
fn find_rsdp() -> usize {
    // EFI boot path provides the RSDP address directly.
    let ovr = super::rsdp_override();
    if ovr != 0 {
        return ovr as usize;
    }
    // Legacy BIOS scan.
    let mut addr = 0xE_0000usize;
    while addr < 0x10_0000 {
        let sig = unsafe { core::slice::from_raw_parts(addr as *const u8, 8) };
        if sig == b"RSD PTR " {
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
                    let flags = unsafe {
                        core::ptr::read_unaligned((madt_addr + offset + 4) as *const u32)
                    };
                    // Bit 0 = processor enabled, bit 1 = online capable.
                    let enabled = if flags & 0x3 != 0 { 1u32 } else { 0 };
                    super::push_cpu(super::CpuDesc {
                        id: apic_id,
                        flags: enabled,
                    });
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
            2 => {
                // Type 2: Interrupt Source Override (10 bytes).
                // Byte 2: bus (always 0 = ISA), byte 3: source IRQ,
                // bytes 4-7: Global System Interrupt, bytes 8-9: flags.
                if entry_len >= 10 {
                    let source = unsafe { *((madt_addr + offset + 3) as *const u8) };
                    let gsi = unsafe {
                        core::ptr::read_unaligned((madt_addr + offset + 4) as *const u32)
                    };
                    let flags = unsafe {
                        core::ptr::read_unaligned((madt_addr + offset + 8) as *const u16)
                    };
                    #[cfg(target_arch = "x86_64")]
                    crate::arch::x86_64::ioapic::register_iso(source, gsi, flags);
                }
            }
            _ => {}
        }

        offset += entry_len;
    }
}

/// Parse the MCFG (Memory Mapped Configuration Space Base Address Description Table).
/// Extracts PCI ECAM base address for PCIe configuration access.
fn parse_mcfg(mcfg_addr: usize, table_len: u32) {
    // MCFG header is 36 bytes (standard ACPI header) + 8 bytes reserved = 44.
    // Each allocation entry is 16 bytes starting at offset 44:
    //   u64 base_address, u16 segment_group, u8 start_bus, u8 end_bus, u32 reserved
    if table_len < 60 {
        return; // Need at least one entry
    }

    let base = unsafe { core::ptr::read_unaligned((mcfg_addr + 44) as *const u64) };
    let segment = unsafe { core::ptr::read_unaligned((mcfg_addr + 52) as *const u16) };
    let bus_start = unsafe { *((mcfg_addr + 54) as *const u8) };
    let bus_end = unsafe { *((mcfg_addr + 55) as *const u8) };

    if base == 0 {
        return;
    }

    // ECAM size: (bus_end - bus_start + 1) buses × 32 devs × 8 funcs × 4096 bytes.
    let bus_count = (bus_end as u64) - (bus_start as u64) + 1;
    let size = bus_count * 32 * 8 * 4096;

    crate::println!(
        "  ACPI MCFG: ECAM at {:#x}, segment {}, buses {}..{}, size {:#x}",
        base, segment, bus_start, bus_end, size
    );

    super::set_pci_ecam(super::PciEcamInfo {
        base,
        size,
        segment,
        bus_start,
        bus_end,
        _pad: 0,
    });
}
