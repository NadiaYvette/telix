#![no_std]
#![no_main]

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Nadia Chambers

//! ACPI table server for x86_64.
//!
//! Maps the ACPI table bounding region via an MMIO cap granted by the kernel,
//! then serves parsed table data to other userspace services over IPC.
//!
//! ## IPC protocol
//!
//! Clients use `syscall::call(acpi_port, tag, d0, d1, d2, d3)`.
//! The server replies via `syscall::reply(...)`.
//!
//! - `ACPI_TABLE_COUNT` (0x7000): → data[0] = number of ACPI tables
//! - `ACPI_TABLE_INFO`  (0x7001): data[0] = index → data[0] = sig_u32, data[1] = length
//! - `ACPI_GET_MCFG`    (0x7002): → data[0] = ecam_base, data[1] = segment|bus_start|bus_end
//! - `ACPI_GET_MADT_OVRDE` (0x7003): data[0] = index → data[0] = bus|source|gsi|flags
//! - `ACPI_GET_FADT_PM` (0x7004): → data[0] = pm1a_evt_blk, data[1] = pm1a_cnt_blk,
//!                                    data[2] = sci_int | acpi_enable<<16 | pm_tmr_blk<<32

extern crate userlib;

use userlib::syscall;

// --- IPC tags ---
const ACPI_TABLE_COUNT: u64 = 0x7000;
const ACPI_TABLE_INFO: u64 = 0x7001;
const ACPI_GET_MCFG: u64 = 0x7002;
const ACPI_GET_MADT_OVRDE: u64 = 0x7003;
const ACPI_GET_FADT_PM: u64 = 0x7004;
const ACPI_ERROR: u64 = 0x70FF;

// --- Table structures ---
const MAX_TABLES: usize = 16;
const MAX_MADT_OVERRIDES: usize = 24;

#[derive(Clone, Copy)]
struct TableEntry {
    sig: [u8; 4],
    va: usize,
    length: u32,
}

#[derive(Clone, Copy, Default)]
struct MadtOverride {
    bus: u8,
    source: u8,
    gsi: u32,
    flags: u16,
}

#[derive(Clone, Copy, Default)]
struct McfgInfo {
    base: u64,
    segment: u16,
    bus_start: u8,
    bus_end: u8,
}

#[derive(Clone, Copy, Default)]
struct FadtInfo {
    pm1a_evt_blk: u32,
    pm1a_cnt_blk: u32,
    sci_int: u16,
    acpi_enable: u8,
    pm_tmr_blk: u32,
}

struct AcpiState {
    tables: [TableEntry; MAX_TABLES],
    table_count: usize,
    region_va: usize,
    region_phys: u64,
    mcfg: McfgInfo,
    mcfg_valid: bool,
    fadt: FadtInfo,
    fadt_valid: bool,
    overrides: [MadtOverride; MAX_MADT_OVERRIDES],
    override_count: usize,
}

// --- Helpers ---

fn print_hex(val: u64) {
    let mut buf = [b'0'; 16];
    let mut v = val;
    for i in (0..16).rev() {
        let nibble = (v & 0xF) as u8;
        buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        v >>= 4;
    }
    // Skip leading zeros.
    let mut start = 0;
    while start < 15 && buf[start] == b'0' {
        start += 1;
    }
    syscall::debug_puts(b"0x");
    syscall::debug_puts(&buf[start..]);
}

fn print_num(val: u64) {
    if val == 0 {
        syscall::debug_puts(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut v = val;
    let mut i = 20;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    syscall::debug_puts(&buf[i..]);
}

fn sig_to_u32(sig: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*sig)
}

/// Read a u32 from a VA (little-endian, unaligned-safe).
unsafe fn read_u32(va: usize) -> u32 {
    let p = va as *const u8;
    let b0 = unsafe { core::ptr::read_volatile(p) };
    let b1 = unsafe { core::ptr::read_volatile(p.add(1)) };
    let b2 = unsafe { core::ptr::read_volatile(p.add(2)) };
    let b3 = unsafe { core::ptr::read_volatile(p.add(3)) };
    u32::from_le_bytes([b0, b1, b2, b3])
}

/// Read a u16 from a VA (little-endian, unaligned-safe).
unsafe fn read_u16(va: usize) -> u16 {
    let p = va as *const u8;
    let b0 = unsafe { core::ptr::read_volatile(p) };
    let b1 = unsafe { core::ptr::read_volatile(p.add(1)) };
    u16::from_le_bytes([b0, b1])
}

/// Read a u64 from a VA (little-endian, unaligned-safe).
unsafe fn read_u64(va: usize) -> u64 {
    let lo = unsafe { read_u32(va) } as u64;
    let hi = unsafe { read_u32(va + 4) } as u64;
    lo | (hi << 32)
}

/// Read a u8 from a VA.
unsafe fn read_u8(va: usize) -> u8 {
    unsafe { core::ptr::read_volatile(va as *const u8) }
}

// --- Table parsers ---

impl AcpiState {
    fn phys_to_va(&self, phys: u64) -> Option<usize> {
        let offset = phys.checked_sub(self.region_phys)?;
        Some(self.region_va + offset as usize)
    }

    fn parse_mcfg(&mut self, va: usize, length: u32) {
        // MCFG entries start at offset 44, each is 16 bytes.
        if length < 60 {
            return;
        }
        let entry_va = va + 44;
        unsafe {
            self.mcfg.base = read_u64(entry_va);
            self.mcfg.segment = read_u16(entry_va + 8);
            self.mcfg.bus_start = read_u8(entry_va + 10);
            self.mcfg.bus_end = read_u8(entry_va + 11);
            self.mcfg_valid = true;
        }
        syscall::debug_puts(b"  [acpi_srv] MCFG: ECAM at ");
        print_hex(self.mcfg.base);
        syscall::debug_puts(b", buses ");
        print_num(self.mcfg.bus_start as u64);
        syscall::debug_puts(b"..");
        print_num(self.mcfg.bus_end as u64);
        syscall::debug_puts(b"\n");
    }

    fn parse_madt(&mut self, va: usize, length: u32) {
        // Walk variable-length MADT entries starting at offset 44.
        // We're interested in type 2 (interrupt source override).
        let mut off = 44usize;
        while off + 2 <= length as usize {
            let entry_type = unsafe { read_u8(va + off) };
            let entry_len = unsafe { read_u8(va + off + 1) } as usize;
            if entry_len < 2 || off + entry_len > length as usize {
                break;
            }
            if entry_type == 2 && entry_len >= 10 && self.override_count < MAX_MADT_OVERRIDES {
                unsafe {
                    let ov = MadtOverride {
                        bus: read_u8(va + off + 2),
                        source: read_u8(va + off + 3),
                        gsi: read_u32(va + off + 4),
                        flags: read_u16(va + off + 8),
                    };
                    self.overrides[self.override_count] = ov;
                    self.override_count += 1;
                }
            }
            off += entry_len;
        }
    }

    fn parse_fadt(&mut self, va: usize, length: u32) {
        // FADT (signature "FACP") fixed offsets.
        if length < 116 {
            return;
        }
        unsafe {
            self.fadt.sci_int = read_u16(va + 46);
            self.fadt.acpi_enable = read_u8(va + 52);
            self.fadt.pm1a_evt_blk = read_u32(va + 56);
            self.fadt.pm1a_cnt_blk = read_u32(va + 64);
            self.fadt.pm_tmr_blk = read_u32(va + 76);
            self.fadt_valid = true;
        }
        syscall::debug_puts(b"  [acpi_srv] FADT: SCI_INT=");
        print_num(self.fadt.sci_int as u64);
        syscall::debug_puts(b", PM1a_EVT=");
        print_hex(self.fadt.pm1a_evt_blk as u64);
        syscall::debug_puts(b", PM1a_CNT=");
        print_hex(self.fadt.pm1a_cnt_blk as u64);
        syscall::debug_puts(b"\n");
    }

    fn init(region_va: usize, region_phys: u64) -> Self {
        let mut state = AcpiState {
            tables: [TableEntry {
                sig: [0; 4],
                va: 0,
                length: 0,
            }; MAX_TABLES],
            table_count: 0,
            region_va,
            region_phys,
            mcfg: McfgInfo::default(),
            mcfg_valid: false,
            fadt: FadtInfo::default(),
            fadt_valid: false,
            overrides: [MadtOverride::default(); MAX_MADT_OVERRIDES],
            override_count: 0,
        };

        // Enumerate tables via SYS_FW_INFO.
        let count = syscall::fw_acpi_table_count() as usize;
        if count == 0 {
            syscall::debug_puts(b"  [acpi_srv] no ACPI tables reported\n");
            return state;
        }

        syscall::debug_puts(b"  [acpi_srv] ");
        print_num(count as u64);
        syscall::debug_puts(b" ACPI tables\n");

        for i in 0..count.min(MAX_TABLES) {
            let (sig_u32, length) = match syscall::fw_acpi_table_info(i as u32) {
                Some(v) => v,
                None => continue,
            };
            let phys = match syscall::fw_acpi_table_addr(i as u32) {
                Some(v) => v,
                None => continue,
            };
            let va = match state.phys_to_va(phys) {
                Some(v) => v,
                None => continue,
            };

            let sig = sig_u32.to_le_bytes();
            state.tables[state.table_count] = TableEntry { sig, va, length };
            state.table_count += 1;

            syscall::debug_puts(b"    ");
            syscall::debug_puts(&sig);
            syscall::debug_puts(b" at ");
            print_hex(phys);
            syscall::debug_puts(b" len=");
            print_num(length as u64);
            syscall::debug_puts(b"\n");

            // Parse known tables.
            if &sig == b"MCFG" {
                state.parse_mcfg(va, length);
            } else if &sig == b"APIC" {
                state.parse_madt(va, length);
            } else if &sig == b"FACP" {
                state.parse_fadt(va, length);
            }
        }

        if state.override_count > 0 {
            syscall::debug_puts(b"  [acpi_srv] ");
            print_num(state.override_count as u64);
            syscall::debug_puts(b" MADT IRQ overrides\n");
        }

        state
    }
}

// --- Entry point ---

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [acpi_srv] starting\n");

    // Decode MMIO cap slot from arg0 low 16 bits.
    let cap_slot = (arg0 & 0xFFFF) as usize;

    // Map the ACPI table region.
    let region_va = match syscall::mmio_map_cap(cap_slot) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [acpi_srv] MMIO map failed, exiting\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Get the physical base of the region.
    let region_phys = match syscall::fw_acpi_region() {
        Some((base, _size)) => base,
        None => {
            syscall::debug_puts(b"  [acpi_srv] no ACPI region, exiting\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    syscall::debug_puts(b"  [acpi_srv] region VA=");
    print_hex(region_va as u64);
    syscall::debug_puts(b" phys=");
    print_hex(region_phys);
    syscall::debug_puts(b"\n");

    // Parse all tables.
    let state = AcpiState::init(region_va, region_phys);

    // Register with name server and serve.
    let port = syscall::port_create();
    syscall::ns_register(b"acpi", port);

    syscall::debug_puts(b"  [acpi_srv] ready, ");
    print_num(state.table_count as u64);
    syscall::debug_puts(b" tables, port=");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // IPC server loop.
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };

        match msg.tag {
            ACPI_TABLE_COUNT => {
                let _ = syscall::reply(ACPI_TABLE_COUNT, state.table_count as u64, 0, 0, 0, 0);
            }

            ACPI_TABLE_INFO => {
                let idx = msg.data[0] as usize;
                if idx < state.table_count {
                    let t = &state.tables[idx];
                    let sig = sig_to_u32(&t.sig);
                    let _ = syscall::reply(
                        ACPI_TABLE_INFO,
                        sig as u64,
                        t.length as u64,
                        0,
                        0,
                        0,
                    );
                } else {
                    let _ = syscall::reply(ACPI_ERROR, 0, 0, 0, 0, 0);
                }
            }

            ACPI_GET_MCFG => {
                if state.mcfg_valid {
                    let bus_info = (state.mcfg.segment as u64)
                        | ((state.mcfg.bus_start as u64) << 16)
                        | ((state.mcfg.bus_end as u64) << 24);
                    let _ = syscall::reply(
                        ACPI_GET_MCFG,
                        state.mcfg.base,
                        bus_info,
                        0,
                        0,
                        0,
                    );
                } else {
                    let _ = syscall::reply(ACPI_ERROR, 0, 0, 0, 0, 0);
                }
            }

            ACPI_GET_MADT_OVRDE => {
                let idx = msg.data[0] as usize;
                if idx < state.override_count {
                    let ov = &state.overrides[idx];
                    let packed = (ov.bus as u64)
                        | ((ov.source as u64) << 8)
                        | ((ov.gsi as u64) << 16)
                        | ((ov.flags as u64) << 48);
                    let _ = syscall::reply(ACPI_GET_MADT_OVRDE, packed, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(ACPI_ERROR, 0, 0, 0, 0, 0);
                }
            }

            ACPI_GET_FADT_PM => {
                if state.fadt_valid {
                    let d2 = (state.fadt.sci_int as u64)
                        | ((state.fadt.acpi_enable as u64) << 16)
                        | ((state.fadt.pm_tmr_blk as u64) << 32);
                    let _ = syscall::reply(
                        ACPI_GET_FADT_PM,
                        state.fadt.pm1a_evt_blk as u64,
                        state.fadt.pm1a_cnt_blk as u64,
                        d2,
                        0,
                        0,
                    );
                } else {
                    let _ = syscall::reply(ACPI_ERROR, 0, 0, 0, 0, 0);
                }
            }

            _ => {
                let _ = syscall::reply(ACPI_ERROR, 0, 0, 0, 0, 0);
            }
        }
    }
}
