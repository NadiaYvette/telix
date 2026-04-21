#![no_std]
#![no_main]

// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright 2026 Nadia Chambers

//! PCI bus enumeration server.
//!
//! Enumerates PCI devices using either PCIe ECAM (memory-mapped config space)
//! or legacy I/O ports (0xCF8/0xCFC on x86_64). Serves device info and
//! config space access to other userspace services over IPC.
//!
//! ## Startup
//!
//! The kernel spawns pci_srv with an MMIO cap for the ECAM region (if available).
//! On x86_64 without MCFG/ECAM, pci_srv falls back to legacy I/O port access.
//!
//! ## IPC protocol
//!
//! Clients use `syscall::call(pci_port, tag, d0, d1, d2, d3)`.
//!
//! - `PCI_DEVICE_COUNT`  (0x7100): → data[0] = count
//! - `PCI_DEVICE_INFO`   (0x7101): data[0] = index
//!     → data[0] = bdf|vendor|device, data[1] = class|sub|progif|hdrtype
//! - `PCI_READ_CONFIG`   (0x7102): data[0] = bdf, data[1] = offset
//!     → data[0] = value (32-bit read)
//! - `PCI_WRITE_CONFIG`  (0x7103): data[0] = bdf, data[1] = offset, data[2] = value
//!     → data[0] = 0 on success
//! - `PCI_BAR_INFO`      (0x7104): data[0] = index, data[1] = bar_idx
//!     → data[0] = base, data[1] = type (0=none, 1=io, 2=mem32, 3=mem64)
//! - `PCI_CAP_FIND`      (0x7105): data[0] = index, data[1] = cap_id
//!     → data[0] = offset (or u64::MAX if not found)

extern crate userlib;

use userlib::syscall;

// --- IPC tags ---
const PCI_DEVICE_COUNT: u64 = 0x7100;
const PCI_DEVICE_INFO: u64 = 0x7101;
const PCI_READ_CONFIG: u64 = 0x7102;
const PCI_WRITE_CONFIG: u64 = 0x7103;
const PCI_BAR_INFO: u64 = 0x7104;
const PCI_CAP_FIND: u64 = 0x7105;
const PCI_ERROR: u64 = 0x71FF;

// --- Device table ---
const MAX_PCI_DEVICES: usize = 64;

#[derive(Clone, Copy)]
struct PciDevice {
    bdf: u32, // bus<<16 | dev<<11 | func<<8
    vendor: u16,
    device_id: u16,
    class: u8,
    subclass: u8,
    prog_if: u8,
    header_type: u8,
    irq_line: u8,
    irq_pin: u8,
    bar: [u64; 6],
    bar_type: [u8; 6], // 0=none, 1=io, 2=mem32, 3=mem64
}

impl PciDevice {
    const EMPTY: Self = PciDevice {
        bdf: 0,
        vendor: 0,
        device_id: 0,
        class: 0,
        subclass: 0,
        prog_if: 0,
        header_type: 0,
        irq_line: 0,
        irq_pin: 0,
        bar: [0; 6],
        bar_type: [0; 6],
    };
}

#[derive(Clone, Copy)]
enum AccessMode {
    Ecam { va: usize, bus_end: u8 },
    #[cfg(target_arch = "x86_64")]
    LegacyIO,
}

struct PciState {
    devices: [PciDevice; MAX_PCI_DEVICES],
    device_count: usize,
    mode: AccessMode,
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

// --- Config space access ---

fn cfg_read32(mode: AccessMode, bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    match mode {
        AccessMode::Ecam { va, .. } => {
            let addr = va
                + ((bus as usize) << 20)
                + ((dev as usize) << 15)
                + ((func as usize) << 12)
                + ((offset as usize) & !3);
            unsafe { core::ptr::read_volatile(addr as *const u32) }
        }
        #[cfg(target_arch = "x86_64")]
        AccessMode::LegacyIO => {
            let addr = 0x8000_0000u32
                | ((bus as u32) << 16)
                | ((dev as u32) << 11)
                | ((func as u32) << 8)
                | ((offset as u32) & 0xFC);
            syscall::ioport_outl(0xCF8, addr);
            syscall::ioport_inl(0xCFC)
        }
    }
}

fn cfg_write32(mode: AccessMode, bus: u8, dev: u8, func: u8, offset: u16, value: u32) {
    match mode {
        AccessMode::Ecam { va, .. } => {
            let addr = va
                + ((bus as usize) << 20)
                + ((dev as usize) << 15)
                + ((func as usize) << 12)
                + ((offset as usize) & !3);
            unsafe { core::ptr::write_volatile(addr as *mut u32, value) }
        }
        #[cfg(target_arch = "x86_64")]
        AccessMode::LegacyIO => {
            let addr = 0x8000_0000u32
                | ((bus as u32) << 16)
                | ((dev as u32) << 11)
                | ((func as u32) << 8)
                | ((offset as u32) & 0xFC);
            syscall::ioport_outl(0xCF8, addr);
            syscall::ioport_outl(0xCFC, value);
        }
    }
}

fn cfg_read16(mode: AccessMode, bus: u8, dev: u8, func: u8, offset: u16) -> u16 {
    let dword = cfg_read32(mode, bus, dev, func, offset & !3);
    let shift = ((offset & 2) * 8) as u32;
    ((dword >> shift) & 0xFFFF) as u16
}

fn cfg_read8(mode: AccessMode, bus: u8, dev: u8, func: u8, offset: u16) -> u8 {
    let dword = cfg_read32(mode, bus, dev, func, offset & !3);
    let shift = ((offset & 3) * 8) as u32;
    ((dword >> shift) & 0xFF) as u8
}

// --- BDF helpers ---

fn bdf_bus(bdf: u32) -> u8 {
    ((bdf >> 16) & 0xFF) as u8
}
fn bdf_dev(bdf: u32) -> u8 {
    ((bdf >> 11) & 0x1F) as u8
}
fn bdf_func(bdf: u32) -> u8 {
    ((bdf >> 8) & 0x07) as u8
}
fn make_bdf(bus: u8, dev: u8, func: u8) -> u32 {
    ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8)
}

// --- PCI class names (common ones) ---

fn class_name(class: u8, subclass: u8) -> &'static [u8] {
    match (class, subclass) {
        (0x00, _) => b"unclassified",
        (0x01, 0x00) => b"SCSI",
        (0x01, 0x01) => b"IDE",
        (0x01, 0x06) => b"SATA",
        (0x01, 0x08) => b"NVMe",
        (0x01, _) => b"storage",
        (0x02, 0x00) => b"ethernet",
        (0x02, _) => b"network",
        (0x03, 0x00) => b"VGA",
        (0x03, _) => b"display",
        (0x04, _) => b"multimedia",
        (0x05, _) => b"memory",
        (0x06, 0x00) => b"host-bridge",
        (0x06, 0x01) => b"ISA-bridge",
        (0x06, 0x04) => b"PCI-bridge",
        (0x06, _) => b"bridge",
        (0x07, _) => b"serial",
        (0x08, _) => b"system",
        (0x0C, 0x03) => b"USB",
        (0x0C, _) => b"serial-bus",
        _ => b"other",
    }
}

// --- Capability walking ---

fn find_capability(mode: AccessMode, bus: u8, dev: u8, func: u8, cap_id: u8) -> Option<u16> {
    // Check if capabilities list is present (status register bit 4).
    let status = cfg_read16(mode, bus, dev, func, 0x06);
    if status & (1 << 4) == 0 {
        return None;
    }
    // Capabilities pointer at offset 0x34 (low byte).
    let mut ptr = cfg_read8(mode, bus, dev, func, 0x34) & !3;
    let mut limit = 48; // safety limit
    while ptr != 0 && limit > 0 {
        let id = cfg_read8(mode, bus, dev, func, ptr as u16);
        if id == cap_id {
            return Some(ptr as u16);
        }
        ptr = cfg_read8(mode, bus, dev, func, (ptr + 1) as u16) & !3;
        limit -= 1;
    }
    None
}

// --- Enumeration ---

impl PciState {
    fn enumerate(&mut self) {
        let (bus_start, bus_end) = match self.mode {
            AccessMode::Ecam { bus_end, .. } => (0u8, bus_end),
            #[cfg(target_arch = "x86_64")]
            AccessMode::LegacyIO => (0, 0), // legacy I/O: bus 0 only
        };

        for bus in bus_start..=bus_end {
            for dev in 0..32u8 {
                let vendor = cfg_read16(self.mode, bus, dev, 0, 0x00);
                if vendor == 0xFFFF {
                    continue;
                }

                let header_type = cfg_read8(self.mode, bus, dev, 0, 0x0E);
                let multi_func = header_type & 0x80 != 0;
                let max_func = if multi_func { 8 } else { 1 };

                for func in 0..max_func {
                    if func > 0 {
                        let v = cfg_read16(self.mode, bus, dev, func, 0x00);
                        if v == 0xFFFF {
                            continue;
                        }
                    }

                    if self.device_count >= MAX_PCI_DEVICES {
                        return;
                    }

                    self.scan_device(bus, dev, func);
                }
            }
        }
    }

    fn scan_device(&mut self, bus: u8, dev: u8, func: u8) {
        let mode = self.mode;
        let vendor = cfg_read16(mode, bus, dev, func, 0x00);
        let device_id = cfg_read16(mode, bus, dev, func, 0x02);
        let class_rev = cfg_read32(mode, bus, dev, func, 0x08);
        let class = ((class_rev >> 24) & 0xFF) as u8;
        let subclass = ((class_rev >> 16) & 0xFF) as u8;
        let prog_if = ((class_rev >> 8) & 0xFF) as u8;
        let header_type = cfg_read8(mode, bus, dev, func, 0x0E) & 0x7F;
        let irq_line = cfg_read8(mode, bus, dev, func, 0x3C);
        let irq_pin = cfg_read8(mode, bus, dev, func, 0x3D);

        let mut pdev = PciDevice {
            bdf: make_bdf(bus, dev, func),
            vendor,
            device_id,
            class,
            subclass,
            prog_if,
            header_type,
            irq_line,
            irq_pin,
            bar: [0; 6],
            bar_type: [0; 6],
        };

        // Read BARs (only for type 0 headers, which have 6 BARs).
        if header_type == 0 {
            let mut bar_idx = 0usize;
            while bar_idx < 6 {
                let offset = (0x10 + bar_idx * 4) as u16;
                let raw = cfg_read32(mode, bus, dev, func, offset);

                if raw == 0 {
                    bar_idx += 1;
                    continue;
                }

                if raw & 1 != 0 {
                    // I/O BAR.
                    pdev.bar[bar_idx] = (raw & !3) as u64;
                    pdev.bar_type[bar_idx] = 1;
                    bar_idx += 1;
                } else {
                    // Memory BAR.
                    let bar_type_bits = (raw >> 1) & 3;
                    if bar_type_bits == 2 && bar_idx + 1 < 6 {
                        // 64-bit BAR.
                        let high = cfg_read32(mode, bus, dev, func, offset + 4);
                        pdev.bar[bar_idx] =
                            ((raw & !0xF) as u64) | ((high as u64) << 32);
                        pdev.bar_type[bar_idx] = 3;
                        bar_idx += 2; // skip next BAR (used as high 32 bits)
                    } else {
                        // 32-bit BAR.
                        pdev.bar[bar_idx] = (raw & !0xF) as u64;
                        pdev.bar_type[bar_idx] = 2;
                        bar_idx += 1;
                    }
                }
            }
        }

        let idx = self.device_count;
        self.devices[idx] = pdev;
        self.device_count += 1;

        // Print device info.
        syscall::debug_puts(b"    ");
        print_num(bus as u64);
        syscall::debug_puts(b":");
        print_num(dev as u64);
        syscall::debug_puts(b".");
        print_num(func as u64);
        syscall::debug_puts(b" ");
        print_hex(vendor as u64);
        syscall::debug_puts(b":");
        print_hex(device_id as u64);
        syscall::debug_puts(b" ");
        syscall::debug_puts(class_name(class, subclass));
        syscall::debug_puts(b"\n");
    }
}

// --- Entry point ---

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [pci_srv] starting\n");

    let cap_slot = (arg0 & 0xFFFF) as usize;

    // Determine access mode.
    let mode = if cap_slot != 0 {
        match syscall::mmio_map_cap(cap_slot) {
            Some(va) => {
                let (_, _bus_start, bus_end) =
                    syscall::fw_pci_ecam_buses().unwrap_or((0, 0, 255));
                syscall::debug_puts(b"  [pci_srv] ECAM VA=");
                print_hex(va as u64);
                syscall::debug_puts(b", buses 0..");
                print_num(bus_end as u64);
                syscall::debug_puts(b"\n");
                AccessMode::Ecam { va, bus_end }
            }
            None => {
                syscall::debug_puts(b"  [pci_srv] MMIO map failed\n");
                #[cfg(target_arch = "x86_64")]
                {
                    syscall::debug_puts(b"  [pci_srv] falling back to legacy I/O\n");
                    AccessMode::LegacyIO
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    loop {
                        core::hint::spin_loop();
                    }
                }
            }
        }
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            syscall::debug_puts(b"  [pci_srv] legacy I/O mode (bus 0)\n");
            AccessMode::LegacyIO
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            syscall::debug_puts(b"  [pci_srv] no ECAM and no legacy I/O, exiting\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    let mut state = PciState {
        devices: [PciDevice::EMPTY; MAX_PCI_DEVICES],
        device_count: 0,
        mode,
    };

    // Enumerate PCI buses.
    syscall::debug_puts(b"  [pci_srv] enumerating...\n");
    state.enumerate();

    syscall::debug_puts(b"  [pci_srv] found ");
    print_num(state.device_count as u64);
    syscall::debug_puts(b" devices\n");

    // Register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"pci", port);

    syscall::debug_puts(b"  [pci_srv] ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // IPC server loop.
    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };

        match msg.tag {
            PCI_DEVICE_COUNT => {
                let _ = syscall::reply(
                    PCI_DEVICE_COUNT,
                    state.device_count as u64,
                    0,
                    0,
                    0,
                    0,
                );
            }

            PCI_DEVICE_INFO => {
                let idx = msg.data[0] as usize;
                if idx < state.device_count {
                    let d = &state.devices[idx];
                    // Pack bdf | vendor | device into data[0].
                    let d0 = (d.bdf as u64)
                        | ((d.vendor as u64) << 32)
                        | ((d.device_id as u64) << 48);
                    // Pack class | subclass | prog_if | header_type into data[1].
                    let d1 = (d.class as u64)
                        | ((d.subclass as u64) << 8)
                        | ((d.prog_if as u64) << 16)
                        | ((d.header_type as u64) << 24)
                        | ((d.irq_line as u64) << 32)
                        | ((d.irq_pin as u64) << 40);
                    let _ = syscall::reply(PCI_DEVICE_INFO, d0, d1, 0, 0, 0);
                } else {
                    let _ = syscall::reply(PCI_ERROR, 0, 0, 0, 0, 0);
                }
            }

            PCI_READ_CONFIG => {
                let bdf = msg.data[0] as u32;
                let offset = msg.data[1] as u16;
                let val = cfg_read32(
                    state.mode,
                    bdf_bus(bdf),
                    bdf_dev(bdf),
                    bdf_func(bdf),
                    offset,
                );
                let _ = syscall::reply(PCI_READ_CONFIG, val as u64, 0, 0, 0, 0);
            }

            PCI_WRITE_CONFIG => {
                let bdf = msg.data[0] as u32;
                let offset = msg.data[1] as u16;
                let value = msg.data[2] as u32;
                cfg_write32(
                    state.mode,
                    bdf_bus(bdf),
                    bdf_dev(bdf),
                    bdf_func(bdf),
                    offset,
                    value,
                );
                let _ = syscall::reply(PCI_WRITE_CONFIG, 0, 0, 0, 0, 0);
            }

            PCI_BAR_INFO => {
                let idx = msg.data[0] as usize;
                let bar_idx = msg.data[1] as usize;
                if idx < state.device_count && bar_idx < 6 {
                    let d = &state.devices[idx];
                    let _ = syscall::reply(
                        PCI_BAR_INFO,
                        d.bar[bar_idx],
                        d.bar_type[bar_idx] as u64,
                        0,
                        0,
                        0,
                    );
                } else {
                    let _ = syscall::reply(PCI_ERROR, 0, 0, 0, 0, 0);
                }
            }

            PCI_CAP_FIND => {
                let idx = msg.data[0] as usize;
                let cap_id = msg.data[1] as u8;
                if idx < state.device_count {
                    let d = &state.devices[idx];
                    let bus = bdf_bus(d.bdf);
                    let dev = bdf_dev(d.bdf);
                    let func = bdf_func(d.bdf);
                    match find_capability(state.mode, bus, dev, func, cap_id) {
                        Some(off) => {
                            let _ =
                                syscall::reply(PCI_CAP_FIND, off as u64, 0, 0, 0, 0);
                        }
                        None => {
                            let _ =
                                syscall::reply(PCI_CAP_FIND, u64::MAX, 0, 0, 0, 0);
                        }
                    }
                } else {
                    let _ = syscall::reply(PCI_ERROR, 0, 0, 0, 0, 0);
                }
            }

            _ => {
                let _ = syscall::reply(PCI_ERROR, 0, 0, 0, 0, 0);
            }
        }
    }
}
