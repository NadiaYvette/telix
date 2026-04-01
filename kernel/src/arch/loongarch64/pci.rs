//! PCI bus enumeration for LoongArch64 (ECAM memory-mapped config space).
//!
//! Scans bus 0 for virtio PCI devices and returns BAR0 + IRQ info.
//! Since we boot with `-kernel` (no firmware), BARs are unassigned.
//! We program them ourselves from a simple allocator.
//!
//! The LoongArch64 QEMU virt machine maps:
//!   - PCI I/O ports 0x4000..0xFFFF → CPU address 0x18004000..0x18010000
//!   - PCI MEM 0x40000000..0x7FFFFFFF → CPU address 0x40000000..0x7FFFFFFF
//!
//! Legacy virtio-pci creates I/O BARs (bit 0=1). We assign PCI I/O port
//! numbers and translate to CPU addresses for MMIO access.

const ECAM_BASE: usize = 0x2000_0000;
const VIRTIO_VENDOR: u16 = 0x1AF4;

/// PCI I/O port range from DTB: PCI port 0x4000 → CPU addr 0x18004000.
/// Translation: CPU_addr = 0x18000000 + PCI_IO_port.
const PCI_IO_BASE: usize = 0x4000;
const PCI_IO_CPU_OFFSET: usize = 0x1800_0000; // CPU_addr = PCI_IO_port + this

/// PCI memory range for memory BARs (if needed).
const PCI_MEM_BASE: usize = 0x4000_0000;

/// Simple bump allocators for BAR assignment.
static mut NEXT_IO_PORT: usize = PCI_IO_BASE;
static mut NEXT_MEM_ADDR: usize = PCI_MEM_BASE;

/// IRQ base for PCI devices on LoongArch64 QEMU virt (EIOINTC).
/// QEMU virt maps PCI INTA# → IRQ 16, INTB# → 17, etc.
const PCI_IRQ_BASE: u8 = 16;

/// Uncached kernel virtual address for a physical address.
/// LoongArch DMW1 window: 0x8000_xxxx_xxxx_xxxx → PA, uncached.
#[inline]
fn uncached(pa: usize) -> usize {
    pa | 0x8000_0000_0000_0000
}

/// A discovered PCI device.
#[allow(dead_code)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub vendor: u16,
    pub device_id: u16,
    /// BAR0 base address as a CPU physical address.
    /// For I/O BARs: translated to CPU MMIO address (0x18000000 + PCI_IO_port).
    /// For MEM BARs: direct CPU address (same as PCI MEM address).
    pub bar0: usize,
    /// PCI interrupt line.
    pub irq: u8,
}

fn ecam_addr(bus: u8, dev: u8, func: u8, offset: u16) -> usize {
    ECAM_BASE
        + ((bus as usize) << 20)
        + ((dev as usize) << 15)
        + ((func as usize) << 12)
        + (offset as usize)
}

fn pci_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let addr = uncached(ecam_addr(bus, dev, func, offset & !3));
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

fn pci_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let addr = uncached(ecam_addr(bus, dev, func, offset & !3));
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u16, val: u16) {
    let addr = uncached(ecam_addr(bus, dev, func, offset & !1));
    unsafe { core::ptr::write_volatile(addr as *mut u16, val) }
}

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u16) -> u16 {
    let addr = uncached(ecam_addr(bus, dev, func, offset & !1));
    unsafe { core::ptr::read_volatile(addr as *const u16) }
}

fn pci_write8(bus: u8, dev: u8, func: u8, offset: u16, val: u8) {
    let addr = uncached(ecam_addr(bus, dev, func, offset));
    unsafe { core::ptr::write_volatile(addr as *mut u8, val) }
}

/// Probe BAR size by writing all-1s and reading back.
fn bar_size(bus: u8, dev: u8, func: u8, bar_offset: u16, is_io: bool) -> u32 {
    let orig = pci_read32(bus, dev, func, bar_offset);
    pci_write32(bus, dev, func, bar_offset, 0xFFFF_FFFF);
    let readback = pci_read32(bus, dev, func, bar_offset);
    pci_write32(bus, dev, func, bar_offset, orig);

    if readback == 0 {
        return 0;
    }

    let mask = if is_io {
        readback & !0x3 // I/O BAR: mask type bits (low 2)
    } else {
        readback & !0xF // Memory BAR: mask type bits (low 4)
    };
    (!mask).wrapping_add(1)
}

/// Assign a BAR address. Returns (PCI address, CPU physical address).
/// For I/O BARs: assigns from PCI I/O space, translates to CPU address.
/// For MEM BARs: assigns from PCI MEM space (identity-mapped).
fn assign_bar(bus: u8, dev: u8, func: u8, bar_offset: u16) -> usize {
    let bar_raw = pci_read32(bus, dev, func, bar_offset);
    let is_io = bar_raw & 1 != 0;

    let size = bar_size(bus, dev, func, bar_offset, is_io) as usize;
    if size == 0 {
        return 0;
    }

    if is_io {
        // I/O BAR: assign from PCI I/O port space.
        let port = unsafe {
            NEXT_IO_PORT = (NEXT_IO_PORT + size - 1) & !(size - 1);
            let p = NEXT_IO_PORT;
            NEXT_IO_PORT += size;
            p
        };
        // Program I/O BAR (bit 0 = 1 for I/O type).
        pci_write32(bus, dev, func, bar_offset, (port as u32) | 1);

        // Translate to CPU address.
        let cpu_addr = port + PCI_IO_CPU_OFFSET;
        crate::println!(
            "  PCI: slot {} BAR I/O port={:#x} size={:#x} → CPU {:#x}",
            dev, port, size, cpu_addr
        );
        cpu_addr
    } else {
        // Memory BAR: assign from PCI memory space.
        let addr = unsafe {
            NEXT_MEM_ADDR = (NEXT_MEM_ADDR + size - 1) & !(size - 1);
            let a = NEXT_MEM_ADDR;
            NEXT_MEM_ADDR += size;
            a
        };
        pci_write32(bus, dev, func, bar_offset, addr as u32);
        crate::println!(
            "  PCI: slot {} BAR MEM addr={:#x} size={:#x}",
            dev, addr, size
        );
        addr
    }
}

/// Find a virtio PCI device by its device ID.
/// Legacy virtio-pci: vendor 0x1AF4, device IDs 0x1000 (net), 0x1001 (blk).
pub fn find_virtio_device(device_id: u16) -> Option<PciDevice> {
    for dev in 0..32u8 {
        let reg0 = pci_read32(0, dev, 0, 0);
        let vendor = reg0 as u16;
        let did = (reg0 >> 16) as u16;
        if vendor == 0xFFFF || vendor == 0 {
            continue;
        }
        if vendor == VIRTIO_VENDOR && did == device_id {
            // Assign BAR0 (returns CPU physical address).
            let bar0 = assign_bar(0, dev, 0, 0x10);

            if bar0 == 0 {
                crate::println!(
                    "  PCI: virtio dev={:#x} at slot {} — BAR0 unassignable",
                    did, dev
                );
                continue;
            }

            // Assign IRQ: INTA=16, INTB=17, etc. Round-robin by slot.
            let irq = PCI_IRQ_BASE + (dev & 3);
            pci_write8(0, dev, 0, 0x3C, irq);

            // Enable bus mastering + I/O space + memory space.
            let cmd = pci_read16(0, dev, 0, 0x04);
            pci_write16(0, dev, 0, 0x04, cmd | 0x07); // I/O + MEM + bus master

            crate::println!(
                "  PCI: found virtio dev={:#x} at slot {} BAR0={:#x} IRQ={}",
                did, dev, bar0, irq
            );

            return Some(PciDevice {
                bus: 0,
                device: dev,
                vendor,
                device_id: did,
                bar0,
                irq,
            });
        }
    }
    None
}
