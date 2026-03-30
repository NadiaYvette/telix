//! PCI bus enumeration for MIPS64 Malta (GT-64120 PCI controller).
//!
//! Malta maps PCI I/O space at physical 0x1800_0000, accessed via KSEG1
//! (uncached) at 0xFFFF_FFFF_B800_0000. PCI config space uses the
//! standard CONFIG_ADDRESS (0xCF8) / CONFIG_DATA (0xCFC) mechanism,
//! same as x86, but via MMIO instead of I/O port instructions.

/// KSEG1 base for PCI I/O space on Malta (GT-64120 maps at PA 0x1800_0000).
const PCI_IO_KSEG1: usize = 0xFFFF_FFFF_B800_0000;

/// GT-64120 ISD (Internal Space Decode) register base via KSEG1.
/// QEMU bootloader relocates ISD from default 0x1400_0000 to 0x1BE0_0000.
/// PCI config access registers are at offsets 0xCF8/0xCFC within ISD.
const GT64120_ISD_KSEG1: usize = 0xFFFF_FFFF_A000_0000 + 0x1BE0_0000;

const CONFIG_ADDRESS: usize = GT64120_ISD_KSEG1 + 0xCF8;
const CONFIG_DATA: usize = GT64120_ISD_KSEG1 + 0xCFC;

const VIRTIO_VENDOR: u16 = 0x1AF4;

/// Simple PCI I/O port allocator. Starts at 0x1000 to avoid system ports.
static mut NEXT_IO_PORT: u32 = 0x1000;

fn next_io_port_aligned(size: u32) -> u32 {
    unsafe {
        let aligned = (NEXT_IO_PORT + size - 1) & !(size - 1);
        NEXT_IO_PORT = aligned + size;
        aligned
    }
}

/// A discovered PCI device.
#[allow(dead_code)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub vendor: u16,
    pub device_id: u16,
    /// BAR0 I/O port base (low bit masked off).
    pub bar0: u16,
    /// PCI interrupt line (from config register 0x3C).
    pub irq: u8,
}

/// Memory barrier to ensure write completes before read.
#[inline(always)]
fn sync() {
    unsafe { core::arch::asm!("sync", options(nostack, preserves_flags)) };
}

fn pci_config_read32(bus: u8, device: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
        sync();
        core::ptr::read_volatile(CONFIG_DATA as *const u32)
    }
}

fn pci_config_write16(bus: u8, device: u8, func: u8, offset: u8, val: u16) {
    let addr: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
        sync();
        let data_addr = CONFIG_DATA + (offset & 2) as usize;
        core::ptr::write_volatile(data_addr as *mut u16, val);
        sync();
    }
}

fn pci_config_write32(bus: u8, device: u8, func: u8, offset: u8, val: u32) {
    let addr: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
        sync();
        core::ptr::write_volatile(CONFIG_DATA as *mut u32, val);
        sync();
    }
}

fn pci_config_read16(bus: u8, device: u8, func: u8, offset: u8) -> u16 {
    let addr: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
        sync();
        let data_addr = CONFIG_DATA + (offset & 2) as usize;
        core::ptr::read_volatile(data_addr as *const u16)
    }
}

/// Find a virtio PCI device by its device ID.
/// For legacy virtio-pci: vendor 0x1AF4, device IDs 0x1000 (net), 0x1001 (blk).
pub fn find_virtio_device(device_id: u16) -> Option<PciDevice> {
    for dev in 0..32u8 {
        let reg0 = pci_config_read32(0, dev, 0, 0);
        let vendor = reg0 as u16;
        let did = (reg0 >> 16) as u16;
        if vendor != 0xFFFF && vendor != 0x0000 {
            crate::println!(
                "  PCI slot {}: vendor={:#06x} device={:#06x}",
                dev, vendor, did
            );
        }
        if vendor == 0xFFFF {
            continue;
        }
        if vendor == VIRTIO_VENDOR && did == device_id {
            // On Malta, firmware doesn't assign PCI BARs — we must do it.
            // Write 0xFFFFFFFF to BAR0 to determine size, then assign I/O port.
            let bar0_raw = pci_config_read32(0, dev, 0, 0x10);
            let bar0;
            if bar0_raw & 1 != 0 && (bar0_raw & !3) == 0 {
                // I/O space BAR, not yet assigned. Size it and assign.
                pci_config_write32(0, dev, 0, 0x10, 0xFFFF_FFFF);
                let size_mask = pci_config_read32(0, dev, 0, 0x10);
                let size = !(size_mask & !3) + 1; // I/O size
                // Assign from our I/O port allocator, aligned to size.
                let port = next_io_port_aligned(size);
                pci_config_write32(0, dev, 0, 0x10, port | 1); // set I/O space bit
                bar0 = port as u16;
                crate::println!(
                    "  PCI: assigned BAR0 I/O port {:#x} (size={})",
                    bar0, size
                );
            } else {
                bar0 = (bar0_raw & !3) as u16;
            }

            // Read IRQ line (offset 0x3C, low byte).
            // On Malta, QEMU routes PCI INTA-INTD to MIPS HW IRQs.
            // Assign a reasonable IRQ if not set.
            let irq_reg = pci_config_read32(0, dev, 0, 0x3C);
            let mut irq = irq_reg as u8;
            if irq == 0 || irq == 0xFF {
                // Assign IRQ based on PCI slot (Malta: INTA→IRQ10, etc.)
                irq = 10 + (dev % 4);
                let new_reg = (irq_reg & 0xFFFF_FF00) | (irq as u32);
                pci_config_write32(0, dev, 0, 0x3C, new_reg);
            }

            crate::println!(
                "  PCI: virtio slot={} BAR0={:#x} IRQ={}",
                dev, bar0, irq
            );

            crate::print!("  PCI: enabling bus master...");
            // Enable bus mastering + I/O space via 32-bit read/write
            // (16-bit access to GT-64120 config data may not be supported).
            let cmd_reg = pci_config_read32(0, dev, 0, 0x04);
            let cmd = cmd_reg as u16;
            if cmd & 0x05 != 0x05 {
                let new_cmd = (cmd_reg & 0xFFFF_0000) | ((cmd | 0x05) as u32);
                unsafe {
                    let addr: u32 = (1 << 31)
                        | ((dev as u32) << 11)
                        | 0x04;
                    core::ptr::write_volatile(CONFIG_ADDRESS as *mut u32, addr);
                    sync();
                    core::ptr::write_volatile(CONFIG_DATA as *mut u32, new_cmd);
                    sync();
                }
            }
            crate::print!(" done\n");

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

/// Read a 32-bit value from PCI I/O space (for userspace ioport translation).
/// `port` is an I/O port number; access goes to KSEG1 + PCI_IO_BASE + port.
pub unsafe fn ioport_read32(port: u16) -> u32 {
    let addr = PCI_IO_KSEG1 + port as usize;
    core::ptr::read_volatile(addr as *const u32)
}

/// Read a 16-bit value from PCI I/O space.
pub unsafe fn ioport_read16(port: u16) -> u16 {
    let addr = PCI_IO_KSEG1 + port as usize;
    core::ptr::read_volatile(addr as *const u16)
}

/// Read an 8-bit value from PCI I/O space.
pub unsafe fn ioport_read8(port: u16) -> u8 {
    let addr = PCI_IO_KSEG1 + port as usize;
    core::ptr::read_volatile(addr as *const u8)
}

/// Write a 32-bit value to PCI I/O space.
pub unsafe fn ioport_write32(port: u16, val: u32) {
    let addr = PCI_IO_KSEG1 + port as usize;
    core::ptr::write_volatile(addr as *mut u32, val);
}

/// Write a 16-bit value to PCI I/O space.
pub unsafe fn ioport_write16(port: u16, val: u16) {
    let addr = PCI_IO_KSEG1 + port as usize;
    core::ptr::write_volatile(addr as *mut u16, val);
}

/// Write an 8-bit value to PCI I/O space.
pub unsafe fn ioport_write8(port: u16, val: u8) {
    let addr = PCI_IO_KSEG1 + port as usize;
    core::ptr::write_volatile(addr as *mut u8, val);
}
