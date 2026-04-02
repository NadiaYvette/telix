//! PCI bus enumeration for x86-64 (I/O port config space access).
//!
//! Scans bus 0 for virtio devices and returns BAR0 + IRQ info.

use super::serial::{inl, inw, outl, outw};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

const VIRTIO_VENDOR: u16 = 0x1AF4;

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

fn pci_config_read32(bus: u8, device: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        inl(CONFIG_DATA)
    }
}

fn pci_config_write16(bus: u8, device: u8, func: u8, offset: u8, val: u16) {
    let addr: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        // Write 16-bit value at the correct offset within the 32-bit register.
        let port = CONFIG_DATA + (offset & 2) as u16;
        outw(port, val);
    }
}

fn pci_config_read16(bus: u8, device: u8, func: u8, offset: u8) -> u16 {
    let addr: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        let port = CONFIG_DATA + (offset & 2) as u16;
        inw(port)
    }
}

// BochsVBE constants.
const BOCHS_VBE_VENDOR: u16 = 0x1234;
const BOCHS_VBE_DEVICE: u16 = 0x1111;

// VBE DISPI register ports.
const VBE_DISPI_IOPORT_INDEX: u16 = 0x01CE;
const VBE_DISPI_IOPORT_DATA: u16 = 0x01CF;

// DISPI register indices.
const VBE_DISPI_INDEX_XRES: u16 = 0x01;
const VBE_DISPI_INDEX_YRES: u16 = 0x02;
const VBE_DISPI_INDEX_BPP: u16 = 0x03;
const VBE_DISPI_INDEX_ENABLE: u16 = 0x04;

const VBE_DISPI_ENABLED: u16 = 0x01;
const VBE_DISPI_LFB_ENABLED: u16 = 0x40;

/// Probe for BochsVBE/QEMU stdvga and set up framebuffer via DISPI registers.
/// Called during kernel init. Sets firmware framebuffer info if found.
pub fn probe_bochs_vbe() {
    // Scan PCI buses 0-3 to find VGA-compatible display devices.
    for bus in 0..4u8 {
        for dev in 0..32u8 {
            let reg0 = pci_config_read32(bus, dev, 0, 0);
            let vendor = reg0 as u16;
            let did = (reg0 >> 16) as u16;
            if vendor == 0xFFFF {
                continue;
            }
            let class_reg = pci_config_read32(bus, dev, 0, 0x08);
            let base_class = (class_reg >> 24) as u8;
            if base_class != 0x03 {
                continue;
            }
            // BochsVBE (1234:1111) or QXL (1b36:0100) — both support DISPI.
            let supports_dispi = (vendor == BOCHS_VBE_VENDOR && did == BOCHS_VBE_DEVICE)
                || (vendor == 0x1b36 && did == 0x0100);
            if !supports_dispi {
                continue;
            }
            // Read BAR0 (MMIO framebuffer address).
            let bar0_raw = pci_config_read32(bus, dev, 0, 0x10);
            let fb_addr = (bar0_raw & !0xF) as u64;
            if fb_addr == 0 {
                continue;
            }

            // Set resolution via DISPI I/O ports.
            let width: u16 = 1024;
            let height: u16 = 768;
            let bpp: u16 = 32;

            unsafe {
                outw(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_ENABLE);
                outw(VBE_DISPI_IOPORT_DATA, 0);
                outw(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_XRES);
                outw(VBE_DISPI_IOPORT_DATA, width);
                outw(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_YRES);
                outw(VBE_DISPI_IOPORT_DATA, height);
                outw(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_BPP);
                outw(VBE_DISPI_IOPORT_DATA, bpp);
                outw(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_ENABLE);
                outw(VBE_DISPI_IOPORT_DATA, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);
            }

            let pitch = width as u32 * (bpp as u32 / 8);
            crate::println!(
                "  BochsVBE: {}x{}x{} at {:#x} pitch={}",
                width, height, bpp, fb_addr, pitch
            );

            crate::firmware::set_framebuffer(crate::firmware::FramebufferInfo {
                addr: fb_addr,
                pitch,
                width: width as u32,
                height: height as u32,
                bpp: bpp as u8,
                fb_type: 1,
                _pad: [0; 2],
            });
            return;
        }
    }
}

/// Find a virtio PCI device by its subsystem device ID.
/// For legacy virtio-pci: vendor 0x1AF4, device IDs 0x1000 (net), 0x1001 (blk).
pub fn find_virtio_device(device_id: u16) -> Option<PciDevice> {
    for dev in 0..32u8 {
        let reg0 = pci_config_read32(0, dev, 0, 0);
        let vendor = reg0 as u16;
        let did = (reg0 >> 16) as u16;
        if vendor == 0xFFFF {
            continue;
        }
        if vendor == VIRTIO_VENDOR && did == device_id {
            // Read BAR0 (offset 0x10).
            let bar0_raw = pci_config_read32(0, dev, 0, 0x10);
            // Bit 0 = 1 means I/O space. Mask off low 2 bits for base.
            let bar0 = (bar0_raw & !3) as u16;

            // Read IRQ line (offset 0x3C, low byte).
            let irq = pci_config_read32(0, dev, 0, 0x3C) as u8;

            // Enable bus mastering (command register offset 0x04, bit 2).
            let cmd = pci_config_read16(0, dev, 0, 0x04);
            if cmd & 0x05 != 0x05 {
                pci_config_write16(0, dev, 0, 0x04, cmd | 0x05); // IO space + bus master
            }

            crate::println!(
                "  PCI: found virtio dev={:#x} at slot {} BAR0={:#x} IRQ={}",
                did,
                dev,
                bar0,
                irq
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
