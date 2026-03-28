//! Virtio MMIO transport layer.
//!
//! Implements the virtio-v1.1 MMIO register interface for device discovery
//! and virtqueue setup on QEMU virt machines.

/// MMIO register offsets (shared between legacy v1 and modern v2).
pub const MAGIC_VALUE: usize = 0x000;
pub const VERSION: usize = 0x004;
pub const DEVICE_ID: usize = 0x008;
#[allow(dead_code)]
pub const VENDOR_ID: usize = 0x00C;
pub const DEVICE_FEATURES: usize = 0x010;
pub const DEVICE_FEATURES_SEL: usize = 0x014;
pub const DRIVER_FEATURES: usize = 0x020;
pub const DRIVER_FEATURES_SEL: usize = 0x024;
/// Legacy (v1) registers.
pub const GUEST_PAGE_SIZE: usize = 0x028;
pub const QUEUE_SEL: usize = 0x030;
pub const QUEUE_NUM_MAX: usize = 0x034;
pub const QUEUE_NUM: usize = 0x038;
#[allow(dead_code)]
pub const QUEUE_ALIGN: usize = 0x03C;
pub const QUEUE_PFN: usize = 0x040;
/// Modern (v2) registers.
pub const QUEUE_READY: usize = 0x044;
pub const QUEUE_NOTIFY: usize = 0x050;
pub const INTERRUPT_STATUS: usize = 0x060;
pub const INTERRUPT_ACK: usize = 0x064;
pub const STATUS: usize = 0x070;
pub const QUEUE_DESC_LOW: usize = 0x080;
pub const QUEUE_DESC_HIGH: usize = 0x084;
pub const QUEUE_DRIVER_LOW: usize = 0x090;
pub const QUEUE_DRIVER_HIGH: usize = 0x094;
pub const QUEUE_DEVICE_LOW: usize = 0x0A0;
pub const QUEUE_DEVICE_HIGH: usize = 0x0A4;

/// Device status bits.
pub const STATUS_ACK: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FAILED: u32 = 128;

/// Virtio device IDs.
pub const DEVICE_NET: u32 = 1;
pub const DEVICE_BLK: u32 = 2;

/// Expected magic value.
pub const VIRTIO_MAGIC: u32 = 0x74726976; // "virt"

/// MMIO read.
pub fn read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// MMIO write.
pub fn write32(base: usize, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val); }
}

/// Probe a single MMIO address. Returns the device ID if the magic matches.
pub fn probe_device_id(base: usize) -> Option<u32> {
    let magic = read32(base, MAGIC_VALUE);
    if magic != VIRTIO_MAGIC {
        return None;
    }
    let dev = read32(base, DEVICE_ID);
    if dev == 0 { return None; }
    Some(dev)
}

/// Look up the platform IRQ number for a virtio-mmio device at the given base.
/// Checks firmware-discovered data first, falls back to QEMU virt defaults.
pub fn device_irq(base: usize) -> u32 {
    for dev in crate::firmware::virtio_devices() {
        if dev.base == base as u64 {
            return dev.irq;
        }
    }
    // Fallback: derive IRQ from base address (QEMU virt layout).
    fallback_irq(base)
}

/// Derive IRQ from MMIO base for QEMU virt machines (fallback when firmware
/// data is unavailable).
fn fallback_irq(base: usize) -> u32 {
    // aarch64: 0x0a000000 + i*0x200 → SPI 16+i = INTID 48+i
    // riscv64: 0x10001000 + (i-1)*0x1000 → PLIC IRQ i (1..=8)
    for dev in FALLBACK_ADDRS {
        if dev.0 == base { return dev.1; }
    }
    0
}

/// (base_address, irq) pairs for QEMU virt machines.
#[cfg(target_arch = "aarch64")]
const FALLBACK_ADDRS: &[(usize, u32)] = &[
    (0x0a00_0000, 48), (0x0a00_0200, 49), (0x0a00_0400, 50), (0x0a00_0600, 51),
    (0x0a00_0800, 52), (0x0a00_0a00, 53), (0x0a00_0c00, 54), (0x0a00_0e00, 55),
    (0x0a00_1000, 56), (0x0a00_1200, 57), (0x0a00_1400, 58), (0x0a00_1600, 59),
    (0x0a00_1800, 60), (0x0a00_1a00, 61), (0x0a00_1c00, 62), (0x0a00_1e00, 63),
    (0x0a00_2000, 64), (0x0a00_2200, 65), (0x0a00_2400, 66), (0x0a00_2600, 67),
    (0x0a00_2800, 68), (0x0a00_2a00, 69), (0x0a00_2c00, 70), (0x0a00_2e00, 71),
    (0x0a00_3000, 72), (0x0a00_3200, 73), (0x0a00_3400, 74), (0x0a00_3600, 75),
    (0x0a00_3800, 76), (0x0a00_3a00, 77), (0x0a00_3c00, 78), (0x0a00_3e00, 79),
];

#[cfg(target_arch = "riscv64")]
const FALLBACK_ADDRS: &[(usize, u32)] = &[
    (0x1000_1000, 1), (0x1000_2000, 2), (0x1000_3000, 3), (0x1000_4000, 4),
    (0x1000_5000, 5), (0x1000_6000, 6), (0x1000_7000, 7), (0x1000_8000, 8),
];

#[cfg(target_arch = "x86_64")]
const FALLBACK_ADDRS: &[(usize, u32)] = &[];

/// Find the first virtio device of the given type.
/// Returns the MMIO base address if found. Checks firmware-discovered
/// devices first, then falls back to probing hardcoded addresses.
pub fn find_device(device_id: u32) -> Option<usize> {
    // Check firmware-discovered devices first.
    for dev in crate::firmware::virtio_devices() {
        if probe_device_id(dev.base as usize) == Some(device_id) {
            return Some(dev.base as usize);
        }
    }
    // Fallback: probe hardcoded addresses.
    for &(base, _) in FALLBACK_ADDRS {
        if probe_device_id(base) == Some(device_id) {
            return Some(base);
        }
    }
    None
}
