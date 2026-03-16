//! Virtio MMIO transport layer.
//!
//! Implements the virtio-v1.1 MMIO register interface for device discovery
//! and virtqueue setup on QEMU virt machines.

/// MMIO register offsets (shared between legacy v1 and modern v2).
pub const MAGIC_VALUE: usize = 0x000;
pub const VERSION: usize = 0x004;
pub const DEVICE_ID: usize = 0x008;
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

/// Known MMIO base addresses for QEMU virt machines.
#[cfg(target_arch = "aarch64")]
pub fn probe_addresses() -> &'static [usize] {
    // QEMU virt: 32 virtio-mmio devices at 0x0a000000 + 0x200 * n
    static ADDRS: [usize; 32] = {
        let base = 0x0a00_0000usize;
        let mut a = [0usize; 32];
        let mut i = 0;
        while i < 32 {
            a[i] = base + i * 0x200;
            i += 1;
        }
        a
    };
    &ADDRS
}

#[cfg(target_arch = "riscv64")]
pub fn probe_addresses() -> &'static [usize] {
    // QEMU virt: 8 virtio-mmio devices at 0x10001000 + 0x1000 * n
    static ADDRS: [usize; 8] = [
        0x1000_1000, 0x1000_2000, 0x1000_3000, 0x1000_4000,
        0x1000_5000, 0x1000_6000, 0x1000_7000, 0x1000_8000,
    ];
    &ADDRS
}

#[cfg(target_arch = "x86_64")]
pub fn probe_addresses() -> &'static [usize] {
    // x86-64 uses PCI, not MMIO. No MMIO probing for Phase 3.
    static ADDRS: [usize; 0] = [];
    &ADDRS
}

/// Find the first virtio device of the given type.
/// Returns the MMIO base address if found.
pub fn find_device(device_id: u32) -> Option<usize> {
    for &base in probe_addresses() {
        let magic = read32(base, MAGIC_VALUE);
        if magic != VIRTIO_MAGIC {
            continue;
        }
        let dev = read32(base, DEVICE_ID);
        if dev == device_id {
            return Some(base);
        }
    }
    None
}
