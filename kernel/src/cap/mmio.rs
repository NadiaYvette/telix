//! MMIO region registry backing `CapType::Memory` capabilities.
//!
//! Firmware-discovered MMIO regions (virtio-mmio, framebuffer, ...) are
//! registered here at boot, producing a small integer `region_id`. A
//! `Memory` capability stores this ID in its `object` field (never a raw
//! physical address), so that kernel validation/revocation can operate on
//! a bounded table rather than trusting untyped pointers from userspace.
//!
//! This is the storage layer for driver-model Step B. `sys_mmio_map_cap`
//! resolves a Memory cap in the calling task's CapSpace to a region,
//! then maps the region's physical pages into the task's address space.

use super::capability::{CapType, Capability, Rights};
use crate::firmware;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of MMIO regions that can be registered. Default QEMU
/// virt exposes ≤8 virtio slots + interrupt controller + UART; 32 leaves
/// headroom without meaningful cost.
pub const MAX_MMIO_REGIONS: usize = 32;

/// Caching attributes for an MMIO region. Translated to arch-specific
/// PTE flags at map time. Currently only `Device` is produced (firmware
/// tables in Telix don't surface caching hints yet); `WriteCombine` is
/// reserved for framebuffer-style regions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum CacheAttr {
    /// Strongly-ordered device memory (nGnRnE / UC).
    Device = 0,
    /// Write-combining (framebuffers etc.). Reserved.
    WriteCombine = 1,
}

impl Default for CacheAttr {
    fn default() -> Self {
        CacheAttr::Device
    }
}

/// A registered MMIO region.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MmioRegion {
    /// Page-aligned physical base (used for PTE mapping).
    pub phys_base: usize,
    /// Page-aligned size (covers `phys_base..phys_base+size`).
    pub size: usize,
    /// Sub-page byte offset of the original (unaligned) base address.
    /// `sys_mmio_map_cap` adds this to the VA so callers see the exact
    /// device register window.
    pub sub_page_offset: usize,
    pub caching: CacheAttr,
}

impl MmioRegion {
    const fn zero() -> Self {
        Self {
            phys_base: 0,
            size: 0,
            sub_page_offset: 0,
            caching: CacheAttr::Device,
        }
    }
}

/// Registry storage. Writes happen only from BSP at boot (single-writer);
/// reads after an Acquire load of `MMIO_COUNT` are safe.
struct MmioTable {
    slots: [UnsafeCell<MmioRegion>; MAX_MMIO_REGIONS],
    count: AtomicU32,
}

// SAFETY: single-writer (BSP, boot time) / many-reader (after Acquire on count).
unsafe impl Sync for MmioTable {}

impl MmioTable {
    const fn new() -> Self {
        Self {
            slots: [const { UnsafeCell::new(MmioRegion::zero()) }; MAX_MMIO_REGIONS],
            count: AtomicU32::new(0),
        }
    }
}

static MMIO_TABLE: MmioTable = MmioTable::new();

/// Register a new MMIO region. Returns its `region_id`, or `None` if the
/// table is full. Idempotent on (base, size): if a region with the same
/// bounds already exists its existing ID is returned.
pub fn register_region(phys_base: usize, size: usize, caching: CacheAttr) -> Option<u32> {
    if size == 0 {
        return None;
    }
    // Page-align both ends so PTE installation is well-defined.
    let page = crate::mm::page::MMUPAGE_SIZE;
    let base_aligned = phys_base & !(page - 1);
    let sub_page_offset = phys_base - base_aligned;
    let end = phys_base.checked_add(size)?;
    let end_aligned = (end + page - 1) & !(page - 1);
    let size_aligned = end_aligned - base_aligned;

    // Deduplicate against existing registrations (exact unaligned base +
    // size — two devices on the same page get distinct regions so each
    // preserves its sub-page offset for sys_mmio_map_cap).
    let n = MMIO_TABLE.count.load(Ordering::Acquire);
    for i in 0..n {
        let r = unsafe { *MMIO_TABLE.slots[i as usize].get() };
        if r.phys_base == base_aligned
            && r.sub_page_offset == sub_page_offset
            && r.size == size_aligned
        {
            return Some(i);
        }
    }

    if n as usize >= MAX_MMIO_REGIONS {
        return None;
    }
    let idx = n;
    unsafe {
        *MMIO_TABLE.slots[idx as usize].get() = MmioRegion {
            phys_base: base_aligned,
            size: size_aligned,
            sub_page_offset,
            caching,
        };
    }
    MMIO_TABLE.count.store(idx + 1, Ordering::Release);
    Some(idx)
}

/// Look up a region by ID.
pub fn region(id: u32) -> Option<MmioRegion> {
    let n = MMIO_TABLE.count.load(Ordering::Acquire);
    if id >= n {
        return None;
    }
    Some(unsafe { *MMIO_TABLE.slots[id as usize].get() })
}

/// Number of registered regions.
#[allow(dead_code)]
pub fn count() -> u32 {
    MMIO_TABLE.count.load(Ordering::Acquire)
}

/// Enumerate firmware-discovered MMIO devices and register a region for
/// each. Called once from `startup_thread` after firmware parsing is
/// complete. Safe to call multiple times (register_region dedupes).
pub fn populate_from_firmware() {
    // Virtio-mmio devices from DTB (arm64/riscv64; empty on x86_64).
    for dev in firmware::virtio_devices() {
        let _ = register_region(dev.base as usize, dev.size as usize, CacheAttr::Device);
    }
    // Framebuffer, if the bootloader surfaced one. Driven as WriteCombine
    // so we get the correct attribute when a userspace display driver
    // maps it via sys_mmio_map_cap.
    if let Some(fb) = firmware::framebuffer_info() {
        let size = (fb.pitch as usize) * (fb.height as usize);
        if fb.addr != 0 && size > 0 {
            let _ = register_region(fb.addr as usize, size, CacheAttr::WriteCombine);
        }
    }
}

/// Construct a Memory capability referencing `region_id` with `rights`.
/// Returns None if `region_id` is out of range.
pub fn make_cap(region_id: u32, rights: Rights) -> Option<Capability> {
    region(region_id)?;
    Some(Capability::new(CapType::Memory, rights, region_id as usize))
}

/// Kernel self-test for the MMIO registry.
///
/// Exercises: (1) region registration and dedup, (2) out-of-range lookup
/// rejection, (3) Memory cap construction and `Rights` attenuation via
/// `derive`. Does *not* exercise the full `sys_mmio_map_cap` path because
/// the kernel startup thread has no user address space to map into — that
/// path is covered end-to-end once the userspace virtio-blk driver
/// (Step C) runs.
pub fn self_test() {
    // Register a synthetic region. Use the first firmware virtio device
    // if available; otherwise fabricate one (the registry doesn't touch
    // the addresses, it just stores them).
    let (base, size) = match firmware::virtio_devices().first() {
        Some(d) => (d.base as usize, d.size as usize),
        None => (0xDEAD_0000usize, 0x1000usize),
    };

    let id = match register_region(base, size, CacheAttr::Device) {
        Some(i) => i,
        None => {
            crate::println!("  [mmio-cap] FAIL: register_region");
            return;
        }
    };

    // Dedup: registering the same (base, size) again returns the same id.
    let id2 = register_region(base, size, CacheAttr::Device);
    if id2 != Some(id) {
        crate::println!(
            "  [mmio-cap] FAIL: dedup returned {:?} (expected Some({}))",
            id2, id
        );
        return;
    }

    // Lookup: valid id round-trips, out-of-range id rejects.
    let r = match region(id) {
        Some(r) => r,
        None => {
            crate::println!("  [mmio-cap] FAIL: region({}) returned None", id);
            return;
        }
    };
    let page = crate::mm::page::MMUPAGE_SIZE;
    let expected_base = base & !(page - 1);
    if r.phys_base != expected_base {
        crate::println!(
            "  [mmio-cap] FAIL: phys_base {:#x} != expected {:#x}",
            r.phys_base, expected_base
        );
        return;
    }
    if region(u32::MAX).is_some() {
        crate::println!("  [mmio-cap] FAIL: out-of-range region() returned Some");
        return;
    }

    // Cap construction: Memory cap with RW, derive to R-only.
    let rw = Rights::READ.union(Rights::WRITE);
    let cap = match make_cap(id, rw) {
        Some(c) => c,
        None => {
            crate::println!("  [mmio-cap] FAIL: make_cap");
            return;
        }
    };
    if cap.cap_type as u8 != CapType::Memory as u8 || cap.object != id as usize {
        crate::println!(
            "  [mmio-cap] FAIL: cap wrong shape (type={:?} obj={})",
            cap.cap_type, cap.object
        );
        return;
    }
    let ro = match cap.derive(Rights::READ) {
        Some(c) => c,
        None => {
            crate::println!("  [mmio-cap] FAIL: derive(READ)");
            return;
        }
    };
    if ro.rights.contains(Rights::WRITE) {
        crate::println!("  [mmio-cap] FAIL: derive did not attenuate WRITE");
        return;
    }
    // Escalation via derive must be rejected.
    if cap.derive(Rights::READ.union(Rights::WRITE).union(Rights::EXEC)).is_some() {
        crate::println!("  [mmio-cap] FAIL: derive allowed rights escalation");
        return;
    }

    crate::println!(
        "  [mmio-cap] PASS: region {} = {:#x}+{:#x} (rw→ro derive OK)",
        id, r.phys_base, r.size
    );
}
