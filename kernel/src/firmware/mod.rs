//! Firmware table parsing and hardware discovery.
//!
//! Provides zero-allocation parsers for DTB (aarch64/riscv64) and
//! ACPI+Multiboot (x86_64). Each arch calls its parser during early
//! boot, populating shared static arrays. Generic kernel code queries
//! the results through a uniform API.
//!
//! All writes happen on the BSP before secondary CPUs start.
//! All reads happen after a Release/Acquire pair on the counts.

pub mod dtb;
#[cfg(target_arch = "x86_64")]
pub mod acpi;
#[cfg(target_arch = "x86_64")]
pub mod multiboot;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::sched::smp::MAX_CPUS;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

pub const MAX_MEM_REGIONS: usize = 8;
pub const MAX_DEVICES: usize = 32;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A physical memory region (available RAM).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct MemRegion {
    pub base: u64,
    pub size: u64,
}

/// A CPU descriptor discovered from firmware tables.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct CpuDesc {
    /// Platform-specific ID: MPIDR (aarch64), hart ID (riscv64), APIC ID (x86_64).
    pub id: u32,
    /// Bit 0 = enabled/online-capable.
    pub flags: u32,
}

/// A virtio-mmio device discovered from DTB.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct VirtioMmioDesc {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
    pub _pad: u32,
}

/// Interrupt controller info (stored for future use).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct IrqControllerInfo {
    /// 0=unknown, 1=GICv3, 2=PLIC, 3=LAPIC+IOAPIC
    pub kind: u32,
    pub _pad: u32,
    /// GIC distributor / PLIC base / LAPIC base
    pub base0: u64,
    /// GIC redistributor / IO APIC base
    pub base1: u64,
}

// ---------------------------------------------------------------------------
// Static storage — UnsafeCell + atomic counts (write-once during boot)
// ---------------------------------------------------------------------------

// SAFETY: Written only by BSP before secondary CPUs start (single-writer),
// read after Acquire on the corresponding count (many-reader). The UnsafeCell
// is needed because we write through shared references during boot.

struct FwArray<T, const N: usize> {
    data: [UnsafeCell<T>; N],
    count: AtomicU32,
}

// SAFETY: Access is protected by the atomic count — writes happen on BSP
// before secondaries start, reads use Acquire ordering on count.
unsafe impl<T, const N: usize> Sync for FwArray<T, N> {}

impl<T: Copy + Default, const N: usize> FwArray<T, N> {
    const fn new() -> Self {
        // SAFETY: Default for our types is all-zeros, which is a valid UnsafeCell init.
        Self {
            data: unsafe { core::mem::zeroed() },
            count: AtomicU32::new(0),
        }
    }

    fn push(&self, val: T) -> bool {
        let idx = self.count.load(Ordering::Relaxed) as usize;
        if idx >= N { return false; }
        unsafe { *self.data[idx].get() = val; }
        self.count.store((idx + 1) as u32, Ordering::Release);
        true
    }

    fn as_slice(&self) -> &[T] {
        let n = self.count.load(Ordering::Acquire) as usize;
        // SAFETY: elements 0..n were fully written before the Release store.
        unsafe { core::slice::from_raw_parts(self.data[0].get() as *const T, n) }
    }

    fn len(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

static MEM_REGIONS: FwArray<MemRegion, MAX_MEM_REGIONS> = FwArray::new();
static CPUS: FwArray<CpuDesc, MAX_CPUS> = FwArray::new();
static VIRTIO_DEVICES: FwArray<VirtioMmioDesc, MAX_DEVICES> = FwArray::new();

// Wrapper to allow UnsafeCell<IrqControllerInfo> in a static.
struct IrqCtrlCell(UnsafeCell<IrqControllerInfo>);
// SAFETY: same single-writer (BSP) / post-boot-read pattern as FwArray.
unsafe impl Sync for IrqCtrlCell {}

static IRQ_CTRL: IrqCtrlCell = IrqCtrlCell(UnsafeCell::new(IrqControllerInfo {
    kind: 0, _pad: 0, base0: 0, base1: 0,
}));

static IRQ_CTRL_SET: AtomicU32 = AtomicU32::new(0);
static TIMEBASE_FREQ: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Public accessors
// ---------------------------------------------------------------------------

/// Available RAM regions discovered from firmware.
pub fn mem_regions() -> &'static [MemRegion] {
    MEM_REGIONS.as_slice()
}

/// CPU descriptors discovered from firmware.
pub fn cpus() -> &'static [CpuDesc] {
    CPUS.as_slice()
}

/// Number of CPUs discovered.
pub fn cpu_count() -> u32 {
    CPUS.len()
}

/// Virtio-mmio devices discovered from DTB.
pub fn virtio_devices() -> &'static [VirtioMmioDesc] {
    VIRTIO_DEVICES.as_slice()
}

/// Interrupt controller info (GIC / PLIC / LAPIC+IOAPIC).
pub fn irq_controller() -> IrqControllerInfo {
    if IRQ_CTRL_SET.load(Ordering::Acquire) != 0 {
        unsafe { *IRQ_CTRL.0.get() }
    } else {
        IrqControllerInfo::default()
    }
}

/// RISC-V timebase frequency from DTB (0 if not set).
pub fn timebase_freq() -> u64 {
    TIMEBASE_FREQ.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Internal push functions (called by arch-specific parsers)
// ---------------------------------------------------------------------------

pub(crate) fn push_mem_region(r: MemRegion) {
    MEM_REGIONS.push(r);
}

pub(crate) fn push_cpu(c: CpuDesc) {
    CPUS.push(c);
}

pub(crate) fn push_virtio(d: VirtioMmioDesc) {
    VIRTIO_DEVICES.push(d);
}

pub(crate) fn set_irq_controller(info: IrqControllerInfo) {
    unsafe { *IRQ_CTRL.0.get() = info; }
    IRQ_CTRL_SET.store(1, Ordering::Release);
}

pub(crate) fn set_timebase_freq(freq: u64) {
    TIMEBASE_FREQ.store(freq, Ordering::Release);
}
