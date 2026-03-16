//! Per-CPU data and SMP utilities.
//!
//! Each CPU has a `PerCpuData` entry in a fixed-size array, indexed by CPU ID.
//! CPU ID is read from architecture-specific registers:
//!   AArch64: TPIDR_EL1
//!   RISC-V:  tp register
//!   x86-64:  LAPIC ID register

use super::thread::ThreadId;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

pub const MAX_CPUS: usize = 4;

/// Per-CPU data. Each CPU has its own instance, accessed lock-free by cpu_id().
pub struct PerCpuData {
    /// Currently running thread on this CPU.
    pub current_thread: AtomicU32,
    /// Idle thread for this CPU (runs when no ready threads).
    pub idle_thread_id: AtomicU32,
    /// Whether this CPU is online and participating in scheduling.
    pub online: AtomicBool,
}

impl PerCpuData {
    pub const fn new() -> Self {
        Self {
            current_thread: AtomicU32::new(0),
            idle_thread_id: AtomicU32::new(0),
            online: AtomicBool::new(false),
        }
    }
}

static PER_CPU: [PerCpuData; MAX_CPUS] = [const { PerCpuData::new() }; MAX_CPUS];

/// Number of CPUs that have completed initialization.
static ONLINE_CPUS: AtomicU32 = AtomicU32::new(0);

/// Get the current CPU's ID (0-based index).
#[inline]
pub fn cpu_id() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let id: u64;
        unsafe { core::arch::asm!("mrs {}, tpidr_el1", out(reg) id); }
        id as u32
    }
    #[cfg(target_arch = "riscv64")]
    {
        let id: u64;
        unsafe { core::arch::asm!("mv {}, tp", out(reg) id); }
        id as u32
    }
    #[cfg(target_arch = "x86_64")]
    {
        // Read LAPIC ID from xAPIC register at 0xFEE00020, bits [31:24].
        let lapic_id = unsafe { core::ptr::read_volatile(0xFEE0_0020 as *const u32) };
        (lapic_id >> 24) & 0xFF
    }
}

/// Get per-CPU data for the given CPU index.
#[inline]
pub fn get(cpu: u32) -> &'static PerCpuData {
    &PER_CPU[cpu as usize]
}

/// Get per-CPU data for the current CPU.
#[inline]
pub fn current() -> &'static PerCpuData {
    get(cpu_id())
}

/// Initialize BSP's per-CPU data. Called once during scheduler init.
pub fn init_bsp(idle_thread: ThreadId) {
    // AArch64: set TPIDR_EL1 = 0 for BSP
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr tpidr_el1, xzr");
    }

    // RISC-V: set tp = 0 for boot hart (we renumber to 0)
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv tp, zero");
    }

    // x86-64: LAPIC ID 0 is the BSP on QEMU — no setup needed.

    let pcpu = get(0);
    pcpu.current_thread.store(idle_thread, Ordering::Relaxed);
    pcpu.idle_thread_id.store(idle_thread, Ordering::Relaxed);
    pcpu.online.store(true, Ordering::Release);
    ONLINE_CPUS.store(1, Ordering::Release);
}

/// Called by each secondary CPU after it finishes local init.
pub fn init_ap(cpu: u32, idle_thread: ThreadId) {
    let pcpu = get(cpu);
    pcpu.current_thread.store(idle_thread, Ordering::Relaxed);
    pcpu.idle_thread_id.store(idle_thread, Ordering::Relaxed);
    pcpu.online.store(true, Ordering::Release);
    ONLINE_CPUS.fetch_add(1, Ordering::Release);
}

/// Number of CPUs currently online.
pub fn online_cpus() -> u32 {
    ONLINE_CPUS.load(Ordering::Acquire)
}
