//! Per-CPU data and SMP utilities.
//!
//! Each CPU has a `PerCpuData` entry in a fixed-size array, indexed by CPU ID.
//! CPU ID is read from architecture-specific registers:
//!   AArch64: TPIDR_EL1
//!   RISC-V:  tp register
//!   x86-64:  LAPIC ID register

use super::thread::ThreadId;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

/// Maximum CPUs supported (compile-time, selected via cargo feature).
#[cfg(feature = "max_cpus_4")]
pub const MAX_CPUS: usize = 4;
#[cfg(feature = "max_cpus_256")]
pub const MAX_CPUS: usize = 256;
#[cfg(feature = "max_cpus_1024")]
pub const MAX_CPUS: usize = 1024;
#[cfg(feature = "max_cpus_4096")]
pub const MAX_CPUS: usize = 4096;
#[cfg(not(any(
    feature = "max_cpus_4",
    feature = "max_cpus_256",
    feature = "max_cpus_1024",
    feature = "max_cpus_4096"
)))]
pub const MAX_CPUS: usize = 64;

// ── Runtime-detected CPU count ───────────────────────────────────────
//
// MAX_CPUS above is a compile-time *ceiling* that sizes bitmaps and the
// few bootstrap per-CPU slots that exist before phys::init runs. The
// runtime value `NR_CPUS` is the number of CPUs actually detected by
// firmware (optionally capped by the `nr_cpus=N` cmdline parameter), and
// it's what per-CPU *storage* scales with. See
// `/home/nyc/.claude/plans/sparkling-frolicking-pike.md`.

/// Runtime-detected CPU count. Defaults to 1 (BSP only) until
/// `detect_cpu_count()` runs between `parse_firmware()` and `phys::init()`.
static NR_CPUS: AtomicUsize = AtomicUsize::new(1);

/// Number of CPUs actually present (detected + cmdline-capped). Use this
/// for loop bounds and to size dynamically-allocated per-CPU storage.
/// `MAX_CPUS` remains the compile-time ceiling used only for bitmap width
/// and the handful of Tier-1 bootstrap slots.
#[inline]
pub fn num_cpus() -> usize {
    NR_CPUS.load(Ordering::Relaxed)
}

/// Discover the real CPU count from firmware and apply the optional
/// `nr_cpus=N` cmdline cap. Call once from the BSP between
/// `parse_firmware()` and `phys::init()`. Returns the resolved count.
pub fn detect_cpu_count() -> usize {
    let detected = crate::firmware::cpu_count() as usize;
    let capped = match crate::boot::cmdline::nr_cpus_cap() {
        Some(cap) => detected.min(cap),
        None => detected,
    };
    let n = capped.max(1).min(MAX_CPUS);
    NR_CPUS.store(n, Ordering::Release);
    n
}

/// Allocate and install dynamic per-CPU slices. Called once from the BSP
/// just after `phys::init()` returns, before `sched::init()`. Each module
/// that owns per-CPU state publishes its own slices here.
pub fn init_dynamic_percpu() {
    debug_assert!(NR_CPUS.load(Ordering::Relaxed) >= 1);
    debug_assert!(num_cpus() <= MAX_CPUS);

    // PER_CPU itself.
    let n = num_cpus();
    unsafe {
        let s = crate::mm::phys::alloc_static_slice::<PerCpuData>(n);
        // PerCpuData::new() produces an all-zero image, matching what
        // alloc_static_slice gives us. No explicit init needed.
        PER_CPU_PTR.store(s.as_mut_ptr(), Ordering::Release);
    }

    // Per-module slices.
    super::scheduler::init_dynamic_percpu();
    super::hotplug::init_dynamic_percpu();
    super::topology::init_dynamic_percpu();
    crate::sync::rcu::init_dynamic_percpu();
    crate::mm::phys::init_dynamic_percpu();
    crate::mm::slab::init_dynamic_percpu();
}

/// Per-hart trap scratch data for RISC-V tp/sscratch swap convention.
/// Accessed from vectors.S — layout and symbol name must stay in sync.
#[cfg(target_arch = "riscv64")]
#[repr(C, align(32))]
pub struct TrapScratch {
    pub kernel_sp: u64, // offset 0: kernel stack pointer for user traps
    pub cpu_id: u64,    // offset 8: this hart's CPU ID
    pub user_sp: u64,   // offset 16: temporary save of user sp during trap entry
    pub _pad: u64,      // offset 24: padding to 32 bytes
}

#[cfg(target_arch = "riscv64")]
#[unsafe(no_mangle)]
pub static mut TRAP_SCRATCH_ARRAY: [TrapScratch; MAX_CPUS] = {
    const INIT: TrapScratch = TrapScratch {
        kernel_sp: 0,
        cpu_id: 0,
        user_sp: 0,
        _pad: 0,
    };
    [INIT; MAX_CPUS]
};

/// Per-CPU trap scratch data for LoongArch64.
/// CSR.SAVE0 points to &TRAP_SCRATCH_ARRAY[cpu] when in user mode (0 in kernel mode).
/// Accessed from vectors.S — layout and symbol name must stay in sync.
#[cfg(target_arch = "loongarch64")]
#[repr(C, align(32))]
pub struct TrapScratch {
    pub kernel_sp: u64, // offset 0
    pub cpu_id: u64,    // offset 8
    pub user_sp: u64,   // offset 16
    pub _pad: u64,      // offset 24
}

#[cfg(target_arch = "loongarch64")]
#[unsafe(no_mangle)]
pub static mut TRAP_SCRATCH_ARRAY: [TrapScratch; MAX_CPUS] = {
    const INIT: TrapScratch = TrapScratch {
        kernel_sp: 0,
        cpu_id: 0,
        user_sp: 0,
        _pad: 0,
    };
    [INIT; MAX_CPUS]
};

/// Per-CPU trap scratch data for MIPS64.
/// KScratch0 (CP0 $31 sel 2) points to &TRAP_SCRATCH_ARRAY[cpu] when in user mode (0 in kernel).
/// Accessed from vectors.S — layout and symbol name must stay in sync.
#[cfg(target_arch = "mips64")]
#[repr(C, align(32))]
pub struct TrapScratch {
    pub kernel_sp: u64, // offset 0
    pub cpu_id: u64,    // offset 8
    pub user_sp: u64,   // offset 16
    pub _pad: u64,      // offset 24
}

#[cfg(target_arch = "mips64")]
#[unsafe(no_mangle)]
pub static mut TRAP_SCRATCH_ARRAY: [TrapScratch; MAX_CPUS] = {
    const INIT: TrapScratch = TrapScratch {
        kernel_sp: 0,
        cpu_id: 0,
        user_sp: 0,
        _pad: 0,
    };
    [INIT; MAX_CPUS]
};

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

/// Dynamic per-CPU data slice. Installed by `init_dynamic_percpu` after
/// phys::init; indexed by CPU id thereafter.
static PER_CPU_PTR: AtomicPtr<PerCpuData> = AtomicPtr::new(core::ptr::null_mut());

/// Get a per-CPU entry by raw pointer arithmetic, skipping slice bounds
/// checks. The caller must ensure `cpu < num_cpus()` (true for any valid
/// cpu_id). This is the hot accessor used by the scheduler.
#[inline]
fn per_cpu_at(cpu: usize) -> &'static PerCpuData {
    let ptr = PER_CPU_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "PER_CPU not init");
    debug_assert!(cpu < num_cpus());
    unsafe { &*ptr.add(cpu) }
}

/// Number of CPUs that have completed initialization.
static ONLINE_CPUS: AtomicU32 = AtomicU32::new(0);

/// Get the current CPU's ID (0-based index).
#[inline]
pub fn cpu_id() -> u32 {
    crate::arch::cpu::cpu_id()
}

/// Get per-CPU data for the given CPU index.
#[inline]
pub fn get(cpu: u32) -> &'static PerCpuData {
    per_cpu_at(cpu as usize)
}

/// Get per-CPU data for the current CPU.
#[inline]
pub fn current() -> &'static PerCpuData {
    get(cpu_id())
}

/// Initialize BSP's per-CPU data. Called once during scheduler init.
pub fn init_bsp(idle_thread: ThreadId) {
    crate::arch::cpu::init_bsp_cpu_id();

    // Update trap scratch array for boot CPU.
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
    unsafe {
        TRAP_SCRATCH_ARRAY[0].cpu_id = 0;
    }

    let pcpu = get(0);
    pcpu.current_thread.store(idle_thread, Ordering::Relaxed);
    pcpu.idle_thread_id.store(idle_thread, Ordering::Relaxed);
    pcpu.online.store(true, Ordering::Release);
    ONLINE_CPUS.store(1, Ordering::Release);
}

/// Called by each secondary CPU after it finishes local init.
pub fn init_ap(cpu: u32, idle_thread: ThreadId) {
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
    unsafe {
        TRAP_SCRATCH_ARRAY[cpu as usize].cpu_id = cpu as u64;
    }

    let pcpu = get(cpu);
    pcpu.current_thread.store(idle_thread, Ordering::Relaxed);
    pcpu.idle_thread_id.store(idle_thread, Ordering::Relaxed);
    pcpu.online.store(true, Ordering::Release);
    ONLINE_CPUS.fetch_add(1, Ordering::Release);
}

/// Number of CPUs currently online (reflects hotplug state).
#[allow(dead_code)]
pub fn online_cpus() -> u32 {
    let mask = super::hotplug::online_mask();
    mask.count()
}
