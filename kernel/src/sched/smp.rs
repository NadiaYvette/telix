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
pub const MAX_CPUS: usize = 256;

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
pub(crate) static NR_CPUS: AtomicUsize = AtomicUsize::new(1);

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

    // TrapScratch slice (riscv64/loongarch64/mips64 only).
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
    init_dynamic_percpu_trap_scratch();

    // Per-arch AP stack regions.
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::smp::init_dynamic_percpu();
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::smp::init_dynamic_percpu();
    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::smp::init_dynamic_percpu();
}

/// Per-CPU trap scratch data, used by archs whose user→kernel trap entry
/// loads the kernel sp from a CPU-local scratch register that points into
/// this slice. Layout and size are referenced from vectors.S — keep in
/// sync (size must be 32 bytes; field offsets baked into asm).
///
/// - RISC-V: sscratch = &TRAP_SCRATCH[cpu] in U-mode, 0 in S-mode
/// - LoongArch64: SAVE0 = &TRAP_SCRATCH[cpu] in user mode, 0 in kernel
/// - MIPS64 (single-CPU): KScratch0 = &TRAP_SCRATCH[0]
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
#[repr(C, align(32))]
pub struct TrapScratch {
    pub kernel_sp: u64, // offset 0
    pub cpu_id: u64,    // offset 8
    pub user_sp: u64,   // offset 16
    pub _pad: u64,      // offset 24
}

/// Pointer to the dynamic per-CPU TrapScratch slice. Trap vector asm reads
/// this symbol (`ld base, TRAP_SCRATCH_BASE`) then indexes by cpu_id to
/// compute `&TRAP_SCRATCH[cpu]` on the user-return path.
///
/// `#[no_mangle]` because vectors.S references it by name.
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
#[unsafe(no_mangle)]
pub static mut TRAP_SCRATCH_BASE: u64 = 0;

/// Rust-side accessor: pointer to the dynamic TrapScratch slice. Mirrors
/// `TRAP_SCRATCH_BASE` (kept in lockstep at init time).
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
static TRAP_SCRATCH_PTR: AtomicPtr<TrapScratch> = AtomicPtr::new(core::ptr::null_mut());

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
#[inline]
fn trap_scratch_at(cpu: usize) -> *mut TrapScratch {
    let base = TRAP_SCRATCH_PTR.load(Ordering::Relaxed);
    debug_assert!(!base.is_null(), "TRAP_SCRATCH not init");
    debug_assert!(cpu < num_cpus());
    unsafe { base.add(cpu) }
}

/// Get a pointer to the per-CPU TrapScratch entry. Used by `trapframe.rs`
/// when installing a kernel stack for a thread that's about to return to
/// user mode.
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
pub fn trap_scratch_for(cpu: usize) -> *mut TrapScratch {
    trap_scratch_at(cpu)
}

/// Allocate the dynamic TrapScratch slice and publish both `TRAP_SCRATCH_PTR`
/// (Rust) and `TRAP_SCRATCH_BASE` (asm symbol). Called from
/// `init_dynamic_percpu` after `phys::init`.
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
pub(crate) fn init_dynamic_percpu_trap_scratch() {
    let n = num_cpus();
    unsafe {
        let s = crate::mm::phys::alloc_static_slice::<TrapScratch>(n);
        let ptr = s.as_mut_ptr();
        TRAP_SCRATCH_PTR.store(ptr, Ordering::Release);
        TRAP_SCRATCH_BASE = ptr as u64;
    }
}

/// Per-CPU data. Each CPU has its own instance, accessed lock-free by cpu_id().
pub struct PerCpuData {
    /// Currently running thread on this CPU.
    pub current_thread: AtomicU32,
    /// Idle thread for this CPU (runs when no ready threads).
    pub idle_thread_id: AtomicU32,
    /// Whether this CPU is online and participating in scheduling.
    pub online: AtomicBool,
    /// Set by wake_thread()/tick() when a reschedule is needed.
    /// Checked on syscall return to trigger preemption.
    pub need_resched: AtomicBool,
    /// Tid currently being dispatched on this CPU (0 = no dispatch).
    /// Set by try_switch BEFORE the on_cpu CAS; cleared AFTER state=Running
    /// and current_thread store.  Lets the rescue path skip threads in the
    /// transient (state=Ready, on_cpu=cpu_real, current_thread=prev_id)
    /// dispatch window — try_switch's CAS already won, but the thread
    /// hasn't transitioned to Running yet.  Without this hint rescue would
    /// false-fire stale_on_cpu, re-enqueue the dispatching thread, and
    /// trigger DOUBLE-SCHED detection that kills it.
    pub dispatching_tid: AtomicU32,
    /// Total successful dispatches on this CPU since boot.  Diagnostic for
    /// #120-class issues — divides total runtime / dispatches gives average
    /// timeslice; lets us spot CPUs that are idle vs CPUs that thrash.
    pub dispatch_count: core::sync::atomic::AtomicU64,
    /// Tid most recently dispatched on this CPU.  Combined with `dispatch_streak`
    /// it reveals the EEVDF LIFO cycling pattern: with all-equal deadlines
    /// strict-`<` pick_eligible drains position 0, the heap backfills from
    /// the tail, and the re-enqueued thread lands at the tail again — so the
    /// same tid wins picks back-to-back.  A long streak on one CPU paired
    /// with starved tids in the same heap is the smoking gun.
    pub last_dispatched_tid: AtomicU32,
    /// Consecutive dispatches of the same tid on this CPU; reset to 1 when
    /// a different tid is dispatched.
    pub dispatch_streak: AtomicU32,
    /// #120 dispatch-symmetry pair (set-pending side).  Bumped each time
    /// `dequeue_set_pending` runs, i.e. each time a dispatching path on this
    /// CPU pops a tid from the run queue and stores ON_CPU_PENDING on it.
    /// Compare with `dispatch_cas_ok_count`: if `set_pending` >> `cas_ok`,
    /// threads enter PENDING but never reach the try_switch CAS-ok point,
    /// which is the residual #120 oscillation signature.
    pub dispatch_set_pending_count: core::sync::atomic::AtomicU64,
    /// #120 dispatch-symmetry pair (cas-ok side).  Bumped at the
    /// `try_switch.cas_ok` trace point in both try_switch and
    /// voluntary_reschedule, after `compare_exchange(PENDING, cpu)`
    /// succeeds.  See `dispatch_set_pending_count`.
    pub dispatch_cas_ok_count: core::sync::atomic::AtomicU64,
    /// #120 per-CPU asymmetry probe: counts RESCUE-STUCK-PENDING fires
    /// attributed to this CPU.  Attribution uses the stuck thread's
    /// `last_cpu` (since `on_cpu == ON_CPU_PENDING` at that point, the
    /// dispatching/parking CPU identity is in `last_cpu`).  If one CPU's
    /// count dominates by 10×+, the original #120 lead — "EEVDF pick-next
    /// never picks rescue-enqueued threads on CPU N specifically" — is
    /// still live.  Pure diagnostic; no concurrency-protocol meaning.
    pub rescue_stuck_pending_count: core::sync::atomic::AtomicU64,
}

impl PerCpuData {
    pub const fn new() -> Self {
        Self {
            current_thread: AtomicU32::new(0),
            idle_thread_id: AtomicU32::new(0),
            online: AtomicBool::new(false),
            need_resched: AtomicBool::new(false),
            dispatching_tid: AtomicU32::new(0),
            dispatch_count: core::sync::atomic::AtomicU64::new(0),
            last_dispatched_tid: AtomicU32::new(0),
            dispatch_streak: AtomicU32::new(0),
            dispatch_set_pending_count: core::sync::atomic::AtomicU64::new(0),
            dispatch_cas_ok_count: core::sync::atomic::AtomicU64::new(0),
            rescue_stuck_pending_count: core::sync::atomic::AtomicU64::new(0),
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

    // Update trap scratch entry for boot CPU.
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "mips64"))]
    unsafe {
        (*trap_scratch_at(0)).cpu_id = 0;
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
        (*trap_scratch_at(cpu as usize)).cpu_id = cpu as u64;
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
