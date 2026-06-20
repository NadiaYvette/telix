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

/// Address of the `NR_CPUS` static, for arming a #228 hardware watchpoint on
/// it.  `NR_CPUS` is written once by `detect_cpu_count()` then read-only, so
/// any later store is the wild-write that scribbles `num_cpus` (surfacing as
/// the `scheduler.rs:7157` index-out-of-bounds OOB under rv64 real-park).
#[allow(dead_code)]
pub fn nr_cpus_addr() -> u64 {
    &NR_CPUS as *const _ as u64
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
        // #208 STATIC-LAYOUT: PerCpuData base + stride (0x290 from FBD
        // analysis matched PerCpuData size — print here to confirm).
        let base = s.as_mut_ptr() as u64;
        let stride = core::mem::size_of::<PerCpuData>() as u64;
        crate::println!(
            "STATIC-LAYOUT: PER_CPU_PTR={:#x} stride={:#x} ({} bytes) n={}",
            base, stride, stride, n
        );
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
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::smp::init_dynamic_percpu();
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

/// #135 cli_max-per-callsite top-N table size.  Each entry holds a
/// unique caller RIP, its max single-CLI duration, and a hit count.
/// 8 slots gives plenty of headroom — a 4-CPU kernel rarely has more
/// than a handful of distinct CLI offenders worth printing.
pub const CLI_TOP_N: usize = 8;

/// One entry in the cli_max-per-callsite table.  All fields are
/// AtomicU64 for lock-free single-writer access (the owning CPU's
/// `record_cli_exit`) plus diagnostic cross-CPU reads.
pub struct CliTopSlot {
    pub rip: core::sync::atomic::AtomicU64,
    pub cycles: core::sync::atomic::AtomicU64,
    pub count: core::sync::atomic::AtomicU64,
}

impl CliTopSlot {
    pub const fn new() -> Self {
        Self {
            rip: core::sync::atomic::AtomicU64::new(0),
            cycles: core::sync::atomic::AtomicU64::new(0),
            count: core::sync::atomic::AtomicU64::new(0),
        }
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
    /// #135 IPI delivery probe: count of vector 0xFD (reschedule IPI)
    /// entries on this CPU.  Bumped at IPI vector handler entry in
    /// arch/x86_64/exception.rs.  Compared with `dispatch_count` to
    /// detect "IPI arrives but try_switch picks nothing" — a sign of
    /// run-queue / on_cpu transition problems.
    pub ipi_recv_count: core::sync::atomic::AtomicU64,
    /// Layer 4 paravirt: `get_monotonic_ns()` snapshot at the most
    /// recent reschedule-IPI receipt on this CPU.  Used by wake routing
    /// to detect "this vCPU is online and dispatching but isn't being
    /// reached by IPIs" — a residual #135 / virt-IPI-delivery pathology
    /// that steal-time can't see.  Stamped at IPI handler entry beside
    /// `ipi_recv_count`.
    pub last_ipi_recv_ns: core::sync::atomic::AtomicU64,
    /// Layer 4 Stage-1 autotune: EWMA mean of IPI inter-arrival
    /// times in ns.  Updated at IPI handler entry.  Used together
    /// with `ipi_interarrival_mad_ns` to compute an adaptive
    /// staleness threshold (μ + k·MAD) per CPU, replacing the
    /// hand-coded `IPI_STALE_NS` constant.  α = 1/16 (fixed).
    pub ipi_interarrival_mean_ns: core::sync::atomic::AtomicU64,
    /// EWMA of mean absolute deviation (MAD) of IPI inter-arrival
    /// times.  MAD is used instead of stddev to avoid sqrt and to
    /// be more robust to outliers (single huge gaps don't poison
    /// the dispersion estimate as quickly).
    pub ipi_interarrival_mad_ns: core::sync::atomic::AtomicU64,
    /// #135 IPI send breakdown by target.  send_reschedule_ipi bumps
    /// `smp::current().ipi_send_to[target]`.  Sum across all CPUs'
    /// arrays gives the global send-to-target totals; the per-CPU
    /// breakdown identifies which CPU is doing the waking.  Compared
    /// with `ipi_recv_count` (target side) to find delivery losses.
    pub ipi_send_to: [core::sync::atomic::AtomicU64; 8],
    /// #135 wake-to-dispatch latency histogram.  4 sub-buckets per decade
    /// over 1µs..1s (6 decades = 24 sub-buckets), plus an underflow
    /// bucket (<1µs) and an overflow bucket (≥1s) for 26 total.  Bumped
    /// in `dispatch_cas_ok` when the matching `pending_set_ns` is
    /// non-zero.  Cutpoints follow log-spaced sub-decade boundaries
    /// (10^(0.25k) per step); see `LAT_CUTS_NS` in scheduler.rs.  Dumps
    /// compute p50/p90/p99/p99.9 from cumulative sums so the per-CPU
    /// log line stays narrow while preserving tail visibility.
    pub dispatch_latency_hist: [core::sync::atomic::AtomicU64; 26],
    /// #135 CLI-residency probe: TSC at the most recent first-level
    /// `arch::irq::disable()` on this CPU.  Updated only on outermost
    /// transition (IF was set before).  Restore reads it back to
    /// compute the CLI-region duration.  0 means no CLI region open.
    pub cli_enter_tsc: core::sync::atomic::AtomicU64,
    /// Cumulative TSC cycles spent with interrupts disabled on this CPU.
    pub cli_total_cycles: core::sync::atomic::AtomicU64,
    /// Largest single CLI region observed on this CPU (TSC cycles).
    pub cli_max_cycles: core::sync::atomic::AtomicU64,
    /// Count of outermost CLI regions (one per disable/restore pair).
    pub cli_count: core::sync::atomic::AtomicU64,
    /// #135 last try_switch entry timestamp (monotonic_ns).  Stamped at
    /// try_switch entry on this CPU.  If a stuck thread's last_cpu shows
    /// last_try_switch_ns far in the past (e.g. >5s ago when rescue fires),
    /// that CPU has stopped scheduling — the wedge is a per-CPU halt, not
    /// a per-thread loss.
    pub last_try_switch_ns: core::sync::atomic::AtomicU64,
    /// #135 last interrupt entry timestamp on this CPU (any vector).
    /// Compare with `last_try_switch_ns` to distinguish:
    ///   * last_irq fresh, last_try_switch stale: CPU is taking IRQs
    ///     but the handler isn't reaching the scheduler (stuck in some
    ///     IRQ handler that doesn't go through try_switch).
    ///   * Both stale: CPU is truly halted — no IRQs arriving, LAPIC
    ///     delivery broken or vCPU descheduled by host.
    pub last_irq_ns: core::sync::atomic::AtomicU64,
    /// Layer 3 paravirt: host-vCPU steal time (ns) snapshot taken on
    /// each successful try_switch CAS_OK on this CPU.  The rescue path
    /// compares this against `steal_time_ns_of_cpu(last_cpu)` to
    /// compute "stolen ns since last successful dispatch on last_cpu" —
    /// a positive confirmation that the picking CPU is currently being
    /// host-descheduled (vs. legitimately busy in a long CLI region).
    /// 0 = never set / hypervisor doesn't expose steal-time.
    pub steal_ns_at_last_dispatch: core::sync::atomic::AtomicU64,
    /// #135 CLI callsite probe: RIP captured when entering the outermost
    /// CLI region.  Updated by `record_cli_enter_rip` from arch::irq::disable.
    /// On a max-CLI update in `record_cli_exit`, copied into `cli_max_rip`
    /// so the rescue dump can identify the kernel callsite that held
    /// interrupts off the longest.  Boot 26: cpu=3 cli_max=97ms — finding
    /// the RIP nails the offending Linux-personality forward path.
    pub cli_enter_rip: core::sync::atomic::AtomicU64,
    pub cli_max_rip: core::sync::atomic::AtomicU64,
    /// #135 cli_max-per-callsite table.  Top-N RIPs by max single-CLI
    /// duration on this CPU, with a hit count per RIP.  The single
    /// cli_max_rip above gives the *worst* offender; this table shows
    /// the *top several* so we can see whether the 97ms culprit is one
    /// callsite or a family.  Only the owning CPU writes to it
    /// (record_cli_exit), so torn cross-CPU reads in the rescue dump
    /// are acceptable — diagnostic-only.
    pub cli_top: [CliTopSlot; CLI_TOP_N],
    /// #135 LAPIC state snapshot — written by this CPU's own timer-tick
    /// handler (vector 32, which is known-working across all CPUs).
    /// Read cross-CPU by the rescue dump.  Diagnoses vector-0xFD
    /// stuck-ISR (missed-EOI), abnormal TPR (priority class blocking
    /// 0xFD), or disabled SVR (LAPIC software-disabled).
    ///   lapic_isr_f: register 0x170 (ISR vectors 224-255; bit 29 = 0xFD)
    ///   lapic_irr_f: register 0x270 (IRR vectors 224-255; bit 29 = 0xFD)
    ///   lapic_tpr:   register 0x080 (Task Priority Register)
    ///   lapic_svr:   register 0x0F0 (Spurious-Interrupt Vector Register)
    ///   lapic_ppr:   register 0x0A0 (Processor Priority Register —
    ///                effective mask = max(TPR_class, ISR_class).  If
    ///                anything stuck in low-vector ISR, PPR is high
    ///                even when ISR_F (high) is clean.)
    ///   lapic_esr:   register 0x280 (Error Status Register — APIC
    ///                detected delivery errors, IPI send/receive faults)
    ///   lapic_isr_lo_or: OR of ISR vectors 0-223 (registers 0x100-0x160,
    ///                7 dwords).  Non-zero means SOMETHING low-priority
    ///                is in-service somewhere, which raises PPR and
    ///                blocks higher-class vectors during the window.
    pub lapic_isr_f: core::sync::atomic::AtomicU32,
    pub lapic_irr_f: core::sync::atomic::AtomicU32,
    pub lapic_tpr: core::sync::atomic::AtomicU32,
    pub lapic_svr: core::sync::atomic::AtomicU32,
    pub lapic_ppr: core::sync::atomic::AtomicU32,
    pub lapic_esr: core::sync::atomic::AtomicU32,
    pub lapic_isr_lo_or: core::sync::atomic::AtomicU32,
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
            ipi_recv_count: core::sync::atomic::AtomicU64::new(0),
            last_ipi_recv_ns: core::sync::atomic::AtomicU64::new(0),
            ipi_interarrival_mean_ns: core::sync::atomic::AtomicU64::new(0),
            ipi_interarrival_mad_ns: core::sync::atomic::AtomicU64::new(0),
            ipi_send_to: [const { core::sync::atomic::AtomicU64::new(0) }; 8],
            dispatch_latency_hist: [const { core::sync::atomic::AtomicU64::new(0) }; 26],
            cli_enter_tsc: core::sync::atomic::AtomicU64::new(0),
            cli_total_cycles: core::sync::atomic::AtomicU64::new(0),
            cli_max_cycles: core::sync::atomic::AtomicU64::new(0),
            cli_count: core::sync::atomic::AtomicU64::new(0),
            last_try_switch_ns: core::sync::atomic::AtomicU64::new(0),
            last_irq_ns: core::sync::atomic::AtomicU64::new(0),
            steal_ns_at_last_dispatch: core::sync::atomic::AtomicU64::new(0),
            cli_enter_rip: core::sync::atomic::AtomicU64::new(0),
            cli_max_rip: core::sync::atomic::AtomicU64::new(0),
            cli_top: [const { CliTopSlot::new() }; CLI_TOP_N],
            lapic_isr_f: core::sync::atomic::AtomicU32::new(0),
            lapic_irr_f: core::sync::atomic::AtomicU32::new(0),
            lapic_tpr: core::sync::atomic::AtomicU32::new(0),
            lapic_svr: core::sync::atomic::AtomicU32::new(0),
            lapic_ppr: core::sync::atomic::AtomicU32::new(0),
            lapic_esr: core::sync::atomic::AtomicU32::new(0),
            lapic_isr_lo_or: core::sync::atomic::AtomicU32::new(0),
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

/// #135 CLI-residency probe: called from `arch::irq::disable()` on the
/// outermost transition (when IF was set before).  Records the entry TSC
/// and caller RIP on the current CPU.  No-op until PER_CPU_PTR is
/// populated.  The RIP is captured at the CLI call-site by the caller
/// (irq::disable is #[inline(always)] so the lea materializes in the
/// caller's body); seeing this RIP in the cli_max_rip rescue field
/// pinpoints which kernel function holds interrupts off the longest.
#[inline]
pub fn record_cli_enter(rip: u64) {
    let ptr = PER_CPU_PTR.load(Ordering::Relaxed);
    if ptr.is_null() { return; }
    let cpu = cpu_id() as usize;
    if cpu >= num_cpus() { return; }
    #[cfg(target_arch = "x86_64")]
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(not(target_arch = "x86_64"))]
    let tsc: u64 = 0;
    let pcpu = unsafe { &*ptr.add(cpu) };
    pcpu.cli_enter_tsc.store(tsc, Ordering::Relaxed);
    pcpu.cli_enter_rip.store(rip, Ordering::Relaxed);
}

/// #135 CLI-residency probe: called from `arch::irq::restore()` on the
/// outermost transition (when IF will be re-enabled).  Reads the matching
/// entry TSC and accumulates the delta into total/max/count.
#[inline]
pub fn record_cli_exit() {
    let ptr = PER_CPU_PTR.load(Ordering::Relaxed);
    if ptr.is_null() { return; }
    let cpu = cpu_id() as usize;
    if cpu >= num_cpus() { return; }
    let pcpu = unsafe { &*ptr.add(cpu) };
    let enter = pcpu.cli_enter_tsc.load(Ordering::Relaxed);
    if enter == 0 { return; }
    #[cfg(target_arch = "x86_64")]
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(not(target_arch = "x86_64"))]
    let now: u64 = 0;
    let delta = now.wrapping_sub(enter);
    pcpu.cli_total_cycles.fetch_add(delta, Ordering::Relaxed);
    pcpu.cli_count.fetch_add(1, Ordering::Relaxed);
    let mut cur_max = pcpu.cli_max_cycles.load(Ordering::Relaxed);
    let mut bumped_max = false;
    while delta > cur_max {
        match pcpu.cli_max_cycles.compare_exchange_weak(
            cur_max, delta, Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => { bumped_max = true; break; }
            Err(observed) => cur_max = observed,
        }
    }
    if bumped_max {
        // Record the RIP that produced this new cli_max so the rescue
        // dump shows which kernel callsite is the worst offender.
        let rip = pcpu.cli_enter_rip.load(Ordering::Relaxed);
        pcpu.cli_max_rip.store(rip, Ordering::Relaxed);
    }
    // #135 per-callsite tracking: update the top-N table.  Only consider
    // CLI regions > CLI_TOP_THRESHOLD (~100µs) to avoid drowning the
    // table in trivial disable/restore pairs.  Single-writer (this CPU
    // owns the table), so no CAS needed — plain loads/stores.
    let rip = pcpu.cli_enter_rip.load(Ordering::Relaxed);
    if rip != 0 && delta > CLI_TOP_THRESHOLD_CYCLES {
        update_cli_top(pcpu, rip, delta);
    }
    pcpu.cli_enter_tsc.store(0, Ordering::Relaxed);
}

/// #135 cli_top threshold: only track CLI regions > ~100µs.  At
/// TSC=2.19GHz this is ~219K cycles.  Hard-coding a cycle threshold
/// avoids a runtime divide; the actual cutoff scales with TSC freq
/// but that's fine for relative ordering.
const CLI_TOP_THRESHOLD_CYCLES: u64 = 200_000;

/// Update the per-CPU cli_top table with one observation.  Single-
/// writer (the owning CPU); other CPUs only READ for diagnostics.
fn update_cli_top(pcpu: &PerCpuData, rip: u64, delta: u64) {
    // Linear scan for matching RIP first.  Track the slot with the
    // smallest cycles (the eviction candidate) in case we need to
    // insert a new RIP.
    let mut min_idx: usize = 0;
    let mut min_cycles: u64 = u64::MAX;
    for i in 0..CLI_TOP_N {
        let slot_rip = pcpu.cli_top[i].rip.load(Ordering::Relaxed);
        let slot_cycles = pcpu.cli_top[i].cycles.load(Ordering::Relaxed);
        if slot_rip == rip {
            // Existing entry — update max if greater, always bump count.
            if delta > slot_cycles {
                pcpu.cli_top[i].cycles.store(delta, Ordering::Relaxed);
            }
            pcpu.cli_top[i].count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if slot_cycles < min_cycles {
            min_cycles = slot_cycles;
            min_idx = i;
        }
    }
    // No matching RIP.  Evict smallest-cycles slot ONLY IF our delta
    // is larger — otherwise the existing entry was the bigger offender
    // and we should leave it.
    if delta > min_cycles {
        pcpu.cli_top[min_idx].rip.store(rip, Ordering::Relaxed);
        pcpu.cli_top[min_idx].cycles.store(delta, Ordering::Relaxed);
        pcpu.cli_top[min_idx].count.store(1, Ordering::Relaxed);
    }
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
