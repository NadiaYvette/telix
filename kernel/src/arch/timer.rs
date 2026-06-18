//! Architecture-independent timer/cycle counter primitives.
//!
//! Centralizes cycle counter reads and timer frequency queries that were
//! previously duplicated via `#[cfg(target_arch)]` blocks in handlers.rs,
//! trace.rs, aspace.rs, and scheduler.rs.

/// Read the current cycle/time counter.
#[inline(always)]
pub fn read_cycles() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::timer::counter()
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::arch::riscv64::trap::read_time()
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::timer::rdtsc()
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let val: u64;
        unsafe {
            core::arch::asm!("rdtime.d {0}, $zero", out(reg) val);
        }
        val
    }
    #[cfg(target_arch = "mips64")]
    {
        let val: u64;
        unsafe {
            core::arch::asm!("dmfc0 {0}, $9", out(reg) val); // CP0.Count
        }
        val
    }
}

/// Return the timer/counter frequency in Hz.
#[inline]
pub fn timer_freq() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::timer::cntfrq()
    }
    #[cfg(target_arch = "riscv64")]
    {
        10_000_000
    } // QEMU virt timebase
    #[cfg(target_arch = "x86_64")]
    {
        // Calibrated at boot via CPUID 0x15/0x16; defaults to 1 GHz
        // until `arch::x86_64::timer::init_tsc_freq` runs.
        crate::arch::x86_64::timer::TSC_HZ.load(core::sync::atomic::Ordering::Acquire)
    }
    #[cfg(target_arch = "loongarch64")]
    {
        100_000_000
    } // QEMU virt Stable Counter = 100 MHz
    #[cfg(target_arch = "mips64")]
    {
        100_000_000
    } // QEMU Malta CP0.Count = 100 MHz
}

/// Get monotonic time in nanoseconds since boot.
///
/// REVERTED to pure TSC arithmetic.  Boots 47/48/49 showed that
/// folding pvclock or pvclock-steal_time into the primary monotonic
/// clock makes the scale inconsistent across initialization phases:
/// callers comparing readings taken at different times can see scale
/// jumps (TSC vs pvclock vs pvclock-steal) that produce 100+ second
/// spurious deltas.  Many heuristics depend on monotonic_ns's
/// absolute value (sleep deadlines, etc.), not just deltas, so a
/// post-init drop in the value would break them.
///
/// Use `vcpu_runtime_ns()` for the paravirt-aware "time the vCPU has
/// actually been running" reading.  Scheduler rescue heuristics that
/// should exclude host-pause durations call that instead.
#[inline]
pub fn monotonic_ns() -> u64 {
    let c = read_cycles() as u128;
    let f = timer_freq() as u128;
    ((c * 1_000_000_000u128) / f) as u64
}

/// Get vCPU-runtime time in nanoseconds since boot — like monotonic_ns
/// but with host-pause durations subtracted.  On x86_64 under KVM with
/// both pvclock and STEAL_TIME enabled, this returns pvclock_ns minus
/// the accumulated stolen ns from the per-CPU STEAL_TIME page.
///
/// Use for scheduler heuristics that should NOT count host-pause time
/// as "real" elapsed time (rescue ages, stuck-thread timeouts, etc.).
/// Falls back to monotonic_ns on bare metal or when paravirt isn't
/// available.
#[inline]
pub fn vcpu_runtime_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(ns) = crate::arch::x86_64::hypervisor::pvclock_now_ns() {
            let steal = crate::arch::hypervisor::ops()
                .steal_time_ns()
                .unwrap_or(0);
            return ns.saturating_sub(steal);
        }
    }
    // Fallback (non-x86, or x86 without pvclock): raw monotonic, minus the
    // synthetic-steal clamp when enabled (#nonx86 timer robustness (b)).  This
    // is the path that immunises arches with no PV steal-time (and TCG) against
    // tick stalls inflating rescue ages / IPC timeouts.
    let base = monotonic_ns();
    if SYNTHETIC_STEAL_CLAMP.load(core::sync::atomic::Ordering::Relaxed) {
        let cpu = crate::sched::smp::cpu_id() as usize;
        if cpu < PER_CPU_SYNTHETIC_STEAL_NS.len() {
            return base.saturating_sub(
                PER_CPU_SYNTHETIC_STEAL_NS[cpu]
                    .load(core::sync::atomic::Ordering::Relaxed),
            );
        }
    }
    base
}

// ===== (b) synthetic tick-gap clamp — non-x86 / no-PV-steal timer robustness =====
//
// Emulates the steal-time *decision* (don't count a stall as real vCPU-time)
// with no hypercall, so it works under TCG and on any arch lacking PV
// steal-time.  The precise signal is tick LATENESS vs the programmed deadline,
// NOT the raw inter-tick gap: Telix's dynamic tick legitimately programs the
// next tick up to ~1s out when idle, so a large gap is normal for an idle CPU.
// A tick that fires far PAST its programmed deadline, however, is a genuine
// stall (host deschedule / TCG stall / pathological IRQ-off region).

const SS_MAX_CPUS: usize = crate::sched::smp::MAX_CPUS;

/// Most-recently programmed one-shot deadline per CPU (ns since boot), written
/// by `program_oneshot_ns` when the clamp is enabled.  Lets `note_tick_fired`
/// measure how late a tick fired relative to when it was scheduled.
static PER_CPU_NEXT_DEADLINE_NS: [core::sync::atomic::AtomicU64; SS_MAX_CPUS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; SS_MAX_CPUS]
};

/// Per-CPU accumulated synthetic steal: ns by which ticks fired past their
/// deadline (beyond the noise threshold).  Subtracted from the
/// `vcpu_runtime_ns` fallback.  Monotonic non-decreasing per CPU, so the
/// fallback stays monotonic (a stall advances monotonic by `gap` and steal by
/// the lateness, leaving net progress ≈ the nominal interval).
static PER_CPU_SYNTHETIC_STEAL_NS: [core::sync::atomic::AtomicU64; SS_MAX_CPUS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; SS_MAX_CPUS]
};

/// Gate.  When on: `program_oneshot_ns` records deadlines, `note_tick_fired`
/// accumulates synthetic steal, and `vcpu_runtime_ns`'s fallback subtracts it.
///
/// Default ON for aarch64 only — validated 2026-06-18 by an oversubscribed
/// MTTCG efficacy A/B (N=8/arm): clamp ON caps the spurious-rescue tail
/// (RESCUE-STUCK-PENDING max 19→7, storms ≥10 1→0, total −33%) while server
/// bringup progress is identical (19–20 spawns/boot → no masking of real
/// starvation), 0 faults.  x86_64 OFF: it has real PV steal-time (pvclock −
/// MSR_KVM_STEAL_TIME) and never reaches the clamped fallback, so the clamp is
/// redundant there.  riscv64/loong/mips OFF pending their own per-arch smoke
/// (the mechanism is arch-neutral + safe-by-construction, so flipping them on
/// after a smoke is low-risk).  A/B-toggle this literal to re-measure (cf.
/// tools/run-qemu.sh TELIX_ICOUNT for clean deterministic measurement).
pub static SYNTHETIC_STEAL_CLAMP: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(cfg!(target_arch = "aarch64"));

/// Tick lateness beyond this is treated as a stall (filters normal scheduling
/// jitter, which under TCG can be a few ms).
const SS_LATENESS_THRESHOLD_NS: u64 = 50_000_000; // 50 ms

/// Observability: total clamp fires + total synthetic-steal ns credited
/// (across all CPUs).  Read via `synthetic_steal_stats()` for diag dumps /
/// A/B validation.
static SYNTHETIC_STEAL_FIRES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static SYNTHETIC_STEAL_TOTAL_NS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// (fires, total_ns) credited by the synthetic-steal clamp since boot.
/// Exposed for diag dumps / the efficacy A/B; not yet wired into a periodic
/// emit (the rate-limited SYNTH-STEAL log covers per-fire visibility).
#[allow(dead_code)]
#[inline]
pub fn synthetic_steal_stats() -> (u64, u64) {
    (
        SYNTHETIC_STEAL_FIRES.load(core::sync::atomic::Ordering::Relaxed),
        SYNTHETIC_STEAL_TOTAL_NS.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Called from the scheduler tick with the firing CPU and the current
/// monotonic time.  When the clamp is enabled, credits this CPU's synthetic
/// steal with how late the tick fired relative to its programmed deadline.
/// Cheap no-op (one relaxed load) when the gate is off.
#[inline]
pub fn note_tick_fired(cpu: usize, now_ns: u64) {
    if !SYNTHETIC_STEAL_CLAMP.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    if cpu >= PER_CPU_NEXT_DEADLINE_NS.len() {
        return;
    }
    let deadline =
        PER_CPU_NEXT_DEADLINE_NS[cpu].load(core::sync::atomic::Ordering::Relaxed);
    if deadline != 0 && now_ns > deadline {
        let lateness = now_ns - deadline;
        if lateness > SS_LATENESS_THRESHOLD_NS {
            PER_CPU_SYNTHETIC_STEAL_NS[cpu]
                .fetch_add(lateness, core::sync::atomic::Ordering::Relaxed);
            let n = SYNTHETIC_STEAL_FIRES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            SYNTHETIC_STEAL_TOTAL_NS
                .fetch_add(lateness, core::sync::atomic::Ordering::Relaxed);
            // Rate-limited visibility (first 12 fires) so an A/B boot shows the
            // clamp engaging on real stalls.
            if n < 12 {
                crate::println!(
                    "SYNTH-STEAL: cpu={} lateness_ms={} fire={} (tick fired past deadline — clamping vcpu_runtime)",
                    cpu, lateness / 1_000_000, n + 1,
                );
            }
        }
    }
}

/// Program the per-CPU timer to fire once at `deadline_ns` (nanoseconds since boot).
/// If the deadline is in the past, the timer fires as soon as possible.
/// Called by the scheduler after each tick to arm the next event.
#[inline]
pub fn program_oneshot_ns(deadline_ns: u64) {
    // #nonx86 timer robustness (b): record the deadline so `note_tick_fired`
    // can measure tick lateness against it.  Gated — zero cost when off.
    if SYNTHETIC_STEAL_CLAMP.load(core::sync::atomic::Ordering::Relaxed) {
        let cpu = crate::sched::smp::cpu_id() as usize;
        if cpu < PER_CPU_NEXT_DEADLINE_NS.len() {
            PER_CPU_NEXT_DEADLINE_NS[cpu]
                .store(deadline_ns, core::sync::atomic::Ordering::Relaxed);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::timer::program_oneshot(deadline_ns);
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::arch::riscv64::trap::program_oneshot(deadline_ns);
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::lapic::program_oneshot(deadline_ns);
    }
    #[cfg(target_arch = "loongarch64")]
    {
        crate::arch::loongarch64::trap::program_oneshot(deadline_ns);
    }
    #[cfg(target_arch = "mips64")]
    {
        crate::arch::mips64::trap::program_oneshot(deadline_ns);
    }
}
