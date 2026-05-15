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
    monotonic_ns()
}

/// Program the per-CPU timer to fire once at `deadline_ns` (nanoseconds since boot).
/// If the deadline is in the past, the timer fires as soon as possible.
/// Called by the scheduler after each tick to arm the next event.
#[inline]
pub fn program_oneshot_ns(deadline_ns: u64) {
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
