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
/// On x86_64 under KVM, this returns a vCPU-runtime monotonic clock:
/// pvclock (CLOCKSOURCE2) for TSC-frequency-corrected time, then
/// subtract STEAL_TIME (nanoseconds the vCPU has been host-
/// descheduled) to exclude host-pause durations from the reading.
/// Boot 91amfsq47/48 showed pvclock alone does NOT exclude host
/// pauses — KVM's master-clock advertises wallclock-like monotonic
/// time across host descheduling.  STEAL_TIME is the documented
/// mechanism for the guest to subtract that.
///
/// Falls back to raw TSC arithmetic on bare metal or other arches.
#[inline]
pub fn monotonic_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(ns) = crate::arch::x86_64::hypervisor::pvclock_now_ns() {
            // Subtract steal-time so the result advances only while
            // the vCPU was running.  steal_time_ns() returns None on
            // bare-metal / non-KVM; treat as zero subtraction.
            let steal = crate::arch::hypervisor::ops()
                .steal_time_ns()
                .unwrap_or(0);
            return ns.saturating_sub(steal);
        }
    }
    let c = read_cycles() as u128;
    let f = timer_freq() as u128;
    ((c * 1_000_000_000u128) / f) as u64
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
