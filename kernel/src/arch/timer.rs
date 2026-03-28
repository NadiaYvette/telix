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
        1_000_000_000
    } // approximate RDTSC freq on QEMU
}

/// Get monotonic time in nanoseconds since boot.
#[inline]
pub fn monotonic_ns() -> u64 {
    let c = read_cycles() as u128;
    let f = timer_freq() as u128;
    ((c * 1_000_000_000u128) / f) as u64
}
