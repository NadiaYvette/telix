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
        1_000_000_000
    } // approximate RDTSC freq on QEMU
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
#[inline]
pub fn monotonic_ns() -> u64 {
    let c = read_cycles() as u128;
    let f = timer_freq() as u128;
    ((c * 1_000_000_000u128) / f) as u64
}
