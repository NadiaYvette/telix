//! Kernel futex — delegates to the HAMT-based turnstile subsystem.

/// Block the current thread if the u32 at user VA `addr` equals `expected`.
/// Returns 0 on wake, 1 on value mismatch, u64::MAX on error.
pub fn futex_wait(addr: usize, expected: u32) -> u64 {
    super::turnstile::futex_wait(addr, expected)
}

/// Wake up to `count` threads waiting on the futex at `addr`.
/// Returns number of threads actually woken.
pub fn futex_wake(addr: usize, count: u32) -> u64 {
    super::turnstile::futex_wake(addr, count)
}
