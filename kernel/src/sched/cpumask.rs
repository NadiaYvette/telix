//! CpuMask — scalable CPU bitmask for affinity and online tracking.
//!
//! Backed by `[u64; CPUMASK_WORDS]` where CPUMASK_WORDS = (MAX_CPUS + 63) / 64.
//! At default MAX_CPUS=64, this is a single u64 — zero overhead vs bare u64.
//! At MAX_CPUS=4096, it's 512 bytes (64 words).
//!
//! `AtomicCpuMask` provides per-word atomic operations for lockless hot paths.
//! The critical operation `test(cpu)` is always a single-word Relaxed load.

use super::smp::MAX_CPUS;
use core::sync::atomic::{AtomicU64, Ordering};

/// Number of u64 words needed to represent MAX_CPUS bits.
pub const CPUMASK_WORDS: usize = (MAX_CPUS + 63) / 64;

/// Bitmask of valid bits in the last word (masks off excess bits beyond MAX_CPUS).
const LAST_WORD_MASK: u64 = if MAX_CPUS % 64 == 0 {
    u64::MAX
} else {
    (1u64 << (MAX_CPUS % 64)) - 1
};

// ---------------------------------------------------------------------------
// CpuMask — value type
// ---------------------------------------------------------------------------

/// CPU bitmask (value type). Bit N = CPU N is in the set.
#[derive(Clone, Copy)]
pub struct CpuMask {
    bits: [u64; CPUMASK_WORDS],
}

impl CpuMask {
    /// Empty mask (no CPUs).
    #[inline]
    pub const fn new() -> Self {
        Self { bits: [0; CPUMASK_WORDS] }
    }

    /// All valid CPUs set (0..MAX_CPUS).
    #[inline]
    pub const fn all() -> Self {
        let mut bits = [u64::MAX; CPUMASK_WORDS];
        // Mask off excess bits in the last word.
        bits[CPUMASK_WORDS - 1] = LAST_WORD_MASK;
        Self { bits }
    }

    /// Single CPU set.
    #[inline]
    pub const fn from_cpu(cpu: u32) -> Self {
        let mut m = Self::new();
        if (cpu as usize) < MAX_CPUS {
            m.bits[cpu as usize / 64] = 1u64 << (cpu as usize % 64);
        }
        m
    }

    /// From a u64 bitmask (backward compat — sets word 0 only).
    #[inline]
    pub const fn from_u64(v: u64) -> Self {
        let mut m = Self::new();
        if CPUMASK_WORDS == 1 {
            m.bits[0] = v & LAST_WORD_MASK;
        } else {
            m.bits[0] = v;
        }
        m
    }

    /// Test if a CPU is in the set.
    #[inline]
    pub const fn test(&self, cpu: u32) -> bool {
        if (cpu as usize) >= MAX_CPUS { return false; }
        self.bits[cpu as usize / 64] & (1u64 << (cpu as usize % 64)) != 0
    }

    /// Set a CPU in the mask.
    #[inline]
    pub fn set(&mut self, cpu: u32) {
        if (cpu as usize) < MAX_CPUS {
            self.bits[cpu as usize / 64] |= 1u64 << (cpu as usize % 64);
        }
    }

    /// Clear a CPU from the mask.
    #[inline]
    pub fn clear(&mut self, cpu: u32) {
        if (cpu as usize) < MAX_CPUS {
            self.bits[cpu as usize / 64] &= !(1u64 << (cpu as usize % 64));
        }
    }

    /// Bitwise AND.
    #[inline]
    pub const fn and(&self, other: &Self) -> Self {
        let mut r = Self::new();
        let mut i = 0;
        while i < CPUMASK_WORDS {
            r.bits[i] = self.bits[i] & other.bits[i];
            i += 1;
        }
        r
    }

    /// Bitwise OR.
    #[inline]
    pub const fn or(&self, other: &Self) -> Self {
        let mut r = Self::new();
        let mut i = 0;
        while i < CPUMASK_WORDS {
            r.bits[i] = self.bits[i] | other.bits[i];
            i += 1;
        }
        r
    }

    /// Bitwise AND-NOT: `self & !other`.
    #[inline]
    pub const fn andnot(&self, other: &Self) -> Self {
        let mut r = Self::new();
        let mut i = 0;
        while i < CPUMASK_WORDS {
            r.bits[i] = self.bits[i] & !other.bits[i];
            i += 1;
        }
        r
    }

    /// True if no CPUs are set.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        let mut i = 0;
        while i < CPUMASK_WORDS {
            if self.bits[i] != 0 { return false; }
            i += 1;
        }
        true
    }

    /// Count of set CPUs.
    #[inline]
    pub const fn count(&self) -> u32 {
        let mut n: u32 = 0;
        let mut i = 0;
        while i < CPUMASK_WORDS {
            n += self.bits[i].count_ones();
            i += 1;
        }
        n
    }

    /// First set CPU, or None.
    #[inline]
    pub const fn first_set(&self) -> Option<u32> {
        let mut i = 0;
        while i < CPUMASK_WORDS {
            if self.bits[i] != 0 {
                let bit = self.bits[i].trailing_zeros();
                return Some(i as u32 * 64 + bit);
            }
            i += 1;
        }
        None
    }

    /// Iterate over set CPUs.
    #[inline]
    pub fn for_each<F: FnMut(u32)>(&self, mut f: F) {
        for i in 0..CPUMASK_WORDS {
            let mut w = self.bits[i];
            while w != 0 {
                let bit = w.trailing_zeros();
                f(i as u32 * 64 + bit);
                w &= w - 1; // clear lowest set bit
            }
        }
    }

    /// Return word 0 as u64 (backward compat for syscall ABI).
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.bits[0]
    }
}

// ---------------------------------------------------------------------------
// AtomicCpuMask — per-word atomic operations
// ---------------------------------------------------------------------------

/// Atomic CPU bitmask for lockless hot-path access.
///
/// Key invariant: `test(cpu)` is a single-word Relaxed atomic load,
/// regardless of CPUMASK_WORDS. Same codegen as bare `AtomicU64` for
/// the scheduler's affinity check hot path.
pub struct AtomicCpuMask {
    bits: [AtomicU64; CPUMASK_WORDS],
}

// Safety: AtomicU64 is Send+Sync; the array inherits this.
unsafe impl Send for AtomicCpuMask {}
unsafe impl Sync for AtomicCpuMask {}

impl AtomicCpuMask {
    /// All zeros (no CPUs).
    pub const fn new() -> Self {
        Self { bits: [const { AtomicU64::new(0) }; CPUMASK_WORDS] }
    }

    /// All valid CPUs set (0..MAX_CPUS). Excess bits in last word are clear.
    pub const fn new_all() -> Self {
        let mask = CpuMask::all();
        let mut bits = [const { AtomicU64::new(0) }; CPUMASK_WORDS];
        let mut i = 0;
        while i < CPUMASK_WORDS {
            bits[i] = AtomicU64::new(mask.bits[i]);
            i += 1;
        }
        Self { bits }
    }

    /// Test if a CPU is set. **Single-word Relaxed load — hot path safe.**
    #[inline]
    pub fn test(&self, cpu: u32) -> bool {
        if (cpu as usize) >= MAX_CPUS { return false; }
        self.bits[cpu as usize / 64].load(Ordering::Relaxed)
            & (1u64 << (cpu as usize % 64)) != 0
    }

    /// Atomically set a CPU bit (fetch_or on one word).
    #[inline]
    pub fn set(&self, cpu: u32) {
        self.set_with(cpu, Ordering::Relaxed);
    }

    /// Atomically set a CPU bit with specified ordering.
    #[inline]
    pub fn set_with(&self, cpu: u32, order: Ordering) {
        if (cpu as usize) < MAX_CPUS {
            self.bits[cpu as usize / 64].fetch_or(1u64 << (cpu as usize % 64), order);
        }
    }

    /// Atomically clear a CPU bit (fetch_and on one word).
    #[inline]
    pub fn clear(&self, cpu: u32) {
        self.clear_with(cpu, Ordering::Relaxed);
    }

    /// Atomically clear a CPU bit with specified ordering.
    #[inline]
    pub fn clear_with(&self, cpu: u32, order: Ordering) {
        if (cpu as usize) < MAX_CPUS {
            self.bits[cpu as usize / 64].fetch_and(!(1u64 << (cpu as usize % 64)), order);
        }
    }

    /// Store a full CpuMask (word-by-word, NOT cross-word atomic).
    #[inline]
    pub fn store_mask(&self, mask: &CpuMask, order: Ordering) {
        for i in 0..CPUMASK_WORDS {
            self.bits[i].store(mask.bits[i], order);
        }
    }

    /// Load a full CpuMask (word-by-word, NOT cross-word atomic).
    #[inline]
    pub fn load_mask(&self, order: Ordering) -> CpuMask {
        let mut m = CpuMask::new();
        for i in 0..CPUMASK_WORDS {
            m.bits[i] = self.bits[i].load(order);
        }
        m
    }

    /// Atomically OR a mask into this one (word-by-word fetch_or).
    #[inline]
    pub fn fetch_or_mask(&self, mask: &CpuMask, order: Ordering) {
        for i in 0..CPUMASK_WORDS {
            if mask.bits[i] != 0 {
                self.bits[i].fetch_or(mask.bits[i], order);
            }
        }
    }

    /// Atomically AND a mask into this one (word-by-word fetch_and).
    #[inline]
    pub fn fetch_and_mask(&self, mask: &CpuMask, order: Ordering) {
        for i in 0..CPUMASK_WORDS {
            self.bits[i].fetch_and(mask.bits[i], order);
        }
    }
}
