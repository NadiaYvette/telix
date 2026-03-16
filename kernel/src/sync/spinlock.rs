//! Interrupt-safe spinlock.
//!
//! Disables IRQs on acquire (saves DAIF), re-enables on release.
//! Uses ARM64 `ldaxr`/`stlxr` for the lock word.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

/// An interrupt-disabling spinlock protecting data of type `T`.
pub struct SpinLock<T> {
    lock: AtomicU32,
    data: UnsafeCell<T>,
}

// Safety: SpinLock provides mutual exclusion via the atomic lock word,
// and disables interrupts to prevent deadlock on the same core.
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            lock: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the lock, disabling interrupts. Returns a guard that
    /// releases the lock and restores interrupt state on drop.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let saved_daif = disable_irqs();

        // Spin until we acquire the lock.
        while self
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Hint to the processor that we're spinning.
            core::hint::spin_loop();
        }

        SpinLockGuard {
            lock: self,
            saved_daif,
        }
    }
}

/// RAII guard — releases the lock and restores DAIF on drop.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    saved_daif: u64,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.lock.store(0, Ordering::Release);
        restore_irqs(self.saved_daif);
    }
}

/// Disable IRQs (set DAIF.I) and return the previous DAIF value.
#[inline(always)]
fn disable_irqs() -> u64 {
    let daif: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, daif",
            "msr daifset, #2",  // Set I bit (mask IRQs)
            out(reg) daif,
        );
    }
    daif
}

/// Restore DAIF to a previously saved value.
#[inline(always)]
fn restore_irqs(saved: u64) {
    unsafe {
        core::arch::asm!(
            "msr daif, {0}",
            in(reg) saved,
        );
    }
}
