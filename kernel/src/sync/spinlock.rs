//! Interrupt-safe spinlock.
//!
//! Disables IRQs on acquire (saves interrupt state), re-enables on release.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

/// An interrupt-disabling spinlock protecting data of type `T`.
pub struct SpinLock<T> {
    lock: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            lock: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Try to acquire the lock without spinning. Returns None if already held.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let saved = arch_disable_irqs();
        if self
            .lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self, saved })
        } else {
            arch_restore_irqs(saved);
            None
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let saved = arch_disable_irqs();

        while self
            .lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }

        SpinLockGuard { lock: self, saved }
    }

    /// Paravirt-aware lock acquire.  Identical to `lock()` except that
    /// after `SPIN_BUDGET` consecutive failed CAS attempts we briefly
    /// restore the caller's IRQ state to let timer interrupts and
    /// IPIs flow before resuming the spin.
    ///
    /// Use when the lock can be held across host-vCPU descheduling
    /// windows (e.g. globally-shared services like namesrv): under
    /// host pause, the holder is frozen and the spinner would
    /// otherwise sit in CLI for the entire pause duration (up to
    /// hundreds of ms), preventing other CPUs' IPIs/timer ticks
    /// from being serviced.
    ///
    /// Safety contract: only callable from contexts where IRQ
    /// handlers do NOT take this lock (otherwise the brief IRQ
    /// re-enable could re-enter and deadlock).  Callers must audit
    /// their lock's IRQ-handler footprint.
    pub fn lock_pv_aware(&self) -> SpinLockGuard<'_, T> {
        let saved = arch_disable_irqs();
        const SPIN_BUDGET: u32 = 1024;
        let mut spin_count: u32 = 0;
        loop {
            if self
                .lock
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return SpinLockGuard { lock: self, saved };
            }
            core::hint::spin_loop();
            spin_count = spin_count.wrapping_add(1);
            if spin_count == SPIN_BUDGET {
                spin_count = 0;
                // Re-enable IRQs briefly so timer ticks and IPIs can
                // fire on this CPU even while the lock holder is
                // host-paused.  No critical section here yet — we
                // haven't acquired the lock — so an IRQ on this CPU
                // is safe regardless of what the handler does.
                arch_restore_irqs(saved);
                core::hint::spin_loop();
                // Re-disable; saved continues to capture the ORIGINAL
                // caller's IRQ state for final Drop restoration.
                let _ = arch_disable_irqs();
            }
        }
    }
}

/// RAII guard — releases the lock and restores interrupt state on drop.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    saved: usize,
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
        arch_restore_irqs(self.saved);
    }
}

// --- Architecture-specific interrupt save/restore ---

#[inline(always)]
pub(crate) fn arch_disable_irqs() -> usize {
    crate::arch::irq::disable()
}

#[inline(always)]
pub(crate) fn arch_restore_irqs(saved: usize) {
    crate::arch::irq::restore(saved);
}
