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
        if self.lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
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

        SpinLockGuard {
            lock: self,
            saved,
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

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub(crate) fn arch_disable_irqs() -> usize {
    let daif: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, daif",
            "msr daifset, #2",
            out(reg) daif,
        );
    }
    daif as usize
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub(crate) fn arch_restore_irqs(saved: usize) {
    unsafe {
        core::arch::asm!(
            "msr daif, {0}",
            "isb",
            in(reg) saved as u64,
        );
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub(crate) fn arch_disable_irqs() -> usize {
    let sstatus: usize;
    unsafe {
        core::arch::asm!(
            "csrrci {0}, sstatus, 0x2",  // Clear SIE bit, return old value
            out(reg) sstatus,
        );
    }
    sstatus
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub(crate) fn arch_restore_irqs(saved: usize) {
    // Restore only the SIE bit from saved sstatus.
    if saved & 0x2 != 0 {
        unsafe {
            core::arch::asm!("csrsi sstatus, 0x2"); // Set SIE
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn arch_disable_irqs() -> usize {
    let flags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {0}",
            "cli",
            out(reg) flags,
        );
    }
    flags as usize
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn arch_restore_irqs(saved: usize) {
    if saved & 0x200 != 0 {
        // IF was set — re-enable interrupts.
        unsafe { core::arch::asm!("sti"); }
    }
}
