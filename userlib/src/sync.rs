//! Userspace synchronization primitives built on futex syscalls.

use crate::syscall;
use core::sync::atomic::{AtomicU32, Ordering};

/// A mutual exclusion lock using futex for kernel-assisted blocking.
///
/// Three states: 0=unlocked, 1=locked (no waiters), 2=locked (with waiters).
/// The uncontended fast path (lock/unlock with no contention) is pure userspace
/// atomic operations — no syscalls.
pub struct Mutex {
    state: AtomicU32,
}

impl Mutex {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
        }
    }

    pub fn lock(&self) {
        // Fast path: uncontended CAS 0 -> 1
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        self.lock_contended();
    }

    #[cold]
    fn lock_contended(&self) {
        loop {
            // Try to acquire: swap to 2 (locked+waiters).
            // If old value was 0, we got the lock.
            let old = self.state.swap(2, Ordering::Acquire);
            if old == 0 {
                return;
            }
            // Lock is held. Sleep until state changes from 2.
            syscall::futex_wait(self.state_ptr(), 2);
        }
    }

    pub fn unlock(&self) {
        // Fast path: CAS 1 -> 0 (no waiters)
        if self
            .state
            .compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        // Slow path: there are waiters (state == 2)
        self.state.store(0, Ordering::Release);
        syscall::futex_wake(self.state_ptr(), 1);
    }

    fn state_ptr(&self) -> *const u32 {
        &self.state as *const AtomicU32 as *const u32
    }
}

unsafe impl Sync for Mutex {}
unsafe impl Send for Mutex {}

// ---------------------------------------------------------------------------
// TicketSpinLock — FIFO-fair spinlock for short critical sections
// ---------------------------------------------------------------------------
//
// Phase B1 of the linux_srv worker-pool plan (project_linux_srv_worker_pool).
// Same shape as the kernel's `TicketSpinLock` so callers porting from kernel
// code find familiar semantics.  Two atomics:
//   - `next_ticket`: incremented by each `lock()` to claim the next position.
//   - `now_serving`: incremented on `unlock()` to release the next holder.
// A caller's ticket == now_serving is the lock-held condition.
//
// Pure spin — no futex fallback.  Use for SHORT critical sections only
// (table-entry lookups, slot updates).  For long sections, fall back to
// the existing futex Mutex.
//
// No backoff: x86's `pause` hint (spin_loop) is sufficient at the
// contention levels we expect for linux_srv worker-pool table accesses
// (≤ N=2-4 workers).  Future upgrade: PV-aware backoff modeled on
// kernel/src/sync/spinlock.rs `lock_pv_aware`.

use core::sync::atomic::AtomicU16;

pub struct TicketSpinLock<T> {
    next_ticket: AtomicU16,
    now_serving: AtomicU16,
    value: core::cell::UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for TicketSpinLock<T> {}
unsafe impl<T: Send> Send for TicketSpinLock<T> {}

impl<T> TicketSpinLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            next_ticket: AtomicU16::new(0),
            now_serving: AtomicU16::new(0),
            value: core::cell::UnsafeCell::new(value),
        }
    }

    /// Acquire the lock, blocking until our ticket is served.  Returns
    /// a guard whose Drop releases the lock.
    pub fn lock(&self) -> TicketSpinLockGuard<'_, T> {
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        while self.now_serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        TicketSpinLockGuard { lock: self }
    }
}

pub struct TicketSpinLockGuard<'a, T> {
    lock: &'a TicketSpinLock<T>,
}

impl<'a, T> core::ops::Deref for TicketSpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T> core::ops::DerefMut for TicketSpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T> Drop for TicketSpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.now_serving.fetch_add(1, Ordering::Release);
    }
}
