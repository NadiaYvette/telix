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
