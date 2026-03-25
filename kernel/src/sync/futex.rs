//! Kernel futex table — supports futex_wait / futex_wake syscalls.

use super::SpinLock;
use crate::sched::thread::{ThreadId, BlockReason};

/// Fixed pool size for futex waiters (independent of thread slot count).
const FUTEX_POOL_SIZE: usize = 128;

struct FutexWaiter {
    active: bool,
    aspace_id: u32,
    va: usize,
    tid: ThreadId,
}

impl FutexWaiter {
    const fn empty() -> Self {
        Self { active: false, aspace_id: 0, va: 0, tid: 0 }
    }
}

static FUTEX_TABLE: SpinLock<[FutexWaiter; FUTEX_POOL_SIZE]> =
    SpinLock::new([const { FutexWaiter::empty() }; FUTEX_POOL_SIZE]);

/// Block the current thread if the u32 at user VA `addr` equals `expected`.
/// Returns 0 on wake, 1 on value mismatch, u64::MAX on error.
pub fn futex_wait(addr: usize, expected: u32) -> u64 {
    let tid = crate::sched::current_thread_id();
    let aspace_id = crate::sched::current_aspace_id();
    let pt_root = crate::sched::scheduler::current_page_table_root();

    let mut table = FUTEX_TABLE.lock();

    // Read current value from user memory while holding the lock.
    let mut buf = [0u8; 4];
    if !crate::syscall::handlers::copy_from_user(pt_root, addr, &mut buf) {
        return u64::MAX; // EFAULT
    }
    let current_val = u32::from_ne_bytes(buf);

    // Value changed — caller should retry.
    if current_val != expected {
        return 1; // EAGAIN
    }

    // Clear wakeup flag WHILE HOLDING the lock (prevents lost wakeup).
    crate::sched::clear_wakeup_flag(tid);

    // Find a free slot.
    let slot = table.iter_mut().find(|w| !w.active);
    match slot {
        Some(w) => {
            w.active = true;
            w.aspace_id = aspace_id;
            w.va = addr;
            w.tid = tid;
        }
        None => return u64::MAX, // table full
    }

    drop(table);

    crate::sched::block_current(BlockReason::FutexWait);
    0
}

/// Wake up to `count` threads waiting on the futex at `addr`.
/// Returns number of threads actually woken.
pub fn futex_wake(addr: usize, count: u32) -> u64 {
    let aspace_id = crate::sched::current_aspace_id();
    let mut woken = 0u32;

    let mut table = FUTEX_TABLE.lock();
    for waiter in table.iter_mut() {
        if woken >= count {
            break;
        }
        if waiter.active && waiter.aspace_id == aspace_id && waiter.va == addr {
            waiter.active = false;
            crate::sched::wake_thread(waiter.tid);
            woken += 1;
        }
    }
    drop(table);

    woken as u64
}
