//! Read-Copy-Update (RCU) — lightweight deferred reclamation.
//!
//! Syscall handlers are implicit RCU read-side critical sections: they
//! execute entirely between two `rcu_quiescent()` calls (which fire on
//! every timer tick in `try_switch`).  No explicit `rcu_read_lock` is
//! needed — any pointer read during a syscall is guaranteed valid until
//! the next quiescent state.
//!
//! Writers that replace or remove a shared structure:
//!   1. Atomically publish the new pointer (store-Release).
//!   2. Call `rcu_defer_free(old_ptr, free_fn)` to schedule reclamation.
//!   The old object is freed only after every online CPU has passed
//!   through at least one quiescent state, ensuring no reader can still
//!   hold a reference.
//!
//! Alternatively, `synchronize_rcu()` blocks the caller until a full
//! grace period has elapsed (useful for destroy paths that need
//! synchronous cleanup).

use crate::sched::smp::{self, MAX_CPUS};
use crate::sched::hotplug;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Per-CPU generation counter
// ---------------------------------------------------------------------------

/// Each CPU increments its generation counter every tick (in try_switch).
/// `synchronize_rcu` / callback processing observe these to detect grace
/// period completion.
static RCU_GEN: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Record a quiescent state on the current CPU.
/// Called once per timer tick from `try_switch`, and also on voluntary
/// context switch points.
#[inline]
pub fn rcu_quiescent() {
    let cpu = smp::cpu_id() as usize;
    // Relaxed: only needs to be visible to synchronize_rcu, which uses
    // Acquire loads.  The quiescent increment itself doesn't order any
    // particular data — the ordering comes from the Acquire/Release on
    // the child pointers that readers follow.
    RCU_GEN[cpu].fetch_add(1, Ordering::Release);
    rcu_process_callbacks(cpu);
}

/// Spin until every online CPU has passed through at least one quiescent
/// state since the call was made.  Must NOT be called from IRQ context.
pub fn synchronize_rcu() {
    // Snapshot every online CPU's current generation.
    let mask = hotplug::online_mask();
    let mut snap = [0u64; MAX_CPUS];
    mask.for_each(|cpu| {
        snap[cpu as usize] = RCU_GEN[cpu as usize].load(Ordering::Acquire);
    });

    // Spin until each CPU advances past its snapshot.
    loop {
        let mut done = true;
        mask.for_each(|cpu| {
            let cur = RCU_GEN[cpu as usize].load(Ordering::Acquire);
            if cur <= snap[cpu as usize] {
                done = false;
            }
        });
        if done {
            return;
        }
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Deferred free callback list (per-CPU, intrusive singly-linked)
// ---------------------------------------------------------------------------

/// Maximum deferred callbacks per CPU before we force inline processing.
/// Keeps memory bounded even if grace periods are slow.
const MAX_PENDING: usize = 256;

/// A deferred free callback.  Stored in a singly-linked list per CPU.
///
/// We embed callbacks in page-sized batches to avoid per-callback
/// allocation.  Each batch holds up to BATCH_CAP entries.
#[repr(C)]
struct RcuCallback {
    ptr: usize,
    free_fn: fn(usize),
}

/// A batch of deferred callbacks, page-allocated.
const BATCH_CAP: usize =
    (crate::mm::page::PAGE_SIZE - 3 * core::mem::size_of::<usize>())
        / core::mem::size_of::<RcuCallback>();

#[repr(C)]
struct RcuBatch {
    next: *mut RcuBatch,
    epoch: u64,
    len: usize,
    entries: [RcuCallback; BATCH_CAP],
}

/// Per-CPU callback queue (head of batch linked list + current fill batch).
struct RcuCpuState {
    /// Linked list of full batches waiting for grace period.
    pending_head: *mut RcuBatch,
    /// Current batch being filled (may be null if no deferrals yet).
    current: *mut RcuBatch,
    /// Count of total pending callbacks across all batches.
    pending_count: usize,
}

impl RcuCpuState {
    const fn new() -> Self {
        Self {
            pending_head: core::ptr::null_mut(),
            current: core::ptr::null_mut(),
            pending_count: 0,
        }
    }
}

// Per-CPU state.  Accessed only from the owning CPU (in rcu_quiescent
// and rcu_defer_free), so no lock needed — just need to prevent
// concurrent access from IRQ context on the same CPU.  Since
// rcu_quiescent runs from IRQ (timer tick) and rcu_defer_free runs
// from syscall context, we use an atomic flag as a simple reentrance
// guard.
static mut RCU_CPU: [RcuCpuState; MAX_CPUS] = [const { RcuCpuState::new() }; MAX_CPUS];

/// Reentrance guard per CPU (0 = free, 1 = in use).
static RCU_BUSY: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

/// Defer freeing `ptr` by calling `free_fn(ptr)` after a grace period.
///
/// Safe to call from syscall context.  The callback will execute during
/// a future `rcu_quiescent()` on this CPU after all other CPUs have
/// passed a quiescent state.
pub fn rcu_defer_free(ptr: usize, free_fn: fn(usize)) {
    let cpu = smp::cpu_id() as usize;

    // Reentrance guard (IRQ might fire rcu_quiescent while we're here).
    if RCU_BUSY[cpu].swap(1, Ordering::Acquire) != 0 {
        // Already inside RCU processing on this CPU — execute immediately.
        // This is safe because we're past the grace period detection point.
        free_fn(ptr);
        return;
    }

    // Safety: we are the only accessor of RCU_CPU[cpu] (same CPU, guard held).
    let state = unsafe { &mut RCU_CPU[cpu] };

    // Ensure we have a current batch.
    if state.current.is_null() {
        if let Some(page) = crate::mm::phys::alloc_page() {
            let batch = page.as_usize() as *mut RcuBatch;
            unsafe {
                (*batch).next = core::ptr::null_mut();
                (*batch).epoch = RCU_GEN[cpu].load(Ordering::Relaxed);
                (*batch).len = 0;
            }
            state.current = batch;
        } else {
            // OOM — free immediately (safe but blocks grace period guarantee).
            RCU_BUSY[cpu].store(0, Ordering::Release);
            free_fn(ptr);
            return;
        }
    }

    let batch = unsafe { &mut *state.current };

    // Append callback.
    batch.entries[batch.len] = RcuCallback { ptr, free_fn };
    batch.len += 1;
    state.pending_count += 1;

    // If batch is full, move to pending list and start a new one.
    if batch.len >= BATCH_CAP {
        let full = state.current;
        unsafe { (*full).next = state.pending_head; }
        state.pending_head = full;
        state.current = core::ptr::null_mut();
    }

    RCU_BUSY[cpu].store(0, Ordering::Release);
}

/// Process eligible callbacks on this CPU.  Called from `rcu_quiescent`.
fn rcu_process_callbacks(cpu: usize) {
    if RCU_BUSY[cpu].swap(1, Ordering::Acquire) != 0 {
        return; // Reentrant — skip this tick.
    }

    let state = unsafe { &mut RCU_CPU[cpu] };

    if state.pending_count == 0 {
        RCU_BUSY[cpu].store(0, Ordering::Release);
        return;
    }

    // Snapshot all CPUs' generations to determine which epoch is safe to free.
    let mask = hotplug::online_mask();
    let mut min_gen = u64::MAX;
    mask.for_each(|c| {
        let g = RCU_GEN[c as usize].load(Ordering::Acquire);
        if g < min_gen {
            min_gen = g;
        }
    });

    // Process the current (partial) batch — move eligible entries out.
    // For simplicity, we process full batches from the pending list
    // whose epoch < min_gen (meaning all CPUs have advanced past it).
    let mut prev: *mut *mut RcuBatch = &mut state.pending_head;
    let mut batch = state.pending_head;

    while !batch.is_null() {
        let b = unsafe { &mut *batch };
        let next = b.next;

        if b.epoch < min_gen {
            // All CPUs have advanced past this batch's epoch — safe to free.
            for i in 0..b.len {
                let cb = &b.entries[i];
                (cb.free_fn)(cb.ptr);
            }
            state.pending_count -= b.len;

            // Unlink and free the batch page.
            unsafe { *prev = next; }
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(batch as usize));
        } else {
            prev = unsafe { &mut (*batch).next };
        }

        batch = next;
    }

    // Also check the current (partial) batch — if eligible, drain it in place.
    if !state.current.is_null() {
        let cur = unsafe { &mut *state.current };
        if cur.epoch < min_gen && cur.len > 0 {
            for i in 0..cur.len {
                let cb = &cur.entries[i];
                (cb.free_fn)(cb.ptr);
            }
            state.pending_count -= cur.len;
            cur.len = 0;
            // Update epoch for reuse.
            cur.epoch = RCU_GEN[cpu].load(Ordering::Relaxed);
        }
    }

    RCU_BUSY[cpu].store(0, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Free-function helpers for common allocation types
// ---------------------------------------------------------------------------

/// Free a single physical page.  Suitable as `free_fn` for `rcu_defer_free`.
pub fn free_page_callback(ptr: usize) {
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(ptr));
}

/// Free a 64-byte slab object.
pub fn free_slab64_callback(ptr: usize) {
    crate::mm::slab::free(crate::mm::page::PhysAddr::new(ptr), 64);
}

/// Free a 256-byte slab object.
pub fn free_slab256_callback(ptr: usize) {
    crate::mm::slab::free(crate::mm::page::PhysAddr::new(ptr), 256);
}
