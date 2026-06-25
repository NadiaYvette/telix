//! #260 — RCU premature-reclaim UAF that corrupts SCHED_THREAD_ART nodes — loom model.
//!
//! Root cause (verified in kernel/src/sync/rcu.rs, 2026-06-25): `rcu_defer_free`
//! stamps a batch's `epoch` ONCE, at batch *allocation* (rcu.rs:221), and never
//! re-stamps it as later callbacks are appended or when the batch is sealed
//! (rcu.rs:244-258). `rcu_process_callbacks` frees the whole batch when
//! `b.epoch < min_gen` (rcu.rs:299). So a node deferred LATE into the batch —
//! unlinked at a higher generation than the batch's first entry — inherits the
//! stale alloc-time epoch and is freed before a full grace period has elapsed
//! since ITS unlink, while a lock-free ART reader (for_each / lookup) may still
//! be walking it. Its 64B/256B slab slot is then re-handed to a new owner →
//! use-after-free (the #260 SCHED_THREAD_ART corruption). NOTE (2026-06-25
//! verdict): a real but NARROW IPC-metadata UAF — NOT the root of the #208
//! Thread/kstack family (Thread/kstack/THREAD_TABLE aren't slab-allocated nor
//! RCU-freed); see memory project_260_rcu_premature_reclaim.
//!
//! The model captures the essential grace-period race:
//!   - A node O is unlinked at generation 2 (the writer's gen at defer time).
//!   - A reader on another CPU loaded O *before* the unlink and is mid-walk; that
//!     CPU's gen is still 1 (it has not quiesced since the unlink).
//!   - The reclaimer frees O when `epoch < min_gen` (min_gen modeled as the
//!     reader CPU's gen, the lagging one).
//!
//!   INVARIANT: O's slab slot is never recycled while the reader is still
//!   walking O (no use-after-free).
//!
//! `epoch_at_alloc_uaf` (#[should_panic]) — epoch = the batch-alloc gen (0, the
//! current kernel): the gate `0 < reader_gen` is already true, so the reclaimer
//! frees O mid-walk → the slot is recycled under the reader → UAF.
//! `epoch_at_unlink_is_safe` — epoch = O's unlink gen (2, the fix: re-stamp on
//! append): the gate `2 < reader_gen` holds only after the reader has quiesced
//! past the unlink (gen ≥ 3), i.e. after its walk completed → no recycle-under-
//! reader. This is the fix: re-stamp the batch epoch on every append (rcu.rs ~245)
//! so reclamation waits a full grace period after the LATEST unlink in the batch.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use loom::sync::Arc;
use loom::thread;

/// `epoch` variants: the gen the batch records for `O`'s reclamation.
const EPOCH_AT_ALLOC: u64 = 0; // current kernel: batch-allocation gen (stale)
const EPOCH_AT_UNLINK: u64 = 2; // the fix: O's actual unlink gen

fn run(epoch_value: u64) {
    // Reader CPU's quiescent generation.  Starts at 1: the reader passed a
    // quiescent state at gen 1 and is now inside a lock-free ART walk holding a
    // reference to O.  O is unlinked at gen 2 (> 1), so the reader has NOT yet
    // quiesced since the unlink — O must not be freed until reader_gen > 2.
    let reader_gen = Arc::new(AtomicU64::new(1));
    // The batch epoch the reclaimer compares against min_gen.
    let epoch = Arc::new(AtomicU64::new(epoch_value));
    // O's slab-slot recycle counter: incremented when O is freed and the slot is
    // re-handed to a new owner.  If it changes mid-walk, the reader is using a
    // recycled (foreign) object = UAF.
    let slot_gen = Arc::new(AtomicU32::new(0));
    let uaf = Arc::new(AtomicBool::new(false));

    // Reclaimer (rcu_process_callbacks): free O when epoch < min_gen.  min_gen is
    // modeled as the lagging reader CPU's gen.  A single attempt — loom explores
    // where it lands relative to the reader's walk.
    let (ep_r, rg_r, sg_r) = (epoch.clone(), reader_gen.clone(), slot_gen.clone());
    let reclaimer = thread::spawn(move || {
        if ep_r.load(Ordering::Acquire) < rg_r.load(Ordering::Acquire) {
            // Grace says "safe" → free O; the slab immediately re-hands the slot.
            sg_r.fetch_add(1, Ordering::AcqRel);
        }
    });

    // Reader (lock-free Art::for_each / lookup): walk O across two field reads,
    // then end the read-side with quiescent states (gen 1 → 2 → 3).
    let (rg_p, sg_p, uaf_p) = (reader_gen.clone(), slot_gen.clone(), uaf.clone());
    let reader = thread::spawn(move || {
        let g0 = sg_p.load(Ordering::Acquire); // O's slot identity at walk start
        let g1 = sg_p.load(Ordering::Acquire); // ... still dereferencing O
        if g0 != g1 {
            // O's slot was recycled between two reads of the same node = UAF.
            uaf_p.store(true, Ordering::Release);
        }
        // End the read-side: quiescent states advance this CPU's gen past the
        // unlink (these happen AFTER the walk, never during it).
        rg_p.fetch_add(1, Ordering::AcqRel); // 1 -> 2
        rg_p.fetch_add(1, Ordering::AcqRel); // 2 -> 3
    });

    reclaimer.join().unwrap();
    reader.join().unwrap();

    assert!(
        !uaf.load(Ordering::Acquire),
        "use-after-free: O's slab slot recycled while the ART reader was walking it",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Current kernel: epoch stamped at batch alloc (gen 0) is stale for a node
    /// unlinked later → the reclaim fires mid-walk → UAF.
    #[test]
    #[should_panic(expected = "use-after-free")]
    fn epoch_at_alloc_uaf() {
        loom::model(|| run(EPOCH_AT_ALLOC));
    }

    /// Fix: re-stamp the batch epoch to the unlink gen on every append → the
    /// `epoch < min_gen` gate waits a full grace period after the latest unlink →
    /// no recycle-under-reader.
    #[test]
    fn epoch_at_unlink_is_safe() {
        loom::model(|| run(EPOCH_AT_UNLINK));
    }
}
