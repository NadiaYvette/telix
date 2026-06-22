//! #198 RELEASE_SLOT_TID clobber — loom model.
//!
//! Models the kernel's per-cpu release slot:
//!   * `transition_release_to_pending(tid)` (scheduler.rs:684) — stash `tid` so
//!     the off-kstack `finalize_release_after_stack_switch` can flip its on_cpu
//!     `RELEASING -> PENDING`.  The kernel does a BLIND `slot.store(tid)`.
//!   * `finalize_release_after_stack_switch()` (705) — `swap(0)` the slot and CAS
//!     the drained tid's on_cpu `RELEASING -> PENDING`.
//!
//! A released thread starts `on_cpu = RELEASING`; it is only dispatchable once
//! finalize flips it to `PENDING` (the pick's claim CAS expects PENDING, and the
//! #208 DD pick-guard correctly REFUSES to dispatch a RELEASING thread because it
//! may still be on its kstack).  So a release that is stashed but never finalized
//! leaves the thread stuck `RELEASING` forever — the #198 orphan.
//!
//!     INVARIANT: every released thread is eventually finalized
//!     (never stranded in RELEASING).
//!
//! `single_slot_clobber_strands_a_release` (#[should_panic]) — the blind single
//! slot loses an update: loom finds the interleaving where a second release
//! overwrites the first before any finalize drains it.
//! `drain_before_overwrite_loses_no_release` — the fix (finalize the prior
//! occupant before overwriting) strands nothing under all interleavings.

#![cfg(loom)]

use loom::sync::atomic::{AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

/// on_cpu lease sentinels (abstracted; real values are u32::MAX-1 / u32::MAX-2).
const RELEASING: u32 = 1;
const PENDING: u32 = 2;

/// Shared scheduler state: the single per-cpu RELEASE_SLOT plus the two released
/// threads' `on_cpu` lease.  `slot`: 0 = empty, else the stashed tid (1 or 2).
struct Sched {
    on_cpu1: AtomicU32,
    on_cpu2: AtomicU32,
    slot: AtomicU32,
}

impl Sched {
    fn new() -> Self {
        // Both threads have been released onto this cpu's slot path: on_cpu set
        // RELEASING by the release path, awaiting finalize.
        Sched {
            on_cpu1: AtomicU32::new(RELEASING),
            on_cpu2: AtomicU32::new(RELEASING),
            slot: AtomicU32::new(0),
        }
    }

    fn on_cpu(&self, tid: u32) -> Option<&AtomicU32> {
        match tid {
            1 => Some(&self.on_cpu1),
            2 => Some(&self.on_cpu2),
            _ => None,
        }
    }

    /// Flip a stashed tid RELEASING -> PENDING (idempotent: a no-op if a
    /// concurrent finalize already flipped it).
    fn flip(&self, tid: u32) {
        if let Some(oc) = self.on_cpu(tid) {
            let _ = oc.compare_exchange(RELEASING, PENDING, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    /// `finalize_release_after_stack_switch`: drain the slot, finalize that tid.
    fn finalize(&self) {
        let t = self.slot.swap(0, Ordering::AcqRel);
        self.flip(t);
    }

    /// BUGGY `transition_release_to_pending`: blind store — clobbers any
    /// un-finalized prior occupant, which is then never flipped to PENDING.
    fn release_blind(&self, tid: u32) {
        self.slot.store(tid, Ordering::Release);
    }

    /// FIXED `transition_release_to_pending`: drain-before-overwrite.  Finalize
    /// any prior occupant before stashing the new tid, so no release is lost.
    /// (Safe: a clobbered predecessor's stack switch preceded this release, so
    /// it is off-kstack — see the DD-safety note in Cargo.toml.)
    fn release_drain_first(&self, tid: u32) {
        let prev = self.slot.swap(tid, Ordering::AcqRel);
        if prev != 0 && prev != tid {
            self.flip(prev);
        }
    }
}

/// Two release+finalize cycles contend for the single slot.  `fixed` selects the
/// drain-before-overwrite release.
fn run(fixed: bool) {
    let s = Arc::new(Sched::new());
    let s1 = s.clone();
    let s2 = s.clone();
    let t1 = thread::spawn(move || {
        if fixed {
            s1.release_drain_first(1);
        } else {
            s1.release_blind(1);
        }
        s1.finalize();
    });
    let t2 = thread::spawn(move || {
        if fixed {
            s2.release_drain_first(2);
        } else {
            s2.release_blind(2);
        }
        s2.finalize();
    });
    t1.join().unwrap();
    t2.join().unwrap();

    // INVARIANT: both released threads were finalized (no stuck RELEASING).
    assert_eq!(
        s.on_cpu1.load(Ordering::Acquire),
        PENDING,
        "tid 1 stuck RELEASING (clobbered before finalize)",
    );
    assert_eq!(
        s.on_cpu2.load(Ordering::Acquire),
        PENDING,
        "tid 2 stuck RELEASING (clobbered before finalize)",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG: the single-slot blind store loses an update.  loom finds the
    /// interleaving (stash 1, stash 2 [clobber], finalize drains 2, finalize
    /// drains nothing) where tid 1 is never finalized -> stuck RELEASING.
    #[test]
    #[should_panic(expected = "stuck RELEASING")]
    fn single_slot_clobber_strands_a_release() {
        loom::model(|| run(false));
    }

    /// FIX: drain-before-overwrite finalizes the prior occupant before stashing,
    /// so every released tid reaches PENDING under all interleavings.
    #[test]
    fn drain_before_overwrite_loses_no_release() {
        loom::model(|| run(true));
    }
}
