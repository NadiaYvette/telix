//! Loom model of the #228 Bug A'' publish-visibility race.
//!
//! See project_228_allocator_double_issue memory note.  The night of
//! 2026-06-20 reduced the #208/#228 `stack_base=0` crasher from ~20%
//! frequent-fatal to ~0.5% rare-recoverable via Bug A (drain only-zero-
//! if-state==Dead) + Bug A' (publish state=Ready AFTER stack_base at all
//! six spawn-finalize sites).  The residual is THIS race: the publish of
//! `state=Ready` and the prior write of `stack_base` are plain (non-atomic)
//! Thread fields, so a dispatcher that reads `state` without a paired
//! acquire can — on a weakly-ordered arch (riscv64) — observe Ready while
//! stack_base is still its zero-init value.
//!
//! Modelled state machine (one freshly-spawned thread, two CPUs):
//!
//!   spawner CPU                     dispatcher CPU (try_switch.next)
//!   ───────────                     ────────────────────────────────
//!   stack_base = KBASE              loop until state == READY
//!   <publish>  state = READY        kbase = stack_base
//!                                   assert!(kbase != 0)   // <-- the bug
//!
//! With a Relaxed publish (modelling the plain fields) loom finds an
//! interleaving + reordering where the dispatcher reads READY but
//! kbase==0.  With a Release store / Acquire load the synchronizes-with
//! edge forbids it.

#![cfg(loom)]

use loom::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread;

const NOT_READY: u8 = 0; // ThreadState::Dead/empty — not dispatchable
const READY: u8 = 2; // ThreadState::Ready

/// The dispatch-relevant subset of a freshly-spawned Thread.
struct Thread {
    /// kstack base VA — written during spawn-finalize, BEFORE the thread
    /// is published Ready.  0 = not yet wired (the danger value).
    stack_base: AtomicUsize,
    /// Dispatch gate.  In the kernel this is a plain `ThreadState` field;
    /// here AtomicU8 so loom can model the read/write ordering precisely.
    state: AtomicU8,
}

impl Thread {
    fn new() -> Self {
        Self {
            stack_base: AtomicUsize::new(0),
            state: AtomicU8::new(NOT_READY),
        }
    }
}

const KBASE: usize = 0x8000_0000; // a plausible non-zero kstack base

/// Run the spawn(publish) ‖ dispatch(observe) race once under loom with
/// the given orderings, asserting the dispatcher never sees READY with a
/// zero stack_base.  `store_ord` is the spawner's state publish; `load_ord`
/// is the dispatcher's state observe.
fn run(store_ord: Ordering, load_ord: Ordering) {
    loom::model(move || {
        let t = Arc::new(Thread::new());

        // Spawner CPU: wire stack_base, then publish Ready.
        let spawner = {
            let t = t.clone();
            thread::spawn(move || {
                // stack_base is written Relaxed in BOTH variants — the
                // synchronization that matters is whether the *publish*
                // of `state` releases this write and the consumer acquires.
                t.stack_base.store(KBASE, Ordering::Relaxed);
                t.state.store(READY, store_ord);
            })
        };

        // Dispatcher CPU: spin until the thread looks dispatchable, then
        // read stack_base exactly as try_switch.next does.
        let dispatcher = {
            let t = t.clone();
            thread::spawn(move || {
                // Bounded spin (loom requires finite executions); one
                // re-check is enough to expose the reorder.
                if t.state.load(load_ord) == READY {
                    let kbase = t.stack_base.load(Ordering::Relaxed);
                    // The invariant try_switch relies on: a Ready thread's
                    // stack_base is published.  Violation => the kernel
                    // computes a 0-based kstack range and spurious-kills.
                    assert!(
                        kbase != 0,
                        "dispatcher observed state=READY with stack_base=0 \
                         (publish-visibility race #228 Bug A'')"
                    );
                }
            })
        };

        spawner.join().unwrap();
        dispatcher.join().unwrap();
    });
}

/// BUG REPRODUCTION: plain (Relaxed) publish — models the current kernel
/// plain `state` field.  Loom finds the Ready+stack_base==0 interleaving
/// and the invariant assert fires, so this test is expected to panic.
#[test]
#[should_panic(expected = "stack_base=0")]
fn relaxed_publish_exposes_zero_stack_base() {
    run(Ordering::Relaxed, Ordering::Relaxed);
}

/// FIX PROOF: Release store / Acquire load — the spawner's Release publish
/// of `state` synchronizes-with the dispatcher's Acquire observe, so the
/// stack_base write (sequenced before the Release) is visible whenever
/// READY is seen.  Loom exhausts all interleavings with no violation.
#[test]
fn release_acquire_publish_is_safe() {
    run(Ordering::Release, Ordering::Acquire);
}
