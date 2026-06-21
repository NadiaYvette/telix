//! Loom model of the completion-ABI **deferred-reply cap lifecycle**
//! (`Rings::serve_deferred` / the `reply_take`+`reply_to` pattern it replaces).
//!
//! A deferred server stashes an inbound request's reply-cap handle and answers
//! it much later (an `OP_REPLY` to the stashed handle). That long stash window
//! maximises the chance the *original* caller dies and its 256-slot slab entry
//! is reused by a *different* caller before the server finally replies — the
//! reply-cap-handle ABA surface. This is the new concurrency the deferred
//! pattern stresses (the leaf `serve` loop never holds a cap across requests).
//!
//! `call_reply.rs` keeps this safe with TWO mechanisms, BOTH modeled here:
//!   1. **ABANDONED intermediate state** — caller death (`abandon_all_for_caller`)
//!      CASes the cap PENDING -> CAP_ABANDONED, *not* CAP_FREE. The slot stays
//!      ABANDONED (un-reusable) until the server's own `fulfill` observes the
//!      marker (CAS-fail branch) and only *then* sets FREE. So a re-alloc can
//!      never race an in-flight stale fulfill of the same slot.
//!   2. **post-CAS generation re-validation** — `fulfill` re-reads the slot
//!      generation *after* claiming PENDING -> FULFILLED and undoes the claim if
//!      it changed (`call_reply.rs:399-408`).
//!
//! Mapped to the real code:
//!   - `gen`   = `ReplyCap::generation` (bumped by `alloc`, encoded in handle)
//!   - `state` = `ReplyCap::state` (CAP_FREE/PENDING/FULFILLED/ABANDONED)
//!   - `owner` = `ReplyCap::caller_tid`
//!   - `alloc()` order is **CAS FREE->PENDING, *then* bump gen, *then* set owner**
//!     (`call_reply.rs:247-259`) — the window the post-CAS recheck alone cannot
//!     cover (gen is still the OLD value between the claim and the bump), which
//!     is precisely why mechanism (1) is required.
//!
//! Properties:
//!  1. `abandoned_state_no_double_ownership` — as written, a stashed-handle
//!     `fulfill` racing a caller-death-and-reuse NEVER both succeeds (`Wake`)
//!     *and* lets the reusing caller claim the slot: no double ownership, and it
//!     never wakes the wrong (reusing) caller.
//!  2. `direct_free_allows_double_ownership` (`#[should_panic]`) — replace the
//!     ABANDONED marker with a direct free-on-death and loom finds the window
//!     where the reusing caller's CAS-claim is stolen by the stale fulfill
//!     before it bumps the generation (so the post-CAS recheck still sees the
//!     OLD gen). Proves the ABANDONED-intermediate-state is load-bearing.

use loom::sync::atomic::{AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

// Cap states, mirroring call_reply.rs CAP_* constants.
const FREE: u32 = 0;
const PENDING: u32 = 1;
const FULFILLED: u32 = 2;
const ABANDONED: u32 = 3;

// Identities (arbitrary, distinct, non-zero tids).
const CALLER_A: u32 = 10; // original caller; the server stashed ITS handle
const CALLER_C: u32 = 20; // a *different* caller that reuses the freed slot
const GEN_A: u32 = 1; // generation when A allocated == the server's stashed gen

#[derive(Clone, Copy, PartialEq)]
enum Discipline {
    /// `call_reply.rs` as written: caller death marks the cap CAP_ABANDONED, an
    /// intermediate state the slot stays in until the server's own `fulfill`
    /// consumes it and sets FREE — so no re-alloc can race the in-flight fulfill.
    AbandonedState,
    /// Broken variant: caller death frees the slot straight to FREE, letting a
    /// different caller re-alloc it concurrently with the stale stashed fulfill.
    DirectFree,
}

#[derive(PartialEq, Debug)]
enum FulfillR {
    Wake(u32), // woke this owner tid
    Abandoned,
    Invalid,
}

struct Outcome {
    server: FulfillR,
    /// Did the reusing caller C successfully claim the slot (alloc CAS ok)?
    c_claimed: bool,
}

/// One (death + reuse) ‖ (stashed fulfill) interleaving.
fn run(d: Discipline) -> Outcome {
    // The shared slab slot. Initially holds caller A's PENDING cap at gen=1,
    // whose handle the deferred server has stashed and is about to answer.
    let gen = Arc::new(AtomicU32::new(GEN_A));
    let state = Arc::new(AtomicU32::new(PENDING));
    let owner = Arc::new(AtomicU32::new(CALLER_A));

    // Thread 1: caller A dies, then a *different* caller C re-allocs the slot.
    // alloc() order = CAS FREE->PENDING, THEN bump gen, THEN store owner
    // (call_reply.rs:247-259). Death + reuse are sequenced in one thread because
    // C can only claim the slot once A's death has released it — the meaningful
    // concurrency is against the server's fulfill (Thread 2), not between these.
    let t_reuse = {
        let gen = gen.clone();
        let state = state.clone();
        let owner = owner.clone();
        thread::spawn(move || -> bool {
            // --- caller A death ---
            match d {
                Discipline::AbandonedState => {
                    // abandon_all_for_caller: PENDING -> ABANDONED. May lose to
                    // a fulfill that already claimed FULFILLED (then A was woken
                    // — i.e. A effectively still alive — and this is a no-op).
                    let _ = state.compare_exchange(
                        PENDING,
                        ABANDONED,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
                Discipline::DirectFree => {
                    // BROKEN: straight to FREE, no intermediate marker.
                    state.store(FREE, Ordering::Release);
                }
            }
            // --- caller C re-alloc (alloc()) ---
            if state
                .compare_exchange(FREE, PENDING, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                gen.fetch_add(1, Ordering::AcqRel); // GEN_A -> GEN_A + 1
                owner.store(CALLER_C, Ordering::Release);
                true
            } else {
                false
            }
        })
    };

    // Thread 2: the deferred server answers the STASHED handle (gen = GEN_A) via
    // fulfill(). Mirrors call_reply::fulfill: pre-CAS gen check, CAS
    // PENDING->FULFILLED, post-CAS gen RE-validation (undo on mismatch).
    let t_server = {
        let gen = gen.clone();
        let state = state.clone();
        let owner = owner.clone();
        thread::spawn(move || -> FulfillR {
            if gen.load(Ordering::Acquire) != GEN_A {
                return FulfillR::Invalid; // stale handle, caught pre-CAS
            }
            match state.compare_exchange(
                PENDING,
                FULFILLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // post-CAS generation re-validation (call_reply.rs:399-408)
                    if gen.load(Ordering::Acquire) != GEN_A {
                        let _ = state.compare_exchange(
                            FULFILLED,
                            PENDING,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        );
                        return FulfillR::Invalid;
                    }
                    FulfillR::Wake(owner.load(Ordering::Acquire))
                }
                Err(ABANDONED) => {
                    // Caller died: drop the reply, free the slot.
                    state.store(FREE, Ordering::Release);
                    FulfillR::Abandoned
                }
                Err(_) => FulfillR::Invalid,
            }
        })
    };

    let c_claimed = t_reuse.join().unwrap();
    let server = t_server.join().unwrap();
    Outcome { server, c_claimed }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As written: across every interleaving the stashed-handle fulfill and a
    /// concurrent caller-death-and-reuse never both succeed. The server either
    /// wakes the *original* caller A (reuse lost the race, so A is alive), or it
    /// observes ABANDONED / a bumped generation and reports Abandoned/Invalid —
    /// it never wakes the reusing caller C, and never "succeeds" against a slot
    /// that C also claimed (which would leave C's cap stolen / FULFILLED).
    #[test]
    fn abandoned_state_no_double_ownership() {
        loom::model(|| {
            let o = run(Discipline::AbandonedState);
            assert_ne!(
                o.server,
                FulfillR::Wake(CALLER_C),
                "stale fulfill woke the reusing caller C"
            );
            assert!(
                !(matches!(o.server, FulfillR::Wake(_)) && o.c_claimed),
                "double ownership: server fulfilled while caller C also claimed the slot"
            );
        });
    }

    /// Drop the ABANDONED intermediate state (free directly on death) and loom
    /// finds the window: caller C's CAS FREE->PENDING claim is stolen by the
    /// stale stashed-handle fulfill BEFORE C bumps the generation, so the
    /// server's post-CAS gen recheck still sees the OLD generation and
    /// "succeeds" while C also claimed the slot — C's cap is left FULFILLED
    /// (corrupted; C will hang). MUST panic: proves the ABANDONED intermediate
    /// state is load-bearing, not incidental.
    #[test]
    #[should_panic]
    fn direct_free_allows_double_ownership() {
        loom::model(|| {
            let o = run(Discipline::DirectFree);
            assert!(
                !(matches!(o.server, FulfillR::Wake(_)) && o.c_claimed),
                "double ownership: server fulfilled while caller C also claimed the slot"
            );
        });
    }
}
