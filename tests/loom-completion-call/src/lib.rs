//! Loom model of the completion-ABI **OP_CALL reply rendezvous** (Phase 1, 2b).
//!
//! An `OP_CALL` issuer submits and continues — it does NOT park on a sync
//! reply-cap. When the target replies, the shared reply path
//! (`call_reply::fulfill`, reached by both `sys_reply` and `complete_reply_to`)
//! pushes a reply-CQE into the issuer's CQ and makes the issuer runnable if it
//! is parked in `reap_wait`. That is a classic producer/parked-consumer
//! rendezvous — the exact lost-wakeup surface the completion model exists to
//! retire (the #198/#173 recv_or_park family) — so it gets a loom model BEFORE
//! the kernel wiring lands.
//!
//! Discipline modeled (§9.1 LOCKED, completion-abi-design.md): the bucket lock
//! (`port_wake_one`'s KEY_IO_REAP bucket, taken in `deliver_to_completion_cq`
//! and again by the park's recheck) serializes the producer's "push CQE + wake
//! if parked" against the consumer's "peek CQ + decide-to-park", and the
//! consumer re-checks the CQ *after* declaring intent to park (re-check-before-
//! sleep). The two interleavings under the lock are:
//!   - consumer CS first: cq==0 -> parked=true; producer CS: cq=1, sees
//!     parked -> wakes.            (parks, but woken -> OK)
//!   - producer CS first: cq=1; consumer CS: cq>0 -> consume via peek, no park.
//! Neither loses the wakeup.
//!
//! Kernel mapping: `cq` = the issuer's CQ depth (Task::io_cq), `parked` =
//! issuer blocked in io_reap_wait on KEY_IO_REAP, `woken` = `port_wake_one`
//! made it runnable, `lock` = the turnstile bucket lock.
//!
//! Properties:
//!  1. `serialized_no_lost_wakeup` — under the locked discipline the issuer
//!     ALWAYS makes progress: it either consumes the reply CQE via the peek/
//!     recheck, or it parks and is woken. It never sleeps forever with a reply
//!     CQE sitting unconsumed in its CQ.
//!  2. `unsynchronized_can_lose_wakeup` (#[should_panic]) — drop the
//!     serialization and loom finds the interleaving where the producer pushes
//!     + checks `parked` (still false) before the consumer sets it, so no wake
//!     is issued and the consumer then parks forever. Proves the bucket-lock
//!     serialization is load-bearing, not incidental.

use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

#[derive(Clone, Copy, PartialEq)]
enum Discipline {
    /// §9.1: producer (push+wake) and consumer (peek+park-decision) both run
    /// under the bucket lock; consumer rechecks the CQ before committing to park.
    Serialized,
    /// Broken variant: no lock serializes push+wake against peek+park-decision.
    /// Must be able to lose a wakeup (gives the model teeth).
    Unsynchronized,
}

struct Outcome {
    /// The issuer committed to parking in reap_wait, a reply CQE is pending in
    /// its CQ, yet it was never made runnable — a lost wakeup (sleeps forever).
    lost_wakeup: bool,
}

/// One submit‖fulfill‖reap interleaving. Returns whether a wakeup was lost.
fn run(d: Discipline) -> Outcome {
    let lock = Arc::new(Mutex::new(())); // turnstile bucket lock (KEY_IO_REAP)
    let cq = Arc::new(AtomicUsize::new(0)); // reply CQEs pending (0 or 1)
    let parked = Arc::new(AtomicBool::new(false)); // issuer parked in reap_wait?
    let woken = Arc::new(AtomicBool::new(false)); // fulfill made it runnable?

    // Issuer reap_wait: peek the CQ; if empty, commit to parking. Under the
    // serialized discipline the peek+commit is one locked critical section (the
    // re-check-before-sleep). Returns true if it parks (awaiting a wake).
    let reaper = {
        let lock = lock.clone();
        let cq = cq.clone();
        let parked = parked.clone();
        thread::spawn(move || -> bool {
            let _g = if d == Discipline::Serialized {
                Some(lock.lock().unwrap())
            } else {
                None
            };
            if cq.load(Ordering::Acquire) > 0 {
                return false; // consumed via peek/recheck — no park
            }
            parked.store(true, Ordering::Release); // commit to parking
            true
        })
    };

    // fulfill -> deliver_to_completion_cq + port_wake_one: push the reply CQE,
    // then transition-wake the issuer iff it is parked. Same lock as the reaper
    // under the serialized discipline.
    let waker = {
        let lock = lock.clone();
        let cq = cq.clone();
        let parked = parked.clone();
        let woken = woken.clone();
        thread::spawn(move || {
            let _g = if d == Discipline::Serialized {
                Some(lock.lock().unwrap())
            } else {
                None
            };
            cq.store(1, Ordering::Release); // push the reply CQE (0 -> 1)
            if parked.load(Ordering::Acquire) {
                woken.store(true, Ordering::Release); // make-runnable
            }
        })
    };

    let parked_for_sleep = reaper.join().unwrap();
    waker.join().unwrap();

    Outcome {
        lost_wakeup: parked_for_sleep
            && cq.load(Ordering::Acquire) > 0
            && !woken.load(Ordering::Acquire),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §9.1 locked discipline: across every interleaving the issuer either
    /// consumes the reply CQE via its peek/recheck or is woken after parking —
    /// never a lost wakeup.
    #[test]
    fn serialized_no_lost_wakeup() {
        loom::model(|| {
            let o = run(Discipline::Serialized);
            assert!(
                !o.lost_wakeup,
                "lost wakeup: issuer parked with a reply CQE pending and was never woken"
            );
        });
    }

    /// Without the bucket-lock serialization, loom finds the interleaving where
    /// the reply CQE is pushed and `parked` checked (false) before the issuer
    /// sets it — no wake — and the issuer then parks forever. This MUST panic;
    /// it is the proof that the serialization is required.
    #[test]
    #[should_panic]
    fn unsynchronized_can_lose_wakeup() {
        loom::model(|| {
            let o = run(Discipline::Unsynchronized);
            assert!(
                !o.lost_wakeup,
                "lost wakeup: issuer parked with a reply CQE pending and was never woken"
            );
        });
    }
}
