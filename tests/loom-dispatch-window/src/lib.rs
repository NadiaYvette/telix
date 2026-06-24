//! #173 dispatch-protocol window-collapse — the **claim→switch window** — loom model.
//!
//! See docs/dispatch-protocol-173-refactor.md and project_phase5_gate_isolation.
//! The 145e systemic stall is a host-pause hitting the dispatch claim→switch
//! window on ~every dispatch.  The sequence the model captures:
//!
//!   1. (rq lock) a picker pops tid, sets `in_queue=false`, `dispatching_tid
//!      [cpuP]=tid`, and CAS-claims `on_cpu: PENDING -> cpuP`.  state=Running.
//!      tid is now *claimed by cpuP* but the asm switch has NOT happened yet.
//!   2. cpuP is **host-paused** before `try_switch` reaches the asm switch.
//!      `reclaim_stale_on_cpu` would normally take a stale on_cpu=realcpu, but it
//!      REFUSES here because `dispatching_tid[cpuP]==tid` ("a direct-dispatch
//!      raced — leave it") — an assumption that is FALSE while cpuP is paused.
//!   3. So tid is stranded: Running, on_cpu=cpuP, but no CPU is executing it.
//!
//! The refactor makes the window RECOVERABLE (it cannot be made atomic — you
//! claim, then later switch):
//!   (a) a reclaimer on cpuR, when it observes cpuP host-paused, MAY take the
//!       claim away from cpuP (the host-pause exemption to the dispatching_tid
//!       protection); and
//!   (b) cpuP, when it resumes and reaches the asm switch, MUST re-validate that
//!       it still owns tid and BAIL if a peer took it.
//!
//!   SAFETY INVARIANT: run_count(tid) <= 1 — tid executes on at most one CPU
//!   across every interleaving (a second run is the #208 double-execution
//!   family).  LIVENESS: tid is never lost — some CPU runs it.
//!
//! What the model establishes:
//!  * `no_recheck_double_runs`      (#[should_panic]) — (i) legacy: no resume-side
//!     re-check ⇒ the reclaimer and cpuP both run tid.
//!  * `reclaim_blind_store_double_runs` (#[should_panic]) — (ii) the reclaimer
//!     must CAS, not blind-store, or it clobbers a concurrent commit (the #208
//!     hazard, cf. loom-orphan-rescue).
//!  * `load_recheck_double_runs`    (#[should_panic]) — (iii) a resume re-check
//!     done as a plain LOAD is TOCTOU: a reclaimer wins between the load and the
//!     asm switch.  **This REFINES the design doc** — "re-check on_cpu==cpu" must
//!     be a CAS-commit, not a load.
//!  * `cas_commit_is_exclusive`     — (iv) CAS-commit resume + CAS reclaim both
//!     compare-exchange from CLAIMED_P, so exactly one wins: run_count <= 1 and
//!     tid is never lost.  This is the protocol the refactor implements.
//!
//! Implementation note (encoding-agnostic): the model writes the arbitration into
//! `on_cpu` for brevity, but the kernel need NOT overload on_cpu's existing
//! contract (lots of code reads `on_cpu==cpu` as "running here").  The CAS
//! arbitration can be realized as a dedicated per-thread `dispatch_claim:
//! AtomicU32` owner/generation word that cpuP CAS-commits and a reclaimer
//! CAS-steals — what matters, and what this model proves, is the CAS-vs-CAS
//! exclusivity, not the specific word it lives in.

#![cfg(loom)]

use loom::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use loom::sync::Arc;
use loom::thread;

// on_cpu states the claim→switch window passes through, as small distinct
// constants (keeps loom's state space minimal).  Real on_cpu uses PENDING /
// RELEASING / MAX sentinels + real cpu numbers; we only need these four here.
const CLAIMED_P: u32 = 1; // claimed by cpuP under the rq lock; asm switch pending
const RUN_P: u32 = 2; // committed: tid is executing on cpuP (switch done)
const CLAIMED_R: u32 = 3; // a host-pause-exempt reclaimer (cpuR) took the claim
                          // (RUN_R is implicit: cpuR, having taken it, will run it)

/// Resume-side (cpuP) strategy for completing the switch after the host-pause.
#[derive(Clone, Copy)]
enum Resume {
    /// Legacy: blind asm-switch, nothing re-validates ownership.
    NoCheck,
    /// Design-doc v1: re-LOAD `on_cpu == cpuP`, then switch.  TOCTOU.
    LoadCheck,
    /// Fix: CAS-commit `CLAIMED_P -> RUN_P`; bail on failure.
    CasCommit,
}

/// Reclaimer-side (cpuR) strategy for taking the claim from a host-paused cpuP.
#[derive(Clone, Copy)]
enum Reclaim {
    /// Unconditional `store(CLAIMED_R)` — clobbers a concurrent commit (#208).
    BlindStore,
    /// `CAS(CLAIMED_P -> CLAIMED_R)` — only the winner takes it.
    Cas,
}

fn run(resume: Resume, reclaim: Reclaim) {
    // Pre-state: cpuP has already won the claim CAS (on_cpu PENDING->cpuP under
    // the rq lock), set dispatching_tid[cpuP]=tid and state=Running.  We model
    // the window from there: cpuP is host-paused between the claim and the asm
    // switch, and a reclaimer on cpuR runs concurrently.
    let on_cpu = Arc::new(AtomicU32::new(CLAIMED_P));
    let ran_p = Arc::new(AtomicBool::new(false)); // cpuP completed the asm switch
    let ran_r = Arc::new(AtomicBool::new(false)); // cpuR took it (and will run it)

    // cpuP: resumes from the host-pause and tries to complete the switch.
    let (ocp, rp) = (on_cpu.clone(), ran_p.clone());
    let p = thread::spawn(move || match resume {
        Resume::NoCheck => {
            // Legacy claim→switch: switch with no re-validation.
            rp.store(true, Ordering::Release);
        }
        Resume::LoadCheck => {
            // Design-doc v1 ("re-check on_cpu == cpu"): a plain load.  A reclaimer
            // can win the CAS between this load and the store below (the asm
            // switch) — TOCTOU.
            if ocp.load(Ordering::Acquire) == CLAIMED_P {
                rp.store(true, Ordering::Release);
            }
        }
        Resume::CasCommit => {
            // Fix: atomically commit CLAIMED_P -> RUN_P.  Mutually exclusive with
            // the reclaimer's CAS(CLAIMED_P -> CLAIMED_R): exactly one wins.
            if ocp
                .compare_exchange(CLAIMED_P, RUN_P, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                rp.store(true, Ordering::Release);
            }
            // else: a peer reclaimed it — bail, do NOT switch.
        }
    });

    // cpuR: a host-pause-exempt reclaimer.  Reaching here already encodes that it
    // passed the gate (on_cpu==cpuP is a real cpu, cpuP host-paused per stale
    // last_try_switch_ns + last_irq_ns, dispatching_tid[cpuP]==tid).  The model's
    // question is purely whether the TAKE is atomic against cpuP's commit.
    let (ocr, rr) = (on_cpu.clone(), ran_r.clone());
    let r = thread::spawn(move || match reclaim {
        Reclaim::BlindStore => {
            // The #208 hazard (cf. loom-orphan-rescue's blind store(PENDING)):
            // an unconditional store can land after cpuP's commit and resurrect a
            // running thread for a second dispatch.
            ocr.store(CLAIMED_R, Ordering::Release);
            rr.store(true, Ordering::Release);
        }
        Reclaim::Cas => {
            if ocr
                .compare_exchange(CLAIMED_P, CLAIMED_R, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Won the claim: cpuR owns tid and will run it.  (cpuR's own
                // claim→switch window then applies recursively — same invariant.)
                rr.store(true, Ordering::Release);
            }
            // else: cpuP committed first — leave it running on cpuP.
        }
    });

    p.join().unwrap();
    r.join().unwrap();

    let ran_p = ran_p.load(Ordering::Acquire);
    let ran_r = ran_r.load(Ordering::Acquire);

    // LIVENESS: the thread is never dropped on the floor (always holds across all
    // strategies; asserted to catch a hypothetical "both bail" regression).
    assert!(ran_p || ran_r, "thread lost: ran on NEITHER cpu");
    // SAFETY: run_count(tid) <= 1.
    assert!(
        !(ran_p && ran_r),
        "double-execution: tid ran on BOTH cpuP and cpuR (run_count > 1)",
    );
}

// ---------------------------------------------------------------------------
// Step 3 shape: the rescue (rescue_host_paused_peers) reclaims a STRANDED claim
// from a host-paused owner, with the real two-atomic follow-up the kernel does.
//
// In the kernel, the owner's resume commit is `CAS(dispatch_claim: ownerCpu →
// MAX)` and the reclaimer's steal is `CAS(dispatch_claim: ownerCpu → MAX)` too
// (DISPATCH_CLAIM_NONE == the committed value, u32::MAX) — i.e. BOTH CAS from the
// same owner value to the SAME target.  Exclusivity is conferred by the FROM
// value (only one CAS sees `ownerCpu`), not the target.  The winner then does its
// own `on_cpu` follow-up: the owner keeps `on_cpu = ownerCpu` and runs; the
// reclaimer re-orphans `on_cpu = PENDING` and re-enqueues for re-dispatch.
//
//   INVARIANT: exactly one of {owner runs, reclaimer recovers} happens (no
//   double, never lost), AND on_cpu ends consistent with whoever won.
const OWNER_CPU: u32 = 0; // owner cpu id (also the armed dispatch_claim value)
const CLAIM_DONE: u32 = 0xFFFF_FFFF; // committed / no-owner (kernel: u32::MAX)
const ON_CPU_PENDING: u32 = 0xFFFF_FFFE; // re-orphaned, dispatchable

fn run_reclaim_followup() {
    let claim = Arc::new(AtomicU32::new(OWNER_CPU)); // dispatch_claim, armed=owner
    let on_cpu = Arc::new(AtomicU32::new(OWNER_CPU)); // on_cpu = owner at arm
    let owner_ran = Arc::new(AtomicBool::new(false));
    let recovered = Arc::new(AtomicBool::new(false));

    // Owner cpu resumes from the host-pause and tries to commit its claim.
    let (c1, ow1) = (claim.clone(), owner_ran.clone());
    let p = thread::spawn(move || {
        if c1
            .compare_exchange(OWNER_CPU, CLAIM_DONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Committed: keep on_cpu = owner and run.  (No on_cpu write needed —
            // it is already the owner cpu from the arm.)
            ow1.store(true, Ordering::Release);
        }
        // else: a reclaimer stole it — bail (do not run).
    });

    // Rescue reclaimer on a peer cpu: the owner is host-paused; steal its claim.
    let (c2, oc2, rc2) = (claim.clone(), on_cpu.clone(), recovered.clone());
    let r = thread::spawn(move || {
        if c2
            .compare_exchange(OWNER_CPU, CLAIM_DONE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Won the stranded claim: re-orphan + (in the kernel) re-enqueue.
            oc2.store(ON_CPU_PENDING, Ordering::Release);
            rc2.store(true, Ordering::Release);
        }
        // else: the owner committed first — leave it running on the owner.
    });

    p.join().unwrap();
    r.join().unwrap();

    let owner_ran = owner_ran.load(Ordering::Acquire);
    let recovered = recovered.load(Ordering::Acquire);
    // Exactly one outcome (no double-execution; never lost).
    assert!(
        owner_ran ^ recovered,
        "claim→switch reclaim: exactly one of owner-run / reclaim must occur",
    );
    // on_cpu is consistent with the winner.
    let oc = on_cpu.load(Ordering::Acquire);
    if owner_ran {
        assert_eq!(oc, OWNER_CPU, "owner ran ⇒ on_cpu stays the owner cpu");
    }
    if recovered {
        assert_eq!(oc, ON_CPU_PENDING, "reclaimed ⇒ on_cpu re-orphaned to PENDING");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (i) Legacy: cpuP does no resume-side re-check, so it switches even after a
    /// reclaimer took the claim → both run tid.
    #[test]
    #[should_panic(expected = "double-execution")]
    fn no_recheck_double_runs() {
        loom::model(|| run(Resume::NoCheck, Reclaim::Cas));
    }

    /// (ii) The reclaimer must CAS, not blind-store: an unconditional store
    /// clobbers cpuP's CAS-commit and resurrects the running thread → double-run.
    #[test]
    #[should_panic(expected = "double-execution")]
    fn reclaim_blind_store_double_runs() {
        loom::model(|| run(Resume::CasCommit, Reclaim::BlindStore));
    }

    /// (iii) REFINEMENT of the design doc: a resume re-check done as a plain LOAD
    /// is insufficient — a reclaimer wins the CAS between cpuP's load and its asm
    /// switch (TOCTOU).  The resume re-check MUST be a CAS-commit.
    #[test]
    #[should_panic(expected = "double-execution")]
    fn load_recheck_double_runs() {
        loom::model(|| run(Resume::LoadCheck, Reclaim::Cas));
    }

    /// (iv) FIX: CAS-commit resume + CAS reclaim both compare-exchange from
    /// CLAIMED_P, so exactly one wins across every interleaving: run_count <= 1
    /// and tid is never lost.  This is the protocol the refactor implements.
    #[test]
    fn cas_commit_is_exclusive() {
        loom::model(|| run(Resume::CasCommit, Reclaim::Cas));
    }

    /// Step 3 (rescue_host_paused_peers) shape: the owner's resume commit and the
    /// reclaimer's steal both CAS from the owner cpu to the SAME target (MAX),
    /// then each does its `on_cpu` follow-up.  Exactly one wins; on_cpu ends
    /// consistent with the winner; the thread is never double-run nor lost.
    #[test]
    fn reclaim_followup_exclusive() {
        loom::model(run_reclaim_followup);
    }
}
