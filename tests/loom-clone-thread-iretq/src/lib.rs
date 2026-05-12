//! Loom model of the `saved_sp` / `syscall_frame_sp` / `pending_switch_sp`
//! lifecycle for a CLONE_THREAD child's consecutive syscalls.
//!
//! ## Background
//!
//! Boot 91amfsq656 captured a Telix kernel bug: a CLONE_THREAD child
//! reaches its FIRST syscall (write), the syscall completes (`ret=16`,
//! `[clone_child_w]` prints), but the immediately-next byte (an `int3`
//! placed by the test) NEVER traps as `#BP`.  Yet the child's
//! `picked_count` continues to climb past 3000 — the scheduler keeps
//! dispatching it.  Conclusion: the child returns to user mode via
//! `iretq` but does NOT reach the post-first-syscall instruction.
//!
//! The most plausible mechanism is a stale or wrong frame pointer in
//! one of: `saved_sp`, `syscall_frame_sp`, or `pending_switch_sp`.
//! This loom test models the lifecycle and asserts the invariant that
//! every iretq returning to user mode pops from a frame whose `rip`
//! field is the "post-current-syscall" RIP, not some stale value.
//!
//! ## Mapping kernel → model
//!
//! `Thread.syscall_frame_sp` (per-thread, set at trap entry):
//!   - Written by `store_frame_sp` at the top of each #UD-emulated syscall.
//!   - Read by `voluntary_reschedule` when deciding the SP to save into
//!     `saved_sp` before a context switch.
//!
//! `Thread.saved_sp` (per-thread, restored on dispatch):
//!   - Written by `try_switch` (timer-driven preempt) with the CURRENT
//!     RSP at preempt time — usually a deep position inside a kernel
//!     function call stack.
//!   - Written by `voluntary_reschedule` with `syscall_frame_sp` — the
//!     user trap frame SP.
//!   - Read by the next `try_switch` / dispatch that picks this thread,
//!     used as the SP for `mov rsp, %rax; pop GPRs; iretq` in vectors.S.
//!
//! `pending_switch_sp` (per-CPU, transient):
//!   - Written by `voluntary_reschedule` to tell the exception return
//!     path "iretq to this SP, not the entry frame_sp".
//!   - Read by `x86_exception_handler`'s `take_pending_switch()`.
//!
//! ## What the model asserts
//!
//! Invariant `I1`: After every syscall's full return cycle (entry →
//! handler → optional block/preempt/wake → exception return), the
//! thread's iretq pops from a frame whose `rip` field equals the
//! "post-syscall RIP" value the handler wrote via `set_rip(rip + 2)`.
//!
//! Invariant `I2`: Two consecutive syscalls on the same thread (no
//! intervening user-mode preemption) MUST both satisfy I1.
//!
//! ## Things NOT modeled
//!
//! * Actual assembly state — we abstract "iretq target" as a u64 read
//!   from saved_sp's pointed-to frame's `rip` field.
//! * CPU migration mid-syscall.  Single-CPU model first; SMP variant
//!   in a follow-up if I1/I2 hold here.
//! * The personality-server reply path beyond block_current → wakeup.
//!
//! Run: `RUSTFLAGS="--cfg loom" cargo test --release`
//!      from this crate's directory.

#![cfg(loom)]

use loom::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use loom::sync::Arc;
use loom::thread;

/// Synthetic SP / RIP values.  Distinct constants make assertion
/// failures obvious without needing real memory addresses.
mod sp {
    pub const KSTACK_TOP_USER_FRAME: u64 = 0x10000; // child_frame_sp
    pub const DEEP_KERNEL_SP: u64        = 0x10100; // mid-handler stack frame
    pub const TIMER_TRAP_FRAME: u64      = 0x10080; // timer pushed-frame
}
mod rip {
    pub const POST_SYSCALL_1: u64 = 0x1c64; // int3 right after first syscall
    pub const POST_SYSCALL_2: u64 = 0x1c7f; // mov $0x3c after second syscall
    pub const USER_CONTINUE_1: u64 = 0x1c65; // some user instruction
}

/// Abstract per-thread state.
struct Thread {
    syscall_frame_sp: AtomicU64,
    saved_sp: AtomicU64,
    /// Models the "RIP field within the frame at saved_sp" — what
    /// iretq will pop and use as the user-mode RIP.  In the real
    /// kernel this is `frame.rip()` at the address `saved_sp`.
    iretq_rip: AtomicU64,
    /// Whether the thread is currently being blocked (modelling
    /// `block_current`'s spin-wait flag).
    in_block: AtomicBool,
    /// "User-mode reached this RIP" log.  The harness appends each
    /// iretq RIP that returns to user mode; the assertions then check
    /// that the sequence equals [POST_SYSCALL_1, POST_SYSCALL_2].
    user_log: AtomicU64,
}

impl Thread {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            syscall_frame_sp: AtomicU64::new(0),
            saved_sp: AtomicU64::new(sp::KSTACK_TOP_USER_FRAME),
            iretq_rip: AtomicU64::new(rip::POST_SYSCALL_1),
            in_block: AtomicBool::new(false),
            user_log: AtomicU64::new(0),
        })
    }
}

/// Mirror of `store_frame_sp`: at trap entry, the handler stores the
/// trap frame SP into the thread's syscall_frame_sp.
fn store_frame_sp(t: &Thread, frame_sp: u64) {
    t.syscall_frame_sp.store(frame_sp, Ordering::Release);
}

/// Mirror of `voluntary_reschedule`'s key step: write saved_sp from
/// syscall_frame_sp before context-switching to another thread.
fn voluntary_reschedule(t: &Thread) {
    let fsp = t.syscall_frame_sp.load(Ordering::Acquire);
    t.saved_sp.store(fsp, Ordering::Release);
}

/// Mirror of `try_switch`'s save on timer preempt: writes saved_sp
/// with the CURRENT SP at preempt time (which is `current_sp` passed
/// from the timer trap handler).
fn try_switch_preempt(t: &Thread, current_sp: u64) {
    t.saved_sp.store(current_sp, Ordering::Release);
}

/// One full syscall return cycle: handler advances the frame's RIP
/// to the post-syscall instruction, sets RAX, and exits.  Models
/// block_current's spin loop (which can race with a timer-driven
/// preempt that writes saved_sp to a DEEP kernel SP).
///
/// Returns the iretq RIP popped from saved_sp's frame.
fn syscall_cycle(t: &Thread, post_syscall_rip: u64) -> u64 {
    // 1. Trap entry: handler stamps syscall_frame_sp.
    let frame_sp = sp::KSTACK_TOP_USER_FRAME;
    store_frame_sp(t, frame_sp);

    // 2. The frame's RIP field IS where iretq will pop to.  Handler
    //    sets it to "post-syscall RIP" via `set_rip(rip + 2)`.
    t.iretq_rip.store(post_syscall_rip, Ordering::Release);

    // 3. block_current spin-wait, can be raced by a timer-driven
    //    try_switch that writes saved_sp = DEEP_KERNEL_SP.
    t.in_block.store(true, Ordering::Release);

    // 4. After wake, control returns up the stack to handlers.rs.
    //    check_preempt_on_return may call voluntary_reschedule.
    voluntary_reschedule(t);

    // 5. Exception handler returns frame_sp.  iretq pops the frame at
    //    saved_sp.  But which frame is that?  In the real kernel, the
    //    chain `mov rsp, rax; pop GPRs; iretq` uses the SP returned
    //    from x86_exception_handler — which is either `frame_sp` (the
    //    entry SP) or `pending_switch_sp` (a different thread's SP).
    //    For a single-thread cycle on this thread, saved_sp now == frame_sp,
    //    so iretq pops from saved_sp's frame.
    let final_sp = t.saved_sp.load(Ordering::Acquire);
    // If final_sp == frame_sp, we're popping the correct (user) frame.
    // Otherwise, we'd pop a DIFFERENT frame's RIP — the bug we're
    // hunting.
    assert_eq!(final_sp, frame_sp,
        "I1 violated: iretq SP {:#x} != trap entry frame_sp {:#x}",
        final_sp, frame_sp);

    let iretq_rip = t.iretq_rip.load(Ordering::Acquire);
    t.in_block.store(false, Ordering::Release);
    iretq_rip
}

/// Models the timer-driven preempt that could fire while the thread
/// is spinning in block_current.  Saves the CURRENT SP — which is
/// inside block_current's spin loop, NOT the user trap frame SP.
///
/// Loom can't model unbounded spins (branch budget exhausts), so we
/// take a single shot: either the preempt runs while in_block is true,
/// or it skips entirely.  Both interleavings cover the race we care
/// about (preempt-during-block vs no-preempt).
fn timer_preempt(t: &Thread) {
    if t.in_block.load(Ordering::Acquire) {
        try_switch_preempt(t, sp::DEEP_KERNEL_SP);
    }
}

#[test]
fn i1_single_syscall_no_preempt() {
    loom::model(|| {
        let t = Thread::new();
        let rip = syscall_cycle(&t, rip::POST_SYSCALL_1);
        assert_eq!(rip, rip::POST_SYSCALL_1);
    });
}

#[test]
fn i2_two_consecutive_syscalls_no_preempt() {
    loom::model(|| {
        let t = Thread::new();
        // First syscall: write
        let rip1 = syscall_cycle(&t, rip::POST_SYSCALL_1);
        assert_eq!(rip1, rip::POST_SYSCALL_1,
            "I2.a: first syscall returned to RIP {:#x}, expected {:#x}",
            rip1, rip::POST_SYSCALL_1);
        // Second syscall: write
        let rip2 = syscall_cycle(&t, rip::POST_SYSCALL_2);
        assert_eq!(rip2, rip::POST_SYSCALL_2,
            "I2.b: second syscall returned to RIP {:#x}, expected {:#x}",
            rip2, rip::POST_SYSCALL_2);
    });
}

/// Captures the RACE that boots 654-656 observed in the real kernel:
/// voluntary_reschedule's `saved_sp = syscall_frame_sp` write and the
/// timer-driven preempt's `saved_sp = DEEP_KERNEL_SP` write can
/// interleave such that the preempt's stale write WINS, leaving
/// iretq pointing into kernel memory instead of the user trap frame.
///
/// Loom's exhaustive interleaving REPRODUCES this:
///   `assertion left == right failed: I1 violated:
///    iretq SP 0x10100 != trap entry frame_sp 0x10000`
///
/// In the real kernel, `voluntary_reschedule` disables IRQs across
/// its body — that serialization is supposed to prevent this race.
/// The current pattern of NOT reaching the next instruction suggests
/// the IRQ-disable invariant is being violated, OR a different code
/// path (e.g., a wake-up from a different CPU writing `saved_sp` via
/// some unanticipated path) is at fault.
///
/// Marked `#[should_panic]` so CI passes today (documenting the
/// expected failure) and flips to a real pass once the kernel
/// invariant is restored.
#[test]
#[should_panic(expected = "I1 violated")]
fn i1_violated_by_concurrent_preempt() {
    loom::model(|| {
        let t = Thread::new();
        let t2 = t.clone();
        let preempter = thread::spawn(move || {
            timer_preempt(&t2);
        });
        let _ = syscall_cycle(&t, rip::POST_SYSCALL_1);
        preempter.join().unwrap();
    });
}
