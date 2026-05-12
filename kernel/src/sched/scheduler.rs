//! Scheduler — priority-based round-robin with timer-driven preemption.
//!
//! Context switching works by swapping kernel stack pointers. When a timer
//! IRQ fires, the exception vector saves all registers onto the current
//! thread's kernel stack. If preemption is needed, we save the current SP
//! in the thread's TCB, load the new thread's SP, and the exception return
//! path restores the new thread's registers and `eret`s to it.
//!
//! SMP: Run queues are shared across all CPUs, protected by the scheduler
//! spinlock. Each CPU tracks its own current/idle thread via smp::PerCpuData.
//!
//! Thread and Task data is stored in ART (Adaptive Radix Tree) keyed by ID,
//! with Thread entries slab-allocated (256 bytes) and Task entries page-
//! allocated (~1400 bytes). Per-thread/task atomics are embedded in the
//! Thread/Task structs and accessed via TASK_TABLE/THREAD_TABLE radix
//! page tables for lock-free lookup.

use super::cpumask;
use super::radix::RadixTable;
use super::smp;
use super::task::{GROUPS_INLINE, RLIMIT_COUNT, Rlimit, Task, TaskId};
use super::thread::{BlockReason, Thread, ThreadId, ThreadState};
use crate::arch::trapframe::EXCEPTION_FRAME_SIZE;
use crate::ipc::art::Art;
use crate::mm::page::{self, MMUPAGE_SIZE, PhysAddr};
use crate::mm::{phys, slab};
use crate::sync::SpinLock;
use super::thread::SCHED_NORMAL;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// EEVDF virtual-time constants
// ---------------------------------------------------------------------------

/// Fixed-point scaling factor for virtual time. ~1M gives microsecond-ish
/// granularity in virtual time space with pure integer arithmetic.
const VTIME_UNIT: u64 = 1 << 20;

/// Kernel stack allocation order (0 = 1 page, 1 = 2 pages).
/// 2 pages provides headroom for deep syscall call chains.
const KSTACK_ORDER: usize = 1;

/// Kernel stack size in bytes (2^KSTACK_ORDER pages).
#[inline]
fn kstack_size() -> usize {
    page::page_size() << KSTACK_ORDER
}

/// Two-level radix table for lockless task pointer lookup.
/// Used by has_port_cap_fast() and SA atomics on the hot path.
pub static TASK_TABLE: RadixTable = RadixTable::new();

/// Two-level radix table for lockless thread pointer lookup.
/// Used by wake_thread(), is_killed(), current_task_id(), etc.
pub static THREAD_TABLE: RadixTable = RadixTable::new();

/// Wrapper for a global ART with interior mutability.
/// Lock-free reads (RCU-safe); writes require holding the corresponding write lock.
pub struct GlobalArt {
    inner: core::cell::UnsafeCell<Art>,
}
unsafe impl Sync for GlobalArt {}
impl GlobalArt {
    const fn new() -> Self {
        Self {
            inner: core::cell::UnsafeCell::new(Art::new()),
        }
    }
    /// Lock-free lookup. Safe without any lock (RCU read-side).
    #[inline]
    pub fn lookup(&self, key: u64) -> Option<usize> {
        unsafe { &*self.inner.get() }.lookup(key)
    }
    /// Lock-free iteration. Safe without any lock (RCU read-side).
    pub fn for_each<F: FnMut(u64, usize)>(&self, f: F) {
        unsafe { &*self.inner.get() }.for_each(f)
    }
    /// Insert. Must hold the corresponding write lock.
    pub fn insert(&self, key: u64, val: usize) -> bool {
        unsafe { &mut *self.inner.get() }.insert(key, val)
    }
    /// Remove. Must hold the corresponding write lock.
    #[allow(dead_code)]
    pub fn remove(&self, key: u64) -> Option<usize> {
        unsafe { &mut *self.inner.get() }.remove(key)
    }
}

/// Global thread ART — lock-free reads (RCU), writes under THREAD_ART_WRITE_LOCK.
pub static SCHED_THREAD_ART: GlobalArt = GlobalArt::new();
/// Global task ART — lock-free reads (RCU), writes under TASK_ART_WRITE_LOCK.
pub static SCHED_TASK_ART: GlobalArt = GlobalArt::new();
/// Write serializer for thread ART structural mutations.
#[allow(dead_code)]
pub static THREAD_ART_WRITE_LOCK: SpinLock<()> = SpinLock::new(());
/// Write serializer for task ART structural mutations.
#[allow(dead_code)]
pub static TASK_ART_WRITE_LOCK: SpinLock<()> = SpinLock::new(());

// ---------------------------------------------------------------------------
// Sleep queue — sorted singly-linked list of sleeping threads by deadline.
// Replaces O(N) full-ART scan with O(1) tick-check + O(K) wake for K expired.
// Protected by SLEEP_QUEUE_LOCK. Head has the earliest deadline.
// ---------------------------------------------------------------------------

/// Head of the sleep queue (thread ID, u32::MAX = empty).
static SLEEP_QUEUE_HEAD: AtomicU32 = AtomicU32::new(u32::MAX);
/// Lock protecting sleep queue mutations (insert / drain).
static SLEEP_QUEUE_LOCK: SpinLock<()> = SpinLock::new(());

/// Cached earliest alarm deadline (0 = none). Updated by alarm() and check_alarm_timers().
static EARLIEST_ALARM_NS: AtomicU64 = AtomicU64::new(0);
/// Cached earliest interval timer deadline (0 = none). Updated by timer_create and check_interval_timers().
static EARLIEST_INTERVAL_NS: AtomicU64 = AtomicU64::new(0);

/// Maximum idle duration (1 second). Prevents unbounded sleep in case of stale caches.
const MAX_IDLE_NS: u64 = 10_000_000; // 10ms — one tick interval, matches TICK_INTERVAL_NS

/// Sentinel value for on_cpu: thread has been dequeued by percpu_pick_next
/// but the CAS in try_switch hasn't promoted it to a real CPU id yet.
/// Prevents rescue_orphaned_threads from re-enqueuing threads in this
/// transient window (which could cause DOUBLE-SCHED if a third CPU steals
/// the re-enqueued thread before the original CAS completes).
const ON_CPU_PENDING: u32 = u32::MAX - 1;

/// on_cpu sentinel (unused — kept for documentation):
/// Old sentinel for threads in deferred-requeue slots. Removed because leaving
/// on_cpu at the CPU number and using a CAS-from-cpu in drain is simpler and
/// avoids the rescue-vs-drain race.
#[allow(dead_code)]
const ON_CPU_DEFERRED: u32 = u32::MAX - 2;

// ---------------------------------------------------------------------------
// Targeted per-tid trace (call/reply slow-path investigation).
// ---------------------------------------------------------------------------
//
// `TRACE_TID` is a single ThreadId.  When non-zero, scheduler/IPC trace
// points emit a one-line ns-stamped log whenever the matched tid is
// involved (either as `current_thread_id()` or as the explicit subject of
// a wake/enqueue).  Set from userspace via `sys_debug_puts` with the
// sentinel payload `b"!TRACE_ME!\n"` — see `sys_debug_puts`.  Initialised
// to 0 at boot (no-trace).
pub static TRACE_TID: AtomicU32 = AtomicU32::new(0);

// Phase-5b stall instrumentation — per-tid wake outcome ring (aarch64-only).
//
// Each entry holds the most recent `wake_parked_thread` outcome for a tid:
//   - `WAKE_TRACE_TID[i]`        : tid this slot is recording (0 = empty)
//   - `WAKE_TRACE_OUTCOME[i]`    : outcome code packed into u32:
//        bits[3:0]   = path code (1=early, 2=fast-path-enq, 3=lost-to-cps,
//                                 4=deferred-local, 5=deferred-ipi,
//                                 6=dup-wake, 7=noop, 8=neither-cas)
//        bits[7:4]   = waker_cpu
//        bits[15:8]  = parking_cpu (when applicable)
//        bits[31:16] = unused
//   - `WAKE_TRACE_TS_NS[i]`      : monotonic_ns at the wake call
//
// Slot is hashed by (tid % WAKE_TRACE_RING).  Last writer wins.
#[cfg(target_arch = "aarch64")]
pub const WAKE_TRACE_RING: usize = 64;
#[cfg(target_arch = "aarch64")]
pub static WAKE_TRACE_TID: [AtomicU32; WAKE_TRACE_RING] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; WAKE_TRACE_RING]
};
#[cfg(target_arch = "aarch64")]
pub static WAKE_TRACE_OUTCOME: [AtomicU32; WAKE_TRACE_RING] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; WAKE_TRACE_RING]
};
#[cfg(target_arch = "aarch64")]
pub static WAKE_TRACE_TS_NS: [AtomicU64; WAKE_TRACE_RING] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; WAKE_TRACE_RING]
};

#[cfg(target_arch = "aarch64")]
#[inline]
pub fn record_wake_trace(tid: ThreadId, path_code: u8, waker_cpu: u32, parking_cpu: u32) {
    let slot = (tid as usize) % WAKE_TRACE_RING;
    let v: u32 = (path_code as u32 & 0xF)
        | ((waker_cpu & 0xF) << 4)
        | ((parking_cpu & 0xFF) << 8);
    WAKE_TRACE_TID[slot].store(tid, Ordering::Relaxed);
    WAKE_TRACE_OUTCOME[slot].store(v, Ordering::Relaxed);
    WAKE_TRACE_TS_NS[slot].store(crate::arch::timer::monotonic_ns(), Ordering::Relaxed);
}
#[cfg(not(target_arch = "aarch64"))]
#[inline]
pub fn record_wake_trace(_tid: ThreadId, _path_code: u8, _waker_cpu: u32, _parking_cpu: u32) {}

/// Emit a trace line if either the current thread or `subject` matches
/// `TRACE_TID`.  Subject = u32::MAX means "current only".
#[inline]
pub fn trace_point(label: &'static str, subject: u32) {
    let want = TRACE_TID.load(Ordering::Relaxed);
    if want == 0 {
        return;
    }
    let cur = current_thread_id();
    if cur as u32 != want && subject != want {
        return;
    }
    let ns = crate::arch::timer::monotonic_ns();
    let cpu = smp::cpu_id();
    crate::println!(
        "[trace tid={} subj={} label={} cpu={} ts={}]",
        cur, subject, label, cpu, ns
    );
}

/// Get a thread reference by ID via radix lookup (lockless).
#[inline]
pub fn thread_ref(tid: u32) -> &'static Thread {
    let p = THREAD_TABLE.get(tid) as *const Thread;
    unsafe { &*p }
}

/// Get a task reference by ID via radix lookup (lockless).
#[inline]
pub fn task_ref(id: TaskId) -> &'static Task {
    let p = TASK_TABLE.get(id) as *const Task;
    unsafe { &*p }
}

/// Get a task reference by ID, returning None if not in ART.
#[inline]
pub fn task_ref_opt(id: TaskId) -> Option<&'static Task> {
    SCHED_TASK_ART
        .lookup(id as u64)
        .map(|val| unsafe { &*(val as *const Task) })
}

/// Get a thread reference by ID, returning None if not in ART.
#[inline]
pub fn thread_ref_opt(id: ThreadId) -> Option<&'static Thread> {
    SCHED_THREAD_ART
        .lookup(id as u64)
        .map(|val| unsafe { &*(val as *const Thread) })
}

// Per-CPU scheduler state lives in dynamic slices sized by num_cpus() and
// installed by `init_dynamic_percpu` (invoked from smp::init_dynamic_percpu
// just after phys::init). See the runtime-nr_cpus plan.
//
// Each array is stored behind an AtomicPtr so it can be published once and
// read cheaply (relaxed load + bounds check) from every call site. The
// accessors panic (via debug_assert!) if called before init_dynamic_percpu.

/// Per-CPU saved frame SP. The exception handler stores the current frame_sp
/// here before calling syscall dispatch, so that park_current_for_ipc() can
/// read it without changing dispatch()'s signature.
static CURRENT_FRAME_SP_PTR: AtomicPtr<AtomicU64> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn current_frame_sp() -> &'static [AtomicU64] {
    let ptr = CURRENT_FRAME_SP_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "CURRENT_FRAME_SP not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU pending context switch target SP. When a syscall handler parks the
/// current thread or does a direct handoff, it stores the target thread's SP
/// here. The exception handler checks this after dispatch() returns and uses
/// it as the new SP if non-zero.
static PENDING_SWITCH_SP_PTR: AtomicPtr<AtomicU64> =
    AtomicPtr::new(core::ptr::null_mut());


#[inline]
fn pending_switch_sp() -> &'static [AtomicU64] {
    let ptr = PENDING_SWITCH_SP_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "PENDING_SWITCH_SP not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU flag indicating a park-triggered context switch has been staged
/// (pending_switch_sp is set) but the assembly `mov rsp, rax` has not yet
/// completed.  Set by park_current_for_ipc / park_current_for_sleep when
/// they store pending_switch_sp; cleared by `clear_pending_switch()` at
/// exception handler entry (by which time the stack switch is done).
/// `wake_parked_thread` spins on this flag instead of `pending_switch_sp`
/// directly, so that take_pending_switch can safely swap(0) without
/// signalling "stack switch done" prematurely.
static PARK_SWITCH_PENDING_PTR: AtomicPtr<core::sync::atomic::AtomicBool> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
pub fn park_switch_pending() -> &'static [core::sync::atomic::AtomicBool] {
    let ptr = PARK_SWITCH_PENDING_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "PARK_SWITCH_PENDING not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU ID of the thread that just parked (IPC or sleep) on this CPU.
/// Set before the park becomes visible to wakers. Cleared by
/// clear_pending_switch at the next exception handler entry, which also
/// clears the per-thread stack_switch_pending flag.
static PARKED_TID_PTR: AtomicPtr<AtomicU32> = AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn parked_tid() -> &'static [AtomicU32] {
    let ptr = PARKED_TID_PTR.load(Ordering::Relaxed);
    if ptr.is_null() {
        // During early init before alloc. Return empty safe slice.
        return &[];
    }
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU deferred re-enqueue. When try_switch re-enqueues the previous
/// thread, a work-stealing CPU could dequeue it while this CPU is still
/// physically on its kernel stack (between percpu_enqueue and the assembly
/// `mov rsp, rax`). We defer the enqueue and process it at the start of
/// the next try_switch / voluntary_reschedule / park_current_for_ipc.
/// Encoding: bits [31:0] = tid, bits [39:32] = prio, bits [47:40] = cpu.
/// Sentinel: 0 = no deferred enqueue (tid 0 = idle, never deferred).
static DEFERRED_REQUEUE_PTR: AtomicPtr<AtomicU64> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_requeue() -> &'static [AtomicU64] {
    let ptr = DEFERRED_REQUEUE_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_REQUEUE not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Mirror of `dequeue_set_pending`: called from each PENDING→cpu CAS-ok
/// site after the thread successfully transitions to Running.  Clears
/// `pending_set_ns` so the low-threshold rescue diag doesn't false-fire,
/// resets the per-tid one-shot log gate, and bumps the CPU's
/// `dispatch_cas_ok_count` to mirror `dispatch_set_pending_count`.
#[inline]
fn dispatch_cas_ok(pcpu: &smp::PerCpuData, tid: ThreadId) {
    // #135 wake-to-dispatch latency probe: compute (cas_ok_ts - pending_set_ns)
    // and bucket per-CPU before clearing the stamp.  4 sub-buckets per
    // decade × 6 decades covers 1µs..1s with ~78%-resolution per step
    // (10^0.25 ≈ 1.778).  Dumps compute p50/p90/p99/p99.9 from these
    // counts for tail visibility without a wide print.  swap-to-0 so a
    // future dequeue_set_pending stamps a fresh value; load-then-store
    // would race with parallel rescue re-enqueues.
    let pend_ts = thread_ref(tid).pending_set_ns.swap(0, Ordering::Relaxed);
    if pend_ts != 0 {
        let now = get_monotonic_ns();
        let delta = now.saturating_sub(pend_ts);
        let bucket = lat_bucket(delta);
        pcpu.dispatch_latency_hist[bucket].fetch_add(1, Ordering::Relaxed);
    }
    if (tid as usize) < PENDING_LOW_LOGGED.len() {
        PENDING_LOW_LOGGED[tid as usize].store(false, Ordering::Relaxed);
    }
    pcpu.dispatch_cas_ok_count.fetch_add(1, Ordering::Relaxed);
}

/// #135 latency histogram cutpoints (ns).  Log-spaced at 10^(0.25·k):
/// 4 sub-buckets per decade × 6 decades covering 1µs..1s.  Buckets:
///   [0]   <1µs (underflow)
///   [1..=24]  the 24 sub-decade ranges
///   [25]  ≥1s (overflow)
/// Use `lat_bucket(ns)` to assign deltas; use `lat_percentile_ns` to
/// compute a percentile from a snapshot of bucket counts.
const LAT_CUTS_NS: [u64; 25] = [
    1_000, 1_778, 3_162, 5_623, 10_000,
    17_783, 31_623, 56_234, 100_000,
    177_828, 316_228, 562_341, 1_000_000,
    1_778_279, 3_162_278, 5_623_413, 10_000_000,
    17_782_794, 31_622_777, 56_234_133, 100_000_000,
    177_827_941, 316_227_766, 562_341_325, 1_000_000_000,
];

#[inline]
fn lat_bucket(delta_ns: u64) -> usize {
    // Linear scan is fine — 25 comparisons, called per dispatch.  A
    // binary search would shave ~4 comparisons but complicates inlining
    // and is not measurable at this site.
    let mut i = 0;
    while i < LAT_CUTS_NS.len() {
        if delta_ns < LAT_CUTS_NS[i] {
            return i;
        }
        i += 1;
    }
    LAT_CUTS_NS.len() // bucket 25 (overflow)
}

/// Estimate the `percentile_x100`-th percentile (e.g. 5000 = p50,
/// 9990 = p99.9) from a 26-element bucket snapshot.  Returns the upper
/// cutpoint of the bucket the threshold falls into — i.e. an upper-
/// bound estimate of the percentile.  For the underflow bucket (delta
/// < 1µs) returns 1µs; for the overflow bucket (delta ≥ 1s) returns
/// `u64::MAX` (rendered as `>=1s` in dumps).
fn lat_percentile_ns(hist: &[u64; 26], percentile_x100: u32) -> u64 {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return 0;
    }
    // Threshold count: ceil(total * pct / 10000).  We want the first
    // bucket whose cumulative count >= threshold.
    let threshold = ((total as u128) * (percentile_x100 as u128) + 9999) / 10000;
    let mut cum: u128 = 0;
    for (i, &c) in hist.iter().enumerate() {
        cum += c as u128;
        if cum >= threshold {
            if i == 0 {
                return LAT_CUTS_NS[0]; // <1µs bucket → 1µs upper bound
            } else if i < LAT_CUTS_NS.len() {
                return LAT_CUTS_NS[i]; // sub-decade upper bound
            } else {
                return u64::MAX; // overflow
            }
        }
    }
    u64::MAX
}

/// Snapshot a CPU's dispatch_latency_hist into a plain [u64; 26] for
/// percentile computation.  Reads each atomic with Relaxed ordering.
#[inline]
fn lat_snapshot(pcpu: &smp::PerCpuData) -> [u64; 26] {
    let mut h = [0u64; 26];
    for i in 0..26 {
        h[i] = pcpu.dispatch_latency_hist[i].load(Ordering::Relaxed);
    }
    h
}

/// Transition a dequeued thread's on_cpu to ON_CPU_PENDING so try_switch's
/// CAS(ON_CPU_PENDING → cpu) can claim it.
///
/// Idempotent under NEW_INV: every dispatching path expects on_cpu to be
/// ON_CPU_PENDING just before the CAS to a real CPU number.
///
/// #120 dispatch-symmetry: bumps `pcpu.dispatch_set_pending_count` and
/// stamps `pending_set_ns` on the thread.  The matching `cas_ok` site in
/// try_switch / voluntary_reschedule clears `pending_set_ns` and bumps
/// `pcpu.dispatch_cas_ok_count`.  Comparing the two on a CPU-by-CPU basis
/// localizes paths where a thread enters PENDING but never makes it to a
/// successful CAS — the residual oscillation pattern.
#[inline]
fn dequeue_set_pending(tid: ThreadId) {
    let now = get_monotonic_ns();
    thread_ref(tid).pending_set_ns.store(now, Ordering::Relaxed);
    thread_ref(tid).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    smp::current()
        .dispatch_set_pending_count
        .fetch_add(1, Ordering::Relaxed);
}

#[inline]
fn drain_deferred_requeue(cpu: u32) {
    let val = deferred_requeue()[cpu as usize].swap(0, Ordering::AcqRel);
    if val != 0 {
        let tid = (val & 0xFFFFFFFF) as ThreadId;
        let prio = ((val >> 32) & 0xFF) as u8;
        let target = ((val >> 40) & 0xFF) as u32;
        // NEW_INV: the deferred-store path already stored ON_CPU_PENDING
        // before publishing the slot. percpu_enqueue's in_queue swap is
        // the sole double-enqueue guard. No CAS protocol is needed; rescue
        // cannot enqueue a thread with on_cpu=PENDING (it filters PENDING
        // as transient), so there is no racing source of double-enqueues
        // from the rescue path.
        trace_sched(tid, 2); // 2=drain_enq
        set_enq_tag(1); // 1=drain_deferred
        percpu_enqueue(target, prio, tid);
    }
}

// ---------------------------------------------------------------------------
// Per-tid event trace (separate from Thread struct to avoid layout changes)
// ---------------------------------------------------------------------------
// Stores the last scheduling event for each thread. When rescue fires, we
// print this to identify which code path left the thread orphaned.
// Encoding: bits [7:0] = event type, bits [39:8] = cpu, bits [63:40] = seq.
// Events: 1=deferred_store, 2=drain_enq, 3=pick_deq, 4=on_cpu_set,
//         5=on_cpu_clear, 6=state_ready, 7=state_running, 8=rescue_enq,
//         9=wake_enq, 10=wake_no_enq, 11=double_enq, 12=steal_deq,
//         13=park_sleep, 14=park_ipc, 15=sleep_wake, 16=ipc_wake
const TRACE_CAP: usize = 256;
static TRACE_EVENTS: [AtomicU64; TRACE_CAP] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; TRACE_CAP]
};
static TRACE_SEQ: AtomicU64 = AtomicU64::new(1);

#[inline(always)]
fn trace_sched(tid: u32, event: u8) {
    if (tid as usize) < TRACE_CAP {
        let seq = TRACE_SEQ.fetch_add(1, Ordering::Relaxed);
        let cpu = smp::cpu_id() as u64;
        let packed = ((seq & 0xFF_FFFF) << 40) | ((cpu & 0xFFFF_FFFF) << 8) | (event as u64);
        TRACE_EVENTS[tid as usize].store(packed, Ordering::Release);
    }
}

fn trace_last(tid: u32) -> (u8, u32, u32) {
    if (tid as usize) < TRACE_CAP {
        let v = TRACE_EVENTS[tid as usize].load(Ordering::Acquire);
        let event = (v & 0xFF) as u8;
        let cpu = ((v >> 8) & 0xFFFF_FFFF) as u32;
        let seq = ((v >> 40) & 0xFF_FFFF) as u32;
        (event, cpu, seq)
    } else {
        (0, 0, 0)
    }
}

/// Per-CPU deferred kernel stack free. When a thread exits, it can't free
/// its own stack (it's running on it). The address is stored here and freed
/// by the next thread scheduled on that CPU.
static DEFERRED_KSTACK_PTR: AtomicPtr<AtomicUsize> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_kstack() -> &'static [AtomicUsize] {
    let ptr = DEFERRED_KSTACK_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_KSTACK not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU deferred thread ID — the thread whose kstack is in DEFERRED_KSTACK.
/// When try_switch drains the deferred free, it also sets stack_base=0 on this
/// thread, making the slot eligible for reuse. This prevents a race where a
/// slot is reused while the dead thread is still physically running.
static DEFERRED_THREAD_PTR: AtomicPtr<AtomicUsize> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_thread() -> &'static [AtomicUsize] {
    let ptr = DEFERRED_THREAD_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_THREAD not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Per-CPU deferred killed-thread cleanup. When try_switch preempts a
/// killed user thread, it marks it Dead and stores the thread ID here.
/// The next tick() call drains this and does full cleanup (aspace destroy, etc.).
static DEFERRED_KILL_PTR: AtomicPtr<AtomicUsize> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn deferred_kill() -> &'static [AtomicUsize] {
    let ptr = DEFERRED_KILL_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "DEFERRED_KILL not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

const NUM_PRIORITIES: usize = 256;

/// Sentinel value for empty linked-list pointers (head/tail/next/prev).
/// Using 0 (idle thread ID) as sentinel so RunQueue/PerCpuRunQueues initialize
/// to all-zero bytes and land in BSS rather than .data. Idle threads are never
/// enqueued, so ID 0 is safe as "no thread".
const RQ_NIL: u32 = 0;

/// Per-priority run queue — a doubly-linked FIFO list threaded through
/// Thread::run_next / run_prev. No fixed capacity limit.
struct RunQueue {
    head: u32, // First thread (RQ_NIL = empty)
    tail: u32, // Last thread (RQ_NIL = empty)
    len: u32,  // Count of enqueued threads
}

impl RunQueue {
    const fn new() -> Self {
        Self {
            head: RQ_NIL,
            tail: RQ_NIL,
            len: 0,
        }
    }

    /// Append a thread to the tail of the queue.
    fn push(&mut self, tid: ThreadId) {
        let t = thread_ref(tid);
        t.run_next.store(RQ_NIL, Ordering::Relaxed);
        t.run_prev.store(self.tail, Ordering::Relaxed);
        if self.tail != RQ_NIL {
            thread_ref(self.tail).run_next.store(tid, Ordering::Relaxed);
        } else {
            self.head = tid;
        }
        self.tail = tid;
        self.len += 1;
    }

    /// Remove and return the head of the queue.
    fn pop(&mut self) -> Option<ThreadId> {
        if self.head == RQ_NIL {
            return None;
        }
        let tid = self.head;
        let t = thread_ref(tid);
        let next = t.run_next.load(Ordering::Relaxed);
        t.run_next.store(RQ_NIL, Ordering::Relaxed);
        t.run_prev.store(RQ_NIL, Ordering::Relaxed);
        self.head = next;
        if next != RQ_NIL {
            thread_ref(next).run_prev.store(RQ_NIL, Ordering::Relaxed);
        } else {
            self.tail = RQ_NIL;
        }
        self.len -= 1;
        Some(tid)
    }

    /// Unlink an arbitrary thread from the queue (O(1) given its linkage).
    fn unlink(&mut self, tid: ThreadId) {
        let t = thread_ref(tid);
        let prev = t.run_prev.load(Ordering::Relaxed);
        let next = t.run_next.load(Ordering::Relaxed);
        if prev != RQ_NIL {
            thread_ref(prev).run_next.store(next, Ordering::Relaxed);
        } else {
            self.head = next;
        }
        if next != RQ_NIL {
            thread_ref(next).run_prev.store(prev, Ordering::Relaxed);
        } else {
            self.tail = prev;
        }
        t.run_next.store(RQ_NIL, Ordering::Relaxed);
        t.run_prev.store(RQ_NIL, Ordering::Relaxed);
        self.len -= 1;
    }

    /// Search for and remove a thread belonging to the given coscheduling group
    /// that can run on the given CPU.
    #[allow(dead_code)]
    fn find_remove_by_group_for_cpu(&mut self, group: u32, cpu: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.cosched_group.load(Ordering::Relaxed) == group && t.affinity_mask.test(cpu) {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }

    /// Search for and remove the first thread whose affinity allows it to run
    /// on the given CPU.
    #[allow(dead_code)]
    fn find_remove_for_cpu(&mut self, cpu: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.affinity_mask.test(cpu) {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }

    /// Search for and remove a thread in the given coscheduling group (no CPU check).
    /// Used by per-CPU queues where affinity is already guaranteed.
    fn find_remove_by_group(&mut self, group: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.cosched_group.load(Ordering::Relaxed) == group {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }

    /// Search for and remove a thread whose affinity allows `cpu` (for work stealing).
    fn find_remove_with_affinity(&mut self, cpu: u32) -> Option<ThreadId> {
        let mut cur = self.head;
        while cur != RQ_NIL {
            let t = thread_ref(cur);
            if t.affinity_mask.test(cpu) {
                self.unlink(cur);
                return Some(cur);
            }
            cur = t.run_next.load(Ordering::Relaxed);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Per-CPU run queues with active priority bitmap
// ---------------------------------------------------------------------------

/// Per-CPU run queues: 256 linked-list heads + 256-bit active bitmap + EEVDF heap.
/// Each CPU's instance is protected by its own SpinLock in PERCPU_RQ.
struct PerCpuRunQueues {
    queues: [RunQueue; NUM_PRIORITIES],
    active: [u64; 4],
    cosched_burst: u32,
    /// EEVDF d-4 min-heap keyed on virtual deadline.
    eevdf_heap: super::heap::Heap4,
    /// Monotonically advancing virtual time floor.  New/waking threads snap
    /// their vruntime to at least this value so sleepers don't accumulate
    /// unbounded credit.
    eevdf_min_vruntime: u64,
    /// Number of SCHED_NORMAL threads currently in the EEVDF heap.
    eevdf_nr_running: u32,
}

impl PerCpuRunQueues {
    const fn new() -> Self {
        Self {
            queues: [const { RunQueue::new() }; NUM_PRIORITIES],
            active: [0; 4],
            cosched_burst: 0,
            eevdf_heap: super::heap::Heap4::new(),
            eevdf_min_vruntime: 0,
            eevdf_nr_running: 0,
        }
    }

    /// Enqueue a thread at the given priority level.
    fn push(&mut self, prio: u8, tid: ThreadId) {
        self.queues[prio as usize].push(tid);
        self.active[prio as usize / 64] |= 1u64 << (prio as usize % 64);
    }

    /// Dequeue the highest-priority (lowest numeric) thread from the bitmap. O(1).
    fn pop_highest(&mut self) -> Option<ThreadId> {
        for word in 0..4 {
            if self.active[word] != 0 {
                let bit = self.active[word].trailing_zeros() as usize;
                let prio = word * 64 + bit;
                let tid = self.queues[prio].pop()?;
                if self.queues[prio].len == 0 {
                    self.active[word] &= !(1u64 << bit);
                }
                return Some(tid);
            }
        }
        None
    }

    /// Class-aware pick-next: RT bitmap (prio 0-127), then EEVDF heap,
    /// then legacy/demoted bitmap (prio 128-255).
    fn class_pick_next(&mut self) -> Option<ThreadId> {
        // 1. RT: check bitmap words 0-1 (priorities 0-127).
        for word in 0..2 {
            if self.active[word] != 0 {
                let bit = self.active[word].trailing_zeros() as usize;
                let prio = word * 64 + bit;
                let tid = self.queues[prio].pop()?;
                if self.queues[prio].len == 0 {
                    self.active[word] &= !(1u64 << bit);
                }
                return Some(tid);
            }
        }
        // 2. EEVDF: pick eligible thread with earliest deadline.
        if let Some((tid, _deadline)) = self.eevdf_heap.pick_eligible(self.eevdf_min_vruntime) {
            self.eevdf_nr_running -= 1;
            return Some(tid);
        }
        // 3. Legacy/demoted/idle: check bitmap words 2-3 (priorities 128-255).
        for word in 2..4 {
            if self.active[word] != 0 {
                let bit = self.active[word].trailing_zeros() as usize;
                let prio = word * 64 + bit;
                let tid = self.queues[prio].pop()?;
                if self.queues[prio].len == 0 {
                    self.active[word] &= !(1u64 << bit);
                }
                return Some(tid);
            }
        }
        None
    }

    /// Find and dequeue a thread in the given coscheduling group.
    /// Checks RT bitmap queues first, then the EEVDF heap.
    ///
    /// #120 dispatch-symmetry audit (2026-05-09): callers of `pop_for_group`
    /// at `percpu_pick_next_cosched` correctly invoke `dequeue_set_pending`
    /// after the pop, mirroring the `class_pick_next` path. The cosched
    /// dispatch path is NOT asymmetric on the on_cpu transition.
    ///
    /// Separate observation (not addressed here): the EEVDF heap variant
    /// scans `0..n` linearly without the rotating `scan_start` origin used
    /// by `pick_eligible`. If multiple cosched group mates share the same
    /// deadline, the lowest physical position wins back-to-back, which can
    /// reproduce the LIFO-starvation pattern within a cosched burst. Out of
    /// scope for the dispatch-symmetry counter pair, flagged for follow-up.
    fn pop_for_group(&mut self, group: u32) -> Option<ThreadId> {
        // 1. RT bitmap queues (priorities 0-127).
        for word in 0..2 {
            if self.active[word] != 0 {
                let mut bits = self.active[word];
                while bits != 0 {
                    let bit = bits.trailing_zeros() as usize;
                    let prio = word * 64 + bit;
                    if let Some(tid) = self.queues[prio].find_remove_by_group(group) {
                        if self.queues[prio].len == 0 {
                            self.active[word] &= !(1u64 << bit);
                        }
                        return Some(tid);
                    }
                    bits &= !(1u64 << bit);
                }
            }
        }
        // 2. EEVDF heap (SCHED_NORMAL threads).
        if let Some((tid, _key)) = self.eevdf_heap.pop_for_group(group, self.eevdf_min_vruntime) {
            self.eevdf_nr_running -= 1;
            return Some(tid);
        }
        // 3. Legacy/demoted bitmap queues (priorities 128-255).
        for word in 2..4 {
            if self.active[word] != 0 {
                let mut bits = self.active[word];
                while bits != 0 {
                    let bit = bits.trailing_zeros() as usize;
                    let prio = word * 64 + bit;
                    if let Some(tid) = self.queues[prio].find_remove_by_group(group) {
                        if self.queues[prio].len == 0 {
                            self.active[word] &= !(1u64 << bit);
                        }
                        return Some(tid);
                    }
                    bits &= !(1u64 << bit);
                }
            }
        }
        None
    }

    /// Remove a specific thread from the prio-254 queue (for wake_thread boost).
    /// Returns true if the thread was found and removed, false otherwise.
    fn remove_tid(&mut self, tid: ThreadId) -> bool {
        let prio = 254usize;
        let mut cur = self.queues[prio].head;
        while cur != RQ_NIL {
            if cur == tid {
                self.queues[prio].unlink(tid);
                if self.queues[prio].len == 0 {
                    self.active[prio / 64] &= !(1u64 << (prio % 64));
                }
                thread_ref(tid).in_queue.store(false, Ordering::Release);
                return true;
            }
            cur = thread_ref(cur).run_next.load(Ordering::Relaxed);
        }
        false
    }

    /// Check if any threads are enqueued. O(1) via bitmap + heap check.
    fn has_ready(&self) -> bool {
        self.active[0] | self.active[1] | self.active[2] | self.active[3] != 0
            || self.eevdf_nr_running > 0
    }

    /// Steal one thread for `thief_cpu` from lowest-priority queue with ≥2 threads.
    #[allow(dead_code)]
    fn steal_one(&mut self, thief_cpu: u32) -> Option<ThreadId> {
        self.steal_one_min(thief_cpu, 2)
    }

    /// Steal a thread from this run queue, requiring at least `min_len` threads
    /// at that priority level. `min_len=1` allows stealing the only thread
    /// (used by idle CPUs); `min_len=2` preserves at least one for the victim.
    fn steal_one_min(&mut self, thief_cpu: u32, min_len: u32) -> Option<ThreadId> {
        // Try stealing from bitmap queues first (RT and legacy).
        for word in (0..4).rev() {
            if self.active[word] != 0 {
                let mut bits = self.active[word];
                while bits != 0 {
                    // Highest set bit = lowest priority = best to steal
                    let bit = 63 - bits.leading_zeros() as usize;
                    let prio = word * 64 + bit;
                    if self.queues[prio].len >= min_len {
                        if let Some(tid) = self.queues[prio].find_remove_with_affinity(thief_cpu) {
                            if self.queues[prio].len == 0 {
                                self.active[word] &= !(1u64 << bit);
                            }
                            thread_ref(tid).in_queue.store(false, Ordering::Release);
                            return Some(tid);
                        }
                    }
                    bits &= !(1u64 << bit);
                }
            }
        }
        // Try stealing from EEVDF heap (steal earliest-deadline thread).
        if self.eevdf_nr_running >= min_len {
            if let Some((tid, _deadline)) = self.eevdf_heap.pop_min() {
                // Check affinity — if the thread can't run on thief, put it back.
                if thread_ref(tid).affinity_mask.test(thief_cpu) {
                    self.eevdf_nr_running -= 1;
                    thread_ref(tid).in_queue.store(false, Ordering::Release);
                    return Some(tid);
                }
                // Can't run on thief — re-insert with same deadline.
                let t = thread_ref(tid);
                self.eevdf_heap.insert(tid, t.eevdf_deadline);
                // Don't decrement eevdf_nr_running — we put it back.
            }
        }
        None
    }
}

static PERCPU_RQ_PTR: AtomicPtr<SpinLock<PerCpuRunQueues>> =
    AtomicPtr::new(core::ptr::null_mut());

#[inline]
fn percpu_rq() -> &'static [SpinLock<PerCpuRunQueues>] {
    let ptr = PERCPU_RQ_PTR.load(Ordering::Relaxed);
    debug_assert!(!ptr.is_null(), "PERCPU_RQ not init");
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

/// Allocate and install this module's dynamic per-CPU slices.
/// Called by `smp::init_dynamic_percpu` after `phys::init`.
pub(crate) fn init_dynamic_percpu() {
    let n = smp::num_cpus();
    unsafe {
        let s = phys::alloc_static_slice::<AtomicU64>(n);
        CURRENT_FRAME_SP_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicU64>(n);
        PENDING_SWITCH_SP_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<core::sync::atomic::AtomicBool>(n);
        PARK_SWITCH_PENDING_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicU32>(n);
        for v in s.iter() { v.store(u32::MAX, Ordering::Relaxed); }
        PARKED_TID_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicU64>(n);
        DEFERRED_REQUEUE_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicUsize>(n);
        DEFERRED_KSTACK_PTR.store(s.as_mut_ptr(), Ordering::Release);

        // DEFERRED_THREAD and DEFERRED_KILL sentinel value is usize::MAX,
        // not 0 — alloc_static_slice returns zeroed memory, so explicitly
        // initialize each slot.
        let s = phys::alloc_static_slice::<AtomicUsize>(n);
        for slot in s.iter() {
            slot.store(usize::MAX, Ordering::Relaxed);
        }
        DEFERRED_THREAD_PTR.store(s.as_mut_ptr(), Ordering::Release);

        let s = phys::alloc_static_slice::<AtomicUsize>(n);
        for slot in s.iter() {
            slot.store(usize::MAX, Ordering::Relaxed);
        }
        DEFERRED_KILL_PTR.store(s.as_mut_ptr(), Ordering::Release);

        // PERCPU_RQ: zero-initialized bytes match PerCpuRunQueues::new()
        // (which uses RQ_NIL == 0 sentinels — see comment on RQ_NIL above).
        // SpinLock<T>::new() is also all-zero for the unlocked state.
        let s = phys::alloc_static_slice::<SpinLock<PerCpuRunQueues>>(n);
        PERCPU_RQ_PTR.store(s.as_mut_ptr(), Ordering::Release);

        // Per-CPU enqueue caller tags (debug).
        let s = phys::alloc_static_slice::<core::sync::atomic::AtomicU8>(n);
        ENQ_CALLER_TAG_PTR.store(s.as_mut_ptr(), Ordering::Release);
    }
}

/// Enqueue a thread onto the per-CPU run queue for the given target CPU.
/// The caller must ensure the thread's state is Ready before calling.
/// Routes SCHED_NORMAL threads (not demoted to prio 254) to the EEVDF heap;
/// all others go to the legacy bitmap queue.
/// Debug: per-CPU caller tag for percpu_enqueue tracing (avoids cross-CPU race).
/// 1=drain_deferred, 2=vol_resched, 3=wake_thread, 4=handoff, 5=steal,
/// 6=wake_parked, 7=sleep_timer, 8=spawn, 9=kill_sleep, 10=other
static ENQ_CALLER_TAG_PTR: AtomicPtr<core::sync::atomic::AtomicU8> =
    AtomicPtr::new(core::ptr::null_mut());

fn enq_caller_tags() -> &'static [core::sync::atomic::AtomicU8] {
    let ptr = ENQ_CALLER_TAG_PTR.load(Ordering::Relaxed);
    if ptr.is_null() { return &[]; }
    unsafe { core::slice::from_raw_parts(ptr, smp::num_cpus()) }
}

fn set_enq_tag(tag: u8) {
    let tags = enq_caller_tags();
    let cpu = smp::cpu_id() as usize;
    if cpu < tags.len() {
        tags[cpu].store(tag, Ordering::Relaxed);
    }
}

fn get_enq_tag() -> u8 {
    let tags = enq_caller_tags();
    let cpu = smp::cpu_id() as usize;
    if cpu < tags.len() { tags[cpu].load(Ordering::Relaxed) } else { 0 }
}

/// Per-source double-enqueue counters for diagnosing thread-loss.
static DOUBLE_ENQ_DRAIN: AtomicU64 = AtomicU64::new(0);
static DOUBLE_ENQ_RESCUE: AtomicU64 = AtomicU64::new(0);
static DOUBLE_ENQ_WAKE: AtomicU64 = AtomicU64::new(0);
static DOUBLE_ENQ_OTHER: AtomicU64 = AtomicU64::new(0);
static ENQ_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Counts phantom-enqueued recoveries: threads found with `in_queue=true`
/// but no actual heap or bitmap membership on their `last_cpu`'s run queue.
/// Driven by `rescue_orphaned_threads_impl`'s self-healing pass.
static RESCUE_PHANTOM: AtomicU64 = AtomicU64::new(0);
/// Per-branch rescue counters in `rescue_orphaned_threads_impl`.  Splits the
/// global `DOUBLE_ENQ_RESCUE` count by which predicate fired so we can tell
/// which orphan pattern is occurring during an IPC stall.
/// `RESCUE_MAX`: orphan path where `on_cpu == u32::MAX`.
/// `RESCUE_STALE_ON_CPU`: Bug A fix branch (commit 712e741) — `on_cpu` claims
/// a real CPU but that CPU's `current_thread` is a different tid.
/// `RESCUE_PENDING`: observed `on_cpu == ON_CPU_PENDING` during the scan.
/// Currently filtered out (transient dispatch state) so no rescue action is
/// taken, but the counter catches how often we observe it.
static RESCUE_MAX: AtomicU64 = AtomicU64::new(0);
static RESCUE_STALE_ON_CPU: AtomicU64 = AtomicU64::new(0);
static RESCUE_PENDING: AtomicU64 = AtomicU64::new(0);
/// #120 sub-pattern A: counts every time the new STUCK_PENDING_AGE check
/// fires its rescue (logs RESCUE-STUCK-PENDING).  Dumped on CALL-TIMEOUT
/// so we can tell whether the rescue is even being entered for orphans.
static RESCUE_STUCK_PENDING_FIRES: AtomicU64 = AtomicU64::new(0);

/// #120 low-threshold PENDING-stuck diagnostic.  Counts the lower-bound (2s)
/// "PENDING-STUCK-LOW" prints — fires when a thread's `pending_set_ns` is
/// older than `PENDING_LOW_THRESHOLD_NS` regardless of whether the 16s
/// rescue threshold is reached.  Lets us see *slow* dispatch oscillations
/// that hard-wedge fixes (commits 644c7b0 / 27cf951) didn't eliminate.
static PENDING_LOW_FIRES: AtomicU64 = AtomicU64::new(0);

/// #135 false-positive probe: count of try_switch invocations where
/// pick returned the running thread (concurrent re-enqueue + self-pick).
/// In this branch we now clear pending_set_ns so the rescue's stale-stamp
/// false positive no longer fires.  High SELF_PICK_COUNT in a boot
/// indicates a noisy false-enqueue source worth chasing separately.
static SELF_PICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Per-tid "already logged for this PENDING episode" flag, cleared when
/// `pending_set_ns` returns to 0 (CAS-ok path) or when the thread leaves
/// the Ready/Pending state.  Prevents flooding the serial log when the
/// same tid keeps re-PENDING-ing.  Indexed by tid, capped at 256.
static PENDING_LOW_LOGGED: [core::sync::atomic::AtomicBool; 256] = {
    const Z: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [Z; 256]
};

/// Per-tid rescue counter for the watchdog dump.  Lets us see *which*
/// tids account for the bulk of rescue traffic when a stall storm fires —
/// e.g. r11/r12 saw 38k+ pend rescues with no clue which threads were
/// being repeatedly rescued.  Indexed by tid, capped at 256 (the kernel
/// rarely runs more threads on a focus boot, and we'd rather skip
/// counting for the rare overflow than waste memory).
const PER_TID_RESCUE_CAP: usize = 256;
static RESCUE_PER_TID: [AtomicU64; PER_TID_RESCUE_CAP] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; PER_TID_RESCUE_CAP]
};

#[inline(always)]
fn rescue_per_tid_inc(tid: u32) {
    let i = tid as usize;
    if i < PER_TID_RESCUE_CAP {
        RESCUE_PER_TID[i].fetch_add(1, Ordering::Relaxed);
    }
}

fn percpu_enqueue(target_cpu: u32, prio: u8, tid: ThreadId) {
    // Double-enqueue detection.  Benign race: rescue_orphaned_threads may
    // enqueue a thread that drain_deferred_requeue is about to enqueue.
    // The in_queue swap detects this and the second enqueue is safely
    // skipped.  No println here — this runs in IRQ context and the serial
    // lock would deadlock with concurrent output on other CPUs.
    if thread_ref(tid).in_queue.swap(true, Ordering::AcqRel) {
        trace_sched(tid, 11); // 11=double_enq
        trace_point("percpu_enqueue.skip_in_queue", tid as u32);
        let src = get_enq_tag();
        match src {
            1 => { DOUBLE_ENQ_DRAIN.fetch_add(1, Ordering::Relaxed); }
            7 => { DOUBLE_ENQ_RESCUE.fetch_add(1, Ordering::Relaxed); }
            6 | 3 => { DOUBLE_ENQ_WAKE.fetch_add(1, Ordering::Relaxed); }
            _ => { DOUBLE_ENQ_OTHER.fetch_add(1, Ordering::Relaxed); }
        }
        return; // Don't enqueue again.
    }
    trace_point("percpu_enqueue.insert", tid as u32);
    ENQ_TOTAL.fetch_add(1, Ordering::Relaxed);
    // #120 instrumentation I: per-thread enqueue counter.
    thread_ref(tid).enqueue_count.fetch_add(1, Ordering::Relaxed);
    // #120 instrumentation H: timestamp the Ready-enqueue event.
    thread_ref(tid).last_ready_ns.store(get_monotonic_ns(), Ordering::Relaxed);
    let mut rq = percpu_rq()[target_cpu as usize].lock();
    let t = thread_ref(tid);
    if t.sched_class == SCHED_NORMAL && prio != 254 {
        eevdf_enqueue(&mut rq, tid);
    } else {
        rq.push(prio, tid);
    }
}

/// Compute EEVDF deadline and insert a thread into the per-CPU heap.
/// Called under the per-CPU RQ lock.
fn eevdf_enqueue(rq: &mut PerCpuRunQueues, tid: ThreadId) {
    let t = unsafe { thread_mut_from_ref(tid) };
    // Compute base virtual time slice and apply latency scaling.
    let weight = t.eevdf_weight as u64;
    let lat_w = t.eevdf_latency_weight as u64;
    let base_slice = (t.default_quantum as u64) * VTIME_UNIT / weight;
    // Lower latency_weight → shorter slice → tighter deadlines → more responsive.
    t.eevdf_slice_vt = ((base_slice * 1024) / lat_w).max(1);

    // Hard-snap vruntime to min_vruntime.  This works in concert with the
    // eligibility filter in class_pick_next: waking threads land at exactly
    // min_vruntime (eligible), while preempted threads have vruntime above
    // min_vruntime (ineligible until others catch up).  The combination
    // provides the EEVDF sleeping-credit benefit — wakers are naturally
    // preferred — without explicit vruntime manipulation below the floor.
    if t.eevdf_vruntime < rq.eevdf_min_vruntime {
        t.eevdf_vruntime = rq.eevdf_min_vruntime;
    }
    // Compute lag: positive = thread is owed CPU (eligible), negative = ahead.
    t.eevdf_lag = rq.eevdf_min_vruntime as i64 - t.eevdf_vruntime as i64;

    // Advance min_vruntime: it's the max of all threads' vruntime at enqueue.
    if t.eevdf_vruntime > rq.eevdf_min_vruntime {
        rq.eevdf_min_vruntime = t.eevdf_vruntime;
    }
    // Set deadline.
    t.eevdf_deadline = t.eevdf_vruntime + t.eevdf_slice_vt;
    // Insert into heap. If full, fall back to bitmap.
    if !rq.eevdf_heap.insert(tid, t.eevdf_deadline) {
        // Heap overflow — fall back to bitmap at the thread's priority.
        rq.push(t.effective_priority, tid);
        return;
    }
    rq.eevdf_nr_running += 1;
}

/// Verify that `tid` is actually present in the EEVDF heap or one of the
/// bitmap-priority queues on `cpu`.  Caller must hold that CPU's `percpu_rq`
/// lock for the duration of the check.
///
/// Used by the rescue self-healing pass to detect "phantom enqueued"
/// threads — `in_queue=true` but no actual queue membership — and re-insert
/// them so the run-queue invariant `in_queue == queue_membership` holds.
fn rq_contains_tid(rq: &PerCpuRunQueues, tid: ThreadId) -> bool {
    // Fast path: EEVDF heap membership is O(1) via the per-thread heap_pos.
    if thread_ref(tid).eevdf_heap_pos != super::heap::HEAP_POS_NONE {
        return true;
    }
    // Bitmap path: walk only the priority queues whose bitmap bits are set.
    // Single-element queues have run_prev=run_next=RQ_NIL, so we can't rely
    // on link fields alone; the head pointer is the source of truth.
    for word in 0..4 {
        let mut bits = rq.active[word];
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            bits &= !(1u64 << bit);
            let prio = word * 64 + bit;
            let mut cur = rq.queues[prio].head;
            while cur != RQ_NIL {
                if cur == tid {
                    return true;
                }
                cur = thread_ref(cur).run_next.load(Ordering::Relaxed);
            }
        }
    }
    false
}

/// Try to steal a thread from another CPU's run queue.
/// Returns the stolen thread's ID, or None.
fn try_steal(cpu: u32) -> Option<ThreadId> {
    try_steal_min(cpu, 2)
}

/// Try to steal from idle — allows taking the only thread at a priority level.
fn try_steal_for_idle(cpu: u32) -> Option<ThreadId> {
    try_steal_min(cpu, 1)
}

fn try_steal_min(cpu: u32, min_len: u32) -> Option<ThreadId> {
    let online = smp::online_cpus() as usize;
    if online <= 1 {
        return None;
    }
    for i in 1..online {
        let victim = ((cpu as usize + i) % online) as u32;
        if let Some(mut rq) = percpu_rq()[victim as usize].try_lock() {
            if let Some(tid) = rq.steal_one_min(cpu, min_len) {
                return Some(tid);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Kernel-held port handlers for task/thread ports
// ---------------------------------------------------------------------------

/// Kernel handler for task ports. Stub — returns empty reply.
fn task_port_handler(
    _port_id: crate::ipc::port::PortId,
    _user_data: usize,
    _msg: &crate::ipc::Message,
) -> crate::ipc::Message {
    crate::ipc::Message::empty()
}

/// Kernel handler for thread ports. Stub — returns empty reply.
fn thread_port_handler(
    _port_id: crate::ipc::port::PortId,
    _user_data: usize,
    _msg: &crate::ipc::Message,
) -> crate::ipc::Message {
    crate::ipc::Message::empty()
}

// ---------------------------------------------------------------------------
// Thread/Task slab/page allocation
// ---------------------------------------------------------------------------

/// Slab size for Thread entries (Thread is ~408 bytes, 512-byte slab).
const THREAD_SLAB_SIZE: usize = 512;
const _: () = assert!(core::mem::size_of::<Thread>() <= THREAD_SLAB_SIZE);

fn alloc_thread_entry() -> Option<*mut Thread> {
    let pa = slab::alloc(THREAD_SLAB_SIZE)?;
    let p = pa.as_usize() as *mut Thread;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, THREAD_SLAB_SIZE);
        core::ptr::write(p, Thread::empty());
    }
    Some(p)
}

#[allow(dead_code)]
fn free_thread_entry(p: *mut Thread) {
    slab::free(PhysAddr::new(p as usize), THREAD_SLAB_SIZE);
}

fn alloc_task_entry() -> Option<*mut Task> {
    // Task is ~1400 bytes — too large for any slab cache, use page allocation.
    let pa = phys::alloc_page()?;
    let p = pa.as_usize() as *mut Task;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, page::page_size());
        core::ptr::write(p, Task::empty());
    }
    Some(p)
}

#[allow(dead_code)]
fn free_task_entry(p: *mut Task) {
    phys::free_page(PhysAddr::new(p as usize));
}

// ---------------------------------------------------------------------------
// ID allocation (lock-free atomic counters)
// ---------------------------------------------------------------------------

/// Monotonic ID counters for thread/task allocation.
static NEXT_THREAD_ID: AtomicU32 = AtomicU32::new(0);
static NEXT_TASK_ID: AtomicU32 = AtomicU32::new(0);

// --- Initialization ---

/// Initialize task 0 and the BSP's idle thread (thread 0).
fn sched_init() {
    TASK_TABLE.init();
    THREAD_TABLE.init();

    let task_ptr = alloc_task_entry().expect("task 0 alloc");
    let task0_port =
        crate::ipc::port::create_kernel_port(task_port_handler, 0).expect("task 0 port");
    unsafe {
        (*task_ptr).id = 0;
        (*task_ptr).active = true;
        (*task_ptr).port_id = task0_port;
    }
    SCHED_TASK_ART.insert(0, task_ptr as usize);
    TASK_TABLE.ensure_l1(0);
    TASK_TABLE.set(0, task_ptr as *mut u8);
    NEXT_TASK_ID.store(1, Ordering::Relaxed);

    let thread_ptr = alloc_thread_entry().expect("thread 0 alloc");
    let thread0_port =
        crate::ipc::port::create_kernel_port(thread_port_handler, 0).expect("thread 0 port");
    // Allocate a proper kernel stack for the BSP idle thread so that
    // update_kernel_stack() sets TSS RSP0 correctly when switching to idle.
    // Without this, stack_base defaults to 0 and RSP0 = 0 + kstack_size(),
    // causing interrupts on the idle CPU to corrupt low memory.
    let bsp_kstack = crate::mm::phys::alloc_pages(KSTACK_ORDER).expect("thread 0 kstack");
    unsafe {
        (*thread_ptr).id = 0;
        (*thread_ptr).state = ThreadState::Running;
        (*thread_ptr).task_id = 0;
        (*thread_ptr).port_id = thread0_port;
        (*thread_ptr).base_priority = 255;
        (*thread_ptr).effective_priority = 255;
        (*thread_ptr).quantum = u32::MAX;
        (*thread_ptr).default_quantum = u32::MAX;
        (*thread_ptr).stack_base = bsp_kstack.as_usize();
    }
    unsafe { &*thread_ptr }.prio.store(255, Ordering::Relaxed);
    SCHED_THREAD_ART.insert(0, thread_ptr as usize);
    THREAD_TABLE.ensure_l1(0);
    THREAD_TABLE.set(0, thread_ptr as *mut u8);
    NEXT_THREAD_ID.store(1, Ordering::Relaxed);
}

/// Create an idle thread for a secondary CPU. Returns its ThreadId.
/// Must be called under THREAD_ART_WRITE_LOCK.
fn create_idle_thread() -> Option<ThreadId> {
    let id = NEXT_THREAD_ID.load(Ordering::Relaxed);
    if id as usize >= RadixTable::capacity() {
        return None;
    }
    NEXT_THREAD_ID.store(id + 1, Ordering::Relaxed);

    let ptr = alloc_thread_entry()?;
    let idle_port = crate::ipc::port::create_kernel_port(thread_port_handler, id as usize)?;
    // Allocate a proper kernel stack so update_kernel_stack() sets correct
    // TSS RSP0 when switching to this idle thread.
    let idle_kstack = crate::mm::phys::alloc_pages(KSTACK_ORDER)?;
    unsafe {
        (*ptr).id = id;
        (*ptr).state = ThreadState::Running;
        (*ptr).task_id = 0;
        (*ptr).port_id = idle_port;
        (*ptr).base_priority = 255;
        (*ptr).effective_priority = 255;
        (*ptr).quantum = u32::MAX;
        (*ptr).default_quantum = u32::MAX;
        (*ptr).sched_class = super::thread::SCHED_IDLE;
        (*ptr).stack_base = idle_kstack.as_usize();
    }
    let t = unsafe { &*ptr };
    t.prio.store(255, Ordering::Relaxed);
    t.thread_task.store(0, Ordering::Relaxed);

    SCHED_THREAD_ART.insert(id as u64, ptr as usize);
    if !THREAD_TABLE.ensure_l1(id) {
        return None;
    }
    THREAD_TABLE.set(id, ptr as *mut u8);
    Some(id)
}

/// Find a reusable (Dead) thread slot, or allocate a new one.
/// Must be called under THREAD_ART_WRITE_LOCK.
fn alloc_thread_id() -> Option<ThreadId> {
    let mut found_id: Option<ThreadId> = None;
    SCHED_THREAD_ART.for_each(|key, val| {
        if found_id.is_some() {
            return;
        }
        if key == 0 {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.state == ThreadState::Dead && t.stack_base == 0 {
            found_id = Some(key as ThreadId);
        }
    });
    if let Some(id) = found_id {
        return Some(id);
    }
    let id = NEXT_THREAD_ID.load(Ordering::Relaxed);
    if id as usize >= RadixTable::capacity() {
        return None;
    }
    let ptr = alloc_thread_entry()?;
    SCHED_THREAD_ART.insert(id as u64, ptr as usize);
    if !THREAD_TABLE.ensure_l1(id) {
        return None;
    }
    THREAD_TABLE.set(id, ptr as *mut u8);
    NEXT_THREAD_ID.store(id + 1, Ordering::Relaxed);
    Some(id)
}

/// Find a reusable (inactive) task slot, or allocate a new one.
/// Must be called under TASK_ART_WRITE_LOCK.
fn alloc_task_id() -> Option<TaskId> {
    let mut found_id: Option<TaskId> = None;
    SCHED_TASK_ART.for_each(|key, val| {
        if found_id.is_some() {
            return;
        }
        if key == 0 {
            return;
        }
        let t = unsafe { &*(val as *const Task) };
        if !t.active && t.exited && t.reaped {
            found_id = Some(key as TaskId);
        }
    });
    if let Some(id) = found_id {
        return Some(id);
    }
    let id = NEXT_TASK_ID.load(Ordering::Relaxed);
    if id as usize >= RadixTable::capacity() {
        return None;
    }
    let ptr = alloc_task_entry()?;
    SCHED_TASK_ART.insert(id as u64, ptr as usize);
    if !TASK_TABLE.ensure_l1(id) {
        return None;
    }
    TASK_TABLE.set(id, ptr as *mut u8);
    NEXT_TASK_ID.store(id + 1, Ordering::Relaxed);
    Some(id)
}

/// Create a kernel-mode thread. Must hold THREAD_ART_WRITE_LOCK.
fn create_thread(entry: fn() -> !, priority: u8, quantum: u32) -> Option<ThreadId> {
    let id = alloc_thread_id()?;

    let stack_page = crate::mm::phys::alloc_pages(KSTACK_ORDER)?;
    let stack_base = stack_page.as_usize();
    let stack_top = stack_base + kstack_size();

    // Create a fake exception frame at the top of the stack.
    // When we "return" from the IRQ handler with this thread's SP,
    // restore_regs will load these values and eret/sret to the entry point.
    let frame_sp = stack_top - EXCEPTION_FRAME_SIZE;
    let frame = frame_sp as *mut u64;
    unsafe {
        // Zero the entire frame.
        for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
            *frame.add(i) = 0;
        }

        crate::arch::trapframe::init_kernel_frame(frame, entry as *const () as usize, stack_top);
    }

    // Clear killed/affinity flags from any previous occupant of this slot.
    let thread = unsafe { thread_mut_from_ref(id) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: on_cpu = ON_CPU_PENDING for any thread about to enter Ready.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = id;
    thread.state = ThreadState::Ready;
    thread.task_id = 0;
    thread.base_priority = priority;
    thread.effective_priority = priority;
    thread.prio.store(priority, Ordering::Relaxed);
    thread.quantum = quantum;
    thread.default_quantum = quantum;
    thread.saved_sp = frame_sp as u64;
    thread.stack_base = stack_base;
    thread.sig_mask = 0;
    thread.sig_pending = 0;

    percpu_enqueue(smp::cpu_id(), priority, id);
    Some(id)
}

/// Parent task info snapshot, taken under SPAWN_LOCK so that the heavy
/// work phase (ELF loading, page table setup) can run without holding it.
struct SpawnParentInfo {
    parent_task: u32,
    sid: TaskId,
    ctty_port: u64,
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    groups_inline: [u32; GROUPS_INLINE],
    groups_overflow: usize,
    ngroups: u32,
    rlimits: [Rlimit; RLIMIT_COUNT],
}

/// Phase 2: do all heavy work (page tables, address space, ELF load, stack,
/// kstack, frame setup, capability grants) WITHOUT holding SPAWN_LOCK.
/// Returns (aspace_id, pt_root, frame_sp, kstack_base, task_port, thread_port) on success.
fn do_spawn_heavy_work(
    task_id: u32,
    thread_id: ThreadId,
    parent: &SpawnParentInfo,
    elf_data: &[u8],
    _priority: u8,
    _quantum: u32,
    arg0: u64,
    arg0_is_port: bool,
    mmio_cap_region: Option<u32>,
) -> Option<(u64, usize, u64, usize, u64, u64)> {
    // Create kernel-held ports for this task and its initial thread.
    let task_port = crate::ipc::port::create_kernel_port(task_port_handler, task_id as usize)?;
    let thread_port =
        crate::ipc::port::create_kernel_port(thread_port_handler, thread_id as usize)?;
    // Create a page table with kernel identity mapping.
    let pt_root = crate::mm::hat::create_user_page_table()?;

    // Create address space.
    let aspace_id = crate::mm::aspace::create(pt_root)?;

    // Bootstrap capabilities: grant SEND caps for well-known kernel ports,
    // and full cap for arg0 if it's a valid active port (port passing on spawn).
    {
        // Initialize this task's embedded capspace.
        {
            let tptr = TASK_TABLE.get(task_id) as *mut Task;
            unsafe {
                (*tptr).capspace = crate::cap::CapSpace::new(task_id);
            }
        }
        // Grant SEND cap for initramfs port (well-known kernel service).
        // No namesrv port grant needed — service registry is a syscall now.
        let iramfs =
            crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            crate::cap::grant_send_cap(task_id, iramfs);
        }

        if arg0_is_port {
            crate::cap::grant_full_port_cap(task_id, arg0);
        }

        // Grant parent: SEND|RECV|MANAGE on child task port, SEND|MANAGE on child thread port.
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let sm = Rights::SEND.union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent.parent_task, task_port, srm);
        crate::cap::grant_port_cap(parent.parent_task, thread_port, sm);
        // Grant child: SEND on own task port, SEND|RECV|MANAGE on own thread port.
        crate::cap::grant_send_cap(task_id, task_port);
        crate::cap::grant_port_cap(task_id, thread_port, srm);
    }

    // If the caller requested an MMIO cap, grant it now — the resulting
    // slot is OR'd into arg0's low 16 bits so the child can call
    // `sys_mmio_map_cap(slot)` as its first MMIO operation. The caller
    // keeps the upper bits of arg0 (e.g. irq<<48) free.
    let arg0 = match mmio_cap_region {
        Some(region_id) => {
            use crate::cap::capability::Rights;
            let rw = Rights::READ.union(Rights::WRITE);
            let slot = crate::cap::grant_mmio_cap(task_id, region_id, rw)?;
            debug_assert!(slot < 0x10000, "mmio cap slot doesn't fit in 16 bits");
            (arg0 & !0xFFFFu64) | (slot as u64 & 0xFFFF)
        }
        None => arg0,
    };

    // Load ELF segments into the address space.
    let elf_info = match crate::loader::elf::load_elf(elf_data, aspace_id, pt_root) {
        Ok(e) => e,
        Err(_) => return None,
    };
    let entry = elf_info.entry;

    // Flush instruction cache.
    crate::arch::cpu::flush_icache();

    // Map user stack.
    const USER_STACK_TOP: usize = crate::arch::trapframe::USER_STACK_TOP;

    let ps = page::page_size();
    let stack_alloc_pages = 8;
    let stack_mmu_pages = stack_alloc_pages * page::page_mmucount();
    let stack_va = USER_STACK_TOP - stack_alloc_pages * ps;

    let obj_id = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        let vma = aspace
            .map_anon(stack_va, stack_mmu_pages, crate::mm::vma::VmaProt::ReadWrite)
            .ok_or(())?;
        Ok::<_, ()>(vma.object_id)
    })
    .ok()?;

    // Eagerly allocate and map stack pages.
    let mmu_count = page::page_mmucount();
    for page_idx in 0..stack_alloc_pages {
        let page_va = stack_va + page_idx * ps;

        let pa = crate::mm::object::with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        })?;
        let pa_usize = pa.as_usize();

        unsafe {
            core::ptr::write_bytes(pa_usize as *mut u8, 0, ps);
        }

        let sw_z = crate::mm::fault::sw_zeroed_bit();
        let pte_flags = crate::mm::hat::USER_RW_FLAGS | sw_z;

        for mmu_idx in 0..mmu_count {
            let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
            let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;

            crate::mm::hat::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
        }
    }

    // Allocate kernel stack for this thread.
    let kstack_page = crate::mm::phys::alloc_pages(KSTACK_ORDER)?;
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + kstack_size();

    // Build a fake exception frame for user-mode entry.
    let frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    let frame = frame_sp as *mut u64;
    unsafe {
        for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
            *frame.add(i) = 0;
        }

        crate::arch::trapframe::init_user_frame(frame, entry as usize, USER_STACK_TOP, &[arg0]);
    }

    Some((
        aspace_id,
        pt_root,
        frame_sp as u64,
        kstack_base,
        task_port,
        thread_port,
    ))
}

/// Phase 1 of user thread creation: allocate task/thread IDs and read parent info.
/// Must hold both TASK_ART_WRITE_LOCK and THREAD_ART_WRITE_LOCK.
fn alloc_spawn_ids() -> Option<(u32, ThreadId, SpawnParentInfo)> {
    let task_id = alloc_task_id()?;
    let thread_id = alloc_thread_id()?;
    let caller_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let parent_task = thread_ref(caller_tid).task_id;
    let ptask = task_ref(parent_task);
    let info = SpawnParentInfo {
        parent_task,
        sid: ptask.sid,
        ctty_port: ptask.ctty_port,
        uid: ptask.uid,
        euid: ptask.euid,
        gid: ptask.gid,
        egid: ptask.egid,
        groups_inline: ptask.groups_inline,
        groups_overflow: ptask.groups_overflow,
        ngroups: ptask.ngroups,
        rlimits: ptask.rlimits,
    };
    Some((task_id, thread_id, info))
}

/// Phase 3 of user thread creation: populate task/thread state and add to run queue.
fn finalize_spawn(
    task_id: u32,
    thread_id: ThreadId,
    parent: &SpawnParentInfo,
    aspace_id: u64,
    pt_root: usize,
    priority: u8,
    quantum: u32,
    frame_sp: u64,
    kstack_base: usize,
    task_port: u64,
    thread_port: u64,
) {
    // Initialize task fields for a newly spawned process.
    // NOTE: do NOT use `*task = Task::empty()` here — do_spawn_heavy_work() has
    // already set up capset/capspace/cur_ports before this function runs.
    // Only reset fields that could be stale from a reused task slot.
    let task = unsafe { task_mut_from_ref(task_id) };
    task.id = task_id;
    task.active = true;
    task.port_id = task_port;
    task.aspace_id = aspace_id;
    task.page_table_root = pt_root;
    task.exit_code = 0;
    task.exited = false;
    task.reaped = false;
    task.wait_status = 0;
    task.thread_count = 1;
    task.parent_task = parent.parent_task;
    task.pgid = task_id;
    task.sid = parent.sid;
    task.ctty_port = parent.ctty_port;
    task.fg_pgid = 0;
    task.uid = parent.uid;
    task.euid = parent.euid;
    task.gid = parent.gid;
    task.egid = parent.egid;
    task.groups_inline = parent.groups_inline;
    task.groups_overflow = parent.groups_overflow;
    task.ngroups = parent.ngroups;
    task.rlimits = parent.rlimits;
    // Reset fields that finalize_spawn doesn't set but could be stale from slot reuse.
    task.max_ports = 128;
    task.max_threads = 32;
    task.max_pages = 512;
    task.sa_enabled = false;
    task.sig_actions = [const { super::task::SignalAction::default() }; super::task::MAX_SIGNALS];
    task.alarm_deadline_ns = 0;
    task.alarm_interval_ns = 0;
    task.sa_pending.store(false, core::sync::atomic::Ordering::Relaxed);
    task.sa_event.store(0, core::sync::atomic::Ordering::Relaxed);
    task.sa_waiter.store(u32::MAX, core::sync::atomic::Ordering::Relaxed);
    // Spawned processes always start with native personality (not inherited).
    // Fork inherits personality; spawn does not.
    task.personality = super::task::PersonalityId::TelixNative;
    task.syscall_abi = super::task::SyscallAbi::TelixNative;
    task.personality_port = 0;

    let thread = unsafe { thread_mut_from_ref(thread_id) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: a freshly-spawned thread enters Ready, so on_cpu must be
    // ON_CPU_PENDING (overrides any stale value from a recycled tid).
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = thread_id;
    thread.state = ThreadState::Ready;
    thread.task_id = task_id;
    thread.port_id = thread_port;
    thread.base_priority = priority;
    thread.effective_priority = priority;
    thread.prio.store(priority, Ordering::Relaxed);
    thread.thread_task.store(task_id, Ordering::Relaxed);
    thread.quantum = quantum;
    thread.default_quantum = quantum;
    thread.saved_sp = frame_sp;
    thread.stack_base = kstack_base;
    thread.sig_mask = 0;
    thread.sig_pending = 0;

    let ts = crate::sync::turnstile::alloc_thread_turnstile();
    thread.turnstile.store(ts, Ordering::Relaxed);

    percpu_enqueue(smp::cpu_id(), priority, thread_id);
}

/// Create a new thread in an existing task. Thread ID and port are pre-allocated.
fn create_thread_in_task(
    task_id: u32,
    id: ThreadId,
    entry: u64,
    stack_top: u64,
    arg: u64,
    priority: u8,
    quantum: u32,
    thread_port: u64,
) -> Option<ThreadId> {
    if !task_ref(task_id).active {
        return None;
    }

    let kstack_page = crate::mm::phys::alloc_pages(KSTACK_ORDER)?;
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + kstack_size();

    let frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    let frame = frame_sp as *mut u64;
    unsafe {
        for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
            *frame.add(i) = 0;
        }

        crate::arch::trapframe::init_user_frame(frame, entry as usize, stack_top as usize, &[arg]);
    }

    let thread = unsafe { thread_mut_from_ref(id) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: thread enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);

    thread.id = id;
    thread.state = ThreadState::Ready;
    thread.task_id = task_id;
    thread.port_id = thread_port;
    thread.base_priority = priority;
    thread.effective_priority = priority;
    thread.prio.store(priority, Ordering::Relaxed);
    thread.thread_task.store(task_id, Ordering::Relaxed);
    thread.quantum = quantum;
    thread.default_quantum = quantum;
    thread.saved_sp = frame_sp as u64;
    thread.stack_base = kstack_base;
    thread.exit_code = 0;
    thread.sig_mask = 0;
    thread.sig_pending = 0;

    let ts = crate::sync::turnstile::alloc_thread_turnstile();
    thread.turnstile.store(ts, Ordering::Relaxed);

    unsafe { task_mut_from_ref(task_id) }.thread_count += 1;
    percpu_enqueue(smp::cpu_id(), priority, id);
    Some(id)
}

/// Get a mutable reference to a thread via its radix pointer.
/// # Safety: Caller must ensure exclusive access (thread is owned by current CPU,
/// or is Blocked/Dead and not accessible from any other path).
#[inline]
pub(crate) unsafe fn thread_mut_from_ref(tid: ThreadId) -> &'static mut Thread {
    let p = THREAD_TABLE.get(tid) as *mut Thread;
    unsafe { &mut *p }
}

/// # Safety: Caller must ensure exclusive access to the mutated fields
/// (e.g., current task's sig_actions, written only by owning task).
#[inline]
pub(crate) unsafe fn task_mut_from_ref(id: TaskId) -> &'static mut Task {
    let p = TASK_TABLE.get(id) as *mut Task;
    unsafe { &mut *p }
}

/// Pick next thread from the current CPU's per-CPU run queue.
/// Returns idle_id if nothing is ready.
fn percpu_pick_next(cpu: u32, idle_id: ThreadId) -> ThreadId {
    let mut rq = percpu_rq()[cpu as usize].lock();
    // Class-aware dispatch: RT → EEVDF → legacy.
    if let Some(tid) = rq.class_pick_next() {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 3); // 3=pick_deq
        return tid;
    }
    drop(rq);
    // Nothing local — try work stealing.
    if let Some(tid) = try_steal(cpu) {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 12); // 12=steal_deq
        return tid;
    }
    idle_id
}

/// Pick next thread, preferring a cosched group mate on the current CPU.
/// Coscheduling only applies to RT-class threads in the bitmap queues.
fn percpu_pick_next_cosched(cpu: u32, idle_id: ThreadId, prev_group: u32) -> (ThreadId, bool) {
    let mut rq = percpu_rq()[cpu as usize].lock();
    if prev_group != 0 && rq.cosched_burst < MAX_COSCHED_BURST {
        if let Some(tid) = rq.pop_for_group(prev_group) {
            thread_ref(tid).in_queue.store(false, Ordering::Release);
            dequeue_set_pending(tid);
            trace_sched(tid, 3); // 3=pick_deq
            rq.cosched_burst += 1;
            COSCHED_HITS.fetch_add(1, Ordering::Relaxed);
            return (tid, true);
        }
    }
    rq.cosched_burst = 0;
    // Class-aware dispatch: RT → EEVDF → legacy.
    if let Some(tid) = rq.class_pick_next() {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 3); // 3=pick_deq
        return (tid, false);
    }
    drop(rq);
    // Nothing local — try work stealing.
    if let Some(tid) = try_steal(cpu) {
        thread_ref(tid).in_queue.store(false, Ordering::Release);
        dequeue_set_pending(tid);
        trace_sched(tid, 12); // 12=steal_deq
        return (tid, false);
    }
    (idle_id, false)
}

/// Spawn write lock: serializes all spawn/fork/thread-create operations.
/// This is the only remaining global lock for the scheduler subsystem.
static SPAWN_LOCK: SpinLock<()> = SpinLock::new(());

pub fn init() {
    sched_init();
    let idle_id = 0; // Thread 0 = BSP idle

    smp::init_bsp(idle_id);
    super::hotplug::mark_online(0);
    crate::println!("  Scheduler initialized (BSP = CPU 0)");
}

/// Called by secondary CPUs to create their idle thread and register.
pub fn init_ap(cpu: u32) {
    let idle_id = {
        let _lock = SPAWN_LOCK.lock();
        create_idle_thread().expect("AP idle thread")
    };
    smp::init_ap(cpu, idle_id);
    super::hotplug::mark_online(cpu);
    crate::println!("  CPU {} scheduler ready (idle thread {})", cpu, idle_id);
}

/// Get the task ID for a given thread (lock-free).
pub fn thread_task_id(tid: ThreadId) -> u32 {
    thread_ref(tid).task_id
}

pub fn spawn(entry: fn() -> !, priority: u8, quantum: u32) -> Option<ThreadId> {
    let _lock = SPAWN_LOCK.lock();
    create_thread(entry, priority, quantum)
}

/// Spawn a new user-mode process from an ELF binary in the initramfs.
/// Creates a new task with its own address space. `arg0` is passed to main().
///
/// Duplicate the parent's groups overflow page for a child task.
/// Must be called outside SCHEDULER lock (allocates a physical page).
/// On success, `parent.groups_overflow` is updated to the child's copy.
/// On failure (OOM), returns false.
fn dup_groups_overflow(parent: &mut SpawnParentInfo) -> bool {
    if parent.ngroups as usize <= GROUPS_INLINE || parent.groups_overflow == 0 {
        return true; // nothing to duplicate
    }
    let page = match crate::mm::phys::alloc_page() {
        Some(p) => p,
        None => return false,
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent.groups_overflow as *const u8,
            page.as_usize() as *mut u8,
            parent.ngroups as usize * core::mem::size_of::<u32>(),
        );
    }
    parent.groups_overflow = page.as_usize();
    true
}

/// Uses a 3-phase lock split: phase 1 (alloc IDs) and phase 3 (finalize)
/// hold SCHEDULER, but phase 2 (ELF loading, page table setup) runs without it.
pub fn spawn_user(elf_name: &[u8], priority: u8, quantum: u32, arg0: u64) -> Option<ThreadId> {
    // Check port_is_active BEFORE locking SCHEDULER to avoid ABBA deadlock.
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    // Look up the ELF binary (no locks needed).
    let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

    // Phase 1: allocate IDs under SPAWN_LOCK.
    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock();
        alloc_spawn_ids()?
    };

    // Phase 2: heavy work (page tables, ELF load, etc.) without locks.
    let (aspace_id, pt_root, frame_sp, kstack_base, task_port, thread_port) = do_spawn_heavy_work(
        task_id,
        thread_id,
        &parent,
        elf_data,
        priority,
        quantum,
        arg0,
        arg0_is_port,
        None,
    )?;

    // Duplicate groups overflow page for child.
    if !dup_groups_overflow(&mut parent) {
        return None;
    }

    // Phase 3: finalize task/thread state.
    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Spawn a driver process with a pre-granted `CapType::Memory` cap for
/// an MMIO region. The resulting cap slot is OR'd into `arg0`'s low 16
/// bits — drivers decode it and pass it to `sys_mmio_map_cap`. Upper
/// bits of `arg0_upper` (typically `irq << 48`) are preserved.
pub fn spawn_user_with_mmio_cap(
    elf_name: &[u8],
    priority: u8,
    quantum: u32,
    arg0_upper: u64,
    mmio_region_id: u32,
) -> Option<ThreadId> {
    // Clear the slot bits the child will overwrite with the cap slot.
    let arg0 = arg0_upper & !0xFFFFu64;

    let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock();
        alloc_spawn_ids()?
    };

    let (aspace_id, pt_root, frame_sp, kstack_base, task_port, thread_port) = do_spawn_heavy_work(
        task_id,
        thread_id,
        &parent,
        elf_data,
        priority,
        quantum,
        arg0,
        false,
        Some(mmio_region_id),
    )?;

    if !dup_groups_overflow(&mut parent) {
        return None;
    }

    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Spawn a new user-mode process from ELF data already in kernel memory.
pub fn spawn_user_from_elf(
    elf_data: &[u8],
    priority: u8,
    quantum: u32,
    arg0: u64,
) -> Option<ThreadId> {
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock();
        alloc_spawn_ids()?
    };

    let (aspace_id, pt_root, frame_sp, kstack_base, task_port, thread_port) = do_spawn_heavy_work(
        task_id,
        thread_id,
        &parent,
        elf_data,
        priority,
        quantum,
        arg0,
        arg0_is_port,
        None,
    )?;

    if !dup_groups_overflow(&mut parent) {
        return None;
    }

    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Spawn a user-mode process with data mapped into its address space.
/// Sets arg0, arg1=data_va, arg2=data_len in the child's initial frame.
pub fn spawn_user_with_data(
    elf_name: &[u8],
    priority: u8,
    quantum: u32,
    data: &[u8],
    data_va: usize,
    arg0: u64,
) -> Option<ThreadId> {
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

    let (task_id, thread_id, mut parent) = {
        let _lock = SPAWN_LOCK.lock();
        alloc_spawn_ids()?
    };

    // Phase 2: ELF load + stack setup WITHOUT SCHEDULER lock.
    let (aspace_id, pt_root, frame_sp, kstack_base, task_port, thread_port) = do_spawn_heavy_work(
        task_id,
        thread_id,
        &parent,
        elf_data,
        priority,
        quantum,
        arg0,
        arg0_is_port,
        None,
    )?;

    // Map data pages into the child's address space (still no SCHEDULER lock).
    let ps = page::page_size();
    let data_alloc_pages = (data.len() + ps - 1) / ps;
    let data_mmu_pages = data_alloc_pages * page::page_mmucount();
    if data_alloc_pages > 0 {
        let obj_id = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
            let vma = aspace
                .map_anon(data_va, data_mmu_pages, crate::mm::vma::VmaProt::ReadOnly)
                .ok_or(())?;
            Ok::<_, ()>(vma.object_id)
        })
        .ok()?;

        let mmu_count = page::page_mmucount();
        let sw_z = crate::mm::fault::sw_zeroed_bit();
        let pte_flags = crate::mm::hat::USER_RO_FLAGS | sw_z;

        for page_idx in 0..data_alloc_pages {
            let page_va = data_va + page_idx * ps;
            let pa = crate::mm::object::with_object(obj_id, |obj| {
                obj.ensure_page(page_idx).map(|(pa, _)| pa)
            })?;
            let pa_usize = pa.as_usize();

            unsafe {
                core::ptr::write_bytes(pa_usize as *mut u8, 0, ps);
                let copy_start = page_idx * ps;
                let copy_end = (copy_start + ps).min(data.len());
                if copy_start < data.len() {
                    core::ptr::copy_nonoverlapping(
                        data[copy_start..copy_end].as_ptr(),
                        pa_usize as *mut u8,
                        copy_end - copy_start,
                    );
                }
            }

            for mmu_idx in 0..mmu_count {
                let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
                let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;
                crate::mm::hat::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
            }
        }
    }

    // Set arg1 = data_va, arg2 = data_len in the thread's exception frame.
    let frame = frame_sp as *mut u64;
    unsafe {
        crate::arch::trapframe::set_frame_arg(frame, 1, data_va as u64);
        crate::arch::trapframe::set_frame_arg(frame, 2, data.len() as u64);
    }

    if !dup_groups_overflow(&mut parent) {
        return None;
    }

    // Phase 3: finalize under SCHEDULER lock.
    finalize_spawn(
        task_id,
        thread_id,
        &parent,
        aspace_id,
        pt_root,
        priority,
        quantum,
        frame_sp,
        kstack_base,
        task_port,
        thread_port,
    );
    Some(thread_id)
}

/// Create a new thread in the caller's task. Returns thread ID or None.
pub fn thread_create(task_id: u32, entry: u64, stack_top: u64, arg: u64) -> Option<ThreadId> {
    let (priority, quantum) = {
        let caller_tid = smp::current().current_thread.load(Ordering::Relaxed);
        let caller = thread_ref(caller_tid);
        (caller.base_priority, caller.default_quantum)
    };
    // Allocate thread ID under SPAWN_LOCK.
    let thread_id = {
        let _lock = SPAWN_LOCK.lock();
        alloc_thread_id()?
    };
    // Create kernel-held port for the new thread.
    let thread_port =
        crate::ipc::port::create_kernel_port(thread_port_handler, thread_id as usize)?;
    // Finalize thread creation.
    let result = create_thread_in_task(
        task_id,
        thread_id,
        entry,
        stack_top,
        arg,
        priority,
        quantum,
        thread_port,
    );
    // Grant caps on the new thread's port.
    if result.is_some() {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(task_id, thread_port, srm);
    }
    result
}

/// Check if a thread has exited and return its exit code.
/// Returns Some(exit_code) if dead and in the same task, None otherwise.
#[allow(dead_code)]
pub fn thread_join_poll(tid: ThreadId, caller_task: u32) -> Option<i32> {
    let t = thread_ref_opt(tid)?;
    if t.task_id != caller_task {
        return None;
    }
    if t.state == ThreadState::Dead {
        Some(t.exit_code)
    } else {
        None
    }
}

/// Blocking thread_join: if target is already dead return its exit code,
/// otherwise register as waiter and block until it exits.
pub fn thread_join_block(tid: ThreadId, caller_task: u32) -> u64 {
    {
        let t_ref = match thread_ref_opt(tid) {
            Some(t) => t,
            None => return u64::MAX,
        };
        if t_ref.task_id != caller_task {
            return u64::MAX;
        }
        if t_ref.state == ThreadState::Dead {
            return t_ref.exit_code as u64;
        }
        // Register ourselves as the join waiter.
        let caller_tid = current_thread_id();
        // Safe: only one joiner per thread, and the target is alive.
        unsafe { thread_mut_from_ref(tid) }.join_waiter = caller_tid;
        // Clear wakeup flag before blocking.
        thread_ref(caller_tid)
            .wakeup
            .store(false, Ordering::Release);
        // Re-check: the target may have exited between the first Dead
        // check and join_waiter registration.  If it raced and didn't see
        // our waiter, we must not block (nobody would wake us).
        if thread_ref(tid).state == ThreadState::Dead {
            unsafe { thread_mut_from_ref(tid) }.join_waiter = u32::MAX;
            return thread_ref(tid).exit_code as u64;
        }
    }
    // Block until the target thread wakes us via exit_current_thread.
    block_current(BlockReason::FutexWait);
    // Re-read exit code (lock-free).
    thread_ref(tid).exit_code as u64
}

/// Get the task ID of the current thread.
#[allow(dead_code)]
pub fn current_task_id() -> TaskId {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid)
        .thread_task
        .load(core::sync::atomic::Ordering::Relaxed)
}

/// Get the page table root of the current thread's task.
#[allow(dead_code)]
pub fn current_page_table_root() -> usize {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    task_ref(task_id).page_table_root
}

/// Called from the timer IRQ handler. Takes the current kernel SP
/// Drain deferred killed-thread cleanup on this CPU.
/// Called at the start of each tick, while running on a live thread's stack.
fn drain_deferred_kills() {
    let cpu = smp::cpu_id() as usize;
    let tid = deferred_kill()[cpu].swap(usize::MAX, Ordering::AcqRel);
    if tid == usize::MAX || tid >= RadixTable::capacity() {
        return;
    }
    let tid = tid as ThreadId;
    let thread = thread_ref(tid);
    let task_id = thread.task_id;

    // Clean up turnstile state.
    crate::sync::turnstile::cleanup_blocked(tid);
    let tptr = THREAD_TABLE.get(tid) as *const super::thread::Thread;
    let ts_addr = unsafe { (*tptr).turnstile.swap(0, Ordering::Relaxed) };
    crate::sync::turnstile::free_thread_turnstile(ts_addr);

    // Destroy the thread's port.
    let thread_port = thread.port_id;
    if thread_port != 0 {
        crate::ipc::port::destroy(thread_port);
    }

    // Check if this was the last thread in its task.
    let task = unsafe { &*(TASK_TABLE.get(task_id) as *const Task) };
    if task.exited {
        // Switch to boot page table before freeing user page tables.
        let pt_root = task.page_table_root;
        if pt_root != 0 {
            let boot_root = crate::mm::hat::boot_page_table_root();
            crate::mm::hat::switch_page_table(boot_root);
        }

        // Free groups overflow.
        let tptr = TASK_TABLE.get(task_id) as *mut Task;
        unsafe {
            (*tptr).free_groups_overflow();
        }

        // Destroy address space.
        let aspace_id = task.aspace_id;
        if aspace_id != 0 {
            crate::mm::aspace::destroy(aspace_id);
        }

        // Restore current thread's page table (we switched to boot PT above).
        if pt_root != 0 {
            let cur_tid = smp::current().current_thread.load(Ordering::Relaxed);
            let cur_task = thread_ref(cur_tid).task_id;
            let cur_root = unsafe { (*(TASK_TABLE.get(cur_task) as *const Task)).page_table_root };
            if cur_root != 0 {
                crate::mm::hat::switch_page_table(cur_root);
            }
        }

        // Auto-reap zombie children.
        let mut zombie_ports = [0u64; 32];
        let mut nz = 0usize;
        SCHED_TASK_ART.for_each(|key, val| {
            if key == 0 {
                return;
            }
            let child = unsafe { &mut *(val as *mut Task) };
            if child.parent_task == task_id && child.exited && !child.reaped {
                child.reaped = true;
                if child.port_id != 0 && nz < 32 {
                    zombie_ports[nz] = child.port_id;
                    child.port_id = 0;
                    nz += 1;
                }
            }
        });
        for i in 0..nz {
            crate::ipc::port::destroy(zombie_ports[i]);
        }
    }
}

/// (pointing to the saved exception frame). Returns the SP to use
/// for restore_regs — either the same SP (no switch) or a different
/// thread's SP (preemption).
/// Interval between ticks in nanoseconds (10ms = 100 Hz equivalent).
const TICK_INTERVAL_NS: u64 = 10_000_000;

/// Handle a reschedule IPI (dedicated vector, no tick processing).
/// Called when a remote CPU enqueues a thread on our run queue while we
/// are idle.  Only runs try_switch() to pick up the newly-enqueued thread.
pub fn reschedule_ipi(current_sp: u64) -> u64 {
    let result = try_switch(current_sp);
    // Reprogram the timer for the (possibly new) running thread.
    let cpu = smp::cpu_id();
    let pcpu = smp::get(cpu);
    let is_idle = pcpu.current_thread.load(core::sync::atomic::Ordering::Relaxed)
        == pcpu.idle_thread_id.load(core::sync::atomic::Ordering::Relaxed);
    let next = compute_next_event(cpu, is_idle);
    crate::arch::timer::program_oneshot_ns(next);
    result
}

pub fn tick(current_sp: u64) -> u64 {
    // Record per-CPU last-tick timestamp + update max-gap.  Diagnostic
    // for wake-latency tail: if a CPU's tick stops firing for seconds,
    // we'd see PER_CPU_TICK_MAX_GAP_NS blow up to match.  Healthy ticks
    // produce gaps near TICK_INTERVAL_NS.
    {
        let cpu = smp::cpu_id() as usize;
        if cpu < smp::MAX_CPUS {
            let now = get_monotonic_ns();
            let prev = PER_CPU_LAST_TICK_NS[cpu].swap(now, Ordering::Relaxed);
            if prev != 0 {
                let gap = now.saturating_sub(prev);
                let mut max = PER_CPU_TICK_MAX_GAP_NS.load(Ordering::Relaxed);
                while gap > max {
                    match PER_CPU_TICK_MAX_GAP_NS.compare_exchange_weak(
                        max, gap, Ordering::Relaxed, Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(seen) => max = seen,
                    }
                }
            }
        }
    }

    check_sleep_timers();
    check_alarm_timers();
    check_interval_timers();

    // Drain deferred killed-thread cleanup from the previous tick.
    drain_deferred_kills();

    // IPC watchdog: on CPU 0, check for stalled IPC every ~5 seconds.
    // If no IPC send/recv has occurred since the last check, dump blocked
    // thread states to help diagnose flaky hangs.
    {
        use core::sync::atomic::AtomicU64;
        static WATCHDOG_TICK: AtomicU64 = AtomicU64::new(0);
        static LAST_IPC_COUNT: AtomicU64 = AtomicU64::new(0);
        static STALL_COUNT: AtomicU64 = AtomicU64::new(0);
        let cpu = smp::cpu_id();
        if cpu == 0 {
            let n = WATCHDOG_TICK.fetch_add(1, Ordering::Relaxed);
            // Check roughly every 5 seconds (tick ≈ 10ms → 500 ticks).
            if n > 0 && n % 500 == 0 {
                let sends = crate::sched::stats::IPC_SENDS.load(Ordering::Relaxed);
                let recvs = crate::sched::stats::IPC_RECVS.load(Ordering::Relaxed);
                let total = sends.wrapping_add(recvs);
                let last = LAST_IPC_COUNT.swap(total, Ordering::Relaxed);
                if total == last {
                    let sc = STALL_COUNT.fetch_add(1, Ordering::Relaxed);
                    if sc < 3 {
                        // First stall detection — dump per-CPU and thread states.
                        // Per-arch IPI counters for validating the tickless-SMP
                        // IPI fix at a glance.  Both aarch64 SGIs and riscv64
                        // S-mode software IRQs share this column.
                        #[cfg(target_arch = "aarch64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::aarch64::irq::SGI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::aarch64::irq::SGI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(target_arch = "riscv64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::riscv64::trap::SGI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::riscv64::trap::SGI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(target_arch = "loongarch64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::loongarch64::trap::SGI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::loongarch64::trap::SGI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(target_arch = "x86_64")]
                        let (sgi_s, sgi_r) = (
                            crate::arch::x86_64::lapic::IPI_SEND_COUNT
                                .load(Ordering::Relaxed),
                            crate::arch::x86_64::lapic::IPI_RECV_COUNT
                                .load(Ordering::Relaxed),
                        );
                        #[cfg(not(any(
                            target_arch = "x86_64",
                            target_arch = "aarch64",
                            target_arch = "riscv64",
                            target_arch = "loongarch64",
                        )))]
                        let (sgi_s, sgi_r): (u64, u64) = (0, 0);
                        let wake_count = SLEEP_WAKE_LATENCY_COUNT.load(Ordering::Relaxed);
                        let wake_total = SLEEP_WAKE_LATENCY_NS_TOTAL.load(Ordering::Relaxed);
                        let wake_max = SLEEP_WAKE_LATENCY_NS_MAX.load(Ordering::Relaxed);
                        let wake_avg_us = if wake_count > 0 {
                            (wake_total / 1000) / wake_count
                        } else {
                            0
                        };
                        let wake_max_us = wake_max / 1000;
                        let b0 = SLEEP_WAKE_LATENCY_BUCKETS[0].load(Ordering::Relaxed);
                        let b1 = SLEEP_WAKE_LATENCY_BUCKETS[1].load(Ordering::Relaxed);
                        let b2 = SLEEP_WAKE_LATENCY_BUCKETS[2].load(Ordering::Relaxed);
                        let b3 = SLEEP_WAKE_LATENCY_BUCKETS[3].load(Ordering::Relaxed);
                        let b4 = SLEEP_WAKE_LATENCY_BUCKETS[4].load(Ordering::Relaxed);
                        let b5 = SLEEP_WAKE_LATENCY_BUCKETS[5].load(Ordering::Relaxed);
                        let b6 = SLEEP_WAKE_LATENCY_BUCKETS[6].load(Ordering::Relaxed);
                        let tick_max_gap_us = PER_CPU_TICK_MAX_GAP_NS.load(Ordering::Relaxed) / 1000;
                        let stale_retarget = STALE_TARGET_RETARGET_COUNT.load(Ordering::Relaxed);
                        let steal_us = crate::arch::hypervisor::ops()
                            .steal_time_ns()
                            .map(|ns| ns / 1000)
                            .unwrap_or(u64::MAX);
                        crate::println!("WATCHDOG: IPC stall detected (sends={} recvs={}) double_enq: drain={} rescue={} wake={} other={} total_enq={} rescue=(max={} stale={} pend={} phantom={}) sgi=(s={} r={}) forced_preempt={} wake_lat=(n={} avg_us={} max_us={}) wake_hist=(<100us:{} <1ms:{} <10ms:{} <100ms:{} <1s:{} <10s:{} >=10s:{}) tick_max_gap_us={} stale_retarget={} bsp_steal_us={} hv={:?}",
                            sends, recvs,
                            DOUBLE_ENQ_DRAIN.load(Ordering::Relaxed),
                            DOUBLE_ENQ_RESCUE.load(Ordering::Relaxed),
                            DOUBLE_ENQ_WAKE.load(Ordering::Relaxed),
                            DOUBLE_ENQ_OTHER.load(Ordering::Relaxed),
                            ENQ_TOTAL.load(Ordering::Relaxed),
                            RESCUE_MAX.load(Ordering::Relaxed),
                            RESCUE_STALE_ON_CPU.load(Ordering::Relaxed),
                            RESCUE_PENDING.load(Ordering::Relaxed),
                            RESCUE_PHANTOM.load(Ordering::Relaxed),
                            sgi_s, sgi_r,
                            FORCED_PREEMPT_COUNT.load(Ordering::Relaxed),
                            wake_count, wake_avg_us, wake_max_us,
                            b0, b1, b2, b3, b4, b5, b6,
                            tick_max_gap_us, stale_retarget,
                            steal_us, crate::arch::hypervisor::kind());
                        // Per-CPU state: what each CPU is running, RQ sizes
                        let ncpus = smp::num_cpus();
                        for c in 0..ncpus {
                            let pc = smp::get(c as u32);
                            let cur = pc.current_thread.load(Ordering::Relaxed);
                            let idle = pc.idle_thread_id.load(Ordering::Relaxed);
                            let rq = percpu_rq()[c].lock();
                            let rq_len = rq.eevdf_nr_running;
                            let has_rdy = rq.has_ready();
                            drop(rq);
                            let is_idle = cur == idle;
                            let def_v = deferred_requeue()[c].load(Ordering::Relaxed);
                            let def_tid = if def_v != 0 { (def_v & 0xFFFFFFFF) as u32 } else { 0 };
                            let cur_task = thread_ref(cur as u32).task_id;
                            let cur_blk = unsafe { &*(THREAD_TABLE.get(cur as u32) as *const Thread) }.blocked_on;
                            let rescue_stuck = pc.rescue_stuck_pending_count.load(Ordering::Relaxed);
                            let hist = lat_snapshot(pc);
                            let n: u64 = hist.iter().sum();
                            let p50 = lat_percentile_ns(&hist, 5000);
                            let p90 = lat_percentile_ns(&hist, 9000);
                            let p99 = lat_percentile_ns(&hist, 9900);
                            let p999 = lat_percentile_ns(&hist, 9990);
                            crate::println!("  cpu{}: cur=tid{} task={} idle={} rq_eevdf={} has_ready={} def={} blk={:?} rescue_stuck={} lat_ns(n={} p50={} p90={} p99={} p999={})",
                                c, cur, cur_task, is_idle, rq_len, has_rdy, def_tid, cur_blk, rescue_stuck,
                                n, p50, p90, p99, p999);
                        }
                        let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(200);
                        for tid in 1..max_tid {
                            let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
                            if t.task_id != 0 && t.state != ThreadState::Dead {
                                let park = t.park_state.load(Ordering::Relaxed);
                                let wakeup = t.wakeup.load(Ordering::Relaxed);
                                let on_cpu = t.on_cpu.load(Ordering::Relaxed);
                                let in_q = t.in_queue.load(Ordering::Relaxed);
                                let last_cpu = t.last_cpu.load(Ordering::Relaxed);
                                let prio = t.prio.load(Ordering::Relaxed);
                                // Show on_cpu/in_q for all non-Running threads so
                                // stale-on-cpu orphans are visible in the dump.
                                if t.state == ThreadState::Running {
                                    continue;
                                }
                                crate::println!(
                                    "  tid={} {:?} {:?} park={} wake={} prio={} on_cpu={} in_q={} last_cpu={} task={}",
                                    tid, t.state, t.blocked_on, park, wakeup, prio, on_cpu, in_q, last_cpu, t.task_id);
                            }
                        }
                        // Top-N rescued tids: which tids dominate the rescue
                        // storm?  When pend / stale_on_cpu / max counts are
                        // huge but spread across many tids, the bug is
                        // structural; when they pile on a single tid, the
                        // bug is in that tid's wakeup path.  Print the top
                        // 5 by rescue count.
                        let mut top_idx = [0usize; 5];
                        let mut top_cnt = [0u64; 5];
                        for i in 1..PER_TID_RESCUE_CAP {
                            let c = RESCUE_PER_TID[i].load(Ordering::Relaxed);
                            if c == 0 { continue; }
                            // Insert into descending top-5.
                            let mut j = 5;
                            while j > 0 && c > top_cnt[j - 1] { j -= 1; }
                            if j < 5 {
                                let mut k = 4;
                                while k > j { top_cnt[k] = top_cnt[k - 1]; top_idx[k] = top_idx[k - 1]; k -= 1; }
                                top_cnt[j] = c;
                                top_idx[j] = i;
                            }
                        }
                        if top_cnt[0] > 0 {
                            crate::println!(
                                "  rescue top: tid{}={} tid{}={} tid{}={} tid{}={} tid{}={}",
                                top_idx[0], top_cnt[0],
                                top_idx[1], top_cnt[1],
                                top_idx[2], top_cnt[2],
                                top_idx[3], top_cnt[3],
                                top_idx[4], top_cnt[4]);
                        }

                        // Phase-5b stall instrumentation (aarch64-only).
                        #[cfg(target_arch = "aarch64")]
                        {
                            let now = get_monotonic_ns();
                            let ncpus_a = smp::num_cpus().min(16);
                            for c in 0..ncpus_a {
                                let send_ts = crate::arch::aarch64::irq::PER_CPU_IPI_SEND_TS_NS[c]
                                    .load(Ordering::Relaxed);
                                let recv_ts = crate::arch::aarch64::irq::PER_CPU_IPI_RECV_TS_NS[c]
                                    .load(Ordering::Relaxed);
                                let send_n  = crate::arch::aarch64::irq::PER_CPU_IPI_SEND_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let recv_n  = crate::arch::aarch64::irq::PER_CPU_IPI_RECV_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let ex_n    = crate::arch::aarch64::irq::PER_CPU_EXCEPTION_ENTRY_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let cps_n   = crate::arch::aarch64::irq::PER_CPU_CLEAR_SWITCH_COUNT[c]
                                    .load(Ordering::Relaxed);
                                let send_age_us = if send_ts != 0 { (now.saturating_sub(send_ts)) / 1000 } else { 0 };
                                let recv_age_us = if recv_ts != 0 { (now.saturating_sub(recv_ts)) / 1000 } else { 0 };
                                let lat_us = if recv_ts >= send_ts && send_ts != 0 {
                                    (recv_ts - send_ts) / 1000
                                } else {
                                    u64::MAX
                                };
                                crate::println!(
                                    "  AA64-IPI cpu{}: send=(n={} age_us={}) recv=(n={} age_us={}) lat_us={} ex_n={} cps_n={} pkpend={} parked_tid={}",
                                    c, send_n, send_age_us, recv_n, recv_age_us, lat_us,
                                    ex_n, cps_n,
                                    park_switch_pending()[c].load(Ordering::Relaxed),
                                    parked_tid()[c].load(Ordering::Relaxed),
                                );
                            }
                            // Recent wake_parked_thread outcomes (top-N slots
                            // with non-zero tid).  Path codes:
                            // 1=early, 2=fast-enq, 3=lost-cps, 4=def-local,
                            // 5=def-ipi, 6=dup, 7=neither-cas-noop.
                            let mut printed = 0u32;
                            for i in 0..WAKE_TRACE_RING {
                                let t = WAKE_TRACE_TID[i].load(Ordering::Relaxed);
                                if t == 0 { continue; }
                                let v = WAKE_TRACE_OUTCOME[i].load(Ordering::Relaxed);
                                let ts = WAKE_TRACE_TS_NS[i].load(Ordering::Relaxed);
                                let path = v & 0xF;
                                let waker_cpu = (v >> 4) & 0xF;
                                let park_cpu = (v >> 8) & 0xFF;
                                let age_us = if ts != 0 { now.saturating_sub(ts) / 1000 } else { 0 };
                                crate::println!(
                                    "  AA64-WAKE tid={} path={} waker_cpu={} park_cpu={} age_us={}",
                                    t, path, waker_cpu, park_cpu, age_us
                                );
                                printed += 1;
                                if printed >= 16 { break; }
                            }
                            // Per-thread stack_switch_pending for blocked threads.
                            let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(64);
                            for tid in 1..max_tid {
                                let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
                                if t.task_id == 0 || t.state == ThreadState::Dead { continue; }
                                let park = t.park_state.load(Ordering::Relaxed);
                                let ssp = t.stack_switch_pending.load(Ordering::Relaxed);
                                if park != 0 || ssp {
                                    crate::println!(
                                        "  AA64-PARK tid={} park_state={} stack_switch_pending={} state={:?} blocked_on={:?} on_cpu={} last_cpu={}",
                                        tid, park, ssp, t.state, t.blocked_on,
                                        t.on_cpu.load(Ordering::Relaxed),
                                        t.last_cpu.load(Ordering::Relaxed),
                                    );
                                }
                            }
                        }
                    }
                    // On every stall tick, attempt to rescue orphaned threads.
                    // TOCTOU false positives are harmless: DOUBLE-ENQ handler
                    // detects and skips redundant enqueues.
                    // Also rescue CallReply-blocked threads (rescue_parked=true)
                    // since IPC is confirmed stalled.
                    // IPC is confirmed stalled for 5+ seconds — force-drain
                    // ALL remote deferred slots.  The assembly switch window
                    // is <1µs; 5s of confirmed stall means it completed eons
                    // ago.  Also send IPIs to kick timer-dead CPUs.
                    {
                        let ncpus_w = smp::num_cpus();
                        for cw in 0..ncpus_w.min(16) {
                            drain_deferred_requeue(cw as u32);
                            if cw as u32 != cpu {
                                crate::arch::irq::send_reschedule_ipi(cw as u32);
                            }
                        }
                    }
                    rescue_orphaned_threads_impl(true);
                } else {
                    STALL_COUNT.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    // Periodic orphan rescue: every 10 ticks (~100ms), scan for Ready
    // threads stuck outside all queues.  Runs on CPU 0 only.
    // Must not run too frequently — running every 2 ticks causes false-
    // positive rescues by catching threads in the transient window
    // between state=Ready and percpu_enqueue in check_sleep_timers
    // (cross-CPU race).  10 ticks gives all CPUs time to drain deferred
    // slots and complete enqueues.
    {
        static RESCUE_COUNTER: AtomicU64 = AtomicU64::new(0);
        static RESCUE_LOCK: AtomicU32 = AtomicU32::new(0);
        let rt = RESCUE_COUNTER.fetch_add(1, Ordering::Relaxed);
        // All CPUs contribute; fire every ~40 ticks with 4 CPUs (~100ms).
        if rt > 0 && rt % 40 == 0 {
            if RESCUE_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                rescue_orphaned_threads_impl(false);
                RESCUE_LOCK.store(0, Ordering::Release);
            }
        }
    }

    // Heartbeat: every ~250ms, a live CPU sends reschedule IPIs and
    // drains stale remote deferred-requeue slots.  All CPUs contribute
    // to a global tick counter; every 100 increments (~250ms with 4
    // CPUs at 10ms ticks), one CPU CAS-wins the HEARTBEAT_LOCK and
    // performs the work.  This survives any single CPU being timer-dead.
    //
    // Stale-slot age: DEFERRED_STALE[c] counts consecutive heartbeat
    // rounds with CPU c's slot non-zero.  Age >=1 means occupied for
    // >=250ms — safe to drain (switch window is <1µs).
    {
        static DEFERRED_STALE: [AtomicU32; 16] = {
            const Z: AtomicU32 = AtomicU32::new(0);
            [Z; 16]
        };
        static HEARTBEAT_COUNTER: AtomicU64 = AtomicU64::new(0);
        static HEARTBEAT_LOCK: AtomicU32 = AtomicU32::new(0);
        let hb = HEARTBEAT_COUNTER.fetch_add(1, Ordering::Relaxed);
        if hb > 0 && hb % 100 == 0 {
            if HEARTBEAT_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                let cpu = smp::cpu_id();
                let ncpus = smp::num_cpus();
                for c in 0..ncpus.min(16) {
                    if c as u32 != cpu {
                        crate::arch::irq::send_reschedule_ipi(c as u32);
                    }
                    let slot = deferred_requeue()[c].load(Ordering::Relaxed);
                    if slot != 0 {
                        let age = DEFERRED_STALE[c].fetch_add(1, Ordering::Relaxed);
                        if age >= 1 {
                            drain_deferred_requeue(c as u32);
                            DEFERRED_STALE[c].store(0, Ordering::Relaxed);
                        }
                    } else {
                        DEFERRED_STALE[c].store(0, Ordering::Relaxed);
                    }
                }
                HEARTBEAT_LOCK.store(0, Ordering::Release);
            }
        }
    }

    // CallReply timeout: every 50 ticks (~500ms), sweep for call/reply
    // threads stuck longer than CALL_REPLY_TIMEOUT_NS. Unlike the WATCHDOG
    // (which requires zero IPC activity system-wide), this fires
    // unconditionally and uses per-thread timestamps to catch individual
    // stuck calls while other IPC traffic continues.
    {
        static CALL_TIMEOUT_COUNTER: AtomicU64 = AtomicU64::new(0);
        static CALL_TIMEOUT_LOCK: AtomicU32 = AtomicU32::new(0);
        let ct = CALL_TIMEOUT_COUNTER.fetch_add(1, Ordering::Relaxed);
        // All CPUs contribute; fire every ~200 ticks (~500ms with 4 CPUs).
        if ct > 0 && ct % 200 == 0 {
            if CALL_TIMEOUT_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                call_reply_timeout_sweep();
                CALL_TIMEOUT_LOCK.store(0, Ordering::Release);
            }
        }
    }

    let result = try_switch(current_sp);

    // If try_switch performed a context switch, clear need_resched since
    // the switch already satisfied the preemption request.
    let cpu = smp::cpu_id();
    let pcpu = smp::get(cpu);
    if result != current_sp {
        pcpu.need_resched.store(false, Ordering::Relaxed);
    }

    // Compute and program the next timer event (dynamic tick).
    let is_idle = pcpu.current_thread.load(Ordering::Relaxed)
        == pcpu.idle_thread_id.load(Ordering::Relaxed);
    let next = compute_next_event(cpu, is_idle);
    crate::arch::timer::program_oneshot_ns(next);

    result
}

/// Compute the earliest timer event this CPU needs to wake for.
/// Returns an absolute deadline in nanoseconds since boot.
fn compute_next_event(cpu: u32, is_idle: bool) -> u64 {
    let now = get_monotonic_ns();
    let mut earliest = now + MAX_IDLE_NS; // cap: 1 second

    // 1. Quantum deadline: if running a real thread, wake when its quantum expires.
    if !is_idle {
        let tid = smp::get(cpu).current_thread.load(Ordering::Relaxed);
        let q = unsafe { thread_mut_from_ref(tid) }.quantum;
        if q != u32::MAX {
            earliest = earliest.min(now + (q as u64) * TICK_INTERVAL_NS);
        }
    }

    // 2. Sleep queue head (O(1) peek, no lock).
    let head = SLEEP_QUEUE_HEAD.load(Ordering::Acquire);
    if head != u32::MAX {
        let head_deadline = unsafe { thread_mut_from_ref(head) }.sleep_deadline_ns;
        if head_deadline != 0 {
            earliest = earliest.min(head_deadline);
        }
    }

    // 3. Cached alarm deadline.
    let alarm = EARLIEST_ALARM_NS.load(Ordering::Relaxed);
    if alarm != 0 {
        earliest = earliest.min(alarm);
    }

    // 4. Cached interval timer deadline.
    let interval = EARLIEST_INTERVAL_NS.load(Ordering::Relaxed);
    if interval != 0 {
        earliest = earliest.min(interval);
    }

    // 5. Deferred kills need draining within one tick.
    if deferred_kill()[cpu as usize].load(Ordering::Relaxed) != 0 {
        earliest = earliest.min(now + TICK_INTERVAL_NS);
    }

    // 6. When idle, check if a remote CPU enqueued work after try_switch
    //    checked the queue.  Without this, the newly-enqueued thread could
    //    sit in the run queue for up to MAX_IDLE_NS (1 second).
    if is_idle {
        let rq = percpu_rq()[cpu as usize].lock();
        let has_work = rq.has_ready();
        drop(rq);
        if has_work {
            earliest = earliest.min(now + 1_000); // 1 μs — wake ASAP
        }
    }

    // Floor: never less than 1 microsecond from now.
    earliest.max(now + 1_000)
}

/// Attempt to switch threads on the current CPU.
/// Uses only per-CPU run queue locks — does NOT take the global SCHEDULER lock.
fn try_switch(current_sp: u64) -> u64 {
    let cpu = smp::cpu_id();
    drain_deferred_requeue(cpu);
    let pcpu = smp::get(cpu);
    let idle_id_for_load = pcpu.idle_thread_id.load(Ordering::Relaxed);
    let cur_for_load = pcpu.current_thread.load(Ordering::Relaxed);
    super::hotplug::tick_load(cpu, cur_for_load == idle_id_for_load);

    // Drain deferred kernel stack free from a previous exit on this CPU.
    let deferred = deferred_kstack()[cpu as usize].load(Ordering::Acquire);
    if deferred != 0 {
        let cur_tid = pcpu.current_thread.load(Ordering::Relaxed);
        // Safety: cur_tid is Running on this CPU, we own it.
        let cur_stack = thread_ref(cur_tid).stack_base;
        if cur_stack != deferred {
            deferred_kstack()[cpu as usize].store(0, Ordering::Release);
            crate::mm::phys::free_pages(crate::mm::page::PhysAddr::new(deferred), KSTACK_ORDER);
            let dead_tid = deferred_thread()[cpu as usize].swap(usize::MAX, Ordering::AcqRel);
            if dead_tid < RadixTable::capacity() {
                // Safety: dead thread is Dead, not on any queue or CPU.
                let t = unsafe { thread_mut_from_ref(dead_tid as ThreadId) };
                t.stack_base = 0;
            }
        }
    }

    let pcpu = smp::current();
    let prev_id = pcpu.current_thread.load(Ordering::Relaxed);
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Decide if preemption is needed (lockless — we own the running thread).
    if prev_id == idle_id {
        // Idle thread: preempt if local queue has work. Also try stealing
        // from other CPUs (with min_len=1) to pick up threads that were
        // demoted to prio 254 by block_current and are stuck on a busy CPU.
        let rq = percpu_rq()[cpu as usize].lock();
        let has_work = rq.has_ready();
        drop(rq);
        if !has_work {
            match try_steal_for_idle(cpu) {
                Some(tid) => {
                    let prio = thread_ref(tid).prio.load(Ordering::Relaxed);
                    set_enq_tag(5); // 5=steal
                    percpu_enqueue(cpu, prio, tid);
                }
                None => {
                    crate::sync::rcu::rcu_quiescent();
                    return current_sp;
                }
            }
        }
    } else {
        if thread_ref(prev_id).yield_asap.load(Ordering::Acquire) {
            // Will preempt — continue below.
        } else {
            // Lazy preemption: when nothing else is ready on this CPU,
            // there's no one to switch to anyway, so skip the quantum
            // decrement entirely.  Without this, every tick still
            // burned CPU on the saturating_sub + write even when the
            // current thread had no contender — and at low quanta
            // (default_quantum=1 in r28) the per-tick CS rate exceeded
            // TICK_INTERVAL_NS, livelocking the system.  With this
            // check, ticks-with-no-contender are pure no-ops, and
            // quantum is only spent during actual contention.
            let has_contender = {
                let rq = percpu_rq()[cpu as usize].lock();
                let ready = rq.has_ready();
                drop(rq);
                ready
            };
            if has_contender {
                // Safety: prev_id is Running on this CPU, we own it.
                let t = unsafe { thread_mut_from_ref(prev_id) };
                // Advance EEVDF virtual runtime for fair accounting.
                // Preemption is still quantum-based for stability; EEVDF
                // deadlines drive dispatch order (earliest-deadline-first)
                // via class_pick_next.
                if t.sched_class == SCHED_NORMAL && t.effective_priority != 254 {
                    let weight = t.eevdf_weight as u64;
                    t.eevdf_vruntime += VTIME_UNIT / weight;
                }
                t.quantum = t.quantum.saturating_sub(1);
                if t.quantum != 0 {
                    crate::sync::rcu::rcu_quiescent();
                    return current_sp; // No preemption needed.
                }
                t.quantum = t.default_quantum;
            } else {
                // No contender — current thread retains quantum, fall
                // through to RCU quiescence and return without picking
                // a "next" thread.
                crate::sync::rcu::rcu_quiescent();
                return current_sp;
            }
        }
    }

    // Clear yield_asap.
    thread_ref(prev_id)
        .yield_asap
        .store(false, Ordering::Release);

    // Pick next thread from per-CPU queue.
    let prev_group = thread_ref(prev_id).cosched_group.load(Ordering::Relaxed);
    let (next_id, _cosched) = percpu_pick_next_cosched(cpu, idle_id, prev_group);

    if prev_id == next_id {
        // percpu_pick_next_cosched dequeued `prev_id` from the run queue
        // (it was re-enqueued by a concurrent wake/rescue while running).
        // Restore on_cpu from ON_CPU_PENDING back to our CPU number — the
        // thread is still running on this CPU and leaving on_cpu as
        // ON_CPU_PENDING would make the thread invisible to scheduling
        // (a future try_switch would see ON_CPU_PENDING and CAS wrongly,
        // or the thread would appear orphaned).
        if prev_id != idle_id {
            thread_ref(prev_id).on_cpu.store(cpu, Ordering::Release);
            // #135 self-pick PENDING-STUCK-LOW false-positive fix:
            // percpu_pick_next_cosched called dequeue_set_pending which
            // stamped pending_set_ns to "now" and set on_cpu=PENDING.
            // We just restored on_cpu but the stale stamp would survive
            // until the next REAL preemption, then the rescue sweep would
            // compute age_ns from this stale stamp and fire PENDING-STUCK-
            // LOW falsely on a thread that ran continuously between.
            // Mirror what dispatch_cas_ok does on the real dispatch path:
            // clear pending_set_ns and reset PENDING_LOW_LOGGED.
            thread_ref(prev_id).pending_set_ns.store(0, Ordering::Relaxed);
            if (prev_id as usize) < PENDING_LOW_LOGGED.len() {
                PENDING_LOW_LOGGED[prev_id as usize].store(false, Ordering::Relaxed);
            }
            SELF_PICK_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        crate::sync::rcu::rcu_quiescent();
        return current_sp;
    }

    crate::sched::stats::CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
    crate::trace::trace_event(crate::trace::EVT_CTX_SWITCH, prev_id, next_id);

    // Wake-to-dispatch latency: if this thread carries a non-zero
    // wake_pending_ts_ns, this is the first dispatch since wake.
    // Swap-to-0 to avoid double-counting if try_switch picks the same
    // thread again before the next park.  Accumulates total + count
    // for running average, and tracks the running max.
    {
        let pending = thread_ref(next_id)
            .wake_pending_ts_ns
            .swap(0, Ordering::Relaxed);
        if pending != 0 {
            let now = get_monotonic_ns();
            let lat = now.saturating_sub(pending);
            SLEEP_WAKE_LATENCY_NS_TOTAL.fetch_add(lat, Ordering::Relaxed);
            SLEEP_WAKE_LATENCY_COUNT.fetch_add(1, Ordering::Relaxed);
            let mut prev_max = SLEEP_WAKE_LATENCY_NS_MAX.load(Ordering::Relaxed);
            while lat > prev_max {
                match SLEEP_WAKE_LATENCY_NS_MAX.compare_exchange_weak(
                    prev_max,
                    lat,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(seen) => prev_max = seen,
                }
            }
            // Histogram bucket: log10-ish, see SLEEP_WAKE_LATENCY_BUCKETS
            // declaration for the bin definitions.
            let bucket = if lat < 100_000 { 0 }              // <100us
                else if lat < 1_000_000 { 1 }                // <1ms
                else if lat < 10_000_000 { 2 }               // <10ms
                else if lat < 100_000_000 { 3 }              // <100ms
                else if lat < 1_000_000_000 { 4 }            // <1s
                else if lat < 10_000_000_000 { 5 }           // <10s
                else { 6 };                                  // >=10s
            SLEEP_WAKE_LATENCY_BUCKETS[bucket].fetch_add(1, Ordering::Relaxed);
        }
    }

    // Save current thread's SP. Safety: we own the running thread.
    let prev_task;
    {
        let prev_t = unsafe { thread_mut_from_ref(prev_id) };
        prev_t.saved_sp = current_sp;
        prev_t.saved_sp_source = 1; // try_switch
        let mut prev_prio = prev_t.effective_priority;
        prev_task = prev_t.task_id;
        // If the thread was demoted by block_current and has been woken
        // (wakeup flag set), restore its base priority so it gets
        // re-enqueued at the correct level instead of being starved.
        if prev_prio > prev_t.base_priority {
            let current_prio = thread_ref(prev_id).prio.load(Ordering::Acquire);
            if thread_ref(prev_id).wakeup.load(Ordering::Acquire) || current_prio < prev_prio {
                prev_t.effective_priority = prev_t.base_priority;
                thread_ref(prev_id)
                    .prio
                    .store(prev_t.base_priority, Ordering::Release);
                prev_prio = prev_t.base_priority;
            }
        }
        // NEW_INV: while state=Ready, on_cpu MUST be ON_CPU_PENDING. The
        // store to ON_CPU_PENDING is performed BEFORE the slot fill (below)
        // and BEFORE state=Ready, so rescue's stale-on-cpu predicate cannot
        // observe (state=Ready, on_cpu=cpu_real) — that combination is now
        // impossible by construction. drain_deferred_requeue therefore needs
        // no CAS to detect rescue-races; it just enqueues unconditionally.
        // Don't re-enqueue Dead threads (they are exiting).
        if prev_id != idle_id && prev_t.state != ThreadState::Dead {
            // If the thread was killed, mark Dead + defer full cleanup
            // so it doesn't keep getting scheduled.
            if thread_ref(prev_id).killed.load(Ordering::Relaxed) {
                prev_t.state = ThreadState::Dead;
                prev_t.exit_code = -9;
                let waiter = prev_t.join_waiter;
                prev_t.join_waiter = u32::MAX;
                if waiter != u32::MAX {
                    wake_thread(waiter);
                }
                let task_id = prev_t.task_id;
                let task = unsafe { task_mut_from_ref(task_id) };
                task.thread_count -= 1;
                if task.thread_count == 0 {
                    task.exit_code = -9;
                    task.exited = true;
                    task.active = false;
                    task.wait_status = ((-9i32 & 0xFF) << 8) | 9; // killed by signal 9
                    send_signal_to_task(task.parent_task, super::task::SIGCHLD);
                    wake_wait_child_threads(task.parent_task);
                }
                // Queue for deferred resource cleanup on next tick.
                deferred_kill()[cpu as usize].store(prev_id as usize, Ordering::Release);
                // Also defer kstack free.
                let kstack_base = prev_t.stack_base;
                deferred_thread()[cpu as usize].store(prev_id as usize, Ordering::Release);
                deferred_kstack()[cpu as usize].store(kstack_base, Ordering::Release);
            } else {
                // Defer re-enqueue: prevent work-stealing from picking up
                // prev while this CPU is still on its kernel stack.
                //
                // NEW_INV: store ON_CPU_PENDING BEFORE slot fill and BEFORE
                // state=Ready. Once that store is visible, rescue's stale-
                // on-cpu predicate (state=Ready ∧ on_cpu<ncpus) cannot match.
                thread_ref(prev_id).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                let packed = (prev_id as u64) | ((prev_prio as u64) << 32) | ((cpu as u64) << 40);
                let old_deferred = deferred_requeue()[cpu as usize].swap(packed, Ordering::AcqRel);
                if old_deferred != 0 {
                    // Defensive: try_switch entry already drained this slot
                    // (line ~2521), so old_deferred should be 0. If somehow
                    // non-zero, the lost tid already has on_cpu=PENDING under
                    // NEW_INV; just enqueue. percpu_enqueue's in_queue swap
                    // is the double-enqueue guard.
                    let lost_tid = (old_deferred & 0xFFFFFFFF) as u32;
                    let lost_prio = ((old_deferred >> 32) & 0xFF) as u8;
                    let lost_target = ((old_deferred >> 40) & 0xFF) as u32;
                    crate::println!(
                        "DEFERRED-OVERWRITE(try_switch): cpu={} lost tid={} prio={} replaced by tid={} prio={}",
                        cpu, lost_tid, lost_prio, prev_id, prev_prio
                    );
                    set_enq_tag(10); // 10=overwrite_rescue
                    percpu_enqueue(lost_target, lost_prio, lost_tid);
                }
                prev_t.state = ThreadState::Ready;
                trace_sched(prev_id, 1); // 1=deferred_store
            }
        }
    }

    // Switch page tables if crossing task boundaries.
    let next_task = thread_ref(next_id).task_id;
    if prev_task != next_task {
        // Need task data — access via TASK_TABLE (lockless).
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + kstack_size());

    // Restore TLS base register for the next thread.
    // Always write FSBASE so stale values from another thread don't leak.
    crate::arch::cpu::set_tls(thread_ref(next_id).tls_base);

    // Double-scheduling detection: CAS on_cpu from ON_CPU_PENDING→cpu.
    // dequeue_set_pending only sets ON_CPU_PENDING for threads that were
    // parked (on_cpu=MAX) or already pending. If on_cpu is a real CPU
    // number (spurious rescue enqueue of a Running thread), CAS fails.
    // Skip for idle threads (per-CPU, never enqueued, can't be double-scheduled).
    //
    // dispatching_tid: published BEFORE the CAS so rescue's stale_on_cpu
    // predicate (state=Ready, on_cpu=cpu_real, current_thread=prev_id) can
    // observe "this CPU is in the middle of dispatching tid" and skip.
    // Cleared AFTER the current_thread store so rescue never sees a thread
    // that has on_cpu=cpu but is neither dispatching nor current_thread.
    if next_id != idle_id {
        pcpu.dispatching_tid.store(next_id, Ordering::Release);
        if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire,
        ) {
            trace_point("try_switch.cas_fail", next_id as u32);
            crate::println!(
                "DOUBLE-SCHED: tid={} on_cpu={} this_cpu={} prev={} src={} set_by={} inq={} state={:?}",
                next_id, other_cpu, cpu, prev_id,
                thread_ref(next_id).saved_sp_source,
                thread_ref(next_id).on_cpu_set_by.load(Ordering::Relaxed),
                thread_ref(next_id).in_queue.load(Ordering::Relaxed),
                thread_ref(next_id).state
            );
            thread_ref(next_id).killed.store(true, Ordering::Release);
            pcpu.dispatching_tid.store(0, Ordering::Release);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            pcpu.current_thread.store(idle_id, Ordering::Relaxed);
            return idle_sp;
        }
        trace_point("try_switch.cas_ok", next_id as u32);
        thread_ref(next_id).on_cpu_set_by.store(1, Ordering::Relaxed); // 1=try_switch
        // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
        dispatch_cas_ok(pcpu, next_id);
        // Set Running IMMEDIATELY after CAS to close the TOCTOU window:
        // between CAS(on_cpu=cpu) and state=Running, rescue sees
        // state=Ready + on_cpu=cpu + current_thread≠tid → false orphan.
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
        trace_sched(next_id, 4); // 4=on_cpu_set
        // #120 dispatch-pattern diagnostic: count + same-tid streak.
        pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
        let prev_picked = pcpu.last_dispatched_tid.swap(next_id as u32, Ordering::Relaxed);
        if prev_picked == next_id as u32 {
            pcpu.dispatch_streak.fetch_add(1, Ordering::Relaxed);
        } else {
            pcpu.dispatch_streak.store(1, Ordering::Relaxed);
        }
    } else {
        // Idle thread: no CAS needed, just set Running.
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    // Activate next thread.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    trace_sched(next_id, 7); // 7=state_running
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    // Clear dispatching_tid: dispatch is fully visible — on_cpu=cpu,
    // state=Running, current_thread=tid all observable to other CPUs.
    if next_id != idle_id {
        pcpu.dispatching_tid.store(0, Ordering::Release);
    }
    thread_ref(next_id).last_cpu.store(cpu, Ordering::Relaxed);

    // RCU quiescent state: all syscall read-side references from the
    // previous timeslice are now dead.  Process deferred frees.
    crate::sync::rcu::rcu_quiescent();

    // Sanity check: saved_sp must be within the thread's kstack, and the
    // CS/RIP fields in the exception frame must be valid.
    {
        let sp = next_t.saved_sp;
        let kbase = next_t.stack_base;
        let kend = kbase as u64 + kstack_size() as u64;
        let is_idle = next_id == idle_id;
        // Idle threads run on boot stacks (ring 0), not their allocated kstack.
        // Their saved_sp is legitimately outside the kstack range — skip the check.
        if !is_idle && (sp < kbase as u64 || sp >= kend) {
            crate::println!(
                "BUG: try_switch: tid={} saved_sp={:#x} OUTSIDE kstack {:#x}..{:#x} (source={})",
                next_id, sp, kbase, kend, next_t.saved_sp_source
            );
            crate::println!(
                "  prev={} next={} task={} state={:?}",
                prev_id, next_id, next_t.task_id, next_t.state
            );
            // Kill this thread and switch to idle instead — restoring from
            // an out-of-range saved_sp would corrupt the CPU state (#DE/#GP).
            thread_ref(next_id).killed.store(true, Ordering::Release);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            pcpu.current_thread.store(idle_id, Ordering::Relaxed);
            return idle_sp;
        }
        // Check for corrupt exception frame (architecture-specific).
        #[cfg(target_arch = "x86_64")]
        if !is_idle && sp >= kbase as u64 && sp < kend {
            // x86_64: CS must be 0x08 (kernel) or 0x23 (user), RIP must be > 64K.
            let rip = unsafe { *((sp as usize + 136) as *const u64) };
            let cs = unsafe { *((sp as usize + 144) as *const u64) };
            let bad_cs = cs != 0x08 && cs != 0x23;
            let bad_rip = rip < 0x10000; // no code below 64K in kernel or user
            if bad_cs || bad_rip {
                crate::println!(
                    "BUG: try_switch: tid={} bad frame RIP={:#x} CS={:#x} sp={:#x} src={} prev={} task={}",
                    next_id, rip, cs, sp, next_t.saved_sp_source, prev_id, next_t.task_id
                );
                // Skip this thread — mark killed and pick idle instead.
                thread_ref(next_id).killed.store(true, Ordering::Release);
                let idle_sp = thread_ref(idle_id).saved_sp;
                unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
                pcpu.current_thread.store(idle_id, Ordering::Relaxed);
                return idle_sp;
            }
        }
        #[cfg(target_arch = "aarch64")]
        if !is_idle && sp >= kbase as u64 && sp < kend {
            // aarch64: ELR_EL1 at frame[32] (offset 256) must be > 64K.
            let elr = unsafe { *((sp as usize + 256) as *const u64) };
            if elr < 0x10000 {
                crate::println!(
                    "BUG: try_switch: tid={} bad frame ELR={:#x} sp={:#x} src={} prev={} task={}",
                    next_id, elr, sp, next_t.saved_sp_source, prev_id, next_t.task_id
                );
                thread_ref(next_id).killed.store(true, Ordering::Release);
                let idle_sp = thread_ref(idle_id).saved_sp;
                unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
                pcpu.current_thread.store(idle_id, Ordering::Relaxed);
                return idle_sp;
            }
        }
    }
    next_t.saved_sp
}

/// Voluntarily reschedule from syscall context.
/// The trap handler must have already called `store_frame_sp()`.
/// If another thread is runnable, sets PENDING_SWITCH_SP so the trap
/// handler performs the context switch on return.
pub fn voluntary_reschedule() {
    // Disable IRQs for the entire function.
    let _irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id();
    drain_deferred_requeue(cpu);
    let pcpu = smp::current();
    let cur_id = pcpu.current_thread.load(Ordering::Relaxed);
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Save frame SP into thread struct.
    let frame_sp = unsafe { thread_mut_from_ref(cur_id) }.syscall_frame_sp;
    let cur_prio;
    let cur_task;
    {
        let t = unsafe { thread_mut_from_ref(cur_id) };
        t.saved_sp = frame_sp;
        t.saved_sp_source = 2; // voluntary_reschedule
        cur_prio = t.effective_priority;
        cur_task = t.task_id;
        // NOTE: state stays Running here. Set to Ready AFTER the deferred
        // store to close the orphan window (see try_switch for rationale).
    }

    // Check if there's another runnable thread before yielding.
    // We DON'T enqueue cur first — see below for why.
    let next_id = percpu_pick_next(cpu, idle_id);

    if next_id == idle_id {
        // No other thread to run — stay Running.
        return;
    }

    crate::sched::stats::CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);

    // Switch page tables if crossing task boundaries.
    let next_task = thread_ref(next_id).task_id;
    if cur_task != next_task {
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + kstack_size());

    // NEW_INV: cur.on_cpu = ON_CPU_PENDING is stored BEFORE the slot fill and
    // BEFORE state=Ready, so rescue's stale-on-cpu predicate cannot observe
    // (state=Ready ∧ on_cpu=cpu_real). The slot's `target` field still
    // encodes cpu_real so drain knows which RQ to enqueue on.
    //
    // Defer re-enqueue of cur instead of percpu_enqueue. We are still on
    // cur's kernel stack — the assembly `mov rsp, rax` hasn't executed yet.
    // If we percpu_enqueue now, another CPU could steal cur and switch to
    // its stack while we're still using it (stack use-after-free → #DE/#GP).
    // Deferred_requeue is per-CPU: only drained by the NEXT scheduling event
    // on THIS CPU (or by remote drain after the 250ms+ stale-slot guard,
    // long after the assembly switch has completed).
    if cur_id != idle_id {
        thread_ref(cur_id).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
        let packed = (cur_id as u64) | ((cur_prio as u64) << 32) | ((cpu as u64) << 40);
        let old_deferred = deferred_requeue()[cpu as usize].swap(packed, Ordering::AcqRel);
        if old_deferred != 0 {
            // Defensive: voluntary_reschedule entry drains this slot first
            // (line ~2873), so old_deferred should be 0. If somehow non-zero,
            // the lost tid already has on_cpu=PENDING under NEW_INV.
            let lost_tid = (old_deferred & 0xFFFFFFFF) as u32;
            let lost_prio = ((old_deferred >> 32) & 0xFF) as u8;
            let lost_target = ((old_deferred >> 40) & 0xFF) as u32;
            crate::println!(
                "DEFERRED-OVERWRITE(vol_resched): cpu={} lost tid={} prio={} replaced by tid={} prio={}",
                cpu, lost_tid, lost_prio, cur_id, cur_prio
            );
            set_enq_tag(10);
            percpu_enqueue(lost_target, lost_prio, lost_tid);
        }
        // Set state=Ready AFTER on_cpu=PENDING and slot fill. On x86 TSO,
        // the prior Release store of PENDING is visible to any CPU that
        // observes state=Ready, so the orphan window is closed.
        unsafe { thread_mut_from_ref(cur_id) }.state = ThreadState::Ready;
        trace_sched(cur_id, 1); // 1=deferred_store
    }

    // Claim on_cpu for next (ON_CPU_PENDING → cpu).
    if next_id != idle_id {
        pcpu.dispatching_tid.store(next_id, Ordering::Release);
        if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu, Ordering::AcqRel, Ordering::Acquire,
        ) {
            crate::println!(
                "DOUBLE-SCHED(vol): tid={} already on cpu={}, this cpu={}",
                next_id, other_cpu, cpu
            );
            thread_ref(next_id).killed.store(true, Ordering::Release);
            pcpu.dispatching_tid.store(0, Ordering::Release);
            // Undo: stay on cur_id. Drain our deferred store (it was cur).
            deferred_requeue()[cpu as usize].store(0, Ordering::Release);
            let t = unsafe { thread_mut_from_ref(cur_id) };
            t.state = ThreadState::Running;
            if cur_id != idle_id {
                thread_ref(cur_id).on_cpu.store(cpu, Ordering::Release);
            }
            // Undo page table and kernel stack changes that were made above
            // before we discovered the double-schedule. We're staying on
            // cur_id, so restore cur's page table and kernel stack pointer.
            if cur_task != next_task {
                let cur_root = {
                    let tptr = TASK_TABLE.get(cur_task) as *const Task;
                    if !tptr.is_null() {
                        unsafe { (*tptr).page_table_root }
                    } else {
                        0
                    }
                };
                if cur_root != 0 {
                    crate::mm::hat::switch_page_table(cur_root);
                }
            }
            crate::arch::trapframe::update_kernel_stack(
                thread_ref(cur_id).stack_base + kstack_size(),
            );
            return;
        }
        thread_ref(next_id).on_cpu_set_by.store(2, Ordering::Relaxed); // 2=vol_resched
        // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
        dispatch_cas_ok(pcpu, next_id);
        // Set Running IMMEDIATELY after CAS — close TOCTOU window (see try_switch).
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
        // #120 dispatch-pattern diagnostic (vol_resched path).
        pcpu.dispatch_count.fetch_add(1, Ordering::Relaxed);
        let prev_picked = pcpu.last_dispatched_tid.swap(next_id as u32, Ordering::Relaxed);
        if prev_picked == next_id as u32 {
            pcpu.dispatch_streak.fetch_add(1, Ordering::Relaxed);
        } else {
            pcpu.dispatch_streak.store(1, Ordering::Relaxed);
        }
    } else {
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    let next_t = unsafe { thread_mut_from_ref(next_id) };
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    if next_id != idle_id {
        pcpu.dispatching_tid.store(0, Ordering::Release);
    }
    let next_sp = next_t.saved_sp;

    pending_switch_sp()[cpu as usize].store(next_sp, Ordering::Release);

    // Reprogram the timer so the deferred slot (holding cur_id) is drained
    // promptly.  Without this, the timer stays at the previous tick's value
    // (up to 200ms in the future), leaving the deferred thread un-enqueued
    // until rescue IPIs the CPU ~100ms later.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
    // Leave IRQs disabled — exception handler consumes pending_switch.
}

// --- Coscheduling ---

/// Maximum consecutive cosched picks before yielding to other threads.
const MAX_COSCHED_BURST: u32 = 4;

/// Count of coscheduling hits (for testing/diagnostics).
pub static COSCHED_HITS: AtomicU64 = AtomicU64::new(0);

// --- Scheduler Activations ---
// SA_PENDING, SA_EVENT, SA_WAITER are now embedded in Task struct,
// accessed via TASK_TABLE radix lookup for lockless access.

/// Set YIELD_ASAP for a thread, causing it to be preempted on the next timer tick.
pub fn set_yield_asap(tid: ThreadId) {
    thread_ref(tid).yield_asap.store(true, Ordering::Release);
}

/// Clear the wakeup flag for a thread. Must be called while holding the
/// relevant lock (turnstile bucket etc.) BEFORE adding the thread as a waiter,
/// to prevent a lost-wakeup race where wake_thread() sets the flag between
/// the lock drop and block_current's flag clear.
pub fn clear_wakeup_flag(tid: ThreadId) {
    thread_ref(tid).wakeup.store(false, Ordering::Release);
}

/// Block the current thread with the given reason.
/// The thread will be preempted on the next timer tick and will not
/// be re-enqueued until `wake_thread()` is called.
///
/// IMPORTANT: The caller must call `clear_wakeup_flag(tid)` while holding
/// the relevant lock, BEFORE adding itself as a waiter and dropping the lock.
pub fn block_current(_reason: BlockReason) {
    let tid = current_thread_id();
    if matches!(_reason, BlockReason::CallReply(_)) {
        trace_point("block_current.CallReply", tid as u32);
    } else {
        trace_point("block_current.entry", tid as u32);
    }
    // Demote effective_priority to 254 (lowest non-idle) so try_switch
    // re-enqueues us at the bottom. This prevents blocked-spinning threads
    // from starving lower-priority threads on single-CPU.
    let tref = thread_ref(tid);
    // Save and demote by one level — enough for try_switch to prefer
    // productive threads but not so extreme that the blocked thread
    // starves (prio=254 caused indefinite starvation under load).
    let demoted = (tref.base_priority as u16 + 1).min(253) as u8;
    let saved_prio = tref.prio.swap(demoted, Ordering::AcqRel);
    unsafe { thread_mut_from_ref(tid) }.effective_priority = demoted;
    // Signal the scheduler to preempt us on the next timer tick instead of
    // waiting for the full quantum. This prevents spinning threads from
    // starving real work on SMP systems.
    tref.yield_asap.store(true, Ordering::Release);
    // With dynamic tick, the timer might be programmed far in the future.
    // Reprogram it to fire within one tick so we get preempted promptly.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
    // Enable interrupts so the timer can preempt us while we spin.
    // This is critical when called from a syscall handler (SVC/ecall/int),
    // because hardware masks IRQs on exception entry.
    let saved = crate::arch::irq::save_and_enable();
    // Spin until the wakeup flag is set. The thread stays Running and
    // gets preempted normally by timer ticks (quantum-based). This avoids
    // a race where wake_thread() re-enqueues a Blocked thread that's still
    // executing on its CPU, causing double-scheduling on SMP.
    while !tref.wakeup.load(Ordering::Acquire) {
        // Check if this thread was killed — break out immediately.
        if tref.killed.load(Ordering::Acquire) {
            break;
        }
        // Reprogram the timer before HLT. After being preempted and
        // scheduled back, compute_next_event may have set the timer far in
        // the future (up to MAX_IDLE_NS). We need a prompt tick so
        // try_switch preempts us and other threads can run.
        crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
        // Use WFI to wait for the next interrupt (timer tick or device IRQ).
        // This is critical on QEMU TCG: spin_loop() keeps the vCPU busy,
        // starving QEMU's I/O thread from processing virtio requests.
        // WFI causes the vCPU to pause until an interrupt arrives.
        crate::arch::irq::wait_for_interrupt();
        // Re-arm: try_switch() clears YIELD_ASAP when it preempts us,
        // but we need it set again so the *next* tick also preempts
        // immediately (we're still blocked, not doing useful work).
        tref.yield_asap.store(true, Ordering::Release);
    }
    tref.yield_asap.store(false, Ordering::Release);
    // Restore effective priority — no SCHEDULER lock needed.
    tref.prio.store(saved_prio, Ordering::Release);
    unsafe { thread_mut_from_ref(tid) }.effective_priority = saved_prio;
    // Re-apply this thread's TLS base in case it was modified while blocked
    // (e.g. by personality_set_tls from the personality server). block_current
    // is a spin-wait — the thread never goes through try_switch on wake-up,
    // so FSBASE would otherwise stay stale until a context switch.
    crate::arch::cpu::set_tls(tref.tls_base);
    crate::arch::irq::restore(saved);
}

/// Raise a thread's effective priority to `new_prio` *if* that represents a
/// priority increase (i.e. a lower numeric value in Telix's convention where
/// 0 = highest, 254 = lowest non-idle). Returns the thread's prior
/// `effective_priority` so the caller can save it for later restoration.
///
/// Used by IPC priority-inheritance donation (`call_reply::donate_priority`).
/// Writes both the `prio` atomic (read by try_switch and wake_thread) and
/// the per-thread `effective_priority` field.
///
/// NOTE: This does not re-enqueue a ready thread at the new priority — the
/// next try_switch tick will pick up the change via the `prio` atomic. For
/// the IPC donation use case, the server is either currently running (just
/// returned from recv_with_cap) or about to be woken (DirectTransfer), so
/// no mid-queue re-sorting is required.
pub fn raise_thread_priority_to(tid: ThreadId, new_prio: u8) -> u8 {
    let tref = thread_ref(tid);
    let old = tref.effective_priority;
    if new_prio < old {
        tref.prio.store(new_prio, Ordering::Release);
        unsafe { thread_mut_from_ref(tid) }.effective_priority = new_prio;
    }
    old
}

/// Restore a thread's effective priority to a saved value. Counterpart to
/// `raise_thread_priority_to`; called when IPC donation is unwound.
///
/// Unconditional write: callers record the exact pre-donation value and
/// expect that value to be re-installed on any terminal path (reply,
/// caller death, server death).
pub fn restore_thread_priority(tid: ThreadId, saved_prio: u8) {
    let tref = thread_ref(tid);
    tref.prio.store(saved_prio, Ordering::Release);
    unsafe { thread_mut_from_ref(tid) }.effective_priority = saved_prio;
}

/// Wake a blocked thread, making it runnable.
pub fn wake_thread(tid: ThreadId) {
    let tref = thread_ref(tid);
    tref.wakeup.store(true, Ordering::Release);
    // Clear yield_asap so the thread isn't preempted on the very next tick
    // before it can check the wakeup flag and exit block_current.
    tref.yield_asap.store(false, Ordering::Release);
    // If the thread was demoted by block_current, restore its priority
    // and send an IPI so it exits the WFI loop promptly.
    let demoted_prio = tref.prio.load(Ordering::Acquire);
    let base = tref.base_priority;
    if demoted_prio > base {
        // Restore prio to base BEFORE attempting remove.
        tref.prio.store(base, Ordering::Release);

        let old_cpu = tref.last_cpu.load(Ordering::Relaxed);
        let waker_cpu = smp::cpu_id();
        // Remove from old CPU's queue and re-enqueue at base prio.
        let removed = {
            if old_cpu as usize == waker_cpu as usize {
                if let Some(mut rq) = percpu_rq()[old_cpu as usize].try_lock() {
                    rq.remove_tid(tid)
                } else {
                    false
                }
            } else {
                let mut rq = percpu_rq()[old_cpu as usize].lock();
                rq.remove_tid(tid)
            }
        };
        if removed {
            trace_sched(tid, 9); // 9=wake_enq
            set_enq_tag(3); // 3=wake_thread
            percpu_enqueue(waker_cpu, base, tid);
        } else {
            trace_sched(tid, 10); // 10=wake_no_enq
            if old_cpu != waker_cpu {
                crate::arch::irq::send_reschedule_ipi(old_cpu);
            }
        }
    }
    // If a DIFFERENT thread with higher priority was woken on this CPU,
    // set need_resched so check_preempt_on_return triggers an immediate
    // voluntary reschedule at the next syscall return boundary.
    // Skip when waking ourselves (e.g., sleep timer waking us from block_current).
    {
        let waker_cpu = smp::cpu_id();
        let pcpu = smp::get(waker_cpu);
        let cur_tid = pcpu.current_thread.load(Ordering::Relaxed);
        if tid != cur_tid {
            let cur_prio = thread_ref(cur_tid).effective_priority;
            let woken_prio = tref.base_priority;
            if woken_prio < cur_prio {
                pcpu.need_resched.store(true, Ordering::Release);
                // Reprogram timer to fire within one tick for prompt preemption.
                // Under dynamic tick, the timer may be set far out (up to
                // MAX_IDLE_NS) if the CPU was idle. With IRQs enabled during
                // syscalls, this ensures the timer fires mid-syscall and
                // try_switch() preempts to the higher-priority thread.
                crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
            }
        }
    }
    // Handle IPC-parked threads (park_current_for_ipc with PARK_COMMITTED).
    // These threads are off-CPU and can only be woken by wake_parked_thread,
    // which requires coordination with frame injection (inject_recv_into_frame).
    //
    // For CallReply-blocked threads, we use the reply cap's state CAS as a
    // coordination mechanism: CAS the cap PENDING→ABANDONED.  If we win,
    // the server's future fulfill() will see ABANDONED and skip frame
    // injection + wake.  If the server already fulfilled, our CAS fails and
    // the server owns the wake.  This avoids the frame corruption race.
    //
    // BUT: only fire the abandon path when the wake represents a *genuine*
    // interruption — i.e., the thread has been killed or has a pending
    // unmasked signal.  Incidental wake_thread calls (a stale wake left
    // over from a previous block_current iteration, a port_wake_one for an
    // earlier turnstile membership, an IPI-driven reschedule attempt) must
    // NOT cancel a legitimate in-flight call/reply.  Cancelling such a call
    // not only frees the cap slot prematurely (allowing reuse before the
    // server replies — the server's fulfill then fails harmlessly, but the
    // caller has been mis-informed via CALL_REPLY_INTERRUPTED) but, in the
    // worst case under rapid call cycles, can race with a fresh sys_call
    // that has just re-published `blocked_on = CallReply(new_slot)` after
    // park_state has been re-armed to PARK_COMMITTED — abandoning a brand-
    // new pending cap with no actual interrupt request behind the wake.
    {
        let park = tref.park_state.load(Ordering::Acquire);
        if park == PARK_COMMITTED {
            let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
            // Only abandon if there's a genuine interrupt request: thread
            // killed, or a deliverable (unmasked) signal pending.  This
            // mirrors the syscall-return signal-check predicate.
            let killed = tref.killed.load(Ordering::Acquire);
            let has_signal = (t.sig_pending & !t.sig_mask) != 0;
            if (killed || has_signal) && let BlockReason::CallReply(slot) = t.blocked_on {
                if crate::ipc::call_reply::abandon_for_interrupt(slot, tid) {
                    // We won: cap is ABANDONED. Inject an interrupted-call
                    // error into the thread's saved frame so userspace sees a
                    // clean error rather than stale register values.
                    let sp = thread_saved_sp(tid);
                    if sp != 0 {
                        let tag = crate::ipc::call_reply::CALL_REPLY_INTERRUPTED;
                        unsafe {
                            use crate::arch::trapframe::ExceptionFrame;
                            let frame = &mut *(sp as *mut ExceptionFrame);
                            crate::syscall::handlers::set_return(frame, 0);
                            crate::syscall::handlers::set_reg(frame, 1, tag);
                            crate::syscall::handlers::set_reg(frame, 2, 0);
                            crate::syscall::handlers::set_reg(frame, 3, 0);
                            crate::syscall::handlers::set_reg(frame, 4, 0);
                            crate::syscall::handlers::set_reg(frame, 5, 0);
                            crate::syscall::handlers::set_reg(frame, 6, 0);
                            crate::syscall::handlers::set_reg(frame, 7, 0);
                        }
                    }
                    // Free the cap slot (leases/donation already unwound by
                    // abandon_for_interrupt).
                    let cap_gen = crate::ipc::call_reply::REPLY_CAPS[slot as usize]
                        .generation
                        .load(Ordering::Acquire);
                    crate::ipc::call_reply::free(
                        (slot as u64) | ((cap_gen as u64) << 32),
                    );
                    wake_parked_thread(tid);
                }
                // If abandon_for_interrupt returned false, the server already
                // fulfilled or is mid-reply. Its wake_parked_thread will
                // handle the wake. Nothing more to do.
            }
            // For non-CallReply COMMITTED threads (PortRecv, PagerFault),
            // their legitimate wakers will handle them. Signal delivery for
            // those block types is a future enhancement.
        }
    }
    // Signal all CPUs so any core spinning in block_current's WFE wakes immediately.
    crate::arch::irq::send_event();
}

/// Called on syscall return. If need_resched was set (by wake_thread or a
/// blocking path on this CPU), perform an immediate voluntary reschedule so
/// the higher-priority thread runs without waiting for the next timer tick.
pub fn check_preempt_on_return() {
    // If a context switch is already staged (from park_current_for_ipc,
    // voluntary_reschedule, or handoff_to during this syscall), don't
    // call voluntary_reschedule again — it would read the switched-to
    // thread's stale syscall_frame_sp and corrupt its saved_sp.
    if has_pending_switch() {
        return;
    }
    let cpu = smp::cpu_id();
    let pcpu = smp::get(cpu);
    if pcpu.need_resched.swap(false, Ordering::AcqRel) {
        voluntary_reschedule();
    }
}

/// Check if a thread has been marked for kill.
pub fn is_killed(tid: ThreadId) -> bool {
    thread_ref(tid).killed.load(Ordering::Acquire)
}

/// Check if a thread is in Dead state (already exiting/exited).
pub fn is_dead(tid: ThreadId) -> bool {
    thread_ref(tid).state == ThreadState::Dead
}

/// Kill all threads in the task that `tid` belongs to.
/// Returns true if the thread was found and the kill signal was sent.
/// Kill all threads in the task that thread `tid` belongs to.
pub fn kill_task(tid: ThreadId) -> bool {
    if tid as usize >= RadixTable::capacity() {
        return false;
    }
    let task_id = {
        let target_thread = match thread_ref_opt(tid) {
            Some(t) => t,
            None => return false,
        };
        if target_thread.state == ThreadState::Dead && target_thread.stack_base == 0 {
            return false;
        }
        target_thread.task_id
    };
    kill_task_by_id(task_id)
}

/// Kill all threads in the given task (by task_id).
pub fn kill_task_by_id(task_id: TaskId) -> bool {
    const MAX_KILL: usize = 64;
    let mut to_kill = [0u32; MAX_KILL];
    let mut kill_count = 0usize;
    {
        let task = match task_ref_opt(task_id) {
            Some(t) => t,
            None => return false,
        };
        if !task.active {
            return false;
        }
        SCHED_THREAD_ART.for_each(|key, val| {
            let t = unsafe { &*(val as *const Thread) };
            if t.task_id == task_id && t.state != ThreadState::Dead && t.stack_base != 0 {
                t.killed.store(true, Ordering::Release);
                if kill_count < MAX_KILL {
                    to_kill[kill_count] = key as u32;
                    kill_count += 1;
                }
            }
        });
    }
    for i in 0..kill_count {
        let tid = to_kill[i] as ThreadId;
        // If the thread is sleeping, remove from sleep queue and enqueue directly
        // so it exits promptly instead of waiting for the deadline.
        let t = unsafe { thread_mut_from_ref(tid) };
        if t.state == ThreadState::Blocked && matches!(t.blocked_on, BlockReason::Sleep) {
            sleep_queue_remove(tid);
            // Wait for the thread's parking stack switch to complete.
            while thread_ref(tid).stack_switch_pending.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
            // NEW_INV: on_cpu must be ON_CPU_PENDING before state=Ready
            // (was u32::MAX from park_for_sleep).
            thread_ref(tid).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
            t.state = ThreadState::Ready;
            t.blocked_on = BlockReason::None;
            t.sleep_deadline_ns = 0;
            let target = t.last_cpu.load(Ordering::Relaxed);
            set_enq_tag(9); // 9=kill_sleep
            percpu_enqueue(target, t.effective_priority, tid);
        } else {
            wake_thread(tid);
        }
    }
    kill_count > 0
}

/// Send a signal to a task (process-directed). Queues on the first
/// thread in the task that has the signal unmasked, or the first thread.
/// SIGKILL always uses the old kill path (immediate termination).
pub fn send_signal_to_task(task_id: u32, sig: u32) -> bool {
    use super::task::{MAX_SIGNALS, SIGKILL, sig_bit};
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return false;
    }
    if sig == SIGKILL {
        return kill_task_by_id(task_id);
    }

    let bit = sig_bit(sig);

    // Check handler disposition (lock-free).
    let task = match task_ref_opt(task_id) {
        Some(t) => t,
        None => return false,
    };
    if !task.active {
        return false;
    }
    let action = &task.sig_actions[(sig - 1) as usize];
    if action.handler == super::task::SigHandler::Ignore {
        return true; // accepted but ignored
    }
    if action.handler == super::task::SigHandler::Default && !super::task::sig_default_is_term(sig)
    {
        return true;
    }

    // Find a thread to receive: prefer one with signal unmasked.
    let mut target: Option<u32> = None;
    let mut any_thread: Option<u32> = None;
    SCHED_THREAD_ART.for_each(|key, val| {
        if target.is_some() {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead && t.stack_base != 0 {
            if any_thread.is_none() {
                any_thread = Some(key as u32);
            }
            if t.sig_mask & bit == 0 {
                target = Some(key as u32);
            }
        }
    });
    let tid = match target.or(any_thread) {
        Some(t) => t,
        None => return false,
    };

    // Safe: sig_pending is only ORed (no lost updates for single-bit sets).
    unsafe { thread_mut_from_ref(tid) }.sig_pending |= bit;

    // Wake the target thread so it can deliver the signal.
    wake_thread(tid as ThreadId);
    true
}

/// Send a signal to a specific thread.
pub fn send_signal_to_thread(tid: ThreadId, sig: u32) -> bool {
    use super::task::{MAX_SIGNALS, SIGKILL, sig_bit};
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return false;
    }
    if tid as usize >= RadixTable::capacity() {
        return false;
    }
    if sig == SIGKILL {
        return kill_task(tid);
    }

    let bit = sig_bit(sig);
    let t = match thread_ref_opt(tid) {
        Some(t) => t,
        None => return false,
    };
    if t.state == ThreadState::Dead || t.stack_base == 0 {
        return false;
    }
    // Safe: sig_pending is only ORed (single-bit set, no lost updates).
    unsafe { thread_mut_from_ref(tid) }.sig_pending |= bit;
    wake_thread(tid);
    true
}

/// Get and clear the next deliverable signal for the current thread.
/// Returns Some(signal_number) if there's a pending, unmasked signal.
pub fn dequeue_signal() -> Option<u32> {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let t = thread_ref(tid);
    let deliverable = t.sig_pending & !t.sig_mask;
    if deliverable == 0 {
        return None;
    }
    // Find lowest-numbered signal.
    let bit_idx = deliverable.trailing_zeros();
    let sig = bit_idx + 1;
    // Safe: only the current thread dequeues its own signals.
    unsafe { thread_mut_from_ref(tid) }.sig_pending &= !(1u64 << bit_idx);
    Some(sig)
}

/// Get the signal action for a signal in the current thread's task.
pub fn get_signal_action(sig: u32) -> Option<super::task::SignalAction> {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    let task = task_ref(task_id);
    if sig < 1 || sig > super::task::MAX_SIGNALS as u32 {
        return None;
    }
    Some(task.sig_actions[(sig - 1) as usize])
}

/// Set signal action for the current task. Returns previous action.
pub fn set_signal_action(
    sig: u32,
    action: super::task::SignalAction,
) -> Option<super::task::SignalAction> {
    use super::task::{MAX_SIGNALS, UNCATCHABLE, sig_bit};
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return None;
    }
    if sig_bit(sig) & UNCATCHABLE != 0 {
        return None;
    } // can't change SIGKILL/SIGSTOP
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    let old = task_ref(task_id).sig_actions[(sig - 1) as usize];
    // Safe: only the current task modifies its own sig_actions.
    unsafe { task_mut_from_ref(task_id) }.sig_actions[(sig - 1) as usize] = action;
    Some(old)
}

/// Set the signal mask for the current thread. Returns old mask.
pub fn set_signal_mask(new_mask: u64) -> u64 {
    use super::task::UNCATCHABLE;
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let old = thread_ref(tid).sig_mask;
    // Cannot mask SIGKILL or SIGSTOP.
    // Safe: only the current thread modifies its own sig_mask.
    unsafe { thread_mut_from_ref(tid) }.sig_mask = new_mask & !UNCATCHABLE;
    old
}

/// Get the signal mask for the current thread.
pub fn get_signal_mask() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid).sig_mask
}

/// Get the pending signal set for the current thread.
pub fn get_signal_pending() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid).sig_pending
}

// --- Phase 43: Process groups, sessions, controlling terminals ---

/// Set the process group ID of a task.
/// pid=0 means current task. pgid=0 means set pgid=pid.
/// Returns 0 on success, u64::MAX on error.
pub fn setpgid(pid: u32, pgid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    let target_task = if pid == 0 { my_task } else { pid };

    match task_ref_opt(target_task) {
        Some(t) if t.active => {}
        _ => return u64::MAX,
    }
    if target_task != my_task && task_ref(target_task).parent_task != my_task {
        return u64::MAX;
    }

    let new_pgid = if pgid == 0 { target_task } else { pgid };
    let target_sid = task_ref(target_task).sid;

    if new_pgid != target_task {
        let mut found = false;
        SCHED_TASK_ART.for_each(|_key, val| {
            if found {
                return;
            }
            let t = unsafe { &*(val as *const Task) };
            if t.active && t.sid == target_sid && t.pgid == new_pgid {
                found = true;
            }
        });
        if !found {
            return u64::MAX;
        }
    }

    // Safe: only the owning task or its parent modifies pgid.
    unsafe { task_mut_from_ref(target_task) }.pgid = new_pgid;
    0
}

/// Get the process group ID of a task.
/// pid=0 means current task.
pub fn getpgid(pid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let target_task = if pid == 0 {
        thread_ref(my_tid).task_id
    } else {
        pid
    };
    match task_ref_opt(target_task) {
        Some(t) if t.active => {
            // Return group leader's task port_id (not raw task_id).
            task_ref(t.pgid).port_id
        }
        _ => u64::MAX,
    }
}

/// Create a new session. The calling task becomes the session leader.
/// Returns the new session ID (= task_id) or u64::MAX on error.
pub fn setsid() -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    let current_pgid = task_ref(my_task).pgid;
    if current_pgid == my_task {
        let mut conflict = false;
        SCHED_TASK_ART.for_each(|_key, val| {
            if conflict {
                return;
            }
            let t = unsafe { &*(val as *const Task) };
            if t.active && t.id != my_task && t.pgid == my_task {
                conflict = true;
            }
        });
        if conflict {
            return u64::MAX;
        }
    }

    // Safe: only the current task modifies its own session/pgroup.
    let task = unsafe { task_mut_from_ref(my_task) };
    task.sid = my_task;
    task.pgid = my_task;
    task.ctty_port = 0;
    task.port_id
}

/// Get the session ID of a task.
/// pid=0 means current task.
pub fn getsid(pid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let target_task = if pid == 0 {
        thread_ref(my_tid).task_id
    } else {
        pid
    };
    match task_ref_opt(target_task) {
        Some(t) if t.active => {
            // Return session leader's task port_id.
            task_ref(t.sid).port_id
        }
        _ => u64::MAX,
    }
}

/// Set the foreground process group for the controlling terminal.
/// The caller must be in the same session as the ctty.
pub fn tcsetpgrp(pgid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    if task_ref(my_task).ctty_port == 0 {
        return u64::MAX;
    }

    let my_sid = task_ref(my_task).sid;
    let mut found = false;
    SCHED_TASK_ART.for_each(|_key, val| {
        if found {
            return;
        }
        let t = unsafe { &*(val as *const Task) };
        if t.active && t.sid == my_sid && t.pgid == pgid {
            found = true;
        }
    });
    if !found {
        return u64::MAX;
    }

    // Store the foreground pgid in the session leader.
    // Safe: only tasks in the session modify fg_pgid, serialized by convention.
    match task_ref_opt(my_sid) {
        Some(t) if t.active => {
            unsafe { task_mut_from_ref(my_sid) }.fg_pgid = pgid;
            0
        }
        _ => u64::MAX,
    }
}

/// Get the foreground process group for the controlling terminal.
pub fn tcgetpgrp() -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    if task_ref(my_task).ctty_port == 0 {
        return u64::MAX;
    }

    let my_sid = task_ref(my_task).sid;
    let mut raw_pgid = u32::MAX;
    SCHED_TASK_ART.for_each(|_key, val| {
        if raw_pgid != u32::MAX {
            return;
        }
        let t = unsafe { &*(val as *const Task) };
        if t.active && t.id == my_sid {
            raw_pgid = t.fg_pgid;
        }
    });
    if raw_pgid == u32::MAX || raw_pgid == 0 {
        u64::MAX
    } else {
        // Return group leader's task port_id.
        task_ref(raw_pgid).port_id
    }
}

/// Send a signal to all tasks in a process group.
pub fn send_signal_to_pgroup(pgid: u32, sig: u32) -> bool {
    use super::task::MAX_SIGNALS;
    if sig < 1 || sig > MAX_SIGNALS as u32 {
        return false;
    }

    let mut task_ids = [0u32; 64];
    let mut count = 0usize;
    SCHED_TASK_ART.for_each(|_key, val| {
        let t = unsafe { &*(val as *const Task) };
        if t.active && t.pgid == pgid && count < 64 {
            task_ids[count] = t.id;
            count += 1;
        }
    });

    if count == 0 {
        return false;
    }

    let mut any = false;
    for i in 0..count {
        if send_signal_to_task(task_ids[i], sig) {
            any = true;
        }
    }
    any
}

/// Set the controlling terminal for the current session.
/// Only the session leader can do this, and only if it has no ctty yet.
pub fn set_ctty(port: u64) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let my_task = thread_ref(my_tid).task_id;

    let task = task_ref(my_task);
    // Must be session leader.
    if task.sid != my_task {
        return u64::MAX;
    }
    // Must not already have a ctty.
    if task.ctty_port != 0 {
        return u64::MAX;
    }

    // Propagate ctty to all tasks in this session.
    let sid = my_task;
    SCHED_TASK_ART.for_each(|_key, val| {
        let t = unsafe { &mut *(val as *mut Task) };
        if t.active && t.sid == sid {
            t.ctty_port = port;
        }
    });
    0
}

#[allow(dead_code)]
pub fn current_thread_id() -> ThreadId {
    smp::current().current_thread.load(Ordering::Relaxed)
}

/// Kill all other threads in the current thread's task (for execve).
/// Marks them as Dead and dequeues from run queues. Returns the number killed.
pub fn kill_other_threads_in_task() -> usize {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(my_tid).task_id;
    let mut killed = 0;

    SCHED_THREAD_ART.for_each(|key, val| {
        if key == my_tid as u64 {
            return;
        }
        let t = unsafe { &mut *(val as *mut Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead {
            t.state = ThreadState::Dead;
            t.exit_code = -9;
            t.killed.store(true, Ordering::Release);
            killed += 1;
        }
    });

    // Set thread_count to 1 (just us).
    // Safe: only the current task's last thread calls this (execve).
    unsafe { task_mut_from_ref(task_id) }.thread_count = 1;
    killed
}

/// Kill all other threads in a specific task (for personality-delegated execve).
/// Keeps `keep_tid` alive, kills everything else in the task.
pub fn kill_other_threads_for_task(task_id: u32, keep_tid: u32) -> usize {
    let mut killed = 0;

    SCHED_THREAD_ART.for_each(|key, val| {
        if key == keep_tid as u64 {
            return;
        }
        let t = unsafe { &mut *(val as *mut Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead {
            t.state = ThreadState::Dead;
            t.exit_code = -9;
            t.killed.store(true, Ordering::Release);
            killed += 1;
        }
    });

    if killed > 0 {
        unsafe { task_mut_from_ref(task_id) }.thread_count = 1;
    }
    killed
}

/// Find a thread in the given task that is blocked on PersonalityWait.
/// Returns the ThreadId, or u32::MAX if none found.
pub fn find_personality_waiter(task_id: u32) -> ThreadId {
    use super::thread::BlockReason;
    let mut found: ThreadId = u32::MAX;
    SCHED_THREAD_ART.for_each(|_key, val| {
        if found != u32::MAX {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id && t.blocked_on == BlockReason::PersonalityWait {
            found = t.id;
        }
    });
    found
}

/// Update the task's page table root after execve replaces the address space.
pub fn update_task_page_table(new_pt_root: usize) {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(my_tid).task_id;
    // Safe: only the current task updates its own page table root (execve).
    unsafe { task_mut_from_ref(task_id) }.page_table_root = new_pt_root;
}

/// Get the address space ID of the current thread's task.
/// Returns 0 if the thread/task has no address space (kernel context).
pub fn current_aspace_id() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let thread = thread_ref(tid);
    let task = task_ref(thread.task_id);
    task.aspace_id
}

/// Fork the current task: clone address space (COW), create child task+thread.
/// Returns the child thread ID (>0) to the parent, or 0 if fork failed.
/// The child will return 0 from this syscall (set in its exception frame).
pub fn fork_current() -> u64 {
    let cpu = smp::cpu_id() as usize;
    let tid = smp::get(cpu as u32).current_thread.load(Ordering::Relaxed);
    let parent_frame_sp = unsafe { thread_mut_from_ref(tid) }.syscall_frame_sp;
    if parent_frame_sp == 0 {
        return u64::MAX;
    }

    // Enforce RLIMIT_NPROC (lock-free).
    {
        let tid = smp::current().current_thread.load(Ordering::Relaxed);
        let task_id = thread_ref(tid).task_id;
        let task = task_ref(task_id);
        let uid = task.uid;
        let nproc_limit = task.rlimits[super::task::RLIMIT_NPROC as usize].cur;
        if nproc_limit != super::task::RLIM_INFINITY {
            let mut count = 0u64;
            SCHED_TASK_ART.for_each(|key, val| {
                if key == 0 {
                    return;
                }
                let t = unsafe { &*(val as *const Task) };
                if t.active && t.uid == uid {
                    count += 1;
                }
            });
            if count >= nproc_limit {
                return u64::MAX;
            }
        }
    }

    // Gather parent info (lock-free).
    let (
        _parent_tid,
        parent_task_id,
        parent_aspace_id,
        parent_priority,
        parent_quantum,
        parent_sig_mask,
        parent_tls_base,
    ) = {
        let tid = smp::current().current_thread.load(Ordering::Relaxed);
        let thread = thread_ref(tid);
        let task = task_ref(thread.task_id);
        (
            tid,
            thread.task_id,
            task.aspace_id,
            thread.base_priority,
            thread.default_quantum,
            thread.sig_mask,
            thread.tls_base,
        )
    };

    // Clone the address space (COW). This is done outside the scheduler lock
    // because it acquires ASPACES and OBJECTS locks.
    let (child_aspace_id, child_pt_root) = match crate::mm::aspace::clone_for_cow(parent_aspace_id)
    {
        Some(x) => x,
        None => return u64::MAX,
    };

    // Create kernel-held port for child task (outside scheduler lock).
    // We don't know child_task_id yet, so use 0 temporarily — updated in finalize.
    // Actually, we allocate task_id first, then create the port.

    // Create child task and thread under the scheduler lock.
    // Snapshot parent groups + credentials while holding lock.
    let (
        child_task_id,
        parent_pgid,
        parent_sid,
        parent_ctty,
        parent_uid,
        parent_euid,
        parent_gid,
        parent_egid,
        parent_groups_inline,
        parent_groups_overflow,
        parent_ngroups,
        parent_rlimits,
        parent_personality,
        parent_syscall_abi,
        parent_personality_port,
    ) = {
        let _lock = SPAWN_LOCK.lock();
        let child_task_id = match alloc_task_id() {
            Some(id) => id,
            None => return u64::MAX,
        };
        let ptask = task_ref(parent_task_id);
        (
            child_task_id,
            ptask.pgid,
            ptask.sid,
            ptask.ctty_port,
            ptask.uid,
            ptask.euid,
            ptask.gid,
            ptask.egid,
            ptask.groups_inline,
            ptask.groups_overflow,
            ptask.ngroups,
            ptask.rlimits,
            ptask.personality,
            ptask.syscall_abi,
            ptask.personality_port,
        )
    };

    // Outside SCHEDULER lock: create task port + duplicate groups overflow page.
    let child_task_port =
        match crate::ipc::port::create_kernel_port(task_port_handler, child_task_id as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };
    let child_groups_overflow =
        if parent_ngroups as usize > GROUPS_INLINE && parent_groups_overflow != 0 {
            match crate::mm::phys::alloc_page() {
                Some(p) => {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            parent_groups_overflow as *const u8,
                            p.as_usize() as *mut u8,
                            parent_ngroups as usize * core::mem::size_of::<u32>(),
                        );
                    }
                    p.as_usize()
                }
                None => return u64::MAX,
            }
        } else {
            0
        };
    // Set up child task. Re-initialize to empty first to avoid stale fields
    // from a reused task slot (e.g., max_ports from a previous SYS_SET_RLIMIT).
    {
        let task = unsafe { task_mut_from_ref(child_task_id) };
        *task = Task::empty();
        task.id = child_task_id;
        task.active = true;
        task.port_id = child_task_port;
        task.aspace_id = child_aspace_id;
        task.page_table_root = child_pt_root;
        task.exit_code = 0;
        task.exited = false;
        task.reaped = false;
        task.wait_status = 0;
        task.thread_count = 1;
        task.parent_task = parent_task_id;
        // Fork inherits parent's process group, session, ctty, credentials, and rlimits.
        task.pgid = parent_pgid;
        task.sid = parent_sid;
        task.ctty_port = parent_ctty;
        task.fg_pgid = 0; // Only session leader tracks fg_pgid.
        task.uid = parent_uid;
        task.euid = parent_euid;
        task.gid = parent_gid;
        task.egid = parent_egid;
        task.groups_inline = parent_groups_inline;
        task.groups_overflow = child_groups_overflow;
        task.ngroups = parent_ngroups;
        task.rlimits = parent_rlimits;
        // Fork inherits parent's personality (foreign OS emulation state).
        task.personality = parent_personality;
        task.syscall_abi = parent_syscall_abi;
        task.personality_port = parent_personality_port;
    }

    // Bootstrap capabilities: copy parent's capset and grant well-known port caps.
    {
        // Copy the fast-path capset so child inherits parent's port access.
        crate::cap::capset_copy(parent_task_id, child_task_id);

        // Initialize child's embedded capspace.
        {
            let tptr = TASK_TABLE.get(child_task_id) as *mut Task;
            unsafe {
                (*tptr).capspace = crate::cap::CapSpace::new(child_task_id);
            }
        }
        // Grant SEND caps for well-known kernel ports.
        let iramfs =
            crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            crate::cap::grant_send_cap(child_task_id, iramfs);
        }

        // Grant parent and child caps on the child's task port.
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_task_port, srm);
        crate::cap::grant_send_cap(child_task_id, child_task_port);
    }

    // Allocate kernel stack for child thread.
    let kstack_page = match crate::mm::phys::alloc_pages(KSTACK_ORDER) {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + kstack_size();

    // Copy parent's exception frame to child's kernel stack.
    let child_frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame_sp as *const u8,
            child_frame_sp as *mut u8,
            EXCEPTION_FRAME_SIZE,
        );
    }

    // Set child's return value to 0.
    {
        let child_frame =
            unsafe { &mut *(child_frame_sp as *mut crate::syscall::handlers::ExceptionFrame) };
        crate::syscall::handlers::set_return(child_frame, 0);
    }

    // Allocate child thread ID under SPAWN_LOCK.
    let child_tid = match {
        let _lock = SPAWN_LOCK.lock();
        alloc_thread_id()
    } {
        Some(id) => id,
        None => return u64::MAX,
    };
    let child_thread_port =
        match crate::ipc::port::create_kernel_port(thread_port_handler, child_tid as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Clear killed/affinity flags.
    let thread = unsafe { thread_mut_from_ref(child_tid) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: child enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = child_tid;
    thread.state = ThreadState::Ready;
    thread.task_id = child_task_id;
    thread.port_id = child_thread_port;
    thread.base_priority = parent_priority;
    thread.effective_priority = parent_priority;
    thread.prio.store(parent_priority, Ordering::Relaxed);
    thread.thread_task.store(child_task_id, Ordering::Relaxed);
    thread.quantum = parent_quantum;
    thread.default_quantum = parent_quantum;
    thread.saved_sp = child_frame_sp as u64;
    thread.stack_base = kstack_base;
    thread.exit_code = 0;
    thread.sig_mask = parent_sig_mask;
    thread.sig_pending = 0;
    // Inherit FSBASE from parent — see fork_for_task for details.
    thread.tls_base = parent_tls_base;

    percpu_enqueue(smp::cpu_id(), parent_priority, child_tid);

    // Grant caps on the child's thread port.
    {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let sm = Rights::SEND.union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_thread_port, sm);
        crate::cap::grant_port_cap(child_task_id, child_thread_port, srm);
    }

    // Return child task port_id to parent (nonzero = parent, 0 = child).
    child_task_port
}

/// Fork a target task on behalf of a personality server.
///
/// Same semantics as `fork_current()` but operates on `target_task_id` / `target_tid`
/// instead of the calling thread. The target must be blocked in PersonalityWait.
/// Returns the child task's port_id, or u64::MAX on error.
pub fn fork_for_task(target_task_id: u32, target_tid: u32) -> u64 {
    // Read target's personality exception frame (not saved_sp, which gets
    // overwritten by context switches during block_current spin-wait).
    let parent_frame_sp = thread_ref(target_tid).personality_frame_sp as usize;
    if parent_frame_sp == 0 {
        return u64::MAX;
    }

    // Gather parent info from target task/thread (lock-free).
    let parent_task_id = target_task_id;
    let parent_aspace_id;
    let parent_priority;
    let parent_quantum;
    let parent_sig_mask;
    let parent_tls_base;
    {
        let thread = thread_ref(target_tid);
        let task = task_ref(target_task_id);
        parent_aspace_id = task.aspace_id;
        parent_priority = thread.base_priority;
        parent_quantum = thread.default_quantum;
        parent_sig_mask = thread.sig_mask;
        parent_tls_base = thread.tls_base;

        // RLIMIT_NPROC check.
        let uid = task.uid;
        let nproc_limit = task.rlimits[super::task::RLIMIT_NPROC as usize].cur;
        if nproc_limit != super::task::RLIM_INFINITY {
            let mut count = 0u64;
            SCHED_TASK_ART.for_each(|key, val| {
                if key == 0 { return; }
                let t = unsafe { &*(val as *const Task) };
                if t.active && t.uid == uid { count += 1; }
            });
            if count >= nproc_limit {
                return u64::MAX;
            }
        }
    }

    // Clone the address space (COW).
    let (child_aspace_id, child_pt_root) = match crate::mm::aspace::clone_for_cow(parent_aspace_id)
    {
        Some(x) => x,
        None => return u64::MAX,
    };

    // Snapshot parent credentials/groups under SPAWN_LOCK.
    let (
        child_task_id,
        parent_pgid, parent_sid, parent_ctty,
        parent_uid, parent_euid, parent_gid, parent_egid,
        parent_groups_inline, parent_groups_overflow, parent_ngroups,
        parent_rlimits,
        parent_personality, parent_syscall_abi, parent_personality_port,
    ) = {
        let _lock = SPAWN_LOCK.lock();
        let child_task_id = match alloc_task_id() {
            Some(id) => id,
            None => return u64::MAX,
        };
        let ptask = task_ref(parent_task_id);
        (
            child_task_id,
            ptask.pgid, ptask.sid, ptask.ctty_port,
            ptask.uid, ptask.euid, ptask.gid, ptask.egid,
            ptask.groups_inline, ptask.groups_overflow, ptask.ngroups,
            ptask.rlimits,
            ptask.personality, ptask.syscall_abi, ptask.personality_port,
        )
    };

    // Create child task port.
    let child_task_port =
        match crate::ipc::port::create_kernel_port(task_port_handler, child_task_id as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Duplicate groups overflow page if needed.
    let child_groups_overflow =
        if parent_ngroups as usize > GROUPS_INLINE && parent_groups_overflow != 0 {
            match crate::mm::phys::alloc_page() {
                Some(p) => {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            parent_groups_overflow as *const u8,
                            p.as_usize() as *mut u8,
                            parent_ngroups as usize * core::mem::size_of::<u32>(),
                        );
                    }
                    p.as_usize()
                }
                None => return u64::MAX,
            }
        } else {
            0
        };

    // Initialize child task struct.
    {
        let task = unsafe { task_mut_from_ref(child_task_id) };
        *task = Task::empty();
        task.id = child_task_id;
        task.active = true;
        task.port_id = child_task_port;
        task.aspace_id = child_aspace_id;
        task.page_table_root = child_pt_root;
        task.exit_code = 0;
        task.exited = false;
        task.reaped = false;
        task.wait_status = 0;
        task.thread_count = 1;
        task.parent_task = parent_task_id;
        task.pgid = parent_pgid;
        task.sid = parent_sid;
        task.ctty_port = parent_ctty;
        task.fg_pgid = 0;
        task.uid = parent_uid;
        task.euid = parent_euid;
        task.gid = parent_gid;
        task.egid = parent_egid;
        task.groups_inline = parent_groups_inline;
        task.groups_overflow = child_groups_overflow;
        task.ngroups = parent_ngroups;
        task.rlimits = parent_rlimits;
        task.personality = parent_personality;
        task.syscall_abi = parent_syscall_abi;
        task.personality_port = parent_personality_port;
    }

    // Bootstrap capabilities.
    {
        crate::cap::capset_copy(parent_task_id, child_task_id);
        {
            let tptr = TASK_TABLE.get(child_task_id) as *mut Task;
            unsafe { (*tptr).capspace = crate::cap::CapSpace::new(child_task_id); }
        }
        let iramfs =
            crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            crate::cap::grant_send_cap(child_task_id, iramfs);
        }
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_task_port, srm);
        crate::cap::grant_send_cap(child_task_id, child_task_port);
    }

    // Allocate kernel stack for child thread.
    let kstack_page = match crate::mm::phys::alloc_pages(KSTACK_ORDER) {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + kstack_size();

    // Copy target's exception frame to child's kernel stack.
    let child_frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame_sp as *const u8,
            child_frame_sp as *mut u8,
            EXCEPTION_FRAME_SIZE,
        );
    }

    // Set child's return value to 0.
    {
        let child_frame =
            unsafe { &mut *(child_frame_sp as *mut crate::syscall::handlers::ExceptionFrame) };
        crate::syscall::handlers::set_return(child_frame, 0);
    }

    // Allocate child thread ID.
    let child_tid = match {
        let _lock = SPAWN_LOCK.lock();
        alloc_thread_id()
    } {
        Some(id) => id,
        None => return u64::MAX,
    };
    let child_thread_port =
        match crate::ipc::port::create_kernel_port(thread_port_handler, child_tid as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Initialize child thread.
    let thread = unsafe { thread_mut_from_ref(child_tid) };
    thread.killed.store(false, Ordering::Release);
    thread.affinity_mask.store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: child enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = child_tid;
    thread.state = ThreadState::Ready;
    thread.task_id = child_task_id;
    thread.port_id = child_thread_port;
    thread.base_priority = parent_priority;
    thread.effective_priority = parent_priority;
    thread.prio.store(parent_priority, Ordering::Relaxed);
    thread.thread_task.store(child_task_id, Ordering::Relaxed);
    thread.quantum = parent_quantum;
    thread.default_quantum = parent_quantum;
    thread.saved_sp = child_frame_sp as u64;
    thread.stack_base = kstack_base;
    thread.exit_code = 0;
    thread.sig_mask = parent_sig_mask;
    thread.sig_pending = 0;
    // Inherit FSBASE from parent.  Without this, the child wakes with
    // tls_base=0, and any compiler-emitted `%fs:0x28` access (e.g. glibc's
    // internal stack-canary loads) faults on first context switch
    // (project_step_g_flakes.md: CR2=0x28, RIP in compositor canary check).
    thread.tls_base = parent_tls_base;

    percpu_enqueue(smp::cpu_id(), parent_priority, child_tid);

    // Grant caps on child's thread port.
    {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        let sm = Rights::SEND.union(Rights::MANAGE);
        crate::cap::grant_port_cap(parent_task_id, child_thread_port, sm);
        crate::cap::grant_port_cap(child_task_id, child_thread_port, srm);
    }

    child_task_port
}

/// Clone a new thread within the same task (CLONE_VM | CLONE_THREAD semantics).
///
/// Copies the parent thread's exception frame, sets return value to 0, applies
/// the new stack pointer and TLS base.  The new thread resumes at the same IP
/// as the parent — exactly what Linux clone(CLONE_VM|CLONE_THREAD) expects.
///
/// `tls_base` of 0 means "inherit from parent" (matches Linux clone semantics
/// when CLONE_SETTLS is not set — the child inherits the parent's TLS, NOT a
/// zero TLS base, otherwise glibc internal `%fs:0xN` accesses fault).
///
/// Returns the new thread's port_id, or u64::MAX on error.
pub fn clone_thread_in_task(
    task_id: u32,
    parent_tid: u32,
    child_stack: u64,
    tls_base: u64,
) -> u64 {
    // Read parent's saved personality exception frame.
    let parent_frame_sp = thread_ref(parent_tid).personality_frame_sp as usize;
    if parent_frame_sp == 0 {
        return u64::MAX;
    }

    let parent_priority = thread_ref(parent_tid).base_priority;
    let parent_quantum = thread_ref(parent_tid).default_quantum;
    let parent_sig_mask = thread_ref(parent_tid).sig_mask;

    // Allocate kernel stack for the new thread.
    let kstack_page = match crate::mm::phys::alloc_pages(KSTACK_ORDER) {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + kstack_size();

    // Copy parent's exception frame to the new thread's kernel stack.
    let child_frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame_sp as *const u8,
            child_frame_sp as *mut u8,
            EXCEPTION_FRAME_SIZE,
        );
    }

    // Set return value to 0 (child sees clone() return 0).
    {
        let child_frame =
            unsafe { &mut *(child_frame_sp as *mut crate::syscall::handlers::ExceptionFrame) };
        crate::syscall::handlers::set_return(child_frame, 0);
        // Set child's user stack pointer.
        if child_stack != 0 {
            crate::arch::trapframe::set_user_sp(child_frame, child_stack as usize);
        }
    }

    // Allocate thread ID and port.
    let child_tid = match {
        let _lock = SPAWN_LOCK.lock();
        alloc_thread_id()
    } {
        Some(id) => id,
        None => return u64::MAX,
    };
    let child_thread_port =
        match crate::ipc::port::create_kernel_port(thread_port_handler, child_tid as usize) {
            Some(p) => p,
            None => return u64::MAX,
        };

    // Initialize the new thread — same task, shared address space.
    let thread = unsafe { thread_mut_from_ref(child_tid) };
    thread.killed.store(false, Ordering::Release);
    thread.affinity_mask.store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);
    // NEW_INV: child enters Ready, so on_cpu = ON_CPU_PENDING.
    thread.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
    thread.in_queue.store(false, Ordering::Release);

    thread.id = child_tid;
    thread.state = ThreadState::Ready;
    thread.task_id = task_id;
    thread.port_id = child_thread_port;
    thread.base_priority = parent_priority;
    thread.effective_priority = parent_priority;
    thread.prio.store(parent_priority, Ordering::Relaxed);
    thread.thread_task.store(task_id, Ordering::Relaxed);
    thread.quantum = parent_quantum;
    thread.default_quantum = parent_quantum;
    thread.saved_sp = child_frame_sp as u64;
    thread.stack_base = kstack_base;
    thread.exit_code = 0;
    thread.sig_mask = parent_sig_mask;
    thread.sig_pending = 0;
    // tls_base = 0 means "inherit from parent" (Linux clone without CLONE_SETTLS).
    thread.tls_base = if tls_base == 0 {
        thread_ref(parent_tid).tls_base
    } else {
        tls_base
    };

    let ts = crate::sync::turnstile::alloc_thread_turnstile();
    thread.turnstile.store(ts, Ordering::Relaxed);

    unsafe { task_mut_from_ref(task_id) }.thread_count += 1;
    percpu_enqueue(smp::cpu_id(), parent_priority, child_tid);

    // Grant caps on the new thread's port.
    {
        use crate::cap::capability::Rights;
        let srm = Rights::SEND.union(Rights::RECV).union(Rights::MANAGE);
        crate::cap::grant_port_cap(task_id, child_thread_port, srm);
    }

    child_thread_port
}

/// Wait for a child of the given target task (non-blocking).
///
/// Like `wait4()` but scans children of `target_task_id` instead of the calling
/// task. Always returns immediately (like WNOHANG behavior).
/// Returns (child_port, child_id, wait_status) or (0, -1, 0) for ECHILD.
pub fn wait4_for_task(target_task_id: u32, pid: i64, flags: u32) -> (u64, i32, i32) {
    let my_pgid = task_ref(target_task_id).pgid;

    let mut found: Option<(u32, i32)> = None;
    let mut has_children = false;
    SCHED_TASK_ART.for_each(|key, val| {
        if found.is_some() || key == 0 { return; }
        let task = unsafe { &*(val as *const Task) };
        if task.parent_task != target_task_id { return; }

        let matches = match pid {
            -1 => true,
            0 => task.pgid == my_pgid,
            p if p > 0 => task.id == p as TaskId,
            p => task.pgid == (-p) as TaskId,
        };
        if !matches { return; }
        has_children = true;

        if task.exited && !task.reaped {
            found = Some((task.id, task.wait_status));
        }
    });

    if let Some((child_id, status)) = found {
        let t = unsafe { task_mut_from_ref(child_id) };
        t.reaped = true;
        let port_id = t.port_id;
        t.port_id = 0;
        if port_id != 0 {
            crate::ipc::port::destroy(port_id);
        }
        (port_id, child_id as i32, status)
    } else if !has_children {
        (0, -1, 0)
    } else {
        (0, 0, 0)
    }
}

/// Terminate the current thread and destroy its task's resources.
/// This function never returns.
pub fn exit_current_thread(exit_code: i32) -> ! {
    // DIAG: confirm this fires for clone3_test child.  Will remove
    // once #136 INVOL-EXIT validation completes.
    {
        let _tmp_tid = smp::current().current_thread.load(Ordering::Relaxed);
        let _tmp_task = thread_ref(_tmp_tid).task_id;
        crate::println!(
            "EXIT-THREAD-ENTRY: tid={} task={} exit={}",
            _tmp_tid, _tmp_task, exit_code
        );
    }
    let (
        tid,
        is_last_thread,
        aspace_id,
        pt_root,
        kstack_base,
        parent_task_id,
        _task_port,
        thread_port,
        task_personality_port,
        task_id_for_exit,
    ) = {
        let pcpu = smp::current();
        let tid = pcpu.current_thread.load(Ordering::Relaxed);
        // Safe: we are the running thread; no contention on our own state.
        let thread = unsafe { thread_mut_from_ref(tid) };
        thread.state = ThreadState::Dead;
        thread.exit_code = exit_code;
        let thread_port = thread.port_id;
        // Wake any thread blocked in thread_join() on us.
        let waiter = thread.join_waiter;
        thread.join_waiter = u32::MAX;
        if waiter != u32::MAX {
            wake_thread(waiter);
        }
        let task_id = thread.task_id;
        let kstack_base = thread.stack_base;
        // NOTE: Do NOT set stack_base=0 here. The thread is still running on
        // its CPU. Setting it to 0 would allow alloc_thread_id to reuse the
        // slot before we're actually off the CPU. Instead, try_switch will set
        // stack_base=0 when it drains DEFERRED_KSTACK (proving the dead thread
        // has been context-switched away).
        // Safe: thread_count decrement needs care for multi-threaded tasks.
        // Use saturating_sub: if a killed thread was already decremented by
        // the scheduler's killed-thread path (try_switch), avoid underflow.
        let task = unsafe { task_mut_from_ref(task_id) };
        task.thread_count = task.thread_count.saturating_sub(1);
        let is_last = task.thread_count == 0;
        let parent_task_id = task.parent_task;
        let task_port = task.port_id;
        let task_personality_port = task.personality_port;
        if is_last {
            task.exit_code = exit_code;
            task.exited = true;
            task.active = false;
            // Encode POSIX wait status: normal exit = (code & 0xFF) << 8.
            task.wait_status = (exit_code & 0xFF) << 8;
        }
        let aspace_id = task.aspace_id;
        let pt_root = task.page_table_root;
        (
            tid,
            is_last,
            aspace_id,
            pt_root,
            kstack_base,
            parent_task_id,
            task_port,
            thread_port,
            task_personality_port,
            task_id,
        )
    };

    // #136 involuntary-exit cleanup: when a thread of a Linux-personality
    // task dies via SIGSEGV/etc. without calling __NR_EXIT, linux_srv
    // never runs handle_exit_thread, so the thread's CLONE_CHILD_CLEARTID
    // address isn't cleared and any FUTEX_WAIT on it (typically
    // pthread_join) hangs forever.  Synthesize a __NR_EXIT message and
    // fire it at linux_srv from kernel context so the cleanup happens.
    //
    // Skip when is_last_thread because:
    //   (a) the leader thread's __NR_EXIT is treated as __NR_EXIT_GROUP
    //       by handle_exit_thread (PROC_TABLE[pi].port == caller_port),
    //       which is the right semantic for "process died"
    //   (b) handle_exit_group also tears down PROC_TABLE state, which we
    //       want to happen exactly once
    //
    // exit_code < 0 marks involuntary exit (signal numbers are negative
    // by Telix convention here): we always want the cleanup, but the
    // log line is more interesting for involuntary deaths.  Fire for
    // all non-last-thread Linux exits to keep behavior uniform.
    if task_personality_port != 0 && !is_last_thread && thread_port != 0 {
        // Tag = (__NR_EXIT=60) | (caller_port << 32).  This matches the
        // shape forward_to_server uses for syscall-forwarded messages.
        const NR_EXIT_LINUX: u64 = 60;
        let msg = crate::ipc::Message {
            tag: NR_EXIT_LINUX | (thread_port << 32),
            data: [exit_code as i64 as u64, 0, 0, 0, 0, 0],
        };
        let send_result = crate::ipc::port::try_send(task_personality_port, msg);
        // Print for ALL non-last-thread Linux exits (voluntary + signal),
        // so we can confirm the cleanup forwarding fires.  Voluntary
        // __NR_EXIT from glibc's pthread bootstrap goes through the
        // kernel's direct shortcut at handlers.rs:262, bypassing
        // linux_srv — without this forward, CLEARTID + FUTEX_WAKE
        // never happen and pthread_join hangs forever.
        crate::println!(
            "INVOL-EXIT: linux thread tid={} task={} port={:#x} exit={} send={}",
            tid, task_id_for_exit, thread_port, exit_code,
            if send_result.is_ok() { "ok" } else { "FAILED" }
        );
    }

    // If the dying thread is holding a reply-cap, deliver a server-died
    // reply to the parked caller so they don't hang forever.
    {
        let tref = thread_ref(tid);
        let handle = tref
            .held_reply_cap
            .swap(u64::MAX, Ordering::AcqRel);
        if handle != u64::MAX {
            let died = crate::ipc::Message::new(
                crate::ipc::call_reply::CALL_REPLY_SERVER_DIED,
                [0; 6],
            );
            match crate::ipc::call_reply::fulfill(handle, &died) {
                crate::ipc::call_reply::FulfillResult::WakeCaller(caller_tid) => {
                    // Inject into the caller's parked frame, then wake.
                    let sp = thread_saved_sp(caller_tid);
                    if sp != 0 {
                        unsafe {
                            use crate::arch::trapframe::ExceptionFrame;
                            let frame = &mut *(sp as *mut ExceptionFrame);
                            crate::syscall::handlers::set_return(frame, 0);
                            crate::syscall::handlers::set_reg(frame, 1, died.tag);
                            crate::syscall::handlers::set_reg(frame, 2, 0);
                            crate::syscall::handlers::set_reg(frame, 3, 0);
                            crate::syscall::handlers::set_reg(frame, 4, 0);
                            crate::syscall::handlers::set_reg(frame, 5, 0);
                            crate::syscall::handlers::set_reg(frame, 6, 0);
                            crate::syscall::handlers::set_reg(frame, 7, 0);
                        }
                    }
                    wake_parked_thread(caller_tid);
                }
                _ => {}
            }
            // free() revokes any grant leases on the cap and returns the
            // slot to the pool. Crucial here: the server is dying, so any
            // grants the caller made into its aspace must be released now
            // to avoid dangling mappings.
            crate::ipc::call_reply::free(handle);
        }

        // Caller-death: if this thread is parked in sys_call (or was about
        // to be), abandon any Pending cap it owns. abandon() revokes its
        // leases so a later server reply cannot reach into a dead aspace.
        crate::ipc::call_reply::abandon_all_for_caller(tid);
    }

    // Clean up turnstile state: dequeue from any wait queue, free pre-allocated turnstile.
    crate::sync::turnstile::cleanup_blocked(tid);
    let tptr = THREAD_TABLE.get(tid) as *const super::thread::Thread;
    let ts_addr = unsafe { (*tptr).turnstile.swap(0, Ordering::Relaxed) };
    crate::sync::turnstile::free_thread_turnstile(ts_addr);

    // Destroy the thread's kernel-held port (outside SCHEDULER lock for lock ordering).
    if thread_port != 0 {
        crate::ipc::port::destroy(thread_port);
    }

    // If this was the last thread (task became zombie), notify parent.
    if is_last_thread {
        // Send SIGCHLD to parent task.
        send_signal_to_task(parent_task_id, super::task::SIGCHLD);
        // Wake any parent threads blocked in WaitChild.
        wake_wait_child_threads(parent_task_id);
    }

    // Only destroy task resources when the last thread exits.
    if is_last_thread {
        // Switch to kernel/boot page table before freeing user page table.
        if pt_root != 0 {
            {
                let boot_root = crate::mm::hat::boot_page_table_root();
                crate::mm::hat::switch_page_table(boot_root);
            }
        }

        // Free groups overflow page if allocated.
        {
            let exit_task_id = thread_ref(tid).task_id;
            let tptr = TASK_TABLE.get(exit_task_id) as *mut Task;
            unsafe {
                (*tptr).free_groups_overflow();
            }
        }

        // Destroy address space (frees VMAs, backing pages, and PT tree).
        if aspace_id != 0 {
            crate::mm::aspace::destroy(aspace_id);
        }
    }

    // NOTE: Do NOT destroy the task port here — the parent still needs it
    // to call waitpid/wait4 (which resolve port_id → task_id). The task
    // port is destroyed when the zombie is reaped.

    // Auto-reap zombie children of this exiting task (prevent zombie leaks).
    if is_last_thread {
        let my_task_id = thread_ref(tid).task_id;
        let mut zombie_ports = [0u64; 32];
        let mut nz = 0usize;
        // Lock-free: only the parent task reaps its zombie children.
        SCHED_TASK_ART.for_each(|key, val| {
            if key == 0 {
                return;
            }
            let task = unsafe { &mut *(val as *mut Task) };
            if task.parent_task == my_task_id && task.exited && !task.reaped {
                task.reaped = true;
                if task.port_id != 0 && nz < 32 {
                    zombie_ports[nz] = task.port_id;
                    task.port_id = 0;
                    nz += 1;
                }
            }
        });
        for i in 0..nz {
            crate::ipc::port::destroy(zombie_ports[i]);
        }
    }

    // Defer freeing our own kernel stack — we're running on it.
    // Also store our thread ID so try_switch can mark the slot as reusable.
    let cpu = smp::cpu_id();
    deferred_thread()[cpu as usize].store(tid as usize, Ordering::Release);
    deferred_kstack()[cpu as usize].store(kstack_base, Ordering::Release);

    // Enable interrupts so the timer can preempt us (we may be in a syscall
    // handler where hardware masked IRQs on exception entry).
    crate::arch::irq::enable();

    // Request immediate preemption on the next tick so we don't waste a
    // full quantum spinning.  Don't use WFI/HLT here: on the next timer
    // IRQ, try_switch() will switch us to a different thread, and on the
    // tick after that it will free our kstack page.  HLT's resume path
    // needs a valid stack, and spin_loop() is purely in-register.
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    thread_ref(tid).yield_asap.store(true, Ordering::Release);
    loop {
        core::hint::spin_loop();
    }
}

// --- IRQ helpers for blocking paths (delegate to arch::irq) ---

/// Save current interrupt state and enable IRQs. Returns saved state.
/// Public so drivers (e.g. virtio_blk) can use polling with WFI.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_irq_save_enable() -> usize {
    crate::arch::irq::save_and_enable()
}

/// Restore interrupt state.
/// Public so drivers (e.g. virtio_blk) can use polling with WFI.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_irq_restore(saved: usize) {
    crate::arch::irq::restore(saved);
}

/// Wait for next interrupt (WFI/HLT). Public for sys_yield.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_wait_for_irq() {
    crate::arch::irq::wait_for_interrupt();
}

/// Check if a child thread's task has exited. Returns exit code if so.
/// Also reaps the child (marks reaped=true) so the task slot can be reused.
pub fn waitpid(child_task_id: TaskId) -> Option<i32> {
    let task = match task_ref_opt(child_task_id) {
        Some(t) => t,
        None => return None,
    };
    if !task.exited {
        return None;
    }
    let port_id = task.port_id;
    let code = task.exit_code;
    // Safe: only the parent reaps a child, and only once.
    let t = unsafe { task_mut_from_ref(child_task_id) };
    t.reaped = true;
    t.port_id = 0; // prevent double-destroy
    if port_id != 0 {
        crate::ipc::port::destroy(port_id);
    }
    Some(code)
}

/// POSIX wait flags.
pub const WNOHANG: u32 = 1;
#[allow(dead_code)]
pub const WUNTRACED: u32 = 2;
#[allow(dead_code)]
pub const WCONTINUED: u32 = 8;

/// Wake all threads in a given task that are blocked in WaitChild.
fn wake_wait_child_threads(task_id: TaskId) {
    let mut to_wake = [0u32; 64];
    let mut count = 0usize;
    SCHED_THREAD_ART.for_each(|key, val| {
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id
            && t.state != ThreadState::Dead
            && t.stack_base != 0
            && t.blocked_on == BlockReason::WaitChild
        {
            if count < 64 {
                to_wake[count] = key as u32;
                count += 1;
            }
        }
    });
    for i in 0..count {
        wake_thread(to_wake[i]);
    }
}

/// Enhanced wait4: wait for child process exit with POSIX semantics.
///
/// `pid` semantics:
///   - pid > 0: wait for child with task_id == pid
///   - pid == -1: wait for any child
///   - pid == 0: wait for any child in caller's process group
///   - pid < -1: wait for any child in process group |pid|
///
/// Returns (child_task_port_id, child_task_id, wait_status) or (0, -1, 0) on error,
/// or (0, 0, 0) for WNOHANG with no exited child.
pub fn wait4(pid: i64, flags: u32) -> (u64, i32, i32) {
    let tid = current_thread_id();

    loop {
        let my_task_id = thread_ref(tid).task_id;
        let my_pgid = task_ref(my_task_id).pgid;

        // Scan for a matching exited (zombie) child (lock-free).
        let mut found: Option<(u32, i32)> = None;
        let mut has_children = false;
        SCHED_TASK_ART.for_each(|key, val| {
            if found.is_some() {
                return;
            }
            if key == 0 {
                return;
            }
            let task = unsafe { &*(val as *const Task) };
            if task.parent_task != my_task_id {
                return;
            }

            // Check pid filter.
            let matches = match pid {
                -1 => true,                           // any child
                0 => task.pgid == my_pgid,            // same pgroup
                p if p > 0 => task.id == p as TaskId, // specific task
                p => task.pgid == (-p) as TaskId,     // specific pgroup
            };
            if !matches {
                return;
            }
            has_children = true;

            if task.exited && !task.reaped {
                found = Some((task.id, task.wait_status));
            }
        });

        if let Some((child_id, status)) = found {
            // Reap the child. Safe: only the parent reaps, and only once.
            let t = unsafe { task_mut_from_ref(child_id) };
            t.reaped = true;
            let port_id = t.port_id;
            t.port_id = 0; // prevent double-destroy
            if port_id != 0 {
                crate::ipc::port::destroy(port_id);
            }
            return (port_id, child_id as i32, status);
        } else if !has_children {
            // No matching children at all — ECHILD.
            return (0, -1, 0);
        } else if flags & WNOHANG != 0 {
            return (0, 0, 0);
        } else {
            // Block: set blocked_on before entering block_current.
            clear_wakeup_flag(tid);
            unsafe { thread_mut_from_ref(tid) }.blocked_on = BlockReason::WaitChild;
            block_current(BlockReason::WaitChild);
        }
    }
}

/// Boost a thread's effective priority if `to_prio` is higher (lower number).
/// Lock-free: uses atomic CAS on prio + direct write to effective_priority.
///
/// For EEVDF (SCHED_NORMAL) threads boosted into the RT range (< 128),
/// the thread is temporarily promoted to SCHED_RT so that `percpu_enqueue`
/// routes it to the RT bitmap on its next enqueue.  If the thread is
/// currently sitting in an EEVDF heap, we tighten its deadline to zero
/// so that it is the next thread picked from the heap, after which the
/// RT routing kicks in.
pub fn boost_priority(tid: ThreadId, to_prio: u8) {
    let tref = thread_ref(tid);
    // CAS loop: only boost if current prio is lower (higher number).
    loop {
        let cur = tref.prio.load(Ordering::Relaxed);
        if to_prio >= cur {
            break;
        } // already at equal or higher priority
        if tref
            .prio
            .compare_exchange_weak(cur, to_prio, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let t = unsafe { thread_mut_from_ref(tid) };
            t.effective_priority = to_prio;
            // Promote SCHED_NORMAL → SCHED_RT for priority inheritance.
            // On next enqueue, percpu_enqueue will route to the RT bitmap.
            if t.sched_class == SCHED_NORMAL && to_prio < 128 {
                t.sched_class = super::thread::SCHED_RT;
                // If the thread is in an EEVDF heap, tighten its deadline
                // to zero so it is picked first at the next class_pick_next.
                let heap_pos = t.eevdf_heap_pos;
                if heap_pos != super::heap::HEAP_POS_NONE {
                    let cpu = tref.last_cpu.load(Ordering::Relaxed) as usize;
                    let mut rq = percpu_rq()[cpu].lock();
                    // Re-check under lock — may have been popped or stolen.
                    let pos = t.eevdf_heap_pos;
                    if pos != super::heap::HEAP_POS_NONE {
                        rq.eevdf_heap.decrease_key(pos as usize, 0);
                    }
                }
            }
            break;
        }
    }
}

/// Reset a thread's effective priority back to its base priority.
/// Lock-free: uses atomic store on prio + direct write to effective_priority.
///
/// If the thread was temporarily promoted to SCHED_RT by `boost_priority`,
/// restore it to SCHED_NORMAL so subsequent enqueues route through EEVDF.
pub fn reset_priority(tid: ThreadId) {
    let tref = thread_ref(tid);
    let base = tref.base_priority;
    tref.prio.store(base, Ordering::Release);
    let t = unsafe { thread_mut_from_ref(tid) };
    t.effective_priority = base;
    // Restore scheduling class if temporarily promoted by PI.
    // (No threads are permanently SCHED_RT today; SCHED_IDLE is never boosted.)
    if t.sched_class == super::thread::SCHED_RT {
        t.sched_class = SCHED_NORMAL;
    }
}

/// Get a thread's current effective priority (lock-free).
pub fn thread_effective_priority(tid: ThreadId) -> u8 {
    if (tid as usize) < RadixTable::capacity() {
        thread_ref(tid).prio.load(Ordering::Acquire)
    } else {
        255
    }
}

/// Boost receiver's priority from the sender (no-op for queued messages).
///
/// Priority inheritance for IPC is handled via two mechanisms:
/// 1. call/reply: the reply-cap mechanism in recv_with_cap does
///    donate_priority from the caller's thread — this is authoritative.
/// 2. DirectTransfer (send): the sys_send/sys_send_nb handlers call
///    boost_priority directly with the sender's effective priority when
///    a parked receiver is found.
///
/// For queued messages there is no synchronous relationship between
/// sender and receiver, so no priority inheritance is needed.
#[inline(always)]
pub fn boost_priority_from_sender(_receiver_tid: ThreadId, _data4: &mut u64) {
    // Intentional no-op — see doc comment above.
}

// --- L4-style handoff scheduling ---

/// Store the current frame SP for use by park/handoff functions.
/// Called by the arch exception handler before dispatching a syscall.
pub fn store_frame_sp(sp: u64) {
    let cpu = smp::cpu_id() as usize;
    current_frame_sp()[cpu].store(sp, Ordering::Release);
    // Also store per-thread so the value survives preemptive CPU migration.
    let tid = smp::get(cpu as u32).current_thread.load(Ordering::Relaxed);
    unsafe { thread_mut_from_ref(tid) }.syscall_frame_sp = sp;
}

/// Read the current exception frame SP for a given CPU.
pub fn read_frame_sp(cpu: usize) -> u64 {
    current_frame_sp()[cpu].load(Ordering::Acquire)
}

/// Take (read and clear) any pending context switch SP.
/// Called by the arch exception handler after syscall dispatch returns.
/// Returns 0 if no switch is pending.
pub fn take_pending_switch() -> u64 {
    let cpu = smp::cpu_id() as usize;
    pending_switch_sp()[cpu].swap(0, Ordering::AcqRel)
}

/// Clear the park-switch-pending flag for the given CPU.  Called at the
/// **start** of the arch exception handler — by that point the previous
/// exception's `mov rsp, rax` (stack switch) has completed and the old
/// thread's kernel stack is no longer in use.  This unblocks
/// `wake_parked_thread`'s spin-wait.
pub fn clear_pending_switch(cpu: usize) {
    // Phase-5b stall instrumentation (aarch64-only).  If aarch64 IRQ
    // entry never calls this, this counter stays 0 — direct evidence
    // that the parking CPU never clears `stack_switch_pending`, so
    // `wake_parked_thread` is forced down the IPI path forever.
    #[cfg(target_arch = "aarch64")]
    {
        if cpu < crate::arch::aarch64::irq::PER_CPU_CLEAR_SWITCH_COUNT.len() {
            crate::arch::aarch64::irq::PER_CPU_CLEAR_SWITCH_COUNT[cpu]
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    park_switch_pending()[cpu].store(false, Ordering::Release);
    // Also clear the per-thread stack_switch_pending for whatever thread
    // was parked on this CPU. The assembly stack switch is now complete.
    let pt = parked_tid();
    if cpu < pt.len() {
        let tid = pt[cpu].swap(u32::MAX, Ordering::AcqRel);
        if tid != u32::MAX {
            let tref = thread_ref(tid);
            tref.stack_switch_pending.store(false, Ordering::Release);

            // SeqCst fence — pairs with the matching fence in
            // `wake_parked_thread` between its CAS PARK_COMMITTED→PARK_WOKEN
            // and its load of `stack_switch_pending`.  Loom found that on
            // a non-TSO ISA (aarch64/riscv64) a waker's Acquire load of
            // `stack_switch_pending` after observing PARK_COMMITTED can
            // legally return the older `true` value (set by
            // `park_current_for_ipc` before its commit-CAS), missing this
            // CPU's later `store(false)` — even though program order on
            // *this* CPU is store-false then CAS-WOKEN→NONE.  Without a
            // total order across the two variables the waker takes the
            // slow IPI path, the IPI lands here after `parked_tid` has
            // been swapped to MAX, and no-one ever enqueues the woken
            // thread → permanent lost wakeup.  SeqCst fences on both
            // sides give us a single total order: either this store(false)
            // is before the waker's load (waker reads false, takes fast
            // path), or our CAS reads PARK_WOKEN (we win arbitration and
            // enqueue here).  x86 TSO already provides this implicitly,
            // so the fence is a no-op there in practice.
            core::sync::atomic::fence(Ordering::SeqCst);

            // Self-enqueue handshake: if a wake already fired while we
            // were stack-switching, it left park_state = PARK_WOKEN and
            // skipped the enqueue (waiting for us).  CAS WOKEN → NONE
            // to claim ownership; if we win, do the percpu_enqueue
            // here on the local (parking) CPU.  If wake's fast path
            // beat us, the CAS fails and we no-op.
            if tref
                .park_state
                .compare_exchange(PARK_WOKEN, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let prio = tref.prio.load(Ordering::Acquire);
                tref.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Ready;
                trace_sched(tid, 16); // 16 = ipc_wake (deferred enqueue path)
                set_enq_tag(8); // 8 = clear_pending_switch deferred enqueue
                percpu_enqueue(cpu as u32, prio, tid);
                // We're already on the parking CPU and about to return
                // from the exception that triggered this clear; setting
                // need_resched ensures the return picks up the newly
                // enqueued thread.
                smp::get(cpu as u32).need_resched.store(true, Ordering::Release);
                trace_point("clear_pending_switch.deferred_enqueue", tid as u32);
            }
        }
    }
}

/// Check if a pending context switch is queued on this CPU.
/// Used by syscall dispatch to detect that park_current_for_ipc or handoff_to
/// changed `current_thread` — callers must skip thread-specific epilogue
/// (signal delivery, is_killed) since those queries would use the wrong thread.
pub fn has_pending_switch() -> bool {
    let cpu = smp::cpu_id() as usize;
    pending_switch_sp()[cpu].load(Ordering::Acquire) != 0
}

/// Get a thread's IPC-injection frame SP. Used by inject_recv_into_frame
/// and inject_fault_into_frame to write into a parked thread's syscall
/// exception frame. Returns ipc_frame_sp (set by pre_save_frame), which
/// is immune to timer-driven try_switch overwriting saved_sp.
pub fn thread_saved_sp(tid: ThreadId) -> u64 {
    let t = thread_ref(tid);
    let ipc = t.ipc_frame_sp;
    if ipc != 0 { ipc } else { t.saved_sp }
}

/// Park the current thread for IPC (true off-CPU park).
/// Saves the current SP from CURRENT_FRAME_SP, marks the thread Blocked,
/// picks the next runnable thread, and stores its SP in PENDING_SWITCH_SP.
/// The exception handler will complete the switch on return.
///
/// Park state constants for the IPC park protocol.
/// See `park_current_for_ipc` and `wake_parked_thread`.
pub const PARK_NONE: u8 = 0;
pub const PARK_ENQUEUED: u8 = 1;
pub const PARK_COMMITTED: u8 = 2;
/// Wake fired while the thread was at COMMITTED but its parking CPU
/// hadn't completed the assembly stack switch yet.  Whoever first
/// CAS's `WOKEN → NONE` claims responsibility for `percpu_enqueue`-ing
/// the thread:
///   - `wake_parked_thread` itself, if it observes `stack_switch_pending`
///     already cleared (fast path: stack switch was already done).
///   - `clear_pending_switch` on the parking CPU, on its next exception
///     entry after the assembly switch completes.
/// The arbitration eliminates the unbounded spin that the previous
/// design had in `wake_parked_thread` (waiting for the parking CPU to
/// finish its `mov rsp, rax` switch); under KVM virt-timer coalescing
/// that spin was the dominant cost of `sys_reply` (~17 ms avg of 24 ms
/// total handler time per boot 418's reply-time split data).
pub const PARK_WOKEN: u8 = 3;

/// Pre-save the current exception frame pointer into the thread's `saved_sp`
/// and set park_state to PARK_ENQUEUED.
///
/// Must be called BEFORE the thread becomes visible in a HAMT turnstile
/// (via `port_enqueue_with_check`), so that if a sender dequeues the thread
/// and calls `inject_recv_into_frame` before `park_current_for_ipc` runs,
/// the injection writes to the correct frame.
pub fn pre_save_frame(tid: ThreadId) {
    let frame_sp = unsafe { thread_mut_from_ref(tid) }.syscall_frame_sp;
    let t = unsafe { thread_mut_from_ref(tid) };
    t.saved_sp = frame_sp;
    t.saved_sp_source = 3; // pre_save_frame
    t.ipc_frame_sp = frame_sp;
    // Clear stale wakeup flag from a prior block_current iteration. Without
    // this, a SIGCHLD that called wake_thread on a thread that then exited
    // block_current and did a fresh sys_call would leave wakeup=true across
    // the park boundary, making rescue_orphaned_threads falsely detect the
    // new call as stuck.
    thread_ref(tid).wakeup.store(false, Ordering::Release);
    // Publish saved_sp/ipc_frame_sp before becoming visible. The Release on
    // park_state ensures both fields are visible to any thread that reads
    // park_state ≥ 1.
    thread_ref(tid).park_state.store(PARK_ENQUEUED, Ordering::Release);
}

/// Unlike block_current() which spins on-CPU, this truly takes the thread
/// off the run queue and saves its frame for later injection by a sender.
///
/// Uses a CAS-based state machine with `wake_parked_thread` to handle the
/// race where a sender dequeues and wakes us between HAMT enqueue and this
/// function. The caller must have already called `pre_save_frame()` (which
/// sets park_state = PARK_ENQUEUED) and `port_enqueue_with_check()`.
pub fn park_current_for_ipc(reason: BlockReason) {
    // Disable IRQs for the entire function. With preemptive syscalls, a
    // timer firing after state=Blocked would let try_switch see a Blocked
    // thread still on-CPU, overwrite state to Ready, and re-enqueue it —
    // creating a double-schedule with the IPC HAMT entry.
    let irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id() as usize;
    drain_deferred_requeue(cpu as u32);

    let cpu_idx = cpu as u32;
    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Re-assign saved_sp from syscall_frame_sp. pre_save_frame set it
    // earlier, but try_switch may have overwritten saved_sp if a timer
    // preempted us between pre_save_frame and this point.
    // syscall_frame_sp is set once at syscall entry (store_frame_sp) and
    // never touched by try_switch, so it always holds the correct value.
    let t = unsafe { thread_mut_from_ref(tid as ThreadId) };
    t.saved_sp = t.syscall_frame_sp;
    t.saved_sp_source = 3; // park_ipc
    t.state = ThreadState::Blocked;
    t.blocked_on = reason;

    // Record wall-clock time for CallReply timeout sweep.
    if matches!(reason, BlockReason::CallReply(_)) {
        thread_ref(tid as ThreadId).call_blocked_ns.store(
            get_monotonic_ns(),
            Ordering::Release,
        );
        trace_point("park_ipc.CallReply", tid as u32);
    }

    // Release on_cpu BEFORE committing park_state. Once park_state is
    // COMMITTED, wake_parked_thread may re-enqueue us on any CPU. If
    // on_cpu still holds a stale CPU value at that point, the scheduling
    // CPU's CAS will fail (DOUBLE-SCHED). By clearing on_cpu first, we
    // ensure the re-enqueued thread passes the CAS.
    if (tid as ThreadId) != idle_id {
        thread_ref(tid as ThreadId).on_cpu.store(u32::MAX, Ordering::Release);
    }
    trace_sched(tid as u32, 14); // 14=park_ipc (state=Blocked, on_cpu=MAX)

    // Mark per-thread stack_switch_pending BEFORE park_state CAS. Once
    // COMMITTED, wake_parked_thread may fire on another CPU. It spins on
    // this per-thread flag (not the per-CPU one) to wait for our assembly
    // stack switch. Cleared by clear_pending_switch at exception entry.
    thread_ref(tid as ThreadId).stack_switch_pending.store(true, Ordering::Release);
    parked_tid()[cpu].store(tid as u32, Ordering::Release);

    // Try to commit the park: CAS PARK_ENQUEUED → PARK_COMMITTED.
    // If this fails, wake_parked_thread already CAS'd PARK_ENQUEUED → PARK_NONE,
    // meaning a sender woke us before we could switch out. The message is
    // already injected into our saved frame — just undo Blocked and return.
    if thread_ref(tid as ThreadId)
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_COMMITTED, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // Early wake — no switch will happen. Clear per-thread flag.
        thread_ref(tid as ThreadId).stack_switch_pending.store(false, Ordering::Release);
        parked_tid()[cpu].store(u32::MAX, Ordering::Release);
        // Restore on_cpu.
        if (tid as ThreadId) != idle_id {
            thread_ref(tid as ThreadId).on_cpu.store(cpu_idx, Ordering::Release);
        }
        t.state = ThreadState::Running;
        return;
    }

    // Read SA state (lock-free).
    let parked_task_id = t.task_id;
    let sa_enabled = task_ref(parked_task_id).sa_enabled;

    // Pick next thread from per-CPU queue (don't re-enqueue current — it's Blocked).
    let next_id = percpu_pick_next(cpu_idx, idle_id);
    let prev_task = thread_ref(tid as ThreadId).task_id;
    let next_task = thread_ref(next_id).task_id;
    if prev_task != next_task {
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + kstack_size());

    // on_cpu for parked thread was released above (before park_state CAS).
    // Claim on_cpu for next (ON_CPU_PENDING → cpu).
    if next_id != idle_id {
        if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu_idx, Ordering::AcqRel, Ordering::Acquire,
        ) {
            crate::println!(
                "DOUBLE-SCHED(park): tid={} already on cpu={}, this cpu={}",
                next_id, other_cpu, cpu_idx
            );
            thread_ref(next_id).killed.store(true, Ordering::Release);
            // Pick idle instead.
            let idle_sp2 = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            pcpu.current_thread.store(idle_id, Ordering::Relaxed);
            pending_switch_sp()[cpu].store(idle_sp2, Ordering::Release);
            return;
        }
        thread_ref(next_id).on_cpu_set_by.store(3, Ordering::Relaxed); // 3=park_ipc
        // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
        dispatch_cas_ok(pcpu, next_id);
        // Set Running IMMEDIATELY after CAS — close TOCTOU window (see try_switch).
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    } else {
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    // Safety: next_id was just dequeued, we own it.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    let next_sp = next_t.saved_sp;

    // Sanity check: saved_sp must be within the thread's kstack.
    // Idle threads run on boot stacks (ring 0), not their allocated kstack.
    {
        let is_idle = next_id == idle_id;
        let kbase = next_t.stack_base;
        let kend = kbase as u64 + kstack_size() as u64;
        if !is_idle && (next_sp < kbase as u64 || next_sp >= kend) {
            crate::println!(
                "BUG: park_ipc: tid={} saved_sp={:#x} OUTSIDE kstack {:#x}..{:#x} (source={})",
                next_id, next_sp, kbase, kend, next_t.saved_sp_source
            );
            // Kill this thread and switch to idle instead.
            thread_ref(next_id).killed.store(true, Ordering::Release);
            let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            pcpu.current_thread.store(idle_id, Ordering::Relaxed);
            pending_switch_sp()[cpu].store(idle_sp, Ordering::Release);
            return;
        }
    }

    // Reprogram the one-shot timer so this CPU gets a tick within one
    // interval. Without this, the dynamic tick may have the timer set far
    // in the future (up to MAX_IDLE_NS = 1s). If a remote CPU wakes us via
    // wake_parked_thread and enqueues on this CPU, the enqueued thread would
    // sit in the run queue until the next timer fires. A prompt tick ensures
    // try_switch() picks it up quickly.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);

    // Mark that this CPU has a park-triggered stack switch pending.
    // wake_parked_thread spins on this flag to wait for our assembly switch.
    park_switch_pending()[cpu].store(true, Ordering::Release);

    // Store pending_switch and do SA notification BEFORE restoring IRQs.
    // With preemptive syscalls, a timer between current_thread update and
    // the exception handler consuming pending_switch would corrupt state:
    // try_switch would see the wrong current_thread on the old thread's stack.
    pending_switch_sp()[cpu].store(next_sp, Ordering::Release);

    // Scheduler activation: notify userspace that a kthread blocked.
    if sa_enabled {
        let tptr = TASK_TABLE.get(parked_task_id) as *mut Task;
        let task = unsafe { &*tptr };
        let waiter = task.sa_waiter.load(Ordering::Acquire);
        if waiter != u32::MAX && waiter as usize != tid {
            task.sa_event.store(tid as u64, Ordering::Release);
            task.sa_pending.store(true, Ordering::Release);
            wake_thread(waiter);
        }
    }

    // Leave IRQs disabled — the exception handler will consume pending_switch
    // and perform the actual stack switch via iretq/eret/sret. Restoring IRQs
    // here would open a window where current_thread != physical stack.
    let _ = irq_saved;
}

/// Wake a parked thread by marking it Ready and enqueueing it.
///
/// Uses a CAS-based state machine with `park_current_for_ipc`:
/// - CAS PARK_ENQUEUED → PARK_NONE: early wake (thread not yet off-CPU).
///   The thread is still running; park_current_for_ipc's CAS will fail and
///   it will skip the context switch. We must NOT enqueue (thread is running).
/// - CAS PARK_COMMITTED → PARK_NONE: normal wake (thread is off-CPU).
///   Set state = Ready and enqueue on a run queue.
pub fn wake_parked_thread(tid: ThreadId) {
    let tref = thread_ref(tid);
    trace_point("wake_parked.entry", tid as u32);

    // Try early wake: CAS PARK_ENQUEUED → PARK_NONE.
    // If the thread hasn't committed to parking yet, just prevent the park.
    // park_current_for_ipc's CAS(ENQUEUED→COMMITTED) will fail and it will
    // undo its Blocked state and continue running.
    if tref
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        trace_point("wake_parked.early_wake", tid as u32);
        record_wake_trace(tid, 1, smp::cpu_id(), u32::MAX);
        unsafe { thread_mut_from_ref(tid) }.ipc_frame_sp = 0;
        return;
    }

    // Try normal wake: CAS PARK_COMMITTED → PARK_WOKEN.
    // Thread is at COMMITTED, but its parking CPU may not have completed
    // the assembly stack switch yet.  Transition to PARK_WOKEN and let
    // arbitration decide who enqueues:
    //   - This wake's fast path (if stack_switch_pending is already false)
    //   - clear_pending_switch on the parking CPU (deferred path)
    // The CAS PARK_WOKEN → PARK_NONE is the arbitration: whoever wins
    // does the enqueue, the other no-ops.  No spin.
    if tref
        .park_state
        .compare_exchange(PARK_COMMITTED, PARK_WOKEN, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        trace_point("wake_parked.committed_wake", tid as u32);
        unsafe { thread_mut_from_ref(tid) }.ipc_frame_sp = 0;
        let waker_cpu = smp::cpu_id();
        let parking_cpu = tref.last_cpu.load(Ordering::Relaxed);

        // SeqCst fence — pairs with the matching fence in
        // `clear_pending_switch` between its `stack_switch_pending.store(false)`
        // and its CAS PARK_WOKEN→PARK_NONE.  Loom found that on a non-TSO
        // ISA (aarch64/riscv64) without this fence the Acquire load below
        // can legally observe the *older* `true` value — set by
        // `park_current_for_ipc` before its commit-CAS — even though the
        // parking CPU's `clear_pending_switch` has already stored `false`
        // and given up on the WOKEN→NONE CAS (which then fails because we
        // hadn't reached this point yet).  Result: we'd take the slow IPI
        // path, but `parked_tid` is already MAX so the IPI's
        // `clear_pending_switch` no-ops → permanent lost wakeup.  With
        // SeqCst fences on both sides, store(false) and the load below
        // are totally ordered, so either we read `false` and take the
        // fast path, or `clear_pending_switch` reads `PARK_WOKEN` and
        // enqueues on its side.  x86 TSO already provides this implicitly.
        // Surgical fence preferred over upgrading the bool's load/store to
        // SeqCst because only this one fast-path read needs the
        // cross-variable ordering — the spin-wait readers at handlers.rs
        // L843, scheduler.rs L3526 / L6303 reload until they see false and
        // are not vulnerable to the stale-read window.
        core::sync::atomic::fence(Ordering::SeqCst);

        // Fast path: stack switch already complete.  We can safely do
        // the enqueue ourselves and apply steal-to-waker re-targeting.
        if !tref.stack_switch_pending.load(Ordering::Acquire) {
            if tref
                .park_state
                .compare_exchange(PARK_WOKEN, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let prio = tref.prio.load(Ordering::Acquire);
                let target = parking_cpu;
                // NEW_INV: store ON_CPU_PENDING BEFORE state=Ready.
                tref.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Ready;
                trace_sched(tid, 16);
                set_enq_tag(6);
                percpu_enqueue(target, prio, tid);
                if target == waker_cpu {
                    smp::get(waker_cpu).need_resched.store(true, Ordering::Release);
                    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
                    trace_point("wake_parked.local_resched", tid as u32);
                } else {
                    crate::arch::irq::send_reschedule_ipi(target);
                    trace_point("wake_parked.remote_ipi", tid as u32);
                }
                record_wake_trace(tid, 2, waker_cpu, parking_cpu);
                return;
            }
            // CAS failed: clear_pending_switch beat us.  It already
            // enqueued.  Done.
            trace_point("wake_parked.lost_to_cps", tid as u32);
            record_wake_trace(tid, 3, waker_cpu, parking_cpu);
            return;
        }

        // Slow path: stack switch still pending.  Don't enqueue here.
        // Send IPI so the parking CPU wakes from HLT and runs its
        // exception entry — clear_pending_switch will then see
        // PARK_WOKEN and do the enqueue locally.  This is what
        // eliminates the unbounded spin: wake's worst-case latency
        // is now bounded by the IPI delivery + parking CPU's
        // exception entry path, not by the parking CPU's vCPU
        // de-scheduling under KVM.
        if parking_cpu == waker_cpu {
            // We are the parking CPU (rare — wake fired while still on
            // syscall path before exception return).  Set need_resched
            // and reprogram timer so exception entry runs promptly.
            smp::get(waker_cpu).need_resched.store(true, Ordering::Release);
            crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);
            trace_point("wake_parked.deferred_local", tid as u32);
            record_wake_trace(tid, 4, waker_cpu, parking_cpu);
        } else {
            crate::arch::irq::send_reschedule_ipi(parking_cpu);
            trace_point("wake_parked.deferred_ipi", tid as u32);
            record_wake_trace(tid, 5, waker_cpu, parking_cpu);
        }
    } else {
        // Both CAS operations failed — park_state is now NONE or WOKEN.
        // If WOKEN, an earlier wake already fired and the enqueue path is
        // in flight (either via clear_pending_switch or the previous
        // wake's fast path) — duplicate wake is a no-op.
        // If NONE, the thread was already woken or never parked.  If this
        // happens on a thread that was just dequeued from the turnstile
        // for IPC injection, the injected message is lost (thread is
        // already running and will return with stale frame data).
        let state = tref.park_state.load(Ordering::Acquire);
        if state == PARK_WOKEN {
            trace_point("wake_parked.dup_wake", tid as u32);
            record_wake_trace(tid, 6, smp::cpu_id(), u32::MAX);
            return;
        }
        record_wake_trace(tid, 7, smp::cpu_id(), u32::MAX);
        let tstate = unsafe { thread_mut_from_ref(tid) }.state;
        let blocked = unsafe { thread_mut_from_ref(tid) }.blocked_on;
        crate::println!(
            "WAKE-PARK-NOOP: tid={} park_state={} thread_state={:?} blocked_on={:?} on_cpu={}",
            tid, state, tstate, blocked, tref.on_cpu.load(Ordering::Relaxed)
        );
    }
}

/// Force-wake CallReply-blocked threads that have been parked longer than
/// CALL_REPLY_TIMEOUT_NS.  Uses the same abandon_for_interrupt CAS as the
/// signal-interrupt path to safely coordinate with concurrent server replies.
/// Called periodically from tick() on CPU 0 (~every 1 second).
///
/// 30s (was 10s) — under heavy lib-load contention (e.g. concurrent
/// xeyes + Xwayland forks each opening 50+ shared libraries through
/// initramfs_srv) a single grant-based read can take >10s of wall-clock
/// while waiting in linux_srv's IPC queue.  The 10s timeout would fire
/// SERVER_DIED on a perfectly healthy chain, causing linux_srv's
/// mmap-fill loop to surface the partial fill as EIO ("file too short"
/// / "failed to map segment from shared object") and Xwayland to bail.
/// 30s is generous enough to ride out boot-time queue spikes without
/// papering over an actual server hang.
const CALL_REPLY_TIMEOUT_NS: u64 = 30_000_000_000; // 30 seconds

#[cold]
#[inline(never)]
fn call_reply_timeout_sweep() {
    let now = get_monotonic_ns();
    let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(200);
    for tid in 1..max_tid {
        let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
        if t.task_id == 0 || t.state != ThreadState::Blocked {
            continue;
        }
        let slot = match t.blocked_on {
            BlockReason::CallReply(s) => s,
            _ => continue,
        };
        let park = t.park_state.load(Ordering::Acquire);
        if park != PARK_COMMITTED {
            continue;
        }
        let blocked_ns = t.call_blocked_ns.load(Ordering::Acquire);
        if blocked_ns == 0 || now.saturating_sub(blocked_ns) < CALL_REPLY_TIMEOUT_NS {
            continue;
        }
        // Thread has been in CallReply for >10s. Force-wake with SERVER_DIED.
        if crate::ipc::call_reply::abandon_for_interrupt(slot, tid as u32) {
            let sp = thread_saved_sp(tid as ThreadId);
            if sp != 0 {
                let tag = crate::ipc::call_reply::CALL_REPLY_SERVER_DIED;
                unsafe {
                    use crate::arch::trapframe::ExceptionFrame;
                    let frame = &mut *(sp as *mut ExceptionFrame);
                    crate::syscall::handlers::set_return(frame, 0);
                    crate::syscall::handlers::set_reg(frame, 1, tag);
                    crate::syscall::handlers::set_reg(frame, 2, 0);
                    crate::syscall::handlers::set_reg(frame, 3, 0);
                    crate::syscall::handlers::set_reg(frame, 4, 0);
                    crate::syscall::handlers::set_reg(frame, 5, 0);
                    crate::syscall::handlers::set_reg(frame, 6, 0);
                    crate::syscall::handlers::set_reg(frame, 7, 0);
                }
            }
            // Free the cap slot (leases/donation already unwound by abandon).
            let cap_gen = crate::ipc::call_reply::REPLY_CAPS[slot as usize]
                .generation
                .load(Ordering::Acquire);
            crate::ipc::call_reply::free((slot as u64) | ((cap_gen as u64) << 32));
            // Clear the timestamp so we don't re-fire on next sweep.
            t.call_blocked_ns.store(0, Ordering::Relaxed);
            crate::println!(
                "CALL-TIMEOUT: tid={} slot={} task={} port={:#x} tag={:#x} blocked_for={}ms",
                tid, slot, t.task_id, t.call_dest_port, t.call_tag,
                (now - blocked_ns) / 1_000_000
            );
            // Per-CPU dispatch state on CALL-TIMEOUT (#120 instrument G):
            // tells us whether the orphan tid is queue-depth-starved (CPUs
            // busy with other work) or whether dispatch-trigger is lost
            // (CPUs idle but not picking up the orphan).
            {
                let ncpus = crate::sched::smp::num_cpus().min(8);
                let stuck_pending_fires = RESCUE_STUCK_PENDING_FIRES.load(Ordering::Relaxed);
                let rescue_pending = RESCUE_PENDING.load(Ordering::Relaxed);
                let pending_low_fires = PENDING_LOW_FIRES.load(Ordering::Relaxed);
                let self_pick_count = SELF_PICK_COUNT.load(Ordering::Relaxed);
                crate::println!(
                    "  CPU-DIAG: rescue_stuck_pending_fires={} rescue_pending_obs={} pending_low_fires={} self_pick={}",
                    stuck_pending_fires, rescue_pending, pending_low_fires, self_pick_count
                );
                for c in 0..ncpus {
                    let pcpu = crate::sched::smp::get(c as u32);
                    let cur = pcpu.current_thread.load(Ordering::Acquire);
                    let dispatching = pcpu.dispatching_tid.load(Ordering::Acquire);
                    let need_resched = pcpu.need_resched.load(Ordering::Acquire);
                    // #120 instrumentation J: run-queue depth (try_lock to avoid
                    // contending the rq if some CPU is mid-dispatch).
                    // Snapshot up to 8 EEVDF heap entries for vruntime/deadline
                    // dump — disambiguates "heap stuck because nothing eligible"
                    // (vruntime > min_vruntime for all) vs "phantom heap entries"
                    // (heap holds tids whose state is no longer Ready).
                    let mut entries: [(u32, u64, u64, u8); 8] = [(0, 0, 0, 0); 8];
                    let mut entries_n: usize = 0;
                    let mut min_vrt: u64 = 0;
                    let (rq_eevdf_count, rq_locked) =
                        if (c as usize) < percpu_rq().len() {
                            if let Some(rq) = percpu_rq()[c as usize].try_lock() {
                                let n = rq.eevdf_nr_running;
                                let any_rt = rq.active[0] != 0 || rq.active[1] != 0;
                                let any_legacy = rq.active[2] != 0 || rq.active[3] != 0;
                                min_vrt = rq.eevdf_min_vruntime;
                                rq.eevdf_heap.for_each_entry(|tid, key| {
                                    if entries_n < 8 {
                                        let tt = thread_ref(tid);
                                        let vrt = tt.eevdf_vruntime;
                                        let st = tt.state as u8;
                                        entries[entries_n] = (tid, key, vrt, st);
                                        entries_n += 1;
                                    }
                                });
                                drop(rq);
                                (n as u64, (any_rt, any_legacy))
                            } else {
                                (u64::MAX, (false, false))
                            }
                        } else {
                            (0, (false, false))
                        };
                    let disp_n = pcpu.dispatch_count.load(Ordering::Relaxed);
                    let disp_last = pcpu.last_dispatched_tid.load(Ordering::Relaxed);
                    let disp_streak = pcpu.dispatch_streak.load(Ordering::Relaxed);
                    let set_pend = pcpu.dispatch_set_pending_count.load(Ordering::Relaxed);
                    let cas_ok   = pcpu.dispatch_cas_ok_count.load(Ordering::Relaxed);
                    let rescue_stuck = pcpu.rescue_stuck_pending_count.load(Ordering::Relaxed);
                    let hist = lat_snapshot(pcpu);
                    let n: u64 = hist.iter().sum();
                    let p50 = lat_percentile_ns(&hist, 5000);
                    let p90 = lat_percentile_ns(&hist, 9000);
                    let p99 = lat_percentile_ns(&hist, 9900);
                    let p999 = lat_percentile_ns(&hist, 9990);
                    crate::println!(
                        "  CPU-DIAG: cpu={} current_thread={} dispatching_tid={} need_resched={} eevdf_n={} eevdf_min_vrt={} rt_pending={} legacy_pending={} dispatches={} last_disp_tid={} streak={} set_pend={} cas_ok={} pend_minus_cas={} rescue_stuck={} lat_ns(n={} p50={} p90={} p99={} p999={})",
                        c, cur, dispatching, need_resched,
                        rq_eevdf_count, min_vrt, rq_locked.0, rq_locked.1,
                        disp_n, disp_last, disp_streak,
                        set_pend, cas_ok, set_pend.saturating_sub(cas_ok),
                        rescue_stuck,
                        n, p50, p90, p99, p999
                    );
                    for i in 0..entries_n {
                        let (etid, ekey, evrt, est) = entries[i];
                        let eligible = evrt <= min_vrt;
                        crate::println!(
                            "    EEVDF[{}]: tid={} deadline={} vruntime={} state={} eligible={}",
                            i, etid, ekey, evrt, est, eligible
                        );
                    }
                }
            }
            // Diagnostic dump for #120: per-port wake counters + state of
            // threads in the destination port's owning aspace.  If
            // wake_no_parker > 0 while parkers exist, we have direct
            // evidence of the wake_recv_waiter race window.
            if let Some(p) = crate::ipc::port::port_ref(t.call_dest_port) {
                let calls    = p.diag_wake_calls.load(Ordering::Relaxed);
                let no_park  = p.diag_wake_no_parker.load(Ordering::Relaxed);
                let inj_ok   = p.diag_wake_inject_ok.load(Ordering::Relaxed);
                let reenq    = p.diag_wake_reenq.load(Ordering::Relaxed);
                let recv_h   = p.recv_holder.load(Ordering::Relaxed);
                crate::println!(
                    "  PORT-DIAG: wake_calls={} no_parker={} inject_ok={} reenq={} recv_holder={}",
                    calls, no_park, inj_ok, reenq, recv_h
                );
                // Cross-check: does the HAMT actually map (port_id, RECV_PARK)
                // to a turnstile right now?  If hamt_found=false while parked
                // threads have ts_blocked_on != 0, we have proof of HAMT/turnstile
                // divergence (orphan turnstile — the bug we're hunting).
                let (hamt_found_park, hamt_ts_park) = crate::sync::turnstile::lookup_port_turnstile(
                    t.call_dest_port,
                    crate::sync::turnstile::KEY_PORT_RECV_PARK,
                );
                let (hamt_found_recv, hamt_ts_recv) = crate::sync::turnstile::lookup_port_turnstile(
                    t.call_dest_port,
                    crate::sync::turnstile::KEY_PORT_RECV,
                );
                crate::println!(
                    "  PORT-DIAG: hamt_lookup RECV_PARK={{found={} ts={:#x}}} RECV={{found={} ts={:#x}}}",
                    hamt_found_park, hamt_ts_park, hamt_found_recv, hamt_ts_recv
                );
                // Walk threads in the recv-holder's task and print any blocked
                // on this very port.  Cap at 8 to avoid log flood.
                if recv_h != u32::MAX {
                    let mut printed = 0u32;
                    SCHED_THREAD_ART.for_each(|_key, val| {
                        if printed >= 8 { return; }
                        let other = unsafe { &*(val as *const Thread) };
                        if other.task_id != recv_h
                            || other.state == ThreadState::Dead
                        {
                            return;
                        }
                        if let BlockReason::PortRecv(rp) = other.blocked_on {
                            if rp == t.call_dest_port {
                                // ts_blocked_on disambiguates #120 sub-patterns:
                                //   != 0  → thread IS on a turnstile (port_dequeue_one
                                //          buggy, or different key, or contention).
                                //   == 0  → thread was dequeued from turnstile but
                                //          state never transitioned Blocked → Ready.
                                // last_ready_ns shows whether the thread has been
                                // Ready since long ago (orphan) or recently (oscillating).
                                // enqueue_count: 1 = just one wake; >1 = rescue
                                // re-enqueued repeatedly but dispatch keeps missing.
                                let now_ns = get_monotonic_ns();
                                let lr = other.last_ready_ns.load(Ordering::Relaxed);
                                let ready_age_ms = if lr > 0 { (now_ns - lr) / 1_000_000 } else { 0 };
                                let ts_addr = other.ts_blocked_on.load(Ordering::Relaxed);
                                crate::println!(
                                    "  PORT-DIAG: dest tid={} state={:?} blocked_on=PortRecv({:#x}) on_cpu={} ts_blocked_on={:#x} enq_count={} ready_age_ms={}",
                                    other.id, other.state, rp,
                                    other.on_cpu.load(Ordering::Relaxed),
                                    ts_addr,
                                    other.enqueue_count.load(Ordering::Relaxed),
                                    ready_age_ms,
                                );
                                // If ts_blocked_on != 0, decode the turnstile so
                                // we know which key/port it's actually registered
                                // under — flags HAMT-orphan turnstiles directly.
                                if let Some((k, asp, va, wc, h)) =
                                    unsafe { crate::sync::turnstile::turnstile_info(ts_addr) }
                                {
                                    let hamt_match = (hamt_found_park && hamt_ts_park == ts_addr)
                                        || (hamt_found_recv && hamt_ts_recv == ts_addr);
                                    crate::println!(
                                        "    TS@{:#x}: key_type={} aspace={} va={:#x} waiter_count={} hash={:#x} hamt_match={}",
                                        ts_addr, k, asp, va, wc, h, hamt_match,
                                    );
                                }
                                printed += 1;
                            }
                        }
                    });
                }
            }
            wake_parked_thread(tid as ThreadId);
        }
    }
}

/// Scan for threads stuck in Ready state that are not in any run queue
/// or deferred-requeue slot.  Re-enqueue them so the system self-heals.
///
/// `rescue_parked`: if true, also scan for CallReply-blocked threads stuck
/// in COMMITTED with wakeup=true and inject SERVER_DIED. Only set this
/// during confirmed IPC stalls (watchdog), not on periodic sweeps, to
/// avoid prematurely killing legitimate slow IPC calls.
/// Per-thread orphan age counter: tracks how many consecutive rescue sweeps
/// a thread has appeared orphaned.  Only rescue when age >= 2 to filter out
/// false positives from the narrow dequeue window (in_queue=false before
/// on_cpu=ON_CPU_PENDING in percpu_pick_next).
static ORPHAN_AGE: [AtomicU32; 256] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; 256]
};

#[cold]
#[inline(never)]
fn rescue_orphaned_threads_impl(rescue_parked: bool) {
    // Drain the local CPU's deferred slot first. This prevents the scenario
    // where a thread is stuck in the same CPU's deferred slot and rescue
    // can't IPI itself to unstick it. Safe because rescue only runs from
    // tick(), which is called from the timer IRQ handler after the stack
    // switch from the previous try_switch has completed.
    // NOTE: we MUST NOT drain remote CPUs' deferred slots — the remote CPU
    // may still be between the deferred store and the assembly stack switch.
    drain_deferred_requeue(smp::cpu_id());

    let max_tid = NEXT_THREAD_ID.load(Ordering::Relaxed).min(200);
    let ncpus = smp::num_cpus();
    for tid in 1..max_tid {
        let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
        if t.task_id == 0 || t.state != ThreadState::Ready {
            // Not a candidate — reset orphan age and the low-threshold log gate.
            if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
            if (tid as usize) < PENDING_LOW_LOGGED.len() {
                PENDING_LOW_LOGGED[tid as usize].store(false, Ordering::Relaxed);
            }
            continue;
        }
        let on = t.on_cpu.load(Ordering::Acquire);
        let inq = t.in_queue.load(Ordering::Acquire);
        // Check for orphaned threads: on_cpu==MAX (never scheduled or cleared
        // by park), OR stale on_cpu (claims a CPU but that CPU is running a
        // different thread).  Skip ON_CPU_PENDING (transient state during
        // scheduling — rescuing it causes DOUBLE-SCHED).
        // `stale_on_cpu` distinguishes the "thread thinks it's on cpu N but
        // cpu N is running a different thread" pattern (Bug A) from the
        // generic on_cpu==MAX orphan (which has wider race windows with
        // park/wake paths and warrants the age filter).
        let mut stale_on_cpu = false;
        // Threshold for declaring an "ON_CPU_PENDING for so long it must
        // be stuck" orphan.  Normal PENDING windows are sub-millisecond
        // (set by percpu_enqueue, cleared by try_switch on the next tick).
        // Anything past STUCK_PENDING_AGE consecutive sweeps means the
        // wake's IPI was lost / the target CPU's try_switch never picked
        // the thread up (#120 root cause: wake_parked_thread fast path
        // runs but the parking CPU never dispatches).
        const STUCK_PENDING_AGE: u32 = 16; // ~16s at 1Hz rescue cadence
        // Low-threshold PENDING-stuck diagnostic — independent of the 16s
        // rescue and 30s CALL-TIMEOUT.  Fires once per stuck episode when
        // `pending_set_ns` is older than ~2s in real time.  Cleared via
        // PENDING_LOW_LOGGED when CAS-ok zeroes pending_set_ns (or when the
        // thread leaves Ready below).
        const PENDING_LOW_THRESHOLD_NS: u64 = 2_000_000_000;
        let is_orphan = if on == u32::MAX {
            true
        } else if on == ON_CPU_PENDING {
            // Transient — dequeue_set_pending just set this — UNLESS the
            // age counter says we've seen this for too long.  Use a
            // separate counter so this state's age doesn't conflict with
            // the on_cpu==MAX path (which has its own age semantics).
            RESCUE_PENDING.fetch_add(1, Ordering::Relaxed);

            // Low-threshold one-shot logger.  Multiple ON_CPU_PENDING
            // store sites in the scheduler (wake/release/rescue) do NOT
            // call `dequeue_set_pending`, so pending_set_ns may be 0 even
            // for a genuinely-stuck thread.  In that case, stamp `now`
            // here so the next sweep can compute an age.
            let pset = t.pending_set_ns.load(Ordering::Relaxed);
            let now_ns = get_monotonic_ns();
            if pset == 0 {
                t.pending_set_ns.store(now_ns, Ordering::Relaxed);
            } else {
                let age_ns = now_ns.saturating_sub(pset);
                if age_ns >= PENDING_LOW_THRESHOLD_NS
                    && (tid as usize) < PENDING_LOW_LOGGED.len()
                    && !PENDING_LOW_LOGGED[tid as usize].swap(true, Ordering::Relaxed)
                {
                    PENDING_LOW_FIRES.fetch_add(1, Ordering::Relaxed);
                    let target = t.last_cpu.load(Ordering::Relaxed);
                    let prio = t.prio.load(Ordering::Relaxed);
                    let inq_now = t.in_queue.load(Ordering::Relaxed);
                    let enq_n = t.enqueue_count.load(Ordering::Relaxed);
                    let (tevt, tcpu, tseq) = trace_last(tid as u32);
                    crate::println!(
                        "PENDING-STUCK-LOW: tid={} task={} age_ns={} last_cpu={} prio={} inq={} enq_n={} trace=(evt={} cpu={} seq={})",
                        tid, t.task_id, age_ns, target, prio, inq_now, enq_n,
                        tevt, tcpu, tseq
                    );
                    // #135 IPI-to-idle latency probe: dump per-CPU histogram
                    // alongside every PENDING-STUCK-LOW print.  The print
                    // itself is already rate-limited (one per tid per stuck
                    // window via PENDING_LOW_LOGGED), so this dump piggybacks
                    // on that limiter.  The histogram bucketizes
                    // (cas_ok_ns - pending_set_ns) so we can attribute the
                    // residual oscillation's wake-to-dispatch latency to
                    // specific CPUs.
                    {
                        let ncpus = crate::sched::smp::num_cpus().min(8);
                        for c in 0..ncpus {
                            let pc = crate::sched::smp::get(c as u32);
                            let hist = lat_snapshot(pc);
                            let n: u64 = hist.iter().sum();
                            let p50 = lat_percentile_ns(&hist, 5000);
                            let p90 = lat_percentile_ns(&hist, 9000);
                            let p99 = lat_percentile_ns(&hist, 9900);
                            let p999 = lat_percentile_ns(&hist, 9990);
                            let p9999 = lat_percentile_ns(&hist, 9999);
                            crate::println!(
                                "  IPI-LAT: cpu={} n={} p50={} p90={} p99={} p999={} p9999={} rescue_stuck={}",
                                c, n, p50, p90, p99, p999, p9999,
                                pc.rescue_stuck_pending_count.load(Ordering::Relaxed),
                            );
                        }
                    }
                    // #135 pick-blindness probe: locate which CPU's runqueue
                    // actually holds the stuck thread, then dump that heap's
                    // entries + scan_start.  rescue_stuck is attributed to
                    // `last_cpu` but a thread woken via sleep_wake or
                    // wake_parked_thread can be enqueued on a *different* CPU
                    // (the wake's `target`).  If the locating CPU's heap shows
                    // tid present alongside other entries but `scan_start`
                    // isn't rotating through its position, we have direct
                    // evidence of pick-rotation breaking down.
                    {
                        let hp = t.eevdf_heap_pos;
                        if hp != super::heap::HEAP_POS_NONE {
                            let ncpus = crate::sched::smp::num_cpus().min(8);
                            let mut located_cpu: i32 = -1;
                            let mut located_n: u32 = 0;
                            let mut located_scan: u32 = 0;
                            let mut located_entries: [(u32, u64, u64, u8); 8] =
                                [(0, 0, 0, 0); 8];
                            let mut located_entries_n: usize = 0;
                            for c in 0..ncpus {
                                if let Some(rq) = percpu_rq()[c].try_lock() {
                                    // rq_contains_tid's heap_pos fast path
                                    // returns true if the thread is in ANY
                                    // CPU's heap (heap_pos is per-thread, not
                                    // per-CPU).  For PICK-LOCATE we need to
                                    // confirm the thread is in *this* CPU's
                                    // heap — walk for_each_entry and capture
                                    // its presence directly.
                                    let mut here = false;
                                    let mut tmp_entries: [(u32, u64, u64, u8); 8] =
                                        [(0, 0, 0, 0); 8];
                                    let mut tmp_n: usize = 0;
                                    rq.eevdf_heap.for_each_entry(|etid, ekey| {
                                        if etid == tid as u32 {
                                            here = true;
                                        }
                                        if tmp_n < 8 {
                                            let tt = thread_ref(etid);
                                            let vrt = tt.eevdf_vruntime;
                                            let st = tt.state as u8;
                                            tmp_entries[tmp_n] = (etid, ekey, vrt, st);
                                            tmp_n += 1;
                                        }
                                    });
                                    if here {
                                        located_cpu = c as i32;
                                        located_n = rq.eevdf_heap.len();
                                        located_scan = rq.eevdf_heap.scan_start_raw();
                                        located_entries = tmp_entries;
                                        located_entries_n = tmp_n;
                                        drop(rq);
                                        break;
                                    }
                                    drop(rq);
                                }
                            }
                            if located_cpu >= 0 {
                                crate::println!(
                                    "  PICK-LOCATE: stuck tid={} (heap_pos={}) in cpu={} eevdf_n={} scan_start={} (scan%n={}) picked_count={} enq_count={}",
                                    tid, hp, located_cpu, located_n, located_scan,
                                    if located_n > 0 {
                                        located_scan % located_n
                                    } else { 0 },
                                    t.picked_count.load(Ordering::Relaxed),
                                    t.enqueue_count.load(Ordering::Relaxed),
                                );
                                for i in 0..located_entries_n {
                                    let (etid, ekey, evrt, est) = located_entries[i];
                                    let marker = if etid == tid as u32 { "  <-- STUCK" } else { "" };
                                    let etpick = thread_ref(etid).picked_count.load(Ordering::Relaxed);
                                    let etenq = thread_ref(etid).enqueue_count.load(Ordering::Relaxed);
                                    crate::println!(
                                        "    HEAP[{}]: tid={} deadline={} vruntime={} state={} picked={} enq={}{}",
                                        i, etid, ekey, evrt, est, etpick, etenq, marker
                                    );
                                }
                            } else {
                                crate::println!(
                                    "  PICK-LOCATE: stuck tid={} (heap_pos={}) NOT FOUND in any cpu runqueue (locks contended or phantom)",
                                    tid, hp
                                );
                            }
                        } else {
                            crate::println!(
                                "  PICK-LOCATE: stuck tid={} eevdf_heap_pos=NONE (not in eevdf heap — check bitmap or just-removed)",
                                tid
                            );
                        }
                    }
                }
            }
            let pending_age = if (tid as usize) < ORPHAN_AGE.len() {
                ORPHAN_AGE[tid as usize].fetch_add(1, Ordering::Relaxed)
            } else { 0 };
            if pending_age >= STUCK_PENDING_AGE {
                // Stuck PENDING: treat as orphan.  Re-enqueue path below
                // will check for actual queue membership and DOUBLE_ENQ
                // before doing the percpu_enqueue, so this is safe.
                RESCUE_STUCK_PENDING_FIRES.fetch_add(1, Ordering::Relaxed);
                // Per-CPU asymmetry probe (#120 lead from
                // project_120_eevdf_dispatch.md): attribute to the thread's
                // last_cpu, since on_cpu == ON_CPU_PENDING here so the
                // identity of the parking/dispatching CPU lives in
                // last_cpu.  Dumped by the WATCHDOG and CALL-TIMEOUT
                // per-CPU loops below as `rescue_stuck=N`.
                let attrib_cpu = t.last_cpu.load(Ordering::Relaxed);
                let ncpus = crate::sched::smp::num_cpus() as u32;
                if attrib_cpu < ncpus {
                    crate::sched::smp::get(attrib_cpu)
                        .rescue_stuck_pending_count
                        .fetch_add(1, Ordering::Relaxed);
                }
                // Rate-limit the println: only log on first crossing
                // (age == STUCK_PENDING_AGE).  Subsequent stuckness still
                // counts in RESCUE_STUCK_PENDING_FIRES but doesn't flood
                // the serial log every sweep.
                if pending_age == STUCK_PENDING_AGE {
                    crate::println!(
                        "RESCUE-STUCK-PENDING: tid={} age={} task={} on_cpu=PENDING - \
                        treating as orphan (#120 IPI/dispatch loss)",
                        tid, pending_age, t.task_id
                    );
                }
                true
            } else {
                // PENDING but not yet aged enough — do NOT fall through
                // to the "if !is_orphan { reset age }" line below, that
                // would zero the counter and the threshold would never
                // be reached.  Skip this tid for this sweep.
                continue;
            }
        } else if on < ncpus as u32 {
            // Check if the claimed CPU is actually running this thread.
            // Also consult dispatching_tid: the claimed CPU may be in the
            // middle of try_switch's dispatch sequence (CAS done, state and
            // current_thread not yet updated).  In that window cur != tid,
            // but the thread is *not* stale — it's about to be Running.
            let pcpu = smp::get(on);
            let cur = pcpu.current_thread.load(Ordering::Acquire);
            let dispatching = pcpu.dispatching_tid.load(Ordering::Acquire);
            let stale = cur != tid as u32 && dispatching != tid as u32;
            stale_on_cpu = stale;
            stale
        } else {
            false // garbage value — don't touch
        };
        // Phantom-enqueued detection: state=Ready + in_queue=true but the
        // thread is not actually in any heap or bitmap queue on its
        // last_cpu.  This violates the in_queue==membership invariant and
        // makes the thread invisible to all schedulers.  Self-heal by
        // clearing the stale flag and re-enqueueing.
        if inq {
            // Only spend cycles on the lock for plausible phantom candidates:
            // on_cpu must be MAX or stale (same orphan filter as below) AND
            // the thread must be Ready.  The earlier `t.state != Ready`
            // check above the loop already screens out non-Ready threads.
            if is_orphan {
                let target = t.last_cpu.load(Ordering::Relaxed);
                let phantom = if (target as usize) < percpu_rq().len() {
                    if let Some(rq) = percpu_rq()[target as usize].try_lock() {
                        let in_actual = rq_contains_tid(&rq, tid as ThreadId);
                        drop(rq);
                        // Re-validate the orphan predicate after the lock.
                        // If state, in_queue or on_cpu flipped while we
                        // scanned, the thread is no longer phantom and a
                        // legitimate path will handle it.
                        let inq_now = t.in_queue.load(Ordering::Acquire);
                        let on_now = t.on_cpu.load(Ordering::Acquire);
                        let still_ready = t.state == ThreadState::Ready;
                        let still_orphan = on_now == u32::MAX
                            || (on_now < ncpus as u32
                                && smp::get(on_now).current_thread.load(Ordering::Acquire)
                                    != tid as u32);
                        inq_now && !in_actual && still_ready && still_orphan
                    } else {
                        false // contended — reassess next sweep
                    }
                } else {
                    false
                };
                if phantom {
                    // Self-heal: clear the stale flag and re-enqueue normally.
                    // percpu_enqueue's swap(true) will succeed (we just
                    // cleared) and proceed with the heap/bitmap insert.  If
                    // a concurrent path enqueues between our store and
                    // swap, the swap returns true and DOUBLE_ENQ counters
                    // increment — benign.
                    let prio = t.prio.load(Ordering::Relaxed);
                    let park = t.park_state.load(Ordering::Relaxed);
                    let wake = t.wakeup.load(Ordering::Relaxed);
                    let blk = t.blocked_on;
                    let heap_pos = t.eevdf_heap_pos;
                    let (tevt, tcpu, tseq) = trace_last(tid as u32);
                    crate::println!(
                        "RESCUE-PHANTOM: tid={} prio={} cpu={} task={} on_cpu={} trace=(evt={} cpu={} seq={}) park={} wake={} blk={:?} hp={}",
                        tid, prio, target, t.task_id, on, tevt, tcpu, tseq,
                        park, wake, blk, heap_pos
                    );
                    RESCUE_PHANTOM.fetch_add(1, Ordering::Relaxed);
                    rescue_per_tid_inc(tid as u32);
                    t.in_queue.store(false, Ordering::Release);
                    t.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                    trace_sched(tid as u32, 8); // 8=rescue_enq
                    set_enq_tag(7); // 7=rescue
                    percpu_enqueue(target, prio, tid as ThreadId);
                    if (tid as usize) < ORPHAN_AGE.len() {
                        ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed);
                    }
                    continue;
                }
            }
            // Genuine queue membership — reset orphan age and move on.
            if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
            continue;
        }
        if !is_orphan {
            if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
            continue;
        }
        {
            // Track orphan age: filter false positives from the narrow
            // dequeue window where in_queue=false but on_cpu hasn't been set
            // to ON_CPU_PENDING yet.
            //
            // The stale-on-cpu pattern (state=Ready, on_cpu=cpu_real,
            // !in_queue, cur!=tid) is unambiguous: every legitimate path
            // either keeps the thread Running on that CPU, transitions
            // on_cpu through ON_CPU_PENDING (filtered above), or holds the
            // thread in a deferred slot (checked below).  Skip the age
            // filter for this pattern — the age filter prevents recovery
            // because tid oscillates through transient non-orphan states
            // between 100ms rescue sweeps, resetting the counter (Bug A).
            let age = if (tid as usize) < ORPHAN_AGE.len() {
                ORPHAN_AGE[tid as usize].fetch_add(1, Ordering::Relaxed)
            } else {
                1 // always rescue for high tids (shouldn't happen in practice)
            };
            if !stale_on_cpu && age < 1 {
                continue; // first sighting — wait one more sweep to confirm
            }
            // Just-in-time deferred slot check: read ALL deferred slots NOW,
            // not from a stale snapshot.  The old snapshot approach went stale
            // within one tick (10ms), causing rescue to falsely re-enqueue
            // threads that were legitimately cycling through deferred slots.
            let mut in_deferred = false;
            let mut deferred_cpu = 0u32;
            for c in 0..ncpus.min(16) {
                let dv = deferred_requeue()[c].load(Ordering::Relaxed);
                if dv != 0 && (dv & 0xFFFFFFFF) as u32 == tid as u32 {
                    in_deferred = true;
                    deferred_cpu = c as u32;
                    break;
                }
            }
            if in_deferred {
                // Thread is in a deferred-requeue slot. Can't enqueue directly
                // (the owning CPU may still be on this thread's kernel stack).
                // Send a reschedule IPI to the CPU whose slot holds this thread
                // so its try_switch → drain_deferred_requeue unsticks it.
                if deferred_cpu != smp::cpu_id() {
                    crate::arch::irq::send_reschedule_ipi(deferred_cpu);
                }
            } else {
                // Not in deferred slot. Re-read on_cpu to filter out the
                // narrow drain window (between swap(0) and store(ON_CPU_PENDING)).
                // If drain just handled it, on_cpu will be ON_CPU_PENDING now.
                //
                // Exception: if `on` was already PENDING when we entered this
                // branch (i.e. we got here via the new STUCK_PENDING_AGE path
                // above), seeing PENDING again on re-read is NOT "drain just
                // handled it" — it's "thread has been PENDING for >=16s and
                // is actually stuck."  Continue to the re-enqueue path.
                let was_stuck_pending = on == ON_CPU_PENDING;
                let on2 = t.on_cpu.load(Ordering::Acquire);
                if on2 == ON_CPU_PENDING && !was_stuck_pending {
                    if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                    continue; // drain just handled it
                }
                // Re-read state: the dispatching CPU may have set Running
                // between our initial state read and the on_cpu/deferred checks.
                if t.state != ThreadState::Ready {
                    if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                    continue; // dispatch completed — thread is Running now
                }
                // Also skip if in_queue changed (drain enqueued between our checks).
                if t.in_queue.load(Ordering::Acquire) {
                    if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                    continue;
                }
                let target = t.last_cpu.load(Ordering::Relaxed);
                let prio = t.prio.load(Ordering::Relaxed);
                let (tevt, tcpu, tseq) = trace_last(tid as u32);
                let park = t.park_state.load(Ordering::Relaxed);
                let wake = t.wakeup.load(Ordering::Relaxed);
                let src = t.saved_sp_source;
                let blk = t.blocked_on;
                let heap_pos = t.eevdf_heap_pos;
                crate::println!(
                    "RESCUE: tid={} prio={} cpu={} task={} on_cpu={} trace=(evt={} cpu={} seq={}) park={} wake={} src={} blk={:?} hp={}",
                    tid, prio, target, t.task_id, on2, tevt, tcpu, tseq,
                    park, wake, src, blk, heap_pos
                );
                if (tid as usize) < ORPHAN_AGE.len() { ORPHAN_AGE[tid as usize].store(0, Ordering::Relaxed); }
                // Reset on_cpu so that when this thread is later dispatched,
                // try_switch's CAS (ON_CPU_PENDING -> cpu) succeeds.
                // dequeue_set_pending already does this on the dispatch
                // side, but doing it here closes a window where a concurrent
                // try_switch reads on_cpu as a stale CPU number before
                // dequeue.
                t.on_cpu.store(ON_CPU_PENDING, Ordering::Release);
                trace_sched(tid as u32, 8); // 8=rescue_enq
                set_enq_tag(7); // 7=rescue
                // Per-branch rescue counter: the two predicates that lead
                // here are mutually exclusive.  `stale_on_cpu` is the Bug A
                // pattern from commit 712e741; otherwise the orphan was
                // detected via `on == u32::MAX`.
                if stale_on_cpu {
                    RESCUE_STALE_ON_CPU.fetch_add(1, Ordering::Relaxed);
                } else {
                    RESCUE_MAX.fetch_add(1, Ordering::Relaxed);
                }
                rescue_per_tid_inc(tid as u32);
                percpu_enqueue(target, prio, tid as ThreadId);
            }
        }
    }

    // Second pass: rescue CallReply-blocked threads stuck in COMMITTED
    // with wakeup=true. Only runs during confirmed IPC stalls, not on
    // periodic sweeps, to avoid prematurely killing legitimate slow calls.
    if !rescue_parked {
        return;
    }
    for tid in 1..max_tid {
        let t = unsafe { &*(THREAD_TABLE.get(tid) as *const Thread) };
        if t.task_id == 0 || t.state != ThreadState::Blocked {
            continue;
        }
        if !matches!(t.blocked_on, BlockReason::CallReply(_)) {
            continue;
        }
        let park = t.park_state.load(Ordering::Acquire);
        let wake = t.wakeup.load(Ordering::Acquire);
        if park == PARK_COMMITTED && wake {
            let (tevt, tcpu, tseq) = trace_last(tid as u32);
            crate::println!(
                "RESCUE-PARK: tid={} task={} blk={:?} trace=(evt={} cpu={} seq={})",
                tid, t.task_id, t.blocked_on, tevt, tcpu, tseq
            );
            let sp = thread_saved_sp(tid as ThreadId);
            if sp != 0 {
                let died_tag = crate::ipc::call_reply::CALL_REPLY_SERVER_DIED;
                unsafe {
                    use crate::arch::trapframe::ExceptionFrame;
                    let frame = &mut *(sp as *mut ExceptionFrame);
                    crate::syscall::handlers::set_return(frame, 0);
                    crate::syscall::handlers::set_reg(frame, 1, died_tag);
                    crate::syscall::handlers::set_reg(frame, 2, 0);
                    crate::syscall::handlers::set_reg(frame, 3, 0);
                    crate::syscall::handlers::set_reg(frame, 4, 0);
                    crate::syscall::handlers::set_reg(frame, 5, 0);
                    crate::syscall::handlers::set_reg(frame, 6, 0);
                    crate::syscall::handlers::set_reg(frame, 7, 0);
                }
            }
            wake_parked_thread(tid as ThreadId);
        }
    }
}

/// Get monotonic time in nanoseconds since boot.
pub fn get_monotonic_ns() -> u64 {
    crate::arch::timer::monotonic_ns()
}

/// Insert a thread into the global sleep queue, sorted by deadline (earliest first).
/// Must be called with the thread already marked Blocked/Sleep and deadline set.
/// Caller must NOT hold SLEEP_QUEUE_LOCK.
fn sleep_queue_insert(tid: ThreadId, deadline_ns: u64) {
    let inserted_at_head;
    {
        let _guard = SLEEP_QUEUE_LOCK.lock();
        let head = SLEEP_QUEUE_HEAD.load(Ordering::Relaxed);

        // Walk the list to find insertion point (sorted by deadline ascending).
        let mut prev: u32 = u32::MAX; // u32::MAX = inserting at head
        let mut cur = head;
        while cur != u32::MAX {
            let ct = unsafe { thread_mut_from_ref(cur) };
            if ct.sleep_deadline_ns > deadline_ns {
                break;
            }
            prev = cur;
            cur = ct.sleep_next;
        }

        let t = unsafe { thread_mut_from_ref(tid) };
        t.sleep_next = cur;

        if prev == u32::MAX {
            // Insert at head.
            SLEEP_QUEUE_HEAD.store(tid, Ordering::Release);
            inserted_at_head = true;
        } else {
            let pt = unsafe { thread_mut_from_ref(prev) };
            pt.sleep_next = tid;
            inserted_at_head = false;
        }
    }

    // If the new deadline is the earliest (inserted at head), reprogram the
    // local CPU's timer so we don't oversleep.
    if inserted_at_head {
        crate::arch::timer::program_oneshot_ns(deadline_ns);
    }
}

/// Remove a thread from the sleep queue (e.g., on signal delivery or cancel).
/// Safe to call even if the thread is not on the queue.
/// Caller must NOT hold SLEEP_QUEUE_LOCK.
fn sleep_queue_remove(tid: ThreadId) {
    let _guard = SLEEP_QUEUE_LOCK.lock();
    let head = SLEEP_QUEUE_HEAD.load(Ordering::Relaxed);
    if head == u32::MAX {
        return;
    }

    // Find and unlink.
    let mut prev: u32 = u32::MAX;
    let mut cur = head;
    while cur != u32::MAX {
        if cur == tid {
            let ct = unsafe { thread_mut_from_ref(cur) };
            let next = ct.sleep_next;
            ct.sleep_next = u32::MAX;
            if prev == u32::MAX {
                SLEEP_QUEUE_HEAD.store(next, Ordering::Release);
            } else {
                let pt = unsafe { thread_mut_from_ref(prev) };
                pt.sleep_next = next;
            }
            return;
        }
        let ct = unsafe { thread_mut_from_ref(cur) };
        prev = cur;
        cur = ct.sleep_next;
    }
}

/// Wake threads whose sleep deadlines have passed.
/// Called from tick() before try_switch. O(1) when no timers expired,
/// O(K) for K expired threads. Only acquires the lock if the head has expired.
fn check_sleep_timers() {
    let now_ns = get_monotonic_ns();

    // Fast path: peek at the head without locking. If the earliest deadline
    // hasn't passed, no work to do.
    let head = SLEEP_QUEUE_HEAD.load(Ordering::Acquire);
    if head == u32::MAX {
        return;
    }
    let head_deadline = unsafe { thread_mut_from_ref(head) }.sleep_deadline_ns;
    if head_deadline > now_ns {
        return;
    }

    // Drain expired entries from the head of the sorted list.
    let mut to_wake: [(ThreadId, u8, u32); 64] = [(0, 0, 0); 64];
    let mut count = 0usize;
    {
        let _guard = SLEEP_QUEUE_LOCK.lock();
        let mut cur = SLEEP_QUEUE_HEAD.load(Ordering::Relaxed);
        while cur != u32::MAX && count < 64 {
            let t = unsafe { thread_mut_from_ref(cur) };
            if t.sleep_deadline_ns > now_ns {
                break;
            } // sorted: rest are later
            let next = t.sleep_next;
            let target = t.last_cpu.load(Ordering::Relaxed);
            to_wake[count] = (cur, t.effective_priority, target);
            t.sleep_next = u32::MAX;
            count += 1;
            cur = next;
        }
        SLEEP_QUEUE_HEAD.store(cur, Ordering::Release);
    }

    let waker_cpu = smp::cpu_id();
    // Wake collected threads (outside the lock).
    for i in 0..count {
        let (tid, prio, mut target) = to_wake[i];
        // Plan A: steal-to-waker for stale targets.  If target CPU's
        // last tick is more than STALE_TICK_THRESHOLD_NS old (KVM
        // virtual-timer dropped, vCPU host-descheduled, etc.), the
        // IPI we'd send won't be processed promptly and the woken
        // thread would sit on target's runqueue for hundreds of ms
        // to seconds.  Re-target to the waker CPU instead — the
        // thread runs immediately at the cost of cache locality.
        // Skip this re-target for the (target == waker) case
        // because last_cpu == self isn't a tail concern.
        // Lowered from 100 ms to 30 ms after Phase 5p flake hunt:
        // when KVM descheduled the host vCPU for >100 ms (we saw 94 s
        // tick gaps), the original 100 ms threshold meant most wakes
        // still went to a CPU that had no recent tick.  Retargeting
        // to the waker CPU much sooner reduces the wake-latency tail.
        const STALE_TICK_THRESHOLD_NS: u64 = 30_000_000; // 30 ms
        if target != waker_cpu && (target as usize) < smp::MAX_CPUS {
            let target_last = PER_CPU_LAST_TICK_NS[target as usize]
                .load(Ordering::Relaxed);
            if target_last != 0
                && now_ns.saturating_sub(target_last) > STALE_TICK_THRESHOLD_NS
            {
                target = waker_cpu;
                STALE_TARGET_RETARGET_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Wait for the thread's parking stack switch to complete.
        while thread_ref(tid).stack_switch_pending.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let t = unsafe { thread_mut_from_ref(tid) };
        t.blocked_on = BlockReason::None;
        t.sleep_deadline_ns = 0;
        // NEW_INV: store ON_CPU_PENDING (was u32::MAX from park_for_sleep)
        // BEFORE state=Ready, so rescue's on==MAX orphan predicate cannot
        // observe (state=Ready ∧ on_cpu=MAX).
        thread_ref(tid).on_cpu.store(ON_CPU_PENDING, Ordering::Release);
        // Diagnostic: stamp wake timestamp for the wake-to-dispatch
        // latency histogram.  Set BEFORE state=Ready so try_switch on
        // any CPU that picks up this thread observes a non-zero
        // timestamp.
        thread_ref(tid).wake_pending_ts_ns.store(now_ns, Ordering::Relaxed);
        t.state = ThreadState::Ready;
        trace_sched(tid, 15); // 15=sleep_wake (state=Ready, about to enqueue)
        set_enq_tag(7); // 7=sleep_timer
        percpu_enqueue(target, prio, tid);
        // Force preemption of the target CPU's currently-running thread
        // by setting yield_asap before sending the reschedule IPI.  The
        // IPI's try_switch checks yield_asap and preempts when set,
        // instead of just decrementing quantum by 1 and returning.
        // This exposes latent preemption-unsafety that the previous
        // ~100 ms quantum-cycle masked; the audit-and-fix path is the
        // current strategy for boot-throughput improvement.
        let waker = waker_cpu;
        if target != waker {
            let pcpu_target = smp::get(target);
            let target_cur = pcpu_target.current_thread.load(Ordering::Relaxed);
            let target_idle = pcpu_target.idle_thread_id.load(Ordering::Relaxed);
            if target_cur != target_idle && target_cur != 0 {
                // Use the ART-checked accessor: between loading
                // current_thread and reaching here the thread could have
                // exited and the tid become stale.  thread_ref_opt
                // returns None on a missing ART entry instead of
                // dereferencing a null/garbage pointer.
                if let Some(t) = thread_ref_opt(target_cur) {
                    t.yield_asap.store(true, Ordering::Release);
                    FORCED_PREEMPT_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            }
            crate::arch::irq::send_reschedule_ipi(target);
        }
    }
}

/// Diagnostic: total forced preemptions from sleep-wake.  Surfaced in
/// the WATCHDOG dump alongside other stall counters.
pub static FORCED_PREEMPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Diagnostic: aggregate wake-to-dispatch latency (ns) for threads
/// woken by check_sleep_timers (or any other code path that stamps
/// `wake_pending_ts_ns`).  Cleared by try_switch when the thread is
/// first dispatched onto a CPU.  WATCHDOG dump derives the running
/// average from these two counters, exposing what the actual sleep_ms
/// wake latency floor looks like under live load.
pub static SLEEP_WAKE_LATENCY_NS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static SLEEP_WAKE_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);
pub static SLEEP_WAKE_LATENCY_NS_MAX: AtomicU64 = AtomicU64::new(0);

/// Bucketed histogram of wake-to-dispatch latencies, log10-style.
/// Bucket index → upper bound (monotonic ns):
///   0: <  100 us         (sub-tick fast path)
///   1: <    1 ms
///   2: <   10 ms          (one TICK_INTERVAL_NS — expected typical)
///   3: <  100 ms          (10 ticks — IPI loss recovery floor)
///   4: <    1 s
///   5: <   10 s
///   6: >= 10 s            (catastrophic outlier)
pub static SLEEP_WAKE_LATENCY_BUCKETS: [AtomicU64; 7] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Per-CPU last tick timestamp (monotonic ns).  Updated at the top
/// of `tick()`.  A multi-second gap means the LAPIC tick on that CPU
/// stopped firing — the most likely cause of the wake-latency
/// long-tail outliers when target CPU's IPI was lost AND its own
/// tick didn't recover.
pub static PER_CPU_LAST_TICK_NS: [AtomicU64; smp::MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; smp::MAX_CPUS]
};
/// Largest observed gap between consecutive ticks on any CPU (ns).
/// If this stays close to TICK_INTERVAL_NS, ticks are healthy; if it
/// blows up to multi-second values, the tick handler isn't running
/// when expected.
pub static PER_CPU_TICK_MAX_GAP_NS: AtomicU64 = AtomicU64::new(0);

/// Plan A counter: number of sleep wakes that were re-targeted from
/// last_cpu to the waker CPU because last_cpu's tick had gone stale
/// past STALE_TICK_THRESHOLD_NS.  A high ratio (relative to
/// SLEEP_WAKE_LATENCY_COUNT) means the tail mitigation is firing
/// often — i.e., target CPUs are routinely going silent under host
/// load.
pub static STALE_TARGET_RETARGET_COUNT: AtomicU64 = AtomicU64::new(0);

/// Check per-task alarm timers and deliver SIGALRM.
/// Called from tick() before try_switch.
fn check_alarm_timers() {
    let now_ns = get_monotonic_ns();
    let mut fired = [0u32; 64];
    let mut count = 0usize;
    let mut next_earliest: u64 = 0;

    // Lock-free: alarm fields are only written by the owning task (alarm())
    // or by this tick path; no concurrent mutation.
    SCHED_TASK_ART.for_each(|_key, val| {
        let task = unsafe { &mut *(val as *mut Task) };
        if task.active && task.alarm_deadline_ns != 0 {
            if task.alarm_deadline_ns <= now_ns {
                if task.alarm_interval_ns != 0 {
                    task.alarm_deadline_ns = now_ns + task.alarm_interval_ns;
                } else {
                    task.alarm_deadline_ns = 0;
                }
                if count < 64 {
                    fired[count] = task.id;
                    count += 1;
                }
            }
            // Track the next earliest alarm (including rearmed ones).
            if task.alarm_deadline_ns != 0 {
                if next_earliest == 0 || task.alarm_deadline_ns < next_earliest {
                    next_earliest = task.alarm_deadline_ns;
                }
            }
        }
    });

    // Update the cached earliest alarm deadline.
    EARLIEST_ALARM_NS.store(next_earliest, Ordering::Relaxed);

    for i in 0..count {
        send_signal_to_task(fired[i], super::task::SIGALRM);
    }
}

/// Check per-thread interval timers and deliver signals when they fire.
fn check_interval_timers() {
    let now_ns = get_monotonic_ns();
    let mut fired_tid: ThreadId = 0;
    let mut fired_sig: u32 = 0;
    let mut fired_interval: u64 = 0;
    let mut found = false;
    let mut next_earliest: u64 = 0;

    // Lock-free: timer fields are only written by the owning thread
    // (sys_timer_create) or by this tick path.
    SCHED_THREAD_ART.for_each(|key, val| {
        let t = unsafe { &*(val as *const Thread) };
        if t.state != ThreadState::Dead
            && t.stack_base != 0
            && t.timer_signal != 0
            && t.timer_next_ns != 0
        {
            if !found && now_ns >= t.timer_next_ns {
                fired_tid = key as ThreadId;
                fired_sig = t.timer_signal;
                fired_interval = t.timer_interval_ns;
                // Re-arm the timer while we have the pointer.
                let t_mut = unsafe { &mut *(val as *mut Thread) };
                t_mut.timer_next_ns = if fired_interval != 0 {
                    now_ns + fired_interval
                } else {
                    0
                };
                found = true;
            }
            // Track the next earliest interval timer (including rearmed).
            let next = unsafe { &*(val as *const Thread) }.timer_next_ns;
            if next != 0 && (next_earliest == 0 || next < next_earliest) {
                next_earliest = next;
            }
        }
    });

    // Update the cached earliest interval timer deadline.
    EARLIEST_INTERVAL_NS.store(next_earliest, Ordering::Relaxed);

    if found {
        send_signal_to_thread(fired_tid, fired_sig);
    }
}

/// Park the current thread for a timed sleep.
/// Sets the deadline and blocks the thread (off-CPU).
pub fn park_current_for_sleep(deadline_ns: u64) {
    // Disable IRQs for the entire function. Same preemption race as
    // park_current_for_ipc — timer after state=Blocked would let try_switch
    // overwrite state to Ready and re-enqueue.
    let irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id() as usize;
    let cpu_idx = cpu as u32;
    drain_deferred_requeue(cpu_idx);

    let tid_for_sp = smp::get(cpu_idx).current_thread.load(Ordering::Relaxed);
    let frame_sp = unsafe { thread_mut_from_ref(tid_for_sp) }.syscall_frame_sp;

    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Set deadline before marking Blocked. Lock-free: we own the running thread.
    let thread = unsafe { thread_mut_from_ref(tid as ThreadId) };
    thread.sleep_deadline_ns = deadline_ns;
    thread.saved_sp = frame_sp;
    thread.saved_sp_source = 5; // park_for_sleep
    thread.state = ThreadState::Blocked;
    thread.blocked_on = BlockReason::Sleep;

    // Release on_cpu BEFORE inserting into sleep queue. Once the thread is
    // visible in the sleep queue, check_sleep_timers on any CPU may expire it
    // and call percpu_enqueue. If on_cpu still holds the old CPU value, the
    // scheduling CPU's CAS will fail (DOUBLE-SCHED). Same pattern as
    // park_current_for_ipc.
    if (tid as ThreadId) != idle_id {
        thread_ref(tid as ThreadId).on_cpu.store(u32::MAX, Ordering::Release);
    }
    trace_sched(tid as u32, 13); // 13=park_sleep (state=Blocked, on_cpu=MAX)

    // Mark per-thread stack_switch_pending BEFORE sleep_queue_insert.
    // Once visible, check_sleep_timers may expire and enqueue us
    // immediately. It spins on this flag before enqueueing.
    thread_ref(tid as ThreadId).stack_switch_pending.store(true, Ordering::Release);
    parked_tid()[cpu].store(tid as u32, Ordering::Release);

    // Insert into sorted sleep queue so check_sleep_timers can find us.
    sleep_queue_insert(tid as ThreadId, deadline_ns);

    // SA notification for the parked thread (lock-free).
    let parked_task_id = thread.task_id;
    let sa_enabled = task_ref(parked_task_id).sa_enabled;

    // Pick next thread from per-CPU queue.
    let next_id = percpu_pick_next(cpu_idx, idle_id);
    let prev_task = thread_ref(tid as ThreadId).task_id;
    let next_task = thread_ref(next_id).task_id;
    if prev_task != next_task {
        let next_root = {
            let tptr = TASK_TABLE.get(next_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + kstack_size());

    // Claim on_cpu for next thread (ON_CPU_PENDING → cpu).
    if next_id != idle_id {
        if let Err(other_cpu) = thread_ref(next_id).on_cpu.compare_exchange(
            ON_CPU_PENDING, cpu_idx, Ordering::AcqRel, Ordering::Acquire,
        ) {
            crate::println!(
                "DOUBLE-SCHED(sleep): tid={} already on cpu={}, this cpu={}",
                next_id, other_cpu, cpu_idx
            );
            thread_ref(next_id).killed.store(true, Ordering::Release);
            // Pick idle instead.
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            pcpu.current_thread.store(idle_id, Ordering::Relaxed);
            pending_switch_sp()[cpu].store(idle_sp, Ordering::Release);
            let _ = irq_saved;
            return;
        }
        thread_ref(next_id).on_cpu_set_by.store(5, Ordering::Relaxed); // 5=park_sleep
        // #120 dispatch-symmetry: clear pending state + bump cas_ok counter.
        dispatch_cas_ok(pcpu, next_id);
        // Set Running IMMEDIATELY after CAS — close TOCTOU window (see try_switch).
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    } else {
        unsafe { thread_mut_from_ref(next_id) }.state = ThreadState::Running;
    }

    // Safety: next_id was just dequeued, we own it.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    let next_sp = next_t.saved_sp;

    // Reprogram the one-shot timer so this CPU wakes at the sleep deadline.
    // Without this, the dynamic tick may have the timer set far in the future
    // (up to MAX_IDLE_NS = 1s), causing the sleep to overshoot its deadline.
    // Done here with IRQs disabled so the timer cannot fire before the switch.
    crate::arch::timer::program_oneshot_ns(deadline_ns);

    // Mark park-switch-pending (see park_current_for_ipc for explanation).
    park_switch_pending()[cpu].store(true, Ordering::Release);

    // Store pending_switch before restoring IRQs — see park_current_for_ipc.
    pending_switch_sp()[cpu].store(next_sp, Ordering::Release);

    if sa_enabled {
        let tptr = TASK_TABLE.get(parked_task_id) as *mut Task;
        let task = unsafe { &*tptr };
        let waiter = task.sa_waiter.load(Ordering::Acquire);
        if waiter != u32::MAX && waiter as usize != tid {
            task.sa_event.store(tid as u64, Ordering::Release);
            task.sa_pending.store(true, Ordering::Release);
            wake_thread(waiter);
        }
    }

    // Leave IRQs disabled — exception handler consumes pending_switch.
    let _ = irq_saved;
}

/// Set an alarm timer for the current task.
/// Returns previous remaining time in nanoseconds.
pub fn alarm(initial_ns: u64, interval_ns: u64) -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let task_id = thread_ref(tid).task_id;
    // Safe: only the current task modifies its own alarm fields.
    let task = unsafe { task_mut_from_ref(task_id) };

    let now = get_monotonic_ns();
    let prev_remaining = if task.alarm_deadline_ns > now {
        task.alarm_deadline_ns - now
    } else {
        0
    };

    if initial_ns == 0 {
        task.alarm_deadline_ns = 0;
        task.alarm_interval_ns = 0;
    } else {
        let deadline = now + initial_ns;
        task.alarm_deadline_ns = deadline;
        task.alarm_interval_ns = interval_ns;
        // If this alarm is earlier than the cached earliest, update and reprogram.
        let cached = EARLIEST_ALARM_NS.load(Ordering::Relaxed);
        if cached == 0 || deadline < cached {
            EARLIEST_ALARM_NS.store(deadline, Ordering::Relaxed);
            crate::arch::timer::program_oneshot_ns(deadline);
        }
    }
    prev_remaining
}

/// L4-style direct handoff: sender donates its remaining quantum to receiver.
/// Saves sender's SP, loads receiver as current thread, stores receiver's SP
/// in PENDING_SWITCH_SP. Receiver must already have its frame injected.
pub fn handoff_to(receiver_tid: ThreadId) {
    // Disable IRQs for the entire function. Same preemption race as
    // voluntary_reschedule — timer after percpu_enqueue would let try_switch
    // double-enqueue the sender.
    let irq_saved = crate::arch::irq::disable();

    let cpu = smp::cpu_id() as usize;
    let cpu_id = cpu as u32;
    drain_deferred_requeue(cpu_id);

    let sender_tid_for_sp = smp::get(cpu_id).current_thread.load(Ordering::Relaxed);
    let frame_sp = unsafe { thread_mut_from_ref(sender_tid_for_sp) }.syscall_frame_sp;

    let pcpu = smp::current();
    let sender_tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;

    // Safety: sender is Running on this CPU, we own it.
    let (sender_prio, remaining_quantum, sender_task);
    {
        let sender = unsafe { thread_mut_from_ref(sender_tid as ThreadId) };
        sender.saved_sp = frame_sp;
        sender_prio = sender.effective_priority;
        remaining_quantum = sender.quantum;
        sender_task = sender.task_id;
        // NOTE: state stays Running here. Set to Ready AFTER deferred store.
    }
    // Defer re-enqueue of sender. Same pattern as voluntary_reschedule:
    // we're still on the sender's kernel stack, so immediate percpu_enqueue
    // would let another CPU steal the sender and use the same stack.
    // NEW_INV: store ON_CPU_PENDING BEFORE slot fill and BEFORE state=Ready.
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        if (sender_tid as ThreadId) != idle_id {
            thread_ref(sender_tid as ThreadId)
                .on_cpu
                .store(ON_CPU_PENDING, Ordering::Release);
            let packed = (sender_tid as u64) | ((sender_prio as u64) << 32)
                | ((cpu_id as u64) << 40);
            let old_deferred = deferred_requeue()[cpu].swap(packed, Ordering::AcqRel);
            if old_deferred != 0 {
                // Defensive: handoff_to entry should have drained this slot.
                // Under NEW_INV, lost tid already has on_cpu=PENDING.
                let lost_tid = (old_deferred & 0xFFFFFFFF) as u32;
                let lost_prio = ((old_deferred >> 32) & 0xFF) as u8;
                let lost_target = ((old_deferred >> 40) & 0xFF) as u32;
                crate::println!(
                    "DEFERRED-OVERWRITE(handoff): cpu={} lost tid={} prio={} replaced by tid={}",
                    cpu, lost_tid, lost_prio, sender_tid
                );
                set_enq_tag(10);
                percpu_enqueue(lost_target, lost_prio, lost_tid);
            }
            unsafe { thread_mut_from_ref(sender_tid as ThreadId) }.state = ThreadState::Ready;
            trace_sched(sender_tid as u32, 1); // 1=deferred_store
        }
    }

    // Donate remaining quantum to receiver.
    // Safety: receiver was Blocked (parked), not on any queue or CPU.
    let receiver = unsafe { thread_mut_from_ref(receiver_tid) };
    receiver.quantum = remaining_quantum;
    let recv_task = receiver.task_id;
    if sender_task != recv_task {
        let next_root = {
            let tptr = TASK_TABLE.get(recv_task) as *const Task;
            if !tptr.is_null() {
                unsafe { (*tptr).page_table_root }
            } else {
                0
            }
        };
        if next_root != 0 {
            crate::mm::hat::switch_page_table(next_root);
        } else {
            let kern_root = crate::mm::hat::kernel_pt_root();
            if kern_root != 0 {
                crate::mm::hat::switch_page_table(kern_root);
            }
        }
    }

    crate::arch::trapframe::update_kernel_stack(receiver.stack_base + kstack_size());

    // Claim on_cpu for receiver (parked threads have on_cpu=MAX from
    // park_current_for_ipc, so CAS expects MAX).
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        if receiver_tid != idle_id {
            pcpu.dispatching_tid.store(receiver_tid, Ordering::Release);
            if let Err(other_cpu) = thread_ref(receiver_tid).on_cpu.compare_exchange(
                u32::MAX, cpu_id, Ordering::AcqRel, Ordering::Acquire,
            ) {
                crate::println!(
                    "DOUBLE-SCHED(handoff): tid={} already on cpu={}, this cpu={}",
                    receiver_tid, other_cpu, cpu_id
                );
                thread_ref(receiver_tid).killed.store(true, Ordering::Release);
                pcpu.dispatching_tid.store(0, Ordering::Release);
                // Stay on sender. Clear deferred store and restore on_cpu.
                deferred_requeue()[cpu].store(0, Ordering::Release);
                let sender2 = unsafe { thread_mut_from_ref(sender_tid as ThreadId) };
                sender2.state = ThreadState::Running;
                thread_ref(sender_tid as ThreadId).on_cpu.store(cpu_id, Ordering::Release);
                return;
            }
            thread_ref(receiver_tid).on_cpu_set_by.store(4, Ordering::Relaxed); // 4=handoff
        }
    }

    // Activate receiver.
    receiver.state = ThreadState::Running;
    pcpu.current_thread.store(receiver_tid, Ordering::Relaxed);
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        if receiver_tid != idle_id {
            pcpu.dispatching_tid.store(0, Ordering::Release);
        }
    }
    let recv_sp = receiver.saved_sp;

    // Sanity check: saved_sp must be within the thread's kstack.
    // Idle threads run on boot stacks (ring 0), not their allocated kstack.
    {
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);
        let is_idle = receiver_tid == idle_id;
        let kbase = receiver.stack_base;
        let kend = kbase as u64 + kstack_size() as u64;
        if !is_idle && (recv_sp < kbase as u64 || recv_sp >= kend) {
            crate::println!(
                "BUG: handoff_to: tid={} saved_sp={:#x} OUTSIDE kstack {:#x}..{:#x} (source={})",
                receiver_tid, recv_sp, kbase, kend, receiver.saved_sp_source
            );
            // Kill this thread and switch to idle instead.
            thread_ref(receiver_tid).killed.store(true, Ordering::Release);
            let idle_sp = thread_ref(idle_id).saved_sp;
            unsafe { thread_mut_from_ref(idle_id) }.state = ThreadState::Running;
            pcpu.current_thread.store(idle_id, Ordering::Relaxed);
            pending_switch_sp()[cpu].store(idle_sp, Ordering::Release);
            return;
        }
    }

    // Reprogram the timer so the deferred slot (holding sender) is drained
    // promptly — same rationale as voluntary_reschedule.
    crate::arch::timer::program_oneshot_ns(get_monotonic_ns() + TICK_INTERVAL_NS);

    // Store pending_switch before restoring IRQs — see park_current_for_ipc
    // comment for why this ordering is critical with preemptive syscalls.
    pending_switch_sp()[cpu].store(recv_sp, Ordering::Release);
    // Leave IRQs disabled through exception handler return.
    let _ = irq_saved;
}

// --- Scheduler Activations API ---

/// Register the current task for scheduler activations.
pub fn sa_register() {
    let task_id = current_task_id();
    if task_id == 0 {
        return;
    }
    // Safe: only the current task modifies its own sa_enabled.
    unsafe { task_mut_from_ref(task_id) }.sa_enabled = true;
}

/// Block until a scheduler activation event occurs.
/// Returns the blocked kthread's TID, or u64::MAX on error.
pub fn sa_wait() -> u64 {
    let task_id = current_task_id();
    if task_id == 0 {
        return u64::MAX;
    }

    let tptr = TASK_TABLE.get(task_id) as *mut Task;
    if tptr.is_null() {
        return u64::MAX;
    }
    let task = unsafe { &*tptr };

    // Fast path: event already pending.
    if task.sa_pending.swap(false, Ordering::SeqCst) {
        task.sa_waiter.store(u32::MAX, Ordering::Relaxed);
        return task.sa_event.load(Ordering::Relaxed);
    }

    // Register as waiter.
    let tid = current_thread_id();
    clear_wakeup_flag(tid);
    task.sa_waiter.store(tid, Ordering::Release);

    // Double-check after registering (prevents lost wakeup).
    if task.sa_pending.swap(false, Ordering::SeqCst) {
        task.sa_waiter.store(u32::MAX, Ordering::Relaxed);
        return task.sa_event.load(Ordering::Relaxed);
    }

    // Block until woken by SA notification.
    block_current(BlockReason::ActivationWait);
    task.sa_waiter.store(u32::MAX, Ordering::Relaxed);
    task.sa_pending.store(false, Ordering::Relaxed);
    task.sa_event.load(Ordering::Relaxed)
}

/// Get the index (0-based) of the current kthread within its task.
pub fn sa_getid() -> u64 {
    let tid = current_thread_id();
    let task_id = current_task_id();
    let mut idx = 0u64;
    let mut found = false;
    SCHED_THREAD_ART.for_each(|key, val| {
        if found {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.task_id == task_id && t.state != ThreadState::Dead && (t.stack_base != 0 || key == 0) {
            if key as u32 == tid {
                found = true;
                return;
            }
            idx += 1;
        }
    });
    if found { idx } else { u64::MAX }
}

/// Set the coscheduling group for the current thread. group=0 removes from any group.
pub fn cosched_set(group: u32) {
    let tid = current_thread_id();
    thread_ref(tid)
        .cosched_group
        .store(group, Ordering::Relaxed);
}

/// Set CPU affinity mask for a thread. Returns true on success.
/// Takes u64 at the syscall ABI boundary; internally converts to CpuMask.
pub fn set_affinity(tid: u32, mask: u64) -> bool {
    if (tid as usize) >= RadixTable::capacity() || mask == 0 {
        return false;
    }
    thread_ref(tid)
        .affinity_mask
        .store_mask(&cpumask::CpuMask::from_u64(mask), Ordering::Relaxed);
    true
}

/// Get CPU affinity mask for a thread.
/// Returns u64 (low 64 bits) for syscall ABI compatibility.
pub fn get_affinity(tid: u32) -> u64 {
    if (tid as usize) >= RadixTable::capacity() {
        return 0;
    }
    thread_ref(tid)
        .affinity_mask
        .load_mask(Ordering::Relaxed)
        .as_u64()
}
