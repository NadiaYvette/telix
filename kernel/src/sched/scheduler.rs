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
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

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

/// Per-CPU saved frame SP. The exception handler stores the current frame_sp
/// here before calling syscall dispatch, so that park_current_for_ipc() can
/// read it without changing dispatch()'s signature.
static CURRENT_FRAME_SP: [AtomicU64; smp::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; smp::MAX_CPUS]
};

/// Per-CPU pending context switch target SP. When a syscall handler parks the
/// current thread or does a direct handoff, it stores the target thread's SP
/// here. The exception handler checks this after dispatch() returns and uses
/// it as the new SP if non-zero.
static PENDING_SWITCH_SP: [AtomicU64; smp::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; smp::MAX_CPUS]
};

/// Per-CPU deferred kernel stack free. When a thread exits, it can't free
/// its own stack (it's running on it). The address is stored here and freed
/// by the next thread scheduled on that CPU.
static DEFERRED_KSTACK: [AtomicUsize; smp::MAX_CPUS] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; smp::MAX_CPUS]
};

/// Per-CPU deferred thread ID — the thread whose kstack is in DEFERRED_KSTACK.
/// When try_switch drains the deferred free, it also sets stack_base=0 on this
/// thread, making the slot eligible for reuse. This prevents a race where a
/// slot is reused while the dead thread is still physically running.
static DEFERRED_THREAD: [AtomicUsize; smp::MAX_CPUS] = {
    const INIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    [INIT; smp::MAX_CPUS]
};

/// Per-CPU deferred killed-thread cleanup. When try_switch preempts a
/// killed user thread, it marks it Dead and stores the thread ID here.
/// The next tick() call drains this and does full cleanup (aspace destroy, etc.).
static DEFERRED_KILL: [AtomicUsize; smp::MAX_CPUS] = {
    const INIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    [INIT; smp::MAX_CPUS]
};

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

/// Per-CPU run queues: 256 linked-list heads + 256-bit active bitmap.
/// Each CPU's instance is protected by its own SpinLock in PERCPU_RQ.
struct PerCpuRunQueues {
    queues: [RunQueue; NUM_PRIORITIES],
    active: [u64; 4],
    cosched_burst: u32,
}

impl PerCpuRunQueues {
    const fn new() -> Self {
        Self {
            queues: [const { RunQueue::new() }; NUM_PRIORITIES],
            active: [0; 4],
            cosched_burst: 0,
        }
    }

    /// Enqueue a thread at the given priority level.
    fn push(&mut self, prio: u8, tid: ThreadId) {
        self.queues[prio as usize].push(tid);
        self.active[prio as usize / 64] |= 1u64 << (prio as usize % 64);
    }

    /// Dequeue the highest-priority (lowest numeric) thread. O(1) via bitmap.
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

    /// Find and dequeue a thread in the given coscheduling group. Searches by priority.
    fn pop_for_group(&mut self, group: u32) -> Option<ThreadId> {
        for word in 0..4 {
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
                return true;
            }
            cur = thread_ref(cur).run_next.load(Ordering::Relaxed);
        }
        false
    }

    /// Check if any threads are enqueued. O(1) via bitmap.
    fn has_ready(&self) -> bool {
        self.active[0] | self.active[1] | self.active[2] | self.active[3] != 0
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
                            return Some(tid);
                        }
                    }
                    bits &= !(1u64 << bit);
                }
            }
        }
        None
    }
}

static PERCPU_RQ: [SpinLock<PerCpuRunQueues>; smp::MAX_CPUS] = {
    const INIT: SpinLock<PerCpuRunQueues> = SpinLock::new(PerCpuRunQueues::new());
    [INIT; smp::MAX_CPUS]
};

/// Enqueue a thread onto the per-CPU run queue for the given target CPU.
/// The caller must ensure the thread's state is Ready before calling.
fn percpu_enqueue(target_cpu: u32, prio: u8, tid: ThreadId) {
    let mut rq = PERCPU_RQ[target_cpu as usize].lock();
    rq.push(prio, tid);
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
        if let Some(mut rq) = PERCPU_RQ[victim as usize].try_lock() {
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

/// Slab size for Thread entries (Thread is ~136 bytes, fits in 256-byte slab).
const THREAD_SLAB_SIZE: usize = 256;

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
    unsafe {
        (*thread_ptr).id = 0;
        (*thread_ptr).state = ThreadState::Running;
        (*thread_ptr).task_id = 0;
        (*thread_ptr).port_id = thread0_port;
        (*thread_ptr).base_priority = 255;
        (*thread_ptr).effective_priority = 255;
        (*thread_ptr).quantum = u32::MAX;
        (*thread_ptr).default_quantum = u32::MAX;
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
    unsafe {
        (*ptr).id = id;
        (*ptr).state = ThreadState::Running;
        (*ptr).task_id = 0;
        (*ptr).port_id = idle_port;
        (*ptr).base_priority = 255;
        (*ptr).effective_priority = 255;
        (*ptr).quantum = u32::MAX;
        (*ptr).default_quantum = u32::MAX;
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

    let stack_page = crate::mm::phys::alloc_page()?;
    let stack_base = stack_page.as_usize();
    let stack_top = stack_base + crate::mm::page::page_size();

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
        let nsrv = crate::io::namesrv::NAMESRV_PORT.load(core::sync::atomic::Ordering::Acquire);
        if nsrv != u64::MAX {
            crate::cap::grant_send_cap(task_id, nsrv);
        }

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
    let stack_alloc_pages = 2;
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
    let kstack_page = crate::mm::phys::alloc_page()?;
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + ps;

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

    let thread = unsafe { thread_mut_from_ref(thread_id) };
    thread.killed.store(false, Ordering::Release);
    thread
        .affinity_mask
        .store_mask(&cpumask::CpuMask::all(), Ordering::Relaxed);
    thread.last_cpu.store(smp::cpu_id(), Ordering::Relaxed);

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

    let kstack_page = crate::mm::phys::alloc_page()?;
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + page::page_size();

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
    let mut rq = PERCPU_RQ[cpu as usize].lock();
    // First try local queue.
    if let Some(tid) = rq.pop_highest() {
        return tid;
    }
    drop(rq);
    // Nothing local — try work stealing.
    if let Some(tid) = try_steal(cpu) {
        return tid;
    }
    idle_id
}

/// Pick next thread, preferring a cosched group mate on the current CPU.
fn percpu_pick_next_cosched(cpu: u32, idle_id: ThreadId, prev_group: u32) -> (ThreadId, bool) {
    let mut rq = PERCPU_RQ[cpu as usize].lock();
    if prev_group != 0 && rq.cosched_burst < MAX_COSCHED_BURST {
        if let Some(tid) = rq.pop_for_group(prev_group) {
            rq.cosched_burst += 1;
            COSCHED_HITS.fetch_add(1, Ordering::Relaxed);
            return (tid, true);
        }
    }
    rq.cosched_burst = 0;
    if let Some(tid) = rq.pop_highest() {
        return (tid, false);
    }
    drop(rq);
    // Nothing local — try work stealing.
    if let Some(tid) = try_steal(cpu) {
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
    let tid = DEFERRED_KILL[cpu].swap(usize::MAX, Ordering::AcqRel);
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
pub fn tick(current_sp: u64) -> u64 {
    check_sleep_timers();
    check_alarm_timers();
    check_interval_timers();

    // Drain deferred killed-thread cleanup from the previous tick.
    drain_deferred_kills();

    try_switch(current_sp)
}

/// Attempt to switch threads on the current CPU.
/// Uses only per-CPU run queue locks — does NOT take the global SCHEDULER lock.
fn try_switch(current_sp: u64) -> u64 {
    let cpu = smp::cpu_id();
    let pcpu = smp::get(cpu);
    let idle_id_for_load = pcpu.idle_thread_id.load(Ordering::Relaxed);
    let cur_for_load = pcpu.current_thread.load(Ordering::Relaxed);
    super::hotplug::tick_load(cpu, cur_for_load == idle_id_for_load);

    // Drain deferred kernel stack free from a previous exit on this CPU.
    let deferred = DEFERRED_KSTACK[cpu as usize].load(Ordering::Acquire);
    if deferred != 0 {
        let cur_tid = pcpu.current_thread.load(Ordering::Relaxed);
        // Safety: cur_tid is Running on this CPU, we own it.
        let cur_stack = thread_ref(cur_tid).stack_base;
        if cur_stack != deferred {
            DEFERRED_KSTACK[cpu as usize].store(0, Ordering::Release);
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(deferred));
            let dead_tid = DEFERRED_THREAD[cpu as usize].swap(usize::MAX, Ordering::AcqRel);
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
        let rq = PERCPU_RQ[cpu as usize].lock();
        let has_work = rq.has_ready();
        drop(rq);
        if !has_work {
            match try_steal_for_idle(cpu) {
                Some(tid) => {
                    let prio = thread_ref(tid).prio.load(Ordering::Relaxed);
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
            // Safety: prev_id is Running on this CPU, we own it.
            let t = unsafe { thread_mut_from_ref(prev_id) };
            t.quantum = t.quantum.saturating_sub(1);
            if t.quantum != 0 {
                crate::sync::rcu::rcu_quiescent();
                return current_sp; // No preemption needed.
            }
            t.quantum = t.default_quantum;
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
        crate::sync::rcu::rcu_quiescent();
        return current_sp;
    }

    crate::sched::stats::CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
    crate::trace::trace_event(crate::trace::EVT_CTX_SWITCH, prev_id, next_id);

    // Save current thread's SP. Safety: we own the running thread.
    let prev_task;
    {
        let prev_t = unsafe { thread_mut_from_ref(prev_id) };
        prev_t.saved_sp = current_sp;
        let mut prev_prio = prev_t.effective_priority;
        prev_task = prev_t.task_id;
        // If the thread was demoted by block_current (prio 254) and has been
        // woken (wakeup flag set), restore its base priority so it gets
        // re-enqueued at the correct level instead of being starved.
        if prev_prio == 254 && prev_t.base_priority < 254 {
            if thread_ref(prev_id).wakeup.load(Ordering::Relaxed) {
                prev_t.effective_priority = prev_t.base_priority;
                thread_ref(prev_id)
                    .prio
                    .store(prev_t.base_priority, Ordering::Relaxed);
                prev_prio = prev_t.base_priority;
            }
        }
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
                DEFERRED_KILL[cpu as usize].store(prev_id as usize, Ordering::Release);
                // Also defer kstack free.
                let kstack_base = prev_t.stack_base;
                DEFERRED_THREAD[cpu as usize].store(prev_id as usize, Ordering::Release);
                DEFERRED_KSTACK[cpu as usize].store(kstack_base, Ordering::Release);
            } else {
                prev_t.state = ThreadState::Ready;
                percpu_enqueue(cpu, prev_prio, prev_id);
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

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + page::page_size());

    // Activate next thread. Safety: next_id was just dequeued, we own it.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    next_t.state = ThreadState::Running;
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    thread_ref(next_id).last_cpu.store(cpu, Ordering::Relaxed);

    // RCU quiescent state: all syscall read-side references from the
    // previous timeslice are now dead.  Process deferred frees.
    crate::sync::rcu::rcu_quiescent();

    next_t.saved_sp
}

/// Voluntarily reschedule from syscall context.
/// The trap handler must have already called `store_frame_sp()`.
/// If another thread is runnable, sets PENDING_SWITCH_SP so the trap
/// handler performs the context switch on return.
pub fn voluntary_reschedule() {
    let cpu = smp::cpu_id();
    let pcpu = smp::current();
    let cur_id = pcpu.current_thread.load(Ordering::Relaxed);
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Save frame SP into thread struct.
    let frame_sp = CURRENT_FRAME_SP[cpu as usize].load(Ordering::Acquire);
    let cur_prio;
    let cur_task;
    {
        let t = unsafe { thread_mut_from_ref(cur_id) };
        t.saved_sp = frame_sp;
        cur_prio = t.effective_priority;
        cur_task = t.task_id;
        t.state = ThreadState::Ready;
    }

    // Re-enqueue current thread.
    if cur_id != idle_id {
        percpu_enqueue(cpu, cur_prio, cur_id);
    }

    // Pick next.
    let next_id = percpu_pick_next(cpu, idle_id);

    if cur_id == next_id {
        // No other thread to run — undo Ready, stay Running.
        let t = unsafe { thread_mut_from_ref(cur_id) };
        t.state = ThreadState::Running;
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

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + page::page_size());

    let next_t = unsafe { thread_mut_from_ref(next_id) };
    next_t.state = ThreadState::Running;
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    let next_sp = next_t.saved_sp;

    PENDING_SWITCH_SP[cpu as usize].store(next_sp, Ordering::Release);
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
    // Demote effective_priority to 254 (lowest non-idle) so try_switch
    // re-enqueues us at the bottom. This prevents blocked-spinning threads
    // from starving lower-priority threads on single-CPU.
    let tref = thread_ref(tid);
    // Save and demote priority atomically — no SCHEDULER lock needed.
    // effective_priority is synced from prio in try_switch.
    let saved_prio = tref.prio.swap(254, Ordering::AcqRel);
    unsafe { thread_mut_from_ref(tid) }.effective_priority = 254;
    // Signal the scheduler to preempt us on the next timer tick instead of
    // waiting for the full quantum. This prevents spinning threads from
    // starving real work on SMP systems.
    tref.yield_asap.store(true, Ordering::Release);
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
    crate::arch::irq::restore(saved);
}

/// Wake a blocked thread, making it runnable.
pub fn wake_thread(tid: ThreadId) {
    let tref = thread_ref(tid);
    tref.wakeup.store(true, Ordering::Release);
    // Clear yield_asap so the thread isn't preempted on the very next tick
    // before it can check the wakeup flag and exit block_current.
    tref.yield_asap.store(false, Ordering::Release);
    // If the thread was demoted to prio 254 by block_current, it may be
    // stuck in a ready queue where higher-priority threads prevent it from
    // running. Move it from its old CPU's prio-254 slot to the waker's CPU
    // at its base priority so it gets picked up promptly.
    let demoted_prio = tref.prio.load(Ordering::Relaxed);
    if demoted_prio == 254 {
        // Read base_priority directly from the thread struct (immutable after creation,
        // safe without SCHEDULER lock). Avoids deadlock when wake_thread is called
        // from exit_current_thread which already holds SCHEDULER.
        let base = tref.base_priority;
        if base < 254 {
            let old_cpu = tref.last_cpu.load(Ordering::Relaxed);
            let waker_cpu = smp::cpu_id();
            // Try to remove from old CPU's queue and re-enqueue at base prio.
            let removed = {
                if let Some(mut rq) = PERCPU_RQ[old_cpu as usize].try_lock() {
                    rq.remove_tid(tid)
                } else {
                    false
                }
            };
            if removed {
                percpu_enqueue(waker_cpu, base, tid);
            }
            // If we couldn't lock or find the thread (it may be currently
            // Running in WFI), that's OK — the wakeup flag is set and it
            // will exit block_current on its next check.
        }
    }
    // Signal all CPUs so any core spinning in block_current's WFE wakes immediately.
    crate::arch::irq::send_event();
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
            t.state = ThreadState::Ready;
            t.blocked_on = BlockReason::None;
            t.sleep_deadline_ns = 0;
            let target = t.last_cpu.load(Ordering::Relaxed);
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
    let parent_frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);
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
        let nsrv = crate::io::namesrv::NAMESRV_PORT.load(core::sync::atomic::Ordering::Acquire);
        if nsrv != u64::MAX {
            crate::cap::grant_send_cap(child_task_id, nsrv);
        }
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
    let kstack_page = match crate::mm::phys::alloc_page() {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + page::page_size();

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

/// Terminate the current thread and destroy its task's resources.
/// This function never returns.
pub fn exit_current_thread(exit_code: i32) -> ! {
    let (
        tid,
        is_last_thread,
        aspace_id,
        pt_root,
        kstack_base,
        parent_task_id,
        _task_port,
        thread_port,
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
        )
    };

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
    DEFERRED_THREAD[cpu as usize].store(tid as usize, Ordering::Release);
    DEFERRED_KSTACK[cpu as usize].store(kstack_base, Ordering::Release);

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
            unsafe { thread_mut_from_ref(tid) }.effective_priority = to_prio;
            break;
        }
    }
}

/// Reset a thread's effective priority back to its base priority.
/// Lock-free: uses atomic store on prio + direct write to effective_priority.
pub fn reset_priority(tid: ThreadId) {
    let tref = thread_ref(tid);
    let base = tref.base_priority;
    tref.prio.store(base, Ordering::Release);
    unsafe { thread_mut_from_ref(tid) }.effective_priority = base;
}

/// Get a thread's current effective priority (lock-free).
pub fn thread_effective_priority(tid: ThreadId) -> u8 {
    if (tid as usize) < RadixTable::capacity() {
        thread_ref(tid).prio.load(Ordering::Acquire)
    } else {
        255
    }
}

// --- L4-style handoff scheduling ---

/// Store the current frame SP for use by park/handoff functions.
/// Called by the arch exception handler before dispatching a syscall.
pub fn store_frame_sp(sp: u64) {
    let cpu = smp::cpu_id() as usize;
    CURRENT_FRAME_SP[cpu].store(sp, Ordering::Release);
}

/// Take (read and clear) any pending context switch SP.
/// Called by the arch exception handler after syscall dispatch returns.
/// Returns 0 if no switch is pending.
pub fn take_pending_switch() -> u64 {
    let cpu = smp::cpu_id() as usize;
    PENDING_SWITCH_SP[cpu].swap(0, Ordering::AcqRel)
}

/// Check if a pending context switch is queued on this CPU.
/// Used by syscall dispatch to detect that park_current_for_ipc or handoff_to
/// changed `current_thread` — callers must skip thread-specific epilogue
/// (signal delivery, is_killed) since those queries would use the wrong thread.
pub fn has_pending_switch() -> bool {
    let cpu = smp::cpu_id() as usize;
    PENDING_SWITCH_SP[cpu].load(Ordering::Acquire) != 0
}

/// Get a thread's saved SP. Used by inject_recv_into_frame to write into
/// a parked thread's exception frame.
pub fn thread_saved_sp(tid: ThreadId) -> u64 {
    thread_ref(tid).saved_sp
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

/// Pre-save the current exception frame pointer into the thread's `saved_sp`
/// and set park_state to PARK_ENQUEUED.
///
/// Must be called BEFORE the thread becomes visible in a HAMT turnstile
/// (via `port_enqueue_with_check`), so that if a sender dequeues the thread
/// and calls `inject_recv_into_frame` before `park_current_for_ipc` runs,
/// the injection writes to the correct frame.
pub fn pre_save_frame(tid: ThreadId) {
    let cpu = smp::cpu_id() as usize;
    let frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);
    let t = unsafe { thread_mut_from_ref(tid) };
    t.saved_sp = frame_sp;
    // Publish saved_sp before becoming visible. The Release on park_state
    // ensures saved_sp is visible to any thread that reads park_state ≥ 1.
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
    let cpu = smp::cpu_id() as usize;

    let cpu_idx = cpu as u32;
    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // saved_sp was already set by pre_save_frame(). Set Blocked + reason.
    let t = unsafe { thread_mut_from_ref(tid as ThreadId) };
    t.state = ThreadState::Blocked;
    t.blocked_on = reason;

    // Try to commit the park: CAS PARK_ENQUEUED → PARK_COMMITTED.
    // If this fails, wake_parked_thread already CAS'd PARK_ENQUEUED → PARK_NONE,
    // meaning a sender woke us before we could switch out. The message is
    // already injected into our saved frame — just undo Blocked and return.
    if thread_ref(tid as ThreadId)
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_COMMITTED, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        t.state = ThreadState::Running;
        return;
    }

    // Read SA state (lock-free).
    let parked_task_id = t.task_id;
    let sa_enabled = task_ref(parked_task_id).sa_enabled;

    // Pick next thread from per-CPU queue (don't re-enqueue current — it's Blocked).
    let next_id = percpu_pick_next(cpu_idx, idle_id);

    // Switch page tables if needed.
    // Disable interrupts across the page-table switch + current_thread update
    // to prevent a timer from seeing TLB_PT_ROOT pointing to the new task
    // while current_thread still identifies the old task (which would cause
    // a subsequent tick() to restore the old task's root, leaving the new
    // task running with the wrong page table).
    let irq_saved = crate::arch::irq::disable();
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

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + page::page_size());

    // Safety: next_id was just dequeued, we own it.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    next_t.state = ThreadState::Running;
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    let next_sp = next_t.saved_sp;
    crate::arch::irq::restore(irq_saved);

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

    PENDING_SWITCH_SP[cpu].store(next_sp, Ordering::Release);
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

    // Try early wake: CAS PARK_ENQUEUED → PARK_NONE.
    // If the thread hasn't committed to parking yet, just prevent the park.
    // park_current_for_ipc's CAS(ENQUEUED→COMMITTED) will fail and it will
    // undo its Blocked state and continue running.
    if tref
        .park_state
        .compare_exchange(PARK_ENQUEUED, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        return;
    }

    // Try normal wake: CAS PARK_COMMITTED → PARK_NONE.
    // Thread is off-CPU — enqueue it on a run queue.
    if tref
        .park_state
        .compare_exchange(PARK_COMMITTED, PARK_NONE, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // park_current_for_ipc used a deferred context switch: it set
        // PENDING_SWITCH_SP on the parking CPU but continued running on the
        // thread's kernel stack until the exception handler consumed the
        // pending switch.  We must wait for that consumption before
        // enqueueing, otherwise the scheduler on another CPU could start
        // executing on the same kernel stack concurrently.
        let parked_cpu = tref.last_cpu.load(Ordering::Relaxed) as usize;
        while PENDING_SWITCH_SP[parked_cpu].load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
        }

        let prio = tref.prio.load(Ordering::Acquire);
        let target = tref.last_cpu.load(Ordering::Relaxed);
        unsafe { thread_mut_from_ref(tid) }.state = ThreadState::Ready;
        percpu_enqueue(target, prio, tid);
    }
    // If park_state is PARK_NONE, thread was already woken or never parked. No-op.
}

/// Get monotonic time in nanoseconds since boot.
pub fn get_monotonic_ns() -> u64 {
    crate::arch::timer::monotonic_ns()
}

/// Insert a thread into the global sleep queue, sorted by deadline (earliest first).
/// Must be called with the thread already marked Blocked/Sleep and deadline set.
/// Caller must NOT hold SLEEP_QUEUE_LOCK.
fn sleep_queue_insert(tid: ThreadId, deadline_ns: u64) {
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
    } else {
        let pt = unsafe { thread_mut_from_ref(prev) };
        pt.sleep_next = tid;
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

    // Wake collected threads (outside the lock).
    for i in 0..count {
        let (tid, prio, target) = to_wake[i];
        let t = unsafe { thread_mut_from_ref(tid) };
        t.state = ThreadState::Ready;
        t.blocked_on = BlockReason::None;
        t.sleep_deadline_ns = 0;
        percpu_enqueue(target, prio, tid);
    }
}

/// Check per-task alarm timers and deliver SIGALRM.
/// Called from tick() before try_switch.
fn check_alarm_timers() {
    let now_ns = get_monotonic_ns();
    let mut fired = [0u32; 64];
    let mut count = 0usize;

    // Lock-free: alarm fields are only written by the owning task (alarm())
    // or by this tick path; no concurrent mutation.
    SCHED_TASK_ART.for_each(|_key, val| {
        let task = unsafe { &mut *(val as *mut Task) };
        if task.active && task.alarm_deadline_ns != 0 && task.alarm_deadline_ns <= now_ns {
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
    });

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

    // Lock-free: timer fields are only written by the owning thread
    // (sys_timer_create) or by this tick path.
    SCHED_THREAD_ART.for_each(|key, val| {
        if found {
            return;
        }
        let t = unsafe { &*(val as *const Thread) };
        if t.state != ThreadState::Dead
            && t.stack_base != 0
            && t.timer_signal != 0
            && t.timer_next_ns != 0
            && now_ns >= t.timer_next_ns
        {
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
    });

    if found {
        send_signal_to_thread(fired_tid, fired_sig);
    }
}

/// Park the current thread for a timed sleep.
/// Sets the deadline and blocks the thread (off-CPU).
pub fn park_current_for_sleep(deadline_ns: u64) {
    let cpu = smp::cpu_id() as usize;
    let cpu_idx = cpu as u32;
    let frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);

    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Set deadline before marking Blocked. Lock-free: we own the running thread.
    let thread = unsafe { thread_mut_from_ref(tid as ThreadId) };
    thread.sleep_deadline_ns = deadline_ns;
    thread.saved_sp = frame_sp;
    thread.state = ThreadState::Blocked;
    thread.blocked_on = BlockReason::Sleep;

    // Insert into sorted sleep queue so check_sleep_timers can find us.
    sleep_queue_insert(tid as ThreadId, deadline_ns);

    // SA notification for the parked thread (lock-free).
    let parked_task_id = thread.task_id;
    let sa_enabled = task_ref(parked_task_id).sa_enabled;

    // Pick next thread from per-CPU queue.
    let next_id = percpu_pick_next(cpu_idx, idle_id);

    // Disable interrupts across page-table switch + current_thread update
    // (same race as park_current_for_ipc — see comment there).
    let irq_saved = crate::arch::irq::disable();
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

    crate::arch::trapframe::update_kernel_stack(thread_ref(next_id).stack_base + page::page_size());

    // Safety: next_id was just dequeued, we own it.
    let next_t = unsafe { thread_mut_from_ref(next_id) };
    next_t.state = ThreadState::Running;
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    let next_sp = next_t.saved_sp;
    crate::arch::irq::restore(irq_saved);

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

    PENDING_SWITCH_SP[cpu].store(next_sp, Ordering::Release);
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
        task.alarm_deadline_ns = now + initial_ns;
        task.alarm_interval_ns = interval_ns;
    }
    prev_remaining
}

/// L4-style direct handoff: sender donates its remaining quantum to receiver.
/// Saves sender's SP, loads receiver as current thread, stores receiver's SP
/// in PENDING_SWITCH_SP. Receiver must already have its frame injected.
pub fn handoff_to(receiver_tid: ThreadId) {
    let cpu = smp::cpu_id() as usize;
    let cpu_id = cpu as u32;
    let frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);

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
        sender.state = ThreadState::Ready;
    }
    percpu_enqueue(cpu_id, sender_prio, sender_tid as ThreadId);

    // Donate remaining quantum to receiver.
    // Safety: receiver was Blocked (parked), not on any queue or CPU.
    let receiver = unsafe { thread_mut_from_ref(receiver_tid) };
    receiver.quantum = remaining_quantum;

    // Disable interrupts across page-table switch + current_thread update
    // (same race as park_current_for_ipc — see comment there).
    let irq_saved = crate::arch::irq::disable();
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

    crate::arch::trapframe::update_kernel_stack(receiver.stack_base + page::page_size());

    // Activate receiver.
    receiver.state = ThreadState::Running;
    pcpu.current_thread.store(receiver_tid, Ordering::Relaxed);
    let recv_sp = receiver.saved_sp;
    crate::arch::irq::restore(irq_saved);

    PENDING_SWITCH_SP[cpu].store(recv_sp, Ordering::Release);
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
