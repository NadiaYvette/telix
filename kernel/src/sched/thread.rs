//! Thread (TCB) — the unit of execution.

/// Thread ID.
pub type ThreadId = u32;

/// Thread states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    #[allow(dead_code)]
    Blocked,
    Dead,
}

/// Why a thread is blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    None,
    PortRecv(u64),
    PortSend(u64),
    PortSetRecv(u32),
    FutexWait,
    ActivationWait,
    ZeroPool,
    Sleep,
    PagerFault,
    PagerWait,
    WaitChild,
    PersonalityWait,
    Kswapd,
    SvcLookup,
    /// Parked in sys_call waiting for sys_reply on a reply-cap slot.
    CallReply(u32),
    /// #164 Memory-scheduler suspend: thread blocked because the
    /// memory scheduler chose its task as the eviction candidate.
    /// Only the explicit `resume_task` call (from the long-term
    /// scheduler when memory pressure drops) wakes it.  No automatic
    /// wakeup via IPC/timer.  When a client sends to a Suspended
    /// server's port the send blocks normally; the queued message is
    /// delivered when the server resumes.
    SuspendedMemPressure,
}

// Thread ID capacity is determined by RadixTable::capacity() — no fixed constant needed.

/// Thread control block.
pub struct Thread {
    pub id: ThreadId,
    pub state: ThreadState,
    pub task_id: u32,
    /// Kernel-held port for this thread. Userspace references this thread by port_id.
    pub port_id: u64,
    /// Base (static) priority assigned at creation.
    pub base_priority: u8,
    /// Effective priority — may be temporarily boosted by priority inheritance.
    pub effective_priority: u8,
    pub quantum: u32,
    pub default_quantum: u32,
    /// Saved kernel stack pointer. When the thread is not running,
    /// this points to a saved exception frame on its kernel stack.
    pub saved_sp: u64,
    /// Physical address of the base of this thread's stack page.
    pub stack_base: usize,
    /// Generation counter bumped each time `stack_base` changes (alloc or
    /// free).  Lets the IPC frame-injection sites detect the deferred-free
    /// race: a sender holding a stale `thread_saved_sp(tid)` would see a
    /// mismatch between the epoch it captured at park and the current epoch.
    /// See [[project-kernel-ud-writer-audit]].
    pub kstack_epoch: u64,
    /// #208 Probe A: shadow of the iretq frame slots captured at park time.
    /// Compared at dispatch to detect corruption that happens between park
    /// and resume.  `iretq_shadow_sp` is the saved_sp value at snapshot time
    /// (0 = no shadow valid).  See [[project-kepoch-probe-first-boot]].
    pub iretq_shadow_rip: u64,
    pub iretq_shadow_cs: u64,
    pub iretq_shadow_rflags: u64,
    pub iretq_shadow_rsp: u64,
    pub iretq_shadow_ss: u64,
    pub iretq_shadow_sp: u64,
    /// #208 full-frame shadow — 22 u64s = entire ExceptionFrame (GPRs +
    /// vec + err + RIP/CS/RFLAGS/RSP/SS).  Captured by
    /// `snapshot_iretq_shadow` at park.  Byte-compared by
    /// `check_iretq_shadow_at_dispatch` to identify ANY byte that
    /// changed between park and dispatch — pinpoints write target.
    pub iretq_shadow_frame: [u64; 22],
    /// Why this thread is blocked (only valid when state == Blocked).
    #[allow(dead_code)]
    pub blocked_on: BlockReason,
    /// Debug: destination port for sys_call (set at CallReply park time).
    pub call_dest_port: u64,
    /// Debug: message tag/opcode for sys_call (set at CallReply park time).
    /// Lets CALL-TIMEOUT diagnostics identify *what* the caller was asking
    /// the destination to do, not just *who* it was talking to.
    pub call_tag: u64,
    /// Exit code set by sys_exit (for thread_join).
    pub exit_code: i32,
    /// Per-thread signal mask — bitmask of blocked signals (bit N = signal N+1).
    pub sig_mask: u64,
    /// Per-thread pending signal set.
    pub sig_pending: u64,
    /// Absolute deadline in nanoseconds-since-boot for Sleep blocking (0 = none).
    pub sleep_deadline_ns: u64,
    /// Next thread in the global sorted sleep queue (u32::MAX = not linked / tail).
    pub sleep_next: u32,
    /// Diagnostic: monotonic_ns timestamp when check_sleep_timers (or any
    /// other waker) marked this thread Ready.  Cleared (swap-to-0) by
    /// try_switch when the thread is first dispatched onto a CPU.  The
    /// difference is the wake-to-dispatch latency, accumulated into
    /// SLEEP_WAKE_LATENCY_* counters surfaced in the WATCHDOG dump.
    pub wake_pending_ts_ns: core::sync::atomic::AtomicU64,
    /// Thread blocked in thread_join() waiting for us to exit (u32::MAX = none).
    pub join_waiter: u32,
    /// Thread-local storage base address (Phase 74).
    pub tls_base: u64,
    /// Per-thread interval timer signal number (Phase 76, 0 = disabled).
    pub timer_signal: u32,
    /// Per-thread timer interval in nanoseconds.
    pub timer_interval_ns: u64,
    /// Next expiry timestamp in nanoseconds-since-boot.
    pub timer_next_ns: u64,
    /// Signal alternate stack base address (Phase 99).
    pub sig_altstack_base: u64,
    /// Signal alternate stack size in bytes (Phase 99).
    pub sig_altstack_size: u64,
    // --- Run queue linkage (doubly-linked list per priority level) ---
    /// Next thread in the same-priority run queue (u32::MAX = tail / not linked).
    pub run_next: core::sync::atomic::AtomicU32,
    /// Previous thread in the same-priority run queue (u32::MAX = head / not linked).
    pub run_prev: core::sync::atomic::AtomicU32,
    // --- Lockless atomics (accessed via THREAD_TABLE radix lookup) ---
    pub wakeup: core::sync::atomic::AtomicBool,
    pub prio: core::sync::atomic::AtomicU8,
    pub yield_asap: core::sync::atomic::AtomicBool,
    pub killed: core::sync::atomic::AtomicBool,
    pub thread_task: core::sync::atomic::AtomicU32,
    pub cosched_group: core::sync::atomic::AtomicU32,
    pub last_cpu: core::sync::atomic::AtomicU32,
    /// Debug: tracks which CPU currently owns this thread (u32::MAX = not
    /// scheduled on any CPU). CAS from MAX→cpu when picking a thread in
    /// try_switch; store MAX when descheduling. If CAS fails, another CPU
    /// already has this thread — indicates double-scheduling bug.
    pub on_cpu: core::sync::atomic::AtomicU32,
    /// Debug: set true when thread is in a run queue, false when dequeued.
    /// Detects double-enqueue (thread added to queue while already queued).
    pub in_queue: core::sync::atomic::AtomicBool,
    /// Debug tag: 1=try_switch, 2=vol_resched, 3=park_ipc, 4=handoff.
    pub on_cpu_set_by: core::sync::atomic::AtomicU8,
    pub affinity_mask: super::cpumask::AtomicCpuMask,
    // --- IPC park state machine (recv_or_park / park_current_for_ipc) ---
    /// Atomic park state for the Dekker-safe park protocol.
    /// 0 = PARK_NONE (not parking), 1 = PARK_ENQUEUED (in HAMT, saved_sp set,
    /// not yet off-CPU), 2 = PARK_COMMITTED (off-CPU, context switch done).
    /// Transitions: recv_or_park sets 0→1, park_current_for_ipc CAS 1→2,
    /// wake_parked_thread CAS 1→0 (early) or CAS 2→0 (normal).
    pub park_state: core::sync::atomic::AtomicU8,
    /// True while this thread's parking CPU hasn't finished its assembly
    /// stack switch. Set before the thread becomes visible to wakers
    /// (park_state CAS or sleep_queue_insert). Cleared by
    /// clear_pending_switch at the next exception handler entry.
    pub stack_switch_pending: core::sync::atomic::AtomicBool,
    // --- Turnstile futex support ---
    /// Pre-allocated turnstile (phys addr as usize, 0 = none/lent).
    pub turnstile: core::sync::atomic::AtomicUsize,
    /// Next thread in turnstile wait queue (0 = end).
    pub ts_next: core::sync::atomic::AtomicU32,
    /// Previous thread in turnstile wait queue (0 = start).
    pub ts_prev: core::sync::atomic::AtomicU32,
    /// Turnstile pointer we're currently blocked on (0 = not blocked).
    pub ts_blocked_on: core::sync::atomic::AtomicUsize,
    /// #120 instrumentation H: monotonic_ns timestamp of the last
    /// transition into ThreadState::Ready.  Used in CALL-TIMEOUT diag
    /// to show whether a stuck-Ready thread has been Ready since long
    /// ago (orphan) or recently (oscillating between states).
    pub last_ready_ns: core::sync::atomic::AtomicU64,
    /// #120 instrumentation I: count of percpu_enqueue calls for this
    /// thread.  Initial wake = 1; rescue re-enqueues bump it.  Lets
    /// CALL-TIMEOUT diag distinguish "thread enqueued once and never
    /// dispatched" from "thread re-enqueued repeatedly by rescue but
    /// dispatch keeps missing it".
    pub enqueue_count: core::sync::atomic::AtomicU64,
    /// #120 dispatch-symmetry: monotonic_ns timestamp at which a dispatching
    /// path stored `ON_CPU_PENDING` on this thread (via
    /// `dequeue_set_pending`).  Cleared (set to 0) by the `try_switch` /
    /// `voluntary_reschedule` `cas_ok` path once the thread becomes Running.
    /// The rescue scan reads this to fire a low-threshold (2s)
    /// "PENDING-STUCK-LOW" diagnostic that's independent of the 16s/30s
    /// rescue-and-CALL-TIMEOUT thresholds.
    pub pending_set_ns: core::sync::atomic::AtomicU64,
    /// Layer 3 paravirt snapshot: picking CPU's accumulated host
    /// steal-time at the moment `dequeue_set_pending` stamped
    /// `pending_set_ns`.  Read by the fast-rescue path to determine
    /// "how much was the picking CPU stolen DURING this pending
    /// wait", which is the correct signal for phantom-pending due
    /// to host descheduling.  Using `PerCpu::steal_ns_at_last_dispatch`
    /// instead is wrong: that field refreshes on every dispatch on
    /// that CPU, so the delta is always small even when the picking
    /// CPU has been heavily stolen since this specific pending stamp.
    /// 0 = bare metal / steal-time not enabled (rescue treats as
    /// "no baseline, fall through to stale-CPU check alone").
    pub pending_set_steal_ns: core::sync::atomic::AtomicU64,
    /// #135 pick-rotation probe: count of pick_eligible / pop_for_group
    /// successful selections for this thread.  Compared to enqueue_count
    /// in PICK-LOCATE dumps to reveal whether a stuck thread is being
    /// scanned-but-skipped vs never-scanned vs picked-but-not-dispatched.
    pub picked_count: core::sync::atomic::AtomicU64,
    // --- Personality forwarding ---
    /// Result value from personality server reply (written by SYS_PERSONALITY_REPLY).
    pub personality_result: core::sync::atomic::AtomicU64,
    /// Saved exception frame pointer for personality-blocked threads.
    /// Unlike saved_sp (which gets overwritten by context switches during
    /// block_current spin-wait), this field preserves the original exception
    /// frame so personality_fork/personality_read_args can read it reliably.
    pub personality_frame_sp: u64,
    /// Current syscall exception frame SP. Set by store_frame_sp() on syscall
    /// entry. Per-thread (not per-CPU) so it survives preemptive migration.
    pub syscall_frame_sp: u64,
    /// Saved IPC-injection frame pointer. Set by pre_save_frame() alongside
    /// saved_sp. Unlike saved_sp (which may be overwritten by timer-driven
    /// try_switch during preemptive syscalls), this field is only written by
    /// pre_save_frame and preserves the correct syscall frame for
    /// inject_recv_into_frame / inject_fault_into_frame.
    pub ipc_frame_sp: u64,
    /// Debug: tracks which code path last wrote saved_sp.
    /// 1 = try_switch, 2 = voluntary_reschedule, 3 = pre_save_frame, 4 = init.
    pub saved_sp_source: u8,
    // --- EEVDF scheduling class ---
    /// Scheduling class: SCHED_NORMAL (0, EEVDF), SCHED_RT (1), SCHED_IDLE (2).
    pub sched_class: u8,
    /// EEVDF weight (nice-to-weight mapping, default 1024). Higher = more CPU share.
    pub eevdf_weight: u16,
    /// Position in the per-CPU d-4 heap (u16::MAX = not in heap).
    pub eevdf_heap_pos: u16,
    /// EEVDF virtual runtime consumed so far (fixed-point, VTIME_UNIT per real tick).
    pub eevdf_vruntime: u64,
    /// EEVDF virtual deadline (key in the d-4 heap).
    pub eevdf_deadline: u64,
    /// EEVDF virtual time slice length = quantum * VTIME_UNIT / weight.
    pub eevdf_slice_vt: u64,
    /// EEVDF lag: positive = thread is owed CPU (eligible), negative = ahead of fair share.
    pub eevdf_lag: i64,
    /// Latency weight (from latency_nice, default 1024). Scales the virtual time slice:
    /// slice_vt = base_slice * 1024 / latency_weight. Lower latency_weight → shorter
    /// slices → tighter deadlines → more responsive scheduling.
    pub eevdf_latency_weight: u16,
    // --- Call/reply IPC (seL4-style) ---
    /// Handle of the reply-cap this thread currently holds, or
    /// `CAP_HANDLE_NONE` (u64::MAX) if none. Set by sys_recv_with_cap when a
    /// call-style request is received; consumed by sys_reply. Walked by the
    /// thread-teardown path to deliver CALL_REPLY_SERVER_DIED if the server
    /// dies holding a cap.
    pub held_reply_cap: core::sync::atomic::AtomicU64,
    /// Monotonic nanosecond timestamp when this thread parked for CallReply.
    /// 0 means not currently in a timed CallReply park. Used by the periodic
    /// call_reply_timeout_sweep to force-wake threads stuck longer than
    /// CALL_REPLY_TIMEOUT_NS.
    pub call_blocked_ns: core::sync::atomic::AtomicU64,
    /// Pending grant leases staged by `sys_grant_pages_lease`, atomically
    /// transferred into the freshly-allocated reply-cap by the next
    /// `sys_call`. Slots with `dst_aspace == 0` are empty. See
    /// `ipc::call_reply::LeaseSlot`.
    pub pending_leases: [crate::ipc::call_reply::LeaseSlot;
        crate::ipc::call_reply::MAX_LEASES_PER_CAP],
    /// High-water count of staged leases (slots may be cleared below this;
    /// iterate by `dst_aspace != 0`).
    pub pending_lease_count: core::sync::atomic::AtomicU32,
    /// #135 transition ring: last 4 state/on_cpu transitions.  Each entry
    /// is packed as:
    ///   bits  0..7   action id (1=SET_PENDING, 2=CAS_OK, 3=CAS_FAIL,
    ///                 4=DESCHED, 5=WAKE_SET_READY)
    ///   bits  8..15  cpu (0..255, 0xFF = unknown)
    ///   bits 16..23  state (Ready=0, Running=1, Blocked=2, Dead=3)
    ///   bits 24..31  on_cpu encoded (0..0xFD = cpu, 0xFE = PENDING, 0xFF = MAX)
    ///   bits 32..63  low 32 bits of monotonic_ns
    /// Written from `sched::record_thread_transition()`.  Dumped from the
    /// RESCUE-STUCK-PENDING block for the stuck tid.
    pub trans_ring: [core::sync::atomic::AtomicU64; 4],
    /// Next slot index (modulo 4) to write into trans_ring.
    pub trans_pos: core::sync::atomic::AtomicU8,
}

impl Thread {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            state: ThreadState::Dead,
            task_id: 0,
            port_id: 0,
            base_priority: 128,
            effective_priority: 128,
            // 1 tick (~10 ms at TICK_INTERVAL_NS=10 ms): every
            // contended tick expires the running thread's quantum.
            // The earlier r28 attempt at 1 livelocked because the
            // tick handler unconditionally decremented quantum even
            // when no one else was ready — so the per-tick CS rate
            // saturated CPU.  Coupled with lazy preemption (skip
            // quantum decrement when has_ready() == false), 1 is
            // safe and gives the tightest wake-latency response for
            // every contended scheduling decision.
            quantum: 1,
            default_quantum: 1,
            saved_sp: 0,
            stack_base: 0,
            kstack_epoch: 0,
            iretq_shadow_rip: 0,
            iretq_shadow_cs: 0,
            iretq_shadow_rflags: 0,
            iretq_shadow_rsp: 0,
            iretq_shadow_ss: 0,
            iretq_shadow_sp: 0,
            iretq_shadow_frame: [0u64; 22],
            blocked_on: BlockReason::None,
            call_dest_port: 0,
            call_tag: 0,
            exit_code: 0,
            sig_mask: 0,
            sig_pending: 0,
            sleep_deadline_ns: 0,
            sleep_next: u32::MAX,
            wake_pending_ts_ns: core::sync::atomic::AtomicU64::new(0),
            join_waiter: u32::MAX,
            tls_base: 0,
            timer_signal: 0,
            timer_interval_ns: 0,
            timer_next_ns: 0,
            sig_altstack_base: 0,
            sig_altstack_size: 0,
            run_next: core::sync::atomic::AtomicU32::new(0),
            run_prev: core::sync::atomic::AtomicU32::new(0),
            park_state: core::sync::atomic::AtomicU8::new(0),
            stack_switch_pending: core::sync::atomic::AtomicBool::new(false),
            wakeup: core::sync::atomic::AtomicBool::new(false),
            prio: core::sync::atomic::AtomicU8::new(255),
            yield_asap: core::sync::atomic::AtomicBool::new(false),
            killed: core::sync::atomic::AtomicBool::new(false),
            thread_task: core::sync::atomic::AtomicU32::new(0),
            cosched_group: core::sync::atomic::AtomicU32::new(0),
            last_cpu: core::sync::atomic::AtomicU32::new(0),
            on_cpu: core::sync::atomic::AtomicU32::new(u32::MAX),
            in_queue: core::sync::atomic::AtomicBool::new(false),
            on_cpu_set_by: core::sync::atomic::AtomicU8::new(0),
            affinity_mask: super::cpumask::AtomicCpuMask::new_all(),
            turnstile: core::sync::atomic::AtomicUsize::new(0),
            ts_next: core::sync::atomic::AtomicU32::new(0),
            ts_prev: core::sync::atomic::AtomicU32::new(0),
            ts_blocked_on: core::sync::atomic::AtomicUsize::new(0),
            last_ready_ns: core::sync::atomic::AtomicU64::new(0),
            enqueue_count: core::sync::atomic::AtomicU64::new(0),
            pending_set_ns: core::sync::atomic::AtomicU64::new(0),
            pending_set_steal_ns: core::sync::atomic::AtomicU64::new(0),
            picked_count: core::sync::atomic::AtomicU64::new(0),
            personality_result: core::sync::atomic::AtomicU64::new(0),
            personality_frame_sp: 0,
            syscall_frame_sp: 0,
            ipc_frame_sp: 0,
            saved_sp_source: 4,
            sched_class: SCHED_NORMAL,
            eevdf_weight: 1024,
            eevdf_heap_pos: super::heap::HEAP_POS_NONE,
            eevdf_vruntime: 0,
            eevdf_deadline: 0,
            eevdf_slice_vt: 0,
            eevdf_lag: 0,
            eevdf_latency_weight: 1024,
            call_blocked_ns: core::sync::atomic::AtomicU64::new(0),
            held_reply_cap: core::sync::atomic::AtomicU64::new(u64::MAX),
            pending_leases: [const { crate::ipc::call_reply::LeaseSlot::empty() };
                crate::ipc::call_reply::MAX_LEASES_PER_CAP],
            pending_lease_count: core::sync::atomic::AtomicU32::new(0),
            trans_ring: [const { core::sync::atomic::AtomicU64::new(0) }; 4],
            trans_pos: core::sync::atomic::AtomicU8::new(0),
        }
    }
}

/// EEVDF fair scheduling (default for all normal threads).
pub const SCHED_NORMAL: u8 = 0;
/// Real-time fixed-priority FIFO/RR (for explicitly marked RT threads).
pub const SCHED_RT: u8 = 1;
/// Idle class (only runs when no other thread is runnable).
pub const SCHED_IDLE: u8 = 2;

/// Nice-to-weight table (Linux CFS/EEVDF compatible).
/// Index = nice + 20, so nice -20 → index 0, nice 0 → index 20, nice +19 → index 39.
/// Values for nice < -10 are clamped to u16::MAX (65535) since the true Linux weights
/// (e.g. nice -20 = 88761) exceed u16 range.
pub const NICE_TO_WEIGHT: [u16; 40] = [
    65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, // nice -20..-11 (clamped)
    9548, 8192, 7024, 6025, 5168, 4434, 3803, 3264, 2800, 2399,        // nice -10..-1
    1024,  820,  655,  526,  423,  335,  272,  215,  172,  137,         // nice  0..+9
     110,   87,   70,   56,   45,   36,   29,   23,   18,   15,        // nice +10..+19
];

/// Convert a nice value (-20..+19) to an EEVDF weight.
pub fn nice_to_weight(nice: i32) -> u16 {
    NICE_TO_WEIGHT[(nice + 20).clamp(0, 39) as usize]
}
