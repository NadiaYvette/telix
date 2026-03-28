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
}

// Thread ID capacity is determined by RadixTable::capacity() — no fixed constant needed.

/// Size of the exception frame saved by vectors.S.
/// AArch64: 288 bytes = 36 x u64 (x0-x30, sp_el0, elr, spsr, esr).
/// RISC-V:  272 bytes = 34 x u64 (x1-x31, sepc, sstatus, scause).
#[cfg(target_arch = "aarch64")]
pub const EXCEPTION_FRAME_SIZE: usize = 288;
#[cfg(target_arch = "riscv64")]
pub const EXCEPTION_FRAME_SIZE: usize = 272;
/// x86-64: 176 bytes = 22 x u64 (r15-rax, vector, error_code, rip, cs, rflags, rsp, ss).
#[cfg(target_arch = "x86_64")]
pub const EXCEPTION_FRAME_SIZE: usize = 176;

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
    /// Why this thread is blocked (only valid when state == Blocked).
    #[allow(dead_code)]
    pub blocked_on: BlockReason,
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
    pub affinity_mask: super::cpumask::AtomicCpuMask,
    // --- Turnstile futex support ---
    /// Pre-allocated turnstile (phys addr as usize, 0 = none/lent).
    pub turnstile: core::sync::atomic::AtomicUsize,
    /// Next thread in turnstile wait queue (0 = end).
    pub ts_next: core::sync::atomic::AtomicU32,
    /// Previous thread in turnstile wait queue (0 = start).
    pub ts_prev: core::sync::atomic::AtomicU32,
    /// Turnstile pointer we're currently blocked on (0 = not blocked).
    pub ts_blocked_on: core::sync::atomic::AtomicUsize,
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
            quantum: 10,
            default_quantum: 10,
            saved_sp: 0,
            stack_base: 0,
            blocked_on: BlockReason::None,
            exit_code: 0,
            sig_mask: 0,
            sig_pending: 0,
            sleep_deadline_ns: 0,
            sleep_next: u32::MAX,
            join_waiter: u32::MAX,
            tls_base: 0,
            timer_signal: 0,
            timer_interval_ns: 0,
            timer_next_ns: 0,
            sig_altstack_base: 0,
            sig_altstack_size: 0,
            run_next: core::sync::atomic::AtomicU32::new(0),
            run_prev: core::sync::atomic::AtomicU32::new(0),
            wakeup: core::sync::atomic::AtomicBool::new(false),
            prio: core::sync::atomic::AtomicU8::new(255),
            yield_asap: core::sync::atomic::AtomicBool::new(false),
            killed: core::sync::atomic::AtomicBool::new(false),
            thread_task: core::sync::atomic::AtomicU32::new(0),
            cosched_group: core::sync::atomic::AtomicU32::new(0),
            last_cpu: core::sync::atomic::AtomicU32::new(0),
            affinity_mask: super::cpumask::AtomicCpuMask::new_all(),
            turnstile: core::sync::atomic::AtomicUsize::new(0),
            ts_next: core::sync::atomic::AtomicU32::new(0),
            ts_prev: core::sync::atomic::AtomicU32::new(0),
            ts_blocked_on: core::sync::atomic::AtomicUsize::new(0),
        }
    }
}
