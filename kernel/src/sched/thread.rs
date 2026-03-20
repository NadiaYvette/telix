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
    PortRecv(u32),
    PortSend(u32),
    PortSetRecv(u32),
    FutexWait,
    ActivationWait,
    ZeroPool,
    Sleep,
    PagerFault,
    PagerWait,
}

/// Maximum number of threads.
pub const MAX_THREADS: usize = 64;

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
}

impl Thread {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            state: ThreadState::Dead,
            task_id: 0,
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
        }
    }
}
