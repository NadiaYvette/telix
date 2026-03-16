//! Thread (TCB) — the unit of execution.

/// Thread ID.
pub type ThreadId = u32;

/// Thread states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked,
    Dead,
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
    pub priority: u8,
    pub quantum: u32,
    pub default_quantum: u32,
    /// Saved kernel stack pointer. When the thread is not running,
    /// this points to a saved exception frame on its kernel stack.
    pub saved_sp: u64,
    /// Physical address of the base of this thread's stack page.
    pub stack_base: usize,
}

impl Thread {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            state: ThreadState::Dead,
            task_id: 0,
            priority: 128,
            quantum: 10,
            default_quantum: 10,
            saved_sp: 0,
            stack_base: 0,
        }
    }
}
