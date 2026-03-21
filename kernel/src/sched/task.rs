//! Task — an address space + capability space container.
//!
//! A task is the unit of resource ownership. Threads run within tasks.
//! In Phase 1, all tasks share the kernel's identity-mapped address space.

/// Task ID.
pub type TaskId = u32;

/// Maximum number of tasks.
pub const MAX_TASKS: usize = 16;

/// Maximum number of signals (1..=MAX_SIGNALS). Bit N in masks = signal N+1.
pub const MAX_SIGNALS: usize = 32;

// Standard POSIX signal numbers (0-indexed bit positions = signal_number - 1).
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;

/// Signal handler disposition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SigHandler {
    /// Default action (terminate, ignore, etc.).
    Default,
    /// Ignore the signal.
    Ignore,
    /// User handler at the given address.
    User(u64),
}

/// Per-signal action (sigaction-like).
#[derive(Clone, Copy)]
pub struct SignalAction {
    pub handler: SigHandler,
    /// Signals to additionally mask while handler executes.
    pub sa_mask: u64,
    /// SA_RESTART flag (auto-restart interrupted syscalls).
    pub restart: bool,
}

impl SignalAction {
    pub const fn default() -> Self {
        Self { handler: SigHandler::Default, sa_mask: 0, restart: false }
    }
}

/// Bitmask for a signal number (1-based).
#[inline]
pub const fn sig_bit(sig: u32) -> u64 {
    if sig >= 1 && sig <= MAX_SIGNALS as u32 {
        1u64 << (sig - 1)
    } else {
        0
    }
}

/// Signals that cannot be caught or masked.
pub const UNCATCHABLE: u64 = (1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1));

/// Default action for a signal: true = terminate, false = ignore.
pub fn sig_default_is_term(sig: u32) -> bool {
    match sig {
        SIGCHLD | SIGCONT => false, // default ignore
        _ => true, // default terminate
    }
}

/// Task structure.
pub struct Task {
    pub id: TaskId,
    pub active: bool,
    /// Address space ID (0 = kernel, uses identity mapping).
    pub aspace_id: u32,
    /// Physical address of the page table root for this task.
    /// 0 = kernel task (uses boot page table, no switching needed).
    pub page_table_root: usize,
    /// Exit code set by sys_exit.
    pub exit_code: i32,
    /// Task that spawned this task (for waitpid).
    pub parent_task: TaskId,
    /// True once exit cleanup is done.
    pub exited: bool,
    /// Number of live threads in this task.
    pub thread_count: u32,
    // --- Resource quotas ---
    pub max_ports: u32,
    pub max_threads: u32,
    pub max_pages: u32,
    pub cur_ports: u32,
    pub cur_pages: u32,
    /// Scheduler activations enabled for this task.
    pub sa_enabled: bool,
    /// Per-signal action table (indexed by signal_number - 1).
    pub sig_actions: [SignalAction; MAX_SIGNALS],
    /// Process group ID. Defaults to task_id on creation.
    pub pgid: TaskId,
    /// Session ID. Defaults to parent's sid, or task_id for setsid().
    pub sid: TaskId,
    /// Controlling terminal port (0 = no ctty).
    pub ctty_port: u32,
    /// Foreground process group (only meaningful on the session leader).
    pub fg_pgid: TaskId,
    /// Alarm deadline in nanoseconds-since-boot (0 = no alarm).
    pub alarm_deadline_ns: u64,
    /// Alarm interval for repeating (0 = one-shot).
    pub alarm_interval_ns: u64,
    // --- Credentials (Phase 48) ---
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID (may differ from uid for setuid binaries).
    pub euid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Supplementary group list.
    pub groups: [u32; MAX_GROUPS],
    /// Number of supplementary groups.
    pub ngroups: u32,
}

/// Maximum supplementary groups per task.
pub const MAX_GROUPS: usize = 32;

impl Task {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            active: false,
            aspace_id: 0,
            page_table_root: 0,
            exit_code: 0,
            parent_task: 0,
            exited: false,
            thread_count: 0,
            max_ports: 16,
            max_threads: 8,
            max_pages: 256,
            cur_ports: 0,
            cur_pages: 0,
            sa_enabled: false,
            sig_actions: [const { SignalAction::default() }; MAX_SIGNALS],
            pgid: 0,
            sid: 0,
            ctty_port: 0,
            fg_pgid: 0,
            alarm_deadline_ns: 0,
            alarm_interval_ns: 0,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            groups: [0; MAX_GROUPS],
            ngroups: 0,
        }
    }
}
