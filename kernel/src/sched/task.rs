//! Task — an address space + capability space container.
//!
//! A task is the unit of resource ownership. Threads run within tasks.
//! In Phase 1, all tasks share the kernel's identity-mapped address space.

/// Task ID.
pub type TaskId = u32;

// Task ID capacity is determined by RadixTable::capacity() — no fixed constant needed.

/// Maximum number of signals (1..=MAX_SIGNALS). Bit N in masks = signal N+1.
pub const MAX_SIGNALS: usize = 32;

// Standard POSIX signal numbers (0-indexed bit positions = signal_number - 1).
#[allow(dead_code)]
pub const SIGHUP: u32 = 1;
#[allow(dead_code)]
pub const SIGINT: u32 = 2;
#[allow(dead_code)]
pub const SIGQUIT: u32 = 3;
#[allow(dead_code)]
pub const SIGILL: u32 = 4;
#[allow(dead_code)]
pub const SIGTRAP: u32 = 5;
#[allow(dead_code)]
pub const SIGABRT: u32 = 6;
#[allow(dead_code)]
pub const SIGBUS: u32 = 7;
#[allow(dead_code)]
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
#[allow(dead_code)]
pub const SIGUSR1: u32 = 10;
#[allow(dead_code)]
pub const SIGSEGV: u32 = 11;
#[allow(dead_code)]
pub const SIGUSR2: u32 = 12;
#[allow(dead_code)]
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
#[allow(dead_code)]
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
#[allow(dead_code)]
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
    #[allow(dead_code)]
    pub restart: bool,
}

impl SignalAction {
    pub const fn default() -> Self {
        Self {
            handler: SigHandler::Default,
            sa_mask: 0,
            restart: false,
        }
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
        _ => true,                  // default terminate
    }
}

// ---------------------------------------------------------------------------
// Personality and syscall ABI types
// ---------------------------------------------------------------------------

/// OS personality — determines what syscall numbers mean.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PersonalityId {
    /// Direct kernel dispatch (current behavior — native Telix syscalls).
    TelixNative = 0,
    /// Minimal POSIX.1 without OS-specific extensions.
    Posix       = 1,
    /// Linux personality (syscall numbers, /proc, signals, etc.).
    Linux       = 2,
    /// Darwin/macOS (Mach traps + BSD syscalls).
    Darwin      = 3,
    /// Windows NT (NtXxx syscall interface).
    WindowsNt   = 4,
    /// FreeBSD.
    FreeBsd     = 5,
    /// Plan 9 from Bell Labs.
    Plan9       = 6,
    /// Haiku (BeOS-compatible).
    Haiku       = 7,
}

/// Syscall ABI — determines which registers hold nr, args, and return value.
/// Each variant is a (personality, architecture, bitness) tuple.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SyscallAbi {
    // --- Native Telix (current behavior, all arches) ---
    TelixNative    = 0,

    // --- Linux ABIs (one per arch × bitness) ---
    LinuxAarch64   = 1,   // nr=x8, args=x0-x5, ret=x0
    LinuxAarch32   = 2,   // nr=r7, args=r0-r5, ret=r0
    LinuxX86_64    = 3,   // nr=rax, args=rdi/rsi/rdx/r10/r8/r9, ret=rax
    LinuxI386      = 4,   // nr=eax, args=ebx/ecx/edx/esi/edi/ebp, ret=eax
    LinuxRv64      = 5,   // nr=a7, args=a0-a5, ret=a0
    LinuxMipsN64   = 6,   // nr=v0 (5000+), args=a0-a5, ret=v0
    LinuxMipsO32   = 7,   // nr=v0 (4000+), args=a0-a3 (+stack), ret=v0
    LinuxMipsN32   = 8,   // nr=v0 (6000+), args=a0-a5, ret=v0
    LinuxLa64      = 9,   // nr=a7, args=a0-a5, ret=a0

    // --- Windows NT ABIs ---
    NtX86_64       = 16,  // nr=rax, args=rcx/rdx/r8/r9 (+stack), ret=rax
    NtAarch64      = 17,  // nr=x8(?), args=x0-x7, ret=x0
    NtI386         = 18,  // nr=eax, args on stack (stdcall), ret=eax

    // --- Darwin ABIs ---
    DarwinX86_64   = 32,  // nr=rax (class in high bits), args=rdi/rsi/rdx/r10/r8/r9
    DarwinAarch64  = 33,  // nr=x16, args=x0-x5, ret=x0 (carry=error)

    // --- Other personalities ---
    Plan9Amd64     = 48,
    HaikuX86_64    = 64,
}

/// Maximum personality ID (for fast-path table sizing).
pub const PERSONALITY_ID_MAX: u8 = 7;

/// Task structure.
pub struct Task {
    pub id: TaskId,
    pub active: bool,
    /// Kernel-held port for this task. Userspace references this task by port_id.
    pub port_id: u64,
    /// Address space ID (port_id, 0 = kernel, uses identity mapping).
    pub aspace_id: u64,
    /// Physical address of the page table root for this task.
    /// 0 = kernel task (uses boot page table, no switching needed).
    pub page_table_root: usize,
    /// Exit code set by sys_exit.
    pub exit_code: i32,
    /// Task that spawned this task (for waitpid).
    pub parent_task: TaskId,
    /// True once exit cleanup is done.
    pub exited: bool,
    /// True once a parent has reaped this task via wait4.
    pub reaped: bool,
    /// POSIX-encoded wait status (set on exit).
    pub wait_status: i32,
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
    pub ctty_port: u64,
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
    /// Supplementary group list (inline storage for up to GROUPS_INLINE entries).
    pub groups_inline: [u32; GROUPS_INLINE],
    /// Overflow page for > GROUPS_INLINE groups (physical address, 0 = none).
    pub groups_overflow: usize,
    /// Number of supplementary groups.
    pub ngroups: u32,
    // --- Resource limits (Phase 50) ---
    pub rlimits: [Rlimit; RLIMIT_COUNT],
    // --- Personality (foreign OS emulation) ---
    /// OS personality for this task (determines syscall semantics).
    pub personality: PersonalityId,
    /// Syscall ABI (determines register extraction for nr/args/return).
    pub syscall_abi: SyscallAbi,
    /// Port of the personality server handling this task (0 = none/native).
    pub personality_port: u64,
    // --- Embedded capability data (lockless access via TASK_TABLE) ---
    /// Per-task lock protecting CNode/CapSpace mutations.
    pub cap_lock: crate::sync::SpinLock<()>,
    /// Per-task sparse capability set for lockless cap checks.
    pub capset: crate::cap::capset::CapSet,
    /// Per-task capability space (CNode + CDT tracking).
    pub capspace: crate::cap::space::CapSpace,
    // --- Scheduler activation atomics ---
    pub sa_pending: core::sync::atomic::AtomicBool,
    pub sa_event: core::sync::atomic::AtomicU64,
    pub sa_waiter: core::sync::atomic::AtomicU32,
}

/// Supplementary groups stored inline in the Task struct (common case).
pub const GROUPS_INLINE: usize = 32;

/// Maximum supplementary groups per task (overflow page capacity).
/// Uses MAX_PAGE_SIZE for const context; runtime capacity may be smaller.
pub const MAX_GROUPS: usize = crate::mm::page::MAX_PAGE_SIZE / core::mem::size_of::<u32>();

// --- Resource limits (Phase 50) ---

/// POSIX resource limit types.
#[allow(dead_code)]
pub const RLIMIT_STACK: u32 = 0;
#[allow(dead_code)]
pub const RLIMIT_NOFILE: u32 = 1;
pub const RLIMIT_AS: u32 = 2;
pub const RLIMIT_NPROC: u32 = 3;
pub const RLIMIT_COUNT: usize = 4;

/// Unlimited resource value.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// POSIX resource limit (soft + hard).
#[derive(Clone, Copy)]
pub struct Rlimit {
    /// Soft limit (current enforced limit, can be raised up to hard).
    pub cur: u64,
    /// Hard limit (ceiling for soft limit; only root can raise).
    pub max: u64,
}

impl Rlimit {
    pub const fn new(cur: u64, max: u64) -> Self {
        Self { cur, max }
    }
}

/// Default resource limits for new tasks.
pub const DEFAULT_RLIMITS: [Rlimit; RLIMIT_COUNT] = [
    Rlimit::new(65536, 1048576), // RLIMIT_STACK: 64K soft, 1M hard
    Rlimit::new(64, 1024),       // RLIMIT_NOFILE: 64 soft, 1024 hard
    Rlimit::new(RLIM_INFINITY, RLIM_INFINITY), // RLIMIT_AS: unlimited
    Rlimit::new(RLIM_INFINITY, RLIM_INFINITY), // RLIMIT_NPROC: unlimited by default
];

impl Task {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            active: false,
            port_id: 0,
            aspace_id: 0,
            page_table_root: 0,
            exit_code: 0,
            parent_task: 0,
            exited: false,
            reaped: true,
            wait_status: 0,
            thread_count: 0,
            max_ports: 128,
            max_threads: 32,
            max_pages: 512,
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
            groups_inline: [0; GROUPS_INLINE],
            groups_overflow: 0,
            ngroups: 0,
            rlimits: DEFAULT_RLIMITS,
            personality: PersonalityId::TelixNative,
            syscall_abi: SyscallAbi::TelixNative,
            personality_port: 0,
            cap_lock: crate::sync::SpinLock::new(()),
            capset: crate::cap::capset::CapSet::new(),
            capspace: crate::cap::space::CapSpace::new(0),
            sa_pending: core::sync::atomic::AtomicBool::new(false),
            sa_event: core::sync::atomic::AtomicU64::new(0),
            sa_waiter: core::sync::atomic::AtomicU32::new(u32::MAX),
        }
    }

    /// Get the supplementary groups slice (inline or overflow).
    #[allow(dead_code)]
    pub fn groups(&self) -> &[u32] {
        let n = self.ngroups as usize;
        if n <= GROUPS_INLINE {
            &self.groups_inline[..n]
        } else {
            unsafe { core::slice::from_raw_parts(self.groups_overflow as *const u32, n) }
        }
    }

    /// Free the overflow page if allocated. Called on last-thread exit.
    pub fn free_groups_overflow(&mut self) {
        if self.groups_overflow != 0 {
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(self.groups_overflow));
            self.groups_overflow = 0;
        }
    }
}
