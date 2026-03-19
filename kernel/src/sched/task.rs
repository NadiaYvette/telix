//! Task — an address space + capability space container.
//!
//! A task is the unit of resource ownership. Threads run within tasks.
//! In Phase 1, all tasks share the kernel's identity-mapped address space.

/// Task ID.
pub type TaskId = u32;

/// Maximum number of tasks.
pub const MAX_TASKS: usize = 16;

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
}

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
        }
    }
}
