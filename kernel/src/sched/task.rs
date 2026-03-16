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
    // In Phase 1, there's no per-task page table — all threads run in kernel space.
    // The capability space will be added when we integrate with the cap system.
}

impl Task {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            active: false,
        }
    }
}
