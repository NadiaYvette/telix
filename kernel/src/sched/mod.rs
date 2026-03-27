pub mod thread;
pub mod task;
pub mod scheduler;
pub mod radix;
pub mod cpumask;
pub mod smp;
pub mod stats;
pub mod topology;
pub mod hotplug;

#[allow(unused_imports)]
pub use scheduler::{init, spawn, spawn_user, spawn_user_from_elf, spawn_user_with_data, tick, current_thread_id, current_aspace_id, clear_wakeup_flag, block_current, wake_thread, boost_priority, reset_priority, thread_effective_priority, arch_irq_save_enable, arch_irq_restore, thread_create, thread_join_poll, thread_join_block, is_killed, kill_task, current_task_id, thread_task_id, sa_register, sa_wait, sa_getid, cosched_set, set_affinity, get_affinity, send_signal_to_task, send_signal_to_thread, dequeue_signal, get_signal_action, set_signal_action, set_signal_mask, get_signal_mask, get_signal_pending, setpgid, getpgid, setsid, getsid, tcsetpgrp, tcgetpgrp, send_signal_to_pgroup, set_ctty, get_monotonic_ns, park_current_for_sleep, alarm};
#[allow(unused_imports)]
pub use hotplug::{cpu_offline, cpu_online, cpu_load, online_mask, pick_packed_cpu, online_affinity_mask};

/// Resolve a task's kernel-held port ID to its internal task_id.
pub fn task_id_from_port(port_id: u64) -> Option<task::TaskId> {
    crate::ipc::port::port_kernel_data(port_id).map(|d| d as task::TaskId)
}

/// Resolve any kernel-held port (task or thread) to a task_id.
/// Validates by checking that the resolved entity's stored port_id matches,
/// to distinguish task ports from thread ports (both use kernel_user_data).
pub fn task_id_from_any_port(port_id: u64) -> Option<task::TaskId> {
    let data = crate::ipc::port::port_kernel_data(port_id)? as u32;
    // Try as task port: check if the task's stored port_id matches.
    if let Some(task) = scheduler::task_ref_opt(data) {
        if task.active && task.port_id == port_id {
            return Some(data as task::TaskId);
        }
    }
    // Try as thread port: check if the thread's stored port_id matches.
    if let Some(thread) = scheduler::thread_ref_opt(data) {
        if thread.port_id == port_id {
            return Some(scheduler::thread_task_id(data));
        }
    }
    None
}

/// Resolve a thread port to its internal thread_id.
/// Validates by checking that the thread's stored port_id matches.
pub fn validated_thread_from_port(port_id: u64) -> Option<thread::ThreadId> {
    let data = crate::ipc::port::port_kernel_data(port_id)? as u32;
    if let Some(thread) = scheduler::thread_ref_opt(data) {
        if thread.port_id == port_id {
            return Some(data);
        }
    }
    None
}

/// Get a task's kernel-held port ID from its internal task_id.
pub fn task_port_id(task_id: task::TaskId) -> u64 {
    let p = scheduler::TASK_TABLE.get(task_id) as *const task::Task;
    if p.is_null() { return 0; }
    unsafe { &*p }.port_id
}

/// Resolve a thread's kernel-held port ID to its internal thread_id.
pub fn thread_id_from_port(port_id: u64) -> Option<thread::ThreadId> {
    crate::ipc::port::port_kernel_data(port_id).map(|d| d as thread::ThreadId)
}

/// Get a thread's kernel-held port ID from its internal thread_id.
pub fn thread_port_id(tid: thread::ThreadId) -> u64 {
    let p = scheduler::THREAD_TABLE.get(tid) as *const thread::Thread;
    if p.is_null() { return 0; }
    unsafe { &*p }.port_id
}
