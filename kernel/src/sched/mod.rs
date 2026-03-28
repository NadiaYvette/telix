pub mod cpumask;
pub mod hotplug;
pub mod radix;
pub mod scheduler;
pub mod smp;
pub mod stats;
pub mod task;
pub mod thread;
pub mod topology;

#[allow(unused_imports)]
pub use hotplug::{
    cpu_load, cpu_offline, cpu_online, online_affinity_mask, online_mask, pick_packed_cpu,
};
#[allow(unused_imports)]
pub use scheduler::{
    alarm, arch_irq_restore, arch_irq_save_enable, block_current, boost_priority,
    clear_wakeup_flag, cosched_set, current_aspace_id, current_task_id, current_thread_id,
    dequeue_signal, get_affinity, get_monotonic_ns, get_signal_action, get_signal_mask,
    get_signal_pending, getpgid, getsid, init, is_killed, kill_task, park_current_for_sleep,
    reset_priority, sa_getid, sa_register, sa_wait, send_signal_to_pgroup, send_signal_to_task,
    send_signal_to_thread, set_affinity, set_ctty, set_signal_action, set_signal_mask, setpgid,
    setsid, spawn, spawn_user, spawn_user_from_elf, spawn_user_with_data, tcgetpgrp, tcsetpgrp,
    thread_create, thread_effective_priority, thread_join_block, thread_join_poll, thread_task_id,
    tick, wake_thread,
};

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
#[allow(dead_code)]
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
    if p.is_null() {
        return 0;
    }
    unsafe { &*p }.port_id
}

/// Resolve a thread's kernel-held port ID to its internal thread_id.
pub fn thread_id_from_port(port_id: u64) -> Option<thread::ThreadId> {
    crate::ipc::port::port_kernel_data(port_id).map(|d| d as thread::ThreadId)
}

/// Get a thread's kernel-held port ID from its internal thread_id.
pub fn thread_port_id(tid: thread::ThreadId) -> u64 {
    let p = scheduler::THREAD_TABLE.get(tid) as *const thread::Thread;
    if p.is_null() {
        return 0;
    }
    unsafe { &*p }.port_id
}
