//! Personality server registry and foreign syscall routing.
//!
//! When a task has a non-native personality, its syscalls are forwarded to a
//! userspace personality server via IPC. Simple syscalls can be translated
//! in-kernel via a registered fast-path table.

use crate::sched::task::PersonalityId;
use core::sync::atomic::{AtomicU64, Ordering};

/// Per-tid FWD probe counter.  Module-scope so exit_current_thread can
/// reset the counter for the dying tid — tid slots are reused, and
/// without this the next user gets a quenched counter and zero trace.
static FWD_LOG_COUNT: [core::sync::atomic::AtomicU32; 256] = {
    const Z: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);
    [Z; 256]
};

/// Called from scheduler::exit_current_thread when a thread dies.
pub fn reset_fwd_log_count(tid: u32) {
    if (tid as usize) < FWD_LOG_COUNT.len() {
        FWD_LOG_COUNT[tid as usize]
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Per-personality server registration.
/// Each personality server registers its port here via SYS_PERSONALITY_REGISTER.
struct PersonalityServer {
    /// Port ID of the personality server (0 = not registered).
    port: AtomicU64,
}

impl PersonalityServer {
    const fn new() -> Self {
        Self {
            port: AtomicU64::new(0),
        }
    }
}

/// Registry indexed by PersonalityId (0 is TelixNative, unused).
static SERVERS: [PersonalityServer; 8] = [const { PersonalityServer::new() }; 8];

/// Register a personality server. Returns 0 on success, u64::MAX on error.
/// Only root (euid 0) can register personality servers.
pub fn register_server(personality: u8, port: u64) -> u64 {
    if personality as usize >= SERVERS.len() || personality == 0 {
        return u64::MAX; // invalid or TelixNative
    }
    // Check credentials: only euid 0 can register.
    let task_id = {
        let tid = crate::sched::smp::current()
            .current_thread
            .load(Ordering::Relaxed);
        crate::sched::scheduler::thread_ref(tid).task_id
    };
    let euid = crate::sched::scheduler::task_ref(task_id).euid;
    if euid != 0 {
        return u64::MAX;
    }
    SERVERS[personality as usize].port.store(port, Ordering::Release);
    0
}

/// Look up the registered personality server port for a given personality ID.
pub fn server_port(personality: PersonalityId) -> u64 {
    let idx = personality as u8 as usize;
    if idx >= SERVERS.len() {
        return 0;
    }
    SERVERS[idx].port.load(Ordering::Acquire)
}

/// Set the personality of a task. Returns 0 on success, u64::MAX on error.
/// Args: target_task_port (0 = self), personality_id, abi_id.
/// Only root (euid 0) or the personality server for the target can call this.
pub fn set_personality(target_port: u64, personality_id: u8, abi_id: u8) -> u64 {
    use crate::sched::task::{PersonalityId, SyscallAbi};

    // Validate personality_id.
    let personality = match personality_id {
        0 => PersonalityId::TelixNative,
        1 => PersonalityId::Posix,
        2 => PersonalityId::Linux,
        3 => PersonalityId::Darwin,
        4 => PersonalityId::WindowsNt,
        5 => PersonalityId::FreeBsd,
        6 => PersonalityId::Plan9,
        7 => PersonalityId::Haiku,
        _ => return u64::MAX,
    };

    // Validate abi_id (just check it's in the known range).
    let abi = match abi_id {
        0 => SyscallAbi::TelixNative,
        1 => SyscallAbi::LinuxAarch64,
        2 => SyscallAbi::LinuxAarch32,
        3 => SyscallAbi::LinuxX86_64,
        4 => SyscallAbi::LinuxI386,
        5 => SyscallAbi::LinuxRv64,
        6 => SyscallAbi::LinuxMipsN64,
        7 => SyscallAbi::LinuxMipsO32,
        8 => SyscallAbi::LinuxMipsN32,
        9 => SyscallAbi::LinuxLa64,
        16 => SyscallAbi::NtX86_64,
        17 => SyscallAbi::NtAarch64,
        18 => SyscallAbi::NtI386,
        32 => SyscallAbi::DarwinX86_64,
        33 => SyscallAbi::DarwinAarch64,
        48 => SyscallAbi::Plan9Amd64,
        64 => SyscallAbi::HaikuX86_64,
        _ => return u64::MAX,
    };

    // Resolve target task.
    let task_id = if target_port == 0 {
        let tid = crate::sched::smp::current()
            .current_thread
            .load(Ordering::Relaxed);
        crate::sched::scheduler::thread_ref(tid).task_id
    } else {
        match crate::sched::task_id_from_any_port(target_port) {
            Some(id) => id,
            None => {
                match crate::sched::task_id_from_any_port(target_port) {
                    Some(id) => id,
                    None => return u64::MAX,
                }
            }
        }
    };

    // Permission check: root or the registered personality server.
    let caller_task_id = {
        let tid = crate::sched::smp::current()
            .current_thread
            .load(Ordering::Relaxed);
        crate::sched::scheduler::thread_ref(tid).task_id
    };
    let caller_euid = crate::sched::scheduler::task_ref(caller_task_id).euid;
    if caller_euid != 0 {
        // Check if caller is the personality server for this personality.
        let srv_port = server_port(personality);
        let caller_port = crate::sched::scheduler::task_ref(caller_task_id).port_id;
        if srv_port == 0 || caller_port != srv_port {
            return u64::MAX;
        }
    }

    // Apply personality.
    let srv = server_port(personality);
    let task = unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) };
    task.personality = personality;
    task.syscall_abi = abi;
    task.personality_port = srv;
    0
}

/// Forward a foreign syscall to the personality server via IPC.
///
/// Packages nr + args into a message, sends to the personality server port,
/// blocks the calling thread, and returns the reply set by SYS_PERSONALITY_REPLY.
///
/// Message format:
///   tag     = (syscall_nr & 0xFFFFFFFF) | (caller_port << 32)
///   data[0] = args[0]
///   data[1] = args[1]
///   data[2] = args[2]
///   data[3] = args[3]
///   data[4] = args[4]
///   data[5] = overwritten with sender priority by port::send internals (args[5] lost)
pub fn forward_to_server(
    personality_port: u64,
    nr: u64,
    args: [u64; 6],
) -> u64 {
    use crate::ipc::message::Message;
    use crate::sched::thread::BlockReason;

    if personality_port == 0 {
        return u64::MAX;
    }

    // Identify the calling thread/task.
    // #136 fix: send the THREAD's port_id (not the task's port) so the
    // personality server's reply can route to the *specific* calling
    // thread.  For CLONE_THREAD tasks (multiple threads sharing one
    // task_id) the task port is ambiguous — find_personality_waiter
    // would pick "any" waiter, sending the child's reply to whichever
    // thread happened to be parked first.  Per-thread port routing
    // preserves the wake target.
    let tid = crate::sched::current_thread_id();
    let task_id = crate::sched::scheduler::thread_ref(tid).task_id;
    let caller_port = crate::sched::scheduler::thread_ref(tid).port_id;

    // #136 IRETQ probe: log every forward (gives us entry + RIP per
    // syscall), rate-limited per-tid.  Pairs with the IRETQ exit
    // print in exception.rs.  If a CHILD of clone3 makes syscalls
    // that show up here but NOT in IRETQ exit prints, that means
    // forward_to_server is being called but the syscall return path
    // doesn't go back through the #UD-emulated dispatcher — possibly
    // a different return route for child threads.
    {
        if (tid as usize) < FWD_LOG_COUNT.len() {
            let n = FWD_LOG_COUNT[tid as usize]
                .fetch_add(1, Ordering::Relaxed);
            if n < 30 {
                let frame_sp_now =
                    unsafe { crate::sched::scheduler::thread_mut_from_ref(tid) }
                        .syscall_frame_sp;
                let rip_at_entry = if frame_sp_now != 0 {
                    #[cfg(target_arch = "x86_64")]
                    {
                        let f = unsafe {
                            &*(frame_sp_now as *const crate::syscall::handlers::ExceptionFrame)
                        };
                        f.rip()
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    {
                        // Other arches: no easy rip() accessor on ExceptionFrame;
                        // omit from log (this is a debug trace, x86-specific
                        // diagnostic).  Returning 0 keeps log structure parseable.
                        0u64
                    }
                } else {
                    0
                };
                crate::println!(
                    "FWD: tid={} task={} nr={} rip_after_inst={:#x} caller_port={:#x}",
                    tid, task_id, nr, rip_at_entry, caller_port
                );
            }
        }
    }

    // Build the forwarded message.
    // Pack syscall number (low 32 bits) and caller port (high 32 bits) into tag,
    // so all 6 data slots carry syscall arguments.
    let msg = Message {
        tag: (nr & 0xFFFF_FFFF) | (caller_port << 32),
        data: [args[0], args[1], args[2], args[3], args[4], args[5]],
    };

    // Sentinel: -4096 as u64. Not a valid Linux syscall return value (valid
    // errno range is -1..-4095, success is non-negative). Used to detect
    // spurious wakes from signals — if we wake and personality_result still
    // holds this sentinel, the personality server hasn't replied yet.
    const PERSONALITY_PENDING: u64 = (-4096i64) as u64;

    // Clear the result field and set blocked_on before sending, so the
    // personality server can find us even if it replies before we block.
    {
        let tref = crate::sched::scheduler::thread_ref(tid);
        tref.personality_result.store(PERSONALITY_PENDING, Ordering::Release);
        tref.wakeup.store(false, Ordering::Release);
    }
    // Safety: single writer (current thread setting its own state).
    unsafe {
        crate::sched::scheduler::thread_mut_from_ref(tid).blocked_on =
            BlockReason::PersonalityWait;
    }

    // Save the exception frame pointer into personality_frame_sp so the
    // personality server can read it reliably (for personality_read_args,
    // personality_copy_in/out, personality_fork). We read from the per-thread
    // syscall_frame_sp (set by store_frame_sp before IRQs were enabled)
    // rather than the per-CPU slot, which may have been overwritten if a
    // timer preempted us and another thread ran on our original CPU.
    {
        let frame_sp = unsafe { crate::sched::scheduler::thread_mut_from_ref(tid) }.syscall_frame_sp;
        unsafe { crate::sched::scheduler::thread_mut_from_ref(tid) }.personality_frame_sp = frame_sp;
    }

    // Send to the personality server.
    if crate::ipc::port::send(personality_port, msg).is_err() {
        unsafe {
            crate::sched::scheduler::thread_mut_from_ref(tid).blocked_on =
                BlockReason::None;
        }
        return u64::MAX;
    }

    // Block until the personality server calls SYS_PERSONALITY_REPLY.
    // Loop handles spurious wakes from signals: if personality_result still
    // holds the sentinel, the server hasn't replied — re-arm and re-block.
    loop {
        crate::sched::block_current(BlockReason::PersonalityWait);
        let result = crate::sched::scheduler::thread_ref(tid)
            .personality_result
            .load(Ordering::Acquire);
        if result != PERSONALITY_PENDING {
            break;
        }
        // Spurious wake (signal delivery). Check if we were killed.
        if crate::sched::scheduler::thread_ref(tid)
            .killed
            .load(Ordering::Acquire)
        {
            break;
        }
        // Re-arm wakeup flag for re-blocking.
        crate::sched::scheduler::thread_ref(tid)
            .wakeup
            .store(false, Ordering::Release);
        // Re-check personality_result AFTER clearing wakeup. If personality_reply
        // fired between our first check and the wakeup.store(false), the result
        // is ready but we just overwrote wakeup — break instead of re-blocking.
        let result2 = crate::sched::scheduler::thread_ref(tid)
            .personality_result
            .load(Ordering::Acquire);
        if result2 != PERSONALITY_PENDING {
            break;
        }
    }

    // Clear blocked_on now that we're awake.
    unsafe {
        crate::sched::scheduler::thread_mut_from_ref(tid).blocked_on =
            BlockReason::None;
    }

    // Read the result deposited by personality_reply().
    crate::sched::scheduler::thread_ref(tid)
        .personality_result
        .load(Ordering::Acquire)
}

/// Reply to a forwarded personality syscall, unblocking the caller.
///
/// Called by the personality server via SYS_PERSONALITY_REPLY.
/// `target_task_port` identifies the blocked task; `result` is the return value.
pub fn personality_reply(target_task_port: u64, result: u64) -> u64 {
    // Permission check: caller must be the registered personality server.
    let caller_task_id = {
        let tid = crate::sched::smp::current()
            .current_thread
            .load(Ordering::Relaxed);
        crate::sched::scheduler::thread_ref(tid).task_id
    };
    let caller_port = crate::sched::scheduler::task_ref(caller_task_id).port_id;

    // Check that caller is a registered personality server.
    let mut is_server = false;
    for i in 1..SERVERS.len() {
        if SERVERS[i].port.load(Ordering::Acquire) == caller_port {
            is_server = true;
            break;
        }
    }
    if !is_server {
        let caller_euid = crate::sched::scheduler::task_ref(caller_task_id).euid;
        if caller_euid != 0 {
            return u64::MAX;
        }
    }

    // #136 fix: target_task_port can now be a THREAD port (per-thread
    // routing — see forward_to_server's caller_port change).  Resolve
    // to a specific thread if it's a thread port; fall back to the
    // legacy "find any waiter in the task" path for task ports (single-
    // thread Linux processes, etc.).
    let target_tid: u32 = if let Some(thread_tid) =
        crate::sched::validated_thread_from_port(target_task_port)
    {
        thread_tid
    } else if let Some(target_task_id) =
        crate::sched::task_id_from_any_port(target_task_port)
    {
        let waiter = find_personality_waiter(target_task_id);
        if waiter == u32::MAX {
            return u64::MAX;
        }
        waiter
    } else {
        return u64::MAX;
    };

    // Deliver the result and wake.
    crate::sched::scheduler::thread_ref(target_tid)
        .personality_result
        .store(result, Ordering::Release);
    crate::sched::wake_thread(target_tid);
    0
}

/// Read args[4] and args[5] from a blocked personality-wait task's saved frame.
///
/// Returns (arg4, arg5) packed as: arg4 in the return register, arg5 in the
/// second return register (arch-specific, delivered via frame).
pub fn personality_read_args(
    target_task_port: u64,
    frame: &mut crate::arch::trapframe::ExceptionFrame,
) -> u64 {
    // Permission check (same as personality_reply).
    let caller_task_id = {
        let tid = crate::sched::smp::current()
            .current_thread
            .load(Ordering::Relaxed);
        crate::sched::scheduler::thread_ref(tid).task_id
    };
    let caller_port = crate::sched::scheduler::task_ref(caller_task_id).port_id;

    let mut is_server = false;
    for i in 1..SERVERS.len() {
        if SERVERS[i].port.load(Ordering::Acquire) == caller_port {
            is_server = true;
            break;
        }
    }
    if !is_server {
        let caller_euid = crate::sched::scheduler::task_ref(caller_task_id).euid;
        if caller_euid != 0 {
            return u64::MAX;
        }
    }

    // Find the target task and its personality-waiting thread.
    let target_task_id = match crate::sched::task_id_from_any_port(target_task_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    // Read args[4] and args[5] from the target's personality exception frame.
    let target_sp = crate::sched::scheduler::thread_ref(target_tid).personality_frame_sp;
    if target_sp == 0 {
        return u64::MAX;
    }
    let target_frame = unsafe { &*(target_sp as *const crate::arch::trapframe::ExceptionFrame) };
    let arg4 = crate::arch::trapframe::syscall_arg(target_frame, 4);
    let arg5 = crate::arch::trapframe::syscall_arg(target_frame, 5);

    // Return arg4 as the primary return value, arg5 in the second register.
    crate::arch::trapframe::set_reg(frame, 1, arg5);
    arg4
}

/// Check that the caller is a registered personality server.
/// Returns the caller's task_id, or None if not authorized.
fn check_personality_server() -> Option<u32> {
    let caller_task_id = {
        let tid = crate::sched::smp::current()
            .current_thread
            .load(Ordering::Relaxed);
        crate::sched::scheduler::thread_ref(tid).task_id
    };
    let caller_port = crate::sched::scheduler::task_ref(caller_task_id).port_id;

    let mut is_server = false;
    for i in 1..SERVERS.len() {
        if SERVERS[i].port.load(Ordering::Acquire) == caller_port {
            is_server = true;
            break;
        }
    }
    if !is_server {
        let caller_euid = crate::sched::scheduler::task_ref(caller_task_id).euid;
        if caller_euid != 0 {
            return None;
        }
    }
    Some(caller_task_id)
}

/// Copy bytes from a blocked personality-wait task's address space into the
/// caller (personality server)'s buffer.
///
/// Args: target_task_port, src_va (in target), dst_va (in caller), len.
/// Returns bytes copied, or u64::MAX on error.
pub fn personality_copy_in(target_port: u64, src_va: usize, dst_va: usize, len: usize) -> u64 {
    if len == 0 {
        return 0;
    }
    let caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    let target_pt = crate::sched::scheduler::task_ref(target_task_id).page_table_root;
    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    let target_aspace = crate::sched::scheduler::task_ref(target_task_id).aspace_id;
    let caller_aspace = crate::sched::scheduler::task_ref(caller_task_id).aspace_id;

    // Copy in chunks through a kernel-side buffer to avoid mapping issues.
    // On failure, try to fault-in the unmapped pages and retry once —
    // translate_va does not demand-page on its own, so fresh stack /
    // COW / pager-backed pages silently fail without this.
    let mut offset = 0;
    let mut tmp = [0u8; 4096];
    while offset < len {
        let chunk = (len - offset).min(4096);
        if !crate::syscall::handlers::copy_from_user(target_pt, src_va + offset, &mut tmp[..chunk]) {
            fault_in_range(target_aspace, target_pt, src_va + offset, chunk, crate::mm::fault::FaultType::Read);
            if !crate::syscall::handlers::copy_from_user(target_pt, src_va + offset, &mut tmp[..chunk]) {
                break;
            }
        }
        if !crate::syscall::handlers::copy_to_user(caller_pt, dst_va + offset, &tmp[..chunk]) {
            fault_in_range(caller_aspace, caller_pt, dst_va + offset, chunk, crate::mm::fault::FaultType::Write);
            if !crate::syscall::handlers::copy_to_user(caller_pt, dst_va + offset, &tmp[..chunk]) {
                break;
            }
        }
        offset += chunk;
    }
    offset as u64
}

/// Copy bytes from the caller (personality server)'s buffer into a blocked
/// personality-wait task's address space.
///
/// Args: target_task_port, dst_va (in target), src_va (in caller), len.
/// Returns bytes copied, or u64::MAX on error.
pub fn personality_copy_out(target_port: u64, dst_va: usize, src_va: usize, len: usize) -> u64 {
    if len == 0 {
        return 0;
    }
    let caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    let target_pt = crate::sched::scheduler::task_ref(target_task_id).page_table_root;
    let caller_aspace = crate::sched::scheduler::task_ref(caller_task_id).aspace_id;
    let target_aspace = crate::sched::scheduler::task_ref(target_task_id).aspace_id;

    let mut offset = 0;
    let mut tmp = [0u8; 4096];
    while offset < len {
        let chunk = (len - offset).min(4096);
        if !crate::syscall::handlers::copy_from_user(caller_pt, src_va + offset, &mut tmp[..chunk]) {
            fault_in_range(caller_aspace, caller_pt, src_va + offset, chunk, crate::mm::fault::FaultType::Read);
            if !crate::syscall::handlers::copy_from_user(caller_pt, src_va + offset, &mut tmp[..chunk]) {
                break;
            }
        }
        if !crate::syscall::handlers::copy_to_user(target_pt, dst_va + offset, &tmp[..chunk]) {
            fault_in_range(target_aspace, target_pt, dst_va + offset, chunk, crate::mm::fault::FaultType::Write);
            if !crate::syscall::handlers::copy_to_user(target_pt, dst_va + offset, &tmp[..chunk]) {
                break;
            }
        }
        offset += chunk;
    }
    offset as u64
}

/// Pre-fault each MMU page in [va, va+len) for the given aspace so that
/// subsequent copy_from_user/copy_to_user see a present leaf PTE.
///
/// Kernel-initiated user-memory access via translate_va doesn't trigger
/// demand-paging the way a hardware MMU fault would — if the page isn't
/// yet present (fresh stack, COW, pager-backed), translate_va returns
/// None and the copy fails silently.  This helper explicitly invokes
/// the fault handler for each MMU page touched so the PTE is populated
/// before the copy runs.
///
/// Uses with_aspace_mut (not with_aspace) so a stale aspace id silently
/// no-ops instead of panicking — the subsequent copy_from_user will
/// still fail, but the caller handles that path gracefully.
fn fault_in_range(
    aspace: u64,
    pt_root: usize,
    va: usize,
    len: usize,
    fault_type: crate::mm::fault::FaultType,
) {
    if len == 0 || pt_root == 0 || aspace == 0 {
        return;
    }
    // Bail if the aspace id isn't live.  handle_page_fault would panic
    // via with_aspace otherwise.
    if crate::mm::aspace::with_aspace_mut(aspace, |_| ()).is_none() {
        return;
    }
    let page_size = crate::mm::page::page_size();
    let first_page = va & !(page_size - 1);
    let last_page = (va + len - 1) & !(page_size - 1);
    let mut p = first_page;
    while p <= last_page {
        if crate::mm::hat::translate_va(pt_root, p).is_none() {
            let _ = crate::mm::fault::handle_page_fault(aspace, p, fault_type);
        }
        p += page_size;
    }
}

/// Fork a target task on behalf of a personality server.
///
/// Returns the child task's port_id, or u64::MAX on error.
pub fn personality_fork(target_port: u64) -> u64 {
    let _caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    crate::sched::scheduler::fork_for_task(target_task_id, target_tid)
}

/// Wait for a child of the target task on behalf of a personality server.
///
/// Returns child_port in r0, status in r1 (via frame). Always non-blocking.
pub fn personality_wait4(
    target_port: u64,
    pid: u64,
    flags: u64,
    frame: &mut crate::arch::trapframe::ExceptionFrame,
) -> u64 {
    let _caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    // Note: target does NOT need to be in PersonalityWait for wait4,
    // but it should be blocked (it's waiting for linux_srv to reply).
    // Actually, the target IS blocked in PersonalityWait since it called
    // Linux wait4 which got forwarded to us.

    let (child_port, _child_id, status) =
        crate::sched::scheduler::wait4_for_task(target_task_id, pid as i64, flags as u32);

    // Pack: child_port in low 32 bits of r1, status in high 32 bits.
    let packed_status = (status as u32) as u64;
    crate::arch::trapframe::set_reg(frame, 1, packed_status);
    child_port
}

/// Personality-delegated execve: replace a blocked target task's image.
/// Args: target_port, name_ptr (in caller's address space), name_len.
/// On success, wakes the target directly (personality server should NOT
/// call personality_reply). Returns 0 on success, u64::MAX on failure.
pub fn personality_execve(
    target_port: u64,
    name_ptr: u64,
    name_len: u64,
    argv_va: u64,
    envp_va: u64,
) -> u64 {
    let _caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    // Read filename from caller's (personality server's) address space.
    // Since we're running on the personality server's thread, we can read directly.
    let len = (name_len as usize).min(64);
    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, len) };

    // argv_va / envp_va are virtual addresses in the **client's** old aspace.
    // exec_for_task reads them via copy_from_user against the client pt_root
    // before tearing down the old address space.
    let result = crate::syscall::handlers::exec_for_task(
        target_task_id,
        target_tid,
        name,
        argv_va as usize,
        envp_va as usize,
        None, // initramfs lookup (existing fast path)
    );
    if result != 0 {
        return u64::MAX;
    }

    // Wake the target thread. Its exception frame has been rewritten to
    // point at the new binary's entry. When it returns through
    // forward_to_server → dispatch → set_return, the set_return writes
    // to rax which is harmless for a freshly exec'd binary.
    // Must use wake_thread() (not raw wakeup.store) so that the thread's
    // priority is restored and yield_asap is cleared, allowing it to
    // actually be scheduled.
    crate::sched::scheduler::thread_ref(target_tid)
        .personality_result
        .store(0, core::sync::atomic::Ordering::Release);
    crate::sched::wake_thread(target_tid);

    0
}

/// #268-B: exec a target task from an ELF image supplied by the personality
/// server, rather than looked up in the kernel initramfs.  This is the
/// native-Telix half of "exec from a disk-backed root": linux_srv reads the
/// ELF off the (ext/btrfs) root via the async VFS path into its own buffer,
/// then invokes this to install it.  Mirrors `personality_execve` but passes
/// the image bytes through to `exec_for_task` instead of a name to look up.
///
/// `image_va`/`image_len` describe the ELF bytes in the PERSONALITY SERVER's
/// address space.  We run on its thread (its aspace is the current CR3), so
/// the slice is directly readable and stays valid through `load_elf` — the
/// only aspace torn down by exec is the *client's*, not the server's.
pub fn personality_exec_image(
    target_port: u64,
    image_va: u64,
    image_len: u64,
    argv_va: u64,
    envp_va: u64,
) -> u64 {
    let _caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    // Bound the image to a sane size and read it from the server's aspace.
    const MAX_EXEC_IMAGE: usize = 64 * 1024 * 1024;
    let len = image_len as usize;
    if image_va == 0 || len == 0 || len > MAX_EXEC_IMAGE {
        return u64::MAX;
    }
    let image = unsafe { core::slice::from_raw_parts(image_va as *const u8, len) };

    // Empty name: the image supplies the binary, so no initramfs lookup.
    let result = crate::syscall::handlers::exec_for_task(
        target_task_id,
        target_tid,
        &[],
        argv_va as usize,
        envp_va as usize,
        Some(image),
    );
    if result != 0 {
        return u64::MAX;
    }

    crate::sched::scheduler::thread_ref(target_tid)
        .personality_result
        .store(0, core::sync::atomic::Ordering::Release);
    crate::sched::wake_thread(target_tid);
    0
}

/// Find a thread in `task_id` that is blocked on PersonalityWait.
/// Returns the ThreadId, or u32::MAX if none found.
fn find_personality_waiter(task_id: u32) -> u32 {
    crate::sched::scheduler::find_personality_waiter(task_id)
}

// =============================================================================
// Cross-address-space memory operations for personality servers
// =============================================================================

/// Resolve target task for a personality memory operation.
/// Returns (target_task_id, target_aspace_id) or None.
fn resolve_personality_target(target_port: u64) -> Option<(u32, u64)> {
    let _caller_task_id = check_personality_server()?;
    // #136 fix: target_port may be a THREAD port (per-thread routing
    // introduced by the forward_to_server change).  Resolve to the
    // task_id either way: thread_port → thread → task_id; task_port →
    // task_id directly.  Memory ops are aspace-wide so any thread of
    // the same task resolves to the same aspace.
    let target_task_id = crate::sched::task_id_from_any_port(target_port)?;
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return None;
    }
    let task = crate::sched::scheduler::task_ref(target_task_id);
    let aspace_id = task.aspace_id;
    if aspace_id == 0 {
        return None;
    }
    Some((target_task_id, aspace_id))
}

/// #275: enumerate a target task's VMAs into the CALLER's buffer, for a real,
/// authoritative /proc/self/maps.  Each entry is 24 bytes: [0..8] va_start LE,
/// [8..16] va_end LE, [16] prot (VmaProt as u8: 0=r-- 1=rw- 2=r-x 3=rwx 4=---),
/// [17..24] reserved.  Entries are VA-ordered (the VMA B+ tree iterates in
/// address order).  Returns the number of entries written, or u64::MAX on error.
///
/// Iterates into a kernel-stack buffer UNDER the aspace lock (no user access
/// while locked → no fault-deadlock), then copies out after releasing the lock.
pub fn personality_enumerate_vmas(target_port: u64, buf_va: u64, buf_len: u64) -> u64 {
    let caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };
    let (_target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };
    const MAX_VMAS: usize = 64;
    const ENTRY: usize = 24;
    let cap = ((buf_len as usize) / ENTRY).min(MAX_VMAS);
    if cap == 0 || buf_va == 0 {
        return 0;
    }
    let mut kbuf = [0u8; MAX_VMAS * ENTRY];
    let n = crate::mm::aspace::with_aspace_mut(aspace_id, |aspace| {
        let mut nn = 0usize;
        let mut it = aspace.vmas.iter();
        while let Some(vma) = it.next() {
            if !vma.active {
                continue;
            }
            if nn >= cap {
                break;
            }
            let off = nn * ENTRY;
            kbuf[off..off + 8].copy_from_slice(&(vma.va_start as u64).to_le_bytes());
            kbuf[off + 8..off + 16]
                .copy_from_slice(&((vma.va_start + vma.va_len) as u64).to_le_bytes());
            kbuf[off + 16] = vma.prot as u8;
            nn += 1;
        }
        nn
    })
    .unwrap_or(0);
    if n == 0 {
        return 0;
    }
    let pt_root = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    if !crate::syscall::handlers::copy_to_user(pt_root, buf_va as usize, &kbuf[..n * ENTRY]) {
        return u64::MAX;
    }
    n as u64
}

/// Map anonymous pages in a target task's address space.
/// Equivalent to sys_mmap_anon but targeting a specified task.
pub fn personality_mmap_anon(target_port: u64, va_hint: u64, page_count: u64, prot: u64) -> u64 {
    use crate::mm::page::{self, MMUPAGE_SIZE};
    use crate::mm::vma::VmaProt;

    let (target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };

    let ps = page::page_size();
    let mmu_count = page::page_mmucount();

    let mmu_pages = page_count as usize;
    if mmu_pages == 0 || mmu_pages > 256 * mmu_count {
        return u64::MAX;
    }
    let alloc_pages = (mmu_pages + mmu_count - 1) / mmu_count;

    // Check page quota.
    let task = crate::sched::scheduler::task_ref(target_task_id);
    if task.cur_pages + alloc_pages as u32 > task.max_pages {
        return u64::MAX;
    }
    let new_bytes = (task.cur_pages as u64 + alloc_pages as u64) * ps as u64;
    let rlimit_as = task.rlimits[crate::sched::task::RLIMIT_AS as usize].cur;
    if rlimit_as != crate::sched::task::RLIM_INFINITY && new_bytes > rlimit_as {
        return u64::MAX;
    }

    let prot = match prot {
        0 => VmaProt::ReadOnly,
        1 => VmaProt::ReadWrite,
        2 => VmaProt::ReadExec,
        3 => VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };

    let va_len = mmu_pages * MMUPAGE_SIZE;

    let va = if va_hint == 0 {
        crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.alloc_heap_va(va_len))
    } else {
        va_hint as usize
    };

    // Create VMA + backing object.
    let obj_id = match crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace.map_anon(va, mmu_pages, prot).map(|vma| vma.object_id)
    }) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Eagerly allocate physical pages and install PTEs in target's page table.
    let pt_root = crate::sched::scheduler::task_ref(target_task_id).page_table_root;

    // After fork, the target's page table may have shared COW markers at
    // intermediate levels.  walk_or_create (used by map_single_mmupage)
    // returns None when it hits a shared marker, silently failing the PTE
    // install.  Break shared markers for the entire VA range first.
    let fork_group = crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.fork_group);
    for mmu_idx in 0..mmu_pages {
        let mmu_va = va + mmu_idx * MMUPAGE_SIZE;
        // COW-break can OOM (cow_break_table -> alloc_page None).  Unlike the
        // fault path (fault.rs:124) this return was silently dropped, leaving
        // the shared marker in place so map_range below failed with a
        // misleading "OutOfMemory" — masking the real upstream alloc failure.
        // Fail the mmap clean (ENOMEM) and surface the true cause instead.
        if !crate::mm::hat::ensure_path_unshared(pt_root, mmu_va, fork_group) {
            crate::println!("[mmap_anon] COW-break OOM va={:#x} -> ENOMEM", mmu_va);
            return u64::MAX;
        }
    }

    let sw_z = crate::mm::fault::sw_zeroed_bit();
    let pte_flags = if prot == VmaProt::None {
        0
    } else {
        crate::mm::hat::pte_flags_for_prot(prot) | sw_z
    };

    for page_idx in 0..alloc_pages {
        let pa = match crate::mm::object::try_with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        }) {
            Some(Some(pa)) => pa,
            _ => return u64::MAX,
        };
        let pa_usize = pa.as_usize();

        // Fill with poison byte (typically 0xCD) so that uninitialized
        // reads by user code are visible — see mm::ANON_POISON_BYTE.
        unsafe { core::ptr::write_bytes(crate::mm::page::phys_to_kva(pa_usize) as *mut u8, crate::mm::ANON_POISON_BYTE, ps); }

        let mmu_start = page_idx * mmu_count;
        let mmu_end = core::cmp::min(mmu_start + mmu_count, mmu_pages);
        let alloc_va = va + mmu_start * MMUPAGE_SIZE;
        let alloc_len = (mmu_end - mmu_start) * MMUPAGE_SIZE;
        if let Err(e) =
            crate::mm::hat::map_range(pt_root, alloc_va, pa_usize, alloc_len, pte_flags)
        {
            crate::println!(
                "[mmap] map_range FAIL va={:#x} pa={:#x} len={:#x} err={:?}",
                alloc_va, pa_usize, alloc_len, e
            );
            return u64::MAX;
        }
    }

    // Superpage promotion.
    crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        if let Some(vma) = aspace.find_vma_mut(va) {
            crate::mm::fault::try_superpage_promotion_eager(pt_root, vma, obj_id);
        }
    });

    // Increment page quota counter.
    unsafe { crate::sched::scheduler::task_mut_from_ref(target_task_id) }.cur_pages += alloc_pages as u32;

    va as u64
}

/// Unmap a VMA in a target task's address space.
pub fn personality_munmap(target_port: u64, va: u64) -> u64 {
    let (_target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };
    if crate::mm::aspace::unmap_anon(aspace_id, va as usize) { 0 } else { u64::MAX }
}

/// Change protection on a mapping in a target task's address space.
pub fn personality_mprotect(target_port: u64, addr: u64, len: u64, prot: u64) -> u64 {
    use crate::mm::vma::VmaProt;

    let (_target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };
    let new_prot = match prot {
        0 => VmaProt::ReadOnly,
        1 => VmaProt::ReadWrite,
        2 => VmaProt::ReadExec,
        3 => VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };
    if crate::mm::aspace::mprotect(aspace_id, addr as usize, len as usize, new_prot) { 0 } else { u64::MAX }
}

/// Resize a mapping in a target task's address space.
pub fn personality_mremap(target_port: u64, old_addr: u64, old_len: u64, new_len: u64) -> u64 {
    let (_target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };
    let result = crate::mm::aspace::mremap(aspace_id, old_addr as usize, old_len as usize, new_len as usize);
    if result == 0 { u64::MAX } else { result as u64 }
}

/// Map anonymous pages at a fixed VA in a target task's address space.
/// Properly handles VMA splitting — any overlapping portions of existing
/// mappings in [va, va + page_count * MMUPAGE_SIZE) are unmapped first.
/// Used by MAP_FIXED semantics (e.g. ld.so placing PT_LOAD segments).
pub fn personality_mmap_fixed(target_port: u64, va: u64, page_count: u64, prot: u64) -> u64 {
    use crate::mm::page::{self, MMUPAGE_SIZE};
    use crate::mm::vma::VmaProt;

    let (target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };

    let ps = page::page_size();
    let mmu_count = page::page_mmucount();

    let mmu_pages = page_count as usize;
    if mmu_pages == 0 || mmu_pages > 256 * mmu_count {
        return u64::MAX;
    }
    if va == 0 || (va as usize) % MMUPAGE_SIZE != 0 {
        return u64::MAX;
    }
    let alloc_pages = (mmu_pages + mmu_count - 1) / mmu_count;
    let va_len = mmu_pages * MMUPAGE_SIZE;
    let va = va as usize;

    // Unmap any overlapping VMAs (with splitting at boundaries).
    let freed = crate::mm::aspace::unmap_range(aspace_id, va, va_len);

    // Adjust page quota: credit freed pages, then check new allocation fits.
    let task = crate::sched::scheduler::task_ref(target_task_id);
    let cur = task.cur_pages.saturating_sub(freed);
    if cur + alloc_pages as u32 > task.max_pages {
        return u64::MAX;
    }
    let new_bytes = (cur as u64 + alloc_pages as u64) * ps as u64;
    let rlimit_as = task.rlimits[crate::sched::task::RLIMIT_AS as usize].cur;
    if rlimit_as != crate::sched::task::RLIM_INFINITY && new_bytes > rlimit_as {
        return u64::MAX;
    }

    let prot = match prot {
        0 => VmaProt::ReadOnly,
        1 => VmaProt::ReadWrite,
        2 => VmaProt::ReadExec,
        3 => VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };

    // Create VMA + backing object.
    let obj_id = match crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace.map_anon(va, mmu_pages, prot).map(|vma| vma.object_id)
    }) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Eagerly allocate physical pages and install PTEs.
    let pt_root = crate::sched::scheduler::task_ref(target_task_id).page_table_root;

    let fork_group = crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.fork_group);
    for mmu_idx in 0..mmu_pages {
        let mmu_va = va + mmu_idx * MMUPAGE_SIZE;
        // See personality_mmap_anon: dropping the COW-break OOM masks the real
        // alloc failure as a map_range "OutOfMemory".  Fail clean (ENOMEM).
        if !crate::mm::hat::ensure_path_unshared(pt_root, mmu_va, fork_group) {
            crate::println!("[mmap_fixed] COW-break OOM va={:#x} -> ENOMEM", mmu_va);
            return u64::MAX;
        }
    }

    let sw_z = crate::mm::fault::sw_zeroed_bit();
    let pte_flags = if prot == VmaProt::None {
        0
    } else {
        crate::mm::hat::pte_flags_for_prot(prot) | sw_z
    };

    for page_idx in 0..alloc_pages {
        let pa = match crate::mm::object::try_with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        }) {
            Some(Some(pa)) => pa,
            _ => return u64::MAX,
        };
        let pa_usize = pa.as_usize();
        unsafe { core::ptr::write_bytes(crate::mm::page::phys_to_kva(pa_usize) as *mut u8, crate::mm::ANON_POISON_BYTE, ps); }

        let mmu_start = page_idx * mmu_count;
        let mmu_end = core::cmp::min(mmu_start + mmu_count, mmu_pages);
        let alloc_va = va + mmu_start * MMUPAGE_SIZE;
        let alloc_len = (mmu_end - mmu_start) * MMUPAGE_SIZE;
        if let Err(e) =
            crate::mm::hat::map_range(pt_root, alloc_va, pa_usize, alloc_len, pte_flags)
        {
            crate::println!(
                "[mmap] map_range FAIL va={:#x} pa={:#x} len={:#x} err={:?}",
                alloc_va, pa_usize, alloc_len, e
            );
            return u64::MAX;
        }
    }

    // Superpage promotion.
    crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        if let Some(vma) = aspace.find_vma_mut(va) {
            crate::mm::fault::try_superpage_promotion_eager(pt_root, vma, obj_id);
        }
    });

    // Update page quota: subtract freed, add allocated.
    unsafe {
        let task_mut = crate::sched::scheduler::task_mut_from_ref(target_task_id);
        task_mut.cur_pages = cur + alloc_pages as u32;
    }

    va as u64
}

/// Set the TLS base register for a target task's thread.
pub fn personality_set_tls(target_port: u64, tls_base: u64) -> u64 {
    let (target_task_id, _aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };
    // Find the thread belonging to this task and set its tls_base.
    // For single-threaded personality tasks, the waiter thread is the one
    // we want. Use find_personality_waiter to get the blocked thread.
    let thread_id = find_personality_waiter(target_task_id);
    if thread_id == 0 || thread_id == u32::MAX {
        return u64::MAX;
    }
    unsafe { crate::sched::scheduler::thread_mut_from_ref(thread_id) }.tls_base = tls_base;
    0
}

/// Create a new thread in a target task on behalf of a personality server.
///
/// This is the CLONE_VM | CLONE_THREAD equivalent for personality tasks.
/// The new thread shares the target task's address space and resumes at the
/// same instruction as the parent (clone semantics), with a new stack and
/// return value 0.
///
/// Args: target_port, child_stack, tls_base, flags (reserved), ctid_va.
/// Returns the new thread's port_id, or u64::MAX on error.
pub fn personality_thread_create(
    target_port: u64,
    child_stack: u64,
    tls_base: u64,
    _flags: u64,
    _ctid_va: u64,
) -> u64 {
    let _caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    // Check thread quota.
    let task = crate::sched::scheduler::task_ref(target_task_id);
    if task.thread_count >= task.max_threads {
        return u64::MAX;
    }

    crate::sched::scheduler::clone_thread_in_task(
        target_task_id, target_tid, child_stack, tls_base,
    )
}

// =============================================================================
// Signal delivery helpers for personality servers
// =============================================================================

/// Dequeue one pending signal from a target task's personality-waiting thread.
///
/// Args: target_port, mask (the signal mask to apply — signals with
/// corresponding bits set in `mask` are blocked and will NOT be dequeued).
/// Returns the 1-based signal number, or 0 if no deliverable signal is pending.
pub fn personality_dequeue_signal(target_port: u64, mask: u64) -> u64 {
    let _caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    let t = crate::sched::scheduler::thread_ref(target_tid);
    let deliverable = t.sig_pending & !mask;
    if deliverable == 0 {
        return 0;
    }
    let bit_idx = deliverable.trailing_zeros();
    let sig = bit_idx + 1;
    // Clear the pending bit.
    unsafe { crate::sched::scheduler::thread_mut_from_ref(target_tid) }.sig_pending &= !(1u64 << bit_idx);
    sig as u64
}

/// Peek at the raw pending-signal mask of a target task's personality-waiting
/// thread, WITHOUT consuming any pending signals.
///
/// Args: target_port. Returns the raw `sig_pending` u64 (bit i = signal i+1
/// pending), or u64::MAX on error.
pub fn personality_peek_signals(target_port: u64) -> u64 {
    let _caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }
    crate::sched::scheduler::thread_ref(target_tid).sig_pending
}

/// Read the exception frame of a target task's personality-waiting thread.
///
/// Copies the raw exception frame bytes into the caller's buffer at `dst_va`.
/// `len` is the buffer size; at most EXCEPTION_FRAME_SIZE bytes are copied.
/// Returns bytes copied, or u64::MAX on error.
pub fn personality_read_frame(target_port: u64, dst_va: usize, len: usize) -> u64 {
    let caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    let frame_sp = crate::sched::scheduler::thread_ref(target_tid).personality_frame_sp;
    if frame_sp == 0 {
        return u64::MAX;
    }

    let frame_size = crate::arch::trapframe::EXCEPTION_FRAME_SIZE;
    let copy_len = len.min(frame_size);
    if copy_len == 0 {
        return 0;
    }

    let frame_bytes = unsafe {
        core::slice::from_raw_parts(frame_sp as *const u8, frame_size)
    };

    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    if crate::syscall::handlers::copy_to_user(caller_pt, dst_va, &frame_bytes[..copy_len]) {
        copy_len as u64
    } else {
        u64::MAX
    }
}

/// Write to the exception frame of a target task's personality-waiting thread.
///
/// Copies bytes from the caller's buffer at `src_va` into the target's
/// exception frame. `len` is the buffer size; at most EXCEPTION_FRAME_SIZE
/// bytes are copied. Returns bytes copied, or u64::MAX on error.
pub fn personality_write_frame(target_port: u64, src_va: usize, len: usize) -> u64 {
    let caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let target_task_id = match crate::sched::task_id_from_any_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    let frame_sp = crate::sched::scheduler::thread_ref(target_tid).personality_frame_sp;
    if frame_sp == 0 {
        return u64::MAX;
    }

    let frame_size = crate::arch::trapframe::EXCEPTION_FRAME_SIZE;
    let copy_len = len.min(frame_size);
    if copy_len == 0 {
        return 0;
    }

    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    let frame_bytes = unsafe {
        core::slice::from_raw_parts_mut(frame_sp as *mut u8, frame_size)
    };

    if crate::syscall::handlers::copy_from_user(caller_pt, src_va, &mut frame_bytes[..copy_len]) {
        copy_len as u64
    } else {
        u64::MAX
    }
}

// =============================================================================
// MAP_SHARED: map physical pages from caller into target's address space
// =============================================================================

/// Map physical pages from the caller's address space into a target task's
/// address space. Used for MAP_SHARED semantics where linux_srv holds the
/// backing memory (e.g. memfd) and needs the client to see the same pages.
///
/// Args: target_port, caller_va (source pages in caller), target_va_hint (0=auto),
///       page_count (in MMUPAGE_SIZE units), prot (0=RO, 1=RW, 2=RX, 3=RWX).
/// Returns the target VA on success, or u64::MAX on error.
pub fn personality_map_shared(
    target_port: u64,
    caller_va: u64,
    target_va_hint: u64,
    page_count: u64,
    prot: u64,
) -> u64 {
    use crate::mm::page::{self, MMUPAGE_SIZE};
    use crate::mm::vma::VmaProt;

    let caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let (target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };

    let mmu_pages = page_count as usize;
    if mmu_pages == 0 || mmu_pages > 256 * page::page_mmucount() {
        return u64::MAX;
    }
    let va_len = mmu_pages * MMUPAGE_SIZE;

    let prot_enum = match prot {
        0 => VmaProt::ReadOnly,
        1 => VmaProt::ReadWrite,
        2 => VmaProt::ReadExec,
        3 => VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };

    // Allocate VA in target's address space.
    let target_va = if target_va_hint == 0 {
        crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.alloc_heap_va(va_len))
    } else {
        target_va_hint as usize
    };

    // Create a VMA in the target (map_anon creates the VMA structure).
    // We won't use its backing object — we'll install PTEs pointing to
    // the caller's physical pages instead.
    let _obj_id = match crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        aspace.map_anon(target_va, mmu_pages, prot_enum).map(|vma| vma.object_id)
    }) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Walk the caller's page table to find physical addresses and install
    // them in the target's page table.
    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    let target_pt = crate::sched::scheduler::task_ref(target_task_id).page_table_root;

    let fork_group = crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.fork_group);

    let sw_z = crate::mm::fault::sw_zeroed_bit();
    let pte_flags = if prot_enum == VmaProt::None {
        0
    } else {
        crate::mm::hat::pte_flags_for_prot(prot_enum) | sw_z
    };

    for mmu_idx in 0..mmu_pages {
        let src_va = caller_va as usize + mmu_idx * MMUPAGE_SIZE;
        let dst_va = target_va + mmu_idx * MMUPAGE_SIZE;

        // Look up the physical address in the caller's page table.
        let pa = match crate::mm::hat::translate_va(caller_pt, src_va) {
            Some(pa) => pa,
            None => return u64::MAX,
        };

        // Ensure the target's page table path is unshared (post-fork).
        // A dropped OOM here would let map_single_mmupage hit the still-shared
        // marker and silently fail; fail the call clean (ENOMEM) instead.
        if !crate::mm::hat::ensure_path_unshared(target_pt, dst_va, fork_group) {
            crate::println!("[map_shared] COW-break OOM dst_va={:#x} -> ENOMEM", dst_va);
            return u64::MAX;
        }

        // Map the caller's physical page into the target's page table.
        if !crate::mm::hat::map_single_mmupage(target_pt, dst_va, pa, pte_flags) {
            crate::println!("[map_shared] map PTE FAIL dst_va={:#x} -> ENOMEM", dst_va);
            return u64::MAX;
        }
    }

    target_va as u64
}

/// Like `personality_map_shared`, but installs the shared PTEs over a region the
/// target has ALREADY mapped (e.g. via `personality_mmap_fixed`/`_anon`) instead
/// of allocating a fresh anon VMA.  Used by the H14 read-only library-page
/// sharing path: linux_srv first reserves/splits the VMA (ld.so's
/// reserve-then-replace needs `mmap_fixed`'s VMA split), then maps the cached
/// library's physical pages SHARED into that region instead of copying the bytes
/// out per-process.  Because the region was created moments earlier in the SAME
/// mmap syscall and the target process has not resumed (so it never touched the
/// region), its PTEs are still unfaulted and there are no stale TLB entries to
/// shoot down — the same property memfd/DRM `map_shared` relies on.
///
/// SAFETY / sharing constraints (enforced by the caller, linux_srv): only used
/// for read-only CODE mappings (`prot == 2`, ReadExec), which are never written
/// or mprotected-writable, so the shared cache pages can never be mutated by the
/// process — no COW is needed.  The shared pages are owned by linux_srv's
/// persistent LIB_CACHE; like memfd/DRM, aspace teardown frees the target's anon
/// object (which owns nothing here) and the page tables, but NOT these pages.
///
/// Args: `target_port`, `caller_va` (source pages in linux_srv), `target_va`
/// (the existing region in the target — REQUIRED, must be non-zero),
/// `page_count` (in MMUPAGE_SIZE units), `prot` (0=RO,1=RW,2=RX,3=RWX).
/// Returns `target_va` on success, or `u64::MAX` on error.
pub fn personality_remap_shared(
    target_port: u64,
    caller_va: u64,
    target_va: u64,
    page_count: u64,
    prot: u64,
) -> u64 {
    use crate::mm::page::{self, MMUPAGE_SIZE};
    use crate::mm::vma::VmaProt;

    let caller_task_id = match check_personality_server() {
        Some(id) => id,
        None => return u64::MAX,
    };

    let (target_task_id, aspace_id) = match resolve_personality_target(target_port) {
        Some(v) => v,
        None => return u64::MAX,
    };

    let mmu_pages = page_count as usize;
    if mmu_pages == 0 || mmu_pages > 256 * page::page_mmucount() {
        return u64::MAX;
    }
    // The target region must already exist; no auto-allocation here.
    if target_va == 0 {
        return u64::MAX;
    }

    let prot_enum = match prot {
        0 => VmaProt::ReadOnly,
        1 => VmaProt::ReadWrite,
        2 => VmaProt::ReadExec,
        3 => VmaProt::ReadWriteExec,
        _ => return u64::MAX,
    };

    // Walk the caller's page table to find physical addresses and install them
    // in the target's already-mapped region (no map_anon — the VMA exists).
    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    let target_pt = crate::sched::scheduler::task_ref(target_task_id).page_table_root;

    let fork_group = crate::mm::aspace::with_aspace(aspace_id, |aspace| aspace.fork_group);

    let sw_z = crate::mm::fault::sw_zeroed_bit();
    let pte_flags = if prot_enum == VmaProt::None {
        0
    } else {
        crate::mm::hat::pte_flags_for_prot(prot_enum) | sw_z
    };

    for mmu_idx in 0..mmu_pages {
        let src_va = caller_va as usize + mmu_idx * MMUPAGE_SIZE;
        let dst_va = target_va as usize + mmu_idx * MMUPAGE_SIZE;

        // Look up the physical address in the caller's page table.
        let pa = match crate::mm::hat::translate_va(caller_pt, src_va) {
            Some(pa) => pa,
            None => return u64::MAX,
        };

        // Ensure the target's page table path is unshared (post-fork COW).
        if !crate::mm::hat::ensure_path_unshared(target_pt, dst_va, fork_group) {
            crate::println!("[remap_shared] COW-break OOM dst_va={:#x} -> ENOMEM", dst_va);
            return u64::MAX;
        }

        // Install the caller's physical page into the target's existing region.
        if !crate::mm::hat::map_single_mmupage(target_pt, dst_va, pa, pte_flags) {
            crate::println!("[remap_shared] map PTE FAIL dst_va={:#x} -> ENOMEM", dst_va);
            return u64::MAX;
        }
    }

    target_va
}
