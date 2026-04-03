//! Personality server registry and foreign syscall routing.
//!
//! When a task has a non-native personality, its syscalls are forwarded to a
//! userspace personality server via IPC. Simple syscalls can be translated
//! in-kernel via a registered fast-path table.

use crate::sched::task::PersonalityId;
use core::sync::atomic::{AtomicU64, Ordering};

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
        match crate::sched::task_id_from_port(target_port) {
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
///   tag     = foreign syscall number
///   data[0] = args[0]
///   data[1] = args[1]
///   data[2] = args[2]
///   data[3] = args[3]
///   data[4] = caller's task port_id (stamped here, NOT by port::send)
///   data[5] = overwritten with sender priority by port::send internals
///
/// args[4-5] are available to the personality server via SYS_PERSONALITY_READ_ARGS.
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
    let tid = crate::sched::current_thread_id();
    let task_id = crate::sched::scheduler::thread_ref(tid).task_id;
    let caller_port = crate::sched::scheduler::task_ref(task_id).port_id;

    // Build the forwarded message.
    let msg = Message {
        tag: nr,
        data: [args[0], args[1], args[2], args[3], caller_port, 0],
    };

    // Clear the result field and set blocked_on before sending, so the
    // personality server can find us even if it replies before we block.
    {
        let tref = crate::sched::scheduler::thread_ref(tid);
        tref.personality_result.store(u64::MAX, Ordering::Release);
        tref.wakeup.store(false, Ordering::Release);
    }
    // Safety: single writer (current thread setting its own state).
    unsafe {
        crate::sched::scheduler::thread_mut_from_ref(tid).blocked_on =
            BlockReason::PersonalityWait;
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
    crate::sched::block_current(BlockReason::PersonalityWait);

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

    // Find the target task.
    let target_task_id = match crate::sched::task_id_from_port(target_task_port) {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Find a thread in the target task that is blocked on PersonalityWait.
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

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
    let target_task_id = match crate::sched::task_id_from_port(target_task_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    // Read args[4] and args[5] from the target's saved exception frame.
    let target_sp = crate::sched::scheduler::thread_ref(target_tid).saved_sp;
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

    let target_task_id = match crate::sched::task_id_from_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    let target_pt = crate::sched::scheduler::task_ref(target_task_id).page_table_root;
    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;

    // Copy in chunks through a kernel-side buffer to avoid mapping issues.
    let mut offset = 0;
    let mut tmp = [0u8; 4096];
    while offset < len {
        let chunk = (len - offset).min(4096);
        if !crate::syscall::handlers::copy_from_user(target_pt, src_va + offset, &mut tmp[..chunk]) {
            break;
        }
        if !crate::syscall::handlers::copy_to_user(caller_pt, dst_va + offset, &tmp[..chunk]) {
            break;
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

    let target_task_id = match crate::sched::task_id_from_port(target_port) {
        Some(id) => id,
        None => return u64::MAX,
    };
    let target_tid = find_personality_waiter(target_task_id);
    if target_tid == u32::MAX {
        return u64::MAX;
    }

    let caller_pt = crate::sched::scheduler::task_ref(caller_task_id).page_table_root;
    let target_pt = crate::sched::scheduler::task_ref(target_task_id).page_table_root;

    let mut offset = 0;
    let mut tmp = [0u8; 4096];
    while offset < len {
        let chunk = (len - offset).min(4096);
        if !crate::syscall::handlers::copy_from_user(caller_pt, src_va + offset, &mut tmp[..chunk]) {
            break;
        }
        if !crate::syscall::handlers::copy_to_user(target_pt, dst_va + offset, &tmp[..chunk]) {
            break;
        }
        offset += chunk;
    }
    offset as u64
}

/// Find a thread in `task_id` that is blocked on PersonalityWait.
/// Returns the ThreadId, or u32::MAX if none found.
fn find_personality_waiter(task_id: u32) -> u32 {
    crate::sched::scheduler::find_personality_waiter(task_id)
}
