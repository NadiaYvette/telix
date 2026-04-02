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
            None => return u64::MAX,
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
    let task = unsafe { crate::sched::scheduler::task_mut_from_ref(task_id) };
    task.personality = personality;
    task.syscall_abi = abi;
    task.personality_port = server_port(personality);
    0
}

/// Forward a foreign syscall to the personality server via IPC.
///
/// Packages nr + 6 args into a message, sends to the personality server port,
/// parks the calling thread, and returns the reply.
///
/// TODO: Implement send-and-receive-reply IPC pattern for personality forwarding.
/// For now returns ENOSYS — no foreign personalities are active yet.
pub fn forward_to_server(
    _personality_port: u64,
    nr: u64,
    _args: [u64; 6],
) -> u64 {
    crate::println!("personality: foreign syscall nr={} — not yet implemented", nr);
    u64::MAX // ENOSYS
}
