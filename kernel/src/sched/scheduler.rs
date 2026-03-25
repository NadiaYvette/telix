//! Scheduler — priority-based round-robin with timer-driven preemption.
//!
//! Context switching works by swapping kernel stack pointers. When a timer
//! IRQ fires, the exception vector saves all registers onto the current
//! thread's kernel stack. If preemption is needed, we save the current SP
//! in the thread's TCB, load the new thread's SP, and the exception return
//! path restores the new thread's registers and `eret`s to it.
//!
//! SMP: Run queues are shared across all CPUs, protected by the scheduler
//! spinlock. Each CPU tracks its own current/idle thread via smp::PerCpuData.

use super::thread::{Thread, ThreadId, ThreadState, BlockReason, MAX_THREADS, EXCEPTION_FRAME_SIZE};
use super::task::{Task, TaskId, MAX_TASKS, MAX_GROUPS, RLIMIT_COUNT, Rlimit};
use super::smp;
use crate::sync::SpinLock;
use crate::mm::page::{PAGE_SIZE, MMUPAGE_SIZE};
use core::sync::atomic::{AtomicUsize, AtomicU32, AtomicU64, Ordering};

/// Per-CPU saved frame SP. The exception handler stores the current frame_sp
/// here before calling syscall dispatch, so that park_current_for_ipc() can
/// read it without changing dispatch()'s signature.
static CURRENT_FRAME_SP: [AtomicU64; smp::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; smp::MAX_CPUS]
};

/// Per-CPU pending context switch target SP. When a syscall handler parks the
/// current thread or does a direct handoff, it stores the target thread's SP
/// here. The exception handler checks this after dispatch() returns and uses
/// it as the new SP if non-zero.
static PENDING_SWITCH_SP: [AtomicU64; smp::MAX_CPUS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; smp::MAX_CPUS]
};

/// Per-CPU deferred kernel stack free. When a thread exits, it can't free
/// its own stack (it's running on it). The address is stored here and freed
/// by the next thread scheduled on that CPU.
static DEFERRED_KSTACK: [AtomicUsize; smp::MAX_CPUS] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; smp::MAX_CPUS]
};

/// Per-CPU deferred thread ID — the thread whose kstack is in DEFERRED_KSTACK.
/// When try_switch drains the deferred free, it also sets stack_base=0 on this
/// thread, making the slot eligible for reuse. This prevents a race where a
/// slot is reused while the dead thread is still physically running.
static DEFERRED_THREAD: [AtomicUsize; smp::MAX_CPUS] = {
    const INIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    [INIT; smp::MAX_CPUS]
};

const NUM_PRIORITIES: usize = 256;
const MAX_QUEUE_LEN: usize = MAX_THREADS;

struct RunQueue {
    entries: [ThreadId; MAX_QUEUE_LEN],
    head: usize,
    tail: usize,
    len: usize,
}

impl RunQueue {
    const fn new() -> Self {
        Self {
            entries: [0; MAX_QUEUE_LEN],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn push(&mut self, id: ThreadId) {
        if self.len < MAX_QUEUE_LEN {
            self.entries[self.tail] = id;
            self.tail = (self.tail + 1) % MAX_QUEUE_LEN;
            self.len += 1;
        }
    }

    fn pop(&mut self) -> Option<ThreadId> {
        if self.len > 0 {
            let id = self.entries[self.head];
            self.head = (self.head + 1) % MAX_QUEUE_LEN;
            self.len -= 1;
            Some(id)
        } else {
            None
        }
    }

    /// Remove the entry at position `i` (relative to head).
    fn remove_at(&mut self, i: usize) {
        if i == 0 {
            // Fast path: same as pop — just advance head.
            self.head = (self.head + 1) % MAX_QUEUE_LEN;
        } else {
            // Shift subsequent entries toward head.
            for j in i..self.len - 1 {
                let from = (self.head + j + 1) % MAX_QUEUE_LEN;
                let to = (self.head + j) % MAX_QUEUE_LEN;
                self.entries[to] = self.entries[from];
            }
            self.tail = if self.tail == 0 { MAX_QUEUE_LEN - 1 } else { self.tail - 1 };
        }
        self.len -= 1;
    }

    /// Search for and remove a thread belonging to the given coscheduling group
    /// that can run on the given CPU.
    fn find_remove_by_group_for_cpu(&mut self, group: u32, cpu: u32) -> Option<ThreadId> {
        let cpu_bit = 1u64 << cpu;
        for i in 0..self.len {
            let idx = (self.head + i) % MAX_QUEUE_LEN;
            let tid = self.entries[idx];
            if COSCHED_GROUP[tid as usize].load(Ordering::Relaxed) == group
                && AFFINITY_MASK[tid as usize].load(Ordering::Relaxed) & cpu_bit != 0
            {
                self.remove_at(i);
                return Some(tid);
            }
        }
        None
    }

    /// Search for and remove the first thread whose affinity allows it to run
    /// on the given CPU.
    fn find_remove_for_cpu(&mut self, cpu: u32) -> Option<ThreadId> {
        let cpu_bit = 1u64 << cpu;
        for i in 0..self.len {
            let idx = (self.head + i) % MAX_QUEUE_LEN;
            let tid = self.entries[idx];
            if AFFINITY_MASK[tid as usize].load(Ordering::Relaxed) & cpu_bit != 0 {
                self.remove_at(i);
                return Some(tid);
            }
        }
        None
    }
}

pub struct Scheduler {
    pub(crate) threads: [Thread; MAX_THREADS],
    pub tasks: [Task; MAX_TASKS],
    run_queues: [RunQueue; NUM_PRIORITIES],
    next_thread_id: ThreadId,
    next_task_id: u32,
    cosched_burst: u32,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: [const { Thread::empty() }; MAX_THREADS],
            tasks: [const { Task::empty() }; MAX_TASKS],
            run_queues: [const { RunQueue::new() }; NUM_PRIORITIES],
            next_thread_id: 0,
            next_task_id: 0,
            cosched_burst: 0,
        }
    }

    /// Initialize task 0 and the BSP's idle thread (thread 0).
    fn init(&mut self) {
        self.tasks[0].id = 0;
        self.tasks[0].active = true;
        self.next_task_id = 1;

        // Thread 0 = BSP idle thread. Its saved_sp will be set on first preemption.
        self.threads[0].id = 0;
        self.threads[0].state = ThreadState::Running;
        self.threads[0].task_id = 0;
        self.threads[0].base_priority = 255;
        self.threads[0].effective_priority = 255;
        THREAD_PRIO[0].store(255, Ordering::Relaxed);
        self.threads[0].quantum = u32::MAX;
        self.threads[0].default_quantum = u32::MAX;
        self.next_thread_id = 1;
    }

    /// Create an idle thread for a secondary CPU. Returns its ThreadId.
    fn create_idle_thread(&mut self) -> Option<ThreadId> {
        let id = self.next_thread_id;
        if id as usize >= MAX_THREADS {
            return None;
        }
        self.next_thread_id += 1;

        let thread = &mut self.threads[id as usize];
        thread.id = id;
        thread.state = ThreadState::Running;
        thread.task_id = 0;
        thread.base_priority = 255;
        thread.effective_priority = 255; // lowest
        THREAD_PRIO[id as usize].store(255, Ordering::Relaxed);
        THREAD_TASK[id as usize].store(0, Ordering::Relaxed);
        thread.quantum = u32::MAX;
        thread.default_quantum = u32::MAX;
        // saved_sp will be set on first preemption
        Some(id)
    }

    /// Find a reusable (Dead) thread slot, or allocate a new one.
    fn alloc_thread_id(&mut self) -> Option<ThreadId> {
        // First, scan for a Dead slot to reuse.
        for i in 1..self.next_thread_id as usize {
            if self.threads[i].state == ThreadState::Dead && self.threads[i].stack_base == 0 {
                return Some(i as ThreadId);
            }
        }
        // Otherwise, allocate a new slot.
        let id = self.next_thread_id;
        if id as usize >= MAX_THREADS {
            return None;
        }
        self.next_thread_id += 1;
        Some(id)
    }

    /// Find a reusable (inactive) task slot, or allocate a new one.
    fn alloc_task_id(&mut self) -> Option<TaskId> {
        // Skip task 0 (kernel task).
        for i in 1..self.next_task_id as usize {
            if !self.tasks[i].active && self.tasks[i].exited && self.tasks[i].reaped {
                return Some(i as TaskId);
            }
        }
        let id = self.next_task_id;
        if id as usize >= MAX_TASKS {
            return None;
        }
        self.next_task_id += 1;
        Some(id)
    }

    fn create_thread(
        &mut self,
        entry: fn() -> !,
        priority: u8,
        quantum: u32,
    ) -> Option<ThreadId> {
        let id = self.alloc_thread_id()?;

        let stack_page = crate::mm::phys::alloc_page()?;
        let stack_base = stack_page.as_usize();
        let stack_top = stack_base + crate::mm::page::PAGE_SIZE;

        // Create a fake exception frame at the top of the stack.
        // When we "return" from the IRQ handler with this thread's SP,
        // restore_regs will load these values and eret/sret to the entry point.
        let frame_sp = stack_top - EXCEPTION_FRAME_SIZE;
        let frame = frame_sp as *mut u64;
        unsafe {
            // Zero the entire frame.
            for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
                *frame.add(i) = 0;
            }

            #[cfg(target_arch = "aarch64")]
            {
                // ELR_EL1 = entry point (offset 256 / 8 = 32).
                *frame.add(32) = entry as *const () as u64;
                // SPSR_EL1 = EL1h (0x5), IRQs enabled (DAIF.I = 0).
                // 0x5 = EL1h mode. We want PSTATE.I = 0 (IRQs unmasked).
                *frame.add(33) = 0x5;
                // ESR_EL1 = 0 (offset 34).
            }

            #[cfg(target_arch = "riscv64")]
            {
                // TrapFrame layout: x1-x31 (31 regs at indices 0..30),
                // sepc at index 31, sstatus at index 32, scause at index 33.
                // sepc = entry point.
                *frame.add(31) = entry as *const () as u64;
                // sstatus: SPP=1 (return to S-mode), SPIE=1 (enable interrupts on sret).
                // SPP = bit 8, SPIE = bit 5.
                *frame.add(32) = (1 << 8) | (1 << 5);
                // scause = 0.
            }

            #[cfg(target_arch = "x86_64")]
            {
                // ExceptionFrame layout (22 u64s):
                //   [0..14]  = r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax
                //   [15]     = vector number
                //   [16]     = error code (dummy)
                //   [17]     = rip (entry point)
                //   [18]     = cs (kernel code segment = 0x08)
                //   [19]     = rflags (interrupts enabled = 0x200)
                //   [20]     = rsp (doesn't matter for kernel threads, set to stack_top)
                //   [21]     = ss (kernel data segment = 0x10)
                *frame.add(17) = entry as *const () as u64;     // RIP
                *frame.add(18) = 0x08;                           // CS = kernel code
                *frame.add(19) = 0x200;                          // RFLAGS = IF (interrupts enabled)
                *frame.add(20) = stack_top as u64;               // RSP
                *frame.add(21) = 0x10;                           // SS = kernel data
            }
        }

        // Clear killed/affinity flags from any previous occupant of this slot.
        KILLED[id as usize].store(false, Ordering::Release);
        AFFINITY_MASK[id as usize].store(u64::MAX, Ordering::Relaxed);
        LAST_CPU[id as usize].store(smp::cpu_id(), Ordering::Relaxed);

        let thread = &mut self.threads[id as usize];
        thread.id = id;
        thread.state = ThreadState::Ready;
        thread.task_id = 0;
        thread.base_priority = priority;
        thread.effective_priority = priority;
        THREAD_PRIO[id as usize].store(priority, Ordering::Relaxed);
        thread.quantum = quantum;
        thread.default_quantum = quantum;
        thread.saved_sp = frame_sp as u64;
        thread.stack_base = stack_base;
        thread.sig_mask = 0;
        thread.sig_pending = 0;

        self.run_queues[priority as usize].push(id);
        Some(id)
    }

}

/// Parent task info snapshot, taken under SCHEDULER lock so that the heavy
/// work phase (ELF loading, page table setup) can run without holding it.
struct SpawnParentInfo {
    parent_task: u32,
    sid: TaskId,
    ctty_port: u64,
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    groups: [u32; MAX_GROUPS],
    ngroups: u32,
    rlimits: [Rlimit; RLIMIT_COUNT],
}

/// Phase 2: do all heavy work (page tables, address space, ELF load, stack,
/// kstack, frame setup, capability grants) WITHOUT holding the SCHEDULER lock.
/// Returns (aspace_id, pt_root, frame_sp, kstack_base) on success.
fn do_spawn_heavy_work(
    task_id: u32,
    _thread_id: ThreadId,
    _parent: &SpawnParentInfo,
    elf_data: &[u8],
    _priority: u8,
    _quantum: u32,
    arg0: u64,
    arg0_is_port: bool,
) -> Option<(u32, usize, u64, usize)> {
    // Create a page table with kernel identity mapping.
    #[cfg(target_arch = "aarch64")]
    let pt_root = crate::arch::aarch64::mm::setup_tables()?;
    #[cfg(target_arch = "riscv64")]
    let pt_root = crate::arch::riscv64::mm::setup_tables()?;
    #[cfg(target_arch = "x86_64")]
    let pt_root = crate::arch::x86_64::mm::create_user_page_table()?;

    // Create address space.
    let aspace_id = crate::mm::aspace::create(pt_root)?;

    // Bootstrap capabilities: grant SEND caps for well-known kernel ports,
    // and full cap for arg0 if it's a valid active port (port passing on spawn).
    {
        let mut caps = crate::cap::CAP_SYSTEM.lock();
        caps.spaces[task_id as usize] = crate::cap::CapSpace::new(task_id);

        let nsrv = crate::io::namesrv::NAMESRV_PORT.load(core::sync::atomic::Ordering::Acquire);
        if nsrv != u64::MAX {
            caps.grant_send_cap(task_id, nsrv);
        }

        let iramfs = crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            caps.grant_send_cap(task_id, iramfs);
        }

        if arg0_is_port {
            caps.grant_full_port_cap(task_id, arg0);
        }
    }

    // Load ELF segments into the address space.
    let elf_info = match crate::loader::elf::load_elf(elf_data, aspace_id, pt_root) {
        Ok(e) => e,
        Err(_) => return None,
    };
    let entry = elf_info.entry;

    // Flush instruction cache.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence.i");
    }

    // Map user stack.
    #[cfg(target_arch = "aarch64")]
    const USER_STACK_TOP: usize = 0x7FFF_F000_0000;
    #[cfg(target_arch = "riscv64")]
    const USER_STACK_TOP: usize = 0x3F_F000_0000;
    #[cfg(target_arch = "x86_64")]
    const USER_STACK_TOP: usize = 0x7FFF_FFFF_0000;

    let stack_pages = 2;
    let stack_va = USER_STACK_TOP - stack_pages * PAGE_SIZE;

    let obj_id = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
        let vma = aspace.map_anon(stack_va, stack_pages, crate::mm::vma::VmaProt::ReadWrite)
            .ok_or(())?;
        Ok::<_, ()>(vma.object_id)
    }).ok()?;

    // Eagerly allocate and map stack pages.
    let mmu_count = PAGE_SIZE / MMUPAGE_SIZE;
    for page_idx in 0..stack_pages {
        let page_va = stack_va + page_idx * PAGE_SIZE;

        let pa = crate::mm::object::with_object(obj_id, |obj| {
            obj.ensure_page(page_idx).map(|(pa, _)| pa)
        })?;
        let pa_usize = pa.as_usize();

        unsafe {
            core::ptr::write_bytes(pa_usize as *mut u8, 0, PAGE_SIZE);
        }

        let sw_z = crate::mm::fault::sw_zeroed_bit();
        #[cfg(target_arch = "aarch64")]
        let pte_flags = crate::arch::aarch64::mm::USER_RW_FLAGS | sw_z;
        #[cfg(target_arch = "riscv64")]
        let pte_flags = crate::arch::riscv64::mm::USER_RW_FLAGS | sw_z;
        #[cfg(target_arch = "x86_64")]
        let pte_flags = crate::arch::x86_64::mm::USER_RW_FLAGS | sw_z;

        for mmu_idx in 0..mmu_count {
            let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
            let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;

            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
        }
    }

    // Allocate kernel stack for this thread.
    let kstack_page = crate::mm::phys::alloc_page()?;
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + PAGE_SIZE;

    // Build a fake exception frame for user-mode entry.
    let frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    let frame = frame_sp as *mut u64;
    unsafe {
        for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
            *frame.add(i) = 0;
        }

        #[cfg(target_arch = "aarch64")]
        {
            *frame.add(32) = entry as u64;           // ELR_EL1
            *frame.add(33) = 0x0;                     // SPSR_EL1 = EL0t
            *frame.add(31) = USER_STACK_TOP as u64;   // SP_EL0
        }

        #[cfg(target_arch = "riscv64")]
        {
            *frame.add(31) = entry as u64;            // sepc
            *frame.add(32) = 1 << 5;                  // sstatus: SPIE=1, SPP=0
            *frame.add(1) = USER_STACK_TOP as u64;    // sp (x2)
        }

        #[cfg(target_arch = "x86_64")]
        {
            *frame.add(17) = entry as u64;                                              // RIP
            *frame.add(18) = (crate::arch::x86_64::gdt::USER_CS as u64) | 3;          // CS
            *frame.add(19) = 0x200;                                                     // RFLAGS = IF
            *frame.add(20) = USER_STACK_TOP as u64;                                     // RSP
            *frame.add(21) = (crate::arch::x86_64::gdt::USER_DS as u64) | 3;          // SS
        }

        // arg0 in first argument register
        #[cfg(target_arch = "aarch64")]
        { *frame.add(0) = arg0; }
        #[cfg(target_arch = "riscv64")]
        { *frame.add(9) = arg0; }
        #[cfg(target_arch = "x86_64")]
        { *frame.add(9) = arg0; }
    }

    Some((aspace_id, pt_root, frame_sp as u64, kstack_base))
}

impl Scheduler {
    /// Phase 1 of user thread creation: allocate task/thread IDs and read parent info.
    /// Must be called under SCHEDULER lock. Returns (task_id, thread_id, parent_info).
    fn alloc_spawn_ids(
        &mut self,
    ) -> Option<(u32, ThreadId, SpawnParentInfo)> {
        let task_id = self.alloc_task_id()?;
        let thread_id = self.alloc_thread_id()?;
        // Read parent info while we have the lock.
        let caller_tid = smp::current().current_thread.load(Ordering::Relaxed);
        let parent_task = self.threads[caller_tid as usize].task_id;
        let pt = parent_task as usize;
        let info = SpawnParentInfo {
            parent_task,
            sid: self.tasks[pt].sid,
            ctty_port: self.tasks[pt].ctty_port,
            uid: self.tasks[pt].uid,
            euid: self.tasks[pt].euid,
            gid: self.tasks[pt].gid,
            egid: self.tasks[pt].egid,
            groups: self.tasks[pt].groups,
            ngroups: self.tasks[pt].ngroups,
            rlimits: self.tasks[pt].rlimits,
        };
        Some((task_id, thread_id, info))
    }

    /// Phase 3 of user thread creation: populate task/thread state and add to run queue.
    /// Must be called under SCHEDULER lock.
    fn finalize_spawn(
        &mut self,
        task_id: u32,
        thread_id: ThreadId,
        parent: &SpawnParentInfo,
        aspace_id: u32,
        pt_root: usize,
        priority: u8,
        quantum: u32,
        frame_sp: u64,
        kstack_base: usize,
    ) {
        let task = &mut self.tasks[task_id as usize];
        task.id = task_id;
        task.active = true;
        task.aspace_id = aspace_id;
        task.page_table_root = pt_root;
        task.exit_code = 0;
        task.exited = false;
        task.reaped = false;
        task.wait_status = 0;
        task.thread_count = 1;
        task.parent_task = parent.parent_task;
        task.pgid = task_id;
        task.sid = parent.sid;
        task.ctty_port = parent.ctty_port;
        task.fg_pgid = 0;
        task.uid = parent.uid;
        task.euid = parent.euid;
        task.gid = parent.gid;
        task.egid = parent.egid;
        task.groups = parent.groups;
        task.ngroups = parent.ngroups;
        task.rlimits = parent.rlimits;

        KILLED[thread_id as usize].store(false, Ordering::Release);
        AFFINITY_MASK[thread_id as usize].store(u64::MAX, Ordering::Relaxed);
        LAST_CPU[thread_id as usize].store(smp::cpu_id(), Ordering::Relaxed);

        let thread = &mut self.threads[thread_id as usize];
        thread.id = thread_id;
        thread.state = ThreadState::Ready;
        thread.task_id = task_id;
        thread.base_priority = priority;
        thread.effective_priority = priority;
        THREAD_PRIO[thread_id as usize].store(priority, Ordering::Relaxed);
        THREAD_TASK[thread_id as usize].store(task_id, Ordering::Relaxed);
        thread.quantum = quantum;
        thread.default_quantum = quantum;
        thread.saved_sp = frame_sp;
        thread.stack_base = kstack_base;
        thread.sig_mask = 0;
        thread.sig_pending = 0;

        self.run_queues[priority as usize].push(thread_id);
    }


    /// Create a new thread in an existing task (shared address space).
    /// The caller provides the user entry point, stack top, and an argument.
    fn create_thread_in_task(
        &mut self,
        task_id: u32,
        entry: u64,
        stack_top: u64,
        arg: u64,
        priority: u8,
        quantum: u32,
    ) -> Option<ThreadId> {
        if !self.tasks[task_id as usize].active {
            return None;
        }

        // Allocate kernel stack.
        let kstack_page = crate::mm::phys::alloc_page()?;
        let kstack_base = kstack_page.as_usize();
        let kstack_top = kstack_base + PAGE_SIZE;

        // Build exception frame for user-mode entry.
        let frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
        let frame = frame_sp as *mut u64;
        unsafe {
            for i in 0..(EXCEPTION_FRAME_SIZE / 8) {
                *frame.add(i) = 0;
            }

            #[cfg(target_arch = "aarch64")]
            {
                *frame.add(32) = entry;          // ELR_EL1
                *frame.add(33) = 0x0;            // SPSR_EL1 = EL0t
                *frame.add(31) = stack_top;      // SP_EL0
            }

            #[cfg(target_arch = "riscv64")]
            {
                *frame.add(31) = entry;          // sepc
                *frame.add(32) = 1 << 5;         // sstatus: SPIE=1, SPP=0
                *frame.add(1) = stack_top;       // sp (x2)
            }

            #[cfg(target_arch = "x86_64")]
            {
                *frame.add(17) = entry;                                              // RIP
                *frame.add(18) = (crate::arch::x86_64::gdt::USER_CS as u64) | 3;   // CS
                *frame.add(19) = 0x200;                                              // RFLAGS = IF
                *frame.add(20) = stack_top;                                          // RSP
                *frame.add(21) = (crate::arch::x86_64::gdt::USER_DS as u64) | 3;   // SS
            }

            // arg in first argument register
            #[cfg(target_arch = "aarch64")]
            { *frame.add(0) = arg; } // x0
            #[cfg(target_arch = "riscv64")]
            { *frame.add(9) = arg; } // a0 = x10
            #[cfg(target_arch = "x86_64")]
            { *frame.add(9) = arg; } // rdi
        }

        let id = self.alloc_thread_id()?;

        // Clear killed/affinity flags from any previous occupant of this slot.
        KILLED[id as usize].store(false, Ordering::Release);
        AFFINITY_MASK[id as usize].store(u64::MAX, Ordering::Relaxed);
        LAST_CPU[id as usize].store(smp::cpu_id(), Ordering::Relaxed);

        let thread = &mut self.threads[id as usize];
        thread.id = id;
        thread.state = ThreadState::Ready;
        thread.task_id = task_id;
        thread.base_priority = priority;
        thread.effective_priority = priority;
        THREAD_PRIO[id as usize].store(priority, Ordering::Relaxed);
        THREAD_TASK[id as usize].store(task_id, Ordering::Relaxed);
        thread.quantum = quantum;
        thread.default_quantum = quantum;
        thread.saved_sp = frame_sp as u64;
        thread.stack_base = kstack_base;
        thread.exit_code = 0;
        thread.sig_mask = 0;
        thread.sig_pending = 0;

        self.tasks[task_id as usize].thread_count += 1;
        self.run_queues[priority as usize].push(id);
        Some(id)
    }


    fn pick_next(&mut self, idle_id: ThreadId) -> ThreadId {
        let cpu = smp::cpu_id();
        for prio in 0..NUM_PRIORITIES {
            if let Some(id) = self.run_queues[prio].find_remove_for_cpu(cpu) {
                return id;
            }
        }
        idle_id
    }

    fn timer_tick_for(&mut self, current: ThreadId, idle_id: ThreadId) -> bool {
        if current == idle_id {
            return self.has_ready_threads();
        }
        // If the thread is spinning in block_current, preempt immediately
        // so other threads can run. Don't consume quantum — the thread
        // will need it when it actually gets woken up.
        if YIELD_ASAP[current as usize].load(Ordering::Acquire) {
            return true;
        }
        let thread = &mut self.threads[current as usize];
        thread.quantum = thread.quantum.saturating_sub(1);
        if thread.quantum == 0 {
            thread.quantum = thread.default_quantum;
            return true;
        }
        false
    }

    fn has_ready_threads(&self) -> bool {
        for prio in 0..NUM_PRIORITIES {
            if self.run_queues[prio].len > 0 {
                return true;
            }
        }
        false
    }

    /// Attempt to switch threads on the current CPU.
    /// Called from IRQ handler with current SP.
    /// Returns the new SP to use for restore_regs.
    fn try_switch(&mut self, current_sp: u64) -> u64 {
        // Update per-CPU load tracking for energy-aware scheduling.
        let cpu = smp::cpu_id();
        let pcpu = smp::get(cpu);
        let idle_id_for_load = pcpu.idle_thread_id.load(Ordering::Relaxed);
        let cur_for_load = pcpu.current_thread.load(Ordering::Relaxed);
        super::hotplug::tick_load(cpu, cur_for_load == idle_id_for_load);

        // Drain deferred kernel stack free from a previous exit on this CPU.
        // IMPORTANT: We must NOT free the page if it belongs to the currently
        // running thread (a dead thread spinning in exit_current_thread).
        // The timer IRQ's exception frame and the entire try_switch() call
        // chain live on that stack — freeing it while another CPU can
        // reallocate it causes use-after-free (corrupted return addresses,
        // manifesting as EC=0x22 PC alignment faults with ELR=0x9 etc.).
        // In that case, leave it in DEFERRED_KSTACK for the next tick when
        // we'll be running on the new thread's stack.
        let deferred = DEFERRED_KSTACK[cpu as usize].load(Ordering::Acquire);
        if deferred != 0 {
            let cur_tid = pcpu.current_thread.load(Ordering::Relaxed);
            if self.threads[cur_tid as usize].stack_base != deferred {
                // Safe: we're on a different thread's stack.
                DEFERRED_KSTACK[cpu as usize].store(0, Ordering::Release);
                crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(deferred));
                let dead_tid = DEFERRED_THREAD[cpu as usize].swap(usize::MAX, Ordering::AcqRel);
                if dead_tid < MAX_THREADS {
                    self.threads[dead_tid].stack_base = 0;
                }
            }
        }

        let pcpu = smp::current();
        let prev_id = pcpu.current_thread.load(Ordering::Relaxed);
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

        if !self.timer_tick_for(prev_id, idle_id) {
            return current_sp; // No preemption needed.
        }

        // The yield/block request has been honoured — clear the flag so the
        // thread gets its full quantum next time it runs.  Without this,
        // sys_yield()/sys_yield_block() leave YIELD_ASAP permanently set,
        // causing the thread to be preempted on every single tick.  On
        // QEMU TCG that maximises lock-holder preemption on userspace
        // spinlocks and leads to intermittent hangs (Phase 30/31).
        YIELD_ASAP[prev_id as usize].store(false, Ordering::Release);

        // Cosched-aware pick: if prev has a group, try to find a group mate
        // that can also run on this CPU.
        let cpu = smp::cpu_id();
        let prev_group = COSCHED_GROUP[prev_id as usize].load(Ordering::Relaxed);
        let next_id = if prev_group != 0 && self.cosched_burst < MAX_COSCHED_BURST {
            // Search all priority levels for a group mate eligible for this CPU.
            let mut mate = None;
            for prio in 0..NUM_PRIORITIES {
                if let Some(id) = self.run_queues[prio].find_remove_by_group_for_cpu(prev_group, cpu) {
                    mate = Some(id);
                    break;
                }
            }
            if let Some(id) = mate {
                self.cosched_burst += 1;
                COSCHED_HITS.fetch_add(1, Ordering::Relaxed);
                id
            } else {
                self.cosched_burst = 0;
                self.pick_next(idle_id)
            }
        } else {
            self.cosched_burst = 0;
            self.pick_next(idle_id)
        };

        if prev_id == next_id {
            return current_sp;
        }

        crate::sched::stats::CONTEXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
        crate::trace::trace_event(crate::trace::EVT_CTX_SWITCH, prev_id, next_id);

        // Save current thread's SP.
        self.threads[prev_id as usize].saved_sp = current_sp;
        let prev_prio = self.threads[prev_id as usize].effective_priority;
        // Don't re-enqueue Dead threads (they are exiting).
        if prev_id != idle_id && self.threads[prev_id as usize].state != ThreadState::Dead {
            self.threads[prev_id as usize].state = ThreadState::Ready;
            self.run_queues[prev_prio as usize].push(prev_id);
        }

        // Switch page tables if crossing task boundaries.
        let prev_task = self.threads[prev_id as usize].task_id;
        let next_task = self.threads[next_id as usize].task_id;
        if prev_task != next_task {
            let next_root = self.tasks[next_task as usize].page_table_root;
            if next_root != 0 {
                #[cfg(target_arch = "aarch64")]
                crate::arch::aarch64::mm::switch_page_table(next_root);
                #[cfg(target_arch = "riscv64")]
                crate::arch::riscv64::mm::switch_page_table(next_root);
                #[cfg(target_arch = "x86_64")]
                crate::arch::x86_64::mm::switch_page_table(next_root);
            } else {
                // Switching to kernel task: restore kernel page table.
                #[cfg(target_arch = "riscv64")]
                {
                    let kern_root = crate::arch::riscv64::mm::kernel_pt_root();
                    if kern_root != 0 {
                        crate::arch::riscv64::mm::switch_page_table(kern_root);
                    }
                }
            }
        }

        // On x86-64, update TSS RSP0 for ring 3→0 transitions.
        #[cfg(target_arch = "x86_64")]
        {
            let next_kstack_top = self.threads[next_id as usize].stack_base + PAGE_SIZE;
            crate::arch::x86_64::gdt::set_rsp0(next_kstack_top as u64);
        }

        // Load next thread's SP.
        self.threads[next_id as usize].state = ThreadState::Running;
        pcpu.current_thread.store(next_id, Ordering::Relaxed);
        LAST_CPU[next_id as usize].store(cpu, Ordering::Relaxed);
        self.threads[next_id as usize].saved_sp
    }
}

pub static SCHEDULER: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

pub fn init() {
    let mut sched = SCHEDULER.lock();
    sched.init();
    let idle_id = 0; // Thread 0 = BSP idle
    drop(sched);

    smp::init_bsp(idle_id);
    super::hotplug::mark_online(0);
    crate::println!("  Scheduler initialized (BSP = CPU 0)");
}

/// Called by secondary CPUs to create their idle thread and register.
pub fn init_ap(cpu: u32) {
    let idle_id = {
        let mut sched = SCHEDULER.lock();
        sched.create_idle_thread().expect("AP idle thread")
    };
    smp::init_ap(cpu, idle_id);
    super::hotplug::mark_online(cpu);
    crate::println!("  CPU {} scheduler ready (idle thread {})", cpu, idle_id);
}

/// Get the task ID for a given thread.
pub fn thread_task_id(tid: ThreadId) -> u32 {
    SCHEDULER.lock().threads[tid as usize].task_id
}

pub fn spawn(entry: fn() -> !, priority: u8, quantum: u32) -> Option<ThreadId> {
    SCHEDULER.lock().create_thread(entry, priority, quantum)
}

/// Spawn a new user-mode process from an ELF binary in the initramfs.
/// Creates a new task with its own address space. `arg0` is passed to main().
///
/// Uses a 3-phase lock split to avoid ABBA deadlock between SCHEDULER and
/// PORT_TABLE: phase 1 (alloc IDs) and phase 3 (finalize) hold SCHEDULER,
/// but phase 2 (ELF loading, page table setup) runs without it.
pub fn spawn_user(elf_name: &[u8], priority: u8, quantum: u32, arg0: u64) -> Option<ThreadId> {
    // Check port_is_active BEFORE locking SCHEDULER to avoid ABBA deadlock.
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    // Look up the ELF binary (no locks needed).
    let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

    // Phase 1: allocate IDs under SCHEDULER lock.
    let (task_id, thread_id, parent) = SCHEDULER.lock().alloc_spawn_ids()?;

    // Phase 2: heavy work (page tables, ELF load, etc.) WITHOUT SCHEDULER lock.
    let (aspace_id, pt_root, frame_sp, kstack_base) =
        do_spawn_heavy_work(task_id, thread_id, &parent, elf_data, priority, quantum, arg0, arg0_is_port)?;

    // Phase 3: finalize task/thread state under SCHEDULER lock.
    SCHEDULER.lock().finalize_spawn(
        task_id, thread_id, &parent, aspace_id, pt_root, priority, quantum, frame_sp, kstack_base,
    );
    Some(thread_id)
}

/// Spawn a new user-mode process from ELF data already in kernel memory.
pub fn spawn_user_from_elf(elf_data: &[u8], priority: u8, quantum: u32, arg0: u64) -> Option<ThreadId> {
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    let (task_id, thread_id, parent) = SCHEDULER.lock().alloc_spawn_ids()?;

    let (aspace_id, pt_root, frame_sp, kstack_base) =
        do_spawn_heavy_work(task_id, thread_id, &parent, elf_data, priority, quantum, arg0, arg0_is_port)?;

    SCHEDULER.lock().finalize_spawn(
        task_id, thread_id, &parent, aspace_id, pt_root, priority, quantum, frame_sp, kstack_base,
    );
    Some(thread_id)
}

/// Spawn a user-mode process with data mapped into its address space.
/// Sets arg0, arg1=data_va, arg2=data_len in the child's initial frame.
pub fn spawn_user_with_data(
    elf_name: &[u8],
    priority: u8,
    quantum: u32,
    data: &[u8],
    data_va: usize,
    arg0: u64,
) -> Option<ThreadId> {
    let arg0_is_port = arg0 > 0 && crate::ipc::port::port_is_active(arg0);

    let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

    let (task_id, thread_id, parent) = SCHEDULER.lock().alloc_spawn_ids()?;

    // Phase 2: ELF load + stack setup WITHOUT SCHEDULER lock.
    let (aspace_id, pt_root, frame_sp, kstack_base) =
        do_spawn_heavy_work(task_id, thread_id, &parent, elf_data, priority, quantum, arg0, arg0_is_port)?;

    // Map data pages into the child's address space (still no SCHEDULER lock).
    let data_pages = (data.len() + PAGE_SIZE - 1) / PAGE_SIZE;
    if data_pages > 0 {
        let obj_id = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
            let vma = aspace.map_anon(data_va, data_pages, crate::mm::vma::VmaProt::ReadOnly)
                .ok_or(())?;
            Ok::<_, ()>(vma.object_id)
        }).ok()?;

        let mmu_count = PAGE_SIZE / MMUPAGE_SIZE;
        let sw_z = crate::mm::fault::sw_zeroed_bit();
        #[cfg(target_arch = "aarch64")]
        let pte_flags = crate::arch::aarch64::mm::USER_RO_FLAGS | sw_z;
        #[cfg(target_arch = "riscv64")]
        let pte_flags = crate::arch::riscv64::mm::USER_RO_FLAGS | sw_z;
        #[cfg(target_arch = "x86_64")]
        let pte_flags = crate::arch::x86_64::mm::USER_RO_FLAGS | sw_z;

        for page_idx in 0..data_pages {
            let page_va = data_va + page_idx * PAGE_SIZE;
            let pa = crate::mm::object::with_object(obj_id, |obj| {
                obj.ensure_page(page_idx).map(|(pa, _)| pa)
            })?;
            let pa_usize = pa.as_usize();

            unsafe {
                core::ptr::write_bytes(pa_usize as *mut u8, 0, PAGE_SIZE);
                let copy_start = page_idx * PAGE_SIZE;
                let copy_end = (copy_start + PAGE_SIZE).min(data.len());
                if copy_start < data.len() {
                    core::ptr::copy_nonoverlapping(
                        data[copy_start..copy_end].as_ptr(),
                        pa_usize as *mut u8,
                        copy_end - copy_start,
                    );
                }
            }

            for mmu_idx in 0..mmu_count {
                let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
                let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;
                #[cfg(target_arch = "aarch64")]
                crate::arch::aarch64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
                #[cfg(target_arch = "riscv64")]
                crate::arch::riscv64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
                #[cfg(target_arch = "x86_64")]
                crate::arch::x86_64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, pte_flags);
            }
        }
    }

    // Set arg1 = data_va, arg2 = data_len in the thread's exception frame.
    let frame = frame_sp as *mut u64;
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            *frame.add(1) = data_va as u64;
            *frame.add(2) = data.len() as u64;
        }
        #[cfg(target_arch = "riscv64")]
        {
            *frame.add(10) = data_va as u64;
            *frame.add(11) = data.len() as u64;
        }
        #[cfg(target_arch = "x86_64")]
        {
            *frame.add(10) = data_va as u64;
            *frame.add(11) = data.len() as u64;
        }
    }

    // Phase 3: finalize under SCHEDULER lock.
    SCHEDULER.lock().finalize_spawn(
        task_id, thread_id, &parent, aspace_id, pt_root, priority, quantum, frame_sp, kstack_base,
    );
    Some(thread_id)
}

/// Create a new thread in the caller's task. Returns thread ID or None.
pub fn thread_create(task_id: u32, entry: u64, stack_top: u64, arg: u64) -> Option<ThreadId> {
    let mut sched = SCHEDULER.lock();
    // Inherit the caller's priority and quantum.
    let caller_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let priority = sched.threads[caller_tid as usize].base_priority;
    let quantum = sched.threads[caller_tid as usize].default_quantum;
    sched.create_thread_in_task(task_id, entry, stack_top, arg, priority, quantum)
}

/// Check if a thread has exited and return its exit code.
/// Returns Some(exit_code) if dead and in the same task, None otherwise.
pub fn thread_join_poll(tid: ThreadId, caller_task: u32) -> Option<i32> {
    let sched = SCHEDULER.lock();
    if (tid as usize) >= MAX_THREADS {
        return None;
    }
    let t = &sched.threads[tid as usize];
    if t.task_id != caller_task {
        return None;
    }
    if t.state == ThreadState::Dead {
        Some(t.exit_code)
    } else {
        None
    }
}

/// Blocking thread_join: if target is already dead return its exit code,
/// otherwise register as waiter and block until it exits.
pub fn thread_join_block(tid: ThreadId, caller_task: u32) -> u64 {
    {
        let mut sched = SCHEDULER.lock();
        if (tid as usize) >= MAX_THREADS {
            return u64::MAX;
        }
        let t = &sched.threads[tid as usize];
        if t.task_id != caller_task {
            return u64::MAX;
        }
        if t.state == ThreadState::Dead {
            return t.exit_code as u64;
        }
        // Register ourselves as the join waiter.
        let caller_tid = current_thread_id();
        sched.threads[tid as usize].join_waiter = caller_tid;
        // Clear wakeup flag before blocking.
        WAKEUP_FLAGS[caller_tid as usize].store(false, Ordering::Release);
    }
    // Block until the target thread wakes us via exit_current_thread.
    block_current(BlockReason::FutexWait);
    // Re-read exit code.
    let sched = SCHEDULER.lock();
    sched.threads[tid as usize].exit_code as u64
}

/// Get the task ID of the current thread.
#[allow(dead_code)]
pub fn current_task_id() -> TaskId {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    THREAD_TASK[tid as usize].load(core::sync::atomic::Ordering::Relaxed)
}

/// Get the page table root of the current thread's task.
#[allow(dead_code)]
pub fn current_page_table_root() -> usize {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    let task_id = sched.threads[tid as usize].task_id;
    sched.tasks[task_id as usize].page_table_root
}

/// Called from the timer IRQ handler. Takes the current kernel SP
/// (pointing to the saved exception frame). Returns the SP to use
/// for restore_regs — either the same SP (no switch) or a different
/// thread's SP (preemption).
pub fn tick(current_sp: u64) -> u64 {
    check_sleep_timers();
    check_alarm_timers();
    check_interval_timers();
    SCHEDULER.lock().try_switch(current_sp)
}

/// Voluntarily yield. Not usable from IRQ context.
#[allow(dead_code)]
pub fn schedule() {
    // For voluntary yield, we would need to save our own context and switch.
    // This is more complex and will be implemented later.
}

/// Per-thread wakeup flags. Set by wake_thread(), checked by block_current().
/// Using atomics avoids needing the scheduler lock in the spin loop.
static WAKEUP_FLAGS: [core::sync::atomic::AtomicBool; super::thread::MAX_THREADS] = {
    const INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [INIT; super::thread::MAX_THREADS]
};

/// Per-thread effective priority, readable without the scheduler lock.
/// Updated by boost_priority/reset_priority and thread creation.
static THREAD_PRIO: [core::sync::atomic::AtomicU8; super::thread::MAX_THREADS] = {
    const INIT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(255);
    [INIT; super::thread::MAX_THREADS]
};

/// Per-thread task_id, readable without the scheduler lock.
/// Updated on thread creation.
static THREAD_TASK: [core::sync::atomic::AtomicU32; super::thread::MAX_THREADS] = {
    const INIT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    [INIT; super::thread::MAX_THREADS]
};

/// Per-thread yield-ASAP flag. When set, `timer_tick_for` will force
/// preemption on the very next timer tick instead of waiting for the
/// full quantum to expire. This prevents spinning threads in
/// `block_current` from starving real work on SMP.
static YIELD_ASAP: [core::sync::atomic::AtomicBool; super::thread::MAX_THREADS] = {
    const INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [INIT; super::thread::MAX_THREADS]
};

/// Per-thread killed flag. When set, block_current() exits early and the
/// syscall return path calls exit_current_thread(-9).
static KILLED: [core::sync::atomic::AtomicBool; super::thread::MAX_THREADS] = {
    const INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [INIT; super::thread::MAX_THREADS]
};

// --- Coscheduling ---

/// Per-thread coscheduling group ID (0 = no group).
static COSCHED_GROUP: [AtomicU32; MAX_THREADS] = {
    const INIT: AtomicU32 = AtomicU32::new(0);
    [INIT; MAX_THREADS]
};

/// Maximum consecutive cosched picks before yielding to other threads.
const MAX_COSCHED_BURST: u32 = 4;

/// Count of coscheduling hits (for testing/diagnostics).
pub static COSCHED_HITS: AtomicU64 = AtomicU64::new(0);

/// Per-thread CPU affinity bitmask. Default u64::MAX = all CPUs allowed.
static AFFINITY_MASK: [AtomicU64; MAX_THREADS] = {
    const INIT: AtomicU64 = AtomicU64::new(u64::MAX);
    [INIT; MAX_THREADS]
};

/// Per-thread last CPU the thread ran on.
static LAST_CPU: [AtomicU32; MAX_THREADS] = {
    const INIT: AtomicU32 = AtomicU32::new(0);
    [INIT; MAX_THREADS]
};

// --- Scheduler Activations ---

/// Per-task SA pending flag: true when an activation event is ready.
static SA_PENDING: [core::sync::atomic::AtomicBool; MAX_TASKS] = {
    const INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [INIT; MAX_TASKS]
};

/// Per-task SA event data: packed (blocked_tid as u64).
static SA_EVENT: [AtomicU64; MAX_TASKS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_TASKS]
};

/// Per-task SA waiter thread ID (u32::MAX = no waiter).
static SA_WAITER: [core::sync::atomic::AtomicU32; MAX_TASKS] = {
    const INIT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(u32::MAX);
    [INIT; MAX_TASKS]
};

/// Set YIELD_ASAP for a thread, causing it to be preempted on the next timer tick.
pub fn set_yield_asap(tid: ThreadId) {
    YIELD_ASAP[tid as usize].store(true, Ordering::Release);
}

/// Clear the wakeup flag for a thread. Must be called while holding the
/// relevant lock (PORT_TABLE etc.) BEFORE adding the thread as a waiter,
/// to prevent a lost-wakeup race where wake_thread() sets the flag between
/// the lock drop and block_current's flag clear.
pub fn clear_wakeup_flag(tid: ThreadId) {
    WAKEUP_FLAGS[tid as usize].store(false, Ordering::Release);
}

/// Block the current thread with the given reason.
/// The thread will be preempted on the next timer tick and will not
/// be re-enqueued until `wake_thread()` is called.
///
/// IMPORTANT: The caller must call `clear_wakeup_flag(tid)` while holding
/// the relevant lock, BEFORE adding itself as a waiter and dropping the lock.
pub fn block_current(_reason: BlockReason) {
    let tid = current_thread_id();
    // Demote effective_priority to 254 (lowest non-idle) so try_switch
    // re-enqueues us at the bottom. This prevents blocked-spinning threads
    // from starving lower-priority threads on single-CPU.
    let saved_prio = {
        let mut sched = SCHEDULER.lock();
        let orig = sched.threads[tid as usize].effective_priority;
        sched.threads[tid as usize].effective_priority = 254;
        orig
    };
    THREAD_PRIO[tid as usize].store(254, Ordering::Release);
    // Signal the scheduler to preempt us on the next timer tick instead of
    // waiting for the full quantum. This prevents spinning threads from
    // starving real work on SMP systems.
    YIELD_ASAP[tid as usize].store(true, Ordering::Release);
    // Enable interrupts so the timer can preempt us while we spin.
    // This is critical when called from a syscall handler (SVC/ecall/int),
    // because hardware masks IRQs on exception entry.
    let saved = arch_save_and_enable_irqs();
    // Spin until the wakeup flag is set. The thread stays Running and
    // gets preempted normally by timer ticks (quantum-based). This avoids
    // a race where wake_thread() re-enqueues a Blocked thread that's still
    // executing on its CPU, causing double-scheduling on SMP.
    while !WAKEUP_FLAGS[tid as usize].load(Ordering::Acquire) {
        // Check if this thread was killed — break out immediately.
        if KILLED[tid as usize].load(Ordering::Acquire) {
            break;
        }
        // Use WFI to wait for the next interrupt (timer tick or device IRQ).
        // This is critical on QEMU TCG: spin_loop() keeps the vCPU busy,
        // starving QEMU's I/O thread from processing virtio requests.
        // WFI causes the vCPU to pause until an interrupt arrives.
        arch_wait_for_interrupt();
        // Re-arm: try_switch() clears YIELD_ASAP when it preempts us,
        // but we need it set again so the *next* tick also preempts
        // immediately (we're still blocked, not doing useful work).
        YIELD_ASAP[tid as usize].store(true, Ordering::Release);
    }
    YIELD_ASAP[tid as usize].store(false, Ordering::Release);
    // Restore effective priority.
    {
        let mut sched = SCHEDULER.lock();
        sched.threads[tid as usize].effective_priority = saved_prio;
    }
    THREAD_PRIO[tid as usize].store(saved_prio, Ordering::Release);
    arch_restore_irqs(saved);
}

/// Wake a blocked thread, making it runnable.
pub fn wake_thread(tid: ThreadId) {
    WAKEUP_FLAGS[tid as usize].store(true, Ordering::Release);
    // Signal all CPUs so any core spinning in block_current's WFE wakes immediately.
    arch_send_event();
}

/// Check if a thread has been marked for kill.
pub fn is_killed(tid: ThreadId) -> bool {
    KILLED[tid as usize].load(Ordering::Acquire)
}

/// Kill all threads in the task that `tid` belongs to.
/// Returns true if the thread was found and the kill signal was sent.
pub fn kill_task(tid: ThreadId) -> bool {
    if tid as usize >= MAX_THREADS {
        return false;
    }
    let sched = SCHEDULER.lock();
    let target_thread = &sched.threads[tid as usize];
    if target_thread.state == ThreadState::Dead && target_thread.stack_base == 0 {
        return false; // Slot not in use.
    }
    let task_id = target_thread.task_id;
    // Kill all non-dead threads in this task.
    for i in 0..MAX_THREADS {
        let t = &sched.threads[i];
        if t.task_id == task_id && t.state != ThreadState::Dead && t.stack_base != 0 {
            KILLED[i].store(true, Ordering::Release);
        }
    }
    drop(sched);
    // Wake all killed threads so they exit block_current spin loops.
    for i in 0..MAX_THREADS {
        if KILLED[i].load(Ordering::Relaxed) {
            wake_thread(i as ThreadId);
        }
    }
    true
}

/// Send a signal to a task (process-directed). Queues on the first
/// thread in the task that has the signal unmasked, or the first thread.
/// SIGKILL always uses the old kill path (immediate termination).
pub fn send_signal_to_task(task_id: u32, sig: u32) -> bool {
    use super::task::{sig_bit, SIGKILL, SIGSTOP, UNCATCHABLE, MAX_SIGNALS};
    if sig < 1 || sig > MAX_SIGNALS as u32 { return false; }
    if sig == SIGKILL {
        // Use existing kill path for SIGKILL.
        let sched = SCHEDULER.lock();
        // Find any thread in this task.
        for i in 0..MAX_THREADS {
            let t = &sched.threads[i];
            if t.task_id == task_id && t.state != ThreadState::Dead && t.stack_base != 0 {
                drop(sched);
                return kill_task(i as ThreadId);
            }
        }
        return false;
    }

    let bit = sig_bit(sig);
    let mut sched = SCHEDULER.lock();

    // Check handler disposition.
    if (task_id as usize) < super::task::MAX_TASKS {
        let task = &sched.tasks[task_id as usize];
        if !task.active { return false; }
        let action = &task.sig_actions[(sig - 1) as usize];
        // If ignored (and not uncatchable), drop the signal.
        if action.handler == super::task::SigHandler::Ignore {
            return true; // accepted but ignored
        }
        // If default and default is ignore, drop it.
        if action.handler == super::task::SigHandler::Default
            && !super::task::sig_default_is_term(sig)
        {
            return true;
        }
    }

    // Find a thread to receive: prefer one with signal unmasked.
    let mut target: Option<usize> = None;
    let mut any_thread: Option<usize> = None;
    for i in 0..sched.next_thread_id as usize {
        let t = &sched.threads[i];
        if t.task_id == task_id && t.state != ThreadState::Dead && t.stack_base != 0 {
            if any_thread.is_none() { any_thread = Some(i); }
            if t.sig_mask & bit == 0 {
                target = Some(i);
                break;
            }
        }
    }
    let tid = match target.or(any_thread) {
        Some(t) => t,
        None => return false,
    };

    sched.threads[tid].sig_pending |= bit;
    drop(sched);

    // Wake the target thread so it can deliver the signal.
    wake_thread(tid as ThreadId);
    true
}

/// Send a signal to a specific thread.
pub fn send_signal_to_thread(tid: ThreadId, sig: u32) -> bool {
    use super::task::{sig_bit, SIGKILL, MAX_SIGNALS};
    if sig < 1 || sig > MAX_SIGNALS as u32 { return false; }
    if tid as usize >= MAX_THREADS { return false; }
    if sig == SIGKILL {
        return kill_task(tid);
    }

    let bit = sig_bit(sig);
    let mut sched = SCHEDULER.lock();
    let t = &mut sched.threads[tid as usize];
    if t.state == ThreadState::Dead || t.stack_base == 0 { return false; }
    t.sig_pending |= bit;
    drop(sched);
    wake_thread(tid);
    true
}

/// Get and clear the next deliverable signal for the current thread.
/// Returns Some(signal_number) if there's a pending, unmasked signal.
pub fn dequeue_signal() -> Option<u32> {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let t = &mut sched.threads[tid as usize];
    let deliverable = t.sig_pending & !t.sig_mask;
    if deliverable == 0 { return None; }
    // Find lowest-numbered signal.
    let bit_idx = deliverable.trailing_zeros();
    let sig = bit_idx + 1;
    t.sig_pending &= !(1u64 << bit_idx);
    Some(sig)
}

/// Get the signal action for a signal in the current thread's task.
pub fn get_signal_action(sig: u32) -> Option<super::task::SignalAction> {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    let task_id = sched.threads[tid as usize].task_id;
    let task = &sched.tasks[task_id as usize];
    if sig < 1 || sig > super::task::MAX_SIGNALS as u32 { return None; }
    Some(task.sig_actions[(sig - 1) as usize])
}

/// Set signal action for the current task. Returns previous action.
pub fn set_signal_action(sig: u32, action: super::task::SignalAction) -> Option<super::task::SignalAction> {
    use super::task::{UNCATCHABLE, MAX_SIGNALS, sig_bit};
    if sig < 1 || sig > MAX_SIGNALS as u32 { return None; }
    if sig_bit(sig) & UNCATCHABLE != 0 { return None; } // can't change SIGKILL/SIGSTOP
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let task_id = sched.threads[tid as usize].task_id;
    let old = sched.tasks[task_id as usize].sig_actions[(sig - 1) as usize];
    sched.tasks[task_id as usize].sig_actions[(sig - 1) as usize] = action;
    Some(old)
}

/// Set the signal mask for the current thread. Returns old mask.
pub fn set_signal_mask(new_mask: u64) -> u64 {
    use super::task::UNCATCHABLE;
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let old = sched.threads[tid as usize].sig_mask;
    // Cannot mask SIGKILL or SIGSTOP.
    sched.threads[tid as usize].sig_mask = new_mask & !UNCATCHABLE;
    old
}

/// Get the signal mask for the current thread.
pub fn get_signal_mask() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    sched.threads[tid as usize].sig_mask
}

/// Get the pending signal set for the current thread.
pub fn get_signal_pending() -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    sched.threads[tid as usize].sig_pending
}

// --- Phase 43: Process groups, sessions, controlling terminals ---

/// Set the process group ID of a task.
/// pid=0 means current task. pgid=0 means set pgid=pid.
/// Returns 0 on success, u64::MAX on error.
pub fn setpgid(pid: u32, pgid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let my_task = sched.threads[my_tid as usize].task_id;

    let target_task = if pid == 0 { my_task } else { pid };

    if target_task as usize >= super::task::MAX_TASKS { return u64::MAX; }
    if !sched.tasks[target_task as usize].active { return u64::MAX; }
    if target_task != my_task && sched.tasks[target_task as usize].parent_task != my_task {
        return u64::MAX;
    }

    let new_pgid = if pgid == 0 { target_task } else { pgid };
    let target_sid = sched.tasks[target_task as usize].sid;

    if new_pgid != target_task {
        let mut found = false;
        for i in 0..super::task::MAX_TASKS {
            if sched.tasks[i].active && sched.tasks[i].sid == target_sid && sched.tasks[i].pgid == new_pgid {
                found = true;
                break;
            }
        }
        if !found { return u64::MAX; }
    }

    sched.tasks[target_task as usize].pgid = new_pgid;
    0
}

/// Get the process group ID of a task.
/// pid=0 means current task.
pub fn getpgid(pid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    let target_task = if pid == 0 {
        sched.threads[my_tid as usize].task_id
    } else {
        pid
    };
    if target_task as usize >= super::task::MAX_TASKS { return u64::MAX; }
    let task = &sched.tasks[target_task as usize];
    if !task.active { return u64::MAX; }
    task.pgid as u64
}

/// Create a new session. The calling task becomes the session leader.
/// Returns the new session ID (= task_id) or u64::MAX on error.
pub fn setsid() -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let my_task = sched.threads[my_tid as usize].task_id;

    let current_pgid = sched.tasks[my_task as usize].pgid;
    if current_pgid == my_task {
        for i in 0..super::task::MAX_TASKS {
            if sched.tasks[i].active && sched.tasks[i].id != my_task && sched.tasks[i].pgid == my_task {
                return u64::MAX;
            }
        }
    }

    sched.tasks[my_task as usize].sid = my_task;
    sched.tasks[my_task as usize].pgid = my_task;
    sched.tasks[my_task as usize].ctty_port = 0;
    my_task as u64
}

/// Get the session ID of a task.
/// pid=0 means current task.
pub fn getsid(pid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    let target_task = if pid == 0 {
        sched.threads[my_tid as usize].task_id
    } else {
        pid
    };
    if target_task as usize >= super::task::MAX_TASKS { return u64::MAX; }
    let task = &sched.tasks[target_task as usize];
    if !task.active { return u64::MAX; }
    task.sid as u64
}

/// Set the foreground process group for the controlling terminal.
/// The caller must be in the same session as the ctty.
pub fn tcsetpgrp(pgid: u32) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let my_task = sched.threads[my_tid as usize].task_id;

    if sched.tasks[my_task as usize].ctty_port == 0 { return u64::MAX; }

    let my_sid = sched.tasks[my_task as usize].sid;
    let mut found = false;
    for i in 0..super::task::MAX_TASKS {
        if sched.tasks[i].active && sched.tasks[i].sid == my_sid && sched.tasks[i].pgid == pgid {
            found = true;
            break;
        }
    }
    if !found { return u64::MAX; }

    // Store the foreground pgid in the session leader.
    for i in 0..super::task::MAX_TASKS {
        if sched.tasks[i].active && sched.tasks[i].id == my_sid {
            sched.tasks[i].fg_pgid = pgid;
            return 0;
        }
    }
    u64::MAX
}

/// Get the foreground process group for the controlling terminal.
pub fn tcgetpgrp() -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    let my_task = sched.threads[my_tid as usize].task_id;

    if sched.tasks[my_task as usize].ctty_port == 0 { return u64::MAX; }

    let my_sid = sched.tasks[my_task as usize].sid;
    for i in 0..super::task::MAX_TASKS {
        if sched.tasks[i].active && sched.tasks[i].id == my_sid {
            return sched.tasks[i].fg_pgid as u64;
        }
    }
    u64::MAX
}

/// Send a signal to all tasks in a process group.
pub fn send_signal_to_pgroup(pgid: u32, sig: u32) -> bool {
    use super::task::MAX_SIGNALS;
    if sig < 1 || sig > MAX_SIGNALS as u32 { return false; }

    let sched = SCHEDULER.lock();
    let mut task_ids = [0u32; super::task::MAX_TASKS];
    let mut count = 0;
    for i in 0..super::task::MAX_TASKS {
        if sched.tasks[i].active && sched.tasks[i].pgid == pgid && count < task_ids.len() {
            task_ids[count] = sched.tasks[i].id;
            count += 1;
        }
    }
    drop(sched);

    if count == 0 { return false; }

    let mut any = false;
    for i in 0..count {
        if send_signal_to_task(task_ids[i], sig) {
            any = true;
        }
    }
    any
}

/// Set the controlling terminal for the current session.
/// Only the session leader can do this, and only if it has no ctty yet.
pub fn set_ctty(port: u64) -> u64 {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let my_task = sched.threads[my_tid as usize].task_id;

    // Must be session leader.
    if sched.tasks[my_task as usize].sid != my_task {
        return u64::MAX;
    }
    // Must not already have a ctty.
    if sched.tasks[my_task as usize].ctty_port != 0 {
        return u64::MAX;
    }

    sched.tasks[my_task as usize].ctty_port = port;

    // Propagate ctty to all tasks in this session.
    let sid = my_task;
    for i in 0..super::task::MAX_TASKS {
        if sched.tasks[i].active && sched.tasks[i].sid == sid {
            sched.tasks[i].ctty_port = port;
        }
    }
    0
}

#[allow(dead_code)]
pub fn current_thread_id() -> ThreadId {
    smp::current().current_thread.load(Ordering::Relaxed)
}

/// Kill all other threads in the current thread's task (for execve).
/// Marks them as Dead and dequeues from run queues. Returns the number killed.
pub fn kill_other_threads_in_task() -> usize {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let task_id = sched.threads[my_tid as usize].task_id;
    let mut killed = 0;

    for i in 0..sched.next_thread_id as usize {
        if i == my_tid as usize { continue; }
        let t = &mut sched.threads[i];
        if t.task_id == task_id && t.state != ThreadState::Dead {
            t.state = ThreadState::Dead;
            t.exit_code = -9;
            KILLED[i].store(true, Ordering::Release);
            killed += 1;
        }
    }

    // Set thread_count to 1 (just us).
    sched.tasks[task_id as usize].thread_count = 1;
    killed
}

/// Update the task's page table root after execve replaces the address space.
pub fn update_task_page_table(new_pt_root: usize) {
    let my_tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let task_id = sched.threads[my_tid as usize].task_id;
    sched.tasks[task_id as usize].page_table_root = new_pt_root;
}

/// Get the address space ID of the current thread's task.
/// Returns 0 if the thread/task has no address space (kernel context).
pub fn current_aspace_id() -> u32 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    let thread = &sched.threads[tid as usize];
    let task = &sched.tasks[thread.task_id as usize];
    task.aspace_id
}

/// Fork the current task: clone address space (COW), create child task+thread.
/// Returns the child thread ID (>0) to the parent, or 0 if fork failed.
/// The child will return 0 from this syscall (set in its exception frame).
pub fn fork_current() -> u64 {
    let cpu = smp::cpu_id() as usize;
    let parent_frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);
    if parent_frame_sp == 0 {
        return u64::MAX;
    }

    // Enforce RLIMIT_NPROC.
    {
        let sched = SCHEDULER.lock();
        let tid = smp::current().current_thread.load(Ordering::Relaxed);
        let task_id = sched.threads[tid as usize].task_id;
        let uid = sched.tasks[task_id as usize].uid;
        let nproc_limit = sched.tasks[task_id as usize]
            .rlimits[super::task::RLIMIT_NPROC as usize].cur;
        if nproc_limit != super::task::RLIM_INFINITY {
            let mut count = 0u64;
            for i in 1..sched.next_task_id as usize {
                if sched.tasks[i].active && sched.tasks[i].uid == uid {
                    count += 1;
                }
            }
            if count >= nproc_limit {
                return u64::MAX;
            }
        }
    }

    // Gather parent info.
    let (parent_tid, parent_task_id, parent_aspace_id, parent_priority, parent_quantum, parent_sig_mask) = {
        let tid = smp::current().current_thread.load(Ordering::Relaxed);
        let sched = SCHEDULER.lock();
        let thread = &sched.threads[tid as usize];
        let task = &sched.tasks[thread.task_id as usize];
        (tid, thread.task_id, task.aspace_id, thread.base_priority, thread.default_quantum, thread.sig_mask)
    };

    // Clone the address space (COW). This is done outside the scheduler lock
    // because it acquires ASPACES and OBJECTS locks.
    let (child_aspace_id, child_pt_root) = match crate::mm::aspace::clone_for_cow(parent_aspace_id) {
        Some(x) => x,
        None => return u64::MAX,
    };

    // Create child task and thread under the scheduler lock.
    let mut sched = SCHEDULER.lock();

    let child_task_id = match sched.alloc_task_id() {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Set up child task.
    {
        let parent_pgid = sched.tasks[parent_task_id as usize].pgid;
        let parent_sid = sched.tasks[parent_task_id as usize].sid;
        let parent_ctty = sched.tasks[parent_task_id as usize].ctty_port;
        let parent_uid = sched.tasks[parent_task_id as usize].uid;
        let parent_euid = sched.tasks[parent_task_id as usize].euid;
        let parent_gid = sched.tasks[parent_task_id as usize].gid;
        let parent_egid = sched.tasks[parent_task_id as usize].egid;
        let parent_groups = sched.tasks[parent_task_id as usize].groups;
        let parent_ngroups = sched.tasks[parent_task_id as usize].ngroups;
        let parent_rlimits = sched.tasks[parent_task_id as usize].rlimits;
        let task = &mut sched.tasks[child_task_id as usize];
        task.id = child_task_id;
        task.active = true;
        task.aspace_id = child_aspace_id;
        task.page_table_root = child_pt_root;
        task.exit_code = 0;
        task.exited = false;
        task.reaped = false;
        task.wait_status = 0;
        task.thread_count = 1;
        task.parent_task = parent_task_id;
        // Fork inherits parent's process group, session, ctty, credentials, and rlimits.
        task.pgid = parent_pgid;
        task.sid = parent_sid;
        task.ctty_port = parent_ctty;
        task.fg_pgid = 0; // Only session leader tracks fg_pgid.
        task.uid = parent_uid;
        task.euid = parent_euid;
        task.gid = parent_gid;
        task.egid = parent_egid;
        task.groups = parent_groups;
        task.ngroups = parent_ngroups;
        task.rlimits = parent_rlimits;
    }

    // Bootstrap capabilities: copy parent's capset and grant well-known port caps.
    {
        // Copy the fast-path capset so child inherits parent's port access.
        crate::cap::capset_copy(parent_task_id, child_task_id);

        let mut caps = crate::cap::CAP_SYSTEM.lock();
        caps.spaces[child_task_id as usize] = crate::cap::CapSpace::new(child_task_id);

        // Grant SEND caps for well-known kernel ports.
        let nsrv = crate::io::namesrv::NAMESRV_PORT.load(core::sync::atomic::Ordering::Acquire);
        if nsrv != u64::MAX {
            caps.grant_send_cap(child_task_id, nsrv);
        }
        let iramfs = crate::io::initramfs::USER_INITRAMFS_PORT.load(core::sync::atomic::Ordering::Acquire);
        if iramfs != u64::MAX {
            caps.grant_send_cap(child_task_id, iramfs);
        }
    }

    // Allocate kernel stack for child thread.
    let kstack_page = match crate::mm::phys::alloc_page() {
        Some(p) => p,
        None => return u64::MAX,
    };
    let kstack_base = kstack_page.as_usize();
    let kstack_top = kstack_base + PAGE_SIZE;

    // Copy parent's exception frame to child's kernel stack.
    let child_frame_sp = kstack_top - EXCEPTION_FRAME_SIZE;
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_frame_sp as *const u8,
            child_frame_sp as *mut u8,
            EXCEPTION_FRAME_SIZE,
        );
    }

    // Set child's return value to 0.
    {
        let child_frame = unsafe { &mut *(child_frame_sp as *mut crate::syscall::handlers::ExceptionFrame) };
        crate::syscall::handlers::set_return(child_frame, 0);
    }

    // Allocate child thread.
    let child_tid = match sched.alloc_thread_id() {
        Some(id) => id,
        None => return u64::MAX,
    };

    // Clear killed/affinity flags.
    KILLED[child_tid as usize].store(false, Ordering::Release);
    AFFINITY_MASK[child_tid as usize].store(u64::MAX, Ordering::Relaxed);
    LAST_CPU[child_tid as usize].store(smp::cpu_id(), Ordering::Relaxed);

    let thread = &mut sched.threads[child_tid as usize];
    thread.id = child_tid;
    thread.state = ThreadState::Ready;
    thread.task_id = child_task_id;
    thread.base_priority = parent_priority;
    thread.effective_priority = parent_priority;
    THREAD_PRIO[child_tid as usize].store(parent_priority, Ordering::Relaxed);
    THREAD_TASK[child_tid as usize].store(child_task_id, Ordering::Relaxed);
    thread.quantum = parent_quantum;
    thread.default_quantum = parent_quantum;
    thread.saved_sp = child_frame_sp as u64;
    thread.stack_base = kstack_base;
    thread.exit_code = 0;
    thread.sig_mask = parent_sig_mask;
    thread.sig_pending = 0;

    sched.run_queues[parent_priority as usize].push(child_tid);

    // Return child thread ID to parent (nonzero = parent, 0 = child).
    // This matches the waitpid API which takes a thread ID.
    child_tid as u64
}

/// Terminate the current thread and destroy its task's resources.
/// This function never returns.
pub fn exit_current_thread(exit_code: i32) -> ! {
    let (tid, is_last_thread, aspace_id, pt_root, kstack_base, parent_task_id) = {
        let pcpu = smp::current();
        let tid = pcpu.current_thread.load(Ordering::Relaxed);
        let mut sched = SCHEDULER.lock();
        let thread = &mut sched.threads[tid as usize];
        thread.state = ThreadState::Dead;
        thread.exit_code = exit_code;
        // Wake any thread blocked in thread_join() on us.
        let waiter = thread.join_waiter;
        thread.join_waiter = u32::MAX;
        if waiter != u32::MAX {
            wake_thread(waiter);
        }
        let task_id = thread.task_id;
        let kstack_base = thread.stack_base;
        // NOTE: Do NOT set stack_base=0 here. The thread is still running on
        // its CPU. Setting it to 0 would allow alloc_thread_id to reuse the
        // slot before we're actually off the CPU. Instead, try_switch will set
        // stack_base=0 when it drains DEFERRED_KSTACK (proving the dead thread
        // has been context-switched away).
        let task = &mut sched.tasks[task_id as usize];
        task.thread_count -= 1;
        let is_last = task.thread_count == 0;
        let parent_task_id = task.parent_task;
        if is_last {
            task.exit_code = exit_code;
            task.exited = true;
            task.active = false;
            // Encode POSIX wait status: normal exit = (code & 0xFF) << 8.
            task.wait_status = (exit_code & 0xFF) << 8;
        }
        let aspace_id = task.aspace_id;
        let pt_root = task.page_table_root;
        (tid, is_last, aspace_id, pt_root, kstack_base, parent_task_id)
    }; // scheduler lock dropped here

    // If this was the last thread (task became zombie), notify parent.
    if is_last_thread {
        // Send SIGCHLD to parent task.
        send_signal_to_task(parent_task_id, super::task::SIGCHLD);
        // Wake any parent threads blocked in WaitChild.
        wake_wait_child_threads(parent_task_id);
    }

    // Only destroy task resources when the last thread exits.
    if is_last_thread {
        // Switch to kernel/boot page table before freeing user page table.
        if pt_root != 0 {
            #[cfg(target_arch = "aarch64")]
            {
                let boot_root = crate::arch::aarch64::mm::boot_page_table_root();
                crate::arch::aarch64::mm::switch_page_table(boot_root);
            }
            #[cfg(target_arch = "riscv64")]
            {
                let boot_root = crate::arch::riscv64::mm::boot_page_table_root();
                crate::arch::riscv64::mm::switch_page_table(boot_root);
            }
            #[cfg(target_arch = "x86_64")]
            {
                let boot_root = crate::arch::x86_64::mm::boot_page_table_root();
                crate::arch::x86_64::mm::switch_page_table(boot_root);
            }
        }

        // Destroy address space (frees VMAs and backing physical pages).
        if aspace_id != 0 {
            crate::mm::aspace::destroy(aspace_id);
        }

        // Free page table intermediate pages.
        if pt_root != 0 {
            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::free_page_table_tree(pt_root);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::free_page_table_tree(pt_root);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::free_page_table_tree(pt_root);
        }
    }

    // Auto-reap zombie children of this exiting task (prevent zombie leaks).
    if is_last_thread {
        let my_task_id = {
            let sched = SCHEDULER.lock();
            sched.threads[tid as usize].task_id
        };
        let mut sched = SCHEDULER.lock();
        for i in 1..sched.next_task_id as usize {
            let task = &sched.tasks[i];
            if task.parent_task == my_task_id && task.exited && !task.reaped {
                sched.tasks[i].reaped = true;
            }
        }
    }

    // Defer freeing our own kernel stack — we're running on it.
    // Also store our thread ID so try_switch can mark the slot as reusable.
    let cpu = smp::cpu_id();
    DEFERRED_THREAD[cpu as usize].store(tid as usize, Ordering::Release);
    DEFERRED_KSTACK[cpu as usize].store(kstack_base, Ordering::Release);

    // Enable interrupts so the timer can preempt us (we may be in a syscall
    // handler where hardware masked IRQs on exception entry).
    arch_enable_irqs();

    // Request immediate preemption on the next tick so we don't waste a
    // full quantum spinning.  Don't use WFI/HLT here: on the next timer
    // IRQ, try_switch() will switch us to a different thread, and on the
    // tick after that it will free our kstack page.  HLT's resume path
    // needs a valid stack, and spin_loop() is purely in-register.
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    YIELD_ASAP[tid as usize].store(true, Ordering::Release);
    loop { core::hint::spin_loop(); }
}

// --- Architecture-specific IRQ helpers for blocking paths ---

/// Save current interrupt state and enable IRQs. Returns saved state.
/// Public so drivers (e.g. virtio_blk) can use polling with WFI.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_irq_save_enable() -> usize {
    arch_save_and_enable_irqs()
}

/// Restore interrupt state.
/// Public so drivers (e.g. virtio_blk) can use polling with WFI.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_irq_restore(saved: usize) {
    arch_restore_irqs(saved);
}

/// Wait for next interrupt (WFI/HLT). Public for sys_yield.
#[inline(always)]
#[allow(dead_code)]
pub fn arch_wait_for_irq() {
    arch_wait_for_interrupt();
}

#[inline(always)]
fn arch_save_and_enable_irqs() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let daif: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, daif",
                "msr daifclr, #2", // Clear IRQ mask → enable IRQs
                "isb",             // Ensure unmask is visible before WFI
                out(reg) daif,
            );
        }
        daif as usize
    }
    #[cfg(target_arch = "riscv64")]
    {
        let sstatus: usize;
        unsafe {
            core::arch::asm!(
                "csrrsi {0}, sstatus, 0x2", // Set SIE bit, return old value
                out(reg) sstatus,
            );
        }
        sstatus
    }
    #[cfg(target_arch = "x86_64")]
    {
        let flags: u64;
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {0}",
                "sti",
                out(reg) flags,
            );
        }
        flags as usize
    }
}

/// Restore interrupt state.
#[inline(always)]
fn arch_restore_irqs(saved: usize) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // ISB is required: MSR writes to DAIF are not self-synchronizing
        // on AArch64.  Without it a subsequent WFI can execute before the
        // IRQ-unmask takes effect, causing a deadlock.
        core::arch::asm!("msr daif, {0}", "isb", in(reg) saved as u64);
    }
    #[cfg(target_arch = "riscv64")]
    {
        if saved & 0x2 == 0 {
            // SIE was clear before — restore it.
            unsafe { core::arch::asm!("csrci sstatus, 0x2"); }
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if saved & 0x200 == 0 {
            // IF was clear before — disable interrupts.
            unsafe { core::arch::asm!("cli"); }
        }
    }
}

/// Unconditionally enable IRQs.
#[inline(always)]
fn arch_enable_irqs() {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("msr daifclr, #2", "isb"); }
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("csrsi sstatus, 0x2"); }
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("sti"); }
}

/// Wait for the next interrupt. Pauses the CPU until an interrupt arrives.
/// On AArch64: WFI. On RISC-V: WFI. On x86-64: HLT.
/// IRQs must be enabled before calling this.
///
/// Critical on QEMU TCG: without this, busy-looping vCPUs starve QEMU's
/// I/O thread, preventing virtio request completion.
#[inline(always)]
fn arch_wait_for_interrupt() {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("wfi"); }
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("wfi"); }
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("hlt"); }
}

/// Send an event to all CPUs. On AArch64, SEV wakes WFE waiters.
/// Currently a no-op since we use WFI (woken by interrupts) instead of WFE.
#[inline(always)]
fn arch_send_event() {
    // WFI-based blocking is woken by interrupts, not events.
    // SEV is unnecessary but harmless as a hint.
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("sev"); }
}

/// Check if a child thread's task has exited. Returns exit code if so.
/// Also reaps the child (marks reaped=true) so the task slot can be reused.
pub fn waitpid(child_tid: ThreadId) -> Option<i32> {
    let mut sched = SCHEDULER.lock();
    if child_tid as usize >= MAX_THREADS {
        return None;
    }
    let task_id = sched.threads[child_tid as usize].task_id;
    let task = &mut sched.tasks[task_id as usize];
    if task.exited {
        task.reaped = true;
        Some(task.exit_code)
    } else {
        None
    }
}

/// POSIX wait flags.
pub const WNOHANG: u32 = 1;
#[allow(dead_code)]
pub const WUNTRACED: u32 = 2;
#[allow(dead_code)]
pub const WCONTINUED: u32 = 8;

/// Wake all threads in a given task that are blocked in WaitChild.
fn wake_wait_child_threads(task_id: TaskId) {
    let sched = SCHEDULER.lock();
    let mut to_wake = [0u32; MAX_THREADS];
    let mut count = 0usize;
    for i in 0..MAX_THREADS {
        let t = &sched.threads[i];
        if t.task_id == task_id && t.state != ThreadState::Dead
            && t.stack_base != 0
            && t.blocked_on == BlockReason::WaitChild
        {
            to_wake[count] = i as u32;
            count += 1;
        }
    }
    drop(sched);
    for i in 0..count {
        wake_thread(to_wake[i]);
    }
}

/// Enhanced wait4: wait for child process exit with POSIX semantics.
///
/// `pid` semantics:
///   - pid > 0: wait for child with task_id == pid
///   - pid == -1: wait for any child
///   - pid == 0: wait for any child in caller's process group
///   - pid < -1: wait for any child in process group |pid|
///
/// Returns (child_task_id, wait_status) or (-1, 0) on error,
/// or (0, 0) for WNOHANG with no exited child.
pub fn wait4(pid: i64, flags: u32) -> (i32, i32) {
    let tid = current_thread_id();

    loop {
        let result = {
            let mut sched = SCHEDULER.lock();
            let my_task_id = sched.threads[tid as usize].task_id;
            let my_pgid = sched.tasks[my_task_id as usize].pgid;

            // Scan for a matching exited (zombie) child.
            let mut found: Option<(u32, i32)> = None;
            let mut has_children = false;
            for i in 1..sched.next_task_id as usize {
                let task = &sched.tasks[i];
                if task.parent_task != my_task_id { continue; }

                // Check pid filter.
                let matches = match pid {
                    -1 => true,                    // any child
                    0 => task.pgid == my_pgid,     // same pgroup
                    p if p > 0 => i == p as usize, // specific task
                    p => task.pgid == (-p) as TaskId, // specific pgroup
                };
                if !matches { continue; }
                has_children = true;

                if task.exited && !task.reaped {
                    found = Some((i as u32, task.wait_status));
                    // Reap the child.
                    sched.tasks[i].reaped = true;
                    break;
                }
            }

            if let Some((child_id, status)) = found {
                Some((child_id as i32, status))
            } else if !has_children {
                // No matching children at all — ECHILD.
                Some((-1, 0))
            } else if flags & WNOHANG != 0 {
                Some((0, 0))
            } else {
                // Block: clear wakeup flag while holding the lock.
                clear_wakeup_flag(tid);
                sched.threads[tid as usize].blocked_on = BlockReason::WaitChild;
                None
            }
        }; // scheduler lock dropped

        match result {
            Some(r) => return r,
            None => {
                // Spin until woken by a child exit.
                block_current(BlockReason::WaitChild);
            }
        }
    }
}

/// Boost a thread's effective priority if `to_prio` is higher (lower number).
pub fn boost_priority(tid: ThreadId, to_prio: u8) {
    let mut sched = SCHEDULER.lock();
    if (tid as usize) < MAX_THREADS {
        let thread = &mut sched.threads[tid as usize];
        if to_prio < thread.effective_priority {
            thread.effective_priority = to_prio;
            THREAD_PRIO[tid as usize].store(to_prio, Ordering::Release);
        }
    }
}

/// Reset a thread's effective priority back to its base priority.
pub fn reset_priority(tid: ThreadId) {
    let mut sched = SCHEDULER.lock();
    if (tid as usize) < MAX_THREADS {
        let thread = &mut sched.threads[tid as usize];
        thread.effective_priority = thread.base_priority;
        THREAD_PRIO[tid as usize].store(thread.base_priority, Ordering::Release);
    }
}

/// Get a thread's current effective priority (lock-free).
pub fn thread_effective_priority(tid: ThreadId) -> u8 {
    if (tid as usize) < MAX_THREADS {
        THREAD_PRIO[tid as usize].load(Ordering::Acquire)
    } else {
        255
    }
}

// --- L4-style handoff scheduling ---

/// Store the current frame SP for use by park/handoff functions.
/// Called by the arch exception handler before dispatching a syscall.
pub fn store_frame_sp(sp: u64) {
    let cpu = smp::cpu_id() as usize;
    CURRENT_FRAME_SP[cpu].store(sp, Ordering::Release);
}

/// Take (read and clear) any pending context switch SP.
/// Called by the arch exception handler after syscall dispatch returns.
/// Returns 0 if no switch is pending.
pub fn take_pending_switch() -> u64 {
    let cpu = smp::cpu_id() as usize;
    PENDING_SWITCH_SP[cpu].swap(0, Ordering::AcqRel)
}

/// Get a thread's saved SP. Used by inject_recv_into_frame to write into
/// a parked thread's exception frame.
pub fn thread_saved_sp(tid: ThreadId) -> u64 {
    SCHEDULER.lock().threads[tid as usize].saved_sp
}

/// Park the current thread for IPC (true off-CPU park).
/// Saves the current SP from CURRENT_FRAME_SP, marks the thread Blocked,
/// picks the next runnable thread, and stores its SP in PENDING_SWITCH_SP.
/// The exception handler will complete the switch on return.
///
/// Unlike block_current() which spins on-CPU, this truly takes the thread
/// off the run queue and saves its frame for later injection by a sender.
pub fn park_current_for_ipc(reason: BlockReason) {
    let cpu = smp::cpu_id() as usize;
    let frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);

    let mut sched = SCHEDULER.lock();
    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Save current thread's state.
    sched.threads[tid].saved_sp = frame_sp;
    sched.threads[tid].state = ThreadState::Blocked;
    sched.threads[tid].blocked_on = reason;

    // Pick next thread (don't re-enqueue current — it's Blocked).
    let next_id = sched.pick_next(idle_id);

    // Switch page tables if needed.
    let prev_task = sched.threads[tid].task_id;
    let next_task = sched.threads[next_id as usize].task_id;
    if prev_task != next_task {
        let next_root = sched.tasks[next_task as usize].page_table_root;
        if next_root != 0 {
            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::switch_page_table(next_root);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::switch_page_table(next_root);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::switch_page_table(next_root);
        } else {
            #[cfg(target_arch = "riscv64")]
            {
                let kern_root = crate::arch::riscv64::mm::kernel_pt_root();
                if kern_root != 0 {
                    crate::arch::riscv64::mm::switch_page_table(kern_root);
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        let next_kstack_top = sched.threads[next_id as usize].stack_base + PAGE_SIZE;
        crate::arch::x86_64::gdt::set_rsp0(next_kstack_top as u64);
    }

    sched.threads[next_id as usize].state = ThreadState::Running;
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    let next_sp = sched.threads[next_id as usize].saved_sp;

    // Read SA state while holding lock.
    let parked_task_id = sched.threads[tid].task_id;
    let sa_enabled = sched.tasks[parked_task_id as usize].sa_enabled;
    drop(sched);

    // Scheduler activation: notify userspace that a kthread blocked.
    if sa_enabled {
        let waiter = SA_WAITER[parked_task_id as usize].load(Ordering::Acquire);
        if waiter != u32::MAX && waiter as usize != tid {
            SA_EVENT[parked_task_id as usize].store(tid as u64, Ordering::Release);
            SA_PENDING[parked_task_id as usize].store(true, Ordering::Release);
            wake_thread(waiter);
        }
    }

    PENDING_SWITCH_SP[cpu].store(next_sp, Ordering::Release);
}

/// Wake a parked thread by marking it Ready and enqueueing it.
/// This is for threads parked via park_current_for_ipc (Blocked state).
pub fn wake_parked_thread(tid: ThreadId) {
    let mut sched = SCHEDULER.lock();
    if (tid as usize) < MAX_THREADS && sched.threads[tid as usize].state == ThreadState::Blocked {
        let prio = sched.threads[tid as usize].effective_priority;
        sched.threads[tid as usize].state = ThreadState::Ready;
        sched.run_queues[prio as usize].push(tid);
    }
}

/// Get monotonic time in nanoseconds since boot.
pub fn get_monotonic_ns() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let c = crate::arch::aarch64::timer::counter();
        let f = crate::arch::aarch64::timer::cntfrq();
        ((c as u128 * 1_000_000_000u128) / f as u128) as u64
    }
    #[cfg(target_arch = "riscv64")]
    {
        let c = crate::arch::riscv64::trap::read_time();
        ((c as u128 * 1_000_000_000u128) / 10_000_000u128) as u64
    }
    #[cfg(target_arch = "x86_64")]
    {
        let c = crate::arch::x86_64::timer::rdtsc();
        // QEMU RDTSC freq ~ 1 GHz, so ns ≈ cycles
        ((c as u128 * 1_000_000_000u128) / 1_000_000_000u128) as u64
    }
}

/// Wake threads whose sleep deadlines have passed.
/// Called from tick() before try_switch.
fn check_sleep_timers() {
    let now_ns = get_monotonic_ns();
    let mut sched = SCHEDULER.lock();
    for i in 0..MAX_THREADS {
        if sched.threads[i].state == ThreadState::Blocked
            && matches!(sched.threads[i].blocked_on, BlockReason::Sleep)
            && sched.threads[i].sleep_deadline_ns != 0
            && sched.threads[i].sleep_deadline_ns <= now_ns
        {
            let prio = sched.threads[i].effective_priority;
            sched.threads[i].state = ThreadState::Ready;
            sched.threads[i].blocked_on = BlockReason::None;
            sched.threads[i].sleep_deadline_ns = 0;
            sched.run_queues[prio as usize].push(i as ThreadId);
        }
    }
}

/// Check per-task alarm timers and deliver SIGALRM.
/// Called from tick() before try_switch.
fn check_alarm_timers() {
    let now_ns = get_monotonic_ns();
    let mut fired = [0u32; super::task::MAX_TASKS];
    let mut count = 0usize;

    {
        let mut sched = SCHEDULER.lock();
        for i in 0..super::task::MAX_TASKS {
            if sched.tasks[i].active
                && sched.tasks[i].alarm_deadline_ns != 0
                && sched.tasks[i].alarm_deadline_ns <= now_ns
            {
                if sched.tasks[i].alarm_interval_ns != 0 {
                    sched.tasks[i].alarm_deadline_ns = now_ns + sched.tasks[i].alarm_interval_ns;
                } else {
                    sched.tasks[i].alarm_deadline_ns = 0;
                }
                if count < fired.len() {
                    fired[count] = sched.tasks[i].id;
                    count += 1;
                }
            }
        }
    }

    for i in 0..count {
        send_signal_to_task(fired[i], super::task::SIGALRM);
    }
}

/// Check per-thread interval timers and deliver signals when they fire.
fn check_interval_timers() {
    let now_ns = get_monotonic_ns();
    let mut fired_tid: ThreadId = 0;
    let mut fired_sig: u32 = 0;
    let mut fired_interval: u64 = 0;
    let mut found = false;

    {
        let mut sched = SCHEDULER.lock();
        for i in 0..sched.threads.len() {
            let t = &sched.threads[i];
            if t.state != ThreadState::Dead
                && t.stack_base != 0
                && t.timer_signal != 0
                && t.timer_next_ns != 0
                && now_ns >= t.timer_next_ns
            {
                fired_tid = t.id;
                fired_sig = t.timer_signal;
                fired_interval = t.timer_interval_ns;
                // Re-arm the timer while we hold the lock.
                sched.threads[i].timer_next_ns = if fired_interval != 0 {
                    now_ns + fired_interval
                } else {
                    0
                };
                found = true;
                break; // Only fire one per tick to avoid re-lock issues.
            }
        }
    }

    if found {
        send_signal_to_thread(fired_tid, fired_sig);
    }
}

/// Park the current thread for a timed sleep.
/// Sets the deadline and blocks the thread (off-CPU).
pub fn park_current_for_sleep(deadline_ns: u64) {
    let cpu = smp::cpu_id() as usize;
    let frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);

    let mut sched = SCHEDULER.lock();
    let pcpu = smp::current();
    let tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;
    let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

    // Set deadline before marking Blocked.
    sched.threads[tid].sleep_deadline_ns = deadline_ns;
    sched.threads[tid].saved_sp = frame_sp;
    sched.threads[tid].state = ThreadState::Blocked;
    sched.threads[tid].blocked_on = BlockReason::Sleep;

    // Pick next thread (don't re-enqueue current — it's Blocked).
    let next_id = sched.pick_next(idle_id);

    // Switch page tables if needed.
    let prev_task = sched.threads[tid].task_id;
    let next_task = sched.threads[next_id as usize].task_id;
    if prev_task != next_task {
        let next_root = sched.tasks[next_task as usize].page_table_root;
        if next_root != 0 {
            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::switch_page_table(next_root);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::switch_page_table(next_root);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::switch_page_table(next_root);
        } else {
            #[cfg(target_arch = "riscv64")]
            {
                let kern_root = crate::arch::riscv64::mm::kernel_pt_root();
                if kern_root != 0 {
                    crate::arch::riscv64::mm::switch_page_table(kern_root);
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        let next_kstack_top = sched.threads[next_id as usize].stack_base + PAGE_SIZE;
        crate::arch::x86_64::gdt::set_rsp0(next_kstack_top as u64);
    }

    sched.threads[next_id as usize].state = ThreadState::Running;
    pcpu.current_thread.store(next_id, Ordering::Relaxed);
    let next_sp = sched.threads[next_id as usize].saved_sp;

    // SA notification for the parked thread.
    let parked_task_id = sched.threads[tid].task_id;
    let sa_enabled = sched.tasks[parked_task_id as usize].sa_enabled;
    drop(sched);

    if sa_enabled {
        let waiter = SA_WAITER[parked_task_id as usize].load(Ordering::Acquire);
        if waiter != u32::MAX && waiter as usize != tid {
            SA_EVENT[parked_task_id as usize].store(tid as u64, Ordering::Release);
            SA_PENDING[parked_task_id as usize].store(true, Ordering::Release);
            wake_thread(waiter);
        }
    }

    PENDING_SWITCH_SP[cpu].store(next_sp, Ordering::Release);
}

/// Set an alarm timer for the current task.
/// Returns previous remaining time in nanoseconds.
pub fn alarm(initial_ns: u64, interval_ns: u64) -> u64 {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let mut sched = SCHEDULER.lock();
    let task_id = sched.threads[tid as usize].task_id;
    let task = &mut sched.tasks[task_id as usize];

    let now = get_monotonic_ns();
    let prev_remaining = if task.alarm_deadline_ns > now {
        task.alarm_deadline_ns - now
    } else {
        0
    };

    if initial_ns == 0 {
        task.alarm_deadline_ns = 0;
        task.alarm_interval_ns = 0;
    } else {
        task.alarm_deadline_ns = now + initial_ns;
        task.alarm_interval_ns = interval_ns;
    }
    prev_remaining
}

/// L4-style direct handoff: sender donates its remaining quantum to receiver.
/// Saves sender's SP, loads receiver as current thread, stores receiver's SP
/// in PENDING_SWITCH_SP. Receiver must already have its frame injected.
pub fn handoff_to(receiver_tid: ThreadId) {
    let cpu = smp::cpu_id() as usize;
    let frame_sp = CURRENT_FRAME_SP[cpu].load(Ordering::Acquire);

    let mut sched = SCHEDULER.lock();
    let pcpu = smp::current();
    let sender_tid = pcpu.current_thread.load(Ordering::Relaxed) as usize;

    // Save sender: goes to Ready on run queue.
    sched.threads[sender_tid].saved_sp = frame_sp;
    let sender_prio = sched.threads[sender_tid].effective_priority;
    sched.threads[sender_tid].state = ThreadState::Ready;
    sched.run_queues[sender_prio as usize].push(sender_tid as ThreadId);

    // Donate remaining quantum to receiver.
    let remaining_quantum = sched.threads[sender_tid].quantum;
    sched.threads[receiver_tid as usize].quantum = remaining_quantum;

    // Switch page tables if needed.
    let sender_task = sched.threads[sender_tid].task_id;
    let recv_task = sched.threads[receiver_tid as usize].task_id;
    if sender_task != recv_task {
        let next_root = sched.tasks[recv_task as usize].page_table_root;
        if next_root != 0 {
            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::switch_page_table(next_root);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::switch_page_table(next_root);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::switch_page_table(next_root);
        } else {
            #[cfg(target_arch = "riscv64")]
            {
                let kern_root = crate::arch::riscv64::mm::kernel_pt_root();
                if kern_root != 0 {
                    crate::arch::riscv64::mm::switch_page_table(kern_root);
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        let next_kstack_top = sched.threads[receiver_tid as usize].stack_base + PAGE_SIZE;
        crate::arch::x86_64::gdt::set_rsp0(next_kstack_top as u64);
    }

    // Activate receiver.
    sched.threads[receiver_tid as usize].state = ThreadState::Running;
    pcpu.current_thread.store(receiver_tid, Ordering::Relaxed);
    let recv_sp = sched.threads[receiver_tid as usize].saved_sp;
    drop(sched);

    PENDING_SWITCH_SP[cpu].store(recv_sp, Ordering::Release);
}

// --- Scheduler Activations API ---

/// Register the current task for scheduler activations.
pub fn sa_register() {
    let task_id = current_task_id();
    if task_id == 0 { return; }
    let mut sched = SCHEDULER.lock();
    sched.tasks[task_id as usize].sa_enabled = true;
}

/// Block until a scheduler activation event occurs.
/// Returns the blocked kthread's TID, or u64::MAX on error.
pub fn sa_wait() -> u64 {
    let task_id = current_task_id();
    if task_id == 0 { return u64::MAX; }

    // Fast path: event already pending.
    if SA_PENDING[task_id as usize].swap(false, Ordering::SeqCst) {
        SA_WAITER[task_id as usize].store(u32::MAX, Ordering::Relaxed);
        return SA_EVENT[task_id as usize].load(Ordering::Relaxed);
    }

    // Register as waiter.
    let tid = current_thread_id();
    clear_wakeup_flag(tid);
    SA_WAITER[task_id as usize].store(tid, Ordering::Release);

    // Double-check after registering (prevents lost wakeup).
    if SA_PENDING[task_id as usize].swap(false, Ordering::SeqCst) {
        SA_WAITER[task_id as usize].store(u32::MAX, Ordering::Relaxed);
        return SA_EVENT[task_id as usize].load(Ordering::Relaxed);
    }

    // Block until woken by SA notification.
    block_current(BlockReason::ActivationWait);
    SA_WAITER[task_id as usize].store(u32::MAX, Ordering::Relaxed);
    SA_PENDING[task_id as usize].store(false, Ordering::Relaxed);
    SA_EVENT[task_id as usize].load(Ordering::Relaxed)
}

/// Get the index (0-based) of the current kthread within its task.
pub fn sa_getid() -> u64 {
    let tid = current_thread_id();
    let task_id = current_task_id();
    let sched = SCHEDULER.lock();
    let mut idx = 0u64;
    for i in 0..MAX_THREADS {
        let t = &sched.threads[i];
        if t.task_id == task_id && t.state != ThreadState::Dead
            && (t.stack_base != 0 || i == 0)
        {
            if i as u32 == tid { return idx; }
            idx += 1;
        }
    }
    u64::MAX
}

/// Set the coscheduling group for the current thread. group=0 removes from any group.
pub fn cosched_set(group: u32) {
    let tid = current_thread_id();
    COSCHED_GROUP[tid as usize].store(group, Ordering::Relaxed);
}

/// Set CPU affinity mask for a thread. Returns true on success.
pub fn set_affinity(tid: u32, mask: u64) -> bool {
    if (tid as usize) >= MAX_THREADS || mask == 0 {
        return false;
    }
    AFFINITY_MASK[tid as usize].store(mask, Ordering::Relaxed);
    true
}

/// Get CPU affinity mask for a thread.
pub fn get_affinity(tid: u32) -> u64 {
    if (tid as usize) >= MAX_THREADS {
        return 0;
    }
    AFFINITY_MASK[tid as usize].load(Ordering::Relaxed)
}
