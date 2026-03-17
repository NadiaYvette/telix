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
use super::task::{Task, TaskId, MAX_TASKS};
use super::smp;
use crate::sync::SpinLock;
use crate::mm::page::{PAGE_SIZE, MMUPAGE_SIZE};
use core::sync::atomic::Ordering;

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
}

struct Scheduler {
    threads: [Thread; MAX_THREADS],
    tasks: [Task; MAX_TASKS],
    run_queues: [RunQueue; NUM_PRIORITIES],
    next_thread_id: ThreadId,
    next_task_id: u32,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: [const { Thread::empty() }; MAX_THREADS],
            tasks: [const { Task::empty() }; MAX_TASKS],
            run_queues: [const { RunQueue::new() }; NUM_PRIORITIES],
            next_thread_id: 0,
            next_task_id: 0,
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
        self.threads[0].priority = 255;
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
        thread.priority = 255; // lowest
        thread.quantum = u32::MAX;
        thread.default_quantum = u32::MAX;
        // saved_sp will be set on first preemption
        Some(id)
    }

    fn create_thread(
        &mut self,
        entry: fn() -> !,
        priority: u8,
        quantum: u32,
    ) -> Option<ThreadId> {
        let id = self.next_thread_id;
        if id as usize >= MAX_THREADS {
            return None;
        }
        self.next_thread_id += 1;

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

        let thread = &mut self.threads[id as usize];
        thread.id = id;
        thread.state = ThreadState::Ready;
        thread.task_id = 0;
        thread.priority = priority;
        thread.quantum = quantum;
        thread.default_quantum = quantum;
        thread.saved_sp = frame_sp as u64;
        thread.stack_base = stack_base;

        self.run_queues[priority as usize].push(id);
        Some(id)
    }

    /// Create a user-mode thread in a new task, loading an ELF binary from initramfs.
    fn create_user_thread(
        &mut self,
        elf_name: &[u8],
        priority: u8,
        quantum: u32,
    ) -> Option<ThreadId> {
        // Look up the ELF binary in the initramfs.
        let elf_data = crate::io::initramfs::lookup_file(elf_name)?;

        // Allocate a new task.
        let task_id = self.next_task_id;
        if task_id as usize >= MAX_TASKS {
            return None;
        }
        self.next_task_id += 1;

        // Create a page table with kernel identity mapping.
        #[cfg(target_arch = "aarch64")]
        let pt_root = crate::arch::aarch64::mm::setup_tables()?;
        #[cfg(target_arch = "riscv64")]
        let pt_root = crate::arch::riscv64::mm::setup_tables()?;
        #[cfg(target_arch = "x86_64")]
        let pt_root = crate::arch::x86_64::mm::create_user_page_table()?;

        // Create address space.
        let aspace_id = crate::mm::aspace::create(pt_root)?;

        // Set up the task.
        let task = &mut self.tasks[task_id as usize];
        task.id = task_id;
        task.active = true;
        task.aspace_id = aspace_id;
        task.page_table_root = pt_root;

        // Load ELF segments into the address space.
        let entry = match crate::loader::elf::load_elf(elf_data, aspace_id, pt_root) {
            Ok(e) => e,
            Err(_) => return None,
        };
        // Flush instruction cache: code was written via identity-mapped VA
        // but will be executed via user VA.
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
        const USER_STACK_TOP: usize = 0x3F_F000_0000; // Below Sv39 256 GiB limit
        #[cfg(target_arch = "x86_64")]
        const USER_STACK_TOP: usize = 0x7FFF_FFFF_0000;

        let stack_pages = 1; // One allocation page for user stack.
        let stack_va = USER_STACK_TOP - stack_pages * PAGE_SIZE;

        // Map the user stack in the address space.
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
                obj.ensure_page(page_idx)
            })?;
            let pa_usize = pa.as_usize();

            // Zero the page.
            unsafe {
                core::ptr::write_bytes(pa_usize as *mut u8, 0, PAGE_SIZE);
            }

            // Map each MMU page.
            #[cfg(target_arch = "aarch64")]
            let pte_flags = crate::arch::aarch64::mm::USER_RW_FLAGS;
            #[cfg(target_arch = "riscv64")]
            let pte_flags = crate::arch::riscv64::mm::USER_RW_FLAGS;
            #[cfg(target_arch = "x86_64")]
            let pte_flags = crate::arch::x86_64::mm::USER_RW_FLAGS;

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

            // Mark installed in VMA.
            crate::mm::aspace::with_aspace(aspace_id, |aspace| {
                if let Some(vma) = aspace.find_vma_mut(page_va) {
                    for mmu_idx in 0..mmu_count {
                        let idx = vma.mmu_index_of(page_va + mmu_idx * MMUPAGE_SIZE);
                        vma.set_installed(idx);
                        vma.set_zeroed(idx);
                    }
                }
            });
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
                // ELR_EL1 = user entry point.
                *frame.add(32) = entry as u64;
                // SPSR_EL1 = EL0t (0x0), IRQs enabled.
                *frame.add(33) = 0x0;
                // SP_EL0 (frame offset 31) = user stack top.
                *frame.add(31) = USER_STACK_TOP as u64;
            }

            #[cfg(target_arch = "riscv64")]
            {
                // sepc = user entry point.
                *frame.add(31) = entry as u64;
                // sstatus: SPP=0 (U-mode), SPIE=1 (enable IRQs on sret).
                *frame.add(32) = 1 << 5; // SPIE only, SPP=0
                // x2/sp (frame index 1) = user stack top.
                *frame.add(1) = USER_STACK_TOP as u64;
            }

            #[cfg(target_arch = "x86_64")]
            {
                *frame.add(17) = entry as u64;                            // RIP
                *frame.add(18) = (crate::arch::x86_64::gdt::USER_CS as u64) | 3; // CS = user code | RPL=3
                *frame.add(19) = 0x200;                                    // RFLAGS = IF
                *frame.add(20) = USER_STACK_TOP as u64;                    // RSP = user stack
                *frame.add(21) = (crate::arch::x86_64::gdt::USER_DS as u64) | 3; // SS = user data | RPL=3
            }
        }

        // Allocate thread.
        let id = self.next_thread_id;
        if id as usize >= MAX_THREADS {
            return None;
        }
        self.next_thread_id += 1;

        let thread = &mut self.threads[id as usize];
        thread.id = id;
        thread.state = ThreadState::Ready;
        thread.task_id = task_id;
        thread.priority = priority;
        thread.quantum = quantum;
        thread.default_quantum = quantum;
        thread.saved_sp = frame_sp as u64;
        thread.stack_base = kstack_base;

        self.run_queues[priority as usize].push(id);
        Some(id)
    }

    fn pick_next(&mut self, idle_id: ThreadId) -> ThreadId {
        for prio in 0..NUM_PRIORITIES {
            if let Some(id) = self.run_queues[prio].pop() {
                return id;
            }
        }
        idle_id
    }

    fn timer_tick_for(&mut self, current: ThreadId, idle_id: ThreadId) -> bool {
        if current == idle_id {
            return self.has_ready_threads();
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
        let pcpu = smp::current();
        let prev_id = pcpu.current_thread.load(Ordering::Relaxed);
        let idle_id = pcpu.idle_thread_id.load(Ordering::Relaxed);

        if !self.timer_tick_for(prev_id, idle_id) {
            return current_sp; // No preemption needed.
        }

        let next_id = self.pick_next(idle_id);

        if prev_id == next_id {
            return current_sp;
        }

        // Save current thread's SP.
        self.threads[prev_id as usize].saved_sp = current_sp;
        let prev_prio = self.threads[prev_id as usize].priority;
        self.threads[prev_id as usize].state = ThreadState::Ready;
        // Don't put idle threads on the run queue.
        if prev_id != idle_id {
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
        self.threads[next_id as usize].saved_sp
    }
}

static SCHEDULER: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

pub fn init() {
    let mut sched = SCHEDULER.lock();
    sched.init();
    let idle_id = 0; // Thread 0 = BSP idle
    drop(sched);

    smp::init_bsp(idle_id);
    crate::println!("  Scheduler initialized (BSP = CPU 0)");
}

/// Called by secondary CPUs to create their idle thread and register.
pub fn init_ap(cpu: u32) {
    let idle_id = {
        let mut sched = SCHEDULER.lock();
        sched.create_idle_thread().expect("AP idle thread")
    };
    smp::init_ap(cpu, idle_id);
    crate::println!("  CPU {} scheduler ready (idle thread {})", cpu, idle_id);
}

pub fn spawn(entry: fn() -> !, priority: u8, quantum: u32) -> Option<ThreadId> {
    SCHEDULER.lock().create_thread(entry, priority, quantum)
}

/// Spawn a new user-mode process from an ELF binary in the initramfs.
/// Creates a new task with its own address space.
pub fn spawn_user(elf_name: &[u8], priority: u8, quantum: u32) -> Option<ThreadId> {
    SCHEDULER.lock().create_user_thread(elf_name, priority, quantum)
}

/// Get the task ID of the current thread.
#[allow(dead_code)]
pub fn current_task_id() -> TaskId {
    let tid = smp::current().current_thread.load(Ordering::Relaxed);
    let sched = SCHEDULER.lock();
    sched.threads[tid as usize].task_id
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

/// Block the current thread with the given reason.
/// The thread will be preempted on the next timer tick and will not
/// be re-enqueued until `wake_thread()` is called.
pub fn block_current(_reason: BlockReason) {
    let tid = current_thread_id();
    WAKEUP_FLAGS[tid as usize].store(false, Ordering::Release);
    // Spin until the wakeup flag is set. The thread stays Running and
    // gets preempted normally by timer ticks (quantum-based). This avoids
    // a race where wake_thread() re-enqueues a Blocked thread that's still
    // executing on its CPU, causing double-scheduling on SMP.
    while !WAKEUP_FLAGS[tid as usize].load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
}

/// Wake a blocked thread, making it runnable.
pub fn wake_thread(tid: ThreadId) {
    WAKEUP_FLAGS[tid as usize].store(true, Ordering::Release);
}

#[allow(dead_code)]
pub fn current_thread_id() -> ThreadId {
    smp::current().current_thread.load(Ordering::Relaxed)
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
