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
use core::sync::atomic::{AtomicUsize, Ordering};

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
            if !self.tasks[i].active && self.tasks[i].exited {
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

        self.run_queues[priority as usize].push(id);
        Some(id)
    }

    /// Create a user-mode thread in a new task, loading an ELF binary from initramfs.
    fn create_user_thread(
        &mut self,
        elf_name: &[u8],
        priority: u8,
        quantum: u32,
        arg0: u64,
    ) -> Option<ThreadId> {
        // Look up the ELF binary in the initramfs.
        let elf_data = crate::io::initramfs::lookup_file(elf_name)?;
        self.create_user_thread_from_elf(elf_data, priority, quantum, arg0)
    }

    /// Create a user-mode thread in a new task from ELF data already in kernel memory.
    fn create_user_thread_from_elf(
        &mut self,
        elf_data: &[u8],
        priority: u8,
        quantum: u32,
        arg0: u64,
    ) -> Option<ThreadId> {
        // Allocate a task slot (may reuse an exited slot).
        let task_id = self.alloc_task_id()?;

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
        task.exit_code = 0;
        task.exited = false;
        // Record the parent task (caller's task) for waitpid.
        let caller_tid = smp::current().current_thread.load(Ordering::Relaxed);
        task.parent_task = self.threads[caller_tid as usize].task_id;

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

            // Write arg0 into the child's first argument register.
            #[cfg(target_arch = "aarch64")]
            { *frame.add(0) = arg0; } // x0
            #[cfg(target_arch = "riscv64")]
            { *frame.add(9) = arg0; } // a0 = x10 at frame index 9
            #[cfg(target_arch = "x86_64")]
            { *frame.add(9) = arg0; } // rdi at frame index 9
        }

        // Allocate thread (may reuse a Dead slot).
        let id = self.alloc_thread_id()?;

        let thread = &mut self.threads[id as usize];
        thread.id = id;
        thread.state = ThreadState::Ready;
        thread.task_id = task_id;
        thread.base_priority = priority;
        thread.effective_priority = priority;
        THREAD_PRIO[id as usize].store(priority, Ordering::Relaxed);
        thread.quantum = quantum;
        thread.default_quantum = quantum;
        thread.saved_sp = frame_sp as u64;
        thread.stack_base = kstack_base;

        self.run_queues[priority as usize].push(id);
        Some(id)
    }

    /// Like create_user_thread, but also copies `data` into the child's address space
    /// at `data_va`, and sets arg1=data_va, arg2=data_len in the initial frame.
    fn create_user_thread_with_data(
        &mut self,
        elf_name: &[u8],
        priority: u8,
        quantum: u32,
        arg0: u64,
        data: &[u8],
        data_va: usize,
    ) -> Option<ThreadId> {
        // First, create the thread normally.
        let tid = self.create_user_thread(elf_name, priority, quantum, arg0)?;

        let task_id = self.threads[tid as usize].task_id;
        let aspace_id = self.tasks[task_id as usize].aspace_id;
        let pt_root = self.tasks[task_id as usize].page_table_root;

        // Map data pages into the child's address space.
        let data_pages = (data.len() + PAGE_SIZE - 1) / PAGE_SIZE;
        if data_pages > 0 {
            let obj_id = crate::mm::aspace::with_aspace(aspace_id, |aspace| {
                let vma = aspace.map_anon(data_va, data_pages, crate::mm::vma::VmaProt::ReadOnly)
                    .ok_or(())?;
                Ok::<_, ()>(vma.object_id)
            }).ok()?;

            let mmu_count = PAGE_SIZE / MMUPAGE_SIZE;
            #[cfg(target_arch = "aarch64")]
            let pte_flags = crate::arch::aarch64::mm::USER_RO_FLAGS;
            #[cfg(target_arch = "riscv64")]
            let pte_flags = crate::arch::riscv64::mm::USER_RO_FLAGS;
            #[cfg(target_arch = "x86_64")]
            let pte_flags = crate::arch::x86_64::mm::USER_RO_FLAGS;

            for page_idx in 0..data_pages {
                let page_va = data_va + page_idx * PAGE_SIZE;
                let pa = crate::mm::object::with_object(obj_id, |obj| {
                    obj.ensure_page(page_idx)
                })?;
                let pa_usize = pa.as_usize();

                // Zero the page first, then copy data.
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
        }

        // Set arg1 = data_va, arg2 = data_len in the thread's exception frame.
        let frame = self.threads[tid as usize].saved_sp as *mut u64;
        unsafe {
            #[cfg(target_arch = "aarch64")]
            {
                *frame.add(1) = data_va as u64; // x1
                *frame.add(2) = data.len() as u64; // x2
            }
            #[cfg(target_arch = "riscv64")]
            {
                *frame.add(10) = data_va as u64; // a1 = x11 at frame index 10
                *frame.add(11) = data.len() as u64; // a2 = x12 at frame index 11
            }
            #[cfg(target_arch = "x86_64")]
            {
                *frame.add(10) = data_va as u64; // rsi at frame index 10
                *frame.add(11) = data.len() as u64; // rdx at frame index 11
            }
        }

        Some(tid)
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
        // Drain deferred kernel stack free from a previous exit on this CPU.
        let cpu = smp::cpu_id();
        let deferred = DEFERRED_KSTACK[cpu as usize].swap(0, Ordering::AcqRel);
        if deferred != 0 {
            crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(deferred));
            // Now mark the dead thread's slot as reusable (stack_base=0).
            let dead_tid = DEFERRED_THREAD[cpu as usize].swap(usize::MAX, Ordering::AcqRel);
            if dead_tid < MAX_THREADS {
                self.threads[dead_tid].stack_base = 0;
            }
        }

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
/// Creates a new task with its own address space. `arg0` is passed to main().
pub fn spawn_user(elf_name: &[u8], priority: u8, quantum: u32, arg0: u64) -> Option<ThreadId> {
    SCHEDULER.lock().create_user_thread(elf_name, priority, quantum, arg0)
}

/// Spawn a new user-mode process from ELF data already in kernel memory.
pub fn spawn_user_from_elf(elf_data: &[u8], priority: u8, quantum: u32, arg0: u64) -> Option<ThreadId> {
    SCHEDULER.lock().create_user_thread_from_elf(elf_data, priority, quantum, arg0)
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
    SCHEDULER.lock().create_user_thread_with_data(elf_name, priority, quantum, arg0, data, data_va)
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

/// Per-thread effective priority, readable without the scheduler lock.
/// Updated by boost_priority/reset_priority and thread creation.
static THREAD_PRIO: [core::sync::atomic::AtomicU8; super::thread::MAX_THREADS] = {
    const INIT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(255);
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
        // Use WFI to wait for the next interrupt (timer tick or device IRQ).
        // This is critical on QEMU TCG: spin_loop() keeps the vCPU busy,
        // starving QEMU's I/O thread from processing virtio requests.
        // WFI causes the vCPU to pause until an interrupt arrives.
        arch_wait_for_interrupt();
    }
    YIELD_ASAP[tid as usize].store(false, Ordering::Release);
    arch_restore_irqs(saved);
}

/// Wake a blocked thread, making it runnable.
pub fn wake_thread(tid: ThreadId) {
    WAKEUP_FLAGS[tid as usize].store(true, Ordering::Release);
    // Signal all CPUs so any core spinning in block_current's WFE wakes immediately.
    arch_send_event();
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

/// Terminate the current thread and destroy its task's resources.
/// This function never returns.
pub fn exit_current_thread(exit_code: i32) -> ! {
    let (tid, aspace_id, pt_root, kstack_base) = {
        let pcpu = smp::current();
        let tid = pcpu.current_thread.load(Ordering::Relaxed);
        let mut sched = SCHEDULER.lock();
        let thread = &mut sched.threads[tid as usize];
        thread.state = ThreadState::Dead;
        let task_id = thread.task_id;
        let kstack_base = thread.stack_base;
        // NOTE: Do NOT set stack_base=0 here. The thread is still running on
        // its CPU. Setting it to 0 would allow alloc_thread_id to reuse the
        // slot before we're actually off the CPU. Instead, try_switch will set
        // stack_base=0 when it drains DEFERRED_KSTACK (proving the dead thread
        // has been context-switched away).
        let task = &mut sched.tasks[task_id as usize];
        task.exit_code = exit_code;
        task.exited = true;
        task.active = false;
        let aspace_id = task.aspace_id;
        let pt_root = task.page_table_root;
        (tid, aspace_id, pt_root, kstack_base)
    }; // scheduler lock dropped here

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

    // Defer freeing our own kernel stack — we're running on it.
    // Also store our thread ID so try_switch can mark the slot as reusable.
    let cpu = smp::cpu_id();
    DEFERRED_THREAD[cpu as usize].store(tid as usize, Ordering::Release);
    DEFERRED_KSTACK[cpu as usize].store(kstack_base, Ordering::Release);

    // Enable interrupts so the timer can preempt us (we may be in a syscall
    // handler where hardware masked IRQs on exception entry).
    arch_enable_irqs();

    // Spin until preempted. The scheduler won't re-enqueue us (Dead state).
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

#[inline(always)]
fn arch_save_and_enable_irqs() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let daif: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, daif",
                "msr daifclr, #2", // Clear IRQ mask → enable IRQs
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
        core::arch::asm!("msr daif, {0}", in(reg) saved as u64);
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
    unsafe { core::arch::asm!("msr daifclr, #2"); }
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
pub fn waitpid(child_tid: ThreadId) -> Option<i32> {
    let sched = SCHEDULER.lock();
    if child_tid as usize >= MAX_THREADS {
        return None;
    }
    let task_id = sched.threads[child_tid as usize].task_id;
    let task = &sched.tasks[task_id as usize];
    if task.exited {
        Some(task.exit_code)
    } else {
        None
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
