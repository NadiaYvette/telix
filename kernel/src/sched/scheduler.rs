//! Scheduler — priority-based round-robin with timer-driven preemption.
//!
//! Context switching works by swapping kernel stack pointers. When a timer
//! IRQ fires, the exception vector saves all registers onto the current
//! thread's kernel stack. If preemption is needed, we save the current SP
//! in the thread's TCB, load the new thread's SP, and the exception return
//! path restores the new thread's registers and `eret`s to it.

use super::thread::{Thread, ThreadId, ThreadState, MAX_THREADS, EXCEPTION_FRAME_SIZE};
use super::task::{Task, MAX_TASKS};
use crate::sync::SpinLock;

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
    current: ThreadId,
    next_thread_id: ThreadId,
    next_task_id: u32,
    idle_thread_id: ThreadId,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: [const { Thread::empty() }; MAX_THREADS],
            tasks: [const { Task::empty() }; MAX_TASKS],
            run_queues: [const { RunQueue::new() }; NUM_PRIORITIES],
            current: 0,
            next_thread_id: 0,
            next_task_id: 0,
            idle_thread_id: 0,
        }
    }

    fn init(&mut self) {
        self.tasks[0].id = 0;
        self.tasks[0].active = true;
        self.next_task_id = 1;

        // Thread 0 = boot/idle thread. Its saved_sp will be set on first preemption.
        self.threads[0].id = 0;
        self.threads[0].state = ThreadState::Running;
        self.threads[0].task_id = 0;
        self.threads[0].priority = 255;
        self.threads[0].quantum = u32::MAX;
        self.threads[0].default_quantum = u32::MAX;
        self.idle_thread_id = 0;
        self.current = 0;
        self.next_thread_id = 1;
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
        // restore_regs will load these values and eret to the entry point.
        let frame_sp = stack_top - EXCEPTION_FRAME_SIZE;
        let frame = frame_sp as *mut u64;
        unsafe {
            // Zero the entire frame (x0-x30 = 0, sp_el0 = 0).
            for i in 0..36 {
                *frame.add(i) = 0;
            }
            // ELR_EL1 = entry point (offset 256 / 8 = 32).
            *frame.add(32) = entry as *const () as u64;
            // SPSR_EL1 = EL1h (0x5), IRQs enabled (DAIF.I = 0).
            // 0x5 = EL1h mode. We want PSTATE.I = 0 (IRQs unmasked).
            *frame.add(33) = 0x5;
            // ESR_EL1 = 0 (offset 34).
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

    fn pick_next(&mut self) -> ThreadId {
        for prio in 0..NUM_PRIORITIES {
            if let Some(id) = self.run_queues[prio].pop() {
                return id;
            }
        }
        self.idle_thread_id
    }

    fn timer_tick(&mut self) -> bool {
        let current = self.current;
        if current == self.idle_thread_id {
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

    /// Attempt to switch threads. Called from IRQ handler with current SP.
    /// Returns the new SP to use for restore_regs (may be same as current if no switch).
    fn try_switch(&mut self, current_sp: u64) -> u64 {
        if !self.timer_tick() {
            return current_sp; // No preemption needed.
        }

        let next_id = self.pick_next();
        let prev_id = self.current;

        if prev_id == next_id {
            return current_sp;
        }

        // Save current thread's SP.
        self.threads[prev_id as usize].saved_sp = current_sp;
        let prev_prio = self.threads[prev_id as usize].priority;
        if self.threads[prev_id as usize].state == ThreadState::Running {
            self.threads[prev_id as usize].state = ThreadState::Ready;
            self.run_queues[prev_prio as usize].push(prev_id);
        }

        // Load next thread's SP.
        self.threads[next_id as usize].state = ThreadState::Running;
        self.current = next_id;
        self.threads[next_id as usize].saved_sp
    }
}

static SCHEDULER: SpinLock<Scheduler> = SpinLock::new(Scheduler::new());

pub fn init() {
    SCHEDULER.lock().init();
    crate::println!("  Scheduler initialized");
}

pub fn spawn(entry: fn() -> !, priority: u8, quantum: u32) -> Option<ThreadId> {
    SCHEDULER.lock().create_thread(entry, priority, quantum)
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

#[allow(dead_code)]
pub fn current_thread_id() -> ThreadId {
    SCHEDULER.lock().current
}
