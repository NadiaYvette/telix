//! M:N green thread (fiber) library.
//!
//! Provides cooperative user-level threading multiplexed onto kernel threads.
//! Fibers are lightweight execution contexts with their own stacks that are
//! scheduled entirely in userspace via context switching.

use core::sync::atomic::{AtomicU32, Ordering};
use crate::syscall;

const MAX_FIBERS: usize = 16;
const MAX_WORKERS: usize = 4;
const FIBER_STACK_SIZE: usize = 4096;

const FIBER_FREE: u8 = 0;
const FIBER_READY: u8 = 1;
const FIBER_RUNNING: u8 = 2;
const FIBER_DONE: u8 = 3;

// --- Architecture-specific fiber context ---

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FiberContext {
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rsp: u64,
}

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FiberContext {
    ra: u64,
    sp: u64,
    s0: u64,
    s1: u64,
    s2: u64,
    s3: u64,
    s4: u64,
    s5: u64,
    s6: u64,
    s7: u64,
    s8: u64,
    s9: u64,
    s10: u64,
    s11: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FiberContext {
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    fp: u64,
    lr: u64,
    sp: u64,
}

impl FiberContext {
    const fn zero() -> Self {
        #[cfg(target_arch = "x86_64")]
        { Self { rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0, rsp: 0 } }
        #[cfg(target_arch = "riscv64")]
        { Self { ra: 0, sp: 0, s0: 0, s1: 0, s2: 0, s3: 0, s4: 0, s5: 0, s6: 0, s7: 0, s8: 0, s9: 0, s10: 0, s11: 0 } }
        #[cfg(target_arch = "aarch64")]
        { Self { x19: 0, x20: 0, x21: 0, x22: 0, x23: 0, x24: 0, x25: 0, x26: 0, x27: 0, x28: 0, fp: 0, lr: 0, sp: 0 } }
    }
}

// --- Fiber state ---

#[derive(Clone, Copy)]
struct Fiber {
    context: FiberContext,
    state: u8,
}

impl Fiber {
    const fn new() -> Self {
        Self { context: FiberContext::zero(), state: FIBER_FREE }
    }
}

// --- Global scheduler state ---

static LOCK: AtomicU32 = AtomicU32::new(0);
/// Count of completed fibers.
pub static COMPLETED: AtomicU32 = AtomicU32::new(0);

static mut TOTAL_FIBERS: u32 = 0;
static mut STACK_BASE: usize = 0;
static mut FIBERS: [Fiber; MAX_FIBERS] = [const { Fiber::new() }; MAX_FIBERS];

// Ready queue (circular buffer).
static mut READY_QUEUE: [u8; MAX_FIBERS] = [0; MAX_FIBERS];
static mut READY_HEAD: usize = 0;
static mut READY_TAIL: usize = 0;
static mut READY_COUNT: usize = 0;

// Per-worker state.
static mut WORKER_CTX: [FiberContext; MAX_WORKERS] = [const { FiberContext::zero() }; MAX_WORKERS];
static mut WORKER_FIBER: [i32; MAX_WORKERS] = [-1; MAX_WORKERS];

// Kernel TID → worker_id mapping.
static mut WORKER_MAP: [i32; 64] = [-1; 64];

// --- Spinlock ---

fn spin_lock() {
    let mut spins = 0u32;
    while LOCK.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        spins += 1;
        if spins & 63 == 0 {
            // On QEMU TCG the lock holder may be on a preempted vCPU.
            // Yielding lets it run and release the lock.
            syscall::yield_now();
        } else {
            core::hint::spin_loop();
        }
    }
}

fn spin_unlock() {
    LOCK.store(0, Ordering::Release);
}

// --- Ready queue operations (must hold LOCK) ---

unsafe fn enqueue_ready(fiber_id: u8) {
    READY_QUEUE[READY_TAIL] = fiber_id;
    READY_TAIL = (READY_TAIL + 1) % MAX_FIBERS;
    READY_COUNT += 1;
}

unsafe fn dequeue_ready() -> i32 {
    if READY_COUNT == 0 {
        return -1;
    }
    let id = READY_QUEUE[READY_HEAD] as i32;
    READY_HEAD = (READY_HEAD + 1) % MAX_FIBERS;
    READY_COUNT -= 1;
    id
}

// --- Context switch (naked functions) ---

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_context(_old: *mut FiberContext, _new: *const FiberContext) {
    core::arch::naked_asm!(
        "mov [rdi+0x00], rbx",
        "mov [rdi+0x08], rbp",
        "mov [rdi+0x10], r12",
        "mov [rdi+0x18], r13",
        "mov [rdi+0x20], r14",
        "mov [rdi+0x28], r15",
        "mov [rdi+0x30], rsp",
        "mov rbx, [rsi+0x00]",
        "mov rbp, [rsi+0x08]",
        "mov r12, [rsi+0x10]",
        "mov r13, [rsi+0x18]",
        "mov r14, [rsi+0x20]",
        "mov r15, [rsi+0x28]",
        "mov rsp, [rsi+0x30]",
        "ret",
    );
}

#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_context(_old: *mut FiberContext, _new: *const FiberContext) {
    core::arch::naked_asm!(
        "sd ra,   0(a0)",
        "sd sp,   8(a0)",
        "sd s0,  16(a0)",
        "sd s1,  24(a0)",
        "sd s2,  32(a0)",
        "sd s3,  40(a0)",
        "sd s4,  48(a0)",
        "sd s5,  56(a0)",
        "sd s6,  64(a0)",
        "sd s7,  72(a0)",
        "sd s8,  80(a0)",
        "sd s9,  88(a0)",
        "sd s10, 96(a0)",
        "sd s11, 104(a0)",
        "ld ra,   0(a1)",
        "ld sp,   8(a1)",
        "ld s0,  16(a1)",
        "ld s1,  24(a1)",
        "ld s2,  32(a1)",
        "ld s3,  40(a1)",
        "ld s4,  48(a1)",
        "ld s5,  56(a1)",
        "ld s6,  64(a1)",
        "ld s7,  72(a1)",
        "ld s8,  80(a1)",
        "ld s9,  88(a1)",
        "ld s10, 96(a1)",
        "ld s11, 104(a1)",
        "ret",
    );
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_context(_old: *mut FiberContext, _new: *const FiberContext) {
    core::arch::naked_asm!(
        "stp x19, x20, [x0, #0]",
        "stp x21, x22, [x0, #16]",
        "stp x23, x24, [x0, #32]",
        "stp x25, x26, [x0, #48]",
        "stp x27, x28, [x0, #64]",
        "stp x29, x30, [x0, #80]",
        "mov x2, sp",
        "str x2, [x0, #96]",
        "ldp x19, x20, [x1, #0]",
        "ldp x21, x22, [x1, #16]",
        "ldp x23, x24, [x1, #32]",
        "ldp x25, x26, [x1, #48]",
        "ldp x27, x28, [x1, #64]",
        "ldp x29, x30, [x1, #80]",
        "ldr x2, [x1, #96]",
        "mov sp, x2",
        "ret",
    );
}

// --- Fiber entry trampoline ---

/// Called when a new fiber starts. Callee-saved registers contain entry/arg.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn fiber_trampoline() {
    core::arch::naked_asm!(
        "mov rdi, r13",      // arg → first function argument
        "call r12",          // call entry(arg)
        "call {exit}",       // fiber_exit()
        "ud2",               // unreachable
        exit = sym fiber_exit,
    );
}

#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
unsafe extern "C" fn fiber_trampoline() {
    core::arch::naked_asm!(
        "mv a0, s1",         // arg → first function argument
        "jalr ra, s0, 0",   // call entry(arg)
        "call {exit}",       // fiber_exit()
        "unimp",             // unreachable
        exit = sym fiber_exit,
    );
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn fiber_trampoline() {
    core::arch::naked_asm!(
        "mov x0, x20",       // arg → first function argument
        "blr x19",           // call entry(arg)
        "bl {exit}",         // fiber_exit()
        "brk #0",            // unreachable
        exit = sym fiber_exit,
    );
}

// --- Public API ---

/// Initialize the green thread scheduler. `stack_page` is the base VA of
/// an mmap'd page used for fiber stacks.
pub fn init(stack_page: usize) {
    unsafe {
        STACK_BASE = stack_page;
        TOTAL_FIBERS = 0;
        READY_HEAD = 0;
        READY_TAIL = 0;
        READY_COUNT = 0;
        COMPLETED.store(0, Ordering::Relaxed);
        for i in 0..MAX_FIBERS {
            FIBERS[i].state = FIBER_FREE;
        }
        for i in 0..MAX_WORKERS {
            WORKER_FIBER[i] = -1;
        }
        for i in 0..64 {
            WORKER_MAP[i] = -1;
        }
    }
}

/// Spawn a new fiber. Returns the fiber ID or -1 on error.
pub fn spawn(entry: fn(u64), arg: u64) -> i32 {
    spin_lock();
    let fiber_id = unsafe {
        let mut id = -1i32;
        for i in 0..MAX_FIBERS {
            if FIBERS[i].state == FIBER_FREE {
                id = i as i32;
                break;
            }
        }
        if id < 0 {
            spin_unlock();
            return -1;
        }
        let i = id as usize;

        // Set up the fiber's stack.
        let stack_base = STACK_BASE + i * FIBER_STACK_SIZE;
        let stack_top = stack_base + FIBER_STACK_SIZE;

        // Initialize context for first switch.
        let mut ctx = FiberContext::zero();

        #[cfg(target_arch = "x86_64")]
        {
            // Push trampoline address on the fiber's stack.
            let ret_addr_slot = (stack_top - 8) as *mut u64;
            core::ptr::write(ret_addr_slot, fiber_trampoline as u64);
            ctx.rsp = (stack_top - 8) as u64;
            ctx.r12 = entry as u64; // entry function
            ctx.r13 = arg;          // argument
        }

        #[cfg(target_arch = "riscv64")]
        {
            ctx.sp = stack_top as u64;
            ctx.ra = fiber_trampoline as u64;
            ctx.s0 = entry as u64;  // entry function
            ctx.s1 = arg;           // argument
        }

        #[cfg(target_arch = "aarch64")]
        {
            ctx.sp = stack_top as u64;
            ctx.lr = fiber_trampoline as u64;
            ctx.x19 = entry as u64; // entry function
            ctx.x20 = arg;          // argument
        }

        FIBERS[i].context = ctx;
        FIBERS[i].state = FIBER_READY;
        TOTAL_FIBERS += 1;
        enqueue_ready(i as u8);
        id
    };
    spin_unlock();
    fiber_id
}

/// Worker entry point. Call from each kernel thread used as a green scheduler worker.
/// `worker_id` should be a unique index (0, 1, 2, ...).
#[unsafe(no_mangle)]
pub extern "C" fn green_worker_entry(worker_id: u64) {
    let wid = worker_id as usize;
    let tid = syscall::sa_getid() as usize;
    unsafe { WORKER_MAP[tid] = wid as i32; }

    loop {
        // Try to dequeue a ready fiber.
        spin_lock();
        let fiber_id = unsafe { dequeue_ready() };
        spin_unlock();

        if fiber_id < 0 {
            // No ready fiber. Check if all done.
            if COMPLETED.load(Ordering::Relaxed) >= unsafe { TOTAL_FIBERS } {
                break;
            }
            // Use yield_block (WFI/HLT) so we don't busy-loop on QEMU TCG.
            // A tight yield_now() loop can starve the other worker from
            // making progress.
            syscall::yield_block();
            continue;
        }

        let fid = fiber_id as usize;
        unsafe {
            WORKER_FIBER[wid] = fiber_id;
            FIBERS[fid].state = FIBER_RUNNING;
            // Switch to fiber. Saves worker context, restores fiber context.
            switch_context(
                &mut WORKER_CTX[wid] as *mut FiberContext,
                &FIBERS[fid].context as *const FiberContext,
            );
            // Returned from fiber (it yielded or exited).
        }
    }

    syscall::exit(0);
}

/// Cooperatively yield the current fiber. Saves context, enqueues self,
/// and switches back to the worker to pick the next fiber.
pub fn fiber_yield() {
    let tid = syscall::sa_getid() as usize;
    let wid = unsafe { WORKER_MAP[tid] } as usize;
    let fid = unsafe { WORKER_FIBER[wid] } as usize;

    // Re-enqueue this fiber.
    spin_lock();
    unsafe {
        FIBERS[fid].state = FIBER_READY;
        enqueue_ready(fid as u8);
    }
    spin_unlock();

    // Switch back to worker.
    unsafe {
        switch_context(
            &mut FIBERS[fid].context as *mut FiberContext,
            &WORKER_CTX[wid] as *const FiberContext,
        );
    }
    // Resumed: another worker switched back to this fiber.
}

/// Called when a fiber's entry function returns. Marks the fiber done
/// and switches back to the worker.
extern "C" fn fiber_exit() -> ! {
    let tid = syscall::sa_getid() as usize;
    let wid = unsafe { WORKER_MAP[tid] } as usize;
    let fid = unsafe { WORKER_FIBER[wid] } as usize;

    unsafe { FIBERS[fid].state = FIBER_DONE; }
    COMPLETED.fetch_add(1, Ordering::Relaxed);

    // Switch back to worker (saves dead fiber context, restores worker).
    unsafe {
        switch_context(
            &mut FIBERS[fid].context as *mut FiberContext,
            &WORKER_CTX[wid] as *const FiberContext,
        );
    }

    // Unreachable: worker never switches back to a done fiber.
    loop { core::hint::spin_loop(); }
}
