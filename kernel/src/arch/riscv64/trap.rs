//! RISC-V trap handling.
//!
//! RISC-V uses a single trap vector for all exceptions and interrupts.
//! The trap entry/exit assembly is in vectors.S.
//! This file contains the Rust handler functions called from those stubs.

use core::sync::atomic::{AtomicU64, Ordering};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Timer interval in time-base ticks (set during init).
static TIMER_INTERVAL: AtomicU64 = AtomicU64::new(0);

/// Exception/trap context saved on the stack by the vector entry stub.
/// Layout must match vectors.S exactly.
#[repr(C)]
pub struct TrapFrame {
    pub regs: [u64; 31], // x1-x31 (indices 0..31, where index i = register x(i+1))
    pub sepc: u64,       // saved exception PC
    pub sstatus: u64,    // saved status register
    pub scause: u64,     // trap cause (saved for convenience)
}

// scause values
const SCAUSE_INTERRUPT_BIT: u64 = 1 << 63;
const SCAUSE_S_TIMER_IRQ: u64 = SCAUSE_INTERRUPT_BIT | 5;
const SCAUSE_S_EXTERNAL_IRQ: u64 = SCAUSE_INTERRUPT_BIT | 9;
const SCAUSE_ECALL_FROM_UMODE: u64 = 8;
const SCAUSE_ECALL_FROM_SMODE: u64 = 9;
const SCAUSE_INST_PAGE_FAULT: u64 = 12;
const SCAUSE_LOAD_PAGE_FAULT: u64 = 13;
const SCAUSE_STORE_PAGE_FAULT: u64 = 15;

/// SBI TIME extension ID and function.
const SBI_EXT_TIME: u64 = 0x54494D45;
const SBI_FUN_SET_TIMER: u64 = 0;

/// Read the `time` CSR (or rdtime pseudo-instruction).
pub fn read_time() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) val) };
    val
}

/// Set the next timer deadline via SBI ecall.
fn sbi_set_timer(stime_value: u64) {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a0") stime_value,
            in("a6") SBI_FUN_SET_TIMER,
            in("a7") SBI_EXT_TIME,
            lateout("a0") _,
            lateout("a1") _,
        );
    }
}

/// Initialize trap handling: set stvec, configure timer.
pub fn init() {
    // Set stvec to our trap vector (direct mode) and ensure sscratch = 0 (S-mode).
    unsafe {
        core::arch::asm!(
            "csrw sscratch, zero",
            "la {tmp}, _trap_entry",
            "csrw stvec, {tmp}",
            tmp = out(reg) _,
        );
    }
    crate::println!("  Trap vector installed");

    // Configure the timer.
    // QEMU riscv virt timebase is 10 MHz. We want ~100 Hz.
    let freq: u64 = 10_000_000; // 10 MHz timebase
    let interval = freq / 100;  // 100 Hz
    TIMER_INTERVAL.store(interval, Ordering::Relaxed);

    // Set first timer deadline.
    let now = read_time();
    sbi_set_timer(now + interval);

    // Enable S-mode timer interrupt and external interrupt in sie.
    unsafe {
        // sie.STIE = bit 5, sie.SEIE = bit 9
        core::arch::asm!("csrs sie, {}", in(reg) (1u64 << 5) | (1u64 << 9));
    }

    // Initialize PLIC for hart 0.
    super::plic::init(0);

    crate::println!("  Timer initialized: timebase={}Hz, interval={} ticks ({}ms)",
        freq, interval, 1000 * interval / freq);
}

/// Initialize trap/timer on a secondary hart.
pub fn init_ap() {
    // Set stvec (already done in assembly, but be safe).
    unsafe {
        core::arch::asm!(
            "la {tmp}, _trap_entry",
            "csrw stvec, {tmp}",
            tmp = out(reg) _,
        );
    }

    // Set first timer deadline for this hart.
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    let now = read_time();
    sbi_set_timer(now + interval);

    // Enable S-mode timer and external interrupts in sie.
    unsafe {
        core::arch::asm!("csrs sie, {}", in(reg) (1u64 << 5) | (1u64 << 9));
    }

    // Initialize PLIC for this hart.
    let hart: u32;
    unsafe { core::arch::asm!("mv {0}, tp", out(reg) hart); }
    super::plic::init(hart);
}

/// Enable S-mode interrupts (set sstatus.SIE).
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("csrs sstatus, {}", in(reg) 1u64 << 1);
    }
}

/// Re-arm the timer so the next interrupt is one interval from now.
/// Used before entering U-mode to prevent a stale timer firing immediately.
#[allow(dead_code)]
pub fn rearm_timer() {
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    let now = read_time();
    sbi_set_timer(now + interval);
}

/// Disable S-mode interrupts (clear sstatus.SIE).
#[allow(dead_code)]
pub fn disable_interrupts() {
    unsafe {
        core::arch::asm!("csrc sstatus, {}", in(reg) 1u64 << 1);
    }
}

/// Handle S-mode external interrupt via PLIC.
fn handle_external_irq() {
    // Determine hart ID from tp register.
    let hart: u32;
    unsafe { core::arch::asm!("mv {0}, tp", out(reg) hart); }

    let irq = super::plic::claim(hart);
    if irq == 0 {
        return; // Spurious
    }

    // Virtio-blk on QEMU virt is PLIC IRQ 1-8 (first virtio device = highest address = IRQ 8,
    // but QEMU virt maps them in reverse: device at 0x10008000 = IRQ 8, 0x10007000 = IRQ 7, etc.)
    // The virtio-blk device gets the first available IRQ. With a single virtio device added
    // via -device, it typically gets IRQ 1. We match any IRQ in 1..=8 to the virtio-blk handler.
    match irq {
        1..=8 => {
            // Try userspace dispatch first; fall back to kernel driver.
            if !crate::io::irq_dispatch::handle_irq(irq) {
                crate::drivers::virtio_blk::irq_handler();
            }
        }
        _ => {
            crate::println!("PLIC: unhandled IRQ {}", irq);
        }
    }

    super::plic::complete(hart, irq);
}

/// Handle timer interrupt: reset the timer and increment tick count.
fn handle_timer_irq() {
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    // Rearm the timer.
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    let now = read_time();
    sbi_set_timer(now + interval);

    // Uncomment for debugging:
    // if ticks % 100 == 0 { crate::println!("[tick {}]", ticks); }
}

/// Main Rust trap handler. Called from vectors.S with current SP as argument.
/// For timer interrupts, calls scheduler tick and returns (potentially new) SP.
/// For other traps, handles and returns same SP.
#[unsafe(no_mangle)]
extern "C" fn trap_handler(frame_sp: u64) -> u64 {
    let frame = unsafe { &mut *(frame_sp as *mut TrapFrame) };
    let scause = frame.scause;

    match scause {
        SCAUSE_S_TIMER_IRQ => {
            handle_timer_irq();
            // Let the scheduler decide if we should switch threads.
            crate::sched::tick(frame_sp)
        }

        SCAUSE_S_EXTERNAL_IRQ => {
            handle_external_irq();
            frame_sp
        }

        SCAUSE_ECALL_FROM_SMODE | SCAUSE_ECALL_FROM_UMODE => {
            // Advance sepc past the ecall instruction (4 bytes).
            frame.sepc += 4;
            crate::syscall::dispatch(frame);
            frame_sp
        }

        SCAUSE_INST_PAGE_FAULT | SCAUSE_LOAD_PAGE_FAULT | SCAUSE_STORE_PAGE_FAULT => {
            let stval = read_stval();
            let fault_type = match scause {
                SCAUSE_INST_PAGE_FAULT => crate::mm::fault::FaultType::Exec,
                SCAUSE_STORE_PAGE_FAULT => crate::mm::fault::FaultType::Write,
                _ => crate::mm::fault::FaultType::Read,
            };
            let aspace_id = crate::sched::current_aspace_id();
            if aspace_id == 0 {
                let cpu = crate::sched::smp::cpu_id();
                let tid = crate::sched::current_thread_id();
                let spp = (frame.sstatus >> 8) & 1;
                crate::println!(
                    "Kernel page fault: cause={:#x} sepc={:#x} stval={:#x} cpu={} tid={} spp={} sstatus={:#x} sp(frame)={:#x}",
                    scause, frame.sepc, stval, cpu, tid, spp, frame.sstatus, frame.regs[1]
                );
                loop { core::hint::spin_loop(); }
            }
            let result = crate::mm::fault::handle_page_fault(aspace_id, stval as usize, fault_type);
            if result == crate::mm::fault::FaultResult::Failed {
                crate::println!(
                    "Unhandled page fault: cause={:#x} sepc={:#x} stval={:#x}",
                    scause, frame.sepc, stval
                );
                loop { core::hint::spin_loop(); }
            }
            frame_sp
        }

        _ => {
            if scause & SCAUSE_INTERRUPT_BIT != 0 {
                crate::println!(
                    "Unhandled S-mode interrupt: cause={:#x} sepc={:#x}",
                    scause & !SCAUSE_INTERRUPT_BIT, frame.sepc
                );
            } else {
                crate::println!(
                    "Unhandled S-mode exception: cause={:#x} sepc={:#x} stval={:#x}",
                    scause, frame.sepc, read_stval()
                );
                loop {
                    core::hint::spin_loop();
                }
            }
            frame_sp
        }
    }
}

/// Read the stval CSR.
fn read_stval() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("csrr {}, stval", out(reg) val) };
    val
}
