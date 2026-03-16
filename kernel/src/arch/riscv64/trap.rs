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
const SCAUSE_ECALL_FROM_UMODE: u64 = 8;
const SCAUSE_ECALL_FROM_SMODE: u64 = 9;

/// SBI TIME extension ID and function.
const SBI_EXT_TIME: u64 = 0x54494D45;
const SBI_FUN_SET_TIMER: u64 = 0;

/// Read the `time` CSR (or rdtime pseudo-instruction).
fn read_time() -> u64 {
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
    // Set stvec to our trap vector (direct mode).
    unsafe {
        core::arch::asm!(
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

    // Enable S-mode timer interrupt in sie.
    unsafe {
        // sie.STIE = bit 5
        core::arch::asm!("csrs sie, {}", in(reg) 1u64 << 5);
    }

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

    // Enable S-mode timer interrupt in sie.
    unsafe {
        core::arch::asm!("csrs sie, {}", in(reg) 1u64 << 5);
    }
}

/// Enable S-mode interrupts (set sstatus.SIE).
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("csrs sstatus, {}", in(reg) 1u64 << 1);
    }
}

/// Disable S-mode interrupts (clear sstatus.SIE).
#[allow(dead_code)]
pub fn disable_interrupts() {
    unsafe {
        core::arch::asm!("csrc sstatus, {}", in(reg) 1u64 << 1);
    }
}

/// Handle timer interrupt: reset the timer and increment tick count.
fn handle_timer_irq() {
    let ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    // Rearm the timer.
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    let now = read_time();
    sbi_set_timer(now + interval);

    // Print every 100 ticks (once per second).
    if ticks % 100 == 0 {
        crate::println!("[tick {}]", ticks);
    }
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

        SCAUSE_ECALL_FROM_SMODE | SCAUSE_ECALL_FROM_UMODE => {
            // Advance sepc past the ecall instruction (4 bytes).
            frame.sepc += 4;
            crate::syscall::dispatch(frame);
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
