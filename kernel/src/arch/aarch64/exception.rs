//! AArch64 exception handlers.
//!
//! The vector table and assembly stubs are in vectors.S.
//! This file contains the Rust handler functions called from those stubs.

/// Exception context saved on the stack by the vector entry stubs.
#[repr(C)]
pub struct ExceptionFrame {
    pub regs: [u64; 31], // x0-x30
    pub sp: u64,         // saved SP_EL0
    pub elr: u64,        // exception link register
    pub spsr: u64,       // saved program status register
    pub esr: u64,        // exception syndrome register
}

/// Install the exception vector table.
pub fn init() {
    unsafe {
        core::arch::asm!(
            "adr x0, __exception_vectors",
            "msr vbar_el1, x0",
            "isb",
            out("x0") _,
        );
    }
    crate::println!("  Exception vectors installed");
}

#[unsafe(no_mangle)]
extern "C" fn exception_unhandled(frame: &ExceptionFrame) {
    crate::println!(
        "UNHANDLED EXCEPTION: ESR={:#x} ELR={:#x} SPSR={:#x}",
        frame.esr, frame.elr, frame.spsr
    );
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn exception_sync_el1(frame: &mut ExceptionFrame) {
    let ec = (frame.esr >> 26) & 0x3f;
    match ec {
        0x15 => {
            // SVC from AArch64. Dispatch syscall.
            crate::syscall::dispatch(frame);
        }
        _ => {
            crate::println!(
                "EL1 Sync exception: EC={:#x} ESR={:#x} ELR={:#x}",
                ec, frame.esr, frame.elr
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

/// IRQ handler for EL1. Returns the (potentially new) SP for context switching.
/// If the scheduler decides to preempt, it returns a different thread's SP.
#[unsafe(no_mangle)]
extern "C" fn exception_irq_el1(frame_sp: u64) -> u64 {
    crate::arch::aarch64::irq::handle_irq();
    // After handling the IRQ (which includes the timer), let the scheduler
    // decide if we should switch threads.
    crate::sched::tick(frame_sp)
}

#[unsafe(no_mangle)]
extern "C" fn exception_serror_el1(frame: &ExceptionFrame) {
    crate::println!(
        "EL1 SError: ESR={:#x} ELR={:#x}",
        frame.esr, frame.elr
    );
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn exception_sync_el0(frame: &mut ExceptionFrame) {
    let ec = (frame.esr >> 26) & 0x3f;
    match ec {
        0x15 => {
            // SVC from AArch64 EL0.
            crate::syscall::dispatch(frame);
        }
        _ => {
            crate::println!(
                "EL0 Sync exception: EC={:#x} ESR={:#x} ELR={:#x}",
                ec, frame.esr, frame.elr
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn exception_irq_el0(_frame: &ExceptionFrame) {
    crate::arch::aarch64::irq::handle_irq();
}

#[unsafe(no_mangle)]
extern "C" fn exception_serror_el0(frame: &ExceptionFrame) {
    crate::println!(
        "EL0 SError: ESR={:#x} ELR={:#x}",
        frame.esr, frame.elr
    );
    loop {
        core::hint::spin_loop();
    }
}
