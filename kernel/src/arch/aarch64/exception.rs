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
extern "C" fn exception_sync_el1(frame_sp: u64) -> u64 {
    let frame = unsafe { &mut *(frame_sp as *mut ExceptionFrame) };
    let ec = (frame.esr >> 26) & 0x3f;
    match ec {
        0x15 => {
            // SVC from AArch64. Dispatch syscall.
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::syscall::dispatch(frame);
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }
        // Data Abort from EL1 (e.g., kernel accessing unmapped address).
        0x25 => {
            let far: u64;
            unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) far); }
            crate::println!(
                "EL1 Data Abort: FAR={:#x} ESR={:#x} ELR={:#x}",
                far, frame.esr, frame.elr
            );
            loop { core::hint::spin_loop(); }
        }
        _ => {
            crate::println!(
                "EL1 Sync exception: EC={:#x} ESR={:#x} ELR={:#x} SP={:#x}",
                ec, frame.esr, frame.elr, frame.sp
            );
            // Dump x29 (FP) and x30 (LR) for stack trace hints.
            crate::println!(
                "  x30(LR)={:#x} x29(FP)={:#x} x0={:#x}",
                frame.regs[30], frame.regs[29], frame.regs[0]
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
extern "C" fn exception_sync_el0(frame_sp: u64) -> u64 {
    let frame = unsafe { &mut *(frame_sp as *mut ExceptionFrame) };
    let ec = (frame.esr >> 26) & 0x3f;
    match ec {
        0x15 => {
            // SVC from AArch64 EL0.
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::syscall::dispatch(frame);
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }
        // Data Abort from EL0.
        0x24 => {
            handle_abort_el0(frame, frame_sp)
        }
        // Instruction Abort from EL0.
        0x20 => {
            handle_abort_el0(frame, frame_sp)
        }
        _ => {
            crate::println!(
                "EL0 Sync exception: EC={:#x} ESR={:#x} ELR={:#x} — killing thread",
                ec, frame.esr, frame.elr
            );
            crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
        }
    }
}

/// Handle a data/instruction abort from EL0 by dispatching to the VM fault handler.
fn handle_abort_el0(frame: &ExceptionFrame, frame_sp: u64) -> u64 {
    let far: u64;
    unsafe { core::arch::asm!("mrs {}, far_el1", out(reg) far); }
    let ec = (frame.esr >> 26) & 0x3f;
    let iss = frame.esr & 0x1FFFFFF;
    let fault_type = if ec == 0x20 {
        crate::mm::fault::FaultType::Exec
    } else if iss & (1 << 6) != 0 {
        // WnR bit (bit 6 of ISS for data aborts): 1 = write.
        crate::mm::fault::FaultType::Write
    } else {
        crate::mm::fault::FaultType::Read
    };

    // Get the current task's address space.
    let aspace_id = crate::sched::current_aspace_id();
    if aspace_id == 0 {
        crate::println!(
            "EL0 Abort with no address space: FAR={:#x} EC={:#x} ELR={:#x}",
            far, ec, frame.elr
        );
        loop { core::hint::spin_loop(); }
    }

    let result = crate::mm::fault::handle_page_fault(aspace_id, far as usize, fault_type);
    match result {
        crate::mm::fault::FaultResult::NeedPager { token } => {
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::mm::pager::initiate_fault(token);
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 { return pending; }
            frame_sp
        }
        crate::mm::fault::FaultResult::Failed => {
            crate::println!(
                "EL0 Abort: unhandled fault FAR={:#x} EC={:#x} ELR={:#x} — killing thread",
                far, ec, frame.elr
            );
            crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
        }
        _ => frame_sp,
    }
}

#[unsafe(no_mangle)]
extern "C" fn exception_irq_el0(frame_sp: u64) -> u64 {
    crate::arch::aarch64::irq::handle_irq();
    crate::sched::tick(frame_sp)
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
