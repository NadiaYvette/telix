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
        frame.esr,
        frame.elr,
        frame.spsr
    );
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
extern "C" fn exception_sync_el1(frame_sp: u64) -> u64 {
    // #246 Fix D drain — match x86_64/exception.rs:1438.  Without this,
    // threads that try_switch transitioned to ON_CPU_RELEASING are never
    // CAS'd to ON_CPU_PENDING, so peer CPUs that observe RELEASING fail
    // their dispatch CAS forever and the thread is permanently undispatchable.
    // Surface: SMP=4 aarch64 wedges with tids stuck at on_cpu=4294967293
    // (ON_CPU_RELEASING sentinel) and console_srv spawn hangs after rootfs_srv.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    let frame = unsafe { &mut *(frame_sp as *mut ExceptionFrame) };
    let ec = (frame.esr >> 26) & 0x3f;
    match ec {
        0x15 => {
            // SVC from AArch64. Dispatch syscall.
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::arch::irq::enable();
            crate::syscall::dispatch(frame);
            let _ = crate::arch::irq::disable();
            crate::sched::scheduler::check_preempt_on_return();
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }
        // Data Abort from EL1 (e.g., kernel accessing unmapped address).
        0x25 => {
            let far: u64;
            unsafe {
                core::arch::asm!("mrs {}, far_el1", out(reg) far);
            }
            // #255 anti-interleave: per-CPU FAULT_BUF + handler_write_bytes.
            // Catches the data-side surface of #228 cleanly (see
            // memory/project_aarch64_data_abort_phys_alloc.md).
            {
                use crate::arch::aarch64::serial::{
                    fault_buf_for_current_cpu, handler_write_bytes, put_byte, put_bytes,
                    put_hex_u64,
                };
                let buf = fault_buf_for_current_cpu();
                let mut k = 0;
                put_bytes(buf, &mut k, b"EL1 Data Abort: FAR=");
                put_hex_u64(buf, &mut k, far);
                put_bytes(buf, &mut k, b" ESR=");
                put_hex_u64(buf, &mut k, frame.esr);
                put_bytes(buf, &mut k, b" ELR=");
                put_hex_u64(buf, &mut k, frame.elr);
                put_byte(buf, &mut k, b'\n');
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            loop {
                core::hint::spin_loop();
            }
        }
        _ => {
            let tid = crate::sched::current_thread_id();
            let kstack_base = crate::sched::scheduler::thread_ref(tid).stack_base;
            // #252 anti-interleave: format the whole header into a stack
            // buffer and emit atomically.  Multiple harts hitting the
            // wild-RIP family (#228) at the same instant would otherwise
            // mash their bytes character-by-character through the shared
            // PL011, masking the actual ESR/ELR/SP/LR (see boot
            // aa64-post-riscv-work.log + memory/project_aarch64_post_phase5_wild_rip.md).
            let page_size = crate::mm::page::page_size();
            {
                use crate::arch::aarch64::serial::{
                    fault_buf_for_current_cpu, handler_write_bytes, put_byte, put_bytes,
                    put_dec_u64, put_hex_u64,
                };
                // #255: per-CPU FAULT_BUF (BSS) instead of stack-local — the
                // stack-local approach failed on boot loop-aa64-2 when the
                // very fault we're dumping has a corrupted kstack (see
                // memory/project_aarch64_handler_buf_kstack.md).
                let buf = fault_buf_for_current_cpu();
                let mut k = 0;
                put_bytes(buf, &mut k, b"EL1 Sync: EC=");
                put_hex_u64(buf, &mut k, ec);
                put_bytes(buf, &mut k, b" ESR=");
                put_hex_u64(buf, &mut k, frame.esr);
                put_bytes(buf, &mut k, b" ELR=");
                put_hex_u64(buf, &mut k, frame.elr);
                put_bytes(buf, &mut k, b" SP_EL0=");
                put_hex_u64(buf, &mut k, frame.sp);
                put_bytes(buf, &mut k, b"\n  x30(LR)=");
                put_hex_u64(buf, &mut k, frame.regs[30]);
                put_bytes(buf, &mut k, b" x29(FP)=");
                put_hex_u64(buf, &mut k, frame.regs[29]);
                put_bytes(buf, &mut k, b" x0=");
                put_hex_u64(buf, &mut k, frame.regs[0]);
                put_bytes(buf, &mut k, b"\n  tid=");
                put_dec_u64(buf, &mut k, tid as u64);
                put_bytes(buf, &mut k, b" kstack_base=");
                put_hex_u64(buf, &mut k, kstack_base as u64);
                put_bytes(buf, &mut k, b" frame_sp=");
                put_hex_u64(buf, &mut k, frame_sp);
                put_bytes(buf, &mut k, b" kstack_end=");
                put_hex_u64(buf, &mut k, (kstack_base + page_size) as u64);
                if kstack_base != 0 {
                    let kstack_end = kstack_base + page_size;
                    if (frame_sp as usize) < kstack_base || (frame_sp as usize) >= kstack_end {
                        put_bytes(buf, &mut k, b"\n  BUG: frame_sp OUTSIDE kstack bounds!");
                    }
                }
                put_byte(buf, &mut k, b'\n');
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            // Find which thread (if any) owns the page containing frame_sp.
            let frame_page = (frame_sp as usize) & !(page_size - 1);
            {
                let mut found = false;
                crate::sched::scheduler::SCHED_THREAD_ART.for_each(|key, val| {
                    if found {
                        return;
                    }
                    let t = unsafe { &*(val as *const crate::sched::thread::Thread) };
                    if t.stack_base == frame_page {
                        crate::println!(
                            "  frame_sp page {:#x} belongs to tid={} state={:?} task={}",
                            frame_page,
                            key,
                            t.state,
                            t.task_id
                        );
                        found = true;
                    }
                });
                if !found {
                    crate::println!(
                        "  frame_sp page {:#x} NOT found in any thread's kstack!",
                        frame_page
                    );
                }
            }
            // Dump saved_sp of crashing thread.
            {
                let t = crate::sched::scheduler::thread_ref(tid);
                crate::println!(
                    "  thread[{}].saved_sp={:#x} state={:?}",
                    tid,
                    t.saved_sp,
                    t.state
                );
            }
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
    // #246 Fix D drain — see exception_sync_el1.  Must run BEFORE
    // clear_pending_switch so peer CPUs can dispatch released threads
    // on the same tick we observe the wake.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    // PARK_WOKEN arbitration & per-thread stack_switch_pending clear.
    // Mirrors x86_64's exception handler.  Without this, a thread that
    // parked on an IPC call has stack_switch_pending stuck at true forever,
    // forcing every wake_parked_thread to take the slow deferred-enqueue
    // path — which delegates to clear_pending_switch on the parking CPU,
    // which never runs.  Result: the wake is permanently lost and the
    // parker hangs in PARK_COMMITTED.  This was the aarch64 Phase 5b
    // call_reply_test stall (`memory/project_aarch64_post_phase5_stall.md`).
    crate::sched::scheduler::clear_pending_switch(crate::sched::smp::cpu_id() as usize);
    crate::arch::aarch64::irq::handle_irq();
    // After handling the IRQ (which includes the timer), let the scheduler
    // decide if we should switch threads.
    crate::sched::tick(frame_sp)
}

#[unsafe(no_mangle)]
extern "C" fn exception_serror_el1(frame: &ExceptionFrame) {
    crate::println!("EL1 SError: ESR={:#x} ELR={:#x}", frame.esr, frame.elr);
    loop {
        core::hint::spin_loop();
    }
}
#[unsafe(no_mangle)]
extern "C" fn exception_sync_el0(frame_sp: u64) -> u64 {
    // #246 Fix D drain — see exception_sync_el1.  Must run BEFORE
    // clear_pending_switch and syscall dispatch so released threads
    // are visible to peer CPUs immediately.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    // See exception_irq_el1 — every exception entry needs to drain any
    // pending PARK_WOKEN arbitration so wake_parked_thread's deferred-local
    // path completes.  Must run before syscall dispatch since the syscall
    // itself may park or wake a peer.
    crate::sched::scheduler::clear_pending_switch(crate::sched::smp::cpu_id() as usize);
    let frame = unsafe { &mut *(frame_sp as *mut ExceptionFrame) };
    let ec = (frame.esr >> 26) & 0x3f;
    match ec {
        0x15 => {
            // SVC from AArch64 EL0.
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::arch::irq::enable();
            crate::syscall::dispatch(frame);
            let _ = crate::arch::irq::disable();
            crate::sched::scheduler::check_preempt_on_return();
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }
        // Data Abort from EL0.
        0x24 => handle_abort_el0(frame, frame_sp),
        // Instruction Abort from EL0.
        0x20 => handle_abort_el0(frame, frame_sp),
        _ => {
            crate::println!(
                "EL0 Sync exception: EC={:#x} ESR={:#x} ELR={:#x} — killing thread",
                ec,
                frame.esr,
                frame.elr
            );
            crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
        }
    }
}

/// Handle a data/instruction abort from EL0 by dispatching to the VM fault handler.
fn handle_abort_el0(frame: &ExceptionFrame, frame_sp: u64) -> u64 {
    let far: u64;
    unsafe {
        core::arch::asm!("mrs {}, far_el1", out(reg) far);
    }
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
            far,
            ec,
            frame.elr
        );
        loop {
            core::hint::spin_loop();
        }
    }

    let result = crate::mm::fault::handle_page_fault(aspace_id, far as usize, fault_type);
    match result {
        crate::mm::fault::FaultResult::NeedPager { token } => {
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::mm::pager::initiate_fault(token);
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            frame_sp
        }
        crate::mm::fault::FaultResult::Failed => {
            crate::println!(
                "EL0 Abort: unhandled fault FAR={:#x} EC={:#x} ELR={:#x} — killing thread",
                far,
                ec,
                frame.elr
            );
            crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
        }
        _ => frame_sp,
    }
}

#[unsafe(no_mangle)]
extern "C" fn exception_irq_el0(frame_sp: u64) -> u64 {
    // #246 Fix D drain — see exception_sync_el1.
    crate::sched::scheduler::finalize_release_after_stack_switch();
    // See exception_irq_el1 — PARK_WOKEN arbitration on every IRQ entry.
    crate::sched::scheduler::clear_pending_switch(crate::sched::smp::cpu_id() as usize);
    crate::arch::aarch64::irq::handle_irq();
    crate::sched::tick(frame_sp)
}

#[unsafe(no_mangle)]
extern "C" fn exception_serror_el0(frame: &ExceptionFrame) {
    crate::println!("EL0 SError: ESR={:#x} ELR={:#x}", frame.esr, frame.elr);
    loop {
        core::hint::spin_loop();
    }
}
