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
            // Fix: kstack is `kstack_size()` bytes (1 MiB on aarch64 64K
            // pages — `KSTACK_ORDER=4`), NOT one page.  Previous emits
            // claimed `BUG: OUTSIDE kstack bounds` whenever frame_sp was
            // beyond the first page; that was always a false positive
            // for any thread with non-trivial kernel work.
            let kstack_size = crate::sched::scheduler::kstack_size();
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
                put_hex_u64(buf, &mut k, (kstack_base + kstack_size) as u64);
                if kstack_base != 0 {
                    let kstack_end = kstack_base + kstack_size;
                    if (frame_sp as usize) < kstack_base || (frame_sp as usize) >= kstack_end {
                        put_bytes(buf, &mut k, b"\n  BUG: frame_sp OUTSIDE kstack bounds!");
                    }
                }
                put_byte(buf, &mut k, b'\n');
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            // Find ALL threads whose kstack window contains frame_sp's
            // page.  If two or more come up, that's direct evidence of a
            // VA-window or PA-window double-issue (Signature A of
            // memory/project_aarch64_post_migration_signatures.md).
            // Also print the offending thread (`tid`)'s own kstack_base
            // alongside, so the reader can compare windows at a glance.
            let frame_page = (frame_sp as usize) & !(page_size - 1);
            {
                use crate::arch::aarch64::serial::{
                    fault_buf_for_current_cpu, handler_write_bytes, put_bytes, put_dec_u64,
                    put_hex_u64,
                };
                let mut owner_count: u32 = 0;
                crate::sched::scheduler::SCHED_THREAD_ART.for_each(|key, val| {
                    let t = unsafe { &*(val as *const crate::sched::thread::Thread) };
                    if t.stack_base != 0
                        && frame_page >= t.stack_base
                        && frame_page < t.stack_base + kstack_size
                    {
                        let buf = fault_buf_for_current_cpu();
                        let mut k = 0;
                        put_bytes(buf, &mut k, b"  frame_sp page ");
                        put_hex_u64(buf, &mut k, frame_page as u64);
                        put_bytes(buf, &mut k, b" claimed by tid=");
                        put_dec_u64(buf, &mut k, key);
                        put_bytes(buf, &mut k, b" task=");
                        put_dec_u64(buf, &mut k, t.task_id as u64);
                        put_bytes(buf, &mut k, b" kstack=[");
                        put_hex_u64(buf, &mut k, t.stack_base as u64);
                        put_bytes(buf, &mut k, b"..");
                        put_hex_u64(buf, &mut k, (t.stack_base + kstack_size) as u64);
                        put_bytes(buf, &mut k, b")\n");
                        handler_write_bytes(&buf[..k.min(buf.len())]);
                        owner_count += 1;
                    }
                });
                if owner_count == 0 {
                    let buf = fault_buf_for_current_cpu();
                    let mut k = 0;
                    put_bytes(buf, &mut k, b"  frame_sp page ");
                    put_hex_u64(buf, &mut k, frame_page as u64);
                    put_bytes(buf, &mut k, b" NOT found in any thread's kstack!\n");
                    handler_write_bytes(&buf[..k.min(buf.len())]);
                } else if owner_count > 1 {
                    let buf = fault_buf_for_current_cpu();
                    let mut k = 0;
                    put_bytes(buf, &mut k, b"  ALIAS: ");
                    put_dec_u64(buf, &mut k, owner_count as u64);
                    put_bytes(buf, &mut k, b" threads claim the same kstack page!\n");
                    handler_write_bytes(&buf[..k.min(buf.len())]);
                }
            }
            // Dump saved_sp + alternate sp fields + corruption canary.
            // #228 root-cause attribution: saved_sp_source tells which
            // writer last touched saved_sp (1=try_switch, 2=voluntary,
            // 3=pre_save_frame, 4=init; anything else = scribble).
            // canary_around_source != THREAD_CANARY_MAGIC means the
            // Thread struct mid-region was clobbered (slab/heap overlap).
            {
                use crate::arch::aarch64::serial::{
                    fault_buf_for_current_cpu, handler_write_bytes, put_byte, put_bytes,
                    put_dec_u64, put_hex_u64,
                };
                let t = crate::sched::scheduler::thread_ref(tid);
                let buf = fault_buf_for_current_cpu();
                let mut k = 0;
                put_bytes(buf, &mut k, b"  thread[");
                put_dec_u64(buf, &mut k, tid as u64);
                put_bytes(buf, &mut k, b"].saved_sp=");
                put_hex_u64(buf, &mut k, t.saved_sp);
                put_bytes(buf, &mut k, b" src=");
                put_dec_u64(buf, &mut k, t.saved_sp_source as u64);
                put_bytes(buf, &mut k, b" canary=");
                put_hex_u64(buf, &mut k, t.canary_around_source);
                if t.canary_around_source != crate::sched::thread::THREAD_CANARY_MAGIC {
                    put_bytes(buf, &mut k, b" CORRUPT");
                }
                put_bytes(buf, &mut k, b"\n  ipc_frame_sp=");
                put_hex_u64(buf, &mut k, t.ipc_frame_sp);
                put_bytes(buf, &mut k, b" syscall_frame_sp=");
                put_hex_u64(buf, &mut k, t.syscall_frame_sp);
                put_bytes(buf, &mut k, b" personality_frame_sp=");
                put_hex_u64(buf, &mut k, t.personality_frame_sp);
                // SPSR_EL1 from trap frame.  PSTATE.M (bits 3:0) at
                // vec_sync_el1 entry is hardware-guaranteed non-zero —
                // EL0 traps route through vec_sync_el0 instead.  So
                // PSTATE.M=0 here means the saved spsr slot was never
                // written (sentinel low-bits) rather than that we
                // actually came from EL0.  Useful diagnostic to flag
                // sentinel-filled frames.
                put_bytes(buf, &mut k, b"\n  spsr=");
                put_hex_u64(buf, &mut k, frame.spsr);
                put_bytes(buf, &mut k, b" PSTATE.M=");
                put_hex_u64(buf, &mut k, frame.spsr & 0xF);
                if (frame.spsr & 0xF) == 0 {
                    // Impossible from a real vec_sync_el1 entry; the slot
                    // holds sentinel low-bits (e.g. CAFEBABE_00000000).
                    put_bytes(buf, &mut k, b" SENTINEL-LOW");
                } else if (frame.spsr & 0xF) == 4 {
                    put_bytes(buf, &mut k, b" EL1t");
                } else if (frame.spsr & 0xF) == 5 {
                    put_bytes(buf, &mut k, b" EL1h");
                }
                put_byte(buf, &mut k, b'\n');
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            // Targeted probe: read the EXACT kstack offsets where save_regs
            // is supposed to have stored x30/sp_el0/elr/spsr/esr.  Cross-
            // check against what `frame.X` returned via the Rust struct
            // to detect "save_regs late portion didn't run" vs
            // "post-handler scribble overwrote the slots".
            {
                use crate::arch::aarch64::serial::{
                    fault_buf_for_current_cpu, handler_write_bytes, put_bytes, put_hex_u64,
                };
                let buf = fault_buf_for_current_cpu();
                let mut k = 0;
                put_bytes(buf, &mut k, b"  trap-frame system-reg slots:\n");
                let base = frame_sp as usize;
                let kstack_top = kstack_base + kstack_size;
                let slots: [(usize, &[u8]); 5] = [
                    (240, b"    [+240 x30] "),
                    (248, b"    [+248 sp ] "),
                    (256, b"    [+256 elr] "),
                    (264, b"    [+264 spsr] "),
                    (272, b"    [+272 esr] "),
                ];
                for (off, label) in slots {
                    let va = base + off;
                    if va + 8 <= kstack_top {
                        let val = unsafe { core::ptr::read_volatile(va as *const u64) };
                        put_bytes(buf, &mut k, label);
                        put_hex_u64(buf, &mut k, val);
                        if val == 0xCAFEBABE_00000000 {
                            put_bytes(buf, &mut k, b" SENTINEL");
                        } else if val == 0 {
                            put_bytes(buf, &mut k, b" ZERO");
                        }
                        put_bytes(buf, &mut k, b"\n");
                    }
                }
                handler_write_bytes(&buf[..k.min(buf.len())]);
            }
            // Walk UPWARD from frame_sp (toward kstack_end, higher VAs)
            // to dump the caller-frame chain.  Upward addresses are the
            // older frames that the current execution was using before
            // the trap — definitely mapped.  Downward (deeper) addresses
            // could be lazy-mapped pages we haven't faulted in yet; that
            // direction is unsafe to read in the EL1 Sync handler and
            // an earlier draft of this probe hung on a nested fault
            // there (see memory/project_aarch64_tid29_linux_srv_wild_jump.md).
            {
                use crate::arch::aarch64::serial::{
                    fault_buf_for_current_cpu, handler_write_bytes, put_byte, put_bytes,
                    put_hex_u64,
                };
                let buf = fault_buf_for_current_cpu();
                let mut k = 0;
                put_bytes(buf, &mut k, b"  kstack [frame_sp .. kstack_end), upward:\n");
                let start = (frame_sp as usize) & !7;
                let kstack_top = kstack_base + kstack_size;
                let max_qwords = 14usize;
                let end = core::cmp::min(start + max_qwords * 8, kstack_top);
                let mut va = start;
                while va < end {
                    let val = unsafe { core::ptr::read_volatile(va as *const u64) };
                    put_bytes(buf, &mut k, b"    [");
                    put_hex_u64(buf, &mut k, va as u64);
                    if va == (frame_sp as usize) {
                        put_bytes(buf, &mut k, b"*] ");
                    } else {
                        put_bytes(buf, &mut k, b" ] ");
                    }
                    put_hex_u64(buf, &mut k, val);
                    if val == 0xCAFEBABE_00000000 {
                        put_bytes(buf, &mut k, b" SENTINEL");
                    } else if val & 0xFFFFFFFF_00000000 == 0xCAFEBABE_00000000 {
                        put_bytes(buf, &mut k, b" SENTINEL-HI");
                    }
                    put_byte(buf, &mut k, b'\n');
                    va += 8;
                }
                handler_write_bytes(&buf[..k.min(buf.len())]);
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
