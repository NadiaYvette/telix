//! x86-64 exception handlers.
//!
//! The vector stubs and IDT loading are in vectors.S and idt.rs.
//! This file contains the ExceptionFrame definition and Rust handlers.

/// Exception context saved on the stack by the vector entry stubs.
///
/// Layout (matching vectors.S push order):
///   regs[0]  = r15
///   regs[1]  = r14
///   regs[2]  = r13
///   regs[3]  = r12
///   regs[4]  = r11
///   regs[5]  = r10
///   regs[6]  = r9
///   regs[7]  = r8
///   regs[8]  = rbp
///   regs[9]  = rdi
///   regs[10] = rsi
///   regs[11] = rdx
///   regs[12] = rcx
///   regs[13] = rbx
///   regs[14] = rax
///   regs[15] = vector_number
///   regs[16] = error_code (real or dummy)
///   regs[17] = rip        (pushed by CPU)
///   regs[18] = cs         (pushed by CPU)
///   regs[19] = rflags     (pushed by CPU)
///   regs[20] = rsp        (pushed by CPU)
///   regs[21] = ss         (pushed by CPU)
#[repr(C)]
pub struct ExceptionFrame {
    pub regs: [u64; 22],
}

// Named indices into ExceptionFrame.regs for convenience.
#[allow(dead_code)]
impl ExceptionFrame {
    pub fn rax(&self) -> u64 {
        self.regs[14]
    }
    pub fn rbx(&self) -> u64 {
        self.regs[13]
    }
    pub fn rcx(&self) -> u64 {
        self.regs[12]
    }
    pub fn rdx(&self) -> u64 {
        self.regs[11]
    }
    pub fn rsi(&self) -> u64 {
        self.regs[10]
    }
    pub fn rdi(&self) -> u64 {
        self.regs[9]
    }
    pub fn rbp(&self) -> u64 {
        self.regs[8]
    }
    pub fn r8(&self) -> u64 {
        self.regs[7]
    }
    pub fn r9(&self) -> u64 {
        self.regs[6]
    }
    pub fn r10(&self) -> u64 {
        self.regs[5]
    }
    pub fn r11(&self) -> u64 {
        self.regs[4]
    }
    pub fn r12(&self) -> u64 {
        self.regs[3]
    }
    pub fn r13(&self) -> u64 {
        self.regs[2]
    }
    pub fn r14(&self) -> u64 {
        self.regs[1]
    }
    pub fn r15(&self) -> u64 {
        self.regs[0]
    }
    pub fn vector(&self) -> u64 {
        self.regs[15]
    }
    pub fn error_code(&self) -> u64 {
        self.regs[16]
    }
    pub fn rip(&self) -> u64 {
        self.regs[17]
    }
    pub fn cs(&self) -> u64 {
        self.regs[18]
    }
    pub fn rflags(&self) -> u64 {
        self.regs[19]
    }
    pub fn rsp(&self) -> u64 {
        self.regs[20]
    }
    pub fn ss(&self) -> u64 {
        self.regs[21]
    }

    pub fn set_rax(&mut self, v: u64) {
        self.regs[14] = v;
    }
    pub fn set_rbx(&mut self, v: u64) {
        self.regs[13] = v;
    }
    pub fn set_rcx(&mut self, v: u64) {
        self.regs[12] = v;
    }
    pub fn set_rdx(&mut self, v: u64) {
        self.regs[11] = v;
    }
    pub fn set_rsi(&mut self, v: u64) {
        self.regs[10] = v;
    }
    pub fn set_rdi(&mut self, v: u64) {
        self.regs[9] = v;
    }
    pub fn set_r8(&mut self, v: u64) {
        self.regs[7] = v;
    }
    pub fn set_r9(&mut self, v: u64) {
        self.regs[6] = v;
    }
    pub fn set_r10(&mut self, v: u64) {
        self.regs[5] = v;
    }
    pub fn set_rsp(&mut self, v: u64) {
        self.regs[20] = v;
    }
    pub fn set_rip(&mut self, v: u64) {
        self.regs[17] = v;
    }
}

/// Number of u64 values in the exception frame.
#[allow(dead_code)]
pub const FRAME_SIZE_U64: usize = 22;

/// Size of the exception frame in bytes.
#[allow(dead_code)]
pub const EXCEPTION_FRAME_SIZE: usize = FRAME_SIZE_U64 * 8; // 176 bytes

/// Validate the iretq frame at `sp` before returning to assembly.
/// If the frame is bad but `sp == fallback_sp` (no context switch happened),
/// we have no safe recovery — halt. If a switch did happen, mark the target
/// killed and return fallback_sp.
#[inline]
fn validate_iretq_frame(sp: u64, fallback_sp: u64, vector: u64) -> u64 {
    // Re-apply the current thread's TLS base before any exception-return
    // path (syscall, IRQ, fault retry).  Empirically FSBASE drifts to 0 on
    // x86 KVM when a personality_set_tls runs while the target is parked
    // and the wake-up race-loses the set_tls call (project_step_g_flakes.md
    // CR2=0x28 mode).  A single wrmsr here is cheap and makes the bug
    // disappear.
    {
        let tid = crate::sched::scheduler::current_thread_id();
        let tls = crate::sched::scheduler::thread_ref(tid).tls_base;
        crate::arch::cpu::set_tls(tls);
    }
    // Absolute minimum: no valid kstack frame can be below 64K — catch
    // saved_sp=0 or any pointer into the real-mode IVT / BIOS data area.
    if sp < 0x10000 {
        let tid = crate::sched::scheduler::current_thread_id();
        crate::println!(
            "BAD frame: sp={:#x} (below 64K) vec={} tid={}",
            sp, vector, tid
        );
        crate::sched::scheduler::thread_ref(tid)
            .killed.store(true, core::sync::atomic::Ordering::Release);
        crate::arch::irq::enable();
        loop { core::hint::spin_loop(); }
    }
    let f = unsafe { &*(sp as *const ExceptionFrame) };
    let cs = f.cs();
    let ss = f.ss();
    let bad_cs = cs != 0x08 && cs != 0x23;
    let bad_ss = ss != 0x00 && ss != 0x10 && ss != 0x1B;
    if bad_cs || bad_ss {
        let tid = crate::sched::scheduler::current_thread_id();
        let tref = crate::sched::scheduler::thread_ref(tid);
        let cur_cpu = crate::sched::smp::cpu_id();
        crate::println!(
            "BAD frame: CS={:#x} SS={:#x} RIP={:#x} vec={} tid={} sp={:#x} src={} last_cpu={} cur_cpu={}",
            cs, ss, f.rip(), vector, tid, sp,
            tref.saved_sp_source,
            tref.last_cpu.load(core::sync::atomic::Ordering::Relaxed),
            cur_cpu
        );
        // Dump full frame to diagnose corruption pattern. If GPRs (offsets
        // 0-112) are valid but CPU-pushed (136-168) are garbage: partial
        // overwrite from frame top. If everything is garbage: full page alias.
        crate::println!(
            "  saved_sp={:#x} kstack={:#x} task={}",
            tref.saved_sp, tref.stack_base, tref.task_id
        );
        // Raw dump: 22 u64 values at [sp..sp+176)
        for i in 0..22u64 {
            let val = unsafe { *((sp + i * 8) as *const u64) };
            crate::println!("  frame[{}]={:#018x}", i, val);
        }
        // Mark the current thread (the one with corrupt state) as killed
        // so the scheduler won't re-enqueue it on the next tick.
        tref.killed.store(true, core::sync::atomic::Ordering::Release);
        // Enable interrupts so timer can switch us off this thread.
        crate::arch::irq::enable();
        loop { core::hint::spin_loop(); }
    }
    sp
}

/// Common interrupt/exception handler called from assembly.
/// For timer IRQ (vector 32), returns potentially new SP for context switch.
#[unsafe(no_mangle)]
extern "C" fn x86_exception_handler(frame_sp: u64) -> u64 {
    // Clear any stale pending_switch_sp left by the previous exception's
    // return path.  The previous cycle's take_pending_switch() loaded the
    // SP without clearing it (so wake_parked_thread's spin-wait could see
    // the non-zero value until the assembly `mov rsp, rax` completed).
    // By this point the stack switch is done — safe to signal completion.
    let cpu = crate::sched::smp::cpu_id() as usize;
    crate::sched::scheduler::clear_pending_switch(cpu);

    let frame = unsafe { &mut *(frame_sp as *mut ExceptionFrame) };
    let vector = frame.vector();

    match vector {
        // CPU exceptions 0-31.
        0 => exception_fault("Divide Error (#DE)", frame),
        1 => exception_fault("Debug (#DB)", frame),
        2 => exception_fault("NMI", frame),
        3 => exception_fault("Breakpoint (#BP)", frame),
        4 => exception_fault("Overflow (#OF)", frame),
        5 => exception_fault("Bound Range (#BR)", frame),
        6 => {
            // #UD handling: if the faulting instruction in userspace is
            // `syscall` (0x0f 0x05) — used by glibc and other Linux binaries —
            // emulate it by dispatching through the normal int 0x80 path.
            // The x86_64 syscall ABI (rax=nr, rdi/rsi/rdx/r10/r8/r9=args)
            // already matches the Telix trapframe accessors.
            let cs = frame.cs();
            let from_user = (cs & 3) == 3;
            if from_user {
                let rip = frame.rip() as *const u8;
                let (b0, b1) = unsafe { (*rip, *rip.add(1)) };
                if b0 == 0x0f && b1 == 0x05 {
                    // Advance past `syscall` (2 bytes) so iretq returns to
                    // the instruction after it.
                    frame.set_rip(frame.rip() + 2);
                    crate::sched::scheduler::store_frame_sp(frame_sp);
                    crate::arch::irq::enable();
                    crate::syscall::dispatch(frame);
                    let _ = crate::arch::irq::disable();
                    crate::sched::scheduler::check_preempt_on_return();
                    let pending = crate::sched::scheduler::take_pending_switch();
                    if pending != 0 {
                        return validate_iretq_frame(pending, frame_sp, 6);
                    }
                    return frame_sp;
                }
                // Diagnostic: dump 16 bytes at the faulting RIP so we can
                // decode the instruction post-mortem.  Boot 421 caught an
                // unexplained #UD inside a userspace dynamic-library
                // region (RIP=0x200bf52d5) — without the bytes it's
                // impossible to tell whether it's an unsupported
                // CPU-feature instruction (AVX-512, CET ENDBR64, etc),
                // memcpy corruption from the IO_READ path, or something
                // else.  Read can fault again if the RIP page is
                // unmapped, but at this point we're about to kill the
                // thread anyway, so a triple-fault here is no worse than
                // the current behavior.
                let mut bytes = [0u8; 16];
                for i in 0..16 {
                    bytes[i] = unsafe { *rip.add(i) };
                }
                crate::println!(
                    "  #UD bytes at RIP: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} \
                     {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                    bytes[8], bytes[9], bytes[10], bytes[11],
                    bytes[12], bytes[13], bytes[14], bytes[15]
                );
            }
            exception_fault("Invalid Opcode (#UD)", frame)
        }
        7 => exception_fault("Device Not Available (#NM)", frame),
        8 => {
            // #DF now runs on IST stack — safe to print diagnostics.
            let cr2: u64;
            unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2); }
            let tid = crate::sched::scheduler::current_thread_id();
            crate::println!(
                "DOUBLE FAULT (#DF): RIP={:#x} RSP={:#x} CR2={:#x} tid={} error={:#x}",
                frame.rip(), frame.rsp(), cr2, tid, frame.error_code()
            );
            crate::println!(
                "  RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
                frame.rax(), frame.rbx(), frame.rcx(), frame.rdx()
            );
            crate::println!(
                "  RSI={:#x} RDI={:#x} RBP={:#x} CS={:#x} SS={:#x}",
                frame.rsi(), frame.rdi(), frame.rbp(), frame.cs(), frame.ss()
            );
            let tref = crate::sched::scheduler::thread_ref(tid);
            crate::println!(
                "  task={} saved_sp={:#x} kstack={:#x} personality_frame_sp={:#x}",
                tref.task_id, tref.saved_sp, tref.stack_base,
                tref.personality_frame_sp
            );
            tref.killed.store(true, core::sync::atomic::Ordering::Release);
            crate::arch::irq::enable();
            loop { core::hint::spin_loop(); }
        }
        10 => exception_fault("Invalid TSS (#TS)", frame),
        11 => exception_fault("Segment Not Present (#NP)", frame),
        12 => exception_fault("Stack Segment (#SS)", frame),
        13 => exception_fault("General Protection (#GP)", frame),
        14 => {
            return handle_page_fault_x86(frame, frame_sp);
        }
        16 => exception_fault("x87 FP Exception (#MF)", frame),
        17 => exception_fault("Alignment Check (#AC)", frame),
        18 => exception_fault("Machine Check (#MC)", frame),
        19 => exception_fault("SIMD FP Exception (#XM)", frame),

        // Timer (PIT IRQ 0 -> vector 32, or LAPIC timer -> vector 32).
        32 => {
            super::timer::handle_timer_irq();
            super::lapic::eoi();
            super::pic::send_eoi(0);
            return validate_iretq_frame(crate::sched::tick(frame_sp), frame_sp, 32);
        }

        // Syscall via int 0x80.
        0x80 => {
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::arch::irq::enable();
            crate::syscall::dispatch(frame);
            let _ = crate::arch::irq::disable();
            crate::sched::scheduler::check_preempt_on_return();
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return validate_iretq_frame(pending, frame_sp, 0x80);
            }
            return validate_iretq_frame(frame_sp, frame_sp, 0x80);
        }

        // Reschedule IPI (vector 0xFD). Sent by a remote CPU when it
        // enqueues a thread on our run queue while we are idle.  Only
        // runs try_switch() — no tick accounting, no timer reprogramming.
        0xFD => {
            super::lapic::IPI_RECV_COUNT
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            super::lapic::eoi();
            return validate_iretq_frame(crate::sched::scheduler::reschedule_ipi(frame_sp), frame_sp, 0xFD);
        }

        // Other IRQs (33-47).
        33..=47 => {
            let irq = (vector - 32) as u8;
            if !crate::io::irq_dispatch::handle_irq(irq as u32) {
                crate::println!("Unhandled IRQ {}", irq);
            }
            if super::ioapic::available() {
                super::lapic::eoi();
            } else {
                super::pic::send_eoi(irq);
            }
        }

        _ => {
            crate::println!("Unhandled interrupt vector {}", vector);
        }
    }

    validate_iretq_frame(frame_sp, frame_sp, vector)
}

fn handle_page_fault_x86(frame: &ExceptionFrame, frame_sp: u64) -> u64 {
    let cr2: u64;
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) cr2);
    }
    let error = frame.error_code();
    // Error code bits: bit 0 = P (present), bit 1 = W/R, bit 2 = U/S, bit 4 = I/D.
    let fault_type = if error & (1 << 4) != 0 {
        crate::mm::fault::FaultType::Exec
    } else if error & (1 << 1) != 0 {
        crate::mm::fault::FaultType::Write
    } else {
        crate::mm::fault::FaultType::Read
    };
    let is_user = (error & (1 << 2)) != 0;
    if !is_user {
        crate::println!(
            "Kernel #PF at RIP={:#x} CR2={:#x} error={:#x}",
            frame.rip(),
            cr2,
            error
        );
        loop {
            core::hint::spin_loop();
        }
    }
    let aspace_id = crate::sched::current_aspace_id();
    if aspace_id == 0 {
        crate::println!(
            "User #PF with no address space: CR2={:#x} RIP={:#x}",
            cr2,
            frame.rip()
        );
        loop {
            core::hint::spin_loop();
        }
    }
    let result = crate::mm::fault::handle_page_fault(aspace_id, cr2 as usize, fault_type);
    match result {
        crate::mm::fault::FaultResult::NeedPager { token } => {
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::mm::pager::initiate_fault(token);
            let pending = crate::sched::scheduler::take_pending_switch();
            return if pending != 0 { pending } else { frame_sp };
        }
        crate::mm::fault::FaultResult::Failed => {
            crate::println!(
                "Unhandled #PF: CR2={:#x} RIP={:#x} RSP={:#x} error={:#x} tid={} task={}",
                cr2,
                frame.rip(),
                frame.rsp(),
                error,
                crate::sched::scheduler::current_thread_id(),
                crate::sched::scheduler::thread_ref(crate::sched::scheduler::current_thread_id()).task_id,
            );
            // Tier-3 core dump for unhandled user-space page faults.
            // Vector 14 = #PF.
            crate::arch::x86_64::coredump::dump_user_fault(frame, 14);
            // Stack snapshot + RBP chain walk — same shape as
            // exception_fault's enhanced dump.  Pair RIPs with
            // [lib-load] entries to resolve via addr2line.
            let rsp = frame.rsp();
            let mut sw = [0u64; 8];
            for i in 0..8 {
                sw[i] = crate::arch::x86_64::coredump::safe_read_user_u64(
                    rsp.wrapping_add((i * 8) as u64),
                ).unwrap_or(0);
            }
            crate::println!(
                "  STACK[0..8]@RSP: {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
                sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]
            );
            let mut rbp = frame.rbp();
            for f in 0..6 {
                if rbp < 0x1000 { break; }
                let saved_rbp = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp) {
                    Some(v) => v, None => break,
                };
                let saved_rip = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp.wrapping_add(8)) {
                    Some(v) => v, None => break,
                };
                crate::println!(
                    "  FRAME[{}]: rbp={:#x} caller_rip={:#x}",
                    f, saved_rbp, saved_rip
                );
                if saved_rbp == 0 || saved_rbp <= rbp { break; }
                rbp = saved_rbp;
            }
            crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
        }
        _ => {}
    }
    frame_sp
}

/// Handle a CPU exception. For userspace faults, kill the thread so the CPU
/// can continue running other threads. For kernel faults, halt (fatal).
fn exception_fault(name: &str, frame: &ExceptionFrame) -> ! {
    let is_user = (frame.cs() & 3) == 3;
    crate::println!(
        "EXCEPTION: {} at RIP={:#x} error_code={:#x} tid={} {}",
        name,
        frame.rip(),
        frame.error_code(),
        crate::sched::scheduler::current_thread_id(),
        if is_user { "(user)" } else { "(KERNEL)" }
    );
    crate::println!(
        "  RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
        frame.rax(),
        frame.rbx(),
        frame.rcx(),
        frame.rdx()
    );
    crate::println!(
        "  RSP={:#x} RBP={:#x} RSI={:#x} RDI={:#x}",
        frame.rsp(),
        frame.rbp(),
        frame.rsi(),
        frame.rdi()
    );
    crate::println!(
        "  CS={:#x} RFLAGS={:#x} SS={:#x}",
        frame.cs(),
        frame.rflags(),
        frame.ss()
    );
    if is_user {
        // Tier-3 core dump: emit machine-readable register +
        // stack-page block to the debug log.  Host script
        // tools/extract-core.py reconstructs an ELF64 core file
        // from these markers + the [lib-load] log lines.
        crate::arch::x86_64::coredump::dump_user_fault(frame, frame.vector());
        // Stack snapshot: 64 bytes (8 u64s) at RSP.  Lets the
        // host post-mortem see saved return addresses + arguments
        // in registers' spill slots.  Faults here would re-fault
        // the thread (which we're killing anyway), so reads are
        // best-effort.
        let rsp = frame.rsp();
        let mut sw = [0u64; 8];
        for i in 0..8 {
            sw[i] = crate::arch::x86_64::coredump::safe_read_user_u64(
                rsp.wrapping_add((i * 8) as u64),
            ).unwrap_or(0);
        }
        crate::println!(
            "  STACK[0..8]@RSP: {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",
            sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]
        );
        // RBP chain walk: print the saved-RIP at each frame for up
        // to 6 frames.  Each frame's layout (per System V AMD64):
        //   [RBP]      = caller's RBP
        //   [RBP + 8]  = caller's saved RIP (return address)
        // Pair these RIPs with the [lib-load] log lines emitted by
        // linux_srv to map them to function names via addr2line.
        let mut rbp = frame.rbp();
        for f in 0..6 {
            if rbp < 0x1000 {
                break;
            }
            let saved_rbp = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp) {
                Some(v) => v, None => break,
            };
            let saved_rip = match crate::arch::x86_64::coredump::safe_read_user_u64(rbp.wrapping_add(8)) {
                Some(v) => v, None => break,
            };
            crate::println!(
                "  FRAME[{}]: rbp={:#x} caller_rip={:#x}",
                f, saved_rbp, saved_rip
            );
            // Stop if RBP didn't decrease (corrupted chain or top of stack).
            if saved_rbp == 0 || saved_rbp <= rbp {
                break;
            }
            rbp = saved_rbp;
        }
        // Kill the faulting thread so the CPU can continue running others.
        // Signal number: SIGILL(4) for #UD, SIGSEGV(11) for #GP/#SS, etc.
        crate::sched::scheduler::exit_current_thread(-11);
    }
    // Mark the current thread as killed so the scheduler won't re-run it,
    // then spin with interrupts enabled so the timer can switch us off.
    let tid = crate::sched::scheduler::current_thread_id();
    if tid != 0 {
        crate::sched::scheduler::thread_ref(tid)
            .killed
            .store(true, core::sync::atomic::Ordering::Release);
    }
    crate::arch::irq::enable();
    loop {
        core::hint::spin_loop();
    }
}
