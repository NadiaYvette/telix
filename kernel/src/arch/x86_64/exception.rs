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
}

/// Number of u64 values in the exception frame.
#[allow(dead_code)]
pub const FRAME_SIZE_U64: usize = 22;

/// Size of the exception frame in bytes.
#[allow(dead_code)]
pub const EXCEPTION_FRAME_SIZE: usize = FRAME_SIZE_U64 * 8; // 176 bytes

/// Common interrupt/exception handler called from assembly.
/// For timer IRQ (vector 32), returns potentially new SP for context switch.
#[unsafe(no_mangle)]
extern "C" fn x86_exception_handler(frame_sp: u64) -> u64 {
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
        6 => exception_fault("Invalid Opcode (#UD)", frame),
        7 => exception_fault("Device Not Available (#NM)", frame),
        8 => exception_fault("Double Fault (#DF)", frame),
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
            // Send EOI to both LAPIC and PIC (safe even if only one is active).
            super::lapic::eoi();
            super::pic::send_eoi(0);
            // Let the scheduler decide if we should context switch.
            return crate::sched::tick(frame_sp);
        }

        // Syscall via int 0x80.
        0x80 => {
            // Store frame SP so park/handoff can read it without changing dispatch()'s signature.
            crate::sched::scheduler::store_frame_sp(frame_sp);
            crate::syscall::dispatch(frame);
            // Check if the syscall triggered a context switch (park or handoff).
            let pending = crate::sched::scheduler::take_pending_switch();
            if pending != 0 {
                return pending;
            }
            return frame_sp;
        }

        // Other IRQs (33-47).
        33..=47 => {
            let irq = (vector - 32) as u8;
            if !crate::io::irq_dispatch::handle_irq(irq as u32) {
                crate::println!("Unhandled IRQ {}", irq);
            }
            super::pic::send_eoi(irq);
        }

        _ => {
            crate::println!("Unhandled interrupt vector {}", vector);
        }
    }

    frame_sp
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
                "Unhandled #PF: CR2={:#x} RIP={:#x} error={:#x} — killing thread",
                cr2,
                frame.rip(),
                error
            );
            crate::sched::scheduler::exit_current_thread(-11); // SIGSEGV
        }
        _ => {}
    }
    frame_sp
}

fn exception_fault(name: &str, frame: &ExceptionFrame) -> ! {
    crate::println!(
        "EXCEPTION: {} at RIP={:#x} error_code={:#x}",
        name,
        frame.rip(),
        frame.error_code()
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
    loop {
        core::hint::spin_loop();
    }
}
