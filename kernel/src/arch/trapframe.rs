//! Architecture-independent trap frame operations.
//!
//! Centralizes exception/trap frame register access, frame initialization,
//! and platform constants that were previously duplicated via `#[cfg(target_arch)]`
//! blocks in handlers.rs and scheduler.rs.

// ---------------------------------------------------------------------------
// ExceptionFrame re-export
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
pub use crate::arch::aarch64::exception::ExceptionFrame;
#[cfg(target_arch = "riscv64")]
pub use crate::arch::riscv64::trap::TrapFrame as ExceptionFrame;
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::exception::ExceptionFrame;

// ---------------------------------------------------------------------------
// Platform constants
// ---------------------------------------------------------------------------

/// User-space stack top address (highest VA before kernel space).
#[cfg(target_arch = "aarch64")]
pub const USER_STACK_TOP: usize = 0x7FFF_F000_0000;
#[cfg(target_arch = "riscv64")]
pub const USER_STACK_TOP: usize = 0x3F_F000_0000;
#[cfg(target_arch = "x86_64")]
pub const USER_STACK_TOP: usize = 0x7FFF_FFFF_0000;

/// Size of the exception frame saved/restored by the trap entry/exit assembly.
/// AArch64: 288 bytes = 36 x u64 (x0-x30, sp_el0, elr, spsr, esr, _pad).
/// RISC-V:  272 bytes = 34 x u64 (x1-x31, sepc, sstatus, scause).
/// x86-64:  176 bytes = 22 x u64 (r15-rax, vector, error_code, rip, cs, rflags, rsp, ss).
#[cfg(target_arch = "aarch64")]
pub const EXCEPTION_FRAME_SIZE: usize = 288;
#[cfg(target_arch = "riscv64")]
pub const EXCEPTION_FRAME_SIZE: usize = 272;
#[cfg(target_arch = "x86_64")]
pub const EXCEPTION_FRAME_SIZE: usize = 176;

/// Approved device MMIO physical address range for sys_mmap_device (start, end).
/// (0, 0) means MMIO device mapping is disabled on this platform.
#[cfg(target_arch = "aarch64")]
pub const DEVICE_MMIO_RANGE: (usize, usize) = (0x0a00_0000, 0x0a00_7000);
#[cfg(target_arch = "riscv64")]
pub const DEVICE_MMIO_RANGE: (usize, usize) = (0x1000_1000, 0x1000_9000);
#[cfg(target_arch = "x86_64")]
pub const DEVICE_MMIO_RANGE: (usize, usize) = (0, 0);

/// PTE flags for device memory mapping (user-accessible, device-nGnRnE on AArch64).
#[inline]
pub fn device_pte_flags() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        const PT_VALID: u64 = 1 << 0;
        const PT_PAGE: u64 = 1 << 1;
        const PT_AF: u64 = 1 << 10;
        const PT_AP_RW_ALL: u64 = 1 << 6;
        const PT_ATTR_IDX_1: u64 = 1 << 2; // MAIR Attr1 = device-nGnRnE
        const PT_UXN: u64 = 1 << 54;
        const PT_PXN: u64 = 1 << 53;
        PT_VALID | PT_PAGE | PT_AF | PT_AP_RW_ALL | PT_ATTR_IDX_1 | PT_UXN | PT_PXN
    }
    #[cfg(target_arch = "riscv64")]
    {
        crate::mm::hat::USER_RW_FLAGS
    }
    #[cfg(target_arch = "x86_64")]
    {
        0
    } // unreachable — DEVICE_MMIO_RANGE is (0,0)
}

// ---------------------------------------------------------------------------
// Syscall ABI accessors
// ---------------------------------------------------------------------------

/// Get syscall number from the exception frame.
#[inline]
pub fn syscall_nr(frame: &ExceptionFrame) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        frame.regs[8]
    } // x8
    #[cfg(target_arch = "riscv64")]
    {
        frame.regs[16]
    } // a7 = x17, stored at index 16
    #[cfg(target_arch = "x86_64")]
    {
        frame.rax()
    }
}

/// Get syscall argument by index (0-5).
#[inline]
pub fn syscall_arg(frame: &ExceptionFrame, n: usize) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        frame.regs[n]
    } // x0-x5
    #[cfg(target_arch = "riscv64")]
    {
        frame.regs[n + 9]
    } // a0-a5 = x10-x15, stored at indices 9..14
    #[cfg(target_arch = "x86_64")]
    {
        match n {
            0 => frame.rdi(),
            1 => frame.rsi(),
            2 => frame.rdx(),
            3 => frame.r10(),
            4 => frame.r8(),
            5 => frame.r9(),
            _ => 0,
        }
    }
}

/// Set the syscall return value in the frame.
#[inline]
pub fn set_return(frame: &mut ExceptionFrame, val: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        frame.regs[0] = val;
    }
    #[cfg(target_arch = "riscv64")]
    {
        frame.regs[9] = val;
    }
    #[cfg(target_arch = "x86_64")]
    {
        frame.set_rax(val);
    }
}

/// Set additional return register by index (for recv multi-register return).
/// Index 1-7 maps to arch-specific registers.
#[inline]
pub fn set_reg(frame: &mut ExceptionFrame, reg: usize, val: u64) {
    #[cfg(target_arch = "aarch64")]
    {
        frame.regs[reg] = val;
    }
    #[cfg(target_arch = "riscv64")]
    {
        frame.regs[reg + 9] = val;
    }
    #[cfg(target_arch = "x86_64")]
    {
        match reg {
            1 => frame.set_rdi(val),
            2 => frame.set_rsi(val),
            3 => frame.set_rdx(val),
            4 => frame.set_r10(val),
            5 => frame.set_r8(val),
            6 => frame.set_r9(val),
            7 => frame.set_rbx(val),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Frame field access
// ---------------------------------------------------------------------------

/// Read the user-space stack pointer from the frame.
#[inline]
pub fn user_sp(frame: &ExceptionFrame) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        frame.sp as usize
    }
    #[cfg(target_arch = "riscv64")]
    {
        frame.regs[1] as usize
    } // sp = x2, stored at index 1
    #[cfg(target_arch = "x86_64")]
    {
        frame.rsp() as usize
    }
}

// ---------------------------------------------------------------------------
// Frame initialization (raw pointer access for stack setup)
// ---------------------------------------------------------------------------

/// Initialize a zeroed exception frame for a kernel thread.
///
/// Sets the program counter to `entry`, configures supervisor/kernel mode
/// with interrupts enabled, and sets the stack pointer.
///
/// # Safety
/// `frame` must point to a zeroed region of at least `EXCEPTION_FRAME_SIZE` bytes.
#[allow(unused_variables)]
#[inline]
pub unsafe fn init_kernel_frame(frame: *mut u64, entry: usize, stack_top: usize) {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            *frame.add(32) = entry as u64; // ELR_EL1
            *frame.add(33) = 0x5; // SPSR_EL1 = EL1h, IRQs unmasked
        }
        #[cfg(target_arch = "riscv64")]
        {
            *frame.add(31) = entry as u64; // sepc
            // sstatus: SPP=1 (S-mode), SPIE=1 (enable interrupts on sret)
            *frame.add(32) = (1 << 8) | (1 << 5);
        }
        #[cfg(target_arch = "x86_64")]
        {
            *frame.add(17) = entry as u64; // RIP
            *frame.add(18) = 0x08; // CS = kernel code segment
            *frame.add(19) = 0x200; // RFLAGS = IF (interrupts enabled)
            *frame.add(20) = stack_top as u64; // RSP
            *frame.add(21) = 0x10; // SS = kernel data segment
        }
    }
}

/// Initialize a zeroed exception frame for a user thread.
///
/// Sets the program counter to `entry`, configures user mode with interrupts
/// enabled, sets the user stack pointer, and writes up to 3 argument values
/// into the argument registers.
///
/// # Safety
/// `frame` must point to a zeroed region of at least `EXCEPTION_FRAME_SIZE` bytes.
#[inline]
pub unsafe fn init_user_frame(frame: *mut u64, entry: usize, sp: usize, args: &[u64]) {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            *frame.add(32) = entry as u64; // ELR_EL1
            *frame.add(33) = 0x0; // SPSR_EL1 = EL0t (user mode)
            *frame.add(31) = sp as u64; // SP_EL0
            // args in x0, x1, x2
            for (i, &val) in args.iter().enumerate().take(3) {
                *frame.add(i) = val;
            }
        }
        #[cfg(target_arch = "riscv64")]
        {
            *frame.add(31) = entry as u64; // sepc
            *frame.add(32) = 1 << 5; // sstatus: SPIE=1, SPP=0 (user mode)
            *frame.add(1) = sp as u64; // sp (x2)
            // args in a0, a1, a2 = indices 9, 10, 11
            for (i, &val) in args.iter().enumerate().take(3) {
                *frame.add(9 + i) = val;
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            *frame.add(17) = entry as u64; // RIP
            *frame.add(18) = (crate::arch::x86_64::gdt::USER_CS as u64) | 3; // CS
            *frame.add(19) = 0x200; // RFLAGS = IF
            *frame.add(20) = sp as u64; // RSP
            *frame.add(21) = (crate::arch::x86_64::gdt::USER_DS as u64) | 3; // SS
            // args: rdi=args[0], rsi=args[1], rdx=args[2]
            const ARG_INDICES: [usize; 3] = [9, 10, 11]; // rdi, rsi, rdx
            for (i, &val) in args.iter().enumerate().take(3) {
                *frame.add(ARG_INDICES[i]) = val;
            }
        }
    }
}

/// Set argument register N in a raw frame pointer (for spawn_with_data arg1/arg2).
///
/// # Safety
/// `frame` must point to a valid exception frame.
#[inline]
pub unsafe fn set_frame_arg(frame: *mut u64, n: usize, val: u64) {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            *frame.add(n) = val;
        }
        #[cfg(target_arch = "riscv64")]
        {
            *frame.add(n + 9) = val;
        }
        #[cfg(target_arch = "x86_64")]
        {
            *frame.add(n + 9) = val;
        } // rdi=9, rsi=10, rdx=11
    }
}

/// Rewrite an exception frame for signal delivery.
///
/// Sets PC to handler, arg0 to signal number, arg1 to frame address,
/// SP to new stack, and clears the link register.
/// On x86_64, also pushes a zero return address on the user stack via
/// the provided `copy_to_user` function and adjusts RSP accordingly.
pub fn setup_signal_entry(
    frame: &mut ExceptionFrame,
    handler: u64,
    sig: u64,
    frame_addr: u64,
    new_sp: usize,
    copy_to_user_fn: fn(usize, usize, &[u8]) -> bool,
    pt_root: usize,
) {
    #[cfg(target_arch = "aarch64")]
    {
        let _ = (copy_to_user_fn, pt_root);
        frame.regs[0] = sig; // arg0 = signal number
        frame.regs[1] = frame_addr; // arg1 = signal frame address
        frame.sp = new_sp as u64; // SP_EL0 = new stack
        frame.regs[30] = 0; // LR = 0
        frame.elr = handler; // PC = handler entry
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = (copy_to_user_fn, pt_root);
        frame.regs[9] = sig; // a0 = signal number
        frame.regs[10] = frame_addr; // a1 = signal frame address
        frame.regs[1] = new_sp as u64; // sp = new stack
        frame.regs[0] = 0; // ra = 0
        let fp = frame as *mut ExceptionFrame as *mut u64;
        unsafe {
            *fp.add(31) = handler;
        } // sepc = handler
    }
    #[cfg(target_arch = "x86_64")]
    {
        // x86 calling convention: push return address on stack.
        let call_sp = new_sp - 8;
        let zero_bytes = 0u64.to_le_bytes();
        let _ = copy_to_user_fn(pt_root, call_sp, &zero_bytes);

        let fp = frame as *mut ExceptionFrame as *mut u64;
        unsafe {
            *fp.add(9) = sig; // rdi = signal number
            *fp.add(10) = frame_addr; // rsi = signal frame address
            *fp.add(17) = handler; // RIP = handler
            *fp.add(20) = call_sp as u64; // RSP = adjusted stack
        }
    }
}

/// Update the kernel stack pointer for the next thread on context switches.
/// x86_64: writes TSS RSP0 for ring 3→0 transitions.
/// riscv64: writes TRAP_SCRATCH_ARRAY[cpu].kernel_sp for user ecall entry.
#[inline]
pub fn update_kernel_stack(_next_kstack_top: usize) {
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::gdt::set_rsp0(_next_kstack_top as u64);

    #[cfg(target_arch = "riscv64")]
    {
        let cpu = crate::arch::cpu::cpu_id() as usize;
        unsafe {
            crate::sched::smp::TRAP_SCRATCH_ARRAY[cpu].kernel_sp = _next_kstack_top as u64;
        }
    }
}
