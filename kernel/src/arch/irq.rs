//! Architecture-independent IRQ primitives.
//!
//! Centralizes interrupt save/restore, WFI, and device IRQ operations
//! that were previously duplicated via `#[cfg(target_arch)]` blocks in
//! spinlock.rs, scheduler.rs, irq_dispatch.rs, and virtio_blk.rs.

/// Save current interrupt state and disable IRQs. Returns opaque saved state.
#[inline(always)]
pub fn disable() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let daif: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, daif",
                "msr daifset, #2",
                out(reg) daif,
            );
        }
        daif as usize
    }
    #[cfg(target_arch = "riscv64")]
    {
        let sstatus: usize;
        unsafe {
            core::arch::asm!(
                "csrrci {0}, sstatus, 0x2",
                out(reg) sstatus,
            );
        }
        sstatus
    }
    #[cfg(target_arch = "x86_64")]
    {
        let flags: u64;
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {0}",
                "cli",
                out(reg) flags,
            );
        }
        flags as usize
    }
}

/// Restore interrupt state from a previous `disable()` call.
#[inline(always)]
pub fn restore(saved: usize) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daif, {0}", "isb", in(reg) saved as u64);
    }
    #[cfg(target_arch = "riscv64")]
    {
        if saved & 0x2 != 0 {
            unsafe {
                core::arch::asm!("csrsi sstatus, 0x2");
            }
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if saved & 0x200 != 0 {
            unsafe {
                core::arch::asm!("sti");
            }
        }
    }
}

/// Unconditionally enable IRQs.
#[inline(always)]
pub fn enable() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifclr, #2", "isb");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("csrsi sstatus, 0x2");
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("sti");
    }
}

/// Save current interrupt state and enable IRQs. Returns opaque saved state.
#[inline(always)]
pub fn save_and_enable() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let daif: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, daif",
                "msr daifclr, #2",
                "isb",
                out(reg) daif,
            );
        }
        daif as usize
    }
    #[cfg(target_arch = "riscv64")]
    {
        let sstatus: usize;
        unsafe {
            core::arch::asm!(
                "csrrsi {0}, sstatus, 0x2",
                out(reg) sstatus,
            );
        }
        sstatus
    }
    #[cfg(target_arch = "x86_64")]
    {
        let flags: u64;
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {0}",
                "sti",
                out(reg) flags,
            );
        }
        flags as usize
    }
}

/// Wait for the next interrupt (WFI/HLT).
#[inline(always)]
pub fn wait_for_interrupt() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("wfi");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("wfi");
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("hlt");
    }
}

/// Send an event to all CPUs (SEV on AArch64, no-op elsewhere).
#[inline(always)]
pub fn send_event() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("sev");
    }
}

/// Enable a device IRQ in the platform interrupt controller (GIC/PLIC/PIC).
pub fn enable_device_irq(irq: u32) {
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::irq::enable_interrupt(irq);
    #[cfg(target_arch = "riscv64")]
    {
        let hart = crate::sched::smp::cpu_id();
        crate::arch::riscv64::plic::enable_irq(hart, irq);
    }
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::pic::unmask(irq as u8);
}

/// Normalize a platform IRQ number to a dispatch table index.
#[inline]
pub fn normalize_irq(irq: u32) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        (irq - 48) as usize
    }
    #[cfg(target_arch = "riscv64")]
    {
        (irq - 1) as usize
    }
    #[cfg(target_arch = "x86_64")]
    {
        irq as usize
    }
}

/// Valid device IRQ range (inclusive) for userspace IRQ wait.
#[inline]
pub const fn valid_irq_range() -> (u32, u32) {
    #[cfg(target_arch = "aarch64")]
    {
        (48, 79)
    }
    #[cfg(target_arch = "riscv64")]
    {
        (1, 8)
    }
    #[cfg(target_arch = "x86_64")]
    {
        (1, 15)
    }
}
