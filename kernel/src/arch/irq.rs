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
        let saved = flags as usize;
        if saved & 0x200 != 0 {
            // #135 CLI callsite probe: capture the RIP of the lea
            // instruction itself.  Since arch::irq::disable is
            // #[inline(always)], this lea materializes in the *caller's*
            // body — the RIP we capture is the caller's instruction
            // address right after their CLI sequence.  Use that to find
            // the kernel callsite of the longest cli_max via the
            // cli_max_rip rescue field.
            let rip: u64;
            unsafe {
                core::arch::asm!(
                    "lea {0}, [rip + 0]",
                    out(reg) rip,
                    options(nomem, nostack, preserves_flags),
                );
            }
            crate::sched::smp::record_cli_enter(rip);
        }
        saved
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let crmd: usize;
        unsafe {
            core::arch::asm!(
                "csrrd {out}, 0x0",    // read CRMD
                "li.w {tmp}, 0x4",     // IE bit = bit 2
                "csrxchg $zero, {tmp}, 0x0", // clear IE
                out = out(reg) crmd,
                tmp = out(reg) _,
            );
        }
        crmd
    }
    #[cfg(target_arch = "mips64")]
    {
        let status: usize;
        unsafe {
            core::arch::asm!(
                "mfc0 {0}, $12",   // read CP0.Status
                "di",              // disable interrupts
                "ehb",             // execution hazard barrier
                out(reg) status,
            );
        }
        status
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
            crate::sched::smp::record_cli_exit();
            unsafe {
                core::arch::asm!("sti");
            }
        }
    }
    #[cfg(target_arch = "loongarch64")]
    {
        if saved & 0x4 != 0 {
            // IE was set — restore it.
            unsafe {
                core::arch::asm!(
                    "li.w {tmp}, 0x4",
                    "csrxchg {tmp}, {tmp}, 0x0", // set IE in CRMD
                    tmp = out(reg) _,
                );
            }
        }
    }
    #[cfg(target_arch = "mips64")]
    {
        if saved & 0x1 != 0 {
            unsafe {
                core::arch::asm!("ei", "ehb");
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
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        core::arch::asm!(
            "li.w {tmp}, 0x4",
            "csrxchg {tmp}, {tmp}, 0x0",
            tmp = out(reg) _,
        );
    }
    #[cfg(target_arch = "mips64")]
    unsafe {
        core::arch::asm!("ei", "ehb");
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
    #[cfg(target_arch = "loongarch64")]
    {
        let crmd: usize;
        unsafe {
            core::arch::asm!(
                "csrrd {out}, 0x0",
                "li.w {tmp}, 0x4",
                "csrxchg {tmp}, {tmp}, 0x0",
                out = out(reg) crmd,
                tmp = out(reg) _,
            );
        }
        crmd
    }
    #[cfg(target_arch = "mips64")]
    {
        let status: usize;
        unsafe {
            core::arch::asm!(
                "mfc0 {0}, $12",
                "ei",
                "ehb",
                out(reg) status,
            );
        }
        status
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
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        core::arch::asm!("idle 0");
    }
    #[cfg(target_arch = "mips64")]
    unsafe {
        core::arch::asm!("wait");
    }
}

/// Send a reschedule IPI to a remote CPU, waking it from idle (HLT/WFI).
///
/// The target CPU takes an interrupt, runs handle_irq() → sched::tick(),
/// and discovers any newly-enqueued threads on its runqueue.  Without a
/// real IPI here the wake-up never arrives under tickless scheduling —
/// the target CPU parks in WFI and, since it decided not to re-arm its
/// timer (no local work), stays parked forever.  Writeup:
/// /tmp/telix-tickless-smp-ipi.md (QEMU-side session, 2026-04-24).
#[inline]
pub fn send_reschedule_ipi(target_cpu: u32) {
    // #135 IPI per-target counter — bump BEFORE the actual send so the
    // count reflects send attempts, not just successful sends.  See
    // sched/smp.rs ipi_send_to for the matching probe.
    {
        let src = crate::sched::smp::cpu_id();
        let pcpu = crate::sched::smp::get(src);
        let slot = (target_cpu as usize).min(pcpu.ipi_send_to.len() - 1);
        pcpu.ipi_send_to[slot]
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    // Hypervisor fast path: when running under KVM (or any
    // hypervisor that advertises a PV IPI hypercall), bypass the
    // native LAPIC ICR write and ask the host directly.  Host-side
    // delivery is typically faster than emulating the LAPIC write
    // and reduces vmexit overhead.  send_reschedule_ipi returns
    // false if the hypervisor isn't ready or doesn't support PV
    // IPI; falling through to the native path then.
    if crate::arch::hypervisor::ops().send_reschedule_ipi(target_cpu) {
        // NOTE: KVM_HC_KICK_CPU (kick_cpu) is intentionally NOT issued
        // here.  Boot 91amfsq626 verified that the LAPIC IPI alone
        // already provides wake-from-HLT semantics under KVM; pairing
        // an additional KICK_CPU hypercall doubled the vmexit cost
        // without reducing per-dispatch rescue_stuck rate (0.013% vs
        // 0.017% baseline — within noise).  The kick_cpu primitive
        // remains in HypervisorOps for targeted future use (e.g. PV
        // spinlock paths where there's no IPI), but should not fire
        // on every cross-CPU reschedule.
        return;
    }
    #[cfg(target_arch = "x86_64")]
    crate::arch::x86_64::lapic::send_reschedule(target_cpu);
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::irq::send_sgi(
        target_cpu,
        crate::arch::aarch64::irq::INTID_RESCHEDULE,
    );
    #[cfg(target_arch = "riscv64")]
    crate::arch::riscv64::trap::sbi_send_ipi(target_cpu);
    #[cfg(target_arch = "loongarch64")]
    crate::arch::loongarch64::trap::send_ipi(target_cpu);
    // mips64: start_secondary_cpus is a TODO and there's no agreed-upon
    // QEMU machine SMP model yet (MT/CMP/CPS all take different paths).
    // Leave this as a no-op until the SMP bring-up picks one; revisit
    // based on /tmp/telix-tickless-smp-ipi.md §"mips64".
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
    )))]
    { let _ = target_cpu; }
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
    {
        if crate::arch::x86_64::ioapic::available() {
            crate::arch::x86_64::ioapic::unmask_irq(irq as u8);
        } else {
            crate::arch::x86_64::pic::unmask(irq as u8);
        }
    }
    #[cfg(target_arch = "loongarch64")]
    {
        // EXTIOI + PCH-PIC: ensure the controller is up, then route+enable this
        // PCI IRQ to core 0 / HWI0.  See arch/loongarch64/eiointc.rs.
        crate::arch::loongarch64::eiointc::init();
        crate::arch::loongarch64::eiointc::enable_irq(irq);
    }
    #[cfg(target_arch = "mips64")]
    {
        let _ = irq; // TODO: CP0 Status IM bits
    }
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
    #[cfg(target_arch = "loongarch64")]
    {
        irq as usize
    }
    #[cfg(target_arch = "mips64")]
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
    #[cfg(target_arch = "loongarch64")]
    {
        // PCI INTx land on PCH-PIC inputs 16..19 (pci.rs PCI_IRQ_BASE=16);
        // allow the PCH-PIC input range.  EXTIOI delivery wired in eiointc.rs.
        (16, 63)
    }
    #[cfg(target_arch = "mips64")]
    {
        (1, 7) // CP0 Cause IP bits
    }
}
