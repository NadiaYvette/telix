//! Architecture-independent CPU identity and TLS primitives.
//!
//! Centralizes CPU ID reads, TLS register writes, and instruction cache
//! flushes that were previously duplicated via `#[cfg(target_arch)]` blocks
//! in smp.rs, handlers.rs, and scheduler.rs.

/// Get the current CPU's ID (0-based index).
#[inline]
pub fn cpu_id() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("mrs {}, tpidr_el1", out(reg) id);
        }
        id as u32
    }
    #[cfg(target_arch = "riscv64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("mv {}, tp", out(reg) id);
        }
        id as u32
    }
    #[cfg(target_arch = "x86_64")]
    {
        // Read LAPIC ID register (offset 0x020) using firmware-discovered base.
        let base = crate::firmware::irq_controller().base0 as usize;
        let base = if base != 0 { base } else { 0xFEE0_0000 };
        let lapic_id = unsafe { core::ptr::read_volatile((base + 0x020) as *const u32) };
        (lapic_id >> 24) & 0xFF
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("csrrd {}, 0x20", out(reg) id); // CSR.CPUID
        }
        id as u32
    }
    #[cfg(target_arch = "mips64")]
    {
        let id: u64;
        unsafe {
            core::arch::asm!("mfc0 {}, $15, 1", out(reg) id); // CP0 EBase
        }
        (id & 0x3FF) as u32 // CPUNum field
    }
}

/// Set the user-space TLS base register.
#[inline]
pub fn set_tls(base: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr tpidr_el0, {}", in(reg) base);
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv tp, {}", in(reg) base);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let lo = base as u32;
        let hi = (base >> 32) as u32;
        unsafe {
            core::arch::asm!("wrmsr", in("ecx") 0xC0000100u32, in("eax") lo, in("edx") hi);
        }
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        // LoongArch: tp register ($r2) is the TLS base.
        core::arch::asm!("move $r2, {}", in(reg) base);
    }
    #[cfg(target_arch = "mips64")]
    unsafe {
        // MIPS: UserLocal CP0 register for TLS.
        core::arch::asm!("dmtc0 {}, $4, 2", in(reg) base); // CP0.UserLocal
    }
}

/// Initialize the BSP's CPU ID register.
#[inline]
pub fn init_bsp_cpu_id() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr tpidr_el1, xzr");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv tp, zero");
    }
    // x86_64: LAPIC ID 0 is BSP on QEMU — no setup needed.
    // loongarch64: CSR.CPUID is read-only, returns 0 for BSP.
    // mips64: EBase.CPUNum is read-only, 0 for BSP.
}

/// Flush the instruction cache. No-op on x86_64 (coherent i-cache).
#[inline(always)]
pub fn flush_icache() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb");
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence.i");
    }
    // x86_64: instruction cache is coherent with data cache.
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        core::arch::asm!("dbar 0", "ibar 0");
    }
    #[cfg(target_arch = "mips64")]
    unsafe {
        // MIPS: SYNCI instruction per cache line, or use CACHE op.
        // For now, full pipeline sync.
        core::arch::asm!("sync", ".set push", ".set mips64r2", "synci 0($zero)", ".set pop");
    }
}
