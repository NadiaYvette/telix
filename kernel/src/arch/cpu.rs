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
        // #250: read cpu_id from `gp`, not `tp`.  `tp` is needed by user
        // code as the TLS base, and set_tls() writes user_tls into the live
        // `tp` register from S-mode (scheduler.rs:6447) — keeping cpu_id
        // there would clobber it on every dispatch.  See
        // memory/project_riscv64_set_tls_tp_clobber.md for the SP-swap
        // and missed-cpu_id chain this avoids.  Trap entry/exit (vectors.S)
        // now swaps `gp` with `sscratch`; `tp` gets the normal save/restore.
        // Compiler doesn't use `gp` for relaxation as long as the kernel is
        // linked with the default rustc behaviour (no -mrelax on output).
        let id: u64;
        unsafe {
            core::arch::asm!("mv {}, gp", out(reg) id, options(nomem, nostack, preserves_flags));
        }
        id as u32
    }
    #[cfg(target_arch = "x86_64")]
    {
        // Read LAPIC ID register (offset 0x020) using firmware-discovered base.
        // #235 C2e: route through PHYS_DIRECT_MAP so the access works on a
        // user CR3 (where PML4[0] is empty post-unmap).  PHYS_DIRECT_MAP
        // covers PA 0..4 GiB, including the 0xFEE0_0000 LAPIC region.
        let base_pa = crate::firmware::irq_controller().base0 as usize;
        let base_pa = if base_pa != 0 { base_pa } else { 0xFEE0_0000 };
        let base_kva = crate::mm::page::phys_to_kva(base_pa);
        let lapic_id = unsafe { core::ptr::read_volatile((base_kva + 0x020) as *const u32) };
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
        // #250: cpu_id lives in `gp` on riscv64, not `tp`.  See cpu_id()
        // comment and memory/project_riscv64_set_tls_tp_clobber.md.
        core::arch::asm!("mv gp, zero", options(nomem, nostack, preserves_flags));
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
