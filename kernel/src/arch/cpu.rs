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
        unsafe { core::arch::asm!("mrs {}, tpidr_el1", out(reg) id); }
        id as u32
    }
    #[cfg(target_arch = "riscv64")]
    {
        let id: u64;
        unsafe { core::arch::asm!("mv {}, tp", out(reg) id); }
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
}

/// Set the user-space TLS base register.
#[inline]
pub fn set_tls(base: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("msr tpidr_el0, {}", in(reg) base); }
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("mv tp, {}", in(reg) base); }
    #[cfg(target_arch = "x86_64")]
    {
        let lo = base as u32;
        let hi = (base >> 32) as u32;
        unsafe { core::arch::asm!("wrmsr", in("ecx") 0xC0000100u32, in("eax") lo, in("edx") hi); }
    }
}

/// Initialize the BSP's CPU ID register.
#[inline]
pub fn init_bsp_cpu_id() {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("msr tpidr_el1, xzr"); }
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("mv tp, zero"); }
    // x86_64: LAPIC ID 0 is BSP on QEMU — no setup needed.
}

/// Flush the instruction cache. No-op on x86_64 (coherent i-cache).
#[inline(always)]
pub fn flush_icache() {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb ish", "ic iallu", "dsb ish", "isb"); }
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("fence.i"); }
    // x86_64: instruction cache is coherent with data cache.
}
