//! RISC-V PLIC (Platform-Level Interrupt Controller) driver for QEMU virt.
//!
//! QEMU virt PLIC base: 0x0C00_0000
//! Context layout: context 0 = M-mode hart 0, context 1 = S-mode hart 0,
//!                 context 2 = M-mode hart 1, context 3 = S-mode hart 1, etc.
//! S-mode context for hart N = 2*N + 1.

const PLIC_BASE: usize = 0x0C00_0000;

// Register offsets
const PRIORITY_BASE: usize = PLIC_BASE; // 4 bytes per IRQ
const ENABLE_BASE: usize = PLIC_BASE + 0x2000; // 0x80 bytes per context
const THRESHOLD_BASE: usize = PLIC_BASE + 0x20_0000; // 0x1000 per context
const CLAIM_BASE: usize = PLIC_BASE + 0x20_0004; // 0x1000 per context

/// S-mode context ID for a given hart.
fn s_context(hart: u32) -> usize {
    (2 * hart + 1) as usize
}

/// Initialize the PLIC for the given hart (S-mode context).
/// Sets priority threshold to 0 (accept all priorities).
pub fn init(hart: u32) {
    let ctx = s_context(hart);
    let threshold = (THRESHOLD_BASE + ctx * 0x1000) as *mut u32;
    unsafe {
        core::ptr::write_volatile(threshold, 0);
    }
}

/// Enable a specific IRQ on the current hart's S-mode context.
pub fn enable_irq(hart: u32, irq: u32) {
    // Set priority for this IRQ (must be > 0 to be deliverable).
    let prio = (PRIORITY_BASE + 4 * irq as usize) as *mut u32;
    unsafe {
        core::ptr::write_volatile(prio, 1);
    }

    // Set enable bit in the S-mode enable register for this hart.
    let ctx = s_context(hart);
    let enable_reg = (ENABLE_BASE + ctx * 0x80 + (irq / 32) as usize * 4) as *mut u32;
    unsafe {
        let val = core::ptr::read_volatile(enable_reg);
        core::ptr::write_volatile(enable_reg, val | (1 << (irq % 32)));
    }
}

/// Claim the highest-priority pending interrupt. Returns IRQ number (0 = none).
pub fn claim(hart: u32) -> u32 {
    let ctx = s_context(hart);
    let claim_reg = (CLAIM_BASE + ctx * 0x1000) as *const u32;
    unsafe { core::ptr::read_volatile(claim_reg) }
}

/// Signal completion of an interrupt.
pub fn complete(hart: u32, irq: u32) {
    let ctx = s_context(hart);
    let complete_reg = (CLAIM_BASE + ctx * 0x1000) as *mut u32;
    unsafe {
        core::ptr::write_volatile(complete_reg, irq);
    }
}
