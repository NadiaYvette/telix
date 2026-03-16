//! 8254 PIT (Programmable Interval Timer) driver.
//!
//! Channel 0, mode 2 (rate generator), ~100 Hz.
//! Fires IRQ 0 -> vector 32 after PIC remapping.

use core::sync::atomic::{AtomicU64, Ordering};

const PIT_CH0_DATA: u16 = 0x40;
const PIT_CMD: u16 = 0x43;

// PIT oscillator frequency (Hz).
const PIT_FREQ: u32 = 1_193_182;

// Target tick rate.
const TARGET_HZ: u32 = 100;

// Divisor for ~100 Hz.
const DIVISOR: u16 = (PIT_FREQ / TARGET_HZ) as u16; // 11932

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

#[inline]
unsafe fn outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack)); }
}

/// Initialize the PIT channel 0 at ~100 Hz.
pub fn init() {
    unsafe {
        // Channel 0, access mode lobyte/hibyte, mode 2 (rate generator), binary
        outb(PIT_CMD, 0x34);

        // Send divisor (low byte then high byte).
        outb(PIT_CH0_DATA, (DIVISOR & 0xFF) as u8);
        outb(PIT_CH0_DATA, (DIVISOR >> 8) as u8);
    }

    // Unmask IRQ 0 (timer) on the PIC.
    super::pic::unmask(0);

    crate::println!("  PIT initialized: divisor={}, ~{} Hz", DIVISOR, TARGET_HZ);
}

/// Handle PIT timer interrupt (IRQ 0). Called from interrupt handler.
pub fn handle_timer_irq() {
    let ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    // Print every 100 ticks (~once per second).
    if ticks % 100 == 0 {
        crate::println!("[tick {}]", ticks);
    }
}

/// Enable interrupts (STI).
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// Disable interrupts (CLI).
#[allow(dead_code)]
pub fn disable_interrupts() {
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}
