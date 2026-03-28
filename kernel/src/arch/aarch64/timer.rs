//! ARM generic timer driver.
//!
//! Uses the EL1 physical timer (CNTP_*) which fires PPI 30.

use core::sync::atomic::{AtomicU64, Ordering};

static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_INTERVAL: AtomicU64 = AtomicU64::new(0);

/// Read the counter frequency (ticks per second).
pub fn cntfrq() -> u64 {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
}

/// Read the current counter value.
pub fn counter() -> u64 {
    let cnt: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) cnt) };
    cnt
}

/// Initialize the timer to fire at ~100 Hz (10 ms interval).
pub fn init() {
    let freq = cntfrq();
    let interval = freq / 100; // 100 Hz
    TIMER_INTERVAL.store(interval, Ordering::Relaxed);

    // Set the timer compare value.
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) interval);
        // Enable the timer: ENABLE=1, IMASK=0.
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
    }

    // Enable the timer interrupt in the GIC.
    super::irq::enable_interrupt(super::irq::INTID_TIMER_EL1_PHYS);

    crate::println!(
        "  Timer initialized: freq={} Hz, interval={} ticks ({}ms)",
        freq,
        interval,
        1000 * interval / freq
    );
}

/// Initialize the timer on a secondary CPU. The timer interval is already
/// known; just program the timer and enable the PPI (done by irq::init_cpu).
pub fn init_ap() {
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) interval);
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
    }
}

/// Handle timer interrupt: reset the timer and increment tick count.
pub fn handle_timer_irq() {
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

    // Reset the timer for the next interval.
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) interval);
    }
}

/// Unmask IRQs (clear DAIF.I bit) to allow interrupts.
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("msr daifclr, #2"); // Clear IRQ mask
    }
}
