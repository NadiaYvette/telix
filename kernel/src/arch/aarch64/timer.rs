//! ARM generic timer driver (one-shot mode).
//!
//! Uses the EL1 physical timer (CNTP_*) which fires PPI 30.
//! Programs CNTP_CVAL_EL0 (absolute comparator) for one-shot operation.
//! The scheduler re-arms the timer after each tick via `program_oneshot()`.

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

/// Initialize the timer to fire at ~100 Hz (10 ms interval) for the first tick.
/// Uses CNTP_CVAL_EL0 (absolute compare) for one-shot operation.
pub fn init() {
    let freq = cntfrq();
    let interval = freq / 100; // 100 Hz
    TIMER_INTERVAL.store(interval, Ordering::Relaxed);

    // Program first one-shot deadline using absolute compare.
    let first_deadline = counter() + interval;
    unsafe {
        core::arch::asm!("msr cntp_cval_el0, {}", in(reg) first_deadline);
        // Enable the timer: ENABLE=1, IMASK=0.
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
    }

    // Enable the timer interrupt in the GIC.
    super::irq::enable_interrupt(super::irq::INTID_TIMER_EL1_PHYS);

    crate::println!(
        "  Timer initialized (one-shot): freq={} Hz, interval={} ticks ({}ms)",
        freq,
        interval,
        1000 * interval / freq
    );
}

/// Initialize the timer on a secondary CPU (one-shot mode).
pub fn init_ap() {
    let interval = TIMER_INTERVAL.load(Ordering::Relaxed);
    let first_deadline = counter() + interval;
    unsafe {
        core::arch::asm!("msr cntp_cval_el0, {}", in(reg) first_deadline);
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64);
    }
}

/// Handle timer interrupt: increment tick count. Timer is NOT rearmed here;
/// the scheduler calls `program_oneshot()` after processing the tick.
pub fn handle_timer_irq() {
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
}

/// Program the timer to fire at `deadline_ns` nanoseconds since boot.
/// Converts from nanoseconds to counter ticks and writes CNTP_CVAL_EL0.
pub fn program_oneshot(deadline_ns: u64) {
    let freq = cntfrq() as u128;
    let ticks = ((deadline_ns as u128 * freq) / 1_000_000_000u128) as u64;
    // Ensure we don't program a value in the past (fire ASAP).
    let now = counter();
    let cval = if ticks > now { ticks } else { now + 1 };
    unsafe {
        core::arch::asm!("msr cntp_cval_el0, {}", in(reg) cval);
    }
}

/// Unmask IRQs (clear DAIF.I bit) to allow interrupts.
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("msr daifclr, #2"); // Clear IRQ mask
    }
}
