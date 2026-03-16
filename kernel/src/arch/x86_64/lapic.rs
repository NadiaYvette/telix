//! Local APIC (xAPIC) driver for x86-64 SMP.
//!
//! The LAPIC is memory-mapped at 0xFEE00000 (default base).
//! Each CPU has its own LAPIC with the same base address (CPU-local view).

const LAPIC_BASE: usize = 0xFEE0_0000;

// Register offsets.
const LAPIC_ID: usize = 0x020;
const LAPIC_EOI: usize = 0x0B0;
const LAPIC_SVR: usize = 0x0F0;
const LAPIC_ICR_LOW: usize = 0x300;
const LAPIC_ICR_HIGH: usize = 0x310;
const LAPIC_TIMER_LVT: usize = 0x320;
const LAPIC_TIMER_INIT: usize = 0x380;
const LAPIC_TIMER_CURRENT: usize = 0x390;
const LAPIC_TIMER_DIV: usize = 0x3E0;

#[inline]
fn read(offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((LAPIC_BASE + offset) as *const u32) }
}

#[inline]
fn write(offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((LAPIC_BASE + offset) as *mut u32, val); }
}

/// Get the LAPIC ID of the current CPU.
pub fn id() -> u32 {
    (read(LAPIC_ID) >> 24) & 0xFF
}

/// Initialize the BSP's LAPIC.
pub fn init_bsp() {
    // Enable LAPIC: set SVR bit 8 (APIC Software Enable), spurious vector = 0xFF.
    write(LAPIC_SVR, 0x100 | 0xFF);
    // Send EOI to clear any pending interrupts.
    write(LAPIC_EOI, 0);
    crate::println!("  LAPIC initialized (BSP ID={})", id());
}

/// Initialize a secondary CPU's LAPIC.
pub fn init_ap() {
    write(LAPIC_SVR, 0x100 | 0xFF);
    write(LAPIC_EOI, 0);
}

/// Send End-of-Interrupt.
pub fn eoi() {
    write(LAPIC_EOI, 0);
}

/// Send INIT IPI to a target LAPIC ID.
pub fn send_init(target_id: u32) {
    // ICR high: destination = target LAPIC ID.
    write(LAPIC_ICR_HIGH, target_id << 24);
    // ICR low: delivery=INIT (5), level=assert, trigger=edge.
    write(LAPIC_ICR_LOW, 0x0000_4500);
    wait_icr_idle();
}

/// Send Startup IPI (SIPI) to a target LAPIC ID.
/// vector_page = physical page number (trampoline_addr >> 12).
pub fn send_sipi(target_id: u32, vector_page: u8) {
    write(LAPIC_ICR_HIGH, target_id << 24);
    // ICR low: delivery=SIPI (6), vector = page number.
    write(LAPIC_ICR_LOW, 0x0000_4600 | (vector_page as u32));
    wait_icr_idle();
}

/// Wait for the ICR delivery status bit to clear.
fn wait_icr_idle() {
    // Bit 12 = delivery status. 0 = idle, 1 = send pending.
    while read(LAPIC_ICR_LOW) & (1 << 12) != 0 {
        core::hint::spin_loop();
    }
}

/// Configure the LAPIC timer for periodic interrupts.
/// Uses vector 32 (same as PIT), divider 16.
pub fn setup_timer() {
    // Divide configuration: value 3 = divide by 16.
    write(LAPIC_TIMER_DIV, 0x03);
    // LVT Timer: vector 32, periodic mode (bit 17).
    write(LAPIC_TIMER_LVT, 32 | (1 << 17));
    // Initial count — calibrated roughly for ~100 Hz.
    // QEMU's LAPIC timer frequency varies. A safe starting value:
    // We'll use a large count and adjust. For QEMU, ~1_000_000 at div 16 ≈ 100 Hz.
    write(LAPIC_TIMER_INIT, 1_000_000);
}

/// Delay roughly N microseconds using a busy loop.
/// This is very approximate — used only during AP startup.
/// Under QEMU TCG, spin loops are much slower than real hardware,
/// so we use a modest iteration count.
pub fn delay_us(us: u32) {
    for _ in 0..(us as u64 * 10) {
        core::hint::spin_loop();
    }
}
