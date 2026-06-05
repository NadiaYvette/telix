//! Local APIC (xAPIC) driver for x86-64 SMP.
//!
//! The LAPIC is memory-mapped at 0xFEE00000 (default base).
//! Each CPU has its own LAPIC with the same base address (CPU-local view).
//!
//! The LAPIC timer is used in one-shot mode for tickless operation.
//! `calibrate_timer()` measures the LAPIC frequency using the PIT,
//! then `program_oneshot()` arms the timer for a specific deadline.

use core::sync::atomic::{AtomicU64, Ordering};

/// Calibrated LAPIC timer frequency (ticks per second at divider 16).
static LAPIC_TIMER_FREQ: AtomicU64 = AtomicU64::new(0);

// LAPIC base discovered from firmware (ACPI MADT), default fallback.
// #235 C2e: returns a PHYS_DIRECT_MAP kva so MMIO access works on any
// CR3, including user PTs whose PML4[0] is empty after the unmap.
const LAPIC_FALLBACK: usize = 0xFEE0_0000;
fn lapic_base() -> usize {
    let info = crate::firmware::irq_controller();
    let pa = if info.kind != 0 {
        info.base0 as usize
    } else {
        LAPIC_FALLBACK
    };
    crate::mm::page::phys_to_kva(pa)
}

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

// PIT ports for calibration.
const PIT_CH2_DATA: u16 = 0x42;
const PIT_CMD: u16 = 0x43;
const PIT_GATE: u16 = 0x61;
const PIT_FREQ: u64 = 1_193_182;

#[inline]
fn read(offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((lapic_base() + offset) as *const u32) }
}

#[inline]
fn write(offset: usize, val: u32) {
    unsafe {
        core::ptr::write_volatile((lapic_base() + offset) as *mut u32, val);
    }
}

#[inline]
unsafe fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack));
    }
    val
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

/// #135 LAPIC state probe — snapshots this CPU's own LAPIC registers
/// into its `PerCpuData` slot.  Called from the timer-tick handler
/// (vector 32), which is known-working on all CPUs even when vector
/// 0xFD (reschedule IPI) has stopped delivering.  The rescue dump
/// reads these cross-CPU to diagnose per-CPU vector-0xFD blockage:
///   * `isr_f` bit 29 (vector 0xFD = 253; 253-224=29) set → ISR is
///     stuck (missed-EOI), new 0xFD IPIs queue in IRR but won't deliver
///   * `irr_f` bit 29 set persistently → pending IPI not being delivered
///   * `tpr` ≥ 0xF0 → priority class blocks 0xFD (priority class = 0xF)
///   * `svr` bit 8 cleared → LAPIC software-disabled
pub fn snapshot_state_to_pcpu() {
    let cpu = crate::sched::smp::cpu_id() as usize;
    if cpu >= crate::sched::smp::MAX_CPUS {
        return;
    }
    let pcpu = crate::sched::smp::get(cpu as u32);
    use core::sync::atomic::Ordering;
    pcpu.lapic_isr_f.store(read(0x170), Ordering::Relaxed);
    pcpu.lapic_irr_f.store(read(0x270), Ordering::Relaxed);
    pcpu.lapic_tpr.store(read(0x080), Ordering::Relaxed);
    pcpu.lapic_svr.store(read(0x0F0), Ordering::Relaxed);
    pcpu.lapic_ppr.store(read(0x0A0), Ordering::Relaxed);
    // ESR: writing first latches current error state for reading.
    // We don't currently use APIC errors for control, just observe.
    pcpu.lapic_esr.store(read(0x280), Ordering::Relaxed);
    // OR of low ISR registers (0x100-0x160, 7 dwords covering vectors
    // 0-223).  Anything non-zero means a vector below 0xE0 is in-service,
    // which raises PPR and blocks higher classes for the duration.
    let isr_or = read(0x100) | read(0x110) | read(0x120) | read(0x130)
        | read(0x140) | read(0x150) | read(0x160);
    pcpu.lapic_isr_lo_or.store(isr_or, Ordering::Relaxed);
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

/// Calibrate the LAPIC timer frequency using PIT channel 2.
///
/// Uses the PIT as a reference clock: programs PIT ch2 for a known delay,
/// starts the LAPIC timer counting down from max, waits for PIT to expire,
/// then reads how many LAPIC ticks elapsed. Repeats 3 times for accuracy.
pub fn calibrate_timer() {
    // Set divider to 16 (register value 0x03).
    write(LAPIC_TIMER_DIV, 0x03);
    // Mask the LAPIC timer LVT (don't fire interrupts during calibration).
    write(LAPIC_TIMER_LVT, 1 << 16); // masked

    // PIT channel 2 calibration: ~50ms delay for accuracy.
    // PIT divisor for 50ms: PIT_FREQ * 50 / 1000 = 59659.
    let pit_divisor: u16 = (PIT_FREQ * 50 / 1000) as u16;

    let mut best_freq: u64 = 0;
    let mut samples = [0u64; 3];

    for i in 0..3 {
        // Configure PIT channel 2, mode 0 (terminal count), binary.
        unsafe {
            // Disable speaker gate, enable PIT ch2 gate.
            let gate = inb(PIT_GATE);
            outb(PIT_GATE, (gate & !0x02) | 0x01); // gate=1, speaker=0
            // Channel 2, access lobyte/hibyte, mode 0, binary.
            outb(PIT_CMD, 0xB0);
            outb(PIT_CH2_DATA, (pit_divisor & 0xFF) as u8);
            outb(PIT_CH2_DATA, (pit_divisor >> 8) as u8);

            // Reset PIT ch2 gate to start counting.
            let gate = inb(PIT_GATE);
            outb(PIT_GATE, gate & !0x01); // gate=0
            outb(PIT_GATE, gate | 0x01);  // gate=1 (rising edge starts count)
        }

        // Start LAPIC timer at max initial count.
        write(LAPIC_TIMER_INIT, 0xFFFF_FFFF);

        // Wait for PIT ch2 output (bit 5 of port 0x61) to go high.
        unsafe {
            while inb(PIT_GATE) & 0x20 == 0 {
                core::hint::spin_loop();
            }
        }

        // Read how many LAPIC ticks elapsed.
        let remaining = read(LAPIC_TIMER_CURRENT);
        let elapsed = 0xFFFF_FFFFu32 - remaining;

        // Compute frequency: elapsed ticks in 50ms → freq = elapsed * 20.
        samples[i] = elapsed as u64 * 20;
    }

    // Stop the LAPIC timer.
    write(LAPIC_TIMER_INIT, 0);

    // Take the median of 3 samples.
    samples.sort_unstable();
    best_freq = samples[1];

    // Sanity check: LAPIC timer should be between 10 MHz and 10 GHz.
    if best_freq < 10_000_000 || best_freq > 10_000_000_000 {
        // Fallback: assume ~100 MHz (QEMU default-ish).
        best_freq = 100_000_000;
        crate::println!("  LAPIC timer calibration: out of range, using fallback {}Hz", best_freq);
    } else {
        crate::println!("  LAPIC timer calibrated: {} Hz (div 16)", best_freq);
    }

    LAPIC_TIMER_FREQ.store(best_freq, Ordering::Relaxed);
}

/// Configure the LAPIC timer in one-shot mode on vector 32.
/// Call after `calibrate_timer()`. Does not arm the timer yet.
pub fn setup_timer() {
    // Divide configuration: value 3 = divide by 16.
    write(LAPIC_TIMER_DIV, 0x03);
    // LVT Timer: vector 32, one-shot mode (bit 17 = 0).
    write(LAPIC_TIMER_LVT, 32);
    // Don't write initial count — timer stays idle until program_oneshot().
}

/// Program the LAPIC timer to fire at `deadline_ns` nanoseconds since boot.
pub fn program_oneshot(deadline_ns: u64) {
    let now_ns = crate::arch::timer::monotonic_ns();
    let delta_ns = deadline_ns.saturating_sub(now_ns);
    let freq = LAPIC_TIMER_FREQ.load(Ordering::Relaxed);
    if freq == 0 {
        return; // Not yet calibrated.
    }
    // Convert delta_ns to LAPIC ticks: ticks = delta_ns * freq / 1e9.
    let ticks = ((delta_ns as u128 * freq as u128) / 1_000_000_000u128) as u32;
    let ticks = if ticks == 0 { 1 } else { ticks };
    // Ensure LVT is unmasked and one-shot.
    write(LAPIC_TIMER_LVT, 32);
    write(LAPIC_TIMER_INIT, ticks);
}

/// Reschedule IPI counters (diagnostic).  Incremented in `send_reschedule`
/// after the LAPIC ICR write and in the 0xFD vector handler at IRQ entry.
/// Surfaced in the watchdog dump's `sgi=(s=… r=…)` field on x86 so we can
/// distinguish "parked CPU is being poked but stuck" (counts increasing)
/// from "CPU is not being poked at all" (counts flat).
pub static IPI_SEND_COUNT: AtomicU64 = AtomicU64::new(0);
pub static IPI_RECV_COUNT: AtomicU64 = AtomicU64::new(0);

/// Broadcast a TLB-flush IPI (vector 0xFC) to all other CPUs.
/// The handler does `mov rax, cr3; mov cr3, rax`, flushing non-global
/// TLB entries on the receiving CPU.  Used after demoting shared page
/// tables (e.g. PHYS_DIRECT_MAP gigapages) so peers don't keep stale
/// cached translations.  Spins until ICR idle; returns without waiting
/// for the peer to actually finish the CR3 reload (caller is responsible
/// for any additional synchronization).
pub fn broadcast_tlb_flush() {
    wait_icr_idle();
    // ICR high unused (destination shorthand = all-excluding-self).
    write(LAPIC_ICR_HIGH, 0);
    // Vector 0xFC, fixed delivery, physical, edge, assert,
    // destination-shorthand = 11 (All Excluding Self, bits 18-19).
    write(LAPIC_ICR_LOW, 0xFC | (0b11 << 18));
    wait_icr_idle();
}

/// TLB-flush IPI receive counter (diagnostic).
pub static TLB_FLUSH_RECV_COUNT: AtomicU64 = AtomicU64::new(0);

/// Send a reschedule IPI (vector 0xFD) to a target CPU.
///
/// The target CPU wakes from HLT (if idle) and runs try_switch(),
/// which discovers the newly-enqueued thread.  Uses a dedicated vector
/// to avoid tick count inflation and full timer processing.
pub fn send_reschedule(target_lapic_id: u32) {
    wait_icr_idle();
    write(LAPIC_ICR_HIGH, target_lapic_id << 24);
    // Fixed delivery (000), vector 0xFD, edge-triggered, assert.
    write(LAPIC_ICR_LOW, 0xFD);
    IPI_SEND_COUNT.fetch_add(1, Ordering::Relaxed);
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
