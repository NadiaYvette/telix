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
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
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
    let _ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
}

/// Read the Time Stamp Counter (RDTSC).
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Enable interrupts (STI).
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// Calibrated TSC frequency in Hz.  Set once at boot by `init_tsc_freq`
/// (called from arch::x86_64::mod::init).  Defaults to 1 GHz so any code
/// reading it before init returns the historical value.
///
/// Pre-fix, the freq was hardcoded to 1 GHz in `arch::timer::timer_freq`.
/// On real KVM the host TSC is typically 2–4 GHz, so monotonic_ns came
/// back ~2–4× larger than real elapsed time — every sleep_ms / watchdog /
/// retry budget was dilated by the same factor, blowing chase budgets.
pub static TSC_HZ: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1_000_000_000);

/// Detect TSC frequency and store it in TSC_HZ.  Order:
///   1. CPUID leaf 0x15 (TSC/crystal ratio + crystal Hz from CPUID)
///   2. CPUID leaf 0x16 (base CPU MHz from CPUID)
///   3. PIT-channel-2 gated calibration (counts RDTSC over a known
///      number of PIT cycles)
///   4. Conservative 1 GHz default (if all three fail)
/// Idempotent; safe to call multiple times.  Must be called *before*
/// LAPIC calibration in the boot sequence so monotonic_ns is correct
/// for any timer scheduling that follows.
pub fn init_tsc_freq() {
    if let Some(hz) = tsc_freq_from_cpuid() {
        TSC_HZ.store(hz, core::sync::atomic::Ordering::Release);
        crate::println!("  TSC frequency: {} Hz (CPUID)", hz);
        return;
    }
    if let Some(hz) = tsc_freq_from_pit() {
        TSC_HZ.store(hz, core::sync::atomic::Ordering::Release);
        crate::println!("  TSC frequency: {} Hz (PIT-calibrated)", hz);
        return;
    }
    crate::println!(
        "  TSC frequency: assumed {} Hz (CPUID + PIT calibration both unavailable)",
        TSC_HZ.load(core::sync::atomic::Ordering::Acquire),
    );
}

/// PIT-channel-2 gated TSC calibration.  Channel 2's gate is software-
/// controlled (port 0x61 bit 0) and its OUT pin is observable on port
/// 0x61 bit 5 — so we can program a one-shot, time it from outside the
/// IRQ path, and read RDTSC at the OUT-pin transition.  This is the
/// classic TSC-calibration method on bare PCs and works on any x86 KVM
/// configuration that exposes PIT (essentially all of them).
///
/// Method: program channel 2 mode 0 (interrupt-on-terminal-count) with
/// a divisor near 64 ms worth of ticks (76544 / 1193182 Hz ≈ 64 ms),
/// snapshot RDTSC, busy-wait for OUT to go high, snapshot RDTSC again,
/// extrapolate.  Doesn't disturb channel 0 (the kernel tick source).
fn tsc_freq_from_pit() -> Option<u64> {
    use super::serial::{inb, outb};
    const PIT_FREQ: u32 = 1_193_182;
    const PIT_CH2_DATA: u16 = 0x42;
    const PIT_CMD: u16 = 0x43;
    const PORT_61: u16 = 0x61;
    // ~64 ms gives good resolution; max 16-bit value is 65535 (~55 ms).
    const DIVISOR: u16 = 65000;
    unsafe {
        // Save and configure port 0x61: bit 0 = ch2 gate, bit 1 = speaker.
        // Disable speaker (bit 1 = 0), enable ch2 gate (bit 0 = 1).
        let saved_61 = inb(PORT_61);
        outb(PORT_61, (saved_61 & 0xfd) | 0x01);
        // PIT command: ch2, lo/hi, mode 0, binary.
        outb(PIT_CMD, 0xb0);
        outb(PIT_CH2_DATA, (DIVISOR & 0xff) as u8);
        outb(PIT_CH2_DATA, (DIVISOR >> 8) as u8);
        let t0 = rdtsc();
        // Wait for OUT (port 0x61 bit 5) to go high — this happens when
        // the down-counter reaches zero.  Budget enough for the full
        // ~55 ms wait plus slack.
        let mut spins: u64 = 0;
        const MAX_SPINS: u64 = 1_000_000_000;
        while (inb(PORT_61) & 0x20) == 0 {
            spins += 1;
            if spins >= MAX_SPINS {
                // Something is wrong — PIT didn't tick.  Restore port and bail.
                outb(PORT_61, saved_61);
                return None;
            }
        }
        let t1 = rdtsc();
        // Restore original port 0x61 state.
        outb(PORT_61, saved_61);
        let cycles = t1.wrapping_sub(t0);
        if cycles == 0 {
            return None;
        }
        // tsc_freq = cycles * PIT_FREQ / DIVISOR
        Some((cycles as u128 * PIT_FREQ as u128 / DIVISOR as u128) as u64)
    }
}

/// Try to get TSC frequency from CPUID.  Returns Some(hz) on success.
fn tsc_freq_from_cpuid() -> Option<u64> {
    // CPUID(EAX=0): EAX = max basic leaf supported.
    let max_leaf: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 0",
            "cpuid",
            "pop rbx",
            inout("eax") 0u32 => max_leaf,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
    if max_leaf >= 0x15 {
        // CPUID 0x15: EBX/EAX = TSC:crystal ratio numerator/denominator,
        // ECX = crystal frequency Hz (0 if unknown).
        let denom: u32;
        let numer: u32;
        let crystal_hz: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 0x15",
                "cpuid",
                "mov {numer:e}, ebx",
                "pop rbx",
                inout("eax") 0u32 => denom,
                numer = out(reg) numer,
                out("ecx") crystal_hz,
                out("edx") _,
                options(nostack, preserves_flags),
            );
        }
        if denom != 0 && numer != 0 && crystal_hz != 0 {
            return Some((crystal_hz as u64) * (numer as u64) / (denom as u64));
        }
    }
    if max_leaf >= 0x16 {
        // CPUID 0x16: EAX low 16 bits = base CPU frequency in MHz.
        let base_mhz: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 0x16",
                "cpuid",
                "pop rbx",
                inout("eax") 0u32 => base_mhz,
                out("ecx") _,
                out("edx") _,
                options(nostack, preserves_flags),
            );
        }
        let mhz = base_mhz & 0xFFFF;
        if mhz != 0 {
            return Some((mhz as u64) * 1_000_000);
        }
    }
    None
}
