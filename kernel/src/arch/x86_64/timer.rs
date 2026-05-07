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

/// Detect TSC frequency via CPUID and store it in TSC_HZ.  Tries leaf
/// 0x15 (TSC/crystal ratio) first, then leaf 0x16 (base CPU MHz) as a
/// fallback.  If neither leaf is available, leaves the conservative
/// 1 GHz default in place.  Idempotent; safe to call multiple times.
pub fn init_tsc_freq() {
    if let Some(hz) = tsc_freq_from_cpuid() {
        TSC_HZ.store(hz, core::sync::atomic::Ordering::Release);
        crate::println!("  TSC frequency: {} Hz (CPUID)", hz);
    } else {
        crate::println!(
            "  TSC frequency: assumed {} Hz (CPUID 0x15/0x16 unavailable)",
            TSC_HZ.load(core::sync::atomic::Ordering::Acquire),
        );
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
