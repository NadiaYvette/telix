//! PL011 UART driver for QEMU virt machine.
//!
//! The PL011 is at MMIO address 0x0900_0000 on the QEMU aarch64 virt platform.
//! We only implement polled transmit — enough for early boot console output.

use core::fmt;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering as AOrdering};

const PL011_BASE: usize = 0x0900_0000;

// PL011 register offsets.
const UARTDR: usize = 0x000; // Data register
const UARTFR: usize = 0x018; // Flag register

// Flag register bits.
const UARTFR_RXFE: u32 = 1 << 4; // Receive FIFO empty
const UARTFR_TXFF: u32 = 1 << 5; // Transmit FIFO full

/// #252 anti-interleave lock for fault-handler emits.  Held with IRQs
/// disabled across the full byte sequence so peer CPUs spin-wait until
/// release instead of mashing their bytes into ours.  Mirror of the
/// x86_64 DirectUart pattern from #224 (kernel/src/arch/x86_64/serial.rs).
static PRINT_LOCK: AtomicUsize = AtomicUsize::new(0);
/// CPU currently holding PRINT_LOCK; -1 = none.  Same-CPU re-entry
/// (nested exception during a dump) is detected and bypasses the lock
/// to avoid deadlock — peers are still excluded by the outer holder.
static PRINT_HOLDER_CPU: AtomicI32 = AtomicI32::new(-1);

struct Pl011;

impl Pl011 {
    fn putc(&self, c: u8) {
        let base = PL011_BASE as *mut u32;
        unsafe {
            // Spin while transmit FIFO is full.
            while core::ptr::read_volatile(base.byte_add(UARTFR)) & UARTFR_TXFF != 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(base.byte_add(UARTDR), c as u32);
        }
    }

    /// Push a pre-formatted byte buffer with no '\n' translation and no
    /// `core::fmt` indirection.  Used inside the exception handler dump
    /// path so the format machinery doesn't run on a corrupted kstack.
    fn push_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            self.putc(b);
        }
    }
}

impl fmt::Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.putc(b'\r');
            }
            self.putc(byte);
        }
        Ok(())
    }
}

/// #252 fault-handler emit path.  Acquires PRINT_LOCK with IRQs
/// disabled, holds it for the entire byte sequence, then releases.
/// Re-entry on the same CPU bypasses the lock (nested exception
/// during a dump) to avoid deadlock — peer CPUs are still excluded
/// by the outer holder.
///
/// CAUTION: writes byte-by-byte at the PL011 line rate (115 kbps on
/// real hardware, much faster in QEMU).  Other CPUs spin during the
/// emit window.  Intended for exception-handler dumps where multi-line
/// atomicity matters, not for routine logging.
pub fn handler_write_bytes(bytes: &[u8]) {
    let my_cpu = crate::sched::smp::cpu_id() as i32;
    if PRINT_HOLDER_CPU.load(AOrdering::Acquire) == my_cpu {
        // Same-CPU re-entry: outer caller already holds the lock, so
        // bytes interleave only with the outer call (not with peers).
        Pl011.push_bytes(bytes);
        return;
    }
    let saved;
    loop {
        while PRINT_LOCK.load(AOrdering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
        let s = crate::arch::irq::disable();
        if PRINT_LOCK
            .compare_exchange(0, 1, AOrdering::Acquire, AOrdering::Relaxed)
            .is_ok()
        {
            saved = s;
            break;
        }
        crate::arch::irq::restore(s);
    }
    PRINT_HOLDER_CPU.store(my_cpu, AOrdering::Release);
    Pl011.push_bytes(bytes);
    PRINT_HOLDER_CPU.store(-1, AOrdering::Release);
    PRINT_LOCK.store(0, AOrdering::Release);
    crate::arch::irq::restore(saved);
}

/// #255 per-CPU fault buffer.  Lives in BSS at a known-good VA so a
/// fault handler whose kstack is corrupt (the very bug we're
/// diagnosing) can still format an emit into a sane location.  Stack-
/// local bufs were the bug source on boot loop-aa64-2: when the EL1
/// Sync handler fires on a thread with `frame_sp` outside kstack
/// bounds, the stack-local `[u8; N]` lands in arbitrary memory and
/// produces NUL-prefix + clean-tail emissions (see
/// memory/project_aarch64_handler_buf_kstack.md).
///
/// Sized to hold the largest formatted record (the EL1 Sync header is
/// the worst case at ~250 bytes; 512 leaves headroom).  At 256 CPUs ×
/// 512 B = 128 KiB BSS — acceptable for the diagnostic improvement.
///
/// Nested-fault caveat: if a fault re-enters the same handler on the
/// same CPU while the outer call is still building its record, the
/// nested handler will scribble the buf.  The same-CPU re-entry bypass
/// in `handler_write_bytes` emits whatever is in the buf at that point,
/// which is acceptable — we still get one of the two records out
/// cleanly, whereas with the stack-local approach we got neither.
const FAULT_BUF_SIZE: usize = 512;
#[repr(align(16))]
struct PerCpuFaultBuf([u8; FAULT_BUF_SIZE]);
static mut FAULT_BUFS: [PerCpuFaultBuf; crate::sched::smp::MAX_CPUS] =
    [const { PerCpuFaultBuf([0; FAULT_BUF_SIZE]) }; crate::sched::smp::MAX_CPUS];

/// Borrow this CPU's fault buffer as a mutable slice.
///
/// SAFETY: caller must hold the formatting-side discipline that no two
/// emits proceed concurrently on the same CPU.  Currently enforced
/// because the only callers are fault handlers (which run with IRQs
/// disabled) and `handler_write_bytes` serializes across CPUs.
pub fn fault_buf_for_current_cpu() -> &'static mut [u8] {
    let cpu = crate::sched::smp::cpu_id() as usize;
    unsafe {
        let base = (&raw mut FAULT_BUFS) as *mut PerCpuFaultBuf;
        let slot = base.add(cpu);
        let bytes = (*slot).0.as_mut_ptr();
        core::slice::from_raw_parts_mut(bytes, FAULT_BUF_SIZE)
    }
}

// #252 escape helpers — let fault-path code emit log lines that share
// NO state with format_args!() / Argument arrays.  Callers build the
// whole line into a `&mut [u8]` (now per-CPU static via
// `fault_buf_for_current_cpu`), then pass it to `handler_write_bytes`
// for an atomic PRINT_LOCK-guarded emit.  Avoids the optimizer-overlap
// where format Argument storage shadows a caller's locals during a
// fault dump (the bug #224 fixed on x86_64 and that this mirror brings
// to aarch64).
//
// All take `(buf, &mut n, ...)` and append to buf, capping writes at
// buf.len() so the caller's `n.min(buf.len())` slice is always sound.
#[inline]
pub fn put_byte(buf: &mut [u8], n: &mut usize, b: u8) {
    if *n < buf.len() {
        buf[*n] = b;
        *n += 1;
    }
}
#[inline]
pub fn put_bytes(buf: &mut [u8], n: &mut usize, s: &[u8]) {
    for &b in s {
        put_byte(buf, n, b);
    }
}
#[inline]
pub fn put_hex_u64(buf: &mut [u8], n: &mut usize, mut v: u64) {
    put_bytes(buf, n, b"0x");
    if v == 0 {
        put_byte(buf, n, b'0');
        return;
    }
    let mut digits = [0u8; 16];
    let mut k = 0;
    while v > 0 {
        let d = (v & 0xf) as u8;
        digits[k] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
        v >>= 4;
        k += 1;
    }
    for i in (0..k).rev() {
        put_byte(buf, n, digits[i]);
    }
}
#[inline]
pub fn put_dec_u64(buf: &mut [u8], n: &mut usize, mut v: u64) {
    if v == 0 {
        put_byte(buf, n, b'0');
        return;
    }
    let mut digits = [0u8; 20];
    let mut k = 0;
    while v > 0 {
        digits[k] = b'0' + (v % 10) as u8;
        v /= 10;
        k += 1;
    }
    for i in (0..k).rev() {
        put_byte(buf, n, digits[i]);
    }
}

/// Read a single byte from the UART (non-blocking).
pub fn getc() -> Option<u8> {
    let base = PL011_BASE as *mut u32;
    unsafe {
        if core::ptr::read_volatile(base.byte_add(UARTFR)) & UARTFR_RXFE != 0 {
            None
        } else {
            Some(core::ptr::read_volatile(base.byte_add(UARTDR)) as u8)
        }
    }
}

/// Write a single byte to the UART.
pub fn putc(c: u8) {
    Pl011.putc(c);
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    Pl011.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::arch::aarch64::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
