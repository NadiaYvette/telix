//! 16550A UART driver for QEMU RISC-V virt machine.
//!
//! The 16550A UART is at MMIO address 0x1000_0000 on the QEMU riscv64 virt platform.
//! We only implement polled transmit — enough for early boot console output.

use core::fmt;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering as AOrdering};

const UART_BASE: usize = 0x1000_0000;

// 16550 register offsets.
const THR: usize = 0x00; // Transmitter Holding Register (write)
const LSR: usize = 0x05; // Line Status Register (read)

// LSR bits.
const LSR_DR: u8 = 1 << 0; // Data Ready
const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty

/// #253 anti-interleave lock for fault-handler emits — mirror of the
/// x86_64 DirectUart path (#224) and aarch64 PL011 path (#252).  Held
/// with IRQs disabled across the full byte sequence so peer harts
/// spin-wait until release instead of mashing their bytes into ours.
/// Surface B of #251 (second fault inside core::fmt::Formatter::pad_integral
/// when the original-fault println runs over a corrupted kstack) is also
/// dodged by the put_*-helper path which doesn't touch format machinery.
static PRINT_LOCK: AtomicUsize = AtomicUsize::new(0);
/// CPU currently holding PRINT_LOCK; -1 = none.  Same-CPU re-entry
/// (nested exception during a dump) is detected and bypasses the lock
/// to avoid deadlock — peers are still excluded by the outer holder.
static PRINT_HOLDER_CPU: AtomicI32 = AtomicI32::new(-1);

struct Uart16550;

impl Uart16550 {
    fn putc(&self, c: u8) {
        let base = UART_BASE as *mut u8;
        unsafe {
            // Spin while transmit holding register is not empty.
            while core::ptr::read_volatile(base.add(LSR)) & LSR_THRE == 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(base.add(THR), c);
        }
    }

    /// Push a pre-formatted byte buffer with no '\n' translation and no
    /// `core::fmt` indirection.  Used inside the trap handler dump path
    /// so the format machinery doesn't run on a corrupted kstack.
    fn push_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            self.putc(b);
        }
    }
}

/// #253 fault-handler emit path.  Acquires PRINT_LOCK with IRQs
/// disabled, holds it for the entire byte sequence, then releases.
/// Re-entry on the same hart bypasses the lock (nested exception
/// during a dump) to avoid deadlock — peer harts are still excluded
/// by the outer holder.
///
/// CAUTION: writes byte-by-byte at the 16550 line rate.  Other harts
/// spin during the emit window.  Intended for trap-handler dumps where
/// multi-line atomicity matters, not for routine logging.
pub fn handler_write_bytes(bytes: &[u8]) {
    let my_cpu = crate::sched::smp::cpu_id() as i32;
    if PRINT_HOLDER_CPU.load(AOrdering::Acquire) == my_cpu {
        Uart16550.push_bytes(bytes);
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
    Uart16550.push_bytes(bytes);
    PRINT_HOLDER_CPU.store(-1, AOrdering::Release);
    PRINT_LOCK.store(0, AOrdering::Release);
    crate::arch::irq::restore(saved);
}

// #253 escape helpers — let fault-path code emit log lines that share
// NO state with format_args!() / Argument arrays.  Callers build the
// whole line into a stack `[u8; N]`, then pass it to
// `handler_write_bytes` for an atomic PRINT_LOCK-guarded emit.  Avoids
// the optimizer-overlap where format Argument storage shadows a
// caller's locals during a fault dump.
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

impl fmt::Write for Uart16550 {
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

/// Read a single byte from the UART (non-blocking).
pub fn getc() -> Option<u8> {
    let base = UART_BASE as *mut u8;
    unsafe {
        if core::ptr::read_volatile(base.add(LSR)) & LSR_DR == 0 {
            None
        } else {
            Some(core::ptr::read_volatile(base.add(THR)))
        }
    }
}

/// Write a single byte to the UART.
pub fn putc(c: u8) {
    Uart16550.putc(c);
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    Uart16550.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::arch::riscv64::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
