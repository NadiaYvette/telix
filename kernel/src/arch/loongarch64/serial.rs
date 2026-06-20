//! LoongArch64 UART (ns16550a) serial output.
//!
//! QEMU virt: UART at physical 0x1FE001E0.
//! Accessed via DMW1 uncached window at 0x8000_0000_1FE0_01E0.

use core::fmt;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering as AOrdering};

const UART_BASE: usize = 0x8000_0000_1FE0_01E0;

/// #254 anti-interleave lock for fault-handler emits — mirror of the
/// x86_64 DirectUart path (#224), aarch64 PL011 path (#252), and
/// riscv64 16550 path (#253).  Held with IRQs disabled across the
/// full byte sequence so peer CPUs spin-wait until release instead of
/// mashing their bytes into ours.
static PRINT_LOCK: AtomicUsize = AtomicUsize::new(0);
/// CPU currently holding PRINT_LOCK; -1 = none.  Same-CPU re-entry
/// (nested exception during a dump) is detected and bypasses the lock
/// to avoid deadlock — peers are still excluded by the outer holder.
static PRINT_HOLDER_CPU: AtomicI32 = AtomicI32::new(-1);

struct Uart16550;

impl Uart16550 {
    fn putc(&self, c: u8) {
        unsafe {
            // Wait for THR empty (LSR bit 5).
            while core::ptr::read_volatile((UART_BASE + 5) as *const u8) & 0x20 == 0 {}
            core::ptr::write_volatile(UART_BASE as *mut u8, c);
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

/// #254 fault-handler emit path.  Acquires PRINT_LOCK with IRQs
/// disabled, holds it for the entire byte sequence, then releases.
/// Re-entry on the same CPU bypasses the lock (nested exception
/// during a dump) to avoid deadlock — peer CPUs are still excluded
/// by the outer holder.
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

// #254 escape helpers — let fault-path code emit log lines that share
// NO state with format_args!() / Argument arrays.  Same shape as the
// x86_64 / aarch64 / riscv64 counterparts.
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
        for b in s.bytes() {
            if b == b'\n' {
                self.putc(b'\r');
            }
            self.putc(b);
        }
        Ok(())
    }
}

/// Write a single byte to the serial port.
pub fn putc(c: u8) {
    Uart16550.putc(c);
}

/// Write a string to the serial port.
pub fn puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

/// Read a single byte from the UART (non-blocking).
pub fn getc() -> Option<u8> {
    unsafe {
        if core::ptr::read_volatile((UART_BASE + 5) as *const u8) & 0x01 == 0 {
            None
        } else {
            Some(core::ptr::read_volatile(UART_BASE as *const u8))
        }
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    // #228 hardening: never panic from a debug print (see riscv64/serial.rs).
    let _ = Uart16550.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::arch::loongarch64::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
