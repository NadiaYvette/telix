//! 16550 UART driver for x86-64 (COM1 at I/O port 0x3F8).
//!
//! Uses x86 port I/O instructions (outb/inb) for polled transmit.

use core::fmt;

const COM1_PORT: u16 = 0x3F8;

// 16550 register offsets from base port.
const THR: u16 = 0; // Transmit Holding Register (write)
const IER: u16 = 1; // Interrupt Enable Register (write) / DLM when DLAB
const FCR: u16 = 2; // FIFO Control Register (write) / IIR (read)
const LCR: u16 = 3; // Line Control Register
const LSR: u16 = 5; // Line Status Register (read)

// LSR bits.
const LSR_DR: u8 = 1 << 0; // Data Ready
const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty

// 16550A FIFO depth — the TX FIFO holds 16 bytes.  Once THRE is set
// after enabling the FIFO, we can push up to 16 bytes without checking
// LSR between them.  Cuts the inb() VM-exits per byte from 1:1 to 1:16.
const FIFO_DEPTH: usize = 16;

#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack));
    }
    val
}

#[inline]
pub unsafe fn outw(port: u16, val: u16) {
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
    }
}

#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") val, options(nomem, nostack));
    }
    val
}

#[inline]
pub unsafe fn outl(port: u16, val: u32) {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack));
    }
}

#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") val, options(nomem, nostack));
    }
    val
}

struct Serial;

impl Serial {
    fn putc(&self, c: u8) {
        unsafe {
            // Wait until the transmit holding register is empty.
            while inb(COM1_PORT + LSR) & LSR_THRE == 0 {
                core::hint::spin_loop();
            }
            outb(COM1_PORT + THR, c);
        }
    }

    /// #154 FIFO-batched write: wait for THRE once per 16-byte batch
    /// rather than per byte.  Halves the inb() VM-exits for typical
    /// debug lines.  When LSR_THRE is set after FIFO enable, the
    /// 16-byte TX FIFO is empty — we can dump up to FIFO_DEPTH bytes
    /// without checking again.  CR translation for newlines is done
    /// in the caller's buffer (see push_bytes) to avoid widening the
    /// hot loop.
    fn push_bytes(&self, bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() {
            unsafe {
                while inb(COM1_PORT + LSR) & LSR_THRE == 0 {
                    core::hint::spin_loop();
                }
                let chunk = (bytes.len() - i).min(FIFO_DEPTH);
                for &b in &bytes[i..i + chunk] {
                    outb(COM1_PORT + THR, b);
                }
            }
            i += FIFO_DEPTH;
        }
    }
}

/// #154 one-time UART init: enable the 16-byte TX FIFO so push_bytes
/// can batch.  Idempotent — callable multiple times.  Should be invoked
/// once during early boot; we keep it lazy so we don't have to thread
/// an init call through bootstrap.
fn init_uart_fifo_once() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::Relaxed) {
        return;
    }
    unsafe {
        // LCR: 8N1, DLAB=0.
        outb(COM1_PORT + LCR, 0x03);
        // IER: disable all UART interrupts (we use polled output only).
        outb(COM1_PORT + IER, 0x00);
        // FCR: enable FIFO, reset RX/TX FIFOs, RX trigger 14 bytes
        //   bit 0: FIFO enable
        //   bit 1: clear RX FIFO
        //   bit 2: clear TX FIFO
        //   bits 6-7: 0b11 = 14-byte RX trigger
        outb(COM1_PORT + FCR, 0xC7);
    }
}

/// Read a single byte from the UART (non-blocking).
pub fn getc() -> Option<u8> {
    unsafe {
        if inb(COM1_PORT + LSR) & LSR_DR == 0 {
            None
        } else {
            Some(inb(COM1_PORT + THR))
        }
    }
}

/// Write a single byte to the UART.
pub fn putc(c: u8) {
    Serial.putc(c);
}

// Holding this lock across the duration of one `_print` call serialises
// concurrent writers — without it, multi-CPU `println!` calls interleave
// at byte granularity and produce unparseable output (per-CPU bytes
// land out of order on the wire).  `SpinLock` is interrupt-safe so
// IRQ-context prints don't deadlock against thread-context prints on
// the same CPU.
//
// #154: the lock holds IRQs OFF for the duration of byte-push.  We
// keep that property (same-CPU re-entry safety) but minimize the hold
// time by pre-formatting outside the lock — see `_print`.
static PRINT_LOCK: crate::sync::SpinLock<()> = crate::sync::SpinLock::new(());

/// #154 print buffer size.  2048 bytes is enough for the long-form
/// rescue/IPI-CNT/CLI-TOP debug lines (typically 100-500 bytes each);
/// overflow truncates rather than panics.
const PRINT_BUF_SIZE: usize = 2048;

/// Fixed-size in-stack buffer implementing `fmt::Write`.  Used to
/// format println! output OUTSIDE the print lock so the IRQs-off
/// critical section only covers the byte-push to the UART.  Boot 44's
/// CLI-TOP probe showed serial::_print as the dominant CLI offender
/// (12-67ms per call across all CPUs); pre-formatting moves the
/// expensive integer-to-string + arg-formatting work out of the
/// lock-held window.
struct StackBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> StackBuf<N> {
    fn new() -> Self {
        Self { buf: [0u8; N], len: 0 }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    fn as_str(&self) -> &str {
        // format_args produces UTF-8; our pushes preserve it.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl<const N: usize> fmt::Write for StackBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let space = N - self.len;
        let n = bytes.len().min(space);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        if bytes.len() > n { Err(fmt::Error) } else { Ok(()) }
    }
}

/// #154 expand `\n` → `\r\n` in-place at format time.  We need this
/// because the UART expects CRLF for proper line breaks and we don't
/// want a per-byte conditional in the inner push loop.  Worst case
/// expansion is 2× (all-newlines), so callers must size their buffer
/// accordingly — PRINT_BUF_SIZE=2048 vs PRINT_FMT_LIMIT=1024 gives
/// room.
const PRINT_FMT_LIMIT: usize = 1024;

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    // First-call FIFO init.  Cheap atomic check on subsequent calls.
    init_uart_fifo_once();

    // Phase 1: format into a per-call stack buffer with IRQs ON.
    // Two buffers: one for the raw format output, one for CRLF-expanded
    // bytes that go to the UART.  Keeping them split lets the
    // framebuffer mirror use the un-expanded text (it handles \n itself).
    let mut fmtbuf = StackBuf::<PRINT_FMT_LIMIT>::new();
    let _ = fmtbuf.write_fmt(args);  // truncation OK

    // CRLF-expand into the wire buffer.
    let mut wirebuf = StackBuf::<PRINT_BUF_SIZE>::new();
    for &b in fmtbuf.as_bytes() {
        if b == b'\n' {
            let _ = wirebuf.write_str("\r\n");
        } else {
            // write_str of a 1-byte slice that we own.
            let one = [b];
            let _ = wirebuf.write_str(unsafe { core::str::from_utf8_unchecked(&one) });
        }
    }

    // Phase 2: acquire the lock and push the pre-formatted bytes
    // through the 16-byte UART FIFO.  IRQs are OFF only for this push.
    {
        let _g = PRINT_LOCK.lock();
        Serial.push_bytes(wirebuf.as_bytes());
    }

    // Mirror to the framebuffer console (no UART contention).
    if crate::drivers::fb_console::available() {
        crate::drivers::fb_console::write_str(fmtbuf.as_str());
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::arch::x86_64::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
