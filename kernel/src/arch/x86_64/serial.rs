//! 16550 UART driver for x86-64 (COM1 at I/O port 0x3F8).
//!
//! Uses x86 port I/O instructions (outb/inb) for polled transmit.

use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicUsize};

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

/// #208 panic-print bypass: a `core::fmt::Write` impl that emits every
/// byte directly to the UART without going through `StackBuf` or the
/// print lock.  When `StackBuf::len` has been corrupted by the #208
/// corruption family, the regular `println!` path can't print the panic
/// message (the bounds-check panic on the corrupted slice recursively
/// re-enters the panic handler, leading to silent triple-fault).  The
/// panic handler should write through this instead.
pub struct DirectUart;

impl fmt::Write for DirectUart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if b == b'\n' {
                Serial.putc(b'\r');
            }
            Serial.putc(b);
        }
        Ok(())
    }
}

/// Emit a pre-formatted byte buffer to the serial port without going
/// through core::fmt.  Used by handler probes that already formatted
/// via a thin hex writer to keep the kstack frame small.
///
/// Takes PRINT_LOCK to prevent interleaving with other CPUs' prints;
/// IRQs are NOT disabled because callers are already in IRQ context.
pub fn handler_write_bytes(bytes: &[u8]) {
    init_uart_fifo_once();
    // Acquire PRINT_LOCK by busy-waiting (we may be in an IRQ handler,
    // so just spin until it's available).  Skip the lock-holder check
    // because we're not at risk of self-deadlock here.
    while PRINT_LOCK
        .compare_exchange(0, 1, AOrdering::Acquire, AOrdering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    Serial.push_bytes(bytes);
    PRINT_LOCK.store(0, AOrdering::Release);
}

/// Atomically format and emit `args` under the global PRINT_LOCK using
/// DirectUart's byte-by-byte writes (no per-CPU buffer, no internal
/// state).  Holds PRINT_LOCK with IRQs disabled across the whole emit
/// so other CPUs' regular prints CANNOT interleave with the output —
/// they spin until we release.  Intended for exception-handler dumps
/// where multi-line atomicity matters.
///
/// CAUTION: this writes byte-by-byte at the UART line rate (~115 kbps),
/// so a long dump takes ~10ms per ~150 chars.  Other CPUs spin during
/// this window.  Acceptable for fatal-path dumps (we're about to
/// `spin_loop()` anyway) but should NOT be used for routine logging.
pub fn dump_atomic(args: fmt::Arguments) {
    use fmt::Write;
    init_uart_fifo_once();
    let my_cpu = crate::sched::smp::cpu_id() as i32;
    // Re-entry bypass: if we're already the lock-holder on this CPU
    // (nested exception during a dump_atomic), write directly without
    // re-acquiring — the outer caller already holds the lock so peer
    // CPUs are still excluded; only the inner write may interleave
    // with the outer.  Avoids deadlock.
    if PRINT_HOLDER_CPU.load(AOrdering::Acquire) == my_cpu {
        let mut d = DirectUart;
        let _ = d.write_fmt(args);
        return;
    }
    let saved = crate::arch::irq::disable();
    loop {
        while PRINT_LOCK.load(AOrdering::Relaxed) != 0 {
            core::hint::spin_loop();
        }
        if PRINT_LOCK
            .compare_exchange(0, 1, AOrdering::Acquire, AOrdering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
    PRINT_HOLDER_CPU.store(my_cpu, AOrdering::Release);
    let mut d = DirectUart;
    let _ = d.write_fmt(args);
    PRINT_HOLDER_CPU.store(-1, AOrdering::Release);
    PRINT_LOCK.store(0, AOrdering::Release);
    crate::arch::irq::restore(saved);
}

/// Macro variant of `dump_atomic` mirroring `println!` ergonomics.
#[macro_export]
macro_rules! dump_atomic {
    ($($arg:tt)*) => ($crate::arch::x86_64::serial::dump_atomic(
        format_args!("{}\n", format_args!($($arg)*))
    ));
}

// #154 v2 polite-lock for print serialization.
//
// Replaces the previous interrupt-safe `SpinLock`, which disabled IRQs
// across the wait for the lock (so a contended print blocked IRQs on
// the waiting CPU for the full duration of the holder's critical
// section).  Polite-lock pattern:
//   - spin with IRQs ON until the lock looks free
//   - disable IRQs, try to claim; on failure restore IRQs and retry
//   - hold lock with IRQs OFF for the critical section
//
// Same-CPU re-entry (an IRQ handler firing while a thread on the same
// CPU is in _print) is handled via `PRINT_HOLDER_CPU`: if we see our
// own CPU as the holder, skip the lock and push bytes directly.  The
// inner call may interleave bytes with the outer call's output, but
// that's better than the deadlock the old regular spinlock would
// produce if it lacked IRQ-safety (and is preferable to blocking IRQs
// for tens of ms during cross-CPU contention, which is what we had).
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering as AOrdering};

static PRINT_LOCK: AtomicU32 = AtomicU32::new(0);
/// CPU id of the current PRINT_LOCK holder, or -1 if free.  Set under
/// the lock; checked before attempting to acquire (re-entry guard).
pub(crate) static PRINT_HOLDER_CPU: AtomicI32 = AtomicI32::new(-1);

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
        let n = self.len.min(N);
        &self.buf[..n]
    }
    fn as_str(&self) -> &str {
        // format_args produces UTF-8; our pushes preserve it.
        let n = self.len.min(N);
        unsafe { core::str::from_utf8_unchecked(&self.buf[..n]) }
    }
}

impl<const N: usize> fmt::Write for StackBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let cur = self.len.min(N);
        let space = N - cur;
        let n = bytes.len().min(space);
        self.buf[cur..cur + n].copy_from_slice(&bytes[..n]);
        self.len = cur + n;
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

/// Per-CPU print buffers.  #208 wild-RIP-in-kstack residual was
/// traced to __print's deep stack frame (~3.4 KiB) overlapping with
/// outer-caller local-variable slots — both PRINT-RET-SCRIBBLE and
/// the post-fix residuals (boots 1765/1766/1767/1772) showed the
/// same fixed-offset corruption pattern despite KSTACK_ORDER bumps.
/// Moving fmtbuf/wirebuf off the stack to per-CPU statics shrinks
/// the frame to ~200 B, drastically changing the absolute saved-RIP
/// slot offset and removing the depth-dependent overlap window.
const MAX_PRINT_CPUS: usize = 16;
struct CpuPrintBufs {
    fmt: UnsafeCell<[u8; PRINT_FMT_LIMIT]>,
    wire: UnsafeCell<[u8; PRINT_BUF_SIZE]>,
    busy: AtomicBool,
}
unsafe impl Sync for CpuPrintBufs {}
static PRINT_BUFS: [CpuPrintBufs; MAX_PRINT_CPUS] = [const {
    CpuPrintBufs {
        fmt: UnsafeCell::new([0u8; PRINT_FMT_LIMIT]),
        wire: UnsafeCell::new([0u8; PRINT_BUF_SIZE]),
        busy: AtomicBool::new(false),
    }
}; MAX_PRINT_CPUS];

/// Per-CPU fallback buffers used when the primary slot is busy
/// (e.g., IRQ re-entry during in-progress _print).  Promoted off the
/// stack to keep the kstack frame small even on the fall-through path
/// — was 768 B of locals (`[0u8;256] + [0u8;512]`).
struct CpuFallbackBufs {
    fmt: UnsafeCell<[u8; 256]>,
    wire: UnsafeCell<[u8; 512]>,
    busy: AtomicBool,
}
unsafe impl Sync for CpuFallbackBufs {}
static FALLBACK_BUFS: [CpuFallbackBufs; MAX_PRINT_CPUS] = [const {
    CpuFallbackBufs {
        fmt: UnsafeCell::new([0u8; 256]),
        wire: UnsafeCell::new([0u8; 512]),
        busy: AtomicBool::new(false),
    }
}; MAX_PRINT_CPUS];

/// Slice-based fmt::Write adapter — writes into a caller-provided
/// mutable slice + length counter.  Used to format into the per-CPU
/// static fmt buffer without allocating any stack frame.
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: &'a mut usize,
}
impl<'a> fmt::Write for SliceWriter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let cap = self.buf.len();
        let cur = (*self.len).min(cap);
        let space = cap - cur;
        let n = bytes.len().min(space);
        self.buf[cur..cur + n].copy_from_slice(&bytes[..n]);
        *self.len = cur + n;
        if bytes.len() > n { Err(fmt::Error) } else { Ok(()) }
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    init_uart_fifo_once();

    // Acquire this CPU's print buffer slot.  If busy (re-entry from
    // an IRQ that fired while we were already inside _print, or the
    // CPU index exceeds MAX_PRINT_CPUS), fall back to a small
    // stack-local buffer and degrade gracefully.
    let cpu = crate::sched::smp::cpu_id() as usize;
    let slot = if cpu < MAX_PRINT_CPUS {
        let s = &PRINT_BUFS[cpu];
        if s.busy.compare_exchange(
            false, true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        ).is_ok() {
            Some(s)
        } else {
            None
        }
    } else {
        None
    };

    let mut fmt_len: usize = 0;
    let mut wire_len: usize = 0;

    // Acquire fallback slot if primary wasn't available.  If even fallback
    // is busy (re-entry of re-entry), skip the print entirely — better
    // than scribbling on the kstack via stack-allocated locals.
    let fallback_slot = if slot.is_none() && cpu < MAX_PRINT_CPUS {
        let s = &FALLBACK_BUFS[cpu];
        if s.busy.compare_exchange(
            false, true,
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
        ).is_ok() {
            Some(s)
        } else {
            None
        }
    } else {
        None
    };

    // Split borrow: get raw pointers to the per-CPU buffers (or the static
    // fallback). If neither available, bail entirely.
    let (fmt_buf, wire_buf): (&mut [u8], &mut [u8]) = if let Some(s) = slot {
        unsafe { (&mut *s.fmt.get(), &mut *s.wire.get()) }
    } else if let Some(s) = fallback_slot {
        unsafe { (&mut *s.fmt.get(), &mut *s.wire.get()) }
    } else {
        // Both primary and fallback busy — drop the print.  Going to a
        // stack-local buffer here is what we're trying to avoid.
        return;
    };

    // Phase 1: format into fmt_buf with IRQs ON.
    {
        let mut w = SliceWriter { buf: fmt_buf, len: &mut fmt_len };
        let _ = w.write_fmt(args);
    }

    // CRLF-expand into wire_buf.
    for i in 0..fmt_len {
        let b = fmt_buf[i];
        if b == b'\n' {
            if wire_len + 2 <= wire_buf.len() {
                wire_buf[wire_len] = b'\r';
                wire_buf[wire_len + 1] = b'\n';
                wire_len += 2;
            }
        } else if wire_len < wire_buf.len() {
            wire_buf[wire_len] = b;
            wire_len += 1;
        }
    }

    // Phase 2: polite-lock acquire + push bytes.
    //
    // Re-entry check first: if we're already the holder on this CPU
    // (IRQ context interrupting a thread mid-_print), bypass the lock
    // and push directly.  The IRQ's bytes will interleave with the
    // outer call's output but no deadlock and no IRQ-blocking wait.
    let my_cpu = crate::sched::smp::cpu_id() as i32;
    let wire_slice = &wire_buf[..wire_len];
    if PRINT_HOLDER_CPU.load(AOrdering::Acquire) == my_cpu {
        Serial.push_bytes(wire_slice);
    } else {
        // Polite-lock acquire: spin IRQ-ON until the lock looks free,
        // then disable IRQs and CAS-try.  On lost race, restore IRQs
        // and re-spin.  Worst-case IRQ-off duration is one critical
        // section (byte-push) rather than full cross-CPU contention.
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
        Serial.push_bytes(wire_slice);
        PRINT_HOLDER_CPU.store(-1, AOrdering::Release);
        PRINT_LOCK.store(0, AOrdering::Release);
        crate::arch::irq::restore(saved);
    }

    // Mirror to the framebuffer console (no UART contention).
    if crate::drivers::fb_console::available() {
        let fmtstr = unsafe {
            core::str::from_utf8_unchecked(&fmt_buf[..fmt_len])
        };
        crate::drivers::fb_console::write_str(fmtstr);
    }

    // Release the per-CPU buffer slot (if we acquired it).  Doing this
    // last ensures no peer (IRQ-context reentry on this CPU) tries to
    // reuse it while we're still reading.
    if let Some(s) = slot {
        s.busy.store(false, core::sync::atomic::Ordering::Release);
    }
    if let Some(s) = fallback_slot {
        s.busy.store(false, core::sync::atomic::Ordering::Release);
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
