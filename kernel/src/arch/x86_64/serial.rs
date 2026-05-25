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
static PRINT_HOLDER_CPU: AtomicI32 = AtomicI32::new(-1);

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

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    // First-call FIFO init.  Cheap atomic check on subsequent calls.
    init_uart_fifo_once();

    // #208 PRINT-RET entry probe: capture the saved return address NOW,
    // before any of __print's body runs.  Compared against an end-of-body
    // probe to see whether the corruption happens DURING __print (and not
    // before we entered).  Offset 0xd38 is the post-prologue position of
    // the saved ret addr (frame 0xd08 + 6×8 saved regs) — re-verify if
    // frame size changes.
    #[cfg(target_arch = "x86_64")]
    let entry_ret: u64 = {
        let v: u64;
        unsafe {
            core::arch::asm!(
                "mov {0}, [rsp + 0xd38]",
                out(reg) v,
                options(readonly, nostack, preserves_flags),
            );
        }
        v
    };

    // #208 DR0 watch arm: install hardware watchpoint on our saved
    // return address slot via the GLOBAL_SAVED_SP_WATCH_ADDR mechanism
    // (all CPUs lazily arm DR0 at exception entry).  Override any
    // pre-existing watch for the duration of __print and restore on
    // exit — the pre-existing proactive arm on tid=4.saved_sp catches
    // legitimate try_switch writes, which crowd out the __print bug
    // captures we want.  When the writer hits __print's slot, the #DB
    // handler logs DR0-HIT-OFF-PATH with the writer's RIP, CPU, tid.
    #[cfg(target_arch = "x86_64")]
    let dr0_saved_prev: u64 = {
        let slot_addr: u64;
        unsafe {
            core::arch::asm!(
                "lea {0}, [rsp + 0xd38]",
                out(reg) slot_addr,
                options(nomem, nostack, preserves_flags),
            );
        }
        use core::sync::atomic::Ordering as O;
        // Atomic swap: save prior watch, install ours.
        let prev = crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
            .swap(slot_addr, O::AcqRel);
        // Arm local DR0 immediately so this CPU catches writes during
        // this __print (other CPUs lazily arm at next exception entry).
        crate::arch::x86_64::gdt::dr0_set_watch_write_qword(slot_addr);
        prev
    };

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

    // Phase 2: polite-lock acquire + push bytes.
    //
    // Re-entry check first: if we're already the holder on this CPU
    // (IRQ context interrupting a thread mid-_print), bypass the lock
    // and push directly.  The IRQ's bytes will interleave with the
    // outer call's output but no deadlock and no IRQ-blocking wait.
    let my_cpu = crate::sched::smp::cpu_id() as i32;
    if PRINT_HOLDER_CPU.load(AOrdering::Acquire) == my_cpu {
        Serial.push_bytes(wirebuf.as_bytes());
    } else {
        // Polite-lock acquire: spin IRQ-ON until the lock looks free,
        // then disable IRQs and CAS-try.  On lost race, restore IRQs
        // and re-spin.  Worst-case IRQ-off duration is one critical
        // section (byte-push) rather than full cross-CPU contention.
        let saved;
        loop {
            // Wait phase: IRQs ON (or already-off in IRQ context).
            while PRINT_LOCK.load(AOrdering::Relaxed) != 0 {
                core::hint::spin_loop();
            }
            // Acquire attempt: IRQs OFF.
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
        // Critical section.
        PRINT_HOLDER_CPU.store(my_cpu, AOrdering::Release);
        Serial.push_bytes(wirebuf.as_bytes());
        PRINT_HOLDER_CPU.store(-1, AOrdering::Release);
        PRINT_LOCK.store(0, AOrdering::Release);
        crate::arch::irq::restore(saved);
    }

    // Mirror to the framebuffer console (no UART contention).
    if crate::drivers::fb_console::available() {
        crate::drivers::fb_console::write_str(fmtbuf.as_str());
    }

    // #208 PRINT-RET probe: read the saved return address from this
    // function's frame just before the compiler's epilogue runs.  If
    // it's been overwritten with a non-canonical value (the recurring
    // #GP at the `ret` instruction = error_code=0, signature of a ret
    // to non-canonical RIP), log via DirectUart bypass — the regular
    // print path is what we're about to fault out of.
    //
    // Frame layout per `objdump -d` (x86_64-unknown-none release):
    //   push %rbp / push %r15..%rbx (6 × 8 = 48 bytes) + sub $0xcd8, %rsp
    //   (frame size includes this probe's locals; was 0xc18 before, 0xcd8
    //   after — re-verify via `objdump -d` if you change anything in
    //   this function).  Saved ret addr is at [rsp + 0xd38]
    //   (frame 0xd08 + 6 × 8 saved regs = 0xd38).
    // This offset is fragile — bumps if the local-frame size changes.
    // If the layout shifts, the probe just reads garbage at that offset,
    // which will likely look non-canonical and surface itself.
    #[cfg(target_arch = "x86_64")]
    {
        let saved_ret: u64;
        unsafe {
            core::arch::asm!(
                "mov {0}, [rsp + 0xd38]",
                out(reg) saved_ret,
                options(readonly, nostack, preserves_flags),
            );
        }
        // Restore the pre-__print global watch (so the proactive arm
        // on tid=4.saved_sp resumes) and disarm/re-arm local DR0
        // accordingly.
        {
            use core::sync::atomic::Ordering as O;
            crate::arch::x86_64::gdt::GLOBAL_SAVED_SP_WATCH_ADDR
                .store(dr0_saved_prev, O::Release);
            if dr0_saved_prev != 0 {
                crate::arch::x86_64::gdt::dr0_set_watch_write_qword(dr0_saved_prev);
            } else {
                crate::arch::x86_64::gdt::dr0_clear();
            }
        }
        // Canonical = upper 17 bits all match bit 47.
        let bit47 = (saved_ret >> 47) & 1;
        let upper = saved_ret >> 48;
        let canonical = if bit47 == 1 { upper == 0xFFFF } else { upper == 0 };
        let mutated = saved_ret != entry_ret;
        if !canonical || mutated {
            use core::sync::atomic::{AtomicU32, Ordering as O};
            static LOG_COUNT: AtomicU32 = AtomicU32::new(0);
            let n = LOG_COUNT.fetch_add(1, O::Relaxed);
            if n < 16 {
                let mut rsp_now: u64;
                unsafe {
                    core::arch::asm!(
                        "mov {0}, rsp",
                        out(reg) rsp_now,
                        options(nomem, nostack, preserves_flags),
                    );
                }
                // Sample the 4 quadwords below the ret-addr slot too,
                // so we can see what scribble pattern is present.
                let below: [u64; 4] = unsafe {
                    [
                        core::ptr::read_volatile((rsp_now + 0xd30) as *const u64),
                        core::ptr::read_volatile((rsp_now + 0xd28) as *const u64),
                        core::ptr::read_volatile((rsp_now + 0xd20) as *const u64),
                        core::ptr::read_volatile((rsp_now + 0xd18) as *const u64),
                    ]
                };
                let mut bypass = DirectUart;
                let _ = core::fmt::Write::write_fmt(
                    &mut bypass,
                    format_args!(
                        "PRINT-RET-SCRIBBLE: cpu={} entry_ret={:#x} exit_ret={:#x} mutated={} canonical={} rsp={:#x} below=[{:#x} {:#x} {:#x} {:#x}] n={}\n",
                        my_cpu, entry_ret, saved_ret, mutated, canonical,
                        rsp_now,
                        below[0], below[1], below[2], below[3], n + 1,
                    ),
                );
            }
        }
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
