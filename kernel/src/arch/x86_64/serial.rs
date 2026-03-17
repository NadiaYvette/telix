//! 16550 UART driver for x86-64 (COM1 at I/O port 0x3F8).
//!
//! Uses x86 port I/O instructions (outb/inb) for polled transmit.

use core::fmt;

const COM1_PORT: u16 = 0x3F8;

// 16550 register offsets from base port.
const THR: u16 = 0; // Transmit Holding Register (write)
const LSR: u16 = 5; // Line Status Register (read)

// LSR bits.
const LSR_DR: u8 = 1 << 0;   // Data Ready
const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty

#[inline]
unsafe fn outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack)); }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack)); }
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
}

impl fmt::Write for Serial {
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

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write;
    Serial.write_fmt(args).unwrap();
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
