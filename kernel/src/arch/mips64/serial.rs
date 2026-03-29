//! MIPS64 UART (16550) serial output.
//!
//! QEMU Malta: UART at physical 0x1F000900.
//! Accessed via KSEG1 unmapped uncached window at 0xFFFF_FFFF_BF00_0900.

use core::fmt;

const UART_BASE: usize = 0xFFFF_FFFF_BF00_0900;

struct Uart16550;

impl Uart16550 {
    fn putc(&self, c: u8) {
        unsafe {
            // Wait for THR empty (LSR bit 5).
            while core::ptr::read_volatile((UART_BASE + 5) as *const u8) & 0x20 == 0 {}
            core::ptr::write_volatile(UART_BASE as *mut u8, c);
        }
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
    Uart16550.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::arch::mips64::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
