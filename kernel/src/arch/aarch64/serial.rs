//! PL011 UART driver for QEMU virt machine.
//!
//! The PL011 is at MMIO address 0x0900_0000 on the QEMU aarch64 virt platform.
//! We only implement polled transmit — enough for early boot console output.

use core::fmt;

const PL011_BASE: usize = 0x0900_0000;

// PL011 register offsets.
const UARTDR: usize = 0x000; // Data register
const UARTFR: usize = 0x018; // Flag register

// Flag register bits.
const UARTFR_TXFF: u32 = 1 << 5; // Transmit FIFO full

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
