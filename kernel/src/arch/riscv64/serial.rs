//! 16550A UART driver for QEMU RISC-V virt machine.
//!
//! The 16550A UART is at MMIO address 0x1000_0000 on the QEMU riscv64 virt platform.
//! We only implement polled transmit — enough for early boot console output.

use core::fmt;

const UART_BASE: usize = 0x1000_0000;

// 16550 register offsets.
const THR: usize = 0x00; // Transmitter Holding Register (write)
const LSR: usize = 0x05; // Line Status Register (read)

// LSR bits.
const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty

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
