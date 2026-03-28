//! 8259 PIC (Programmable Interrupt Controller) driver.
//!
//! Remaps IRQ 0-7 to vectors 32-39, IRQ 8-15 to vectors 40-47.
//! Only unmasks IRQ 0 (PIT timer) initially.

// I/O ports for the two PICs.
const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW1 flags.
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;

// ICW4 flags.
const ICW4_8086: u8 = 0x01;

// Vector offsets after remapping.
pub const PIC1_OFFSET: u8 = 32;
pub const PIC2_OFFSET: u8 = 40;

// EOI command.
const EOI: u8 = 0x20;

#[inline]
unsafe fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack));
    }
    val
}

/// Small I/O delay (needed between PIC commands).
#[inline]
unsafe fn io_wait() {
    // Write to an unused port to create a short delay.
    unsafe {
        outb(0x80, 0);
    }
}

/// Initialize and remap both PICs.
pub fn init() {
    unsafe {
        // Save current masks.
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        // ICW1: Begin initialization sequence.
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: Set vector offsets.
        outb(PIC1_DATA, PIC1_OFFSET);
        io_wait();
        outb(PIC2_DATA, PIC2_OFFSET);
        io_wait();

        // ICW3: Tell PICs about each other.
        outb(PIC1_DATA, 4); // PIC1: slave on IRQ 2
        io_wait();
        outb(PIC2_DATA, 2); // PIC2: cascade identity
        io_wait();

        // ICW4: 8086 mode.
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Mask all IRQs initially.
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);

        let _ = (mask1, mask2); // Suppress unused warnings.
    }

    crate::println!("  PIC remapped (IRQ 0-7 -> vec 32-39, IRQ 8-15 -> vec 40-47)");
}

/// Unmask a specific IRQ line.
pub fn unmask(irq: u8) {
    unsafe {
        if irq < 8 {
            let mask = inb(PIC1_DATA) & !(1 << irq);
            outb(PIC1_DATA, mask);
        } else {
            let mask = inb(PIC2_DATA) & !(1 << (irq - 8));
            outb(PIC2_DATA, mask);
            // Also unmask IRQ 2 on PIC1 (cascade).
            let mask1 = inb(PIC1_DATA) & !(1 << 2);
            outb(PIC1_DATA, mask1);
        }
    }
}

/// Send End-of-Interrupt for the given IRQ.
pub fn send_eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, EOI);
        }
        outb(PIC1_CMD, EOI);
    }
}
