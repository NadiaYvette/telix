//! Interrupt Descriptor Table (IDT) for x86-64.
//!
//! 256 entries, each pointing to an interrupt stub in the vectors assembly.

use super::gdt::KERNEL_CS;
use core::cell::UnsafeCell;

/// IDT entry (gate descriptor) for x86-64.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,        // bits 0-2: IST index, rest zero
    type_attr: u8,  // type and attributes
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        IdtEntry {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Configure as an interrupt gate.
    fn set(&mut self, handler: u64, dpl3: bool) {
        self.offset_low = handler as u16;
        self.selector = KERNEL_CS;
        self.ist = 0;
        self.type_attr = if dpl3 { 0xEE } else { 0x8E };
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.reserved = 0;
    }
}

/// IDTR pointer structure for lidt instruction.
#[repr(C, packed)]
struct IdtPtr {
    limit: u16,
    base: u64,
}

const IDT_ENTRIES: usize = 256;

/// Wrapper to allow mutable access to the IDT from a static.
/// Safety: IDT is only mutated during init() before interrupts are enabled.
struct IdtStorage(UnsafeCell<[IdtEntry; IDT_ENTRIES]>);
unsafe impl Sync for IdtStorage {}

static IDT: IdtStorage = IdtStorage(UnsafeCell::new([IdtEntry::missing(); IDT_ENTRIES]));

unsafe extern "C" {
    /// Vector stub table defined in vectors.S.
    /// Each entry is a function pointer to the stub for that vector.
    static __isr_stub_table: [u64; IDT_ENTRIES];
}

/// Load the IDT with all 256 vector stubs.
pub fn init() {
    unsafe {
        let idt = &mut *IDT.0.get();
        for i in 0..IDT_ENTRIES {
            let handler = __isr_stub_table[i];
            let dpl3 = i == 0x80;
            idt[i].set(handler, dpl3);
        }

        let ptr = IdtPtr {
            limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: idt.as_ptr() as u64,
        };

        core::arch::asm!("lidt [{}]", in(reg) &ptr, options(nostack));
    }

    crate::println!("  IDT loaded (256 vectors)");
}
