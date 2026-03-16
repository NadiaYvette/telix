//! Global Descriptor Table (GDT) for x86-64.
//!
//! Defines kernel code and data segments needed for 64-bit long mode.
//! The boot GDT in boot.S gets us into long mode; this GDT is the
//! permanent one used once Rust is running.

use core::mem::size_of;

/// GDT entry (segment descriptor).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GdtEntry(u64);

impl GdtEntry {
    const fn null() -> Self {
        GdtEntry(0)
    }

    /// Kernel code segment: 64-bit, present, DPL=0, executable, readable.
    const fn kernel_code() -> Self {
        // Base=0, Limit=0xFFFFF, G=1, L=1 (64-bit), P=1, DPL=0, S=1, Type=0xA (exec/read)
        GdtEntry(0x00AF_9A00_0000_FFFF)
    }

    /// Kernel data segment: present, DPL=0, writable.
    const fn kernel_data() -> Self {
        // Base=0, Limit=0xFFFFF, G=1, D/B=1, P=1, DPL=0, S=1, Type=0x2 (read/write)
        GdtEntry(0x00CF_9200_0000_FFFF)
    }
}

/// GDTR pointer structure for lgdt instruction.
#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

/// Our kernel GDT: null + code + data = 3 entries.
#[repr(C, align(16))]
struct Gdt {
    entries: [GdtEntry; 3],
}

static GDT: Gdt = Gdt {
    entries: [
        GdtEntry::null(),        // 0x00: Null
        GdtEntry::kernel_code(), // 0x08: Kernel code (CS)
        GdtEntry::kernel_data(), // 0x10: Kernel data (DS/SS/ES/FS/GS)
    ],
};

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;

/// Load the kernel GDT and reload segment registers.
pub fn init() {
    let ptr = GdtPtr {
        limit: (size_of::<Gdt>() - 1) as u16,
        base: &GDT as *const Gdt as u64,
    };

    unsafe {
        core::arch::asm!(
            "lgdt [{ptr}]",
            // Reload CS via a far return
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            // Reload data segments
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov fs, {ds:x}",
            "mov gs, {ds:x}",
            "mov ss, {ds:x}",
            ptr = in(reg) &ptr,
            cs = in(reg) KERNEL_CS as u64,
            ds = in(reg) KERNEL_DS as u64,
            tmp = lateout(reg) _,
        );
    }

    crate::println!("  GDT loaded");
}
