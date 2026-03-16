//! Global Descriptor Table (GDT) for x86-64.
//!
//! Defines kernel and user code/data segments, plus a TSS for ring 3→0
//! transitions. The boot GDT in boot.S gets us into long mode; this GDT
//! is the permanent one used once Rust is running.

use core::cell::UnsafeCell;
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
        GdtEntry(0x00AF_9A00_0000_FFFF)
    }

    /// Kernel data segment: present, DPL=0, writable.
    const fn kernel_data() -> Self {
        GdtEntry(0x00CF_9200_0000_FFFF)
    }

    /// User data segment: present, DPL=3, writable.
    const fn user_data() -> Self {
        GdtEntry(0x00CF_F200_0000_FFFF)
    }

    /// User code segment: 64-bit, present, DPL=3, executable, readable.
    const fn user_code() -> Self {
        GdtEntry(0x00AF_FA00_0000_FFFF)
    }
}

/// GDTR pointer structure for lgdt instruction.
#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

/// 64-bit TSS structure.
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iopb_offset: u16,
}

/// GDT: null + kcode + kdata + udata + ucode + TSS (2 entries) = 7 entries.
/// TSS descriptor is 16 bytes (2 GDT slots).
#[repr(C, align(16))]
struct GdtStorage {
    entries: UnsafeCell<[u64; 7]>,
}

unsafe impl Sync for GdtStorage {}

static GDT: GdtStorage = GdtStorage {
    entries: UnsafeCell::new([
        0x0000_0000_0000_0000,                    // 0x00: Null
        GdtEntry::kernel_code().0,                // 0x08: Kernel code
        GdtEntry::kernel_data().0,                // 0x10: Kernel data
        GdtEntry::user_data().0,                  // 0x18: User data (DPL=3)
        GdtEntry::user_code().0,                  // 0x20: User code (DPL=3)
        0, // 0x28: TSS low (filled at runtime)
        0, // 0x30: TSS high (filled at runtime)
    ]),
};

static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iopb_offset: size_of::<Tss>() as u16,
};

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x18;
pub const USER_CS: u16 = 0x20;
const TSS_SEL: u16 = 0x28;

/// Set the kernel stack pointer used when entering ring 0 from ring 3.
pub fn set_rsp0(rsp0: u64) {
    unsafe {
        TSS.rsp0 = rsp0;
    }
}

/// Load the kernel GDT with user segments and TSS, reload segment registers.
pub fn init() {
    // Fill in the TSS descriptor at runtime (needs the TSS address).
    let tss_addr = unsafe { core::ptr::addr_of!(TSS) as u64 };
    let tss_limit = (size_of::<Tss>() - 1) as u64;

    // TSS descriptor low: limit[15:0], base[23:0], type=0x9, P=1, base[31:24]
    let tss_low: u64 = (tss_limit & 0xFFFF)
        | ((tss_addr & 0xFFFF) << 16)
        | (((tss_addr >> 16) & 0xFF) << 32)
        | (0x89u64 << 40) // P=1, DPL=0, type=0x9 (available 64-bit TSS)
        | (((tss_limit >> 16) & 0xF) << 48)
        | (((tss_addr >> 24) & 0xFF) << 56);
    // TSS descriptor high: base[63:32]
    let tss_high: u64 = tss_addr >> 32;

    // Set RSP0 to the current kernel stack (boot stack).
    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp);
        TSS.rsp0 = rsp;
    }

    unsafe {
        let gdt = &mut *GDT.entries.get();
        gdt[5] = tss_low;
        gdt[6] = tss_high;
    }

    let ptr = GdtPtr {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: GDT.entries.get() as u64,
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
            // Load the TSS
            "ltr {tss:x}",
            ptr = in(reg) &ptr,
            cs = in(reg) KERNEL_CS as u64,
            ds = in(reg) KERNEL_DS as u64,
            tss = in(reg) TSS_SEL as u64,
            tmp = lateout(reg) _,
        );
    }

    crate::println!("  GDT loaded");
}
