//! Global Descriptor Table (GDT) for x86-64.
//!
//! Defines kernel and user code/data segments, plus a per-CPU TSS for
//! ring 3→0 transitions. Each CPU gets its own GDT and TSS so that
//! RSP0 can be updated independently on SMP systems.

use crate::sched::smp::MAX_CPUS;
use core::mem::size_of;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x18;
pub const USER_CS: u16 = 0x20;
const TSS_SEL: u16 = 0x28;

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

/// GDTR pointer structure for lgdt instruction.
#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

/// Per-CPU GDT: null + kcode + kdata + udata + ucode + TSS (2 entries) = 7 entries.
#[repr(C, align(16))]
struct PerCpuGdt {
    entries: [u64; 7],
}

/// Per-CPU GDT and TSS arrays.
static mut PER_CPU_GDT: [PerCpuGdt; MAX_CPUS] = {
    const INIT: PerCpuGdt = PerCpuGdt {
        entries: [
            0x0000_0000_0000_0000,  // 0x00: Null
            0x00AF_9A00_0000_FFFF,  // 0x08: Kernel code (64-bit, DPL=0)
            0x00CF_9200_0000_FFFF,  // 0x10: Kernel data (DPL=0)
            0x00CF_F200_0000_FFFF,  // 0x18: User data (DPL=3)
            0x00AF_FA00_0000_FFFF,  // 0x20: User code (64-bit, DPL=3)
            0,                       // 0x28: TSS low (filled at runtime)
            0,                       // 0x30: TSS high (filled at runtime)
        ],
    };
    [INIT; MAX_CPUS]
};

static mut PER_CPU_TSS: [Tss; MAX_CPUS] = {
    const INIT: Tss = Tss {
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
    [INIT; MAX_CPUS]
};

/// Set the kernel stack pointer used when entering ring 0 from ring 3.
/// Updates the current CPU's TSS.
pub fn set_rsp0(rsp0: u64) {
    let cpu = crate::sched::smp::cpu_id() as usize;
    unsafe {
        PER_CPU_TSS[cpu].rsp0 = rsp0;
    }
}

/// Build and load a TSS descriptor into the given CPU's GDT, then lgdt + ltr.
fn load_gdt_for_cpu(cpu: usize) {
    let tss_addr = unsafe { core::ptr::addr_of!(PER_CPU_TSS[cpu]) as u64 };
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

    unsafe {
        PER_CPU_GDT[cpu].entries[5] = tss_low;
        PER_CPU_GDT[cpu].entries[6] = tss_high;
    }

    let ptr = GdtPtr {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: unsafe { PER_CPU_GDT[cpu].entries.as_ptr() as u64 },
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
}

/// Load the BSP's GDT with user segments and TSS.
pub fn init() {
    // Set RSP0 to the current kernel stack (boot stack).
    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp);
        PER_CPU_TSS[0].rsp0 = rsp;
    }

    load_gdt_for_cpu(0);
    crate::println!("  GDT loaded");
}

/// Load a per-CPU GDT with TSS for a secondary CPU.
pub fn init_ap(cpu: u32) {
    let cpu = cpu as usize;
    // Set RSP0 to the current AP stack.
    unsafe {
        let rsp: u64;
        core::arch::asm!("mov {}, rsp", out(reg) rsp);
        PER_CPU_TSS[cpu].rsp0 = rsp;
    }

    load_gdt_for_cpu(cpu);
}
