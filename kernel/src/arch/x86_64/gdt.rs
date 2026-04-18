//! Global Descriptor Table (GDT) for x86-64.
//!
//! Defines kernel and user code/data segments, plus a per-CPU TSS for
//! ring 3→0 transitions. Each CPU gets its own GDT and TSS so that
//! RSP0 can be updated independently on SMP systems.
//!
//! Storage layout (Tier-1 bootstrap + Tier-2 dynamic):
//! - BSP (cpu 0) uses `PER_CPU_GDT_BOOT` / `PER_CPU_TSS_BOOT` — single
//!   static slot. The BSP runs `init()` very early in boot, before
//!   `phys::init`, so dynamic allocation isn't available yet. Once the
//!   GDT is loaded into GDTR (a CPU register holding a pointer), the
//!   storage cannot move, so the BSP keeps using the bootstrap forever.
//! - APs use `PER_CPU_GDT_AP` / `PER_CPU_TSS_AP` — dynamic slices
//!   allocated by `init_dynamic_percpu()` after `phys::init`, sized
//!   `num_cpus() - 1` and indexed by `(cpu - 1)`.

use crate::sched::smp;
use core::mem::size_of;
use core::sync::atomic::{AtomicPtr, Ordering};

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

/// Initial GDT entries (filled in at runtime for the TSS slots).
const GDT_INIT: PerCpuGdt = PerCpuGdt {
    entries: [
        0x0000_0000_0000_0000, // 0x00: Null
        0x00AF_9A00_0000_FFFF, // 0x08: Kernel code (64-bit, DPL=0)
        0x00CF_9200_0000_FFFF, // 0x10: Kernel data (DPL=0)
        0x00CF_F200_0000_FFFF, // 0x18: User data (DPL=3)
        0x00AF_FA00_0000_FFFF, // 0x20: User code (64-bit, DPL=3)
        0,                     // 0x28: TSS low (filled at runtime)
        0,                     // 0x30: TSS high (filled at runtime)
    ],
};

const TSS_INIT: Tss = Tss {
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

/// Tier-1 bootstrap GDT/TSS for the BSP. Loaded into GDTR at very early
/// boot (before phys::init), so the storage must be statically known and
/// cannot move afterwards.
static mut PER_CPU_GDT_BOOT: PerCpuGdt = GDT_INIT;
static mut PER_CPU_TSS_BOOT: Tss = TSS_INIT;

/// Tier-2 dynamic per-CPU GDT/TSS for APs. Allocated by
/// `init_dynamic_percpu()` after `phys::init`. Sized `num_cpus() - 1` and
/// indexed by `(cpu - 1)` so slot 0 (BSP) is not wasted.
static PER_CPU_GDT_AP_PTR: AtomicPtr<PerCpuGdt> = AtomicPtr::new(core::ptr::null_mut());
static PER_CPU_TSS_AP_PTR: AtomicPtr<Tss> = AtomicPtr::new(core::ptr::null_mut());

/// Allocate the AP per-CPU GDT/TSS slices. Called from
/// `smp::init_dynamic_percpu` after `phys::init`. Initializes each AP
/// slot with the same GDT_INIT/TSS_INIT pattern as the bootstrap.
pub(crate) fn init_dynamic_percpu() {
    let n = smp::num_cpus();
    if n <= 1 {
        return; // Single-CPU mode: no APs.
    }
    let aps = n - 1;
    unsafe {
        let g = crate::mm::phys::alloc_static_slice::<PerCpuGdt>(aps);
        for slot in g.iter_mut() {
            *slot = GDT_INIT;
        }
        PER_CPU_GDT_AP_PTR.store(g.as_mut_ptr(), Ordering::Release);

        let t = crate::mm::phys::alloc_static_slice::<Tss>(aps);
        for slot in t.iter_mut() {
            *slot = TSS_INIT;
        }
        PER_CPU_TSS_AP_PTR.store(t.as_mut_ptr(), Ordering::Release);
    }
}

/// Pointer to this CPU's GDT storage. BSP uses bootstrap, APs use the
/// dynamic slice.
#[inline]
fn gdt_for(cpu: usize) -> *mut PerCpuGdt {
    if cpu == 0 {
        &raw mut PER_CPU_GDT_BOOT
    } else {
        let base = PER_CPU_GDT_AP_PTR.load(Ordering::Relaxed);
        debug_assert!(!base.is_null(), "PER_CPU_GDT_AP not init");
        debug_assert!(cpu < smp::num_cpus());
        unsafe { base.add(cpu - 1) }
    }
}

/// Per-CPU IST stack for the double-fault handler (4 KiB each, up to 16 CPUs).
/// A dedicated stack is critical: without IST, a #DF caused by stack overflow
/// or corruption tries to push onto the broken stack → triple fault → silent reboot.
const MAX_IST_CPUS: usize = 16;
const IST_STACK_SIZE: usize = 4096;

#[repr(C, align(4096))]
struct IstStack {
    data: [u8; IST_STACK_SIZE],
}

static mut IST_STACKS: [IstStack; MAX_IST_CPUS] = {
    const EMPTY: IstStack = IstStack { data: [0; IST_STACK_SIZE] };
    [EMPTY; MAX_IST_CPUS]
};

/// Pointer to this CPU's TSS storage. BSP uses bootstrap, APs use the
/// dynamic slice.
#[inline]
fn tss_for(cpu: usize) -> *mut Tss {
    if cpu == 0 {
        &raw mut PER_CPU_TSS_BOOT
    } else {
        let base = PER_CPU_TSS_AP_PTR.load(Ordering::Relaxed);
        debug_assert!(!base.is_null(), "PER_CPU_TSS_AP not init");
        debug_assert!(cpu < smp::num_cpus());
        unsafe { base.add(cpu - 1) }
    }
}

/// Set the kernel stack pointer used when entering ring 0 from ring 3.
/// Updates the current CPU's TSS.
pub fn set_rsp0(rsp0: u64) {
    let cpu = smp::cpu_id() as usize;
    unsafe {
        (*tss_for(cpu)).rsp0 = rsp0;
    }
}

/// Build and load a TSS descriptor into the given CPU's GDT, then lgdt + ltr.
fn load_gdt_for_cpu(cpu: usize) {
    let gdt = gdt_for(cpu);
    let tss = tss_for(cpu);
    let tss_addr = tss as u64;
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
        (*gdt).entries[5] = tss_low;
        (*gdt).entries[6] = tss_high;
    }

    let ptr = GdtPtr {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: unsafe { (*gdt).entries.as_ptr() as u64 },
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
        (*tss_for(0)).rsp0 = rsp;
        // IST[0] → dedicated double-fault stack (stack grows down, so point to top).
        (*tss_for(0)).ist[0] =
            IST_STACKS[0].data.as_ptr() as u64 + IST_STACK_SIZE as u64;
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
        (*tss_for(cpu)).rsp0 = rsp;
        // IST[0] → dedicated double-fault stack.
        if cpu < MAX_IST_CPUS {
            (*tss_for(cpu)).ist[0] =
                IST_STACKS[cpu].data.as_ptr() as u64 + IST_STACK_SIZE as u64;
        }
    }

    load_gdt_for_cpu(cpu);
}
