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

/// #208 STATIC-LAYOUT probe: print absolute addresses of the per-CPU
/// statics so we can attribute FRAME-BYTE-DELTA `live=` values to a
/// specific structure.  Called once from `smp::init_dynamic_percpu`
/// after the AP slices are allocated.
pub fn debug_print_static_layout() {
    let ist = (&raw const IST_STACKS) as u64;
    let gdt_boot = (&raw const PER_CPU_GDT_BOOT) as u64;
    let tss_boot = (&raw const PER_CPU_TSS_BOOT) as u64;
    let gdt_ap = PER_CPU_GDT_AP_PTR.load(Ordering::Relaxed) as u64;
    let tss_ap = PER_CPU_TSS_AP_PTR.load(Ordering::Relaxed) as u64;
    crate::println!(
        "STATIC-LAYOUT: IST_STACKS={:#x}..{:#x} GDT_BOOT={:#x} TSS_BOOT={:#x} GDT_AP={:#x} TSS_AP={:#x} IstStack={} Tss={} PerCpuGdt={}",
        ist,
        ist + (core::mem::size_of::<[IstStack; MAX_IST_CPUS]>() as u64),
        gdt_boot,
        tss_boot,
        gdt_ap,
        tss_ap,
        core::mem::size_of::<IstStack>(),
        core::mem::size_of::<Tss>(),
        core::mem::size_of::<PerCpuGdt>(),
    );
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

/// IST slot 2 — used for #SS (Stack Segment Fault, vector 12).  Phase 1 of
/// #216 per-CPU IRQ stacks per the slot-allocation policy in task #239.
/// #SS is a fatal class (calls exit_current_thread → context switch on
/// the next thread's kstack), so even without #237 asm-stub awareness
/// the existing `mov rsp, rax` at __isr_common's tail correctly switches
/// off the IST stack onto the next thread's kstack.  Same shape as #DF
/// on IST 1.
static mut IST_STACKS_SS: [IstStack; MAX_IST_CPUS] = {
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
/// Updates the current CPU's TSS.  `target_tid` is the thread that
/// will use this RSP0 — recorded in the #208 RSP0 update ring for
/// diagnostic attribution.
pub fn set_rsp0(target_tid: u32, rsp0: u64) {
    let cpu = smp::cpu_id() as usize;
    unsafe {
        (*tss_for(cpu)).rsp0 = rsp0;
    }
    crate::sched::scheduler::record_rsp0_update(cpu as u32, target_tid, rsp0);
}

/// Read the current CPU's TSS RSP0.  Used by the #208 RSP0-MISMATCH
/// probe to distinguish "update_kernel_stack never ran" from "ran but
/// the CPU's exception-entry didn't observe it".
pub fn get_rsp0() -> u64 {
    let cpu = smp::cpu_id() as usize;
    unsafe { (*tss_for(cpu)).rsp0 }
}

/// #230: read a specific CPU's TSS RSP0 (sweep-time cross-CPU audit).
pub fn tss_rsp0_for(cpu: usize) -> u64 {
    unsafe { (*tss_for(cpu)).rsp0 }
}

/// #208 DR0 watchpoint helpers.  Used to catch the writer that
/// corrupts iretq frame slots.  Single-CPU watch: arms DR0 on the
/// calling CPU only; if the writer is on another CPU, this won't
/// catch it.
///
/// `DR0_WATCH_ADDR` lets the #DB handler re-arm with the same
/// address after stub-region hits.
static DR0_WATCH_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn dr0_set_watch_write_qword(addr: u64) {
    DR0_WATCH_ADDR.store(addr, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        core::arch::asm!("mov dr0, {0}", in(reg) addr, options(nostack));
        // DR7: L0=1, RW0=01 (write), LEN0=10 (8 bytes).
        let dr7: u64 = (1u64 << 0) | (0b01u64 << 16) | (0b10u64 << 18);
        core::arch::asm!("mov dr7, {0}", in(reg) dr7, options(nostack));
    }
}

pub fn dr0_get_watched() -> u64 {
    DR0_WATCH_ADDR.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn dr0_clear() {
    DR0_WATCH_ADDR.store(0, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        let zero: u64 = 0;
        core::arch::asm!("mov dr7, {0}", in(reg) zero, options(nostack));
        core::arch::asm!("mov dr0, {0}", in(reg) zero, options(nostack));
    }
}

/// #208 saved_sp watchpoint — global target address that EVERY CPU
/// arms DR0 to watch.  When set non-zero, each CPU lazily arms its
/// own DR0 (via dr0_ensure_watching) at top of x86_exception_handler.
/// Any write triggers DR0-HIT; the handler filters CPU stub pushes,
/// so legitimate try_switch writes log as DR0-HIT-OFF-PATH with the
/// writer's RIP.
pub static GLOBAL_SAVED_SP_WATCH_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

#[inline]
pub fn dr0_ensure_watching(addr: u64) {
    if addr == 0 {
        return;
    }
    // Always re-arm: DR0_WATCH_ADDR is a global, but HW DR0 is per-CPU,
    // so the global-equal check fails to detect that a peer CPU's DR0
    // register is stale (set by an older arm) while DR0_WATCH_ADDR was
    // updated by a different CPU since.  Boot 1872 caught DR0 firing
    // on a stale saved_sp address despite `watched` being L1-slot.
    // Cost is one outb + 2 GPR-to-DR moves per exception — cheap.
    let cur_reg: u64;
    unsafe {
        core::arch::asm!("mov {0}, dr0", out(reg) cur_reg, options(nomem, nostack));
    }
    if cur_reg == addr {
        return;
    }
    dr0_set_watch_write_qword(addr);
}

/// #233 user-RIP-scribble investigation: arm DR1 on the recurring
/// scribbled slot (0xfffffe00049ff608) so any write on this CPU
/// triggers #DB with the writer's RIP.  Static target chosen because
/// boots 2600/2623/2627/2640 all hit THIS exact VA — strongly
/// deterministic via the kstack VA bump allocator.
pub const SLOT_WATCH_VA: u64 = 0xfffffe00049ff608;
static DR1_WATCH_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn dr1_set_watch_write_qword(addr: u64) {
    DR1_WATCH_ADDR.store(addr, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        // Read current DR7 so we don't clobber other DR bits.
        let mut cur_dr7: u64;
        core::arch::asm!("mov {0}, dr7", out(reg) cur_dr7, options(nomem, nostack));
        // L1 = bit 2; RW1 = bits 20-21 = 0b01 (write); LEN1 = bits 22-23 = 0b10 (8 B).
        let dr1_bits: u64 = (1u64 << 2) | (0b01u64 << 20) | (0b10u64 << 22);
        // Clear any prior DR1 config in DR7 then OR new bits.
        let mask: u64 = (1u64 << 2) | (0b11u64 << 20) | (0b11u64 << 22);
        cur_dr7 = (cur_dr7 & !mask) | dr1_bits;
        core::arch::asm!("mov dr1, {0}", in(reg) addr, options(nostack));
        core::arch::asm!("mov dr7, {0}", in(reg) cur_dr7, options(nostack));
    }
}

#[inline]
pub fn dr1_ensure_watching() {
    let addr = SLOT_WATCH_VA;
    let cur_reg: u64;
    unsafe {
        core::arch::asm!("mov {0}, dr1", out(reg) cur_reg, options(nomem, nostack));
    }
    if cur_reg == addr {
        return;
    }
    dr1_set_watch_write_qword(addr);
}

/// DR2 watchpoint on the second recurring slot 0xfffffe0000bffd68
/// (hit by boots 2594/2599/2692/2695 with the second-call ret-target
/// scribble pattern, multiple tids/cpus).
pub const SLOT_WATCH_VA_2: u64 = 0xfffffe0000bffd68;
static DR2_WATCH_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn dr2_set_watch_write_qword(addr: u64) {
    DR2_WATCH_ADDR.store(addr, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        let mut cur_dr7: u64;
        core::arch::asm!("mov {0}, dr7", out(reg) cur_dr7, options(nomem, nostack));
        // L2 = bit 4; RW2 = bits 24-25 = 0b01 (write); LEN2 = bits 26-27 = 0b10 (8 B).
        let dr2_bits: u64 = (1u64 << 4) | (0b01u64 << 24) | (0b10u64 << 26);
        let mask: u64 = (1u64 << 4) | (0b11u64 << 24) | (0b11u64 << 26);
        cur_dr7 = (cur_dr7 & !mask) | dr2_bits;
        core::arch::asm!("mov dr2, {0}", in(reg) addr, options(nostack));
        core::arch::asm!("mov dr7, {0}", in(reg) cur_dr7, options(nostack));
    }
}

#[inline]
pub fn dr2_ensure_watching() {
    let addr = SLOT_WATCH_VA_2;
    let cur_reg: u64;
    unsafe {
        core::arch::asm!("mov {0}, dr2", out(reg) cur_reg, options(nomem, nostack));
    }
    if cur_reg == addr {
        return;
    }
    dr2_set_watch_write_qword(addr);
}

/// DR3 watchpoint on tid=8's deterministic NULL-write slot
/// 0xfffffe00013ff628 (boots 2522/2528).
pub const SLOT_WATCH_VA_3: u64 = 0xfffffe00013ff628;
static DR3_WATCH_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub fn dr3_set_watch_write_qword(addr: u64) {
    DR3_WATCH_ADDR.store(addr, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        let mut cur_dr7: u64;
        core::arch::asm!("mov {0}, dr7", out(reg) cur_dr7, options(nomem, nostack));
        // L3 = bit 6; RW3 = bits 28-29 = 0b01 (write); LEN3 = bits 30-31 = 0b10 (8 B).
        let dr3_bits: u64 = (1u64 << 6) | (0b01u64 << 28) | (0b10u64 << 30);
        let mask: u64 = (1u64 << 6) | (0b11u64 << 28) | (0b11u64 << 30);
        cur_dr7 = (cur_dr7 & !mask) | dr3_bits;
        core::arch::asm!("mov dr3, {0}", in(reg) addr, options(nostack));
        core::arch::asm!("mov dr7, {0}", in(reg) cur_dr7, options(nostack));
    }
}

#[inline]
pub fn dr3_ensure_watching() {
    let addr = SLOT_WATCH_VA_3;
    let cur_reg: u64;
    unsafe {
        core::arch::asm!("mov {0}, dr3", out(reg) cur_reg, options(nomem, nostack));
    }
    if cur_reg == addr {
        return;
    }
    dr3_set_watch_write_qword(addr);
}

/// Read DR6, clear the B0..B3 status bits, return the original value.
pub fn dr6_read_clear() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mov {0}, dr6", out(reg) val, options(nostack));
        let cleared = val & !0xFu64;
        core::arch::asm!("mov dr6, {0}", in(reg) cleared, options(nostack));
    }
    val
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
        // IST[1] → dedicated #SS stack (#216 Phase 1).
        (*tss_for(0)).ist[1] =
            IST_STACKS_SS[0].data.as_ptr() as u64 + IST_STACK_SIZE as u64;
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
            // IST[1] → dedicated #SS stack (#216 Phase 1).
            (*tss_for(cpu)).ist[1] =
                IST_STACKS_SS[cpu].data.as_ptr() as u64 + IST_STACK_SIZE as u64;
        }
    }

    load_gdt_for_cpu(cpu);
}
