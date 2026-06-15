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
    ist: u8,       // bits 0-2: IST index, rest zero
    type_attr: u8, // type and attributes
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

    /// Set IST index (1-7) for this gate. 0 means no IST.
    fn set_ist(&mut self, ist_index: u8) {
        self.ist = ist_index & 0x7;
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

/// Read the loaded IDTR via `sidt`.  Returns (limit, base).
#[cfg(feature = "vm_debug_probes")]
#[inline]
fn read_idtr() -> (u16, u64) {
    let mut buf = [0u8; 10];
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) buf.as_mut_ptr(), options(nostack));
    }
    let limit = u16::from_le_bytes([buf[0], buf[1]]);
    let base = u64::from_le_bytes([
        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
    ]);
    (limit, base)
}

/// #208 5f hunt: validate the LOADED IDT (via sidt).  Reads the raw 16-byte
/// hardware gate format (layout-independent) for the key vectors — #DF(8),
/// #GP(13), #PF(14), syscall(0x80) — and checks each is Present, selector
/// == KERNEL_CS, canonical handler offset.  A corrupted IDT entry means the
/// CPU can't dispatch that exception → escalates to #DF → (if #DF's gate is
/// also bad) → silent triple, exactly the no-output Phase-5f signature.
/// Returns (code, vector, handler) of the first anomaly: 1=IDTR base
/// non-canonical (vector=base), 2=limit wrong (vector=limit), 3=entry bad.
#[cfg(feature = "vm_debug_probes")]
pub fn idt_anomaly() -> Option<(u32, u64, u64)> {
    let (limit, base) = read_idtr();
    if base < 0xFFFF_8000_0000_0000 {
        return Some((1, 0, base));
    }
    if limit as usize != IDT_ENTRIES * 16 - 1 {
        return Some((2, (IDT_ENTRIES * 16 - 1) as u64, limit as u64));
    }
    for &v in &[8u64, 13, 14, 0x80] {
        let p = (base + v * 16) as *const u8;
        unsafe {
            let ol = core::ptr::read_unaligned(p as *const u16) as u64;
            let sel = core::ptr::read_unaligned(p.add(2) as *const u16);
            let type_attr = core::ptr::read_unaligned(p.add(5));
            let om = core::ptr::read_unaligned(p.add(6) as *const u16) as u64;
            let oh = core::ptr::read_unaligned(p.add(8) as *const u32) as u64;
            let handler = ol | (om << 16) | (oh << 32);
            let present = type_attr & 0x80 != 0;
            if !present || sel != KERNEL_CS || handler < 0xFFFF_8000_0000_0000 {
                return Some((3, v, handler));
            }
        }
    }
    None
}

/// Load the IDT with all 256 vector stubs.
pub fn init() {
    unsafe {
        let idt = &mut *IDT.0.get();
        for i in 0..IDT_ENTRIES {
            let handler = __isr_stub_table[i];
            // DPL=3 (user-callable):
            //   - 0x80: legacy int 0x80 syscall ABI
            //   - 3 (#BP): user-mode INT 3 (0xCC) is the Linux SIGTRAP path.
            //     glibc's abort/assertion sequences emit INT 3 after printing
            //     the error message — without DPL=3 the CPU raises #GP(IDT3)
            //     instead of delivering #BP to the kernel handler.
            //     Pattern C (boots 547/550/556) was this exact symptom.
            let dpl3 = i == 0x80 || i == 3;
            idt[i].set(handler, dpl3);
        }
        // Vector 8 (#DF) uses IST 1 → TSS.ist[0] so it gets a clean stack
        // even when the current kernel stack is corrupted/overflowed.
        idt[8].set_ist(1);
        // Vector 12 (#SS Stack Segment) uses IST 2 → TSS.ist[1].  #216
        // Phase 1 per the slot-allocation policy in task #239.  #SS is a
        // fatal class (exit_current_thread, no resume on this thread), so
        // the __isr_common `mov rsp, rax` switch onto the next thread's
        // kstack correctly drops the IST stack contents — same shape as
        // #DF on IST 1.
        idt[12].set_ist(2);
        // Vector 2 (NMI) uses IST 3 → TSS.ist[2].  #216 Phase 2 per the
        // slot-allocation policy in task #239.  See gdt.rs IST_STACKS_NMI
        // for why no asm trampoline is required at this stage: Telix's
        // current NMI handler reaches `exception_fault` which panics +
        // halts, so the outer NMI never executes the iretq that would
        // consume the saved iretq frame — meaning the classic nested-
        // NMI corruption pattern (single-shot rsp store at IST3_TOP)
        // can't affect us today.  #241's NMI_NEST_DEPTH short-circuits
        // the nested case before it recurses into exception_fault.
        idt[2].set_ist(3);
        // Vector 14 (#PF) uses IST 4 → TSS.ist[3].  #216 Phase 3 per
        // the slot-allocation policy in task #239.  See gdt.rs
        // IST_STACKS_PF for the rationale: the corruption window from
        // a peer #PF during an async-PF park doesn't manifest today
        // (async_pf=0 in observed boots) and `park_faulting_from_ist`
        // (#240) is queued for when it does start firing.  The win is
        // that a #PF on a stack-overflow guard page — the exact
        // cascade pattern we saw in boot 3243 before today's IST
        // sequence — now lands cleanly on a fresh 1 MiB stack instead
        // of recursing into the corrupted kstack and triple-faulting.
        idt[14].set_ist(4);

        let ptr = IdtPtr {
            limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: idt.as_ptr() as u64,
        };

        core::arch::asm!("lidt [{}]", in(reg) &ptr, options(nostack));
    }

    crate::println!("  IDT loaded (256 vectors)");
}

/// Load the IDT on the current CPU (for APs — IDT is already initialized).
pub fn load() {
    unsafe {
        let idt = &*IDT.0.get();
        let ptr = IdtPtr {
            limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: idt.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{}]", in(reg) &ptr, options(nostack));
    }
}
