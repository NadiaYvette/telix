//! LoongArch64 PCI interrupt delivery: PCH-PIC + EXTIOI with HT-MSI forwarding.
//!
//! QEMU loongarch `virt` topology (verified against QEMU 10.1.4 source +
//! LoongArch3A5000 manual ch.11; see memory/project_loong_pci_irq_design.md):
//!
//!   PCI INTx -> PCH-PIC input i -> (HT-MSI: htmsi_vector[i]) -> EXTIOI irq
//!            -> (ipmap pin / coremap core) -> CPU HWI pin -> CSR.ESTAT.IS
//!
//! EXTIOI pin p connects to CPU gpio pin (p+2); CPU gpio pin N sets ESTAT.IS
//! bit N.  So EXTIOI pin 0 -> ESTAT.IS[2] = HWI0, which the kernel already
//! enables (trap.rs ECFG.LIE bit 2) and vectors through the HWI0 handler.
//!
//! Until a boot proves real IRQ delivery, drivers keep their poll fallback;
//! `valid_irq_range`/attach only widen once delivery is validated, so a wrong
//! routing cannot regress a server into hanging on IRQs that never arrive.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// EXTIOI — IOCSR registers (iocsrrd.d / iocsrwr.d / iocsrrd.w / iocsrwr.w).
// Absolute IOCSR offsets (APIC_BASE 0x1400 + reg; from loongarch_extioi_common.h).
// ---------------------------------------------------------------------------
const IOCSR_MISC_FUNC: u32 = 0x0420; // bit 48 = EXT_INT_en (IOCSRM_EXTIOI_EN)
const EXTIOI_EN_BIT: u64 = 1u64 << 48;
const EXTIOI_IPMAP: u32 = 0x14c0; // 8 bytes: byte g (group=irq/32) -> ctz32 = HWI pin
const EXTIOI_ENABLE: u32 = 0x1600; // 4x u64 (256 bits); set bit `irq`
const EXTIOI_COREISR: u32 = 0x1800; // current-core status (4x u64); read=pending, write=W1C
const EXTIOI_COREMAP: u32 = 0x1c00; // 256 bytes: byte irq -> ctz32 = target core

// ---------------------------------------------------------------------------
// PCH-PIC — MMIO at phys 0x10000000 (VIRT_PCH_REG_BASE), accessed uncached.
// Offsets from loongarch_pic_common.h.
// ---------------------------------------------------------------------------
const PCH_PIC_PHYS: usize = 0x1000_0000;
const PCH_PIC_INT_MASK: usize = 0x20; // u64, 1 = masked
const PCH_PIC_HTMSI_EN: usize = 0x40; // u64, 1 = forward as HT-MSI to extioi
const PCH_PIC_INT_EDGE: usize = 0x60; // u64, 1 = edge, 0 = level (PCI INTx is level)
const PCH_PIC_HTMSI_VEC: usize = 0x200; // 64 bytes: htmsi_vector[input] = extioi irq

/// LoongArch DMW uncached window for MMIO (mirrors pci.rs `uncached`).
#[inline]
fn pch_ptr(off: usize) -> *mut u64 {
    (0x8000_0000_0000_0000usize | (PCH_PIC_PHYS + off)) as *mut u64
}
#[inline]
fn pch_rd(off: usize) -> u64 {
    unsafe { core::ptr::read_volatile(pch_ptr(off)) }
}
#[inline]
fn pch_wr(off: usize, val: u64) {
    unsafe { core::ptr::write_volatile(pch_ptr(off), val) }
}
/// Byte write into the PCH-PIC htmsi_vector array.
#[inline]
fn pch_htmsi_vec_set(input: u32, vec: u8) {
    let p = (0x8000_0000_0000_0000usize | (PCH_PIC_PHYS + PCH_PIC_HTMSI_VEC + input as usize))
        as *mut u8;
    unsafe { core::ptr::write_volatile(p, vec) }
}

// --- IOCSR access (d = 64-bit, w = 32-bit) ---
#[inline]
fn iocsr_rd64(addr: u32) -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("iocsrrd.d {o}, {a}", o = out(reg) v, a = in(reg) addr) };
    v
}
#[inline]
fn iocsr_wr64(addr: u32, val: u64) {
    unsafe { core::arch::asm!("iocsrwr.d {v}, {a}", v = in(reg) val, a = in(reg) addr) };
}
#[inline]
fn iocsr_rd32(addr: u32) -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("iocsrrd.w {o}, {a}", o = out(reg) v, a = in(reg) addr) };
    v
}
#[inline]
fn iocsr_wr32(addr: u32, val: u32) {
    unsafe { core::arch::asm!("iocsrwr.w {v}, {a}", v = in(reg) val, a = in(reg) addr) };
}

static INITED: AtomicBool = AtomicBool::new(false);

/// Count of extioi IRQs actually delivered through HWI0 (proves real
/// hardware delivery vs. drivers completing via their used-ring poll).
static EXTIOI_DISPATCHES: AtomicU32 = AtomicU32::new(0);

/// One-time controller init: enable extended-I/O mode + route every group to
/// HWI pin 0 (HWI0).  Per-IRQ enable + core routing happen in `enable_irq`.
pub fn init() {
    if INITED.swap(true, Ordering::AcqRel) {
        return;
    }
    // Enable extended-I/O interrupt mode (HT interrupts go straight to extioi).
    let misc = iocsr_rd64(IOCSR_MISC_FUNC);
    iocsr_wr64(IOCSR_MISC_FUNC, misc | EXTIOI_EN_BIT);
    // ipmap: all 8 groups (256 irqs) -> pin 0 (HWI0).  Each byte = 0x01,
    // QEMU decodes ctz32(byte) = pin.  8 bytes = one u64 write at 0x14c0.
    iocsr_wr64(EXTIOI_IPMAP, 0x0101_0101_0101_0101);
    crate::println!("  [eiointc] extended-I/O IRQ mode enabled (PCI IRQs -> HWI0)");
}

/// Enable delivery of a single PCI/extioi `irq` to core 0 / HWI0.
/// Programs both EXTIOI (coremap + enable) and PCH-PIC (htmsi forward + unmask).
pub fn enable_irq(irq: u32) {
    if irq >= 256 {
        return;
    }
    // EXTIOI coremap[irq] = core 0 (byte 0x01).  Word-aligned RMW (QEMU indexes
    // the 256-byte coremap as u32 words).
    let cm_addr = EXTIOI_COREMAP + (irq & !3);
    let shift = (irq & 3) * 8;
    let mut w = iocsr_rd32(cm_addr);
    w &= !(0xffu32 << shift);
    w |= 0x01u32 << shift; // ctz32(0x01) = core 0
    iocsr_wr32(cm_addr, w);

    // EXTIOI enable bit `irq`.
    let en_addr = EXTIOI_ENABLE + (irq / 64) * 8;
    let d = iocsr_rd64(en_addr);
    iocsr_wr64(en_addr, d | (1u64 << (irq % 64)));

    // PCH-PIC: forward input `irq` to extioi irq `irq` (identity htmsi_vector),
    // enable HT-MSI for it, keep it level-triggered, then unmask.  Program the
    // forward path BEFORE unmasking so a pending line can't fire into an
    // unconfigured extioi entry.
    pch_htmsi_vec_set(irq, irq as u8);
    let bit = 1u64 << (irq % 64); // PCH-PIC has 32 inputs; all in the low u64
    pch_wr(PCH_PIC_HTMSI_EN, pch_rd(PCH_PIC_HTMSI_EN) | bit);
    pch_wr(PCH_PIC_INT_EDGE, pch_rd(PCH_PIC_INT_EDGE) & !bit); // level
    pch_wr(PCH_PIC_INT_MASK, pch_rd(PCH_PIC_INT_MASK) & !bit); // unmask
}

/// Read this core's pending extioi IRQs, invoke `dispatch` for each, and ACK
/// (W1C) the bits we serviced.  Called from the HWI0 trap handler.
pub fn claim_and_dispatch(mut dispatch: impl FnMut(u32)) {
    for grp in 0..4u32 {
        let addr = EXTIOI_COREISR + grp * 8;
        let pending = iocsr_rd64(addr);
        if pending == 0 {
            continue;
        }
        let mut bits = pending;
        while bits != 0 {
            let b = bits.trailing_zeros();
            let irq = grp * 64 + b;
            // One-shot delivery proof: print the first few real HWI0 IRQs so a
            // boot can confirm hardware delivery (drivers otherwise complete via
            // their used-ring poll fast-path, which would mask a dead IRQ path).
            let n = EXTIOI_DISPATCHES.fetch_add(1, Ordering::Relaxed);
            if n < 4 {
                crate::println!(
                    "  [eiointc] HWI0 IRQ DELIVERED: irq={} (#{}) — real interrupt delivery confirmed",
                    irq,
                    n + 1
                );
            }
            dispatch(irq);
            bits &= bits - 1;
        }
        // W1C: write the serviced bits back to clear the per-core latch.
        iocsr_wr64(addr, pending);
    }
}
