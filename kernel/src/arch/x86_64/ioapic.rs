//! I/O APIC driver for external interrupt routing on x86-64.
//!
//! The I/O APIC replaces the legacy 8259 PIC on modern hardware.
//! Its base address is discovered from the ACPI MADT (stored in
//! `firmware::IrqControllerInfo::base1`).
//!
//! Each I/O APIC pin has a 64-bit Redirection Table Entry (RTE)
//! that maps the pin to a CPU LAPIC vector.  This module routes
//! legacy ISA IRQs through the I/O APIC, honoring MADT Interrupt
//! Source Override entries that remap IRQ→GSI mappings.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

// ── Register access ────────────────────────────────────────────────
//
// I/O APIC registers are accessed indirectly via two MMIO registers:
//   IOREGSEL (offset 0x00): write the register index
//   IOWIN    (offset 0x10): read/write the selected register

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;

// I/O APIC register indices (written to IOREGSEL).
const IOAPIC_ID: u32 = 0x00;
const IOAPIC_VER: u32 = 0x01;
const IOAPIC_REDTBL_BASE: u32 = 0x10;

// Redirection Table Entry (RTE) bit fields (low 32 bits).
const RTE_MASK: u32 = 1 << 16;       // Interrupt masked
const RTE_LEVEL: u32 = 1 << 15;      // Level-triggered (vs edge)
const RTE_ACTIVELOW: u32 = 1 << 13;  // Active-low polarity (vs active-high)

// ── State ──────────────────────────────────────────────────────────

static IOAPIC_BASE: AtomicUsize = AtomicUsize::new(0);
static IOAPIC_AVAILABLE: AtomicBool = AtomicBool::new(false);
static IOAPIC_MAX_ENTRY: AtomicU8 = AtomicU8::new(0);

/// Interrupt Source Override: ISA IRQ → Global System Interrupt remap.
/// Index = ISA IRQ (0..15), value = GSI.  0xFF = no override.
static mut ISO_TABLE: [u8; 16] = [0xFF; 16];
/// Per-GSI flags from MADT ISO entries: bit 0 = active-low, bit 1 = level.
static mut ISO_FLAGS: [u8; 24] = [0; 24];

/// Returns true if the I/O APIC is initialized and available.
pub fn available() -> bool {
    IOAPIC_AVAILABLE.load(Ordering::Acquire)
}

// ── MMIO helpers ───────────────────────────────────────────────────

#[inline]
fn reg_read(base: usize, reg: u32) -> u32 {
    unsafe {
        core::ptr::write_volatile(base as *mut u32, reg);
        core::ptr::read_volatile((base + IOWIN) as *const u32)
    }
}

#[inline]
fn reg_write(base: usize, reg: u32, val: u32) {
    unsafe {
        core::ptr::write_volatile(base as *mut u32, reg);
        core::ptr::write_volatile((base + IOWIN) as *mut u32, val);
    }
}

// ── Initialization ─────────────────────────────────────────────────

/// Initialize the I/O APIC using the base address from ACPI MADT.
///
/// Must be called after `firmware::acpi::find_and_parse()` and after
/// `lapic::init_bsp()`.  If no I/O APIC was found in the MADT, this
/// is a no-op and `available()` remains false.
pub fn init() {
    let info = crate::firmware::irq_controller();
    let base = info.base1 as usize;
    if base == 0 {
        crate::println!("  I/O APIC: not found in MADT, using legacy PIC");
        return;
    }

    IOAPIC_BASE.store(base, Ordering::Release);

    // Read version register: bits 23:16 = max redirection entry index.
    let ver = reg_read(base, IOAPIC_VER);
    let max_entry = ((ver >> 16) & 0xFF) as u8;
    IOAPIC_MAX_ENTRY.store(max_entry, Ordering::Release);

    let id = (reg_read(base, IOAPIC_ID) >> 24) & 0xF;

    crate::println!(
        "  I/O APIC: id={} base={:#x} ver={:#x} pins=0..{}",
        id, base, ver & 0xFF, max_entry
    );

    // Mask all entries initially.
    for i in 0..=max_entry {
        let lo_reg = IOAPIC_REDTBL_BASE + (i as u32) * 2;
        reg_write(base, lo_reg, RTE_MASK);
        reg_write(base, lo_reg + 1, 0);
    }

    // Disable the legacy 8259 PIC by masking all IRQs.
    // The PIC was already initialized and remapped by pic::init(), so
    // just mask everything — the I/O APIC takes over.
    disable_legacy_pic();

    IOAPIC_AVAILABLE.store(true, Ordering::Release);

    // Route the standard ISA IRQs using identity mapping (IRQ N → GSI N)
    // unless overridden by MADT Interrupt Source Overrides.
    setup_default_routes();
}

/// Disable the legacy 8259 PIC by masking all IRQs on both chips.
fn disable_legacy_pic() {
    unsafe {
        // Mask all on PIC1 and PIC2.
        core::arch::asm!("out dx, al", in("dx") 0x21u16, in("al") 0xFFu8, options(nomem, nostack));
        core::arch::asm!("out dx, al", in("dx") 0xA1u16, in("al") 0xFFu8, options(nomem, nostack));
    }
}

/// Register an MADT Interrupt Source Override.
///
/// Called by the ACPI MADT parser for each type-2 entry.
/// `source` is the ISA IRQ, `gsi` is the Global System Interrupt,
/// `flags` encodes polarity (bits 1:0) and trigger mode (bits 3:2).
pub fn register_iso(source: u8, gsi: u32, flags: u16) {
    if (source as usize) < 16 {
        unsafe {
            ISO_TABLE[source as usize] = gsi as u8;
        }
    }
    if (gsi as usize) < 24 {
        // Decode MADT ISO flags:
        //   Polarity: 0b00=conform, 0b01=active-high, 0b11=active-low
        //   Trigger:  0b00=conform, 0b01=edge, 0b11=level
        let pol = flags & 0x3;
        let trig = (flags >> 2) & 0x3;
        let mut f: u8 = 0;
        if pol == 3 { f |= 1; }   // active-low
        if trig == 3 { f |= 2; }  // level-triggered
        unsafe {
            ISO_FLAGS[gsi as usize] = f;
        }
    }
    crate::println!(
        "  I/O APIC: ISO IRQ {} -> GSI {} flags={:#06x}",
        source, gsi, flags
    );
}

/// Set up default routes for ISA IRQs 0-15.
///
/// Each ISA IRQ is routed to its corresponding vector (IRQ+32) on the
/// BSP (LAPIC ID 0), honoring any Interrupt Source Overrides.
/// All entries start masked; `unmask_irq()` enables them.
fn setup_default_routes() {
    let base = IOAPIC_BASE.load(Ordering::Acquire);
    let bsp_lapic = super::lapic::id();

    for irq in 0u8..16 {
        // Check for Interrupt Source Override.
        let gsi = unsafe {
            if ISO_TABLE[irq as usize] != 0xFF {
                ISO_TABLE[irq as usize] as u32
            } else {
                irq as u32
            }
        };

        let max = IOAPIC_MAX_ENTRY.load(Ordering::Acquire) as u32;
        if gsi > max {
            continue;
        }

        let vector = 32u32 + irq as u32;

        // Determine trigger/polarity from ISO flags or ISA defaults.
        let flags = if (gsi as usize) < 24 {
            unsafe { ISO_FLAGS[gsi as usize] }
        } else {
            0
        };

        let mut rte_lo: u32 = (vector & 0xFF) | RTE_MASK; // masked initially
        if flags & 1 != 0 { rte_lo |= RTE_ACTIVELOW; }
        if flags & 2 != 0 { rte_lo |= RTE_LEVEL; }

        // Physical destination mode, fixed delivery.
        let rte_hi: u32 = bsp_lapic << 24;

        let lo_reg = IOAPIC_REDTBL_BASE + gsi * 2;
        reg_write(base, lo_reg, rte_lo);
        reg_write(base, lo_reg + 1, rte_hi);
    }
}

// ── Runtime API ────────────────────────────────────────────────────

/// Unmask an IRQ on the I/O APIC.  `irq` is the ISA IRQ number (0-15);
/// it is translated to the correct GSI via Interrupt Source Overrides.
pub fn unmask_irq(irq: u8) {
    let base = IOAPIC_BASE.load(Ordering::Acquire);
    if base == 0 { return; }

    let gsi = irq_to_gsi(irq);
    let max = IOAPIC_MAX_ENTRY.load(Ordering::Acquire) as u32;
    if gsi > max { return; }

    let lo_reg = IOAPIC_REDTBL_BASE + gsi * 2;
    let rte = reg_read(base, lo_reg);
    reg_write(base, lo_reg, rte & !RTE_MASK);
}

/// Mask an IRQ on the I/O APIC.
pub fn mask_irq(irq: u8) {
    let base = IOAPIC_BASE.load(Ordering::Acquire);
    if base == 0 { return; }

    let gsi = irq_to_gsi(irq);
    let max = IOAPIC_MAX_ENTRY.load(Ordering::Acquire) as u32;
    if gsi > max { return; }

    let lo_reg = IOAPIC_REDTBL_BASE + gsi * 2;
    let rte = reg_read(base, lo_reg);
    reg_write(base, lo_reg, rte | RTE_MASK);
}

/// Route a GSI to a specific vector and LAPIC ID.
///
/// Used for PCI device interrupts where the GSI comes from PCI config
/// space (or ACPI _PRT) rather than ISA legacy mapping.
pub fn route_gsi(gsi: u32, vector: u8, lapic_id: u32) {
    let base = IOAPIC_BASE.load(Ordering::Acquire);
    if base == 0 { return; }

    let max = IOAPIC_MAX_ENTRY.load(Ordering::Acquire) as u32;
    if gsi > max { return; }

    let lo_reg = IOAPIC_REDTBL_BASE + gsi * 2;
    // Edge-triggered, active-high, physical mode, fixed delivery, masked.
    let rte_lo: u32 = (vector as u32) | RTE_MASK;
    let rte_hi: u32 = lapic_id << 24;
    reg_write(base, lo_reg, rte_lo);
    reg_write(base, lo_reg + 1, rte_hi);
}

/// Translate an ISA IRQ to its GSI, honoring Interrupt Source Overrides.
fn irq_to_gsi(irq: u8) -> u32 {
    if (irq as usize) < 16 {
        unsafe {
            if ISO_TABLE[irq as usize] != 0xFF {
                return ISO_TABLE[irq as usize] as u32;
            }
        }
    }
    irq as u32
}
