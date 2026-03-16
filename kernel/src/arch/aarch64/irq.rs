//! GICv3 interrupt controller driver for QEMU virt machine.
//!
//! QEMU virt provides a GICv3 at:
//!   Distributor:   0x0800_0000
//!   Redistributor: 0x080A_0000
//!
//! We use system register access for the CPU interface (ICC_* registers).

// GICD (Distributor) registers
const GICD_BASE: usize = 0x0800_0000;
const GICD_CTLR: usize = GICD_BASE + 0x000;
const GICD_ISENABLER: usize = GICD_BASE + 0x100; // Array of 32-bit registers
const GICD_IPRIORITYR: usize = GICD_BASE + 0x400; // Array of 8-bit fields
const GICD_ITARGETSR: usize = GICD_BASE + 0x800; // Array of 8-bit fields

// GICR (Redistributor) registers — one per CPU, 128 KiB stride
const GICR_BASE: usize = 0x080A_0000;
const GICR_STRIDE: usize = 0x20000; // 128 KiB per redistributor
const GICR_WAKER_OFFSET: usize = 0x14;
// SGI/PPI redistributor frame is at offset 0x10000 from the redistributor base
const GICR_SGI_BASE_OFFSET: usize = 0x10000;
const GICR_IGROUPR0_OFFSET: usize = 0x080;  // Interrupt Group Register 0 (SGIs/PPIs)
const GICR_ISENABLER0_OFFSET: usize = 0x100;
const GICR_IPRIORITYR_OFFSET: usize = 0x400;

// Interrupt IDs
pub const INTID_TIMER_EL1_PHYS: u32 = 30; // PPI: EL1 physical timer (CNTP)
const INTID_SPURIOUS: u32 = 1023;

/// Initialize the GICv3 for the boot CPU (CPU 0).
pub fn init() {
    // 1. Wake the redistributor for CPU 0.
    let gicr_base = GICR_BASE;
    let waker = (gicr_base + GICR_WAKER_OFFSET) as *mut u32;
    unsafe {
        // Clear ProcessorSleep bit (bit 1).
        let val = core::ptr::read_volatile(waker);
        core::ptr::write_volatile(waker, val & !(1 << 1));
        // Wait until ChildrenAsleep (bit 2) clears.
        while core::ptr::read_volatile(waker) & (1 << 2) != 0 {
            core::hint::spin_loop();
        }
    }

    // 2. Put all SGIs/PPIs (INTID 0-31) into Group 1 (non-secure).
    let sgi_base = gicr_base + GICR_SGI_BASE_OFFSET;
    unsafe {
        let igroupr0 = (sgi_base + GICR_IGROUPR0_OFFSET) as *mut u32;
        core::ptr::write_volatile(igroupr0, 0xFFFF_FFFF); // All Group 1
    }

    // 3. Configure ICC system registers.
    unsafe {
        // ICC_SRE_EL1: Enable system register access (bit 0).
        core::arch::asm!("mrs {tmp}, S3_0_C12_C12_5", "orr {tmp}, {tmp}, #1", "msr S3_0_C12_C12_5, {tmp}", "isb", tmp = out(reg) _);

        // ICC_PMR_EL1: Set priority mask to allow all priorities (0xFF).
        core::arch::asm!("mov {tmp}, #0xFF", "msr S3_0_C4_C6_0, {tmp}", tmp = out(reg) _);

        // ICC_CTLR_EL1: Default config is fine.

        // ICC_IGRPEN1_EL1: Enable Group 1 interrupts (bit 0).
        core::arch::asm!("mov {tmp}, #1", "msr S3_0_C12_C12_7, {tmp}", "isb", tmp = out(reg) _);
    }

    // 3. Enable the distributor (Group 1 non-secure).
    unsafe {
        let ctlr = GICD_CTLR as *mut u32;
        // Set EnableGrp1NS (bit 1) and ARE_NS (bit 4).
        core::ptr::write_volatile(ctlr, (1 << 1) | (1 << 4));
    }

    crate::println!("  GICv3 initialized");
}

/// Enable a specific interrupt ID.
pub fn enable_interrupt(intid: u32) {
    if intid < 32 {
        // PPI/SGI: configure via redistributor for CPU 0.
        let sgi_base = GICR_BASE + GICR_SGI_BASE_OFFSET;
        let reg = (sgi_base + GICR_ISENABLER0_OFFSET) as *mut u32;
        unsafe {
            let val = core::ptr::read_volatile(reg);
            core::ptr::write_volatile(reg, val | (1 << intid));
        }
        // Set priority (lower number = higher priority). Use 0x80.
        let prio_reg = (sgi_base + GICR_IPRIORITYR_OFFSET + intid as usize) as *mut u8;
        unsafe {
            core::ptr::write_volatile(prio_reg, 0x80);
        }
    } else {
        // SPI: configure via distributor.
        let reg_index = (intid / 32) as usize;
        let bit = intid % 32;
        let reg = (GICD_ISENABLER + reg_index * 4) as *mut u32;
        unsafe {
            core::ptr::write_volatile(reg, 1 << bit);
        }
        // Set priority.
        let prio_reg = (GICD_IPRIORITYR + intid as usize) as *mut u8;
        unsafe {
            core::ptr::write_volatile(prio_reg, 0x80);
        }
        // Route to CPU 0 (GICD_IROUTER default is fine for GICv3 with ARE).
    }
}

/// Acknowledge the highest-priority pending interrupt. Returns the interrupt ID.
pub fn acknowledge() -> u32 {
    let intid: u64;
    unsafe {
        // ICC_IAR1_EL1
        core::arch::asm!("mrs {}, S3_0_C12_C12_0", out(reg) intid);
    }
    intid as u32
}

/// Signal end-of-interrupt for the given interrupt ID.
pub fn end_of_interrupt(intid: u32) {
    unsafe {
        // ICC_EOIR1_EL1
        core::arch::asm!("msr S3_0_C12_C12_1, {}", in(reg) intid as u64);
    }
}

/// Top-level IRQ handler called from exception vectors.
pub fn handle_irq() {
    let intid = acknowledge();
    if intid == INTID_SPURIOUS {
        return;
    }

    match intid {
        INTID_TIMER_EL1_PHYS => {
            crate::arch::aarch64::timer::handle_timer_irq();
        }
        _ => {
            crate::println!("Unhandled IRQ: {}", intid);
        }
    }

    end_of_interrupt(intid);
}
