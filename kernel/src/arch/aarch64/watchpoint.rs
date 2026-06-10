//! ARMv8 hardware watchpoint via DBGWVR0_EL1 / DBGWCR0_EL1.
//!
//! Mirrors arch::riscv64::watchpoint.  Arms a single watchpoint slot
//! (we use #0) for EL1 store accesses to an 8-byte aligned address.
//! When the watchpoint fires, the synchronous EL1 vector handler with
//! ESR_EL1.EC=0x35 (Watchpoint exception, same EL) catches it, logs
//! the offender, disarms, and returns.
//!
//! Used to catch the writer of zero_daemon's Thread.saved_sp slot for
//! #228 — the rv64 surface confirmed the corruption bypasses
//! write_saved_sp, so the watchpoint is the only way to attribute it
//! to a specific PC.
//!
//! DBGWCR<n>_EL1 layout (ARM ARM D13.3.16):
//!   [0]     E    - enable
//!   [2:1]   PAC  - privilege access control (01 = EL1)
//!   [4:3]   LSC  - load/store control (10 = store-only, 11 = both)
//!   [12:5]  BAS  - byte address select (0xFF = all 8 bytes)
//!   [13]    HMC  - higher mode control (1 = required for EL1 with PAC=01)
//!   [15:14] SSC  - security state control (00 = non-secure + secure)
//!   [16]    LBN  - linked breakpoint number (0 = unlinked)
//!   [19:17] WT   - watchpoint type (000 = unlinked address match)
//!   [23:20] MASK - address mask (0 = exact match)
//!
//! MDSCR_EL1.MDE (bit 15) must be 1 for watchpoints to fire in
//! Monitor Debug-mode; we set it on arm() and leave it set.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const DBGWCR_E:   u64 = 1 << 0;
const DBGWCR_PAC_EL1: u64 = 0b01 << 1;
const DBGWCR_LSC_STORE: u64 = 0b10 << 3;
const DBGWCR_BAS_8BYTE: u64 = 0xFF << 5;
const DBGWCR_HMC: u64 = 1 << 13;
// SSC=00, LBN=0, WT=0, MASK=0 — defaults to all-zero.

const MDSCR_MDE: u64 = 1 << 15;

/// Last-armed address; 0 = disarmed.  Read by the trap handler.
static ARMED_ADDR: AtomicU64 = AtomicU64::new(0);
static EVER_ARMED: AtomicBool = AtomicBool::new(false);

/// Arm a EL1 store watchpoint on `addr` (must be 8-byte aligned).
/// On QEMU virt the DBGWxR registers and EC=0x35 routing are fully
/// supported — no host stub needed.
pub fn arm(addr: u64) {
    debug_assert_eq!(addr & 0x7, 0, "watchpoint address must be 8-byte aligned");
    EVER_ARMED.store(true, Ordering::Relaxed);
    ARMED_ADDR.store(addr, Ordering::Release);
    let wcr = DBGWCR_E
        | DBGWCR_PAC_EL1
        | DBGWCR_LSC_STORE
        | DBGWCR_BAS_8BYTE
        | DBGWCR_HMC;
    unsafe {
        // DBGWVR0_EL1 = addr
        core::arch::asm!(
            "msr dbgwvr0_el1, {}",
            in(reg) addr,
            options(nostack, preserves_flags),
        );
        // DBGWCR0_EL1 = enable + EL1 store match
        core::arch::asm!(
            "msr dbgwcr0_el1, {}",
            in(reg) wcr,
            options(nostack, preserves_flags),
        );
        // MDSCR_EL1.MDE = 1.  Read-modify-write so we don't trash
        // SS or other bits.
        let mut mdscr: u64;
        core::arch::asm!(
            "mrs {}, mdscr_el1",
            out(reg) mdscr,
            options(nomem, nostack, preserves_flags),
        );
        mdscr |= MDSCR_MDE;
        core::arch::asm!(
            "msr mdscr_el1, {}",
            in(reg) mdscr,
            options(nostack, preserves_flags),
        );
        // ISB to ensure subsequent instructions see the new debug state.
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

/// Disarm the watchpoint.  Safe to call from the trap handler.
pub fn disarm() {
    ARMED_ADDR.store(0, Ordering::Release);
    unsafe {
        core::arch::asm!(
            "msr dbgwcr0_el1, {}",
            in(reg) 0u64,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

#[allow(dead_code)]
pub fn armed_addr() -> u64 {
    ARMED_ADDR.load(Ordering::Acquire)
}
