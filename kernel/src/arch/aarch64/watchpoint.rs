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
//! Monitor Debug-mode; KDE (bit 13) must also be 1 for same-EL
//! events (EL1→EL1) per ARM ARM AArch64.GenerateDebugExceptionsFrom
//! and QEMU debug_helper.c aa64_generate_debug_exceptions (cur_el ==
//! debug_el branch).  PSTATE.D in DAIF must also be clear.  We set
//! MDE+KDE on arm() and leave them set; D is left to the caller.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const DBGWCR_E:   u64 = 1 << 0;
const DBGWCR_PAC_EL1: u64 = 0b01 << 1;     // PAC=01 → privileged (EL1+)
const DBGWCR_LSC_STORE: u64 = 0b10 << 3;
const DBGWCR_BAS_8BYTE: u64 = 0xFF << 5;
// HMC=0, SSC=00, PAC=01 → match in NS EL1 (Linux kernel watchpoint
// convention, per ARM ARM Table D7-5).  Earlier HMC=1 setting was
// for EL2-also matches and didn't fire EL1 stores in our smoke test.
const DBGWCR_SSC_BOTH: u64 = 0b11 << 14;   // SSC=11 → secure + non-secure

const MDSCR_MDE: u64 = 1 << 15;
// KDE = Kernel Debug Enable.  Required for same-EL (EL1→EL1) debug
// exceptions to fire when cur_el == debug_el (see ARM ARM section
// D2.4 "Routing debug exceptions" + QEMU aa64_generate_debug_exceptions).
const MDSCR_KDE: u64 = 1 << 13;

/// Last-armed address; 0 = disarmed.  Read by the trap handler.
static ARMED_ADDR: AtomicU64 = AtomicU64::new(0);
static EVER_ARMED: AtomicBool = AtomicBool::new(false);

/// Arm a EL1 store watchpoint on `addr` (must be 8-byte aligned).
/// On QEMU virt the DBGWxR registers and EC=0x35 routing are fully
/// supported — no host stub needed.
pub fn arm(addr: u64) {
    debug_assert_eq!(addr & 0x7, 0, "watchpoint address must be 8-byte aligned");
    EVER_ARMED.store(true, Ordering::Relaxed);
    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    ARMED_ADDR.store(addr, Ordering::Release);
    WATCHED_ADDR.store(addr, Ordering::Release);
    let wcr = DBGWCR_E
        | DBGWCR_PAC_EL1
        | DBGWCR_LSC_STORE
        | DBGWCR_BAS_8BYTE
        | DBGWCR_SSC_BOTH;
    unsafe {
        // Clear PSTATE.D (DAIF bit 9) — boot.S leaves it set, which
        // MASKS all debug exceptions even when MDSCR.MDE/KDE are
        // enabled.  Without this the watchpoint never fires.
        core::arch::asm!(
            "msr daifclr, #8",
            options(nostack, preserves_flags),
        );
        // OSLAR_EL1 = 0 (release OS Lock).  Default state varies and
        // a set OS Lock blocks watchpoint events from firing.
        core::arch::asm!(
            "msr oslar_el1, {}",
            in(reg) 0u64,
            options(nostack, preserves_flags),
        );
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
        mdscr |= MDSCR_MDE | MDSCR_KDE;
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

/// Sticky address — last value passed to arm(), even after disarm().
pub fn watched_addr() -> u64 {
    WATCHED_ADDR.load(Ordering::Acquire)
}

/// Persistent record of the last address passed to `arm()`.  Survives
/// `disarm()` so `re_arm()` can restore the trigger.  Mirrors the
/// rv64 watchpoint module.
static WATCHED_ADDR: AtomicU64 = AtomicU64::new(0);
static WATCHED_ADDR_AUX: AtomicU64 = AtomicU64::new(0);
static ARMED_ADDR_AUX: AtomicU64 = AtomicU64::new(0);

pub static HIT_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static ARM_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

const LEGIT_PC_SLOTS: usize = 8;
static LEGIT_PCS: [AtomicU64; LEGIT_PC_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

pub fn is_legit_pc(pc: u64) -> bool {
    for slot in LEGIT_PCS.iter() {
        let v = slot.load(Ordering::Acquire);
        if v == pc { return true; }
        if v == 0 { return false; }
    }
    false
}

pub fn learn_legit_pc(pc: u64) -> Option<usize> {
    for (i, slot) in LEGIT_PCS.iter().enumerate() {
        let v = slot.load(Ordering::Acquire);
        if v == pc { return None; }
        if v == 0 {
            if slot.compare_exchange(0, pc, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return Some(i);
            } else {
                continue;
            }
        }
    }
    None
}

/// Re-arm DBGWVR0 on the previously armed address.
pub fn re_arm() {
    let addr = WATCHED_ADDR.load(Ordering::Acquire);
    if addr == 0 {
        return;
    }
    ARMED_ADDR.store(addr, Ordering::Release);
    let wcr = DBGWCR_E
        | DBGWCR_PAC_EL1
        | DBGWCR_LSC_STORE
        | DBGWCR_BAS_8BYTE
        | DBGWCR_SSC_BOTH;
    unsafe {
        core::arch::asm!(
            "msr dbgwvr0_el1, {}",
            in(reg) addr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "msr dbgwcr0_el1, {}",
            in(reg) wcr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

/// Arm watchpoint #1 (DBGWVR1) on `addr`.  Used to catch alias
/// writes via the slab identity VA (vs the SLAB_THREAD_REGION VA
/// the primary watches).
pub fn arm_aux(addr: u64) {
    debug_assert_eq!(addr & 0x7, 0, "aux watchpoint address must be 8-byte aligned");
    ARMED_ADDR_AUX.store(addr, Ordering::Release);
    WATCHED_ADDR_AUX.store(addr, Ordering::Release);
    let wcr = DBGWCR_E
        | DBGWCR_PAC_EL1
        | DBGWCR_LSC_STORE
        | DBGWCR_BAS_8BYTE
        | DBGWCR_SSC_BOTH;
    unsafe {
        core::arch::asm!(
            "msr dbgwvr1_el1, {}",
            in(reg) addr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "msr dbgwcr1_el1, {}",
            in(reg) wcr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

pub fn disarm_aux() {
    ARMED_ADDR_AUX.store(0, Ordering::Release);
    unsafe {
        core::arch::asm!(
            "msr dbgwcr1_el1, {}",
            in(reg) 0u64,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

pub fn re_arm_aux() {
    let addr = WATCHED_ADDR_AUX.load(Ordering::Acquire);
    if addr == 0 {
        return;
    }
    ARMED_ADDR_AUX.store(addr, Ordering::Release);
    let wcr = DBGWCR_E
        | DBGWCR_PAC_EL1
        | DBGWCR_LSC_STORE
        | DBGWCR_BAS_8BYTE
        | DBGWCR_SSC_BOTH;
    unsafe {
        core::arch::asm!(
            "msr dbgwvr1_el1, {}",
            in(reg) addr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!(
            "msr dbgwcr1_el1, {}",
            in(reg) wcr,
            options(nostack, preserves_flags),
        );
        core::arch::asm!("isb", options(nostack, preserves_flags));
    }
}

pub fn watched_addr_aux() -> u64 {
    WATCHED_ADDR_AUX.load(Ordering::Acquire)
}

/// Deliberately fire the watchpoint to verify the EC=0x35 path is
/// wired correctly.  Arms on a local u64, writes through volatile,
/// expects a WP-HIT log line.  Used once at boot from main.rs when
/// `wp_savedsp=2` is set, to validate the infrastructure before
/// believing or disbelieving real-world hits.
#[allow(dead_code)]
pub fn smoke_test() {
    static SMOKE_TARGET: AtomicU64 = AtomicU64::new(0);
    let addr = &SMOKE_TARGET as *const _ as u64;
    crate::println!("[#228 WP smoke-test] arming on {:#x}", addr);
    arm(addr);
    // Write to trigger.  If the watchpoint fires, the handler logs
    // WP-HIT and advances ELR past this store.  After the store, the
    // watchpoint is disarmed by the handler, so this write completes.
    SMOKE_TARGET.store(0xDEADBEEF_CAFEBABE, Ordering::SeqCst);
    crate::println!("[#228 WP smoke-test] post-store: {:#x}",
        SMOKE_TARGET.load(Ordering::SeqCst));
}
