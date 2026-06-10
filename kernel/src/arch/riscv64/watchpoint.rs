//! RISC-V Sdtrig (Debug-Trigger extension) hardware watchpoint.
//!
//! Arms a single mcontrol-type trigger that fires a Breakpoint
//! exception (scause=3) on any S-mode (or M-mode) store matching the
//! given address.  Used to catch the writer of zero_daemon's Thread
//! struct slot in #228.
//!
//! CSRs (RISC-V Debug spec):
//!   tselect  (0x7a0) — select which of up to 16 triggers to configure
//!   tdata1   (0x7a1) — trigger configuration word
//!   tdata2   (0x7a2) — trigger data (the address)
//!
//! tdata1 for type=2 (mcontrol) on RV64:
//!   [63:60] type            (= 2 = mcontrol)
//!   [10:7]  action          (0 = raise Breakpoint exception)
//!   [6]     m               (match in M-mode)
//!   [5]     dmode           (0 = S-mode writable, 1 = debug-only)
//!   [4]     s               (match in S-mode)
//!   [3]     u               (match in U-mode)
//!   [2:0]   modes: load (bit 0), store (bit 1), execute (bit 2)
//!
//! For our purpose we want store match in S-mode (and M-mode for
//! good measure, in case the writer happens to be IRQ-context with
//! sstatus.SPP=S but somehow misclassified).  Action=0 raises the
//! Breakpoint exception that scause=3 catches in trap.rs.

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

const TDATA1_TYPE_MCONTROL: u64 = 2 << 60;
const TDATA1_M: u64 = 1 << 6;
const TDATA1_S: u64 = 1 << 4;
const TDATA1_STORE: u64 = 1 << 1;

/// What the trigger is currently armed on (0 = disarmed).  Read by
/// the trap handler to skip the watchpoint arm if it's already
/// fired and not been re-armed.
static ARMED_ADDR: AtomicU64 = AtomicU64::new(0);
/// Set the first time arm() is called so we can guard against double
/// arms which would race the trigger reconfiguration.
static EVER_ARMED: AtomicBool = AtomicBool::new(false);

/// Arm a S-mode store watchpoint on `addr`.  Fires Breakpoint
/// exception on the next store to `[addr, addr+8)`.  Caller is
/// expected to be S-mode kernel code.
pub fn arm(addr: u64) {
    EVER_ARMED.store(true, Ordering::Relaxed);
    ARMED_ADDR.store(addr, Ordering::Release);
    unsafe {
        // Select trigger 0.
        core::arch::asm!(
            "csrw 0x7a0, {}",
            in(reg) 0u64,
            options(nomem, nostack),
        );
        // Address.
        core::arch::asm!(
            "csrw 0x7a2, {}",
            in(reg) addr,
            options(nomem, nostack),
        );
        // Config: mcontrol type, S-mode + M-mode, store, action=0.
        let tdata1 = TDATA1_TYPE_MCONTROL | TDATA1_M | TDATA1_S | TDATA1_STORE;
        core::arch::asm!(
            "csrw 0x7a1, {}",
            in(reg) tdata1,
            options(nomem, nostack),
        );
    }
}

/// Disarm the trigger.  Safe to call from the Breakpoint trap
/// handler — leaves the trigger configured but with no fire modes.
pub fn disarm() {
    ARMED_ADDR.store(0, Ordering::Release);
    unsafe {
        core::arch::asm!(
            "csrw 0x7a0, {}",
            in(reg) 0u64,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "csrw 0x7a1, {}",
            in(reg) 0u64,
            options(nomem, nostack),
        );
    }
}

/// Current armed address, or 0 if not armed.
#[allow(dead_code)]
pub fn armed_addr() -> u64 {
    ARMED_ADDR.load(Ordering::Acquire)
}
