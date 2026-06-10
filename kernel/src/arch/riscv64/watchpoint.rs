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
    ARM_COUNT.fetch_add(1, Ordering::Relaxed);
    ARMED_ADDR.store(addr, Ordering::Release);
    WATCHED_ADDR.store(addr, Ordering::Release);
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

/// Re-arm the trigger on the most recently `arm()`-ed address.
/// Used by the Breakpoint trap handler to keep catching writers
/// after the first (legit) hit so later corrupting writers don't go
/// unobserved.  No-op if `arm()` was never called.
pub fn re_arm() {
    let addr = WATCHED_ADDR.load(Ordering::Acquire);
    if addr == 0 {
        return;
    }
    ARMED_ADDR.store(addr, Ordering::Release);
    unsafe {
        core::arch::asm!(
            "csrw 0x7a0, {}",
            in(reg) 0u64,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "csrw 0x7a2, {}",
            in(reg) addr,
            options(nomem, nostack),
        );
        let tdata1 = TDATA1_TYPE_MCONTROL | TDATA1_M | TDATA1_S | TDATA1_STORE;
        core::arch::asm!(
            "csrw 0x7a1, {}",
            in(reg) tdata1,
            options(nomem, nostack),
        );
    }
}

/// Persistent record of the last address passed to `arm()`.  Distinct
/// from `ARMED_ADDR` (which is cleared by `disarm()`) so `re_arm()`
/// can find the target without the caller threading it through.
static WATCHED_ADDR: AtomicU64 = AtomicU64::new(0);

/// Counter incremented on every trap-handler hit.  Useful for a
/// post-boot sanity check ("did the WP fire at all?") via the
/// existing scheduler tick log path.
pub static HIT_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// Counter incremented every time arm() is called.  Boot-time only
/// (we want to know whether the saved_sp arm site ever runs).
pub static ARM_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Per-process learned set of "legit" store PCs that fired the
/// watchpoint.  After the first N distinct PCs are observed (the
/// inlined `thread.saved_sp = new_value` sites from write_saved_sp),
/// subsequent hits at any of those PCs are quiet and re-armed.
/// A new PC after the learn slots are full is the corruption writer.
const LEGIT_PC_SLOTS: usize = 8;
static LEGIT_PCS: [AtomicU64; LEGIT_PC_SLOTS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

/// Returns true if `pc` is in the learned legit set.
pub fn is_legit_pc(pc: u64) -> bool {
    for slot in LEGIT_PCS.iter() {
        let v = slot.load(Ordering::Acquire);
        if v == pc { return true; }
        if v == 0 { return false; }
    }
    false
}

/// Add `pc` to the legit set if there is room.  Returns
/// `Some(slot_index)` on first insertion, `None` if full or already
/// present.  Caller uses this to log a single "LEARN" line per new PC.
pub fn learn_legit_pc(pc: u64) -> Option<usize> {
    for (i, slot) in LEGIT_PCS.iter().enumerate() {
        let v = slot.load(Ordering::Acquire);
        if v == pc { return None; }
        if v == 0 {
            // Race-safe-enough for boot single-shot: if CAS loses,
            // the other thread is also learning the same PC, so the
            // legit set still contains it.
            if slot.compare_exchange(0, pc, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return Some(i);
            } else {
                continue;
            }
        }
    }
    None
}

/// Current armed address, or 0 if not armed.
#[allow(dead_code)]
pub fn armed_addr() -> u64 {
    ARMED_ADDR.load(Ordering::Acquire)
}

/// Address last passed to arm() (sticky — not cleared by disarm()).
/// Used by the scheduler to bootstrap arming on APs once the BSP
/// has registered the target slot.
pub fn watched_addr() -> u64 {
    WATCHED_ADDR.load(Ordering::Acquire)
}

/// Deliberately fire the watchpoint to verify Sdtrig and scause=3
/// routing are wired correctly.  Arms on a local static, writes
/// through volatile, expects a WP-HIT log line.  Used once at boot
/// from arch::riscv64::boot when `wp_savedsp=2`, to validate the
/// infrastructure before believing or disbelieving real-world hits.
#[allow(dead_code)]
pub fn smoke_test() {
    static SMOKE_TARGET: AtomicU64 = AtomicU64::new(0);
    let addr = &SMOKE_TARGET as *const _ as u64;
    crate::println!("[#228 WP smoke-test] arming on {:#x}", addr);
    arm(addr);
    SMOKE_TARGET.store(0xDEADBEEF_CAFEBABE, Ordering::SeqCst);
    crate::println!("[#228 WP smoke-test] post-store: {:#x}",
        SMOKE_TARGET.load(Ordering::SeqCst));
}
