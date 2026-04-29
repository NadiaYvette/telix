//! seL4-style call/reply IPC with kernel-managed reply capabilities.
//!
//! # Model
//!
//! A `ReplyCap` is a one-shot rendezvous object allocated by `sys_call`
//! and consumed by `sys_reply`. The caller parks on the cap; the server
//! receives the request along with the cap (installed on its thread),
//! handles it, and delivers the reply through the cap.
//!
//! # Invariants
//!
//! - A cap is created atomically with sending the request. The caller
//!   cannot be woken except through `sys_reply` on this specific cap
//!   (or thread-death via `abandon_waiter`).
//! - Reply delivery goes through `inject_recv_into_frame` on the caller's
//!   saved exception frame — there is no port queue that could drop the
//!   reply silently. If the server replies, the caller gets the reply.
//! - A cap is **linear**: a single `sys_reply` consumes it. A second
//!   `sys_reply` with the same handle returns an error.
//! - If the server dies before replying, the kernel's thread-teardown
//!   path walks the thread's held cap (if any) and delivers a
//!   `CALL_REPLY_SERVER_DIED` tag to the caller.
//!
//! # This iteration (message-only)
//!
//! Grant lease handling is NOT yet wired up — this module only implements
//! the message-rendezvous part. Step 2 will add `GrantLease` that lives on
//! the cap and ties grant lifetime to reply lifetime.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::ipc::Message;

/// Maximum number of simultaneously outstanding reply caps.
pub const MAX_REPLY_CAPS: usize = 256;

/// Maximum grant leases attached to a single reply-cap. Most IPC calls need
/// 0-2 grants (e.g. pathname + data buffer); 4 gives comfortable headroom.
pub const MAX_LEASES_PER_CAP: usize = 4;

/// A single grant lease: grant in the destination aspace that should be
/// revoked when the owning reply-cap completes (fulfill, abandon, or
/// server-death). The tuple is exactly what `mm::grant::revoke_grant`
/// needs — (dst_aspace, dst_va). `page_count` is informational.
#[repr(C)]
pub struct LeaseSlot {
    /// Destination aspace id (u64 — matches `mm::aspace::ASpaceId`); 0 means
    /// the slot is empty.
    pub dst_aspace: AtomicU64,
    /// Destination VA of the grant.
    pub dst_va: AtomicUsize,
    /// Number of MMU pages granted (stored for future validation / debug).
    pub page_count: AtomicU32,
}

impl LeaseSlot {
    pub const fn empty() -> Self {
        Self {
            dst_aspace: AtomicU64::new(0),
            dst_va: AtomicUsize::new(0),
            page_count: AtomicU32::new(0),
        }
    }

    #[inline]
    pub fn clear(&self) {
        self.dst_aspace.store(0, Ordering::Relaxed);
        self.dst_va.store(0, Ordering::Relaxed);
        self.page_count.store(0, Ordering::Relaxed);
    }

    #[inline]
    pub fn store(&self, dst_aspace: u64, dst_va: usize, page_count: u32) {
        self.dst_va.store(dst_va, Ordering::Relaxed);
        self.page_count.store(page_count, Ordering::Relaxed);
        // Publish aspace last — readers use it as the "slot occupied" flag.
        self.dst_aspace.store(dst_aspace, Ordering::Release);
    }
}

/// Reply cap lifecycle state.
///
/// Transitions:
///   Free → Pending: allocated by sys_call
///   Pending → Fulfilled: sys_reply consumes cap, writes reply, wakes caller
///   Pending → Abandoned: caller thread died before reply arrived
///   Fulfilled → Free: caller's sys_call returns, releases slot
///   Abandoned → Free: sys_reply observes abandoned state, drops reply
pub const CAP_FREE: u32 = 0;
pub const CAP_PENDING: u32 = 1;
pub const CAP_FULFILLED: u32 = 2;
pub const CAP_ABANDONED: u32 = 3;

/// Special reply tag: server died before replying. Delivered to the caller
/// by the kernel's thread-teardown path.
pub const CALL_REPLY_SERVER_DIED: u64 = 0xFFFF_FFFF_FFFF_FE00;

/// Special reply tag: IPC call interrupted by signal delivery.
/// The cap was abandoned; the server's reply (if any) will be silently dropped.
pub const CALL_REPLY_INTERRUPTED: u64 = 0xFFFF_FFFF_FFFF_FE02;

/// Special reply tag: cap invalidated for another reason (future use).
#[allow(dead_code)]
pub const CALL_REPLY_INVALIDATED: u64 = 0xFFFF_FFFF_FFFF_FE01;

/// A single reply-cap slot.
///
/// All fields are atomic because:
/// - sys_call (caller CPU) writes generation/state/caller_tid on alloc.
/// - sys_reply (server CPU, potentially different) reads+writes state
///   and writes reply fields.
/// - Thread teardown (any CPU) reads held_cap and writes state on abandon.
#[repr(C, align(64))]
pub struct ReplyCap {
    /// Generation counter. Incremented on every allocation. A handle's
    /// generation must match the slot's current generation to be valid —
    /// this prevents stale handles from reaching into a reused slot.
    pub generation: AtomicU32,
    /// Current lifecycle state (CAP_* constants above).
    pub state: AtomicU32,
    /// Thread ID of the parked caller (set on alloc).
    pub caller_tid: AtomicU32,
    /// Reply message: tag. Written by sys_reply before state transition.
    pub reply_tag: AtomicU64,
    /// Reply message: data[0..6].
    pub reply_data: [AtomicU64; 6],
    /// Grant leases attached to this cap. Revoked atomically with
    /// fulfill/abandon/server-death.
    pub leases: [LeaseSlot; MAX_LEASES_PER_CAP],
    /// Number of occupied lease slots (high-water; slots may be cleared
    /// out-of-order so iteration checks `dst_aspace != 0`).
    pub lease_count: AtomicU32,
    /// Priority-donation target: the server TID whose effective priority
    /// was raised on behalf of this cap's caller. 0 = none / already unwound.
    /// Set by `donate_priority` when the server installs the cap; cleared
    /// idempotently by `undonate_priority` (called from `free` and `abandon`).
    pub donated_server_tid: AtomicU32,
    /// Saved server effective_priority, captured at donation time. Restored
    /// on undonation. Stored as u32 for atomic convenience; value fits in u8.
    pub saved_server_prio: AtomicU32,
}

impl ReplyCap {
    const fn empty() -> Self {
        Self {
            generation: AtomicU32::new(0),
            state: AtomicU32::new(CAP_FREE),
            caller_tid: AtomicU32::new(0),
            reply_tag: AtomicU64::new(0),
            reply_data: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            leases: [const { LeaseSlot::empty() }; MAX_LEASES_PER_CAP],
            lease_count: AtomicU32::new(0),
            donated_server_tid: AtomicU32::new(0),
            saved_server_prio: AtomicU32::new(0),
        }
    }

    fn store_reply(&self, msg: &Message) {
        self.reply_tag.store(msg.tag, Ordering::Relaxed);
        for i in 0..6 {
            self.reply_data[i].store(msg.data[i], Ordering::Relaxed);
        }
    }

    fn load_reply(&self) -> Message {
        Message {
            tag: self.reply_tag.load(Ordering::Relaxed),
            data: [
                self.reply_data[0].load(Ordering::Relaxed),
                self.reply_data[1].load(Ordering::Relaxed),
                self.reply_data[2].load(Ordering::Relaxed),
                self.reply_data[3].load(Ordering::Relaxed),
                self.reply_data[4].load(Ordering::Relaxed),
                self.reply_data[5].load(Ordering::Relaxed),
            ],
        }
    }
}

/// Global slab of reply caps.
pub(crate) static REPLY_CAPS: [ReplyCap; MAX_REPLY_CAPS] = {
    // Manually construct because ReplyCap::empty() is not Copy.
    const EMPTY: ReplyCap = ReplyCap::empty();
    [const { EMPTY }; MAX_REPLY_CAPS]
};

/// Encoded 64-bit cap handle: (generation << 32) | slot_index.
/// Encodes to `u64::MAX` when invalid.
pub type CapHandle = u64;
pub const CAP_HANDLE_NONE: CapHandle = u64::MAX;

#[inline]
fn encode_handle(slot: u32, generation: u32) -> CapHandle {
    ((generation as u64) << 32) | (slot as u64)
}

#[inline]
fn decode_handle(handle: CapHandle) -> Option<(u32, u32)> {
    if handle == CAP_HANDLE_NONE {
        return None;
    }
    let slot = (handle & 0xFFFF_FFFF) as u32;
    let generation = (handle >> 32) as u32;
    if (slot as usize) >= MAX_REPLY_CAPS {
        return None;
    }
    Some((slot, generation))
}

/// Lookup a cap by handle, returning a reference only if the generation
/// matches (i.e., the slot hasn't been recycled since the handle was minted).
pub fn lookup(handle: CapHandle) -> Option<&'static ReplyCap> {
    let (slot, g) = decode_handle(handle)?;
    let cap = &REPLY_CAPS[slot as usize];
    if cap.generation.load(Ordering::Acquire) != g {
        return None;
    }
    Some(cap)
}

/// Allocate a free reply-cap slot for the given caller. Returns the handle
/// on success, or `None` if the slab is exhausted.
///
/// On success the cap is in state `Pending` with caller_tid set. Reply
/// fields are uninitialized; sys_reply must write them before fulfilling.
pub fn alloc(caller_tid: u32) -> Option<CapHandle> {
    // Linear scan for a free slot. At MAX_REPLY_CAPS=256 and low contention
    // this is fast enough; if it becomes hot we can add a free-list.
    for slot in 0..MAX_REPLY_CAPS {
        let cap = &REPLY_CAPS[slot];
        if cap
            .state
            .compare_exchange(
                CAP_FREE,
                CAP_PENDING,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            // Bump generation before publishing the handle.
            let g = cap.generation.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
            cap.caller_tid.store(caller_tid, Ordering::Relaxed);
            // Clear stale reply fields.
            cap.reply_tag.store(0, Ordering::Relaxed);
            for i in 0..6 {
                cap.reply_data[i].store(0, Ordering::Relaxed);
            }
            // Clear stale lease slots from a prior use of this slab entry.
            for l in cap.leases.iter() {
                l.clear();
            }
            cap.lease_count.store(0, Ordering::Relaxed);
            // Clear any stale donation bookkeeping from a prior use.
            cap.donated_server_tid.store(0, Ordering::Relaxed);
            cap.saved_server_prio.store(0, Ordering::Relaxed);
            return Some(encode_handle(slot as u32, g));
        }
    }
    None
}

/// Free a cap slot that has been consumed. Only called by the caller
/// (after a successful sys_call reply) or by the server (when the cap
/// was abandoned and the reply should be dropped).
///
/// Also revokes any grant leases attached to the cap. This is the kernel-
/// owned cleanup that replaces the revoke-race-prone client-side revoke:
/// the grants live exactly as long as the cap does.
pub fn free(handle: CapHandle) {
    let cap = match lookup(handle) {
        Some(c) => c,
        None => return,
    };
    undonate_priority(cap);
    revoke_cap_leases(cap);
    // Transition to Free regardless of current state.
    cap.state.store(CAP_FREE, Ordering::Release);
}

/// Attach a grant lease to a Pending cap. Called from sys_call after
/// alloc()+grant_pages, BEFORE the message is sent. Returns true if the
/// lease was recorded; false if the cap has too many leases or the handle
/// is invalid.
///
/// The caller must have the cap in state Pending with a generation-matched
/// handle — we do not validate state because the only caller path (sys_call
/// immediately after alloc) has it by construction.
pub fn arm_lease(handle: CapHandle, dst_aspace: u64, dst_va: usize, page_count: u32) -> bool {
    let cap = match lookup(handle) {
        Some(c) => c,
        None => return false,
    };
    let idx = cap.lease_count.fetch_add(1, Ordering::AcqRel) as usize;
    if idx >= MAX_LEASES_PER_CAP {
        // Too many leases — roll back and fail. The already-granted pages
        // must be revoked by the caller; we don't clean them up here.
        cap.lease_count.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    cap.leases[idx].store(dst_aspace, dst_va, page_count);
    true
}

/// Revoke all grant leases attached to the cap. Idempotent: if called twice,
/// the second walk finds all slots cleared. Uses `try_with_object` semantics
/// internally (via `mm::grant::revoke_grant`), so stale objects or already-
/// torn-down aspaces are handled gracefully.
fn revoke_cap_leases(cap: &ReplyCap) {
    // Snapshot count with Acquire to pair with arm_lease's Release on aspace.
    let count = cap.lease_count.load(Ordering::Acquire) as usize;
    let count = count.min(MAX_LEASES_PER_CAP);
    for i in 0..count {
        let slot = &cap.leases[i];
        let aspace = slot.dst_aspace.swap(0, Ordering::AcqRel);
        if aspace == 0 {
            continue; // already cleared
        }
        let va = slot.dst_va.load(Ordering::Relaxed);
        crate::mm::grant::revoke_grant(aspace, va);
        slot.dst_va.store(0, Ordering::Relaxed);
        slot.page_count.store(0, Ordering::Relaxed);
    }
    cap.lease_count.store(0, Ordering::Release);
}

/// Fulfill a cap: store the reply message and mark Pending → Fulfilled.
/// Returns the caller TID to wake, or None if the cap was abandoned (in
/// which case the reply is dropped and the slot is freed here).
pub fn fulfill(handle: CapHandle, reply: &Message) -> FulfillResult {
    // Decode the handle so we have the (slot, gen) pair available for
    // re-validation after the state CAS — the cap could in principle be
    // freed and re-allocated between `lookup` and the CAS, in which case
    // CAS would succeed against the *new* PENDING owner and we'd deliver
    // the reply to the wrong caller.
    let (slot, expected_gen) = match decode_handle(handle) {
        Some(p) => p,
        None => return FulfillResult::InvalidHandle,
    };
    let cap = &REPLY_CAPS[slot as usize];
    if cap.generation.load(Ordering::Acquire) != expected_gen {
        return FulfillResult::InvalidHandle;
    }
    // Atomically claim the cap.  Note: we deliberately do NOT write the
    // reply payload before the CAS — the payload is delivered by the
    // caller (sys_reply) directly into the parked thread's frame via
    // inject_recv_into_frame, not read from the cap.  Writing to the cap
    // before the CAS would risk clobbering a recycled cap's storage if
    // the handle is stale (lookup races free+alloc).
    match cap.state.compare_exchange(
        CAP_PENDING,
        CAP_FULFILLED,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // Re-validate generation under the FULFILLED state.  If the
            // cap was freed and re-allocated between our lookup and the
            // CAS, the CAS may have just claimed the *new* PENDING owner
            // — caller_tid would be the new caller, and waking it would
            // mis-route the reply to the wrong thread.  In that case undo
            // the FULFILLED transition (restore PENDING for the new
            // owner) and report invalid.
            let cur_gen = cap.generation.load(Ordering::Acquire);
            if cur_gen != expected_gen {
                let _ = cap.state.compare_exchange(
                    CAP_FULFILLED,
                    CAP_PENDING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
                return FulfillResult::InvalidHandle;
            }
            cap.store_reply(reply);
            let tid = cap.caller_tid.load(Ordering::Acquire);
            if tid == 0 {
                // Caller TID 0 is invalid (idle / not a real caller).
                // Treat as InvalidHandle rather than wake tid=0.
                let _ = cap.state.compare_exchange(
                    CAP_FULFILLED,
                    CAP_PENDING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
                return FulfillResult::InvalidHandle;
            }
            FulfillResult::WakeCaller(tid)
        }
        Err(CAP_ABANDONED) => {
            // Caller died — drop the reply and free the slot.
            cap.state.store(CAP_FREE, Ordering::Release);
            FulfillResult::Abandoned
        }
        Err(_) => FulfillResult::InvalidHandle,
    }
}

pub enum FulfillResult {
    /// Caller is parked; wake the indicated TID with the stored reply.
    WakeCaller(u32),
    /// Caller died while waiting. Reply has been dropped; slot is free.
    Abandoned,
    /// Handle did not refer to a Pending cap (double-reply, stale, etc.).
    InvalidHandle,
}

/// Scan the slab for any cap whose caller_tid matches the given thread and
/// abandon each one. Called from the thread-teardown path when a thread
/// dies — it may be parked in `sys_call` waiting for a reply, in which
/// case we must abandon the cap, revoke its grant leases, and drop any
/// reply the server eventually produces.
///
/// Called at most once per thread death, on a 256-slot linear scan; the
/// cost is negligible compared to the rest of teardown.
pub fn abandon_all_for_caller(caller_tid: u32) {
    for slot in 0..MAX_REPLY_CAPS {
        let cap = &REPLY_CAPS[slot];
        // Cheap pre-filter: only Pending caps are interesting, and the
        // caller_tid must match. caller_tid is only meaningful while the
        // cap is Pending, so the combined check is sufficient.
        if cap.state.load(Ordering::Acquire) != CAP_PENDING {
            continue;
        }
        if cap.caller_tid.load(Ordering::Relaxed) != caller_tid {
            continue;
        }
        let g = cap.generation.load(Ordering::Acquire);
        abandon(encode_handle(slot as u32, g));
    }
}

/// Mark a pending cap as abandoned (caller died before reply). Called by
/// the thread-teardown path. If the server has already fulfilled this cap,
/// we free it here since the caller will never consume the reply.
pub fn abandon(handle: CapHandle) {
    let cap = match lookup(handle) {
        Some(c) => c,
        None => return,
    };
    match cap.state.compare_exchange(
        CAP_PENDING,
        CAP_ABANDONED,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // Server will observe Abandoned on reply and free the slot —
            // but we revoke leases now because the caller's aspace (and
            // therefore the granted pages' source) is being torn down.
            // Leaving the server holding a mapping into a dead source
            // aspace is exactly the fault we're trying to prevent.
            // Also unwind priority donation eagerly: the server is still
            // alive, and may take arbitrary time to reply.
            undonate_priority(cap);
            revoke_cap_leases(cap);
        }
        Err(CAP_FULFILLED) => {
            // Reply already in; just drop it (and revoke any stragglers —
            // fulfill's caller should have done so, but be defensive).
            undonate_priority(cap);
            revoke_cap_leases(cap);
            cap.state.store(CAP_FREE, Ordering::Release);
        }
        Err(_) => {}
    }
}

/// Abandon a cap identified by slot index + expected caller, for signal
/// interruption of a parked IPC call.
///
/// Returns `true` if the cap was successfully transitioned PENDING → ABANDONED
/// (meaning the caller now owns the wake — the server's future `fulfill` will
/// see ABANDONED and NOT inject into the frame).  Returns `false` if the cap
/// was already fulfilled/free/abandoned or the caller_tid didn't match.
///
/// Used by `wake_thread` to coordinate with `sys_reply`: the cap state CAS
/// serializes against `fulfill`'s CAS, so exactly one side wins and handles
/// frame injection + wake.
pub fn abandon_for_interrupt(slot: u32, expected_caller: u32) -> bool {
    if (slot as usize) >= MAX_REPLY_CAPS {
        return false;
    }
    let cap = &REPLY_CAPS[slot as usize];
    if cap.caller_tid.load(Ordering::Acquire) != expected_caller {
        return false;
    }
    match cap.state.compare_exchange(
        CAP_PENDING,
        CAP_ABANDONED,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            undonate_priority(cap);
            revoke_cap_leases(cap);
            true
        }
        Err(_) => false,
    }
}

/// Priority-inheritance donation (step 3a, MCS-lite without budgets).
///
/// When a caller parks in `sys_call` and a server receives the message, we
/// *donate* the caller's effective priority to the server for the duration
/// of the cap. In Telix priority numbers lower = higher priority, so this
/// means we lower the server's `effective_priority` to `min(server, caller)`.
/// The server's original priority is saved on the cap and restored on any
/// terminal path (normal reply, caller death, server death).
///
/// Chained donations compose naturally: if server A (already running at the
/// donated priority from upstream client C) calls into server B, B inherits
/// A's current elevated priority via a fresh cap whose `saved_server_prio`
/// captures B's pre-donation value. Unwinding B's cap restores B; A stays
/// elevated until A replies to C.
///
/// Called at the point the server installs its `held_reply_cap` — both the
/// sys_call DirectTransfer path and the sys_recv_with_cap immediate-delivery
/// path. Idempotent per-cap (a second donate on the same cap would overwrite
/// saved_server_prio, so callers must not double-call).
pub fn donate_priority(handle: CapHandle, server_tid: u32, caller_prio: u8) {
    let cap = match lookup(handle) {
        Some(c) => c,
        None => return,
    };
    // Record the donation target first. Use Release so a concurrent
    // undonate_priority observing nonzero also sees the saved prio.
    cap.saved_server_prio
        .store(0, Ordering::Relaxed); // placeholder; real value written below
    let old_prio =
        crate::sched::scheduler::raise_thread_priority_to(server_tid, caller_prio);
    cap.saved_server_prio.store(old_prio as u32, Ordering::Relaxed);
    cap.donated_server_tid.store(server_tid, Ordering::Release);
}

/// Reverse `donate_priority`. Idempotent: a second call on the same cap is a
/// no-op because `donated_server_tid` is swap-cleared to 0.
///
/// Called from `free` and `abandon` so every terminal path unwinds exactly
/// once. `free` runs on the reply path; `abandon` runs eagerly on caller
/// death so the server's priority is restored without waiting for its
/// eventual reply.
pub fn undonate_priority(cap: &ReplyCap) {
    let server_tid = cap.donated_server_tid.swap(0, Ordering::AcqRel);
    if server_tid == 0 {
        return;
    }
    let saved = cap.saved_server_prio.load(Ordering::Acquire) as u8;
    crate::sched::scheduler::restore_thread_priority(server_tid, saved);
}

/// Read the reply message from a fulfilled cap. Only called by the caller
/// after being woken by sys_reply. Does NOT free the slot — caller calls
/// `free()` after copying out.
pub fn take_reply(handle: CapHandle) -> Option<Message> {
    let cap = lookup(handle)?;
    if cap.state.load(Ordering::Acquire) != CAP_FULFILLED {
        return None;
    }
    Some(cap.load_reply())
}
