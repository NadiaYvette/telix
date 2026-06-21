//! Completion-based IPC primitives (Phase 0 of the native completion ABI).
//!
//! See `docs/completion-abi-design.md` and `plans/completion-phase0.md`.
//!
//! An **SQE** (Submission Queue Entry) is a request a task submits to the
//! kernel; a **CQE** (Completion Queue Entry) is a result the kernel posts
//! back. Each server gets one SQ (server→kernel) and one CQ (kernel→server),
//! both **SPSC** (single producer, single consumer):
//!   - SQ: producer = the owning task, consumer = the kernel.
//!   - CQ: producer = the kernel, consumer = the owning task.
//!
//! SPSC lets us use a plain head/tail ring with **no per-slot state byte** —
//! unlike `port::MpscQueue`, which needs the byte precisely because it is
//! multi-producer (a CAS-claimed tail can be claimed-but-not-yet-written).
//! With a single producer, `tail` advancing == the slot is written, so the
//! head/tail delta alone defines fill, and `is_empty` (the consumer's check)
//! agrees with `pop` by construction.  This is also why the completion model
//! sidesteps the legacy recv_or_park is_empty()/recv() + recv_holder races.
//!
//! Phase 0 defines the layout + ring algorithm only; wiring into syscalls is
//! step ② (SYS_IO_SETUP) and the deliver path is step ③.

#![allow(dead_code)] // wired up in Phase-0 steps ②/③

use core::sync::atomic::{AtomicU32, Ordering};

/// Submission Queue Entry — one request. Exactly 64 bytes (one cache line).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sqe {
    pub opcode: u32,
    pub flags: u32,
    /// Capability handle the op acts on (dest port, or a reply-cap). Validated
    /// at use-time (§9.4): re-looked-up when the SQE is performed; a dead /
    /// insufficient-rights cap yields a `Cqe` error, never UB.
    pub target_cap: u64,
    /// Caller-chosen correlation token, echoed in the matching `Cqe`.
    pub user_data: u64,
    /// Inline payload (or a grant descriptor when `flags & FLAG_GRANT`).
    pub inline: [u64; 5],
}

/// Completion Queue Entry — one result/event. Exactly 64 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Cqe {
    /// Echoed from the SQE that caused this completion (correlation).
    pub user_data: u64,
    /// Status: 0 = ok, negative = -errno (e.g. EREVOKED for a revoked cap).
    pub result: i64,
    /// A capability this completion installs into the consumer's cap-space
    /// (reply-cap, granted page, accepted connection). 0 = none.
    pub delivered_cap: u64,
    /// Inline reply payload.
    pub inline: [u64; 5],
}

const _: () = assert!(core::mem::size_of::<Sqe>() == 64);
const _: () = assert!(core::mem::size_of::<Cqe>() == 64);

// Phase-0 opcodes (SQE.opcode).
pub const OP_SEND: u32 = 1;
pub const OP_CALL: u32 = 2; // send + await reply (matched by user_data)
pub const OP_REPLY: u32 = 3;

// SQE flags.
pub const FLAG_GRANT: u32 = 1 << 0; // `inline` is a grant descriptor

/// Ring header. Lives at the base of a shared region; the slot array
/// (`capacity * size_of::<T>`) immediately follows it. `capacity` is a power
/// of two so `mask == capacity - 1`. `head`/`tail` are free-running u32 indices
/// (wrap is fine; only the delta and the masked index matter).
#[repr(C)]
pub struct RingHeader {
    /// Consumer position (next slot to read). Owned by the consumer.
    pub head: AtomicU32,
    /// Producer position (next slot to write). Owned by the producer.
    pub tail: AtomicU32,
    pub capacity: u32,
    pub mask: u32,
}

/// SPSC ring view over a shared `RingHeader` + slot array. Not owned: `hdr`
/// and `slots` point into a region mapped into both the task and the kernel.
///
/// Safety contract: exactly one producer thread calls `push`, exactly one
/// consumer thread calls `pop`/`is_empty`, for the lifetime of the ring.
pub struct SpscRing<T: Copy> {
    hdr: *mut RingHeader,
    slots: *mut T,
}

impl<T: Copy> SpscRing<T> {
    /// # Safety
    /// `hdr` and `slots` must point at a live, correctly-sized shared region
    /// (`slots` has `(*hdr).capacity` elements) honoring the single-producer /
    /// single-consumer contract above.
    pub unsafe fn from_raw(hdr: *mut RingHeader, slots: *mut T) -> Self {
        Self { hdr, slots }
    }

    /// Producer side: enqueue `val`. Returns `false` if the ring is full.
    ///
    /// # Safety
    /// Caller is the sole producer.
    pub unsafe fn push(&self, val: T) -> bool {
        unsafe {
            let hdr = &*self.hdr;
            let tail = hdr.tail.load(Ordering::Relaxed); // producer owns tail
            let head = hdr.head.load(Ordering::Acquire); // observe freed slots
            if tail.wrapping_sub(head) >= hdr.capacity {
                return false; // full
            }
            let idx = (tail & hdr.mask) as usize;
            core::ptr::write(self.slots.add(idx), val); // fill slot
            // Release pairs with the consumer's Acquire load of `tail`, ensuring
            // the slot write is visible before the slot becomes dequeuable.
            hdr.tail.store(tail.wrapping_add(1), Ordering::Release);
            true
        }
    }

    /// Consumer side: dequeue. Returns `None` if the ring is empty.
    ///
    /// # Safety
    /// Caller is the sole consumer.
    pub unsafe fn pop(&self) -> Option<T> {
        unsafe {
            let hdr = &*self.hdr;
            let head = hdr.head.load(Ordering::Relaxed); // consumer owns head
            let tail = hdr.tail.load(Ordering::Acquire); // observe published slots
            if head == tail {
                return None; // empty
            }
            let idx = (head & hdr.mask) as usize;
            let val = core::ptr::read(self.slots.add(idx)); // read slot
            // Release pairs with the producer's Acquire load of `head`, freeing
            // the slot for reuse only after the read completes.
            hdr.head.store(head.wrapping_add(1), Ordering::Release);
            Some(val)
        }
    }

    /// Consumer side: is the ring empty? (the check `REAP_WAIT` makes before
    /// sleeping — §9.1 lost-wakeup guard re-checks this after registering.)
    ///
    /// # Safety
    /// Caller is the sole consumer (or a racy snapshot is acceptable).
    pub unsafe fn is_empty(&self) -> bool {
        unsafe {
            let hdr = &*self.hdr;
            hdr.head.load(Ordering::Relaxed) == hdr.tail.load(Ordering::Acquire)
        }
    }
}

/// Byte size of a ring region for `capacity` entries of size `entry` bytes:
/// the header plus the slot array. `capacity` must be a power of two.
pub const fn ring_region_size(capacity: u32, entry: usize) -> usize {
    core::mem::size_of::<RingHeader>() + (capacity as usize) * entry
}

// ===========================================================================
// Phase-0 kernel-side ring management + syscall backends.
//
// One SQ + one CQ per task, each a single MMU page (so depth ≤ 32: a 4 KiB
// page holds the 16-byte header + 32×64-byte entries = 2064 bytes). The pages
// are allocated from the phys allocator (so the kernel always has a direct-map
// view via `phys_to_kva`, valid in any context including the deliver path) and
// also mapped into the caller's address space (user RW) so userspace can drive
// the rings without a syscall per entry.
//
// Cache-line layout (head/tail on separate lines, entry alignment) is a Phase-2
// perf concern; the ABI is not frozen until the completion path becomes the
// default personality, so the compact header here can be revised then.
// ===========================================================================

use crate::mm::page::{phys_to_kva, MMUPAGE_SIZE};

/// Self-test / no-op opcode: `SUBMIT` echoes it straight back as a `Cqe` with
/// `result = RES_OK` and the payload copied through. Lets us validate the
/// SETUP→SUBMIT→REAP round-trip before the deliver path (step ③) exists.
pub const OP_NOP: u32 = 0xFFFF_FFFF;

/// `Cqe.result` ok / not-yet-implemented (real opcodes land in step ③).
pub const RES_OK: i64 = 0;
pub const RES_ENOSYS: i64 = -38; // mirrors Linux ENOSYS for familiarity
pub const RES_EIO: i64 = -5; // mirrors Linux EIO — outbound send/alloc failed

/// Phase-0 ring depth bounds (entries per ring; power of two; single-page).
pub const MIN_DEPTH: u32 = 2;
pub const MAX_DEPTH: u32 = 32;

#[inline]
unsafe fn sq_ring(kva: usize) -> SpscRing<Sqe> {
    let hdr = kva as *mut RingHeader;
    let slots = (kva + core::mem::size_of::<RingHeader>()) as *mut Sqe;
    unsafe { SpscRing::from_raw(hdr, slots) }
}

#[inline]
unsafe fn cq_ring(kva: usize) -> SpscRing<Cqe> {
    let hdr = kva as *mut RingHeader;
    let slots = (kva + core::mem::size_of::<RingHeader>()) as *mut Cqe;
    unsafe { SpscRing::from_raw(hdr, slots) }
}

/// Free a ring page given its kernel VA (mirrors `Task::free_groups_overflow`).
fn free_ring(kva: usize) {
    crate::mm::phys::free_page(crate::mm::page::PhysAddr::new(crate::mm::page::kva_to_phys(kva)));
}

/// Allocate one ring page, initialize its header for `depth` entries, and map
/// it into the given aspace (user RW). Returns `(user_va, kernel_va)`.
fn map_ring(aspace_id: u64, pt_root: usize, flags: u64, depth: u32) -> Result<(usize, usize), ()> {
    let pa = crate::mm::phys::alloc_page().ok_or(())?;
    let kva = phys_to_kva(pa.as_usize());
    // Zero the whole page (header + all slots), then stamp the header. The
    // AtomicU32 head/tail have the same representation as u32, so the zeroing
    // leaves them at 0.
    unsafe {
        core::ptr::write_bytes(kva as *mut u8, 0, MMUPAGE_SIZE);
        let hdr = &mut *(kva as *mut RingHeader);
        hdr.capacity = depth;
        hdr.mask = depth - 1;
    }
    let uva = crate::mm::aspace::with_aspace(aspace_id, |a| a.alloc_heap_va(MMUPAGE_SIZE));
    if crate::mm::hat::map_range(pt_root, uva, pa.as_usize(), MMUPAGE_SIZE, flags).is_err() {
        crate::mm::phys::free_page(pa);
        return Err(());
    }
    Ok((uva, kva))
}

/// `SYS_IO_SETUP` backend: set up the calling task's completion context.
/// Allocates + maps an SQ and a CQ (one page each) into the current aspace,
/// records their kernel VAs + depth on the `Task`, and returns the two user
/// VAs. One-shot per task for Phase 0.
pub fn io_setup(depth: u32) -> Result<(usize, usize), ()> {
    if depth < MIN_DEPTH || depth > MAX_DEPTH || !depth.is_power_of_two() {
        return Err(());
    }
    let task_id = crate::sched::scheduler::current_task_id();
    if task_id == 0 {
        return Err(()); // kernel context: no user aspace
    }
    let task = crate::sched::scheduler::task_ref(task_id);
    if task.io_depth.load(Ordering::Acquire) != 0 {
        return Err(()); // already set up
    }
    let aspace_id = crate::sched::scheduler::current_aspace_id();
    if aspace_id == 0 {
        return Err(());
    }
    let pt_root = crate::sched::scheduler::current_page_table_root();
    let flags = crate::mm::hat::pte_flags_for_prot(crate::mm::vma::VmaProt::ReadWrite);

    let (sq_uva, sq_kva) = map_ring(aspace_id, pt_root, flags, depth)?;
    let (cq_uva, cq_kva) = match map_ring(aspace_id, pt_root, flags, depth) {
        Ok(v) => v,
        Err(()) => {
            free_ring(sq_kva); // roll back the SQ page (PTE drops at teardown)
            return Err(());
        }
    };

    task.io_sq_kva.store(sq_kva, Ordering::Relaxed);
    task.io_cq_kva.store(cq_kva, Ordering::Relaxed);
    task.io_depth.store(depth, Ordering::Release); // publishes readiness last
    Ok((sq_uva, cq_uva))
}

/// `SYS_IO_TEARDOWN` backend: disable completion delivery for the current task
/// by clearing `io_depth` (the deliver hook in port.rs is gated on
/// `io_depth != 0`). Any task that sets up a ring for a bounded purpose (e.g.
/// the boot self-test) but otherwise uses normal `recv` IPC MUST call this when
/// done — otherwise the hook keeps routing ALL inbound messages to the now-
/// unreaped CQ (observed wedging init at the Phase-7 ramdisk test).
///
/// NOTE: the ring pages / user VAs are intentionally NOT unmapped here (a small
/// one-shot leak per setup/teardown) to keep this simple and safe; full
/// reclamation belongs to address-space teardown. The longer-term fix is
/// per-port deliver scoping, which would make this unnecessary — see
/// project_completion_abi_phase0.
pub fn io_teardown() -> u64 {
    let task_id = crate::sched::scheduler::current_task_id();
    if task_id == 0 {
        return 0;
    }
    let task = crate::sched::scheduler::task_ref(task_id);
    // Clear io_depth FIRST (Release) so the deliver hook stops routing before
    // the ring pointers drop, then drop the pointers.
    task.io_depth.store(0, Ordering::Release);
    task.io_sq_kva.store(0, Ordering::Relaxed);
    task.io_cq_kva.store(0, Ordering::Relaxed);
    0
}

/// Perform a single SQE. Returns `Some(cqe)` to post a completion, or `None`
/// for fire-and-forget ops (OP_REPLY) that produce no self-completion.
fn perform_sqe(sqe: &Sqe) -> Option<Cqe> {
    match sqe.opcode {
        OP_NOP => Some(Cqe {
            user_data: sqe.user_data,
            result: RES_OK,
            delivered_cap: 0,
            inline: sqe.inline, // echo the payload (NOP round-trip)
        }),
        OP_REPLY => {
            // Bridge: complete the sync caller this reply-cap (`target_cap`)
            // refers to. Reply payload: tag = user_data, data[0..5] = inline,
            // data[5] = 0. Fire-and-forget — no self-completion to the server.
            let reply = crate::ipc::Message::new(
                sqe.user_data,
                [
                    sqe.inline[0],
                    sqe.inline[1],
                    sqe.inline[2],
                    sqe.inline[3],
                    sqe.inline[4],
                    0,
                ],
            );
            crate::syscall::handlers::complete_reply_to(sqe.target_cap, &reply);
            None
        }
        OP_SEND => {
            // Fire-and-forget send to target_cap (a port). The outbound
            // message is tag = inline[0], data[0..4] = inline[1..5] (4 payload
            // words) + sender identity in data[4]; no reply-cap. (The wire tag
            // must stay separate from `user_data`, which is the issuer's
            // private correlation token — hence tag = inline[0].)
            let issuer = crate::sched::scheduler::current_task_id();
            let mut msg = crate::ipc::Message::new(
                sqe.inline[0],
                [
                    sqe.inline[1],
                    sqe.inline[2],
                    sqe.inline[3],
                    sqe.inline[4],
                    crate::sched::task_port_id(issuer),
                    0,
                ],
            );
            let ok = crate::syscall::handlers::completion_send(sqe.target_cap, &mut msg, None);
            Some(Cqe {
                user_data: sqe.user_data,
                result: if ok { RES_OK } else { RES_EIO },
                delivered_cap: 0,
                inline: [0; 5],
            })
        }
        OP_CALL => {
            // Async call: allocate a completion reply-cap bound to this task +
            // user_data, send the request to target_cap carrying that cap in
            // data[5], and post NO CQE now — the reply arrives later as a CQE
            // (matched by user_data) via fulfill -> deliver_reply_cqe.
            let issuer = crate::sched::scheduler::current_task_id();
            let handle = match crate::ipc::call_reply::alloc_completion(issuer, sqe.user_data) {
                Some(h) => h,
                None => {
                    // Reply-cap slab exhausted — report the failure now.
                    return Some(Cqe {
                        user_data: sqe.user_data,
                        result: RES_EIO,
                        delivered_cap: 0,
                        inline: [0; 5],
                    });
                }
            };
            let mut msg = crate::ipc::Message::new(
                sqe.inline[0],
                [
                    sqe.inline[1],
                    sqe.inline[2],
                    sqe.inline[3],
                    sqe.inline[4],
                    crate::sched::task_port_id(issuer),
                    handle,
                ],
            );
            if crate::syscall::handlers::completion_send(sqe.target_cap, &mut msg, Some(handle)) {
                None // reply CQE is delivered asynchronously on fulfill
            } else {
                // Send failed — free the cap and report the error now.
                crate::ipc::call_reply::free(handle);
                Some(Cqe {
                    user_data: sqe.user_data,
                    result: RES_EIO,
                    delivered_cap: 0,
                    inline: [0; 5],
                })
            }
        }
        _ => Some(Cqe {
            user_data: sqe.user_data,
            result: RES_ENOSYS,
            delivered_cap: 0,
            inline: sqe.inline,
        }),
    }
}

/// `SYS_IO_SUBMIT` backend: drain the caller's SQ, perform each SQE, and push a
/// CQE per entry. Returns the number of entries performed.
pub fn io_submit() -> u64 {
    let task_id = crate::sched::scheduler::current_task_id();
    if task_id == 0 {
        return 0;
    }
    let task = crate::sched::scheduler::task_ref(task_id);
    if task.io_depth.load(Ordering::Acquire) == 0 {
        return 0; // no completion context
    }
    let sq_kva = task.io_sq_kva.load(Ordering::Relaxed);
    let cq_kva = task.io_cq_kva.load(Ordering::Relaxed);
    let mut n = 0u64;
    // SAFETY: the calling task is the sole SQ consumer (kernel side) and the
    // sole CQ producer; both rings live at stable kernel VAs for this task.
    unsafe {
        let sq = sq_ring(sq_kva);
        let cq = cq_ring(cq_kva);
        while let Some(sqe) = sq.pop() {
            // perform_sqe returns None for fire-and-forget ops (OP_REPLY).
            if let Some(cqe) = perform_sqe(&sqe) {
                // CQ full → drop (Phase 0; backlog is §9.3). Unreachable in the
                // self-test where depth is sized + reaping is prompt.
                let _ = cq.push(cqe);
            }
            n += 1;
        }
    }
    n
}

/// Count of CQEs currently available in the ring at `cq_kva` (consumer view).
///
/// # Safety
/// `cq_kva` is a live CQ ring kernel VA for a completion-enabled task.
unsafe fn cq_avail(cq_kva: usize) -> u32 {
    unsafe {
        let hdr = &*(cq_kva as *const RingHeader);
        let head = hdr.head.load(Ordering::Relaxed);
        let tail = hdr.tail.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }
}

/// `SYS_IO_REAP_WAIT` backend: block until at least `min` CQEs are available
/// (`min == 0` ⇒ non-blocking poll), then return the count available. Userspace
/// reads the CQEs directly from the ring (it owns the CQ head and advances it).
///
/// Park/wake reuses the proven turnstile (Option A): the server parks on its
/// task identity port under `KEY_IO_REAP`; the deliver path posts a CQE then
/// `port_wake_one`s it. `port_enqueue_with_check` rechecks "CQ empty" under the
/// HAMT bucket lock, which `port_wake_one` also takes — so the recheck and the
/// wake are serialized, giving lost-wakeup safety without manual fences. Mirrors
/// `port::recv_or_park`'s pre-save → enqueue-with-recheck → commit sequence.
pub fn io_reap_wait(min: u64) -> u64 {
    let task_id = crate::sched::scheduler::current_task_id();
    if task_id == 0 {
        return 0;
    }
    let task = crate::sched::scheduler::task_ref(task_id);
    if task.io_depth.load(Ordering::Acquire) == 0 {
        return 0; // no completion context
    }
    let cq_kva = task.io_cq_kva.load(Ordering::Relaxed);
    let port_id = task.port_id;
    let tid = crate::sched::scheduler::current_thread_id();

    // Fast path / non-blocking poll.
    // SAFETY: cq_kva is this task's live CQ ring.
    let avail = unsafe { cq_avail(cq_kva) };
    if min == 0 || avail as u64 >= min {
        return avail as u64;
    }

    // Block AT MOST ONCE, mirroring port::recv_or_park: capture tid once, do a
    // single pre_save_frame + enqueue-with-recheck + park, then return the
    // current count. The userspace Rings::reap_wait loops THIS syscall until it
    // has >= min, so the kernel never loop-parks. (Loop-parking re-ran
    // pre_save_frame every iteration, corrupting the saved frame and
    // livelocking the idle thread — comp5a, see project_completion_abi_phase0.)
    crate::sched::scheduler::pre_save_frame(tid);
    let enqueued = crate::sync::turnstile::port_enqueue_with_check(
        port_id,
        crate::sync::turnstile::KEY_IO_REAP,
        tid,
        // Park only if still empty (re-checked under the bucket lock, which
        // port_wake_one also takes → lost-wakeup-safe).
        || unsafe { cq_avail(cq_kva) } == 0,
    );
    if enqueued {
        crate::sched::scheduler::park_current_for_ipc(
            crate::sched::thread::BlockReason::PortRecv(port_id),
        );
    } else {
        // CQ became non-empty during enqueue — reset park bookkeeping.
        unsafe { crate::sched::scheduler::thread_mut_from_ref(tid) }.ipc_frame_sp = 0;
        crate::sched::scheduler::thread_ref(tid)
            .park_state
            .store(crate::sched::scheduler::PARK_NONE, Ordering::Release);
    }
    // Return whatever is available now (may be < min if woken spuriously; the
    // userspace loop re-blocks).
    unsafe { cq_avail(cq_kva) as u64 }
}

/// Set on an inbound-request CQE's `user_data` to carry the receive-port id
/// (`user_data = recv_port | INBOUND_PORT_BIT`), so a multi-port server (linux_srv:
/// personality + backend-reply + worker ports all funnel into one CQ) can demux
/// which of its ports a request arrived on — the `port_set_recv` `src_port` it
/// relied on, preserved into the completion model (linux_srv endgame phase LA).
///
/// Distinct from an OP_CALL reply's `user_data` (which carries the issuer's
/// correlation token with `CALL_TOKEN_BIT = 1<<63` set, userlib-side) and from a
/// legacy/self-completion `user_data` (no high bits). Port ids are < 2^32, so
/// `recv_port | (1<<62)` never collides with either. MUST match the userlib
/// `INBOUND_PORT_BIT` in `userlib/src/completion.rs`.
pub const INBOUND_PORT_BIT: u64 = 1 << 62;

/// Deliver an incoming `Message` to a completion-enabled task's CQ — the deliver
/// path's replacement for queueing / DirectTransfer. Maps the message into a
/// `Cqe` and wakes the server if it's parked in `io_reap_wait`. Returns false
/// if the CQ is full (the caller falls back to the legacy queue for Phase 0).
///
/// `recv_port` is the port the message was delivered TO (the receiver's source
/// port); it is stamped into `user_data` (with `INBOUND_PORT_BIT`) so a multi-port
/// server can demux. Leaf servers (`serve`/`serve_deferred`) ignore `user_data`.
///
/// Message → Cqe mapping (preserves all 7 message words):
///   user_data     = recv_port | INBOUND_PORT_BIT  (which port it arrived on)
///   result        = tag        (the message tag / opcode)
///   inline[0..5]  = data[0..5] (payload; data[4] carries sender identity)
///   delivered_cap = data[5]    (the reply-cap handle for CALL; data for SEND)
pub fn deliver_to_completion_cq(task_id: u32, recv_port: u64, msg: &crate::ipc::Message) -> bool {
    let task = match crate::sched::scheduler::task_ref_opt(task_id) {
        Some(t) => t,
        None => return false,
    };
    let cq_kva = task.io_cq_kva.load(Ordering::Relaxed);
    if cq_kva == 0 {
        crate::println!("IODELIV-NOCTX: task={} tag={:#x}", task_id, msg.tag);
        return false;
    }
    let cqe = Cqe {
        user_data: recv_port | INBOUND_PORT_BIT,
        result: msg.tag as i64,
        delivered_cap: msg.data[5],
        inline: [msg.data[0], msg.data[1], msg.data[2], msg.data[3], msg.data[4]],
    };
    // SAFETY: the kernel is the sole CQ producer for this task; cq_kva is its
    // live CQ ring.
    let pushed = unsafe { cq_ring(cq_kva).push(cqe) };
    if !pushed {
        crate::println!("IODELIV-FULL: task={} tag={:#x}", task_id, msg.tag);
        return false; // CQ full — caller falls back to the legacy queue
    }
    // Wake the server if parked in io_reap_wait. The bucket lock taken here and
    // in port_enqueue_with_check's recheck serializes us against a concurrent
    // park, giving lost-wakeup safety (no-op if the server isn't parked).
    let _ = crate::sync::turnstile::port_wake_one(task.port_id, crate::sync::turnstile::KEY_IO_REAP);
    true
}

/// Deliver an `OP_CALL` *reply* to `task_id`'s CQ, tagged with the issuer's
/// correlation `user_data` (vs `deliver_to_completion_cq`, which tags inbound
/// requests with `user_data = 0`). Called from the reply paths (`fulfill` ->
/// `DeliverToCompletion`). Wakes the issuer if parked in `io_reap_wait`.
/// Returns false if the task has no CQ or the CQ is full.
///
/// Reply `Message` -> `Cqe`:
///   user_data     = the issuer's correlation token (echoed)
///   result        = reply.tag (the reply opcode / status)
///   inline[0..5]  = reply.data[0..4]
///   delivered_cap = reply.data[5] (any cap the reply granted)
pub fn deliver_reply_cqe(task_id: u32, user_data: u64, reply: &crate::ipc::Message) -> bool {
    let task = match crate::sched::scheduler::task_ref_opt(task_id) {
        Some(t) => t,
        None => return false,
    };
    let cq_kva = task.io_cq_kva.load(Ordering::Relaxed);
    if cq_kva == 0 {
        crate::println!("IOREPLY-NOCTX: task={} ud={:#x}", task_id, user_data);
        return false;
    }
    let cqe = Cqe {
        user_data,
        result: reply.tag as i64,
        delivered_cap: reply.data[5],
        inline: [
            reply.data[0],
            reply.data[1],
            reply.data[2],
            reply.data[3],
            reply.data[4],
        ],
    };
    // SAFETY: the kernel is the sole CQ producer for this task; cq_kva is its
    // live CQ ring.
    let pushed = unsafe { cq_ring(cq_kva).push(cqe) };
    if !pushed {
        crate::println!("IOREPLY-FULL: task={} ud={:#x}", task_id, user_data);
        return false;
    }
    let _ = crate::sync::turnstile::port_wake_one(task.port_id, crate::sync::turnstile::KEY_IO_REAP);
    true
}
