//! Userspace side of the completion-based IPC ABI (Phase 0).
//!
//! Mirrors `kernel/src/ipc/completion.rs`: the SQE/CQE layouts and the SPSC
//! ring algorithm. A task calls `Rings::setup(depth)` once to get its SQ + CQ
//! mapped into its address space, then:
//!   - producer of the SQ: `submit_one(sqe)` writes an entry, `submit()` asks
//!     the kernel to drain + perform them;
//!   - consumer of the CQ: `reap_wait(min)` returns how many completions are
//!     ready, `reap_one()` pops one.
//!
//! The ring layout MUST match the kernel exactly (it is the shared memory). See
//! the kernel module for the ownership rules: for the SQ the kernel is the
//! consumer (owns `head`), for the CQ the kernel is the producer (owns `tail`).

use crate::arch;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Source of OP_CALL correlation tokens (the CQE's `user_data`).
static NEXT_CALL_TOKEN: AtomicU64 = AtomicU64::new(0);
/// High bit set on every call token so a reply CQE (`user_data != 0`) is always
/// distinguishable from an inbound request CQE (`user_data == 0`).
const CALL_TOKEN_BIT: u64 = 1 << 63;

const SYS_IO_SETUP: u64 = 130;
const SYS_IO_SUBMIT: u64 = 131;
const SYS_IO_REAP_WAIT: u64 = 132;
const SYS_IO_TEARDOWN: u64 = 133;

/// Self-test / no-op opcode (kernel echoes it back as a `result = 0` CQE).
pub const OP_NOP: u32 = 0xFFFF_FFFF;
pub const OP_SEND: u32 = 1;
pub const OP_CALL: u32 = 2;
pub const OP_REPLY: u32 = 3;

/// Submission Queue Entry — must match `kernel::ipc::completion::Sqe` (64 B).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sqe {
    pub opcode: u32,
    pub flags: u32,
    pub target_cap: u64,
    pub user_data: u64,
    pub inline: [u64; 5],
}

/// Completion Queue Entry — must match `kernel::ipc::completion::Cqe` (64 B).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Cqe {
    pub user_data: u64,
    pub result: i64,
    pub delivered_cap: u64,
    pub inline: [u64; 5],
}

const _: () = assert!(core::mem::size_of::<Sqe>() == 64);
const _: () = assert!(core::mem::size_of::<Cqe>() == 64);

/// Ring header — must match `kernel::ipc::completion::RingHeader`.
#[repr(C)]
struct RingHeader {
    head: AtomicU32,
    tail: AtomicU32,
    capacity: u32,
    mask: u32,
}

const HDR_SIZE: usize = core::mem::size_of::<RingHeader>();

/// Producer push (used by userspace for the SQ). Returns false if full.
///
/// # Safety
/// `base` is a live ring mapped by `Rings::setup`; caller is the sole producer.
unsafe fn ring_push<T: Copy>(base: usize, val: T) -> bool {
    unsafe {
        let hdr = &*(base as *const RingHeader);
        let slots = (base + HDR_SIZE) as *mut T;
        let tail = hdr.tail.load(Ordering::Relaxed);
        let head = hdr.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= hdr.capacity {
            return false;
        }
        let idx = (tail & hdr.mask) as usize;
        core::ptr::write(slots.add(idx), val);
        hdr.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }
}

/// Consumer pop (used by userspace for the CQ). Returns None if empty.
///
/// # Safety
/// `base` is a live ring mapped by `Rings::setup`; caller is the sole consumer.
unsafe fn ring_pop<T: Copy>(base: usize) -> Option<T> {
    unsafe {
        let hdr = &*(base as *const RingHeader);
        let slots = (base + HDR_SIZE) as *const T;
        let head = hdr.head.load(Ordering::Relaxed);
        let tail = hdr.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let idx = (head & hdr.mask) as usize;
        let val = core::ptr::read(slots.add(idx));
        hdr.head.store(head.wrapping_add(1), Ordering::Release);
        Some(val)
    }
}

/// A task's completion rings (SQ + CQ), mapped into its address space.
pub struct Rings {
    sq: usize,
    cq: usize,
}

impl Rings {
    /// Set up the calling task's completion rings. `depth` must be a power of
    /// two in `[2, 32]`. One-shot per task. Returns None on error.
    pub fn setup(depth: u32) -> Option<Rings> {
        let (sq, cq) = unsafe { arch::syscall1_2ret(SYS_IO_SETUP, depth as u64) };
        if sq == u64::MAX {
            return None;
        }
        Some(Rings {
            sq: sq as usize,
            cq: cq as usize,
        })
    }

    /// Enqueue one SQE (producer side of the SQ). Returns false if the SQ is
    /// full (drain it with `submit()` first).
    pub fn push(&self, sqe: Sqe) -> bool {
        unsafe { ring_push::<Sqe>(self.sq, sqe) }
    }

    /// Ask the kernel to drain the SQ and perform each entry. Returns the count
    /// performed.
    pub fn submit(&self) -> u64 {
        unsafe { arch::syscall0(SYS_IO_SUBMIT) }
    }

    /// Block until at least `min` completions are available, then return the
    /// count (`min == 0` = single non-blocking poll). The kernel parks at most
    /// once per syscall (mirroring recv_or_park), so we loop the syscall until
    /// `min` is satisfied. This is NOT a busy-spin: each iteration that finds
    /// the CQ still empty re-blocks in the kernel.
    pub fn reap_wait(&self, min: u64) -> u64 {
        loop {
            let n = unsafe { arch::syscall1(SYS_IO_REAP_WAIT, min) };
            if min == 0 || n >= min {
                return n;
            }
        }
    }

    /// Pop one completion (consumer side of the CQ). Returns None if empty.
    pub fn reap(&self) -> Option<Cqe> {
        unsafe { ring_pop::<Cqe>(self.cq) }
    }

    /// Issue an `OP_CALL` to `dest_cap` and block until its reply CQE arrives.
    /// `tag` is the wire opcode for the destination server; `args` are up to 4
    /// payload words (delivered as the message's data[0..3]). Returns the reply
    /// `Cqe` — its `result` is the reply tag, `inline` the reply data,
    /// `delivered_cap` any cap the reply granted — or None if the SQE could not
    /// be queued.
    ///
    /// The correlation `user_data` carries `CALL_TOKEN_BIT`, so the reply CQE
    /// (`user_data != 0`) is always distinguishable from an inbound request CQE
    /// (`user_data == 0`). This is the simple one-outstanding-call form; a
    /// fan-out server multiplexing many in-flight calls drives the ring
    /// directly and correlates by token itself.
    pub fn call(&self, dest_cap: u64, tag: u64, args: [u64; 4]) -> Option<Cqe> {
        let token = NEXT_CALL_TOKEN.fetch_add(1, Ordering::Relaxed) | CALL_TOKEN_BIT;
        let sqe = Sqe {
            opcode: OP_CALL,
            flags: 0,
            target_cap: dest_cap,
            user_data: token,
            inline: [tag, args[0], args[1], args[2], args[3]],
        };
        if !self.push(sqe) {
            return None;
        }
        self.submit();
        loop {
            self.reap_wait(1);
            while let Some(cqe) = self.reap() {
                if cqe.user_data == token {
                    return Some(cqe);
                }
                // Not our reply (e.g. an inbound request, user_data == 0, on a
                // shared ring) — ignore it for this blocking call.
            }
        }
    }

    /// Run a classic request/reply server on the completion queue — the
    /// completion-ABI equivalent of the legacy `loop { recv_with_cap; handle;
    /// reply }` (design docs §2.5.2 → §2.5.4; the `completion_server_loop`
    /// helper of completion-abi-design.md Appendix A). Never returns.
    ///
    /// Each iteration blocks in `reap_wait`, then drains every ready CQE. An
    /// inbound client call arrives as a CQE the kernel deliver hook synthesised
    /// (`result` = tag, `inline` = data with `inline[4]` = sender identity,
    /// `delivered_cap` = the one-shot reply-cap). For each request the handler
    /// returns `Some(Reply)` to answer via a batched `OP_REPLY`, or `None` for
    /// fire-and-forget. Replies are submitted once per drained batch.
    ///
    /// Leaf servers only (no outbound `OP_CALL` yet): every CQE is treated as a
    /// request. Fan-out servers (replies to our own `OP_CALL`, `user_data != 0`)
    /// are Phase 2.
    pub fn serve<F>(&self, mut handler: F) -> !
    where
        F: FnMut(Request) -> Option<Reply>,
    {
        loop {
            self.reap_wait(1);
            let mut pending = false;
            while let Some(cqe) = self.reap() {
                let req = Request {
                    tag: cqe.result as u64,
                    data: cqe.inline,
                    reply_cap: cqe.delivered_cap,
                };
                if let Some(reply) = handler(req) {
                    let sqe = Sqe {
                        opcode: OP_REPLY,
                        flags: 0,
                        target_cap: cqe.delivered_cap,
                        user_data: reply.tag,
                        inline: reply.data,
                    };
                    // SQ full mid-batch → flush the queued replies, then retry.
                    if !self.push(sqe) {
                        self.submit();
                        let _ = self.push(sqe);
                    }
                    pending = true;
                }
            }
            if pending {
                self.submit();
            }
        }
    }
}

/// One inbound request decoded from a CQE, mirroring the legacy
/// `recv_with_cap` fields so a converted handler sees identical data.
pub struct Request {
    /// Message tag / opcode (legacy `msg.tag`).
    pub tag: u64,
    /// Payload words; `data[4]` carries the sender identity (kernel deliver
    /// mapping), matching the legacy `data[0..5]`.
    pub data: [u64; 5],
    /// One-shot reply-cap handle to answer this request (legacy `reply_cap`).
    pub reply_cap: u64,
}

/// A reply to post via `OP_REPLY`. `tag` becomes the reply message tag,
/// `data[0..5]` the reply payload.
pub struct Reply {
    pub tag: u64,
    pub data: [u64; 5],
}

/// Phase-0 self-test: SETUP → push a NOP SQE → SUBMIT → REAP → verify the CQE
/// echoes our `user_data` and payload. Returns true on success.
///
/// Consumes the caller's one-shot completion context, so only call it from a
/// task that won't otherwise use the completion ABI.
/// Tear down the current task's completion ring: clears the kernel's `io_depth`
/// so the deliver hook stops routing inbound messages into the CQ. REQUIRED for
/// any task (like init running this self-test) that opens a ring for a bounded
/// purpose and then returns to normal `recv` IPC — otherwise the hook hijacks
/// all later replies into the unreaped CQ and the task wedges.
pub fn teardown() {
    unsafe {
        arch::syscall0(SYS_IO_TEARDOWN);
    }
}

pub fn self_test() -> bool {
    let rings = match Rings::setup(8) {
        Some(r) => r,
        None => return false, // never set up → nothing to tear down
    };
    let token = 0x00C0_FFEE_u64;
    let sqe = Sqe {
        opcode: OP_NOP,
        flags: 0,
        target_cap: 0,
        user_data: token,
        inline: [1, 2, 3, 4, 5],
    };
    // Short-circuit so a failure still falls through to teardown() below.
    let ok = rings.push(sqe)
        && rings.submit() == 1
        && rings.reap_wait(1) >= 1
        && match rings.reap() {
            Some(c) => {
                c.user_data == token && c.result == 0 && c.inline[0] == 1 && c.inline[4] == 5
            }
            None => false,
        };
    // CRITICAL: drop the ring so the kernel deliver-hook stops hijacking this
    // task's normal recv IPC (init reuses recv for the ramdisk test etc.).
    teardown();
    ok
}
