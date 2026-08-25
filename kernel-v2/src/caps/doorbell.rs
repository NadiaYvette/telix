//! Per-port inbound doorbells — the interrupt side of cross-partition
//! delivery.
//!
//! A `IntcDoorbell` is the kernel-v2 mirror of the SSG-3 interrupt
//! controller model in `tessera/hardware/src/intc.sail` (and the
//! `intc_proofs.v` theorems): a pending latch gated by a mask.  The
//! correspondence is per-theorem:
//!
//! | intc.sail / intc_proofs.v        | `IntcDoorbell`                                   |
//! |----------------------------------|--------------------------------------------------|
//! | `intc_send_sets_pending`         | `send()` latches `pending`                        |
//! | `intc_ack_unmasked_clears_pending` | `ack()` clears `pending` (and disarms) when it rings |
//! | `intc_ack_masked_noop`           | `ack()` is a no-op while `masked`                 |
//! | `intc_ack_no_pending_noop`       | `ack()` is a no-op with no pending delivery       |
//! | `intc_mask_sets_masked`          | `mask()` / `unmask()`                             |
//! | `intc_send_ack_refines_deliver_ipi` | `rings()` — pending ∧ ¬masked — is exactly the delivery condition |
//! | `intc_unmask_then_ack_delivers`  | a delivery latched while masked completes at unmask |
//!
//! The `armed` flag is the receiver's own bookkeeping: a task that
//! would block sets `arm()` so a later `ring` is recognisable as the
//! wakeup for *its* wait (in the single-threaded model this is what
//! makes `recv_blocking` able to return `Blocked` rather than spin).

/// The state of one port's inbound doorbell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntcDoorbell {
    /// A delivery has arrived and not yet been acked (latched).
    pending: bool,
    /// The receiver has masked this doorbell (e.g. inside a critical
    /// section): arrivals are latched but never ring.
    masked: bool,
    /// The receiver is (or was) blocked on this port, waiting for a ring.
    armed: bool,
}

impl IntcDoorbell {
    /// A fresh doorbell: no pending delivery, unmasked, unarmed.
    #[inline]
    pub const fn new() -> Self {
        IntcDoorbell {
            pending: false,
            masked: false,
            armed: false,
        }
    }

    /// True iff a delivery is latched and not masked.
    #[inline]
    pub const fn pending(&self) -> bool {
        self.pending
    }

    /// True iff the receiver has masked the doorbell.
    #[inline]
    pub const fn masked(&self) -> bool {
        self.masked
    }

    /// True iff a receiver is waiting on this doorbell.
    #[inline]
    pub const fn armed(&self) -> bool {
        self.armed
    }

    /// The delivery condition (`intc_send_ack_refines_deliver_ipi`):
    /// a delivery is observable iff pending and unmasked.
    #[inline]
    pub const fn rings(&self) -> bool {
        self.pending && !self.masked
    }

    /// An IPI / delivery arrives: latch `pending`
    /// (`intc_send_sets_pending`).  If the receiver is armed and
    /// unmasked, this is the wakeup; in the single-threaded model the
    /// wakeup is materialised by the receiver's next call.
    pub fn send(&mut self) {
        self.pending = true;
    }

    /// The receiver declares it is (about to be) blocked on this port.
    pub fn arm(&mut self) {
        self.armed = true;
    }

    /// The receiver is no longer waiting.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Mask the doorbell (`intc_mask_sets_masked`): arrivals are
    /// latched but do not ring.
    pub fn mask(&mut self) {
        self.masked = true;
    }

    /// Unmask the doorbell.
    pub fn unmask(&mut self) {
        self.masked = false;
    }

    /// Acknowledge the delivery (`intc_ack_unmasked_clears_pending`).
    ///
    /// - `true` iff the doorbell *rang* (pending ∧ ¬masked): the
    ///   delivery is consumed, `pending` cleared and the wait disarmed;
    /// - `false` (a no-op, `intc_ack_masked_noop` /
    ///   `intc_ack_no_pending_noop`) otherwise — state unchanged.
    pub fn ack(&mut self) -> bool {
        if self.rings() {
            self.pending = false;
            self.armed = false;
            true
        } else {
            false
        }
    }
}

impl Default for IntcDoorbell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_latches_pending() {
        let mut d = IntcDoorbell::new();
        assert!(!d.pending());
        d.send();
        assert!(d.pending());
        assert!(d.rings());
    }

    #[test]
    fn ack_unmasked_clears_pending() {
        let mut d = IntcDoorbell::new();
        d.send();
        assert!(d.ack());
        assert!(!d.pending());
        assert!(!d.rings());
    }

    #[test]
    fn ack_no_pending_noop() {
        let mut d = IntcDoorbell::new();
        assert!(!d.ack());
        assert!(!d.pending());
    }

    #[test]
    fn masked_holds_delivery() {
        let mut d = IntcDoorbell::new();
        d.mask();
        d.send(); // latched...
        assert!(d.pending());
        assert!(!d.rings()); // ...but never rings while masked
        assert!(!d.ack()); // ack while masked is a no-op
        assert!(d.pending()); // delivery still latched
        d.unmask();
        assert!(d.rings()); // intc_unmask_then_ack_delivers
        assert!(d.ack());
        assert!(!d.pending());
    }

    #[test]
    fn arm_disarm_bookkeeping() {
        let mut d = IntcDoorbell::new();
        assert!(!d.armed());
        d.arm();
        assert!(d.armed());
        d.send();
        d.ack(); // a successful ack disarms the wait
        assert!(!d.armed());
    }
}
