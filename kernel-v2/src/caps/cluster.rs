//! The multikernel cluster: multiple partitions, each owning a local
//! `Transport` and per-port inbound doorbells.
//!
//! This is the kernel-v2 rendering of the whitepaper's multikernel
//! domains (SSG-1 topology scoping) composed with the SSG-3 interrupt
//! controller: a cross-partition send enqueues into the destination
//! partition's transport (`deliver_inbound`) and rings the target
//! port's doorbell, which is what wakes a blocked receiver.
//!
//! Capability story: ports are local to their partition; a task in
//! another partition addresses one via a `CapType::RemotePort(part,
//! port)` capability (granted by `grant_port_remote`), so the
//! un-forgeability invariant extends across the cluster — a sender can
//! only reach a remote port the kernel granted it a capability for.
//!
//! Iris correspondence: each partition's transport + doorbells are
//! exclusive resources of that partition's kernel instance; the IPI
//! ring is the `bc_machine_ipi_step_via_intc` ghost step from
//! `tessera/hardware/rocq/intc_weak_broadcast.v` — delivery precedes
//! the ack that completes the receive.

use alloc::collections::BTreeMap;

use super::cap::{CapType, PartitionId, PortId, Rights, TaskId};
use super::doorbell::IntcDoorbell;
use super::port::Message;
use super::table::GrantError;
use super::transport::{Transport, TransportError};

/// `Cluster` operation failures.  Every error leaves the cluster
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterError {
    /// The partition id does not name a live partition.
    UnknownPartition,
    /// The task id does not name a registered task in its partition.
    UnknownTask,
    /// The port id does not name a live port in its partition.
    UnknownPort,
    /// The task holds no capability for the port.
    NoSuchCap,
    /// The task's capability lacks the required right.
    RightsViolation,
    /// A table is full.
    TableFull,
    /// A port queue is at its bound (no message lost — sender keeps it).
    QueueFull,
    /// A port queue is empty.
    QueueEmpty,
    /// `recv_blocking` found an empty queue: the receiver is now armed
    /// and will be woken by the next delivery's doorbell ring.
    Blocked,
    /// `recv_blocking` was attempted while the doorbell is masked: a
    /// masked task does not block on interrupts.
    Masked,
    /// A cross-partition operation was given the same partition twice;
    /// local operations belong on the partition's `Transport`.
    SamePartition,
    /// A grant failed (see `GrantError`).
    Grant(GrantError),
}

impl From<TransportError> for ClusterError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::UnknownTask => ClusterError::UnknownTask,
            TransportError::UnknownPort => ClusterError::UnknownPort,
            TransportError::NoSuchCap => ClusterError::NoSuchCap,
            TransportError::RightsViolation => ClusterError::RightsViolation,
            TransportError::TableFull => ClusterError::TableFull,
            TransportError::QueueFull => ClusterError::QueueFull,
            TransportError::QueueEmpty => ClusterError::QueueEmpty,
            TransportError::Grant(ge) => ClusterError::Grant(ge),
        }
    }
}

/// One partition of the cluster: a local transport and the inbound
/// doorbell of every port in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    transport: Transport,
    doorbells: BTreeMap<PortId, IntcDoorbell>,
}

/// The cluster: a set of multikernel partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    next_partition: u32,
    partitions: BTreeMap<PartitionId, Partition>,
}

impl Default for Cluster {
    fn default() -> Self {
        Self::new()
    }
}

impl Cluster {
    /// An empty cluster.
    pub fn new() -> Self {
        Cluster {
            next_partition: 0,
            partitions: BTreeMap::new(),
        }
    }

    fn partition(&self, part: PartitionId) -> Result<&Partition, ClusterError> {
        self.partitions
            .get(&part)
            .ok_or(ClusterError::UnknownPartition)
    }

    fn partition_mut(&mut self, part: PartitionId) -> Result<&mut Partition, ClusterError> {
        self.partitions
            .get_mut(&part)
            .ok_or(ClusterError::UnknownPartition)
    }

    fn doorbell(&self, part: PartitionId, port: PortId) -> Result<&IntcDoorbell, ClusterError> {
        self.partition(part)?
            .doorbells
            .get(&port)
            .ok_or(ClusterError::UnknownPort)
    }

    fn doorbell_mut(
        &mut self,
        part: PartitionId,
        port: PortId,
    ) -> Result<&mut IntcDoorbell, ClusterError> {
        self.partition_mut(part)?
            .doorbells
            .get_mut(&port)
            .ok_or(ClusterError::UnknownPort)
    }

    /// Find the capability in `task`'s table (in partition `part`)
    /// referring to `ty`, if any.
    fn find_cap(
        &self,
        part: PartitionId,
        task: TaskId,
        ty: CapType,
    ) -> Result<Option<Rights>, ClusterError> {
        let p = self.partition(part)?;
        let t = p.transport.table(task).ok_or(ClusterError::UnknownTask)?;
        Ok(t.iter().find(|(_, c)| c.ty == ty).map(|(_, c)| c.rights))
    }

    /// Create a new partition, returning its fresh id.
    pub fn create_partition(&mut self, cap_slots: usize) -> PartitionId {
        let id = PartitionId(self.next_partition);
        self.next_partition += 1;
        self.partitions.insert(
            id,
            Partition {
                transport: Transport::new(),
                doorbells: BTreeMap::new(),
            },
        );
        id
    }

    /// Register a task in `part` with an empty capability table of
    /// `cap_slots` slots.
    pub fn create_task(
        &mut self,
        part: PartitionId,
        cap_slots: usize,
    ) -> Result<TaskId, ClusterError> {
        let p = self.partition_mut(part)?;
        Ok(p.transport.create_task(cap_slots))
    }

    /// Create a port owned by `task` in `part`, granting the owner the
    /// local `Port(port)` capability, and install the port's inbound
    /// doorbell.
    pub fn create_port(
        &mut self,
        part: PartitionId,
        task: TaskId,
        bound: usize,
    ) -> Result<PortId, ClusterError> {
        let p = self.partition_mut(part)?;
        let port = p.transport.create_port(task, bound)?;
        p.doorbells.insert(port, IntcDoorbell::new());
        Ok(port)
    }

    /// Same-partition grant: delegate to the partition's transport.
    pub fn grant_port(
        &mut self,
        part: PartitionId,
        from: TaskId,
        to: TaskId,
        port: PortId,
        rights: Rights,
    ) -> Result<(), ClusterError> {
        let p = self.partition_mut(part)?;
        p.transport.grant_port(from, to, port, rights)?;
        Ok(())
    }

    /// Cross-partition grant: copy the capability for port `port`
    /// (owned in `from_p`) into `to_t`'s table in `to_p` as a
    /// `RemotePort(from_p, port)` capability with `rights` (a subset of
    /// the source's rights).
    ///
    /// Preconditions: `from_p ≠ to_p`; `from_t` (in `from_p`) holds a
    /// `Port(port)` cap with the `GRANT` right; `rights ⊆` its rights;
    /// `to_t` has a free slot.  Failure leaves the cluster unchanged.
    pub fn grant_port_remote(
        &mut self,
        from_p: PartitionId,
        from_t: TaskId,
        to_p: PartitionId,
        to_t: TaskId,
        port: PortId,
        rights: Rights,
    ) -> Result<(), ClusterError> {
        if from_p == to_p {
            return Err(ClusterError::SamePartition);
        }
        // Source-capability checks in `from_p` (read-only borrow ends
        // before the mutable borrow of `to_p`).
        let (grant_ok, rights_ok) = {
            let src = self
                .find_cap(from_p, from_t, CapType::Port(port))?
                .ok_or(ClusterError::NoSuchCap)?;
            (src.contains(Rights::GRANT), rights.is_subset_of(src))
        };
        if !grant_ok {
            return Err(ClusterError::RightsViolation);
        }
        if !rights_ok {
            return Err(ClusterError::Grant(GrantError::RightsAmplification));
        }
        // The port must actually live in `from_p`.
        if !self.partition(from_p)?.transport.has_port(port) {
            return Err(ClusterError::UnknownPort);
        }
        let to = self.partition_mut(to_p)?;
        to.transport
            .alloc_cap(to_t, CapType::RemotePort(from_p, port), rights)?;
        Ok(())
    }

    /// Local send: delegate to the partition's transport.
    pub fn send(
        &mut self,
        part: PartitionId,
        task: TaskId,
        port: PortId,
        msg: Message,
    ) -> Result<(), ClusterError> {
        let p = self.partition_mut(part)?;
        p.transport.send(task, port, msg)?;
        Ok(())
    }

    /// Cross-partition send: `task` (in `from_p`) sends `msg` to `port`
    /// in `to_p` through its `RemotePort(to_p, port)` capability.
    ///
    /// On success the message is enqueued in `to_p`'s transport and the
    /// port's doorbell rings (waking a blocked receiver).  On `QueueFull`
    /// nothing is delivered and the doorbell is untouched — the sender
    /// keeps the message (no message is ever lost).
    pub fn send_remote(
        &mut self,
        from_p: PartitionId,
        from_t: TaskId,
        to_p: PartitionId,
        port: PortId,
        msg: Message,
    ) -> Result<(), ClusterError> {
        if from_p == to_p {
            return Err(ClusterError::SamePartition);
        }
        let rights = self
            .find_cap(from_p, from_t, CapType::RemotePort(to_p, port))?
            .ok_or(ClusterError::NoSuchCap)?;
        if !rights.contains(Rights::SEND) {
            return Err(ClusterError::RightsViolation);
        }
        self.deliver_inbound(to_p, port, msg)
    }

    /// Kernel-internal inbound delivery: enqueue `msg` into `port` in
    /// `part` and ring the port's doorbell (the wakeup path).
    ///
    /// This is the shared primitive behind `send_remote` and the
    /// device-inbound path (NIC / other node).  The enqueue honours the
    /// port bound; only a successful enqueue rings the doorbell.
    pub fn deliver_inbound(
        &mut self,
        part: PartitionId,
        port: PortId,
        msg: Message,
    ) -> Result<(), ClusterError> {
        let p = self.partition_mut(part)?;
        p.transport.deliver(port, msg)?;
        let db = p
            .doorbells
            .get_mut(&port)
            .ok_or(ClusterError::UnknownPort)?;
        db.send();
        Ok(())
    }

    /// Non-blocking receive: `task` (in `part`) takes the head of
    /// `port`'s queue, consuming the pending delivery's ack.
    ///
    /// `poll` is the explicit mailbox read and is allowed while the
    /// doorbell is masked (a masked task may still drain its queue).
    pub fn poll(
        &mut self,
        part: PartitionId,
        task: TaskId,
        port: PortId,
    ) -> Result<Message, ClusterError> {
        let p = self.partition_mut(part)?;
        let msg = p.transport.recv(task, port)?;
        if let Some(db) = p.doorbells.get_mut(&port) {
            db.ack(); // the delivery this receive consumed is done
        }
        Ok(msg)
    }

    /// Blocking receive: like `poll`, but if the queue is empty the
    /// receiver arms the doorbell and waits for the IPI wakeup.
    ///
    /// In the single-threaded model the wait cannot actually suspend,
    /// so the honest contract is: `Err(Blocked)` means the receiver is
    /// *armed* — the next successful `deliver_inbound` on this port is
    /// its wakeup, after which a subsequent `poll` / `recv_blocking`
    /// succeeds.  A masked doorbell never rings, so a masked task
    /// returns `Err(Masked)` instead of waiting forever.
    pub fn recv_blocking(
        &mut self,
        part: PartitionId,
        task: TaskId,
        port: PortId,
    ) -> Result<Message, ClusterError> {
        let p = self.partition_mut(part)?;
        let db = p
            .doorbells
            .get_mut(&port)
            .ok_or(ClusterError::UnknownPort)?;
        if db.masked() {
            return Err(ClusterError::Masked);
        }
        // Fast path: a message is already queued.
        if let Ok(m) = p.transport.recv(task, port) {
            db.ack();
            return Ok(m);
        }
        // The queue is empty: arm, then honour a delivery that raced in
        // between (in the sequential model this is unreachable — a
        // delivery always enqueues before ringing — but it is the
        // contract the concurrent refinement must keep).
        db.arm();
        if db.rings() {
            db.ack();
            if let Ok(m) = p.transport.recv(task, port) {
                return Ok(m);
            }
        }
        Err(ClusterError::Blocked)
    }

    /// Acknowledge `port`'s doorbell in `part` without receiving
    /// (`intc_ack_unmasked_clears_pending`).  Returns `false` when
    /// there was nothing to ack (masked or no pending delivery).
    pub fn ack_doorbell(&mut self, part: PartitionId, port: PortId) -> Result<bool, ClusterError> {
        Ok(self.doorbell_mut(part, port)?.ack())
    }

    /// Mask `port`'s doorbell in `part` (`intc_mask_sets_masked`):
    /// arrivals latch but never ring.
    pub fn mask_doorbell(&mut self, part: PartitionId, port: PortId) -> Result<(), ClusterError> {
        self.doorbell_mut(part, port)?.mask();
        Ok(())
    }

    /// Unmask `port`'s doorbell in `part`.
    pub fn unmask_doorbell(&mut self, part: PartitionId, port: PortId) -> Result<(), ClusterError> {
        self.doorbell_mut(part, port)?.unmask();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(t: TaskId, b: u8) -> Message {
        Message::new(t, alloc::vec![b])
    }

    /// Two partitions, each with one task; `a` owns `p` in part 0 and
    /// grants `b` in part 1 a remote SEND capability for it.
    fn two_partition_setup() -> (Cluster, PartitionId, PartitionId, TaskId, TaskId, PortId) {
        let mut c = Cluster::new();
        let pa = c.create_partition(8);
        let pb = c.create_partition(8);
        let a = c.create_task(pa, 8).unwrap();
        let b = c.create_task(pb, 8).unwrap();
        let p = c.create_port(pa, a, 4).unwrap();
        c.grant_port_remote(pa, a, pb, b, p, Rights::SEND).unwrap();
        (c, pa, pb, a, b, p)
    }

    #[test]
    fn cross_partition_send_poll_roundtrip() {
        let (mut c, pa, pb, a, b, p) = two_partition_setup();
        // b sends into a's port through the remote cap...
        c.send_remote(pb, b, pa, p, msg(b, 7)).unwrap();
        // ...a receives it locally.
        let got = c.poll(pa, a, p).unwrap();
        assert_eq!(got.payload, alloc::vec![7]);
        assert_eq!(got.from, b);
        // The delivery was acked by the receive.
        assert!(!c.doorbell(pa, p).unwrap().pending());
    }

    #[test]
    fn send_remote_requires_remote_cap() {
        let (mut c, pa, pb, _a, _b, p) = two_partition_setup();
        // a never granted b a cap for port p — build a fresh task c2.
        let c2 = c.create_task(pb, 8).unwrap();
        let before = c.clone();
        assert_eq!(
            c.send_remote(pb, c2, pa, p, msg(c2, 1)),
            Err(ClusterError::NoSuchCap)
        );
        assert_eq!(c, before);
    }

    #[test]
    fn remote_send_rights_violation() {
        let (mut c, pa, pb, a, _b, p) = two_partition_setup();
        let _ = a;
        // Grant only RECV — no SEND — to a fresh task.
        let c2 = c.create_task(pb, 8).unwrap();
        c.grant_port_remote(pa, a, pb, c2, p, Rights::RECV).unwrap();
        let before = c.clone();
        assert_eq!(
            c.send_remote(pb, c2, pa, p, msg(c2, 1)),
            Err(ClusterError::RightsViolation)
        );
        assert_eq!(c, before);
    }

    #[test]
    fn remote_grant_no_amplification() {
        let mut c = Cluster::new();
        let pa = c.create_partition(8);
        let pb = c.create_partition(8);
        let a = c.create_task(pa, 8).unwrap();
        let b = c.create_task(pb, 8).unwrap();
        let p = c.create_port(pa, a, 4).unwrap();
        // a's cap is SEND-only: cannot grant ALL remotely.
        let before = c.clone();
        assert_eq!(
            c.grant_port_remote(pa, a, pb, b, p, Rights::ALL),
            Err(ClusterError::Grant(GrantError::RightsAmplification))
        );
        assert_eq!(c, before);
        // SEND-only grant works and enables the remote send.
        c.grant_port_remote(pa, a, pb, b, p, Rights::SEND).unwrap();
        c.send_remote(pb, b, pa, p, msg(b, 3)).unwrap();
        assert_eq!(c.poll(pa, a, p).unwrap().payload, alloc::vec![3]);
    }

    #[test]
    fn recv_blocking_blocks_then_delivery_wakes() {
        let (mut c, pa, pb, a, b, p) = two_partition_setup();
        // a blocks on the empty port.
        assert_eq!(c.recv_blocking(pa, a, p), Err(ClusterError::Blocked));
        assert!(c.doorbell(pa, p).unwrap().armed());
        // b's cross-partition send delivers + rings → a's wakeup.
        c.send_remote(pb, b, pa, p, msg(b, 42)).unwrap();
        assert!(c.doorbell(pa, p).unwrap().rings());
        // a retries and gets the message.
        let got = c.recv_blocking(pa, a, p).unwrap();
        assert_eq!(got.payload, alloc::vec![42]);
        assert!(!c.doorbell(pa, p).unwrap().pending());
    }

    #[test]
    fn full_queue_refuses_delivery_no_ring_no_loss() {
        let (mut c, pa, pb, a, b, _p) = two_partition_setup();
        // bound 4 → fill to the bound with three more... actually the
        // setup bound is 4; use a dedicated bound-1 port instead.
        let p1 = c.create_port(pa, a, 1).unwrap();
        c.grant_port_remote(pa, a, pb, b, p1, Rights::SEND).unwrap();
        c.send_remote(pb, b, pa, p1, msg(b, 1)).unwrap();
        // Full: second delivery is refused, nothing rings, sender keeps it.
        let before = c.clone();
        assert_eq!(
            c.send_remote(pb, b, pa, p1, msg(b, 2)),
            Err(ClusterError::QueueFull)
        );
        assert_eq!(c, before);
        // Exactly one message arrived.
        assert_eq!(c.poll(pa, a, p1).unwrap().payload, alloc::vec![1]);
        assert_eq!(c.poll(pa, a, p1), Err(ClusterError::QueueEmpty));
    }

    #[test]
    fn masked_holds_delivery_then_unmask_recvs() {
        let (mut c, pa, pb, a, b, p) = two_partition_setup();
        c.mask_doorbell(pa, p).unwrap();
        // Delivery is latched but never rings.
        c.send_remote(pb, b, pa, p, msg(b, 9)).unwrap();
        assert!(c.doorbell(pa, p).unwrap().pending());
        assert!(!c.doorbell(pa, p).unwrap().rings());
        // A masked task does not block; it drains explicitly instead.
        assert_eq!(c.recv_blocking(pa, a, p), Err(ClusterError::Masked));
        assert_eq!(c.poll(pa, a, p).unwrap().payload, alloc::vec![9]);
        // The ack inside poll was a no-op while masked
        // (`intc_ack_masked_noop`) — the delivery is still latched.
        assert!(c.doorbell(pa, p).unwrap().pending());
        // Unmask: the latched delivery is now observable
        // (`intc_unmask_then_ack_delivers`), and the ack completes it.
        c.unmask_doorbell(pa, p).unwrap();
        assert!(c.doorbell(pa, p).unwrap().rings());
        assert!(c.ack_doorbell(pa, p).unwrap());
        assert!(!c.doorbell(pa, p).unwrap().pending());
    }

    #[test]
    fn local_send_does_not_ring_cross_partition() {
        // A same-partition send never touches the doorbell machinery.
        let mut c = Cluster::new();
        let pa = c.create_partition(8);
        let a = c.create_task(pa, 8).unwrap();
        let p = c.create_port(pa, a, 4).unwrap();
        assert!(!c.doorbell(pa, p).unwrap().pending());
        c.send(pa, a, p, msg(a, 5)).unwrap();
        // poll acks a doorbell that never rang: harmless no-op, and the
        // message still arrives.
        assert_eq!(c.poll(pa, a, p).unwrap().payload, alloc::vec![5]);
    }

    #[test]
    fn same_partition_remote_ops_rejected() {
        let (mut c, pa, pb, a, b, p) = two_partition_setup();
        assert_eq!(
            c.send_remote(pa, a, pa, p, msg(a, 1)),
            Err(ClusterError::SamePartition)
        );
        assert_eq!(
            c.grant_port_remote(pa, a, pa, a, p, Rights::SEND),
            Err(ClusterError::SamePartition)
        );
    }

    #[test]
    fn ack_no_pending_noop() {
        let (mut c, pa, _pb, _a, _b, p) = two_partition_setup();
        assert!(!c.ack_doorbell(pa, p).unwrap());
        assert_eq!(c.mask_doorbell(pa, p), Ok(()));
        assert!(!c.ack_doorbell(pa, p).unwrap()); // masked → no-op
        c.unmask_doorbell(pa, p).unwrap();
    }
}
