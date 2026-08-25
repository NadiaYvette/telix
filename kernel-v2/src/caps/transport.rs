//! The message-passing layer: tasks, ports, and the capability checks
//! that gate every send/recv/grant.
//!
//! Iris correspondence: `Transport` owns every task's `CapTable` and
//! every `Port` (exclusive resources).  `send`/`recv` have preconditions
//! of the form "the task holds a `Port(port)` capability with the
//! send/recv right", which the `wp` triples state; the kernel's
//! exclusive table ownership is what makes capability handles
//! unforgeable (`cap_unforgeable` in the spec).
//!
//! Cross-partition delivery (sender and receiver in different
//! multikernel domains) is a later milestone: `recv` may block and be
//! woken by an IPI, and that path composes with the SSG-3
//! interrupt-controller theorems (`bc_machine_ipi_step_via_intc`).

use alloc::collections::BTreeMap;

use super::cap::{CapSlot, CapType, PortId, Rights, TaskId};
use super::port::{Message, Port, RecvError, SendError};
use super::table::{CapTable, GrantError, Slot};

/// `Transport` operation failures.  Every error leaves the transport
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The task id does not name a registered task.
    UnknownTask,
    /// The port id does not name a live port.
    UnknownPort,
    /// The task holds no capability for the port.
    NoSuchCap,
    /// The task's capability lacks the required right.
    RightsViolation,
    /// The task's capability table is full.
    TableFull,
    /// A port queue is at its bound.
    QueueFull,
    /// A port queue is empty.
    QueueEmpty,
    /// A grant failed (see `GrantError`).
    Grant(GrantError),
}

/// The capability transport: tasks, per-task capability tables, ports,
/// and the message-passing operations over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport {
    next_task: u32,
    next_port: u32,
    tasks: BTreeMap<TaskId, CapTable>,
    ports: BTreeMap<PortId, Port>,
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport {
    /// An empty transport.
    pub fn new() -> Self {
        Transport {
            next_task: 0,
            next_port: 0,
            tasks: BTreeMap::new(),
            ports: BTreeMap::new(),
        }
    }

    /// Register a new task with an empty capability table of
    /// `cap_slots` slots, returning its fresh id.
    pub fn create_task(&mut self, cap_slots: usize) -> TaskId {
        let id = TaskId(self.next_task);
        self.next_task += 1;
        self.tasks.insert(id, CapTable::new(cap_slots));
        id
    }

    /// `task`'s capability table, if the task is registered.
    ///
    /// Public so higher layers (the cluster / multikernel domain) can
    /// inspect tables for partition-qualified capabilities; the kernel's
    /// exclusive ownership of tables is unaffected (read-only view).
    pub fn table(&self, task: TaskId) -> Option<&CapTable> {
        self.tasks.get(&task)
    }

    fn table_mut(&mut self, task: TaskId) -> Option<&mut CapTable> {
        self.tasks.get_mut(&task)
    }

    /// True iff `port` exists in this transport.
    pub fn has_port(&self, port: PortId) -> bool {
        self.ports.contains_key(&port)
    }

    /// Kernel-internal capability allocation: place `ty` with `rights`
    /// into `task`'s table.
    ///
    /// Used by the cluster to plant partition-qualified capabilities
    /// (`RemotePort`) across partitions.  `UnknownTask` / `TableFull`
    /// on failure; table unchanged.
    pub fn alloc_cap(
        &mut self,
        task: TaskId,
        ty: CapType,
        rights: Rights,
    ) -> Result<(), TransportError> {
        let table = self.table_mut(task).ok_or(TransportError::UnknownTask)?;
        match table.alloc_slot(ty, rights) {
            Some(_) => Ok(()),
            None => Err(TransportError::TableFull),
        }
    }

    /// Kernel-internal inbound delivery: enqueue `msg` into `port`
    /// *without* a capability check.
    ///
    /// The kernel (or a device path — NIC, another node) is the
    /// authority: this is the counterpart of `send`, which requires the
    /// sender to hold a `Port(port)` cap with `SEND`.  The bound is
    /// still enforced: a full queue refuses the message (`QueueFull`)
    /// and is unchanged — no message is ever lost or invented.
    pub fn deliver(&mut self, port: PortId, msg: Message) -> Result<(), TransportError> {
        let p = self
            .ports
            .get_mut(&port)
            .ok_or(TransportError::UnknownPort)?;
        p.send(msg).map_err(|SendError| TransportError::QueueFull)
    }

    /// Create a port owned by `task` with queue bound `bound`, and
    /// grant the owner a `Port(port)` capability with send+recv rights.
    ///
    /// Fails with `UnknownTask` (task not registered) or `TableFull`
    /// (owner's table is full) — transport unchanged.
    pub fn create_port(&mut self, task: TaskId, bound: usize) -> Result<PortId, TransportError> {
        if !self.tasks.contains_key(&task) {
            return Err(TransportError::UnknownTask);
        }
        let id = PortId(self.next_port);
        self.next_port += 1;
        self.ports.insert(id, Port::new(task, bound));
        let table = self.table_mut(task).ok_or(TransportError::UnknownTask)?;
        match table.alloc_slot(
            CapType::Port(id),
            Rights::SEND | Rights::RECV | Rights::GRANT,
        ) {
            Some(_) => Ok(id),
            None => {
                // Roll back the port we just inserted so failure leaves
                // the transport unchanged.
                self.ports.remove(&id);
                Err(TransportError::TableFull)
            }
        }
    }

    /// The capability slot in `task`'s table referring to `port`, if any.
    fn find_port_cap<'a>(table: &'a CapTable, port: PortId) -> Option<(Slot, &'a CapSlot)> {
        table.iter().find(|(_, c)| c.ty == CapType::Port(port))
    }

    /// Grant a copy of the `Port(port)` capability from `from` to `to`
    /// with `rights` (a subset of the source's rights).
    ///
    /// Preconditions: both tasks exist; `from` holds a `Port(port)` cap
    /// with the `GRANT` right; `rights ⊆` its rights; `to` has a free
    /// slot.  Any failure leaves the transport unchanged.
    pub fn grant_port(
        &mut self,
        from: TaskId,
        to: TaskId,
        port: PortId,
        rights: Rights,
    ) -> Result<(), TransportError> {
        if !self.ports.contains_key(&port) {
            return Err(TransportError::UnknownPort);
        }
        // Source-capability checks (the immutable borrow of `from`'s
        // table ends here, before we take a mutable borrow for `to`).
        let (grant_ok, rights_ok) = {
            let t = self.table(from).ok_or(TransportError::UnknownTask)?;
            let (_, src) = Self::find_port_cap(t, port).ok_or(TransportError::NoSuchCap)?;
            (
                src.rights.contains(Rights::GRANT),
                rights.is_subset_of(src.rights),
            )
        };
        if !grant_ok {
            return Err(TransportError::RightsViolation);
        }
        if !rights_ok {
            return Err(TransportError::Grant(GrantError::RightsAmplification));
        }
        let table = self.table_mut(to).ok_or(TransportError::UnknownTask)?;
        match table.alloc_slot(CapType::Port(port), rights) {
            Some(_) => Ok(()),
            None => Err(TransportError::TableFull),
        }
    }

    /// Send `msg` from `task` on `port`.
    ///
    /// Preconditions: `task` holds a `Port(port)` cap with `SEND`; the
    /// port's queue is below its bound.  The message's ownership moves
    /// into the queue.  Failures leave the transport unchanged (in
    /// particular, a full queue means the message is not accepted).
    pub fn send(&mut self, task: TaskId, port: PortId, msg: Message) -> Result<(), TransportError> {
        let has_send = {
            let t = self.table(task).ok_or(TransportError::UnknownTask)?;
            let (_, cap) = Self::find_port_cap(t, port).ok_or(TransportError::NoSuchCap)?;
            cap.rights.contains(Rights::SEND)
        };
        if !has_send {
            return Err(TransportError::RightsViolation);
        }
        let p = self
            .ports
            .get_mut(&port)
            .ok_or(TransportError::UnknownPort)?;
        p.send(msg).map_err(|SendError| TransportError::QueueFull)
    }

    /// Receive the head of `port`'s queue on behalf of `task`.
    ///
    /// Preconditions: `task` holds a `Port(port)` cap with `RECV`.
    /// Ownership of the message moves queue → caller.  An empty queue
    /// is an error and leaves the transport unchanged.
    pub fn recv(&mut self, task: TaskId, port: PortId) -> Result<Message, TransportError> {
        let has_recv = {
            let t = self.table(task).ok_or(TransportError::UnknownTask)?;
            let (_, cap) = Self::find_port_cap(t, port).ok_or(TransportError::NoSuchCap)?;
            cap.rights.contains(Rights::RECV)
        };
        if !has_recv {
            return Err(TransportError::RightsViolation);
        }
        let p = self
            .ports
            .get_mut(&port)
            .ok_or(TransportError::UnknownPort)?;
        p.recv().map_err(|RecvError| TransportError::QueueEmpty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(t: TaskId, b: u8) -> Message {
        Message::new(t, alloc::vec![b])
    }

    #[test]
    fn create_task_and_port() {
        let mut tr = Transport::new();
        let t = tr.create_task(8);
        let p = tr.create_port(t, 4).unwrap();
        assert!(tr.ports.contains_key(&p));
        // The owner holds a port cap with send+recv+grant.
        let table = tr.table(t).unwrap();
        assert!(table.iter().any(|(_, c)| c.ty == CapType::Port(p)));
    }

    #[test]
    fn create_port_unknown_task_fails() {
        let mut tr = Transport::new();
        assert_eq!(
            tr.create_port(TaskId(99), 4),
            Err(TransportError::UnknownTask)
        );
    }

    #[test]
    fn send_recv_roundtrip_through_owner_cap() {
        let mut tr = Transport::new();
        let a = tr.create_task(8);
        let p = tr.create_port(a, 4).unwrap();
        tr.send(a, p, msg(a, 7)).unwrap();
        let got = tr.recv(a, p).unwrap();
        assert_eq!(got.payload, alloc::vec![7]);
        assert_eq!(got.from, a);
    }

    #[test]
    fn cap_unforgeable_no_cap_no_send() {
        let mut tr = Transport::new();
        let a = tr.create_task(8);
        let b = tr.create_task(8); // never granted anything
        let p = tr.create_port(a, 4).unwrap();
        let before = tr.clone();
        assert_eq!(tr.send(b, p, msg(b, 1)), Err(TransportError::NoSuchCap));
        assert_eq!(tr.recv(b, p), Err(TransportError::NoSuchCap));
        assert_eq!(tr, before);
    }

    #[test]
    fn rights_violation_send_without_send_right() {
        let mut tr = Transport::new();
        let a = tr.create_task(8);
        let b = tr.create_task(8);
        let p = tr.create_port(a, 4).unwrap();
        // Grant b only RECV.
        tr.grant_port(a, b, p, Rights::RECV).unwrap();
        let before = tr.clone();
        assert_eq!(
            tr.send(b, p, msg(b, 1)),
            Err(TransportError::RightsViolation)
        );
        assert_eq!(tr, before);
    }

    #[test]
    fn grant_port_transfers_and_respects_rights() {
        let mut tr = Transport::new();
        let a = tr.create_task(8);
        let b = tr.create_task(8);
        let p = tr.create_port(a, 4).unwrap();
        // b can send once granted SEND (but not before).
        assert_eq!(tr.send(b, p, msg(b, 1)), Err(TransportError::NoSuchCap));
        tr.grant_port(a, b, p, Rights::SEND).unwrap();
        tr.send(b, p, msg(b, 2)).unwrap();
        assert_eq!(tr.recv(a, p).unwrap().payload, alloc::vec![2]);
        // Amplification attempt fails, transport unchanged.
        let before = tr.clone();
        assert_eq!(
            tr.grant_port(a, b, p, Rights::ALL),
            Err(TransportError::Grant(GrantError::RightsAmplification))
        );
        assert_eq!(tr, before);
    }

    #[test]
    fn bounded_queue_overflow_fails_cleanly() {
        let mut tr = Transport::new();
        let a = tr.create_task(8);
        let p = tr.create_port(a, 2).unwrap();
        tr.send(a, p, msg(a, 1)).unwrap();
        tr.send(a, p, msg(a, 2)).unwrap();
        let before = tr.clone();
        assert_eq!(tr.send(a, p, msg(a, 3)), Err(TransportError::QueueFull));
        assert_eq!(tr, before);
        // FIFO still intact.
        assert_eq!(tr.recv(a, p).unwrap().payload, alloc::vec![1]);
        assert_eq!(tr.recv(a, p).unwrap().payload, alloc::vec![2]);
    }

    #[test]
    fn recv_empty_fails_cleanly() {
        let mut tr = Transport::new();
        let a = tr.create_task(8);
        let p = tr.create_port(a, 2).unwrap();
        let before = tr.clone();
        assert_eq!(tr.recv(a, p), Err(TransportError::QueueEmpty));
        assert_eq!(tr, before);
    }

    #[test]
    fn grant_to_full_table_fails_and_rolls_back() {
        let mut tr = Transport::new();
        let a = tr.create_task(2);
        let b = tr.create_task(2);
        let p = tr.create_port(a, 4).unwrap();
        // Fill b's table with two dummy caps so the grant has no free slot.
        let tb = tr.tasks.get_mut(&b).unwrap();
        tb.alloc_slot(CapType::Memory { base: 0, pages: 1 }, Rights::NONE);
        tb.alloc_slot(CapType::Memory { base: 1, pages: 1 }, Rights::NONE);
        let before = tr.clone();
        assert_eq!(
            tr.grant_port(a, b, p, Rights::SEND),
            Err(TransportError::TableFull)
        );
        assert_eq!(tr, before);
    }
}
