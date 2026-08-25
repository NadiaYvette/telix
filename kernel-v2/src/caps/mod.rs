//! Capability transport — Phase K1.5 of the kernel-v2 build-up.
//!
//! The microkernel IPC core: capability tables, ports (bounded message
//! queues), and the message-passing layer over them.  The un-forgeability
//! story is the seL4 model: a capability handle is a `(TaskId, Slot)` pair
//! into a table that only the kernel mutates, so a task can only act on
//! capabilities the kernel granted it.
//!
//! Correspondence to the Iris heap_lang spec and the Tessera hardware
//! models is itemised in `docs/kernel-v2-verification-bridge.md`.

pub mod cap;
pub mod cluster;
pub mod doorbell;
pub mod port;
pub mod table;
pub mod transport;

pub use cap::{CapSlot, CapType, PartitionId, PortId, Rights, TaskId};
pub use cluster::{Cluster, ClusterError};
pub use doorbell::IntcDoorbell;
pub use port::{Message, Port, RecvError, SendError};
pub use table::{CapTable, GrantError, Slot};
pub use transport::{Transport, TransportError};
