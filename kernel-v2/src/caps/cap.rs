//! The capability model: identifiers, the rights lattice, capability
//! types, and capability slots.
//!
//! Iris correspondence (`docs/kernel-v2-verification-bridge.md`): `Rights`
//! is an Iris abstract type with the same subset lattice; `CapType` is a
//! disjoint sum in the spec; `CapSlot` is a record.  Validity of a slot
//! in a table is the presence of a `CapSlot` (the `Option` in
//! `CapTable`), not a stored flag.

use core::fmt;

/// Unique identifier for a task (a kernel-v2 domain/thread).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u32);

/// Unique identifier for a port (a message endpoint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortId(pub u32);

/// Access rights on a capability.
///
/// Bit flags; the subset lattice is what `grant` must respect: a grant
/// may only copy rights that are already present on the source
/// capability (no rights amplification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const GRANT: Rights = Rights(1 << 2);
    pub const SEND: Rights = Rights(1 << 3);
    pub const RECV: Rights = Rights(1 << 4);
    pub const ALL: Rights = Rights(0b11111);

    /// True iff every bit in `other` is set in `self`.
    #[inline]
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    /// True iff `self` is a subset of `rhs` — the no-amplification
    /// check used by `CapTable::grant`.
    #[inline]
    pub const fn is_subset_of(self, rhs: Rights) -> bool {
        self.0 & !rhs.0 == 0
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;

    #[inline]
    fn bitor(self, rhs: Rights) -> Rights {
        Rights(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Rights {
    #[inline]
    fn bitor_assign(&mut self, rhs: Rights) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (name, bit) in [
            ("read", Self::READ),
            ("write", Self::WRITE),
            ("grant", Self::GRANT),
            ("send", Self::SEND),
            ("recv", Self::RECV),
        ] {
            if self.contains(bit) {
                if !first {
                    f.write_str("|")?;
                }
                first = false;
                f.write_str(name)?;
            }
        }
        if first {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// The kind of object a capability refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapType {
    /// A message port (endpoint) in the transport.
    Port(PortId),
    /// A memory region.  (Later: governed by the K1 machine-interface
    /// memory resources; the transport itself does not touch it.)
    Memory { base: u64, pages: u64 },
}

/// A capability slot: the object it refers to and the rights held on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapSlot {
    pub ty: CapType,
    pub rights: Rights,
}

impl CapSlot {
    /// A port capability granting `rights` on `port`.
    #[inline]
    pub const fn port(port: PortId, rights: Rights) -> Self {
        CapSlot {
            ty: CapType::Port(port),
            rights,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_subset_lattice() {
        assert!(Rights::NONE.is_subset_of(Rights::ALL));
        assert!(Rights::SEND.is_subset_of(Rights::ALL));
        assert!(Rights::SEND.is_subset_of(Rights::SEND | Rights::RECV));
        assert!(!Rights::ALL.is_subset_of(Rights::SEND));
        assert!(!(Rights::SEND | Rights::RECV).is_subset_of(Rights::SEND));
    }

    #[test]
    fn rights_contains() {
        assert!(Rights::ALL.contains(Rights::GRANT));
        assert!((Rights::SEND | Rights::RECV).contains(Rights::SEND));
        assert!(!Rights::SEND.contains(Rights::RECV));
    }

    #[test]
    fn port_cap_constructor() {
        let c = CapSlot::port(PortId(7), Rights::SEND | Rights::RECV);
        assert_eq!(c.ty, CapType::Port(PortId(7)));
        assert!(c.rights.contains(Rights::SEND));
    }
}
