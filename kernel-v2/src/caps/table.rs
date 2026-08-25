//! Per-task capability tables.
//!
//! The kernel holds the *exclusive* ownership of every task's capability
//! table (in Iris terms, a K1 resource); a task can only exercise the
//! capabilities the kernel granted it — that is the un-forgeability
//! story, and it needs no cryptography.
//!
//! `Slot` is a table index; `CapTable` is a fixed-capacity `Vec<Option<
//! CapSlot>>` where a slot's validity is the presence of a value.
//! All operations are total: failures return an error and leave the
//! table unchanged.

use alloc::vec::Vec;

use super::cap::{CapSlot, CapType, Rights};

/// A capability slot: an index into a `CapTable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Slot(pub usize);

/// `CapTable::grant` failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// The source slot is empty (or out of range).
    BadSource,
    /// The destination slot is out of range.
    BadDest,
    /// The destination slot is already occupied.
    DestOccupied,
    /// The requested rights are not a subset of the source's rights
    /// (rights amplification is impossible by construction).
    RightsAmplification,
}

/// A task's capability table: a fixed set of slots, each either empty
/// or holding one capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapTable {
    slots: Vec<Option<CapSlot>>,
    /// Rotating search hint so `alloc_slot` does not always start at 0.
    next_hint: usize,
}

impl CapTable {
    /// An empty table with `capacity` slots.
    pub fn new(capacity: usize) -> Self {
        CapTable {
            slots: alloc::vec![None; capacity],
            next_hint: 0,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// The capability in `s`, if any.
    #[inline]
    pub fn get(&self, s: Slot) -> Option<&CapSlot> {
        self.slots.get(s.0).and_then(|o| o.as_ref())
    }

    /// Iterate over the occupied slots.
    pub fn iter(&self) -> impl Iterator<Item = (Slot, &CapSlot)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, o)| o.as_ref().map(|c| (Slot(i), c)))
    }

    /// Find the first slot holding a capability of type `ty`, if any.
    pub fn find(&self, ty: CapType) -> Option<Slot> {
        self.slots
            .iter()
            .position(|o| matches!(o, Some(c) if c.ty == ty))
            .map(Slot)
    }

    /// Allocate a fresh slot holding `ty` with `rights`.
    ///
    /// - `Some(Slot)` on success (the slot was empty, now occupied);
    /// - `None` if the table is full — table unchanged.
    pub fn alloc_slot(&mut self, ty: CapType, rights: Rights) -> Option<Slot> {
        let n = self.slots.len();
        for i in 0..n {
            let idx = (self.next_hint + i) % n;
            if self.slots[idx].is_none() {
                self.slots[idx] = Some(CapSlot { ty, rights });
                self.next_hint = (idx + 1) % n;
                return Some(Slot(idx));
            }
        }
        None
    }

    /// Free the slot `s`: invalidate it and return the capability that
    /// was held.
    ///
    /// - `Some(CapSlot)` if `s` was occupied (now empty);
    /// - `None` if `s` was empty or out of range.
    pub fn free_slot(&mut self, s: Slot) -> Option<CapSlot> {
        let cell = self.slots.get_mut(s.0)?;
        cell.take()
    }

    /// Copy a capability from `from` to `to` with (a subset of) the
    /// source's rights — a seL4-style grant.
    ///
    /// Failures (all leave the table unchanged):
    /// - `BadSource` — source empty/out of range;
    /// - `BadDest` / `DestOccupied` — destination not free;
    /// - `RightsAmplification` — `rights` not ⊆ source rights.
    pub fn grant(&mut self, from: Slot, to: Slot, rights: Rights) -> Result<(), GrantError> {
        let src = self
            .slots
            .get(from.0)
            .and_then(|o| *o)
            .ok_or(GrantError::BadSource)?;
        if !rights.is_subset_of(src.rights) {
            return Err(GrantError::RightsAmplification);
        }
        let dest = self.slots.get_mut(to.0).ok_or(GrantError::BadDest)?;
        if dest.is_some() {
            return Err(GrantError::DestOccupied);
        }
        *dest = Some(CapSlot { ty: src.ty, rights });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::cap::PortId;

    fn port(port: u32) -> CapType {
        CapType::Port(PortId(port))
    }

    #[test]
    fn alloc_gives_unique_valid_slots() {
        let mut t = CapTable::new(4);
        let a = t.alloc_slot(port(1), Rights::SEND).unwrap();
        let b = t.alloc_slot(port(2), Rights::RECV).unwrap();
        let c = t.alloc_slot(port(3), Rights::ALL).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(t.get(a).unwrap().ty, port(1));
        assert_eq!(t.get(b).unwrap().rights, Rights::RECV);
    }

    #[test]
    fn alloc_full_table_returns_none() {
        let mut t = CapTable::new(2);
        assert!(t.alloc_slot(port(1), Rights::NONE).is_some());
        assert!(t.alloc_slot(port(2), Rights::NONE).is_some());
        let before = t.clone();
        assert_eq!(t.alloc_slot(port(3), Rights::NONE), None);
        assert_eq!(t, before);
    }

    #[test]
    fn free_invalidates_and_reuses() {
        let mut t = CapTable::new(4);
        let a = t.alloc_slot(port(1), Rights::SEND).unwrap();
        let freed = t.free_slot(a).unwrap();
        assert_eq!(freed.ty, port(1));
        assert_eq!(t.get(a), None);
        // The slot is reusable (the allocator scans from a rotating
        // hint, so the exact slot index is not specified — only that
        // a valid slot comes back and the freed one is no longer it).
        let b = t.alloc_slot(port(9), Rights::RECV).unwrap();
        assert_ne!(t.get(b), None);
        assert_eq!(t.get(b).unwrap().ty, port(9));
        // Freeing a again is not possible: it was already invalidated.
        assert_eq!(t.free_slot(a), None);
    }

    #[test]
    fn free_empty_or_oob_is_none() {
        let mut t = CapTable::new(2);
        assert_eq!(t.free_slot(Slot(0)), None);
        assert_eq!(t.free_slot(Slot(99)), None);
    }

    #[test]
    fn grant_copies_subset_rights() {
        let mut t = CapTable::new(3);
        let src = t.alloc_slot(port(7), Rights::ALL).unwrap();
        let dst = t.alloc_slot(port(0), Rights::NONE).unwrap();
        // Overwrite the dst placeholder with an empty slot via free.
        t.free_slot(dst);
        t.grant(src, dst, Rights::SEND | Rights::RECV).unwrap();
        assert_eq!(t.get(dst).unwrap().ty, port(7));
        assert_eq!(t.get(dst).unwrap().rights, Rights::SEND | Rights::RECV);
        // Source untouched.
        assert_eq!(t.get(src).unwrap().rights, Rights::ALL);
    }

    #[test]
    fn grant_no_rights_amplification() {
        let mut t = CapTable::new(3);
        let src = t.alloc_slot(port(7), Rights::SEND).unwrap();
        let dst = t.alloc_slot(port(0), Rights::NONE).unwrap();
        t.free_slot(dst);
        let before = t.clone();
        assert_eq!(
            t.grant(src, dst, Rights::ALL),
            Err(GrantError::RightsAmplification)
        );
        assert_eq!(t, before);
        assert_eq!(t.get(dst), None);
    }

    #[test]
    fn grant_failures_leave_table_unchanged() {
        let mut t = CapTable::new(3);
        let src = t.alloc_slot(port(7), Rights::ALL).unwrap();
        let dst = t.alloc_slot(port(0), Rights::NONE).unwrap();
        // Destination occupied.
        let before = t.clone();
        assert_eq!(
            t.grant(src, dst, Rights::SEND),
            Err(GrantError::DestOccupied)
        );
        assert_eq!(t, before);
        // Bad source.
        t.free_slot(src);
        assert_eq!(
            t.grant(Slot(99), dst, Rights::SEND),
            Err(GrantError::BadSource)
        );
        assert_eq!(t.grant(src, dst, Rights::SEND), Err(GrantError::BadSource));
    }
}
