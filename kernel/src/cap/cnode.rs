//! CNode: capability storage node — an array of capability slots.
//!
//! A task's capability space is a tree of CNodes. For the common single-level
//! case, a task has a single root CNode and refers to capabilities by slot index.

use super::capability::Capability;

/// Number of slots in a CNode. Must be a power of 2.
pub const CNODE_SLOTS: usize = 64;

/// A capability storage node: a fixed-size array of capability slots.
pub struct CNode {
    slots: [Capability; CNODE_SLOTS],
}

impl CNode {
    pub const fn new() -> Self {
        Self {
            slots: [Capability::null(); CNODE_SLOTS],
        }
    }

    /// Get a reference to a slot by index.
    pub fn get(&self, index: usize) -> Option<&Capability> {
        if index < CNODE_SLOTS {
            Some(&self.slots[index])
        } else {
            None
        }
    }

    /// Get a mutable reference to a slot by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Capability> {
        if index < CNODE_SLOTS {
            Some(&mut self.slots[index])
        } else {
            None
        }
    }

    /// Insert a capability at the given slot index.
    /// Returns the previous capability in that slot.
    pub fn insert(&mut self, index: usize, cap: Capability) -> Option<Capability> {
        if index < CNODE_SLOTS {
            let old = self.slots[index];
            self.slots[index] = cap;
            Some(old)
        } else {
            None
        }
    }

    /// Remove (null out) the capability at the given slot index.
    /// Returns the removed capability.
    pub fn remove(&mut self, index: usize) -> Option<Capability> {
        if index < CNODE_SLOTS {
            let old = self.slots[index];
            self.slots[index] = Capability::null();
            Some(old)
        } else {
            None
        }
    }

    /// Find the first empty slot. Returns the index or None.
    pub fn find_empty(&self) -> Option<usize> {
        for i in 0..CNODE_SLOTS {
            if self.slots[i].is_null() {
                return Some(i);
            }
        }
        None
    }

    /// Number of non-null capabilities.
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|c| !c.is_null()).count()
    }
}
