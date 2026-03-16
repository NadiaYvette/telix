//! Per-task capability space.
//!
//! Each task has a CapSpace which wraps a root CNode and provides
//! operations for inserting, looking up, deriving, and revoking capabilities.
//! The CDT is global (shared across all tasks); the CapSpace just manages
//! the task's own CNode slots.

use super::capability::{Capability, Rights};
use super::cdt::Cdt;
use super::cnode::{CNode, CNODE_SLOTS};

/// Per-task capability space: a root CNode plus a task ID for CDT tracking.
pub struct CapSpace {
    pub root: CNode,
    pub task_id: u32,
}

impl CapSpace {
    pub const fn new(task_id: u32) -> Self {
        Self {
            root: CNode::new(),
            task_id,
        }
    }

    /// Insert a new root capability (not derived from anything) into the first
    /// empty slot. Returns the slot index, or None if full.
    pub fn insert(&mut self, mut cap: Capability, cdt: &mut Cdt) -> Option<usize> {
        let slot = self.root.find_empty()?;
        let cdt_idx = cdt.insert_root(&cap, self.task_id, slot as u16)?;
        cap.cdt_index = cdt_idx;
        self.root.insert(slot, cap);
        Some(slot)
    }

    /// Insert a capability at a specific slot as a root capability.
    pub fn insert_at(&mut self, slot: usize, mut cap: Capability, cdt: &mut Cdt) -> bool {
        if slot >= CNODE_SLOTS {
            return false;
        }
        if let Some(cdt_idx) = cdt.insert_root(&cap, self.task_id, slot as u16) {
            cap.cdt_index = cdt_idx;
            self.root.insert(slot, cap);
            true
        } else {
            false
        }
    }

    /// Derive a capability from `src_slot` with attenuated rights, placing
    /// the derived capability in the first empty slot of `dest_space`.
    /// Returns the destination slot index, or None on failure.
    pub fn derive_to(
        &self,
        src_slot: usize,
        new_rights: Rights,
        dest_space: &mut CapSpace,
        cdt: &mut Cdt,
    ) -> Option<usize> {
        let src_cap = self.root.get(src_slot)?;
        if src_cap.is_null() {
            return None;
        }
        let mut derived = src_cap.derive(new_rights)?;
        let dest_slot = dest_space.root.find_empty()?;
        let cdt_idx = cdt.insert_derived(
            src_cap.cdt_index,
            &derived,
            dest_space.task_id,
            dest_slot as u16,
        )?;
        derived.cdt_index = cdt_idx;
        dest_space.root.insert(dest_slot, derived);
        Some(dest_slot)
    }

    /// Revoke all capabilities derived from the capability in `slot`.
    /// The capability in `slot` remains; all its CDT children are removed.
    /// Returns the number of revoked capabilities.
    pub fn revoke(&self, slot: usize, cdt: &mut Cdt) -> usize {
        if let Some(cap) = self.root.get(slot) {
            if !cap.is_null() && cap.cdt_index != u32::MAX {
                return cdt.revoke_children(cap.cdt_index);
            }
        }
        0
    }

    /// Look up a capability by slot index.
    pub fn lookup(&self, slot: usize) -> Option<&Capability> {
        let cap = self.root.get(slot)?;
        if cap.is_null() {
            None
        } else {
            Some(cap)
        }
    }
}
