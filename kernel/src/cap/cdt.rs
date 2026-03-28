//! Capability Derivation Tree (CDT).
//!
//! Tracks parent-child relationships among capabilities. When a capability is
//! derived (copied with attenuated rights) or transferred, the derived capability
//! is a child of the original in the CDT. This enables recursive revocation:
//! revoking a parent revokes all its descendants.
//!
//! Implementation: a page-backed growable array of CDT nodes, each with
//! parent/first-child/next-sibling indices. Pages are allocated on demand
//! via phys::alloc_page(), so there is no compile-time cap on node count.

use super::capability::{CapType, Capability};
use crate::mm::paged_array::PagedArray;

const CDT_NONE: u32 = u32::MAX;

/// A node in the capability derivation tree.
#[derive(Clone, Copy)]
struct CdtNode {
    /// The capability this node represents.
    cap_type: CapType,
    object: usize,
    /// Tree linkage.
    parent: u32,
    first_child: u32,
    next_sibling: u32,
    /// Back-reference: which task/cnode/slot holds this capability.
    /// (task_id, slot_index) — used during revocation to null out the slot.
    task_id: u32,
    slot_index: u16,
    /// Whether this node is in use.
    active: bool,
}

impl CdtNode {
    const fn empty() -> Self {
        Self {
            cap_type: CapType::Null,
            object: 0,
            parent: CDT_NONE,
            first_child: CDT_NONE,
            next_sibling: CDT_NONE,
            task_id: 0,
            slot_index: 0,
            active: false,
        }
    }
}

/// The global capability derivation tree.
pub struct Cdt {
    nodes: PagedArray<CdtNode>,
    /// Free list head (index of first free node).
    free_head: u32,
}

impl Cdt {
    pub const fn new() -> Self {
        Self {
            nodes: PagedArray::new(),
            free_head: CDT_NONE,
        }
    }

    /// Initialize: allocate the first page and set up the free list.
    pub fn init(&mut self) {
        if !self.nodes.ensure_capacity(1) {
            return;
        }
        let cap = self.nodes.capacity();
        for i in 0..cap {
            self.nodes.get_mut(i).next_sibling = if i + 1 < cap {
                (i + 1) as u32
            } else {
                CDT_NONE
            };
        }
        self.free_head = 0;
    }

    /// Allocate a CDT node for a root capability (no parent).
    /// Returns the CDT index, or None if full.
    pub fn insert_root(&mut self, cap: &Capability, task_id: u32, slot_index: u16) -> Option<u32> {
        let idx = self.alloc_node()?;
        let node = self.nodes.get_mut(idx as usize);
        node.cap_type = cap.cap_type;
        node.object = cap.object;
        node.parent = CDT_NONE;
        node.first_child = CDT_NONE;
        node.next_sibling = CDT_NONE;
        node.task_id = task_id;
        node.slot_index = slot_index;
        node.active = true;
        Some(idx)
    }

    /// Insert a derived capability as a child of `parent_idx`.
    /// Returns the CDT index for the new node, or None if full.
    pub fn insert_derived(
        &mut self,
        parent_idx: u32,
        cap: &Capability,
        task_id: u32,
        slot_index: u16,
    ) -> Option<u32> {
        if (parent_idx as usize) >= self.nodes.capacity()
            || !self.nodes.get(parent_idx as usize).active
        {
            return None;
        }

        let idx = self.alloc_node()?;

        // Read parent's first child before mutating the new node.
        let parents_first_child = self.nodes.get(parent_idx as usize).first_child;

        let node = self.nodes.get_mut(idx as usize);
        node.cap_type = cap.cap_type;
        node.object = cap.object;
        node.parent = parent_idx;
        node.first_child = CDT_NONE;
        node.next_sibling = parents_first_child;
        node.task_id = task_id;
        node.slot_index = slot_index;
        node.active = true;

        // Link as first child of parent.
        self.nodes.get_mut(parent_idx as usize).first_child = idx;

        Some(idx)
    }

    /// Revoke a capability and all its descendants.
    /// Returns the number of capabilities revoked (not counting the root).
    /// The root capability itself is NOT removed — only its children.
    /// The caller is responsible for deciding what to do with the root.
    pub fn revoke_children(&mut self, parent_idx: u32) -> usize {
        if (parent_idx as usize) >= self.nodes.capacity()
            || !self.nodes.get(parent_idx as usize).active
        {
            return 0;
        }

        let mut count = 0;
        // Recursively free all children.
        let mut child = self.nodes.get(parent_idx as usize).first_child;
        while child != CDT_NONE {
            let next = self.nodes.get(child as usize).next_sibling;
            count += self.revoke_subtree(child);
            child = next;
        }
        self.nodes.get_mut(parent_idx as usize).first_child = CDT_NONE;
        count
    }

    /// Remove a single node from the CDT (and all its descendants).
    /// Returns the number of nodes removed.
    #[allow(dead_code)]
    pub fn remove(&mut self, idx: u32) -> usize {
        if (idx as usize) >= self.nodes.capacity() || !self.nodes.get(idx as usize).active {
            return 0;
        }

        // Unlink from parent's child list.
        let parent = self.nodes.get(idx as usize).parent;
        if parent != CDT_NONE {
            self.unlink_child(parent, idx);
        }

        self.revoke_subtree(idx)
    }

    /// Get the task_id and slot_index for a CDT node (for revocation callbacks).
    #[allow(dead_code)]
    pub fn get_location(&self, idx: u32) -> Option<(u32, u16)> {
        if (idx as usize) >= self.nodes.capacity() || !self.nodes.get(idx as usize).active {
            return None;
        }
        let node = self.nodes.get(idx as usize);
        Some((node.task_id, node.slot_index))
    }

    /// Check if a node is active.
    #[allow(dead_code)]
    pub fn is_active(&self, idx: u32) -> bool {
        (idx as usize) < self.nodes.capacity() && self.nodes.get(idx as usize).active
    }

    // --- Internal helpers ---

    fn alloc_node(&mut self) -> Option<u32> {
        if self.free_head == CDT_NONE {
            // Grow: allocate one more page's worth of nodes.
            let old_cap = self.nodes.capacity();
            if !self.nodes.ensure_capacity(old_cap + 1) {
                return None;
            }
            let new_cap = self.nodes.capacity();
            // Chain new nodes into free list.
            for i in old_cap..new_cap {
                self.nodes.get_mut(i).next_sibling = if i + 1 < new_cap {
                    (i + 1) as u32
                } else {
                    CDT_NONE
                };
            }
            self.free_head = old_cap as u32;
        }
        let idx = self.free_head;
        self.free_head = self.nodes.get(idx as usize).next_sibling;
        *self.nodes.get_mut(idx as usize) = CdtNode::empty();
        Some(idx)
    }

    fn free_node(&mut self, idx: u32) {
        *self.nodes.get_mut(idx as usize) = CdtNode::empty();
        self.nodes.get_mut(idx as usize).next_sibling = self.free_head;
        self.free_head = idx;
    }

    /// Recursively revoke a subtree rooted at `idx`. Returns count of removed nodes.
    fn revoke_subtree(&mut self, idx: u32) -> usize {
        let mut count = 1; // Count this node.
        let mut child = self.nodes.get(idx as usize).first_child;
        while child != CDT_NONE {
            let next = self.nodes.get(child as usize).next_sibling;
            count += self.revoke_subtree(child);
            child = next;
        }
        self.free_node(idx);
        count
    }

    /// Remove `child` from `parent`'s child linked list.
    #[allow(dead_code)]
    fn unlink_child(&mut self, parent: u32, child: u32) {
        let first = self.nodes.get(parent as usize).first_child;
        if first == child {
            let next = self.nodes.get(child as usize).next_sibling;
            self.nodes.get_mut(parent as usize).first_child = next;
            return;
        }
        let mut prev = first;
        while prev != CDT_NONE {
            let next = self.nodes.get(prev as usize).next_sibling;
            if next == child {
                let child_next = self.nodes.get(child as usize).next_sibling;
                self.nodes.get_mut(prev as usize).next_sibling = child_next;
                return;
            }
            prev = next;
        }
    }
}
