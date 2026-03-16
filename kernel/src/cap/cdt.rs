//! Capability Derivation Tree (CDT).
//!
//! Tracks parent-child relationships among capabilities. When a capability is
//! derived (copied with attenuated rights) or transferred, the derived capability
//! is a child of the original in the CDT. This enables recursive revocation:
//! revoking a parent revokes all its descendants.
//!
//! Implementation: a static array of CDT nodes, each with parent/first-child/
//! next-sibling indices. This avoids dynamic allocation for the tree structure.

use super::capability::{CapType, Capability};

const CDT_NONE: u32 = u32::MAX;

/// Maximum number of CDT nodes (capabilities tracked for derivation).
const MAX_CDT_NODES: usize = 4096;

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
    nodes: [CdtNode; MAX_CDT_NODES],
    /// Free list head (index of first free node).
    free_head: u32,
}

impl Cdt {
    pub const fn new() -> Self {
        Self {
            nodes: [CdtNode::empty(); MAX_CDT_NODES],
            free_head: CDT_NONE, // Will be initialized by init()
        }
    }

    /// Initialize the free list. Must be called before use.
    pub fn init(&mut self) {
        for i in 0..MAX_CDT_NODES {
            self.nodes[i].next_sibling = if i + 1 < MAX_CDT_NODES {
                (i + 1) as u32
            } else {
                CDT_NONE
            };
        }
        self.free_head = 0;
    }

    /// Allocate a CDT node for a root capability (no parent).
    /// Returns the CDT index, or None if full.
    pub fn insert_root(
        &mut self,
        cap: &Capability,
        task_id: u32,
        slot_index: u16,
    ) -> Option<u32> {
        let idx = self.alloc_node()?;
        let node = &mut self.nodes[idx as usize];
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
        if parent_idx as usize >= MAX_CDT_NODES || !self.nodes[parent_idx as usize].active {
            return None;
        }

        let idx = self.alloc_node()?;

        // Read parent's first child before mutating the new node.
        let parents_first_child = self.nodes[parent_idx as usize].first_child;

        let node = &mut self.nodes[idx as usize];
        node.cap_type = cap.cap_type;
        node.object = cap.object;
        node.parent = parent_idx;
        node.first_child = CDT_NONE;
        node.next_sibling = parents_first_child;
        node.task_id = task_id;
        node.slot_index = slot_index;
        node.active = true;

        // Link as first child of parent.
        self.nodes[parent_idx as usize].first_child = idx;

        Some(idx)
    }

    /// Revoke a capability and all its descendants.
    /// Returns the number of capabilities revoked (not counting the root).
    /// The root capability itself is NOT removed — only its children.
    /// The caller is responsible for deciding what to do with the root.
    pub fn revoke_children(&mut self, parent_idx: u32) -> usize {
        if parent_idx as usize >= MAX_CDT_NODES || !self.nodes[parent_idx as usize].active {
            return 0;
        }

        let mut count = 0;
        // Recursively free all children.
        let mut child = self.nodes[parent_idx as usize].first_child;
        while child != CDT_NONE {
            let next = self.nodes[child as usize].next_sibling;
            count += self.revoke_subtree(child);
            child = next;
        }
        self.nodes[parent_idx as usize].first_child = CDT_NONE;
        count
    }

    /// Remove a single node from the CDT (and all its descendants).
    /// Returns the number of nodes removed.
    pub fn remove(&mut self, idx: u32) -> usize {
        if idx as usize >= MAX_CDT_NODES || !self.nodes[idx as usize].active {
            return 0;
        }

        // Unlink from parent's child list.
        let parent = self.nodes[idx as usize].parent;
        if parent != CDT_NONE {
            self.unlink_child(parent, idx);
        }

        self.revoke_subtree(idx)
    }

    /// Get the task_id and slot_index for a CDT node (for revocation callbacks).
    pub fn get_location(&self, idx: u32) -> Option<(u32, u16)> {
        if idx as usize >= MAX_CDT_NODES || !self.nodes[idx as usize].active {
            return None;
        }
        let node = &self.nodes[idx as usize];
        Some((node.task_id, node.slot_index))
    }

    /// Check if a node is active.
    #[allow(dead_code)]
    pub fn is_active(&self, idx: u32) -> bool {
        (idx as usize) < MAX_CDT_NODES && self.nodes[idx as usize].active
    }

    // --- Internal helpers ---

    fn alloc_node(&mut self) -> Option<u32> {
        if self.free_head == CDT_NONE {
            return None;
        }
        let idx = self.free_head;
        self.free_head = self.nodes[idx as usize].next_sibling;
        self.nodes[idx as usize] = CdtNode::empty();
        Some(idx)
    }

    fn free_node(&mut self, idx: u32) {
        self.nodes[idx as usize] = CdtNode::empty();
        self.nodes[idx as usize].next_sibling = self.free_head;
        self.free_head = idx;
    }

    /// Recursively revoke a subtree rooted at `idx`. Returns count of removed nodes.
    fn revoke_subtree(&mut self, idx: u32) -> usize {
        let mut count = 1; // Count this node.
        let mut child = self.nodes[idx as usize].first_child;
        while child != CDT_NONE {
            let next = self.nodes[child as usize].next_sibling;
            count += self.revoke_subtree(child);
            child = next;
        }
        self.free_node(idx);
        count
    }

    /// Remove `child` from `parent`'s child linked list.
    fn unlink_child(&mut self, parent: u32, child: u32) {
        let first = self.nodes[parent as usize].first_child;
        if first == child {
            self.nodes[parent as usize].first_child = self.nodes[child as usize].next_sibling;
            return;
        }
        let mut prev = first;
        while prev != CDT_NONE {
            let next = self.nodes[prev as usize].next_sibling;
            if next == child {
                self.nodes[prev as usize].next_sibling = self.nodes[child as usize].next_sibling;
                return;
            }
            prev = next;
        }
    }
}
