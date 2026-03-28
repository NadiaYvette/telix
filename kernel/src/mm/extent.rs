//! B+ tree of physical memory extents.
//!
//! Replaces the traditional coremap (per-frame metadata array) with an
//! extent-based data structure. Each entry describes a contiguous range of
//! physical memory with uniform properties.
//!
//! The B+ tree provides:
//! - O(log n) point lookup and insert/remove
//! - O(1) range scan continuation via leaf sibling pointers
//! - Automatic coalescing of adjacent extents with identical properties
//! - Splitting extents on partial remove

use super::page::PhysAddr;
use super::slab;
use core::ptr;

// ---------------------------------------------------------------------------
// Extent entry — describes one contiguous physical range
// ---------------------------------------------------------------------------

/// Flags describing the state of a physical memory extent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct ExtentFlags(pub u16);

#[allow(dead_code)]
impl ExtentFlags {
    pub const NONE: Self = Self(0);
    pub const DIRTY: Self = Self(1 << 0);
    pub const WRITEBACK: Self = Self(1 << 1);
    pub const LOCKED: Self = Self(1 << 2);
    pub const ANON: Self = Self(1 << 3);
    pub const CACHE: Self = Self(1 << 4);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A single extent entry in the B+ tree.
#[derive(Clone, Copy, Debug)]
pub struct ExtentEntry {
    /// Start physical address (PAGE_SIZE-aligned).
    pub start: PhysAddr,
    /// Number of allocation pages in this extent.
    pub page_count: u16,
    /// State flags.
    pub flags: ExtentFlags,
    /// Reference count for this extent.
    pub refcount: u16,
    /// Owning memory object ID (0 = none).
    pub object_id: u64,
    /// Offset within the memory object (in PAGE_SIZE units).
    pub object_offset: u32,
}

impl ExtentEntry {
    /// Physical address one past the end of this extent.
    pub fn end(&self) -> PhysAddr {
        PhysAddr::new(self.start.as_usize() + (self.page_count as usize) * super::page::PAGE_SIZE)
    }

    /// Whether this extent can be coalesced with `other` (which must start
    /// immediately after `self`).
    fn can_coalesce(&self, other: &Self) -> bool {
        self.end() == other.start
            && self.flags == other.flags
            && self.refcount == other.refcount
            && self.object_id == other.object_id
            && self.object_id != 0
            && self.object_offset + self.page_count as u32 == other.object_offset
    }
}

// ---------------------------------------------------------------------------
// B+ tree node structures
// ---------------------------------------------------------------------------

/// Maximum keys in an interior node. With 8-byte keys and 8-byte child
/// pointers, plus a small header, this fits comfortably in a 512-byte slab
/// object.
const ORDER: usize = 24;
/// Maximum entries in a leaf node (each ExtentEntry is 32 bytes).
const LEAF_CAP: usize = 15;

/// Node tag stored in the first byte of every node.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum NodeTag {
    Interior = 0,
    Leaf = 1,
}

/// Interior (branch) node of the B+ tree.
#[repr(C)]
struct InteriorNode {
    tag: NodeTag,
    key_count: u8,
    _pad: [u8; 6],
    /// keys[0..key_count]: separator keys (PhysAddr values stored as usize).
    keys: [usize; ORDER],
    /// children[0..key_count+1]: pointers to child nodes.
    children: [*mut u8; ORDER + 1],
}

/// Leaf node of the B+ tree.
#[repr(C)]
pub(crate) struct LeafNode {
    tag: NodeTag,
    entry_count: u8,
    _pad: [u8; 6],
    entries: [ExtentEntry; LEAF_CAP],
    next: *mut LeafNode,
    prev: *mut LeafNode,
}

// Slab size for nodes — use 512-byte cache.
const NODE_SLAB_SIZE: usize = 512;

fn alloc_node() -> *mut u8 {
    match slab::alloc(NODE_SLAB_SIZE) {
        Some(pa) => {
            let p = pa.as_usize() as *mut u8;
            unsafe { ptr::write_bytes(p, 0, NODE_SLAB_SIZE) };
            p
        }
        None => ptr::null_mut(),
    }
}

fn free_node(p: *mut u8) {
    if !p.is_null() {
        slab::free(PhysAddr::new(p as usize), NODE_SLAB_SIZE);
    }
}

fn node_tag(p: *const u8) -> NodeTag {
    if p.is_null() {
        NodeTag::Leaf // shouldn't happen
    } else {
        let byte = unsafe { *p };
        if byte == NodeTag::Interior as u8 {
            NodeTag::Interior
        } else {
            NodeTag::Leaf
        }
    }
}

fn as_interior(p: *mut u8) -> &'static mut InteriorNode {
    unsafe { &mut *(p as *mut InteriorNode) }
}

fn as_leaf(p: *mut u8) -> &'static mut LeafNode {
    unsafe { &mut *(p as *mut LeafNode) }
}

// ---------------------------------------------------------------------------
// B+ tree
// ---------------------------------------------------------------------------

/// B+ tree of physical memory extents.
pub struct ExtentTree {
    root: *mut u8,
    /// Count of entries across all leaves.
    count: usize,
}

unsafe impl Send for ExtentTree {}
unsafe impl Sync for ExtentTree {}

/// Iterator over extent entries in a range.
pub struct RangeIter {
    leaf: *mut LeafNode,
    index: usize,
    end: PhysAddr,
}

impl RangeIter {
    pub fn next(&mut self) -> Option<&ExtentEntry> {
        loop {
            if self.leaf.is_null() {
                return None;
            }
            let leaf = unsafe { &*self.leaf };
            if self.index >= leaf.entry_count as usize {
                self.leaf = leaf.next;
                self.index = 0;
                continue;
            }
            let entry = &leaf.entries[self.index];
            if entry.start >= self.end {
                return None;
            }
            self.index += 1;
            return Some(entry);
        }
    }
}

impl ExtentTree {
    /// Create an empty B+ tree.
    pub const fn new() -> Self {
        Self {
            root: ptr::null_mut(),
            count: 0,
        }
    }

    /// Number of extent entries in the tree.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Look up the extent containing `addr`. Returns None if no extent covers it.
    pub fn lookup(&self, addr: PhysAddr) -> Option<&ExtentEntry> {
        if self.root.is_null() {
            return None;
        }
        let leaf = self.find_leaf(addr);
        let leaf = unsafe { &*leaf };
        for i in 0..leaf.entry_count as usize {
            let e = &leaf.entries[i];
            if addr >= e.start && addr < e.end() {
                return Some(e);
            }
            if e.start > addr {
                break;
            }
        }
        None
    }

    /// Look up a mutable reference to the extent containing `addr`.
    #[allow(dead_code)]
    pub fn lookup_mut(&mut self, addr: PhysAddr) -> Option<&mut ExtentEntry> {
        if self.root.is_null() {
            return None;
        }
        let leaf = self.find_leaf(addr);
        let leaf = unsafe { &mut *leaf };
        let mut found = None;
        for i in 0..leaf.entry_count as usize {
            if addr >= leaf.entries[i].start && addr < leaf.entries[i].end() {
                found = Some(i);
                break;
            }
            if leaf.entries[i].start > addr {
                break;
            }
        }
        found.map(move |i| &mut leaf.entries[i])
    }

    /// Iterate extents whose ranges overlap [start, end).
    pub fn range(&self, start: PhysAddr, end: PhysAddr) -> RangeIter {
        if self.root.is_null() {
            return RangeIter {
                leaf: ptr::null_mut(),
                index: 0,
                end,
            };
        }
        let leaf = self.find_leaf(start);
        // Find the first entry that might overlap.
        let leaf_ref = unsafe { &*leaf };
        let mut idx = 0;
        for i in 0..leaf_ref.entry_count as usize {
            if leaf_ref.entries[i].end() > start {
                idx = i;
                break;
            }
            idx = i + 1;
        }
        RangeIter {
            leaf,
            index: idx,
            end,
        }
    }

    /// Insert an extent. Attempts to coalesce with neighbors.
    pub fn insert(&mut self, entry: ExtentEntry) {
        if self.root.is_null() {
            // Create the first leaf.
            let p = alloc_node();
            if p.is_null() {
                return;
            }
            let leaf = as_leaf(p);
            leaf.tag = NodeTag::Leaf;
            leaf.entry_count = 1;
            leaf.entries[0] = entry;
            leaf.next = ptr::null_mut();
            leaf.prev = ptr::null_mut();
            self.root = p;
            self.count = 1;
            return;
        }

        // Find the leaf where this entry belongs.
        let leaf_ptr = self.find_leaf(entry.start);
        let leaf = unsafe { &mut *leaf_ptr };

        // Find insertion position (sorted by start address).
        let mut pos = leaf.entry_count as usize;
        for i in 0..leaf.entry_count as usize {
            if entry.start < leaf.entries[i].start {
                pos = i;
                break;
            }
        }

        // Try coalesce with predecessor.
        if pos > 0 && leaf.entries[pos - 1].can_coalesce(&entry) {
            leaf.entries[pos - 1].page_count += entry.page_count;
            // Try coalesce with successor too.
            if pos < leaf.entry_count as usize
                && leaf.entries[pos - 1].can_coalesce(&leaf.entries[pos])
            {
                leaf.entries[pos - 1].page_count += leaf.entries[pos].page_count;
                // Remove entries[pos] by shifting.
                self.remove_entry_at(leaf_ptr, pos);
                // Net: added one, removed one => count stays same, but we merged
                // two inserts worth. Actually we didn't increment count yet.
                // The entry was coalesced, not inserted as new.
                return;
            }
            return;
        }

        // Try coalesce with successor.
        if pos < leaf.entry_count as usize && entry.can_coalesce(&leaf.entries[pos]) {
            leaf.entries[pos].start = entry.start;
            leaf.entries[pos].page_count += entry.page_count;
            leaf.entries[pos].object_offset = entry.object_offset;
            return;
        }

        // No coalescing — insert at pos.
        if (leaf.entry_count as usize) < LEAF_CAP {
            // Room in this leaf.
            self.insert_entry_at(leaf_ptr, pos, entry);
            self.count += 1;
        } else {
            // Leaf is full — split and insert.
            self.split_leaf_and_insert(leaf_ptr, pos, entry);
            self.count += 1;
        }
    }

    /// Remove the extent starting at exactly `start`. Returns the removed entry if found.
    pub fn remove(&mut self, start: PhysAddr) -> Option<ExtentEntry> {
        if self.root.is_null() {
            return None;
        }
        let leaf_ptr = self.find_leaf(start);
        let leaf = unsafe { &mut *leaf_ptr };
        for i in 0..leaf.entry_count as usize {
            if leaf.entries[i].start == start {
                let entry = leaf.entries[i];
                self.remove_entry_at(leaf_ptr, i);
                self.count -= 1;
                // If the tree is now empty, free the root.
                if self.count == 0 {
                    self.free_tree(self.root);
                    self.root = ptr::null_mut();
                }
                return Some(entry);
            }
            if leaf.entries[i].start > start {
                break;
            }
        }
        None
    }

    /// Split the extent containing `addr` at page boundary `split_at`.
    /// The original extent is shortened to [start, split_at) and a new
    /// extent [split_at, end) is inserted (without coalescing).
    /// Returns true if the split was performed.
    pub fn split_at(&mut self, addr: PhysAddr, split_at: PhysAddr) -> bool {
        if self.root.is_null() {
            return false;
        }
        let leaf_ptr = self.find_leaf(addr);
        let leaf = unsafe { &mut *leaf_ptr };
        for i in 0..leaf.entry_count as usize {
            let e = &leaf.entries[i];
            if addr >= e.start && addr < e.end() && split_at > e.start && split_at < e.end() {
                let orig_end_pages = e.page_count;
                let pages_before =
                    ((split_at.as_usize() - e.start.as_usize()) / super::page::PAGE_SIZE) as u16;
                let pages_after = orig_end_pages - pages_before;
                let new_entry = ExtentEntry {
                    start: split_at,
                    page_count: pages_after,
                    flags: e.flags,
                    refcount: e.refcount,
                    object_id: e.object_id,
                    object_offset: e.object_offset + pages_before as u32,
                };
                // Shorten original.
                let e = &mut leaf.entries[i];
                e.page_count = pages_before;
                // Insert the new tail directly (no coalescing).
                let pos = i + 1;
                if (leaf.entry_count as usize) < LEAF_CAP {
                    self.insert_entry_at(leaf_ptr, pos, new_entry);
                    self.count += 1;
                } else {
                    self.split_leaf_and_insert(leaf_ptr, pos, new_entry);
                    self.count += 1;
                }
                return true;
            }
        }
        false
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Find the leaf node that should contain `addr`.
    fn find_leaf(&self, addr: PhysAddr) -> *mut LeafNode {
        let mut node = self.root;
        loop {
            if node.is_null() {
                return ptr::null_mut();
            }
            match node_tag(node) {
                NodeTag::Leaf => return node as *mut LeafNode,
                NodeTag::Interior => {
                    let interior = as_interior(node);
                    let mut child_idx = interior.key_count as usize;
                    for j in 0..interior.key_count as usize {
                        if addr.as_usize() < interior.keys[j] {
                            child_idx = j;
                            break;
                        }
                    }
                    node = interior.children[child_idx];
                }
            }
        }
    }

    /// Insert entry at position `pos` in a leaf that has room.
    fn insert_entry_at(&self, leaf_ptr: *mut LeafNode, pos: usize, entry: ExtentEntry) {
        let leaf = unsafe { &mut *leaf_ptr };
        let count = leaf.entry_count as usize;
        // Shift entries right.
        for j in (pos..count).rev() {
            leaf.entries[j + 1] = leaf.entries[j];
        }
        leaf.entries[pos] = entry;
        leaf.entry_count += 1;
    }

    /// Remove entry at position `pos` in a leaf.
    fn remove_entry_at(&self, leaf_ptr: *mut LeafNode, pos: usize) {
        let leaf = unsafe { &mut *leaf_ptr };
        let count = leaf.entry_count as usize;
        for j in pos..count - 1 {
            leaf.entries[j] = leaf.entries[j + 1];
        }
        leaf.entry_count -= 1;
        // Note: we don't handle underflow/merging for simplicity in Phase 2.
        // The tree may become slightly unbalanced but correctness is preserved.
    }

    /// Split a full leaf and insert a new entry.
    fn split_leaf_and_insert(&mut self, leaf_ptr: *mut LeafNode, pos: usize, entry: ExtentEntry) {
        let new_ptr = alloc_node();
        if new_ptr.is_null() {
            return; // OOM — drop the insert
        }
        let new_leaf = as_leaf(new_ptr as *mut u8);
        new_leaf.tag = NodeTag::Leaf;

        let old_leaf = unsafe { &mut *leaf_ptr };

        // Collect all entries + the new one into a temporary array.
        let total = old_leaf.entry_count as usize + 1;
        let mut tmp = [ExtentEntry {
            start: PhysAddr::new(0),
            page_count: 0,
            flags: ExtentFlags::NONE,
            refcount: 0,
            object_id: 0,
            object_offset: 0,
        }; LEAF_CAP + 1];
        for i in 0..pos {
            tmp[i] = old_leaf.entries[i];
        }
        tmp[pos] = entry;
        for i in pos..old_leaf.entry_count as usize {
            tmp[i + 1] = old_leaf.entries[i];
        }

        // Split: first half stays in old_leaf, second half goes to new_leaf.
        let mid = total / 2;
        old_leaf.entry_count = mid as u8;
        for i in 0..mid {
            old_leaf.entries[i] = tmp[i];
        }
        new_leaf.entry_count = (total - mid) as u8;
        for i in 0..(total - mid) {
            new_leaf.entries[i] = tmp[mid + i];
        }

        // Link siblings.
        let new_leaf_as_leaf = new_ptr as *mut LeafNode;
        new_leaf.next = old_leaf.next;
        new_leaf.prev = leaf_ptr;
        if !old_leaf.next.is_null() {
            unsafe { (*old_leaf.next).prev = new_leaf_as_leaf };
        }
        old_leaf.next = new_leaf_as_leaf;

        // Promote the first key of the new leaf to the parent.
        let promote_key = new_leaf.entries[0].start.as_usize();
        self.insert_into_parent(leaf_ptr as *mut u8, promote_key, new_ptr as *mut u8);
    }

    /// Insert a new child pointer into the parent of `left`. If the parent
    /// is full, split recursively. If `left` is the root, create a new root.
    fn insert_into_parent(&mut self, left: *mut u8, key: usize, right: *mut u8) {
        // If left is the root, create a new root.
        if left == self.root {
            let new_root = alloc_node();
            if new_root.is_null() {
                return;
            }
            let root = as_interior(new_root);
            root.tag = NodeTag::Interior;
            root.key_count = 1;
            root.keys[0] = key;
            root.children[0] = left;
            root.children[1] = right;
            self.root = new_root;
            return;
        }

        // Find the parent of `left`.
        let parent_ptr = self.find_parent(self.root, left);
        if parent_ptr.is_null() {
            return;
        }
        let parent = as_interior(parent_ptr);

        // Find the index of `left` in parent's children.
        let mut left_idx = 0;
        for i in 0..=parent.key_count as usize {
            if parent.children[i] == left {
                left_idx = i;
                break;
            }
        }

        if (parent.key_count as usize) < ORDER {
            // Room in parent — insert key and right child.
            let kc = parent.key_count as usize;
            for j in (left_idx + 1..=kc).rev() {
                parent.children[j + 1] = parent.children[j];
            }
            for j in (left_idx..kc).rev() {
                parent.keys[j + 1] = parent.keys[j];
            }
            parent.keys[left_idx] = key;
            parent.children[left_idx + 1] = right;
            parent.key_count += 1;
        } else {
            // Parent is full — split the interior node.
            self.split_interior_and_insert(parent_ptr, left_idx, key, right);
        }
    }

    /// Split a full interior node and insert a new key/child.
    fn split_interior_and_insert(
        &mut self,
        node_ptr: *mut u8,
        insert_idx: usize,
        key: usize,
        right_child: *mut u8,
    ) {
        let node = as_interior(node_ptr);
        let new_ptr = alloc_node();
        if new_ptr.is_null() {
            return;
        }
        let new_node = as_interior(new_ptr);
        new_node.tag = NodeTag::Interior;

        // Build temporary arrays with the new key/child inserted.
        let total_keys = node.key_count as usize + 1;
        let mut tmp_keys = [0usize; ORDER + 1];
        let mut tmp_children = [ptr::null_mut::<u8>(); ORDER + 2];

        for i in 0..insert_idx {
            tmp_keys[i] = node.keys[i];
        }
        tmp_keys[insert_idx] = key;
        for i in insert_idx..node.key_count as usize {
            tmp_keys[i + 1] = node.keys[i];
        }

        for i in 0..=insert_idx {
            tmp_children[i] = node.children[i];
        }
        tmp_children[insert_idx + 1] = right_child;
        for i in insert_idx + 1..=node.key_count as usize {
            tmp_children[i + 1] = node.children[i];
        }

        // Split at midpoint. The middle key is promoted.
        let mid = total_keys / 2;
        let promote_key = tmp_keys[mid];

        // Left node keeps keys[0..mid] and children[0..=mid].
        node.key_count = mid as u8;
        for i in 0..mid {
            node.keys[i] = tmp_keys[i];
        }
        for i in 0..=mid {
            node.children[i] = tmp_children[i];
        }

        // Right node gets keys[mid+1..total_keys] and children[mid+1..=total_keys].
        let right_keys = total_keys - mid - 1;
        new_node.key_count = right_keys as u8;
        for i in 0..right_keys {
            new_node.keys[i] = tmp_keys[mid + 1 + i];
        }
        for i in 0..=right_keys {
            new_node.children[i] = tmp_children[mid + 1 + i];
        }

        self.insert_into_parent(node_ptr, promote_key, new_ptr);
    }

    /// Find the parent of `child` starting from `node`. Returns null if not found.
    fn find_parent(&self, node: *mut u8, child: *mut u8) -> *mut u8 {
        if node.is_null() || node_tag(node) == NodeTag::Leaf {
            return ptr::null_mut();
        }
        let interior = as_interior(node);
        for i in 0..=interior.key_count as usize {
            if interior.children[i] == child {
                return node;
            }
        }
        // Recurse into children.
        for i in 0..=interior.key_count as usize {
            let result = self.find_parent(interior.children[i], child);
            if !result.is_null() {
                return result;
            }
        }
        ptr::null_mut()
    }

    /// Free all nodes in the tree rooted at `node`.
    fn free_tree(&self, node: *mut u8) {
        if node.is_null() {
            return;
        }
        if node_tag(node) == NodeTag::Interior {
            let interior = as_interior(node);
            for i in 0..=interior.key_count as usize {
                self.free_tree(interior.children[i]);
            }
        }
        free_node(node);
    }

    /// Return the leftmost leaf (for iteration).
    #[allow(dead_code)]
    pub fn first_leaf(&self) -> *mut LeafNode {
        if self.root.is_null() {
            return ptr::null_mut();
        }
        let mut node = self.root;
        loop {
            match node_tag(node) {
                NodeTag::Leaf => return node as *mut LeafNode,
                NodeTag::Interior => {
                    let interior = as_interior(node);
                    node = interior.children[0];
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (called from kmain)
// ---------------------------------------------------------------------------

pub fn run_tests() {
    test_basic_insert_lookup();
    test_coalesce();
    test_split();
    test_range_query();
    test_many_inserts();
    crate::println!("  Extent tree: all tests passed");
}

fn test_basic_insert_lookup() {
    let mut tree = ExtentTree::new();
    assert!(tree.is_empty());

    let e1 = ExtentEntry {
        start: PhysAddr::new(0x10_0000),
        page_count: 4,
        flags: ExtentFlags::ANON,
        refcount: 1,
        object_id: 1,
        object_offset: 0,
    };
    tree.insert(e1);
    assert_eq!(tree.len(), 1);

    // Lookup at start.
    let found = tree.lookup(PhysAddr::new(0x10_0000)).unwrap();
    assert_eq!(found.page_count, 4);
    assert_eq!(found.object_id, 1);

    // Lookup in the middle.
    let found = tree
        .lookup(PhysAddr::new(0x10_0000 + super::page::PAGE_SIZE))
        .unwrap();
    assert_eq!(found.start, PhysAddr::new(0x10_0000));

    // Lookup outside.
    assert!(tree.lookup(PhysAddr::new(0x20_0000)).is_none());

    // Remove.
    let removed = tree.remove(PhysAddr::new(0x10_0000)).unwrap();
    assert_eq!(removed.page_count, 4);
    assert!(tree.is_empty());
}

fn test_coalesce() {
    let mut tree = ExtentTree::new();
    let ps = super::page::PAGE_SIZE;

    // Insert two adjacent extents with matching properties — should coalesce.
    let e1 = ExtentEntry {
        start: PhysAddr::new(0x10_0000),
        page_count: 2,
        flags: ExtentFlags::ANON,
        refcount: 1,
        object_id: 1,
        object_offset: 0,
    };
    let e2 = ExtentEntry {
        start: PhysAddr::new(0x10_0000 + 2 * ps),
        page_count: 3,
        flags: ExtentFlags::ANON,
        refcount: 1,
        object_id: 1,
        object_offset: 2,
    };
    tree.insert(e1);
    tree.insert(e2);

    // Should be coalesced into one extent of 5 pages.
    assert_eq!(tree.len(), 1);
    let found = tree.lookup(PhysAddr::new(0x10_0000)).unwrap();
    assert_eq!(found.page_count, 5);

    // Insert non-adjacent — should not coalesce.
    let e3 = ExtentEntry {
        start: PhysAddr::new(0x20_0000),
        page_count: 1,
        flags: ExtentFlags::ANON,
        refcount: 1,
        object_id: 2,
        object_offset: 0,
    };
    tree.insert(e3);
    assert_eq!(tree.len(), 2);
}

fn test_split() {
    let mut tree = ExtentTree::new();
    let ps = super::page::PAGE_SIZE;

    let e = ExtentEntry {
        start: PhysAddr::new(0x10_0000),
        page_count: 8,
        flags: ExtentFlags::ANON,
        refcount: 1,
        object_id: 1,
        object_offset: 0,
    };
    tree.insert(e);

    // Split at page 3 (offset 3*PAGE_SIZE from start).
    let split_addr = PhysAddr::new(0x10_0000 + 3 * ps);
    assert!(tree.split_at(PhysAddr::new(0x10_0000), split_addr));

    // Should now have two extents.
    assert_eq!(tree.len(), 2);

    let first = tree.lookup(PhysAddr::new(0x10_0000)).unwrap();
    assert_eq!(first.page_count, 3);
    assert_eq!(first.object_offset, 0);

    let second = tree.lookup(split_addr).unwrap();
    assert_eq!(second.page_count, 5);
    assert_eq!(second.object_offset, 3);
}

fn test_range_query() {
    let mut tree = ExtentTree::new();
    let ps = super::page::PAGE_SIZE;

    // Insert 3 non-coalescing extents (different object_ids).
    for i in 0..3u32 {
        tree.insert(ExtentEntry {
            start: PhysAddr::new(0x10_0000 + (i as usize) * 4 * ps),
            page_count: 2,
            flags: ExtentFlags::ANON,
            refcount: 1,
            object_id: (i + 1) as u64,
            object_offset: 0,
        });
    }
    assert_eq!(tree.len(), 3);

    // Range query covering all three.
    let mut iter = tree.range(PhysAddr::new(0x10_0000), PhysAddr::new(0x10_0000 + 12 * ps));
    let mut found = 0;
    while iter.next().is_some() {
        found += 1;
    }
    assert_eq!(found, 3);

    // Range query covering only the middle one.
    let mut iter = tree.range(
        PhysAddr::new(0x10_0000 + 4 * ps),
        PhysAddr::new(0x10_0000 + 8 * ps),
    );
    let e = iter.next().unwrap();
    assert_eq!(e.object_id, 2);
    assert!(iter.next().is_none());
}

fn test_many_inserts() {
    let mut tree = ExtentTree::new();
    let ps = super::page::PAGE_SIZE;

    // Insert enough extents to trigger leaf splits.
    // Use different object IDs to prevent coalescing.
    let n = LEAF_CAP * 3;
    for i in 0..n {
        tree.insert(ExtentEntry {
            start: PhysAddr::new(0x100_0000 + i * ps),
            page_count: 1,
            flags: ExtentFlags::ANON,
            refcount: 1,
            object_id: (i + 1) as u64,
            object_offset: 0,
        });
    }
    assert_eq!(tree.len(), n);

    // Verify all entries are findable.
    for i in 0..n {
        let addr = PhysAddr::new(0x100_0000 + i * ps);
        let found = tree.lookup(addr);
        assert!(found.is_some(), "Missing extent at index {}", i);
        assert_eq!(found.unwrap().object_id, (i + 1) as u64);
    }

    // Remove all.
    for i in 0..n {
        let addr = PhysAddr::new(0x100_0000 + i * ps);
        assert!(tree.remove(addr).is_some());
    }
    assert!(tree.is_empty());
}
