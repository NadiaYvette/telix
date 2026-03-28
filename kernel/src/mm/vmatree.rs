//! B+ tree of VMAs keyed by virtual address interval.
//!
//! Provides O(log n) point-in-interval lookup (`find`: given a VA, return the
//! VMA whose [va_start, va_start+va_len) contains it), O(log n) insert/remove,
//! and O(1) sequential iteration via leaf sibling pointers (used by WSCLOCK).
//!
//! Unlike the extent tree, VMAs are never coalesced — each mapping is distinct.

use super::page::PhysAddr;
use super::slab;
use super::vma::Vma;
use core::ptr;

// ---------------------------------------------------------------------------
// Node structures
// ---------------------------------------------------------------------------

/// Interior node order. Each key is a usize (va_start), each child is a pointer.
/// With 8-byte keys + 8-byte pointers + header, fits in 512-byte slab.
const ORDER: usize = 24;

/// Maximum VMAs per leaf. Vma is small (~40 bytes without bitmaps), so we store
/// pointers to slab-allocated Vmas. With 8-byte keys + 8-byte pointers + header
/// + sibling links, LEAF_CAP pointers fit comfortably in 512 bytes.
const LEAF_CAP: usize = 24;

const NODE_SLAB_SIZE: usize = 512;
const VMA_SLAB_SIZE: usize = 64; // Vma is ~40 bytes without bitmaps

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum NodeTag {
    Interior = 0,
    Leaf = 1,
}

/// Interior node.
#[repr(C)]
struct InteriorNode {
    tag: NodeTag,
    key_count: u8,
    _pad: [u8; 6],
    /// keys[0..key_count]: separator keys (va_start values).
    keys: [usize; ORDER],
    /// children[0..key_count+1]: pointers to child nodes.
    children: [*mut u8; ORDER + 1],
}

/// Leaf node. Stores (key, vma_ptr) pairs sorted by va_start.
#[repr(C)]
pub(crate) struct LeafNode {
    tag: NodeTag,
    entry_count: u8,
    _pad: [u8; 6],
    /// va_start values, sorted.
    keys: [usize; LEAF_CAP],
    /// Pointers to slab-allocated Vma structs (1:1 with keys).
    vmas: [*mut Vma; LEAF_CAP],
    next: *mut LeafNode,
    prev: *mut LeafNode,
}

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

/// Allocate a Vma on the slab heap.
fn alloc_vma() -> *mut Vma {
    // Vma is large; we need the right slab size. Use 512-byte bucket.
    // If Vma doesn't fit in 512 bytes we need a bigger bucket — check at compile time.
    // Vma is ~1KB with per-MMU-page bitmaps for installed/zeroed tracking.
    const _: () = assert!(
        core::mem::size_of::<Vma>() <= VMA_SLAB_SIZE,
        "Vma does not fit in slab bucket"
    );
    match slab::alloc(VMA_SLAB_SIZE) {
        Some(pa) => {
            let p = pa.as_usize() as *mut Vma;
            unsafe { p.write(Vma::empty()) };
            p
        }
        None => ptr::null_mut(),
    }
}

fn free_vma(p: *mut Vma) {
    if !p.is_null() {
        slab::free(PhysAddr::new(p as usize), VMA_SLAB_SIZE);
    }
}

fn node_tag(p: *const u8) -> NodeTag {
    if p.is_null() {
        NodeTag::Leaf
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
// VmaTree
// ---------------------------------------------------------------------------

/// B+ tree of VMAs with interval-query semantics.
pub struct VmaTree {
    root: *mut u8,
    count: usize,
}

unsafe impl Send for VmaTree {}
unsafe impl Sync for VmaTree {}

impl VmaTree {
    pub const fn new() -> Self {
        Self {
            root: ptr::null_mut(),
            count: 0,
        }
    }

    /// Number of VMAs in the tree.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Find the VMA containing virtual address `va` (point-in-interval query).
    /// Returns a mutable reference to the Vma.
    pub fn find_mut(&self, va: usize) -> Option<&mut Vma> {
        if self.root.is_null() {
            return None;
        }
        // Walk to the leaf that would contain a VMA starting at or before `va`.
        let leaf = self.find_leaf(va);
        if leaf.is_null() {
            return None;
        }

        // The VMA containing `va` has va_start <= va < va_start + va_len.
        // Since keys are sorted by va_start, we want the last entry with
        // va_start <= va, then check if va < va_start + va_len.
        let leaf_ref = unsafe { &*leaf };
        let count = leaf_ref.entry_count as usize;

        // Binary search for the rightmost key <= va.
        let mut candidate: Option<usize> = None;
        for i in 0..count {
            if leaf_ref.keys[i] <= va {
                candidate = Some(i);
            } else {
                break;
            }
        }

        if let Some(idx) = candidate {
            let vma = unsafe { &mut *leaf_ref.vmas[idx] };
            if vma.active && vma.contains(va) {
                return Some(vma);
            }
        }

        // The VMA might be in the previous leaf (if va_start is in the previous
        // leaf but va_start + va_len extends past the leaf boundary).
        if !leaf_ref.prev.is_null() {
            let prev = unsafe { &*leaf_ref.prev };
            let pc = prev.entry_count as usize;
            if pc > 0 {
                let vma = unsafe { &mut *prev.vmas[pc - 1] };
                if vma.active && vma.contains(va) {
                    return Some(vma);
                }
            }
        }

        None
    }

    /// Find the VMA containing `va` (immutable).
    pub fn find(&self, va: usize) -> Option<&Vma> {
        self.find_mut(va).map(|v| &*v)
    }

    /// Insert a new VMA. Allocates a Vma on the slab and initializes it.
    /// Returns a mutable reference to the newly inserted Vma, or None on OOM.
    pub fn insert(
        &mut self,
        va_start: usize,
        va_len: usize,
        prot: super::vma::VmaProt,
        object_id: u64,
        object_offset: u32,
    ) -> Option<&mut Vma> {
        let vma_ptr = alloc_vma();
        if vma_ptr.is_null() {
            return None;
        }
        let vma = unsafe { &mut *vma_ptr };
        vma.va_start = va_start;
        vma.va_len = va_len;
        vma.prot = prot;
        vma.object_id = object_id;
        vma.object_offset = object_offset;
        vma.active = true;

        if self.root.is_null() {
            let p = alloc_node();
            if p.is_null() {
                free_vma(vma_ptr);
                return None;
            }
            let leaf = as_leaf(p);
            leaf.tag = NodeTag::Leaf;
            leaf.entry_count = 1;
            leaf.keys[0] = va_start;
            leaf.vmas[0] = vma_ptr;
            self.root = p;
            self.count = 1;
            return Some(unsafe { &mut *vma_ptr });
        }

        let leaf_ptr = self.find_leaf(va_start);
        let leaf = unsafe { &mut *leaf_ptr };

        // Find insertion position (sorted by va_start).
        let mut pos = leaf.entry_count as usize;
        for i in 0..leaf.entry_count as usize {
            if va_start < leaf.keys[i] {
                pos = i;
                break;
            }
        }

        if (leaf.entry_count as usize) < LEAF_CAP {
            self.insert_at(leaf_ptr, pos, va_start, vma_ptr);
            self.count += 1;
        } else {
            self.split_leaf_and_insert(leaf_ptr, pos, va_start, vma_ptr);
            self.count += 1;
        }

        Some(unsafe { &mut *vma_ptr })
    }

    /// Remove the VMA starting at `va_start`. Frees the slab-allocated Vma.
    /// Returns true if found and removed.
    pub fn remove(&mut self, va_start: usize) -> bool {
        if self.root.is_null() {
            return false;
        }
        let leaf_ptr = self.find_leaf(va_start);
        let leaf = unsafe { &mut *leaf_ptr };
        for i in 0..leaf.entry_count as usize {
            if leaf.keys[i] == va_start {
                let vma_ptr = leaf.vmas[i];
                self.remove_at(leaf_ptr, i);
                free_vma(vma_ptr);
                self.count -= 1;
                if self.count == 0 {
                    self.free_tree(self.root);
                    self.root = ptr::null_mut();
                }
                return true;
            }
            if leaf.keys[i] > va_start {
                break;
            }
        }
        false
    }

    /// Return the first leaf node (for sequential iteration).
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

    /// Iterate over all VMAs in VA order.
    pub fn iter(&self) -> VmaIter {
        VmaIter {
            leaf: self.first_leaf(),
            index: 0,
        }
    }

    /// Count total MMU pages across all VMAs.
    pub fn total_mmu_pages(&self) -> usize {
        let mut total = 0;
        let mut it = self.iter();
        while let Some(vma) = it.next() {
            total += vma.mmu_page_count();
        }
        total
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Find the leaf that should contain a VMA with the given va_start.
    fn find_leaf(&self, va: usize) -> *mut LeafNode {
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
                        if va < interior.keys[j] {
                            child_idx = j;
                            break;
                        }
                    }
                    node = interior.children[child_idx];
                }
            }
        }
    }

    /// Insert key + vma_ptr at position `pos` in a leaf with room.
    fn insert_at(&self, leaf_ptr: *mut LeafNode, pos: usize, key: usize, vma: *mut Vma) {
        let leaf = unsafe { &mut *leaf_ptr };
        let count = leaf.entry_count as usize;
        for j in (pos..count).rev() {
            leaf.keys[j + 1] = leaf.keys[j];
            leaf.vmas[j + 1] = leaf.vmas[j];
        }
        leaf.keys[pos] = key;
        leaf.vmas[pos] = vma;
        leaf.entry_count += 1;
    }

    /// Remove entry at position `pos` in a leaf.
    fn remove_at(&self, leaf_ptr: *mut LeafNode, pos: usize) {
        let leaf = unsafe { &mut *leaf_ptr };
        let count = leaf.entry_count as usize;
        for j in pos..count - 1 {
            leaf.keys[j] = leaf.keys[j + 1];
            leaf.vmas[j] = leaf.vmas[j + 1];
        }
        leaf.entry_count -= 1;
    }

    /// Split a full leaf and insert.
    fn split_leaf_and_insert(
        &mut self,
        leaf_ptr: *mut LeafNode,
        pos: usize,
        key: usize,
        vma: *mut Vma,
    ) {
        let new_ptr = alloc_node();
        if new_ptr.is_null() {
            return;
        }
        let new_leaf = as_leaf(new_ptr);
        new_leaf.tag = NodeTag::Leaf;

        let old_leaf = unsafe { &mut *leaf_ptr };
        let total = old_leaf.entry_count as usize + 1;

        // Temporary arrays.
        let mut tmp_keys = [0usize; LEAF_CAP + 1];
        let mut tmp_vmas = [ptr::null_mut::<Vma>(); LEAF_CAP + 1];

        for i in 0..pos {
            tmp_keys[i] = old_leaf.keys[i];
            tmp_vmas[i] = old_leaf.vmas[i];
        }
        tmp_keys[pos] = key;
        tmp_vmas[pos] = vma;
        for i in pos..old_leaf.entry_count as usize {
            tmp_keys[i + 1] = old_leaf.keys[i];
            tmp_vmas[i + 1] = old_leaf.vmas[i];
        }

        let mid = total / 2;
        old_leaf.entry_count = mid as u8;
        for i in 0..mid {
            old_leaf.keys[i] = tmp_keys[i];
            old_leaf.vmas[i] = tmp_vmas[i];
        }
        new_leaf.entry_count = (total - mid) as u8;
        for i in 0..(total - mid) {
            new_leaf.keys[i] = tmp_keys[mid + i];
            new_leaf.vmas[i] = tmp_vmas[mid + i];
        }

        // Link siblings.
        let new_leaf_ptr = new_ptr as *mut LeafNode;
        new_leaf.next = old_leaf.next;
        new_leaf.prev = leaf_ptr;
        if !old_leaf.next.is_null() {
            unsafe { (*old_leaf.next).prev = new_leaf_ptr };
        }
        old_leaf.next = new_leaf_ptr;

        let promote_key = new_leaf.keys[0];
        self.insert_into_parent(leaf_ptr as *mut u8, promote_key, new_ptr as *mut u8);
    }

    fn insert_into_parent(&mut self, left: *mut u8, key: usize, right: *mut u8) {
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

        let parent_ptr = self.find_parent(self.root, left);
        if parent_ptr.is_null() {
            return;
        }
        let parent = as_interior(parent_ptr);

        let mut left_idx = 0;
        for i in 0..=parent.key_count as usize {
            if parent.children[i] == left {
                left_idx = i;
                break;
            }
        }

        if (parent.key_count as usize) < ORDER {
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
            self.split_interior_and_insert(parent_ptr, left_idx, key, right);
        }
    }

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

        let mid = total_keys / 2;
        let promote_key = tmp_keys[mid];

        node.key_count = mid as u8;
        for i in 0..mid {
            node.keys[i] = tmp_keys[i];
        }
        for i in 0..=mid {
            node.children[i] = tmp_children[i];
        }

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
        for i in 0..=interior.key_count as usize {
            let result = self.find_parent(interior.children[i], child);
            if !result.is_null() {
                return result;
            }
        }
        ptr::null_mut()
    }

    fn free_tree(&self, node: *mut u8) {
        if node.is_null() {
            return;
        }
        if node_tag(node) == NodeTag::Leaf {
            let leaf = as_leaf(node);
            for i in 0..leaf.entry_count as usize {
                free_vma(leaf.vmas[i]);
            }
        } else {
            let interior = as_interior(node);
            for i in 0..=interior.key_count as usize {
                self.free_tree(interior.children[i]);
            }
        }
        free_node(node);
    }

    /// Free all VMAs and nodes. Resets the tree to empty.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        if !self.root.is_null() {
            self.free_tree(self.root);
            self.root = ptr::null_mut();
            self.count = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Iterator
// ---------------------------------------------------------------------------

/// Iterator over VMAs in VA order (via leaf sibling pointers).
pub struct VmaIter {
    leaf: *mut LeafNode,
    index: usize,
}

impl VmaIter {
    pub fn next(&mut self) -> Option<&mut Vma> {
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
            let vma = unsafe { &mut *leaf.vmas[self.index] };
            self.index += 1;
            return Some(vma);
        }
    }
}

/// WSCLOCK cursor — tracks position within the VMA tree for clock-hand scanning.
/// Replaces the old index-based ClockHand.
#[derive(Clone, Copy)]
pub struct VmaCursor {
    /// Current leaf node.
    #[allow(dead_code)]
    pub leaf: *mut LeafNode,
    /// Index within the current leaf.
    pub leaf_index: usize,
    /// MMU page offset within the current VMA.
    pub mmu_page_offset: usize,
}

unsafe impl Send for VmaCursor {}
unsafe impl Sync for VmaCursor {}

impl VmaCursor {
    pub const fn new() -> Self {
        Self {
            leaf: ptr::null_mut(),
            leaf_index: 0,
            mmu_page_offset: 0,
        }
    }

    /// Get the VMA at the current cursor position, or None if invalid.
    pub fn current_vma(&self) -> Option<&mut Vma> {
        if self.leaf.is_null() {
            return None;
        }
        let leaf = unsafe { &*self.leaf };
        if self.leaf_index >= leaf.entry_count as usize {
            return None;
        }
        Some(unsafe { &mut *leaf.vmas[self.leaf_index] })
    }

    /// Advance to the next VMA (wrapping to first_leaf when reaching the end).
    pub fn advance_vma(&mut self, tree: &VmaTree) {
        if self.leaf.is_null() {
            self.leaf = tree.first_leaf();
            self.leaf_index = 0;
            self.mmu_page_offset = 0;
            return;
        }
        let leaf = unsafe { &*self.leaf };
        self.leaf_index += 1;
        if self.leaf_index >= leaf.entry_count as usize {
            if !leaf.next.is_null() {
                self.leaf = leaf.next;
                self.leaf_index = 0;
            } else {
                // Wrap around.
                self.leaf = tree.first_leaf();
                self.leaf_index = 0;
            }
        }
        self.mmu_page_offset = 0;
    }

    /// Ensure cursor points to a valid position. If the tree has changed
    /// (e.g., VMAs removed), reset to the beginning.
    pub fn validate(&mut self, tree: &VmaTree) {
        if tree.is_empty() {
            *self = Self::new();
            return;
        }
        if self.leaf.is_null() {
            self.leaf = tree.first_leaf();
            self.leaf_index = 0;
            self.mmu_page_offset = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

pub fn run_tests() {
    test_basic_insert_find();
    test_interval_query();
    test_remove();
    test_iteration();
    test_many_inserts();
    crate::println!("  VMA tree: all tests passed");
}

fn test_basic_insert_find() {
    let mut tree = VmaTree::new();
    assert!(tree.is_empty());

    let vma = tree
        .insert(0x1000_0000, 0x10000, super::vma::VmaProt::ReadWrite, 1, 0)
        .unwrap();
    assert_eq!(vma.va_start, 0x1000_0000);
    assert_eq!(vma.va_len, 0x10000);
    assert_eq!(tree.len(), 1);

    // Find at start.
    let found = tree.find(0x1000_0000).unwrap();
    assert_eq!(found.object_id, 1);

    // Find in middle.
    let found = tree.find(0x1000_8000).unwrap();
    assert_eq!(found.va_start, 0x1000_0000);

    // Find at end-1.
    let found = tree.find(0x1000_FFFF).unwrap();
    assert_eq!(found.va_start, 0x1000_0000);

    // Miss: before.
    assert!(tree.find(0x0FFF_FFFF).is_none());

    // Miss: at end (exclusive).
    assert!(tree.find(0x1001_0000).is_none());

    tree.clear();
}

fn test_interval_query() {
    let mut tree = VmaTree::new();

    // Three non-overlapping VMAs.
    tree.insert(0x1000_0000, 0x10000, super::vma::VmaProt::ReadWrite, 1, 0);
    tree.insert(0x2000_0000, 0x20000, super::vma::VmaProt::ReadOnly, 2, 0);
    tree.insert(0x3000_0000, 0x10000, super::vma::VmaProt::ReadExec, 3, 0);
    assert_eq!(tree.len(), 3);

    // Point queries hit the right VMAs.
    assert_eq!(tree.find(0x1000_5000).unwrap().object_id, 1);
    assert_eq!(tree.find(0x2000_1000).unwrap().object_id, 2);
    assert_eq!(tree.find(0x3000_0000).unwrap().object_id, 3);

    // Gaps return None.
    assert!(tree.find(0x1001_0000).is_none());
    assert!(tree.find(0x2002_0000).is_none());

    tree.clear();
}

fn test_remove() {
    let mut tree = VmaTree::new();
    tree.insert(0x1000_0000, 0x10000, super::vma::VmaProt::ReadWrite, 1, 0);
    tree.insert(0x2000_0000, 0x10000, super::vma::VmaProt::ReadWrite, 2, 0);
    assert_eq!(tree.len(), 2);

    assert!(tree.remove(0x1000_0000));
    assert_eq!(tree.len(), 1);
    assert!(tree.find(0x1000_5000).is_none());
    assert!(tree.find(0x2000_5000).is_some());

    assert!(tree.remove(0x2000_0000));
    assert!(tree.is_empty());
}

fn test_iteration() {
    let mut tree = VmaTree::new();
    // Insert in reverse order — iteration should still be VA-sorted.
    tree.insert(0x3000_0000, 0x10000, super::vma::VmaProt::ReadWrite, 3, 0);
    tree.insert(0x1000_0000, 0x10000, super::vma::VmaProt::ReadWrite, 1, 0);
    tree.insert(0x2000_0000, 0x10000, super::vma::VmaProt::ReadWrite, 2, 0);

    let mut it = tree.iter();
    assert_eq!(it.next().unwrap().object_id, 1);
    assert_eq!(it.next().unwrap().object_id, 2);
    assert_eq!(it.next().unwrap().object_id, 3);
    assert!(it.next().is_none());

    tree.clear();
}

fn test_many_inserts() {
    let mut tree = VmaTree::new();
    let n = LEAF_CAP * 3; // Enough to trigger leaf splits.
    for i in 0..n {
        let va = 0x1000_0000 + i * 0x10_0000;
        tree.insert(
            va,
            0x10000,
            super::vma::VmaProt::ReadWrite,
            (i + 1) as u64,
            0,
        );
    }
    assert_eq!(tree.len(), n);

    // All findable.
    for i in 0..n {
        let va = 0x1000_0000 + i * 0x10_0000 + 0x1000;
        let vma = tree.find(va);
        assert!(vma.is_some(), "Missing VMA at index {}", i);
        assert_eq!(vma.unwrap().object_id, (i + 1) as u64);
    }

    // Remove all.
    for i in 0..n {
        let va = 0x1000_0000 + i * 0x10_0000;
        assert!(tree.remove(va));
    }
    assert!(tree.is_empty());
}
