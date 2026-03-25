//! Adaptive Radix Tree (ART) for the port table.
//!
//! Maps 48-bit keys (port local IDs, 44 bits used) to `usize` values.
//! Three inner node sizes: Node4 (64B slab), Node16 (256B slab), Node256 (raw page).
//! Path compression stores up to 6 prefix bytes per node.
//! Leaves are slab-allocated (key, value) pairs tagged with LSB=1.

use crate::mm::slab;
use crate::mm::page::PhysAddr;
use crate::mm::phys;

/// Key length in bytes (48-bit key space, upper 4 bits always 0).
const KEY_LEN: usize = 6;
/// Maximum partial-key bytes stored in a node header.
const MAX_PARTIAL: usize = 6;

/// Extract byte `depth` from a 40-bit key (MSB-first).
#[inline]
fn key_at(key: u64, depth: usize) -> u8 {
    ((key >> (8 * (KEY_LEN - 1 - depth))) & 0xFF) as u8
}

// ---------------------------------------------------------------------------
// Tagged-pointer encoding
// ---------------------------------------------------------------------------
// 0          → empty child slot
// ptr | 1    → leaf  (ptr points to a Leaf, always ≥8-byte aligned)
// ptr (even) → inner node (ptr points to a Header / Node4 / Node16 / Node256)

#[inline]
fn is_leaf(p: usize) -> bool {
    p != 0 && p & 1 != 0
}

#[inline]
fn tag_leaf(p: *mut Leaf) -> usize {
    (p as usize) | 1
}

#[inline]
fn untag_leaf(p: usize) -> *mut Leaf {
    (p & !1usize) as *mut Leaf
}

// ---------------------------------------------------------------------------
// Leaf
// ---------------------------------------------------------------------------

#[repr(C)]
struct Leaf {
    key: u64,
    value: usize,
}

const LEAF_SLAB: usize = 64;

fn alloc_leaf(key: u64, value: usize) -> Option<*mut Leaf> {
    let pa = slab::alloc(LEAF_SLAB)?;
    let p = pa.as_usize() as *mut Leaf;
    unsafe {
        (*p).key = key;
        (*p).value = value;
    }
    Some(p)
}

fn free_leaf(p: *mut Leaf) {
    slab::free(PhysAddr::new(p as usize), LEAF_SLAB);
}

// ---------------------------------------------------------------------------
// Node header (common prefix of every inner node)
// ---------------------------------------------------------------------------

const NODE4: u8 = 4;
const NODE16: u8 = 16;
const NODE256: u8 = 255;

/// 8 bytes: fits at the start of every node type.
#[repr(C)]
struct Header {
    node_type: u8,
    num_children: u8,
    partial_len: u8,
    partial: [u8; MAX_PARTIAL],
}

// ---------------------------------------------------------------------------
// Node4  — up to 4 children, sorted keys
// ---------------------------------------------------------------------------
// Layout: Header(9) + keys(4) + _pad(3) + children(32) = 48 bytes → 64B slab

const NODE4_SLAB: usize = 64;

#[repr(C)]
struct Node4 {
    h: Header,
    keys: [u8; 4],
    _pad: [u8; 3],
    children: [usize; 4],
}

fn alloc_node4(partial: &[u8]) -> Option<*mut Node4> {
    let pa = slab::alloc(NODE4_SLAB)?;
    let p = pa.as_usize() as *mut Node4;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, NODE4_SLAB);
        (*p).h.node_type = NODE4;
        let plen = partial.len().min(MAX_PARTIAL);
        (*p).h.partial_len = plen as u8;
        core::ptr::copy_nonoverlapping(partial.as_ptr(), (*p).h.partial.as_mut_ptr(), plen);
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Node16 — up to 16 children, sorted keys
// ---------------------------------------------------------------------------
// Layout: Header(9) + 7pad + keys(16) + children(128) = 160 bytes → 256B slab

const NODE16_SLAB: usize = 256;

#[repr(C)]
struct Node16 {
    h: Header,
    keys: [u8; 16],
    children: [usize; 16],
}

fn alloc_node16(partial: &[u8]) -> Option<*mut Node16> {
    let pa = slab::alloc(NODE16_SLAB)?;
    let p = pa.as_usize() as *mut Node16;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, NODE16_SLAB);
        (*p).h.node_type = NODE16;
        let plen = partial.len().min(MAX_PARTIAL);
        (*p).h.partial_len = plen as u8;
        core::ptr::copy_nonoverlapping(partial.as_ptr(), (*p).h.partial.as_mut_ptr(), plen);
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Node256 — direct-indexed by byte value
// ---------------------------------------------------------------------------
// Layout: Header(9) + 7pad + children(2048) = 2064 bytes → 4096B slab

#[repr(C)]
struct Node256 {
    h: Header,
    children: [usize; 256],
}

/// Allocate a Node256 from a raw physical page (too large for slab).
fn alloc_node256(partial: &[u8]) -> Option<*mut Node256> {
    let pa = phys::alloc_page()?;
    let p = pa.as_usize() as *mut Node256;
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, crate::mm::page::PAGE_SIZE);
        (*p).h.node_type = NODE256;
        let plen = partial.len().min(MAX_PARTIAL);
        (*p).h.partial_len = plen as u8;
        core::ptr::copy_nonoverlapping(partial.as_ptr(), (*p).h.partial.as_mut_ptr(), plen);
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Free any node by type tag
// ---------------------------------------------------------------------------

unsafe fn free_node(ptr: usize) {
    let h = &*(ptr as *const Header);
    match h.node_type {
        NODE4 => slab::free(PhysAddr::new(ptr), NODE4_SLAB),
        NODE16 => slab::free(PhysAddr::new(ptr), NODE16_SLAB),
        NODE256 => phys::free_page(PhysAddr::new(ptr)),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Child lookup / mutation helpers
// ---------------------------------------------------------------------------

/// Find the child pointer for `byte` in inner node at `node_ptr`. Returns 0 if absent.
unsafe fn find_child(node_ptr: usize, byte: u8) -> usize {
    let h = &*(node_ptr as *const Header);
    match h.node_type {
        NODE4 => {
            let n = &*(node_ptr as *const Node4);
            for i in 0..n.h.num_children as usize {
                if n.keys[i] == byte {
                    return n.children[i];
                }
            }
            0
        }
        NODE16 => {
            let n = &*(node_ptr as *const Node16);
            for i in 0..n.h.num_children as usize {
                if n.keys[i] == byte {
                    return n.children[i];
                }
            }
            0
        }
        NODE256 => {
            let n = &*(node_ptr as *const Node256);
            n.children[byte as usize]
        }
        _ => 0,
    }
}

/// Return a mutable pointer to the child slot for `byte`, or None if absent.
unsafe fn find_child_slot(node_ptr: usize, byte: u8) -> Option<*mut usize> {
    let h = &*(node_ptr as *const Header);
    match h.node_type {
        NODE4 => {
            let n = &mut *(node_ptr as *mut Node4);
            for i in 0..n.h.num_children as usize {
                if n.keys[i] == byte {
                    return Some(&mut n.children[i] as *mut usize);
                }
            }
            None
        }
        NODE16 => {
            let n = &mut *(node_ptr as *mut Node16);
            for i in 0..n.h.num_children as usize {
                if n.keys[i] == byte {
                    return Some(&mut n.children[i] as *mut usize);
                }
            }
            None
        }
        NODE256 => {
            let n = &mut *(node_ptr as *mut Node256);
            if n.children[byte as usize] != 0 {
                Some(&mut n.children[byte as usize] as *mut usize)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Add a child to the node at `*node_slot`. Grows the node if full.
/// Updates `*node_slot` if the node is replaced (growth).
/// Returns false on allocation failure.
unsafe fn add_child(node_slot: *mut usize, byte: u8, child: usize) -> bool {
    let node_ptr = *node_slot;
    let h = &*(node_ptr as *const Header);
    match h.node_type {
        NODE4 => {
            let n = &mut *(node_ptr as *mut Node4);
            if (n.h.num_children as usize) < 4 {
                // Insert sorted.
                let nc = n.h.num_children as usize;
                let mut pos = nc;
                for i in 0..nc {
                    if byte < n.keys[i] {
                        pos = i;
                        break;
                    }
                }
                // Shift right.
                for i in (pos..nc).rev() {
                    n.keys[i + 1] = n.keys[i];
                    n.children[i + 1] = n.children[i];
                }
                n.keys[pos] = byte;
                n.children[pos] = child;
                n.h.num_children += 1;
                true
            } else {
                // Grow to Node16.
                grow_to_16(node_slot, byte, child)
            }
        }
        NODE16 => {
            let n = &mut *(node_ptr as *mut Node16);
            if (n.h.num_children as usize) < 16 {
                let nc = n.h.num_children as usize;
                let mut pos = nc;
                for i in 0..nc {
                    if byte < n.keys[i] {
                        pos = i;
                        break;
                    }
                }
                for i in (pos..nc).rev() {
                    n.keys[i + 1] = n.keys[i];
                    n.children[i + 1] = n.children[i];
                }
                n.keys[pos] = byte;
                n.children[pos] = child;
                n.h.num_children += 1;
                true
            } else {
                // Grow to Node256.
                grow_to_256(node_slot, byte, child)
            }
        }
        NODE256 => {
            let n = &mut *(node_ptr as *mut Node256);
            n.children[byte as usize] = child;
            n.h.num_children = n.h.num_children.saturating_add(1);
            true
        }
        _ => false,
    }
}

/// Remove child `byte` from inner node. Does not shrink nodes.
unsafe fn remove_child(node_ptr: usize, byte: u8) {
    let h = &*(node_ptr as *const Header);
    match h.node_type {
        NODE4 => {
            let n = &mut *(node_ptr as *mut Node4);
            let nc = n.h.num_children as usize;
            for i in 0..nc {
                if n.keys[i] == byte {
                    // Shift left.
                    for j in i..nc - 1 {
                        n.keys[j] = n.keys[j + 1];
                        n.children[j] = n.children[j + 1];
                    }
                    n.keys[nc - 1] = 0;
                    n.children[nc - 1] = 0;
                    n.h.num_children -= 1;
                    return;
                }
            }
        }
        NODE16 => {
            let n = &mut *(node_ptr as *mut Node16);
            let nc = n.h.num_children as usize;
            for i in 0..nc {
                if n.keys[i] == byte {
                    for j in i..nc - 1 {
                        n.keys[j] = n.keys[j + 1];
                        n.children[j] = n.children[j + 1];
                    }
                    n.keys[nc - 1] = 0;
                    n.children[nc - 1] = 0;
                    n.h.num_children -= 1;
                    return;
                }
            }
        }
        NODE256 => {
            let n = &mut *(node_ptr as *mut Node256);
            if n.children[byte as usize] != 0 {
                n.children[byte as usize] = 0;
                n.h.num_children = n.h.num_children.saturating_sub(1);
            }
        }
        _ => {}
    }
}

/// Number of children in a node.
unsafe fn num_children(node_ptr: usize) -> u8 {
    (*(node_ptr as *const Header)).num_children
}

// ---------------------------------------------------------------------------
// Node growth
// ---------------------------------------------------------------------------

/// Grow Node4 → Node16. Adds the new (byte, child) entry.
unsafe fn grow_to_16(node_slot: *mut usize, byte: u8, child: usize) -> bool {
    let old_ptr = *node_slot;
    let old = &*(old_ptr as *const Node4);
    let plen = old.h.partial_len as usize;
    let new = match alloc_node16(&old.h.partial[..plen]) {
        Some(p) => p,
        None => return false,
    };
    // Copy existing children.
    let nc = old.h.num_children as usize;
    for i in 0..nc {
        (*new).keys[i] = old.keys[i];
        (*new).children[i] = old.children[i];
    }
    (*new).h.num_children = nc as u8;
    // Insert the new child (sorted).
    let n = &mut *new;
    let mut pos = nc;
    for i in 0..nc {
        if byte < n.keys[i] {
            pos = i;
            break;
        }
    }
    for i in (pos..nc).rev() {
        n.keys[i + 1] = n.keys[i];
        n.children[i + 1] = n.children[i];
    }
    n.keys[pos] = byte;
    n.children[pos] = child;
    n.h.num_children += 1;
    // Replace node.
    *node_slot = new as usize;
    slab::free(PhysAddr::new(old_ptr), NODE4_SLAB);
    true
}

/// Grow Node16 → Node256. Adds the new (byte, child) entry.
unsafe fn grow_to_256(node_slot: *mut usize, byte: u8, child: usize) -> bool {
    let old_ptr = *node_slot;
    let old = &*(old_ptr as *const Node16);
    let plen = old.h.partial_len as usize;
    let new = match alloc_node256(&old.h.partial[..plen]) {
        Some(p) => p,
        None => return false,
    };
    // Scatter existing children into direct-index slots.
    let nc = old.h.num_children as usize;
    for i in 0..nc {
        (*new).children[old.keys[i] as usize] = old.children[i];
    }
    (*new).children[byte as usize] = child;
    (*new).h.num_children = (nc + 1) as u8;
    // Replace node.
    *node_slot = new as usize;
    slab::free(PhysAddr::new(old_ptr), NODE16_SLAB);
    true
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// An Adaptive Radix Tree mapping 48-bit keys to usize values.
pub struct Art {
    root: usize,
    len: usize,
}

impl Art {
    pub const fn new() -> Self {
        Self { root: 0, len: 0 }
    }

    /// Number of entries in the tree.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Look up a value by 40-bit key.
    pub fn lookup(&self, key: u64) -> Option<usize> {
        let mut node = self.root;
        let mut depth: usize = 0;

        loop {
            if node == 0 {
                return None;
            }
            if is_leaf(node) {
                let leaf = unsafe { &*untag_leaf(node) };
                return if leaf.key == key { Some(leaf.value) } else { None };
            }

            let h = unsafe { &*(node as *const Header) };
            let plen = h.partial_len as usize;

            // Verify partial key.
            for i in 0..plen {
                if depth + i >= KEY_LEN || h.partial[i] != key_at(key, depth + i) {
                    return None;
                }
            }
            depth += plen;

            if depth >= KEY_LEN {
                return None;
            }

            let byte = key_at(key, depth);
            node = unsafe { find_child(node, byte) };
            depth += 1;
        }
    }

    /// Insert a (key, value) pair. Returns true on success, false on OOM.
    /// If the key already exists, the value is updated.
    pub fn insert(&mut self, key: u64, value: usize) -> bool {
        // Pre-allocate the leaf.
        let leaf = match alloc_leaf(key, value) {
            Some(l) => l,
            None => return false,
        };

        if self.root == 0 {
            self.root = tag_leaf(leaf);
            self.len += 1;
            return true;
        }

        // Use raw pointers to root and len to avoid &mut self aliasing with
        // the slot pointer (which initially points to self.root).
        let root_ptr = &mut self.root as *mut usize;
        let len_ptr = &mut self.len as *mut usize;
        let ok = unsafe { insert_inner(root_ptr, len_ptr, key, value, leaf, 0) };
        if !ok {
            free_leaf(leaf);
        }
        ok
    }

    /// Remove an entry by key. Returns the value if found.
    pub fn remove(&mut self, key: u64) -> Option<usize> {
        if self.root == 0 {
            return None;
        }
        let root_ptr = &mut self.root as *mut usize;
        let len_ptr = &mut self.len as *mut usize;
        unsafe { remove_inner(root_ptr, len_ptr, key, 0) }
    }

    /// Iterate over all (key, value) pairs. Calls `f(key, value)` for each.
    pub fn for_each<F: FnMut(u64, usize)>(&self, mut f: F) {
        if self.root != 0 {
            unsafe { for_each_inner(self.root, &mut f) };
        }
    }
}

// ---------------------------------------------------------------------------
// Free functions for insert/remove — avoids &mut self aliasing with slot ptrs
// ---------------------------------------------------------------------------

/// Recursive insert into the subtree rooted at `*slot`.
/// `len_ptr` points to the tree's length counter.
/// `new_leaf` is a pre-allocated Leaf; caller frees it on failure.
unsafe fn insert_inner(
    slot: *mut usize,
    len_ptr: *mut usize,
    key: u64,
    value: usize,
    new_leaf: *mut Leaf,
    depth: usize,
) -> bool {
    let current = *slot;

    if current == 0 {
        *slot = tag_leaf(new_leaf);
        *len_ptr += 1;
        return true;
    }

    if is_leaf(current) {
        let existing = &*untag_leaf(current);
        if existing.key == key {
            (*untag_leaf(current)).value = value;
            free_leaf(new_leaf);
            return true;
        }
        return split_leaves(slot, len_ptr, current, new_leaf, key, depth);
    }

    let h = &*(current as *const Header);
    let plen = h.partial_len as usize;

    let mut match_len: usize = 0;
    for i in 0..plen {
        if depth + i >= KEY_LEN || h.partial[i] != key_at(key, depth + i) {
            break;
        }
        match_len += 1;
    }

    if match_len < plen {
        return split_node(slot, len_ptr, new_leaf, key, depth, match_len);
    }

    let new_depth = depth + plen;
    if new_depth >= KEY_LEN {
        free_leaf(new_leaf);
        return false;
    }

    let byte = key_at(key, new_depth);

    if let Some(child_slot) = find_child_slot(current, byte) {
        return insert_inner(child_slot, len_ptr, key, value, new_leaf, new_depth + 1);
    }

    if add_child(slot, byte, tag_leaf(new_leaf)) {
        *len_ptr += 1;
        true
    } else {
        false
    }
}

/// Split two leaves that share a prefix starting at `depth`.
unsafe fn split_leaves(
    slot: *mut usize,
    len_ptr: *mut usize,
    existing_tagged: usize,
    new_leaf: *mut Leaf,
    new_key: u64,
    depth: usize,
) -> bool {
    let existing = &*untag_leaf(existing_tagged);
    let old_key = existing.key;

    let mut prefix_len: usize = 0;
    while depth + prefix_len < KEY_LEN
        && key_at(old_key, depth + prefix_len) == key_at(new_key, depth + prefix_len)
    {
        prefix_len += 1;
    }

    let mut partial = [0u8; MAX_PARTIAL];
    let plen = prefix_len.min(MAX_PARTIAL);
    for i in 0..plen {
        partial[i] = key_at(old_key, depth + i);
    }

    let node = match alloc_node4(&partial[..plen]) {
        Some(n) => n,
        None => return false,
    };

    let diverge = depth + prefix_len;
    if diverge >= KEY_LEN {
        slab::free(PhysAddr::new(node as usize), NODE4_SLAB);
        return false;
    }

    let old_byte = key_at(old_key, diverge);
    let new_byte = key_at(new_key, diverge);

    if old_byte < new_byte {
        (*node).keys[0] = old_byte;
        (*node).children[0] = existing_tagged;
        (*node).keys[1] = new_byte;
        (*node).children[1] = tag_leaf(new_leaf);
    } else {
        (*node).keys[0] = new_byte;
        (*node).children[0] = tag_leaf(new_leaf);
        (*node).keys[1] = old_byte;
        (*node).children[1] = existing_tagged;
    }
    (*node).h.num_children = 2;

    *slot = node as usize;
    *len_ptr += 1;
    true
}

/// Split an inner node whose partial key mismatches at position `match_len`.
unsafe fn split_node(
    slot: *mut usize,
    len_ptr: *mut usize,
    new_leaf: *mut Leaf,
    new_key: u64,
    depth: usize,
    match_len: usize,
) -> bool {
    let old_node_ptr = *slot;
    let old_h = &mut *(old_node_ptr as *mut Header);
    let old_plen = old_h.partial_len as usize;

    let mut new_partial = [0u8; MAX_PARTIAL];
    let nplen = match_len.min(MAX_PARTIAL);
    for i in 0..nplen {
        new_partial[i] = old_h.partial[i];
    }

    let parent = match alloc_node4(&new_partial[..nplen]) {
        Some(n) => n,
        None => return false,
    };

    let old_byte = old_h.partial[match_len];
    let new_byte = key_at(new_key, depth + match_len);

    let remaining = old_plen - match_len - 1;
    let mut shortened = [0u8; MAX_PARTIAL];
    for i in 0..remaining.min(MAX_PARTIAL) {
        shortened[i] = old_h.partial[match_len + 1 + i];
    }
    old_h.partial_len = remaining as u8;
    old_h.partial[..MAX_PARTIAL].copy_from_slice(&shortened);

    if old_byte < new_byte {
        (*parent).keys[0] = old_byte;
        (*parent).children[0] = old_node_ptr;
        (*parent).keys[1] = new_byte;
        (*parent).children[1] = tag_leaf(new_leaf);
    } else {
        (*parent).keys[0] = new_byte;
        (*parent).children[0] = tag_leaf(new_leaf);
        (*parent).keys[1] = old_byte;
        (*parent).children[1] = old_node_ptr;
    }
    (*parent).h.num_children = 2;

    *slot = parent as usize;
    *len_ptr += 1;
    true
}

/// Recursive remove. `slot` points to the child pointer in the parent.
unsafe fn remove_inner(
    slot: *mut usize,
    len_ptr: *mut usize,
    key: u64,
    depth: usize,
) -> Option<usize> {
    let current = *slot;
    if current == 0 {
        return None;
    }

    if is_leaf(current) {
        let leaf = &*untag_leaf(current);
        if leaf.key == key {
            let value = leaf.value;
            free_leaf(untag_leaf(current));
            *slot = 0;
            *len_ptr -= 1;
            return Some(value);
        }
        return None;
    }

    let h = &*(current as *const Header);
    let plen = h.partial_len as usize;

    for i in 0..plen {
        if depth + i >= KEY_LEN || h.partial[i] != key_at(key, depth + i) {
            return None;
        }
    }
    let new_depth = depth + plen;
    if new_depth >= KEY_LEN {
        return None;
    }

    let byte = key_at(key, new_depth);
    let child_slot = find_child_slot(current, byte)?;

    let result = remove_inner(child_slot, len_ptr, key, new_depth + 1);
    if result.is_some() {
        if *child_slot == 0 {
            remove_child(current, byte);
        }
        if num_children(current) == 0 {
            free_node(current);
            *slot = 0;
        }
    }
    result
}

unsafe fn for_each_inner<F: FnMut(u64, usize)>(node: usize, f: &mut F) {
    if node == 0 {
        return;
    }
    if is_leaf(node) {
        let leaf = &*untag_leaf(node);
        f(leaf.key, leaf.value);
        return;
    }
    let h = &*(node as *const Header);
    match h.node_type {
        NODE4 => {
            let n = &*(node as *const Node4);
            for i in 0..n.h.num_children as usize {
                for_each_inner(n.children[i], f);
            }
        }
        NODE16 => {
            let n = &*(node as *const Node16);
            for i in 0..n.h.num_children as usize {
                for_each_inner(n.children[i], f);
            }
        }
        NODE256 => {
            let n = &*(node as *const Node256);
            for i in 0..256 {
                if n.children[i] != 0 {
                    for_each_inner(n.children[i], f);
                }
            }
        }
        _ => {}
    }
}
