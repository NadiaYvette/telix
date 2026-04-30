//! Adaptive Radix Tree (ART) for the port table.
//!
//! Maps 48-bit keys (port local IDs, 44 bits used) to `usize` values.
//! Three inner node sizes: Node4 (64B slab), Node16 (256B slab), Node256 (raw page).
//! Path compression stores up to 6 prefix bytes per node.
//! Leaves are slab-allocated (key, value) pairs tagged with LSB=1.
//!
//! **Concurrency model (RCU):**
//! - `lookup` / `for_each` are lock-free readers using atomic loads.
//! - `insert` / `remove` are externally serialized (single writer).
//! - Mutations use COW for Node4/Node16 (no in-place shifts visible to
//!   readers) and deferred free via RCU for replaced nodes.

use crate::mm::page::PhysAddr;
use crate::mm::phys;
use crate::mm::slab;
use core::sync::atomic::{AtomicUsize, Ordering};

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
// Atomic slot helpers
// ---------------------------------------------------------------------------
// Children are stored as plain `usize` in repr(C) node structs (for slab
// layout compatibility). We access them atomically via casts to AtomicUsize,
// which has the same size and alignment (guaranteed by Rust).

#[inline]
unsafe fn slot_load(p: *const usize) -> usize {
    unsafe { (*(p as *const AtomicUsize)).load(Ordering::Acquire) }
}

#[inline]
unsafe fn slot_store(p: *mut usize, val: usize) {
    unsafe { (*(p as *mut AtomicUsize)).store(val, Ordering::Release) }
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

/// Defer-free a published leaf (reclaimed after RCU grace period).
fn rcu_defer_free_leaf(p: *mut Leaf) {
    crate::sync::rcu::rcu_defer_free(p as usize, crate::sync::rcu::free_slab64_callback);
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
        // Source-aliasing guard: if `partial` points into the slab block
        // we just got back, write_bytes would zero the source bytes
        // before copy_nonoverlapping reads them. Snapshot to a local
        // first to break the alias.
        let plen = partial.len().min(MAX_PARTIAL);
        let mut snapshot = [0u8; MAX_PARTIAL];
        for i in 0..plen {
            snapshot[i] = partial[i];
        }
        core::ptr::write_bytes(p as *mut u8, 0, NODE16_SLAB);
        (*p).h.node_type = NODE16;
        (*p).h.partial_len = plen as u8;
        core::ptr::copy_nonoverlapping(snapshot.as_ptr(), (*p).h.partial.as_mut_ptr(), plen);
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
        core::ptr::write_bytes(p as *mut u8, 0, crate::mm::page::page_size());
        (*p).h.node_type = NODE256;
        let plen = partial.len().min(MAX_PARTIAL);
        (*p).h.partial_len = plen as u8;
        core::ptr::copy_nonoverlapping(partial.as_ptr(), (*p).h.partial.as_mut_ptr(), plen);
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Free a node immediately (only for nodes that were never published to readers).
unsafe fn free_node(ptr: usize) {
    unsafe {
        let h = &*(ptr as *const Header);
        match h.node_type {
            NODE4 => slab::free(PhysAddr::new(ptr), NODE4_SLAB),
            NODE16 => slab::free(PhysAddr::new(ptr), NODE16_SLAB),
            NODE256 => phys::free_page(PhysAddr::new(ptr)),
            _ => {}
        }
    }
}

/// Defer-free a published node (reclaimed after RCU grace period).
fn rcu_defer_free_node(ptr: usize) {
    let free_fn = unsafe {
        let h = &*(ptr as *const Header);
        match h.node_type {
            NODE4 => crate::sync::rcu::free_slab64_callback as fn(usize),
            NODE16 => crate::sync::rcu::free_slab256_callback as fn(usize),
            NODE256 => crate::sync::rcu::free_page_callback as fn(usize),
            _ => return,
        }
    };
    crate::sync::rcu::rcu_defer_free(ptr, free_fn);
}

// ---------------------------------------------------------------------------
// Reader-path child lookup (lock-free, uses atomic loads)
// ---------------------------------------------------------------------------

/// Find the child pointer for `byte` in inner node at `node_ptr`.
/// Returns 0 if absent. Uses atomic loads for RCU-safe reading.
unsafe fn find_child(node_ptr: usize, byte: u8) -> usize {
    unsafe {
        let h = &*(node_ptr as *const Header);
        match h.node_type {
            NODE4 => {
                let n = &*(node_ptr as *const Node4);
                for i in 0..n.h.num_children as usize {
                    if n.keys[i] == byte {
                        return slot_load(&n.children[i]);
                    }
                }
                0
            }
            NODE16 => {
                let n = &*(node_ptr as *const Node16);
                for i in 0..n.h.num_children as usize {
                    if n.keys[i] == byte {
                        return slot_load(&n.children[i]);
                    }
                }
                0
            }
            NODE256 => {
                let n = &*(node_ptr as *const Node256);
                slot_load(&n.children[byte as usize])
            }
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Writer-path child slot (under external write serialization)
// ---------------------------------------------------------------------------

/// Return a mutable pointer to the child slot for `byte`, or None if absent.
/// Writer-only: the returned pointer is used for atomic stores by recursive
/// insert/remove operations.
unsafe fn find_child_slot(node_ptr: usize, byte: u8) -> Option<*mut usize> {
    unsafe {
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
}

// ---------------------------------------------------------------------------
// COW add_child — allocates new node with entry inserted, publishes
// atomically, defers free of old node.
// ---------------------------------------------------------------------------

/// Add a child to the node at `*node_slot`. Grows the node if full.
/// Uses COW for Node4/Node16 (allocate new, copy with insertion, publish).
/// Node256 uses a single atomic store (no COW needed).
unsafe fn add_child(node_slot: *mut usize, byte: u8, child: usize) -> bool {
    unsafe {
        let node_ptr = *node_slot;
        let h = &*(node_ptr as *const Header);
        match h.node_type {
            NODE4 => {
                let old = &*(node_ptr as *const Node4);
                if (old.h.num_children as usize) < 4 {
                    let nc = old.h.num_children as usize;
                    let plen = old.h.partial_len as usize;
                    let new = match alloc_node4(&old.h.partial[..plen]) {
                        Some(p) => p,
                        None => return false,
                    };
                    let mut pos = nc;
                    for i in 0..nc {
                        if byte < old.keys[i] {
                            pos = i;
                            break;
                        }
                    }
                    let n = &mut *new;
                    for i in 0..pos {
                        n.keys[i] = old.keys[i];
                        n.children[i] = old.children[i];
                    }
                    n.keys[pos] = byte;
                    n.children[pos] = child;
                    for i in pos..nc {
                        n.keys[i + 1] = old.keys[i];
                        n.children[i + 1] = old.children[i];
                    }
                    n.h.num_children = (nc + 1) as u8;
                    slot_store(node_slot, new as usize);
                    rcu_defer_free_node(node_ptr);
                    true
                } else {
                    grow_to_16(node_slot, byte, child)
                }
            }
            NODE16 => {
                let old = &*(node_ptr as *const Node16);
                if (old.h.num_children as usize) < 16 {
                    let nc = old.h.num_children as usize;
                    let plen = old.h.partial_len as usize;
                    let new = match alloc_node16(&old.h.partial[..plen]) {
                        Some(p) => p,
                        None => return false,
                    };
                    let mut pos = nc;
                    for i in 0..nc {
                        if byte < old.keys[i] {
                            pos = i;
                            break;
                        }
                    }
                    let n = &mut *new;
                    for i in 0..pos {
                        n.keys[i] = old.keys[i];
                        n.children[i] = old.children[i];
                    }
                    n.keys[pos] = byte;
                    n.children[pos] = child;
                    for i in pos..nc {
                        n.keys[i + 1] = old.keys[i];
                        n.children[i + 1] = old.children[i];
                    }
                    n.h.num_children = (nc + 1) as u8;
                    slot_store(node_slot, new as usize);
                    rcu_defer_free_node(node_ptr);
                    true
                } else {
                    grow_to_256(node_slot, byte, child)
                }
            }
            NODE256 => {
                let n = &mut *(node_ptr as *mut Node256);
                slot_store(&mut n.children[byte as usize], child);
                n.h.num_children = n.h.num_children.saturating_add(1);
                true
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Node growth (COW + deferred free)
// ---------------------------------------------------------------------------

/// Grow Node4 → Node16. Adds the new (byte, child) entry.
unsafe fn grow_to_16(node_slot: *mut usize, byte: u8, child: usize) -> bool {
    unsafe {
        let old_ptr = *node_slot;
        let old = &*(old_ptr as *const Node4);
        let plen = old.h.partial_len as usize;
        let new = match alloc_node16(&old.h.partial[..plen]) {
            Some(p) => p,
            None => return false,
        };
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
        slot_store(node_slot, new as usize);
        rcu_defer_free_node(old_ptr);
        true
    }
}

/// Grow Node16 → Node256. Adds the new (byte, child) entry.
unsafe fn grow_to_256(node_slot: *mut usize, byte: u8, child: usize) -> bool {
    unsafe {
        let old_ptr = *node_slot;
        let old = &*(old_ptr as *const Node16);
        let plen = old.h.partial_len as usize;
        let new = match alloc_node256(&old.h.partial[..plen]) {
            Some(p) => p,
            None => return false,
        };
        let nc = old.h.num_children as usize;
        for i in 0..nc {
            (*new).children[old.keys[i] as usize] = old.children[i];
        }
        (*new).children[byte as usize] = child;
        (*new).h.num_children = (nc + 1) as u8;
        slot_store(node_slot, new as usize);
        rcu_defer_free_node(old_ptr);
        true
    }
}

// ---------------------------------------------------------------------------
// COW remove child (Node4/Node16 only — Node256 uses atomic zero)
// ---------------------------------------------------------------------------

/// Allocate a new node of the same type without the entry for `byte`.
unsafe fn cow_node_remove_child(node_ptr: usize, byte: u8) -> Option<usize> {
    unsafe {
        let h = &*(node_ptr as *const Header);
        match h.node_type {
            NODE4 => {
                let old = &*(node_ptr as *const Node4);
                let nc = old.h.num_children as usize;
                let plen = old.h.partial_len as usize;
                let new = alloc_node4(&old.h.partial[..plen])?;
                let n = &mut *new;
                let mut j = 0;
                for i in 0..nc {
                    if old.keys[i] != byte {
                        n.keys[j] = old.keys[i];
                        n.children[j] = old.children[i];
                        j += 1;
                    }
                }
                n.h.num_children = j as u8;
                Some(new as usize)
            }
            NODE16 => {
                let old = &*(node_ptr as *const Node16);
                let nc = old.h.num_children as usize;
                let plen = old.h.partial_len as usize;
                let new = alloc_node16(&old.h.partial[..plen])?;
                let n = &mut *new;
                let mut j = 0;
                for i in 0..nc {
                    if old.keys[i] != byte {
                        n.keys[j] = old.keys[i];
                        n.children[j] = old.children[i];
                        j += 1;
                    }
                }
                n.h.num_children = j as u8;
                Some(new as usize)
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// COW clone node with new partial (for split_node)
// ---------------------------------------------------------------------------

/// Clone an inner node with a new partial key. All children are copied.
unsafe fn clone_node_with_partial(old_ptr: usize, new_partial: &[u8]) -> Option<usize> {
    unsafe {
        let h = &*(old_ptr as *const Header);
        match h.node_type {
            NODE4 => {
                let old = &*(old_ptr as *const Node4);
                let new = alloc_node4(new_partial)?;
                (*new).h.num_children = old.h.num_children;
                (*new).keys = old.keys;
                (*new).children = old.children;
                Some(new as usize)
            }
            NODE16 => {
                let old = &*(old_ptr as *const Node16);
                let new = alloc_node16(new_partial)?;
                (*new).h.num_children = old.h.num_children;
                (*new).keys = old.keys;
                (*new).children = old.children;
                Some(new as usize)
            }
            NODE256 => {
                let old = &*(old_ptr as *const Node256);
                let new = alloc_node256(new_partial)?;
                (*new).h.num_children = old.h.num_children;
                (*new).children = old.children;
                Some(new as usize)
            }
            _ => None,
        }
    }
}

/// Number of children in a node.
unsafe fn num_children(node_ptr: usize) -> u8 {
    unsafe { (*(node_ptr as *const Header)).num_children }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Global write serialization lock for ART mutations.
/// Readers (lookup) never acquire this. Writers (insert/remove) are
/// Write serializer for ART structural mutations (insert/remove/grow).
/// Readers are lock-free via RCU; only writers need this lock.
pub static ART_WRITE_LOCK: crate::sync::SpinLock<()> = crate::sync::SpinLock::new(());

/// When true, `Art::insert` runs a post-insert lookup self-check and
/// dumps structural state on mismatch. Off by default to avoid runtime
/// cost; enabled by the kernel-side ART stress harness.
pub static SELF_CHECK_INSERT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Structured outcome of a diagnostic lookup. See `Art::lookup_diag`.
/// `Display` is implemented via `print_lookup_outcome` (no_std-friendly
/// — emits via `println!` directly so we don't have to plumb a fmt::Write).
#[derive(Copy, Clone)]
pub enum LookupOutcome {
    Found(usize),
    EmptySlot { step: u32, depth: u32 },
    LeafKeyMismatch { leaf_key: u64, wanted: u64, depth: u32 },
    PartialMismatch { depth: u32, partial_byte: u8, wanted: u8, node_ptr: usize, node_type: u8 },
    DepthExceededInPartial { depth: u32, plen: u32 },
    DepthExceededAfterPartial { depth: u32 },
    MissingChild { depth: u32, byte: u8, node_ptr: usize, node_type: u8, num_children: u8 },
    WalkRunaway { depth: u32 },
}

/// Emit a single-line description of a LookupOutcome to the kernel log.
pub fn print_lookup_outcome(prefix: &str, key: u64, outcome: LookupOutcome) {
    match outcome {
        LookupOutcome::Found(v) =>
            crate::println!("{}: key={} → Found(value={:#x})", prefix, key, v),
        LookupOutcome::EmptySlot { step, depth } =>
            crate::println!("{}: key={} → EmptySlot step={} depth={}", prefix, key, step, depth),
        LookupOutcome::LeafKeyMismatch { leaf_key, wanted, depth } =>
            crate::println!(
                "{}: key={} → LeafKeyMismatch leaf_key={} wanted={} depth={}",
                prefix, key, leaf_key, wanted, depth
            ),
        LookupOutcome::PartialMismatch { depth, partial_byte, wanted, node_ptr, node_type } =>
            crate::println!(
                "{}: key={} → PartialMismatch depth={} partial={:#x} wanted={:#x} node={:#x} type={}",
                prefix, key, depth, partial_byte, wanted, node_ptr, node_type
            ),
        LookupOutcome::DepthExceededInPartial { depth, plen } =>
            crate::println!(
                "{}: key={} → DepthExceededInPartial depth={} plen={}",
                prefix, key, depth, plen
            ),
        LookupOutcome::DepthExceededAfterPartial { depth } =>
            crate::println!("{}: key={} → DepthExceededAfterPartial depth={}", prefix, key, depth),
        LookupOutcome::MissingChild { depth, byte, node_ptr, node_type, num_children } =>
            crate::println!(
                "{}: key={} → MissingChild depth={} byte={:#x} node={:#x} type={} nc={}",
                prefix, key, depth, byte, node_ptr, node_type, num_children
            ),
        LookupOutcome::WalkRunaway { depth } =>
            crate::println!("{}: key={} → WalkRunaway depth={}", prefix, key, depth),
    }
}

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
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Lock-free lookup by 40-bit key (RCU read-side, no lock needed).
    /// Safe to call concurrently with mutations on other CPUs.
    pub fn lookup(&self, key: u64) -> Option<usize> {
        let mut node = unsafe { slot_load(&self.root) };
        let mut depth: usize = 0;

        loop {
            if node == 0 {
                return None;
            }
            if is_leaf(node) {
                let leaf = unsafe { &*untag_leaf(node) };
                return if leaf.key == key {
                    Some(leaf.value)
                } else {
                    None
                };
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

    /// Lookup with structured outcome — used by diagnostic call sites.
    /// Walks the same path as `lookup` but reports exactly which step
    /// failed, so a single repro of an invariant violation pinpoints the
    /// faulting descent step instead of just yielding a None.
    pub fn lookup_diag(&self, key: u64) -> LookupOutcome {
        let root = unsafe { slot_load(&self.root) };
        let mut node = root;
        let mut depth: usize = 0;
        let mut step: u32 = 0;

        loop {
            if node == 0 {
                return LookupOutcome::EmptySlot {
                    step,
                    depth: depth as u32,
                };
            }
            if is_leaf(node) {
                let leaf = unsafe { &*untag_leaf(node) };
                if leaf.key == key {
                    return LookupOutcome::Found(leaf.value);
                } else {
                    return LookupOutcome::LeafKeyMismatch {
                        leaf_key: leaf.key,
                        wanted: key,
                        depth: depth as u32,
                    };
                }
            }

            let h = unsafe { &*(node as *const Header) };
            let plen = h.partial_len as usize;
            let nt = h.node_type;
            let nc = h.num_children;

            for i in 0..plen {
                if depth + i >= KEY_LEN {
                    return LookupOutcome::DepthExceededInPartial {
                        depth: (depth + i) as u32,
                        plen: plen as u32,
                    };
                }
                let want = key_at(key, depth + i);
                if h.partial[i] != want {
                    return LookupOutcome::PartialMismatch {
                        depth: (depth + i) as u32,
                        partial_byte: h.partial[i],
                        wanted: want,
                        node_ptr: node,
                        node_type: nt,
                    };
                }
            }
            depth += plen;

            if depth >= KEY_LEN {
                return LookupOutcome::DepthExceededAfterPartial {
                    depth: depth as u32,
                };
            }

            let byte = key_at(key, depth);
            let next = unsafe { find_child(node, byte) };
            if next == 0 {
                return LookupOutcome::MissingChild {
                    depth: depth as u32,
                    byte,
                    node_ptr: node,
                    node_type: nt,
                    num_children: nc,
                };
            }
            node = next;
            depth += 1;
            step += 1;
            if step > 32 {
                return LookupOutcome::WalkRunaway { depth: depth as u32 };
            }
        }
    }

    /// Snapshot of the root pointer (atomic load) — for diagnostics that
    /// want to compare what the writer just published with what the
    /// reader observed on the same thread.
    pub fn root_snapshot(&self) -> usize {
        unsafe { slot_load(&self.root) }
    }

    /// Insert a (key, value) pair. Returns true on success, false on OOM.
    /// If the key already exists, the value is updated.
    /// Must be called under write serialization.
    pub fn insert(&mut self, key: u64, value: usize) -> bool {
        // Pre-allocate the leaf.
        let leaf = match alloc_leaf(key, value) {
            Some(l) => l,
            None => return false,
        };

        if self.root == 0 {
            unsafe {
                slot_store(&mut self.root, tag_leaf(leaf));
            }
            self.len += 1;
            return true;
        }

        let root_ptr = &mut self.root as *mut usize;
        let len_ptr = &mut self.len as *mut usize;
        let ok = unsafe { insert_inner(root_ptr, len_ptr, key, value, leaf, 0) };
        if !ok {
            free_leaf(leaf);
        }
        // Post-insert self-check: a successful insert of `key` MUST be
        // immediately resolvable by lookup. Failure here is a structural
        // bug in the ART (not a race — `insert` is serialized).
        if ok && SELF_CHECK_INSERT.load(Ordering::Relaxed) {
            if self.lookup(key).is_none() {
                let outcome = self.lookup_diag(key);
                crate::println!(
                    "ART self-check: insert(key={}) returned true but lookup failed. root={:#x}",
                    key, unsafe { slot_load(&self.root) }
                );
                print_lookup_outcome("  self-check", key, outcome);
                self.dump_root_partial(key);
            }
        }
        ok
    }

    /// Public root dump for stress-test instrumentation.
    pub fn debug_dump_root(&self, label: &str) {
        let root = unsafe { slot_load(&self.root) };
        if root == 0 {
            crate::println!("  [{}] root: empty", label);
            return;
        }
        if is_leaf(root) {
            let leaf = unsafe { &*untag_leaf(root) };
            crate::println!("  [{}] root: leaf key={} value={:#x}", label, leaf.key, leaf.value);
            return;
        }
        unsafe {
            let h = &*(root as *const Header);
            crate::println!(
                "  [{}] root addr={:#x} type={} nc={} plen={} partial={:02x?}",
                label, root, h.node_type, h.num_children, h.partial_len,
                &h.partial[..h.partial_len as usize]
            );
            // Also show keys[] for inner nodes — confirms whether children
            // are addressable.
            match h.node_type {
                NODE4 => {
                    let n = &*(root as *const Node4);
                    let nc = n.h.num_children as usize;
                    crate::println!("    keys[0..{}]={:02x?}", nc, &n.keys[..nc]);
                }
                NODE16 => {
                    let n = &*(root as *const Node16);
                    let nc = n.h.num_children as usize;
                    crate::println!("    keys[0..{}]={:02x?}", nc, &n.keys[..nc]);
                }
                _ => {}
            }
        }
    }

    /// One-shot dump of the root inner node's header + first level keys —
    /// used by the post-insert self-check. Cheap, called only on failure.
    fn dump_root_partial(&self, key: u64) {
        let root = unsafe { slot_load(&self.root) };
        if root == 0 || is_leaf(root) {
            crate::println!("  dump_root: root={:#x} leaf={}", root, is_leaf(root));
            return;
        }
        unsafe {
            let h = &*(root as *const Header);
            crate::println!(
                "  dump_root: addr={:#x} type={} nc={} plen={} partial={:02x?}",
                root, h.node_type, h.num_children, h.partial_len,
                &h.partial[..h.partial_len as usize]
            );
            // First-level keys
            match h.node_type {
                NODE4 => {
                    let n = &*(root as *const Node4);
                    let nc = n.h.num_children as usize;
                    crate::println!("    Node4 keys[0..{}] = {:02x?}", nc, &n.keys[..nc]);
                }
                NODE16 => {
                    let n = &*(root as *const Node16);
                    let nc = n.h.num_children as usize;
                    crate::println!("    Node16 keys[0..{}] = {:02x?}", nc, &n.keys[..nc]);
                }
                NODE256 => {
                    let n = &*(root as *const Node256);
                    let target = key_at(key, h.partial_len as usize);
                    let child_at = slot_load(&n.children[target as usize]);
                    crate::println!(
                        "    Node256 nc={} children[wanted_byte=0x{:02x}]={:#x}",
                        n.h.num_children, target, child_at
                    );
                }
                _ => {}
            }
        }
    }

    /// Remove an entry by key. Returns the value if found.
    /// Must be called under write serialization.
    pub fn remove(&mut self, key: u64) -> Option<usize> {
        if self.root == 0 {
            return None;
        }
        let root_ptr = &mut self.root as *mut usize;
        let len_ptr = &mut self.len as *mut usize;
        unsafe { remove_inner(root_ptr, len_ptr, key, 0) }
    }

    /// Iterate over all (key, value) pairs. Calls `f(key, value)` for each.
    /// Uses atomic loads for RCU safety.
    pub fn for_each<F: FnMut(u64, usize)>(&self, mut f: F) {
        let root = unsafe { slot_load(&self.root) };
        if root != 0 {
            unsafe { for_each_inner(root, &mut f) };
        }
    }
}

// ---------------------------------------------------------------------------
// Insert internals
// ---------------------------------------------------------------------------

/// Recursive insert into the subtree rooted at `*slot`.
unsafe fn insert_inner(
    slot: *mut usize,
    len_ptr: *mut usize,
    key: u64,
    value: usize,
    new_leaf: *mut Leaf,
    depth: usize,
) -> bool {
    unsafe {
        let current = *slot;

        if current == 0 {
            slot_store(slot, tag_leaf(new_leaf));
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
    unsafe {
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

        slot_store(slot, node as usize);
        *len_ptr += 1;
        true
    }
}

/// Split an inner node whose partial key mismatches at position `match_len`.
/// COW: clones the old node with shortened partial instead of mutating in place.
unsafe fn split_node(
    slot: *mut usize,
    len_ptr: *mut usize,
    new_leaf: *mut Leaf,
    new_key: u64,
    depth: usize,
    match_len: usize,
) -> bool {
    unsafe {
        let old_node_ptr = *slot;
        let old_h = &*(old_node_ptr as *const Header);
        let old_plen = old_h.partial_len as usize;

        // Build the new parent's partial (the shared prefix up to mismatch).
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

        // COW: clone old node with the remaining partial (after the mismatch byte).
        let remaining = old_plen - match_len - 1;
        let mut shortened = [0u8; MAX_PARTIAL];
        // Only copy bytes that exist in old_h.partial[]; the array has
        // MAX_PARTIAL slots, so indices match_len+1.. may be out of range
        // when match_len is near the end.
        let avail = MAX_PARTIAL.saturating_sub(match_len + 1);
        for i in 0..remaining.min(MAX_PARTIAL).min(avail) {
            shortened[i] = old_h.partial[match_len + 1 + i];
        }

        let cloned =
            match clone_node_with_partial(old_node_ptr, &shortened[..remaining.min(MAX_PARTIAL)]) {
                Some(c) => c,
                None => {
                    // Free unpublished parent.
                    free_node(parent as usize);
                    return false;
                }
            };

        if old_byte < new_byte {
            (*parent).keys[0] = old_byte;
            (*parent).children[0] = cloned;
            (*parent).keys[1] = new_byte;
            (*parent).children[1] = tag_leaf(new_leaf);
        } else {
            (*parent).keys[0] = new_byte;
            (*parent).children[0] = tag_leaf(new_leaf);
            (*parent).keys[1] = old_byte;
            (*parent).children[1] = cloned;
        }
        (*parent).h.num_children = 2;

        slot_store(slot, parent as usize);
        rcu_defer_free_node(old_node_ptr);
        *len_ptr += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// Remove internals
// ---------------------------------------------------------------------------

/// Recursive remove. `slot` points to the child pointer in the parent.
unsafe fn remove_inner(
    slot: *mut usize,
    len_ptr: *mut usize,
    key: u64,
    depth: usize,
) -> Option<usize> {
    unsafe {
        let current = *slot;
        if current == 0 {
            return None;
        }

        if is_leaf(current) {
            let leaf = &*untag_leaf(current);
            if leaf.key == key {
                let value = leaf.value;
                slot_store(slot, 0);
                rcu_defer_free_leaf(untag_leaf(current));
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
            // Check if child was zeroed (leaf removed at deeper level).
            if *child_slot == 0 {
                let h = &*(current as *const Header);
                match h.node_type {
                    NODE256 => {
                        // Child already atomically zeroed; just update count.
                        let n = &mut *(current as *mut Node256);
                        n.h.num_children = n.h.num_children.saturating_sub(1);
                        if n.h.num_children == 0 {
                            slot_store(slot, 0);
                            rcu_defer_free_node(current);
                        }
                    }
                    _ => {
                        // Node4 or Node16: COW without the removed child.
                        let nc = num_children(current);
                        if nc <= 1 {
                            // Node becomes empty after removal — no COW needed.
                            slot_store(slot, 0);
                            rcu_defer_free_node(current);
                        } else if let Some(new_ptr) = cow_node_remove_child(current, byte) {
                            slot_store(slot, new_ptr);
                            rcu_defer_free_node(current);
                        }
                        // On OOM: old node retains the key with zeroed child.
                        // Readers see 0 = not found. Functionally correct.
                    }
                }
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Iteration (lock-free, uses atomic loads)
// ---------------------------------------------------------------------------

unsafe fn for_each_inner<F: FnMut(u64, usize)>(node: usize, f: &mut F) {
    unsafe {
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
                    let child = slot_load(&n.children[i]);
                    for_each_inner(child, f);
                }
            }
            NODE16 => {
                let n = &*(node as *const Node16);
                for i in 0..n.h.num_children as usize {
                    let child = slot_load(&n.children[i]);
                    for_each_inner(child, f);
                }
            }
            NODE256 => {
                let n = &*(node as *const Node256);
                for i in 0..256 {
                    let child = slot_load(&n.children[i]);
                    if child != 0 {
                        for_each_inner(child, f);
                    }
                }
            }
            _ => {}
        }
    }
}
